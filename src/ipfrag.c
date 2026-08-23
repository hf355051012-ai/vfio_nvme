#include "ipfrag.h"
#include "net.h"
#include "smp.h"
#include "timer.h"
#include "uart.h"

/* 8 バイトを 1 単位として「どこが埋まったか」を持つ。**単純にバイト数を
 * 数える方式では、同じ断片が 2 回来ただけで「そろった」と誤判定する。**
 * 断片のオフセットは必ず 8 の倍数なので、この粒度でちょうど表せる。 */
#define IPFRAG_BLOCK       8u
#define IPFRAG_BLOCKS_MAX  ((IPFRAG_MAX_LEN + IPFRAG_BLOCK - 1u) / IPFRAG_BLOCK)  /* 8192 */
#define IPFRAG_BITMAP_LEN  ((IPFRAG_BLOCKS_MAX + 7u) / 8u)                        /* 1024 */

typedef struct {
    uint8_t   in_use;
    netaddr_t src;
    netaddr_t dst;
    uint32_t  id;
    uint8_t   protocol;
    uint64_t  started_at;   /* 最初の断片が来た時刻(IPFRAG_TIMEOUT_MS の判定) */
    uint32_t  total_len;    /* 最終断片が来て確定した全長。0 = まだ不明 */
    uint32_t  blocks_set;   /* 埋まった 8 バイト単位の数 */
    uint8_t   bitmap[IPFRAG_BITMAP_LEN];
    uint8_t   buf[IPFRAG_MAX_LEN];
} ipfrag_ctx_t;

/* コアごとに持つ。受信はコアごとに独立して回るので、ロックを避けるための
 * 分割(tcp.c の s_conns[] と同じ考え方)。 */
static ipfrag_ctx_t s_frag[SMP_MAX_CORES][IPFRAG_CTX_MAX];

static uint32_t s_completed;
static uint32_t s_dropped;
static uint32_t s_timeouts;

/*=================================================================
 * 期限切れの組み立て途中を捨てる。
 *
 * **この層には定期実行の入口が無い**ので、断片が届いたときにまとめて見る。
 * 相手が黙り込んだまま次の断片が一度も来なければ、そのぶんの領域は
 * 次に誰かが断片を送ってくるまで残るが、実害は無い(4 個ぶんの静的領域)。
 *
 * 引数:
 *   core - 対象コア
 *   now  - 現在時刻
 * コール元:
 *   ipfrag_input()
 * ===============================================================*/
static void ipfrag_reap(unsigned core, uint64_t now)
{
    (void)now;
    for (unsigned i = 0; i < IPFRAG_CTX_MAX; i++) {
        ipfrag_ctx_t *c = &s_frag[core][i];
        if (!c->in_use) continue;
        if (timeout_ms(c->started_at, IPFRAG_TIMEOUT_MS)) {
            uart_printf("[IPfrag] 組み立てを %u ms で打ち切り (id=%u proto=%u %u/%u バイト)\n",
                        (unsigned)IPFRAG_TIMEOUT_MS, (unsigned)c->id, (unsigned)c->protocol,
                        (unsigned)(c->blocks_set * IPFRAG_BLOCK), (unsigned)c->total_len);
            c->in_use = 0;
            s_timeouts++;
        }
    }
}

/*=================================================================
 * 鍵が一致する組み立て途中を探す。無ければ空きを 1 つ確保する。
 *
 * 引数:
 *   core / src / dst / id / protocol - 鍵
 *   now - 現在時刻(新規確保時の開始時刻)
 * 戻り値:
 *   使う文脈。空きが無ければ NULL
 * コール元:
 *   ipfrag_input()
 * ===============================================================*/
static ipfrag_ctx_t *ipfrag_lookup(unsigned core, const netaddr_t *src, const netaddr_t *dst,
                                    uint32_t id, uint8_t protocol, uint64_t now)
{
    for (unsigned i = 0; i < IPFRAG_CTX_MAX; i++) {
        ipfrag_ctx_t *c = &s_frag[core][i];
        if (!c->in_use) continue;
        if (c->id == id && c->protocol == protocol &&
            netaddr_eq(&c->src, src) && netaddr_eq(&c->dst, dst)) {
            return c;
        }
    }
    for (unsigned i = 0; i < IPFRAG_CTX_MAX; i++) {
        ipfrag_ctx_t *c = &s_frag[core][i];
        if (c->in_use) continue;
        c->in_use     = 1;
        c->src        = *src;
        c->dst        = *dst;
        c->id         = id;
        c->protocol   = protocol;
        c->started_at = now;
        c->total_len  = 0;
        c->blocks_set = 0;
        for (unsigned b = 0; b < IPFRAG_BITMAP_LEN; b++) c->bitmap[b] = 0;
        return c;
    }
    return NULL;
}

int ipfrag_input(const netaddr_t *src, const netaddr_t *dst,
                 uint32_t id, uint8_t protocol,
                 uint32_t frag_off, int more,
                 const volatile uint8_t *data, uint32_t len,
                 const uint8_t **out_data, uint32_t *out_len)
{
    unsigned core = smp_core_index();
    uint64_t now  = timer_now();

    /* **境界の検査を先にやる。** ここを緩めると、オフセットの大きな断片 1 個で
     * バッファの外へ書けてしまう(teardrop / ping of death と呼ばれた古典的な
     * 攻撃はどちらもこの検査漏れ)。 */
    if (len == 0u || frag_off > IPFRAG_MAX_LEN || len > IPFRAG_MAX_LEN ||
        frag_off + len > IPFRAG_MAX_LEN) {
        uart_printf("[IPfrag] 範囲外の断片を破棄 (off=%u len=%u)\n",
                    (unsigned)frag_off, (unsigned)len);
        s_dropped++;
        return 0;
    }
    /* 最後以外の断片は 8 の倍数でなければならない(RFC 791)。
     * 揃っていないと後続のオフセットを 8 バイト単位で表せない。 */
    if (more && (len % IPFRAG_BLOCK) != 0u) {
        uart_printf("[IPfrag] 中間断片の長さが 8 の倍数でない (len=%u) 破棄\n", (unsigned)len);
        s_dropped++;
        return 0;
    }
    if ((frag_off % IPFRAG_BLOCK) != 0u) {
        uart_printf("[IPfrag] オフセットが 8 の倍数でない (off=%u) 破棄\n", (unsigned)frag_off);
        s_dropped++;
        return 0;
    }

    ipfrag_reap(core, now);

    ipfrag_ctx_t *c = ipfrag_lookup(core, src, dst, id, protocol, now);
    if (c == NULL) {
        uart_printf("[IPfrag] 組み立て中の枠が満杯(%u 個)-- 断片を破棄\n",
                    (unsigned)IPFRAG_CTX_MAX);
        s_dropped++;
        return 0;
    }

    /* 全長は最終断片(more=0)で確定する。食い違う 2 つ目が来たら、
     * どちらかが偽物なので組み立てごと捨てる。 */
    if (!more) {
        uint32_t end = frag_off + len;
        if (c->total_len != 0u && c->total_len != end) {
            uart_printf("[IPfrag] 最終断片の全長が食い違う (%u != %u) -- 組み立てを破棄\n",
                        (unsigned)c->total_len, (unsigned)end);
            c->in_use = 0;
            s_dropped++;
            return 0;
        }
        c->total_len = end;
    }

    /* **既に埋まっている場所は上書きしない。** 重複した断片を数え直さない
     * ためと、後から来た断片で前の内容を書き換えられないようにするため
     * (重なり合う断片を使った古典的な攻撃への対処)。 */
    uint32_t start_blk = frag_off / IPFRAG_BLOCK;
    uint32_t end_blk   = (frag_off + len + IPFRAG_BLOCK - 1u) / IPFRAG_BLOCK;
    for (uint32_t blk = start_blk; blk < end_blk; blk++) {
        uint32_t byte = blk / 8u;
        uint8_t  bit  = (uint8_t)(1u << (blk % 8u));
        if (c->bitmap[byte] & bit) continue;   /* もう埋まっている */
        c->bitmap[byte] |= bit;
        c->blocks_set++;

        uint32_t bstart = blk * IPFRAG_BLOCK;
        uint32_t bend   = bstart + IPFRAG_BLOCK;
        if (bstart < frag_off) bstart = frag_off;
        if (bend > frag_off + len) bend = frag_off + len;
        for (uint32_t p = bstart; p < bend; p++) {
            c->buf[p] = data[p - frag_off];
        }
    }

    if (c->total_len == 0u) return 0;   /* 最終断片がまだ */
    uint32_t need = (c->total_len + IPFRAG_BLOCK - 1u) / IPFRAG_BLOCK;
    if (c->blocks_set < need) return 0; /* 穴が残っている */

    if (out_data) *out_data = c->buf;
    if (out_len)  *out_len  = c->total_len;
    c->in_use = 0;   /* 完成したので枠を返す(buf はこの後すぐ読まれる) */
    s_completed++;
    return 1;
}

void ipfrag_stats(uint32_t *completed, uint32_t *dropped, uint32_t *timeouts,
                  uint32_t *active)
{
    if (completed) *completed = s_completed;
    if (dropped)   *dropped   = s_dropped;
    if (timeouts)  *timeouts  = s_timeouts;
    if (active) {
        uint32_t n = 0;
        for (unsigned co = 0; co < SMP_MAX_CORES; co++) {
            for (unsigned i = 0; i < IPFRAG_CTX_MAX; i++) {
                if (s_frag[co][i].in_use) n++;
            }
        }
        *active = n;
    }
}

void ipfrag_reset(void)
{
    for (unsigned co = 0; co < SMP_MAX_CORES; co++) {
        for (unsigned i = 0; i < IPFRAG_CTX_MAX; i++) s_frag[co][i].in_use = 0;
    }
}
