#include "ipfrag.h"
#include "net.h"
#include "netif.h"
#include "icmp.h"
#include "ipv6.h"
#include "smp.h"
#include "timer.h"
#include "uart.h"

/* 8 バイトを 1 単位として「どこが埋まったか」を持つ。**単純にバイト数を
 * 数える方式では、同じ断片が 2 回来ただけで「そろった」と誤判定する。**
 * 断片のオフセットは必ず 8 の倍数なので、この粒度でちょうど表せる。 */
#define IPFRAG_BLOCK       8u
#define IPFRAG_BLOCKS_MAX  ((IPFRAG_MAX_LEN + IPFRAG_BLOCK - 1u) / IPFRAG_BLOCK)  /* 8192 */
#define IPFRAG_BITMAP_LEN  ((IPFRAG_BLOCKS_MAX + 7u) / 8u)                        /* 1024 */

/* データを置くページ。1 つのデータグラムは最大 16 ページ(65536 バイト)。 */
#define IPFRAG_NPAGES       (IPFRAG_POOL_BYTES / IPFRAG_PAGE_BYTES)               /* 1024 */
#define IPFRAG_DGRAM_PAGES  ((IPFRAG_MAX_LEN + IPFRAG_PAGE_BYTES - 1u) / IPFRAG_PAGE_BYTES) /* 16 */
#define IPFRAG_NO_PAGE      0xFFFFu

/* 組み立て中の文脈の数の上限。**数で抑えるためのものではない** --
 * どの文脈も少なくとも 1 ページを使うので、ページの数を超えて同時に
 * 存在することはない。 */
#define IPFRAG_CTX_POOL     IPFRAG_NPAGES

volatile uint32_t g_ipfrag_mem_limit = IPFRAG_POOL_BYTES;

typedef struct {
    uint8_t   in_use;
    netaddr_t src;
    netaddr_t dst;
    uint32_t  id;
    uint8_t   protocol;
    uint64_t  started_at;   /* 最初の断片が来た時刻(IPFRAG_TIMEOUT_MS の判定) */
    uint32_t  total_len;    /* 最終断片が来て確定した全長。0 = まだ不明 */
    uint32_t  blocks_set;   /* 埋まった 8 バイト単位の数 */
    uint16_t  page[IPFRAG_DGRAM_PAGES];  /* 位置 p のデータは page[p / 4096] に置く */
    uint8_t   bitmap[IPFRAG_BITMAP_LEN];
    /* オフセット 0 の断片の控え(上位プロトコルと、時間切れの ICMP の引用・宛先)。 */
    uint8_t   first_seen;
    uint8_t   first_proto;
    uint16_t  head_len;
    uint8_t   head[IPFRAG_HEAD_SAVE];
    uint8_t   src_mac[6];
    netif_t  *netif;
} ipfrag_ctx_t;

/* 時間切れで ICMP を返す相手。ロックを持ったまま送らないよう、回収で控えてから
 * ロックの外で送る(コアごと、1 回の回収で最大 8 個)。 */
#define IPFRAG_TE_MAX 8u
typedef struct {
    netaddr_t src;
    uint16_t  head_len;
    uint8_t   head[IPFRAG_HEAD_SAVE];
    uint8_t   src_mac[6];
    netif_t  *netif;
} ipfrag_te_t;
static ipfrag_te_t s_te[SMP_MAX_CORES][IPFRAG_TE_MAX];
static uint32_t    s_te_n[SMP_MAX_CORES];

/* 使用量は「使っているページ x 4KB + 使っている文脈 x 文脈の大きさ」で数える
 * (Linux が組み立て中の skb の truesize を足し上げるのに相当する)。 */
#define IPFRAG_CTX_COST ((uint32_t)sizeof(ipfrag_ctx_t))

/* **表は全コアで 1 つ。** 断片はめったに来ないので 1 本のロックで足りる。
 * コアごとに分けると、同じデータグラムの断片が RSS で別々のコアに配られた
 * ときに組み立てられない(2 個目以降の断片はポート番号を持たないので、
 * 先頭の断片と同じ受信キューに来るとは限らない)。 */
static smp_spinlock_t s_lock;
static ipfrag_ctx_t   s_ctx[IPFRAG_CTX_POOL];
static uint16_t       s_active[IPFRAG_CTX_POOL];   /* 使用中の文脈の番号(詰めて並べる) */
static uint32_t       s_nactive;
static uint8_t        s_pages[IPFRAG_NPAGES][IPFRAG_PAGE_BYTES] __attribute__((aligned(64)));
static uint16_t       s_free_page[IPFRAG_NPAGES];  /* 空きページの番号のスタック */
static uint32_t       s_nfree_page;
static uint8_t        s_pool_ready;
static uint32_t       s_mem_used;
static uint32_t       s_mem_peak;

/* 完成したデータグラムを並べ直す先。コアごとに 1 つ(そのコアの次の完成まで有効)。 */
static uint8_t s_out[SMP_MAX_CORES][IPFRAG_MAX_LEN + 1u] __attribute__((aligned(64)));

static uint32_t s_completed;
static uint32_t s_dropped;
static uint32_t s_timeouts;
static uint32_t s_refused;   /* 上限を超えていて新しい組み立てを断った数 */

/*=================================================================
 * 空きページの一覧を初めて使うときに作る(s_lock を持って呼ぶ)。
 * コール元:
 *   ipfrag_input(), ipfrag_reset()
 * ===============================================================*/
static void ipfrag_pool_init_locked(void)
{
    if (s_pool_ready) return;
    for (uint32_t i = 0; i < IPFRAG_NPAGES; i++) {
        s_free_page[i] = (uint16_t)(IPFRAG_NPAGES - 1u - i);
    }
    s_nfree_page = IPFRAG_NPAGES;
    s_pool_ready = 1;
}

/*=================================================================
 * 文脈を 1 つ、使っていたページごと返す(s_lock を持って呼ぶ)。
 *
 * 引数:
 *   slot - s_active[] の中の位置(最後の要素を詰めて埋める)
 * コール元:
 *   ipfrag_reap_locked(), ipfrag_input(), ipfrag_reset()
 * ===============================================================*/
static void ipfrag_free_locked(uint32_t slot)
{
    ipfrag_ctx_t *c = &s_ctx[s_active[slot]];
    for (uint32_t i = 0; i < IPFRAG_DGRAM_PAGES; i++) {
        if (c->page[i] == IPFRAG_NO_PAGE) continue;
        s_free_page[s_nfree_page++] = c->page[i];
        c->page[i] = IPFRAG_NO_PAGE;
        s_mem_used -= IPFRAG_PAGE_BYTES;
    }
    c->in_use = 0;
    s_mem_used -= IPFRAG_CTX_COST;
    s_active[slot] = s_active[--s_nactive];
}

/*=================================================================
 * 期限切れの組み立て途中を捨てる(s_lock を持って呼ぶ)。
 *
 * **この層には定期実行の入口が無い**ので、断片が届いたときにまとめて見る。
 * 相手が黙り込んだまま次の断片が一度も来なければ、そのぶんの領域は
 * 次に誰かが断片を送ってくるまで残る。
 *
 * 引数:
 *   now - 現在時刻
 * コール元:
 *   ipfrag_input()
 * ===============================================================*/
static void ipfrag_reap_locked(uint64_t now)
{
    (void)now;
    unsigned core = smp_core_index();
    for (uint32_t s = 0; s < s_nactive; ) {
        ipfrag_ctx_t *c = &s_ctx[s_active[s]];
        if (timeout_ms(c->started_at, IPFRAG_TIMEOUT_MS)) {
            uart_printf("[IPfrag] 組み立てを %u ms で打ち切り (id=%u proto=%u %u/%u バイト)\n",
                        (unsigned)IPFRAG_TIMEOUT_MS, (unsigned)c->id, (unsigned)c->protocol,
                        (unsigned)(c->blocks_set * IPFRAG_BLOCK), (unsigned)c->total_len);
            /* **先頭の断片を受け取っていたら Time Exceeded(code 1)を返す**
             * (RFC 1122 3.3.2 / RFC 8200 4.5)。先頭が無ければ、上位の何を
             * 引用すればよいか分からないので返さない(RFC も同じ条件)。 */
            if (c->first_seen && s_te_n[core] < IPFRAG_TE_MAX) {
                ipfrag_te_t *t = &s_te[core][s_te_n[core]++];
                t->src = c->src;
                t->head_len = c->head_len;
                for (uint32_t i = 0; i < c->head_len; i++) t->head[i] = c->head[i];
                for (uint32_t i = 0; i < 6u; i++) t->src_mac[i] = c->src_mac[i];
                t->netif = c->netif;
            }
            ipfrag_free_locked(s);
            s_timeouts++;
            continue;   /* 詰めて入った要素を同じ位置で見る */
        }
        s++;
    }
}

/*=================================================================
 * 鍵が一致する組み立て途中を探す。無ければ新しく 1 つ始める
 * (s_lock を持って呼ぶ)。
 *
 * 引数:
 *   src / dst / id / protocol - 鍵
 *   now  - 現在時刻(新規の開始時刻)
 *   slot - 見つけた / 始めた文脈の s_active[] の中の位置
 * 戻り値:
 *   使う文脈。上限を超えていて始められなければ NULL
 * コール元:
 *   ipfrag_input()
 * ===============================================================*/
static ipfrag_ctx_t *ipfrag_lookup_locked(const netaddr_t *src, const netaddr_t *dst,
                                           uint32_t id, uint8_t protocol, uint64_t now,
                                           uint32_t *slot)
{
    /* IPv6 の鍵に Next Header は入れない(RFC 8200 4.5)。 */
    if (src->family == NETADDR_V6) protocol = 0;
    for (uint32_t s = 0; s < s_nactive; s++) {
        ipfrag_ctx_t *c = &s_ctx[s_active[s]];
        if (c->id == id && c->protocol == protocol &&
            netaddr_eq(&c->src, src) && netaddr_eq(&c->dst, dst)) {
            *slot = s;
            return c;
        }
    }
    /* **新しく始めるかどうかだけを上限で決める**(Linux の inet_frag_create() と
     * 同じ)。組み立て中のものに断片を足すのは上限を超えていても受け付ける --
     * 途中で切ると、そこまで受け取った分が全部無駄になる。 */
    if (s_mem_used + IPFRAG_CTX_COST > g_ipfrag_mem_limit || s_nactive >= IPFRAG_CTX_POOL) {
        return NULL;
    }
    ipfrag_ctx_t *c = NULL;
    for (uint32_t i = 0; i < IPFRAG_CTX_POOL; i++) {
        if (!s_ctx[i].in_use) { c = &s_ctx[i]; s_active[s_nactive] = (uint16_t)i; break; }
    }
    if (c == NULL) return NULL;
    c->in_use     = 1;
    c->src        = *src;
    c->dst        = *dst;
    c->id         = id;
    c->protocol   = protocol;
    c->started_at = now;
    c->total_len  = 0;
    c->blocks_set = 0;
    c->first_seen = 0;
    c->head_len   = 0;
    for (uint32_t i = 0; i < IPFRAG_DGRAM_PAGES; i++) c->page[i] = IPFRAG_NO_PAGE;
    for (uint32_t b = 0; b < IPFRAG_BITMAP_LEN; b++) c->bitmap[b] = 0;
    *slot = s_nactive++;
    s_mem_used += IPFRAG_CTX_COST;
    if (s_mem_used > s_mem_peak) s_mem_peak = s_mem_used;
    return c;
}

/*=================================================================
 * 位置 p を含むページを用意する(s_lock を持って呼ぶ)。
 *
 * 戻り値:
 *   そのページの先頭。空きページが無ければ NULL
 * コール元:
 *   ipfrag_input()
 * ===============================================================*/
static uint8_t *ipfrag_page_locked(ipfrag_ctx_t *c, uint32_t p)
{
    uint32_t pi = p / IPFRAG_PAGE_BYTES;
    if (c->page[pi] == IPFRAG_NO_PAGE) {
        if (s_nfree_page == 0u) return NULL;
        c->page[pi] = s_free_page[--s_nfree_page];
        s_mem_used += IPFRAG_PAGE_BYTES;
        if (s_mem_used > s_mem_peak) s_mem_peak = s_mem_used;
    }
    return s_pages[c->page[pi]];
}

/*=================================================================
 * 時間切れで控えた相手へ ICMP Time Exceeded(code 1)を返す(ロックの外で呼ぶ)。
 * コール元:
 *   ipfrag_input()
 * ===============================================================*/
static void ipfrag_send_time_exceeded(void)
{
    unsigned core = smp_core_index();
    uint32_t n = s_te_n[core];
    s_te_n[core] = 0;
    for (uint32_t i = 0; i < n; i++) {
        ipfrag_te_t *t = &s_te[core][i];
        netif_t *prev = g_active_ctx;
        if (t->netif) netif_activate(t->netif);
        if (t->src.family == NETADDR_V6) {
            icmpv6_send_error(ICMPV6_TYPE_TIME_EXCEEDED, 1u, 0u, t->head, t->head_len,
                              t->src.a, t->src_mac);
        } else {
            uint8_t sip[4] = { t->src.a[0], t->src.a[1], t->src.a[2], t->src.a[3] };
            icmp_send_time_exceeded(1u, t->head, t->head_len, sip, t->src_mac);
        }
        if (t->netif) netif_activate(prev);
    }
}

int ipfrag_input(const netaddr_t *src, const netaddr_t *dst,
                 uint32_t id, uint8_t protocol,
                 uint32_t frag_off, int more,
                 const volatile uint8_t *data, uint32_t len,
                 const uint8_t *pkt, uint32_t pkt_len, const uint8_t *src_mac,
                 const uint8_t **out_data, uint32_t *out_len, uint8_t *out_proto)
{
    const int v6 = (src->family == NETADDR_V6);
    unsigned core = smp_core_index();
    uint64_t now  = timer_now();

    /* **境界の検査を先にやる。** ここを緩めると、オフセットの大きな断片 1 個で
     * バッファの外へ書けてしまう(teardrop / ping of death と呼ばれた古典的な
     * 攻撃はどちらもこの検査漏れ)。 */
    if (len == 0u || frag_off > IPFRAG_MAX_LEN || len > IPFRAG_MAX_LEN ||
        frag_off + len > IPFRAG_MAX_LEN) {
        uart_printf("[IPfrag] 範囲外の断片を破棄 (off=%u len=%u)\n",
                    (unsigned)frag_off, (unsigned)len);
        __atomic_add_fetch(&s_dropped, 1u, __ATOMIC_RELAXED);
        return 0;
    }
    /* 最後以外の断片は 8 の倍数でなければならない(RFC 791)。
     * 揃っていないと後続のオフセットを 8 バイト単位で表せない。 */
    if (more && (len % IPFRAG_BLOCK) != 0u) {
        uart_printf("[IPfrag] 中間断片の長さが 8 の倍数でない (len=%u) 破棄\n", (unsigned)len);
        __atomic_add_fetch(&s_dropped, 1u, __ATOMIC_RELAXED);
        return 0;
    }
    if ((frag_off % IPFRAG_BLOCK) != 0u) {
        uart_printf("[IPfrag] オフセットが 8 の倍数でない (off=%u) 破棄\n", (unsigned)frag_off);
        __atomic_add_fetch(&s_dropped, 1u, __ATOMIC_RELAXED);
        return 0;
    }

    smp_spin_lock(&s_lock);
    ipfrag_pool_init_locked();
    ipfrag_reap_locked(now);

    uint32_t slot = 0;
    ipfrag_ctx_t *c = ipfrag_lookup_locked(src, dst, id, protocol, now, &slot);
    if (c == NULL) {
        uint32_t used = s_mem_used, nact = s_nactive;
        uint32_t nref = ++s_refused;
        s_dropped++;
        smp_spin_unlock(&s_lock);
        ipfrag_send_time_exceeded();
        /* 上限に当たり続けると断片ごとに出るので、1, 2, 4, 8 .. 回目だけ表示する。 */
        if ((nref & (nref - 1u)) == 0u) {
            uart_printf("[IPfrag] 組み立ての領域が上限(使用 %u / 上限 %u バイト、組み立て中 %u 個)"
                        "-- 断片を破棄(%u 回目)\n",
                        (unsigned)used, (unsigned)g_ipfrag_mem_limit, (unsigned)nact, (unsigned)nref);
        }
        return 0;
    }

    /* 全長は最終断片(more=0)で確定する。食い違う 2 つ目が来たら、
     * どちらかが偽物なので組み立てごと捨てる。 */
    if (!more) {
        uint32_t end = frag_off + len;
        if (c->total_len != 0u && c->total_len != end) {
            uint32_t was = c->total_len;
            ipfrag_free_locked(slot);
            s_dropped++;
            smp_spin_unlock(&s_lock);
            uart_printf("[IPfrag] 最終断片の全長が食い違う (%u != %u) -- 組み立てを破棄\n",
                        (unsigned)was, (unsigned)end);
            return 0;
        }
        /* **全長が決まった時点で、それより後ろが 1 つでも埋まっていたら組み立てを
         * 捨てる。** 後ろの断片を「埋まった数」に数えたままだと、全長の内側に穴が
         * 残っていても数の上ではそろったことになり、ページの無い位置を読む
         * (領域外の読み出し、または前に使ったページの古い中身を渡す)。 */
        uint32_t end_blk_all = (end + IPFRAG_BLOCK - 1u) / IPFRAG_BLOCK;
        int beyond = 0;
        for (uint32_t blk = end_blk_all; blk < IPFRAG_BITMAP_LEN * 8u; blk++) {
            if (c->bitmap[blk / 8u] & (uint8_t)(1u << (blk % 8u))) { beyond = 1; break; }
        }
        if (beyond) {
            ipfrag_free_locked(slot);
            s_dropped++;
            smp_spin_unlock(&s_lock);
            uart_printf("[IPfrag] 全長 %u より後ろの断片がある -- 組み立てを破棄\n", (unsigned)end);
            return 0;
        }
        c->total_len = end;
    } else if (c->total_len != 0u && frag_off + len > c->total_len) {
        /* 全長が決まった後に、それを越える断片が来た。どちらかが偽物。 */
        uint32_t was = c->total_len;
        ipfrag_free_locked(slot);
        s_dropped++;
        smp_spin_unlock(&s_lock);
        uart_printf("[IPfrag] 全長 %u を越える断片 (off=%u len=%u) -- 組み立てを破棄\n",
                    (unsigned)was, (unsigned)frag_off, (unsigned)len);
        return 0;
    }

    /* **既に埋まっている場所は上書きしない。** 重複した断片を数え直さない
     * ためと、後から来た断片で前の内容を書き換えられないようにするため
     * (重なり合う断片を使った古典的な攻撃への対処)。 */
    uint32_t start_blk = frag_off / IPFRAG_BLOCK;
    uint32_t end_blk   = (frag_off + len + IPFRAG_BLOCK - 1u) / IPFRAG_BLOCK;
    if (v6) {
        /* **IPv6 は重なりを見つけたら組み立てごと捨てる**(RFC 5722 の MUST。
         * どちらの中身を残すかが受け手ごとに違うと、検査の装置と最終的な受け手で
         * 違う中身を見せられる)。範囲が全部埋まっているものは、まったく同じ
         * 断片の再送とみなし、その断片だけを捨てる(RFC 5722 が許す扱い)。 */
        uint32_t set = 0;
        for (uint32_t blk = start_blk; blk < end_blk; blk++) {
            if (c->bitmap[blk / 8u] & (uint8_t)(1u << (blk % 8u))) set++;
        }
        if (set != 0u && set != end_blk - start_blk) {
            ipfrag_free_locked(slot);
            s_dropped++;
            smp_spin_unlock(&s_lock);
            ipfrag_send_time_exceeded();
            uart_printf("[IPfrag] IPv6 の断片が重なっている (off=%u len=%u) -- 組み立てを破棄"
                        "(RFC 5722)\n", (unsigned)frag_off, (unsigned)len);
            return 0;
        }
    }
    /* オフセット 0 の断片の頭を控える(上位プロトコルと、時間切れの ICMP のため)。 */
    if (frag_off == 0u && !c->first_seen) {
        c->first_seen  = 1;
        c->first_proto = protocol;
        uint32_t h = pkt_len < IPFRAG_HEAD_SAVE ? pkt_len : IPFRAG_HEAD_SAVE;
        for (uint32_t i = 0; i < h && pkt; i++) c->head[i] = pkt[i];
        c->head_len = (uint16_t)(pkt ? h : 0u);
        for (uint32_t i = 0; i < 6u; i++) c->src_mac[i] = src_mac ? src_mac[i] : 0u;
        c->netif = g_active_ctx;
    }
    for (uint32_t blk = start_blk; blk < end_blk; blk++) {
        uint32_t byte = blk / 8u;
        uint8_t  bit  = (uint8_t)(1u << (blk % 8u));
        if (c->bitmap[byte] & bit) continue;   /* もう埋まっている */

        uint32_t bstart = blk * IPFRAG_BLOCK;
        uint32_t bend   = bstart + IPFRAG_BLOCK;
        if (bstart < frag_off) bstart = frag_off;
        if (bend > frag_off + len) bend = frag_off + len;
        /* 8 バイトの単位はページ(4096 の倍数)の境界をまたがない。 */
        uint8_t *pg = ipfrag_page_locked(c, bstart);
        if (pg == NULL) {
            ipfrag_free_locked(slot);
            s_dropped++;
            smp_spin_unlock(&s_lock);
            uart_printf("[IPfrag] 組み立ての領域のページが尽きた -- 組み立てを破棄\n");
            return 0;
        }
        for (uint32_t p = bstart; p < bend; p++) {
            pg[p % IPFRAG_PAGE_BYTES] = data[p - frag_off];
        }
        c->bitmap[byte] |= bit;
        c->blocks_set++;
    }

    int done = 0;
    if (c->total_len != 0u &&
        c->blocks_set >= (c->total_len + IPFRAG_BLOCK - 1u) / IPFRAG_BLOCK) {
        /* そろった。ページをこのコアの作業領域へ並べ直して文脈を返す。 */
        uint32_t total = c->total_len;
        uint8_t *out = s_out[core];
        for (uint32_t off = 0; off < total; off += IPFRAG_PAGE_BYTES) {
            uint32_t n = total - off;
            if (n > IPFRAG_PAGE_BYTES) n = IPFRAG_PAGE_BYTES;
            volatile_fast_copy(out + off, s_pages[c->page[off / IPFRAG_PAGE_BYTES]], n);
        }
        if (out_proto) *out_proto = c->first_proto;
        ipfrag_free_locked(slot);
        s_completed++;
        if (out_data) *out_data = out;
        if (out_len)  *out_len  = total;
        done = 1;
    }
    smp_spin_unlock(&s_lock);
    ipfrag_send_time_exceeded();
    return done;
}

void ipfrag_stats(uint32_t *completed, uint32_t *dropped, uint32_t *timeouts,
                  uint32_t *active)
{
    if (completed) *completed = s_completed;
    if (dropped)   *dropped   = s_dropped;
    if (timeouts)  *timeouts  = s_timeouts;
    if (active)    *active    = s_nactive;
}

void ipfrag_mem_stats(uint32_t *used, uint32_t *peak, uint32_t *refused)
{
    if (used)    *used    = s_mem_used;
    if (peak)    *peak    = s_mem_peak;
    if (refused) *refused = s_refused;
}

void ipfrag_reset(void)
{
    smp_spin_lock(&s_lock);
    ipfrag_pool_init_locked();
    while (s_nactive > 0u) ipfrag_free_locked(s_nactive - 1u);
    s_mem_peak = s_mem_used;
    smp_spin_unlock(&s_lock);
}
