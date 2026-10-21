#include "ipsec.h"
#include "netif.h"
#include <stddef.h>
#include "timestamp.h"   /* 同上 */
#include "cache.h"
#include "uart.h"
#include "arp.h"
#include "ipv6.h"
#include "tcp.h"   /* tcp_ack_flush_deferred(): 相乗りできなかった ACK の返却 */
#include "timer.h"

volatile uint32_t g_neigh_cache_ttl_ms = NEIGH_CACHE_TTL_DEFAULT_MS;

/* 実際に使う有効期間(RFC 4861 の ReachableTime)と、それを決めたときの基準値・時刻。 */
static volatile uint32_t s_reach_ms;
static volatile uint32_t s_reach_base;
static volatile uint64_t s_reach_at;

/*=================================================================
 * 実際に使う有効期間(ミリ秒)を返す。基準値(g_neigh_cache_ttl_ms、RFC 4861 の
 * BaseReachableTime)の 0.5〜1.5 倍の一様乱数で、基準値が変わったときと、
 * 3 時間ごとに引き直す(RFC 4861 6.3.2)。
 *
 * **乱数でずらすのは、同じ時刻に覚えた相手の期限が一斉に切れて、確認の
 * 問い合わせが同時に出るのを避けるため**(RFC 4861 6.3.2 の説明のとおり)。
 * 一度決めたら同じ値を使い続けるので、エントリごとに期限がばらつくのではなく、
 * 機器ごとにばらつく(リンク上の機器どうしが同期しない)。
 *
 * 引数:
 *   now - 現在時刻(timer_now() の ns)
 * コール元:
 *   neigh_expiry_from_now(), neigh_reachable_ms()
 * ===============================================================*/
static uint32_t neigh_reach_at(uint64_t now)
{
    uint32_t base = g_neigh_cache_ttl_ms;
    if (s_reach_ms != 0u && s_reach_base == base &&
        now - s_reach_at < 3ull * 3600ull * 1000000000ull) {
        return s_reach_ms;
    }
    /* 暗号の強さは要らない(同期を崩すだけ)ので、時刻を xorshift でかき混ぜる。 */
    uint64_t x = now ^ 0x9E3779B97F4A7C15ull;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    uint32_t ms = base / 2u + (uint32_t)(x % ((uint64_t)base + 1u));   /* base x [0.5, 1.5] */
    if (ms == 0u) ms = 1u;
    s_reach_base = base;
    s_reach_at   = now;
    s_reach_ms   = ms;
    return ms;
}

/* 今の有効期間(ミリ秒)。`arpage` の表示と、検査の待ち時間に使う。 */
uint32_t neigh_reachable_ms(void)
{
    return neigh_reach_at(timer_now());
}

/*=================================================================
 * 近隣キャッシュへ新しく入れる(または延命する)エントリの有効期限を返す。
 *
 * 戻り値:
 *   timer_now() と同じ単位(ns)の絶対時刻
 * コール元:
 *   arp_cache_insert(), ndp_cache_insert()
 * ===============================================================*/
uint64_t neigh_expiry_from_now(void)
{
    uint64_t now = timer_now();
    return now + (uint64_t)neigh_reach_at(now) * 1000000ull;
}

/*=================================================================
 * DELAY の長さと確認要求の間隔(ミリ秒)。どちらも TTL に連動する。
 *
 * コール元:
 *   neigh_check_age(), arp_cache_peek(), ndp_cache_peek(), shell_arpage()
 * ===============================================================*/
unsigned neigh_delay_ms(void)
{
    unsigned ms = g_neigh_cache_ttl_ms / NEIGH_DELAY_DIVISOR;
    return ms < 10u ? 10u : ms;
}

unsigned neigh_probe_interval_ms(void)
{
    unsigned ms = g_neigh_cache_ttl_ms / 60u;
    return ms < 10u ? 10u : ms;
}

/*=================================================================
 * 近隣キャッシュ 1 エントリの寿命を判定する(ARP/NDP 共通、RFC 4861 7.3)。
 * 失効しても**時間では捨てない**。使われたら DELAY を置き、その後は使われる
 * たびに間隔を空けて確認要求を出し、NEIGH_MAX_UNICAST_SOLICIT 回とも応答が
 * 無いまま間隔が過ぎたときだけ DEAD を返す(netif.h の説明を参照)。
 *
 * timer_now() が ns を返すので、除算の要る timeout_ms() ではなく絶対時刻の
 * 差で比較する。送信 1 セグメントごとに通る経路なので、fresh の判定より
 * 先では除算をしない。
 *
 * 引数:
 *   now        - 現在時刻(呼び出し元が 1 回だけ読んで渡す)
 *   expires_at - このエントリの有効期限
 *   probe_at   - 次に確認要求を出してよい時刻(0=失効後まだ使われていない)。
 *                出す番なら更新して返す
 *   probes     - 出した確認要求の数。DELAY に入るときに 0 へ戻す
 * 戻り値:
 *   NEIGH_FRESH / NEIGH_STALE / NEIGH_STALE_PROBE / NEIGH_DEAD
 * コール元:
 *   arp_cache_lookup_nud(), ndp_cache_lookup_nud()
 * ===============================================================*/
int neigh_check_age(uint64_t now, uint64_t expires_at, uint64_t *probe_at,
                    uint8_t *probes)
{
    if ((int64_t)(now - expires_at) < 0) return NEIGH_FRESH;

    /* **失効してから初めて使われたときは確認要求を出さない**(RFC 4861 の
     * DELAY 相)。probe_at==0 が「まだ一度も使われていない」印なので、ここで
     * DELAY の期限を入れて今回は黙って MAC を返す。この間に上位層
     * (TCP の累積 ACK 前進)が到達性を裏付ければ、確認要求は 1 個も出ない。 */
    if (*probe_at == 0u) {
        *probe_at = now + (uint64_t)neigh_delay_ms() * 1000000ull;
        *probes = 0;
        return NEIGH_STALE;
    }

    if ((int64_t)(now - *probe_at) < 0) return NEIGH_STALE;

    /* 出す番。すでに上限まで出して、最後の 1 個からも間隔ぶん応答が無い。 */
    if (*probes >= NEIGH_MAX_UNICAST_SOLICIT) return NEIGH_DEAD;

    (*probes)++;
    *probe_at = now + (uint64_t)neigh_probe_interval_ms() * 1000000ull;
    return NEIGH_STALE_PROBE;
}

/*=================================================================
 * エントリの状態を書き換えずに読む(arp_cache_peek() / ndp_cache_peek() 用)。
 *
 * 戻り値:
 *   0=fresh、1=stale、-1=確認要求がすべて無応答(次の lookup で破棄される)
 *   remain_ms は fresh なら失効まで、stale なら次の確認要求まで(0=まだ
 *   使われていない、または出す番)
 * コール元:
 *   arp_cache_peek(), ndp_cache_peek()
 * ===============================================================*/
int neigh_peek_state(uint64_t now, uint64_t expires_at, uint64_t probe_at,
                     uint8_t probes, uint32_t *remain_ms)
{
    if ((int64_t)(now - expires_at) < 0) {
        if (remain_ms) *remain_ms = (uint32_t)((expires_at - now) / 1000000ull);
        return 0;
    }
    int due = (probe_at == 0u) || (int64_t)(now - probe_at) >= 0;
    if (due && probe_at != 0u && probes >= NEIGH_MAX_UNICAST_SOLICIT) return -1;
    if (remain_ms) *remain_ms = due ? 0u : (uint32_t)((probe_at - now) / 1000000ull);
    return 1;
}

/*=================================================================
 * 宛先 addr へ最後に問い合わせ(ブロードキャストの ARP request / マルチキャストの
 * NS)を出した時刻の置き場を返す(アクティブなインターフェースの表)。無ければ
 * いちばん古い枠を addr 用に空けて返す(時刻 0 = まだ出していない)。
 *
 * 解決は同期で 1 つずつ行うので、8 枠で足りる。古い枠を潰しても、その宛先へ
 * 1 秒以内にもう一度出すおそれがあるだけで、動作は壊れない。
 *
 * 引数:
 *   addr - 解決したい宛先(次ホップ)
 * 戻り値:
 *   時刻の置き場(timer_now() と同じ ns)
 * コール元:
 *   arp_resolve(), ndp_resolve()
 * ===============================================================*/
uint64_t *neigh_req_stamp(const netaddr_t *addr)
{
    neigh_req_t *t = g_active_ctx->neigh_req;
    unsigned slot = 0;
    for (unsigned i = 0; i < NEIGH_REQ_SLOTS; i++) {
        if (t[i].at != 0u && netaddr_eq(&t[i].addr, addr)) return &t[i].at;
        if (t[i].at < t[slot].at) slot = i;
    }
    t[slot].addr = *addr;
    t[slot].at   = 0;
    return &t[slot].at;
}

/*=================================================================
 * 宛先 addr を、いま解決している最中(問い合わせを出して NEIGH_RETRANS_MS 以内)か。
 * RFC 4861 の INCOMPLETE 状態の代わり(このスタックは INCOMPLETE のエントリを
 * 作らず、ndp_resolve() が問い合わせを出して応答を待つ)。
 *
 * 引数:
 *   addr - 宛先
 * 戻り値:
 *   1=解決中、0=そうでない
 * コール元:
 *   ndp_cache_update_na()
 * ===============================================================*/
int neigh_req_pending(const netaddr_t *addr)
{
    const neigh_req_t *t = g_active_ctx->neigh_req;
    uint64_t now = timer_now();
    for (unsigned i = 0; i < NEIGH_REQ_SLOTS; i++) {
        if (t[i].at != 0u && netaddr_eq(&t[i].addr, addr)) {
            return now - t[i].at < (uint64_t)NEIGH_RETRANS_MS * 1000000ull;
        }
    }
    return 0;
}

/*=================================================================
 * IPv4 のゲートウェイ gw が死んだことを受けて、候補の次のものへ切り替える
 * (RFC 1122 3.3.1.4:dead gateway detection。3.3.1.2:デフォルトゲートウェイを
 * 複数持てること)。死んだと判断するのは、近隣キャッシュの確認要求がすべて無応答
 * だったときと、解決に失敗したとき(arp.c から呼ぶ)。**その gw を次ホップにして
 * いた Redirect の宛先も消す**(死んだルータへ向け続けないため)。
 *
 * 引数:
 *   ni - インターフェース
 *   gw - 死んだと分かったアドレス(ゲートウェイでなければ何もしない)
 * コール元:
 *   arp_cache_lookup_nud(), arp_resolve()
 * ===============================================================*/
void netif_gw4_dead(netif_t *ni, uint32_t gw)
{
    if (!ni || gw == 0u) return;
    for (unsigned i = 0; i < ni->dest4_cnt; ) {
        if (ni->dest4[i].nexthop == gw) {
            ni->dest4[i] = ni->dest4[--ni->dest4_cnt];
            continue;
        }
        i++;
    }
    if (ni->gateway != gw || ni->gw4_cnt < 2u) return;
    unsigned cur = 0;
    for (unsigned i = 0; i < ni->gw4_cnt; i++) if (ni->gw4_list[i] == gw) cur = i;
    uint32_t next = ni->gw4_list[(cur + 1u) % ni->gw4_cnt];
    ni->gateway = next;
    uart_printf("[ROUTE] %s: ゲートウェイ %u.%u.%u.%u に届かない -- %u.%u.%u.%u へ切り替え"
                "(RFC 1122 3.3.1.4)\n", ni->name ? ni->name : "?",
                (gw >> 24) & 0xFFu, (gw >> 16) & 0xFFu, (gw >> 8) & 0xFFu, gw & 0xFFu,
                (next >> 24) & 0xFFu, (next >> 16) & 0xFFu, (next >> 8) & 0xFFu, next & 0xFFu);
}

/*=================================================================
 * Redirect を受け入れて、宛先 dst の次ホップを nexthop にする(宛先ごとの経路、
 * RFC 1122 3.3.1.2 の route cache)。同じ宛先があれば置き換え、満杯なら古いものから
 * 順に上書きする。
 * コール元:
 *   icmp_handle()
 * ===============================================================*/
void netif_dest4_set(netif_t *ni, uint32_t dst, uint32_t nexthop)
{
    if (!ni) return;
    for (unsigned i = 0; i < ni->dest4_cnt; i++) {
        if (ni->dest4[i].dst == dst) { ni->dest4[i].nexthop = nexthop; return; }
    }
    unsigned slot;
    if (ni->dest4_cnt < NETIF_DEST4_MAX) {
        slot = ni->dest4_cnt;
        ni->dest4[slot].dst = dst;
        ni->dest4[slot].nexthop = nexthop;
        ni->dest4_cnt++;
        return;
    }
    slot = ni->dest4_next % NETIF_DEST4_MAX;
    ni->dest4_next = (uint8_t)((slot + 1u) % NETIF_DEST4_MAX);
    ni->dest4[slot].dst = dst;
    ni->dest4[slot].nexthop = nexthop;
}

/* ---- 確認要求の観測フック(`nudtest` 用)---- */
volatile uint32_t g_neigh_confirm_count;

static neigh_probe_observer_t s_neigh_probe_observer;

/*=================================================================
 * 確認要求(ARP request / NS)の観測フックを登録する(NULL で解除)。
 *
 * コール元:
 *   shell_nudtest()
 * ===============================================================*/
void neigh_set_probe_observer(neigh_probe_observer_t fn)
{
    s_neigh_probe_observer = fn;
}

/*=================================================================
 * 確認要求を出す直前に観測フックへ渡す。**ユニキャストで出ているか**は
 * 送信直前か相手側でしか分からない。
 *
 * 引数:
 *   is_v6      - 1=NDP、0=ARP
 *   is_unicast - 1=キャッシュ済み MAC へ直接、0=ブロードキャスト/マルチキャスト
 *   dst_mac    - 実際に使う L2 宛先
 * コール元:
 *   arp_send_request_to(), ndp_send_ns_to()
 * ===============================================================*/
void neigh_probe_notify(int is_v6, int is_unicast, const uint8_t dst_mac[ETH_ALEN])
{
    if (s_neigh_probe_observer) s_neigh_probe_observer(is_v6, is_unicast, dst_mac);
}

netif_t *g_netif_active_slots[SMP_MAX_CORES];

#define NETIF_MAX_TOTAL (NETIF_MAX_REGISTERED * SMP_MAX_CORES)

static netif_t     *s_registered[NETIF_MAX_TOTAL];
static unsigned        s_registered_count;
static smp_spinlock_t  s_registered_lock;

void netif_activate(netif_t *ctx)
{
    g_active_ctx = ctx;
}

/* ------------------------------------------------------------------ */
/* Ethernet フレーム層(旧 eth.c の共通ディスパッチ部)                  */
/* ------------------------------------------------------------------ */

#define HANDLER_MAX 8

static struct {
    uint16_t      ethertype;
    eth_handler_t handler;
    int           used;
} g_handlers[HANDLER_MAX];

/*=================================================================
 * EtherType 別の受信ハンドラを登録する。同一 EtherType への再登録は上書き、
 * handler=NULL で解除。
 *
 * 引数:
 *   ethertype - 対象の EtherType(0x0800=IPv4, 0x0806=ARP)
 *   handler   - eth_dispatch() から呼ばれる関数。NULL で登録解除
 * コール元:
 *   arp_init(), ip_init()
 * ===============================================================*/
void eth_register_handler(uint16_t ethertype, eth_handler_t handler)
{
    for (int i = 0; i < HANDLER_MAX; i++) {
        if (g_handlers[i].used && g_handlers[i].ethertype == ethertype) {
            g_handlers[i].handler = handler;
            if (!handler) g_handlers[i].used = 0;
            return;
        }
    }
    if (handler) {
        for (int i = 0; i < HANDLER_MAX; i++) {
            if (!g_handlers[i].used) {
                g_handlers[i].ethertype = ethertype;
                g_handlers[i].handler   = handler;
                g_handlers[i].used      = 1;
                return;
            }
        }
        uart_printf("[eth] handler table full\n");
    }
}

/* eth_dispatch() 呼び出しのネストは無い前提の per-core スカラー。 */
static int s_rx_hw_csum_ok[SMP_MAX_CORES];
static int s_rx_l2_mcast[SMP_MAX_CORES];

int eth_rx_l2_multicast(void)
{
    return s_rx_l2_mcast[smp_core_index()];
}

/*=================================================================
 * いま eth_dispatch() が処理中のフレームが、NIC で L3/L4 チェックサム検証
 * 済みかを返す。真ならソフトウェア再検証を省いてよい。
 *
 * 戻り値:
 *   1=HW 検証済み、0=未検証(ソフトウェアで検証すること)
 * コール元:
 *   ip_handle_frame(), tcp_input()
 * ===============================================================*/
int eth_rx_hw_csum_ok(void)
{
    return s_rx_hw_csum_ok[smp_core_index()];
}

/* ESP を復号した中身をもう一度 ip_handle_frame() へ入れるとき、NIC の検証結果
 * (外側の ESP に対するもの)を使わせないために 0 にする(ipsec.c)。 */
unsigned eth_tx_room_of(netif_t *nif)
{
    if (!nif || !nif->nic || !nif->nic->tx_room) return 0xFFFFFFFFu;
    return nif->nic->tx_room(nif->nic_priv);
}

void eth_rx_set_hw_csum_ok(int v)
{
    s_rx_hw_csum_ok[smp_core_index()] = v;
}

/*=================================================================
 * 受信フレームの EtherType を見て、登録済みハンドラへペイロードを渡す。
 * ハンドラ実行中だけ nb->hw_csum_ok を per-core スロットへ公開する
 * (eth_rx_hw_csum_ok() が読む)。nb の解放は呼び出し側の責任。
 *
 * 引数:
 *   nb - 受信フレーム(Ethernet ヘッダから)
 * コール元:
 *   net_poll_all_and_dispatch()
 * ===============================================================*/
void eth_dispatch(net_buf_t *nb)
{
    if (!nb || nb->len < ETH_HDR_LEN) return;
    uint16_t etype = (uint16_t)((nb->data[12] << 8) | nb->data[13]);
    const uint8_t *src_mac = &nb->data[6];
    const uint8_t *payload = &nb->data[ETH_HDR_LEN];
    size_t plen = nb->len - ETH_HDR_LEN;

    unsigned core = smp_core_index();
    s_rx_hw_csum_ok[core] = nb->hw_csum_ok;
    s_rx_l2_mcast[core] = nb->data[0] & 1u;   /* 宛先 MAC の I/G ビット */

    for (int i = 0; i < HANDLER_MAX; i++) {
        if (g_handlers[i].used && g_handlers[i].ethertype == etype) {
            g_handlers[i].handler(payload, plen, src_mac); // -> arp_handle_frame / ip_handle_frame
            break;
        }
    }
    s_rx_hw_csum_ok[core] = 0;
    s_rx_l2_mcast[core] = 0;
}

/*=================================================================
 * アクティブインターフェースの MAC アドレスを取得する。
 *
 * 引数:
 *   mac - 格納先(6 バイト)。未初期化ならゼロ MAC を返す
 * コール元:
 *   arp_handle_frame(), arp_send_request(), ip_build_header()
 * ===============================================================*/
void eth_get_mac(uint8_t mac[ETH_ALEN])
{
    for (int i = 0; i < ETH_ALEN; i++) {
        mac[i] = g_active_ctx ? g_active_ctx->mac[i] : 0u;
    }
}

/*=================================================================
 * 断片列を 1 フレームとして送信し、ハードウェアの送信完了まで待つ
 * (戻った時点で全断片のメモリを再利用してよい)。実体は
 * g_active_ctx->nic->send_frags = mlx5_net_send_frags()。
 *
 * 引数:
 *   frags      - 断片配列(連結して 1 フレームになる)
 *   frag_count - 断片数(1..ETH_TX_MAX_FRAGS)
 * 戻り値:
 *   0=送信完了、-1=アクティブインターフェース無し/送信失敗
 * コール元:
 *   eth_send()
 * ===============================================================*/
int eth_send_frags(const eth_frag_t *frags, unsigned frag_count)
{
    int rc;
    if (g_ipsec_npol && ipsec_out_frags(frags, frag_count, 0, &rc)) return rc;   /* ESP で包む相手 */
    return eth_send_frags_raw(frags, frag_count);
}

/* ESP を通らない素の送信(ipsec.c が包んだフレームを送るのに使う)。 */
int eth_send_frags_raw(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) {
        uart_printf("[eth] eth_send_frags: アクティブなインターフェースが無い\n");
        return -1;
    }
    return g_active_ctx->nic->send_frags(g_active_ctx->nic_priv, frags, frag_count); // -> mlx5_net_send_frags
}

/*=================================================================
 * eth_send_frags() と同じキューイングを行うが送信完了を待たずに返る。
 * 到達保証は呼び出し元(TCP の ACK ベース再送)が担保する。
 *
 * 引数:
 *   frags / frag_count - eth_send_frags() と同じ
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   tcp_send_segment(), tcp_send_bare_ack()
 * ===============================================================*/
int eth_send_frags_async(const eth_frag_t *frags, unsigned frag_count)
{
    int rc;
    if (g_ipsec_npol && ipsec_out_frags(frags, frag_count, 1, &rc)) return rc;
    return eth_send_frags_async_raw(frags, frag_count);
}

int eth_send_frags_async_raw(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) return -1;
    return g_active_ctx->nic->send_frags_async(g_active_ctx->nic_priv, frags, frag_count); // -> mlx5_net_send_frags_async
}

/*=================================================================
 * LSO(TCP Segmentation Offload)送信。hdr をテンプレートとして payload を
 * HW が mss 単位に分割送出する。非対応バックエンドでは -1。
 *
 * 引数:
 *   hdr / hdr_len         - L2+L3+L4 ヘッダのテンプレート
 *   payload / payload_len - 分割対象のペイロード(複数 MSS 分でよい)
 *   mss                   - 分割単位
 * 戻り値:
 *   0=キューイング成功、-1=非対応/失敗
 * コール元:
 *   tcp_send_segment_lso()
 * ===============================================================*/
int eth_send_lso_async(const void *hdr, uint16_t hdr_len,
                       const void *payload, uint32_t payload_len, uint16_t mss)
{
    int rc;
    if (g_ipsec_npol && ipsec_out_lso(hdr, hdr_len, payload, payload_len, mss, &rc)) return rc;
    if (!g_active_ctx || !g_active_ctx->nic->send_lso) return -1;
    return g_active_ctx->nic->send_lso(g_active_ctx->nic_priv, hdr, hdr_len, payload, payload_len, mss); // -> mlx5_net_send_lso_async
}

/*=================================================================
 * 次に eth_send_frags_async() が使う TX スロット番号を返す。そのスロットの
 * 前回のフレームが未完了なら完了までブロックする。呼び出し元は戻ってから
 * 初めて、そのスロット専用の送信バッファへ書き込んでよい。
 *
 * 戻り値:
 *   使用予定の TX スロット番号
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_bare_ack()
 * ===============================================================*/
unsigned eth_tx_wait_free_slot(void)
{
    if (!g_active_ctx) return 0;
    return g_active_ctx->nic->tx_wait_free_slot(g_active_ctx->nic_priv); // -> mlx5_net_tx_wait_free_slot
}

/*=================================================================
 * net_buf 1 個を 1 フレームとして送信する。nb の所有権は本関数に渡り、
 * 成否によらず内部で net_buf_free() される。NIC の DMA ソースになるため、
 * 送信前に dcache_clean_range() でキャッシュをクリーンする。
 *
 * 引数:
 *   nb - 送信するフレーム(Ethernet ヘッダから、FCS 抜き)
 * 戻り値:
 *   0=送信完了、-1=フレーム長不正/送信失敗
 * コール元:
 *   arp_handle_frame(), arp_send_request(), ip_send_prepared()
 * ===============================================================*/
int eth_send(net_buf_t *nb)
{
    if (!nb) return -1;
    if (nb->len < ETH_HDR_LEN || nb->len > NET_BUF_SIZE) {
        uart_printf("[eth] eth_send: 不正なフレーム長 (%u)\n", (unsigned)nb->len);
        net_buf_free(nb);
        return -1;
    }
    dcache_clean_range(nb->data, nb->len);
    eth_frag_t frag = { nb->data, nb->len };
    int ret = eth_send_frags(&frag, 1);
    net_buf_free(nb);
    return ret;
}

/*=================================================================
 * インターフェースを受信ポーリングの巡回対象として登録する。登録した瞬間の
 * コアがそのハードウェアのポーリング担当(owner_core)になる。二重登録は無視。
 *
 * 引数:
 *   ctx - 登録するインターフェース
 * コール元:
 *   mlx5_net_register_dual()
 * ===============================================================*/
void netif_register(netif_t *ctx)
{
    smp_spin_lock(&s_registered_lock);
    for (unsigned i = 0; i < s_registered_count; i++) {
        if (s_registered[i] == ctx) {
            smp_spin_unlock(&s_registered_lock);
            return; // 既に登録済み
        }
    }
    if (s_registered_count < NETIF_MAX_TOTAL) {
        ctx->owner_core = smp_core_index();
        ctx->is_poll_owner = 1;
        /* 送信キューの番号: 同じ nic_priv の先客がいればその番号、いなければ次の番号。 */
        unsigned nq = 0;
        int found = 0;
        for (unsigned i = 0; i < s_registered_count; i++) {
            if (s_registered[i]->nic_priv == ctx->nic_priv) { ctx->txq_index = s_registered[i]->txq_index; found = 1; break; }
            if (s_registered[i]->txq_index + 1u > nq) nq = s_registered[i]->txq_index + 1u;
        }
        if (!found) ctx->txq_index = nq;
        s_registered[s_registered_count++] = ctx;
    }
    smp_spin_unlock(&s_registered_lock);
}

/*=================================================================
 * インターフェースを登録一覧から外す。別サブネットの別名インターフェースを
 * 一時的に足して外す(`routetest`)ような用途のためのもので、常用の経路では
 * 呼ばれない。登録されていなければ何もしない。
 *
 * 引数:
 *   ctx - 外すインターフェース
 * コール元:
 *   shell_routetest()
 * ===============================================================*/
void netif_unregister(netif_t *ctx)
{
    smp_spin_lock(&s_registered_lock);
    for (unsigned i = 0; i < s_registered_count; i++) {
        if (s_registered[i] != ctx) continue;
        for (unsigned j = i + 1; j < s_registered_count; j++) {
            s_registered[j - 1] = s_registered[j];
        }
        s_registered_count--;
        ctx->is_poll_owner = 0;
        break;
    }
    smp_spin_unlock(&s_registered_lock);
}

/*=================================================================
 * インターフェースのポーリング担当コアを変更する(target を core1 へ移す等)。
 *
 * 引数:
 *   ctx  - 対象インターフェース
 *   core - 新しい担当コア番号
 * コール元:
 *   shell_dispatch(), shell_ensure_tcp_session()
 * ===============================================================*/
int net_core_has_rx(unsigned core)
{
    unsigned n = g_net_mt_cores;
    if (n > 1u) return core >= 1u && core <= n;
    for (unsigned i = 0; i < s_registered_count; i++) {
        if (s_registered[i]->is_poll_owner && s_registered[i]->owner_core == core) return 1;
    }
    return 0;
}

void netif_set_owner_core(netif_t *ctx, unsigned core)
{
    ctx->owner_core = core;
}

/*=================================================================
 * 登録済みインターフェースを名前("mlx5-pf0" 等)で引く。
 *
 * 引数:
 *   name - 探す名前
 * 戻り値:
 *   見つかったインターフェース。無ければ NULL
 * コール元:
 *   shell_dispatch(), shell_ensure_tcp_session(), rdma_cm_fill_addr()
 * ===============================================================*/
netif_t *netif_find(const char *name)
{
    for (unsigned i = 0; i < s_registered_count; i++) {
        const char *a = s_registered[i]->name;
        const char *b = name;
        unsigned j = 0;
        while (a[j] != '\0' && b[j] != '\0' && a[j] == b[j]) j++;
        if (a[j] == '\0' && b[j] == '\0') {
            return s_registered[i];
        }
    }
    return NULL;
}

/*=================================================================
 * 登録済みインターフェースを自機 IPv4 で引く。TCP がコネクションの
 * local_ip から送信元インターフェースを逆引きするのに使う。
 *
 * 引数:
 *   ip - 探す IPv4(ホストバイトオーダー)
 * 戻り値:
 *   見つかったインターフェース。無ければ NULL
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_bare_ack(),
 *   tcp_send_async_ex(), tcp_priv_try_grant_mlx5_async_overflow()
 * ===============================================================*/
netif_t *netif_find_by_ip(uint32_t ip)
{
    for (unsigned i = 0; i < s_registered_count; i++) {
        if (s_registered[i]->ip == ip) {
            return s_registered[i];
        }
    }
    return NULL;
}

/*=================================================================
 * IPv6 リンクローカルアドレスから登録済みインターフェースを引く。IPv6 の
 * アドレスは netif_t に持たず MAC から EUI-64 で毎回導出するので、ここでも
 * 各インターフェースの MAC から組み立てて比較する。
 *
 * 引数:
 *   addr - 探すリンクローカルアドレス(16 バイト)
 * 戻り値:
 *   見つかった netif_t、無ければ NULL
 * コール元:
 *   tcp_send_segment() 系(v6 コネクションの送信元インターフェース特定)
 * ===============================================================*/
netif_t *netif_find_by_ip6(const uint8_t addr[16])
{
    for (unsigned i = 0; i < s_registered_count; i++) {
        const uint8_t *mac = s_registered[i]->mac;
        uint8_t ll[16];
        for (unsigned j = 0; j < 16; j++) ll[j] = 0;
        ll[0] = 0xFE; ll[1] = 0x80;
        ll[8]  = (uint8_t)(mac[0] ^ 0x02u);
        ll[9]  = mac[1];
        ll[10] = mac[2];
        ll[11] = 0xFF;
        ll[12] = 0xFE;
        ll[13] = mac[3];
        ll[14] = mac[4];
        ll[15] = mac[5];

        int same = 1;
        for (unsigned j = 0; j < 16; j++) {
            if (ll[j] != addr[j]) { same = 0; break; }
        }
        if (same) return s_registered[i];

        /* グローバルアドレスでも引けるようにする(リンクローカルは MAC から
         * 導出できるがグローバルは導出できないので netif_t の状態を見る)。 */
        if (s_registered[i]->ip6_global_set) {
            int gsame = 1;
            for (unsigned j = 0; j < 16; j++) {
                if (s_registered[i]->ip6_global[j] != addr[j]) { gsame = 0; break; }
            }
            if (gsame) return s_registered[i];
        }
        /* 2 つ目以降のグローバルアドレス(RA の複数のプレフィックスから作ったもの)。 */
        for (unsigned k = 0; k < s_registered[i]->ip6_extra_cnt; k++) {
            int esame = 1;
            for (unsigned j = 0; j < 16; j++) {
                if (s_registered[i]->ip6_extra[k].addr[j] != addr[j]) { esame = 0; break; }
            }
            if (esame) return s_registered[i];
        }
    }
    return NULL;
}

/*=================================================================
 * 受信フレームの宛先 IP(ARP なら tpa、IPv4 なら dst_ip)を見て、同じ物理
 * NIC を共有する別名インターフェースの中にその IP を名乗るものがあれば
 * それを返す。無ければポーリング主体をそのまま返す。
 *
 * 引数:
 *   poller - このフレームをポーリングしたインターフェース
 *   nb     - 受信フレーム
 * 戻り値:
 *   このフレームを処理すべきインターフェース
 * コール元:
 *   net_poll_all_and_dispatch()
 * ===============================================================*/
static netif_t *netif_resolve_frame_owner(netif_t *poller, const net_buf_t *nb)
{
    if (nb->len < 14u + 20u) return poller;  /* ARP/IPどちらの最小長にも満たない */

    uint16_t etype = (uint16_t)(((unsigned)nb->data[12] << 8) | (unsigned)nb->data[13]);
    const uint8_t *tgt;
    if (etype == 0x0806u && nb->len >= 14u + 28u) {
        tgt = &nb->data[14u + 24u];  /* ARP: Target Protocol Address */
    } else if (etype == 0x0800u) {
        tgt = &nb->data[14u + 16u]; /* IPv4: Destination Address */
    } else if (etype == 0x86DDu && nb->len >= 14u + 40u) {
        /* IPv6: 宛先アドレス(ヘッダ先頭から 24 バイト目)を見て、グローバル
         * アドレスを名乗っている別名インターフェースへ回す。**これが無いと
         * A1 の IPv6 エンドツーエンドが組めない** -- 別名の netif_t を
         * 一時登録しても、フレームは常にポーリング主体のものとして処理されて
         * しまう(IPv4 は上の分岐で振り分けている)。
         * リンクローカルとマルチキャストは対象外(下位 3 バイトが EUI-64 由来で
         * 一意なので、従来どおりポーリング主体で処理すればよい)。 */
        const uint8_t *d6 = &nb->data[14u + 24u];
        if (d6[0] != 0xFFu && !(d6[0] == 0xFEu && (d6[1] & 0xC0u) == 0x80u)) {
            for (unsigned i = 0; i < s_registered_count; i++) {
                netif_t *c = s_registered[i];
                if (!c->ip6_global_set || c->nic != poller->nic ||
                    c->nic_priv != poller->nic_priv) {
                    continue;
                }
                int same = 1;
                for (unsigned j = 0; j < 16u; j++) {
                    if (c->ip6_global[j] != d6[j]) { same = 0; break; }
                }
                if (same) return c;
                for (unsigned k = 0; k < c->ip6_extra_cnt; k++) {
                    int esame = 1;
                    for (unsigned j = 0; j < 16u; j++) {
                        if (c->ip6_extra[k].addr[j] != d6[j]) { esame = 0; break; }
                    }
                    if (esame) return c;
                }
            }
        }
        return poller;
    } else {
        return poller;
    }
    uint32_t target_ip = ((uint32_t)tgt[0] << 24) | ((uint32_t)tgt[1] << 16) |
                          ((uint32_t)tgt[2] << 8) | (uint32_t)tgt[3];
    if (target_ip == poller->ip) return poller;

    for (unsigned i = 0; i < s_registered_count; i++) {
        netif_t *c = s_registered[i];
        if (c != poller && c->nic == poller->nic && c->nic_priv == poller->nic_priv &&
            c->ip == target_ip) {
            return c;
        }
    }
    return poller;
}

/*=================================================================
 * 宛先アドレスから送信に使う宛先 MAC を解決する。宛先が自分のサブネット外
 * なら「宛先の MAC」ではなく「ゲートウェイの MAC」を引くのが要点で、
 * L3 の宛先アドレスはそのままにして L2 の宛先だけをルータへ向ける。
 *
 * TCP の送信ホットパスは同じ判定を tcp_resolve_mac() に持っており
 * (キャッシュ照合を挟むため)、こちらは UDP/シェルなどの冷たい経路が使う。
 *
 * 引数:
 *   dst     - 宛先アドレス(IPv4/IPv6)
 *   out_mac - 解決した MAC の格納先
 * 戻り値:
 *   0=解決できた、-1=失敗
 * コール元:
 *   shell_udptest(), shell_udptest6(), shell_routetest()
 * ===============================================================*/
int net_resolve_mac(const netaddr_t *dst, uint8_t out_mac[ETH_ALEN])
{
    if (dst->family == NETADDR_V6) {
        return ndp_resolve(netif_next_hop6(g_active_ctx, dst->a), out_mac);
    }
    return arp_resolve(netif_next_hop4(g_active_ctx, netaddr_v4_host(dst)), out_mac);
}

/*=================================================================
 * インターフェースの IPv4 アドレスと IPv6 リンクローカルについて重複
 * アドレス検出を行い、結果を netif_t へ記録する。IPv4 は RFC 5227 の
 * ARP Probe、IPv6 は RFC 4862 の DAD。
 *
 * どちらも「応答が返ってこないこと」で空きと判断するので、衝突が無い場合は
 * 待ち時間ぶん(既定で 1 アドレスあたり ARP_PROBE_NUM * ARP_PROBE_INTERVAL_MS)
 * を必ず消費する。起動時に全インターフェースへ 1 回ずつ走らせるので、
 * この値がそのまま起動時間に乗る。
 *
 * 引数:
 *   ctx - 検査するインターフェース
 * 戻り値:
 *   0=どちらも衝突なし、-1=いずれかで衝突を検出した
 * コール元:
 *   run_shell(), shell_dadtest()
 * ===============================================================*/
int net_dup_addr_detect(netif_t *ctx)
{
    if (!ctx) return -1;

    netif_t *prev = g_active_ctx;
    netif_activate(ctx);

    uint8_t mac[ETH_ALEN];
    int conflict = 0;

    int r4 = arp_probe(ctx->ip, ARP_PROBE_NUM, ARP_PROBE_INTERVAL_MS, mac);
    if (r4 == 1) {
        ctx->ipv4_dup = NETIF_DAD_CONFLICT;
        for (unsigned i = 0; i < ETH_ALEN; i++) ctx->dup_mac4[i] = mac[i];
        uart_printf("[!!] %s: IPv4 アドレス %u.%u.%u.%u は既に "
                    "%02x:%02x:%02x:%02x:%02x:%02x が使用しています(RFC 5227 ARP Probe)\n",
                    ctx->name,
                    (ctx->ip >> 24) & 0xFFu, (ctx->ip >> 16) & 0xFFu,
                    (ctx->ip >> 8) & 0xFFu, ctx->ip & 0xFFu,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        conflict = 1;
    } else if (r4 == 0) {
        ctx->ipv4_dup = NETIF_DAD_PASSED;
    }

    /* リンクローカルは MAC から導出するので、activate 後に取る必要がある。 */
    uint8_t ll[16];
    ipv6_link_local_addr(ll);
    int r6 = ipv6_dad(ll, ARP_PROBE_NUM, ARP_PROBE_INTERVAL_MS, mac);
    if (r6 == 1) {
        ctx->dad_state = NETIF_DAD_CONFLICT;
        for (unsigned i = 0; i < ETH_ALEN; i++) ctx->dup_mac6[i] = mac[i];
        uart_printf("[!!] %s: IPv6 リンクローカルが既に "
                    "%02x:%02x:%02x:%02x:%02x:%02x に使われています(RFC 4862 DAD)\n",
                    ctx->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        conflict = 1;
    } else if (r6 == 0) {
        ctx->dad_state = NETIF_DAD_PASSED;
    }

    netif_activate(prev);
    return conflict ? -1 : 0;
}

#define NET_POLL_BATCH_MAX 64u

/* [計数] 受信の周回(`rxstat`)。コアごとに 1 つ(他のコアと行を共有しない)。
 * 1 回の net_poll_all_and_dispatch() の中で、インターフェース 1 つから拾ったフレームの数を
 * 0 / 1 / 2-3 / 4-7 / 8-15 / 16-31 / 32-63 / 64(上限)に分けて数え、拾う前に待っていた CQE の
 * おおよその数(rx_pending)と、周回の中で使った時間(TSC)も数える。 */
volatile uint32_t g_rxstat_on;
typedef struct {
    uint64_t polls;            /* インターフェース 1 つを見た回数 */
    uint64_t frames;
    uint64_t hist[8];
    uint64_t pend[5];          /* 拾う前に待っていた CQE: 0 / >=32 / >=64 / >=128 / >=192 */
    uint64_t tsc_in;           /* net_poll_all_and_dispatch() の中にいた TSC */
    uint64_t calls;
    uint64_t tsc_first, tsc_last;
} __attribute__((aligned(64))) rxstat_t;
static rxstat_t s_rxstat[SMP_MAX_CORES];
static uint64_t s_rxstat_t0_ns;

static inline uint64_t rxstat_tsc(void) { return __builtin_ia32_rdtsc(); }

static inline unsigned rxstat_bucket(unsigned k)
{
    if (k == 0u) return 0u;
    if (k >= NET_POLL_BATCH_MAX) return 7u;
    unsigned b = 1u;
    while ((2u << (b - 1u)) <= k && b < 6u) b++;
    return b;   /* 1:1 2:2-3 3:4-7 4:8-15 5:16-31 6:32-63 */
}

/*=================================================================
 * シェルの `rxstat`。受信の周回の計数をコアごとに出す。
 * 引数:
 *   clear - 非 0 なら 0 に戻して数え直す
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void netif_rxstat_show(int clear)
{
    if (clear) {
        for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
            volatile uint8_t *p = (volatile uint8_t *)&s_rxstat[c];
            for (unsigned i = 0; i < sizeof(rxstat_t); i++) p[i] = 0;
        }
        s_rxstat_t0_ns = timer_now();
        uart_printf("rxstat: 0 に戻しました(計数は %s)\n", g_rxstat_on ? "on" : "off");
        return;
    }
    uint64_t ns = timer_now() - s_rxstat_t0_ns;
    uart_printf("rxstat: 計数 %s、基準から %llu ms\n", g_rxstat_on ? "on" : "off", (unsigned long long)(ns / 1000000u));
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        rxstat_t *s = &s_rxstat[c];
        if (!s->polls) continue;
        uint64_t span = s->tsc_last - s->tsc_first;
        uart_printf("  core%u: 周回 %llu(インターフェースを見た回数 %llu)/ フレーム %llu(1 回あたり %llu.%02llu)\n",
                    c, (unsigned long long)s->calls, (unsigned long long)s->polls, (unsigned long long)s->frames,
                    (unsigned long long)(s->frames / s->polls), (unsigned long long)(s->frames * 100u / s->polls % 100u));
        uart_printf("    拾った数の分布(0 / 1 / 2-3 / 4-7 / 8-15 / 16-31 / 32-63 / 64=上限): %llu / %llu / %llu / %llu / %llu / %llu / %llu / %llu\n",
                    (unsigned long long)s->hist[0], (unsigned long long)s->hist[1], (unsigned long long)s->hist[2],
                    (unsigned long long)s->hist[3], (unsigned long long)s->hist[4], (unsigned long long)s->hist[5],
                    (unsigned long long)s->hist[6], (unsigned long long)s->hist[7]);
        uart_printf("    拾う前に待っていた CQE(<32 / >=32 / >=64 / >=128 / >=192): %llu / %llu / %llu / %llu / %llu\n",
                    (unsigned long long)s->pend[0], (unsigned long long)s->pend[1], (unsigned long long)s->pend[2],
                    (unsigned long long)s->pend[3], (unsigned long long)s->pend[4]);
        if (span) {
            uart_printf("    周回の中の時間 %llu%%(TSC %llu / %llu)、周回 1 回 %llu TSC、フレーム 1 個 %llu TSC(中の時間)\n",
                        (unsigned long long)(s->tsc_in * 100u / span), (unsigned long long)s->tsc_in, (unsigned long long)span,
                        (unsigned long long)(span / (s->calls ? s->calls : 1u)),
                        (unsigned long long)(s->tsc_in / (s->frames ? s->frames : 1u)));
        }
    }
}

/* ---- 受信フレームのコア間配送(マルチコア分散) --------------------------
 *
 * **NIC の受信キューは PF に 1 本しか無い**ので、RQ を見るのは常に
 * netif の owner_core 1 コア。そこで 4-tuple のハッシュから担当コアを決め、
 * 自分の担当でなければ相手コアのリングへ積む。渡された側は
 * net_poll_all_and_dispatch() の先頭で自分のリングを消費する。
 *
 * **同じコネクションは必ず同じコアへ行く**ので、TCP の状態
 * (s_conns[core] / s_priv[core])をコアまたぎで触ることにはならない。
 * net_buf は所有コアを持つので、渡した先で解放してよい(net_buf.c)。 */
volatile uint32_t g_net_mt_cores = 1u;   /* 1 = 従来の単一コア(陰性対照) */

/* RSS の鍵。**素性の分かっている標準の RSS 鍵を使う**(規則的な鍵だと入力ビットが出力の下位ビットへ効かず、
 * 全コネクションが同じバケツへ落ちた)。固定値なのは、起動ごとに分散先が変わると測定が再現しないため。
 * mlx5.c の TIR もこの鍵を使う。 */
const uint8_t g_net_rss_key[40] = {
    0x6du, 0x5au, 0x56u, 0xdau, 0x25u, 0x5bu, 0x0eu, 0xc2u,
    0x41u, 0x67u, 0x25u, 0x3du, 0x43u, 0xa3u, 0x8fu, 0xb0u,
    0xd0u, 0xcau, 0x2bu, 0xcbu, 0xaeu, 0x7bu, 0x30u, 0xb4u,
    0x77u, 0xcbu, 0x2du, 0xa3u, 0x80u, 0x30u, 0xf2u, 0x0cu,
    0x6au, 0x42u, 0xb7u, 0x3bu, 0xbeu, 0xacu, 0x01u, 0xfau,
};

int net_rss_core_v4(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    unsigned n = g_net_mt_cores;
    if (n <= 1u) return -1;
    /* ハッシュに入れる順は 送信元 IP / 宛先 IP / 送信元ポート / 宛先ポート(どれもネットワークのバイト順)。 */
    uint8_t in[12] = {
        (uint8_t)(sip >> 24), (uint8_t)(sip >> 16), (uint8_t)(sip >> 8), (uint8_t)sip,
        (uint8_t)(dip >> 24), (uint8_t)(dip >> 16), (uint8_t)(dip >> 8), (uint8_t)dip,
        (uint8_t)(sport >> 8), (uint8_t)sport, (uint8_t)(dport >> 8), (uint8_t)dport,
    };
    /* Toeplitz: 入力の 1 ビットごとに、鍵をそのビット位置から 32 ビット切り出したものを XOR する。 */
    uint32_t h = 0;
    uint32_t v = ((uint32_t)g_net_rss_key[0] << 24) | ((uint32_t)g_net_rss_key[1] << 16) |
                 ((uint32_t)g_net_rss_key[2] << 8) | g_net_rss_key[3];
    for (unsigned i = 0; i < sizeof(in); i++) {
        for (unsigned b = 0; b < 8u; b++) {
            if (in[i] & (0x80u >> b)) h ^= v;
            v <<= 1;
            if (g_net_rss_key[i + 4u] & (0x80u >> b)) v |= 1u;
        }
    }
    /* 表はハッシュの下位ビットで引く。表の中身は rxq[0..n-1] の繰り返しで、コア c は rxq[c-1] を見る。 */
    unsigned idx = h & (NET_RSS_TABLE_SIZE - 1u);
    return (int)(idx % n) + 1;
}
volatile net_mt_counter_t g_net_mt_consumed[SMP_MAX_CORES];




/*=================================================================
 * 自コアが担当する全インターフェースを巡回し、受信フレームを 1 インター
 * フェースあたり最大 NET_POLL_BATCH_MAX 個まで取り出して eth_dispatch()
 * へ流す。アクティブインターフェースは呼び出し前の値に復元して返る。
 *
 * 戻り値:
 *   1=1 フレーム以上受信した、0=何も来ていなかった
 * コール元:
 *   run_shell(), worker_main(), tcp_poll_once_ex(), arp_resolve(),
 *   shell_ensure_tcp_session()
 * ===============================================================*/
int net_poll_all_and_dispatch(void)
{
    unsigned core = smp_core_index();
    netif_t *prev = g_active_ctx;
    int got_frame = 0;

    /* **RSS 有効時は core1..coreN が自分の RQ だけを見る。**
     * NIC が 4-tuple のハッシュで配るので、同じコネクションのフレームは
     * 必ず同じコアへ届く -- ソフトウェアで配り直す必要はない。
     * **core0(シェル)は受信を持たない**(入力待ちで止まるとその RQ の
     * コネクションが進まなくなるため)。
     * 単一コアのときは従来どおり owner_core だけが見る。 */
    unsigned n = g_net_mt_cores;
    if (n > 1u) {
        if (core == 0u || core > n) {
            netif_activate(prev);
            return 0;
        }
    }

    /* **時間で進める IPv6 の仕事**(DAD の判定、MLD の再送、寿命切れの掃除)を、
     * 受信を見るコアの 256 周に 1 回だけ呼ぶ。IPv6 のフレームが来ないあいだも進める
     * ため。仕事が無ければ ipv6_timer_tick() は旗を 1 つ読んで戻る。 */
    {
        static uint32_t s_tick_div[SMP_MAX_CORES];
        if (((++s_tick_div[core]) & 0xFFu) == 0u) ipv6_timer_tick();
    }

    /* **受信フレーム数はローカルに溜めて、最後に 1 回だけ書く。**
     * volatile な 64bit の read-modify-write を**フレームごとに**回すと
     * read が目に見えて落ちる(512B read 264k -> 168k、4K read 184k -> 144k)。
     * `g_net_mt_cores > 1` にしただけで分散していなくても落ちるので、
     * 「分散が遅い」と誤読しかけた。**診断カウンタの代金は、診断したい
     * 効果と同じ桁になりうる。** */
    unsigned consumed = 0;
    const int rs_on = (int)g_rxstat_on;
    uint64_t rs_t0 = rs_on ? rxstat_tsc() : 0u;

    /* **前の巡回で応答へ相乗りできなかった ACK をここで返す。**
     * 借りが無ければ何もしない(コアごとの旗 1 個を見るだけ)。 */
    tcp_ack_flush_deferred();
    /* 待ち行列で確立した接続の引き渡しは持ち主のコアが行う(待っている
     * ジョブが別のコアに居ても、ここで受け皿へ渡して accept_ready を立てる)。 */
    tcp_backlog_service();

    for (unsigned i = 0; i < s_registered_count; i++) {
        netif_t *ctx = s_registered[i];
        if (!ctx->is_poll_owner) {
            continue;
        }
        if (n <= 1u && ctx->owner_core != core) {
            continue;   /* 単一コア: 持ち主だけ */
        }
        netif_activate(ctx);
        if (rs_on && ctx->nic->rx_pending) {
            unsigned pv = ctx->nic->rx_pending(ctx->nic_priv);
            s_rxstat[core].pend[pv >= 192u ? 4u : pv >= 128u ? 3u : pv >= 64u ? 2u : pv >= 32u ? 1u : 0u]++;
        }
        unsigned k;
        for (k = 0; k < NET_POLL_BATCH_MAX; k++) {
            net_buf_t *nb = ctx->nic->poll_recv(ctx->nic_priv); // -> rp1_poll_recv / mlx5_net_poll_recv
            if (!nb) {
                break;
            }
            got_frame = 1;
            consumed++;
            netif_t *owner = netif_resolve_frame_owner(ctx, nb);
            if (owner != ctx) {
                netif_activate(owner);
            }
            eth_dispatch(nb);
            net_buf_free(nb);
            if (owner != ctx) {
                netif_activate(ctx);
            }
        }
        if (rs_on) {
            s_rxstat[core].polls++;
            s_rxstat[core].frames += k;
            s_rxstat[core].hist[rxstat_bucket(k)]++;
        }
    }
    if (rs_on) {
        uint64_t t1 = rxstat_tsc();
        rxstat_t *s = &s_rxstat[core];
        if (!s->tsc_first) s->tsc_first = rs_t0;
        s->tsc_last = t1;
        s->tsc_in += t1 - rs_t0;
        s->calls++;
    }

    if (n > 1u && consumed != 0u) {
        g_net_mt_consumed[core].v += consumed;
    }

    netif_activate(prev);
    return got_frame;
}
