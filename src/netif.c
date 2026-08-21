#include "netif.h"
#include <stddef.h>
#include "timestamp.h"   /* 同上 */
#include "cache.h"
#include "uart.h"
#include "arp.h"
#include "ipv6.h"
#include "timer.h"

volatile uint32_t g_neigh_cache_ttl_ms = NEIGH_CACHE_TTL_DEFAULT_MS;

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
    return timer_now() + (uint64_t)g_neigh_cache_ttl_ms * 1000000ull;
}

/*=================================================================
 * 近隣キャッシュ 1 エントリの寿命を判定する(ARP/NDP 共通)。判定は
 * 3 段階で、失効しても猶予のあいだは使い続けてよい(netif.h の説明を参照)。
 *
 * timer_now() が ns を返すので、除算の要る timeout_ms() ではなく絶対時刻の
 * 差で比較する。送信 1 セグメントごとに通る経路なので除算は入れない。
 *
 * 引数:
 *   now        - 現在時刻(呼び出し元が 1 回だけ読んで渡す)
 *   expires_at - このエントリの有効期限
 *   probe_at   - 次に確認要求を出してよい時刻。出す番なら更新して返す
 * 戻り値:
 *   NEIGH_FRESH / NEIGH_STALE / NEIGH_STALE_PROBE / NEIGH_DEAD
 * コール元:
 *   arp_cache_lookup(), ndp_cache_lookup()
 * ===============================================================*/
int neigh_check_age(uint64_t now, uint64_t expires_at, uint64_t *probe_at)
{
    if ((int64_t)(now - expires_at) < 0) return NEIGH_FRESH;

    uint32_t ttl_ms = g_neigh_cache_ttl_ms;
    uint64_t grace_ns = (uint64_t)(ttl_ms / 6u) * 1000000ull;
    if ((int64_t)(now - (expires_at + grace_ns)) >= 0) return NEIGH_DEAD;

    if ((int64_t)(now - *probe_at) >= 0) {
        uint32_t interval_ms = ttl_ms / 60u;
        if (interval_ms < 10u) interval_ms = 10u;
        *probe_at = now + (uint64_t)interval_ms * 1000000ull;
        return NEIGH_STALE_PROBE;
    }
    return NEIGH_STALE;
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

    for (int i = 0; i < HANDLER_MAX; i++) {
        if (g_handlers[i].used && g_handlers[i].ethertype == etype) {
            g_handlers[i].handler(payload, plen, src_mac); // -> arp_handle_frame / ip_handle_frame
            break;
        }
    }
    s_rx_hw_csum_ok[core] = 0;
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

    for (unsigned i = 0; i < s_registered_count; i++) {
        netif_t *ctx = s_registered[i];
        if (ctx->owner_core != core || !ctx->is_poll_owner) {
            continue;
        }
        netif_activate(ctx);
        for (unsigned n = 0; n < NET_POLL_BATCH_MAX; n++) {
            net_buf_t *nb = ctx->nic->poll_recv(ctx->nic_priv); // -> rp1_poll_recv / mlx5_net_poll_recv
            if (!nb) {
                break;
            }
            got_frame = 1;
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
    }

    netif_activate(prev);
    return got_frame;
}
