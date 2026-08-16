#include "netif.h"
#include <stddef.h>
#include "timestamp.h"   /* 同上 */
#include "cache.h"
#include "uart.h"

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
