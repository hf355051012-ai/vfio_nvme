#ifndef NETIF_H
#define NETIF_H

#include <stdint.h>
#include <stddef.h>
#include "net_buf.h"
#include "netaddr.h"
#include "smp.h"

#define ETH_ALEN            6
#define ETH_HDR_LEN         14      /* dst(6) + src(6) + ethertype(2) */
#define ETH_JUMBO_MAX_LEN   10240u  /* ジャンボフレームの最大長(ヘッダ+ペイロード+FCS) */

/* 送信フレームを構成する1個の断片(スキャッタ・ギャザー送信用)。 */
typedef struct {
    const void *data;
    uint16_t    len;
} eth_frag_t;

#define ETH_TX_MAX_FRAGS 2

#define ETH_RX_RING_SIZE 128
#define ETH_TX_RING_SIZE 256

/* 自機の MAC アドレス(アクティブインターフェースのもの)を取得する。 */
void eth_get_mac(uint8_t mac[ETH_ALEN]);

int eth_send(net_buf_t *nb);

int eth_send_frags(const eth_frag_t *frags, unsigned frag_count);

int eth_send_frags_async(const eth_frag_t *frags, unsigned frag_count);

int eth_send_lso_async(const void *hdr, uint16_t hdr_len,
                       const void *payload, uint32_t payload_len, uint16_t mss);

unsigned eth_tx_wait_free_slot(void);

typedef void (*eth_handler_t)(const uint8_t *payload, size_t len, const uint8_t *src_mac);

/* EtherType に対するハンドラを登録する(再登録は上書き、NULL で解除)。 */
void eth_register_handler(uint16_t ethertype, eth_handler_t handler);

/* nb の EtherType に応じて登録済みハンドラを呼ぶ。nb の解放は呼び出し側の責任。 */
void eth_dispatch(net_buf_t *nb);

int eth_rx_hw_csum_ok(void);

#define ARP_CACHE_SIZE 8u

typedef struct {
    uint32_t ip;
    uint8_t  mac[ETH_ALEN];
    int      valid;
    uint64_t expires_at;  /* この時刻(timer_now() の ns)を過ぎたら stale */
    uint64_t probe_at;    /* stale 中、次に確認要求を出してよい時刻 */
} arp_cache_entry_t;

/* IPv6 の近隣キャッシュ。ARP と役割は同じだが、解決手段が ARP ではなく
 * ICMPv6 の Neighbor Solicitation/Advertisement(NDP)になる。 */
#define NDP_CACHE_SIZE 8u

typedef struct {
    uint8_t  addr[16];
    uint8_t  mac[ETH_ALEN];
    int      valid;
    uint64_t expires_at;
    uint64_t probe_at;
} ndp_cache_entry_t;

/* ---- 近隣キャッシュ(ARP/NDP 共通)のエージング ----
 *
 * 一度入れたら永久に有効だと、相手の NIC 交換や IP 移動に追従できない。
 * ただし **失効したエントリを即座に捨ててはいけない**。捨てると次の送信で
 * arp_resolve()(最大 900ms のポーリング待ち)が tcp_send() のバルク送信
 * ループの内側で走り、しかもその中の net_poll_all_and_dispatch() が
 * tcp_input_addr() を再入させて別の送信 -> 再びキャッシュミス -> 入れ子の
 * arp_resolve() という連鎖を作る(深さに上限が無い)。
 *
 * そこで Linux の NUD と同じく「失効しても確認が取れるまでは使い続ける」形に
 * する。lookup は stale なエントリでも MAC を返し、代わりに確認要求
 * (ARP request / NS)を probe 間隔で投げる。相手が応答すれば insert が
 * 呼ばれて延命し、猶予時間ぶん応答が無ければそこで初めて破棄する。
 * これで送信ホットパスがブロックすることは一度も無い。 */
#define NEIGH_FRESH        0   /* 有効期限内 */
#define NEIGH_STALE        1   /* 失効したが猶予中。使ってよい */
#define NEIGH_STALE_PROBE  2   /* 同上。加えて今回は確認要求を出す番 */
#define NEIGH_DEAD        -1   /* 猶予も尽きた。破棄する */

/* 有効期間(ミリ秒)。猶予は TTL/6、確認要求の間隔は TTL/60 として連動する。
 * シェルの `arpage` で変更できる(短くして検証するため)。 */
extern volatile uint32_t g_neigh_cache_ttl_ms;
#define NEIGH_CACHE_TTL_DEFAULT_MS 60000u

int neigh_check_age(uint64_t now, uint64_t expires_at, uint64_t *probe_at);
uint64_t neigh_expiry_from_now(void);

typedef struct {
    int (*send_frags)(void *priv, const eth_frag_t *frags, unsigned frag_count);
    int (*send_frags_async)(void *priv, const eth_frag_t *frags, unsigned frag_count);
    int (*send_lso)(void *priv, const void *hdr, uint16_t hdr_len,
                     const void *payload, uint32_t payload_len, uint16_t mss);
    unsigned (*tx_wait_free_slot)(void *priv);
    net_buf_t *(*poll_recv)(void *priv);
} nic_ops_t;

typedef struct netif {
    const char *name;   /* ログ/`net use`コマンド用の識別子("rp1","mlx5-pf0"等) */
    uint8_t     mac[ETH_ALEN];
    uint32_t    ip;      /* 自機IPv4(ホストバイトオーダー)。net.hのNET_SELF_IPが参照する */
    /* ルーティング(経路表は「デフォルトゲートウェイ 1 本」で足りる。宛先が
     * 自分のサブネット外なら、L2 の解決先を宛先ではなくゲートウェイにする)。
     * gateway=0 なら未設定で、全ての宛先を同一リンク上として扱う従来の挙動。 */
    uint32_t    netmask;        /* IPv4 サブネットマスク(ホストバイトオーダー) */
    uint32_t    gateway;        /* IPv4 デフォルトゲートウェイ。0=未設定 */
    uint8_t     gateway6[16];   /* IPv6 デフォルトルータ(通常はリンクローカル) */
    uint8_t     gateway6_set;   /* 1=gateway6 が有効。毎パケットの 16 バイト走査を避ける */
    /* 重複アドレス検出の結果。IPv6 のリンクローカルは MAC から毎回導出して
     * いて netif_t に持たないので、「検査したか」の状態はここに置くしかない。 */
    uint8_t     dad_state;      /* NETIF_DAD_*(IPv6 リンクローカル) */
    uint8_t     ipv4_dup;       /* NETIF_DAD_*(IPv4 アドレス) */
    uint8_t     dup_mac6[ETH_ALEN];  /* IPv6 で衝突した相手の MAC(表示用) */
    uint8_t     dup_mac4[ETH_ALEN];  /* IPv4 で衝突した相手の MAC(表示用) */
    const nic_ops_t *nic;
    void       *nic_priv;
    arp_cache_entry_t arp_cache[ARP_CACHE_SIZE];
    ndp_cache_entry_t ndp_cache[NDP_CACHE_SIZE];
    uint16_t    mss_cap;
    uint16_t    rx_ring_size;
    uint8_t     hw_csum_offload;
    uint8_t     tx_zerocopy_2frag;
    uint32_t    hw_lso_max_bytes;
    unsigned    owner_core;
    int         is_poll_owner;
} netif_t;

extern netif_t *g_netif_active_slots[SMP_MAX_CORES];

static inline netif_t **netif_active_slot(void)
{
    return &g_netif_active_slots[smp_core_index()];
}
#define g_active_ctx (*netif_active_slot())

void netif_activate(netif_t *ctx);

#define NETIF_MAX_REGISTERED 4u
void netif_register(netif_t *ctx);

void netif_set_owner_core(netif_t *ctx, unsigned core);

netif_t *netif_find(const char *name);

netif_t *netif_find_by_ip(uint32_t ip);

netif_t *netif_find_by_ip6(const uint8_t addr[16]);

void netif_unregister(netif_t *ctx);

int net_poll_all_and_dispatch(void);

/*=================================================================
 * dst へ送るとき、実際に L2 アドレスを解決すべき相手(次ホップ)の IPv4 を
 * 返す。同一サブネットなら宛先そのもの、サブネット外ならゲートウェイ。
 *
 * 引数:
 *   ni  - 送信元インターフェース(NULL 可)
 *   dst - 宛先 IPv4(ホストバイトオーダー)
 * 戻り値:
 *   ARP を引くべき IPv4(ホストバイトオーダー)
 * コール元:
 *   tcp_resolve_mac(), net_resolve_mac(), shell_route()
 * ===============================================================*/
static inline uint32_t netif_next_hop4(const netif_t *ni, uint32_t dst)
{
    /* ゲートウェイ未設定なら従来どおり「宛先は必ず同一リンク上」。 */
    if (!ni || ni->gateway == 0u || ni->netmask == 0u) return dst;
    /* ブロードキャストとマルチキャストはルータへ渡さない。 */
    if (dst == 0xFFFFFFFFu) return dst;
    if ((dst & 0xF0000000u) == 0xE0000000u) return dst;
    /* 同一サブネットなら宛先を直接解決する(サブネットブロードキャストも
     * マスク内なのでこの判定に含まれる)。 */
    if (((dst ^ ni->ip) & ni->netmask) == 0u) return dst;
    return ni->gateway;
}

/*=================================================================
 * netif_next_hop4() の IPv6 版。戻り値は dst か ni->gateway6 のどちらかを
 * 指すポインタで、コピーは発生しない。
 *
 * 引数:
 *   ni  - 送信元インターフェース(NULL 可)
 *   dst - 宛先 IPv6(16 バイト)
 * 戻り値:
 *   NDP を引くべきアドレスへのポインタ
 * コール元:
 *   tcp_resolve_mac(), net_resolve_mac(), shell_route()
 * ===============================================================*/
static inline const uint8_t *netif_next_hop6(const netif_t *ni, const uint8_t dst[16])
{
    if (!ni || !ni->gateway6_set) return dst;
    if (dst[0] == 0xFFu) return dst;                              /* ff00::/8 マルチキャスト */
    if (dst[0] == 0xFEu && (dst[1] & 0xC0u) == 0x80u) return dst; /* fe80::/10 リンクローカル */
    return ni->gateway6;
}

/* dst への送信に使う宛先 MAC を解決する(必要ならゲートウェイの MAC を引く)。
 * IPv4 は ARP、IPv6 は NDP。0=解決できた、-1=失敗。 */
int net_resolve_mac(const netaddr_t *dst, uint8_t out_mac[ETH_ALEN]);

/* ---- 重複アドレス検出の結果(netif_t.dad_state / ipv4_dup)---- */
#define NETIF_DAD_UNKNOWN   0   /* 未実施 */
#define NETIF_DAD_PASSED    1   /* 衝突なし */
#define NETIF_DAD_CONFLICT  2   /* 衝突を検出した */

/* インターフェースの IPv4 アドレスと IPv6 リンクローカルの両方について
 * 重複アドレス検出を行い、結果を netif_t へ記録する。0=どちらも衝突なし、
 * -1=いずれかで衝突を検出した(ログに大きく出す)。
 *
 * **衝突を見つけてもアドレスの使用は止めない。** この装置は 2 ポートを同一
 * プロセスで駆動しているので、誤検出でアドレスを封じると全部止まる。RFC の
 * 要求は「検出して警告する」までを満たし、停止の判断は運用に委ねる。 */
int net_dup_addr_detect(netif_t *ctx);

static inline uint32_t net_active_ip(void)
{
    return g_active_ctx ? g_active_ctx->ip : 0u;
}

static inline uint16_t net_active_mss_cap(void)
{
    return g_active_ctx ? g_active_ctx->mss_cap : 1460u;
}

static inline uint16_t net_active_rx_ring_size(void)
{
    return (g_active_ctx && g_active_ctx->rx_ring_size) ? g_active_ctx->rx_ring_size
                                                        : (uint16_t)ETH_RX_RING_SIZE;
}

static inline int net_active_hw_csum_offload(void)
{
    return g_active_ctx ? g_active_ctx->hw_csum_offload : 0;
}

static inline int net_active_tx_zerocopy(void)
{
    return g_active_ctx ? g_active_ctx->tx_zerocopy_2frag : 0;
}

static inline uint32_t net_active_lso_max_bytes(void)
{
    return g_active_ctx ? g_active_ctx->hw_lso_max_bytes : 0u;
}

#endif /* NETIF_H */
