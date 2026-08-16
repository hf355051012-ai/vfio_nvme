#ifndef NETIF_H
#define NETIF_H

#include <stdint.h>
#include <stddef.h>
#include "net_buf.h"
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
} arp_cache_entry_t;

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
    const nic_ops_t *nic;
    void       *nic_priv;
    arp_cache_entry_t arp_cache[ARP_CACHE_SIZE];
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

int net_poll_all_and_dispatch(void);

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
