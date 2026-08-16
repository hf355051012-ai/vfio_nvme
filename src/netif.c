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

int eth_rx_hw_csum_ok(void)
{
    return s_rx_hw_csum_ok[smp_core_index()];
}

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

void eth_get_mac(uint8_t mac[ETH_ALEN])
{
    for (int i = 0; i < ETH_ALEN; i++) {
        mac[i] = g_active_ctx ? g_active_ctx->mac[i] : 0u;
    }
}

int eth_send_frags(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) {
        uart_printf("[eth] eth_send_frags: アクティブなインターフェースが無い\n");
        return -1;
    }
    return g_active_ctx->nic->send_frags(g_active_ctx->nic_priv, frags, frag_count); // -> mlx5_net_send_frags
}

int eth_send_frags_async(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) return -1;
    return g_active_ctx->nic->send_frags_async(g_active_ctx->nic_priv, frags, frag_count); // -> mlx5_net_send_frags_async
}

int eth_send_lso_async(const void *hdr, uint16_t hdr_len,
                       const void *payload, uint32_t payload_len, uint16_t mss)
{
    if (!g_active_ctx || !g_active_ctx->nic->send_lso) return -1;
    return g_active_ctx->nic->send_lso(g_active_ctx->nic_priv, hdr, hdr_len, payload, payload_len, mss); // -> mlx5_net_send_lso_async
}

unsigned eth_tx_wait_free_slot(void)
{
    if (!g_active_ctx) return 0;
    return g_active_ctx->nic->tx_wait_free_slot(g_active_ctx->nic_priv); // -> mlx5_net_tx_wait_free_slot
}

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

void netif_set_owner_core(netif_t *ctx, unsigned core)
{
    ctx->owner_core = core;
}

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

netif_t *netif_find_by_ip(uint32_t ip)
{
    for (unsigned i = 0; i < s_registered_count; i++) {
        if (s_registered[i]->ip == ip) {
            return s_registered[i];
        }
    }
    return NULL;
}

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
