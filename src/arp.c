#include <stddef.h>
#include "arp.h"
#include "netif.h"
#include "net_buf.h"
#include "net.h"
#include "netif.h"
#include "uart.h"
#include "timer.h"

#define ARP_OFF_HTYPE offsetof(arp_packet_t, htype)
#define ARP_OFF_PTYPE offsetof(arp_packet_t, ptype)
#define ARP_OFF_HLEN  offsetof(arp_packet_t, hlen)
#define ARP_OFF_PLEN  offsetof(arp_packet_t, plen)
#define ARP_OFF_OPER  offsetof(arp_packet_t, oper)
#define ARP_OFF_SHA   offsetof(arp_packet_t, sha)
#define ARP_OFF_SPA   offsetof(arp_packet_t, spa)
#define ARP_OFF_THA   offsetof(arp_packet_t, tha)
#define ARP_OFF_TPA   offsetof(arp_packet_t, tpa)

/* ------------------------------------------------------------------ */
/* IP->MAC 簡易キャッシュ                                                */
/* ------------------------------------------------------------------ */

#define ARP_RESOLVE_TIMEOUT_MS 300u /* 1回のrequestあたりのポーリング待ち */
#define ARP_RESOLVE_MAX_ATTEMPTS 3u /* requestを再送する最大回数(合計最大約900ms) */

static void arp_cache_insert(uint32_t ip, const uint8_t mac[ETH_ALEN])
{
    arp_cache_entry_t *cache = g_active_ctx->arp_cache;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].ip == ip) {
            for (int j = 0; j < ETH_ALEN; j++) cache[i].mac[j] = mac[j];
            return;
        }
    }
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            cache[i].ip = ip;
            for (int j = 0; j < ETH_ALEN; j++) cache[i].mac[j] = mac[j];
            cache[i].valid = 1;
            return;
        }
    }
    cache[0].ip = ip;
    for (int j = 0; j < ETH_ALEN; j++) cache[0].mac[j] = mac[j];
    cache[0].valid = 1;
}

int arp_cache_lookup(uint32_t ip, uint8_t out_mac[ETH_ALEN])
{
    arp_cache_entry_t *cache = g_active_ctx->arp_cache;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].ip == ip) {
            for (int j = 0; j < ETH_ALEN; j++) out_mac[j] = cache[i].mac[j];
            return 0;
        }
    }
    return -1;
}

void arp_init(void)
{
    eth_register_handler(0x0806u, arp_handle_frame);  /* EtherType: ARP */
}

void arp_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac)
{
    if (len < sizeof(arp_packet_t)) {
        uart_printf("[ARP] フレーム長不足 (len=%u < %u)\n",
                    (unsigned)len, (unsigned)sizeof(arp_packet_t));
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = payload;

    uint16_t htype = rd16be(in + ARP_OFF_HTYPE);
    uint16_t ptype = rd16be(in + ARP_OFF_PTYPE);
    uint8_t  hlen  = in[ARP_OFF_HLEN];
    uint8_t  plen  = in[ARP_OFF_PLEN];
    uint16_t oper  = rd16be(in + ARP_OFF_OPER);

    if (htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 ||
        hlen != ETH_ALEN || plen != 4) {
        uart_printf("[ARP] 非対応フォーマット (htype=%u ptype=0x%04X hlen=%u plen=%u) 無視\n",
                    htype, ptype, hlen, plen);
        return;
    }

    if (oper == ARP_OP_REPLY) {
        uint32_t sender_ip = rd32be(in + ARP_OFF_SPA);
        uint8_t sender_mac[ETH_ALEN];
        for (int i = 0; i < ETH_ALEN; i++) sender_mac[i] = in[ARP_OFF_SHA + i];
        arp_cache_insert(sender_ip, sender_mac);
        return;
    }

    uint32_t target_ip = rd32be(in + ARP_OFF_TPA);

    if (oper != ARP_OP_REQUEST || target_ip != NET_SELF_IP) {
        return;
    }

    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] ARP reply: net_bufプール枯渇\n");
        return;
    }

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t self_ip[4];
    ip_to_octets(NET_SELF_IP, self_ip);

    const volatile uint8_t *vsrc_mac = src_mac;

    volatile uint8_t *out = nb->data;

    /* Ethernetヘッダ: dst=要求元, src=自分, type=ARP(0x0806) */
    for (int i = 0; i < ETH_ALEN; i++) out[i]            = vsrc_mac[i];
    for (int i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x08;
    out[13] = 0x06;

    volatile uint8_t *rep = out + ETH_HDR_LEN;
    wr16be(rep + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
    wr16be(rep + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
    rep[ARP_OFF_HLEN] = ETH_ALEN;
    rep[ARP_OFF_PLEN] = 4;
    wr16be(rep + ARP_OFF_OPER, ARP_OP_REPLY);
    for (int i = 0; i < ETH_ALEN; i++) rep[ARP_OFF_SHA + i] = self_mac[i];
    for (int i = 0; i < 4;        i++) rep[ARP_OFF_SPA + i] = self_ip[i];
    for (int i = 0; i < ETH_ALEN; i++) rep[ARP_OFF_THA + i] = in[ARP_OFF_SHA + i];
    for (int i = 0; i < 4;        i++) rep[ARP_OFF_TPA + i] = in[ARP_OFF_SPA + i];

    nb->len = ETH_HDR_LEN + sizeof(arp_packet_t);

    if (eth_send(nb) != 0)
        uart_printf("[!] ARP reply 送信失敗\n");
}

int arp_send_request(uint32_t target_ip)
{
    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] ARP request: net_bufプール枯渇\n");
        return -1;
    }

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t self_ip[4];
    ip_to_octets(NET_SELF_IP, self_ip);
    uint8_t tpa[4];
    ip_to_octets(target_ip, tpa);

    volatile uint8_t *out = nb->data;

    /* Ethernetヘッダ: dst=ブロードキャスト, src=自分, type=ARP(0x0806) */
    for (int i = 0; i < ETH_ALEN; i++) out[i]            = 0xFFu;
    for (int i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x08;
    out[13] = 0x06;

    volatile uint8_t *req = out + ETH_HDR_LEN;
    wr16be(req + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
    wr16be(req + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
    req[ARP_OFF_HLEN] = ETH_ALEN;
    req[ARP_OFF_PLEN] = 4;
    wr16be(req + ARP_OFF_OPER, ARP_OP_REQUEST);
    for (int i = 0; i < ETH_ALEN; i++) req[ARP_OFF_SHA + i] = self_mac[i];
    for (int i = 0; i < 4;        i++) req[ARP_OFF_SPA + i] = self_ip[i];
    for (int i = 0; i < ETH_ALEN; i++) req[ARP_OFF_THA + i] = 0x00u; /* requestでは未使用(0埋め) */
    for (int i = 0; i < 4;        i++) req[ARP_OFF_TPA + i] = tpa[i];

    nb->len = ETH_HDR_LEN + sizeof(arp_packet_t);

    uart_printf("[ARP] request 送信: who-has %u.%u.%u.%u tell %u.%u.%u.%u\n",
                tpa[0], tpa[1], tpa[2], tpa[3],
                self_ip[0], self_ip[1], self_ip[2], self_ip[3]);

    int ret = eth_send(nb);
    if (ret != 0)
        uart_printf("[!] ARP request 送信失敗\n");
    return ret;
}

int arp_resolve(uint32_t ip, uint8_t out_mac[ETH_ALEN])
{
    if (arp_cache_lookup(ip, out_mac) == 0) {
        return 0;
    }

    for (unsigned attempt = 0; attempt < ARP_RESOLVE_MAX_ATTEMPTS; attempt++) {
        if (arp_send_request(ip) != 0) {
            return -1;
        }

        uint64_t start = timer_now();
        do {
            net_poll_all_and_dispatch();
            if (arp_cache_lookup(ip, out_mac) == 0) {
                return 0;
            }
        } while (!timeout_ms(start, ARP_RESOLVE_TIMEOUT_MS));
    }

    return -1;
}
