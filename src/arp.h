#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stddef.h>

#define ARP_HTYPE_ETHERNET  1u      /* Hardware type: Ethernet */
#define ARP_PTYPE_IPV4      0x0800u /* Protocol type: IPv4 */
#define ARP_OP_REQUEST      1u
#define ARP_OP_REPLY        2u

typedef struct __attribute__((packed)) {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];  /* Sender Hardware Address */
    uint8_t  spa[4];  /* Sender Protocol Address (IPv4) */
    uint8_t  tha[6];  /* Target Hardware Address */
    uint8_t  tpa[4];  /* Target Protocol Address (IPv4) */
} arp_packet_t;

void arp_init(void);

void arp_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac);

int arp_send_request(uint32_t target_ip);

/* 解決済みの IP -> MAC を登録する(= エントリの延命)。通常は ARP reply の
 * 受信時に内部から呼ばれる。`arptest` が応答の来ない相手を仕込むのにも使う。 */
void arp_cache_insert(uint32_t ip, const uint8_t mac[6]);

int arp_cache_lookup(uint32_t ip, uint8_t out_mac[6]);

/* キャッシュを引かずにエントリの寿命だけを見る(`arptest` の観測用)。
 * 0=fresh、1=stale(猶予中)、-1=未登録。remain_ms は残り猶予/寿命。 */
int arp_cache_peek(uint32_t ip, uint32_t *remain_ms);

int arp_resolve(uint32_t ip, uint8_t out_mac[6]);

#endif /* ARP_H */
