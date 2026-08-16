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

int arp_cache_lookup(uint32_t ip, uint8_t out_mac[6]);

int arp_resolve(uint32_t ip, uint8_t out_mac[6]);

#endif /* ARP_H */
