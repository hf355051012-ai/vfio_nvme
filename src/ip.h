#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <stddef.h>
#include "net_buf.h"
#include "netif.h"

#define IP_PROTO_ICMP 1u
#define IP_PROTO_TCP  6u

typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;      /* [7:4]version(4) [3:0]IHL(ワード数、オプション無しなら5) */
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
} ip_header_t;

#define IP_PAYLOAD_OFFSET (ETH_HDR_LEN + (unsigned)sizeof(ip_header_t))

void ip_init(void);

void ip_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac);

void ip_build_header(uint8_t *buf, const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                      uint8_t protocol, uint16_t payload_len);

int ip_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
            uint8_t protocol, const uint8_t *payload, uint16_t payload_len);

net_buf_t *ip_prepare_send_buf(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                                uint8_t protocol, uint16_t payload_len);

int ip_send_prepared(net_buf_t *nb, uint16_t payload_len);

#endif /* IP_H */
