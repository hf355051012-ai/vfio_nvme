#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stddef.h>
#include "smp.h"

#define ICMP_TYPE_ECHO_REPLY    0u
#define ICMP_TYPE_DEST_UNREACH  3u
#define ICMP_TYPE_ECHO_REQUEST  8u
#define ICMP_TYPE_TIME_EXCEEDED 11u

/* Destination Unreachable の code(RFC 792) */
#define ICMP_CODE_PROTO_UNREACH 2u
#define ICMP_CODE_PORT_UNREACH  3u
/* code=4 は「分割が必要だが DF が立っている」。RFC 1191 でこのメッセージに
 * 次ホップの MTU を載せる拡張が入り、Path MTU Discovery の土台になった。
 * **MTU が入るのは未使用 4 バイトの下位 16bit(ICMP ヘッダの byte 6-7)**で、
 * byte 4-5 は 0 でなければならない。ここを取り違えやすい
 * (ICMPv6 の Packet Too Big は 32bit 全体が MTU で、layout が違う)。 */
#define ICMP_CODE_FRAG_NEEDED   4u

extern volatile uint32_t g_icmp_echo_request_count[SMP_MAX_CORES];
extern volatile uint32_t g_icmp_echo_reply_sent_count[SMP_MAX_CORES];

extern volatile uint64_t g_icmp_echo_reply_time[SMP_MAX_CORES];

void icmp_handle(const uint8_t *data, size_t len,
                 const uint8_t src_ip[4], const uint8_t *src_mac);

int icmp_send_dest_unreach(uint8_t code,
                            const uint8_t *orig_ip_hdr, size_t orig_len,
                            const uint8_t src_ip[4], const uint8_t *src_mac);

#endif /* ICMP_H */
