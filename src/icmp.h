#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stddef.h>
#include "smp.h"

#define ICMP_TYPE_ECHO_REPLY    0u
#define ICMP_TYPE_ECHO_REQUEST  8u

extern volatile uint32_t g_icmp_echo_request_count[SMP_MAX_CORES];
extern volatile uint32_t g_icmp_echo_reply_sent_count[SMP_MAX_CORES];

extern volatile uint64_t g_icmp_echo_reply_time[SMP_MAX_CORES];

void icmp_handle(const uint8_t *data, size_t len,
                 const uint8_t src_ip[4], const uint8_t *src_mac);

#endif /* ICMP_H */
