#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <stddef.h>

#define UDP_HDR_LEN 8u

/* RoCEv2 の固定宛先ポート。自分の RDMA トラフィックが catch-all フロー
 * ステアリング経由で Ethernet RX にも複製されて来るため、ip.c がこのポート宛の
 * 「待ち受け無し」に対して ICMP エラーを返さないよう除外するのに使う。 */
#define UDP_PORT_ROCEV2 4791u

/* ポートに紐づく受信ハンドラ。data はペイロード先頭(UDP ヘッダの直後)。 */
typedef void (*udp_handler_t)(const uint8_t *data, size_t len,
                               const uint8_t src_ip[4], uint16_t src_port,
                               const uint8_t *src_mac);

void udp_init(void);

int udp_bind(uint16_t port, udp_handler_t handler);

void udp_unbind(uint16_t port);

int udp_input(const uint8_t *data, size_t len,
              const uint8_t src_ip[4], const uint8_t dst_ip[4],
              const uint8_t *src_mac);

int udp_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
             uint16_t src_port, uint16_t dst_port,
             const uint8_t *payload, uint16_t payload_len);

#endif /* UDP_H */
