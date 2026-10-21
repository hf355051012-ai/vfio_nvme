#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <stddef.h>
#include "netaddr.h"

#define UDP_HDR_LEN 8u

/* RoCEv2 の固定宛先ポート。自分の RDMA トラフィックが catch-all フロー
 * ステアリング経由で Ethernet RX にも複製されて来るため、ip.c がこのポート宛の
 * 「待ち受け無し」に対して ICMP エラーを返さないよう除外するのに使う。 */
#define UDP_PORT_ROCEV2 4791u

/* ポートに紐づく受信ハンドラ。data はペイロード先頭(UDP ヘッダの直後)。
 * src は IPv4/IPv6 のどちらもありうる(family を見て区別する)。
 * dst は受け取ったデータグラムの宛先(自分のアドレスか、IPv4 のブロードキャスト)。
 * **応答の送信元を選ぶのに要る**(RFC 1122 4.1.3.5 は宛先を上位へ渡すことを MUST とする)。 */
typedef void (*udp_handler_t)(const uint8_t *data, size_t len,
                               const netaddr_t *src, uint16_t src_port,
                               const netaddr_t *dst, const uint8_t *src_mac);

/* ポートに紐づく ICMP エラーのハンドラ(RFC 1122 4.1.3.3:UDP は受けた ICMP エラーを
 * 上位へ渡す MUST)。remote / remote_port は引用されたデータグラムの宛先(= 相手)、
 * local_port は自分のポート。type / code は ICMP(v6 なら ICMPv6)のもの。 */
typedef void (*udp_error_handler_t)(const netaddr_t *remote, uint16_t remote_port,
                                     uint16_t local_port, uint8_t type, uint8_t code, int v6);
int udp_set_error_handler(uint16_t port, udp_error_handler_t fn);

/* ICMP / ICMPv6 のエラーが引用した UDP ヘッダを渡す(icmp.c / ipv6.c から)。 */
void udp_icmp_error(const netaddr_t *remote, const uint8_t *quoted_udp, size_t qlen,
                    uint8_t type, uint8_t code, int v6);

void udp_init(void);

int udp_bind(uint16_t port, udp_handler_t handler);

void udp_unbind(uint16_t port);

int udp_input_addr(const uint8_t *data, size_t len,
                   const netaddr_t *src, const netaddr_t *dst,
                   const uint8_t *src_mac);

int udp_input(const uint8_t *data, size_t len,
              const uint8_t src_ip[4], const uint8_t dst_ip[4],
              const uint8_t *src_mac);

int udp_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
             uint16_t src_port, uint16_t dst_port,
             const uint8_t *payload, uint16_t payload_len);

int udp_send6(const uint8_t dst[16], const uint8_t dst_mac[6],
              uint16_t src_port, uint16_t dst_port,
              const uint8_t *payload, uint16_t payload_len);

#endif /* UDP_H */
