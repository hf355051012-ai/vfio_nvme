#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * udp.h — UDPエコーサーバ — フェーズ4
 * ================================================================ */

#define IP_PROTO_UDP    17u

/* エコーサーバのポート(決め打ち)。標準Echo(7)と紛らわしくない値にする。 */
#define UDP_ECHO_PORT   7777u

/* udpstat コマンド用の統計カウンタ */
extern volatile uint32_t g_udp_recv_count;
extern volatile uint32_t g_udp_echo_reply_count;

/* ip.c(protocol==17)から呼ばれるUDPペイロード処理本体。
 * src_ip/dst_ip: 受信時のIPv4アドレス(4バイト、生バイト列)
 * payload/len:   UDPヘッダ+データ全体
 * src_mac:       送信元MACアドレス(応答の宛先MACとして使う)
 */
void udp_handle(const uint8_t src_ip[4], const uint8_t dst_ip[4],
                const uint8_t *payload, size_t len, const uint8_t *src_mac);

/* UDPパケットを構築し、ip_send()経由で送信する。
 * dst_ip/dst_mac:     宛先
 * src_port/dst_port:  ポート番号(ホストバイトオーダー)
 * data/data_len:      UDPペイロード
 * 戻り値: ip_send()の戻り値をそのまま返す(0=成功, -1=失敗)
 */
int udp_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
             uint16_t src_port, uint16_t dst_port,
             const uint8_t *data, uint16_t data_len);

#endif /* UDP_H */
