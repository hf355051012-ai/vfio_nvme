#ifndef IPSEC_H
#define IPSEC_H

/* IPsec の ESP(RFC 4303、トランスポートモード、IPv4)。iSCSI(RFC 7143 8 章)が求める
 * データの保護。鍵は IKEv2(ike.c)が作って ipsec_sa_install() で入れる。
 *
 *   - 暗号は AES-GCM-16 / 128 ビット(RFC 4106)。鍵 16 バイト + salt 4 バイト。
 *     nonce = salt || IV(8)、AAD = SPI || 順序番号(ESN は使わない)、ICV 16 バイト。
 *   - **方針(policy)を持つ相手との IPv4 の通信は全部 ESP で包む**(IKE の UDP 500 を除く)。
 *     SA がまだ無ければ送らずに捨てる。相手から届いた平文(IKE 以外)も捨てる。
 *   - 送信は netif.c の eth_send_frags / _async / eth_send_lso_async の入口で横取りする。
 *     NIC のチェックサムと LSO は ESP の中身に効かないので、L4 のチェックサムを
 *     ソフトウェアで計算し、LSO の大きいセグメントはソフトウェアで分割してから包む。
 *   - 受信は ip.c がプロトコル 50 を渡してくる。復号した中身に IPv4 ヘッダを付け直して
 *     ip_handle_frame() へ入れ直す(このときはチェックサムをソフトウェアで検証させる)。 */

#include <stdint.h>
#include <stddef.h>
#include "netif.h"

#define IP_PROTO_ESP 50u
/* ESP で増える長さの上限: SPI 4 + 順序番号 4 + IV 8 + ICV 16 + Pad Length 1 +
 * Next Header 1 + パディング 3 = 37。TCP の MSS からこれを引く。 */
#define IPSEC_ESP_OVERHEAD 40u
#define IPSEC_MAX_PEERS 4u

/* 方針を持つ相手の数(0 なら全部の判定を素通りする。ホットパスはこれだけを見る)。 */
extern volatile uint32_t g_ipsec_npol;

int  ipsec_policy_add(uint32_t peer_ip);
void ipsec_policy_del(uint32_t peer_ip);
int  ipsec_policy_match(uint32_t ip);

/* SA を入れる(同じ相手の既存の SA は置き換える)。key は 20 バイト(鍵 16 + salt 4)。 */
int  ipsec_sa_install(uint32_t peer_ip, uint32_t spi_in, const uint8_t key_in[20],
                      uint32_t spi_out, const uint8_t key_out[20]);
void ipsec_sa_del(uint32_t peer_ip);
int  ipsec_sa_up(uint32_t peer_ip);
/* 受信用 SPI から相手を引く(ike.c の DELETE 処理用)。0 = 無い。 */
uint32_t ipsec_sa_peer_by_spi_out(uint32_t spi_out);

/* netif.c から。戻り値 1 = 横取りした(*rc に結果)、0 = 対象外(そのまま送る)。 */
int ipsec_out_frags(const eth_frag_t *frags, unsigned n, int async, int *rc);
int ipsec_out_lso(const void *hdr, uint16_t hdr_len, const void *payload,
                  uint32_t payload_len, uint16_t mss, int *rc);

/* ip.c から。ESP のデータグラム(IPv4 ヘッダから total_len まで)。 */
void ipsec_esp_input(const uint8_t *ip, size_t len, const uint8_t *src_mac);
/* ip.c から。方針を持つ相手から届いた平文を捨てるべきなら 1。 */
int  ipsec_rx_drop_plain(uint32_t src_ip, uint8_t proto, const uint8_t *l4, size_t len);

void ipsec_status(void);
void ipsec_stats_clear(void);

#endif /* IPSEC_H */
