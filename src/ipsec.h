#ifndef IPSEC_H
#define IPSEC_H

/* IPsec の ESP(RFC 4303、トランスポートモード、IPv4)。iSCSI(RFC 7143 8 章)が求める
 * データの保護。鍵は IKEv2(ike.c)が作って ipsec_sa_install() で入れる。
 *
 *   - 暗号は AES-GCM-16 / 128 ビット(RFC 4106)。鍵 16 バイト + salt 4 バイト。
 *     nonce = salt || IV(8)、AAD = SPI || 順序番号(ESN は使わない)、ICV 16 バイト。
 *   - **方針(policy)を持つ相手との IPv4 の通信は全部 ESP で包む**。素通しは自分の IKE だけ
 *     (送信は送信元ポート 500、受信は宛先ポート 500。NAT-T の 4500 は素通しにしない。RFC 4301 5.1 / 5.2)。
 *     SA がまだ無ければ送らずに捨てる。相手から届いた平文(IKE 以外)も捨てる。
 *   - ESN を使わないので、送信の順序番号が 2^32 - 1 に達したら以後は送らずに捨てる(RFC 4303 3.3.3。
 *     SA は作り直さないので `ipsec down` / `up` で張り直す)。
 *   - 受信: 再送攻撃の窓(64)は復号の後にロックの中で確かめ直して進める。パディングの中身
 *     (1, 2, 3, ...)を確かめる(RFC 4303 2.4)。受信の SPI は相手どうしで重ねない。
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

/* SA を入れる(同じ相手の既存の SA は置き換える)。key は aes_klen + 4 バイト
 * (AES の鍵 16 / 32 + salt 4。RFC 4106 の KEYMAT の並び)。aes_klen が 16 / 32 以外なら -1。 */
int  ipsec_sa_install(uint32_t peer_ip, uint32_t spi_in, const uint8_t *key_in,
                      uint32_t spi_out, const uint8_t *key_out, size_t aes_klen);
void ipsec_sa_del(uint32_t peer_ip);
/* 受信の SPI が spi_in の SA のときだけ消す(置き換えた後の古い IKE SA の後始末用)。 */
void ipsec_sa_del_if(uint32_t peer_ip, uint32_t spi_in);
int  ipsec_sa_up(uint32_t peer_ip);
/* 受信用 SPI から相手を引く(ike.c の DELETE 処理用)。0 = 無い。 */
uint32_t ipsec_sa_peer_by_spi_out(uint32_t spi_out);
/* 受信の SPI spi が except_ip 以外の相手で使われていれば 1(ike.c が SPI を選ぶときに使う)。
 * ipsec_sa_install() も重なる SPI と 256 未満の SPI を断る(-1)。 */
int  ipsec_spi_in_used(uint32_t spi, uint32_t except_ip);

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

/* ---- 試験用(rfctest sec)。ふだんの経路からは呼ばない ---- */
typedef struct {
    uint32_t rx_pkts, rx_replay, rx_auth_fail, rx_pad_bad, rx_plain_drop, tx_seq_exhausted;
    uint32_t spi_in, spi_out;
} ipsec_test_stats_t;
int  ipsec_test_stats(uint32_t peer_ip, ipsec_test_stats_t *o);
/* 次に送る順序番号を seq + 1 にする(使い切りの試験)。 */
void ipsec_test_set_seq_out(uint32_t peer_ip, uint64_t seq);
/* 1 フレーム(Ethernet + IPv4 + L4)を ESP で包んで送る。順序番号を使い切っていれば送らずに 0。 */
int  ipsec_test_send(uint32_t peer_ip, const uint8_t *frame, uint32_t flen);
/* 送るフレームが ESP で包まれずに素通しになるなら 1(IKE の素通しの範囲の試験)。 */
int  ipsec_test_tx_bypass(const uint8_t *frame, uint32_t flen);

#endif /* IPSEC_H */
