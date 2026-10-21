#ifndef IKE_H
#define IKE_H

/* IKEv2(RFC 7296)。ESP(ipsec.c)の鍵を作る。iSCSI の IPsec(RFC 7143 8 章)用。
 *
 *   - 交わす組は相手ごとに 1 つに絞る:
 *       既定: IKE SA は AES-GCM-16 / 128(RFC 5282)+ PRF HMAC-SHA2-256 + CURVE_25519(DH 群 31)、
 *             子 SA は ESP の AES-GCM-16 / 128。strongSwan の proposals = aes128gcm16-prfsha256-x25519 /
 *             esp_proposals = aes128gcm16。
 *       CNSA 2.0(`ipsec psk ... cnsa`、PLAN_cnsa2.md 段階 3): IKE SA は AES-GCM-16 / 256 + PRF HMAC-SHA2-384 +
 *             ML-KEM-1024(変換 ID 37、draft-ietf-ipsecme-ikev2-mlkem。IKE_SA_INIT の KE に直接載せる)、
 *             子 SA は ESP の AES-GCM-16 / 256。strongSwan の proposals = aes256gcm16-prfsha384-mlkem1024 /
 *             esp_proposals = aes256gcm16。
 *     どちらも ESN 無し、トランスポートモード。
 *   - 認証は事前共有鍵(AUTH 方式 2)。身元は互いの IPv4 アドレス(ID_IPV4_ADDR)。
 *   - 交換は IKE_SA_INIT と IKE_AUTH(子 SA を 1 つ作る)、INFORMATIONAL(DELETE と生存確認)。
 *     始める側(`ipsec up`)と受ける側(相手から来たら答える)の両方。
 *     作り直し(CREATE_CHILD_SA)は受けない(NO_ADDITIONAL_SAS で断る)。
 *   - **新しい交換は「交渉中」の枠で進め、IKE_AUTH で相手を認証できてから確立した SA と
 *     置き換える**(RFC 7296 2.21.1。認証されていない IKE_SA_INIT で動いている SA を壊さない)。
 *   - 再送は 1・2・4 秒の間隔で指数に延ばし、最後に 8 秒待って諦める(2.4)。COOKIE を求められたら
 *     付けて送り直す(2.6)。IKE_SA_INIT への誤りの通知は認証されていないので、時間切れまで
 *     本物の応答を待つ(2.21.1)。
 *   - 知らない重要なペイロードは UNSUPPORTED_CRITICAL_PAYLOAD、壊れた要求は INVALID_SYNTAX で
 *     中身を処理する前に断る(2.5 / 2.21.2)。子 SA の TS はホスト間・全プロトコル・全ポートだけ(2.9)。
 *   - 生存確認・寿命・作り直し・NAT-T は無い(SA は 1 つで作り直さない)。 */

#include <stdint.h>
#include "netif.h"

#define IKE_PORT 500u

int  ike_init(void);
/* 相手と事前共有鍵を登録する(IPsec の方針も入る)。nif は相手へ出るインターフェース。
 * cnsa が 0 でなければ CNSA 2.0 の組だけを使う / 受ける。 */
int  ike_peer_add(uint32_t peer_ip, const char *psk, netif_t *nif, const uint8_t peer_mac[6], int cnsa);
void ike_peer_del(uint32_t peer_ip);
/* こちらから IKE SA と子 SA を作る(同期。終わるまで待つ)。0 = 成功。 */
int  ike_up(uint32_t peer_ip);
/* DELETE を送って SA を消す。 */
void ike_down(uint32_t peer_ip);
void ike_status(void);

/* ---- 試験用(rfctest sec)。ふだんの経路からは呼ばない ----
 * ike_test_loop(1, rto): 送るメッセージをワイヤに出さず待ち行列へ積む(再送の最初の間隔は rto ミリ秒)。
 *   同じプロセスに 2 つの相手(A と B)を登録し、ike_test_set_self() で「A から見たこちら = B」
 *   「B から見たこちら = A」にすると、待ち行列を ike_test_pump() で配って自分どうしで交渉できる
 *   (送り手のアドレスを送信元として ike_rx() へ渡す)。ike_up() などの待ちの中でも配る。
 * フィルタは配る前に呼ばれ、0 以外を返すとそのメッセージは配らない(捨てる / 試験が差し替える)。
 * ike_test_loop(0, 0) で元に戻す(フィルタと TS の差し替えも外れる)。 */
typedef int (*ike_test_filter_fn)(uint32_t src, uint32_t dst, uint8_t *msg, uint32_t *len);
typedef struct {
    uint8_t  state, half_state, initiator, child_up;
    uint16_t last_notify, half_last_notify;
    uint32_t esp_spi_in, esp_spi_out;
    uint8_t  spi_i[8], spi_r[8];
    uint32_t n_up, n_bad, n_retx, n_crit, n_err;
} ike_test_info_t;
enum { IKE_TEST_ST_NONE = 0, IKE_TEST_ST_ESTABLISHED = 3, IKE_TEST_ST_R_INIT = 4 };
void ike_test_loop(int on, unsigned rto_ms);
void ike_test_set_filter(ike_test_filter_fn f);
/* 始める側の TSi / TSr のプロトコル(0 = 全部。TS_UNACCEPTABLE の試験用)。 */
void ike_test_ts_proto(uint8_t proto);
int  ike_test_pop(uint32_t *src, uint32_t *dst, uint8_t *buf, uint32_t cap);
void ike_test_pump(void);
void ike_test_rx(uint32_t src, uint32_t dst, const uint8_t *msg, uint32_t len);
int  ike_test_set_self(uint32_t peer_ip, uint32_t self_ip);
int  ike_test_info(uint32_t peer_ip, ike_test_info_t *o);
/* 確立した IKE SA の上で、中身 inner(最初の種類 first)の INFORMATIONAL の要求を送って応答を待つ。 */
int  ike_test_send_info(uint32_t peer_ip, uint8_t first, const uint8_t *inner, uint32_t ilen);

#endif /* IKE_H */
