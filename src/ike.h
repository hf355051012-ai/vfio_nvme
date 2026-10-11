#ifndef IKE_H
#define IKE_H

/* IKEv2(RFC 7296)。ESP(ipsec.c)の鍵を作る。iSCSI の IPsec(RFC 7143 8 章)用。
 *
 *   - 交わす組は 1 つに絞る: IKE SA は AES-GCM-16 / 128(RFC 5282)+ PRF HMAC-SHA2-256 +
 *     CURVE_25519(DH 群 31)、子 SA は ESP の AES-GCM-16 / 128、ESN 無し、トランスポートモード。
 *     strongSwan の proposals = aes128gcm16-prfsha256-x25519 / esp_proposals = aes128gcm16。
 *   - 認証は事前共有鍵(AUTH 方式 2)。身元は互いの IPv4 アドレス(ID_IPV4_ADDR)。
 *   - 交換は IKE_SA_INIT と IKE_AUTH(子 SA を 1 つ作る)、INFORMATIONAL(DELETE と生存確認)。
 *     始める側(`ipsec up`)と受ける側(相手から来たら答える)の両方。
 *     作り直し(CREATE_CHILD_SA)は受けない(NO_ADDITIONAL_SAS で断る)。 */

#include <stdint.h>
#include "netif.h"

#define IKE_PORT 500u

int  ike_init(void);
/* 相手と事前共有鍵を登録する(IPsec の方針も入る)。nif は相手へ出るインターフェース。 */
int  ike_peer_add(uint32_t peer_ip, const char *psk, netif_t *nif, const uint8_t peer_mac[6]);
void ike_peer_del(uint32_t peer_ip);
/* こちらから IKE SA と子 SA を作る(同期。終わるまで待つ)。0 = 成功。 */
int  ike_up(uint32_t peer_ip);
/* DELETE を送って SA を消す。 */
void ike_down(uint32_t peer_ip);
void ike_status(void);

#endif /* IKE_H */
