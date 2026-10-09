#ifndef NVME_AUTH_H
#define NVME_AUTH_H

/* NVMe in-band 認証(DH-HMAC-CHAP)の共通部分(PLAN_auth_tls.md 段階 C)。
 *
 *   - ホスト / コントローラの両方が使う計算(鍵の文字列の解釈、鍵の変換、
 *     DH で強めたチャレンジ、R1 / R2)。コントローラ側は nvmet_auth.c。
 *   - **ホスト側(イニシエータ)のやりとり**: Negotiate を作る / Challenge から
 *     Reply を作る / Success1 を確かめて Success2 か Failure2 を作る。
 *     トランスポート(TCP / RDMA)の送受信は呼び出し側がやる。
 *
 * 計算は Linux の drivers/nvme/common/auth.c と host/auth.c / target/auth.c
 * (OptiPlex の ~/rpi-kbuild/src、6.18)から写した。
 */

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

/* include/linux/nvme.h の値 */
#define NVME_AUTH_SECP_DHCHAP      0xE9u   /* NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER */
#define NVME_AUTH_TYPE_COMMON      0x00u
#define NVME_AUTH_TYPE_DHCHAP      0x01u
#define NVME_AUTH_MSG_NEGOTIATE    0x00u
#define NVME_AUTH_MSG_CHALLENGE    0x01u
#define NVME_AUTH_MSG_REPLY        0x02u
#define NVME_AUTH_MSG_SUCCESS1     0x03u
#define NVME_AUTH_MSG_SUCCESS2     0x04u
#define NVME_AUTH_MSG_FAILURE2     0xF0u
#define NVME_AUTH_MSG_FAILURE1     0xF1u
#define NVME_AUTH_ID_DHCHAP        0x01u
#define NVME_AUTH_FAIL_REASON      0x01u
#define NVME_AUTH_FAIL_FAILED      0x01u
#define NVME_AUTH_FAIL_HASH        0x04u
#define NVME_AUTH_FAIL_DHGROUP     0x05u
#define NVME_AUTH_FAIL_PAYLOAD     0x06u
#define NVME_AUTH_FAIL_MESSAGE     0x07u

/* Authentication Send / Receive の cdw10: SECP=0xE9、SPSP0=SPSP1=1 */
#define NVME_AUTH_CDW10            ((NVME_AUTH_SECP_DHCHAP << 24) | (1u << 16) | (1u << 8))
/* Connect の応答(dw0)の「認証が要る」(NVME_CONNECT_AUTHREQ_ATR)。 */
#define NVME_AUTH_CONNECT_ATR      (1u << 17)
/* Authentication Receive に渡す長さ(Linux のホストも 4096。ffdhe8192 の Challenge
 * = 16 + 64 + 1024 バイトが収まる)。 */
#define NVME_AUTH_RECV_LEN         4096u

typedef struct {
    uint8_t  key[64];
    uint32_t len;     /* 0 = 鍵なし */
    uint8_t  hash;    /* DHHC-1:<hh>: の hh。0 なら変換しない */
} nvme_auth_key_t;

/* DHHC-1:<hh>:<base64>: を解く。0=成功、-1=書式、-2=長さ、-3=CRC 不一致。 */
int nvme_auth_parse_secret(const char *sec, nvme_auth_key_t *k);
const char *nvme_auth_parse_error(int r);

/* 鍵の変換(Linux の nvme_auth_transform_key())。戻り値は出力の長さ。 */
uint32_t nvme_auth_transform_key(const nvme_auth_key_t *k, const char *nqn, uint8_t *out);

/* DH で強めたチャレンジ。dhgid=0 なら c をそのまま写す。 */
void nvme_auth_augment(uint8_t hashid, uint8_t dhgid, const uint8_t *skey, size_t skey_len,
                       const uint8_t *c, uint8_t *out);

/* R1 = HMAC(鍵, Ca1 ‖ S1 ‖ T_ID ‖ SC_C ‖ "HostHost" ‖ hostnqn ‖ 0 ‖ subnqn) */
void nvme_auth_host_response(const nvme_auth_key_t *hostkey, uint8_t hashid, const uint8_t *ca1,
                             uint32_t s1, uint16_t tid, uint8_t sc_c, const char *hostnqn,
                             const char *subnqn, uint8_t *out);
/* R2 = HMAC(鍵, Ca2 ‖ S2 ‖ T_ID ‖ 0 ‖ "Controller" ‖ subnqn ‖ 0 ‖ hostnqn) */
void nvme_auth_ctrl_response(const nvme_auth_key_t *ctrlkey, uint8_t hashid, const uint8_t *ca2,
                             uint32_t s2, uint16_t tid, const char *hostnqn, const char *subnqn,
                             uint8_t *out);

const char *nvme_auth_dh_name(uint8_t dhgid);

/* ------------------------------------------------------------------ */
/* ホスト側(イニシエータ)                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    nvme_auth_key_t host;     /* ホストの鍵(必須)*/
    nvme_auth_key_t ctrl;     /* コントローラの鍵。len != 0 なら双方向を求める */
    const char *hostnqn;
    const char *subnqn;
    uint16_t tid;
    uint8_t  hashid, dhgid, bidir;
    uint32_t s2;
    uint8_t  c2[64];
    uint8_t  skey[CRYPTO_FFDHE_MAX_LEN];
    uint32_t skey_len;
} nvme_auth_host_t;

/* AUTH_Negotiate を作る(ハッシュ 3 種、DH 群は NULL と ffdhe 全部を候補に挙げる。
 * Linux のホストと同じ)。戻り値は長さ。 */
uint32_t nvme_auth_host_negotiate(nvme_auth_host_t *h, uint8_t *out);
/* Challenge を読んで Reply を作る。戻り値は Reply の長さ、0 = Challenge が不正
 * (相手が Failure1 を返してきた場合も 0。*why に理由)。 */
uint32_t nvme_auth_host_reply(nvme_auth_host_t *h, const uint8_t *in, uint32_t inlen,
                              uint8_t *out, uint32_t cap, const char **why);
/* Success1(または Failure1)を読む。1 = 認証が済んだ(双方向なら out に
 * Success2 を作り *outlen に長さ)、0 = 失敗(双方向でコントローラの応答が
 * 合わなければ out に Failure2)。 */
int nvme_auth_host_result(nvme_auth_host_t *h, const uint8_t *in, uint32_t inlen,
                          uint8_t *out, uint32_t *outlen, const char **why);
void nvme_auth_host_wipe(nvme_auth_host_t *h);

/* イニシエータの鍵の設定(シェルの `nvmeauth`)。TCP / RDMA の両方の接続ジョブが読む。 */
const nvme_auth_key_t *nvme_auth_host_key(void);
const nvme_auth_key_t *nvme_auth_ctrl_key(void);
void nvme_auth_host_shell(const char *args);

#endif /* NVME_AUTH_H */
