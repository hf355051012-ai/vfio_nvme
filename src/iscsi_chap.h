#ifndef ISCSI_CHAP_H
#define ISCSI_CHAP_H

/* iSCSI の CHAP(RFC 7143 12.1.3 / RFC 1994)。ターゲットとイニシエータで共用する。
 *   応答 = H(CHAP_I の 1 バイト || 秘密 || CHAP_C)
 *   CHAP_A: 5 = MD5 / 6 = SHA-1 / 7 = SHA-256 / 8 = SHA3-256(Linux の LIO と open-iscsi が持つ 4 種)
 *   値は 16 進("0x...")か base64("0b...")。こちらから送るときは 16 進。 */

#include <stdint.h>
#include "crypto.h"

#define ISCSI_CHAP_NAME_MAX   256u
#define ISCSI_CHAP_SECRET_MAX 256u
#define ISCSI_CHAP_BIN_MAX    1024u    /* CHAP_C / CHAP_R の上限(RFC 7143 12.1.3)*/
#define ISCSI_CHAP_STR_MAX    (2u * ISCSI_CHAP_BIN_MAX + 4u)

typedef struct {
    int      set;                       /* CHAP を求める(ターゲット)/ 使う(イニシエータ)*/
    char     user[ISCSI_CHAP_NAME_MAX];
    uint8_t  secret[ISCSI_CHAP_SECRET_MAX];
    uint32_t slen;
    int      mutual;                    /* 双方向: 相手にも答えさせる */
    char     muser[ISCSI_CHAP_NAME_MAX];
    uint8_t  msecret[ISCSI_CHAP_SECRET_MAX];
    uint32_t mlen;
} iscsi_chap_cfg_t;

/* CHAP_A の番号 -> ハッシュ(-1 = 扱わない)。 */
int  iscsi_chap_hash(int alg);
/* 相手の並び("8,7,6,5")から、最初に扱えるものを選ぶ(-1 = 無い)。 */
int  iscsi_chap_pick(const char *list, uint32_t len);
/* 応答を計算する。戻り値は長さ(0 = 失敗)。 */
uint32_t iscsi_chap_response(int alg, uint8_t id, const uint8_t *secret, uint32_t slen,
                             const uint8_t *chal, uint32_t clen, uint8_t *out);
/* "0x..." / "0b..." を読む。戻り値は長さ、-1 = 形式の誤り。 */
int  iscsi_chap_decode(const char *v, uint32_t vl, uint8_t *out, uint32_t cap);
/* "0x..." にする(out は 2n + 3 バイト以上)。 */
void iscsi_chap_hex(const uint8_t *b, uint32_t n, char *out);
/* 10 進(CHAP_I / CHAP_A)。-1 = 数でない。 */
int  iscsi_chap_num(const char *v, uint32_t vl);

/* 秘密の下限の目安(RFC 7143 12.1.3: 96 ビット以上にすべき = SHOULD)。 */
#define ISCSI_CHAP_SECRET_MIN 12u

/* 設定を確かめる(RFC 7143 12.1.3)。戻り値 0 = よい / -1 = 断る(*why)。
 *   - 双方向で、相手を確かめる秘密と自分が答える秘密が同じ -> 断る(MUST NOT。同じ秘密を両方向に
 *     使えると、相手の挑戦をそのまま投げ返す反射で認証を通せる)。
 *   - 秘密が 96 ビット(12 バイト)未満 -> 断らずに *warn に理由(SHOULD)。
 * cfg が NULL / set=0(解除)は常によい。warn は NULL でよい。 */
int  iscsi_chap_cfg_check(const iscsi_chap_cfg_t *cfg, const char **why, const char **warn);

/* 受けた CHAP_R(got / gl)が、自分が同じ挑戦(id / chal)に own_secret で答えたときの値と等しいか。
 * 等しければ 1(**認証失敗として扱う**。RFC 7143 12.1.3: 同じ秘密が両方向に使われていることを
 * 受け手が見つけるための規則)。own_secret が無ければ(slen = 0)0。 */
int  iscsi_chap_is_own_response(int alg, uint8_t id, const uint8_t *own_secret, uint32_t slen,
                                const uint8_t *chal, uint32_t clen, const uint8_t *got, uint32_t gl);

#endif /* ISCSI_CHAP_H */
