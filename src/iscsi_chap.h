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

#endif /* ISCSI_CHAP_H */
