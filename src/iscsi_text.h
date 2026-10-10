#ifndef ISCSI_TEXT_H
#define ISCSI_TEXT_H

/* iSCSI のテキスト鍵(key=value\0 の並び)の解釈と交渉(RFC 7143 6 章・13 章)。
 * ターゲットの側の規則をここに集める(イニシエータの側は段階 D で足す)。 */

#include <stdint.h>
#include "iscsi.h"

#define ISCSI_NAME_MAX 224u   /* iSCSI 名の上限(RFC 7143 4.2.7.1 は 223 バイト)*/

/* ターゲットとして提示する値。 */
typedef struct {
    uint32_t max_recv_dsl;        /* 自分の MaxRecvDataSegmentLength */
    uint32_t first_burst;
    uint32_t max_burst;
    uint32_t max_outstanding_r2t;
    uint8_t  initial_r2t;         /* 1 = Yes を求める(OR なので 1 なら必ず Yes になる)*/
    uint8_t  immediate_data;      /* 1 = 受け付ける(AND)*/
    uint8_t  allow_crc32c;        /* ダイジェストを受け付けるか */
    uint16_t tpgt;                /* TargetPortalGroupTag */
    const char *target_alias;     /* NULL なら宣言しない */
    uint8_t  chap_required;       /* 通常セッションで CHAP を求める(AuthMethod=None を受けない)*/
    uint8_t  iser;                /* iSER の接続(RDMAExtensions=Yes を受ける。ダイジェストは使わない)*/
    uint32_t target_recv_dsl;     /* iSER: こちらが受け取れる長さ(TargetRecvDataSegmentLength)*/
} iscsi_tgt_pref_t;

#define ISCSI_NEG_CHAP_STR 2100u   /* CHAP_C / CHAP_R の文字列("0x" + 1024 バイトの 16 進)*/

typedef struct {
    iscsi_params_t p;             /* 交渉の結果(Full Feature Phase で使う)*/
    char initiator_name[ISCSI_NAME_MAX];
    char initiator_alias[64];
    char target_name[ISCSI_NAME_MAX];
    uint8_t got_initiator_name;
    uint8_t got_target_name;
    uint8_t got_session_type;
    uint8_t auth_chosen;          /* AuthMethod に答えた */
    uint8_t auth_none;            /* AuthMethod=None に決まった */
    uint8_t auth_chap;            /* AuthMethod=CHAP に決まった */
    /* CHAP の鍵(応答はしない。ログインの処理が手順を進める)。got_* は 1 回の要求ごとに消す。 */
    uint8_t got_chap_a, got_chap_i, got_chap_c, got_chap_n, got_chap_r;
    char    chap_a[64];
    char    chap_i[8];
    char    chap_n[256];
    char    chap_c[ISCSI_NEG_CHAP_STR];
    char    chap_r[ISCSI_NEG_CHAP_STR];
    uint8_t declared_mrdsl;       /* 自分の MaxRecvDataSegmentLength を宣言済み */
    uint8_t declared_tpgt;
    uint8_t bad_session_type;     /* SessionType が Normal / Discovery 以外 */
} iscsi_neg_t;

/* ログインの最初に 1 回。値は RFC 7143 の既定値で埋める。 */
void iscsi_neg_init(iscsi_neg_t *n);

/* Login / Text 要求 1 回分の鍵を処理し、応答の鍵を rsp へ書く。
 * stage は要求の CSG。戻り値は rsp に書いた長さ、-1 = 形式の誤り(呼び出し側が
 * ログインを 0x0207 / 0x020b で断る)。 */
int iscsi_neg_target(iscsi_neg_t *n, const iscsi_tgt_pref_t *pref, uint8_t stage,
                     const uint8_t *req, uint32_t len, uint8_t *rsp, uint32_t cap);

/* key=value\0 を 1 つ足す(収まらなければ -1)。 */
int iscsi_kv_put(uint8_t *buf, uint32_t cap, uint32_t *pos, const char *key, const char *val);
int iscsi_kv_put_u32(uint8_t *buf, uint32_t cap, uint32_t *pos, const char *key, uint32_t v);

/* 並びから次の 1 組を取り出す。戻り値 1 = 取れた / 0 = 終わり。key / val は
 * NUL 終端されない(長さで返す)。 */
int iscsi_kv_next(const uint8_t *buf, uint32_t len, uint32_t *pos,
                  const char **key, uint32_t *klen, const char **val, uint32_t *vlen);

#endif /* ISCSI_TEXT_H */
