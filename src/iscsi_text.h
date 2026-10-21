#ifndef ISCSI_TEXT_H
#define ISCSI_TEXT_H

/* iSCSI のテキスト鍵(key=value\0 の並び)の解釈と交渉(RFC 7143 6 章・13 章)。
 * ターゲットの側の規則(iscsi_neg_target)と、イニシエータの側で相手の応答を確かめる規則
 * (iscsi_ini_neg_rsp)、ログイン要求の BHS の検査(iscsi_login_check)をここに集める。 */

#include <stdint.h>
#include "iscsi.h"

#define ISCSI_NAME_MAX 224u   /* iSCSI 名の上限(RFC 7143 4.2.7.1 は 223 バイト)*/
#define ISCSI_VALUE_MAX 255u  /* 1 つの値の上限(RFC 7143 6.1。鍵ごとに別の決まりがあるものを除く)*/

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

/* 対応する iSCSIProtocolLevel(RFC 7143 13.24)。RFC 7143 / 7144 に合わせた実装として 1 を名乗る。 */
#define ISCSI_PROTO_LEVEL 1u

/*=================================================================
 * ログインの間に一度出た鍵の記録(RFC 7143 6.2: 同じ鍵を 2 回宣言・交渉してはならず、
 * 受け手は見つけなければならない)。知っている鍵はビット、知らない鍵は名前の要約で覚える。
 * ===============================================================*/
#define ISCSI_KEYSEEN_UNK 16u
typedef struct {
    uint64_t known;                       /* iscsi_key_index() の番号のビット */
    uint32_t unk[ISCSI_KEYSEEN_UNK];      /* 知らない鍵の名前の FNV-1a */
    uint8_t  n_unk;
} iscsi_keyseen_t;

/* 鍵を 1 つ記録する。戻り値 1 = 既に出ていた(2 回目)/ 0 = 初めて。 */
int iscsi_keyseen_add(iscsi_keyseen_t *s, const char *k, uint32_t kl);
/* 知っている鍵の番号(-1 = 知らない)。 */
int iscsi_key_index(const char *k, uint32_t kl);

typedef struct {
    iscsi_params_t p;             /* 交渉の結果(Full Feature Phase で使う)*/
    char initiator_name[ISCSI_NAME_MAX];
    char initiator_alias[ISCSI_VALUE_MAX + 1u];
    char target_name[ISCSI_NAME_MAX];
    uint8_t got_initiator_name;
    uint8_t got_target_name;
    uint8_t got_session_type;
    uint8_t got_initiator_alias;
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
    uint8_t rdma_offered;         /* iSER: こちらから RDMAExtensions=Yes を申し出た(RFC 7145 6.3)*/
    uint8_t rdma_answered;        /* iSER: 申し出に相手が答えた */
    iscsi_keyseen_t seen;         /* ログイン全体で出た鍵(重複の検出)*/
    /* 断る理由(iscsi_neg_target が -1 を返したとき)。fail_status はログイン応答の状態。 */
    const char *err;
    uint16_t fail_status;
} iscsi_neg_t;

/* ログインの最初に 1 回。値は RFC 7143 の既定値で埋める。 */
void iscsi_neg_init(iscsi_neg_t *n);

/* Login 要求 1 回分の鍵を処理し、応答の鍵を rsp へ書く。
 * stage は要求の CSG。戻り値は rsp に書いた長さ、-1 = 断る(理由は n->err、ログイン応答の
 * 状態は n->fail_status。形式の誤り・重複・範囲外・段に合わない鍵は 0x0200)。 */
int iscsi_neg_target(iscsi_neg_t *n, const iscsi_tgt_pref_t *pref, uint8_t stage,
                     const uint8_t *req, uint32_t len, uint8_t *rsp, uint32_t cap);

/*=================================================================
 * イニシエータの側(RFC 7143 6.2 / 13 章)。こちらが出した鍵(offers)への相手の答えが
 * 結果の決め方(Result function)で許されるものかを確かめ、相手が申し出た鍵には答えを作る。
 * ===============================================================*/
typedef struct {
    iscsi_params_t p;             /* 決まった値(呼び出し側が既定値で埋めてから渡す)*/
    iscsi_keyseen_t seen;         /* 相手の鍵(重複の検出、ログイン全体)*/
    uint8_t discovery;
    uint8_t iser;
    const char *err;
} iscsi_ini_neg_t;

void iscsi_ini_neg_init(iscsi_ini_neg_t *n, int discovery, int iser);
/* 応答 1 つ(rsp)を確かめる。offers はこの段でこちらが出した鍵の並び(ログイン全体の申し出を
 * 渡してよい)。相手の申し出への答えを ans に書く(*alen)。戻り値 0 = よい / -1 = 規格違反
 * (n->err。RFC 7143 6.2 によりイニシエータは接続を切る)。 */
int iscsi_ini_neg_rsp(iscsi_ini_neg_t *n, const uint8_t *offers, uint32_t olen,
                      const uint8_t *rsp, uint32_t rlen, uint8_t *ans, uint32_t cap, uint32_t *alen);

/*=================================================================
 * ログイン要求の BHS の検査(RFC 7143 6.3 / 11.12)。ターゲット(TCP / iSER)で共用する。
 * ===============================================================*/
typedef struct {
    uint8_t  started;
    uint8_t  stage;               /* 今の段(最初の要求の CSG、移行に同意したら NSG)*/
    uint8_t  isid[6];
    uint16_t tsih;
    uint16_t cid;
    uint32_t itt;
} iscsi_login_state_t;

/* 戻り値 0 = よい / それ以外 = 断るときのログイン応答の状態(*why に理由)。
 * 最初の要求で ISID / TSIH / CID / ITT / 段を控え、以後それらが変わる・C と T が両方立つ・
 * CSG が今の段と違う(後戻りを含む)・CSG / NSG が予約値、を断る。 */
uint16_t iscsi_login_check(iscsi_login_state_t *st, const uint8_t bhs[ISCSI_BHS_LEN], const char **why);
/* 移行に同意した(応答で T=1 を返した)ときに呼ぶ。 */
static inline void iscsi_login_transit(iscsi_login_state_t *st, uint8_t nsg) { st->stage = nsg; }

/* key=value\0 を 1 つ足す(収まらなければ -1)。 */
int iscsi_kv_put(uint8_t *buf, uint32_t cap, uint32_t *pos, const char *key, const char *val);
int iscsi_kv_put_u32(uint8_t *buf, uint32_t cap, uint32_t *pos, const char *key, uint32_t v);

/* 並びから次の 1 組を取り出す。戻り値 1 = 取れた / 0 = 終わり。key / val は
 * NUL 終端されない(長さで返す)。 */
int iscsi_kv_next(const uint8_t *buf, uint32_t len, uint32_t *pos,
                  const char **key, uint32_t *klen, const char **val, uint32_t *vlen);

#endif /* ISCSI_TEXT_H */
