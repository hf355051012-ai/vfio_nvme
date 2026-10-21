/* iSCSI のテキスト鍵の解釈と交渉(RFC 7143 6.2 / 13 章)。
 *
 * 鍵の種類ごとに結果の決め方が違う(13 章の各鍵の "Result function"):
 *   - 最小値 : MaxBurstLength / FirstBurstLength / MaxOutstandingR2T / MaxConnections /
 *              ErrorRecoveryLevel / DefaultTime2Retain / iSCSIProtocolLevel
 *   - 最大値 : DefaultTime2Wait
 *   - OR     : InitialR2T / DataPDUInOrder / DataSequenceInOrder / TaggedBufferForSolicitedDataOnly
 *   - AND    : ImmediateData / IFMarker / OFMarker / RDMAExtensions
 *   - 列挙   : HeaderDigest / DataDigest / AuthMethod / TaskReporting(相手の並びの最初の、こちらが使えるもの)
 *   - 宣言型 : InitiatorName / InitiatorAlias / TargetName / SessionType / X#NodeArchitecture /
 *              MaxRecvDataSegmentLength(**向きごとに別**。相手の値は相手の受け取れる長さ)
 * 知らない鍵には NotUnderstood、Discovery セッションでセッション全体の鍵には Irrelevant。
 * **RFC 7143 自身が定めた鍵には NotUnderstood を返さない**(6.2。返すと相手は「その版を知らない
 * 実装」とみなす)。廃止された IFMarkInt / OFMarkInt は Reject(13.25)。
 * 段階 0 で取った open-iscsi <-> LIO の記録(tools/iscsi_ref/)と同じ応答になることを見る。 */
#include "iscsi_text.h"
#include <string.h>

/* ---------------------------------------------------------------- 鍵の表 */

enum {
    K_SESSION_TYPE = 0, K_INITIATOR_NAME, K_TARGET_NAME, K_INITIATOR_ALIAS,   /* 名前の宣言(0〜3)*/
    K_TARGET_ALIAS, K_TARGET_ADDRESS, K_TPGT, K_SEND_TARGETS,
    K_HEADER_DIGEST, K_DATA_DIGEST, K_AUTH_METHOD,
    K_CHAP_A, K_CHAP_I, K_CHAP_C, K_CHAP_N, K_CHAP_R,
    K_MRDSL, K_MAX_BURST, K_FIRST_BURST, K_MAX_OUT_R2T, K_MAX_CONN, K_ERL, K_T2RETAIN, K_T2WAIT,
    K_INITIAL_R2T, K_DATA_PDU_IN_ORDER, K_DATA_SEQ_IN_ORDER, K_IMMEDIATE_DATA, K_IFMARKER, K_OFMARKER,
    K_IFMARKINT, K_OFMARKINT, K_TASK_REPORTING, K_PROTO_LEVEL, K_NODE_ARCH,
    K_RDMA_EXT, K_INI_RDSL, K_TGT_RDSL, K_TBSDO,
    K_COUNT
};

typedef struct {
    const char *name;
    uint32_t    lo, hi;        /* 数の鍵の範囲(RFC 7143 13 章 / RFC 7145 6 章)*/
    uint8_t     session;       /* セッション全体の鍵(Discovery では Irrelevant)*/
} keydef_t;

static const keydef_t KEYS[K_COUNT] = {
    [K_SESSION_TYPE]      = { "SessionType", 0, 0, 0 },
    [K_INITIATOR_NAME]    = { "InitiatorName", 0, 0, 0 },
    [K_TARGET_NAME]       = { "TargetName", 0, 0, 0 },
    [K_INITIATOR_ALIAS]   = { "InitiatorAlias", 0, 0, 0 },
    [K_TARGET_ALIAS]      = { "TargetAlias", 0, 0, 0 },
    [K_TARGET_ADDRESS]    = { "TargetAddress", 0, 0, 0 },
    [K_TPGT]              = { "TargetPortalGroupTag", 0, 65535, 0 },
    [K_SEND_TARGETS]      = { "SendTargets", 0, 0, 0 },
    [K_HEADER_DIGEST]     = { "HeaderDigest", 0, 0, 0 },
    [K_DATA_DIGEST]       = { "DataDigest", 0, 0, 0 },
    [K_AUTH_METHOD]       = { "AuthMethod", 0, 0, 0 },
    [K_CHAP_A]            = { "CHAP_A", 0, 0, 0 },
    [K_CHAP_I]            = { "CHAP_I", 0, 0, 0 },
    [K_CHAP_C]            = { "CHAP_C", 0, 0, 0 },
    [K_CHAP_N]            = { "CHAP_N", 0, 0, 0 },
    [K_CHAP_R]            = { "CHAP_R", 0, 0, 0 },
    [K_MRDSL]             = { "MaxRecvDataSegmentLength", 512, 16777215, 0 },
    [K_MAX_BURST]         = { "MaxBurstLength", 512, 16777215, 1 },
    [K_FIRST_BURST]       = { "FirstBurstLength", 512, 16777215, 1 },
    [K_MAX_OUT_R2T]       = { "MaxOutstandingR2T", 1, 65535, 1 },
    [K_MAX_CONN]          = { "MaxConnections", 1, 65535, 1 },
    [K_ERL]               = { "ErrorRecoveryLevel", 0, 2, 0 },
    [K_T2RETAIN]          = { "DefaultTime2Retain", 0, 3600, 0 },
    [K_T2WAIT]            = { "DefaultTime2Wait", 0, 3600, 0 },
    [K_INITIAL_R2T]       = { "InitialR2T", 0, 0, 1 },
    [K_DATA_PDU_IN_ORDER] = { "DataPDUInOrder", 0, 0, 1 },
    [K_DATA_SEQ_IN_ORDER] = { "DataSequenceInOrder", 0, 0, 1 },
    [K_IMMEDIATE_DATA]    = { "ImmediateData", 0, 0, 1 },
    [K_IFMARKER]          = { "IFMarker", 0, 0, 0 },
    [K_OFMARKER]          = { "OFMarker", 0, 0, 0 },
    [K_IFMARKINT]         = { "IFMarkInt", 0, 0, 0 },
    [K_OFMARKINT]         = { "OFMarkInt", 0, 0, 0 },
    [K_TASK_REPORTING]    = { "TaskReporting", 0, 0, 1 },
    [K_PROTO_LEVEL]       = { "iSCSIProtocolLevel", 0, 31, 1 },
    [K_NODE_ARCH]         = { "X#NodeArchitecture", 0, 0, 0 },
    [K_RDMA_EXT]          = { "RDMAExtensions", 0, 0, 0 },
    [K_INI_RDSL]          = { "InitiatorRecvDataSegmentLength", 512, 16777215, 0 },
    [K_TGT_RDSL]          = { "TargetRecvDataSegmentLength", 512, 16777215, 0 },
    [K_TBSDO]             = { "TaggedBufferForSolicitedDataOnly", 0, 0, 0 },
};
_Static_assert(K_COUNT <= 64, "iscsi_keyseen_t.known は 64 ビット");

int iscsi_key_index(const char *k, uint32_t kl)
{
    for (int i = 0; i < K_COUNT; i++) {
        const char *n = KEYS[i].name;
        if (strlen(n) == kl && memcmp(n, k, kl) == 0) return i;   /* 鍵は大文字小文字を区別する */
    }
    return -1;
}

int iscsi_keyseen_add(iscsi_keyseen_t *s, const char *k, uint32_t kl)
{
    const int i = iscsi_key_index(k, kl);
    if (i >= 0) {
        const uint64_t bit = 1ull << i;
        if (s->known & bit) return 1;
        s->known |= bit;
        return 0;
    }
    /* 知らない鍵は名前の要約で覚える。要約が偶然重なれば 2 回目と誤認するが、32 ビットの
     * FNV-1a で 16 個までなので実害は無い。あふれたら(17 個目以降)検出をあきらめる。 */
    uint32_t h = 2166136261u;
    for (uint32_t j = 0; j < kl; j++) { h ^= (uint8_t)k[j]; h *= 16777619u; }
    for (unsigned j = 0; j < s->n_unk; j++) if (s->unk[j] == h) return 1;
    if (s->n_unk < ISCSI_KEYSEEN_UNK) s->unk[s->n_unk++] = h;
    return 0;
}

/* ---------------------------------------------------------------- 並びの読み書き */

void iscsi_neg_init(iscsi_neg_t *n)
{
    memset(n, 0, sizeof(*n));
    iscsi_params_t *p = &n->p;
    p->hdgst = 0;
    p->ddgst = 0;
    p->initial_r2t = 1;
    p->immediate_data = 1;
    p->data_pdu_in_order = 1;
    p->data_seq_in_order = 1;
    p->erl = 0;
    p->max_recv_dsl = ISCSI_LOGIN_MAX_DSL;   /* 宣言するまでは既定の 8192 */
    p->max_xmit_dsl = ISCSI_LOGIN_MAX_DSL;
    p->first_burst = 65536u;
    p->max_burst = 262144u;
    p->max_outstanding_r2t = 1u;
    p->max_connections = 1u;
    p->time2wait = 2u;
    p->time2retain = 20u;
    p->ini_recv_dsl = 262144u;   /* RFC 7145 の既定値 */
    p->tgt_recv_dsl = 8192u;
    p->proto_level = 0;          /* 鍵が出なければ 0(RFC 7143 13.24 の既定)*/
}

int iscsi_kv_next(const uint8_t *buf, uint32_t len, uint32_t *pos,
                  const char **key, uint32_t *klen, const char **val, uint32_t *vlen)
{
    while (*pos < len && buf[*pos] == 0) (*pos)++;   /* 余分な NUL(パディング)を飛ばす */
    if (*pos >= len) return 0;
    const uint32_t s = *pos;
    uint32_t e = s;
    while (e < len && buf[e] != 0) e++;
    *pos = e;
    uint32_t eq = s;
    while (eq < e && buf[eq] != '=') eq++;
    *key = (const char *)&buf[s];
    *klen = eq - s;
    if (eq < e) {
        *val = (const char *)&buf[eq + 1];
        *vlen = e - eq - 1;
    } else {
        *val = "";
        *vlen = 0;
    }
    return 1;
}

int iscsi_kv_put(uint8_t *buf, uint32_t cap, uint32_t *pos, const char *key, const char *val)
{
    const uint32_t kl = (uint32_t)strlen(key), vl = (uint32_t)strlen(val);
    if (*pos + kl + 1u + vl + 1u > cap) return -1;
    memcpy(&buf[*pos], key, kl);
    buf[*pos + kl] = '=';
    memcpy(&buf[*pos + kl + 1u], val, vl);
    buf[*pos + kl + 1u + vl] = 0;
    *pos += kl + vl + 2u;
    return 0;
}

int iscsi_kv_put_u32(uint8_t *buf, uint32_t cap, uint32_t *pos, const char *key, uint32_t v)
{
    char s[12];
    int i = 11;
    s[i] = 0;
    do { s[--i] = (char)('0' + v % 10u); v /= 10u; } while (v && i > 0);
    return iscsi_kv_put(buf, cap, pos, key, &s[i]);
}

static int veq(const char *v, uint32_t vl, const char *s)
{
    return vl == strlen(s) && memcmp(v, s, vl) == 0;
}

/* 10 進か 0x の 16 進(RFC 7143 6.1 の numerical value)。-1 = 数でない。 */
static int64_t parse_num(const char *v, uint32_t vl)
{
    if (vl == 0) return -1;
    uint64_t x = 0;
    uint32_t i = 0;
    if (vl > 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
        for (i = 2; i < vl; i++) {
            const char c = v[i];
            const int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                        : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (d < 0 || x > 0xFFFFFFFFull) return -1;
            x = x * 16u + (uint64_t)d;
        }
    } else {
        for (i = 0; i < vl; i++) {
            if (v[i] < '0' || v[i] > '9' || x > 0xFFFFFFFFull) return -1;
            x = x * 10u + (uint64_t)(v[i] - '0');
        }
    }
    return x > 0xFFFFFFFFull ? -1 : (int64_t)x;
}

/* 鍵 idx の数の値を読み、範囲(KEYS[].lo〜hi)の外なら -1。 */
static int64_t parse_num_in(int idx, const char *v, uint32_t vl)
{
    const int64_t x = parse_num(v, vl);
    if (x < 0 || (uint64_t)x < KEYS[idx].lo || (uint64_t)x > KEYS[idx].hi) return -1;
    return x;
}

/* Yes / No。-1 = どちらでもない。 */
static int parse_bool(const char *v, uint32_t vl)
{
    if (veq(v, vl, "Yes")) return 1;
    if (veq(v, vl, "No")) return 0;
    return -1;
}

/* 列挙(カンマ区切り)の中に s があるか。 */
static int list_has(const char *v, uint32_t vl, const char *s)
{
    const uint32_t sl = (uint32_t)strlen(s);
    uint32_t i = 0;
    while (i <= vl) {
        uint32_t j = i;
        while (j < vl && v[j] != ',') j++;
        if (j - i == sl && memcmp(&v[i], s, sl) == 0) return (int)(i + 1u);   /* 1 起点の位置 */
        i = j + 1u;
    }
    return 0;
}

/* 相手の並びの最初の、こちらが使える値(digest: CRC32C / None)。 */
static const char *pick_digest(const char *v, uint32_t vl, int allow_crc)
{
    const int c = allow_crc ? list_has(v, vl, "CRC32C") : 0;
    const int n = list_has(v, vl, "None");
    if (c && (!n || c < n)) return "CRC32C";
    if (n) return "None";
    return NULL;
}

static uint32_t umin(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t umax(uint32_t a, uint32_t b) { return a > b ? a : b; }

/* 断る理由を控えて -1 を返す(ログイン応答は Initiator error = 0x0200)。 */
static int neg_err(iscsi_neg_t *n, const char *why)
{
    n->err = why;
    n->fail_status = ISCSI_LS_INIT_ERR;
    return -1;
}

/* 宣言の値を控える。**黙って切らない**(長すぎれば断る。RFC 7143 6.1 / 4.2.7.1)。
 * 同じ要求の中の 2 回目は重複、前の要求で出たものは**同じ値に限って**受ける(下の説明)。 */
static int take_decl(iscsi_neg_t *n, int idx, uint32_t *req_mask, char *dst, uint32_t cap,
                     uint8_t *got, const char *v, uint32_t vl)
{
    if (*req_mask & (1u << idx)) return neg_err(n, "同じ要求に同じ宣言が 2 回ある");
    *req_mask |= 1u << idx;
    if (vl >= cap) return neg_err(n, "宣言の値が長すぎる");
    if (*got) {
        /* **libiscsi は認証の段の最初と運用の段の最初の両方で InitiatorName / TargetName /
         * SessionType を送る**(lib/login.c の iscsi_login_add_initiatorname() の「opneg or the first
         * leg of secneg」)。LIO はこれを受けるので、同じ値の宣言し直しは受ける。値を変えるのは断る
         * (RFC 7143 6.2 の「宣言し直し」の検出の趣旨はこちら)。 */
        if (strlen(dst) != vl || memcmp(dst, v, vl) != 0) return neg_err(n, "宣言の値がログインの途中で変わった");
        return 0;
    }
    memcpy(dst, v, vl);
    dst[vl] = 0;
    *got = 1;
    return 0;
}

/* ---------------------------------------------------------------- ターゲット */

int iscsi_neg_target(iscsi_neg_t *n, const iscsi_tgt_pref_t *pref, uint8_t stage,
                     const uint8_t *req, uint32_t len, uint8_t *rsp, uint32_t cap)
{
    iscsi_params_t *p = &n->p;
    uint32_t out = 0;
    const char *k, *v;
    uint32_t kl, vl, pos = 0;
    uint32_t req_mask = 0;   /* 名前の宣言(K_SESSION_TYPE〜K_INITIATOR_ALIAS)がこの要求で出たか */
    n->err = NULL;

    /* 1 回目: 宣言型のうち、他の鍵の扱いを左右するもの(SessionType は後ろに来てもよい)。 */
    while (iscsi_kv_next(req, len, &pos, &k, &kl, &v, &vl)) {
        const int idx = iscsi_key_index(k, kl);
        if (idx == K_SESSION_TYPE) {
            /* 規則は take_decl() と同じ(同じ要求の 2 回目は重複、前の要求と同じ値なら受ける)。
             * 値は文字列で控えず p->discovery で比べる。 */
            if (req_mask & (1u << idx)) return neg_err(n, "同じ要求に同じ宣言が 2 回ある");
            req_mask |= 1u << idx;
            const int disc = veq(v, vl, "Discovery") ? 1 : veq(v, vl, "Normal") ? 0 : -1;
            if (n->got_session_type) {
                if (n->bad_session_type || disc < 0 || (uint8_t)disc != p->discovery)
                    return neg_err(n, "SessionType がログインの途中で変わった");
            } else if (disc < 0) {
                n->bad_session_type = 1;
            } else {
                p->discovery = (uint8_t)disc;
            }
            n->got_session_type = 1;
        } else if (idx == K_INITIATOR_NAME) {
            if (take_decl(n, idx, &req_mask, n->initiator_name, sizeof(n->initiator_name),
                          &n->got_initiator_name, v, vl) < 0) return -1;
        } else if (idx == K_TARGET_NAME) {
            if (take_decl(n, idx, &req_mask, n->target_name, sizeof(n->target_name),
                          &n->got_target_name, v, vl) < 0) return -1;
        } else if (idx == K_INITIATOR_ALIAS) {
            if (take_decl(n, idx, &req_mask, n->initiator_alias, sizeof(n->initiator_alias),
                          &n->got_initiator_alias, v, vl) < 0) return -1;
        }
    }

    /* 2 回目: 交渉。 */
    pos = 0;
    while (iscsi_kv_next(req, len, &pos, &k, &kl, &v, &vl)) {
        char key[64];
        if (kl == 0 || kl >= sizeof(key)) return neg_err(n, "鍵の名前が空か 63 バイトを超える");   /* 6.1 */
        memcpy(key, k, kl);
        key[kl] = 0;
        const int idx = iscsi_key_index(k, kl);
        if (idx >= 0 && idx <= K_INITIATOR_ALIAS) continue;   /* 名前の宣言は 1 回目で済ませた(応答しない)*/
        /* **同じ鍵の 2 回目はログインを断る**(RFC 7143 6.2「受け手は見つけなければならない。ターゲットは
         * Login reject(Initiator error)で答える」)。名前の宣言だけは上の take_decl() の規則。 */
        if (iscsi_keyseen_add(&n->seen, k, kl)) return neg_err(n, "同じ鍵がログインの中で 2 回出た");
        /* 値の長さの上限(6.1)。CHAP_C / CHAP_R は 1024 バイトの 2 進を符号化したものなので別の上限。 */
        if (vl > ISCSI_VALUE_MAX && idx != K_CHAP_C && idx != K_CHAP_R) return neg_err(n, "値が 255 バイトを超える");
        /* **認証の鍵は認証の段でだけ**(6.3。運用の段で来たら段に合わない鍵として断る)。 */
        if (stage != ISCSI_STAGE_SEC && idx >= K_AUTH_METHOD && idx <= K_CHAP_R)
            return neg_err(n, "認証の鍵が運用の段で来た");
        int r = 0;

        if (idx < 0) {
            /* 知らない鍵(X- で始まる私的な鍵も含む)。 */
            r = iscsi_kv_put(rsp, cap, &out, key, "NotUnderstood");
        } else if (p->discovery && KEYS[idx].session) {
            r = iscsi_kv_put(rsp, cap, &out, key, "Irrelevant");
        } else switch (idx) {
        case K_NODE_ARCH:
            continue;   /* 宣言(13.26)。情報として受けるだけで応答しない */
        case K_TARGET_ALIAS: case K_TARGET_ADDRESS: case K_TPGT: case K_SEND_TARGETS:
            /* ターゲットが送る鍵 / Full Feature Phase の鍵。ログイン中のイニシエータには意味が無い。 */
            r = iscsi_kv_put(rsp, cap, &out, key, "Irrelevant");
            break;
        case K_RDMA_EXT: {
            /* AND(RFC 7145 6.3)。iSER の接続でだけ Yes にする。こちらが先に申し出ていれば、これは
             * その答え(答えに答え直さない)。 */
            const int b = parse_bool(v, vl);
            if (b < 0) return neg_err(n, "RDMAExtensions の値が不正");
            p->rdma_ext = (uint8_t)(b && pref->iser);
            if (n->rdma_offered) { n->rdma_answered = 1; continue; }
            r = iscsi_kv_put(rsp, cap, &out, key, p->rdma_ext ? "Yes" : "No");
            break;
        }
        case K_INI_RDSL: case K_TGT_RDSL: {
            /* 小さいほう(RFC 7145 6.4 / 6.5。LIO も同じ)。iSER でなければ Irrelevant。 */
            const int64_t x = parse_num_in(idx, v, vl);
            if (x < 0) return neg_err(n, "受信長の値が範囲の外");
            if (!pref->iser) {
                r = iscsi_kv_put(rsp, cap, &out, key, "Irrelevant");
            } else if (idx == K_INI_RDSL) {
                p->ini_recv_dsl = umin((uint32_t)x, 262144u);
                r = iscsi_kv_put_u32(rsp, cap, &out, key, p->ini_recv_dsl);
            } else {
                p->tgt_recv_dsl = umin((uint32_t)x, pref->target_recv_dsl);
                r = iscsi_kv_put_u32(rsp, cap, &out, key, p->tgt_recv_dsl);
            }
            break;
        }
        case K_TBSDO: {
            /* OR(RFC 7145 6.9)。こちらはどちらの意味でも扱えるので、相手の値をそのまま結果にする
             * (こちらの値 No と OR を取ると相手の値になる)。iSER でなければ Irrelevant。 */
            const int b = parse_bool(v, vl);
            if (b < 0) return neg_err(n, "TaggedBufferForSolicitedDataOnly の値が不正");
            if (!pref->iser) { r = iscsi_kv_put(rsp, cap, &out, key, "Irrelevant"); break; }
            p->tbsdo = (uint8_t)b;
            p->tbsdo_set = 1;
            r = iscsi_kv_put(rsp, cap, &out, key, b ? "Yes" : "No");
            break;
        }
        case K_MRDSL: {
            const int64_t x = parse_num_in(idx, v, vl);
            if (x < 0) return neg_err(n, "MaxRecvDataSegmentLength が範囲の外");   /* 512〜2^24-1(13.12)*/
            p->max_xmit_dsl = (uint32_t)x;            /* 相手が受け取れる長さ = こちらが送る上限 */
            continue;
        }
        case K_HEADER_DIGEST: case K_DATA_DIGEST: {
            const char *c = pick_digest(v, vl, pref->allow_crc32c);
            if (!c) {
                r = iscsi_kv_put(rsp, cap, &out, key, "Reject");
            } else {
                if (idx == K_HEADER_DIGEST) p->hdgst = (c[0] == 'C'); else p->ddgst = (c[0] == 'C');
                r = iscsi_kv_put(rsp, cap, &out, key, c);
            }
            break;
        }
        case K_AUTH_METHOD: {
            /* CHAP を求めるなら CHAP だけ、求めないなら None だけ(Discovery は CHAP を求めない)。 */
            n->auth_chosen = 1;
            const int want_chap = pref->chap_required && !p->discovery;
            n->auth_chap = want_chap && list_has(v, vl, "CHAP") ? 1 : 0;
            n->auth_none = !want_chap && list_has(v, vl, "None") ? 1 : 0;
            r = iscsi_kv_put(rsp, cap, &out, key, n->auth_chap ? "CHAP" : n->auth_none ? "None" : "Reject");
            break;
        }
        case K_CHAP_A: case K_CHAP_I: case K_CHAP_C: case K_CHAP_N: case K_CHAP_R: {
            /* 値を控えるだけ(手順はログインの処理が進める)。長すぎれば形式の誤り。 */
            char *dst; uint32_t dcap; uint8_t *got;
            switch (idx) {
            case K_CHAP_A: dst = n->chap_a; dcap = sizeof(n->chap_a); got = &n->got_chap_a; break;
            case K_CHAP_I: dst = n->chap_i; dcap = sizeof(n->chap_i); got = &n->got_chap_i; break;
            case K_CHAP_C: dst = n->chap_c; dcap = sizeof(n->chap_c); got = &n->got_chap_c; break;
            case K_CHAP_N: dst = n->chap_n; dcap = sizeof(n->chap_n); got = &n->got_chap_n; break;
            default:       dst = n->chap_r; dcap = sizeof(n->chap_r); got = &n->got_chap_r; break;
            }
            if (vl >= dcap) return neg_err(n, "CHAP の値が長すぎる");
            memcpy(dst, v, vl);
            dst[vl] = 0;
            *got = 1;
            continue;
        }
        case K_INITIAL_R2T: case K_DATA_PDU_IN_ORDER: case K_DATA_SEQ_IN_ORDER: {
            const int b = parse_bool(v, vl);
            if (b < 0) return neg_err(n, "Yes / No でない");
            /* OR。InitialR2T はこちらの希望、in-order の 2 つは**順序どおりにしか扱えないので常に Yes**。 */
            const int mine = (idx == K_INITIAL_R2T) ? pref->initial_r2t : 1;
            const int res = b || mine;
            if (idx == K_INITIAL_R2T) p->initial_r2t = (uint8_t)res;
            else if (idx == K_DATA_PDU_IN_ORDER) p->data_pdu_in_order = (uint8_t)res;
            else p->data_seq_in_order = (uint8_t)res;
            r = iscsi_kv_put(rsp, cap, &out, key, res ? "Yes" : "No");
            break;
        }
        case K_IMMEDIATE_DATA: case K_IFMARKER: case K_OFMARKER: {
            const int b = parse_bool(v, vl);
            if (b < 0) return neg_err(n, "Yes / No でない");
            /* AND。マーカは実装しない(RFC 7143 13.25 は IFMarker / OFMarker に No も許す。LIO も No)。 */
            const int mine = (idx == K_IMMEDIATE_DATA) ? pref->immediate_data : 0;
            const int res = b && mine;
            if (idx == K_IMMEDIATE_DATA) p->immediate_data = (uint8_t)res;
            r = iscsi_kv_put(rsp, cap, &out, key, res ? "Yes" : "No");
            break;
        }
        case K_IFMARKINT: case K_OFMARKINT:
            /* 廃止された鍵。**Reject で答えなければならない**(NotUnderstood は禁止。13.25)。 */
            r = iscsi_kv_put(rsp, cap, &out, key, "Reject");
            break;
        case K_TASK_REPORTING:
            /* 列挙(13.23)。ResponseFence / FastAbort の意味は実装しないので RFC3720 だけ。 */
            r = iscsi_kv_put(rsp, cap, &out, key, list_has(v, vl, "RFC3720") ? "RFC3720" : "Reject");
            break;
        case K_PROTO_LEVEL: {
            /* 最小値(13.24)。こちらは 1(RFC 7143 / 7144)。 */
            const int64_t x = parse_num_in(idx, v, vl);
            if (x < 0) return neg_err(n, "iSCSIProtocolLevel が範囲の外");
            p->proto_level = (uint8_t)umin((uint32_t)x, ISCSI_PROTO_LEVEL);
            r = iscsi_kv_put_u32(rsp, cap, &out, key, p->proto_level);
            break;
        }
        default: {   /* 数の交渉(最小値 / 最大値)*/
            const int64_t x = parse_num_in(idx, v, vl);
            if (x < 0) return neg_err(n, "数の値が範囲の外");   /* ErrorRecoveryLevel > 2、Time2Wait > 3600 など */
            uint32_t res;
            switch (idx) {
            case K_MAX_BURST:   res = p->max_burst = umin((uint32_t)x, pref->max_burst); break;
            case K_FIRST_BURST: res = p->first_burst = umin((uint32_t)x, pref->first_burst); break;
            case K_MAX_OUT_R2T: res = p->max_outstanding_r2t = umin((uint32_t)x, pref->max_outstanding_r2t); break;
            case K_MAX_CONN:    res = p->max_connections = 1u; break;          /* MC/S は扱わない */
            case K_ERL:         res = 0u; p->erl = 0; break;                     /* ERL=0 だけ */
            case K_T2RETAIN:    res = p->time2retain = 0u; break;                /* ERL=0 なので保持しない */
            default:            res = p->time2wait = umax((uint32_t)x, 2u); break;
            }
            r = iscsi_kv_put_u32(rsp, cap, &out, key, res);
            break;
        }
        }
        if (r < 0) return neg_err(n, "応答が長すぎる");
    }
    /* FirstBurstLength は MaxBurstLength を超えない(13.14)。 */
    if (p->first_burst > p->max_burst) p->first_burst = p->max_burst;

    /* こちらの宣言(最初の応答で 1 回だけ)。MaxRecvDataSegmentLength は操作の交渉の
     * 段でだけ宣言する -- 認証の段から直接 FFP へ移ったら宣言しないまま既定の 8192 を使う。 */
    if (!n->declared_mrdsl && stage == ISCSI_STAGE_OP && !pref->iser) {
        if (iscsi_kv_put_u32(rsp, cap, &out, "MaxRecvDataSegmentLength", pref->max_recv_dsl) < 0) return neg_err(n, "応答が長すぎる");
        p->max_recv_dsl = pref->max_recv_dsl;
        n->declared_mrdsl = 1;
    }
    /* iSER のターゲットは、相手が出していなければ**最初の運用の段の応答で RDMAExtensions=Yes を申し出る**
     * (RFC 7145 6.3)。Linux の iSER イニシエータは最初の要求で必ず出すので、普段はここを通らない。 */
    if (pref->iser && stage == ISCSI_STAGE_OP && !n->rdma_offered &&
        !(n->seen.known & (1ull << K_RDMA_EXT))) {
        if (iscsi_kv_put(rsp, cap, &out, "RDMAExtensions", "Yes") < 0) return neg_err(n, "応答が長すぎる");
        n->rdma_offered = 1;
    }
    if (!n->declared_tpgt) {
        if (pref->target_alias && !p->discovery &&
            iscsi_kv_put(rsp, cap, &out, "TargetAlias", pref->target_alias) < 0) return neg_err(n, "応答が長すぎる");
        /* 通常セッションの最初の応答に必須(13.9)。LIO は Discovery でも返すので揃える。 */
        if (iscsi_kv_put_u32(rsp, cap, &out, "TargetPortalGroupTag", pref->tpgt) < 0) return neg_err(n, "応答が長すぎる");
        n->declared_tpgt = 1;
    }
    return (int)out;
}

/* ---------------------------------------------------------------- イニシエータ */

void iscsi_ini_neg_init(iscsi_ini_neg_t *n, int discovery, int iser)
{
    iscsi_params_t keep = n->p;   /* 既定値は呼び出し側が入れてある */
    memset(n, 0, sizeof(*n));
    n->p = keep;
    n->discovery = (uint8_t)(discovery != 0);
    n->iser = (uint8_t)(iser != 0);
}

/* 並びから鍵 name の値を探す(1 = あった)。 */
static int find_val(const uint8_t *buf, uint32_t len, const char *name, uint32_t nl, const char **v, uint32_t *vl)
{
    const char *k;
    uint32_t kl, pos = 0;
    while (iscsi_kv_next(buf, len, &pos, &k, &kl, v, vl))
        if (kl == nl && memcmp(k, name, nl) == 0) return 1;
    return 0;
}

static int ini_err(iscsi_ini_neg_t *n, const char *why) { n->err = why; return -1; }

/* 相手の申し出(こちらが出していない鍵)への答え。こちらの値はイニシエータとして申し出るときと同じ
 * (iscsi_init.c の login() の並び)。 */
static int ini_answer(iscsi_ini_neg_t *n, int idx, const char *key, const char *v, uint32_t vl,
                      uint8_t *ans, uint32_t cap, uint32_t *alen)
{
    iscsi_params_t *p = &n->p;
    if (idx < 0) return iscsi_kv_put(ans, cap, alen, key, "NotUnderstood");
    if (n->discovery && KEYS[idx].session) return iscsi_kv_put(ans, cap, alen, key, "Irrelevant");
    switch (idx) {
    case K_HEADER_DIGEST: case K_DATA_DIGEST:
        if (!list_has(v, vl, "None")) return iscsi_kv_put(ans, cap, alen, key, "Reject");
        if (idx == K_HEADER_DIGEST) p->hdgst = 0; else p->ddgst = 0;
        return iscsi_kv_put(ans, cap, alen, key, "None");
    case K_INITIAL_R2T: case K_DATA_PDU_IN_ORDER: case K_DATA_SEQ_IN_ORDER:   /* OR、こちらは Yes */
        if (parse_bool(v, vl) < 0) return -2;
        return iscsi_kv_put(ans, cap, alen, key, "Yes");
    case K_IMMEDIATE_DATA: {                                                  /* AND、こちらは Yes */
        const int b = parse_bool(v, vl);
        if (b < 0) return -2;
        p->immediate_data = (uint8_t)b;
        return iscsi_kv_put(ans, cap, alen, key, b ? "Yes" : "No");
    }
    case K_IFMARKER: case K_OFMARKER:
        if (parse_bool(v, vl) < 0) return -2;
        return iscsi_kv_put(ans, cap, alen, key, "No");
    case K_IFMARKINT: case K_OFMARKINT:
        return iscsi_kv_put(ans, cap, alen, key, "Reject");
    case K_TASK_REPORTING:
        return iscsi_kv_put(ans, cap, alen, key, list_has(v, vl, "RFC3720") ? "RFC3720" : "Reject");
    case K_PROTO_LEVEL:
        if (parse_num_in(idx, v, vl) < 0) return -2;
        return iscsi_kv_put_u32(ans, cap, alen, key, 0u);   /* こちら(イニシエータ)は 0 */
    case K_ERL: case K_T2RETAIN:
        if (parse_num_in(idx, v, vl) < 0) return -2;
        return iscsi_kv_put_u32(ans, cap, alen, key, 0u);
    case K_T2WAIT: {
        const int64_t x = parse_num_in(idx, v, vl);
        if (x < 0) return -2;
        return iscsi_kv_put_u32(ans, cap, alen, key, umax((uint32_t)x, 2u));
    }
    case K_MAX_CONN: case K_MAX_OUT_R2T:
        if (parse_num_in(idx, v, vl) < 0) return -2;
        return iscsi_kv_put_u32(ans, cap, alen, key, 1u);
    case K_MAX_BURST: case K_FIRST_BURST: {
        const int64_t x = parse_num_in(idx, v, vl);
        if (x < 0) return -2;
        const uint32_t res = umin((uint32_t)x, idx == K_MAX_BURST ? 262144u : 65536u);
        if (idx == K_MAX_BURST) p->max_burst = res; else p->first_burst = res;
        return iscsi_kv_put_u32(ans, cap, alen, key, res);
    }
    case K_RDMA_EXT: {
        const int b = parse_bool(v, vl);
        if (b < 0) return -2;
        p->rdma_ext = (uint8_t)(b && n->iser);
        return iscsi_kv_put(ans, cap, alen, key, p->rdma_ext ? "Yes" : "No");
    }
    case K_TBSDO:
        /* こちらの iSER イニシエータは Linux と同じく「要請したデータだけ」を指す(Yes)。OR。 */
        if (parse_bool(v, vl) < 0) return -2;
        return iscsi_kv_put(ans, cap, alen, key, n->iser ? "Yes" : "Irrelevant");
    case K_AUTH_METHOD:
        return iscsi_kv_put(ans, cap, alen, key, list_has(v, vl, "None") ? "None" : "Reject");
    default:
        return iscsi_kv_put(ans, cap, alen, key, "Irrelevant");
    }
}

int iscsi_ini_neg_rsp(iscsi_ini_neg_t *n, const uint8_t *offers, uint32_t olen,
                      const uint8_t *rsp, uint32_t rlen, uint8_t *ans, uint32_t cap, uint32_t *alen)
{
    iscsi_params_t *p = &n->p;
    const char *k, *v;
    uint32_t kl, vl, pos = 0;
    *alen = 0;
    n->err = NULL;
    while (iscsi_kv_next(rsp, rlen, &pos, &k, &kl, &v, &vl)) {
        char key[64];
        if (kl == 0 || kl >= sizeof(key)) return ini_err(n, "鍵の名前が空か 63 バイトを超える");
        memcpy(key, k, kl);
        key[kl] = 0;
        /* 相手が同じ鍵を 2 回出したら接続を切る(RFC 7143 6.2「イニシエータが見つけたら接続を落とす」)。 */
        if (iscsi_keyseen_add(&n->seen, k, kl)) return ini_err(n, "ターゲットが同じ鍵を 2 回出した");
        const int idx = iscsi_key_index(k, kl);
        /* 相手が宣言するもの・CHAP の鍵(chap_login() が見る)は値を確かめるだけ。 */
        if (idx == K_TARGET_ALIAS || idx == K_TARGET_ADDRESS || idx == K_NODE_ARCH ||
            (idx >= K_CHAP_A && idx <= K_CHAP_R)) continue;
        if (idx == K_TPGT) {
            if (parse_num_in(idx, v, vl) < 0) return ini_err(n, "TargetPortalGroupTag が範囲の外");
            continue;
        }
        if (idx == K_MRDSL) {
            const int64_t x = parse_num_in(idx, v, vl);
            if (x < 0) return ini_err(n, "MaxRecvDataSegmentLength が範囲の外");
            p->max_xmit_dsl = (uint32_t)x;
            continue;
        }
        const char *ov;
        uint32_t ovl;
        if (!find_val(offers, olen, key, kl, &ov, &ovl)) {
            /* こちらが出していない = 相手の申し出。答える。 */
            const int r = ini_answer(n, idx, key, v, vl, ans, cap, alen);
            if (r == -2) return ini_err(n, "相手の申し出の値が不正");
            if (r < 0) return ini_err(n, "答えが長すぎる");
            continue;
        }
        /* ---- こちらの申し出への答え。結果の決め方で許されるかを確かめる(RFC 7143 6.2 / 13 章)---- */
        if (veq(v, vl, "NotUnderstood") || veq(v, vl, "Irrelevant") || veq(v, vl, "Reject")) {
            /* 既定値のまま(Reject された digest は None)。 */
            continue;
        }
        if (idx < 0) return ini_err(n, "こちらの知らない鍵に値が返った");
        switch (idx) {
        case K_HEADER_DIGEST: case K_DATA_DIGEST:
        case K_AUTH_METHOD: case K_TASK_REPORTING:
            /* 列挙: 答えはこちらの並びの 1 つでなければならない。 */
            {
                char val[ISCSI_VALUE_MAX + 1u];
                if (vl == 0 || vl > ISCSI_VALUE_MAX || memchr(v, ',', vl)) return ini_err(n, "列挙の答えが 1 つの値でない");
                memcpy(val, v, vl);
                val[vl] = 0;
                if (!list_has(ov, ovl, val)) return ini_err(n, "こちらの並びに無い値が選ばれた");
                if (idx == K_HEADER_DIGEST) p->hdgst = (val[0] == 'C');
                else if (idx == K_DATA_DIGEST) p->ddgst = (val[0] == 'C');
            }
            break;
        case K_INITIAL_R2T: case K_DATA_PDU_IN_ORDER: case K_DATA_SEQ_IN_ORDER: case K_TBSDO: {
            /* OR: こちらが Yes なら答えも Yes。 */
            const int b = parse_bool(v, vl), o = parse_bool(ov, ovl);
            if (b < 0) return ini_err(n, "Yes / No でない");
            if (o == 1 && b == 0) return ini_err(n, "OR の鍵で No が返った");
            if (idx == K_INITIAL_R2T) p->initial_r2t = (uint8_t)b;
            else if (idx == K_DATA_PDU_IN_ORDER) p->data_pdu_in_order = (uint8_t)b;
            else if (idx == K_DATA_SEQ_IN_ORDER) p->data_seq_in_order = (uint8_t)b;
            else { p->tbsdo = (uint8_t)b; p->tbsdo_set = 1; }
            break;
        }
        case K_IMMEDIATE_DATA: case K_IFMARKER: case K_OFMARKER: case K_RDMA_EXT: {
            /* AND: こちらが No なら答えも No。 */
            const int b = parse_bool(v, vl), o = parse_bool(ov, ovl);
            if (b < 0) return ini_err(n, "Yes / No でない");
            if (o == 0 && b == 1) return ini_err(n, "AND の鍵で Yes が返った");
            if (idx == K_IMMEDIATE_DATA) p->immediate_data = (uint8_t)b;
            else if (idx == K_RDMA_EXT) p->rdma_ext = (uint8_t)b;
            break;
        }
        case K_T2WAIT: {
            /* 最大値: 答えはこちらの値以上。 */
            const int64_t x = parse_num_in(idx, v, vl), o = parse_num(ov, ovl);
            if (x < 0 || x < o) return ini_err(n, "最大値の鍵の答えがこちらの値より小さい");
            p->time2wait = (uint32_t)x;
            break;
        }
        case K_MAX_BURST: case K_FIRST_BURST: case K_MAX_OUT_R2T: case K_MAX_CONN: case K_ERL:
        case K_T2RETAIN: case K_PROTO_LEVEL: case K_INI_RDSL: case K_TGT_RDSL: {
            /* 最小値: 答えはこちらの値以下(範囲の中)。 */
            const int64_t x = parse_num_in(idx, v, vl), o = parse_num(ov, ovl);
            if (x < 0 || x > o) return ini_err(n, "最小値の鍵の答えがこちらの値より大きい");
            switch (idx) {
            case K_MAX_BURST:   p->max_burst = (uint32_t)x; break;
            case K_FIRST_BURST: p->first_burst = (uint32_t)x; break;
            case K_MAX_OUT_R2T: p->max_outstanding_r2t = (uint32_t)x; break;
            case K_MAX_CONN:    p->max_connections = (uint32_t)x; break;
            case K_ERL:         p->erl = (uint8_t)x; break;
            case K_T2RETAIN:    p->time2retain = (uint32_t)x; break;
            case K_PROTO_LEVEL: p->proto_level = (uint8_t)x; break;
            case K_INI_RDSL:    p->ini_recv_dsl = (uint32_t)x; break;
            default:            p->tgt_recv_dsl = (uint32_t)x; break;
            }
            break;
        }
        default:
            /* こちらが申し出ない種類(名前など)に値が返った。 */
            return ini_err(n, "宣言した鍵に答えが返った");
        }
    }
    if (p->first_burst > p->max_burst) return ini_err(n, "FirstBurstLength が MaxBurstLength を超える");
    return 0;
}

/* ---------------------------------------------------------------- ログイン要求の BHS */

uint16_t iscsi_login_check(iscsi_login_state_t *st, const uint8_t bhs[ISCSI_BHS_LEN], const char **why)
{
    const uint8_t fl = bhs[1];
    const int T = (fl & ISCSI_LOGIN_T) != 0, C = (fl & ISCSI_LOGIN_C) != 0;
    const uint8_t csg = (uint8_t)((fl >> 2) & 3u), nsg = (uint8_t)(fl & 3u);
    const uint32_t itt = iscsi_be32(&bhs[ISCSI_OFF_ITT]);
    const uint16_t tsih = iscsi_be16(&bhs[ISCSI_LOGIN_OFF_TSIH]);
    const uint16_t cid = iscsi_be16(&bhs[ISCSI_LOGIN_OFF_CID]);
    *why = NULL;
    /* C=1 のときは T=0 でなければならない(11.12.2)。 */
    if (C && T) { *why = "C と T が両方立っている"; return ISCSI_LS_INIT_ERR; }
    if (csg == 2u || csg == 3u) { *why = "CSG が予約値 / FFP"; return ISCSI_LS_INVALID_REQUEST; }
    if (T && (nsg == 2u || nsg <= csg)) { *why = "NSG が不正"; return ISCSI_LS_INVALID_REQUEST; }
    if (!st->started) {
        st->started = 1;
        st->stage = csg;
        memcpy(st->isid, &bhs[ISCSI_LOGIN_OFF_ISID], 6);
        st->tsih = tsih;
        st->cid = cid;
        st->itt = itt;
        return 0;
    }
    /* ログインの途中で ISID / TSIH / CID / ITT は変わらない(11.12.3〜11.12.6。ITT は「同じ並びの
     * 要求はみな同じ」。LIO も "changed ITT unexpectedly" で断る)。 */
    if (memcmp(st->isid, &bhs[ISCSI_LOGIN_OFF_ISID], 6) != 0) { *why = "ISID がログインの途中で変わった"; return ISCSI_LS_INIT_ERR; }
    if (tsih != st->tsih) { *why = "TSIH がログインの途中で変わった"; return ISCSI_LS_INIT_ERR; }
    if (cid != st->cid) { *why = "CID がログインの途中で変わった"; return ISCSI_LS_INIT_ERR; }
    if (itt != st->itt) { *why = "ITT がログインの途中で変わった"; return ISCSI_LS_INIT_ERR; }
    /* CSG は今の段(移行に同意した段)と同じでなければならない。後戻りも先走りも断る(6.3)。 */
    if (csg != st->stage) { *why = "CSG が今の段と違う(後戻り / 同意の無い移行)"; return ISCSI_LS_INIT_ERR; }
    return 0;
}
