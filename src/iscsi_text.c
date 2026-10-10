/* iSCSI のテキスト鍵の解釈と交渉(RFC 7143 6.2 / 13 章)。
 *
 * 鍵の種類ごとに結果の決め方が違う(13 章の各鍵の "Result function"):
 *   - 最小値 : MaxBurstLength / FirstBurstLength / MaxOutstandingR2T / MaxConnections /
 *              ErrorRecoveryLevel / DefaultTime2Retain
 *   - 最大値 : DefaultTime2Wait
 *   - OR     : InitialR2T / DataPDUInOrder / DataSequenceInOrder
 *   - AND    : ImmediateData / IFMarker / OFMarker
 *   - 列挙   : HeaderDigest / DataDigest / AuthMethod(相手の並びの最初の、こちらが使えるもの)
 *   - 宣言型 : InitiatorName / InitiatorAlias / TargetName / SessionType /
 *              MaxRecvDataSegmentLength(**向きごとに別**。相手の値は相手の受け取れる長さ)
 * 知らない鍵には NotUnderstood、Discovery セッションでセッション全体の鍵には Irrelevant。
 * 段階 0 で取った open-iscsi <-> LIO の記録(tools/iscsi_ref/)と同じ応答になることを見る。 */
#include "iscsi_text.h"
#include <string.h>

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

static int keq(const char *k, uint32_t kl, const char *name)
{
    return kl == strlen(name) && memcmp(k, name, kl) == 0;   /* 鍵は大文字小文字を区別する */
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

/* Yes / No。-1 = どちらでもない。 */
static int parse_bool(const char *v, uint32_t vl)
{
    if (veq(v, vl, "Yes")) return 1;
    if (veq(v, vl, "No")) return 0;
    return -1;
}

static void copy_str(char *dst, uint32_t cap, const char *v, uint32_t vl)
{
    if (vl >= cap) vl = cap - 1u;
    memcpy(dst, v, vl);
    dst[vl] = 0;
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

/* セッション全体の鍵(Normal のときだけ意味がある。Discovery では Irrelevant)。 */
static int is_session_key(const char *k, uint32_t kl)
{
    return keq(k, kl, "InitialR2T") || keq(k, kl, "ImmediateData") || keq(k, kl, "MaxBurstLength") ||
           keq(k, kl, "FirstBurstLength") || keq(k, kl, "MaxOutstandingR2T") ||
           keq(k, kl, "MaxConnections") || keq(k, kl, "DataPDUInOrder") || keq(k, kl, "DataSequenceInOrder");
}

static uint32_t umin(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t umax(uint32_t a, uint32_t b) { return a > b ? a : b; }

int iscsi_neg_target(iscsi_neg_t *n, const iscsi_tgt_pref_t *pref, uint8_t stage,
                     const uint8_t *req, uint32_t len, uint8_t *rsp, uint32_t cap)
{
    iscsi_params_t *p = &n->p;
    uint32_t out = 0;
    const char *k, *v;
    uint32_t kl, vl, pos = 0;

    /* 1 回目: 宣言型のうち、他の鍵の扱いを左右するもの(SessionType は後ろに来てもよい)。 */
    while (iscsi_kv_next(req, len, &pos, &k, &kl, &v, &vl)) {
        if (keq(k, kl, "SessionType")) {
            n->got_session_type = 1;
            if (veq(v, vl, "Discovery")) p->discovery = 1;
            else if (veq(v, vl, "Normal")) p->discovery = 0;
            else n->bad_session_type = 1;
        } else if (keq(k, kl, "InitiatorName")) {
            n->got_initiator_name = 1;
            copy_str(n->initiator_name, sizeof(n->initiator_name), v, vl);
        } else if (keq(k, kl, "TargetName")) {
            n->got_target_name = 1;
            copy_str(n->target_name, sizeof(n->target_name), v, vl);
        } else if (keq(k, kl, "InitiatorAlias")) {
            copy_str(n->initiator_alias, sizeof(n->initiator_alias), v, vl);
        }
    }

    /* 2 回目: 交渉。 */
    pos = 0;
    while (iscsi_kv_next(req, len, &pos, &k, &kl, &v, &vl)) {
        char key[64];
        if (kl == 0 || kl >= sizeof(key)) return -1;   /* 鍵の名前は 63 バイトまで(RFC 7143 6.1)*/
        memcpy(key, k, kl);
        key[kl] = 0;
        int r = 0;

        if (keq(k, kl, "SessionType") || keq(k, kl, "InitiatorName") ||
            keq(k, kl, "TargetName") || keq(k, kl, "InitiatorAlias")) {
            continue;   /* 宣言型(応答しない)*/
        } else if (keq(k, kl, "RDMAExtensions")) {
            /* AND(RFC 7145 6.3)。iSER の接続でだけ Yes にする。 */
            const int b = parse_bool(v, vl);
            if (b < 0) return -1;
            p->rdma_ext = (uint8_t)(b && pref->iser);
            r = iscsi_kv_put(rsp, cap, &out, key, p->rdma_ext ? "Yes" : "No");
        } else if (keq(k, kl, "InitiatorRecvDataSegmentLength") ||
                   keq(k, kl, "TargetRecvDataSegmentLength")) {
            /* 小さいほう(RFC 7145 6.4 / 6.5。LIO も同じ)。iSER でなければ Irrelevant。 */
            const int64_t x = parse_num(v, vl);
            if (x < 512 || x > 16777215) return -1;
            if (!pref->iser) {
                r = iscsi_kv_put(rsp, cap, &out, key, "Irrelevant");
            } else if (key[0] == 'I') {
                p->ini_recv_dsl = umin((uint32_t)x, 262144u);
                r = iscsi_kv_put_u32(rsp, cap, &out, key, p->ini_recv_dsl);
            } else {
                p->tgt_recv_dsl = umin((uint32_t)x, pref->target_recv_dsl);
                r = iscsi_kv_put_u32(rsp, cap, &out, key, p->tgt_recv_dsl);
            }
        } else if (keq(k, kl, "MaxRecvDataSegmentLength")) {
            const int64_t x = parse_num(v, vl);
            if (x < 512 || x > 16777215) return -1;   /* 512〜2^24-1(13.12)*/
            p->max_xmit_dsl = (uint32_t)x;            /* 相手が受け取れる長さ = こちらが送る上限 */
            continue;
        } else if (p->discovery && is_session_key(k, kl)) {
            r = iscsi_kv_put(rsp, cap, &out, key, "Irrelevant");
        } else if (keq(k, kl, "HeaderDigest") || keq(k, kl, "DataDigest")) {
            const char *c = pick_digest(v, vl, pref->allow_crc32c);
            if (!c) {
                r = iscsi_kv_put(rsp, cap, &out, key, "Reject");
            } else {
                if (key[0] == 'H') p->hdgst = (c[0] == 'C'); else p->ddgst = (c[0] == 'C');
                r = iscsi_kv_put(rsp, cap, &out, key, c);
            }
        } else if (keq(k, kl, "AuthMethod")) {
            /* CHAP を求めるなら CHAP だけ、求めないなら None だけ(Discovery は CHAP を求めない)。 */
            n->auth_chosen = 1;
            const int want_chap = pref->chap_required && !p->discovery;
            n->auth_chap = want_chap && list_has(v, vl, "CHAP") ? 1 : 0;
            n->auth_none = !want_chap && list_has(v, vl, "None") ? 1 : 0;
            r = iscsi_kv_put(rsp, cap, &out, key, n->auth_chap ? "CHAP" : n->auth_none ? "None" : "Reject");
        } else if (keq(k, kl, "CHAP_A") || keq(k, kl, "CHAP_I") || keq(k, kl, "CHAP_C") ||
                   keq(k, kl, "CHAP_N") || keq(k, kl, "CHAP_R")) {
            /* 値を控えるだけ(手順はログインの処理が進める)。長すぎれば形式の誤り。 */
            char *dst; uint32_t dcap; uint8_t *got;
            switch (key[5]) {
            case 'A': dst = n->chap_a; dcap = sizeof(n->chap_a); got = &n->got_chap_a; break;
            case 'I': dst = n->chap_i; dcap = sizeof(n->chap_i); got = &n->got_chap_i; break;
            case 'C': dst = n->chap_c; dcap = sizeof(n->chap_c); got = &n->got_chap_c; break;
            case 'N': dst = n->chap_n; dcap = sizeof(n->chap_n); got = &n->got_chap_n; break;
            default:  dst = n->chap_r; dcap = sizeof(n->chap_r); got = &n->got_chap_r; break;
            }
            if (vl >= dcap) return -1;
            memcpy(dst, v, vl);
            dst[vl] = 0;
            *got = 1;
            continue;
        } else if (keq(k, kl, "InitialR2T") || keq(k, kl, "DataPDUInOrder") ||
                   keq(k, kl, "DataSequenceInOrder")) {
            const int b = parse_bool(v, vl);
            if (b < 0) return -1;
            /* OR。InitialR2T はこちらの希望、in-order の 2 つは**順序どおりにしか扱えないので常に Yes**。 */
            const int mine = keq(k, kl, "InitialR2T") ? pref->initial_r2t : 1;
            const int res = b || mine;
            if (keq(k, kl, "InitialR2T")) p->initial_r2t = (uint8_t)res;
            else if (keq(k, kl, "DataPDUInOrder")) p->data_pdu_in_order = (uint8_t)res;
            else p->data_seq_in_order = (uint8_t)res;
            r = iscsi_kv_put(rsp, cap, &out, key, res ? "Yes" : "No");
        } else if (keq(k, kl, "ImmediateData") || keq(k, kl, "IFMarker") || keq(k, kl, "OFMarker")) {
            const int b = parse_bool(v, vl);
            if (b < 0) return -1;
            /* AND。マーカは実装しない(RFC 7143 では廃止)。 */
            const int mine = keq(k, kl, "ImmediateData") ? pref->immediate_data : 0;
            const int res = b && mine;
            if (keq(k, kl, "ImmediateData")) p->immediate_data = (uint8_t)res;
            r = iscsi_kv_put(rsp, cap, &out, key, res ? "Yes" : "No");
        } else if (keq(k, kl, "MaxBurstLength") || keq(k, kl, "FirstBurstLength") ||
                   keq(k, kl, "MaxOutstandingR2T") || keq(k, kl, "MaxConnections") ||
                   keq(k, kl, "ErrorRecoveryLevel") || keq(k, kl, "DefaultTime2Retain") ||
                   keq(k, kl, "DefaultTime2Wait")) {
            const int64_t x = parse_num(v, vl);
            if (x < 0) return -1;
            uint32_t res;
            if (keq(k, kl, "MaxBurstLength")) {
                if (x < 512) return -1;
                res = p->max_burst = umin((uint32_t)x, pref->max_burst);
            } else if (keq(k, kl, "FirstBurstLength")) {
                if (x < 512) return -1;
                res = p->first_burst = umin((uint32_t)x, pref->first_burst);
            } else if (keq(k, kl, "MaxOutstandingR2T")) {
                if (x < 1) return -1;
                res = p->max_outstanding_r2t = umin((uint32_t)x, pref->max_outstanding_r2t);
            } else if (keq(k, kl, "MaxConnections")) {
                if (x < 1) return -1;
                res = p->max_connections = 1u;          /* MC/S は扱わない */
            } else if (keq(k, kl, "ErrorRecoveryLevel")) {
                res = 0u; p->erl = 0;                    /* ERL=0 だけ */
            } else if (keq(k, kl, "DefaultTime2Retain")) {
                res = p->time2retain = umin((uint32_t)x, 0u);   /* ERL=0 なので保持しない */
            } else {
                res = p->time2wait = umax((uint32_t)x, 2u);
            }
            r = iscsi_kv_put_u32(rsp, cap, &out, key, res);
        } else {
            /* 知らない鍵(X- で始まる私的な鍵も含む)。 */
            r = iscsi_kv_put(rsp, cap, &out, key, "NotUnderstood");
        }
        if (r < 0) return -1;
    }
    /* FirstBurstLength は MaxBurstLength を超えない(13.14)。 */
    if (p->first_burst > p->max_burst) p->first_burst = p->max_burst;

    /* こちらの宣言(最初の応答で 1 回だけ)。MaxRecvDataSegmentLength は操作の交渉の
     * 段でだけ宣言する -- 認証の段から直接 FFP へ移ったら宣言しないまま既定の 8192 を使う。 */
    if (!n->declared_mrdsl && stage == ISCSI_STAGE_OP && !pref->iser) {
        if (iscsi_kv_put_u32(rsp, cap, &out, "MaxRecvDataSegmentLength", pref->max_recv_dsl) < 0) return -1;
        p->max_recv_dsl = pref->max_recv_dsl;
        n->declared_mrdsl = 1;
    }
    if (!n->declared_tpgt) {
        if (pref->target_alias && !p->discovery &&
            iscsi_kv_put(rsp, cap, &out, "TargetAlias", pref->target_alias) < 0) return -1;
        /* 通常セッションの最初の応答に必須(13.9)。LIO は Discovery でも返すので揃える。 */
        if (iscsi_kv_put_u32(rsp, cap, &out, "TargetPortalGroupTag", pref->tpgt) < 0) return -1;
        n->declared_tpgt = 1;
    }
    return (int)out;
}
