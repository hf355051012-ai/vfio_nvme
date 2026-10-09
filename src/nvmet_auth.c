#include "nvmet_auth.h"
#include "crypto.h"
#include "uart.h"

#include <stdlib.h>
#include <string.h>

/* include/linux/nvme.h の値 */
#define AUTH_SECP_DHCHAP        0xE9u   /* NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER */
#define AUTH_TYPE_COMMON        0x00u
#define AUTH_TYPE_DHCHAP        0x01u
#define MSG_NEGOTIATE           0x00u
#define MSG_CHALLENGE           0x01u
#define MSG_REPLY               0x02u
#define MSG_SUCCESS1            0x03u
#define MSG_SUCCESS2            0x04u
#define MSG_FAILURE2            0xF0u
#define MSG_FAILURE1            0xF1u
#define AUTH_ID_DHCHAP          0x01u   /* protocol descriptor の authid */
#define FAIL_REASON_FAILED      0x01u
#define FAIL_FAILED             0x01u
#define FAIL_NOT_USABLE         0x02u
#define FAIL_HASH_UNUSABLE      0x04u
#define FAIL_DHGROUP_UNUSABLE   0x05u
#define FAIL_INCORRECT_PAYLOAD  0x06u
#define FAIL_INCORRECT_MESSAGE  0x07u

#define AUTH_RECV_MAX           4096u   /* Linux のホストは AL に最大 4096 を入れてくる */

/* ------------------------------------------------------------------ */
/* 設定(シェルの nvmetauth が書く。admin ジョブは読むだけ)。           */
/* ------------------------------------------------------------------ */
static struct {
    int      enabled;
    char     hostnqn[NVMET_AUTH_NQN_MAX + 1];
    uint8_t  key[64];
    uint32_t key_len;
    uint8_t  key_hash;    /* DHHC-1:<hh>: の hh。0 なら鍵をそのまま使う */
    uint8_t  hash_pref;   /* 優先するハッシュ(Linux の dhchap_hash、既定 SHA-256)*/
} s_cfg = { .hash_pref = CRYPTO_SHA256 };

static inline uint16_t rd16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32le_b(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void wr16le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void wr32le_b(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

int nvmet_auth_enabled(void) { return s_cfg.enabled; }

void nvmet_auth_reset(nvmet_auth_sess_t *s) {
    crypto_wipe(s, sizeof(*s));
    s->step = MSG_NEGOTIATE;
}

/*=================================================================
 * DHHC-1:<hh>:<base64>: を解く(Linux の nvme_auth_extract_key())。
 * base64 を解いた末尾 4 バイトが鍵本体の CRC-32(リトルエンディアン)。
 * 鍵本体は 32 / 48 / 64 バイト。
 * ===============================================================*/
static int parse_secret(const char *sec, uint8_t *key, uint32_t *klen, uint8_t *khash) {
    if (strncmp(sec, "DHHC-1:", 7) != 0) return -1;
    if (sec[7] < '0' || sec[7] > '9' || sec[8] < '0' || sec[8] > '9' || sec[9] != ':') return -1;
    const unsigned hh = (unsigned)((sec[7] - '0') * 10 + (sec[8] - '0'));
    if (hh > 3u) return -1;
    const char *b = sec + 10;
    const char *e = strchr(b, ':');
    const size_t blen = e ? (size_t)(e - b) : strlen(b);
    uint8_t raw[72];
    const int n = crypto_base64_decode(b, blen, raw, sizeof(raw));
    if (n != 36 && n != 52 && n != 68) return -2;
    const uint32_t len = (uint32_t)n - 4u;
    if (crypto_crc32(raw, len) != rd32le_b(raw + len)) return -3;
    memcpy(key, raw, len);
    crypto_wipe(raw, sizeof(raw));
    *klen = len;
    *khash = (uint8_t)hh;
    return 0;
}

/* ------------------------------------------------------------------ */

uint16_t nvmet_auth_on_connect(nvmet_auth_sess_t *s, const uint8_t *hostnqn256, uint32_t *atr) {
    nvmet_auth_reset(s);
    *atr = 0;
    size_t n = 0;
    while (n < NVMET_AUTH_NQN_MAX && hostnqn256[n] != 0) n++;
    memcpy(s->hostnqn, hostnqn256, n);
    s->hostnqn[n] = 0;
    if (!s_cfg.enabled) return 0;
    /* 鍵を設定したホスト以外は受け付けない(Linux は allow_any_host でなければ
     * hosts/ に無いホストを nvmet_setup_auth() で弾き、Connect が Invalid Host になる)。 */
    if (strcmp(s->hostnqn, s_cfg.hostnqn) != 0) {
        uart_printf("[auth] 設定外のホスト %s の Connect を拒否\n", s->hostnqn);
        return NVMET_AUTH_SC_INVALID_HOST;
    }
    s->required = 1;
    *atr = NVMET_AUTH_CONNECT_ATR;
    return 0;
}

int nvmet_auth_blocks(const nvmet_auth_sess_t *s) {
    return s->required && (!s->authenticated || s->failed);
}

/*=================================================================
 * ホストの応答を計算する(Linux の nvmet_auth_host_hash())。
 *   鍵 = key_hash ? HMAC(key_hash, 鍵, hostnqn ‖ "NVMe-over-Fabrics") : 鍵
 *   R1 = HMAC(hash, 鍵, C1 ‖ S1(LE32) ‖ T_ID(LE16) ‖ SC_C ‖ "HostHost" ‖
 *             hostnqn ‖ 0x00 ‖ subnqn)
 * DH 群が NULL なので C1 はそのまま(DH があれば augmented challenge になる。段階 B)。
 * ===============================================================*/
static void host_response(const nvmet_auth_sess_t *s, const char *subnqn, uint8_t *out) {
    uint8_t tkey[CRYPTO_HASH_MAX];
    uint32_t tlen;
    if (s_cfg.key_hash) {
        crypto_hmac_ctx_t t;
        crypto_hmac_init(&t, (crypto_hash_id_t)s_cfg.key_hash, s_cfg.key, s_cfg.key_len);
        crypto_hmac_update(&t, s->hostnqn, strlen(s->hostnqn));
        crypto_hmac_update(&t, "NVMe-over-Fabrics", 17);
        crypto_hmac_final(&t, tkey);
        tlen = (uint32_t)crypto_hash_len((crypto_hash_id_t)s_cfg.key_hash);
    } else {
        memcpy(tkey, s_cfg.key, s_cfg.key_len);
        tlen = s_cfg.key_len;
    }
    const crypto_hash_id_t id = (crypto_hash_id_t)s->hashid;
    const size_t hl = crypto_hash_len(id);
    uint8_t b4[4];
    crypto_hmac_ctx_t h;
    crypto_hmac_init(&h, id, tkey, tlen);
    crypto_hmac_update(&h, s->c1, hl);
    wr32le_b(b4, s->s1);
    crypto_hmac_update(&h, b4, 4);
    wr16le(b4, s->tid);
    crypto_hmac_update(&h, b4, 2);
    crypto_hmac_update(&h, &s->sc_c, 1);
    crypto_hmac_update(&h, "HostHost", 8);
    crypto_hmac_update(&h, s->hostnqn, strlen(s->hostnqn));
    b4[0] = 0;
    crypto_hmac_update(&h, b4, 1);
    crypto_hmac_update(&h, subnqn, strlen(subnqn));
    crypto_hmac_final(&h, out);
    crypto_wipe(tkey, sizeof(tkey));
}

static void fail(nvmet_auth_sess_t *s, uint8_t reason, const char *why) {
    s->step = MSG_FAILURE1;
    s->status = reason;
    s->authenticated = 0;
    uart_printf("[auth] 失敗: %s(理由 0x%02x)\n", why, reason);
}

/* AUTH_Negotiate(Linux の nvmet_auth_negotiate())。 */
static void on_negotiate(nvmet_auth_sess_t *s, const uint8_t *d, uint32_t len) {
    s->tid = rd16le(d + 4);
    s->sc_c = d[6];
    const uint8_t napd = d[7];
    if (s->sc_c != 0) {   /* secure channel concatenation は TLS が要る(段階 H)*/
        fail(s, 0x03u /* CONCAT_MISMATCH */, "SC_C(secure channel concatenation)は未対応");
        return;
    }
    if (napd != 1 || len < 8u + 64u) {
        fail(s, FAIL_HASH_UNUSABLE, "protocol descriptor が 1 個でない");
        return;
    }
    const uint8_t *pd = d + 8;   /* authid, rsvd, halen, dhlen, idlist[60] */
    if (pd[0] != AUTH_ID_DHCHAP) {
        fail(s, FAIL_INCORRECT_PAYLOAD, "authid が DH-HMAC-CHAP でない");
        return;
    }
    const uint8_t halen = pd[2], dhlen = pd[3];
    const uint8_t *ids = pd + 4;
    uint8_t pick = 0, fallback = 0;
    for (unsigned i = 0; i < halen && i < 30u; i++) {
        const uint8_t h = ids[i];
        if (h < 1 || h > 3) continue;
        if (!fallback) fallback = h;
        if (h == s_cfg.hash_pref) pick = h;
    }
    if (!pick) pick = fallback;
    if (!pick) {
        fail(s, FAIL_HASH_UNUSABLE, "使えるハッシュが無い");
        return;
    }
    int null_ok = 0;
    for (unsigned i = 0; i < dhlen && i < 30u; i++) {
        if (ids[30u + i] == 0x00u) null_ok = 1;
    }
    if (!null_ok) {
        fail(s, FAIL_DHGROUP_UNUSABLE, "DH 群 NULL が候補に無い(段階 A は NULL のみ)");
        return;
    }
    s->hashid = pick;
    s->dhgid = 0;
    s->step = MSG_CHALLENGE;
    uart_printf("[auth] Negotiate: T_ID=%u ハッシュ=SHA-%u DH=NULL\n", s->tid,
                pick == 1 ? 256u : pick == 2 ? 384u : 512u);
}

/* DH-HMAC-CHAP_Reply(Linux の nvmet_auth_reply())。 */
static void on_reply(nvmet_auth_sess_t *s, const uint8_t *d, uint32_t len, const char *subnqn) {
    const uint8_t hl = d[6];
    const uint8_t cvalid = d[8];
    const uint16_t dhvlen = rd16le(d + 10);
    const uint32_t s2 = rd32le_b(d + 12);
    const size_t want = crypto_hash_len((crypto_hash_id_t)s->hashid);
    if (hl != want || len < 16u + 2u * hl + dhvlen) {
        fail(s, FAIL_INCORRECT_PAYLOAD, "Reply の長さが合わない");
        return;
    }
    if (dhvlen != 0) {
        fail(s, FAIL_INCORRECT_PAYLOAD, "DH 群 NULL なのに DH の値が付いている");
        return;
    }
    uint8_t expect[CRYPTO_HASH_MAX];
    host_response(s, subnqn, expect);
    const int ok = crypto_equal(expect, d + 16, hl);
    crypto_wipe(expect, sizeof(expect));
    if (!ok) {
        fail(s, FAIL_FAILED, "ホストの応答が一致しない(鍵が違う)");
        return;
    }
    /* 双方向(cvalid かつ S2 != 0)はコントローラの鍵が要る(段階 B)。
     * S2 == 0 で C2 が付くのは concat 用の PSK を作るためで、双方向ではない。 */
    if (cvalid && s2 != 0) {
        fail(s, FAIL_FAILED, "双方向認証は未対応(コントローラの鍵が無い)");
        return;
    }
    s->authenticated = 1;
    s->step = MSG_SUCCESS1;
    uart_printf("[auth] ホスト %s を認証しました\n", s->hostnqn);
}

uint16_t nvmet_auth_send(nvmet_auth_sess_t *s, uint32_t cdw10, uint32_t cdw11,
                         const uint8_t *data, uint32_t dlen, const char *subnqn) {
    /* cdw10 = resv3 | SPSP0 << 8 | SPSP1 << 16 | SECP << 24(struct nvmf_auth_send_command)*/
    if ((cdw10 >> 24) != AUTH_SECP_DHCHAP || ((cdw10 >> 8) & 0xFFu) != 1u ||
        ((cdw10 >> 16) & 0xFFu) != 1u) {
        return NVMET_AUTH_SC_INVALID_FIELD;
    }
    const uint32_t tl = cdw11;
    if (tl == 0 || tl > dlen || data == NULL || tl < 8u) return NVMET_AUTH_SC_INVALID_FIELD;
    if (!s->required) {
        uart_printf("[auth] 認証を求めていないセッションに Authentication Send\n");
        return NVMET_AUTH_SC_INVALID_FIELD;
    }
    const uint8_t type = data[0], id = data[1];
    if (type == AUTH_TYPE_COMMON && id == MSG_NEGOTIATE) {
        /* いつでも最初からやり直せる(Linux も同じ)。 */
        s->authenticated = 0;
        s->failed = 0;
        on_negotiate(s, data, tl);
    } else if (type == AUTH_TYPE_COMMON && id == MSG_FAILURE2) {
        fail(s, data[7], "ホストが Failure2 を返した");
        s->failed = 1;
    } else if (type != AUTH_TYPE_DHCHAP || id != s->step) {
        fail(s, FAIL_INCORRECT_MESSAGE, "想定外のメッセージ");
        s->failed = 1;
    } else if (rd16le(data + 4) != s->tid) {
        fail(s, FAIL_INCORRECT_PAYLOAD, "T_ID が違う");
    } else if (id == MSG_REPLY) {
        on_reply(s, data, tl, subnqn);
    } else if (id == MSG_SUCCESS2) {
        /* 双方向のときだけ来る。段階 A では来ない(Reply で断っている)。 */
        fail(s, FAIL_INCORRECT_MESSAGE, "Success2 は段階 A では来ないはず");
        s->failed = 1;
    }
    return 0;
}

uint16_t nvmet_auth_receive(nvmet_auth_sess_t *s, uint32_t cdw10, uint32_t cdw11,
                            uint8_t *out, uint32_t cap, uint32_t *out_len) {
    *out_len = 0;
    if ((cdw10 >> 24) != AUTH_SECP_DHCHAP || ((cdw10 >> 8) & 0xFFu) != 1u ||
        ((cdw10 >> 16) & 0xFFu) != 1u) {
        return NVMET_AUTH_SC_INVALID_FIELD;
    }
    const uint32_t al = cdw11;
    if (al == 0 || al > cap || al > AUTH_RECV_MAX || al < 16u) return NVMET_AUTH_SC_INVALID_FIELD;
    memset(out, 0, al);
    *out_len = al;
    if (s->step == MSG_CHALLENGE) {
        /* DH-HMAC-CHAP_Challenge(Linux の nvmet_auth_challenge())。 */
        const uint8_t hl = (uint8_t)crypto_hash_len((crypto_hash_id_t)s->hashid);
        if (al < 16u + hl) return NVMET_AUTH_SC_INVALID_FIELD;
        do {
            crypto_random(&s->s1, sizeof(s->s1));
        } while (s->s1 == 0);   /* 0 は「双方向でない」の意味に使われるので避ける */
        crypto_random(s->c1, hl);
        out[0] = AUTH_TYPE_DHCHAP;
        out[1] = MSG_CHALLENGE;
        wr16le(out + 4, s->tid);
        out[6] = hl;
        out[8] = s->hashid;
        out[9] = s->dhgid;
        wr16le(out + 10, 0);        /* dhvlen: NULL 群なので DH の値は無い */
        wr32le_b(out + 12, s->s1);
        memcpy(out + 16, s->c1, hl);
        s->step = MSG_REPLY;
        uart_printf("[auth] Challenge を返した(S1=%u、C1 %u バイト)\n", s->s1, hl);
        return 0;
    }
    if (s->step == MSG_SUCCESS1) {
        /* DH-HMAC-CHAP_Success1(片方向なので rvalid=0、R2 無し)。 */
        out[0] = AUTH_TYPE_DHCHAP;
        out[1] = MSG_SUCCESS1;
        wr16le(out + 4, s->tid);
        out[6] = (uint8_t)crypto_hash_len((crypto_hash_id_t)s->hashid);
        out[8] = 0;   /* rvalid */
        s->step = MSG_SUCCESS2;
        crypto_wipe(s->c1, sizeof(s->c1));
        return 0;
    }
    /* Failure1(それ以外の場面で読まれたときも、Linux と同じく Failure1 を返す)。 */
    if (s->step != MSG_FAILURE1) {
        s->status = FAIL_FAILED;
        uart_printf("[auth] 想定外の場面(step=0x%02x)で Authentication Receive\n", s->step);
    }
    out[0] = AUTH_TYPE_COMMON;
    out[1] = MSG_FAILURE1;
    wr16le(out + 4, s->tid);
    out[6] = FAIL_REASON_FAILED;
    out[7] = s->status;
    s->authenticated = 0;
    s->failed = 1;
    return 0;
}

/* ------------------------------------------------------------------ */

void nvmet_auth_shell(const char *args) {
    char buf[600];
    strncpy(buf, args ? args : "", sizeof(buf) - 1u);
    buf[sizeof(buf) - 1u] = 0;
    char *tok[4];
    unsigned nt = 0;
    char *save = 0;
    for (char *p = strtok_r(buf, " \t\r\n", &save); p && nt < 4u; p = strtok_r(0, " \t\r\n", &save)) {
        tok[nt++] = p;
    }
    if (nt == 1 && strcmp(tok[0], "off") == 0) {
        crypto_wipe(&s_cfg, sizeof(s_cfg));
        s_cfg.hash_pref = CRYPTO_SHA256;
        uart_printf("nvmetauth: 認証を求めない(次の Connect から)\n");
        return;
    }
    if (nt >= 2) {
        uint8_t key[64];
        uint32_t klen = 0;
        uint8_t khash = 0;
        const int r = parse_secret(tok[1], key, &klen, &khash);
        if (r != 0) {
            uart_printf("nvmetauth: 鍵の形式が正しくない(%s)。DHHC-1:<00-03>:<base64>: の形\n",
                        r == -3 ? "末尾の CRC-32 が合わない" : r == -2 ? "長さが 32/48/64 バイトでない"
                                                              : "書式");
            crypto_wipe(key, sizeof(key));
            return;
        }
        uint8_t pref = CRYPTO_SHA256;
        if (nt >= 3) {
            if (!strcmp(tok[2], "sha384")) pref = CRYPTO_SHA384;
            else if (!strcmp(tok[2], "sha512")) pref = CRYPTO_SHA512;
            else if (strcmp(tok[2], "sha256") != 0) {
                uart_printf("nvmetauth: ハッシュは sha256 / sha384 / sha512\n");
                return;
            }
        }
        strncpy(s_cfg.hostnqn, tok[0], NVMET_AUTH_NQN_MAX);
        s_cfg.hostnqn[NVMET_AUTH_NQN_MAX] = 0;
        memcpy(s_cfg.key, key, klen);
        s_cfg.key_len = klen;
        s_cfg.key_hash = khash;
        s_cfg.hash_pref = pref;
        s_cfg.enabled = 1;
        crypto_wipe(key, sizeof(key));
    } else if (nt != 0) {
        uart_printf("使い方: nvmetauth <hostnqn> <DHHC-1:..:..:> [sha256|sha384|sha512] / nvmetauth off\n");
        return;
    }
    if (!s_cfg.enabled) {
        uart_printf("nvmetauth: 認証を求めない(どのホストも鍵なしで繋がる)\n");
    } else {
        /* 鍵そのものは表示しない。 */
        uart_printf("nvmetauth: ホスト %s に DH-HMAC-CHAP を求める(鍵 %u バイト、鍵の変換 %u、"
                    "優先ハッシュ SHA-%u、DH 群 NULL、片方向)。次の Connect から\n",
                    s_cfg.hostnqn, s_cfg.key_len, s_cfg.key_hash,
                    s_cfg.hash_pref == 1 ? 256u : s_cfg.hash_pref == 2 ? 384u : 512u);
    }
}
