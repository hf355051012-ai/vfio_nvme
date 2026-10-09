#include "nvmet_auth.h"
#include "nvme_auth.h"
#include "crypto.h"
#include "timer.h"
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
#define MSG_DONE                0xFFu   /* 自前の印: やりとりが終わった */
#define AUTH_ID_DHCHAP          0x01u   /* protocol descriptor の authid */
#define FAIL_REASON_FAILED      0x01u
#define FAIL_FAILED             0x01u
#define FAIL_NOT_USABLE         0x02u
#define FAIL_CONCAT_MISMATCH    0x03u
#define FAIL_HASH_UNUSABLE      0x04u
#define FAIL_DHGROUP_UNUSABLE   0x05u
#define FAIL_INCORRECT_PAYLOAD  0x06u
#define FAIL_INCORRECT_MESSAGE  0x07u

#define AUTH_RECV_MAX           4096u   /* Linux のホストは AL に最大 4096 を入れてくる */

/* ------------------------------------------------------------------ */
/* 設定(シェルの nvmetauth が書く。admin ジョブは読むだけ)。           */
/* ------------------------------------------------------------------ */
static struct {
    int        enabled;
    char       hostnqn[NVMET_AUTH_NQN_MAX + 1];
    nvme_auth_key_t host;      /* ホストの鍵(ホストが知っているはずの鍵)*/
    nvme_auth_key_t ctrl;      /* コントローラの鍵(双方向のときホストに示す鍵)。len=0 なら無し */
    uint8_t    hash_pref; /* 優先するハッシュ(Linux の dhchap_hash、既定 SHA-256)*/
    uint8_t    dhgid;     /* 使う DH 群(Linux の dhchap_dhgroup、既定 NULL)*/
} s_cfg = { .hash_pref = CRYPTO_SHA256 };

static inline uint16_t rd16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32le_b(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void wr16le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void wr32le_b(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}


static unsigned hash_bits(uint8_t id) { return id == 1 ? 256u : id == 2 ? 384u : 512u; }

int nvmet_auth_enabled(void) { return s_cfg.enabled; }

void nvmet_auth_reset(nvmet_auth_sess_t *s) {
    crypto_wipe(s, sizeof(*s));
    s->step = MSG_NEGOTIATE;
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

static void fail(nvmet_auth_sess_t *s, uint8_t reason, const char *why) {
    s->step = MSG_FAILURE1;
    s->status = reason;
    s->authenticated = 0;
    crypto_wipe(s->dh_priv, sizeof(s->dh_priv));
    crypto_wipe(s->skey, sizeof(s->skey));
    uart_printf("[auth] 失敗: %s(理由 0x%02x)\n", why, reason);
}

/* AUTH_Negotiate(Linux の nvmet_auth_negotiate())。 */
static void on_negotiate(nvmet_auth_sess_t *s, const uint8_t *d, uint32_t len) {
    s->tid = rd16le(d + 4);
    s->sc_c = d[6];
    const uint8_t napd = d[7];
    if (s->sc_c != 0) {   /* secure channel concatenation は TLS が要る(段階 H)*/
        fail(s, FAIL_CONCAT_MISMATCH, "SC_C(secure channel concatenation)は未対応");
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
    /* DH 群は設定したものだけを使う(ホストの候補に入っていること)。
     * Linux のホストは既定で NULL と ffdhe2048〜8192 を全部候補に挙げてくる。 */
    int ok = 0;
    for (unsigned i = 0; i < dhlen && i < 30u; i++) {
        if (ids[30u + i] == s_cfg.dhgid) ok = 1;
    }
    if (!ok) {
        fail(s, FAIL_DHGROUP_UNUSABLE, "設定した DH 群がホストの候補に無い");
        return;
    }
    s->hashid = pick;
    s->dhgid = s_cfg.dhgid;
    s->step = MSG_CHALLENGE;
    uart_printf("[auth] Negotiate: T_ID=%u ハッシュ=SHA-%u DH=%s\n", s->tid, hash_bits(pick),
                nvme_auth_dh_name(s->dhgid));
}

/* DH-HMAC-CHAP_Reply(Linux の nvmet_auth_reply())。
 *   [16] R1(hl)/ [16+hl] C2(hl)/ [16+2hl] ホストの DH 公開値(dhvlen)*/
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
    if (s->dhgid == 0) {
        if (dhvlen != 0) {
            fail(s, FAIL_INCORRECT_PAYLOAD, "DH 群 NULL なのに DH の値が付いている");
            return;
        }
    } else {
        /* ホストの公開値から共有秘密を作る(検査に通らない値は弾く)。 */
        const size_t plen = crypto_ffdhe_len(s->dhgid);
        const uint64_t t0 = timer_now();
        if (dhvlen != plen ||
            crypto_ffdhe_shared(s->dhgid, s->dh_priv, d + 16u + 2u * hl, dhvlen, s->skey) != 0) {
            fail(s, FAIL_DHGROUP_UNUSABLE, "ホストの DH 公開値が正しくない");
            return;
        }
        s->skey_len = (uint32_t)plen;
        crypto_wipe(s->dh_priv, sizeof(s->dh_priv));
        uart_printf("[auth] 共有秘密を計算(%s、%u us)\n", nvme_auth_dh_name(s->dhgid),
                    (unsigned)get_us_from(t0));
    }
    uint8_t expect[CRYPTO_HASH_MAX], ca1[CRYPTO_HASH_MAX];
    nvme_auth_augment(s->hashid, s->dhgid, s->skey, s->skey_len, s->c1, ca1);
    nvme_auth_host_response(&s_cfg.host, s->hashid, ca1, s->s1, s->tid, s->sc_c, s->hostnqn, subnqn, expect);
    crypto_wipe(ca1, sizeof(ca1));
    const int ok = crypto_equal(expect, d + 16, hl);
    crypto_wipe(expect, sizeof(expect));
    if (!ok) {
        fail(s, FAIL_FAILED, "ホストの応答が一致しない(鍵が違う)");
        return;
    }
    if (cvalid && s2 != 0) {
        /* 双方向: ホストもこちらを確かめたがっている。コントローラの鍵が要る。 */
        if (s_cfg.ctrl.len == 0) {
            fail(s, FAIL_FAILED, "双方向を求められたがコントローラの鍵が無い");
            return;
        }
        s->bidir = 1;
        s->s2 = s2;
        memcpy(s->c2, d + 16u + hl, hl);
        s->step = MSG_SUCCESS1;   /* 認証済みにするのは Success2 を受けてから */
        uart_printf("[auth] ホスト %s を認証しました(双方向: こちらの応答を返す)\n", s->hostnqn);
        return;
    }
    /* S2 == 0 で C2 が付くのは concat 用の PSK を作るためで、双方向ではない。 */
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
        s->bidir = 0;
        on_negotiate(s, data, tl);
    } else if (type == AUTH_TYPE_COMMON && id == MSG_FAILURE2) {
        /* 双方向でこちらの応答 R2 が合わなかった、などでホストが断ってきた。 */
        fail(s, data[7], "ホストが Failure2 を返した(こちらの応答をホストが認めなかった)");
        s->failed = 1;
    } else if (type != AUTH_TYPE_DHCHAP || id != s->step) {
        fail(s, FAIL_INCORRECT_MESSAGE, "想定外のメッセージ");
        s->failed = 1;
    } else if (rd16le(data + 4) != s->tid) {
        fail(s, FAIL_INCORRECT_PAYLOAD, "T_ID が違う");
    } else if (id == MSG_REPLY) {
        on_reply(s, data, tl, subnqn);
    } else if (id == MSG_SUCCESS2) {
        /* 双方向のときだけ来る: ホストがこちらの R2 を確かめ終えた。 */
        if (!s->bidir) {
            fail(s, FAIL_INCORRECT_MESSAGE, "双方向でないのに Success2");
            s->failed = 1;
        } else {
            s->authenticated = 1;
            s->step = MSG_DONE;
            uart_printf("[auth] 双方向の認証が終わった(ホストがこちらを認めた)\n");
        }
    }
    return 0;
}

uint16_t nvmet_auth_receive(nvmet_auth_sess_t *s, uint32_t cdw10, uint32_t cdw11,
                            uint8_t *out, uint32_t cap, uint32_t *out_len, const char *subnqn) {
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
        /* DH-HMAC-CHAP_Challenge(Linux の nvmet_auth_challenge())。
         *   [16] C1(hl)/ [16+hl] こちらの DH 公開値(dhvlen)*/
        const uint8_t hl = (uint8_t)crypto_hash_len((crypto_hash_id_t)s->hashid);
        const size_t dhlen = s->dhgid ? crypto_ffdhe_len(s->dhgid) : 0u;
        if (al < 16u + hl + dhlen) return NVMET_AUTH_SC_INVALID_FIELD;
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
        wr16le(out + 10, (uint16_t)dhlen);
        wr32le_b(out + 12, s->s1);
        memcpy(out + 16, s->c1, hl);
        if (dhlen) {
            /* **セッションごとに秘密の指数を作り直す**(Linux はコントローラ単位で
             * 使い回すが、作り直すほうが安全で、費用は接続時の数 ms だけ)。 */
            const uint64_t t0 = timer_now();
            if (crypto_ffdhe_keygen(s->dhgid, s->dh_priv, out + 16 + hl) != 0) {
                return NVMET_AUTH_SC_INVALID_FIELD;
            }
            uart_printf("[auth] DH 公開値を作った(%s、%u バイト、%u us)\n", nvme_auth_dh_name(s->dhgid),
                        (unsigned)dhlen, (unsigned)get_us_from(t0));
        }
        s->step = MSG_REPLY;
        uart_printf("[auth] Challenge を返した(S1=%u、C1 %u バイト)\n", s->s1, hl);
        return 0;
    }
    if (s->step == MSG_SUCCESS1) {
        /* DH-HMAC-CHAP_Success1。双方向なら R2 を付ける(rvalid=1)。 */
        const uint8_t hl = (uint8_t)crypto_hash_len((crypto_hash_id_t)s->hashid);
        if (s->bidir && al < 16u + hl) return NVMET_AUTH_SC_INVALID_FIELD;
        out[0] = AUTH_TYPE_DHCHAP;
        out[1] = MSG_SUCCESS1;
        wr16le(out + 4, s->tid);
        out[6] = hl;
        if (s->bidir) {
            uint8_t ca2[CRYPTO_HASH_MAX];
            nvme_auth_augment(s->hashid, s->dhgid, s->skey, s->skey_len, s->c2, ca2);
            nvme_auth_ctrl_response(&s_cfg.ctrl, s->hashid, ca2, s->s2, s->tid, s->hostnqn, subnqn, out + 16);
            crypto_wipe(ca2, sizeof(ca2));
            out[8] = 1;   /* rvalid */
            s->step = MSG_SUCCESS2;
        } else {
            s->step = MSG_DONE;
        }
        crypto_wipe(s->c1, sizeof(s->c1));
        crypto_wipe(s->c2, sizeof(s->c2));
        crypto_wipe(s->skey, sizeof(s->skey));
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
    static const char usage[] =
        "使い方: nvmetauth <hostnqn> <ホストの鍵 DHHC-1:..> [sha256|sha384|sha512]\n"
        "                  [null|ffdhe2048|ffdhe3072|ffdhe4096|ffdhe6144|ffdhe8192] [ctrl=<DHHC-1:..>]\n"
        "        nvmetauth off\n";
    char buf[600];
    strncpy(buf, args ? args : "", sizeof(buf) - 1u);
    buf[sizeof(buf) - 1u] = 0;
    char *tok[8];
    unsigned nt = 0;
    char *save = 0;
    for (char *p = strtok_r(buf, " \t\r\n", &save); p && nt < 8u; p = strtok_r(0, " \t\r\n", &save)) {
        tok[nt++] = p;
    }
    if (nt == 1 && strcmp(tok[0], "off") == 0) {
        crypto_wipe(&s_cfg, sizeof(s_cfg));
        s_cfg.hash_pref = CRYPTO_SHA256;
        uart_printf("nvmetauth: 認証を求めない(次の Connect から)\n");
        return;
    }
    if (nt >= 2) {
        nvme_auth_key_t host, ctrl;
        memset(&ctrl, 0, sizeof(ctrl));
        int r = nvme_auth_parse_secret(tok[1], &host);
        uint8_t pref = CRYPTO_SHA256, dh = 0;
        for (unsigned i = 2; i < nt && r == 0; i++) {
            if (!strcmp(tok[i], "sha256")) pref = CRYPTO_SHA256;
            else if (!strcmp(tok[i], "sha384")) pref = CRYPTO_SHA384;
            else if (!strcmp(tok[i], "sha512")) pref = CRYPTO_SHA512;
            else if (!strncmp(tok[i], "ctrl=", 5)) r = nvme_auth_parse_secret(tok[i] + 5, &ctrl);
            else {
                unsigned g;
                for (g = 0; g < 6u && strcmp(tok[i], nvme_auth_dh_name((uint8_t)g)) != 0; g++) {
                }
                if (g == 6u) {
                    uart_printf("nvmetauth: 分からない指定 %s\n%s", tok[i], usage);
                    return;
                }
                dh = (uint8_t)g;
            }
        }
        if (r != 0) {
            uart_printf("nvmetauth: 鍵の形式が正しくない(%s)。DHHC-1:<00-03>:<base64>: の形\n",
                        nvme_auth_parse_error(r));
            crypto_wipe(&host, sizeof(host));
            crypto_wipe(&ctrl, sizeof(ctrl));
            return;
        }
        strncpy(s_cfg.hostnqn, tok[0], NVMET_AUTH_NQN_MAX);
        s_cfg.hostnqn[NVMET_AUTH_NQN_MAX] = 0;
        s_cfg.host = host;
        s_cfg.ctrl = ctrl;
        s_cfg.hash_pref = pref;
        s_cfg.dhgid = dh;
        s_cfg.enabled = 1;
        crypto_wipe(&host, sizeof(host));
        crypto_wipe(&ctrl, sizeof(ctrl));
    } else if (nt != 0) {
        uart_printf("%s", usage);
        return;
    }
    if (!s_cfg.enabled) {
        uart_printf("nvmetauth: 認証を求めない(どのホストも鍵なしで繋がる)\n");
    } else {
        /* 鍵そのものは表示しない。 */
        uart_printf("nvmetauth: ホスト %s に DH-HMAC-CHAP を求める(ホストの鍵 %u バイト・変換 %u、"
                    "コントローラの鍵 %s、優先ハッシュ SHA-%u、DH 群 %s)。次の Connect から\n",
                    s_cfg.hostnqn, s_cfg.host.len, s_cfg.host.hash,
                    s_cfg.ctrl.len ? "あり(双方向に応じる)" : "なし(片方向のみ)",
                    hash_bits(s_cfg.hash_pref), nvme_auth_dh_name(s_cfg.dhgid));
    }
}
