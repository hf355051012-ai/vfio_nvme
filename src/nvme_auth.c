#include "nvme_auth.h"
#include "uart.h"

#include <string.h>

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static const char *const s_dh_name[6] = { "null", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192" };

const char *nvme_auth_dh_name(uint8_t dhgid) { return dhgid < 6u ? s_dh_name[dhgid] : "?"; }

/*=================================================================
 * DHHC-1:<hh>:<base64>: を解く(Linux の nvme_auth_extract_key())。
 * base64 を解いた末尾 4 バイトが鍵本体の CRC-32(リトルエンディアン)。
 * 鍵本体は 32 / 48 / 64 バイト。
 * ===============================================================*/
int nvme_auth_parse_secret(const char *sec, nvme_auth_key_t *k) {
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
    if (crypto_crc32(raw, len) != rd32(raw + len)) return -3;
    memcpy(k->key, raw, len);
    crypto_wipe(raw, sizeof(raw));
    k->len = len;
    k->hash = (uint8_t)hh;
    return 0;
}

const char *nvme_auth_parse_error(int r) {
    return r == -3 ? "末尾の CRC-32 が合わない" : r == -2 ? "長さが 32/48/64 バイトでない" : "書式";
}

uint32_t nvme_auth_transform_key(const nvme_auth_key_t *k, const char *nqn, uint8_t *out) {
    if (k->hash == 0) {
        memcpy(out, k->key, k->len);
        return k->len;
    }
    crypto_hmac_ctx_t t;
    crypto_hmac_init(&t, (crypto_hash_id_t)k->hash, k->key, k->len);
    crypto_hmac_update(&t, nqn, strlen(nqn));
    crypto_hmac_update(&t, "NVMe-over-Fabrics", 17);
    crypto_hmac_final(&t, out);
    return (uint32_t)crypto_hash_len((crypto_hash_id_t)k->hash);
}

/* Ca = HMAC(hash, H(共有秘密), C)(Linux の nvme_auth_augmented_challenge())。
 * H は合意したハッシュそのもの。共有秘密は素数の長さに 0 詰めしたまま。 */
void nvme_auth_augment(uint8_t hashid, uint8_t dhgid, const uint8_t *skey, size_t skey_len,
                       const uint8_t *c, uint8_t *out) {
    const crypto_hash_id_t id = (crypto_hash_id_t)hashid;
    const size_t hl = crypto_hash_len(id);
    if (dhgid == 0) {
        memcpy(out, c, hl);
        return;
    }
    uint8_t hk[CRYPTO_HASH_MAX];
    crypto_hash(id, skey, skey_len, hk);
    crypto_hmac(id, hk, hl, c, hl, out);
    crypto_wipe(hk, sizeof(hk));
}

void nvme_auth_host_response(const nvme_auth_key_t *hostkey, uint8_t hashid, const uint8_t *ca1,
                             uint32_t s1, uint16_t tid, uint8_t sc_c, const char *hostnqn,
                             const char *subnqn, uint8_t *out) {
    uint8_t tkey[CRYPTO_HASH_MAX], b4[4];
    const uint32_t tlen = nvme_auth_transform_key(hostkey, hostnqn, tkey);
    const crypto_hash_id_t id = (crypto_hash_id_t)hashid;
    crypto_hmac_ctx_t h;
    crypto_hmac_init(&h, id, tkey, tlen);
    crypto_hmac_update(&h, ca1, crypto_hash_len(id));
    wr32(b4, s1);
    crypto_hmac_update(&h, b4, 4);
    wr16(b4, tid);
    crypto_hmac_update(&h, b4, 2);
    crypto_hmac_update(&h, &sc_c, 1);
    crypto_hmac_update(&h, "HostHost", 8);
    crypto_hmac_update(&h, hostnqn, strlen(hostnqn));
    b4[0] = 0;
    crypto_hmac_update(&h, b4, 1);
    crypto_hmac_update(&h, subnqn, strlen(subnqn));
    crypto_hmac_final(&h, out);
    crypto_wipe(tkey, sizeof(tkey));
}

/* **NQN の並びと区切りが R1 と逆**(subnqn が先)。取り違えないこと。 */
void nvme_auth_ctrl_response(const nvme_auth_key_t *ctrlkey, uint8_t hashid, const uint8_t *ca2,
                             uint32_t s2, uint16_t tid, const char *hostnqn, const char *subnqn,
                             uint8_t *out) {
    uint8_t tkey[CRYPTO_HASH_MAX], b4[4];
    const uint32_t tlen = nvme_auth_transform_key(ctrlkey, subnqn, tkey);
    const crypto_hash_id_t id = (crypto_hash_id_t)hashid;
    crypto_hmac_ctx_t h;
    crypto_hmac_init(&h, id, tkey, tlen);
    crypto_hmac_update(&h, ca2, crypto_hash_len(id));
    wr32(b4, s2);
    crypto_hmac_update(&h, b4, 4);
    wr16(b4, tid);
    crypto_hmac_update(&h, b4, 2);
    b4[0] = 0;
    crypto_hmac_update(&h, b4, 1);
    crypto_hmac_update(&h, "Controller", 10);
    crypto_hmac_update(&h, subnqn, strlen(subnqn));
    crypto_hmac_update(&h, b4, 1);
    crypto_hmac_update(&h, hostnqn, strlen(hostnqn));
    crypto_hmac_final(&h, out);
    crypto_wipe(tkey, sizeof(tkey));
}

/* ------------------------------------------------------------------ */
/* ホスト側                                                            */
/* ------------------------------------------------------------------ */

uint32_t nvme_auth_host_negotiate(nvme_auth_host_t *h, uint8_t *out) {
    /* struct nvmf_auth_dhchap_negotiate_data + protocol descriptor 1 個 = 72 バイト
     * (Linux の nvme_auth_set_dhchap_negotiate_data())。 */
    do {
        crypto_random(&h->tid, sizeof(h->tid));
    } while (h->tid == 0);
    memset(out, 0, 72);
    out[0] = NVME_AUTH_TYPE_COMMON;
    out[1] = NVME_AUTH_MSG_NEGOTIATE;
    wr16(out + 4, h->tid);
    out[6] = 0;                    /* SC_C: secure channel concatenation なし */
    out[7] = 1;                    /* napd */
    out[8] = NVME_AUTH_ID_DHCHAP;
    out[10] = 3;                   /* halen */
    out[11] = 6;                   /* dhlen */
    out[12] = CRYPTO_SHA256;
    out[13] = CRYPTO_SHA384;
    out[14] = CRYPTO_SHA512;
    for (unsigned i = 0; i < 6u; i++) out[12 + 30 + i] = (uint8_t)i;   /* NULL, ffdhe2048..8192 */
    return 72u;
}

uint32_t nvme_auth_host_reply(nvme_auth_host_t *h, const uint8_t *in, uint32_t inlen,
                              uint8_t *out, uint32_t cap, const char **why) {
    *why = "";
    if (inlen < 16u) { *why = "Challenge が短い"; return 0; }
    if (in[1] == NVME_AUTH_MSG_FAILURE1) {
        *why = "コントローラが Failure1 を返した";
        return 0;
    }
    if (in[0] != NVME_AUTH_TYPE_DHCHAP || in[1] != NVME_AUTH_MSG_CHALLENGE || rd16(in + 4) != h->tid) {
        *why = "Challenge でない / T_ID が違う";
        return 0;
    }
    const uint8_t hl = in[6], hashid = in[8], dhgid = in[9];
    const uint16_t dhvlen = rd16(in + 10);
    const uint32_t s1 = rd32(in + 12);
    if (hashid < 1 || hashid > 3 || hl != crypto_hash_len((crypto_hash_id_t)hashid)) {
        *why = "ハッシュが分からない";
        return 0;
    }
    const size_t plen = dhgid ? crypto_ffdhe_len(dhgid) : 0u;
    if (dhgid > 5 || dhvlen != plen || inlen < 16u + hl + dhvlen) {
        *why = "DH 群 / DH の値の長さが合わない";
        return 0;
    }
    if (cap < 16u + 2u * hl + plen) {
        *why = "Reply の置き場が足りない";
        return 0;
    }
    h->hashid = hashid;
    h->dhgid = dhgid;
    memset(out, 0, 16u + 2u * hl + plen);
    if (dhgid) {
        /* 自分の秘密の指数を作り、相手の公開値と合わせて共有秘密を作る。
         * 相手の値の検査(範囲と部分群)は crypto_ffdhe_shared() がやる。 */
        uint8_t priv[CRYPTO_FFDHE_PRIV_LEN];
        if (crypto_ffdhe_keygen(dhgid, priv, out + 16u + 2u * hl) != 0 ||
            crypto_ffdhe_shared(dhgid, priv, in + 16u + hl, dhvlen, h->skey) != 0) {
            crypto_wipe(priv, sizeof(priv));
            *why = "コントローラの DH 公開値が正しくない";
            return 0;
        }
        crypto_wipe(priv, sizeof(priv));
        h->skey_len = (uint32_t)plen;
    }
    uint8_t ca1[CRYPTO_HASH_MAX];
    nvme_auth_augment(hashid, dhgid, h->skey, h->skey_len, in + 16, ca1);
    nvme_auth_host_response(&h->host, hashid, ca1, s1, h->tid, 0, h->hostnqn, h->subnqn, out + 16);
    crypto_wipe(ca1, sizeof(ca1));
    out[0] = NVME_AUTH_TYPE_DHCHAP;
    out[1] = NVME_AUTH_MSG_REPLY;
    wr16(out + 4, h->tid);
    out[6] = hl;
    wr16(out + 10, (uint16_t)plen);
    if (h->ctrl.len) {
        /* 双方向: こちらからも C2 を出し、S2(0 以外)を付ける
         * (Linux の nvme_auth_set_dhchap_reply_data())。 */
        h->bidir = 1;
        crypto_random(h->c2, hl);
        do {
            crypto_random(&h->s2, sizeof(h->s2));
        } while (h->s2 == 0);
        out[8] = 1;   /* cvalid */
        memcpy(out + 16u + hl, h->c2, hl);
    } else {
        h->bidir = 0;
        h->s2 = 0;
    }
    wr32(out + 12, h->s2);
    return 16u + 2u * hl + (uint32_t)plen;
}

int nvme_auth_host_result(nvme_auth_host_t *h, const uint8_t *in, uint32_t inlen,
                          uint8_t *out, uint32_t *outlen, const char **why) {
    *outlen = 0;
    *why = "";
    if (inlen < 16u) { *why = "応答が短い"; return 0; }
    if (in[1] == NVME_AUTH_MSG_FAILURE1) {
        *why = "コントローラが Failure1 を返した(こちらの鍵が違う)";
        return 0;
    }
    if (in[0] != NVME_AUTH_TYPE_DHCHAP || in[1] != NVME_AUTH_MSG_SUCCESS1 || rd16(in + 4) != h->tid) {
        *why = "Success1 でない / T_ID が違う";
        return 0;
    }
    if (!h->bidir) return 1;
    /* 双方向: コントローラの応答 R2 を自分で計算して比べる。 */
    const size_t hl = crypto_hash_len((crypto_hash_id_t)h->hashid);
    uint8_t ca2[CRYPTO_HASH_MAX], r2[CRYPTO_HASH_MAX];
    nvme_auth_augment(h->hashid, h->dhgid, h->skey, h->skey_len, h->c2, ca2);
    nvme_auth_ctrl_response(&h->ctrl, h->hashid, ca2, h->s2, h->tid, h->hostnqn, h->subnqn, r2);
    const int ok = (in[8] == 1) && inlen >= 16u + hl && crypto_equal(r2, in + 16, hl);
    crypto_wipe(ca2, sizeof(ca2));
    crypto_wipe(r2, sizeof(r2));
    if (!ok) {
        /* Failure2(Linux の nvme_auth_set_dhchap_failure2_data())。 */
        memset(out, 0, 8);
        out[0] = NVME_AUTH_TYPE_COMMON;
        out[1] = NVME_AUTH_MSG_FAILURE2;
        wr16(out + 4, h->tid);
        out[6] = NVME_AUTH_FAIL_REASON;
        out[7] = NVME_AUTH_FAIL_FAILED;
        *outlen = 8;
        *why = "コントローラの応答が一致しない(コントローラの鍵が違う)";
        return 0;
    }
    memset(out, 0, 16);   /* Success2: type, id, rsvd, T_ID, rsvd[10] */
    out[0] = NVME_AUTH_TYPE_DHCHAP;
    out[1] = NVME_AUTH_MSG_SUCCESS2;
    wr16(out + 4, h->tid);
    *outlen = 16;
    return 1;
}

void nvme_auth_host_wipe(nvme_auth_host_t *h) {
    crypto_wipe(h->c2, sizeof(h->c2));
    crypto_wipe(h->skey, sizeof(h->skey));
    h->skey_len = 0;
}

/* ------------------------------------------------------------------ */

static nvme_auth_key_t s_host_key, s_ctrl_key;

const nvme_auth_key_t *nvme_auth_host_key(void) { return &s_host_key; }
const nvme_auth_key_t *nvme_auth_ctrl_key(void) { return &s_ctrl_key; }

void nvme_auth_host_shell(const char *args) {
    char buf[600];
    strncpy(buf, args ? args : "", sizeof(buf) - 1u);
    buf[sizeof(buf) - 1u] = 0;
    char *tok[3];
    unsigned nt = 0;
    char *save = 0;
    for (char *p = strtok_r(buf, " \t\r\n", &save); p && nt < 3u; p = strtok_r(0, " \t\r\n", &save)) {
        tok[nt++] = p;
    }
    if (nt == 1 && !strcmp(tok[0], "off")) {
        crypto_wipe(&s_host_key, sizeof(s_host_key));
        crypto_wipe(&s_ctrl_key, sizeof(s_ctrl_key));
    } else if (nt >= 1) {
        nvme_auth_key_t hk, ck;
        memset(&ck, 0, sizeof(ck));
        int r = nvme_auth_parse_secret(tok[0], &hk);
        if (r == 0 && nt >= 2) {
            r = strncmp(tok[1], "ctrl=", 5) ? -1 : nvme_auth_parse_secret(tok[1] + 5, &ck);
        }
        if (r != 0) {
            uart_printf("nvmeauth: 鍵の形式が正しくない(%s)\n"
                        "使い方: nvmeauth <ホストの鍵 DHHC-1:..> [ctrl=<コントローラの鍵>] / nvmeauth off\n",
                        nvme_auth_parse_error(r));
            return;
        }
        s_host_key = hk;
        s_ctrl_key = ck;
        crypto_wipe(&hk, sizeof(hk));
        crypto_wipe(&ck, sizeof(ck));
    }
    if (s_host_key.len == 0) {
        uart_printf("nvmeauth: イニシエータの鍵なし(相手が認証を求めたら接続に失敗する)\n");
    } else {
        uart_printf("nvmeauth: 相手が認証を求めたら DH-HMAC-CHAP で答える(ホストの鍵 %u バイト・変換 %u、%s)\n",
                    s_host_key.len, s_host_key.hash,
                    s_ctrl_key.len ? "コントローラの鍵あり = 双方向を求める" : "片方向");
    }
}
