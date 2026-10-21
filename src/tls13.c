/* TLS 1.3 のサーバ側(PLAN_auth_tls.md 段階 D)とクライアント側(段階 F)。仕様は tls13.h の冒頭。
 *
 * 鍵の予定表は RFC 8446 7.1、レコード層は 5.2〜5.3、HelloRetryRequest は 4.1.4 と 4.4.1。
 * NVMe/TCP の PSK の導出は libnvme の src/nvme/linux.c(derive_retained_key /
 * derive_psk_digest / gen_tls_identity / derive_tls_key)から写した。写しが正しいことは
 * tools/tls_psk_check.py が Linux(tlshd)の実データで確かめてある。
 *
 * **CNSA 2.0(PLAN_cnsa2.md 段階 2)**: 握手のハッシュと鍵の長さは PSK で決まる
 * (t->hid / t->hl。SHA-384 の PSK なら TLS_AES_256_GCM_SHA384)。鍵共有は x25519 か
 * ML-KEM-1024(draft-ietf-tls-mlkem: クライアントの key_share がカプセル化鍵 1568 バイト、
 * サーバの key_share が暗号文 1568 バイト、共有秘密 32 バイトを (EC)DHE の入力にする)。
 */
#include "tls13.h"

#include <stdio.h>
#include <string.h>

#define HMAX TLS13_HASH_MAX

enum {
    CT_CCS = 20, CT_ALERT = 21, CT_HANDSHAKE = 22, CT_APPDATA = 23,
    HS_CLIENT_HELLO = 1, HS_SERVER_HELLO = 2, HS_NEW_SESSION_TICKET = 4,
    HS_ENCRYPTED_EXTENSIONS = 8, HS_FINISHED = 20, HS_KEY_UPDATE = 24, HS_MESSAGE_HASH = 254,
    EXT_SUPPORTED_GROUPS = 10, EXT_PRE_SHARED_KEY = 41, EXT_EARLY_DATA = 42,
    EXT_SUPPORTED_VERSIONS = 43, EXT_COOKIE = 44, EXT_PSK_KEX_MODES = 45, EXT_KEY_SHARE = 51,
    GROUP_X25519 = 0x001D, GROUP_MLKEM1024 = 0x0202,
    SUITE_AES128_GCM_SHA256 = 0x1301, SUITE_AES256_GCM_SHA384 = 0x1302,
};

/* SHA-256("HelloRetryRequest")(RFC 8446 4.1.3)。HelloRetryRequest の ServerHello.random */
static const uint8_t HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd24(const uint8_t *p) { return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2]; }
static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr24(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }

const char *tls13_alert_name(uint8_t d) {
    switch (d) {
    case TLS13_ALERT_CLOSE_NOTIFY: return "close_notify";
    case TLS13_ALERT_UNEXPECTED_MESSAGE: return "unexpected_message";
    case TLS13_ALERT_BAD_RECORD_MAC: return "bad_record_mac";
    case TLS13_ALERT_RECORD_OVERFLOW: return "record_overflow";
    case TLS13_ALERT_HANDSHAKE_FAILURE: return "handshake_failure";
    case TLS13_ALERT_ILLEGAL_PARAMETER: return "illegal_parameter";
    case TLS13_ALERT_DECODE_ERROR: return "decode_error";
    case TLS13_ALERT_DECRYPT_ERROR: return "decrypt_error";
    case TLS13_ALERT_PROTOCOL_VERSION: return "protocol_version";
    case TLS13_ALERT_INTERNAL_ERROR: return "internal_error";
    case TLS13_ALERT_MISSING_EXTENSION: return "missing_extension";
    case TLS13_ALERT_UNSUPPORTED_EXTENSION: return "unsupported_extension";
    case TLS13_ALERT_UNKNOWN_PSK_IDENTITY: return "unknown_psk_identity";
    default: return "?";
    }
}

const char *tls13_suite_name(uint16_t s) {
    return s == SUITE_AES256_GCM_SHA384 ? "TLS_AES_256_GCM_SHA384"
         : s == SUITE_AES128_GCM_SHA256 ? "TLS_AES_128_GCM_SHA256" : "?";
}

const char *tls13_group_name(uint16_t g) {
    return g == GROUP_MLKEM1024 ? "MLKEM1024" : g == GROUP_X25519 ? "x25519" : "?";
}

static crypto_hash_id_t psk_hash(const tls13_psk_t *p) {
    return p->hash == CRYPTO_SHA384 ? CRYPTO_SHA384 : CRYPTO_SHA256;
}

static void set_hash(tls13_t *t, crypto_hash_id_t h) {
    t->hid = h;
    t->hl = (unsigned)crypto_hash_len(h);
    t->suite = (h == CRYPTO_SHA384) ? SUITE_AES256_GCM_SHA384 : SUITE_AES128_GCM_SHA256;
}

/* 使ってよい群。CNSA 2.0 専用なら ML-KEM-1024 だけ。 */
static unsigned allowed_groups(const tls13_t *t) {
    if (t->cnsa) return TLS13_GROUP_MLKEM1024;
    if (t->groups) return t->groups;
    return t->is_client ? TLS13_GROUP_X25519 : (TLS13_GROUP_X25519 | TLS13_GROUP_MLKEM1024);
}

static unsigned group_bit(uint16_t g) {
    return g == GROUP_X25519 ? TLS13_GROUP_X25519 : g == GROUP_MLKEM1024 ? TLS13_GROUP_MLKEM1024 : 0u;
}

/* ---- 鍵の予定表(RFC 8446 7.1)---- */
static void xlabel(crypto_hash_id_t h, const uint8_t *secret, const char *label, const void *ctx, size_t clen,
                   uint8_t *out, size_t olen) {
    crypto_hkdf_expand_label(h, secret, crypto_hash_len(h), label, ctx, clen, out, olen);
}

static void expand_label(const tls13_t *t, const uint8_t *secret, const char *label, const void *ctx, size_t clen,
                         uint8_t *out, size_t olen) {
    xlabel(t->hid, secret, label, ctx, clen, out, olen);
}

static void derive_secret(const tls13_t *t, const uint8_t *secret, const char *label, const uint8_t *th, uint8_t *out) {
    expand_label(t, secret, label, th, t->hl, out, t->hl);
}

static void empty_hash(const tls13_t *t, uint8_t *out) { crypto_hash(t->hid, "", 0, out); }

static void transcript(const tls13_t *t, uint8_t *out) {
    crypto_hash_ctx_t c = t->th;   /* 途中の値を取り出す(本体は続ける)*/
    crypto_hash_final(&c, out);
}

static void dir_install(const tls13_t *t, tls13_dir_t *d, const uint8_t *secret) {
    uint8_t key[32];
    const size_t kl = (t->hid == CRYPTO_SHA384) ? 32u : 16u;   /* AES-256 / AES-128 */
    memcpy(d->secret, secret, t->hl);
    expand_label(t, secret, "key", NULL, 0, key, kl);
    expand_label(t, secret, "iv", NULL, 0, d->iv, 12);
    crypto_aesgcm_init(&d->aead, key, kl);
    crypto_wipe(key, sizeof(key));
    d->seq = 0;
    d->on = 1;
    d->epoch++;
}

static void nonce(const tls13_dir_t *d, uint8_t n[12]) {
    memcpy(n, d->iv, 12);
    for (int i = 0; i < 8; i++) n[11 - i] ^= (uint8_t)(d->seq >> (8 * i));
}

static void keylog(tls13_t *t, const char *label, const uint8_t *secret) {
    if (!t->keylog) return;
    char line[200];   /* 最長のラベル 31 文字 + 64 + 96 + 区切り */
    int n = snprintf(line, sizeof(line), "%s ", label);
    for (int i = 0; i < 32; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", t->crandom[i]);
    n += snprintf(line + n, sizeof(line) - (size_t)n, " ");
    for (unsigned i = 0; i < t->hl; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", secret[i]);
    t->keylog(t->keylog_arg, line);
}

/* HelloRetryRequest の後の transcript(RFC 8446 4.4.1): 1 回目の ClientHello を
 * message_hash(254, 長さ, Hash(CH1))に置き換え、HelloRetryRequest を続ける。 */
static void transcript_hrr(tls13_t *t, const uint8_t *ch1_hash, const uint8_t *hrr, size_t hrrlen) {
    uint8_t mh[4 + HMAX];
    mh[0] = HS_MESSAGE_HASH;
    wr24(mh + 1, t->hl);
    memcpy(mh + 4, ch1_hash, t->hl);
    crypto_hash_init(&t->th, t->hid);
    crypto_hash_update(&t->th, mh, 4u + t->hl);
    crypto_hash_update(&t->th, hrr, hrrlen);
}

/* binder = HMAC(finished_key(binder_key), Transcript-Hash(... || ClientHello の binder のリストより前))。
 * HelloRetryRequest の後は transcript(message_hash + HRR)の続きに切り詰めた CH2 を足す。 */
static void binder_value(const tls13_t *t, const uint8_t *early, const uint8_t *ch, size_t trunc, uint8_t *out) {
    uint8_t bkey[HMAX], fkey[HMAX], h[HMAX], eh[HMAX];
    empty_hash(t, eh);
    derive_secret(t, early, t->test_resumption ? "res binder" : "ext binder", eh, bkey);
    expand_label(t, bkey, "finished", NULL, 0, fkey, t->hl);
    crypto_hash_ctx_t c;
    if (t->hrr) c = t->th;
    else crypto_hash_init(&c, t->hid);
    crypto_hash_update(&c, ch, trunc);
    crypto_hash_final(&c, h);
    crypto_hmac(t->hid, fkey, t->hl, h, t->hl, out);
    crypto_wipe(bkey, sizeof(bkey));
    crypto_wipe(fkey, sizeof(fkey));
}

/* ---- レコードを書く ---- */
typedef struct {
    uint8_t *p;
    size_t cap, len;
    int over;
} obuf_t;

static uint8_t *ob_take(obuf_t *o, size_t n) {
    if (o->len + n > o->cap) {
        o->over = 1;
        return NULL;
    }
    uint8_t *r = o->p + o->len;
    o->len += n;
    return r;
}

static void put_plain(obuf_t *o, uint8_t type, const uint8_t *data, size_t n) {
    uint8_t *r = ob_take(o, 5u + n);
    if (!r) return;
    r[0] = type; r[1] = 3; r[2] = 3;
    wr16(r + 3, (unsigned)n);
    memcpy(r + 5, data, n);
}

static void put_ccs(obuf_t *o) {
    static const uint8_t one = 1;
    put_plain(o, CT_CCS, &one, 1);
}

/* TLSInnerPlaintext = data || type を暗号化して 1 レコード(詰め物なし)。 */
static size_t seal_record(tls13_dir_t *d, uint8_t type, const uint8_t *data, size_t n, uint8_t *r) {
    const size_t clen = n + 1u + 16u;
    r[0] = CT_APPDATA; r[1] = 3; r[2] = 3;
    wr16(r + 3, (unsigned)clen);
    memmove(r + 5, data, n);
    r[5 + n] = type;
    uint8_t iv[12];
    nonce(d, iv);
    crypto_aesgcm_seal(&d->aead, iv, r, 5, r + 5, n + 1u, r + 5, r + 5 + n + 1u);
    d->seq++;
    return 5u + clen;
}

static void put_enc(obuf_t *o, tls13_dir_t *d, uint8_t type, const uint8_t *data, size_t n) {
    uint8_t *r = ob_take(o, 5u + n + 1u + 16u);
    if (!r) return;
    seal_record(d, type, data, n, r);
}

static int fail(tls13_t *t, obuf_t *o, uint8_t desc, const char *why) {
    if (t->state == TLS13_ST_FAILED) return -1;
    const uint8_t a[2] = { 2, desc };   /* fatal */
    if (t->tx.on) put_enc(o, &t->tx, CT_ALERT, a, 2);
    else put_plain(o, CT_ALERT, a, 2);
    t->alert_sent = desc;
    t->why = why;
    t->state = TLS13_ST_FAILED;
    return -1;
}

/* ---- NVMe/TCP の PSK ---- */
int tls13_nvme_psk(tls13_psk_t out[2], const char *keystr, const char *hostnqn,
                   const char *subnqn, const char **why) {
    static const char pre[] = "NVMeTLSkey-1:";
    const char *dummy;
    if (!why) why = &dummy;
    const size_t kl = strlen(keystr);
    if (kl < sizeof(pre) - 1u + 4u || memcmp(keystr, pre, sizeof(pre) - 1u) != 0) {
        *why = "NVMeTLSkey-1: で始まっていない";
        return -1;
    }
    const char *p = keystr + sizeof(pre) - 1u;
    if (p[2] != ':' || keystr[kl - 1] != ':') {
        *why = "形式が NVMeTLSkey-1:hh:<base64>: でない";
        return -1;
    }
    const unsigned hh = (unsigned)((p[0] - '0') * 10 + (p[1] - '0'));
    uint8_t raw[48 + 4];
    const int n = crypto_base64_decode(p + 3, (size_t)(keystr + kl - 1 - (p + 3)), raw, sizeof(raw));
    if (n != 32 + 4 && n != 48 + 4) {
        *why = "鍵が 32 / 48 バイトでない";
        return -1;
    }
    const unsigned klen = (unsigned)n - 4u;
    const uint32_t crc = (uint32_t)raw[klen] | ((uint32_t)raw[klen + 1] << 8) | ((uint32_t)raw[klen + 2] << 16) |
                         ((uint32_t)raw[klen + 3] << 24);
    if (crypto_crc32(raw, klen) != crc) {
        *why = "鍵の CRC-32 が合わない";
        return -1;
    }
    if (hh > 2u || (hh == 1u && klen != 32u) || (hh == 2u && klen != 48u)) {
        *why = "変換のハッシュ(00 / 01 = SHA-256 / 02 = SHA-384)と鍵の長さが合わない";
        return -1;
    }
    /* 暗号スイートのハッシュ(libnvme の cipher): 変換なしなら鍵の長さで決まる */
    const crypto_hash_id_t h = (klen == 48u) ? CRYPTO_SHA384 : CRYPTO_SHA256;
    const unsigned cipher = (h == CRYPTO_SHA384) ? 2u : 1u;
    /* 1. retained PSK(hh=00 なら設定鍵そのまま)*/
    uint8_t prk[HMAX], retained[HMAX];
    if (hh == 0u) {
        memcpy(retained, raw, klen);
    } else {
        crypto_hkdf_extract(h, NULL, 0, raw, klen, prk);
        xlabel(h, prk, "HostNQN", hostnqn, strlen(hostnqn), retained, klen);
    }
    /* 2. 身元の digest = base64(HMAC(retained, host " " sub " NVMe-over-Fabrics")) */
    crypto_hmac_ctx_t m;
    uint8_t dig[HMAX];
    crypto_hmac_init(&m, h, retained, klen);
    crypto_hmac_update(&m, hostnqn, strlen(hostnqn));
    crypto_hmac_update(&m, " ", 1);
    crypto_hmac_update(&m, subnqn, strlen(subnqn));
    crypto_hmac_update(&m, " NVMe-over-Fabrics", 18);
    crypto_hmac_final(&m, dig);
    char b64[80];
    crypto_base64_encode(dig, klen, b64);

    crypto_hkdf_extract(h, NULL, 0, retained, klen, prk);
    for (int v = 0; v < 2; v++) {
        tls13_psk_t *o = &out[v];
        const int w = (v == 0)
            ? snprintf(o->identity, sizeof(o->identity), "NVMe1R%02u %s %s %s", cipher, hostnqn, subnqn, b64)
            : snprintf(o->identity, sizeof(o->identity), "NVMe0R%02u %s %s", cipher, hostnqn, subnqn);
        if (w <= 0 || (size_t)w >= sizeof(o->identity)) {
            *why = "NQN が長すぎる";
            return -1;
        }
        o->identity_len = (uint16_t)w;
        o->hash = (uint8_t)h;
        /* 3. TLS PSK = HKDF-Expand-Label(Extract(0, retained), "nvme-tls-psk", 文脈, 鍵の長さ)
         *    文脈は版 1 なら "hh " + digest、版 0 なら身元そのもの。 */
        char ctx[100];
        const char *c = o->identity;
        size_t cl = (size_t)w;
        if (v == 0) {
            cl = (size_t)snprintf(ctx, sizeof(ctx), "%02u %s", cipher, b64);
            c = ctx;
        }
        xlabel(h, prk, "nvme-tls-psk", c, cl, o->psk, klen);
    }
    crypto_wipe(prk, sizeof(prk));
    crypto_wipe(retained, sizeof(retained));
    crypto_wipe(raw, sizeof(raw));
    return 2;
}

int tls13_nvme_generated_psk(tls13_psk_t *out, const uint8_t *psk, size_t len,
                             const char *hostnqn, const char *subnqn) {
    if (len != 32u) return -1;
    /* digest = base64(HMAC(PSK, host " " sub " NVMe-over-Fabrics"))(設定鍵の版 1 と同じ式で、
     * retained PSK の代わりに生成した PSK を使う)*/
    crypto_hmac_ctx_t m;
    uint8_t dig[32], prk[32];
    crypto_hmac_init(&m, CRYPTO_SHA256, psk, 32);
    crypto_hmac_update(&m, hostnqn, strlen(hostnqn));
    crypto_hmac_update(&m, " ", 1);
    crypto_hmac_update(&m, subnqn, strlen(subnqn));
    crypto_hmac_update(&m, " NVMe-over-Fabrics", 18);
    crypto_hmac_final(&m, dig);
    char b64[64], ctx[80];
    crypto_base64_encode(dig, 32, b64);
    const int w = snprintf(out->identity, sizeof(out->identity), "NVMe1G01 %s %s %s", hostnqn, subnqn, b64);
    if (w <= 0 || (size_t)w >= sizeof(out->identity)) return -1;
    out->identity_len = (uint16_t)w;
    out->hash = CRYPTO_SHA256;
    const int cl = snprintf(ctx, sizeof(ctx), "01 %s", b64);
    crypto_hkdf_extract(CRYPTO_SHA256, NULL, 0, psk, 32, prk);
    xlabel(CRYPTO_SHA256, prk, "nvme-tls-psk", ctx, (size_t)cl, out->psk, 32);
    crypto_wipe(prk, sizeof(prk));
    return 0;
}

void tls13_server_init(tls13_t *t, const tls13_psk_t *psks, unsigned npsk) {
    memset(t, 0, sizeof(*t));
    t->psks = psks;
    t->npsk = npsk;
    t->psk_index = -1;
    t->alert_sent = 0xFF;
    t->alert_recv = 0xFF;
    set_hash(t, CRYPTO_SHA256);   /* PSK を選んだら決め直す */
}

/* ---- ClientHello ---- */

/* key_share のリスト(ClientShare)から、使ってよい群の公開値を好みの順(ML-KEM-1024 が先)で選ぶ。
 * 長さが群の決まりと違うものは選ばない。 */
static const uint8_t *pick_share(const uint8_t *ks, size_t kslen, unsigned allow, uint16_t *grp) {
    static const uint16_t pref[2] = { GROUP_MLKEM1024, GROUP_X25519 };
    for (unsigned pi = 0; pi < 2; pi++) {
        if (!(allow & group_bit(pref[pi]))) continue;
        const uint16_t want_len = pref[pi] == GROUP_MLKEM1024 ? CRYPTO_MLKEM1024_EK_LEN : 32u;
        for (const uint8_t *q = ks; q + 4 <= ks + kslen;) {
            const uint16_t g = rd16(q), kl = rd16(q + 2);
            if (q + 4 + kl > ks + kslen) break;
            if (g == pref[pi] && kl == want_len) {
                *grp = g;
                return q + 4;
            }
            q += 4 + kl;
        }
    }
    return NULL;
}

/* HelloRetryRequest を送る(1 回目の ClientHello に使える key_share が無く、supported_groups には
 * 使える群がある場合)。transcript は CH1 を message_hash に置き換えて HRR を続けた形にする。 */
static int send_hrr(tls13_t *t, const uint8_t *msg, size_t mlen, const uint8_t *sid, uint8_t sidlen, uint16_t want,
                    obuf_t *o) {
    uint8_t h1[HMAX];
    crypto_hash(t->hid, msg, mlen, h1);
    uint8_t hr[128];
    size_t n = 0;
    hr[n++] = HS_SERVER_HELLO;
    n += 3;
    hr[n++] = 3; hr[n++] = 3;
    memcpy(hr + n, HRR_RANDOM, 32); n += 32;
    hr[n++] = sidlen;
    memcpy(hr + n, sid, sidlen); n += sidlen;
    wr16(hr + n, t->suite); n += 2;
    hr[n++] = 0;
    const size_t extpos = n;
    n += 2;
    wr16(hr + n, EXT_SUPPORTED_VERSIONS); wr16(hr + n + 2, 2); wr16(hr + n + 4, 0x0304); n += 6;
    wr16(hr + n, EXT_KEY_SHARE); wr16(hr + n + 2, 2); wr16(hr + n + 4, want); n += 6;   /* selected_group */
    wr16(hr + extpos, (unsigned)(n - extpos - 2));
    wr24(hr + 1, (unsigned)(n - 4));
    transcript_hrr(t, h1, hr, n);
    put_plain(o, CT_HANDSHAKE, hr, n);
    if (sidlen) put_ccs(o);   /* 互換モード: 最初の握手メッセージの直後に CCS(RFC 8446 D.4)*/
    memcpy(t->sid, sid, sidlen);
    t->sidlen = sidlen;
    t->group = want;
    t->hrr = 1;
    return o->over ? fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "送信バッファが足りない") : 0;
}

static int on_client_hello(tls13_t *t, const uint8_t *msg, size_t mlen, obuf_t *o) {
    const uint8_t *p = msg + 4, *end = msg + mlen;
#define NEED(n) do { if ((size_t)(end - p) < (size_t)(n)) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "ClientHello が短い"); } while (0)
    NEED(2 + 32 + 1);
    p += 2;   /* legacy_version(supported_versions で見る)*/
    memcpy(t->crandom, p, 32);
    p += 32;
    const uint8_t sidlen = *p++;
    if (sidlen > 32) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "session_id が長い");
    NEED(sidlen);
    const uint8_t *sid = p;
    p += sidlen;
    if (t->hrr && (sidlen != t->sidlen || memcmp(sid, t->sid, sidlen) != 0))
        return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "2 回目の ClientHello のセッション ID が違う");
    NEED(2);
    const uint16_t cslen = rd16(p);
    p += 2;
    NEED(cslen);
    int have128 = 0, have256 = 0;
    for (unsigned i = 0; i + 1u < cslen; i += 2) {
        have128 |= (rd16(p + i) == SUITE_AES128_GCM_SHA256);
        have256 |= (rd16(p + i) == SUITE_AES256_GCM_SHA384);
    }
    p += cslen;
    NEED(1);
    const uint8_t cmlen = *p++;
    NEED(cmlen);
    const uint8_t *cm = p;
    p += cmlen;
    NEED(2);
    const uint16_t extlen = rd16(p);
    p += 2;
    if ((size_t)(end - p) != extlen) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "拡張の長さが合わない");

    int v13 = 0, dhe = 0, kexm = 0, early_ext = 0;
    const uint8_t *ks = NULL, *sg = NULL, *psk_ext = NULL;
    size_t kslen = 0, sglen = 0, psk_len = 0;
    while (p < end) {
        NEED(4);
        const uint16_t et = rd16(p), el = rd16(p + 2);
        p += 4;
        NEED(el);
        const uint8_t *e = p;
        p += el;
        switch (et) {
        case EXT_SUPPORTED_VERSIONS:
            for (unsigned i = 1; el >= 1 && i + 1u <= e[0] && i + 1u < el; i += 2) v13 |= (rd16(e + i) == 0x0304);
            break;
        case EXT_PSK_KEX_MODES:
            kexm = 1;
            for (unsigned i = 1; el >= 1 && i <= e[0] && i < el; i++) dhe |= (e[i] == 1);
            break;
        case EXT_EARLY_DATA:
            early_ext = 1;
            break;
        case EXT_KEY_SHARE:
            if (el < 2 || 2u + rd16(e) > el) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "key_share の長さ");
            ks = e + 2;
            kslen = rd16(e);
            break;
        case EXT_SUPPORTED_GROUPS:
            if (el < 2 || 2u + rd16(e) > el) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "supported_groups の長さ");
            sg = e + 2;
            sglen = rd16(e);
            break;
        case EXT_PRE_SHARED_KEY:
            if (p != end) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "pre_shared_key が最後の拡張でない");
            psk_ext = e;
            psk_len = el;
            break;
        default:
            break;   /* 知らない拡張は読み飛ばす */
        }
    }
    if (!v13) return fail(t, o, TLS13_ALERT_PROTOCOL_VERSION, "TLS 1.3 を出していない");
    /* RFC 8446 4.1.2: TLS 1.3 の ClientHello の legacy_compression_methods は「0 が 1 バイト」ちょうど。
     * それ以外は illegal_parameter で断る(MUST)。以前は長さだけ読み飛ばしていた。 */
    if (cmlen != 1 || cm[0] != 0)
        return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "legacy_compression_methods が 0 の 1 バイトでない");
    if (!psk_ext) return fail(t, o, TLS13_ALERT_MISSING_EXTENSION, "pre_shared_key が無い(証明書は使えない)");
    /* 4.2.9: pre_shared_key を出して psk_key_exchange_modes を出さないクライアントは断る(MUST)。
     * 9.2 の決まりで alert は missing_extension(以前は psk_dhe_ke が無いのと同じ handshake_failure)。 */
    if (!kexm) return fail(t, o, TLS13_ALERT_MISSING_EXTENSION, "psk_key_exchange_modes が無い");
    if (!dhe) return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE, "psk_dhe_ke を出していない");
    /* 9.2: supported_groups と key_share は両方あるか両方無いか。片方だけなら missing_extension。
     * 以前は supported_groups だけのときに HelloRetryRequest で key_share を求め直していた。 */
    if ((sg != NULL) != (ks != NULL))
        return fail(t, o, TLS13_ALERT_MISSING_EXTENSION, "supported_groups と key_share の片方しか無い");
    /* early_data(4.2.10): 0-RTT は受け付けない(EncryptedExtensions に early_data を返さない)。
     * 相手は早期データを送ってくるので、max_early_data_size までは読み飛ばす(on_record())。
     * HelloRetryRequest の後の ClientHello に early_data を付けてはいけない(4.1.2)。 */
    if (early_ext) {
        if (t->hrr) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "2 回目の ClientHello に early_data");
        t->early_offered = 1;
        t->early_left = TLS13_EARLY_SKIP_MAX;
    } else if (t->hrr) {
        t->early_left = 0;   /* 2 回目の ClientHello の後は早期データが来ない(握手の鍵で開けるはず)*/
    }

    /* pre_shared_key: 識別子のリスト → binder のリスト。PSK のハッシュの暗号スイートを相手が出していて、
     * (CNSA 2.0 専用なら)SHA-384 のものだけを選ぶ。HRR の後は 1 回目と同じハッシュに限る。 */
    if (psk_len < 2) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "pre_shared_key の長さ");
    const uint8_t *q = psk_ext + 2, *ids_end = psk_ext + 2 + rd16(psk_ext);
    if (ids_end + 2 > psk_ext + psk_len) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "pre_shared_key の長さ");
    int chosen = -1, known = 0;
    unsigned idx = 0, sel = 0;
    while (q + 2 <= ids_end) {
        const uint16_t il = rd16(q);
        if (q + 2 + il + 4 > ids_end) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "PSK 身元の長さ");
        for (unsigned k = 0; k < t->npsk && chosen < 0; k++) {
            const int match = t->test_resumption ||
                              (t->psks[k].identity_len == il && memcmp(t->psks[k].identity, q + 2, il) == 0);
            if (!match) continue;
            known = 1;
            const crypto_hash_id_t h = psk_hash(&t->psks[k]);
            if (t->cnsa && h != CRYPTO_SHA384) continue;
            if (!(h == CRYPTO_SHA384 ? have256 : have128)) continue;
            if (t->hrr && h != t->hid) continue;
            chosen = (int)k;
            sel = idx;
        }
        q += 2 + il + 4;
        idx++;
    }
    if (chosen < 0) {
        if (!known) return fail(t, o, TLS13_ALERT_UNKNOWN_PSK_IDENTITY, "知らない PSK の身元");
        return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE,
                    t->cnsa ? "CNSA 2.0 専用: SHA-384 の PSK と TLS_AES_256_GCM_SHA384 の組が無い"
                            : "PSK のハッシュに合う暗号スイートを出していない");
    }
    set_hash(t, psk_hash(&t->psks[chosen]));

    /* 鍵共有: 使える群の key_share が無ければ HelloRetryRequest で求め直す(1 回だけ)*/
    const unsigned allow = allowed_groups(t);
    uint16_t grp = 0;
    const uint8_t *share = ks ? pick_share(ks, kslen, allow, &grp) : NULL;
    if (!share) {
        if (t->hrr) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "2 回目の ClientHello に求めた群の key_share が無い");
        uint16_t want = 0;
        for (unsigned pass = 0; pass < 2 && !want; pass++) {   /* ML-KEM-1024 を先に */
            const uint16_t g = pass == 0 ? GROUP_MLKEM1024 : GROUP_X25519;
            if (!(allow & group_bit(g))) continue;
            for (size_t i = 0; sg && i + 1u < sglen; i += 2) if (rd16(sg + i) == g) want = g;
        }
        if (!want)
            return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE,
                        t->cnsa ? "CNSA 2.0 専用: 相手が MLKEM1024 を出していない" : "使える鍵共有の群が無い");
        return send_hrr(t, msg, mlen, sid, sidlen, want, o);
    }
    if (t->hrr && grp != t->group) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "求めた群と違う key_share");

    /* binder: 選んだ身元と同じ位置のもの */
    const uint8_t *binders = ids_end;   /* 2 バイトの長さから */
    const uint8_t *b = binders + 2, *bend = binders + 2 + rd16(binders);
    if (bend != psk_ext + psk_len) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "binder のリストの長さ");
    for (unsigned i = 0; i < sel && b < bend; i++) b += 1 + b[0];
    if (b >= bend || b + 1 + b[0] > bend) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "binder が無い");
    /* binder の長さは PSK のハッシュの長さ(RFC 8446 4.2.11)。Ubuntu の tlshd(ktls-utils 1.3.0)は
     * SHA-384 の PSK(NVMe1R02)でも SHA-256 の 32 バイトの binder を付けてくる(PLAN_cnsa2.md 段階 2)。 */
    if (b[0] != t->hl)
        return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER,
                    t->hl == 48u ? "binder が 48 バイトでない(相手は SHA-384 の PSK を別のハッシュで扱っている)"
                                 : "binder が 32 バイトでない(相手は SHA-256 の PSK を別のハッシュで扱っている)");

    const tls13_psk_t *ps = &t->psks[chosen];
    uint8_t early[HMAX], want[HMAX], eh[HMAX];
    crypto_hkdf_extract(t->hid, NULL, 0, ps->psk, t->hl, early);
    empty_hash(t, eh);
    binder_value(t, early, msg, (size_t)(binders - msg), want);
    if (!crypto_equal(want, b + 1, t->hl)) return fail(t, o, TLS13_ALERT_DECRYPT_ERROR, "binder が合わない(PSK が違う)");
    t->psk_index = chosen;
    t->selected_identity = (uint16_t)sel;
    if (!t->hrr) crypto_hash_init(&t->th, t->hid);
    crypto_hash_update(&t->th, msg, mlen);

    /* 鍵共有: x25519 なら公開値、ML-KEM-1024 なら相手のカプセル化鍵でカプセル化した暗号文を返す */
    static const uint8_t base[32] = { 9 };
    uint8_t priv[32], spub[CRYPTO_MLKEM1024_CT_LEN], shared[32];
    size_t spublen;
    if (grp == GROUP_X25519) {
        if (t->test_priv) memcpy(priv, t->test_priv, 32);
        else if (crypto_random(priv, 32) != 0) return fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "乱数が取れない");
        crypto_x25519(spub, priv, base);
        spublen = 32;
        if (crypto_x25519(shared, priv, share) != 0) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "x25519 の公開値が小位数の点");
        crypto_wipe(priv, sizeof(priv));
    } else {
        if (crypto_mlkem1024_encaps(share, spub, shared) != 0)
            return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "ML-KEM-1024 のカプセル化鍵が不正(係数が q 以上)");
        spublen = CRYPTO_MLKEM1024_CT_LEN;
    }
    t->group = grp;

    /* ServerHello(拡張の並びは RFC 8448 と同じ: pre_shared_key, key_share, supported_versions)*/
    uint8_t sh[128 + CRYPTO_MLKEM1024_CT_LEN];
    size_t n = 0;
    sh[n++] = HS_SERVER_HELLO;
    n += 3;
    sh[n++] = 3; sh[n++] = 3;
    if (t->test_random) memcpy(sh + n, t->test_random, 32);
    else if (crypto_random(sh + n, 32) != 0) return fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "乱数が取れない");
    n += 32;
    sh[n++] = sidlen;
    memcpy(sh + n, sid, sidlen);
    n += sidlen;
    wr16(sh + n, t->suite); n += 2;
    sh[n++] = 0;
    const size_t extpos = n;
    n += 2;
    wr16(sh + n, EXT_PRE_SHARED_KEY); wr16(sh + n + 2, 2); wr16(sh + n + 4, sel); n += 6;
    wr16(sh + n, EXT_KEY_SHARE); wr16(sh + n + 2, (unsigned)(4 + spublen)); wr16(sh + n + 4, grp);
    wr16(sh + n + 6, (unsigned)spublen);
    memcpy(sh + n + 8, spub, spublen); n += 8 + spublen;
    wr16(sh + n, EXT_SUPPORTED_VERSIONS); wr16(sh + n + 2, 2); wr16(sh + n + 4, 0x0304); n += 6;
    wr16(sh + extpos, (unsigned)(n - extpos - 2));
    wr24(sh + 1, (unsigned)(n - 4));
    crypto_hash_update(&t->th, sh, n);
    put_plain(o, CT_HANDSHAKE, sh, n);
    /* セッション ID を返す互換モードなら ChangeCipherSpec を 1 個挟む(RFC 8446 D.4。
     * GnuTLS もそうしている)。HelloRetryRequest の直後に送っていれば 2 回目は要らない。 */
    if (sidlen && !t->hrr) put_ccs(o);

    /* 握手の秘密 */
    uint8_t derived[HMAX], hs[HMAX], th1[HMAX];
    derive_secret(t, early, "derived", eh, derived);
    crypto_hkdf_extract(t->hid, derived, t->hl, shared, 32, hs);
    transcript(t, th1);
    derive_secret(t, hs, "c hs traffic", th1, t->c_hs);
    derive_secret(t, hs, "s hs traffic", th1, t->s_hs);
    derive_secret(t, hs, "derived", eh, derived);
    static const uint8_t zero[HMAX];
    crypto_hkdf_extract(t->hid, derived, t->hl, zero, t->hl, t->master);
    keylog(t, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", t->c_hs);
    keylog(t, "SERVER_HANDSHAKE_TRAFFIC_SECRET", t->s_hs);
    dir_install(t, &t->tx, t->s_hs);
    dir_install(t, &t->rx, t->c_hs);

    /* EncryptedExtensions(空)+ Finished を 1 レコードで */
    uint8_t fl[256];
    size_t fn = 0;
    if (t->test_ee) {
        memcpy(fl, t->test_ee, t->test_ee_len);
        fn = t->test_ee_len;
    } else {
        static const uint8_t ee[6] = { HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0 };
        memcpy(fl, ee, sizeof(ee));
        fn = sizeof(ee);
    }
    crypto_hash_update(&t->th, fl, fn);
    uint8_t th[HMAX], sfk[HMAX];
    transcript(t, th);
    expand_label(t, t->s_hs, "finished", NULL, 0, sfk, t->hl);
    fl[fn] = HS_FINISHED;
    wr24(fl + fn + 1, t->hl);
    crypto_hmac(t->hid, sfk, t->hl, th, t->hl, fl + fn + 4);
    crypto_hash_update(&t->th, fl + fn, 4 + t->hl);
    fn += 4 + t->hl;
    put_enc(o, &t->tx, CT_HANDSHAKE, fl, fn);

    /* 相手の Finished の期待値と、アプリの秘密(どちらも CH..サーバ Finished の transcript)*/
    uint8_t cfk[HMAX], c_ap[HMAX], s_ap[HMAX];
    transcript(t, th);
    expand_label(t, t->c_hs, "finished", NULL, 0, cfk, t->hl);
    crypto_hmac(t->hid, cfk, t->hl, th, t->hl, t->cfin);
    derive_secret(t, t->master, "c ap traffic", th, c_ap);
    derive_secret(t, t->master, "s ap traffic", th, s_ap);
    keylog(t, "CLIENT_TRAFFIC_SECRET_0", c_ap);
    keylog(t, "SERVER_TRAFFIC_SECRET_0", s_ap);
    dir_install(t, &t->tx, s_ap);
    memcpy(t->master, c_ap, t->hl);   /* 相手の Finished を確かめたら rx に入れる(master はもう要らない)*/
    t->state = TLS13_ST_WAIT_CFIN;

    crypto_wipe(early, sizeof(early)); crypto_wipe(shared, sizeof(shared));
    crypto_wipe(hs, sizeof(hs)); crypto_wipe(s_ap, sizeof(s_ap)); crypto_wipe(c_ap, sizeof(c_ap));
    return o->over ? fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "送信バッファが足りない") : 0;
#undef NEED
}

/* ---- クライアント(段階 F)---- */
void tls13_client_init(tls13_t *t, const tls13_psk_t *psk) {
    tls13_server_init(t, psk, 1);
    t->is_client = 1;
    t->psk_index = 0;
    set_hash(t, psk_hash(psk));
}

/* ClientHello の本体を ch へ組み立てる(binder まで計算する)。share は key_share を付ける群。
 * HelloRetryRequest の後(t->hrr)は、乱数とセッション ID は 1 回目と同じ、cookie を返し、
 * binder は transcript(message_hash + HRR)の続きで計算する。
 * reuse = 1 なら key_share の値を作り直さず 1 回目と同じにする(cookie だけの HelloRetryRequest。
 * RFC 8446 4.1.2: 2 回目の ClientHello は、HRR が key_share を指定したときだけ key_share を差し替え、
 * ほかは同じでなければならない)。x25519 は控えた秘密鍵から公開値を作り直し、ML-KEM は
 * 復号鍵の中のカプセル化鍵(FIPS 203: dk = dk_pke || ek || H(ek) || z)をそのまま使う。0 なら失敗。 */
static size_t build_client_hello(tls13_t *t, uint8_t *ch, size_t cap, unsigned share, int reuse) {
    const tls13_psk_t *psk = &t->psks[0];
    const unsigned allow = allowed_groups(t);
    static const uint8_t base[32] = { 9 };
    size_t n = 0;
    if (cap < 512u + CRYPTO_MLKEM1024_EK_LEN + TLS13_IDENT_MAX) return 0;
    ch[n++] = HS_CLIENT_HELLO;
    n += 3;
    ch[n++] = 3; ch[n++] = 3;
    memcpy(ch + n, t->crandom, 32); n += 32;
    ch[n++] = 32;
    memcpy(ch + n, t->sid, 32); n += 32;
    wr16(ch + n, 2); wr16(ch + n + 2, t->suite); n += 4;
    ch[n++] = 1; ch[n++] = 0;
    const size_t extpos = n;
    n += 2;
    /* supported_versions: TLS 1.3 だけ */
    wr16(ch + n, EXT_SUPPORTED_VERSIONS); wr16(ch + n + 2, 3); ch[n + 4] = 2; wr16(ch + n + 5, 0x0304); n += 7;
    /* supported_groups: 使ってよい群を好みの順(ML-KEM-1024 が先)*/
    {
        uint16_t gl[2];
        unsigned ng = 0;
        if (allow & TLS13_GROUP_MLKEM1024) gl[ng++] = GROUP_MLKEM1024;
        if (allow & TLS13_GROUP_X25519) gl[ng++] = GROUP_X25519;
        wr16(ch + n, EXT_SUPPORTED_GROUPS); wr16(ch + n + 2, 2 + 2 * ng); wr16(ch + n + 4, 2 * ng);
        for (unsigned i = 0; i < ng; i++) wr16(ch + n + 6 + 2 * i, gl[i]);
        n += 6 + 2 * ng;
    }
    /* key_share: share の群それぞれの公開値(ML-KEM-1024 はカプセル化鍵、x25519 は 32 バイト)*/
    {
        const size_t kspos = n;
        n += 6;
        if (share & TLS13_GROUP_MLKEM1024) {
            wr16(ch + n, GROUP_MLKEM1024); wr16(ch + n + 2, CRYPTO_MLKEM1024_EK_LEN);
            if (reuse) memcpy(ch + n + 4, t->ml_dk + 384u * 4u, CRYPTO_MLKEM1024_EK_LEN);
            else if (crypto_mlkem1024_keygen(ch + n + 4, t->ml_dk) != 0) return 0;
            n += 4 + CRYPTO_MLKEM1024_EK_LEN;
        }
        if (share & TLS13_GROUP_X25519) {
            if (reuse) { /* 控えた秘密鍵のまま */ }
            else if (t->test_priv) memcpy(t->cpriv, t->test_priv, 32);
            else if (crypto_random(t->cpriv, 32) != 0) return 0;
            wr16(ch + n, GROUP_X25519); wr16(ch + n + 2, 32);
            crypto_x25519(ch + n + 4, t->cpriv, base);
            n += 4 + 32;
        }
        wr16(ch + kspos, EXT_KEY_SHARE); wr16(ch + kspos + 2, (unsigned)(n - kspos - 4));
        wr16(ch + kspos + 4, (unsigned)(n - kspos - 6));
        t->sent = share;
    }
    /* cookie(HelloRetryRequest に付いてきたら、そのまま返す)*/
    if (t->cookie_len) {
        wr16(ch + n, EXT_COOKIE); wr16(ch + n + 2, 2u + t->cookie_len); wr16(ch + n + 4, t->cookie_len);
        memcpy(ch + n + 6, t->cookie, t->cookie_len);
        n += 6u + t->cookie_len;
    }
    /* psk_key_exchange_modes: psk_dhe_ke だけ */
    wr16(ch + n, EXT_PSK_KEX_MODES); wr16(ch + n + 2, 2); ch[n + 4] = 1; ch[n + 5] = 1; n += 6;
    /* early_data(試験用だけ。HelloRetryRequest の後は付けない。4.1.2)*/
    if (t->test_early_data && !t->hrr) { wr16(ch + n, EXT_EARLY_DATA); wr16(ch + n + 2, 0); n += 4; }
    /* pre_shared_key(**最後の拡張**): 身元 1 本 + binder 1 本 */
    const unsigned il = psk->identity_len, hl = t->hl;
    if (n + 4 + 2 + 2 + il + 4 + 2 + 1 + hl > cap) return 0;
    wr16(ch + n, EXT_PRE_SHARED_KEY); wr16(ch + n + 2, 2 + 2 + il + 4 + 2 + 1 + hl); n += 4;
    wr16(ch + n, 2 + il + 4); wr16(ch + n + 2, il); memcpy(ch + n + 4, psk->identity, il);
    memset(ch + n + 4 + il, 0, 4);   /* 外部 PSK なので obfuscated_ticket_age は 0 */
    n += 2 + 2 + il + 4;
    const size_t binders = n;
    wr16(ch + n, 1 + hl); ch[n + 2] = (uint8_t)hl; n += 3 + hl;
    wr16(ch + extpos, (unsigned)(n - extpos - 2));
    wr24(ch + 1, (unsigned)(n - 4));
    binder_value(t, t->early, ch, binders, ch + binders + 3);
    return n;
}

size_t tls13_client_hello(tls13_t *t, uint8_t *out, size_t cap) {
    obuf_t o = { out, cap, 0, 0 };
    const tls13_psk_t *psk = &t->psks[0];
    if (t->cnsa && psk_hash(psk) != CRYPTO_SHA384) {
        t->why = "CNSA 2.0 専用には SHA-384 の PSK(NVMeTLSkey-1:02:)が要る";
        return 0;
    }
    if (t->test_random) memcpy(t->crandom, t->test_random, 32);
    else if (crypto_random(t->crandom, 32) != 0) return 0;
    if (crypto_random(t->sid, 32) != 0) return 0;   /* 互換モード(tlshd と同じ)*/
    t->sidlen = 32;
    crypto_hkdf_extract(t->hid, NULL, 0, psk->psk, t->hl, t->early);
    const unsigned allow = allowed_groups(t);
    const unsigned share = t->share ? (t->share & allow) : allow;
    if (!share) return 0;
    uint8_t ch[TLS13_HS_MAX];
    const size_t n = build_client_hello(t, ch, sizeof(ch), share, 0);
    if (!n) return 0;
    crypto_hash_init(&t->th, t->hid);
    crypto_hash_update(&t->th, ch, n);
    put_plain(&o, CT_HANDSHAKE, ch, n);
    t->state = TLS13_ST_WAIT_SH;
    return o.over ? 0 : o.len;
}

/* ---- クライアントが受ける拡張の確かめ(RFC 8446 4.2)----
 * 応答(ServerHello / HelloRetryRequest / EncryptedExtensions)の拡張は、
 *   - クライアントが出していないもの(HRR の cookie を除く)なら unsupported_extension(MUST)、
 *   - 出したがそのメッセージに入ってはいけないものなら illegal_parameter(MUST)、
 *   - 同じ拡張が 2 つあれば illegal_parameter(4.2: 同じ種類は 1 つまで)。
 * 以前は知らない拡張を読み飛ばしていた。 */
enum {
    EB_SUPPORTED_GROUPS = 1u, EB_PRE_SHARED_KEY = 2u, EB_EARLY_DATA = 4u, EB_SUPPORTED_VERSIONS = 8u,
    EB_COOKIE = 16u, EB_PSK_KEX_MODES = 32u, EB_KEY_SHARE = 64u,
};

static unsigned ext_bit(uint16_t et) {
    switch (et) {
    case EXT_SUPPORTED_GROUPS: return EB_SUPPORTED_GROUPS;
    case EXT_PRE_SHARED_KEY: return EB_PRE_SHARED_KEY;
    case EXT_EARLY_DATA: return EB_EARLY_DATA;
    case EXT_SUPPORTED_VERSIONS: return EB_SUPPORTED_VERSIONS;
    case EXT_COOKIE: return EB_COOKIE;
    case EXT_PSK_KEX_MODES: return EB_PSK_KEX_MODES;
    case EXT_KEY_SHARE: return EB_KEY_SHARE;
    default: return 0;
    }
}

/* クライアントが ClientHello に付けた拡張か。 */
static int client_sent_ext(const tls13_t *t, uint16_t et) {
    switch (et) {
    case EXT_SUPPORTED_VERSIONS: case EXT_SUPPORTED_GROUPS: case EXT_KEY_SHARE:
    case EXT_PSK_KEX_MODES: case EXT_PRE_SHARED_KEY:
        return 1;
    case EXT_COOKIE: return t->hrr && t->cookie_len != 0;
    case EXT_EARLY_DATA: return t->test_early_data != 0;
    default: return 0;
    }
}

/* 0 = よい、それ以外は送る alert。allow はそのメッセージに入ってよい拡張(EB_*)。 */
static uint8_t resp_ext_check(const tls13_t *t, uint16_t et, unsigned allow, unsigned *seen) {
    const unsigned b = ext_bit(et);
    if (!client_sent_ext(t, et) && !(b == EB_COOKIE && (allow & EB_COOKIE))) return TLS13_ALERT_UNSUPPORTED_EXTENSION;
    if (!(allow & b) || (*seen & b)) return TLS13_ALERT_ILLEGAL_PARAMETER;
    *seen |= b;
    return 0;
}

/* HelloRetryRequest を受けた: 求められた群の key_share だけを付けた ClientHello を送り直す。 */
static int on_hello_retry(tls13_t *t, const uint8_t *msg, size_t mlen, obuf_t *o) {
    if (t->hrr) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "2 回目の HelloRetryRequest");
    const uint8_t *p = msg + 4 + 2 + 32, *end = msg + mlen;
    if (*p != 32 || memcmp(p + 1, t->sid, 32) != 0) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "セッション ID が返ってこない");
    p += 33;
    if (rd16(p) != t->suite || p[2] != 0) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "出していない暗号スイート");
    p += 3;
    const uint16_t extlen = rd16(p);
    p += 2;
    if ((size_t)(end - p) != extlen) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "拡張の長さが合わない");
    int v13 = 0;
    uint16_t want = 0;
    unsigned seen = 0;
    t->cookie_len = 0;
    while (p + 4 <= end) {
        const uint16_t et = rd16(p), el = rd16(p + 2);
        const uint8_t *e = p + 4;
        if (e + el > end) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "拡張の長さが合わない");
        /* HelloRetryRequest に入ってよいのは supported_versions / key_share / cookie だけ(4.1.4)。
         * cookie はクライアントが出していなくても返ってくる唯一の拡張(4.2)。 */
        const uint8_t bad = resp_ext_check(t, et, EB_SUPPORTED_VERSIONS | EB_KEY_SHARE | EB_COOKIE, &seen);
        if (bad) return fail(t, o, bad, "HelloRetryRequest に出していない / 入ってはいけない拡張");
        if (et == EXT_SUPPORTED_VERSIONS && el == 2) v13 = (rd16(e) == 0x0304);
        else if (et == EXT_KEY_SHARE && el == 2) want = rd16(e);
        else if (et == EXT_COOKIE) {
            if (el < 3 || rd16(e) + 2u != el || rd16(e) > TLS13_COOKIE_MAX)
                return fail(t, o, TLS13_ALERT_DECODE_ERROR, "cookie の長さ");
            t->cookie_len = rd16(e);
            memcpy(t->cookie, e + 2, t->cookie_len);
        }
        p = e + el;
    }
    if (!v13) return fail(t, o, TLS13_ALERT_PROTOCOL_VERSION, "TLS 1.3 でない");
    /* 求められた群は、使ってよく、まだ key_share を付けていないものでなければならない(RFC 8446 4.1.4)。
     * **key_share が無く cookie だけの HelloRetryRequest も正しい**(サーバが状態を持たずに
     * アドレスの到達性を確かめる使い方。4.2.2)。そのときは key_share をそのまま、cookie を足して送り直す。
     * どちらも無ければ ClientHello が何も変わらないので illegal_parameter(4.1.4)。 */
    const unsigned wb = group_bit(want);
    if (want && (!(allowed_groups(t) & wb) || (t->sent & wb)))
        return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "HelloRetryRequest が求めた群が使えない / 既に送った");
    if (!want && !t->cookie_len)
        return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "HelloRetryRequest が ClientHello を何も変えない");
    uint8_t h1[HMAX];
    transcript(t, h1);   /* CH1 の Hash */
    t->hrr = 1;
    t->group = want;
    transcript_hrr(t, h1, msg, mlen);
    uint8_t ch[TLS13_HS_MAX];
    const size_t n = want ? build_client_hello(t, ch, sizeof(ch), wb, 0)
                          : build_client_hello(t, ch, sizeof(ch), t->sent, 1);
    if (!n) return fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "2 回目の ClientHello を組めない");
    crypto_hash_update(&t->th, ch, n);
    put_ccs(o);   /* 互換モード: 2 回目の ClientHello の前に CCS(RFC 8446 D.4。Finished の前には送らない)*/
    put_plain(o, CT_HANDSHAKE, ch, n);
    return o->over ? fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "送信バッファが足りない") : 0;
}

static int on_server_hello(tls13_t *t, const uint8_t *msg, size_t mlen, obuf_t *o) {
    const uint8_t *p = msg + 4, *end = msg + mlen;
    if (end - p < 2 + 32 + 1 + 32 + 2 + 1 + 2) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "ServerHello が短い");
    p += 2;
    if (memcmp(p, HRR_RANDOM, 32) == 0) return on_hello_retry(t, msg, mlen, o);
    p += 32;
    if (*p != 32 || memcmp(p + 1, t->sid, 32) != 0) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "セッション ID が返ってこない");
    p += 33;
    if (rd16(p) != t->suite || p[2] != 0) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "出していない暗号スイート");
    p += 3;
    const uint16_t extlen = rd16(p);
    p += 2;
    if ((size_t)(end - p) != extlen) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "拡張の長さが合わない");
    int v13 = 0, psk_ok = 0;
    const uint8_t *share = NULL;
    uint16_t grp = 0;
    unsigned seen = 0;
    while (p + 4 <= end) {
        const uint16_t et = rd16(p), el = rd16(p + 2);
        const uint8_t *e = p + 4;
        if (e + el > end) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "拡張の長さが合わない");
        /* ServerHello に入ってよいのは supported_versions / key_share / pre_shared_key だけ(4.1.3 / 4.2)*/
        const uint8_t bad = resp_ext_check(t, et, EB_SUPPORTED_VERSIONS | EB_KEY_SHARE | EB_PRE_SHARED_KEY, &seen);
        if (bad) return fail(t, o, bad, "ServerHello に出していない / 入ってはいけない拡張");
        if (et == EXT_SUPPORTED_VERSIONS && el == 2) v13 = (rd16(e) == 0x0304);
        else if (et == EXT_KEY_SHARE && el >= 4 && rd16(e + 2) + 4u == el) {
            const uint16_t g = rd16(e), kl = rd16(e + 2);
            if ((g == GROUP_X25519 && kl == 32) || (g == GROUP_MLKEM1024 && kl == CRYPTO_MLKEM1024_CT_LEN)) {
                share = e + 4;
                grp = g;
            }
        } else if (et == EXT_PRE_SHARED_KEY && el == 2) psk_ok = (rd16(e) == 0);
        p = e + el;
    }
    if (!v13) return fail(t, o, TLS13_ALERT_PROTOCOL_VERSION, "TLS 1.3 でない");
    if (!psk_ok) return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE, "サーバが PSK を選ばなかった(証明書は使えない)");
    if (!share) return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE, "サーバの key_share が無い");
    if (!(t->sent & group_bit(grp))) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "key_share を付けていない群でサーバが答えた");
    uint8_t shared[32];
    if (grp == GROUP_X25519) {
        if (crypto_x25519(shared, t->cpriv, share) != 0) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "x25519 の公開値が小位数の点");
    } else if (crypto_mlkem1024_decaps(t->ml_dk, share, shared) != 0) {
        return fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "ML-KEM-1024 の復号鍵が壊れている");
    }
    /* ML-KEM の暗号文が壊れていても失敗は返らない(暗黙の拒否で違う共有秘密になり、
     * 次のサーバの Finished が合わずに decrypt_error になる)。 */
    t->group = grp;
    crypto_hash_update(&t->th, msg, mlen);

    uint8_t eh[HMAX], derived[HMAX], hs[HMAX], th[HMAX];
    static const uint8_t zero[HMAX];
    empty_hash(t, eh);
    derive_secret(t, t->early, "derived", eh, derived);
    crypto_hkdf_extract(t->hid, derived, t->hl, shared, 32, hs);
    transcript(t, th);
    derive_secret(t, hs, "c hs traffic", th, t->c_hs);
    derive_secret(t, hs, "s hs traffic", th, t->s_hs);
    derive_secret(t, hs, "derived", eh, derived);
    crypto_hkdf_extract(t->hid, derived, t->hl, zero, t->hl, t->master);
    keylog(t, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", t->c_hs);
    keylog(t, "SERVER_HANDSHAKE_TRAFFIC_SECRET", t->s_hs);
    dir_install(t, &t->rx, t->s_hs);
    /* **送信もここでクライアントの握手の鍵にする。** ServerHello を受けた後の alert は握手の鍵で
     * 保護して送る(RFC 8446 5 / 7.3: サーバはこの後のクライアントのレコードを c_hs で開く)。
     * 以前は Finished を送るときに入れていたので、EncryptedExtensions / サーバの Finished の段で
     * 断ったときの alert が平文で出て、サーバには読めなかった。Finished はこの鍵のまま
     * (順序番号 0 から。alert を送っていれば握手は終わっている)で送る。 */
    dir_install(t, &t->tx, t->c_hs);
    crypto_wipe(t->early, sizeof(t->early)); crypto_wipe(t->cpriv, sizeof(t->cpriv));
    crypto_wipe(t->ml_dk, sizeof(t->ml_dk));
    crypto_wipe(shared, sizeof(shared)); crypto_wipe(hs, sizeof(hs));
    t->state = TLS13_ST_WAIT_EE;
    return 0;
}

static int on_server_finished(tls13_t *t, const uint8_t *msg, size_t mlen, obuf_t *o) {
    uint8_t th[HMAX], fk[HMAX], want[HMAX];
    transcript(t, th);   /* CH..EE */
    expand_label(t, t->s_hs, "finished", NULL, 0, fk, t->hl);
    crypto_hmac(t->hid, fk, t->hl, th, t->hl, want);
    if (!crypto_equal(want, msg + 4, t->hl)) return fail(t, o, TLS13_ALERT_DECRYPT_ERROR, "サーバの Finished が合わない");
    crypto_hash_update(&t->th, msg, mlen);

    uint8_t c_ap[HMAX], s_ap[HMAX], fin[4 + HMAX];
    transcript(t, th);   /* CH..サーバ Finished */
    derive_secret(t, t->master, "c ap traffic", th, c_ap);
    derive_secret(t, t->master, "s ap traffic", th, s_ap);
    keylog(t, "CLIENT_TRAFFIC_SECRET_0", c_ap);
    keylog(t, "SERVER_TRAFFIC_SECRET_0", s_ap);
    expand_label(t, t->c_hs, "finished", NULL, 0, fk, t->hl);
    fin[0] = HS_FINISHED;
    wr24(fin + 1, t->hl);
    crypto_hmac(t->hid, fk, t->hl, th, t->hl, fin + 4);
    crypto_hash_update(&t->th, fin, 4u + t->hl);
    /* 互換モードではこちらも最初の暗号化レコードの前に CCS を 1 個送る(RFC 8446 D.4)。
     * HelloRetryRequest を受けたときは 2 回目の ClientHello の前に送ってある。 */
    if (!t->hrr) put_ccs(o);
    put_enc(o, &t->tx, CT_HANDSHAKE, fin, 4u + t->hl);   /* tx は ServerHello のときに c_hs にしてある */
    dir_install(t, &t->tx, c_ap);
    dir_install(t, &t->rx, s_ap);
    crypto_wipe(t->master, sizeof(t->master));
    crypto_wipe(c_ap, sizeof(c_ap)); crypto_wipe(s_ap, sizeof(s_ap));
    t->state = TLS13_ST_OPEN;
    return o->over ? fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "送信バッファが足りない") : 0;
}

/* 握手メッセージ 1 個 */
static int on_handshake(tls13_t *t, const uint8_t *msg, size_t mlen, obuf_t *o) {
    switch (t->state) {
    case TLS13_ST_WAIT_CH:
        if (msg[0] != HS_CLIENT_HELLO) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "ClientHello でない");
        return on_client_hello(t, msg, mlen, o);
    case TLS13_ST_WAIT_CFIN:
        if (msg[0] != HS_FINISHED || mlen != 4u + t->hl) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "Finished でない");
        if (!crypto_equal(msg + 4, t->cfin, t->hl)) return fail(t, o, TLS13_ALERT_DECRYPT_ERROR, "相手の Finished が合わない");
        t->early_left = 0;   /* 早期データの読み飛ばしはここまで(以後の開けないレコードは bad_record_mac)*/
        dir_install(t, &t->rx, t->master);
        crypto_wipe(t->master, sizeof(t->master));
        t->state = TLS13_ST_OPEN;
        return 0;
    case TLS13_ST_WAIT_SH:
        if (msg[0] != HS_SERVER_HELLO) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "ServerHello でない");
        return on_server_hello(t, msg, mlen, o);
    case TLS13_ST_WAIT_EE:
        if (msg[0] != HS_ENCRYPTED_EXTENSIONS) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "EncryptedExtensions でない");
        if (mlen < 6 || 6u + rd16(msg + 4) != mlen) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "EncryptedExtensions の長さ");
        {
            /* こちらが出した拡張のうち EncryptedExtensions に入ってよいのは supported_groups だけ
             * (サーバの好みの群を知らせる。4.2.7)。0-RTT は送らないので early_data も受けない。 */
            unsigned seen = 0;
            for (const uint8_t *p = msg + 6; p < msg + mlen;) {
                if (p + 4 > msg + mlen || p + 4 + rd16(p + 2) > msg + mlen)
                    return fail(t, o, TLS13_ALERT_DECODE_ERROR, "EncryptedExtensions の拡張の長さ");
                const uint8_t bad = resp_ext_check(t, rd16(p), EB_SUPPORTED_GROUPS, &seen);
                if (bad) return fail(t, o, bad, "EncryptedExtensions に出していない / 入ってはいけない拡張");
                p += 4 + rd16(p + 2);
            }
        }
        crypto_hash_update(&t->th, msg, mlen);   /* 中身(supported_groups)は使わない */
        t->state = TLS13_ST_WAIT_SFIN;
        return 0;
    case TLS13_ST_WAIT_SFIN:
        if (msg[0] != HS_FINISHED || mlen != 4u + t->hl) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "サーバの Finished でない");
        return on_server_finished(t, msg, mlen, o);
    case TLS13_ST_OPEN:
        if (msg[0] == HS_KEY_UPDATE) {
            /* 相手の鍵を進める。求められたらこちらも進めて KeyUpdate を返す(RFC 8446 4.6.3)。
             * 本体は request_update の 1 バイトだけで、値は 0(求めない)/ 1(求める)だけ。
             * 長さが違えば decode_error、値が違えば illegal_parameter(4.6.3 の MUST)。
             * 以前は長さが違うと「想定外のメッセージ」、値が 2 以上だと黙って 0 と同じに扱っていた。 */
            if (mlen != 5) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "KeyUpdate の長さ");
            if (msg[4] > 1) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "KeyUpdate の request_update が 0 / 1 でない");
            uint8_t ns[HMAX];
            expand_label(t, t->rx.secret, "traffic upd", NULL, 0, ns, t->hl);
            dir_install(t, &t->rx, ns);
            if (msg[4] == 1) {
                static const uint8_t ku[5] = { HS_KEY_UPDATE, 0, 0, 1, 0 };
                put_enc(o, &t->tx, CT_HANDSHAKE, ku, sizeof(ku));
                expand_label(t, t->tx.secret, "traffic upd", NULL, 0, ns, t->hl);
                dir_install(t, &t->tx, ns);
            }
            crypto_wipe(ns, sizeof(ns));
            return 0;
        }
        /* NewSessionTicket はサーバだけが送る(4.6.1)。クライアントは読み捨てる(再開は使わない)。
         * サーバが受けたら unexpected_message(以前はどちら側でも読み捨てていた)。 */
        if (msg[0] == HS_NEW_SESSION_TICKET && t->is_client) return 0;
        return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "握手の後の想定外のメッセージ");
    default:
        return -1;
    }
}

/* 握手のバイト列を溜め、メッセージ単位で処理する。 */
static int on_handshake_bytes(tls13_t *t, const uint8_t *d, size_t n, obuf_t *o) {
    if (t->hlen + n > sizeof(t->hbuf)) return fail(t, o, TLS13_ALERT_RECORD_OVERFLOW, "握手メッセージが大きすぎる");
    memcpy(t->hbuf + t->hlen, d, n);
    t->hlen += n;
    while (t->hlen >= 4) {
        const size_t ml = 4u + rd24(t->hbuf + 1);
        if (ml > sizeof(t->hbuf)) return fail(t, o, TLS13_ALERT_RECORD_OVERFLOW, "握手メッセージが大きすぎる");
        if (t->hlen < ml) break;
        const uint32_t before = t->rx.epoch;
        if (on_handshake(t, t->hbuf, ml, o) != 0) return -1;
        memmove(t->hbuf, t->hbuf + ml, t->hlen - ml);
        t->hlen -= ml;
        /* 受信の鍵が切り替わる境目にメッセージが残っていてはいけない(RFC 8446 5.1)。
         * **状態の変化ではなく鍵の世代で見る** -- クライアントは EE と Finished を
         * 同じレコードで受け取る(状態は変わるが鍵は同じ)。 */
        if (t->rx.epoch != before && t->hlen) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "鍵の切り替わりをまたぐ握手メッセージ");
    }
    return 0;
}

static int on_record(tls13_t *t, uint8_t *rec, size_t rlen, obuf_t *o,
                     uint8_t *app, size_t appcap, size_t *applen) {
    uint8_t type = rec[0];
    uint8_t *d = rec + 5;
    size_t n = rlen - 5;
    if (type == CT_CCS) {
        /* 互換モードの CCS は無視する(RFC 8446 5 / D.4)。受けてよいのは**最初の ClientHello の後から
         * 相手の Finished まで**で、握手メッセージの途中(5.1: 握手メッセージに別の種類のレコードを
         * 挟まない)でもいけない。サーバが最初の ClientHello より前に受けたら unexpected_message(5)。 */
        const int before_ch = !t->is_client && t->state == TLS13_ST_WAIT_CH && !t->hrr;
        if (n == 1 && d[0] == 1 && t->state != TLS13_ST_OPEN && !before_ch && t->hlen == 0) return 0;
        return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "想定外の ChangeCipherSpec");
    }
    if (t->rx.on) {
        if (type != CT_APPDATA) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "暗号化されていないレコード");
        if (n < 17) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "暗号文が短い");
        /* 復号した TLSInnerPlaintext が 2^14 + 1 を超えるなら record_overflow(5.2 / 5.4 の MUST)。
         * AEAD のタグは 16 バイト固定なので、復号の前に長さで分かる(開ける手間も省ける)。 */
        if (n - 16u > TLS13_PLAIN_MAX + 1u) return fail(t, o, TLS13_ALERT_RECORD_OVERFLOW, "復号した長さが 2^14 + 1 を超える");
        uint8_t iv[12];
        nonce(&t->rx, iv);
        /* **平文の受け取り先へ直接復号する**(段階 G。その場で復号してから写すと
         * 64KB の IO で 1 回余計にコピーする)。入り切らないとき(握手中に小さい
         * 受け取り先を渡された場合など)だけその場で復号する。application_data で
         * なかったら(握手 / alert)そこを作業域として使うだけで、applen は進めない。 */
        uint8_t *dst = (*applen + (n - 16u) <= appcap) ? app + *applen : d;
        if (crypto_aesgcm_open(&t->rx.aead, iv, rec, 5, d, n - 16u, dst, d + n - 16u) != 0) {
            /* 0-RTT を受け付けなかったサーバは、握手の鍵で開けないレコードを早期データとして
             * max_early_data_size まで読み飛ばす(RFC 8446 4.2.10)。早期データは early secret の鍵なので
             * 開けないのが正しい。順序番号は進めない(早期データは握手の鍵の列に入らない)。
             * 相手が early_data を出していなければ、または上限を超えたら従来どおり断る。 */
            if (t->early_left && t->state == TLS13_ST_WAIT_CFIN) {
                if (n > t->early_left)
                    return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "早期データが max_early_data_size を超える");
                t->early_left -= (uint32_t)n;
                return 0;
            }
            return fail(t, o, TLS13_ALERT_BAD_RECORD_MAC, "復号できない(タグが合わない)");
        }
        d = dst;
        t->rx.seq++;
        n -= 16u;
        while (n && d[n - 1] == 0) n--;   /* 詰め物 */
        if (!n) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "内側の種別が無い");
        type = d[--n];
    } else if (type == CT_APPDATA && t->early_left && t->hrr && t->state == TLS13_ST_WAIT_CH) {
        /* HelloRetryRequest の後、2 回目の ClientHello までに届く application_data は 1 回目の
         * ClientHello に続けて送られた 0-RTT。開ける鍵は無いので、max_early_data_size まで読み飛ばす
         * (RFC 8446 4.2.10)。 */
        if (n > t->early_left) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "早期データが max_early_data_size を超える");
        t->early_left -= (uint32_t)n;
        return 0;
    }
    /* 握手メッセージの途中(hbuf に続きを待つものがある)に別の種類のレコードを挟んではいけない
     * (RFC 8446 5.1 の MUST)。ふだんは hlen が 0 なので比較 1 個。 */
    if (t->hlen != 0 && type != CT_HANDSHAKE)
        return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "握手メッセージの途中に別の種類のレコード");
    switch (type) {
    case CT_HANDSHAKE:
        return on_handshake_bytes(t, d, n, o);
    case CT_ALERT:
        if (n != 2) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "alert の長さ");
        t->alert_recv = d[1];
        if (d[1] == TLS13_ALERT_CLOSE_NOTIFY) {
            /* 相手が書き込みを閉じた。**こちらも close_notify を送ってから閉じる**(RFC 8446 6.1:
             * 誤りの alert を送っていない限り、書き込みを閉じる前に close_notify を送る MUST)。
             * 以前は受けたら CLOSED にするだけで、nvmet_tls_close() は OPEN のときしか送らなかったので
             * 相手から閉じたときは一度も送っていなかった。送る alert は out に入り、呼び出し側が吐く。 */
            if (!t->close_sent && t->tx.on) {
                static const uint8_t cn[2] = { 1, TLS13_ALERT_CLOSE_NOTIFY };
                put_enc(o, &t->tx, CT_ALERT, cn, 2);
                t->close_sent = 1;
            }
            t->state = TLS13_ST_CLOSED;
            return 0;
        }
        t->state = TLS13_ST_FAILED;
        t->why = "相手から alert";
        return -1;
    case CT_APPDATA:
        if (t->state != TLS13_ST_OPEN) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "握手の前の application_data");
        if (d == app + *applen) {   /* 直接復号した */
            *applen += n;
            return 0;
        }
        if (*applen + n > appcap) return fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "平文の受け取り先が足りない");
        memcpy(app + *applen, d, n);
        *applen += n;
        return 0;
    default:
        return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "知らないレコード種別");
    }
}

int tls13_input(tls13_t *t, const uint8_t *in, size_t n,
                uint8_t *out, size_t cap, size_t *outlen,
                uint8_t *app, size_t appcap, size_t *applen) {
    obuf_t o = { out, cap, *outlen, 0 };
    int rc = 0;
    while (n && rc == 0 && t->state != TLS13_ST_CLOSED && t->state != TLS13_ST_FAILED) {
        /* **近道(段階 G): 入力の中に暗号化レコードが丸ごと揃っていれば、組み立て用の
         * バッファへ写さずにその場から直接復号する。** 自作の送り手は 1 レコード =
         * 1 セグメントで送るのでほぼ毎回ここを通る。入力は書き換えない(復号は平文の
         * 受け取り先へ。入り切らないなら近道を使わない)。 */
        if (t->rlen == 0 && n >= 5 && t->rx.on && in[0] == CT_APPDATA) {   /* 版の 2 バイトは見ない(5.1)*/
            const size_t rl = 5u + rd16(in + 3);
            if (rl <= n && rl <= sizeof(t->rbuf) && rl >= 5u + 17u && *applen + (rl - 5u - 16u) <= appcap) {
                rc = on_record(t, (uint8_t *)(uintptr_t)in, rl, &o, app, appcap, applen);
                in += rl;
                n -= rl;
                continue;
            }
        }
        /* ヘッダ 5 バイトを揃えてから本体 */
        size_t want = 5;
        if (t->rlen >= 5) want = 5u + rd16(t->rbuf + 3);
        if (want > sizeof(t->rbuf)) {
            rc = fail(t, &o, TLS13_ALERT_RECORD_OVERFLOW, "レコードが大きすぎる");
            break;
        }
        size_t take = want - t->rlen;
        if (take > n) take = n;
        memcpy(t->rbuf + t->rlen, in, take);
        t->rlen += take;
        in += take;
        n -= take;
        if (t->rlen < 5) continue;
        /* **ヘッダが揃ったらすぐ種別を確かめる。** TLS を使わないホストの平文の
         * ICReq(先頭 0x00)を長さだけ見て待つと、ありもしない残りを待って
         * ホストが諦めるまで黙ることになる(実機で踏んだ)。
         * legacy_record_version(2 バイト目と 3 バイト目)は**見ない**(RFC 8446 5.1: どんな目的にも
         * 使ってはならない。最初の ClientHello は 0x0301 のこともある)。以前は 2 バイト目が 3 で
         * なければ断っていた。 */
        if (t->rbuf[0] < CT_CCS || t->rbuf[0] > CT_APPDATA) {
            rc = fail(t, &o, TLS13_ALERT_UNEXPECTED_MESSAGE, "TLS のレコードでない(TLS を使わないホストか)");
            break;
        }
        /* 長さの上限(5.1 / 5.2 の MUST、超えたら record_overflow): 平文のレコード(TLSPlaintext)は
         * 2^14、暗号文(TLSCiphertext、外側の種別が application_data)は 2^14 + 256。
         * 以前は平文のレコードも 2^14 + 256 まで受けていた。 */
        const size_t lim = (t->rbuf[0] == CT_APPDATA) ? TLS13_PLAIN_MAX + 256u : TLS13_PLAIN_MAX;
        want = 5u + rd16(t->rbuf + 3);
        if (want - 5u > lim || want > sizeof(t->rbuf)) {
            rc = fail(t, &o, TLS13_ALERT_RECORD_OVERFLOW, "レコードが大きすぎる");
            break;
        }
        if (t->rlen < want) continue;
        rc = on_record(t, t->rbuf, want, &o, app, appcap, applen);
        t->rlen = 0;
    }
    *outlen = o.len;
    if (o.over) return -1;
    return rc;
}

size_t tls13_seal(tls13_t *t, const void *in, size_t n, uint8_t *out) {
    if (t->state != TLS13_ST_OPEN || n > TLS13_PLAIN_MAX) return 0;
    return seal_record(&t->tx, CT_APPDATA, (const uint8_t *)in, n, out);
}

size_t tls13_seal2(tls13_t *t, const void *p1, size_t l1, const void *p2, size_t l2, uint8_t *out) {
    if (t->state != TLS13_ST_OPEN || l1 + l2 > TLS13_PLAIN_MAX) return 0;
    const size_t n = l1 + l2;
    const size_t clen = n + 1u + 16u;
    out[0] = CT_APPDATA; out[1] = 3; out[2] = 3;
    wr16(out + 3, (unsigned)clen);
    static const uint8_t type = CT_APPDATA;   /* TLSInnerPlaintext の末尾の種別 */
    const crypto_iov_t v[3] = { { p1, l1 }, { p2, l2 }, { &type, 1 } };
    uint8_t iv[12];
    nonce(&t->tx, iv);
    crypto_aesgcm_seal_iov(&t->tx.aead, iv, out, 5, v, 3, out + 5, out + 5 + n + 1u);
    t->tx.seq++;
    return 5u + clen;
}

size_t tls13_close(tls13_t *t, uint8_t *out) {
    static const uint8_t a[2] = { 1, TLS13_ALERT_CLOSE_NOTIFY };
    if (!t->tx.on || t->close_sent) return 0;
    t->close_sent = 1;
    return seal_record(&t->tx, CT_ALERT, a, 2, out);
}

/* ---- 自己検査 ---- */
#include "tls13_vectors.h"

static int tfail(char *err, size_t errlen, const char *what) {
    if (errlen) {
        strncpy(err, what, errlen - 1u);
        err[errlen - 1u] = 0;
    }
    return -1;
}

static char s_kl[4][200];
static unsigned s_kln;
static void kl_capture(void *arg, const char *line) {
    (void)arg;
    if (s_kln < 4) {
        strncpy(s_kl[s_kln], line, sizeof(s_kl[0]) - 1);
        s_kln++;
    }
}

static int hexline_has(const char *line, const uint8_t *v) {
    char hx[65];
    for (int i = 0; i < 32; i++) snprintf(hx + 2 * i, 3, "%02x", v[i]);
    return strstr(line, hx) != NULL;
}

/* 自作のクライアントとサーバを握手させ、両方向に 1 レコードずつ流す。
 * 戻り値: 0=成功、1=サーバが断った、2=クライアントが断った、3=終わらない、4=往復が通らない。 */
static int self_pair(tls13_t *s, tls13_t *c) {
    static uint8_t a[8192], b[8192], app[64];
    size_t an = tls13_client_hello(c, a, sizeof(a)), al = 0;
    if (!an) return 2;
    for (int i = 0; i < 6; i++) {
        size_t bn = 0;
        if (an && tls13_input(s, a, an, b, sizeof(b), &bn, app, sizeof(app), &al) != 0) return 1;
        an = 0;
        if (bn && tls13_input(c, b, bn, a, sizeof(a), &an, app, sizeof(app), &al) != 0) return 2;
        if (s->state == TLS13_ST_OPEN && c->state == TLS13_ST_OPEN && an == 0) {
            al = 0;
            size_t rl = tls13_seal(c, "ping", 4, a), xn = 0;
            if (tls13_input(s, a, rl, b, sizeof(b), &xn, app, sizeof(app), &al) != 0 || al != 4 || memcmp(app, "ping", 4))
                return 4;
            al = 0;
            rl = tls13_seal(s, "pong", 4, a);
            if (tls13_input(c, a, rl, b, sizeof(b), &xn, app, sizeof(app), &al) != 0 || al != 4 || memcmp(app, "pong", 4))
                return 4;
            return 0;
        }
    }
    return 3;
}

int tls13_selftest(char *err, size_t errlen) {
    /* RFC 8448 4 章: ClientHello(早期データの申告つき、資格は resumption PSK)を
     * 食わせ、サーバの乱数・x25519 の鍵・EncryptedExtensions を RFC と同じにすると、
     * ServerHello のレコードと、暗号化された EE + Finished のレコードが**全バイト**
     * 一致すること。 */
    static tls13_psk_t psk;
    static tls13_t t;
    static uint8_t out[1024];
    memcpy(psk.psk, RFC8448_PSK, 32);
    psk.identity_len = 0;
    tls13_server_init(&t, &psk, 1);
    t.test_random = RFC8448_S_RANDOM;
    t.test_priv = RFC8448_S_PRIV;
    t.test_ee = RFC8448_EE;
    t.test_ee_len = sizeof(RFC8448_EE);
    t.test_resumption = 1;
    t.keylog = kl_capture;
    s_kln = 0;
    size_t ol = 0, al = 0;
    uint8_t app[16];
    /* 細切れに食わせる(レコードの組み立てを通す)*/
    for (size_t off = 0; off < sizeof(RFC8448_CH_RECORD);) {
        const size_t step = (sizeof(RFC8448_CH_RECORD) - off < 37u) ? sizeof(RFC8448_CH_RECORD) - off : 37u;
        if (tls13_input(&t, RFC8448_CH_RECORD + off, step, out, sizeof(out), &ol, app, sizeof(app), &al) != 0)
            return tfail(err, errlen, t.why ? t.why : "TLS 1.3 ClientHello を受け付けない");
        off += step;
    }
    if (ol != sizeof(RFC8448_SH_RECORD) + sizeof(RFC8448_FLIGHT_RECORD))
        return tfail(err, errlen, "TLS 1.3 サーバの出力の長さ");
    if (memcmp(out, RFC8448_SH_RECORD, sizeof(RFC8448_SH_RECORD)) != 0)
        return tfail(err, errlen, "TLS 1.3 ServerHello");
    if (memcmp(out + sizeof(RFC8448_SH_RECORD), RFC8448_FLIGHT_RECORD, sizeof(RFC8448_FLIGHT_RECORD)) != 0)
        return tfail(err, errlen, "TLS 1.3 EE + Finished(暗号文)");
    if (s_kln != 4 || !hexline_has(s_kl[0], RFC8448_C_HS) || !hexline_has(s_kl[1], RFC8448_S_HS) ||
        !hexline_has(s_kl[2], RFC8448_C_AP) || !hexline_has(s_kl[3], RFC8448_S_AP))
        return tfail(err, errlen, "TLS 1.3 鍵の予定表");

    /* 陰性対照: binder を 1 ビット壊すと decrypt_error で断る */
    static uint8_t ch[sizeof(RFC8448_CH_RECORD)];
    memcpy(ch, RFC8448_CH_RECORD, sizeof(ch));
    ch[sizeof(ch) - 1] ^= 1;
    tls13_server_init(&t, &psk, 1);
    t.test_resumption = 1;
    ol = 0;
    if (tls13_input(&t, ch, sizeof(ch), out, sizeof(out), &ol, app, sizeof(app), &al) == 0 ||
        t.alert_sent != TLS13_ALERT_DECRYPT_ERROR || ol != 7)
        return tfail(err, errlen, "TLS 1.3 壊れた binder を受け付けた");
    /* 陰性対照: 身元が一致しなければ unknown_psk_identity */
    tls13_server_init(&t, &psk, 1);
    ol = 0;
    if (tls13_input(&t, RFC8448_CH_RECORD, sizeof(RFC8448_CH_RECORD), out, sizeof(out), &ol, app, sizeof(app), &al) == 0 ||
        t.alert_sent != TLS13_ALERT_UNKNOWN_PSK_IDENTITY)
        return tfail(err, errlen, "TLS 1.3 知らない身元を受け付けた");

    /* 自作のクライアント <-> 自作のサーバ(段階 F と CNSA 2.0)。
     * **自作どうしなので両側が同じ間違い方をしうる** -- 独立の確認は
     * tools/tls13_check.c(OpenSSL のサーバ / クライアントと握手)と Linux の tlshd が受け持つ。 */
    {
        static tls13_t c;
        static tls13_psk_t p256, p384, bad;
        memset(&p256, 0, sizeof(p256));
        memcpy(p256.identity, "NVMe1R01 selftest", 17);
        p256.identity_len = 17;
        for (int i = 0; i < 32; i++) p256.psk[i] = (uint8_t)(i * 3 + 1);
        p384 = p256;
        memcpy(p384.identity, "NVMe1R02 selftest", 17);
        p384.hash = CRYPTO_SHA384;
        for (int i = 0; i < 48; i++) p384.psk[i] = (uint8_t)(i * 5 + 2);
        static const struct {
            const char *what;
            int use384, scnsa, ccnsa;
            unsigned cgroups, cshare, sgroups;
            int want, hrr, mlkem;
        } T[] = {
            { "TLS 1.3 自作どうし: SHA-256 + x25519",               0, 0, 0, 0, 0, 0, 0, 0, 0 },
            { "TLS 1.3 自作どうし: SHA-384 + ML-KEM-1024(CNSA)",   1, 1, 1, 0, 0, 0, 0, 0, 1 },
            { "TLS 1.3 自作どうし: HelloRetryRequest で ML-KEM へ",  1, 1, 0, TLS13_GROUP_X25519 | TLS13_GROUP_MLKEM1024,
              TLS13_GROUP_X25519, 0, 0, 1, 1 },
            { "TLS 1.3 自作どうし: x25519 だけのクライアントを CNSA が断る", 1, 1, 0, TLS13_GROUP_X25519, 0, 0, 1, 0, 0 },
            { "TLS 1.3 自作どうし: SHA-256 の PSK を CNSA が断る",  0, 1, 0, TLS13_GROUP_MLKEM1024, 0, 0, 1, 0, 0 },
            { "TLS 1.3 自作どうし: x25519 だけのサーバへ HelloRetryRequest", 0, 0, 0,
              TLS13_GROUP_X25519 | TLS13_GROUP_MLKEM1024, TLS13_GROUP_MLKEM1024, TLS13_GROUP_X25519, 0, 1, 0 },
        };
        for (unsigned k = 0; k < sizeof(T) / sizeof(T[0]); k++) {
            const tls13_psk_t *pp = T[k].use384 ? &p384 : &p256;
            tls13_server_init(&t, pp, 1);
            t.cnsa = T[k].scnsa;
            t.groups = T[k].sgroups;
            tls13_client_init(&c, pp);
            c.cnsa = T[k].ccnsa;
            c.groups = T[k].cgroups;
            c.share = T[k].cshare;
            const int r = self_pair(&t, &c);
            if (r != T[k].want) return tfail(err, errlen, t.why ? t.why : c.why ? c.why : T[k].what);
            if (r == 0 && (t.hrr != T[k].hrr || c.hrr != T[k].hrr || t.group != c.group ||
                           (t.group == GROUP_MLKEM1024) != T[k].mlkem || t.suite != c.suite ||
                           t.suite != (T[k].use384 ? SUITE_AES256_GCM_SHA384 : SUITE_AES128_GCM_SHA256)))
                return tfail(err, errlen, T[k].what);
        }
        /* 陰性対照: 違う PSK は decrypt_error(SHA-384 + ML-KEM でも)*/
        bad = p384;
        bad.psk[5] ^= 1;
        tls13_server_init(&t, &bad, 1);
        tls13_client_init(&c, &p384);
        c.cnsa = 1;
        if (self_pair(&t, &c) != 1 || t.alert_sent != TLS13_ALERT_DECRYPT_ERROR)
            return tfail(err, errlen, "TLS 1.3 自作どうし: 違う PSK を受け付けた");
        crypto_wipe(&c, sizeof(c));
    }
    crypto_wipe(&t, sizeof(t));
    return 0;
}
