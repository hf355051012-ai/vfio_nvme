/* TLS 1.3 のサーバ側(PLAN_auth_tls.md 段階 D)。仕様は tls13.h の冒頭。
 *
 * 鍵の予定表は RFC 8446 7.1、レコード層は 5.2〜5.3。NVMe/TCP の PSK の導出は
 * libnvme の src/nvme/linux.c(derive_retained_key / derive_psk_digest /
 * gen_tls_identity / derive_tls_key)から写した。写しが正しいことは
 * tools/tls_psk_check.py が Linux(tlshd)の実データで確かめてある。
 */
#include "tls13.h"

#include <stdio.h>
#include <string.h>

#define HL 32u   /* SHA-256 */

enum {
    CT_CCS = 20, CT_ALERT = 21, CT_HANDSHAKE = 22, CT_APPDATA = 23,
    HS_CLIENT_HELLO = 1, HS_SERVER_HELLO = 2, HS_NEW_SESSION_TICKET = 4,
    HS_ENCRYPTED_EXTENSIONS = 8, HS_FINISHED = 20, HS_KEY_UPDATE = 24,
    EXT_SUPPORTED_GROUPS = 10, EXT_PRE_SHARED_KEY = 41, EXT_EARLY_DATA = 42,
    EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEX_MODES = 45, EXT_KEY_SHARE = 51,
    GROUP_X25519 = 0x001D, SUITE_AES128_GCM_SHA256 = 0x1301,
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
    case TLS13_ALERT_UNKNOWN_PSK_IDENTITY: return "unknown_psk_identity";
    default: return "?";
    }
}

/* ---- 鍵の予定表(RFC 8446 7.1)---- */
static void expand_label(const uint8_t *secret, const char *label, const void *ctx, size_t clen,
                         uint8_t *out, size_t olen) {
    crypto_hkdf_expand_label(CRYPTO_SHA256, secret, HL, label, ctx, clen, out, olen);
}

static void derive_secret(const uint8_t *secret, const char *label, const uint8_t th[HL], uint8_t out[HL]) {
    expand_label(secret, label, th, HL, out, HL);
}

static void empty_hash(uint8_t out[HL]) { crypto_hash(CRYPTO_SHA256, "", 0, out); }

static void transcript(const tls13_t *t, uint8_t out[HL]) {
    crypto_hash_ctx_t c = t->th;   /* 途中の値を取り出す(本体は続ける)*/
    crypto_hash_final(&c, out);
}

static void dir_install(tls13_dir_t *d, const uint8_t secret[HL]) {
    uint8_t key[16];
    memcpy(d->secret, secret, HL);
    expand_label(secret, "key", NULL, 0, key, 16);
    expand_label(secret, "iv", NULL, 0, d->iv, 12);
    crypto_aes128gcm_init(&d->aead, key);
    crypto_wipe(key, sizeof(key));
    d->seq = 0;
    d->on = 1;
}

static void nonce(const tls13_dir_t *d, uint8_t n[12]) {
    memcpy(n, d->iv, 12);
    for (int i = 0; i < 8; i++) n[11 - i] ^= (uint8_t)(d->seq >> (8 * i));
}

static void keylog(tls13_t *t, const char *label, const uint8_t secret[HL]) {
    if (!t->keylog) return;
    char line[200];   /* 最長のラベル 31 文字 + 64 + 64 + 区切り */
    int n = snprintf(line, sizeof(line), "%s ", label);
    for (int i = 0; i < 32; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", t->crandom[i]);
    n += snprintf(line + n, sizeof(line) - (size_t)n, " ");
    for (unsigned i = 0; i < HL; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", secret[i]);
    t->keylog(t->keylog_arg, line);
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

/* TLSInnerPlaintext = data || type を暗号化して 1 レコード(詰め物なし)。 */
static size_t seal_record(tls13_dir_t *d, uint8_t type, const uint8_t *data, size_t n, uint8_t *r) {
    const size_t clen = n + 1u + 16u;
    r[0] = CT_APPDATA; r[1] = 3; r[2] = 3;
    wr16(r + 3, (unsigned)clen);
    memmove(r + 5, data, n);
    r[5 + n] = type;
    uint8_t iv[12];
    nonce(d, iv);
    crypto_aes128gcm_seal(&d->aead, iv, r, 5, r + 5, n + 1u, r + 5, r + 5 + n + 1u);
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
    uint8_t raw[64 + 4];
    const int n = crypto_base64_decode(p + 3, (size_t)(keystr + kl - 1 - (p + 3)), raw, sizeof(raw));
    if (n != 32 + 4) {
        *why = "鍵が 32 バイトでない(SHA-384 の 48 バイト鍵 = TLS_AES_256_GCM_SHA384 は未対応)";
        return -1;
    }
    const uint32_t crc = (uint32_t)raw[32] | ((uint32_t)raw[33] << 8) | ((uint32_t)raw[34] << 16) | ((uint32_t)raw[35] << 24);
    if (crypto_crc32(raw, 32) != crc) {
        *why = "鍵の CRC-32 が合わない";
        return -1;
    }
    if (hh > 1u) {
        *why = "変換のハッシュが SHA-256(01)/ なし(00)でない";
        return -1;
    }
    /* 1. retained PSK(hh=00 なら設定鍵そのまま)*/
    uint8_t prk[HL], retained[HL];
    if (hh == 0u) {
        memcpy(retained, raw, HL);
    } else {
        crypto_hkdf_extract(CRYPTO_SHA256, NULL, 0, raw, 32, prk);
        expand_label(prk, "HostNQN", hostnqn, strlen(hostnqn), retained, HL);
    }
    /* 2. 身元の digest = base64(HMAC(retained, host " " sub " NVMe-over-Fabrics")) */
    crypto_hmac_ctx_t m;
    uint8_t dig[HL];
    crypto_hmac_init(&m, CRYPTO_SHA256, retained, HL);
    crypto_hmac_update(&m, hostnqn, strlen(hostnqn));
    crypto_hmac_update(&m, " ", 1);
    crypto_hmac_update(&m, subnqn, strlen(subnqn));
    crypto_hmac_update(&m, " NVMe-over-Fabrics", 18);
    crypto_hmac_final(&m, dig);
    char b64[64];
    crypto_base64_encode(dig, HL, b64);

    crypto_hkdf_extract(CRYPTO_SHA256, NULL, 0, retained, HL, prk);
    for (int v = 0; v < 2; v++) {
        tls13_psk_t *o = &out[v];
        const int w = (v == 0)
            ? snprintf(o->identity, sizeof(o->identity), "NVMe1R01 %s %s %s", hostnqn, subnqn, b64)
            : snprintf(o->identity, sizeof(o->identity), "NVMe0R01 %s %s", hostnqn, subnqn);
        if (w <= 0 || (size_t)w >= sizeof(o->identity)) {
            *why = "NQN が長すぎる";
            return -1;
        }
        o->identity_len = (uint16_t)w;
        /* 3. TLS PSK = HKDF-Expand-Label(Extract(0, retained), "nvme-tls-psk", 文脈, 32)
         *    文脈は版 1 なら "01 " + digest、版 0 なら身元そのもの。 */
        char ctx[80];
        const char *c = o->identity;
        size_t cl = (size_t)w;
        if (v == 0) {
            cl = (size_t)snprintf(ctx, sizeof(ctx), "01 %s", b64);
            c = ctx;
        }
        expand_label(prk, "nvme-tls-psk", c, cl, o->psk, HL);
    }
    crypto_wipe(prk, sizeof(prk));
    crypto_wipe(retained, sizeof(retained));
    crypto_wipe(raw, sizeof(raw));
    return 2;
}

void tls13_server_init(tls13_t *t, const tls13_psk_t *psks, unsigned npsk) {
    memset(t, 0, sizeof(*t));
    t->psks = psks;
    t->npsk = npsk;
    t->psk_index = -1;
    t->alert_sent = 0xFF;
    t->alert_recv = 0xFF;
    crypto_hash_init(&t->th, CRYPTO_SHA256);
}

/* ---- ClientHello ---- */
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
    NEED(2);
    const uint16_t cslen = rd16(p);
    p += 2;
    NEED(cslen);
    int have_suite = 0;
    for (unsigned i = 0; i + 1u < cslen; i += 2) have_suite |= (rd16(p + i) == SUITE_AES128_GCM_SHA256);
    p += cslen;
    NEED(1);
    const uint8_t cmlen = *p++;
    NEED(cmlen);
    p += cmlen;
    NEED(2);
    const uint16_t extlen = rd16(p);
    p += 2;
    if ((size_t)(end - p) != extlen) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "拡張の長さが合わない");

    int v13 = 0, dhe = 0;
    const uint8_t *share = NULL, *psk_ext = NULL;
    size_t psk_len = 0;
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
            for (unsigned i = 1; el >= 1 && i <= e[0] && i < el; i++) dhe |= (e[i] == 1);
            break;
        case EXT_KEY_SHARE:
            if (el >= 2) {
                const uint8_t *q = e + 2, *qe = e + 2 + rd16(e);
                if (qe > e + el) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "key_share の長さ");
                while (q + 4 <= qe) {
                    const uint16_t g = rd16(q), kl = rd16(q + 2);
                    if (q + 4 + kl > qe) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "key_share の長さ");
                    if (g == GROUP_X25519 && kl == 32) share = q + 4;
                    q += 4 + kl;
                }
            }
            break;
        case EXT_PRE_SHARED_KEY:
            if (p != end) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "pre_shared_key が最後の拡張でない");
            psk_ext = e;
            psk_len = el;
            break;
        default:
            break;   /* 知らない拡張は読み飛ばす(early_data も受け付けないだけ)*/
        }
    }
    if (!v13) return fail(t, o, TLS13_ALERT_PROTOCOL_VERSION, "TLS 1.3 を出していない");
    if (!have_suite) return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE, "TLS_AES_128_GCM_SHA256 を出していない");
    if (!psk_ext) return fail(t, o, TLS13_ALERT_MISSING_EXTENSION, "pre_shared_key が無い(証明書は使えない)");
    if (!dhe) return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE, "psk_dhe_ke を出していない");
    if (!share) return fail(t, o, TLS13_ALERT_HANDSHAKE_FAILURE, "x25519 の key_share が無い(HelloRetryRequest は未対応)");

    /* pre_shared_key: 識別子のリスト → binder のリスト */
    if (psk_len < 2) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "pre_shared_key の長さ");
    const uint8_t *q = psk_ext + 2, *ids_end = psk_ext + 2 + rd16(psk_ext);
    if (ids_end + 2 > psk_ext + psk_len) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "pre_shared_key の長さ");
    int chosen = -1;
    unsigned idx = 0, sel = 0;
    while (q + 2 <= ids_end) {
        const uint16_t il = rd16(q);
        if (q + 2 + il + 4 > ids_end) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "PSK 身元の長さ");
        if (chosen < 0) {
            if (t->test_resumption && t->npsk > 0) {
                chosen = 0;
                sel = idx;
            }
            for (unsigned k = 0; k < t->npsk && chosen < 0; k++) {
                if (t->psks[k].identity_len == il && memcmp(t->psks[k].identity, q + 2, il) == 0) {
                    chosen = (int)k;
                    sel = idx;
                }
            }
        }
        q += 2 + il + 4;
        idx++;
    }
    if (chosen < 0) return fail(t, o, TLS13_ALERT_UNKNOWN_PSK_IDENTITY, "知らない PSK の身元");
    /* binder: 選んだ身元と同じ位置のもの */
    const uint8_t *binders = ids_end;   /* 2 バイトの長さから */
    const uint8_t *b = binders + 2, *bend = binders + 2 + rd16(binders);
    if (bend != psk_ext + psk_len) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "binder のリストの長さ");
    for (unsigned i = 0; i < sel && b < bend; i++) b += 1 + b[0];
    if (b >= bend || b[0] != HL || b + 1 + HL > bend) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "binder が無い");

    const uint8_t *psk = t->psks[chosen].psk;
    uint8_t early[HL], bkey[HL], fkey[HL], h[HL], want[HL], eh[HL];
    crypto_hkdf_extract(CRYPTO_SHA256, NULL, 0, psk, HL, early);
    empty_hash(eh);
    derive_secret(early, t->test_resumption ? "res binder" : "ext binder", eh, bkey);
    expand_label(bkey, "finished", NULL, 0, fkey, HL);
    crypto_hash(CRYPTO_SHA256, msg, (size_t)(binders - msg), h);   /* binder のリストより前 */
    crypto_hmac(CRYPTO_SHA256, fkey, HL, h, HL, want);
    if (!crypto_equal(want, b + 1, HL)) return fail(t, o, TLS13_ALERT_DECRYPT_ERROR, "binder が合わない(PSK が違う)");
    t->psk_index = chosen;
    t->selected_identity = (uint16_t)sel;
    crypto_hash_update(&t->th, msg, mlen);

    /* x25519 */
    uint8_t priv[32], pub[32], shared[32];
    static const uint8_t base[32] = { 9 };
    if (t->test_priv) memcpy(priv, t->test_priv, 32);
    else if (crypto_random(priv, 32) != 0) return fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "乱数が取れない");
    crypto_x25519(pub, priv, base);
    if (crypto_x25519(shared, priv, share) != 0) return fail(t, o, TLS13_ALERT_ILLEGAL_PARAMETER, "x25519 の公開値が小位数の点");

    /* ServerHello(拡張の並びは RFC 8448 と同じ: pre_shared_key, key_share, supported_versions)*/
    uint8_t sh[128];
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
    wr16(sh + n, SUITE_AES128_GCM_SHA256); n += 2;
    sh[n++] = 0;
    const size_t extpos = n;
    n += 2;
    wr16(sh + n, EXT_PRE_SHARED_KEY); wr16(sh + n + 2, 2); wr16(sh + n + 4, sel); n += 6;
    wr16(sh + n, EXT_KEY_SHARE); wr16(sh + n + 2, 36); wr16(sh + n + 4, GROUP_X25519); wr16(sh + n + 6, 32);
    memcpy(sh + n + 8, pub, 32); n += 40;
    wr16(sh + n, EXT_SUPPORTED_VERSIONS); wr16(sh + n + 2, 2); wr16(sh + n + 4, 0x0304); n += 6;
    wr16(sh + extpos, (unsigned)(n - extpos - 2));
    wr24(sh + 1, (unsigned)(n - 4));
    crypto_hash_update(&t->th, sh, n);
    put_plain(o, CT_HANDSHAKE, sh, n);
    /* セッション ID を返す互換モードなら ChangeCipherSpec を 1 個挟む(RFC 8446 D.4。
     * GnuTLS もそうしている)。 */
    if (sidlen) {
        static const uint8_t one = 1;
        put_plain(o, CT_CCS, &one, 1);
    }

    /* 握手の秘密 */
    uint8_t derived[HL], hs[HL], th1[HL];
    derive_secret(early, "derived", eh, derived);
    crypto_hkdf_extract(CRYPTO_SHA256, derived, HL, shared, 32, hs);
    transcript(t, th1);
    derive_secret(hs, "c hs traffic", th1, t->c_hs);
    derive_secret(hs, "s hs traffic", th1, t->s_hs);
    derive_secret(hs, "derived", eh, derived);
    static const uint8_t zero[HL];
    crypto_hkdf_extract(CRYPTO_SHA256, derived, HL, zero, HL, t->master);
    keylog(t, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", t->c_hs);
    keylog(t, "SERVER_HANDSHAKE_TRAFFIC_SECRET", t->s_hs);
    dir_install(&t->tx, t->s_hs);
    dir_install(&t->rx, t->c_hs);

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
    uint8_t th[HL], sfk[HL];
    transcript(t, th);
    expand_label(t->s_hs, "finished", NULL, 0, sfk, HL);
    fl[fn] = HS_FINISHED;
    wr24(fl + fn + 1, HL);
    crypto_hmac(CRYPTO_SHA256, sfk, HL, th, HL, fl + fn + 4);
    crypto_hash_update(&t->th, fl + fn, 4 + HL);
    fn += 4 + HL;
    put_enc(o, &t->tx, CT_HANDSHAKE, fl, fn);

    /* 相手の Finished の期待値と、アプリの秘密(どちらも CH..サーバ Finished の transcript)*/
    uint8_t cfk[HL], c_ap[HL], s_ap[HL];
    transcript(t, th);
    expand_label(t->c_hs, "finished", NULL, 0, cfk, HL);
    crypto_hmac(CRYPTO_SHA256, cfk, HL, th, HL, t->cfin);
    derive_secret(t->master, "c ap traffic", th, c_ap);
    derive_secret(t->master, "s ap traffic", th, s_ap);
    keylog(t, "CLIENT_TRAFFIC_SECRET_0", c_ap);
    keylog(t, "SERVER_TRAFFIC_SECRET_0", s_ap);
    dir_install(&t->tx, s_ap);
    memcpy(t->master, c_ap, HL);   /* 相手の Finished を確かめたら rx に入れる(master はもう要らない)*/
    t->state = TLS13_ST_WAIT_CFIN;

    crypto_wipe(early, sizeof(early)); crypto_wipe(priv, sizeof(priv)); crypto_wipe(shared, sizeof(shared));
    crypto_wipe(hs, sizeof(hs)); crypto_wipe(s_ap, sizeof(s_ap)); crypto_wipe(c_ap, sizeof(c_ap));
    return o->over ? fail(t, o, TLS13_ALERT_INTERNAL_ERROR, "送信バッファが足りない") : 0;
#undef NEED
}

/* 握手メッセージ 1 個 */
static int on_handshake(tls13_t *t, const uint8_t *msg, size_t mlen, obuf_t *o) {
    switch (t->state) {
    case TLS13_ST_WAIT_CH:
        if (msg[0] != HS_CLIENT_HELLO) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "ClientHello でない");
        return on_client_hello(t, msg, mlen, o);
    case TLS13_ST_WAIT_CFIN:
        if (msg[0] != HS_FINISHED || mlen != 4 + HL) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "Finished でない");
        if (!crypto_equal(msg + 4, t->cfin, HL)) return fail(t, o, TLS13_ALERT_DECRYPT_ERROR, "相手の Finished が合わない");
        dir_install(&t->rx, t->master);
        crypto_wipe(t->master, sizeof(t->master));
        t->state = TLS13_ST_OPEN;
        return 0;
    case TLS13_ST_OPEN:
        if (msg[0] == HS_KEY_UPDATE && mlen == 5) {
            /* 相手の鍵を進める。求められたらこちらも進めて KeyUpdate を返す(RFC 8446 4.6.3)*/
            uint8_t ns[HL];
            expand_label(t->rx.secret, "traffic upd", NULL, 0, ns, HL);
            dir_install(&t->rx, ns);
            if (msg[4] == 1) {
                static const uint8_t ku[5] = { HS_KEY_UPDATE, 0, 0, 1, 0 };
                put_enc(o, &t->tx, CT_HANDSHAKE, ku, sizeof(ku));
                expand_label(t->tx.secret, "traffic upd", NULL, 0, ns, HL);
                dir_install(&t->tx, ns);
            }
            crypto_wipe(ns, sizeof(ns));
            return 0;
        }
        if (msg[0] == HS_NEW_SESSION_TICKET) return 0;
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
        const tls13_state_t before = t->state;
        if (on_handshake(t, t->hbuf, ml, o) != 0) return -1;
        memmove(t->hbuf, t->hbuf + ml, t->hlen - ml);
        t->hlen -= ml;
        /* 鍵が切り替わる境目にメッセージが残っていてはいけない(RFC 8446 5.1)*/
        if (t->state != before && t->hlen) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "鍵の切り替わりをまたぐ握手メッセージ");
    }
    return 0;
}

static int on_record(tls13_t *t, uint8_t *rec, size_t rlen, obuf_t *o,
                     uint8_t *app, size_t appcap, size_t *applen) {
    uint8_t type = rec[0];
    uint8_t *d = rec + 5;
    size_t n = rlen - 5;
    if (type == CT_CCS) {
        /* 互換モードの CCS は相手の Finished までは無視する(RFC 8446 5)*/
        if (n == 1 && d[0] == 1 && t->state != TLS13_ST_OPEN) return 0;
        return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "想定外の ChangeCipherSpec");
    }
    if (t->rx.on) {
        if (type != CT_APPDATA) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "暗号化されていないレコード");
        if (n < 17) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "暗号文が短い");
        uint8_t iv[12];
        nonce(&t->rx, iv);
        if (crypto_aes128gcm_open(&t->rx.aead, iv, rec, 5, d, n - 16u, d, d + n - 16u) != 0)
            return fail(t, o, TLS13_ALERT_BAD_RECORD_MAC, "復号できない(タグが合わない)");
        t->rx.seq++;
        n -= 16u;
        while (n && d[n - 1] == 0) n--;   /* 詰め物 */
        if (!n) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "内側の種別が無い");
        type = d[--n];
    }
    switch (type) {
    case CT_HANDSHAKE:
        return on_handshake_bytes(t, d, n, o);
    case CT_ALERT:
        if (n != 2) return fail(t, o, TLS13_ALERT_DECODE_ERROR, "alert の長さ");
        t->alert_recv = d[1];
        t->state = (d[1] == TLS13_ALERT_CLOSE_NOTIFY) ? TLS13_ST_CLOSED : TLS13_ST_FAILED;
        if (d[1] != TLS13_ALERT_CLOSE_NOTIFY) t->why = "相手から alert";
        return d[1] == TLS13_ALERT_CLOSE_NOTIFY ? 0 : -1;
    case CT_APPDATA:
        if (t->state != TLS13_ST_OPEN) return fail(t, o, TLS13_ALERT_UNEXPECTED_MESSAGE, "握手の前の application_data");
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
    while (n && rc == 0 && (t->state == TLS13_ST_WAIT_CH || t->state == TLS13_ST_WAIT_CFIN || t->state == TLS13_ST_OPEN)) {
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
        /* **ヘッダが揃ったらすぐ種別と版を確かめる。** TLS を使わないホストの平文の
         * ICReq(先頭 0x00)を長さだけ見て待つと、ありもしない残りを待って
         * ホストが諦めるまで黙ることになる(実機で踏んだ)。 */
        if (t->rbuf[0] < CT_CCS || t->rbuf[0] > CT_APPDATA || t->rbuf[1] != 3) {
            rc = fail(t, &o, TLS13_ALERT_UNEXPECTED_MESSAGE, "TLS のレコードでない(TLS を使わないホストか)");
            break;
        }
        want = 5u + rd16(t->rbuf + 3);
        if (want > sizeof(t->rbuf)) {
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

size_t tls13_close(tls13_t *t, uint8_t *out) {
    static const uint8_t a[2] = { 1, TLS13_ALERT_CLOSE_NOTIFY };
    if (!t->tx.on) return 0;
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
    crypto_wipe(&t, sizeof(t));
    return 0;
}
