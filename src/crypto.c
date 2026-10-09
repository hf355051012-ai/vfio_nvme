#include "crypto.h"

#include <string.h>
#include <sys/random.h>

/* =================================================================
 * SHA-256 / 384 / 512(FIPS 180-4)
 *
 * 速さは要らない(DH-HMAC-CHAP も TLS の鍵の導出も接続時にしか動かない)ので、
 * 仕様の式をそのまま書く。この CPU(Coffee Lake)には SHA-NI も無い。
 * ================================================================= */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

static const uint32_t IV256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};
static const uint64_t IV384[8] = {
    0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull, 0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
    0x67332667ffc00b31ull, 0x8eb44a8768581511ull, 0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
};
static const uint64_t IV512[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};

static inline uint32_t ror32(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }
static inline uint64_t ror64(uint64_t x, unsigned n) { return (x >> n) | (x << (64u - n)); }

static inline uint32_t ld32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint64_t ld64be(const uint8_t *p) {
    return ((uint64_t)ld32be(p) << 32) | ld32be(p + 4);
}
static inline void st32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void st64be(uint8_t *p, uint64_t v) {
    st32be(p, (uint32_t)(v >> 32));
    st32be(p + 4, (uint32_t)v);
}

static void sha256_block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64];
    for (unsigned t = 0; t < 16; t++) w[t] = ld32be(p + 4u * t);
    for (unsigned t = 16; t < 64; t++) {
        const uint32_t s0 = ror32(w[t - 15], 7) ^ ror32(w[t - 15], 18) ^ (w[t - 15] >> 3);
        const uint32_t s1 = ror32(w[t - 2], 17) ^ ror32(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (unsigned t = 0; t < 64; t++) {
        const uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + K256[t] + w[t];
        const uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha512_block(uint64_t h[8], const uint8_t *p) {
    uint64_t w[80];
    for (unsigned t = 0; t < 16; t++) w[t] = ld64be(p + 8u * t);
    for (unsigned t = 16; t < 80; t++) {
        const uint64_t s0 = ror64(w[t - 15], 1) ^ ror64(w[t - 15], 8) ^ (w[t - 15] >> 7);
        const uint64_t s1 = ror64(w[t - 2], 19) ^ ror64(w[t - 2], 61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (unsigned t = 0; t < 80; t++) {
        const uint64_t S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        const uint64_t ch = (e & f) ^ (~e & g);
        const uint64_t t1 = hh + S1 + ch + K512[t] + w[t];
        const uint64_t S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        const uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
        const uint64_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

size_t crypto_hash_len(crypto_hash_id_t id) {
    switch (id) {
    case CRYPTO_SHA256: return 32u;
    case CRYPTO_SHA384: return 48u;
    case CRYPTO_SHA512: return 64u;
    default: return 0u;
    }
}

size_t crypto_hash_block(crypto_hash_id_t id) {
    return (id == CRYPTO_SHA256) ? 64u : (crypto_hash_len(id) ? 128u : 0u);
}

int crypto_hash_init(crypto_hash_ctx_t *c, crypto_hash_id_t id) {
    memset(c, 0, sizeof(*c));
    c->id = id;
    switch (id) {
    case CRYPTO_SHA256: memcpy(c->st.s32, IV256, sizeof(IV256)); return 0;
    case CRYPTO_SHA384: memcpy(c->st.s64, IV384, sizeof(IV384)); return 0;
    case CRYPTO_SHA512: memcpy(c->st.s64, IV512, sizeof(IV512)); return 0;
    default: return -1;
    }
}

static void hash_compress(crypto_hash_ctx_t *c, const uint8_t *blk) {
    if (c->id == CRYPTO_SHA256) {
        sha256_block(c->st.s32, blk);
    } else {
        sha512_block(c->st.s64, blk);
    }
}

void crypto_hash_update(crypto_hash_ctx_t *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    const size_t bs = crypto_hash_block(c->id);
    c->total += len;
    if (c->fill) {
        size_t take = bs - c->fill;
        if (take > len) take = len;
        memcpy(c->buf + c->fill, p, take);
        c->fill += (uint32_t)take;
        p += take;
        len -= take;
        if (c->fill < bs) return;
        hash_compress(c, c->buf);
        c->fill = 0;
    }
    while (len >= bs) {
        hash_compress(c, p);
        p += bs;
        len -= bs;
    }
    if (len) {
        memcpy(c->buf, p, len);
        c->fill = (uint32_t)len;
    }
}

void crypto_hash_final(crypto_hash_ctx_t *c, uint8_t *out) {
    const size_t bs = crypto_hash_block(c->id);
    const size_t lenfield = (bs == 64u) ? 8u : 16u;   /* 長さ欄は 64 / 128 ビット */
    const uint64_t bits = c->total << 3;
    const uint64_t bits_hi = c->total >> 61;
    c->buf[c->fill++] = 0x80;
    if (c->fill > bs - lenfield) {
        memset(c->buf + c->fill, 0, bs - c->fill);
        hash_compress(c, c->buf);
        c->fill = 0;
    }
    memset(c->buf + c->fill, 0, bs - c->fill);
    if (lenfield == 16u) st64be(c->buf + bs - 16u, bits_hi);
    st64be(c->buf + bs - 8u, bits);
    hash_compress(c, c->buf);

    const size_t n = crypto_hash_len(c->id);
    if (c->id == CRYPTO_SHA256) {
        for (unsigned i = 0; i < 8; i++) st32be(out + 4u * i, c->st.s32[i]);
    } else {
        uint8_t tmp[64];
        for (unsigned i = 0; i < 8; i++) st64be(tmp + 8u * i, c->st.s64[i]);
        memcpy(out, tmp, n);   /* SHA-384 は先頭 48 バイト */
        crypto_wipe(tmp, sizeof(tmp));
    }
    crypto_wipe(c, sizeof(*c));
}

int crypto_hash(crypto_hash_id_t id, const void *data, size_t len, uint8_t *out) {
    crypto_hash_ctx_t c;
    if (crypto_hash_init(&c, id) != 0) return -1;
    crypto_hash_update(&c, data, len);
    crypto_hash_final(&c, out);
    return 0;
}

/* =================================================================
 * HMAC(RFC 2104)
 * ================================================================= */

int crypto_hmac_init(crypto_hmac_ctx_t *c, crypto_hash_id_t id, const void *key, size_t klen) {
    const size_t bs = crypto_hash_block(id);
    if (bs == 0) return -1;
    uint8_t k[CRYPTO_BLOCK_MAX];
    memset(k, 0, sizeof(k));
    if (klen > bs) {
        crypto_hash(id, key, klen, k);   /* ブロックより長い鍵はハッシュしてから使う */
    } else if (klen) {
        memcpy(k, key, klen);
    }
    uint8_t pad[CRYPTO_BLOCK_MAX];
    for (size_t i = 0; i < bs; i++) pad[i] = (uint8_t)(k[i] ^ 0x36u);
    crypto_hash_init(&c->inner, id);
    crypto_hash_update(&c->inner, pad, bs);
    for (size_t i = 0; i < bs; i++) pad[i] = (uint8_t)(k[i] ^ 0x5cu);
    crypto_hash_init(&c->outer, id);
    crypto_hash_update(&c->outer, pad, bs);
    crypto_wipe(k, sizeof(k));
    crypto_wipe(pad, sizeof(pad));
    return 0;
}

void crypto_hmac_update(crypto_hmac_ctx_t *c, const void *data, size_t len) {
    crypto_hash_update(&c->inner, data, len);
}

void crypto_hmac_final(crypto_hmac_ctx_t *c, uint8_t *out) {
    uint8_t ih[CRYPTO_HASH_MAX];
    const size_t n = crypto_hash_len(c->inner.id);
    crypto_hash_final(&c->inner, ih);
    crypto_hash_update(&c->outer, ih, n);
    crypto_hash_final(&c->outer, out);
    crypto_wipe(ih, sizeof(ih));
}

int crypto_hmac(crypto_hash_id_t id, const void *key, size_t klen,
                const void *msg, size_t mlen, uint8_t *out) {
    crypto_hmac_ctx_t c;
    if (crypto_hmac_init(&c, id, key, klen) != 0) return -1;
    crypto_hmac_update(&c, msg, mlen);
    crypto_hmac_final(&c, out);
    return 0;
}

/* =================================================================
 * HKDF(RFC 5869)と HKDF-Expand-Label(RFC 8446 7.1)
 * ================================================================= */

int crypto_hkdf_extract(crypto_hash_id_t id, const void *salt, size_t slen,
                        const void *ikm, size_t ilen, uint8_t *prk) {
    static const uint8_t zero[CRYPTO_HASH_MAX];
    const size_t n = crypto_hash_len(id);
    if (n == 0) return -1;
    if (salt == NULL || slen == 0) {
        salt = zero;
        slen = n;
    }
    return crypto_hmac(id, salt, slen, ikm, ilen, prk);
}

int crypto_hkdf_expand(crypto_hash_id_t id, const uint8_t *prk, size_t prklen,
                       const void *info, size_t ilen, uint8_t *okm, size_t olen) {
    const size_t n = crypto_hash_len(id);
    if (n == 0 || olen > 255u * n) return -1;
    uint8_t t[CRYPTO_HASH_MAX];
    size_t tlen = 0, done = 0;
    for (uint8_t ctr = 1; done < olen; ctr++) {
        crypto_hmac_ctx_t c;
        crypto_hmac_init(&c, id, prk, prklen);
        crypto_hmac_update(&c, t, tlen);
        crypto_hmac_update(&c, info, ilen);
        crypto_hmac_update(&c, &ctr, 1);
        crypto_hmac_final(&c, t);
        tlen = n;
        const size_t take = (olen - done < n) ? (olen - done) : n;
        memcpy(okm + done, t, take);
        done += take;
    }
    crypto_wipe(t, sizeof(t));
    return 0;
}

int crypto_hkdf_expand_label(crypto_hash_id_t id, const uint8_t *secret, size_t slen,
                             const char *label, const void *ctx, size_t clen,
                             uint8_t *out, size_t olen) {
    static const char prefix[] = "tls13 ";
    const size_t plen = sizeof(prefix) - 1u;
    const size_t llen = strlen(label);
    if (plen + llen > 255u || clen > 255u || olen > 0xFFFFu) return -1;
    /* struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } HkdfLabel */
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t k = 0;
    info[k++] = (uint8_t)(olen >> 8);
    info[k++] = (uint8_t)olen;
    info[k++] = (uint8_t)(plen + llen);
    memcpy(info + k, prefix, plen);
    k += plen;
    memcpy(info + k, label, llen);
    k += llen;
    info[k++] = (uint8_t)clen;
    if (clen) memcpy(info + k, ctx, clen);
    k += clen;
    return crypto_hkdf_expand(id, secret, slen, info, k, out, olen);
}

/* =================================================================
 * base64 / CRC-32 / 乱数 / 比較 / 消去
 * ================================================================= */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t crypto_base64_encode(const void *in, size_t n, char *out) {
    const uint8_t *p = (const uint8_t *)in;
    size_t k = 0;
    for (size_t i = 0; i < n; i += 3) {
        const uint32_t v = ((uint32_t)p[i] << 16) | ((i + 1 < n) ? (uint32_t)p[i + 1] << 8 : 0u) |
                           ((i + 2 < n) ? (uint32_t)p[i + 2] : 0u);
        out[k++] = B64[(v >> 18) & 63u];
        out[k++] = B64[(v >> 12) & 63u];
        out[k++] = (i + 1 < n) ? B64[(v >> 6) & 63u] : '=';
        out[k++] = (i + 2 < n) ? B64[v & 63u] : '=';
    }
    out[k] = 0;
    return k;
}

static int b64val(char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

int crypto_base64_decode(const char *in, size_t n, uint8_t *out, size_t cap) {
    while (n && in[n - 1] == '=') n--;           /* 詰め物は有っても無くてもよい */
    if (n % 4u == 1u) return -1;                 /* 6 ビットだけ余る長さは有り得ない */
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        const int v = b64val(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (k >= cap) return -1;
            out[k++] = (uint8_t)(acc >> bits);
        }
    }
    if (bits && (acc & ((1u << bits) - 1u))) return -1;   /* 余りのビットは 0 でなければならない */
    return (int)k;
}

uint32_t crypto_crc32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (unsigned b = 0; b < 8; b++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

int crypto_random(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len) {
        const ssize_t r = getrandom(p, len, 0);
        if (r <= 0) return -1;
        p += r;
        len -= (size_t)r;
    }
    return 0;
}

int crypto_equal(const void *a, const void *b, size_t n) {
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0;
}

void crypto_wipe(void *p, size_t n) {
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}

/* =================================================================
 * 自己検査。期待値は OpenSSL(Python hashlib / hmac)で作り直したもので、
 * FIPS 180-4 / RFC 4231 / RFC 5869 / RFC 8448 に載っている値と一致する。
 * ================================================================= */

static int hexeq(const uint8_t *got, const char *hex, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (unsigned j = 0; j < 2; j++) {
            const char ch = hex[2 * i + j];
            v = (v << 4) | (unsigned)((ch <= '9') ? ch - '0' : ch - 'a' + 10);
        }
        if (got[i] != (uint8_t)v) return 0;
    }
    return hex[2 * n] == 0;   /* 期待値の長さも一致すること */
}

static void unhex(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            const char ch = hex[2 * i + (size_t)j];
            v = v * 16u + (unsigned)(ch <= '9' ? ch - '0' : (ch | 0x20) - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
}

static int fail(char *err, size_t errlen, const char *what) {
    if (err && errlen) {
        strncpy(err, what, errlen - 1u);
        err[errlen - 1u] = 0;
    }
    return -1;
}

int crypto_selftest(char *err, size_t errlen) {
    static const char *const msgs[] = {
        "",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    };
    static const char *const want_hash[5][3] = {
        { "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        { "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
          "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" },
        { "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
          "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
        /* 'a' x 1,000,000(update を細切れに呼ぶ経路も通す)*/
        { "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
          "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
          "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" },
    };
    uint8_t out[255];
    for (unsigned m = 0; m < 5; m++) {
        for (unsigned h = 0; h < 3; h++) {
            const crypto_hash_id_t id = (crypto_hash_id_t)(h + 1u);
            if (m < 4) {
                crypto_hash(id, msgs[m], strlen(msgs[m]), out);
            } else {
                static uint8_t a[997];
                memset(a, 'a', sizeof(a));
                crypto_hash_ctx_t c;
                crypto_hash_init(&c, id);
                size_t left = 1000000u;
                while (left) {
                    const size_t take = left < sizeof(a) ? left : sizeof(a);
                    crypto_hash_update(&c, a, take);
                    left -= take;
                }
                crypto_hash_final(&c, out);
            }
            if (!hexeq(out, want_hash[m][h], crypto_hash_len(id))) return fail(err, errlen, "SHA-2");
        }
    }

    /* HMAC: RFC 4231 の test case 1 / 2 / 6 / 7 */
    static const char *const want_hmac[4][3] = {
        { "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
          "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" },
        { "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
          "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" },
        { "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
          "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
          "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598" },
        { "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
          "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
          "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58" },
    };
    uint8_t k0b[20], kaa[131];
    memset(k0b, 0x0b, sizeof(k0b));
    memset(kaa, 0xaa, sizeof(kaa));
    const struct { const uint8_t *k; size_t kl; const char *m; } hc[4] = {
        { k0b, 20, "Hi There" },
        { (const uint8_t *)"Jefe", 4, "what do ya want for nothing?" },
        { kaa, 131, "Test Using Larger Than Block-Size Key - Hash Key First" },
        { kaa, 131, "This is a test using a larger than block-size key and a larger than block-size data. "
                    "The key needs to be hashed before being used by the HMAC algorithm." },
    };
    for (unsigned t = 0; t < 4; t++) {
        for (unsigned h = 0; h < 3; h++) {
            const crypto_hash_id_t id = (crypto_hash_id_t)(h + 1u);
            crypto_hmac(id, hc[t].k, hc[t].kl, hc[t].m, strlen(hc[t].m), out);
            if (!hexeq(out, want_hmac[t][h], crypto_hash_len(id))) return fail(err, errlen, "HMAC");
        }
    }

    /* HKDF: RFC 5869 test case 1(SHA-256)/ 3(salt・info 無し)と SHA-384 版 */
    uint8_t ikm[22], salt[13], info[10], prk[CRYPTO_HASH_MAX];
    memset(ikm, 0x0b, sizeof(ikm));
    for (unsigned i = 0; i < 13; i++) salt[i] = (uint8_t)i;
    for (unsigned i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0u + i);
    crypto_hkdf_extract(CRYPTO_SHA256, salt, 13, ikm, 22, prk);
    if (!hexeq(prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", 32))
        return fail(err, errlen, "HKDF-Extract");
    crypto_hkdf_expand(CRYPTO_SHA256, prk, 32, info, 10, out, 42);
    if (!hexeq(out, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42))
        return fail(err, errlen, "HKDF-Expand");
    crypto_hkdf_extract(CRYPTO_SHA256, NULL, 0, ikm, 22, prk);
    crypto_hkdf_expand(CRYPTO_SHA256, prk, 32, NULL, 0, out, 42);
    if (!hexeq(out, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42))
        return fail(err, errlen, "HKDF(salt / info 無し)");
    crypto_hkdf_extract(CRYPTO_SHA384, salt, 13, ikm, 22, prk);
    crypto_hkdf_expand(CRYPTO_SHA384, prk, 48, info, 10, out, 100);
    if (!hexeq(out, "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5d95d1da3e62587b22eb8943d0fab6bb631a2fe9df1a68c6ce5d56116a52005b3f122b88b39b7251fcd6c44d3ef25f20ed96802bf1b2c1d98bf74", 100))
        return fail(err, errlen, "HKDF SHA-384");

    /* HKDF-Expand-Label: RFC 8448 の early secret(PSK 無し)と "derived" */
    static const uint8_t zero32[32];
    crypto_hkdf_extract(CRYPTO_SHA256, NULL, 0, zero32, 32, prk);
    if (!hexeq(prk, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a", 32))
        return fail(err, errlen, "TLS 1.3 early secret");
    uint8_t eh[32];
    crypto_hash(CRYPTO_SHA256, "", 0, eh);
    crypto_hkdf_expand_label(CRYPTO_SHA256, prk, 32, "derived", eh, 32, out, 32);
    if (!hexeq(out, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba", 32))
        return fail(err, errlen, "HKDF-Expand-Label");

    /* CRC-32 / base64(RFC 4648 10 章)*/
    if (crypto_crc32("123456789", 9) != 0xCBF43926u) return fail(err, errlen, "CRC-32");
    static const char *const b64in[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
    static const char *const b64out[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };
    for (unsigned i = 0; i < 7; i++) {
        char enc[16];
        uint8_t dec[16];
        crypto_base64_encode(b64in[i], strlen(b64in[i]), enc);
        if (strcmp(enc, b64out[i]) != 0) return fail(err, errlen, "base64 encode");
        const int n = crypto_base64_decode(b64out[i], strlen(b64out[i]), dec, sizeof(dec));
        if (n != (int)strlen(b64in[i]) || memcmp(dec, b64in[i], (size_t)n) != 0)
            return fail(err, errlen, "base64 decode");
    }
    if (crypto_base64_decode("Zm9v!A==", 8, out, sizeof(out)) != -1) return fail(err, errlen, "base64 不正文字");

    /* ffdhe: 指数 x1 = 01 02 .. 40、x2 = 41 42 .. 80(各 64 バイト)で
     * 2^x1 と (2^x2)^x1 を計算し、SHA-256 を比べる。期待値は Python の
     * 組み込みの整数(pow)で計算したもの。共有秘密は部分群の検査を含むので
     * 起動を遅くしない 2048 / 3072 だけ。 */
    static const char *const want_dh[5][2] = {
        { "1908b0773912e53f8b481d76c9723f551e22e7edcee9e562bf0cc763a9ce3958",
          "17947c482b7dbb4197a9e9319cba6a569535dbc12000e94f4231ce7c2baf3efd" },
        { "e9f81f609bb558fd1ea247cff217d7681f14a9b132cb0c93203a873ad800ca24",
          "7d2ba81f1cfac146cf48854b3b798d8a6e75aa089cc1e857af17ffef471bc03d" },
        { "a53688d3a4d42b2c60ebff8551c83d059a0415eea23c365d1e190ebaff879f1c", NULL },
        { "21ff5bd61a7d69b1817b7ae910dc291ab6c5f4d60aa562b30c987dda2f0f9157", NULL },
        { "b2f1e92b44e0a45ee7b23938bfd9be352a84ab3878fa0afae756e3c4f6999e9e", NULL },
    };
    {
        static uint8_t y1[CRYPTO_FFDHE_MAX_LEN], y2[CRYPTO_FFDHE_MAX_LEN], z[CRYPTO_FFDHE_MAX_LEN];
        uint8_t x1[CRYPTO_FFDHE_PRIV_LEN], x2[CRYPTO_FFDHE_PRIV_LEN], d[32];
        for (unsigned i = 0; i < CRYPTO_FFDHE_PRIV_LEN; i++) {
            x1[i] = (uint8_t)(1u + i);
            x2[i] = (uint8_t)(65u + i);
        }
        for (unsigned g = 1; g <= 5; g++) {
            const size_t n = crypto_ffdhe_len(g);
            crypto_ffdhe_public(g, x1, y1);
            crypto_hash(CRYPTO_SHA256, y1, n, d);
            if (!hexeq(d, want_dh[g - 1][0], 32)) return fail(err, errlen, "ffdhe 公開値");
            if (want_dh[g - 1][1] == NULL) continue;
            crypto_ffdhe_public(g, x2, y2);
            if (crypto_ffdhe_shared(g, x1, y2, n, z) != 0) return fail(err, errlen, "ffdhe 公開値の検査");
            crypto_hash(CRYPTO_SHA256, z, n, d);
            if (!hexeq(d, want_dh[g - 1][1], 32)) return fail(err, errlen, "ffdhe 共有秘密");
            /* 陰性対照: 1 と p-1 は弾く(部分群の検査より先に範囲で落ちる)。 */
            memset(y2, 0, n);
            y2[n - 1] = 1;
            if (crypto_ffdhe_shared(g, x1, y2, n, z) == 0) return fail(err, errlen, "ffdhe y=1 を受け付けた");
        }
    }

    /* AES-128(FIPS-197 付録 C.1)と GCM(McGrew & Viega の Test Case 4:
     * 60 バイトの平文 = 端数ブロックあり、20 バイトの AAD)。 */
    {
        static const uint8_t k0[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        static const uint8_t p0[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        crypto_aes128_encrypt_block(k0, p0, out);
        if (!hexeq(out, "69c4e0d86a7b0430d8cdb78070b4c55a", 16)) return fail(err, errlen, "AES-128");

        uint8_t key[16], iv[12], aad[20], pt[60], ct[60], tag[16], back[60];
        unhex("feffe9928665731c6d6a8f9467308308", key, 16);
        unhex("cafebabefacedbaddecaf888", iv, 12);
        unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 20);
        unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", pt, 60);
        crypto_aes128gcm_t g;
        crypto_aes128gcm_init(&g, key);
        crypto_aes128gcm_seal(&g, iv, aad, 20, pt, 60, ct, tag);
        if (!hexeq(ct, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                       "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", 60))
            return fail(err, errlen, "AES-GCM 暗号文");
        if (!hexeq(tag, "5bc94fbc3221a5db94fae95ae7121a47", 16)) return fail(err, errlen, "AES-GCM タグ");
        if (crypto_aes128gcm_open(&g, iv, aad, 20, ct, 60, back, tag) != 0 || memcmp(back, pt, 60) != 0)
            return fail(err, errlen, "AES-GCM 復号");
        /* 陰性対照: 暗号文・AAD・タグのどれを 1 ビット変えても開かない */
        ct[59] ^= 1;
        if (crypto_aes128gcm_open(&g, iv, aad, 20, ct, 60, back, tag) == 0) return fail(err, errlen, "AES-GCM 改ざん(暗号文)");
        ct[59] ^= 1; aad[0] ^= 1;
        if (crypto_aes128gcm_open(&g, iv, aad, 20, ct, 60, back, tag) == 0) return fail(err, errlen, "AES-GCM 改ざん(AAD)");
        aad[0] ^= 1; tag[15] ^= 0x80;
        if (crypto_aes128gcm_open(&g, iv, aad, 20, ct, 60, back, tag) == 0) return fail(err, errlen, "AES-GCM 改ざん(タグ)");
    }

    /* X25519(RFC 7748 5.2 の 1 本目と 6.1 の鍵交換)*/
    {
        uint8_t s[32], u[32], r[32], a[32], b[32], pa[32], pb[32];
        static const uint8_t base[32] = { 9 };
        unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", s, 32);
        unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
        crypto_x25519(r, s, u);
        if (!hexeq(r, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", 32))
            return fail(err, errlen, "X25519 5.2");
        unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a, 32);
        unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b, 32);
        crypto_x25519(pa, a, base);
        crypto_x25519(pb, b, base);
        if (!hexeq(pa, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32) ||
            !hexeq(pb, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", 32))
            return fail(err, errlen, "X25519 公開値");
        crypto_x25519(r, a, pb);
        if (!hexeq(r, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32))
            return fail(err, errlen, "X25519 共有秘密");
        /* 陰性対照: 位数 1 の点(u=0)は全 0 になるので拒否する */
        memset(u, 0, 32);
        if (crypto_x25519(r, a, u) == 0) return fail(err, errlen, "X25519 小位数の点を受け付けた");
    }

    /* 比較(陰性対照つき)と乱数(全部 0 は返さない、2 回で違う値)*/
    if (!crypto_equal("abcd", "abcd", 4) || crypto_equal("abcd", "abce", 4)) return fail(err, errlen, "crypto_equal");
    uint8_t r1[32], r2[32];
    if (crypto_random(r1, 32) || crypto_random(r2, 32) || crypto_equal(r1, r2, 32))
        return fail(err, errlen, "crypto_random");
    return 0;
}
