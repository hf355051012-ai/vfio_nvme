/* 有限体 Diffie-Hellman(RFC 7919 の ffdhe2048〜8192)と、そのための大数の冪剰余。
 * PLAN_auth_tls.md 段階 B(DH-HMAC-CHAP の DH 群)。
 *
 * 64 ビットの limb で Montgomery 乗算(CIOS)をし、4 ビットの固定窓で冪乗する。
 * 接続時にしか使わないので速さより分かりやすさを優先した。**定数時間ではない**
 * (実験用の実装。crypto.h の注記どおり)。
 *
 * 値の受け渡しはビッグエンディアンのバイト列で、**長さは素数の長さに 0 詰めする**
 * (Linux の dh_compute_value() -> mpi_write_to_sgl() と同じ。共有秘密はこの
 * 長さのままハッシュされるので、詰め方が違うと認証が通らない)。
 */
#include "crypto.h"
#include "ffdhe_primes.h"

#include <string.h>

#define BN_LIMBS_MAX 128u   /* 8192 ビット */

typedef struct {
    unsigned n;                    /* limb 数 */
    uint64_t p[BN_LIMBS_MAX];      /* 法(奇数)。limb は下位から */
    uint64_t n0;                   /* -p^-1 mod 2^64 */
    uint64_t rr[BN_LIMBS_MAX];     /* R^2 mod p(R = 2^(64n))*/
} mont_t;

static void be_to_limbs(const uint8_t *in, size_t len, uint64_t *out, unsigned n) {
    memset(out, 0, (size_t)n * 8u);
    for (size_t i = 0; i < len && i < (size_t)n * 8u; i++) {
        out[i / 8u] |= (uint64_t)in[len - 1u - i] << (8u * (i % 8u));
    }
}

static void limbs_to_be(const uint64_t *in, unsigned n, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[len - 1u - i] = (i < (size_t)n * 8u) ? (uint8_t)(in[i / 8u] >> (8u * (i % 8u))) : 0u;
    }
}

static int bn_cmp(const uint64_t *a, const uint64_t *b, unsigned n) {
    for (unsigned i = n; i-- > 0;) {
        if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
    }
    return 0;
}

static uint64_t bn_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, unsigned n) {
    uint64_t borrow = 0;
    for (unsigned i = 0; i < n; i++) {
        const unsigned __int128 d = (unsigned __int128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1u;
    }
    return borrow;
}

/* r = a * b * R^-1 mod p(a, b < p)。r は a / b と同じ領域でもよい。 */
static void mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, const mont_t *m) {
    const unsigned n = m->n;
    uint64_t t[BN_LIMBS_MAX + 2];
    memset(t, 0, sizeof(uint64_t) * (n + 2u));
    for (unsigned i = 0; i < n; i++) {
        uint64_t c = 0;
        for (unsigned j = 0; j < n; j++) {
            const unsigned __int128 v = (unsigned __int128)a[j] * b[i] + t[j] + c;
            t[j] = (uint64_t)v;
            c = (uint64_t)(v >> 64);
        }
        unsigned __int128 v = (unsigned __int128)t[n] + c;
        t[n] = (uint64_t)v;
        t[n + 1] = (uint64_t)(v >> 64);

        const uint64_t q = t[0] * m->n0;
        v = (unsigned __int128)q * m->p[0] + t[0];
        c = (uint64_t)(v >> 64);
        for (unsigned j = 1; j < n; j++) {
            v = (unsigned __int128)q * m->p[j] + t[j] + c;
            t[j - 1] = (uint64_t)v;
            c = (uint64_t)(v >> 64);
        }
        v = (unsigned __int128)t[n] + c;
        t[n - 1] = (uint64_t)v;
        t[n] = t[n + 1] + (uint64_t)(v >> 64);
    }
    if (t[n] != 0 || bn_cmp(t, m->p, n) >= 0) {
        bn_sub(r, t, m->p, n);
    } else {
        memcpy(r, t, (size_t)n * 8u);
    }
}

/* 法を受け取って Montgomery の準備をする。法は奇数で 8192 ビット以下。 */
static int mont_setup(mont_t *m, const uint8_t *mod, size_t mlen) {
    while (mlen && mod[0] == 0) { mod++; mlen--; }
    if (mlen == 0 || mlen > BN_LIMBS_MAX * 8u || !(mod[mlen - 1] & 1u)) return -1;
    m->n = (unsigned)((mlen + 7u) / 8u);
    be_to_limbs(mod, mlen, m->p, m->n);
    /* p0^-1 mod 2^64 をニュートン法で(1 回ごとに正しいビット数が倍になる)。 */
    uint64_t inv = m->p[0];
    for (unsigned i = 0; i < 6; i++) inv *= 2u - m->p[0] * inv;
    m->n0 = (uint64_t)0 - inv;
    /* R^2 mod p: 1 を 2 * 64n 回 2 倍して、そのつど p を超えたら引く。 */
    uint64_t x[BN_LIMBS_MAX];
    memset(x, 0, sizeof(x));
    x[0] = 1;
    for (unsigned k = 0; k < 128u * m->n; k++) {
        uint64_t carry = 0;
        for (unsigned i = 0; i < m->n; i++) {
            const uint64_t nc = x[i] >> 63;
            x[i] = (x[i] << 1) | carry;
            carry = nc;
        }
        if (carry || bn_cmp(x, m->p, m->n) >= 0) bn_sub(x, x, m->p, m->n);
    }
    memcpy(m->rr, x, sizeof(uint64_t) * m->n);
    return 0;
}

/* out = base^exp mod p(base < p は呼び出し側が保証する)。4 ビットの固定窓。 */
static void mont_pow(uint64_t *out, const uint64_t *base, const uint8_t *exp, size_t elen,
                     const mont_t *m) {
    static uint64_t tab[16][BN_LIMBS_MAX];   /* base^0..15(Montgomery 形)*/
    const unsigned n = m->n;
    uint64_t one[BN_LIMBS_MAX];
    memset(one, 0, sizeof(one));
    one[0] = 1;
    mont_mul(tab[0], one, m->rr, m);       /* 1 * R mod p */
    mont_mul(tab[1], base, m->rr, m);      /* base * R mod p */
    for (unsigned i = 2; i < 16; i++) mont_mul(tab[i], tab[i - 1], tab[1], m);
    uint64_t acc[BN_LIMBS_MAX];
    memcpy(acc, tab[0], (size_t)n * 8u);
    for (size_t i = 0; i < elen; i++) {
        for (unsigned half = 0; half < 2; half++) {
            const unsigned w = half ? (exp[i] & 0x0Fu) : (exp[i] >> 4);
            for (unsigned s = 0; s < 4; s++) mont_mul(acc, acc, acc, m);
            if (w) mont_mul(acc, acc, tab[w], m);
        }
    }
    mont_mul(out, acc, one, m);            /* Montgomery 形から戻す */
}

int crypto_modexp(const uint8_t *base, size_t blen, const uint8_t *exp, size_t elen,
                  const uint8_t *mod, size_t mlen, uint8_t *out) {
    static mont_t m;
    if (mont_setup(&m, mod, mlen) != 0) return -1;
    uint64_t b[BN_LIMBS_MAX];
    while (blen && base[0] == 0) { base++; blen--; }
    if (blen > (size_t)m.n * 8u) return -1;
    be_to_limbs(base, blen, b, m.n);
    if (bn_cmp(b, m.p, m.n) >= 0) return -1;
    uint64_t r[BN_LIMBS_MAX];
    mont_pow(r, b, exp, elen, &m);
    limbs_to_be(r, m.n, out, mlen);
    return 0;
}

/* ------------------------------------------------------------------ */

static const uint8_t *ffdhe_p(unsigned gid, size_t *len) {
    switch (gid) {
    case CRYPTO_FFDHE2048: *len = sizeof(FFDHE2048_P); return FFDHE2048_P;
    case CRYPTO_FFDHE3072: *len = sizeof(FFDHE3072_P); return FFDHE3072_P;
    case CRYPTO_FFDHE4096: *len = sizeof(FFDHE4096_P); return FFDHE4096_P;
    case CRYPTO_FFDHE6144: *len = sizeof(FFDHE6144_P); return FFDHE6144_P;
    case CRYPTO_FFDHE8192: *len = sizeof(FFDHE8192_P); return FFDHE8192_P;
    default: *len = 0; return NULL;
    }
}

size_t crypto_ffdhe_len(unsigned gid) {
    size_t len;
    return ffdhe_p(gid, &len) ? len : 0u;
}

/* 群ごとの Montgomery の準備は一度だけ(R^2 の計算に 8192 ビットで数 ms かかる)。 */
static const mont_t *ffdhe_mont(unsigned gid) {
    static mont_t m[6];
    static int ready[6];
    size_t len;
    const uint8_t *p = ffdhe_p(gid, &len);
    if (p == NULL) return NULL;
    if (!ready[gid]) {
        if (mont_setup(&m[gid], p, len) != 0) return NULL;
        ready[gid] = 1;
    }
    return &m[gid];
}

static int ffdhe_pow(unsigned gid, const uint64_t *base, const uint8_t *exp, size_t elen, uint8_t *out) {
    const mont_t *m = ffdhe_mont(gid);
    if (m == NULL) return -1;
    uint64_t r[BN_LIMBS_MAX];
    mont_pow(r, base, exp, elen, m);
    limbs_to_be(r, m->n, out, (size_t)m->n * 8u);
    return 0;
}

int crypto_ffdhe_public(unsigned gid, const uint8_t priv[CRYPTO_FFDHE_PRIV_LEN], uint8_t *pub) {
    const mont_t *m = ffdhe_mont(gid);
    if (m == NULL) return -1;
    uint64_t g[BN_LIMBS_MAX];
    memset(g, 0, sizeof(g));
    g[0] = 2;   /* RFC 7919 の生成元 */
    return ffdhe_pow(gid, g, priv, CRYPTO_FFDHE_PRIV_LEN, pub);
}

int crypto_ffdhe_keygen(unsigned gid, uint8_t priv[CRYPTO_FFDHE_PRIV_LEN], uint8_t *pub) {
    if (crypto_ffdhe_len(gid) == 0) return -1;
    if (crypto_random(priv, CRYPTO_FFDHE_PRIV_LEN) != 0) return -1;
    priv[0] |= 0x80u;   /* 指数を短くしない(512 ビットちょうどにする)*/
    return crypto_ffdhe_public(gid, priv, pub);
}

int crypto_ffdhe_shared(unsigned gid, const uint8_t priv[CRYPTO_FFDHE_PRIV_LEN],
                        const uint8_t *peer, size_t peerlen, uint8_t *out) {
    const mont_t *m = ffdhe_mont(gid);
    if (m == NULL || peerlen == 0 || peerlen > (size_t)m->n * 8u) return -1;
    /* 相手の公開値を確かめる(Linux の dh_is_pubkey_valid() と同じ):
     *   1 < y < p - 1、かつ y^q = 1(q = (p - 1) / 2。素数位数の部分群に居る)。
     * 確かめないと、y = 1 や p - 1 を送られたとき共有秘密が相手の思いどおりになる。 */
    uint64_t y[BN_LIMBS_MAX], pm1[BN_LIMBS_MAX], one[BN_LIMBS_MAX];
    be_to_limbs(peer, peerlen, y, m->n);
    memset(one, 0, sizeof(one));
    one[0] = 1;
    bn_sub(pm1, m->p, one, m->n);
    if (bn_cmp(y, one, m->n) <= 0 || bn_cmp(y, pm1, m->n) >= 0) return -2;
    uint8_t q[BN_LIMBS_MAX * 8u];
    const size_t plen = (size_t)m->n * 8u;
    {
        uint64_t ql[BN_LIMBS_MAX];
        for (unsigned i = 0; i < m->n; i++) {   /* q = (p - 1) >> 1 */
            ql[i] = (pm1[i] >> 1) | (i + 1u < m->n ? pm1[i + 1u] << 63 : 0u);
        }
        limbs_to_be(ql, m->n, q, plen);
    }
    uint8_t chk[BN_LIMBS_MAX * 8u];
    ffdhe_pow(gid, y, q, plen, chk);
    for (size_t i = 0; i + 1u < plen; i++) {
        if (chk[i] != 0) return -3;
    }
    if (chk[plen - 1u] != 1u) return -3;
    return ffdhe_pow(gid, y, priv, CRYPTO_FFDHE_PRIV_LEN, out);
}
