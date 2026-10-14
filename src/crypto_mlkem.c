/* ML-KEM-1024(FIPS 203)。CNSA 2.0 の鍵共有(PLAN_cnsa2.md 段階 1)。
 *
 * FIPS 203 の擬似コードをそのまま写した素直な実装で、係数は常に [0, q) の整数で持つ
 * (Montgomery 表現や Barrett 還元は使わない。q = 3329 での剰余はコンパイラが定数の
 * 掛け算に直すので、秘密の値で分岐も可変時間の除算もしない)。鍵共有は握手のときに
 * 1 回だけなので速さは要らない。
 *
 * 写した箇所(FIPS 203 の節):
 *   - 4.2.1 の H / G / J / PRF / XOF   = SHA3-256 / SHA3-512 / SHAKE256(32) / SHAKE256 / SHAKE128
 *   - 4.2.2 SampleNTT / SamplePolyCBD、4.3 NTT / NTT^-1 / MultiplyNTTs、4.2.1 Compress / ByteEncode
 *   - 5 章 K-PKE、6 章 ML-KEM の内部関数、7 章の入力検査(カプセル化鍵の剰余の検査、
 *     復号鍵の中のハッシュの検査)
 *
 * 正しさは tools/crypto_check.c が OpenSSL 3.5 と突き合わせる(種から作った鍵、ikme を与えた
 * カプセル化、両方向の復号、壊した暗号文での暗黙の拒否の値)。
 */
#include "crypto.h"

#include <string.h>

#define Q     3329
#define KK    4          /* ML-KEM-1024 の k */
#define ETA1  2
#define ETA2  2
#define DU    11
#define DV    5

typedef struct { int16_t c[256]; } poly;   /* 係数は [0, q) */

/* ζ^BitRev7(i) mod q(FIPS 203 付録 A の NTT 用)と、ζ^(2 BitRev7(i) + 1)(MultiplyNTTs 用)。 */
static const int16_t ZETA[128] = {
       1, 1729, 2580, 3289, 2642,  630, 1897,  848, 1062, 1919,  193,  797, 2786, 3260,  569, 1746,
     296, 2447, 1339, 1476, 3046,   56, 2240, 1333, 1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
     289,  331, 3253, 1756, 1197, 2304, 2277, 2055,  650, 1977, 2513,  632, 2865,   33, 1320, 1915,
    2319, 1435,  807,  452, 1438, 2868, 1534, 2402, 2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
      17, 2761,  583, 2649, 1637,  723, 2288, 1100, 1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,  939, 2308, 2437, 2388,  733, 2337,  268,  641,
    1584, 2298, 2037, 3220,  375, 2549, 2090, 1645, 1063,  319, 2773,  757, 2099,  561, 2466, 2594,
    2804, 1092,  403, 1026, 1143, 2150, 2775,  886, 1722, 1212, 1874, 1029, 2110, 2935,  885, 2154,
};
static const int16_t GAMMA[128] = {
      17, 3312, 2761,  568,  583, 2746, 2649,  680, 1637, 1692,  723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662,  667, 3281,   48,  233, 3096,  756, 2573, 2156, 1173, 3015,  314, 3050,  279,
    1703, 1626, 1651, 1678, 2789,  540, 1789, 1540, 1847, 1482,  952, 2377, 1461, 1868, 2687,  642,
     939, 2390, 2308, 1021, 2437,  892, 2388,  941,  733, 2596, 2337,  992,  268, 3061,  641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220,  109,  375, 2954, 2549,  780, 2090, 1239, 1645, 1684,
    1063, 2266,  319, 3010, 2773,  556,  757, 2572, 2099, 1230,  561, 2768, 2466,  863, 2594,  735,
    2804,  525, 1092, 2237,  403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775,  554,  886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935,  394,  885, 2444, 2154, 1175,
};

static inline int16_t mq(int32_t x) { return (int16_t)(((x % Q) + Q) % Q); }

/* ---- NTT(FIPS 203 Algorithm 9 / 10)---- */
static void ntt(poly *f) {
    unsigned k = 1;
    for (unsigned len = 128; len >= 2; len >>= 1) {
        for (unsigned start = 0; start < 256; start += 2u * len) {
            const int32_t z = ZETA[k++];
            for (unsigned j = start; j < start + len; j++) {
                const int32_t t = (z * f->c[j + len]) % Q;
                f->c[j + len] = mq(f->c[j] - t);
                f->c[j] = mq(f->c[j] + t);
            }
        }
    }
}

static void invntt(poly *f) {
    unsigned k = 127;
    for (unsigned len = 2; len <= 128; len <<= 1) {
        for (unsigned start = 0; start < 256; start += 2u * len) {
            const int32_t z = ZETA[k--];
            for (unsigned j = start; j < start + len; j++) {
                const int32_t t = f->c[j];
                f->c[j] = mq(t + f->c[j + len]);
                f->c[j + len] = mq(z * mq(f->c[j + len] - t));
            }
        }
    }
    for (unsigned i = 0; i < 256; i++) f->c[i] = mq((int32_t)f->c[i] * 3303);   /* 128^-1 mod q */
}

/* h += f * g(NTT 領域、Algorithm 11 / 12)。 */
static void basemul_acc(poly *h, const poly *f, const poly *g) {
    for (unsigned i = 0; i < 128; i++) {
        const int32_t a0 = f->c[2 * i], a1 = f->c[2 * i + 1], b0 = g->c[2 * i], b1 = g->c[2 * i + 1];
        const int32_t c0 = mq(a0 * b0 + mq(a1 * b1) * GAMMA[i]);
        const int32_t c1 = mq(a0 * b1 + a1 * b0);
        h->c[2 * i] = mq(h->c[2 * i] + c0);
        h->c[2 * i + 1] = mq(h->c[2 * i + 1] + c1);
    }
}

static void poly_add(poly *a, const poly *b) {
    for (unsigned i = 0; i < 256; i++) a->c[i] = mq(a->c[i] + b->c[i]);
}

/* ---- 符号化(Algorithm 5 / 6)と圧縮(4.2.1)---- */
static void byte_encode(unsigned d, const poly *f, uint8_t *out) {
    uint32_t acc = 0;
    unsigned bits = 0, o = 0;
    for (unsigned i = 0; i < 256; i++) {
        acc |= (uint32_t)f->c[i] << bits;
        bits += d;
        while (bits >= 8) {
            out[o++] = (uint8_t)acc;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/* d = 12 のときは q で剰余を取る(FIPS 203 の ByteDecode_12)。 */
static void byte_decode(unsigned d, const uint8_t *in, poly *f) {
    uint32_t acc = 0;
    unsigned bits = 0, o = 0;
    const uint32_t mask = (1u << d) - 1u;
    for (unsigned i = 0; i < 256; i++) {
        while (bits < d) {
            acc |= (uint32_t)in[o++] << bits;
            bits += 8;
        }
        const uint32_t v = acc & mask;
        acc >>= d;
        bits -= d;
        f->c[i] = (int16_t)(d == 12 ? v % Q : v);
    }
}

static void compress(unsigned d, poly *f) {
    for (unsigned i = 0; i < 256; i++)
        f->c[i] = (int16_t)(((((uint32_t)f->c[i] << d) + Q / 2) / Q) & ((1u << d) - 1u));
}

static void decompress(unsigned d, poly *f) {
    for (unsigned i = 0; i < 256; i++)
        f->c[i] = (int16_t)(((uint32_t)f->c[i] * Q + (1u << (d - 1))) >> d);
}

/* ---- 標本(Algorithm 7 / 8)---- */
static void sample_ntt(const uint8_t rho[32], uint8_t j, uint8_t i, poly *a) {
    crypto_shake_t x;
    uint8_t seed[34], b[168];
    memcpy(seed, rho, 32);
    seed[32] = j;
    seed[33] = i;
    crypto_shake_init(&x, 128);
    crypto_shake_absorb(&x, seed, sizeof(seed));
    unsigned n = 0, pos = sizeof(b);
    while (n < 256) {
        if (pos + 3 > sizeof(b)) {   /* 168 は 3 の倍数なのでブロックの境目でちょうど尽きる */
            crypto_shake_squeeze(&x, b, sizeof(b));
            pos = 0;
        }
        const uint32_t d1 = b[pos] | ((uint32_t)(b[pos + 1] & 0x0F) << 8);
        const uint32_t d2 = (b[pos + 1] >> 4) | ((uint32_t)b[pos + 2] << 4);
        pos += 3;
        if (d1 < Q) a->c[n++] = (int16_t)d1;
        if (d2 < Q && n < 256) a->c[n++] = (int16_t)d2;
    }
}

/* PRF_eta(s, b) = SHAKE256(s || b, 64 eta) から CBD_eta で 1 本(eta = 2 のみ)。 */
static void sample_cbd2(const uint8_t s[32], uint8_t nonce, poly *f) {
    uint8_t in[33], B[64 * 2];
    memcpy(in, s, 32);
    in[32] = nonce;
    crypto_shake(256, in, sizeof(in), B, sizeof(B));
    for (unsigned i = 0; i < 256; i++) {
        unsigned x = 0, y = 0;
        for (unsigned j = 0; j < 2; j++) {
            const unsigned bx = 4 * i + j, by = 4 * i + 2 + j;
            x += (B[bx / 8] >> (bx % 8)) & 1u;
            y += (B[by / 8] >> (by % 8)) & 1u;
        }
        f->c[i] = mq((int32_t)x - (int32_t)y);
    }
    crypto_wipe(B, sizeof(B));
}

/* ---- K-PKE(5 章)---- */

/* ek_pke(1568)と dk_pke(1536)。 */
static void kpke_keygen(const uint8_t d[32], uint8_t *ek, uint8_t *dkp) {
    uint8_t in[33], g[64];
    memcpy(in, d, 32);
    in[32] = KK;
    crypto_hash(CRYPTO_SHA3_512, in, sizeof(in), g);
    const uint8_t *rho = g, *sigma = g + 32;
    poly s[KK], e, t, a;
    uint8_t n = 0;
    for (unsigned i = 0; i < KK; i++) { sample_cbd2(sigma, n++, &s[i]); ntt(&s[i]); }
    for (unsigned i = 0; i < KK; i++) {
        sample_cbd2(sigma, (uint8_t)(n + i), &e);
        ntt(&e);
        memset(&t, 0, sizeof(t));
        for (unsigned j = 0; j < KK; j++) {
            sample_ntt(rho, (uint8_t)j, (uint8_t)i, &a);   /* Â[i, j] = SampleNTT(rho || j || i) */
            basemul_acc(&t, &a, &s[j]);
        }
        poly_add(&t, &e);
        byte_encode(12, &t, ek + 384 * i);
    }
    memcpy(ek + 384 * KK, rho, 32);
    for (unsigned i = 0; i < KK; i++) byte_encode(12, &s[i], dkp + 384 * i);
    crypto_wipe(s, sizeof(s));
    crypto_wipe(&e, sizeof(e));
    crypto_wipe(g, sizeof(g));
    crypto_wipe(in, sizeof(in));
}

static void kpke_encrypt(const uint8_t *ek, const uint8_t m[32], const uint8_t r[32], uint8_t *ct) {
    const uint8_t *rho = ek + 384 * KK;
    poly y[KK], th, a, u, v, e;
    for (unsigned i = 0; i < KK; i++) { sample_cbd2(r, (uint8_t)i, &y[i]); ntt(&y[i]); }
    for (unsigned i = 0; i < KK; i++) {
        memset(&u, 0, sizeof(u));
        for (unsigned j = 0; j < KK; j++) {
            sample_ntt(rho, (uint8_t)i, (uint8_t)j, &a);   /* Â[j, i](転置)= SampleNTT(rho || i || j) */
            basemul_acc(&u, &a, &y[j]);
        }
        invntt(&u);
        sample_cbd2(r, (uint8_t)(KK + i), &e);   /* e1 */
        poly_add(&u, &e);
        compress(DU, &u);
        byte_encode(DU, &u, ct + 32 * DU * i);
    }
    memset(&v, 0, sizeof(v));
    for (unsigned i = 0; i < KK; i++) {
        byte_decode(12, ek + 384 * i, &th);
        basemul_acc(&v, &th, &y[i]);
    }
    invntt(&v);
    sample_cbd2(r, (uint8_t)(2 * KK), &e);   /* e2 */
    poly_add(&v, &e);
    for (unsigned i = 0; i < 256; i++)       /* mu = Decompress_1(ByteDecode_1(m)) */
        v.c[i] = mq(v.c[i] + (int32_t)((m[i / 8] >> (i % 8)) & 1u) * ((Q + 1) / 2));
    compress(DV, &v);
    byte_encode(DV, &v, ct + 32 * DU * KK);
    crypto_wipe(y, sizeof(y));
    crypto_wipe(&e, sizeof(e));
    crypto_wipe(&v, sizeof(v));
}

static void kpke_decrypt(const uint8_t *dkp, const uint8_t *ct, uint8_t m[32]) {
    poly w, u, s, v;
    memset(&w, 0, sizeof(w));
    for (unsigned i = 0; i < KK; i++) {
        byte_decode(DU, ct + 32 * DU * i, &u);
        decompress(DU, &u);
        ntt(&u);
        byte_decode(12, dkp + 384 * i, &s);
        basemul_acc(&w, &s, &u);
    }
    invntt(&w);
    byte_decode(DV, ct + 32 * DU * KK, &v);
    decompress(DV, &v);
    for (unsigned i = 0; i < 256; i++) v.c[i] = mq(v.c[i] - w.c[i]);
    compress(1, &v);
    memset(m, 0, 32);
    for (unsigned i = 0; i < 256; i++) m[i / 8] |= (uint8_t)(v.c[i] << (i % 8));
    crypto_wipe(&s, sizeof(s));
    crypto_wipe(&v, sizeof(v));
    crypto_wipe(&w, sizeof(w));
}

/* ---- ML-KEM(6 章 / 7 章)---- */

int crypto_mlkem1024_keygen_seed(const uint8_t d[32], const uint8_t z[32], uint8_t *ek, uint8_t *dk) {
    kpke_keygen(d, ek, dk);                                   /* dk = dk_pke || ek || H(ek) || z */
    memcpy(dk + 384 * KK, ek, CRYPTO_MLKEM1024_EK_LEN);
    crypto_hash(CRYPTO_SHA3_256, ek, CRYPTO_MLKEM1024_EK_LEN, dk + 384 * KK + CRYPTO_MLKEM1024_EK_LEN);
    memcpy(dk + 384 * KK + CRYPTO_MLKEM1024_EK_LEN + 32, z, 32);
    return 0;
}

int crypto_mlkem1024_keygen(uint8_t *ek, uint8_t *dk) {
    uint8_t dz[64];
    if (crypto_random(dz, sizeof(dz)) != 0) return -1;
    crypto_mlkem1024_keygen_seed(dz, dz + 32, ek, dk);
    crypto_wipe(dz, sizeof(dz));
    return 0;
}

/* カプセル化鍵の検査(7.2): t の 12 ビットの値が全部 q 未満であること。 */
static int ek_ok(const uint8_t *ek) {
    for (unsigned i = 0; i < 384 * KK; i += 3) {
        const uint32_t d1 = ek[i] | ((uint32_t)(ek[i + 1] & 0x0F) << 8);
        const uint32_t d2 = (ek[i + 1] >> 4) | ((uint32_t)ek[i + 2] << 4);
        if (d1 >= Q || d2 >= Q) return 0;
    }
    return 1;
}

int crypto_mlkem1024_encaps_seed(const uint8_t *ek, const uint8_t m[32], uint8_t *ct, uint8_t ss[32]) {
    if (!ek_ok(ek)) return -1;
    uint8_t in[64], kr[64];
    memcpy(in, m, 32);
    crypto_hash(CRYPTO_SHA3_256, ek, CRYPTO_MLKEM1024_EK_LEN, in + 32);   /* (K, r) = G(m || H(ek)) */
    crypto_hash(CRYPTO_SHA3_512, in, sizeof(in), kr);
    kpke_encrypt(ek, m, kr + 32, ct);
    memcpy(ss, kr, 32);
    crypto_wipe(in, sizeof(in));
    crypto_wipe(kr, sizeof(kr));
    return 0;
}

int crypto_mlkem1024_encaps(const uint8_t *ek, uint8_t *ct, uint8_t ss[32]) {
    uint8_t m[32];
    if (crypto_random(m, sizeof(m)) != 0) return -1;
    const int r = crypto_mlkem1024_encaps_seed(ek, m, ct, ss);
    crypto_wipe(m, sizeof(m));
    return r;
}

/* 復号鍵の検査(7.3): 中に入っている H(ek) が ek のハッシュと一致すること。
 * 暗号文が壊れていても失敗は返さず、J(z || c) の値(暗黙の拒否)を共有秘密にする。 */
int crypto_mlkem1024_decaps(const uint8_t *dk, const uint8_t *ct, uint8_t ss[32]) {
    const uint8_t *dkp = dk, *ek = dk + 384 * KK, *h = ek + CRYPTO_MLKEM1024_EK_LEN, *z = h + 32;
    uint8_t hh[32];
    crypto_hash(CRYPTO_SHA3_256, ek, CRYPTO_MLKEM1024_EK_LEN, hh);
    if (!crypto_equal(hh, h, 32)) return -1;
    uint8_t in[64], kr[64], kbar[32];
    uint8_t ct2[CRYPTO_MLKEM1024_CT_LEN];
    kpke_decrypt(dkp, ct, in);                               /* m' */
    memcpy(in + 32, h, 32);
    crypto_hash(CRYPTO_SHA3_512, in, sizeof(in), kr);        /* (K', r') = G(m' || h) */
    crypto_shake_t x;                                        /* K̄ = J(z || c) */
    crypto_shake_init(&x, 256);
    crypto_shake_absorb(&x, z, 32);
    crypto_shake_absorb(&x, ct, CRYPTO_MLKEM1024_CT_LEN);
    crypto_shake_squeeze(&x, kbar, 32);
    kpke_encrypt(ek, in, kr + 32, ct2);
    /* c == c' なら K'、違えば K̄。定数時間で選ぶ。 */
    const uint8_t keep = (uint8_t)(0u - (unsigned)crypto_equal(ct, ct2, CRYPTO_MLKEM1024_CT_LEN));
    for (unsigned i = 0; i < 32; i++) ss[i] = (uint8_t)((kr[i] & keep) | (kbar[i] & (uint8_t)~keep));
    crypto_wipe(in, sizeof(in));
    crypto_wipe(kr, sizeof(kr));
    crypto_wipe(kbar, sizeof(kbar));
    crypto_wipe(&x, sizeof(x));
    return 0;
}
