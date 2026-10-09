/* X25519(RFC 7748、PLAN_auth_tls.md 段階 0')。
 *
 * Linux の tlshd(GnuTLS)は NVMe/TCP の TLS 握手で psk_dhe_ke しか出さず、
 * key_share に secp256r1 と x25519 を入れてくる(段階 D の調査で実測)。
 * x25519 だけ答えれば足りるので、楕円曲線はこれ 1 つ。
 *
 * 体の元は 2^51 進 5 桁(unsigned __int128 で掛ける)。梯子は RFC 7748 5 章の
 * 擬似コードそのまま。定数時間の cswap を使う。
 */
#include "crypto.h"

#include <string.h>

typedef uint64_t fe[5];
typedef unsigned __int128 u128;
#define MASK51 0x7FFFFFFFFFFFFull

static uint64_t ld64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void fe_frombytes(fe h, const uint8_t s[32]) {
    h[0] = ld64le(s) & MASK51;
    h[1] = (ld64le(s + 6) >> 3) & MASK51;
    h[2] = (ld64le(s + 12) >> 6) & MASK51;
    h[3] = (ld64le(s + 19) >> 1) & MASK51;
    h[4] = (ld64le(s + 24) >> 12) & MASK51;   /* 最上位ビットは捨てる(RFC 7748 5)*/
}

static void fe_carry(fe h) {
    uint64_t c;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
    c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
    c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
    c = h[4] >> 51; h[4] &= MASK51; h[0] += c * 19u;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
}

static void fe_tobytes(uint8_t s[32], const fe f) {
    fe h;
    memcpy(h, f, sizeof(fe));
    fe_carry(h);
    fe_carry(h);
    /* p 以上なら p を引く: q = (h + 19) >> 255 */
    uint64_t q = (h[0] + 19u) >> 51;
    q = (h[1] + q) >> 51;
    q = (h[2] + q) >> 51;
    q = (h[3] + q) >> 51;
    q = (h[4] + q) >> 51;
    h[0] += 19u * q;
    uint64_t c;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
    c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
    c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
    h[4] &= MASK51;
    const uint64_t t[4] = {
        h[0] | (h[1] << 51),
        (h[1] >> 13) | (h[2] << 38),
        (h[2] >> 26) | (h[3] << 25),
        (h[3] >> 39) | (h[4] << 12),
    };
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) s[8 * i + j] = (uint8_t)(t[i] >> (8 * j));
}

static void fe_add(fe h, const fe f, const fe g) {
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
    fe_carry(h);
}

/* f - g。2p を足してから引く(f, g は fe_carry 済みで各桁 2^51 + 小)。 */
static void fe_sub(fe h, const fe f, const fe g) {
    h[0] = f[0] + 0xFFFFFFFFFFFDAull - g[0];   /* 2 * (2^51 - 19) */
    for (int i = 1; i < 5; i++) h[i] = f[i] + 0xFFFFFFFFFFFFEull - g[i];   /* 2 * (2^51 - 1) */
    fe_carry(h);
}

static void fe_mul(fe h, const fe f, const fe g) {
    const uint64_t g1 = 19u * g[1], g2 = 19u * g[2], g3 = 19u * g[3], g4 = 19u * g[4];
    u128 r0 = (u128)f[0] * g[0] + (u128)f[1] * g4 + (u128)f[2] * g3 + (u128)f[3] * g2 + (u128)f[4] * g1;
    u128 r1 = (u128)f[0] * g[1] + (u128)f[1] * g[0] + (u128)f[2] * g4 + (u128)f[3] * g3 + (u128)f[4] * g2;
    u128 r2 = (u128)f[0] * g[2] + (u128)f[1] * g[1] + (u128)f[2] * g[0] + (u128)f[3] * g4 + (u128)f[4] * g3;
    u128 r3 = (u128)f[0] * g[3] + (u128)f[1] * g[2] + (u128)f[2] * g[1] + (u128)f[3] * g[0] + (u128)f[4] * g4;
    u128 r4 = (u128)f[0] * g[4] + (u128)f[1] * g[3] + (u128)f[2] * g[2] + (u128)f[3] * g[1] + (u128)f[4] * g[0];
    r1 += (uint64_t)(r0 >> 51); h[0] = (uint64_t)r0 & MASK51;
    r2 += (uint64_t)(r1 >> 51); h[1] = (uint64_t)r1 & MASK51;
    r3 += (uint64_t)(r2 >> 51); h[2] = (uint64_t)r2 & MASK51;
    r4 += (uint64_t)(r3 >> 51); h[3] = (uint64_t)r3 & MASK51;
    const uint64_t c = (uint64_t)(r4 >> 51); h[4] = (uint64_t)r4 & MASK51;
    h[0] += c * 19u;
    h[1] += h[0] >> 51; h[0] &= MASK51;
}

static void fe_mul_small(fe h, const fe f, uint64_t k) {
    u128 c = 0;
    for (int i = 0; i < 5; i++) {
        c += (u128)f[i] * k;
        h[i] = (uint64_t)c & MASK51;
        c >>= 51;
    }
    h[0] += (uint64_t)c * 19u;
    fe_carry(h);
}

/* z^(p-2)、p-2 = 2^255 - 21。素朴な二乗と掛け算(接続時に 1 回なので速さは要らない)。 */
static void fe_invert(fe out, const fe z) {
    static const uint8_t e[32] = {
        0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
    };
    fe r = { 1, 0, 0, 0, 0 };
    for (int i = 254; i >= 0; i--) {
        fe_mul(r, r, r);
        if ((e[i >> 3] >> (i & 7)) & 1) fe_mul(r, r, z);
    }
    memcpy(out, r, sizeof(fe));
}

static void fe_cswap(fe a, fe b, uint64_t swap) {
    const uint64_t m = 0u - swap;
    for (int i = 0; i < 5; i++) {
        const uint64_t t = m & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

int crypto_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t k[32];
    memcpy(k, scalar, 32);
    k[0] &= 248u; k[31] &= 127u; k[31] |= 64u;

    fe x1, x2 = { 1, 0, 0, 0, 0 }, z2 = { 0 }, x3, z3 = { 1, 0, 0, 0, 0 };
    fe_frombytes(x1, point);
    memcpy(x3, x1, sizeof(fe));
    uint64_t swap = 0;
    for (int t = 254; t >= 0; t--) {
        const uint64_t kt = (k[t >> 3] >> (t & 7)) & 1u;
        swap ^= kt;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = kt;
        fe a, aa, b, bb, e, c, d, da, cb, tmp;
        fe_add(a, x2, z2);   fe_mul(aa, a, a);
        fe_sub(b, x2, z2);   fe_mul(bb, b, b);
        fe_sub(e, aa, bb);
        fe_add(c, x3, z3);   fe_sub(d, x3, z3);
        fe_mul(da, d, a);    fe_mul(cb, c, b);
        fe_add(tmp, da, cb); fe_mul(x3, tmp, tmp);
        fe_sub(tmp, da, cb); fe_mul(tmp, tmp, tmp); fe_mul(z3, x1, tmp);
        fe_mul(x2, aa, bb);
        fe_mul_small(tmp, e, 121665u); fe_add(tmp, aa, tmp); fe_mul(z2, e, tmp);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    fe zi;
    fe_invert(zi, z2);
    fe_mul(x2, x2, zi);
    fe_tobytes(out, x2);
    crypto_wipe(k, sizeof(k));
    /* 全 0 は相手が小位数の点を送ってきた印(RFC 7748 6.1、RFC 8446 7.4.2 で拒否する)*/
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc ? 0 : -1;
}

int crypto_x25519_keygen(uint8_t priv[32], uint8_t pub[32]) {
    static const uint8_t base[32] = { 9 };
    if (crypto_random(priv, 32) != 0) return -1;
    return crypto_x25519(pub, priv, base);
}
