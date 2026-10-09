/* AES-128 と GCM(TLS 1.3 の TLS_AES_128_GCM_SHA256 用、PLAN_auth_tls.md 段階 0')。
 *
 * AES は AES-NI、GHASH は PCLMULQDQ。**まず正しく、1 ブロックずつ**(段階 G で
 * 4〜8 本インタリーブにする)。GHASH の乗算は Intel の白書
 * 「Intel Carry-Less Multiplication Instruction and its Usage for Computing the
 * GCM Mode」の Algorithm 5(ビット反転した表現のまま掛けて 1 ビットずらす形)。
 *
 * 命令拡張は関数ごとの target 属性で有効にする(tools/crypto_check.c から
 * -maes なしでもそのままビルドできるように)。
 */
#include "crypto.h"

#include <string.h>
#include <immintrin.h>

#define AESFN __attribute__((target("aes,pclmul,ssse3")))

/* ---- AES-128 の鍵の展開 ---- */
AESFN static __m128i key_step(__m128i k, __m128i t) {
    t = _mm_shuffle_epi32(t, 0xFF);
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    return _mm_xor_si128(k, t);
}

#define KEXP(i, rcon) rk[i] = key_step(rk[(i) - 1], _mm_aeskeygenassist_si128(rk[(i) - 1], rcon))

AESFN static void aes128_expand(__m128i rk[11], const uint8_t key[16]) {
    rk[0] = _mm_loadu_si128((const __m128i *)key);
    KEXP(1, 0x01); KEXP(2, 0x02); KEXP(3, 0x04); KEXP(4, 0x08); KEXP(5, 0x10);
    KEXP(6, 0x20); KEXP(7, 0x40); KEXP(8, 0x80); KEXP(9, 0x1B); KEXP(10, 0x36);
}

AESFN static __m128i aes128_enc(const __m128i rk[11], __m128i b) {
    b = _mm_xor_si128(b, rk[0]);
    for (int i = 1; i < 10; i++) b = _mm_aesenc_si128(b, rk[i]);
    return _mm_aesenclast_si128(b, rk[10]);
}

AESFN void crypto_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    __m128i rk[11];
    aes128_expand(rk, key);
    _mm_storeu_si128((__m128i *)out, aes128_enc(rk, _mm_loadu_si128((const __m128i *)in)));
    crypto_wipe(rk, sizeof(rk));
}

/* ---- GHASH ---- */
AESFN static __m128i bswap128(__m128i x) {
    return _mm_shuffle_epi8(x, _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
}

/* GF(2^128) の積(バイト順を反転した表現どうし)。 */
AESFN static __m128i gfmul(__m128i a, __m128i b) {
    __m128i t2, t3, t4, t5, t6, t7, t8, t9;
    t3 = _mm_clmulepi64_si128(a, b, 0x00);
    t4 = _mm_clmulepi64_si128(a, b, 0x10);
    t5 = _mm_clmulepi64_si128(a, b, 0x01);
    t6 = _mm_clmulepi64_si128(a, b, 0x11);
    t4 = _mm_xor_si128(t4, t5);
    t5 = _mm_slli_si128(t4, 8);
    t4 = _mm_srli_si128(t4, 8);
    t3 = _mm_xor_si128(t3, t5);
    t6 = _mm_xor_si128(t6, t4);
    /* 256 ビットの積全体を 1 ビット左へ(反転した表現のための補正)*/
    t7 = _mm_srli_epi32(t3, 31);
    t8 = _mm_srli_epi32(t6, 31);
    t3 = _mm_slli_epi32(t3, 1);
    t6 = _mm_slli_epi32(t6, 1);
    t9 = _mm_srli_si128(t7, 12);
    t8 = _mm_slli_si128(t8, 4);
    t7 = _mm_slli_si128(t7, 4);
    t3 = _mm_or_si128(t3, t7);
    t6 = _mm_or_si128(t6, t8);
    t6 = _mm_or_si128(t6, t9);
    /* x^128 + x^7 + x^2 + x + 1 で還元 */
    t7 = _mm_slli_epi32(t3, 31);
    t8 = _mm_slli_epi32(t3, 30);
    t9 = _mm_slli_epi32(t3, 25);
    t7 = _mm_xor_si128(t7, t8);
    t7 = _mm_xor_si128(t7, t9);
    t8 = _mm_srli_si128(t7, 4);
    t7 = _mm_slli_si128(t7, 12);
    t3 = _mm_xor_si128(t3, t7);
    t2 = _mm_srli_epi32(t3, 1);
    t4 = _mm_srli_epi32(t3, 2);
    t5 = _mm_srli_epi32(t3, 7);
    t2 = _mm_xor_si128(t2, t4);
    t2 = _mm_xor_si128(t2, t5);
    t2 = _mm_xor_si128(t2, t8);
    t3 = _mm_xor_si128(t3, t2);
    return _mm_xor_si128(t6, t3);
}

/* x に data を吸わせる(端数は 0 詰めした 1 ブロックとして扱う)。 */
AESFN static __m128i ghash_update(__m128i x, __m128i h, const uint8_t *p, size_t n) {
    while (n >= 16u) {
        x = gfmul(_mm_xor_si128(x, bswap128(_mm_loadu_si128((const __m128i *)p))), h);
        p += 16; n -= 16u;
    }
    if (n) {
        uint8_t blk[16] = { 0 };
        memcpy(blk, p, n);
        x = gfmul(_mm_xor_si128(x, bswap128(_mm_loadu_si128((const __m128i *)blk))), h);
    }
    return x;
}

AESFN void crypto_aes128gcm_init(crypto_aes128gcm_t *c, const uint8_t key[16]) {
    __m128i rk[11];
    aes128_expand(rk, key);
    memcpy(c->rk, rk, sizeof(rk));
    _mm_storeu_si128((__m128i *)c->h, bswap128(aes128_enc(rk, _mm_setzero_si128())));
    crypto_wipe(rk, sizeof(rk));
}

/* CTR で in を out へ(暗号化も復号も同じ)。J0 = IV || 00000001、データは inc32(J0) から。 */
AESFN static void gcm_ctr(const __m128i rk[11], const uint8_t iv[12], const uint8_t *in, uint8_t *out, size_t n) {
    uint8_t ctr[16];
    memcpy(ctr, iv, 12);
    uint32_t cnt = 2u;
    while (n) {
        ctr[12] = (uint8_t)(cnt >> 24); ctr[13] = (uint8_t)(cnt >> 16);
        ctr[14] = (uint8_t)(cnt >> 8);  ctr[15] = (uint8_t)cnt;
        cnt++;
        uint8_t ks[16];
        _mm_storeu_si128((__m128i *)ks, aes128_enc(rk, _mm_loadu_si128((const __m128i *)ctr)));
        const size_t take = n < 16u ? n : 16u;
        for (size_t i = 0; i < take; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
        in += take; out += take; n -= take;
    }
}

AESFN static void gcm_tag(const crypto_aes128gcm_t *c, const __m128i rk[11], const uint8_t iv[12],
                          const uint8_t *aad, size_t alen, const uint8_t *ct, size_t n, uint8_t tag[16]) {
    const __m128i h = _mm_loadu_si128((const __m128i *)c->h);
    __m128i x = _mm_setzero_si128();
    x = ghash_update(x, h, aad, alen);
    x = ghash_update(x, h, ct, n);
    uint8_t lens[16];
    const uint64_t ab = (uint64_t)alen * 8u, cb = (uint64_t)n * 8u;
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)(ab >> (56 - 8 * i));
        lens[8 + i] = (uint8_t)(cb >> (56 - 8 * i));
    }
    x = ghash_update(x, h, lens, 16u);
    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    const __m128i e = aes128_enc(rk, _mm_loadu_si128((const __m128i *)j0));
    _mm_storeu_si128((__m128i *)tag, _mm_xor_si128(e, bswap128(x)));
}

AESFN void crypto_aes128gcm_seal(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                                 const void *aad, size_t alen, const void *in, size_t n,
                                 void *out, uint8_t tag[16]) {
    __m128i rk[11];
    memcpy(rk, c->rk, sizeof(rk));
    gcm_ctr(rk, iv, (const uint8_t *)in, (uint8_t *)out, n);
    gcm_tag(c, rk, iv, (const uint8_t *)aad, alen, (const uint8_t *)out, n, tag);
}

AESFN int crypto_aes128gcm_open(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                                const void *aad, size_t alen, const void *in, size_t n,
                                void *out, const uint8_t tag[16]) {
    __m128i rk[11];
    memcpy(rk, c->rk, sizeof(rk));
    uint8_t want[16];
    gcm_tag(c, rk, iv, (const uint8_t *)aad, alen, (const uint8_t *)in, n, want);
    if (!crypto_equal(want, tag, 16u)) return -1;   /* 平文は出さない */
    gcm_ctr(rk, iv, (const uint8_t *)in, (uint8_t *)out, n);
    return 0;
}
