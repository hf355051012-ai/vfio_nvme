/* AES-128 と GCM(TLS 1.3 の TLS_AES_128_GCM_SHA256 用、PLAN_auth_tls.md 段階 0' / G)。
 *
 * AES は AES-NI、GHASH は PCLMULQDQ。**段階 G で 8 ブロック単位にした**:
 *   - CTR: 独立な 8 本の AES を 1 ラウンドずつ交互に流す。aesenc は待ち 4 サイクル・
 *     1 サイクルに 1 個なので、1 本ずつだと 10 ラウンド x 4 サイクルを直列に待つ
 *     (CRC32C の 3 本インタリーブと同じ考え方)。
 *   - GHASH: H の 1〜8 乗を先に計算しておき、X = (X+C0)H^8 + C1 H^7 + ... + C7 H を
 *     **還元前の 256 ビットの積のまま足し合わせ、還元を 1 回だけ**にする
 *     (シフトと還元は GF(2) の上で線形なので、和の還元 = 還元の和)。
 * 段階 0' の 1 ブロックずつの実装は 1 コア約 480 MB/s で、TLS の速さの上限になっていた。
 * GHASH の乗算は Intel の白書
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

/* 還元前の 256 ビットの積 a*b を (lo, hi) へ足し込む。 */
AESFN static inline void clmul_acc(__m128i a, __m128i b, __m128i *lo, __m128i *hi) {
    const __m128i t3 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t4 = _mm_clmulepi64_si128(a, b, 0x10);
    const __m128i t5 = _mm_clmulepi64_si128(a, b, 0x01);
    const __m128i t6 = _mm_clmulepi64_si128(a, b, 0x11);
    t4 = _mm_xor_si128(t4, t5);
    *lo = _mm_xor_si128(*lo, _mm_xor_si128(t3, _mm_slli_si128(t4, 8)));
    *hi = _mm_xor_si128(*hi, _mm_xor_si128(t6, _mm_srli_si128(t4, 8)));
}

/* 256 ビットの積 (t3 = 下位, t6 = 上位) を 1 ビット寄せて還元する。 */
AESFN static inline __m128i gf_reduce(__m128i t3, __m128i t6) {
    __m128i t2, t4, t5, t7, t8, t9;
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

/* GF(2^128) の積(バイト順を反転した表現どうし)。 */
AESFN static __m128i gfmul(__m128i a, __m128i b) {
    __m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128();
    clmul_acc(a, b, &lo, &hi);
    return gf_reduce(lo, hi);
}

/* x に data を吸わせる(端数は 0 詰めした 1 ブロックとして扱う)。
 * 128 バイトずつは H^8..H^1 で畳んで還元 1 回、残りは 1 ブロックずつ。 */
AESFN static __m128i ghash_update(__m128i x, const crypto_aes128gcm_t *c, const uint8_t *p, size_t n) {
    const __m128i h = _mm_loadu_si128((const __m128i *)c->hpow[0]);
    while (n >= 128u) {
        __m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128();
        clmul_acc(_mm_xor_si128(x, bswap128(_mm_loadu_si128((const __m128i *)p))),
                  _mm_loadu_si128((const __m128i *)c->hpow[7]), &lo, &hi);
#pragma GCC unroll 7
        for (int i = 1; i < 8; i++) {
            clmul_acc(bswap128(_mm_loadu_si128((const __m128i *)(p + 16 * i))),
                      _mm_loadu_si128((const __m128i *)c->hpow[7 - i]), &lo, &hi);
        }
        x = gf_reduce(lo, hi);
        p += 128; n -= 128u;
    }
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
    const __m128i h = bswap128(aes128_enc(rk, _mm_setzero_si128()));
    __m128i p = h;
    for (int i = 0; i < 8; i++) {   /* H^1..H^8 */
        _mm_storeu_si128((__m128i *)c->hpow[i], p);
        p = gfmul(p, h);
    }
    crypto_wipe(rk, sizeof(rk));
}

/* ---- 8 ブロック単位の CTR と GHASH(段階 G)----
 *
 * カウンタはバイト順を反転した形(cb)で持つ: 末尾 4 バイトの BE の数が 32 ビット
 * 要素 0 の LE の数になるので、_mm_add_epi32 がそのまま inc32(2^32 で回る)。 */

/* 8 本の AES を 1 ラウンドずつ交互に流して、鍵ストリーム 8 ブロックを作る。 */
AESFN static inline void aes8(const __m128i rk[11], __m128i cb, __m128i b[8]) {
#pragma GCC unroll 8
    for (int i = 0; i < 8; i++)
        b[i] = _mm_xor_si128(bswap128(_mm_add_epi32(cb, _mm_set_epi32(0, 0, 0, i))), rk[0]);
#pragma GCC unroll 9
    for (int r = 1; r < 10; r++) {
#pragma GCC unroll 8
        for (int i = 0; i < 8; i++) b[i] = _mm_aesenc_si128(b[i], rk[r]);
    }
#pragma GCC unroll 8
    for (int i = 0; i < 8; i++) b[i] = _mm_aesenclast_si128(b[i], rk[10]);
}

/* 反転済みの 8 ブロックを H^8..H^1 で畳み、還元を 1 回だけする。 */
AESFN static inline __m128i ghash8(__m128i x, const crypto_aes128gcm_t *c, const __m128i blk[8]) {
    __m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128();
    clmul_acc(_mm_xor_si128(x, blk[0]), _mm_loadu_si128((const __m128i *)c->hpow[7]), &lo, &hi);
#pragma GCC unroll 7
    for (int i = 1; i < 8; i++) clmul_acc(blk[i], _mm_loadu_si128((const __m128i *)c->hpow[7 - i]), &lo, &hi);
    return gf_reduce(lo, hi);
}

/* 端数(128 バイト未満)の CTR。1 ブロックずつ。 */
AESFN static void ctr_tail(const __m128i rk[11], __m128i *cb, const uint8_t *in, uint8_t *out, size_t n) {
    while (n) {
        uint8_t ks[16];
        _mm_storeu_si128((__m128i *)ks, aes128_enc(rk, bswap128(*cb)));
        *cb = _mm_add_epi32(*cb, _mm_set_epi32(0, 0, 0, 1));
        const size_t take = n < 16u ? n : 16u;
        for (size_t i = 0; i < take; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
        in += take; out += take; n -= take;
    }
}

/* 長さのブロックを吸わせ、E(K, J0) と混ぜてタグにする。 */
AESFN static void gcm_finish(const crypto_aes128gcm_t *c, const __m128i rk[11], const uint8_t iv[12],
                             __m128i x, size_t alen, size_t n, uint8_t tag[16]) {
    uint8_t lens[16];
    const uint64_t ab = (uint64_t)alen * 8u, cbits = (uint64_t)n * 8u;
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)(ab >> (56 - 8 * i));
        lens[8 + i] = (uint8_t)(cbits >> (56 - 8 * i));
    }
    x = ghash_update(x, c, lens, 16u);
    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    const __m128i e = aes128_enc(rk, _mm_loadu_si128((const __m128i *)j0));
    _mm_storeu_si128((__m128i *)tag, _mm_xor_si128(e, bswap128(x)));
}

AESFN static __m128i ctr_start(const uint8_t iv[12]) {
    uint8_t j[16];
    memcpy(j, iv, 12);
    j[12] = 0; j[13] = 0; j[14] = 0; j[15] = 2;   /* データは inc32(J0) から */
    return bswap128(_mm_loadu_si128((const __m128i *)j));
}

/* 暗号化。**AES 8 本と、1 つ前の 8 ブロックの GHASH を同じ周回に並べる**
 * (AES と PCLMULQDQ は別の演算器なので重なる。今の 8 ブロックの GHASH は今の
 * AES の結果を待つので、1 周遅らせて依存を切る)。 */
AESFN void crypto_aes128gcm_seal(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                                 const void *aad, size_t alen, const void *in, size_t n,
                                 void *out, uint8_t tag[16]) {
    __m128i rk[11];
    memcpy(rk, c->rk, sizeof(rk));
    const uint8_t *ip = (const uint8_t *)in;
    uint8_t *op = (uint8_t *)out;
    size_t left = n;
    __m128i cb = ctr_start(iv);
    __m128i x = ghash_update(_mm_setzero_si128(), c, (const uint8_t *)aad, alen);
    __m128i prev[8];
    int have = 0;
    while (left >= 128u) {
        __m128i b[8];
        aes8(rk, cb, b);
        cb = _mm_add_epi32(cb, _mm_set_epi32(0, 0, 0, 8));
        if (have) x = ghash8(x, c, prev);
#pragma GCC unroll 8
        for (int i = 0; i < 8; i++) {
            const __m128i ct = _mm_xor_si128(b[i], _mm_loadu_si128((const __m128i *)(ip + 16 * i)));
            _mm_storeu_si128((__m128i *)(op + 16 * i), ct);
            prev[i] = bswap128(ct);
        }
        have = 1;
        ip += 128; op += 128; left -= 128u;
    }
    if (have) x = ghash8(x, c, prev);
    if (left) {
        ctr_tail(rk, &cb, ip, op, left);
        x = ghash_update(x, c, op, left);
    }
    gcm_finish(c, rk, iv, x, alen, n, tag);
}

/* 断片の列から、次の len バイトの読み出し先を返す。1 つの断片に収まっていれば
 * そこを直接指し、またぐときだけ tmp へ寄せる。 */
static const uint8_t *iov_take(const crypto_iov_t *v, int nv, int *vi, size_t *vo, size_t len, uint8_t *tmp) {
    while (*vi < nv && *vo == v[*vi].n) { (*vi)++; *vo = 0; }
    if (*vi < nv && *vo + len <= v[*vi].n) {
        const uint8_t *p = (const uint8_t *)v[*vi].p + *vo;
        *vo += len;
        return p;
    }
    size_t got = 0;
    while (got < len && *vi < nv) {
        size_t c = v[*vi].n - *vo;
        if (c > len - got) c = len - got;
        memcpy(tmp + got, (const uint8_t *)v[*vi].p + *vo, c);
        got += c;
        *vo += c;
        if (*vo == v[*vi].n) { (*vi)++; *vo = 0; }
    }
    return tmp;
}

/* crypto_aes128gcm_seal() の断片版(段階 G。TLS の送信が PDU のヘッダ・データ・
 * 内側の種別 1 バイトを、写さずに直接 TCP の再送スロットへ暗号化するため)。 */
AESFN void crypto_aes128gcm_seal_iov(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                                     const void *aad, size_t alen, const crypto_iov_t *v, int nv,
                                     void *out, uint8_t tag[16]) {
    __m128i rk[11];
    memcpy(rk, c->rk, sizeof(rk));
    size_t n = 0;
    for (int i = 0; i < nv; i++) n += v[i].n;
    uint8_t *op = (uint8_t *)out;
    size_t left = n;
    int vi = 0;
    size_t vo = 0;
    uint8_t tmp[128];
    __m128i cb = ctr_start(iv);
    __m128i x = ghash_update(_mm_setzero_si128(), c, (const uint8_t *)aad, alen);
    __m128i prev[8];
    int have = 0;
    while (left >= 128u) {
        const uint8_t *ip = iov_take(v, nv, &vi, &vo, 128u, tmp);
        __m128i b[8];
        aes8(rk, cb, b);
        cb = _mm_add_epi32(cb, _mm_set_epi32(0, 0, 0, 8));
        if (have) x = ghash8(x, c, prev);
#pragma GCC unroll 8
        for (int i = 0; i < 8; i++) {
            const __m128i ct = _mm_xor_si128(b[i], _mm_loadu_si128((const __m128i *)(ip + 16 * i)));
            _mm_storeu_si128((__m128i *)(op + 16 * i), ct);
            prev[i] = bswap128(ct);
        }
        have = 1;
        op += 128; left -= 128u;
    }
    if (have) x = ghash8(x, c, prev);
    if (left) {
        const uint8_t *ip = iov_take(v, nv, &vi, &vo, left, tmp);
        ctr_tail(rk, &cb, ip, op, left);
        x = ghash_update(x, c, op, left);
    }
    gcm_finish(c, rk, iv, x, alen, n, tag);
}

/* 復号。暗号文は最初から分かっているので、同じ 8 ブロックの GHASH と AES を並べる。
 * **タグが合わなければ、書いた平文を消して -1**(in == out でもよい)。 */
AESFN int crypto_aes128gcm_open(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                                const void *aad, size_t alen, const void *in, size_t n,
                                void *out, const uint8_t tag[16]) {
    __m128i rk[11];
    memcpy(rk, c->rk, sizeof(rk));
    const uint8_t *ip = (const uint8_t *)in;
    uint8_t *op = (uint8_t *)out;
    size_t left = n;
    __m128i cb = ctr_start(iv);
    __m128i x = ghash_update(_mm_setzero_si128(), c, (const uint8_t *)aad, alen);
    while (left >= 128u) {
        __m128i ct[8], blk[8], b[8];
#pragma GCC unroll 8
        for (int i = 0; i < 8; i++) {
            ct[i] = _mm_loadu_si128((const __m128i *)(ip + 16 * i));
            blk[i] = bswap128(ct[i]);
        }
        x = ghash8(x, c, blk);
        aes8(rk, cb, b);
        cb = _mm_add_epi32(cb, _mm_set_epi32(0, 0, 0, 8));
#pragma GCC unroll 8
        for (int i = 0; i < 8; i++) _mm_storeu_si128((__m128i *)(op + 16 * i), _mm_xor_si128(b[i], ct[i]));
        ip += 128; op += 128; left -= 128u;
    }
    if (left) {
        x = ghash_update(x, c, ip, left);   /* 復号より先に(in == out のとき上書きされる)*/
        ctr_tail(rk, &cb, ip, op, left);
    }
    uint8_t want[16];
    gcm_finish(c, rk, iv, x, alen, n, want);
    if (!crypto_equal(want, tag, 16u)) {
        crypto_wipe(out, n);   /* 検証できなかった平文は残さない */
        return -1;
    }
    return 0;
}
