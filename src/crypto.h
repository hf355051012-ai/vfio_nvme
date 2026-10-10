#ifndef CRYPTO_H
#define CRYPTO_H

/* 認証(DH-HMAC-CHAP)と TLS 1.3 のための暗号部品(PLAN_auth_tls.md 段階 0)。
 *
 * **外部ライブラリを使わない自前の実装。** 正しさは 2 つで担保する:
 *   - crypto_selftest(): 起動時に既知の値(FIPS 180-4 / RFC 4231 / RFC 5869 /
 *     RFC 8448 の値を OpenSSL で作り直して照合したもの)と比べる。
 *   - tools/crypto_check.c: この .c を OpenSSL の libcrypto と一緒にビルドし、
 *     乱数の入力で全長・全アライメントを突き合わせる(自作どうしだと両側が
 *     同じ間違い方をする、の対策。CRC32C で踏んだ穴)。
 *
 * このファイルはプラットフォームに依存しない(uart も使わない)。tools/ から
 * そのまま単体でビルドできるようにしておくこと。
 *
 * **実験用の実装**: 定数時間なのは crypto_equal()(MAC / タグの比較)だけ。
 */

#include <stdint.h>
#include <stddef.h>

/* ハッシュの番号は NVMe の DH-HMAC-CHAP の HashID と同じ値にしてある
 * (include/linux/nvme.h の NVME_AUTH_HASH_SHA256 = 0x01 ...)。 */
typedef enum {
    CRYPTO_SHA256 = 1,
    CRYPTO_SHA384 = 2,
    CRYPTO_SHA512 = 3,
    /* iSCSI の CHAP(RFC 7143 12.1.3、CHAP_A = 5 / 6 / 7 / 8)。MD5 と SHA-1 は
     * 古いが、open-iscsi と LIO が今も既定の候補に入れている。 */
    CRYPTO_MD5 = 4,
    CRYPTO_SHA1 = 5,
    CRYPTO_SHA3_256 = 6,
} crypto_hash_id_t;

#define CRYPTO_HASH_MAX   64u    /* 最長の出力(SHA-512)*/
#define CRYPTO_BLOCK_MAX  144u   /* 最長のブロック(SHA3-256 の rate 136。SHA-384 / 512 は 128)*/

typedef struct {
    crypto_hash_id_t id;
    uint64_t total;              /* これまでに入れたバイト数 */
    uint32_t fill;               /* buf に溜まっているバイト数 */
    union {
        uint32_t s32[8];
        uint64_t s64[25];        /* SHA3 は 25 レーン(200 バイト)*/
    } st;
    uint8_t buf[CRYPTO_BLOCK_MAX];
} crypto_hash_ctx_t;

/* 0 なら未知の id。 */
size_t crypto_hash_len(crypto_hash_id_t id);
size_t crypto_hash_block(crypto_hash_id_t id);

int  crypto_hash_init(crypto_hash_ctx_t *c, crypto_hash_id_t id);
void crypto_hash_update(crypto_hash_ctx_t *c, const void *data, size_t len);
void crypto_hash_final(crypto_hash_ctx_t *c, uint8_t *out);
int  crypto_hash(crypto_hash_id_t id, const void *data, size_t len, uint8_t *out);

typedef struct {
    crypto_hash_ctx_t inner;
    crypto_hash_ctx_t outer;
} crypto_hmac_ctx_t;

int  crypto_hmac_init(crypto_hmac_ctx_t *c, crypto_hash_id_t id, const void *key, size_t klen);
void crypto_hmac_update(crypto_hmac_ctx_t *c, const void *data, size_t len);
void crypto_hmac_final(crypto_hmac_ctx_t *c, uint8_t *out);
int  crypto_hmac(crypto_hash_id_t id, const void *key, size_t klen,
                 const void *msg, size_t mlen, uint8_t *out);

/* HKDF(RFC 5869)。salt が NULL / 長さ 0 ならハッシュ長の 0 を使う。
 * expand の出力は 255 * ハッシュ長まで(超えたら -1)。 */
int crypto_hkdf_extract(crypto_hash_id_t id, const void *salt, size_t slen,
                        const void *ikm, size_t ilen, uint8_t *prk);
int crypto_hkdf_expand(crypto_hash_id_t id, const uint8_t *prk, size_t prklen,
                       const void *info, size_t ilen, uint8_t *okm, size_t olen);
/* HKDF-Expand-Label(RFC 8446 7.1)。label には "tls13 " を付けずに渡す
 * (Linux の drivers/nvme/common/auth.c の hkdf_expand_label() と同じ約束)。 */
int crypto_hkdf_expand_label(crypto_hash_id_t id, const uint8_t *secret, size_t slen,
                             const char *label, const void *ctx, size_t clen,
                             uint8_t *out, size_t olen);

/* base64(RFC 4648、標準の英字表、'=' 詰め)。
 * encode: 出力は 4*ceil(n/3) 文字 + NUL。戻り値は文字数。
 * decode: '=' は有っても無くてもよい。戻り値は出力バイト数、不正なら -1。 */
size_t crypto_base64_encode(const void *in, size_t n, char *out);
int    crypto_base64_decode(const char *in, size_t n, uint8_t *out, size_t cap);

/* CRC-32(IEEE 802.3、多項式 0xEDB88320、初期値・最終反転あり)。
 * DH-HMAC-CHAP / TLS の鍵の文字列の末尾 4 バイト(リトルエンディアン)。
 * **CRC32C(crc32c.c)ではない。** */
uint32_t crypto_crc32(const void *data, size_t len);

/* 乱数(getrandom)。0=成功、-1=失敗。 */
int  crypto_random(void *buf, size_t len);
/* 定数時間の比較。等しければ 1。 */
int  crypto_equal(const void *a, const void *b, size_t n);
/* 最適化で消されない消去(鍵の後始末)。 */
void crypto_wipe(void *p, size_t n);

/* ---- 有限体 Diffie-Hellman(crypto_dh.c、RFC 7919 の ffdhe 群、生成元 2)----
 * 群の番号は NVMe の DH-HMAC-CHAP の DH group ID と同じ(1=2048 ... 5=8192)。
 * 公開値・共有秘密は**素数の長さ(256〜1024 バイト)に 0 詰めしたビッグエンディアン**
 * (Linux の dh_compute_value() と同じ。共有秘密はこの長さのままハッシュされる)。 */
enum {
    CRYPTO_FFDHE2048 = 1,
    CRYPTO_FFDHE3072 = 2,
    CRYPTO_FFDHE4096 = 3,
    CRYPTO_FFDHE6144 = 4,
    CRYPTO_FFDHE8192 = 5,
};
#define CRYPTO_FFDHE_PRIV_LEN  64u     /* 秘密の指数は 512 ビット */
#define CRYPTO_FFDHE_MAX_LEN   1024u   /* ffdhe8192 の長さ */

size_t crypto_ffdhe_len(unsigned gid);   /* 0 なら未知の群 */
/* 秘密の指数を乱数で作り、公開値 2^x mod p を pub(crypto_ffdhe_len バイト)へ。 */
int crypto_ffdhe_keygen(unsigned gid, uint8_t priv[CRYPTO_FFDHE_PRIV_LEN], uint8_t *pub);
/* 与えた指数での公開値(自己検査用)。 */
int crypto_ffdhe_public(unsigned gid, const uint8_t priv[CRYPTO_FFDHE_PRIV_LEN], uint8_t *pub);
/* 共有秘密 peer^x mod p。peer は 1 < y < p-1 かつ素数位数の部分群に居ること
 * (y^((p-1)/2) = 1)を確かめ、だめなら負を返す。 */
int crypto_ffdhe_shared(unsigned gid, const uint8_t priv[CRYPTO_FFDHE_PRIV_LEN],
                        const uint8_t *peer, size_t peerlen, uint8_t *out);
/* 汎用の冪剰余 base^exp mod mod(mod は奇数、1024 バイトまで、base < mod)。
 * out は mlen バイト。検算用(tools/crypto_check.c が OpenSSL の BN_mod_exp と比べる)。 */
int crypto_modexp(const uint8_t *base, size_t blen, const uint8_t *exp, size_t elen,
                  const uint8_t *mod, size_t mlen, uint8_t *out);

/* ---- AES-128 と GCM(crypto_aes.c、AES-NI + PCLMULQDQ)----
 * TLS 1.3 の TLS_AES_128_GCM_SHA256 用。IV は 12 バイト、タグは 16 バイト固定。 */
typedef struct {
    uint8_t rk[11 * 16];         /* 展開した鍵 */
    uint8_t hpow[8][16];         /* GHASH の鍵 H = E(K, 0) の 1〜8 乗(バイト順を反転した表現)。
                                  * 8 ブロックをまとめて畳むために先に計算しておく */
    uint8_t hkar[8][16];         /* hpow[i] の上位 64 ビットと下位 64 ビットの XOR(下位 64 ビットに置く)。
                                  * Karatsuba 法で 1 ブロックの掛け算を 3 回にするため */
} crypto_aes128gcm_t;

/* 8 ブロックのループ本体を手書きのアセンブリ(crypto_aes_x86.S、AVX)で回すか。
 * -1 = CPU が AVX を持てば使う(既定)、0 = 使わない(C の組込み関数の版。陰性対照と比較用)。 */
extern int crypto_aes_asm;

void crypto_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void crypto_aes128gcm_init(crypto_aes128gcm_t *c, const uint8_t key[16]);
/* in と out は同じでもよい。 */
void crypto_aes128gcm_seal(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                           const void *aad, size_t alen, const void *in, size_t n,
                           void *out, uint8_t tag[16]);
/* 断片(最大 4 個)を続けた平文を暗号化する(段階 G)。平文をいったん連続した
 * バッファへ写さずに済む。out と断片は重ならないこと。 */
typedef struct { const void *p; size_t n; } crypto_iov_t;
void crypto_aes128gcm_seal_iov(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                               const void *aad, size_t alen, const crypto_iov_t *v, int nv,
                               void *out, uint8_t tag[16]);
/* タグが合わなければ -1(書いた平文は消してから返す)。 */
int  crypto_aes128gcm_open(const crypto_aes128gcm_t *c, const uint8_t iv[12],
                           const void *aad, size_t alen, const void *in, size_t n,
                           void *out, const uint8_t tag[16]);

/* ---- X25519(crypto_x25519.c、RFC 7748)----
 * 結果が全 0(相手が小位数の点を送ってきた)なら -1。 */
int crypto_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
int crypto_x25519_keygen(uint8_t priv[32], uint8_t pub[32]);

/* 既知の値との照合。0=全部一致。err に最初に食い違った項目名を入れる。 */
int crypto_selftest(char *err, size_t errlen);

#endif /* CRYPTO_H */
