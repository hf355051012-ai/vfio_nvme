#ifndef TLS13_H
#define TLS13_H

/* TLS 1.3 のサーバ側(PLAN_auth_tls.md 段階 D)とクライアント側(段階 F)。
 * NVMe/TCP の secure channel 用。
 *
 * **できることを絞ってある**(相手は Linux の tlshd = GnuTLS と OpenSSL):
 *   - 暗号スイートは TLS_AES_128_GCM_SHA256 と TLS_AES_256_GCM_SHA384。**PSK のハッシュで決まる**
 *     (SHA-256 の PSK なら前者、SHA-384 の PSK なら後者。RFC 8446 4.2.11 の約束)。
 *   - 認証は外部 PSK だけ(証明書は使わない)。鍵交換は psk_dhe_ke(tlshd は psk_ke を出さない)。
 *   - 鍵共有は x25519 と ML-KEM-1024(draft-ietf-tls-mlkem の群 0x0202。CNSA 2.0 用、
 *     PLAN_cnsa2.md 段階 2)。相手が使える群の key_share を付けてこなければ
 *     HelloRetryRequest で求め直す(サーバ / クライアントとも 1 回だけ)。
 *   - 0-RTT・セッションチケットは使わない。
 *
 * TCP とは独立した「受け取ったバイト列を食わせると、送るバイト列と復号した
 * 平文が出てくる」形にしてある(自己検査と tools/ の検算から同じ関数を叩くため)。
 * プラットフォームに依存しない(uart も使わない)。
 */

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

#define TLS13_PLAIN_MAX   16384u                      /* 1 レコードの平文の上限(2^14)*/
#define TLS13_REC_MAX     (5u + TLS13_PLAIN_MAX + 256u) /* 暗号文のレコード 1 個の上限 */
#define TLS13_IDENT_MAX   512u
#define TLS13_HS_MAX      4096u                       /* 握手メッセージ 1 個の上限(ClientHello)*/
#define TLS13_HASH_MAX    48u                         /* SHA-384 */
#define TLS13_COOKIE_MAX  256u
/* 0-RTT を受け付けないときに読み飛ばす早期データの上限(RFC 8446 4.2.10 の max_early_data_size)。
 * 外部 PSK に設定値は無いので OpenSSL の既定(2^14)にレコード 1 個ぶんの余裕(256)を足した値。
 * 暗号文の本体(タグ込み)の長さで数える。 */
#define TLS13_EARLY_SKIP_MAX (TLS13_PLAIN_MAX + 256u)

/* 鍵共有の群(tls13_t.groups / share のビット)*/
enum {
    TLS13_GROUP_X25519    = 1u,
    TLS13_GROUP_MLKEM1024 = 2u,
};

/* NVMe/TCP の PSK 1 本(身元とその TLS PSK)。 */
typedef struct {
    char     identity[TLS13_IDENT_MAX];
    uint16_t identity_len;
    uint8_t  psk[TLS13_HASH_MAX];
    uint8_t  hash;                 /* 0 / CRYPTO_SHA256 = SHA-256(32 バイト)、CRYPTO_SHA384 = SHA-384(48 バイト)*/
} tls13_psk_t;

typedef enum {
    TLS13_ST_WAIT_CH = 0,   /* ClientHello 待ち(HelloRetryRequest の後の 2 回目も)*/
    TLS13_ST_WAIT_CFIN,     /* こちらの Finished まで送った。相手の Finished 待ち */
    TLS13_ST_OPEN,          /* 握手が済んだ。application_data が流せる */
    TLS13_ST_CLOSED,        /* close_notify を受けた */
    TLS13_ST_FAILED,        /* alert を送った / 受けた */
    /* クライアント側(段階 F)*/
    TLS13_ST_WAIT_SH,       /* ClientHello を送った。ServerHello(か HelloRetryRequest)待ち */
    TLS13_ST_WAIT_EE,       /* EncryptedExtensions 待ち */
    TLS13_ST_WAIT_SFIN,     /* サーバの Finished 待ち */
} tls13_state_t;

/* alert の description(RFC 8446 6)*/
enum {
    TLS13_ALERT_CLOSE_NOTIFY = 0,
    TLS13_ALERT_UNEXPECTED_MESSAGE = 10,
    TLS13_ALERT_BAD_RECORD_MAC = 20,
    TLS13_ALERT_RECORD_OVERFLOW = 22,
    TLS13_ALERT_HANDSHAKE_FAILURE = 40,
    TLS13_ALERT_ILLEGAL_PARAMETER = 47,
    TLS13_ALERT_DECODE_ERROR = 50,
    TLS13_ALERT_DECRYPT_ERROR = 51,
    TLS13_ALERT_PROTOCOL_VERSION = 70,
    TLS13_ALERT_INTERNAL_ERROR = 80,
    TLS13_ALERT_MISSING_EXTENSION = 109,
    TLS13_ALERT_UNSUPPORTED_EXTENSION = 110,
    TLS13_ALERT_UNKNOWN_PSK_IDENTITY = 115,
};

/* 1 方向のレコードの鍵 */
typedef struct {
    crypto_aesgcm_t aead;
    uint8_t  iv[12];
    uint64_t seq;
    uint8_t  secret[TLS13_HASH_MAX];   /* KeyUpdate で次の鍵を作る元 */
    int      on;
    uint32_t epoch;        /* 鍵を入れ替えた回数(握手メッセージが鍵の境目をまたいでいないかの判定)*/
} tls13_dir_t;

typedef void (*tls13_keylog_fn)(void *arg, const char *line);

typedef struct {
    tls13_state_t state;
    uint8_t  alert_sent;          /* 送った alert(0xFF = なし)*/
    uint8_t  alert_recv;          /* 受けた alert(0xFF = なし)*/
    const char *why;              /* 失敗の理由(ログ用)*/

    const tls13_psk_t *psks;
    unsigned npsk;
    int      psk_index;           /* 選んだ PSK(psks の添字)*/
    uint16_t selected_identity;   /* ClientHello の識別子リスト中の位置 */

    /* 方針(init の後、握手の前に呼び出し側が入れる)*/
    unsigned groups;              /* 使ってよい群(TLS13_GROUP_*)。0 = 既定(サーバは両方、クライアントは x25519)*/
    unsigned share;               /* クライアント: 最初の ClientHello で key_share を付ける群(0 = groups 全部)。
                                   * HelloRetryRequest を試すための検算用のつまみ */
    int      cnsa;                /* CNSA 2.0 専用: SHA-384 の PSK + ML-KEM-1024 だけを使う(groups より優先)*/

    tls13_keylog_fn keylog;       /* SSLKEYLOGFILE 形式の 1 行を渡す(NULL 可)*/
    void    *keylog_arg;

    /* 自己検査用のつまみ(RFC 8448 の再現)。通常は 0 / NULL。 */
    const uint8_t *test_random;   /* サーバの乱数を固定 */
    const uint8_t *test_priv;     /* x25519 の秘密鍵を固定 */
    const uint8_t *test_ee;       /* EncryptedExtensions をこのバイト列にする */
    size_t   test_ee_len;
    int      test_resumption;     /* binder の label を "res binder" にし、身元を問わず先頭を選ぶ */
    int      test_early_data;     /* クライアント: ClientHello に early_data を付ける(0-RTT を読み飛ばす試験用)*/

    uint8_t  close_sent;          /* close_notify を送った(受けたときに送り返すかの判定)*/
    uint8_t  early_offered;       /* サーバ: 相手が early_data を付けてきた(0-RTT は受け付けず読み飛ばす)*/
    uint32_t early_left;          /* サーバ: あと読み飛ばしてよい早期データ(TLS13_EARLY_SKIP_MAX から減らす)*/

    /* 決まったもの */
    crypto_hash_id_t hid;         /* 握手のハッシュ(PSK のハッシュ)*/
    unsigned hl;                  /* その長さ(32 / 48)*/
    uint16_t suite;               /* 暗号スイート(0x1301 / 0x1302)*/
    uint16_t group;               /* 鍵共有の群(0x001D / 0x0202)。HelloRetryRequest の後は求めた群 */
    int      hrr;                 /* HelloRetryRequest を送った(サーバ)/ 受けた(クライアント)*/

    int      is_client;
    uint8_t  sid[32];             /* 互換モードのセッション ID(クライアントが作る / サーバは 2 回目の照合用)*/
    uint8_t  sidlen;
    uint8_t  early[TLS13_HASH_MAX];   /* クライアント: early secret(ServerHello まで持つ)*/
    uint8_t  cpriv[32];           /* クライアント: x25519 の秘密鍵(ServerHello まで持つ)*/
    uint8_t  ml_dk[CRYPTO_MLKEM1024_DK_LEN];   /* クライアント: ML-KEM の復号鍵(ServerHello まで持つ)*/
    unsigned sent;                /* クライアント: key_share を付けた群 */
    uint8_t  cookie[TLS13_COOKIE_MAX];   /* クライアント: HelloRetryRequest の cookie(そのまま返す)*/
    uint16_t cookie_len;

    crypto_hash_ctx_t th;         /* 握手の transcript */
    uint8_t  crandom[32];
    uint8_t  c_hs[TLS13_HASH_MAX], s_hs[TLS13_HASH_MAX], master[TLS13_HASH_MAX];
    uint8_t  cfin[TLS13_HASH_MAX];   /* 相手の Finished の期待値 */

    tls13_dir_t rx, tx;

    uint8_t  rbuf[TLS13_REC_MAX]; /* レコードの組み立て */
    size_t   rlen;
    uint8_t  hbuf[TLS13_HS_MAX];  /* 握手メッセージの組み立て(レコードをまたぐ場合)*/
    size_t   hlen;
} tls13_t;

/* NVMeTLSkey-1:hh:<base64>: から、NVMe/TCP の身元と TLS PSK を作る
 * (libnvme の derive_nvme_keys() と同じ。身元の版 1 = "NVMe1Rhh host sub digest" と
 * 版 0 = "NVMe0Rhh host sub" の 2 本を out[0..1] に入れる)。hh = 01 は SHA-256 の 32 バイト鍵、
 * 02 は SHA-384 の 48 バイト鍵(TLS_AES_256_GCM_SHA384、CNSA 2.0)、00 は鍵の長さで決まる。
 * 戻り値は作った本数(2)、鍵の形式が悪ければ -1(why に理由)。 */
int tls13_nvme_psk(tls13_psk_t out[2], const char *keystr, const char *hostnqn,
                   const char *subnqn, const char **why);

/* secure channel concatenation(段階 H)で DH-HMAC-CHAP が生成した PSK から、
 * 身元 "NVMe1G01 host sub digest" と TLS PSK を作る(Linux の nvme_auth_generate_digest() +
 * nvme_auth_derive_tls_psk())。PSK は SHA-256 の 32 バイトだけ(TLS_AES_128_GCM_SHA256)。 */
int tls13_nvme_generated_psk(tls13_psk_t *out, const uint8_t *psk, size_t len,
                             const char *hostnqn, const char *subnqn);

void tls13_server_init(tls13_t *t, const tls13_psk_t *psks, unsigned npsk);

/* クライアント(段階 F)。psk は 1 本(身元とその TLS PSK)。
 * tls13_client_hello() が ClientHello のレコードを out へ書き、長さを返す(0 なら失敗)。
 * 以後は tls13_input() に相手の応答を食わせる(こちらの Finished は out に出る)。 */
void   tls13_client_init(tls13_t *t, const tls13_psk_t *psk);
size_t tls13_client_hello(tls13_t *t, uint8_t *out, size_t cap);

/* 受け取ったバイト列を食わせる。送るべきバイト列を out へ(*outlen)、復号した
 * application_data を app へ(*applen、appcap を超えたら失敗)追記する。
 * 戻り値: 0=続行、-1=失敗(out に alert が入っている。state は FAILED)。 */
int tls13_input(tls13_t *t, const uint8_t *in, size_t n,
                uint8_t *out, size_t cap, size_t *outlen,
                uint8_t *app, size_t appcap, size_t *applen);

/* application_data を 1 レコードに暗号化する(n <= TLS13_PLAIN_MAX)。
 * 戻り値はレコードの長さ(5 + n + 1 + 16)。OPEN でなければ 0。 */
size_t tls13_seal(tls13_t *t, const void *in, size_t n, uint8_t *out);

/* 2 断片を続けた application_data を 1 レコードに暗号化して out へ書く(段階 G)。
 * 平文を写さずに済む(out は TCP の再送スロットでよい)。戻り値は長さ、OPEN でなければ 0。 */
size_t tls13_seal2(tls13_t *t, const void *p1, size_t l1, const void *p2, size_t l2, uint8_t *out);

/* close_notify のレコードを作る。戻り値は長さ。 */
size_t tls13_close(tls13_t *t, uint8_t *out);

const char *tls13_alert_name(uint8_t desc);
const char *tls13_suite_name(uint16_t suite);
const char *tls13_group_name(uint16_t group);

/* 既知の値との照合(RFC 8448 4 章を再現する)と、自作どうしの握手
 * (SHA-384 + ML-KEM-1024、HelloRetryRequest、CNSA 専用の陰性)。0=一致。 */
int tls13_selftest(char *err, size_t errlen);

#endif /* TLS13_H */
