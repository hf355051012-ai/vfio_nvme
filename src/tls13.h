#ifndef TLS13_H
#define TLS13_H

/* TLS 1.3 のサーバ側(PLAN_auth_tls.md 段階 D)。NVMe/TCP の secure channel 用。
 *
 * **できることを絞ってある**(相手は Linux の tlshd = GnuTLS):
 *   - 暗号スイートは TLS_AES_128_GCM_SHA256 だけ。
 *   - 認証は外部 PSK だけ(証明書は使わない)。鍵交換は psk_dhe_ke + x25519
 *     (tlshd は psk_ke を出さない。key_share に x25519 を入れてくる)。
 *   - HelloRetryRequest・0-RTT・セッションチケットは使わない。
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

/* NVMe/TCP の PSK 1 本(身元とその TLS PSK)。 */
typedef struct {
    char     identity[TLS13_IDENT_MAX];
    uint16_t identity_len;
    uint8_t  psk[32];
} tls13_psk_t;

typedef enum {
    TLS13_ST_WAIT_CH = 0,   /* ClientHello 待ち */
    TLS13_ST_WAIT_CFIN,     /* こちらの Finished まで送った。相手の Finished 待ち */
    TLS13_ST_OPEN,          /* 握手が済んだ。application_data が流せる */
    TLS13_ST_CLOSED,        /* close_notify を受けた */
    TLS13_ST_FAILED,        /* alert を送った / 受けた */
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
    TLS13_ALERT_UNKNOWN_PSK_IDENTITY = 115,
};

/* 1 方向のレコードの鍵 */
typedef struct {
    crypto_aes128gcm_t aead;
    uint8_t  iv[12];
    uint64_t seq;
    uint8_t  secret[32];   /* KeyUpdate で次の鍵を作る元 */
    int      on;
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

    tls13_keylog_fn keylog;       /* SSLKEYLOGFILE 形式の 1 行を渡す(NULL 可)*/
    void    *keylog_arg;

    /* 自己検査用のつまみ(RFC 8448 の再現)。通常は 0 / NULL。 */
    const uint8_t *test_random;   /* サーバの乱数を固定 */
    const uint8_t *test_priv;     /* x25519 の秘密鍵を固定 */
    const uint8_t *test_ee;       /* EncryptedExtensions をこのバイト列にする */
    size_t   test_ee_len;
    int      test_resumption;     /* binder の label を "res binder" にし、身元を問わず先頭を選ぶ */

    crypto_hash_ctx_t th;         /* 握手の transcript */
    uint8_t  crandom[32];
    uint8_t  c_hs[32], s_hs[32], master[32];
    uint8_t  cfin[32];            /* 相手の Finished の期待値 */

    tls13_dir_t rx, tx;

    uint8_t  rbuf[TLS13_REC_MAX]; /* レコードの組み立て */
    size_t   rlen;
    uint8_t  hbuf[TLS13_HS_MAX];  /* 握手メッセージの組み立て(レコードをまたぐ場合)*/
    size_t   hlen;
} tls13_t;

/* NVMeTLSkey-1:hh:<base64>: から、NVMe/TCP の身元と TLS PSK を作る
 * (libnvme の derive_nvme_keys() と同じ。身元の版 1 = "NVMe1R01 host sub digest" と
 * 版 0 = "NVMe0R01 host sub" の 2 本を out[0..1] に入れる)。
 * 戻り値は作った本数(2)、鍵の形式が悪ければ -1(why に理由)。 */
int tls13_nvme_psk(tls13_psk_t out[2], const char *keystr, const char *hostnqn,
                   const char *subnqn, const char **why);

void tls13_server_init(tls13_t *t, const tls13_psk_t *psks, unsigned npsk);

/* 受け取ったバイト列を食わせる。送るべきバイト列を out へ(*outlen)、復号した
 * application_data を app へ(*applen、appcap を超えたら失敗)追記する。
 * 戻り値: 0=続行、-1=失敗(out に alert が入っている。state は FAILED)。 */
int tls13_input(tls13_t *t, const uint8_t *in, size_t n,
                uint8_t *out, size_t cap, size_t *outlen,
                uint8_t *app, size_t appcap, size_t *applen);

/* application_data を 1 レコードに暗号化する(n <= TLS13_PLAIN_MAX)。
 * 戻り値はレコードの長さ(5 + n + 1 + 16)。OPEN でなければ 0。 */
size_t tls13_seal(tls13_t *t, const void *in, size_t n, uint8_t *out);

/* close_notify のレコードを作る。戻り値は長さ。 */
size_t tls13_close(tls13_t *t, uint8_t *out);

const char *tls13_alert_name(uint8_t desc);

/* 既知の値との照合(RFC 8448 4 章を再現する)。0=一致。 */
int tls13_selftest(char *err, size_t errlen);

#endif /* TLS13_H */
