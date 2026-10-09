#ifndef NVMET_TLS_H
#define NVMET_TLS_H

/* NVMe/TCP ターゲットの TLS 1.3(PLAN_auth_tls.md 段階 D / E)。
 *
 * 設定(シェルの `nvmettls`)と、接続 1 本ぶんの握手・レコード層。TLS 自体は tls13.c。
 * TCP が確立したら **ICReq より前に** 握手する(NVMe/TCP の決まり。Linux の
 * nvmet_tcp も tlshd に握手させてから ICReq を待つ)。Linux のホストは admin と
 * IO キューの**全部の接続で**握手してくる。
 *
 * 段階 E(レコード層): nvmet_tcp_conn_t.tls が NULL でなければ、
 *   - 送信: nvmet_tcp.c の送信関数が全部 nvmet_tls_send() を通る。平文を
 *     16KB までのレコードに暗号化して tcp_send_async() へ(再送スロットには
 *     暗号文が入るので、再送は同じ暗号文を送り直すだけ)。ゼロコピー送信は使わない。
 *   - 受信(pull): nvmet_tcp_recv_poll() が nvmet_tls_recv() から平文を読む。
 *   - 受信(push): IO キューの upcall の前に nvmet_tls_feed() を挟み、
 *     **タグの検証が通った平文だけ**を元のパーサへ流す。
 * 受信の途中で生まれた送信(KeyUpdate の応答、alert)は溜めておき、次の送信の
 * 頭で必ず先に吐く(upcall の中からは送らない約束のため)。
 */

#include <stdint.h>
#include <stddef.h>
#include "tcp.h"
#include "tls13.h"

#define NVMET_TLS_APP_MAX  (2u * TLS13_PLAIN_MAX + 8192u)  /* 平文の溜め */
#define NVMET_TLS_FEED     8192u                           /* 1 回に食わせる暗号文 */

/* 接続 1 本ぶん */
typedef struct nvmet_tls_conn {
    tls13_t  t;
    uint8_t  pend[2048];           /* 送るべきもの(握手の応答、KeyUpdate、alert)*/
    size_t   pendlen;
    uint8_t  in[NVMET_TLS_FEED];   /* TCP から読んだ暗号文 */
    uint8_t  app[NVMET_TLS_APP_MAX]; /* 復号した平文(pull 用の待ち行列 / push 用の作業域)*/
    size_t   applen, apphead;
    uint8_t  rec[TLS13_REC_MAX];   /* 送信レコードの組み立て */
    int      failed;
    uint64_t rx_records, tx_records, rx_bytes, tx_bytes;
    tls13_psk_t cpsk;               /* クライアント: この接続の PSK(身元は host / sub で決まる)*/
} nvmet_tls_conn_t;

int  nvmet_tls_enabled(void);   /* TLS を必須にしている(`nvmettls` で鍵を設定した)*/
/* TLS を受けられる(設定した鍵か、concatenation で生成した鍵がある)。必須でなければ
 * 最初のバイトで TLS(0x16)か平文の ICReq(0x00)かを見分ける(段階 H)。 */
int  nvmet_tls_possible(void);
/* concatenation で生成した PSK を登録する(以後の TLS の握手で使える)。 */
void nvmet_tls_set_generated(const tls13_psk_t *p);
/* 握手を始める前に TCP から読んでしまったバイト(ICReq のつもりで読んだ ClientHello の頭)を
 * 食わせる。戻り値は nvmet_tls_poll() と同じ。 */
int  nvmet_tls_preload(nvmet_tls_conn_t *s, tcp_conn_t *tcp, const uint8_t *buf, size_t n);
/* nvmettls [<hostnqn> <NVMeTLSkey-1:..> [keylog <path>] | off | corrupt <N>] */
void nvmet_tls_shell(const char *args);

/* 握手を始める(TCP が確立した直後)。 */
void nvmet_tls_start(nvmet_tls_conn_t *s);
/* 握手を進める。戻り値: 0=続行、1=握手済み、-1=失敗(alert は送った)。
 * 握手の後に続けて届いた平文は待ち行列に残る(nvmet_tls_recv() で読める)。 */
int  nvmet_tls_poll(nvmet_tls_conn_t *s, tcp_conn_t *tcp);

/* ---- 段階 E: レコード層 ---- */
/* 平文を読む。戻り値: >0=読んだバイト数、0=まだ無い、-1=相手が閉じた / 失敗。 */
int  nvmet_tls_recv(nvmet_tls_conn_t *s, tcp_conn_t *tcp, uint8_t *dst, uint32_t max);
/* 1〜2 断片を暗号化して送る。戻り値: 0=成功、-1=失敗。 */
int  nvmet_tls_send(nvmet_tls_conn_t *s, tcp_conn_t *tcp, const void *p1, uint32_t l1,
                    const void *p2, uint32_t l2);
/* push 型: 届いた暗号文を食わせ、検証の通った平文を deliver へ渡す。
 * 戻り値: 0=続行、-1=失敗(相手の alert / 壊れたレコード)。 */
typedef void (*nvmet_tls_deliver_fn)(void *arg, const volatile uint8_t *data, uint16_t len);
int  nvmet_tls_feed(nvmet_tls_conn_t *s, const volatile uint8_t *data, uint16_t len,
                    nvmet_tls_deliver_fn deliver, void *arg);
/* 待ち行列に残っている平文を deliver へ渡す(upcall を付けた直後に呼ぶ)。 */
void nvmet_tls_drain(nvmet_tls_conn_t *s, nvmet_tls_deliver_fn deliver, void *arg);
/* 溜めた送信を吐き、close_notify を送り、状態を消す。 */
void nvmet_tls_close(nvmet_tls_conn_t *s, tcp_conn_t *tcp);

/* ---- 段階 F: イニシエータ側(内蔵イニシエータの `tcpbench ... tls`)---- */
int  nvme_tls_client_enabled(void);
/* nvmetls [<NVMeTLSkey-1:..> [keylog <path>] | off] */
void nvme_tls_client_shell(const char *args);
/* ClientHello を送って握手を始める(以後は nvmet_tls_poll() で進める)。0=送った、-1=失敗。 */
int  nvme_tls_client_start(nvmet_tls_conn_t *s, tcp_conn_t *tcp, const char *hostnqn, const char *subnqn);

/* 検証用: 次に送る N 個のレコードの暗号文を 1 ビット壊す(`nvmettls corrupt N`)。 */
extern volatile uint32_t g_nvmet_tls_corrupt;

#endif /* NVMET_TLS_H */
