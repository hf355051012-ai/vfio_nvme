#ifndef NVMET_TLS_H
#define NVMET_TLS_H

/* NVMe/TCP ターゲットの TLS 1.3(PLAN_auth_tls.md 段階 D)。
 *
 * 設定(シェルの `nvmettls`)と、接続 1 本ぶんの握手の駆動。TLS 自体は tls13.c。
 * TCP が確立したら **ICReq より前に** 握手する(NVMe/TCP の決まり。Linux の
 * nvmet_tcp も tlshd に握手させてから ICReq を待つ)。
 *
 * 段階 D の範囲: 握手を通し、最初の暗号文(ICReq)を復号して読めることを
 * 確かめるまで。**PDU 全体を暗号化して流すのは段階 E(レコード層)**なので、
 * いまは ICReq を確かめたら close_notify で閉じる。
 */

#include <stdint.h>
#include <stddef.h>
#include "tcp.h"
#include "tls13.h"

/* 接続 1 本ぶん */
typedef struct {
    tls13_t  t;
    uint8_t  out[2048];            /* 握手でこちらが送るもの(SH + CCS + EE/Finished)*/
    uint8_t  in[4096];             /* TCP から読んだ暗号文 */
    uint8_t  app[4096];            /* 復号した平文 */
    size_t   applen;
} nvmet_tls_conn_t;

int  nvmet_tls_enabled(void);
/* nvmettls [<hostnqn> <NVMeTLSkey-1:..> [keylog <path>] | off] */
void nvmet_tls_shell(const char *args);

/* 握手を始める(TCP が確立した直後)。 */
void nvmet_tls_start(nvmet_tls_conn_t *s);
/* 届いた分を処理して、返すべきものを送る。
 * 戻り値: 0=続行(まだ握手中、または平文がまだ足りない)、1=握手済み、-1=失敗(alert は送った)。 */
int  nvmet_tls_poll(nvmet_tls_conn_t *s, tcp_conn_t *tcp);
/* close_notify を送る。 */
void nvmet_tls_close(nvmet_tls_conn_t *s, tcp_conn_t *tcp);

#endif /* NVMET_TLS_H */
