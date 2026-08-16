#ifndef NVME_TCP_H
#define NVME_TCP_H

#include <stdint.h>
#include "tcp.h"
#include "nvme_types.h"
#include "nvme_tcp_pdu.h"  /* NVME_TCP_ICRESP_LEN(下記ジョブ化向けAPI群のヘッダバッファサイズに使う) */

typedef struct {
    tcp_conn_t tcp;
    uint32_t   maxdata;    /* ICRespのMAXH2CDATA -- 1回のH2CDataで送れる最大バイト数 */
    uint16_t   next_cid;   /* コマンドID採番カウンタ(nvme_tcp_send_cmd()が使用) */

    const uint8_t *pending_data;
    uint32_t       pending_len;
    uint16_t       pending_cid;
} nvme_tcp_conn_t;

int nvme_tcp_send_cmd(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe,
                      const void *data, uint32_t dlen);

int nvme_tcp_send_cmd_async(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe, uint16_t *out_cid);

/* コネクションを閉じる(tcp_close()をそのまま呼ぶ)。 */
void nvme_tcp_close(nvme_tcp_conn_t *c);

typedef struct {
    uint8_t  *buf;
    uint32_t  want;
    uint32_t  got;
    uint64_t  reset_tick;
} nvme_tcp_xfer_t;

void nvme_tcp_xfer_reset(nvme_tcp_xfer_t *x, void *buf, uint32_t want);

int nvme_tcp_recv_poll(nvme_tcp_conn_t *c, nvme_tcp_xfer_t *x);

int nvme_tcp_send_icreq(nvme_tcp_conn_t *c);

int nvme_tcp_verify_icresp(nvme_tcp_conn_t *c, const uint8_t icresp_buf[NVME_TCP_ICRESP_LEN]);

int nvme_tcp_send_h2c_data(nvme_tcp_conn_t *c, uint16_t ttag, uint32_t r2to, uint32_t r2tl);

int nvme_tcp_send_h2c_data_ex(nvme_tcp_conn_t *c, uint16_t cid, uint16_t ttag,
                               uint32_t r2to, uint32_t r2tl,
                               const void *data, uint32_t data_len);

#endif /* NVME_TCP_H */
