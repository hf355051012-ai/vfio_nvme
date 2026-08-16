#ifndef NVMET_TCP_H
#define NVMET_TCP_H

#include <stdint.h>
#include "tcp.h"
#include "nvme_types.h"
#include "nvme_tcp_pdu.h"  /* NVME_TCP_HDR_LEN(下記API群のヘッダバッファサイズに使う) */

typedef struct {
    tcp_conn_t tcp;
    uint16_t   maxdata;
    uint16_t   last_cid;
    uint8_t    hdgst;
    uint8_t    ddgst;
} nvmet_tcp_conn_t;

void nvmet_tcp_accept_arm(nvmet_tcp_conn_t *c, int listener);

int nvmet_tcp_send_r2t(nvmet_tcp_conn_t *c, uint16_t cid,
                        uint32_t r2to, uint32_t r2tl);

uint32_t nvmet_tcp_max_h2c_data(const nvmet_tcp_conn_t *c);

int nvmet_tcp_send_resp(nvmet_tcp_conn_t *c, const nvme_cqe_t *cqe);

int nvmet_tcp_send_c2h(nvmet_tcp_conn_t *c, uint16_t cid, const nvme_cqe_t *cqe,
                       const void *data, uint32_t dlen,
                       int data_success);

int nvmet_tcp_send_c2h_async(nvmet_tcp_conn_t *c, uint16_t cid,
                              const void *data, uint32_t dlen);

/* コネクションを閉じる(tcp_close()をそのまま呼ぶ)。 */
void nvmet_tcp_close(nvmet_tcp_conn_t *c);

typedef struct {
    uint8_t  *buf;
    uint32_t  want;
    uint32_t  got;
} nvmet_tcp_xfer_t;

/* 新しい受信を開始する(got=0にリセットするだけ)。 */
void nvmet_tcp_xfer_reset(nvmet_tcp_xfer_t *x, void *buf, uint32_t want);

int nvmet_tcp_recv_poll(nvmet_tcp_conn_t *c, nvmet_tcp_xfer_t *x);

uint32_t nvmet_tcp_parse_cmd_dlen(const nvmet_tcp_conn_t *c, const uint8_t hdr_buf[NVME_TCP_HDR_LEN]);

int nvmet_tcp_verify_hdgst(const nvmet_tcp_conn_t *c,
                            const void *hdr1, uint32_t len1,
                            const void *hdr2, uint32_t len2,
                            const uint8_t got[4]);
int nvmet_tcp_check_ddgst_crc(const nvmet_tcp_conn_t *c, uint32_t running_crc,
                               const uint8_t got[4]);

int nvmet_tcp_verify_ddgst(const nvmet_tcp_conn_t *c,
                            const void *data, uint32_t len,
                            const uint8_t got[4]);

int nvmet_tcp_send_icresp(nvmet_tcp_conn_t *c, const uint8_t icreq_buf[NVME_TCP_ICREQ_LEN]);

#endif /* NVMET_TCP_H */
