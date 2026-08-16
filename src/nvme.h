#ifndef NVME_H
#define NVME_H

#include <stdint.h>
#include "nvme_tcp.h"
#include "nvme_types.h"

#define NVME_SUBNQN_MAX 224u

typedef struct {
    nvme_tcp_conn_t admin;
    nvme_tcp_conn_t io;
    int      io_connected;
    uint16_t ctrlr_id;
    uint32_t lba_size;   /* nvme_identify_ns()が設定する、現在のnamespaceのLBAサイズ(バイト) */
    uint64_t nsze;
    char     subnqn[NVME_SUBNQN_MAX];

    volatile int busy;
} nvme_ctx_t;

extern nvme_ctx_t s_nvme_ctx;

typedef struct {
    int               state;   /* nvme_exec_state_t(nvme.c)、呼び出し側は直接見ない */
    nvme_tcp_conn_t  *conn;
    const nvme_sqe_t *sqe;
    const void       *send_data;
    uint32_t          send_len;
    void             *recv_buf;
    uint32_t          recv_buflen;
    nvme_tcp_xfer_t   xfer;
    uint8_t           hdr_buf[8];   /* NVME_TCP_HDR_LEN */
    uint8_t           rest_buf[16];
    uint32_t          datao;
    uint32_t          datal;
    uint16_t          ttag;
    nvme_cqe_t        cqe_out;
    int               result;  /* 完了時: CQEステータス(0=success)、通信エラー等は-1 */
} nvme_exec_ctx_t;

void nvme_exec_begin(nvme_exec_ctx_t *ec, nvme_tcp_conn_t *conn, const nvme_sqe_t *sqe,
                      const void *send_data, uint32_t send_len,
                      void *recv_buf, uint32_t recv_buflen);

int nvme_exec_step(nvme_exec_ctx_t *ec);

void nvme_build_identify_sqe(nvme_sqe_t *sqe, uint8_t cns, uint32_t nsid);
void nvme_build_read_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len);
void nvme_build_write_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len);

void nvme_update_lba_size_from_id_ns(nvme_ctx_t *ctx, uint32_t nsid, const void *buf4096);

int nvme_connect_job_start(nvme_ctx_t *ctx, uint32_t ip, uint16_t port, const char *subnqn);

#define NVME_IO_QDEPTH 8u

int nvme_write_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                              const void *buf, uint32_t nlb, uint32_t duration_ms,
                              uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms);

int nvme_read_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                             void *buf, uint32_t nlb, uint32_t duration_ms,
                             uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms);

#endif /* NVME_H */
