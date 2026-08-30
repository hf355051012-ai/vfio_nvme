#ifndef NVME_H
#define NVME_H

#include <stdint.h>
#include "nvme_tcp.h"
#include "netaddr.h"
#include "nvme_types.h"

#define NVME_SUBNQN_MAX 224u

/* Discovery Log Page のレイアウト(struct nvmf_disc_rsp_page_hdr /
 * nvmf_disc_rsp_page_entry。どちらも 1024 バイト)。オフセットは
 * tools/disc_log_check.c の offsetof で確認済み。 */
#define NVME_DISC_HDR_BYTES    1024u
#define NVME_DISC_ENTRY_BYTES  1024u
#define NVME_DISC_OFF_GENCTR      0u
#define NVME_DISC_OFF_NUMREC      8u
#define NVME_DISC_OFF_RECFMT     16u

/* Discovery Log Page の受信バッファ上限。ヘッダ 1024 + エントリ 1024×4。
 * このターゲットのエントリは 1 個だが、余裕を見て 4 個ぶん確保しておく。 */
#define NVME_DISC_LOG_MAX (NVME_DISC_HDR_BYTES + 4u * NVME_DISC_ENTRY_BYTES)

typedef struct {
    nvme_tcp_conn_t admin;
    nvme_tcp_conn_t io;
    int      io_connected;
    uint16_t ctrlr_id;
    uint32_t lba_size;   /* nvme_identify_ns()が設定する、現在のnamespaceのLBAサイズ(バイト) */
    /* IO キューの Command Capsule に載せられる in-capsule データの上限
     * (Identify Controller の IOCCSZ から算出。0=in-capsule 不可)。
     * **これを見ずに R2T 経路へ倒すと Linux の nvmet-tcp とは通信できない** --
     * 相手は「長さが inline_data_size 以下の write は in-capsule のはず」と
     * 決め打ちして R2T を送らないため(nvmet_tcp_queue_response())。 */
    uint32_t icdsz;
    uint64_t nsze;
    char     subnqn[NVME_SUBNQN_MAX];

    /* 接続前に設定する。nvme_connect_job_start() が admin/IO 両キューの
     * ICReq 要求値へ配る。 */
    uint8_t  req_hdgst;
    uint8_t  req_ddgst;

    /* 接続前に 1 にすると Discovery コントローラとして接続する。Identify
     * Controller の後で Discovery Log Page を 2 回(ヘッダだけ → 全体)読み、
     * **IO キューは作らずに完了する**(Discovery コントローラは admin のみ)。 */
    uint8_t  discovery_mode;
    /* 読み取った Discovery Log Page。1024(ヘッダ)+ 1024×N(エントリ)。 */
    uint8_t  disc_log[NVME_DISC_LOG_MAX] __attribute__((aligned(64)));
    uint32_t disc_log_len;   /* 実際に読めたバイト数 */
    uint64_t disc_numrec;    /* ヘッダから読んだ NUMREC */

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
    /* 型固有部(16)+ヘッダダイジェスト(4)をまとめて 1 回で受ける。 */
    uint8_t           rest_buf[16 + 4];
    uint8_t           dgst_buf[4];  /* データダイジェストの受信先 */
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
void nvme_build_get_log_page_sqe(nvme_sqe_t *sqe, uint8_t lid, uint32_t lpo, uint32_t bytes);
void nvme_build_read_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len);
void nvme_build_write_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb,
                          uint32_t total_len, int use_inline);
/* 1 で in-capsule write を止め、R2T 経路へ倒す(A/B 用の恒久デバッグ機能)。 */
void nvme_set_incapsule_disable(int off);
/* NVMe/TCP の同時 outstanding 数(1..NVME_IO_QDEPTH)。 */
void     nvme_set_io_qdepth(unsigned d);
unsigned nvme_io_qdepth(void);

void nvme_update_lba_size_from_id_ns(nvme_ctx_t *ctx, uint32_t nsid, const void *buf4096);

/* 接続先を netaddr_t で指定する本体。IPv4/IPv6 のどちらでもよい。 */
int nvme_connect_job_start_addr(nvme_ctx_t *ctx, const netaddr_t *addr, uint16_t port,
                                const char *subnqn);

/* IPv4 用の薄いラッパ。 */
int nvme_connect_job_start(nvme_ctx_t *ctx, uint32_t ip, uint16_t port, const char *subnqn);

/* NVMe/TCP パイプラインの **同時 outstanding 数の上限**(静的配列の大きさ)。
 * 実際に使う本数は nvme_set_io_qdepth() で実行時に決める(既定 8)。
 * 深さを振って測るために可変にしてある。 */
#define NVME_IO_QDEPTH 128u

int nvme_write_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                              const void *buf, uint32_t nlb, uint32_t duration_ms,
                              uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms);

int nvme_read_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                             void *buf, uint32_t nlb, uint32_t duration_ms,
                             uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms);

#endif /* NVME_H */
