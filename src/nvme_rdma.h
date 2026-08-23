#ifndef NVME_RDMA_H
#define NVME_RDMA_H

#include <stdint.h>
#include "mlx5_qp.h"
#include "rdma_cm.h"
#include "job.h"
#include "nvme_types.h"

#define NVME_RDMA_MSG_MAX    2048u
#define NVME_RDMA_ID_BUF_LEN 4096u  /* Identify Controller/Namespace応答長 */
#define NVME_RDMA_TEST_LEN    512u  /* write/read検証(nvmerdmaconnect)に使うテストデータ長 */

#define NVME_RDMA_BENCH_BUF_MAX 262144u

typedef enum {
    NVMER_ST_CM_SPAWN = 0,
    NVMER_ST_CM_WAIT,
    NVMER_ST_SEND_CONNECT,
    NVMER_ST_WAIT_CONNECT,
    NVMER_ST_SEND_PROP_SET_CC,
    NVMER_ST_WAIT_PROP_SET_CC,
    NVMER_ST_SEND_PROP_GET_CSTS,
    NVMER_ST_WAIT_PROP_GET_CSTS,
    NVMER_ST_CSTS_POLL_WAIT,
    NVMER_ST_SEND_ID_CTRL,
    NVMER_ST_WAIT_ID_CTRL,
    NVMER_ST_SEND_ID_NS,
    NVMER_ST_WAIT_ID_NS,
    NVMER_ST_IOQ_CM_SPAWN,
    NVMER_ST_IOQ_CM_WAIT,
    NVMER_ST_IOQ_SEND_CONNECT,
    NVMER_ST_IOQ_WAIT_CONNECT,
    NVMER_ST_SEND_WRITE,
    NVMER_ST_WAIT_WRITE,
    NVMER_ST_SEND_READ,
    NVMER_ST_WAIT_READ,
    NVMER_ST_PIPELINE_SETUP,
    NVMER_ST_PIPELINE_LOOP,
    NVMER_ST_DONE_OK,
    NVMER_ST_DONE_FAIL,
} nvme_rdma_state_t;

#define NVME_RDMA_PL_QDEPTH_MAX 15u

typedef struct {
    rdma_cm_ctx_t cm;   /* CM確立(established後、cm.dev/cm.rc_qpが本命のQP) */
    /* IO キュー(qid=1)は **別の CM 接続と別の QP** になる。
     * Linux は admin キューで IO コマンドを受け付けない
     * (opcode 0x02 は admin では Get Log Page になる)ので、
     * 実ホストと相互運用するにはこちらが要る。 */
    rdma_cm_ctx_t io_cm;
    int bench_peeked;    /* read データの先頭を一度だけ表示するための印 */
    int io_queue_ready;  /* 1=以後の IO は io_cm.rc_qp を使う */

    uint16_t cntlid;
    uint32_t lba_size;
    uint64_t nsze;
    uint64_t bench_cur_lba;  /* ベンチで次に発行するコマンドの開始 LBA。 */
    uint32_t nsid;
    unsigned csts_poll_count;
    uint64_t wait_started_ticks;

    volatile uint8_t write_buf[NVME_RDMA_BENCH_BUF_MAX] __attribute__((aligned(64)));
    volatile uint8_t read_buf[NVME_RDMA_BENCH_BUF_MAX] __attribute__((aligned(64)));
    volatile uint8_t id_ctrl[NVME_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));
    volatile uint8_t id_ns[NVME_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));

    volatile uint8_t send_buf[NVME_RDMA_MSG_MAX] __attribute__((aligned(64)));
    volatile uint8_t recv_buf[NVME_RDMA_MSG_MAX] __attribute__((aligned(64)));

    int      send_done;
    int      recv_done;
    uint32_t recv_len;
    uint64_t cmd_deadline;
    uint16_t cur_cid;
    nvme_cqe_t cqe_out;

    int failed;
    int done;     /* トップレベルのCONNECT->WRITE->READ(またはbenchループ)が完走したら1 */
    int write_ok;
    int read_ok;

    volatile int stop_requested;

    int      bench_enabled;
    int      bench_is_read;      /* 1=read繰り返し、0=write繰り返し */
    uint32_t bench_chunk_bytes;  /* 1コマンドあたりの転送バイト数(lba_sizeの倍数) */
    uint32_t bench_duration_ms;
    uint64_t bench_start_ticks;
    uint32_t bench_count;
    uint64_t bench_bytes;

    uint32_t bench_qdepth;

    int      reusable;
    uint32_t established_generation;
} nvme_rdma_ctx_t;

job_result_t nvme_rdma_connect_job_step(job_t *self);

void nvme_rdma_run_bench(mlx5_dev_t *dev0, mlx5_dev_t *dev1, uint32_t duration_ms,
                         int is_read, uint32_t chunk_bytes, uint32_t qdepth,
                         uint64_t *out_bytes, uint32_t *out_count,
                         uint32_t *out_elapsed_ms);

void nvme_rdma_set_peer_override(int enable, uint32_t ip, const uint8_t mac[6]);

/* 外部ホストのターゲットへ繋ぐ設定。**有効にすると同一プロセス内の
 * ターゲットを立てず、イニシエータだけを動かす。** PF0<->PF1 の RoCEv2 は
 * FW が内部で折り返して消すので、実際に相互運用できる相手はこちらだけ。 */
#define NVME_RDMA_SUBNQN_MAX 224u

typedef struct {
    int      enabled;
    uint32_t ip;               /* host order */
    uint8_t  mac[6];
    uint16_t port;             /* NVMe-oF のポート(既定 4420)*/
    char     subnqn[NVME_RDMA_SUBNQN_MAX];
} nvme_rdma_remote_t;

void nvme_rdma_set_remote_target(int enable, uint32_t ip, const uint8_t mac[6],
                                 uint16_t port, const char *subnqn);
const nvme_rdma_remote_t *nvme_rdma_remote_target(void);

/* Identify Namespace が信用できない相手向けの手動上書き。
 * lba_size=0 で解除。**正常な相手には使わないこと。** */
void nvme_rdma_set_ns_override(uint32_t lba_size, uint64_t nsze);
void nvme_rdma_get_ns_override(uint32_t *lba_size, uint64_t *nsze);

#endif /* NVME_RDMA_H */
