#ifndef NVMET_RDMA_H
#define NVMET_RDMA_H

#include <stdint.h>
#include "mlx5_qp.h"
#include "rdma_cm.h"
#include "job.h"
#include "nvme_types.h"

#define NVMET_RDMA_LBA_SIZE      512u
#define NVMET_RDMA_NS_LBA_COUNT (NVMET_RDMA_RAMDISK_SLOT_SIZE / NVMET_RDMA_LBA_SIZE)
#define NVMET_RDMA_INLINE_MAX  4096u  /* in-capsule データの上限(Linux nvmet の既定と同じ)*/
#define NVMET_RDMA_MSG_MAX     (64u + NVMET_RDMA_INLINE_MAX)
#define NVMET_RDMA_ID_BUF_LEN  4096u
#define NVMET_RDMA_SUBNQN "nqn.2014-08.org.nvmexpress:uuid:deadbeef-rdma-babe-dead-beefcafebabe"

#define NVMET_RDMA_SC_ERROR 0x0002u

/* パイプラインのスロット数 = **投稿しておく RECV の本数**。
 * ホストへ広告する MAXCMD(下)より必ず大きくすること。**同じ値にすると
 * ホストが上限まで出した瞬間に RQ が空になり、以後の CapsuleCmd が
 * RNR NAK でリトライに落ちる**(エラーは 1 つも出ず、ただ極端に遅くなる)。
 * 実機では qd=12 の 64k write が 830 -> 2 MiB/s に落ちた。 */
#define NVMET_RDMA_MAX_PENDING 192u

/* Identify Controller の MAXCMD として広告する値(ホストの同時発行数の上限)。
 * SQ は 64 WQEBB なので、1 コマンドあたり最大 2 WQE として 32 まで。 */
#define NVMET_RDMA_MAXCMD 128u

typedef enum {
    NVMETR_ST_CM_SPAWN = 0,
    NVMETR_ST_CM_WAIT,
    NVMETR_ST_POST_RECV,
    NVMETR_ST_WAIT_CAPSULE,
    NVMETR_ST_DATA_MOVE,
    NVMETR_ST_WAIT_DATA_MOVE,
    NVMETR_ST_SEND_RESP,
    NVMETR_ST_WAIT_RESP_SENT,
    NVMETR_ST_PIPELINE_SETUP,
    NVMETR_ST_PIPELINE_LOOP,
} nvmet_rdma_state_t;

typedef struct {
    uint16_t ctrlr_id;   /* 固定値1(nvme_rdma.cのcntlidと一致させる) */
    uint32_t cc;
    int      cc_en;

    volatile uint8_t id_ctrl[NVMET_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));
    volatile uint8_t id_ns[NVMET_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));

    volatile uint8_t *ram_disk;
} nvmet_rdma_ctrl_t;

/* 1インスタンス分の RAM ディスク容量(dma_alloc で確保する、nvmet_rdma.c)。 */
#define NVMET_RDMA_RAMDISK_SLOT_SIZE 0x10000000ULL  /* 256MB */

typedef struct {
    uint16_t cid;
    uint8_t  opcode;
    uint8_t  fctype;
    uint32_t nsid;
    uint32_t cdw10, cdw11, cdw12;
    uint64_t ksgl_addr;
    uint32_t ksgl_len;
    uint32_t ksgl_key;
    uint64_t io_slba;
    int      need_data_move;
    int      data_inline;        /* 1=データが受信 capsule に載っている(RDMA_READ 不要)*/
    uint32_t inline_off;        /* capsule 先頭の SQE(64B)からの相対オフセット */
    int      data_move_is_write;
    uint32_t resp_dw0;
    uint32_t resp_dw1;
    uint16_t resp_status;
} nvmet_rdma_pl_pending_t;

/* SQ(RDMA_WRITE/READ+応答SEND)の完了を先入れ先出しで追跡する。 */
typedef struct {
    int      is_resp_send;
    unsigned slot;
} nvmet_rdma_pl_sqop_t;

typedef struct {
    nvmet_rdma_pl_pending_t pending[NVMET_RDMA_MAX_PENDING];
    volatile uint8_t recv_bufs[NVMET_RDMA_MAX_PENDING][NVMET_RDMA_MSG_MAX] __attribute__((aligned(64)));
    volatile uint8_t resp_bufs[NVMET_RDMA_MAX_PENDING][NVME_CQE_LEN] __attribute__((aligned(64)));

    unsigned rq_order[NVMET_RDMA_MAX_PENDING];
    unsigned rq_head, rq_tail;

    nvmet_rdma_pl_sqop_t sq_ops[NVMET_RDMA_MAX_PENDING * 2u];
    unsigned sq_head, sq_tail;

    uint32_t rra_inflight;
    uint32_t rra_max;
    unsigned rra_pending[NVMET_RDMA_MAX_PENDING];
    unsigned rra_pending_head, rra_pending_tail;
} nvmet_rdma_pl_state_t;

typedef struct nvmet_rdma_ctx nvmet_rdma_ctx_t;

struct nvmet_rdma_ctx {
    rdma_cm_ctx_t cm;

    nvmet_rdma_ctrl_t *ctrl;

    uint8_t  queue_id;

    int      enable_io_queue;

    volatile uint8_t recv_buf[NVMET_RDMA_MSG_MAX] __attribute__((aligned(64)));
    volatile uint8_t send_buf[NVMET_RDMA_MSG_MAX] __attribute__((aligned(64)));

    /* 現在処理中のコマンドの解析結果(DATA_MOVE/SEND_RESPステートで参照)。 */
    uint32_t recv_len;
    uint8_t  opcode;
    uint8_t  fctype;
    uint32_t nsid;
    uint16_t cid;
    uint32_t cdw10, cdw11, cdw12;
    uint64_t ksgl_addr;
    uint32_t ksgl_len;
    uint32_t ksgl_key;
    uint32_t resp_dw0;
    uint32_t resp_dw1;
    uint16_t resp_status;
    int      need_data_move;      /* 1ならDATA_MOVEステートを経由する */
    int      data_inline;         /* 1ならデータが受信capsuleに載っている */
    int      data_move_is_write;
    uint64_t io_slba;             /* Write時、RDMA_READ完了後にram_diskへコミットする位置 */

    uint64_t deadline;
    int      failed;
    int      established;

    volatile int stop_requested;

    int pipeline_enabled;

    nvmet_rdma_pl_state_t pl;

    /* [関数ポインタ登録先] nvmetr_on_admin_established(nvmet_rdma.c、s_standalone_ctxに登録)。 */
    void (*on_established)(nvmet_rdma_ctx_t *self);

    const char *self_label;
    uint8_t peer_mac_fallback[6];
    /* [関数ポインタ登録先] nvmetr_on_admin_disconnected(nvmet_rdma.c、s_standalone_ctxに登録)。 */
    void (*on_disconnected)(nvmet_rdma_ctx_t *self);
};

/* 外部ホスト向けの常駐 NVMe-oF RDMA ターゲットを起動する。
 * peer_mac は REP を返すときの宛先 L2 アドレス(CM には含まれないため)。 */
void nvmet_rdma_run_standalone(mlx5_dev_t *dev, const char *self_label, const uint8_t peer_mac[6]);

job_result_t nvmet_rdma_job_step(job_t *self);

#endif /* NVMET_RDMA_H */
