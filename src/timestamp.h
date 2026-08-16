#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <stdint.h>

#define TS_LOG_BYTES        (1024u * 1024u)
#define TS_LOG_ENTRY_BYTES  64u
#define TS_LOG_COUNT        (TS_LOG_BYTES / TS_LOG_ENTRY_BYTES)

#define TS_KIND_PLAIN     0u  /* ts_log(): tag/argのみ有効 */
#define TS_KIND_NVME_PDU  1u  /* ts_log_nvme_tcp_pdu(): PDU系フィールドが有効 */
#define TS_KIND_TCP_ACK   2u  /* ts_log_tcp_ack(): TCP系フィールドが有効 */
#define TS_KIND_RDMA      3u  /* ts_log_rdma(): ConnectX SQ/RQ WQE投稿・CQE消費系フィールドが有効 */

typedef struct {
    uint64_t ticks;         /*  0: timer_now()の値 */
    uint32_t tag;            /*  8: File#|Func#|info(TS_MK()で組み立てる) */
    uint32_t arg;

    uint8_t  kind;            /* 16: TS_KIND_* */
    uint8_t  pdu_type;
    uint8_t  hlen;             /* 18: CH: PDUヘッダ長(nvme_tcp_hdr_t.hlen) / RDMA: ds_cnt */
    uint8_t  pdo;              /* 19: CH: PDU Data Offset(nvme_tcp_hdr_t.pdo) */
    uint16_t cid;             /* 20: PSH: Command ID(CapsuleCmd/RSP) / RDMA: rkey上位16bit */
    uint16_t cccid;
    uint16_t status;          /* 24: PSH: NVMeステータス(RSPのみ) / RDMA: syndrome */
    uint16_t tcp_flags;       /* 26: TCPフラグビット */
    uint32_t pdu_len;         /* 28: CH: PDU全体長(plen) / RDMA: qpn */
    uint32_t data_offset;
    uint32_t data_length;
    uint32_t ttag;            /* 40: PSH: Transfer Tag(R2T/H2CData) / RDMA: sq_pc/rq_pc/cq_cc */
    uint32_t tcp_seq;         /* 44: TCP seq */
    uint32_t tcp_ack_seq;     /* 48: TCP ack_seq */
    uint32_t tcp_window;      /* 52: 実効ウィンドウサイズ(スケーリング適用後) */

    uint8_t  conn_slot;
    uint8_t  opcode;
    uint8_t  sgl_type;
    uint8_t  pad[5];          /* 59: 予約(将来拡張用、常に0) */
} ts_entry_t;                 /* 64 bytes */

typedef struct {
    /* CH: 全PDU種別共通(nvme_tcp_pdu.hのnvme_tcp_hdr_t参照) */
    uint8_t  pdu_type;
    uint8_t  hlen;
    uint8_t  pdo;
    uint32_t plen;

    /* PSH: pdu_typeに応じて有効な組み合わせが変わる(上記コメント参照) */
    uint16_t cid;
    uint8_t  opcode;
    uint8_t  sgl_type;
    uint16_t status;
    uint16_t cccid;
    uint32_t ttag;
    uint32_t data_offset;
    uint32_t data_length;
} ts_nvme_pdu_t;

#define TS_RDMA_OP_SQ_SEND        1u  /* mlx5_qp_post_send()/post_send_ud() */
#define TS_RDMA_OP_SQ_RDMA_WRITE  2u  /* mlx5_qp_post_rdma_write() */
#define TS_RDMA_OP_SQ_RDMA_READ   3u  /* mlx5_qp_post_rdma_read() */
#define TS_RDMA_OP_RQ_POST        4u  /* mlx5_qp_post_recv()/post_recv_gsi() */
#define TS_RDMA_OP_CQE            5u  /* poll_cqe()系が成功CQEを消費(rc==1) */
#define TS_RDMA_OP_CQE_ERR        6u  /* poll_cqe()系がエラー系CQEを消費(rc==-1) */
#define TS_RDMA_OP_CMD_RECV       7u

typedef struct {
    uint8_t  rdma_op;       /* TS_RDMA_OP_* */
    uint8_t  wqe_cqe_opcode;
    uint8_t  ds_cnt;         /* SQ投稿のみ有効(WQEのdata segment数) */
    uint8_t  syndrome;       /* CQE_ERRのみ有効 */
    uint32_t qpn;
    uint32_t counter;        /* このイベント時点のsq_pc/rq_pc/cq_cc */
    uint32_t len;
    uint32_t remote_addr;
    uint32_t remote_rkey;    /* RDMA_WRITE/READのみ有効 */
} ts_rdma_t;

#define TS_MK(file, func, info) \
    ( ((uint32_t)(uint8_t)(file) << 24) \
    | ((uint32_t)(uint8_t)(func) << 16) \
    | ((uint32_t)(uint16_t)(info)) )

#define TS_TAG_FILE(tag) ((uint8_t)((uint32_t)(tag) >> 24))
#define TS_TAG_FUNC(tag) ((uint8_t)((uint32_t)(tag) >> 16))
#define TS_TAG_INFO(tag) ((uint16_t)(uint32_t)(tag))

enum ts_file {
    TS_FILE_TCP        = 0x01u,
    TS_FILE_NVME       = 0x02u,
    TS_FILE_MLX5_NET   = 0x03u,
    TS_FILE_NVMET      = 0x04u,
    TS_FILE_NVMET_TCP  = 0x05u,
    TS_FILE_MLX5_QP    = 0x06u,
    TS_FILE_ETH        = 0x07u,
    TS_FILE_NVME_TCP   = 0x08u,
    TS_FILE_NVMET_RDMA = 0x09u,
};

enum ts_func {
    /* tcp.c (0x0X) */
    TS_FUNC_tcp_send_segment      = 0x01u,
    TS_FUNC_tcp_send              = 0x02u,
    TS_FUNC_tcp_recv_internal     = 0x03u,
    TS_FUNC_tcp_input             = 0x04u,
    TS_FUNC_tcp_async_poll        = 0x05u,
    TS_FUNC_tcp_async_short_poll  = 0x06u,
    TS_FUNC_tcp_send_async_enqueue= 0x07u,
    TS_FUNC_tcp_send_async_short  = 0x08u,
    /* nvme.c (0x1X) */
    TS_FUNC_nvme_read_pipelined_run   = 0x10u,
    TS_FUNC_nvme_write_pipelined_run  = 0x11u,
    TS_FUNC_nvme_pipeline_read_rx_tick= 0x12u,
    TS_FUNC_nvme_pipeline_rx_tick     = 0x13u,
    TS_FUNC_nvme_pipeline_h2c_pump    = 0x14u,
    TS_FUNC_nvme_connect_job_step     = 0x15u,
    TS_FUNC_nvme_exec_step            = 0x16u,
    /* mlx5_net.c (0x2X) */
    TS_FUNC_mlx5_net_post_frame       = 0x20u,
    TS_FUNC_mlx5_net_post_lso_frame   = 0x21u,
    TS_FUNC_mlx5_net_sq_wait_room     = 0x22u,
    TS_FUNC_mlx5_net_try_recover      = 0x23u,
    TS_FUNC_mlx5_wqe_analyze          = 0x24u,
    TS_FUNC_mlx5_net_send_frags       = 0x25u,
    TS_FUNC_mlx5_net_send_frags_async = 0x26u,
    TS_FUNC_mlx5_net_send_lso_async   = 0x27u,
    TS_FUNC_mlx5_net_sq_reap_one      = 0x28u,
    TS_FUNC_mlx5_net_poll_recv        = 0x29u,
    /* nvmet.c (0x3X) */
    TS_FUNC_nvmet_admin_dispatch      = 0x30u,
    TS_FUNC_nvmet_io_dispatch_cmd     = 0x31u,
    TS_FUNC_nvmet_io_dispatch_h2c     = 0x32u,
    TS_FUNC_nvmet_io_job_step_impl    = 0x33u,
    TS_FUNC_nvmet_admin_job_step      = 0x34u,
    TS_FUNC_nvmet_io_rx_upcall        = 0x35u,
    /* nvmet_tcp.c (0x4X) */
    TS_FUNC_nvmet_tcp_recv_cmd        = 0x40u,
    TS_FUNC_nvmet_tcp_recv_cmd_body   = 0x41u,
    TS_FUNC_nvmet_tcp_send_c2h        = 0x42u,
    TS_FUNC_nvmet_tcp_send_c2h_async  = 0x43u,
    TS_FUNC_nvmet_tcp_send_icresp     = 0x44u,
    TS_FUNC_nvmet_tcp_send_r2t        = 0x45u,
    TS_FUNC_nvmet_tcp_send_resp       = 0x46u,
    /* mlx5_qp.c (0x5X) */
    TS_FUNC_mlx5_qp_post_send         = 0x50u,
    TS_FUNC_mlx5_qp_post_send_ud      = 0x51u,
    TS_FUNC_mlx5_qp_post_rdma_common  = 0x52u,
    TS_FUNC_mlx5_qp_post_recv         = 0x53u,
    TS_FUNC_mlx5_qp_post_recv_gsi     = 0x54u,
    TS_FUNC_mlx5_qp_poll_cqe          = 0x55u,
    TS_FUNC_mlx5_qp_poll_cqe_gsi      = 0x56u,
    /* eth.c (0x6X) */
    TS_FUNC_eth_dump_tx_ring_debug    = 0x60u,
    TS_FUNC_eth_tx_queue              = 0x61u,
    /* nvme_tcp.c (0x7X) */
    TS_FUNC_nvme_tcp_recv_poll        = 0x70u,
    /* nvmet_rdma.c (0x8X) */
    TS_FUNC_nvmet_rdma_job_step       = 0x80u,
};

void ts_log(uint32_t tag, uint32_t arg);

void ts_log_nvme_tcp_pdu(uint32_t tag, const volatile ts_nvme_pdu_t *info);

void ts_log_rdma(uint32_t tag, const volatile ts_rdma_t *info);

void ts_log_tcp_ack(uint32_t tag, uint8_t conn_slot, uint32_t seq,
                     uint32_t ack_seq, uint32_t window, uint16_t flags);

uint64_t ts_log_query_start_last_n(unsigned core, uint32_t count);

uint64_t ts_log_query_start_last_n_matching(unsigned core, uint32_t mask, uint32_t value, uint32_t count);

void ts_log_dump_core(unsigned core, uint64_t start, uint32_t count, uint32_t mask, uint32_t value);

#define TS_FREEZE_COUNT 2048u

void ts_log_freeze(void);

void ts_log_set_paused_core(unsigned core, int paused);

uint32_t ts_log_mode(void);
void  ts_log_mode_set(uint32_t mode);

#define TS_MODE_HOTPATH 0x4u
#define TS_HOT(tag, arg) do { if (ts_log_mode() & TS_MODE_HOTPATH) ts_log((tag), (arg)); } while (0)
#endif /* TIMESTAMP_H */
