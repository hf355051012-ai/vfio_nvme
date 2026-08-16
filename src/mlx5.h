#ifndef MLX5_H
#define MLX5_H

#include <stdint.h>

#define LOG_SET 0
#define LOG_GET 1
#define LOG_CLR 2
#define MLX5_MAX_FW_PAGES 8192u  // FWへMANAGE_PAGES(GIVE)で譲渡するスクラッチページ数の上限(32MB分)。実測のinit pages要求: ConnectX-4 Lx=2489、フルConnectX-4(MCX456A、100GbE)=4521。後者が4096を超えたため8192へ拡大(64MB/PFのDMA領域に収まる、下記_Static_assert検証)
#define MLX5_FW_PAGE_SIZE 4096u

#define MLX5_CMD_MBOX_ALIGN 1024u

#define MLX5_CMD_MBOX_CHAIN_BLOCKS 4u // 方向あたり最大 16+4*512=2064バイト

#define MLX5_EQ_BUF_SIZE    4096u

#define MLX5_CQ_BUF_SIZE    65536u
#define MLX5_CQ_DBR_SIZE    64u

#define MLX5_RQ_WQE_SIZE    4096u
#define MLX5_RQ_DBR_SIZE    64u
#define MLX5_RQ_NUM_WQES    256u
#define MLX5_JUMBO_MAX_LEN  10240u
#define MLX5_RQ_BUF_PER_WQE MLX5_JUMBO_MAX_LEN

#define MLX5_RX_HEADROOM    2u
#define MLX5_RQ_DATA_SIZE   ((uint64_t)MLX5_RQ_NUM_WQES * MLX5_RQ_BUF_PER_WQE) // 512KB

#define MLX5_SQ_CQ_BUF_SIZE 65536u
#define MLX5_SQ_CQ_DBR_SIZE 64u

#define MLX5_SQ_WQE_SIZE    4096u
#define MLX5_SQ_WQE_COUNT   8u
#define MLX5_SQ_DBR_SIZE    64u

#define MLX5_SQ_TX_FRAME_SIZE 64u

#define MLX5_NET_TX_STAGE_SIZE MLX5_JUMBO_MAX_LEN
#define MLX5_NET_TX_STAGE_TOTAL_SIZE ((uint64_t)MLX5_SQ_WQE_COUNT * MLX5_NET_TX_STAGE_SIZE)

#define MLX5_QP_WQE_BUF_SIZE 8192u
#define MLX5_QP_DBR_SIZE     64u   // 実際に使うのは8B(RCV counter 4B+

#define MLX5_GSI_WQE_BUF_SIZE 8192u
#define MLX5_GSI_DBR_SIZE     64u

uint64_t mlx5_dma_addr(const volatile void *cpu_ptr);

#define MLX5_OPCODE_SEND        0x0au
#define MLX5_OPCODE_NOP         0x00u
#define MLX5_OPCODE_LSO         0x0eu
#define MLX5_OPCODE_RDMA_WRITE      0x08u
#define MLX5_OPCODE_RDMA_WRITE_IMM  0x09u
#define MLX5_OPCODE_RDMA_READ       0x10u
#define MLX5_LSO_MAX_BYTES_CAP  65536u
#define MLX5_WQE_CTRL_CQ_UPDATE 0x08u
#define MLX5_SEND_WQE_BB        64u
#define MLX5_BF_OFFSET          0x800u

#define MLX5_NUM_RXQ 2u
typedef struct {
    uint32_t  cqn;         // このRQ専用のCQ
    uint32_t  rqn;
    uint32_t  tirn;
    uintptr_t cq_buf_cpu;  // 旧 dev->rq_cq_buf_cpu
    uintptr_t cq_dbr_cpu;  // 旧 dev->rq_cq_dbr_cpu
    uintptr_t data_cpu;    // 旧 dev->rq_data_cpu(受信データバッファ)
    uintptr_t wqe_cpu;     // 旧 dev->rq_wqe_cpu(WQEリング)
    uintptr_t dbr_cpu;     // 旧 dev->rq_dbr_cpu(RQドアベル)
} mlx5_rxq_t;

typedef struct {
    uint64_t bar0_base;     // このPFのBAR0 CPUアドレス
    uint8_t  pf_index;      // 0=PF0 / 1=PF1(旧 dma_base の PF 判別用途を置換)
    uint32_t fw_pages_used; // MANAGE_PAGES(GIVE)で既に譲渡したページ数(PFごとに独立)
    uint32_t uarn;
    uint32_t eqn;
    uint32_t pdn;
    uint32_t mkey;
    mlx5_rxq_t rxq[MLX5_NUM_RXQ];  // RX キュー配列(旧 cqn/rqn/tirn/rq_*_cpu を集約)
    uint32_t tdn;
    uint32_t tisn;
    uint32_t sq_cqn; // SQ用CQ(RQ用とは別)
    uint32_t sqn;
    uint32_t port_mtu;
    uint32_t clock_khz;
    uint32_t max_lso_bytes;
    uint8_t log_max_ra_req_qp; // 自分がinitiatorとして持てる同時RDMA_READ/ATOMIC数
    uint8_t log_max_ra_res_qp; // 自分がresponderとして受け付けられる同時RDMA_READ/ATOMIC数
    uint32_t bringup_generation;

    uintptr_t qp_cq_buf_cpu;
    uintptr_t qp_cq_dbr_cpu;
    uintptr_t qp2_cq_buf_cpu;
    uintptr_t qp2_cq_dbr_cpu;
    uintptr_t gsi_cq_buf_cpu;
    uintptr_t gsi_cq_dbr_cpu;

    uintptr_t sq_cq_buf_cpu;
    uintptr_t sq_cq_dbr_cpu;

    uintptr_t cmdq_cpu;
    uintptr_t out_mbox_cpu;   /* チェイン先頭。ブロック i = base + i*MLX5_CMD_MBOX_ALIGN */
    uintptr_t in_mbox_cpu;
    uintptr_t fw_pages_cpu;   /* 先頭。ページ idx = base + idx*MLX5_FW_PAGE_SIZE */
    uintptr_t eq_buf_cpu;
    uintptr_t sq_wqe_cpu;
    uintptr_t sq_dbr_cpu;
    uintptr_t sq_tx_frame_cpu;
    uintptr_t net_tx_stage_cpu; /* 先頭。スロット slot = base + slot*MLX5_NET_TX_STAGE_SIZE */
    uintptr_t qp_wqe_cpu;
    uintptr_t qp_dbr_cpu;
    uintptr_t gsi_wqe_cpu;
    uintptr_t gsi_dbr_cpu;
    uintptr_t qp2_wqe_cpu;
    uintptr_t qp2_dbr_cpu;
} __attribute__((aligned(16))) mlx5_dev_t;

uint32_t mlx5_qp_max_concurrent_rdma_read(mlx5_dev_t *dev);

extern int g_mlx5_skip_fte_experiment;

int mlx5_hca_bringup(mlx5_dev_t *dev, const char *label, int monitor_only);

int mlx5_recover_sq(mlx5_dev_t *dev);

void mlx5_monitor_dump_saved(void);

void mlx5_monitor_set_devs(const mlx5_dev_t *dev0, const mlx5_dev_t *dev1);

void mlx5_monitor_summary3(mlx5_dev_t *d0, mlx5_dev_t *d1,
                           uint32_t (*rd)(void *ctx, uint32_t off), void *cx0, void *cx1);

int mlx5_net_register_dual(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

// IPv4-mapped IPv6形式のRoCEv2 GID(::ffff:a.b.c.d)を構築する。
void mlx5_build_roce_gid_v4(uint32_t ipv4_host_order, uint8_t out_gid[16]);

int mlx5_set_roce_address(mlx5_dev_t *dev, uint32_t index, const uint8_t gid[16], const uint8_t mac[6]);

typedef struct {
    int      in_use;
    uint32_t qpn;
    uint32_t pdn;
    uint32_t uarn;
    uint32_t mkey;        // rw/rr有効なQP専用MKey(既存Ethernet用MKeyとは別)
    uint32_t cqn;         // 送受信共有CQ
    uint32_t sq_pc;       // 投稿した送信WQE数の累積(常に単純増加、mlx5_net_state_tと同じ規約)
    uint32_t rq_pc;       // 投稿したRECV WQE数の累積
    uint32_t cq_cc;       // 共有CQの消費カウンタ(送受信の完了が同じCQ
    uint32_t local_psn;   // 自分のnext_send_psn初期値(乱数)
    uint32_t remote_qpn;
    uint32_t remote_psn;  // 相手のnext_send_psn(手動設定またはCM経由で受け取る、フェーズb/e)
    uint8_t  remote_gid[16]; // IPv4-mapped IPv6 (RoCEv2)
    uint8_t  remote_mac[6];
    uint16_t remote_udp_sport;
    uint8_t  local_gid_index;
    uint32_t qkey;
    uint8_t  qp_index;
    uint8_t  path_mtu;
} mlx5_qp_t;

static inline uint64_t mlx5_qp_wqe_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_wqe_cpu : (uint64_t)dev->qp2_wqe_cpu;
}
static inline uint64_t mlx5_qp_dbr_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_dbr_cpu : (uint64_t)dev->qp2_dbr_cpu;
}
static inline uint64_t mlx5_qp_cq_buf_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_cq_buf_cpu : (uint64_t)dev->qp2_cq_buf_cpu;
}
static inline uint64_t mlx5_qp_cq_dbr_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_cq_dbr_cpu : (uint64_t)dev->qp2_cq_dbr_cpu;
}

int mlx5_qp_create_rc(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t qp_index);

int mlx5_qp_modify_rst2init(mlx5_dev_t *dev, mlx5_qp_t *qp);

int mlx5_qp_modify_init2rtr(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t remote_qpn,
                             const uint8_t remote_gid[16], const uint8_t remote_mac[6],
                             uint32_t remote_start_psn);

int mlx5_qp_modify_rtr2rts(mlx5_dev_t *dev, mlx5_qp_t *qp);

int mlx5_qp_query_counters(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t *out_hw_rq, uint32_t *out_sw_rq,
                            uint16_t *out_hw_sq, uint16_t *out_sw_sq);

// QP と、その QP のために確保した UAR/PD/MKey/CQ をまとめて解放する
// (DESTROY_QP -> DESTROY_MKEY -> DESTROY_CQ -> DEALLOC_PD -> DEALLOC_UAR)。
// 呼んだ後 qp のハンドルはゼロクリアされる(二重解放しても無害)。
int mlx5_qp_destroy(mlx5_dev_t *dev, mlx5_qp_t *qp);

int mlx5_qp_create_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp);

int mlx5_qp_modify_rst2init_ud(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t qkey);

int mlx5_qp_modify_init2rtr_ud(mlx5_dev_t *dev, mlx5_qp_t *qp);

int mlx5_qp_modify_rtr2rts_ud(mlx5_dev_t *dev, mlx5_qp_t *qp);

uint16_t mlx5_calc_udp_sport(uint32_t lqpn, uint32_t rqpn);

#define MLX5_GRH_BYTES 40u

void mlx5_net_dump_sq_debug(int pf_index);

#endif /* MLX5_H */
