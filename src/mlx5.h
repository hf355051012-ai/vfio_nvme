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

/* RC QP の WQE バッファ。**RQ 領域(256 x 16B = 4096)の直後が SQ 領域**という
 * 固定レイアウトで、SQ は log_sq_size=9 = 512 WQEBB x 64B = 32768 バイト使う。
 * qd=128 まで積めるようにするため 8192 から広げた(1 コマンドが SEND 2 WQEBB、
 * ターゲット側は RDMA_READ/WRITE + SEND で最大 3 WQEBB 使う)。
 * **GSI は別バッファ(MLX5_GSI_WQE_BUF_SIZE)なので影響しない。** */
#define MLX5_QP_WQE_BUF_SIZE 65536u

/* RC QP の WQ レイアウトと、CREATE_QP へ渡す PAS の枚数。
 * **SQ を広げたら PAS の枚数も一緒に増やすこと。** 2 枚(RQ 1 + SQ 1)固定の
 * まま SQ だけ 32KB にすると、FW が CREATE_QP を syndrome=0x002f50ca で
 * 拒否する(実機で踏んだ)。log_page_size=0 なので 1 枚 = 4KB。 */
#define MLX5_QP_RQ_BYTES  4096u                      /* log_rq_size=8 x 16B */
#define MLX5_QP_SQ_BYTES  (512u * MLX5_SEND_WQE_BB)  /* log_sq_size=9 x 64B */
#define MLX5_QP_WQ_PAGES  ((MLX5_QP_RQ_BYTES + MLX5_QP_SQ_BYTES + 4095u) / 4096u)
#define MLX5_QP_DBR_SIZE     64u   // 実際に使うのは8B(RCV counter 4B+

#define MLX5_GSI_WQE_BUF_SIZE 8192u
#define MLX5_GSI_DBR_SIZE     64u

uint64_t mlx5_dma_addr(const volatile void *cpu_ptr);

#define MLX5_OPCODE_SEND        0x0au
/* この長さ以下の SEND は WQE へ埋め込む(1 WQEBB=64B に収める)。
 * ctrl(16)+inline ヘッダ(4)= 20 バイト使うので 44 まで入るが、
 * 応答 capsule の 16 バイトが収まればよいので余裕を持たせる。 */
#define MLX5_SEND_INLINE_MAX   40u
#define MLX5_OPCODE_SEND_INVAL 0x01u  /* SEND_WITH_INVALIDATE(include/linux/mlx5/device.h)*/
#define MLX5_OPCODE_NOP         0x00u
#define MLX5_OPCODE_LSO         0x0eu
#define MLX5_OPCODE_RDMA_WRITE      0x08u
#define MLX5_OPCODE_RDMA_WRITE_IMM  0x09u
#define MLX5_OPCODE_RDMA_READ       0x10u
#define MLX5_OPCODE_ATOMIC_CS       0x11u
#define MLX5_OPCODE_ATOMIC_FA       0x12u
#define MLX5_OPCODE_ATOMIC_MASKED_CS 0x14u
#define MLX5_OPCODE_ATOMIC_MASKED_FA 0x15u
#define MLX5_LSO_MAX_BYTES_CAP  65536u
#define MLX5_WQE_CTRL_CQ_UPDATE 0x08u
#define MLX5_SEND_WQE_BB        64u
#define MLX5_BF_OFFSET          0x800u

/* **受信キューの本数 = 分散できるコア数。** RSS(CREATE_RQT + Toeplitz の
 * TIR)で 4-tuple ハッシュにより振り分ける。**既定では catch-all の FTE が
 * rxq[0] の直接 TIR を指したまま**で、`netmt N` で RSS TIR へ張り替える。 */
#define MLX5_NUM_RXQ 4u
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

/* **送信キューの本数 = コアの本数。** 添字は `smp_core_index()` そのもので、
 * **core0(シェル)も自分の SQ を持つ**。こうすると SQ のリング状態
 * (sq_pc / WQE 領域 / ドアベルレコード)がコア間で共有されないので、
 * **送信の排他が一切要らなくなる**(以前は PF ごとの spinlock で直列化して
 * いたが、`tx_wait_free_slot()` がロックの外で SQ の CQE を刈っていたため、
 * 完了を二重計上して SQ を過剰投稿する競合が残っていた)。
 * **SMP_MAX_CORES と一致させること**(mlx5_net.c に _Static_assert がある)。
 * TIS は全 SQ で共有する(Linux の mlx5e も TC ごとに 1 つを共有する)。 */
#define MLX5_NUM_TXQ 4u
typedef struct {
    uint32_t  cqn;          // このSQ専用のCQ(旧 dev->sq_cqn)
    uint32_t  sqn;          // 旧 dev->sqn
    uintptr_t cq_buf_cpu;   // 旧 dev->sq_cq_buf_cpu
    uintptr_t cq_dbr_cpu;   // 旧 dev->sq_cq_dbr_cpu
    uintptr_t wqe_cpu;      // 旧 dev->sq_wqe_cpu(WQEリング)
    uintptr_t dbr_cpu;      // 旧 dev->sq_dbr_cpu(SQドアベルレコード)
    uintptr_t stage_cpu;    // 旧 dev->net_tx_stage_cpu(断片連結用ステージ)
} mlx5_txq_t;

/* **RC QP を何本まで持てるか。** 0 番は admin(またはイニシエータの admin)、
 * 1 番以降が IO キュー。**ここが RDMA の IO キュー本数の上限**になる。
 * 1 本あたり WQE 64KB + CQ 64KB なので、8 本 x 2 PF で約 2MB。 */
#define MLX5_NUM_RCQP 8u
typedef struct {
    uintptr_t wqe_cpu;     // 旧 dev->qp_wqe_cpu / qp2_wqe_cpu
    uintptr_t dbr_cpu;     // 旧 dev->qp_dbr_cpu / qp2_dbr_cpu
    uintptr_t cq_buf_cpu;  // 旧 dev->qp_cq_buf_cpu / qp2_cq_buf_cpu
    uintptr_t cq_dbr_cpu;  // 旧 dev->qp_cq_dbr_cpu / qp2_cq_dbr_cpu
} mlx5_rcqp_res_t;

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
    /* RSS。**使うコア数ごとに RQT と TIR を作り置きしておく**(添字 = コア数、
     * 2..MLX5_NUM_RXQ が有効)。実行時に作り直さないので、切り替えは
     * FTE の転送先を差し替えるだけで済む(オブジェクトを leak しない)。
     * **添字 n の RQT は rxq[0..n-1] を繰り返して埋めてある**ので、
     * ハッシュは n 本の RQ にだけ散る。 */
    uint32_t rqtn[MLX5_NUM_RXQ + 1];
    uint32_t rss_tirn[MLX5_NUM_RXQ + 1];
    /* **番号 0 は有効な TIR/RQT 番号**(実機で rqtn=0 / tirn=0 が返る)。
     * 0 を「未作成」の印に使うと切り替えが必ず失敗する。 */
    uint8_t  rss_ready[MLX5_NUM_RXQ + 1];
    uint32_t rx_ft_table_id;
    uint32_t rx_ft_group_id;
    /* **この装置は table_id / group_id / tirn / rqtn がすべて 0 から始まる。**
     * 番号 0 を「未作成」の印に使うと必ず誤判定するので、旗を別に持つ。 */
    uint8_t  rx_ft_valid;
    uint32_t tisn;                  // TISは全SQで共有する
    mlx5_txq_t txq[MLX5_NUM_TXQ];   // 送信キュー配列(旧 sqn/sq_cqn/sq_*_cpu を集約)
    uint32_t port_mtu;
    uint8_t  num_vhca_ports;  /* HCA cap bit 0x610。非0なら ROCE_ADDRESS に vhca_port_num が要る */
    uint8_t  can_disable_lb_uc; /* HCA cap bit 0x3e1。vport のユニキャストloopbackを切れるか */
    uint16_t roce_gid_vlan;    /* [調査用] 非0なら SET_ROCE_ADDRESS に vlan_valid/vlan_id を入れる */
    uint32_t clock_khz;
    uint32_t max_lso_bytes;
    uint8_t log_max_ra_req_qp; // 自分がinitiatorとして持てる同時RDMA_READ/ATOMIC数
    uint8_t log_max_ra_res_qp; // 自分がresponderとして受け付けられる同時RDMA_READ/ATOMIC数
    uint32_t bringup_generation;

    uintptr_t gsi_cq_buf_cpu;
    uintptr_t gsi_cq_dbr_cpu;

    uintptr_t cmdq_cpu;
    uintptr_t out_mbox_cpu;   /* チェイン先頭。ブロック i = base + i*MLX5_CMD_MBOX_ALIGN */
    uintptr_t in_mbox_cpu;
    uintptr_t fw_pages_cpu;   /* 先頭。ページ idx = base + idx*MLX5_FW_PAGE_SIZE */
    uintptr_t eq_buf_cpu;
    uintptr_t sq_tx_frame_cpu;
    mlx5_rcqp_res_t rcqp[MLX5_NUM_RCQP]; // RC QP ごとの WQE/DBR/CQ(旧 qp_*_cpu / qp2_*_cpu)
    uintptr_t gsi_wqe_cpu;
    uintptr_t gsi_dbr_cpu;
} __attribute__((aligned(16))) mlx5_dev_t;

uint32_t mlx5_qp_max_concurrent_rdma_read(mlx5_dev_t *dev);

/* QUERY_HCA_CAP(ATOMIC)の要点(struct mlx5_ifc_atomic_caps_bits)。 */
typedef struct {
    uint8_t  req_endianness_mode;          /* 0=BE / 1=ホスト順(responder としての解釈)*/
    uint8_t  supported_endianness_mode_1;
    uint16_t operations;                   /* bit0 CS / bit1 FA / bit2 拡張CS / bit3 拡張FA */
    uint16_t size_qp;                      /* bit n = 2^n バイト */
} mlx5_atomic_caps_t;
int mlx5_query_atomic_caps(mlx5_dev_t *dev, mlx5_atomic_caps_t *out);

extern int g_mlx5_skip_fte_experiment;

int mlx5_hca_bringup(mlx5_dev_t *dev, const char *label, int monitor_only);

int mlx5_recover_sq(mlx5_dev_t *dev, unsigned q);

void mlx5_monitor_dump_saved(void);

void mlx5_monitor_set_devs(const mlx5_dev_t *dev0, const mlx5_dev_t *dev1);

void mlx5_monitor_summary3(mlx5_dev_t *d0, mlx5_dev_t *d1,
                           uint32_t (*rd)(void *ctx, uint32_t off), void *cx0, void *cx1);

int mlx5_net_register_dual(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

/* catch-all の FTE の転送先を直接 TIR / RSS TIR で張り替える(受信の分散)。 */
int mlx5_set_rss_enable(mlx5_dev_t *dev, unsigned ncores);
int mlx5_net_set_rss(unsigned ncores);

// IPv4-mapped IPv6形式のRoCEv2 GID(::ffff:a.b.c.d)を構築する。
void mlx5_build_roce_gid_v4(uint32_t ipv4_host_order, uint8_t out_gid[16]);

int mlx5_set_roce_address(mlx5_dev_t *dev, uint32_t index, const uint8_t gid[16], const uint8_t mac[6]);
int mlx5_dump_nic_vport_context(mlx5_dev_t *dev, const char *tag);
void mlx5_probe_flow_table_types(mlx5_dev_t *dev, const char *label);
int mlx5_force_tx_to_uplink(mlx5_dev_t *dev, const char *label,
                            uint8_t table_type, int set_root);
int mlx5_query_roce_address(mlx5_dev_t *dev, uint32_t index, uint8_t port_num,
                            uint8_t out_gid[16], uint8_t out_mac[6],
                            uint8_t *out_l3, uint8_t *out_ver);

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

/* **添字が範囲外なら 0 番へ倒す。** 昔は `qp_index == 0 ? A : B` の三項
 * 演算子だったので **RC QP は 2 本が上限**で、RDMA ターゲットは IO キューを
 * 1 本しか持てなかった(admin が 0、IO が 1 で使い切る)。 */
static inline unsigned mlx5_rcqp_slot(const mlx5_qp_t *qp) {
    return (qp->qp_index < MLX5_NUM_RCQP) ? (unsigned)qp->qp_index : 0u;
}
static inline uint64_t mlx5_qp_wqe_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (uint64_t)dev->rcqp[mlx5_rcqp_slot(qp)].wqe_cpu;
}
static inline uint64_t mlx5_qp_dbr_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (uint64_t)dev->rcqp[mlx5_rcqp_slot(qp)].dbr_cpu;
}
static inline uint64_t mlx5_qp_cq_buf_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (uint64_t)dev->rcqp[mlx5_rcqp_slot(qp)].cq_buf_cpu;
}
static inline uint64_t mlx5_qp_cq_dbr_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (uint64_t)dev->rcqp[mlx5_rcqp_slot(qp)].cq_dbr_cpu;
}

int mlx5_qp_create_rc(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t qp_index);
/* cs_req=0x11 で read / atomic の応答 32B までを CQE へ書かせる(mlx5.c 参照)。 */
int mlx5_qp_create_rc_ex(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t qp_index, uint8_t cs_req);

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
