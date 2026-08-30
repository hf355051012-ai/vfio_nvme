#include "mlx5_qp.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"
#include "cache.h"
#include "netif.h"
#include "net.h"
#include "ib_mad.h"
#include "timestamp.h"

#define MLX5_QP_CQE_SIZE        64u
#define MLX5_QP_CQ_NUM_ENTRIES  (MLX5_CQ_BUF_SIZE / MLX5_QP_CQE_SIZE) // 1024
#define MLX5_QP_CQ_LOG_SIZE     10u
#define MLX5_CQE_OFF_BYTE_CNT   44u
#define MLX5_CQE_OFF_SYNDROME   55u
#define MLX5_CQE_OFF_OP_OWN     63u
#define MLX5_CQE_OPCODE_REQ         0x0u // 送信完了(SQ側)
#define MLX5_CQE_OPCODE_RESP_SEND   0x2u // SEND受信完了(RQ側)
#define MLX5_CQE_OPCODE_SIG_ERR     0xCu
#define MLX5_CQE_OPCODE_REQ_ERR     0xDu
#define MLX5_CQE_OPCODE_RESP_ERR    0xEu
#define MLX5_CQE_OPCODE_INVALID     0xFu

_Static_assert(MLX5_QP_CQ_NUM_ENTRIES == 1024u, "MLX5_CQ_BUF_SIZE/MLX5_QP_CQE_SIZE assumption changed");

/*=================================================================
 * RC QP の SQ へ SEND WQE を 1 個投稿し、BlueFlame ドアベルを鳴らす。
 * 送信完了は待たない(mlx5_qp_poll_cqe() で確認する)。
 *
 * 引数:
 *   dev  - この QP を持つ HCA
 *   qp   - 送信元 RC QP
 *   data - 送信するペイロード
 *   len  - そのバイト数
 * 戻り値:
 *   0=投稿成功、-1=引数不正/SQ 空き待ちタイムアウト
 * コール元:
 *   rdma_cm_job_step(), nvmet_rdma_job_step(), nvmetr_pl_send_response(),
 *   nvme_rdma_connect_job_step(), nvmer_post_send()
 * ===============================================================*/
int mlx5_qp_post_send(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len) {
    return mlx5_qp_post_send_ex(dev, qp, data, len, 0, 0, 0);
}

int mlx5_qp_post_send2(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data0, uint32_t len0,
                       const void *data1, uint32_t len1) {
    return mlx5_qp_post_send_ex(dev, qp, data0, len0, data1, len1, 0);
}

/*=================================================================
 * SEND を 2 つのバッファから 1 つのメッセージとして送る。data1 が NULL
 * なら 1 バッファの通常の SEND。**NVMe-oF の in-capsule write** が
 * 「64 バイトのコマンド + データ」を 1 メッセージで送るために要る
 * (Linux の nvme_rdma_map_sg_inline() も sge[0]/sge[1] の 2 本)。
 * data_seg が 1 本増えても ds_cnt は 3、WQE は 48 バイトなので
 * 1 WQEBB(64 バイト)に収まる。
 *
 * 引数:
 *   dev / qp    - 対象デバイスと QP
 *   data0 / len0 - 1 本目(コマンド capsule)
 *   data1 / len1 - 2 本目(データ。NULL なら付けない)
 * 戻り値:
 *   0=成功
 * コール元:
 *   mlx5_qp_post_send(), nvme_rdma.c の in-capsule write
 * ===============================================================*/
int mlx5_qp_post_send_ex(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data0, uint32_t len0,
                         const void *data1, uint32_t len1, uint32_t inval_rkey) {
    const void *data = data0;
    uint32_t len = len0;
    uint32_t pc = qp->sq_pc;
    uint32_t idx = pc & 511u; // log_sq_size=9 -- 512 WQEBB
    volatile uint8_t *sq_base =
        (volatile uint8_t *)(uintptr_t)(mlx5_qp_wqe_addr(dev, qp) + 4096u); // SQ regionはRQ regionの直後
    volatile uint8_t *wqe = sq_base + (uint64_t)idx * MLX5_SEND_WQE_BB;
    for (unsigned i = 0; i < MLX5_SEND_WQE_BB; i++) {
        wqe[i] = 0;
    }

    /* **小さい送信は WQE へ埋め込む(inline data segment)。** ポインタで渡すと
     * NIC が WQE とペイロードで PCIe の DMA 読みを 2 回する。埋め込めば WQE の
     * 取得 1 回で済む。NVMe-oF の応答 capsule は 16 バイトなので必ず収まる。 */
    const int use_inl = (data1 == 0 && len0 <= MLX5_SEND_INLINE_MAX);
    /* inline: ctrl(1) + ceil((4+len)/16)。通常: ctrl(1)+data_seg(1..2) */
    const uint32_t ds_cnt = use_inl ? (1u + ((4u + len0 + 15u) / 16u))
                                    : ((data1 != 0) ? 3u : 2u);
    /* inval_rkey が非 0 なら SEND_WITH_INVALIDATE。相手の HCA にその rkey を
     * 無効化させる。**これを返さないと、ホストは 1 コマンドごとに自分で
     * LOCAL_INV を投げる**(Linux の nvme-rdma は register_always=Y が既定で、
     * コマンドごとに MR を登録して SGL の型に invalidate(0x4f)を立ててくる)。
     * 実測で 4096B read qd=128 が 663 -> 825 MiB/s。 */
    uint32_t op = (inval_rkey != 0u) ? MLX5_OPCODE_SEND_INVAL : MLX5_OPCODE_SEND;
    uint32_t opmod_idx_opcode = ((pc & 0xFFFFu) << 8) | op;
    wqe[0] = (uint8_t)(opmod_idx_opcode >> 24);
    wqe[1] = (uint8_t)(opmod_idx_opcode >> 16);
    wqe[2] = (uint8_t)(opmod_idx_opcode >> 8);
    wqe[3] = (uint8_t)opmod_idx_opcode;

    uint32_t qpn_ds = (qp->qpn << 8) | ds_cnt;
    wqe[4] = (uint8_t)(qpn_ds >> 24);
    wqe[5] = (uint8_t)(qpn_ds >> 16);
    wqe[6] = (uint8_t)(qpn_ds >> 8);
    wqe[7] = (uint8_t)qpn_ds;

    wqe[11] = (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE; // fm_ce_se -- 常にCQE要求(診断用途、常にsignaled)
    if (inval_rkey != 0u) { // ctrl_seg の imm(byte12-15)へ無効化する rkey(BE)
        wqe[12] = (uint8_t)(inval_rkey >> 24);
        wqe[13] = (uint8_t)(inval_rkey >> 16);
        wqe[14] = (uint8_t)(inval_rkey >> 8);
        wqe[15] = (uint8_t)inval_rkey;
    }

    if (use_inl) { // inline_seg(wqe[16..19]=byte_count|MLX5_INLINE_SEG、以降にデータ)
        uint32_t bc = 0x80000000u | len0;   // bit31 = inline
        wqe[16] = (uint8_t)(bc >> 24);
        wqe[17] = (uint8_t)(bc >> 16);
        wqe[18] = (uint8_t)(bc >> 8);
        wqe[19] = (uint8_t)bc;
        const uint8_t *src = (const uint8_t *)data0;
        for (uint32_t i = 0; i < len0; i++) wqe[20 + i] = src[i];
        goto ring_db;
    }
    // data_seg(wqe[16..31]): byte_count(4B BE)+lkey(4B BE)+addr(8B BE)。
    uint32_t byte_count = len;
    wqe[16] = (uint8_t)(byte_count >> 24);
    wqe[17] = (uint8_t)(byte_count >> 16);
    wqe[18] = (uint8_t)(byte_count >> 8);
    wqe[19] = (uint8_t)byte_count;
    wqe[20] = (uint8_t)(qp->mkey >> 24);
    wqe[21] = (uint8_t)(qp->mkey >> 16);
    wqe[22] = (uint8_t)(qp->mkey >> 8);
    wqe[23] = (uint8_t)qp->mkey;
    uint64_t data_pa = mlx5_dma_addr(data);
    for (unsigned b = 0; b < 8; b++) {
        wqe[24 + b] = (uint8_t)(data_pa >> (56 - 8 * b));
    }

    if (data1 != 0) { // 2本目のdata_seg(wqe[32..47])
        wqe[32] = (uint8_t)(len1 >> 24);
        wqe[33] = (uint8_t)(len1 >> 16);
        wqe[34] = (uint8_t)(len1 >> 8);
        wqe[35] = (uint8_t)len1;
        wqe[36] = (uint8_t)(qp->mkey >> 24);
        wqe[37] = (uint8_t)(qp->mkey >> 16);
        wqe[38] = (uint8_t)(qp->mkey >> 8);
        wqe[39] = (uint8_t)qp->mkey;
        uint64_t d1_pa = mlx5_dma_addr(data1);
        for (unsigned b = 0; b < 8; b++) {
            wqe[40 + b] = (uint8_t)(d1_pa >> (56 - 8 * b));
        }
    }

ring_db:;
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)mlx5_qp_dbr_addr(dev, qp);
    uint32_t new_pc = pc + 1u;
    dbr[4] = (uint8_t)(new_pc >> 24);
    dbr[5] = (uint8_t)(new_pc >> 16);
    dbr[6] = (uint8_t)(new_pc >> 8);
    dbr[7] = (uint8_t)new_pc;

    dma_wmb();

    uint32_t raw0 = (uint32_t)wqe[0] | ((uint32_t)wqe[1] << 8) |
                    ((uint32_t)wqe[2] << 16) | ((uint32_t)wqe[3] << 24);
    uint32_t raw1 = (uint32_t)wqe[4] | ((uint32_t)wqe[5] << 8) |
                    ((uint32_t)wqe[6] << 16) | ((uint32_t)wqe[7] << 24);
    uint64_t uar_addr = dev->bar0_base + (uint64_t)qp->uarn * 4096u;
    /* BlueFlame の 8 バイトは 1 命令でアトミックに書く。32bit x 2 に分けると
     * PCIe 上で分割されうる(Linux の mlx5_write64() が「32bit システムでは
     * ロックが必要」と注記しているのと同じ理由)。同時 RDMA_READ を 1 本から
     * 16 本へ緩めてドアベル発行頻度が上がった途端、LOCAL_QP_OP_ERR
     * (syndrome=0x02)として実機で顕在化した。 */
    uint64_t raw64 = (uint64_t)raw0 | ((uint64_t)raw1 << 32);
    mmio_write64(uar_addr + MLX5_BF_OFFSET, raw64);

    qp->sq_pc = new_pc;

    volatile ts_rdma_t ts_info = {0};
    ts_info.rdma_op = TS_RDMA_OP_SQ_SEND;
    ts_info.wqe_cqe_opcode = (uint8_t)op;
    ts_info.ds_cnt = (uint8_t)ds_cnt;
    ts_info.qpn = qp->qpn;
    ts_info.counter = new_pc;
    ts_info.len = len + len1;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_post_send, 0), &ts_info);

    return 0;
}

/*=================================================================
 * UD/GSI QP の SQ へ SEND WQE を 1 個投稿する。ctrl_seg + datagram_seg
 * (struct mlx5_av 相当、宛先 GID/MAC/QPN/UDP sport)+ data_seg の構成。
 * GSI 宛の送信では remote_qpn に常に 1(既知の GSI QPN)を渡すこと。
 *
 * 引数:
 *   dev / qp     - 送信元 HCA と UD/GSI QP
 *   data / len   - 送信ペイロード
 *   remote_qpn   - 宛先 QPN(GSI なら 1 固定)
 *   remote_gid   - 宛先 GID(16 バイト)
 *   remote_mac   - 宛先 MAC(6 バイト)
 * 戻り値:
 *   0=投稿成功、-1=失敗
 * コール元:
 *   rdma_cm_job_step(), nvmetr_check_gsi_disconnect()
 * ===============================================================*/
int mlx5_qp_post_send_ud(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len,
                          uint32_t remote_qpn, uint32_t remote_qkey,
                          const uint8_t remote_gid[16], const uint8_t remote_mac[6]) {
    uint32_t pc = qp->sq_pc;
    uint32_t idx0 = pc & 63u; // log_sq_size=6 -- 64 WQEBB
    uint32_t idx1 = (idx0 + 1u) & 63u;
    volatile uint8_t *sq_base =
        (volatile uint8_t *)(uintptr_t)((uint64_t)dev->gsi_wqe_cpu + 4096u); // SQ regionはRQ regionの直後
    volatile uint8_t *wqe0 = sq_base + (uint64_t)idx0 * MLX5_SEND_WQE_BB;
    volatile uint8_t *wqe1 = sq_base + (uint64_t)idx1 * MLX5_SEND_WQE_BB;
    for (unsigned i = 0; i < MLX5_SEND_WQE_BB; i++) {
        wqe0[i] = 0;
        wqe1[i] = 0;
    }

    const uint32_t ds_cnt = 5u; // ctrl_seg(1)+datagram_seg(3)+data_seg(1)
    uint32_t opmod_idx_opcode = ((pc & 0xFFFFu) << 8) | MLX5_OPCODE_SEND;
    wqe0[0] = (uint8_t)(opmod_idx_opcode >> 24);
    wqe0[1] = (uint8_t)(opmod_idx_opcode >> 16);
    wqe0[2] = (uint8_t)(opmod_idx_opcode >> 8);
    wqe0[3] = (uint8_t)opmod_idx_opcode;

    uint32_t qpn_ds = (qp->qpn << 8) | ds_cnt;
    wqe0[4] = (uint8_t)(qpn_ds >> 24);
    wqe0[5] = (uint8_t)(qpn_ds >> 16);
    wqe0[6] = (uint8_t)(qpn_ds >> 8);
    wqe0[7] = (uint8_t)qpn_ds;

    wqe0[11] = (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE; // fm_ce_se -- 常にsignaled

    // datagram_seg / struct mlx5_av(wqe0[16..63]、48バイト)。
    wqe0[16] = (uint8_t)(remote_qkey >> 24);
    wqe0[17] = (uint8_t)(remote_qkey >> 16);
    wqe0[18] = (uint8_t)(remote_qkey >> 8);
    wqe0[19] = (uint8_t)remote_qkey; // key.qkey
    wqe0[24] = (uint8_t)((remote_qpn >> 24) | 0x80u); // bit31=MLX5_EXTENDED_UD_AV
    wqe0[25] = (uint8_t)(remote_qpn >> 16);
    wqe0[26] = (uint8_t)(remote_qpn >> 8);
    wqe0[27] = (uint8_t)remote_qpn; // dqp_dct(下位24bit=宛先QPN)
    uint16_t udp_sport = mlx5_calc_udp_sport(qp->qpn, remote_qpn);
    wqe0[30] = (uint8_t)(udp_sport >> 8);
    wqe0[31] = (uint8_t)udp_sport;
    // wqe0[32..35] reserved0 = 0
    for (unsigned i = 0; i < 6; i++) {
        wqe0[36 + i] = remote_mac[i];
    }
    // wqe0[42] tclass = 0
    wqe0[43] = 64; // hop_limit
    uint32_t grh_gid_fl = (1u << 30) | ((uint32_t)qp->local_gid_index << 20); // GRH bit|sgid_index、flow_label=0
    wqe0[44] = (uint8_t)(grh_gid_fl >> 24);
    wqe0[45] = (uint8_t)(grh_gid_fl >> 16);
    wqe0[46] = (uint8_t)(grh_gid_fl >> 8);
    wqe0[47] = (uint8_t)grh_gid_fl;
    for (unsigned i = 0; i < 16; i++) {
        wqe0[48 + i] = remote_gid[i];
    }

    // data_seg(wqe1[0..15]、ローカルの送信データバッファ)。
    uint32_t byte_count = len;
    wqe1[0] = (uint8_t)(byte_count >> 24);
    wqe1[1] = (uint8_t)(byte_count >> 16);
    wqe1[2] = (uint8_t)(byte_count >> 8);
    wqe1[3] = (uint8_t)byte_count;
    wqe1[4] = (uint8_t)(qp->mkey >> 24);
    wqe1[5] = (uint8_t)(qp->mkey >> 16);
    wqe1[6] = (uint8_t)(qp->mkey >> 8);
    wqe1[7] = (uint8_t)qp->mkey;
    uint64_t data_pa = mlx5_dma_addr(data);
    for (unsigned b = 0; b < 8; b++) {
        wqe1[8 + b] = (uint8_t)(data_pa >> (56 - 8 * b));
    }

    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->gsi_dbr_cpu;
    uint32_t new_pc = pc + 2u; // このWQEはWQEBB 2個分を消費した
    dbr[4] = (uint8_t)(new_pc >> 24);
    dbr[5] = (uint8_t)(new_pc >> 16);
    dbr[6] = (uint8_t)(new_pc >> 8);
    dbr[7] = (uint8_t)new_pc;

    dma_wmb();

    uint32_t raw0 = (uint32_t)wqe0[0] | ((uint32_t)wqe0[1] << 8) |
                    ((uint32_t)wqe0[2] << 16) | ((uint32_t)wqe0[3] << 24);
    uint32_t raw1 = (uint32_t)wqe0[4] | ((uint32_t)wqe0[5] << 8) |
                    ((uint32_t)wqe0[6] << 16) | ((uint32_t)wqe0[7] << 24);
    uint64_t uar_addr = dev->bar0_base + (uint64_t)qp->uarn * 4096u;
    /* BlueFlame の 8 バイトは 1 命令でアトミックに書く。32bit x 2 に分けると
     * PCIe 上で分割されうる(Linux の mlx5_write64() が「32bit システムでは
     * ロックが必要」と注記しているのと同じ理由)。同時 RDMA_READ を 1 本から
     * 16 本へ緩めてドアベル発行頻度が上がった途端、LOCAL_QP_OP_ERR
     * (syndrome=0x02)として実機で顕在化した。 */
    uint64_t raw64 = (uint64_t)raw0 | ((uint64_t)raw1 << 32);
    mmio_write64(uar_addr + MLX5_BF_OFFSET, raw64);

    qp->sq_pc = new_pc;

    volatile ts_rdma_t ts_info = {0};
    ts_info.rdma_op = TS_RDMA_OP_SQ_SEND;
    ts_info.wqe_cqe_opcode = (uint8_t)MLX5_OPCODE_SEND;
    ts_info.ds_cnt = (uint8_t)ds_cnt;
    ts_info.qpn = qp->qpn;
    ts_info.counter = new_pc;
    ts_info.len = len;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_post_send_ud, 0), &ts_info);

    return 0;
}

/*=================================================================
 * RDMA_WRITE / RDMA_READ 共通の WQE 組み立て。ctrl_seg + raddr_seg
 * (リモートアドレス + rkey)+ data_seg(ローカルバッファ)の ds_cnt=3。
 *
 * 引数:
 *   dev / qp     - 送信元 HCA と RC QP
 *   opcode       - MLX5_OPCODE_RDMA_WRITE か MLX5_OPCODE_RDMA_READ
 *   local / len  - ローカル側バッファとバイト数
 *   remote_addr  - 相手側の仮想アドレス
 *   remote_key   - 相手側 rkey
 * 戻り値:
 *   0=投稿成功、-1=失敗
 * コール元:
 *   mlx5_qp_post_rdma_write(), mlx5_qp_post_rdma_read()
 * ===============================================================*/
static int mlx5_qp_post_rdma_common(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t opcode,
                                     void *local_data, uint32_t len,
                                     uint64_t remote_addr, uint32_t remote_rkey) {
    uint32_t pc = qp->sq_pc;
    uint32_t idx = pc & 511u; // log_sq_size=9 -- 512 WQEBB
    volatile uint8_t *sq_base =
        (volatile uint8_t *)(uintptr_t)(mlx5_qp_wqe_addr(dev, qp) + 4096u);
    volatile uint8_t *wqe = sq_base + (uint64_t)idx * MLX5_SEND_WQE_BB;
    for (unsigned i = 0; i < MLX5_SEND_WQE_BB; i++) {
        wqe[i] = 0;
    }

    const uint32_t ds_cnt = 3u; // ctrl_seg(1)+raddr_seg(1)+data_seg(1)
    uint32_t opmod_idx_opcode = ((pc & 0xFFFFu) << 8) | opcode;
    wqe[0] = (uint8_t)(opmod_idx_opcode >> 24);
    wqe[1] = (uint8_t)(opmod_idx_opcode >> 16);
    wqe[2] = (uint8_t)(opmod_idx_opcode >> 8);
    wqe[3] = (uint8_t)opmod_idx_opcode;

    uint32_t qpn_ds = (qp->qpn << 8) | ds_cnt;
    wqe[4] = (uint8_t)(qpn_ds >> 24);
    wqe[5] = (uint8_t)(qpn_ds >> 16);
    wqe[6] = (uint8_t)(qpn_ds >> 8);
    wqe[7] = (uint8_t)qpn_ds;

    wqe[11] = (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE; // fm_ce_se -- 常にsignaled

    // raddr_seg(wqe[16..31]): raddr(8B BE)+rkey(4B BE)+reserved(4B)。
    for (unsigned b = 0; b < 8; b++) {
        wqe[16 + b] = (uint8_t)(remote_addr >> (56 - 8 * b));
    }
    wqe[24] = (uint8_t)(remote_rkey >> 24);
    wqe[25] = (uint8_t)(remote_rkey >> 16);
    wqe[26] = (uint8_t)(remote_rkey >> 8);
    wqe[27] = (uint8_t)remote_rkey;

    uint32_t byte_count = len;
    wqe[32] = (uint8_t)(byte_count >> 24);
    wqe[33] = (uint8_t)(byte_count >> 16);
    wqe[34] = (uint8_t)(byte_count >> 8);
    wqe[35] = (uint8_t)byte_count;
    wqe[36] = (uint8_t)(qp->mkey >> 24);
    wqe[37] = (uint8_t)(qp->mkey >> 16);
    wqe[38] = (uint8_t)(qp->mkey >> 8);
    wqe[39] = (uint8_t)qp->mkey;
    uint64_t data_pa = mlx5_dma_addr(local_data);
    for (unsigned b = 0; b < 8; b++) {
        wqe[40 + b] = (uint8_t)(data_pa >> (56 - 8 * b));
    }

    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)mlx5_qp_dbr_addr(dev, qp);
    uint32_t new_pc = pc + 1u;
    dbr[4] = (uint8_t)(new_pc >> 24);
    dbr[5] = (uint8_t)(new_pc >> 16);
    dbr[6] = (uint8_t)(new_pc >> 8);
    dbr[7] = (uint8_t)new_pc;

    dma_wmb();

    uint32_t raw0 = (uint32_t)wqe[0] | ((uint32_t)wqe[1] << 8) |
                    ((uint32_t)wqe[2] << 16) | ((uint32_t)wqe[3] << 24);
    uint32_t raw1 = (uint32_t)wqe[4] | ((uint32_t)wqe[5] << 8) |
                    ((uint32_t)wqe[6] << 16) | ((uint32_t)wqe[7] << 24);
    uint64_t uar_addr = dev->bar0_base + (uint64_t)qp->uarn * 4096u;
    /* BlueFlame の 8 バイトは 1 命令でアトミックに書く。32bit x 2 に分けると
     * PCIe 上で分割されうる(Linux の mlx5_write64() が「32bit システムでは
     * ロックが必要」と注記しているのと同じ理由)。同時 RDMA_READ を 1 本から
     * 16 本へ緩めてドアベル発行頻度が上がった途端、LOCAL_QP_OP_ERR
     * (syndrome=0x02)として実機で顕在化した。 */
    uint64_t raw64 = (uint64_t)raw0 | ((uint64_t)raw1 << 32);
    mmio_write64(uar_addr + MLX5_BF_OFFSET, raw64);

    qp->sq_pc = new_pc;

    volatile ts_rdma_t ts_info = {0};
    ts_info.rdma_op = (opcode == MLX5_OPCODE_RDMA_READ) ? TS_RDMA_OP_SQ_RDMA_READ
                                                          : TS_RDMA_OP_SQ_RDMA_WRITE;
    ts_info.wqe_cqe_opcode = (uint8_t)opcode;
    ts_info.ds_cnt = (uint8_t)ds_cnt;
    ts_info.qpn = qp->qpn;
    ts_info.counter = new_pc;
    ts_info.len = len;
    ts_info.remote_addr = (uint32_t)remote_addr;
    ts_info.remote_rkey = remote_rkey;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_post_rdma_common, 0), &ts_info);

    return 0;
}

/*=================================================================
 * local_data(len バイト)を相手の remote_addr へ書き込む。CQE は送信元
 * (この QP)にのみ生成され、相手側には一切通知されない(IBTA 仕様)。
 *
 * 引数:
 *   dev / qp - 送信元 HCA と RC QP
 *   local_data / len - 送るデータ
 *   remote_addr / remote_key - 相手側のアドレスと rkey
 * 戻り値:
 *   0=投稿成功、-1=失敗
 * コール元:
 *   nvmet_rdma_job_step(), nvmetr_pl_start_data_move()
 * ===============================================================*/
int mlx5_qp_post_rdma_write(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *local_data, uint32_t len,
                             uint64_t remote_addr, uint32_t remote_rkey) {
    return mlx5_qp_post_rdma_common(dev, qp, MLX5_OPCODE_RDMA_WRITE,
                                     (void *)(uintptr_t)local_data, len, remote_addr, remote_rkey);
}

/*=================================================================
 * 相手の remote_addr から len バイト読み出して local_buf へ書き込む。
 * CQE は要求した側(この QP)にのみ生成される。同時発行数は相手の
 * Responder Resources 上限に制約される。
 *
 * 引数:
 *   dev / qp - 要求元 HCA と RC QP
 *   local_buf / len - 読み出し先とバイト数
 *   remote_addr / remote_key - 相手側のアドレスと rkey
 * 戻り値:
 *   0=投稿成功、-1=失敗
 * コール元:
 *   nvmet_rdma_job_step(), nvmetr_pl_issue_rdma_read()
 * ===============================================================*/
int mlx5_qp_post_rdma_read(mlx5_dev_t *dev, mlx5_qp_t *qp, void *local_buf, uint32_t len,
                            uint64_t remote_addr, uint32_t remote_rkey) {
    return mlx5_qp_post_rdma_common(dev, qp, MLX5_OPCODE_RDMA_READ,
                                     local_buf, len, remote_addr, remote_rkey);
}

/*=================================================================
 * RC QP の RQ へ RECV WQE を 1 個投稿する(data_seg 1 個のみ)。
 *
 * 引数:
 *   dev / qp - 対象 HCA と RC QP
 *   buf      - 受信先バッファ
 *   buf_len  - その容量
 * 戻り値:
 *   0=投稿成功、-1=失敗
 * コール元:
 *   rdma_cm_job_step(), nvmet_rdma_job_step(), nvmetr_pl_post_recv_slot(),
 *   nvmer_post_recv(), nvmer_pl_post_recv_slot()
 * ===============================================================*/
int mlx5_qp_post_recv(mlx5_dev_t *dev, mlx5_qp_t *qp, void *buf, uint32_t buf_len) {
    uint32_t pc = qp->rq_pc;
    uint32_t idx = pc & 255u; // log_rq_size=8 -- 256エントリ
    volatile uint8_t *rq_base = (volatile uint8_t *)(uintptr_t)mlx5_qp_wqe_addr(dev, qp);
    volatile uint8_t *wqe = rq_base + (uint64_t)idx * 16u; // stride=16B(log_rq_strideフィールド値0)

    uint32_t byte_count = buf_len;
    wqe[0] = (uint8_t)(byte_count >> 24);
    wqe[1] = (uint8_t)(byte_count >> 16);
    wqe[2] = (uint8_t)(byte_count >> 8);
    wqe[3] = (uint8_t)byte_count;
    wqe[4] = (uint8_t)(qp->mkey >> 24);
    wqe[5] = (uint8_t)(qp->mkey >> 16);
    wqe[6] = (uint8_t)(qp->mkey >> 8);
    wqe[7] = (uint8_t)qp->mkey;
    uint64_t buf_pa = mlx5_dma_addr(buf);
    for (unsigned b = 0; b < 8; b++) {
        wqe[8 + b] = (uint8_t)(buf_pa >> (56 - 8 * b));
    }

    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)mlx5_qp_dbr_addr(dev, qp);
    uint32_t new_pc = pc + 1u;
    dbr[0] = (uint8_t)(new_pc >> 24);
    dbr[1] = (uint8_t)(new_pc >> 16);
    dbr[2] = (uint8_t)(new_pc >> 8);
    dbr[3] = (uint8_t)new_pc;

    dma_wmb();

    qp->rq_pc = new_pc;

    volatile ts_rdma_t ts_info = {0};
    ts_info.rdma_op = TS_RDMA_OP_RQ_POST;
    ts_info.qpn = qp->qpn;
    ts_info.counter = new_pc;
    ts_info.len = buf_len;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_post_recv, 0), &ts_info);

    return 0;
}

/*=================================================================
 * RC QP の CQ を 1 件だけ非ブロッキングでポーリングする。owner bit の
 * 周回トグルと opcode!=INVALID の両方で「HW が書いた完了か」を判定する。
 *
 * 引数:
 *   dev / qp      - 対象 HCA と RC QP
 *   out_is_send   - 1=SQ(送信)の完了、0=RQ(受信)の完了
 *   out_byte_cnt  - 受信完了時のバイト数
 *   out_wqe_idx   - 完了した WQE のインデックス
 * 戻り値:
 *   1=完了を1件取り出した、0=まだ無い、-1=エラー完了
 * コール元:
 *   rdma_cm_job_step(), nvmet_rdma_job_step(), nvme_rdma_connect_job_step(),
 *   nvmer_wait_exec()
 * ===============================================================*/
int mlx5_qp_poll_cqe(mlx5_dev_t *dev, mlx5_qp_t *qp, int *out_is_send,
                     uint32_t *out_recv_len, uint8_t *out_syndrome) {
    uint64_t cq_buf = mlx5_qp_cq_buf_addr(dev, qp);
    uint32_t ci = qp->cq_cc & (MLX5_QP_CQ_NUM_ENTRIES - 1u);
    volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf + (uint64_t)ci * MLX5_QP_CQE_SIZE);

    dcache_invalidate_range((const void *)(uintptr_t)cqe, MLX5_QP_CQE_SIZE);

    uint8_t op_own = cqe[MLX5_CQE_OFF_OP_OWN];
    uint8_t owner_bit = op_own & 0x01u;
    uint8_t opcode = (uint8_t)(op_own >> 4);
    uint8_t expected_owner = (uint8_t)((qp->cq_cc >> MLX5_QP_CQ_LOG_SIZE) & 0x01u);

    if (owner_bit != expected_owner || opcode == MLX5_CQE_OPCODE_INVALID) {
        return 0; // まだHWが書いていない
    }

    // 消費: CQドアベル(consumer_index、bytes0-3)を更新する。
    qp->cq_cc++;
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)mlx5_qp_cq_dbr_addr(dev, qp);
    dbr[0] = (uint8_t)(qp->cq_cc >> 24);
    dbr[1] = (uint8_t)(qp->cq_cc >> 16);
    dbr[2] = (uint8_t)(qp->cq_cc >> 8);
    dbr[3] = (uint8_t)qp->cq_cc;
    dcache_clean_range((const void *)(uintptr_t)dbr, 64u);

    if (opcode == MLX5_CQE_OPCODE_SIG_ERR || opcode == MLX5_CQE_OPCODE_REQ_ERR ||
        opcode == MLX5_CQE_OPCODE_RESP_ERR) {
        uint8_t synd = cqe[MLX5_CQE_OFF_SYNDROME];
        if (out_syndrome) {
            *out_syndrome = synd;
        }
        volatile ts_rdma_t ts_err = {0};
        ts_err.rdma_op = TS_RDMA_OP_CQE_ERR;
        ts_err.wqe_cqe_opcode = opcode;
        ts_err.syndrome = synd;
        ts_err.qpn = qp->qpn;
        ts_err.counter = qp->cq_cc;
        ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_poll_cqe, 0), &ts_err);
        return -1;
    }

    if (out_is_send) {
        *out_is_send = (opcode == MLX5_CQE_OPCODE_REQ) ? 1 : 0;
    }
    uint32_t byte_cnt = 0;
    if (opcode == MLX5_CQE_OPCODE_RESP_SEND) {
        byte_cnt = ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT] << 24) |
                   ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 1] << 16) |
                   ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 2] << 8) |
                   cqe[MLX5_CQE_OFF_BYTE_CNT + 3];
        if (out_recv_len) {
            *out_recv_len = byte_cnt;
        }
    }

    volatile ts_rdma_t ts_ok = {0};
    ts_ok.rdma_op = TS_RDMA_OP_CQE;
    ts_ok.wqe_cqe_opcode = opcode;
    ts_ok.qpn = qp->qpn;
    ts_ok.counter = qp->cq_cc;
    ts_ok.len = byte_cnt;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_poll_cqe, 1), &ts_ok);

    return 1;
}

/*=================================================================
 * 直前に mlx5_qp_poll_cqe() が消費した CQE の opcode(上位 nibble)を返す。
 * エラー完了が REQ_ERR(自分が requester)か RESP_ERR(responder)かの
 * 切り分けに使う診断用。
 *
 * 引数:
 *   dev / qp - 対象 HCA と RC QP
 * 戻り値:
 *   CQE opcode(0xd=REQ_ERR, 0xe=RESP_ERR 等)
 * コール元:
 *   nvmet_rdma_job_step(), nvme_rdma_connect_job_step()
 * ===============================================================*/
uint8_t mlx5_qp_last_cqe_opcode(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    uint64_t cq_buf = mlx5_qp_cq_buf_addr(dev, qp);
    uint32_t ci = (qp->cq_cc - 1u) & (MLX5_QP_CQ_NUM_ENTRIES - 1u);
    volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf + (uint64_t)ci * MLX5_QP_CQE_SIZE);
    return (uint8_t)(cqe[MLX5_CQE_OFF_OP_OWN] >> 4);
}

int mlx5_qp_post_recv_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, void *buf, uint32_t buf_len) {
    uint32_t pc = qp->rq_pc;
    uint32_t idx = pc & 255u; // log_rq_size=8 -- 256エントリ
    volatile uint8_t *rq_base = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->gsi_wqe_cpu;
    volatile uint8_t *wqe = rq_base + (uint64_t)idx * 16u;

    uint32_t byte_count = buf_len;
    wqe[0] = (uint8_t)(byte_count >> 24);
    wqe[1] = (uint8_t)(byte_count >> 16);
    wqe[2] = (uint8_t)(byte_count >> 8);
    wqe[3] = (uint8_t)byte_count;
    wqe[4] = (uint8_t)(qp->mkey >> 24);
    wqe[5] = (uint8_t)(qp->mkey >> 16);
    wqe[6] = (uint8_t)(qp->mkey >> 8);
    wqe[7] = (uint8_t)qp->mkey;
    uint64_t buf_pa = mlx5_dma_addr(buf);
    for (unsigned b = 0; b < 8; b++) {
        wqe[8 + b] = (uint8_t)(buf_pa >> (56 - 8 * b));
    }

    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->gsi_dbr_cpu;
    uint32_t new_pc = pc + 1u;
    dbr[0] = (uint8_t)(new_pc >> 24);
    dbr[1] = (uint8_t)(new_pc >> 16);
    dbr[2] = (uint8_t)(new_pc >> 8);
    dbr[3] = (uint8_t)new_pc;

    dma_wmb();

    qp->rq_pc = new_pc;

    volatile ts_rdma_t ts_info = {0};
    ts_info.rdma_op = TS_RDMA_OP_RQ_POST;
    ts_info.qpn = qp->qpn;
    ts_info.counter = new_pc;
    ts_info.len = buf_len;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_post_recv_gsi, 0), &ts_info);

    return 0;
}

/*=================================================================
 * GSI/UD QP の共有 CQ を 1 件だけ非ブロッキングでポーリングする。
 * mlx5_qp_poll_cqe() と同じロジックだが GSI 専用の CQ アドレスを見る。
 *
 * 引数:
 *   dev / qp / out_is_send / out_byte_cnt / out_wqe_idx
 *            - mlx5_qp_poll_cqe() と同じ
 * 戻り値:
 *   1=完了を1件取り出した、0=まだ無い、-1=エラー完了
 * コール元:
 *   rdma_cm_job_step(), nvmetr_check_gsi_disconnect()
 * ===============================================================*/
int mlx5_qp_poll_cqe_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, int *out_is_send,
                          uint32_t *out_recv_len, uint8_t *out_syndrome) {
    uint64_t cq_buf = (uint64_t)dev->gsi_cq_buf_cpu;
    uint32_t ci = qp->cq_cc & (MLX5_QP_CQ_NUM_ENTRIES - 1u);
    volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf + (uint64_t)ci * MLX5_QP_CQE_SIZE);

    dcache_invalidate_range((const void *)(uintptr_t)cqe, MLX5_QP_CQE_SIZE);

    uint8_t op_own = cqe[MLX5_CQE_OFF_OP_OWN];
    uint8_t owner_bit = op_own & 0x01u;
    uint8_t opcode = (uint8_t)(op_own >> 4);
    uint8_t expected_owner = (uint8_t)((qp->cq_cc >> MLX5_QP_CQ_LOG_SIZE) & 0x01u);

    if (owner_bit != expected_owner || opcode == MLX5_CQE_OPCODE_INVALID) {
        return 0;
    }

    /* [切り分け] この CQE が本当に自分の QP のものか。sop_drop_qpn(byte56-59)の
     * 下位 24bit が QPN、wqe_counter は byte60-61。 */
    {
        uint32_t cqe_qpn = (((uint32_t)cqe[57] << 16) | ((uint32_t)cqe[58] << 8) | cqe[59]);
        uint32_t wqe_cnt = ((uint32_t)cqe[60] << 8) | cqe[61];
        uint32_t bcnt    = ((uint32_t)cqe[44] << 24) | ((uint32_t)cqe[45] << 16) |
                           ((uint32_t)cqe[46] << 8) | cqe[47];
        uart_printf("mlx5qp: [DBG] GSI CQE op=%u own=%u qpn=%u(自qpn=%u) wqe_cnt=%u byte_cnt=%u\n",
                    opcode, owner_bit, cqe_qpn, qp->qpn, wqe_cnt, bcnt);
    }

    qp->cq_cc++;
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)dev->gsi_cq_dbr_cpu;
    dbr[0] = (uint8_t)(qp->cq_cc >> 24);
    dbr[1] = (uint8_t)(qp->cq_cc >> 16);
    dbr[2] = (uint8_t)(qp->cq_cc >> 8);
    dbr[3] = (uint8_t)qp->cq_cc;
    dcache_clean_range((const void *)(uintptr_t)dbr, 64u);

    if (opcode == MLX5_CQE_OPCODE_SIG_ERR || opcode == MLX5_CQE_OPCODE_REQ_ERR ||
        opcode == MLX5_CQE_OPCODE_RESP_ERR) {
        uint8_t synd = cqe[MLX5_CQE_OFF_SYNDROME];
        if (out_syndrome) {
            *out_syndrome = synd;
        }
        volatile ts_rdma_t ts_err = {0};
        ts_err.rdma_op = TS_RDMA_OP_CQE_ERR;
        ts_err.wqe_cqe_opcode = opcode;
        ts_err.syndrome = synd;
        ts_err.qpn = qp->qpn;
        ts_err.counter = qp->cq_cc;
        ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_poll_cqe_gsi, 0), &ts_err);
        return -1;
    }

    if (out_is_send) {
        *out_is_send = (opcode == MLX5_CQE_OPCODE_REQ) ? 1 : 0;
    }
    uint32_t byte_cnt = 0;
    if (opcode == MLX5_CQE_OPCODE_RESP_SEND) {
        byte_cnt = ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT] << 24) |
                   ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 1] << 16) |
                   ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 2] << 8) |
                   cqe[MLX5_CQE_OFF_BYTE_CNT + 3];
        if (out_recv_len) {
            *out_recv_len = byte_cnt;
        }
    }

    volatile ts_rdma_t ts_ok = {0};
    ts_ok.rdma_op = TS_RDMA_OP_CQE;
    ts_ok.wqe_cqe_opcode = opcode;
    ts_ok.qpn = qp->qpn;
    ts_ok.counter = qp->cq_cc;
    ts_ok.len = byte_cnt;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_poll_cqe_gsi, 1), &ts_ok);

    return 1;
}
