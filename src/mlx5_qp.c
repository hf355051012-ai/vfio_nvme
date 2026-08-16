// RC QP用WQE組み立て/ドアベル/CQEポーリング(FWコマンド不要、純粋なメモリ/
// MMIO操作)。mlx5_net.c(Ethernet raw送受信のデータパス層)と同じ役割分担
// -- FWコマンド(mlx5_cmd_exec()呼び出し)は全てmlx5.c側(mlx5_qp_create_rc()
// 等)に置く、という既存アーキテクチャの境界を踏襲する。
//
// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)
// フェーズ(b)。

#include "mlx5_qp.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"
#include "cache.h"
#include "netif.h"
#include "net.h"
#include "ib_mad.h"
#include "timestamp.h"

// TS_TAG_MLX5_QPはmlx5_qp.hで定義済み(nvmet_rdma.cのNVMeコマンド受信
// ログとも共有するため公開マクロへ昇格した、mlx5_qp.hのコメント参照)。

// mlx5.cのmlx5_sq_send_test_frame()/mlx5_net.cのWQE組み立てと同じ定数
// (MLX5_OPCODE_SEND/MLX5_WQE_CTRL_CQ_UPDATE/MLX5_SEND_WQE_BB/MLX5_BF_OFFSET)
// はmlx5.hで共有済み。CQE関連定数はmlx5.c/mlx5_net.cそれぞれで private に
// 定義されている(共有ヘッダに無い)ため、ここでも同じ値を独自に定義する
// (mlx5.cのMLX5_CQE_SIZE/MLX5_CQE_INVALID、mlx5_net.cのMLX5_CQE_OFF_*と
// 同値、実機で確認済みのstruct mlx5_cqe64レイアウト)。
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

int mlx5_qp_post_send(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len) {
    uint32_t pc = qp->sq_pc;
    uint32_t idx = pc & 63u; // log_sq_size=6 -- 64 WQEBB
    volatile uint8_t *sq_base =
        (volatile uint8_t *)(uintptr_t)(mlx5_qp_wqe_addr(dev, qp) + 4096u); // SQ regionはRQ regionの直後
    volatile uint8_t *wqe = sq_base + (uint64_t)idx * MLX5_SEND_WQE_BB;
    for (unsigned i = 0; i < MLX5_SEND_WQE_BB; i++) {
        wqe[i] = 0;
    }

    const uint32_t ds_cnt = 2u; // ctrl_seg(1)+data_seg(1)、eth_seg無し(RC QPはHWがL2/L3/UDP/BTHを構成する)
    uint32_t opmod_idx_opcode = ((pc & 0xFFFFu) << 8) | MLX5_OPCODE_SEND;
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

    // SQドアベル(MLX5_SND_DBR=1、include/linux/mlx5/qp.hで確認済み --
    // 共有ドアベルレコード[8バイト]の後半4バイト)。
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)mlx5_qp_dbr_addr(dev, qp);
    uint32_t new_pc = pc + 1u;
    dbr[4] = (uint8_t)(new_pc >> 24);
    dbr[5] = (uint8_t)(new_pc >> 16);
    dbr[6] = (uint8_t)(new_pc >> 8);
    dbr[7] = (uint8_t)new_pc;

    dma_wmb();

    // BlueFlame: ctrl_seg先頭8バイトをUARへ書く(mlx5.cのmlx5_sq_send_
    // test_frame()/mlx5_net.cのmlx5_net_wqe_commit()と同じパターン)。
    uint32_t raw0 = (uint32_t)wqe[0] | ((uint32_t)wqe[1] << 8) |
                    ((uint32_t)wqe[2] << 16) | ((uint32_t)wqe[3] << 24);
    uint32_t raw1 = (uint32_t)wqe[4] | ((uint32_t)wqe[5] << 8) |
                    ((uint32_t)wqe[6] << 16) | ((uint32_t)wqe[7] << 24);
    uint64_t uar_addr = dev->bar0_base + (uint64_t)qp->uarn * 4096u;
    mmio_write32(uar_addr + MLX5_BF_OFFSET, raw0);
    mmio_write32(uar_addr + MLX5_BF_OFFSET + 4u, raw1);

    qp->sq_pc = new_pc;

    volatile ts_rdma_t ts_info = {0};
    ts_info.rdma_op = TS_RDMA_OP_SQ_SEND;
    ts_info.wqe_cqe_opcode = (uint8_t)MLX5_OPCODE_SEND;
    ts_info.ds_cnt = (uint8_t)ds_cnt;
    ts_info.qpn = qp->qpn;
    ts_info.counter = new_pc;
    ts_info.len = len;
    ts_log_rdma(TS_MK(TS_FILE_MLX5_QP, TS_FUNC_mlx5_qp_post_send, 0), &ts_info);

    return 0;
}

// フェーズ(d): UD/GSI QP経由でSEND WQEを1個投稿する。ctrl_seg(16B)+
// datagram_seg(struct mlx5_av相当、48B=3DS、include/linux/mlx5/qp.hで
// 実際に確認済み)+data_seg(16B)=ds_cnt5、80バイト=WQEBB0(64B)を完全に
// 埋めた上でWQEBB1の先頭16バイトへ食い込む -- mlx5_net.cの「偶数アライン
// 方式」(TCPゼロコピー2フラグメント送信、ds_cnt=5で全く同じサイズ)と
// 構造的に同一で、既に実機で実績のあるパターンを踏襲する。GSI用のSQ
// リング(log_sq_size=6、64 WQEBB)は「1論理送信=2 WQEBB固定」として
// qp->sq_pcをWQEBB単位のカウンタのまま扱う(mlx5_net.cのような「論理WQE
// 単位カウンタ+2倍換算」の二重管理はしない、GSIは低頻度・同期送信
// [呼び出し元が完了を待ってから次を送る]前提のため不要な複雑さ)。
// AVの各フィールドのバイトオフセット(struct mlx5_av、48バイト)は
// drivers/infiniband/hw/mlx5/ah.cのcreate_ib_ah()を実際に取得し裏取り
// 済み: qkey[0..3]/dqp_dct[8..11、下位24bit=宛先QPN]/stat_rate_sl[12]/
// fl_mlid[13、RoCEでは0]/udp_sport[14..15 BE16]/rmac[20..25]/tclass[26]/
// hop_limit[27]/grh_gid_fl[28..31 BE32、bit30=GRH存在ビット(RoCEでは
// 常に1)|sgid_index<<20|flow_label]/rgid[32..47]。
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
    // wqe0[20..23] reserved = 0
    //
    // 実機で発見した本物のバグ(2026-08-12): dqp_dct(下位24bit=宛先QPN)の
    // bit31に`MLX5_EXTENDED_UD_AV`(0x80000000、include/linux/mlx5/
    // device.hで確認済み)を立て忘れていた -- drivers/infiniband/hw/mlx5/
    // wr.cのset_datagram_seg()を実際に取得して確認したところ、
    // `dseg->av.dqp_dct = cpu_to_be32(ud_wr(wr)->remote_qpn |
    // MLX5_EXTENDED_UD_AV);`と、この帯域を必ずORしていた。このビットは
    // 「このAVは48バイトのGRH拡張形式(struct mlx5_av全体)であり、16バイト
    // の短縮形式(struct mlx5_base_av)ではない」ことをHWへ伝える -- 立てて
    // いないとHWはAVを短縮形式(1DS)と解釈し、我々が宣言したds_cnt=5
    // (ctrl+AV3DS+data)との不整合により、実機でLOCAL_LENGTH_ERR
    // (syndrome=0x01)としてSQ自身のCQEに現れた。
    wqe0[24] = (uint8_t)((remote_qpn >> 24) | 0x80u); // bit31=MLX5_EXTENDED_UD_AV
    wqe0[25] = (uint8_t)(remote_qpn >> 16);
    wqe0[26] = (uint8_t)(remote_qpn >> 8);
    wqe0[27] = (uint8_t)remote_qpn; // dqp_dct(下位24bit=宛先QPN)
    // wqe0[28] stat_rate_sl = 0
    // wqe0[29] fl_mlid = 0(RoCEでは未使用)
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
    mmio_write32(uar_addr + MLX5_BF_OFFSET, raw0);
    mmio_write32(uar_addr + MLX5_BF_OFFSET + 4u, raw1);

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

// フェーズ(c)、RDMA_WRITE/RDMA_READ共通のWQE組み立てヘルパ。ctrl_seg
// (16B)+raddr_seg(16B、リモートアドレス+rkey)+data_seg(16B、ローカル
// バッファ)=ds_cnt3、struct mlx5_wqe_raddr_seg(include/linux/mlx5/qp.h、
// raddr[8B BE]+rkey[4B BE]+reserved[4B])のバイトオフセットを実際に
// 取得して裏取り済み。opcodeだけがWRITE(0x08)/READ(0x10)で異なるため
// 共通化する -- READはWQEのdata_seg(ローカル側)が「読み込んだデータの
// 書き込み先」、raddr_segが「読み出し元」になる意味の違いだけで、WQEの
// バイトレイアウト自体はWRITEと同一。
static int mlx5_qp_post_rdma_common(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t opcode,
                                     void *local_data, uint32_t len,
                                     uint64_t remote_addr, uint32_t remote_rkey) {
    uint32_t pc = qp->sq_pc;
    uint32_t idx = pc & 63u; // log_sq_size=6 -- 64 WQEBB
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

    // data_seg(wqe[32..47]): byte_count(4B)+lkey(4B)+addr(8B) -- ローカル側
    // バッファ(WRITEなら送信元、READなら書き込み先)。
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
    mmio_write32(uar_addr + MLX5_BF_OFFSET, raw0);
    mmio_write32(uar_addr + MLX5_BF_OFFSET + 4u, raw1);

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

// RDMA_WRITE: local_data(len バイト)を相手のremote_addr(そのQPのrkeyで
// アクセス可能な範囲)へ書き込む。CQEは送信元(このQP)にのみ生成され、
// 相手側には一切通知されない(IBTA仕様通り、RDMA_WRITE with Immediateを
// 使わない限り受信側は完了を検知できない)。
int mlx5_qp_post_rdma_write(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *local_data, uint32_t len,
                             uint64_t remote_addr, uint32_t remote_rkey) {
    return mlx5_qp_post_rdma_common(dev, qp, MLX5_OPCODE_RDMA_WRITE,
                                     (void *)(uintptr_t)local_data, len, remote_addr, remote_rkey);
}

// RDMA_READ: 相手のremote_addrからlenバイトを読み出し、local_bufへ
// 書き込む。CQEは送信元(このQP、= 読み出しを要求した側)にのみ生成される。
int mlx5_qp_post_rdma_read(mlx5_dev_t *dev, mlx5_qp_t *qp, void *local_buf, uint32_t len,
                            uint64_t remote_addr, uint32_t remote_rkey) {
    return mlx5_qp_post_rdma_common(dev, qp, MLX5_OPCODE_RDMA_READ,
                                     local_buf, len, remote_addr, remote_rkey);
}

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

    // RQドアベル(MLX5_RCV_DBR=0、共有ドアベルレコードの前半4バイト)。
    // RQ投稿はSQと異なりBlueFlame/UARへの書き込みは不要(HWはドアベル
    // レコードの更新をDMAで検知するだけで、SQのような即時処理起動の
    // 仕組みを必要としない)。
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

// 診断用(2026-08-12、パイプライン化調査): 直前にmlx5_qp_poll_cqe()が
// 消費した(qp->cq_cc-1番目の)CQEのopcode(上位nibble)を読む -- REQ_ERR
// (0xd、自分がREQUESTERだった操作=SQ側)かRESP_ERR(0xe、自分がRESPONDER
// だった操作=RQ側)かでエラーの向きを切り分けるために使う。呼び出し元は
// mlx5_qp_poll_cqe()の直後、cq_ccが変わる前に呼ぶこと。
uint8_t mlx5_qp_last_cqe_opcode(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    uint64_t cq_buf = mlx5_qp_cq_buf_addr(dev, qp);
    uint32_t ci = (qp->cq_cc - 1u) & (MLX5_QP_CQ_NUM_ENTRIES - 1u);
    volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf + (uint64_t)ci * MLX5_QP_CQE_SIZE);
    return (uint8_t)(cqe[MLX5_CQE_OFF_OP_OWN] >> 4);
}

// フェーズ(d): GSI/UD QPのRQへRECV WQEを1個投稿する。mlx5_qp_post_recv()
// (RC QP専用、MLX5_QP_WQE_ADDR/MLX5_QP_DBR_ADDRをハードコード)と全く同じ
// WQEフォーマット(data_seg 1個のみ)だが、GSI専用のDMA領域(MLX5_GSI_
// WQE_ADDR/MLX5_GSI_DBR_ADDR)を参照する点だけが異なる -- 既存のRC専用
// 関数を書き換えず並行する新関数として複製する(このプロジェクト一貫の
// 「既存の動作確認済みコードに極力触れない」方針、pcie1.c/pcie.cの分離と
// 同じ)。buf_lenには実ペイロード長+MLX5_GRH_BYTES(40)分の余裕を含める
// こと(mlx5.hのMLX5_GRH_BYTESコメント参照)。
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

// フェーズ(d): GSI/UD QPの共有CQを1件だけ非ブロッキングでポーリングする。
// mlx5_qp_poll_cqe()(RC QP専用)と全く同じロジックだが、GSI専用のCQ
// アドレス(MLX5_GSI_CQ_BUF_CACHE_ADDR/MLX5_GSI_CQ_DBR_CACHE_ADDR)を
// 参照する。
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

// `mlx5qp pingpong`シェルコマンド用の一発診断。PF0/PF1双方にRC QPを1本ずつ
// 作り、相互のQPN/PSN/GID/MACを(RDMA CM等を使わず)直接読み書きしてRTSへ
// 遷移させ、PF0→PF1・PF1→PF0双方向のSEND/RECVを1発ずつ試す。
void mlx5_qp_pingpong_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1) {
    mlx5_qp_t qp0, qp1;

    uart_printf("mlx5qp pingpong: creating QP on PF0...\n");
    if (mlx5_qp_create_rc(dev0, &qp0, 0u) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (PF0 CREATE_QP)\n");
        return;
    }
    uart_printf("mlx5qp pingpong: creating QP on PF1...\n");
    if (mlx5_qp_create_rc(dev1, &qp1, 0u) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (PF1 CREATE_QP)\n");
        return;
    }

    // 2026-08-11、実機診断: num_vhca_ports>0の場合はSET_ROCE_ADDRESS等が
    // vhca_port_numの明示指定を要求する可能性があるため確認する。
    {
        uint8_t npn0 = 0, nvp0 = 0, npn1 = 0, nvp1 = 0;
        mlx5_query_hca_cap_ports(dev0, &npn0, &nvp0);
        mlx5_query_hca_cap_ports(dev1, &npn1, &nvp1);
        uart_printf("mlx5qp pingpong: PF0 native_port_num=%u num_vhca_ports=%u\n", npn0, nvp0);
        uart_printf("mlx5qp pingpong: PF1 native_port_num=%u num_vhca_ports=%u\n", npn1, nvp1);
    }

    // 自分自身のGIDテーブル(index 0)へ登録する -- mlx5_roce_probe()と
    // 同じロジック(netif_find()で見つかれば実際のIP/MAC、無ければ
    // mlx5_net.cと同じ決め打ち値へフォールバック)。
    uint32_t ipv4_0, ipv4_1;
    uint8_t mac0[6], mac1[6];
    netif_t *ctx0 = netif_find("mlx5-pf0");
    netif_t *ctx1 = netif_find("mlx5-pf1");
    if (ctx0 != NULL) {
        ipv4_0 = ctx0->ip;
        for (unsigned i = 0; i < 6; i++) mac0[i] = ctx0->mac[i];
    } else {
        ipv4_0 = ip_from_octets(192, 168, 101, 10);
        mac0[0] = 0x02; mac0[1] = 0x00; mac0[2] = 0x00; mac0[3] = 0x00; mac0[4] = 0x10; mac0[5] = 0x10;
    }
    if (ctx1 != NULL) {
        ipv4_1 = ctx1->ip;
        for (unsigned i = 0; i < 6; i++) mac1[i] = ctx1->mac[i];
    } else {
        ipv4_1 = ip_from_octets(192, 168, 101, 11);
        mac1[0] = 0x02; mac1[1] = 0x00; mac1[2] = 0x00; mac1[3] = 0x00; mac1[4] = 0x10; mac1[5] = 0x11;
    }

    uint8_t gid0[16], gid1[16];
    mlx5_build_roce_gid_v4(ipv4_0, gid0);
    mlx5_build_roce_gid_v4(ipv4_1, gid1);
    if (mlx5_set_roce_address(dev0, 0, gid0, mac0) != 0 ||
        mlx5_set_roce_address(dev1, 0, gid1, mac1) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (SET_ROCE_ADDRESS)\n");
        return;
    }
    qp0.local_gid_index = 0;
    qp1.local_gid_index = 0;

    if (mlx5_qp_modify_rst2init(dev0, &qp0) != 0 || mlx5_qp_modify_rst2init(dev1, &qp1) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (RST2INIT_QP)\n");
        return;
    }
    // 2026-08-11、実機診断: INIT2RTR_QPがBAD_OP_ERR(status=0x02)で失敗した
    // ため、RST2INIT_QP成功後に実際にINIT状態へ遷移できているかを
    // QUERY_QPで確認する。
    {
        uint8_t st0 = 0xFF, st1 = 0xFF;
        mlx5_qp_query_state(dev0, &qp0, &st0);
        mlx5_qp_query_state(dev1, &qp1, &st1);
        uart_printf("mlx5qp pingpong: post-RST2INIT state PF0=%u PF1=%u (INIT=1)\n", st0, st1);
    }

    // RECVを先にpostしておく(相手のSENDが届く前にRQへバッファを用意して
    // おく必要がある、RC QPはTCPと違い自動バッファリングされない)。
    static volatile uint8_t recv_buf0[256];
    static volatile uint8_t recv_buf1[256];
    if (mlx5_qp_post_recv(dev0, &qp0, (void *)(uintptr_t)recv_buf0, sizeof(recv_buf0)) != 0 ||
        mlx5_qp_post_recv(dev1, &qp1, (void *)(uintptr_t)recv_buf1, sizeof(recv_buf1)) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (post_recv)\n");
        return;
    }

    // 相互にremote_qpn/GID/MAC/開始PSNを設定してINIT->RTRへ(手動QP確立
    // -- 標準のIB CM/RDMA_CMを使わず、両端が同一プログラム内にあることを
    // 利用して直接フィールドを読み書きする、フェーズ(b)の設計通り)。
    if (mlx5_qp_modify_init2rtr(dev0, &qp0, qp1.qpn, gid1, mac1, qp1.local_psn) != 0 ||
        mlx5_qp_modify_init2rtr(dev1, &qp1, qp0.qpn, gid0, mac0, qp0.local_psn) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (INIT2RTR_QP)\n");
        return;
    }

    if (mlx5_qp_modify_rtr2rts(dev0, &qp0) != 0 || mlx5_qp_modify_rtr2rts(dev1, &qp1) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (RTR2RTS_QP)\n");
        return;
    }

    uint8_t st0 = 0xFF, st1 = 0xFF;
    mlx5_qp_query_state(dev0, &qp0, &st0);
    mlx5_qp_query_state(dev1, &qp1, &st1);
    uart_printf("mlx5qp pingpong: QUERY_QP state PF0=%u PF1=%u (RTS=3)\n", st0, st1);

    // PF0->PF1へSEND、PF1側のRECV完了(SQ側)/PF0側のSEND完了(SQ側)双方を
    // タイムアウト付きでポーリングする。
    static const char msg[] = "rpi5-boot RC QP pingpong (phase b)";
    if (mlx5_qp_post_send(dev0, &qp0, msg, (uint32_t)sizeof(msg)) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (post_send PF0->PF1)\n");
        return;
    }

    int send_done = 0, recv_done = 0;
    uint64_t start = timer_now();
    while (!(send_done && recv_done)) {
        if (timeout_ms(start, 3000u)) {
            uart_printf("mlx5qp pingpong: TIMEOUT waiting for CQE (send_done=%d recv_done=%d)\n",
                        send_done, recv_done);
            return;
        }
        if (!send_done) {
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(dev0, &qp0, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                send_done = 1;
                uart_printf("mlx5qp pingpong: PF0 SQ CQE observed (send completed)\n");
            } else if (rc < 0) {
                uart_printf("mlx5qp pingpong: FAILED (PF0 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
        if (!recv_done) {
            int is_send = 0;
            uint32_t recv_len = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(dev1, &qp1, &is_send, &recv_len, &synd);
            if (rc == 1 && !is_send) {
                recv_done = 1;
                uart_printf("mlx5qp pingpong: PF1 RQ CQE observed (recv completed, len=%u): \"", recv_len);
                for (uint32_t i = 0; i < recv_len && i < sizeof(recv_buf1); i++) {
                    uart_printf("%c", (char)recv_buf1[i]);
                }
                uart_printf("\"\n");
            } else if (rc < 0) {
                uart_printf("mlx5qp pingpong: FAILED (PF1 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
    }

    int match = 1;
    for (unsigned i = 0; i < sizeof(msg); i++) {
        if (recv_buf1[i] != (uint8_t)msg[i]) {
            match = 0;
            break;
        }
    }
    uart_printf("mlx5qp pingpong: PF0->PF1 data %s\n", match ? "MATCH" : "MISMATCH");
    if (!match) {
        uart_printf("mlx5qp pingpong: FAILED (data mismatch)\n");
        return;
    }

    // 逆方向(PF1->PF0)も確認する -- フェーズ(b)完了条件は「双方向」の
    // SEND/RECV成功。recv_buf0は既にpost_recv済みなのでそのまま使える。
    static const char msg2[] = "rpi5-boot RC QP pingpong reverse (PF1->PF0)";
    if (mlx5_qp_post_send(dev1, &qp1, msg2, (uint32_t)sizeof(msg2)) != 0) {
        uart_printf("mlx5qp pingpong: FAILED (post_send PF1->PF0)\n");
        return;
    }
    int send_done2 = 0, recv_done2 = 0;
    uint64_t start2 = timer_now();
    while (!(send_done2 && recv_done2)) {
        if (timeout_ms(start2, 3000u)) {
            uart_printf("mlx5qp pingpong: TIMEOUT waiting for reverse CQE (send_done=%d recv_done=%d)\n",
                        send_done2, recv_done2);
            return;
        }
        if (!send_done2) {
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(dev1, &qp1, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                send_done2 = 1;
                uart_printf("mlx5qp pingpong: PF1 SQ CQE observed (send completed)\n");
            } else if (rc < 0) {
                uart_printf("mlx5qp pingpong: FAILED (PF1 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
        if (!recv_done2) {
            int is_send = 0;
            uint32_t recv_len = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(dev0, &qp0, &is_send, &recv_len, &synd);
            if (rc == 1 && !is_send) {
                recv_done2 = 1;
                uart_printf("mlx5qp pingpong: PF0 RQ CQE observed (recv completed, len=%u): \"", recv_len);
                for (uint32_t i = 0; i < recv_len && i < sizeof(recv_buf0); i++) {
                    uart_printf("%c", (char)recv_buf0[i]);
                }
                uart_printf("\"\n");
            } else if (rc < 0) {
                uart_printf("mlx5qp pingpong: FAILED (PF0 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
    }
    int match2 = 1;
    for (unsigned i = 0; i < sizeof(msg2); i++) {
        if (recv_buf0[i] != (uint8_t)msg2[i]) {
            match2 = 0;
            break;
        }
    }
    uart_printf("mlx5qp pingpong: PF1->PF0 data %s\n", match2 ? "MATCH" : "MISMATCH");
    if (!match2) {
        uart_printf("mlx5qp pingpong: FAILED (reverse data mismatch)\n");
        return;
    }

    uart_printf("mlx5qp pingpong: PASS (bidirectional RC QP SEND/RECV over RoCEv2 confirmed)\n");
}

// フェーズ(c): PF0<->PF1でRC QPを確立し、双方向のRDMA_WRITE/RDMA_READを
// 確認する。mlx5_qp_pingpong_test()と同じ手順(GID登録・RST2INIT・
// INIT2RTR・RTR2RTS)を踏むが、post_recv/SENDは行わない -- RDMA_WRITE/
// READはリモートのRQを一切経由しない(相手のRQへ何もPOSTしなくても
// 届く)ため、post_recvは不要。異常系(rkey誤りでREMOTE_ACCESS_ERR)も
// 最後に確認する。`mlx5qp rdma`シェルコマンド用。
void mlx5_qp_rdma_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1) {
    mlx5_qp_t qp0, qp1;

    uart_printf("mlx5qp rdma: creating QP on PF0...\n");
    if (mlx5_qp_create_rc(dev0, &qp0, 0u) != 0) {
        uart_printf("mlx5qp rdma: FAILED (PF0 CREATE_QP)\n");
        return;
    }
    uart_printf("mlx5qp rdma: creating QP on PF1...\n");
    if (mlx5_qp_create_rc(dev1, &qp1, 0u) != 0) {
        uart_printf("mlx5qp rdma: FAILED (PF1 CREATE_QP)\n");
        return;
    }

    uint32_t ipv4_0, ipv4_1;
    uint8_t mac0[6], mac1[6];
    netif_t *ctx0 = netif_find("mlx5-pf0");
    netif_t *ctx1 = netif_find("mlx5-pf1");
    if (ctx0 != NULL) {
        ipv4_0 = ctx0->ip;
        for (unsigned i = 0; i < 6; i++) mac0[i] = ctx0->mac[i];
    } else {
        ipv4_0 = ip_from_octets(192, 168, 101, 10);
        mac0[0] = 0x02; mac0[1] = 0x00; mac0[2] = 0x00; mac0[3] = 0x00; mac0[4] = 0x10; mac0[5] = 0x10;
    }
    if (ctx1 != NULL) {
        ipv4_1 = ctx1->ip;
        for (unsigned i = 0; i < 6; i++) mac1[i] = ctx1->mac[i];
    } else {
        ipv4_1 = ip_from_octets(192, 168, 101, 11);
        mac1[0] = 0x02; mac1[1] = 0x00; mac1[2] = 0x00; mac1[3] = 0x00; mac1[4] = 0x10; mac1[5] = 0x11;
    }

    uint8_t gid0[16], gid1[16];
    mlx5_build_roce_gid_v4(ipv4_0, gid0);
    mlx5_build_roce_gid_v4(ipv4_1, gid1);
    if (mlx5_set_roce_address(dev0, 0, gid0, mac0) != 0 ||
        mlx5_set_roce_address(dev1, 0, gid1, mac1) != 0) {
        uart_printf("mlx5qp rdma: FAILED (SET_ROCE_ADDRESS)\n");
        return;
    }
    qp0.local_gid_index = 0;
    qp1.local_gid_index = 0;

    if (mlx5_qp_modify_rst2init(dev0, &qp0) != 0 || mlx5_qp_modify_rst2init(dev1, &qp1) != 0) {
        uart_printf("mlx5qp rdma: FAILED (RST2INIT_QP)\n");
        return;
    }
    if (mlx5_qp_modify_init2rtr(dev0, &qp0, qp1.qpn, gid1, mac1, qp1.local_psn) != 0 ||
        mlx5_qp_modify_init2rtr(dev1, &qp1, qp0.qpn, gid0, mac0, qp0.local_psn) != 0) {
        uart_printf("mlx5qp rdma: FAILED (INIT2RTR_QP)\n");
        return;
    }
    if (mlx5_qp_modify_rtr2rts(dev0, &qp0) != 0 || mlx5_qp_modify_rtr2rts(dev1, &qp1) != 0) {
        uart_printf("mlx5qp rdma: FAILED (RTR2RTS_QP)\n");
        return;
    }
    uint8_t st0 = 0xFF, st1 = 0xFF;
    mlx5_qp_query_state(dev0, &qp0, &st0);
    mlx5_qp_query_state(dev1, &qp1, &st1);
    uart_printf("mlx5qp rdma: QUERY_QP state PF0=%u PF1=%u (RTS=3)\n", st0, st1);

    // PF0->PF1: RDMA_WRITE。src(PF0側、送信元パターン)をdst(PF1側、
    // qp1.mkeyで公開されている物理アドレス)へ直接書き込む。
    static volatile uint8_t src0[64];
    static volatile uint8_t dst1[64];
    for (unsigned i = 0; i < sizeof(src0); i++) {
        src0[i] = (uint8_t)(0xA0u + i);
        dst1[i] = 0;
    }
    dcache_clean_range((const void *)(uintptr_t)src0, sizeof(src0));
    // 2026-08-12、実機で発見した本物のバグ: dst1(書き込み先)のゼロクリア
    // 直後にdcache_clean_range()を呼んでいなかった -- ゼロクリアで生じた
    // dirtyなキャッシュラインが、後段のdcache_invalidate_range()
    // (`dc civac`=クリーン+無効化)によってHWのDMA書き込み後にメイン
    // メモリへ書き戻され、HWが書いた実データを「0」で上書きしてしまって
    // いた(64B要求で先頭16Bだけ正しく見えていたのはこの競合の結果、
    // 完全な原因ではなく偶然の産物だった可能性が高い)。
    dcache_clean_range((const void *)(uintptr_t)dst1, sizeof(dst1));
    uint64_t dst1_pa = mlx5_dma_addr((const void *)(uintptr_t)dst1);
    if (mlx5_qp_post_rdma_write(dev0, &qp0, (const void *)(uintptr_t)src0, (uint32_t)sizeof(src0),
                                 dst1_pa, qp1.mkey) != 0) {
        uart_printf("mlx5qp rdma: FAILED (post_rdma_write PF0->PF1)\n");
        return;
    }
    {
        int done = 0;
        uint64_t start = timer_now();
        while (!done) {
            if (timeout_ms(start, 3000u)) {
                uart_printf("mlx5qp rdma: TIMEOUT waiting for WRITE CQE (PF0->PF1)\n");
                return;
            }
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(dev0, &qp0, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                done = 1;
                uart_printf("mlx5qp rdma: PF0 SQ CQE observed (RDMA_WRITE completed)\n");
            } else if (rc < 0) {
                uart_printf("mlx5qp rdma: FAILED (PF0 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
    }
    dcache_invalidate_range((const void *)(uintptr_t)dst1, sizeof(dst1));
    int wmatch = 1;
    for (unsigned i = 0; i < sizeof(src0); i++) {
        if (dst1[i] != src0[i]) {
            wmatch = 0;
            break;
        }
    }
    uart_printf("mlx5qp rdma: PF0->PF1 RDMA_WRITE data %s\n", wmatch ? "MATCH" : "MISMATCH");
    if (!wmatch) {
        uart_printf("mlx5qp rdma: FAILED (RDMA_WRITE data mismatch)\n");
        return;
    }

    // PF1->PF0: RDMA_READ。PF1のQPがPF0側(src0、qp0.mkeyで公開)から
    // 読み出し、PF1側のローカルバッファdst0へ書き込む。
    static volatile uint8_t dst0[64];
    for (unsigned i = 0; i < sizeof(dst0); i++) {
        dst0[i] = 0;
    }
    dcache_clean_range((const void *)(uintptr_t)dst0, sizeof(dst0));
    uint64_t src0_pa = mlx5_dma_addr((const void *)(uintptr_t)src0);
    if (mlx5_qp_post_rdma_read(dev1, &qp1, (void *)(uintptr_t)dst0, (uint32_t)sizeof(dst0),
                                src0_pa, qp0.mkey) != 0) {
        uart_printf("mlx5qp rdma: FAILED (post_rdma_read PF1->PF0)\n");
        return;
    }
    {
        int done = 0;
        uint64_t start = timer_now();
        while (!done) {
            if (timeout_ms(start, 3000u)) {
                uart_printf("mlx5qp rdma: TIMEOUT waiting for READ CQE (PF1->PF0)\n");
                return;
            }
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(dev1, &qp1, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                done = 1;
                uart_printf("mlx5qp rdma: PF1 SQ CQE observed (RDMA_READ completed)\n");
            } else if (rc < 0) {
                uart_printf("mlx5qp rdma: FAILED (PF1 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
    }
    dcache_invalidate_range((const void *)(uintptr_t)dst0, sizeof(dst0));
    int rmatch = 1;
    for (unsigned i = 0; i < sizeof(dst0); i++) {
        if (dst0[i] != src0[i]) {
            rmatch = 0;
            break;
        }
    }
    uart_printf("mlx5qp rdma: PF1->PF0 RDMA_READ data %s\n", rmatch ? "MATCH" : "MISMATCH");
    if (!rmatch) {
        uart_printf("mlx5qp rdma: FAILED (RDMA_READ data mismatch)\n");
        return;
    }

    // 異常系: 誤ったrkey(自分自身のmkey、相手のmkeyではない値)でRDMA_
    // WRITEを送り、REMOTE_ACCESS_ERR系のsyndromeがCQEに現れることを確認
    // する。相手側のmkeyテーブルに存在しないmkey値を指定した場合の挙動。
    uint32_t bogus_rkey = qp0.mkey ^ 0xFFu; // 存在しないと思われるmkey値
    if (mlx5_qp_post_rdma_write(dev0, &qp0, (const void *)(uintptr_t)src0, (uint32_t)sizeof(src0),
                                 dst1_pa, bogus_rkey) != 0) {
        uart_printf("mlx5qp rdma: FAILED (post_rdma_write with bogus rkey)\n");
        return;
    }
    {
        int done = 0;
        uint64_t start = timer_now();
        while (!done) {
            if (timeout_ms(start, 3000u)) {
                uart_printf("mlx5qp rdma: TIMEOUT waiting for bogus-rkey CQE (expected an error)\n");
                return;
            }
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(dev0, &qp0, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                done = 1;
                uart_printf("mlx5qp rdma: bogus-rkey WRITE unexpectedly succeeded (no error CQE)\n");
            } else if (rc < 0) {
                done = 1;
                uart_printf("mlx5qp rdma: bogus-rkey WRITE correctly failed, syndrome=0x%02x\n", synd);
            }
        }
    }

    uart_printf("mlx5qp rdma: PASS (bidirectional RDMA_WRITE/READ over RoCEv2 confirmed)\n");
}

// 2026-08-11、フェーズ(b)実機診断: 同一PF内に2本のRC QPを作り、互いに
// "自分自身"のGID/MACを使って接続する(qp0の相手をqp1、qp1の相手をqp0、
// ただし両方ともdev一つ・GID一つを共有)。mlx5_qp_pingpong_test()と
// ほぼ同じ手順だが、dev0==dev1==devである点だけが異なる -- INIT2RTR_QPの
// BAD_OP_ERRがクロスPF(別々のPCI関数/command interface)接続特有の問題か
// どうかを切り分けるための対照実験。
void mlx5_qp_loopback_test(mlx5_dev_t *dev, const char *label) {
    mlx5_qp_t qp0, qp1;

    uart_printf("mlx5qp loop(%s): creating QP #0...\n", label);
    if (mlx5_qp_create_rc(dev, &qp0, 0u) != 0) {
        uart_printf("mlx5qp loop(%s): FAILED (QP#0 CREATE_QP)\n", label);
        return;
    }
    uart_printf("mlx5qp loop(%s): creating QP #1...\n", label);
    if (mlx5_qp_create_rc(dev, &qp1, 0u) != 0) {
        uart_printf("mlx5qp loop(%s): FAILED (QP#1 CREATE_QP)\n", label);
        return;
    }

    uint32_t ipv4;
    uint8_t mac[6];
    netif_t *ctx = netif_find(label);
    if (ctx != NULL) {
        ipv4 = ctx->ip;
        for (unsigned i = 0; i < 6; i++) mac[i] = ctx->mac[i];
    } else {
        ipv4 = ip_from_octets(192, 168, 101, 10);
        mac[0] = 0x02; mac[1] = 0x00; mac[2] = 0x00; mac[3] = 0x00; mac[4] = 0x10; mac[5] = 0x10;
    }
    uint8_t gid[16];
    mlx5_build_roce_gid_v4(ipv4, gid);
    if (mlx5_set_roce_address(dev, 0, gid, mac) != 0) {
        uart_printf("mlx5qp loop(%s): FAILED (SET_ROCE_ADDRESS)\n", label);
        return;
    }
    qp0.local_gid_index = 0;
    qp1.local_gid_index = 0;

    if (mlx5_qp_modify_rst2init(dev, &qp0) != 0 || mlx5_qp_modify_rst2init(dev, &qp1) != 0) {
        uart_printf("mlx5qp loop(%s): FAILED (RST2INIT_QP)\n", label);
        return;
    }

    static volatile uint8_t recv_buf0[256];
    static volatile uint8_t recv_buf1[256];
    if (mlx5_qp_post_recv(dev, &qp0, (void *)(uintptr_t)recv_buf0, sizeof(recv_buf0)) != 0 ||
        mlx5_qp_post_recv(dev, &qp1, (void *)(uintptr_t)recv_buf1, sizeof(recv_buf1)) != 0) {
        uart_printf("mlx5qp loop(%s): FAILED (post_recv)\n", label);
        return;
    }

    {
        uint8_t st0 = 0xFFu, st1 = 0xFFu;
        mlx5_qp_query_state(dev, &qp0, &st0);
        mlx5_qp_query_state(dev, &qp1, &st1);
        uart_printf("mlx5qp loop(%s): pre-INIT2RTR state qp0=%u qp1=%u (INIT=1)\n", label, st0, st1);
    }

    if (mlx5_qp_modify_init2rtr(dev, &qp0, qp1.qpn, gid, mac, qp1.local_psn) != 0 ||
        mlx5_qp_modify_init2rtr(dev, &qp1, qp0.qpn, gid, mac, qp0.local_psn) != 0) {
        uart_printf("mlx5qp loop(%s): FAILED (INIT2RTR_QP)\n", label);
        return;
    }

    if (mlx5_qp_modify_rtr2rts(dev, &qp0) != 0 || mlx5_qp_modify_rtr2rts(dev, &qp1) != 0) {
        uart_printf("mlx5qp loop(%s): FAILED (RTR2RTS_QP)\n", label);
        return;
    }

    uart_printf("mlx5qp loop(%s): PASS -- QP#0(qpn=%u)<->QP#1(qpn=%u) reached RTS\n",
                label, qp0.qpn, qp1.qpn);
}

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(d): GSI/UD QP1相当。PF0<->PF1で
// UD(またはGSI/QP1相当、use_gsiで選択)QPを1本ずつ作り、RST2INIT->
// INIT2RTR->RTR2RTSを経てRTSへ遷移させ、PF0からPF1へダミーのMAD形式
// パケットを1個送信、到着・内容一致を確認する(CM無し、手動でQPN/GID/
// MACを交換する、フェーズ(b)のmlx5_qp_pingpong_test()と同じ設計)。
// `mlx5mad test`シェルコマンド用(mlx5.cのmlx5_gsi_cmd_test()から呼ばれる)。
void mlx5_gsi_mad_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1, int use_gsi) {
    mlx5_qp_t qp0, qp1;
    const char *kind = use_gsi ? "GSI(QP1)" : "UD";

    uart_printf("mlx5mad test: creating %s QP on PF0...\n", kind);
    int rc0 = use_gsi ? mlx5_qp_create_gsi(dev0, &qp0) : mlx5_qp_create_ud(dev0, &qp0);
    if (rc0 != 0) {
        uart_printf("mlx5mad test: FAILED (PF0 CREATE_QP)\n");
        return;
    }
    uart_printf("mlx5mad test: creating %s QP on PF1...\n", kind);
    int rc1 = use_gsi ? mlx5_qp_create_gsi(dev1, &qp1) : mlx5_qp_create_ud(dev1, &qp1);
    if (rc1 != 0) {
        uart_printf("mlx5mad test: FAILED (PF1 CREATE_QP)\n");
        return;
    }

    // GID/MAC登録(mlx5_qp_pingpong_test()と同じフォールバックパターン)。
    uint32_t ipv4_0, ipv4_1;
    uint8_t mac0[6], mac1[6];
    netif_t *ctx0 = netif_find("mlx5-pf0");
    netif_t *ctx1 = netif_find("mlx5-pf1");
    if (ctx0 != NULL) {
        ipv4_0 = ctx0->ip;
        for (unsigned i = 0; i < 6; i++) mac0[i] = ctx0->mac[i];
    } else {
        ipv4_0 = ip_from_octets(192, 168, 101, 10);
        mac0[0] = 0x02; mac0[1] = 0x00; mac0[2] = 0x00; mac0[3] = 0x00; mac0[4] = 0x10; mac0[5] = 0x10;
    }
    if (ctx1 != NULL) {
        ipv4_1 = ctx1->ip;
        for (unsigned i = 0; i < 6; i++) mac1[i] = ctx1->mac[i];
    } else {
        ipv4_1 = ip_from_octets(192, 168, 101, 11);
        mac1[0] = 0x02; mac1[1] = 0x00; mac1[2] = 0x00; mac1[3] = 0x00; mac1[4] = 0x10; mac1[5] = 0x11;
    }
    uint8_t gid0[16], gid1[16];
    mlx5_build_roce_gid_v4(ipv4_0, gid0);
    mlx5_build_roce_gid_v4(ipv4_1, gid1);
    if (mlx5_set_roce_address(dev0, 0, gid0, mac0) != 0 ||
        mlx5_set_roce_address(dev1, 0, gid1, mac1) != 0) {
        uart_printf("mlx5mad test: FAILED (SET_ROCE_ADDRESS)\n");
        return;
    }
    qp0.local_gid_index = 0;
    qp1.local_gid_index = 0;

    uint32_t qkey = use_gsi ? IB_QP1_QKEY : 0x12345678u;
    if (mlx5_qp_modify_rst2init_ud(dev0, &qp0, qkey) != 0 ||
        mlx5_qp_modify_rst2init_ud(dev1, &qp1, qkey) != 0) {
        uart_printf("mlx5mad test: FAILED (RST2INIT_QP)\n");
        return;
    }

    // 相手のRECVが届く前にRQへバッファを用意しておく(RC QPと同じ理由)。
    // GRH(40B)+標準MADサイズ(256B)分の余裕を持たせる。
    static volatile uint8_t recv_buf1[MLX5_GRH_BYTES + IB_MGMT_MAD_SIZE];
    if (mlx5_qp_post_recv_gsi(dev1, &qp1, (void *)(uintptr_t)recv_buf1, sizeof(recv_buf1)) != 0) {
        uart_printf("mlx5mad test: FAILED (post_recv)\n");
        return;
    }

    if (mlx5_qp_modify_init2rtr_ud(dev0, &qp0) != 0 || mlx5_qp_modify_init2rtr_ud(dev1, &qp1) != 0) {
        uart_printf("mlx5mad test: FAILED (INIT2RTR_QP)\n");
        return;
    }
    if (mlx5_qp_modify_rtr2rts_ud(dev0, &qp0) != 0 || mlx5_qp_modify_rtr2rts_ud(dev1, &qp1) != 0) {
        uart_printf("mlx5mad test: FAILED (RTR2RTS_QP)\n");
        return;
    }

    uint8_t st0 = 0xFFu, st1 = 0xFFu;
    mlx5_qp_query_state(dev0, &qp0, &st0);
    mlx5_qp_query_state(dev1, &qp1, &st1);
    uart_printf("mlx5mad test: QUERY_QP state PF0=%u PF1=%u (RTS=3)\n", st0, st1);

    // ダミーのMAD(class_version=1、method=IB_MGMT_METHOD_SEND、tid固定値、
    // データ部に既知の文字列パターン)を組み立てる。
    static volatile uint8_t mad_buf[IB_MGMT_MAD_SIZE];
    for (unsigned i = 0; i < sizeof(mad_buf); i++) {
        mad_buf[i] = 0;
    }
    ib_mad_hdr_build(mad_buf, IB_MGMT_CLASS_CM, 1, IB_MGMT_METHOD_SEND,
                     0x1122334455667788ull, 0x1234u, 0xdeadbeefu);
    static const char mad_payload[] = "rpi5-boot phase(d) GSI/MAD test payload";
    for (unsigned i = 0; i < sizeof(mad_payload) && (IB_MAD_HDR_LEN + i) < sizeof(mad_buf); i++) {
        mad_buf[IB_MAD_HDR_LEN + i] = (uint8_t)mad_payload[i];
    }
    // mad_bufは通常のcacheable RAM(DMA読み出し元)なので、CPUの書き込みを
    // HWから見えるようにするため送信前にキャッシュクリーンが必要
    // (RDMA_WRITEテストのsrc0と同じ理由 -- 忘れるとHWがDMA読み出し時点で
    // まだメインメモリへ書き戻されていない[実質ゼロの]内容を読んでしまう)。
    dcache_clean_range((const void *)(uintptr_t)mad_buf, sizeof(mad_buf));

    // 2026-08-12、実機診断: UD(st=0x2)は`remote_qpn=qp1.qpn`(CREATE_QPが
    // 実際に割り当てた番号)で完全に動作したが、GSI(st=0x8)を同じ経路
    // (dest_qpn=qp1.qpnの実際の割り当て値)で試したところSEND自体はHWで
    // 処理完了する(hw_sq_wqebb=2)のに相手のRQへ一切届かなかった
    // (hw_rq=0のまま、mlx5_qp_query_counters()で確認)。**実機で確認
    // (2026-08-12)**: IBTA仕様通りGSI(QP1)はネットワーク上「宛先QPN=1」
    // という固定の既知値で参照する規約で、CREATE_QPが内部的に割り当てる
    // 実際のQPN(388等)はローカルな管理番号に過ぎない -- 送信側はGSIへ
    // 向けるパケットのBTH宛先QPNを常に1にする必要があり、受信側HWが
    // QPN=1到着を認識して自分のGSI QPオブジェクト(実際のQPN=388)へ
    // 内部的にルーティングする。dest_qpn=1へ変更したところ実機でPASS
    // (CQE到着・データ完全一致)を確認した -- フェーズ(e)でCM/MADの
    // 宛先を組み立てる際もこの規約(GSI宛は常にQPN=1固定)に従うこと。
    uint32_t dest_qpn = use_gsi ? 1u : qp1.qpn;
    if (mlx5_qp_post_send_ud(dev0, &qp0, (const void *)(uintptr_t)mad_buf, (uint32_t)sizeof(mad_buf),
                              dest_qpn, qp1.qkey, gid1, mac1) != 0) {
        uart_printf("mlx5mad test: FAILED (post_send PF0->PF1)\n");
        return;
    }

    int send_done = 0, recv_done = 0;
    uint32_t recv_len = 0;
    uint64_t start = timer_now();
    while (!(send_done && recv_done)) {
        if (timeout_ms(start, 3000u)) {
            uart_printf("mlx5mad test: TIMEOUT waiting for CQE (send_done=%d recv_done=%d)\n",
                        send_done, recv_done);
            // このQP自身のRQ/SQでHWが実際に何WQEを処理したかをQUERY_QPで
            // 直接確認する(mlx5stat/QUERY_RQ/QUERY_SQはEthernetバック
            // エンド固定のdev->rqn/sqnしか見ないため、個々のmlx5_qp_tは
            // これで確認する必要がある -- mlx5_qp_query_counters()参照)。
            uint32_t hw_rq1 = 0, sw_rq1 = 0;
            uint16_t hw_sq0 = 0, sw_sq0 = 0;
            mlx5_qp_query_counters(dev0, &qp0, NULL, NULL, &hw_sq0, &sw_sq0);
            mlx5_qp_query_counters(dev1, &qp1, &hw_rq1, &sw_rq1, NULL, NULL);
            uart_printf("mlx5mad test: diag PF0 qp0(qpn=%u): hw_sq_wqebb=%u sw_sq_wqebb=%u\n",
                        qp0.qpn, hw_sq0, sw_sq0);
            uart_printf("mlx5mad test: diag PF1 qp1(qpn=%u): hw_rq=%u sw_rq=%u\n",
                        qp1.qpn, hw_rq1, sw_rq1);
            return;
        }
        if (!send_done) {
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe_gsi(dev0, &qp0, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                send_done = 1;
                uart_printf("mlx5mad test: PF0 SQ CQE observed (send completed)\n");
            } else if (rc < 0) {
                uart_printf("mlx5mad test: FAILED (PF0 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
        if (!recv_done) {
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe_gsi(dev1, &qp1, &is_send, &recv_len, &synd);
            if (rc == 1 && !is_send) {
                recv_done = 1;
                uart_printf("mlx5mad test: PF1 RQ CQE observed (recv completed, byte_cnt=%u, "
                            "expect GRH(%u)+MAD(%u)=%u)\n",
                            recv_len, MLX5_GRH_BYTES, (unsigned)sizeof(mad_buf),
                            MLX5_GRH_BYTES + (unsigned)sizeof(mad_buf));
            } else if (rc < 0) {
                uart_printf("mlx5mad test: FAILED (PF1 CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
    }

    if (recv_len != MLX5_GRH_BYTES + sizeof(mad_buf)) {
        uart_printf("mlx5mad test: WARNING byte_cnt mismatch (got %u, expected %u) -- "
                    "checking payload anyway\n", recv_len, MLX5_GRH_BYTES + (unsigned)sizeof(mad_buf));
    }

    // recv_buf1は通常のcacheable RAM(DMA先バッファ)なので、HWの書き込みを
    // CPUから見えるようにする前にキャッシュ無効化が必要(RDMA_WRITE/READ
    // テストのdst1/dst0と同じ理由、CLAUDE.md「DMAコヒーレンシの落とし穴」
    // 節参照 -- 忘れると読んだ内容が古い/ゼロのままになる)。
    dcache_invalidate_range((const void *)(uintptr_t)recv_buf1, sizeof(recv_buf1));

    int match = 1;
    for (unsigned i = 0; i < sizeof(mad_buf); i++) {
        if (recv_buf1[MLX5_GRH_BYTES + i] != mad_buf[i]) {
            match = 0;
            break;
        }
    }
    uart_printf("mlx5mad test: PF0->PF1 MAD payload (after %uB GRH offset) %s\n",
                MLX5_GRH_BYTES, match ? "MATCH" : "MISMATCH");
    if (!match) {
        uart_printf("mlx5mad test: FAILED (MAD content mismatch)\n");
        return;
    }

    uart_printf("mlx5mad test: PASS (%s SEND/RECV over RoCEv2, single MAD, PF0->PF1 confirmed)\n", kind);
}
