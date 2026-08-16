// ConnectX-4 Lx (mlx5) HCA初期化、フェーズ1: Initialization Segmentの読み取りと
// ファームウェア準備完了待ち。構造体レイアウト・定数は推測せずLinuxカーネル
// (`include/linux/mlx5/device.h`, `drivers/net/ethernet/mellanox/mlx5/core/
// cmd.c`, `main.c`)から直接取得したものを使用している(このプロジェクト一貫の
// 方法論、CLAUDE.md「参照ドライバソース」節と同じ)。
//
// **本ファイルは-O0でビルドすること(Makefile参照)。** 実機で発見した未解明の
// 問題: -O2でビルドすると、ENABLE_HCA成功直後のQUERY_ISSIが毎回
// MLX5_CMD_STAT_BAD_SYS_STATE_ERR(delivery status=0x04)で失敗する
// (QUERY_PAGES/MANAGE_PAGES関連コードの呼び出しを完全に無効化しても再現、
// 呼び出し元での再順序化やコマンド完了後の遅延追加でも解消せず、
// -fno-strict-aliasingでも解消しなかった)。-O0でビルドすると同じソースが
// 実機で確実に成功する(ENABLE_HCA→QUERY_ISSI→SET_ISSI→QUERY_PAGESまで
// 実機確認済み)。根本原因(コンパイラの最適化がこの特定のハードウェア
// タイミングに対して何をしているのか)は未特定のまま -- 再調査する際は、
// 生成されたアセンブリを-O2/-O0で比較し、mlx5_cmd_exec()のドアベル書き込み
// 〜ポーリング開始までの命令列の違いから当たりを付けること。

#include "mlx5.h"
#include "mmio.h"
#include "timer.h"
#include "uart.h"
#include "cache.h"
#include "net.h"
#include "netif.h"
#include "mlx5_qp.h"
#include "rdma_cm.h"
#include "nvme_rdma.h"
#include "nvmet_rdma.h"
#include <stddef.h>
#include "platform.h"

// mlx5.hのMLX5_DMA_BASE/SIZE(board.h)は.dma_bssとは独立した専用128MB
// 領域 -- .dma_bssとの衝突検知はmmu.c側(mmu_build_tables()、コンパイル時
// 定数同士の比較のみで済むためリンカシンボルを跨いだ実行時チェックは
// 不要になった)に一本化した。

// ConnectXのBAR0はpcie1_assign_bar0_at()によりPCIアドレスへ割り当て済み。
// アウトバウンド窓0(pcie1_rc_init()内のpcie1_set_outbound_win(0,
// PCIE1_OUTBOUND_CPU_BASE, 0, PCIE1_OUTBOUND_SIZE))がCPUアドレス
// PCIE1_OUTBOUND_CPU_BASEをPCIアドレス0へ写しているため、BAR0はそのまま
// CPUアドレスPCIE1_OUTBOUND_CPU_BASE+オフセットでアクセスできる
// (デュアルポート対応: PF0/PF1それぞれのBAR0 CPUアドレスは
// `mlx5_dev_t.bar0_base` として個別に保持する、CLAUDE.md「ConnectX
// デュアルポート対応」節参照 -- 以前のグローバル固定`MLX5_BAR0_BASE`は
// 廃止した)。

// mlx5/InfiniBand系のレジスタはビッグエンディアン(__be32) -- このプロジェクト
// がこれまで扱ってきたBroadcom/RP1系(リトルエンディアン)とは異なるため、
// 読み書き両方で明示的にバイトスワップが必要。ここを忘れるとfw_rev等が
// 全く辻褄の合わない値になる(実機で確認する前に必ず疑うべき箇所)。
static inline uint32_t mlx5_read32(const mlx5_dev_t *dev, uint64_t off) {
    return __builtin_bswap32(mmio_read32(dev->bar0_base + off));
}

static inline void mlx5_write32(const mlx5_dev_t *dev, uint64_t off, uint32_t val) {
    mmio_write32(dev->bar0_base + off, __builtin_bswap32(val));
}

// --- Initialization Segment (BAR0オフセット0)。フィールドオフセットは
// `struct mlx5_init_seg`(device.h)から手計算で導出した値 -- 各フィールドの
// 前にある`rsvd`配列のバイト数を積算している。今後このstructの新しい
// フィールドを扱う際は、同じ方法で再計算するか、上記ヘッダを再取得して
// 確認すること。 ---
#define MLX5_ISEG_FW_REV            0x000u  // __be32 fw_rev
#define MLX5_ISEG_CMDIF_REV_FW_SUB  0x004u  // __be32 cmdif_rev_fw_sub (cmdif_revは上位16bit)
#define MLX5_ISEG_CMDQ_ADDR_H       0x010u  // __be32 cmdq_addr_h
#define MLX5_ISEG_CMDQ_ADDR_L_SZ    0x014u  // __be32 cmdq_addr_l_sz (下位8bitにlog_sz<<4|log_stride)
#define MLX5_ISEG_CMD_DBELL         0x018u  // __be32 cmd_dbell
#define MLX5_ISEG_INITIALIZING      0x1FCu  // __be32 initializing (bit31)

// Linux mlx5_core cmd.cの`CMD_IF_REV`と同値。ConnectX-4世代のファームウェアは
// このコマンドインターフェース版数を報告するはずで、一致しなければ以降の
// コマンド構造体(オペコード/レイアウト)の前提が崩れるため即座に中断する。
#define MLX5_CMD_IF_REV 5u

// ファームウェア初期化待ちのタイムアウト。Linux側は起動直後は約2秒
// (pre-initializing)、その後さらに長い時間(initializing、既定で数十秒
// オーダー)を許容しているが、まずは実機での応答性を見るため短めに設定
// しておく -- 実機でタイムアウトする場合はここを見直すこと。
#define MLX5_FW_INIT_TIMEOUT_MS 5000u

// フェーズ2(下記)の前方宣言。
static int mlx5_cmdq_init(mlx5_dev_t *dev);
static int mlx5_enable_hca(mlx5_dev_t *dev);
static int mlx5_query_issi(mlx5_dev_t *dev, uint16_t *out_current_issi, uint32_t *out_supported_issi_dw0);
static int mlx5_set_issi(mlx5_dev_t *dev, uint16_t issi);
static int mlx5_query_pages(mlx5_dev_t *dev, uint32_t op_mod, uint16_t *out_function_id, int32_t *out_num_pages);
static int mlx5_manage_pages_give(mlx5_dev_t *dev, uint16_t function_id, int32_t npages);
#define MLX5_QUERY_PAGES_OP_MOD_BOOT_PAGES 0x1u
#define MLX5_QUERY_PAGES_OP_MOD_INIT_PAGES 0x2u

// フェーズ3(下記)の前方宣言。
static int mlx5_query_hca_cap_general(mlx5_dev_t *dev, uint8_t *cap_out);
static int mlx5_set_hca_cap_general(mlx5_dev_t *dev, const uint8_t *cap_in);
static int mlx5_query_hca_cap_eth_offloads(mlx5_dev_t *dev, uint32_t *out_max_lso_bytes); // 2026-08-10、LSO対応
static int mlx5_init_hca(mlx5_dev_t *dev);
#define MLX5_HCA_CAP_BYTES 256u // 定義根拠は下記フェーズ3セクションのコメント参照

// フェーズ4(下記)の前方宣言。
static int mlx5_alloc_uar(mlx5_dev_t *dev, uint32_t *out_uarn);
static int mlx5_create_eq(mlx5_dev_t *dev, uint32_t uarn, uint32_t *out_eqn);
static int mlx5_alloc_pd(mlx5_dev_t *dev, uint32_t *out_pdn);
static int mlx5_create_mkey_pa(mlx5_dev_t *dev, uint32_t pdn, uint32_t *out_mkey);
static int mlx5_create_cq(mlx5_dev_t *dev, uint32_t uarn, uint32_t eqn, uint64_t buf_addr, uint64_t dbr_addr, uint32_t *out_cqn);
static int mlx5_alloc_transport_domain(mlx5_dev_t *dev, uint32_t *out_tdn);
static int mlx5_create_tis(mlx5_dev_t *dev, uint32_t tdn, uint32_t *out_tisn);
static int mlx5_create_rq(mlx5_dev_t *dev, unsigned rxq_idx, uint32_t cqn, uint32_t pdn, uint32_t uarn, uint32_t mkey, uint32_t *out_rqn);
static int mlx5_modify_rq_to_rdy(mlx5_dev_t *dev, uint32_t rqn);
static int mlx5_create_tir(mlx5_dev_t *dev, uint32_t rqn, uint32_t tdn, uint32_t *out_tirn);
static int mlx5_create_flow_table_nic_rx(mlx5_dev_t *dev, uint32_t *out_table_id);
static int mlx5_set_flow_table_root_nic_rx(mlx5_dev_t *dev, uint32_t table_id);
static int mlx5_create_flow_group_catchall(mlx5_dev_t *dev, uint32_t table_id, uint32_t *out_group_id);
static int mlx5_set_fte_fwd_tir(mlx5_dev_t *dev, uint32_t table_id, uint32_t group_id, uint32_t tirn);
static int mlx5_create_sq(mlx5_dev_t *dev, uint32_t cqn, uint32_t pdn, uint32_t uarn, uint32_t tisn, uint32_t *out_sqn);
static int mlx5_modify_sq_to_rdy(mlx5_dev_t *dev, uint32_t sqn);
static int mlx5_set_port_admin_status_up(mlx5_dev_t *dev);
static int mlx5_query_port_oper_status(mlx5_dev_t *dev, uint8_t *out_oper_status);
static int mlx5_set_port_mtu(mlx5_dev_t *dev, uint16_t desired_mtu, uint16_t *out_applied_mtu);

// フェーズ10(下記)の前方宣言 -- モニタ機能(PPCNT physical port統計
// カウンタ、QUERY_RQ/QUERY_SQ/QUERY_CQによるHW内部状態の直接確認)。
static int mlx5_query_port_status(mlx5_dev_t *dev, uint8_t *out_admin_status, uint8_t *out_oper_status);
static int mlx5_ppcnt_query(mlx5_dev_t *dev, uint8_t grp, uint8_t *counter_set_out);
static void mlx5_dump_ieee802_3(mlx5_dev_t *dev, const char *label);
static void mlx5_dump_phys_layer(mlx5_dev_t *dev, const char *label);
static int mlx5_query_wq_state(mlx5_dev_t *dev, uint16_t opcode, uint32_t objn,
                                uint8_t *out_state, uint32_t *out_hw_counter, uint32_t *out_sw_counter);
static int mlx5_query_cq_state(mlx5_dev_t *dev, uint32_t cqn, uint8_t *out_status, uint8_t *out_st,
                                uint32_t *out_consumer_counter, uint32_t *out_producer_counter);
static void mlx5_monitor_dump_dev(mlx5_dev_t *dev, const char *label);

// initializingビット(bit31)がクリアされるまで待つ。Linux main.cの
// wait_fw_init()は"pre-initializing"(cmdq登録より前)と"initializing"
// (cmdq登録の直後、ENABLE_HCAより前)の2箇所で呼ばれる -- 実機で確認: 2回目
// を省略するとENABLE_HCA自体は成功するのに直後のQUERY_ISSIが
// MLX5_CMD_STAT_BAD_SYS_STATE_ERR(delivery status=0x04)で失敗した。
static int mlx5_wait_fw_init(const mlx5_dev_t *dev, const char *phase) {
    uart_printf("mlx5: waiting for firmware %s...\n", phase);
    uint64_t start = timer_now();
    while (1) {
        uint32_t initializing = mlx5_read32(dev, MLX5_ISEG_INITIALIZING);
        if (!(initializing >> 31)) {
            return 0;
        }
        if (timeout_ms(start, MLX5_FW_INIT_TIMEOUT_MS)) {
            uart_printf("mlx5: firmware %s timed out after %ums (initializing=0x%08x)\n",
                        phase, MLX5_FW_INIT_TIMEOUT_MS, initializing);
            return -1;
        }
    }
}

// 一時的な実験用フラグ(2026-08-13、原因特定後に削除すること)。
// mlx5_hca_bringup()内のcatch-all FTE設定をスキップするかどうか。
int g_mlx5_skip_fte_experiment = 0;

// monitor_only=1: cmdq設定+ENABLE_HCA+capability設定までで止め、INIT_HCA
// (4521ページの巨大なMANAGE_PAGES確保を含む)以降のデータパス資源作成
// (EQ/CQ/RQ/SQ/TIR/フローテーブル/QP)を全てスキップする。HWモニタ
// (温度/エラーカウンタ/PCIe/リンク状態、いずれもACCESS_REGまたはBAR0読み)
// はこの軽量ブリングアップだけで足りる -- 常駐ドライバが無い以上カードと
// 話すには最低限ENABLE_HCA(+cmdq)が必要だが、送受信用の資源までは要らない。
int mlx5_hca_bringup(mlx5_dev_t *dev, const char *label, int monitor_only) {
    uart_printf("mlx5: ===== bringing up %s (bar0_base=0x%08x%08x pf_index=%u) =====\n",
                label, (uint32_t)(dev->bar0_base >> 32), (uint32_t)dev->bar0_base,
                (unsigned)dev->pf_index);
    dev->fw_pages_used = 0;
    // 2026-08-12、nvme_rdma.cの接続再利用機構が「このdevで以前確立した
    // RC QP等がまだ有効か」を判定するのに使う(mlx5.h dev->bringup_
    // generationコメント参照)。成功/失敗を問わずこの関数へ再突入した
    // 時点で以前のFWオブジェクトハンドルは無効になりうるため、無条件に
    // 増やす。
    dev->bringup_generation++;

    /* Phase 2 (x86-vfio-port): QP系CQ(RC QP 1本目/2本目/GSI)の完了確認CQ
     * バッファ+ドアベルを COHERENT DMA アリーナから確保。本関数は net init
     * mlx5 のたびに呼ばれ dev は毎回 {0} クリアされるため、PF ごとに関数内
     * static で初回のみ dma_alloc し以後は再利用して dev へ再設定する
     * (bump アリーナ枯渇を防ぐ、第1段階の RAMディスクと同じ冪等の流儀)。
     * PF 判別は dev->pf_index(0=PF0 / 1=PF1)で行う。 */
    {
        static uintptr_t s_qpcq_buf[2], s_qpcq_dbr[2];
        static uintptr_t s_qp2cq_buf[2], s_qp2cq_dbr[2];
        static uintptr_t s_gsicq_buf[2], s_gsicq_dbr[2];
        /* 段階3: Ethernet(mlx5_net)経路の RQ/SQ CQ + RQ 受信データバッファ。 */
        static uintptr_t s_rqcq_buf[2][MLX5_NUM_RXQ], s_rqcq_dbr[2][MLX5_NUM_RXQ];
        static uintptr_t s_sqcq_buf[2], s_sqcq_dbr[2];
        static uintptr_t s_rqdata[2][MLX5_NUM_RXQ];
        /* 段階4: DEVICE アリーナ(cmdq/mailbox/fw_pages/EQ/各 WQE リング/
         * ドアベル/TX ステージ)。fw_pages が支配的(16MB/PF)。 */
        static uintptr_t s_cmdq[2], s_outmbox[2], s_inmbox[2], s_fwpages[2];
        static uintptr_t s_eqbuf[2];
        static uintptr_t s_rqwqe[2][MLX5_NUM_RXQ], s_rqdbr[2][MLX5_NUM_RXQ], s_sqwqe[2], s_sqdbr[2];
        static uintptr_t s_sqtxframe[2], s_nettxstage[2];
        static uintptr_t s_qpwqe[2], s_qpdbr[2], s_gsiwqe[2], s_gsidbr[2];
        static uintptr_t s_qp2wqe[2], s_qp2dbr[2];
        unsigned pf = dev->pf_index;
        if (s_qpcq_buf[pf] == 0) {
            s_qpcq_buf[pf]  = (uintptr_t)dma_alloc(MLX5_CQ_BUF_SIZE, 4096u, DMA_COHERENT).cpu;
            s_qpcq_dbr[pf]  = (uintptr_t)dma_alloc(MLX5_CQ_DBR_SIZE, 64u,   DMA_COHERENT).cpu;
            s_qp2cq_buf[pf] = (uintptr_t)dma_alloc(MLX5_CQ_BUF_SIZE, 4096u, DMA_COHERENT).cpu;
            s_qp2cq_dbr[pf] = (uintptr_t)dma_alloc(MLX5_CQ_DBR_SIZE, 64u,   DMA_COHERENT).cpu;
            s_gsicq_buf[pf] = (uintptr_t)dma_alloc(MLX5_CQ_BUF_SIZE, 4096u, DMA_COHERENT).cpu;
            s_gsicq_dbr[pf] = (uintptr_t)dma_alloc(MLX5_CQ_DBR_SIZE, 64u,   DMA_COHERENT).cpu;
            /* RQ/SQ の CQ バッファは CREATE_CQ の pas[] 要件で 4096 アライン。
             * RQ 受信データバッファ(512KB)は各 WQE の data_seg.addr で個々の
             * スロットを参照するためページ境界は不要だが、RX headroom(+2)で
             * TCP ペイロードを8整列へ乗せる前提のスロット先頭8整列と、dcache
             * 操作のキャッシュライン境界のため 4096 アラインで確保する
             * (旧 MLX5_RQ_DATA_CACHE_ADDR の PF 領域先頭と同じくページ整列)。 */
            for (unsigned q = 0; q < MLX5_NUM_RXQ; q++) {
                s_rqcq_buf[pf][q] = (uintptr_t)dma_alloc(MLX5_CQ_BUF_SIZE, 4096u, DMA_COHERENT).cpu;
                s_rqcq_dbr[pf][q] = (uintptr_t)dma_alloc(MLX5_CQ_DBR_SIZE, 64u,   DMA_COHERENT).cpu;
                s_rqdata[pf][q]   = (uintptr_t)dma_alloc(MLX5_RQ_DATA_SIZE, 4096u, DMA_COHERENT).cpu;
                s_rqwqe[pf][q]    = (uintptr_t)dma_alloc(MLX5_RQ_WQE_SIZE, 4096u, DMA_DEVICE).cpu;
                s_rqdbr[pf][q]    = (uintptr_t)dma_alloc(MLX5_RQ_DBR_SIZE, 64u,   DMA_DEVICE).cpu;
            }
            s_sqcq_buf[pf] = (uintptr_t)dma_alloc(MLX5_SQ_CQ_BUF_SIZE, 4096u, DMA_COHERENT).cpu;
            s_sqcq_dbr[pf] = (uintptr_t)dma_alloc(MLX5_SQ_CQ_DBR_SIZE, 64u,   DMA_COHERENT).cpu;
            /* 段階4: DEVICE アリーナ。cmdq/EQ/各 WQE リングは 4096 アライン
             * (ISEG/CREATE_EQ/CREATE_{RQ,SQ,QP} の pas[] 要件)、mailbox は
             * 1024 アライン(各ブロック単独で 1024 境界、roundup_pow_of_two(576)
             * =1024、CLAUDE.md 参照)、fw_pages は 4096 アライン。ドアベル/TX
             * フレーム/TX ステージは 64 アライン(TX ステージのスロット先頭は
             * MLX5_NET_TX_STAGE_SIZE=10240 が 64/8 の倍数のため 64 で足りる)。 */
            s_cmdq[pf]       = (uintptr_t)dma_alloc(4096u,                                4096u, DMA_DEVICE).cpu;
            s_outmbox[pf]    = (uintptr_t)dma_alloc(MLX5_CMD_MBOX_CHAIN_BLOCKS * MLX5_CMD_MBOX_ALIGN, MLX5_CMD_MBOX_ALIGN, DMA_DEVICE).cpu;
            s_inmbox[pf]     = (uintptr_t)dma_alloc(MLX5_CMD_MBOX_CHAIN_BLOCKS * MLX5_CMD_MBOX_ALIGN, MLX5_CMD_MBOX_ALIGN, DMA_DEVICE).cpu;
            s_fwpages[pf]    = (uintptr_t)dma_alloc((uint64_t)MLX5_MAX_FW_PAGES * MLX5_FW_PAGE_SIZE, 4096u, DMA_DEVICE).cpu;
            s_eqbuf[pf]      = (uintptr_t)dma_alloc(MLX5_EQ_BUF_SIZE,                     4096u, DMA_DEVICE).cpu;
            s_sqwqe[pf]      = (uintptr_t)dma_alloc(MLX5_SQ_WQE_SIZE,                     4096u, DMA_DEVICE).cpu;
            s_sqdbr[pf]      = (uintptr_t)dma_alloc(MLX5_SQ_DBR_SIZE,                     64u,   DMA_DEVICE).cpu;
            s_sqtxframe[pf]  = (uintptr_t)dma_alloc(MLX5_SQ_TX_FRAME_SIZE,                64u,   DMA_DEVICE).cpu;
            s_nettxstage[pf] = (uintptr_t)dma_alloc(MLX5_NET_TX_STAGE_TOTAL_SIZE,         64u,   DMA_DEVICE).cpu;
            s_qpwqe[pf]      = (uintptr_t)dma_alloc(MLX5_QP_WQE_BUF_SIZE,                 4096u, DMA_DEVICE).cpu;
            s_qpdbr[pf]      = (uintptr_t)dma_alloc(MLX5_QP_DBR_SIZE,                     64u,   DMA_DEVICE).cpu;
            s_gsiwqe[pf]     = (uintptr_t)dma_alloc(MLX5_GSI_WQE_BUF_SIZE,                4096u, DMA_DEVICE).cpu;
            s_gsidbr[pf]     = (uintptr_t)dma_alloc(MLX5_GSI_DBR_SIZE,                    64u,   DMA_DEVICE).cpu;
            s_qp2wqe[pf]     = (uintptr_t)dma_alloc(MLX5_QP_WQE_BUF_SIZE,                 4096u, DMA_DEVICE).cpu;
            s_qp2dbr[pf]     = (uintptr_t)dma_alloc(MLX5_QP_DBR_SIZE,                     64u,   DMA_DEVICE).cpu;
        }
        dev->qp_cq_buf_cpu  = s_qpcq_buf[pf];
        dev->qp_cq_dbr_cpu  = s_qpcq_dbr[pf];
        dev->qp2_cq_buf_cpu = s_qp2cq_buf[pf];
        dev->qp2_cq_dbr_cpu = s_qp2cq_dbr[pf];
        dev->gsi_cq_buf_cpu = s_gsicq_buf[pf];
        dev->gsi_cq_dbr_cpu = s_gsicq_dbr[pf];
        for (unsigned q = 0; q < MLX5_NUM_RXQ; q++) {
            dev->rxq[q].cq_buf_cpu = s_rqcq_buf[pf][q];
            dev->rxq[q].cq_dbr_cpu = s_rqcq_dbr[pf][q];
            dev->rxq[q].data_cpu   = s_rqdata[pf][q];
            dev->rxq[q].wqe_cpu    = s_rqwqe[pf][q];
            dev->rxq[q].dbr_cpu    = s_rqdbr[pf][q];
        }
        dev->sq_cq_buf_cpu  = s_sqcq_buf[pf];
        dev->sq_cq_dbr_cpu  = s_sqcq_dbr[pf];
        dev->cmdq_cpu        = s_cmdq[pf];
        dev->out_mbox_cpu    = s_outmbox[pf];
        dev->in_mbox_cpu     = s_inmbox[pf];
        dev->fw_pages_cpu    = s_fwpages[pf];
        dev->eq_buf_cpu      = s_eqbuf[pf];
        dev->sq_wqe_cpu      = s_sqwqe[pf];
        dev->sq_dbr_cpu      = s_sqdbr[pf];
        dev->sq_tx_frame_cpu = s_sqtxframe[pf];
        dev->net_tx_stage_cpu = s_nettxstage[pf];
        dev->qp_wqe_cpu      = s_qpwqe[pf];
        dev->qp_dbr_cpu      = s_qpdbr[pf];
        dev->gsi_wqe_cpu     = s_gsiwqe[pf];
        dev->gsi_dbr_cpu     = s_gsidbr[pf];
        dev->qp2_wqe_cpu     = s_qp2wqe[pf];
        dev->qp2_dbr_cpu     = s_qp2dbr[pf];
    }

    uint32_t fw_rev = mlx5_read32(dev, MLX5_ISEG_FW_REV);
    uint32_t cmdif_rev_fw_sub = mlx5_read32(dev, MLX5_ISEG_CMDIF_REV_FW_SUB);
    uint32_t cmdif_rev = cmdif_rev_fw_sub >> 16;

    uart_printf("mlx5: fw_rev=0x%08x cmdif_rev=%u (driver expects %u)\n",
                fw_rev, cmdif_rev, (unsigned)MLX5_CMD_IF_REV);

    if (fw_rev == 0xffffffffu) {
        uart_printf("mlx5: init segment read back all-1s -- BAR0 not accessible, aborting\n");
        return -1;
    }

    if (cmdif_rev != MLX5_CMD_IF_REV) {
        uart_printf("mlx5: unexpected cmdif_rev, aborting (structures/opcodes below assume rev %u)\n",
                    (unsigned)MLX5_CMD_IF_REV);
        return -1;
    }

    if (mlx5_wait_fw_init(dev, "pre-initializing") != 0) {
        return -1;
    }

    if (mlx5_cmdq_init(dev) != 0) {
        return -1;
    }

    if (mlx5_enable_hca(dev) != 0) {
        uart_printf("mlx5: ENABLE_HCA failed\n");
        return -1;
    }
    uart_printf("mlx5: ENABLE_HCA ok\n");

    uint16_t current_issi = 0;
    uint32_t supported_issi_dw0 = 0;
    if (mlx5_query_issi(dev, &current_issi, &supported_issi_dw0) != 0) {
        return -1;
    }
    uart_printf("mlx5: QUERY_ISSI: current_issi=%u supported_issi_dw0=0x%08x\n",
                current_issi, supported_issi_dw0);

    // Linux mlx5_core main.c の mlx5_core_set_issi() と同じ判断: bit1が
    // 立っていればISSI 1をサポートしているのでそちらへ切り替える
    // (bit0のみ/何もサポート報告が無い場合はISSI 0のまま、SET_ISSI自体
    // 呼ばない)。
    if (supported_issi_dw0 & (1u << 1)) {
        if (mlx5_set_issi(dev, 1) != 0) {
            uart_printf("mlx5: SET_ISSI(1) failed\n");
            return -1;
        }
        uart_printf("mlx5: SET_ISSI(1) ok\n");

        // 実機での切り替わり確認のため再度QUERY_ISSIで読み直す(Linux
        // ドライバはここまでしないが、このプロジェクトの一貫した方法論
        // 「変更のたびに実測で裏取りする」に合わせて確認しておく)。
        uint16_t verify_issi = 0;
        if (mlx5_query_issi(dev, &verify_issi, NULL) == 0) {
            uart_printf("mlx5: post-SET_ISSI current_issi=%u (expected 1)\n", verify_issi);
        }
    } else {
        uart_printf("mlx5: ISSI 1 not supported (supported_issi_dw0=0x%08x), staying at ISSI 0\n",
                    supported_issi_dw0);
    }

    uint16_t func_id = 0;
    int32_t num_boot_pages = 0;
    if (mlx5_query_pages(dev, MLX5_QUERY_PAGES_OP_MOD_BOOT_PAGES, &func_id, &num_boot_pages) != 0) {
        return -1;
    }
    uart_printf("mlx5: QUERY_PAGES(boot): function_id=%u num_pages=%d\n", func_id, num_boot_pages);

    if (mlx5_manage_pages_give(dev, func_id, num_boot_pages) != 0) {
        uart_printf("mlx5: MANAGE_PAGES(GIVE, boot) failed\n");
        return -1;
    }
    uart_printf("mlx5: MANAGE_PAGES(GIVE, boot): gave %d pages ok\n", num_boot_pages);

    // フェーズ3: HCA capability 設定 -> INIT_HCA。Linux main.cの
    // mlx5_function_open()の順序(set_hca_cap() -> satisfy_startup_pages
    // (init pages) -> mlx5_cmd_init_hca())をそのまま踏襲する。SET_HCA_CAP
    // は本来多数の任意機能ビットを個別に立てる(handle_hca_cap_atomic/odp/
    // roce等)が、それらはこのプロジェクトのスコープ外の機能なので、
    // 「QUERY_HCA_CAP(cur)で読んだ値をそのままSET_HCA_CAPへ送り返す」
    // 最小実装にとどめる -- 個々のフィールドを独自に組み立てるより、FWが
    // 既に「現在有効」として報告した値をそのまま追認する方が安全。
    uint8_t hca_cap[MLX5_HCA_CAP_BYTES];
    if (mlx5_query_hca_cap_general(dev, hca_cap) != 0) {
        return -1;
    }
    uart_printf("mlx5: QUERY_HCA_CAP(general, cur) ok\n");
    uart_printf("mlx5: num_ports=%u lag_master=%u num_lag_ports=%u\n",
                hca_cap[55], (uint8_t)((hca_cap[79] >> 4) & 0x1u), (uint8_t)(hca_cap[79] & 0xFu));

    // 2026-08-09、MTXC/MRXF待ちのHW-domain切り分け(方針1、CLAUDE.md
    // 「MTXC/MRXF待ち改善の検討方針」節参照)。device_frequency_khzは
    // cmd_hca_cap_bits先頭からのバイトオフセット156(mlx5.hのclock_khz
    // コメント参照)。実機で実際に妥当な非ゼロ値が返るかはまだ未確認
    // -- ここで生の値をログ出力し、憶測で使わないことを徹底する。
    dev->clock_khz = ((uint32_t)hca_cap[156] << 24) | ((uint32_t)hca_cap[157] << 16) |
                      ((uint32_t)hca_cap[158] << 8) | (uint32_t)hca_cap[159];
    uart_printf("mlx5: device_frequency_khz=%u\n", dev->clock_khz);

    // 2026-08-12、RDMA_READパイプライン化調査: RC QPのlog_rra_max/
    // log_sra_max(RTR2RTS_QPで指定するRDMA読み出し同時実行数)がFWの
    // 実際のHCA capability(log_max_ra_req_qp/log_max_ra_res_qp、cmd_hca_
    // cap_bits絶対bitオフセット0x14a/0x156、mlx5_ifc.hから実際に取得し
    // 手計算で裏取り済み)を超えていないか確認するため、生の値を毎回
    // 表示する(推測しない、このプロジェクト一貫の方法論)。
    dev->log_max_ra_req_qp = hca_cap[41] & 0x3Fu;
    dev->log_max_ra_res_qp = (uint8_t)(((hca_cap[42] & 0x03u) << 4) | ((hca_cap[43] & 0xF0u) >> 4));
    uart_printf("mlx5: log_max_ra_req_qp=%u (max=%u) log_max_ra_res_qp=%u (max=%u)\n",
                dev->log_max_ra_req_qp, 1u << dev->log_max_ra_req_qp,
                dev->log_max_ra_res_qp, 1u << dev->log_max_ra_res_qp);

    if (mlx5_set_hca_cap_general(dev, hca_cap) != 0) {
        uart_printf("mlx5: SET_HCA_CAP(general) failed\n");
        return -1;
    }
    uart_printf("mlx5: SET_HCA_CAP(general) ok\n");

    // 2026-08-10、LSO対応。失敗しても致命的ではない(単にLSO非対応として
    // 扱う、CLAUDE.md方針通りブリングアップ全体を止めない) -- dev-
    // >max_lso_bytesは呼び出し失敗時も0のまま(mlx5_query_hca_cap_eth_
    // offloads()冒頭で先に0初期化している)。
    if (mlx5_query_hca_cap_eth_offloads(dev, &dev->max_lso_bytes) != 0) {
        uart_printf("mlx5: QUERY_HCA_CAP(eth_offloads) failed -- LSO disabled\n");
        dev->max_lso_bytes = 0u;
    } else {
        uart_printf("mlx5: ETHERNET_OFFLOADS max_lso_cap -> max_lso_bytes=%u\n",
                    dev->max_lso_bytes);
    }

    uint16_t init_func_id = 0;
    int32_t num_init_pages = 0;
    if (mlx5_query_pages(dev, MLX5_QUERY_PAGES_OP_MOD_INIT_PAGES, &init_func_id, &num_init_pages) != 0) {
        return -1;
    }
    uart_printf("mlx5: QUERY_PAGES(init): function_id=%u num_pages=%d\n", init_func_id, num_init_pages);

    if (mlx5_manage_pages_give(dev, init_func_id, num_init_pages) != 0) {
        uart_printf("mlx5: MANAGE_PAGES(GIVE, init) failed\n");
        return -1;
    }
    uart_printf("mlx5: MANAGE_PAGES(GIVE, init): gave %d pages ok\n", num_init_pages);

    if (mlx5_init_hca(dev) != 0) {
        uart_printf("mlx5: INIT_HCA failed\n");
        return -1;
    }
    uart_printf("mlx5: INIT_HCA ok\n");

    // HWモニタ用の軽量ブリングアップはここで打ち切る。ACCESS_REG(MTMP温度/
    // PPCNT/MPCNT/PAOS)はINIT_HCA後でないと応答しない(実測: INIT_HCA前だと
    // 温度=0/oper=DOWN)ため、INIT_HCAまでは行う。ただし送受信用のデータパス
    // 資源(UAR/EQ/PD/CQ/RQ/TIR/フローテーブル/SQ)は不要なので全てスキップする。
    // リンク状態を意味あるものにするため、ポートのadmin UPだけは設定して
    // oper_statusを短時間(最大1秒)ポーリングする(PMTU等の細かい設定は省略)。
    if (monitor_only) {
        (void)mlx5_set_port_admin_status_up(dev);
        uint64_t st = timer_now();
        uint8_t oper = 0xFFu;
        while (!timeout_ms(st, 1000u)) {
            if (mlx5_query_port_oper_status(dev, &oper) == 0 && oper == 1u) break;
        }
        uart_printf("mlx5: (monitor-only) データパス資源(EQ/CQ/RQ/SQ/TIR/flow)作成をスキップ\n");
        return 0;
    }

    // フェーズ4: UAR割り当て -> EQ作成。CREATE_CQ(次フェーズ以降)の
    // 必須フィールドc_eqn_or_apu_element(mlx5_ifc.hのstruct
    // mlx5_ifc_cqc_bits参照)が有効なEQ番号を要求するため、CQを作る前に
    // 最低1つのEQが要る。このプロジェクトは全コマンドをポーリングで待つ
    // 方針(ユーザー指示、CLAUDE.md「ConnectX(mlx5) HCA初期化」節参照)の
    // ため、実際にMSI-X割り込みを配送させる仕組みは作らない -- このEQは
    // CREATE_CQの要件を満たすためだけの最小限のダミーとして存在する。
    uint32_t uarn = 0;
    if (mlx5_alloc_uar(dev, &uarn) != 0) {
        uart_printf("mlx5: ALLOC_UAR failed\n");
        return -1;
    }
    uart_printf("mlx5: ALLOC_UAR ok: uarn=%u\n", uarn);

    uint32_t eqn = 0;
    if (mlx5_create_eq(dev, uarn, &eqn) != 0) {
        uart_printf("mlx5: CREATE_EQ failed\n");
        return -1;
    }
    uart_printf("mlx5: CREATE_EQ ok: eqn=%u\n", eqn);

    // PD(Protection Domain)割り当て -> PA(physical address)モードの
    // MKey作成。QP/SQ/RQ等が実データを送受信するにはメモリ保護の単位
    // (PD)とHCAにDMAアクセスを許可するキー(MKey)が要る。今回はLinux
    // ib_umem/MTTのような細かいメモリ登録は行わず、`mlx5_ib_get_dma_mr()`
    // と同じ「PAモード、start_addr=0、length64=1」の単一MKeyで物理アドレス
    // 空間全体への直接アクセスを許可する最小実装にした(下記
    // mlx5_create_mkey_pa()のコメント参照)。
    uint32_t pdn = 0;
    if (mlx5_alloc_pd(dev, &pdn) != 0) {
        uart_printf("mlx5: ALLOC_PD failed\n");
        return -1;
    }
    uart_printf("mlx5: ALLOC_PD ok: pdn=%u\n", pdn);

    uint32_t mkey = 0;
    if (mlx5_create_mkey_pa(dev, pdn, &mkey) != 0) {
        uart_printf("mlx5: CREATE_MKEY failed\n");
        return -1;
    }
    uart_printf("mlx5: CREATE_MKEY ok: mkey=0x%08x\n", mkey);

    // CQ(Completion Queue)作成。上記で作ったuarn(ドアベル用UARページ)と
    // eqn(このCQの完了イベントを受け取るEQ番号 -- CLAUDE.md「ConnectX(mlx5)
    // HCA初期化」節の通り、実際には配送を受けずポーリングする方針だが
    // c_eqn_or_apu_elementフィールドは有効なEQ番号を要求するため必須)を
    // 渡す。
    // Transport Domain割り当て -> TIS(Transport Interface Send)作成(送信用、
    // 単一)。Linux en_common.cのmlx5e_create_mdev_resources()/create_tis()と
    // 同じ順序 -- TISはtransport_domainフィールドにtdnを要求する。
    uint32_t tdn = 0;
    if (mlx5_alloc_transport_domain(dev, &tdn) != 0) {
        uart_printf("mlx5: ALLOC_TRANSPORT_DOMAIN failed\n");
        return -1;
    }
    uart_printf("mlx5: ALLOC_TRANSPORT_DOMAIN ok: tdn=%u\n", tdn);

    uint32_t tisn = 0;
    if (mlx5_create_tis(dev, tdn, &tisn) != 0) {
        uart_printf("mlx5: CREATE_TIS failed\n");
        return -1;
    }
    uart_printf("mlx5: CREATE_TIS ok: tisn=%u\n", tisn);

    // RXキューを MLX5_NUM_RXQ 本作成(各: CQ->RQ->RDY->TIR)。マルチコネクション
    // で接続ごとにフローステアリングで担当RQへ振り分け、担当コアが専任
    // ポーリングする(受信並列化)。各RQは専用のCQ・受信データ/WQEリング・
    // ドアベル(dev->rxq[q]、DMA確保済み)を持つ。
    for (unsigned q = 0; q < MLX5_NUM_RXQ; q++) {
        uint32_t cqn = 0;
        if (mlx5_create_cq(dev, uarn, eqn,
                           (uint64_t)dev->rxq[q].cq_buf_cpu, (uint64_t)dev->rxq[q].cq_dbr_cpu, &cqn) != 0) {
            uart_printf("mlx5: CREATE_CQ[%u] failed\n", q);
            return -1;
        }
        dev->rxq[q].cqn = cqn;

        uint32_t rqn = 0;
        if (mlx5_create_rq(dev, q, cqn, pdn, uarn, mkey, &rqn) != 0) {
            uart_printf("mlx5: CREATE_RQ[%u] failed\n", q);
            return -1;
        }
        dev->rxq[q].rqn = rqn;

        if (mlx5_modify_rq_to_rdy(dev, rqn) != 0) {
            uart_printf("mlx5: MODIFY_RQ[%u](RST->RDY) failed\n", q);
            return -1;
        }

        uint32_t tirn = 0;
        if (mlx5_create_tir(dev, rqn, tdn, &tirn) != 0) {
            uart_printf("mlx5: CREATE_TIR[%u] failed\n", q);
            return -1;
        }
        dev->rxq[q].tirn = tirn;
        uart_printf("mlx5: RXQ[%u] ok: cqn=%u rqn=%u tirn=%u\n", q, cqn, rqn, tirn);
    }

    // フローステアリング: NIC RX用フローテーブルを作成してrootに設定し、
    // 「全パケットをこのTIRへ転送する」単一ルール(catch-all、宛先MAC等の
    // 条件は一切見ない)を追加する。これが無いとConnectXはこれまで作った
    // RQ/TIRへ実際のフレームを一切届けない(TIR作成だけではフレームの
    // 経路が決まらない)。
    uint32_t table_id = 0;
    if (mlx5_create_flow_table_nic_rx(dev, &table_id) != 0) {
        uart_printf("mlx5: CREATE_FLOW_TABLE failed\n");
        return -1;
    }
    uart_printf("mlx5: CREATE_FLOW_TABLE ok: table_id=%u\n", table_id);

    if (mlx5_set_flow_table_root_nic_rx(dev, table_id) != 0) {
        uart_printf("mlx5: SET_FLOW_TABLE_ROOT failed\n");
        return -1;
    }
    uart_printf("mlx5: SET_FLOW_TABLE_ROOT ok\n");

    uint32_t group_id = 0;
    if (mlx5_create_flow_group_catchall(dev, table_id, &group_id) != 0) {
        uart_printf("mlx5: CREATE_FLOW_GROUP failed\n");
        return -1;
    }
    uart_printf("mlx5: CREATE_FLOW_GROUP ok: group_id=%u\n", group_id);

    // 一時的な実験(2026-08-13、フェーズ(i)実Linuxホスト接続確認): このFTE
    // (catch-all、宛先を一切見ずに全パケットをTIRへ転送)が、RC QP宛の
    // RoCEv2フレームまで飲み込み、verbs QPのRQへ一切届かなくしている
    // (「[IP]未対応プロトコル」ログがverbs QP作成前から出ていた実機観測)
    // という仮説を検証するため、FTE自体の設定を無条件でスキップする。
    // これによりEthernet受信(ping/arp含む)は機能しなくなるが、RC QP受信が
    // 改善するかどうかで仮説の真偽を切り分けられる。原因特定後に元に戻す。
    if (g_mlx5_skip_fte_experiment) {
        uart_printf("mlx5: SET_FLOW_TABLE_ENTRY SKIPPED (experiment: g_mlx5_skip_fte_experiment=1)\n");
    } else if (mlx5_set_fte_fwd_tir(dev, table_id, group_id, dev->rxq[0].tirn) != 0) {
        uart_printf("mlx5: SET_FLOW_TABLE_ENTRY failed\n");
        return -1;
    } else {
        // Stage2: catch-all は rxq[0] へ。rxq[1..] は作成済みだが、per-port
        // フローステアリング(Stage3)を入れるまでフレームは届かない(idle)。
        uart_printf("mlx5: SET_FLOW_TABLE_ENTRY ok (catch-all -> rxq[0].tirn=%u)\n", dev->rxq[0].tirn);
    }

    // SQ(Send Queue)作成。TX完了確認用にRQとは別の専用CQを用意する
    // (mlx5_create_cq()コメント参照)。
    uint32_t sq_cqn = 0;
    if (mlx5_create_cq(dev, uarn, eqn, (uint64_t)dev->sq_cq_buf_cpu, (uint64_t)dev->sq_cq_dbr_cpu, &sq_cqn) != 0) {
        uart_printf("mlx5: CREATE_CQ(SQ) failed\n");
        return -1;
    }
    uart_printf("mlx5: CREATE_CQ(SQ) ok: cqn=%u\n", sq_cqn);

    uint32_t sqn = 0;
    if (mlx5_create_sq(dev, sq_cqn, pdn, uarn, tisn, &sqn) != 0) {
        uart_printf("mlx5: CREATE_SQ failed\n");
        return -1;
    }
    uart_printf("mlx5: CREATE_SQ ok: sqn=%u\n", sqn);

    if (mlx5_modify_sq_to_rdy(dev, sqn) != 0) {
        uart_printf("mlx5: MODIFY_SQ(RST->RDY) failed\n");
        return -1;
    }
    uart_printf("mlx5: MODIFY_SQ(RST->RDY) ok\n");

    // ジャンボフレーム対応(2026-08-09): mlx5_net.cのRQ/TXバッファを
    // MLX5_JUMBO_MAX_LEN(mlx5.h)へ拡張したのに合わせ、ポート自体の
    // 最大フレーム長もPMTUレジスタで引き上げる(mlx5_set_port_mtu()
    // コメント参照)。失敗しても致命的ではない(標準MTUのままリンクは
    // 使える)ため、ログのみでbringup自体は継続する -- ただしdev->
    // port_mtuは必ず何らかの安全な値で埋める(mlx5_net.cがmss_capの
    // 逆算に使うため、未設定[0]のままだと下流でMSS=0という壊れた値に
    // なりかねない)。標準Ethernet(非ジャンボ)相当の1518へフォール
    // バックする。
    {
        uint16_t applied_mtu = 1518u;
        if (mlx5_set_port_mtu(dev, (uint16_t)MLX5_JUMBO_MAX_LEN, &applied_mtu) != 0) {
            uart_printf("mlx5: PMTU(set admin_mtu) failed -- ジャンボフレーム無しで継続します\n");
            applied_mtu = 1518u;
        }
        dev->port_mtu = applied_mtu;
    }

    if (mlx5_set_port_admin_status_up(dev) != 0) {
        uart_printf("mlx5: PAOS(set admin UP) failed\n");
        return -1;
    }
    uart_printf("mlx5: PAOS(set admin UP) ok\n");

    // PHYの自動ネゴシエーション完了を待つ(admin UPを設定した直後は
    // oper_statusがまだDOWNのままの可能性がある -- 最大3秒ポーリング)。
    {
        uint64_t start = timer_now();
        uint8_t oper_status = 0xFFu;
        while (1) {
            if (mlx5_query_port_oper_status(dev, &oper_status) == 0 && oper_status == 1u) {
                break;
            }
            if (timeout_ms(start, 3000u)) {
                break;
            }
        }
        uart_printf("mlx5: PAOS oper_status=%u (1=UP)\n", oper_status);
    }

    dev->uarn = uarn;
    dev->eqn = eqn;
    dev->pdn = pdn;
    dev->mkey = mkey;
    // dev->rxq[q].{cqn,rqn,tirn} は上記のRXキュー生成ループで設定済み。
    dev->tdn = tdn;
    dev->tisn = tisn;
    dev->sq_cqn = sq_cqn;
    dev->sqn = sqn;

    uart_printf("mlx5: ===== %s bringup complete =====\n", label);
    return 0;
}

// mlx5_dual_port_bringup_and_test()が最後に初期化したPF0/PF1のハンドルを
// 保持する(mlx5_monitor_dump_saved()/`mlx5stat`シェルコマンドが、
// ENABLE_HCA等の非冪等なコマンド列を再実行せずにいつでも内部レジスタを
// 再クエリできるようにするため、CLAUDE.md「ConnectXデュアルポート対応」
// 節の「早期フェーズの非冪等性」を踏まえた設計)。
static mlx5_dev_t s_last_dev0;
static mlx5_dev_t s_last_dev1;
static int s_last_devs_valid = 0;

// mlx5_net.c(TCP/IPスタック統合バックエンド)がbringupしたPF0/PF1も
// `mlx5stat`から再クエリできるよう、保存先を外部から更新できるように
// する(以前はmlx5_dual_port_bringup_and_test()専用だった)。
void mlx5_monitor_set_devs(const mlx5_dev_t *dev0, const mlx5_dev_t *dev1)
{
    s_last_dev0 = *dev0;
    s_last_dev1 = *dev1;
    s_last_devs_valid = 1;
}

// ============================================================================
// フェーズ2: コマンドキュー(cmdq)の構築と最初の実コマンド発行(QUERY_ISSI)。
//
// レイアウト・定数はfw_rev/cmdif_rev同様、推測せずLinux mlx5_core
// (`include/linux/mlx5/device.h` の struct mlx5_cmd_layout/mlx5_cmd_prot_block、
// `drivers/net/ethernet/mellanox/mlx5/core/cmd.c` の cmd_work_handler()/
// mlx5_cmd_enable()/mlx5_copy_from_msg()、`include/linux/mlx5/mlx5_ifc.h` の
// MLX5_CMD_OP_QUERY_ISSI/struct mlx5_ifc_query_issi_{in,out}_bits)から取得。
// ============================================================================

// mlx5_dma_addr()/MLX5_DMA_ADDR_HI32はmlx5.hへ移した(mlx5_net.cも
// 同じ変換が必要なため -- 詳細なコメントはmlx5.h参照)。

// コマンドキューエントリ(64バイト、device.hのstruct mlx5_cmd_layout)。
// 全フィールドがビッグエンディアン。
typedef struct {
    uint8_t  type;
    uint8_t  rsvd0[3];
    uint32_t inlen;
    uint64_t in_ptr;
    uint32_t in[4];
    uint32_t out[4];
    uint64_t out_ptr;
    uint32_t outlen;
    uint8_t  token;
    uint8_t  sig;
    uint8_t  rsvd1;
    uint8_t  status_own;
} __attribute__((packed)) mlx5_cmd_layout_t;
_Static_assert(sizeof(mlx5_cmd_layout_t) == 64, "mlx5_cmd_layout_t must be 64 bytes");

// メールボックスブロック(576バイト、device.hのstruct mlx5_cmd_prot_block)。
// 16バイトを超える入力/出力の続きを運ぶ。`next`(64bit BE、次ブロックの
// DMAアドレス)/`block_num`(32bit BE、0始まりの連番)でチェインする
// (CREATE_FLOW_GROUP等、512バイトを大きく超える固定長フィールドを持つ
// コマンド向け、下記MLX5_CMD_MBOX_CHAIN_MAX参照)。
typedef struct {
    uint8_t  data[512];
    uint8_t  rsvd0[48];
    uint64_t next;
    uint32_t block_num;
    uint8_t  rsvd1;
    uint8_t  token;
    uint8_t  ctrl_sig;
    uint8_t  sig;
} __attribute__((packed)) mlx5_cmd_prot_block_t;
_Static_assert(sizeof(mlx5_cmd_prot_block_t) == 576, "mlx5_cmd_prot_block_t must be 576 bytes");

#define MLX5_CMD_OWNER_HW    0x1u  // status_ownのオーナービット(1=FW所有、driver.hのCMD_OWNER_HW)
#define MLX5_PCI_CMD_XPORT   7u    // device.hのMLX5_PCI_CMD_XPORT(lay->typeの固定値)
#define MLX5_CMD_MAILBOX_MAX (16u + 512u) // lay->in/out(16B) + メールボックス1個(512B) -- 単一ブロックで足りる小さいコマンド用
#define MLX5_CMD_MBOX_CHAIN_MAX (16u + MLX5_CMD_MBOX_CHAIN_BLOCKS * 512u) // 16B + 複数ブロック(mlx5.h参照) -- mlx5_cmd_exec()自体の上限

// このプロジェクトは同時に1コマンドしか発行しない(ポーリング専用、割り込み
// 無し)ため、コマンドキューは常にentry 0だけを使う。FWが報告する
// log_sz/log_strideに関わらずentry 0のアドレスは常にキュー先頭 -- 複数
// コマンドの同時発行(Linuxのセマフォベースのslot割り当て)は今回のスコープ外。
//
// DMAバッファは通常のstatic配列(section(".dma_bss")+aligned()属性でリンカに
// 配置を委ねる方式)ではなく、mlx5.hで固定した物理アドレスへのポインタ
// キャストでアクセスする -- 以前は前者の方式で、s_in_mboxが1024バイト境界を
// 満たさず実機でMLX5_CMD_DELIVERY_STAT_IN_PTR_ALIGN_ERRを引いた(直前の
// シンボルのサイズにアドレスが左右される、CLAUDE.md「ConnectX(mlx5) HCA
// 初期化」節参照)。C変数として確保しない(=どの.dma_bssパッキングにも
// 一切依存しない)ことで、このクラスのバグを構造的に排除する。
// devをS_CMDQ(dev)のように渡す(デュアルポート対応、CLAUDE.md「ConnectX
// デュアルポート対応」節参照)。
/* Phase 2 段階4: DEVICE アリーナから確保した cmdq/mailbox の CPU アドレス
 * (dev フィールド)を使う。mailbox はチェイン先頭 + i*MLX5_CMD_MBOX_ALIGN。 */
#define S_CMDQ(dev)        ((volatile uint8_t *)(uintptr_t)(dev)->cmdq_cpu)
#define S_OUT_MBOX(dev, i) ((volatile mlx5_cmd_prot_block_t *)(uintptr_t)((dev)->out_mbox_cpu + (uint64_t)(i) * MLX5_CMD_MBOX_ALIGN))
#define S_IN_MBOX(dev, i)  ((volatile mlx5_cmd_prot_block_t *)(uintptr_t)((dev)->in_mbox_cpu + (uint64_t)(i) * MLX5_CMD_MBOX_ALIGN))

// アライメント/重複チェックはbase=0で評価する(mlx5.hの該当コメント参照
// -- baseが4096アラインである限りオフセットのみで結果が決まるため、
// 0での検証は実際のPF0/PF1どちらのdma_baseに対しても有効)。

// FWへMANAGE_PAGES(GIVE)で譲渡するスクラッチページ(4KB単位、FWが内部用途で
// DMA読み書きする、中身は driver からは不透明)。実機のQUERY_PAGES(boot)は
// 6ページを要求した(2026-08-01確認) -- MLX5_MAX_FW_PAGES=32(mlx5.h)で
// 余裕を持たせてある。1回のMANAGE_PAGES呼び出しはメールボックス1個
// (512B/8B=64エントリ)までしか対応していないため、要求が64ページを
// 超えたら現状エラーにする(超える場合の複数メールボックスチェインは
// 今回のスコープ外)。
static inline volatile uint8_t *mlx5_fw_page(const mlx5_dev_t *dev, uint32_t idx) {
    /* Phase 2 段階4: DEVICE アリーナから確保した fw_pages 先頭 + idx*4096。 */
    return (volatile uint8_t *)(uintptr_t)((uint64_t)dev->fw_pages_cpu + (uint64_t)idx * MLX5_FW_PAGE_SIZE);
}

#define MLX5_CMD_TIMEOUT_MS 2000u

// コマンドキューをFWへ登録する(cmdif_rev確認済み・initializing完了後に
// 一度呼ぶ。同じセッション内で複数回呼んでも冪等 -- FWへ現在のキュー
// アドレスを再度教えるだけ)。
static int mlx5_cmdq_init(mlx5_dev_t *dev) {
    uint32_t cmd_l = mlx5_read32(dev, MLX5_ISEG_CMDQ_ADDR_L_SZ) & 0xffu;
    uint32_t log_sz = (cmd_l >> 4) & 0xfu;
    uint32_t log_stride = cmd_l & 0xfu;
    uart_printf("mlx5: cmdq log_sz=%u (%u entries) log_stride=%u (%u bytes/entry)\n",
                log_sz, 1u << log_sz, log_stride, 1u << log_stride);

    if (log_stride != 6u) {
        // mlx5_cmd_layout_tは64バイト固定なので、FWが違うストライドを
        // 報告してきた場合entry 0以外のオフセット計算が崩れる -- ただし
        // entry 0自体は常にキュー先頭(オフセット0)なので、このプロジェクト
        // (常にentry 0のみ使用)への実害は無い。念のため警告だけ出す。
        uart_printf("mlx5: warning: unexpected log_stride=%u (expected 6=64bytes) -- "
                    "entry 0 still usable, but this struct assumes 64-byte stride\n",
                    log_stride);
    }
    if ((1u << log_sz) < 1u) {
        uart_printf("mlx5: cmdq size looks invalid, aborting\n");
        return -1;
    }

    uint64_t cmdq_dma = mlx5_dma_addr(S_CMDQ(dev));
    mlx5_write32(dev, MLX5_ISEG_CMDQ_ADDR_H, (uint32_t)(cmdq_dma >> 32));
    mlx5_write32(dev, MLX5_ISEG_CMDQ_ADDR_L_SZ, (uint32_t)cmdq_dma);
    // Linux cmd.cのmlx5_cmd_enable()と同じ理由のメモリバリア: FWが完全な
    // アドレスを見る前に後続の処理(ドアベル等)が進んでしまわないように。
    dma_wmb();

    // 実機で発見した本物のバグ: cmdq登録直後に間を置かず最初のコマンドの
    // ドアベルを鳴らすと、FWがまだ新しいcmdqアドレスを取り込み切れておらず
    // タイムアウトすることがある(登録直後にuart_printf()でエントリ内容を
    // ダンプする診断コードを挟んだ場合は毎回成功し、削除すると再現する、
    // という比較で突き止めた -- ダンプ自体がUART送信で数msの猶予を作って
    // いたのが実質的な「待ち」になっていた)。ここで明示的に短い遅延を
    // 入れることで診断コード無しでも安定させる。
    timer_delay_ms(10);

    return 0;
}

// 単一コマンドを発行する(常にキューentry 0を使うポーリング専用実装)。
// in/outとも対称に扱う: 16バイトまではlay->in/out(インライン)、それを
// 超える分は複数のメールボックスブロック(512バイト/個)を`next`で連結して
// 送受信する -- 合計MLX5_CMD_MBOX_CHAIN_MAX(mlx5.hのMLX5_CMD_MBOX_CHAIN_
// BLOCKS参照)まで対応。ブロック数が1個で足りる従来の小さいコマンド
// (QUERY_ISSI等)もこの経路をそのまま通る(n=1のチェインとして扱われる
// だけで動作は変わらない)。
// - in_buf/in_len: 呼び出し元が組み立てた入力(mlx5_ifc.hの各*_in_bitsの
//   ビッグエンディアン生バイト列そのもの、先頭2バイトがopcode)。
// - out_buf/out_len: 出力を受け取るバッファ(呼び出し元が対応する
//   *_out_bits構造体のバイト数を渡す)。
// 成功時0、失敗時負値を返す。
static int mlx5_cmd_exec(mlx5_dev_t *dev, const uint8_t *in_buf, uint32_t in_len, void *out_buf, uint32_t out_len) {
    if (out_len > MLX5_CMD_MBOX_CHAIN_MAX) {
        uart_printf("mlx5: cmd_exec: out_len=%u exceeds mailbox chain support (max %u)\n",
                    out_len, MLX5_CMD_MBOX_CHAIN_MAX);
        return -1;
    }
    if (in_len > MLX5_CMD_MBOX_CHAIN_MAX) {
        uart_printf("mlx5: cmd_exec: in_len=%u exceeds mailbox chain support (max %u)\n",
                    in_len, MLX5_CMD_MBOX_CHAIN_MAX);
        return -1;
    }

    volatile mlx5_cmd_layout_t *lay = (volatile mlx5_cmd_layout_t *)(void *)S_CMDQ(dev);
    for (unsigned i = 0; i < sizeof(*lay); i++) {
        ((volatile uint8_t *)lay)[i] = 0;
    }

    // 入力: 生バイト列をそのままコピーする(既にビッグエンディアンの配線
    // フォーマットなのでバイトスワップ不要 -- 送受信双方で一貫してこの
    // 規約を使う、mlx5_query_issi()の出力パース側コメント参照)。先頭
    // 16バイトはlay->in[4]、残りは入力メールボックスチェインへ。
    {
        volatile uint8_t *dst = (volatile uint8_t *)lay->in;
        for (uint32_t i = 0; i < 16u; i++) {
            dst[i] = (i < in_len) ? in_buf[i] : 0;
        }
    }
    uint32_t opcode = ((uint32_t)in_buf[0] << 8) | in_buf[1];

    if (in_len > 16u) {
        uint32_t remaining = in_len - 16u;
        uint32_t nblocks = (remaining + 511u) / 512u;
        for (uint32_t b = 0; b < nblocks; b++) {
            volatile mlx5_cmd_prot_block_t *blk = S_IN_MBOX(dev, b);
            for (unsigned i = 0; i < sizeof(*blk); i++) {
                ((volatile uint8_t *)blk)[i] = 0;
            }
            uint32_t chunk = remaining > 512u ? 512u : remaining;
            for (uint32_t i = 0; i < chunk; i++) {
                blk->data[i] = in_buf[16 + b * 512u + i];
            }
            blk->block_num = __builtin_bswap32(b);
            // next: 次のブロックのDMAアドレス(最終ブロックは0のまま)。
            // ブロックsignature(ctrl_sig/sig)は計算しない -- 実際に
            // torvalds/linux(master)のcmd.cを再取得して確認した: `cmd->
            // checksum_disabled`はmlx5_cmd_init()で無条件に1へ固定され
            // 以後トグルされないため、set_signature()の`calc_chain_sig()`
            // (メールボックスのctrl_sig/sig計算)は常にスキップされる --
            // 現行アップストリームドライバは実機に対して常にメールボックスの
            // signatureをゼロのまま送っている(このプロジェクトで以前
            // 試しに計算する実装を入れたが根拠が無かったため撤回した経緯
            // がある、CLAUDE.md「ConnectX(mlx5) HCA初期化」節参照)。
            if (b + 1 < nblocks) {
                blk->next = __builtin_bswap64(mlx5_dma_addr(S_IN_MBOX(dev, b + 1)));
            }
            remaining -= chunk;
        }
        lay->in_ptr = __builtin_bswap64(mlx5_dma_addr(S_IN_MBOX(dev, 0)));
    }
    lay->inlen = __builtin_bswap32(in_len);

    int need_mbox = (out_len > 16u);
    uint32_t out_nblocks = 0;
    if (need_mbox) {
        uint32_t out_remaining = out_len - 16u;
        out_nblocks = (out_remaining + 511u) / 512u;
        for (uint32_t b = 0; b < out_nblocks; b++) {
            volatile mlx5_cmd_prot_block_t *blk = S_OUT_MBOX(dev, b);
            for (unsigned i = 0; i < sizeof(*blk); i++) {
                ((volatile uint8_t *)blk)[i] = 0;
            }
            blk->block_num = __builtin_bswap32(b);
            if (b + 1 < out_nblocks) {
                blk->next = __builtin_bswap64(mlx5_dma_addr(S_OUT_MBOX(dev, b + 1)));
            }
        }
        lay->out_ptr = __builtin_bswap64(mlx5_dma_addr(S_OUT_MBOX(dev, 0)));
    }
    lay->outlen = __builtin_bswap32(out_len);
    lay->type = MLX5_PCI_CMD_XPORT;
    lay->token = 0;

    // lay->sig: 64バイト全体のXORが0xFFになるよう計算する(Linux cmd.cの
    // set_signature()と同じ、checksum_disabled(メールボックス側sig省略)とは
    // 無関係に常に計算される)。
    {
        uint8_t x = 0;
        const volatile uint8_t *b = (const volatile uint8_t *)lay;
        for (unsigned i = 0; i < sizeof(*lay); i++) {
            if (i == offsetof(mlx5_cmd_layout_t, sig)) {
                continue;
            }
            x ^= b[i];
        }
        lay->sig = (uint8_t)~x;
    }

    // 所有権をFWへ渡す(以降driverはstatus_ownを読むだけ、書き換えない)。
    lay->status_own = MLX5_CMD_OWNER_HW;
    dma_wmb();

    mlx5_write32(dev, MLX5_ISEG_CMD_DBELL, 1u << 0); // entry 0

    uint64_t start = timer_now();
    while (lay->status_own & MLX5_CMD_OWNER_HW) {
        if (timeout_ms(start, MLX5_CMD_TIMEOUT_MS)) {
            uart_printf("mlx5: cmd_exec: opcode=0x%x timed out waiting for completion\n", opcode);
            return -1;
        }
    }

    uint8_t delivery_status = (uint8_t)(lay->status_own >> 1);
    if (delivery_status != 0) {
        uart_printf("mlx5: cmd_exec: opcode=0x%x delivery status=0x%02x (expected 0=OK)\n",
                    opcode, delivery_status);
        return -1;
    }

    if (out_buf) {
        uint8_t *dst = (uint8_t *)out_buf;
        uint32_t copy0 = out_len < 16u ? out_len : 16u;
        const volatile uint8_t *src0 = (const volatile uint8_t *)lay->out;
        for (uint32_t i = 0; i < copy0; i++) {
            dst[i] = src0[i];
        }
        if (out_len > 16u) {
            uint32_t rest = out_len - 16u;
            for (uint32_t b = 0; b < out_nblocks; b++) {
                const volatile mlx5_cmd_prot_block_t *blk = S_OUT_MBOX(dev, b);
                uint32_t chunk = rest > 512u ? 512u : rest;
                for (uint32_t i = 0; i < chunk; i++) {
                    dst[16 + b * 512u + i] = blk->data[i];
                }
                rest -= chunk;
            }
        }
    }

    return 0;
}

#define MLX5_CMD_OP_ENABLE_HCA   0x104u
#define MLX5_CMD_OP_QUERY_PAGES  0x107u
#define MLX5_CMD_OP_MANAGE_PAGES 0x108u
#define MLX5_MANAGE_PAGES_OP_MOD_GIVE      0x1u

// ENABLE_HCA: struct mlx5_ifc_enable_hca_in/out_bits(共に16バイト、インライン)。
// Linux main.c の mlx5_function_enable() では、コマンドインターフェース有効化
// (cmdq登録)・FW初期化完了待ちの直後、SET_ISSI/QUERY_PAGES(boot)より前に
// 呼ばれる -- これを飛ばすとQUERY_PAGES等の資源管理系コマンドが
// MLX5_CMD_STAT_BAD_RES_STATE_ERR(status=0x09)で拒否される(実機で確認済み、
// PCIeリンクの電気的リセットを挟んでも同一syndromeで再現したため、
// 「前回までのテストの残骸」ではなくこのコマンド自体の欠落が原因と特定した)。
static int mlx5_enable_hca(mlx5_dev_t *dev) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_ENABLE_HCA >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ENABLE_HCA & 0xffu);
    // embedded_cpu_function=0, function_id_type=0, function_id=0(自分自身)
    // -- bytes[8:11]はゼロのままでよい。

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: ENABLE_HCA: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    return 0;
}

// QUERY_PAGES: struct mlx5_ifc_query_pages_out_bits(16バイト、インライン
// のみでメールボックス不要)。status(1B)+reserved(3B) / syndrome(4B) /
// embedded_cpu_function(1bit)+reserved(15bit)+function_id(16bit) /
// num_pages(4B、符号あり)。
static int mlx5_query_pages(mlx5_dev_t *dev, uint32_t op_mod, uint16_t *out_function_id, int32_t *out_num_pages) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_QUERY_PAGES >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_QUERY_PAGES & 0xffu);
    in[6] = (uint8_t)(op_mod >> 8);
    in[7] = (uint8_t)(op_mod & 0xffu);
    // embedded_cpu_function=0, function_id=0(自分自身) -- bytes[8:11]は
    // ゼロのままでよい。

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: QUERY_PAGES(op_mod=%u): command status=0x%02x syndrome=0x%08x\n",
                    op_mod, status, syndrome);
        return -1;
    }

    if (out_function_id) {
        *out_function_id = (uint16_t)(((uint16_t)out[10] << 8) | out[11]);
    }
    if (out_num_pages) {
        *out_num_pages = (int32_t)(((uint32_t)out[12] << 24) | ((uint32_t)out[13] << 16) |
                                    ((uint32_t)out[14] << 8) | out[15]);
    }
    return 0;
}

// 1回のMANAGE_PAGES呼び出しで送れるpas[]エントリ数の上限
// (メールボックス1個512B/8B=64エントリ、MLX5_CMD_MAILBOX_MAXの制約)。
// init pages(実機で2489ページ=約9.7MBを要求、CLAUDE.md「ConnectX(mlx5)
// HCA初期化」節参照)のような大きい要求は、メールボックスチェイン
// (今回未実装)の代わりにMANAGE_PAGES(GIVE)を複数回に分けて呼ぶことで
// 満たす -- PRM上GIVEは単一の一括操作である必要はなく、追加のページを
// 都度FWへ譲渡していく操作として繰り返し呼んでよい(実機で確認、下記
// mlx5_manage_pages_give()参照)。
#define MLX5_MANAGE_PAGES_MAX_PER_CALL 64u
_Static_assert(16u + MLX5_MANAGE_PAGES_MAX_PER_CALL * 8u <= MLX5_CMD_MAILBOX_MAX,
               "MLX5_MANAGE_PAGES_MAX_PER_CALL must fit in a single mailbox block");

// MANAGE_PAGES(op_mod=GIVE)を1チャンク分(最大MLX5_MANAGE_PAGES_MAX_PER_CALL
// ページ)だけ発行する下位ヘルパ。struct mlx5_ifc_manage_pages_in_bits。
// 固定ヘッダ16バイト(opcode/op_mod/function_id/input_num_entries)の直後に
// pas[](n個の64bit物理アドレス、ビッグエンディアン)が続く -- 16バイトを
// 超える分はメールボックスへ(mlx5_cmd_exec()の対称メールボックス対応、
// 上記コメント参照)。出力はstatus/syndromeのみ(16バイト、インライン)。
static int mlx5_manage_pages_give_chunk(mlx5_dev_t *dev, uint16_t function_id, uint32_t n, uint32_t page_base_idx) {
    uint8_t in[16 + MLX5_MANAGE_PAGES_MAX_PER_CALL * 8];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_MANAGE_PAGES >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_MANAGE_PAGES & 0xffu);
    in[6] = 0x00; // op_mod上位バイト
    in[7] = (uint8_t)MLX5_MANAGE_PAGES_OP_MOD_GIVE;
    in[10] = (uint8_t)(function_id >> 8); // embedded_cpu_function=0, function_id
    in[11] = (uint8_t)(function_id & 0xffu);
    in[12] = (uint8_t)(n >> 24);
    in[13] = (uint8_t)(n >> 16);
    in[14] = (uint8_t)(n >> 8);
    in[15] = (uint8_t)n;

    for (uint32_t i = 0; i < n; i++) {
        uint64_t addr = mlx5_dma_addr(mlx5_fw_page(dev, page_base_idx + i));
        unsigned off = 16u + i * 8u;
        for (unsigned b = 0; b < 8; b++) {
            in[off + b] = (uint8_t)(addr >> (56 - 8 * b));
        }
    }

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, 16u + n * 8u, out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: MANAGE_PAGES(GIVE, n=%u): command status=0x%02x syndrome=0x%08x\n",
                    n, status, syndrome);
        return -1;
    }
    return 0;
}

// npages全体を、MLX5_MANAGE_PAGES_MAX_PER_CALLページずつのチャンクへ
// 分割してMANAGE_PAGES(GIVE)を繰り返す。
static int mlx5_manage_pages_give(mlx5_dev_t *dev, uint16_t function_id, int32_t npages) {
    if (npages <= 0) {
        return 0; // 要求無し、何もしなくてよい(pagealloc.cのmlx5_satisfy_startup_pages()と同じ)。
    }
    uint32_t remaining = (uint32_t)npages;
    if (remaining > MLX5_MAX_FW_PAGES - dev->fw_pages_used) {
        uart_printf("mlx5: MANAGE_PAGES: requested %u pages exceeds remaining pool (%u/%u used)\n",
                    remaining, dev->fw_pages_used, (unsigned)MLX5_MAX_FW_PAGES);
        return -1;
    }

    while (remaining > 0) {
        uint32_t n = remaining > MLX5_MANAGE_PAGES_MAX_PER_CALL ? MLX5_MANAGE_PAGES_MAX_PER_CALL : remaining;
        int rc = mlx5_manage_pages_give_chunk(dev, function_id, n, dev->fw_pages_used);
        if (rc != 0) {
            return rc;
        }
        dev->fw_pages_used += n;
        remaining -= n;
    }
    return 0;
}

#define MLX5_CMD_OP_QUERY_ISSI 0x10au
#define MLX5_CMD_OP_SET_ISSI   0x10bu

// QUERY_ISSI: struct mlx5_ifc_query_issi_out_bits(112バイト)。
// status(1B)+reserved(3B) / syndrome(4B) / reserved(2B)+current_issi(2B) /
// reserved(20B) / reserved(76B) / supported_issi_dw0(4B) = 112B。
static int mlx5_query_issi(mlx5_dev_t *dev, uint16_t *out_current_issi, uint32_t *out_supported_issi_dw0) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_QUERY_ISSI >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_QUERY_ISSI & 0xffu);

    uint8_t out[112];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: QUERY_ISSI: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    uint16_t current_issi = (uint16_t)(((uint16_t)out[10] << 8) | out[11]);
    uint32_t supported_issi_dw0 = ((uint32_t)out[108] << 24) | ((uint32_t)out[109] << 16) |
                                   ((uint32_t)out[110] << 8) | out[111];

    if (out_current_issi) {
        *out_current_issi = current_issi;
    }
    if (out_supported_issi_dw0) {
        *out_supported_issi_dw0 = supported_issi_dw0;
    }
    return 0;
}

// SET_ISSI: struct mlx5_ifc_set_issi_in_bits(16バイト、opcode/op_mod共通
// ヘッダの直後、DWORD2の下位16bitに設定したいISSI値=issiを入れる
// フィールド名は"current_issi"だがPRM上の名称そのまま、実際には「これから
// 設定する値」)。出力struct mlx5_ifc_set_issi_out_bitsは16バイト(status/
// syndrome/reserved)でインライン(メールボックス不要)。
static int mlx5_set_issi(mlx5_dev_t *dev, uint16_t issi) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_SET_ISSI >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_SET_ISSI & 0xffu);
    in[10] = (uint8_t)(issi >> 8);
    in[11] = (uint8_t)(issi & 0xffu);

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: SET_ISSI(%u): command status=0x%02x syndrome=0x%08x\n",
                    issi, status, syndrome);
        return -1;
    }
    return 0;
}

// ============================================================================
// フェーズ3: HCA capability設定(QUERY_HCA_CAP/SET_HCA_CAP)とINIT_HCA。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_{query,set}_hca_cap_{in,out}_bits/
// struct mlx5_ifc_cmd_hca_cap_bits/struct mlx5_ifc_init_hca_in_bits、
// `drivers/net/ethernet/mellanox/mlx5/core/main.c`の
// mlx5_core_get_caps_mode()/set_caps()、`fw.c`のmlx5_cmd_init_hca())
// から取得。
// ============================================================================

#define MLX5_CMD_OP_QUERY_HCA_CAP 0x100u
#define MLX5_CMD_OP_INIT_HCA      0x102u
#define MLX5_CMD_OP_SET_HCA_CAP   0x109u

// QUERY_HCA_CAP/SET_HCA_CAPのop_mod上位15bitはcap_type(0=general)、
// 下位1bitがcur(1)/max(0) -- main.cのmlx5_core_get_caps_mode()の
// `u16 opmod = (cap_type << 1) | (cap_mode & 0x01);`と同じ計算。
// このプロジェクトはgeneral capsのcur値だけを読み、それをそのまま
// SET_HCA_CAPへ送り返す(下記mlx5_set_hca_cap_general()参照)。
#define MLX5_CAP_TYPE_GENERAL 0u
// 2026-08-10、LSO対応。torvalds/linux include/linux/mlx5/mlx5_ifc.hの
// enum(MLX5_SET_HCA_CAP_OP_MOD_ETHERNET_OFFLOADS)で実際に確認した値。
#define MLX5_CAP_TYPE_ETHERNET_OFFLOADS 1u
// 2026-08-11、RoCEv2対応(ConnectX RoCEv2 NVMe-oF実装計画フェーズ(a))。
// include/linux/mlx5/device.hのenum mlx5_cap_type(GENERAL=0,
// ETHERNET_OFFLOADS=1,ODP=2,ATOMIC=3,ROCE=4)で実際に確認した値。
#define MLX5_CAP_TYPE_ROCE 4u
#define MLX5_HCA_CAP_OPMOD_CUR 1u

// struct mlx5_ifc_cmd_hca_cap_bits(mlx5_ifc.h)は0x780バイト目
// (`match_definer_format_supported[0x40]`の直前、offset 0x780=1920bit)
// で終わり、そのフィールド自身(0x40=64bit=8byte)を加えて合計
// 0x800bit=256バイトちょうど。QUERY_HCA_CAP/SET_HCA_CAP双方の
// `capability`フィールドは実際には`union mlx5_ifc_hca_cap_union_bits`
// (他のcap type向けに4096バイトへパディングされている)だが、
// general capsだけを読み書きする分にはこの256バイトだけをoutlen/inlenに
// 指定すれば十分(FWはoutlen/inlenで指定された長さだけを読み書きする、
// このプロジェクトの他コマンド(QUERY_ISSI等)でも同じ規約を使っている)。
// ヘッダ16バイト+256バイト=272バイトはMLX5_CMD_MAILBOX_MAX(528バイト、
// 単一メールボックスブロック)に収まるため、チェイン未実装のままでも
// 送受信できる。
_Static_assert(16u + MLX5_HCA_CAP_BYTES <= MLX5_CMD_MAILBOX_MAX,
               "general HCA caps must fit in a single mailbox block");

// QUERY_HCA_CAP(general, cur): status(1B)+reserved(3B)/syndrome(4B)/
// reserved(8B)の16バイトヘッダの直後にcmd_hca_cap_bits(256バイト)。
static int mlx5_query_hca_cap_general(mlx5_dev_t *dev, uint8_t *cap_out) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_QUERY_HCA_CAP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_QUERY_HCA_CAP & 0xffu);
    uint16_t op_mod = (uint16_t)((MLX5_CAP_TYPE_GENERAL << 1) | MLX5_HCA_CAP_OPMOD_CUR);
    in[6] = (uint8_t)(op_mod >> 8);
    in[7] = (uint8_t)(op_mod & 0xffu);

    uint8_t out[16 + MLX5_HCA_CAP_BYTES];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: QUERY_HCA_CAP(general): command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }

    for (uint32_t i = 0; i < MLX5_HCA_CAP_BYTES; i++) {
        cap_out[i] = out[16 + i];
    }
    return 0;
}

// QUERY_HCA_CAP(ETHERNET_OFFLOADS, cur): struct mlx5_ifc_per_protocol_
// networking_offload_caps_bits(torvalds/linux include/linux/mlx5/
// mlx5_ifc.hで実際に取得・確認済み)。このプロジェクトが読むのは
// max_lso_cap(5bit)のみ -- struct先頭から2バイト目(out[16+1])の下位
// 5bit(`byte1 & 0x1F`)。0ならLSO非対応、非0なら`1<<値`が最大送信
// バイト数(公開情報で典型値18=262144バイトを確認、DPDK/mlx5ctl等の
// userspaceツールでも同名フィールドとして扱われている -- Linuxカーネル
// 本体側での「1<<値」という解釈のソース一次確認までは至らなかったが、
// 5bitフィールドで生値18という妥当な範囲・業界一般のTSO上限サイズと
// 整合するため採用する。この解釈が誤っていても、呼び出し元
// [mlx5_hca_bringup()]がMLX5_LSO_MAX_BYTES_CAPでクランプした上でログに
// 出すため、明らかにおかしい値であれば実機で即座に気付ける)。
// LSOケーパビリティは読み取り専用のHW固定値(SET_HCA_CAPでの有効化は
// 不要 -- Linux側もこのcap typeに対応するSET_HCA_CAPは行っていない)。
static int mlx5_query_hca_cap_eth_offloads(mlx5_dev_t *dev, uint32_t *out_max_lso_bytes) {
    *out_max_lso_bytes = 0u;

    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_QUERY_HCA_CAP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_QUERY_HCA_CAP & 0xffu);
    uint16_t op_mod = (uint16_t)((MLX5_CAP_TYPE_ETHERNET_OFFLOADS << 1) | MLX5_HCA_CAP_OPMOD_CUR);
    in[6] = (uint8_t)(op_mod >> 8);
    in[7] = (uint8_t)(op_mod & 0xffu);

    uint8_t out[16 + MLX5_HCA_CAP_BYTES];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: QUERY_HCA_CAP(eth_offloads): command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }

    uint8_t max_lso_cap = out[16 + 1] & 0x1Fu;
    uint32_t max_lso_bytes = max_lso_cap ? (1u << max_lso_cap) : 0u;
    if (max_lso_bytes > MLX5_LSO_MAX_BYTES_CAP) {
        max_lso_bytes = MLX5_LSO_MAX_BYTES_CAP;
    }
    *out_max_lso_bytes = max_lso_bytes;
    return 0;
}

// SET_HCA_CAP(op_mod=GENERAL_DEVICE=0<<1=0): struct
// mlx5_ifc_set_hca_cap_in_bits。固定ヘッダ16バイト
// (opcode/op_mod/other_function等、いずれも自分自身=全ゼロで良い)の
// 直後にcmd_hca_cap_bits(256バイト) -- cap_inはmlx5_query_hca_cap_general()
// が読んだcur値をそのまま渡す想定(個々のフィールドを独自に組み立てず、
// FWが「現在有効」と報告した値をそのまま追認する最小実装、CLAUDE.md
// 「ConnectX(mlx5) HCA初期化」節参照)。出力はstatus/syndromeのみ
// (16バイト、インライン)。
static int mlx5_set_hca_cap_general(mlx5_dev_t *dev, const uint8_t *cap_in) {
    uint8_t in[16 + MLX5_HCA_CAP_BYTES];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_SET_HCA_CAP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_SET_HCA_CAP & 0xffu);
    uint16_t op_mod = (uint16_t)(MLX5_CAP_TYPE_GENERAL << 1); // GENERAL_DEVICE
    in[6] = (uint8_t)(op_mod >> 8);
    in[7] = (uint8_t)(op_mod & 0xffu);
    for (uint32_t i = 0; i < MLX5_HCA_CAP_BYTES; i++) {
        in[16 + i] = cap_in[i];
    }

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: SET_HCA_CAP(general): command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }
    return 0;
}

// INIT_HCA: struct mlx5_ifc_init_hca_in_bits(32バイト -- opcode/op_mod
// 共通ヘッダ4バイト+reserved4バイト+reserved2bit/sw_vhca_id14bit+
// reserved16bit+sw_owner_id[4][32bit]=16バイト)。sw_owner_id/sw_vhca_id
// は共にFW capability(`sw_owner_id`/`sw_vhca_id_valid`)が有効な場合のみ
// 設定するオプション機能(fw.cのmlx5_cmd_init_hca()参照) -- このプロジェクト
// はそれらのcapabilityを個別に読んでいないため、常に全ゼロのまま送る
// (Linux側もcapability非対応なら同様に全ゼロ)。出力はstatus/syndromeのみ
// (16バイト、インライン)。
static int mlx5_init_hca(mlx5_dev_t *dev) {
    uint8_t in[32] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_INIT_HCA >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_INIT_HCA & 0xffu);

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: INIT_HCA: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    return 0;
}

// ============================================================================
// フェーズ4: UAR割り当て(ALLOC_UAR)とEQ作成(CREATE_EQ)。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_{alloc_uar,create_eq}_{in,out}_bits/
// struct mlx5_ifc_eqc_bits、`include/linux/mlx5/device.h`の
// struct mlx5_eqe、`drivers/net/ethernet/mellanox/mlx5/core/uar.c`の
// mlx5_cmd_alloc_uar()、`eq.c`のcreate_map_eq()/init_eq_buf())から取得。
// ============================================================================

#define MLX5_CMD_OP_ALLOC_UAR 0x802u
#define MLX5_CMD_OP_CREATE_EQ 0x301u

// ALLOC_UAR: struct mlx5_ifc_alloc_uar_in/out_bits(共に16バイト、インライン、
// メールボックス不要)。出力のuar[0x18](24bit)がUAR番号(uarn) --
// bit0x48(=72)から24bit、つまりout[9..11]の3バイトBE値。
static int mlx5_alloc_uar(mlx5_dev_t *dev, uint32_t *out_uarn) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_ALLOC_UAR >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ALLOC_UAR & 0xffu);

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: ALLOC_UAR: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_uarn) {
        *out_uarn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// EQE(struct mlx5_eqe、device.h)は全世代のmlx5で64バイト固定
// (rsvd0(1)+type(1)+rsvd1(1)+sub_type(1)+rsvd2[7*4=28]+ev_data(28)+
// rsvd3(2)+signature(1)+owner(1)=64バイト -- ev_data自体のレイアウトは
// 使わないため未展開)。EQバッファ1ページ(4096B)には64エントリ入る
// (log_eq_size=6=2^6=64、mlx5.hのMLX5_EQ_BUF_SIZE参照)。
#define MLX5_EQE_SIZE 64u
#define MLX5_EQ_NUM_ENTRIES (MLX5_EQ_BUF_SIZE / MLX5_EQE_SIZE)
#define MLX5_EQE_OWNER_INIT_VAL 1u // eq.cのinit_eq_buf()と同じ初期値
_Static_assert(MLX5_EQ_NUM_ENTRIES == 64u, "MLX5_EQ_BUF_SIZE/MLX5_EQE_SIZE assumption changed");

// CREATE_EQ: struct mlx5_ifc_create_eq_in_bits。固定ヘッダ16バイト+
// eq_context_entry(struct mlx5_ifc_eqc_bits、64バイト、in[16..79])+
// reserved(8バイト、in[80..87])+event_bitmask(32バイト、in[88..119])+
// reserved(152バイト、in[120..271])の合計272バイトの直後にpas[]
// (今回は1ページ分、8バイトのみ)。eqc内の各フィールドのバイトオフセットは
// mlx5_ifc.hの累積ビットオフセットから手計算(下記コメント参照、コード
// レビュー時に再検算しやすいよう相対オフセットを明示している)。
//
// - log_eq_size: eqc相対byte12の下位5bit(上位3bitはreserved) -- 64エントリ=2^6。
// - uar_page: eqc相対byte13-15、24bit BE -- ALLOC_UARで得たuarnをそのまま。
// - intr: eqc相対byte22下位4bit+byte23、12bit -- 0固定。このプロジェクトは
//   MSI-X/IRQを一切構成していない(ポーリング専用、ユーザー指示)ため、
//   ベクタ番号を指定しても実際に割り込みが配送されることはない想定
//   (実機で本当にこの値のままFWが受理するかは未検証)。
// - log_page_size: eqc相対byte24の下位5bit -- 0固定(4KBページ、
//   MLX5_ADAPTER_PAGE_SHIFT基準、mlx5_dma_addr()と同じ4KB単位)。
// - event_bitmask(in[88..119]): 全ゼロのまま -- どのイベント種別も
//   有効化しない。このEQはCREATE_CQのeqn要件を満たすためだけに存在し、
//   実際にイベント配送を受ける設計にはしていない。
static int mlx5_create_eq(mlx5_dev_t *dev, uint32_t uarn, uint32_t *out_eqn) {
    // EQバッファの各EQEのownerバイト(エントリ末尾)をLinuxのinit_eq_buf()
    // と同じ初期値にしておく -- 万一将来ポーリングでEQEを読む処理を追加
    // する際、HWがまだ書いていないエントリを誤って「新規イベント」と
    // 誤認しないようにするため(今回はEQ自体を能動的に読まないため実害は
    // 無いが、real driverと同じ規約を踏襲しておく)。
    volatile uint8_t *eq_buf = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->eq_buf_cpu;
    for (unsigned i = 0; i < MLX5_EQ_NUM_ENTRIES; i++) {
        eq_buf[i * MLX5_EQE_SIZE + (MLX5_EQE_SIZE - 1)] = (uint8_t)MLX5_EQE_OWNER_INIT_VAL;
    }

    uint8_t in[272 + 8];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_EQ >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_EQ & 0xffu);

    in[16 + 12] = 6u; // log_eq_size=6 (64エントリ)、上位3bit(reserved)は0のまま
    in[16 + 13] = (uint8_t)(uarn >> 16);
    in[16 + 14] = (uint8_t)(uarn >> 8);
    in[16 + 15] = (uint8_t)uarn;
    in[16 + 22] = 0x00; // intr上位4bit=0
    in[16 + 23] = 0x00; // intr下位8bit=0
    in[16 + 24] = 0u;   // log_page_size=0 (4KB)

    uint64_t eq_pa = mlx5_dma_addr((volatile void *)(uintptr_t)(uint64_t)dev->eq_buf_cpu);
    unsigned pas_off = 272;
    for (unsigned b = 0; b < 8; b++) {
        in[pas_off + b] = (uint8_t)(eq_pa >> (56 - 8 * b));
    }

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_EQ: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    // create_eq_out: status(1)+reserved(3)/syndrome(4)/reserved(3)+
    // eq_number(1、bit0x58=byte11)/reserved(4) = 16バイト。
    if (out_eqn) {
        *out_eqn = out[11];
    }
    return 0;
}

// ============================================================================
// フェーズ5: PD割り当て(ALLOC_PD)とPAモードMKey作成(CREATE_MKEY)。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_{alloc_pd,create_mkey}_{in,out}_bits/
// struct mlx5_ifc_mkc_bits、`drivers/net/ethernet/mellanox/mlx5/core/pd.c`の
// mlx5_core_alloc_pd()、`drivers/infiniband/hw/mlx5/mr.c`の
// mlx5_ib_get_dma_mr()/set_mkc_access_pd_addr_fields())から取得。
// ============================================================================

#define MLX5_CMD_OP_ALLOC_PD    0x800u
#define MLX5_CMD_OP_CREATE_MKEY 0x200u

// ALLOC_PD: struct mlx5_ifc_alloc_pd_in/out_bits(共に16バイト、インライン、
// メールボックス不要)。出力のpd[0x18](24bit、out[9..11]のBE値)がPD番号。
static int mlx5_alloc_pd(mlx5_dev_t *dev, uint32_t *out_pdn) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_ALLOC_PD >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ALLOC_PD & 0xffu);

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: ALLOC_PD: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_pdn) {
        *out_pdn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// CREATE_MKEY(PAモード): struct mlx5_ifc_create_mkey_in_bits。固定ヘッダ
// 16バイトの直後にmemory_key_mkey_entry(struct mlx5_ifc_mkc_bits、
// 64バイト、in[16..79])、以降のreserved/translations_octword_actual_size/
// klm_pas_mtt[]は今回のPAモード(access_mode=0、start_addr=0、
// length64=1で「物理アドレス空間全体」を表す、Linux
// mlx5_ib_get_dma_mr()と同じ手法 -- MTT/KLMによる個別バッファ登録を
// 一切行わず、HCAに任意の物理アドレスへの直接DMAアクセスを許可する
// 最小実装)では一切使わないため、in_len=272バイト(mkc本体まで)だけで
// 良い。mkc内の各フィールドのバイトオフセットはmlx5_ifc.hの累積ビット
// オフセットから手計算(コードレビュー時に再検算しやすいよう相対
// オフセットを明示している)。
//
// - mkc相対byte2: [umr_en(bit0,MSB)][a][rw][rr][lw][lr][access_mode_1_0(2bit,LSB)]
//   -- lw=1,lr=1(ローカル読み書き許可)、他は0、access_mode_1_0=0(PA)
//   なので byte2=0x0C(0b00001100)。
// - mkc相対byte12: length64(bit0,MSB)=1、他は0なのでbyte12=0x80。
//   (start_addr=0/len=0のまま「64bit空間全体」を表す、set_mkc_access_
//   pd_addr_fields()相当だがstart_addr=0固定・acc最小構成に単純化)
// - mkc相対byte13-15: pd[0x18]、24bit BE -- ALLOC_PDで得たpdn。
static int mlx5_create_mkey_pa(mlx5_dev_t *dev, uint32_t pdn, uint32_t *out_mkey) {
    uint8_t in[272];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_MKEY >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_MKEY & 0xffu);

    in[16 + 2] = 0x0Cu; // lw=1, lr=1, access_mode_1_0=0(PA)
    // qpn(mkc相対byte4-6、24bit)は0xFFFFFF固定 -- 実ドライバの
    // drivers/net/ethernet/mellanox/mlx5/core/en_common.cの
    // mlx5e_create_mkey()が、SQ/RQのWQEデータセグメントから汎用的に
    // 参照される(特定のQPに紐付かない)MKeyへ明示的にこの値を設定して
    // いることを確認した上で踏襲した(qpn=0のままだと「QP番号0に紐付く」
    // という別の意味に解釈されうるため)。
    in[16 + 4] = 0xFFu;
    in[16 + 5] = 0xFFu;
    in[16 + 6] = 0xFFu;
    in[16 + 12] = 0x80u; // length64=1
    in[16 + 13] = (uint8_t)(pdn >> 16);
    in[16 + 14] = (uint8_t)(pdn >> 8);
    in[16 + 15] = (uint8_t)pdn;
    // mkey_7_0(mkc相対byte7)は0のままにする -- 唯一のMKeyしか作らない
    // ためFW側との衝突は起きない。最終的なmkey番号は
    // (mkey_index << 8) | mkey_7_0(driver.hのmlx5_idx_to_mkey()参照)。

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_MKEY: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_mkey) {
        // create_mkey_out: status(1)+reserved(3)/syndrome(4)/reserved(1)+
        // mkey_index(3、out[9..11]のBE値)/reserved(4) = 16バイト。
        uint32_t mkey_index = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
        *out_mkey = mkey_index << 8; // | mkey_7_0(=0)
    }
    return 0;
}

// ============================================================================
// フェーズ6: CQ(Completion Queue)作成(CREATE_CQ)。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_{create_cq}_{in,out}_bits/struct mlx5_ifc_cqc_bits、
// `include/linux/mlx5/device.h`のstruct mlx5_cqe64、
// `drivers/net/ethernet/mellanox/mlx5/core/cq.c`のmlx5_create_cq())
// から取得。
// ============================================================================

#define MLX5_CMD_OP_CREATE_CQ 0x400u

// CQE(struct mlx5_cqe64、device.h)は名前の通り64バイト固定。
// 2026-08-11、CQバッファを1ページ(4096B、64エントリ)から16ページ
// (65536B、1024エントリ)へ拡張(board.hのMLX5_CQ_CACHE_PF_SIZEコメント
// 参照 -- 実機で旧64エントリのRQ用CQがオーバーラン[status=9]したことへの
// 対策、RQのWQE深さ[MLX5_RQ_NUM_WQES=256]に対して4倍の余裕を持たせた)。
#define MLX5_CQE_SIZE 64u
#define MLX5_CQ_NUM_ENTRIES (MLX5_CQ_BUF_SIZE / MLX5_CQE_SIZE)
_Static_assert(MLX5_CQ_NUM_ENTRIES == 1024u, "MLX5_CQ_BUF_SIZE/MLX5_CQE_SIZE assumption changed");
#define MLX5_CQ_LOG_SIZE_VAL 10u // log2(1024) -- cqc.log_cq_sizeへ書く値
_Static_assert((1u << MLX5_CQ_LOG_SIZE_VAL) == MLX5_CQ_NUM_ENTRIES,
               "MLX5_CQ_LOG_SIZE_VAL must be log2(MLX5_CQ_NUM_ENTRIES)");
// log_page_size=0(4KBページ単位)のままなので、CQバッファ65536Bは
// 65536/4096=16ページ、すなわちpas[]は16エントリ(8バイト×16=128バイト)
// 必要になる -- 単一メールボックス(MLX5_CMD_MAILBOX_MAX=528バイト)には
// 272+128=400バイトで収まるため、メールボックスチェインは不要。
#define MLX5_CQ_NUM_PAGES (MLX5_CQ_BUF_SIZE / 4096u)
_Static_assert(MLX5_CQ_NUM_PAGES == 16u, "MLX5_CQ_BUF_SIZE/4096 assumption changed");
_Static_assert(272u + MLX5_CQ_NUM_PAGES * 8u <= 528u,
               "CREATE_CQ input must still fit in a single mailbox block");
#define MLX5_CQE_INVALID 0xFu // cq.hのenum MLX5_CQE_INVALID -- op_own上位nibbleがこの値なら「まだHWが書いていない」

// CREATE_CQ: struct mlx5_ifc_create_cq_in_bits。固定ヘッダ16バイト+
// cq_context(struct mlx5_ifc_cqc_bits、64バイト、in[16..79])+
// reserved(12バイト、in[80..91])+cq_umem_valid他reserved(180バイト、
// in[92..271])の合計272バイトの直後にpas[](MLX5_CQ_NUM_PAGES[16]ページ分、
// 各8バイト)。cqc内の各フィールドのバイトオフセットはCREATE_EQのeqcと
// 同じ手法でmlx5_ifc.hの累積ビットオフセットから手計算した:
//
// - cqe_sz: cqc相対byte1の上位3bit -- 0固定(64バイトCQE)。
// - log_cq_size: cqc相対byte12の下位5bit -- MLX5_CQ_LOG_SIZE_VAL(2^10=1024エントリ)。
// - uar_page: cqc相対byte13-15、24bit BE -- ALLOC_UARで得たuarn。
// - c_eqn_or_apu_element: cqc相対byte20-23、32bit BE -- CREATE_EQで
//   得たeqn(このプロジェクトはポーリング専用のため実際にイベント配送を
//   受け取ることはない、CLAUDE.md「ConnectX(mlx5) HCA初期化」節参照)。
// - log_page_size: cqc相対byte24の下位5bit -- 0固定(4KB)。
// - dbr_addr: cqc相対byte56-63、64bit BE -- dbr_addr引数の物理アドレス。
//
// buf_addr/dbr_addrを引数化しているのはSQ用の専用CQ(RQ用とは別の
// MLX5_SQ_CQ_BUF_ADDR/DBR_ADDR)も同じ実装で作れるようにするため
// (mlx5_create_sq()コメント参照 -- 実ドライバもTX/RXで別々のCQを使う)。
static int mlx5_create_cq(mlx5_dev_t *dev, uint32_t uarn, uint32_t eqn, uint64_t buf_addr, uint64_t dbr_addr, uint32_t *out_cqn) {
    // ドアベルレコードをゼロクリアしておく(consumer_index/arm_indexの
    // 初期値0)。
    //
    // 2026-08-09: 呼び出し元(RQ/SQ双方のCREATE_CQ)がbuf_addr/dbr_addrに
    // board.hのMLX5_CQ_CACHE_BASE(Normal cacheable RAM)を渡すようになった
    // ため、CPUのこのゼロ書き込みがキャッシュに留まりHWから見えない恐れが
    // ある -- dcache_clean_range()で明示的にPoint of Coherencyまで
    // クリーンする(tcp.cのs_seg_bufs等、DMAソースにするキャッシュ可能
    // バッファへ書いた直後の既存パターンと同じ)。
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)dbr_addr;
    for (unsigned i = 0; i < MLX5_CQ_DBR_SIZE; i++) {
        dbr[i] = 0;
    }
    dcache_clean_range((const void *)dbr_addr, MLX5_CQ_DBR_SIZE);

    // CQバッファの各CQEの末尾バイト(op_own、struct mlx5_cqe64の最終
    // フィールド)上位nibbleをMLX5_CQE_INVALID(0xF、device.hのenum)に
    // 初期化しておく -- これによりHWがまだ何も書いていないエントリを、
    // 所有権ビットのトグル規約(周回のたびに期待値が反転する、CQ作成
    // 直後の1回きりの確認では厳密な追跡が本質的でない)に頼らず、
    // 単に「opcodeがINVALIDのままか否か」で判定できるようにする
    // (下記mlx5_cq_poll_any()参照)。上記dbrと同じ理由でクリーンが必要。
    {
        volatile uint8_t *cq_buf = (volatile uint8_t *)(uintptr_t)buf_addr;
        for (unsigned i = 0; i < MLX5_CQ_NUM_ENTRIES; i++) {
            cq_buf[i * MLX5_CQE_SIZE + (MLX5_CQE_SIZE - 1)] = (uint8_t)(MLX5_CQE_INVALID << 4);
        }
        dcache_clean_range((const void *)buf_addr, (uint64_t)MLX5_CQ_NUM_ENTRIES * MLX5_CQE_SIZE);
    }

    uint8_t in[272 + MLX5_CQ_NUM_PAGES * 8];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_CQ >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_CQ & 0xffu);

    in[16 + 12] = (uint8_t)MLX5_CQ_LOG_SIZE_VAL; // log_cq_size (1024エントリ)
    in[16 + 13] = (uint8_t)(uarn >> 16);
    in[16 + 14] = (uint8_t)(uarn >> 8);
    in[16 + 15] = (uint8_t)uarn;
    in[16 + 20] = (uint8_t)(eqn >> 24); // c_eqn_or_apu_element(32bit BE)
    in[16 + 21] = (uint8_t)(eqn >> 16);
    in[16 + 22] = (uint8_t)(eqn >> 8);
    in[16 + 23] = (uint8_t)eqn;
    in[16 + 24] = 0u; // log_page_size=0 (4KB)

    uint64_t dbr_pa = mlx5_dma_addr((volatile void *)(uintptr_t)dbr_addr);
    for (unsigned b = 0; b < 8; b++) {
        in[16 + 56 + b] = (uint8_t)(dbr_pa >> (56 - 8 * b));
    }

    // pas[]: CQバッファはMLX5_CQ_NUM_PAGES(16)ページの物理連続領域
    // (buf_addr自体が4096アライン、mlx5.hの_Static_assert群で保証済み)
    // なので、各ページの物理アドレスはcq_pa+i*4096で機械的に求まる。
    uint64_t cq_pa = mlx5_dma_addr((volatile void *)(uintptr_t)buf_addr);
    unsigned pas_off = 272;
    for (unsigned p = 0; p < MLX5_CQ_NUM_PAGES; p++) {
        uint64_t page_pa = cq_pa + (uint64_t)p * 4096u;
        for (unsigned b = 0; b < 8; b++) {
            in[pas_off + p * 8u + b] = (uint8_t)(page_pa >> (56 - 8 * b));
        }
    }

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_CQ: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    // create_cq_out: status(1)+reserved(3)/syndrome(4)/reserved(1)+
    // cqn(3、bit0x48=byte9からのBE値)/reserved(4) = 16バイト。
    if (out_cqn) {
        *out_cqn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// ============================================================================
// フェーズ7: Transport Domain割り当て(ALLOC_TRANSPORT_DOMAIN)と
// TIS作成(CREATE_TIS)。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_{alloc_transport_domain,create_tis}_{in,out}_bits/
// struct mlx5_ifc_tisc_bits、`drivers/net/ethernet/mellanox/mlx5/core/
// en_common.c`のmlx5e_create_mdev_resources()/mlx5e_create_tis())から取得。
// ============================================================================

#define MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN 0x816u
#define MLX5_CMD_OP_CREATE_TIS             0x912u

// ALLOC_TRANSPORT_DOMAIN: ALLOC_UAR/ALLOC_PDと全く同じ16バイトインライン
// パターン(出力のtransport_domain[0x18]がtdn、out[9..11]のBE値)。
static int mlx5_alloc_transport_domain(mlx5_dev_t *dev, uint32_t *out_tdn) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN & 0xffu);

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: ALLOC_TRANSPORT_DOMAIN: command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }

    if (out_tdn) {
        *out_tdn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// CREATE_TIS: struct mlx5_ifc_create_tis_in_bits。固定ヘッダ32バイト
// (opcode/uid/reserved/op_mod共通8バイト+reserved_at_40[0xc0]24バイト、
// mkc系のCREATE_MKEY/CREATE_EQ等の16バイトヘッダとは異なる点に注意)の
// 直後にtis_context(struct mlx5_ifc_tisc_bits、160バイト)、合計192バイト。
// tisc相対byte37-39がtransport_domain(24bit BE) -- 累積ビットオフセット
// (tisc_bitsのreserved_at_120[0x8]+transport_domain[0x18]、offset 0x120=
// 288bit=byte36から)から手計算した。設定するのはtransport_domainのみ
// (strict_lag_tx_port_affinity/prio等は複数ポート/QoS向けのオプション
// 機能でこのプロジェクトのスコープ外、0のままで良い)。
static int mlx5_create_tis(mlx5_dev_t *dev, uint32_t tdn, uint32_t *out_tisn) {
    uint8_t in[192];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_TIS >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_TIS & 0xffu);

    in[32 + 37] = (uint8_t)(tdn >> 16);
    in[32 + 38] = (uint8_t)(tdn >> 8);
    in[32 + 39] = (uint8_t)tdn;

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_TIS: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_tisn) {
        *out_tisn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// ============================================================================
// フェーズ8: RQ(Receive Queue)作成(CREATE_RQ)、RST->RDY遷移(MODIFY_RQ)、
// TIR(Transport Interface Receive)作成(CREATE_TIR)。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_{create_rq,modify_rq,create_tir}_{in,out}_bits/
// struct mlx5_ifc_{rqc,wq,tirc}_bits、`include/linux/mlx5/qp.h`の
// struct mlx5_wqe_data_seg、`drivers/net/ethernet/mellanox/mlx5/core/
// en_main.c`のmlx5e_create_rq()/mlx5e_modify_rq_state())から取得。
// ============================================================================

#define MLX5_CMD_OP_CREATE_RQ  0x908u
#define MLX5_CMD_OP_MODIFY_RQ  0x909u
#define MLX5_CMD_OP_CREATE_TIR 0x900u

#define MLX5_WQ_TYPE_CYCLIC        1u
#define MLX5_WQ_END_PAD_MODE_ALIGN 1u
#define MLX5_RQC_STATE_RST         0u
#define MLX5_RQC_STATE_RDY         1u

// CREATE_RQ: struct mlx5_ifc_create_rq_in_bits。固定ヘッダ32バイト
// (CREATE_TISと同じ、reserved_at_40が0xc0=24バイト)の直後にrq_context
// (struct mlx5_ifc_rqc_bits、240バイト、in[32..271])、さらにその内部
// (rqc相対byte48=in[80]から)にwq(struct mlx5_ifc_wq_bits、192バイト、
// in[80..271])が埋め込まれる -- CQ/EQと異なりpas[]は"wq"構造体自身の
// 末尾(wq相対byte192=in[272])に続く。フィールドのバイトオフセットは
// mlx5_ifc.hの累積ビットオフセットから手計算した:
//
// - rqc相対byte1(in[33])上位nibble: state -- 作成時は常にRST(0)、
//   MODIFY_RQで後からRDYへ遷移させる(en_main.cと同じ2段階ライフサイクル)。
// - rqc相対byte9-11(in[41..43]): cqn。
// - wq相対byte0(in[80])上位nibble: wq_type -- CYCLIC(1)固定
//   (striding RQ等の高度な機能は使わない)。
// - wq相対byte9-11(in[89..91]): pd。
// - wq相対byte13-15(in[93..95]): uar_page。
// - wq相対byte16-23(in[96..103]): dbr_addr(64bit BE) -- MLX5_RQ_DBR_ADDR。
// - wq相対byte33(in[113])下位5bit: log_wq_stride -- 4(2^4=16バイト、
//   struct mlx5_wqe_data_seg1個分)。
// - wq相対byte34(in[114])下位5bit: log_wq_pg_sz -- 0(4KB)。
// - wq相対byte35(in[115])下位5bit: log_wq_sz -- 8(2^8=256エントリ、
//   mlx5.hのMLX5_RQ_NUM_WQES参照)。
// - wq相対byte192(in[272]、8バイト): pas[0] -- MLX5_RQ_WQE_ADDR
//   (1ページ=256エントリ×16バイト)。
//
// WQE自体(struct mlx5_wqe_data_seg、byte_count/lkey/addr各BE)は
// MLX5_RQ_WQE_ADDRに256個分事前に組み立て、各々がMLX5_RQ_DATA_ADDR側の
// 専用受信バッファ(1個2048バイト)を指すようにする -- ドアベルを
// 都度鳴らして動的に補充する設計にはせず、作成時に全エントリを
// 埋めきる最小実装(このプロジェクトのポーリング専用方針、CLAUDE.md
// 「ConnectX(mlx5) HCA初期化」節と同じ考え方)。
static int mlx5_create_rq(mlx5_dev_t *dev, unsigned rxq_idx, uint32_t cqn, uint32_t pdn, uint32_t uarn, uint32_t mkey, uint32_t *out_rqn) {
    volatile uint8_t *wqe_ring = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->rxq[rxq_idx].wqe_cpu;
    for (unsigned i = 0; i < MLX5_RQ_NUM_WQES; i++) {
        volatile uint8_t *wqe = wqe_ring + (uint64_t)i * 16u;
        // RX headroom(mlx5.hのMLX5_RX_HEADROOM参照): NICがフレームを
        // スロット先頭+HEADROOMへ書くようにアドレスをずらし、書き込み可能
        // 長も同じだけ縮める(スロット末尾を越えて書かないため)。これで
        // 受信フレームのTCPペイロードが8整列に着地する。
        uint32_t rq_buf_len = MLX5_RQ_BUF_PER_WQE - MLX5_RX_HEADROOM;
        uint64_t buf_pa = mlx5_dma_addr(
            (volatile void *)(uintptr_t)((uint64_t)dev->rxq[rxq_idx].data_cpu
                                         + (uint64_t)i * MLX5_RQ_BUF_PER_WQE + MLX5_RX_HEADROOM));
        wqe[0] = (uint8_t)(rq_buf_len >> 24);
        wqe[1] = (uint8_t)(rq_buf_len >> 16);
        wqe[2] = (uint8_t)(rq_buf_len >> 8);
        wqe[3] = (uint8_t)rq_buf_len;
        wqe[4] = (uint8_t)(mkey >> 24);
        wqe[5] = (uint8_t)(mkey >> 16);
        wqe[6] = (uint8_t)(mkey >> 8);
        wqe[7] = (uint8_t)mkey;
        for (unsigned b = 0; b < 8; b++) {
            wqe[8 + b] = (uint8_t)(buf_pa >> (56 - 8 * b));
        }
    }

    // 実機で発見した本物のバグ(修正済み、CLAUDE.md「モニタ機能でCQ/RQ
    // 無応答の原因を特定」節参照): ドアベルレコードをゼロクリアした
    // *まま*にしていた。Linux mlx5_core(`drivers/net/ethernet/mellanox/
    // mlx5/core/wq.h`)の`mlx5_wq_cyc_update_db_record()`(RQ/SQ共通の
    // cyclic WQが使う関数、`*wq->db = cpu_to_be32(wq->wqe_ctr)`)による
    // と、dbrの先頭32bit(BE)は「HWへ渡した(=消費してよい)WQEの累計数」
    // を表す producer カウンタであり、WQEをリングへ書き込むだけでは
    // 不十分 -- ドアベルレコードでその数をHWへ明示的に伝える必要がある。
    // 本実装は256エントリ全てを作成時に一括で埋める設計(上記コメント
    // 参照)なので、この値は常にMLX5_RQ_NUM_WQES(256)で固定してよい
    // (SQ側は`mlx5_sq_send_test_frame()`が送信のたびに同じ式
    // `sq_dbr[0..3]=BE32(new_pc)`で正しく更新している一方、RQ側は
    // CREATE_RQ実装時にこの更新自体を書き忘れていた)。
    //
    // 症状(実機`mlx5stat`のモニタ出力で確認): ドアベル未更新のRQは
    // HWから見て「利用可能なWQEが0個」の状態のまま -- 対向ポートの
    // MAC自体はフレームを正しく受信していた(相手ポートのPPCNT
    // IEEE802.3 rx_frames_ok/rx_octets_okがテスト送信のたびに1/64ずつ
    // 正しく増加し、fcs_err/align_err等のエラー系カウンタは終始0)のに、
    // 受信側RQのhw_counter/sw_counterと、そのRQに紐付くCQの
    // producer_counterが全て0のまま一切動かなかった -- 「フレームは
    // 物理的に正しく届いているのに、RQが一つもWQEを持っていないと
    // HWが認識しているため完了を書けない」という今回のバグと完全に
    // 整合する。
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->rxq[rxq_idx].dbr_cpu;
    for (unsigned i = 0; i < MLX5_RQ_DBR_SIZE; i++) {
        dbr[i] = 0;
    }
    dbr[0] = (uint8_t)(MLX5_RQ_NUM_WQES >> 24);
    dbr[1] = (uint8_t)(MLX5_RQ_NUM_WQES >> 16);
    dbr[2] = (uint8_t)(MLX5_RQ_NUM_WQES >> 8);
    dbr[3] = (uint8_t)MLX5_RQ_NUM_WQES;

    uint8_t in[272 + 8];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_RQ >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_RQ & 0xffu);

    in[33] = (uint8_t)(MLX5_RQC_STATE_RST << 4);
    in[41] = (uint8_t)(cqn >> 16);
    in[42] = (uint8_t)(cqn >> 8);
    in[43] = (uint8_t)cqn;

    // byte0(wq先頭) = wq_type(4bit,MSB) | wq_signature(1bit) |
    // end_padding_mode(2bit) | cd_slave(1bit)。実ドライバ
    // (en/params.cのrq_end_pad_mode())はLRO無効時(このプロジェクトは
    // LRO自体を実装していないため常に該当)は常にMLX5_WQ_END_PAD_MODE_
    // ALIGN(1)を設定しており、0(NONE)のまま送ると実機でCREATE_RQが
    // BAD_PARAM_ERR(status=0x03)で拒否されることを確認した -- 実ドライバの
    // デフォルトを踏襲するよう修正した。
    in[80] = (uint8_t)((MLX5_WQ_TYPE_CYCLIC << 4) | (MLX5_WQ_END_PAD_MODE_ALIGN << 1));
    in[89] = (uint8_t)(pdn >> 16);
    in[90] = (uint8_t)(pdn >> 8);
    in[91] = (uint8_t)pdn;
    // uar_page(wq相対byte13-15)は実ドライバのmlx5e_create_rq()/
    // mlx5e_build_rq_param()のいずれもRQに対しては一切設定していない
    // (SQ専用のフィールドと判明、en/params.cのmlx5e_build_sq_param()参照)
    // ため、ここでは書かない(uarnは将来SQ実装時に使う想定でシグネチャ
    // には残す)。
    (void)uarn;

    uint64_t dbr_pa = mlx5_dma_addr((volatile void *)(uintptr_t)(uint64_t)dev->rxq[rxq_idx].dbr_cpu);
    for (unsigned b = 0; b < 8; b++) {
        in[96 + b] = (uint8_t)(dbr_pa >> (56 - 8 * b));
    }

    in[113] = 4u; // log_wq_stride=4 (16バイト)
    in[114] = 0u; // log_wq_pg_sz=0 (4KB)
    in[115] = 8u; // log_wq_sz=8 (256エントリ)

    uint64_t wqe_pa = mlx5_dma_addr((volatile void *)(uintptr_t)(uint64_t)dev->rxq[rxq_idx].wqe_cpu);
    for (unsigned b = 0; b < 8; b++) {
        in[272 + b] = (uint8_t)(wqe_pa >> (56 - 8 * b));
    }

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_RQ: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_rqn) {
        *out_rqn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// MODIFY_RQ: struct mlx5_ifc_modify_rq_in_bits。固定ヘッダ32バイト
// (rq_state(4bit)+reserved(4bit)+rqn(24bit)がbyte8-11、modify_bitmaskが
// byte16-23)の直後にrq_context(rqc、240バイト、in[32..271]) -- pas[]は
// 送らない(バッファ構成は変更しない、状態遷移のみ)。RST->RDYの1回だけ
// 対応する(このプロジェクトの用途では十分)。
static int mlx5_modify_rq_to_rdy(mlx5_dev_t *dev, uint32_t rqn) {
    uint8_t in[272];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_MODIFY_RQ >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_MODIFY_RQ & 0xffu);

    in[8] = (uint8_t)(MLX5_RQC_STATE_RST << 4); // rq_state(現在の状態)
    in[9] = (uint8_t)(rqn >> 16);
    in[10] = (uint8_t)(rqn >> 8);
    in[11] = (uint8_t)rqn;
    // modify_bitmask(in[16..23])は0のまま -- state以外のフィールドは
    // 変更しない。

    in[32 + 1] = (uint8_t)(MLX5_RQC_STATE_RDY << 4); // ctx.state(新しい状態)

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: MODIFY_RQ: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    return 0;
}

// CREATE_TIR: struct mlx5_ifc_create_tir_in_bits。固定ヘッダ32バイト
// (CREATE_TISと同じパターン)の直後にtir_context(struct
// mlx5_ifc_tirc_bits、240バイト、in[32..271])。DIRECT(単一RQへの固定
// ルーティング、RSS等のINDIRECT/hash機能は使わない)モードのみ対応:
// disp_type(tirc相対byte4上位nibble)は0固定(=DIRECT)のため明示的には
// 何も書かない。設定するのはinline_rqn(tirc相対byte29-31=in[61..63])と
// transport_domain(tirc相対byte37-39=in[69..71])のみ。
static int mlx5_create_tir(mlx5_dev_t *dev, uint32_t rqn, uint32_t tdn, uint32_t *out_tirn) {
    uint8_t in[272];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_TIR >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_TIR & 0xffu);

    in[61] = (uint8_t)(rqn >> 16);
    in[62] = (uint8_t)(rqn >> 8);
    in[63] = (uint8_t)rqn;
    in[69] = (uint8_t)(tdn >> 16);
    in[70] = (uint8_t)(tdn >> 8);
    in[71] = (uint8_t)tdn;

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_TIR: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_tirn) {
        *out_tirn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// ============================================================================
// フェーズ9.5: SQ(Send Queue)作成(CREATE_SQ)、RST->RDY遷移(MODIFY_SQ)、
// 最小Ethernetフレーム1個の送信(WQE構築+ドアベル)。
//
// このConnectXカードは2つの物理ポートをケーブルで直結したループバック構成
// (ユーザー確認済み)のため、RX経路(CREATE_RQ/CREATE_TIR/フローステア
// リング、既に実機で動作確認済み)だけでは外部にトラフィック発生源が無く
// 検証できない -- 自分でSQから1フレーム送信し、ループバック経由でRQ側の
// CQに完了(CQE)が積まれるかを見ることで、送受信経路全体を確認する。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`のstruct
// mlx5_ifc_{create_sq,modify_sq}_{in,out}_bits/struct mlx5_ifc_sqc_bits、
// `include/linux/mlx5/qp.h`のstruct mlx5_wqe_{ctrl,eth,data}_seg、
// `include/linux/mlx5/doorbell.h`のMLX5_BF_OFFSET/mlx5_write64()、
// `drivers/net/ethernet/mellanox/mlx5/core/en_main.c`のSQ作成コード、
// `en/txrx.h`のmlx5e_notify_hw()/mlx5e_post_nop()、`en_tx.c`の
// mlx5e_sq_xmit_wqe()、`en/params.c`のmlx5e_build_sq_param_common()/
// build_sq_param()から取得。
// ============================================================================

#define MLX5_CMD_OP_CREATE_SQ 0x904u
#define MLX5_CMD_OP_MODIFY_SQ 0x905u
#define MLX5_SQC_STATE_RST    0u
#define MLX5_SQC_STATE_RDY    1u
#define MLX5_SQC_STATE_ERR    3u  // mlx5_monitor_dump_dev()のstate表示コメント参照

// CREATE_SQ: struct mlx5_ifc_create_sq_in_bits。固定ヘッダ32バイト
// (CREATE_RQと全く同じパターン、reserved_at_40[0xc0]=24バイト)の直後に
// sq_context(struct mlx5_ifc_sqc_bits、240バイト、in[32..271])、さらに
// その内部(sqc相対byte48=in[80]から)にwq(RQと共通のstruct
// mlx5_ifc_wq_bits、192バイト、in[80..271])が埋め込まれる。mlx5_ifc.hの
// struct mlx5_ifc_sqc_bitsを実測(累積ビットオフセットから手計算)した
// ところ、cqn/wqの位置がCREATE_RQのrqcと偶然同じオフセットになった
// (先頭48バイトの個々のフィールド名は異なるが、byte9-11=cqn、byte48から
// wq、という構造は共通):
//
// - sqc相対byte1(in[33])上位nibble: state -- RQと同じくRST(0)で作成し、
//   MODIFY_SQで後からRDYへ遷移させる。
// - sqc相対byte9-11(in[41..43]): cqn -- RQとは別の専用CQ(呼び出し元が
//   MLX5_SQ_CQ_BUF_ADDR/DBR_ADDRで作成したCQ)。
// - sqc相対byte45-47(in[77..79]): tis_num_0 -- CREATE_TISで得たtisn
//   (RQのrqcには存在しないSQ固有のフィールド、TIS紐付けはここだけで
//   完結しWQE側には設定不要、en_tx.cのmlx5e_sq_xmit_wqe()参照)。
// - wq相対byte0(in[80])上位nibble: wq_type -- CYCLIC(1)固定
//   (en_main.cのSQ作成コードが無条件でMLX5_WQ_TYPE_CYCLICを設定)。
// - wq相対byte9-11(in[89..91]): pd。
// - wq相対byte13-15(in[93..95]): uar_page -- RQは実ドライバがこの
//   フィールドを一切設定しないため省略したが(mlx5_create_rq()コメント
//   参照)、SQはドアベル/BlueFlameの宛先を決めるため必須
//   (en_main.cのSQ作成コード: MLX5_SET(wq, wq, uar_page, csp->uar_page))。
// - wq相対byte16-23(in[96..103]): dbr_addr(64bit BE)。
// - wq相対byte33(in[113])下位5bit: log_wq_stride -- 6(2^6=64バイト、
//   qp.hのMLX5_SEND_WQE_BB、ctrl_seg+eth_seg+data_seg1組分、
//   en/params.cのmlx5e_build_sq_param_common()参照 -- RQのlog_wq_stride
//   =4(16バイト)とは異なる値になる点に注意)。
// - wq相対byte34(in[114])下位5bit: log_wq_pg_sz -- 0(4KB)。
// - wq相対byte35(in[115])下位5bit: log_wq_sz -- 4(2^4=16WQEBB、
//   mlx5.hのMLX5_SQ_WQE_SIZE参照 -- テストフレーム1個の送信に十分な
//   最小リング)。
// - wq相対byte192(in[272]、8バイト): pas[0] -- MLX5_SQ_WQE_ADDR。
static int mlx5_create_sq(mlx5_dev_t *dev, uint32_t cqn, uint32_t pdn, uint32_t uarn, uint32_t tisn, uint32_t *out_sqn) {
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->sq_dbr_cpu;
    for (unsigned i = 0; i < MLX5_SQ_DBR_SIZE; i++) {
        dbr[i] = 0;
    }

    uint8_t in[272 + 8];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_SQ >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_SQ & 0xffu);

    in[32 + 1] = (uint8_t)(MLX5_SQC_STATE_RST << 4);
    in[32 + 9] = (uint8_t)(cqn >> 16);
    in[32 + 10] = (uint8_t)(cqn >> 8);
    in[32 + 11] = (uint8_t)cqn;
    // 実機で見つかった本物のバグ(修正済み): tis_num_0(下記)だけを設定し
    // tis_lst_sz(sqc相対byte32-33、16bit)を0のままにしていた。実ドライバ
    // (en_main.cのmlx5e_create_sq()呼び出し元、csp.tis_lst_sz=1)は必ず
    // 1を設定している -- 「tis_num_0にTIS番号を書いたのにリスト長が0」
    // という自己矛盾した状態になり、CREATE_SQ自体は成功する(構文的には
    // 妥当)もののMLX5_OPCODE_SENDでの実送信時にHWがTISを解決できず即座に
    // SQがstate=ERR(3)へ落ちる(hw_counterも進まない、CQEも一切出ない)
    // という完全に沈黙した実機バグの原因だった。NOP(opcode=0x00)はTIS/
    // 送信経路を一切通らないため影響を受けず成功していたことが、
    // ds_cnt/eth_seg/data_seg/inlineヘッダ全ての組み合わせを潰しても
    // 再現しなかった理由。
    in[32 + 32] = 0x00u;
    in[32 + 33] = 0x01u; // tis_lst_sz=1
    in[32 + 45] = (uint8_t)(tisn >> 16);
    in[32 + 46] = (uint8_t)(tisn >> 8);
    in[32 + 47] = (uint8_t)tisn;

    in[80] = (uint8_t)(MLX5_WQ_TYPE_CYCLIC << 4);
    in[89] = (uint8_t)(pdn >> 16);
    in[90] = (uint8_t)(pdn >> 8);
    in[91] = (uint8_t)pdn;
    in[93] = (uint8_t)(uarn >> 16);
    in[94] = (uint8_t)(uarn >> 8);
    in[95] = (uint8_t)uarn;

    uint64_t dbr_pa = mlx5_dma_addr((volatile void *)(uintptr_t)(uint64_t)dev->sq_dbr_cpu);
    for (unsigned b = 0; b < 8; b++) {
        in[96 + b] = (uint8_t)(dbr_pa >> (56 - 8 * b));
    }

    // 2026-08-09、TCPゼロコピー送信(2 data_seg構成)対応を試みた際、
    // log_wq_stride=7(128バイト固定ストライド)を実機で試したところ
    // CREATE_SQがBAD_PARAM_ERR(status=0x03)で拒否された。Linux
    // en/params.cのmlx5e_build_sq_param_common()を確認したところ、
    // log_wq_strideは常に`ilog2(MLX5_SEND_WQE_BB)`=6(64バイト)固定で
    // あり、可変長WQE(複数data_seg)はストライド拡張ではなく producer
    // counter(sq->pc)をWQEBB単位で管理し、1WQEが複数WQEBBを消費したら
    // pcをその数だけ進める設計(en_tx.cのmlx5e_txwqe_complete()の
    // `sq->pc += wi->num_wqebbs`参照)と判明したため、6(64バイト)へ
    // 戻した -- mlx5_net.c側でWQEBB単位のpc/cc管理を実装する
    // (MLX5_SQ_WQE_STRIDE参照)。
    in[113] = 6u; // log_wq_stride=6 (64バイト、MLX5_SEND_WQE_BB)
    in[114] = 0u; // log_wq_pg_sz=0 (4KB)
    in[115] = 4u; // log_wq_sz=4 (16 WQEBB)

    uint64_t wqe_pa = mlx5_dma_addr((volatile void *)(uintptr_t)(uint64_t)dev->sq_wqe_cpu);
    for (unsigned b = 0; b < 8; b++) {
        in[272 + b] = (uint8_t)(wqe_pa >> (56 - 8 * b));
    }

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_SQ: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_sqn) {
        *out_sqn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// MODIFY_SQ: struct mlx5_ifc_modify_sq_in_bits。固定ヘッダ32バイト
// (sq_state(4bit)+reserved(4bit)+sqn(24bit)がbyte8-11、modify_bitmaskが
// byte16-23 -- MODIFY_RQと全く同じ配置)の直後にsq_context(sqc、
// 240バイト、in[32..271])。cur_state->new_stateの任意の遷移に対応する
// (2026-08-08、mlx5_recover_sq()のERR->RST遷移に使うため、RST->RDY
// 固定だった実装を一般化した)。
static int mlx5_modify_sq_state(mlx5_dev_t *dev, uint32_t sqn, uint8_t cur_state, uint8_t new_state) {
    uint8_t in[272];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_MODIFY_SQ >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_MODIFY_SQ & 0xffu);

    in[8] = (uint8_t)(cur_state << 4); // sq_state(現在の状態)
    in[9] = (uint8_t)(sqn >> 16);
    in[10] = (uint8_t)(sqn >> 8);
    in[11] = (uint8_t)sqn;
    // modify_bitmask(in[16..23])は0のまま -- MODIFY_RQと同じく実機で
    // state遷移のみでも受理されることを確認する。

    in[32 + 1] = (uint8_t)(new_state << 4); // ctx.state(新しい状態)

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: MODIFY_SQ(sqn=%u, %u->%u): command status=0x%02x syndrome=0x%08x\n",
                    sqn, cur_state, new_state, status, syndrome);
        return -1;
    }
    return 0;
}

static int mlx5_modify_sq_to_rdy(mlx5_dev_t *dev, uint32_t sqn) {
    return mlx5_modify_sq_state(dev, sqn, MLX5_SQC_STATE_RST, MLX5_SQC_STATE_RDY);
}

// ============================================================================
// フェーズ9.6: PAOS(Port Administrative and Operational Status)レジスタで
// ポートのadmin stateをUPへ設定する。
//
// TX(SQ)は実機で完全に機能する(hw_counter/CQE双方で確認済み)のにループ
// バック経由のRXが一切観測されない問題を切り分けた結果判明した事実:
// Linux en_main.cのmlx5e_open()は、SQ/RQ/TIR等の作成が全て終わった後に
// `mlx5e_modify_admin_state(priv->mdev, MLX5_PORT_UP)`(port.cの
// mlx5_set_port_admin_status())を必ず呼んでいる -- ConnectXのポートは
// 電源投入直後、ドライバが明示的にadmin状態をUPへ設定するまで論理的に
// 無効(DOWN)のままである可能性が高い。このプロジェクトはこれまで一度も
// このレジスタに触れていなかった。
//
// PAOSはCREATE_*系のような通常コマンドではなく、`MLX5_CMD_OP_ACCESS_REG`
// (opcode 0x805)という汎用の「アクセスレジスタ」コマンド経由でread/write
// する(port.cのmlx5_access_reg()/mlx5_core_access_reg()参照)。
// struct mlx5_ifc_access_register_in_bits: 固定ヘッダ16バイト
// (opcode/reserved/reserved/op_mod)の直後にreserved(2B)+register_id
// (2B、in[10..11])+argument(4B、in[12..15]、常に0)+register_data[]
// (可変長、in[16]から)。op_mod=0がWRITE、1がREAD(MLX5_ACCESS_REGISTER_
// IN_OP_MOD_WRITE/READ)。register_id=MLX5_REG_PAOS=0x5006(driver.hの
// enum mlx5_reg)。
//
// struct mlx5_ifc_paos_reg_bits(16バイト、register_data[]の中身):
// - byte0: swid -- 0のまま。
// - byte1: local_port -- 1固定(mlx5_set_port_admin_status()と同じ)。
// - byte2: reserved(上位nibble)+admin_status(下位nibble) -- UP=1。
// - byte4上位bit(MSB): ase(Admin Status Enable、この書き込みで
//   admin_statusを実際に反映させるフラグ) -- 1。
#define MLX5_CMD_OP_ACCESS_REG 0x805u
#define MLX5_REG_PAOS          0x5006u
static int mlx5_set_port_admin_status_up(mlx5_dev_t *dev) {
    uint8_t in[16 + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    // op_mod(in[6..7]) = WRITE(0) -- 既に0のまま。
    in[10] = (uint8_t)(MLX5_REG_PAOS >> 8);
    in[11] = (uint8_t)(MLX5_REG_PAOS & 0xffu);
    // argument(in[12..15]) = 0のまま。

    in[16 + 1] = 0x01u; // local_port=1
    in[16 + 2] = 0x01u; // admin_status=UP(1、下位nibble)
    in[16 + 4] = 0x80u; // ase=1(bit7)

    uint8_t out[16 + 16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5: PAOS(set admin UP): mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: PAOS(set admin UP): command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }
    return 0;
}

// PAOSのoper_status(実際のリンク状態、admin_statusとは別 -- PHYの
// 自動ネゴシエーション完了を要する)を読む。mlx5_hca_bringup()が
// admin状態をUPへ設定した直後、実際にリンクアップするまで待つのに使う。
static int mlx5_query_port_oper_status(mlx5_dev_t *dev, uint8_t *out_oper_status) {
    uint8_t in[16 + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    in[6] = 0x00; in[7] = 0x01; // op_mod=READ(1)
    in[10] = (uint8_t)(MLX5_REG_PAOS >> 8);
    in[11] = (uint8_t)(MLX5_REG_PAOS & 0xffu);
    in[16 + 1] = 0x01u; // local_port=1

    uint8_t out[16 + 16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        return -1;
    }
    *out_oper_status = (uint8_t)(out[16 + 3] & 0x0Fu);
    return 0;
}

// フェーズ9.7: PMTU(Port MTU)レジスタでポートの最大フレーム長を設定する
// (ジャンボフレーム対応、2026-08-09)。
//
// mlx5_net.cのRQ/TXバッファをMLX5_JUMBO_MAX_LEN(10240、mlx5.hコメント
// 参照、RP1のeth.hのETH_JUMBO_MAX_LENと同値)へ拡張したのに合わせ、
// ConnectX自身のポートMTUも引き上げる必要がある -- Linux port.cの
// mlx5_set_port_mtu()/mlx5_query_port_max_mtu()、en.hのMLX5E_SW2HW_MTU()
// マクロを実際に取得して確認したところ(推測しない、このプロジェクト
// 一貫の方法論)、admin_mtuフィールドに書く値は`sw_mtu + hard_mtu`
// (hard_mtu = ETH_HLEN+VLAN_HLEN+ETH_FCS_LEN = 22、en_main.cの
// mlx5e_build_rq_frags_info()等が参照するparams->hard_mtu)というワイヤ上
// の実フレーム最大長そのもの(IPペイロードのMTUではない)と判明した --
// つまりMLX5_JUMBO_MAX_LEN(RQバッファ/TXステージバッファのサイズ、
// ワイヤ上のフレーム最大長として設計した値)をそのままadmin_mtuへ書けば
// よく、別途sw_mtuを逆算する必要は無い。
//
// PMTUはPAOSと同じ`MLX5_CMD_OP_ACCESS_REG`(opcode 0x805)経由でread/
// writeする。register_id=MLX5_REG_PMTU=0x5003(port.cの実際の呼び出し
// `mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out), MLX5_REG_
// PMTU, 0, 0/1)`から確認)。struct mlx5_ifc_pmtu_reg_bits(16バイト、
// mlx5_ifc.hから実際に取得):
// - byte1: local_port -- 1固定(PAOSと同じ規約)。
// - byte4-5: max_mtu(BE16) -- このHCA/ポートが物理的にサポートする
//   最大フレーム長、読み取り専用。
// - byte8-9: admin_mtu(BE16) -- 書き込み対象。
// - byte12-13: oper_mtu(BE16) -- 実際に適用されている値、読み取り専用。
#define MLX5_REG_PMTU 0x5003u

// PMTUのmax_mtuを読む(mlx5_set_port_mtu()が書こうとする値がこれを
// 超えないかの確認に使う)。
static int mlx5_query_port_max_mtu(mlx5_dev_t *dev, uint16_t *out_max_mtu) {
    uint8_t in[16 + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    in[6] = 0x00; in[7] = 0x01; // op_mod=READ(1)
    in[10] = (uint8_t)(MLX5_REG_PMTU >> 8);
    in[11] = (uint8_t)(MLX5_REG_PMTU & 0xffu);
    in[16 + 1] = 0x01u; // local_port=1

    uint8_t out[16 + 16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        return -1;
    }
    *out_max_mtu = (uint16_t)(((uint16_t)out[16 + 4] << 8) | out[16 + 5]);
    return 0;
}

// PMTUのadmin_mtuへdesired_mtu(ワイヤ上の最大フレーム長そのもの、上記
// コメント参照)を書く。desired_mtuがmax_mtu(HW上限)を超える場合は
// max_mtuへ切り詰める(黙って拒否されて意味不明な失敗になるより安全側)。
// 成功時、実際に適用した値(切り詰め後)を*out_applied_mtuへ書く --
// 呼び出し元(mlx5_hca_bringup())がdev->port_mtuへ保存し、mlx5_net.cが
// netif_t.mss_capをこの実際の値から逆算する(固定値のジャンボMSSを
// 使うと、実機のHW上限[本ソフトで実測10000]を超えるTCPセグメントを
// 送ってしまう恐れがあるため)。
static int mlx5_set_port_mtu(mlx5_dev_t *dev, uint16_t desired_mtu, uint16_t *out_applied_mtu) {
    uint16_t max_mtu = 0;
    if (mlx5_query_port_max_mtu(dev, &max_mtu) != 0) {
        uart_printf("mlx5: PMTU(query max_mtu) failed\n");
        return -1;
    }
    uint16_t mtu = desired_mtu;
    if (max_mtu != 0 && mtu > max_mtu) {
        uart_printf("mlx5: PMTU: desired_mtu=%u exceeds max_mtu=%u, clamping\n",
                    (unsigned)desired_mtu, (unsigned)max_mtu);
        mtu = max_mtu;
    }

    uint8_t in[16 + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    // op_mod(in[6..7]) = WRITE(0) -- 既に0のまま。
    in[10] = (uint8_t)(MLX5_REG_PMTU >> 8);
    in[11] = (uint8_t)(MLX5_REG_PMTU & 0xffu);

    in[16 + 1] = 0x01u; // local_port=1
    in[16 + 8] = (uint8_t)(mtu >> 8); // admin_mtu(BE16)
    in[16 + 9] = (uint8_t)mtu;

    uint8_t out[16 + 16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5: PMTU(set admin_mtu): mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: PMTU(set admin_mtu): command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }
    uart_printf("mlx5: PMTU(set admin_mtu=%u) ok (max_mtu=%u)\n", (unsigned)mtu, (unsigned)max_mtu);
    *out_applied_mtu = mtu;
    return 0;
}

// ============================================================================
// フェーズ(a): RoCEv2アドレッシング土台(GIDテーブル)。ConnectX RoCEv2
// NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)フェーズ(a)。
// QPはまだ作らない -- 「roce」総合capabilityビット・詳細RoCE capability・
// GIDテーブル(SET_ROCE_ADDRESS/QUERY_ROCE_ADDRESS)の読み書きのみ。
// バイトオフセットは全てtorvalds/linux(include/linux/mlx5/mlx5_ifc.h/
// device.h)から本セッションで実際に取得して裏取り済み(推測しない、この
// プロジェクト一貫の方法論)。
// ============================================================================

#define MLX5_CMD_OP_QUERY_ROCE_ADDRESS 0x760u
#define MLX5_CMD_OP_SET_ROCE_ADDRESS   0x761u
// device.hのenum(MLX5_ROCE_L3_TYPE_IPV4=0/_IPV6=1、MLX5_ROCE_VERSION_1=0/
// _2=2)で確認済み。SET_ROCE_ADDRESSに書くのはこのenum値そのものであり、
// 詳細capability(下記mlx5_query_hca_cap_roce())が返すビットマップ値
// (_CAP接尾辞、1<<enum値)とは別物 -- 混同しないこと。
#define MLX5_ROCE_L3_TYPE_IPV4 0u
#define MLX5_ROCE_VERSION_2    2u

// IPv4-mapped IPv6形式のRoCEv2 GID(::ffff:a.b.c.d)を構築する。
// ipv4_host_orderはホストバイトオーダーのIPv4アドレス(net.hのip_from_
// octets()等で構築)。
void mlx5_build_roce_gid_v4(uint32_t ipv4_host_order, uint8_t out_gid[16]) {
    for (unsigned i = 0; i < 10; i++) {
        out_gid[i] = 0;
    }
    out_gid[10] = 0xFF;
    out_gid[11] = 0xFF;
    out_gid[12] = (uint8_t)(ipv4_host_order >> 24);
    out_gid[13] = (uint8_t)(ipv4_host_order >> 16);
    out_gid[14] = (uint8_t)(ipv4_host_order >> 8);
    out_gid[15] = (uint8_t)ipv4_host_order;
}

// SET_ROCE_ADDRESS(opcode 0x761)。struct mlx5_ifc_set_roce_address_in_
// bits(48バイト、mlx5_ifc.h:5143-5157)のレイアウト(本セッションで実際に
// 取得・裏取り済み):
// - in[8..9]: roce_address_index(BE16)
// - in[16..31]: source_l3_address(GIDそのもの)
// - in[34..39]: source_mac_47_32+source_mac_31_0が連続しているため単純に
//   mac[0..5]を6バイトそのままコピー(Linux ether_addr_copy()と同じ規約)
// - in[42]下位nibble: roce_l3_type = MLX5_ROCE_L3_TYPE_IPV4固定
// - in[43]: roce_version = MLX5_ROCE_VERSION_2固定
// vhca_port_num(in[11]下位nibble)はnum_vhca_ports capability>0の場合のみ
// 設定する規約(Linux mlx5_core_roce_gid_set()と同じ)だが、このプロジェクト
// は複数vhcaポート構成を使わないため常に0のままでよい。
int mlx5_set_roce_address(mlx5_dev_t *dev, uint32_t index, const uint8_t gid[16], const uint8_t mac[6]) {
    uint8_t in[16 + 32] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_SET_ROCE_ADDRESS >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_SET_ROCE_ADDRESS & 0xffu);
    in[8] = (uint8_t)(index >> 8);
    in[9] = (uint8_t)(index & 0xffu);

    for (unsigned i = 0; i < 16; i++) {
        in[16 + i] = gid[i];
    }
    for (unsigned i = 0; i < 6; i++) {
        in[34 + i] = mac[i];
    }
    in[42] = (uint8_t)(MLX5_ROCE_L3_TYPE_IPV4 & 0x0Fu);
    in[43] = MLX5_ROCE_VERSION_2;

    uint8_t out[16 + 32];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5: SET_ROCE_ADDRESS(index=%u): mlx5_cmd_exec failed rc=%d\n",
                    (unsigned)index, rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: SET_ROCE_ADDRESS(index=%u): command status=0x%02x syndrome=0x%08x\n",
                    (unsigned)index, status, syndrome);
        return -1;
    }
    return 0;
}

// ============================================================================
// フェーズ(b): RC QP。ConnectX RoCEv2 NVMe-oF実装計画
// (~/.claude/plans/peppy-wobbling-lamport.md)フェーズ(b)。
//
// struct mlx5_ifc_qpc_bits(232バイト、mlx5_ifc.h:3652-3793)の全フィールド
// バイトオフセットは本セッションで実際に取得・裏取り済み(コメント中の
// 「相対byteNN」は全てqpc[0]起点)。CREATE_QP/RST2INIT_QP/INIT2RTR_QP/
// RTR2RTS_QP/QUERY_QP/DESTROY_QPいずれもLinux qpc.c(drivers/infiniband/
// hw/mlx5/qpc.c)のmlx5_core_qp_modify()で確認した通り、各コマンドの
// 入力は「固定24バイトヘッダ(opcode/uid/reserved/op_mod/qpn/reserved/
// opt_param_mask/ece)+qpc(232バイト)」が共通レイアウト(CREATE_QPのみ
// 末尾にwq_umem_*+pas[]が追加で付く)。
//
// opt_param_mask(どのqpcフィールドが"追加の任意上書き"として有効かを示す
// ビットマスク、enum mlx5_qp_optpar、qp.h)はdrivers/infiniband/hw/mlx5/
// qp.cのopt_mask[cur][new][st]テーブルを実際に確認して転記した値を使う
// (推測しない) -- 同テーブルに[RST][INIT]のエントリが無い(C言語の
// 静的配列でデフォルト0になる)ことから、RST2INIT_QPのopt_param_maskは
// 常に0だと判明した(pd/ポート番号/アクセス権等はこの遷移では"任意"では
// なく常に必須のフィールドとして扱われる)。
// ============================================================================

#define MLX5_CMD_OP_CREATE_QP     0x500u
#define MLX5_CMD_OP_DESTROY_QP    0x501u
#define MLX5_CMD_OP_RST2INIT_QP   0x502u
#define MLX5_CMD_OP_INIT2RTR_QP   0x503u
#define MLX5_CMD_OP_RTR2RTS_QP    0x504u
#define MLX5_CMD_OP_QUERY_QP      0x50bu
#define MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT 0x755u

#define MLX5_QP_ST_RC          0x0u  // include/linux/mlx5/qp.hのenum(MLX5_QP_ST_RC)で確認済み
#define MLX5_QP_PM_MIGRATED    0x3u  // 同qp.h
#define MLX5_NON_ZERO_RQ       0x0u  // 同qp.h(通常のcyclic RQ、SRQ/RMP/XRQではない)
#define IB_MTU_1024            0x3u  // include/rdma/ib_verbs.hのenum ib_mtu

#define MLX5_QPC_BYTES 232u // struct mlx5_ifc_qpc_bits全体、上記コメント参照

// primary_address_path(struct mlx5_ifc_ads_bits、mlx5_ifc.h:827-867、
// 44バイト)を、qpc[24]を起点としてRoCEv2用に埋める共通ヘルパ。
// full=1なら相手GID/MAC/UDP宛先ポート等(INIT2RTR_QP専用のフィールド)も
// 埋める、full=0ならack_timeout/vhca_port_numのみ(RTR2RTS_QP用、GID/MAC
// は既にINIT2RTRで確定済みのため再送不要)。
//
// 各フィールドのads_bits内相対バイトオフセット(本セッションで実際に
// mlx5_ifc.hから取得・裏取り済み):
// - src_addr_index: 相対byte9(1バイト) -- 自分のGIDテーブルindex。
// - hop_limit: 相対byte11(1バイト) -- IP TTL相当、64固定。
// - tclass: 相対byte12下位nibble+byte13上位nibble(バイト非整列8bit
//   フィールド) -- 0固定(ToS未使用)。
// - flow_label: 相対byte13下位nibble+byte14+byte15(20bit) -- 0固定
//   (RFC6438 ECMPエントロピーはudp_sportの方で表現、rdma_calc_flow_label()
//   相当は今回固定0で簡略化)。
// - rgid_rip: 相対byte16-31(16バイト) -- 相手GID。
// - dscp: 相対byte33下位6bit -- 0固定。
// - udp_sport: 相対byte34-35(BE16) -- include/rdma/ib_verbs.hの
//   rdma_flow_label_to_udp_sport()/rdma_calc_flow_label()を実際に取得し
//   同じアルゴリズムで計算(下記mlx5_ads_calc_udp_sport()参照)。
// - eth_prio: 相対byte36の(bit1-3) -- 0固定(sl=0相当)。
// - vhca_port_num: 相対byte37(1バイト) -- 常に1(物理ポート1本のみ)。
// - rmac_47_32+rmac_31_0: 相対byte38-43(6バイト連続) -- 相手MAC、
//   Linux ether_addr_copy()と同じ単純な6バイトコピー。
// - ack_timeout: 相対byte8上位5bit(pos0-4、mask0xF8) -- 14固定
//   (ibv_rc_pingpong等の標準的なRC QP例で使われる慣習的デフォルト値、
//   4.096us*2^14≈約67ms)。IB_QP_TIMEOUT属性に対応、RTR2RTS_QPで設定。
// 2026-08-11、実機で発見: RST2INIT_QPにack_timeoutを含めるとBAD_PARAM_ERR
// (status=0x03)で拒否されることを確認した -- ack_timeoutはIBTA上RTR2RTS
// (IB_QP_TIMEOUT)でのみ意味を持つフィールドであり、Linux ib_qp.cの
// mlx5_set_path()も`attr_mask & IB_QP_TIMEOUT`の場合のみ書く。vhca_port_num
// は逆に毎回(mlx5_set_path()が呼ばれるどの遷移でも)無条件に書かれる。
// set_ack_timeoutを呼び出し元ごとに明示的に分離した。
static void mlx5_ads_fill_roce(uint8_t *ads /* qpc+24を指す、44バイト */,
                                const uint8_t remote_gid[16], const uint8_t remote_mac[6],
                                uint16_t udp_sport, int full, int set_ack_timeout) {
    ads[37] = 1; // vhca_port_num(常に設定)
    if (set_ack_timeout) {
        ads[8] = (uint8_t)(14u << 3); // ack_timeout(pos0-4、mask0xF8)=14
    }
    if (!full) {
        return;
    }
    // 実機で検証(2026-08-12、フェーズ(i)実Linuxホスト接続確認):
    // grhビット(byte5のMSB、bit0x28)を立てると、このFW上ではINIT2RTR_QP
    // コマンド自体が失敗する(state=INITのまま進まない、failed=1)ことを
    // クリーンな環境で確定的に再現した -- GSI/UD側のstruct mlx5_avでは
    // GRH存在ビットが必須(bit30常に1)だが、RC QP側のqpc.primary_address_
    // path(struct mlx5_ifc_ads_bits)では逆にこのビットに触れてはならない
    // (rre/rwe/raeと同様、このFWがqpc.adsの一部フィールドについて厳格な
    // 検証を行う一例)。GSIとRCは全く別の構造体・別のFWコマンドパスであり、
    // 両者で同じ規則が成り立つとは限らない、という教訓。既存の`ads[9]=0`
    // 以降の設定(GID/MAC/UDP宛先ポート/hop_limit)は全てQUERY_QPで正しく
    // FW側に保持されることを確認済みで、それ自体は問題ではなかった。
    ads[9] = 0; // src_addr_index(自分のGIDテーブルindex、常に0)
    ads[11] = 64; // hop_limit
    // tclass/flow_labelは0固定のまま(ads[12]/[13]の該当ビットは既に0)。
    for (unsigned i = 0; i < 16; i++) {
        ads[16 + i] = remote_gid[i];
    }
    ads[34] = (uint8_t)(udp_sport >> 8);
    ads[35] = (uint8_t)udp_sport;
    for (unsigned i = 0; i < 6; i++) {
        ads[38 + i] = remote_mac[i];
    }
}

// rdma_calc_flow_label()/rdma_flow_label_to_udp_sport()(include/rdma/
// ib_verbs.h、実際に取得・裏取り済み)と同じアルゴリズム。flow_labelは
// 本実装では常に0固定(上記mlx5_ads_fill_roce()参照)のため、
// rdma_calc_flow_label(lqpn, rqpn)側の経路(flow_label==0の場合に使われる
// フォールバック)を常に使う。
uint16_t mlx5_calc_udp_sport(uint32_t lqpn, uint32_t rqpn) {
    uint64_t v = (uint64_t)lqpn * (uint64_t)rqpn;
    v ^= v >> 20;
    v ^= v >> 40;
    uint32_t fl = (uint32_t)(v & 0x000FFFFFu);
    uint32_t fl_low = fl & 0x3FFFu;
    uint32_t fl_high = fl & 0xFC000u;
    fl_low ^= fl_high >> 14;
    return (uint16_t)(fl_low | 0xC000u);
}

// rw/rr(リモートRDMA_WRITE/READアクセス)を有効にしたPAモードMKey。
// 既存のmlx5_create_mkey_pa()(byte2=0x0C、lw/lrのみ)とは別のQP専用MKey
// として作成する(既存Ethernet用MKeyには一切触れない)。mkc相対byte2の
// ビット位置はstruct mlx5_ifc_mkc_bits(mlx5_ifc.h:4521-4536)で実際に
// 確認済み: [umr_en(bit16)][a(17)][rw(18)][rr(19)][lw(20)][lr(21)]
// [access_mode_1_0(22-23)] -- 既存のlw=1,lr=1(0x0C)にrw=1,rr=1を追加した
// 0x3C。
static int mlx5_create_mkey_pa_rw(mlx5_dev_t *dev, uint32_t pdn, uint32_t *out_mkey) {
    uint8_t in[272];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_MKEY >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_MKEY & 0xffu);

    in[16 + 2] = 0x3Cu; // umr_en=0,a=0,rw=1,rr=1,lw=1,lr=1,access_mode_1_0=0(PA)
    in[16 + 4] = 0xFFu;
    in[16 + 5] = 0xFFu;
    in[16 + 6] = 0xFFu; // qpn=0xFFFFFF(既存mlx5_create_mkey_pa()と同じ、特定QPに紐付けない汎用MKey)
    in[16 + 12] = 0x80u; // length64=1
    in[16 + 13] = (uint8_t)(pdn >> 16);
    in[16 + 14] = (uint8_t)(pdn >> 8);
    in[16 + 15] = (uint8_t)pdn;

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_MKEY(rw): command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    if (out_mkey) {
        uint32_t mkey_index = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
        *out_mkey = mkey_index << 8;
    }
    return 0;
}

// MODIFY_NIC_VPORT_CONTEXT(opcode 0x755)でnic_vport_context.roce_en=1を
// 立てる。実機で発見(2026-08-12): drivers/infiniband/hw/mlx5/main.cの
// mlx5_ib_roce_init()(port_type==ETHの場合、本プロジェクトのconfig)は
// mlx5_enable_eth()経由でmlx5_nic_vport_enable_roce()
// (drivers/net/ethernet/mellanox/mlx5/core/vport.c)を無条件に呼んでおり、
// これはmlx5_ib(RDMAサブシステム)固有の初期化ステップで、本プロジェクトが
// これまで実装してきたmlx5_core(Ethernet)相当の範囲には一切含まれて
// いなかった -- INIT2RTR_QPが実機で常にBAD_OP_ERR(status=0x02、
// syndrome=0x00e18032固定)を返し続けていた根本原因の最有力候補。
// struct mlx5_ifc_modify_nic_vport_context_in_bits(mlx5_ifc.h:8117-8133)/
// struct mlx5_ifc_nic_vport_context_bits(mlx5_ifc.h:4452-4505)/
// struct mlx5_ifc_modify_nic_vport_field_select_bits(mlx5_ifc.h:8099-8115)
// を実際に取得しバイトオフセットを手計算で確定した:
//   in[0..1]=opcode(BE16)、in[8]=other_vport(0=自分のvport)、
//   in[15] mask0x02 = field_select.roce_en、
//   in[259] mask0x01 = nic_vport_context.roce_en(struct本体はbyte256から
//   開始、その先頭4バイトワード内の最終ビット)。
static int mlx5_nic_vport_enable_roce(mlx5_dev_t *dev) {
    // 実機で発見(2026-08-12): 264バイトへ切り詰めるとstatus=0x51
    // (BAD_OUTP_LEN_ERR)で拒否された -- 他コマンド(QUERY_HCA_CAP等)で
    // 通用していた「必要なフィールド分だけに絞ってよい」規約がこの
    // コマンドには通用しなかった。実ドライバ(kvzalloc(MLX5_ST_SZ_BYTES(
    // modify_nic_vport_context_in)))と同じくnic_vport_context構造体
    // 全体(reserved_at_80[240B]+nic_vport_context固定部256B、可変長の
    // current_uc_mac_address[]手前まで)をフルサイズ(16+4+240+256=516B)
    // で送る。
    uint8_t in[516];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT & 0xffu);
    in[15] |= 0x02u; // field_select.roce_en=1
    in[259] |= 0x01u; // nic_vport_context.roce_en=1

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5: MODIFY_NIC_VPORT_CONTEXT(roce_en): mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: MODIFY_NIC_VPORT_CONTEXT(roce_en): command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }
    uart_printf("mlx5: MODIFY_NIC_VPORT_CONTEXT(roce_en=1) ok\n");
    return 0;
}

// CREATE_QP: struct mlx5_ifc_create_qp_{in,out}_bits(mlx5_ifc.h:9459-9497、
// 実際に取得・裏取り済み)。inレイアウト: 固定ヘッダ24バイト(opcode(2)+
// uid(2)+reserved(2)+op_mod(2)+qpc_ext(1bit)+reserved(7bit)+input_qpn
// (3byte)+reserved(4byte)+opt_param_mask(4byte)+ece(4byte))+qpc(232バイト、
// in[24..255])+wq_umem_offset(8B、使わない)+wq_umem_id(4B、使わない)+
// wq_umem_valid(1bit、0=物理アドレスpas[]を使う)+pas[](in[272]から、
// 8バイト/エントリ×2エントリ=RQ region先頭/SQ region先頭)。
int mlx5_qp_create_rc(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t qp_index) {
    // MODIFY_NIC_VPORT_CONTEXT(roce_en=1)は冪等(何度呼んでも安全、実
    // ドライバのmlx5_nic_vport_enable_roce()も参照カウントするだけで
    // 実害無し)なので、QP作成のたびに確実性を優先して毎回呼ぶ。
    if (mlx5_nic_vport_enable_roce(dev) != 0) {
        uart_printf("mlx5qp: MODIFY_NIC_VPORT_CONTEXT(roce_en) failed\n");
        return -1;
    }

    for (unsigned i = 0; i < sizeof(*qp); i++) {
        ((uint8_t *)qp)[i] = 0;
    }
    qp->in_use = 1;
    qp->qp_index = qp_index; // ゼロクリアの後で設定すること(前に設定すると消える)
    qp->local_psn = (uint32_t)(timer_now() & 0x00FFFFFFu); // 24bit PSN空間

    if (mlx5_alloc_uar(dev, &qp->uarn) != 0) {
        uart_printf("mlx5qp: ALLOC_UAR failed\n");
        return -1;
    }
    if (mlx5_alloc_pd(dev, &qp->pdn) != 0) {
        uart_printf("mlx5qp: ALLOC_PD failed\n");
        return -1;
    }
    if (mlx5_create_mkey_pa_rw(dev, qp->pdn, &qp->mkey) != 0) {
        uart_printf("mlx5qp: CREATE_MKEY(rw) failed\n");
        return -1;
    }

    uint64_t cq_buf = mlx5_qp_cq_buf_addr(dev, qp);
    uint64_t cq_dbr = mlx5_qp_cq_dbr_addr(dev, qp);
    if (mlx5_create_cq(dev, qp->uarn, dev->eqn, cq_buf, cq_dbr, &qp->cqn) != 0) {
        uart_printf("mlx5qp: CREATE_CQ failed\n");
        return -1;
    }

    // WQEバッファ+ドアベルをゼロクリアする(前回のQPの残骸が残らないよう、
    // 既存のRQ/SQ初期化と同じ配慮)。Device-nGnRnE領域のため
    // dcache操作は不要(volatile書き込みのみで確実にHWから見える)。
    volatile uint8_t *wqe_buf = (volatile uint8_t *)(uintptr_t)mlx5_qp_wqe_addr(dev, qp);
    for (unsigned i = 0; i < MLX5_QP_WQE_BUF_SIZE; i++) {
        wqe_buf[i] = 0;
    }
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)mlx5_qp_dbr_addr(dev, qp);
    for (unsigned i = 0; i < MLX5_QP_DBR_SIZE; i++) {
        dbr[i] = 0;
    }

    uint8_t in[24 + MLX5_QPC_BYTES + 8 + 4 + 4 + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_QP & 0xffu);
    // qpc_ext=0, input_qpn=0(新規QP), opt_param_mask=0, ece=0のまま。

    uint8_t *qpc = &in[24];
    qpc[1] = MLX5_QP_ST_RC; // st(byte1)
    qpc[5] = (uint8_t)(qp->pdn >> 16);
    qpc[6] = (uint8_t)(qp->pdn >> 8);
    qpc[7] = (uint8_t)qp->pdn; // pd(byte5-7)
    qpc[8] = (uint8_t)((IB_MTU_1024 << 5) | (20u & 0x1Fu)); // mtu(pos0-2)|log_msg_max(pos3-7)=20
    qpc[9] = (uint8_t)((8u & 0xFu) << 3); // log_rq_size=8(256エントリ)、log_rq_stride=0(pos5-7)
    qpc[10] = (uint8_t)((6u & 0xFu) << 3); // log_sq_size=6(64 WQEBB)、no_sq=0
    qpc[13] = (uint8_t)(qp->uarn >> 16);
    qpc[14] = (uint8_t)(qp->uarn >> 8);
    qpc[15] = (uint8_t)qp->uarn; // uar_page(byte13-15)
    // log_page_size(byte20下位5bit)=0(4KBページ)のまま。
    qpc[125] = (uint8_t)(qp->cqn >> 16);
    qpc[126] = (uint8_t)(qp->cqn >> 8);
    qpc[127] = (uint8_t)qp->cqn; // cqn_snd(byte125-127)
    qpc[157] = (uint8_t)(qp->cqn >> 16);
    qpc[158] = (uint8_t)(qp->cqn >> 8);
    qpc[159] = (uint8_t)qp->cqn; // cqn_rcv(byte157-159)
    uint64_t dbr_pa = mlx5_dma_addr((volatile void *)(uintptr_t)dbr);
    for (unsigned b = 0; b < 8; b++) {
        qpc[160 + b] = (uint8_t)(dbr_pa >> (56 - 8 * b));
    } // dbr_addr(byte160-167)
    qpc[172] = (uint8_t)(MLX5_NON_ZERO_RQ & 0x07u); // rq_type(byte172下位3bit)

    // wq_umem_valid=0(既に全体ゼロ初期化済み、物理アドレスpas[]方式を使う)。
    unsigned pas_off = 24 + MLX5_QPC_BYTES + 8 + 4 + 4; // = 272
    uint64_t rq_pa = mlx5_dma_addr((volatile void *)(uintptr_t)wqe_buf);
    uint64_t sq_pa = mlx5_dma_addr((volatile void *)(uintptr_t)(wqe_buf + 4096));
    for (unsigned b = 0; b < 8; b++) {
        in[pas_off + b] = (uint8_t)(rq_pa >> (56 - 8 * b));
        in[pas_off + 8 + b] = (uint8_t)(sq_pa >> (56 - 8 * b));
    }

    uint8_t out[16 + 4];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: CREATE_QP: mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: CREATE_QP: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    // create_qp_out: status(1)+reserved(3)/syndrome(4)/reserved(1)+
    // qpn(3、out[9..11]のBE値)/ece(4) = 20バイト。
    qp->qpn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    uart_printf("mlx5qp: CREATE_QP ok: qpn=%u local_psn=%u cqn=%u pdn=%u uarn=%u mkey=0x%08x\n",
                qp->qpn, qp->local_psn, qp->cqn, qp->pdn, qp->uarn, qp->mkey);
    return 0;
}

// RST2INIT_QP。opt_param_mask=0(実機で確認: qp.hのopt_mask[RST][INIT]
// テーブルにエントリが無い[C配列のデフォルト0]ことから予想した値で、実際に
// 実機でも成功した)。pd/primary_address_path.vhca_port_num(=1)を設定する。
// **実機で発見(2026-08-11)**: 当初IBTA的にはRST->INITでアクセス権
// (rre/rwe/rae、qpc byte146)も必須と考え設定していたが、含めると
// command status=0x03(BAD_PARAM_ERR)で拒否された。このFWではRST2INIT_QP
// にrre/rwe/raeを含めてはならない(pd+vhca_port_numのみが正解)と実機で
// 確定した -- 詳細はCLAUDE.md「フェーズ(b)実機診断」節参照。
int mlx5_qp_modify_rst2init(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    uint8_t in[24 + MLX5_QPC_BYTES + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_RST2INIT_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_RST2INIT_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;
    // opt_param_mask(in[16..19])=0のまま。

    uint8_t *qpc = &in[24];
    qpc[5] = (uint8_t)(qp->pdn >> 16);
    qpc[6] = (uint8_t)(qp->pdn >> 8);
    qpc[7] = (uint8_t)qp->pdn; // pd
    qpc[11] |= 0x10; // rlky=1 (bit0x5B、qpc.h確認済み) -- ib_qp.cの
                      // __mlx5_ib_modify_qp()が「!ibqp->uobject(カーネル
                      // モードQP)かつRST->INIT」で無条件に立てるビット。
                      // 本プロジェクトはベアメタルなので常にカーネルQP
                      // 相当 -- これまで見落としていた
    mlx5_ads_fill_roce(&qpc[24], NULL, NULL, 0, 0, 0); // vhca_port_num=1のみ

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: RST2INIT_QP: mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: RST2INIT_QP: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    uart_printf("mlx5qp: RST2INIT_QP(qpn=%u) ok\n", qp->qpn);
    return 0;
}

// INIT2RTR_QP。opt_param_mask=RRE|RAE|RWE|PKEY_INDEX(0x1E、qp.hのenum
// mlx5_qp_optparで確認済み: RRE=1<<1,RAE=1<<2,RWE=1<<3,PKEY_INDEX=1<<4。
// drivers/infiniband/hw/mlx5/qp.cのopt_mask[INIT][RTR][RC]テーブルで
// 確認した値からALT_ADDR_PATH/LAG_TX_AFFを除いたもの、このプロジェクトは
// セカンダリパス/LAGを使わないため)。
//
// **実機で発見した根本原因(2026-08-12、詳細はCLAUDE.md「ConnectX RoCEv2
// NVMe-oF実装計画フェーズ(b)追加調査」節参照)**: INIT2RTR_QPが常に
// BAD_OP_ERR(status=0x02, syndrome=0x00e18032)で拒否されていた真因は
// qpcフィールドの内容ではなく、`MODIFY_NIC_VPORT_CONTEXT`
// (opcode 0x755)で`nic_vport_context.roce_en=1`を一度も立てていな
// かったこと -- drivers/infiniband/hw/mlx5/main.cのmlx5_ib_roce_init()
// (port_type==ETH、本プロジェクトのconfig)がmlx5_enable_eth()経由で
// 無条件に呼ぶ`mlx5_nic_vport_enable_roce()`(mlx5_core側)は、本プロ
// ジェクトがこれまで実装してきたEthernet/NVMe-TCP相当の範囲(mlx5_core
// 機能のみ)には一切含まれていなかった、mlx5_ib固有の前提条件だった。
// `mlx5_qp_create_rc()`が毎回`mlx5_nic_vport_enable_roce()`を呼ぶ
// ようになった後は、rre/rwe/rae(qpc[146])を含めるとBAD_PARAM_ERR
// (syndrome=0x00069efe、RST2INIT_QPで一度踏んだのと同一syndrome)に
// なったため、下記の通りRDMA_WRITE/READアクセス権(rre/rwe/rae/
// log_rra_max)は未設定のまま外している -- SEND/RECVのみのping-pong
// (`mlx5qp pingpong`)は実機で双方向とも成功したが、フェーズ(c)で
// RDMA_WRITE/READを実装する際は、このアクセス権をどう有効化すれば
// 拒否されないかを改めて実機で確認すること(pd/mtu等、他のどの
// フィールドとの組み合わせが問題なのかは未特定)。
int mlx5_qp_modify_init2rtr(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t remote_qpn,
                             const uint8_t remote_gid[16], const uint8_t remote_mac[6],
                             uint32_t remote_start_psn) {
    qp->remote_qpn = remote_qpn;
    for (unsigned i = 0; i < 16; i++) {
        qp->remote_gid[i] = remote_gid[i];
    }
    for (unsigned i = 0; i < 6; i++) {
        qp->remote_mac[i] = remote_mac[i];
    }
    qp->remote_psn = remote_start_psn;
    qp->remote_udp_sport = mlx5_calc_udp_sport(qp->qpn, remote_qpn);

    uint8_t in[24 + MLX5_QPC_BYTES + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_INIT2RTR_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_INIT2RTR_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;
    uint32_t optpar = 0x02u | 0x04u | 0x08u | 0x10u; // RRE|RAE|RWE|PKEY_INDEX
    in[16] = (uint8_t)(optpar >> 24);
    in[17] = (uint8_t)(optpar >> 16);
    in[18] = (uint8_t)(optpar >> 8);
    in[19] = (uint8_t)optpar;

    uint8_t *qpc = &in[24];
    qpc[5] = (uint8_t)(qp->pdn >> 16);
    qpc[6] = (uint8_t)(qp->pdn >> 8);
    qpc[7] = (uint8_t)qp->pdn; // pd
    // RC接続の両端は同じpath MTUを使わねばならない(IBTA)。passive側
    // (nvmetrdmastart)はrdma_cm.cが相手のCM REQから読んだPATH_PACKET_
    // PAYLOAD_MTUをqp->path_mtuへ設定済み -- それを使う。未設定(0)や
    // 範囲外はIB_MTU_1024へフォールバック(active/ループバックは1024固定
    // でREQを広告するため既定のままで整合する)。1024固定のままだと
    // host jumbo接続でRDMA_WRITEがREMOTE_INVAL_REQ_ERRになる(mlx5.hの
    // mlx5_qp_t.path_mtuコメント参照)。
    uint8_t mtu_val = qp->path_mtu;
    if (mtu_val < 1u || mtu_val > 5u) mtu_val = IB_MTU_1024; // 1=256..5=4096、範囲外は1024
    qpc[8] = (uint8_t)((mtu_val << 5) | (20u & 0x1Fu)); // mtu(pos0-2)|log_msg_max(pos3-7)
    qpc[21] = (uint8_t)(remote_qpn >> 16);
    qpc[22] = (uint8_t)(remote_qpn >> 8);
    qpc[23] = (uint8_t)remote_qpn; // remote_qpn(byte21-23)
    // **実機で確認済み(2026-08-12)**: rre/rwe/rae(qpc[146])とlog_rra_max
    // (qpc[145])はこのFWではINIT2RTR_QPで設定しても無視される(QUERY_QPで
    // 実際に読み返すとqpc[146]が常に0のまま保持されないことを確認済み)。
    // 実際にはRTR2RTS_QP遷移(mlx5_qp_modify_rtr2rts()参照)で設定するのが
    // このFWの仕様だった -- 詳細はCLAUDE.md「ConnectX RoCEv2 NVMe-oF
    // 実装計画フェーズ(c)」節参照。
    qpc[148] = (uint8_t)(12u & 0x1Fu); // min_rnr_nak(pos3-7)=12
    // **実機で発見(2026-08-13、フェーズ(i)実Linuxホスト接続確認)**: next_rcv_psn
    // には「相手がREQ/REPで宣言した値(remote_start_psn)」ではなく「自分自身が
    // REQ/REPで宣言した値(qp->local_psn)」を設定するのが正しい -- Linuxの
    // drivers/infiniband/core/cma.c(rdma_init_qp_attr()の`qp_attr->rq_psn =
    // id_priv->seq_num`、cm.cのcm_init_qp_rts_attr()の`qp_attr->sq_psn =
    // cm_id_priv->sq_psn`[相手がREQ/REPで宣言した値])を実際に取得して確認
    // 済み: REQ/REPの STARTING_PSN フィールドは「送信者自身がこれから使う
    // 送信開始PSN」ではなく「送信者が"自分の受信開始PSNとして要求する"値
    // (=相手にこの値を送信開始PSNとして使わせる)」という意味だった --
    // 直感的な読み方(フィールド名からの素朴な連想)とは逆の意味を持つ。
    // 一度この修正を試し、PF0<->PF1の`mlx5qp pingpong`ループバックが
    // タイムアウトするのを見て誤りと判断し撤回したが、実際にはその時点で
    // rpi5のPF0/PF1はケーブルで直結されておらず(それぞれ別々に
    // OptiPlexへ接続済み)、ループバック自体が物理的に成立しない状態
    // だった -- ユーザー確認により判明。ループバックテストの失敗は
    // この修正とは無関係だったため、修正を再適用する。
    qpc[149] = (uint8_t)(qp->local_psn >> 16);
    qpc[150] = (uint8_t)(qp->local_psn >> 8);
    qpc[151] = (uint8_t)qp->local_psn; // next_rcv_psn(byte149-151) = 自分がREQ/REPで宣言した値
    mlx5_ads_fill_roce(&qpc[24], remote_gid, remote_mac, qp->remote_udp_sport, 1, 0);

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: INIT2RTR_QP: mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: INIT2RTR_QP: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    uart_printf("mlx5qp: INIT2RTR_QP(qpn=%u) ok: remote_qpn=%u remote_start_psn=%u udp_sport=%u\n",
                qp->qpn, remote_qpn, remote_start_psn, qp->remote_udp_sport);
    return 0;
}

uint32_t mlx5_qp_max_concurrent_rdma_read(mlx5_dev_t *dev) {
    uint8_t log_v = dev->log_max_ra_req_qp;
    if (dev->log_max_ra_res_qp < log_v) log_v = dev->log_max_ra_res_qp;
    if (log_v > 4u) log_v = 4u;
    return 1u << log_v;
}

int mlx5_qp_modify_rtr2rts(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    uint8_t in[24 + MLX5_QPC_BYTES + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_RTR2RTS_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_RTR2RTS_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;
    uint32_t optpar = 0x02u | 0x04u | 0x08u | 0x400u | 0x40u; // RRE|RAE|RWE|PM_STATE|RNR_TIMEOUT
    in[16] = (uint8_t)(optpar >> 24);
    in[17] = (uint8_t)(optpar >> 16);
    in[18] = (uint8_t)(optpar >> 8);
    in[19] = (uint8_t)optpar;

    uint8_t *qpc = &in[24];
    qpc[2] = (uint8_t)(MLX5_QP_PM_MIGRATED << 3); // pm_state(pos3-4)
    // **実機で発見(2026-08-12)**: rre/rwe/raeはINIT2RTR_QPではなくこの
    // RTR2RTS_QP遷移で設定するのがこのFWの実際の仕様だった -- optparには
    // 元々RRE|RAE|RWEが含まれていたが、qpc本体(qpc[145]/[146])への実際の
    // 値の書き込みが漏れており、QUERY_QPで読み返すと常に0のままだった
    // (INIT2RTR_QP側でqpc[145]/[146]を設定してもFWに反映されないことを
    // QUERY_QPで確認済み)。raeは外す(atomic capabilityを有効化していない
    // ため、含めるとBAD_PARAM_ERR)。
    // 2026-08-12実機で発見: ハードコード値2(4件のつもり)は実際のHCA
    // capability(dev->log_max_ra_res_qp/log_max_ra_req_qp、
    // mlx5_hca_bringup()でQUERY_HCA_CAPから読み取り済み)を超えることが
    // あり、超えた分は「コマンド自体は成功するが実際には未定義動作
    // (タイミング依存でREMOTE_INVAL_REQ_ERR)」になっていた(このカードは
    // log_max_ra_res_qp=0=1件、log_max_ra_req_qp=4=16件を報告)。
    //
    // log_sra_max(自分がinitiatorとして同時に出すRDMA_READ数)は、本来
    // IBTA的には「相手が実際にresponderとして受け付けられる数
    // (相手のlog_rra_max)」でクランプすべきだが、rdma_cm.c(CM層)は
    // REQ/REPのResponder Resources/Initiator Depthフィールドをまだ
    // 実際の交渉には使っていない(固定値4を書くだけの未実装、CLAUDE.md
    // 「ConnectX RoCEv2 NVMe-oF実装計画フェーズ(f)」節「rkey交換について」
    // の関連コメント参照)。このプロジェクトは常に同一カードの2ポート
    // ループバック構成(PF0<->PF1が物理的に同一HCAで、双方のcapabilityは
    // 必ず一致する)なので、暫定的に「自分のcapability同士のmin」
    // (=相手も自分と同じcapabilityのはずという前提)でクランプする --
    // 異種HCA間の本物の接続では相手の実際の値をCM経由で受け取り使う
    // 必要がある(未実装、将来の課題)。
    uint8_t log_rra = dev->log_max_ra_res_qp;
    if (log_rra > 4u) log_rra = 4u; // qpc[145]のフィールド幅は3bit(0-7)
    uint8_t log_sra = 0;
    { // mlx5_qp_max_concurrent_rdma_read()と同じmin(req,res)クランプを
      // 対数のまま計算(log2(その関数の戻り値)相当)。
        uint32_t v = mlx5_qp_max_concurrent_rdma_read(dev);
        while ((1u << log_sra) < v && log_sra < 4u) log_sra++;
    }
    qpc[145] = (uint8_t)(log_rra << 5); // log_rra_max
    qpc[146] = 0xC0u; // rre|rwe = 1,1 (rae=0)
    qpc[113] = (uint8_t)((log_sra << 5) | (7u & 0x07u)); // log_sra_max(pos0-2)|retry_count=7(pos5-7)
    qpc[114] = (uint8_t)(7u << 5); // rnr_retry=7(pos0-2、7=infinite retry、IBTA仕様)
    // next_send_psnには「自分がREQ/REPで宣言した値(qp->local_psn)」ではなく
    // 「相手がREQ/REPで宣言した値(qp->remote_psn)」を設定する -- 上記
    // mlx5_qp_modify_init2rtr()のnext_rcv_psnコメント参照(同じ発見の対称
    // side)。Linuxの`qp_attr->sq_psn = cm_id_priv->sq_psn`(相手が宣言した
    // 値)と一致させるための修正。
    qpc[121] = (uint8_t)(qp->remote_psn >> 16);
    qpc[122] = (uint8_t)(qp->remote_psn >> 8);
    qpc[123] = (uint8_t)qp->remote_psn; // next_send_psn(byte121-123) = 相手がREQ/REPで宣言した値
    mlx5_ads_fill_roce(&qpc[24], NULL, NULL, 0, 0, 1); // ack_timeout/vhca_port_numのみ

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: RTR2RTS_QP: mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: RTR2RTS_QP: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    uart_printf("mlx5qp: RTR2RTS_QP(qpn=%u) ok -- QP should now be RTS\n", qp->qpn);
    return 0;
}

// QUERY_QP診断拡張(フェーズ(d)): QPが自分自身のRQ/SQで実際にどれだけの
// WQEをHWが処理したかを直接確認する(mlx5stat/QUERY_RQ/QUERY_SQは
// dev->rxq[0].rqn/dev->sqn[Ethernet backend用の固定リソース]しか見ないため、
// 個々のmlx5_qp_tが持つRQ/SQは別途これで確認する必要がある)。
// struct mlx5_ifc_qpc_bits(本セッションで実際に取得・裏取り済み)の
// hw_rq_counter[絶対byte184-187]/sw_rq_counter[188-191、いずれもBE32]、
// hw_sq_wqebb_counter[180-181]/sw_sq_wqebb_counter[182-183、BE16] --
// dbr_addr(byte160-167)+q_key(168-171)+reserved_at_560/rq_type(172)+
// srqn_rmpn_xrqn(173-175)+reserved_at_580(176)+rmsn(177-179)の直後という
// 積み上げから確定した。
int mlx5_qp_query_counters(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t *out_hw_rq, uint32_t *out_sw_rq,
                            uint16_t *out_hw_sq, uint16_t *out_sw_sq) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_QUERY_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_QUERY_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;

    uint8_t out[24 + MLX5_QPC_BYTES];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        return -1;
    }
    const uint8_t *qpc = &out[24];
    if (out_hw_sq) {
        *out_hw_sq = (uint16_t)(((uint16_t)qpc[180] << 8) | qpc[181]);
    }
    if (out_sw_sq) {
        *out_sw_sq = (uint16_t)(((uint16_t)qpc[182] << 8) | qpc[183]);
    }
    if (out_hw_rq) {
        *out_hw_rq = ((uint32_t)qpc[184] << 24) | ((uint32_t)qpc[185] << 16) |
                     ((uint32_t)qpc[186] << 8) | qpc[187];
    }
    if (out_sw_rq) {
        *out_sw_rq = ((uint32_t)qpc[188] << 24) | ((uint32_t)qpc[189] << 16) |
                     ((uint32_t)qpc[190] << 8) | qpc[191];
    }
    return 0;
}

// DESTROY_QP: 16バイトin(opcode/uid/reserved/op_mod/reserved/qpn/reserved)、
// 16バイトout(status/syndrome/reserved)。
int mlx5_qp_destroy(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_DESTROY_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_DESTROY_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        return -1;
    }
    qp->in_use = 0;
    return 0;
}

// ============================================================================
// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)
// フェーズ(d): GSI/UD QP(QP1相当)。mlx5_qp_create_rc()と全く同じ手順
// (ALLOC_UAR/ALLOC_PD/rw+rr有効なCREATE_MKEY/CREATE_CQ/CREATE_QP)を、
// GSI専用のDMA領域(mlx5.hのMLX5_GSI_WQE_ADDR等、RC QPの領域とは別)と
// qpc.st値だけを変えて複製する。「既存の動作確認済みコードに極力触れ
// ない」という方針(pcie1.c/pcie.c分離と同じ)により、mlx5_qp_create_
// rc()自体は一切変更していない。
// ============================================================================

#define MLX5_QP_ST_UD  0x2u // include/linux/mlx5/qp.hのenumで確認済み
#define MLX5_QP_ST_QP1 0x8u // 同、drivers/infiniband/hw/mlx5/qp.cの
                             // to_mlx5_st()で「case MLX5_IB_QPT_HW_GSI:
                             // return MLX5_QP_ST_QP1;」と確認済み(GSI/
                             // QP1相当)。QP0(SMI、IB専用の管理QP、RoCEには
                             // 存在しない)はMLX5_QP_ST_QP0=0x7で別。
#define MLX5_QP1_QKEY  0x80010000u // include/rdma/ib_mad.hのIB_QP1_QKEY。
                                    // 最上位ビット(bit31)が立っているため、
                                    // 受信側QPがこの値をqkeyに設定していれば
                                    // 送信側が指定したqkeyの値を検査せず
                                    // 受理する(IBTA仕様の「特別なqkey」規約)。

static int mlx5_qp_create_ud_common(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t st) {
    // MODIFY_NIC_VPORT_CONTEXT(roce_en=1)は冪等(mlx5_qp_create_rc()と同じ
    // 理由で毎回呼ぶ)。
    if (mlx5_nic_vport_enable_roce(dev) != 0) {
        uart_printf("mlx5qp: MODIFY_NIC_VPORT_CONTEXT(roce_en) failed\n");
        return -1;
    }

    for (unsigned i = 0; i < sizeof(*qp); i++) {
        ((uint8_t *)qp)[i] = 0;
    }
    qp->in_use = 1;
    qp->local_psn = (uint32_t)(timer_now() & 0x00FFFFFFu);

    if (mlx5_alloc_uar(dev, &qp->uarn) != 0) {
        uart_printf("mlx5qp: ALLOC_UAR failed\n");
        return -1;
    }
    if (mlx5_alloc_pd(dev, &qp->pdn) != 0) {
        uart_printf("mlx5qp: ALLOC_PD failed\n");
        return -1;
    }
    // rw/rrはUD/GSIには不要(RDMA_WRITE/READを一切使わない)だが、既存の
    // rw/rr有効なmkey作成関数をそのまま再利用する(第3のmkeyバリアントを
    // 新設するコストを避ける、余分な権限があっても実害は無い)。
    if (mlx5_create_mkey_pa_rw(dev, qp->pdn, &qp->mkey) != 0) {
        uart_printf("mlx5qp: CREATE_MKEY(rw) failed\n");
        return -1;
    }

    uint64_t cq_buf = (uint64_t)dev->gsi_cq_buf_cpu;
    uint64_t cq_dbr = (uint64_t)dev->gsi_cq_dbr_cpu;
    if (mlx5_create_cq(dev, qp->uarn, dev->eqn, cq_buf, cq_dbr, &qp->cqn) != 0) {
        uart_printf("mlx5qp: CREATE_CQ failed\n");
        return -1;
    }

    volatile uint8_t *wqe_buf = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->gsi_wqe_cpu;
    for (unsigned i = 0; i < MLX5_GSI_WQE_BUF_SIZE; i++) {
        wqe_buf[i] = 0;
    }
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->gsi_dbr_cpu;
    for (unsigned i = 0; i < MLX5_GSI_DBR_SIZE; i++) {
        dbr[i] = 0;
    }

    uint8_t in[24 + MLX5_QPC_BYTES + 8 + 4 + 4 + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_QP & 0xffu);

    uint8_t *qpc = &in[24];
    qpc[1] = st; // st(byte1) -- mlx5_qp_create_rc()との本質的な違いはここだけ
    qpc[5] = (uint8_t)(qp->pdn >> 16);
    qpc[6] = (uint8_t)(qp->pdn >> 8);
    qpc[7] = (uint8_t)qp->pdn; // pd(byte5-7)
    qpc[8] = (uint8_t)((IB_MTU_1024 << 5) | (20u & 0x1Fu)); // mtu|log_msg_max
    qpc[9] = (uint8_t)((8u & 0xFu) << 3); // log_rq_size=8(256エントリ)
    qpc[10] = (uint8_t)((6u & 0xFu) << 3); // log_sq_size=6(64 WQEBB)
    qpc[13] = (uint8_t)(qp->uarn >> 16);
    qpc[14] = (uint8_t)(qp->uarn >> 8);
    qpc[15] = (uint8_t)qp->uarn; // uar_page(byte13-15)
    qpc[125] = (uint8_t)(qp->cqn >> 16);
    qpc[126] = (uint8_t)(qp->cqn >> 8);
    qpc[127] = (uint8_t)qp->cqn; // cqn_snd(byte125-127)
    qpc[157] = (uint8_t)(qp->cqn >> 16);
    qpc[158] = (uint8_t)(qp->cqn >> 8);
    qpc[159] = (uint8_t)qp->cqn; // cqn_rcv(byte157-159)
    uint64_t dbr_pa = mlx5_dma_addr((volatile void *)(uintptr_t)dbr);
    for (unsigned b = 0; b < 8; b++) {
        qpc[160 + b] = (uint8_t)(dbr_pa >> (56 - 8 * b));
    } // dbr_addr(byte160-167)
    qpc[172] = (uint8_t)(MLX5_NON_ZERO_RQ & 0x07u); // rq_type

    unsigned pas_off = 24 + MLX5_QPC_BYTES + 8 + 4 + 4; // = 272
    uint64_t rq_pa = mlx5_dma_addr((volatile void *)(uintptr_t)wqe_buf);
    uint64_t sq_pa = mlx5_dma_addr((volatile void *)(uintptr_t)(wqe_buf + 4096));
    for (unsigned b = 0; b < 8; b++) {
        in[pas_off + b] = (uint8_t)(rq_pa >> (56 - 8 * b));
        in[pas_off + 8 + b] = (uint8_t)(sq_pa >> (56 - 8 * b));
    }

    uint8_t out[16 + 4];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: CREATE_QP(st=0x%x): mlx5_cmd_exec failed rc=%d\n", st, rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: CREATE_QP(st=0x%x): command status=0x%02x syndrome=0x%08x\n",
                    st, status, syndrome);
        return -1;
    }
    qp->qpn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    uart_printf("mlx5qp: CREATE_QP(st=0x%x) ok: qpn=%u local_psn=%u cqn=%u pdn=%u uarn=%u mkey=0x%08x\n",
                st, qp->qpn, qp->local_psn, qp->cqn, qp->pdn, qp->uarn, qp->mkey);
    return 0;
}

int mlx5_qp_create_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    return mlx5_qp_create_ud_common(dev, qp, MLX5_QP_ST_QP1);
}

// RST2INIT_QP(UD/GSI共通)。RC版と同じopt_param_mask=0方針(RST2INIT_QPは
// qp.cのopt_mask[RST][INIT]テーブルにエントリが無く常に0でよいことをRCで
// 確認済み)。pd/vhca_port_num(=1、mlx5_ads_fill_roce()を再利用)に加え、
// UD/GSI固有のqkey(qpc.q_key、byte168-171、struct mlx5_ifc_qpc_bitsで
// dbr_addr[0x40]の直後と確認済み)を設定する。
int mlx5_qp_modify_rst2init_ud(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t qkey) {
    qp->qkey = qkey;
    uint8_t in[24 + MLX5_QPC_BYTES + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_RST2INIT_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_RST2INIT_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;

    uint8_t *qpc = &in[24];
    qpc[5] = (uint8_t)(qp->pdn >> 16);
    qpc[6] = (uint8_t)(qp->pdn >> 8);
    qpc[7] = (uint8_t)qp->pdn; // pd
    qpc[11] |= 0x10; // rlky=1(RCと同じ、カーネルモードQPとして常に立てる)
    mlx5_ads_fill_roce(&qpc[24], NULL, NULL, 0, 0, 0); // vhca_port_num=1のみ
    qpc[168] = (uint8_t)(qkey >> 24);
    qpc[169] = (uint8_t)(qkey >> 16);
    qpc[170] = (uint8_t)(qkey >> 8);
    qpc[171] = (uint8_t)qkey; // q_key(byte168-171)

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: RST2INIT_QP(ud): mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: RST2INIT_QP(ud): command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    uart_printf("mlx5qp: RST2INIT_QP(ud, qpn=%u) ok, qkey=0x%08x\n", qp->qpn, qkey);
    return 0;
}

// INIT2RTR_QP(UD/GSI共通)。RCと異なりQPC自体に相手のQPN/GID/PATHを
// 一切持たない(実ドライバのgsi.cのmodify_to_rts()がINIT->RTR遷移で
// IB_QP_STATEしか指定していないのと同じ理由 -- UDの相手アドレスは送信
// WQEのAV[Address Vector]に毎回埋め込むため)。opt_param_mask=PKEY_INDEX|
// Q_KEY(0x30、qp.cのopt_mask[INIT][RTR][UD]テーブルの値)を使うが、
// 実際のpkey_index/qkeyフィールド自体はRST2INIT_QPで既に設定済みの値を
// そのまま維持する想定(再送するかはFWの実機挙動次第 -- rre/rwe/raeが
// INIT2RTR_QPでは保持されずRTR2RTS_QPで再設定が必要だった実機の教訓
// [フェーズ(c)]があるため、QUERY_QPで実際に確認すること)。
int mlx5_qp_modify_init2rtr_ud(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    uint8_t in[24 + MLX5_QPC_BYTES + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_INIT2RTR_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_INIT2RTR_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;
    uint32_t optpar = 0x10u | 0x20u; // PKEY_INDEX|Q_KEY
    in[16] = (uint8_t)(optpar >> 24);
    in[17] = (uint8_t)(optpar >> 16);
    in[18] = (uint8_t)(optpar >> 8);
    in[19] = (uint8_t)optpar;

    uint8_t *qpc = &in[24];
    qpc[5] = (uint8_t)(qp->pdn >> 16);
    qpc[6] = (uint8_t)(qp->pdn >> 8);
    qpc[7] = (uint8_t)qp->pdn; // pd
    qpc[8] = (uint8_t)((IB_MTU_1024 << 5) | (20u & 0x1Fu)); // mtu|log_msg_max
    mlx5_ads_fill_roce(&qpc[24], NULL, NULL, 0, 0, 0); // vhca_port_num=1のみ
    qpc[168] = (uint8_t)(qp->qkey >> 24);
    qpc[169] = (uint8_t)(qp->qkey >> 16);
    qpc[170] = (uint8_t)(qp->qkey >> 8);
    qpc[171] = (uint8_t)qp->qkey; // q_key -- 念のため再送(フェーズc教訓)

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: INIT2RTR_QP(ud): mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: INIT2RTR_QP(ud): command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    uart_printf("mlx5qp: INIT2RTR_QP(ud, qpn=%u) ok\n", qp->qpn);
    return 0;
}

// RTR2RTS_QP(UD/GSI共通)。next_send_psn(=qp->local_psn)のみ設定する
// (実ドライバのmodify_to_rts()がIB_QP_STATE|IB_QP_SQ_PSNのみ指定するのと
// 同じ)。**実機で確認(2026-08-12)**: 当初RC版に倣いpm_state/ack_timeout/
// qkey再送/optpar(Q_KEY|PM_STATE)を含めていたが、BAD_PARAM_ERR
// (status=0x03、syndrome=0x003670a5)で拒否された -- UDは接続を持たない
// (ack_timeout等のRC固有の再送パラメータはそもそも意味を持たない)ため、
// 実ドライバの実際の呼び出しパターン(modify_to_rts()、IB_QP_STATE|
// IB_QP_SQ_PSNのみ)に厳密に合わせ、next_send_psn以外は一切設定しない
// 最小構成へ変更した。
int mlx5_qp_modify_rtr2rts_ud(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    uint8_t in[24 + MLX5_QPC_BYTES + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_RTR2RTS_QP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_RTR2RTS_QP & 0xffu);
    in[9] = (uint8_t)(qp->qpn >> 16);
    in[10] = (uint8_t)(qp->qpn >> 8);
    in[11] = (uint8_t)qp->qpn;
    // opt_param_mask(in[16..19])=0のまま。

    uint8_t *qpc = &in[24];
    qpc[121] = (uint8_t)(qp->local_psn >> 16);
    qpc[122] = (uint8_t)(qp->local_psn >> 8);
    qpc[123] = (uint8_t)qp->local_psn; // next_send_psn(byte121-123)

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        uart_printf("mlx5qp: RTR2RTS_QP(ud): mlx5_cmd_exec failed rc=%d\n", rc);
        return rc;
    }
    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5qp: RTR2RTS_QP(ud): command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }
    uart_printf("mlx5qp: RTR2RTS_QP(ud, qpn=%u) ok -- QP should now be RTS\n", qp->qpn);
    return 0;
}

// MLX5_OPCODE_SEND/MLX5_WQE_CTRL_CQ_UPDATE/MLX5_SEND_WQE_BB/MLX5_BF_OFFSET
// はmlx5.hへ移した(mlx5_net.cもSQ WQE組み立てに同じ定数が必要なため)。

// ============================================================================
// フェーズ9: フローステアリング -- NIC RX用フローテーブル作成
// (CREATE_FLOW_TABLE)、root設定(SET_FLOW_TABLE_ROOT)、catch-allフロー
// グループ作成(CREATE_FLOW_GROUP)、単一ルール設定(SET_FLOW_TABLE_ENTRY)。
//
// レイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_{create_flow_table,set_flow_table_root,
// create_flow_group,set_fte}_{in,out}_bits/struct mlx5_ifc_{flow_table_
// context,flow_context,dest_format}_bits、`drivers/net/ethernet/
// mellanox/mlx5/core/fs_cmd.c`のmlx5_cmd_create_flow_table()/
// mlx5_cmd_update_root_ft()/mlx5_cmd_create_flow_group()/
// mlx5_cmd_set_fte())から取得。
//
// CREATE_FLOW_GROUP/SET_FLOW_TABLE_ENTRYは固定長部分がそれぞれ1024バイト/
// 840バイトあり単一メールボックスブロック(528バイト)に収まらないため、
// このプロジェクトで初めてメールボックスチェイン(mlx5_cmd_exec()の
// MLX5_CMD_MBOX_CHAIN_BLOCKS対応、上記参照)を実際に使うコマンドになる。
//
// 各構造体の固定サイズは、mlx5_ifc.hの「最後のreserved_atNNNフィールド名
// が自分自身の累積ビットオフセットを表す」という命名規約を直接読むことで
// 手計算し(例: struct mlx5_ifc_fte_match_param_bitsの最終フィールド
// `reserved_at_e00[0x200]` -> 0xe00+0x200=0x1000bit=512byte)、再帰的な
// スクリプトパースでは共用体(union)の扱いを誤って過小な値を出したため
// 採用しなかった(検算に使ったスクリプト自体にバグがあった、という
// 教訓 -- このプロジェクトの「手計算だけに頼らない」方針の逆に振れた
// 失敗例として記録しておく)。
// ============================================================================

#define MLX5_CMD_OP_SET_FLOW_TABLE_ROOT  0x92fu
#define MLX5_CMD_OP_CREATE_FLOW_TABLE    0x930u
#define MLX5_CMD_OP_CREATE_FLOW_GROUP    0x933u
#define MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY 0x936u

#define MLX5_FLOW_TABLE_TYPE_NIC_RX          0u
#define MLX5_IFC_FLOW_DESTINATION_TYPE_TIR   2u
#define MLX5_FLOW_CONTEXT_ACTION_FWD_DEST    0x4u

// CREATE_FLOW_TABLE: struct mlx5_ifc_create_flow_table_in_bits。固定
// ヘッダ24バイト(他のflow系コマンドと共通のother_vport/vport_number
// パターン、mlx5_ifc.hの累積ビットオフセットから手計算)の直後に
// flow_table_context(struct mlx5_ifc_flow_table_context_bits、40バイト
// [24バイトの実フィールド+16バイトのunion(sw_owner/rtc、未使用)]、
// in[24..63])、合計64バイト。table_type(in[16])=NIC_RX(0)以外は全て
// デフォルト値(0)で良い最小構成: table_miss_action=DEF(0,ドロップ)、
// level=0(単一テーブル、他テーブルへのチェイン無し)、log_size=0
// (1エントリのみ、単一のcatch-allルールしか作らないため)、
// sw_owner=0(FW管理の従来型テーブル、software-managed steeringは使わない)。
static int mlx5_create_flow_table_nic_rx(mlx5_dev_t *dev, uint32_t *out_table_id) {
    uint8_t in[64];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_FLOW_TABLE >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_FLOW_TABLE & 0xffu);
    in[16] = (uint8_t)MLX5_FLOW_TABLE_TYPE_NIC_RX;

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_FLOW_TABLE: command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }

    if (out_table_id) {
        *out_table_id = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// SET_FLOW_TABLE_ROOT: struct mlx5_ifc_set_flow_table_root_in_bits(64バイト、
// 単一メールボックスで足りる)。table_type(in[16])=NIC_RX(0)、
// table_id(in[21..23])=作成したフローテーブルのID。op_mod=0が「接続」
// (fs_cmd.cのmlx5_cmd_update_root_ft()参照、disconnectのみop_mod=1)。
static int mlx5_set_flow_table_root_nic_rx(mlx5_dev_t *dev, uint32_t table_id) {
    uint8_t in[64];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_SET_FLOW_TABLE_ROOT >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_SET_FLOW_TABLE_ROOT & 0xffu);
    in[16] = (uint8_t)MLX5_FLOW_TABLE_TYPE_NIC_RX;
    in[21] = (uint8_t)(table_id >> 16);
    in[22] = (uint8_t)(table_id >> 8);
    in[23] = (uint8_t)table_id;

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: SET_FLOW_TABLE_ROOT: command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }
    return 0;
}

// CREATE_FLOW_GROUP: struct mlx5_ifc_create_flow_group_in_bits。固定
// ヘッダ64バイト(他のflow系コマンドと同じother_vport/vport_number
// パターン)の直後にmatch_criteria(struct mlx5_ifc_fte_match_param_bits、
// 512バイト、in[64..575])、さらにreserved(448バイト、in[576..1023])、
// 合計1024バイト -- 初めてメールボックスチェインが必要になるコマンド。
// table_type(in[16])=NIC_RX(0)、table_id(in[21..23])=対象フローテーブル。
// start_flow_index/end_flow_index(in[28..31]/in[36..39])は共に0
// (このグループは単一エントリ[0,0]のみ扱う、複数ルールを持つ設計には
// していない)。match_criteria_enable(in[63])=0(どのヘッダフィールドも
// 見ない、catch-all)なのでmatch_criteria本体(in[64..575])は全ゼロで良い。
static int mlx5_create_flow_group_catchall(mlx5_dev_t *dev, uint32_t table_id, uint32_t *out_group_id) {
    uint8_t in[1024];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_FLOW_GROUP >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_FLOW_GROUP & 0xffu);
    in[16] = (uint8_t)MLX5_FLOW_TABLE_TYPE_NIC_RX;
    in[21] = (uint8_t)(table_id >> 16);
    in[22] = (uint8_t)(table_id >> 8);
    in[23] = (uint8_t)table_id;
    // start_flow_index/end_flow_index/match_criteria_enableは全て0のまま。

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: CREATE_FLOW_GROUP: command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }

    if (out_group_id) {
        *out_group_id = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

// SET_FLOW_TABLE_ENTRY: struct mlx5_ifc_set_fte_in_bits。固定ヘッダ64
// バイトの直後にflow_context(struct mlx5_ifc_flow_context_bits、768
// バイト、in[64..831])、さらにdestination[1](struct mlx5_ifc_dest_
// format_bits、8バイト、in[832..839])、合計840バイト -- CREATE_FLOW_GROUP
// と同じくメールボックスチェインが必要。
//
// ヘッダ側: table_type(in[16])=NIC_RX(0)、table_id(in[21..23])、
// flow_index(in[32..35])=0(このFTEはCREATE_FLOW_GROUPで作った
// [0,0]範囲の唯一のスロットへ入る)。
// flow_context側(絶対オフセット=64+相対): group_id(in[68..71])=作成した
// フローグループのID(fs_cmd.cのmlx5_cmd_set_fte()が明示的に設定して
// いるフィールド)、action(in[78..79])=FWD_DEST(0x4)、
// destination_list_size(in[81..83])=1。match_value(in[128..639]相当)は
// 全ゼロのまま(catch-all、上記CREATE_FLOW_GROUPのmatch_criteria_enable=0
// と対になる設計)。
// destination[0](in[832..839]): destination_type(in[832])=TIR(2)、
// destination_id(in[833..835])=tirn。
static int mlx5_set_fte_fwd_tir(mlx5_dev_t *dev, uint32_t table_id, uint32_t group_id, uint32_t tirn) {
    uint8_t in[840];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY & 0xffu);
    in[16] = (uint8_t)MLX5_FLOW_TABLE_TYPE_NIC_RX;
    in[21] = (uint8_t)(table_id >> 16);
    in[22] = (uint8_t)(table_id >> 8);
    in[23] = (uint8_t)table_id;
    // flow_index(in[32..35])は0のまま。

    in[68] = (uint8_t)(group_id >> 24); // flow_context.group_id(32bit BE)
    in[69] = (uint8_t)(group_id >> 16);
    in[70] = (uint8_t)(group_id >> 8);
    in[71] = (uint8_t)group_id;
    in[78] = (uint8_t)(MLX5_FLOW_CONTEXT_ACTION_FWD_DEST >> 8); // action(16bit BE)
    in[79] = (uint8_t)(MLX5_FLOW_CONTEXT_ACTION_FWD_DEST & 0xffu);
    in[81] = 0; // destination_list_size(24bit BE) = 1
    in[82] = 0;
    in[83] = 1;

    in[832] = (uint8_t)MLX5_IFC_FLOW_DESTINATION_TYPE_TIR; // destination[0].destination_type
    in[833] = (uint8_t)(tirn >> 16); // destination[0].destination_id(24bit BE)
    in[834] = (uint8_t)(tirn >> 8);
    in[835] = (uint8_t)tirn;

    uint8_t out[16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }

    uint8_t status = out[0];
    if (status != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: SET_FLOW_TABLE_ENTRY: command status=0x%02x syndrome=0x%08x\n",
                    status, syndrome);
        return -1;
    }
    return 0;
}

// ============================================================================
// フェーズ10: モニタ機能 -- PPCNT(Ports Performance Counters, physical port
// 統計カウンタ)とQUERY_RQ/QUERY_SQ/QUERY_CQ(RQ/SQ/CQのHW内部状態を
// FWコマンドで直接読む)。CQ/RQが応答しない問題を「ソフトウェアに見える
// CQEの有無」だけでなく、MAC/PHYレベルで実際に何が起きているか
// (フレームは物理的に送受信されたか)・HW自身の内部カウンタ(hw_counter/
// producer_counter)が動いたかで多角的に切り分けるために実装する。
//
// PPCNTのレイアウトはLinux mlx5_core(`include/linux/mlx5/mlx5_ifc.h`の
// struct mlx5_ifc_ppcnt_reg_bits/struct mlx5_ifc_eth_802_3_cntrs_grp_
// data_layout_bits/struct mlx5_ifc_phys_layer_cntrs_bits、
// `include/linux/mlx5/device.h`のenum内MLX5_IEEE_802_3_COUNTERS_GROUP/
// MLX5_PHYSICAL_LAYER_COUNTERS_GROUP)から取得。QUERY_RQ/QUERY_SQ/
// QUERY_CQのレイアウトは同ヘッダのstruct mlx5_ifc_query_{rq,sq,cq}_
// {in,out}_bits/struct mlx5_ifc_wq_bits(hw_counter/sw_counter)/
// struct mlx5_ifc_cqc_bits(consumer_counter/producer_counter)から取得。
// いずれもこのプロジェクトの他コマンドと同じ手法(mlx5_ifc.hの累積ビット
// オフセットから手計算)でバイト位置を導出し、CREATE_RQ/CREATE_SQ側の
// 既存の実測済みオフセット(rqc/sqc相対byte1=state、byte9-11=cqn、
// wqがrqc/sqc相対byte48から埋め込まれる)と突き合わせて整合を確認した
// -- 具体的にはQUERY_RQ/QUERY_SQ出力のヘッダが32バイト(CREATE_RQ/
// CREATE_SQの入力ヘッダと同じ)で、rqc/sqc内のwq埋め込み位置(相対
// byte48)もCREATE_RQ/CREATE_SQで既に実機検証済みの値と完全に一致する
// ことを確認済み。
// ============================================================================

#define MLX5_REG_PPCNT               0x5008u
#define MLX5_PPCNT_GRP_IEEE_802_3    0x0u  // MLX5_IEEE_802_3_COUNTERS_GROUP(device.h)
#define MLX5_PPCNT_GRP_PHYSICAL_LAYER 0x12u // MLX5_PHYSICAL_LAYER_COUNTERS_GROUP(device.h)
#define MLX5_PPCNT_COUNTER_SET_BYTES 248u   // struct mlx5_ifc_ppcnt_reg_bits.counter_set(グループ種別によらず固定)
// 2026-08-15、HWモニタ(温度/PCIeエラー)。register_id は driver.h の enum mlx5_reg。
#define MLX5_REG_MTMP                0x900Au // Management Temperature(struct mlx5_ifc_mtmp_reg_bits)
#define MLX5_REG_MPCNT               0x9051u // Management PCIe Counters(struct mlx5_ifc_mpcnt_reg_bits)
#define MLX5_MPCNT_GRP_PCIE_PERF     0x0u    // PCIE_PERFORMANCE_COUNTERS_GROUP

#define MLX5_CMD_OP_QUERY_RQ 0x90bu
#define MLX5_CMD_OP_QUERY_SQ 0x907u
#define MLX5_CMD_OP_QUERY_CQ 0x402u

// PAOS(既存のmlx5_set_port_admin_status_up()/mlx5_query_port_oper_status()
// と同じレジスタ)からadmin_status/oper_statusの両方を一度に読む。
// mlx5_query_port_oper_status()はoper_statusしか返さないため、モニタ用に
// 別関数として追加した(既存の検証済み関数へは手を入れない)。
static int mlx5_query_port_status(mlx5_dev_t *dev, uint8_t *out_admin_status, uint8_t *out_oper_status) {
    uint8_t in[16 + 16];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    in[6] = 0x00; in[7] = 0x01; // op_mod=READ(1)
    in[10] = (uint8_t)(MLX5_REG_PAOS >> 8);
    in[11] = (uint8_t)(MLX5_REG_PAOS & 0xffu);
    in[16 + 1] = 0x01u; // local_port=1

    uint8_t out[16 + 16];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        return -1;
    }
    if (out_admin_status) {
        *out_admin_status = (uint8_t)(out[16 + 2] & 0x0Fu);
    }
    if (out_oper_status) {
        *out_oper_status = (uint8_t)(out[16 + 3] & 0x0Fu);
    }
    return 0;
}

// PPCNT(register_id=0x5008)をACCESS_REG(READ)経由で読む。register_data
// (struct mlx5_ifc_ppcnt_reg_bits)は8バイトヘッダ+counter_set(グループ
// 種別によらず固定248バイト)。ヘッダの各フィールドのバイト位置は
// PAOSと同じ手法で導出:
// - byte0: swid=0
// - byte1: local_port=1(PAOSと同じ規約)
// - byte3下位6bit: grp(呼び出し元指定)
static int mlx5_ppcnt_query(mlx5_dev_t *dev, uint8_t grp, uint8_t *counter_set_out) {
    uint8_t in[16 + 8 + MLX5_PPCNT_COUNTER_SET_BYTES];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    in[6] = 0x00; in[7] = 0x01; // op_mod=READ(1)
    in[10] = (uint8_t)(MLX5_REG_PPCNT >> 8);
    in[11] = (uint8_t)(MLX5_REG_PPCNT & 0xffu);
    in[16 + 1] = 0x01u; // local_port=1
    in[16 + 3] = (uint8_t)(grp & 0x3Fu);

    uint8_t out[sizeof(in)];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: PPCNT(grp=0x%x): command status=0x%02x syndrome=0x%08x\n",
                    grp, out[0], syndrome);
        return -1;
    }
    for (unsigned i = 0; i < MLX5_PPCNT_COUNTER_SET_BYTES; i++) {
        counter_set_out[i] = out[16 + 8 + i];
    }
    return 0;
}

// counter_set内の8バイト(32bit BE hi直後に32bit BE lo)を1個の64bit
// カウンタとして表示する。uart_printf()は64bit引数に未対応
// (`%l`修飾子は読み飛ばすだけでva_argは32bit読みのまま、CLAUDE.mdの
// timestamp.c節と同じ理由で64bit値を直接渡すとva_argの整列がずれる)
// ため、hiが0なら下位32bitだけを10進で、非0ならhi:loを16進2ワードで
// 表示する(既存コードの"bar0_base=0x%08x%08x"パターンと同じ手法)。
static void mlx5_print_ctr64(const char *name, const uint8_t *cs, unsigned byte_off) {
    uint32_t hi = ((uint32_t)cs[byte_off] << 24) | ((uint32_t)cs[byte_off + 1] << 16) |
                  ((uint32_t)cs[byte_off + 2] << 8) | cs[byte_off + 3];
    uint32_t lo = ((uint32_t)cs[byte_off + 4] << 24) | ((uint32_t)cs[byte_off + 5] << 16) |
                  ((uint32_t)cs[byte_off + 6] << 8) | cs[byte_off + 7];
    if (hi == 0) {
        uart_printf(" %s=%u", name, lo);
    } else {
        uart_printf(" %s=0x%08x%08x", name, hi, lo);
    }
}

static uint32_t mlx5_ctr32(const uint8_t *cs, unsigned byte_off) {
    return ((uint32_t)cs[byte_off] << 24) | ((uint32_t)cs[byte_off + 1] << 16) |
           ((uint32_t)cs[byte_off + 2] << 8) | cs[byte_off + 3];
}

// IEEE 802.3(MACレベル)カウンタ。フィールドオフセットはstruct
// mlx5_ifc_eth_802_3_cntrs_grp_data_layout_bits(mlx5_ifc.h)の出現順
// (全て64bit hi/loペア、8バイトずつ)から手計算:
// frames_transmitted_ok=0, frames_received_ok=8,
// frame_check_sequence_errors=16, alignment_errors=24,
// octets_transmitted_ok=32, octets_received_ok=40, (以下48-72は
// multicast/broadcast系、今回は省略), in_range_length_errors=80,
// out_of_range_length_field=88, frame_too_long_errors=96,
// symbol_error_during_carrier=104。
static void mlx5_dump_ieee802_3(mlx5_dev_t *dev, const char *label) {
    uint8_t cs[MLX5_PPCNT_COUNTER_SET_BYTES];
    if (mlx5_ppcnt_query(dev, MLX5_PPCNT_GRP_IEEE_802_3, cs) != 0) {
        uart_printf("mlx5: [%s] PPCNT(IEEE802.3) query failed\n", label);
        return;
    }
    uart_printf("mlx5: [%s] IEEE802.3:", label);
    mlx5_print_ctr64("tx_frames_ok", cs, 0);
    mlx5_print_ctr64("rx_frames_ok", cs, 8);
    mlx5_print_ctr64("fcs_err", cs, 16);
    mlx5_print_ctr64("align_err", cs, 24);
    mlx5_print_ctr64("tx_octets_ok", cs, 32);
    mlx5_print_ctr64("rx_octets_ok", cs, 40);
    uart_printf("\n");
    uart_printf("mlx5: [%s] IEEE802.3:", label);
    mlx5_print_ctr64("in_range_len_err", cs, 80);
    mlx5_print_ctr64("out_of_range_len", cs, 88);
    mlx5_print_ctr64("frame_too_long", cs, 96);
    mlx5_print_ctr64("symbol_err_carrier", cs, 104);
    uart_printf("\n");
}

// Physical Layer(PHYレベル)カウンタ。struct mlx5_ifc_phys_layer_cntrs_bits
// (mlx5_ifc.h)より: symbol_errors=8(64bit hi/loペア)、
// link_down_events=192(32bit単独フィールド、hi/loペアではない点に
// 注意)、successful_recovery_events=196(同32bit単独)。
static void mlx5_dump_phys_layer(mlx5_dev_t *dev, const char *label) {
    uint8_t cs[MLX5_PPCNT_COUNTER_SET_BYTES];
    if (mlx5_ppcnt_query(dev, MLX5_PPCNT_GRP_PHYSICAL_LAYER, cs) != 0) {
        uart_printf("mlx5: [%s] PPCNT(PhysLayer) query failed\n", label);
        return;
    }
    uart_printf("mlx5: [%s] PhysLayer:", label);
    mlx5_print_ctr64("symbol_errors", cs, 8);
    uart_printf(" link_down_events=%u successful_recovery_events=%u\n",
                mlx5_ctr32(cs, 192), mlx5_ctr32(cs, 196));
}

// ============================================================================
// 2026-08-15、HWモニタ機能: 温度(MTMP)/ PCIe HWエラーカウンタ(MPCNT)/
// FW health buffer / PCIe config(リンク速度・幅・MPS・MRRS)。全て
// Linuxドライバ(mlx5_ifc.h / device.h / thermal.c / pci.c)から実バイト
// レイアウトを裏取りして実装(推測しない、CLAUDE.md一貫の方法論)。
// register系(温度・MPCNT・health)は BAR0/ACCESS_REG のみで rpi5/x86 共通。
// PCIe config は読み出し機構がプラットフォーム依存(x86=vfio_cfg_read32、
// rpi5=pcie1_cfg_read32)なので、読み関数を関数ポインタで受け取る。
// ============================================================================

// MTMP(0x900A)ACCESS_REG READ。register_data(struct mlx5_ifc_mtmp_reg_bits、
// 32バイト): temperature=相対byte6-7(BE16, 符号付き, 単位1/8℃)、
// max_temperature=相対byte10-11。sensor_index=0(相対byte2-3のbits20-31)。
static int mlx5_query_mtmp(mlx5_dev_t *dev, int16_t *out_temp, int16_t *out_max) {
    uint8_t in[16 + 32];
    for (unsigned i = 0; i < sizeof(in); i++) in[i] = 0;
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    in[6] = 0x00; in[7] = 0x01;                     // op_mod=READ(1)
    in[10] = (uint8_t)(MLX5_REG_MTMP >> 8);
    in[11] = (uint8_t)(MLX5_REG_MTMP & 0xffu);
    // sensor_index=0 -> register_data 全ゼロでよい。

    uint8_t out[sizeof(in)];
    if (mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out)) != 0) return -1;
    if (out[0] != 0) return -1;
    const uint8_t *rd = &out[16];
    if (out_temp) *out_temp = (int16_t)(((uint16_t)rd[6] << 8) | rd[7]);
    if (out_max)  *out_max  = (int16_t)(((uint16_t)rd[10] << 8) | rd[11]);
    return 0;
}

// MPCNT(0x9051)ACCESS_REG READ。PPCNTと同じヘッダ規約(grp=相対byte3下位
// 6bit、counter_set は register_data 先頭+8バイト)。
static int mlx5_mpcnt_query(mlx5_dev_t *dev, uint8_t grp, uint8_t *cs_out) {
    uint8_t in[16 + 8 + MLX5_PPCNT_COUNTER_SET_BYTES];
    for (unsigned i = 0; i < sizeof(in); i++) in[i] = 0;
    in[0] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ACCESS_REG & 0xffu);
    in[6] = 0x00; in[7] = 0x01;                     // op_mod=READ(1)
    in[10] = (uint8_t)(MLX5_REG_MPCNT >> 8);
    in[11] = (uint8_t)(MLX5_REG_MPCNT & 0xffu);
    in[16 + 3] = (uint8_t)(grp & 0x3Fu);            // grp
    uint8_t out[sizeof(in)];
    if (mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out)) != 0) return -1;
    if (out[0] != 0) return -1;
    for (unsigned i = 0; i < MLX5_PPCNT_COUNTER_SET_BYTES; i++) cs_out[i] = out[16 + 8 + i];
    return 0;
}

// PPCNT/MPCNT の64bitカウンタ(hi@off, lo@off+4)が非0か。
static int mlx5_ctr64_nonzero(const uint8_t *cs, unsigned off) {
    for (unsigned i = 0; i < 8; i++) if (cs[off + i]) return 1;
    return 0;
}

// HWハードエラーの有無をビットマスクで返す(0=エラー無し)。ブリングアップ時に
// 増える良性の情報カウンタ(tx/rx_errors, L0->recovery, link_down_events 等)は
// 含めず、実際の異常のみ対象: FWアサート(health synd)/PCIe CRC(dllp/tlp)・
// 致命的DevSta(NonFatal/Fatal/UnsupReq)/Etherフレーム破損(fcs/align/symbol)。
// devsta は呼び出し元が config space から読んで渡す(機構がプラットフォーム依存)。
#define MLX5_HWERR_FW      0x01u
#define MLX5_HWERR_PCIE    0x02u
#define MLX5_HWERR_ETH_FCS 0x04u
#define MLX5_HWERR_ETH_ALN 0x08u
#define MLX5_HWERR_ETH_SYM 0x10u
static uint32_t mlx5_hw_error_flags(mlx5_dev_t *dev, uint16_t devsta) {
    uint32_t f = 0;
    // FW health synd(init-seg 相対 byte0x23d、mlx5_read32(0x23c)の bits23:16)
    if ((uint8_t)((mlx5_read32(dev, 0x23cu) >> 16) & 0xffu)) f |= MLX5_HWERR_FW;
    uint8_t cs[MLX5_PPCNT_COUNTER_SET_BYTES];
    if (mlx5_mpcnt_query(dev, MLX5_MPCNT_GRP_PCIE_PERF, cs) == 0) {
        if (mlx5_ctr32(cs, 32) || mlx5_ctr32(cs, 36)) f |= MLX5_HWERR_PCIE; // crc dllp/tlp
    }
    if (devsta & 0x0Eu) f |= MLX5_HWERR_PCIE; // DevSta NonFatal|Fatal|UnsupReq
    if (mlx5_ppcnt_query(dev, MLX5_PPCNT_GRP_IEEE_802_3, cs) == 0) {
        if (mlx5_ctr64_nonzero(cs, 16))  f |= MLX5_HWERR_ETH_FCS; // fcs_err
        if (mlx5_ctr64_nonzero(cs, 24))  f |= MLX5_HWERR_ETH_ALN; // align_err
        if (mlx5_ctr64_nonzero(cs, 104)) f |= MLX5_HWERR_ETH_SYM; // symbol_err_carrier
    }
    return f;
}

// PCIe config space から速度コード/幅/MPS/MRRS/DevSta を取得する(表示は
// しない)。config読み出し機構はプラットフォーム依存なので rd(ctx,off) を
// 関数ポインタで受け取る。値エンコードは PCIe Base Spec 標準(mlx5非依存)。
typedef struct {
    int valid;
    unsigned cur_spd, cur_w, max_spd, max_w, mps, mrrs;
    uint16_t devsta;
} mlx5_pcie_info_t;
static void mlx5_pcie_query_cfg(uint32_t (*rd)(void *, uint32_t), void *ctx, mlx5_pcie_info_t *o) {
    o->valid = 0;
    if (!((rd(ctx, 0x04u) >> 16) & 0x10u)) return;    // Status: capability list 無し
    uint8_t cap = (uint8_t)(rd(ctx, 0x34u) & 0xfcu);  // Capabilities Pointer
    uint32_t pcie = 0;
    for (int i = 0; i < 48 && cap >= 0x40u; i++) {
        uint32_t h = rd(ctx, cap);
        if ((h & 0xffu) == 0x10u) { pcie = cap; break; } // PCIe Express Cap
        cap = (uint8_t)((h >> 8) & 0xfcu);
    }
    if (pcie == 0) return;
    uint32_t lnkcap = rd(ctx, pcie + 0x0cu);
    uint16_t lnksta = (uint16_t)(rd(ctx, pcie + 0x10u) >> 16); // +0x12
    uint32_t devcs  = rd(ctx, pcie + 0x08u);
    uint16_t devctl = (uint16_t)(devcs & 0xffffu);             // +0x08
    o->cur_spd = lnksta & 0xfu;  o->cur_w = (lnksta >> 4) & 0x3fu;
    o->max_spd = lnkcap & 0xfu;  o->max_w = (lnkcap >> 4) & 0x3fu;
    o->mps  = (devctl >> 5) & 0x7u;
    o->mrrs = (devctl >> 12) & 0x7u;
    o->devsta = (uint16_t)(devcs >> 16);                       // +0x0a
    o->valid = 1;
}

// HWモニタの3行サマリ(PF0/PF1集約)。1行目=エラー有無+温度+FW、
// 2行目=Etherポートのリンク状態、3行目=PCIeリンク(速度/幅/MPS/MRRS)。
// config読み出しはプラットフォーム依存のため rd(ctx,off) を関数ポインタで
// 受け取る(cx0=PF0, cx1=PF1)。詳細な生カウンタが要るときは PPCNT 等を
// 個別に読むこと(この関数はあくまで「異常が無いか一目で分かる」用途)。
void mlx5_monitor_summary3(mlx5_dev_t *d0, mlx5_dev_t *d1,
                           uint32_t (*rd)(void *, uint32_t), void *cx0, void *cx1) {
    mlx5_dev_t *dv[2] = { d0, d1 };
    void *cx[2] = { cx0, cx1 };
    mlx5_pcie_info_t pi[2];
    uint32_t ef[2];
    int16_t tc[2] = { 0, 0 }, tm[2] = { 0, 0 };
    uint8_t op[2] = { 0, 0 };
    for (int i = 0; i < 2; i++) {
        mlx5_pcie_query_cfg(rd, cx[i], &pi[i]);
        ef[i] = mlx5_hw_error_flags(dv[i], pi[i].valid ? pi[i].devsta : 0);
        mlx5_query_mtmp(dv[i], &tc[i], &tm[i]);
        uint8_t admin = 0;
        mlx5_query_port_status(dv[i], &admin, &op[i]);
    }
    // --- 1行目: エラー有無 + 温度 + FW ---
    uint32_t all = ef[0] | ef[1];
    if (all == 0) {
        uart_printf("mlx5: No Error");
    } else {
        uart_printf("mlx5: ERROR:");
        for (int i = 0; i < 2; i++) {
            if (!ef[i]) continue;
            uart_printf(" PF%d[", i);
            if (ef[i] & MLX5_HWERR_FW)      uart_printf("FW-assert ");
            if (ef[i] & MLX5_HWERR_PCIE)    uart_printf("PCIe ");
            if (ef[i] & MLX5_HWERR_ETH_FCS) uart_printf("fcs ");
            if (ef[i] & MLX5_HWERR_ETH_ALN) uart_printf("align ");
            if (ef[i] & MLX5_HWERR_ETH_SYM) uart_printf("symbol ");
            uart_printf("]");
        }
    }
    uart_printf("  |  temp PF0/PF1=%d/%dC (max %d/%d)  |  FW=%s\n",
                tc[0] / 8, tc[1] / 8, tm[0] / 8, tm[1] / 8,
                (all & MLX5_HWERR_FW) ? "ASSERT" : "ok");
    // --- 2行目: Ether ポートのリンク状態 ---
    uart_printf("mlx5: Ether:  PF0(port1) link=%s   PF1(port2) link=%s\n",
                op[0] ? "UP" : "DOWN", op[1] ? "UP" : "DOWN");
    // --- 3行目: PCIe リンク(PF0/PF1 は同一ASICなのでMPS/MRRSは共通表示) ---
    uart_printf("mlx5: PCIe :  PF0 Gen%u x%u   PF1 Gen%u x%u   MPS=%uB MRRS=%uB\n",
                pi[0].cur_spd, pi[0].cur_w, pi[1].cur_spd, pi[1].cur_w,
                128u << pi[0].mps, 128u << pi[0].mrrs);
}

// QUERY_RQ(0x90b)/QUERY_SQ(0x907)は共通レイアウト: 固定ヘッダ32バイト
// (status/syndrome/reserved、struct mlx5_ifc_query_{rq,sq}_out_bits)の
// 直後にrqc/sqc(struct mlx5_ifc_{rqc,sqc}_bits、240バイト)。rqc/sqcは
// どちらも相対byte1上位nibbleがstate(RST=0/RDY=1/ERR=3、CREATE_RQ/
// CREATE_SQで既に実測済みの値と同じ意味)、相対byte48からstruct
// mlx5_ifc_wq_bitsが埋め込まれ、その中のhw_counter/sw_counter(各32bit)
// はwq相対byte24-27/28-31 -- つまりrqc/sqc相対byte72-75/76-79、
// クエリ出力での絶対オフセットは32+72=104 / 32+76=108。
// hw_counterはHWが実際に消費(RQ:受信完了、SQ:送信完了)したWQE数、
// sw_counterはソフトウェアがドアベルで投稿したWQE数 -- 両者の差が
// HW未処理分。RQのhw_counterが0のままなら、そもそもHWがこのRQのWQEに
// 一度も触れていないことを意味する(フレームがこのRQへ届いていない、
// またはRQ自体が機能していない)。
static int mlx5_query_wq_state(mlx5_dev_t *dev, uint16_t opcode, uint32_t objn,
                                uint8_t *out_state, uint32_t *out_hw_counter, uint32_t *out_sw_counter) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(opcode >> 8);
    in[1] = (uint8_t)(opcode & 0xffu);
    in[9] = (uint8_t)(objn >> 16);
    in[10] = (uint8_t)(objn >> 8);
    in[11] = (uint8_t)objn;

    uint8_t out[32 + 240];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: QUERY_%s(objn=%u): command status=0x%02x syndrome=0x%08x\n",
                    (opcode == MLX5_CMD_OP_QUERY_RQ) ? "RQ" : "SQ", objn, out[0], syndrome);
        return -1;
    }
    if (out_state) {
        *out_state = (uint8_t)(out[33] >> 4);
    }
    if (out_hw_counter) {
        *out_hw_counter = ((uint32_t)out[104] << 24) | ((uint32_t)out[105] << 16) |
                           ((uint32_t)out[106] << 8) | out[107];
    }
    if (out_sw_counter) {
        *out_sw_counter = ((uint32_t)out[108] << 24) | ((uint32_t)out[109] << 16) |
                           ((uint32_t)out[110] << 8) | out[111];
    }
    return 0;
}

// 【mlx5net TX回復ロジック、2026-08-08】mlx5_net.cの`mlx5_net_send_frags()`が
// 送信完了(CQE)待ちで1秒タイムアウトした際に呼ぶ、SQのERROR状態からの
// 復帰処理。RP1のCadence GEM(eth.c)が持つeth_tx_halt()/eth_tx_recover()
// (TX_WRAPハング時のTHALT+TBQP再ラッチ)に相当する仕組みがConnectX側には
// 一つも実装されていなかった -- 一度SQがERROR状態に落ちると、ソフトウェア
// 側がどれだけ再送(TCP層のtcp_send_reliable()等)を試みても、壊れた
// ままのSQへ送り続けるだけで永久に回復しない(実機で確認済み: 一度
// タイムアウトすると以後の全ての送信・FIN送出まで含めて全滅する)。
//
// まずQUERY_SQで実際にERROR状態(state=3)かどうかを確認してから復帰処理を
// 行う -- ソフトウェア側の1秒という待ち時間は推測に過ぎず、単にまだRDYの
// まま遅いだけの可能性を無用にERR->RST->RDYへ遷移させて壊さないため
// (CLAUDE.md「デバッグ手法」節と同じ「まず実測で確認してから対処する」
// 方法論)。
int mlx5_recover_sq(mlx5_dev_t *dev) {
    uint8_t state = 0xFFu;
    if (mlx5_query_wq_state(dev, MLX5_CMD_OP_QUERY_SQ, dev->sqn, &state, NULL, NULL) != 0) {
        uart_printf("mlx5: SQ(sqn=%u) recovery: QUERY_SQ失敗\n", dev->sqn);
        return -1;
    }
    if (state == MLX5_SQC_STATE_RDY) {
        /* 2026-08-15、core-split で発見・修正した本物のバグ: SQ が RDY(=
         * エラーではなく、単に完了が遅くて wait_room タイムアウトが誤発火した
         * だけ)の場合、ハードウェア SQ は一切リセットされていない。ここで
         * return 0 を返すと呼び出し元(mlx5_net_try_recover)が「復帰成功」と
         * 誤認してソフトの sq_pc/sq_cc を 0 に戻し、ハードの実カウンタ(数百万)
         * と desync して以後永久に「SQ 満杯」になる。RDY は "1"(何もしていない)
         * として区別し、呼び出し元がソフトカウンタを触らないようにする。 */
        return 1; // 既にRDY -- 実リセットしていない(ソフトカウンタを触るな)
    }
    if (state != MLX5_SQC_STATE_ERR) {
        uart_printf("mlx5: SQ(sqn=%u) recovery: 想定外の状態(state=%u)、復帰を諦めます\n",
                    dev->sqn, state);
        return -1;
    }
    uart_printf("mlx5: SQ(sqn=%u) がERROR状態です、ERR->RST->RDYで復帰を試みます\n", dev->sqn);
    if (mlx5_modify_sq_state(dev, dev->sqn, MLX5_SQC_STATE_ERR, MLX5_SQC_STATE_RST) != 0) {
        return -1;
    }
    if (mlx5_modify_sq_state(dev, dev->sqn, MLX5_SQC_STATE_RST, MLX5_SQC_STATE_RDY) != 0) {
        return -1;
    }
    uart_printf("mlx5: SQ(sqn=%u) 復帰完了、RDYへ戻りました\n", dev->sqn);
    return 0;
}

// QUERY_CQ(0x402): 固定ヘッダ16バイト(status/syndrome/reserved、struct
// mlx5_ifc_query_cq_out_bits -- RQ/SQとは異なりreservedが8バイトのみで
// ヘッダ合計16バイト、CREATE_CQの入力ヘッダと同じ)の直後にcqc(struct
// mlx5_ifc_cqc_bits、64バイト固定)。cqc内: 相対byte0上位nibble=status
// (MLX5_CQC_STATUS_OK=0、_CQ_OVERFLOW=9、_CQ_WRITE_FAIL=0xa)、相対
// byte2下位nibble=st(一般的な状態フィールド)、相対byte41-43=
// consumer_counter(24bit)、相対byte45-47=producer_counter(24bit)。
// producer_counterはHWが実際にこのCQへ書き込んだCQEの総数(op_ownの
// トグル判定に頼らないHW自身のカウンタ) -- これが0のままならHWは
// このCQへ一度もCQEを書いていないことになる(mlx5_cq_poll_any()の
// 「CQE[0]が初期値のまま」という判定と矛盾しないかの裏取りにもなる)。
static int mlx5_query_cq_state(mlx5_dev_t *dev, uint32_t cqn, uint8_t *out_status, uint8_t *out_st,
                                uint32_t *out_consumer_counter, uint32_t *out_producer_counter) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_QUERY_CQ >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_QUERY_CQ & 0xffu);
    in[9] = (uint8_t)(cqn >> 16);
    in[10] = (uint8_t)(cqn >> 8);
    in[11] = (uint8_t)cqn;

    uint8_t out[16 + 64];
    int rc = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
    if (rc != 0) {
        return rc;
    }
    if (out[0] != 0) {
        uint32_t syndrome = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
                             ((uint32_t)out[6] << 8) | out[7];
        uart_printf("mlx5: QUERY_CQ(cqn=%u): command status=0x%02x syndrome=0x%08x\n",
                    cqn, out[0], syndrome);
        return -1;
    }
    if (out_status) {
        *out_status = (uint8_t)(out[16 + 0] >> 4);
    }
    if (out_st) {
        *out_st = (uint8_t)(out[16 + 2] & 0x0Fu);
    }
    if (out_consumer_counter) {
        *out_consumer_counter = ((uint32_t)out[16 + 41] << 16) | ((uint32_t)out[16 + 42] << 8) | out[16 + 43];
    }
    if (out_producer_counter) {
        *out_producer_counter = ((uint32_t)out[16 + 45] << 16) | ((uint32_t)out[16 + 46] << 8) | out[16 + 47];
    }
    return 0;
}

// 1つのPFについて、PAOS(admin/oper状態)・PPCNT(IEEE802.3/Physical
// Layer)・RQ/SQのHW状態(state/hw_counter/sw_counter)・RQ用CQ/SQ用CQの
// HW状態(status/st/consumer_counter/producer_counter)を一括表示する。
static void mlx5_monitor_dump_dev(mlx5_dev_t *dev, const char *label) {
    uint8_t admin = 0xFFu, oper = 0xFFu;
    if (mlx5_query_port_status(dev, &admin, &oper) == 0) {
        uart_printf("mlx5: [%s] PAOS: admin_status=%u oper_status=%u (1=UP)\n", label, admin, oper);
    } else {
        uart_printf("mlx5: [%s] PAOS query failed\n", label);
    }

    mlx5_dump_ieee802_3(dev, label);
    mlx5_dump_phys_layer(dev, label);

    uint8_t rq_state = 0xFFu;
    uint32_t rq_hw = 0, rq_sw = 0;
    if (mlx5_query_wq_state(dev, MLX5_CMD_OP_QUERY_RQ, dev->rxq[0].rqn, &rq_state, &rq_hw, &rq_sw) == 0) {
        uart_printf("mlx5: [%s] RQ(rqn=%u): state=%u(0=RST,1=RDY,3=ERR) hw_counter=%u sw_counter=%u\n",
                    label, dev->rxq[0].rqn, rq_state, rq_hw, rq_sw);
    }
    uint8_t sq_state = 0xFFu;
    uint32_t sq_hw = 0, sq_sw = 0;
    if (mlx5_query_wq_state(dev, MLX5_CMD_OP_QUERY_SQ, dev->sqn, &sq_state, &sq_hw, &sq_sw) == 0) {
        uart_printf("mlx5: [%s] SQ(sqn=%u): state=%u(0=RST,1=RDY,3=ERR) hw_counter=%u sw_counter=%u\n",
                    label, dev->sqn, sq_state, sq_hw, sq_sw);
    }

    uint8_t rqcq_status = 0xFFu, rqcq_st = 0xFFu;
    uint32_t rqcq_cc = 0, rqcq_pc = 0;
    if (mlx5_query_cq_state(dev, dev->rxq[0].cqn, &rqcq_status, &rqcq_st, &rqcq_cc, &rqcq_pc) == 0) {
        uart_printf("mlx5: [%s] RQ's CQ(cqn=%u): status=%u st=%u consumer_counter=%u producer_counter=%u\n",
                    label, dev->rxq[0].cqn, rqcq_status, rqcq_st, rqcq_cc, rqcq_pc);
    }
    uint8_t sqcq_status = 0xFFu, sqcq_st = 0xFFu;
    uint32_t sqcq_cc = 0, sqcq_pc = 0;
    if (mlx5_query_cq_state(dev, dev->sq_cqn, &sqcq_status, &sqcq_st, &sqcq_cc, &sqcq_pc) == 0) {
        uart_printf("mlx5: [%s] SQ's CQ(cqn=%u): status=%u st=%u consumer_counter=%u producer_counter=%u\n",
                    label, dev->sq_cqn, sqcq_status, sqcq_st, sqcq_cc, sqcq_pc);
    }
}

void mlx5_monitor_dump_saved(void) {
    if (!s_last_devs_valid) {
        uart_printf("mlx5: no saved HCA state -- run `mlx5` (bring-up) first\n");
        return;
    }
    mlx5_monitor_dump_dev(&s_last_dev0, "PF0(port1)");
    mlx5_monitor_dump_dev(&s_last_dev1, "PF1(port2)");
}
