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

static inline uint32_t mlx5_read32(const mlx5_dev_t *dev, uint64_t off) {
    return __builtin_bswap32(mmio_read32(dev->bar0_base + off));
}

static inline void mlx5_write32(const mlx5_dev_t *dev, uint64_t off, uint32_t val) {
    mmio_write32(dev->bar0_base + off, __builtin_bswap32(val));
}

#define MLX5_ISEG_FW_REV            0x000u  // __be32 fw_rev
#define MLX5_ISEG_CMDIF_REV_FW_SUB  0x004u  // __be32 cmdif_rev_fw_sub (cmdif_revは上位16bit)
#define MLX5_ISEG_CMDQ_ADDR_H       0x010u  // __be32 cmdq_addr_h
#define MLX5_ISEG_CMDQ_ADDR_L_SZ    0x014u  // __be32 cmdq_addr_l_sz (下位8bitにlog_sz<<4|log_stride)
#define MLX5_ISEG_CMD_DBELL         0x018u  // __be32 cmd_dbell
#define MLX5_ISEG_INITIALIZING      0x1FCu  // __be32 initializing (bit31)

#define MLX5_CMD_IF_REV 5u

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

static int mlx5_query_port_status(mlx5_dev_t *dev, uint8_t *out_admin_status, uint8_t *out_oper_status);
static int mlx5_ppcnt_query(mlx5_dev_t *dev, uint8_t grp, uint8_t *counter_set_out);
static void mlx5_dump_ieee802_3(mlx5_dev_t *dev, const char *label);
static void mlx5_dump_phys_layer(mlx5_dev_t *dev, const char *label);
static int mlx5_query_wq_state(mlx5_dev_t *dev, uint16_t opcode, uint32_t objn,
                                uint8_t *out_state, uint32_t *out_hw_counter, uint32_t *out_sw_counter);
static int mlx5_query_cq_state(mlx5_dev_t *dev, uint32_t cqn, uint8_t *out_status, uint8_t *out_st,
                                uint32_t *out_consumer_counter, uint32_t *out_producer_counter);
static void mlx5_monitor_dump_dev(mlx5_dev_t *dev, const char *label);

/*
 * Initialization Segment の initializing ビット(bit31)がクリアされる
 * まで待つ。FW のブートが終わるまでコマンドを発行してはならない。
 *
 * 引数:
 *   dev   - 対象 HCA
 *   phase - ログ用のフェーズ名
 * 戻り値:
 *   0=クリアされた、-1=タイムアウト
 * コール元:
 *   mlx5_hca_bringup()
 */
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

int g_mlx5_skip_fte_experiment = 0;

/*
 * ConnectX を使える状態まで一気に立ち上げる。FW init 待ち -> cmdq 登録 ->
 * ENABLE_HCA -> ISSI -> boot/init ページ供給 -> HCA cap 設定 -> INIT_HCA ->
 * UAR/EQ/PD/MKey/CQ/TIS/RQ/TIR/SQ 作成 -> ポート admin UP と MTU 設定 ->
 * フローステアリング(catch-all)まで。
 *
 * 引数:
 *   dev          - 初期化する HCA(bar0_base と pf_index を設定済みのこと)
 *   label        - ログ用の名前("PF0" 等)
 *   monitor_only - 1=ENABLE_HCA と capability までで止める(モニタ用途)
 * 戻り値:
 *   0=成功、-1=いずれかの段階で失敗
 * コール元:
 *   bringup_pf()
 */
int mlx5_hca_bringup(mlx5_dev_t *dev, const char *label, int monitor_only) {
    uart_printf("mlx5: ===== bringing up %s (bar0_base=0x%08x%08x pf_index=%u) =====\n",
                label, (uint32_t)(dev->bar0_base >> 32), (uint32_t)dev->bar0_base,
                (unsigned)dev->pf_index);
    dev->fw_pages_used = 0;
    dev->bringup_generation++;

    {
        static uintptr_t s_qpcq_buf[2], s_qpcq_dbr[2];
        static uintptr_t s_qp2cq_buf[2], s_qp2cq_dbr[2];
        static uintptr_t s_gsicq_buf[2], s_gsicq_dbr[2];
        /* 段階3: Ethernet(mlx5_net)経路の RQ/SQ CQ + RQ 受信データバッファ。 */
        static uintptr_t s_rqcq_buf[2][MLX5_NUM_RXQ], s_rqcq_dbr[2][MLX5_NUM_RXQ];
        static uintptr_t s_sqcq_buf[2], s_sqcq_dbr[2];
        static uintptr_t s_rqdata[2][MLX5_NUM_RXQ];
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
            for (unsigned q = 0; q < MLX5_NUM_RXQ; q++) {
                s_rqcq_buf[pf][q] = (uintptr_t)dma_alloc(MLX5_CQ_BUF_SIZE, 4096u, DMA_COHERENT).cpu;
                s_rqcq_dbr[pf][q] = (uintptr_t)dma_alloc(MLX5_CQ_DBR_SIZE, 64u,   DMA_COHERENT).cpu;
                s_rqdata[pf][q]   = (uintptr_t)dma_alloc(MLX5_RQ_DATA_SIZE, 4096u, DMA_COHERENT).cpu;
                s_rqwqe[pf][q]    = (uintptr_t)dma_alloc(MLX5_RQ_WQE_SIZE, 4096u, DMA_DEVICE).cpu;
                s_rqdbr[pf][q]    = (uintptr_t)dma_alloc(MLX5_RQ_DBR_SIZE, 64u,   DMA_DEVICE).cpu;
            }
            s_sqcq_buf[pf] = (uintptr_t)dma_alloc(MLX5_SQ_CQ_BUF_SIZE, 4096u, DMA_COHERENT).cpu;
            s_sqcq_dbr[pf] = (uintptr_t)dma_alloc(MLX5_SQ_CQ_DBR_SIZE, 64u,   DMA_COHERENT).cpu;
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

    if (supported_issi_dw0 & (1u << 1)) {
        if (mlx5_set_issi(dev, 1) != 0) {
            uart_printf("mlx5: SET_ISSI(1) failed\n");
            return -1;
        }
        uart_printf("mlx5: SET_ISSI(1) ok\n");

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

    uint8_t hca_cap[MLX5_HCA_CAP_BYTES];
    if (mlx5_query_hca_cap_general(dev, hca_cap) != 0) {
        return -1;
    }
    uart_printf("mlx5: QUERY_HCA_CAP(general, cur) ok\n");
    uart_printf("mlx5: num_ports=%u lag_master=%u num_lag_ports=%u\n",
                hca_cap[55], (uint8_t)((hca_cap[79] >> 4) & 0x1u), (uint8_t)(hca_cap[79] & 0xFu));

    dev->clock_khz = ((uint32_t)hca_cap[156] << 24) | ((uint32_t)hca_cap[157] << 16) |
                      ((uint32_t)hca_cap[158] << 8) | (uint32_t)hca_cap[159];
    uart_printf("mlx5: device_frequency_khz=%u\n", dev->clock_khz);

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

    if (g_mlx5_skip_fte_experiment) {
        uart_printf("mlx5: SET_FLOW_TABLE_ENTRY SKIPPED (experiment: g_mlx5_skip_fte_experiment=1)\n");
    } else if (mlx5_set_fte_fwd_tir(dev, table_id, group_id, dev->rxq[0].tirn) != 0) {
        uart_printf("mlx5: SET_FLOW_TABLE_ENTRY failed\n");
        return -1;
    } else {
        uart_printf("mlx5: SET_FLOW_TABLE_ENTRY ok (catch-all -> rxq[0].tirn=%u)\n", dev->rxq[0].tirn);
    }

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

static mlx5_dev_t s_last_dev0;
static mlx5_dev_t s_last_dev1;
static int s_last_devs_valid = 0;

/*
 * モニタコマンドが再初期化なしで参照できるよう、bring-up 済みの PF0/PF1 を
 * 保存する。
 *
 * 引数:
 *   dev0, dev1 - 保存する HCA ハンドル
 * コール元:
 *   mlx5_net_register_dual()
 */
void mlx5_monitor_set_devs(const mlx5_dev_t *dev0, const mlx5_dev_t *dev1)
{
    s_last_dev0 = *dev0;
    s_last_dev1 = *dev1;
    s_last_devs_valid = 1;
}

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

#define S_CMDQ(dev)        ((volatile uint8_t *)(uintptr_t)(dev)->cmdq_cpu)
#define S_OUT_MBOX(dev, i) ((volatile mlx5_cmd_prot_block_t *)(uintptr_t)((dev)->out_mbox_cpu + (uint64_t)(i) * MLX5_CMD_MBOX_ALIGN))
#define S_IN_MBOX(dev, i)  ((volatile mlx5_cmd_prot_block_t *)(uintptr_t)((dev)->in_mbox_cpu + (uint64_t)(i) * MLX5_CMD_MBOX_ALIGN))

/*
 * FW へ MANAGE_PAGES(GIVE)で譲渡するスクラッチページ(4KB 単位)の
 * アドレスを返す。
 *
 * 引数:
 *   dev - 対象 HCA
 *   idx - ページ番号
 * 戻り値:
 *   そのページの先頭
 * コール元:
 *   mlx5_manage_pages_give_chunk()
 */
static inline volatile uint8_t *mlx5_fw_page(const mlx5_dev_t *dev, uint32_t idx) {
    /* Phase 2 段階4: DEVICE アリーナから確保した fw_pages 先頭 + idx*4096。 */
    return (volatile uint8_t *)(uintptr_t)((uint64_t)dev->fw_pages_cpu + (uint64_t)idx * MLX5_FW_PAGE_SIZE);
}

#define MLX5_CMD_TIMEOUT_MS 2000u

/*
 * コマンドキューを FW へ登録する(Initialization Segment の
 * CMDQ_ADDR_H/L へ物理アドレスを書く)。書き込み直後は FW が新しい cmdq を
 * 取り込み切るまで少し待つ必要がある。
 *
 * 引数:
 *   dev - 対象 HCA
 * 戻り値:
 *   0=成功、-1=タイムアウト
 * コール元:
 *   mlx5_hca_bringup()
 */
static int mlx5_cmdq_init(mlx5_dev_t *dev) {
    uint32_t cmd_l = mlx5_read32(dev, MLX5_ISEG_CMDQ_ADDR_L_SZ) & 0xffu;
    uint32_t log_sz = (cmd_l >> 4) & 0xfu;
    uint32_t log_stride = cmd_l & 0xfu;
    uart_printf("mlx5: cmdq log_sz=%u (%u entries) log_stride=%u (%u bytes/entry)\n",
                log_sz, 1u << log_sz, log_stride, 1u << log_stride);

    if (log_stride != 6u) {
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
    dma_wmb();

    timer_delay_ms(10);

    return 0;
}

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

/*
 * ENABLE_HCA コマンドを発行する。
 *
 * 引数:
 *   dev - 対象 HCA
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
static int mlx5_enable_hca(mlx5_dev_t *dev) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_ENABLE_HCA >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_ENABLE_HCA & 0xffu);

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

/*
 * QUERY_PAGES で、FW が要求するページ数(boot/init)を問い合わせる。
 *
 * 引数:
 *   dev              - 対象 HCA
 *   op_mod           - boot か init か
 *   out_function_id  - 対象 function id の格納先
 *   out_num_pages    - 要求ページ数の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
static int mlx5_query_pages(mlx5_dev_t *dev, uint32_t op_mod, uint16_t *out_function_id, int32_t *out_num_pages) {
    uint8_t in[16] = {0};
    in[0] = (uint8_t)(MLX5_CMD_OP_QUERY_PAGES >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_QUERY_PAGES & 0xffu);
    in[6] = (uint8_t)(op_mod >> 8);
    in[7] = (uint8_t)(op_mod & 0xffu);

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

#define MLX5_MANAGE_PAGES_MAX_PER_CALL 64u
_Static_assert(16u + MLX5_MANAGE_PAGES_MAX_PER_CALL * 8u <= MLX5_CMD_MAILBOX_MAX,
               "MLX5_MANAGE_PAGES_MAX_PER_CALL must fit in a single mailbox block");

/*
 * MANAGE_PAGES(GIVE)を 1 チャンク分(単一メールボックスに収まる最大
 * ページ数まで)発行する。
 *
 * 引数:
 *   dev            - 対象 HCA
 *   function_id    - 対象 function
 *   n              - このチャンクで渡すページ数
 *   page_base_idx  - 渡すページの開始番号
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_manage_pages_give()
 */
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

/*
 * npages 全体をチャンクに分けて MANAGE_PAGES(GIVE)を繰り返し発行する
 * (init ページは数千ページになるため 1 回では送れない)。
 *
 * 引数:
 *   dev         - 対象 HCA
 *   function_id - 対象 function
 *   npages      - 渡すページ総数
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * QUERY_ISSI で現在の ISSI と対応 ISSI のビットマップを読む。
 *
 * 引数:
 *   dev                     - 対象 HCA
 *   out_current_issi        - 現在値の格納先
 *   out_supported_issi_dw0  - 対応ビットマップの格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * SET_ISSI で使用する ISSI を設定する。
 *
 * 引数:
 *   dev  - 対象 HCA
 *   issi - 設定する ISSI(通常 1)
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

#define MLX5_CMD_OP_QUERY_HCA_CAP 0x100u
#define MLX5_CMD_OP_INIT_HCA      0x102u
#define MLX5_CMD_OP_SET_HCA_CAP   0x109u

#define MLX5_CAP_TYPE_GENERAL 0u
#define MLX5_CAP_TYPE_ETHERNET_OFFLOADS 1u
#define MLX5_CAP_TYPE_ROCE 4u
#define MLX5_HCA_CAP_OPMOD_CUR 1u

_Static_assert(16u + MLX5_HCA_CAP_BYTES <= MLX5_CMD_MAILBOX_MAX,
               "general HCA caps must fit in a single mailbox block");

/*
 * QUERY_HCA_CAP(general, current)で 256 バイトの general capability を読む。
 *
 * 引数:
 *   dev     - 対象 HCA
 *   cap_out - 256 バイトの格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * QUERY_HCA_CAP(ETHERNET_OFFLOADS)を読み、LSO の最大バイト数を取り出す。
 *
 * 引数:
 *   dev               - 対象 HCA
 *   out_max_lso_bytes - LSO 上限の格納先(非対応なら 0)
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * SET_HCA_CAP(general)で capability を設定する。QUERY_HCA_CAP で読んだ
 * 現在値をそのまま送り返す最小実装。
 *
 * 引数:
 *   dev    - 対象 HCA
 *   cap_in - 送り返す 256 バイト
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * INIT_HCA コマンドを発行し HCA を稼働状態にする。
 *
 * 引数:
 *   dev - 対象 HCA
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

#define MLX5_CMD_OP_ALLOC_UAR 0x802u
#define MLX5_CMD_OP_CREATE_EQ 0x301u

/*
 * ALLOC_UAR で UAR(ドアベル書き込み用の BAR 領域)を確保する。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   out_uarn - UAR 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup(), mlx5_qp_create_rc(), mlx5_qp_create_ud_common()
 */
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

#define MLX5_EQE_SIZE 64u
#define MLX5_EQ_NUM_ENTRIES (MLX5_EQ_BUF_SIZE / MLX5_EQE_SIZE)
#define MLX5_EQE_OWNER_INIT_VAL 1u // eq.cのinit_eq_buf()と同じ初期値
_Static_assert(MLX5_EQ_NUM_ENTRIES == 64u, "MLX5_EQ_BUF_SIZE/MLX5_EQE_SIZE assumption changed");

/*
 * CREATE_EQ で Event Queue を作る。このドライバはポーリング専用で割り込みを
 * 使わないため、CREATE_CQ が要求する eqn を満たすための最小限のダミー。
 *
 * 引数:
 *   dev     - 対象 HCA
 *   uarn    - 使用する UAR 番号
 *   out_eqn - EQ 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
static int mlx5_create_eq(mlx5_dev_t *dev, uint32_t uarn, uint32_t *out_eqn) {
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

    if (out_eqn) {
        *out_eqn = out[11];
    }
    return 0;
}

#define MLX5_CMD_OP_ALLOC_PD    0x800u
#define MLX5_CMD_OP_CREATE_MKEY 0x200u

/*
 * ALLOC_PD で Protection Domain を確保する。
 *
 * 引数:
 *   dev     - 対象 HCA
 *   out_pdn - PD 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup(), mlx5_qp_create_rc(), mlx5_qp_create_ud_common()
 */
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

/*
 * CREATE_MKEY で PA(物理アドレス)モードの MKey を作る。start_addr=0 /
 * length64=1 で物理アドレス空間全体を対象にする最小実装。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   pdn      - 所属 PD
 *   out_mkey - mkey の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
static int mlx5_create_mkey_pa(mlx5_dev_t *dev, uint32_t pdn, uint32_t *out_mkey) {
    uint8_t in[272];
    for (unsigned i = 0; i < sizeof(in); i++) {
        in[i] = 0;
    }
    in[0] = (uint8_t)(MLX5_CMD_OP_CREATE_MKEY >> 8);
    in[1] = (uint8_t)(MLX5_CMD_OP_CREATE_MKEY & 0xffu);

    in[16 + 2] = 0x0Cu; // lw=1, lr=1, access_mode_1_0=0(PA)
    in[16 + 4] = 0xFFu;
    in[16 + 5] = 0xFFu;
    in[16 + 6] = 0xFFu;
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
        uart_printf("mlx5: CREATE_MKEY: command status=0x%02x syndrome=0x%08x\n", status, syndrome);
        return -1;
    }

    if (out_mkey) {
        uint32_t mkey_index = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
        *out_mkey = mkey_index << 8; // | mkey_7_0(=0)
    }
    return 0;
}

#define MLX5_CMD_OP_CREATE_CQ 0x400u

#define MLX5_CQE_SIZE 64u
#define MLX5_CQ_NUM_ENTRIES (MLX5_CQ_BUF_SIZE / MLX5_CQE_SIZE)
_Static_assert(MLX5_CQ_NUM_ENTRIES == 1024u, "MLX5_CQ_BUF_SIZE/MLX5_CQE_SIZE assumption changed");
#define MLX5_CQ_LOG_SIZE_VAL 10u // log2(1024) -- cqc.log_cq_sizeへ書く値
_Static_assert((1u << MLX5_CQ_LOG_SIZE_VAL) == MLX5_CQ_NUM_ENTRIES,
               "MLX5_CQ_LOG_SIZE_VAL must be log2(MLX5_CQ_NUM_ENTRIES)");
#define MLX5_CQ_NUM_PAGES (MLX5_CQ_BUF_SIZE / 4096u)
_Static_assert(MLX5_CQ_NUM_PAGES == 16u, "MLX5_CQ_BUF_SIZE/4096 assumption changed");
_Static_assert(272u + MLX5_CQ_NUM_PAGES * 8u <= 528u,
               "CREATE_CQ input must still fit in a single mailbox block");
#define MLX5_CQE_INVALID 0xFu // cq.hのenum MLX5_CQE_INVALID -- op_own上位nibbleがこの値なら「まだHWが書いていない」

/*
 * CREATE_CQ で Completion Queue を作る。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   uarn     - 使用する UAR 番号
 *   eqn      - 紐付ける EQ 番号
 *   buf_addr - CQ バッファ(1 ページ)
 *   dbr_addr - ドアベルレコード
 *   out_cqn  - CQ 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup(), mlx5_qp_create_rc(), mlx5_qp_create_ud_common()
 */
static int mlx5_create_cq(mlx5_dev_t *dev, uint32_t uarn, uint32_t eqn, uint64_t buf_addr, uint64_t dbr_addr, uint32_t *out_cqn) {
    volatile uint8_t *dbr = (volatile uint8_t *)(uintptr_t)dbr_addr;
    for (unsigned i = 0; i < MLX5_CQ_DBR_SIZE; i++) {
        dbr[i] = 0;
    }
    dcache_clean_range((const void *)dbr_addr, MLX5_CQ_DBR_SIZE);

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

    if (out_cqn) {
        *out_cqn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    }
    return 0;
}

#define MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN 0x816u
#define MLX5_CMD_OP_CREATE_TIS             0x912u

/*
 * ALLOC_TRANSPORT_DOMAIN で transport domain を確保する。
 *
 * 引数:
 *   dev     - 対象 HCA
 *   out_tdn - TD 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * CREATE_TIS で送信側の Transport Interface Send を作る。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   tdn      - 所属 transport domain
 *   out_tisn - TIS 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

#define MLX5_CMD_OP_CREATE_RQ  0x908u
#define MLX5_CMD_OP_MODIFY_RQ  0x909u
#define MLX5_CMD_OP_CREATE_TIR 0x900u

#define MLX5_WQ_TYPE_CYCLIC        1u
#define MLX5_WQ_END_PAD_MODE_ALIGN 1u
#define MLX5_RQC_STATE_RST         0u
#define MLX5_RQC_STATE_RDY         1u

/*
 * CREATE_RQ で受信キューを作る。単一の CYCLIC WQ で、各 WQE が専用の受信
 * バッファを指す。作成直後に RQ ドアベルへ「投稿済み WQE 数」を書いて全
 * エントリを一括で武装する(これを忘れると HW は受信を配送できない)。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   rxq_idx  - この PF 内の受信キュー番号
 *   cqn      - 完了を受け取る CQ
 *   pdn      - 所属 PD
 *   uarn     - 使用する UAR
 *   mkey     - 受信バッファを参照する mkey
 *   out_rqn  - RQ 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
static int mlx5_create_rq(mlx5_dev_t *dev, unsigned rxq_idx, uint32_t cqn, uint32_t pdn, uint32_t uarn, uint32_t mkey, uint32_t *out_rqn) {
    volatile uint8_t *wqe_ring = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->rxq[rxq_idx].wqe_cpu;
    for (unsigned i = 0; i < MLX5_RQ_NUM_WQES; i++) {
        volatile uint8_t *wqe = wqe_ring + (uint64_t)i * 16u;
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

    in[80] = (uint8_t)((MLX5_WQ_TYPE_CYCLIC << 4) | (MLX5_WQ_END_PAD_MODE_ALIGN << 1));
    in[89] = (uint8_t)(pdn >> 16);
    in[90] = (uint8_t)(pdn >> 8);
    in[91] = (uint8_t)pdn;
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

/*
 * MODIFY_RQ で RQ を RST から RDY へ遷移させる。
 *
 * 引数:
 *   dev - 対象 HCA
 *   rqn - 対象 RQ
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * CREATE_TIR で受信側の Transport Interface Receive を作る。RSS は使わず
 * DIRECT で単一 RQ へ固定ルーティングする最小実装。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   rqn      - 転送先 RQ
 *   tdn      - 所属 transport domain
 *   out_tirn - TIR 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

#define MLX5_CMD_OP_CREATE_SQ 0x904u
#define MLX5_CMD_OP_MODIFY_SQ 0x905u
#define MLX5_SQC_STATE_RST    0u
#define MLX5_SQC_STATE_RDY    1u
#define MLX5_SQC_STATE_ERR    3u  // mlx5_monitor_dump_dev()のstate表示コメント参照

/*
 * CREATE_SQ で送信キューを作る。tis_lst_sz=1 と tis_num_0 の設定が必須で、
 * これを忘れると CREATE_SQ/MODIFY_SQ は成功するのに WQE が一切フェッチ
 * されず SQ が黙って ERR へ落ちる。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   cqn      - 完了を受け取る CQ
 *   pdn      - 所属 PD
 *   uarn     - 使用する UAR
 *   tisn     - 送信に使う TIS
 *   out_sqn  - SQ 番号の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * MODIFY_SQ で SQ の状態を遷移させる。
 *
 * 引数:
 *   dev       - 対象 HCA
 *   sqn       - 対象 SQ
 *   cur_state - 現在の状態
 *   new_state - 遷移先の状態
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_modify_sq_to_rdy(), mlx5_recover_sq()
 */
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

/*
 * SQ を RST から RDY へ遷移させる薄いラッパ。
 *
 * 引数:
 *   dev - 対象 HCA
 *   sqn - 対象 SQ
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
static int mlx5_modify_sq_to_rdy(mlx5_dev_t *dev, uint32_t sqn) {
    return mlx5_modify_sq_state(dev, sqn, MLX5_SQC_STATE_RST, MLX5_SQC_STATE_RDY);
}

#define MLX5_CMD_OP_ACCESS_REG 0x805u
#define MLX5_REG_PAOS          0x5006u
/*
 * ACCESS_REG(PAOS)でポートの admin 状態を UP にする。これを呼ばないと
 * ポートは論理的に無効のままで、フレームが一切流れない。
 *
 * 引数:
 *   dev - 対象 HCA
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * PAOS の oper_status(PHY のオートネゴシエーション完了を要する実際の
 * リンク状態、admin_status とは別)を読む。
 *
 * 引数:
 *   dev             - 対象 HCA
 *   out_oper_status - 格納先(1=UP)
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

#define MLX5_REG_PMTU 0x5003u

/*
 * PMTU の max_mtu(このポートが受け付ける最大フレーム長)を読む。
 *
 * 引数:
 *   dev         - 対象 HCA
 *   out_max_mtu - 格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_set_port_mtu()
 */
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

/*
 * PMTU の admin_mtu へ希望値を書く。先に max_mtu を読み、超える場合は
 * 切り詰めてから書く(黙って拒否されるより安全側)。
 *
 * 引数:
 *   dev              - 対象 HCA
 *   desired_mtu      - 希望するワイヤ上の最大フレーム長
 *   out_applied_mtu  - 実際に適用された値の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

#define MLX5_CMD_OP_QUERY_ROCE_ADDRESS 0x760u
#define MLX5_CMD_OP_SET_ROCE_ADDRESS   0x761u
#define MLX5_ROCE_L3_TYPE_IPV4 0u
#define MLX5_ROCE_VERSION_2    2u

/*
 * IPv4 から IPv4-mapped IPv6 形式の RoCEv2 GID(::ffff:a.b.c.d)を構築する。
 *
 * 引数:
 *   ipv4_host_order - IPv4(ホストバイトオーダー)
 *   out_gid         - 16 バイトの格納先
 * コール元:
 *   rdma_cm_fill_addr()
 */
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

/*
 * SET_ROCE_ADDRESS で GID テーブルへ自分の GID と MAC を登録する
 * (RoCEv2 固定、L3 type は IPv4)。
 *
 * 引数:
 *   dev   - 対象 HCA
 *   index - GID テーブルのインデックス
 *   gid   - 登録する GID(16 バイト)
 *   mac   - 登録する MAC(6 バイト)
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_setup_gsi()
 */
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

/*
 * QPC の primary_address_path(44 バイト)へ RoCEv2 のアドレス情報
 * (相手 GID/MAC、UDP sport、hop limit、vhca_port_num)を書く。
 *
 * 引数:
 *   ads             - qpc+24 を指すポインタ
 *   remote_gid      - 相手 GID
 *   remote_mac      - 相手 MAC
 *   udp_sport       - 算出済み UDP 送信元ポート
 *   set_ack_timeout - 1=ack_timeout も設定する(RTR2RTS 用)
 * コール元:
 *   mlx5_qp_modify_init2rtr(), mlx5_qp_modify_init2rtr_ud(), mlx5_qp_modify_rtr2rts()
 */
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

/*
 * QPN の組から RoCEv2 の UDP 送信元ポートを算出する(Linux の
 * rdma_calc_flow_label()/rdma_flow_label_to_udp_sport() と同じ式)。
 *
 * 引数:
 *   lqpn - 自分の QPN
 *   rqpn - 相手の QPN
 * 戻り値:
 *   UDP 送信元ポート
 * コール元:
 *   mlx5_qp_modify_init2rtr(), mlx5_qp_post_send_ud()
 */
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

/*
 * リモートからの RDMA_WRITE/READ を許可した PA モード MKey を作る
 * (rw/rr ビットを立てる)。RDMA データ転送にはこちらが要る。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   pdn      - 所属 PD
 *   out_mkey - mkey の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_qp_create_rc(), mlx5_qp_create_ud_common()
 */
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

/*
 * MODIFY_NIC_VPORT_CONTEXT で roce_en=1 を立てる。これが無いと
 * INIT2RTR_QP が BAD_OP_ERR で拒否される(RoCE アドレスパスを参照しない
 * CREATE_QP/RST2INIT_QP は成功してしまうため気付きにくい)。
 *
 * 引数:
 *   dev - 対象 HCA
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_qp_create_rc(), mlx5_qp_create_ud_common()
 */
static int mlx5_nic_vport_enable_roce(mlx5_dev_t *dev) {
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

/*
 * RC QP を 1 本作る。必要な UAR/PD/MKey(rw+rr)/CQ もここでまとめて確保し、
 * roce_en も立てる。WQE/CQ の DMA アドレスは qp_index で 1 本目/2 本目を
 * 切り替える。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   qp       - 初期化する QP ハンドル
 *   qp_index - 0=admin 用、1=IO キュー用
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_setup_rc()
 */
int mlx5_qp_create_rc(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t qp_index) {
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
    qp->qpn = ((uint32_t)out[9] << 16) | ((uint32_t)out[10] << 8) | out[11];
    uart_printf("mlx5qp: CREATE_QP ok: qpn=%u local_psn=%u cqn=%u pdn=%u uarn=%u mkey=0x%08x\n",
                qp->qpn, qp->local_psn, qp->cqn, qp->pdn, qp->uarn, qp->mkey);
    return 0;
}

/*
 * RC QP を RST から INIT へ遷移させる。この FW では pd と
 * vhca_port_num だけを設定すること(rre/rwe/rae を含めると BAD_PARAM_ERR)。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 対象 QP
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_setup_rc()
 */
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

/*
 * RC QP を INIT から RTR へ遷移させる。相手 QPN・開始 PSN・path MTU と
 * RoCEv2 アドレスパスを設定する。**開始 PSN の向きに注意** -- 自分が受信に
 * 期待する PSN は自分が REQ/REP で宣言した値、送信に使う PSN は相手が
 * 宣言した値。
 *
 * 引数:
 *   dev              - 対象 HCA
 *   qp               - 対象 QP
 *   remote_qpn       - 相手の QPN
 *   remote_start_psn - 相手が宣言した開始 PSN
 *   remote_gid       - 相手 GID
 *   remote_mac       - 相手 MAC
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_job_step()
 */
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
    uint8_t mtu_val = qp->path_mtu;
    if (mtu_val < 1u || mtu_val > 5u) mtu_val = IB_MTU_1024; // 1=256..5=4096、範囲外は1024
    qpc[8] = (uint8_t)((mtu_val << 5) | (20u & 0x1Fu)); // mtu(pos0-2)|log_msg_max(pos3-7)
    qpc[21] = (uint8_t)(remote_qpn >> 16);
    qpc[22] = (uint8_t)(remote_qpn >> 8);
    qpc[23] = (uint8_t)remote_qpn; // remote_qpn(byte21-23)
    qpc[148] = (uint8_t)(12u & 0x1Fu); // min_rnr_nak(pos3-7)=12
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

/*
 * この HCA が同時に受け付けられる RDMA_READ の数を返す(general cap の
 * log_max_ra_req_qp / log_max_ra_res_qp の小さい方から求める)。実測では 1。
 *
 * 引数:
 *   dev - 対象 HCA
 * 戻り値:
 *   同時 RDMA_READ 数
 * コール元:
 *   mlx5_qp_modify_rtr2rts(), nvmet_rdma_job_step()
 */
uint32_t mlx5_qp_max_concurrent_rdma_read(mlx5_dev_t *dev) {
    uint8_t log_v = dev->log_max_ra_req_qp;
    if (dev->log_max_ra_res_qp < log_v) log_v = dev->log_max_ra_res_qp;
    if (log_v > 4u) log_v = 4u;
    return 1u << log_v;
}

/*
 * RC QP を RTR から RTS へ遷移させる。rre/rwe(リモート RDMA アクセス許可)
 * と log_rra_max はこの遷移で設定する -- INIT2RTR で書いても FW は保持しない。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 対象 QP
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_job_step()
 */
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

/*
 * QUERY_QP で QP の RQ/SQ が実際に何 WQE 処理したかを読む(HW 側と
 * ソフトウェア側のカウンタを突き合わせ、詰まりの所在を切り分ける診断用)。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 対象 QP
 *   out_hw_rq / out_sw_rq - RQ の HW/SW カウンタ
 *   out_hw_sq / out_sw_sq - SQ の HW/SW カウンタ
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   nvme_rdma_connect_job_step(), nvmet_rdma_job_step()
 */
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

/*
 * DESTROY_QP で FW 側の QP オブジェクトを解放する。ジョブを止めるだけでは
 * 解放されず、作り直しを繰り返すと FW のリソースが枯渇する。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 解放する QP
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   nvmer_destroy_qp_if_valid(), nvmetr_destroy_qp_if_valid()
 */
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

#define MLX5_QP_ST_UD  0x2u // include/linux/mlx5/qp.hのenumで確認済み
#define MLX5_QP_ST_QP1 0x8u // 同、drivers/infiniband/hw/mlx5/qp.cの
#define MLX5_QP1_QKEY  0x80010000u // include/rdma/ib_mad.hのIB_QP1_QKEY。

/*
 * UD / GSI QP を 1 本作る共通実装(service type だけが違う)。RC 同様に
 * UAR/PD/MKey/CQ の確保と roce_en も行う。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 初期化する QP ハンドル
 *   st  - service type(UD か QP1)
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_qp_create_gsi()
 */
static int mlx5_qp_create_ud_common(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t st) {
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

/*
 * GSI(QP1 相当)QP を作る薄いラッパ。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 初期化する QP ハンドル
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_setup_gsi()
 */
int mlx5_qp_create_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp) {
    return mlx5_qp_create_ud_common(dev, qp, MLX5_QP_ST_QP1);
}

/*
 * UD/GSI QP を RST から INIT へ遷移させる。
 *
 * 引数:
 *   dev  - 対象 HCA
 *   qp   - 対象 QP
 *   qkey - このキューの Q_Key
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_setup_gsi()
 */
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

/*
 * UD/GSI QP を INIT から RTR へ遷移させる。UD は相手情報を QPC ではなく
 * 送信 WQE の AV に載せるため、ここでは path 情報を設定しない。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 対象 QP
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_setup_gsi()
 */
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

/*
 * UD/GSI QP を RTR から RTS へ遷移させる。
 *
 * 引数:
 *   dev - 対象 HCA
 *   qp  - 対象 QP
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   rdma_cm_setup_gsi()
 */
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

#define MLX5_CMD_OP_SET_FLOW_TABLE_ROOT  0x92fu
#define MLX5_CMD_OP_CREATE_FLOW_TABLE    0x930u
#define MLX5_CMD_OP_CREATE_FLOW_GROUP    0x933u
#define MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY 0x936u

#define MLX5_FLOW_TABLE_TYPE_NIC_RX          0u
#define MLX5_IFC_FLOW_DESTINATION_TYPE_TIR   2u
#define MLX5_FLOW_CONTEXT_ACTION_FWD_DEST    0x4u

/*
 * CREATE_FLOW_TABLE で NIC RX のフローテーブルを作る。
 *
 * 引数:
 *   dev          - 対象 HCA
 *   out_table_id - テーブル ID の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * SET_FLOW_TABLE_ROOT で作ったテーブルを NIC RX のルートに設定する。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   table_id - ルートにするテーブル
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * CREATE_FLOW_GROUP で match 条件を一切持たない catch-all グループを作る
 * (1024 バイトの固定長コマンドでメールボックスチェインが要る)。
 *
 * 引数:
 *   dev          - 対象 HCA
 *   table_id     - 所属テーブル
 *   out_group_id - グループ ID の格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * SET_FLOW_TABLE_ENTRY で「全受信フレームを TIR へ転送する」ルールを 1 本
 * 入れる。これが無いと HW はフレームを RQ へ届けない。
 *
 * 引数:
 *   dev      - 対象 HCA
 *   table_id - 対象テーブル
 *   group_id - 対象グループ
 *   tirn     - 転送先 TIR
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hca_bringup()
 */
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

/*
 * PAOS から admin/oper 両方のポート状態を読む。
 *
 * 引数:
 *   dev - 対象 HCA
 *   out_admin_status / out_oper_status - 格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_monitor_dump_dev(), mlx5_monitor_summary3()
 */
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

/*
 * ACCESS_REG(PPCNT)で物理ポートの統計カウンタグループを読む。
 *
 * 引数:
 *   dev     - 対象 HCA
 *   grp     - カウンタグループ(0x0=IEEE802.3, 0x12=Physical Layer)
 *   out     - 読んだレジスタの格納先
 *   out_len - その容量
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_dump_ieee802_3(), mlx5_dump_phys_layer(), mlx5_hw_error_flags()
 */
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

/*
 * PPCNT レジスタから 32bit カウンタを取り出す。
 *
 * 引数:
 *   reg - PPCNT レジスタ
 *   off - バイトオフセット
 * 戻り値:
 *   カウンタ値
 * コール元:
 *   mlx5_dump_phys_layer(), mlx5_hw_error_flags()
 */
static uint32_t mlx5_ctr32(const uint8_t *cs, unsigned byte_off) {
    return ((uint32_t)cs[byte_off] << 24) | ((uint32_t)cs[byte_off + 1] << 16) |
           ((uint32_t)cs[byte_off + 2] << 8) | cs[byte_off + 3];
}

/*
 * PPCNT の IEEE802.3 グループ(tx/rx frames_ok、fcs_err、align_err 等)を
 * 表示する。MAC 層まで実際にフレームが届いているかの確認に使う。
 *
 * 引数:
 *   dev - 対象 HCA
 * コール元:
 *   mlx5_monitor_dump_dev()
 */
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

/*
 * PPCNT の Physical Layer グループ(symbol_errors、link_down_events 等)を
 * 表示する。
 *
 * 引数:
 *   dev - 対象 HCA
 * コール元:
 *   mlx5_monitor_dump_dev()
 */
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

/*
 * ACCESS_REG(MTMP)でチップ温度を読む。値はいずれも 1/8 度単位。
 *
 * out_peak は「許容最大」ではなく **これまでに記録された最高温度**
 * (struct mlx5_ifc_mtmp_reg_bits の max_temperature、Linux hwmon の
 * temp1_highest 相当。mtr ビットでリセットでき、mte ビットで記録の
 * 有効/無効を切り替えられる履歴値)。許容最大は out_crit の方
 * (temp_threshold_hi、hwmon の temp1_crit 相当)。
 *
 * 引数:
 *   dev       - 対象 HCA
 *   out_temp  - 現在の温度の格納先(不要なら NULL)
 *   out_peak  - 記録された最高温度の格納先(不要なら NULL)
 *   out_crit  - 許容最大(critical しきい値)の格納先(不要なら NULL)
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_monitor_summary3()
 */
static int mlx5_query_mtmp(mlx5_dev_t *dev, int16_t *out_temp, int16_t *out_peak,
                           int16_t *out_crit) {
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
    // バイト位置は mtmp_reg のビットオフセットそのまま:
    //   temperature=0x30 -> 6, max_temperature=0x50 -> 10, temp_threshold_hi=0x70 -> 14
    if (out_temp) *out_temp = (int16_t)(((uint16_t)rd[6] << 8) | rd[7]);
    if (out_peak) *out_peak = (int16_t)(((uint16_t)rd[10] << 8) | rd[11]);
    if (out_crit) *out_crit = (int16_t)(((uint16_t)rd[14] << 8) | rd[15]);
    return 0;
}

/*
 * ACCESS_REG(MPCNT)で PCIe レイヤのエラーカウンタを読む。
 *
 * 引数:
 *   dev     - 対象 HCA
 *   grp     - カウンタグループ
 *   out     - 読んだレジスタの格納先
 *   out_len - その容量
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_hw_error_flags()
 */
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

/*
 * PPCNT/MPCNT の 64bit カウンタが非ゼロかを調べる。
 *
 * 引数:
 *   reg - レジスタ
 *   off - バイトオフセット
 * 戻り値:
 *   1=非ゼロ、0=ゼロ
 * コール元:
 *   mlx5_hw_error_flags()
 */
static int mlx5_ctr64_nonzero(const uint8_t *cs, unsigned off) {
    for (unsigned i = 0; i < 8; i++) if (cs[off + i]) return 1;
    return 0;
}

#define MLX5_HWERR_FW      0x01u
#define MLX5_HWERR_PCIE    0x02u
#define MLX5_HWERR_ETH_FCS 0x04u
#define MLX5_HWERR_ETH_ALN 0x08u
#define MLX5_HWERR_ETH_SYM 0x10u
/*
 * PPCNT/MPCNT/health レジスタを走査し、ハードウェアエラーが 1 つでも
 * 立っているかをフラグにまとめる。
 *
 * 引数:
 *   dev - 対象 HCA
 * 戻り値:
 *   エラー種別のビットマスク(0=異常なし)
 * コール元:
 *   mlx5_monitor_summary3()
 */
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

typedef struct {
    int valid;
    unsigned cur_spd, cur_w, max_spd, max_w, mps, mrrs;
    uint16_t devsta;
} mlx5_pcie_info_t;
/*
 * PCI コンフィグ空間の PCIe Capability からリンク速度・幅・MPS・MRRS を
 * 読み出す。
 *
 * 引数:
 *   rd  - コンフィグ空間リード関数
 *   ctx - rd へ渡すコンテキスト
 *   o   - 読み取り結果の格納先
 * コール元:
 *   mlx5_monitor_summary3()
 */
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

/*
 * シェルの `monitor`。PF0/PF1 について温度・health・PCIe リンク状態・
 * MAC/PHY エラーカウンタ・ポート状態をまとめて表示する。
 *
 * 引数:
 *   dev0, dev1 - 表示する HCA
 *   rd         - コンフィグ空間リード関数
 *   ctx0, ctx1 - rd へ渡すコンテキスト
 * コール元:
 *   shell_dispatch()
 */
void mlx5_monitor_summary3(mlx5_dev_t *d0, mlx5_dev_t *d1,
                           uint32_t (*rd)(void *, uint32_t), void *cx0, void *cx1) {
    mlx5_dev_t *dv[2] = { d0, d1 };
    void *cx[2] = { cx0, cx1 };
    mlx5_pcie_info_t pi[2];
    uint32_t ef[2];
    int16_t tc[2] = { 0, 0 }, tp[2] = { 0, 0 }, tk[2] = { 0, 0 };
    uint8_t op[2] = { 0, 0 };
    for (int i = 0; i < 2; i++) {
        mlx5_pcie_query_cfg(rd, cx[i], &pi[i]);
        ef[i] = mlx5_hw_error_flags(dv[i], pi[i].valid ? pi[i].devsta : 0);
        mlx5_query_mtmp(dv[i], &tc[i], &tp[i], &tk[i]);
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
    // peak=これまでの最高記録、crit=許容最大(MTMP の max_temperature /
    // temp_threshold_hi、mlx5_query_mtmp() のコメント参照)。
    uart_printf("  |  temp PF0/PF1=%d/%dC (peak %d/%d, crit %d/%d)  |  FW=%s\n",
                tc[0] / 8, tc[1] / 8, tp[0] / 8, tp[1] / 8, tk[0] / 8, tk[1] / 8,
                (all & MLX5_HWERR_FW) ? "ASSERT" : "ok");
    // --- 2行目: Ether ポートのリンク状態 ---
    uart_printf("mlx5: Ether:  PF0(port1) link=%s   PF1(port2) link=%s\n",
                op[0] ? "UP" : "DOWN", op[1] ? "UP" : "DOWN");
    // --- 3行目: PCIe リンク(PF0/PF1 は同一ASICなのでMPS/MRRSは共通表示) ---
    uart_printf("mlx5: PCIe :  PF0 Gen%u x%u   PF1 Gen%u x%u   MPS=%uB MRRS=%uB\n",
                pi[0].cur_spd, pi[0].cur_w, pi[1].cur_spd, pi[1].cur_w,
                128u << pi[0].mps, 128u << pi[0].mrrs);
}

/*
 * QUERY_RQ / QUERY_SQ で WQ の状態(RST/RDY/ERR)と hw/sw カウンタを読む。
 *
 * 引数:
 *   dev       - 対象 HCA
 *   is_sq     - 1=SQ、0=RQ
 *   wqn       - 対象 WQ 番号
 *   out_state - 状態の格納先
 *   out_hw / out_sw - カウンタの格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_monitor_dump_dev(), mlx5_recover_sq()
 */
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

/*
 * ERR 状態に落ちた SQ を ERR->RST->RDY と遷移させて復帰させる。まず
 * QUERY_SQ で本当に ERR かを確認してから行う。
 *
 * 引数:
 *   dev - 対象 HCA
 *   sqn - 対象 SQ
 * 戻り値:
 *   0=復帰した、-1=失敗
 * コール元:
 *   mlx5_net_try_recover()
 */
int mlx5_recover_sq(mlx5_dev_t *dev) {
    uint8_t state = 0xFFu;
    if (mlx5_query_wq_state(dev, MLX5_CMD_OP_QUERY_SQ, dev->sqn, &state, NULL, NULL) != 0) {
        uart_printf("mlx5: SQ(sqn=%u) recovery: QUERY_SQ失敗\n", dev->sqn);
        return -1;
    }
    if (state == MLX5_SQC_STATE_RDY) {
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

/*
 * QUERY_CQ で CQ の status と producer/consumer カウンタを読む
 * (CQ オーバーフローの検出に使う)。
 *
 * 引数:
 *   dev        - 対象 HCA
 *   cqn        - 対象 CQ
 *   out_status - status の格納先
 *   out_pc / out_cc - カウンタの格納先
 * 戻り値:
 *   0=成功、-1=コマンド失敗
 * コール元:
 *   mlx5_monitor_dump_dev()
 */
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

/*
 * 1 つの HCA について、ポート状態・MAC/PHY カウンタ・RQ/SQ/CQ の状態を
 * まとめて表示する。
 *
 * 引数:
 *   dev   - 対象 HCA
 *   label - ログ用の名前
 * コール元:
 *   mlx5_monitor_dump_saved()
 */
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

/*
 * mlx5_monitor_set_devs() で保存済みの PF0/PF1 について
 * mlx5_monitor_dump_dev() を呼ぶ(SQ 復帰時などに再初期化なしで状態を残す)。
 *
 * コール元:
 *   mlx5_net_try_recover()
 */
void mlx5_monitor_dump_saved(void) {
    if (!s_last_devs_valid) {
        uart_printf("mlx5: no saved HCA state -- run `mlx5` (bring-up) first\n");
        return;
    }
    mlx5_monitor_dump_dev(&s_last_dev0, "PF0(port1)");
    mlx5_monitor_dump_dev(&s_last_dev1, "PF1(port2)");
}
