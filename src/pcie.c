// BCM2712用PCIe2(x4、ドメイン2)ルートコンプレックスの立ち上げ -- RP1を
// 収容する内部リンク。MSI・インバウンドDMA・SSCは実装しない。

#include "pcie.h"
#include "board.h"
#include "mmio.h"
#include "timer.h"
#include "pl011.h"

extern pl011_t debug_uart; // main.cで定義

// --- PCIE_RC_BASEからのレジスタオフセット ---
#define R_RC_CFG_VENDOR_SPECIFIC_REG1   0x0188u
#define R_RC_CFG_PRIV1_ID_VAL3          0x043cu
#define R_RC_CFG_PRIV1_LINK_CAPABILITY  0x04dcu
#define R_RC_TL_VDM_CTL0                0x0a20u
#define R_RC_TL_VDM_CTL1                0x0a0cu
#define R_RC_DL_MDIO_ADDR               0x1100u
#define R_RC_DL_MDIO_WR_DATA            0x1104u
#define R_RC_DL_MDIO_RD_DATA            0x1108u
#define R_RC_PL_PHY_CTL_15              0x184cu

#define R_MISC_MISC_CTRL                0x4008u
#define R_MISC_CPU2PCIE_WIN0_LO         0x400cu
#define R_MISC_CPU2PCIE_WIN0_HI         0x4010u
#define R_MISC_RC_BAR1_CFG_LO           0x402cu
#define R_MISC_RC_BAR2_CFG_LO           0x4034u
#define R_MISC_RC_BAR2_CFG_HI           0x4038u
#define R_MISC_RC_BAR3_CFG_LO           0x403cu
#define R_MISC_UBUS_BAR2_CFG_REMAP      0x40b4u
#define R_MISC_RC_CONFIG_RETRY_TIMEOUT  0x405cu
#define R_MISC_PCIE_CTRL                0x4064u
#define R_MISC_PCIE_STATUS              0x4068u
#define R_MISC_CPU2PCIE_WIN0_BASE_LIMIT 0x4070u
#define R_MISC_CPU2PCIE_WIN0_BASE_HI    0x4080u
#define R_MISC_CPU2PCIE_WIN0_LIMIT_HI   0x4084u
#define R_MISC_HARD_DEBUG               0x4304u
#define R_MISC_CTRL_1                   0x40a0u
#define R_MISC_UBUS_CTRL                0x40a4u
#define R_MISC_UBUS_TIMEOUT             0x40a8u
#define R_MISC_TC_QUEUE_TO_QOS(x)       (0x4160u - (x) * 4u)
#define R_MISC_VDM_PRIO_QOS_HI          0x4164u
#define R_MISC_VDM_PRIO_QOS_LO          0x4168u
#define R_MISC_AXI_INTF_CTRL            0x416cu
#define R_MISC_AXI_READ_ERROR_DATA      0x4170u
// BCM2712の実際のコンフィグ空間ウィンドウ(pcie_offsets_bcm2712[]は別チップ用)。
#define R_EXT_CFG_INDEX                 0x9000u
#define R_EXT_CFG_DATA                  0x8000u

// --- ビットフィールド ---
#define MISC_CTRL_SCB_ACCESS_EN        0x1000u
#define MISC_CTRL_CFG_READ_UR_MODE     0x2000u
#define MISC_CTRL_MAX_BURST_MASK       0x300000u
#define MISC_CTRL_MAX_BURST_SHIFT      20u
#define MISC_CTRL_SCB0_SIZE_MASK       0xf8000000u
#define MISC_CTRL_SCB0_SIZE_SHIFT      27u

#define UBUS_BAR_CFG_REMAP_ACCESS_EN   0x1u

#define HARD_DEBUG_SERDES_IDDQ         0x08000000u

#define PCIE_CTRL_PERSTB                0x4u

#define PCIE_STATUS_DL_ACTIVE          0x20u
#define PCIE_STATUS_PHYLINKUP          0x10u

#define WIN0_BASE_LIMIT_LIMIT_MASK     0xfff00000u
#define WIN0_BASE_LIMIT_BASE_MASK      0x0000fff0u
#define WIN0_BASE_HI_MASK              0xffu
#define WIN0_LIMIT_HI_MASK             0xffu

#define UBUS_CTRL_REPLY_ERR_DIS        (1u << 13)
#define UBUS_CTRL_REPLY_DECERR_DIS     (1u << 19)

#define AXI_EN_RCLK_QOS_ARRAY_FIX      (1u << 13)
#define AXI_EN_QOS_UPDATE_TIMING_FIX   (1u << 12)
#define AXI_DIS_QOS_GATING_IN_MASTER   (1u << 11)
#define AXI_REQFIFO_EN_QOS_PROPAGATION (1u << 7)
#define AXI_MASTER_MAX_OUTSTANDING_MASK 0x3fu

#define CTRL_1_EN_VDM_QOS_CONTROL      (1u << 5)

#define RC_BAR_CFG_LO_SIZE_MASK        0x1fu

#define LINK_CAP_ASPM_MASK             0xc00u
#define LINK_CAP_ASPM_SHIFT            10u
#define ASPM_L1_ONLY                   0x2u

#define VENDOR_REG1_ENDIAN_MASK        0xcu

#define MDIO_PORT0        0u
#define MDIO_CMD_READ     1u
#define MDIO_CMD_WRITE    0u
#define MDIO_DATA_DONE    0x80000000u
#define MDIO_DATA_MASK    0x7fffffffu
#define SET_ADDR_OFFSET   0x1fu

static void log_str(const char *s) {
    pl011_puts(&debug_uart, s);
}

static void log_hex(uint32_t v) {
    pl011_hex32(&debug_uart, v);
}

// --- リセット ---

// rescal(SERDES)リセットを解除し、完了を待つ。
static void rescal_deassert(void) {
    uint32_t reg = mmio_read32(RESCAL_BASE + 0x0);
    mmio_write32(RESCAL_BASE + 0x0, reg | 1u);

    reg = mmio_read32(RESCAL_BASE + 0x0);
    if (!(reg & 1u)) {
        log_str("pcie: rescal failed to start\n");
        return;
    }

    uint64_t start = timer_now();
    while (!(mmio_read32(RESCAL_BASE + 0x8) & 1u)) {
        if (timeout_ms(start, 1000u)) { // 1秒
            log_str("pcie: rescal timed out\n");
            break;
        }
    }

    reg = mmio_read32(RESCAL_BASE + 0x0);
    mmio_write32(RESCAL_BASE + 0x0, reg & ~1u);
}

// "bridge"リセットラインをアサートする。
static void bridge_reset_assert(void) {
    uint32_t bank = BRIDGE_RESET_ID >> 5;
    uint32_t bit = BRIDGE_RESET_ID & 0x1fu;
    uint64_t off = (uint64_t)bank * 0x18u;
    mmio_write32(BRIDGE_RESET_BASE + off + 0x00, 1u << bit);
}

// "bridge"リセットラインを解除する。
static void bridge_reset_deassert(void) {
    uint32_t bank = BRIDGE_RESET_ID >> 5;
    uint32_t bit = BRIDGE_RESET_ID & 0x1fu;
    uint64_t off = (uint64_t)bank * 0x18u;
    mmio_write32(BRIDGE_RESET_BASE + off + 0x04, 1u << bit);
    timer_delay_ms(1);
}

// --- MDIO (refclk PLL修正専用) ---

static uint32_t mdio_form_pkt(uint32_t port, uint32_t regad, uint32_t cmd) {
    uint32_t pkt = 0;
    pkt |= (port & 0xfu) << 16;
    pkt |= (regad & 0xffffu);
    pkt |= (cmd & 0xfffu) << 20;
    return pkt;
}

static int mdio_read(uint32_t port, uint32_t regad, uint32_t *val) {
    mmio_write32(PCIE_RC_BASE + R_RC_DL_MDIO_ADDR, mdio_form_pkt(port, regad, MDIO_CMD_READ));
    mmio_read32(PCIE_RC_BASE + R_RC_DL_MDIO_ADDR);

    uint64_t start = timer_now();
    uint32_t data;
    while (1) {
        data = mmio_read32(PCIE_RC_BASE + R_RC_DL_MDIO_RD_DATA);
        if (data & MDIO_DATA_DONE) {
            break;
        }
        if (timeout_ms(start, 10u)) {
            return -1;
        }
    }
    *val = data & MDIO_DATA_MASK;
    return 0;
}

static int mdio_write(uint32_t port, uint32_t regad, uint32_t wrdata) {
    mmio_write32(PCIE_RC_BASE + R_RC_DL_MDIO_ADDR, mdio_form_pkt(port, regad, MDIO_CMD_WRITE));
    mmio_read32(PCIE_RC_BASE + R_RC_DL_MDIO_ADDR);
    mmio_write32(PCIE_RC_BASE + R_RC_DL_MDIO_WR_DATA, MDIO_DATA_DONE | (wrdata & 0xffffu));

    uint64_t start = timer_now();
    while (mmio_read32(PCIE_RC_BASE + R_RC_DL_MDIO_WR_DATA) & MDIO_DATA_DONE) {
        if (timeout_ms(start, 10u)) {
            return -1;
        }
    }
    return 0;
}

// 54MHz(xosc)のrefclkソースを許可するPLL設定。
static void pcie_munge_pll(void) {
    static const uint8_t regs[] = {0x16, 0x17, 0x18, 0x19, 0x1b, 0x1c, 0x1e};
    static const uint16_t data[] = {0x50b9, 0xbda1, 0x0094, 0x97b4, 0x5030, 0x5030, 0x0007};
    uint32_t tmp;

    mdio_write(MDIO_PORT0, SET_ADDR_OFFSET, 0x1600);
    for (unsigned i = 0; i < sizeof(regs); i++) {
        mdio_write(MDIO_PORT0, regs[i], data[i]);
        mdio_read(MDIO_PORT0, regs[i], &tmp);
    }
    timer_delay_ms(1);
}

// --- QoS / AXIインターフェース設定 ---

// QoS関連のchicken bitとVDM優先度マップを設定する。
static void pcie_set_tc_qos(void) {
    uint32_t reg = mmio_read32(PCIE_RC_BASE + R_MISC_AXI_INTF_CTRL);
    reg &= ~AXI_REQFIFO_EN_QOS_PROPAGATION;
    reg |= AXI_EN_RCLK_QOS_ARRAY_FIX | AXI_EN_QOS_UPDATE_TIMING_FIX | AXI_DIS_QOS_GATING_IN_MASTER;
    mmio_write32(PCIE_RC_BASE + R_MISC_AXI_INTF_CTRL, reg);

    reg = mmio_read32(PCIE_RC_BASE + R_MISC_AXI_INTF_CTRL);
    if (!(reg & AXI_EN_QOS_UPDATE_TIMING_FIX)) {
        reg = (reg & ~AXI_MASTER_MAX_OUTSTANDING_MASK) | 15u;
        mmio_write32(PCIE_RC_BASE + R_MISC_AXI_INTF_CTRL, reg);
    }

    reg = mmio_read32(PCIE_RC_BASE + R_MISC_CTRL_1);
    reg &= ~CTRL_1_EN_VDM_QOS_CONTROL;
    mmio_write32(PCIE_RC_BASE + R_MISC_CTRL_1, reg);

    uint32_t qos_map = 0x08080809u;

    reg = mmio_read32(PCIE_RC_BASE + R_MISC_CTRL_1);
    reg |= CTRL_1_EN_VDM_QOS_CONTROL;
    mmio_write32(PCIE_RC_BASE + R_MISC_CTRL_1, reg);

    mmio_write32(PCIE_RC_BASE + R_MISC_VDM_PRIO_QOS_LO, qos_map);
    mmio_write32(PCIE_RC_BASE + R_MISC_VDM_PRIO_QOS_HI, qos_map);

    mmio_write32(PCIE_RC_BASE + R_RC_TL_VDM_CTL1, 0);

    reg = mmio_read32(PCIE_RC_BASE + R_RC_TL_VDM_CTL0);
    reg |= 0x10000u | 0x20000u | 0x40000u; // VDM_ENABLED | IGNORETAG | IGNOREVNDRID
    mmio_write32(PCIE_RC_BASE + R_RC_TL_VDM_CTL0, reg);
}

// --- アウトバウンドウィンドウ ---

// CPUアドレス範囲をPCIバスアドレスに変換するウィンドウを設定する。
static void pcie_set_outbound_win(unsigned win, uint64_t cpu_addr, uint64_t pcie_addr, uint64_t size) {
    mmio_write32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_LO + (uint64_t)win * 8,
                 (uint32_t)pcie_addr);
    mmio_write32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_HI + (uint64_t)win * 8,
                 (uint32_t)(pcie_addr >> 32));

    uint64_t cpu_addr_mb = cpu_addr / 0x100000ULL;
    uint64_t limit_addr_mb = (cpu_addr + size - 1) / 0x100000ULL;

    uint32_t tmp = mmio_read32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_LIMIT + (uint64_t)win * 4);
    tmp = (tmp & ~WIN0_BASE_LIMIT_BASE_MASK) | (((uint32_t)cpu_addr_mb << 4) & WIN0_BASE_LIMIT_BASE_MASK);
    tmp = (tmp & ~WIN0_BASE_LIMIT_LIMIT_MASK) | (((uint32_t)limit_addr_mb << 20) & WIN0_BASE_LIMIT_LIMIT_MASK);
    mmio_write32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_LIMIT + (uint64_t)win * 4, tmp);

    uint32_t cpu_addr_mb_high = (uint32_t)(cpu_addr_mb >> 12);
    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_HI + (uint64_t)win * 8);
    tmp = (tmp & ~WIN0_BASE_HI_MASK) | (cpu_addr_mb_high & WIN0_BASE_HI_MASK);
    mmio_write32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_HI + (uint64_t)win * 8, tmp);

    uint32_t limit_addr_mb_high = (uint32_t)(limit_addr_mb >> 12);
    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_LIMIT_HI + (uint64_t)win * 8);
    tmp = (tmp & ~WIN0_LIMIT_HI_MASK) | (limit_addr_mb_high & WIN0_LIMIT_HI_MASK);
    mmio_write32(PCIE_RC_BASE + R_MISC_CPU2PCIE_WIN0_LIMIT_HI + (uint64_t)win * 8, tmp);
}

// --- リンクトレーニング ---

// データリンクがアクティブかつPHYリンクアップかを返す。
static int pcie_link_is_up(void) {
    uint32_t status = mmio_read32(PCIE_RC_BASE + R_MISC_PCIE_STATUS);
    return (status & PCIE_STATUS_DL_ACTIVE) && (status & PCIE_STATUS_PHYLINKUP);
}

// PERST#をデアサートしてリンクトレーニングを開始し、確立を待つ。
static int pcie_start_link(void) {
    uint32_t tmp = mmio_read32(PCIE_RC_BASE + R_MISC_PCIE_CTRL);
    tmp |= PCIE_CTRL_PERSTB;
    mmio_write32(PCIE_RC_BASE + R_MISC_PCIE_CTRL, tmp);

    timer_delay_ms(100); // PCIe仕様: PERST#解除後100ms待つ

    uint64_t start = timer_now();
    while (!timeout_ms(start, 100u)) {
        if (pcie_link_is_up()) {
            return 0;
        }
    }
    return -1;
}

// --- 公開API ---

// bus/devfn/offsetのコンフィグ空間を読む。bus 0はRCレジスタへ直接アクセスする。
uint32_t pcie_cfg_read32(uint8_t bus, uint8_t devfn, uint16_t offset) {
    uint32_t reg_off = offset & 0xfffu;
    if (bus == 0) {
        return devfn == 0 ? mmio_read32(PCIE_RC_BASE + reg_off) : 0xffffffffu;
    }
    uint32_t idx = ((uint32_t)bus << 20) | ((uint32_t)devfn << 12);
    mmio_write32(PCIE_RC_BASE + R_EXT_CFG_INDEX, idx);
    return mmio_read32(PCIE_RC_BASE + R_EXT_CFG_DATA + reg_off);
}

// pcie_cfg_read32()の書き込み版。
void pcie_cfg_write32(uint8_t bus, uint8_t devfn, uint16_t offset, uint32_t val) {
    uint32_t reg_off = offset & 0xfffu;
    if (bus == 0) {
        if (devfn == 0) {
            mmio_write32(PCIE_RC_BASE + reg_off, val);
        }
        return;
    }
    uint32_t idx = ((uint32_t)bus << 20) | ((uint32_t)devfn << 12);
    mmio_write32(PCIE_RC_BASE + R_EXT_CFG_INDEX, idx);
    mmio_write32(PCIE_RC_BASE + R_EXT_CFG_DATA + reg_off, val);
}

// PCIeルートコンプレックスを立ち上げ、RP1のBAR割り当てまで完了させる。
int pcie_rc_init(void) {
    uint32_t tmp;

    // リンクが既に確立済みならreset/rescal/PLL/relinkだけスキップする。
    if (!pcie_link_is_up()) {
        log_str("pcie: resetting bridge\n");
        bridge_reset_assert();
        timer_delay_ms(1);
        bridge_reset_deassert();

        tmp = mmio_read32(PCIE_RC_BASE + R_MISC_HARD_DEBUG);
        tmp &= ~HARD_DEBUG_SERDES_IDDQ;
        mmio_write32(PCIE_RC_BASE + R_MISC_HARD_DEBUG, tmp);
        timer_delay_ms(1);

        log_str("pcie: rescal\n");
        rescal_deassert();

        log_str("pcie: munging PLL for 54MHz xosc refclk\n");
        pcie_munge_pll();

        tmp = mmio_read32(PCIE_RC_BASE + R_RC_PL_PHY_CTL_15);
        tmp = (tmp & ~0xffu) | 0x12u; // L1SSエラッタ対策
        mmio_write32(PCIE_RC_BASE + R_RC_PL_PHY_CTL_15, tmp);
    }

    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_MISC_CTRL);
    tmp |= MISC_CTRL_SCB_ACCESS_EN;
    tmp |= MISC_CTRL_CFG_READ_UR_MODE;
    tmp = (tmp & ~MISC_CTRL_MAX_BURST_MASK) | ((1u << MISC_CTRL_MAX_BURST_SHIFT) & MISC_CTRL_MAX_BURST_MASK);
    mmio_write32(PCIE_RC_BASE + R_MISC_MISC_CTRL, tmp);

    pcie_set_tc_qos();

    // インバウンドRC_BAR2ウィンドウ: RP1(のDMAエンジン、例えばEthernet MAC)
    // 自身が発行するPCIバスアドレス 0x10_00000000-0x1f_ffffffff (64GB、
    // bcm2712.dtsiのpcie2ノードのdma-ranges "64GB system RAM space at
    // PCIe 10_00000000" 参照)を、CPU物理アドレス0x0-0xf_ffffffffへ
    // 写す。これが無いとRP1発のDMA読み書きはどこにも届かず、無効領域
    // アクセス扱いになる -- 直後で設定するUBUS_CTRL(REPLY_ERR_DIS/
    // REPLY_DECERR_DIS)+AXI_READ_ERROR_DATA=0xffffffffの効果で、
    // エラー応答の代わりに0xffffffffが返るため、例えばTX記述子の
    // ctrlワードを読んだつもりが0xffffffffになりTX_USEDビット(bit31)が
    // 立って見える(「記述子は既に使用済みだった」ように誤認識される)、
    // という分かりにくい壊れ方をする。
    //
    // rc_bar2_offsetに書く値は「CPU側アドレス」ではなく「PCI側(RP1が
    // 実際に発行する側)アドレス」= 0x10_00000000 そのもの -- 以前の実装は
    // ここを0(CPU側アドレス)と誤解しており、それだと窓がPCIアドレス
    // 0x0-0xf_ffffffff (RP1自身のペリフェラル領域とその先の未使用域)を
    // 開けるだけで、RP1が実際にDMAで使う0x10_00000000-0x1f_ffffffffには
    // 一切かからず、無効化していたのと同じ状態だった。
    // drivers/pci/controller/pcie-brcmstb.cの
    // brcm_pcie_get_rc_bar2_size_and_offset()と、それが依拠する
    // drivers/of/address.cの of_dma_get_range() (`r->offset =
    // range.cpu_addr - range.bus_addr;`) を突き合わせて確認した:
    // `pcie_beg = entry->res->start - entry->offset` は
    // `cpu_addr - (cpu_addr - bus_addr) = bus_addr` となり、
    // `rc_bar2_offset = lowest_pcie_addr` はPCI(bus)側アドレスである。
    // サイズのエンコード(brcm_pcie_encode_ibar_size()相当): 64GB =
    // 2^36なので (36-15) = 21 (64KB-64GB範囲の式: log2(size)-15)。
    //
    // 【結果】この修正(オフセットの向き)自体は正しかったが、単独では
    // Ethernet DMAの不具合は直らなかった -- 本当の原因はRP1のEthernet
    // MAC(GEM)自身が、rp1.dtsiのdma-ranges通りにRP1ローカルアドレスへ
    // +0x10_00000000を自動付加しているわけではなかったこと(GEMを64bit
    // アドレッシングモードに切り替え、ソフトウェア側で明示的に上位32bit
    // =0x10を全DMAアドレスに付加して初めてTX/RXが動いた -- 詳細は
    // src/eth.cのDMA_ADDR_HI32参照)。とはいえこのRC_BAR2窓自体は本物の
    // 必要設定(インバウンドDMAの前提条件)なので、消さずに残すこと。
    uint64_t rc_bar2_offset = 0x1000000000ull; // PCI側アドレス 0x10_00000000
    tmp = (uint32_t)rc_bar2_offset;
    tmp = (tmp & ~RC_BAR_CFG_LO_SIZE_MASK) | (21u & RC_BAR_CFG_LO_SIZE_MASK);
    mmio_write32(PCIE_RC_BASE + R_MISC_RC_BAR2_CFG_LO, tmp);
    mmio_write32(PCIE_RC_BASE + R_MISC_RC_BAR2_CFG_HI, (uint32_t)(rc_bar2_offset >> 32));

    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_UBUS_BAR2_CFG_REMAP);
    tmp |= UBUS_BAR_CFG_REMAP_ACCESS_EN;
    mmio_write32(PCIE_RC_BASE + R_MISC_UBUS_BAR2_CFG_REMAP, tmp);

    // SCB(System Control Bus/メモリチャネル)サイズもBAR2と同じ64GB分
    // (log2(size)-15 = 21)を申告する(brcm,scb-sizesが無い場合の
    // フォールバック計算=BAR2と同一値になるケースにそのまま合わせた)。
    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_MISC_CTRL);
    tmp = (tmp & ~MISC_CTRL_SCB0_SIZE_MASK) | ((21u << MISC_CTRL_SCB0_SIZE_SHIFT) & MISC_CTRL_SCB0_SIZE_MASK);
    mmio_write32(PCIE_RC_BASE + R_MISC_MISC_CTRL, tmp);

    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_UBUS_CTRL);
    tmp |= UBUS_CTRL_REPLY_ERR_DIS | UBUS_CTRL_REPLY_DECERR_DIS;
    mmio_write32(PCIE_RC_BASE + R_MISC_UBUS_CTRL, tmp);
    mmio_write32(PCIE_RC_BASE + R_MISC_AXI_READ_ERROR_DATA, 0xffffffffu);
    mmio_write32(PCIE_RC_BASE + R_MISC_UBUS_TIMEOUT, 0xB2D0000u);
    mmio_write32(PCIE_RC_BASE + R_MISC_RC_CONFIG_RETRY_TIMEOUT, 0xABA0000u);

    // インバウンドRC_BAR1/RC_BAR3ウィンドウを無効化する(不要なため)。
    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_RC_BAR1_CFG_LO);
    tmp &= ~RC_BAR_CFG_LO_SIZE_MASK;
    mmio_write32(PCIE_RC_BASE + R_MISC_RC_BAR1_CFG_LO, tmp);

    tmp = mmio_read32(PCIE_RC_BASE + R_MISC_RC_BAR3_CFG_LO);
    tmp &= ~RC_BAR_CFG_LO_SIZE_MASK;
    mmio_write32(PCIE_RC_BASE + R_MISC_RC_BAR3_CFG_LO, tmp);

    tmp = mmio_read32(PCIE_RC_BASE + R_RC_CFG_PRIV1_LINK_CAPABILITY);
    tmp = (tmp & ~LINK_CAP_ASPM_MASK) | ((ASPM_L1_ONLY << LINK_CAP_ASPM_SHIFT) & LINK_CAP_ASPM_MASK);
    mmio_write32(PCIE_RC_BASE + R_RC_CFG_PRIV1_LINK_CAPABILITY, tmp);

    // コンフィグ空間上でPCIe-PCIeブリッジとして見せる。
    tmp = mmio_read32(PCIE_RC_BASE + R_RC_CFG_PRIV1_ID_VAL3);
    tmp = (tmp & ~0xffffffu) | 0x060400u;
    mmio_write32(PCIE_RC_BASE + R_RC_CFG_PRIV1_ID_VAL3, tmp);

    pcie_set_outbound_win(0, PCIE_OUTBOUND_CPU_BASE, 0, PCIE_OUTBOUND_SIZE);

    tmp = mmio_read32(PCIE_RC_BASE + R_RC_CFG_VENDOR_SPECIFIC_REG1);
    tmp &= ~VENDOR_REG1_ENDIAN_MASK; // リトルエンディアン
    mmio_write32(PCIE_RC_BASE + R_RC_CFG_VENDOR_SPECIFIC_REG1, tmp);

    if (!pcie_link_is_up()) {
        log_str("pcie: deasserting PERST#, waiting for link training\n");
        if (pcie_start_link() != 0) {
            log_str("pcie: link did not come up\n");
            return -1;
        }
        uint32_t status = mmio_read32(PCIE_RC_BASE + R_MISC_PCIE_STATUS);
        log_str("pcie: link up, status=0x");
        log_hex(status);
        log_str("\n");
    }

    // Type-1ブリッジヘッダ: bus 1(RP1)へのコンフィグアクセスを転送させる。
    pcie_cfg_write32(0, 0, 0x18, 0x00010100u);

    // ルートポートのP2Pブリッジメモリウィンドウを全開放する(RP1のBAR宛の
    // メモリアクセスを通すために必要)。
    pcie_cfg_write32(0, 0, 0x20, 0xfff00000u);

    // ルートポート自身のCommand register(bus 0)でMemory Space + Bus Masterを有効化する。
    uint32_t root_cmd = pcie_cfg_read32(0, 0, 0x04);
    root_cmd |= 0x6u;
    pcie_cfg_write32(0, 0, 0x04, root_cmd);

    // RP1のBAR割り当てまで済ませてから返る(呼び出し元は全てRP1が目的のため)。
    return rp1_assign_bar0();
}

// RP1は独立した2本の32ビットBARを持つ: BAR0はPCIeフロントエンド(16KB)、
// BAR1が実際のペリフェラルレジスタ空間(GPIO/SPI/UART/PWM等、4MB)。
int rp1_assign_bar0(void) {
    // 両方のBARをプローブする(全ビット1を書いて読み戻す)。BARのbit0は
    // 常に0のはずなので、0xffffffffのままならRP1は応答していない。
    pcie_cfg_write32(1, 0, 0x10, 0xffffffffu);
    uint32_t probe0 = pcie_cfg_read32(1, 0, 0x10);
    if (probe0 == 0xffffffffu) {
        log_str("pcie: RP1 BAR0 probe read back all-1s -- not responding, aborting\n");
        return -1;
    }

    pcie_cfg_write32(1, 0, 0x14, 0xffffffffu);
    uint32_t probe1 = pcie_cfg_read32(1, 0, 0x14);
    if (probe1 == 0xffffffffu) {
        log_str("pcie: RP1 BAR1 probe read back all-1s -- not responding, aborting\n");
        return -1;
    }

    // BAR1(ペリフェラル)をPCI 0x0に、BAR0はその直後に割り当てる。
    pcie_cfg_write32(1, 0, 0x14, 0x00000000u);
    pcie_cfg_write32(1, 0, 0x10, 0x00410000u);

    uint32_t cmd = pcie_cfg_read32(1, 0, 0x04);
    cmd |= 0x6u; // Memory Space Enable | Bus Master Enable
    pcie_cfg_write32(1, 0, 0x04, cmd);

    return 0;
}
