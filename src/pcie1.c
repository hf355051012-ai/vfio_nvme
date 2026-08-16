// BCM2712用PCIe(x1、ドメイン1)ルートコンプレックスの立ち上げ -- SoC直結の
// 外部M.2/FFCコネクタ(config.txtのdtparam=pciex1が有効化するリンクそのもの、
// board.hのPCIE1_RC_BASE参照)。ConnectX用。
//
// pcie.c(PCIE_RC_BASE、ドメイン2、RP1収容)と同じbrcm,bcm2712-pcie IPブロック
// だが、意図的に別ファイルとして複製している -- pcie.c のpcie_rc_init()は
// 実機フィードバックを重ねて完成した壊れやすいコードで、command.c/err.c/
// eth.cから広く依存されている。ベースアドレスを引数化して汎用化する案も
// 検討したが、RP1側の安定動作に影響が及ぶリスクを避けるため、こちらは
// 完全に独立した新規ファイルとした
// (~/.claude/plans/imperative-conjuring-stallman.md参照)。
//
// レジスタオフセット・ビットフィールドの意味はpcie.cと同一(同じIPブロック)
// なので、詳しいコメントはpcie.c側を参照。ここでは差分(ベースアドレス、
// bridgeリセットid、アウトバウンド窓、BAR0が64bit単一という前提)にのみ
// コメントを付ける。

#include "pcie1.h"
#include "board.h"
#include "mmio.h"
#include "timer.h"
#include "pl011.h"

extern pl011_t debug_uart; // main.cで定義

// --- PCIE1_RC_BASEからのレジスタオフセット(pcie.cと同一) ---
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
#define R_MISC_VDM_PRIO_QOS_HI          0x4164u
#define R_MISC_VDM_PRIO_QOS_LO          0x4168u
#define R_MISC_AXI_INTF_CTRL            0x416cu
#define R_MISC_AXI_READ_ERROR_DATA      0x4170u
#define R_EXT_CFG_INDEX                 0x9000u
#define R_EXT_CFG_DATA                  0x8000u

// --- ビットフィールド(pcie.cと同一) ---
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

// rescal(SERDES)リセットを解除し、完了を待つ。RESCAL_BASEは全PCIeインスタンス
// (PCIE_RC_BASE/PCIE1_RC_BASE)で共有の物理ブロックのため、pcie.cのRP1側で
// 既に解除済みでもここでもう一度呼んで問題ない(既に解除済みの状態から
// 始まり、即座に完了ビットが立っているだけ)。
static void rescal_deassert(void) {
    uint32_t reg = mmio_read32(RESCAL_BASE + 0x0);
    mmio_write32(RESCAL_BASE + 0x0, reg | 1u);

    reg = mmio_read32(RESCAL_BASE + 0x0);
    if (!(reg & 1u)) {
        log_str("pcie1: rescal failed to start\n");
        return;
    }

    uint64_t start = timer_now();
    while (!(mmio_read32(RESCAL_BASE + 0x8) & 1u)) {
        if (timeout_ms(start, 1000u)) { // 1秒
            log_str("pcie1: rescal timed out\n");
            break;
        }
    }

    reg = mmio_read32(RESCAL_BASE + 0x0);
    mmio_write32(RESCAL_BASE + 0x0, reg & ~1u);
}

// "bridge"リセットラインをアサートする(PCIE1_BRIDGE_RESET_ID=43、
// PCIE_RC_BASE用のBRIDGE_RESET_ID=44とは別id)。
static void bridge_reset_assert(void) {
    uint32_t bank = PCIE1_BRIDGE_RESET_ID >> 5;
    uint32_t bit = PCIE1_BRIDGE_RESET_ID & 0x1fu;
    uint64_t off = (uint64_t)bank * 0x18u;
    mmio_write32(BRIDGE_RESET_BASE + off + 0x00, 1u << bit);
}

// "bridge"リセットラインを解除する。
static void bridge_reset_deassert(void) {
    uint32_t bank = PCIE1_BRIDGE_RESET_ID >> 5;
    uint32_t bit = PCIE1_BRIDGE_RESET_ID & 0x1fu;
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
    mmio_write32(PCIE1_RC_BASE + R_RC_DL_MDIO_ADDR, mdio_form_pkt(port, regad, MDIO_CMD_READ));
    mmio_read32(PCIE1_RC_BASE + R_RC_DL_MDIO_ADDR);

    uint64_t start = timer_now();
    uint32_t data;
    while (1) {
        data = mmio_read32(PCIE1_RC_BASE + R_RC_DL_MDIO_RD_DATA);
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
    mmio_write32(PCIE1_RC_BASE + R_RC_DL_MDIO_ADDR, mdio_form_pkt(port, regad, MDIO_CMD_WRITE));
    mmio_read32(PCIE1_RC_BASE + R_RC_DL_MDIO_ADDR);
    mmio_write32(PCIE1_RC_BASE + R_RC_DL_MDIO_WR_DATA, MDIO_DATA_DONE | (wrdata & 0xffffu));

    uint64_t start = timer_now();
    while (mmio_read32(PCIE1_RC_BASE + R_RC_DL_MDIO_WR_DATA) & MDIO_DATA_DONE) {
        if (timeout_ms(start, 10u)) {
            return -1;
        }
    }
    return 0;
}

// 54MHz(xosc)のrefclkソースを許可するPLL設定(pcie.cのpcie_munge_pll()と同一手順)。
static void pcie1_munge_pll(void) {
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

// --- QoS / AXIインターフェース設定(pcie.cのpcie_set_tc_qos()と同一手順) ---

static void pcie1_set_tc_qos(void) {
    uint32_t reg = mmio_read32(PCIE1_RC_BASE + R_MISC_AXI_INTF_CTRL);
    reg &= ~AXI_REQFIFO_EN_QOS_PROPAGATION;
    reg |= AXI_EN_RCLK_QOS_ARRAY_FIX | AXI_EN_QOS_UPDATE_TIMING_FIX | AXI_DIS_QOS_GATING_IN_MASTER;
    mmio_write32(PCIE1_RC_BASE + R_MISC_AXI_INTF_CTRL, reg);

    reg = mmio_read32(PCIE1_RC_BASE + R_MISC_AXI_INTF_CTRL);
    if (!(reg & AXI_EN_QOS_UPDATE_TIMING_FIX)) {
        reg = (reg & ~AXI_MASTER_MAX_OUTSTANDING_MASK) | 15u;
        mmio_write32(PCIE1_RC_BASE + R_MISC_AXI_INTF_CTRL, reg);
    }

    reg = mmio_read32(PCIE1_RC_BASE + R_MISC_CTRL_1);
    reg &= ~CTRL_1_EN_VDM_QOS_CONTROL;
    mmio_write32(PCIE1_RC_BASE + R_MISC_CTRL_1, reg);

    uint32_t qos_map = 0x08080809u;

    reg = mmio_read32(PCIE1_RC_BASE + R_MISC_CTRL_1);
    reg |= CTRL_1_EN_VDM_QOS_CONTROL;
    mmio_write32(PCIE1_RC_BASE + R_MISC_CTRL_1, reg);

    mmio_write32(PCIE1_RC_BASE + R_MISC_VDM_PRIO_QOS_LO, qos_map);
    mmio_write32(PCIE1_RC_BASE + R_MISC_VDM_PRIO_QOS_HI, qos_map);

    mmio_write32(PCIE1_RC_BASE + R_RC_TL_VDM_CTL1, 0);

    reg = mmio_read32(PCIE1_RC_BASE + R_RC_TL_VDM_CTL0);
    reg |= 0x10000u | 0x20000u | 0x40000u; // VDM_ENABLED | IGNORETAG | IGNOREVNDRID
    mmio_write32(PCIE1_RC_BASE + R_RC_TL_VDM_CTL0, reg);
}

// --- アウトバウンドウィンドウ(pcie.cのpcie_set_outbound_win()と同一手順) ---

static void pcie1_set_outbound_win(unsigned win, uint64_t cpu_addr, uint64_t pcie_addr, uint64_t size) {
    mmio_write32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_LO + (uint64_t)win * 8,
                 (uint32_t)pcie_addr);
    mmio_write32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_HI + (uint64_t)win * 8,
                 (uint32_t)(pcie_addr >> 32));

    uint64_t cpu_addr_mb = cpu_addr / 0x100000ULL;
    uint64_t limit_addr_mb = (cpu_addr + size - 1) / 0x100000ULL;

    uint32_t tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_LIMIT + (uint64_t)win * 4);
    tmp = (tmp & ~WIN0_BASE_LIMIT_BASE_MASK) | (((uint32_t)cpu_addr_mb << 4) & WIN0_BASE_LIMIT_BASE_MASK);
    tmp = (tmp & ~WIN0_BASE_LIMIT_LIMIT_MASK) | (((uint32_t)limit_addr_mb << 20) & WIN0_BASE_LIMIT_LIMIT_MASK);
    mmio_write32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_LIMIT + (uint64_t)win * 4, tmp);

    uint32_t cpu_addr_mb_high = (uint32_t)(cpu_addr_mb >> 12);
    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_HI + (uint64_t)win * 8);
    tmp = (tmp & ~WIN0_BASE_HI_MASK) | (cpu_addr_mb_high & WIN0_BASE_HI_MASK);
    mmio_write32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_BASE_HI + (uint64_t)win * 8, tmp);

    uint32_t limit_addr_mb_high = (uint32_t)(limit_addr_mb >> 12);
    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_LIMIT_HI + (uint64_t)win * 8);
    tmp = (tmp & ~WIN0_LIMIT_HI_MASK) | (limit_addr_mb_high & WIN0_LIMIT_HI_MASK);
    mmio_write32(PCIE1_RC_BASE + R_MISC_CPU2PCIE_WIN0_LIMIT_HI + (uint64_t)win * 8, tmp);
}

// --- リンクトレーニング ---

static int pcie1_link_is_up(void) {
    uint32_t status = mmio_read32(PCIE1_RC_BASE + R_MISC_PCIE_STATUS);
    return (status & PCIE_STATUS_DL_ACTIVE) && (status & PCIE_STATUS_PHYLINKUP);
}

static int pcie1_start_link(void) {
    uint32_t tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_PCIE_CTRL);
    tmp |= PCIE_CTRL_PERSTB;
    mmio_write32(PCIE1_RC_BASE + R_MISC_PCIE_CTRL, tmp);

    timer_delay_ms(100); // PCIe仕様: PERST#解除後100ms待つ

    uint64_t start = timer_now();
    while (!timeout_ms(start, 100u)) {
        if (pcie1_link_is_up()) {
            return 0;
        }
    }
    return -1;
}

// PERST#を明示的にアサート->デアサートするサイクル(pcie1.hのコメント参照)。
// pcie1_start_link()はデアサートのみ(電源投入直後のブリングアップ専用)
// だったため、こちらはアサート側も自前で行う新規関数。
//
// 【2026-08-07、実機で発見・修正】この関数はPERST#のトグルのみを行い、
// RC側(SoCローカル)のbridge_reset/rescal(SERDES)/PLL(refclk)初期化
// (pcie1_rc_init()冒頭の`if (!pcie1_link_is_up())`ブロック)を一切
// 行っていなかった -- これは「同一起動セッション内で既に`pcie1_rc_init()`
// (`pcie1`/`mlx5`/`net init mlx5`のいずれか)が最低1回は実行済みで、
// RC側の初期化が既に済んでいる」ことを暗黙の前提にしていた。実機で
// `reboot`直後(この起動セッションでPCIe1関連コマンドを一度も実行して
// いない状態)に`pcie1 reset`を最初のPCIe1操作として実行したところ、
// 「link did not come back up after PERST# reset」で確実に失敗した
// (2回連続再現)。直後に素の`pcie1`(rescal/PLL込みのフルブリングアップ)
// を実行すると即座にリンクアップし、ConnectXカード/リンク自体は健全
// であることを確認 -- PERST#トグルだけではRC側が未初期化のままの
// SERDES/PLLでリンクトレーニングできないというRC側の準備不足が真因
// だったと判断できる。**修正**: PERST#アサート前にbridge_reset/rescal/
// PLL setup(pcie1_rc_init()と同一の手順)を無条件で行うようにした
// (rescal_deassert()等は既に「複数回呼んでも問題ない」設計、コメント
// 参照) -- 同一セッション内で既に初期化済みの場合も、この程度の
// 追加コストは`pcie1 reset`自体が低頻度の操作である以上無視できる。 */
int pcie1_reset_link(void) {
    bridge_reset_assert();
    timer_delay_ms(1);
    bridge_reset_deassert();

    uint32_t tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_HARD_DEBUG);
    tmp &= ~HARD_DEBUG_SERDES_IDDQ;
    mmio_write32(PCIE1_RC_BASE + R_MISC_HARD_DEBUG, tmp);
    timer_delay_ms(1);

    rescal_deassert();
    pcie1_munge_pll();

    tmp = mmio_read32(PCIE1_RC_BASE + R_RC_PL_PHY_CTL_15);
    tmp = (tmp & ~0xffu) | 0x12u; // L1SSエラッタ対策(pcie1_rc_init()と同一)
    mmio_write32(PCIE1_RC_BASE + R_RC_PL_PHY_CTL_15, tmp);

    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_PCIE_CTRL);
    tmp &= ~PCIE_CTRL_PERSTB; // PERST#をアサート(Low駆動)
    mmio_write32(PCIE1_RC_BASE + R_MISC_PCIE_CTRL, tmp);

    log_str("pcie1: PERST# asserted, holding ConnectX in reset\n");
    timer_delay_ms(10); // PCIe仕様のTPERST最小100usより十分長く確保

    tmp |= PCIE_CTRL_PERSTB; // PERST#をデアサート(High駆動、pcie1_start_link()と同じビット)
    mmio_write32(PCIE1_RC_BASE + R_MISC_PCIE_CTRL, tmp);

    log_str("pcie1: PERST# deasserted, waiting for link training\n");
    timer_delay_ms(100); // PCIe仕様: PERST#解除後100ms待つ(pcie1_start_link()と同じ)

    // ポーリング上限は1000ms。実機で300msでも不十分な事象を確認した
    // (2026-08-02、真のコールドブート後): pcie1_start_link()(`pcicfg1`
    // 等が使う経路)はPERST#の**デアサートのみ**を行う -- 呼ばれる時点で
    // 既にPERST#がHigh(電源投入直後の初期状態のまま、または前回の
    // トレーニング済みリンクがまだ生きている状態)であることが多く、
    // 実質的に「既にトレーニング済みのリンクをそのまま確認するだけ」に
    // なりやすい。対してこちら(pcie1_reset_link())はPERST#を実際に
    // アサート->デアサートする**完全なリセットサイクル**であり、
    // ConnectX自身のPHY/アナログ回路を含む本物のコールドリセットに近い
    // 状態から再トレーニングさせる -- こちらの方が本質的に長い時間を
    // 要する。実機で、300msの旧タイムアウトでは`pcie1 reset`(この関数)
    // が繰り返し確実にタイムアウトする一方、直後に`pcicfg1`
    // (pcie1_start_link()経由)を実行すると即座に成功し、ConnectX自体は
    // 物理的に接続され応答可能(Vendor ID=0x15b3)であることを確認した --
    // リンク不在ではなく、完全リセット後の再トレーニングに要する時間が
    // 単純に不足していたと判断し、余裕を持って1000msへ引き上げた。
    uint64_t start = timer_now();
    while (!timeout_ms(start, 1000u)) {
        if (pcie1_link_is_up()) {
            uint32_t status = mmio_read32(PCIE1_RC_BASE + R_MISC_PCIE_STATUS);
            log_str("pcie1: link re-established after reset, status=0x");
            log_hex(status);
            log_str("\n");

            // PCIeのDL_ACTIVE/PHYLINKUPはリンク層(PHY/Data Link Layer)の
            // トレーニング完了を示すだけで、ConnectX自身の内部ファーム
            // ウェア(BAR0メモリマップドレジスタへの応答を実際に処理する
            // 側)がブートを終えたことは保証しない。実機で、この直後に
            // 間を置かず`net init mlx5`(BAR0メモリマップドアクセスを
            // 即座に開始する経路)を呼ぶとData Abort(実際にはPCIe側の
            // 応答無し/不正な応答に起因すると見られる)で確実にクラッシュ
            // する一方、`pcicfg1`(config空間の全レジスタ読み取り、数十〜
            // 数百ms程度かかる)を間に挟むと成功することを確認した。
            //
            // 固定時間のtimer_delay_ms()による「勘」の待機ではなく、
            // ConnectX自身のconfig空間(bus1 devfn0、Vendor/Device ID)を
            // 実際に繰り返し読み、期待値が連続して安定して返ることを
            // 確認してから先へ進む -- `pcicfg1`が結果的に行っていたのと
            // 同種の反復読み取りを、ここで意図的に行う形。config空間
            // 読み取り自体はリセット直後から既に正しい値(Vendor ID)を
            // 返すことを確認済みなので、この読み取りループの真の役割は
            // 「ConnectX側の何らかの内部準備が整うまでの経過時間」を、
            // 固定の推測値ではなく実際のPCIe1レジスタアクセスの往復時間
            // (実測でRP1同様レイテンシが大きいことが分かっている)に
            // 連動させて確保することにある -- 正確に何を待っているのかは
            // 未解明のまま(ConnectX内部のFWブート状態を直接示すレジスタ
            // は未確認)だが、実機で確実に問題を再現しなくなることを確認
            // した安全策。
            {
                #define PCIE1_POST_RESET_STABLE_READS 32u
                #define PCIE1_POST_RESET_VENDOR_ID    0x15b3u
                unsigned stable = 0;
                uint64_t poll_start = timer_now();
                while (stable < PCIE1_POST_RESET_STABLE_READS) {
                    uint32_t id = pcie1_cfg_read32(1, 0, 0x00);
                    if ((id & 0xffffu) == PCIE1_POST_RESET_VENDOR_ID) {
                        stable++;
                    } else {
                        stable = 0; // 不安定な読み取りがあれば数え直す
                    }
                    if (timeout_ms(poll_start, 2000u)) { // 安全弁
                        log_str("pcie1: warning -- ConnectX config space did not stabilize within timeout\n");
                        break;
                    }
                }
            }
            return 0;
        }
    }
    log_str("pcie1: link did not come back up after PERST# reset\n");
    return -1;
}

// --- 公開API ---

uint32_t pcie1_cfg_read32(uint8_t bus, uint8_t devfn, uint16_t offset) {
    uint32_t reg_off = offset & 0xfffu;
    if (bus == 0) {
        return devfn == 0 ? mmio_read32(PCIE1_RC_BASE + reg_off) : 0xffffffffu;
    }
    uint32_t idx = ((uint32_t)bus << 20) | ((uint32_t)devfn << 12);
    mmio_write32(PCIE1_RC_BASE + R_EXT_CFG_INDEX, idx);
    return mmio_read32(PCIE1_RC_BASE + R_EXT_CFG_DATA + reg_off);
}

void pcie1_cfg_write32(uint8_t bus, uint8_t devfn, uint16_t offset, uint32_t val) {
    uint32_t reg_off = offset & 0xfffu;
    if (bus == 0) {
        if (devfn == 0) {
            mmio_write32(PCIE1_RC_BASE + reg_off, val);
        }
        return;
    }
    uint32_t idx = ((uint32_t)bus << 20) | ((uint32_t)devfn << 12);
    mmio_write32(PCIE1_RC_BASE + R_EXT_CFG_INDEX, idx);
    mmio_write32(PCIE1_RC_BASE + R_EXT_CFG_DATA + reg_off, val);
}

// 標準capabilityリンクリスト(offset 0x34から辿る)を実際に探索して、
// PCI Express Capability(ID=0x10)のベースオフセットを返す(見つからな
// ければ0)。pcidump.cのdump_std_caps()と同じ手法 -- Device Control
// レジスタ(cap_base+0x08)はこの構造体内の相対オフセットであり、絶対
// config空間オフセットではないため、決め打ちせずここで実際に探索する。
static uint16_t pcie1_find_pcie_cap(uint8_t bus, uint8_t devfn) {
    uint32_t status = pcie1_cfg_read32(bus, devfn, 0x04) >> 16;
    if (!(status & (1u << 4))) {
        return 0; // Capabilities Listビットがクリア
    }
    uint8_t ptr = (uint8_t)(pcie1_cfg_read32(bus, devfn, 0x34) & 0xfcu);
    int count = 0;
    while (ptr >= 0x40u) {
        uint32_t hdr = pcie1_cfg_read32(bus, devfn, ptr);
        uint8_t cap_id = (uint8_t)(hdr & 0xffu);
        uint8_t next   = (uint8_t)((hdr >> 8) & 0xfcu);
        if (cap_id == 0x10u) {
            return ptr;
        }
        count++;
        if (count > 48 || next == 0) {
            break;
        }
        ptr = next;
    }
    return 0;
}

// PCIe Capability構造体のDevice Control(cap_base+0x08)のMax Payload
// Size(bit[7:5])を設定する。Device Capabilities(cap_base+0x04)の
// Max Payload Size Supported(bit[2:0])でクランプしてから書く -- 要求
// 値がこのデバイスの対応上限を超えないようにする安全策(このプロジェクト
// のPMTUクランプ[mlx5.cのmlx5_set_port_mtu()]と同じ考え方)。desired_
// fieldのエンコーディングはPCIe仕様通り: 0=128B,1=256B,2=512B,
// 3=1024B,4=2048B,5=4096B。
//
// PCIe仕様上、MPSはルートポートから末端デバイスまでの経路全体で同じ
// 値に揃える必要がある(揃っていないとメモリ読み書きTLPが分割されず
// 送信元の値のまま出てしまい、受信側が処理できない)。実機の
// pcicfg1コマンドでルートポート(bus0,devfn0)・ConnectX(bus1,devfn0/1)
// いずれもMax Payload Size Supported=2(512B)であることを確認済み
// (CLAUDE.mdのMPS/MRRS分析参照)。
static void pcie1_set_mps(uint8_t bus, uint8_t devfn, uint8_t desired_field) {
    uint16_t cap = pcie1_find_pcie_cap(bus, devfn);
    if (cap == 0) {
        log_str("pcie1: PCIe capability not found (bus/devfn), cannot set MPS\n");
        return;
    }
    uint32_t devcap = pcie1_cfg_read32(bus, devfn, (uint16_t)(cap + 0x04));
    uint8_t supported = (uint8_t)(devcap & 0x7u);
    uint8_t field = (desired_field <= supported) ? desired_field : supported;

    // Device Control(bit[15:0])とDevice Status(bit[31:16])は同一DWORD
    // だが、pcie1_cfg_read32/write32は32bit粒度でしかアクセスできない
    // ため、read-modify-writeでDevice Control側のMPSフィールドだけを
    // 書き換える(root_cmd等、このファイルの既存パターンと同じ)。
    uint32_t devctl_dw = pcie1_cfg_read32(bus, devfn, (uint16_t)(cap + 0x08));
    devctl_dw = (devctl_dw & ~(0x7u << 5)) | ((uint32_t)field << 5);
    pcie1_cfg_write32(bus, devfn, (uint16_t)(cap + 0x08), devctl_dw);

    // 書き込みっぱなしにせず読み戻して確認する(このファイルのCommand
    // registerと同じ方針)。
    uint32_t readback = pcie1_cfg_read32(bus, devfn, (uint16_t)(cap + 0x08));
    uint8_t readback_field = (uint8_t)((readback >> 5) & 0x7u);
    log_str("pcie1: MPS set to field=0x");
    log_hex(readback_field);
    log_str(readback_field == field ? " ok\n" : " (!!readback mismatch)\n");
}

// PCIe Capability構造体のDevice Control(cap_base+0x08)のMax Read Request
// Size(bit[14:12])を設定する。MPSと異なりMRRSはDevice Capabilitiesに
// 対応上限を示すフィールドが存在しない -- PCIe仕様上、いかなるデバイスも
// 128B〜4096Bの全範囲のMRRS値を受理できる必要がある(MRRSは「この
// デバイス自身が発行するreadリクエスト1個の最大サイズ」というリクエスタ
// 側だけのローカルな制約であり、戻ってくるCompletionはどのみちMPSサイズ
// (このプロジェクトでは512B、ルートポート自身の対応上限)へ分割される
// ため、経路全体で値を揃える必要があるMPSとは違いクランプ/相互合意が
// 不要)。実機で`pcicfg1`から読んだDevice Controlの初期値はMRRS=512B
// だったが、これは本関数(以前は存在しなかった)ではなくConnectX自身の
// リセット後デフォルト値 -- MPSとは独立に、より大きな値へ引き上げる
// ことで、1回のreadリクエストで運べるデータ量を増やし、同じ帯域遅延積
// を満たすのに必要な同時アウトスタンディングreadリクエスト数を減らせる
// (CLAUDE.md「write>readの差の機構的説明」節参照)。desired_fieldの
// エンコーディングはMPSと同じ: 0=128B,1=256B,2=512B,3=1024B,4=2048B,
// 5=4096B。
static void pcie1_set_mrrs(uint8_t bus, uint8_t devfn, uint8_t desired_field) {
    uint16_t cap = pcie1_find_pcie_cap(bus, devfn);
    if (cap == 0) {
        log_str("pcie1: PCIe capability not found (bus/devfn), cannot set MRRS\n");
        return;
    }

    uint32_t devctl_dw = pcie1_cfg_read32(bus, devfn, (uint16_t)(cap + 0x08));
    devctl_dw = (devctl_dw & ~(0x7u << 12)) | ((uint32_t)desired_field << 12);
    pcie1_cfg_write32(bus, devfn, (uint16_t)(cap + 0x08), devctl_dw);

    uint32_t readback = pcie1_cfg_read32(bus, devfn, (uint16_t)(cap + 0x08));
    uint8_t readback_field = (uint8_t)((readback >> 12) & 0x7u);
    log_str("pcie1: MRRS set to field=0x");
    log_hex(readback_field);
    log_str(readback_field == desired_field ? " ok\n" : " (!!readback mismatch)\n");
}

int pcie1_rc_init(void) {
    uint32_t tmp;

    if (!pcie1_link_is_up()) {
        log_str("pcie1: resetting bridge\n");
        bridge_reset_assert();
        timer_delay_ms(1);
        bridge_reset_deassert();

        tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_HARD_DEBUG);
        tmp &= ~HARD_DEBUG_SERDES_IDDQ;
        mmio_write32(PCIE1_RC_BASE + R_MISC_HARD_DEBUG, tmp);
        timer_delay_ms(1);

        log_str("pcie1: rescal\n");
        rescal_deassert();

        log_str("pcie1: munging PLL for 54MHz xosc refclk\n");
        pcie1_munge_pll();

        tmp = mmio_read32(PCIE1_RC_BASE + R_RC_PL_PHY_CTL_15);
        tmp = (tmp & ~0xffu) | 0x12u; // L1SSエラッタ対策
        mmio_write32(PCIE1_RC_BASE + R_RC_PL_PHY_CTL_15, tmp);
    }

    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_MISC_CTRL);
    tmp |= MISC_CTRL_SCB_ACCESS_EN;
    tmp |= MISC_CTRL_CFG_READ_UR_MODE;
    tmp = (tmp & ~MISC_CTRL_MAX_BURST_MASK) | ((1u << MISC_CTRL_MAX_BURST_SHIFT) & MISC_CTRL_MAX_BURST_MASK);
    mmio_write32(PCIE1_RC_BASE + R_MISC_MISC_CTRL, tmp);

    pcie1_set_tc_qos();

    // インバウンドRC_BAR2ウィンドウ: pcie.cのpcie_rc_init()と同じ理由
    // (ConnectX自身がDMAで発行するPCIバスアドレス0x10_00000000-0x1f_ffffffff
    // をCPU物理アドレス0x0-0xf_ffffffffへ写す)。ConnectX自体のDMAアドレッシング
    // 方式(64bit化・上位32bit付加が必要か)はまだ確認していないため、この窓は
    // RP1と同じ設定を踏襲しておく(将来ConnectXドライバ実装時に見直す)。
    uint64_t rc_bar2_offset = 0x1000000000ull;
    tmp = (uint32_t)rc_bar2_offset;
    tmp = (tmp & ~RC_BAR_CFG_LO_SIZE_MASK) | (21u & RC_BAR_CFG_LO_SIZE_MASK);
    mmio_write32(PCIE1_RC_BASE + R_MISC_RC_BAR2_CFG_LO, tmp);
    mmio_write32(PCIE1_RC_BASE + R_MISC_RC_BAR2_CFG_HI, (uint32_t)(rc_bar2_offset >> 32));

    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_UBUS_BAR2_CFG_REMAP);
    tmp |= UBUS_BAR_CFG_REMAP_ACCESS_EN;
    mmio_write32(PCIE1_RC_BASE + R_MISC_UBUS_BAR2_CFG_REMAP, tmp);

    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_MISC_CTRL);
    tmp = (tmp & ~MISC_CTRL_SCB0_SIZE_MASK) | ((21u << MISC_CTRL_SCB0_SIZE_SHIFT) & MISC_CTRL_SCB0_SIZE_MASK);
    mmio_write32(PCIE1_RC_BASE + R_MISC_MISC_CTRL, tmp);

    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_UBUS_CTRL);
    tmp |= UBUS_CTRL_REPLY_ERR_DIS | UBUS_CTRL_REPLY_DECERR_DIS;
    mmio_write32(PCIE1_RC_BASE + R_MISC_UBUS_CTRL, tmp);
    mmio_write32(PCIE1_RC_BASE + R_MISC_AXI_READ_ERROR_DATA, 0xffffffffu);
    mmio_write32(PCIE1_RC_BASE + R_MISC_UBUS_TIMEOUT, 0xB2D0000u);
    mmio_write32(PCIE1_RC_BASE + R_MISC_RC_CONFIG_RETRY_TIMEOUT, 0xABA0000u);

    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_RC_BAR1_CFG_LO);
    tmp &= ~RC_BAR_CFG_LO_SIZE_MASK;
    mmio_write32(PCIE1_RC_BASE + R_MISC_RC_BAR1_CFG_LO, tmp);

    tmp = mmio_read32(PCIE1_RC_BASE + R_MISC_RC_BAR3_CFG_LO);
    tmp &= ~RC_BAR_CFG_LO_SIZE_MASK;
    mmio_write32(PCIE1_RC_BASE + R_MISC_RC_BAR3_CFG_LO, tmp);

    tmp = mmio_read32(PCIE1_RC_BASE + R_RC_CFG_PRIV1_LINK_CAPABILITY);
    tmp = (tmp & ~LINK_CAP_ASPM_MASK) | ((ASPM_L1_ONLY << LINK_CAP_ASPM_SHIFT) & LINK_CAP_ASPM_MASK);
    mmio_write32(PCIE1_RC_BASE + R_RC_CFG_PRIV1_LINK_CAPABILITY, tmp);

    // コンフィグ空間上でPCIe-PCIeブリッジとして見せる。
    tmp = mmio_read32(PCIE1_RC_BASE + R_RC_CFG_PRIV1_ID_VAL3);
    tmp = (tmp & ~0xffffffu) | 0x060400u;
    mmio_write32(PCIE1_RC_BASE + R_RC_CFG_PRIV1_ID_VAL3, tmp);

    pcie1_set_outbound_win(0, PCIE1_OUTBOUND_CPU_BASE, 0, PCIE1_OUTBOUND_SIZE);

    tmp = mmio_read32(PCIE1_RC_BASE + R_RC_CFG_VENDOR_SPECIFIC_REG1);
    tmp &= ~VENDOR_REG1_ENDIAN_MASK; // リトルエンディアン
    mmio_write32(PCIE1_RC_BASE + R_RC_CFG_VENDOR_SPECIFIC_REG1, tmp);

    if (!pcie1_link_is_up()) {
        log_str("pcie1: deasserting PERST#, waiting for link training\n");
        if (pcie1_start_link() != 0) {
            log_str("pcie1: link did not come up\n");
            return -1;
        }
        uint32_t status = mmio_read32(PCIE1_RC_BASE + R_MISC_PCIE_STATUS);
        log_str("pcie1: link up, status=0x");
        log_hex(status);
        log_str("\n");
    }

    // Type-1ブリッジヘッダ: bus 1(ConnectX)へのコンフィグアクセスを転送させる。
    pcie1_cfg_write32(0, 0, 0x18, 0x00010100u);

    // ルートポートのP2Pブリッジメモリウィンドウを全開放する。
    pcie1_cfg_write32(0, 0, 0x20, 0xfff00000u);

    // ルートポート自身のCommand register(bus 0)でMemory Space + Bus Masterを有効化する。
    uint32_t root_cmd = pcie1_cfg_read32(0, 0, 0x04);
    root_cmd |= 0x6u;
    pcie1_cfg_write32(0, 0, 0x04, root_cmd);

    // MPS(Max Payload Size)を512Bへ設定する(ユーザー指示、CLAUDE.mdの
    // MPS/MRRS分析参照)。ルートポートはリセットのたびに毎回呼ばれる
    // この関数で設定しておく -- ConnectX側(pcie1_assign_bar0_at())も
    // 同じ512Bに揃える。
    pcie1_set_mps(0, 0, 2u); // 2 = 512B

    return 0;
}

// ConnectXは一般的に単一の64bit BAR0(config offset 0x10-0x17)を持つ想定
// (Mellanox/NVIDIA ConnectXシリーズの一般的なBAR構成)。RP1のrp1_assign_bar0()
// (独立した2本の32bit BAR前提)とは構成が異なるため新規実装する -- 決め打ち
// せず、実際のconfig space読み出し結果(bit[2:1])で64bit/32bitを判定する。
//
// devfn/pci_addr_baseを引数化しているのは、このConnectXがマルチファンク
// ションデバイス(PCI Header Typeのbit7が実機で確認済み)であり、devfn=0/1
// それぞれが独立した物理ポートに対応する別々のPCI関数(≒別々のHCA
// インスタンス)であることが判明したため -- CLAUDE.md「ConnectXデュアル
// ポート対応」節参照。devfn=1(2つ目の物理ポート)にも同じ手順を、互いに
// 重ならない別のPCIアドレスへ適用できるようにした。
int pcie1_assign_bar0_at(uint8_t devfn, uint64_t pci_addr_base, uint64_t *size_out, int *is64_out) {
    // BAR0下位32bitをプローブ。
    pcie1_cfg_write32(1, devfn, 0x10, 0xffffffffu);
    uint32_t probe_lo = pcie1_cfg_read32(1, devfn, 0x10);
    if (probe_lo == 0xffffffffu) {
        log_str("pcie1: BAR0 probe read back all-1s -- device not responding, aborting\n");
        return -1;
    }

    int is_mem = (probe_lo & 0x1u) == 0;
    if (!is_mem) {
        log_str("pcie1: BAR0 is an I/O BAR, unexpected, aborting\n");
        return -1;
    }
    uint32_t bar_type = (probe_lo >> 1) & 0x3u; // 0=32bit, 2=64bit
    int is64 = (bar_type == 0x2u);

    uint64_t size;
    if (is64) {
        pcie1_cfg_write32(1, devfn, 0x14, 0xffffffffu);
        uint32_t probe_hi = pcie1_cfg_read32(1, devfn, 0x14);

        uint64_t mask = ((uint64_t)probe_hi << 32) | (probe_lo & 0xfffffff0u);
        size = (~mask) + 1u;

        if (pci_addr_base + size > PCIE1_OUTBOUND_SIZE) {
            log_str("pcie1: BAR0 (+ base offset) exceeds PCIE1_OUTBOUND_SIZE, aborting (need larger outbound window)\n");
            return -1;
        }

        // 指定のPCIアドレスへ割り当て。
        pcie1_cfg_write32(1, devfn, 0x14, (uint32_t)(pci_addr_base >> 32));
        pcie1_cfg_write32(1, devfn, 0x10, (uint32_t)(pci_addr_base & 0xfffffff0u));
    } else {
        uint32_t mask32 = probe_lo & 0xfffffff0u;
        size = (uint64_t)((~mask32) + 1u);

        if (pci_addr_base + size > PCIE1_OUTBOUND_SIZE) {
            log_str("pcie1: BAR0 (+ base offset) exceeds PCIE1_OUTBOUND_SIZE, aborting (need larger outbound window)\n");
            return -1;
        }

        pcie1_cfg_write32(1, devfn, 0x10, (uint32_t)(pci_addr_base & 0xfffffff0u));
    }

    uint32_t cmd = pcie1_cfg_read32(1, devfn, 0x04);
    cmd |= 0x6u; // Memory Space Enable | Bus Master Enable
    pcie1_cfg_write32(1, devfn, 0x04, cmd);

    // MPS(Max Payload Size)を512Bへ設定する(ユーザー指示、CLAUDE.mdの
    // MPS/MRRS分析参照)。pcie1_rc_init()側でルートポートも同じ512Bに
    // 揃えている -- PCIe仕様上、経路全体で一致している必要がある。
    pcie1_set_mps(1, devfn, 2u); // 2 = 512B

    // MRRS(Max Read Request Size)を4096Bへ引き上げる(MPSとは独立、
    // ConnectX単独の設定でよくルートポート側は変更不要 -- 上記
    // pcie1_set_mrrs()のコメント参照)。ConnectXはこのPFのローカル
    // メモリ(RPi5 DRAM、RDMA READコマンド処理時のソースデータ読み出し)
    // をPCIe1経由でnon-posted readするため、この値を上げることで
    // 1リクエストあたりの転送量を増やし、同じ帯域を得るのに必要な
    // 同時アウトスタンディングリクエスト数を減らせる。
    pcie1_set_mrrs(1, devfn, 5u); // 5 = 4096B

    // 書き込みっぱなしにせず、実際にMemory Space Enable(bit1)/Bus Master
    // Enable(bit2)が読み戻せることを確認する -- 以前はここを確認しておらず、
    // 書き込み直後にBAR0メモリマップドアクセス(mlx5_hca_bringup()の最初の
    // レジスタ読み取り)へ進んだ結果、実機でData Abort(Translation fault)
    // を引き起こすことがあった(CLAUDE.md「`pcie1 reset`直後の`net init
    // mlx5`実行でData Abortする問題」節参照)。config空間の読み戻し自体は
    // 即座に正しい値を返すことを確認済みなので、この確認だけで実害の
    // あるタイミング問題を捕捉できるかは未確定だが、「書き込みが本当に
    // 反映されたか」を無条件に信じない、という最低限の安全策として追加する。
    uint32_t cmd_readback = pcie1_cfg_read32(1, devfn, 0x04);
    if ((cmd_readback & 0x6u) != 0x6u) {
        log_str("pcie1: warning -- Command register readback did not show Memory/Bus Master enable (0x");
        log_hex(cmd_readback);
        log_str(")\n");
    }

    if (size_out) *size_out = size;
    if (is64_out) *is64_out = is64;

    log_str("pcie1: BAR0(devfn=");
    log_hex(devfn);
    log_str(") assigned at PCI addr 0x");
    log_hex((uint32_t)pci_addr_base);
    log_str(", size=0x");
    log_hex((uint32_t)size);
    log_str(is64 ? " (64bit)\n" : " (32bit)\n");

    return 0;
}

int pcie1_assign_bar0(uint64_t *size_out, int *is64_out) {
    return pcie1_assign_bar0_at(0, 0, size_out, is64_out);
}
