// eth.c — RP1内蔵Ethernet(Cadence MACB/GEM)ドライバ
//
// RP1のEthernetブロックはdtb上 compatible = "raspberrypi,rp1-gem",
// "cdns,macb" (phy-mode = "rgmii-id") -- Synopsys DesignWare GMAC(dwmac4)
// ではない。詳細はeth.h冒頭のコメント参照。
//
// レジスタオフセット・ビットフィールド・記述子フォーマットは
// drivers/net/ethernet/cadence/macb.h, macb_main.c (raspberrypi/linux,
// rpi-6.6.y) を参照して決定している。AXIパイプライン設定(AMP)の値は
// arch/arm64/boot/dts/broadcom/rp1.dtsi の rp1_eth ノード
// (cdns,aw2w-max-pipe=8, cdns,ar2r-max-pipe=8, cdns,use-aw2b-fill)
// をそのまま採用した。MDCクロック分周はpclk(RP1_CLK_SYS)=200MHz
// (同dtsi)から gem_mdc_clk_div() 相当の計算でGEM_CLK_DIV96を選んでいる。
//
// ベースアドレス: PCIE_OUTBOUND_CPU_BASE + RP1_ETH_IP_BASE。
// RP1_ETH_IP_BASE(=0x100000)は include/dt-bindings/mfd/rp1.h の値
// (BAR1内オフセット)。fan.c のRP1_REG()パターンに倣う。
//
// DMAアドレスについて: RP1が(GEMのDMAエンジンとして)自ら発行するバス
// アドレスは、rp1.dtsi の rp1 ノードの dma-ranges で
//   inbound RP1 0x_xxxxxxxx -> PCIe 1x_xxxxxxxx (size 0x10_00000000)
// と定義されている -- つまりRP1のローカル側から見た「そのままの」
// CPU物理アドレス(0x0始まり)を指定するだけで、RP1自身のバスファブリック
// がPCIeバスアドレス側で+0x10_00000000を透過的に付加し、CPU側の
// Root Complexがそれをさらに実アドレスへ戻す(この2段目は素通し)。
// したがって記述子のaddrフィールド・RBQP/TBQPには、
// PCIE_OUTBOUND_CPU_BASEのようなオフセットを一切加算しない、
// net_buf_t の生のCPU物理アドレスをそのまま書けばよい。
// これは実機未検証の推論であり(この現象のためのDMA実績はこのプロジェクトに
// まだ無い)、rp1.dtsiのdma-rangesコメント("PCIe address space layout:
// 00_00000000-00_00xxxxxx = RP1 peripherals, 10_00000000-1x_xxxxxxxx =
// up to 64GB system RAM")から導いたもの。もし実機でTX/RXが完了しない
// (busy-waitタイムアウトする)場合、まずここを疑うこと。
//
// MMU無効(SCTLR.M=0)のため全メモリがDeviceメモリ相当(net.h参照)であり、
// キャッシュコヒーレンシの問題は原理上発生しない(Linuxドライバの
// dma_wmb()/dma_map_single()等のキャッシュ管理は不要)。ただし
// コンパイラの並べ替え・ストア結合は別問題のため、記述子リング(RP1の
// DMAエンジンとCPUの両方が読み書きする共有メモリ)は volatile 経由で
// アクセスする。

#include "eth.h"
#include "net_buf.h"
#include "net.h"
#include "netctx.h"
#include "board.h"
#include "mmio.h"
#include "pcie.h"
#include "timer.h"
#include "uart.h"
#include "cache.h"
#include "timestamp.h"
#include "smp.h"
#include <stdint.h>
#include <stddef.h>

#define RP1_REG(off)     (PCIE_OUTBOUND_CPU_BASE + (off))
#define RP1_ETH_IP_BASE  0x100000u  /* include/dt-bindings/mfd/rp1.h */
#define ETH_BASE         RP1_REG(RP1_ETH_IP_BASE)

/* --- PHYハードウェアリセット (RP1 GPIO32、active-low) ---
 * dtb (arch/arm64/boot/dts/broadcom/bcm2712-rpi-5-b.dts の &rp1_eth) より:
 *   phy-reset-gpios = <&rp1_gpio 32 GPIO_ACTIVE_LOW>;
 *   phy-reset-duration = <5>; // ms
 * GPIO32はRP1のbank1(GPIO28-33を担当)に属する。bank内オフセット
 * j = 32 - 28 = 4。bank1のgpio_offset/pads_offsetは
 * drivers/pinctrl/pinctrl-rp1.c の rp1_iobanks[] テーブル
 * ({28, 6, 0x4000, ..., pads_offset=0x4004}) より。
 *
 * GPIO_CTRLレジスタのOUTOVER/OEOVERフィールドは、FUNCSEL(現在選択中の
 * ペリフェラル信号)を経由せずピンレベルを直接強制するハードオーバーライド
 * (OEOVER=ENABLE(3)/OUTOVER=LOW(2)|HIGH(3))を持つ -- 同driverの
 * RP1_OUTOVER_系/RP1_OEOVER_系 定数より。これを使えばRIOブロック
 * (bank毎のOUT/OEレジスタ、通常のgpiolib経由の出力に使う)に触れずに
 * 済むため、こちらを採用する。fan.cのGPIO45(bank2, PWM ALT0機能)とは
 * 異なりFUNCSEL自体は素のGPIO(RP1_FSEL_GPIO=5)にしておく。 */
#define RP1_GPIO_BASE  RP1_REG(0xd0000)
#define RP1_PADS_BASE  RP1_REG(0xf0000)

#define PHY_RST_BANK1_GPIO_OFFSET 0x4000u
#define PHY_RST_BANK1_PADS_OFFSET 0x4004u
#define PHY_RST_J                 4u /* GPIO32 - bank1のmin_gpio(28) */

#define PHY_RST_CTRL_REG (RP1_GPIO_BASE + PHY_RST_BANK1_GPIO_OFFSET + PHY_RST_J * 8 + 0x4)
#define PHY_RST_PAD_REG  (RP1_PADS_BASE + PHY_RST_BANK1_PADS_OFFSET + PHY_RST_J * 4)

#define GPIO_CTRL_FUNCSEL_MASK  0x0000001fu
#define GPIO_CTRL_OUTOVER_MASK  0x00003000u
#define GPIO_CTRL_OEOVER_MASK   0x0000c000u
#define GPIO_CTRL_FUNCSEL_GPIO  0x00000005u  /* RP1_FSEL_GPIO */
#define GPIO_CTRL_OUTOVER_LOW   (2u << 12)
#define GPIO_CTRL_OUTOVER_HIGH  (3u << 12)
#define GPIO_CTRL_OEOVER_ENABLE (3u << 14)

#define PAD_OUT_DISABLE_BIT 0x00000080u

#define PHY_RESET_HOLD_MS   5u  /* dtbのphy-reset-duration */
#define PHY_RESET_SETTLE_MS 10u /* リセット解除後のマージン(dtb未指定、経験的な値) */

/* オートネゴシエーション完了を待つ最大時間。実測でリンクLED点灯後も
 * BMSRのLink Statusが立つまで数百ms〜数秒かかることがあるため、
 * 10ms程度の一回読みでは早すぎる(実機で確認済み)。1000BASE-Tは
 * マスタ/スレーブ調停を含むぶん10/100より時間がかかることがあるため、
 * GTCR/ANAR/BMCRでの明示的な再ネゴシエーション導入時に3000→5000へ
 * 余裕を増やした。 */
#define ETH_LINK_WAIT_MS 5000u

/* --- レジスタオフセット (macb.h の GEM_ / MACB_ 系マクロを参照) --- */
#define R_NCR      0x0000u /* Network Control */
#define R_NCFGR    0x0004u /* Network Config */
#define R_NSR      0x0008u /* Network Status */
#define R_TSR      0x0014u /* Transmit Status */
/* TSRのビット定義(drivers/net/ethernet/cadence/macb.hより取得済み、
 * CLAUDE.mdの「参照ドライバソース」節参照)。write-1-clear。 */
#define TSR_UBR    (1u << 0) /* Used Bit Read -- HWが既にUSED=1の記述子を
                               * 使おうとした(想定外の状態) */
#define TSR_COL    (1u << 1) /* Collision occurred(半二重時のみ通常発生) */
#define TSR_RLE    (1u << 2) /* Retry Limit Exceeded */
#define TSR_TGO    (1u << 3) /* Transmit Go(送信中を示す状態ビット、エラーではない) */
#define TSR_BEX    (1u << 4) /* TX frame corruption due to AHB error --
                               * DMA読み出し自体が失敗したことを示す
                               * (アドレス関連の問題を直接示しうる重要なビット) */
#define TSR_COMP   (1u << 5) /* Transmit complete(成功、エラーではない) */
#define TSR_UND    (1u << 6) /* Transmit underrun */
#define R_RBQP     0x0018u /* RX Q base pointer (queue0 legacy offset) */
#define R_TBQP     0x001cu /* TX Q base pointer (queue0 legacy offset) */
#define R_TBQPH    0x04c8u /* TX Q base pointer 上位32bit (queue0共通) */
#define R_RBQPH    0x04d4u /* RX Q base pointer 上位32bit (queue0共通) */
#define R_RSR      0x0020u /* Receive Status */
#define RSR_BNA    (1u << 0) /* Buffer Not Available -- RXリング全記述子がUSEDで空きが無く、
                               * 到着フレームがハードウェアレベルで破棄された */
#define RSR_REC    (1u << 1) /* Frame Received */
#define RSR_OVR    (1u << 2) /* Receive Overrun */
#define R_ISR      0x0024u /* Interrupt Status (queue0) */
#define R_IDR      0x002cu /* Interrupt Disable (queue0) */
#define R_MAN      0x0034u /* PHY Maintenance (MDIO) */
#define R_USRIO    0x000cu /* User IO (GEM: RGMII/refclk select) */
#define R_DMACFG   0x0010u /* DMA Configuration */
#define R_JML      0x0048u /* Jumbo Max Length (GEM専用、macb.hのGEM_JMLオフセット) --
                              * ジャンボフレーム受信の最大許容長。macb_main.cの
                              * macb_init_hw()と同じ順序(NCFGR書き込みの直後)で、
                              * MACB_CAPS_JUMBO時のみETH_JUMBO_MAX_LEN(eth.h)を書く。 */
#define R_AMP      0x0054u /* AXI Max Pipeline */
#define R_SA1B     0x0088u /* Specific Addr 1 Bottom */
#define R_SA1T     0x008cu /* Specific Addr 1 Top */
#define R_DCFG1    0x0280u /* Design Config 1 (data bus width etc) */

/* --- NCR (Network Control) ビット --- */
#define NCR_RE       (1u << 2)  /* Receive enable */
#define NCR_TE       (1u << 3)  /* Transmit enable */
#define NCR_MPE      (1u << 4)  /* Management port enable (MDIO) */
#define NCR_CLRSTAT  (1u << 5)  /* Clear stats regs */
#define NCR_TSTART   (1u << 9)  /* Start transmission */
#define NCR_THALT    (1u << 10) /* Transmit halt (macb.hのMACB_THALT_OFFSET) --
                               * TEをいきなり落とすのではなく、進行中の送信を
                               * 綺麗に止めるための正規の停止要求ビット。
                               * macb_main.cのmacb_halt_tx()参照(下記
                               * eth_tx_halt()コメント)。 */

/* --- NCFGR (Network Config) ビット・フィールド --- */
#define NCFGR_SPD     (1u << 0)  /* Speed (1=100M、10Mでは立てない。GBE=1なら無視される) */
#define NCFGR_FD      (1u << 1)  /* Full duplex */
#define NCFGR_BIG     (1u << 8)  /* Receive 1536 byte frames -- ジャンボフレーム対応
                               * (2026-07-25)後は使わない。macb_main.cのmacb_init_hw()が
                               * 「MACB_CAPS_JUMBOならJFRAME、無ければBIG」と排他的に
                               * 設定しているのに合わせ、常時JFRAME側を使う(下記)。 */
#define NCFGR_JFRAME  (1u << 3)  /* Jumbo frame enable (macb.hのMACB_JFRAME_OFFSET=3) --
                               * 立てるとRXの最大許容長がGEM_JMLレジスタ(R_JML)の値まで
                               * 拡張される。標準サイズのフレームも引き続き問題なく
                               * 受信できる(上限が広がるだけ)ため、常時有効にして良い。 */
#define NCFGR_GBE     (1u << 10) /* Gigabit mode enable (GEM専用) */
#define NCFGR_DRFCS   (1u << 17) /* Discard Rx FCS (HWがFCSを自動除去) */
#define NCFGR_CLK_SHIFT 18       /* MDCクロック分周 (GEM専用フィールド、3bit) */
#define NCFGR_DBW_SHIFT 21       /* データバス幅 (2bit) */
/* CAF(promisc)・NBC(no broadcast)は共に立てない(デフォルト0)ままにする --
 * SA1(自機MAC)一致 + ブロードキャストは通常通り受信させる(ARP等に必要)。
 *
 * RBOF(RXバッファオフセット, bit14-15)は意図的に0のまま(NET_IP_ALIGN不使用)。
 * eth_dispatch()/arp.c等の既存コードはEthernetヘッダがnb->data[0]から
 * 始まる前提で書かれている -- Linuxの一般的なRBOF=2(IPヘッダを4バイト
 * 境界に揃える)にすると先頭2バイトがパディングになり、その前提が崩れる。
 * このプロジェクトのnet.hが元々バイト単位アクセスを徹底しているのは
 * まさにこの手の非アライン配置に対応するためなので、RBOF=0のままで問題ない。 */

/* GEM_CLK_DIV* (macb.h) -- pclk=RP1_CLK_SYS=200MHz (rp1.dtsi) なので
 * gem_mdc_clk_div()の判定基準(<=240MHz)によりDIV96を選ぶ。 */
#define GEM_CLK_DIV96 5u

/* --- DMACFG ビット・フィールド --- */
#define DMACFG_FBLDO_SHIFT 0    /* 固定バースト長 (5bit) */
#define DMACFG_RXBMS_SHIFT 8    /* RXバッファメモリサイズ (2bit) */
#define DMACFG_TXPBMS      (1u << 10) /* TXバッファをフルメモリサイズに */
#define DMACFG_RXBS_SHIFT  16   /* DMA受信バッファサイズ、64バイト単位 (8bit) */
#define DMACFG_ADDR64      (1u << 30) /* GEM_ADDR64: 64bitアドレッシング(拡張記述子)を有効化 */

/* DMAアドレスの上位32bit。rp1.dtsiのdma-ranges("inbound RP1 0x_xxxxxxxx ->
 * PCIe 1x_xxxxxxxx")は、RP1ローカルアドレス(0x0始まり)がRP1の
 * バスファブリックによって自動的にPCIバスアドレス(0x10_00000000始まり)
 * へ変換されると読める内容だったが、実機で確認した結果これは自動では
 * 行われておらず、GEM(Ethernet MAC)自身のDMAエンジンは32bit
 * アドレッシングモードのままだと素のRP1ローカルアドレス(0x0始まり)を
 * そのまま発行し、RC_BAR2窓(PCIアドレス0x10_00000000起点、pcie.c参照)に
 * 届かないままだった -- これがTX/RXの記述子アクセスが対称的に失敗して
 * いた実際の原因(RC_BAR2の設定自体は正しくても直らなかった)。
 * GEMをADDR64(64bitアドレッシング/4ワード拡張記述子)に切り替え、
 * ソフトウェア側でこの上位ワードを明示的に全DMAアドレス(記述子リング
 * 自体のTBQP/RBQPと、各記述子が指すバッファの両方)に付加することで
 * 解決した。 */
#define DMA_ADDR_HI32 0x10u

/* raspberrypi_rp1_config (macb_main.c) の dma_burst_length = 16 */
#define ETH_DMA_BURST_LENGTH 16u

/* --- AMP (AXI Max Pipeline) --- rp1.dtsiのrp1_ethノードのプロパティ値を
 * そのまま採用(cdns,aw2w-max-pipe=8, cdns,ar2r-max-pipe=8,
 * cdns,use-aw2b-fill) */
#define AMP_AR2R_MAX_PIPE_SHIFT 0
#define AMP_AW2W_MAX_PIPE_SHIFT 8
#define AMP_AW2B_FILL           (1u << 16)

/* --- DCFG1 --- */
#define DCFG1_DBWDEF_SHIFT 25
#define DCFG1_DBWDEF_MASK  0x7u

/* --- USRIO --- */
#define USRIO_RGMII (1u << 0) /* GEM_RGMII: RGMIIインターフェースを選択 */

/* --- NSR (Network Status) --- */
#define NSR_IDLE (1u << 2) /* PHY管理ロジックがアイドル */

/* --- MAN (PHY Maintenance/MDIO, clause22) --- */
#define MAN_C22_SOF        (1u << 30)
#define MAN_C22_WRITE      (1u << 28)  /* OPフィールド(2bit) = 01 = write */
#define MAN_C22_READ       (2u << 28)  /* OPフィールド(2bit) = 10 = read */
#define MAN_C22_CODE       (2u << 16)
#define MAN_PHYA_SHIFT     23
#define MAN_REGA_SHIFT     18
#define MAN_DATA_MASK      0xFFFFu

/* dtb (rp1.dtsi -> rpi5b.dtsの &rp1_eth オーバレイ) の
 * ethernet-phy@1 (reg = <0x1>) より。 */
#define ETH_PHY_ADDR 1u
#define MII_BMSR     1u          /* 標準MII BMSRレジスタ番号 */
#define MII_BMSR_LINK_STATUS (1u << 2)

/* ネゴシエート結果の解決・オートネゴシエーション制御に使う標準MII
 * レジスタ(IEEE 802.3 clause22)。
 *
 * 【解決済みの実機バグ】以前は「ローカル側の対応可否(GTCR、reg9)は
 * 読んでいない -- 起動直後のPHYはリセットデフォルトで全能力(1000BASE-T
 * 含む)をアドバタイズしているという前提」でGTCR/ANAR/BMCRへの書き込みを
 * 一切行わずPHYのリセットデフォルト任せにしていたが、この前提は誤りだった
 * -- 実機で常に`BMSR=0x796d, 100M-FD`(BMSR bit8のExtended Statusは1、
 * つまりPHY自体は1000BASE-T対応)としかリンクせず、Gigabit対応の
 * Raspberry Pi 5のはずが100Mbpsに制限されていた。GTCRへ明示的に
 * 1000BASE-T広告ビットを書き、ANARも明示的に10/100広告を書いた上で
 * BMCRでオートネゴシエーションを再起動する(eth_init()参照)ことで解決。 */
#define MII_BMCR     0u  /* Basic Mode Control */
#define MII_ANAR     4u  /* Auto-Negotiation Advertisement */
#define MII_ANLPAR   5u  /* Auto-Negotiation Link Partner Ability */
#define MII_GTCR     9u  /* 1000BASE-T Control (自分の広告能力を書く) */
#define MII_GTSR     10u /* 1000BASE-T Status (相手の広告能力を読む) */

#define BMCR_DUPLEX_MODE    (1u << 8)
#define BMCR_RESTART_AN     (1u << 9)
#define BMCR_AN_ENABLE      (1u << 12)
#define BMCR_SPEED_MSB      (1u << 6)

/* ANARの下位5bit(セレクタフィールド)はIEEE 802.3で"00001"固定。 */
#define ANAR_SELECTOR_802_3 (1u << 0)
#define ANAR_10       (1u << 5)
#define ANAR_10FD     (1u << 6)
#define ANAR_100      (1u << 7)
#define ANAR_100FD    (1u << 8)
/* 自分が広告する全二重/半二重10/100(ANAR書き込み値、セレクタ込み)。 */
#define ANAR_ADV_ALL_10_100 (ANAR_SELECTOR_802_3 | ANAR_10 | ANAR_10FD | ANAR_100 | ANAR_100FD)

#define ANLPAR_10     (1u << 5)
#define ANLPAR_10FD   (1u << 6)
#define ANLPAR_100    (1u << 7)
#define ANLPAR_100FD  (1u << 8)

/* GTCR書き込み時に自分が広告する1000BASE-T全二重/半二重。 */
#define GTCR_ADV_1000HD (1u << 8)
#define GTCR_ADV_1000FD (1u << 9)
#define GTCR_ADV_ALL_1000 (GTCR_ADV_1000HD | GTCR_ADV_1000FD)

#define GTSR_LP_1000FD (1u << 11)
#define GTSR_LP_1000HD (1u << 10)

/* --- DMA記述子 (macb_dma_desc + macb_dma_desc_64、64bitアドレッシング) ---
 * macb_main.cのコメント(dma address width 64 bits)通り、記述子は4ワード
 * (16バイト)構成: word0=addr下位32bit、word1=ctrl、word2=addr上位32bit、
 * word3=未使用。macb_64b_desc()がaddr上位ワードを"desc直後の8バイト"
 * (=このstructのaddr_hi/resvdフィールド)として読み書きするのと同じ
 * レイアウト。
 * RX: addr(下位)のbit0=USED, bit1=WRAP, bit31:2=バッファアドレス下位。
 *     ctrlはHWが書く受信ステータス(FRMLEN/SOF/EOF等)。
 * TX: addr(下位)は生のバッファアドレス下位(フラグ無し)。
 *     ctrlはSWが書く送信要求(FRMLEN/LAST/WRAP)、HWが完了時にUSEDを立てる。
 */
typedef struct {
    uint32_t addr;
    uint32_t ctrl;
    uint32_t addr_hi;
    uint32_t resvd;
} gem_desc_t;

#define RX_USED       (1u << 0)
#define RX_WRAP       (1u << 1)
#define RX_CTRL_SOF   (1u << 14)
#define RX_CTRL_EOF   (1u << 15)
/* RXディスクリプタctrlワードのフレーム長フィールド。macb_main.cの
 * macb_init_hw()は bp->rx_frm_len_mask を MACB_CAPS_JUMBO の有無で
 * MACB_RX_FRMLEN_MASK(12bit, 0xFFF, BIGモード用)/MACB_RX_JFRMLEN_MASK
 * (14bit, 0x3FFF, JFRAMEモード用)に出し分けている。NCFGR_JFRAMEを常時
 * 有効にした(上記コメント参照)のに合わせ、常にジャンボ用の14bit
 * マスクを使う -- 12bitのままだとETH_JUMBO_MAX_LEN級のフレーム長が
 * 4096の剰余に切り詰められ、eth_poll_recv()が誤った長さでコピーする。 */
#define RX_FRMLEN_MASK 0x3FFFu

#define TX_LAST       (1u << 15)
#define TX_WRAP       (1u << 30)
#define TX_USED       (1u << 31)
#define TX_FRMLEN_MASK 0x3FFFu /* GEM_TX_FRMLEN_SIZE=14bit */

/* ETH_RX_RING_SIZE: eth.hで定義・公開(2026-07-25、tcp.cが広告受信ウィンドウ
 * をRXリング容量で頭打ちにする際にも使うようになったため — 詳細な経緯
 * コメント・非ジャンボ接続でのRSR.BNA/OVR再発とtcp.c側の対策の経緯は
 * eth.hのETH_RX_RING_SIZEコメント参照)。 */

/* RXリングの実際の確保サイズ。ETH_RX_RING_SIZEより余分にエントリ分を
 * 多く確保し、末尾の余剰エントリはインデックス計算(WRAPビット判定等、
 * 全てentry == ETH_RX_RING_SIZE-1基準)に一切登場させない -- 純粋な
 * ガード領域。実機のtcpbenchで2回、s_rx_ring直後に配置されていた
 * s_rx_tail/g_eth_rsr_bna_count/g_eth_rsr_ovr_countが、あたかも
 * s_rx_ring[ETH_RX_RING_SIZE以降](本来存在しないインデックス)へ
 * 書き込まれたかのような値に上書きされる事象を確認した(1回目は
 * RSR.BNA累計が21億超、2回目は「SOF/EOFが揃わないフレーム」の連続警告
 * (eth_poll_recv())に続いてRSR.BNA累計が1億超、さらにARPキャッシュ
 * (s_arp_cache、このリングよりさらに後方)まで巻き込まれ既知IPの解決が
 * 突然失敗する事態も確認 -- 2回目は当初の4エントリ分のガード(64バイト)
 * では吸収しきれない規模の書き込みだったことを示唆する)。ソフトウェア側の
 * WRAPビット設定(gem_init_rx_ring()、eth_poll_recv()の再武装、いずれも
 * entry==ETH_RX_RING_SIZE-1で正しく設定済み)に明白な誤りは見当たらず、
 * RP1のGEM DMAエンジン側の稀なタイミング起因(大きな受信バーストで顕在化)
 * と疑われるが、実機での再現条件はまだ特定できていない。
 * 【これは緩和策であり根本修正ではない】── 原因究明とは別に、s_rx_ring
 * (単一配列、コンパイラ/リンカによる並べ替えの影響を受けない)の直後を
 * 未使用領域にしておくことで、何かがここへ誤って書き込んでも実害のある
 * グローバル変数を破壊しないようにする。別配列としてガードを置く実装を
 * 最初に試したが、コンパイラが未使用の別配列をs_rx_ring隣接ではない
 * 位置へ再配置してしまい無意味だった -- 同一配列内でなければ隣接性は
 * 保証されない。2回目の事象を受け、ガードを4→16エントリ(256バイト)に
 * 拡大した。 */
#define ETH_RX_RING_ALLOC_SIZE (ETH_RX_RING_SIZE + 16)
/* ETH_TX_RING_SIZE(eth.hで定義・公開、tcp.cがスロットごとの送信バッファを
 * ETH_TX_RING_SIZE個確保するため)は元は2だったが、eth_send_frags()
 * (スキャッタ・ギャザー送信)は1フレームあたり最大ETH_TX_MAX_FRAGS(=2)個の
 * 連続したディスクリプタを消費し、リング終端をまたぐ場合は単純化のため
 * 先頭へ巻き戻る実装のため、その無駄なスロットスキップの余裕分と、RX
 * リングとの対称性も兼ねて8にした。2026-07-25、256(TX_WRAP再ラッチ頻度
 * 低減)へ拡大した -- 一時「entry=ETH_TX_RING_SIZE-1でのタイムアウト」を
 * リングサイズのせいと誤診断して8まで戻したが、8でも同じ症状(entry=7)
 * がnvmetのIOキュー接続直後に再現することを実機で確認し、リングサイズは
 * 無関係(admin/IO2コネクションが同じ物理TXリングを共有し始めるタイミング
 * 固有の別問題)と判明したため256へ戻した(eth.hのETH_TX_RING_SIZE
 * コメント参照)。現在はeth_send_frags_async()+eth_tx_wait_free_slot()
 * によるパイプライン化(未完了のフレームを最大ETH_TX_RING_SIZE個まで
 * キューイングできる)の実際の並行度そのものでもある。 */

/* TXリングの実際の確保サイズ(2026-07-25追加、根本原因の可能性が高い修正)。
 * raspberrypi/linux(rpi-6.6.y)のmacb_main.c/macb.hを再取得して調査した
 * ところ、GEMにはディスクリプタの読み先読み(プリフェッチ)機能があり
 * (`MACB_CAPS_BD_RD_PREFETCH`)、対応機種ではドライバがリングを論理サイズ
 * より`bp->tx_bd_rd_prefetch`バイト分余分に確保する
 * (`macb_alloc_consistent()`)。この値は`GEM_DCFG10`(オフセット0x02A4、
 * 読み取り専用のシリコン設計値)の`TXBD_RDBUFF`(bit[15:12])から
 * `(2 << (val-1)) * macb_dma_desc_get_size(bp)`で計算される。
 *
 * `raspberrypi_rp1_config`(macb_main.c)の`.caps`には
 * `MACB_CAPS_BD_RD_PREFETCH`が含まれておらず、Linuxドライバは`DCFG10`を
 * 一度も読まない -- が、これはソフトウェア側の判断に過ぎず、`DCFG10`
 * 自体はハードウェアの固定設計値なので、フラグの有無は実機シリコンが
 * 本当にプリフェッチ機構を持つかどうかを何も証明しない。実機で
 * `rp1 0x1002a4 1`(`RP1_ETH_IP_BASE`+`GEM_DCFG10`)を読んだところ
 * `0x24444444`が返り、TXBD_RDBUFF=RXBD_RDBUFF=4を確認した --
 * `(2 << (4-1)) = 16`記述子分(16バイト/記述子として256バイト)の
 * プリフェッチ深度を実機シリコンが実際に持っている。
 *
 * これがTX_WRAPディスクリプタ(entry=ETH_TX_RING_SIZE-1)だけがGEMに
 * 無視される(TX_USEDが立たない)現象の根本原因である可能性が高いと
 * 判断した: GEMの先読みエンジンは、WRAPビットを解釈してリング先頭へ
 * 戻る前に、物理的にリング直後のメモリを投機的に読みに行きうる。
 * `s_tx_ring[ETH_TX_RING_SIZE]`ちょうどの確保だとリング直後には
 * (コンパイラ/リンカが配置した)無関係な何かが存在し、この投機的先読みが
 * 何らかの形でGEM内部状態を混乱させ、WRAP記述子自体の処理(USEDビット
 * 反映)を妨げている可能性がある。確率的な発生(タイミング依存の投機的
 * 先読みが実際にその境界まで到達するかどうかに依存)、他のあらゆる
 * ソフトウェア側の要因(アドレス書き込み順序、リングサイズ、2コネクション
 * 干渉、RX処理との近接)との相関の欠如とも矛盾しない説明になっている。
 *
 * 【傍証】RXリング(`ETH_RX_RING_ALLOC_SIZE`、下記)には元々別の理由
 * (実機で確認した謎のメモリ破壊への緩和策、以下のコメント参照)で
 * ちょうど16エントリのガード領域が付いていた -- 今回測定した
 * RXBD_RDBUFF=4(=16記述子)と偶然にも一致する。RX側でこのTX_WRAP相当の
 * 症状(entry=ETH_RX_RING_SIZE-1が無視される)が一度も報告されていない
 * ことは、この既存のガード領域が結果的にRXプリフェッチ用の着地パッドを
 * 兼ねていた可能性を示唆する。
 *
 * 【現状】この修正(TX側にも16エントリのガード/パディングを追加)は
 * まだ実機で検証していない -- 次回のnvmet/fio再現テストで
 * `entry=ETH_TX_RING_SIZE-1`のタイムアウトが解消するか確認すること。
 * パディング領域はRXと同じくガード(常にゼロであるべき)としても扱い、
 * `eth_check_tx_guard()`で監視する(`err`コマンドから呼ばれる)。 */
#define ETH_TX_RING_ALLOC_SIZE (ETH_TX_RING_SIZE + 16)

/* テレメトリ用カウンタ(eth.h参照)。tcpbench等が1秒ごとの差分を
 * サンプリングしてロス相当の指標として使う。 */
volatile uint32_t g_eth_rsr_bna_count = 0;
volatile uint32_t g_eth_rsr_ovr_count = 0;

/* リング・RXバッファ用net_buf_tは、双方とも記述子リングと同じくRP1の
 * DMAエンジンがCPUと同時に読み書きする共有メモリなのでvolatile経由。
 * .dma_bssセクション配置についてはnet_buf.cのs_poolと同じ理由
 * (MMU有効化、mmu.c参照)。 */
static volatile gem_desc_t s_rx_ring[ETH_RX_RING_ALLOC_SIZE] __attribute__((aligned(64), section(".dma_bss")));
static volatile gem_desc_t s_tx_ring[ETH_TX_RING_ALLOC_SIZE] __attribute__((aligned(64), section(".dma_bss")));

/* RXリング用バッファは一般プール(net_buf.c、cacheable)からではなく専用
 * 配列から取る -- ここはGEMのDMAが直接読み書きする実体そのものなので
 * .dma_bssへ配置しDevice-nGnRnEのまま維持する必要がある(net_buf.cの
 * s_poolは受信後のコピー先「out」バッファ等、DMAが直接触らない短命用途
 * 専用にしてcacheable化した -- MMU有効化、mmu.c参照)。このリングが
 * eth_init()完了後ずっと専有し続ける(一般プールへは返却しない) --
 * eth_poll_recv()の既存の契約(eth.h参照)通り、完成したフレームは
 * 別途net_buf_alloc()した(cacheableな)バッファへコピーして呼び出し側へ
 * 渡し、リング側のバッファ自体はその場で同じスロットに再登録(再武装)する。 */
static net_buf_t s_rx_ring_bufs[ETH_RX_RING_SIZE] __attribute__((aligned(64), section(".dma_bss")));
static net_buf_t *s_rx_bufs[ETH_RX_RING_SIZE];
static unsigned s_rx_tail;   /* 次に確認するRXリングのインデックス */
static unsigned s_tx_head;   /* 次に使うTXリングのインデックス */
/* TX_WRAPスロット(slot ETH_TX_RING_SIZE-1)を前回のeth_tx_queue()で使用した
 * ことを示すフラグ。次回のeth_tx_queue()でTEトグル+TBQP再ラッチが必要。
 * 詳細はeth_tx_queue()のコメント参照。 */
static int s_tx_wrap_pending = 0;
static uint32_t s_ncr_base;  /* eth_init()完了時点のNCR値(RE/TE/MPE等込み)。
                               * eth_send()がNCR_TSTARTを立てる際、毎回
                               * mmio_read32()で読み直さずこれを使う。 */

_Static_assert(sizeof(net_buf_t) % 64 == 0,
               "net_buf_tのサイズは64バイトの倍数である必要がある(GEMのRXバッファサイズ制約)");
/* DMACFG.RXBSは8bitフィールド(64バイト単位)なので表現できる最大値は
 * 255*64=16320バイト -- net_buf_tを将来さらに拡張する場合にこの上限を
 * 静かに超えないようにする(超えるとRXBSの上位ビットが切り捨てられ、
 * ハードウェアが意図より小さいバッファサイズで動作してしまう)。 */
_Static_assert(sizeof(net_buf_t) / 64 <= 255,
               "net_buf_tが大きすぎてDMACFG.RXBS(8bit, 64バイト単位)に収まらない");

/* ------------------------------------------------------------------ */
/* EtherType ハンドラテーブル (既存のまま、変更なし)                       */
/* ------------------------------------------------------------------ */

#define HANDLER_MAX 8

static struct {
    uint16_t      ethertype;
    eth_handler_t handler;
    int           used;
} g_handlers[HANDLER_MAX];


/* ------------------------------------------------------------------ */
/* eth_dispatch()でコールされるハンドラの登録関数                     */
/* ip_init(), arp_ini()からコールされる                               */
/* ------------------------------------------------------------------ */
void eth_register_handler(uint16_t ethertype, eth_handler_t handler)
{
    // 既存エントリを検索
    for (int i = 0; i < HANDLER_MAX; i++) {
        if (g_handlers[i].used && g_handlers[i].ethertype == ethertype) {
            g_handlers[i].handler = handler;
            if (!handler) g_handlers[i].used = 0;
            return;
        }
    }
    // 空きスロットに追加
    if (handler) {
        for (int i = 0; i < HANDLER_MAX; i++) {
            if (!g_handlers[i].used) {
                g_handlers[i].ethertype = ethertype;
                g_handlers[i].handler   = handler;
                g_handlers[i].used      = 1;
                return;
            }
        }
        uart_printf("[eth] handler table full\n");
    }
}

// 2026-08-09、ハードウェアチェックサムオフロード対応(eth.hコメント
// 参照)。per-coreスカラー -- eth_dispatch()呼び出しのネスト無し前提。
static int s_rx_hw_csum_ok[SMP_MAX_CORES];

int eth_rx_hw_csum_ok(void)
{
    return s_rx_hw_csum_ok[smp_core_index()];
}

void eth_dispatch(net_buf_t *nb)
{
    if (!nb || nb->len < 14) return;
    uint16_t etype = (uint16_t)((nb->data[12] << 8) | nb->data[13]);
    const uint8_t *src_mac = &nb->data[6];
    const uint8_t *payload = &nb->data[14];
    size_t plen = nb->len - 14;

    unsigned core = smp_core_index();
    s_rx_hw_csum_ok[core] = nb->hw_csum_ok;

    for (int i = 0; i < HANDLER_MAX; i++) {
        if (g_handlers[i].used && g_handlers[i].ethertype == etype) {
            g_handlers[i].handler(payload, plen, src_mac); // -> arp_handle_frame(arp.c) / ip_handle_frame(ip.c)。eth_register_handler()で登録
            break;
        }
    }
    s_rx_hw_csum_ok[core] = 0;
}

/* ------------------------------------------------------------------ */
/* MDIO (clause22)                                                     */
/* ------------------------------------------------------------------ */

static int gem_mdio_wait_idle(void)
{
    uint64_t start = timer_now();

    while (!(mmio_read32(ETH_BASE + R_NSR) & NSR_IDLE)) {
        if (get_ms_from(start) > 100u) {
            return -1;
        }
    }
    return 0;
}

// MDIO(clause22)でPHYレジスタを1つ読む。NCR.MPEが有効になっている必要がある。
static int gem_mdio_read(uint8_t phy_addr, uint8_t regnum, uint16_t *out)
{
    if (gem_mdio_wait_idle() != 0) return -1;

    uint32_t man = MAN_C22_SOF | MAN_C22_READ | MAN_C22_CODE
                 | ((uint32_t)(phy_addr & 0x1Fu) << MAN_PHYA_SHIFT)
                 | ((uint32_t)(regnum & 0x1Fu) << MAN_REGA_SHIFT);
    mmio_write32(ETH_BASE + R_MAN, man);

    if (gem_mdio_wait_idle() != 0) return -1;

    *out = (uint16_t)(mmio_read32(ETH_BASE + R_MAN) & MAN_DATA_MASK);
    return 0;
}

// MDIO(clause22)でPHYレジスタを1つ書く。NCR.MPEが有効になっている必要が
// ある。GTCR/ANAR/BMCRへ広告能力・オートネゴシエーション再起動を
// 明示的に書くために追加(このファイル冒頭のMII_GTCR等のコメント参照 --
// 以前はPHYのリセットデフォルト任せで、それが実機で100Mbps制限の原因に
// なっていた)。
static int gem_mdio_write(uint8_t phy_addr, uint8_t regnum, uint16_t val)
{
    if (gem_mdio_wait_idle() != 0) return -1;

    uint32_t man = MAN_C22_SOF | MAN_C22_WRITE | MAN_C22_CODE
                 | ((uint32_t)(phy_addr & 0x1Fu) << MAN_PHYA_SHIFT)
                 | ((uint32_t)(regnum & 0x1Fu) << MAN_REGA_SHIFT)
                 | ((uint32_t)val & MAN_DATA_MASK);
    mmio_write32(ETH_BASE + R_MAN, man);

    return gem_mdio_wait_idle();
}

// 標準MIIレジスタ(GTSR/ANAR/ANLPAR)から実際にネゴシエートされた速度/
// デュプレックスを解決する。1000BASE-T(GTSR)を優先し、リンクパートナーが
// 対応していなければANAR&ANLPARの共通能力から100/10・全二重/半二重を
// 標準の優先順位(100FD > 100HD > 10FD > 10HD)で決める。
// MDIO自体が応答しない場合(gem_mdio_read失敗)は10BASE-T半二重を返す
// (NCFGRの初期値相当の最も保守的な設定)。
static void gem_resolve_speed_duplex(int *out_gbe, int *out_spd100, int *out_fd)
{
    uint16_t gtsr = 0;
    if (gem_mdio_read(ETH_PHY_ADDR, MII_GTSR, &gtsr) == 0 &&
        (gtsr & (GTSR_LP_1000FD | GTSR_LP_1000HD))) {
        *out_gbe = 1;
        *out_spd100 = 0;
        *out_fd = (gtsr & GTSR_LP_1000FD) ? 1 : 0;
        return;
    }

    uint16_t anar = 0, anlpar = 0;
    gem_mdio_read(ETH_PHY_ADDR, MII_ANAR, &anar);
    gem_mdio_read(ETH_PHY_ADDR, MII_ANLPAR, &anlpar);
    uint16_t common = anar & anlpar;

    *out_gbe = 0;
    if (common & ANLPAR_100FD) {
        *out_spd100 = 1; *out_fd = 1;
    } else if (common & ANLPAR_100) {
        *out_spd100 = 1; *out_fd = 0;
    } else if (common & ANLPAR_10FD) {
        *out_spd100 = 0; *out_fd = 1;
    } else {
        *out_spd100 = 0; *out_fd = 0;
    }
}

/* ------------------------------------------------------------------ */
/* リング初期化                                                          */
/* ------------------------------------------------------------------ */

// TXリングを初期化する(全記述子をUSED=空きにし、最終エントリにWRAPを立てる)。
// addr_hiは常にDMA_ADDR_HI32(バッファ未設定時も含め一律)。
static void gem_init_tx_ring(void)
{
    for (unsigned i = 0; i < ETH_TX_RING_SIZE; i++) {
        s_tx_ring[i].addr_hi = DMA_ADDR_HI32;
        s_tx_ring[i].addr = 0;
        s_tx_ring[i].ctrl = TX_USED;
        s_tx_ring[i].resvd = 0;
    }
    s_tx_ring[ETH_TX_RING_SIZE - 1].ctrl |= TX_WRAP;
    s_tx_head = 0;
}

// TXリング内の全記述子のUSED/WRAP/LASTビットとFRMLENを記録する。
// 2026-07-25、nvmetのIOキュー接続直後という特定タイミングで
// eth_tx_wait_slot()のタイムアウトが繰り返し再発する事象の調査用に追加。
// 実際にハードウェアがどこまで処理し、どこで止まっているか(TX_USEDが
// 立っている範囲、WRAPビットの位置)を、eth_tx_recover()がリングを
// 作り直して証拠を消す前に記録する。
//
// 【重要な訂正】最初はuart_printf()で1エントリ1行ずつ出力していたが、
// 実機の`ts`ログで、この出力自体が115200bpsのUARTを256行分ブロッキング
// 送信するせいで約1〜1.5秒の追加停止を生んでいたと判明した(タイムアウト
// 5秒と合わせて実測delta=約6.15秒の空白がts_logに残っていた)。この停止
// 時間の延長自体が、ホスト側のTCP/NVMeタイムアウトを誘発して接続が
// RST/FINで切られる一因になっていた可能性が高い。診断コード自体が問題を
// 悪化させていた典型例 -- ts_log()(インメモリのリングバッファ、即座に
// 返る)へ記録する方式に切り替え、UARTには1行の要約だけ出す。詳細は
// `ts mask 0xffff0000 0x07600000 num <count>` で後から確認できる(arg = index<<24 |
// USED<<23 | WRAP<<22 | LAST<<21 | FRMLEN(14bit))。
// eth_dump_tx_ring_debug()のts_log記録は、後始末処理(eth_tx_recover()、
// TCP再送、Ctrl+C中断、セッション終了/FIN再送等)が大量にts_log()を発生
// させると`ts mask ...0x07600000`が見つかる前にリングバッファから押し出される
// ことを実機で確認した(2026-07-25、`ts type TXRDタグ一致なし`)。ネット
// ワーク越しにハングを見てから`ts`コマンドを打つまでシェルがnvmetで
// ブロックされ続けるため、ユーザ側で「即座に読む」対策は取れない。
// このスナップショットはts_logとは独立した専用バッファで、以後どれだけ
// ts_log()が呼ばれても上書きされない -- `txdump`コマンド(command.c)で
// いつでも確認できる。
static uint32_t s_tx_ring_snapshot[ETH_TX_RING_SIZE];
static unsigned s_tx_ring_snapshot_head = 0;
static int      s_tx_ring_snapshot_wrap_pending = 0;
static int      s_tx_ring_snapshot_valid = 0;

static void eth_dump_tx_ring_debug(void)
{
    uart_printf("[eth] TXリングダンプ (s_tx_head=%u s_tx_wrap_pending=%d、"
                "詳細は`ts mask 0xffff0000 0x07600000 num 300`または`txdump`参照)\n",
                s_tx_head, s_tx_wrap_pending);
    s_tx_ring_snapshot_head = s_tx_head;
    s_tx_ring_snapshot_wrap_pending = s_tx_wrap_pending;
    for (unsigned i = 0; i < ETH_TX_RING_SIZE; i++) {
        uint32_t ctrl = s_tx_ring[i].ctrl;
        uint32_t arg = (i << 24)
                     | ((ctrl & TX_USED) ? (1u << 23) : 0u)
                     | ((ctrl & TX_WRAP) ? (1u << 22) : 0u)
                     | ((ctrl & TX_LAST) ? (1u << 21) : 0u)
                     | (ctrl & TX_FRMLEN_MASK);
        s_tx_ring_snapshot[i] = arg;
        ts_log(TS_MK(TS_FILE_ETH, TS_FUNC_eth_dump_tx_ring_debug, 0), arg);
    }
    s_tx_ring_snapshot_valid = 1;
}

void eth_print_tx_ring_snapshot(void)
{
    if (!s_tx_ring_snapshot_valid) {
        uart_printf("[eth] TXリングスナップショット無し"
                    "(TXリング枠待ちタイムアウトはまだ発生していない)\n");
        return;
    }
    uart_printf("[eth] TXリングスナップショット (直近のタイムアウト検出時点、"
                "s_tx_head=%u s_tx_wrap_pending=%d)\n",
                s_tx_ring_snapshot_head, s_tx_ring_snapshot_wrap_pending);
    for (unsigned i = 0; i < ETH_TX_RING_SIZE; i++) {
        uint32_t arg     = s_tx_ring_snapshot[i];
        unsigned used    = (arg >> 23) & 1u;
        unsigned wrap    = (arg >> 22) & 1u;
        unsigned last    = (arg >> 21) & 1u;
        unsigned frmlen  = arg & TX_FRMLEN_MASK;
        uart_printf("  [%3u] USED=%u WRAP=%u LAST=%u FRMLEN=%u\n",
                    i, used, wrap, last, frmlen);
    }
}

// macb_main.cのmacb_halt_tx()相当。TE(Transmit Enable)をいきなり落とす
// のではなく、正規の停止要求ビットNCR.THALTを立て、TSR.TGO(Transmit Go、
// 送信進行中を示す状態ビット)が落ちるまで待つ -- 進行中の送信を安全に
// 完了させてから止める、という正規の手順。
//
// 2026-07-25、実機でnvmetのIOキュー接続直後にeth_tx_wait_slot()の
// タイムアウト→eth_tx_recover()が繰り返し再発する事象を調査中に、
// raspberrypi/linuxのmacb_main.cを再取得して確認したところ、当時の
// eth_tx_recover()の「macb_tx_error_task()にならった」という主張は
// 誤りだったと判明した -- 実ドライバはTHALT(このビット)+TSR.TGO待ちで
// 停止し、**正常系ではTEに一切触れない**。TEを直接落とすのはドライバ側の
// 「THALT自体がタイムアウトした」という異常系のみのフォールバックであり、
// 我々のコードが常用していた「TE off→TBQP書き換え→TE on」は実ドライバの
// 正常系の手順とは異なるものだった。TEを直接操作する方式がRP1のGEMで
// 何らかの不整合を招いていた可能性があるため、実ドライバの手順に合わせて
// 書き直した。
// タイムアウト値14ms(MACB_HALT_TIMEOUT、実ドライバと同値)。
// 戻り値: 0=THALTで正常停止, -1=タイムアウト(呼び出し元がTEの強制トグルに
//         フォールバックすること、macb_tx_error_task()のhalt_timeout分岐と同じ)
static int eth_tx_halt(void)
{
    mmio_write32(ETH_BASE + R_NCR, mmio_read32(ETH_BASE + R_NCR) | NCR_THALT);

    uint64_t start = timer_now();
    while (mmio_read32(ETH_BASE + R_TSR) & TSR_TGO) {
        if (get_ms_from(start) > 14u) {
            return -1;
        }
    }
    return 0;
}

// TX記述子タイムアウト(entryのUSEDがハードウェアから一向に立たない)からの
// 回復処理。GEMがTSR.UBR等でTXキューを内部的に停止させた場合、記述子の
// ソフトウェア側状態(未USEDのまま)だけを次回呼び出しでどう組み直しても
// ハードウェアが再びそこを見に行く保証が無い -- 実機のtcptestで、最初の
// scatter-gather送信(2記述子)が一度タイムアウトした後は、以降の送信が
// (単一記述子の送信も含め)すべて同じタイムアウトで失敗し続けることを確認
// 済み(CLAUDE.md不掲載、tcptest実行ログで確認)。TSRを読み捨てるだけでは
// 復帰しなかったため、TBQPを再ラッチさせ、リング全体を初期状態に作り直す。
// このフレームの記述子は破棄されるが、呼び出し元(tcp.c)はeth_send_frags()
// の失敗をtcp_send()の再送(Go-Back-N)で扱う前提なので、ここでは失うだけで
// 問題ない。
//
// 2026-07-25、TBQP書き換え前の停止手順をeth_tx_halt()(THALT正規手順)に
// 置き換えた -- 以前はTEを直接落としていたが、実ドライバの正常系はTEに
// 一切触れないと判明したため(eth_tx_halt()コメント参照)。THALT自体が
// タイムアウトした場合のみ、実ドライバのhalt_timeout分岐と同じくTEを
// 強制的に落として復帰させる。
static void eth_tx_recover(void)
{
    uint32_t tsr = mmio_read32(ETH_BASE + R_TSR);
    if (tsr != 0) {
        uart_printf("[eth] TX回復: TSR=0x%08x (", tsr);
        if (tsr & TSR_UBR) uart_printf(" UBR");
        if (tsr & TSR_COL) uart_printf(" COL");
        if (tsr & TSR_RLE) uart_printf(" RLE");
        if (tsr & TSR_BEX) uart_printf(" BEX");
        if (tsr & TSR_UND) uart_printf(" UND");
        uart_printf(" ) をクリアしTXキューを再初期化\n");
    }

    int halted = (eth_tx_halt() == 0);
    if (!halted) {
        uart_printf("[eth] TX回復: THALTタイムアウト(14ms)、TEを強制トグル\n");
        uint32_t ncr = mmio_read32(ETH_BASE + R_NCR);
        mmio_write32(ETH_BASE + R_NCR, ncr & ~NCR_TE);
    }

    mmio_write32(ETH_BASE + R_TSR, 0xFFFFFFFFu);  // write-1-clearで全ビットクリア

    gem_init_tx_ring();
    s_tx_wrap_pending = 0;  // リング再初期化でフラグも無効化
    mmio_write32(ETH_BASE + R_TBQP, (uint32_t)(uintptr_t)s_tx_ring);
    mmio_write32(ETH_BASE + R_TBQPH, DMA_ADDR_HI32);

    if (!halted) {
        mmio_write32(ETH_BASE + R_NCR, s_ncr_base);  // TE(と他ビット)を復元(異常系のみ)
    }
    // halted==1(正常系)ではNCR(TE含む)には一切触れない -- 実ドライバの
    // macb_tx_error_task()の正常系と同じ(THALT自体がTEを無効化しない)。
}

// RXリングを初期化する。専用配列s_rx_ring_bufs(.dma_bss)から直接取る
// ため、一般プール(net_buf.c)の空き状況には依存しない。
static int gem_init_rx_ring(void)
{
    for (unsigned i = 0; i < ETH_RX_RING_SIZE; i++) {
        net_buf_t *nb = &s_rx_ring_bufs[i];
        /* 受信ゼロコピー対応(net_buf.h参照): これらのリングバッファは
         * net_buf_alloc()を経由しない静的確保なので、dataを実体storageへ
         * 明示的に向ける。GEMのDMA先は&nb->storage(offset0、旧&nb->dataと
         * 同一アドレス)。 */
        nb->data = nb->storage;
        s_rx_bufs[i] = nb;
        s_rx_ring[i].ctrl = 0;
        uint32_t addr = (uint32_t)(uintptr_t)nb->storage;
        if (i == ETH_RX_RING_SIZE - 1) addr |= RX_WRAP;
        s_rx_ring[i].addr_hi = DMA_ADDR_HI32;
        s_rx_ring[i].addr = addr;
        s_rx_ring[i].resvd = 0;
    }
    s_rx_tail = 0;
    return 0;
}

// RXリング復旧処理: RSR.BNA(Buffer Not Available)/RSR.OVR(Receive Overrun)を
// eth_poll_recv()で検出した際に呼ぶ。drivers/net/ethernet/cadence/
// macb_main.cのmacb_interrupt()、RXUBR処理そのもの(CLAUDE.mdの「参照
// ドライバソース」節参照、実際にfetchして確認済み) -- 「heavy load下で
// DMAが停止し、REを再度有効化するまでUsed Buffer Descriptor Readが
// 延々と続くハードウェアの既知の問題」に対する当該ドライバの対処は
// NCR.REを一度落として立て直すことだけ。
//
// 【重要】RBQP/RBQPHは絶対に書き直さないこと -- 実ドライバもそうしていない。
// 一度これでハマった: RBQPをs_rx_ring(先頭、entry0)へ書き戻す版を最初に
// 実装したところ、ハードウェアの内部書き込み位置がentry0へ巻き戻る一方
// s_rx_tail(ソフトウェア側の次に読むべき位置)はそのままになり、両者が
// 完全にズレた。以降ハードウェアは実際にフレームを受信していても
// s_rx_tailとは違う位置に書き込むため、eth_poll_recv()は永久にそれを
// 見つけられず「フレームが一切届かない」ように見える -- BNAで一度も
// 発生しなかったはずの新たな受信断を自ら作り出してしまった(実機の
// tcptestで2回目の接続がSYN再送5回すべて失敗するという形で確認)。
// NCR.REのトグルだけならソフトウェア側のリング状態(s_rx_ring/
// s_rx_bufs/s_rx_tail)は一切触れる必要がなく、ハードウェアの書き込み
// 位置もs_rx_tailとの対応を保ったまま復帰する。
static void eth_rx_recover(void)
{
    uint32_t ncr = mmio_read32(ETH_BASE + R_NCR);
    mmio_write32(ETH_BASE + R_NCR, ncr & ~NCR_RE);
    mmio_write32(ETH_BASE + R_NCR, ncr | NCR_RE);
}

/* ------------------------------------------------------------------ */
/* PHYハードウェアリセット (RP1 GPIO32)                                   */
/* ------------------------------------------------------------------ */

// GPIO32(active-low)をパルスして外部PHYをリセットする。
// macb_mdio_reset()(macb_main.c)相当: アサート(Low) -> 5ms保持 -> 解除(High)。
static void phy_hw_reset(void)
{
    // パッドの出力ドライバを有効化する(POR/前回状態によらず確実にする)。
    uint32_t pad = mmio_read32(PHY_RST_PAD_REG);
    pad &= ~PAD_OUT_DISABLE_BIT;
    mmio_write32(PHY_RST_PAD_REG, pad);

    // FUNCSELを素のGPIOにし、OEOVER=ENABLE/OUTOVER=LOWでLow出力を強制する
    // (アサート = リセット状態)。
    uint32_t ctrl = mmio_read32(PHY_RST_CTRL_REG);
    ctrl &= ~(GPIO_CTRL_FUNCSEL_MASK | GPIO_CTRL_OUTOVER_MASK | GPIO_CTRL_OEOVER_MASK);
    ctrl |= GPIO_CTRL_FUNCSEL_GPIO | GPIO_CTRL_OEOVER_ENABLE | GPIO_CTRL_OUTOVER_LOW;
    mmio_write32(PHY_RST_CTRL_REG, ctrl);

    timer_delay_ms(PHY_RESET_HOLD_MS);

    // OUTOVERをHIGHに変更して解除する(FUNCSEL/OEOVERはそのまま)。
    ctrl = (ctrl & ~GPIO_CTRL_OUTOVER_MASK) | GPIO_CTRL_OUTOVER_HIGH;
    mmio_write32(PHY_RST_CTRL_REG, ctrl);

    timer_delay_ms(PHY_RESET_SETTLE_MS);
}

/* ------------------------------------------------------------------ */
/* 公開API                                                              */
/* ------------------------------------------------------------------ */

// rp1_*(下記フルの定義)の前方宣言 -- s_rp1_opsが先に参照するため。
static int rp1_send_frags(void *priv, const eth_frag_t *frags, unsigned frag_count);
static int rp1_send_frags_async(void *priv, const eth_frag_t *frags, unsigned frag_count);
static unsigned rp1_tx_wait_free_slot(void *priv);
static net_buf_t *rp1_poll_recv(void *priv);

// RP1バックエンドのMACアドレス(ローカル管理アドレス、固定値)。
// s_rp1_ctx.macの初期値としても使う(eth_init()参照)。
static const uint8_t RP1_MAC[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x05 };

// nic_ops_t: RP1バックエンド(netctx.h参照)。
static const nic_ops_t s_rp1_ops = {
    .send_frags        = rp1_send_frags,
    .send_frags_async  = rp1_send_frags_async,
    .tx_wait_free_slot = rp1_tx_wait_free_slot,
    .poll_recv         = rp1_poll_recv,
};
static net_ctx_t s_rp1_ctx;
/* コア1向けtelnetセッション用のRP1別名(net.hのNET_RP1_CORE1_IP、
 * netctx.hのnet_ctx_register_alias()コメント参照)。実ハードウェアは
 * s_rp1_ctxと完全に共有し、このctx自体はポーリングされない。 */
static net_ctx_t s_rp1_ctx_core1;

void eth_get_mac(uint8_t mac[ETH_ALEN])
{
    if (g_active_ctx) {
        for (int i = 0; i < ETH_ALEN; i++) mac[i] = g_active_ctx->mac[i];
        return;
    }
    // フォールバック: net init前(g_active_ctx未設定)に呼ばれた場合の
    // 従来の固定値。通常この経路は通らない(eth_init()が自分自身の
    // ブリングアップ中に呼ぶeth_get_mac()より前にs_rp1_ctxを
    // 登録・アクティブ化するため)。
    for (int i = 0; i < ETH_ALEN; i++) mac[i] = RP1_MAC[i];
}

void eth_init(void)
{
    if (pcie_rc_init() != 0) {
        uart_printf("[eth] PCIeブリングアップ失敗、初期化中止\n");
        return;
    }

    net_buf_pool_init();

    // netctx.h: RP1をnet_ctx_tとして登録・アクティブ化する。以降の
    // eth_get_mac()呼び出し(このeth_init()自身の中も含む)が正しく
    // このコンテキストのMACを返せるよう、ブリングアップの他の処理より
    // 前に行う。既存の呼び出し側(`net init`、引数無し)は一切変更
    // なしで今まで通りRP1が使われる(CLAUDE.md「TCP/IPスタックの
    // ConnectX統合」節参照)。
    s_rp1_ctx.name = "rp1";
    for (int i = 0; i < ETH_ALEN; i++) s_rp1_ctx.mac[i] = RP1_MAC[i];
    s_rp1_ctx.ip = NET_RP1_DEFAULT_IP;
    s_rp1_ctx.nic = &s_rp1_ops;
    s_rp1_ctx.nic_priv = NULL;
    // RP1はジャンボフレーム対応済み(NET_BUF_SIZE=10240、eth.hのETH_JUMBO_
    // MAX_LEN参照)なのでtcp.cのTCP_MSS_LOCAL(10182)をそのまま使う --
    // 値そのものはtcp.h非公開のため、ここでは直接の定数として複製する
    // (netctx.hのnet_ctx_t.mss_capコメント参照、両者がずれないよう
    // 変更時は両方を確認すること)。
    s_rp1_ctx.mss_cap = 10182u;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) s_rp1_ctx.arp_cache[i].valid = 0;
    net_ctx_register(&s_rp1_ctx);
    net_ctx_activate(&s_rp1_ctx);

    // コア1向けtelnetセッション用の別名ctx(net.hのNET_RP1_CORE1_IP、
    // netctx.hのnet_ctx_register_alias()コメント参照)。MACはs_rp1_ctxと
    // 同じ(同一物理NICのため、IPアドレスだけを別に名乗るIPエイリアシング)。
    s_rp1_ctx_core1.name = "rp1-core1";
    for (int i = 0; i < ETH_ALEN; i++) s_rp1_ctx_core1.mac[i] = RP1_MAC[i];
    s_rp1_ctx_core1.ip = NET_RP1_CORE1_IP;
    s_rp1_ctx_core1.mss_cap = 10182u;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) s_rp1_ctx_core1.arp_cache[i].valid = 0;
    net_ctx_register_alias(&s_rp1_ctx_core1, &s_rp1_ctx);

    // 0. PHYをGPIO32(active-low)でハードリセットする。MAC自体の設定より
    //    先に行い、後続のMAC初期化にかかる時間だけリセット解除後の
    //    settleマージンと重ねられるようにする。
    phy_hw_reset();

    // 1. USRIO: RGMIIインターフェースを選択 (dtb phy-mode="rgmii-id")
    mmio_write32(ETH_BASE + R_USRIO, USRIO_RGMII);

    // 2. macb_reset_hw相当: RX/TX無効化、統計クリア、ステータス/割り込みクリア
    uint32_t ncr = mmio_read32(ETH_BASE + R_NCR);
    ncr &= ~(NCR_RE | NCR_TE);
    ncr |= NCR_CLRSTAT;
    mmio_write32(ETH_BASE + R_NCR, ncr);
    mmio_write32(ETH_BASE + R_TSR, 0xFFFFFFFFu);
    mmio_write32(ETH_BASE + R_RSR, 0xFFFFFFFFu);
    mmio_write32(ETH_BASE + R_IDR, 0xFFFFFFFFu);
    (void)mmio_read32(ETH_BASE + R_ISR);

    // 3. 自機MACアドレスをSA1B/SA1Tへ設定
    uint8_t mac[ETH_ALEN];
    eth_get_mac(mac);
    uint32_t sa1b = (uint32_t)mac[0] | ((uint32_t)mac[1] << 8)
                  | ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24);
    uint32_t sa1t = (uint32_t)mac[4] | ((uint32_t)mac[5] << 8);
    mmio_write32(ETH_BASE + R_SA1B, sa1b);
    mmio_write32(ETH_BASE + R_SA1T, sa1t);

    // 4. AXIパイプライン設定 (rp1.dtsiのrp1_ethノードのプロパティ値そのまま)
    uint32_t amp = (8u << AMP_AR2R_MAX_PIPE_SHIFT)
                 | (8u << AMP_AW2W_MAX_PIPE_SHIFT)
                 | AMP_AW2B_FILL;
    mmio_write32(ETH_BASE + R_AMP, amp);

    // 5. MDIO(MPE)を有効化し、リンク確立(オートネゴシエーション完了)を
    //    最大ETH_LINK_WAIT_MS待つ。BMSR bit2(Link Status)はラッチ式
    //    (sticky-low)のため毎回2回連続読みし、2回目の値を現在の状態とする
    //    (IEEE 802.3 clause22の一般的な仕様、特定PHYベンダ固有ではない)。
    //    BMSR=0xffff(全ビット1)はMDIOバスに誰も応答していない
    //    (フローティング)ことを示す典型的なパターンなので弾く。
    //    NCFGRのSPD/FD/GBEビットは実際のネゴシエーション結果に合わせる
    //    必要があるため、この判定をNCFGR書き込み(6.)より先に行う。
    ncr = mmio_read32(ETH_BASE + R_NCR);
    mmio_write32(ETH_BASE + R_NCR, ncr | NCR_MPE);

    // 5a. オートネゴシエーションで広告する能力を明示的に書く。以前は
    //     PHYのリセットデフォルト任せ(GTCR/ANAR/BMCR一切書き込みなし)
    //     だったが、それだと実機で常に100M-FDにしかリンクせず、
    //     Gigabit対応のはずのRaspberry Pi 5が100Mbps制限になっていた
    //     (BMSR bit8のExtended Statusは立っており、PHY自体は1000BASE-T
    //     対応であることは確認済み — MII_GTCR等のコメント参照)。
    //     GTCR(1000BASE-T広告)とANAR(10/100広告)を明示的に設定した上で
    //     BMCRでオートネゴシエーションを再起動し、新しい広告内容で
    //     ネゴシエーションをやり直させる。
    gem_mdio_write(ETH_PHY_ADDR, MII_GTCR, GTCR_ADV_ALL_1000);
    gem_mdio_write(ETH_PHY_ADDR, MII_ANAR, ANAR_ADV_ALL_10_100);
    gem_mdio_write(ETH_PHY_ADDR, MII_BMCR, BMCR_AN_ENABLE | BMCR_RESTART_AN);

    uint16_t bmsr = 0;
    int link_up = 0;
    uint64_t link_start = timer_now();
    do {
        uint16_t tmp;
        if (gem_mdio_read(ETH_PHY_ADDR, MII_BMSR, &tmp) == 0 &&
            gem_mdio_read(ETH_PHY_ADDR, MII_BMSR, &bmsr) == 0 &&
            bmsr != 0xFFFFu && (bmsr & MII_BMSR_LINK_STATUS)) {
            link_up = 1;
            break;
        }
        timer_delay_ms(50);
    } while (get_ms_from(link_start) < ETH_LINK_WAIT_MS);

    int gbe, spd100, fd;
    if (link_up) {
        gem_resolve_speed_duplex(&gbe, &spd100, &fd);
        uart_printf("[eth] PHY(addr=%u) リンクアップ (BMSR=0x%04x, %s%s)\n",
                    ETH_PHY_ADDR, bmsr,
                    gbe ? "1000M" : (spd100 ? "100M" : "10M"),
                    fd ? "-FD" : "-HD");
    } else {
        // リンク未確立: Gigabit/全二重を仮定してNCFGRを設定する
        // (フォールバック。実際のリンクとは食い違う可能性がある)。
        gbe = 1; spd100 = 0; fd = 1;
        uart_printf("[eth] PHY(addr=%u) %ums待ってもリンク未確立 (最終BMSR=0x%04x)、"
                    "Gigabit/全二重を仮定して続行する\n",
                    ETH_PHY_ADDR, ETH_LINK_WAIT_MS, bmsr);
    }

    // 6. NCFGR: MDC分周 + データバス幅(DCFG1から自己申告値を読む) +
    //    JFRAME(ジャンボフレーム有効、GEM_JML=ETH_JUMBO_MAX_LENまで受信、
    //    2026-07-25にBIGから切り替え -- macb_main.cのmacb_init_hw()と同じ
    //    「MACB_CAPS_JUMBOならJFRAME、無ければBIG」の排他ロジック。標準
    //    サイズのフレームも問題なく受信できるため常時有効で構わない) +
    //    DRFCS(FCS自動除去) + 実際にネゴシエートされた速度/デュプレックス(5.)。
    //    RBOFは意図的に0のまま(eth.h冒頭コメント参照)。
    uint32_t dcfg1 = mmio_read32(ETH_BASE + R_DCFG1);
    uint32_t dbwdef = (dcfg1 >> DCFG1_DBWDEF_SHIFT) & DCFG1_DBWDEF_MASK;
    uint32_t dbw = (dbwdef == 4u) ? 2u : (dbwdef == 2u) ? 1u : 0u; // macb_dbw()相当

    uint32_t ncfgr = NCFGR_JFRAME
                   | NCFGR_DRFCS
                   | (GEM_CLK_DIV96 << NCFGR_CLK_SHIFT)
                   | (dbw << NCFGR_DBW_SHIFT);
    if (fd) ncfgr |= NCFGR_FD;
    if (gbe) ncfgr |= NCFGR_GBE;
    else if (spd100) ncfgr |= NCFGR_SPD;
    mmio_write32(ETH_BASE + R_NCFGR, ncfgr);

    // 6a. JML(Jumbo Max Length): macb_init_hw()と同じくNCFGR書き込み直後に
    //     設定する。ETH_JUMBO_MAX_LEN(eth.h、実機ドライバのjumbo_max_len
    //     と同値の10240)を書く。
    mmio_write32(ETH_BASE + R_JML, ETH_JUMBO_MAX_LEN);

    // 7. DMACFG: RXバッファサイズ(net_buf_tの実サイズ/64。ジャンボ対応後は
    //    10304/64=161)、TX/RXバッファをフルメモリサイズに、バースト長16、
    //    ADDR64(64bitアドレッシング/拡張記述子)を有効化。
    uint32_t rxbs = (uint32_t)(sizeof(net_buf_t) / 64);
    uint32_t dmacfg = (ETH_DMA_BURST_LENGTH << DMACFG_FBLDO_SHIFT)
                    | (0x3u << DMACFG_RXBMS_SHIFT)
                    | DMACFG_TXPBMS
                    | (rxbs << DMACFG_RXBS_SHIFT)
                    | DMACFG_ADDR64;
    mmio_write32(ETH_BASE + R_DMACFG, dmacfg);

    // 8. TX/RX記述子リングを構築し、ベースポインタを設定
    gem_init_tx_ring();
    if (gem_init_rx_ring() != 0) {
        uart_printf("[eth] RXリング初期化失敗、初期化中止\n");
        return;
    }
    mmio_write32(ETH_BASE + R_RBQP, (uint32_t)(uintptr_t)s_rx_ring);
    mmio_write32(ETH_BASE + R_TBQP, (uint32_t)(uintptr_t)s_tx_ring);
    // ADDR64有効化に合わせ、記述子リング自体の64bitアドレスの上位32bitも
    // DMA_ADDR_HI32にする(記述子が指すバッファ側のaddr_hiと同じ理由)。
    mmio_write32(ETH_BASE + R_RBQPH, DMA_ADDR_HI32);
    mmio_write32(ETH_BASE + R_TBQPH, DMA_ADDR_HI32);

    // 9. RX/TX有効化
    ncr = mmio_read32(ETH_BASE + R_NCR);
    s_ncr_base = ncr | NCR_RE | NCR_TE;
    mmio_write32(ETH_BASE + R_NCR, s_ncr_base);
    // eth_send()はこのs_ncr_baseをキャッシュ済みの値として使い、送信の
    // たびにNCRを読み直さない(PCIe MMIO読み出しラウンドトリップを
    // 1回減らす -- 実測ではこの読み出し自体は0us近くだったが、それでも
    // 無駄なPCIeトランザクションを送信のたびに発生させる理由が無い)。
    // eth_init()以降、NCRの他ビット(RE/TE/MPE)を書き換える経路が無い
    // 前提が崩れたら、ここも合わせて更新すること。

    uart_printf("[eth] RP1 GEM init 完了 (MAC=%02x:%02x:%02x:%02x:%02x:%02x)\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* entryの記述子が前回の占有者の送信完了(TX_USED=1)を示すまでブロックする
 * (タイムアウトでeth_tx_recover()、リングを初期状態へ作り直す)。
 * gem_init_tx_ring()直後、または既に完了済みのスロットではTX_USEDが
 * 既に立っているため即座に通過する — 実際にブロックするのはパイプライン化
 * (ETH_TX_RING_SIZE個先行キューイング)によりリングが一周し、まだ完了して
 * いない古いフレームへ追いついた場合のみ。
 * 戻り値: 0=空き確認, -1=タイムアウト(eth_tx_recover()実行済み) */
static int eth_tx_wait_slot(unsigned entry)
{
    uint64_t wait_start = timer_now();
    /* 2026-07-25、nvmetのfio read実行中にETH_TX_RING_SIZEの値に関わらず
     * (8/32/256いずれでも)ある1枚のフレームだけがTX_USEDを一向に立てない
     * まま止まる事象を実機で確認した -- リングサイズは無罪と確定済み
     * (eth.hのETH_TX_RING_SIZEコメント参照)。THALT正規手順への置き換え
     * (eth_tx_halt())でも解消せず、`ts`ログでadmin queue(conn0)との
     * 干渉も無い(純粋にconn1単独の定常送信中に発生)ことを確認したが、
     * 根本原因はまだ特定できていない。
     *
     * 【診断中に踏んだ別の実機バグ】原因切り分けのためタイムアウトを
     * 1秒→5秒へ一時的に延長し、詰まった記述子リング全体をUART経由で
     * ダンプする処理も追加したところ、この延長+ダンプ出力
     * (115200bpsのUARTを256行ブロッキング送信、約1〜1.5秒)によって
     * 復旧までの総停止時間が約6秒超まで伸び、その間にホスト側の
     * TCP/NVMeタイムアウトが発火して接続がRST/FINで切られる、という
     * 診断コード自体が症状を悪化させる事態を実機で確認した(`ts`ログに
     * delta=約6147466usの空白として記録された)。タイムアウトは1秒に
     * 戻し、リングダンプはts_log()(即座に返るインメモリ記録)方式へ
     * 変更した(eth_dump_tx_ring_debug()参照)— 元々の1秒タイムアウト+
     * 軽い復旧処理であれば、この個別フレームの詰まり自体は接続を殺さず
     * 吸収できていた可能性がある。 */
    while (!(s_tx_ring[entry].ctrl & TX_USED)) {
        if (get_ms_from(wait_start) > 1000u) { // 1秒
            uart_printf("[eth] TXリング枠待ちタイムアウト (entry=%u)\n", entry);
            /* 後始末処理(eth_tx_recover()、TCP再送、Ctrl+C中断、セッション
             * 終了/FIN再送等)が大量にts_log()を発生させ、この時点までの
             * 文脈(TXQE/SSEG/ASND等)がリングバッファから押し出されて
             * しまう前に凍結する(2026-07-25追加、`ts frozen`参照)。必ず
             * eth_dump_tx_ring_debug()より前に呼ぶ -- そちらが256件の
             * TXRDエントリを追加する前の、障害直前の文脈をそのまま保存する
             * ため。 */
            ts_log_freeze();
            /* eth_tx_recover()がリングを作り直す前に、ハードウェアが実際
             * どこまで処理していたかの証拠を残す(2026-07-25追加、こちらは
             * s_tx_ring_snapshot[]にも独立保存するため`ts`の上書きの影響を
             * 受けない、`txdump`参照)。 */
            eth_dump_tx_ring_debug();
            eth_tx_recover();
            return -1;
        }
    }
    return 0;
}

/* frags[]をTXリングへ書き込みNCR_TSTARTを立てて送信をハードウェアへ
 * 引き渡す(eth_send_frags()/eth_send_frags_async()共通の実装)。この
 * フレーム自体の送信完了は待たない — 呼び出し元がeth_send_frags()なら
 * この後で待ち、eth_send_frags_async()なら待たずに返る。
 * 戻り値: 0=キュー成功(entry0_out/last_entry_outに範囲を書く)、
 *         -1=引数エラー/スロット空き待ちタイムアウト */
static int eth_tx_queue(const eth_frag_t *frags, unsigned frag_count,
                         unsigned *entry0_out, unsigned *last_entry_out)
{
    if (!frags || frag_count == 0 || frag_count > ETH_TX_MAX_FRAGS) {
        return -1;
    }

    uint32_t total_len = 0;
    for (unsigned f = 0; f < frag_count; f++) total_len += frags[f].len;
    if (total_len < ETH_HDR_LEN || total_len > NET_BUF_SIZE) {
        uart_printf("[eth] eth_send_frags: 不正なフレーム長 (%u)\n", total_len);
        return -1;
    }

    // このフレームで使うfrag_count個の連続したディスクリプタが、リング
    // 終端をまたがないようにする(WRAPはディスクリプタの「リング内位置」
    // に付くものでありフレームの断片境界とは無関係なので、またぐ場合の
    // 処理を複雑にするより単純に先頭へ巻き戻る -- 巻き戻りで飛ばした
    // 残りのスロットはリングが一周してまた使われるまで無駄になるが、
    // ETH_TX_RING_SIZEに対しfrag_countは小さいため実害は無い)。
    // TX_WRAPスロット(slot 7)を前回使用した場合の回復処理。
    //
    // 問題: RP1 GEMはTX_WRAPによるリング折り返し後、内部の「次に処理する
    // 記述子ポインタ」がTBQP(slot 0)へ更新されず、TX_WRAPスロット(slot 7)
    // のままに留まることがある。この状態でNCR_TSTARTを書くと、ハードウェアは
    // slot 7を再度読み、TX_USED=1(前回送信の完了マーク)を検出してUBRを立てて
    // 停止する。以降のNCR_TSTARTも同様に失敗し続け、パイプライン化された
    // 残りのセグメント(segment 9〜12相当)が永続的に送信されなくなる。
    //
    // 解決: TBQPを再ラッチさせることでハードウェアの内部ポインタをslot 0に
    // リセットする。eth_tx_recover()のコメントに記述された「TSRを読み捨てる
    // だけでは復帰しなかったため TBQP を再ラッチ」と同じ処置。ただし
    // eth_tx_recover()はリングを完全に再初期化するのに対し、ここではリング
    // の内容は維持し、TBQPのみ操作する。
    //
    // 2026-07-25、TBQP書き換え前の停止手順をeth_tx_halt()(NCR.THALTの
    // 正規手順、eth_tx_recover()と同じ)に置き換えた -- 以前はTEを直接
    // 落としていたが、実ドライバ(macb_main.cのmacb_halt_tx()/
    // macb_tx_error_task())の正常系はTEに一切触れずTHALT+TSR.TGO待ちだけで
    // 完結すると判明したため(eth_tx_halt()コメント参照)。
    //
    // タイミング制約: 停止は進行中のDMA転送を中断しうるため、必ず
    // TX_WRAPスロット(slot ETH_TX_RING_SIZE-1)の送信完了を確認してから
    // 行う。そのスロットのTX_USED=1が立てば全フレームが送信済みであることが
    // 保証される(リングは順序通りに処理される)。
    if (s_tx_wrap_pending) {
        s_tx_wrap_pending = 0;
        if (eth_tx_wait_slot(ETH_TX_RING_SIZE - 1) != 0) {
            // タイムアウト: eth_tx_wait_slot()がeth_tx_recover()を実行し
            // リングを再初期化済み。このフレームは破棄してエラーを返す。
            return -1;
        }
        // 最終スロットの送信完了確認済み。THALT+TBQP再ラッチを実施。
        mmio_write32(ETH_BASE + R_TSR, 0xFFFFFFFFu);     // TSR全ビットクリア
        int halted = (eth_tx_halt() == 0);
        if (!halted) {
            uart_printf("[eth] TX_WRAP再ラッチ: THALTタイムアウト(14ms)、TEを強制トグル\n");
            mmio_write32(ETH_BASE + R_NCR, s_ncr_base & ~NCR_TE);
        }
        mmio_write32(ETH_BASE + R_TBQP, (uint32_t)(uintptr_t)s_tx_ring);
        mmio_write32(ETH_BASE + R_TBQPH, DMA_ADDR_HI32);
        if (!halted) {
            mmio_write32(ETH_BASE + R_NCR, s_ncr_base);  // TE復元(異常系のみ)
        }
        // 正常系(halted==1)ではNCR(TE含む)には一切触れない。TBQP再ラッチ後、
        // ハードウェアはTBQP(slot 0)を参照する。slot 0はまだTX_USED=1
        // (前回フレームの完了マーク)のためUBRが発生し停止するのは想定内 —
        // 続く記述子書き込みとNCR_TSTARTで正しく再起動する。
    }

    if (s_tx_head + frag_count > ETH_TX_RING_SIZE) {
        s_tx_head = 0;
    }
    unsigned entry0 = s_tx_head;
    unsigned last_entry = entry0 + frag_count - 1;

    // TX_WRAPスロット無視バグの調査用(2026-07-25追加)。eth.c自体はどの
    // TCPコネクションが呼んでいるか知らないが、tcp_send_segment()は直前に
    // SSLT/SCKS(ts_conn_arg()でコネクションスロット+データ長を埋め込み済み)
    // を記録してから直ちにeth_send_frags()/_async()を呼ぶため、`ts`の
    // 生ログ(`ts <start> <end>`、タグ絞り込み無し)を時系列で見れば、この
    // TXQEタグの直前に記録されたSSLT/SCKS/ASND等のconn_slotから「どの
    // 接続がこのentry0を占有したか」を後付けで対応付けられる。
    // arg = entry0<<24 | frag_count<<21 | total_len(21bit)。
    ts_log(TS_MK(TS_FILE_ETH, TS_FUNC_eth_tx_queue, 0),
           ((uint32_t)entry0 << 24) | ((uint32_t)frag_count << 21) | (total_len & 0x1FFFFFu));

    // このフレームが使う各スロットについて、前回の占有者の送信完了を
    // 待つ(パイプライン化のバックプレッシャ、eth_tx_wait_slot()参照)。
    // タイムアウト時はeth_tx_recover()がs_tx_headを0へ作り直すため、
    // entry0/last_entryは無効になる -- ここでは即座に-1を返し、以降の
    // 記述子書き込みには進まない。
    for (unsigned e = entry0; e <= last_entry; e++) {
        if (eth_tx_wait_slot(e) != 0) {
            return -1;
        }
    }

    // 以下、drivers/net/ethernet/cadence/macb_main.cのmacb_tx_map()と
    // 同じ手順(CLAUDE.mdの「参照ドライバソース」節参照、実際にfetchして
    // 確認済み): 先頭ディスクリプタ(entry0、ハードウェアが次に見る位置)
    // はまずUSED=1にしておき、後続の断片(あれば)のaddr/ctrlを先に確定
    // させてから、最後に先頭ディスクリプタのctrlを書いてUSEDをクリアし
    // ハードウェアへ引き渡す。この順序が必要な理由: 先頭ディスクリプタの
    // USEDをクリアした瞬間からハードウェアがこのフレームの消費(TX_LAST=0
    // でのディスクリプタチェイン走査含む)を開始しうるため、それより
    // 後ろの全ディスクリプタは、先頭のUSEDクリアより「前」に確定して
    // いなければならない。
    //
    // メモリバリアについて: 通常のARM(Normal memory/キャッシュあり環境)
    // でこの種の準備にwmb()が必要になるのは、CPUのストアバッファや
    // キャッシュにより書き込み順序が入れ替わって外部から観測されうる
    // ためだが、このプロジェクトはMMU無効(SCTLR.M=0)で全メモリがDevice-
    // nGnRnE相当(net.h参照) -- non-Gathering/non-Reordering/no Early
    // write acknowledgementであり、CPUの発行順序どおりに各アクセスが
    // 完了することが architecturally 保証される。よって明示的なバリア
    // 命令は不要で、コンパイラによる並べ替えだけをvolatile経由の
    // アクセスで防げば十分(net.hの既存方針と同じ)。
    s_tx_ring[entry0].ctrl = TX_USED;

    // アドレス書き込み順序について(2026-07-25、実機調査で追加): macb_main.c
    // のmacb_set_addr()は64bitアドレッシング時、必ずaddr_hi(上位32bit)を
    // addr(下位32bit)より先に書く。理由としてコード中のコメントは「RXの
    // addrフィールド下位ビットにRX_USEDが乗っているため、下位を書く前に
    // 上位を可視化する必要がある」とRX固有の理由を挙げているが、同じ
    // macb_set_addr()はTXでも無条件にこの順序(addr_hi→addr)を使っており、
    // ドライバはTX/RXで順序を分けていない。以前の実装はこれを見落とし
    // addr→addr_hiの順(逆順)で書いていた -- ETH_TX_RING_SIZEに関わらず
    // TX_WRAPが立つ最終ディスクリプタだけがGEMに一貫して無視される
    // (TX_USEDが永久に立たない)事象を実機で確認し、実ドライバの書き込み
    // 順序を再確認して発見した相違点。TX_WRAPスロット特有の内部ステート
    // マシン遷移が、この順序に敏感である可能性を疑い、実ドライバに合わせて
    // addr_hiを先に書く順序へ修正した(まだ実機未検証)。
    for (unsigned f = 1; f < frag_count; f++) {
        unsigned entry = entry0 + f;
        uint32_t ctrl = (uint32_t)frags[f].len & TX_FRMLEN_MASK;
        if (f == frag_count - 1) ctrl |= TX_LAST;
        if (entry == ETH_TX_RING_SIZE - 1) ctrl |= TX_WRAP;

        s_tx_ring[entry].addr_hi = DMA_ADDR_HI32;
        s_tx_ring[entry].addr = (uint32_t)(uintptr_t)frags[f].data;
        s_tx_ring[entry].ctrl = ctrl;
    }

    s_tx_ring[entry0].addr_hi = DMA_ADDR_HI32;
    s_tx_ring[entry0].addr = (uint32_t)(uintptr_t)frags[0].data;
    {
        uint32_t ctrl0 = (uint32_t)frags[0].len & TX_FRMLEN_MASK;
        if (frag_count == 1) ctrl0 |= TX_LAST;
        if (entry0 == ETH_TX_RING_SIZE - 1) ctrl0 |= TX_WRAP;
        s_tx_ring[entry0].ctrl = ctrl0;  // USEDクリア = ハードウェアへの引き渡し
    }

    // NCR_TSTART前にTSRをクリアする。
    // RP1 GEMでは、TEトグル後またはTX_WRAPによる折り返し後にUBRが発生した
    // 場合、TSR.UBRが残った状態でNCR_TSTARTを書いてもハードウェアが再起動
    // しないことがある(s_tx_wrap_pending処理コメント参照)。
    // write-1-clearで全ビットをクリアしてからNCR_TSTARTを書く。
    mmio_write32(ETH_BASE + R_TSR, 0xFFFFFFFFu);
    // s_ncr_base(eth_init()完了時点のNCR値)を使い、送信のたびにNCRを
    // 読み直さない(eth_init()コメント参照)。
    mmio_write32(ETH_BASE + R_NCR, s_ncr_base | NCR_TSTART);

    // TX_WRAPスロットを使った場合は次回の呼び出しでTE再ラッチが必要。
    if (last_entry == ETH_TX_RING_SIZE - 1) {
        s_tx_wrap_pending = 1;
    }

    s_tx_head = (last_entry + 1) % ETH_TX_RING_SIZE;
    *entry0_out = entry0;
    *last_entry_out = last_entry;
    return 0;
}

// 以下4関数(rp1_*)はRP1 GEM固有の実装 -- 以前はeth_send_frags()等の
// 公開名そのものだったが、ConnectX(mlx5)統合(netctx.h参照)により、
// 公開名は「現在アクティブなコンテキストのバックエンドへディスパッチ
// する」薄いラッパーへ変わった(下記参照)。priv引数はnic_ops_tの
// シグネチャに合わせるためだけで、RP1は単一グローバル実装のため未使用。
static int rp1_send_frags(void *priv, const eth_frag_t *frags, unsigned frag_count)
{
    (void)priv;
    unsigned entry0, last_entry;
    if (eth_tx_queue(frags, frag_count, &entry0, &last_entry) != 0) {
        return -1;
    }

    // 完了待ちはこのフレームの最後の断片(TX_LAST=1)のUSEDビットを見る。
    // ハードウェアがどの時点で途中の断片のUSEDを立てるかの詳細に関わらず、
    // 「最後の断片のUSEDが立つ」のはTX_LASTで区切られるフレーム全体の
    // 送信が完了した後でしかありえない(定義上)ので、これが最も確実。
    uint64_t start = timer_now();
    while (!(s_tx_ring[last_entry].ctrl & TX_USED)) {
        if (get_ms_from(start) > 1000u) { // 1秒
            uart_printf("[eth] TXタイムアウト (entry=%u..%u)\n", entry0, last_entry);
            /* 一時診断(調査用、原因特定後に削除予定): entry0/last_entryの
             * 記述子の生の内容とfrags[]の元アドレスをeth_tx_recover()が
             * リングを再初期化する前にダンプする -- descriptorのaddr/
             * addr_hiがおかしい値になっていないか(GEMが実際にDMA readを
             * 試みたPCIアドレスが妥当か)を確認するため。 */
            uart_printf("[eth] entry0=%u addr_hi=0x%08x addr=0x%08x ctrl=0x%08x\n",
                        entry0, s_tx_ring[entry0].addr_hi, s_tx_ring[entry0].addr,
                        s_tx_ring[entry0].ctrl);
            if (last_entry != entry0) {
                uart_printf("[eth] last_entry=%u addr_hi=0x%08x addr=0x%08x ctrl=0x%08x\n",
                            last_entry, s_tx_ring[last_entry].addr_hi,
                            s_tx_ring[last_entry].addr, s_tx_ring[last_entry].ctrl);
            }
            uart_printf("[eth] frags[0].data=%p frags[0].len=%u frag_count=%u\n",
                        (const void *)frags[0].data, (unsigned)frags[0].len, frag_count);
            eth_tx_recover();
            return -1;
        }
    }
    return 0;
}

static int rp1_send_frags_async(void *priv, const eth_frag_t *frags, unsigned frag_count)
{
    (void)priv;
    unsigned entry0, last_entry;
    return eth_tx_queue(frags, frag_count, &entry0, &last_entry);
}

static unsigned rp1_tx_wait_free_slot(void *priv)
{
    (void)priv;
    // frag_count=1前提: この場合s_tx_headは常に[0, ETH_TX_RING_SIZE)の
    // 範囲内(eth_tx_queue()末尾の%演算子参照)なので、eth_tx_queue()の
    // 巻き戻り分岐(s_tx_head+frag_count>SIZE、frag_count>=2のときしか
    // 成立しない)には該当しない -- このフレームが使うスロットは常に
    // s_tx_head自身。
    unsigned entry = s_tx_head;
    if (eth_tx_wait_slot(entry) != 0) {
        // eth_tx_recover()がs_tx_headを0へ作り直しているので、待って
        // いたentryではなく最新のs_tx_headを返す。
        return s_tx_head;
    }
    return entry;
}

// 公開API(eth.h): 現在アクティブなコンテキスト(netctx.h)のバックエンド
// (RP1ならrp1_*、ConnectXならmlx5_net_*)へディスパッチする。呼び出し側
// (arp.c/ip.c/icmp.c/tcp.c)は一切変更していない -- 関数名・シグネチャ・
// 呼び出し規約は従来のまま。
// [関数ポインタ] 以下の eth_send_frags/async/lso/tx_wait_free_slot/poll_recv は
// g_active_ctx->nic 経由の間接呼び出し。実体は RP1=rp1_*(このファイル、s_rp1_ops) /
// ConnectX=mlx5_net_*(mlx5_net.c、s_mlx5_net_ops)。定義は netctx.h の nic_ops_t 参照。
int eth_send_frags(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) {
        uart_printf("[eth] eth_send_frags: アクティブなインターフェースが無い(net init未実行?)\n");
        return -1;
    }
    return g_active_ctx->nic->send_frags(g_active_ctx->nic_priv, frags, frag_count); // -> rp1_send_frags / mlx5_net_send_frags
}

int eth_send_frags_async(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) {
        return -1;
    }
    return g_active_ctx->nic->send_frags_async(g_active_ctx->nic_priv, frags, frag_count); // -> rp1_send_frags_async / mlx5_net_send_frags_async
}

// 2026-08-10、LSO対応(netctx.hのnic_ops_t.send_lsoコメント参照)。
// アクティブなインターフェースがLSO非対応(nic->send_lso==NULL、RP1は
// 常にこれ)なら-1を返す -- 呼び出し元(tcp.cのtcp_send_segment_lso())は
// net_active_lso_max_bytes()>0を確認してからしか呼ばない設計のため、
// このNULLチェックが実際に働くのは想定外の呼び出し順序に対する防御。
int eth_send_lso_async(const void *hdr, uint16_t hdr_len,
                        const void *payload, uint32_t payload_len, uint16_t mss)
{
    if (!g_active_ctx || !g_active_ctx->nic->send_lso) {
        return -1;
    }
    return g_active_ctx->nic->send_lso(g_active_ctx->nic_priv, hdr, hdr_len, payload, payload_len, mss); // -> mlx5_net_send_lso_async(RP1はsend_lso==NULL)
}

unsigned eth_tx_wait_free_slot(void)
{
    if (!g_active_ctx) {
        return 0;
    }
    return g_active_ctx->nic->tx_wait_free_slot(g_active_ctx->nic_priv); // -> rp1_tx_wait_free_slot / mlx5_net_tx_wait_free_slot
}

uint32_t eth_read_tsr_and_clear(void)
{
    uint32_t tsr = mmio_read32(ETH_BASE + R_TSR);
    if (tsr != 0) {
        mmio_write32(ETH_BASE + R_TSR, tsr);  // write-1-clear
    }
    return tsr;
}

uint32_t eth_read_isr(void)
{
    // ISRは読み出しでクリアされる設計が一般的(このコードベースではビット
    // 定義未裏取り、err.c参照)。eth_init()での初期読み捨て以降ここでしか
    // 読まない。
    return mmio_read32(ETH_BASE + R_ISR);
}

int eth_send(net_buf_t *nb)
{
    if (!nb) return -1;
    if (nb->len < ETH_HDR_LEN || nb->len > NET_BUF_SIZE) {
        uart_printf("[eth] eth_send: 不正なフレーム長 (%u)\n", (unsigned)nb->len);
        net_buf_free(nb);
        return -1;
    }

    // nbはnet_buf.cの一般プール(net_buf_alloc())由来で、MMU有効化後は
    // Normal cacheable(net_buf.cのs_poolコメント参照、tcp.cのs_seg_buf
    // と違いDMA専用の.dma_bssには置いていない)。しかしeth_send_frags()
    // にわたすと、そのままGEMのTX DMAソースとして使われる(ARP request/
    // reply、ip_send()経由のICMP等、いずれもこの経路)。CPUの書き込み
    // (フレーム構築)がキャッシュに留まったまま物理RAMへ届いていないと、
    // GEMが古い/不完全な内容をDMA読みしてしまい、実機でARP解決が常に
    // 失敗する形で発現した(tcpbenchのconnect失敗で発見)。DMA発行前に
    // 明示的にPoint of Coherencyまでクリーンする(cache.hのコメント参照
    // -- PCIe越しの外部バスマスタ向けにはdsb sy(system全体)を使う
    // dcache_clean_range()を使う。CPUコア間向けのdsb ish(inner shareable)
    // で十分なsync_icache_range()とはバリアの範囲が異なるため、ここは
    // 前者を使う)。
    dcache_clean_range(nb->data, nb->len);

    eth_frag_t frag = { nb->data, nb->len };
    int ret = eth_send_frags(&frag, 1);
    net_buf_free(nb);
    return ret;
}

static net_buf_t *rp1_poll_recv(void *priv)
{
    (void)priv;
    // RSR.BNA/OVRを確認する(write-1-clearなので読んだら即クリア)。
    // BNAが立つのはRXリング全記述子がUSED(空き無し)のままフレームが
    // 届いた場合 -- ソフトウェアのポーリングが追いつかずリングが溢れ、
    // ハードウェアがフレームを黙って破棄したことを示す。以前はここで
    // 毎回uart_printf()していたが、115200bpsのブロッキング送信が
    // ポーリング自体を遅延させ、スループット計測を歪める・ARP解決の
    // 取りこぼしを誘発する副作用があったため、カウンタのみにして
    // 呼び出し側(tcpbench等)が任意のタイミングでサンプリングする方式に
    // した(eth.hのg_eth_rsr_bna_count/g_eth_rsr_ovr_count参照)。
    //
    // カウンタ計上だけでは不十分 -- 実機のtcptestで、BNAが一度立つと
    // それ以降のセッション中ずっとRXが完全に沈黙する(ソフトウェア側は
    // ディスクリプタを正しく空けているにもかかわらず)ことを確認済み。
    // eth_rx_recover()のコメント参照。
    uint32_t rsr = mmio_read32(ETH_BASE + R_RSR);
    if (rsr & (RSR_BNA | RSR_OVR)) {
        mmio_write32(ETH_BASE + R_RSR, rsr & (RSR_BNA | RSR_OVR));
        if (rsr & RSR_BNA) g_eth_rsr_bna_count++;
        if (rsr & RSR_OVR) g_eth_rsr_ovr_count++;
        eth_rx_recover();
    }

    unsigned entry = s_rx_tail;

    if (!(s_rx_ring[entry].addr & RX_USED)) {
        return NULL; // 受信フレームなし
    }

    uint32_t ctrl = s_rx_ring[entry].ctrl;
    net_buf_t *ring_nb = s_rx_bufs[entry];
    net_buf_t *out = NULL;

    if ((ctrl & RX_CTRL_SOF) && (ctrl & RX_CTRL_EOF)) {
        uint32_t len = ctrl & RX_FRMLEN_MASK;
        if (len <= NET_BUF_SIZE) {
            out = net_buf_alloc();
            if (out) {
                /* ring_nb->data/out->dataはともに各net_buf_tのstorage[]
                 * (offset0、aligned(64))を指すので常に8バイト境界に整列して
                 * いる -- volatile_fast_copy()のワイドアクセス経路に確実に乗る
                 * (net.hのvolatile_fast_copy()コメント参照)。RP1は受信ゼロ
                 * コピー非対応なので、GEMがstorageへDMAした内容をnet_buf(out)へ
                 * コピーする従来動作のまま。 */
                volatile_fast_copy(out->data, ring_nb->data, len);
                out->len = (uint16_t)len;
                out->hw_csum_ok = 0; // RP1はチェックサムオフロード未対応(net_buf.hコメント参照)
            } else {
                uart_printf("[eth] poll: net_bufプール枯渇、フレーム破棄\n");
            }
        } else {
            uart_printf("[eth] poll: 異常なフレーム長 (%u)、破棄\n", (unsigned)len);
        }
    } else {
        // マルチディスクリプタ(net_buf_tのRXバッファサイズ超のフレーム、
        // DMACFG.RXBS=sizeof(net_buf_t)/64バイト超)は未対応。JFRAME設定
        // (NCFGR)+GEM_JML(=ETH_JUMBO_MAX_LEN)とnet_buf_tのサイズ
        // (ETH_JUMBO_MAX_LEN以上、net_buf.h参照)により通常は起こらない
        // はずだが、念のため検出する。
        uart_printf("[eth] poll: SOF/EOFが揃わないフレーム(未対応)、破棄\n");
    }

    // このリングスロットを再武装する(ctrl=0を先に書いてからaddrで
    // USEDをクリアする -- gem_rx_refill()と同じ順序)。
    s_rx_ring[entry].ctrl = 0;
    uint32_t addr = (uint32_t)(uintptr_t)ring_nb->storage;
    if (entry == ETH_RX_RING_SIZE - 1) addr |= RX_WRAP;
    s_rx_ring[entry].addr_hi = DMA_ADDR_HI32;
    s_rx_ring[entry].addr = addr;

    s_rx_tail = (entry + 1) % ETH_RX_RING_SIZE;
    return out;
}

net_buf_t *eth_poll_recv(void)
{
    if (!g_active_ctx) {
        return NULL;
    }
    return g_active_ctx->nic->poll_recv(g_active_ctx->nic_priv); // -> rp1_poll_recv / mlx5_net_poll_recv
}

int eth_check_rx_guard(void)
{
    int corrupted = 0;
    for (unsigned i = ETH_RX_RING_SIZE; i < ETH_RX_RING_ALLOC_SIZE; i++) {
        uint32_t addr = s_rx_ring[i].addr;
        uint32_t ctrl = s_rx_ring[i].ctrl;
        uint32_t addr_hi = s_rx_ring[i].addr_hi;
        uint32_t resvd = s_rx_ring[i].resvd;
        if (addr != 0 || ctrl != 0 || addr_hi != 0 || resvd != 0) {
            uart_printf("[eth] RXリングガード領域が破壊されている! "
                        "index=%u(s_rx_ring[%u]) addr=0x%08x ctrl=0x%08x "
                        "addr_hi=0x%08x resvd=0x%08x\n",
                        i - ETH_RX_RING_SIZE, i, addr, ctrl, addr_hi, resvd);
            corrupted = 1;
        }
    }
    if (!corrupted) {
        uart_printf("[eth] RXリングガード領域(%u件)は正常(全ゼロ)\n",
                    (unsigned)(ETH_RX_RING_ALLOC_SIZE - ETH_RX_RING_SIZE));
    }
    return corrupted;
}

// s_tx_ring直後のガード/プリフェッチパディング領域(ETH_TX_RING_ALLOC_SIZE
// コメント参照)が常にゼロのままかを確認する。ここが非ゼロになっていれば、
// GEMのディスクリプタ先読みが実際にこの領域まで書き込みを行った(または
// 別の原因での実行時破壊が起きた)ことの動かぬ証拠になる。
int eth_check_tx_guard(void)
{
    int corrupted = 0;
    for (unsigned i = ETH_TX_RING_SIZE; i < ETH_TX_RING_ALLOC_SIZE; i++) {
        uint32_t addr    = s_tx_ring[i].addr;
        uint32_t ctrl    = s_tx_ring[i].ctrl;
        uint32_t addr_hi = s_tx_ring[i].addr_hi;
        uint32_t resvd   = s_tx_ring[i].resvd;
        if (addr != 0 || ctrl != 0 || addr_hi != 0 || resvd != 0) {
            uart_printf("[eth] TXリングガード領域が破壊されている! "
                        "index=%u(s_tx_ring[%u]) addr=0x%08x ctrl=0x%08x "
                        "addr_hi=0x%08x resvd=0x%08x\n",
                        i - ETH_TX_RING_SIZE, i, addr, ctrl, addr_hi, resvd);
            corrupted = 1;
        }
    }
    if (!corrupted) {
        uart_printf("[eth] TXリングガード領域(%u件)は正常(全ゼロ)\n",
                    (unsigned)(ETH_TX_RING_ALLOC_SIZE - ETH_TX_RING_SIZE));
    }
    return corrupted;
}

/* ------------------------------------------------------------------ */
/* PHY関連 (未実装、eth.h参照)                                           */
/* ------------------------------------------------------------------ */

int eth_phy_link_up(void)
{
    return 0;
}

int eth_phy_aneg_complete(void)
{
    return 0;
}

int eth_wait_link_up(uint32_t timeout_ms)
{
    (void)timeout_ms;
    return 0;
}

void eth_set_loopback(int enable)
{
    (void)enable;
}
