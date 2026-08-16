// err.c
//
// PCIe AER / RP1 Ethernet(GEM) エラーレジスタ診断 — フェーズ5
// 詳細はerr.hのファイル冒頭コメント参照。

#include <stdint.h>
#include "err.h"
#include "pcie.h"
#include "eth.h"
#include "uart.h"

/* AER(Advanced Error Reporting)拡張capabilityのID。PCI Express仕様の
 * 拡張capability構造共通。 */
#define AER_CAP_ID 0x0001u

#define AER_OFF_UNCORRECTABLE_STATUS 0x04u
#define AER_OFF_CORRECTABLE_STATUS   0x10u

/* 拡張capabilityリンクリストを辿ってAERのオフセットを探す
 * (pcidump.cのdump_ext_caps()と同じ歩き方 -- offset=0x100から開始し、
 * 各capabilityヘッダのbit[31:20]が次のcapabilityへのオフセット)。
 * 戻り値: 見つかればoffset(0x100以上)、無ければ0 */
static uint16_t find_aer_offset(uint8_t bus, uint8_t devfn)
{
    uint16_t offset = 0x100u;
    int count = 0;

    while (offset >= 0x100u && offset <= 0xffcu) {
        uint32_t hdr = pcie_cfg_read32(bus, devfn, offset);
        if (hdr == 0x00000000u || hdr == 0xffffffffu) {
            break;
        }

        uint16_t cap_id = (uint16_t)(hdr & 0xffffu);
        if (cap_id == AER_CAP_ID) {
            return offset;
        }

        offset = (uint16_t)((hdr >> 20) & 0xffcu);
        count++;
        if (count > 64) {
            break;  /* capabilityリストの循環を警戒(pcidump.cと同じ安全策) */
        }
    }
    return 0;
}

/* bus/devfnのAER Correctable/Uncorrectable Error Statusを読み、0でなければ
 * ログに出す(読んだレジスタはwrite-1-clearでクリアする)。
 * 戻り値: 1=何らかのエラービットが立っていた、0=AER capability無し
 *         またはクリーン */
static int check_aer(uint8_t bus, uint8_t devfn, const char *label)
{
    uint16_t aer_off = find_aer_offset(bus, devfn);
    if (aer_off == 0) {
        uart_printf("[ERR] %s: AER capabilityが見つからない\n", label);
        return 0;
    }

    uint32_t uncorr = pcie_cfg_read32(bus, devfn, (uint16_t)(aer_off + AER_OFF_UNCORRECTABLE_STATUS));
    uint32_t corr    = pcie_cfg_read32(bus, devfn, (uint16_t)(aer_off + AER_OFF_CORRECTABLE_STATUS));

    int has_error = 0;
    if (uncorr != 0) {
        uart_printf("[ERR] %s: AER Uncorrectable Error Status = 0x%08x\n", label, uncorr);
        pcie_cfg_write32(bus, devfn, (uint16_t)(aer_off + AER_OFF_UNCORRECTABLE_STATUS), uncorr);
        has_error = 1;
    }
    if (corr != 0) {
        /* Replay Timer Timeout(bit12)はリンクトレーニング由来の良性ノイズと
         * 既知(CLAUDE.md参照)。それ単体なら参考情報として出すだけにし、
         * has_errorは立てない -- 他のビットが同時に立っていれば通常通り
         * エラー扱いする。 */
        uart_printf("[ERR] %s: AER Correctable Error Status = 0x%08x%s\n", label, corr,
                    (corr == (1u << 12)) ? " (Replay Timer Timeoutのみ、既知の良性ノイズ)" : "");
        pcie_cfg_write32(bus, devfn, (uint16_t)(aer_off + AER_OFF_CORRECTABLE_STATUS), corr);
        if (corr != (1u << 12)) {
            has_error = 1;
        }
    }
    if (!has_error && (uncorr == 0 && corr == 0)) {
        uart_printf("[ERR] %s: AERエラー無し\n", label);
    }
    return has_error;
}

int err_check_all(void)
{
    int any = 0;

    any |= check_aer(0, 0, "RootPort(bus0,devfn0)");
    any |= check_aer(1, 0, "RP1(bus1,devfn0)");

    uint32_t tsr = eth_read_tsr_and_clear();
    if (tsr != 0) {
        uart_printf("[ERR] GEM TSR = 0x%08x :", tsr);
        if (tsr & (1u << 0)) uart_printf(" UBR(Used-Bit-Read)");
        if (tsr & (1u << 1)) uart_printf(" COL(衝突)");
        if (tsr & (1u << 2)) uart_printf(" RLE(再送上限超過)");
        if (tsr & (1u << 3)) uart_printf(" TGO(送信中)");
        if (tsr & (1u << 4)) uart_printf(" BEX(AHBバスエラーによるフレーム破損)");
        if (tsr & (1u << 5)) uart_printf(" COMP(送信完了)");
        if (tsr & (1u << 6)) uart_printf(" UND(アンダーラン)");
        uart_printf("\n");
        /* TGO(bit3)/COMP(bit5)は状態/成功ビットでありエラーではない。
         * それ以外(UBR=bit0/COL=bit1/RLE=bit2/BEX=bit4/UND=bit6、
         * ビット定義はeth.cのTSR_*マクロ参照)が立っていれば実エラーと
         * して扱う。 */
        uint32_t tsr_err_bits = (1u << 0) | (1u << 1) | (1u << 2) | (1u << 4) | (1u << 6);
        if (tsr & tsr_err_bits) {
            any = 1;
        }
    } else {
        uart_printf("[ERR] GEM TSR = 0 (エラー無し)\n");
    }

    uart_printf("[ERR] 累計RSR.BNA=%u RSR.OVR=%u (eth.c、RXリング溢れ/オーバーラン)\n",
                g_eth_rsr_bna_count, g_eth_rsr_ovr_count);

    /* ISR(Interrupt Status Register)は eth_init() で初期化時に1回読み捨てて
     * 以降一度も読んでいなかった(CLAUDE.md「TXハングの真因候補」節参照)。
     * ビット定義はこのコードベースで未裏取りのため生の16進値のみ表示する
     * -- 0でなければ何らかの割り込み要因(TXエラー系を含みうる)が起きた
     * ことは分かる。GEMのISRは読み出しでクリアされる設計が一般的なため、
     * ここで読むと以後の状態は変わる点に注意(調査用途のみ、他コードは
     * ISRを参照していないため副作用は無い)。 */
    uint32_t isr = eth_read_isr();
    uart_printf("[ERR] GEM ISR = 0x%08x (ビット定義未確認、非ゼロなら参考情報として記録)\n", isr);

    /* RXリング境界のメモリ破壊(CLAUDE.md参照、根本原因未特定の既知バグ)が
     * 実際に発生したかを直接確認する -- ガード領域(本来常にゼロ)が非ゼロ
     * なら、s_rx_ring[ETH_RX_RING_SIZE]以降への実在しないインデックス
     * 書き込みが実際に起きた動かぬ証拠になる。 */
    any |= eth_check_rx_guard();
    any |= eth_check_tx_guard();

    return any;
}
