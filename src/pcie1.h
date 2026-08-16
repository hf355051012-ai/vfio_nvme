#ifndef PCIE1_H
#define PCIE1_H

#include <stdint.h>

// PCIe(x1、ドメイン1、SoC直結の外部M.2/FFCコネクタ、board.hのPCIE1_RC_BASE
// 参照)を立ち上げる。ConnectX用。成功(リンク確立)時0、失敗時は負値を返す。
int pcie1_rc_init(void);

// PCIe1のPERST#(R_MISC_PCIE_CTRL.PERSTB)を明示的にアサート->デアサートし、
// ConnectX側をPCIe Fundamental Resetにかける -- ENABLE_HCA以降の残存FW状態
// (CLAUDE.md「ConnectX(mlx5)HCA初期化」節の「ConnectX自身のFW状態は
// チェインロードをまたいでpersistする」問題)を、電源再投入やSoCの`reboot`
// (PMウォッチドッグ、RP1/Ethernet等の無関係な状態まで巻き込んで失う)を
// 経由せずクリアする。PCIe1ドメインのリンクだけを対象にし、RC側の設定
// (outbound window等、pcie1_rc_init()が既に済ませたレジスタ)には触れない
// -- ConnectX自身のconfig space(BAR0割り当て・Command register)は電源
// オンデフォルトへ戻るため、呼び出し後はpcie1_assign_bar0_at()の再実行が
// 必要(mlx5_dual_port_bringup_and_test()が内部で毎回行うので、通常は
// このリセット後にそのまま`mlx5`を実行すればよい)。
// 戻り値: 0=リセット後にリンク再確立、-1=リンクが戻らなかった。
int pcie1_reset_link(void);

// コンフィグ空間アクセス。pcie1_rc_init()成功後のみ有効。
uint32_t pcie1_cfg_read32(uint8_t bus, uint8_t devfn, uint16_t offset);
void pcie1_cfg_write32(uint8_t bus, uint8_t devfn, uint16_t offset, uint32_t val);

// bus1 devfn0(ConnectX PF0)のBAR0をプローブし、PCIアドレス0へ割り当てて
// Memory Space + Bus Masterを有効化する。pcie1_assign_bar0_at(0, 0,
// size_out, is64_out)の薄いラッパー(後方互換維持用)。
// size_out: プローブしたBARサイズ(バイト)を返す(NULL可)。
// is64_out: 64bit BARだったら1、32bitなら0を返す(NULL可)。
// 戻り値: 0=成功, -1=失敗(BAR無応答、サイズがPCIE1_OUTBOUND_SIZE超過等)。
int pcie1_assign_bar0(uint64_t *size_out, int *is64_out);

// bus1 devfn(任意)のBAR0をプローブし、指定のPCIアドレスへ割り当てて
// Memory Space + Bus Masterを有効化する。ConnectXがマルチファンクション
// デバイス(2つの物理ポートがdevfn=0/1として別々のPCI関数で見える構成、
// CLAUDE.md「ConnectXデュアルポート対応」節参照)であることを踏まえ、
// devfn=1(2つ目の物理ポート)にも同じ手順を適用できるよう汎用化した。
// pci_addr_base: このBAR0を割り当てるPCIアドレス(devfn=1の場合、通常は
// devfn=0のBAR0サイズの直後を指定する -- 互いに重ならないようにする
// のは呼び出し元の責任)。
int pcie1_assign_bar0_at(uint8_t devfn, uint64_t pci_addr_base, uint64_t *size_out, int *is64_out);

#endif /* PCIE1_H */
