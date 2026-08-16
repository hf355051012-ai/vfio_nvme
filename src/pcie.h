#ifndef PCIE_H
#define PCIE_H

#include <stdint.h>

// PCIeルートコンプレックスを立ち上げ、RP1のBAR割り当てまで完了させる。
// 成功(リンク確立)時0、失敗時は負値を返す。
int pcie_rc_init(void);

// コンフィグ空間アクセス。pcie_rc_init()成功後のみ有効。
uint32_t pcie_cfg_read32(uint8_t bus, uint8_t devfn, uint16_t offset);
void pcie_cfg_write32(uint8_t bus, uint8_t devfn, uint16_t offset, uint32_t val);

// RP1のBAR0/BAR1を割り当て、Memory Space + Bus Masterを有効化する。
int rp1_assign_bar0(void);

#endif
