#ifndef PCIDUMP_H
#define PCIDUMP_H

#include <stdint.h>

// pcie_cfg_read32()/pcie1_cfg_read32()のいずれかを渡す -- ドメイン(RP1/ConnectX)
// ごとにレジスタベースが異なるため、呼び出し元がどちらを使うか選択する。
typedef uint32_t (*pci_cfg_read32_fn)(uint8_t bus, uint8_t devfn, uint16_t offset);

// デバイスのPCI/PCIeコンフィグ空間全体をデバッグUARTにダンプする。
void pci_dump_config(uint8_t bus, uint8_t devfn, pci_cfg_read32_fn cfg_read32);

#endif
