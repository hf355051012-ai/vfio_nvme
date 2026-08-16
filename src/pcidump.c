// 名前付きPCI/PCIeコンフィグ空間ダンプ。PCIe Base Specのレジスタレイアウトに従う。

#include "pcidump.h"
#include "pl011.h"
#include <stddef.h>

extern pl011_t debug_uart; // main.cで定義

// pci_dump_config()の呼び出しごとに設定される、ドメイン固有のconfig読み出し関数
// (pcie_cfg_read32/pcie1_cfg_read32のいずれか)。シングルスレッドのベアメタル
// コードなのでファイルスコープの一時変数で十分 -- 全ヘルパにポインタを引き回す
// より簡潔。
static pci_cfg_read32_fn s_cfg_read32;

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
    uint16_t offset;
    uint8_t width;
    const char *name;
} reg_desc_t;

// valをdigits桁の16進数として出力する。
static void hex_digits(uint32_t val, int digits) {
    for (int shift = (digits - 1) * 4; shift >= 0; shift -= 4) {
        uint32_t nibble = (val >> shift) & 0xfu;
        pl011_putc(&debug_uart, (char)(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10)));
    }
}

// 文字列sを出力し、widthに満たない分をスペースで埋める。
static void pad(const char *s, unsigned width) {
    unsigned len = 0;
    while (s[len] != '\0') {
        len++;
    }
    pl011_puts(&debug_uart, s);
    while (len < width) {
        pl011_putc(&debug_uart, ' ');
        len++;
    }
}

// コンフィグ空間から1バイトを読む。
static uint8_t read_byte(uint8_t bus, uint8_t devfn, uint16_t off) {
    uint32_t dw = s_cfg_read32(bus, devfn, (uint16_t)(off & ~3u));
    return (uint8_t)(dw >> ((off & 3u) * 8u));
}

// 1レジスタを "offset  width  name  value" の形式で出力する。
static void dump_reg(uint8_t bus, uint8_t devfn, uint16_t abs_off, uint8_t width, const char *name) {
    uint32_t dw = s_cfg_read32(bus, devfn, (uint16_t)(abs_off & ~3u));
    uint32_t val;
    if (width == 1) {
        val = (dw >> ((abs_off & 3u) * 8u)) & 0xffu;
    } else if (width == 2) {
        val = (dw >> ((abs_off & 2u) * 8u)) & 0xffffu;
    } else {
        val = dw;
    }

    pl011_puts(&debug_uart, "0x");
    hex_digits(abs_off, 3);
    pl011_puts(&debug_uart, "  ");
    pl011_putc(&debug_uart, (char)('0' + width));
    pl011_puts(&debug_uart, "  ");
    pad(name, 38);
    pl011_puts(&debug_uart, "0x");
    hex_digits(val, width * 2);
    pl011_puts(&debug_uart, "\n");
}

// --- 標準ヘッダ (0x00-0x3f) ---

static const reg_desc_t type0_regs[] = {
    {0x00, 2, "Vendor ID"},
    {0x02, 2, "Device ID"},
    {0x04, 2, "Command"},
    {0x06, 2, "Status"},
    {0x08, 1, "Revision ID"},
    {0x09, 1, "Class Code (Prog IF)"},
    {0x0a, 1, "Class Code (Sub-Class)"},
    {0x0b, 1, "Class Code (Base Class)"},
    {0x0c, 1, "Cache Line Size"},
    {0x0d, 1, "Latency Timer"},
    {0x0e, 1, "Header Type"},
    {0x0f, 1, "BIST"},
    {0x10, 4, "BAR0"},
    {0x14, 4, "BAR1"},
    {0x18, 4, "BAR2"},
    {0x1c, 4, "BAR3"},
    {0x20, 4, "BAR4"},
    {0x24, 4, "BAR5"},
    {0x28, 4, "Cardbus CIS Pointer"},
    {0x2c, 2, "Subsystem Vendor ID"},
    {0x2e, 2, "Subsystem ID"},
    {0x30, 4, "Expansion ROM Base Address"},
    {0x34, 1, "Capabilities Pointer"},
    {0x3c, 1, "Interrupt Line"},
    {0x3d, 1, "Interrupt Pin"},
    {0x3e, 1, "Min_Gnt"},
    {0x3f, 1, "Max_Lat"},
};

static const reg_desc_t type1_regs[] = {
    {0x00, 2, "Vendor ID"},
    {0x02, 2, "Device ID"},
    {0x04, 2, "Command"},
    {0x06, 2, "Status"},
    {0x08, 1, "Revision ID"},
    {0x09, 1, "Class Code (Prog IF)"},
    {0x0a, 1, "Class Code (Sub-Class)"},
    {0x0b, 1, "Class Code (Base Class)"},
    {0x0c, 1, "Cache Line Size"},
    {0x0d, 1, "Latency Timer"},
    {0x0e, 1, "Header Type"},
    {0x0f, 1, "BIST"},
    {0x10, 4, "BAR0"},
    {0x14, 4, "BAR1"},
    {0x18, 1, "Primary Bus Number"},
    {0x19, 1, "Secondary Bus Number"},
    {0x1a, 1, "Subordinate Bus Number"},
    {0x1b, 1, "Secondary Latency Timer"},
    {0x1c, 1, "I/O Base"},
    {0x1d, 1, "I/O Limit"},
    {0x1e, 2, "Secondary Status"},
    {0x20, 2, "Memory Base"},
    {0x22, 2, "Memory Limit"},
    {0x24, 2, "Prefetchable Memory Base"},
    {0x26, 2, "Prefetchable Memory Limit"},
    {0x28, 4, "Prefetchable Base Upper 32 Bits"},
    {0x2c, 4, "Prefetchable Limit Upper 32 Bits"},
    {0x30, 2, "I/O Base Upper 16 Bits"},
    {0x32, 2, "I/O Limit Upper 16 Bits"},
    {0x34, 1, "Capabilities Pointer"},
    {0x38, 4, "Expansion ROM Base Address"},
    {0x3c, 1, "Interrupt Line"},
    {0x3d, 1, "Interrupt Pin"},
    {0x3e, 2, "Bridge Control"},
};

// --- 標準capability (0x40-0xff) ---

static const reg_desc_t cap_pm_regs[] = { // Power Management, ID=0x01
    {0x00, 4, "[PM] Header (ID/Next/Cap)"},
    {0x04, 2, "[PM] Capabilities"},
    {0x06, 2, "[PM] Control/Status"},
    {0x08, 1, "[PM] Bridge Support Ext"},
    {0x09, 1, "[PM] Data"},
};

static const reg_desc_t cap_msi_regs[] = { // MSI, ID=0x05
    {0x00, 4, "[MSI] Header (ID/Next/Ctrl)"},
    {0x04, 4, "[MSI] Message Address"},
    {0x08, 2, "[MSI] Message Data"},
    {0x0c, 4, "[MSI] Mask Bits"},
    {0x10, 4, "[MSI] Pending Bits"},
};

static const reg_desc_t cap_msix_regs[] = { // MSI-X, ID=0x11
    {0x00, 4, "[MSI-X] Header (ID/Next/Ctrl)"},
    {0x04, 4, "[MSI-X] Table Offset/BIR"},
    {0x08, 4, "[MSI-X] PBA Offset/BIR"},
};

static const reg_desc_t cap_pcie_regs[] = { // PCI Express Capability, ID=0x10
    {0x00, 4, "[PCIe] Header (ID/Next)"},
    {0x02, 2, "[PCIe] Capabilities"},
    {0x04, 4, "[PCIe] Device Capabilities"},
    {0x08, 2, "[PCIe] Device Control"},
    {0x0a, 2, "[PCIe] Device Status"},
    {0x0c, 4, "[PCIe] Link Capabilities"},
    {0x10, 2, "[PCIe] Link Control"},
    {0x12, 2, "[PCIe] Link Status"},
    {0x14, 4, "[PCIe] Slot Capabilities"},
    {0x18, 2, "[PCIe] Slot Control"},
    {0x1a, 2, "[PCIe] Slot Status"},
    {0x1c, 2, "[PCIe] Root Control"},
    {0x1e, 2, "[PCIe] Root Capabilities"},
    {0x20, 4, "[PCIe] Root Status"},
    {0x24, 4, "[PCIe] Device Capabilities 2"},
    {0x28, 2, "[PCIe] Device Control 2"},
    {0x2a, 2, "[PCIe] Device Status 2"},
    {0x2c, 4, "[PCIe] Link Capabilities 2"},
    {0x30, 2, "[PCIe] Link Control 2"},
    {0x32, 2, "[PCIe] Link Status 2"},
    {0x34, 4, "[PCIe] Slot Capabilities 2"},
    {0x38, 2, "[PCIe] Slot Control 2"},
    {0x3a, 2, "[PCIe] Slot Status 2"},
};

static const reg_desc_t cap_sata_regs[] = { // SATA Index-Data Pair, ID=0x12
    {0x00, 4, "[SATA] Header (ID/Next)"},
    {0x04, 4, "[SATA] Revision / Bar Info"},
    {0x08, 4, "[SATA] Offset"},
};

// 標準capabilityリンクリストを辿って出力する。
static void dump_std_caps(uint8_t bus, uint8_t devfn) {
    uint16_t status = (uint16_t)(s_cfg_read32(bus, devfn, 0x04) >> 16);
    if (!(status & (1u << 4))) {
        return; // Capabilities Listビットがクリア
    }

    uint8_t ptr = read_byte(bus, devfn, 0x34) & 0xfcu;
    int count = 0;

    while (ptr >= 0x40u) {
        uint32_t hdr = s_cfg_read32(bus, devfn, ptr);
        uint8_t cap_id = (uint8_t)(hdr & 0xffu);
        uint8_t next = (uint8_t)((hdr >> 8) & 0xfcu);

        const reg_desc_t *regs = NULL;
        unsigned nregs = 0;
        switch (cap_id) {
            case 0x01: regs = cap_pm_regs;   nregs = ARRAY_LEN(cap_pm_regs);   break;
            case 0x05: regs = cap_msi_regs;  nregs = ARRAY_LEN(cap_msi_regs);  break;
            case 0x10: regs = cap_pcie_regs; nregs = ARRAY_LEN(cap_pcie_regs); break;
            case 0x11: regs = cap_msix_regs; nregs = ARRAY_LEN(cap_msix_regs); break;
            case 0x12: regs = cap_sata_regs; nregs = ARRAY_LEN(cap_sata_regs); break;
            default:
                dump_reg(bus, devfn, ptr, 4, "[Cap] Header (ID/Next, unknown ID)");
                break;
        }
        for (unsigned i = 0; i < nregs; i++) {
            dump_reg(bus, devfn, (uint16_t)(ptr + regs[i].offset), regs[i].width, regs[i].name);
        }

        count++;
        if (count > 48 || next == 0) {
            break;
        }
        ptr = next;
    }
}

// --- 拡張capability (0x100-0xffc) ---

static const reg_desc_t excap_aer_regs[] = { // Advanced Error Reporting, ID=0x0001
    {0x00, 4, "[AER] Header"},
    {0x04, 4, "[AER] Uncorrectable Error Status"},
    {0x08, 4, "[AER] Uncorrectable Error Mask"},
    {0x0c, 4, "[AER] Uncorrectable Error Severity"},
    {0x10, 4, "[AER] Correctable Error Status"},
    {0x14, 4, "[AER] Correctable Error Mask"},
    {0x18, 4, "[AER] Capabilities and Control"},
    {0x1c, 4, "[AER] Header Log [0]"},
    {0x20, 4, "[AER] Header Log [1]"},
    {0x24, 4, "[AER] Header Log [2]"},
    {0x28, 4, "[AER] Header Log [3]"},
    {0x2c, 4, "[AER] TLP Prefix Log [0]"},
    {0x30, 4, "[AER] TLP Prefix Log [1]"},
    {0x34, 4, "[AER] TLP Prefix Log [2]"},
    {0x38, 4, "[AER] TLP Prefix Log [3]"},
};

static const reg_desc_t excap_aer_rp_regs[] = { // AERのルートポート限定フィールド
    {0x3c, 4, "[AER] Root Error Command"},
    {0x40, 4, "[AER] Root Error Status"},
    {0x44, 4, "[AER] Error Source Identification"},
};

static const reg_desc_t excap_vc_regs[] = { // Virtual Channel, ID=0x0002
    {0x00, 4, "[VC] Header"},
    {0x04, 4, "[VC] Port VC Capability 1"},
    {0x08, 4, "[VC] Port VC Capability 2"},
    {0x0c, 2, "[VC] Port VC Control"},
    {0x0e, 2, "[VC] Port VC Status"},
    {0x10, 4, "[VC] VC0 Resource Capability"},
    {0x14, 4, "[VC] VC0 Resource Control"},
    {0x1a, 2, "[VC] VC0 Resource Status"},
};

static const reg_desc_t excap_dsn_regs[] = { // Device Serial Number, ID=0x0003
    {0x00, 4, "[DSN] Header"},
    {0x04, 4, "[DSN] Serial Number Lower DW"},
    {0x08, 4, "[DSN] Serial Number Upper DW"},
};

static const reg_desc_t excap_pb_regs[] = { // Power Budgeting, ID=0x0004
    {0x00, 4, "[PB] Header"},
    {0x04, 4, "[PB] Data Select"},
    {0x08, 4, "[PB] Data"},
    {0x0c, 4, "[PB] Power Budget Capability"},
};

static const reg_desc_t excap_vsec_regs[] = { // Vendor-Specific Extended Cap, ID=0x000b
    {0x00, 4, "[VSEC] Header"},
    {0x04, 4, "[VSEC] ID / Rev / Length"},
    {0x08, 2, "[VSEC] (Vendor Defined)"},
};

static const reg_desc_t excap_acs_regs[] = { // Access Control Services, ID=0x000d
    {0x00, 4, "[ACS] Header"},
    {0x04, 2, "[ACS] Capability"},
    {0x06, 2, "[ACS] Control"},
    {0x08, 4, "[ACS] Egress Control Vector [0]"},
};

static const reg_desc_t excap_ari_regs[] = { // Alternative Routing-ID Interpretation, ID=0x000e
    {0x00, 4, "[ARI] Header"},
    {0x04, 2, "[ARI] Capability"},
    {0x06, 2, "[ARI] Control"},
};

static const reg_desc_t excap_ats_regs[] = { // Address Translation Services, ID=0x000f
    {0x00, 4, "[ATS] Header"},
    {0x04, 2, "[ATS] Capability"},
    {0x06, 2, "[ATS] Control"},
};

static const reg_desc_t excap_sriov_regs[] = { // Single Root I/O Virtualization, ID=0x0010
    {0x00, 4, "[SR-IOV] Header"},
    {0x04, 4, "[SR-IOV] Capabilities"},
    {0x08, 2, "[SR-IOV] Control"},
    {0x0a, 2, "[SR-IOV] Status"},
    {0x0c, 2, "[SR-IOV] InitialVFs"},
    {0x0e, 2, "[SR-IOV] TotalVFs"},
    {0x10, 2, "[SR-IOV] NumVFs"},
    {0x12, 2, "[SR-IOV] Function Dependency Link"},
    {0x14, 2, "[SR-IOV] First VF Offset"},
    {0x16, 2, "[SR-IOV] VF Stride"},
    {0x1a, 2, "[SR-IOV] VF Device ID"},
    {0x1c, 4, "[SR-IOV] Supported Page Sizes"},
    {0x20, 4, "[SR-IOV] System Page Size"},
    {0x24, 4, "[SR-IOV] VF BAR0"},
    {0x28, 4, "[SR-IOV] VF BAR1"},
    {0x2c, 4, "[SR-IOV] VF BAR2"},
    {0x30, 4, "[SR-IOV] VF BAR3"},
    {0x34, 4, "[SR-IOV] VF BAR4"},
    {0x38, 4, "[SR-IOV] VF BAR5"},
    {0x3c, 4, "[SR-IOV] VF Migration State Array Off"},
};

static const reg_desc_t excap_pri_regs[] = { // Page Request Interface, ID=0x0013
    {0x00, 4, "[PRI] Header"},
    {0x04, 2, "[PRI] Control"},
    {0x06, 2, "[PRI] Status"},
    {0x08, 4, "[PRI] Page Request Capacity"},
    {0x0c, 4, "[PRI] Page Request Allocation"},
};

static const reg_desc_t excap_rbar_regs[] = { // Resizable BAR, ID=0x0015
    {0x00, 4, "[RBAR] Header"},
    {0x04, 4, "[RBAR] BAR0 Capability"},
    {0x08, 4, "[RBAR] BAR0 Control"},
    {0x0c, 4, "[RBAR] BAR1 Capability"},
    {0x10, 4, "[RBAR] BAR1 Control"},
    {0x14, 4, "[RBAR] BAR2 Capability"},
    {0x18, 4, "[RBAR] BAR2 Control"},
    {0x1c, 4, "[RBAR] BAR3 Capability"},
    {0x20, 4, "[RBAR] BAR3 Control"},
    {0x24, 4, "[RBAR] BAR4 Capability"},
    {0x28, 4, "[RBAR] BAR4 Control"},
    {0x2c, 4, "[RBAR] BAR5 Capability"},
    {0x30, 4, "[RBAR] BAR5 Control"},
};

static const reg_desc_t excap_tph_regs[] = { // TPH Requester, ID=0x0017
    {0x00, 4, "[TPH] Header"},
    {0x04, 4, "[TPH] Requester Capability"},
    {0x08, 4, "[TPH] Requester Control"},
    {0x0c, 4, "[TPH] ST Table Entry [0]"},
};

static const reg_desc_t excap_ltr_regs[] = { // Latency Tolerance Reporting, ID=0x0018
    {0x00, 4, "[LTR] Header"},
    {0x04, 2, "[LTR] Max Snoop Latency"},
    {0x06, 2, "[LTR] Max No-Snoop Latency"},
};

static const reg_desc_t excap_sec_pcie_regs[] = { // Secondary PCIe (Gen3 EQ), ID=0x0019
    {0x00, 4, "[SecPCIe] Header"},
    {0x04, 4, "[SecPCIe] Link Control 3"},
    {0x08, 4, "[SecPCIe] Lane Error Status"},
    {0x0c, 4, "[SecPCIe] EQ Control Lane 0"},
};

static const reg_desc_t excap_pasid_regs[] = { // Process Address Space ID, ID=0x001b
    {0x00, 4, "[PASID] Header"},
    {0x04, 2, "[PASID] Capability"},
    {0x06, 2, "[PASID] Control"},
};

static const reg_desc_t excap_dpc_regs[] = { // Downstream Port Containment, ID=0x001d
    {0x00, 4, "[DPC] Header"},
    {0x04, 2, "[DPC] Capability"},
    {0x06, 2, "[DPC] Control"},
    {0x08, 2, "[DPC] Status"},
    {0x0a, 2, "[DPC] Error Source ID"},
    {0x0c, 4, "[DPC] RP PIO Status"},
    {0x10, 4, "[DPC] RP PIO Mask"},
    {0x14, 4, "[DPC] RP PIO Severity"},
    {0x18, 4, "[DPC] RP PIO SysError"},
    {0x1c, 4, "[DPC] RP PIO Exception"},
    {0x20, 4, "[DPC] RP PIO Header Log [0]"},
    {0x24, 4, "[DPC] RP PIO Header Log [1]"},
    {0x28, 4, "[DPC] RP PIO Header Log [2]"},
    {0x2c, 4, "[DPC] RP PIO Header Log [3]"},
    {0x30, 4, "[DPC] RP PIO ImpSpec Log"},
};

static const reg_desc_t excap_l1pm_regs[] = { // L1 PM Substates, ID=0x001e
    {0x00, 4, "[L1PM] Header"},
    {0x04, 4, "[L1PM] Capabilities"},
    {0x08, 4, "[L1PM] Control 1"},
    {0x0c, 4, "[L1PM] Control 2"},
};

static const reg_desc_t excap_ptm_regs[] = { // Precision Time Measurement, ID=0x001f
    {0x00, 4, "[PTM] Header"},
    {0x04, 4, "[PTM] Capability"},
    {0x08, 4, "[PTM] Control"},
};

static const reg_desc_t excap_dvsec_regs[] = { // Designated Vendor-Specific, ID=0x0023
    {0x00, 4, "[DVSEC] Header"},
    {0x04, 4, "[DVSEC] Vendor ID / Rev / Length"},
    {0x08, 2, "[DVSEC] ID"},
};

static const reg_desc_t excap_dlf_regs[] = { // Data Link Feature, ID=0x0025
    {0x00, 4, "[DLF] Header"},
    {0x04, 4, "[DLF] Data Link Feature Capabilities"},
    {0x08, 4, "[DLF] Data Link Feature Exchange"},
};

static const reg_desc_t excap_pl16_regs[] = { // Physical Layer 16.0 GT/s, ID=0x0026
    {0x00, 4, "[PL16] Header"},
    {0x04, 4, "[PL16] Capabilities"},
    {0x08, 4, "[PL16] Control"},
    {0x0c, 4, "[PL16] Status"},
    {0x10, 4, "[PL16] Local Parity Mismatch Status"},
    {0x14, 4, "[PL16] First Retimer Parity Mismatch"},
    {0x18, 4, "[PL16] Second Retimer Parity Mismatch"},
    {0x20, 4, "[PL16] TX Preset [Lanes 0-3]"},
};

static const reg_desc_t excap_margin_regs[] = { // Lane Margining at the Receiver, ID=0x0027
    {0x00, 4, "[Margin] Header"},
    {0x04, 2, "[Margin] Port Capabilities"},
    {0x06, 2, "[Margin] Port Status"},
    {0x08, 2, "[Margin] Lane 0 Control"},
    {0x0a, 2, "[Margin] Lane 0 Status"},
};

// 拡張capabilityリンクリストを辿って出力する。
static void dump_ext_caps(uint8_t bus, uint8_t devfn, int is_bridge) {
    uint16_t offset = 0x100;
    int count = 0;

    while (offset >= 0x100u && offset <= 0xffcu) {
        uint32_t hdr = s_cfg_read32(bus, devfn, offset);
        if (hdr == 0x00000000u || hdr == 0xffffffffu) {
            break;
        }

        uint16_t cap_id = (uint16_t)(hdr & 0xffffu);
        uint16_t next_off = (uint16_t)((hdr >> 20) & 0xffcu);

        const reg_desc_t *regs = NULL;
        unsigned nregs = 0;
        switch (cap_id) {
            case 0x0001: regs = excap_aer_regs;      nregs = ARRAY_LEN(excap_aer_regs);      break;
            case 0x0002: regs = excap_vc_regs;       nregs = ARRAY_LEN(excap_vc_regs);       break;
            case 0x0003: regs = excap_dsn_regs;      nregs = ARRAY_LEN(excap_dsn_regs);      break;
            case 0x0004: regs = excap_pb_regs;       nregs = ARRAY_LEN(excap_pb_regs);       break;
            case 0x000b: regs = excap_vsec_regs;     nregs = ARRAY_LEN(excap_vsec_regs);     break;
            case 0x000d: regs = excap_acs_regs;      nregs = ARRAY_LEN(excap_acs_regs);      break;
            case 0x000e: regs = excap_ari_regs;      nregs = ARRAY_LEN(excap_ari_regs);      break;
            case 0x000f: regs = excap_ats_regs;      nregs = ARRAY_LEN(excap_ats_regs);      break;
            case 0x0010: regs = excap_sriov_regs;    nregs = ARRAY_LEN(excap_sriov_regs);    break;
            case 0x0013: regs = excap_pri_regs;      nregs = ARRAY_LEN(excap_pri_regs);      break;
            case 0x0015: regs = excap_rbar_regs;     nregs = ARRAY_LEN(excap_rbar_regs);     break;
            case 0x0017: regs = excap_tph_regs;      nregs = ARRAY_LEN(excap_tph_regs);      break;
            case 0x0018: regs = excap_ltr_regs;      nregs = ARRAY_LEN(excap_ltr_regs);      break;
            case 0x0019: regs = excap_sec_pcie_regs; nregs = ARRAY_LEN(excap_sec_pcie_regs); break;
            case 0x001b: regs = excap_pasid_regs;    nregs = ARRAY_LEN(excap_pasid_regs);    break;
            case 0x001d: regs = excap_dpc_regs;      nregs = ARRAY_LEN(excap_dpc_regs);      break;
            case 0x001e: regs = excap_l1pm_regs;     nregs = ARRAY_LEN(excap_l1pm_regs);     break;
            case 0x001f: regs = excap_ptm_regs;      nregs = ARRAY_LEN(excap_ptm_regs);      break;
            case 0x0023: regs = excap_dvsec_regs;    nregs = ARRAY_LEN(excap_dvsec_regs);    break;
            case 0x0025: regs = excap_dlf_regs;      nregs = ARRAY_LEN(excap_dlf_regs);      break;
            case 0x0026: regs = excap_pl16_regs;     nregs = ARRAY_LEN(excap_pl16_regs);     break;
            case 0x0027: regs = excap_margin_regs;   nregs = ARRAY_LEN(excap_margin_regs);   break;
            default:
                dump_reg(bus, devfn, offset, 4, "[ExtCap] Header (unknown ID)");
                break;
        }
        for (unsigned i = 0; i < nregs; i++) {
            dump_reg(bus, devfn, (uint16_t)(offset + regs[i].offset), regs[i].width, regs[i].name);
        }
        if (cap_id == 0x0001 && is_bridge) {
            for (unsigned i = 0; i < ARRAY_LEN(excap_aer_rp_regs); i++) {
                dump_reg(bus, devfn, (uint16_t)(offset + excap_aer_rp_regs[i].offset),
                         excap_aer_rp_regs[i].width, excap_aer_rp_regs[i].name);
            }
        }

        count++;
        if (count > 64) {
            pl011_puts(&debug_uart, "[stopped: possible loop in capability list]\n");
            break;
        }
        if (next_off == 0) {
            break;
        }
        offset = next_off;
    }
}

// 指定デバイスのPCI/PCIeコンフィグ空間全体をダンプする。
void pci_dump_config(uint8_t bus, uint8_t devfn, pci_cfg_read32_fn cfg_read32) {
    s_cfg_read32 = cfg_read32;
    uint16_t vendor_id = (uint16_t)s_cfg_read32(bus, devfn, 0x00);
    if (vendor_id == 0xffffu) {
        pl011_puts(&debug_uart, "device not present (Vendor ID = 0xffff)\n");
        return;
    }

    uint8_t htype = read_byte(bus, devfn, 0x0e) & 0x7fu;
    int is_bridge = (htype == 0x01);

    const reg_desc_t *regs;
    unsigned nregs;
    if (htype == 0x00) {
        regs = type0_regs;
        nregs = ARRAY_LEN(type0_regs);
    } else if (htype == 0x01) {
        regs = type1_regs;
        nregs = ARRAY_LEN(type1_regs);
    } else {
        pl011_puts(&debug_uart, "unsupported Header Type: 0x");
        hex_digits(htype, 2);
        pl011_puts(&debug_uart, "\n");
        return;
    }

    pl011_puts(&debug_uart, "\nconfig dump: bus=0x");
    hex_digits(bus, 2);
    pl011_puts(&debug_uart, " devfn=0x");
    hex_digits(devfn, 2);
    pl011_puts(&debug_uart, is_bridge ? "  [Type 1 - Bridge]\n" : "  [Type 0 - Endpoint]\n");
    pl011_puts(&debug_uart, "offset  w  name                                    value\n");

    for (unsigned i = 0; i < nregs; i++) {
        dump_reg(bus, devfn, regs[i].offset, regs[i].width, regs[i].name);
    }

    dump_std_caps(bus, devfn);
    dump_ext_caps(bus, devfn, is_bridge);
}
