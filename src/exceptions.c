#include "exceptions.h"
#include "pl011.h"

extern char vector_table[];   // vectors.Sで定義
extern char _start[];         // boot.Sで定義
extern pl011_t debug_uart;    // main.cで初期化

/* [関数ポインタ] 登録先は _start(boot.S) -- フォルト回復時にこのプログラム
 * 自身の_startへ生アドレスキャストでジャンプする(下記 ((entry_fn)(uint64_t)_start)(...))。 */
typedef void (*entry_fn)(uint64_t, uint64_t);

// vector_tableをVBAR_EL2にインストールする。
void exceptions_init(void) {
    uint64_t addr = (uint64_t)vector_table;
    __asm__ volatile("msr vbar_el2, %0" : : "r"(addr));
    __asm__ volatile("isb");
}

// ベクタ番号を人間可読な名前に変換する。
static const char *vector_name(uint64_t v) {
    switch (v) {
        case 0:  return "Synchronous (current EL, SP0)";
        case 1:  return "IRQ (current EL, SP0)";
        case 2:  return "FIQ (current EL, SP0)";
        case 3:  return "SError (current EL, SP0)";
        case 4:  return "Synchronous (current EL, SPx)";
        case 5:  return "IRQ (current EL, SPx)";
        case 6:  return "FIQ (current EL, SPx)";
        case 7:  return "SError (current EL, SPx)";
        case 8:  return "Synchronous (lower EL, AArch64)";
        case 9:  return "IRQ (lower EL, AArch64)";
        case 10: return "FIQ (lower EL, AArch64)";
        case 11: return "SError (lower EL, AArch64)";
        case 12: return "Synchronous (lower EL, AArch32)";
        case 13: return "IRQ (lower EL, AArch32)";
        case 14: return "FIQ (lower EL, AArch32)";
        case 15: return "SError (lower EL, AArch32)";
        default: return "unknown vector";
    }
}

// ESR_EL2のEC(ビット[31:26])を人間可読な名前に変換する。
static const char *esr_ec_name(uint64_t esr) {
    uint32_t ec = (uint32_t)((esr >> 26) & 0x3f);
    switch (ec) {
        case 0x00: return "unknown reason";
        case 0x01: return "trapped WFI/WFE";
        case 0x0e: return "illegal execution state";
        case 0x15: return "SVC instruction";
        case 0x16: return "HVC instruction";
        case 0x17: return "SMC instruction";
        case 0x20: return "instruction abort (lower EL)";
        case 0x21: return "instruction abort (same EL)";
        case 0x22: return "PC alignment fault";
        case 0x24: return "data abort (lower EL)";
        case 0x25: return "data abort (same EL)";
        case 0x26: return "SP alignment fault";
        case 0x2f: return "SError interrupt";
        default:   return "other";
    }
}

// "label0x<16進値>\n" の形式で1行出力する。
static void print_hex_field(const char *label, uint64_t val) {
    pl011_puts(&debug_uart, label);
    pl011_hex64(&debug_uart, val);
    pl011_puts(&debug_uart, "\n");
}

// レジスタ番号を "x<番号>" の形式で出力する。
static void print_reg_index(int i) {
    pl011_puts(&debug_uart, "x");
    if (i >= 10) {
        pl011_putc(&debug_uart, (char)('0' + i / 10));
    }
    pl011_putc(&debug_uart, (char)('0' + i % 10));
}

// 例外フレームをデバッグUARTに出力し、_startへ分岐してCLIに復帰する(戻らない)。
// ハードウェアリセットではないのでPCIe/RP1の状態は保持される。
void exception_handler(exception_frame_t *f) {
    pl011_puts(&debug_uart, "\n\n*** EXCEPTION ***\n");

    pl011_puts(&debug_uart, "vector : ");
    pl011_puts(&debug_uart, vector_name(f->vector));
    pl011_puts(&debug_uart, "\n");

    print_hex_field("sp     = 0x", f->sp);
    print_hex_field("elr    = 0x", f->elr);
    print_hex_field("spsr   = 0x", f->spsr);
    print_hex_field("esr    = 0x", f->esr);

    pl011_puts(&debug_uart, "esr.EC : ");
    pl011_puts(&debug_uart, esr_ec_name(f->esr));
    pl011_puts(&debug_uart, "\n");

    print_hex_field("far    = 0x", f->far);

    for (int i = 0; i <= 30; i++) {
        print_reg_index(i);
        pl011_puts(&debug_uart, "     = 0x");
        pl011_hex64(&debug_uart, f->x[i]);
        pl011_puts(&debug_uart, "\n");
    }

    pl011_puts(&debug_uart, "*** returning to _start ***\n");

    ((entry_fn)(uint64_t)_start)(0, 0);
    while (1) { // _startは戻らないはずだが、念のため
        __asm__ volatile("wfe");
    }
}
