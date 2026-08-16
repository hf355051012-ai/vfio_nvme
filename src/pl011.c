// 汎用ARM PrimeCell PL011 UARTドライバ(ポーリング方式)。

#include "pl011.h"
#include "mmio.h"
#include "timer.h"
#include "smp.h"

#define PL011_DR    0x00
#define PL011_FR    0x18
#define PL011_IBRD  0x24
#define PL011_FBRD  0x28
#define PL011_LCRH  0x2c
#define PL011_CR    0x30
#define PL011_IFLS  0x34
#define PL011_IMSC  0x38
#define PL011_ICR   0x44

#define PL011_FR_BUSY   (1u << 3)
#define PL011_FR_RXFE   (1u << 4)
#define PL011_FR_TXFF   (1u << 5)

#define PL011_LCRH_FEN       (1u << 4)
#define PL011_LCRH_WLEN_8BIT (3u << 5)

#define PL011_CR_UARTEN (1u << 0)
#define PL011_CR_TXE    (1u << 8)
#define PL011_CR_RXE    (1u << 9)

// UARTを初期化する(ボーレート、8N1、FIFO有効化)。
void pl011_init(pl011_t *u, uint64_t base, uint32_t uart_clk_hz, uint32_t baud) {
    u->base = base;

    // BUSY中にUARTENをクリアすると送信中の文字が途切れるので先に待つ。
    while (mmio_read32(base + PL011_FR) & PL011_FR_BUSY) {
    }

    mmio_write32(base + PL011_CR, 0);

    uint32_t lcrh = mmio_read32(base + PL011_LCRH);
    mmio_write32(base + PL011_LCRH, lcrh & ~PL011_LCRH_FEN);

    // ボーレート除数 = UARTCLK / (16 * baud)
    uint32_t div_x64 = (uint32_t)(((uint64_t)uart_clk_hz * 4) / baud);
    mmio_write32(base + PL011_IBRD, div_x64 / 64);
    mmio_write32(base + PL011_FBRD, div_x64 % 64);

    mmio_write32(base + PL011_LCRH, PL011_LCRH_WLEN_8BIT | PL011_LCRH_FEN);

    mmio_write32(base + PL011_IMSC, 0);
    mmio_write32(base + PL011_ICR, 0x7ff);

    mmio_write32(base + PL011_CR, PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE);
}

static pl011_tap_fn s_tap = 0;

void pl011_set_tap(pl011_tap_fn fn) {
    s_tap = fn;
}

// 1文字送信する。
void pl011_putc(pl011_t *u, char c) {
    while (mmio_read32(u->base + PL011_FR) & PL011_FR_TXFF) {
    }
    mmio_write32(u->base + PL011_DR, (uint32_t)(uint8_t)c);
    if (s_tap) {
        s_tap(c);
    }
}

// 文字列を送信する("\n"は"\r\n"に変換)。
void pl011_puts(pl011_t *u, const char *s) {
    while (*s) {
        if (*s == '\n') {
            pl011_putc(u, '\r');
        }
        pl011_putc(u, *s++);
    }
}

// 0-15を16進数字1文字に変換する。
static char hex_digit(uint32_t nibble) {
    return (char)(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));
}

// 32ビット値を16進数で送信する。
void pl011_hex32(pl011_t *u, uint32_t val) {
    for (int shift = 28; shift >= 0; shift -= 4) {
        pl011_putc(u, hex_digit((val >> shift) & 0xf));
    }
}

// 64ビット値を16進数で送信する。
void pl011_hex64(pl011_t *u, uint64_t val) {
    for (int shift = 60; shift >= 0; shift -= 4) {
        pl011_putc(u, hex_digit((uint32_t)((val >> shift) & 0xf)));
    }
}

// 未読バイトがあるかを返す。
int pl011_tstc(pl011_t *u) {
    return !(mmio_read32(u->base + PL011_FR) & PL011_FR_RXFE);
}

// 1文字受信する(届くまでブロックする)。
char pl011_getc(pl011_t *u) {
    while (mmio_read32(u->base + PL011_FR) & PL011_FR_RXFE) {
    }
    return (char)(mmio_read32(u->base + PL011_DR) & 0xff);
}

// timeout_val_ms以内に受信できれば0-255、届かなければ-1を返す。
int pl011_getc_timeout(pl011_t *u, uint32_t timeout_val_ms) {
    uint64_t start = timer_now();
    while (!pl011_tstc(u)) {
        if (timeout_ms(start, timeout_val_ms)) {
            return -1;
        }
    }
    return (int)(uint8_t)mmio_read32(u->base + PL011_DR);
}

// 64ビット値を10進数で送信する。
void pl011_udec64(pl011_t *u, uint64_t val) {
    char buf[20];
    int i = 0;

    if (val == 0) {
        pl011_putc(u, '0');
        return;
    }
    while (val > 0) {
        buf[i++] = (char)('0' + (val % 10));
        val /= 10;
    }
    while (i > 0) {
        pl011_putc(u, buf[--i]);
    }
}

/* ================================================================
 * コアをまたいだUART出力の排他制御(マルチコア化 Phase 5、
 * ~/.claude/plans/wondrous-baking-gadget.md参照)。
 *
 * pl011_putc()/pl011_puts()/pl011_hex32()/pl011_hex64()/pl011_udec64()
 * 自体は意図的にこのロックを一切使わない(下位のハードウェア直叩き
 * プリミティブのまま) -- ロックを取るのは「1回の論理的な出力単位
 * (uart_printf()の1呼び出し全体等)」を組み立てる側の責務にする。
 * これにより:
 * (1) pl011_puts()等を内部で複数回呼ぶ上位関数(uart_printf())が、
 *     自分の呼び出しの先頭でロックし末尾で解放するだけで済み、内部の
 *     個々のpl011_putc()呼び出しで再帰的にロックを取ろうとして自己
 *     デッドロックする心配が無い。
 * (2) exceptions.c(例外ハンドラ)はpl011_puts()/pl011_hex64()を
 *     これまで通り直接呼ぶだけで、このロックを一切経由しない(意図的な
 *     設計 -- 他コアがロックを保持したまま何らかの理由で進行不能に
 *     なっていても、例外ダンプの出力だけは確実に行える。計画のPhase 5
 *     節「例外ハンドラ経由の出力はロックを無視して強制出力する」に
 *     対応)。exceptions.c側のコード変更は一切不要。
 * ================================================================ */
static smp_spinlock_t s_uart_lock;

void pl011_lock(void)
{
    smp_spin_lock(&s_uart_lock);
}

void pl011_unlock(void)
{
    smp_spin_unlock(&s_uart_lock);
}

/* core1がsecondary_main()の中で(mmu_init_secondary()の直後、smp.c参照)
 * 1回呼ぶ。core1がこのロックを保持したまま例外を起こしsecondary_entry
 * (boot.S)へ再入した場合、secondary_entryはcore0のprimary_coreとは
 * 異なり`.bss`をゼロクリアしない(マルチコア化 Phase 2「実機で踏んだ罠」
 * 節参照)ため、このロックが「保持されたまま」取り残されうる -- 放置
 * すると、以後core0がuart_printf()を呼ぶたびにこのロックの解放を
 * 永久に待ち続け、core1側の1回の例外がシステム全体のUART出力を道連れに
 * 恒久停止させるという重大な退行になる。secondary_main()の再入
 * (通常のcpuon初回起動、または例外リカバリ後の再入のいずれも)のたびに
 * 無条件でロックを未保持状態へリセットすることで、この経路を断つ。
 * 実装はpl011_unlock()と同一(smp_spin_unlock()は現在の保持者を
 * 確認せず無条件に0を書き込む設計のため、そのまま「強制リセット」
 * として使える)だが、呼び出し側の意図(解放ではなくリセット)を
 * コードで自己文書化するため別名の関数にしてある。 */
void pl011_lock_reset(void)
{
    smp_spin_unlock(&s_uart_lock);
}
