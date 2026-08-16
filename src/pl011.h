#ifndef PL011_H
#define PL011_H

#include <stdint.h>

typedef struct {
    uint64_t base;
} pl011_t;

// UARTを初期化する(ボーレート、8N1、FIFO有効化)。
void pl011_init(pl011_t *u, uint64_t base, uint32_t uart_clk_hz, uint32_t baud);
// 1文字送信する。
void pl011_putc(pl011_t *u, char c);
// 文字列を送信する("\n"は"\r\n"に変換される)。
void pl011_puts(pl011_t *u, const char *s);
// 32ビット値を16進数で送信する。
void pl011_hex32(pl011_t *u, uint32_t val);
// 64ビット値を16進数で送信する。
void pl011_hex64(pl011_t *u, uint64_t val);
// 64ビット値を10進数で送信する。
void pl011_udec64(pl011_t *u, uint64_t val);
// 未読バイトがあるかを返す。
int pl011_tstc(pl011_t *u);
// 1文字受信する(届くまでブロックする)。
char pl011_getc(pl011_t *u);
// timeout_val_ms以内に受信できれば0-255、届かなければ-1を返す。
int pl011_getc_timeout(pl011_t *u, uint32_t timeout_val_ms);

// 出力タップ: pl011_putc()で実際に送信される全バイトのコピーを受け取る
// フック(telnet.c参照 -- シリアルコンソール出力をネットワーク越しにも
// 鏡映するために使う)。同時に1個までしか登録できない(このプロジェクトに
// pl011_tインスタンスはdebug_uart一つしか無いため、複数フック機構は
// 過剰、main.c参照)。fnにNULLを渡すと解除できる。
typedef void (*pl011_tap_fn)(char c);
void pl011_set_tap(pl011_tap_fn fn);

/* コアをまたいだUART出力の排他制御(マルチコア化 Phase 5、
 * ~/.claude/plans/wondrous-baking-gadget.md参照)。「1回の論理的な出力
 * 単位」(uart_printf()の1呼び出し全体等)を組み立てる側が、その最初と
 * 最後でこのペアを呼ぶ -- pl011_putc()/pl011_puts()等の下位プリミティブ
 * 自体はロックしない(詳細はpl011.cのコメント参照)。
 * 例外ハンドラ(exceptions.c)は意図的にこのロックを一切使わない
 * (デッドロック回避のため、pl011.c参照) -- 例外経路のコードは変更不要。 */
void pl011_lock(void);
void pl011_unlock(void);

/* core1がsecondary_main()の中で(mmu_init_secondary()の直後)1回呼ぶ。
 * core1が例外リカバリ経由でロック保持状態のまま再入した場合の恒久
 * デッドロック(システム全体のUART出力停止)を防ぐための強制リセット。
 * 詳細はpl011.cのコメント参照。 */
void pl011_lock_reset(void);

#endif
