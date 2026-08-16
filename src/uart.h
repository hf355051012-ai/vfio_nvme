#ifndef UART_H
#define UART_H

/*
 * uart.h — Pi4 TCP/IP スタックとの互換レイヤ
 *
 * TCPIP プロジェクトのネットワークスタック (arp.c / ip.c / icmp.c 等) は
 * uart_printf / uart_puts / uart_putc に依存している。
 * rpi5-boot ではこれらを debug_uart (pl011_t) 経由で実装する。
 * 実装は uart_shim.c にある。
 */

#include <stdarg.h>
#include <stdint.h>

/* 書式出力 (%d %u %x %X %p %s %c %%, 幅/ゼロパディング/-フラグ対応) */
void uart_printf(const char *fmt, ...);

/* 文字列出力 (\n は \r\n に変換) */
void uart_puts(const char *s);

/* 1文字出力 */
void uart_putc(char c);

/* 受信FIFOに待機中のバイトが無ければ即座に0を返す(非ブロッキング)。
 * バイトがあれば1個だけ読み出し(FIFOから消費する -- ハードウェアの
 * データレジスタは読むと消える性質上、消費せず覗き見ることはできない)、
 * それがCtrl+C(0x03, ASCII ETX)なら1を返す。それ以外の文字だった場合は
 * 読み捨てる(このプロジェクトのシェルは長時間ブロックするコマンド実行中
 * に先読みバッファを持たないため、Ctrl+C以外のキー入力はここで失われる
 * -- 長時間コマンドの実行中は「次のコマンドを先行入力する」用途は元々
 * 想定していない)。
 * tcp_poll_once()(tcp.c)から毎回呼ばれ、長時間ブロックする一連の待ち
 * ループ(nvmet_run()等)にCtrl+Cでの中断手段を提供する
 * (tcp.hのtcp_abort_requested()参照)。 */
int uart_check_ctrl_c(void);

#endif /* UART_H */
