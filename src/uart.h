#ifndef UART_H
#define UART_H

#include <stdarg.h>
#include <stdint.h>

/* 書式出力 (%d %u %x %X %p %s %c %%, 幅/ゼロパディング/-フラグ対応) */
void uart_printf(const char *fmt, ...);

/* 文字列出力 (\n は \r\n に変換) */
void uart_puts(const char *s);

/* 1文字出力 */
void uart_putc(char c);

int uart_check_ctrl_c(void);

#endif /* UART_H */
