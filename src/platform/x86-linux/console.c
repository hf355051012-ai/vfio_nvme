#include "uart.h"

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* ------------------------------------------------------------------ */
/* 基本 I/O                                                             */
/* ------------------------------------------------------------------ */

void uart_putc(char c)
{
    putchar((unsigned char)c);
    if (c == '\n') {
        fflush(stdout);
    }
}

/*=================================================================
 * NUL 終端文字列をコンソールへ出力する。
 *
 * 引数:
 *   s - 出力する文字列
 * コール元:
 *   main(), uart_printf(), shell_editor_byte()
 * ===============================================================*/
void uart_puts(const char *s)
{
    if (!s) return;
    for (const char *p = s; *p; p++) {
        if (*p == '\n') uart_putc('\r');
        uart_putc(*p);
    }
    fflush(stdout);
}

/*=================================================================
 * 標準入力を非ブロッキングで覗き、Ctrl+C(0x03)が来ていれば消費して 1 を
 * 返す。長時間ブロックする待ちループからの中断検出に使う。
 *
 * 戻り値:
 *   1=Ctrl+C を検出した、0=何も無い
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
int uart_check_ctrl_c(void)
{
    static int inited = 0;
    if (!inited) {
        int fl = fcntl(0, F_GETFL, 0);
        if (fl != -1) {
            (void)fcntl(0, F_SETFL, fl | O_NONBLOCK);
        }
        inited = 1;
    }
    unsigned char ch;
    ssize_t n = read(0, &ch, 1);
    if (n == 1) {
        return (ch == 0x03) ? 1 : 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* uart_printf 実装 (uart_shim.c から移植、pl011/telnet 依存を除去)      */
/* ------------------------------------------------------------------ */

/* 符号なし10進をバッファに逆順で書き、桁数を返す(最大10桁) */
static int pf_fmt_uint(uint32_t val, char buf[10])
{
    int n = 0;
    if (val == 0) { buf[n++] = '0'; return n; }
    uint32_t v = val;
    while (v > 0) { buf[n++] = (char)('0' + v % 10); v /= 10; }
    return n;
}

/* 符号なし16進をバッファに逆順で書き、桁数を返す(最大8桁) */
static int pf_fmt_hex(uint32_t val, int upper, char buf[8])
{
    const char *hex = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int n = 0;
    if (val == 0) { buf[n++] = '0'; return n; }
    uint32_t v = val;
    while (v > 0) { buf[n++] = hex[v & 0xF]; v >>= 4; }
    return n;
}

/* 逆順バッファをパディング付きで出力(left=1 で左詰め) */
static void pf_emit(char *buf, int n, char pad, int width, int left)
{
    if (!left)
        for (int i = n; i < width; i++) uart_putc(pad);
    for (int i = n - 1; i >= 0; i--) uart_putc(buf[i]);
    if (left)
        for (int i = n; i < width; i++) uart_putc(' ');
}

void uart_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    while (*fmt) {
        if (*fmt != '%') {
            if (*fmt == '\n') uart_putc('\r');
            uart_putc(*fmt++);
            continue;
        }
        fmt++;  /* '%' を読み飛ばす */

        int  left  = 0;
        char pad   = ' ';
        int  width = 0;

        if (*fmt == '-') { left = 1; fmt++; }
        if (*fmt == '0' && !left) { pad = '0'; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }

        int precision = -1;
        if (*fmt == '.') {
            fmt++;
            if (*fmt == '*') {
                precision = va_arg(ap, int);
                fmt++;
            } else {
                precision = 0;
                while (*fmt >= '0' && *fmt <= '9') { precision = precision * 10 + (*fmt - '0'); fmt++; }
            }
        }

        if (*fmt == 'l') fmt++;  /* long 修飾子は読み飛ばす */

        char buf[10];
        int  n;

        switch (*fmt) {
        case 'd': case 'i': {
            int32_t v = (int32_t)va_arg(ap, int);
            if (v < 0) {
                uart_putc('-');
                if (width > 1) width--;
                n = pf_fmt_uint((uint32_t)(-v), buf);
            } else {
                n = pf_fmt_uint((uint32_t)v, buf);
            }
            pf_emit(buf, n, pad, width, left);
            break;
        }
        case 'u':
            n = pf_fmt_uint((uint32_t)va_arg(ap, unsigned int), buf);
            pf_emit(buf, n, pad, width, left);
            break;
        case 'x':
            n = pf_fmt_hex((uint32_t)va_arg(ap, unsigned int), 0, buf);
            pf_emit(buf, n, pad, width, left);
            break;
        case 'X':
            n = pf_fmt_hex((uint32_t)va_arg(ap, unsigned int), 1, buf);
            pf_emit(buf, n, pad, width, left);
            break;
        case 'p': {
            uart_puts("0x");
            uintptr_t v = (uintptr_t)va_arg(ap, void *);
            n = pf_fmt_hex((uint32_t)v, 1, buf);
            pf_emit(buf, n, '0', 8, 0);
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            int len = 0;
            const char *t = s;
            while (*t && (precision < 0 || len < precision)) { t++; len++; }
            if (!left)
                for (int i = len; i < width; i++) uart_putc(' ');
            for (int i = 0; i < len; i++) uart_putc(s[i]);
            if (left)
                for (int i = len; i < width; i++) uart_putc(' ');
            break;
        }
        case 'c':
            uart_putc((char)va_arg(ap, int));
            break;
        case '%':
            uart_putc('%');
            break;
        default:
            uart_putc('%');
            uart_putc(*fmt);
            break;
        }
        fmt++;
    }

    va_end(ap);
    fflush(stdout);
}
