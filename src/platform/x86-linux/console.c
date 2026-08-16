// platform/x86-linux/console.c
//
// コンソール(uart.h 契約)の x86-linux 実装(x86-vfio-port Phase 3、
// ~/.claude/plans/x86-vfio-port.md §3 参照)。RPi5 の PL011 UART(uart_shim.c)
// に相当する層で、core(arp/ip/icmp/tcp/nvme*/mlx5* 等)が使う
// uart_printf/uart_puts/uart_putc/uart_check_ctrl_c を stdout/stdin へ橋渡し
// する。書式出力ロジック(pf_fmt_uint/pf_fmt_hex/pf_emit/uart_printf)は
// uart_shim.c から移植(元コードは全て uart_putc を経由するので、uart_putc を
// stdout へ差し替えるだけで動く)。RPi5 側の telnet リダイレクト/pl011_lock は
// 持たない(x86 は当面単一プロセスのコンソール)。

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
    /* stdout へ 1 バイト。低頻度なので都度 flush して、パニック/長待ちの
     * 直前でもログが確実に見えるようにする(RPi5 の PL011 が同期出力なのと
     * 同じ「出したら必ず見える」性質を保つ)。 */
    putchar((unsigned char)c);
    if (c == '\n') {
        fflush(stdout);
    }
}

void uart_puts(const char *s)
{
    /* RPi5 の pl011_puts() は '\n' を '\r\n' に変換する。忠実に踏襲する
     * (POSIX tty でも余分な CR は無害、Phase 4 で RPi5 ログと突き合わせる
     * ときに出力が一致していると比較しやすい)。 */
    if (!s) return;
    for (const char *p = s; *p; p++) {
        if (*p == '\n') uart_putc('\r');
        uart_putc(*p);
    }
    fflush(stdout);
}

int uart_check_ctrl_c(void)
{
    /* 非ブロッキングで stdin から 1 バイト読み、Ctrl+C(0x03)なら 1。
     * cooked tty では端末が Ctrl+C を SIGINT に変換してしまうため実際には
     * 0x03 が届かないことが多いが、raw モードやパイプ入力では機能する。
     * core(tcp_poll_once)の長時間待ちループ用の中断手段(uart.h 参照)。 */
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

/*
 * uart_printf — 書式出力(uart_shim.c と同一仕様)。
 * 対応指定子: %d %i %u %x %X %p %s %c %%、幅/ゼロパディング/左詰め、
 * %.N / %.* 精度、%l 修飾子読み飛ばし。
 */
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
