// uart_shim.c
//
// Pi4 TCP/IP スタック互換レイヤ
//
// TCPIP プロジェクトのネットワークスタック (arp.c / ip.c / icmp.c 等) は
// uart_printf / uart_puts / uart_putc を使ってデバッグ出力する。
// rpi5-boot ではこれらを main.c で定義されている debug_uart (pl011_t) に
// ブリッジして実装する。
//
// uart_printf の実装は TCPIP/src/uart.c の pf_fmt_uint / pf_fmt_hex /
// pf_emit / uart_printf をそのまま移植したもの。元コードの全関数は
// uart_putc を経由しているため、uart_putc を pl011_putc に差し替えるだけで
// 動作する。

#include "uart.h"
#include "pl011.h"
#include "telnet.h"
#include <stdint.h>
#include <stdarg.h>

// main.c で定義されているグローバルコンソール
extern pl011_t debug_uart;

/* ------------------------------------------------------------------ */
/* 基本 I/O                                                             */
/* ------------------------------------------------------------------ */

void uart_putc(char c)
{
    /* マルチコア化(telnetのコアごと分離、~/.claude/plans/wondrous-
     * baking-gadget.md参照): telnet.cのインスタンス1がdispatch()実行中
     * だけ、telnet_output_redirect_begin()でこのリダイレクトを有効化する。
     * 有効な間は物理UARTに一切触れない(ロックも取らない、pl011_set_tap()
     * 経由のミラーリングも発生しない -- インスタンス1は物理UARTから
     * 完全に独立した出力先を持つ、ユーザー指示「print文も完全に独立」)。 */
    if (telnet_output_redirect_putc(c)) {
        return;
    }
    pl011_putc(&debug_uart, c);
}

int uart_check_ctrl_c(void)
{
    if (!pl011_tstc(&debug_uart)) {
        return 0;
    }
    char c = pl011_getc(&debug_uart);  /* tstc()で確認済みなのでブロックしない */
    return (c == 0x03) ? 1 : 0;
}

void uart_puts(const char *s)
{
    pl011_puts(&debug_uart, s);
}

/* ------------------------------------------------------------------ */
/* uart_printf 実装 (TCPIP/src/uart.c から移植)                         */
/* ------------------------------------------------------------------ */

/* 符号なし10進をバッファに逆順で書き、桁数を返す（最大10桁） */
static int pf_fmt_uint(uint32_t val, char buf[10])
{
    int n = 0;
    if (val == 0) { buf[n++] = '0'; return n; }
    uint32_t v = val;
    while (v > 0) { buf[n++] = (char)('0' + v % 10); v /= 10; }
    return n;
}

/* 符号なし16進をバッファに逆順で書き、桁数を返す（最大8桁） */
static int pf_fmt_hex(uint32_t val, int upper, char buf[8])
{
    const char *hex = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int n = 0;
    if (val == 0) { buf[n++] = '0'; return n; }
    uint32_t v = val;
    while (v > 0) { buf[n++] = hex[v & 0xF]; v >>= 4; }
    return n;
}

/* 逆順バッファをパディング付きで出力（left=1 で左詰め） */
static void pf_emit(char *buf, int n, char pad, int width, int left)
{
    if (!left)
        for (int i = n; i < width; i++) uart_putc(pad);
    for (int i = n - 1; i >= 0; i--) uart_putc(buf[i]);
    if (left)
        for (int i = n; i < width; i++) uart_putc(' ');
}

/*
 * uart_printf — 書式出力
 * 対応指定子: %d %i %u %x %X %p %s %c %%
 * 幅指定・ゼロパディング・左詰め(-フラグ)に対応。
 * %l 修飾子は読み飛ばす (引数は 32bit として扱う)。
 * %s は精度指定(".N"または可変引数から取る".*")に対応 -- 呼び出し側
 * バッファがNUL終端されていない/されているか不明な部分文字列を渡す
 * 用途(例: command.cのcmd_help()、コマンド名の長さだけを表示する)。
 */
void uart_printf(const char *fmt, ...)
{
    /* マルチコア化 Phase 5(~/.claude/plans/wondrous-baking-gadget.md
     * 参照): この呼び出し全体を1つのアトミックな出力単位として扱う --
     * 他コア(core1)からの並行出力(smp.cのsecondary_main()末尾メッセージ
     * 等)がこの呼び出しの途中に割り込んで文字が混線しないようにする
     * (pl011.cのpl011_lock()コメント参照)。内部で何度も呼ぶ
     * uart_putc()自体はロックしない(自己デッドロック防止)。
     *
     * telnetのコアごと分離(2026-08-08): telnet_output_redirect_active()
     * が真の間(telnet.cのインスタンス1がdispatch()実行中)は、この呼び出し
     * 全体が物理UARTに一切触れない(uart_putc()参照)ため、pl011_lock()も
     * 取得しない -- 物理UARTのロックを共有すること自体が「print文が
     * 完全に独立」という要件と矛盾するため、意図的にスキップする。 */
    int redirected = telnet_output_redirect_active();
    if (!redirected) {
        pl011_lock();
    }

    va_list ap;
    va_start(ap, fmt);

    while (*fmt) {
        if (*fmt != '%') {
            if (*fmt == '\n') uart_putc('\r');
            uart_putc(*fmt++);
            continue;
        }
        fmt++;  /* '%' を読み飛ばす */

        /* ---- フラグ解析 ---- */
        int  left  = 0;
        char pad   = ' ';
        int  width = 0;

        if (*fmt == '-') { left = 1; fmt++; }
        if (*fmt == '0' && !left) { pad = '0'; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }

        /* ---- 精度指定(".N"または".*") ----
         * -1は「精度指定なし」を意味する(%sでは文字列全体をNUL終端まで
         * 出力)。'*'の場合は幅指定と同じく可変引数から取る -- 呼び出し側の
         * 引数順は printf標準と同じく「精度の数値」→「本体の引数」。 */
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

        /* ---- 変換指定子 ---- */
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
    if (!redirected) {
        pl011_unlock();
    }
}
