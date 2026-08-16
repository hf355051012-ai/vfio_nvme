// UART経由のファームウェア更新。

#include "fwupdate.h"
#include "board.h"
#include "pl011.h"
#include "xmodem.h"
#include "cache.h"

extern pl011_t debug_uart; // main.cで定義
extern char _start[]; // 現在実行中のこのイメージの開始アドレス

/* [関数ポインタ] 具体的な登録先関数は無い -- チェインロードしたイメージの
 * エントリ(LOAD_ADDR先頭=そのイメージの_start、boot.S)へ生アドレスキャストで
 * ジャンプするためのもの(下記 ((entry_fn)addr)(...) 参照)。 */
typedef void (*entry_fn)(uint64_t, uint64_t);

// fwupdate.h参照。
void fwupdate_jump_to_image(uint64_t addr, uint64_t len, uint64_t magic) {
    sync_icache_range((void *)addr, len);
    ((entry_fn)addr)(0, magic);
    while (1) { // ロードしたイメージが戻ってきた場合のみここに到達
        __asm__ volatile("wfe");
    }
}

// 新しいファームウェアイメージをUART経由で受信し、実行する。
void fwupdate_run(void) {
    uint64_t here = (uint64_t)_start;

    if (here != PRIMARY_BASE) {
        // チェインロードされたペイロードから動作中 -- プライマリへ戻って更新する。
        pl011_puts(&debug_uart, "\nfwupdate: not running from the primary image -- "
                                 "returning there to update (peripheral state is preserved)...\n");
        fwupdate_jump_to_image(PRIMARY_BASE, 0, FWUPDATE_AUTO_MAGIC);
    }

    pl011_puts(&debug_uart, "\nfwupdate: waiting for Xmodem sender (Ctrl-X Ctrl-X to abort)...\n");

    int64_t n = xmodem_receive(&debug_uart, (uint8_t *)LOAD_ADDR, LOAD_MAX_SIZE);
    if (n < 0) {
        pl011_puts(&debug_uart, "fwupdate: failed - ");
        pl011_puts(&debug_uart, xmodem_error_string(n));
        pl011_puts(&debug_uart, "\n");
        return;
    }

    pl011_puts(&debug_uart, "fwupdate: received ");
    pl011_udec64(&debug_uart, (uint64_t)n);
    pl011_puts(&debug_uart, " bytes at 0x");
    pl011_hex64(&debug_uart, LOAD_ADDR);
    pl011_puts(&debug_uart, ", jumping now.\n");

    fwupdate_jump_to_image(LOAD_ADDR, (uint64_t)n, 0);
}
