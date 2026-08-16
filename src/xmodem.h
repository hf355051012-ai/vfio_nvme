#ifndef XMODEM_H
#define XMODEM_H

#include <stdint.h>
#include "pl011.h"

// Xmodem/Xmodem-1K転送をbufferに受信する。成功時は受信バイト数、失敗時は負値。
int64_t xmodem_receive(pl011_t *u, uint8_t *buffer, uint64_t max_len);

// エラーコードを人間可読な文字列に変換する。
const char *xmodem_error_string(int64_t code);

#endif
