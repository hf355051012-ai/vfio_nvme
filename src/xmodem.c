// Xmodem/Xmodem-CRC受信側。

#include "xmodem.h"

#define SOH 0x01
#define STX 0x02
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CAN 0x18

#define BYTE_TIMEOUT_MS 2000
#define MAX_CONSEC_ERRORS 10

// CRC-16/CCITTを計算する。
static uint16_t crc16_ccitt(const uint8_t *data, uint32_t len) {
    uint16_t crc = 0;
    for (uint32_t i = 0; i < len; i++) {
        crc = (uint16_t)(crc ^ ((uint16_t)data[i] << 8));
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

// pl011_getc_timeout()への薄いラッパー。
static int recv_byte(pl011_t *u, uint32_t timeout_ms) {
    return pl011_getc_timeout(u, timeout_ms);
}

// Xmodem/Xmodem-1K転送をbufferに受信する。
int64_t xmodem_receive(pl011_t *u, uint8_t *buffer, uint64_t max_len) {
    uint8_t block_buf[1024];
    uint8_t expected = 1;
    uint64_t total = 0;
    int use_crc = 1;
    int errors = 0;
    int c = -1;

    // CRCモードを要求し、応答がなければ途中でチェックサムモードに切り替える。
    for (int attempt = 0; attempt < 20 && c < 0; attempt++) {
        pl011_putc(u, use_crc ? 'C' : NAK);
        c = recv_byte(u, 1000);
        if (c < 0 && attempt == 9) {
            use_crc = 0;
        }
    }
    if (c < 0) {
        return -1; // 誰も送信を開始しなかった
    }

    while (1) {
        if (c == EOT) {
            pl011_putc(u, ACK);
            return (int64_t)total;
        }
        if (c == CAN) {
            return -2; // 送信側がキャンセルした
        }

        int ok = (c == SOH || c == STX);
        uint32_t block_size = (c == STX) ? 1024u : 128u;
        int blk = -1;

        if (ok) {
            int blk_inv;
            blk = recv_byte(u, BYTE_TIMEOUT_MS);
            blk_inv = recv_byte(u, BYTE_TIMEOUT_MS);
            ok = (blk >= 0 && blk_inv >= 0 && ((blk ^ blk_inv) & 0xff) == 0xff);
        }

        if (ok) {
            for (uint32_t i = 0; i < block_size; i++) {
                int d = recv_byte(u, BYTE_TIMEOUT_MS);
                if (d < 0) {
                    ok = 0;
                    break;
                }
                block_buf[i] = (uint8_t)d;
            }
        }

        if (ok) {
            if (use_crc) {
                int hi = recv_byte(u, BYTE_TIMEOUT_MS);
                int lo = recv_byte(u, BYTE_TIMEOUT_MS);
                ok = (hi >= 0 && lo >= 0 &&
                      (uint16_t)((hi << 8) | lo) == crc16_ccitt(block_buf, block_size));
            } else {
                int cksum = recv_byte(u, BYTE_TIMEOUT_MS);
                uint8_t sum = 0;
                for (uint32_t i = 0; i < block_size; i++) {
                    sum = (uint8_t)(sum + block_buf[i]);
                }
                ok = (cksum >= 0 && sum == (uint8_t)cksum);
            }
        }

        if (ok && blk == (int)expected) {
            if (total + block_size > max_len) {
                pl011_putc(u, CAN);
                pl011_putc(u, CAN);
                return -4; // 転送先バッファを超えてしまう
            }
            for (uint32_t i = 0; i < block_size; i++) {
                buffer[total + i] = block_buf[i];
            }
            total += block_size;
            expected = (uint8_t)(expected + 1);
            errors = 0;
            pl011_putc(u, ACK);
        } else if (ok && blk == (int)(uint8_t)(expected - 1)) {
            pl011_putc(u, ACK); // 既に受信済みのブロックの再送
        } else {
            errors++;
            if (errors >= MAX_CONSEC_ERRORS) {
                pl011_putc(u, CAN);
                pl011_putc(u, CAN);
                return -3; // 連続エラーが多すぎたので諦める
            }
            pl011_putc(u, NAK);
        }

        c = recv_byte(u, BYTE_TIMEOUT_MS);
    }
}

// エラーコードを人間可読な文字列に変換する。
const char *xmodem_error_string(int64_t code) {
    switch (code) {
        case -1: return "no sender responded (timed out waiting for start)";
        case -2: return "cancelled by sender";
        case -3: return "too many consecutive errors, gave up";
        case -4: return "transfer exceeded destination buffer size";
        default: return "unknown error";
    }
}
