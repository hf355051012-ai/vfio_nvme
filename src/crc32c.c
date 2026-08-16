#include "crc32c.h"

#if defined(__x86_64__)
#include <nmmintrin.h>
#define CRC32C_U8(crc, v)  ((uint32_t)_mm_crc32_u8((crc), (v)))
#define CRC32C_U32(crc, v) ((uint32_t)_mm_crc32_u32((crc), (v)))
#define CRC32C_U64(crc, v) ((uint32_t)_mm_crc32_u64((uint64_t)(crc), (v)))
#else
#error "crc32c: no hardware CRC32C backend for this architecture"
#endif

/*
 * CRC-32C(Castagnoli)を SSE4.2 のハードウェア命令で計算する。ポインタの
 * 実アライメントを見て 8/4/1 バイト単位を切り替える(ワイヤバッファ由来で
 * 任意にアラインされうるため)。返すのは「実行中の生 CRC 値」で、最終
 * ダイジェストにするには呼び出し側が ~ を取る。
 *
 * 引数:
 *   crc  - 継続値。先頭では 0xFFFFFFFF を渡す
 *   data - 対象バイト列
 *   len  - バイト数
 * 戻り値:
 *   len バイト分を取り込んだ後の生 CRC 値
 * コール元:
 *   nvmet_tcp_append_hdgst(), nvmet_tcp_append_ddgst(),
 *   nvmet_tcp_verify_hdgst(), nvmet_tcp_verify_ddgst(), crc32c_selftest()
 */
uint32_t crc32c(uint32_t crc, const volatile void *data, size_t len)
{
    const volatile uint8_t *p = (const volatile uint8_t *)data;
    if (!p) return crc;

    size_t i = 0;

    if (((uintptr_t)p & 7u) == 0) {
        for (; i + 8 <= len; i += 8) {
            uint64_t v = *(const volatile uint64_t *)(p + i);
            crc = CRC32C_U64(crc, v);
        }
    } else if (((uintptr_t)p & 3u) == 0) {
        for (; i + 4 <= len; i += 4) {
            uint32_t v = *(const volatile uint32_t *)(p + i);
            crc = CRC32C_U32(crc, v);
        }
    }

    for (; i < len; i++) {
        crc = CRC32C_U8(crc, p[i]);
    }

    return crc;
}
