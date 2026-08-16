// crc32c.c
//
// CRC32C(Castagnoli多項式)のハードウェア計算(ARMv8 CRC32命令)。
// net.hのvolatile_fast_copy()/checksum_accumulate()と同じ「実行時に
// アライメントを見て、揃っていればワイドアクセス、揃っていなければ
// バイト単位にフォールバック」の方針を踏襲する — dataはNVMe/TCPの
// ワイヤバッファ(任意にアラインされうる)を指すことがあるため。

#include "crc32c.h"

/* CRC32C(Castagnoli 多項式)のハードウェア命令バックエンドを arch ごとに
 * 選ぶ(x86-vfio-port Phase 3、~/.claude/plans/x86-vfio-port.md §3)。
 *   - aarch64: ARMv8 CRC32 命令(__builtin_aarch64_crc32c{b,w,x})。
 *   - x86-64 : SSE4.2 CRC32 命令(_mm_crc32_u{8,32,64}、nmmintrin.h、
 *              -msse4.2)。SSE4.2 の CRC32 は Castagnoli 多項式そのものなので
 *              直接対応する(§4-6)。
 * どちらも「実行中の生 CRC 値」を返す規約は同一(最終反転は呼び出し側、
 * crc32c.h 参照)。ワイド/バイト単位のアライメント分岐ロジックも共通。 */
#if defined(__aarch64__)
#define CRC32C_U8(crc, v)  ((uint32_t)__builtin_aarch64_crc32cb((crc), (v)))
#define CRC32C_U32(crc, v) ((uint32_t)__builtin_aarch64_crc32cw((crc), (v)))
#define CRC32C_U64(crc, v) ((uint32_t)__builtin_aarch64_crc32cx((crc), (v)))
#elif defined(__x86_64__)
#include <nmmintrin.h>
#define CRC32C_U8(crc, v)  ((uint32_t)_mm_crc32_u8((crc), (v)))
#define CRC32C_U32(crc, v) ((uint32_t)_mm_crc32_u32((crc), (v)))
/* _mm_crc32_u64 は 64bit crc を取り 64bit を返すが、上位はゼロ拡張された
 * 32bit CRC。crc を uint64_t へ渡し、結果の下位32bitを使う。 */
#define CRC32C_U64(crc, v) ((uint32_t)_mm_crc32_u64((uint64_t)(crc), (v)))
#else
#error "crc32c: no hardware CRC32C backend for this architecture"
#endif

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
