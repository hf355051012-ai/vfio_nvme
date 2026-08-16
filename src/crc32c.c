#include "crc32c.h"

#if defined(__x86_64__)
#include <nmmintrin.h>
#define CRC32C_U8(crc, v)  ((uint32_t)_mm_crc32_u8((crc), (v)))
#define CRC32C_U32(crc, v) ((uint32_t)_mm_crc32_u32((crc), (v)))
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
