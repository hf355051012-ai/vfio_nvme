#ifndef CRC32C_H
#define CRC32C_H

#include <stdint.h>
#include <stddef.h>

uint32_t crc32c(uint32_t crc, const volatile void *data, size_t len);

#endif /* CRC32C_H */
