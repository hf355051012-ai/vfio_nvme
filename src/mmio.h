#ifndef MMIO_H
#define MMIO_H

#include <stdint.h>

// 32ビットMMIOレジスタへの読み書き。
static inline void mmio_write32(uint64_t addr, uint32_t val) {
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr) {
    return *(volatile uint32_t *)addr;
}

static inline void mmio_write64(uint64_t addr, uint64_t val) {
    *(volatile uint64_t *)addr = val;
}

#define dma_wmb() __asm__ volatile("mfence" ::: "memory")

#endif
