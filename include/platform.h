#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>

typedef struct {
    void    *cpu; /* CPU-visible address (for CPU reads/writes) */
    uint64_t dev; /* device/DMA address (programmed into descriptors) */
} dma_region_t;

typedef enum {
    DMA_DEVICE = 0,
    DMA_COHERENT = 1,
} dma_kind_t;

dma_region_t dma_alloc(uint64_t size, uint64_t align, dma_kind_t kind);

void dma_free(dma_region_t region);

#endif /* PLATFORM_H */
