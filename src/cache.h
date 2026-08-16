#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

static inline void dcache_clean_range(const void *start, uint64_t len) {
    (void)start; (void)len;
    __asm__ volatile("" ::: "memory");
}

static inline void dcache_invalidate_range(const void *start, uint64_t len) {
    (void)start; (void)len;
    __asm__ volatile("" ::: "memory");
}

#endif /* CACHE_H */
