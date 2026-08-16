#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

/* ================================================================
 * DMA キャッシュコヒーレンシの HAL 契約。呼び出し規約は
 *   clean      = CPU 書込 -> デバイスから可視化
 *   invalidate = デバイス書込 -> CPU から可読化
 * x86 は DMA コヒーレントなので実体は no-op(コンパイラバリアのみ)。
 * core 側(mlx5_net/nvmet_rdma/netif 等)は非コヒーレントな環境へ移植
 * したときにそのまま動くよう、呼び出し自体は残してある。
 * ================================================================ */

static inline void dcache_clean_range(const void *start, uint64_t len) {
    (void)start; (void)len;
    __asm__ volatile("" ::: "memory");
}

static inline void dcache_invalidate_range(const void *start, uint64_t len) {
    (void)start; (void)len;
    __asm__ volatile("" ::: "memory");
}

#endif /* CACHE_H */
