#include "platform.h"
#include "vfio.h"
#include "uart.h"

#include <sys/mman.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* mlx5.h(board.h 等を引き込むので include せず)の x86 分岐と同じ宣言。 */
uint64_t mlx5_dma_addr(const volatile void *cpu_ptr);

/* プール総サイズ = 256MB = 128 × 2MB hugepage(§5、hugepages を 128 枚予約済み)。 */
#define DMA_POOL_SIZE   (512ull * 1024ull * 1024ull)

/* IOVA 割り当て起点(低位、IOMMU の IOVA 幅に確実に収まる)。 */
#define DMA_IOVA_BASE   0x100000000ull

/* vaddr 領域 -> IOVA の対応表(/proc/self/maps の rw 領域を VFIO へマップした記録)。 */
typedef struct {
    uintptr_t va_start;
    uintptr_t va_end;
    uint64_t  iova_start;
} dma_region_map_t;

#define DMA_MAX_REGIONS 64

static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t        *s_pool      = 0;
static uint64_t        s_pool_size = 0;
static uint64_t        s_next_off  = 0;
static int             s_maps_done = 0;

static dma_region_map_t s_regions[DMA_MAX_REGIONS];
static int              s_nregions = 0;
static uint64_t         s_next_iova = DMA_IOVA_BASE;

static void remap_process_memory(void)
{
    if (s_maps_done || !vfio_is_ready()) {
        return;
    }
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        uart_printf("[hal_dma] /proc/self/maps を開けない\n");
        return;
    }
    char line[512];
    unsigned mapped = 0, skipped = 0;
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        char path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]",
                       &start, &end, perms, path);
        if (n < 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        if (path[0] == '[' &&
            (strstr(path, "vvar") || strstr(path, "vdso") || strstr(path, "vsyscall"))) {
            continue;
        }
        if (end <= start) continue;
        if (s_nregions >= DMA_MAX_REGIONS) { skipped++; continue; }

        uint64_t sz   = end - start;
        uint64_t iova = s_next_iova;
        if (vfio_dma_map((void *)(uintptr_t)start, iova, sz) == 0) {
            s_regions[s_nregions].va_start   = (uintptr_t)start;
            s_regions[s_nregions].va_end     = (uintptr_t)end;
            s_regions[s_nregions].iova_start = iova;
            s_nregions++;
            s_next_iova += sz; /* 領域は page 境界なので iova も page 整列を維持 */
            mapped++;
        } else {
            skipped++;
        }
    }
    fclose(f);
    s_maps_done = 1;
    uart_printf("[hal_dma] DMA マップ: %u 領域成功 / %u スキップ (IOVA 0x%08x%08x-0x%08x%08x)\n",
                mapped, skipped,
                (uint32_t)(DMA_IOVA_BASE >> 32), (uint32_t)DMA_IOVA_BASE,
                (uint32_t)(s_next_iova >> 32), (uint32_t)s_next_iova);
}

static int pool_init_locked(void)
{
    if (s_pool) {
        return 0;
    }
    void *p = mmap(0, DMA_POOL_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (p == MAP_FAILED) {
        p = mmap(0, DMA_POOL_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            uart_printf("[hal_dma] プール mmap 失敗\n");
            return -1;
        }
        uart_printf("[hal_dma] プール確保: 匿名ページ %uMB(hugepage 使用不可)\n",
                    (unsigned)(DMA_POOL_SIZE >> 20));
    } else {
        uart_printf("[hal_dma] プール確保: 2MB hugepage %uMB\n",
                    (unsigned)(DMA_POOL_SIZE >> 20));
    }
    s_pool      = (uint8_t *)p;
    s_pool_size = DMA_POOL_SIZE;
    s_next_off  = 0;
    memset(s_pool, 0, s_pool_size); /* 物理割り当てを確定(VFIO ピン留め前) */

    remap_process_memory();
    return 0;
}

dma_region_t dma_alloc(uint64_t size, uint64_t align, dma_kind_t kind)
{
    (void)kind; /* x86 は全コヒーレント */
    if (align == 0u) {
        align = 64u;
    }
    dma_region_t r = { .cpu = 0, .dev = 0 };

    pthread_mutex_lock(&s_lock);
    if (pool_init_locked() != 0) {
        pthread_mutex_unlock(&s_lock);
        return r;
    }
    uint64_t off = (s_next_off + (align - 1u)) & ~(align - 1u);
    if (off >= s_next_off && off + size >= off && off + size <= s_pool_size) {
        s_next_off = off + size;
        r.cpu = s_pool + off;
        r.dev = mlx5_dma_addr(r.cpu); /* 対応表から IOVA を引く(プールもマップ済み) */
    } else {
        uart_printf("[hal_dma] プール枯渇(要求 0x%x, 残 0x%x)\n",
                    (unsigned)size, (unsigned)(s_pool_size - s_next_off));
    }
    pthread_mutex_unlock(&s_lock);
    return r;
}

uint64_t mlx5_dma_addr(const volatile void *cpu_ptr)
{
    uintptr_t p = (uintptr_t)cpu_ptr;
    for (int i = 0; i < s_nregions; i++) {
        if (p >= s_regions[i].va_start && p < s_regions[i].va_end) {
            return s_regions[i].iova_start + (uint64_t)(p - s_regions[i].va_start);
        }
    }
    uart_printf("[hal_dma] mlx5_dma_addr: 未マップ領域のポインタ %p\n", (void *)cpu_ptr);
    return (uint64_t)p;
}
