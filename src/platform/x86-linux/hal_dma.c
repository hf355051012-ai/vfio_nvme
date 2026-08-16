// platform/x86-linux/hal_dma.c
//
// DMA アロケータ(include/platform.h の dma_alloc/dma_free 契約)+ cpu->dev 変換
// (mlx5_dma_addr、mlx5.h の x86 分岐)の x86-linux 実装(x86-vfio-port Phase 3-5、
// ~/.claude/plans/x86-vfio-port.md §3-5 参照)。
//
// 【x86 の DMA モデル】RPi5 は全物理 RAM が DMA 可能(RC_BAR2 窓が全域を張る)ため
// core は任意の static バッファを DMA ソースにできる。x86 は IOMMU があり、VFIO で
// マップした領域だけが DMA 可能。core は任意の static/プールバッファを DMA に使うので、
// **プロセスの rw メモリ領域(.bss/.data/heap/DMA プール)を VFIO でマップ**し、
// `mlx5_dma_addr()` が cpu ポインタ -> IOVA を引けるようにする。
//
// **IOVA は identity(=vaddr)ではなく低位に連番割り当てする**: 実行体は PIE で
// vaddr が高位(~0x7f..)になり、この IOMMU の IOVA 幅(実測でこの高位 vaddr を
// そのまま IOVA にすると VFIO_IOMMU_MAP_DMA が全領域失敗する)を超える。低位
// (0x1_0000_0000 起点)から連番で IOVA を割り当てて各領域をマップし、
// mlx5_dma_addr() は vaddr が属する領域を引いて iova_base + (cpu - va_base) を返す。
//
// dma_alloc はプール(hugepage 優先)から bump 払い出しするだけ(kind 無視、x86 は
// 全コヒーレント)。プールもマップ対象領域の一つなので dev はその IOVA。

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
/* 512MB。内訳の大半は nvmet_rdma / nvme_rdma の RAM ディスク
 * (NVMET_RDMA_RAMDISK_SLOT_SIZE = 256MB)で、残りが cmdq/mailbox/RQ/SQ/CQ 等。
 * Linux 側と名前空間を 256MB で揃えるため 256MB から拡大した。
 * hugepage が不足すると匿名ページへフォールバックする(性能が落ちるので、
 * /proc/sys/vm/nr_hugepages を 256 枚以上にしておくこと)。 */
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

/* /proc/self/maps を読み、rw 領域を低位 IOVA へ連番マップする。ベストエフォート
 * (失敗はスキップ)。特殊カーネルマッピング([vvar]/[vdso]/[vsyscall])は除外。
 * VFIO 準備前に呼ばれたら何もしない。プール確保後に 1 度だけ呼ばれる想定。 */
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

    /* プール確保後にプロセスメモリ全体をマップ(プール自身・.bss の static
     * バッファ・heap を DMA 可能にする)。 */
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

/* core に残る唯一の cpu->dev 変換(mlx5.h の x86 分岐が宣言)。cpu ポインタが属する
 * マップ済み領域を引いて対応する IOVA を返す。 */
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
