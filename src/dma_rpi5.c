#include <stdint.h>
#include "platform.h"
#include "board.h"
#include "smp.h"

/* ================================================================
 * dma_rpi5.c -- DMA アロケータの RPi5 (ベアメタル) 実装
 * (x86-vfio-port Phase 2、include/platform.h の契約を実装、
 * ~/.claude/plans/x86-vfio-port.md §3 参照)。
 *
 * kind 別の2つの単純な bump アリーナから払い出す。mmu.c が既に属性を
 * マップ済みの固定領域にそのまま重ねることで、真のコールドブート(SD
 * カード書き換え)を経ずに通常の fwupdate チェインロードで検証できる:
 *   - DMA_DEVICE   : MLX5_DMA_BASE アリーナ(mmu.c が Device-nGnRnE)。
 *   - DMA_COHERENT : NVMET_RDMA_RAMDISK_BASE 以降(272MB 超は全域が
 *                    mmu.c で Normal cacheable、L1 index 0 の 1GB 窓内)。
 * dev アドレスは mlx5_dma_addr() と同一(RC_BAR2 インバウンド窓の
 * 上位32bit=0x10 を付加、下位32bit は cpu アドレスそのまま)。
 *
 * 【Phase 2 完了(段階5)】mlx5 の全 DMA バッファは dma_alloc 経由へ移行
 * 済みで、core の固定オフセットマクロ(MLX5_*_ADDR と *_CACHE_ADDR)は全廃
 * した。dev アドレスの上位32bit(RC_BAR2 窓)は board.h の
 * MLX5_DMA_ADDR_HI32 に単一定義し、mlx5.h の mlx5_dma_addr() とここが
 * 共有する(以前は両者が個別に 0x10 を定義していた重複を解消)。
 * ================================================================ */

/* DEVICE アリーナ = [MLX5_DMA_BASE, MLX5_DMA_BASE + MLX5_DMA_SIZE)。
 * mmu.c が Device-nGnRnE でマップ済み。 */
static uint64_t s_device_next = MLX5_DMA_BASE;
#define DMA_DEVICE_ARENA_END (MLX5_DMA_BASE + MLX5_DMA_SIZE)

/* COHERENT アリーナ = [NVMET_RDMA_RAMDISK_BASE, 1GB)。272MB 超は mmu.c が
 * 無条件に Normal cacheable でマップ済み(L1 index 0 の 1GB 窓内)。 */
static uint64_t s_coherent_next = NVMET_RDMA_RAMDISK_BASE;
#define DMA_COHERENT_ARENA_END 0x40000000ULL /* 1GB */

/* bring-up 時に core0/core1 双方から呼ばれうる(nvmet_rdma standalone が
 * core1 で初期化される等)ため、アリーナ bump を排他する。 */
static smp_spinlock_t s_dma_lock;

dma_region_t dma_alloc(uint64_t size, uint64_t align, dma_kind_t kind)
{
    if (align == 0u) {
        align = 64u; /* 既定は 1 キャッシュライン境界 */
    }

    dma_region_t r = { .cpu = 0, .dev = 0 };

    smp_spin_lock(&s_dma_lock);

    uint64_t *next;
    uint64_t  end;
    if (kind == DMA_DEVICE) {
        next = &s_device_next;
        end  = DMA_DEVICE_ARENA_END;
    } else {
        next = &s_coherent_next;
        end  = DMA_COHERENT_ARENA_END;
    }

    uint64_t addr = (*next + (align - 1u)) & ~(align - 1u);
    /* addr + size のオーバーフロー無し、かつアリーナ末尾を超えないこと。 */
    if (addr >= *next /* align 丸めでラップしていない */ &&
        addr + size >= addr /* size 加算でラップしていない */ &&
        addr + size <= end) {
        *next = addr + size;
        r.cpu = (void *)(uintptr_t)addr;
        r.dev = ((uint64_t)MLX5_DMA_ADDR_HI32 << 32) | (uint32_t)addr;
    }

    smp_spin_unlock(&s_dma_lock);
    return r;
}

void dma_free(dma_region_t region)
{
    /* bump アロケータ: 解放しない(このプロジェクトは起動時に確保して
     * 以後 free しない、platform.h の契約コメント参照)。 */
    (void)region;
}
