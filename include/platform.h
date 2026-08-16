#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>

/* ================================================================
 * platform.h -- プラットフォーム HAL 契約(x86-vfio-port Phase 1 で新設、
 * ~/.claude/plans/x86-vfio-port.md 参照)。
 *
 * このヘッダは「アーキ非依存の core(mlx5 ドライバ + RoCEv2/NVMe-oF +
 * TCP/IP スタック)が呼び、各 platform が実装する」契約のうち、既存の
 * src/{mmio,cache,timer,smp}.h では表現しきれていない **DMA アロケータ**
 * を定義する。他の HAL 契約(MMIO / キャッシュ / タイマ / SMP)は引き続き
 * src/{mmio,cache,timer,smp}.h(それぞれ冒頭バナー参照)が担う。
 *
 * 【Phase 1 の位置づけ】この時点では core はまだこの契約を呼んでおらず
 * (dma_alloc/dma_free は未配線)、RPi5 は従来通り board.h の固定物理
 * アドレス(MLX5_DMA_BASE 等)を直接使っている。Phase 2 で mlx5_dma_addr()
 * と board.h 固定アドレス参照を dma_alloc 経由へ置換し、RPi5 実装が
 * 「従来の固定物理アドレスを順に払い出す」形で既存挙動を完全再現する。
 * その後 Phase 3 で x86-linux 実装(hugepage 確保 + VFIO_IOMMU_MAP_DMA、
 * dev=IOVA)を差し込む。
 *
 * 【DMA アドレスモデル(本移植最大の継ぎ目)】
 *   - RPi5: dev = cpu(固定物理) + RC_BAR2 インバウンド窓オフセット
 *     (0x10_00000000)。ConnectX は PCI 側アドレスを発行し、brcmstb RC の
 *     RC_BAR2 が PCI->RAM を張る(CLAUDE.md「DMA には 64bit アドレッシングが
 *     必要」参照)。
 *   - x86-linux: dev = IOMMU の IOVA(VFIO_IOMMU_MAP_DMA で確立)。
 *   - VxWorks(将来): cacheDmaMalloc + CACHE_DMA_VIRT_TO_PHYS。
 * いずれの差異も dma_alloc の platform 実装の中にだけ閉じ込め、core は
 * cpu/dev の 2 値を受け取るだけで分岐しない(#ifdef を core に撒かない)。
 * ================================================================ */

/* DMA 可能領域 1 個を表す。cpu は CPU から見えるアドレス(読み書き用)、
 * dev はディスクリプタ/ドアベルに書き込む「デバイス(DMA)アドレス」。
 * RPi5 では dev = cpu + RC_BAR2 オフセット、x86 では dev = IOVA。 */
typedef struct {
    void    *cpu; /* CPU-visible address (for CPU reads/writes) */
    uint64_t dev; /* device/DMA address (programmed into descriptors) */
} dma_region_t;

/* DMA 領域のメモリ属性(2026-08-14、Phase 2 でユーザーと合意した契約拡張)。
 * RPi5 は DMA バッファを2属性で厳密に使い分けている(x86 は全コヒーレントで
 * 区別不要 -- kind を無視して常にコヒーレント確保でよい):
 *   - DMA_DEVICE:   Device-nGnRnE(非キャッシュ)。cmdq/mailbox/WQE リング/
 *                   ドアベル等、強い順序保証が要る/CPU がホットに触らない
 *                   バッファ。RPi5 では MLX5_DMA_BASE アリーナ(mmu.c が
 *                   Device-nGnRnE でマップ)から払い出す。
 *   - DMA_COHERENT: Normal cacheable(手動 flush)。RQ 受信データ/各種 CQ/
 *                   RAM ディスク等、CPU がホットに読み書きするバッファ。
 *                   RPi5 では 272MB 以降の cacheable アリーナから払い出し、
 *                   DMA コヒーレンシは呼び出し元が dcache_clean/invalidate_
 *                   range() で手動管理する(cache.h バナー参照)。 */
typedef enum {
    DMA_DEVICE = 0,
    DMA_COHERENT = 1,
} dma_kind_t;

/* size バイト・align バイト境界・kind 属性の DMA 可能領域を確保して返す。
 * align は 2 の冪であること(0 の場合は実装既定の最小アラインを使う)。
 * 失敗時は {cpu=NULL, dev=0} を返す。**bring-up 時に一度だけ確保する前提**
 * (このプロジェクトは起動時に全 DMA バッファを確保し、以後 free しない)。
 * platform 実装:
 *   - RPi5: kind 別の2アリーナ(DMA_DEVICE=MLX5_DMA_BASE、DMA_COHERENT=
 *     272MB 以降の cacheable 領域)から順に払い出す。dev = mlx5_dma_addr(cpu)
 *     (= (0x10<<32) | 下位32bit、RC_BAR2 インバウンド窓オフセット)。
 *   - x86-linux(Phase 3): hugepage 上に確保済みの領域から払い出し、対応する
 *     IOVA を dev に返す(起動時に一括 VFIO_IOMMU_MAP_DMA 済みの前提)。kind は
 *     無視(全コヒーレント)。 */
dma_region_t dma_alloc(uint64_t size, uint64_t align, dma_kind_t kind);

/* dma_alloc で得た領域を解放する(RPi5 の bump 払い出しでは no-op でよい。
 * x86 では free-list への返却)。 */
void dma_free(dma_region_t region);

#endif /* PLATFORM_H */
