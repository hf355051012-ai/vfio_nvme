#ifndef X86_VFIO_H
#define X86_VFIO_H

/* 注意: include guard は X86_VFIO_H(VFIO_H ではない)。システムの
 * <linux/vfio.h> も同じ VFIO_H を使うため、ここで VFIO_H を先に定義すると
 * linux/vfio.h 全体が丸ごとスキップされ、VFIO_* マクロが未定義になる。 */

#include <stdint.h>

/* ================================================================
 * vfio.h -- x86-linux 用 VFIO ヘルパの platform 内部 API(x86-vfio-port
 * Phase 3-5、~/.claude/plans/x86-vfio-port.md §4-6 参照)。
 *
 * VFIO は Linux/BIOS が既に列挙済みの PCIe デバイスを IOMMU 保護つきで
 * ユーザ空間から掴む仕組み。ConnectX を vfio-pci にバインドし、BAR mmap
 * (MMIO)/ config space 確認 / VFIO_IOMMU_MAP_DMA(hal_dma.c が使う)を行う。
 *
 * **複数デバイス対応(Phase 5、dual-port PF0/PF1 ループバック用)**: ConnectX-4
 * Lx の 2 物理ポートは別々の PCI 関数(01:00.0 / 01:00.1)だが、同一 IOMMU
 * グループに属する。VFIO では container/group を 1 度だけ開き、そこから各 BDF の
 * device fd を取る(DMA マップも container 単位=両デバイス共有)。よって
 * vfio_init() を BDF ごとに呼ぶとデバイススロット(0,1,...)を返し、以降の
 * BAR/config 操作はそのスロット番号で指定する。
 * ================================================================ */

/* pci_bdf の VFIO デバイスを掴む。初回は container/group を開いて TYPE1 IOMMU を
 * 設定し、以後の呼び出しは同一 container/group を再利用する(同一グループ前提)。
 * 戻り値: デバイススロット番号(0,1,...)、失敗時 -1。 */
int vfio_init(const char *pci_bdf);

/* container が開き、少なくとも 1 デバイスを掴んでいるか(1=可)。 */
int vfio_is_ready(void);

/* デバイス dev の BAR(0..5)を mmap して CPU 仮想アドレスを返す(mmio_read32 等で
 * そのままデリファレンス可)。size_out に BAR サイズを返す。失敗時 NULL。 */
void *vfio_map_bar(int dev, int bar, uint64_t *size_out);

/* デバイス dev の config space 32bit 読み書き。 */
uint32_t vfio_cfg_read32(int dev, uint32_t offset);
void     vfio_cfg_write32(int dev, uint32_t offset, uint32_t val);

/* デバイス dev の Command レジスタに Memory Space Enable | Bus Master Enable。 */
int vfio_enable_bus_master(int dev);

/* [vaddr, vaddr+size) を IOVA へ DMA マップ(VFIO_IOMMU_MAP_DMA、READ|WRITE)。
 * container 単位なので掴んだ全デバイスから同じ IOVA で見える。0=成功、-1=失敗。 */
int vfio_dma_map(void *vaddr, uint64_t iova, uint64_t size);

#endif /* X86_VFIO_H */
