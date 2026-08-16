#ifndef X86_VFIO_H
#define X86_VFIO_H

#include <stdint.h>

int vfio_init(const char *pci_bdf);

/* container が開き、少なくとも 1 デバイスを掴んでいるか(1=可)。 */
int vfio_is_ready(void);

void *vfio_map_bar(int dev, int bar, uint64_t *size_out);

/* デバイス dev の config space 32bit 読み書き。 */
uint32_t vfio_cfg_read32(int dev, uint32_t offset);
void     vfio_cfg_write32(int dev, uint32_t offset, uint32_t val);

/* デバイス dev の Command レジスタに Memory Space Enable | Bus Master Enable。 */
int vfio_enable_bus_master(int dev);

int vfio_dma_map(void *vaddr, uint64_t iova, uint64_t size);

#endif /* X86_VFIO_H */
