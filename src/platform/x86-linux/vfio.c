// platform/x86-linux/vfio.c
//
// VFIO による ConnectX(vfio-pci バインド済み)の掴み(x86-vfio-port Phase 3-5、
// ~/.claude/plans/x86-vfio-port.md §4-6 参照)。標準 VFIO シーケンス:
//   container(/dev/vfio/vfio) -> group(/dev/vfio/<N>) -> device -> BAR mmap /
//   config region / VFIO_IOMMU_MAP_DMA。PCIe 列挙・BAR 割り当ては Linux/BIOS
//   済みなので RPi5 の pcie1.c(PERST#/rescal/PLL/リンク訓練)は不要。
//
// **複数デバイス**: container/group は 1 度だけ開き(同一 IOMMU グループ前提)、
// 各 BDF の device fd を配列で保持する。DMA マップは container 単位なので
// 掴んだ全デバイスで共有される(dual-port PF0/PF1 ループバック用、§5)。

#include "vfio.h"
#include "uart.h"

#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define VFIO_MAX_DEVICES 4

static int s_container = -1;
static int s_group     = -1;
static int s_grpnum    = -1;

typedef struct {
    int      fd;        /* device fd(-1=未使用) */
    uint64_t cfg_off;   /* config region のデバイス fd 内オフセット */
    uint64_t cfg_size;
    char     bdf[32];
} vfio_dev_t;

static vfio_dev_t s_dev[VFIO_MAX_DEVICES];
static int        s_ndev = 0;

/* /sys/bus/pci/devices/<BDF>/iommu_group のリンク先末尾からグループ番号を得る。 */
static int read_iommu_group(const char *bdf)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/iommu_group", bdf);
    char link[256];
    ssize_t n = readlink(path, link, sizeof(link) - 1);
    if (n < 0) {
        uart_printf("[vfio] readlink(%s) 失敗 (errno=%d) -- IOMMU 無効か BDF 誤り\n",
                    path, errno);
        return -1;
    }
    link[n] = '\0';
    const char *slash = strrchr(link, '/');
    const char *num = slash ? slash + 1 : link;
    return (int)strtol(num, 0, 10);
}

/* container/group を初回のみ開いて TYPE1 IOMMU を設定する。0=成功。 */
static int container_open_once(const char *bdf)
{
    if (s_container >= 0) {
        /* 既に開いている -- 同一グループであることを確認(異なると VFIO は
         * 別 container を要するが、このプロジェクトは同一グループの ConnectX
         * 2 ポートのみ想定)。 */
        int g = read_iommu_group(bdf);
        if (g != s_grpnum) {
            uart_printf("[vfio] %s は別 IOMMU グループ %d(既存 %d)-- 未対応\n",
                        bdf, g, s_grpnum);
            return -1;
        }
        return 0;
    }

    int grpnum = read_iommu_group(bdf);
    if (grpnum < 0) return -1;

    s_container = open("/dev/vfio/vfio", O_RDWR);
    if (s_container < 0) {
        uart_printf("[vfio] open(/dev/vfio/vfio) 失敗 (errno=%d) -- vfio 未ロード?\n", errno);
        return -1;
    }
    if (ioctl(s_container, VFIO_GET_API_VERSION) != VFIO_API_VERSION ||
        !ioctl(s_container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
        uart_printf("[vfio] VFIO API/TYPE1 IOMMU 非対応\n");
        goto fail;
    }

    char grppath[64];
    snprintf(grppath, sizeof(grppath), "/dev/vfio/%d", grpnum);
    s_group = open(grppath, O_RDWR);
    if (s_group < 0) {
        uart_printf("[vfio] open(%s) 失敗 (errno=%d) -- vfio-pci にバインド済み?\n",
                    grppath, errno);
        goto fail;
    }

    struct vfio_group_status gstat;
    memset(&gstat, 0, sizeof(gstat));
    gstat.argsz = sizeof(gstat);
    if (ioctl(s_group, VFIO_GROUP_GET_STATUS, &gstat) < 0 ||
        !(gstat.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        uart_printf("[vfio] グループ %d が VIABLE でない(同一グループの他デバイスも要バインド)\n", grpnum);
        goto fail;
    }
    if (ioctl(s_group, VFIO_GROUP_SET_CONTAINER, &s_container) < 0 ||
        ioctl(s_container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0) {
        uart_printf("[vfio] SET_CONTAINER/SET_IOMMU 失敗 (errno=%d)\n", errno);
        goto fail;
    }
    s_grpnum = grpnum;
    return 0;

fail:
    if (s_group >= 0)     { close(s_group);     s_group = -1; }
    if (s_container >= 0) { close(s_container); s_container = -1; }
    return -1;
}

int vfio_init(const char *pci_bdf)
{
    /* 既に掴んでいる BDF なら既存スロットを返す。 */
    for (int i = 0; i < s_ndev; i++) {
        if (strcmp(s_dev[i].bdf, pci_bdf) == 0) return i;
    }
    if (s_ndev >= VFIO_MAX_DEVICES) {
        uart_printf("[vfio] デバイス数上限\n");
        return -1;
    }
    if (container_open_once(pci_bdf) != 0) {
        return -1;
    }

    int fd = ioctl(s_group, VFIO_GROUP_GET_DEVICE_FD, pci_bdf);
    if (fd < 0) {
        uart_printf("[vfio] VFIO_GROUP_GET_DEVICE_FD(%s) 失敗 (errno=%d)\n", pci_bdf, errno);
        return -1;
    }

    struct vfio_device_info dinfo;
    memset(&dinfo, 0, sizeof(dinfo));
    dinfo.argsz = sizeof(dinfo);
    if (ioctl(fd, VFIO_DEVICE_GET_INFO, &dinfo) < 0) {
        uart_printf("[vfio] VFIO_DEVICE_GET_INFO 失敗 (errno=%d)\n", errno);
        close(fd);
        return -1;
    }

    struct vfio_region_info rinfo;
    memset(&rinfo, 0, sizeof(rinfo));
    rinfo.argsz = sizeof(rinfo);
    rinfo.index = VFIO_PCI_CONFIG_REGION_INDEX;
    if (ioctl(fd, VFIO_DEVICE_GET_REGION_INFO, &rinfo) < 0) {
        uart_printf("[vfio] config region info 取得失敗 (errno=%d)\n", errno);
        close(fd);
        return -1;
    }

    int slot = s_ndev++;
    s_dev[slot].fd       = fd;
    s_dev[slot].cfg_off  = rinfo.offset;
    s_dev[slot].cfg_size = rinfo.size;
    snprintf(s_dev[slot].bdf, sizeof(s_dev[slot].bdf), "%s", pci_bdf);

    uart_printf("[vfio] %s を掴んだ (slot=%d, group=%d, regions=%u, config=%u)\n",
                pci_bdf, slot, s_grpnum, (unsigned)dinfo.num_regions, (unsigned)rinfo.size);
    return slot;
}

int vfio_is_ready(void)
{
    return (s_container >= 0) && (s_ndev > 0);
}

static int dev_ok(int dev)
{
    return dev >= 0 && dev < s_ndev && s_dev[dev].fd >= 0;
}

void *vfio_map_bar(int dev, int bar, uint64_t *size_out)
{
    if (!dev_ok(dev) || bar < 0 || bar > 5) return 0;
    struct vfio_region_info rinfo;
    memset(&rinfo, 0, sizeof(rinfo));
    rinfo.argsz = sizeof(rinfo);
    rinfo.index = (uint32_t)(VFIO_PCI_BAR0_REGION_INDEX + bar);
    if (ioctl(s_dev[dev].fd, VFIO_DEVICE_GET_REGION_INFO, &rinfo) < 0) {
        uart_printf("[vfio] slot%d BAR%d region info 失敗 (errno=%d)\n", dev, bar, errno);
        return 0;
    }
    if (rinfo.size == 0 || !(rinfo.flags & VFIO_REGION_INFO_FLAG_MMAP)) {
        uart_printf("[vfio] slot%d BAR%d は mmap 不可 or サイズ 0\n", dev, bar);
        return 0;
    }
    void *va = mmap(0, rinfo.size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    s_dev[dev].fd, (off_t)rinfo.offset);
    if (va == MAP_FAILED) {
        uart_printf("[vfio] slot%d BAR%d mmap 失敗 (errno=%d)\n", dev, bar, errno);
        return 0;
    }
    if (size_out) *size_out = rinfo.size;
    uart_printf("[vfio] slot%d BAR%d を mmap (size=0x%x)\n", dev, bar, (unsigned)rinfo.size);
    return va;
}

uint32_t vfio_cfg_read32(int dev, uint32_t offset)
{
    if (!dev_ok(dev)) return 0xffffffffu;
    uint32_t v = 0xffffffffu;
    if (pread(s_dev[dev].fd, &v, sizeof(v), (off_t)(s_dev[dev].cfg_off + offset)) != (ssize_t)sizeof(v)) {
        uart_printf("[vfio] slot%d config read @0x%x 失敗 (errno=%d)\n", dev, offset, errno);
        return 0xffffffffu;
    }
    return v;
}

void vfio_cfg_write32(int dev, uint32_t offset, uint32_t val)
{
    if (!dev_ok(dev)) return;
    if (pwrite(s_dev[dev].fd, &val, sizeof(val), (off_t)(s_dev[dev].cfg_off + offset)) != (ssize_t)sizeof(val)) {
        uart_printf("[vfio] slot%d config write @0x%x 失敗 (errno=%d)\n", dev, offset, errno);
    }
}

int vfio_enable_bus_master(int dev)
{
    if (!dev_ok(dev)) return -1;
    /* PCI Command(0x04)下位16bit: bit1=Memory Space Enable、bit2=Bus Master
     * Enable。既存値に 0x06 を OR(CLAUDE.md「Command レジスタ有効化」教訓)。 */
    uint32_t cmd = vfio_cfg_read32(dev, 0x04);
    vfio_cfg_write32(dev, 0x04, cmd | 0x6u);
    return 0;
}

int vfio_dma_map(void *vaddr, uint64_t iova, uint64_t size)
{
    if (s_container < 0) return -1;
    struct vfio_iommu_type1_dma_map dm;
    memset(&dm, 0, sizeof(dm));
    dm.argsz = sizeof(dm);
    dm.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    dm.vaddr = (uint64_t)(uintptr_t)vaddr;
    dm.iova  = iova;
    dm.size  = size;
    if (ioctl(s_container, VFIO_IOMMU_MAP_DMA, &dm) < 0) {
        uart_printf("[vfio] VFIO_IOMMU_MAP_DMA(iova=0x%08x%08x, size=0x%x) 失敗 (errno=%d)\n",
                    (uint32_t)(iova >> 32), (uint32_t)iova, (unsigned)size, errno);
        return -1;
    }
    return 0;
}
