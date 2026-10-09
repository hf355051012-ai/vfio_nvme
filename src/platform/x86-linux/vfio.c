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
    uint64_t bar_off[6]; /* BAR の region のデバイス fd 内オフセット(vfio_map_bar で記録)*/
    uint64_t bar_size[6];
    int      bar_sysfs[6]; /* 1=BAR を sysfs の resource<N> から mmap した */
} vfio_dev_t;

static vfio_dev_t s_dev[VFIO_MAX_DEVICES];
static int        s_ndev = 0;

/*=================================================================
 * /sys/bus/pci/devices/<BDF>/iommu_group のリンク先末尾から IOMMU グループ
 * 番号を得る。
 *
 * 引数:
 *   bdf - PCI アドレス("0000:01:00.0")
 * 戻り値:
 *   グループ番号。取得できなければ -1
 * コール元:
 *   container_open_once()
 * ===============================================================*/
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

/*=================================================================
 * VFIO コンテナと IOMMU グループを初回だけ開き、TYPE1 IOMMU を設定する。
 * 2 枚目以降の PF は同じコンテナを共有する。
 *
 * 引数:
 *   bdf - PCI アドレス
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   vfio_init()
 * ===============================================================*/
static int container_open_once(const char *bdf)
{
    if (s_container >= 0) {
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

/*=================================================================
 * BDF で指定した PCI デバイスを VFIO で掴み、以後の操作に使うスロット番号を
 * 返す。コンテナ/グループの初期化は初回のみ行う。
 *
 * 引数:
 *   pci_bdf - PCI アドレス("0000:01:00.0")
 * 戻り値:
 *   スロット番号(>=0)。失敗なら -1
 * コール元:
 *   run_dual_pf()
 * ===============================================================*/
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

/*=================================================================
 * VFIO コンテナが利用可能な状態か(DMA マップを発行できるか)を返す。
 *
 * 戻り値:
 *   1=利用可能、0=未初期化
 * コール元:
 *   remap_process_memory()
 * ===============================================================*/
int vfio_is_ready(void)
{
    return (s_container >= 0) && (s_ndev > 0);
}

/*=================================================================
 * スロット番号が有効な範囲で、かつそのデバイスが開かれているかを確認する。
 *
 * 引数:
 *   dev - スロット番号
 * 戻り値:
 *   1=有効、0=無効
 * コール元:
 *   vfio_map_bar(), vfio_cfg_read32(), vfio_cfg_write32(),
 *   vfio_enable_bus_master()
 * ===============================================================*/
static int dev_ok(int dev)
{
    return dev >= 0 && dev < s_ndev && s_dev[dev].fd >= 0;
}

/*=================================================================
 * デバイスの BAR を mmap してユーザ空間アドレスを返す。
 *
 * 引数:
 *   dev      - スロット番号
 *   bar      - BAR 番号(ConnectX のレジスタは BAR0)
 *   size_out - マップしたサイズの格納先
 * 戻り値:
 *   マップ先アドレス。失敗なら NULL
 * コール元:
 *   bringup_pf()
 * ===============================================================*/
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
    /* **BAR は sysfs の resource<N> から mmap する(vfio の fd からは mmap しない)。**
     * vfio-pci は BAR を mmap されると、カーネル内でも BAR 全体を pci_iomap()
     * (UC-)するので、PAT にその型が BAR 全体ぶん登録され、**後から一部の
     * ページを write-combining にできなくなる**(BlueFlame が使えない。
     * vfio_bar_set_wc() 参照)。sysfs の mmap も実効の型は同じ UC- なので、
     * 既存のレジスタ/ドアベルの扱いは変わらない。開けなければ従来の vfio へ。 */
    void *va = MAP_FAILED;
    const char *bar_env = getenv("VFIO_NVME_BAR");   /* "vfio" で従来の vfio の mmap(A/B 用)*/
    if (!(bar_env != 0 && strcmp(bar_env, "vfio") == 0)) {
        char path[96];
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/resource%d", s_dev[dev].bdf, bar);
        int sfd = open(path, O_RDWR | O_SYNC);
        if (sfd >= 0) {
            va = mmap(0, rinfo.size, PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);
            close(sfd);
        }
        s_dev[dev].bar_sysfs[bar] = (va != MAP_FAILED);
    }
    if (va == MAP_FAILED) {
        va = mmap(0, rinfo.size, PROT_READ | PROT_WRITE, MAP_SHARED,
                  s_dev[dev].fd, (off_t)rinfo.offset);
    }
    if (va == MAP_FAILED) {
        uart_printf("[vfio] slot%d BAR%d mmap 失敗 (errno=%d)\n", dev, bar, errno);
        return 0;
    }
    if (size_out) *size_out = rinfo.size;
    s_dev[dev].bar_off[bar] = rinfo.offset;
    s_dev[dev].bar_size[bar] = rinfo.size;
    uart_printf("[vfio] slot%d BAR%d を mmap (size=0x%x、%s)\n", dev, bar, (unsigned)rinfo.size,
                s_dev[dev].bar_sysfs[bar] ? "sysfs resource" : "vfio");
    return va;
}

/* BAR の [off, off+len) を UC(sysfs か vfio、vfio_map_bar と同じ経路)で MAP_FIXED する。 */
static int bar_map_uc_fixed(int dev, int bar, uint8_t *va, uint64_t off, uint64_t len)
{
    void *p = MAP_FAILED;
    if (s_dev[dev].bar_sysfs[bar]) {
        char path[96];
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/resource%d", s_dev[dev].bdf, bar);
        int fd = open(path, O_RDWR | O_SYNC);
        if (fd >= 0) {
            p = mmap(va, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, (off_t)off);
            close(fd);
        }
    } else {
        p = mmap(va, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, s_dev[dev].fd,
                 (off_t)(s_dev[dev].bar_off[bar] + off));
    }
    return (p == (void *)va) ? 0 : -1;
}

/*=================================================================
 * vfio_map_bar() でマップした BAR のうち [off, off+len) だけを、同じ仮想
 * アドレスのまま **write-combining**(sysfs の resource<bar>_wc)へ張り替える。
 * wc=0 なら UC へ戻す。BlueFlame(rdma_short.c)用。
 *
 * **x86 の PAT は同じ物理ページに別の型を許さない。** 型の衝突があると
 * resource0_wc の mmap は**黙って UC- に格下げされる**(実機で踏んだ。BF に
 * 書いた WQE を NIC が捨てる形で出る。`rshort bfprobe` で判定できる)。
 * 衝突の元は 2 つあった:
 *   1. vfio の fd から BAR を mmap すると、vfio-pci がカーネル内で BAR 全体を
 *      pci_iomap() する。これはユーザ空間からは外せない -> vfio_map_bar() で
 *      BAR を sysfs の resource<N> から mmap するようにした。
 *   2. ユーザ空間の mmap も BAR 全体ぶん登録され、**そのページだけ munmap
 *      しても元の mmap が全部消えるまで登録が残る**(kernel 7.0 で確認)。
 *      -> BAR を「前 / そのページ / 後」の 3 つの mmap に組み直す。前と後を
 *      MAP_FIXED し直すと元の mmap はそのページだけになり、それを munmap
 *      すると登録が外れる。MAP_FIXED の置き換えは mmap_lock の中で行われる
 *      ので、**他コアがその間に前後のページを触っても待たされるだけで落ちない**。
 *      (MTRR では救えない: この機材は BAR を含む 1GB が MTRR で UC 指定で、
 *      重なりでは UC が勝つ。)
 *
 * 引数:
 *   dev    - スロット番号
 *   bar    - BAR 番号
 *   bar_va - vfio_map_bar() が返したアドレス
 *   off    - BAR 内オフセット(4KB 境界)
 *   len    - バイト数
 *   wc     - 1=WC へ、0=vfio の UC へ戻す
 * 戻り値:
 *   0=成功、-1=失敗(失敗時は UC のマップへ戻すよう試みる)
 * コール元:
 *   hal_bar0_map_wc(), hal_bar0_unmap_wc()
 * ===============================================================*/
int vfio_bar_set_wc(int dev, int bar, void *bar_va, uint64_t off, uint64_t len, int wc)
{
    if (!dev_ok(dev) || bar < 0 || bar > 5) return -1;
    uint8_t *base = (uint8_t *)bar_va;
    uint8_t *va = base + off;
    const uint64_t size = s_dev[dev].bar_size[bar];
    if (off + len > size) return -1;
    void *p = MAP_FAILED;
    if (wc) {
        /* 前と後を張り直す(元の mmap をこのページだけに縮める)。 */
        if (off > 0 && bar_map_uc_fixed(dev, bar, base, 0, off) != 0) {
            uart_printf("[vfio] BAR%d の前半を張り直せない (errno=%d)\n", bar, errno);
            return -1;
        }
        if (off + len < size && bar_map_uc_fixed(dev, bar, va + len, off + len, size - off - len) != 0) {
            uart_printf("[vfio] BAR%d の後半を張り直せない (errno=%d)\n", bar, errno);
            return -1;
        }
    }
    /* このページを先に明示的に外す。MAP_FIXED の置き換えは新しいマップを張った
     * 後で古い方を片付けるので、置き換えに任せると古い UC- の登録が残った状態で
     * WC を登録しようとして、また UC- に格下げされる。 */
    if (munmap(va, len) != 0) {
        uart_printf("[vfio] munmap(BAR%d+0x%llx) 失敗 (errno=%d)\n", bar,
                    (unsigned long long)off, errno);
        return -1;
    }
    if (wc) {
        char path[96];
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/resource%d_wc", s_dev[dev].bdf, bar);
        int fd = open(path, O_RDWR | O_SYNC);
        if (fd >= 0) {
            p = mmap(va, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, (off_t)off);
            close(fd);
        }
        if (p == va) return 0;
        uart_printf("[vfio] %s の mmap 失敗 (errno=%d) -- UC へ戻す\n", path, errno);
    }
    if (bar_map_uc_fixed(dev, bar, va, off, len) != 0) {
        uart_printf("[vfio] BAR%d+0x%llx を UC へ戻せない (errno=%d)\n", bar,
                    (unsigned long long)off, errno);
        return -1;
    }
    return wc ? -1 : 0;
}

/*=================================================================
 * PCI コンフィグ空間から 32bit 読む。
 *
 * 引数:
 *   dev    - スロット番号
 *   offset - コンフィグ空間オフセット
 * 戻り値:
 *   読んだ値。失敗時は 0xFFFFFFFF
 * コール元:
 *   bringup_pf(), vfio_enable_bus_master(), x86_cfg_rd()
 * ===============================================================*/
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

/*=================================================================
 * PCI コンフィグ空間へ 32bit 書く。
 *
 * 引数:
 *   dev    - スロット番号
 *   offset - コンフィグ空間オフセット
 *   val    - 書く値
 * コール元:
 *   vfio_enable_bus_master()
 * ===============================================================*/
void vfio_cfg_write32(int dev, uint32_t offset, uint32_t val)
{
    if (!dev_ok(dev)) return;
    if (pwrite(s_dev[dev].fd, &val, sizeof(val), (off_t)(s_dev[dev].cfg_off + offset)) != (ssize_t)sizeof(val)) {
        uart_printf("[vfio] slot%d config write @0x%x 失敗 (errno=%d)\n", dev, offset, errno);
    }
}

/*=================================================================
 * Command レジスタの Bus Master Enable を立てる(NIC が DMA を発行できる
 * ようにする)。
 *
 * 引数:
 *   dev - スロット番号
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   bringup_pf()
 * ===============================================================*/
int vfio_enable_bus_master(int dev)
{
    if (!dev_ok(dev)) return -1;
    uint32_t cmd = vfio_cfg_read32(dev, 0x04);
    vfio_cfg_write32(dev, 0x04, cmd | 0x6u);
    return 0;
}

/*=================================================================
 * ユーザ空間アドレス vaddr から size バイトを IOVA へマップする
 * (VFIO_IOMMU_MAP_DMA)。
 *
 * 引数:
 *   vaddr - マップするユーザ空間アドレス
 *   iova  - 割り当てる IOVA
 *   size  - バイト数
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   remap_process_memory()
 * ===============================================================*/
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
