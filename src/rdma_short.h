#ifndef RDMA_SHORT_H
#define RDMA_SHORT_H

#include "mlx5.h"

/* 1〜32 バイトの短い RDMA 転送(WRITE / READ / CAS / FAA)を最短経路で出す。
 *
 * 相手は Linux(librdmacm + libibverbs)の `tools/rdma_short_peer.c`。
 * 接続は IB CM(rdma_cm.c)で張り、相手の MR のアドレスと rkey は
 * **REP の private data** で受け取る。データ経路は NVMe-oF のジョブを
 * 通さず、シェル(core0)から SQ へ直接 WQE を書いて CQ を直接覗く。
 *
 * 相手の MR の配置(rdma_short_peer.c と同じ取り決め):
 *   [0, 4096)        データ領域。初期値 (i*7+3) & 0xff
 *   [4096, 4608)     8 バイトの atomic 語 x 64(初期値 0、ホスト順 = LE)
 *   [4608, 4616)     エンディアン判定用の語(LE で 0x0102030405060708)
 */
#define RSHORT_MAX_LEN        32u
#define RSHORT_DEFAULT_PORT   18515u
#define RSHORT_DATA_BYTES     4096u
#define RSHORT_ATOMIC_OFF     4096u
#define RSHORT_ATOMIC_WORDS   64u
#define RSHORT_PROBE_OFF      4608u
#define RSHORT_MR_MIN_BYTES   8192u
#define RSHORT_PRIV_MAGIC     0x52534854u   /* 'RSHT' */

void rdma_short_shell(const char *args, mlx5_dev_t *dev0, mlx5_dev_t *dev1);

/* プラットフォームが用意する: BAR0 の [off, off+len) を同じアドレスのまま
 * write-combining へ張り替える(BlueFlame 用。x86-linux は sysfs の
 * resource0_wc。失敗なら NULL)。unmap は UC へ戻す。 */
void *hal_bar0_map_wc(const mlx5_dev_t *dev, uint64_t off, uint64_t len);
void  hal_bar0_unmap_wc(const mlx5_dev_t *dev, void *p, uint64_t len);

#endif /* RDMA_SHORT_H */
