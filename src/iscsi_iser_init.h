#ifndef ISCSI_ISER_INIT_H
#define ISCSI_ISER_INIT_H

/* iSER イニシエータ(RFC 7145)。PLAN_iscsi.md 段階 I。相手は Linux の LIO(ib_isert)。
 * シェル(core0)の上で同期的に動く(`iscsibench` と同じ作り)。PF0 から繋ぐ。
 * 読み出しは相手が RDMA_WRITE でこちらのバッファへ書き、書き込みは相手が RDMA_READ で
 * こちらのバッファから引く(R2T / Data-In / Data-Out は無い)。 */

#include <stdint.h>
#include "mlx5.h"

int  iscsi_iser_connect(mlx5_dev_t *dev, uint32_t ip, const uint8_t mac[6], const char *target_iqn);
void iscsi_iser_close(void);
int  iscsi_iser_connected(void);
int  iscsi_iser_bench(int is_read, uint32_t chunk, uint32_t qd, uint32_t runtime_ms,
                      uint64_t *bytes, uint32_t *count, uint32_t *elapsed_ms, uint32_t *mismatch);
void iscsi_iser_status(void);

#endif /* ISCSI_ISER_INIT_H */
