#ifndef ISCSIT_ISER_H
#define ISCSIT_ISER_H

/* iSER ターゲット(RFC 7145: iSCSI を RDMA で運ぶ)。PLAN_iscsi.md 段階 I。
 *
 * 相手は Linux の ib_iser(open-iscsi の iface `iser`)。RDMA CM で RC QP を張り、
 * iSCSI の PDU は「iSER ヘッダ 28 バイト + BHS + データ」を SEND で運ぶ。
 * **データは PDU に載せない**: 読み出しはこちらが RDMA_WRITE でイニシエータのメモリへ書き、
 * 書き込みはこちらが RDMA_READ で引く(R2T / Data-In / Data-Out は出ない)。
 * SCSI の実行は TCP のターゲットと同じ `scsi.c`、記憶域も同じ LUN を使う。
 * 1 接続(= 1 セッション)だけを受ける。 */

#include <stdint.h>
#include "mlx5.h"

#define ISCSIT_ISER_PORT 3260u

int  iscsit_iser_start(mlx5_dev_t *dev, const char *self_label, const uint8_t peer_mac[6]);
int  iscsit_iser_started(void);
void iscsit_iser_status(void);
void iscsit_iser_stats_clear(void);

#endif /* ISCSIT_ISER_H */
