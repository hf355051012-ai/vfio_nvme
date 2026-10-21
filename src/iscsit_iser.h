#ifndef ISCSIT_ISER_H
#define ISCSIT_ISER_H

/* iSER ターゲット(RFC 7145: iSCSI を RDMA で運ぶ)。PLAN_iscsi.md 段階 I。
 *
 * 相手は Linux の ib_iser(open-iscsi の iface `iser`)。RDMA CM で RC QP を張り、
 * iSCSI の PDU は「iSER ヘッダ 28 バイト + BHS + データ」を SEND で運ぶ。
 * **データは PDU に載せない**: 読み出しはこちらが RDMA_WRITE でイニシエータのメモリへ書き、
 * 書き込みはこちらが RDMA_READ で引く(R2T / Data-In / Data-Out は出ない)。
 * SCSI の実行は TCP のターゲットと同じ `scsi.c`、記憶域も同じ LUN を使う。
 * 1 つの PF で 1 接続(= 1 セッション)を受ける。PF ごとに起動できる(2 ポートで受ける)。 */

#include <stdint.h>
#include "mlx5.h"

#define ISCSIT_ISER_PORT 3260u

/* inst = 実体の番号(0 = pf1、1 = pf0)、core = ジョブを固定するコア。 */
int  iscsit_iser_start(mlx5_dev_t *dev, const char *self_label, const uint8_t peer_mac[6], unsigned inst,
                       unsigned core);
int  iscsit_iser_started(void);
/* iSER の各実体の仕事を捨てて Unit Attention を立てる / cold なら接続を畳ませる(iscsit_xreset() と
 * 同じ意味。TCP のターゲットの LU / TARGET RESET からも呼ぶ)。except の実体は除く。 */
void iscsit_iser_xreset(unsigned lun_mask, uint8_t asc, uint8_t ascq, unsigned flags, int cold, const void *except);
void iscsit_iser_status(void);
void iscsit_iser_stats_clear(void);

#endif /* ISCSIT_ISER_H */
