#ifndef ISCSI_PDU_H
#define ISCSI_PDU_H

/* iSCSI の PDU を TCP へ送る(ターゲットとイニシエータで共用)。 */

#include <stdint.h>
#include "tcp.h"

#define ISCSI_SEND_CORRUPT_HDGST 0x1u   /* 陰性対照: ヘッダダイジェストを壊す */
#define ISCSI_SEND_CORRUPT_DDGST 0x2u   /* 陰性対照: データダイジェストを壊す */

/* bhs(48 バイト)の DataSegmentLength はここで埋める。hd / dd はダイジェストを付けるか。
 * 1 セグメントに収まれば ヘッダ + データ + (パディング + データダイジェスト) を 1 回の
 * 短経路送信で出し、収まらなければセグメントずつに刻む(**やはり短経路だけ**。長経路と
 * 混ぜると TLS で順序が崩れた。CLAUDE.md)。戻り値 0 = 成功 / -1 = 失敗。 */
int iscsi_pdu_send(tcp_conn_t *tcp, int hd, int dd, uint8_t *bhs, const uint8_t *data, uint32_t dlen,
                   unsigned corrupt);

/* 1 セグメントに収まらない PDU の本体をゼロコピーの長経路(LSO)で送るか(`iscsizc on|off`)。
 * **0 が「短経路で刻む」従来の送り方 = 陰性対照。** */
extern volatile uint32_t g_iscsi_pdu_zerocopy;

/* ダイジェスト(CRC32C、最後に反転)はワイヤ上で**リトルエンディアン**。 */
uint32_t iscsi_get_le32(const uint8_t *p);

#endif /* ISCSI_PDU_H */
