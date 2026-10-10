#ifndef ISCSIT_H
#define ISCSIT_H

/* iSCSI ターゲット(RFC 7143、TCP、ポート 3260)。PLAN_iscsi.md 段階 A:
 * Login(鍵の交渉)/ Discovery(SendTargets)/ Text / NOP / Logout / Reject。
 * SCSI コマンドは段階 B まで全部 CHECK CONDITION(ILLEGAL REQUEST)で返す。 */

#include <stdint.h>
#include "netif.h"
#include "iscsi_chap.h"

/* 同時に受ける接続の数。**1 接続 = 1 セッション**(MaxConnections=1)。
 * open-iscsi は Discovery のあと通常セッションを張り、session reinstatement では
 * 一瞬 2 本並ぶので、最低 2 本は要る。 */
#define ISCSIT_MAX_CONNS      4u
/* コマンドの窓(MaxCmdSN = ExpCmdSN + この数 - 1)。LIO は 64。 */
#define ISCSIT_CMD_WINDOW     128u
/* 自分が受け取れる 1 PDU のデータ長(MaxRecvDataSegmentLength の宣言)。LIO と同じ。 */
#define ISCSIT_MAX_RECV_DSL   262144u
/* Login が終わるまでの上限(accept からの経過)。 */
#define ISCSIT_LOGIN_TIMEOUT_MS 15000u
/* Logout 応答を送ってから相手が閉じるのを待つ上限。 */
#define ISCSIT_LINGER_MS      2000u

#define ISCSIT_DEFAULT_IQN "iqn.2026-10.local.vfionvme:ram0"

/* 次に送る N 個のヘッダ / データダイジェストをわざと壊す(陰性対照。`iscsit corrupt h|d N`)。 */
extern volatile uint32_t g_iscsit_corrupt_hdgst;
extern volatile uint32_t g_iscsit_corrupt_ddgst;
/* 受信の ACK を応答へ相乗りさせる(`iscsit ackpiggy on|off`、次の接続から)。 */
extern volatile uint32_t g_iscsit_ackpiggy;

/* 生存確認(NOP-In)。無通信がこれだけ続いたら打ち、応答をこれだけ待つ(ms、0 = 打たない)。 */
extern volatile uint32_t g_iscsit_nopin_ms;
extern volatile uint32_t g_iscsit_nopin_wait_ms;
/* 接続 idx にログアウトを求める(Async Message、AsyncEvent = 1)。 */
void iscsit_request_logout(unsigned idx);

/* 通常セッションに CHAP を求める(NULL で解除)。Discovery には求めない(LIO の既定と同じ)。 */
void iscsit_set_chap(const iscsi_chap_cfg_t *cfg);

int  iscsit_start(uint16_t port, netif_t *nif);
int  iscsit_started(void);
void iscsit_status(void);
void iscsit_stats_clear(void);

#endif /* ISCSIT_H */
