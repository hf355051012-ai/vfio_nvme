#ifndef ISCSI_INIT_H
#define ISCSI_INIT_H

/* iSCSI イニシエータ(RFC 7143、TCP)。PLAN_iscsi.md 段階 D。
 * シェル(core0)の上で同期的に動く(NVMe/TCP の tcpbench と同じ作り)。セッションは 1 本。 */

#include <stdint.h>
#include "netaddr.h"
#include "iscsi_chap.h"

#define ISCSI_INI_DEFAULT_NAME "iqn.2026-10.local.vfionvme:init"

/* 通常セッションを張る(ログインまで)。target_iqn が NULL / 空なら Discovery で最初の対象を使う。 */
int  iscsi_ini_connect(const netaddr_t *dst, uint16_t port, const char *target_iqn, int hdgst, int ddgst);
void iscsi_ini_close(void);           /* ログアウトして閉じる */
int  iscsi_ini_connected(void);
int  iscsi_ini_digest(int *hd, int *dd);
/* Discovery セッションで SendTargets=All を表示する。最初の TargetName を first へ(NULL 可)。 */
int  iscsi_ini_discover(const netaddr_t *dst, uint16_t port, char *first, unsigned cap);
/* qd 本を流し続けて測る。読み出しは抜き取りで内容(書き込みと同じ模様)を照合し、
 * 食い違いの数を *mismatch へ返す。 */
int  iscsi_ini_bench(int is_read, uint32_t chunk, uint32_t qd, uint32_t runtime_ms,
                     uint64_t *bytes, uint32_t *count, uint32_t *elapsed_ms, uint32_t *mismatch);
/* 通常セッションのログインで CHAP を使う(NULL で解除)。 */
void iscsi_ini_set_chap(const iscsi_chap_cfg_t *cfg);
void iscsi_ini_status(void);

#endif /* ISCSI_INIT_H */
