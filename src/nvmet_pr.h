#ifndef NVMET_PR_H
#define NVMET_PR_H

/* 予約(Reservation、IO コマンド 0Dh / 0Eh / 11h / 15h)。
 *
 * 名前空間を共有する複数のホストのうち、誰が書いて(読んで)よいかを取り決める。
 * 振る舞いは Linux の drivers/nvme/target/pr.c に合わせてある(どの場合に
 * Reservation Conflict を返すか、生成番号をいつ増やすか、通知を誰に出すか)。
 *
 * **状態は名前空間ごとに 1 つで、コントローラ(2 ポートのときの 2 つの実体)の
 * 間で共有する。** 登録者はホスト識別子(Connect の hostid、128 ビット)で見分ける。
 * 不揮発には残さない(Identify Namespace の RESCAP bit0 = 0)。 */

#include <stdint.h>
#include "nvmet.h"
#include "nvme_types.h"

/* 1 つの名前空間に登録できるホストの数。 */
#define NVMET_PR_MAX_REGS 16u

/* Identify Namespace の RESCAP: 6 種類の予約 + IEKEY の解釈(1.3 の定義)。
 * bit0(Persist Through Power Loss)は持たない。 */
#define NVMET_PR_RESCAP 0xFEu

/* 予約を持っているホストがいる名前空間は 1(IO の毎コマンドの判定はこれだけ読む)。 */
extern volatile uint8_t g_nvmet_pr_held[NVMET_NSID_MAX];

/* ターゲットの実体を通知先として登録する(nvmet_job_start() から)。 */
void nvmet_pr_attach(nvmet_ctx_t *ctx);
/* セッションの終わりに、その実体に溜まった通知を捨てる。 */
void nvmet_pr_session_reset(nvmet_ctx_t *ctx);

/* 予約の 4 コマンドを実行して CQE の status を返す。
 * data / dlen は in-capsule のデータ(Register / Acquire / Release)、
 * out は Report の応答の書き込み先(4096 バイト)、*out_len に長さを返す。 */
uint16_t nvmet_pr_execute(nvmet_ctx_t *ctx, uint32_t nsid, const nvme_sqe_t *sqe,
                          const uint8_t *data, uint32_t dlen, uint8_t *out, uint32_t *out_len);

/* 予約の保持者がいるときに、IO コマンドが通ってよいかを判定する。
 * 0 = 通す、それ以外 = 返す status(Reservation Conflict)。 */
uint16_t nvmet_pr_check_access(const nvmet_ctx_t *ctx, uint32_t nsid, uint32_t opcode);

/* Set / Get Features の FID=0x82(Reservation Notification Mask)。
 * 戻り値は status、*result に DW0 を返す。 */
uint16_t nvmet_pr_set_notify_mask(nvmet_ctx_t *ctx, uint32_t nsid, uint32_t mask, uint32_t *result);
uint16_t nvmet_pr_get_notify_mask(nvmet_ctx_t *ctx, uint32_t nsid, uint32_t *result);

/* Get Log Page の LID=0x80 を 1 件取り出して 64 バイトに組み立てる(無ければゼロ)。 */
void nvmet_pr_build_log(nvmet_ctx_t *ctx, uint8_t *buf);

/* シェルの `nvmetpr`(名前空間ごとの登録者と保持者を表示)。 */
void nvmet_pr_show(void);

#endif /* NVMET_PR_H */
