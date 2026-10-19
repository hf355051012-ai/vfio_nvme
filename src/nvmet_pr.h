#ifndef NVMET_PR_H
#define NVMET_PR_H

/* 予約(Reservation、IO コマンド 0Dh / 0Eh / 11h / 15h)。
 *
 * 名前空間を共有する複数のホストのうち、誰が書いて(読んで)よいかを取り決める。
 * 振る舞いは Linux の drivers/nvme/target/pr.c に合わせてある(どの場合に
 * Reservation Conflict を返すか、生成番号をいつ増やすか、通知を誰に出すか)。
 *
 * **状態は「ドメイン」(= サブシステム、RAM ディスクの組)の名前空間ごとに 1 つ**で、
 * そのドメインのコントローラ(2 ポートのときの 2 つの実体)の間で共有する。
 * NVMe/TCP(nvmet.c)と NVMe-oF RDMA(nvmet_rdma.c)は別のサブシステムで RAM ディスクも
 * 別なので、ドメインを分ける。登録者はホスト識別子(Connect の hostid、128 ビット)で見分ける。
 * 不揮発には残さない(Identify Namespace の RESCAP bit0 = 0)。
 *
 * このヘッダは nvmet.h / nvmet_rdma.h の両方から読むので、どちらも include しない。 */

#include <stdint.h>

#define NVMET_PR_DOM_TCP   0u
#define NVMET_PR_DOM_RDMA  1u
#define NVMET_PR_DOMAINS   2u
/* 1 ドメインの名前空間の数の上限(nvmet.h の NVMET_NSID_MAX と同じ。nvmet.c で検算する)。 */
#define NVMET_PR_NSID_MAX  2u
/* 1 つの名前空間に登録できるホストの数。 */
#define NVMET_PR_MAX_REGS 16u
/* 通知先として登録できるコントローラの数(TCP 2 + RDMA 2)。 */
#define NVMET_PR_MAX_CTRLS 4u

/* Identify Namespace の RESCAP: 6 種類の予約 + IEKEY の解釈(1.3 の定義)。
 * bit0(Persist Through Power Loss)は持たない。 */
#define NVMET_PR_RESCAP 0xFEu

/* Reservation Notification ログの 1 件(LID=0x80 の 64 バイトに組み立てる)。 */
#define NVMET_PR_LOG_SLOTS 16u
typedef struct {
    uint64_t count;
    uint32_t nsid;
    uint8_t  type;   /* 1 = 登録を奪われた / 2 = 予約が解放された / 3 = 予約を奪われた */
} nvmet_pr_log_t;

/* コントローラ 1 つぶんの、予約に関わる状態。nvmet_ctx_t / nvmet_rdma_ctrl_t に埋め込む。
 * **ログを積むのは予約のコマンドを処理したコア(IO ジョブ)、取り出して AER で知らせるのは
 * admin のジョブ。** 積むのも取り出すのも nvmet_pr.c のロックの中。 */
typedef struct {
    uint8_t  hostid[16];      /* admin の Connect のデータ(offset 0)で受け取ったホスト識別子 */
    volatile int live;        /* 1 = 通常のサブシステムに admin が繋がっている(通知を送ってよい)*/
    uint16_t cntlid;
    uint8_t  domain;
    nvmet_pr_log_t log[NVMET_PR_LOG_SLOTS];
    uint32_t log_head, log_tail;
    uint64_t log_counter;     /* 最後に積んだログの通し番号(0 は使わない)*/
    uint64_t log_lost;        /* 待ち行列が満杯で捨てた数 */
    volatile int aer_notify;  /* 1 = AER で「ログ 0x80 を読め」と知らせたい */
} nvmet_pr_ctrl_t;

/* 予約を持っているホストがいる名前空間は 1(IO の毎コマンドの判定はこれだけ読む)。 */
extern volatile uint8_t g_nvmet_pr_held[NVMET_PR_DOMAINS][NVMET_PR_NSID_MAX];

/* コントローラを通知先として登録する(ターゲットの起動時)。 */
void nvmet_pr_attach(nvmet_pr_ctrl_t *c, uint8_t domain);
/* admin の Connect を受けたとき(通常のサブシステム)。ホスト識別子を控えて通知先にする。 */
void nvmet_pr_connect(nvmet_pr_ctrl_t *c, const uint8_t *hostid16, uint16_t cntlid);
/* セッションの終わりに、溜まった通知を捨てて通知先から外す(登録そのものはホストに付くので残す)。 */
void nvmet_pr_session_reset(nvmet_pr_ctrl_t *c);

/* 予約の 4 コマンドを実行して CQE の status を返す。
 * data / dlen は送られてきたデータ(Register / Acquire / Release)、
 * out は Report の応答の書き込み先(out_max バイト)、*out_len に長さを返す。 */
uint16_t nvmet_pr_execute(nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t opcode, uint32_t cdw10,
                          uint32_t cdw11, const uint8_t *data, uint32_t dlen,
                          uint8_t *out, uint32_t out_max, uint32_t *out_len);

/* 予約の保持者がいるときに、IO コマンドが通ってよいかを判定する。
 * 0 = 通す、それ以外 = 返す status(Reservation Conflict)。 */
uint16_t nvmet_pr_check_access(const nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t opcode);

/* Set / Get Features の FID=0x82(Reservation Notification Mask)。
 * 戻り値は status、*result に DW0 を返す。 */
uint16_t nvmet_pr_set_notify_mask(nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t mask, uint32_t *result);
uint16_t nvmet_pr_get_notify_mask(nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t *result);

/* Get Log Page の LID=0x80 を 1 件取り出して 64 バイトに組み立てる(無ければゼロ)。 */
void nvmet_pr_build_log(nvmet_pr_ctrl_t *c, uint8_t *buf);

/* シェルの `nvmetpr`(ドメインと名前空間ごとの登録者と保持者を表示)。 */
void nvmet_pr_show(void);

#endif /* NVMET_PR_H */
