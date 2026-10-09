#ifndef JOB_H
#define JOB_H

#include <stdint.h>

/* nvmet が admin 1 + IO キュー NVMET_IO_QUEUES(4)= 5 枠使うので、RDMA 側や
 * 内蔵イニシエータと同時に立てても足りるだけの余裕を持たせてある。 */
/* nvmet の admin 1 + IO 16、nvmet-rdma の standalone 1 + IO 4 + CM 1 で 23。 */
#define JOB_MAX 32u

/* 眠っている(park した)ジョブを念のため step する周期。job_scheduler_tick()
 * の呼び出し回数で数える。**2 の冪であること**(マスクで判定する)。
 *
 * 起床条件を取りこぼしても必ずこの周期で拾えるので、park は「見落とすと
 * 二度と起きない」形にはならない。逆に言えば park で失われるのは最大
 * この周期ぶんの反応時間だけ(受信ループ 1 周が 60〜100ns 程度なので
 * 256 周でも 25us 前後。接続確立やタイムアウトの ms スケールに対して無害)。 */
#define JOB_IDLE_TICK_DIVISOR 256u

typedef enum {
    JOB_WAITING = 0,  /* まだ完了していない、次tickでまたstep()を呼んでほしい */
    JOB_DONE    = 1,  /* このtickで完了した(呼び出し元がJOB_DONEを返した時点でスケジューラが自動的にキューから外す) */
} job_result_t;

typedef struct job job_t;

typedef job_result_t (*job_step_fn)(job_t *self);

struct job {
    int         in_use;
    job_step_fn step;   /* 次に呼ぶステップ関数 */
    int         state;  /* ジョブ固有のstate(呼び出し元がswitchで解釈する、0で初期化される) */
    void       *ctx;    /* ジョブ固有のコンテキスト(呼び出し元がstatic領域等で確保すること -- mallocなし環境) */
    const char *name;   /* `jobs`コマンド等の診断表示用 */
    volatile int cancel_requested;
    volatile int claimed;
    void *affinity_key;
    int pinned_core;
    /* 1=眠っている。スケジューラは起床条件が立つか JOB_IDLE_TICK_DIVISOR 回に
     * 1 回になるまで step を呼ばない。**判定はロックを取らずに行う**ので、
     * 眠っているジョブのコストは 2〜3 回のロードだけになる。
     *
     * これが無いと、接続していない IO キュー(nvmet は上限ぶんジョブを
     * spawn して余りを待機させる)が毎 tick s_job_lock を 2 回取り、
     * そのキャッシュラインがコア間を往復して**受信ポーリングの周期が
     * ジョブ本数に比例して延びる**。 */
    volatile int idle;
    /* 即時の起床条件。両方が非 NULL で値が食い違えば次の tick で必ず起こす。
     * ready-ring の head/tail を指させると「コマンドが届いた」で起きる
     * (取りこぼしても JOB_IDLE_TICK_DIVISOR で拾えるので lost wakeup は無い)。 */
    const volatile uint32_t *wake_a;
    const volatile uint32_t *wake_b;
};

job_t *job_spawn(job_step_fn step, void *ctx, const char *name);

void job_set_affinity(job_t *job, void *affinity_key);

void job_pin_to_core(job_t *job, unsigned core);

/* 自分を眠らせる / 起こす。**ジョブ自身の step() から呼ぶこと**(呼び出し中は
 * そのジョブを claim しているので、ロック無しで書いてよい)。
 * wake_a/wake_b は即時に起こしたい条件(不要なら両方 NULL)。 */
void job_park(job_t *job, const volatile uint32_t *wake_a, const volatile uint32_t *wake_b);
void job_unpark(job_t *job);

void job_scheduler_tick(void);

/* 現在アクティブなジョブ数。 */
unsigned job_active_count(void);

/* 指定の ctx を参照しているアクティブなジョブへ停止を要求する(戻り値=要求した数)。
 * **ジョブの ctx を作り直したりゼロクリアする前に必ず呼ぶこと。** 他コアで
 * 走っているジョブが古い ctx を触り続けると NULL を踏んで落ちる。 */
unsigned job_cancel_by_ctx(const void *ctx);

/* 指定の ctx を参照しているアクティブなジョブの数(0 になれば触ってよい)。 */
unsigned job_count_by_ctx(const void *ctx);

void job_list_dump(void);

/* park の有効/無効(`jobpark on|off`)。**0 が park を入れる前の挙動**という
 * 恒久的な陰性対照。**戻し忘れると未接続の IO キューが毎 tick 空回りする。** */
extern volatile int g_job_park_enable;

void job_park_stats_dump(void);
void job_park_stats_clear(void);

#endif /* JOB_H */
