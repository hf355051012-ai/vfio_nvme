#ifndef JOB_H
#define JOB_H

#include <stdint.h>

#define JOB_MAX 12u

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
};

job_t *job_spawn(job_step_fn step, void *ctx, const char *name);

void job_set_affinity(job_t *job, void *affinity_key);

void job_pin_to_core(job_t *job, unsigned core);

void job_scheduler_tick(void);

/* 現在アクティブなジョブ数。 */
unsigned job_active_count(void);

void job_list_dump(void);

#endif /* JOB_H */
