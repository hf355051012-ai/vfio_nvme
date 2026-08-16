#include "job.h"
#include "uart.h"
#include "timer.h"
#include "smp.h"
#include <stddef.h>

static job_t s_jobs[JOB_MAX];
static smp_spinlock_t s_job_lock;

job_t *job_spawn(job_step_fn step, void *ctx, const char *name)
{
    smp_spin_lock(&s_job_lock);
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (!s_jobs[i].in_use) {
            s_jobs[i].in_use = 1;
            s_jobs[i].step   = step;
            s_jobs[i].state  = 0;
            s_jobs[i].ctx    = ctx;
            s_jobs[i].name   = name;
            s_jobs[i].cancel_requested = 0;
            s_jobs[i].claimed = 0;
            s_jobs[i].affinity_key = NULL;
            s_jobs[i].pinned_core = (int)smp_core_index();
            smp_spin_unlock(&s_job_lock);
            return &s_jobs[i];
        }
    }
    smp_spin_unlock(&s_job_lock);
    return NULL;
}

/*=================================================================
 * ジョブに affinity key を設定する。同じ key を持つジョブは同時に 1 本しか
 * 実行されない(別コアが既に実行中ならスキップされる)。同一コネクション
 * を触る admin/IO ジョブの同時実行を防ぐために使う。
 *
 * 引数:
 *   job          - 対象ジョブ
 *   affinity_key - 排他の単位を表す任意のポインタ。NULL で排他無し
 * コール元:
 *   nvme_connect_job_start(), nvmet_job_start()
 * ===============================================================*/
void job_set_affinity(job_t *job, void *affinity_key)
{
    if (!job) return;
    smp_spin_lock(&s_job_lock);
    job->affinity_key = affinity_key;
    smp_spin_unlock(&s_job_lock);
}

/*=================================================================
 * ジョブを特定のコアに固定する。以後そのコアの job_scheduler_tick() だけが
 * このジョブを実行する。
 *
 * 引数:
 *   job  - 対象ジョブ
 *   core - 固定先のコア番号
 * コール元:
 *   nvmet_job_start(), nvmer_pin_target_to_core1()
 * ===============================================================*/
void job_pin_to_core(job_t *job, unsigned core)
{
    if (!job) return;
    smp_spin_lock(&s_job_lock);
    job->pinned_core = (int)core;
    smp_spin_unlock(&s_job_lock);
}

static volatile int s_ticking[SMP_MAX_CORES];

/*=================================================================
 * 同じ affinity_key を持つ他のジョブが今どこかのコアで実行中(claimed)かを
 * 調べる。s_job_lock を保持したまま呼ぶこと。
 *
 * 引数:
 *   skip_index - 判定から除外するジョブ(自分自身)のインデックス
 *   key        - 調べる affinity key(NULL なら常に 0)
 * 戻り値:
 *   1=他のジョブが実行中、0=空いている
 * コール元:
 *   job_scheduler_tick()
 * ===============================================================*/
static int job_affinity_busy_locked(unsigned skip_index, void *key)
{
    if (!key) return 0;
    for (unsigned j = 0; j < JOB_MAX; j++) {
        if (j == skip_index) continue;
        if (s_jobs[j].in_use && s_jobs[j].claimed && s_jobs[j].affinity_key == key) {
            return 1;
        }
    }
    return 0;
}

void job_scheduler_tick(void)
{
    unsigned core = smp_core_index();
    if (s_ticking[core]) {
        return;
    }
    s_ticking[core] = 1;

    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (!s_jobs[i].in_use ||
            (s_jobs[i].pinned_core >= 0 && (unsigned)s_jobs[i].pinned_core != core)) {
            continue;
        }

        smp_spin_lock(&s_job_lock);
        if (!s_jobs[i].in_use || s_jobs[i].claimed ||
            (s_jobs[i].pinned_core >= 0 && (unsigned)s_jobs[i].pinned_core != core) ||
            job_affinity_busy_locked(i, s_jobs[i].affinity_key)) {
            smp_spin_unlock(&s_job_lock);
            continue;
        }
        s_jobs[i].claimed = 1;
        smp_spin_unlock(&s_job_lock);

        job_result_t r = s_jobs[i].step(&s_jobs[i]);

        smp_spin_lock(&s_job_lock);
        if (r == JOB_DONE) {
            s_jobs[i].in_use = 0;
        }
        s_jobs[i].claimed = 0;
        smp_spin_unlock(&s_job_lock);
    }

    s_ticking[core] = 0;
}

/*=================================================================
 * 現在ジョブテーブルに登録されている(=完了していない)ジョブ数を返す。
 *
 * 戻り値:
 *   アクティブなジョブ数
 * コール元:
 *   nvme_connect_job_start(), nvmet_job_start()
 * ===============================================================*/
unsigned job_active_count(void)
{
    smp_spin_lock(&s_job_lock);
    unsigned n = 0;
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (s_jobs[i].in_use) n++;
    }
    smp_spin_unlock(&s_job_lock);
    return n;
}

/*=================================================================
 * アクティブなジョブの一覧(名前と state)を表示する。シェルの `jobs`。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void job_list_dump(void)
{
    smp_spin_lock(&s_job_lock);
    unsigned n = 0;
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (s_jobs[i].in_use) n++;
    }
    uart_printf("jobs: %u/%u active\n", n, (unsigned)JOB_MAX);
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (s_jobs[i].in_use) {
            uart_printf("  [%u] %s (state=%d%s, core=%d)\n", i, s_jobs[i].name, s_jobs[i].state,
                        s_jobs[i].claimed ? ", running" : "", s_jobs[i].pinned_core);
        }
    }
    smp_spin_unlock(&s_job_lock);
}
