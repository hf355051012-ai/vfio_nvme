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

void job_set_affinity(job_t *job, void *affinity_key)
{
    if (!job) return;
    smp_spin_lock(&s_job_lock);
    job->affinity_key = affinity_key;
    smp_spin_unlock(&s_job_lock);
}

void job_pin_to_core(job_t *job, unsigned core)
{
    if (!job) return;
    smp_spin_lock(&s_job_lock);
    job->pinned_core = (int)core;
    smp_spin_unlock(&s_job_lock);
}

static volatile int s_ticking[SMP_MAX_CORES];

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
