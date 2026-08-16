#include "smp.h"
#include "timer.h"
#include "job.h"
#include "netif.h"

#include <pthread.h>
#include <sched.h>
#include <stdint.h>

static __thread unsigned t_core_index = 0u;

unsigned smp_core_index(void)
{
    return t_core_index;
}

/* smp.h 契約の可視状態(単一ライタ=当該コア、複数リーダ=smpstat 等)。 */
volatile uint64_t g_core1_heartbeat = 0;
volatile int      g_core1_alive     = 0;
volatile uint64_t g_core2_heartbeat = 0;
volatile int      g_core2_alive     = 0;
volatile uint64_t g_core3_heartbeat = 0;
volatile int      g_core3_alive     = 0;

/* 性能分析用のコア別注入遅延(smp.h 参照)。 */
volatile uint32_t g_sim_delay_us[SMP_MAX_CORES] = { 0 };

/*
 * 律速要因の切り分け用に、呼び出しコアのメインループへ人為的な遅延を
 * 注入する(シェルの `simdelay <core> <us>` で設定した値ぶんビジーウェイト)。
 * 0 なら何もしない。
 *
 * コール元:
 *   worker_main(), nvme_rdma_run_bench(), nvme_read_pipelined_run(),
 *   nvme_write_pipelined_run()
 */
void sim_delay_tick(void)
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) {
        return; /* core2(コピー専任、SMP_MAX_CORES 外)は注入対象にしない */
    }
    uint32_t us = g_sim_delay_us[core];
    if (us == 0u) {
        return;
    }
    uint64_t start = timer_now();
    while (!timeout_us(start, us)) {
        /* 純粋なビジーウェイト(ネットワークポーリング等は呼ばない) */
    }
}

/* ------------------------------------------------------------------ */
/* ワーカスレッド起動(pthread + CPU affinity)                          */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned core_index;      /* このワーカのコア番号(TLS へ設定) */
    volatile uint64_t *hb;    /* ハートビートカウンタ */
    volatile int      *alive; /* 生存フラグ */
} worker_arg_t;

/*
 * 呼び出しスレッドを指定 CPU へ pin する(pthread_setaffinity_np)。
 *
 * 引数:
 *   cpu - 固定先の論理 CPU 番号
 * コール元:
 *   worker_main()
 */
static void set_affinity(unsigned cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

/*
 * core1 ワーカスレッドの本体。自分の CPU へ pin した後、
 * job_scheduler_tick() と net_poll_all_and_dispatch() を回し続ける
 * (core1 に pin されたジョブと、core1 が owner のインターフェースを処理する)。
 *
 * 引数:
 *   argp - コア番号を渡す引数ブロック
 * 戻り値:
 *   常に NULL(戻らない)
 * コール元:
 *   smp_boot_core1() から pthread_create の関数ポインタとして
 */
static void *worker_main(void *argp)
{
    worker_arg_t *a = (worker_arg_t *)argp;
    t_core_index = a->core_index;
    set_affinity(a->core_index);

    *a->alive = 1;
    for (;;) {
        (*a->hb)++;
        sim_delay_tick();  /* 性能切り分け用(g_sim_delay_us[1]=core1、原因特定後は0のまま無害) */
        job_scheduler_tick();
        net_poll_all_and_dispatch();
    }
    return 0; /* 到達しない */
}

/* PF ごとに 1 度だけ起動する(二重起動しても実害は無いが再起動しない)。 */
static worker_arg_t s_core1_arg;
static pthread_t    s_core1_thr;

/*
 * core1 ワーカスレッドを起動する(既に起動済みなら何もしない冪等関数)。
 * 起動後、ハートビートが進み始めるまで待つ。
 *
 * 戻り値:
 *   0=起動済み/成功、-1=pthread 作成失敗
 * コール元:
 *   smp_selftest(), shell_dispatch(), shell_ensure_tcp_session(),
 *   nvmer_pin_target_to_core1()
 */
int smp_boot_core1(void)
{
    if (g_core1_alive) {
        return 0; /* 既に起動済み */
    }
    s_core1_arg.core_index = 1u;
    s_core1_arg.hb    = &g_core1_heartbeat;
    s_core1_arg.alive = &g_core1_alive;
    if (pthread_create(&s_core1_thr, 0, worker_main, &s_core1_arg) != 0) {
        return -1;
    }
    /* g_core1_alive が立つまで最大 2 秒待つ(RPi5 の smp_boot_core1 と同じ規約)。 */
    uint64_t start = timer_now();
    while (!g_core1_alive) {
        if (timeout_sec(start, 2u)) {
            return -1;
        }
    }
    return 0;
}
