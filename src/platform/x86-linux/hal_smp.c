// platform/x86-linux/hal_smp.c
//
// SMP / コア間同期(smp.h 契約)の x86-linux 実装(x86-vfio-port Phase 3、
// ~/.claude/plans/x86-vfio-port.md §3 参照)。RPi5 は PSCI CPU_ON でセカンダリ
// コアを起こし MPIDR でコア番号を得る(smp.h の static inline / smp.c)。x86 では
// pthread + pthread_setaffinity_np でワーカスレッドを起こし、コア番号は TLS で
// 持つ。spinlock は smp.h の x86 分岐(C11 __atomic)がインラインで提供する。
//
// 【Phase 3 のスコープ】ここで起こすワーカは、RPi5 の secondary_main()
// (job_scheduler_tick + rxcopy を回すコア処理)ではなく、pthread+affinity が
// 実際に機能することを確認するための最小ハートビートループ。実際の per-core
// ジョブ処理の割り当ては Phase 5(RoCEv2/NVMe-oF データパス)で行う
// (その時点で secondary_main 相当の x86 ワーカへ差し替える)。

/* pthread_setaffinity_np / CPU_SET は _GNU_SOURCE を要する。全 x86 ソース
 * 共通に Makefile の CFLAGS が -D_GNU_SOURCE を渡す(個別ファイルで #define
 * すると -D と二重定義になり警告になるため、ここでは定義しない)。 */
#include "smp.h"
#include "timer.h"
#include "job.h"
#include "netif.h"

#include <pthread.h>
#include <sched.h>
#include <stdint.h>

/* 現在実行中スレッドのコア番号(0=core0=メインスレッド)。メインスレッドは
 * TLS 既定の 0 のまま。ワーカスレッドは起動時に自分の番号を設定する。 */
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

static void set_affinity(unsigned cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    /* 失敗しても致命的ではない(コア数が少ない環境等) -- 論理的な独立動作
     * 自体は affinity 無しでも成立する。 */
    (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

static void *worker_main(void *argp)
{
    worker_arg_t *a = (worker_arg_t *)argp;
    t_core_index = a->core_index;
    set_affinity(a->core_index);

    *a->alive = 1;
    for (;;) {
        (*a->hb)++;
        sim_delay_tick();  /* 性能切り分け用(g_sim_delay_us[1]=core1、原因特定後は0のまま無害) */
        /* RPi5 の secondary_main() 相当: このコアに pin されたジョブを処理する。
         * NVMe-oF RDMA ループバック(nvme_rdma_run_connect_test)は target ジョブを
         * core1 に pin する(nvmer_pin_target_to_core1)ので、core1 が
         * job_scheduler_tick() を回さないと target が処理されずデッドロックする。
         * job が無ければ no-op なので、self-test 等で core1 を起こしただけでも無害。 */
        job_scheduler_tick();
        /* rpi5 の secondary_main() 相当: このコアが owner の net_ctx(例:
         * NVMe/TCP の target を core1 に載せた場合の mlx5-pf1)の RX を idle ループ
         * でも継続的に排出する。net_poll_all_and_dispatch() は owner_core!=自コアの
         * ctx をスキップするので二重 poll にはならない。これが無いと、pf1 の RX が
         * 「core1 のジョブが tcp を触った瞬間」しか処理されず、相手(core0)からの
         * ARP request 等に対する応答が滞る(x86 で NVMe/TCP core-split 時に実際に
         * ARP 解決失敗を踏んだ)。net_ctx が 1 つも登録されていなければ no-op。 */
        net_poll_all_and_dispatch();
    }
    return 0; /* 到達しない */
}

/* PF ごとに 1 度だけ起動する(二重起動しても実害は無いが再起動しない)。 */
static worker_arg_t s_core1_arg;
static pthread_t    s_core1_thr;

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
