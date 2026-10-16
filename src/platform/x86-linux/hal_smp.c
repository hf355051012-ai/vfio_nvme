#include "smp.h"
#include "timer.h"
#include "job.h"
#include "netif.h"

#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <unistd.h>

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

/*=================================================================
 * 律速要因の切り分け用に、呼び出しコアのメインループへ人為的な遅延を
 * 注入する(シェルの `simdelay <core> <us>` で設定した値ぶんビジーウェイト)。
 * 0 なら何もしない。
 *
 * コール元:
 *   worker_main(), nvme_rdma_run_bench(), nvme_read_pipelined_run(),
 *   nvme_write_pipelined_run()
 * ===============================================================*/
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

/*=================================================================
 * 呼び出しスレッドを指定 CPU へ pin する(pthread_setaffinity_np)。
 *
 * 引数:
 *   cpu - 固定先の論理 CPU 番号
 * コール元:
 *   worker_main()
 * ===============================================================*/
static void set_affinity(unsigned cpu)
{
    /* **コア番号が論理 CPU の数を超えたら折り返す。** OptiPlex(4 CPU)で
     * core4..core8 を起こしたとき、存在しない CPU へ pin しようとして失敗し
     * どこへでも流れるより、決まった CPU に載るほうが測定が再現する
     * (ただし core0..core3 と同じ CPU を分け合うので速くはならない)。 */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0 && cpu >= (unsigned)ncpu) cpu %= (unsigned)ncpu;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

/*=================================================================
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
 * ===============================================================*/
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

/* コアごとに 1 度だけ起動する(二重起動しても実害は無いが再起動しない)。
 * core1..core3 のハートビートと生存フラグは従来の大域変数(smpstat などが読む)、
 * core4 以降はこの配列に持つ。 */
static worker_arg_t      s_core_arg[SMP_MAX_CORES];
static pthread_t         s_core_thr[SMP_MAX_CORES];
static volatile uint64_t s_core_hb[SMP_MAX_CORES];
static volatile int      s_core_alive[SMP_MAX_CORES];

/*=================================================================
 * コア番号からハートビートと生存フラグの置き場を引く。
 *
 * 引数:
 *   core      - 1..SMP_MAX_CORES-1
 *   hb/alive  - 置き場の格納先
 * コール元:
 *   smp_boot_core()
 * ===============================================================*/
static void core_slots(unsigned core, volatile uint64_t **hb, volatile int **alive)
{
    switch (core) {
    case 1u: *hb = &g_core1_heartbeat; *alive = &g_core1_alive; break;
    case 2u: *hb = &g_core2_heartbeat; *alive = &g_core2_alive; break;
    case 3u: *hb = &g_core3_heartbeat; *alive = &g_core3_alive; break;
    default: *hb = &s_core_hb[core];   *alive = &s_core_alive[core]; break;
    }
}

/*=================================================================
 * 指定コアのワーカスレッドを起動する(既に起動済みなら何もしない冪等関数)。
 * 起動後、生存フラグが立つまで最大 2 秒待つ(RPi5 の smp_boot_core1 と同じ規約)。
 *
 * 引数:
 *   core - 1..SMP_MAX_CORES-1(0 はシェル自身なので起こさない)
 * 戻り値:
 *   0=起動済み/成功、-1=範囲外 / pthread 作成失敗 / 起動待ちのタイムアウト
 * コール元:
 *   smp_boot_core1/2/3(), smp_boot_cores_upto()
 * ===============================================================*/
int smp_boot_core(unsigned core)
{
    if (core == 0u || core >= SMP_MAX_CORES) {
        return -1;
    }
    volatile uint64_t *hb;
    volatile int *alive;
    core_slots(core, &hb, &alive);
    if (*alive) {
        return 0; /* 既に起動済み */
    }
    s_core_arg[core].core_index = core;
    s_core_arg[core].hb    = hb;
    s_core_arg[core].alive = alive;
    if (pthread_create(&s_core_thr[core], 0, worker_main, &s_core_arg[core]) != 0) {
        return -1;
    }
    uint64_t start = timer_now();
    while (!*alive) {
        if (timeout_sec(start, 2u)) {
            return -1;
        }
    }
    return 0;
}

/*=================================================================
 * core1..coreN のワーカをまとめて起こす(`netmt N` / `rdmacores N` 用)。
 * **散らす先のコアは、その上にジョブや受信キューを載せる前に起こしておくこと**
 * (起きていないコアへ pin したジョブは誰にも回されず黙って止まる)。
 *
 * 引数:
 *   n - 最後に起こすコア番号(0 / 1 なら core1 だけ)
 * 戻り値:
 *   0=全部成功、-1=どれかが失敗
 * コール元:
 *   shell_dispatch() の netmt / rdmacores、nvmet_rdma_run_standalone()
 * ===============================================================*/
int smp_boot_cores_upto(unsigned n)
{
    if (n < 1u) n = 1u;
    if (n >= SMP_MAX_CORES) return -1;
    for (unsigned c = 1u; c <= n; c++) {
        if (smp_boot_core(c) != 0) return -1;
    }
    return 0;
}

/*=================================================================
 * core1 ワーカスレッドを起動する(smp_boot_core(1) の別名)。
 *
 * 戻り値:
 *   0=起動済み/成功、-1=pthread 作成失敗
 * コール元:
 *   smp_selftest(), shell_dispatch(), shell_ensure_tcp_session(),
 *   nvmer_pin_target_to_core1()
 * ===============================================================*/
int smp_boot_core1(void)
{
    return smp_boot_core(1u);
}

/*=================================================================
 * core2 ワーカスレッドを起動する(smp_boot_core(2) の別名)。
 * **未使用に見えても削除しないこと** -- 一度、未到達関数の一括削除で消して
 * しまい復活させた経緯がある(いまは 2 ポート / iSER / RDMA が呼ぶ)。
 *
 * 戻り値:
 *   0=起動済み/成功、-1=pthread 作成失敗
 * コール元:
 *   nvmet_rdma_run_standalone(), iscsit_iser の起動、2 ポートの起動
 * ===============================================================*/
int smp_boot_core2(void)
{
    return smp_boot_core(2u);
}

/*=================================================================
 * core3 ワーカスレッドを起動する(smp_boot_core(3) の別名)。
 * 削除しない理由は smp_boot_core2() のコメント参照。
 *
 * 戻り値:
 *   0=起動済み/成功、-1=pthread 作成失敗
 * コール元:
 *   (いまは直接の呼び出し元は無い。smp_boot_cores_upto() 経由で起きる)
 * ===============================================================*/
int smp_boot_core3(void)
{
    return smp_boot_core(3u);
}
