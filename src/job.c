#include "job.h"
#include "uart.h"
#include "timer.h"
#include "smp.h"
#include <stddef.h>

static job_t s_jobs[JOB_MAX];
static smp_spinlock_t s_job_lock;

/* park(眠っているジョブをロック無しで飛ばす)を効かせるか。**0 にすると
 * park を入れる前とまったく同じ挙動**になる恒久的な陰性対照(`jobpark off`)。
 * この環境の A/B は交互に測らないと当てにならないので、ビルドを差し替えずに
 * 同一セッション内で切り替えられるようにしてある。 */
volatile int g_job_park_enable = 1;

/* park で飛ばした step の回数と、実際に呼んだ step の回数(`jobpark` で表示)。
 * **「本当に飛んでいるか」を見る唯一の手段**なので消さないこと。
 *
 * **コアごとに 64 バイト空けて置く。** 共有の 1 変数にすると、この計装自身が
 * コア間でキャッシュラインを往復させて、測ろうとしている効果を潰す
 * (`tcp_copy_stats` と同じ理由)。 */
typedef struct {
    /* **volatile が要る。** 素の uint64_t にすると、コンパイラが巡回ループの
     * 中の連続した `++` をレジスタにまとめて最後に 1 回だけ書き戻す。
     * すると `jobpark clear` で 0 にした直後に、他コアが**古い値を書き戻して
     * 復活させる**(実機で「clear した直後に 4.8 億」と表示されて気付いた)。 */
    volatile uint64_t park_skips;
    volatile uint64_t steps;
    uint8_t           pad[48];
} job_stat_t;
static job_stat_t s_job_stat[SMP_MAX_CORES] __attribute__((aligned(64)));

/* **実際に使っている枠の上限(+1)。** `job_scheduler_tick()` は毎 tick
 * ここまでしか走査しない。**JOB_MAX まで舐めると、上限を上げただけで
 * ポーリング 1 周が延びる** -- job_t は 1 枠 1 キャッシュラインなので、
 * JOB_MAX を 16 -> 32 にしたとき RDMA の 512B write(ポーリング周期に
 * いちばん敏感な条件)が 339k -> 267k に落ちた。**上限と costs を
 * 切り離すこと。** 書き換えは s_job_lock の中だけ。 */
static volatile unsigned s_job_high;

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
            s_jobs[i].idle   = 0;
            s_jobs[i].wake_a = NULL;
            s_jobs[i].wake_b = NULL;
            if (i + 1u > s_job_high) s_job_high = i + 1u;
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

/*=================================================================
 * 自分を眠らせる。以後スケジューラは、起床条件(wake_a != wake_b)が立つか
 * JOB_IDLE_TICK_DIVISOR 回に 1 回になるまで step を呼ばない。
 *
 * **ジョブ自身の step() から呼ぶこと。** そのジョブは claim 済み
 * (= 他コアは触らない)かつ 1 コアに pin されているので、ロック無しの
 * 素の書き込みでよい。**idle は最後に立てる** -- 先に立てると、
 * まだ古い wake ポインタを指したままの瞬間をスケジューラが読みうる。
 *
 * 引数:
 *   job            - 対象ジョブ(step の self)
 *   wake_a, wake_b - 即時起床条件。両方非 NULL で値が違えば起こす(不要なら NULL)
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
void job_park(job_t *job, const volatile uint32_t *wake_a, const volatile uint32_t *wake_b)
{
    if (!job) return;
    job->wake_a = wake_a;
    job->wake_b = wake_b;
    __asm__ volatile("" ::: "memory");
    job->idle = 1;
}

/*=================================================================
 * 自分を起こす(毎 tick step される状態へ戻す)。眠っていないときは何も
 * 書かない -- 毎 tick 呼ばれる想定なので、無駄にキャッシュラインを
 * 汚さないようにしてある。
 *
 * 引数:
 *   job - 対象ジョブ(step の self)
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
void job_unpark(job_t *job)
{
    if (!job || !job->idle) return;
    job->idle   = 0;
    job->wake_a = NULL;
    job->wake_b = NULL;
}

static volatile int s_ticking[SMP_MAX_CORES];
static uint32_t     s_tick_count[SMP_MAX_CORES];

/* affinity_key を持ったまま claim されているジョブの数(s_job_lock 下でのみ
 * 触る)。0 のあいだは job_affinity_busy_locked() の全走査を丸ごと飛ばせる。
 * 走査は 16 スロット = 16 キャッシュラインを舐めるので、実行中のジョブ 1 本
 * につき毎 tick それだけの参照が乗っていた。 */
static unsigned s_affinity_claimed;

/*=================================================================
 * 眠っているジョブを今回の tick で走らせるかを、ロックを取らずに判定する。
 *
 * 引数:
 *   j    - 対象ジョブ
 *   tick - このコアの tick 通番
 * 戻り値:
 *   1=走らせる、0=飛ばす
 * コール元:
 *   job_scheduler_tick()
 * ===============================================================*/
static int job_idle_should_run(const job_t *j, uint32_t tick)
{
    if (j->cancel_requested) return 1;
    const volatile uint32_t *a = j->wake_a;
    const volatile uint32_t *b = j->wake_b;
    if (a && b && *a != *b) return 1;
    return (tick & (JOB_IDLE_TICK_DIVISOR - 1u)) == 0u;
}

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
    if (!key || s_affinity_claimed == 0) return 0;
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
    uint32_t tick = ++s_tick_count[core];

    unsigned high = s_job_high;
    for (unsigned i = 0; i < high; i++) {
        if (!s_jobs[i].in_use ||
            (s_jobs[i].pinned_core >= 0 && (unsigned)s_jobs[i].pinned_core != core)) {
            continue;
        }
        /* **眠っているジョブは s_job_lock を取らずに飛ばす。** ここでロックを
         * 取ると、そのキャッシュラインが tick を回している全コアの間を往復し、
         * 受信ポーリングの 1 周がジョブ本数に比例して延びる(接続していない
         * IO キューを上限ぶん spawn する nvmet でこれが効く)。 */
        if (s_jobs[i].idle && g_job_park_enable &&
            !job_idle_should_run(&s_jobs[i], tick)) {
            s_job_stat[core].park_skips++;
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
        /* step() の中で job_set_affinity() を呼ばれても数が狂わないよう、
         * 増やしたかどうかをローカルに覚えておく。 */
        int aff_counted = (s_jobs[i].affinity_key != NULL);
        if (aff_counted) s_affinity_claimed++;
        smp_spin_unlock(&s_job_lock);

        s_job_stat[core].steps++;
        job_result_t r = s_jobs[i].step(&s_jobs[i]);

        smp_spin_lock(&s_job_lock);
        if (r == JOB_DONE) {
            s_jobs[i].in_use = 0;
            s_jobs[i].idle   = 0;
            /* 末尾が空いたら上限を詰め直す(空いた枠が中間なら据え置き)。 */
            while (s_job_high > 0u && !s_jobs[s_job_high - 1u].in_use) s_job_high--;
        }
        if (aff_counted) s_affinity_claimed--;
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
 * 指定の ctx を参照しているジョブへ停止を要求する。
 *
 * **ジョブの ctx をゼロクリア/再初期化する前にこれを呼び、job_count_by_ctx()
 * が 0 になるまで待つこと。** RDMA の CM ジョブは他コア(core1)で走っている
 * ので、待たずに ctx を潰すと gsi_qp が NULL になった瞬間を踏んで落ちる
 * (実機で segfault: mlx5_qp_poll_cqe_gsi+0xf)。
 *
 * 引数:
 *   ctx - job_spawn() に渡したコンテキストのアドレス
 * 戻り値:
 *   停止を要求したジョブ数
 * コール元:
 *   nvmer_quiesce_jobs()
 * ===============================================================*/
unsigned job_cancel_by_ctx(const void *ctx)
{
    smp_spin_lock(&s_job_lock);
    unsigned n = 0;
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (s_jobs[i].in_use && s_jobs[i].ctx == ctx) {
            s_jobs[i].cancel_requested = 1;
            n++;
        }
    }
    smp_spin_unlock(&s_job_lock);
    return n;
}

/*=================================================================
 * 指定の ctx を参照しているアクティブなジョブ数。
 *
 * 引数:
 *   ctx - job_spawn() に渡したコンテキストのアドレス
 * 戻り値:
 *   まだ居るジョブ数(0 なら ctx を触ってよい)
 * コール元:
 *   nvmer_quiesce_jobs()
 * ===============================================================*/
unsigned job_count_by_ctx(const void *ctx)
{
    smp_spin_lock(&s_job_lock);
    unsigned n = 0;
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (s_jobs[i].in_use && s_jobs[i].ctx == ctx) n++;
    }
    smp_spin_unlock(&s_job_lock);
    return n;
}

/*=================================================================
 * park の効き具合を表示する(シェルの `jobpark`)。飛ばした回数と実際に
 * step した回数の比が、そのまま「未接続の IO キューがどれだけ空回りして
 * いたか」になる。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void job_park_stats_dump(void)
{
    uint64_t skips = 0, steps = 0;
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        skips += s_job_stat[c].park_skips;
        steps += s_job_stat[c].steps;
    }
    uart_printf("jobpark: %s (周期=%u tick)\n",
                g_job_park_enable ? "on" : "off", (unsigned)JOB_IDLE_TICK_DIVISOR);
    uint64_t total = steps + skips;
    uart_printf("  step 実行 %llu 回 / park で回避 %llu 回 (回避率 %llu.%llu%%)\n",
                (unsigned long long)steps, (unsigned long long)skips,
                (unsigned long long)(total ? skips * 100u / total : 0u),
                (unsigned long long)(total ? (skips * 1000u / total) % 10u : 0u));
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        if (s_job_stat[c].steps || s_job_stat[c].park_skips) {
            uart_printf("  core%u: step %llu / 回避 %llu\n", c,
                        (unsigned long long)s_job_stat[c].steps,
                        (unsigned long long)s_job_stat[c].park_skips);
        }
    }
}

/*=================================================================
 * park の統計を 0 に戻す(A/B の一方を測り始める前に叩く)。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void job_park_stats_clear(void)
{
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        s_job_stat[c].park_skips = 0;
        s_job_stat[c].steps      = 0;
    }
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
            uart_printf("  [%u] %s (state=%d%s%s, core=%d)\n", i, s_jobs[i].name, s_jobs[i].state,
                        s_jobs[i].claimed ? ", running" : "",
                        s_jobs[i].idle ? ", idle" : "", s_jobs[i].pinned_core);
        }
    }
    smp_spin_unlock(&s_job_lock);
}
