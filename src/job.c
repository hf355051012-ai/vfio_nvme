// job.c
//
// 明示的ステートマシン用の汎用ジョブ/スケジューラ基盤。設計意図は
// job.hのコメント参照。mallocを使わない環境のため、固定サイズ配列
// (JOB_MAX個)で管理する。
//
// マルチコア化 Phase 4(~/.claude/plans/wondrous-baking-gadget.md参照):
// 他のper-coreモジュール(net_buf.c/timestamp.c等)と異なり、ジョブ
// テーブル(s_jobs[])は単一の共有配列のままにし、smp.hのsmp_spinlock_t
// (s_job_lock)で保護する -- 将来「空いているコアが他コアのジョブを拾って
// 処理する」を実現するにはテーブル自体の共有が前提になるため(ユーザー
// 指示、job.h冒頭のコメント参照)。

#include "job.h"
#include "uart.h"
#include "timer.h"
#include "smp.h"
#include <stddef.h>

static job_t s_jobs[JOB_MAX];
static smp_spinlock_t s_job_lock;

/* ロック順序についての注意(マルチコア化 Phase 5、
 * ~/.claude/plans/wondrous-baking-gadget.md参照): job_list_dump()は
 * s_job_lockを保持したままuart_printf()(pl011.cのUART排他ロックを
 * 内部で取る)を呼ぶ。この一方向のネスト(s_job_lock保持 -> uart_lock
 * 取得)自体はデッドロックを生まない -- uart_printf()側がs_job_lockへ
 * 依存する経路が無い限り安全(現状無い)。ただし将来job.c/pl011.c
 * どちらかに手を入れる際は、この順序を逆転させる(uart_lockを保持した
 * まま何かがs_job_lockを取ろうとする)コードを追加しないこと -- 循環
 * 依存が生まれるとデッドロックになる。 */

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
            /* 既定は「spawnしたコアに固定」(job.h冒頭の「core pinning
             * 機構」コメント参照) -- 既存の呼び出し元(telnet/ping/nvme等、
             * すべてcore0のシェルから生成される)は何もしなくても今まで
             * 通りcore0に留まる。 */
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

int job_request_cancel(unsigned index)
{
    smp_spin_lock(&s_job_lock);
    int ok = (index < JOB_MAX) && s_jobs[index].in_use;
    if (ok) {
        s_jobs[index].cancel_requested = 1;
    }
    smp_spin_unlock(&s_job_lock);
    return ok ? 0 : -1;
}

unsigned job_cancel_all_by_step(job_step_fn step)
{
    smp_spin_lock(&s_job_lock);
    unsigned n = 0;
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (s_jobs[i].in_use && s_jobs[i].step == step) {
            s_jobs[i].cancel_requested = 1;
            n++;
        }
    }
    smp_spin_unlock(&s_job_lock);
    return n;
}

unsigned job_cancel_by_ctx(void *ctx)
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

/* 再入ガード(コアごと)。tcp.cのtcp_recv_internal()が(旧来のブロッキング
 * nvme_exec()経由の待ちのように、job_scheduler_tick()を長時間呼ばない
 * トップレベルシェルコマンドから使われる場合に)自分の内部待ちループから
 * job_scheduler_tick()を呼べるようにするための仕組み(CLAUDE.md
 * 「nvme bench」節参照 -- ConnectX PF0<->PF1ループバックのように
 * クライアント/サーバが同一プロセス内に同居する構成で、クライアント側の
 * 長時間ブロッキング呼び出し中、ジョブ化されたサーバ側(nvmet-io等)が
 * 20秒間まるごとCPUを貰えず応答データを一切処理できない、という実機
 * バグを発見・修正した際に導入した)。ジョブ自身のstep()関数が(telnet/
 * nvmet等の非ブロッキング受信を経由して)このtickの最中に再びtcp_recv_
 * internal()の待ちループへ入り、そこから再度job_scheduler_tick()を
 * 呼ぼうとするケースがあるため、実行中の呼び出しが最後まで終わるまで
 * 追加の呼び出しは即座に何もせず戻る(無限再帰・ジョブの多重tickを
 * 防ぐ)。これはコア固有の呼び出しスタックの再入を防ぐためのものなので、
 * s_job_lock(テーブル全体の排他)とは別にコアごとに独立して持つ --
 * 「あるコアが自分自身の呼び出しスタックの中で再度tickしようとして
 * いないか」であり、他コアの並行tickとは無関係の話のため。 */
static volatile int s_ticking[SMP_MAX_CORES];

/* s_job_lock保持中に呼ぶこと。skip_index自身は除外し、同じ
 * affinity_key(NULLでない)を持つ*他の*in_useジョブが現在claimed
 * (別コアで実行中)かどうかを調べる(job.h冒頭の「affinity_key機構」
 * コメント参照)。O(JOB_MAX)の線形走査だが、JOB_MAX=12と小さいため
 * 無視できるコスト。 */
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
        /* 2026-08-11、実機の`ts`計測(core0/core1が同時にタイトループで
         * job_scheduler_tick()を呼び続けるNVMe/TCP write負荷テスト中、
         * この関数自体が毎回一定約9usかかっていた)で判明した性能問題への
         * 対処: 大半のスロットは空(in_use==0)か他コアにpinned_coreで
         * 固定されており、この関数の呼び出し元(core0/core1)にとって
         * 最初から対象外であることが多い。以前は空スロットであっても
         * 判定のためだけに毎回smp_spin_lock/unlockを行っており、s_job_lock
         * を両コアが同時に奪い合う状況下でこの無駄なロック往復コストが
         * 無視できないボトルネックになっていた。ロックを取る*前*に
         * in_use/pinned_coreだけを見て明らかに対象外のスロットを弾く
         * (ヒントとしてのみ使う、正しさの保証は下のロック内の再チェックが
         * 引き続き担う -- in_useは volatile ではないため他コアの更新が
         * 即座に見える保証は無いが、それは許容できる: 見落としても次回の
         * tickで再度この事前チェックに来るだけで、誤って進んでしまう側
         * [他コアが既にclaimedにした等]は下のロック内チェックが確実に
         * 弾く)。 */
        if (!s_jobs[i].in_use ||
            (s_jobs[i].pinned_core >= 0 && (unsigned)s_jobs[i].pinned_core != core)) {
            continue;
        }

        smp_spin_lock(&s_job_lock);
        if (!s_jobs[i].in_use || s_jobs[i].claimed ||
            (s_jobs[i].pinned_core >= 0 && (unsigned)s_jobs[i].pinned_core != core) ||
            job_affinity_busy_locked(i, s_jobs[i].affinity_key)) {
            /* 使用中でない、既に他コア(もしくは自コアの再入元、ただし
             * 通常はs_tickingで既に弾かれている)が実行中、このコアには
             * ピン止めされていない(job.h冒頭の「core pinning機構」
             * コメント参照)、または同じaffinity_keyを共有する*別の*
             * ジョブが他コアで実行中 -- いずれの場合もこのジョブは
             * ブロックせずスキップし、次のジョブへ進む(job.hのjob_t.
             * claimedコメント参照、1個のジョブ/リソースの完了を他コアが
             * 待つ設計にはしない)。 */
            smp_spin_unlock(&s_job_lock);
            continue;
        }
        s_jobs[i].claimed = 1;
        smp_spin_unlock(&s_job_lock);

        // -> job_spawn()で登録されたstep関数(具体名一覧は job.h の job_step_fn コメント参照:
        //    nvmet_admin_job_step/nvmet_io_job_step/nvme_connect_job_step/rdma_cm_job_step/telnet_job_step 等)
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

void job_delay_ms(uint32_t ms)
{
    uint64_t start = timer_now();
    do {
        job_scheduler_tick();
    } while (!timeout_ms(start, ms));
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

static int job_name_eq(const char *a, const char *b)
{
    unsigned i = 0;
    while (a[i] != '\0' && b[i] != '\0' && a[i] == b[i]) i++;
    return a[i] == '\0' && b[i] == '\0';
}

unsigned job_active_count_excluding(const char *name)
{
    smp_spin_lock(&s_job_lock);
    unsigned n = 0;
    for (unsigned i = 0; i < JOB_MAX; i++) {
        if (s_jobs[i].in_use && !job_name_eq(s_jobs[i].name, name)) n++;
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
