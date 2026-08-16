// smp.c
//
// マルチコア化 Phase 2(セカンダリコア用Cコード実行環境の確立、
// ~/.claude/plans/wondrous-baking-gadget.md参照)。

#include "smp.h"
#include "mmu.h"
#include "exceptions.h"
#include "pl011.h"
#include "psci.h"
#include "timer.h"
#include "job.h"
#include "netctx.h"
#include "rxcopy.h"

extern pl011_t debug_uart; // main.cで初期化

// command.cのcmd_cpuon()と同じパターン(boot.S側の.globalラベルをリンカ
// シンボルとして参照)。
extern char secondary_entry[];

volatile uint64_t g_core1_heartbeat = 0;
volatile int g_core1_alive = 0;

/* 3コア化: RXコピーオフロード専任のcore2用(smp.h参照)。 */
volatile uint64_t g_core2_heartbeat = 0;
volatile int g_core2_alive = 0;

/* 2026-08-11、性能切り分け用の一時計装(smp.hのg_sim_delay_us/
 * sim_delay_tick()コメント参照、原因特定後に削除すること)。 */
volatile uint32_t g_sim_delay_us[SMP_MAX_CORES];

void sim_delay_tick(void)
{
    uint32_t us = g_sim_delay_us[smp_core_index()];
    if (us == 0u) {
        return;
    }
    uint64_t start = timer_now();
    while (!timeout_us(start, us)) {
        /* 意図的な純粋ビジーウェイト -- tcp_poll_once()等は一切呼ばない
         * (呼ぶとこの遅延の間もネットワーク処理が進んでしまい、
         * 「このコアのクロックが遅い」という模擬にならない)。 */
    }
}

int smp_boot_core1(void)
{
    if (g_core1_alive) {
        return 0; // 既に起動済み(前回のcpuon/platform_init等)
    }

    // BCM2712はMPIDRのAffinity 0が全コア0固定、コア番号はAffinity 1
    // (bits[15:8])にエンコードされる非標準構成(Phase 1で実機確認済み、
    // command.cのcmd_cpuon()と同じ値)。
    uint64_t target_cpu = 1u << 8;
    int64_t ret = psci_cpu_on(target_cpu, (uint64_t)secondary_entry, 0u);
    if (ret != 0 && ret != -4 /* ALREADY_ON: 別経路で既に起動要求済み */) {
        return -1;
    }

    uint64_t start = timer_now();
    while (!g_core1_alive) {
        if (timeout_ms(start, 2000u)) { // 2秒
            return -1; // secondary_main()がidle loop手前まで到達しなかった
        }
    }
    return 0;
}

/* 3コア化: core2(コピー専任)をPSCI CPU_ONで起動する。smp_boot_core1()と
 * 全く同じ構造で、target_cpuのAff1だけが2(bits[15:8]=2)になる。core2は
 * secondary_entry(boot.S)でAff1=2を見て__stack3_topを選び、secondary_main()の
 * core2分岐(コピー専任ループ)へ入る。 */
int smp_boot_core2(void)
{
    if (g_core2_alive) {
        return 0; // 既に起動済み
    }
    uint64_t target_cpu = 2u << 8;
    int64_t ret = psci_cpu_on(target_cpu, (uint64_t)secondary_entry, 0u);
    if (ret != 0 && ret != -4 /* ALREADY_ON */) {
        return -1;
    }
    uint64_t start = timer_now();
    while (!g_core2_alive) {
        if (timeout_ms(start, 2000u)) {
            return -1;
        }
    }
    return 0;
}

// secondary_entry(src/boot.S)からbl一発で呼ばれる。専用Cスタック
// (__stack2_top)は既に設定済み。
void secondary_main(void)
{
    mmu_init_secondary();

    // マルチコア化 Phase 5(~/.claude/plans/wondrous-baking-gadget.md
    // 参照): pl011_lock_reset()はmmu_init_secondary()の直後(core1自身の
    // MMU/キャッシュがcore0のマッピングと一致した状態が確実になった
    // 時点)で呼ぶこと -- これより前にUART排他ロック(pl011.cの
    // s_uart_lock、通常のNormal cacheable RAM)へ触れると、core1がまだ
    // 自分のMMU/キャッシュを有効化していない状態でアクセスすることになり、
    // core0側のキャッシュ済みビューとのコヒーレンシが保証されない
    // (このプロジェクトの「MMU有効時はキャッシュコヒーレント相互接続に
    // 依存する」設計全体の前提が崩れる)。
    //
    // このリセットが必要な理由: secondary_entry(boot.S)はcore0の
    // primary_coreと異なり`.bss`をゼロクリアしない(Phase 2「実機で
    // 踏んだ罠」節参照)。もしcore1が以前このロックを保持したまま例外を
    // 起こしsecondary_entryへ再入した場合、ロックは「保持されたまま」
    // 取り残され、以後core0のuart_printf()呼び出しが永久にこのロックの
    // 解放を待ち続ける(core1の1回の例外がシステム全体のUART出力を
    // 道連れに恒久停止させる、という重大な退行になる)。secondary_main()の
    // 再入のたびに無条件でリセットすることでこの経路を断つ
    // (pl011.cのpl011_lock_reset()コメント参照)。
    pl011_lock_reset();

    // VBAR_EL2はコアごとのレジスタなので、core0と同じvector_table
    // (vectors.S)をcore1自身にも設定する必要がある -- exceptions_init()
    // 自体はコア非依存の関数で、core0のmain()と全く同じものをそのまま
    // 呼ぶだけでよい(「exceptions_init()共有」、計画のPhase 2節参照)。
    exceptions_init();

    // 役割の分岐: core2(Aff1=2)はRXコピーオフロード専任、それ以外(core1)は
    // ターゲット本体(nvmet処理)。3コア化の要点は「重いコピーをcore1(target
    // 本体)から完全に切り離してcore2へ移す」こと -- 以前はcore1がtargetと
    // コピーの両方を担い、job/net_poll走査とコピーが同一コアで競合していた
    // (だから1024周回に1回へ間引く回避策が必要だった)。core2をコピー専任に
    // 分離したことで、core1は毎周回job/net_pollを回す純粋なtargetループに、
    // core2はrxcopy_worker_drain()だけを回すコピーループになり、間引きが
    // 不要になった。
    unsigned idx = smp_core_index();

    // pl011_lock()/pl011_unlock()でこの1回きりの起動完了通知を
    // アトミックな出力単位にする -- core0が同時にuart_printf()で
    // 出力していても文字が混線しない。
    pl011_lock();
    if (idx == 2u) {
        pl011_puts(&debug_uart, "[core2] secondary_main: ready, RX copy-offload worker loop.\n");
    } else {
        pl011_puts(&debug_uart, "[core1] secondary_main: MMU/vectors ready, entering target loop.\n");
    }
    pl011_unlock();

    if (idx == 2u) {
        // ================= core2: RXコピーオフロード専任 =================
        // rxcopy_worker_drain()以外は一切呼ばない -- per-core配列
        // (SMP_MAX_CORES=2のまま、g_sim_delay_us/net_buf/tcp/timestamp/job等)を
        // smp_core_index()==2で添字するとOOBになるため、それらに触れる関数
        // (sim_delay_tick()/job_scheduler_tick()/net_poll_all_and_dispatch()/
        // ts_log()等)はこのループから絶対に呼ばないこと。rxcopy_worker_drain()は
        // モジュールstatic(s_ring/s_head/s_done、per-coreではない)と
        // volatile_fast_copyのみを触るため安全。
        g_core2_alive = 1;
        for (;;) {
            g_core2_heartbeat++;
            rxcopy_worker_drain();
        }
    }

    // ================= core1: ターゲット本体(nvmet処理) =================
    // 【マルチコア化 Phase 6】core0のcommand_shell_run()メインループと
    // 同じ2つの呼び出し(job_scheduler_tick()/net_poll_all_and_dispatch())
    // をここでも回す -- job.cの共有ジョブテーブルはコアを問わず同じ
    // API/同じロックで保護されているため、core1がこれを呼ぶために
    // 追加の配線は不要(pinned_core!=1のジョブは自動的にスキップ)。
    // net_poll_all_and_dispatch()も同様に、owner_core==1のnet_ctx_t
    // (platform_init.c/test.c/nvmetがcore1へ引き渡したPF1)だけをポーリング
    // する。コピーはcore2へ移したので、ここではrxcopy_worker_drain()は
    // 呼ばない(間引きも不要、毎周回job/net_pollを回す純粋なtargetループ)。
    g_core1_alive = 1;
    for (;;) {
        g_core1_heartbeat++;
        sim_delay_tick();  /* 2026-08-11、性能切り分け用の一時計装(smp.h参照) */
        job_scheduler_tick();
        net_poll_all_and_dispatch();
    }
}
