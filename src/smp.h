#ifndef SMP_H
#define SMP_H

#include <stdint.h>

/* ================================================================
 * HAL 契約: SMP / コア間同期(x86-vfio-port の platform 継ぎ目、
 * ~/.claude/plans/x86-vfio-port.md §3 参照)。core の rxcopy/job/smp_core_index
 * 参照がこれに依存する。下記は RPi5 実装(PSCI CPU_ON によるコア起動、MPIDR
 * によるコア番号、LDAXR/STXR + WFE スピンロック、release/acquire は stlr/ldar)。
 * x86-linux では pthread + pthread_setaffinity_np でコアを起こし、smp_core_index
 * は TLS、スピンロックは pthread_spinlock / C11 atomics に差し替わる(VxWorks は
 * taskSpawn + CPU affinity)。SMP_MAX_CORES/関数シグネチャは platform で実装差
 * があってよいが、core から見た契約(コア番号・排他・release/acquire)は保つ。
 * ================================================================ */

/* ================================================================
 * smp.h — マルチコア化 Phase 2(セカンダリコア用Cコード実行環境の確立)
 * ~/.claude/plans/wondrous-baking-gadget.md 参照。
 *
 * src/boot.Sのsecondary_entry(PSCI CPU_ON経由でcore1として起動される、
 * または例外リカバリでcore1が再入する)が専用Cスタックを設定した直後に
 * secondary_main()を呼ぶ。secondary_main()はcore1自身のMMU
 * (mmu_init_secondary())と例外ベクタ(exceptions_init()、core0と
 * 共有する同一関数)を設定した後、ハートビートカウンタを刻む空ループへ
 * 入る(戻らない)。Phase 6でnvmet.c等の実処理をcore1へ割り当てる予定
 * だが、それまではこの空ループのまま。
 * ================================================================ */

// secondary_entry(src/boot.S)から呼ばれるcore1用のCエントリポイント。
// 戻らない。
void secondary_main(void);

// core1がsecondary_main()の空ループ内で増分し続ける、ロック無しの単調
// カウンタ。Phase 6で計画済みの「ハートビートカウンタ」をPhase 2の時点で
// 前倒しで導入した -- cpuon(Phase 1)のUART出力はtelnetからは見えない
// という罠(~/.claude/plans/wondrous-baking-gadget.md「実機で踏んだ罠」
// 節参照)があったため、telnet越しでも core1 が実際に独立して動作し
// 続けていることを確認できる手段として用意する。単一ライタ(core1)・
// 複数リーダ(core0のsmpstatコマンド)の単調増加値なのでロックは不要。
extern volatile uint64_t g_core1_heartbeat;

// core1がMMU/例外ベクタの初期化を終え、空ループに入ったかどうかを示す
// 状態フラグ。smpstatコマンドが`g_core1_heartbeat`の増加だけでなく、
// この値でも「core1が実際にsecondary_main()末尾まで到達したか」を
// 区別できるようにする。
extern volatile int g_core1_alive;

/* 【マルチコア化 Phase 6】core1をプログラムからPSCI CPU_ONで起動し、
 * secondary_main()がidle loop手前(g_core1_alive=1)まで到達するのを
 * 待つ(最大2秒)。command.cのcpuonコマンド(手動診断用、出力内容は
 * Phase 1で実機確認済みのため変更しない)とは別に、platform_init.c等の
 * 自動化されたブリングアップフローから呼ぶための静かな版。
 * 既にg_core1_alive==1なら(前回のcpuon/platform_init等で起動済み)何も
 * せず0を返す -- 二重にCPU_ONを呼んでも実害は無い(PSCIはALREADY_ONを
 * 返すだけ)が、待つ必要が無いため早期returnする。
 * 戻り値: 0=成功(core1は既に、またはこの呼び出しで到達した)、
 * -1=CPU_ON自体が失敗、またはタイムアウトしてもg_core1_aliveにならなかった。 */
int smp_boot_core1(void);

/* 3コア化(RXコピーオフロード専任のcore2)。core1(target本体)とは独立に
 * PSCI CPU_ONで起動する(target_cpu Aff1=2)。core2はsecondary_main()の
 * core2分岐に入り、rxcopy_worker_drain()だけを回すコピー専任ループになる
 * -- per-core配列(SMP_MAX_CORES=2のまま)には一切触れないため、SMP_MAX_
 * CORESを増やす必要はなく、大きな状態も持たない(必要なのは専用Cスタック
 * __stack3_topだけ)。rxcopy_set_enabled()から呼ばれる。
 * 戻り値はsmp_boot_core1()と同じ意味。 */
int smp_boot_core2(void);

/* core2用。g_core1_*と同じ規約(単一ライタ=core2、複数リーダ=smpstat)。 */
extern volatile uint64_t g_core2_heartbeat;
extern volatile int      g_core2_alive;

/* 4コア化(x86マルチコネクション、2026-08-15): core3。x86-linuxのみ
 * (SMP_MAX_CORES=4)。2 initiator(core0/core2)+ 2 target(core1/core3)。 */
int smp_boot_core3(void);
extern volatile uint64_t g_core3_heartbeat;
extern volatile int      g_core3_alive;

/* ================================================================
 * マルチコア化 Phase 3以降(per-coreモジュール化)の共通プリミティブ。
 * ~/.claude/plans/wondrous-baking-gadget.md参照。
 * ================================================================ */

/* 今回はcore0/core1の2コアのみ対応(Phase 2でcore1のみPSCI CPU_ONで
 * 起動する設計、core2/3は未使用のまま)。per-coreモジュール(Phase 3の
 * net_buf.c/timestamp.c、Phase 4のnetctx.c/ip.c/icmp.c/tcp.c -- ただし
 * job.cはユーザー指示によりper-core化を撤回し、下記smp_spinlock_tによる
 * 共有ジョブテーブル方式に変更した)はこの値を配列サイズとして使う。
 * 将来3コア目以降を起動する場合はこの値を増やすこと。
 *
 * 2026-08-15、マルチコネクション対応: x86-linux は 2 initiator + 2 target の
 * 4コア構成にするため 4 とする(OptiPlex i3-8100=物理4コア)。per-core配列
 * (tcp.cのs_priv等)が倍増するが x86 は .bss 動的確保で問題ない。rpi5
 * (aarch64)は固定メモリ配置(DMA_BSS_BASE等)を保つため 2 のまま
 * (kernel_2712.img は byte-identical)。 */
#if defined(__x86_64__)
#define SMP_MAX_CORES 4u
#else
#define SMP_MAX_CORES 2u
#endif

/* 現在実行中のコアのインデックス(0=core0, 1=core1, ...)を返す。
 * MPIDR_EL1のAffinity1(bits[15:8])から算出する -- BCM2712はAffinity0が
 * 全コア0固定で、コア番号はAffinity1にエンコードされる非標準構成
 * (マルチコア化 Phase 1で実機確認済み、src/boot.Sの_startのコア判定と
 * 同じ抽出方法)。単なるMRS+シフト+マスクなので、ホットパスから直接
 * 呼んでも無視できるコストしかかからない -- per-coreモジュールの
 * alloc/free/log等、頻繁に呼ばれる関数の先頭で毎回呼び直してよい。
 *
 * 戻り値がSMP_MAX_CORES以上になることは現在の設計(core0/core1のみ
 * 起動)では起こり得ないが、per-coreモジュール側はSMP_MAX_CORESでの
 * 配列サイズ確保・インデックス計算を前提にしているため、3コア目以降を
 * 起動する変更をする際はSMP_MAX_CORES自体を必ず見直すこと。 */
#if defined(__aarch64__)
static inline unsigned smp_core_index(void)
{
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return (unsigned)((mpidr >> 8) & 0xFFu);
}
#else
/* x86-linux: コア番号は MPIDR ではなく TLS で持つ(platform/x86-linux/
 * hal_smp.c が pthread 起動時にスレッドローカルへ設定する)。 */
unsigned smp_core_index(void);
#endif

/* 2026-08-11、ユーザー指示による性能分析用の一時計装(原因特定後に削除
 * すること) -- initiator(core0)/target(core1)のどちらが実際のスループット
 * の律速要因かを切り分けるため、各コアのメインループへ意図的な微小遅延
 * (「クロックが低下している」ことの模擬)を注入できるようにする。
 * g_sim_delay_us[core]にマイクロ秒単位の値を設定すると、そのコアの
 * メインループが毎周回その分だけ純粋なビジーウェイト(ネットワーク
 * ポーリング等は一切呼ばない、CPU時間だけを消費する)を行う。片方の
 * コアにだけ遅延を入れてスループットが変化すれば、そちらが律速側だと
 * 判断できる(遅延を入れても変化しない側は、ボトルネックではなく
 * "待たされている側"である可能性が高い)。0(既定)なら何もしない。 */
extern volatile uint32_t g_sim_delay_us[SMP_MAX_CORES];

/* g_sim_delay_us[smp_core_index()]分だけビジーウェイトする(0なら即座に
 * 戻る)。呼び出し元(core0: nvme.cのnvme_write_pipelined_run()、core1:
 * smp.cのsecondary_main())のメインループから毎周回呼ぶこと。 */
void sim_delay_tick(void);

/* ================================================================
 * マルチコア化 Phase 4: 最小限のスピンロック(job.cの共有ジョブテーブル
 * 用に導入、~/.claude/plans/wondrous-baking-gadget.md参照)。
 *
 * このプロジェクトの基本方針は「新規ロック機構を極力作らない」(コアごとに
 * 独立したメモリを持たせて競合そのものを無くす、net_buf.c/timestamp.c/
 * ip.c/icmp.c/netctx.c/tcp.c等のper-core化がこれ)だが、job.cのジョブ
 * テーブルだけは例外 -- 「空いているコアが他コアのジョブを拾って処理
 * できる」という将来要件(work-stealing)は、ジョブテーブル自体が
 * コアをまたいで共有されていない限り実現できない。job.c以外の
 * モジュールが持つ状態(tcp接続・net_bufプール等)は、今回はまだ
 * smp_core_index()で暗黙に「今実行しているコア」を参照する設計の
 * ままなので、ジョブが実際にコアをまたいで移動しても安全に動作する
 * (ctx経由で明示的に自分の担当インターフェースを参照する)ことは、
 * 現時点ではjob step関数の実装側が保証していない -- 将来job step側の
 * 設計変更が必要になった際に見直すこと。
 *
 * ARMv8-AのLDAXR/STXR(exclusive monitor)による標準的なtest-and-set
 * スピンロック(ARM公式ドキュメント/Linuxカーネルと同じ定石パターン)。
 * ロック取得中はwfeで待ち(sevで起床、解放側が必ずsevを発行する)、
 * ビジーポーリングによる無駄な電力/バス帯域消費を避ける。LSE atomics
 * (Cortex-A76はArmv8.2でサポート)への依存を避け、baseline ARMv8.0の
 * LL/SCのみで書いてあるため追加のコンパイラフラグは不要。 */
typedef volatile uint32_t smp_spinlock_t;

#if defined(__aarch64__)

static inline void smp_spin_lock(smp_spinlock_t *lock)
{
    uint32_t tmp;
    __asm__ volatile(
        "1:\n"
        "   ldaxr   %w0, %1\n"      /* tmp = *lock (acquireセマンティクス) */
        "   cbnz    %w0, 2f\n"      /* 既にロック済みなら待ちへ */
        "   stxr    %w0, %w2, %1\n" /* tmp(ステータス) = 1をストア試行 */
        "   cbnz    %w0, 1b\n"      /* ストア失敗(競合)なら最初からやり直し */
        "   b       3f\n"
        "2:\n"
        "   wfe\n"                  /* unlock側のsevで起床 */
        "   b       1b\n"
        "3:\n"
        : "=&r"(tmp), "+Q"(*lock)
        : "r"(1u)
        : "cc", "memory"
    );
}

static inline void smp_spin_unlock(smp_spinlock_t *lock)
{
    __asm__ volatile("stlr wzr, %0" : "+Q"(*lock) :: "memory"); /* releaseセマンティクスで0を書く */
    __asm__ volatile("sev" ::: "memory"); /* wfeで待っている他コアを起こす */
}

#else /* !__aarch64__ */

/* x86-linux: x86 は TSO。GCC の __atomic 組み込みで acquire/release を明示した
 * test-and-set スピンロックにする(LSE/LL-SC 相当を C11 メモリモデルで表現)。
 * 待ちループでは pause 命令(_mm_pause 相当)でスピン圧を下げる。 */
static inline void smp_spin_lock(smp_spinlock_t *lock)
{
    while (__atomic_exchange_n(lock, 1u, __ATOMIC_ACQUIRE)) {
        __builtin_ia32_pause();
    }
}

static inline void smp_spin_unlock(smp_spinlock_t *lock)
{
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

#endif /* __aarch64__ */

#endif /* SMP_H */
