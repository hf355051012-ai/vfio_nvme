#ifndef JOB_H
#define JOB_H

#include <stdint.h>

/* ================================================================
 * job.h — 明示的ステートマシン用の汎用ジョブ/スケジューラ基盤
 *
 * 背景: 従来このプロジェクトのtcp.c/icmp.c/arp.c/nvmet.c/nvme.c等は
 * 「wait箇所は関数内部でポーリングループを回し、完了/タイムアウトまで
 * 戻らない」ブロッキング設計だった。これを、NVMe/TCP関連の制御から
 * 段階的に「waitに入ったらジョブを登録してメインループへ戻り、
 * メインループが毎tick全ジョブをポーリングして未完了分を再開する」
 * 明示的ステートマシン設計へ移行する(CLAUDE.md「NVMe/TCP制御の
 * ステートマシン化」節参照)。フェーズ1では本基盤とシェルのメインループ
 * (command.c)のみを対象とし、nvmet.c/nvme.c自体の変換は後続フェーズ。
 *
 * 1ジョブ = 1つの処理/1つのコネクション(例: 将来的にnvmet.cを変換する際、
 * admin queueとIO queueはそれぞれ別々のjob_tになる想定)。ジョブが複数の
 * 内部ステップを持つ場合はjob_t.stateのenum値で表現する(呼び出し元が
 * 自分のstep関数内でswitchする)。
 *
 * マルチコア化 Phase 4(~/.claude/plans/wondrous-baking-gadget.md参照):
 * net_buf.c/timestamp.c/tcp.c等の他モジュールはコアごとに独立したメモリを
 * 持つper-core化(競合そのものを無くす、新規ロック不要)を採用しているが、
 * job.cのジョブテーブルだけは意図的に**単一の共有テーブル**のままにし、
 * smp.hのsmp_spinlock_tで保護している -- 将来「空いているコアが他コアの
 * ジョブを拾って処理する」(work-stealing)を実現するには、ジョブテーブル
 * 自体がコアをまたいで共有されている必要があるため(ユーザー指示、
 * per-core化するとこれが構造的に不可能になる)。`job_t.claimed`
 * (下記)が「今どのコアかが実行中か」を表し、二重実行を防ぐ。
 *
 * 【解消済み(2026-08-08)】以前ここには「job stepがsmp_core_index()で
 * 『今実行しているコア』を暗黙に参照する設計のままなので、ジョブが
 * 別コアへ移動すると壊れる」という制約を記していた。tcp.c/netif.cを
 * 「暗黙の実行コア」ではなく「リソース自身が覚えている生成時のowner」
 * ベースの参照に変更したことで解消した(詳細は~/.claude/plans/
 * wondrous-baking-gadget.md「job stepのctx経由リソース参照化」節、
 * tcp.hのtcp_conn_t.owner_core/netif.hのnetif_t.owner_coreコメント
 * 参照)。
 *
 * 【新たに導入したaffinity_key機構】上記の「owner固定化」だけでは、
 * 同じインターフェース/リソースを扱う*複数の*ジョブ(例: nvmet-adminと
 * nvmet-io、どちらも同じnetif_tへbindされる)が、job.cの共有スケジューラ
 * によって*同時に2つの異なるコアで*claimされてしまう可能性は残る --
 * 各ジョブのowner参照自体は正しくても、そのownerが指す先(TCP接続テーブル・
 * NICのTXリング等、tcp.c/eth.c/mlx5_net.c内部の非スレッドセーフな状態)を
 * 2つのコアが本当に同時に読み書きすれば競合する。job.hのjob_t.claimedは
 * 「同一ジョブの二重実行」しか防がない。
 * job_set_affinity()(下記)で、関連するジョブ群に同じaffinity_key
 * (典型的にはそのリソースを表すポインタ、例えばnetif_t*)を設定すると、
 * job_scheduler_tick()は「同じaffinity_keyを持つ*他の*ジョブが現在
 * claimed(実行中)であれば、このジョブもこのtickではclaimしない」という
 * 追加の排他を行う -- これにより、同じリソースに属するジョブ群が異なる
 * コアで同時に走ることはなくなる(1個のジョブ完了を他コアが待つのとは
 * 異なり、「同じaffinity_keyの*どれか*が実行中なら他は全てスキップ」と
 * いう軽量なグルーピングロックとして機能する)。affinity_key==NULL
 * (job_spawn()直後のデフォルト)のジョブはこの追加チェックを一切受けない
 * (telnet/ping等、単独リソースしか触らないジョブは今まで通り)。
 *
 * 【Phase 6で追加したcore pinning機構】affinity_keyだけでは「同じ
 * リソースに属するジョブ群が異なるコアで*同時に*claimされない」ことしか
 * 保証しない -- あるジョブが*常に*特定のコアで実行される(NICの
 * owner_coreと一致し続ける)ことまでは保証しないと、Phase 4完了時点の
 * 申し送りに記していた。この隙間を埋めるのがjob_t.pinned_core:
 * job_spawn()は呼び出した瞬間のsmp_core_index()を既定値として記録し、
 * job_scheduler_tick()は「pinned_core >= 0 かつ 今実行しているコアと
 * 不一致」なジョブを一切claimしない(他コアがこのジョブをtickして
 * 拾ってくれるまで待つ、job.h冒頭のclaimedと同じく「ブロックしない
 * スキップ」)。既定で「spawnしたコアに固定」なので、telnet/ping/
 * nvme等の既存ジョブ(すべてcore0のシェルから生成される)は今まで通り
 * core0だけで動き続け、明示的にjob_pin_to_core()を呼んだジョブだけが
 * 別のコアへ引き渡される(nvmet.cのnvmet_job_start()がbound_ctx->
 * owner_coreへ再ピンする例を参照)。将来の真のwork-stealing(空いている
 * コアが未ピンのジョブを自由に拾う)は、ここでは実装していない -- 今回は
 * 安全側(何もしなければ今まで通りcore0固定)を優先した。
 * ================================================================ */

#define JOB_MAX 12u  /* 同時ジョブ数の上限(システム全体で共有、コアごとの
                      * 個別枠ではない -- job.cのジョブテーブルは単一の
                      * 共有配列)。nvmet常駐サーバ最大3系統(RP1+ConnectX
                      * PF0/PF1)×admin/IO 2ジョブ=6を常時占有しうる前提で、
                      * ping/nvme connect等の一時的なジョブ用に余裕を
                      * 持たせた(platform_init.c参照)。 */

typedef enum {
    JOB_WAITING = 0,  /* まだ完了していない、次tickでまたstep()を呼んでほしい */
    JOB_DONE    = 1,  /* このtickで完了した(呼び出し元がJOB_DONEを返した時点でスケジューラが自動的にキューから外す) */
} job_result_t;

typedef struct job job_t;

/* ジョブの1ステップ関数。呼ばれるたびに「今できる分だけ」処理してすぐ
 * 戻ること -- 内部でブロッキングの待ちループ(while+タイムアウト等)を
 * 回してはならない。まだ完了していなければJOB_WAITINGを返す(次回の
 * job_scheduler_tick()で再度呼ばれる)。 */
/* [関数ポインタ登録先一覧 -- ctagsジャンプ補助] job_spawn()で登録される具体的なstep関数:
 *   ping_job_step(command.c), nvme_cli_report_job_step(command.c), ftpd_job_step(ftpd.c),
 *   telnet_job_step(telnet.c), nvme_connect_job_step / nvme_io_job_step(nvme.c),
 *   nvmet_admin_job_step / nvmet_io_job_step(nvmet.c),
 *   rdma_cm_job_step(rdma_cm.c), nvme_rdma_connect_job_step / nvmet_rdma_job_step(nvme_rdma.c/nvmet_rdma.c)。
 * 間接呼び出しは job.c の job_scheduler_tick() 内 s_jobs[i].step(&s_jobs[i])。 */
typedef job_result_t (*job_step_fn)(job_t *self);

struct job {
    int         in_use;
    job_step_fn step;   /* 次に呼ぶステップ関数 */
    int         state;  /* ジョブ固有のstate(呼び出し元がswitchで解釈する、0で初期化される) */
    void       *ctx;    /* ジョブ固有のコンテキスト(呼び出し元がstatic領域等で確保すること -- mallocなし環境) */
    const char *name;   /* `jobs`コマンド等の診断表示用 */
    /* `job stop <番号>`シェルコマンド(job_request_cancel()経由)が立てる
     * 停止要求フラグ。スケジューラ自身はこれを一切見ない(job_scheduler_
     * tick()は従来通りstep()を呼ぶだけ) -- 各ジョブのstep関数が自分の
     * selfを通じてself->cancel_requestedを確認し、「今安全に停止できる
     * 状態か」を自分で判断してから後始末(接続クローズ・リスナー解除等)
     * を行いJOB_DONEを返す責務を持つ。強制終了(スケジューラが外部から
     * ジョブの資源を勝手に片付ける)は行わない -- job_tはジョブ固有の
     * 資源(TCPコネクション等)について何も知らないため。 */
    volatile int cancel_requested;
    /* マルチコア化 Phase 4: 現在いずれかのコアがこのジョブのstep()を
     * 実行中かどうか(1=実行中)。job_scheduler_tick()がs_job_lock
     * (smp_spinlock_t)保持下で立てる/下ろす -- 同一ジョブのstep()を
     * 2つのコアが同時に呼ばないようにするための排他フラグ(job.h冒頭の
     * 「重要な制約」参照、job step自体は今のところコアをまたいで安全に
     * 動くとは限らないため、二重実行そのものを防ぐことが目的)。他コアは
     * claimed==1のジョブを見つけたら待たずに次のジョブへ進む(スピン
     * しない) -- 1個のジョブの実行完了を他コアがブロックして待つ設計に
     * すると、job stepの「今できる分だけ処理してすぐ戻る」という短時間
     * 契約と合わせても、複数コアでの並行処理という目的そのものを損なう
     * ため。 */
    volatile int claimed;
    /* job_set_affinity()で設定する、このジョブが属するリソースの識別子
     * (典型的にはnetif_t*等のポインタをそのままキーとして使う、値の
     * 意味はjob.c自身は一切解釈せずポインタ比較のみ行う)。NULL(既定値、
     * job_spawn()直後)なら追加のグルーピング排他を受けない。job.h冒頭の
     * 「affinity_key機構」コメント参照。 */
    void *affinity_key;
    /* job_spawn()が既定でsmp_core_index()(呼び出し元のコア)を書き込む、
     * このジョブを実行してよいコア番号。job_scheduler_tick()は
     * pinned_core != 今実行しているコア のジョブをclaimしない(job.h
     * 冒頭の「core pinning機構」コメント参照)。job_pin_to_core()で
     * 明示的に変更しない限り「spawnしたコアに固定」のまま。 */
    int pinned_core;
};

/* 新しいジョブをキューへ登録する。ctxの実体は呼び出し元が用意し、job_t自身が
 * JOB_DONEを返すまで生存させること。
 * 戻り値: 登録したjob_tへのポインタ、空きが無ければNULL(呼び出し元は
 * その場でエラー処理する -- ジョブテーブル枯渇は無視して良い状況では
 * ない)。 */
job_t *job_spawn(job_step_fn step, void *ctx, const char *name);

/* job(job_spawn()の戻り値)にaffinity_keyを設定する。同じaffinity_keyを
 * 共有する複数のジョブは、job_scheduler_tick()によって異なるコアで同時に
 * claimされることがなくなる(job.h冒頭の「affinity_key機構」コメント
 * 参照)。job_spawn()直後、そのジョブがまだ一度もtickされていないうちに
 * 呼ぶこと(nvmet.cのnvmet_job_start()がadmin/ioジョブ両方に同じ
 * netif_t*(bound_ctx)を設定する例を参照)。keyにNULLを渡すと解除
 * できる(通常は使わない)。 */
void job_set_affinity(job_t *job, void *affinity_key);

/* job(job_spawn()の戻り値)を明示的にcoreへピン止めする。既定では
 * job_spawn()を呼んだコアに既にピン止めされているので、そのコアで
 * 動かし続けたいだけなら呼ぶ必要はない -- 別コア(典型的にはNICの
 * netif_t.owner_coreを引き渡した先)へ処理を移す場合にのみ呼ぶ
 * (job.h冒頭の「core pinning機構」コメント、nvmet.cのnvmet_job_start()
 * 参照)。呼び出し後、次回以降のjob_scheduler_tick()はそのコアからしか
 * このジョブをclaimしない。 */
void job_pin_to_core(job_t *job, unsigned core);

/* 登録済みの全ジョブを1回ずつポーリングする(メインループから毎tick呼ぶ)。
 * JOB_DONEを返したジョブは自動的にキューから外れる(in_use=0)。 */
void job_scheduler_tick(void);

/* 現在アクティブなジョブ数。 */
unsigned job_active_count(void);

/* アクティブジョブの一覧をuart_printf()で表示する(`jobs`コマンド用の
 * 診断出力)。表示される番号(`[N]`)はjob_request_cancel()に渡す番号と
 * 同じ、s_jobs[]内の生インデックス。 */
void job_list_dump(void);

#endif /* JOB_H */
