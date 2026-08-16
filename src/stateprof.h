#ifndef STATEPROF_H
#define STATEPROF_H

#include <stdint.h>

/* ================================================================
 * stateprof.h — 明示的ステートマシン(job.h基盤、nvmet.c/nvme.c参照)
 * 向けの軽量な「各ステート滞在時間」プロファイラ。
 *
 * 背景(~/.claude/plans/wondrous-baking-gadget.md「次回セッションへの
 * 申し送り」参照): マルチコア化(nvmetをcore1へ、nvmeをcore0へ分離)の
 * 効果測定がジャンボフレーム化より前にまず必要と判断した。ts_log()
 * (timestamp.h)は個々のイベントを時系列に記録する道具であり、
 * 「NIO_ST_RECV_H2C_DATAに合計何ms滞在したか」のような集計を得るには
 * 大量のログを人手で読んで差分を取る必要があった。本モジュールは、
 * job stepのswitch(self->state)が呼ばれるたびに「前回どの状態にいたか」
 * との差分(timer_now()ベース)を状態ごとに積算するだけの、専用の集計器。
 *
 * 使い方(nvmet.c/nvme.cの各job step関数を参照):
 *   1. state_prof_t を対象ステートマシンの生存期間と同じ場所(job.hの
 *      ctxや、nvmet_ctx_tのような固定寿命の構造体)に埋め込む。
 *   2. job step関数の先頭(switch(self->state)より前、早期returnより前)
 *      で毎回 state_prof_mark(&prof, self->state) を呼ぶ -- これだけで
 *      「前回のstate_prof_mark()呼び出し時からstateが変わっていれば、
 *      直前のstateの滞在時間を確定してから新しいstateの計測を始める」
 *      という前提で、呼び出し元は遷移そのものを意識する必要がない。
 *   3. 性能分析したい区間の直前に state_prof_reset() で統計をゼロに
 *      戻し、区間終了後に state_prof_dump() でuart_printf経由の表を
 *      表示する(区間を区切らず動かし続けると、`ACCEPT_WAIT`のような
 *      「クライアント接続を何分でも待つ」ステートの滞在時間が支配的に
 *      なり、実処理の内訳が埋もれてしまうため、明示的なreset区切りが
 *      重要)。
 *
 * 「滞在時間」は壁時計時間(timer_now()の差分)であり、job_scheduler_
 * tick()が他のジョブに時間を取られてこのjob stepが呼ばれなかった時間も
 * 含む -- これは意図的: 「このステートで実際にCPUを使っていた時間」
 * ではなく「このステートに留まっていた実時間(=大半はネットワーク応答
 * 待ち、または他ジョブ/他コアに邪魔された待ち)」を見るのが目的
 * (core0/core1どちらがボトルネックかを切り分けるための計測)。
 *
 * 別コアが書いたstate_prof_tを別コアから読む(例: core0のシェルから
 * core1にpin止めされたnvmet-ioの統計をdumpする)ことを想定している --
 * このプロジェクトのMMU設定(Normal cacheable RAM、Inner Shareable、
 * ~/.claude/plans/wondrous-baking-gadget.md「MMUは有効」節)ではコア間で
 * キャッシュコヒーレントなため、`jobs`/`smpstat`/`ts core`が既にやって
 * いるのと同じ「ロック無しでそのまま読む」で問題ない(統計値なので
 * 多少の読み取りタイミングのズレは許容できる)。
 * ================================================================ */

/* 対象ステートマシンが持つステート数の上限。現状の最大は
 * nvmet_io_state_t(NIO_ST_*、16個)なので、将来のステート追加を見越して
 * 余裕を持たせた値にしてある。stateがこの範囲外の値なら
 * state_prof_mark()は静かに何もしない(呼び出し側のenum変更漏れ等で
 * 配列外アクセスにならないための安全弁)。 */
#define STATEPROF_MAX_STATES 20u

typedef struct {
    uint8_t  started;          /* 0 = state_prof_mark()がまだ一度も呼ばれていない。
                                 * `nvmet_ctx_t`のように固定物理アドレスに置かれ
                                 * `.bss`のゼロクリア対象外の構造体は、明示的な
                                 * state_prof_reset()を一度も呼ばずに使われうる
                                 * (真のコールドブート直後の電源投入時DRAM不定値、
                                 * または単純な0初期化)-- current_stateだけを
                                 * 「未開始」の目印にすると、ゼロ初期化直後に
                                 * たまたまstate値0(多くのステートマシンで最初の
                                 * ステート)へ遷移した際、entry_ticksが0のまま
                                 * (起動からの経過時間)を最初のステートの滞在
                                 * 時間として誤って積算してしまう。このフラグで
                                 * 「ゼロ初期化か明示的resetか」を問わず、初回の
                                 * mark()呼び出しを常に正しく初期化として扱う。 */
    uint64_t entry_ticks;      /* 現在のcurrent_stateへ入った時刻(timer_now()) */
    int      current_state;    /* 現在のステート(startedが0の間は不定) */
    uint64_t total_ticks[STATEPROF_MAX_STATES];  /* 各ステートの累積滞在時間(ticks) */
    uint64_t max_ticks[STATEPROF_MAX_STATES];    /* 各ステートの1回あたり最長滞在時間(ticks) */
    uint32_t enter_count[STATEPROF_MAX_STATES];  /* そのステートへ遷移した回数 */
    uint32_t poll_count[STATEPROF_MAX_STATES];   /* そのステートでstep()が呼ばれた回数
                                                    * (=job_scheduler_tick()がこのジョブを
                                                    * このステートのままclaimした回数、
                                                    * ポーリング頻度/スケジューラ負荷の目安) */
} state_prof_t;

/* 全統計をゼロに戻す(started=0、次のstate_prof_mark()呼び出しを
 * 新規の初回呼び出しとして扱い、そこから計測を始める)。性能分析したい
 * 区間の直前に呼ぶこと。 */
void state_prof_reset(state_prof_t *p);

/* job step関数の先頭(switch(self->state)より前)で毎回呼ぶ。
 * 前回呼び出し時からstateが変化していれば、直前のstateの滞在時間
 * (今回呼ばれた時刻 - 前回stateが変わった時刻)をtotal_ticks/max_ticks
 * へ積算してから、新しいstateの計測を開始する(entry_ticksを更新)。
 * stateが変化していなければ、単にpoll_count[state]をインクリメントする
 * だけ(積算はまだ行わない -- 実際にそのステートを抜けた時点でまとめて
 * 積算する設計、途中経過を見たい場合はstate_prof_dump()が現在の
 * current_stateについてのみ「経過中の分」を暫定加算して表示する)。 */
void state_prof_mark(state_prof_t *p, int state);

/* 現在のcurrent_stateの滞在時間を今この瞬間で確定させる(total_ticks/
 * max_ticksへ積算し、entry_ticksを現在時刻へ進める -- current_state自体は
 * 変えない、以後も同じstateに留まっているものとして計測を続けられる)。
 * ジョブがJOB_DONEで終了する直前や、稼働中のまま統計を正確に読みたい
 * 場面(state_prof_dump()を呼ぶ前)で使う。started==0(一度も
 * mark()されていない)なら何もしない。 */
void state_prof_flush(state_prof_t *p);

/* pの現在の統計をuart_printf経由で表として表示する。names[0..name_count)
 * はstate値に対応する人間可読な名前(呼び出し元のenumと同じ並び順で
 * 渡すこと) -- state値がname_count以上ならその行は"?"として表示する。
 * labelはこのステートマシンを識別するための見出し文字列(例:
 * "nvmet-admin(mlx5-pf1)")。呼び出し時点でcurrent_stateがまだ
 * 継続中であれば、その分の経過時間を暫定加算して表示する(内部の
 * 積算値そのものは変更しない -- state_prof_flush()と違い、呼び出しても
 * pの内容は変わらない読み取り専用の表示)。enter_count/poll_countが共に
 * 0のステート(一度も観測されていない)は表示を省略する。 */
void state_prof_dump(const state_prof_t *p, const char *const *names, unsigned name_count,
                      const char *label);

#endif /* STATEPROF_H */
