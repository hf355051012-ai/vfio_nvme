#ifndef TELNET_H
#define TELNET_H

#include <stdint.h>
#include "netctx.h"

/* ================================================================
 * telnet.h — シリアルコンソールをTCP/telnet経由でも操作できるようにする
 *
 * 設計方針: 新しい独立したシェルセッションを実装するのではなく、既存の
 * シリアルコンソール(command.cのs_editor/shell_line_poll())へ「もう1つの
 * 入出力口」を追加する形にした。理由:
 *   - command.cの全コマンドハンドラ(約100個)はpl011_puts(&debug_uart,..)/
 *     uart_printf()経由でハードウェアUARTへ直接出力しており、これらを
 *     telnet向けに全て複製・付け替えるのは非現実的に大きい変更になる。
 *   - このプロジェクトはポーリング専用・単一スレッドの協調的実行モデル
 *     (割り込み無し)なので、「今どちらの入出力口として振る舞うか」を
 *     頻繁に切り替える既存のnetctx.h方式と同じ考え方が、ここでも自然に
 *     適用できる。
 *
 * 出力(インスタンス0): pl011_putc()(pl011.hのpl011_set_tap())にフックし、
 * シリアルコンソールへ書かれる全バイトのコピーをtelnetクライアントへも
 * 流す。入力: shell_line_poll()(command.c)が、物理UART(pl011_tstc/getc)に
 * 加えてtelnet_console_tstc(0)/telnet_console_getc(0)もポーリングし、
 * どちらから届いた文字も同じ行編集ステートマシンで処理する。
 *
 * 結果として、シリアルとインスタンス0のtelnetは「同じシェルセッションを
 * 覗く2つの窓」になる -- 片方に入力した内容がもう片方にも表示される。
 * これは複数の人間が同じtmuxセッションを共有する場合と同じ特性
 * (CLAUDE.md「ハードウェアテストループ」節参照)で、新たに問題を増やす
 * ものではない。
 *
 * 【2026-08-08追加: インスタンス1(コア1向け)】ユーザー指示「telnetを
 * コアごとにできるようにしてほしい。print文も完全に独立」を受け、2つ目の
 * 完全に独立したtelnetセッション(インスタンス1)を追加した。インスタンス0
 * とは以下の点で完全に分離している:
 *   - 別々のIPアドレス(NET_RP1_CORE1_IP、net.h参照。物理NICはRP1
 *     1枚のままだが、netctx.hのnet_ctx_register_alias()によるIP
 *     エイリアシングで下1桁だけ別のIPを名乗る)。
 *   - 別々のポート(既定23 vs 2323、cmd_telnet2()参照)。
 *   - 別々の送受信リングバッファ・telnetワイヤプロトコルパーサ状態。
 *   - 別々の行編集状態(command.cのs_editor2)・別々のコマンド履歴。
 *   - 出力は物理UARTに一切触れない(pl011_lock()を取得しない、
 *     tap経由でもない) -- telnet_output_redirect_*()経由で、インスタンス1
 *     のdispatch()実行中はuart_printf()/uart_putc()の出力を直接この
 *     インスタンスのtx_ringへだけ書き込む(uart_shim.cのuart_putc()参照)。
 *
 * 【実行コアについての正直な注記】このプロジェクトのNICドライバ
 * (eth.c/mlx5_net.c)はコアをまたいだ同時アクセスに対して一切スレッド
 * セーフでない(netctx.hのnet_ctx_t.owner_coreコメント参照)。このため
 * インスタンス1の「セッション」自体(行編集・dispatch・出力バッファ)は
 * インスタンス0と完全に独立しているが、実際にRP1のTX/RXへ触れる処理
 * (tcp_send()の内部等)は、他の全てのRP1利用者と同様、RP1のowner_core
 * (net_poll_all_and_dispatch()経由でRP1を実際にポーリングするコア)上で
 * 実行される必要がある。現状はcore1が独自の実行ループを持たない
 * (Phase 6未着手)ため、インスタンス1のjob step自体もcommand_shell_run()
 * のメインループ(=RP1のowner_core)から呼ばれるjob_scheduler_tick()に
 * よって処理される -- 「論理的に完全独立、物理的な実行はowner_coreに
 * 集約」という設計であり、コア1が実際にコードを実行しているわけでは
 * まだない。将来core1が自前のjob_scheduler_tick()ループを持つように
 * なった際、affinity_key(job.h参照)でこのインスタンス1のjobをRP1の
 * owner_coreへ固定する(またはRP1とは別のNICへ切り替える)ことを検討
 * すること。 */

/* telnetインスタンス数。0=既存のcore0向けセッション(UART併用)、
 * 1=core1向けセッション(telnet専用、完全独立)。 */
#define TELNET_INSTANCE_COUNT 2u

/* telnetサーバをジョブとして起動する(常駐 -- CLAUDE.md「nvmet: 常駐
 * サーバ化」節と同じ設計。クライアント切断後も自動的に次の接続を待つ)。
 * instance: 0または1(上記TELNET_INSTANCE_COUNT参照)。
 * bound_ctxで待ち受けるインターフェースを限定できる(NULLなら任意の
 * インターフェース、tcp_listen()のctx引数と同じ意味)。
 * 各インスタンスは同時に1接続のみを扱う(2人目は最初のクライアントが
 * 切断するまで待たされる -- どのみち行編集ステートは1つしか無いため)。
 * 戻り値: 0=起動成功、-1=失敗(既に起動中、リスナー/ジョブ枠が無い等) */
int telnet_server_start_instance(unsigned instance, uint16_t port, net_ctx_t *bound_ctx);

/* telnet_server_start_instance(0, port, bound_ctx)の薄いラッパー
 * (既存呼び出し元(main.c/platform_init.c/cmd_telnet())との互換用)。 */
int telnet_server_start(uint16_t port, net_ctx_t *bound_ctx);

/* 停止は`job stop <番号>`シェルコマンド(job.hのjob_request_cancel())
 * 経由で行う -- telnet専用の停止関数は無い。稼働中の接続(あれば)は
 * 即座に切断され、リスナーも解除される(telnetは進行中の対話セッションを
 * 保護する必要が無いため、nvmetのインスタンス単位の停止と違い即座に
 * 反映される、telnet.cのtelnet_job_step()参照)。 */

/* shell_line_poll()(command.c)専用の入力窓口。telnetプロトコルの制御
 * バイト(IAC等)はtelnet.c内部で既に取り除かれており、ここに積まれるのは
 * クライアントが入力した生のデータバイトのみ。 */
int  telnet_console_tstc(unsigned instance);
char telnet_console_getc(unsigned instance);

/* PC側から`exit`/`quit`シェルコマンドで能動的にtelnet接続を終えられる
 * ようにするための要求API(command.cのcmd_exit()から呼ぶ)。job stop
 * (job_request_cancel())と違いリスナー/jobは維持したまま、現在の
 * クライアント接続だけを切断する(次の接続はすぐまた受け付ける)。
 * 戻り値: 1=切断要求を受理(接続中だった)、0=何もしなかった(未接続)。 */
int telnet_request_exit(unsigned instance);

/* 【インスタンス1専用の出力リダイレクト、上記「印刷文も完全に独立」節
 * 参照】インスタンス1のdispatch()実行中、command.cがこれで挟むことで、
 * uart_printf()/uart_putc()(uart_shim.c)の出力を物理UARTではなく
 * インスタンス1のtx_ringへ直接書き込むよう切り替える。ネストしない
 * (command.cは常にインスタンス0またはインスタンス1のどちらか一方の
 * dispatch()しか同時に実行しない、単一物理コア上の協調的実行のため)。 */
void telnet_output_redirect_begin(unsigned instance);
void telnet_output_redirect_end(void);

/* uart_shim.cのuart_putc()/uart_printf()が使う。現在リダイレクト中なら
 * cをそのインスタンスのtx_ringへ書き込んで1を返す(呼び出し元は物理UART
 * に触れてはならない)。リダイレクト無しなら0を返す(通常の物理UART経路
 * を使うこと)。 */
int telnet_output_redirect_putc(char c);

/* telnet_output_redirect_begin()中かどうか(uart_printf()がpl011_lock()を
 * 取得すべきかどうかの判定に使う -- リダイレクト中は物理UARTに一切
 * 触れないため、ロックを取る必要も無い)。 */
int telnet_output_redirect_active(void);

/* command.cのshell_line_poll()相当が、インスタンス1の行編集・エコー時に
 * 使う直接出力(物理UARTを一切経由しない)。telnet_output_redirect_putc()
 * と同じ書き込み先だが、dispatch()の外(行編集中)から明示的にインスタンス
 * 番号を指定して呼べるようにするための薄いラッパー。 */
void telnet_instance_putc(unsigned instance, char c);
void telnet_instance_puts(unsigned instance, const char *s);

#endif /* TELNET_H */
