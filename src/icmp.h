#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stddef.h>
#include "smp.h"

/* ================================================================
 * icmp.h — ICMP Echo応答(ping応答) — フェーズ3
 * ================================================================ */

#define ICMP_TYPE_ECHO_REPLY    0u
#define ICMP_TYPE_ECHO_REQUEST  8u

/* pingstat コマンド用の統計カウンタ。マルチコア化 Phase 4
 * (~/.claude/plans/wondrous-baking-gadget.md参照)によりコアごとに
 * 独立配列化した -- icmp_handle()は受信フレームを処理したコア
 * (net_poll_all_and_dispatch()の呼び出し元)で実行されるため、Phase 6で
 * core1がPF1宛のICMPを処理するようになった場合でも、core0側の統計と
 * 混ざらない。呼び出し側は`g_icmp_echo_reply_time[smp_core_index()]`の
 * ように自コアのインデックスで参照すること(command.cのping実装参照)。 */
extern volatile uint32_t g_icmp_echo_request_count[SMP_MAX_CORES];
extern volatile uint32_t g_icmp_echo_reply_sent_count[SMP_MAX_CORES];

/* 直近に受信したEcho Replyのtimer_now()時刻(icmp_handle内、ログ出力より
 * 前に記録)。pingコマンドのRTT計測がuart_printf()のブロッキング時間を
 * 含めてしまわないようにするため — icmp_wait_echo_reply()が0を返した後、
 * 呼び出し側はこれを使って経過時間を計算すること
 * (詳細はicmp.cのicmp_handle()内コメント参照)。上記2カウンタと同じ理由で
 * コアごとに独立配列化した。 */
extern volatile uint64_t g_icmp_echo_reply_time[SMP_MAX_CORES];

/* ip.c から呼ばれるICMPペイロード処理本体。
 * data/len: ICMPヘッダ+データ(IPペイロード全体)
 * src_ip:   送信元IPv4アドレス(4バイト、応答の宛先IPとして使う)
 * src_mac:  送信元MACアドレス(応答の宛先MACとして使う)
 * type==Echo Requestの場合はEcho Replyを構築してip_send()で返す。
 * type==Echo Replyの場合はicmp_wait_echo_reply()向けに記録する。
 * それ以外はログのみで無視する。
 */
void icmp_handle(const uint8_t *data, size_t len,
                 const uint8_t src_ip[4], const uint8_t *src_mac);

/* dst_ip宛にICMP Echo Request(type=8)を送信する。宛先MACはarp.hの
 * ARPキャッシュから引き、無ければarp_resolve()でその場で解決する
 * (解決できなければ送信中止)。
 * ident/seq: ICMPヘッダの識別子・シーケンス番号(呼び出し側が採番する)
 * 戻り値: ip_send()の戻り値をそのまま返す(0=成功, -1=失敗、ARP解決
 * 失敗時も-1)。 */
int icmp_send_echo_request(const uint8_t dst_ip[4], uint16_t ident, uint16_t seq);

/* 指定ident/seqのEcho Replyが届くまで、最大timeout_val_msの間
 * eth_poll_recv()+eth_dispatch()をポーリングして待つ
 * (受信自体はicmp_handle()経由で記録される)。
 * 戻り値: 0=一致するEcho Replyを受信、-1=タイムアウト */
int icmp_wait_echo_reply(uint16_t ident, uint16_t seq, uint32_t timeout_val_ms);

/* icmp_wait_echo_reply()の非ブロッキング版 -- 1回だけ「今readyかどうか」を
 * 確認するだけで、ポーリングループは回さない。job.h(ジョブ/スケジューラ
 * 基盤、CLAUDE.md「NVMe/TCP制御のステートマシン化」節参照)を使う
 * ping(command.cのcmd_ping())専用 -- 実際の受信ポーリング自体は
 * メインループ(command_shell_run())が毎tick呼ぶnet_poll_all_and_
 * dispatch()が担うため、この関数はicmp_handle()が既に記録した結果を
 * 見るだけでよい。
 * 戻り値: 1=一致するEcho Replyを受信済み(呼び出し側は改めて記録を消費
 * したことになる、以後同じseqに対して再度1を返すことはない)、0=まだ */
int icmp_echo_reply_ready(uint16_t ident, uint16_t seq);

#endif /* ICMP_H */
