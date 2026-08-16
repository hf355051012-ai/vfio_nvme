#ifndef IPERF3_H
#define IPERF3_H

#include <stdint.h>

/* ================================================================
 * iperf3.h — iperf3サーバ(受信側)実装。
 *
 * 標準のiperf3クライアント(PC側)と相互接続できるよう、esnet/iperf
 * (GitHub, masterブランチ)の実ソース(src/iperf_server_api.c,
 * src/iperf_tcp.c, src/iperf_api.c, src/iperf_client_api.c)から直接
 * 確認したワイヤプロトコルをそのまま実装する。クライアント機能は
 * 実装しない(このプロジェクトは常にサーバ側)。
 *
 * 対応: TCPのみ、単一データストリーム(-P 1、iperf3のデフォルト)、
 * 通常方向(クライアント→Pi)と-R(reverse、Pi→クライアント)の両方。
 * 非対応: UDP/SCTP(ACCESS_DENIEDを返し切断)、-P 2以上(2本目以降を
 * acceptしないためクライアント側がハングする)、-d/--bidirectional
 * (警告のみで通常方向として処理、結果は不正確)。詳細は
 * ~/.claude/plans/jazzy-napping-goblet.md 参照。
 * ================================================================ */

/* portでリッスンし、1セッション分(制御コネクション+単一データ
 * ストリーム)を最後まで処理して戻る(nvmet_run()と同じ「1回勝負」の
 * 設計)。別のクライアントを受けるには再度呼び出すこと。
 * 戻り値: 0=セッション正常終了(クライアント切断を含む)、
 *         -1=失敗/タイムアウト/Ctrl+C中断 */
int iperf3_run(uint16_t port);

#endif /* IPERF3_H */
