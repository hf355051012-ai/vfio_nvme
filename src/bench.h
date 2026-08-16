#ifndef BENCH_H
#define BENCH_H

#include <stdint.h>

/* ================================================================
 * bench.h — TCPスループット計測 — フェーズ5
 *
 * 接続後、送信チャンクサイズを段階的に大きくしながら
 * send→(エコー)recv のラウンドを一定時間ずつ繰り返し、1秒ごとに
 * 送受信バイト数・再送回数(g_tcp_retransmit_count)・RXリング溢れ回数
 * (g_eth_rsr_bna_count)のテレメトリをログ出力する。
 *
 * 対向側に「受信したものを即座にそのまま送り返す」ストリーミング
 * echoサーバが必要(script/bench.ps1参照 -- test.ps1の「指定バイト数を
 * 受信し終えてから送り返す」バッファ型とは異なり、連続的な往復に
 * 対応するため受信し次第すぐ送り返す設計)。
 * ================================================================ */

/* dst_ip:dst_portへ接続し、スループット計測を実行する。
 * phase_duration_ms: 各フェーズ(チャンクサイズ)を実行する時間(ミリ秒)。 */
void tcp_bench_run(uint32_t dst_ip, uint16_t dst_port, uint32_t phase_duration_ms);

/* dst_ip:dst_portへ接続し、一方向(送信専用)のスループット計測を実行する。
 * tcp_bench_run()と違いエコーの受信を待たない -- 最大チャンクサイズ
 * (BENCH_MAX_CHUNK=32768バイト)でtcp_send()を打ち続けるだけで、完了待ちは
 * TCPの実ACK(相手のカーネルが自動で返す)のみに依存する。tcp_send()自体は
 * 内部でeth_send_frags_async()による複数セグメントのパイプライン送信を
 * 行うため、tcp_bench_run()の「1ラウンドごとにエコー全体を待つ」設計が
 * 隠してしまうTX側の実際のスループットを見るためのもの。
 * 対向には、受信したデータをただ読み捨てるだけのsinkサーバが必要
 * (script/sink.ps1 -- bench.ps1と違いエコーを返さない。エコーを返さない
 * ことが重要で、返してしまうとPi側が読まない受信データがバッファに
 * 溜まり続けるだけで実害はないが、対向スクリプトの実装をより単純に
 * できるため専用のスクリプトにした)。
 * duration_ms: 計測を実行する時間(ミリ秒)。
 *
 * 【実機で確認済みの既知の制約】sink.ps1相手だと、tcpbench(平均約
 * 4.85MB/s)よりむしろ大幅に遅くなる(実測30〜300KB/s程度)ことがある —
 * これはコードのバグではなくTCPの既知の相互作用(「遅延ACKと小さい
 * cwndの衝突」)。sink.ps1はデータを一切送り返さないため、Windows側は
 * ACKを相乗りさせる出力データを持たず、2つ目のフルサイズセグメントが
 * 揃うか約200msの遅延ACKタイマーが満了するまでACKを出さない。cwndが
 * (輻輳制御で)小さくなると1バーストが2セグメント未満になりやすく、
 * 200msタイマー待ちに陥る → こちらのRTO(TCP_RTO_MIN_MS=200ms)もほぼ
 * 同時に満了し、本当はロスしていないのに不要な再送(spurious
 * retransmission、Wireshark上のラベルで確認済み)をしてcwndを
 * さらに縮める、という悪循環になる。tcp_bench_run()/nvme(read/write)が
 * 問題にならないのは、相手が送り返すデータにACKが相乗りするため
 * (bench.ps1/test.ps1はエコーを返す、nvmetもC2HData/CQEを返す)。
 * TX側そのものの動作検証はtcptestコマンド(3セグメントが約144マイクロ秒
 * 間隔で連続送出されることを確認済み)で行うこと -- sendbenchの絶対値を
 * 額面通りのスループット指標として使わないこと。 */
void tcp_send_bench_run(uint32_t dst_ip, uint16_t dst_port, uint32_t duration_ms);

#endif /* BENCH_H */
