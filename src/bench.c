// bench.c
//
// TCPスループット計測 — フェーズ5
// 送信チャンクサイズを段階的に大きくしながらsend→recv(エコー)の
// ラウンドを繰り返し、1秒ごとに送受信バイト数・再送回数・RXリング
// 溢れ回数を報告する。対向にストリーミングechoサーバが必要
// (script/bench.ps1)。

#include <stddef.h>
#include "bench.h"
#include "tcp.h"
#include "eth.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "smp.h"

/* 段階的に大きくするチャンクサイズ(バイト)。64は1セグメント未満、
 * 1460は旧MSS(非ジャンボ時代)ちょうどだった値(2026-07-25のジャンボ
 * フレーム対応でTCP_MSS_LOCALは10182へ拡張されたため、現在は1460も
 * 1セグメント未満のチャンクになる — 非ジャンボ相当のチャンクサイズでの
 * 挙動も引き続き計測できるよう値自体は変更していない)、4096以降は
 * 複数セグメントへの分割送信を踏む。
 * 旧実装は最大4096(3セグメント)までしか無く、tcp_send()が内部に持つ
 * cwnd主導のパイプライン送信(複数セグメントをACK待ちせず連続送信する
 * 仕組み、tcp.h冒頭のTier3コメント参照)がほとんど生きなかった —
 * 1ラウンドで送る量が小さすぎて、輻輳ウィンドウが育っても使い切れず、
 * 「1ラウンドの往復レイテンシ」がスループットを決めてしまっていた
 * (会話履歴のtcpbench調査参照)。
 *
 * 一度は61440(TCP_RX_BUF_SIZEの44セグメント分にほぼ合わせた値)まで試した
 * が、実機で「SOF/EOFが揃わないフレーム」の連続警告に続きRXリング周辺の
 * メモリ破壊(eth.cのETH_RX_RING_ALLOC_SIZEコメント参照)を引き起こし、
 * ARPキャッシュ破壊・接続断に至ることを確認した。一方32768(22セグメント/
 * ラウンド)までは複数回の実機テストで再送・BNA/OVR・破壊とも皆無で
 * ピーク520KB/sを達成済み。61440側の根本原因(RP1 GEM側の稀なタイミング
 * 起因と疑われるが未特定)を追いかけるより、実証済みの安全な上限に留める
 * 方を優先し、32768を最大チャンクとする。 */
#define BENCH_NUM_PHASES 5
static const uint16_t s_bench_chunk_sizes[BENCH_NUM_PHASES] = {64, 1460, 8192, 16384, 32768};

#define BENCH_MAX_CHUNK       32768u
#define BENCH_RECV_TIMEOUT_MS 5000u

/* 送受信バッファ。malloc無し環境のためstatic(BSS)確保。
 * aligned(64): tcp_send()はゼロコピー送信のためs_bench_txのアドレスを
 * 直接RP1 GEMのTXディスクリプタへ渡す(net_buf.hのnet_buf_tと同じ理由の
 * アライメント要求、tcp.hのtcp_send()ドキュメント参照)。 */
static uint8_t s_bench_tx[BENCH_MAX_CHUNK] __attribute__((aligned(64)));
static uint8_t s_bench_rx[BENCH_MAX_CHUNK] __attribute__((aligned(64)));

static void bench_fill_pattern(uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xFFu);
    }
}

/* chunkバイトを送信し、エコーされた同じ長さを受信しきるまで待つ
 * (1回のtcp_recv()はs_rx_count分すべてを一括で返せるが、それでも
 * chunk全体が一度に届いているとは限らないため複数回呼ぶ)。
 * 戻り値: 0=成功(送受信とも完了)、-1=失敗(送信/受信エラー、切断等) */
static int bench_round(tcp_conn_t *conn, uint16_t chunk,
                        uint32_t *sent_out, uint32_t *recv_out)
{
    int sent = tcp_send(conn, s_bench_tx, chunk);
    if (sent <= 0) {
        return -1;
    }
    *sent_out += (uint32_t)sent;

    uint16_t received = 0;
    while (received < (uint16_t)sent) {
        uint16_t space = (uint16_t)((uint16_t)sent - received);
        int n = tcp_recv(conn, s_bench_rx + received, space, BENCH_RECV_TIMEOUT_MS);
        if (n <= 0) {
            return -1;  /* タイムアウト、または相手がクローズ(0) */
        }
        received = (uint16_t)(received + n);
    }
    *recv_out += received;
    return 0;
}

void tcp_bench_run(uint32_t dst_ip, uint16_t dst_port, uint32_t phase_duration_ms)
{
    uint8_t dst_octets[4];
    ip_to_octets(dst_ip, dst_octets);
    uart_printf("[BENCH] ===== TCPスループット計測開始: %u.%u.%u.%u:%u "
                "(フェーズ毎%ums) =====\n",
                dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3],
                dst_port, phase_duration_ms);

    bench_fill_pattern(s_bench_tx, BENCH_MAX_CHUNK);

    tcp_conn_t conn;
    if (tcp_connect(&conn, dst_ip, dst_port) != 0) {
        uart_printf("[BENCH] FAIL: connect失敗\n");
        return;
    }

    uint32_t total_sent = 0, total_recv = 0;
    uint32_t sent_since_report = 0, recv_since_report = 0;
    uint32_t rounds_since_report = 0;

    uint32_t prev_retransmit = g_tcp_retransmit_count[smp_core_index()];
    uint32_t prev_bna        = g_eth_rsr_bna_count;

    uint64_t test_start = timer_now();
    uint64_t last_report = test_start;

    int aborted = 0;

    for (int phase = 0; phase < BENCH_NUM_PHASES && !aborted; phase++) {
        uint16_t chunk = s_bench_chunk_sizes[phase];
        uart_printf("[BENCH] ---- フェーズ%d/%d開始: チャンクサイズ=%uバイト ----\n",
                    phase + 1, BENCH_NUM_PHASES, chunk);

        uint64_t phase_start = timer_now();

        while (!timeout_ms(phase_start, phase_duration_ms)) {
            uint32_t s = 0, r = 0;
            if (bench_round(&conn, chunk, &s, &r) != 0) {
                uart_printf("[BENCH] ラウンド失敗(state=%d)、計測を中断\n", (int)conn.state);
                aborted = 1;
                break;
            }
            total_sent += s;
            total_recv += r;
            sent_since_report += s;
            recv_since_report += r;
            rounds_since_report++;

            if (timeout_sec(last_report, 1)) {
                uint64_t now = timer_now();
                uint32_t cur_retransmit = g_tcp_retransmit_count[smp_core_index()];
                uint32_t cur_bna        = g_eth_rsr_bna_count;

                uart_printf("[BENCH] t=%us chunk=%uB send=%uB/s recv=%uB/s "
                            "rounds=%u retransmit=%u bna=%u total_send=%uB total_recv=%uB\n",
                            (unsigned)get_sec_from(test_start),
                            chunk,
                            sent_since_report, recv_since_report,
                            rounds_since_report,
                            cur_retransmit - prev_retransmit,
                            cur_bna - prev_bna,
                            total_sent, total_recv);

                sent_since_report = 0;
                recv_since_report = 0;
                rounds_since_report = 0;
                prev_retransmit = cur_retransmit;
                prev_bna = cur_bna;
                last_report = now;
            }
        }
    }

    tcp_close(&conn);

    uint32_t total_ms = (uint32_t)get_ms_from(test_start);
    uart_printf("[BENCH] ---- 結果 ----\n");
    uart_printf("[BENCH] 総送信=%uバイト 総受信=%uバイト 所要時間=%ums\n",
                total_sent, total_recv, total_ms);
    if (total_ms > 0) {
        uint32_t avg_bps = (uint32_t)(((uint64_t)total_sent * 1000u) / total_ms);
        uart_printf("[BENCH] 平均送信スループット=%u B/s\n", avg_bps);
    }
    uart_printf("[BENCH] 総再送回数=%u 総RSR.BNA回数=%u 総RSR.OVR回数=%u\n",
                g_tcp_retransmit_count[smp_core_index()], g_eth_rsr_bna_count, g_eth_rsr_ovr_count);
    uart_printf("[BENCH] ===== TCPスループット計測終了 =====\n");
}

void tcp_send_bench_run(uint32_t dst_ip, uint16_t dst_port, uint32_t duration_ms)
{
    uint8_t dst_octets[4];
    ip_to_octets(dst_ip, dst_octets);
    uart_printf("[SENDBENCH] ===== TCP一方向送信スループット計測開始: %u.%u.%u.%u:%u "
                "(chunk=%uバイト, %ums) =====\n",
                dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3],
                dst_port, (unsigned)BENCH_MAX_CHUNK, duration_ms);

    bench_fill_pattern(s_bench_tx, BENCH_MAX_CHUNK);

    tcp_conn_t conn;
    if (tcp_connect(&conn, dst_ip, dst_port) != 0) {
        uart_printf("[SENDBENCH] FAIL: connect失敗\n");
        return;
    }

    uint32_t total_sent = 0;
    uint32_t sent_since_report = 0;
    uint32_t rounds_since_report = 0;

    uint32_t prev_retransmit = g_tcp_retransmit_count[smp_core_index()];
    uint32_t prev_bna        = g_eth_rsr_bna_count;

    uint64_t test_start = timer_now();
    uint64_t last_report = test_start;

    /* エコー待ちが無いため、ここでの完了待ちはtcp_send()内部のACKポーリング
     * のみ(bench_round()のような別途tcp_recv()呼び出しは不要)。 */
    while (!timeout_ms(test_start, duration_ms)) {
        int sent = tcp_send(&conn, s_bench_tx, (uint16_t)BENCH_MAX_CHUNK);
        if (sent <= 0) {
            uart_printf("[SENDBENCH] 送信失敗(state=%d)、計測を中断\n", (int)conn.state);
            break;
        }
        total_sent += (uint32_t)sent;
        sent_since_report += (uint32_t)sent;
        rounds_since_report++;

        if (timeout_sec(last_report, 1)) {
            uint64_t now = timer_now();
            uint32_t cur_retransmit = g_tcp_retransmit_count[smp_core_index()];
            uint32_t cur_bna        = g_eth_rsr_bna_count;

            uart_printf("[SENDBENCH] t=%us send=%uB/s rounds=%u retransmit=%u bna=%u total=%uB\n",
                        (unsigned)get_sec_from(test_start),
                        sent_since_report, rounds_since_report,
                        cur_retransmit - prev_retransmit,
                        cur_bna - prev_bna,
                        total_sent);

            sent_since_report = 0;
            rounds_since_report = 0;
            prev_retransmit = cur_retransmit;
            prev_bna = cur_bna;
            last_report = now;
        }
    }

    tcp_close(&conn);

    uint32_t total_ms = (uint32_t)get_ms_from(test_start);
    uart_printf("[SENDBENCH] ---- 結果 ----\n");
    uart_printf("[SENDBENCH] 総送信=%uバイト 所要時間=%ums\n", total_sent, total_ms);
    if (total_ms > 0) {
        uint32_t avg_bps = (uint32_t)(((uint64_t)total_sent * 1000u) / total_ms);
        uart_printf("[SENDBENCH] 平均送信スループット=%u B/s\n", avg_bps);
    }
    uart_printf("[SENDBENCH] 総再送回数=%u 総RSR.BNA回数=%u 総RSR.OVR回数=%u\n",
                g_tcp_retransmit_count[smp_core_index()], g_eth_rsr_bna_count, g_eth_rsr_ovr_count);
    uart_printf("[SENDBENCH] ===== TCP一方向送信スループット計測終了 =====\n");
}
