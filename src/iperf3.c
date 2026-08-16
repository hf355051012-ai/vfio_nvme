// iperf3.c
//
// iperf3サーバ(受信側)実装。標準のiperf3クライアント(PC側)と相互接続
// できるよう、esnet/iperf(GitHub, masterブランチ)の実ソースから直接
// 確認したワイヤプロトコルを実装する。詳細な設計根拠は
// ~/.claude/plans/jazzy-napping-goblet.md を参照。

#include "iperf3.h"
#include "tcp.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* プロトコル定数(esnet/iperf src/iperf.h, src/iperf_api.h より)         */
/* ------------------------------------------------------------------ */

#define IPERF3_COOKIE_SIZE 37u

/* 状態値(制御コネクション上で1バイトsigned charとしてやり取りする)。 */
#define IPERF3_ST_TEST_START      1
#define IPERF3_ST_TEST_RUNNING    2
#define IPERF3_ST_TEST_END        4
#define IPERF3_ST_PARAM_EXCHANGE  9
#define IPERF3_ST_CREATE_STREAMS  10
#define IPERF3_ST_EXCHANGE_RESULTS 13
#define IPERF3_ST_DISPLAY_RESULTS 14
#define IPERF3_ST_IPERF_DONE      16
#define IPERF3_ST_ACCESS_DENIED   (-1)

#define IPERF3_ACCEPT_TIMEOUT_MS   30000u
#define IPERF3_CTRL_TIMEOUT_MS     5000u
#define IPERF3_DATA_TIMEOUT_MS     200u
#define IPERF3_DONE_WAIT_MS        1000u

/* データストリームの送受信チャンクサイズ。bench.cのBENCH_MAX_CHUNKと
 * 同じ値・同じ根拠(実機で61440がRXリング境界のメモリ破壊を誘発したのに
 * 対し32768は複数回の実機テストで再送・BNA/OVR・破壊とも皆無だった —
 * bench.cのs_bench_chunk_sizesコメント参照)。iperf3クライアント自身の
 * デフォルトblksize(TCPで128KB)はこのプロジェクトの実機実績が無いため
 * 採用しない。 */
#define IPERF3_CHUNK 32768u

/* ------------------------------------------------------------------ */
/* 送受信バッファ。malloc無し環境のためstatic(BSS)確保。
 * aligned(64): tcp_send()はゼロコピー送信のためバッファのアドレスを
 * 直接RP1 GEMのTXディスクリプタへ渡す(tcp.hのtcp_send()ドキュメント、
 * bench.cのs_bench_tx/s_bench_rxと同じ理由)。送信(reverse)専用と受信
 * (通常方向)専用で分け、双方とも1セッションにつき片方向しか使わない。 */
static uint8_t s_iperf3_tx[IPERF3_CHUNK] __attribute__((aligned(64)));
static uint8_t s_iperf3_rx[IPERF3_CHUNK] __attribute__((aligned(64)));

#define IPERF3_JSON_SCAN_MAX 512u
#define IPERF3_RESULTS_JSON_MAX 256u

/* ------------------------------------------------------------------ */
/* 汎用ヘルパ                                                           */
/* ------------------------------------------------------------------ */

/* 指定バイト数ちょうどを受信するまでtcp_recv()を繰り返す。
 * nvmet_tcp.cのnvmet_tcp_recv_exact()が過去に踏んだ「受信途中(got>0)で
 * タイムアウトすると消費済みバイトが失われストリーム同期が壊れる」バグ
 * (CLAUDE.md参照)と同じ轍を踏まないよう、got==0の場合のみタイムアウトで
 * 打ち切り、got>0の間はFIN/中断まで待ち直す。
 * 戻り値: 0=成功、-1=失敗(FIN/RST/中断、または1バイトも受け取れないまま
 *         タイムアウト) */
static int recv_exact(tcp_conn_t *conn, uint8_t *buf, uint32_t len, uint32_t timeout_ms)
{
    uint32_t got = 0;
    while (got < len) {
        int n = tcp_recv(conn, buf + got, (uint16_t)(len - got), timeout_ms);
        if (n < 0) {
            if (got == 0) {
                return -1;
            }
            if (tcp_abort_requested()) {
                return -1;
            }
            continue;  /* 部分受信済み: タイムアウトでも諦めず待ち直す */
        }
        if (n == 0) {
            return -1;  /* 相手がFINを送った(半クローズ) */
        }
        got += (uint32_t)n;
    }
    return 0;
}

static int iperf3_send_state(tcp_conn_t *ctrl, int8_t state)
{
    uint8_t b = (uint8_t)state;
    return (tcp_send(ctrl, &b, 1) == 1) ? 0 : -1;
}

/* 4バイトBE長 + JSON本体を1回のtcp_send()で送る。 */
static int iperf3_send_json(tcp_conn_t *ctrl, const char *json, uint32_t len)
{
    static uint8_t s_json_out[4 + IPERF3_RESULTS_JSON_MAX] __attribute__((aligned(64)));
    if (len > IPERF3_RESULTS_JSON_MAX) {
        return -1;
    }
    wr32be(s_json_out, len);
    for (uint32_t i = 0; i < len; i++) {
        s_json_out[4 + i] = (uint8_t)json[i];
    }
    int sent = tcp_send(ctrl, s_json_out, (uint16_t)(4u + len));
    return (sent == (int)(4u + len)) ? 0 : -1;
}

/* 4バイトBE長を読み、本体をscan_bufへ受信する(scan_cap超過分は読み捨てる
 * ―― 将来のiperf3バージョンでJSONが伸びてもストリーム同期を壊さない
 * ための安全策)。scan_bufは常にNUL終端する。
 * 戻り値: 0=成功、-1=失敗 */
static int iperf3_recv_json(tcp_conn_t *ctrl, char *scan_buf, uint32_t scan_cap,
                             uint32_t timeout_ms)
{
    uint8_t len_be[4];
    if (recv_exact(ctrl, len_be, 4, timeout_ms) != 0) {
        return -1;
    }
    uint32_t hsize = rd32be(len_be);

    uint32_t to_scan = (hsize < scan_cap - 1u) ? hsize : (scan_cap - 1u);
    if (to_scan > 0) {
        if (recv_exact(ctrl, (uint8_t *)scan_buf, to_scan, timeout_ms) != 0) {
            return -1;
        }
    }
    scan_buf[to_scan] = '\0';

    uint32_t remaining = hsize - to_scan;
    uint8_t discard[64];
    while (remaining > 0) {
        uint32_t chunk = (remaining < sizeof(discard)) ? remaining : (uint32_t)sizeof(discard);
        if (recv_exact(ctrl, discard, chunk, timeout_ms) != 0) {
            return -1;
        }
        remaining -= chunk;
    }
    return 0;
}

/* 部分文字列検索のみ(完全なJSONパーサは実装しない)。実クライアントの
 * JSON_write()はcJSON_PrintUnformatted()(キーと値の間にスペース無しの
 * コンパクト表記)を使うため、固定文字列検索で安全に判定できる。 */
static int json_has(const char *json, const char *needle)
{
    if (!json || !needle) {
        return 0;
    }
    for (const char *p = json; *p; p++) {
        const char *a = p;
        const char *b = needle;
        while (*a && *b && *a == *b) {
            a++;
            b++;
        }
        if (*b == '\0') {
            return 1;
        }
    }
    return 0;
}

/* 符号なし10進をoutへ前進書き込みし、書いた桁数を返す(NUL終端はしない)。 */
static uint32_t u32_to_str(uint32_t val, char *out)
{
    char tmp[10];
    int n = 0;
    if (val == 0) {
        out[0] = '0';
        return 1;
    }
    while (val > 0) {
        tmp[n++] = (char)('0' + (val % 10u));
        val /= 10u;
    }
    for (int i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    return (uint32_t)n;
}

/* command.cのnvme_bench_print_rate()と同じ固定小数点方式(uart_printf()は
 * %f非対応、CLAUDE.md参照)でMB/sを1桁小数まで表示する。 */
static void iperf3_print_rate(uint64_t bytes, uint32_t ms)
{
    if (ms == 0) {
        uart_printf("0.0MB/s");
        return;
    }
    uint64_t bps = (bytes * 1000ull) / ms;
    uint32_t mb_int  = (uint32_t)(bps / 1000000ull);
    uint32_t mb_frac = (uint32_t)((bps / 100000ull) % 10ull);
    uart_printf("%u.%uMB/s", mb_int, mb_frac);
}

/* サーバ側の結果JSONを組み立てる。クライアント側get_results()
 * (iperf_api.c)が必須とするフィールドをすべて含める:
 * トップレベルのcpu_util_total/cpu_util_user/cpu_util_system/
 * sender_has_retransmits、streams配列(各要素id/bytes/retransmits/
 * jitter/errors/packets必須、start_time/end_timeも欠けるとその後の
 * コードがNULL参照しうるため含める)。 */
static uint32_t iperf3_build_results_json(char *out, uint32_t cap, uint64_t bytes, uint32_t secs)
{
    static const char prefix[] =
        "{\"cpu_util_total\":0,\"cpu_util_user\":0,\"cpu_util_system\":0,"
        "\"sender_has_retransmits\":-1,\"streams\":[{\"id\":1,\"bytes\":";
    static const char mid[] =
        ",\"retransmits\":-1,\"jitter\":0,\"errors\":0,\"packets\":0,\"start_time\":0,\"end_time\":";
    static const char suffix[] = "}]}";

    uint32_t pos = 0;
    #define APPEND_LIT(lit) do { \
        uint32_t l = (uint32_t)(sizeof(lit) - 1); \
        if (pos + l >= cap) { return 0; } \
        for (uint32_t i = 0; i < l; i++) { out[pos + i] = (lit)[i]; } \
        pos += l; \
    } while (0)

    APPEND_LIT(prefix);
    {
        char numbuf[20];
        uint32_t n = u32_to_str((uint32_t)bytes, numbuf);
        if (pos + n >= cap) { return 0; }
        for (uint32_t i = 0; i < n; i++) { out[pos + i] = numbuf[i]; }
        pos += n;
    }
    APPEND_LIT(mid);
    {
        char numbuf[20];
        uint32_t n = u32_to_str(secs, numbuf);
        if (pos + n >= cap) { return 0; }
        for (uint32_t i = 0; i < n; i++) { out[pos + i] = numbuf[i]; }
        pos += n;
    }
    APPEND_LIT(suffix);
    #undef APPEND_LIT

    return pos;
}

/* ------------------------------------------------------------------ */
/* データループ                                                         */
/* ------------------------------------------------------------------ */

/* 制御チャネルを非ブロッキングにポーリングし、TEST_ENDを検知したら1を
 * 返す。tcp_recv(ctrl, &b, 1, 0)はtcp_recv_internal()のdo-whileが
 * timeout_ticks=0でも最低1回は本体を実行するため、真に非ブロッキングな
 * ポーリングとして機能する(tcp.c参照)。 */
static int iperf3_check_test_end(tcp_conn_t *ctrl)
{
    uint8_t b;
    int n = tcp_recv(ctrl, &b, 1, 0);
    if (n == 1 && (int8_t)b == IPERF3_ST_TEST_END) {
        return 1;
    }
    return 0;
}

/* 通常方向: クライアント→Piへのデータを受信し続け、バイト数を積算する。 */
static uint64_t iperf3_run_upload(tcp_conn_t *ctrl, tcp_conn_t *data)
{
    uint64_t total = 0;
    uint64_t since_report = 0;
    uint64_t start = timer_now();
    uint64_t last_report = start;

    for (;;) {
        int n = tcp_recv(data, s_iperf3_rx, (uint16_t)IPERF3_CHUNK, IPERF3_DATA_TIMEOUT_MS);
        if (n > 0) {
            total += (uint64_t)n;
            since_report += (uint64_t)n;
        } else if (n == 0) {
            uart_printf("[iperf3] データストリームが切断されました\n");
            break;
        }
        /* n<0はタイムアウト(データが来ていないだけ) -- 継続する */

        if (iperf3_check_test_end(ctrl)) {
            break;
        }
        if (tcp_abort_requested()) {
            uart_printf("[iperf3] Ctrl+Cで中断\n");
            break;
        }

        if (timeout_sec(last_report, 1)) {
            uint64_t now = timer_now();
            uart_printf("[iperf3] t=%us recv=", (unsigned)get_sec_from(start));
            iperf3_print_rate(since_report, 1000u);
            uart_printf(" total=%uB\n", (unsigned)total);
            since_report = 0;
            last_report = now;
        }
    }
    return total;
}

/* reverse方向: Pi→クライアントへデータを送り続け、バイト数を積算する。 */
static uint64_t iperf3_run_download(tcp_conn_t *ctrl, tcp_conn_t *data)
{
    for (uint32_t i = 0; i < IPERF3_CHUNK; i++) {
        s_iperf3_tx[i] = (uint8_t)(i & 0xFFu);
    }

    uint64_t total = 0;
    uint64_t since_report = 0;
    uint64_t start = timer_now();
    uint64_t last_report = start;

    for (;;) {
        int sent = tcp_send(data, s_iperf3_tx, (uint16_t)IPERF3_CHUNK);
        if (sent <= 0) {
            uart_printf("[iperf3] 送信失敗(state=%d)、計測を中断\n", (int)data->state);
            break;
        }
        total += (uint64_t)sent;
        since_report += (uint64_t)sent;

        if (iperf3_check_test_end(ctrl)) {
            break;
        }
        if (tcp_abort_requested()) {
            uart_printf("[iperf3] Ctrl+Cで中断\n");
            break;
        }

        if (timeout_sec(last_report, 1)) {
            uint64_t now = timer_now();
            uart_printf("[iperf3] t=%us send=", (unsigned)get_sec_from(start));
            iperf3_print_rate(since_report, 1000u);
            uart_printf(" total=%uB\n", (unsigned)total);
            since_report = 0;
            last_report = now;
        }
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* メインドライバ                                                       */
/* ------------------------------------------------------------------ */

int iperf3_run(uint16_t port)
{
    /* ctx=NULL: 従来通りインターフェースを問わず受け付ける(単一
     * インターフェース運用前提の既存呼び出し元、tcp.hのtcp_listen()
     * コメント参照)。 */
    int listener = tcp_listen(port, NULL);
    if (listener < 0) {
        uart_printf("[!] iperf3: listen失敗\n");
        return -1;
    }

    tcp_conn_t ctrl;
    uart_printf("[iperf3] 制御コネクション待ち (port=%u)\n", port);
    if (tcp_accept(listener, &ctrl, IPERF3_ACCEPT_TIMEOUT_MS) != 0) {
        if (tcp_abort_requested()) {
            uart_printf("[iperf3] Ctrl+Cで中断しました\n");
        } else {
            uart_printf("[!] iperf3: 制御コネクション接続待ちタイムアウト\n");
        }
        tcp_unlisten(listener);
        return -1;
    }
    uint8_t client_octets[4];
    ip_to_octets(ctrl.remote_ip, client_octets);
    uart_printf("[iperf3] 制御コネクション確立 (client=%u.%u.%u.%u)\n",
                client_octets[0], client_octets[1], client_octets[2], client_octets[3]);

    uint8_t cookie[IPERF3_COOKIE_SIZE];
    if (recv_exact(&ctrl, cookie, IPERF3_COOKIE_SIZE, IPERF3_CTRL_TIMEOUT_MS) != 0) {
        uart_printf("[!] iperf3: cookie受信失敗\n");
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }

    if (iperf3_send_state(&ctrl, IPERF3_ST_PARAM_EXCHANGE) != 0) {
        uart_printf("[!] iperf3: PARAM_EXCHANGE送信失敗\n");
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }

    static char s_param_json[IPERF3_JSON_SCAN_MAX];
    if (iperf3_recv_json(&ctrl, s_param_json, sizeof(s_param_json), IPERF3_CTRL_TIMEOUT_MS) != 0) {
        uart_printf("[!] iperf3: parametersの受信失敗\n");
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }

    if (json_has(s_param_json, "\"udp\":true") || json_has(s_param_json, "\"sctp\":true")) {
        uart_printf("[!] iperf3: UDP/SCTPは未対応、ACCESS_DENIEDを返します\n");
        iperf3_send_state(&ctrl, IPERF3_ST_ACCESS_DENIED);
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }
    int reverse = json_has(s_param_json, "\"reverse\":true");
    if (json_has(s_param_json, "\"bidirectional\":true")) {
        uart_printf("[!] iperf3: bidirectionalは未対応、通常方向として処理します\n");
    }
    if (json_has(s_param_json, "\"parallel\":2") || json_has(s_param_json, "\"parallel\":3") ||
        json_has(s_param_json, "\"parallel\":4")) {
        uart_printf("[!] iperf3: 複数ストリーム(-P>1)は未対応です。"
                    "クライアントが2本目以降の接続待ちでハングする可能性があります\n");
    }
    uart_printf("[iperf3] parameters受信完了 (%s)\n", reverse ? "reverse" : "normal");

    tcp_conn_t data;
    tcp_accept_begin(listener, &data);

    if (iperf3_send_state(&ctrl, IPERF3_ST_CREATE_STREAMS) != 0) {
        uart_printf("[!] iperf3: CREATE_STREAMS送信失敗\n");
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }

    uart_printf("[iperf3] データストリーム接続待ち\n");
    if (tcp_accept_wait(listener, &data, IPERF3_ACCEPT_TIMEOUT_MS) != 0) {
        if (tcp_abort_requested()) {
            uart_printf("[iperf3] Ctrl+Cで中断しました\n");
        } else {
            uart_printf("[!] iperf3: データストリーム接続待ちタイムアウト\n");
        }
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }

    uint8_t data_cookie[IPERF3_COOKIE_SIZE];
    if (recv_exact(&data, data_cookie, IPERF3_COOKIE_SIZE, IPERF3_CTRL_TIMEOUT_MS) != 0) {
        uart_printf("[!] iperf3: データストリームのcookie受信失敗\n");
        tcp_close(&data);
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }
    int cookie_mismatch = 0;
    for (uint32_t i = 0; i < IPERF3_COOKIE_SIZE; i++) {
        if (cookie[i] != data_cookie[i]) {
            cookie_mismatch = 1;
            break;
        }
    }
    if (cookie_mismatch) {
        /* 単一クライアント前提の簡略化: 不一致はログのみで処理は継続する
         * (実iperf3サーバのようにACCESS_DENIEDを返して再度accept_waitで
         * 待ち直すことはしない)。 */
        uart_printf("[!] iperf3: cookie不一致(想定外の接続?)、処理は継続します\n");
    }
    uart_printf("[iperf3] データストリーム接続完了\n");

    if (iperf3_send_state(&ctrl, IPERF3_ST_TEST_START) != 0 ||
        iperf3_send_state(&ctrl, IPERF3_ST_TEST_RUNNING) != 0) {
        uart_printf("[!] iperf3: TEST_START/TEST_RUNNING送信失敗\n");
        tcp_close(&data);
        tcp_close(&ctrl);
        tcp_unlisten(listener);
        return -1;
    }

    uint64_t test_start_ticks = timer_now();
    uint64_t total_bytes = reverse ? iperf3_run_download(&ctrl, &data)
                                    : iperf3_run_upload(&ctrl, &data);
    uint32_t total_ms = (uint32_t)get_ms_from(test_start_ticks);

    tcp_close(&data);

    uart_printf("[iperf3] ---- 結果 ----\n");
    uart_printf("[iperf3] 総%s=%uバイト 所要時間=%ums 平均=",
                reverse ? "送信" : "受信", (unsigned)total_bytes, total_ms);
    iperf3_print_rate(total_bytes, total_ms);
    uart_printf("\n");

    if (iperf3_send_state(&ctrl, IPERF3_ST_EXCHANGE_RESULTS) == 0) {
        static char s_results_scan[128];
        iperf3_recv_json(&ctrl, s_results_scan, sizeof(s_results_scan), IPERF3_CTRL_TIMEOUT_MS);
        /* クライアントの結果JSONは内容を使わないため戻り値は無視する
         * (読み捨てに失敗した場合でも、以降のDISPLAY_RESULTS送信で
         * クライアント側は既に自身の結果を送り終えているため大きな
         * 実害は無い)。 */

        static char s_results_json[IPERF3_RESULTS_JSON_MAX];
        uint32_t secs = total_ms / 1000u;
        uint32_t len = iperf3_build_results_json(s_results_json, sizeof(s_results_json),
                                                  total_bytes, secs);
        if (len > 0) {
            iperf3_send_json(&ctrl, s_results_json, len);
        }
        iperf3_send_state(&ctrl, IPERF3_ST_DISPLAY_RESULTS);

        uint8_t done_byte;
        recv_exact(&ctrl, &done_byte, 1, IPERF3_DONE_WAIT_MS);  /* ベストエフォート */
    }

    tcp_close(&ctrl);
    tcp_unlisten(listener);
    uart_printf("[iperf3] セッション終了\n");
    return 0;
}
