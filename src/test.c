// test.c
//
// TCP統合テスト — フェーズ5
// tcp_connect() -> tcp_send() -> tcp_recv() -> tcp_close() を一括で流し、
// 長い転送(複数セグメントへの分割・ウィンドウ制御を実地に踏むサイズ)を
// 含めて送受信データの一致まで検証する。
//
// 対向側にTCPエコーサーバ(接続ごとに、指定バイト数を受信し終えてから
// その内容をそのまま送り返すサーバ)を用意しておくことが前提。単純な
// ストリーミングechoではなく「受信完了してから送り返す」設計であること
// が重要 — 本実装のtcp_recv()は受信セグメントを1件分しか保持しない
// 単一スロット設計なので、tcp_send()実行中(まだ送信完了していない段階)
// にエコーが並行して返ってき始めると、複数セグメント分のデータが
// tcp_recv()で取り出す前に上書きされて失われうる。「全部受け取ってから
// まとめて返す」サーバであれば、そのエコーはこちらのtcp_send()が完全に
// 完了した後にしか届かないため、この制約と衝突しない。

#include <stddef.h>
#include "test.h"
#include "tcp.h"
#include "net.h"
#include "netctx.h"
#include "uart.h"
#include "timer.h"
#include "pcie1.h"
#include "mlx5.h"
#include "nvmet.h"
#include "nvme.h"
#include "job.h"
#include "smp.h"
#include "timestamp.h"

/* 256KB(NVMET_MAX_TRANSFER_BYTES相当の1コマンド分)以上の転送を余裕を
 * 持ってテストできるよう、その8倍(2MB)を上限にする(2026-08-08)。
 * 以前256KB固定だったのは、tcp_recv()/tcp_recv_no_ack()のmaxlen引数が
 * uint16_tのまま残っていたため(65536の倍数を渡すと呼び出し時点で暗黙に
 * 下位16bitへtruncateされmaxlen=0になる、tcp.hの各コメント参照)であり、
 * ConnectX/RP1のバックエンド差(net_ctx_t.mss_cap)自体が上限を課して
 * いたわけではない -- tcp_recv()/tcp_recv_no_ack()をuint32_t化したことで
 * この制約は解消した。 */
#define TCP_TEST_MAX_LEN (262144u * 8u)

#define TCP_TEST_RECV_CHUNK_TIMEOUT_MS   3000u  /* tcp_recv()1回あたりの待ち */
#define TCP_TEST_RECV_OVERALL_TIMEOUT_MS 15000u /* エコー全体の受信し終わるまでの上限 */

/* 送信/受信バッファ。malloc無し環境のためstatic(BSS)確保 —
 * icmp.c/tcp.cの作業バッファと同じ理由でスタックを避ける。
 * aligned(64): tcp_send()はゼロコピー送信のためこのバッファのアドレスを
 * 直接RP1 GEMのTXディスクリプタへ渡す(net_buf.hのnet_buf_tと同じ理由の
 * アライメント要求 — GEMのDMAエンジンがバースト転送するため、バッファ
 * 先頭が十分アラインされていないと転送が完了しない実機不具合を確認
 * 済み。net_buf_tに合わせて64バイトにしておく)。tcp.hのtcp_send()の
 * ドキュメント参照。64バイトアラインは下記test_fill_pattern()が要求する
 * 8バイト境界(uint64_t単位ストア)も自動的に満たす。 */
static uint8_t s_test_tx[TCP_TEST_MAX_LEN] __attribute__((aligned(64)));
static uint8_t s_test_rx[TCP_TEST_MAX_LEN] __attribute__((aligned(64)));

/* 決定的なテストパターン(0x00,0x01,...,0xFF,0x00,...の反復)を生成する。
 * 固定パターンなので、受信側で不一致が起きた際にオフセットから
 * 期待値(offset & 0xFF)を逆算しやすい。
 *
 * 8バイト単位でストアする(2026-08-08、1バイトずつのループから変更) --
 * TCP_TEST_MAX_LEN拡張(2MB級)後、1バイトずつのループが無視できない
 * コストになったため。パターンは256バイト周期(0x00-0xFFの反復)で
 * 256は8の倍数なので、周期内の32個の8バイト値だけを一度計算し、以後は
 * それを繰り返し書き込むだけで済む。
 *
 * bufは8バイト境界にアラインされていることが前提(uint64_t*へキャスト
 * して書き込むため) -- この関数はtest.c内でのみ使う静的テスト/作業
 * バッファ(s_test_tx/s_test_rx/s_temp_test_wbuf、いずれもaligned(64)
 * 以上)の先頭ポインタからしか呼ばない。net.h/arp.cが規約とする「任意に
 * アラインされうるポインタ(ワイヤバッファ等)へはvolatile経由のバイト
 * 単位アクセスのみ」はここでは適用されない(呼び出し元を限定している
 * ため) -- 新しい呼び出し元をこの関数に追加する場合は、渡すバッファが
 * 実際に8バイト境界にアラインされていることを確認すること。 */
static void test_fill_pattern(uint8_t *buf, uint32_t len)
{
    uint64_t pattern[32];
    for (uint32_t w = 0; w < 32u; w++) {
        uint64_t v = 0;
        for (uint32_t b = 0; b < 8u; b++) {
            v |= ((uint64_t)(uint8_t)((w * 8u + b) & 0xFFu)) << (8u * b);
        }
        pattern[w] = v;
    }

    uint64_t *buf64 = (uint64_t *)buf;
    uint32_t words = len / 8u;
    for (uint32_t w = 0; w < words; w++) {
        buf64[w] = pattern[w & 31u];
    }
    for (uint32_t i = words * 8u; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xFFu);
    }
}

int tcp_test_run(uint32_t dst_ip, uint16_t dst_port, uint32_t len)
{
    if (len == 0 || len > TCP_TEST_MAX_LEN) {
        uart_printf("[TEST] 長さが範囲外 (1-%u): %u\n", TCP_TEST_MAX_LEN, len);
        return -1;
    }

    test_fill_pattern(s_test_tx, len);

    uint8_t dst_octets[4];
    ip_to_octets(dst_ip, dst_octets);
    uart_printf("[TEST] ===== TCP統合テスト開始: %u.%u.%u.%u:%u len=%u =====\n",
                dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3], dst_port, len);

    tcp_conn_t conn;
    uint64_t t0 = timer_now();

    if (tcp_connect(&conn, dst_ip, dst_port) != 0) {
        uart_printf("[TEST] FAIL: connect失敗\n");
        return -1;
    }
    uint32_t connect_ms = (uint32_t)get_ms_from(t0);

    uint64_t t1 = timer_now();
    int sent = tcp_send(&conn, s_test_tx, len);
    uint32_t send_ms = (uint32_t)get_ms_from(t1);

    if (sent != (int)len) {
        uart_printf("[TEST] FAIL: 送信不完全 (%d/%u バイト)\n", sent, len);
        tcp_close(&conn);
        return -1;
    }
    uart_printf("[TEST] 送信完了: %d バイト (%u ms, MSS=%u, 約%uセグメント)\n",
                sent, send_ms, conn.snd_mss,
                (unsigned)((len + conn.snd_mss - 1) / conn.snd_mss));

    /* エコーされたデータを受信しきるまでtcp_recv()を繰り返す
     * (1回のtcp_recv()は1セグメント分までしか返さないため)。
     * receivedはuint32_t(2026-08-08、uint16_tから拡張): TCP_TEST_MAX_LENを
     * 65536バイト以上へ拡張する際、この変数がuint16_tのままだと
     * received+=nでオーバーフローし無限ループ/誤動作になる
     * (tcp_recv()自体のmaxlen引数もuint16_t→uint32_t化済み、tcp.h参照)。 */
    uint32_t received = 0;
    uint64_t t2 = timer_now();
    while (received < len) {
        if (timeout_ms(t2, TCP_TEST_RECV_OVERALL_TIMEOUT_MS)) {
            uart_printf("[TEST] 受信全体タイムアウト (受信済み %u/%u バイト)\n", received, len);
            break;
        }
        uint32_t space = len - received;
        int n = tcp_recv(&conn, s_test_rx + received, space, TCP_TEST_RECV_CHUNK_TIMEOUT_MS);
        if (n > 0) {
            received += (uint32_t)n;
        } else if (n == 0) {
            uart_printf("[TEST] 相手がFINでクローズ (受信済み %u/%u バイト)\n", received, len);
            break;
        } else {
            uart_printf("[TEST] 受信タイムアウト (受信済み %u/%u バイト)\n", received, len);
            break;
        }
    }
    uint32_t recv_ms = (uint32_t)get_ms_from(t2);

    uint64_t t3 = timer_now();
    tcp_close(&conn);
    uint32_t close_ms = (uint32_t)get_ms_from(t3);

    int ok = (received == len);
    uint32_t mismatch_offset = 0;
    if (ok) {
        for (uint32_t i = 0; i < len; i++) {
            if (s_test_rx[i] != s_test_tx[i]) {
                ok = 0;
                mismatch_offset = i;
                break;
            }
        }
    }

    uart_printf("[TEST] ---- タイミング ----\n");
    uart_printf("[TEST] connect=%ums send=%ums recv=%ums close=%ums\n",
                connect_ms, send_ms, recv_ms, close_ms);

    if (ok) {
        uart_printf("[TEST] PASS: 送受信 %u バイトが完全一致\n", len);
    } else if (received != len) {
        uart_printf("[TEST] FAIL: 受信バイト数不一致 (受信=%u 期待=%u)\n", received, len);
    } else {
        uart_printf("[TEST] FAIL: オフセット %u でデータ不一致 (送信=0x%02X 受信=0x%02X)\n",
                    mismatch_offset, s_test_tx[mismatch_offset], s_test_rx[mismatch_offset]);
    }
    uart_printf("[TEST] ===== TCP統合テスト終了 =====\n");

    return ok ? 0 : -1;
}

/* tcp_loopback_test(): tcp_test_run()と違い外部エコーサーバを使わず、
 * 同一プログラム内の2つのnet_ctx_t(netctx.h)をサーバ役/クライアント役
 * として使う自己完結テスト。tcp_accept_begin()(ブロックしない受け皿
 * 準備)を先に済ませてからtcp_connect()(内部でtcp_poll_once()経由の
 * net_poll_all_and_dispatch()が両方のコンテキストをポーリングするため、
 * サーバ側のSYN処理・SYN|ACK応答が自動的に進む)を呼ぶことで、単一
 * スレッド・ポーリング専用のこのプロジェクトでも「サーバ役がaccept()
 * でブロックする一方、クライアント役がconnect()でブロックする」という
 * 通常は2プロセス/2スレッドを要する構図を1つの関数内で成立させている
 * (tcp.hのtcp_accept_begin()コメント -- nvmet.cが早着SYN対策で同じ
 * パターンを使っている -- と同じ仕組みの転用)。
 *
 * 片方向送信のみ(エコーなし、tcp_test_run()と違いサーバ役は受信して
 * 比較するだけ)。エコーを省いたのは、既存のtcp_recv()が1セグメント分
 * しか保持しない単一スロット設計であることに加え、往復エコーだと
 * サーバ役・クライアント役どちらの送信がいつ完了するかの依存関係が
 * 複雑になるため、まず片方向の疎通・完全性・スループットの検証に
 * とどめた(往復が必要な検証は将来必要になれば別途拡張する)。
 *
 * 既知の制約(close処理が約15〜18秒かかる、実機確認済み): tcp_close()は
 * 呼び出しのたびに無条件でs_conns[]から自分自身を登録解除する
 * (tcp.cのtcp_close()実装参照)。本関数は同一プログラム内でserver_conn/
 * client_connの両方を順にtcp_close()するため、先に閉じた側が
 * s_conns[]から消えた後で、後に閉じた側が送る最後のFINには応答できる
 * 相手が(このプログラム内には)もういない状態になる -- その最後のFINは
 * tcp_send_reliable()の再送上限(5回、RTO指数バックオフで合計約15秒)まで
 * 空振りしてから諦める(データ自体は既に転送・検証済みなので実害は
 * 無いが、テスト1回あたりの所要時間に響く)。外部の別プロセス相手なら
 * 相手ソケットが消えないため本来この問題は起きない -- 同一プログラム内で
 * 両端点を持つテスト特有の制約。根本修正(tcp_close()に「相手の最終FINを
 * 待ってから登録解除する」オプションを追加する等)は今回のスコープ外。 */
int tcp_loopback_test(uint32_t server_ip, uint32_t client_ip, uint16_t port, uint32_t len)
{
    if (len == 0 || len > TCP_TEST_MAX_LEN) {
        uart_printf("[TEST] 長さが範囲外 (1-%u): %u\n", TCP_TEST_MAX_LEN, len);
        return -1;
    }

    net_ctx_t *server_ctx = net_ctx_find_by_ip(server_ip);
    net_ctx_t *client_ctx = net_ctx_find_by_ip(client_ip);
    if (!server_ctx || !client_ctx) {
        uart_printf("[TEST] 未知のIP(登録済みインターフェースではない、`net init mlx5`実行済みか確認)\n");
        return -1;
    }

    test_fill_pattern(s_test_tx, len);

    uint8_t server_octets[4], client_octets[4];
    ip_to_octets(server_ip, server_octets);
    ip_to_octets(client_ip, client_octets);
    uart_printf("[TEST] ===== TCPループバックテスト開始: server=%s(%u.%u.%u.%u) "
                "client=%s(%u.%u.%u.%u) port=%u len=%u =====\n",
                server_ctx->name, server_octets[0], server_octets[1], server_octets[2], server_octets[3],
                client_ctx->name, client_octets[0], client_octets[1], client_octets[2], client_octets[3],
                port, len);

    static tcp_conn_t server_conn;
    static tcp_conn_t client_conn;

    net_ctx_activate(server_ctx);
    /* server_ctxを明示的にbindする(tcp.hのtcp_listen()コメント参照) --
     * この関数自体がserver_ctx/client_ctxという2つの別インターフェースを
     * 同時に扱うため、そのままの意図に合う。 */
    int listener = tcp_listen(port, server_ctx);
    if (listener < 0) {
        uart_printf("[TEST] FAIL: tcp_listen失敗\n");
        return -1;
    }
    tcp_accept_begin(listener, &server_conn);

    net_ctx_activate(client_ctx);
    uint64_t t0 = timer_now();
    if (tcp_connect(&client_conn, server_ip, port) != 0) {
        uart_printf("[TEST] FAIL: connect失敗\n");
        net_ctx_activate(server_ctx);
        tcp_unlisten(listener);
        return -1;
    }
    uint32_t connect_ms = (uint32_t)get_ms_from(t0);

    net_ctx_activate(server_ctx);
    if (tcp_accept_wait(listener, &server_conn, 3000u) != 0) {
        uart_printf("[TEST] FAIL: accept失敗(サーバ側がESTABLISHEDに到達しなかった)\n");
        tcp_unlisten(listener);
        net_ctx_activate(client_ctx);
        tcp_close(&client_conn);
        return -1;
    }
    tcp_unlisten(listener);

    net_ctx_activate(client_ctx);
    uint64_t t1 = timer_now();
    int sent = tcp_send(&client_conn, s_test_tx, len);
    uint32_t send_ms = (uint32_t)get_ms_from(t1);

    if (sent != (int)len) {
        uart_printf("[TEST] FAIL: 送信不完全 (%d/%u バイト)\n", sent, len);
        tcp_close(&client_conn);
        net_ctx_activate(server_ctx);
        tcp_close(&server_conn);
        return -1;
    }
    uart_printf("[TEST] 送信完了: %d バイト (%u ms, MSS=%u, 約%uセグメント)\n",
                sent, send_ms, client_conn.snd_mss,
                (unsigned)((len + client_conn.snd_mss - 1) / client_conn.snd_mss));

    net_ctx_activate(server_ctx);
    /* receivedはuint32_t(2026-08-08、uint16_tから拡張、tcp_test_run()と
     * 同じ理由 -- TCP_TEST_MAX_LEN拡張時にuint16_tのままだとオーバーフロー
     * する)。 */
    uint32_t received = 0;
    uint64_t t2 = timer_now();
    while (received < len) {
        if (timeout_ms(t2, TCP_TEST_RECV_OVERALL_TIMEOUT_MS)) {
            uart_printf("[TEST] 受信全体タイムアウト (受信済み %u/%u バイト)\n", received, len);
            break;
        }
        uint32_t space = len - received;
        int n = tcp_recv(&server_conn, s_test_rx + received, space, TCP_TEST_RECV_CHUNK_TIMEOUT_MS);
        if (n > 0) {
            received += (uint32_t)n;
        } else if (n == 0) {
            uart_printf("[TEST] 相手がFINでクローズ (受信済み %u/%u バイト)\n", received, len);
            break;
        } else {
            uart_printf("[TEST] 受信タイムアウト (受信済み %u/%u バイト)\n", received, len);
            break;
        }
    }
    uint32_t recv_ms = (uint32_t)get_ms_from(t2);

    uint64_t t3 = timer_now();
    tcp_close(&server_conn);
    net_ctx_activate(client_ctx);
    tcp_close(&client_conn);
    uint32_t close_ms = (uint32_t)get_ms_from(t3);

    int ok = (received == len);
    uint32_t mismatch_offset = 0;
    if (ok) {
        for (uint32_t i = 0; i < len; i++) {
            if (s_test_rx[i] != s_test_tx[i]) {
                ok = 0;
                mismatch_offset = i;
                break;
            }
        }
    }

    uart_printf("[TEST] ---- タイミング ----\n");
    uart_printf("[TEST] connect=%ums send=%ums recv=%ums close=%ums\n",
                connect_ms, send_ms, recv_ms, close_ms);
    if (send_ms > 0) {
        uart_printf("[TEST] 送信スループット: 約%u KB/s\n", (unsigned)(((uint64_t)len * 1000u / send_ms) / 1024u));
    }

    if (ok) {
        uart_printf("[TEST] PASS: 送受信 %u バイトが完全一致\n", len);
    } else if (received != len) {
        uart_printf("[TEST] FAIL: 受信バイト数不一致 (受信=%u 期待=%u)\n", received, len);
    } else {
        uart_printf("[TEST] FAIL: オフセット %u でデータ不一致 (送信=0x%02X 受信=0x%02X)\n",
                    mismatch_offset, s_test_tx[mismatch_offset], s_test_rx[mismatch_offset]);
    }
    uart_printf("[TEST] ===== TCPループバックテスト終了 =====\n");

    return ok ? 0 : -1;
}

// tcploopbenchのモードビット(test.h参照)。ユーザー指示(2026-08-10)により
// 「別コマンドを作るのではなく既存コマンドにモードを追加する」方針へ変更 --
// 以前ここにあった`tcp_loopback_bench_split()`という別関数/`tcploopbenchsplit`
// という別コマンドは廃止し、`tcp_loopback_bench()`のmode引数へ統合した。
//
// TCPLOOPBENCH_MODE_CORE_SPLIT: server(target)側のlisten/accept/recvループを
// core1へピン止めしたjob(job.h)として走らせ、client(initiator)側の送信は
// 従来通りcore0で同期的に回す -- `ts core 0`が送信側、`ts core 1`が受信側
// だけのログになる(LSO診断でinitiator/targetの`ts`を分離したいという要望に
// 対応)。このプロジェクトのマルチコア設計(job.h冒頭コメント参照)では
// core1は`job_scheduler_tick()`のcooperative pollingでしかコードを実行
// できないため、`test`コマンドのNVMe/TCP core分割(net_ctx_set_owner_core()+
// job_pin_to_core()、nvmet.cのnvmet_job_start()参照)と同じパターンを使う。
//
// TCPLOOPBENCH_MODE_SINGLE_SHOT: 継続送信ループの代わりに`tcp_send()`を
// 1回だけ呼ぶ(単発転送)。duration_msは「その1回分の転送が受信側に届き
// 切るまで待つ猶予」として使う(継続送信の期間ではない)。1バーストだけの
// `ts`ログを見たい場合、継続モードだと複数バーストが混在して追いづらい
// ため。

/* CORE_SPLIT時のserver(target)側job状態機械。job stepの契約(job.h
 * 「呼ばれるたびに『今できる分だけ』処理してすぐ戻ること」)を守るため、
 * 1tickあたり高々1回の短いtcp_recv()呼び出し(既存の同期版と同じ
 * timeout_val_ms=1)に留め、複数秒に渡るブロッキングループは書かない。 */
typedef enum {
    BENCH_SPLIT_ST_LISTEN = 0,
    BENCH_SPLIT_ST_WAIT_ACCEPT,
    BENCH_SPLIT_ST_DRAIN,
    BENCH_SPLIT_ST_FINAL_DRAIN,
} bench_split_state_t;

/* 2026-08-10、実機で発見した本物のバグの修正: 以前はBENCH_SPLIT_ST_DRAIN
 * が`drain_timeout_ms`(=duration_ms)だけで無条件にFINAL_DRAINへ遷移して
 * いた -- これはcore0(クライアント)の送信ループとは完全に独立したタイマー
 * のため、クライアント側が`tcp_send()`内部のRTO再送(最大5回、200ms〜
 * 3200msの倍々、合計最大6.2秒)でduration_msを超えて送り続けている最中に、
 * core1のjobが先にFINAL_DRAIN→クローズ(FIN送信)してしまう競合を実機で
 * 確認した(teraterm.logで「送信ウィンドウ再送」の途中に「close: FIN送信
 * (能動close)」が割り込むのを直接確認済み)。クローズ済みの相手に対する
 * 再送は永遠にACKされず、xfer_lenがduration_ms以内に送り切れないサイズに
 * なった途端、末尾のごく僅かなバイトだけが再送上限到達まで失敗し続ける
 * 現象として再現した。
 *
 * 修正: FINAL_DRAINへの遷移を「クライアントが明示的に送信完了(成功/
 * 諦め問わず)を知らせてきた(client_send_done)」ことをトリガーにする --
 * これによりサーバはクライアントの送信ループが実際に終わるまで待つ
 * (非分割版の同期実装と同じ順序保証を、フラグ経由で再現する)。
 * クライアント側が本当にハングした場合にjobが永久に残り続けないよう、
 * 安全弁としてduration_ms+BENCH_SPLIT_SAFETY_MARGIN_MS(データ再送
 * 最大6.2秒+close時のFIN再送、実機で約15〜18秒かかることを確認済み
 * [CLAUDE.md「tcp_loopback_test()の既知の制約」節参照]、を踏まえ余裕を
 * 持たせた値)の絶対タイムアウトも維持する。 */
#define BENCH_SPLIT_SAFETY_MARGIN_MS 60000u

typedef struct {
    net_ctx_t *server_ctx;
    uint16_t   port;
    uint32_t   drain_timeout_ms; /* 単発モードでは待ち猶予、継続モードでは送信継続時間と同じ値(安全弁の絶対タイムアウト計算にのみ使う) */
    int        listener;
    tcp_conn_t server_conn;
    uint64_t   accept_deadline_start;
    uint64_t   drain_start;
    uint64_t   final_drain_start;
    volatile uint64_t total_recvd; /* core0側(呼び出し元)が結果表示のために読む */
    volatile int ready;  /* 1 = accept受け皿を用意済み、core0はtcp_connect()してよい */
    volatile int failed; /* 1 = listen/accept失敗、core0は待つのを諦めてよい */
    volatile int client_send_done; /* 1 = core0の送信ループ(再送含む)が完全に終わった、core1はFINAL_DRAINへ進んでよい */
} bench_split_ctx_t;

static bench_split_ctx_t s_bench_split_ctx;

static job_result_t bench_split_server_job_step(job_t *self)
{
    bench_split_ctx_t *bc = (bench_split_ctx_t *)self->ctx;

    switch (self->state) {
    case BENCH_SPLIT_ST_LISTEN: {
        net_ctx_activate(bc->server_ctx);
        bc->listener = tcp_listen(bc->port, bc->server_ctx);
        if (bc->listener < 0) {
            uart_printf("[BENCH] tcp_listen失敗 (core1)\n");
            bc->failed = 1;
            return JOB_DONE;
        }
        tcp_accept_begin(bc->listener, &bc->server_conn);
        bc->ready = 1; /* core0のtcp_connect()を解禁 */
        bc->accept_deadline_start = timer_now();
        self->state = BENCH_SPLIT_ST_WAIT_ACCEPT;
        return JOB_WAITING;
    }
    case BENCH_SPLIT_ST_WAIT_ACCEPT: {
        if (tcp_accept_ready_poll(bc->listener) == 1) {
            tcp_unlisten(bc->listener);
            bc->drain_start = timer_now();
            self->state = BENCH_SPLIT_ST_DRAIN;
            return JOB_WAITING;
        }
        /* tcp_accept_ready_poll()自体はタイムアウトしない(tcp.hのコメント
         * 参照)ため、呼び出し側であるここで管理する -- client側のconnect()
         * が失敗した場合等にjobが永久にWAIT_ACCEPTのまま残らないようにする
         * (このジョブは常駐サーバではなく1回限りの診断用途のため)。 */
        if (timeout_ms(bc->accept_deadline_start, 10000u)) {
            uart_printf("[BENCH] accept待ちタイムアウト (core1)\n");
            tcp_unlisten(bc->listener);
            return JOB_DONE;
        }
        return JOB_WAITING;
    }
    case BENCH_SPLIT_ST_DRAIN: {
        int n = tcp_recv(&bc->server_conn, s_test_rx, TCP_TEST_MAX_LEN, 1u);
        if (n > 0) {
            bc->total_recvd += (uint32_t)n;
        }
        /* client_send_done(core0が明示的に立てる)を主トリガーとし、
         * client側が本当にハングした場合のためだけの安全弁として
         * drain_timeout_ms+BENCH_SPLIT_SAFETY_MARGIN_MSの絶対タイムアウト
         * も残す(上記bench_split_ctx_tのコメント参照)。 */
        if (bc->client_send_done ||
            timeout_ms(bc->drain_start, bc->drain_timeout_ms + BENCH_SPLIT_SAFETY_MARGIN_MS)) {
            bc->final_drain_start = timer_now();
            self->state = BENCH_SPLIT_ST_FINAL_DRAIN;
        }
        return JOB_WAITING;
    }
    case BENCH_SPLIT_ST_FINAL_DRAIN:
    default: {
        int n = tcp_recv(&bc->server_conn, s_test_rx, TCP_TEST_MAX_LEN, 1u);
        if (n > 0) {
            bc->total_recvd += (uint32_t)n;
            bc->final_drain_start = timer_now(); /* データが来ている間は猶予を延ばす */
        }
        if (timeout_ms(bc->final_drain_start, 500u)) {
            tcp_close(&bc->server_conn);
            return JOB_DONE;
        }
        return JOB_WAITING;
    }
    }
}

/* mode bit0 : core分離(target側をcore1のjobへピン止め、ts core 0=送信側/ts core 1=受信側に分離) */
/* mode bit1 : 単発転送モード */
int tcp_loopback_bench(uint32_t server_ip, uint32_t client_ip, uint16_t port, uint32_t duration_ms,
                        uint32_t mode, uint32_t xfer_len)
{
    net_ctx_t *server_ctx = net_ctx_find_by_ip(server_ip);
    net_ctx_t *client_ctx = net_ctx_find_by_ip(client_ip);
    if (!server_ctx || !client_ctx) {
        uart_printf("[BENCH] 未知のIP(登録済みインターフェースではない、`net init mlx5`実行済みか確認)\n");
        return -1;
    }

    const int core_split  = (mode & TCPLOOPBENCH_MODE_CORE_SPLIT) != 0;
    const int single_shot = (mode & TCPLOOPBENCH_MODE_SINGLE_SHOT) != 0;
    if (xfer_len == 0u || xfer_len > TCP_TEST_MAX_LEN) {
        xfer_len = TCP_TEST_MAX_LEN;
    }

    test_fill_pattern(s_test_tx, TCP_TEST_MAX_LEN);

    uart_printf("[BENCH] ===== TCP持続スループット計測開始: server=%s client=%s port=%u "
                "duration=%ums xfer_len=%uB core_split=%d single_shot=%d =====\n",
                server_ctx->name, client_ctx->name, port, duration_ms, xfer_len,
                core_split, single_shot);

    static tcp_conn_t server_conn; /* core_split==0の時のみ使う */
    static tcp_conn_t client_conn;
    int listener = -1;

    if (core_split) {
        if (smp_boot_core1() != 0) {
            uart_printf("[BENCH] FAIL: core1起動に失敗、core_split不可\n");
            return -1;
        }
        net_ctx_set_owner_core(server_ctx, 1u);

        s_bench_split_ctx.server_ctx = server_ctx;
        s_bench_split_ctx.port = port;
        s_bench_split_ctx.drain_timeout_ms = duration_ms;
        s_bench_split_ctx.listener = -1;
        s_bench_split_ctx.total_recvd = 0;
        s_bench_split_ctx.ready = 0;
        s_bench_split_ctx.failed = 0;
        s_bench_split_ctx.client_send_done = 0;

        job_t *job = job_spawn(bench_split_server_job_step, &s_bench_split_ctx, "bench-split-server");
        if (!job) {
            uart_printf("[BENCH] FAIL: job_spawn失敗(ジョブテーブル満杯)\n");
            return -1;
        }
        job_pin_to_core(job, 1u);

        /* core1のjobがtcp_listen()+tcp_accept_begin()を終える(ready=1)まで
         * core0側で待つ -- job_scheduler_tick()はcore1がpinned_core一致の
         * 自分のtickで自然に呼ぶ(secondary_main()のアイドルループ、smp.c
         * 参照)ため、ここでは単純にreadyフラグをポーリングするだけでよい。 */
        uint64_t wait_start = timer_now();
        while (!s_bench_split_ctx.ready && !s_bench_split_ctx.failed) {
            if (timeout_ms(wait_start, 3000u)) {
                uart_printf("[BENCH] FAIL: core1側のlisten準備がタイムアウトしました\n");
                return -1;
            }
        }
        if (s_bench_split_ctx.failed) {
            uart_printf("[BENCH] FAIL: core1側でlisten失敗\n");
            return -1;
        }

        net_ctx_activate(client_ctx);
        if (tcp_connect(&client_conn, server_ip, port) != 0) {
            uart_printf("[BENCH] FAIL: connect失敗\n");
            /* core1のjobはBENCH_SPLIT_ST_WAIT_ACCEPTの10秒タイムアウトで
             * 自然に片付く(job_request_cancel()はジョブテーブルインデックス
             * を要求するが、job_spawn()の戻り値からは取得できないため
             * ここから明示的にキャンセルする手段は無い)。 */
            return -1;
        }
    } else {
        net_ctx_activate(server_ctx);
        listener = tcp_listen(port, server_ctx);
        if (listener < 0) {
            uart_printf("[BENCH] FAIL: tcp_listen失敗\n");
            return -1;
        }
        tcp_accept_begin(listener, &server_conn);

        net_ctx_activate(client_ctx);
        if (tcp_connect(&client_conn, server_ip, port) != 0) {
            uart_printf("[BENCH] FAIL: connect失敗\n");
            net_ctx_activate(server_ctx);
            tcp_unlisten(listener);
            return -1;
        }

        net_ctx_activate(server_ctx);
        if (tcp_accept_wait(listener, &server_conn, 8000u) != 0) {
            uart_printf("[BENCH] FAIL: accept失敗(サーバ側がESTABLISHEDに到達しなかった)\n");
            tcp_unlisten(listener);
            net_ctx_activate(client_ctx);
            tcp_close(&client_conn);
            return -1;
        }
        tcp_unlisten(listener);
    }

    uint64_t test_start = timer_now();
    uint64_t last_report = test_start;
    uint64_t total_sent = 0;
    uint64_t total_recvd = 0; /* core_split==0の時のみ使う(core_split時はs_bench_split_ctx.total_recvdを見る) */
    uint64_t send_rounds = 0;

    if (single_shot) {
        net_ctx_activate(client_ctx);
        int sent = tcp_send(&client_conn, s_test_tx, xfer_len);
        if (sent > 0) {
            total_sent += (uint32_t)sent;
            send_rounds++;
        }
        if (!core_split) {
            /* core_split==0の単発モードは、下記の共通「最終ドレイン」
             * ループ(500ms猶予)だけで受信側を排出する -- 継続モードの
             * ような毎ラウンドdrainは1回しか送らないので不要。 */
        }
    } else {
        /* パイプライン化(バッチドレイン)の試行は実機で撤回した
         * (2026-08-07、CLAUDE.md「`tcploopbench`のバッチドレイン方式
         * パイプライン化を試行、実機で繰り返し不安定化・撤回」節参照)。
         * ドレインの頻度を下げる設計自体は理論上安全なはずだったが、
         * ConnectX PF0<->PF1ループバックでの実機再テストで、コマンドが
         * 数十秒〜1分以上応答を返さなくなる事象を複数回確認し、原因を
         * 特定できないまま安全側に倒してこの安定版(毎ラウンド明示的に
         * ドレイン)へ戻した。 */
        while (!timeout_ms(test_start, duration_ms)) {
            net_ctx_activate(client_ctx);
            int sent = tcp_send(&client_conn, s_test_tx, xfer_len);
            if (sent > 0) {
                total_sent += (uint32_t)sent;
                send_rounds++;
            }

            if (!core_split) {
                /* サーバ側は溜まっている分を排出するだけ(相手のウィンドウを
                 * 空けるため) -- エコーは返さない、片方向スループット計測。
                 * core_split時はcore1のjobが自分のtickで独立に排出するため
                 * ここでは何もしない。 */
                net_ctx_activate(server_ctx);
                for (;;) {
                    int n = tcp_recv(&server_conn, s_test_rx, TCP_TEST_MAX_LEN, 1u);
                    if (n <= 0) break;
                    total_recvd += (uint32_t)n;
                }
            }

            if (timeout_sec(last_report, 1)) {
                uint64_t now = timer_now();
                uart_printf("[BENCH] t=%us sent=%uB recvd=%uB rounds=%u\n",
                            (unsigned)get_sec_from(test_start),
                            (unsigned)total_sent,
                            (unsigned)(core_split ? s_bench_split_ctx.total_recvd : total_recvd),
                            (unsigned)send_rounds);
                last_report = now;
            }
        }
    }

    /* client(core0)の送信ループ(tcp_send()内部のRTO再送含む)が完全に
     * 終わった -- 成功/再送上限到達で諦めた、いずれの場合もここに到達
     * する。core1のjob(bench_split_server_job_step())はこのフラグを見て
     * 初めてFINAL_DRAINへ進む(上記bench_split_ctx_tのコメント参照、
     * 実機で確認した「サーバが先にクローズしてクライアントの再送が
     * 永遠にACKされない」競合の修正)。 */
    if (core_split) {
        s_bench_split_ctx.client_send_done = 1;
    }

    uint32_t elapsed_ms = (uint32_t)get_ms_from(test_start);

    net_ctx_activate(client_ctx);
    tcp_close(&client_conn);

    if (core_split) {
        /* core1側のjob(FINAL_DRAINで最後の500ms猶予を消化中)がJOB_DONEに
         * なるまで、単純に十分な猶予(FINAL_DRAINの500ms+バッファ)だけ
         * 待つ。 */
        timer_delay_ms(1000u);
    } else {
        /* 送信終了後、サーバ側にまだ届いていない分が残っているかもしれない
         * ので、短い猶予を設けて最後の排出を行う。 */
        uint64_t drain_start = timer_now();
        net_ctx_activate(server_ctx);
        while (!timeout_ms(drain_start, 500u)) {
            int n = tcp_recv(&server_conn, s_test_rx, TCP_TEST_MAX_LEN, 50u);
            if (n <= 0) break;
            total_recvd += (uint32_t)n;
        }
        tcp_close(&server_conn);
    }

    uint64_t final_recvd = core_split ? s_bench_split_ctx.total_recvd : total_recvd;

    uart_printf("[BENCH] ---- 結果 ----\n");
    uart_printf("[BENCH] elapsed=%ums rounds=%u sent=%uB recvd=%uB\n",
                elapsed_ms, (unsigned)send_rounds, (unsigned)total_sent, (unsigned)final_recvd);
    if (elapsed_ms > 0) {
        uint64_t bps = (total_sent * 1000ull) / elapsed_ms;
        uint32_t mb_int  = (uint32_t)(bps / 1000000ull);
        uint32_t mb_frac = (uint32_t)((bps / 100000ull) % 10ull);
        uart_printf("[BENCH] 送信スループット: 約%u.%uMB/s(相手への到達分=%uB, %u%%)\n",
                    mb_int, mb_frac, (unsigned)final_recvd,
                    total_sent > 0 ? (unsigned)((final_recvd * 100ull) / total_sent) : 0u);
    }
    uart_printf("[BENCH] ===== 計測終了%s =====\n",
                core_split ? "(`ts core 0`=送信側/`ts core 1`=受信側)" : "");

    return 0;
}

/* temp_test()専用のwriteテストデータバッファ(nvme_write_begin()自体は
 * 内部にデータバッファを持たないため、呼び出し側であるtemp_test()が
 * 用意する)。malloc無し環境のためstatic(BSS)確保。
 *
 * nvme_write_begin()/nvme_read_begin()およびそれらの進行状況を監視する
 * nvme_io_job_done()/nvme_io_job_result()はnvme.c/nvme.hに一本化されて
 * いる(command.c等、他の呼び出し元とすべて同じ実装を共有する) -- 以前
 * ここにあったtest.c専用の重複実装(s_nvme_test_sqe/s_nvme_test_exec/
 * nvme_test_exec_job_step()/nvme_test_state()/nvme_test_done()/
 * nvme_test_result())は削除済み。 */
static uint8_t s_temp_test_wbuf[8388608] __attribute__((aligned(8192)));

/* temp_test()の最初にts_log()を再開(記録開始)し、終了時に一時停止する
 * (ユーザー指示) -- コード自身が障害検出直後に即座にpauseすれば、人間が
 * 手動で`ts pause`するのと違い反応の遅れで肝心の記録が上書きされる心配が
 * 無いため、freezeという別バッファへのコピー機構は不要だった。次回の
 * temp_test()呼び出しの冒頭で再開されるまでリングバッファはそのまま
 * 静止するので、`ts`/`ts core 1`でじっくり確認できる。initiator(nvme、
 * 常にcore0)とtarget(nvmet、mode&1ならcore1)両方を対象にするため、
 * ts_log_set_paused()の明示的コア指定版(timestamp.h)を使う
 * (SMP_MAX_CORESは現状core0/core1の2つ)。 */
static void temp_test_ts_pause_all(int paused)
{
    ts_log_set_paused_core(0u, paused);
    ts_log_set_paused_core(1u, paused);
}

int temp_test(uint64_t* param)
{
    temp_test_ts_pause_all(0);  /* 再開(前回の一時停止を解除、記録開始) */

    uart_printf("Start Test\n");
    timer_delay_ms(500);
    int i;
    static char namebuf0[16] __attribute__((aligned(8))) = "mlx5-pf0";
    static char namebuf1[16] __attribute__((aligned(8))) = "mlx5-pf1";
    static uint8_t ip[4] __attribute__((aligned(8))) = {192, 168, 101, 11};
    static char subnqn[128] __attribute__((aligned(128))) = "nqn.2014-08.org.nvmexpress:uuid:deadbeef-cafe-babe-dead-beefcafebabe";
    net_ctx_t *ctx0;
    net_ctx_t *ctx1;
    nvmet_ctx_t *s_nvmet_ctx;
    uint64_t port  = 4420u;

    uint64_t nsid  = param[0];
    uint64_t lba   = param[1];
    uint64_t nlb   = param[2];
    uint64_t mode  = param[3];


    for(i=0;i<TESTPARAM;i++){
        uart_printf("param%d : 0x%08x\n", i, param[i]);
    }
    uart_printf("\n");
    timer_delay_ms(100);

    test_fill_pattern(s_temp_test_wbuf, sizeof(s_temp_test_wbuf));

    int already_connected = (s_nvme_ctx.io_connected != 0);

    if (!already_connected) {
        if (s_nvme_ctx.busy) {
            uart_printf("[TEST] 前回の操作が完了していません、切断して片付けます...\n");
            nvme_disconnect(&s_nvme_ctx);
            job_delay_ms(1500); /* targetがFINを検出しACCEPT_WAITへ戻るのを待つ */
        }

        // pcie1 reset
        if (pcie1_reset_link() != 0) {
            uart_printf("Error pcie1_reset_link\n");
            temp_test_ts_pause_all(1);
            return 1;
        }

        // net init mlx5
        if(mlx5_net_init_dual_loopback() != 0) {
            uart_printf("Error mlx5_net_init_dual_loopback\n");
            temp_test_ts_pause_all(1);
            return 1;
        }

        uart_printf("ctx0 = net_ctx_find()\n");
        ctx0 = net_ctx_find(namebuf0);
        uart_printf("ctx1 = net_ctx_find()\n");
        ctx1 = net_ctx_find(namebuf1);

        if(mode&1){
            if (smp_boot_core1() != 0) {
                uart_printf("[TEST] core1起動に失敗、target(nvmet)はcore0のまま動作します\n");
            } else if (ctx1) {
                net_ctx_set_owner_core(ctx1, 1u);
                uart_printf("[TEST] target(mlx5-pf1)をcore1へ引き渡しました\n");
            }
        }

        // net use mlx5-pf1
        net_ctx_activate(ctx1);

        s_nvmet_ctx = NVMET_CTX_SLOT(3);
        if (nvmet_job_start(s_nvmet_ctx, (uint16_t)port, ctx1, "manual") != 0) {
            uart_printf("[!] nvmet: 起動失敗\n");
        }

        // net use mlx5-pf0
        net_ctx_activate(ctx0);

        // nvme connect 192.168.101.11 4420 nqn.2014-08.org.nvmexpress:uuid:deadbeef-cafe-babe-dead-beefcafebabe
        uint32_t dst_ip = ip_from_octets(ip[0], ip[1], ip[2], ip[3]);
        nvme_connect_job_start(&s_nvme_ctx, dst_ip, (uint16_t)port, subnqn);

        uart_printf("nvme connect完了を待っています...\n");
        uint64_t connect_wait_start = timer_now();
        while (s_nvme_ctx.busy){
            job_delay_ms(50);
            if (timeout_ms(connect_wait_start, 8000u)) {
                uart_printf("[TEST] nvme connect失敗またはタイムアウト、write/readテストをスキップします\n");
                temp_test_ts_pause_all(1);
                return 1;
            }
        }
        uart_printf("nvme connect完了 (lba_size=%u)\n", s_nvme_ctx.lba_size);
    } else {
        uart_printf("[TEST] 既存の接続を再利用します"
                     "(pcie1 reset/net init/core1起動/再接続をスキップ)\n");
    }

    nvme_io_exec_prof_reset();
    nvmet_ctx_prof_reset(NVMET_CTX_SLOT(3));

    int single_shot = ((mode & 0xf0) == 0x10);
    int do_read = ((mode & 0x4u) != 0);
    const char *io_label = do_read ? "read" : "write";
    int use_pipeline = ((mode & 0x200u) != 0) && !single_shot;
    uart_printf("%s負荷テスト開始 (%s, %u ブロック/回 = %u バイト/回)\n",
                io_label,
                single_shot ? "単発1回" : (use_pipeline ? "3秒間・パイプライン化" : "3秒間"),
                (unsigned)nlb, (unsigned)((uint32_t)nlb * s_nvme_ctx.lba_size));
    uint32_t write_count = 0;
    uint64_t load_test_start = timer_now();
    uint32_t elapsed_ms = 0;
    uint64_t total_bytes = 0;

    if (use_pipeline) {
        uint32_t pl_count = 0;
        uint64_t pl_bytes = 0;
        uint32_t pl_elapsed = 0;
        if (do_read) {
            nvme_read_pipelined_run(&s_nvme_ctx, (uint32_t)nsid, lba, s_temp_test_wbuf, (uint32_t)nlb,
                                     3000u, &pl_count, &pl_bytes, &pl_elapsed);
        } else {
            nvme_write_pipelined_run(&s_nvme_ctx, (uint32_t)nsid, lba, s_temp_test_wbuf, (uint32_t)nlb,
                                      3000u, &pl_count, &pl_bytes, &pl_elapsed);
        }
        write_count = pl_count;
        total_bytes = pl_bytes;
        elapsed_ms  = pl_elapsed;
    } else {
        uint64_t single_shot_submit_tick = 0;
        uint64_t single_shot_done_tick = 0;
        int single_shot_completed = 0;
        while (!timeout_ms(load_test_start, 3000u)) {
            if (mlx5_net_any_sq_halted()) {
                uart_printf("[TEST] SQがhalt状態のため負荷テストを中断します\n");
                break;
            }
            if (!s_nvme_ctx.busy) {
                single_shot_submit_tick = timer_now();
                int rc = do_read
                    ? nvme_read_begin(&s_nvme_ctx, (uint32_t)nsid, lba, s_temp_test_wbuf, (uint32_t)nlb)
                    : nvme_write_begin(&s_nvme_ctx, (uint32_t)nsid, lba, s_temp_test_wbuf, (uint32_t)nlb);
                if (rc == 0) {
                    write_count++;
                } else {
                    uart_printf("[TEST] nvme_%s_begin失敗、負荷テストを中断\n", io_label);
                    break;
                }
            } else {
                job_delay_ms(1);
            }
            if (single_shot) break;
        }
        if (single_shot && write_count > 0) {
            uint64_t wait_start = timer_now();
            while (s_nvme_ctx.busy && !timeout_ms(wait_start, 10000u)) { /* 10秒 */
                job_delay_ms(1);
            }
            single_shot_done_tick = timer_now();
            single_shot_completed = !s_nvme_ctx.busy;
            uint32_t latency_ms = (uint32_t)ticks_to_ms(single_shot_done_tick - single_shot_submit_tick);
            if (single_shot_completed) {
                uart_printf("[TEST] 単発%s完了レイテンシ: %u ms (%u バイト)\n",
                            io_label, latency_ms, (unsigned)((uint32_t)nlb * s_nvme_ctx.lba_size));
            } else {
                uart_printf("[TEST] 単発%s: 10秒以内に完了しませんでした(busyのまま、%u ms経過)\n",
                            io_label, latency_ms);
            }
        }
        elapsed_ms = (uint32_t)get_ms_from(load_test_start);
        total_bytes = (uint64_t)write_count * (uint32_t)nlb * s_nvme_ctx.lba_size;
    }

    uart_printf("%s負荷テスト終了: %u回実行 (計%u バイト, %u ms)\n",
                io_label, write_count, (unsigned)total_bytes, elapsed_ms);
    if (!single_shot && elapsed_ms > 0) {
        uint64_t bps = (total_bytes * 1000ull) / elapsed_ms;
        uint32_t mb_int  = (uint32_t)(bps / 1000000ull);
        uint32_t mb_frac = (uint32_t)((bps / 100000ull) % 10ull);
        uint32_t iops    = (uint32_t)((uint64_t)write_count * 1000ull / elapsed_ms);
        uart_printf("%s負荷テスト スループット: 約%u.%uMB/s (約%u IOPS)\n",
                    io_label, mb_int, mb_frac, iops);
    }

    {
        uint64_t drain_start = timer_now();
        while (s_nvme_ctx.busy && !timeout_ms(drain_start, 3000u)) {
            job_delay_ms(1);
        }
    }
    temp_test_ts_pause_all(1);

    uart_printf("[TEST] --- ステート滞在時間統計(直前のwrite負荷テスト区間) ---\n");
    nvme_io_exec_prof_dump();
    nvmet_ctx_prof_dump(NVMET_CTX_SLOT(3));

    if (mode & 0x100u) {
        nvme_disconnect(&s_nvme_ctx);
        uart_printf("[TEST] 切断しました(mode bit8指定)\n");
    }

    uart_printf("\nTest Normal end\n");
    return 0;
}
