#ifndef TEST_H
#define TEST_H

#include <stdint.h>
#include "nvme.h"

#define TESTPARAM 4
int temp_test(uint64_t* param);

/* nvme_write_begin()/nvme_read_begin()、およびそれらの進行状況を監視する
 * nvme_io_job_done()/nvme_io_job_result()はnvme.hで宣言されている
 * (nvme.cに実装が一本化されており、command.c等の他の呼び出し元と全て
 * 同じ実装を共有する -- test.hに独自の重複宣言は置かない)。 */

/* ================================================================
 * test.h — TCP統合テスト — フェーズ5
 *
 * tcp_connect() -> tcp_send()(複数セグメントに分割されるような長さも
 * 指定可能) -> tcp_recv()(エコー折返しの受信) -> tcp_close() を一括で
 * 流し、送受信データがバイト単位で完全一致するかまで検証する。
 *
 * 対向側にTCPエコーサーバ(接続ごとに、指定バイト数を受信し終えてから
 * その内容をそのまま送り返すサーバ)を用意しておくことが前提。
 * ================================================================ */

/* dst_ip:dst_portへ接続し、決定的なテストパターン(0x00,0x01,...,0xFFの
 * 反復)をlenバイト送信、対向からエコーされた同じ長さのデータを受信して
 * 一致検証する。結果はuart_printf()で逐次報告する。
 * 戻り値: 0=PASS(送受信一致)、-1=FAIL(接続/送信/受信失敗、または不一致) */
int tcp_test_run(uint32_t dst_ip, uint16_t dst_port, uint32_t len);

/* tcp_test_run()の自己完結版 -- 外部のTCPエコーサーバを必要とせず、
 * 同一プログラム内の2つのネットワークインターフェース(netctx.h、
 * server_ip/client_ipそれぞれのIPを持つ登録済みnet_ctx_t、例えば
 * `net init mlx5`が用意するConnectX PF0/PF1のループバック構成)を
 * サーバ役/クライアント役として使い、片方向送信(サーバは受信するだけ、
 * エコーは返さない)の疎通・完全性・スループットを検証する。
 * server_ip/client_ipは共にnet_ctx_find_by_ip()で解決できる(=登録済み)
 * 必要がある。
 * 戻り値: 0=PASS、-1=FAIL(接続/送信/受信失敗、不一致、または未知のIP) */
int tcp_loopback_test(uint32_t server_ip, uint32_t client_ip, uint16_t port, uint32_t len);

/* tcp_loopback_test()の持続スループット計測版。1回のtcp_send()/tcp_recv()
 * では短すぎて(ms精度では測れないほど速い)正確なMB/s値が出せないため、
 * 同一コネクションを張ったまま送信・排出をduration_msの間ループし続け、
 * 累積バイト数/経過時間からスループットを計算する。
 *
 * mode: 下記TCPLOOPBENCH_MODE_*のビットOR(0=従来通り、client/server双方
 * ともcore0の単一同期関数内、継続送信ループ)。
 * - TCPLOOPBENCH_MODE_CORE_SPLIT: server(target)側のlisten/accept/recv
 *   ループをcore1へピン止めしたjob(job.h)として走らせ、client(initiator)
 *   側の送信は従来通りcore0で同期的に回す -- `ts core 0`が送信側、
 *   `ts core 1`が受信側だけのログになる(LSO診断でinitiator/targetの
 *   `ts`を分離したい場合に使う)。初回呼び出し時にsmp_boot_core1()で
 *   core1を起動する(以後は再利用、二重起動しても無害)。
 * - TCPLOOPBENCH_MODE_SINGLE_SHOT: 継続送信ループの代わりにtcp_send()を
 *   1回だけ呼ぶ(単発転送)。duration_msは「その1回分の転送が受信側に
 *   届き切るまで待つ猶予」として使う(継続送信の期間ではない)。1バースト
 *   だけの`ts`ログを見たい場合、継続モードだと複数バーストが混在して
 *   追いづらいため。
 *
 * xfer_len: 1回のtcp_send()呼び出しで送るバイト数(0を渡すと既定値
 * TCP_TEST_MAX_LEN[test.c、2MB]を使う)。TCP_TEST_MAX_LENを超える値は
 * 安全側にTCP_TEST_MAX_LENへクランプする(s_test_tx/s_test_rxの実容量を
 * 超えて読み書きしないため)。単発モードでLSOが実際にどの程度の塊で
 * トリガーされるかを`ts`で見たい場合等、送信サイズを細かく制御したい
 * ケース向け。
 * 戻り値: 0=完走、-1=接続確立自体に失敗(未知のIP、accept/core1起動失敗等) */
#define TCPLOOPBENCH_MODE_CORE_SPLIT  0x1u
#define TCPLOOPBENCH_MODE_SINGLE_SHOT 0x2u
int tcp_loopback_bench(uint32_t server_ip, uint32_t client_ip, uint16_t port, uint32_t duration_ms,
                        uint32_t mode, uint32_t xfer_len);

#endif /* TEST_H */
