#include "uart.h"
#include "timer.h"
#include "smp.h"
#include "crc32c.h"
#include "vfio.h"
#include "mlx5.h"
#include "nvme_rdma.h"
#include "net.h"
#include "arp.h"
#include "ip.h"
#include "ipv6.h"
#include "udp.h"
#include "netif.h"
#include "job.h"
#include "nvme.h"
#include "nvmet.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>   /* read/usleep(常駐シェルの非ブロッキング入力・アイドル待ち) */
#include <fcntl.h>
#include <stdlib.h>   /* atoi/strtoul/exit */
#include <termios.h>  /* raw モード(履歴/矢印キーのため canonical/echo を無効化) */
#include <stdio.h>    /* setvbuf(raw モードで1文字ずつ即時エコーするため無バッファ化) */
#include "timestamp.h" /* ts コマンド(ts_log ダンプ) */
#include "tcp.h"       /* ackthresh コマンド(g_tcp_ack_threshold) */

/*=================================================================
 * CRC32C を 2 段階で確認する。
 *  (1) 既知テストベクタ CRC32C("123456789")=0xE3069283
 *  (2) ポインタのアライメント 0〜7 の全パターンで、1 バイト単位の基準計算と
 *      一致すること(crc32c() は先頭端数を食って 8 整列させてから 8 バイト
 *      単位で回すため、オフセットごとに通る経路が変わる。ダイジェストを
 *      有効にすると実際にデータ開始位置が 4 整列になるので、この検証が
 *      無いと片方の経路だけ壊れていても気づけない)
 * crc32c() は生の実行中 CRC を返す規約なので、ここで ~ を取る。
 *
 * 戻り値:
 *   0=全て一致、-1=不一致
 * コール元:
 *   main()
 * ===============================================================*/
static int crc32c_selftest(void)
{
    const char *v = "123456789";
    uint32_t digest = ~crc32c(0xFFFFFFFFu, v, 9);
    int ok = (digest == 0xE3069283u);
    uart_printf("[selftest] crc32c(\"123456789\") = 0x%08X (期待 0xE3069283) -> %s\n",
                digest, ok ? "OK" : "NG");

    static uint8_t buf[4096 + 8];
    for (unsigned i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i * 31u + 7u);
    int align_ok = 1;
    for (unsigned off = 0; off < 8u; off++) {
        /* 基準: 長さ1で呼べば必ず1バイト単位の経路を通る */
        uint32_t ref = 0xFFFFFFFFu;
        for (unsigned i = 0; i < 4096u; i++) ref = crc32c(ref, &buf[off + i], 1);
        uint32_t got = crc32c(0xFFFFFFFFu, &buf[off], 4096u);
        if (got != ref) {
            uart_printf("[selftest] crc32c align off=%u: 0x%08X != 基準 0x%08X -> NG\n",
                        off, got, ref);
            align_ok = 0;
        }
    }
    uart_printf("[selftest] crc32c 全アライメント(offset 0-7, 4096B) -> %s\n",
                align_ok ? "OK" : "NG");

    return (ok && align_ok) ? 0 : -1;
}

/*=================================================================
 * タイマ周波数を表示し、timer_delay_ms(10) の実測経過を出す。
 *
 * コール元:
 *   main()
 * ===============================================================*/
static void timer_selftest(void)
{
    uart_printf("[selftest] timer_freq = %u Hz\n", (uint32_t)timer_freq());
    uint64_t t0 = timer_now();
    timer_delay_ms(10u);
    uint64_t us = get_us_from(t0);
    uart_printf("[selftest] timer_delay_ms(10) 実測経過 = %u us (>=10000 なら OK)\n",
                (uint32_t)us);
}

/*=================================================================
 * スピンロックの lock/unlock が期待通り状態を変えるかを確認する。
 *
 * コール元:
 *   main()
 * ===============================================================*/
static void spinlock_selftest(void)
{
    smp_spinlock_t lock = 0;
    smp_spin_lock(&lock);
    int held = (lock != 0);
    smp_spin_unlock(&lock);
    int freed = (lock == 0);
    uart_printf("[selftest] spinlock lock/unlock -> %s\n",
                (held && freed) ? "OK" : "NG");
}

/*=================================================================
 * core1 を起動し、ハートビートが増加すること(pthread が実際に回っている
 * こと)を確認する。
 *
 * コール元:
 *   main()
 * ===============================================================*/
static void smp_selftest(void)
{
    uart_printf("[selftest] smp_core_index()(メインスレッド) = %u (期待 0)\n",
                smp_core_index());
    if (smp_boot_core1() != 0) {
        uart_printf("[selftest] smp_boot_core1 失敗\n");
        return;
    }
    uint64_t hb0 = g_core1_heartbeat;
    timer_delay_ms(50u);
    uint64_t hb1 = g_core1_heartbeat;
    uart_printf("[selftest] core1 alive=%d heartbeat %u -> %u (増加していれば pthread 稼働) -> %s\n",
                g_core1_alive, (uint32_t)hb0, (uint32_t)hb1,
                (hb1 > hb0) ? "OK" : "NG");
}

static mlx5_dev_t s_dev0, s_dev1; /* 大きい構造体なので static */

/*=================================================================
 * VFIO スロットの PF を掴んで ConnectX を bring-up する。Bus Master を
 * 有効化し BAR0 を mmap して dev->bar0_base に入れ、mlx5_hca_bringup() を
 * 通す。
 *
 * 引数:
 *   slot     - vfio_init() が返したスロット番号
 *   dev      - 初期化する HCA ハンドル
 *   pf_index - 0=PF0 / 1=PF1(DMA 領域の前半後半の割り当てに使う)
 *   label    - ログ用の名前("PF0" 等)
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   run_dual_pf()
 * ===============================================================*/
static int bringup_pf(int slot, mlx5_dev_t *dev, uint8_t pf_index, const char *label)
{
    if (slot < 0) {
        uart_printf("[main] %s: vfio_init 失敗 -- vfio-pci バインド / IOMMU を確認\n", label);
        return -1;
    }
    vfio_enable_bus_master(slot);
    uint32_t id = vfio_cfg_read32(slot, 0x00);
    uart_printf("[main] %s Vendor=0x%04X Device=0x%04X\n", label, id & 0xffffu, (id >> 16) & 0xffffu);

    uint64_t bar_size = 0;
    void *bar0 = vfio_map_bar(slot, 0, &bar_size);
    if (!bar0) {
        uart_printf("[main] %s BAR0 mmap 失敗\n", label);
        return -1;
    }
    memset(dev, 0, sizeof(*dev));
    dev->bar0_base = (uint64_t)(uintptr_t)bar0;
    dev->pf_index  = pf_index;

    int rc = mlx5_hca_bringup(dev, label, 0);
    uart_printf("[main] %s mlx5_hca_bringup -> %d (%s)\n", label, rc, rc == 0 ? "OK" : "FAILED");
    return rc;
}

nvme_ctx_t s_nvme_ctx;

static nvmet_ctx_t s_x86_nvmet; /* .bss(内蔵 RAM ディスク含む、TCP 経路は CPU 側) */

static uint8_t s_nvmetcp_buf[262144] __attribute__((aligned(4096)));

/*=================================================================
 * mlx5_monitor_summary3() へ渡す PCI コンフィグ空間リード関数。
 *
 * 引数:
 *   ctx - VFIO スロット番号を intptr_t で包んだもの
 *   off - コンフィグ空間オフセット
 * 戻り値:
 *   読んだ 32bit 値
 * コール元:
 *   shell_dispatch() から関数ポインタとして
 * ===============================================================*/
static uint32_t x86_cfg_rd(void *ctx, uint32_t off)
{
    return vfio_cfg_read32((int)(intptr_t)ctx, off);
}

/* ====================================================================== */
/* 常駐シェル(rpi5 の command_shell_run() 相当)                          */
/*                                                                        */
/* rpi5 は main() が対話ループ(command_shell_run)に入り job_scheduler_tick */
/* を回し続けるため、一度ブリングアップしたカードも nvmet ターゲットジョブも */
/* プロセスが終わらない限り常駐する。x86 はこれまで「1モード実行して return */
/* →プロセス終了」だったので毎回コールドスタートになっていた。ここで同じ    */
/* 常駐ループを持たせる: 起動時に1回だけフルブリングアップし、以後は          */
/* コマンドを対話的に受け付け、アイドル時に job_scheduler_tick() を回す。     */
/* これで monitor は再初期化なしで即実行でき、nvmet ターゲットも常駐する。    */
/* ====================================================================== */

static int s_shell_nvmet_started = 0;
static int s_shell_tcp_connected = 0;

/*=================================================================
 * NVMe/TCP の常駐セッション(target@core1 + initiator@core0)を 1 回だけ
 * 確立し、以後の tcpbench で再利用する。`nvmet` コマンドで既にターゲットが
 * 常駐していればそれを使う。
 *
 * 戻り値:
 *   0=確立済み、-1=インターフェース未登録/接続タイムアウト
 * コール元:
 *   shell_tcpbench()
 * ===============================================================*/
static int shell_ensure_tcp_session(uint8_t want_hdgst, uint8_t want_ddgst)
{
    /* ダイジェストは ICReq/ICResp でコネクション確立時に一度だけ合意する。
     * 要求が変わったら既存セッションは使い回せないので張り直す。 */
    if (s_shell_tcp_connected &&
        (s_nvme_ctx.req_hdgst != want_hdgst || s_nvme_ctx.req_ddgst != want_ddgst)) {
        uart_printf("tcpbench: digest設定が変わったのでセッションを張り直します\n");
        nvme_tcp_close(&s_nvme_ctx.io);
        nvme_tcp_close(&s_nvme_ctx.admin);
        s_nvme_ctx.io_connected = 0;
        s_shell_tcp_connected   = 0;
        /* 常駐 target が FIN を検出して次のクライアント待ちへ戻るまで回す。 */
        uint64_t t0 = timer_now();
        while (!timeout_ms(t0, 1500u)) {
            job_scheduler_tick();
            net_poll_all_and_dispatch();
        }
    }
    if (s_shell_tcp_connected) return 0;
    s_nvme_ctx.req_hdgst = want_hdgst;
    s_nvme_ctx.req_ddgst = want_ddgst;
    netif_t *ctx0 = netif_find("mlx5-pf0");
    netif_t *ctx1 = netif_find("mlx5-pf1");
    if (!ctx0 || !ctx1) { uart_printf("netif 未登録\n"); return -1; }

    if (!s_shell_nvmet_started) {
        if (smp_boot_core1() == 0) netif_set_owner_core(ctx1, 1u);
        netif_activate(ctx1);
        if (nvmet_job_start(&s_x86_nvmet, 4421u, ctx1, "manual") != 0) {
            uart_printf("tcpbench: ターゲット起動失敗\n"); return -1;
        }
        s_shell_nvmet_started = 1;
        uart_printf("tcpbench: ターゲット常駐起動 (pf1, core1)\n");
    }

    netif_activate(ctx0);
    static char subnqn[128] = "nqn.2014-08.org.nvmexpress:uuid:deadbeef-cafe-babe-dead-beefcafebabe";
    nvme_connect_job_start(&s_nvme_ctx, ip_from_octets(192, 168, 101, 11), 4421u, subnqn);
    uint64_t t = timer_now();
    while (s_nvme_ctx.busy) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        if (timeout_ms(t, 15000u)) { uart_printf("tcpbench: connect タイムアウト\n"); return -1; }
    }
    if (s_nvme_ctx.lba_size == 0u) { uart_printf("tcpbench: lba_size=0\n"); return -1; }
    s_shell_tcp_connected = 1;
    uart_printf("tcpbench: initiator 接続完了 (lba_size=%u)\n", s_nvme_ctx.lba_size);
    return 0;
}

/*=================================================================
 * シェルの `ping6`。アクティブなインターフェースから ICMPv6 Echo Request を
 * 全ノードマルチキャスト(ff02::1)へ送り、対向 PF からの Echo Reply を待つ。
 * 2 ポートとも自作ドライバが握っているため Linux から ping6 できず、疎通は
 * この内部往復で確認する。リンクローカルアドレスも表示する。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_ping6(void)
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;

    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);
    uart_printf("ping6: 自分のリンクローカル = fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                ll[8], ll[9], ll[10], ll[11], ll[12], ll[13], ll[14], ll[15]);

    uint32_t before = g_ipv6_echo_reply_count[core];
    if (ipv6_send_echo_request(0x1234u, 1u, 32u) != 0) {
        uart_printf("ping6: Echo Request 送信失敗\n");
        return;
    }
    uart_printf("ping6: Echo Request 送信 (ff02::1 宛, データ32B)\n");

    uint64_t t0 = timer_now();
    while (!timeout_ms(t0, 2000u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
        if (g_ipv6_echo_reply_count[core] != before) {
            uart_printf("ping6: OK -- Echo Reply を受信 (%u us)\n",
                        (unsigned)get_us_from(t0));
            return;
        }
    }
    uart_printf("ping6: タイムアウト(Echo Reply が返りませんでした)\n");
}

static volatile uint32_t s_udptest_rx;
static volatile uint16_t s_udptest_len;

/*=================================================================
 * `udptest` が待ち受けるポートの受信ハンドラ。受信を記録するだけ。
 *
 * 引数:
 *   data/len  - UDP ペイロード
 *   src_ip    - 送信元 IPv4
 *   src_port  - 送信元ポート
 *   src_mac   - 送信元 MAC(未使用)
 * コール元:
 *   udp_input()
 * ===============================================================*/
static void shell_udptest_handler(const uint8_t *data, size_t len,
                                   const netaddr_t *src, uint16_t src_port,
                                   const uint8_t *src_mac)
{
    (void)data; (void)src_mac;
    s_udptest_len = (uint16_t)len;
    s_udptest_rx++;
    if (src->family == NETADDR_V6) {
        uart_printf("[udptest] 受信 %u バイト (from IPv6 ...:%02x%02x:%u)\n",
                    (unsigned)len, src->a[14], src->a[15], src_port);
    } else {
        uart_printf("[udptest] 受信 %u バイト (from %u.%u.%u.%u:%u)\n",
                    (unsigned)len, src->a[0], src->a[1], src->a[2], src->a[3], src_port);
    }
}

/*=================================================================
 * シェルの `udptest`。対向 PF へ UDP を 1 発送り、受信ハンドラが呼ばれるかを
 * 確認する。続けて待ち受けの無いポートへも送り、ICMP Port Unreachable が
 * 返ることも確認する(RoCEv2 の 4791 は除外されるが、それ以外は返る)。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_udptest(void)
{
    const uint16_t port_ok = 7777u;
    const uint16_t port_ng = 7778u;

    if (udp_bind(port_ok, shell_udptest_handler) != 0) {
        uart_printf("udptest: udp_bind 失敗\n");
        return;
    }

    uint32_t peer_ip = (net_active_ip() == 0xC0A8650Au) ? 0xC0A8650Bu : 0xC0A8650Au;
    uint8_t peer_mac[6];
    if (arp_resolve(peer_ip, peer_mac) != 0) {
        uart_printf("udptest: ARP 解決失敗 (%u.%u.%u.%u)\n",
                    (peer_ip >> 24) & 0xFFu, (peer_ip >> 16) & 0xFFu,
                    (peer_ip >> 8) & 0xFFu, peer_ip & 0xFFu);
        udp_unbind(port_ok);
        return;
    }

    uint8_t dst_ip[4] = { (uint8_t)(peer_ip >> 24), (uint8_t)(peer_ip >> 16),
                          (uint8_t)(peer_ip >> 8), (uint8_t)peer_ip };
    static uint8_t body[64];
    for (unsigned i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(0xA0u + i);

    uint32_t before = s_udptest_rx;
    if (udp_send(dst_ip, peer_mac, port_ok, port_ok, body, (uint16_t)sizeof(body)) != 0) {
        uart_printf("udptest: udp_send 失敗\n");
        udp_unbind(port_ok);
        return;
    }
    uart_printf("udptest: %u バイトを %u.%u.%u.%u:%u へ送信\n",
                (unsigned)sizeof(body), dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], port_ok);

    uint64_t t0 = timer_now();
    while (!timeout_ms(t0, 1000u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
        if (s_udptest_rx != before) break;
    }
    if (s_udptest_rx != before) {
        uart_printf("udptest: OK -- 受信ハンドラが %u バイトで呼ばれました\n",
                    (unsigned)s_udptest_len);
    } else {
        uart_printf("udptest: NG -- 受信ハンドラが呼ばれませんでした\n");
    }

    /* 待ち受けの無いポート -- 相手が Port Unreachable を返すはず。 */
    uart_printf("udptest: 待ち受け無しポート %u へ送信(Port Unreachable 期待)\n", port_ng);
    udp_send(dst_ip, peer_mac, port_ok, port_ng, body, 16u);
    t0 = timer_now();
    while (!timeout_ms(t0, 500u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
    }

    udp_unbind(port_ok);
}

/*=================================================================
 * 対向 PF のリンクローカルアドレスを求める。2 ポートは同一プロセスから
 * 駆動しているので、相手側インターフェースの MAC から EUI-64 を組み立てる
 * (NDP で探すまでもなく確定できる)。
 *
 * 引数:
 *   out - 16 バイトの格納先
 * 戻り値:
 *   対向の netif_t。見つからなければ NULL
 * コール元:
 *   shell_udptest6(), shell_tcp6test()
 * ===============================================================*/
static netif_t *shell_peer_ll6(uint8_t out[16])
{
    netif_t *a = netif_find("mlx5-pf0");
    netif_t *b = netif_find("mlx5-pf1");
    netif_t *peer = (g_active_ctx == a) ? b : a;
    if (!peer) return NULL;

    const uint8_t *mac = peer->mac;
    for (unsigned i = 0; i < 16; i++) out[i] = 0;
    out[0] = 0xFE; out[1] = 0x80;
    out[8]  = (uint8_t)(mac[0] ^ 0x02u);
    out[9]  = mac[1];
    out[10] = mac[2];
    out[11] = 0xFF;
    out[12] = 0xFE;
    out[13] = mac[3];
    out[14] = mac[4];
    out[15] = mac[5];
    return peer;
}

/*=================================================================
 * シェルの `udptest6`。対向 PF のリンクローカル宛に UDP over IPv6 を 1 発
 * 送り、受信ハンドラが呼ばれることを確認する。宛先 MAC は NDP(Neighbor
 * Solicitation/Advertisement)で解決する。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_udptest6(void)
{
    const uint16_t port = 7777u;

    uint8_t peer_ll[16];
    if (!shell_peer_ll6(peer_ll)) {
        uart_printf("udptest6: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }

    if (udp_bind(port, shell_udptest_handler) != 0) {
        uart_printf("udptest6: udp_bind 失敗\n");
        return;
    }

    uint8_t peer_mac[6];
    if (ndp_resolve(peer_ll, peer_mac) != 0) {
        uart_printf("udptest6: NDP 解決失敗\n");
        udp_unbind(port);
        return;
    }
    uart_printf("udptest6: NDP 解決 OK (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                peer_mac[0], peer_mac[1], peer_mac[2],
                peer_mac[3], peer_mac[4], peer_mac[5]);

    static uint8_t body[64];
    for (unsigned i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(0x50u + i);

    uint32_t before = s_udptest_rx;
    if (udp_send6(peer_ll, peer_mac, port, port, body, (uint16_t)sizeof(body)) != 0) {
        uart_printf("udptest6: udp_send6 失敗\n");
        udp_unbind(port);
        return;
    }
    uart_printf("udptest6: %u バイトを対向のリンクローカル:%u へ送信\n",
                (unsigned)sizeof(body), port);

    uint64_t t0 = timer_now();
    while (!timeout_ms(t0, 1000u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
        if (s_udptest_rx != before) break;
    }
    if (s_udptest_rx != before) {
        uart_printf("udptest6: OK -- 受信ハンドラが %u バイトで呼ばれました\n",
                    (unsigned)s_udptest_len);
    } else {
        uart_printf("udptest6: NG -- 受信ハンドラが呼ばれませんでした\n");
    }
    udp_unbind(port);
}

/*=================================================================
 * シェルの `tcp6test`。同一プロセス内の 2 つのインターフェースを
 * サーバ役/クライアント役にして、IPv6 上で TCP を確立しデータを 1 往復
 * させる。ポーリング専用・単一スレッドなので、接続待ちは
 * tcp_accept_begin()(ブロックしない受け皿準備)で用意しておき、
 * tcp_connect_poll() が内部で回すポーリングにサーバ側の処理も乗せる。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_tcp6test(void)
{
    const uint16_t port = 6000u;
    static tcp_conn_t s_srv, s_cli;

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("tcp6test: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uart_printf("tcp6test: client=%s server=%s port=%u\n", self->name, peer->name, port);

    /* サーバ役の受け皿を先に用意する(対向インターフェース宛に束縛)。 */
    int listener = tcp_listen(port, peer);
    if (listener < 0) {
        uart_printf("tcp6test: tcp_listen 失敗\n");
        return;
    }
    s_srv.state = TCP_CLOSED;
    tcp_accept_begin(listener, &s_srv);

    netif_activate(self);
    tcp_connect_begin6(&s_cli, peer_ll, port);

    uint64_t t0 = timer_now();
    int established = 0;
    while (!timeout_ms(t0, 3000u)) {
        netif_activate(self);
        int r = tcp_connect_poll(&s_cli);
        net_poll_all_and_dispatch();
        if (r == 1) { established = 1; break; }
        if (r < 0) break;
    }
    if (!established) {
        uart_printf("tcp6test: NG -- 接続確立できず (client state=%d server state=%d)\n",
                    (int)s_cli.state, (int)s_srv.state);
        tcp_unlisten(listener);
        return;
    }
    uart_printf("tcp6test: 接続確立 (MSS=%u)\n", (unsigned)s_cli.snd_mss);

    /* フルサイズ(MSS)セグメントを何本も流す大きさにしておく。小さいままだと
     * 1 セグメントに収まってしまい、L3 ヘッダ 20 バイト増による MTU 超過
     * (NIC が無言で捨てる)を踏まずに PASS してしまう。 */
    static uint8_t tx[65536];
    static uint8_t rx[65536];
    for (unsigned i = 0; i < sizeof(tx); i++) tx[i] = (uint8_t)(i * 7u + 3u);

    netif_activate(self);
    /* tcp_send() は送信できたバイト数を返す(失敗/中断で -1)。 */
    if (tcp_send(&s_cli, tx, sizeof(tx)) != (int)sizeof(tx)) {
        uart_printf("tcp6test: NG -- 送信失敗\n");
        tcp_close(&s_cli);
        tcp_unlisten(listener);
        return;
    }

    uint32_t got = 0;
    t0 = timer_now();
    while (got < sizeof(tx) && !timeout_ms(t0, 3000u)) {
        netif_activate(peer);
        int n = tcp_recv(&s_srv, rx + got, (uint32_t)sizeof(rx) - got, 20u);
        if (n > 0) got += (uint32_t)n;
        else if (n < 0) break;
        net_poll_all_and_dispatch();
    }

    int match = (got == sizeof(tx));
    for (uint32_t i = 0; match && i < got; i++) {
        if (rx[i] != tx[i]) match = 0;
    }
    uart_printf("tcp6test: 受信 %u/%u バイト -- %s\n",
                (unsigned)got, (unsigned)sizeof(tx),
                match ? "PASS(内容一致)" : "NG(内容不一致または不足)");

    netif_activate(self);
    tcp_close(&s_cli);
    netif_activate(peer);
    tcp_close(&s_srv);
    tcp_unlisten(listener);
    netif_activate(self);
}

/* ---- ベンチ引数パース + サマリ表示(bench/tcpbench 共通) ---- */
#define BENCH_MAX_CHUNKS 8u
typedef struct {
    uint32_t chunk;       /* 1 コマンドあたりの転送バイト数 */
    int      is_read;     /* 1=read、0=write */
    uint64_t bytes;       /* 転送できた総バイト数 */
    uint32_t count;       /* 完了コマンド数 */
    uint32_t elapsed_ms;  /* 実測時間(0 なら測定失敗) */
} bench_res_t;
typedef struct {
    uint32_t chunks[BENCH_MAX_CHUNKS];
    unsigned nchunks;
    int      do_r, do_w;
    uint32_t qd;
    uint8_t  hdgst, ddgst;  /* NVMe/TCP のみ。RDMA には digest の概念が無い */
} bench_plan_t;

/*=================================================================
 * 文字列を空白区切りで最大 n トークンに分割する(s を破壊する)。
 *
 * 引数:
 *   s   - 分割対象(書き換えられる)
 *   tok - 各トークン先頭の格納先
 *   n   - tok の要素数
 * 戻り値:
 *   実際に得られたトークン数
 * コール元:
 *   bench_plan_parse(), shell_simdelay(), shell_ts()
 * ===============================================================*/
static unsigned shell_tokenize(char *s, char *tok[], unsigned n)
{
    unsigned c = 0;
    while (*s && c < n) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        tok[c++] = s;
        while (*s && *s != ' ' && *s != '\t') s++;
        if (*s) *s++ = 0;
    }
    return c;
}

/*=================================================================
 * ベンチ引数 "[KB[,KB...]] [r|w|rw] [qd] [hdgst] [ddgst]" を解析する。
 * 省略時は 8/64/256KB・read+write・qd=8・digest 無効。hdgst/ddgst は
 * 位置ではなくキーワードで判定するので、qd の有無に関わらず書ける
 * (NVMe/TCP 専用。RDMA トランスポートには digest の概念が無い)。
 *
 * 引数:
 *   args - 引数文字列(破壊される)
 *   pl   - 解析結果の格納先
 * コール元:
 *   shell_tcpbench(), shell_rdmabench()
 * ===============================================================*/
static void bench_plan_parse(char *args, bench_plan_t *pl)
{
    char *tok[5];
    unsigned nt = shell_tokenize(args, tok, 5);
    pl->qd = 8u; pl->do_r = 1; pl->do_w = 1;
    pl->hdgst = 0; pl->ddgst = 0;

    /* 先に digest キーワードを抜き取り、残りを従来通り位置引数として扱う。 */
    unsigned kept = 0;
    for (unsigned i = 0; i < nt; i++) {
        if (strcmp(tok[i], "hdgst") == 0)  { pl->hdgst = 1; continue; }
        if (strcmp(tok[i], "ddgst") == 0)  { pl->ddgst = 1; continue; }
        if (strcmp(tok[i], "digest") == 0) { pl->hdgst = 1; pl->ddgst = 1; continue; }
        tok[kept++] = tok[i];
    }
    nt = kept;

    if (nt == 0) {
        pl->chunks[0] = 8192u; pl->chunks[1] = 65536u; pl->chunks[2] = 262144u; pl->nchunks = 3;
    } else {
        /* tok[0] = カンマ区切りのKBリスト。atoi は ',' で止まるので順に読む。 */
        pl->nchunks = 0;
        char *p = tok[0];
        while (*p && pl->nchunks < BENCH_MAX_CHUNKS) {
            uint32_t kb = (uint32_t)atoi(p);
            pl->chunks[pl->nchunks++] = (kb ? kb : 64u) * 1024u;
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
        }
        if (pl->nchunks == 0) { pl->chunks[0] = 65536u; pl->nchunks = 1; }
    }
    if (nt >= 2) {
        if (tok[1][0] == 'r' && tok[1][1] == 0) pl->do_w = 0;
        else if (tok[1][0] == 'w' && tok[1][1] == 0) pl->do_r = 0;
        /* "rw" その他は read+write 両方 */
    }
    if (nt >= 3) { uint32_t q = (uint32_t)atoi(tok[2]); if (q) pl->qd = q; }
}

/*=================================================================
 * 符号なし 10 進を文字列にする。
 *
 * 引数:
 *   v   - 変換する値
 *   out - 出力先(NUL 終端する)
 *   cap - out のバイト数
 * 戻り値:
 *   書き込んだ文字数(NUL を除く)
 * コール元:
 *   bench_summary()
 * ===============================================================*/
static unsigned bench_u32_str(uint32_t v, char *out, unsigned cap)
{
    char rev[12];
    unsigned n = 0;
    if (v == 0u) rev[n++] = '0';
    while (v > 0u && n < sizeof(rev)) { rev[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    unsigned o = 0;
    while (n > 0u && o + 1u < cap) out[o++] = rev[--n];
    out[o] = 0;
    return o;
}

/*=================================================================
 * 100 倍固定小数点値を "整数部.小数2桁" の文字列にする。uart_printf は
 * %f を持たないため、右詰めの数値列は一度文字列へ組み立ててから %s で出す。
 *
 * 引数:
 *   x100 - 実値の 100 倍
 *   out  - 出力先(NUL 終端する)
 *   cap  - out のバイト数
 * 戻り値:
 *   書き込んだ文字数(NUL を除く)
 * コール元:
 *   bench_lat_str(), bench_summary()
 * ===============================================================*/
static unsigned bench_fx2_str(uint64_t x100, char *out, unsigned cap)
{
    char rev[24];
    unsigned n = 0;
    uint64_t ip = x100 / 100ull;
    unsigned fp = (unsigned)(x100 % 100ull);
    if (ip == 0ull) rev[n++] = '0';
    while (ip > 0ull && n < sizeof(rev)) { rev[n++] = (char)('0' + (unsigned)(ip % 10ull)); ip /= 10ull; }
    unsigned o = 0;
    while (n > 0u && o + 4u < cap) out[o++] = rev[--n];
    if (o + 3u < cap) {
        out[o++] = '.';
        out[o++] = (char)('0' + fp / 10u);
        out[o++] = (char)('0' + fp % 10u);
    }
    out[o] = 0;
    return o;
}

/*=================================================================
 * 平均レイテンシ(ns)を linux_loopback.sh と同じ "N.NN us" / "N.NN ms"
 * 表記にする(1ms 以上なら ms)。
 *
 * 引数:
 *   ns  - 平均レイテンシ(ナノ秒)
 *   out - 出力先(NUL 終端する)
 *   cap - out のバイト数
 * コール元:
 *   bench_summary()
 * ===============================================================*/
static void bench_lat_str(uint64_t ns, char *out, unsigned cap)
{
    const char *unit;
    unsigned o;
    if (ns >= 1000000ull) { o = bench_fx2_str(ns / 10000ull, out, cap); unit = " ms"; }
    else                  { o = bench_fx2_str(ns / 10ull,    out, cap); unit = " us"; }
    for (unsigned i = 0; unit[i] && o + 1u < cap; i++) out[o++] = unit[i];
    out[o] = 0;
}

/*=================================================================
 * ベンチ結果を linux_loopback.sh と同じ書式の表で表示する
 * (rw / bs / qd / MiB/s / IOPS / avg latency)。行の並びも同じで、
 * write を全 chunk 分並べたあとに read を並べる。avg latency は、
 * このベンチが qd 本を常時 outstanding に保つ設計であることから
 * Little の法則(平均レイテンシ = qd / IOPS)で求めている。
 *
 * 引数:
 *   transport  - トランスポート名("tcp" / "rocev2")
 *   qd         - queue depth
 *   runtime_ms - 1 条件あたりの測定時間
 *   r          - 測定結果の配列
 *   n          - その件数
 * コール元:
 *   shell_tcpbench(), shell_rdmabench()
 * ===============================================================*/
static void bench_summary(const char *transport, uint32_t qd, uint32_t runtime_ms,
                          const bench_res_t *r, unsigned n)
{
    uart_printf("\nスタック: vfio_nvme / トランスポート: %s / qd=%u / runtime=%us\n\n",
                transport, qd, runtime_ms / 1000u);
    uart_printf("%-10s %-8s %-6s %12s %12s %14s\n",
                "rw", "bs", "qd", "MiB/s", "IOPS", "avg latency");
    uart_printf("%-10s %-8s %-6s %12s %12s %14s\n",
                "----------", "--------", "------", "------------", "------------", "--------------");

    for (int pass = 0; pass < 2; pass++) {   /* 0=write を先に、1=read を後に */
        for (unsigned i = 0; i < n; i++) {
            if (r[i].is_read != pass) continue;

            char bs[16], mib[24], iops[24], lat[24];
            unsigned o = bench_u32_str(r[i].chunk / 1024u, bs, sizeof(bs));
            if (o + 1u < sizeof(bs)) bs[o++] = 'k';
            bs[o] = 0;

            const char *rw = r[i].is_read ? "read" : "write";
            uint32_t el = r[i].elapsed_ms;
            if (el == 0u || r[i].count == 0u) {
                uart_printf("%-10s %-8s %-6u %12s %12s %14s\n", rw, bs, qd, "-", "-", "-");
                continue;
            }
            bench_fx2_str((r[i].bytes * 100000ull) / ((uint64_t)el * 1048576ull), mib, sizeof(mib));
            bench_fx2_str(((uint64_t)r[i].count * 100000ull) / (uint64_t)el, iops, sizeof(iops));
            bench_lat_str(((uint64_t)qd * (uint64_t)el * 1000000ull) / (uint64_t)r[i].count,
                          lat, sizeof(lat));
            uart_printf("%-10s %-8s %-6u %12s %12s %14s\n", rw, bs, qd, mib, iops, lat);
        }
    }
}

/*=================================================================
 * NVMe/TCP を 1 条件だけ 3 秒間回してスループットを測る。
 *
 * 引数:
 *   chunk   - 1 コマンドあたりの転送バイト数
 *   is_read - 1=read、0=write
 *   out     - 測定結果の格納先
 * コール元:
 *   shell_tcpbench()
 * ===============================================================*/
static void tcp_measure(uint32_t chunk, int is_read, bench_res_t *out)
{
    uint32_t nlb = chunk / s_nvme_ctx.lba_size;
    uint32_t cnt = 0, el = 0; uint64_t by = 0;
    if (is_read) nvme_read_pipelined_run(&s_nvme_ctx, 1u, 0u, s_nvmetcp_buf, nlb, 3000u, &cnt, &by, &el);
    else         nvme_write_pipelined_run(&s_nvme_ctx, 1u, 0u, s_nvmetcp_buf, nlb, 3000u, &cnt, &by, &el);
    uart_printf("[tcp] chunk=%u %s: %u 回, %u ms\n", chunk, is_read ? "read " : "write", cnt, el);
    out->chunk      = chunk;
    out->is_read    = is_read;
    out->bytes      = by;
    out->count      = cnt;
    out->elapsed_ms = el;
}

/*=================================================================
 * シェルの `tcpbench`。セッションを確立(既にあれば再利用)し、指定 chunk ×
 * read/write でスループットを測って表を出す。
 *
 * 引数:
 *   args - "[KB[,KB...]] [r|w|rw]"
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_tcpbench(char *args)
{
    bench_plan_t pl; bench_plan_parse(args, &pl);
    if (shell_ensure_tcp_session(pl.hdgst, pl.ddgst) != 0) return;
    if (pl.hdgst != s_nvme_ctx.io.hdgst || pl.ddgst != s_nvme_ctx.io.ddgst) {
        uart_printf("[!] tcpbench: digestの合意結果が要求と異なります "
                    "(要求 hdgst=%u ddgst=%u / 合意 hdgst=%u ddgst=%u)\n",
                    pl.hdgst, pl.ddgst, s_nvme_ctx.io.hdgst, s_nvme_ctx.io.ddgst);
    }
    for (unsigned i = 0; i < sizeof(s_nvmetcp_buf); i++) s_nvmetcp_buf[i] = (uint8_t)(0x5au ^ (i * 7u));
    bench_res_t res[2u * BENCH_MAX_CHUNKS]; unsigned nr = 0;
    for (unsigned c = 0; c < pl.nchunks; c++) {
        if (pl.do_w) tcp_measure(pl.chunks[c], 0, &res[nr++]);
        if (pl.do_r) tcp_measure(pl.chunks[c], 1, &res[nr++]);
    }
    char transport[32];
    unsigned o = 0;
    const char *base = "tcp";
    while (base[o]) { transport[o] = base[o]; o++; }
    if (s_nvme_ctx.io.hdgst || s_nvme_ctx.io.ddgst) {
        const char *suffix = s_nvme_ctx.io.hdgst && s_nvme_ctx.io.ddgst ? "+hdgst+ddgst"
                            : (s_nvme_ctx.io.hdgst ? "+hdgst" : "+ddgst");
        for (unsigned k = 0; suffix[k] && o + 1u < sizeof(transport); k++) transport[o++] = suffix[k];
    }
    transport[o] = 0;
    bench_summary(transport, NVME_IO_QDEPTH, 3000u, res, nr);
}

/*=================================================================
 * シェルの `bench`。NVMe-oF RDMA のスループットを指定 chunk × read/write ×
 * qdepth で測って表を出す。
 *
 * 引数:
 *   args - "[KB[,KB...]] [r|w|rw] [qd]"
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_rdmabench(char *args)
{
    bench_plan_t pl; bench_plan_parse(args, &pl);
    if (pl.hdgst || pl.ddgst) {
        /* ダイジェストは NVMe/TCP トランスポート固有の機能。RDMA には
         * 該当する仕組みが無い(RoCE のパケット CRC が担う)ので無視する。 */
        uart_printf("[!] bench: NVMe-oF RDMA に digest はありません(無視します。tcpbench で指定してください)\n");
    }
    /* nvme_rdma_run_bench() 側でも丸められるが、表と平均レイテンシ計算を
     * 実際に使われた qd に合わせるためここでも同じ上限を適用する。 */
    uint32_t qd = (pl.qd > NVME_RDMA_PL_QDEPTH_MAX) ? NVME_RDMA_PL_QDEPTH_MAX : pl.qd;
    bench_res_t res[2u * BENCH_MAX_CHUNKS]; unsigned nr = 0;
    for (unsigned c = 0; c < pl.nchunks; c++) {
        for (int is_read = 0; is_read < 2; is_read++) {
            if (!(is_read ? pl.do_r : pl.do_w)) continue;
            bench_res_t *e = &res[nr++];
            e->chunk = pl.chunks[c];
            e->is_read = is_read;
            nvme_rdma_run_bench(&s_dev0, &s_dev1, 3000u, is_read, pl.chunks[c], qd,
                                &e->bytes, &e->count, &e->elapsed_ms);
        }
    }
    bench_summary("rocev2", qd, 3000u, res, nr);
}

/*=================================================================
 * シェルの `ts`。ts_log リングのダンプと pause/resume/mode 切り替えを行う。
 *
 * 引数:
 *   args - "[core N] [num N] [mask M V] | pause | resume"
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_ts(char *args)
{
    char *tok[8];
    unsigned nt = shell_tokenize(args, tok, 8);
    unsigned core = 0, num = 20; uint32_t mask = 0, val = 0; int have_mask = 0; int pause = -1;
    for (unsigned i = 0; i < nt; ) {
        if (strcmp(tok[i], "pause") == 0) { pause = 1; i++; }
        else if (strcmp(tok[i], "resume") == 0) { pause = 0; i++; }
        else if (strcmp(tok[i], "mode") == 0 && i + 1 < nt) {
            ts_log_mode_set((uint32_t)strtoul(tok[i + 1], 0, 0));
            uart_printf("ts: mode=0x%x (bit0=cmd, bit2=hotpath per-frame)\n", ts_log_mode());
            return;
        }
        else if (strcmp(tok[i], "core") == 0 && i + 1 < nt) { core = (unsigned)atoi(tok[i + 1]); i += 2; }
        else if (strcmp(tok[i], "num") == 0 && i + 1 < nt) { num = (unsigned)atoi(tok[i + 1]); i += 2; }
        else if (strcmp(tok[i], "mask") == 0 && i + 2 < nt) {
            mask = (uint32_t)strtoul(tok[i + 1], 0, 0); val = (uint32_t)strtoul(tok[i + 2], 0, 0);
            have_mask = 1; i += 3;
        } else i++;
    }
    if (pause == 1) { ts_log_set_paused_core(core, 1); uart_printf("ts: core%u paused\n", core); return; }
    if (pause == 0) { ts_log_set_paused_core(core, 0); uart_printf("ts: core%u resumed\n", core); return; }
    uint64_t start = have_mask ? ts_log_query_start_last_n_matching(core, mask, val, num)
                               : ts_log_query_start_last_n(core, num);
    ts_log_dump_core(core, start, num, mask, val);
}

/*=================================================================
 * シェルの `simdelay`。指定コアのメインループへ注入する人為的遅延(us)を
 * 設定する(律速要因の切り分け用)。
 *
 * 引数:
 *   args - "<core> <us>" または "show"
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_simdelay(char *args)
{
    char *tok[2];
    unsigned nt = shell_tokenize(args, tok, 2);
    if (nt >= 1 && strcmp(tok[0], "show") == 0) {
        for (unsigned c = 0; c < SMP_MAX_CORES; c++)
            uart_printf("simdelay: core%u = %uus\n", c, (unsigned)g_sim_delay_us[c]);
        return;
    }
    if (nt < 2) { uart_printf("usage: simdelay <core> <us> | simdelay show\n"); return; }
    unsigned core = (unsigned)atoi(tok[0]);
    if (core >= SMP_MAX_CORES) { uart_printf("simdelay: core は 0..%u\n", SMP_MAX_CORES - 1); return; }
    g_sim_delay_us[core] = (uint32_t)atoi(tok[1]);
    uart_printf("simdelay: core%u = %uus\n", core, (unsigned)g_sim_delay_us[core]);
}

/*=================================================================
 * シェルの `ackthresh`。TCP の遅延 ACK 閾値(フルサイズ何セグメントごとに
 * ACK するか)を設定/表示する。
 *
 * 引数:
 *   args - 新しい閾値。省略時は現在値を表示
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_ackthresh(char *args)
{
    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
        unsigned n = (unsigned)atoi(args);
        if (n < 1u) n = 1u;
        g_tcp_ack_threshold = n;
    }
    uart_printf("ackthresh: %u (フルサイズ%uセグメント毎にACK)\n",
                (unsigned)g_tcp_ack_threshold, (unsigned)g_tcp_ack_threshold);
}

/*=================================================================
 * 入力 1 行をコマンドとして解釈し実行する(monitor / nvmet / tcpbench /
 * bench / simdelay / ackthresh / ts / jobs / help / quit)。
 *
 * 引数:
 *   line   - 入力行(破壊される)
 *   s0, s1 - PF0/PF1 の VFIO スロット番号(monitor が config 空間を読む)
 * コール元:
 *   run_shell()
 * ===============================================================*/
static void shell_dispatch(char *line, int s0, int s1)
{
    /* 先頭の空白を飛ばし、コマンド語を取り出す。 */
    while (*line == ' ' || *line == '\t') line++;
    if (*line == 0) return;

    if (strncmp(line, "monitor", 7) == 0 || strncmp(line, "mon", 3) == 0) {
        /* 再初期化なし: 既にブリングアップ済みの s_dev0/s_dev1 を読むだけ。 */
        mlx5_monitor_summary3(&s_dev0, &s_dev1, x86_cfg_rd,
                              (void *)(intptr_t)s0, (void *)(intptr_t)s1);
    } else if (strncmp(line, "nvmet", 5) == 0) {
        if (s_shell_nvmet_started) {
            uart_printf("nvmet: 既に常駐起動済み\n");
            return;
        }
        uint16_t port = 4421u;
        const char *p = line + 5;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') port = (uint16_t)atoi(p);
        netif_t *ctx1 = netif_find("mlx5-pf1");
        if (!ctx1) { uart_printf("nvmet: mlx5-pf1 未登録\n"); return; }
        if (smp_boot_core1() == 0) netif_set_owner_core(ctx1, 1u);
        if (nvmet_job_start(&s_x86_nvmet, port, ctx1, "manual") != 0) {
            uart_printf("nvmet: nvmet_job_start 失敗\n"); return;
        }
        s_shell_nvmet_started = 1;
        uart_printf("nvmet: ターゲット常駐起動 (pf1, port %u) -- 接続待ち\n", port);
    } else if (strncmp(line, "tcpbench", 8) == 0) {
        shell_tcpbench(line + 8);
    } else if (strncmp(line, "bench", 5) == 0) {
        shell_rdmabench(line + 5);
    } else if (strncmp(line, "simdelay", 8) == 0) {
        shell_simdelay(line + 8);
    } else if (strncmp(line, "ackthresh", 9) == 0) {
        shell_ackthresh(line + 9);
    } else if (strncmp(line, "ts", 2) == 0 && (line[2] == 0 || line[2] == ' ')) {
        shell_ts(line + 2);
    } else if (strncmp(line, "ping6", 5) == 0) {
        shell_ping6();
    } else if (strncmp(line, "udptest6", 8) == 0) {
        shell_udptest6();
    } else if (strncmp(line, "udptest", 7) == 0) {
        shell_udptest();
    } else if (strncmp(line, "tcp6test", 8) == 0) {
        shell_tcp6test();
    } else if (strncmp(line, "jobs", 4) == 0) {
        job_list_dump();
    } else if (strncmp(line, "help", 4) == 0) {
        uart_printf("commands:\n"
                    "  monitor                              HW状態(温度/エラー/PCIe/リンク)\n"
                    "  bench [KB[,KB...]] [r|w|rw] [qd]      NVMe-oF RDMA スループット\n"
                    "  tcpbench [KB[,KB...]] [r|w|rw] [hdgst] [ddgst] [digest]\n"
                    "                                        NVMe/TCP スループット(qdは内部固定)\n"
                    "                                        hdgst/ddgst/digest でCRC32Cダイジェストを有効化\n"
                    "                                        (指定が前回と変わるとセッションを張り直す)\n"
                    "  ts [core N] [num N] [mask M V] | ts pause|resume   ts_log ダンプ\n"
                    "  simdelay <core> <us> | simdelay show   律速切り分け(遅延注入)\n"
                    "  ping6                                 対向PFへICMPv6 Echo(IPv6疎通確認)\n"
                    "  udptest | udptest6                    対向PFへUDP往復(v4はPort Unreachableも確認)\n"
                    "  tcp6test                              対向PFとIPv6上でTCP確立+データ往復\n"
                    "  nvmet [port] | jobs | help | quit    (↑↓で履歴呼び出し)\n"
                    "  例: bench 8,64,256 rw 8 / tcpbench 64,256 w digest / ts core 1 num 40\n");
    } else if (strncmp(line, "quit", 4) == 0 || strncmp(line, "exit", 4) == 0) {
        uart_printf("bye\n");
        exit(0);
    } else {
        uart_printf("unknown: %s  (help でコマンド一覧)\n", line);
    }
}

/* ---- 常駐シェルの行編集(64件履歴 + ↑↓ 呼び出し + backspace) ---- */
#define SHELL_LINE_MAX 128
#define SHELL_HIST_MAX 64

static char     s_hist[SHELL_HIST_MAX][SHELL_LINE_MAX];
static unsigned s_hist_count = 0;

typedef struct {
    char     line[SHELL_LINE_MAX];
    unsigned len;
    char     draft[SHELL_LINE_MAX];
    unsigned draft_len;
    unsigned hist_idx;
    int      browsing;   /* 履歴閲覧中か */
    int      esc;        /* 0=通常, 1=ESC受信, 2=ESC[受信 */
} shell_editor_t;

/*=================================================================
 * 確定した入力行をコマンド履歴へ積む(上下キーで呼び出せるようにする)。
 *
 * 引数:
 *   l - 積む行
 * コール元:
 *   run_shell()
 * ===============================================================*/
static void shell_hist_push(const char *l)
{
    if (l[0] == 0) return;
    if (s_hist_count > 0 && strcmp(s_hist[s_hist_count - 1], l) == 0) return; /* 直前と同一は積まない */
    if (s_hist_count == SHELL_HIST_MAX) {                                     /* 満杯なら最古を捨てる */
        for (unsigned i = 1; i < SHELL_HIST_MAX; i++) memcpy(s_hist[i - 1], s_hist[i], SHELL_LINE_MAX);
        s_hist_count--;
    }
    unsigned i = 0;
    for (; l[i] && i < SHELL_LINE_MAX - 1; i++) s_hist[s_hist_count][i] = l[i];
    s_hist[s_hist_count][i] = 0;
    s_hist_count++;
}

/*=================================================================
 * 行編集バッファの内容を src で置き換え、画面の表示も更新する
 * (履歴の呼び出しに使う)。
 *
 * 引数:
 *   ed  - 行エディタ状態
 *   src - 新しい行内容
 * コール元:
 *   shell_editor_byte()
 * ===============================================================*/
static void shell_set_line(shell_editor_t *ed, const char *src)
{
    unsigned i = 0;
    for (; src[i] && i < SHELL_LINE_MAX - 1; i++) ed->line[i] = src[i];
    ed->line[i] = 0; ed->len = i;
    uart_printf("\r\033[K> %s", ed->line);   /* 行クリア + プロンプト + 再描画 */
}

/*=================================================================
 * 入力 1 バイトを行エディタへ与える。通常文字の挿入・バックスペース・
 * 上下キー(履歴)・改行による行確定を扱う。
 *
 * 引数:
 *   ed - 行エディタ状態
 *   ch - 入力バイト
 * 戻り値:
 *   1=行が確定した(ed->line が有効)、0=編集継続中
 * コール元:
 *   run_shell()
 * ===============================================================*/
static int shell_editor_byte(shell_editor_t *ed, unsigned char ch)
{
    if (ed->esc == 1) { ed->esc = (ch == '[') ? 2 : 0; return 0; }
    if (ed->esc == 2) {
        ed->esc = 0;
        if (ch == 'A') {                          /* ↑: 履歴を遡る */
            if (s_hist_count == 0) return 0;
            if (!ed->browsing) {
                for (unsigned i = 0; i < ed->len; i++) ed->draft[i] = ed->line[i];
                ed->draft_len = ed->len; ed->browsing = 1; ed->hist_idx = s_hist_count;
            }
            if (ed->hist_idx > 0) { ed->hist_idx--; shell_set_line(ed, s_hist[ed->hist_idx]); }
        } else if (ch == 'B') {                   /* ↓: 履歴を進む/下書きへ */
            if (!ed->browsing) return 0;
            ed->hist_idx++;
            if (ed->hist_idx >= s_hist_count) {
                ed->draft[ed->draft_len] = 0; shell_set_line(ed, ed->draft); ed->browsing = 0;
            } else {
                shell_set_line(ed, s_hist[ed->hist_idx]);
            }
        }
        return 0;   /* C/D(左右カーソル)は未対応 -- 末尾編集のみ */
    }
    if (ch == 0x1b) { ed->esc = 1; return 0; }
    if (ch == '\r' || ch == '\n') { ed->line[ed->len] = 0; uart_putc('\r'); uart_putc('\n'); return 1; }
    if (ch == 0x7f || ch == 0x08) { if (ed->len > 0) { ed->len--; ed->line[ed->len] = 0; uart_puts("\b \b"); } return 0; }
    if (ch >= 0x20 && ch < 0x7f) {
        if (ed->len < SHELL_LINE_MAX - 1) { ed->line[ed->len++] = (char)ch; ed->line[ed->len] = 0; uart_putc((char)ch); }
        return 0;
    }
    return 0;
}

static struct termios s_orig_tio;
static int s_raw_active = 0;
static void shell_restore_tty(void) { if (s_raw_active) { tcsetattr(0, TCSANOW, &s_orig_tio); s_raw_active = 0; } }
/*=================================================================
 * 端末を raw モード(canonical/echo 無効)にする。矢印キーと 1 文字ずつの
 * 即時エコーのため。プロセス終了時に元へ戻す atexit ハンドラも登録する。
 *
 * コール元:
 *   run_shell()
 * ===============================================================*/
static void shell_raw_mode(void)
{
    if (!isatty(0)) return;
    if (tcgetattr(0, &s_orig_tio) != 0) return;
    struct termios t = s_orig_tio;
    t.c_lflag &= ~((tcflag_t)(ICANON | ECHO));
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
    if (tcsetattr(0, TCSANOW, &t) == 0) { s_raw_active = 1; atexit(shell_restore_tty); }
}

/*=================================================================
 * 常駐シェル。起動時に 1 回だけ arp/ip ハンドラ登録と netif 登録を行い、
 * 以後はコマンドを対話的に受け付けつつ、アイドル時に job_scheduler_tick()
 * と net_poll_all_and_dispatch() を回し続ける(戻らない)。
 *
 * 引数:
 *   s0, s1 - PF0/PF1 の VFIO スロット番号
 * コール元:
 *   run_dual_pf()
 * ===============================================================*/
static void run_shell(int s0, int s1)
{
    /* Ethernet/TCP/nvmet 用の net_ctx を1回だけ登録(以後のコマンドで再利用)。 */
    arp_init();
    ip_init();
    ipv6_init();
    udp_init();
    mlx5_net_register_dual(&s_dev0, &s_dev1);

    int fl = fcntl(0, F_GETFL, 0);
    if (fl != -1) (void)fcntl(0, F_SETFL, fl | O_NONBLOCK);
    shell_raw_mode();
    setvbuf(stdout, NULL, _IONBF, 0);

    uart_printf("\n==== x86 常駐シェル(bring-up 済み、再初期化なし、↑↓で履歴呼び出し) ====\n");
    uart_printf("commands: monitor | bench [KB[,KB..]] [r|w|rw] [qd] | tcpbench [..] | ts [..] | nvmet [port] | jobs | help | quit\n> ");

    shell_editor_t ed = {0};
    ed.hist_idx = s_hist_count;
    for (;;) {
        unsigned char ch;
        while (read(0, &ch, 1) == 1) {
            if (shell_editor_byte(&ed, ch)) {
                if (ed.len > 0) { shell_hist_push(ed.line); shell_dispatch(ed.line, s0, s1); }
                ed.len = 0; ed.line[0] = 0; ed.browsing = 0; ed.hist_idx = s_hist_count;
                uart_printf("> ");
            }
        }
        /* アイドル: 常駐ジョブ(nvmet ターゲット等)と受信ポーリングを回す。 */
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        usleep(1000);
    }
}

/*=================================================================
 * PF0/PF1 を両方 bring-up し、常駐シェルへ入る(戻らない)。
 *
 * 引数:
 *   bdf0, bdf1 - 2 つの PF の PCI アドレス
 * 戻り値:
 *   -1=bring-up 失敗(成功時は run_shell() から戻らない)
 * コール元:
 *   main()
 * ===============================================================*/
static int run_dual_pf(const char *bdf0, const char *bdf1)
{
    uart_printf("\n========== dual-PF bring-up: %s + %s ==========\n", bdf0, bdf1);
    int s0 = vfio_init(bdf0);
    int s1 = vfio_init(bdf1);
    if (bringup_pf(s0, &s_dev0, 0u, "PF0") != 0) return -1;
    if (bringup_pf(s1, &s_dev1, 1u, "PF1") != 0) return -1;
    run_shell(s0, s1);
    return 0;
}

/*=================================================================
 * エントリポイント。自己テスト(crc32c / timer / spinlock / smp)を行い、
 * 引数に 2 つの PCI アドレスが与えられていれば bring-up + 常駐シェルへ。
 *
 * 引数:
 *   argc, argv - argv[1], argv[2] が PF0/PF1 の PCI アドレス
 * 戻り値:
 *   0=正常、1=自己テスト失敗または bring-up 失敗
 * ===============================================================*/
int main(int argc, char **argv)
{
    uart_puts("\nvfio_nvme -- ConnectX-4 / VFIO / NVMe-oF (RoCEv2 + TCP)\n\n");

    int rc = 0;
    rc |= crc32c_selftest();
    timer_selftest();
    spinlock_selftest();
    smp_selftest();

    if (argc >= 3) {
        return run_dual_pf(argv[1], argv[2]) ? 1 : 0;
    }

    uart_puts("\n使い方:\n"
              "  sudo ./vfio_nvme <BDF0> <BDF1>   dual PF bring-up + 常駐シェル\n"
              "  例: sudo ./vfio_nvme 0000:01:00.0 0000:01:00.1\n");
    uart_printf("\nself-tests %s\n", (rc == 0) ? "PASSED" : "had FAILURES");
    return rc ? 1 : 0;
}
