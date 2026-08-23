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
#include "icmp.h"
#include "ipv6.h"
#include "udp.h"
#include "netif.h"
#include "pmtu.h"
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

static int     s_shell_nvmet_started = 0;
static int     s_shell_tcp_connected = 0;
static uint8_t s_shell_tcp_ipv6      = 0;  /* 現在のセッションが IPv6 か */

/* 定義は下方(ping6/udptest6 群と一緒に置いてある)。 */
static netif_t *shell_peer_ll6(uint8_t out[16]);

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
static int shell_ensure_tcp_session(uint8_t want_hdgst, uint8_t want_ddgst, uint8_t want_ipv6)
{
    /* ダイジェストは ICReq/ICResp でコネクション確立時に一度だけ合意する。
     * IPv4/IPv6 もコネクション単位で決まる。いずれも要求が変わったら既存
     * セッションは使い回せないので張り直す。 */
    if (s_shell_tcp_connected &&
        (s_nvme_ctx.req_hdgst != want_hdgst || s_nvme_ctx.req_ddgst != want_ddgst ||
         s_shell_tcp_ipv6 != want_ipv6)) {
        uart_printf("tcpbench: digest/IP版の設定が変わったのでセッションを張り直します\n");
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
    netaddr_t target;
    if (want_ipv6) {
        /* nvmet 側の listener はポートだけで待つ family 非依存の実装なので、
         * ターゲットには手を入れず、イニシエータが v6 で繋ぎに行くだけでよい。 */
        uint8_t peer_ll[16];
        if (!shell_peer_ll6(peer_ll)) {
            uart_printf("tcpbench: 対向インターフェースが見つかりません\n");
            return -1;
        }
        target = netaddr_v6(peer_ll);
    } else {
        target = netaddr_v4(ip_from_octets(192, 168, 101, 11));
    }
    nvme_connect_job_start_addr(&s_nvme_ctx, &target, 4421u, subnqn);
    uint64_t t = timer_now();
    while (s_nvme_ctx.busy) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        if (timeout_ms(t, 15000u)) { uart_printf("tcpbench: connect タイムアウト\n"); return -1; }
    }
    if (s_nvme_ctx.lba_size == 0u) { uart_printf("tcpbench: lba_size=0\n"); return -1; }
    s_shell_tcp_connected = 1;
    s_shell_tcp_ipv6      = want_ipv6;
    uart_printf("tcpbench: initiator 接続完了 (lba_size=%u, %s)\n",
                s_nvme_ctx.lba_size, want_ipv6 ? "IPv6" : "IPv4");
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
    netaddr_t peer_addr = netaddr_v4(peer_ip);
    if (net_resolve_mac(&peer_addr, peer_mac) != 0) {
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
    netaddr_t peer_addr6 = netaddr_v6(peer_ll);
    if (net_resolve_mac(&peer_addr6, peer_mac) != 0) {
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
 * 同一プロセス内の 2 つのインターフェースをサーバ役/クライアント役にして
 * TCP を確立し、64KB を 1 往復させてバイト一致を確認する。ポーリング専用・
 * 単一スレッドなので、接続待ちは tcp_accept_begin()(ブロックしない受け皿
 * 準備)で用意しておき、tcp_connect_poll() が内部で回すポーリングに
 * サーバ側の処理も乗せる。
 *
 * dst の family は問わない(tcp_connect_begin_to() が吸収する)。宛先が
 * サーバ側インターフェースの IP と違っていてもよいので、ゲートウェイ経由の
 * 経路(routetest)もこの関数で検証できる。
 *
 * 引数:
 *   label   - ログの先頭に出す呼び出し元名("tcp6test" 等)
 *   self    - クライアント役インターフェース
 *   srv_if  - サーバ役インターフェース(listen をここに束縛する)
 *   dst     - クライアントが接続する宛先アドレス
 *   port    - 使用ポート
 *   out_mss - NULL 可。確立したコネクションの snd_mss を返す(PMTU の検証用)
 * 戻り値:
 *   1=64KB が一致して往復した、0=失敗
 * コール元:
 *   shell_tcp6test(), shell_routetest(), shell_pmtutest()
 * ===============================================================*/
static int shell_tcp_echo_once(const char *label, netif_t *self, netif_t *srv_if,
                                const netaddr_t *dst, uint16_t port, uint16_t *out_mss)
{
    static tcp_conn_t s_srv, s_cli;

    uart_printf("%s: client=%s server=%s port=%u\n", label, self->name, srv_if->name, port);

    /* サーバ役の受け皿を先に用意する(サーバ側インターフェース宛に束縛)。 */
    int listener = tcp_listen(port, srv_if);
    if (listener < 0) {
        uart_printf("%s: tcp_listen 失敗\n", label);
        return 0;
    }
    s_srv.state = TCP_CLOSED;
    tcp_accept_begin(listener, &s_srv);

    netif_activate(self);
    tcp_connect_begin_to(&s_cli, dst, port);

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
        uart_printf("%s: NG -- 接続確立できず (client state=%d server state=%d)\n",
                    label, (int)s_cli.state, (int)s_srv.state);
        tcp_unlisten(listener);
        netif_activate(self);
        return 0;
    }
    uart_printf("%s: 接続確立 (MSS=%u)\n", label, (unsigned)s_cli.snd_mss);
    if (out_mss) *out_mss = s_cli.snd_mss;

    /* フルサイズ(MSS)セグメントを何本も流す大きさにしておく。小さいままだと
     * 1 セグメントに収まってしまい、L3 ヘッダ 20 バイト増による MTU 超過
     * (NIC が無言で捨てる)を踏まずに PASS してしまう。 */
    static uint8_t tx[65536];
    static uint8_t rx[65536];
    for (unsigned i = 0; i < sizeof(tx); i++) tx[i] = (uint8_t)(i * 7u + 3u);

    netif_activate(self);
    /* tcp_send() は送信できたバイト数を返す(失敗/中断で -1)。 */
    if (tcp_send(&s_cli, tx, sizeof(tx)) != (int)sizeof(tx)) {
        uart_printf("%s: NG -- 送信失敗\n", label);
        tcp_close(&s_cli);
        tcp_unlisten(listener);
        netif_activate(self);
        return 0;
    }

    uint32_t got = 0;
    t0 = timer_now();
    while (got < sizeof(tx) && !timeout_ms(t0, 3000u)) {
        netif_activate(srv_if);
        int n = tcp_recv(&s_srv, rx + got, (uint32_t)sizeof(rx) - got, 20u);
        if (n > 0) got += (uint32_t)n;
        else if (n < 0) break;
        net_poll_all_and_dispatch();
    }

    int match = (got == sizeof(tx));
    for (uint32_t i = 0; match && i < got; i++) {
        if (rx[i] != tx[i]) match = 0;
    }
    uart_printf("%s: 受信 %u/%u バイト -- %s\n",
                label, (unsigned)got, (unsigned)sizeof(tx),
                match ? "PASS(内容一致)" : "NG(内容不一致または不足)");

    netif_activate(self);
    tcp_close(&s_cli);
    netif_activate(srv_if);
    tcp_close(&s_srv);
    tcp_unlisten(listener);
    netif_activate(self);
    return match;
}

/*=================================================================
 * シェルの `tcp6test`。対向 PF のリンクローカル宛に IPv6 で TCP を確立し、
 * 64KB を往復させてバイト一致を確認する。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_tcp6test(void)
{
    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("tcp6test: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    netaddr_t dst = netaddr_v6(peer_ll);
    shell_tcp_echo_once("tcp6test", self, peer, &dst, 6000u, NULL);
}

/*=================================================================
 * 待ち受けの無いポートへ接続を試み、RST で即座に失敗することを確認する
 * (rsttest の v4/v6 共通部)。
 *
 * RST が返らない実装では SYN が 500ms から倍々で 5 回再送されるまで
 * (合計 15 秒以上)失敗が確定しないので、経過時間そのものが判定になる。
 *
 * 引数:
 *   label  - 表示用のラベル("IPv4" / "IPv6")
 *   dst    - 接続先(対向 PF)
 *   port   - 待ち受けの無いポート
 * 戻り値:
 *   1=期待どおり即座に失敗、0=失敗しなかった/遅すぎた
 * コール元:
 *   shell_rsttest()
 * ===============================================================*/
static int shell_rsttest_one(const char *label, const netaddr_t *dst, uint16_t port)
{
    /* SYN 1 回ぶんの RTO(TCP_INITIAL_RTO_MS=500ms)より十分短ければ RST 由来と
     * 言える。ARP/NDP の解決が初回に入るので、その往復(実測 150〜200us)ぶんの
     * 余裕は見ておく。 */
    const uint64_t rst_deadline_us = 200000u;
    static tcp_conn_t s_conn;

    s_conn.state = TCP_CLOSED;
    tcp_connect_begin_to(&s_conn, dst, port);

    uint64_t t0 = timer_now();
    int r = 0;
    while (!timeout_ms(t0, 3000u)) {
        r = tcp_connect_poll(&s_conn);
        net_poll_all_and_dispatch();
        if (r != 0) break;
    }
    uint64_t elapsed_us = get_us_from(t0);

    if (r > 0) {
        uart_printf("rsttest: NG(%s) -- 待ち受けが無いはずのポート %u へ接続できてしまいました\n",
                    label, (unsigned)port);
        tcp_close(&s_conn);
        return 0;
    }
    if (r == 0) {
        uart_printf("rsttest: NG(%s) -- 3 秒たっても接続失敗が確定しませんでした\n", label);
        return 0;
    }
    if (elapsed_us > rst_deadline_us) {
        uart_printf("rsttest: NG(%s) -- 失敗まで %uus かかりました(RST ではなく SYN 再送の"
                    "タイムアウト待ちの疑い、期待 <%uus)\n",
                    label, (unsigned)elapsed_us, (unsigned)rst_deadline_us);
        return 0;
    }
    uart_printf("rsttest: PASS(%s) -- %uus で接続失敗が確定(RST 受信)\n",
                label, (unsigned)elapsed_us);
    return 1;
}

/*=================================================================
 * シェルの `rsttest`。対向 PF の「誰も待ち受けていないポート」へ v4/v6 の
 * 両方で接続し、RST が返って即座に失敗することを確認する。
 *
 * 2 ポートとも同一プロセスの自作ドライバが握っているので、RST を返すのも
 * 自分自身(対向インターフェースの受信経路)になる。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_rsttest(void)
{
    /* nvmet(4421)や tcp6test(6000)と衝突しない、誰も listen しない番号。 */
    const uint16_t dead_port = 6001u;

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("rsttest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }

    uint32_t peer_ip = (net_active_ip() == 0xC0A8650Au) ? 0xC0A8650Bu : 0xC0A8650Au;
    netaddr_t dst4 = netaddr_v4(peer_ip);
    netaddr_t dst6 = netaddr_v6(peer_ll);

    uart_printf("rsttest: client=%s server=%s port=%u(待ち受け無し)\n",
                self->name, peer->name, (unsigned)dead_port);

    netif_activate(self);
    int ok4 = shell_rsttest_one("IPv4", &dst4, dead_port);
    netif_activate(self);
    int ok6 = shell_rsttest_one("IPv6", &dst6, dead_port);
    netif_activate(self);

    uart_printf("rsttest: %s\n", (ok4 && ok6) ? "PASS" : "NG");
}

/*=================================================================
 * 「受け皿を用意する前に届いた SYN」がどう扱われるかを 1 回測る
 * (backlogtest の陽性/陰性で共有する本体)。
 *
 * listen だけして tcp_accept_begin() を呼ばずに接続を試み、確立するまでの
 * 時間を測る。待ち行列があれば即座に確立し、無ければ SYN は捨てられて
 * 相手の SYN 再送(TCP_INITIAL_RTO_MS=500ms)を待つことになる。
 * arm_after_ms を過ぎたら受け皿を用意するので、どちらの場合も最後は
 * accept まで進む(そこまでの経過時間が判定材料)。
 *
 * 引数:
 *   label        - 表示用のラベル
 *   self         - クライアント役インターフェース
 *   srv_if       - サーバ役インターフェース
 *   dst          - 接続先
 *   port         - 使用ポート
 *   arm_after_ms - 何 ms 後に tcp_accept_begin() を呼ぶか
 *   out_estab_us - NULL 可。クライアント側で確立するまでの時間(us)
 *   out_accept_us- NULL 可。サーバ側で accept が返るまでの時間(us)
 * 戻り値:
 *   1=accept まで進んで 64KB が一致した、0=失敗
 * コール元:
 *   shell_backlogtest()
 * ===============================================================*/
static int shell_backlog_once(const char *label, netif_t *self, netif_t *srv_if,
                               const netaddr_t *dst, uint16_t port,
                               uint32_t arm_after_ms,
                               uint32_t *out_estab_us, uint32_t *out_accept_us)
{
    static tcp_conn_t s_srv, s_cli;
    static uint8_t tx[65536];
    static uint8_t rx[65536];

    int listener = tcp_listen(port, srv_if);
    if (listener < 0) {
        uart_printf("backlogtest: NG(%s) -- tcp_listen 失敗\n", label);
        return 0;
    }
    s_srv.state = TCP_CLOSED;
    s_cli.state = TCP_CLOSED;

    /* **ここでは tcp_accept_begin() を呼ばない**(受け皿の無い隙間の再現)。 */
    netif_activate(self);
    tcp_connect_begin_to(&s_cli, dst, port);

    for (unsigned i = 0; i < sizeof(tx); i++) tx[i] = (uint8_t)(i * 11u + 5u);

    uint64_t t0 = timer_now();
    int established = 0, armed = 0, accepted = 0, sent = -1;
    uint32_t estab_us = 0, accept_us = 0;
    while (!timeout_ms(t0, 5000u)) {
        if (!armed && timeout_ms(t0, arm_after_ms)) {
            netif_activate(srv_if);
            tcp_accept_begin(listener, &s_srv);
            armed = 1;
            netif_activate(self);
        }
        if (!established) {
            netif_activate(self);
            int r = tcp_connect_poll(&s_cli);
            if (r == 1) { established = 1; estab_us = (uint32_t)get_us_from(t0); }
            else if (r < 0) break;
        }
        if (established && sent < 0 && !armed) {
            /* **accept される前に**データを流す。待ち行列の中のコネクション
             * でも受信は動いている(s_conns[] に居るので rx_buf へ積まれる)。
             * 引き渡しでプライベート状態が失われるとここが不一致になる。 */
            netif_activate(self);
            sent = tcp_send(&s_cli, tx, sizeof(tx));
        }
        if (armed && !accepted) {
            netif_activate(srv_if);
            if (tcp_accept_ready_poll(listener) == 1) {
                accepted = 1; accept_us = (uint32_t)get_us_from(t0);
            }
        }
        net_poll_all_and_dispatch();
        if (established && accepted) break;
    }
    netif_activate(self);

    if (out_estab_us)  *out_estab_us  = estab_us;
    if (out_accept_us) *out_accept_us = accept_us;

    if (!established || !accepted) {
        uart_printf("backlogtest: NG(%s) -- 確立=%d accept=%d (client state=%d server state=%d)\n",
                    label, established, accepted, (int)s_cli.state, (int)s_srv.state);
        netif_activate(self); tcp_close(&s_cli);
        netif_activate(srv_if); tcp_close(&s_srv);
        tcp_unlisten(listener);
        netif_activate(self);
        return 0;
    }

    /* まだ送っていなければここで送る(陰性対照は accept の後に確立するので
     * この経路を通る)。フルサイズのセグメントが何本も出る大きさにする。 */
    if (sent < 0) {
        netif_activate(self);
        sent = tcp_send(&s_cli, tx, sizeof(tx));
    }

    uint32_t got = 0;
    uint64_t t1 = timer_now();
    while (sent == (int)sizeof(tx) && got < sizeof(tx) && !timeout_ms(t1, 3000u)) {
        netif_activate(srv_if);
        int n = tcp_recv(&s_srv, rx + got, (uint32_t)sizeof(rx) - got, 20u);
        if (n > 0) got += (uint32_t)n;
        else if (n < 0) break;
        net_poll_all_and_dispatch();
    }
    int match = (got == sizeof(tx));
    for (uint32_t i = 0; match && i < got; i++) {
        if (rx[i] != tx[i]) match = 0;
    }

    netif_activate(self);  tcp_close(&s_cli);
    netif_activate(srv_if); tcp_close(&s_srv);
    tcp_unlisten(listener);
    netif_activate(self);

    uart_printf("backlogtest: %s -- 確立まで %uus / accept まで %uus / 64KB %s(%u バイト受信)\n",
                label, (unsigned)estab_us, (unsigned)accept_us,
                match ? "一致" : "不一致", (unsigned)got);
    return match;
}

/*=================================================================
 * シェルの `backlogtest`。listen backlog(段階 23 = C5)の検証。
 *
 * 「受け皿(tcp_accept_begin)を用意する前に SYN が届く」状況を作り、
 *   [1] 待ち行列が有効なら SYN 再送を待たずに確立する(陽性)
 *   [2] 待ち行列を 0 にすると SYN が捨てられ、相手の SYN 再送
 *       (500ms)まで確立しない(陰性対照)
 * を**経過時間で**判定する。単に「最後は接続できた」を見るだけでは、
 * backlog が無くても SYN 再送で最終的に成功するので退行を検出できない
 * (rsttest と同じ考え方)。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_backlogtest(void)
{
    const uint16_t port = 6002u;          /* nvmet(4421)/tcp6test(6000)/rsttest(6001)と別 */
    const uint32_t arm_after_ms  = 1200u; /* SYN 再送(500ms)より後に受け皿を用意する */
    const uint32_t fast_limit_us = 200000u; /* SYN 1 回ぶんの RTO より十分短いこと */

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("backlogtest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint32_t peer_ip = (net_active_ip() == 0xC0A8650Au) ? 0xC0A8650Bu : 0xC0A8650Au;
    netaddr_t dst4 = netaddr_v4(peer_ip);

    uint32_t saved_depth = g_tcp_backlog_max;
    uint32_t before_accept = g_tcp_backlog_accept_count;

    uart_printf("backlogtest: client=%s server=%s port=%u(受け皿は %ums 後に用意)\n",
                self->name, peer->name, (unsigned)port, (unsigned)arm_after_ms);

    /* [1] 陽性: 待ち行列が有効。受け皿が無くても SYN を積んで確立まで進む。 */
    tcp_backlog_set_max(tcp_backlog_capacity());
    uint32_t estab1 = 0, accept1 = 0;
    int ok1 = shell_backlog_once("[1] backlog 有効", self, peer, &dst4, port,
                                  arm_after_ms, &estab1, &accept1);
    if (ok1 && estab1 > fast_limit_us) {
        uart_printf("backlogtest: NG -- backlog 有効なのに確立まで %uus かかりました"
                    "(SYN 再送待ちの疑い、期待 <%uus)\n",
                    (unsigned)estab1, (unsigned)fast_limit_us);
        ok1 = 0;
    }
    if (ok1 && g_tcp_backlog_accept_count == before_accept) {
        uart_printf("backlogtest: NG -- 待ち行列からの引き渡しが 1 度も起きていません"
                    "(隙間に当たっていない)\n");
        ok1 = 0;
    }

    /* [2] 陰性対照: 待ち行列を 0 にすると SYN は捨てられ、SYN 再送を待つ。 */
    tcp_backlog_set_max(0);
    uint32_t estab2 = 0, accept2 = 0;
    int ok2 = shell_backlog_once("[2] backlog 0(陰性対照)", self, peer, &dst4, port,
                                  arm_after_ms, &estab2, &accept2);
    if (ok2 && estab2 < fast_limit_us) {
        uart_printf("backlogtest: NG -- backlog 0 なのに %uus で確立しました"
                    "(SYN を取りこぼしていない = 陰性対照になっていない)\n",
                    (unsigned)estab2);
        ok2 = 0;
    }

    /* [3] SYN|ACK を 1 個だけ落として、相手の SYN 再送に SYN|ACK を送り直す
     *     経路を通す。送り直さない実装ではこの接続は永久に確立しない
     *     (相手は SYN を再送し続け、こちらは SYN_RCVD のまま黙る)。
     *     受け皿は最初から用意する(この検査は backlog とは独立)。 */
    tcp_backlog_set_max(tcp_backlog_capacity());
    uint32_t before_retx = g_tcp_synack_retx_count;
    g_tcp_synack_drop_next = 1;
    uint32_t estab3 = 0, accept3 = 0;
    int ok3 = shell_backlog_once("[3] SYN|ACK を 1 個落とす", self, peer, &dst4, port,
                                  0u /* すぐ arm する */, &estab3, &accept3);
    if (g_tcp_synack_retx_count == before_retx) {
        uart_printf("backlogtest: NG -- SYN|ACK の送り直しが起きていません"
                    "(落とせていない = 陽性対照になっていない)\n");
        ok3 = 0;
    }
    g_tcp_synack_drop_next = 0;  /* **必ず戻す** */

    tcp_backlog_set_max(saved_depth);  /* **必ず元に戻す**(txdrop と同じ注意) */

    uart_printf("backlogtest: 確立まで 有効=%uus / 無効=%uus (差 %uus) / SYN|ACK 落とし=%uus\n",
                (unsigned)estab1, (unsigned)estab2,
                (unsigned)((estab2 > estab1) ? (estab2 - estab1) : 0u),
                (unsigned)estab3);
    uart_printf("backlogtest: %s (backlog 深さを %u へ復元)\n",
                (ok1 && ok2 && ok3) ? "PASS" : "NG", (unsigned)g_tcp_backlog_max);
}

/*=================================================================
 * シェルの `backlog`。listen backlog の深さの表示/変更(0=無効)。
 *
 * 0 にすると「受け皿が用意されているときだけ SYN を受理する」従来の
 * 挙動へ戻る。**戻し忘れると以後の接続確立が SYN 再送待ちになる**ので
 * 注意(txdrop と同じ性質の恒久デバッグ機能)。
 *
 * 引数:
 *   args - 深さ。省略時は現在値と統計を表示
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_backlog(char *args)
{
    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
        tcp_backlog_set_max((unsigned)atoi(args));
    }
    unsigned waiting = 0, estab = 0;
    tcp_backlog_stats(&waiting, &estab);
    if (g_tcp_backlog_max == 0u) {
        uart_printf("backlog: 無効(受け皿が用意されているときだけ SYN を受理)\n");
    } else {
        uart_printf("backlog: 深さ %u (上限 %u)\n",
                    (unsigned)g_tcp_backlog_max, tcp_backlog_capacity());
    }
    uart_printf("backlog: 待機中=%u(うち確立済み=%u) 引き渡し=%u 満杯で破棄=%u\n",
                waiting, estab,
                (unsigned)g_tcp_backlog_accept_count,
                (unsigned)g_tcp_backlog_overflow_count);
}

/*=================================================================
 * シェルの `synackdrop`。次に送る SYN|ACK を N 個だけ捨てる。
 *
 * `txdrop` はデータを持つセグメントしか捨てないので、握手そのものを
 * 落として「相手の SYN 再送に SYN|ACK を送り直す」経路を通すにはこれが要る。
 * **戻し忘れると以後の受動 open が全部 1 回ぶん遅れる**(N は使うたびに
 * 減るので自然に 0 へ戻るが、大きな値を入れたときは注意)。
 *
 * 引数:
 *   args - N。省略時は残りと送り直した回数を表示
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_synackdrop(char *args)
{
    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
        g_tcp_synack_drop_next = (uint32_t)atoi(args);
    }
    uart_printf("synackdrop: 残り %u 個を破棄 / SYN 再送に応じた SYN|ACK 送り直し %u 回\n",
                (unsigned)g_tcp_synack_drop_next, (unsigned)g_tcp_synack_retx_count);
}

/*=================================================================
 * ロスを注入しながら 64KB を rounds 回送り、その間に RTT 推定が何回
 * 更新されたかを数える(tcptstest の本体)。
 *
 * **Karn のアルゴリズムでは「再送が起きたウィンドウ」の RTT を測れない**
 * ので、ロスがある状態でこの回数を Timestamps の有無で比べると、
 * 効果がそのまま数字に出る。
 *
 * 引数:
 *   label      - 表示用ラベル
 *   self       - クライアント役インターフェース
 *   srv_if     - サーバ役インターフェース
 *   dst        - 接続先
 *   port       - 使用ポート
 *   rounds     - 64KB を何往復ぶん送るか
 *   drop_every - ロス注入(データセグメント N 個に 1 個)。0=注入しない
 *   out_mss    - NULL 可。確立したコネクションの snd_mss
 *   out_rtt    - NULL 可。RTT 推定の更新回数
 *   out_ts     - NULL 可。TSecr 由来のサンプル数
 *   out_retx   - NULL 可。再送回数
 *   out_srtt   - NULL 可。最後の平滑化 RTT(us)
 * 戻り値:
 *   1=全ラウンドでバイト一致、0=失敗
 * コール元:
 *   shell_tcptstest()
 * ===============================================================*/
static int shell_loss_run(const char *label, netif_t *self, netif_t *srv_if,
                            const netaddr_t *dst, uint16_t port, unsigned rounds,
                            uint32_t drop_every, uint16_t *out_mss,
                            uint32_t *out_rtt, uint32_t *out_ts, uint32_t *out_retx,
                            uint64_t *out_srtt, uint32_t *out_ms, uint8_t *out_sack)
{
    static tcp_conn_t s_srv, s_cli;
    /* **1 回の tcp_send() を大きくしないと、ロスを注入しても穴の後ろが
     * 存在しない。** cwnd が小さいうちは「飛んだぶん = ウィンドウ全体」に
     * なり、受信側に順序不正が 1 つも生じないので SACK も高速再送も出番が
     * 無い(64KB で試したときは実際にそうなり、SACK ブロックが 1 個も
     * 出なかった)。 */
    static uint8_t tx[512u * 1024u];
    static uint8_t rx[512u * 1024u];

    int listener = tcp_listen(port, srv_if);
    if (listener < 0) {
        uart_printf("tcptstest: NG(%s) -- tcp_listen 失敗\n", label);
        return 0;
    }
    s_srv.state = TCP_CLOSED;
    s_cli.state = TCP_CLOSED;
    tcp_accept_begin(listener, &s_srv);

    netif_activate(self);
    tcp_connect_begin_to(&s_cli, dst, port);

    uint64_t t0 = timer_now();
    int established = 0;
    while (!timeout_ms(t0, 3000u)) {
        netif_activate(self);
        int r = tcp_connect_poll(&s_cli);
        net_poll_all_and_dispatch();
        netif_activate(srv_if);
        tcp_accept_ready_poll(listener);
        if (r == 1) { established = 1; break; }
        if (r < 0) break;
    }
    netif_activate(self);
    if (!established) {
        uart_printf("tcptstest: NG(%s) -- 接続確立できず\n", label);
        tcp_unlisten(listener);
        return 0;
    }
    if (out_mss)  *out_mss  = s_cli.snd_mss;
    if (out_sack) *out_sack = (uint8_t)tcp_conn_sack_enabled(&s_cli);

    for (unsigned i = 0; i < sizeof(tx); i++) tx[i] = (uint8_t)(i * 13u + 7u);

    /* 統計はここで 0 に戻す(確立までのぶんを混ぜない)。 */
    uint32_t rtt_before = g_tcp_rtt_update_count;
    uint32_t ts_before  = g_tcp_ts_rtt_samples;
    uint32_t retx_before = 0;
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) retx_before += g_tcp_retransmit_count[c];
    uint64_t run_start = timer_now();

    g_tcp_tx_drop_every = drop_every;

    int ok = 1;
    for (unsigned r = 0; r < rounds && ok; r++) {
        netif_activate(self);
        if (tcp_send(&s_cli, tx, sizeof(tx)) != (int)sizeof(tx)) {
            uart_printf("tcptstest: NG(%s) -- %u 回目の送信に失敗\n", label, r + 1u);
            ok = 0;
            break;
        }
        uint32_t got = 0;
        uint64_t t1 = timer_now();
        while (got < sizeof(tx) && !timeout_ms(t1, 5000u)) {
            netif_activate(srv_if);
            int n = tcp_recv(&s_srv, rx + got, (uint32_t)sizeof(rx) - got, 20u);
            if (n > 0) got += (uint32_t)n;
            else if (n < 0) break;
            net_poll_all_and_dispatch();
        }
        if (got != sizeof(tx)) {
            uart_printf("tcptstest: NG(%s) -- %u 回目の受信が %u バイトで止まった\n",
                        label, r + 1u, (unsigned)got);
            ok = 0;
            break;
        }
        for (uint32_t i = 0; ok && i < got; i++) {
            if (rx[i] != tx[i]) {
                uart_printf("tcptstest: NG(%s) -- %u 回目の内容が不一致(offset %u)\n",
                            label, r + 1u, (unsigned)i);
                ok = 0;
            }
        }
    }

    g_tcp_tx_drop_every = 0;  /* **必ず戻す** */

    if (out_rtt) *out_rtt = g_tcp_rtt_update_count - rtt_before;
    if (out_ts)  *out_ts  = g_tcp_ts_rtt_samples - ts_before;
    if (out_retx) {
        uint32_t retx_after = 0;
        for (unsigned c = 0; c < SMP_MAX_CORES; c++) retx_after += g_tcp_retransmit_count[c];
        *out_retx = retx_after - retx_before;
    }
    if (out_srtt) tcp_conn_ts_info(&s_cli, out_srtt, NULL);
    if (out_ms)   *out_ms = (uint32_t)get_ms_from(run_start);

    netif_activate(self);  tcp_close(&s_cli);
    netif_activate(srv_if); tcp_close(&s_srv);
    tcp_unlisten(listener);
    netif_activate(self);
    return ok;
}

/*=================================================================
 * シェルの `tcptstest`。TCP Timestamps(段階 24 = C3a)の検証。
 *
 *   [1] 合意すると MSS が 12 バイト減る(オプションのぶん)
 *   [2] **ロス注入下でも RTT 推定が更新され続ける**(陽性対照)
 *   [3] `tcpts off` では Karn の制約で更新が止まる(陰性対照)
 *
 * [2] と [3] を組で取るのが要点。無ロスでは Timestamps が無くても RTT は
 * 測れるので、**ロスを注入しないと効果は 1 つも見えない**。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_tcptstest(void)
{
    const uint16_t port  = 6005u;
    const unsigned rounds = 4u;    /* 512KB x 4 = 2MB */
    const uint32_t drop  = 12u;    /* データセグメント 12 個に 1 個を捨てる */

    netif_t *peer = NULL;
    netif_t *self = g_active_ctx;
    uint8_t peer_ll[16];
    peer = shell_peer_ll6(peer_ll);
    if (!peer || !self) {
        uart_printf("tcptstest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint32_t peer_ip = (net_active_ip() == 0xC0A8650Au) ? 0xC0A8650Bu : 0xC0A8650Au;
    netaddr_t dst4 = netaddr_v4(peer_ip);

    uint32_t saved_ts   = g_tcp_ts_enable;
    uint32_t saved_drop = g_tcp_tx_drop_every;
    uint32_t paws_before = g_tcp_paws_drop_count;

    uart_printf("tcptstest: client=%s server=%s port=%u (512KB x %u、txdrop %u)\n",
                self->name, peer->name, (unsigned)port, rounds, (unsigned)drop);

    /* [1][2] Timestamps 有効 */
    g_tcp_ts_enable = 1;
    uint16_t mss_on = 0; uint32_t rtt_on = 0, ts_on = 0, retx_on = 0; uint64_t srtt_on = 0;
    int ok_on = shell_loss_run("[有効]", self, peer, &dst4, port, rounds, drop,
                                 &mss_on, &rtt_on, &ts_on, &retx_on, &srtt_on, NULL, NULL);

    /* [3] 陰性対照: Timestamps 無効 */
    g_tcp_ts_enable = 0;
    uint16_t mss_off = 0; uint32_t rtt_off = 0, ts_off = 0, retx_off = 0; uint64_t srtt_off = 0;
    int ok_off = shell_loss_run("[無効]", self, peer, &dst4, port, rounds, drop,
                                 &mss_off, &rtt_off, &ts_off, &retx_off, &srtt_off, NULL, NULL);

    g_tcp_ts_enable     = saved_ts;    /* **必ず元に戻す** */
    g_tcp_tx_drop_every = saved_drop;

    uart_printf("tcptstest: 有効 -- MSS=%u RTT更新=%u(うちTSecr由来=%u) 再送=%u srtt=%uus\n",
                (unsigned)mss_on, (unsigned)rtt_on, (unsigned)ts_on,
                (unsigned)retx_on, (unsigned)srtt_on);
    uart_printf("tcptstest: 無効 -- MSS=%u RTT更新=%u(うちTSecr由来=%u) 再送=%u srtt=%uus\n",
                (unsigned)mss_off, (unsigned)rtt_off, (unsigned)ts_off,
                (unsigned)retx_off, (unsigned)srtt_off);

    int ok = ok_on && ok_off;
    if (ok && mss_off != (uint16_t)(mss_on + 12u)) {
        uart_printf("tcptstest: NG -- MSS の差が 12 ではありません(有効=%u 無効=%u)\n",
                    (unsigned)mss_on, (unsigned)mss_off);
        ok = 0;
    }
    if (ok && ts_on == 0u) {
        uart_printf("tcptstest: NG -- TSecr から RTT を 1 度も測れていません\n");
        ok = 0;
    }
    if (ok && retx_on == 0u) {
        uart_printf("tcptstest: NG -- 再送が 1 度も起きていません"
                    "(ロスを注入できていない = 陽性対照になっていない)\n");
        ok = 0;
    }
    if (ok && rtt_on <= rtt_off) {
        uart_printf("tcptstest: NG -- ロス注入下で RTT の更新回数が増えていません"
                    "(有効=%u 無効=%u)\n", (unsigned)rtt_on, (unsigned)rtt_off);
        ok = 0;
    }
    if (g_tcp_paws_drop_count != paws_before) {
        uart_printf("tcptstest: NG -- PAWS が %u 個のセグメントを捨てました"
                    "(正常な往復で発火してはいけない)\n",
                    (unsigned)(g_tcp_paws_drop_count - paws_before));
        ok = 0;
    }
    uart_printf("tcptstest: %s (tcpts を %s、txdrop を %u へ復元)\n",
                ok ? "PASS" : "NG", g_tcp_ts_enable ? "有効" : "無効",
                (unsigned)g_tcp_tx_drop_every);
}

/*=================================================================
 * シェルの `sacktest`。SACK(段階 25 = C3b)の検証。
 *
 * **ロス率を振って曲線として比べる。** 単一の点で比べても意味が無い
 * (段階 2 で「代表的でない条件で測って結論を出した」失敗をしている)。
 * 各ロス率で 64KB x 8 を流し、SACK 有効/無効(= Go-Back-N)で
 *   - 所要時間(= スループット)
 *   - 再送回数(**ロス 1 個あたり何個送り直したか**)
 * を並べる。
 *
 * 引数:
 *   args - ロス率のリスト(省略時は 1000,200,50,12)
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_sacktest(char *args)
{
    const uint16_t port   = 6006u;
    const unsigned rounds = 4u;    /* 512KB x 4 = 2MB */
    uint32_t drops[6] = { 1000u, 200u, 50u, 12u, 0u, 0u };
    unsigned ndrops = 4u;

    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
        /* カンマ区切りのロス率リスト(atoi は ',' で止まる)。 */
        const char *p = args;
        ndrops = 0;
        while (*p && ndrops < 6u) {
            int v = atoi(p);
            if (v > 0) drops[ndrops++] = (uint32_t)v;
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
        }
        if (ndrops == 0) { ndrops = 1; drops[0] = 12u; }
    }

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("sacktest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint32_t peer_ip = (net_active_ip() == 0xC0A8650Au) ? 0xC0A8650Bu : 0xC0A8650Au;
    netaddr_t dst4 = netaddr_v4(peer_ip);

    uint32_t saved_sack = g_tcp_sack_enable;
    uint32_t saved_drop = g_tcp_tx_drop_every;

    uart_printf("sacktest: client=%s server=%s port=%u (512KB x %u を各ロス率で)\n",
                self->name, peer->name, (unsigned)port, rounds);
    uart_printf("sacktest: %-8s %-6s %10s %8s %8s %10s\n",
                "txdrop", "SACK", "所要ms", "破棄", "再送", "再送/破棄");

    int ok = 1;
    uint32_t retx_sack_total = 0, retx_gbn_total = 0;
    uint32_t ms_sack_total = 0, ms_gbn_total = 0;
    for (unsigned d = 0; d < ndrops; d++) {
        for (int mode = 1; mode >= 0; mode--) {   /* 1=SACK 有効、0=Go-Back-N */
            g_tcp_sack_enable = (uint32_t)mode;
            for (unsigned c = 0; c < SMP_MAX_CORES; c++) g_tcp_tx_dropped_count[c] = 0;
            uint32_t segs_before = g_tcp_retransmit_segs;
            uint32_t retx = 0, ms = 0;
            uint8_t  sack_on = 0;
            if (!shell_loss_run("sacktest", self, peer, &dst4, port, rounds, drops[d],
                                 NULL, NULL, NULL, &retx, NULL, &ms, &sack_on)) {
                ok = 0;
            }
            uint32_t dropped = 0;
            for (unsigned c = 0; c < SMP_MAX_CORES; c++) dropped += g_tcp_tx_dropped_count[c];
            /* **見るのは「再送を始めた回数」ではなく「送り直したセグメント数」**。
             * Go-Back-N は穴の後ろも全部送り直すので、そこに差が出る。 */
            uint32_t segs = g_tcp_retransmit_segs - segs_before;
            uart_printf("sacktest: %-8u %-6s %10u %8u %8u %10u/100\n",
                        (unsigned)drops[d], sack_on ? "あり" : "なし",
                        (unsigned)ms, (unsigned)dropped, (unsigned)segs,
                        dropped ? (unsigned)((uint64_t)segs * 100u / dropped) : 0u);
            (void)retx;
            if (mode == 1) {
                ms_sack_total += ms;
                retx_sack_total += segs;
                if (!sack_on) {
                    uart_printf("sacktest: NG -- SACK を有効にしたのに合意できていません\n");
                    ok = 0;
                }
            } else {
                ms_gbn_total += ms;
                retx_gbn_total += segs;
                if (sack_on) {
                    uart_printf("sacktest: NG -- SACK を無効にしたのに合意しています\n");
                    ok = 0;
                }
            }
        }
    }

    g_tcp_sack_enable   = saved_sack;   /* **必ず元に戻す** */
    g_tcp_tx_drop_every = saved_drop;

    uart_printf("sacktest: 合計 -- 所要 SACK あり=%ums / なし=%ums、"
                "再送セグメント あり=%u / なし=%u\n",
                (unsigned)ms_sack_total, (unsigned)ms_gbn_total,
                (unsigned)retx_sack_total, (unsigned)retx_gbn_total);
    /* **判定は所要時間で行う。** 再送セグメント数は「注入されたロスの数」が
     * 走行ごとに違う(ロス注入は送ったセグメント数に比例する)ので、
     * 有無の比較にそのまま使えない。回復が速くなったかどうかが見たいこと。 */
    if (ok && ms_sack_total >= ms_gbn_total) {
        uart_printf("sacktest: NG -- SACK を入れてもロス下の所要時間が縮んでいません\n");
        ok = 0;
    }
    if (ok && g_tcp_sack_skipped_count == 0u) {
        uart_printf("sacktest: NG -- 「SACK 済みなので送らない」が 1 度も起きていません\n");
        ok = 0;
    }
    uart_printf("sacktest: %s (tcpsack を %s、txdrop を %u へ復元。送信省略=%u ブロック送出=%u)\n",
                ok ? "PASS" : "NG", g_tcp_sack_enable ? "有効" : "無効",
                (unsigned)g_tcp_tx_drop_every,
                (unsigned)g_tcp_sack_skipped_count, (unsigned)g_tcp_sack_sent_count);
}

/*=================================================================
 * シェルの `tcpsack`。SACK(RFC 2018)の有効/無効と統計。
 *
 * **コネクション単位で SYN のときに決まる**ので、切り替えても既存の
 * コネクションには効かない。
 *
 * 引数:
 *   args - on / off。省略時は現在値と統計を表示
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_tcpsack(char *args)
{
    while (*args == ' ') args++;
    if (strncmp(args, "on", 2) == 0) {
        g_tcp_sack_enable = 1;
    } else if (strncmp(args, "off", 3) == 0) {
        g_tcp_sack_enable = 0;
    } else if (strncmp(args, "debug", 5) == 0) {
        g_tcp_sack_debug = 8;   /* 次の 8 回だけ scoreboard をダンプする */
    } else if (strncmp(args, "report", 6) == 0) {
        /* 合意もブロック送出もしたまま、再送だけ Go-Back-N に戻す
         * (「SACK の何が効いて何が損なのか」を分けて測るため)。 */
        g_tcp_sack_use_tx = 0;
    } else if (strncmp(args, "use", 3) == 0) {
        g_tcp_sack_use_tx = 1;
    }
    uart_printf("tcpsack: %s(次に張るコネクションから。既存のものは変わらない)\n",
                g_tcp_sack_enable ? "有効" : "無効");
    uart_printf("tcpsack: 送信省略=%u / ブロック送出=%u / ブロック受領=%u / 再送セグメント=%u\n",
                (unsigned)g_tcp_sack_skipped_count, (unsigned)g_tcp_sack_sent_count,
                (unsigned)g_tcp_sack_rx_count, (unsigned)g_tcp_retransmit_segs);
    uart_printf("tcpsack: 判定を試みた=%u / scoreboard が空=%u\n",
                (unsigned)g_tcp_sack_probe_count, (unsigned)g_tcp_sack_noinfo_count);
    uart_printf("tcpsack: 空振りした高速再送=%u / partial ACK での再送=%u\n",
                (unsigned)g_tcp_fr_empty, (unsigned)g_tcp_sack_partial_retx);
    uart_printf("tcpsack: 重複ACKの行き先 -- 補正で消費=%u 回復中=%u recoverガード=%u "
                "1RTT制限=%u 閾値到達=%u\n",
                (unsigned)g_tcp_dup_suppressed, (unsigned)g_tcp_dup_in_recovery,
                (unsigned)g_tcp_dup_recover_guard, (unsigned)g_tcp_dup_rate_limited,
                (unsigned)g_tcp_dup_threshold_hit);
}

/*=================================================================
 * シェルの `tcpts`。TCP Timestamps(RFC 7323)の有効/無効と統計。
 *
 * **コネクション単位で SYN の交換のときに決まる**ので、切り替えても既存の
 * コネクションには効かない(`tcpbench` のセッションは張り直しが要る)。
 *
 * 引数:
 *   args - on / off。省略時は現在値と統計を表示
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_tcpts(char *args)
{
    while (*args == ' ') args++;
    if (strncmp(args, "on", 2) == 0) {
        g_tcp_ts_enable = 1;
    } else if (strncmp(args, "off", 3) == 0) {
        g_tcp_ts_enable = 0;
    }
    uart_printf("tcpts: %s(次に張るコネクションから。既存のものは変わらない)\n",
                g_tcp_ts_enable ? "有効" : "無効");
    uart_printf("tcpts: TSecr から測った RTT サンプル=%u / PAWS で破棄=%u\n",
                (unsigned)g_tcp_ts_rtt_samples, (unsigned)g_tcp_paws_drop_count);
}

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
 *   shell_route(), bench_plan_parse(), shell_simdelay(), shell_ts()
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
 * "a.b.c.d" をホストバイトオーダーの IPv4 へ変換する。
 *
 * 引数:
 *   s   - 変換元。オクテット 4 個が '.' 区切りである必要がある
 *   out - 変換結果の格納先
 * 戻り値:
 *   0=変換できた、-1=書式が不正
 * コール元:
 *   shell_route()
 * ===============================================================*/
static int shell_parse_ipv4(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    for (unsigned oct = 0; oct < 4u; oct++) {
        if (*s < '0' || *s > '9') return -1;
        uint32_t b = 0;
        while (*s >= '0' && *s <= '9') {
            b = b * 10u + (uint32_t)(*s - '0');
            if (b > 255u) return -1;
            s++;
        }
        v = (v << 8) | b;
        if (oct < 3u) {
            if (*s != '.') return -1;
            s++;
        }
    }
    if (*s != '\0') return -1;
    *out = v;
    return 0;
}

/*=================================================================
 * IPv4 をオクテット表記で 1 行に出す(uart_printf に %s 用の変換先が
 * 無いので、呼び出しごとに 4 引数で展開する用のマクロ代わり)。
 *
 * 引数:
 *   label - 行頭のラベル
 *   ip    - 表示する IPv4(ホストバイトオーダー)
 * コール元:
 *   shell_route()
 * ===============================================================*/
static void shell_print_ipv4(const char *label, uint32_t ip)
{
    uart_printf("%s%u.%u.%u.%u", label,
                (ip >> 24) & 0xFFu, (ip >> 16) & 0xFFu, (ip >> 8) & 0xFFu, ip & 0xFFu);
}

/*=================================================================
 * シェルの `route`。引数なしで全インターフェースの IP / netmask /
 * ゲートウェイを表示し、"<if> <netmask> <gateway>" で IPv4 の経路を設定する
 * (gateway に 0.0.0.0 を渡すと解除 = 全ての宛先を同一リンク上として扱う)。
 *
 * 引数:
 *   args - "" または "<ifname> <netmask> <gateway>"
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_route(char *args)
{
    char *tok[3];
    unsigned nt = shell_tokenize(args, tok, 3);

    if (nt >= 3u) {
        netif_t *ni = netif_find(tok[0]);
        uint32_t mask = 0, gw = 0;
        if (!ni) {
            uart_printf("route: インターフェース %s が見つかりません\n", tok[0]);
            return;
        }
        if (shell_parse_ipv4(tok[1], &mask) != 0 || shell_parse_ipv4(tok[2], &gw) != 0) {
            uart_printf("route: netmask/gateway の書式が不正です(a.b.c.d)\n");
            return;
        }
        ni->netmask = mask;
        ni->gateway = gw;
        uart_printf("route: %s を設定しました\n", ni->name);
    } else if (nt != 0u) {
        uart_printf("route: 使い方 -- route | route <ifname> <netmask> <gateway>\n");
        return;
    }

    for (unsigned i = 0; i < NETIF_MAX_REGISTERED * SMP_MAX_CORES; i++) {
        /* netif_find は名前でしか引けないので、既知の 2 本を直接見る。 */
        static const char *names[] = { "mlx5-pf0", "mlx5-pf1" };
        if (i >= sizeof(names) / sizeof(names[0])) break;
        netif_t *ni = netif_find(names[i]);
        if (!ni) continue;
        shell_print_ipv4("  ", ni->ip);
        shell_print_ipv4(" mask ", ni->netmask);
        if (ni->gateway) {
            shell_print_ipv4(" gw ", ni->gateway);
        } else {
            uart_printf(" gw なし(全て同一リンク扱い)");
        }
        uart_printf("  %s%s\n", ni->name, ni->gateway6_set ? " [gw6 設定あり]" : "");
    }
}

/* ---- fragtest: 受信断片を観測して RFC 791 どおりかを確かめる ---- */
#define FRAGTEST_MAX_FRAGS 16u
#define FRAGTEST_BUF_SIZE  65536u

static struct {
    uint16_t id;
    uint16_t off;
    uint16_t len;
    int      more;
    uint8_t  protocol;
} s_frag_seen[FRAGTEST_MAX_FRAGS];
static unsigned s_frag_count;
static unsigned s_frag_overflow;
static uint8_t  s_frag_reasm[FRAGTEST_BUF_SIZE];
static uint8_t  s_frag_dump;   /* 1=IP ヘッダ相当を 16 進で出す(tools/ip_frag_check 用) */

/*=================================================================
 * ip.c から断片ごとに呼ばれる観測フック。**再構成はここでテスト側が独自に
 * 行う**(スタックは再構成しないので、これが送信側を確かめる唯一の手段)。
 *
 * 引数:
 *   id / frag_off / more / protocol - 断片のヘッダから取り出した値
 *   payload / len                   - その断片のペイロード
 * コール元:
 *   ip_handle_frame() から関数ポインタ経由
 * ===============================================================*/
static void shell_frag_observer(uint16_t id, uint16_t frag_off, int more,
                                 uint8_t protocol, const uint8_t *payload, uint16_t len)
{
    if (s_frag_count >= FRAGTEST_MAX_FRAGS) { s_frag_overflow++; return; }
    if ((uint32_t)frag_off + len > FRAGTEST_BUF_SIZE) { s_frag_overflow++; return; }

    s_frag_seen[s_frag_count].id       = id;
    s_frag_seen[s_frag_count].off      = frag_off;
    s_frag_seen[s_frag_count].len      = len;
    s_frag_seen[s_frag_count].more     = more;
    s_frag_seen[s_frag_count].protocol = protocol;
    s_frag_count++;

    for (uint16_t i = 0; i < len; i++) s_frag_reasm[frag_off + i] = payload[i];
}

/*=================================================================
 * 観測した断片列が RFC 791 どおりかを検査する。
 *
 * 引数:
 *   label      - 表示用のラベル
 *   want_total - 送信した IP ペイロードの総バイト数
 *   want_frags - 期待する断片数(0 なら個数は判定しない)
 * 戻り値:
 *   1=すべて期待どおり、0=そうでない
 * コール元:
 *   shell_fragtest()
 * ===============================================================*/
static int shell_frag_verify(const char *label, uint32_t want_total, unsigned want_frags)
{
    int ok = 1;

    if (s_frag_overflow) {
        uart_printf("fragtest: NG %s -- 観測が溢れた (%u 個)\n", label, s_frag_overflow);
        return 0;
    }
    if (s_frag_count == 0) {
        uart_printf("fragtest: NG %s -- 断片が 1 つも観測されなかった\n", label);
        return 0;
    }
    if (want_frags != 0u && s_frag_count != want_frags) {
        uart_printf("fragtest: NG %s -- 断片数が %u(期待 %u)\n",
                    label, s_frag_count, want_frags);
        ok = 0;
    }

    /* 全断片で ID が同じか。違うと受信側が束ねられない。 */
    for (unsigned i = 1; i < s_frag_count; i++) {
        if (s_frag_seen[i].id != s_frag_seen[0].id) {
            uart_printf("fragtest: NG %s -- 断片 %u の ID が %u(先頭は %u)\n",
                        label, i, s_frag_seen[i].id, s_frag_seen[0].id);
            ok = 0;
        }
    }

    /* オフセットと長さが [0, want_total) を隙間も重複も無く覆うか。
     * 送信順に届く前提は置かず、offset を足し合わせて確認する。 */
    uint32_t covered = 0;
    int last_seen = 0;
    for (unsigned i = 0; i < s_frag_count; i++) {
        covered += s_frag_seen[i].len;
        /* 最後以外の断片長は 8 の倍数でなければならない
         * (フラグメントオフセットが 8 バイト単位なので、端数が出ると
         *  次の断片のオフセットを表現できない)。 */
        if (s_frag_seen[i].more && (s_frag_seen[i].len % 8u) != 0u) {
            uart_printf("fragtest: NG %s -- MF=1 の断片 %u の長さ %u が 8 の倍数でない\n",
                        label, i, s_frag_seen[i].len);
            ok = 0;
        }
        if (!s_frag_seen[i].more) {
            last_seen++;
            if ((uint32_t)s_frag_seen[i].off + s_frag_seen[i].len != want_total) {
                uart_printf("fragtest: NG %s -- 最終断片の末尾が %u(期待 %u)\n", label,
                            (unsigned)s_frag_seen[i].off + s_frag_seen[i].len,
                            (unsigned)want_total);
                ok = 0;
            }
        }
        if ((s_frag_seen[i].off % 8u) != 0u) {
            uart_printf("fragtest: NG %s -- 断片 %u のオフセット %u が 8 の倍数でない\n",
                        label, i, s_frag_seen[i].off);
            ok = 0;
        }
    }
    if (last_seen != 1) {
        uart_printf("fragtest: NG %s -- MF=0 の断片が %u 個(1 個であるべき)\n",
                    label, (unsigned)last_seen);
        ok = 0;
    }
    if (covered != want_total) {
        uart_printf("fragtest: NG %s -- 断片長の合計が %u(期待 %u)\n",
                    label, (unsigned)covered, (unsigned)want_total);
        ok = 0;
    }

    uart_printf("fragtest: %s %s -- 断片 %u 個 / id=%u / 合計 %u バイト\n",
                ok ? "OK" : "NG", label, s_frag_count, s_frag_seen[0].id, (unsigned)covered);
    for (unsigned i = 0; i < s_frag_count; i++) {
        uart_printf("    断片%u: offset=%u len=%u MF=%d protocol=%u\n",
                    i, s_frag_seen[i].off, s_frag_seen[i].len,
                    s_frag_seen[i].more, s_frag_seen[i].protocol);
    }
    if (s_frag_dump) {
        /* tools/ip_frag_check が読む形式。Linux の struct iphdr で解釈させる
         * ため、ワイヤ上の 20 バイトをそのまま復元できる値だけを出す。 */
        uart_printf("FRAGDUMP total=%u count=%u\n", (unsigned)want_total, s_frag_count);
        for (unsigned i = 0; i < s_frag_count; i++) {
            uart_printf("FRAGDUMP frag id=%u off=%u len=%u mf=%d proto=%u\n",
                        s_frag_seen[i].id, s_frag_seen[i].off, s_frag_seen[i].len,
                        s_frag_seen[i].more, s_frag_seen[i].protocol);
        }
    }
    return ok;
}

/*=================================================================
 * シェルの `fragtest`。A4(送信側の IP フラグメント)の検証。
 *
 * **このスタックは受信側の再構成を実装していない**ので、素直な往復では
 * 確かめられない。ip.c に観測フックを入れ、断片を捨てる直前にテスト側へ
 * 渡してもらい、**テスト側が RFC 791 を見ながら独自に再構成する**。
 * 送信側(ip.c)と検査側(main.c)が別のコードなので、「両側が同じ間違いを
 * して検出できない」形にはならない。
 *
 * 3 パターン見る:
 *  [1] MTU 以下 -- 分割されない(断片が 1 つも観測されない)
 *  [2] MTU の 2 倍超 -- 中間断片(MF=1 かつ offset 非 0)が生じる
 *  [3] UDP 経由 -- 計画が「実害があるのは UDP のみ」と書いている経路
 *
 * 引数:
 *   args - "dump" を付けると tools/ip_frag_check 用の行も出す
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_fragtest(char *args)
{
    /* RFC 3692 の実験・試験用プロトコル番号。上位ハンドラが居ないので、
     * 断片でない [1] のケースは Protocol Unreachable が返るだけで済む。 */
    const uint8_t test_proto = 253u;

    while (*args == ' ') args++;
    s_frag_dump = (strncmp(args, "dump", 4) == 0);

    uint8_t peer_ll[16];  /* shell_peer_ll6() は必ず書き込むので NULL は渡せない */
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("fragtest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }

    uint16_t ip_mtu = net_active_ip_mtu();
    uint16_t max_payload = (uint16_t)(ip_mtu - 20u);
    uint16_t chunk = (uint16_t)(max_payload & ~7u);
    uart_printf("fragtest: L3 MTU=%u -> 1 断片の IP ペイロード上限=%u(8 の倍数へ切り下げ %u)\n",
                ip_mtu, max_payload, chunk);

    uint32_t peer_ip = peer->ip;
    uint8_t dst_ip[4] = { (uint8_t)(peer_ip >> 24), (uint8_t)(peer_ip >> 16),
                          (uint8_t)(peer_ip >> 8), (uint8_t)peer_ip };
    uint8_t dst_mac[6];
    netaddr_t peer_addr = netaddr_v4(peer_ip);
    if (net_resolve_mac(&peer_addr, dst_mac) != 0) {
        uart_printf("fragtest: 対向 PF の MAC 解決に失敗\n");
        return;
    }

    static uint8_t tx[FRAGTEST_BUF_SIZE];
    for (unsigned i = 0; i < sizeof(tx); i++) tx[i] = (uint8_t)(i * 31u + 11u);

    int ok = 1;
    ip_set_frag_observer(shell_frag_observer);

    /* ---- [1] MTU 以下は分割されない ---- */
    s_frag_count = 0; s_frag_overflow = 0;
    ip_send(dst_ip, dst_mac, test_proto, tx, (uint16_t)(max_payload));
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 100u); ) net_poll_all_and_dispatch();
    if (s_frag_count != 0) {
        uart_printf("fragtest: NG [1] MTU ちょうど(%u バイト)なのに断片が %u 個出た\n",
                    max_payload, s_frag_count);
        ok = 0;
    } else {
        uart_printf("fragtest: OK [1] IP ペイロード %u バイト -- 分割されない\n", max_payload);
    }

    /* ---- [2] MTU の 2 倍超 -> 中間断片が生じる ---- */
    const uint16_t big = (uint16_t)(chunk * 2u + 1000u);
    unsigned want = 3u;
    s_frag_count = 0; s_frag_overflow = 0;
    if (ip_send(dst_ip, dst_mac, test_proto, tx, big) != 0) {
        uart_printf("fragtest: NG [2] ip_send が失敗\n");
        ok = 0;
    } else {
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
        ok &= shell_frag_verify("[2] IP 直送(中間断片あり)", big, want);
        /* 再構成した内容が送ったものと一致するか。 */
        int match = 1;
        for (uint32_t i = 0; i < big; i++) {
            if (s_frag_reasm[i] != tx[i]) { match = 0; break; }
        }
        uart_printf("fragtest: %s [2] 再構成した %u バイトが送信内容と%s\n",
                    match ? "OK" : "NG", big, match ? "一致" : "不一致");
        if (!match) ok = 0;
        /* 中間断片(MF=1 かつ offset 非 0)が実際に生じたか。ここを通らないと
         * 「2 個に割れるだけ」のケースしか検証できていない。 */
        int middle = 0;
        for (unsigned i = 0; i < s_frag_count; i++) {
            if (s_frag_seen[i].more && s_frag_seen[i].off != 0u) middle = 1;
        }
        uart_printf("fragtest: %s [2] 中間断片(MF=1 かつ offset 非 0)が%s\n",
                    middle ? "OK" : "NG", middle ? "存在する" : "無い");
        if (!middle) ok = 0;
    }

    /* ---- [3] UDP 経由(計画が実害ありとしている経路)---- */
    const uint16_t udp_payload = 10000u;
    s_frag_count = 0; s_frag_overflow = 0;
    if (udp_send(dst_ip, dst_mac, 7777u, 7777u, tx, udp_payload) != 0) {
        uart_printf("fragtest: NG [3] udp_send が失敗\n");
        ok = 0;
    } else {
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
        /* UDP ヘッダ 8 バイトぶん多い。断片数は 0 指定で個数判定を省く。 */
        ok &= shell_frag_verify("[3] UDP 経由", (uint32_t)udp_payload + 8u, 0u);
        if (s_frag_count > 0 && s_frag_seen[0].protocol != IP_PROTO_UDP) {
            uart_printf("fragtest: NG [3] protocol が %u(UDP=%u であるべき)\n",
                        s_frag_seen[0].protocol, IP_PROTO_UDP);
            ok = 0;
        }
    }

    ip_set_frag_observer(NULL);
    s_frag_dump = 0;
    uart_printf("fragtest: %s\n", ok ? "PASS" : "NG");
}

/* ---- pmtutest: ICMP エラーを注入して PMTU の学習と適用を確かめる ---- */

static uint8_t s_pmtu_dump;  /* 1=注入した ICMP を 16 進で出す(tools/icmp_mtu_check 用) */

/*=================================================================
 * ICMP Fragmentation Needed(type 3 / code 4)を 1 個組み立てて送る。
 * ルータの役を対向インターフェースが務める。
 *
 * **MTU の置き場所が要点。** RFC 1191 では未使用 4 バイトのうち
 * 「上位 16bit は 0、下位 16bit が次ホップ MTU」。byte 4-5 に書くと桁が狂う。
 *
 * 引数:
 *   to_ip / to_mac - 送り先(ICMP エラーを受け取る側)
 *   orig_src       - 引用する元データグラムの送信元(= 受け取る側)
 *   orig_dst       - 引用する元データグラムの宛先(= PMTU を学習させたい宛先)
 *   mtu            - 報告する次ホップ MTU
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_pmtutest()
 * ===============================================================*/
static int shell_inject_frag_needed(const uint8_t to_ip[4], const uint8_t to_mac[6],
                                     uint32_t orig_src, uint32_t orig_dst, uint16_t mtu)
{
    static uint8_t msg[8u + 20u + 8u];
    for (unsigned i = 0; i < sizeof(msg); i++) msg[i] = 0;

    msg[0] = ICMP_TYPE_DEST_UNREACH;
    msg[1] = ICMP_CODE_FRAG_NEEDED;
    /* msg[2..3] はチェックサム、msg[4..5] は 0 のまま(RFC 1191)。 */
    msg[6] = (uint8_t)(mtu >> 8);
    msg[7] = (uint8_t)mtu;

    /* 引用する元 IPv4 ヘッダ(20 バイト)+ 続く 8 バイト。 */
    uint8_t *q = msg + 8u;
    q[0] = 0x45;                       /* version=4, IHL=5 */
    q[2] = 0x25; q[3] = 0x00;          /* total_length: 何でもよい(9472) */
    q[6] = 0x40;                       /* DF を立てる(Frag Needed の前提) */
    q[8] = 64;                         /* TTL */
    q[9] = IP_PROTO_TCP;
    q[12] = (uint8_t)(orig_src >> 24); q[13] = (uint8_t)(orig_src >> 16);
    q[14] = (uint8_t)(orig_src >> 8);  q[15] = (uint8_t)orig_src;
    q[16] = (uint8_t)(orig_dst >> 24); q[17] = (uint8_t)(orig_dst >> 16);
    q[18] = (uint8_t)(orig_dst >> 8);  q[19] = (uint8_t)orig_dst;

    wr16be(msg + 2, inet_checksum(msg, (uint16_t)sizeof(msg)));

    if (s_pmtu_dump) {
        uart_printf("ICMPDUMP v4 len=%u", (unsigned)sizeof(msg));
        for (unsigned i = 0; i < sizeof(msg); i++) uart_printf(" %02x", msg[i]);
        uart_printf("\n");
    }
    return ip_send(to_ip, to_mac, IP_PROTO_ICMP, msg, (uint16_t)sizeof(msg));
}

/*=================================================================
 * ICMPv6 Packet Too Big(type 2 / code 0)を 1 個組み立てて送る。
 *
 * **IPv4 と MTU の置き場所が違う。** ICMPv6 は byte 4-7 の 32bit 全体が MTU。
 * IPv4 と同じつもりで下位 16bit だけに書くと 0 と読まれる。
 *
 * 引数:
 *   to / to_mac - 送り先(ICMP エラーを受け取る側)
 *   orig_src    - 引用する元パケットの送信元(= 受け取る側)
 *   orig_dst    - 引用する元パケットの宛先(= PMTU を学習させたい宛先)
 *   mtu         - 報告する MTU
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_pmtutest()
 * ===============================================================*/
static int shell_inject_packet_too_big(const uint8_t to[16], const uint8_t to_mac[6],
                                        const uint8_t orig_src[16], const uint8_t orig_dst[16],
                                        uint32_t mtu)
{
    static uint8_t msg[8u + 40u + 8u];
    for (unsigned i = 0; i < sizeof(msg); i++) msg[i] = 0;

    msg[0] = ICMPV6_TYPE_PACKET_TOO_BIG;
    msg[1] = 0;
    /* msg[2..3] はチェックサム。msg[4..7] の 32bit 全体が MTU。 */
    msg[4] = (uint8_t)(mtu >> 24); msg[5] = (uint8_t)(mtu >> 16);
    msg[6] = (uint8_t)(mtu >> 8);  msg[7] = (uint8_t)mtu;

    /* 引用する元 IPv6 ヘッダ(40 バイト)+ 続く 8 バイト。 */
    uint8_t *q = msg + 8u;
    q[0] = 0x60;                       /* version=6 */
    q[4] = 0x24; q[5] = 0x00;          /* payload_length: 何でもよい */
    q[6] = IPV6_NH_TCP;
    q[7] = 64;                         /* hop limit */
    for (unsigned i = 0; i < 16; i++) q[8 + i]  = orig_src[i];
    for (unsigned i = 0; i < 16; i++) q[24 + i] = orig_dst[i];

    /* ICMPv6 はチェックサムに疑似ヘッダが必須。送信元はアクティブな
     * インターフェースのリンクローカル(ipv6_send() が使うものと同じ)。 */
    uint8_t src[16];
    ipv6_link_local_addr(src);
    wr16be(msg + 2, ipv6_pseudo_checksum(src, to, IPV6_NH_ICMPV6, msg, (uint16_t)sizeof(msg)));

    if (s_pmtu_dump) {
        uart_printf("ICMPDUMP v6 len=%u", (unsigned)sizeof(msg));
        for (unsigned i = 0; i < sizeof(msg); i++) uart_printf(" %02x", msg[i]);
        uart_printf("\n");
    }
    return ipv6_send(to, to_mac, IPV6_NH_ICMPV6, msg, (uint16_t)sizeof(msg));
}

/*=================================================================
 * シェルの `pmtutest`。A5/A6(Path MTU Discovery)の検証。
 *
 * **MTU の揃った DAC 直結では ICMP Frag Needed / Packet Too Big が誰からも
 * 飛んでこない。** そこで対向インターフェースにルータの役をさせ、これらを
 * 人為的に注入する。A5/A6 の実装範囲は「受信して学習し、送信へ反映する」側
 * なので、注入側がテストコードでも検証の意味は失われない。
 *
 * ただし**注入する ICMP の形式そのものが自作**なので、そこを間違えると
 * 「自分の間違いを自分で受け入れて PASS する」ことになる。`dump` を付けると
 * 注入したメッセージを 16 進で出すので、`tools/icmp_mtu_check`(Linux の
 * struct icmphdr / icmp6_hdr のみ)に食わせて形式を確かめられる。
 *
 * 引数:
 *   args - "dump" で 16 進出力を有効化
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_pmtutest(char *args)
{
    /* IPv4 側は routetest と同じ別名インターフェース(10.9.9.9)を宛先にする。
     * **nvmet が使う 192.168.101.11 を宛先にすると、学習した PMTU が生きている
     * セッションの snd_mss まで下げてしまう**(pmtu_clear() では戻らない)。 */
    const uint32_t far_ip = ip_from_octets(10, 9, 9, 9);
    const uint16_t port   = 6003u;
    const uint16_t v4_mtu = 1500u;   /* 定番の Ethernet MTU */
    const uint32_t v6_mtu = 1400u;   /* IPv6 の下限 1280 より上 */
    static netif_t s_alias;

    while (*args == ' ') args++;
    s_pmtu_dump = (strncmp(args, "dump", 4) == 0);

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("pmtutest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint8_t self_ll[16];
    ipv6_link_local_addr(self_ll);

    const uint32_t self_ip = self->ip;
    uint8_t self_ip_oct[4] = { (uint8_t)(self_ip >> 24), (uint8_t)(self_ip >> 16),
                               (uint8_t)(self_ip >> 8), (uint8_t)self_ip };
    uint8_t self_mac[6];
    for (unsigned i = 0; i < 6u; i++) self_mac[i] = self->mac[i];

    int ok = 1;
    netaddr_t far_addr = netaddr_v4(far_ip);
    netaddr_t peer6    = netaddr_v6(peer_ll);

    /* 対向 PF を「別サブネットの相手」として実在させる(routetest と同じ手)。 */
    s_alias = *peer;
    s_alias.name    = "pmtu-far";
    s_alias.ip      = far_ip;
    s_alias.netmask = 0u;
    s_alias.gateway = 0u;
    s_alias.gateway6_set = 0u;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) s_alias.arp_cache[i].valid = 0;
    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) s_alias.ndp_cache[i].valid = 0;
    netif_register(&s_alias);
    s_alias.is_poll_owner = 0;
    netif_activate(self);

    /* ---- [1] 初期状態 ---- */
    pmtu_clear();
    if (pmtu_lookup(&far_addr) != 0u || pmtu_lookup(&peer6) != 0u) {
        uart_printf("pmtutest: NG [1] クリア直後なのに学習済みの値がある\n");
        ok = 0;
    } else {
        uart_printf("pmtutest: OK [1] 初期状態 -- 学習済みの PMTU なし\n");
    }

    /* ---- [2] IPv4: Frag Needed を注入して学習させる ----
     * ルータ役として対向 PF から送る。引用する元データグラムは
     * 「self -> 10.9.9.9」なので、self が 10.9.9.9 の PMTU を学習する。 */
    netif_activate(peer);
    int inj = shell_inject_frag_needed(self_ip_oct, self_mac, self_ip, far_ip, v4_mtu);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();

    uint16_t got4 = pmtu_lookup(&far_addr);
    uart_printf("pmtutest: %s [2] IPv4 Frag Needed(MTU=%u)-> 学習値=%u\n",
                (inj == 0 && got4 == v4_mtu) ? "OK" : "NG", v4_mtu, got4);
    if (inj != 0 || got4 != v4_mtu) ok = 0;

    /* ---- [3] IPv4: 新規 TCP コネクションの MSS が下がる ---- */
    uint16_t mss4 = 0;
    if (shell_tcp_echo_once("pmtutest", self, &s_alias, &far_addr, port, &mss4)) {
        /* Timestamps を合意していると、載せるオプションのぶん(12 バイト)
         * ペイロードの上限がさらに下がる(Linux も 1500 の MTU で mss 1448)。 */
        uint16_t want = (uint16_t)(v4_mtu - 20u - 20u - (g_tcp_ts_enable ? 12u : 0u));
        uart_printf("pmtutest: %s [3] IPv4 コネクションの MSS=%u(期待 %u)\n",
                    (mss4 == want) ? "OK" : "NG", mss4, want);
        if (mss4 != want) ok = 0;
    } else {
        uart_printf("pmtutest: NG [3] IPv4 の往復に失敗\n");
        ok = 0;
    }
    netif_activate(self);

    /* ---- [4] IPv4: ip_send が学習した PMTU で分割する ---- */
    {
        static uint8_t tx[4096];
        for (unsigned i = 0; i < sizeof(tx); i++) tx[i] = (uint8_t)(i * 13u + 5u);
        uint8_t far_oct[4] = { 10, 9, 9, 9 };
        uint8_t far_mac[6];
        for (unsigned i = 0; i < 6u; i++) far_mac[i] = s_alias.mac[i];

        s_frag_count = 0; s_frag_overflow = 0;
        ip_set_frag_observer(shell_frag_observer);
        ip_send(far_oct, far_mac, 253u, tx, (uint16_t)sizeof(tx));
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
        ip_set_frag_observer(NULL);

        /* PMTU 1500 -> IP ペイロード上限 1480(8 の倍数なのでそのまま)。
         * 4096 バイトは 1480 + 1480 + 1136 の 3 断片になる。 */
        uint16_t want_chunk = (uint16_t)((v4_mtu - 20u) & ~7u);
        int good = (s_frag_count == 3u) && (s_frag_seen[0].len == want_chunk);
        uart_printf("pmtutest: %s [4] ip_send が PMTU で分割 -- 断片 %u 個 / 先頭 %u バイト"
                    "(期待 3 個 / %u バイト)\n",
                    good ? "OK" : "NG", s_frag_count,
                    s_frag_count ? s_frag_seen[0].len : 0u, want_chunk);
        if (!good) ok = 0;
    }

    /* ---- [5] IPv6: Packet Too Big を注入して学習させる ---- */
    netif_activate(peer);
    int inj6 = shell_inject_packet_too_big(self_ll, self_mac, self_ll, peer_ll, v6_mtu);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();

    uint16_t got6 = pmtu_lookup(&peer6);
    uart_printf("pmtutest: %s [5] IPv6 Packet Too Big(MTU=%u)-> 学習値=%u\n",
                (inj6 == 0 && got6 == (uint16_t)v6_mtu) ? "OK" : "NG",
                (unsigned)v6_mtu, got6);
    if (inj6 != 0 || got6 != (uint16_t)v6_mtu) ok = 0;

    /* ---- [6] IPv6: 新規 TCP コネクションの MSS が下がる ---- */
    uint16_t mss6 = 0;
    if (shell_tcp_echo_once("pmtutest6", self, peer, &peer6, (uint16_t)(port + 1u), &mss6)) {
        uint16_t want = (uint16_t)(v6_mtu - 40u - 20u - (g_tcp_ts_enable ? 12u : 0u));
        uart_printf("pmtutest: %s [6] IPv6 コネクションの MSS=%u(期待 %u)\n",
                    (mss6 == want) ? "OK" : "NG", mss6, want);
        if (mss6 != want) ok = 0;
    } else {
        uart_printf("pmtutest: NG [6] IPv6 の往復に失敗\n");
        ok = 0;
    }
    netif_activate(self);

    /* ---- [7] 床: 下限未満の報告は採用しない ---- */
    netif_activate(peer);
    shell_inject_frag_needed(self_ip_oct, self_mac, self_ip, far_ip, 100u);   /* < 576 */
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 100u); ) net_poll_all_and_dispatch();
    netif_activate(peer);
    shell_inject_packet_too_big(self_ll, self_mac, self_ll, peer_ll, 1000u);  /* < 1280 */
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 100u); ) net_poll_all_and_dispatch();

    int floor_ok = (pmtu_lookup(&far_addr) == v4_mtu) &&
                   (pmtu_lookup(&peer6) == (uint16_t)v6_mtu);
    uart_printf("pmtutest: %s [7] 床 -- v4 に 100 / v6 に 1000 を報告しても学習値は"
                " %u / %u のまま\n", floor_ok ? "OK" : "NG",
                pmtu_lookup(&far_addr), pmtu_lookup(&peer6));
    if (!floor_ok) ok = 0;

    /* ---- [8] 大きい値の報告は無視する(PMTU は下げる方向のみ)---- */
    netif_activate(peer);
    shell_inject_frag_needed(self_ip_oct, self_mac, self_ip, far_ip, 9000u);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 100u); ) net_poll_all_and_dispatch();
    int nogrow = (pmtu_lookup(&far_addr) == v4_mtu);
    uart_printf("pmtutest: %s [8] MTU=9000 を報告しても学習値は %u のまま"
                "(上げ直しは TTL 満了に任せる)\n",
                nogrow ? "OK" : "NG", pmtu_lookup(&far_addr));
    if (!nogrow) ok = 0;

    uart_printf("pmtutest: 学習済みエントリ:\n");
    pmtu_dump();

    /* ---- [9] 後始末 ---- */
    netif_unregister(&s_alias);
    pmtu_clear();
    netif_activate(self);
    s_pmtu_dump = 0;

    if (pmtu_lookup(&far_addr) != 0u || pmtu_lookup(&peer6) != 0u) {
        uart_printf("pmtutest: NG [9] クリアしたのに学習値が残っている\n");
        ok = 0;
    }
    uart_printf("pmtutest: %s(PMTU キャッシュはクリアしました。**IPv6 の生きた\n"
                "  セッションがあれば snd_mss は下がったままなので張り直すこと**)\n",
                ok ? "PASS" : "NG");
}

/*=================================================================
 * 重複アドレス検出 1 件の結果を表示し、期待どおりかを判定する。
 *
 * 引数:
 *   label     - 表示用のラベル
 *   got       - arp_probe()/ipv6_dad() の戻り値(0=空き、1=使用中、-1=失敗)
 *   want_used - 1=使用中を期待、0=空きを期待
 *   mac       - got==1 のとき相手の MAC
 *   want_mac  - 期待する MAC。NULL なら照合しない
 * 戻り値:
 *   1=期待どおり、0=そうでない
 * コール元:
 *   shell_dadtest()
 * ===============================================================*/
static int shell_dad_check(const char *label, int got, int want_used,
                           const uint8_t mac[6], const uint8_t *want_mac)
{
    if (got < 0) {
        uart_printf("dadtest: NG %s -- 検査の送信に失敗\n", label);
        return 0;
    }
    if (got != want_used) {
        uart_printf("dadtest: NG %s -- %s と判定されました(期待は%s)\n", label,
                    got ? "使用中" : "空き", want_used ? "使用中" : "空き");
        return 0;
    }
    if (got == 0) {
        uart_printf("dadtest: OK %s -- 空き(応答なし)\n", label);
        return 1;
    }
    int mac_ok = 1;
    if (want_mac) {
        for (unsigned i = 0; i < 6u; i++) if (mac[i] != want_mac[i]) mac_ok = 0;
    }
    uart_printf("dadtest: %s %s -- 使用中 %02x:%02x:%02x:%02x:%02x:%02x%s\n",
                mac_ok ? "OK" : "NG", label,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                mac_ok ? "" : "(期待した MAC と不一致)");
    return mac_ok;
}

/*=================================================================
 * シェルの `dadtest`。A3(重複アドレス検出)の検証。
 *
 * **陰性だけを見ても意味が無い。** 「自分のアドレスは空き」は、検出が
 * 一切動いていなくても成立してしまう(応答が来ないことで判定するため)。
 * そこで対向 PF の実在するアドレスを検査する陽性対照を必ず組にする。
 * 2 ポートを同一プロセスで駆動しているので、相手役は自分自身の対向
 * インターフェースが務める。
 *
 * DAC 直結リンクはオンボード NIC(enp2s0)と物理的に繋がっていないので、
 * ここで出す ARP Probe / DAD NS はユーザの LAN には 1 フレームも出ない。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_dadtest(void)
{
    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("dadtest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }

    uint8_t self_ll[16];
    ipv6_link_local_addr(self_ll);

    uint8_t mac[6];
    int ok = 1;

    uart_printf("dadtest: self=%s peer=%s (probes=%u interval=%ums)\n",
                self->name, peer->name, ARP_PROBE_NUM, ARP_PROBE_INTERVAL_MS);

    /* [1][2] IPv4: 自分のアドレスは空き、対向 PF のアドレスは使用中。 */
    ok &= shell_dad_check("[1] IPv4 自分のアドレス",
                          arp_probe(self->ip, ARP_PROBE_NUM, ARP_PROBE_INTERVAL_MS, mac),
                          0, mac, NULL);
    ok &= shell_dad_check("[2] IPv4 対向PFのアドレス(陽性対照)",
                          arp_probe(peer->ip, ARP_PROBE_NUM, ARP_PROBE_INTERVAL_MS, mac),
                          1, mac, peer->mac);

    /* [3][4] IPv6 も同じ組み合わせ。 */
    netif_activate(self);
    ok &= shell_dad_check("[3] IPv6 自分のリンクローカル",
                          ipv6_dad(self_ll, ARP_PROBE_NUM, ARP_PROBE_INTERVAL_MS, mac),
                          0, mac, NULL);
    netif_activate(self);
    ok &= shell_dad_check("[4] IPv6 対向PFのリンクローカル(陽性対照)",
                          ipv6_dad(peer_ll, ARP_PROBE_NUM, ARP_PROBE_INTERVAL_MS, mac),
                          1, mac, peer->mac);
    netif_activate(self);

    /* [5] netif_t への記録。起動時に走らせているので、この時点で両方
     *     PASSED になっているはず。念のため呼び直して同じ結果になることを見る。 */
    int r = net_dup_addr_detect(self);
    uart_printf("dadtest: [5] %s の記録 -- IPv4=%s IPv6=%s (戻り値=%d)\n", self->name,
                self->ipv4_dup == NETIF_DAD_PASSED ? "衝突なし"
                    : (self->ipv4_dup == NETIF_DAD_CONFLICT ? "衝突" : "未実施"),
                self->dad_state == NETIF_DAD_PASSED ? "衝突なし"
                    : (self->dad_state == NETIF_DAD_CONFLICT ? "衝突" : "未実施"),
                r);
    if (r != 0 || self->ipv4_dup != NETIF_DAD_PASSED || self->dad_state != NETIF_DAD_PASSED) {
        uart_printf("dadtest: NG [5] 自分のアドレスなのに衝突が記録されました\n");
        ok = 0;
    }
    netif_activate(self);

    uart_printf("dadtest: %s\n", ok ? "PASS" : "NG");
}

/* ---- slaac / slaactest: RA を注入して SLAAC の学習と適用を確かめる ---- */

static uint8_t s_ra_dump;  /* 1=注入した RA を 16 進で出す(tools/ra_check 用) */

/*=================================================================
 * Router Advertisement を 1 個組み立てて送る。ルータの役を対向インター
 * フェースが務める(pmtutest が ICMP エラーを注入するのと同じ手)。
 *
 * **オプションの並びとバイト配置が要点**。RA 本体は 16 バイト
 * (ICMPv6 ヘッダ 8 + reachable 4 + retrans 4)で、cur hop limit は byte 4、
 * フラグは byte 5、ルータ寿命は byte 6-7。オプションはそこから 8 バイト単位。
 * Prefix Information は 32 バイト固定で、プレフィックス本体は先頭から 16。
 * ここを間違えると受信側も同じ間違い方をして「自分の間違いを自分で受け入れて
 * PASS する」ので、`dump` の 16 進を `tools/ra_check`(glibc の
 * struct nd_router_advert / nd_opt_prefix_info のみ)に食わせて確かめる。
 *
 * 引数:
 *   to / to_mac  - 送り先(RA を受け取る側)
 *   prefix       - 広告するプレフィックス(上位 plen ビットのみ意味を持つ)
 *   plen         - プレフィックス長
 *   pio_flags    - PIO_FLAG_ONLINK / PIO_FLAG_AUTO
 *   valid / pref - 有効期間・優先期間(秒)
 *   rlife        - ルータ寿命(秒)。0 なら「デフォルトルータから外せ」
 *   mtu          - MTU オプションの値(0 なら付けない)
 *   hop_limit    - IPv6 ヘッダの hop limit。**255 以外は受信側が捨てるはず**
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_slaactest()
 * ===============================================================*/
static int shell_inject_ra(const uint8_t to[16], const uint8_t to_mac[6],
                            const uint8_t prefix[16], uint8_t plen, uint8_t pio_flags,
                            uint32_t valid, uint32_t pref, uint16_t rlife,
                            uint32_t mtu, uint8_t hop_limit)
{
    static uint8_t msg[16u + 8u + 32u + 8u];
    unsigned len = 16u + 8u + 32u;
    for (unsigned i = 0; i < sizeof(msg); i++) msg[i] = 0;

    msg[0] = ICMPV6_TYPE_RA;
    msg[1] = 0;
    /* msg[2..3] はチェックサム。 */
    msg[RA_OFF_CUR_HOP_LIMIT] = 64u;
    msg[RA_OFF_FLAGS]         = 0;      /* M/O とも立てない(DHCPv6 は無い) */
    wr16be(msg + RA_OFF_ROUTER_LIFETIME, rlife);
    /* reachable time / retrans timer は 0 =「指定しない」(RFC 4861 4.2)。 */

    /* Source Link-Layer Address(ルータの MAC を教える)。 */
    uint8_t self_mac[6];
    eth_get_mac(self_mac);
    msg[16] = NDP_OPT_SRC_LLADDR;
    msg[17] = 1u;
    for (unsigned i = 0; i < 6u; i++) msg[18u + i] = self_mac[i];

    /* Prefix Information(32 バイト固定 = 長さ 4)。 */
    uint8_t *p = msg + 24u;
    p[0] = NDP_OPT_PREFIX_INFO;
    p[1] = 4u;
    p[PIO_OFF_PREFIX_LEN] = plen;
    p[PIO_OFF_FLAGS]      = pio_flags;
    wr32be(p + PIO_OFF_VALID, valid);
    wr32be(p + PIO_OFF_PREFERRED, pref);
    /* p[12..15] は reserved2。 */
    for (unsigned i = 0; i < 16u; i++) p[PIO_OFF_PREFIX + i] = prefix[i];

    if (mtu != 0u) {
        uint8_t *m = msg + 56u;
        m[0] = NDP_OPT_MTU;
        m[1] = 1u;
        /* m[2..3] は reserved。 */
        wr32be(m + 4u, mtu);
        len += 8u;
    }

    uint8_t src[16];
    ipv6_link_local_addr(src);
    wr16be(msg + 2, ipv6_pseudo_checksum(src, to, IPV6_NH_ICMPV6, msg, (uint16_t)len));

    if (s_ra_dump) {
        uart_printf("RADUMP len=%u", len);
        for (unsigned i = 0; i < len; i++) uart_printf(" %02x", msg[i]);
        uart_printf("\n");
    }

    /* **hop limit を変えられる必要がある**(255 以外を捨てることの確認)ので、
     * hop limit 255 固定の ipv6_send() ではなく自分でフレームを組む。 */
    net_buf_t *nb = net_buf_alloc();
    if (!nb) return -1;
    ipv6_build_header(nb->data, src, to, to_mac, IPV6_NH_ICMPV6, (uint16_t)len);
    nb->data[ETH_HDR_LEN + offsetof(ipv6_header_t, hop_limit)] = hop_limit;
    for (unsigned i = 0; i < len; i++) {
        nb->data[ETH_HDR_LEN + IPV6_HDR_LEN + i] = msg[i];
    }
    nb->len = (uint16_t)(ETH_HDR_LEN + IPV6_HDR_LEN + len);
    return eth_send(nb);
}

/*=================================================================
 * self が RA を処理し終えるまで受信を回す(注入は非同期なので待ちが要る)。
 *
 * 引数:
 *   ms - 待つ時間
 * コール元:
 *   shell_slaactest()
 * ===============================================================*/
static void shell_poll_ms(uint32_t ms)
{
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, ms); ) net_poll_all_and_dispatch();
}

/*=================================================================
 * netif のグローバルアドレスを SLAAC の状態ごと解除する(テストの各段の
 * 前提を揃えるため)。
 *
 * コール元:
 *   shell_slaactest()
 * ===============================================================*/
static void shell_clear_global6(netif_t *ni)
{
    ni->ip6_global_set         = 0;
    ni->ip6_global_from_ra     = 0;
    ni->ip6_global_valid_until = 0;
    ni->ip6_global_dad         = NETIF_DAD_UNKNOWN;
}

/*=================================================================
 * シェルの `slaac`。Router Solicitation を送って RA を待ち、結果を表示する。
 *
 * このリンクにはルータが居ないので、通常は「RA が来ませんでした」で終わる
 * (それが正しい)。**RA を出す相手が居るときにグローバルアドレスが生えるか**
 * を見るためのコマンドで、ループバックでの検証は `slaactest` が行う。
 *
 * 引数:
 *   args - "" で全インターフェース、"<if>" で 1 つ、続けて待ち時間(ms)
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_slaac(char *args)
{
    while (*args == ' ') args++;

    char name[32] = {0};
    unsigned k = 0;
    while (*args && *args != ' ' && k < sizeof(name) - 1u) name[k++] = *args++;
    name[k] = 0;
    while (*args == ' ') args++;
    uint32_t wait_ms = (*args >= '0' && *args <= '9') ? (uint32_t)atoi(args)
                                                      : SLAAC_RS_INTERVAL_MS;

    netif_t *prev = g_active_ctx;
    static const char *ifnames[] = { "mlx5-pf0", "mlx5-pf1" };
    for (unsigned i = 0; i < 2u; i++) {
        netif_t *ni = netif_find(ifnames[i]);
        if (!ni) continue;
        if (name[0] && strncmp(name, ni->name, sizeof(name)) != 0) continue;

        int r = ipv6_slaac_solicit(ni, SLAAC_RS_NUM, wait_ms);
        ipv6_slaac_age(ni);
        uart_printf("slaac: %-10s RS x%u(各 %ums)-> %s\n", ni->name, SLAAC_RS_NUM, wait_ms,
                    (r == 1) ? "グローバルアドレスを設定"
                             : (r == 0 ? "RA なし(このリンクにはルータが居ない)"
                                       : "RS の送信に失敗"));
        if (ni->ip6_global_set) {
            uart_printf("slaac: %-10s addr=", ni->name);
            for (unsigned j = 0; j < 8u; j++) {
                uart_printf("%s%02x%02x", (j ? ":" : ""),
                            ni->ip6_global[j * 2u], ni->ip6_global[j * 2u + 1u]);
            }
            uart_printf("/%u (%s, DAD=%s)\n", ni->ip6_prefix_len,
                        ni->ip6_global_from_ra ? "SLAAC" : "手動",
                        ni->ip6_global_dad == NETIF_DAD_PASSED ? "衝突なし"
                            : (ni->ip6_global_dad == NETIF_DAD_CONFLICT ? "衝突" : "未実施"));
        }
        if (ni->gateway6_set) {
            uart_printf("slaac: %-10s router=", ni->name);
            for (unsigned j = 0; j < 8u; j++) {
                uart_printf("%s%02x%02x", (j ? ":" : ""),
                            ni->gateway6[j * 2u], ni->gateway6[j * 2u + 1u]);
            }
            uart_printf(" (%s)\n", ni->gateway6_from_ra ? "RA 由来" : "手動");
        }
        if (ni->ra_link_mtu) {
            uart_printf("slaac: %-10s RA の MTU オプション=%u(記録のみ。mss_cap=%u は"
                        "変えない)\n", ni->name, (unsigned)ni->ra_link_mtu, ni->mss_cap);
        }
    }
    if (prev) netif_activate(prev);
}

/*=================================================================
 * シェルの `slaactest`。B1(RS/RA + SLAAC)の検証。
 *
 * **このリンクには RA を出すルータが居ない**ので、対向 PF にルータ役をさせて
 * RA を注入する(pmtutest と同じ)。B1 の実装範囲は「RS を出し、RA を解釈して
 * アドレスとデフォルトルータを設定する」側なので、注入側がテストコードでも
 * 検証の意味は失われない。ただし**注入する RA の形式そのものが自作**なので、
 * `dump` を付けて `tools/ra_check` に読ませること。
 *
 * 陰性対照(A フラグ無し / prefix_len != 64 / hop limit != 255)を必ず組で
 * 見る。「アドレスが設定された」だけを見ても、何でも受け入れる実装と区別が
 * つかない。
 *
 * 引数:
 *   args - "dump" で 16 進出力を有効化
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_slaactest(char *args)
{
    while (*args == ' ') args++;
    s_ra_dump = (strncmp(args, "dump", 4) == 0);

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("slaactest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint8_t self_ll[16];
    ipv6_link_local_addr(self_ll);
    uint8_t self_mac[6];
    for (unsigned i = 0; i < 6u; i++) self_mac[i] = self->mac[i];

    /* テスト用プレフィックス 2001:db8:0:7::/64(ドキュメント用アドレス)。 */
    uint8_t prefix[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x07,
                           0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t want[16];
    for (unsigned i = 0; i < 8u; i++)  want[i] = prefix[i];
    for (unsigned i = 8u; i < 16u; i++) want[i] = self_ll[i];

    /* 元の状態を控えて最後に戻す。 */
    const uint8_t  save_gw_set  = self->gateway6_set;
    const uint8_t  save_gw_ra   = self->gateway6_from_ra;
    const uint64_t save_gw_till = self->gateway6_valid_until;
    uint8_t save_gw[16];
    for (unsigned i = 0; i < 16u; i++) save_gw[i] = self->gateway6[i];
    const uint16_t save_mss = self->mss_cap;
    const uint16_t save_mtu = self->mtu;
    /* **peer 側のデフォルトルータも一旦外す。** [6] は peer をクライアントに
     * するので、peer に(外部の RA などで)ゲートウェイが残っていると
     * サブネット外宛として L2 をルータへ向けてしまい、実データが届かない。
     * 実機でこれを踏んだ -- Pi5 から RA を受けた直後に slaactest を回すと
     * [6] だけが Destination Unreachable で落ちる。 */
    const uint8_t  save_pgw_set  = peer->gateway6_set;
    const uint8_t  save_pgw_ra   = peer->gateway6_from_ra;
    const uint64_t save_pgw_till = peer->gateway6_valid_until;

    int ok = 1;
    shell_clear_global6(self);
    self->gateway6_set = 0; self->gateway6_from_ra = 0; self->gateway6_valid_until = 0;
    self->ra_link_mtu = 0;
    peer->gateway6_set = 0; peer->gateway6_from_ra = 0; peer->gateway6_valid_until = 0;

    uart_printf("slaactest: self=%s peer(ルータ役)=%s\n", self->name, peer->name);

    /* ---- [1] 初期状態 ---- */
    if (self->ip6_global_set || self->gateway6_set) {
        uart_printf("slaactest: NG [1] 初期化したのに設定が残っている\n");
        ok = 0;
    } else {
        uart_printf("slaactest: OK [1] 初期状態 -- グローバルアドレス/ルータとも未設定\n");
    }

    /* ---- [2] RS を出せること ----
     * ここで見るのは「送信できること」だけ。**外部にルータが居るかどうかで
     * 判定を変えてはいけない** -- Pi5 で `send_ra.py ... listen`(ルータ役)を
     * 動かしたまま回すと本物の RA が返ってくる。実機でこれを踏んだので、
     * 「RA が来ないこと」を条件にせず、来たら状態を消してから先へ進む。 */
    int rs = ipv6_slaac_solicit(self, 1u, 100u);
    netif_activate(self);
    uart_printf("slaactest: %s [2] RS 送信 -> %s\n", (rs >= 0) ? "OK" : "NG",
                rs == 0 ? "RA なし(このリンクにルータは居ない)"
                        : (rs == 1 ? "RA あり(外部にルータが居る。以降は注入で検証する)"
                                   : "送信失敗"));
    if (rs < 0) ok = 0;
    shell_clear_global6(self);
    self->gateway6_set = 0; self->gateway6_from_ra = 0; self->gateway6_valid_until = 0;
    self->ra_link_mtu = 0;

    /* ---- [3] RA を注入 -> プレフィックス + EUI-64 のアドレスが生える ---- */
    netif_activate(peer);
    int inj = shell_inject_ra(self_ll, self_mac, prefix, 64u,
                              PIO_FLAG_ONLINK | PIO_FLAG_AUTO,
                              1800u, 900u, 1800u, 9000u, 255u);
    netif_activate(self);
    shell_poll_ms(200u);

    int addr_ok = self->ip6_global_set && self->ip6_global_from_ra &&
                  self->ip6_prefix_len == 64u;
    for (unsigned i = 0; addr_ok && i < 16u; i++) {
        if (self->ip6_global[i] != want[i]) addr_ok = 0;
    }
    uart_printf("slaactest: %s [3] RA -> addr=", (inj == 0 && addr_ok) ? "OK" : "NG");
    for (unsigned j = 0; j < 8u; j++) {
        uart_printf("%s%02x%02x", (j ? ":" : ""),
                    self->ip6_global[j * 2u], self->ip6_global[j * 2u + 1u]);
    }
    uart_printf("(期待 2001:0db8:0000:0007: + EUI-64)\n");
    if (inj != 0 || !addr_ok) ok = 0;

    /* ---- [4] デフォルトルータが RA の送信元になる ---- */
    int gw_ok = self->gateway6_set && self->gateway6_from_ra;
    for (unsigned i = 0; gw_ok && i < 16u; i++) {
        if (self->gateway6[i] != peer_ll[i]) gw_ok = 0;
    }
    uart_printf("slaactest: %s [4] デフォルトルータ = RA の送信元リンクローカル\n",
                gw_ok ? "OK" : "NG");
    if (!gw_ok) ok = 0;

    /* ---- [5] MTU オプションは記録するだけで適用しない ---- */
    int mtu_ok = (self->ra_link_mtu == 9000u) && (self->mss_cap == save_mss) &&
                 (self->mtu == save_mtu);
    uart_printf("slaactest: %s [5] MTU オプション=%u を記録(mss_cap=%u/mtu=%u は不変)\n",
                mtu_ok ? "OK" : "NG", (unsigned)self->ra_link_mtu,
                self->mss_cap, self->mtu);
    if (!mtu_ok) ok = 0;

    /* ---- [6] そのアドレスで実データが通る ----
     * peer(クライアント、リンクローカル)-> self(サーバ、SLAAC アドレス)で
     * 64KB を往復させる。**アドレスを名乗るだけでなく、受信の振り分け
     * (ipv6_addr_is_ours / netif_find_by_ip6)まで通ることを確認する。** */
    {
        netaddr_t dst = netaddr_v6(self->ip6_global);
        int echo = shell_tcp_echo_once("slaactest", peer, self, &dst, 6005u, NULL);
        uart_printf("slaactest: %s [6] SLAAC アドレス宛に 64KB 往復\n", echo ? "OK" : "NG");
        if (!echo) ok = 0;
        netif_activate(self);
    }

    /* ---- [7] 2 時間ルール: 既存アドレスの寿命は縮められない ---- */
    netif_activate(peer);
    shell_inject_ra(self_ll, self_mac, prefix, 64u, PIO_FLAG_ONLINK | PIO_FLAG_AUTO,
                    1u, 1u, 1800u, 0u, 255u);
    netif_activate(self);
    shell_poll_ms(200u);
    shell_poll_ms(1300u);          /* valid=1 が効いていれば、ここで消える */
    ipv6_slaac_age(self);
    uart_printf("slaactest: %s [7] valid=1s の RA で既存アドレスは縮まない"
                "(RFC 4862 の 2 時間ルール)\n", self->ip6_global_set ? "OK" : "NG");
    if (!self->ip6_global_set) ok = 0;

    /* ---- [8] 有効期間の満了で解除される(新規アドレスには 2 時間ルールが
     *          適用されないので、一度解除してから短い寿命で作り直す)---- */
    shell_clear_global6(self);
    netif_activate(peer);
    shell_inject_ra(self_ll, self_mac, prefix, 64u, PIO_FLAG_ONLINK | PIO_FLAG_AUTO,
                    1u, 1u, 1800u, 0u, 255u);
    netif_activate(self);
    shell_poll_ms(200u);
    int born = self->ip6_global_set;
    shell_poll_ms(1300u);
    ipv6_slaac_age(self);
    uart_printf("slaactest: %s [8] valid=1s で作り直すと 1 秒後に解除される"
                "(設定=%d -> 解除後=%d)\n",
                (born && !self->ip6_global_set) ? "OK" : "NG",
                born, self->ip6_global_set);
    if (!born || self->ip6_global_set) ok = 0;

    /* ---- [9] 陰性対照: A フラグ無し ---- */
    shell_clear_global6(self);
    netif_activate(peer);
    shell_inject_ra(self_ll, self_mac, prefix, 64u, PIO_FLAG_ONLINK,
                    1800u, 900u, 1800u, 0u, 255u);
    netif_activate(self);
    shell_poll_ms(200u);
    uart_printf("slaactest: %s [9] 陰性対照 -- A フラグ無しの prefix では設定しない\n",
                self->ip6_global_set ? "NG" : "OK");
    if (self->ip6_global_set) ok = 0;

    /* ---- [10] 陰性対照: prefix_len != 64(EUI-64 と合わせて 128 にならない)----
     * **プレフィックス長より下のビットは 0 でなければならない**(RFC 4861 4.6.2)
     * ので、/64 用のプレフィックスを長さだけ 48 にして使い回してはいけない。
     * 陰性対照は「試したい性質以外は正しい」形にする -- そうしないと、実装が
     * どちらの理由で捨てたのか区別できない(`tools/ra_check` がこの違反を
     * 検出したので気付いた)。 */
    {
        uint8_t prefix48[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0 };
        shell_clear_global6(self);
        netif_activate(peer);
        shell_inject_ra(self_ll, self_mac, prefix48, 48u, PIO_FLAG_ONLINK | PIO_FLAG_AUTO,
                        1800u, 900u, 1800u, 0u, 255u);
    }
    netif_activate(self);
    shell_poll_ms(200u);
    uart_printf("slaactest: %s [10] 陰性対照 -- prefix_len=48 は無視する\n",
                self->ip6_global_set ? "NG" : "OK");
    if (self->ip6_global_set) ok = 0;

    /* ---- [11] 陰性対照: hop limit != 255(リンク外からの RA)----
     * **これが効いていないと、リンク外のノードが経路とプレフィックスを
     * 注入できる**(RFC 4861 6.1.2 が 255 を要求する理由)。 */
    shell_clear_global6(self);
    netif_activate(peer);
    shell_inject_ra(self_ll, self_mac, prefix, 64u, PIO_FLAG_ONLINK | PIO_FLAG_AUTO,
                    1800u, 900u, 1800u, 0u, 64u);
    netif_activate(self);
    shell_poll_ms(200u);
    uart_printf("slaactest: %s [11] 陰性対照 -- hop limit=64 の RA は破棄する\n",
                self->ip6_global_set ? "NG" : "OK");
    if (self->ip6_global_set) ok = 0;

    /* ---- [12] ルータ寿命 0 でデフォルトルータから外れる ---- */
    netif_activate(peer);
    shell_inject_ra(self_ll, self_mac, prefix, 64u, PIO_FLAG_ONLINK | PIO_FLAG_AUTO,
                    1800u, 900u, 0u, 0u, 255u);
    netif_activate(self);
    shell_poll_ms(200u);
    uart_printf("slaactest: %s [12] router_lifetime=0 でデフォルトルータが外れる\n",
                self->gateway6_set ? "NG" : "OK");
    if (self->gateway6_set) ok = 0;

    /* ---- [13] 後始末 ---- */
    shell_clear_global6(self);
    self->ra_link_mtu = 0;
    self->gateway6_set         = save_gw_set;
    self->gateway6_from_ra     = save_gw_ra;
    self->gateway6_valid_until = save_gw_till;
    for (unsigned i = 0; i < 16u; i++) self->gateway6[i] = save_gw[i];
    peer->gateway6_set         = save_pgw_set;
    peer->gateway6_from_ra     = save_pgw_ra;
    peer->gateway6_valid_until = save_pgw_till;
    netif_activate(self);
    s_ra_dump = 0;

    uart_printf("slaactest: %s(グローバルアドレスと RA 由来のルータは"
                "解除しました)\n", ok ? "PASS" : "NG");
}

/*=================================================================
 * IPv6 アドレスの文字列を 16 バイトへ変換する。**RFC 4291 の完全表記
 * (8 グループ)のみ**受け付け、`::` の省略記法は展開しない
 * (nvmet.c の IPv6 表記と同じ方針)。
 *
 * 引数:
 *   s   - "2001:0db8:0000:0009:0000:0000:0000:0020" のような文字列
 *   out - 16 バイトの格納先
 * 戻り値:
 *   1=解析できた、0=書式不正
 * コール元:
 *   shell_dispatch()(ip6addr / udp6send)
 * ===============================================================*/
static int shell_parse_ip6(const char *s, uint8_t out[16])
{
    unsigned gi = 0, v = 0, ndig = 0;
    for (;; s++) {
        if (*s == ':' || *s == 0) {
            if (ndig == 0 || gi >= 8u) return 0;
            out[gi * 2u] = (uint8_t)(v >> 8); out[gi * 2u + 1u] = (uint8_t)v;
            gi++; v = 0; ndig = 0;
            if (*s == 0) break;
        } else {
            unsigned d;
            if (*s >= '0' && *s <= '9')      d = (unsigned)(*s - '0');
            else if (*s >= 'a' && *s <= 'f') d = (unsigned)(*s - 'a') + 10u;
            else if (*s >= 'A' && *s <= 'F') d = (unsigned)(*s - 'A') + 10u;
            else return 0;
            v = (v << 4) | d; ndig++;
            if (ndig > 4u) return 0;
        }
    }
    return (gi == 8u);
}

/*=================================================================
 * シェルの `udp6send <addr> <port> <bytes>`。指定した IPv6 宛へ UDP を
 * 1 個送る。**リンク MTU を超える長さを指定すると送信側の断片化が走る**ので、
 * 外部ホスト(Linux)に再構成させて B4 を確かめるのに使う。
 *
 * データは `(i * 31 + 7) & 0xff` で埋める(`tools/udp6_echo.py` が同じ式で
 * 検算する)。
 *
 * 引数:
 *   args - "<addr> <port> <bytes>"
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_udp6send(char *args)
{
    char tok[3][80];
    unsigned nt = 0;
    const char *q = args;
    while (*q && nt < 3u) {
        while (*q == ' ') q++;
        if (!*q) break;
        unsigned k = 0;
        while (*q && *q != ' ' && k < 79u) tok[nt][k++] = *q++;
        tok[nt][k] = 0;
        nt++;
    }
    if (nt < 3u) {
        uart_printf("udp6send: 使い方 udp6send <完全表記のIPv6> <port> <bytes>\n"
                    "  例: udp6send 2001:0db8:0000:0009:0000:0000:0000:0020 7780 9300\n");
        return;
    }

    uint8_t dst[16];
    if (!shell_parse_ip6(tok[0], dst)) {
        uart_printf("udp6send: アドレスは完全表記(8 グループ)で指定してください\n");
        return;
    }
    uint16_t port  = (uint16_t)atoi(tok[1]);
    unsigned bytes = (unsigned)atoi(tok[2]);
    if (bytes > 10000u) bytes = 10000u;

    uint8_t mac[6];
    netaddr_t d6 = netaddr_v6(dst);
    if (net_resolve_mac(&d6, mac) != 0) {
        uart_printf("udp6send: 宛先 MAC を解決できません(NDP 失敗)\n");
        return;
    }

    static uint8_t buf[10000];
    for (unsigned i = 0; i < bytes; i++) buf[i] = (uint8_t)(i * 31u + 7u);

    int r = udp_send6(dst, mac, port, port, buf, (uint16_t)bytes);
    uart_printf("udp6send: %u バイトを :%u へ送信 -> %s(リンク MTU=%u なので"
                "%s)\n", bytes, port, (r == 0) ? "OK" : "失敗", net_active_ip_mtu(),
                ((unsigned)(bytes + 8u + 40u) > net_active_ip_mtu())
                    ? "断片化される" : "断片化されない");
}

/* ---- ext6test: IPv6 拡張ヘッダの走査と送信側の断片化 ---- */

#define EXT6_MAX_FRAGS 16u
static struct { uint16_t off; uint16_t len; int more; uint32_t id; uint8_t nh; }
    s_ext6_seen[EXT6_MAX_FRAGS];
static unsigned s_ext6_count;
static unsigned s_ext6_overflow;
static uint8_t  s_ext6_reasm[32768];
static uint8_t  s_ext6_dump;

/*=================================================================
 * 受信 IPv6 断片の観測フック。**受信側の再構成は実装していない**ので、
 * 送信側の断片化はここでしか確かめられない(`fragtest` の IPv4 版と同じ)。
 *
 * コール元:
 *   ipv6_skip_ext_headers() から関数ポインタ経由
 * ===============================================================*/
static void shell_ext6_frag_observer(uint32_t id, uint16_t frag_off, int more,
                                      uint8_t next_header, const uint8_t *payload,
                                      uint16_t len)
{
    if (s_ext6_count >= EXT6_MAX_FRAGS) { s_ext6_overflow++; return; }
    s_ext6_seen[s_ext6_count].off  = frag_off;
    s_ext6_seen[s_ext6_count].len  = len;
    s_ext6_seen[s_ext6_count].more = more;
    s_ext6_seen[s_ext6_count].id   = id;
    s_ext6_seen[s_ext6_count].nh   = next_header;
    s_ext6_count++;

    if ((uint32_t)frag_off + len <= sizeof(s_ext6_reasm)) {
        for (uint16_t i = 0; i < len; i++) s_ext6_reasm[frag_off + i] = payload[i];
    }
    if (s_ext6_dump) {
        uart_printf("IP6FRAG id=%u off=%u more=%d nh=%u len=%u\n",
                    (unsigned)id, frag_off, more, next_header, len);
    }
}

/* ext6test が注入する拡張ヘッダの種類。 */
#define EXT6_KIND_HBH        0   /* Hop-by-Hop(PadN のみ)*/
#define EXT6_KIND_DSTOPTS    1   /* Destination Options(PadN のみ)*/
#define EXT6_KIND_RT_SEG0    2   /* Routing、segments_left=0(読み飛ばす)*/
#define EXT6_KIND_RT_SEG1    3   /* Routing、segments_left=1(破棄すべき)*/
#define EXT6_KIND_BAD_TLV    4   /* 未知オプション、上位 2bit=01(破棄すべき)*/
#define EXT6_KIND_FRAGMENT   5   /* Fragment ヘッダ(破棄すべき)*/

/*=================================================================
 * 拡張ヘッダを 1 つ付けた UDP over IPv6 を 1 個組み立てて送る。
 *
 * **チェックサムの疑似ヘッダに入れるのは UDP の長さと next header=17** で、
 * 拡張ヘッダは含めない(MLD の Router Alert と同じ落とし穴)。IPv6 ヘッダの
 * next_header と、疑似ヘッダの next header は別物。
 *
 * 引数:
 *   to / to_mac - 送り先
 *   kind        - EXT6_KIND_*
 *   port        - UDP の送信元/宛先ポート
 *   body / blen - UDP ペイロード
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_ext6test()
 * ===============================================================*/
static int shell_inject_ext6(const uint8_t to[16], const uint8_t to_mac[6],
                              int kind, uint16_t port,
                              const uint8_t *body, uint16_t blen)
{
    uint8_t src[16];
    ipv6_link_local_addr(src);

    /* UDP データグラム(ヘッダ 8 + 本体)。 */
    static uint8_t udp[256];
    uint16_t ulen = (uint16_t)(8u + blen);
    if (ulen > sizeof(udp)) return -1;
    for (unsigned i = 0; i < ulen; i++) udp[i] = 0;
    wr16be(udp + 0, port);
    wr16be(udp + 2, port);
    wr16be(udp + 4, ulen);
    for (uint16_t i = 0; i < blen; i++) udp[8u + i] = body[i];
    wr16be(udp + 6, ipv6_pseudo_checksum(src, to, IPV6_NH_UDP, udp, ulen));

    /* 拡張ヘッダ 8 バイト。 */
    uint8_t ext[8];
    uint8_t ext_nh;
    for (unsigned i = 0; i < 8u; i++) ext[i] = 0;
    switch (kind) {
    case EXT6_KIND_HBH:
    case EXT6_KIND_DSTOPTS:
        ext_nh = (kind == EXT6_KIND_HBH) ? IPV6_NH_HOPOPTS : IPV6_NH_DSTOPTS;
        ext[0] = IPV6_NH_UDP; ext[1] = 0;
        ext[2] = IPV6_TLV_PADN; ext[3] = 4;   /* PadN で 8 バイトへ揃える */
        break;
    case EXT6_KIND_RT_SEG0:
    case EXT6_KIND_RT_SEG1:
        ext_nh = IPV6_NH_ROUTING;
        ext[0] = IPV6_NH_UDP; ext[1] = 0;
        ext[2] = 0;                                        /* routing type 0 */
        ext[3] = (kind == EXT6_KIND_RT_SEG1) ? 1u : 0u;    /* segments left */
        break;
    case EXT6_KIND_BAD_TLV:
        ext_nh = IPV6_NH_DSTOPTS;
        ext[0] = IPV6_NH_UDP; ext[1] = 0;
        ext[2] = 0x41u;   /* 上位 2bit=01 = 「破棄せよ」、未知の type */
        ext[3] = 4;
        break;
    case EXT6_KIND_FRAGMENT:
    default:
        ext_nh = IPV6_NH_FRAGMENT;
        ext[0] = IPV6_NH_UDP; ext[1] = 0;
        wr16be(ext + 2, IPV6_FRAG_MORE);   /* offset=0、More=1 */
        wr32be(ext + 4, 0xABCD1234u);
        break;
    }

    if (s_ext6_dump) {
        uart_printf("EXT6DUMP kind=%d nh=%u len=8", kind, ext_nh);
        for (unsigned i = 0; i < 8u; i++) uart_printf(" %02x", ext[i]);
        uart_printf("\n");
    }

    net_buf_t *nb = net_buf_alloc();
    if (!nb) return -1;
    ipv6_build_header(nb->data, src, to, to_mac, ext_nh, (uint16_t)(8u + ulen));
    uint8_t *p = nb->data + ETH_HDR_LEN + IPV6_HDR_LEN;
    for (unsigned i = 0; i < 8u; i++) p[i] = ext[i];
    for (uint16_t i = 0; i < ulen; i++) p[8u + i] = udp[i];
    nb->len = (uint16_t)(ETH_HDR_LEN + IPV6_HDR_LEN + 8u + ulen);
    return eth_send(nb);
}

/*=================================================================
 * シェルの `ext6test`。B4(IPv6 拡張ヘッダ / フラグメント)の検証。
 *
 * 受信側のチェーン走査は B2(MLD)の前提として先に入れたもので、**Linux
 * ブリッジが出す Hop-by-Hop 付きの MLD Query を処理できている**ことで実
 * パケットでの確認は済んでいる。ここで確かめるのは、
 *   - Hop-by-Hop 以外(Destination Options / Routing)も辿れること
 *   - **Routing の segments_left != 0 は破棄する**こと(RFC 8200 4.4。
 *     一律に読み飛ばすと廃止された Routing Type 0 を受け入れてしまう)
 *   - **未知オプションの上位 2bit が「破棄」なら破棄する**こと(同 4.2)
 *   - Fragment ヘッダ付きは破棄すること
 *   - **送信側の断片化**(B4 の本体。IPv6 は経路上で分割されないので、
 *     MTU 超のデータグラムは送信元が割るしかない)
 *
 * 引数:
 *   args - "dump" で 16 進/断片情報も出す(tools/ip6_ext_check 用)
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_ext6test(char *args)
{
    while (*args == ' ') args++;
    s_ext6_dump = (strncmp(args, "dump", 4) == 0);

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("ext6test: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint8_t self_ll[16], self_mac[6], peer_mac[6];
    ipv6_link_local_addr(self_ll);
    for (unsigned i = 0; i < 6u; i++) self_mac[i] = self->mac[i];
    for (unsigned i = 0; i < 6u; i++) peer_mac[i] = peer->mac[i];

    const uint16_t port = 7779u;
    int ok = 1;
    if (udp_bind(port, shell_udptest_handler) != 0) {
        uart_printf("ext6test: udp_bind 失敗\n");
        return;
    }

    static uint8_t body[32];
    for (unsigned i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(0xA0u + i);

    /* ---- [1]〜[5] 受信側: 拡張ヘッダ付きのパケットを注入する ---- */
    static const struct { int kind; int expect_deliver; const char *name; } cases[] = {
        { EXT6_KIND_HBH,      1, "[1] Hop-by-Hop 付き -- 上位へ届く" },
        { EXT6_KIND_DSTOPTS,  1, "[2] Destination Options 付き -- 上位へ届く" },
        { EXT6_KIND_RT_SEG0,  1, "[3] Routing(segments_left=0)-- 読み飛ばして届く" },
        { EXT6_KIND_RT_SEG1,  0, "[4] 陰性対照 -- Routing(segments_left=1)は破棄" },
        { EXT6_KIND_BAD_TLV,  0, "[5] 陰性対照 -- 未知オプション(破棄指示)は破棄" },
    };
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        uint32_t before = s_udptest_rx;
        netif_activate(peer);
        int inj = shell_inject_ext6(self_ll, self_mac, cases[c].kind, port,
                                    body, (uint16_t)sizeof(body));
        netif_activate(self);
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 150u); ) net_poll_all_and_dispatch();
        netif_activate(self);
        int got = (s_udptest_rx != before);
        int len_ok = !got || (s_udptest_len == (uint16_t)sizeof(body));
        int good = (inj == 0) && (got == cases[c].expect_deliver) && len_ok;
        uart_printf("ext6test: %s %s(受信=%d 期待=%d%s)\n", good ? "OK" : "NG",
                    cases[c].name, got, cases[c].expect_deliver,
                    got ? (len_ok ? " 長さ一致" : " **長さ不一致**") : "");
        if (!good) ok = 0;
    }

    /* ---- [6] Fragment ヘッダ付きは破棄され、観測フックには届く ---- */
    s_ext6_count = 0; s_ext6_overflow = 0;
    ipv6_set_frag_observer(shell_ext6_frag_observer);
    {
        uint32_t before = s_udptest_rx;
        netif_activate(peer);
        shell_inject_ext6(self_ll, self_mac, EXT6_KIND_FRAGMENT, port,
                          body, (uint16_t)sizeof(body));
        netif_activate(self);
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 150u); ) net_poll_all_and_dispatch();
        netif_activate(self);
        int delivered = (s_udptest_rx != before);
        int good = (!delivered) && (s_ext6_count == 1u) &&
                   (s_ext6_seen[0].id == 0xABCD1234u) && (s_ext6_seen[0].more == 1) &&
                   (s_ext6_seen[0].off == 0u) && (s_ext6_seen[0].nh == IPV6_NH_UDP);
        uart_printf("ext6test: %s [6] Fragment 付きは上位へ渡さない(受信=%d)、"
                    "断片として観測できる(%u 個 / id=0x%08x more=%d nh=%u)\n",
                    good ? "OK" : "NG", delivered, s_ext6_count,
                    s_ext6_count ? (unsigned)s_ext6_seen[0].id : 0u,
                    s_ext6_count ? s_ext6_seen[0].more : -1,
                    s_ext6_count ? s_ext6_seen[0].nh : 0u);
        if (!good) ok = 0;
    }

    /* ---- [7] 送信側の断片化 ----
     * **PMTU を下げてから送る。** リンク MTU(9256)のままだと 1 断片に
     * 9208 バイト載るので、`udp_send6` のバッファ上限(NET_BUF_SIZE)では
     * 中間断片(MF=1 かつ offset 非 0)を作れない。A5/A6 で学習した PMTU が
     * そのまま分割に効くことの確認も兼ねる。 */
    const uint16_t test_mtu = 1400u;
    netaddr_t peer6 = netaddr_v6(peer_ll);
    pmtu_clear();
    pmtu_learn(&peer6, test_mtu);
    {
        static uint8_t big[4000];
        for (unsigned i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 31u + 7u);

        s_ext6_count = 0; s_ext6_overflow = 0;
        for (unsigned i = 0; i < sizeof(s_ext6_reasm); i++) s_ext6_reasm[i] = 0;

        netif_activate(self);
        int sent = udp_send6(peer_ll, peer_mac, port, port, big, (uint16_t)sizeof(big));
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 300u); ) net_poll_all_and_dispatch();
        netif_activate(self);

        /* chunk = (1400 - 40 - 8) & ~7 = 1352。UDP ヘッダ 8 + 4000 = 4008 なので
         * 1352 + 1352 + 1304 の 3 断片。 */
        uint16_t want_chunk = (uint16_t)((test_mtu - 40u - 8u) & ~7u);
        int has_middle = 0;
        for (unsigned i = 0; i < s_ext6_count; i++) {
            if (s_ext6_seen[i].more && s_ext6_seen[i].off != 0u) has_middle = 1;
        }
        /* 再構成した UDP データグラムがバイト一致するか(先頭 8 バイトは
         * UDP ヘッダなので、その後ろを比べる)。 */
        unsigned bad = 0, first_bad = 0;
        for (unsigned i = 0; i < sizeof(big); i++) {
            if (s_ext6_reasm[8u + i] != big[i]) {
                if (bad == 0u) first_bad = i;
                bad++;
            }
        }
        int match = (s_ext6_count == 3u) && (bad == 0u);
        if (bad) {
            uart_printf("ext6test:   不一致 %u バイト、最初は i=%u:", bad, first_bad);
            for (unsigned k = 0; k < 8u && first_bad + k < sizeof(big); k++) {
                uart_printf(" %02x/%02x", s_ext6_reasm[8u + first_bad + k],
                            big[first_bad + k]);
            }
            uart_printf(" (受信/期待)\n");
        }
        int good = (sent == 0) && (s_ext6_count == 3u) && !s_ext6_overflow &&
                   (s_ext6_seen[0].len == want_chunk) && has_middle && match &&
                   (s_ext6_seen[0].nh == IPV6_NH_UDP);
        uart_printf("ext6test: %s [7] PMTU=%u で UDP 4000B を送信 -- 断片 %u 個 / "
                    "先頭 %u バイト(期待 3 個 / %u)/ 中間断片=%d / 再構成一致=%d\n",
                    good ? "OK" : "NG", test_mtu, s_ext6_count,
                    s_ext6_count ? s_ext6_seen[0].len : 0u, want_chunk, has_middle, match);
        if (!good) ok = 0;
    }

    /* ---- [8] 陰性対照: MTU 以下は分割しない ---- */
    {
        static uint8_t small[512];
        for (unsigned i = 0; i < sizeof(small); i++) small[i] = (uint8_t)i;
        s_ext6_count = 0;
        uint32_t before = s_udptest_rx;
        netif_activate(self);
        udp_send6(peer_ll, peer_mac, port, port, small, (uint16_t)sizeof(small));
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
        netif_activate(self);
        int delivered = (s_udptest_rx != before);
        uart_printf("ext6test: %s [8] 陰性対照 -- PMTU 以下(512B)は分割せず"
                    "そのまま届く(断片 %u 個 / 受信=%d)\n",
                    (s_ext6_count == 0u && delivered) ? "OK" : "NG",
                    s_ext6_count, delivered);
        if (s_ext6_count != 0u || !delivered) ok = 0;
    }

    ipv6_set_frag_observer(NULL);
    pmtu_clear();
    udp_unbind(port);
    netif_activate(self);
    s_ext6_dump = 0;
    uart_printf("ext6test: %s(PMTU キャッシュはクリアしました)\n", ok ? "PASS" : "NG");
}

/* ---- nudtest: 到達不能検出(DELAY / ユニキャスト probe / 上位層の確認)---- */

static unsigned s_nud_uni;      /* 観測したユニキャストの確認要求 */
static unsigned s_nud_multi;    /* 観測したブロードキャスト/マルチキャストの要求 */
static unsigned s_nud_other;    /* 対向(サーバ役)側から出た確認要求 */
static uint8_t  s_nud_last_mac[6];
static netif_t *s_nud_self;     /* どちらのインターフェースの送信かを見分ける */

/*=================================================================
 * 確認要求の観測フック。**ユニキャストで出ているか**はここか相手側でしか
 * 見えない(送信後のフレームは誰も保持しない)。
 *
 * コール元:
 *   neigh_probe_notify() から関数ポインタ経由
 * ===============================================================*/
static void shell_nud_observer(int is_v6, int is_unicast, const uint8_t dst_mac[6])
{
    (void)is_v6;
    /* **どちらのインターフェースが出した確認要求か**を分ける。TCP の往復では
     * サーバ役(対向 PF)も送信するが、**データを受け取るだけの側には上位層の
     * 到達確認が存在しない**(相手が自分のデータを受け取った証拠が無い)ので、
     * そちらが確認要求を出すのは正しい動作。検証したいのは送信側。 */
    uart_printf("nudtest:   [観測] %s の確認要求 %s -> %02x:%02x:%02x:%02x:%02x:%02x (%s)\n",
                is_v6 ? "IPv6" : "IPv4", is_unicast ? "ユニキャスト" : "ブロードキャスト",
                dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                g_active_ctx ? g_active_ctx->name : "?");
    if (s_nud_self && g_active_ctx != s_nud_self) {
        s_nud_other++;
        return;
    }
    if (is_unicast) s_nud_uni++; else s_nud_multi++;
    for (unsigned i = 0; i < 6u; i++) s_nud_last_mac[i] = dst_mac[i];
}

/*=================================================================
 * Neighbor Advertisement を 1 個組み立てて送る。**フラグ(Solicited /
 * Override)を自由に振れる**ことが要点で、これが無いと RFC 4861 7.2.5 の
 * 「Override 無しの NA は既存の MAC を書き換えない」を確かめられない。
 *
 * 引数:
 *   to / to_mac - 送り先(NA を受け取る側)
 *   target      - NA の Target Address
 *   tgt_mac     - Target Link-Layer Address オプションに入れる MAC
 *   solicited   - S フラグ、override_flag - O フラグ
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_nudtest()
 * ===============================================================*/
static int shell_inject_na(const uint8_t to[16], const uint8_t to_mac[6],
                            const uint8_t target[16], const uint8_t tgt_mac[6],
                            int solicited, int override_flag)
{
    static uint8_t msg[8u + 16u + 8u];
    for (unsigned i = 0; i < sizeof(msg); i++) msg[i] = 0;

    msg[0] = ICMPV6_TYPE_NA;
    msg[1] = 0;
    /* msg[2..3] はチェックサム。msg[4] の上位 3 ビットが R/S/O。 */
    msg[4] = (uint8_t)((solicited ? 0x40u : 0u) | (override_flag ? 0x20u : 0u));
    for (unsigned i = 0; i < 16u; i++) msg[8u + i] = target[i];
    msg[24] = 2u;   /* Target Link-Layer Address */
    msg[25] = 1u;
    for (unsigned i = 0; i < 6u; i++) msg[26u + i] = tgt_mac[i];

    uint8_t src[16];
    ipv6_link_local_addr(src);
    wr16be(msg + 2, ipv6_pseudo_checksum(src, to, IPV6_NH_ICMPV6, msg, (uint16_t)sizeof(msg)));
    return ipv6_send(to, to_mac, IPV6_NH_ICMPV6, msg, (uint16_t)sizeof(msg));
}

/*=================================================================
 * シェルの `nudtest`。B3(到達不能検出)の検証。
 *
 * A2 で入った「失効 -> 確認 -> 延命/破棄」に対して、B3 で足したのは 3 つ:
 *   - **DELAY 相**: 失効したエントリを使った瞬間には確認要求を出さない
 *   - **ユニキャストの確認要求**: MAC を知っている相手にブロードキャストしない
 *   - **上位層の到達確認**: TCP の累積 ACK が進んだら確認要求を出さずに延命
 * 加えて **NA のフラグ解釈**(Solicited だけが到達確認、Override 無しは
 * 既存の MAC を書き換えない)。
 *
 * `arptest` と同じく TTL を一時的に縮めて実行し、**必ず元に戻す**。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_nudtest(void)
{
    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("nudtest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint8_t self_ll[16], self_mac[6];
    ipv6_link_local_addr(self_ll);
    for (unsigned i = 0; i < 6u; i++) self_mac[i] = self->mac[i];

    /* **TTL は 1200ms**。猶予(TTL/6)が 200ms あるので、失効してから
     * 「NA を注げて、状態を読み取れる」窓が十分に取れる。600ms だと猶予が
     * 100ms しかなく、注入と読み取りのあいだに破棄されて誤判定した(実機)。 */
    const uint32_t saved_ttl = g_neigh_cache_ttl_ms;
    const uint32_t ttl = 1200u;         /* 猶予=200ms、DELAY=100ms、probe 間隔=20ms */
    const uint32_t delay_ms = ttl / NEIGH_DELAY_DIVISOR;
    g_neigh_cache_ttl_ms = ttl;

    int ok = 1;
    uint8_t mac[6];
    s_nud_self = self;
    s_nud_other = 0;
    neigh_set_probe_observer(shell_nud_observer);
    uart_printf("nudtest: TTL=%ums DELAY=%ums で検証(終了時に %ums へ戻します)\n",
                ttl, delay_ms, saved_ttl);

    /* ---- 準備: 対向 PF の v4/v6 を解決し、**寿命の起点を作り直す** ----
     * **`arp_resolve()` / `ndp_resolve()` だけでは足りない。** キャッシュが
     * fresh なら何も送らずに帰るので、`expires_at` は前回入った時点の TTL の
     * ままになる。直前に `arptest`(TTL を 600ms へ変えて最後に 60000ms へ
     * 戻す)を走らせていると **60 秒先の期限が残り、この検証の待ち時間では
     * 失効しない**。実機で「nudtest 単独なら PASS、arptest の直後だけ NG」と
     * いう形で踏んだ。`*_cache_insert()` は必ず現在の TTL で入れ直す。 */
    netif_activate(self);
    if (arp_resolve(peer->ip, mac) != 0 || ndp_resolve(peer_ll, mac) != 0) {
        uart_printf("nudtest: NG -- 対向 PF の解決に失敗\n");
        neigh_set_probe_observer(NULL);
        g_neigh_cache_ttl_ms = saved_ttl;
        return;
    }
    netif_activate(self);
    arp_cache_insert(peer->ip, peer->mac);
    ndp_cache_insert(peer_ll, peer->mac);

    /* ---- [1] DELAY: 失効直後の lookup では確認要求を出さない ---- */
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, ttl + 20u); ) net_poll_all_and_dispatch();
    s_nud_uni = 0; s_nud_multi = 0;
    netif_activate(self);
    /* **「確認要求が 0 個」だけでは DELAY を確かめたことにならない** --
     * エントリがまだ fresh でも同じ結果になる。先に本当に失効しているかを
     * peek で確認する(これが無くて、fresh のまま PASS していた)。 */
    int stale4 = (arp_cache_peek(peer->ip, NULL) == 1);
    int stale6 = (ndp_cache_peek(peer_ll, NULL) == 1);
    int hit4 = (arp_cache_lookup(peer->ip, mac) == 0);
    int hit6 = (ndp_cache_lookup(peer_ll, mac) == 0);
    uart_printf("nudtest: %s [1] DELAY -- 失効済み(v4=%d v6=%d)の lookup は MAC を返し"
                "(v4=%d v6=%d)、確認要求は %u 個(期待 0)\n",
                (stale4 && stale6 && hit4 && hit6 &&
                 s_nud_uni == 0u && s_nud_multi == 0u) ? "OK" : "NG",
                stale4, stale6, hit4, hit6, s_nud_uni + s_nud_multi);
    if (!stale4 || !stale6 || !hit4 || !hit6 || s_nud_uni != 0u || s_nud_multi != 0u) ok = 0;

    /* ---- [2] DELAY 経過後はユニキャストで確認要求を出す ---- */
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, delay_ms + 20u); ) {
        net_poll_all_and_dispatch();
    }
    s_nud_uni = 0; s_nud_multi = 0;
    netif_activate(self);
    arp_cache_lookup(peer->ip, mac);
    int uni4 = s_nud_uni;
    int mac4_ok = 1;
    for (unsigned i = 0; i < 6u; i++) if (s_nud_last_mac[i] != peer->mac[i]) mac4_ok = 0;
    uart_printf("nudtest: %s [2] IPv4 の確認要求 -- ユニキャスト %u / ブロードキャスト %u、"
                "宛先 MAC が対向 PF=%d\n",
                (uni4 == 1 && s_nud_multi == 0u && mac4_ok) ? "OK" : "NG",
                s_nud_uni, s_nud_multi, mac4_ok);
    if (uni4 != 1 || s_nud_multi != 0u || !mac4_ok) ok = 0;

    s_nud_uni = 0; s_nud_multi = 0;
    netif_activate(self);
    ndp_cache_lookup(peer_ll, mac);
    int mac6_ok = 1;
    for (unsigned i = 0; i < 6u; i++) if (s_nud_last_mac[i] != peer->mac[i]) mac6_ok = 0;
    uart_printf("nudtest: %s [3] IPv6 の確認要求 -- ユニキャスト %u / マルチキャスト %u、"
                "宛先 MAC が対向 PF=%d(33:33:ff:.. ではない)\n",
                (s_nud_uni == 1u && s_nud_multi == 0u && mac6_ok) ? "OK" : "NG",
                s_nud_uni, s_nud_multi, mac6_ok);
    if (s_nud_uni != 1u || s_nud_multi != 0u || !mac6_ok) ok = 0;

    /* ---- [4] 上位層の到達確認: confirmed=1 なら確認要求を出さずに延命 ---- */
    netif_activate(self);
    arp_resolve(peer->ip, mac);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, ttl + delay_ms + 30u); ) {
        net_poll_all_and_dispatch();
    }
    netif_activate(self);
    s_nud_uni = 0; s_nud_multi = 0;
    int was_stale = (arp_cache_peek(peer->ip, NULL) == 1);
    arp_cache_lookup_nud(peer->ip, mac, 1);
    int now_fresh = (arp_cache_peek(peer->ip, NULL) == 0);
    uart_printf("nudtest: %s [4] 上位層の到達確認 -- stale(%d)から確認要求 %u 個で"
                "fresh(%d)へ戻る\n",
                (was_stale && now_fresh && s_nud_uni == 0u && s_nud_multi == 0u)
                    ? "OK" : "NG", was_stale, s_nud_uni + s_nud_multi, now_fresh);
    if (!was_stale || !now_fresh || s_nud_uni != 0u || s_nud_multi != 0u) ok = 0;

    /* ---- [5] TCP を流すと確認要求が 1 個も出ない ----
     * **TCP が到達確認フラグを立てていることの端から端までの確認。**
     * わざと失効させた状態で往復させる。 */
    /* **この段だけ TTL を伸ばす。** 猶予(TTL/6)より長い停止が往復の途中に
     * 入るとエントリが破棄され、NUD の確認要求ではなく `arp_resolve()` の
     * ブロードキャスト再解決が走る。この経路(Pi5 のブリッジ越し)では
     * **RTO による 200ms の停止が実際に起きる**ので、TTL=1200ms の猶予
     * 200ms では足りなかった(実機で踏み、原因を取り違えかけた)。 */
    const uint32_t ttl5 = 3000u;   /* 猶予 500ms > RTO 200ms */
    g_neigh_cache_ttl_ms = ttl5;
    netif_activate(self);
    /* **`arp_resolve()` では起点を作り直せない。** キャッシュが fresh なら
     * 何も送らずに帰るので、`expires_at` は前の TTL のままになる(実機で
     * 「待ったのに DEAD」になって気付いた)。`arp_cache_insert()` は必ず
     * 現在の TTL で入れ直すので、こちらを使う(`arptest` と同じ手)。 */
    arp_cache_insert(peer->ip, peer->mac);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, ttl5 + 20u); ) {
        net_poll_all_and_dispatch();
    }
    netif_activate(self);
    int stale_before = (arp_cache_peek(peer->ip, NULL) == 1);
    s_nud_uni = 0; s_nud_multi = 0; s_nud_other = 0;
    uint32_t confirm_before = g_neigh_confirm_count;
    netaddr_t peer_v4 = netaddr_v4(peer->ip);
    int echo = shell_tcp_echo_once("nudtest", self, peer, &peer_v4, 6007u, NULL);
    netif_activate(self);
    /* **往復後に fresh へ戻っていること**が上位層の確認が効いた証拠。確認要求を
     * 1 個も出していないのだから、延命できる経路は他に無い。 */
    int fresh_after = (arp_cache_peek(peer->ip, NULL) == 0);
    uint32_t confirms = g_neigh_confirm_count - confirm_before;
    /* **「確認要求が 0 個」だけでは足りない** -- DELAY 中で黙っていただけかも
     * しれない。上位層の確認が実際に適用された回数が増えていることを見る。 */
    uart_printf("nudtest: %s [5] stale(%d)のまま TCP を 64KB 往復 -- 上位層の確認 %u 回 / "
                "送信側の確認要求 %u 個(期待 0)、往復後に fresh(%d)/ 受信側 %u 個"
                "(こちらは正常 -- データを受けるだけの側に到達確認は無い)\n",
                (echo && stale_before && fresh_after && confirms > 0u &&
                 s_nud_uni == 0u && s_nud_multi == 0u) ? "OK" : "NG",
                stale_before, confirms, s_nud_uni + s_nud_multi, fresh_after, s_nud_other);
    if (!echo || !stale_before || !fresh_after || confirms == 0u ||
        s_nud_uni != 0u || s_nud_multi != 0u) {
        ok = 0;
    }
    g_neigh_cache_ttl_ms = ttl;

    /* ---- [6][7] NA のフラグ解釈(RFC 4861 7.2.5)----
     * 実在しないアドレスにエントリを仕込んで、そこへ偽の NA を投げる
     * (実際に使っているアドレスを汚さないため)。 */
    {
        uint8_t fake[16], real[6] = { 0x02, 0x00, 0x00, 0x00, 0xAA, 0xAA };
        uint8_t bogus[6] = { 0x02, 0x00, 0x00, 0x00, 0xBB, 0xBB };
        for (unsigned i = 0; i < 16u; i++) fake[i] = 0;
        fake[0] = 0xFE; fake[1] = 0x80; fake[14] = 0xDE; fake[15] = 0xAD;

        netif_activate(self);
        ndp_cache_insert(fake, real);

        /* [6] Override 無しで違う MAC を主張する NA は無視する。 */
        netif_activate(peer);
        shell_inject_na(self_ll, self_mac, fake, bogus, 1, 0);
        netif_activate(self);
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 150u); ) net_poll_all_and_dispatch();
        netif_activate(self);
        ndp_cache_lookup(fake, mac);
        int kept = 1;
        for (unsigned i = 0; i < 6u; i++) if (mac[i] != real[i]) kept = 0;
        uart_printf("nudtest: %s [6] 陰性対照 -- Override 無しの NA は既存の MAC を"
                    "書き換えない\n", kept ? "OK" : "NG");
        if (!kept) ok = 0;

        /* [7] Override 有りなら書き換わる(陽性対照)。 */
        netif_activate(peer);
        shell_inject_na(self_ll, self_mac, fake, bogus, 1, 1);
        netif_activate(self);
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 150u); ) net_poll_all_and_dispatch();
        netif_activate(self);
        ndp_cache_lookup(fake, mac);
        int changed = 1;
        for (unsigned i = 0; i < 6u; i++) if (mac[i] != bogus[i]) changed = 0;
        uart_printf("nudtest: %s [7] 陽性対照 -- Override 有りの NA は書き換える\n",
                    changed ? "OK" : "NG");
        if (!changed) ok = 0;

        /* [8] 非要請 NA(S=0)は延命しない。
         * **猶予(TTL/6 = 200ms)の中で「注入 -> 読み取り」を 2 回やる**ので、
         * 失効直後から始めて待ち時間を短く刻む。ここを雑にすると、猶予切れで
         * 破棄されたものを「延命しなかった」と誤読する(ndp_cache_peek は
         * 未登録と猶予切れをどちらも -1 で返す)。 */
        /* **起点をここで作り直す。** 直前の段の待ち時間ぶん寿命が進んでいると、
         * 猶予(TTL/6)の末尾で判定することになり「延命しなかった」と
         * 「猶予切れで破棄された」を取り違える(実機で踏んだ。
         * `ndp_cache_peek` はどちらも -1 ではなく…前者は 1、後者は -1 を返す
         * ので、== 1 の判定が静かに落ちる)。 */
        netif_activate(peer);
        shell_inject_na(self_ll, self_mac, fake, bogus, 1, 1);
        netif_activate(self);
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 30u); ) net_poll_all_and_dispatch();
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, ttl - 10u); ) {
            net_poll_all_and_dispatch();
        }
        netif_activate(self);
        int before = ndp_cache_peek(fake, NULL);
        netif_activate(peer);
        shell_inject_na(self_ll, self_mac, fake, bogus, 0, 1);
        netif_activate(self);
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 40u); ) net_poll_all_and_dispatch();
        netif_activate(self);
        int still_stale = (ndp_cache_peek(fake, NULL) == 1);
        netif_activate(peer);
        shell_inject_na(self_ll, self_mac, fake, bogus, 1, 1);
        netif_activate(self);
        for (uint64_t t0 = timer_now(); !timeout_ms(t0, 40u); ) net_poll_all_and_dispatch();
        netif_activate(self);
        int refreshed = (ndp_cache_peek(fake, NULL) == 0);
        uart_printf("nudtest: %s [8] 非要請 NA は延命せず(注入前=%d stale のまま=%d)、"
                    "solicited NA で fresh へ戻る(%d)\n",
                    (before == 1 && still_stale && refreshed) ? "OK" : "NG",
                    before, still_stale, refreshed);
        if (before != 1 || !still_stale || !refreshed) ok = 0;
    }

    neigh_set_probe_observer(NULL);
    s_nud_self = NULL;
    g_neigh_cache_ttl_ms = saved_ttl;
    netif_activate(self);
    uart_printf("nudtest: %s(TTL は %ums へ戻しました)\n", ok ? "PASS" : "NG", saved_ttl);
}

/* ---- mld / mldtest: MLD の Report 送出と Query 応答を確かめる ---- */

static uint8_t  s_mld_dump;          /* 1=送信した MLD を 16 進で出す(tools/mld_check 用) */
static unsigned s_mld_seen;          /* 観測した MLD メッセージ数 */
static uint8_t  s_mld_last[256];     /* 直近に送った MLD メッセージ */
static unsigned s_mld_last_len;
static uint8_t  s_mld_last_dst[16];

/*=================================================================
 * 送信 MLD の観測フック。ルータもスヌーピングするスイッチも居ないので、
 * 自分が何を送ったかはここでしか確かめられない(`ip_set_frag_observer()` と
 * 同じ考え方)。
 *
 * コール元:
 *   mld_send() から関数ポインタ経由
 * ===============================================================*/
static void shell_mld_observer(const uint8_t *msg, unsigned len, const uint8_t dst[16])
{
    s_mld_seen++;
    if (len > sizeof(s_mld_last)) len = sizeof(s_mld_last);
    for (unsigned i = 0; i < len; i++) s_mld_last[i] = msg[i];
    s_mld_last_len = len;
    for (unsigned i = 0; i < 16u; i++) s_mld_last_dst[i] = dst[i];

    if (s_mld_dump) {
        uart_printf("MLDDUMP len=%u", len);
        for (unsigned i = 0; i < len; i++) uart_printf(" %02x", msg[i]);
        uart_printf("\n");
    }
}

/*=================================================================
 * MLD の Query を 1 個組み立てて送る。Querier の役を対向インターフェースが
 * 務める(`pmtutest` / `slaactest` と同じ手)。
 *
 * **v1 と v2 は長さで区別される**(v1=24、v2>=28)。受信側が長さではなく
 * 別の何かで判定していれば、ここで作り分けたときに食い違って露見する。
 * Router Alert と hop limit=1 も Query 側の必須条件なので、引数で外せる
 * ようにして陰性対照に使う。
 *
 * 引数:
 *   to / to_mac  - 送り先
 *   mca          - 対象グループ(全 0 なら General Query)
 *   v2           - 1=MLDv2 Query(28 バイト)、0=MLDv1 Query(24 バイト)
 *   hop_limit    - IPv6 ヘッダの hop limit(1 以外は受信側が捨てるはず)
 *   router_alert - 0 なら Hop-by-Hop を付けない(受信側が捨てるはず)
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_mldtest()
 * ===============================================================*/
static int shell_inject_mld_query(const uint8_t to[16], const uint8_t to_mac[6],
                                   const uint8_t mca[16], int v2,
                                   uint8_t hop_limit, int router_alert)
{
    static uint8_t msg[28];
    unsigned len = v2 ? 28u : 24u;
    for (unsigned i = 0; i < sizeof(msg); i++) msg[i] = 0;

    msg[0] = ICMPV6_TYPE_MLD_QUERY;
    msg[1] = 0;
    /* msg[2..3] はチェックサム。msg[4..5] = Maximum Response Code(ms)。 */
    wr16be(msg + 4u, 1000u);
    /* msg[6..7] は reserved。msg[8..23] が Multicast Address。 */
    for (unsigned i = 0; i < 16u; i++) msg[8u + i] = mca[i];
    if (v2) {
        msg[24] = 2u;   /* QRV=2、S フラグ無し */
        msg[25] = 125u; /* QQIC */
        wr16be(msg + 26u, 0);  /* 送信元指定無し */
    }

    uint8_t src[16];
    ipv6_link_local_addr(src);
    wr16be(msg + 2, ipv6_pseudo_checksum(src, to, IPV6_NH_ICMPV6, msg, (uint16_t)len));

    if (s_mld_dump) {
        uart_printf("MLDDUMP len=%u", len);
        for (unsigned i = 0; i < len; i++) uart_printf(" %02x", msg[i]);
        uart_printf("\n");
    }

    net_buf_t *nb = net_buf_alloc();
    if (!nb) return -1;
    unsigned hbh = router_alert ? 8u : 0u;
    ipv6_build_header(nb->data, src, to, to_mac,
                      router_alert ? IPV6_NH_HOPOPTS : IPV6_NH_ICMPV6,
                      (uint16_t)(hbh + len));
    nb->data[ETH_HDR_LEN + offsetof(ipv6_header_t, hop_limit)] = hop_limit;

    uint8_t *p = nb->data + ETH_HDR_LEN + IPV6_HDR_LEN;
    if (router_alert) {
        p[0] = IPV6_NH_ICMPV6; p[1] = 0;
        p[2] = IPV6_TLV_ROUTER_ALERT; p[3] = 2; p[4] = 0; p[5] = 0;
        p[6] = IPV6_TLV_PADN;  p[7] = 0;
    }
    for (unsigned i = 0; i < len; i++) p[hbh + i] = msg[i];
    nb->len = (uint16_t)(ETH_HDR_LEN + IPV6_HDR_LEN + hbh + len);
    return eth_send(nb);
}

/*=================================================================
 * シェルの `mld`。参加グループと MLD の状態を表示する。`mld report` で
 * 非要請 Report を送る。
 *
 * 引数:
 *   args - "report" で Report を送る
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_mld(char *args)
{
    while (*args == ' ') args++;
    int do_report = (strncmp(args, "report", 6) == 0);
    /* **`mld leave` は実スイッチ配下では通信を止める。** スヌーピングする
     * スイッチが要請ノードマルチキャストの転送をやめるので、相手からの NS が
     * 届かなくなる(= B2 が効いていることの陰性対照そのもの)。戻すには
     * `mld report`。 */
    int do_leave  = (strncmp(args, "leave", 5) == 0);
    if (strncmp(args, "off", 3) == 0 || strncmp(args, "on", 2) == 0) {
        int on = (args[1] == 'n');
        ipv6_mld_set_enabled(on);
        uart_printf("mld: MLD の送信を%s(%s)\n", on ? "再開しました" : "止めました",
                    on ? "通常" : "**スヌーピングするスイッチ配下では通信が止まる。"
                                 "戻すのを忘れないこと**");
        return;
    }

    netif_t *prev = g_active_ctx;
    static const char *ifnames[] = { "mlx5-pf0", "mlx5-pf1" };
    for (unsigned i = 0; i < 2u; i++) {
        netif_t *ni = netif_find(ifnames[i]);
        if (!ni) continue;
        uint8_t groups[IPV6_MCAST_MAX][16];
        unsigned n = ipv6_mcast_groups(ni, groups, IPV6_MCAST_MAX);
        uart_printf("mld: %-10s 報告対象 %u グループ(ff02::1 は対象外)、%s%s\n",
                    ni->name, n, ipv6_mld_v1_mode() ? "v1 互換モード" : "v2",
                    ipv6_mld_enabled() ? "" : " ** 送信停止中(mld on で再開)**");
        for (unsigned k = 0; k < n; k++) {
            uart_printf("mld: %-10s   ", ni->name);
            for (unsigned j = 0; j < 8u; j++) {
                uart_printf("%s%02x%02x", (j ? ":" : ""),
                            groups[k][j * 2u], groups[k][j * 2u + 1u]);
            }
            uart_printf("\n");
        }
        if (do_report) {
            int sent = ipv6_mld_report_all(ni);
            uart_printf("mld: %-10s Report を %d 通送信\n", ni->name, sent);
        }
        if (do_leave) {
            netif_activate(ni);
            for (unsigned k = 0; k < n; k++) ipv6_mld_leave(groups[k]);
            uart_printf("mld: %-10s %u グループの離脱を通知(戻すには mld report)\n",
                        ni->name, n);
        }
    }
    if (prev) netif_activate(prev);
}

/*=================================================================
 * シェルの `mldtest`。B2(MLD)の検証。
 *
 * **このリンクには Querier が居ない**ので、対向 PF に Querier 役をさせて
 * Query を注入する。送信した Report は誰も受け取らない(ルータもスヌーピング
 * するスイッチも居ない)ので、`ipv6_set_mld_observer()` で送信直前に覗く。
 *
 * 陰性対照(hop limit != 1 / Router Alert 無し / 参加していないグループ)を
 * 必ず組で見る。「Report を送った」だけを見ても、何でも応答する実装と区別が
 * つかない。
 *
 * 引数:
 *   args - "dump" で 16 進出力(tools/mld_check 用)
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_mldtest(char *args)
{
    while (*args == ' ') args++;
    s_mld_dump = (strncmp(args, "dump", 4) == 0);

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("mldtest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    uint8_t self_ll[16], self_sol[16], self_mac[6];
    ipv6_link_local_addr(self_ll);
    ipv6_solicited_node_addr(self_ll, self_sol);
    for (unsigned i = 0; i < 6u; i++) self_mac[i] = self->mac[i];

    uint8_t any[16], other[16];
    for (unsigned i = 0; i < 16u; i++) { any[i] = 0; other[i] = 0; }
    /* 参加していないグループ(陰性対照用)。ff02::1:ff00:9999 */
    other[0] = 0xFF; other[1] = 0x02; other[11] = 0x01; other[12] = 0xFF;
    other[13] = 0x00; other[14] = 0x99; other[15] = 0x99;

    int ok = 1;
    ipv6_set_mld_observer(shell_mld_observer);

    /* ---- [1] 参加グループの列挙 ---- */
    {
        uint8_t groups[IPV6_MCAST_MAX][16];
        unsigned n = ipv6_mcast_groups(self, groups, IPV6_MCAST_MAX);
        int good = (n >= 1u);
        for (unsigned j = 0; good && j < 16u; j++) {
            if (groups[0][j] != self_sol[j]) good = 0;
        }
        /* ff02::1 が混ざっていないこと(RFC 3810 6 で報告対象外)。 */
        for (unsigned k = 0; k < n; k++) {
            if (groups[k][15] == 0x01 && groups[k][12] == 0x00) good = 0;
        }
        uart_printf("mldtest: %s [1] 報告対象は %u グループ(要請ノード。ff02::1 は含まない)\n",
                    good ? "OK" : "NG", n);
        if (!good) ok = 0;
    }

    /* ---- [2] 非要請 Report(v2)---- */
    s_mld_seen = 0; s_mld_last_len = 0;
    ipv6_mld_report_all(self);
    netif_activate(self);
    {
        /* v2 Report: type=143、レコード数は 6-7、レコードは 20 バイト。 */
        int good = (s_mld_seen == MLD_UNSOLICITED_REPORTS) &&
                   (s_mld_last_len >= 28u) &&
                   (s_mld_last[0] == ICMPV6_TYPE_MLD2_REPORT) &&
                   (s_mld_last[7] >= 1u) &&
                   (s_mld_last[8] == MLD2_CHANGE_TO_EXCLUDE) &&
                   (s_mld_last_dst[15] == 0x16);
        uart_printf("mldtest: %s [2] 非要請 Report -- %u 通 / type=%u / レコード %u 個 / "
                    "宛先 ff02::%02x\n", good ? "OK" : "NG", s_mld_seen,
                    s_mld_last[0], s_mld_last[7], s_mld_last_dst[15]);
        if (!good) ok = 0;
    }

    /* ---- [3] v2 General Query -> MODE_IS_EXCLUDE で応答 ---- */
    s_mld_seen = 0;
    netif_activate(peer);
    int inj = shell_inject_mld_query(self_ll, self_mac, any, 1, 1u, 1);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
    {
        int good = (inj == 0) && (s_mld_seen >= 1u) &&
                   (s_mld_last[0] == ICMPV6_TYPE_MLD2_REPORT) &&
                   (s_mld_last[8] == MLD2_MODE_IS_EXCLUDE);
        uart_printf("mldtest: %s [3] v2 General Query -> v2 Report(レコード種別 %u、"
                    "期待 %u=MODE_IS_EXCLUDE)\n", good ? "OK" : "NG",
                    s_mld_last[8], MLD2_MODE_IS_EXCLUDE);
        if (!good) ok = 0;
    }

    /* ---- [4] 陰性対照: hop limit != 1 の Query は無視 ---- */
    s_mld_seen = 0;
    netif_activate(peer);
    shell_inject_mld_query(self_ll, self_mac, any, 1, 64u, 1);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
    uart_printf("mldtest: %s [4] 陰性対照 -- hop limit=64 の Query は無視する\n",
                (s_mld_seen == 0u) ? "OK" : "NG");
    if (s_mld_seen != 0u) ok = 0;

    /* ---- [5] 陰性対照: Router Alert 無しの Query は無視 ---- */
    s_mld_seen = 0;
    netif_activate(peer);
    shell_inject_mld_query(self_ll, self_mac, any, 1, 1u, 0);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
    uart_printf("mldtest: %s [5] 陰性対照 -- Router Alert 無しの Query は無視する\n",
                (s_mld_seen == 0u) ? "OK" : "NG");
    if (s_mld_seen != 0u) ok = 0;

    /* ---- [6] 陰性対照: 参加していないグループ宛の Specific Query ----
     * **宛先はそのグループ**なので、自分宛と判定されるように self の
     * 要請ノードアドレス宛で送りつつ、本文のグループだけを別物にする。 */
    s_mld_seen = 0;
    netif_activate(peer);
    shell_inject_mld_query(self_sol, self_mac, other, 1, 1u, 1);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
    uart_printf("mldtest: %s [6] 陰性対照 -- 参加していないグループの Query には応答しない\n",
                (s_mld_seen == 0u) ? "OK" : "NG");
    if (s_mld_seen != 0u) ok = 0;

    /* ---- [7] Group-Specific Query -> そのグループだけ報告 ---- */
    s_mld_seen = 0;
    netif_activate(peer);
    shell_inject_mld_query(self_sol, self_mac, self_sol, 1, 1u, 1);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
    {
        int good = (s_mld_seen == 1u) && (s_mld_last[7] == 1u);
        uart_printf("mldtest: %s [7] Group-Specific Query -> %u 通 / レコード %u 個"
                    "(期待 1 通 / 1 個)\n", good ? "OK" : "NG", s_mld_seen, s_mld_last[7]);
        if (!good) ok = 0;
    }

    /* ---- [8] v1 Query(24 バイト)-> v1 互換モードへ落ちる ----
     * **Linux ブリッジの既定は `mcast_mld_version 1`** なので、実スイッチ
     * 配下ではこちらが本番の経路になる。 */
    s_mld_seen = 0;
    netif_activate(peer);
    shell_inject_mld_query(self_ll, self_mac, any, 0, 1u, 1);
    netif_activate(self);
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 200u); ) net_poll_all_and_dispatch();
    {
        /* v1 Report: type=131、24 バイト、8-23 がグループ、宛先はグループ自身。 */
        int good = (s_mld_seen >= 1u) && ipv6_mld_v1_mode() &&
                   (s_mld_last[0] == ICMPV6_TYPE_MLD_REPORT) && (s_mld_last_len == 24u);
        for (unsigned j = 0; good && j < 16u; j++) {
            if (s_mld_last[8u + j] != self_sol[j]) good = 0;
            if (s_mld_last_dst[j] != self_sol[j]) good = 0;
        }
        uart_printf("mldtest: %s [8] v1 Query -> v1 Report(type=%u len=%u、"
                    "互換モード=%d、宛先=グループ自身)\n", good ? "OK" : "NG",
                    s_mld_last[0], s_mld_last_len, ipv6_mld_v1_mode());
        if (!good) ok = 0;
    }

    /* ---- [9] v1 互換モード中の離脱は Done(type 132)---- */
    s_mld_seen = 0;
    ipv6_mld_leave(self_sol);
    {
        int good = (s_mld_seen == 1u) && (s_mld_last[0] == ICMPV6_TYPE_MLD_DONE) &&
                   (s_mld_last_dst[15] == 0x02);   /* ff02::2 全ルータ */
        uart_printf("mldtest: %s [9] 離脱通知 -- type=%u(期待 %u=Done)/ 宛先 ff02::%02x\n",
                    good ? "OK" : "NG", s_mld_last[0], ICMPV6_TYPE_MLD_DONE,
                    s_mld_last_dst[15]);
        if (!good) ok = 0;
    }

    /* ---- [10] 後始末: v1 互換モードを抜けて参加し直す ----
     * **`mldtest` は Done を送ってしまうので、必ず Report を送り直す**
     * (実スイッチ配下なら、ここを忘れると以後 NDP が届かなくなる)。 */
    ipv6_mld_clear_v1_mode();
    ipv6_mld_report_all(self);
    netif_activate(self);
    ipv6_set_mld_observer(NULL);
    s_mld_dump = 0;

    uart_printf("mldtest: %s(v1 互換モードを解除し、Report を送り直しました)\n",
                ok ? "PASS" : "NG");
}

/*=================================================================
 * シェルの `arpage`。近隣キャッシュ(ARP/NDP 共通)の有効期間を変更する。
 * 既定は 60 秒だが、それでは検証に 1 分以上かかるので短くできるようにして
 * ある。猶予(TTL/6)と確認要求の間隔(TTL/60)もこれに連動する。
 *
 * 引数:
 *   args - "" で現在値の表示、"<ms>" で設定
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_arpage(char *args)
{
    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
        uint32_t ms = (uint32_t)atoi(args);
        if (ms < 60u) {
            uart_printf("arpage: 短すぎます(確認要求の間隔が 1ms 未満になる)。60ms 以上を指定してください\n");
            return;
        }
        g_neigh_cache_ttl_ms = ms;
    }
    uint32_t ttl = g_neigh_cache_ttl_ms;
    uint32_t iv = ttl / 60u;
    if (iv < 10u) iv = 10u;
    uart_printf("arpage: TTL=%ums 猶予=%ums 確認要求の間隔=%ums\n", ttl, ttl / 6u, iv);
}

/*=================================================================
 * 近隣キャッシュの状態を 1 行で表示する(arptest の観測用)。
 *
 * 引数:
 *   label - 行頭のラベル
 *   state - arp_cache_peek()/ndp_cache_peek() の戻り値
 *   remain_ms - 同関数が返した残り時間
 * コール元:
 *   shell_arptest()
 * ===============================================================*/
static void shell_print_neigh(const char *label, int state, uint32_t remain_ms)
{
    if (state == 0) {
        uart_printf("  %s: fresh(失効まで %ums)\n", label, remain_ms);
    } else if (state == 1) {
        uart_printf("  %s: stale -- 使いつつ確認要求中(破棄まで %ums)\n", label, remain_ms);
    } else {
        uart_printf("  %s: 未登録(破棄済み)\n", label);
    }
}

/*=================================================================
 * シェルの `arptest`。A2(ARP/NDP キャッシュのエージング)の検証。
 *
 * 見たいのは 3 つ。
 *  (a) 失効しても即座には捨てず、猶予のあいだ MAC を返し続けること
 *      (捨てると送信ホットパスで arp_resolve() がブロックする)
 *  (b) 相手が応答すれば延命して fresh へ戻ること
 *  (c) 応答が無ければ猶予切れで本当に破棄されること
 *
 * (c) は「応答が返ってこない相手」が要るので、誰も名乗っていない IP の
 * エントリを arp_cache_insert() で直接仕込む。実際に居ない相手なので
 * 確認要求への応答は永久に来ない。
 *
 * TTL は測定中だけ短くし、最後に必ず元へ戻す。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_arptest(void)
{
    const uint32_t test_ttl_ms = 600u;   /* 猶予 100ms、確認要求は 10ms 間隔 */
    const uint32_t dead_ip = ip_from_octets(192, 168, 101, 99);  /* 誰も名乗っていない */
    const uint8_t  dead_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x10, 0x99 };

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("arptest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    const uint32_t peer_ip = peer->ip;
    const uint32_t saved_ttl = g_neigh_cache_ttl_ms;
    g_neigh_cache_ttl_ms = test_ttl_ms;

    int ok = 1;
    uint8_t mac[6];
    uint32_t remain = 0;

    uart_printf("arptest: TTL=%ums 猶予=%ums で検証(終了時に %ums へ戻します)\n",
                test_ttl_ms, test_ttl_ms / 6u, saved_ttl);

    /* --- 実在する相手(対向 PF)--- */
    netaddr_t peer_addr = netaddr_v4(peer_ip);
    netaddr_t peer_addr6 = netaddr_v6(peer_ll);
    if (net_resolve_mac(&peer_addr, mac) != 0 || net_resolve_mac(&peer_addr6, mac) != 0) {
        uart_printf("arptest: NG -- 対向 PF の解決に失敗\n");
        g_neigh_cache_ttl_ms = saved_ttl;
        return;
    }
    /* peek の戻り値と remain は必ず別の文で受ける。同じ呼び出し式を
     * uart_printf の引数に並べると、C は引数の評価順序を規定していないので
     * remain が更新される前に読まれて 1 回ぶん古い値が出る(実際に踏んだ)。 */
    uart_printf("arptest: [1] 解決直後\n");
    int a1 = arp_cache_peek(peer_ip, &remain);
    shell_print_neigh("ARP 対向PF", a1, remain);
    int n1 = ndp_cache_peek(peer_ll, &remain);
    shell_print_neigh("NDP 対向PF", n1, remain);
    if (a1 != 0 || n1 != 0) {
        uart_printf("arptest: NG [1] 解決直後なのに fresh ではない\n");
        ok = 0;
    }

    /* 応答の来ない相手を仕込む。以後この 2 つを並べて追いかける。 */
    arp_cache_insert(dead_ip, dead_mac);

    /* --- TTL を過ぎるまで待つ(受信は回し続ける)--- */
    uint64_t t0 = timer_now();
    while (!timeout_ms(t0, test_ttl_ms + 20u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
    }

    uart_printf("arptest: [2] TTL 経過直後(まだ lookup していない)\n");
    int a2 = arp_cache_peek(peer_ip, &remain);
    shell_print_neigh("ARP 対向PF", a2, remain);
    int d2 = arp_cache_peek(dead_ip, &remain);
    shell_print_neigh("ARP 応答無し", d2, remain);
    /* 対向 PF 側は、裏で NVMe セッションが動いていると待っている間に lookup
     * されて延命されることがある(それ自体は正しい動作)。ここで stale を
     * 断言できるのは、誰も触らない「応答の無い相手」のほうだけ。 */
    if (d2 != 1) {
        uart_printf("arptest: NG [2] TTL を過ぎても stale になっていない\n");
        ok = 0;
    }

    /* --- (a)(b) stale なエントリを lookup する。MAC は返り、確認要求が出る。
     *     実在する相手は応答するので fresh へ戻る。 --- */
    int hit4 = (arp_cache_lookup(peer_ip, mac) == 0);
    int hit6 = (ndp_cache_lookup(peer_ll, mac) == 0);
    int hit_dead = (arp_cache_lookup(dead_ip, mac) == 0);
    uart_printf("arptest: [3] stale なエントリの lookup -- 対向PF v4=%s v6=%s / 応答無し=%s\n",
                hit4 ? "MAC を返した" : "失敗", hit6 ? "MAC を返した" : "失敗",
                hit_dead ? "MAC を返した" : "失敗");
    if (!hit4 || !hit6 || !hit_dead) {
        uart_printf("arptest: NG [3] stale なのに MAC を返さなかった"
                    "(送信ホットパスがブロックする)\n");
        ok = 0;
    }

    /* **DELAY 相を跨いでからもう一度 lookup する**(B3 で入った RFC 4861 の
     * DELAY_FIRST_PROBE_TIME)。stale なエントリを使った最初の 1 回は確認要求を
     * 出さずに黙って MAC を返すので、そこで待っても応答は来ない。DELAY
     * (TTL/12)が明けてから引き直すと確認要求が出る。 */
    t0 = timer_now();
    while (!timeout_ms(t0, test_ttl_ms / NEIGH_DELAY_DIVISOR + 20u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
    }
    netif_activate(self);
    arp_cache_lookup(peer_ip, mac);
    ndp_cache_lookup(peer_ll, mac);

    /* 応答が届くまで少し回す。 */
    t0 = timer_now();
    while (!timeout_ms(t0, 50u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
    }
    uart_printf("arptest: [4] DELAY 経過後に引き直して確認要求 -> 応答後\n");
    int s4 = arp_cache_peek(peer_ip, &remain);
    shell_print_neigh("ARP 対向PF", s4, remain);
    int s6 = ndp_cache_peek(peer_ll, &remain);
    shell_print_neigh("NDP 対向PF", s6, remain);
    if (s4 != 0 || s6 != 0) {
        uart_printf("arptest: NG [4] 応答があったのに fresh へ戻っていない\n");
        ok = 0;
    }

    /* --- (c) 応答の来ない相手は猶予切れで破棄される --- */
    t0 = timer_now();
    while (!timeout_ms(t0, test_ttl_ms + test_ttl_ms / 6u + 50u)) {
        net_poll_all_and_dispatch();
        job_scheduler_tick();
    }
    int dead_hit = (arp_cache_lookup(dead_ip, mac) == 0);
    uart_printf("arptest: [5] 応答の無い相手 -- lookup は %s\n",
                dead_hit ? "まだ MAC を返した" : "未登録を返した(破棄された)");
    if (dead_hit) {
        uart_printf("arptest: NG [5] 猶予を過ぎても破棄されていない\n");
        ok = 0;
    }

    g_neigh_cache_ttl_ms = saved_ttl;
    /* 対向 PF のエントリを本来の TTL で入れ直す(短い TTL のまま残すと、
     * 以後のベンチ中に無用な確認要求が飛ぶ)。lookup は stale なエントリの
     * 期限を更新しないので、明示的に insert し直す必要がある。 */
    uint8_t mac4[6], mac6[6];
    if (arp_cache_lookup(peer_ip, mac4) == 0) arp_cache_insert(peer_ip, mac4);
    if (ndp_cache_lookup(peer_ll, mac6) == 0) ndp_cache_insert(peer_ll, mac6);

    uart_printf("arptest: %s(TTL は %ums へ戻しました)\n", ok ? "PASS" : "NG", saved_ttl);
}

/*=================================================================
 * シェルの `routetest`。A1(ルーティング/ゲートウェイ)の検証。
 *
 * DAC 直結の 2 ポートしか無いので「別セグメントの向こう側」を素直には作れ
 * ない。そこで対向 PF と同じ物理ポート(同じ nic/nic_priv/MAC)を共有する
 * 別名インターフェースを 10.9.9.9 として一時登録する。既存の
 * netif_resolve_frame_owner() が宛先 IP を見てフレームを別名側へ渡すので、
 * **宛先 IP(10.9.9.9)と次ホップ IP(192.168.101.11)が異なる状態で実データを
 * 流せる**。これが「ゲートウェイの MAC を引いている」ことの直接の証拠になる
 * (アドレス演算だけの確認では、宛先とゲートウェイが同じでも通ってしまう)。
 *
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_routetest(void)
{
    /* 別サブネットの宛先。対向 PF の別名として一時的に実在させる。 */
    const uint32_t far_ip = ip_from_octets(10, 9, 9, 9);
    const uint16_t port   = 6002u;
    static netif_t s_alias;   /* netif_t は登録表にポインタで載るので静的に置く */

    uint8_t peer_ll[16];
    netif_t *peer = shell_peer_ll6(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("routetest: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }

    const uint32_t saved_mask = self->netmask;
    const uint32_t saved_gw   = self->gateway;
    const uint8_t  saved_gw6_set = self->gateway6_set;
    uint8_t saved_gw6[16];
    for (unsigned i = 0; i < 16; i++) saved_gw6[i] = self->gateway6[i];

    int ok = 1;

    /* [1] ゲートウェイ未設定なら、サブネット外でも宛先を直接解決する
     *     (A1 を入れる前の挙動と同じ)。 */
    self->netmask = ip_from_octets(255, 255, 255, 0);
    self->gateway = 0u;
    if (netif_next_hop4(self, far_ip) != far_ip) {
        uart_printf("routetest: NG [1] gw 未設定なのに次ホップが宛先と違う\n");
        ok = 0;
    } else {
        uart_printf("routetest: OK [1] gw 未設定 -- 次ホップ = 宛先(従来の挙動)\n");
    }

    /* [2] ゲートウェイを設定したときの次ホップ選択。 */
    self->gateway = peer->ip;
    struct { uint32_t dst; uint32_t want; const char *why; } cases[] = {
        { peer->ip,             peer->ip,            "同一サブネット -> 宛先を直接" },
        { far_ip,               peer->ip,            "サブネット外 -> ゲートウェイ" },
        { 0xFFFFFFFFu,          0xFFFFFFFFu,         "限定ブロードキャスト -> 宛先" },
        { ip_from_octets(224,0,0,1), ip_from_octets(224,0,0,1),
                                                     "マルチキャスト -> 宛先" },
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint32_t hop = netif_next_hop4(self, cases[i].dst);
        if (hop != cases[i].want) {
            shell_print_ipv4("routetest: NG [2] 宛先 ", cases[i].dst);
            shell_print_ipv4(" の次ホップが ", hop);
            shell_print_ipv4(" (期待 ", cases[i].want);
            uart_printf(") -- %s\n", cases[i].why);
            ok = 0;
        }
    }
    if (ok) uart_printf("routetest: OK [2] 次ホップ選択 4 ケースすべて期待どおり\n");

    /* [3] サブネット外の宛先を解決すると、ゲートウェイ(対向 PF)の MAC が
     *     返ること。宛先 10.9.9.9 の MAC ではなく 192.168.101.11 の MAC を
     *     引いている、というのがここの主張。 */
    netaddr_t far_addr = netaddr_v4(far_ip);
    uint8_t got_mac[6];
    if (net_resolve_mac(&far_addr, got_mac) != 0) {
        uart_printf("routetest: NG [3] サブネット外宛の MAC 解決に失敗\n");
        ok = 0;
    } else {
        int same = 1;
        for (unsigned i = 0; i < 6u; i++) if (got_mac[i] != peer->mac[i]) same = 0;
        uart_printf("routetest: %s [3] 10.9.9.9 の次ホップ MAC = "
                    "%02x:%02x:%02x:%02x:%02x:%02x (%s の MAC%s)\n",
                    same ? "OK" : "NG",
                    got_mac[0], got_mac[1], got_mac[2], got_mac[3], got_mac[4], got_mac[5],
                    peer->name, same ? "" : " と不一致");
        if (!same) ok = 0;
    }

    /* [4] IPv6。グローバルアドレス宛は gateway6 へ、リンクローカルと
     *     マルチキャストは宛先へ。実データの往復は v6 のグローバルアドレスを
     *     名乗る手段がまだ無いので(B1 SLAAC 待ち)、解決までを確認する。 */
    for (unsigned i = 0; i < 16; i++) self->gateway6[i] = peer_ll[i];
    self->gateway6_set = 1u;
    uint8_t global6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    uint8_t mcast6[16]  = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    int v6_ok = (netif_next_hop6(self, global6) == self->gateway6) &&
                (netif_next_hop6(self, peer_ll) == peer_ll) &&
                (netif_next_hop6(self, mcast6)  == mcast6);
    netaddr_t g6 = netaddr_v6(global6);
    if (v6_ok && net_resolve_mac(&g6, got_mac) == 0) {
        for (unsigned i = 0; i < 6u; i++) if (got_mac[i] != peer->mac[i]) v6_ok = 0;
    } else {
        v6_ok = 0;
    }
    uart_printf("routetest: %s [4] IPv6 -- グローバル宛は gateway6(%s)へ、"
                "リンクローカル/マルチキャストは宛先へ\n",
                v6_ok ? "OK" : "NG", peer->name);
    if (!v6_ok) ok = 0;

    /* [5] エンドツーエンド。対向 PF の別名として 10.9.9.9 を一時的に実在させ、
     *     ゲートウェイ経路で 64KB を往復させる。 */
    s_alias = *peer;                /* MAC / nic / nic_priv / mss_cap 等を引き継ぐ */
    s_alias.name    = "route-far";
    s_alias.ip      = far_ip;
    s_alias.netmask = 0u;           /* 戻りは従来どおり宛先を直接 ARP する */
    s_alias.gateway = 0u;
    s_alias.gateway6_set = 0u;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) s_alias.arp_cache[i].valid = 0;
    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) s_alias.ndp_cache[i].valid = 0;
    netif_register(&s_alias);
    /* 受信キューは対向 PF が持っている。別名を巡回対象にすると同じ RQ を
     * 二重にポーリングしてしまうので、ポーリング主体からは外す。フレームは
     * netif_resolve_frame_owner() が宛先 IP を見てこちらへ回してくれる。 */
    s_alias.is_poll_owner = 0;

    netif_activate(self);
    int e2e = shell_tcp_echo_once("routetest", self, &s_alias, &far_addr, port, NULL);
    if (!e2e) ok = 0;

    /* [6] IPv6 のエンドツーエンド。別名に「別プレフィックスのグローバル
     *     アドレス」を名乗らせ、自分側にもグローバルアドレスを付けて、
     *     ゲートウェイ経路で 64KB を往復させる。
     *
     *     **宛先(2001:db8:0:9::9)と次ホップ(対向 PF のリンクローカル)が
     *     別物である状態で実データを流す**のがここの主張。別名側は
     *     gateway6 を持たないので、戻りは宛先を直接 NDP で引く。 */
    {
        static const uint8_t self6[16] = { 0x20,0x01,0x0d,0xb8,0,0,0,0x01,0,0,0,0,0,0,0,0x10 };
        static const uint8_t far6[16]  = { 0x20,0x01,0x0d,0xb8,0,0,0,0x09,0,0,0,0,0,0,0,0x09 };
        for (unsigned i = 0; i < 16u; i++) {
            self->ip6_global[i]    = self6[i];
            s_alias.ip6_global[i]  = far6[i];
        }
        self->ip6_global_set   = 1u;
        self->ip6_prefix_len   = 64u;
        s_alias.ip6_global_set = 1u;
        s_alias.ip6_prefix_len = 64u;

        netif_activate(self);
        netaddr_t far6_addr = netaddr_v6(far6);
        int e2e6 = shell_tcp_echo_once("routetest6", self, &s_alias, &far6_addr,
                                       (uint16_t)(port + 1u), NULL);
        uart_printf("routetest: %s [6] IPv6 エンドツーエンド(宛先 2001:db8:0:9::9 / "
                    "次ホップ %s)\n", e2e6 ? "OK" : "NG", peer->name);
        if (!e2e6) ok = 0;

        self->ip6_global_set = 0u;   /* 後始末(別名はこの後 unregister される) */
    }

    netif_unregister(&s_alias);

    /* [7] 設定を元に戻す。戻し忘れると以後の tcpbench/bench が全部
     *     ゲートウェイ経路を通ることになる。 */
    self->netmask = saved_mask;
    self->gateway = saved_gw;
    self->gateway6_set = saved_gw6_set;
    for (unsigned i = 0; i < 16; i++) self->gateway6[i] = saved_gw6[i];
    netif_activate(self);

    uart_printf("routetest: %s(設定は元に戻しました)\n", ok ? "PASS" : "NG");
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
    uint8_t  ipv6;          /* NVMe/TCP のみ。1=対向のリンクローカルへ IPv6 で繋ぐ */
} bench_plan_t;

/*=================================================================
 * ベンチ引数 "[KB[,KB...]] [r|w|rw] [qd] [hdgst] [ddgst] [ipv6]" を解析する。
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
    pl->hdgst = 0; pl->ddgst = 0; pl->ipv6 = 0;

    /* 先に digest キーワードを抜き取り、残りを従来通り位置引数として扱う。 */
    unsigned kept = 0;
    for (unsigned i = 0; i < nt; i++) {
        if (strcmp(tok[i], "hdgst") == 0)  { pl->hdgst = 1; continue; }
        if (strcmp(tok[i], "ddgst") == 0)  { pl->ddgst = 1; continue; }
        if (strcmp(tok[i], "digest") == 0) { pl->hdgst = 1; pl->ddgst = 1; continue; }
        if (strcmp(tok[i], "ipv6") == 0)   { pl->ipv6 = 1; continue; }
        if (strcmp(tok[i], "ipv4") == 0)   { pl->ipv6 = 0; continue; }
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
    if (shell_ensure_tcp_session(pl.hdgst, pl.ddgst, pl.ipv6) != 0) return;
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
 * シェルの `txdrop`。TCP のデータセグメントを人為的に N 個に 1 個捨てる
 * ロス注入を設定/表示する(0=無効)。
 *
 * DAC 直結ループバックではパケットロスがまず起きないので、高速再送
 * (3 dup ACK)の経路を実機で通すにはこれが要る。引数なしで現在値と
 * これまでに捨てた数、再送の内訳を表示する。
 *
 * 引数:
 *   args - N。省略時は現在値と統計を表示
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_txdrop(char *args)
{
    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
        g_tcp_tx_drop_every = (uint32_t)atoi(args);
        /* 切り替えのたびに統計を 0 に戻す(前回の測定と混ざらないように)。 */
        for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
            g_tcp_tx_dropped_count[c]      = 0;
            g_tcp_retransmit_count[c]      = 0;
            g_tcp_fast_retransmit_count[c] = 0;
            g_tcp_dup_ack_count[c]         = 0;
        }
        g_tcp_retransmit_segs    = 0;
        g_tcp_sack_skipped_count = 0;
    }

    uint32_t dropped = 0, retx = 0, fastretx = 0, dupack = 0;
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        dropped   += g_tcp_tx_dropped_count[c];
        retx      += g_tcp_retransmit_count[c];
        fastretx  += g_tcp_fast_retransmit_count[c];
        dupack    += g_tcp_dup_ack_count[c];
    }
    if (g_tcp_tx_drop_every == 0u) {
        uart_printf("txdrop: 無効\n");
    } else {
        uart_printf("txdrop: データセグメント %u 個に 1 個を破棄\n",
                    (unsigned)g_tcp_tx_drop_every);
    }
    uart_printf("txdrop: 破棄=%u 重複ACK=%u 再送=%u (うち高速再送=%u、残りはRTO由来=%u)\n",
                (unsigned)dropped, (unsigned)dupack, (unsigned)retx,
                (unsigned)fastretx, (unsigned)(retx - fastretx));
    /* **送り直したセグメント数**。Go-Back-N と SACK の差はここに出る
     * (再送を「何回始めたか」ではなく「何個送り直したか」)。 */
    uart_printf("txdrop: 送り直したセグメント=%u (破棄 1 個あたり %u/100) "
                "SACK で省略=%u\n",
                (unsigned)g_tcp_retransmit_segs,
                dropped ? (unsigned)((uint64_t)g_tcp_retransmit_segs * 100u / dropped) : 0u,
                (unsigned)g_tcp_sack_skipped_count);
}

/*=================================================================
 * Discovery Log Page を人が読める形で表示する。
 *
 * オフセットは nvme.h / nvmet.h の定数(tools/disc_log_check.c の offsetof で
 * 確認済み)を使う。文字列フィールドは NUL 終端されていない可能性があるので
 * 長さを見ながら出す。
 *
 * 引数:
 *   log / len - Discovery Log Page の生バイト列と長さ
 * コール元:
 *   shell_nvmediscover()
 * ===============================================================*/
static void shell_disc_log_print_str(const char *label, const uint8_t *p, uint32_t max)
{
    uint32_t n = 0;
    while (n < max && p[n] != 0) n++;
    uart_printf("    %-8s = \"", label);
    for (uint32_t i = 0; i < n; i++) uart_printf("%c", (char)p[i]);
    uart_printf("\"\n");
}

static void shell_disc_log_print(const uint8_t *log, uint32_t len)
{
    if (len < NVME_DISC_HDR_BYTES) return;
    uint64_t numrec = rd64le(&log[NVME_DISC_OFF_NUMREC]);
    uart_printf("  genctr=%u numrec=%u recfmt=%u\n",
                (unsigned)rd64le(&log[NVME_DISC_OFF_GENCTR]),
                (unsigned)numrec,
                rd16le(&log[NVME_DISC_OFF_RECFMT]));

    uint32_t avail = (len - NVME_DISC_HDR_BYTES) / NVME_DISC_ENTRY_BYTES;
    for (uint32_t i = 0; i < numrec && i < avail; i++) {
        const uint8_t *e = &log[NVME_DISC_HDR_BYTES + i * NVME_DISC_ENTRY_BYTES];
        static const char *trt[] = { "PCI", "RDMA", "FC", "TCP" };
        static const char *afm[] = { "PCI", "IPv4", "IPv6", "IB", "FC" };
        uint8_t trtype = e[NVMET_DISC_ENT_OFF_TRTYPE];
        uint8_t adrfam = e[NVMET_DISC_ENT_OFF_ADRFAM];
        uart_printf("  entry[%u]: trtype=%u(%s) adrfam=%u(%s) subtype=%u treq=%u\n",
                    i, trtype, (trtype < 4u) ? trt[trtype] : "?",
                    adrfam, (adrfam < 5u) ? afm[adrfam] : "?",
                    e[NVMET_DISC_ENT_OFF_SUBTYPE], e[NVMET_DISC_ENT_OFF_TREQ]);
        uart_printf("    portid=%u cntlid=0x%04x asqsz=%u\n",
                    rd16le(&e[NVMET_DISC_ENT_OFF_PORTID]),
                    rd16le(&e[NVMET_DISC_ENT_OFF_CNTLID]),
                    rd16le(&e[NVMET_DISC_ENT_OFF_ASQSZ]));
        shell_disc_log_print_str("trsvcid", &e[NVMET_DISC_ENT_OFF_TRSVCID], 32u);
        shell_disc_log_print_str("subnqn",  &e[NVMET_DISC_ENT_OFF_SUBNQN], 256u);
        shell_disc_log_print_str("traddr",  &e[NVMET_DISC_ENT_OFF_TRADDR], 256u);
    }
}

/*=================================================================
 * シェルの `nvmediscover`。Discovery コントローラ(固定 NQN)へ接続し、
 * Discovery Log Page を取得して内容を表示する。`nvme discover` 相当。
 *
 * ホストの実際の手順を再現する: まずヘッダ 1024 バイトだけを LPO=0 で読み、
 * NUMREC を見てから全体を読み直す。**ターゲットが Get Log Page のオフセット
 * (LPO)に対応していないとここで破綻する。**
 *
 * 引数:
 *   args - "dump" を付けると Discovery Log Page 全体を 16 進で出力する。
 *          その出力を tools/disc_log_check.c(Linux カーネルの構造体だけを
 *          使う独立したパーサ)へ食わせて妥当性を確認する。
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_nvmediscover(char *args)
{
    while (*args == ' ') args++;
    int want_dump = (args[0] == 'd' && args[1] == 'u' && args[2] == 'm' && args[3] == 'p');

    netif_t *ctx0 = netif_find("mlx5-pf0");
    netif_t *ctx1 = netif_find("mlx5-pf1");
    if (!ctx0 || !ctx1) { uart_printf("nvmediscover: netif 未登録\n"); return; }

    /* ターゲットが未起動なら起こす(tcpbench と同じ条件で 4421 番)。 */
    if (!s_shell_nvmet_started) {
        if (smp_boot_core1() == 0) netif_set_owner_core(ctx1, 1u);
        netif_activate(ctx1);
        if (nvmet_job_start(&s_x86_nvmet, 4421u, ctx1, "manual") != 0) {
            uart_printf("nvmediscover: ターゲット起動失敗\n"); return;
        }
        s_shell_nvmet_started = 1;
        uart_printf("nvmediscover: ターゲット常駐起動 (pf1, core1)\n");
    }

    /* discovery は通常セッションとは別のコントローラなので、既存の
     * tcpbench セッションが張られていたら閉じてから繋ぎ直す。 */
    if (s_shell_tcp_connected) {
        uart_printf("nvmediscover: 既存の tcpbench セッションを閉じます\n");
        nvme_tcp_close(&s_nvme_ctx.io);
        nvme_tcp_close(&s_nvme_ctx.admin);
        s_nvme_ctx.io_connected = 0;
        s_shell_tcp_connected   = 0;
        uint64_t t0 = timer_now();
        while (!timeout_ms(t0, 1500u)) { job_scheduler_tick(); net_poll_all_and_dispatch(); }
    }

    netif_activate(ctx0);
    s_nvme_ctx.req_hdgst     = 0;
    s_nvme_ctx.req_ddgst     = 0;
    s_nvme_ctx.discovery_mode = 1;

    netaddr_t target = netaddr_v4(ip_from_octets(192, 168, 101, 11));
    uart_printf("nvmediscover: 192.168.101.11:4421 へ discovery 接続 (subnqn=%s)\n",
                NVMET_DISCOVERY_NQN);
    nvme_connect_job_start_addr(&s_nvme_ctx, &target, 4421u, NVMET_DISCOVERY_NQN);

    uint64_t t = timer_now();
    while (s_nvme_ctx.busy) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        if (timeout_ms(t, 15000u)) {
            uart_printf("nvmediscover: NG -- タイムアウト\n");
            s_nvme_ctx.discovery_mode = 0;
            return;
        }
    }
    s_nvme_ctx.discovery_mode = 0;

    if (s_nvme_ctx.disc_log_len == 0) {
        uart_printf("nvmediscover: NG -- Discovery Log Page を取得できませんでした\n");
    } else {
        uart_printf("nvmediscover: PASS -- %u バイト取得 (numrec=%u)\n",
                    s_nvme_ctx.disc_log_len, (unsigned)s_nvme_ctx.disc_numrec);
        shell_disc_log_print(s_nvme_ctx.disc_log, s_nvme_ctx.disc_log_len);
        if (want_dump) {
            uart_printf("---- BEGIN DISCOVERY LOG HEX (%u バイト) ----\n",
                        s_nvme_ctx.disc_log_len);
            for (uint32_t i = 0; i < s_nvme_ctx.disc_log_len; i++) {
                uart_printf("%02x", s_nvme_ctx.disc_log[i]);
                if ((i % 32u) == 31u) uart_printf("\n");
            }
            if ((s_nvme_ctx.disc_log_len % 32u) != 0u) uart_printf("\n");
            uart_printf("---- END DISCOVERY LOG HEX ----\n");
        }
    }

    /* discovery セッションは admin だけ。閉じて通常の tcpbench が張り直せる
     * 状態へ戻す。 */
    nvme_tcp_close(&s_nvme_ctx.admin);
    uint64_t t2 = timer_now();
    while (!timeout_ms(t2, 1000u)) { job_scheduler_tick(); net_poll_all_and_dispatch(); }
    netif_activate(ctx0);
}

/*=================================================================
 * シェルの `qploop`。RC QP の作成と破棄を N 回繰り返し、FW 側リソースが
 * 枯渇しないことを確認する。
 *
 * `mlx5_qp_create_rc()` は QP 1 本につき UAR / PD / MKey / CQ も確保する。
 * これらを解放しないと作り直すたびに FW のリソースが溜まり、いずれ確保が
 * 失敗する(過去に INIT2RTR_QP が BAD_RES_ERR=0x05 で落ちた実績がある)。
 * **何回目で失敗するかを数値で出すのが目的**なので、失敗したらその回数を
 * 報告して止める。
 *
 * 引数:
 *   args - 繰り返し回数。省略時は 8(FW を一気に枯渇させると復旧が重いので
 *          少しずつ増やして試すこと)
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
static void shell_qploop(char *args)
{
    while (*args == ' ') args++;
    unsigned n = (*args >= '0' && *args <= '9') ? (unsigned)atoi(args) : 8u;
    if (n == 0u) n = 1u;
    if (n > 256u) n = 256u;  /* 一気に枯渇させない */

    /* qp_index=0 は admin QP と DMA バッファを共有する。RDMA セッションが
     * 生きている間に叩くとそれを壊すので、bench の後は使わないこと。 */
    static mlx5_qp_t qp;
    mlx5_dev_t *dev = &s_dev0;

    uart_printf("qploop: RC QP の作成/破棄を %u 回繰り返します (PF0)\n", n);
    unsigned done = 0;
    for (unsigned i = 0; i < n; i++) {
        if (mlx5_qp_create_rc(dev, &qp, 0) != 0) {
            uart_printf("qploop: NG -- %u 回目の mlx5_qp_create_rc() が失敗 "
                        "(FW リソース枯渇の疑い)\n", i + 1u);
            return;
        }
        if (mlx5_qp_modify_rst2init(dev, &qp) != 0) {
            uart_printf("qploop: NG -- %u 回目の RST2INIT_QP が失敗\n", i + 1u);
            mlx5_qp_destroy(dev, &qp);
            return;
        }
        if (mlx5_qp_destroy(dev, &qp) != 0) {
            uart_printf("qploop: NG -- %u 回目の mlx5_qp_destroy() が失敗\n", i + 1u);
            return;
        }
        done++;
    }
    uart_printf("qploop: PASS -- %u 回すべて成功\n", done);
}

/*=================================================================
 * 入力 1 行をコマンドとして解釈し実行する(monitor / nvmet / tcpbench /
 * bench / simdelay / ackthresh / txdrop / qploop / ts / jobs / help / quit)。
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
    } else if (strncmp(line, "ip6addr", 7) == 0) {
        /* ip6addr                        -- 各インターフェースの設定を表示
         * ip6addr <if> <addr> [plen]     -- グローバル IPv6 アドレスを設定
         * ip6addr <if> off               -- 解除
         *
         * **アドレスは RFC 4291 の完全表記(8 グループ)のみ受け付ける。**
         * `::` の省略記法は展開しない(nvmet.c の IPv6 表記と同じ方針)。
         * 例: ip6addr mlx5-pf0 2001:0db8:0000:0001:0000:0000:0000:0010 64
         *
         * B1(SLAAC)を入れるまでの間、グローバルアドレスを名乗る手段が無くて
         * 保留になっていた A1 の IPv6 エンドツーエンドと A6 の IPv6 UDP 分割を
         * 動かすための手動設定。SLAAC が入ったら同じ netif_t の状態を
         * RA から埋めることになる。 */
        char tok[3][80];
        unsigned nt = 0;
        const char *q = line + 7;
        while (*q && nt < 3u) {
            while (*q == ' ') q++;
            if (!*q) break;
            unsigned k = 0;
            while (*q && *q != ' ' && k < 79u) tok[nt][k++] = *q++;
            tok[nt][k] = 0;
            nt++;
        }
        if (nt == 0) {
            static const char *ifnames[] = { "mlx5-pf0", "mlx5-pf1" };
            for (unsigned i = 0; i < 2u; i++) {
                netif_t *ni = netif_find(ifnames[i]);
                if (!ni) continue;
                ipv6_slaac_age(ni);   /* 表示は冷たい経路なのでここで満了を判定する */
                if (ni->ip6_global_set) {
                    uart_printf("ip6addr: %-10s global=", ni->name);
                    for (unsigned j = 0; j < 8u; j++) {
                        uart_printf("%s%02x%02x", (j ? ":" : ""),
                                    ni->ip6_global[j * 2u], ni->ip6_global[j * 2u + 1u]);
                    }
                    uart_printf("/%u %s", ni->ip6_prefix_len,
                                ni->ip6_global_from_ra ? "(SLAAC" : "(手動");
                    if (ni->ip6_global_valid_until != 0u) {
                        uint64_t now = timer_now();
                        uint64_t rem = ((int64_t)(ni->ip6_global_valid_until - now) > 0)
                                     ? (ni->ip6_global_valid_until - now) : 0u;
                        uart_printf("、残り %us", (unsigned)(rem / 1000000000ull));
                    }
                    uart_printf(")\n");
                } else {
                    uart_printf("ip6addr: %-10s global=(未設定、リンクローカルのみ)\n", ni->name);
                }
            }
        } else if (nt >= 2u) {
            netif_t *ni = netif_find(tok[0]);
            if (!ni) {
                uart_printf("ip6addr: インターフェース %s が見つかりません\n", tok[0]);
            } else if (strncmp(tok[1], "off", 3) == 0) {
                /* **解除の前に離脱を通知する。** そのアドレスの要請ノード
                 * マルチキャストにはもう用が無いので、スヌーピングする
                 * スイッチに転送をやめさせる(順序が逆だとグループが
                 * 分からなくなる)。 */
                if (ni->ip6_global_set) {
                    uint8_t sol[16];
                    ipv6_solicited_node_addr(ni->ip6_global, sol);
                    netif_t *prev6 = g_active_ctx;
                    netif_activate(ni);
                    ipv6_mld_leave(sol);
                    if (prev6) netif_activate(prev6);
                }
                ni->ip6_global_set         = 0;
                ni->ip6_global_from_ra     = 0;
                ni->ip6_global_valid_until = 0;
                ni->ip6_global_dad         = NETIF_DAD_UNKNOWN;
                uart_printf("ip6addr: %s のグローバルアドレスを解除しました\n", ni->name);
            } else {
                uint8_t a[16];
                unsigned gi = 0, v = 0, ndig = 0;
                const char *r = tok[1];
                int bad = 0;
                for (;; r++) {
                    if (*r == ':' || *r == 0) {
                        if (ndig == 0 || gi >= 8u) { bad = 1; break; }
                        a[gi * 2u] = (uint8_t)(v >> 8); a[gi * 2u + 1u] = (uint8_t)v;
                        gi++; v = 0; ndig = 0;
                        if (*r == 0) break;
                    } else {
                        unsigned d;
                        if (*r >= '0' && *r <= '9')      d = (unsigned)(*r - '0');
                        else if (*r >= 'a' && *r <= 'f') d = (unsigned)(*r - 'a') + 10u;
                        else if (*r >= 'A' && *r <= 'F') d = (unsigned)(*r - 'A') + 10u;
                        else { bad = 1; break; }
                        v = (v << 4) | d; ndig++;
                        if (ndig > 4u) { bad = 1; break; }
                    }
                }
                if (bad || gi != 8u) {
                    uart_printf("ip6addr: 完全表記(8 グループ)で指定してください "
                                "例 2001:0db8:0000:0001:0000:0000:0000:0010\n");
                } else {
                    for (unsigned j = 0; j < 16u; j++) ni->ip6_global[j] = a[j];
                    ni->ip6_global_set = 1;
                    ni->ip6_prefix_len = 64u;
                    /* **手動設定は寿命を持たない**(valid_until=0)。この 2 つを
                     * 落としておかないと、RA から作ったアドレスを上書きした
                     * ときに古い期限が残り、勝手に解除される。 */
                    ni->ip6_global_from_ra     = 0;
                    ni->ip6_global_valid_until = 0;
                    /* 新しい要請ノードマルチキャストへの参加を報告する。 */
                    ipv6_mld_report_all(ni);
                    if (nt >= 3u) {
                        unsigned pl = 0; const char *t = tok[2];
                        while (*t >= '0' && *t <= '9') { pl = pl * 10u + (unsigned)(*t - '0'); t++; }
                        if (pl > 0 && pl <= 128u) ni->ip6_prefix_len = (uint8_t)pl;
                    }
                    uart_printf("ip6addr: %s に設定しました(/%u)\n", ni->name, ni->ip6_prefix_len);
                }
            }
        }
    } else if (strncmp(line, "gidvlan", 7) == 0) {
        /* gidvlan <vid> -- **PF1 の GID だけ** VLAN 付きで登録する(0 で解除)。
         * FW の「自装置の GID 宛」判定が VLAN まで見ているかを切り分ける道具。
         * PF0 は素のままなので、PF0 が出すフレームはタグ無しで観測できる。 */
        const char *a = line + 7;
        while (*a == ' ') a++;
        unsigned v = 0;
        while (*a >= '0' && *a <= '9') { v = v * 10u + (unsigned)(*a - '0'); a++; }
        s_dev1.roce_gid_vlan = (uint16_t)v;
        uart_printf("gidvlan: PF1 の GID VLAN = %u (0=無効)\n", v);
    } else if (strncmp(line, "rocepeer", 8) == 0) {
        /* rocepeer <a.b.c.d> <pf1|pi5|bogus> -- 次の bench の宛先 GID と宛先 MAC を
         * 独立に指定する。**FW が「ローカル宛」を MAC で見ているのか GID で見て
         * いるのかを切り分けるための道具。** 引数なしで解除。 */
        const char *arg = line + 8;
        while (*arg == ' ') arg++;
        if (*arg == 0) {
            nvme_rdma_set_peer_override(0, 0, 0);
            uart_printf("rocepeer: 上書きを解除しました\n");
        } else {
            unsigned a = 0, b = 0, c = 0, d = 0;
            const char *pmac = arg;
            while (*pmac && *pmac != ' ') pmac++;
            while (*pmac == ' ') pmac++;
            {   /* a.b.c.d を手で読む(sscanf は使わない) */
                const char *q = arg;
                unsigned *slot[4] = { &a, &b, &c, &d };
                for (unsigned i = 0; i < 4u; i++) {
                    unsigned v = 0;
                    while (*q >= '0' && *q <= '9') { v = v * 10u + (unsigned)(*q - '0'); q++; }
                    *slot[i] = v;
                    if (*q == '.') q++;
                }
            }
            static const uint8_t mac_pf1[6]   = {0x02, 0x00, 0x00, 0x00, 0x10, 0x11};
            static const uint8_t mac_pi5[6]   = {0xb8, 0xce, 0xf6, 0x73, 0xbf, 0x7e};
            static const uint8_t mac_bogus[6] = {0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB};
            const uint8_t *m = mac_pf1;
            if (strncmp(pmac, "pi5", 3) == 0)        m = mac_pi5;
            else if (strncmp(pmac, "bogus", 5) == 0) m = mac_bogus;
            nvme_rdma_set_peer_override(1, ip_from_octets((uint8_t)a, (uint8_t)b,
                                                          (uint8_t)c, (uint8_t)d), m);
            uart_printf("rocepeer: 次の bench は %u.%u.%u.%u / "
                        "%02x:%02x:%02x:%02x:%02x:%02x へ送ります\n",
                        a, b, c, d, m[0], m[1], m[2], m[3], m[4], m[5]);
        }
    } else if (strncmp(line, "fdbprobe", 8) == 0) {
        /* FDB でも転送先を指定できるか。**ルートには設定しない**(FDB のルートを
         * 自前テーブルにすると全通信が落ちうる)。
         * **ルートに設定しなくても、FDB に catch-all を置いた時点で転送が壊れる。**
         * 後始末で消しているが、通信がおかしくなったら vn_start.sh から
         * 立て直すこと(プロセス終了時に vfio-pci がデバイスをリセットする)。 */
        uart_printf("[!] fdbprobe: FDB を触るので通信が壊れる場合がある"
                    "(直らなければプロセスを再起動)\n");
        mlx5_force_tx_to_uplink(&s_dev0, "pf0-fdb", 4u /* FDB */, 0);
        mlx5_force_tx_to_uplink(&s_dev1, "pf1-fdb", 4u /* FDB */, 0);
    } else if (strncmp(line, "txuplink", 8) == 0) {
        mlx5_force_tx_to_uplink(&s_dev0, "pf0", 1u /* NIC_TX */, 1);
        mlx5_force_tx_to_uplink(&s_dev1, "pf1", 1u /* NIC_TX */, 1);
    } else if (strncmp(line, "ftprobe", 7) == 0) {
        mlx5_probe_flow_table_types(&s_dev0, "pf0");
        mlx5_probe_flow_table_types(&s_dev1, "pf1");
    } else if (strncmp(line, "nvmens", 6) == 0) {
        /* 名前空間の一覧 / 追加 / 削除。**稼働中に叩くと D6 の AER が発火し、
         * ホストが名前空間を再スキャンする**(D8 と組で確かめる項目)。 */
        const char *p = line + 6;
        while (*p == ' ') p++;
        if (*p == '\0') { nvmet_ns_show(&s_x86_nvmet); return; }
        int add = (strncmp(p, "add", 3) == 0);
        int del = (strncmp(p, "del", 3) == 0);
        if (!add && !del) {
            uart_printf("usage: nvmens [add <nsid> | del <nsid>]\n");
            return;
        }
        p += 3;
        while (*p == ' ') p++;
        uint32_t nsid = (uint32_t)atoi(p);
        if (nvmet_ns_set_active(&s_x86_nvmet, nsid, add) == 0) {
            nvmet_ns_show(&s_x86_nvmet);
        }
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
    } else if (strncmp(line, "txdrop", 6) == 0) {
        shell_txdrop(line + 6);
    } else if (strncmp(line, "backlogtest", 11) == 0) {
        shell_backlogtest();
    } else if (strncmp(line, "backlog", 7) == 0) {
        shell_backlog(line + 7);
    } else if (strncmp(line, "synackdrop", 10) == 0) {
        shell_synackdrop(line + 10);
    } else if (strncmp(line, "tcptstest", 9) == 0) {
        shell_tcptstest();
    } else if (strncmp(line, "tcpts", 5) == 0) {
        shell_tcpts(line + 5);
    } else if (strncmp(line, "sacktest", 8) == 0) {
        shell_sacktest(line + 8);
    } else if (strncmp(line, "tcpsack", 7) == 0) {
        shell_tcpsack(line + 7);
    } else if (strncmp(line, "qploop", 6) == 0) {
        shell_qploop(line + 6);
    } else if (strncmp(line, "nvmediscover", 12) == 0) {
        shell_nvmediscover(line + 12);
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
    } else if (strncmp(line, "rsttest", 7) == 0) {
        shell_rsttest();
    } else if (strncmp(line, "routetest", 9) == 0) {
        shell_routetest();
    } else if (strncmp(line, "route", 5) == 0) {
        shell_route(line + 5);
    } else if (strncmp(line, "arptest", 7) == 0) {
        shell_arptest();
    } else if (strncmp(line, "dadtest", 7) == 0) {
        shell_dadtest();
    } else if (strncmp(line, "fragtest", 8) == 0) {
        shell_fragtest(line + 8);
    } else if (strncmp(line, "pmtutest", 8) == 0) {
        shell_pmtutest(line + 8);
    } else if (strncmp(line, "slaactest", 9) == 0) {
        shell_slaactest(line + 9);
    } else if (strncmp(line, "slaac", 5) == 0) {
        shell_slaac(line + 5);
    } else if (strncmp(line, "udp6send", 8) == 0) {
        shell_udp6send(line + 8);
    } else if (strncmp(line, "ext6test", 8) == 0) {
        shell_ext6test(line + 8);
    } else if (strncmp(line, "nudtest", 7) == 0) {
        shell_nudtest();
    } else if (strncmp(line, "mldtest", 7) == 0) {
        shell_mldtest(line + 7);
    } else if (strncmp(line, "mld", 3) == 0) {
        shell_mld(line + 3);
    } else if (strncmp(line, "arpage", 6) == 0) {
        shell_arpage(line + 6);
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
                    "  rsttest                               待ち受け無しポートへ接続しRSTで即失敗するか(v4/v6)\n"
                    "  route [<if> <netmask> <gateway>]      経路表示/設定(gateway 0.0.0.0 で解除)\n"
                    "  routetest                             サブネット外宛がゲートウェイのMACで送られるか(v4/v6)\n"
                    "  arpage [ms]                           ARP/NDPキャッシュの有効期間(既定60000ms)\n"
                    "  arptest                               キャッシュのエージング(失効→確認→延命/破棄)\n"
                    "  udp6send <addr> <port> <bytes>        指定IPv6宛にUDPを1個送る(MTU超で断片化)\n"
                    "  ext6test [dump]                       IPv6拡張ヘッダの走査と送信側の断片化\n"
                    "  nudtest                               到達不能検出(DELAY/ユニキャスト確認/上位層の確認)\n"
                    "  dadtest                               重複アドレス検出(ARP Probe / IPv6 DAD)\n"
                    "  fragtest [dump]                       送信側IP断片化(MTU超のUDP/IPを分割)\n"
                    "  pmtutest [dump]                       経路MTU探索(ICMP Frag Needed/PTBを注入)\n"
                    "  slaac [<if>] [ms]                     RSを送りRAを待つ(IPv6アドレス自動設定)\n"
                    "  slaactest [dump]                      SLAAC(RAを注入してプレフィックス+EUI-64)\n"
                    "  mld [report|leave|off|on]             参加グループ表示/Report送出/離脱/送信停止\n"
                    "  mldtest [dump]                        MLD(Queryを注入してReportを確認)\n"
                    "  ip6addr [<if> <addr>|<if> off]        グローバルIPv6アドレスの表示/手動設定\n"
                    "  txdrop [N]                            ロス注入(データN個に1個破棄、0=無効)+再送統計\n"
                    "  backlog [N]                           listen backlogの深さ表示/変更(0=無効)+統計\n"
                    "  backlogtest                           受け皿の用意前に届いたSYNを拾えるか(陰性対照つき)\n"
                    "  synackdrop [N]                        次のSYN|ACKをN個捨てる(握手のロス注入)\n"
                    "  tcpts [on|off]                        TCP Timestamps(RFC 7323)の有効/無効+統計\n"
                    "  tcptstest                             ロス注入下でRTT推定が更新され続けるか(陰性対照つき)\n"
                    "  tcpsack [on|off]                      SACK(RFC 2018)の有効/無効+統計\n"
                    "  sacktest [N,N..]                      ロス率を振ってSACKとGo-Back-Nの再送数を比べる\n"
                    "  qploop [N]                            RC QPの作成/破棄をN回繰り返しFWリソース枯渇を見る\n"
                    "  nvmediscover [dump]                   Discovery Log Pageを取得(dumpで16進出力)\n"
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

    /* アドレスを使い始める前に重複アドレス検出を行う(IPv4=RFC 5227 の
     * ARP Probe、IPv6=RFC 4862 の DAD)。ハンドラ登録と netif 登録の両方が
     * 済んでいないと応答を受け取れないので、必ずこの位置で呼ぶ。
     * 衝突が無ければ待ち時間ぶん(4 アドレス x 100ms 程度)かかる。 */
    net_dup_addr_detect(netif_find("mlx5-pf0"));
    net_dup_addr_detect(netif_find("mlx5-pf1"));

    /* アドレスの検査が済んだら Router Solicitation を出し、RA が来れば
     * SLAAC でグローバルアドレスを作る(RFC 4861/4862)。**このリンクには
     * ルータが居ないので通常は何も起きない**が、非要請 RA を受け取ったときの
     * 経路と同じものなので、外部にルータが居る構成へ持って行けばそのまま
     * 効く。RS の回数と間隔は ipv6.h の SLAAC_RS_* で短くしてある
     * (RFC 値の 3 回 x 4 秒だと起動が 12 秒延びるだけになる)。 */
    ipv6_slaac_solicit(netif_find("mlx5-pf0"), SLAAC_RS_NUM, SLAAC_RS_INTERVAL_MS);
    ipv6_slaac_solicit(netif_find("mlx5-pf1"), SLAAC_RS_NUM, SLAAC_RS_INTERVAL_MS);

    /* 参加しているマルチキャストグループを MLD で報告する(RFC 2710/3810)。
     * **スヌーピングするスイッチの配下では、これを出さないと要請ノード
     * マルチキャストが転送されず NDP が一切通らない。** アドレスが確定した
     * 後(DAD と SLAAC の後)でなければ報告するグループが決まらないので、
     * 必ずこの位置。 */
    ipv6_mld_report_all(netif_find("mlx5-pf0"));
    ipv6_mld_report_all(netif_find("mlx5-pf1"));

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
