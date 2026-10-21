#include "rfctest.h"
#include "uart.h"
#include "tcp.h"
#include "netif.h"
#include "netaddr.h"
#include "net.h"
#include "timer.h"
#include "smp.h"

/*=================================================================
 * シェルの `rfctest tcp`。RFC 9293 ほかに合わせて直した TCP の動きを、対向 PF との
 * 自作どうしの接続で確かめる。正しい相手は送ってこない形のセグメント(まだ送って
 * いないものへの ACK、窓の外のデータ、確立済みの 4-tuple への SYN、MSS 0 の SYN|ACK ..)は
 * tcp_debug_inject() / tcp_debug_inject_to() で相手を騙って撃ち込む。
 *
 * 項目(番号は直した項目の番号):
 *   [1]  SND.NXT を越える ACK で snd_una が進まない(陰性対照: ACK = SND.NXT は捨てない)
 *   [2]  受信窓の外のデータを受け取らない(陽性対照: 窓の中の順序外は受け取る)
 *   [25] ACK ビットの無いセグメントを捨てる
 *   [4]  穴の向こうの FIN は穴が埋まるまで処理しない。埋まったら CLOSE_WAIT、データは全部届く
 *   [6]  確立済みの 4-tuple への SYN に challenge ACK を返し、2 つ目の TCB を作らない
 *   [8]  ISN が時計そのものではない(RFC 6528)
 *   [9]  一時ポートが範囲内で、続けて張っても重ならず、既存の接続とも重ならない(RFC 6056)
 *   [14a] 待ち受け(受け皿なし・待ち行列 0)への SYN には RST を返さない(従来どおり黙って捨てる)
 *   [24] SYN_SENT で受け入れられない ACK の SYN|ACK に RST を返し、SYN_SENT のまま
 *   [10] MSS 0 の SYN|ACK で落ちず、snd_mss が下限(88)以上
 *   [14b] 待ち受けのポートへの ACK 付きセグメント(接続の無いもの)に RST を返す
 *   [27] Keepalive の既定が無効
 * 結果は「rfctest tcp: OK [n] ...」と最後の「rfctest tcp: PASS / NG」。
 * ===============================================================*/

static unsigned s_ng;

static void rt_res(int ok, const char *num, const char *msg)
{
    uart_printf("rfctest tcp: %s [%s] %s\n", ok ? "OK" : "NG", num, msg);
    if (!ok) s_ng++;
}

/* 時間で動く処理も含めて ms ミリ秒ポーリングする。 */
static void rt_pump(uint32_t ms)
{
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, ms); ) tcp_poll();
}

static uint32_t rt_sum(volatile uint32_t *a)
{
    uint32_t s = 0;
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) s += a[c];
    return s;
}

/*=================================================================
 * self(クライアント)から peer(サーバ)の port へ IPv4 で接続し、両側が ESTABLISHED に
 * なるまで回す。listener_out に待ち受けのハンドルを返す。
 * ===============================================================*/
static int rt_establish(netif_t *self, netif_t *peer, uint16_t port,
                        tcp_conn_t *cli, tcp_conn_t *srv, int *listener_out)
{
    *listener_out = -1;
    int l = tcp_listen(port, peer);
    if (l < 0) return 0;
    *listener_out = l;
    srv->state = TCP_CLOSED;
    cli->state = TCP_CLOSED;
    tcp_accept_begin(l, srv);
    netif_activate(self);
    netaddr_t dst = netaddr_v4(peer->ip);
    tcp_connect_begin_to(cli, &dst, port);
    int est = 0;
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 3000u); ) {
        netif_activate(self);
        int r = tcp_connect_poll(cli);
        net_poll_all_and_dispatch();
        netif_activate(peer);
        tcp_accept_ready_poll(l);
        if (r == 1) { est = 1; break; }
        if (r < 0) break;
    }
    netif_activate(self);
    if (!est) return 0;
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, 500u) && srv->state != TCP_ESTABLISHED; ) tcp_poll();
    netif_activate(self);
    return srv->state == TCP_ESTABLISHED;
}

void rfctest_tcp(const char *args)
{
    (void)args;
    s_ng = 0;

    uint8_t peer_ll[16];
    netif_t *peer = rfctest_peer(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("rfctest tcp: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    const netaddr_t peer4 = netaddr_v4(peer->ip);
    const netaddr_t self4 = netaddr_v4(self->ip);
    uart_printf("rfctest tcp: client=%s server=%s\n", self->name, peer->name);

    /* ---- [27] Keepalive の既定 ---- */
    rt_res(g_tcp_keepalive_enable == 0u, "27", "Keepalive の既定は無効(新しい接続は tcp_set_keepalive() で有効にする)");

    /* ---- 確立した 1 本で [1] [2] [25] [6] [4] ---- */
    static tcp_conn_t cli, srv, extra;
    int listener = -1;
    const uint16_t port = 6021u;
    if (!rt_establish(self, peer, port, &cli, &srv, &listener)) {
        rt_res(0, "1-6", "検査用の接続を張れない");
        if (listener >= 0) tcp_unlisten(listener);
        uart_printf("rfctest tcp: NG\n");
        return;
    }
    uart_printf("rfctest tcp: 接続確立 (client port %u -> %u)\n", (unsigned)cli.local_port, (unsigned)port);

    /* [1] SND.NXT を越える ACK */
    {
        const uint32_t una_gap0 = tcp_unacked_bytes(&cli);
        const uint32_t d0 = g_tcp_ack_unsent_drop;
        tcp_debug_inject(&cli, TCP_FLAG_ACK, cli.rcv_seq, tcp_snd_max(&cli) + 1000u, 0xFFFFu, NULL, 0);
        netif_activate(self);
        rt_pump(100);
        const int ok = (tcp_unacked_bytes(&cli) == una_gap0) && (g_tcp_ack_unsent_drop > d0) &&
                       (cli.state == TCP_ESTABLISHED);
        uart_printf("rfctest tcp:   未確認 %u -> %u、捨てた数 %u -> %u\n", (unsigned)una_gap0,
                    (unsigned)tcp_unacked_bytes(&cli), (unsigned)d0, (unsigned)g_tcp_ack_unsent_drop);
        rt_res(ok, "1", "SND.NXT + 1000 への ACK を捨て、snd_una を進めない");
        const uint32_t d1 = g_tcp_ack_unsent_drop;
        tcp_debug_inject(&cli, TCP_FLAG_ACK, cli.rcv_seq, tcp_snd_max(&cli), 0xFFFFu, NULL, 0);
        netif_activate(self);
        rt_pump(100);
        rt_res(g_tcp_ack_unsent_drop == d1 && cli.state == TCP_ESTABLISHED, "1b",
               "陰性対照: ACK = SND.NXT は捨てない");
    }

    /* [2] 受信窓の外のデータ */
    const uint32_t r0 = cli.rcv_seq;
    static uint8_t pat[256];
    for (unsigned i = 0; i < sizeof(pat); i++) pat[i] = (uint8_t)(i * 13u + 7u);
    {
        const uint32_t o0 = g_tcp_rx_oow_drop;
        tcp_debug_inject(&cli, TCP_FLAG_ACK | TCP_FLAG_PSH, r0 + 0x10000000u, cli.snd_seq, 0xFFFFu, pat, 64);
        netif_activate(self);
        rt_pump(100);
        rt_res(cli.rcv_seq == r0 && g_tcp_rx_oow_drop > o0 && cli.state == TCP_ESTABLISHED, "2",
               "RCV.NXT + 256MB のデータを受け取らずに捨てる");
        /* 陽性対照: 窓の中の順序外 [r0+100, r0+164) は置き場に入る(これは [4] の材料にもなる)。 */
        const uint32_t ooo0 = rt_sum(g_tcp_rx_ooo);
        const uint32_t o1 = g_tcp_rx_oow_drop;
        tcp_debug_inject(&cli, TCP_FLAG_ACK | TCP_FLAG_PSH, r0 + 100u, cli.snd_seq, 0xFFFFu, pat + 100, 64);
        netif_activate(self);
        rt_pump(100);
        rt_res(rt_sum(g_tcp_rx_ooo) > ooo0 && g_tcp_rx_oow_drop == o1 && cli.rcv_seq == r0, "2b",
               "陽性対照: 窓の中の順序外のデータは受け取る(rcv_seq はまだ進まない)");
    }

    /* [25] ACK ビットの無いセグメント */
    {
        const uint32_t n0 = g_tcp_noack_drop;
        tcp_debug_inject(&cli, TCP_FLAG_PSH, r0, 0u, 0xFFFFu, pat, 10);
        netif_activate(self);
        rt_pump(100);
        rt_res(g_tcp_noack_drop > n0 && cli.rcv_seq == r0, "25", "ACK ビットの無いデータを捨てる");
    }

    /* [6] 確立済みの 4-tuple への SYN(サーバ側)。もう 1 つ受け皿を用意し、そこへ 2 つ目の TCB が
     * できないことを見る。 */
    {
        extra.state = TCP_CLOSED;
        tcp_accept_begin(listener, &extra);
        const uint32_t c0 = g_tcp_syn_challenge;
        tcp_debug_inject(&srv, TCP_FLAG_SYN, 0x12345678u, 0u, 0xFFFFu, NULL, 0);
        netif_activate(self);
        rt_pump(100);
        const int ok = (g_tcp_syn_challenge > c0) && (extra.state == TCP_CLOSED) &&
                       (srv.state == TCP_ESTABLISHED);
        rt_res(ok, "6", "確立済みの 4-tuple への SYN に challenge ACK、2 つ目の TCB を作らない");
        if (tcp_accept_cancel(listener, &extra)) tcp_close(&extra);
    }

    /* [4] 穴の向こうの FIN。[r0+100, r0+164) は [2b] で置き場にある。[r0+164, r0+200) + FIN を送り、
     * まだ CLOSE_WAIT にならないこと、[r0, r0+100) で穴を埋めると CLOSE_WAIT になり、
     * 200 バイトが順に読めることを見る。 */
    {
        tcp_debug_inject(&cli, TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_FIN, r0 + 164u, cli.snd_seq, 0xFFFFu,
                         pat + 164, 36);
        netif_activate(self);
        rt_pump(100);
        rt_res(cli.state == TCP_ESTABLISHED && cli.rcv_seq == r0, "4a",
               "穴の向こうの FIN では CLOSE_WAIT にならない");
        tcp_debug_inject(&cli, TCP_FLAG_ACK | TCP_FLAG_PSH, r0, cli.snd_seq, 0xFFFFu, pat, 100);
        netif_activate(self);
        rt_pump(100);
        uint8_t got[256];
        uint32_t n = 0;
        for (uint64_t t0 = timer_now(); n < 200u && !timeout_ms(t0, 500u); ) {
            int k = tcp_recv(&cli, got + n, 256u - n, 20u);
            if (k > 0) n += (uint32_t)k;
            else if (k == 0) break;
        }
        int same = (n == 200u);
        for (uint32_t i = 0; same && i < 200u; i++) if (got[i] != pat[i]) same = 0;
        uart_printf("rfctest tcp:   state=%d rcv_seq=r0+%u 読めた %u バイト\n",
                    (int)cli.state, (unsigned)(cli.rcv_seq - r0), (unsigned)n);
        rt_res(cli.state == TCP_CLOSE_WAIT && cli.rcv_seq == r0 + 201u && same, "4b",
               "穴が埋まると FIN を処理して CLOSE_WAIT、データ 200 バイトは順に一致");
    }

    /* [9] の一部: 既存の接続(cli)と同じ相手・同じポートへ張るとき、cli のポートを使わない。 */
    uint16_t cli_port = cli.local_port;

    /* 後始末。撃ち込んだデータでクライアントの rcv_seq はサーバの送った量より先へ進んでいる
     * (サーバから見るとまだ送っていないものへの ACK = [1] の検査で捨てられる)ので、普通に
     * FIN を交わすと FIN の再送の上限まで待つ。サーバを正しい seq の RST で先に閉じ、
     * クライアントの FIN には待ち受けのポートからの RST([14b] と同じ)で応えさせる。 */
    tcp_debug_inject_rst(&srv, srv.rcv_seq);
    netif_activate(self);
    rt_pump(100);
    netif_activate(self);  tcp_close(&cli);
    netif_activate(peer);  tcp_close(&srv);
    tcp_unlisten(listener);
    netif_activate(self);

    /* ---- [8] [9] ISN と一時ポート ---- */
    {
        static tcp_conn_t c;
        const uint16_t dead = 6022u;
        uint32_t isn[2]; uint16_t lp[2]; uint64_t tb[2], ta[2];
        for (unsigned k = 0; k < 2u; k++) {
            c.state = TCP_CLOSED;
            netif_activate(self);
            tb[k] = timer_now();
            tcp_connect_begin_to(&c, &peer4, dead);
            ta[k] = timer_now();
            isn[k] = c.snd_seq;
            lp[k]  = c.local_port;
            for (uint64_t t0 = timer_now(); !timeout_ms(t0, 1000u); ) {
                netif_activate(self);
                int r = tcp_connect_poll(&c);
                net_poll_all_and_dispatch();
                if (r != 0) break;
            }
            if (c.state != TCP_CLOSED) tcp_close(&c);
        }
        int clockish = 0;
        for (unsigned k = 0; k < 2u; k++) {
            const uint32_t lo = (uint32_t)tb[k], hi = (uint32_t)ta[k];
            if ((uint32_t)(isn[k] - lo) <= (uint32_t)(hi - lo)) clockish = 1;   /* 旧: ISN = timer_now() */
        }
        const int32_t delta = (int32_t)((isn[1] - isn[0]) - (uint32_t)((tb[1] - tb[0]) >> 12));
        const int stride_random = (delta > 1000000 || delta < -1000000);
        uart_printf("rfctest tcp:   ISN %u / %u、ポート %u / %u(既存の接続のポート %u)\n",
                    (unsigned)isn[0], (unsigned)isn[1], (unsigned)lp[0], (unsigned)lp[1], (unsigned)cli_port);
        rt_res(!clockish && stride_random, "8", "ISN が時計そのものでなく、4-tuple ごとに鍵付きのずらしが入る");
        const int in_range = lp[0] >= 49152u && lp[1] >= 49152u;
        rt_res(in_range && lp[0] != lp[1] && lp[0] != cli_port && lp[1] != cli_port, "9",
               "一時ポートが 49152 以上で、続けて張っても既存の接続とも重ならない");
    }

    /* ---- [14a] [24] [10] [14b] 受け皿の無い待ち受けを相手に ---- */
    {
        static tcp_conn_t c3;
        const uint16_t lport = 6023u;
        const unsigned saved_backlog = g_tcp_backlog_max;
        int l2 = tcp_listen(lport, peer);
        if (l2 < 0) {
            rt_res(0, "10", "tcp_listen 失敗");
        } else {
            tcp_backlog_set_max(0);
            const uint32_t ovf0 = g_tcp_backlog_overflow_count;
            const uint32_t lr0  = g_tcp_listen_rst;
            c3.state = TCP_CLOSED;
            netif_activate(self);
            tcp_connect_begin_to(&c3, &peer4, lport);
            for (uint64_t t0 = timer_now(); !timeout_ms(t0, 150u); ) {
                netif_activate(self);
                (void)tcp_connect_poll(&c3);
                net_poll_all_and_dispatch();
            }
            netif_activate(self);
            rt_res(g_tcp_backlog_overflow_count > ovf0 && g_tcp_listen_rst == lr0 && c3.state == TCP_SYN_SENT,
                   "14a", "受け皿も待ち行列も無い待ち受けへの SYN は黙って捨てる(RST を返さない)");

            /* [24] 自分の SYN を確認しない SYN|ACK */
            const uint32_t sr0 = g_tcp_synsent_rst;
            tcp_debug_inject_to(&peer4, lport, &self4, c3.local_port,
                                TCP_FLAG_SYN | TCP_FLAG_ACK, 777u, c3.snd_seq + 5u, 1460);
            netif_activate(self);
            rt_pump(100);
            rt_res(g_tcp_synsent_rst > sr0 && c3.state == TCP_SYN_SENT, "24",
                   "SYN_SENT で受け入れられない ACK の SYN|ACK に RST を返し、SYN_SENT のまま");

            /* [10] MSS 0 の SYN|ACK。確立した後の ACK は接続の無い待ち受けのポートへ行くので、
             * [14b] の RST が返ってきて閉じる。 */
            tcp_debug_inject_to(&peer4, lport, &self4, c3.local_port,
                                TCP_FLAG_SYN | TCP_FLAG_ACK, 777u, c3.snd_seq + 1u, 0);
            int est = 0;
            for (uint64_t t0 = timer_now(); !timeout_ms(t0, 300u); ) {
                netif_activate(self);
                int r = tcp_connect_poll(&c3);
                net_poll_all_and_dispatch();
                if (r == 1) est = 1;
                if (r != 0) break;
            }
            netif_activate(self);
            rt_pump(100);
            uart_printf("rfctest tcp:   MSS 0 の SYN|ACK の後 snd_mss=%u state=%d\n",
                        (unsigned)c3.snd_mss, (int)c3.state);
            rt_res(c3.snd_mss >= 88u && (est || c3.state == TCP_CLOSED), "10",
                   "MSS 0 の SYN|ACK でも落ちず、snd_mss は下限 88 以上");
            rt_res(g_tcp_listen_rst > lr0 && c3.state == TCP_CLOSED, "14b",
                   "待ち受けのポートへの ACK 付きセグメント(接続なし)に RST を返す");
            if (c3.state != TCP_CLOSED) tcp_close(&c3);
            tcp_backlog_set_max(saved_backlog);
            tcp_unlisten(l2);
        }
    }

    netif_activate(self);
    uart_printf("rfctest tcp: %s\n", s_ng == 0 ? "PASS" : "NG");
}
