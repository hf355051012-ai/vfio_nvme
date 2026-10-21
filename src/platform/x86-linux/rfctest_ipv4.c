#include <stddef.h>
#include <string.h>
#include "rfctest.h"
#include "uart.h"
#include "net.h"
#include "net_buf.h"
#include "netif.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "ipfrag.h"
#include "timer.h"
#include "arp.h"

/* ---- rfctest ipv4: IPv4 / ICMP / UDP / 断片の組み立てを RFC に合わせた動きの確認 ----
 *
 * 対向 PF(同じリンクのもう一方のインターフェース)に、作った IPv4 のフレームを送らせて、
 * こちら(self)がどう扱うかを見る。どの項目も「直す前の実装では NG になる」形にしてある。 */

#define RT4_PORT_OPEN   7790u   /* self で待ち受けるポート */
#define RT4_PORT_CLOSED 7791u   /* self で待ち受けないポート */
#define RT4_PORT_PEER   7792u   /* peer 側で待ち受け、ICMP エラーを受けるポート */

static volatile unsigned s_rx_count;
static volatile size_t   s_rx_len;
static volatile int      s_rx_dst_bcast;
static volatile unsigned s_err_count;
static volatile uint16_t s_err_remote_port;
static volatile uint8_t  s_err_type, s_err_code;

static void rt4_rx(const uint8_t *data, size_t len, const netaddr_t *src, uint16_t src_port,
                   const netaddr_t *dst, const uint8_t *src_mac)
{
    (void)data; (void)src; (void)src_port; (void)src_mac;
    s_rx_count++;
    s_rx_len = len;
    s_rx_dst_bcast = (dst && dst->family == NETADDR_V4 && dst->a[3] == 0xFFu);
}

static void rt4_err(const netaddr_t *remote, uint16_t remote_port, uint16_t local_port,
                    uint8_t type, uint8_t code, int v6)
{
    (void)remote; (void)local_port; (void)v6;
    s_err_count++;
    s_err_remote_port = remote_port;
    s_err_type = type;
    s_err_code = code;
}

static void rt4_poll(uint32_t ms)
{
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, ms); ) net_poll_all_and_dispatch();
}

/*=================================================================
 * アクティブなインターフェース(peer)から、中身を自由に振った IPv4 のフレームを 1 個送る。
 *
 * 引数:
 *   dst_mac   - Ethernet の宛先
 *   src / dst - IP の送信元 / 宛先(ホストバイトオーダー)
 *   ihl       - ヘッダの長さ(32 ビット単位。5 より大きければ NOP で埋める)
 *   flags_frag - フラグとオフセット(8 バイト単位)
 *   id / proto
 *   body / len - IP のペイロード
 * ===============================================================*/
static int rt4_send_raw(const uint8_t dst_mac[6], uint32_t src, uint32_t dst, unsigned ihl,
                        uint16_t flags_frag, uint16_t id, uint8_t proto,
                        const uint8_t *body, size_t len)
{
    net_buf_t *nb = net_buf_alloc();
    if (!nb) return -1;
    uint8_t self_mac[6];
    eth_get_mac(self_mac);
    volatile uint8_t *o = nb->data;
    for (unsigned i = 0; i < 6u; i++) { o[i] = dst_mac[i]; o[6u + i] = self_mac[i]; }
    o[12] = 0x08; o[13] = 0x00;
    volatile uint8_t *h = o + ETH_HDR_LEN;
    size_t hl = (size_t)ihl * 4u;
    for (size_t i = 0; i < hl; i++) h[i] = (i >= 20u) ? 0x01u : 0u;   /* オプションは NOP(1) */
    h[0] = (uint8_t)(0x40u | ihl);
    wr16be(h + 2, (uint16_t)(hl + len));
    wr16be(h + 4, id);
    wr16be(h + 6, flags_frag);
    h[8] = 64; h[9] = proto;
    wr32be(h + 12, src);
    wr32be(h + 16, dst);
    wr16be(h + 10, inet_checksum(h, hl));
    for (size_t i = 0; i < len; i++) h[hl + i] = body[i];
    nb->len = (uint16_t)(ETH_HDR_LEN + hl + len);
    return eth_send(nb);
}

/* UDP のデータグラム(ヘッダ + ペイロード)を buf に組む。チェックサムは 0(IPv4 では省略可)。 */
static size_t rt4_udp(uint8_t *buf, uint16_t sport, uint16_t dport, size_t payload)
{
    wr16be(buf, sport); wr16be(buf + 2, dport);
    wr16be(buf + 4, (uint16_t)(8u + payload)); wr16be(buf + 6, 0);
    for (size_t i = 0; i < payload; i++) buf[8u + i] = (uint8_t)(i * 7u + 3u);
    return 8u + payload;
}

void rfctest_ipv4(const char *args)
{
    while (*args == ' ') args++;
    int long_test = (strncmp(args, "timeout", 7) == 0);

    uint8_t peer_ll[16];
    netif_t *peer = rfctest_peer(peer_ll);
    netif_t *self = g_active_ctx;
    if (!peer || !self) {
        uart_printf("rfctest ipv4: 対向インターフェースが見つかりません\n");
        return;
    }
    static uint8_t buf[24000];
    const uint8_t bcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    int ok = 1;

    netif_activate(self);
    udp_bind(RT4_PORT_OPEN, rt4_rx);
    netif_activate(peer);
    udp_bind(RT4_PORT_PEER, rt4_rx);
    udp_set_error_handler(RT4_PORT_PEER, rt4_err);
    ipfrag_reset();

    /* ---- [1] 全長より後ろの断片で、穴の残った組み立てを完成扱いにしない(RFC 791)----
     * 最終断片(off=4096, len=8, MF=0)と、全長より後ろの断片(off=4104, MF=1)を送る。
     * 直す前は「埋まった数」が足りて、ページの無い位置を読んでいた。 */
    {
        uint32_t c0, d0, c1, d1;
        ipfrag_stats(&c0, &d0, NULL, NULL);
        size_t n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_OPEN, 0);
        (void)n;
        for (size_t i = 0; i < 520u; i++) buf[i] = (uint8_t)i;
        netif_activate(peer);
        s_rx_count = 0;
        rt4_send_raw(self->mac, peer->ip, self->ip, 5, (uint16_t)(4096u / 8u), 0x4141, IP_PROTO_UDP, buf, 8);
        for (unsigned k = 0; k < 64u; k++) {
            rt4_send_raw(self->mac, peer->ip, self->ip, 5,
                         (uint16_t)(0x2000u | ((4104u + k * 8u) / 8u)), 0x4141, IP_PROTO_UDP, buf, 8);
        }
        netif_activate(self);
        rt4_poll(60);
        ipfrag_stats(&c1, &d1, NULL, NULL);
        int good = (c1 == c0) && (d1 > d0) && s_rx_count == 0u;
        uart_printf("rfctest ipv4: %s [1] 全長より後ろの断片 -- 完成 %u 個(期待 0)、破棄 +%u\n",
                    good ? "OK" : "NG", c1 - c0, d1 - d0);
        if (!good) ok = 0;
        ipfrag_reset();
    }

    /* ---- [2] オプション付きのヘッダ(IHL=7、NOP 8 バイト)も受け取る(RFC 1122 3.2.1.8)---- */
    {
        size_t n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_OPEN, 32);
        s_rx_count = 0;
        netif_activate(peer);
        rt4_send_raw(self->mac, peer->ip, self->ip, 7, 0, 0x4242, IP_PROTO_UDP, buf, n);
        netif_activate(self);
        rt4_poll(40);
        int good = (s_rx_count == 1u && s_rx_len == 32u);
        uart_printf("rfctest ipv4: %s [2] IHL=7 のデータグラムを受け取る(%u 個、%u バイト)\n",
                    good ? "OK" : "NG", s_rx_count, (unsigned)s_rx_len);
        if (!good) ok = 0;
    }

    /* ---- [3] 正しくない送信元(ブロードキャスト / マルチキャスト / 0)からのデータグラムは
     * 黙って捨て、ICMP エラーも返さない(RFC 1122 3.2.1.3 / 3.2.2)---- */
    {
        const uint32_t bad[3] = { 0xFFFFFFFFu, ip_from_octets(224, 0, 0, 5), 0u };
        size_t n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_CLOSED, 8);
        uint32_t e0 = g_icmp_err_sent;
        s_rx_count = 0;
        netif_activate(peer);
        for (unsigned k = 0; k < 3u; k++) {
            rt4_send_raw(self->mac, bad[k], self->ip, 5, 0, (uint16_t)(0x4300u + k), IP_PROTO_UDP, buf, n);
        }
        n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_OPEN, 8);
        rt4_send_raw(self->mac, 0xFFFFFFFFu, self->ip, 5, 0, 0x4303, IP_PROTO_UDP, buf, n);
        netif_activate(self);
        rt4_poll(40);
        int good = (g_icmp_err_sent == e0) && s_rx_count == 0u;
        uart_printf("rfctest ipv4: %s [3] 正しくない送信元 -- ICMP エラー %u 個、受け取り %u 個(期待 0 / 0)\n",
                    good ? "OK" : "NG", g_icmp_err_sent - e0, s_rx_count);
        if (!good) ok = 0;
    }

    /* ---- [4] リンク層のブロードキャストで届いた、IP の宛先が自分だけのものは捨てる
     * (RFC 1122 3.3.6)。待ち受けの無いポート宛てでも ICMP エラーを返さない ---- */
    {
        size_t n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_OPEN, 8);
        uint32_t e0 = g_icmp_err_sent;
        s_rx_count = 0;
        netif_activate(peer);
        rt4_send_raw(bcast_mac, peer->ip, self->ip, 5, 0, 0x4401, IP_PROTO_UDP, buf, n);
        n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_CLOSED, 8);
        rt4_send_raw(bcast_mac, peer->ip, self->ip, 5, 0, 0x4402, IP_PROTO_UDP, buf, n);
        netif_activate(self);
        rt4_poll(40);
        int good = (s_rx_count == 0u) && (g_icmp_err_sent == e0);
        uart_printf("rfctest ipv4: %s [4] L2 ブロードキャストで自分宛て -- 受け取り %u 個 / ICMP エラー %u 個"
                    "(期待 0 / 0)\n", good ? "OK" : "NG", s_rx_count, g_icmp_err_sent - e0);
        if (!good) ok = 0;
    }

    /* ---- [5] IP のブロードキャスト宛ての UDP は受け取り、待ち受けの無いポートでも ICMP エラーを
     * 返さない(RFC 1122 3.3.6 / 3.2.2)---- */
    {
        size_t n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_OPEN, 16);
        uint32_t e0 = g_icmp_err_sent;
        s_rx_count = 0; s_rx_dst_bcast = 0;
        netif_activate(peer);
        rt4_send_raw(bcast_mac, peer->ip, 0xFFFFFFFFu, 5, 0, 0x4501, IP_PROTO_UDP, buf, n);
        n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_CLOSED, 16);
        rt4_send_raw(bcast_mac, peer->ip, 0xFFFFFFFFu, 5, 0, 0x4502, IP_PROTO_UDP, buf, n);
        netif_activate(self);
        rt4_poll(40);
        /* 自分(peer)のブロードキャストが自分にも返ってくる(この装置の性質)ので、受け取りは 1 個以上。 */
        int good = (s_rx_count >= 1u) && s_rx_dst_bcast && (g_icmp_err_sent == e0);
        uart_printf("rfctest ipv4: %s [5] ブロードキャスト宛て -- 受け取り %u 個(宛先をハンドラへ渡す=%d)/"
                    " ICMP エラー %u 個\n", good ? "OK" : "NG", s_rx_count, s_rx_dst_bcast,
                    g_icmp_err_sent - e0);
        if (!good) ok = 0;
    }

    /* ---- [6] チェックサムの壊れた Echo Request には答えない(RFC 792)---- */
    {
        uint8_t icmp[16] = { ICMP_TYPE_ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8 };
        wr16be(icmp + 2, (uint16_t)(inet_checksum(icmp, sizeof(icmp)) ^ 0x0101u));
        unsigned core = 0;
        uint32_t r0 = 0;
        for (core = 0; core < SMP_MAX_CORES; core++) r0 += g_icmp_echo_reply_sent_count[core];
        netif_activate(peer);
        rt4_send_raw(self->mac, peer->ip, self->ip, 5, 0, 0x4601, IP_PROTO_ICMP, icmp, sizeof(icmp));
        netif_activate(self);
        rt4_poll(40);
        uint32_t r1 = 0;
        for (core = 0; core < SMP_MAX_CORES; core++) r1 += g_icmp_echo_reply_sent_count[core];
        uart_printf("rfctest ipv4: %s [6] チェックサムの壊れた Echo Request -- 応答 %u 個(期待 0)\n",
                    (r1 == r0) ? "OK" : "NG", r1 - r0);
        if (r1 != r0) ok = 0;
    }

    /* ---- [7] 20000 バイトの Echo Request(断片で届く)にも全部答える(RFC 1122 3.2.2.6)---- */
    {
        static uint8_t big[20008];
        big[0] = ICMP_TYPE_ECHO_REQUEST; big[1] = 0; big[2] = 0; big[3] = 0;
        wr16be(big + 4, 0x7777); wr16be(big + 6, 1);
        for (size_t i = 8; i < sizeof(big); i++) big[i] = (uint8_t)(i * 13u);
        wr16be(big + 2, inet_checksum(big, sizeof(big)));
        uint32_t r0 = 0, r1 = 0;
        for (unsigned c = 0; c < SMP_MAX_CORES; c++) r0 += g_icmp_echo_reply_sent_count[c];
        uint8_t sip[4] = { (uint8_t)(self->ip >> 24), (uint8_t)(self->ip >> 16),
                           (uint8_t)(self->ip >> 8), (uint8_t)self->ip };
        netif_activate(peer);
        ip_send(sip, self->mac, IP_PROTO_ICMP, big, (uint16_t)sizeof(big));
        netif_activate(self);
        rt4_poll(200);
        for (unsigned c = 0; c < SMP_MAX_CORES; c++) r1 += g_icmp_echo_reply_sent_count[c];
        uart_printf("rfctest ipv4: %s [7] 20008 バイトの Echo Request -- 応答 %u 個(期待 1)\n",
                    (r1 - r0 == 1u) ? "OK" : "NG", r1 - r0);
        if (r1 - r0 != 1u) ok = 0;
    }

    /* ---- [8] TCP のヘッダには DF を立て、UDP / ICMP には立てない(RFC 1191 6.5)---- */
    {
        static uint8_t hb[ETH_HDR_LEN + 20u];
        uint8_t dip[4] = { 192, 168, 101, 1 }, dmac[6] = { 0 };
        netif_activate(self);
        ip_build_header(hb, dip, dmac, IP_PROTO_TCP, 100);
        int df = (rd16be(hb + ETH_HDR_LEN + 6u) & 0x4000u) != 0u;
        uart_printf("rfctest ipv4: %s [8] TCP の IP ヘッダに DF が立つ(%d)\n", df ? "OK" : "NG", df);
        if (!df) ok = 0;
    }

    /* ---- [9] 断片で届いた UDP の Port Unreachable は、組み立て後の姿と UDP ヘッダを引用する
     * (RFC 792 / RFC 1122 3.2.2)。peer 側の UDP のエラーハンドラに届き、相手のポートが
     * 正しく読めることで確かめる(直す前は最後の断片のヘッダと途中の 8 バイトを引用していた)---- */
    {
        size_t n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_CLOSED, 3000);
        s_err_count = 0; s_err_remote_port = 0;
        netif_activate(peer);
        /* 先頭 1480 バイトと残りの 2 つに分けて送る。 */
        rt4_send_raw(self->mac, peer->ip, self->ip, 5, 0x2000u, 0x4901, IP_PROTO_UDP, buf, 1480);
        rt4_send_raw(self->mac, peer->ip, self->ip, 5, (uint16_t)(1480u / 8u), 0x4901, IP_PROTO_UDP,
                     buf + 1480, n - 1480u);
        netif_activate(self);
        rt4_poll(100);
        netif_activate(peer);
        rt4_poll(20);
        netif_activate(self);
        int good = (s_err_count >= 1u && s_err_remote_port == RT4_PORT_CLOSED &&
                    s_err_type == ICMP_TYPE_DEST_UNREACH && s_err_code == ICMP_CODE_PORT_UNREACH);
        uart_printf("rfctest ipv4: %s [9] 断片で届いた UDP の Port Unreachable -- エラー %u 個、"
                    "引用から読んだ相手のポート %u(期待 %u)\n", good ? "OK" : "NG",
                    s_err_count, s_err_remote_port, RT4_PORT_CLOSED);
        if (!good) ok = 0;
    }

    /* ---- [10] 組み立ての時間切れで Time Exceeded(code 1)を返す(RFC 1122 3.3.2)----
     * 60 秒かかるので `rfctest ipv4 timeout` のときだけ。 */
    if (long_test) {
        size_t n = rt4_udp(buf, RT4_PORT_PEER, RT4_PORT_OPEN, 200);
        s_err_count = 0;
        netif_activate(peer);
        rt4_send_raw(self->mac, peer->ip, self->ip, 5, 0x2000u, 0x4A01, IP_PROTO_UDP, buf, 104);
        netif_activate(self);
        (void)n;
        uart_printf("rfctest ipv4: [10] 先頭の断片だけ送った。%u 秒待ちます\n",
                    (unsigned)(IPFRAG_TIMEOUT_MS / 1000u + 1u));
        rt4_poll(IPFRAG_TIMEOUT_MS + 1000u);
        /* 回収は次の断片が来たときに行うので、関係のない断片を 1 個送って回収させる。 */
        netif_activate(peer);
        rt4_send_raw(self->mac, peer->ip, self->ip, 5, 0x2000u, 0x4A02, IP_PROTO_UDP, buf, 8);
        netif_activate(self);
        rt4_poll(50);
        netif_activate(peer);
        rt4_poll(20);
        netif_activate(self);
        int good = (s_err_count >= 1u && s_err_type == ICMP_TYPE_TIME_EXCEEDED && s_err_code == 1u);
        uart_printf("rfctest ipv4: %s [10] 組み立ての時間切れ -- peer が受けた ICMP %u 個(type %u code %u、"
                    "期待 11 / 1)\n", good ? "OK" : "NG", s_err_count, s_err_type, s_err_code);
        if (!good) ok = 0;
        ipfrag_reset();
    }

    /* ---- [11] Redirect(RFC 1122 3.2.2.2)----
     * self のゲートウェイを peer にし、サブネットの外(10.9.9.9)宛ての Redirect を受ける。
     * いまの次ホップ(peer)から来たものは受け入れ、別の送信元(.50 を名乗る)からのものは捨てる。 */
    {
        uint32_t sv_mask = self->netmask, sv_gw = self->gateway;
        uint8_t sv_cnt = self->gw4_cnt, sv_dcnt = self->dest4_cnt;
        const uint32_t far = ip_from_octets(10, 9, 9, 9);
        const uint32_t new_gw = ip_from_octets(192, 168, 101, 77);
        self->netmask = 0xFFFFFF00u; self->gateway = peer->ip; self->gw4_cnt = 0; self->dest4_cnt = 0;
        uint8_t red[8 + 28];
        memset(red, 0, sizeof(red));
        red[0] = ICMP_TYPE_REDIRECT; red[1] = 1;
        wr32be(red + 4, new_gw);
        uint8_t *q = red + 8;
        q[0] = 0x45; wr16be(q + 2, 48); q[8] = 64; q[9] = IP_PROTO_UDP;
        wr32be(q + 12, self->ip); wr32be(q + 16, far);
        wr16be(red + 2, inet_checksum(red, sizeof(red)));
        netif_activate(peer);
        /* 偽物: 次ホップでない .50 を名乗る。 */
        rt4_send_raw(self->mac, ip_from_octets(192, 168, 101, 50), self->ip, 5, 0, 0x4B01,
                     IP_PROTO_ICMP, red, sizeof(red));
        netif_activate(self);
        rt4_poll(40);
        uint32_t nh_bad = netif_next_hop4(self, far);
        netif_activate(peer);
        rt4_send_raw(self->mac, peer->ip, self->ip, 5, 0, 0x4B02, IP_PROTO_ICMP, red, sizeof(red));
        netif_activate(self);
        rt4_poll(40);
        uint32_t nh_ok = netif_next_hop4(self, far);
        int good = (nh_bad == peer->ip) && (nh_ok == new_gw);
        uart_printf("rfctest ipv4: %s [11] Redirect -- 次ホップでない送信元のものは捨てる(%d)、"
                    "次ホップからのものは受け入れる(%d)\n", good ? "OK" : "NG",
                    nh_bad == peer->ip, nh_ok == new_gw);
        if (!good) ok = 0;

        /* ---- [12] ゲートウェイの候補が 2 つあり、使っているものに届かなければ次へ切り替える
         * (RFC 1122 3.3.1.2 / 3.3.1.4)。誰も名乗っていない .99 を先にしておく ---- */
        const uint32_t dead = ip_from_octets(192, 168, 101, 99);
        self->dest4_cnt = 0;
        self->gw4_list[0] = dead; self->gw4_list[1] = peer->ip; self->gw4_cnt = 2;
        self->gateway = dead;
        uint8_t mac[6];
        arp_resolve(dead, mac);   /* 1 秒待って失敗する */
        int switched = (self->gateway == peer->ip);
        uart_printf("rfctest ipv4: %s [12] 届かないゲートウェイから次の候補へ切り替える(%d)\n",
                    switched ? "OK" : "NG", switched);
        if (!switched) ok = 0;

        self->netmask = sv_mask; self->gateway = sv_gw; self->gw4_cnt = sv_cnt; self->dest4_cnt = sv_dcnt;
    }

    netif_activate(peer);
    udp_unbind(RT4_PORT_PEER);
    netif_activate(self);
    udp_unbind(RT4_PORT_OPEN);
    uart_printf("rfctest ipv4: %s\n", ok ? "PASS" : "NG");
}
