#include <stddef.h>
#include <stdint.h>
#include "rfctest.h"
#include "uart.h"
#include "netif.h"
#include "net.h"
#include "net_buf.h"
#include "netaddr.h"
#include "ipv6.h"
#include "ipfrag.h"
#include "pmtu.h"
#include "timer.h"
#include "udp.h"
#include "smp.h"

/* ==== `rfctest ipv6`:IPv6 を RFC に合わせて直した動きを確かめる ====
 *
 * 対向 PF(rfctest_peer())に「相手のノード」の役をさせ、作ったパケットを送らせて
 * こちら(アクティブなインターフェース = self)の反応を見る。**相手が自作の送信経路で
 * 素直に出せない形**(断片で運ぶ NDP、送信元がマルチキャスト、途中の Hop-by-Hop、
 * はみ出したオプション、Redirect など)を作るので、IPv6 ヘッダから自分で組んで
 * eth_send() する。
 *
 * 試験の前後で self の IPv6 の状態(アドレス・ルータ・プレフィックス・宛先キャッシュ・
 * hop limit・MLD の再送)を控えて戻す。プレフィックスは 2001:db8:0:6x::/64(文書用)。 */

static int      s_ok;
static netif_t *s_self;
static netif_t *s_peer;
static uint8_t  s_self_ll[16];
static uint8_t  s_peer_ll[16];

/* ---- self の状態の控え ---- */
typedef struct {
    uint8_t  g[16], g_set, g_plen, g_ra, g_dad;
    uint64_t g_valid, g_pref, g_dadu;
    uint8_t  gw[16], gw_set, gw_ra;
    uint64_t gw_valid;
    uint32_t ra_mtu;
    uint8_t  hop;
    netif_ip6addr_t extra[NETIF_IP6_EXTRA];
    uint8_t  extra_cnt;
    netif_prefix6_t pfx[NETIF_PREFIX6_MAX];
    uint8_t  pfx_cnt;
    netif_router6_t rt[NETIF_ROUTER6_MAX];
    uint8_t  rt_cnt;
    netif_dest6_t dest[NETIF_DEST6_MAX];
    uint8_t  dest_cnt;
} rt_state_t;

static void rt_save(const netif_t *n, rt_state_t *s)
{
    for (unsigned i = 0; i < 16u; i++) { s->g[i] = n->ip6_global[i]; s->gw[i] = n->gateway6[i]; }
    s->g_set = n->ip6_global_set; s->g_plen = n->ip6_prefix_len; s->g_ra = n->ip6_global_from_ra;
    s->g_dad = n->ip6_global_dad; s->g_valid = n->ip6_global_valid_until;
    s->g_pref = n->ip6_global_pref_until; s->g_dadu = n->ip6_global_dad_until;
    s->gw_set = n->gateway6_set; s->gw_ra = n->gateway6_from_ra; s->gw_valid = n->gateway6_valid_until;
    s->ra_mtu = n->ra_link_mtu; s->hop = n->ra_cur_hop_limit;
    for (unsigned i = 0; i < NETIF_IP6_EXTRA; i++) s->extra[i] = n->ip6_extra[i];
    s->extra_cnt = n->ip6_extra_cnt;
    for (unsigned i = 0; i < NETIF_PREFIX6_MAX; i++) s->pfx[i] = n->prefix6[i];
    s->pfx_cnt = n->prefix6_cnt;
    for (unsigned i = 0; i < NETIF_ROUTER6_MAX; i++) s->rt[i] = n->router6[i];
    s->rt_cnt = n->router6_cnt;
    for (unsigned i = 0; i < NETIF_DEST6_MAX; i++) s->dest[i] = n->dest6[i];
    s->dest_cnt = n->dest6_cnt;
}

static void rt_restore(netif_t *n, const rt_state_t *s)
{
    for (unsigned i = 0; i < 16u; i++) { n->ip6_global[i] = s->g[i]; n->gateway6[i] = s->gw[i]; }
    n->ip6_global_set = s->g_set; n->ip6_prefix_len = s->g_plen; n->ip6_global_from_ra = s->g_ra;
    n->ip6_global_dad = s->g_dad; n->ip6_global_valid_until = s->g_valid;
    n->ip6_global_pref_until = s->g_pref; n->ip6_global_dad_until = s->g_dadu;
    n->gateway6_set = s->gw_set; n->gateway6_from_ra = s->gw_ra; n->gateway6_valid_until = s->gw_valid;
    n->ra_link_mtu = s->ra_mtu; n->ra_cur_hop_limit = s->hop;
    for (unsigned i = 0; i < NETIF_IP6_EXTRA; i++) n->ip6_extra[i] = s->extra[i];
    n->ip6_extra_cnt = s->extra_cnt;
    for (unsigned i = 0; i < NETIF_PREFIX6_MAX; i++) n->prefix6[i] = s->pfx[i];
    n->prefix6_cnt = s->pfx_cnt;
    for (unsigned i = 0; i < NETIF_ROUTER6_MAX; i++) n->router6[i] = s->rt[i];
    n->router6_cnt = s->rt_cnt;
    for (unsigned i = 0; i < NETIF_DEST6_MAX; i++) n->dest6[i] = s->dest[i];
    n->dest6_cnt = s->dest_cnt;
    n->mld_rep_left = 0;
    n->mld_leave_left = 0;
}

/* 試験の各段の前提を揃える: SLAAC の状態・ルータ・プレフィックス・宛先キャッシュを空にする。 */
static void rt_clear_v6(netif_t *n)
{
    n->ip6_global_set = 0; n->ip6_global_from_ra = 0; n->ip6_global_valid_until = 0;
    n->ip6_global_pref_until = 0; n->ip6_global_dad = NETIF_DAD_UNKNOWN;
    n->ip6_extra_cnt = 0; n->prefix6_cnt = 0; n->router6_cnt = 0; n->dest6_cnt = 0;
    n->gateway6_set = 0; n->gateway6_from_ra = 0; n->gateway6_valid_until = 0;
    n->mld_rep_left = 0; n->mld_leave_left = 0;
    n->ra_cur_hop_limit = 0;
}

/* ---- 小道具 ---- */

static int rt_eq16(const uint8_t *a, const uint8_t *b)
{
    for (unsigned i = 0; i < 16u; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static void rt_pfx(uint8_t out[16], uint8_t x)
{
    for (unsigned i = 0; i < 16u; i++) out[i] = 0;
    out[0] = 0x20; out[1] = 0x01; out[2] = 0x0d; out[3] = 0xb8; out[7] = x;
}

/* プレフィックス 2001:db8:0:x::/64 + self の EUI-64(SLAAC が作るはずのアドレス)。 */
static void rt_slaac_addr(uint8_t out[16], uint8_t x)
{
    rt_pfx(out, x);
    for (unsigned i = 8u; i < 16u; i++) out[i] = s_self_ll[i];
}

static void rt_mcast_mac(const uint8_t a[16], uint8_t mac[6])
{
    mac[0] = 0x33; mac[1] = 0x33; mac[2] = a[12]; mac[3] = a[13]; mac[4] = a[14]; mac[5] = a[15];
}

static void rt_poll(uint32_t ms)
{
    for (uint64_t t0 = timer_now(); !timeout_ms(t0, ms); ) {
        net_poll_all_and_dispatch();
        ipv6_timer_tick();
    }
    netif_activate(s_self);
}

static uint32_t rt_sum(volatile uint32_t *a)
{
    uint32_t s = 0;
    for (unsigned i = 0; i < SMP_MAX_CORES; i++) s += a[i];
    return s;
}

/*=================================================================
 * from から IPv6 パケットを 1 個送る。ヘッダは ipv6_build_header() で組み、hop limit を
 * 書き換え、ペイロード(拡張ヘッダを含む)をそのまま後ろへ置く。
 * ===============================================================*/
static int rt_send(netif_t *from, const uint8_t src[16], const uint8_t dst[16],
                   const uint8_t dst_mac[6], uint8_t hop, uint8_t nh,
                   const uint8_t *pl, uint16_t len)
{
    netif_t *prev = g_active_ctx;
    netif_activate(from);
    net_buf_t *nb = net_buf_alloc();
    if (!nb) { netif_activate(prev); return -1; }
    ipv6_build_header(nb->data, src, dst, dst_mac, nh, len);
    nb->data[ETH_HDR_LEN + offsetof(ipv6_header_t, hop_limit)] = hop;
    for (unsigned i = 0; i < len; i++) nb->data[ETH_HDR_LEN + IPV6_HDR_LEN + i] = pl[i];
    nb->len = (uint16_t)(ETH_HDR_LEN + IPV6_HDR_LEN + len);
    int r = eth_send(nb);
    netif_activate(prev);
    return r;
}

/* peer -> self(リンクローカル同士、hop 255)。 */
static int rt_p2s(uint8_t nh, const uint8_t *pl, uint16_t len)
{
    return rt_send(s_peer, s_peer_ll, s_self_ll, s_self->mac, 255u, nh, pl, len);
}

/* UDP データグラムを組む(チェックサムは最終の宛先と next header 17 で)。 */
static uint16_t rt_udp(uint8_t *out, const uint8_t src[16], const uint8_t dst[16],
                       uint16_t sport, uint16_t dport, unsigned dlen)
{
    uint16_t ulen = (uint16_t)(8u + dlen);
    wr16be(out + 0, sport); wr16be(out + 2, dport); wr16be(out + 4, ulen); wr16be(out + 6, 0);
    for (unsigned i = 0; i < dlen; i++) out[8u + i] = (uint8_t)(0x30u + i);
    uint16_t c = ipv6_pseudo_checksum(src, dst, IPV6_NH_UDP, out, ulen);
    wr16be(out + 6, c ? c : 0xFFFFu);
    return ulen;
}

static void rt_icmp_csum(uint8_t *m, uint16_t len, const uint8_t src[16], const uint8_t dst[16])
{
    wr16be(m + 2, 0);
    wr16be(m + 2, ipv6_pseudo_checksum(src, dst, IPV6_NH_ICMPV6, m, len));
}

/* Echo Request(8 + 16 バイト)を組む。 */
static uint16_t rt_echo(uint8_t *m, const uint8_t src[16], const uint8_t dst[16], uint16_t seq)
{
    for (unsigned i = 0; i < 24u; i++) m[i] = (uint8_t)i;
    m[0] = ICMPV6_TYPE_ECHO_REQUEST; m[1] = 0;
    wr16be(m + 4, 0x7E57u); wr16be(m + 6, seq);
    rt_icmp_csum(m, 24u, src, dst);
    return 24u;
}

typedef struct { uint8_t x; uint8_t flags; uint32_t valid; uint32_t pref; } rt_pio_t;

/*=================================================================
 * peer から self へ RA を送る(送信元 src は自由に選べる。送信元 MAC は peer)。
 * ===============================================================*/
static int rt_ra(const uint8_t src[16], uint16_t rlife, uint8_t curhop,
                 const rt_pio_t *pio, unsigned npio)
{
    static uint8_t m[16u + 8u + 32u * 3u];
    if (npio > 3u) npio = 3u;
    unsigned len = 16u + 8u + 32u * npio;
    for (unsigned i = 0; i < len; i++) m[i] = 0;
    m[0] = ICMPV6_TYPE_RA;
    m[RA_OFF_CUR_HOP_LIMIT] = curhop;
    wr16be(m + RA_OFF_ROUTER_LIFETIME, rlife);
    m[16] = NDP_OPT_SRC_LLADDR; m[17] = 1u;
    for (unsigned i = 0; i < 6u; i++) m[18u + i] = s_peer->mac[i];
    for (unsigned k = 0; k < npio; k++) {
        uint8_t *p = m + 24u + 32u * k;
        p[0] = NDP_OPT_PREFIX_INFO; p[1] = 4u;
        p[PIO_OFF_PREFIX_LEN] = 64u;
        p[PIO_OFF_FLAGS] = pio[k].flags;
        wr32be(p + PIO_OFF_VALID, pio[k].valid);
        wr32be(p + PIO_OFF_PREFERRED, pio[k].pref);
        rt_pfx(p + PIO_OFF_PREFIX, pio[k].x);
    }
    rt_icmp_csum(m, (uint16_t)len, src, s_self_ll);
    return rt_send(s_peer, src, s_self_ll, s_self->mac, 255u, IPV6_NH_ICMPV6, m, (uint16_t)len);
}

/* ---- 観測フック ---- */

static unsigned s_udp_rx;
static void rt_udp_handler(const uint8_t *data, size_t len, const netaddr_t *src,
                           uint16_t src_port, const netaddr_t *dst, const uint8_t *src_mac)
{
    (void)data; (void)len; (void)src; (void)src_port; (void)dst; (void)src_mac;
    s_udp_rx++;
}

static unsigned s_mld_seen;
static void rt_mld_obs(const uint8_t *msg, unsigned len, const uint8_t dst[16])
{
    (void)msg; (void)len; (void)dst;
    if (g_active_ctx == s_self) s_mld_seen++;
}

static uint8_t  s_tx_hop;
static uint8_t  s_tx_type;
static unsigned s_tx_seen;
static void rt_tx_obs(uint8_t hop, uint8_t nh, const uint8_t *payload, uint16_t len)
{
    if (g_active_ctx != s_self) return;
    s_tx_hop  = hop;
    s_tx_type = (nh == IPV6_NH_ICMPV6 && len) ? payload[0] : 0u;
    s_tx_seen++;
}

#define RT_FRAG_MAX 16u
static uint32_t s_frag_id[RT_FRAG_MAX];
static unsigned s_frag_n;
static void rt_frag_obs(uint32_t id, uint16_t off, int more, uint8_t nh,
                        const uint8_t *payload, uint16_t len)
{
    (void)off; (void)more; (void)nh; (void)payload; (void)len;
    if (s_frag_n < RT_FRAG_MAX) s_frag_id[s_frag_n++] = id;
}

/* peer が受けた ICMPv6 のエラーを待つ。戻り値は増えた数。 */
static uint32_t rt_err_wait(uint32_t before, uint32_t ms)
{
    rt_poll(ms);
    return g_icmpv6_err_rx - before;
}

#define RT_PORT 7791u   /* 試験で待ち受けるポート */

/*=================================================================
 * シェルの `rfctest ipv6`。RFC に合わせて直した動きを確かめる。
 * 項目の番号は直した項目の番号(報告書と同じ)。
 * ===============================================================*/
void rfctest_ipv6(const char *args)
{
    (void)args;
    s_self = g_active_ctx;
    s_peer = rfctest_peer(s_peer_ll);
    if (!s_self || !s_peer) {
        uart_printf("rfctest ipv6: 対向インターフェースが見つかりません(net init mlx5 が必要)\n");
        return;
    }
    netif_activate(s_self);
    ipv6_link_local_addr(s_self_ll);
    s_ok = 1;

    rt_state_t saved;
    rt_save(s_self, &saved);
    rt_clear_v6(s_self);
    if (udp_bind(RT_PORT, rt_udp_handler) != 0) {
        uart_printf("rfctest ipv6: udp_bind 失敗\n");
        return;
    }
    /* 相手(peer)の MAC を self の近隣キャッシュへ入れておく(エラーの返送や Echo Reply が
     * 解決待ちにならないように)。 */
    ndp_cache_insert(s_peer_ll, s_peer->mac);
    uart_printf("rfctest ipv6: self=%s peer=%s\n", s_self->name, s_peer->name);

    uint8_t pl[512];
    uint8_t a1[16], a2[16], a3[16], a4[16];
    rt_slaac_addr(a1, 0x61); rt_slaac_addr(a2, 0x62);
    rt_slaac_addr(a3, 0x63); rt_slaac_addr(a4, 0x64);

    /* ---- [1] SLAAC のアドレスは DAD が済むまで使わない(RFC 4862 5.4)---- */
    {
        rt_pio_t p1 = { 0x61, PIO_FLAG_AUTO, 1800u, 1800u };   /* A のみ(L=0) */
        uint32_t ns_before = rt_sum(g_ipv6_ns_count);
        rt_ra(s_peer_ll, 0u, 0u, &p1, 1u);
        rt_poll(10u);
        int tent = s_self->ip6_global_set && rt_eq16(s_self->ip6_global, a1) &&
                   s_self->ip6_global_dad == NETIF_DAD_TENTATIVE;
        int not_ours = !ipv6_addr_is_ours(a1);
        /* DAD 中のアドレスへの NS には答えない(5.4.3)。 */
        uint8_t m[32];
        for (unsigned i = 0; i < 32u; i++) m[i] = 0;
        m[0] = ICMPV6_TYPE_NS;
        for (unsigned i = 0; i < 16u; i++) m[8u + i] = a1[i];
        m[24] = NDP_OPT_SRC_LLADDR; m[25] = 1u;
        for (unsigned i = 0; i < 6u; i++) m[26u + i] = s_peer->mac[i];
        uint8_t sol[16], solmac[6];
        ipv6_solicited_node_addr(a1, sol);
        rt_mcast_mac(sol, solmac);
        rt_icmp_csum(m, 32u, s_peer_ll, sol);
        rt_send(s_peer, s_peer_ll, sol, solmac, 255u, IPV6_NH_ICMPV6, m, 32u);
        rt_poll(20u);
        int no_na = (rt_sum(g_ipv6_ns_count) == ns_before);
        rt_poll(200u);
        int passed = ipv6_addr_is_ours(a1) && s_self->ip6_global_dad == NETIF_DAD_PASSED;
        int good = tent && not_ours && no_na && passed;
        uart_printf("rfctest ipv6: %s [1] SLAAC のアドレスは DAD 中は使わず(TENTATIVE=%d 自分宛て=%d "
                    "NS に答えない=%d)、%ums 後に使い始める(=%d)\n", good ? "OK" : "NG",
                    tent, !not_ours, no_na, IPV6_SLAAC_DAD_MS, passed);
        if (!good) s_ok = 0;

        /* 衝突: 2 つ目のプレフィックスの RA の直後に、そのアドレスの NA を相手が出す。 */
        rt_pio_t p2 = { 0x62, PIO_FLAG_AUTO, 1800u, 1800u };
        rt_ra(s_peer_ll, 0u, 0u, &p2, 1u);
        rt_poll(5u);
        int was_tent = 0;
        for (unsigned i = 0; i < s_self->ip6_extra_cnt; i++) {
            if (rt_eq16(s_self->ip6_extra[i].addr, a2) &&
                s_self->ip6_extra[i].dad == NETIF_DAD_TENTATIVE) was_tent = 1;
        }
        const uint8_t bogus[6] = { 0x02, 0x00, 0x00, 0x00, 0xD1, 0xD2 };
        uint8_t all_nodes[16] = { 0xff, 0x02, 0,0,0,0,0,0,0,0,0,0,0,0,0, 0x01 };
        uint8_t an_mac[6];
        rt_mcast_mac(all_nodes, an_mac);
        for (unsigned i = 0; i < 32u; i++) m[i] = 0;
        m[0] = ICMPV6_TYPE_NA; m[4] = 0x20u;   /* O のみ */
        for (unsigned i = 0; i < 16u; i++) m[8u + i] = a2[i];
        m[24] = NDP_OPT_TGT_LLADDR; m[25] = 1u;
        for (unsigned i = 0; i < 6u; i++) m[26u + i] = bogus[i];
        rt_icmp_csum(m, 32u, s_peer_ll, all_nodes);
        rt_send(s_peer, s_peer_ll, all_nodes, an_mac, 255u, IPV6_NH_ICMPV6, m, 32u);
        rt_poll(200u);
        int still = 0;
        for (unsigned i = 0; i < s_self->ip6_extra_cnt; i++) {
            if (rt_eq16(s_self->ip6_extra[i].addr, a2)) still = 1;
        }
        int dupmac = 1;
        for (unsigned i = 0; i < 6u; i++) if (s_self->dup_mac6[i] != bogus[i]) dupmac = 0;
        good = was_tent && !still && dupmac && !ipv6_addr_is_ours(a2);
        uart_printf("rfctest ipv6: %s [1b] DAD 中に同じアドレスの NA が来たら衝突として使わない"
                    "(DAD 中だった=%d 外れた=%d 相手の MAC を記録=%d)\n", good ? "OK" : "NG",
                    was_tent, !still, dupmac);
        if (!good) s_ok = 0;
    }

    /* ---- [11] 複数の Prefix Information は別の枠に入る ---- */
    {
        rt_pio_t pp[2] = { { 0x63, PIO_FLAG_AUTO, 1800u, 1800u },
                           { 0x64, PIO_FLAG_AUTO, 1800u, 1800u } };
        rt_ra(s_peer_ll, 0u, 0u, pp, 2u);
        rt_poll(250u);
        int good = rt_eq16(s_self->ip6_global, a1) && s_self->ip6_global_set &&
                   ipv6_addr_is_ours(a1) && ipv6_addr_is_ours(a3) && ipv6_addr_is_ours(a4);
        uart_printf("rfctest ipv6: %s [11] 3 つのプレフィックスのアドレスを全部持つ(1 つ目は上書き"
                    "されない。2 つ目以降 %u 個)\n", good ? "OK" : "NG", s_self->ip6_extra_cnt);
        if (!good) s_ok = 0;

        /* rule 8: 宛先とプレフィックスが一致するアドレスを送信元にする。 */
        uint8_t d4[16], src[16];
        rt_pfx(d4, 0x64); d4[15] = 0x99;
        ipv6_source_for(d4, src);
        int r8 = rt_eq16(src, a4);
        /* ---- [26] グローバルスコープのマルチキャスト宛てはグローバルアドレスから ---- */
        uint8_t mg[16] = { 0xff, 0x0e, 0,0,0,0,0,0,0,0,0,0,0,0,0, 0x01 };
        uint8_t ml[16] = { 0xff, 0x02, 0,0,0,0,0,0,0,0,0,0,0,0,0, 0x01 };
        uint8_t sg[16], sl[16];
        ipv6_source_for(mg, sg);
        ipv6_source_for(ml, sl);
        int r26 = (sg[0] == 0x20) && rt_eq16(sl, s_self_ll);
        uart_printf("rfctest ipv6: %s [11b] 送信元はプレフィックスが一致するアドレス(RFC 6724 rule 8)\n",
                    r8 ? "OK" : "NG");
        uart_printf("rfctest ipv6: %s [26] ff0e::1 宛てはグローバル、ff02::1 宛てはリンクローカルから"
                    "(RFC 6724 rule 2)\n", r26 ? "OK" : "NG");
        if (!r8 || !r26) s_ok = 0;

        /* ---- [23] 推奨寿命が切れたアドレスは新しい通信の送信元にしない ---- */
        uint8_t dfar[16];
        rt_pfx(dfar, 0x99); dfar[15] = 0x01;
        uint8_t before[16], after[16];
        ipv6_source_for(dfar, before);
        rt_pio_t dep = { 0x61, PIO_FLAG_AUTO, 1800u, 0u };   /* 1 つ目を deprecated に */
        rt_ra(s_peer_ll, 0u, 0u, &dep, 1u);
        rt_poll(50u);
        ipv6_source_for(dfar, after);
        good = rt_eq16(before, a1) && !rt_eq16(after, a1) && after[0] == 0x20 &&
               ipv6_addr_is_ours(a1);
        uart_printf("rfctest ipv6: %s [23] preferred=0 の 1 つ目は送信元に使わない(前=1 つ目 %d / "
                    "後=別のアドレス %d / 受信は続ける %d)\n", good ? "OK" : "NG",
                    rt_eq16(before, a1), !rt_eq16(after, a1), ipv6_addr_is_ours(a1));
        if (!good) s_ok = 0;
    }

    /* ---- [5] on-link の判定(RFC 4861 5.2 / 6.3.4、RFC 5942)---- */
    {
        rt_pio_t pl5 = { 0x65, PIO_FLAG_ONLINK, 1800u, 1800u };   /* L のみ */
        rt_ra(s_peer_ll, 1800u, 0u, &pl5, 1u);
        rt_poll(50u);
        uint8_t d5[16], d1[16], dfar[16];
        rt_pfx(d5, 0x65); d5[15] = 0x05;
        rt_pfx(d1, 0x61); d1[15] = 0x05;
        rt_pfx(dfar, 0x99); dfar[15] = 0x05;
        int gw = s_self->gateway6_set && s_self->gateway6_from_ra && rt_eq16(s_self->gateway6, s_peer_ll);
        int on5  = (netif_next_hop6(s_self, d5) == d5);
        int off1 = (netif_next_hop6(s_self, d1) == s_self->gateway6);     /* A=1 L=0 は on-link でない */
        int offf = (netif_next_hop6(s_self, dfar) == s_self->gateway6);
        /* 手動設定のアドレスのプレフィックスは on-link(1 つ目を手動に見せかけて確かめる)。 */
        s_self->ip6_global_from_ra = 0;
        int man = (netif_next_hop6(s_self, d1) == d1);
        s_self->ip6_global_from_ra = 1;
        int good = gw && on5 && off1 && offf && man;
        uart_printf("rfctest ipv6: %s [5] on-link 判定(ルータ=%d L=1 は直接=%d A のみは経由=%d "
                    "外は経由=%d 手動のプレフィックスは直接=%d)\n", good ? "OK" : "NG",
                    gw, on5, off1, offf, man);
        if (!good) s_ok = 0;
    }

    /* ---- [7] デフォルトルータの一覧(RFC 4861 6.3.4 / 6.3.6)---- */
    {
        uint8_t r2[16];
        for (unsigned i = 0; i < 16u; i++) r2[i] = 0;
        r2[0] = 0xfe; r2[1] = 0x80; r2[14] = 0x02; r2[15] = 0x02;
        rt_ra(r2, 1800u, 0u, NULL, 0u);
        rt_poll(50u);
        int two  = (s_self->router6_cnt == 2u) && rt_eq16(s_self->gateway6, s_peer_ll);
        rt_ra(s_peer_ll, 0u, 0u, NULL, 0u);   /* 今のルータが寿命 0 */
        rt_poll(50u);
        int sw   = (s_self->router6_cnt == 1u) && s_self->gateway6_set && rt_eq16(s_self->gateway6, r2);
        rt_ra(r2, 0u, 0u, NULL, 0u);
        rt_poll(50u);
        int none = (s_self->router6_cnt == 0u) && !s_self->gateway6_set;
        int good = two && sw && none;
        uart_printf("rfctest ipv6: %s [7] ルータを 2 つ覚え(=%d)、今のものが外れると次へ切り替わり"
                    "(=%d)、全部外れると無し(=%d)\n", good ? "OK" : "NG", two, sw, none);
        if (!good) s_ok = 0;
    }

    /* ---- [6] Redirect(RFC 4861 8.1 / 8.3)---- */
    {
        rt_ra(s_peer_ll, 1800u, 0u, NULL, 0u);
        rt_poll(50u);
        uint8_t dst[16], dst2[16], tgt[16], fake[16];
        rt_pfx(dst, 0x77); dst[15] = 0x01;
        rt_pfx(dst2, 0x77); dst2[15] = 0x02;
        for (unsigned i = 0; i < 16u; i++) { tgt[i] = 0; fake[i] = 0; }
        tgt[0] = 0xfe; tgt[1] = 0x80; tgt[14] = 0xbe; tgt[15] = 0xef;
        fake[0] = 0xfe; fake[1] = 0x80; fake[14] = 0x09; fake[15] = 0x09;
        const uint8_t tmac[6] = { 0x02, 0x00, 0x00, 0x00, 0xBE, 0xEF };
        uint8_t m[48];
        uint32_t rc0 = g_ipv6_redirect_count;
        int pre = (netif_next_hop6(s_self, dst) == s_self->gateway6);

        /* 組む関数(src から、hop で) */
        #define RT_REDIRECT(SRC, HOP, TGT, DST)                                        \
            do {                                                                         \
                for (unsigned i_ = 0; i_ < 48u; i_++) m[i_] = 0;                        \
                m[0] = ICMPV6_TYPE_REDIRECT;                                             \
                for (unsigned i_ = 0; i_ < 16u; i_++) {                                  \
                    m[REDIRECT_OFF_TARGET + i_] = (TGT)[i_];                             \
                    m[REDIRECT_OFF_DEST + i_]   = (DST)[i_];                             \
                }                                                                        \
                m[40] = NDP_OPT_TGT_LLADDR; m[41] = 1u;                                  \
                for (unsigned i_ = 0; i_ < 6u; i_++) m[42u + i_] = tmac[i_];             \
                rt_icmp_csum(m, 48u, (SRC), s_self_ll);                                  \
                rt_send(s_peer, (SRC), s_self_ll, s_self->mac, (HOP), IPV6_NH_ICMPV6,    \
                        m, 48u);                                                         \
            } while (0)

        RT_REDIRECT(fake, 255u, tgt, dst);        /* 今の次ホップでない送信元 */
        RT_REDIRECT(s_peer_ll, 64u, tgt, dst);    /* hop limit が 255 でない */
        rt_poll(50u);
        int neg = (g_ipv6_redirect_count == rc0) && (netif_next_hop6(s_self, dst) == s_self->gateway6);
        RT_REDIRECT(s_peer_ll, 255u, tgt, dst);   /* 正しいもの: 別のルータへ */
        RT_REDIRECT(s_peer_ll, 255u, dst2, dst2); /* 正しいもの: 相手は on-link */
        rt_poll(50u);
        const uint8_t *nh1 = netif_next_hop6(s_self, dst);
        const uint8_t *nh2 = netif_next_hop6(s_self, dst2);
        int pos = rt_eq16(nh1, tgt) && rt_eq16(nh2, dst2) && (g_ipv6_redirect_count == rc0 + 2u);
        #undef RT_REDIRECT
        int good = pre && neg && pos;
        uart_printf("rfctest ipv6: %s [6] Redirect(ルータ以外 / hop 64 は無視=%d、ルータからのものは"
                    "宛先キャッシュへ=%d)\n", good ? "OK" : "NG", neg, pos);
        if (!good) s_ok = 0;
        s_self->dest6_cnt = 0;
        rt_ra(s_peer_ll, 0u, 0u, NULL, 0u);
        rt_poll(50u);
    }

    /* ---- [2] 断片で運ばれた NDP は捨てる(RFC 6980)/ [4] 原子断片はその場で処理 ---- */
    {
        const uint8_t bogus[6] = { 0x02, 0x00, 0x00, 0x00, 0xEE, 0x02 };
        ndp_cache_insert(s_peer_ll, s_peer->mac);
        uint32_t ns_before = rt_sum(g_ipv6_ns_count);
        /* Fragment(原子断片)+ NS(Target = self、Source Link-Layer = bogus) */
        for (unsigned i = 0; i < 40u; i++) pl[i] = 0;
        pl[0] = IPV6_NH_ICMPV6; wr32be(pl + 4, 0x51515151u);
        uint8_t *m = pl + 8;
        m[0] = ICMPV6_TYPE_NS;
        for (unsigned i = 0; i < 16u; i++) m[8u + i] = s_self_ll[i];
        m[24] = NDP_OPT_SRC_LLADDR; m[25] = 1u;
        for (unsigned i = 0; i < 6u; i++) m[26u + i] = bogus[i];
        rt_icmp_csum(m, 32u, s_peer_ll, s_self_ll);
        rt_p2s(IPV6_NH_FRAGMENT, pl, 40u);
        rt_poll(50u);
        uint8_t mac[6];
        ndp_cache_lookup(s_peer_ll, mac);
        int kept = 1;
        for (unsigned i = 0; i < 6u; i++) if (mac[i] != s_peer->mac[i]) kept = 0;
        int ign = (rt_sum(g_ipv6_ns_count) == ns_before);
        /* 陽性対照: 原子断片の Echo Request には答える(断片の経路そのものは生きている)。 */
        uint32_t rep0 = rt_sum(g_ipv6_echo_reply_count);
        for (unsigned i = 0; i < 8u; i++) pl[i] = 0;
        pl[0] = IPV6_NH_ICMPV6; wr32be(pl + 4, 0x52525252u);
        rt_echo(pl + 8, s_peer_ll, s_self_ll, 1u);
        rt_p2s(IPV6_NH_FRAGMENT, pl, 8u + 24u);
        rt_poll(50u);
        int echo = (rt_sum(g_ipv6_echo_reply_count) != rep0);
        int good = kept && ign && echo;
        uart_printf("rfctest ipv6: %s [2] 断片で運ばれた NS は捨てる(MAC 不変=%d 処理しない=%d)、"
                    "陽性対照: 原子断片の Echo には答える=%d\n", good ? "OK" : "NG", kept, ign, echo);
        if (!good) s_ok = 0;

        /* [4][19] 原子断片 + Destination Options + UDP。表に入れず、Fragment ヘッダの後ろの
         * 拡張ヘッダも辿って届く。同じ識別子の先頭断片(組み立て中)が居ても混ざらない。 */
        uint32_t comp0 = 0, act0 = 0, comp1 = 0, act1 = 0, act_mid = 0;
        ipfrag_stats(&comp0, NULL, NULL, &act0);
        /* 先頭断片(M=1、識別子 0x4444):Fragment + UDP 16 バイト(8 の倍数) */
        for (unsigned i = 0; i < 8u; i++) pl[i] = 0;
        pl[0] = IPV6_NH_UDP; wr16be(pl + 2, IPV6_FRAG_MORE); wr32be(pl + 4, 0x4444u);
        rt_udp(pl + 8, s_peer_ll, s_self_ll, RT_PORT, RT_PORT, 8u);
        wr16be(pl + 8 + 4, 200u);   /* 全体はもっと長いと名乗る(続きは来ない) */
        rt_p2s(IPV6_NH_FRAGMENT, pl, 8u + 16u);
        rt_poll(20u);
        ipfrag_stats(NULL, NULL, NULL, &act_mid);
        unsigned rx0 = s_udp_rx;
        for (unsigned i = 0; i < 16u; i++) pl[i] = 0;
        pl[0] = IPV6_NH_DSTOPTS; wr32be(pl + 4, 0x4444u);          /* Fragment(原子) */
        pl[8] = IPV6_NH_UDP; pl[9] = 0; pl[10] = IPV6_TLV_PADN; pl[11] = 4;   /* DstOpts */
        uint16_t ul = rt_udp(pl + 16, s_peer_ll, s_self_ll, RT_PORT, RT_PORT, 12u);
        rt_p2s(IPV6_NH_FRAGMENT, pl, (uint16_t)(16u + ul));
        rt_poll(50u);
        ipfrag_stats(&comp1, NULL, NULL, &act1);
        int deliv = (s_udp_rx == rx0 + 1u);
        good = deliv && (comp1 == comp0) && (act1 == act_mid) && (act_mid == act0 + 1u);
        uart_printf("rfctest ipv6: %s [4][19] 原子断片は組み立ての表に入れずに届く(届いた=%d 完成数 "
                    "%u->%u 組み立て中 %u->%u->%u)、Fragment の後ろの Destination Options も辿る\n",
                    good ? "OK" : "NG", deliv, comp0, comp1, act0, act_mid, act1);
        if (!good) s_ok = 0;
        ipfrag_reset();
    }

    /* ---- [9][16][17][18] Parameter Problem と Destination Unreachable ----
     * 頻度の制限(10 個 / 秒、10 個まで溜める)に当たらないよう、最初にバケツを満たす。 */
    rt_poll(1100u);
    {
        uint32_t e0;
        /* a) 知らない Next Header(253)-> code 1、Pointer 6 */
        for (unsigned i = 0; i < 16u; i++) pl[i] = (uint8_t)i;
        e0 = g_icmpv6_err_rx;
        rt_p2s(253u, pl, 16u);
        int a = (rt_err_wait(e0, 50u) == 1u) && g_icmpv6_err_rx_type == ICMPV6_TYPE_PARAM_PROBLEM &&
                g_icmpv6_err_rx_code == ICMPV6_CODE_PP_NEXTHDR && g_icmpv6_err_rx_param == 6u;
        /* b) 動作ビット 10 の知らないオプション -> code 2、Pointer 42 */
        pl[0] = IPV6_NH_UDP; pl[1] = 0; pl[2] = 0x81u; pl[3] = 4; pl[4] = pl[5] = pl[6] = pl[7] = 0;
        uint16_t ul = rt_udp(pl + 8, s_peer_ll, s_self_ll, RT_PORT, RT_PORT, 8u);
        e0 = g_icmpv6_err_rx;
        rt_p2s(IPV6_NH_DSTOPTS, pl, (uint16_t)(8u + ul));
        int b = (rt_err_wait(e0, 50u) == 1u) && g_icmpv6_err_rx_code == ICMPV6_CODE_PP_OPTION &&
                g_icmpv6_err_rx_param == 42u;
        /* c) マルチキャスト宛て: 動作ビット 11 は返さない、10 は返す */
        uint8_t an[16] = { 0xff, 0x02, 0,0,0,0,0,0,0,0,0,0,0,0,0, 0x01 };
        uint8_t anmac[6];
        rt_mcast_mac(an, anmac);
        pl[2] = 0xC1u;
        rt_udp(pl + 8, s_peer_ll, an, RT_PORT, RT_PORT, 8u);
        e0 = g_icmpv6_err_rx;
        rt_send(s_peer, s_peer_ll, an, anmac, 64u, IPV6_NH_DSTOPTS, pl, (uint16_t)(8u + ul));
        int c11 = (rt_err_wait(e0, 50u) == 0u);
        pl[2] = 0x81u;
        e0 = g_icmpv6_err_rx;
        rt_send(s_peer, s_peer_ll, an, anmac, 64u, IPV6_NH_DSTOPTS, pl, (uint16_t)(8u + ul));
        int c10 = (rt_err_wait(e0, 50u) >= 1u) && g_icmpv6_err_rx_code == ICMPV6_CODE_PP_OPTION;
        /* d) Segments Left != 0 の Routing -> code 0、Pointer 42(Routing Type) */
        pl[0] = IPV6_NH_UDP; pl[1] = 0; pl[2] = 0; pl[3] = 1;
        for (unsigned i = 4; i < 8u; i++) pl[i] = 0;
        rt_udp(pl + 8, s_peer_ll, s_self_ll, RT_PORT, RT_PORT, 8u);
        e0 = g_icmpv6_err_rx;
        rt_p2s(IPV6_NH_ROUTING, pl, (uint16_t)(8u + ul));
        int d = (rt_err_wait(e0, 50u) == 1u) && g_icmpv6_err_rx_code == ICMPV6_CODE_PP_HEADER &&
                g_icmpv6_err_rx_param == 42u;
        /* e) 待ち受けの無い UDP -> Destination Unreachable code 4。4791(RoCEv2)には返さない */
        ul = rt_udp(pl, s_peer_ll, s_self_ll, 7790u, 7790u, 8u);
        e0 = g_icmpv6_err_rx;
        rt_p2s(IPV6_NH_UDP, pl, ul);
        int e = (rt_err_wait(e0, 50u) == 1u) && g_icmpv6_err_rx_type == ICMPV6_TYPE_DEST_UNREACH &&
                g_icmpv6_err_rx_code == ICMPV6_CODE_PORT_UNREACH;
        ul = rt_udp(pl, s_peer_ll, s_self_ll, UDP_PORT_ROCEV2, UDP_PORT_ROCEV2, 8u);
        e0 = g_icmpv6_err_rx;
        rt_p2s(IPV6_NH_UDP, pl, ul);
        int e4791 = (rt_err_wait(e0, 50u) == 0u);
        /* f) 最後でない断片の長さが 8 の倍数でない -> code 0、Pointer 4 */
        for (unsigned i = 0; i < 8u; i++) pl[i] = 0;
        pl[0] = IPV6_NH_UDP; wr16be(pl + 2, IPV6_FRAG_MORE); wr32be(pl + 4, 0x5555u);
        rt_udp(pl + 8, s_peer_ll, s_self_ll, RT_PORT, RT_PORT, 4u);   /* 12 バイト */
        e0 = g_icmpv6_err_rx;
        rt_p2s(IPV6_NH_FRAGMENT, pl, 8u + 12u);
        int f = (rt_err_wait(e0, 50u) == 1u) && g_icmpv6_err_rx_code == ICMPV6_CODE_PP_HEADER &&
                g_icmpv6_err_rx_param == 4u;
        int good = a && b && c11 && c10 && d && e && e4791 && f;
        uart_printf("rfctest ipv6: %s [9] エラーを返す(知らない NH=%d 動作 10=%d マルチキャスト宛て "
                    "11 は返さない=%d 10 は返す=%d Routing=%d UDP ポート=%d 4791 は返さない=%d "
                    "断片の長さ=%d)\n", good ? "OK" : "NG", a, b, c11, c10, d, e, e4791, f);
        if (!good) s_ok = 0;
    }
    rt_poll(1100u);
    {
        uint32_t e0;
        /* [16] Hop-by-Hop が IPv6 ヘッダの直後でない -> 届かず、code 1、Pointer 40 */
        unsigned rx0 = s_udp_rx;
        pl[0] = IPV6_NH_HOPOPTS; pl[1] = 0; pl[2] = IPV6_TLV_PADN; pl[3] = 4;
        for (unsigned i = 4; i < 8u; i++) pl[i] = 0;
        pl[8] = IPV6_NH_UDP; pl[9] = 0; pl[10] = IPV6_TLV_PADN; pl[11] = 4;
        for (unsigned i = 12; i < 16u; i++) pl[i] = 0;
        uint16_t ul = rt_udp(pl + 16, s_peer_ll, s_self_ll, RT_PORT, RT_PORT, 8u);
        e0 = g_icmpv6_err_rx;
        rt_p2s(IPV6_NH_DSTOPTS, pl, (uint16_t)(16u + ul));
        int g16 = (rt_err_wait(e0, 50u) == 1u) && (s_udp_rx == rx0) &&
                  g_icmpv6_err_rx_code == ICMPV6_CODE_PP_NEXTHDR && g_icmpv6_err_rx_param == 40u;
        /* 陽性対照: 先頭の Hop-by-Hop は届く */
        rx0 = s_udp_rx;
        rt_p2s(IPV6_NH_HOPOPTS, pl + 8, (uint16_t)(8u + ul));
        rt_poll(50u);
        int g16p = (s_udp_rx == rx0 + 1u);
        uart_printf("rfctest ipv6: %s [16] 途中の Hop-by-Hop は捨てて code 1(=%d)、先頭のものは届く(=%d)\n",
                    (g16 && g16p) ? "OK" : "NG", g16, g16p);
        if (!g16 || !g16p) s_ok = 0;

        /* [17] オプションが拡張ヘッダの外へはみ出す -> 捨てる(エラーは返さない) */
        rx0 = s_udp_rx;
        pl[0] = IPV6_NH_UDP; pl[1] = 0; pl[2] = 0x1Eu; pl[3] = 10u;   /* 動作 00、長さ 10 > 残り 4 */
        for (unsigned i = 4; i < 8u; i++) pl[i] = 0;
        ul = rt_udp(pl + 8, s_peer_ll, s_self_ll, RT_PORT, RT_PORT, 8u);
        rt_p2s(IPV6_NH_DSTOPTS, pl, (uint16_t)(8u + ul));
        rt_poll(50u);
        int g17 = (s_udp_rx == rx0);
        pl[3] = 4u;   /* 陽性対照: 収まる長さなら(動作 00 なので)読み飛ばして届く */
        rt_p2s(IPV6_NH_DSTOPTS, pl, (uint16_t)(8u + ul));
        rt_poll(50u);
        int g17p = (s_udp_rx == rx0 + 1u);
        uart_printf("rfctest ipv6: %s [17] はみ出したオプションは捨てる(=%d)、収まれば届く(=%d)\n",
                    (g17 && g17p) ? "OK" : "NG", g17, g17p);
        if (!g17 || !g17p) s_ok = 0;

        /* [18] 先頭の断片が上位のヘッダまでを含まない -> code 3、Pointer 0 */
        for (unsigned i = 0; i < 16u; i++) pl[i] = 0;
        pl[0] = IPV6_NH_DSTOPTS; wr16be(pl + 2, IPV6_FRAG_MORE); wr32be(pl + 4, 0x6666u);
        pl[8] = IPV6_NH_UDP; pl[9] = 0; pl[10] = IPV6_TLV_PADN; pl[11] = 4;   /* DstOpts だけ */
        e0 = g_icmpv6_err_rx;
        rt_p2s(IPV6_NH_FRAGMENT, pl, 16u);
        int g18 = (rt_err_wait(e0, 50u) == 1u) && g_icmpv6_err_rx_code == ICMPV6_CODE_PP_CHAIN &&
                  g_icmpv6_err_rx_param == 0u;
        uart_printf("rfctest ipv6: %s [18] 上位のヘッダを含まない先頭の断片は捨てて code 3(RFC 7112)\n",
                    g18 ? "OK" : "NG");
        if (!g18) s_ok = 0;
    }

    /* ---- [9b] 送る頻度の制限(RFC 4443 2.4(f))---- */
    rt_poll(1100u);
    {
        uint32_t e0 = g_icmpv6_err_rx;
        uint32_t lim0 = g_icmpv6_err_ratelimited;
        for (unsigned k = 0; k < 30u; k++) {
            for (unsigned i = 0; i < 16u; i++) pl[i] = (uint8_t)k;
            rt_p2s(253u, pl, 16u);
            if ((k & 7u) == 7u) rt_poll(1u);   /* 送信の枠を溢れさせない */
        }
        uint32_t got = rt_err_wait(e0, 200u);
        uint32_t lim = g_icmpv6_err_ratelimited - lim0;
        int good = (got >= ICMPV6_ERR_BURST / 2u) && (got <= ICMPV6_ERR_BURST + 4u) && (lim >= 15u);
        uart_printf("rfctest ipv6: %s [9b] 30 個の誘因に返したエラー %u 個(上限 %u 個 + 補充)、"
                    "制限で送らなかった %u 個\n", good ? "OK" : "NG", got, ICMPV6_ERR_BURST, lim);
        if (!good) s_ok = 0;
    }

    /* ---- [15] 断片の識別子は全体で 1 つの数(起点は乱数)---- */
    {
        netaddr_t p6 = netaddr_v6(s_peer_ll);
        pmtu_learn(&p6, 1400u);
        static uint8_t big[3000];
        for (unsigned i = 0; i < sizeof(big); i++) big[i] = (uint8_t)i;
        s_frag_n = 0;
        ipv6_set_frag_observer(rt_frag_obs);
        udp_send6(s_peer_ll, s_peer->mac, RT_PORT, RT_PORT, big, (uint16_t)sizeof(big));
        rt_poll(50u);
        unsigned n1 = s_frag_n;
        uint32_t id1 = n1 ? s_frag_id[0] : 0u;
        udp_send6(s_peer_ll, s_peer->mac, RT_PORT, RT_PORT, big, (uint16_t)sizeof(big));
        rt_poll(50u);
        uint32_t id2 = (s_frag_n > n1) ? s_frag_id[n1] : 0u;
        ipv6_set_frag_observer(NULL);
        pmtu_clear();
        int good = (n1 >= 2u) && (s_frag_n > n1) && (id2 == id1 + 1u) && (id1 > 0xFFFFu);
        uart_printf("rfctest ipv6: %s [15] 断片の識別子 0x%08x -> 0x%08x(1 つずつ進む / 起点が小さい"
                    "値でない)\n", good ? "OK" : "NG", (unsigned)id1, (unsigned)id2);
        if (!good) s_ok = 0;
    }

    /* ---- [21] 長さが 24 でも 28 以上でもない MLD Query は捨てる ---- */
    s_self->mld_rep_left = 0; s_self->mld_leave_left = 0;
    s_peer->mld_rep_left = 0; s_peer->mld_leave_left = 0;
    ipv6_set_mld_observer(rt_mld_obs);
    {
        unsigned res[3];
        const unsigned lens[3] = { 26u, 28u, 24u };
        for (unsigned k = 0; k < 3u; k++) {
            unsigned qlen = lens[k];
            for (unsigned i = 0; i < 8u + qlen; i++) pl[i] = 0;
            pl[0] = IPV6_NH_ICMPV6; pl[1] = 0;
            pl[2] = IPV6_TLV_ROUTER_ALERT; pl[3] = 2; pl[6] = IPV6_TLV_PADN; pl[7] = 0;
            uint8_t *q = pl + 8;
            q[0] = ICMPV6_TYPE_MLD_QUERY;
            wr16be(q + 4, 1000u);
            if (qlen >= 28u) { q[24] = 2u; q[25] = 125u; }
            rt_icmp_csum(q, (uint16_t)qlen, s_peer_ll, s_self_ll);
            s_mld_seen = 0;
            rt_send(s_peer, s_peer_ll, s_self_ll, s_self->mac, 1u, IPV6_NH_HOPOPTS, pl,
                    (uint16_t)(8u + qlen));
            rt_poll(100u);
            res[k] = s_mld_seen;
            if (k == 1u) {
                /* [22] の前に v1 互換モードが残っていないこと */
                ipv6_mld_clear_v1_mode();
            }
        }
        int g21 = (res[0] == 0u) && (res[1] >= 1u);
        uart_printf("rfctest ipv6: %s [21] 長さ 26 の Query は捨てる(Report %u 通)、28 には答える"
                    "(%u 通)\n", g21 ? "OK" : "NG", res[0], res[1]);
        if (!g21) s_ok = 0;

        /* ---- [22] v1 互換モードはインターフェースごと(最後の 24 バイトの Query は self だけへ)---- */
        netif_activate(s_self);
        int v1s = ipv6_mld_v1_mode();
        netif_activate(s_peer);
        int v1p = ipv6_mld_v1_mode();
        netif_activate(s_self);
        int g22 = (res[2] >= 1u) && v1s && !v1p;
        uart_printf("rfctest ipv6: %s [22] v1 の Query を受けた self だけが v1 互換(self=%d peer=%d)\n",
                    g22 ? "OK" : "NG", v1s, v1p);
        if (!g22) s_ok = 0;
        ipv6_mld_clear_v1_mode();
    }

    /* ---- [12] 非要請 Report は間隔を空けて再送する(RFC 3810 6.1)---- */
    {
        s_mld_seen = 0;
        ipv6_mld_report_all(s_self);
        netif_activate(s_self);
        unsigned now0 = s_mld_seen;
        rt_poll(MLD_UNSOL_INTERVAL_MS + 300u);
        unsigned later = s_mld_seen;
        int good = (now0 == MLD_UNSOLICITED_REPORTS) && (later == MLD_ROBUSTNESS);
        uart_printf("rfctest ipv6: %s [12] 非要請 Report はその場で %u 通、%ums 以内に再送して合計 %u 通"
                    "(期待 %u / %u)\n", good ? "OK" : "NG", now0, MLD_UNSOL_INTERVAL_MS, later,
                    MLD_UNSOLICITED_REPORTS, MLD_ROBUSTNESS);
        if (!good) s_ok = 0;
    }
    ipv6_set_mld_observer(NULL);

    /* ---- [24] hop limit: NDP だけ 255、それ以外は 64 か RA の Cur Hop Limit ---- */
    {
        ipv6_set_tx_observer(rt_tx_obs);
        netif_activate(s_self);
        s_tx_seen = 0;
        ipv6_send_echo_request(0x24u, 1u, 8u);
        int echo64 = s_tx_seen && s_tx_type == ICMPV6_TYPE_ECHO_REQUEST && s_tx_hop == 64u;
        s_tx_seen = 0;
        ndp_send_ns_unicast(s_peer_ll, s_peer->mac);
        int ns255 = s_tx_seen && s_tx_type == ICMPV6_TYPE_NS && s_tx_hop == 255u;
        rt_ra(s_peer_ll, 0u, 77u, NULL, 0u);
        rt_poll(50u);
        s_tx_seen = 0;
        ipv6_send_echo_request(0x24u, 2u, 8u);
        int echo77 = s_tx_seen && s_tx_hop == 77u;
        s_tx_seen = 0;
        ndp_send_ns_unicast(s_peer_ll, s_peer->mac);
        int ns255b = s_tx_seen && s_tx_hop == 255u;
        uint8_t hb[ETH_HDR_LEN + IPV6_HDR_LEN];
        ipv6_build_header(hb, s_self_ll, s_peer_ll, s_peer->mac, IPV6_NH_TCP, 0u);
        int tcp77 = (hb[ETH_HDR_LEN + offsetof(ipv6_header_t, hop_limit)] == 77u);
        ipv6_set_tx_observer(NULL);
        s_self->ra_cur_hop_limit = 0;
        int good = echo64 && ns255 && echo77 && ns255b && tcp77;
        uart_printf("rfctest ipv6: %s [24] hop limit(Echo=64:%d NS=255:%d、RA の Cur Hop Limit 77 の"
                    "後 Echo=77:%d NS=255:%d TCP のヘッダ=77:%d)\n", good ? "OK" : "NG",
                    echo64, ns255, echo77, ns255b, tcp77);
        if (!good) s_ok = 0;
        rt_poll(100u);   /* Echo Request への返事が届き終わるのを待つ([25] の数え方を乱さない) */
    }

    /* ---- [25] 送信元がマルチキャスト / :: のパケットは捨てる ---- */
    {
        uint8_t msrc[16] = { 0xff, 0x02, 0,0,0,0,0,0,0,0,0,0,0,0,0, 0x01 };
        uint8_t usrc[16];
        for (unsigned i = 0; i < 16u; i++) usrc[i] = 0;
        uint32_t req0 = rt_sum(g_ipv6_echo_request_count);
        uint32_t rep0 = rt_sum(g_ipv6_echo_reply_count);
        rt_echo(pl, msrc, s_self_ll, 3u);
        rt_send(s_peer, msrc, s_self_ll, s_self->mac, 64u, IPV6_NH_ICMPV6, pl, 24u);
        rt_echo(pl, usrc, s_self_ll, 4u);
        rt_send(s_peer, usrc, s_self_ll, s_self->mac, 64u, IPV6_NH_ICMPV6, pl, 24u);
        rt_poll(50u);
        int dropped = (rt_sum(g_ipv6_echo_request_count) == req0) &&
                      (rt_sum(g_ipv6_echo_reply_count) == rep0);
        rt_echo(pl, s_peer_ll, s_self_ll, 5u);
        rt_p2s(IPV6_NH_ICMPV6, pl, 24u);
        rt_poll(50u);
        int pos = (rt_sum(g_ipv6_echo_reply_count) == rep0 + 1u);
        int good = dropped && pos;
        uart_printf("rfctest ipv6: %s [25] 送信元 ff02::1 / :: の Echo Request は捨てる(=%d)、"
                    "陽性対照: 普通の送信元には答える(=%d)\n", good ? "OK" : "NG", dropped, pos);
        if (!good) s_ok = 0;
    }

    /* ---- 後始末 ---- */
    udp_unbind(RT_PORT);
    ipv6_set_mld_observer(NULL);
    ipv6_set_tx_observer(NULL);
    ipv6_set_frag_observer(NULL);
    rt_restore(s_self, &saved);
    s_peer->mld_rep_left = 0; s_peer->mld_leave_left = 0;
    netif_activate(s_self);
    /* SLAAC で参加したグループを外したので、今の参加状態を報告し直す。 */
    ipv6_mld_report_all(s_self);
    netif_activate(s_self);
    uart_printf("rfctest ipv6: %s(アドレス・ルータ・プレフィックス・宛先キャッシュ・hop limit は"
                "元に戻しました)\n", s_ok ? "PASS" : "NG");
}
