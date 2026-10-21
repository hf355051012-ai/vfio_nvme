#include "rfctest.h"
#include "uart.h"
#include "ipsec.h"
#include "ike.h"
#include "ip.h"
#include "tls13.h"
#include "crypto.h"
#include "net.h"
#include "timer.h"
#include <string.h>

/*=================================================================
 * シェルの `rfctest sec`。IPsec の ESP(ipsec.c)、IKEv2(ike.c)、TLS 1.3(tls13.c)を
 * RFC に合わせて直した動きを確かめる。**ワイヤには何も出さない**:
 *   - ESP: 作った ESP のパケットを ipsec_esp_input() へ直接渡す(中身は Next Header 59 =
 *     「中身無し」にして上へは渡さない)。送信は順序番号を使い切った状態でだけ呼ぶ(送らずに捨てる)。
 *   - IKE: ike_test_loop() で送信を待ち行列へ回し、同じプロセスに相手を 2 つ(A と B)作って
 *     自分どうしで交渉させる。偽のメッセージは ike_test_rx() で直接渡す。
 *   - TLS: tls13.c はメモリ上の状態機械なので、自作のサーバとクライアントを直接つなぎ、
 *     作ったレコードを食わせる。
 * 使うアドレスは 10.250.0.x(実際の相手と重ならない)。終わったら方針も SA も消す。
 * 各項目は「rfctest sec: OK [n] ...」、最後に「rfctest sec: PASS / NG」。
 * ===============================================================*/

static unsigned s_n, s_ng;
#define CHK(c, msg) do {                                                      \
        s_n++;                                                                \
        if (c) uart_printf("rfctest sec: OK [%u] %s\n", s_n, (msg));          \
        else { s_ng++; uart_printf("rfctest sec: NG [%u] %s\n", s_n, (msg)); } \
    } while (0)

#define IP4(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

/* ================================================================= ESP */

static const uint32_t ESP_PEER = IP4(10, 250, 0, 9);
static const uint32_t ESP_PEER2 = IP4(10, 250, 0, 10);
static const uint32_t ESP_SELF = IP4(10, 250, 0, 1);

/* 鍵 16 + salt 4(RFC 4106 の KEYMAT の並び)*/
static void esp_key(uint8_t k[20], uint8_t seed)
{
    for (unsigned i = 0; i < 20; i++) k[i] = (uint8_t)(seed + i * 7u);
}

/* 相手(ESP_PEER)から届く ESP のパケットを作る。中身 plen バイト + パディング + Pad Length + Next Header 59。
 * bad_pad なら最初のパディングを 1 でなくする。戻り値は IPv4 データグラムの長さ。 */
static uint32_t esp_build(uint8_t *ip, uint32_t spi, uint32_t seq, uint32_t plen, int bad_pad)
{
    uint8_t kin[20];
    esp_key(kin, 0x31);
    crypto_aesgcm_t k;
    crypto_aesgcm_init(&k, kin, 16);
    const uint32_t pad = (4u - ((plen + 2u) & 3u)) & 3u;
    const uint32_t ptlen = plen + pad + 2u;
    const uint32_t tot = 20u + 8u + 8u + ptlen + 16u;
    memset(ip, 0, 20);
    ip[0] = 0x45;
    wr16be(ip + 2, (uint16_t)tot);
    ip[8] = 64;
    ip[9] = IP_PROTO_ESP;
    wr32be(ip + 12, ESP_PEER);
    wr32be(ip + 16, ESP_SELF);
    uint8_t *esp = ip + 20;
    wr32be(esp, spi);
    wr32be(esp + 4, seq);
    uint8_t *iv = esp + 8;
    wr32be(iv, 0);
    wr32be(iv + 4, seq);
    uint8_t *pt = iv + 8;
    for (uint32_t i = 0; i < plen; i++) pt[i] = (uint8_t)(0xA0u + i);
    for (uint32_t i = 0; i < pad; i++) pt[plen + i] = (uint8_t)(i + 1u);
    if (bad_pad && pad) pt[plen] = 0x55;
    pt[plen + pad] = (uint8_t)pad;
    pt[plen + pad + 1] = 59;   /* 中身無し */
    uint8_t nonce[12];
    memcpy(nonce, kin + 16, 4);
    memcpy(nonce + 4, iv, 8);
    crypto_aesgcm_seal(&k, nonce, esp, 8, pt, ptlen, pt, pt + ptlen);
    return tot;
}

/* Ethernet + IPv4 + UDP のフレーム(宛先 dst、ポート sp -> dp)。 */
static uint32_t udp_frame(uint8_t *f, uint32_t dst, uint16_t sp, uint16_t dp)
{
    memset(f, 0, 14 + 20 + 8 + 4);
    f[12] = 0x08;
    f[13] = 0x00;
    uint8_t *ip = f + 14;
    ip[0] = 0x45;
    wr16be(ip + 2, 20 + 8 + 4);
    ip[8] = 64;
    ip[9] = IP_PROTO_UDP;
    wr32be(ip + 12, ESP_SELF);
    wr32be(ip + 16, dst);
    wr16be(ip + 20, sp);
    wr16be(ip + 22, dp);
    wr16be(ip + 24, 8 + 4);
    return 14 + 20 + 8 + 4;
}

static void test_esp(void)
{
    uart_printf("rfctest sec: --- ESP(RFC 4303)---\n");
    uint8_t kin[20], kout[20];
    esp_key(kin, 0x31);
    esp_key(kout, 0x52);
    if (ipsec_sa_install(ESP_PEER, 0x5000u, kin, 0x6000u, kout, 16) != 0) {
        CHK(0, "試験用の SA を入れられない(方針の空きが無い?)");
        return;
    }
    static uint8_t pkt[256];
    ipsec_test_stats_t s0, s1;

    ipsec_test_stats(ESP_PEER, &s0);
    uint32_t n = esp_build(pkt, 0x5000u, 1, 3, 0);
    ipsec_esp_input(pkt, n, NULL);
    ipsec_test_stats(ESP_PEER, &s1);
    CHK(s1.rx_pkts == s0.rx_pkts + 1u && s1.rx_pad_bad == s0.rx_pad_bad,
        "A4: パディングが 1, 2, 3 の ESP は受ける");

    n = esp_build(pkt, 0x5000u, 2, 3, 1);
    ipsec_esp_input(pkt, n, NULL);
    ipsec_test_stats(ESP_PEER, &s0);
    CHK(s0.rx_pad_bad == s1.rx_pad_bad + 1u && s0.rx_pkts == s1.rx_pkts,
        "A4: パディングの中身が 1, 2, 3 でない ESP は捨てる(RFC 4303 2.4)");

    n = esp_build(pkt, 0x5000u, 1, 3, 0);
    ipsec_esp_input(pkt, n, NULL);
    ipsec_test_stats(ESP_PEER, &s1);
    CHK(s1.rx_replay == s0.rx_replay + 1u && s1.rx_pkts == s0.rx_pkts,
        "A5: 受けた順序番号をもう一度受けたら再送として捨てる(窓はロックの中で確かめ直す)");

    /* A1: 順序番号を使い切ったら送らない */
    static uint8_t fr[64];
    const uint32_t fl = udp_frame(fr, ESP_PEER, 1234, 5678);
    ipsec_test_set_seq_out(ESP_PEER, 0xFFFFFFFFull);
    const int rc = ipsec_test_send(ESP_PEER, fr, fl);
    ipsec_test_stats(ESP_PEER, &s0);
    CHK(rc == 0 && s0.tx_seq_exhausted == s1.tx_seq_exhausted + 1u,
        "A1: 順序番号 2^32 - 1 の次は送らずに捨てて数える(RFC 4303 3.3.3)");
    ipsec_test_set_seq_out(ESP_PEER, 0);

    /* A2: IKE の素通しは自分の IKE(UDP 500)だけ */
    uint8_t l4[12] = { 0 };
    wr16be(l4, 500); wr16be(l4 + 2, 500);
    const int in500 = ipsec_rx_drop_plain(ESP_PEER, IP_PROTO_UDP, l4, 12);
    wr16be(l4, 4500); wr16be(l4 + 2, 4500);
    const int in4500 = ipsec_rx_drop_plain(ESP_PEER, IP_PROTO_UDP, l4, 12);
    wr16be(l4, 500); wr16be(l4 + 2, 1234);
    const int in_sp500 = ipsec_rx_drop_plain(ESP_PEER, IP_PROTO_UDP, l4, 12);
    CHK(in500 == 0 && in4500 == 1 && in_sp500 == 1,
        "A2: 受信の平文は宛先ポート 500 だけ通し、4500 と送信元 500 だけのものは捨てる(RFC 4301 5.2)");
    udp_frame(fr, ESP_PEER, 500, 500);
    const int out500 = ipsec_test_tx_bypass(fr, fl);
    udp_frame(fr, ESP_PEER, 4500, 4500);
    const int out4500 = ipsec_test_tx_bypass(fr, fl);
    udp_frame(fr, ESP_PEER, 1234, 500);
    const int out_dp500 = ipsec_test_tx_bypass(fr, fl);
    CHK(out500 == 1 && out4500 == 0 && out_dp500 == 0,
        "A2: 送信の素通しは送信元ポート 500 だけ(4500 と宛先 500 だけのものは ESP で包む。RFC 4301 5.1)");

    /* A6: 受信の SPI をほかの相手と重ねない */
    const int dup = ipsec_sa_install(ESP_PEER2, 0x5000u, kin, 0x7000u, kout, 16);
    const int low = ipsec_sa_install(ESP_PEER2, 0x00FFu, kin, 0x7000u, kout, 16);
    CHK(dup == -1 && low == -1 && ipsec_spi_in_used(0x5000u, ESP_PEER2) == 1 &&
        ipsec_spi_in_used(0x5000u, ESP_PEER) == 0 && !ipsec_policy_match(ESP_PEER2),
        "A6: ほかの相手と同じ受信の SPI / 256 未満の SPI の SA は入れない");

    ipsec_policy_del(ESP_PEER);
    ipsec_policy_del(ESP_PEER2);
}

/* ================================================================= IKEv2 */

static const uint32_t IKE_A = IP4(10, 250, 0, 1);
static const uint32_t IKE_B = IP4(10, 250, 0, 2);
static const uint32_t IKE_C = IP4(10, 250, 0, 3);
static const char IKE_PSK[] = "rfctest-sec-psk";

enum { PROP_OK = 0, PROP_INTEG_SHA, PROP_UNKNOWN_TYPE, PROP_INTEG_NONE };

static uint32_t put_tr(uint8_t *m, uint32_t n, uint8_t type, uint16_t id, uint16_t kl)
{
    m[n] = 3; m[n + 1] = 0;
    wr16be(m + n + 2, kl ? 12 : 8);
    m[n + 4] = type; m[n + 5] = 0;
    wr16be(m + n + 6, id);
    if (kl) { wr16be(m + n + 8, 0x800E); wr16be(m + n + 10, kl); }
    return n + (kl ? 12u : 8u);
}

/* IKE_SA_INIT の要求を作る(SA → KE → Nonce [→ 知らない重要なペイロード 200])。 */
static uint32_t ike_init_req(uint8_t *m, const uint8_t spi_i[8], uint8_t ver, uint8_t flags, int prop, int cnsa,
                             uint16_t ke_grp, const uint8_t *ke, uint32_t ke_len, uint32_t nonce_len, int crit)
{
    memcpy(m, spi_i, 8);
    memset(m + 8, 0, 8);
    m[16] = 33; m[17] = ver; m[18] = 34; m[19] = flags;
    wr32be(m + 20, 0);
    uint32_t n = 28;
    /* SA */
    const uint32_t sa = n;
    m[n] = 34; m[n + 1] = 0; n += 4;
    const uint32_t pr = n;
    m[n] = 0; m[n + 1] = 0; n += 4;
    m[n++] = 1; m[n++] = 1; m[n++] = 0;
    const uint32_t ntpos = n++;
    unsigned nt = 0;
    uint32_t lastpos = n;
    lastpos = n; n = put_tr(m, n, 1, 20, cnsa ? 256 : 128); nt++;
    lastpos = n; n = put_tr(m, n, 2, cnsa ? 6 : 5, 0); nt++;
    lastpos = n; n = put_tr(m, n, 4, cnsa ? 37 : 31, 0); nt++;
    if (prop == PROP_INTEG_SHA) { lastpos = n; n = put_tr(m, n, 3, 12, 0); nt++; }
    if (prop == PROP_UNKNOWN_TYPE) { lastpos = n; n = put_tr(m, n, 13, 1, 0); nt++; }
    if (prop == PROP_INTEG_NONE) { lastpos = n; n = put_tr(m, n, 3, 0, 0); nt++; }
    m[lastpos] = 0;
    m[ntpos] = (uint8_t)nt;
    wr16be(m + pr + 2, (uint16_t)(n - pr));
    wr16be(m + sa + 2, (uint16_t)(n - sa));
    /* KE */
    const uint32_t kp = n;
    m[n] = 40; m[n + 1] = 0; n += 4;
    wr16be(m + n, ke_grp); wr16be(m + n + 2, 0); n += 4;
    if (ke) memcpy(m + n, ke, ke_len); else memset(m + n, 0x42, ke_len);
    n += ke_len;
    wr16be(m + kp + 2, (uint16_t)(n - kp));
    /* Nonce */
    const uint32_t np = n;
    m[n] = crit ? 200 : 0; m[n + 1] = 0; n += 4;
    for (uint32_t i = 0; i < nonce_len; i++) m[n + i] = (uint8_t)(0x11u + i);
    n += nonce_len;
    wr16be(m + np + 2, (uint16_t)(n - np));
    if (crit) {
        m[n] = 0; m[n + 1] = 0x80; wr16be(m + n + 2, 4); n += 4;
    }
    wr32be(m + 24, n);
    return n;
}

/* 平文の応答の最初のペイロードの種類と、通知なら種類と中身。 */
static uint8_t resp_first(const uint8_t *m, int len, uint16_t *ntype, const uint8_t **data, uint32_t *dlen)
{
    *ntype = 0;
    if (len < 32) return 0xFF;
    const uint8_t first = m[16];
    if (first == 41 && len >= 36) {
        const uint32_t plen = rd16be(m + 30);
        *ntype = rd16be(m + 34);
        if (data) *data = m + 36;
        if (dlen) *dlen = plen >= 8u ? plen - 8u : 0u;
    }
    return first;
}

static uint8_t s_ike_out[4200];
static uint8_t s_ike_in[4200];

/* 待ち行列の最初のメッセージを取り出し(残りは捨てる)、最初のペイロードと通知を読む。 */
static int pop_one(uint8_t *first, uint16_t *ntype, const uint8_t **data, uint32_t *dlen)
{
    const int n = ike_test_pop(NULL, NULL, s_ike_out, sizeof(s_ike_out));
    while (ike_test_pop(NULL, NULL, s_ike_in, sizeof(s_ike_in)) >= 0) { }
    if (n < 0) return -1;
    *first = resp_first(s_ike_out, n, ntype, data, dlen);
    return n;
}

static void drain(void)
{
    while (ike_test_pop(NULL, NULL, s_ike_in, sizeof(s_ike_in)) >= 0) { }
}

/* ---- フィルタ(待ち行列を配る前に呼ばれる)---- */
static int s_fmode;
static unsigned s_fcount;
static int s_fok;
static uint64_t s_ftimes[8];
enum { F_NONE = 0, F_ERRNOTIFY, F_COOKIE, F_DROP_INIT, F_FLIP_I };
static const uint8_t COOKIE_DATA[16] = { 'r', 'f', 'c', 't', 'e', 's', 't', '-', 'c', 'o', 'o', 'k', 'i', 'e', '!', '!' };

static int is_init_req(const uint8_t *m) { return m[18] == 34 && !(m[19] & 0x20); }

/* 応答者が返す保護しない通知(IKE_SA_INIT の応答)を作って、始めた側(entry A)へ渡す。 */
static void inject_init_notify(const uint8_t *req, uint16_t type, const uint8_t *data, uint32_t dlen)
{
    uint8_t r[128];
    memcpy(r, req, 8);
    memset(r + 8, 0, 8);
    r[16] = 41; r[17] = 0x20; r[18] = 34; r[19] = 0x20;
    wr32be(r + 20, 0);
    r[28] = 0; r[29] = 0; wr16be(r + 30, (uint16_t)(8u + dlen));
    r[32] = 0; r[33] = 0; wr16be(r + 34, type);
    memcpy(r + 36, data, dlen);
    wr32be(r + 24, 36u + dlen);
    ike_test_rx(IKE_A, IKE_B, r, 36u + dlen);
}

static int filt(uint32_t src, uint32_t dst, uint8_t *m, uint32_t *len)
{
    (void)src;
    (void)len;
    switch (s_fmode) {
    case F_ERRNOTIFY:
        if (dst == IKE_A && is_init_req(m) && s_fcount++ == 0)
            inject_init_notify(m, 14, NULL, 0);   /* 偽の NO_PROPOSAL_CHOSEN を先に。本物も配る */
        return 0;
    case F_COOKIE:
        if (dst == IKE_A && is_init_req(m)) {
            if (s_fcount++ == 0) {
                inject_init_notify(m, 16390, COOKIE_DATA, sizeof(COOKIE_DATA));
                return 1;   /* 最初の要求は捨て、COOKIE を求める */
            }
            /* 送り直した要求の最初のペイロードが COOKIE の通知で、中身が同じか(RFC 7296 2.6)*/
            s_fok = m[16] == 41 && rd16be(m + 34) == 16390 && rd16be(m + 30) == 8u + sizeof(COOKIE_DATA) &&
                    memcmp(m + 36, COOKIE_DATA, sizeof(COOKIE_DATA)) == 0;
        }
        return 0;
    case F_DROP_INIT:
        if (dst == IKE_A && is_init_req(m)) {
            if (s_fcount < 8) s_ftimes[s_fcount] = timer_now();
            s_fcount++;
            return 1;
        }
        return 0;
    case F_FLIP_I:
        if (dst == IKE_B && m[18] == 34 && (m[19] & 0x20) && s_fcount++ == 0) {
            m[19] |= 0x08;   /* 応答者の応答に I を立てる → 始めた側が捨てる(3.1)*/
            s_fok = 1;
        }
        return 0;
    default:
        return 0;
    }
}

static void fset(int mode)
{
    s_fmode = mode;
    s_fcount = 0;
    s_fok = 0;
}

static int sa_pair_ok(void)
{
    ike_test_info_t a, b;
    if (ike_test_info(IKE_A, &a) || ike_test_info(IKE_B, &b)) return 0;
    return a.state == IKE_TEST_ST_ESTABLISHED && b.state == IKE_TEST_ST_ESTABLISHED && a.initiator && !b.initiator &&
           a.child_up && b.child_up && a.esp_spi_out == b.esp_spi_in && a.esp_spi_in == b.esp_spi_out &&
           a.esp_spi_in != b.esp_spi_in && memcmp(a.spi_i, b.spi_i, 8) == 0 && memcmp(a.spi_r, b.spi_r, 8) == 0 &&
           ipsec_sa_up(IKE_A) && ipsec_sa_up(IKE_B);
}

static void test_ike(void)
{
    uart_printf("rfctest sec: --- IKEv2(RFC 7296)---\n");
    static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0x7e, 0x57 };
    if (ike_peer_add(IKE_A, IKE_PSK, NULL, mac, 0) || ike_peer_add(IKE_B, IKE_PSK, NULL, mac, 0) ||
        ike_peer_add(IKE_C, IKE_PSK, NULL, mac, 1)) {
        CHK(0, "試験用の IKE の相手を登録できない(相手の空きが無い?)");
        ike_peer_del(IKE_A); ike_peer_del(IKE_B); ike_peer_del(IKE_C);
        return;
    }
    ike_test_set_self(IKE_A, IKE_B);   /* A へ話すときのこちら = B */
    ike_test_set_self(IKE_B, IKE_A);
    ike_test_set_self(IKE_C, IKE_A);
    ike_test_loop(1, 5);
    ike_test_set_filter(filt);
    fset(F_NONE);

    ike_test_info_t a0, a1, b0, b1;
    CHK(ike_up(IKE_A) == 0 && sa_pair_ok(), "自分どうしで IKE SA と子 SA ができ、受信の SPI が重ならない(A6)");

    /* ---- 認証されていない IKE_SA_INIT(B へ、B を騙って送る)---- */
    static uint8_t req[4200];
    uint8_t spi[8] = { 0xA1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t xpriv[32], xpub[32];
    crypto_x25519_keygen(xpriv, xpub);
    uint8_t first;
    uint16_t nt;
    const uint8_t *nd;
    uint32_t ndl;
    int n;

    ike_test_info(IKE_B, &b0);
    drain();
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_OK, 0, 31, xpub, 32, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    ike_test_info(IKE_B, &b1);
    pop_one(&first, &nt, &nd, &ndl);
    CHK(first == 33 && b1.state == IKE_TEST_ST_ESTABLISHED && memcmp(b0.spi_i, b1.spi_i, 8) == 0 &&
        b1.half_state == IKE_TEST_ST_R_INIT && ipsec_sa_up(IKE_B),
        "B1: 認証されていない IKE_SA_INIT は交渉中の枠で答え、確立した SA と ESP は残す(2.21.1)");

    n = (int)ike_init_req(req, spi, 0x20, 0x00, PROP_OK, 0, 31, xpub, 32, 32, 0);
    spi[0]++;
    memcpy(req, spi, 8);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    CHK(pop_one(&first, &nt, &nd, &ndl) < 0, "B9: I フラグの無い IKE_SA_INIT の要求には答えない(3.1)");

    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x21, 0x08, PROP_OK, 0, 31, xpub, 32, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    CHK(pop_one(&first, &nt, &nd, &ndl) > 0 && first == 33, "B3: マイナー版 2.1 は 2.0 として受ける(2.5)");

    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x30, 0x08, PROP_OK, 0, 31, xpub, 32, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    n = pop_one(&first, &nt, &nd, &ndl);
    CHK(n > 0 && first == 41 && nt == 5 && s_ike_out[17] == 0x20,
        "B3: メジャー版 3 には INVALID_MAJOR_VERSION を版 2.0 のヘッダで返す(3.1)");

    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_OK, 0, 31, xpub, 32, 32, 1);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    n = pop_one(&first, &nt, &nd, &ndl);
    CHK(n > 0 && nt == 1 && ndl == 1 && nd[0] == 200,
        "B5: 知らない重要なペイロード(200)には UNSUPPORTED_CRITICAL_PAYLOAD とその種類を返す(2.5)");

    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_INTEG_SHA, 0, 31, xpub, 32, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    pop_one(&first, &nt, &nd, &ndl);
    const int integ_sha = (nt == 14);
    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_UNKNOWN_TYPE, 0, 31, xpub, 32, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    pop_one(&first, &nt, &nd, &ndl);
    const int unknown_type = (nt == 14);
    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_INTEG_NONE, 0, 31, xpub, 32, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    pop_one(&first, &nt, &nd, &ndl);
    CHK(integ_sha && unknown_type && first == 33,
        "B11: GCM に NONE 以外の INTEG だけ / 知らない変換の種類の提案は NO_PROPOSAL_CHOSEN、INTEG NONE は受ける(3.3.6)");

    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_OK, 0, 31, xpub, 31, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    pop_one(&first, &nt, &nd, &ndl);
    const int len_bad = (nt == 7);
    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_OK, 0, 19, xpub, 32, 32, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    pop_one(&first, &nt, &nd, &ndl);
    CHK(len_bad && nt == 17 && ndl == 2 && rd16be(nd) == 31,
        "B11: 群が合って長さだけ違う KE は INVALID_SYNTAX、群が違えば INVALID_KE_PAYLOAD(群 31 を求める)");

    spi[0]++;
    n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_OK, 0, 31, xpub, 32, 15, 0);
    ike_test_rx(IKE_B, IKE_A, req, (uint32_t)n);
    pop_one(&first, &nt, &nd, &ndl);
    const int n15 = (nt == 7);
    /* CNSA(PRF SHA-384)の相手 C: Nonce は 24 バイト以上 */
    {
        static uint8_t ek[CRYPTO_MLKEM1024_EK_LEN], dk[CRYPTO_MLKEM1024_DK_LEN];
        crypto_mlkem1024_keygen(ek, dk);
        spi[0]++;
        n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_OK, 1, 37, ek, sizeof(ek), 16, 0);
        ike_test_rx(IKE_C, IKE_A, req, (uint32_t)n);
        pop_one(&first, &nt, &nd, &ndl);
        const int c16 = (nt == 7);
        spi[0]++;
        n = (int)ike_init_req(req, spi, 0x20, 0x08, PROP_OK, 1, 37, ek, sizeof(ek), 24, 0);
        ike_test_rx(IKE_C, IKE_A, req, (uint32_t)n);
        pop_one(&first, &nt, &nd, &ndl);
        CHK(n15 && c16 && first == 33,
            "B4: Nonce は 16 バイト以上、PRF SHA-384 なら 24 バイト以上(PRF の鍵長の半分。2.10)");
    }

    /* ---- 置き換え(B1)---- */
    ike_test_info(IKE_A, &a0);
    CHK(ike_up(IKE_A) == 0 && sa_pair_ok() && ike_test_info(IKE_A, &a1) == 0 && memcmp(a0.spi_i, a1.spi_i, 8) != 0,
        "B1: 新しい交換は交渉中の枠で進め、IKE_AUTH の後に置き換える(ESP の SA は新しいもの)");
    ike_test_pump();   /* 古い IKE SA の Delete を配る(新しい子 SA を消さないこと)*/
    CHK(sa_pair_ok(), "B1: 置き換えた後に古い IKE SA の Delete が届いても新しい子 SA は残る");

    /* ---- B7: IKE_SA_INIT への偽の誤りの通知では諦めない ---- */
    fset(F_ERRNOTIFY);
    const int r7 = ike_up(IKE_A);
    ike_test_info(IKE_A, &a1);
    CHK(r7 == 0 && sa_pair_ok() && a1.last_notify == 14,
        "B7: IKE_SA_INIT に偽の NO_PROPOSAL_CHOSEN が届いても、本物の応答を待って確立する(2.21.1)");
    ike_test_pump();

    /* ---- B6: COOKIE ---- */
    fset(F_COOKIE);
    const int r6 = ike_up(IKE_A);
    CHK(r6 == 0 && s_fok && sa_pair_ok(),
        "B6: COOKIE を求められたら最初のペイロードに付けて送り直し、確立する(2.6)");
    ike_test_pump();

    /* ---- B9: 応答に I が立っていたら捨てる ---- */
    ike_test_info(IKE_A, &a0);
    fset(F_FLIP_I);
    const int r9 = ike_up(IKE_A);
    ike_test_info(IKE_A, &a1);
    CHK(r9 == 0 && s_fok && a1.n_bad > a0.n_bad && a1.n_retx > a0.n_retx,
        "B9: I フラグの立った IKE_SA_INIT の応答は捨て、再送で得た正しい応答で確立する(3.1)");
    ike_test_pump();

    /* ---- B2: 再送の間隔は指数で延びる。失敗しても確立した SA は残る ---- */
    ike_test_info(IKE_A, &a0);
    fset(F_DROP_INIT);
    const int r2 = ike_up(IKE_A);
    ike_test_info(IKE_A, &a1);
    int expo = s_fcount == 4u;
    if (expo) {
        const uint64_t d1 = s_ftimes[1] - s_ftimes[0], d2 = s_ftimes[2] - s_ftimes[1], d3 = s_ftimes[3] - s_ftimes[2];
        expo = d2 * 2u >= d1 * 3u && d3 * 2u >= d2 * 3u;   /* 1.5 倍以上ずつ延びる */
    }
    CHK(r2 != 0 && expo && sa_pair_ok() && memcmp(a0.spi_i, a1.spi_i, 8) == 0,
        "B2: 応答が無ければ間隔を倍にして 3 回送り直して諦め、確立した SA は残る(2.4)");
    fset(F_NONE);

    /* ---- B5: INFORMATIONAL に知らない重要なペイロード → Delete を処理しない ---- */
    {
        uint8_t inner[16];
        inner[0] = 200; inner[1] = 0; wr16be(inner + 2, 8);   /* Delete(IKE)、次は 200 */
        inner[4] = 1; inner[5] = 0; wr16be(inner + 6, 0);
        inner[8] = 0; inner[9] = 0x80; wr16be(inner + 10, 4);  /* 知らない重要なペイロード */
        const int r = ike_test_send_info(IKE_A, 42, inner, 12);
        ike_test_info(IKE_A, &a1);
        ike_test_info(IKE_B, &b1);
        CHK(r == 0 && a1.last_notify == 1 && b1.state == IKE_TEST_ST_ESTABLISHED && ipsec_sa_up(IKE_B),
            "B5: INFORMATIONAL に知らない重要なペイロードがあれば UNSUPPORTED_CRITICAL_PAYLOAD だけ返し、Delete を処理しない");
    }
    /* ---- B11: ESP の Delete は SPI を確かめる ---- */
    {
        uint8_t inner[16];
        inner[0] = 0; inner[1] = 0; wr16be(inner + 2, 12);
        inner[4] = 3; inner[5] = 4; wr16be(inner + 6, 1);
        wr32be(inner + 8, 0xDEADBEEFu);
        ike_test_send_info(IKE_A, 42, inner, 12);
        const int kept = ipsec_sa_up(IKE_B);
        ike_test_info(IKE_A, &a1);
        wr32be(inner + 8, a1.esp_spi_in);   /* A の受信の SPI(RFC 7296 1.4.1: 自分の受信の SPI を並べる)*/
        ike_test_send_info(IKE_A, 42, inner, 12);
        ike_test_info(IKE_B, &b1);
        CHK(kept && !ipsec_sa_up(IKE_B) && !b1.child_up && b1.state == IKE_TEST_ST_ESTABLISHED,
            "B11: 知らない SPI の ESP の Delete では消さず、子 SA の SPI のときだけ消す(1.4.1 / 3.11)");
    }

    /* ---- B8: TS がホスト間・全プロトコルでなければ TS_UNACCEPTABLE ---- */
    CHK(ike_up(IKE_A) == 0 && sa_pair_ok(), "(B8 の前に張り直す)");
    ike_test_pump();
    ike_test_info(IKE_B, &b0);
    ike_test_ts_proto(6);
    const int r8 = ike_up(IKE_A);
    ike_test_ts_proto(0);
    ike_test_pump();
    ike_test_info(IKE_B, &b1);
    CHK(r8 != 0 && b1.n_err > b0.n_err && b1.state == IKE_TEST_ST_NONE && !ipsec_sa_up(IKE_B),
        "B8: TCP だけの TS には TS_UNACCEPTABLE を返し、始めた側は失敗して後始末の Delete を送る(2.9)");

    /* ---- ike_down: Delete も応答まで送り直す ---- */
    CHK(ike_up(IKE_A) == 0 && sa_pair_ok(), "(ike_down の前に張り直す)");
    ike_test_pump();
    ike_down(IKE_A);
    ike_test_pump();
    ike_test_info(IKE_A, &a1);
    ike_test_info(IKE_B, &b1);
    CHK(a1.state == IKE_TEST_ST_NONE && b1.state == IKE_TEST_ST_NONE && !ipsec_sa_up(IKE_A) && !ipsec_sa_up(IKE_B),
        "ike_down: Delete で両側の IKE SA と子 SA が消える");

    ike_test_loop(0, 0);
    ike_peer_del(IKE_A);
    ike_peer_del(IKE_B);
    ike_peer_del(IKE_C);
}

/* ================================================================= TLS 1.3 */

static tls13_psk_t s_psk;
static tls13_t s_srv, s_cli;
static uint8_t s_a[24576], s_b[24576], s_app[20000], s_rec[17000];

static void psk_init(void)
{
    memset(&s_psk, 0, sizeof(s_psk));
    memcpy(s_psk.identity, "NVMe1R01 rfctest sec", 20);
    s_psk.identity_len = 20;
    for (int i = 0; i < 32; i++) s_psk.psk[i] = (uint8_t)(i * 5 + 3);
}

static void fresh(void)
{
    tls13_server_init(&s_srv, &s_psk, 1);
    tls13_client_init(&s_cli, &s_psk);
}

static int feed(tls13_t *t, const uint8_t *in, size_t n, uint8_t *out, size_t *ol)
{
    size_t al = 0;
    *ol = 0;
    return tls13_input(t, in, n, out, sizeof(s_a), ol, s_app, sizeof(s_app), &al);
}

/* 握手を最後まで進める。0 = 両方 OPEN。 */
static int pair_open(size_t an)
{
    size_t bn;
    for (int i = 0; i < 6; i++) {
        bn = 0;
        if (an && feed(&s_srv, s_a, an, s_b, &bn)) return 1;
        an = 0;
        if (bn && feed(&s_cli, s_b, bn, s_a, &an)) return 2;
        if (s_srv.state == TLS13_ST_OPEN && s_cli.state == TLS13_ST_OPEN && an == 0) return 0;
    }
    return 3;
}

static int open_fresh(void)
{
    fresh();
    return pair_open(tls13_client_hello(&s_cli, s_a, sizeof(s_a)));
}

static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr24(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }
static unsigned rd16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }

/* 方向 d の鍵で、内側の種別 type・中身 data(n バイト)のレコードを作る(長さの検査を通さない)。 */
static size_t seal_raw(tls13_dir_t *d, uint8_t type, const uint8_t *data, size_t n, uint8_t *r)
{
    r[0] = 23; r[1] = 3; r[2] = 3;
    wr16(r + 3, (unsigned)(n + 1u + 16u));
    memmove(r + 5, data, n);
    r[5 + n] = type;
    uint8_t iv[12];
    memcpy(iv, d->iv, 12);
    for (int i = 0; i < 8; i++) iv[11 - i] ^= (uint8_t)(d->seq >> (8 * i));
    crypto_aesgcm_seal(&d->aead, iv, r, 5, r + 5, n + 1u, r + 5, r + 5 + n + 1u);
    d->seq++;
    return 5u + n + 1u + 16u;
}

/* ClientHello のレコードの拡張の並びの全体長の位置。 */
static size_t ch_ext_pos(const uint8_t *r)
{
    size_t p = 5 + 4 + 2 + 32;
    p += 1u + r[p];
    p += 2u + rd16(r + p);
    p += 1u + r[p];
    return p;
}

static void hs_fix(uint8_t *r, size_t len)
{
    wr16(r + 3, (unsigned)(len - 5u));
    wr24(r + 6, (unsigned)(len - 9u));
}

static int ch_remove_ext(uint8_t *r, size_t *len, unsigned type)
{
    const size_t ep = ch_ext_pos(r);
    for (size_t p = ep + 2; p + 4 <= *len;) {
        const unsigned et = rd16(r + p), el = rd16(r + p + 2);
        if (et == type) {
            const size_t k = 4u + el;
            memmove(r + p, r + p + k, *len - p - k);
            *len -= k;
            hs_fix(r, *len);
            wr16(r + ep, rd16(r + ep) - (unsigned)k);
            return 0;
        }
        p += 4u + el;
    }
    return -1;
}

/* ClientHello の中の拡張 type の中身(なければ NULL)。 */
static const uint8_t *ch_find_ext(const uint8_t *r, size_t len, unsigned type, unsigned *el)
{
    const size_t ep = ch_ext_pos(r);
    for (size_t p = ep + 2; p + 4 <= len;) {
        const unsigned et = rd16(r + p), l = rd16(r + p + 2);
        if (et == type) { *el = l; return r + p + 4; }
        p += 4u + l;
    }
    return NULL;
}

/* サーバの出力の先頭(ServerHello のレコード)の拡張の並びの最後に ext を足す。 */
static void sh_add_ext(uint8_t *b, size_t *bn, const uint8_t *ext, size_t el)
{
    const size_t shlen = 5u + rd16(b + 3);
    memmove(b + shlen + el, b + shlen, *bn - shlen);
    memcpy(b + shlen, ext, el);
    wr16(b + 3, rd16(b + 3) + (unsigned)el);
    wr24(b + 6, (unsigned)(rd16(b + 3) - 4u));
    const size_t ep = 5 + 4 + 2 + 32 + 1 + b[5 + 4 + 2 + 32] + 2 + 1;
    wr16(b + ep, rd16(b + ep) + (unsigned)el);
    *bn += el;
}

/* サーバに CH(と続き)を食わせ、alert を確かめる。 */
static int srv_alert_after(const uint8_t *in, size_t n, uint8_t want)
{
    size_t bn;
    const int rc = feed(&s_srv, in, n, s_b, &bn);
    return rc != 0 && s_srv.alert_sent == want;
}

static void test_tls(void)
{
    uart_printf("rfctest sec: --- TLS 1.3(RFC 8446)---\n");
    psk_init();
    size_t an, bn, cn;

    /* C1: close_notify を受けたら close_notify を返す */
    {
        int ok = open_fresh() == 0;
        const size_t rl = tls13_close(&s_cli, s_rec);
        ok = ok && rl == 24 && feed(&s_srv, s_rec, rl, s_b, &bn) == 0 && s_srv.state == TLS13_ST_CLOSED &&
             bn == 24 && s_b[0] == 23;
        ok = ok && feed(&s_cli, s_b, bn, s_a, &an) == 0 && s_cli.state == TLS13_ST_CLOSED &&
             s_cli.alert_recv == TLS13_ALERT_CLOSE_NOTIFY && an == 0 && tls13_close(&s_srv, s_rec) == 0;
        CHK(ok, "C1: close_notify を受けたら自分の close_notify を送り、二度は送らない(6.1)");
    }
    /* C2: 長さの上限 */
    {
        fresh();
        static const uint8_t hdr[5] = { 22, 3, 3, 0x40, 0x01 };   /* 平文 16385 バイト */
        const int p = srv_alert_after(hdr, 5, TLS13_ALERT_RECORD_OVERFLOW);
        int q = open_fresh() == 0;
        static uint8_t big[16385];
        memset(big, 0x61, sizeof(big));
        /* 中身 16385 + 種別 1 = TLSInnerPlaintext 16386 バイト(上限 2^14 + 1 = 16385 を 1 超える)*/
        const size_t rl = seal_raw(&s_cli.tx, 23, big, sizeof(big), s_rec);
        q = q && srv_alert_after(s_rec, rl, TLS13_ALERT_RECORD_OVERFLOW);
        CHK(p && q, "C2: 平文のレコード > 2^14、復号した中身 > 2^14 + 1 は record_overflow(5.1 / 5.4)");
    }
    /* C3: KeyUpdate の検査 */
    {
        static const uint8_t ku2[5] = { 24, 0, 0, 1, 2 };
        static const uint8_t ku6[6] = { 24, 0, 0, 2, 0, 0 };
        int p = open_fresh() == 0;
        size_t rl = seal_raw(&s_cli.tx, 22, ku2, 5, s_rec);
        p = p && srv_alert_after(s_rec, rl, TLS13_ALERT_ILLEGAL_PARAMETER);
        int q = open_fresh() == 0;
        rl = seal_raw(&s_cli.tx, 22, ku6, 6, s_rec);
        q = q && srv_alert_after(s_rec, rl, TLS13_ALERT_DECODE_ERROR);
        CHK(p && q, "C3: KeyUpdate の request_update が 2 なら illegal_parameter、長さ違いは decode_error(4.6.3)");
    }
    /* C4: legacy_compression_methods */
    {
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        const size_t cm = ch_ext_pos(s_a) - 1u;   /* 圧縮方式の 1 バイト目 */
        s_a[cm] = 1;
        const int p = srv_alert_after(s_a, an, TLS13_ALERT_ILLEGAL_PARAMETER);
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        const size_t cl = ch_ext_pos(s_a) - 2u;   /* 圧縮方式の長さ */
        memmove(s_a + cl + 2, s_a + cl + 1, an - cl - 1);   /* [1][0] -> [2][0][0] */
        s_a[cl] = 2;
        s_a[cl + 1] = 0;
        an++;
        hs_fix(s_a, an);
        const int q = srv_alert_after(s_a, an, TLS13_ALERT_ILLEGAL_PARAMETER);
        CHK(p && q, "C4: legacy_compression_methods が [0] でなければ illegal_parameter(4.1.2)");
    }
    /* C5: 0-RTT を受け付けずに読み飛ばす */
    {
        static uint8_t fake[5 + 9000];
        fake[0] = 23; fake[1] = 3; fake[2] = 3;
        wr16(fake + 3, 9000);
        memset(fake + 5, 0x77, 9000);
        fresh();
        s_cli.test_early_data = 1;
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        memcpy(s_a + an, fake, 105);
        wr16(s_a + an + 3, 100);
        bn = 0;
        int p = feed(&s_srv, s_a, an + 105, s_b, &bn) == 0 && s_srv.state == TLS13_ST_WAIT_CFIN;
        cn = 0;
        p = p && feed(&s_cli, s_b, bn, s_a, &cn) == 0 && pair_open(cn) == 0;
        /* 上限を超えたら unexpected_message */
        fresh();
        s_cli.test_early_data = 1;
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        memcpy(s_a + an, fake, sizeof(fake));
        memcpy(s_a + an + sizeof(fake), fake, sizeof(fake));
        const int q = srv_alert_after(s_a, an + 2 * sizeof(fake), TLS13_ALERT_UNEXPECTED_MESSAGE);
        /* early_data を出していなければ開けないレコードは bad_record_mac */
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        memcpy(s_a + an, fake, 105);
        wr16(s_a + an + 3, 100);
        const int r = srv_alert_after(s_a, an + 105, TLS13_ALERT_BAD_RECORD_MAC);
        /* HelloRetryRequest の後も、2 回目の ClientHello までの application_data を読み飛ばす */
        fresh();
        s_srv.groups = TLS13_GROUP_MLKEM1024;
        s_cli.groups = TLS13_GROUP_X25519 | TLS13_GROUP_MLKEM1024;
        s_cli.share = TLS13_GROUP_X25519;
        s_cli.test_early_data = 1;
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        memcpy(s_a + an, fake, 105);
        wr16(s_a + an + 3, 100);
        bn = 0;
        int h = feed(&s_srv, s_a, an + 105, s_b, &bn) == 0 && s_srv.hrr && s_srv.state == TLS13_ST_WAIT_CH;
        cn = 0;
        h = h && feed(&s_cli, s_b, bn, s_a, &cn) == 0 && pair_open(cn) == 0 && s_srv.group == 0x0202;
        CHK(p && q && r && h,
            "C5: early_data を出した相手の開けないレコードは max_early_data_size まで読み飛ばす(HRR の後も。4.2.10)");
    }
    /* C7: ServerHello に出していない拡張 / 入ってはいけない拡張 */
    {
        static const uint8_t ext_sni[4] = { 0, 0, 0, 0 };
        static const uint8_t ext_sg[6] = { 0, 10, 0, 2, 0, 0 };
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        feed(&s_srv, s_a, an, s_b, &bn);
        sh_add_ext(s_b, &bn, ext_sni, sizeof(ext_sni));
        const int p = feed(&s_cli, s_b, bn, s_a, &cn) != 0 && s_cli.alert_sent == TLS13_ALERT_UNSUPPORTED_EXTENSION;
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        feed(&s_srv, s_a, an, s_b, &bn);
        sh_add_ext(s_b, &bn, ext_sg, sizeof(ext_sg));
        const int q = feed(&s_cli, s_b, bn, s_a, &cn) != 0 && s_cli.alert_sent == TLS13_ALERT_ILLEGAL_PARAMETER;
        CHK(p && q, "C7: ServerHello に出していない拡張は unsupported_extension、出したが入れてはいけない拡張は illegal_parameter(4.2)");
    }
    /* C7: cookie だけの HelloRetryRequest */
    {
        static const uint8_t HRR_RANDOM[32] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        };
        int ok = 1;
        for (int with_cookie = 1; with_cookie >= 0; with_cookie--) {
            fresh();
            an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
            unsigned ks1l = 0;
            static uint8_t ks1[2000];
            const uint8_t *ks = ch_find_ext(s_a, an, 51, &ks1l);
            if (!ks || ks1l > sizeof(ks1)) { ok = 0; break; }
            memcpy(ks1, ks, ks1l);
            uint8_t h[128];
            size_t n = 0;
            h[n++] = 22; h[n++] = 3; h[n++] = 3; n += 2;
            h[n++] = 2; n += 3;
            h[n++] = 3; h[n++] = 3;
            memcpy(h + n, HRR_RANDOM, 32); n += 32;
            h[n++] = 32;
            memcpy(h + n, s_cli.sid, 32); n += 32;
            wr16(h + n, s_cli.suite); n += 2;
            h[n++] = 0;
            const size_t ep = n;
            n += 2;
            wr16(h + n, 43); wr16(h + n + 2, 2); wr16(h + n + 4, 0x0304); n += 6;
            if (with_cookie) { wr16(h + n, 44); wr16(h + n + 2, 6); wr16(h + n + 4, 4); memcpy(h + n + 6, "abcd", 4); n += 10; }
            wr16(h + ep, (unsigned)(n - ep - 2));
            hs_fix(h, n);
            const int rc = feed(&s_cli, h, n, s_a, &cn);
            if (with_cookie) {
                /* 出力は CCS + 2 回目の ClientHello。cookie が入り、key_share は 1 回目と同じ */
                const uint8_t *ch2 = s_a + 6;
                const size_t ch2l = cn - 6;
                unsigned cl = 0, k2l = 0;
                const uint8_t *ck = rc == 0 && s_a[0] == 20 ? ch_find_ext(ch2, ch2l, 44, &cl) : NULL;
                const uint8_t *k2 = ck ? ch_find_ext(ch2, ch2l, 51, &k2l) : NULL;
                ok = ok && ck && cl == 6 && memcmp(ck + 2, "abcd", 4) == 0 && k2 && k2l == ks1l &&
                     memcmp(k2, ks1, ks1l) == 0;
            } else {
                ok = ok && rc != 0 && s_cli.alert_sent == TLS13_ALERT_ILLEGAL_PARAMETER;
            }
        }
        CHK(ok, "C7: cookie だけの HelloRetryRequest には key_share を変えずに cookie を付けて送り直し、"
                "何も変えない HRR は illegal_parameter(4.1.4)");
    }
    /* C7: 最初の ClientHello より前の CCS / 握手メッセージの途中の別のレコード */
    {
        static const uint8_t ccs[6] = { 20, 3, 3, 0, 1, 1 };
        fresh();
        const int p = srv_alert_after(ccs, 6, TLS13_ALERT_UNEXPECTED_MESSAGE);
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        static uint8_t two[120];
        two[0] = 22; two[1] = 3; two[2] = 3; wr16(two + 3, 50);
        memcpy(two + 5, s_a + 5, 50);                  /* ClientHello の頭 50 バイトだけ */
        static const uint8_t alert[7] = { 21, 3, 3, 0, 2, 1, 0 };
        memcpy(two + 55, alert, 7);
        const int q = srv_alert_after(two, 62, TLS13_ALERT_UNEXPECTED_MESSAGE) && s_srv.alert_recv == 0xFF;
        CHK(p && q, "C7: 最初の ClientHello の前の CCS、握手メッセージの途中の alert は unexpected_message(5 / 5.1)");
    }
    /* C7: サーバが NewSessionTicket を受けたら unexpected_message */
    {
        static const uint8_t nst[13] = { 4, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        int p = open_fresh() == 0;
        const size_t rl = seal_raw(&s_cli.tx, 22, nst, sizeof(nst), s_rec);
        p = p && srv_alert_after(s_rec, rl, TLS13_ALERT_UNEXPECTED_MESSAGE);
        CHK(p, "C7: サーバが NewSessionTicket を受けたら unexpected_message(4.6.1)");
    }
    /* C7: psk_key_exchange_modes が無い / supported_groups と key_share の片方だけ */
    {
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        int p = ch_remove_ext(s_a, &an, 45) == 0 && srv_alert_after(s_a, an, TLS13_ALERT_MISSING_EXTENSION);
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        int q = ch_remove_ext(s_a, &an, 51) == 0 && srv_alert_after(s_a, an, TLS13_ALERT_MISSING_EXTENSION);
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        q = q && ch_remove_ext(s_a, &an, 10) == 0 && srv_alert_after(s_a, an, TLS13_ALERT_MISSING_EXTENSION);
        CHK(p && q, "C7: psk_key_exchange_modes が無い、supported_groups と key_share の片方だけなら missing_extension(4.2.9 / 9.2)");
    }
    /* C7: legacy_record_version は見ない */
    {
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        s_a[1] = 0; s_a[2] = 0;
        CHK(pair_open(an) == 0, "C7: レコードの legacy_record_version が 0x0000 でも受ける(5.1)");
    }
    /* C7: クライアントが EncryptedExtensions 待ちで送る alert は握手の鍵で保護する */
    {
        fresh();
        an = tls13_client_hello(&s_cli, s_a, sizeof(s_a));
        feed(&s_srv, s_a, an, s_b, &bn);
        const size_t shl = 5u + rd16(s_b + 3);
        int p = feed(&s_cli, s_b, shl, s_a, &cn) == 0 && s_cli.state == TLS13_ST_WAIT_EE;
        static const uint8_t plain[9] = { 22, 3, 3, 0, 4, 8, 0, 0, 0 };
        p = p && feed(&s_cli, plain, 9, s_a, &cn) != 0 && cn == 24 && s_a[0] == 23;
        size_t xn;
        p = p && feed(&s_srv, s_a, cn, s_b, &xn) != 0 && s_srv.alert_recv == TLS13_ALERT_UNEXPECTED_MESSAGE;
        CHK(p, "C7: ServerHello の後のクライアントの alert は握手の鍵で暗号化し、サーバが読める(5 / 7.3)");
    }
    /* 回帰: 自作どうしの往復と KeyUpdate(update_requested)*/
    {
        int ok = open_fresh() == 0;
        static const uint8_t ku1[5] = { 24, 0, 0, 1, 1 };
        const size_t rl = seal_raw(&s_cli.tx, 22, ku1, 5, s_rec);
        /* クライアント側も鍵を進めたことにする(tls13.c の手順と同じ)*/
        ok = ok && feed(&s_srv, s_rec, rl, s_b, &bn) == 0 && bn > 0 && s_srv.state == TLS13_ST_OPEN;
        CHK(ok, "回帰: 正しい KeyUpdate(update_requested)にはこちらの KeyUpdate を返す");
    }
    crypto_wipe(&s_srv, sizeof(s_srv));
    crypto_wipe(&s_cli, sizeof(s_cli));
}

void rfctest_sec(const char *args)
{
    (void)args;
    s_n = s_ng = 0;
    test_esp();
    test_ike();
    test_tls();
    char err[96];
    CHK(tls13_selftest(err, sizeof(err)) == 0, "回帰: tls13_selftest(RFC 8448 の再現と自作どうしの握手)");
    uart_printf("rfctest sec: %s(%u 項目中 NG %u)\n", s_ng ? "NG" : "PASS", s_n, s_ng);
}
