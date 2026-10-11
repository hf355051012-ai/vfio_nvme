/* IPsec の ESP(RFC 4303 / RFC 4106、トランスポートモード、IPv4)。説明は ipsec.h。
 * 形式は Linux の net/ipv4/esp4.c と crypto/gcm.c(rfc4106)に合わせた:
 *   [IPv4 ヘッダ(proto=50)][SPI 4][順序番号 4][IV 8][暗号文: 元の L4 + パディング +
 *   Pad Length 1 + Next Header 1][ICV 16]
 *   パディングは 1, 2, 3, ... の並び(RFC 4303 2.4)、暗号文の長さを 4 の倍数にする。 */
#include "ipsec.h"
#include "ip.h"
#include "net.h"
#include "netif.h"
#include "crypto.h"
#include "smp.h"
#include "uart.h"
#include <string.h>

/* netif.c の素の送信(ESP を通らない)。 */
int eth_send_frags_raw(const eth_frag_t *frags, unsigned frag_count);
int eth_send_frags_async_raw(const eth_frag_t *frags, unsigned frag_count);
void eth_rx_set_hw_csum_ok(int v);

#define ESP_HDR_LEN   8u     /* SPI + 順序番号 */
#define ESP_IV_LEN    8u
#define ESP_ICV_LEN   16u
#define IKE_PORT      500u
#define IKE_NATT_PORT 4500u
#define OUT_SLOTS     16u
#define OUT_BYTES     10240u

typedef struct {
    uint8_t  used;
    uint32_t peer;                 /* ホストバイトオーダー */
    uint8_t  up;                   /* SA が入っている */
    uint32_t spi_in, spi_out;
    crypto_aes128gcm_t k_in, k_out;
    uint8_t  salt_in[4], salt_out[4];
    volatile uint64_t seq_out;     /* 次に送る順序番号 - 1 */
    uint32_t rp_top;               /* 受け取った最大の順序番号 */
    uint64_t rp_map;               /* rp_top から下 64 個を受けたか */
    /* 統計 */
    volatile uint64_t tx_pkts, tx_bytes, rx_pkts, rx_bytes;
    volatile uint32_t rx_auth_fail, rx_replay, tx_no_sa, rx_plain_drop, tx_frag_drop;
} ipsec_peer_t;

volatile uint32_t g_ipsec_npol;
static ipsec_peer_t s_peer[IPSEC_MAX_PEERS];
static volatile uint32_t s_rx_unknown_spi;
static int s_via_esp[SMP_MAX_CORES];
static uint8_t s_lin[SMP_MAX_CORES][OUT_BYTES] __attribute__((aligned(64)));
static uint8_t s_out[SMP_MAX_CORES][OUT_SLOTS][OUT_BYTES] __attribute__((aligned(64)));

static ipsec_peer_t *peer_find(uint32_t ip)
{
    for (unsigned i = 0; i < IPSEC_MAX_PEERS; i++)
        if (s_peer[i].used && s_peer[i].peer == ip) return &s_peer[i];
    return NULL;
}

int ipsec_policy_add(uint32_t ip)
{
    if (peer_find(ip)) return 0;
    for (unsigned i = 0; i < IPSEC_MAX_PEERS; i++) {
        if (!s_peer[i].used) {
            memset(&s_peer[i], 0, sizeof(s_peer[i]));
            s_peer[i].peer = ip;
            s_peer[i].used = 1;
            g_ipsec_npol++;
            return 0;
        }
    }
    return -1;
}

void ipsec_policy_del(uint32_t ip)
{
    ipsec_peer_t *p = peer_find(ip);
    if (!p) return;
    crypto_wipe(p, sizeof(*p));
    p->used = 0;
    if (g_ipsec_npol) g_ipsec_npol--;
}

int ipsec_policy_match(uint32_t ip)
{
    return g_ipsec_npol && peer_find(ip) != NULL;
}

int ipsec_sa_install(uint32_t ip, uint32_t spi_in, const uint8_t key_in[20],
                     uint32_t spi_out, const uint8_t key_out[20])
{
    ipsec_peer_t *p = peer_find(ip);
    if (!p) {
        if (ipsec_policy_add(ip) < 0) return -1;
        p = peer_find(ip);
    }
    p->up = 0;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    crypto_aes128gcm_init(&p->k_in, key_in);
    crypto_aes128gcm_init(&p->k_out, key_out);
    memcpy(p->salt_in, key_in + 16, 4);
    memcpy(p->salt_out, key_out + 16, 4);
    p->spi_in = spi_in;
    p->spi_out = spi_out;
    p->seq_out = 0;
    p->rp_top = 0;
    p->rp_map = 0;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    p->up = 1;
    return 0;
}

void ipsec_sa_del(uint32_t ip)
{
    ipsec_peer_t *p = peer_find(ip);
    if (!p) return;
    p->up = 0;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    crypto_wipe(&p->k_in, sizeof(p->k_in));
    crypto_wipe(&p->k_out, sizeof(p->k_out));
}

int ipsec_sa_up(uint32_t ip)
{
    ipsec_peer_t *p = peer_find(ip);
    return p && p->up;
}

uint32_t ipsec_sa_peer_by_spi_out(uint32_t spi_out)
{
    for (unsigned i = 0; i < IPSEC_MAX_PEERS; i++)
        if (s_peer[i].used && s_peer[i].up && s_peer[i].spi_out == spi_out) return s_peer[i].peer;
    return 0;
}

/* ---------------------------------------------------------------- チェックサム */

static uint32_t sum16(uint32_t s, const uint8_t *p, size_t n)
{
    return checksum_accumulate(s, p, n);   /* net.h(8 バイトずつ読む)*/
}

static uint16_t fold(uint32_t s)
{
    while (s >> 16) s = (s & 0xFFFFu) + (s >> 16);
    return (uint16_t)~s;
}

/* IPv4 ヘッダ(20 バイト)のチェックサムを入れ直す。 */
static void ip_csum(uint8_t *ip)
{
    ip[10] = ip[11] = 0;
    const uint16_t c = fold(sum16(0, ip, 20));
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
}

/* TCP / UDP のチェックサムをソフトウェアで計算し直す(NIC のオフロードは
 * ESP の中身に効かない。送信側は疑似ヘッダの部分和だけを入れていることがある)。 */
static void l4_csum(const uint8_t *ip, uint8_t proto, uint8_t *l4, size_t len)
{
    unsigned off;
    if (proto == IP_PROTO_TCP) {
        if (len < 20) return;
        off = 16;
    } else if (proto == IP_PROTO_UDP) {
        if (len < 8) return;
        off = 6;
    } else {
        return;
    }
    l4[off] = l4[off + 1] = 0;
    uint32_t s = sum16(0, ip + 12, 8);   /* 送信元と宛先 */
    s += proto;
    s += (uint32_t)len;
    s = sum16(s, l4, len);
    uint16_t c = fold(s);
    if (proto == IP_PROTO_UDP && c == 0) c = 0xFFFFu;
    l4[off] = (uint8_t)(c >> 8);
    l4[off + 1] = (uint8_t)c;
}

static int is_ike(uint8_t proto, const uint8_t *l4, size_t len)
{
    if (proto != IP_PROTO_UDP || len < 8) return 0;
    const uint16_t sp = (uint16_t)((l4[0] << 8) | l4[1]), dp = (uint16_t)((l4[2] << 8) | l4[3]);
    return sp == IKE_PORT || dp == IKE_PORT || sp == IKE_NATT_PORT || dp == IKE_NATT_PORT;
}

/* ---------------------------------------------------------------- 送信 */

/* 1 フレーム(Ethernet + IPv4 + L4、frame に連続して置いたもの)を ESP で包んで送る。
 * frame は書き換えてよい(L4 のチェックサムを入れ直す)。 */
static int esp_send_one(ipsec_peer_t *p, uint8_t *frame, uint32_t flen, int async)
{
    uint8_t *ip = frame + ETH_HDR_LEN;
    const uint16_t tot = (uint16_t)((ip[2] << 8) | ip[3]);
    if (tot < 20u || ETH_HDR_LEN + (uint32_t)tot > flen) return -1;
    const uint8_t proto = ip[9];
    uint8_t *l4 = ip + 20;
    const uint32_t l4len = tot - 20u;
    l4_csum(ip, proto, l4, l4len);

    /* 送り先は、NIC の送信スロットに対応させた作業場所(NIC が読み終えるまで書き換えない)。 */
    const unsigned core = smp_core_index();
    const unsigned slot = eth_tx_wait_free_slot() % OUT_SLOTS;
    uint8_t *o = s_out[core][slot];
    const uint32_t pad = (4u - ((l4len + 2u) & 3u)) & 3u;
    const uint32_t ptlen = l4len + pad + 2u;
    const uint32_t esplen = ESP_HDR_LEN + ESP_IV_LEN + ptlen + ESP_ICV_LEN;
    const uint32_t olen = ETH_HDR_LEN + 20u + esplen;
    if (olen > OUT_BYTES || 20u + esplen > 0xFFFFu) return -1;
    memcpy(o, frame, ETH_HDR_LEN + 20u);
    uint8_t *oip = o + ETH_HDR_LEN;
    oip[2] = (uint8_t)((20u + esplen) >> 8);
    oip[3] = (uint8_t)(20u + esplen);
    oip[9] = IP_PROTO_ESP;
    ip_csum(oip);
    uint8_t *esp = oip + 20;
    const uint64_t seq = __atomic_add_fetch(&p->seq_out, 1u, __ATOMIC_RELAXED);
    wr32be(esp, p->spi_out);
    wr32be(esp + 4, (uint32_t)seq);
    uint8_t *iv = esp + ESP_HDR_LEN;
    wr32be(iv, (uint32_t)(seq >> 32));
    wr32be(iv + 4, (uint32_t)seq);
    uint8_t *pt = iv + ESP_IV_LEN;
    memcpy(pt, l4, l4len);
    for (uint32_t i = 0; i < pad; i++) pt[l4len + i] = (uint8_t)(i + 1u);
    pt[l4len + pad] = (uint8_t)pad;
    pt[l4len + pad + 1] = proto;
    uint8_t nonce[12];
    memcpy(nonce, p->salt_out, 4);
    memcpy(nonce + 4, iv, 8);
    crypto_aes128gcm_seal(&p->k_out, nonce, esp, ESP_HDR_LEN, pt, ptlen, pt, pt + ptlen);
    p->tx_pkts++;
    p->tx_bytes += l4len;
    eth_frag_t f = { o, (uint16_t)olen };
    return async ? eth_send_frags_async_raw(&f, 1) : eth_send_frags_raw(&f, 1);
}

/* 送るフレームが ESP の対象か。対象なら相手(SA を持たなくても方針はある)を返す。 */
static ipsec_peer_t *out_target(const uint8_t *frame, uint32_t flen)
{
    if (flen < ETH_HDR_LEN + 20u || frame[12] != 0x08 || frame[13] != 0x00) return NULL;
    const uint8_t *ip = frame + ETH_HDR_LEN;
    if ((ip[0] >> 4) != 4) return NULL;
    ipsec_peer_t *p = peer_find(rd32be(ip + 16));
    if (!p) return NULL;
    if ((ip[0] & 0x0Fu) == 5u && is_ike(ip[9], ip + 20, flen - ETH_HDR_LEN - 20u)) return NULL;
    return p;
}

int ipsec_out_frags(const eth_frag_t *frags, unsigned n, int async, int *rc)
{
    if (!g_ipsec_npol || n == 0) return 0;
    /* 先頭の断片だけで判定できる(IPv4 ヘッダと UDP のポートまで入っている)。 */
    const uint8_t *f0 = (const uint8_t *)frags[0].data;
    uint32_t flen = 0;
    for (unsigned i = 0; i < n; i++) flen += frags[i].len;
    if (frags[0].len < ETH_HDR_LEN + 20u + 8u) {
        /* 短すぎる先頭断片(まず無い)。連結してから判定する。 */
        if (flen > OUT_BYTES) return 0;
    }
    const unsigned core = smp_core_index();
    uint8_t *lin = s_lin[core];
    if (flen > OUT_BYTES) return 0;
    if (frags[0].len >= ETH_HDR_LEN + 28u) {
        if (!out_target(f0, frags[0].len)) return 0;
    }
    uint32_t off = 0;
    for (unsigned i = 0; i < n; i++) {
        memcpy(lin + off, frags[i].data, frags[i].len);
        off += frags[i].len;
    }
    ipsec_peer_t *p = out_target(lin, flen);
    if (!p) return 0;
    const uint8_t *ip = lin + ETH_HDR_LEN;
    const uint16_t ff = (uint16_t)((ip[6] << 8) | ip[7]);
    if ((ip[0] & 0x0Fu) != 5u || (ff & 0x3FFFu) != 0u) {
        /* 断片と IP オプションは包まない(トランスポートモードは断片化の前に包む必要がある)。 */
        p->tx_frag_drop++;
        *rc = 0;
        return 1;
    }
    if (!p->up) {
        p->tx_no_sa++;
        *rc = 0;   /* SA が無いうちは黙って捨てる(TCP は再送する)*/
        return 1;
    }
    *rc = esp_send_one(p, lin, flen, async);
    return 1;
}

/* LSO で渡された大きいセグメントを MSS ごとに分け、それぞれ ESP で包んで送る。 */
int ipsec_out_lso(const void *hdr, uint16_t hdr_len, const void *payload,
                  uint32_t payload_len, uint16_t mss, int *rc)
{
    if (!g_ipsec_npol) return 0;
    const uint8_t *h = (const uint8_t *)hdr;
    if (hdr_len < ETH_HDR_LEN + 40u) return 0;
    ipsec_peer_t *p = out_target(h, hdr_len);
    if (!p) return 0;
    if (!p->up) { p->tx_no_sa++; *rc = 0; return 1; }
    const unsigned core = smp_core_index();
    uint8_t *lin = s_lin[core];
    const uint8_t *pl = (const uint8_t *)payload;
    const uint8_t *tcp0 = h + ETH_HDR_LEN + 20;
    const uint32_t seq0 = rd32be(tcp0 + 4);
    const uint16_t id0 = (uint16_t)((h[ETH_HDR_LEN + 4] << 8) | h[ETH_HDR_LEN + 5]);
    const uint8_t flags0 = tcp0[13];
    uint32_t off = 0;
    unsigned k = 0;
    *rc = 0;
    while (off < payload_len) {
        uint32_t seg = payload_len - off;
        if (seg > mss) seg = mss;
        const int last = (off + seg == payload_len);
        if ((uint32_t)hdr_len + seg > OUT_BYTES) { *rc = -1; return 1; }
        memcpy(lin, h, hdr_len);
        memcpy(lin + hdr_len, pl + off, seg);
        uint8_t *ip = lin + ETH_HDR_LEN;
        const uint32_t tot = (uint32_t)(hdr_len - ETH_HDR_LEN) + seg;
        ip[2] = (uint8_t)(tot >> 8);
        ip[3] = (uint8_t)tot;
        ip[4] = (uint8_t)((id0 + k) >> 8);
        ip[5] = (uint8_t)(id0 + k);
        ip_csum(ip);
        uint8_t *tcp = ip + 20;
        wr32be(tcp + 4, seq0 + off);
        /* FIN と PSH は最後のセグメントだけ、CWR は最初だけ(NIC の LSO と同じ)。 */
        uint8_t fl = flags0;
        if (!last) fl &= (uint8_t)~0x09u;
        if (k) fl &= (uint8_t)~0x80u;
        tcp[13] = fl;
        if (esp_send_one(p, lin, hdr_len + seg, 1) < 0) { *rc = -1; return 1; }
        off += seg;
        k++;
    }
    return 1;
}

/* ---------------------------------------------------------------- 受信 */

void ipsec_esp_input(const uint8_t *ipc, size_t len, const uint8_t *src_mac)
{
    uint8_t *ip = (uint8_t *)(uintptr_t)ipc;   /* 受信バッファはその場で復号してよい */
    if (len < 20u + ESP_HDR_LEN + ESP_IV_LEN + 2u + ESP_ICV_LEN) return;
    const uint8_t *esp = ip + 20;
    const uint32_t spi = rd32be(esp), seq = rd32be(esp + 4);
    ipsec_peer_t *p = NULL;
    for (unsigned i = 0; i < IPSEC_MAX_PEERS; i++) {
        if (s_peer[i].used && s_peer[i].up && s_peer[i].spi_in == spi) { p = &s_peer[i]; break; }
    }
    if (!p || rd32be(ip + 12) != p->peer) {
        s_rx_unknown_spi++;
        return;
    }
    /* 再送攻撃の窓(64)。認証の前に「明らかに古い」ものだけ捨て、窓の更新は認証の後。 */
    if (seq == 0 || (p->rp_top >= 64u && seq <= p->rp_top - 64u) ||
        (seq <= p->rp_top && (p->rp_map >> (p->rp_top - seq)) & 1u)) {
        p->rx_replay++;
        return;
    }
    const uint32_t ctlen = (uint32_t)len - 20u - ESP_HDR_LEN - ESP_IV_LEN - ESP_ICV_LEN;
    uint8_t *ct = ip + 20 + ESP_HDR_LEN + ESP_IV_LEN;
    uint8_t nonce[12];
    memcpy(nonce, p->salt_in, 4);
    memcpy(nonce + 4, esp + ESP_HDR_LEN, 8);
    if (crypto_aes128gcm_open(&p->k_in, nonce, esp, ESP_HDR_LEN, ct, ctlen, ct, ct + ctlen) != 0) {
        p->rx_auth_fail++;
        return;
    }
    if (seq > p->rp_top) {
        const uint32_t d = seq - p->rp_top;
        p->rp_map = (d >= 64u) ? 1u : ((p->rp_map << d) | 1u);
        p->rp_top = seq;
    } else {
        p->rp_map |= (uint64_t)1u << (p->rp_top - seq);
    }
    const uint8_t padlen = ct[ctlen - 2], nh = ct[ctlen - 1];
    if ((uint32_t)padlen + 2u > ctlen) return;
    const uint32_t inner = ctlen - 2u - padlen;
    p->rx_pkts++;
    p->rx_bytes += inner;
    if (nh == 59u) return;   /* 中身無し(ダミー)*/
    /* 平文の直前に IPv4 ヘッダを作り直し、ip_handle_frame() へ入れ直す。 */
    uint8_t hdr[20];
    memcpy(hdr, ip, 20);
    uint8_t *nip = ct - 20;
    memcpy(nip, hdr, 20);
    nip[2] = (uint8_t)((20u + inner) >> 8);
    nip[3] = (uint8_t)(20u + inner);
    nip[6] = nip[7] = 0;
    nip[9] = nh;
    ip_csum(nip);
    const unsigned core = smp_core_index();
    const int prev_csum = eth_rx_hw_csum_ok();
    eth_rx_set_hw_csum_ok(0);   /* 中の TCP / UDP はソフトウェアで検証させる */
    s_via_esp[core] = 1;
    ip_handle_frame(nip, 20u + inner, src_mac);
    s_via_esp[core] = 0;
    eth_rx_set_hw_csum_ok(prev_csum);
}

int ipsec_rx_drop_plain(uint32_t src_ip, uint8_t proto, const uint8_t *l4, size_t len)
{
    if (s_via_esp[smp_core_index()]) return 0;
    ipsec_peer_t *p = peer_find(src_ip);
    if (!p || proto == IP_PROTO_ESP || is_ike(proto, l4, len)) return 0;
    p->rx_plain_drop++;
    return 1;
}

/* ---------------------------------------------------------------- 表示 */

void ipsec_status(void)
{
    uart_printf("ipsec: 方針 %u 件、知らない SPI の ESP %u\n", g_ipsec_npol, s_rx_unknown_spi);
    for (unsigned i = 0; i < IPSEC_MAX_PEERS; i++) {
        ipsec_peer_t *p = &s_peer[i];
        if (!p->used) continue;
        uart_printf("  %u.%u.%u.%u: SA %s  SPI 受 0x%08x / 送 0x%08x\n", p->peer >> 24, (p->peer >> 16) & 255u,
                    (p->peer >> 8) & 255u, p->peer & 255u, p->up ? "あり" : "なし", p->spi_in, p->spi_out);
        uart_printf("    送 %llu 個 %llu バイト、受 %llu 個 %llu バイト、認証の失敗 %u、再送 %u、"
                    "SA 無しで捨てた %u、平文を捨てた %u、断片を捨てた %u\n",
                    (unsigned long long)p->tx_pkts, (unsigned long long)p->tx_bytes,
                    (unsigned long long)p->rx_pkts, (unsigned long long)p->rx_bytes,
                    p->rx_auth_fail, p->rx_replay, p->tx_no_sa, p->rx_plain_drop, p->tx_frag_drop);
    }
}

void ipsec_stats_clear(void)
{
    s_rx_unknown_spi = 0;
    for (unsigned i = 0; i < IPSEC_MAX_PEERS; i++) {
        ipsec_peer_t *p = &s_peer[i];
        p->tx_pkts = p->tx_bytes = p->rx_pkts = p->rx_bytes = 0;
        p->rx_auth_fail = p->rx_replay = p->tx_no_sa = p->rx_plain_drop = p->tx_frag_drop = 0;
    }
}
