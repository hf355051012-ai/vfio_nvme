// arp.c
//
// ARP (RFC 826, Ethernet/IPv4) 応答実装 — フェーズ2
// 自機宛のARP requestにのみARP replyを返す。
//
// 全ての多バイトフィールド(2バイト以上)アクセスは net.h の
// rd16be/rd32be/wr16be/wr32be (volatile経由のバイト単位アクセス)のみを
// 使う。理由は net.h のコメント、および CLAUDE.md 参照。
// パケットバッファ(payload/src_mac/nb->data)由来のポインタは、単発の
// 1バイトアクセスであっても念のため volatile 経由で統一している
// (自分で確保したローカル変数 self_mac/self_ip は対象外: コンパイラが
// 自分自身の割り付けと整合したコードしか生成しないため安全)。

#include <stddef.h>
#include "arp.h"
#include "netctx.h"
#include "net_buf.h"
#include "net.h"
#include "netctx.h"
#include "uart.h"
#include "timer.h"

/* arp_packet_t 内のバイトオフセット (packed, 28バイト)。
 * offsetof はコンパイル時定数であり、メモリアクセスは発生しない。 */
#define ARP_OFF_HTYPE offsetof(arp_packet_t, htype)
#define ARP_OFF_PTYPE offsetof(arp_packet_t, ptype)
#define ARP_OFF_HLEN  offsetof(arp_packet_t, hlen)
#define ARP_OFF_PLEN  offsetof(arp_packet_t, plen)
#define ARP_OFF_OPER  offsetof(arp_packet_t, oper)
#define ARP_OFF_SHA   offsetof(arp_packet_t, sha)
#define ARP_OFF_SPA   offsetof(arp_packet_t, spa)
#define ARP_OFF_THA   offsetof(arp_packet_t, tha)
#define ARP_OFF_TPA   offsetof(arp_packet_t, tpa)

/* ------------------------------------------------------------------ */
/* IP->MAC 簡易キャッシュ                                                */
/* ------------------------------------------------------------------ */
/* 以前はここに単一のファイル静的配列(s_arp_cache)を持っていたが、
 * ConnectX統合(複数ネットワークインターフェースの並行運用、netctx.h
 * 参照)により、ARPキャッシュは「現在アクティブなコンテキスト
 * (g_active_ctx)ごと」に持つ必要がある(RP1とmlx5-PF0/PF1がそれぞれ
 * 独立したARPキャッシュを持つべきであり、混ぜてはならないため)。
 * arp_cache_entry_t/ARP_CACHE_SIZEの定義自体はnetctx.hへ移した
 * (net_ctx_t.arp_cacheが埋め込むため)。 */

#define ARP_RESOLVE_TIMEOUT_MS 300u /* 1回のrequestあたりのポーリング待ち */
#define ARP_RESOLVE_MAX_ATTEMPTS 3u /* requestを再送する最大回数(合計最大約900ms) */

// 既存エントリがあれば更新、無ければ空きスロットに追加、空きも無ければ
// 先頭エントリ(最も古く追加されたもの)を上書きする単純な方式。
static void arp_cache_insert(uint32_t ip, const uint8_t mac[ETH_ALEN])
{
    arp_cache_entry_t *cache = g_active_ctx->arp_cache;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].ip == ip) {
            for (int j = 0; j < ETH_ALEN; j++) cache[i].mac[j] = mac[j];
            return;
        }
    }
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            cache[i].ip = ip;
            for (int j = 0; j < ETH_ALEN; j++) cache[i].mac[j] = mac[j];
            cache[i].valid = 1;
            return;
        }
    }
    cache[0].ip = ip;
    for (int j = 0; j < ETH_ALEN; j++) cache[0].mac[j] = mac[j];
    cache[0].valid = 1;
}

int arp_cache_lookup(uint32_t ip, uint8_t out_mac[ETH_ALEN])
{
    arp_cache_entry_t *cache = g_active_ctx->arp_cache;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].ip == ip) {
            for (int j = 0; j < ETH_ALEN; j++) out_mac[j] = cache[i].mac[j];
            return 0;
        }
    }
    return -1;
}

void arp_init(void)
{
    eth_register_handler(0x0806u, arp_handle_frame);  /* EtherType: ARP */
}

void arp_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac)
{
    if (len < sizeof(arp_packet_t)) {
        uart_printf("[ARP] フレーム長不足 (len=%u < %u)\n",
                    (unsigned)len, (unsigned)sizeof(arp_packet_t));
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = payload;

    uint16_t htype = rd16be(in + ARP_OFF_HTYPE);
    uint16_t ptype = rd16be(in + ARP_OFF_PTYPE);
    uint8_t  hlen  = in[ARP_OFF_HLEN];
    uint8_t  plen  = in[ARP_OFF_PLEN];
    uint16_t oper  = rd16be(in + ARP_OFF_OPER);

    if (htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 ||
        hlen != ETH_ALEN || plen != 4) {
        uart_printf("[ARP] 非対応フォーマット (htype=%u ptype=0x%04X hlen=%u plen=%u) 無視\n",
                    htype, ptype, hlen, plen);
        return;
    }

    if (oper == ARP_OP_REPLY) {
        uint32_t sender_ip = rd32be(in + ARP_OFF_SPA);
        uint8_t sender_mac[ETH_ALEN];
        for (int i = 0; i < ETH_ALEN; i++) sender_mac[i] = in[ARP_OFF_SHA + i];
        arp_cache_insert(sender_ip, sender_mac);
//        uart_printf("[ARP] reply受信: %u.%u.%u.%u is-at %02x:%02x:%02x:%02x:%02x:%02x\n",
//                    in[ARP_OFF_SPA + 0], in[ARP_OFF_SPA + 1],
//                    in[ARP_OFF_SPA + 2], in[ARP_OFF_SPA + 3],
//                    sender_mac[0], sender_mac[1], sender_mac[2],
//                    sender_mac[3], sender_mac[4], sender_mac[5]);
        return;
    }

    /* Target IP との一致判定: rd32be()でバイト単位に安全に読み出した後の
     * 純粋なレジスタ上の値同士の比較なので、以降はアライメント/最適化の
     * 懸念なく通常の整数比較でよい。 */
    uint32_t target_ip = rd32be(in + ARP_OFF_TPA);

    if (oper != ARP_OP_REQUEST || target_ip != NET_SELF_IP) {
        /* 自機宛でないARP(他ホスト同士のトラフィック)は無視するだけで、
         * ログには出さない -- LAN上では頻繁に発生し、しかもuart_printf()
         * は115200bpsでブロッキングするため、ブロードキャストノイズが
         * 多い瞬間に大量に出るとRXポーリング自体を遅延させ、ARP解決の
         * 取りこぼしを誘発しうる(arp_resolve()のタイムアウト調査で判明)。 */
        return;
    }

//    uart_printf("[ARP] request 受信: who-has %u.%u.%u.%u tell %u.%u.%u.%u -> reply送信\n",
//                in[ARP_OFF_TPA + 0], in[ARP_OFF_TPA + 1],
//                in[ARP_OFF_TPA + 2], in[ARP_OFF_TPA + 3],
//                in[ARP_OFF_SPA + 0], in[ARP_OFF_SPA + 1],
//                in[ARP_OFF_SPA + 2], in[ARP_OFF_SPA + 3]);

    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] ARP reply: net_bufプール枯渇\n");
        return;
    }

    /* self_mac/self_ip はこの関数のローカル変数(コンパイラが自分自身の
     * 割り付けと矛盾しないコードしか生成しないため素のアクセスで安全)。 */
    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t self_ip[4];
    ip_to_octets(NET_SELF_IP, self_ip);

    /* 送信元MAC(src_mac)も別のnet_bufのEthernetヘッダを指しているため
     * volatile経由で統一する(ethwireのstore結合対策と同じ理由で、
     * loadの結合にも同様の危険があるため)。 */
    const volatile uint8_t *vsrc_mac = src_mac;

    /* 返信バッファもvolatile経由のバイト単位書き込みに統一する
     * (ethwireで確立した方針を踏襲)。 */
    volatile uint8_t *out = nb->data;

    /* Ethernetヘッダ: dst=要求元, src=自分, type=ARP(0x0806) */
    for (int i = 0; i < ETH_ALEN; i++) out[i]            = vsrc_mac[i];
    for (int i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x08;
    out[13] = 0x06;

    volatile uint8_t *rep = out + ETH_HDR_LEN;
    wr16be(rep + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
    wr16be(rep + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
    rep[ARP_OFF_HLEN] = ETH_ALEN;
    rep[ARP_OFF_PLEN] = 4;
    wr16be(rep + ARP_OFF_OPER, ARP_OP_REPLY);
    for (int i = 0; i < ETH_ALEN; i++) rep[ARP_OFF_SHA + i] = self_mac[i];
    for (int i = 0; i < 4;        i++) rep[ARP_OFF_SPA + i] = self_ip[i];
    for (int i = 0; i < ETH_ALEN; i++) rep[ARP_OFF_THA + i] = in[ARP_OFF_SHA + i];
    for (int i = 0; i < 4;        i++) rep[ARP_OFF_TPA + i] = in[ARP_OFF_SPA + i];

    nb->len = ETH_HDR_LEN + sizeof(arp_packet_t);

    if (eth_send(nb) != 0)
        uart_printf("[!] ARP reply 送信失敗\n");
//    else
//        uart_printf("[ARP] reply 送信完了\n");
}

int arp_send_request(uint32_t target_ip)
{
    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] ARP request: net_bufプール枯渇\n");
        return -1;
    }

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t self_ip[4];
    ip_to_octets(NET_SELF_IP, self_ip);
    uint8_t tpa[4];
    ip_to_octets(target_ip, tpa);

    /* 送信バッファもvolatile経由のバイト単位書き込みに統一する
     * (arp_handle_frameの返信構築と同じ理由)。 */
    volatile uint8_t *out = nb->data;

    /* Ethernetヘッダ: dst=ブロードキャスト, src=自分, type=ARP(0x0806) */
    for (int i = 0; i < ETH_ALEN; i++) out[i]            = 0xFFu;
    for (int i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x08;
    out[13] = 0x06;

    volatile uint8_t *req = out + ETH_HDR_LEN;
    wr16be(req + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
    wr16be(req + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
    req[ARP_OFF_HLEN] = ETH_ALEN;
    req[ARP_OFF_PLEN] = 4;
    wr16be(req + ARP_OFF_OPER, ARP_OP_REQUEST);
    for (int i = 0; i < ETH_ALEN; i++) req[ARP_OFF_SHA + i] = self_mac[i];
    for (int i = 0; i < 4;        i++) req[ARP_OFF_SPA + i] = self_ip[i];
    for (int i = 0; i < ETH_ALEN; i++) req[ARP_OFF_THA + i] = 0x00u; /* requestでは未使用(0埋め) */
    for (int i = 0; i < 4;        i++) req[ARP_OFF_TPA + i] = tpa[i];

    nb->len = ETH_HDR_LEN + sizeof(arp_packet_t);

    uart_printf("[ARP] request 送信: who-has %u.%u.%u.%u tell %u.%u.%u.%u\n",
                tpa[0], tpa[1], tpa[2], tpa[3],
                self_ip[0], self_ip[1], self_ip[2], self_ip[3]);

    int ret = eth_send(nb);
    if (ret != 0)
        uart_printf("[!] ARP request 送信失敗\n");
    return ret;
}

int arp_resolve(uint32_t ip, uint8_t out_mac[ETH_ALEN])
{
    if (arp_cache_lookup(ip, out_mac) == 0) {
        return 0;
    }

    /* requestを1回送って300ms待つだけだと、ブロードキャストノイズが多い
     * 瞬間(RXリングが混雑している等)にreplyを取りこぼして即失敗する
     * ことがある(tcp_connect()経由の初回呼び出しで実機再現)。
     * ARP_RESOLVE_MAX_ATTEMPTS回までrequestを再送しながら都度
     * ARP_RESOLVE_TIMEOUT_MS待つことで、単発の取りこぼしに対して
     * 頑健にする。 */
    for (unsigned attempt = 0; attempt < ARP_RESOLVE_MAX_ATTEMPTS; attempt++) {
        if (arp_send_request(ip) != 0) {
            return -1;
        }

        uint64_t start = timer_now();
        do {
            // net_poll_all_and_dispatch(): 登録済みの全コンテキストを
            // ポーリングする(netctx.h参照) -- ループバック構成
            // (ConnectX PF0/PF1)で相手側が独立に応答するには、待って
            // いる間も相手のコンテキストを一緒にポーリングし続ける
            // 必要があるため、eth_poll_recv()+eth_dispatch()の単発呼び
            // 出しをこちらへ置き換えた。登録数が1つ(通常のRP1単体運用)
            // でも従来と同じ動作になる。
            net_poll_all_and_dispatch();
            if (arp_cache_lookup(ip, out_mac) == 0) {
                return 0;
            }
        } while (!timeout_ms(start, ARP_RESOLVE_TIMEOUT_MS));
    }

    return -1;
}
