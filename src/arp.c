#include <stddef.h>
#include "arp.h"
#include "netif.h"
#include "net_buf.h"
#include "net.h"
#include "netif.h"
#include "uart.h"
#include "timer.h"

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

#define ARP_RESOLVE_TIMEOUT_MS 300u /* 1回のrequestあたりのポーリング待ち */
#define ARP_RESOLVE_MAX_ATTEMPTS 3u /* requestを再送する最大回数(合計最大約900ms) */

/* ---- 重複アドレス検出(ARP Probe、RFC 5227)の実行中状態 ----
 *
 * DAD と同じく起動時とシェルからしか走らない冷たい直列処理なので per-core に
 * しない。arp_handle_frame() が衝突を書き、arp_probe() が読む。
 * target が 0 のときは「検査中でない」を意味する(0.0.0.0 は検査できない)。 */
static volatile uint32_t s_probe_target;
static volatile int      s_probe_conflict;
static uint8_t           s_probe_conflict_mac[ETH_ALEN];
/* 検査を始めたインターフェースの MAC。**受信時の eth_get_mac() では代用でき
 * ない。** probe への reply は tpa が 0.0.0.0(probe の spa をそのまま返す)
 * なので netif_resolve_frame_owner() が宛先で振り分けられず、対向 PF 側の
 * インターフェースで処理される。そこで eth_get_mac() を読むと検査した側とは
 * 別の MAC が返り、自分の応答を他人の応答と誤認する(実機で踏んだ)。 */
static uint8_t           s_probe_self_mac[ETH_ALEN];

/*=================================================================
 * 解決済みの IP -> MAC 対応をアクティブインターフェースの ARP キャッシュへ
 * 登録する。同じ IP のエントリがあれば上書き(= 延命)、空きが無ければ
 * 先頭を潰す。ARP reply が届くたびに呼ばれるので、これが stale なエントリを
 * fresh へ戻す唯一の経路でもある。
 *
 * 引数:
 *   ip  - 対象の IPv4 アドレス(ホストバイトオーダー)
 *   mac - その IP の MAC アドレス(6 バイト)
 * コール元:
 *   arp_handle_frame(), shell_arptest()
 * ===============================================================*/
void arp_cache_insert(uint32_t ip, const uint8_t mac[ETH_ALEN])
{
    arp_cache_entry_t *cache = g_active_ctx->arp_cache;
    uint64_t expiry = neigh_expiry_from_now();

    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].ip == ip) {
            for (int j = 0; j < ETH_ALEN; j++) cache[i].mac[j] = mac[j];
            cache[i].expires_at = expiry;
            cache[i].probe_at   = 0;
            return;
        }
    }
    unsigned slot = 0;  /* 空きが無ければ先頭を潰す */
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid) { slot = i; break; }
    }
    cache[slot].ip = ip;
    for (int j = 0; j < ETH_ALEN; j++) cache[slot].mac[j] = mac[j];
    cache[slot].valid      = 1;
    cache[slot].expires_at = expiry;
    cache[slot].probe_at   = 0;
}

/*=================================================================
 * ARP キャッシュを引く。有効期限を過ぎたエントリは即座に捨てず、猶予の
 * あいだは MAC を返しつつ確認要求(ARP request)を投げる。**送信ホット
 * パスをブロックさせないため**で、理由の詳細は netif.h の説明にある。
 * 猶予も尽きたら無効化して未登録として返す。
 *
 * 引数:
 *   ip        - 探す IPv4 アドレス(ホストバイトオーダー)
 *   out_mac   - 見つかった MAC の格納先(6 バイト)
 *   confirmed - 1=上位層が到達性を裏付けた(TCP の累積 ACK が進んだ)
 * 戻り値:
 *   0=ヒット(fresh または stale)、-1=未登録/寿命切れ
 * コール元:
 *   arp_cache_lookup(), tcp_resolve_mac()
 * ===============================================================*/
int arp_cache_lookup_nud(uint32_t ip, uint8_t out_mac[ETH_ALEN], int confirmed)
{
    arp_cache_entry_t *cache = g_active_ctx->arp_cache;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid || cache[i].ip != ip) continue;

        /* **上位層の到達確認**(RFC 4861 7.3.1)。相手が自分の送ったデータを
         * 確かに受け取った(TCP の累積 ACK が進んだ)なら、それは ARP/NS を
         * 撃つより強い到達性の証拠なので、確認要求を出さずに延命する。
         * ここで済ませれば TTL ごとの 1 往復が丸ごと消える。 */
        if (confirmed) {
            g_neigh_confirm_count++;
            cache[i].expires_at = neigh_expiry_from_now();
            cache[i].probe_at   = 0;
            for (int j = 0; j < ETH_ALEN; j++) out_mac[j] = cache[i].mac[j];
            return 0;
        }

        /* 時刻の読み出しは照合が当たったときだけ(1 回)。 */
        int age = neigh_check_age(timer_now(), cache[i].expires_at, &cache[i].probe_at);
        if (age == NEIGH_DEAD) {
            cache[i].valid = 0;
            return -1;
        }
        for (int j = 0; j < ETH_ALEN; j++) out_mac[j] = cache[i].mac[j];
        if (age == NEIGH_STALE_PROBE) {
            /* **到達確認はユニキャストで出す**(RFC 4861 7.2.4 / Linux の
             * NUD PROBE と同じ)。MAC はもう持っているので、ブロードキャストで
             * リンク上の全員を起こす理由が無い。応答が来れば
             * arp_cache_insert() が延命する。 */
            arp_send_request_unicast(ip, cache[i].mac);
        }
        return 0;
    }
    return -1;
}

int arp_cache_lookup(uint32_t ip, uint8_t out_mac[ETH_ALEN])
{
    return arp_cache_lookup_nud(ip, out_mac, 0);
}

/*=================================================================
 * エントリの寿命だけを観測する。**キャッシュを一切書き換えない**ので、
 * 確認要求も出さず失効もさせない(`arptest` が状態遷移を外から見るため)。
 *
 * 引数:
 *   ip        - 探す IPv4 アドレス(ホストバイトオーダー)
 *   remain_ms - NULL 可。fresh なら失効まで、stale なら破棄までの残り
 * 戻り値:
 *   0=fresh、1=stale(猶予中)、-1=未登録または猶予切れ
 * コール元:
 *   shell_arptest()
 * ===============================================================*/
int arp_cache_peek(uint32_t ip, uint32_t *remain_ms)
{
    const arp_cache_entry_t *cache = g_active_ctx->arp_cache;
    uint64_t now = timer_now();

    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid || cache[i].ip != ip) continue;

        uint64_t grace_ns = (uint64_t)(g_neigh_cache_ttl_ms / 6u) * 1000000ull;
        uint64_t deadline;
        int state;
        if ((int64_t)(now - cache[i].expires_at) < 0) {
            deadline = cache[i].expires_at;
            state = 0;
        } else if ((int64_t)(now - (cache[i].expires_at + grace_ns)) >= 0) {
            return -1;  /* 次の lookup で破棄される */
        } else {
            deadline = cache[i].expires_at + grace_ns;
            state = 1;
        }
        if (remain_ms) *remain_ms = (uint32_t)((deadline - now) / 1000000ull);
        return state;
    }
    return -1;
}

/*=================================================================
 * EtherType 0x0806(ARP)のフレームハンドラを登録する。ハードウェアには
 * 触れないので、インターフェース登録の前後どちらで呼んでもよい。
 *
 * コール元:
 *   run_shell()
 * ===============================================================*/
void arp_init(void)
{
    eth_register_handler(0x0806u, arp_handle_frame);  /* EtherType: ARP */
}

/*=================================================================
 * 受信 ARP フレームを処理する。reply なら送信元をキャッシュへ入れ、自機宛の
 * request なら reply を返す。Ethernet/IPv4 以外のフォーマットは無視する。
 *
 * 引数:
 *   payload - ARP パケット本体(Ethernet ヘッダの直後)
 *   len     - payload のバイト数
 *   src_mac - 送信元 MAC(reply の宛先に使う)
 * コール元:
 *   eth_dispatch() から関数ポインタ経由(arp_init() で登録)
 * ===============================================================*/
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

    uint32_t sender_ip = rd32be(in + ARP_OFF_SPA);

    /* 検査中のアドレスを送信元として名乗るフレームは、そのアドレスが既に
     * 使われている証拠(RFC 5227 2.1.1)。reply だけでなく request でも成立する
     * -- 相手が自分のアドレスとして ARP を出しているか、同じアドレスを同時に
     * 検査しているかのどちらか。自分の probe は送信元 0.0.0.0 なので、
     * target(非 0)と一致することはなく自己検出は起きない。 */
    if (s_probe_target != 0u && sender_ip == s_probe_target) {
        /* RFC 5227 2.1.1 は「sender hardware address が自ホストのインター
         * フェースのものでない」ことを条件にしている。比較相手は
         * **検査を開始したインターフェースの MAC**(s_probe_self_mac)で、
         * 受信時の eth_get_mac() ではない(理由は宣言部のコメント)。 */
        int from_self = 1;
        for (int i = 0; i < ETH_ALEN; i++) {
            if (in[ARP_OFF_SHA + i] != s_probe_self_mac[i]) { from_self = 0; break; }
        }
        if (!from_self) {
            for (int i = 0; i < ETH_ALEN; i++) s_probe_conflict_mac[i] = in[ARP_OFF_SHA + i];
            s_probe_conflict = 1;
        }
    }

    if (oper == ARP_OP_REPLY) {
        uint8_t sender_mac[ETH_ALEN];
        for (int i = 0; i < ETH_ALEN; i++) sender_mac[i] = in[ARP_OFF_SHA + i];
        arp_cache_insert(sender_ip, sender_mac);
        return;
    }

    uint32_t target_ip = rd32be(in + ARP_OFF_TPA);

    if (oper != ARP_OP_REQUEST || target_ip != NET_SELF_IP) {
        return;
    }

    /* この装置はマルチキャスト/ブロードキャストを送信元へループバックする
     * (ping6 の「Echo Request 受信」が 1 回の送信で 2 行出るのが同じ現象)。
     * 自分が出したブロードキャスト request が自分に戻ってくるので、送信元
     * ハードウェアアドレスが自分なら応答しない。返しても相手は自分だけで、
     * 重複アドレス検出に無駄なフレームを混ぜるだけになる。 */
    {
        uint8_t self_mac_now[ETH_ALEN];
        eth_get_mac(self_mac_now);
        int loopback = 1;
        for (int i = 0; i < ETH_ALEN; i++) {
            if (in[ARP_OFF_SHA + i] != self_mac_now[i]) { loopback = 0; break; }
        }
        if (loopback) return;
    }

    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] ARP reply: net_bufプール枯渇\n");
        return;
    }

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t self_ip[4];
    ip_to_octets(NET_SELF_IP, self_ip);

    const volatile uint8_t *vsrc_mac = src_mac;

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
}

/*=================================================================
 * target_ip の MAC を問う ARP request をブロードキャストする(送信元 IP
 * 指定版)。sender_ip に 0 を渡すと RFC 5227 の **ARP Probe** になる。
 * probe が送信元を 0.0.0.0 にするのは、まだ使ってよいと確定していない
 * アドレスを名乗らないため(受け取った側のキャッシュも汚さない)。
 *
 * 引数:
 *   target_ip - 問い合わせたい IPv4 アドレス(ホストバイトオーダー)
 *   sender_ip - 送信元として名乗る IPv4。0 なら ARP Probe
 * 戻り値:
 *   0=送信成功、-1=net_buf 枯渇/送信失敗
 * コール元:
 *   arp_send_request(), arp_probe()
 * ===============================================================*/
static int arp_send_request_from(uint32_t target_ip, uint32_t sender_ip,
                                  const uint8_t dst_mac[ETH_ALEN])
{
    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] ARP request: net_bufプール枯渇\n");
        return -1;
    }

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t self_ip[4];
    ip_to_octets(sender_ip, self_ip);
    uint8_t tpa[4];
    ip_to_octets(target_ip, tpa);

    volatile uint8_t *out = nb->data;

    /* Ethernetヘッダ: dst=ブロードキャスト または相手の MAC, src=自分,
     * type=ARP(0x0806)。**到達確認(NUD)は既にキャッシュしている MAC へ
     * ユニキャストで送る** -- ブロードキャストだと、そのリンク上の全ノードの
     * 割り込みを起こしてキャッシュも汚す。Linux も NUD の PROBE は
     * ユニキャストの ARP request を使う。 */
    for (int i = 0; i < ETH_ALEN; i++) out[i]            = dst_mac ? dst_mac[i] : 0xFFu;
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

    if (sender_ip == 0u) {
        uart_printf("[ARP] probe 送信: who-has %u.%u.%u.%u (送信元 0.0.0.0、RFC 5227)\n",
                    tpa[0], tpa[1], tpa[2], tpa[3]);
    } else {
        uart_printf("[ARP] request 送信: who-has %u.%u.%u.%u tell %u.%u.%u.%u%s\n",
                    tpa[0], tpa[1], tpa[2], tpa[3],
                    self_ip[0], self_ip[1], self_ip[2], self_ip[3],
                    dst_mac ? " (到達確認、ユニキャスト)" : "");
    }
    {
        const uint8_t bcast[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        neigh_probe_notify(0, dst_mac ? 1 : 0, dst_mac ? dst_mac : bcast);
    }

    int ret = eth_send(nb);
    if (ret != 0)
        uart_printf("[!] ARP request 送信失敗\n");
    return ret;
}

/*=================================================================
 * target_ip の MAC を問う通常の ARP request(送信元は自分の IPv4)。
 *
 * 引数:
 *   target_ip - 問い合わせたい IPv4 アドレス(ホストバイトオーダー)
 * 戻り値:
 *   0=送信成功、-1=失敗
 * コール元:
 *   arp_resolve(), arp_cache_lookup()
 * ===============================================================*/
int arp_send_request(uint32_t target_ip)
{
    return arp_send_request_from(target_ip, NET_SELF_IP, NULL);
}

/*=================================================================
 * 到達確認(NUD)用のユニキャスト ARP request。**MAC を既に知っている相手に
 * 「まだそこに居るか」を聞く**ので、ブロードキャストにする理由が無い。
 *
 * 引数:
 *   target_ip - 確認したい IPv4 アドレス(ホストバイトオーダー)
 *   mac       - キャッシュしている相手の MAC
 * 戻り値:
 *   0=送信成功、-1=失敗
 * コール元:
 *   arp_cache_lookup_nud()
 * ===============================================================*/
int arp_send_request_unicast(uint32_t target_ip, const uint8_t mac[ETH_ALEN])
{
    return arp_send_request_from(target_ip, NET_SELF_IP, mac);
}

/*=================================================================
 * 重複アドレス検出(RFC 5227 の ARP Probe)。ip を使い始める前に、その
 * アドレスを既に誰かが使っていないかを確かめる。送信元 0.0.0.0 の ARP
 * request を probes 個送り、各回 interval_ms のあいだ受信を回して、
 * **そのアドレスを送信元として名乗るフレーム**(reply でも request でも)が
 * 来たら衝突とみなす。
 *
 * IPv6 の ipv6_dad() と対になる関数で、判定の作りも同じ。「返ってこない
 * こと」で空きと判断するので、待ち時間ぶんは必ずかかる。
 *
 * 引数:
 *   ip          - 検査するアドレス(0 は検査できない)
 *   probes      - probe を送る回数
 *   interval_ms - 1 回ごとに応答を待つ時間
 *   out_mac     - NULL 可。衝突時に相手の MAC を入れる
 * 戻り値:
 *   0=空き、1=既に使われている、-1=引数不正/送信失敗
 * コール元:
 *   net_dup_addr_detect(), shell_dadtest()
 * ===============================================================*/
int arp_probe(uint32_t ip, unsigned probes, uint32_t interval_ms, uint8_t out_mac[ETH_ALEN])
{
    if (ip == 0u) return -1;  /* 0.0.0.0 は「検査中でない」の目印に使っている */

    eth_get_mac(s_probe_self_mac);
    s_probe_conflict = 0;
    s_probe_target = ip;

    for (unsigned attempt = 0; attempt < probes && !s_probe_conflict; attempt++) {
        if (arp_send_request_from(ip, 0u, NULL) != 0) {
            s_probe_target = 0u;
            return -1;
        }
        uint64_t start = timer_now();
        while (!timeout_ms(start, interval_ms)) {
            net_poll_all_and_dispatch();
            if (s_probe_conflict) break;
        }
    }

    s_probe_target = 0u;
    if (s_probe_conflict) {
        if (out_mac) {
            for (unsigned i = 0; i < ETH_ALEN; i++) out_mac[i] = s_probe_conflict_mac[i];
        }
        return 1;
    }
    return 0;
}

/*=================================================================
 * IP から MAC を解決する。まずキャッシュを引き、無ければ request を送って
 * ARP_RESOLVE_TIMEOUT_MS ずつ最大 ARP_RESOLVE_MAX_ATTEMPTS 回待つ
 * (待っている間も net_poll_all_and_dispatch() で受信を回す)。
 *
 * 引数:
 *   ip      - 解決したい IPv4 アドレス(ホストバイトオーダー)
 *   out_mac - 解決できた MAC の格納先(6 バイト)
 * 戻り値:
 *   0=解決成功、-1=タイムアウト/送信失敗
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_bare_ack()
 * ===============================================================*/
int arp_resolve(uint32_t ip, uint8_t out_mac[ETH_ALEN])
{
    if (arp_cache_lookup(ip, out_mac) == 0) {
        return 0;
    }

    for (unsigned attempt = 0; attempt < ARP_RESOLVE_MAX_ATTEMPTS; attempt++) {
        if (arp_send_request(ip) != 0) {
            return -1;
        }

        uint64_t start = timer_now();
        do {
            net_poll_all_and_dispatch();
            if (arp_cache_lookup(ip, out_mac) == 0) {
                return 0;
            }
        } while (!timeout_ms(start, ARP_RESOLVE_TIMEOUT_MS));
    }

    return -1;
}
