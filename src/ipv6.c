#include <stddef.h>
#include "ipv6.h"
#include "netif.h"
#include "net.h"
#include "net_buf.h"
#include "uart.h"
#include "smp.h"

#define ICMPV6_OFF_TYPE     0u
#define ICMPV6_OFF_CODE     1u
#define ICMPV6_OFF_CHECKSUM 2u

/* Neighbor Solicitation/Advertisement の本体レイアウト(ICMPv6 ヘッダの後)。
 * NS:  reserved[4] + target[16] + option...
 * NA:  flags[4]    + target[16] + option...  flags の bit31=R bit30=S bit29=O */
#define NDP_OFF_TARGET  4u
#define NDP_BODY_LEN    20u  /* reserved/flags 4 + target 16 */

#define NDP_OPT_SRC_LLADDR 1u
#define NDP_OPT_TGT_LLADDR 2u

volatile uint32_t g_ipv6_echo_request_count[SMP_MAX_CORES];
volatile uint32_t g_ipv6_echo_reply_count[SMP_MAX_CORES];
volatile uint32_t g_ipv6_ns_count[SMP_MAX_CORES];

/*=================================================================
 * EtherType 0x86DD(IPv6)のフレームハンドラを登録する。
 *
 * コール元:
 *   run_shell()
 * ===============================================================*/
void ipv6_init(void)
{
    eth_register_handler(0x86DDu, ipv6_handle_frame);
}

/*=================================================================
 * 自分の MAC から EUI-64 を作り、リンクローカルアドレス fe80::/64 を組む。
 * IPv4 のような静的設定を持たなくてもこのアドレスだけは常に存在するので、
 * IPv6 の疎通確認(ping6)はこれで足りる。
 *
 * 引数:
 *   out - 16 バイトの格納先
 * コール元:
 *   ipv6_addr_is_ours(), ipv6_send(), ipv6_handle_icmpv6()
 * ===============================================================*/
void ipv6_link_local_addr(uint8_t out[IPV6_ADDR_LEN])
{
    uint8_t mac[ETH_ALEN];
    eth_get_mac(mac);

    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[i] = 0;
    out[0] = 0xFE; out[1] = 0x80;
    /* EUI-64: MAC の上位3バイト + FF FE + 下位3バイト、先頭バイトの U/L を反転 */
    out[8]  = (uint8_t)(mac[0] ^ 0x02u);
    out[9]  = mac[1];
    out[10] = mac[2];
    out[11] = 0xFF;
    out[12] = 0xFE;
    out[13] = mac[3];
    out[14] = mac[4];
    out[15] = mac[5];
}

/*=================================================================
 * 受信アドレスが自ノード宛かを判定する。リンクローカル本体、そのアドレスの
 * 要請ノードマルチキャスト(ff02::1:ffXX:XXXX)、全ノードマルチキャスト
 * (ff02::1)の 3 つを受ける。
 *
 * 引数:
 *   addr - 判定する宛先アドレス
 * 戻り値:
 *   1=自分宛、0=それ以外
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
int ipv6_addr_is_ours(const uint8_t addr[IPV6_ADDR_LEN])
{
    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);

    int same = 1;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        if (addr[i] != ll[i]) { same = 0; break; }
    }
    if (same) return 1;

    /* ff02::1 (全ノード) */
    if (addr[0] == 0xFF && addr[1] == 0x02) {
        int zero_mid = 1;
        for (unsigned i = 2; i < 15; i++) {
            if (addr[i] != 0) { zero_mid = 0; break; }
        }
        if (zero_mid && addr[15] == 0x01) return 1;

        /* ff02::1:ffXX:XXXX (要請ノードマルチキャスト) -- 下位 24bit が一致 */
        if (addr[11] == 0xFF && addr[12] == ll[13] &&
            addr[13] == ll[14] && addr[14] == ll[15]) {
            /* addr[12..14] がリンクローカル下位3バイトと一致すれば自分宛 */
            return 1;
        }
    }
    return 0;
}

/*=================================================================
 * IPv6 の疑似ヘッダを含めたチェックサムを計算する(ICMPv6/TCP/UDP 共通)。
 * IPv6 では ICMPv6 でもチェックサムが必須で、疑似ヘッダを必ず含める。
 *
 * 引数:
 *   src / dst - 送信元・宛先アドレス
 *   next_hdr  - 上位プロトコル番号
 *   data/len  - 上位プロトコルのメッセージ全体
 * 戻り値:
 *   格納すべきチェックサム値
 * コール元:
 *   ipv6_handle_icmpv6(), ipv6_send_icmpv6()
 * ===============================================================*/
static uint16_t ipv6_pseudo_checksum(const uint8_t src[IPV6_ADDR_LEN],
                                      const uint8_t dst[IPV6_ADDR_LEN],
                                      uint8_t next_hdr,
                                      const volatile uint8_t *data, uint16_t len)
{
    uint32_t sum = 0;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i += 2) {
        sum += ((uint32_t)src[i] << 8) | src[i + 1];
        sum += ((uint32_t)dst[i] << 8) | dst[i + 1];
    }
    sum += (uint32_t)len;
    sum += (uint32_t)next_hdr;

    uint16_t i = 0;
    for (; (uint32_t)i + 1u < (uint32_t)len; i = (uint16_t)(i + 2)) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    }
    if (i < len) sum += (uint32_t)data[i] << 8;

    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

/*=================================================================
 * ICMPv6 メッセージを 1 個送る。Ethernet + IPv6 ヘッダを組み立て、
 * 疑似ヘッダ込みのチェックサムを埋めてから送出する。
 *
 * 引数:
 *   dst / dst_mac - 宛先
 *   msg / msg_len - ICMPv6 メッセージ全体(チェックサム欄は 0 にしておく)
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
static int ipv6_send_icmpv6(const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
                             uint8_t *msg, uint16_t msg_len)
{
    uint8_t src[IPV6_ADDR_LEN];
    ipv6_link_local_addr(src);

    wr16be(msg + ICMPV6_OFF_CHECKSUM, 0);
    uint16_t csum = ipv6_pseudo_checksum(src, dst, IPV6_NH_ICMPV6, msg, msg_len);
    wr16be(msg + ICMPV6_OFF_CHECKSUM, csum);

    return ipv6_send(dst, dst_mac, IPV6_NH_ICMPV6, msg, msg_len);
}

/*=================================================================
 * 受信 ICMPv6 を処理する。Echo Request には Echo Reply、Neighbor
 * Solicitation には Neighbor Advertisement を返す(NA を返さないと相手は
 * こちらの MAC を解決できず、IPv6 通信が一切成立しない)。
 *
 * 引数:
 *   msg / len - ICMPv6 メッセージ本体
 *   src / dst - IPv6 ヘッダの送信元・宛先
 *   src_mac   - 送信元 MAC(応答の宛先に使う)
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static void ipv6_handle_icmpv6(const uint8_t *msg, size_t len,
                                const uint8_t src[IPV6_ADDR_LEN],
                                const uint8_t dst[IPV6_ADDR_LEN],
                                const uint8_t *src_mac)
{
    if (len < 8u) {
        uart_printf("[IPv6] ICMPv6 長不足 (len=%u)\n", (unsigned)len);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = msg;
    uint8_t type = in[ICMPV6_OFF_TYPE];

    if (!eth_rx_hw_csum_ok()) {
        uint16_t verify = ipv6_pseudo_checksum(src, dst, IPV6_NH_ICMPV6, in, (uint16_t)len);
        if (verify != 0u) {
            uart_printf("[IPv6] ICMPv6 チェックサム不正 (0x%04X) 破棄\n", verify);
            return;
        }
    }

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t out[SMP_MAX_CORES][NET_BUF_SIZE];

    if (type == ICMPV6_TYPE_ECHO_REQUEST) {
        if (len > NET_BUF_SIZE) {
            uart_printf("[IPv6] Echo Request が大きすぎる (%u)\n", (unsigned)len);
            return;
        }
        g_ipv6_echo_request_count[core]++;
        for (size_t i = 0; i < len; i++) out[core][i] = in[i];
        out[core][ICMPV6_OFF_TYPE] = ICMPV6_TYPE_ECHO_REPLY;
        out[core][ICMPV6_OFF_CODE] = 0;
        uart_printf("[IPv6] Echo Request 受信 (len=%u)、Echo Reply を返します\n",
                    (unsigned)len);
        ipv6_send_icmpv6(src, src_mac, out[core], (uint16_t)len);
        return;
    }

    if (type == ICMPV6_TYPE_NS) {
        if (len < 8u + NDP_BODY_LEN) {
            uart_printf("[IPv6] NS 長不足 (len=%u)\n", (unsigned)len);
            return;
        }
        /* 要請対象が自分のリンクローカルでなければ無視 */
        uint8_t ll[IPV6_ADDR_LEN];
        ipv6_link_local_addr(ll);
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
            if (in[8u + NDP_OFF_TARGET + i] != ll[i]) return;
        }
        g_ipv6_ns_count[core]++;

        /* NA を組み立てる: flags に S(Solicited)|O(Override)、target は自分、
         * オプションに Target Link-Layer Address を付ける。 */
        uint8_t *na = out[core];
        for (unsigned i = 0; i < 8u + NDP_BODY_LEN + 8u; i++) na[i] = 0;
        na[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_NA;
        na[ICMPV6_OFF_CODE] = 0;
        na[8] = 0x60;  /* S=1(bit30), O=1(bit29) */
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) na[8u + NDP_OFF_TARGET + i] = ll[i];
        uint8_t self_mac[ETH_ALEN];
        eth_get_mac(self_mac);
        na[8u + NDP_BODY_LEN + 0] = NDP_OPT_TGT_LLADDR;
        na[8u + NDP_BODY_LEN + 1] = 1u;  /* 長さ(8バイト単位) */
        for (unsigned i = 0; i < ETH_ALEN; i++) na[8u + NDP_BODY_LEN + 2u + i] = self_mac[i];

        uart_printf("[IPv6] Neighbor Solicitation 受信、Advertisement を返します\n");
        ipv6_send_icmpv6(src, src_mac, na, (uint16_t)(8u + NDP_BODY_LEN + 8u));
        return;
    }

    if (type == ICMPV6_TYPE_ECHO_REPLY) {
        g_ipv6_echo_reply_count[core]++;
        uart_printf("[IPv6] Echo Reply 受信 (id=%u seq=%u)\n",
                    rd16be(in + 4), rd16be(in + 6));
        return;
    }
    if (type == ICMPV6_TYPE_NA) {
        return;  /* 近隣キャッシュを持たないので今は使わない */
    }
    uart_printf("[IPv6] 未対応の ICMPv6 type=%u 無視\n", type);
}

/*=================================================================
 * 受信 IPv6 フレームを検証して上位へ渡す。IPv6 ヘッダにチェックサムは無く、
 * 拡張ヘッダも未対応なので next_header をそのまま見る。
 *
 * 引数:
 *   payload - IPv6 ヘッダ先頭(Ethernet ヘッダの直後)
 *   len     - payload のバイト数
 *   src_mac - 送信元 MAC
 * コール元:
 *   eth_dispatch() から関数ポインタ経由(ipv6_init() で登録)
 * ===============================================================*/
void ipv6_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac)
{
    if (len < IPV6_HDR_LEN) {
        uart_printf("[IPv6] フレーム長不足 (len=%u)\n", (unsigned)len);
        return;
    }

    const volatile uint8_t *in = payload;
    if ((in[0] >> 4) != 6u) {
        uart_printf("[IPv6] version フィールドが 6 でない 無視\n");
        return;
    }

    uint16_t plen = rd16be(in + offsetof(ipv6_header_t, payload_len));
    uint8_t  nh   = in[offsetof(ipv6_header_t, next_header)];
    if ((size_t)plen + IPV6_HDR_LEN > len) {
        uart_printf("[IPv6] payload_length がフレーム長を超過 (plen=%u len=%u) 無視\n",
                    plen, (unsigned)len);
        return;
    }

    uint8_t src[IPV6_ADDR_LEN], dst[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        src[i] = in[offsetof(ipv6_header_t, src) + i];
        dst[i] = in[offsetof(ipv6_header_t, dst) + i];
    }
    if (!ipv6_addr_is_ours(dst)) {
        return;
    }

    const uint8_t *body = payload + IPV6_HDR_LEN;
    if (nh == IPV6_NH_ICMPV6) {
        ipv6_handle_icmpv6(body, plen, src, dst, src_mac);
    } else {
        /* TCP/UDP over IPv6 は未対応。スタック全体が 4 バイトアドレスを前提に
         * しているため、対応にはアドレス幅の抽象化が要る(README 参照)。 */
        uart_printf("[IPv6] 未対応の next_header=%u 無視\n", nh);
    }
}

/*=================================================================
 * IPv6 データグラムを 1 個送信する。拡張ヘッダは付けない。
 *
 * 引数:
 *   dst / dst_mac         - 宛先
 *   next_header           - 上位プロトコル番号
 *   payload / payload_len - 上位プロトコルのメッセージ
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_send_icmpv6()
 * ===============================================================*/
int ipv6_send(const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
              uint8_t next_header, const uint8_t *payload, uint16_t payload_len)
{
    uint32_t frame_len = (uint32_t)ETH_HDR_LEN + IPV6_HDR_LEN + payload_len;
    if (frame_len > NET_BUF_SIZE) {
        uart_printf("[!] IPv6: フレーム長超過 (%u)\n", (unsigned)frame_len);
        return -1;
    }

    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] IPv6: net_buf 確保失敗\n");
        return -1;
    }

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t src[IPV6_ADDR_LEN];
    ipv6_link_local_addr(src);

    volatile uint8_t *out = nb->data;
    for (unsigned i = 0; i < ETH_ALEN; i++) out[i]            = dst_mac[i];
    for (unsigned i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x86; out[13] = 0xDD;  /* EtherType: IPv6 */

    volatile uint8_t *h = out + ETH_HDR_LEN;
    h[0] = 0x60; h[1] = 0; h[2] = 0; h[3] = 0;  /* version=6, TC=0, flow label=0 */
    wr16be(h + offsetof(ipv6_header_t, payload_len), payload_len);
    h[offsetof(ipv6_header_t, next_header)] = next_header;
    h[offsetof(ipv6_header_t, hop_limit)]   = 255u;  /* NDP は 255 必須、それ以外も無害 */
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        h[offsetof(ipv6_header_t, src) + i] = src[i];
        h[offsetof(ipv6_header_t, dst) + i] = dst[i];
    }
    for (uint16_t i = 0; i < payload_len; i++) {
        out[ETH_HDR_LEN + IPV6_HDR_LEN + i] = payload[i];
    }

    nb->len = (uint16_t)frame_len;
    int rc = eth_send(nb);
    net_buf_free(nb);
    return rc;
}

/*=================================================================
 * ICMPv6 Echo Request を全ノードマルチキャスト(ff02::1、L2 は
 * 33:33:00:00:00:01)へ 1 個送る。直結リンクなので近隣探索でアドレス解決を
 * しなくても相手に届き、疎通確認ができる。
 *
 * 引数:
 *   ident / seq - Echo の識別子と通番
 *   payload_len - Echo ヘッダ(8)の後ろに付けるデータ長
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_ping6()
 * ===============================================================*/
int ipv6_send_echo_request(uint16_t ident, uint16_t seq, uint16_t payload_len)
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t req[SMP_MAX_CORES][NET_BUF_SIZE];

    uint32_t total = 8u + payload_len;
    if (total > NET_BUF_SIZE) return -1;

    uint8_t *m = req[core];
    for (uint32_t i = 0; i < total; i++) m[i] = (uint8_t)(i);
    m[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_ECHO_REQUEST;
    m[ICMPV6_OFF_CODE] = 0;
    wr16be(m + ICMPV6_OFF_CHECKSUM, 0);
    wr16be(m + 4, ident);
    wr16be(m + 6, seq);

    uint8_t dst[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) dst[i] = 0;
    dst[0] = 0xFF; dst[1] = 0x02; dst[15] = 0x01;   /* ff02::1 */
    const uint8_t dst_mac[ETH_ALEN] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };

    return ipv6_send_icmpv6(dst, dst_mac, m, (uint16_t)total);
}
