#include <stddef.h>
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "netif.h"
#include "net_buf.h"
#include "net.h"
#include "uart.h"
#include "smp.h"

#define IP_OFF_VER_IHL     offsetof(ip_header_t, ver_ihl)
#define IP_OFF_TOS         offsetof(ip_header_t, tos)
#define IP_OFF_TOTAL_LEN   offsetof(ip_header_t, total_len)
#define IP_OFF_ID          offsetof(ip_header_t, id)
#define IP_OFF_FLAGS_FRAG  offsetof(ip_header_t, flags_frag)
#define IP_OFF_TTL         offsetof(ip_header_t, ttl)
#define IP_OFF_PROTOCOL    offsetof(ip_header_t, protocol)
#define IP_OFF_CHECKSUM    offsetof(ip_header_t, checksum)
#define IP_OFF_SRC_IP      offsetof(ip_header_t, src_ip)
#define IP_OFF_DST_IP      offsetof(ip_header_t, dst_ip)

#define IP_DEFAULT_TTL 64u

static uint16_t s_ip_id[SMP_MAX_CORES];  /* IP identification: 単純増加カウンタ(固定値でも可) */

/*
 * EtherType 0x0800(IPv4)のフレームハンドラを登録する。
 *
 * コール元:
 *   run_shell()
 */
void ip_init(void)
{
    eth_register_handler(0x0800u, ip_handle_frame);  /* EtherType: IPv4 */
}

/*
 * 受信 IPv4 フレームを検証して上位プロトコルへ渡す。version/IHL/チェック
 * サム/total_length/宛先 IP を確認し、ICMP は icmp_handle()、TCP は
 * tcp_input() へ。HW チェックサムオフロード済み(eth_rx_hw_csum_ok())なら
 * ソフトウェア検証は省く。
 *
 * 引数:
 *   payload - IPv4 ヘッダ先頭(Ethernet ヘッダの直後)
 *   len     - payload のバイト数
 *   src_mac - 送信元 MAC(ICMP reply 用に icmp_handle へ渡す)
 * コール元:
 *   eth_dispatch() から関数ポインタ経由(ip_init() で登録)
 */
void ip_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac)
{
    if (len < sizeof(ip_header_t)) {
        uart_printf("[IP] フレーム長不足 (len=%u < %u)\n",
                    (unsigned)len, (unsigned)sizeof(ip_header_t));
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = payload;

    uint8_t ver_ihl = in[IP_OFF_VER_IHL];
    uint8_t version = (uint8_t)(ver_ihl >> 4);
    uint8_t ihl     = (uint8_t)(ver_ihl & 0x0Fu);

    if (version != 4) {
        uart_printf("[IP] 非対応バージョン (version=%u) 無視\n", version);
        return;
    }
    if (ihl != 5) {
        uart_printf("[IP] オプション付きIPヘッダ(IHL=%u)は未対応、無視\n", ihl);
        return;
    }

    if (!eth_rx_hw_csum_ok()) {
        uint16_t verify = inet_checksum(in, sizeof(ip_header_t));
        if (verify != 0) {
            uart_printf("[IP] ヘッダチェックサム不正 (計算結果=0x%04X、0であるべき) 無視\n",
                        verify);
            return;
        }
    }

    uint16_t total_len = rd16be(in + IP_OFF_TOTAL_LEN);
    if ((size_t)total_len > len) {
        uart_printf("[IP] total_lengthがフレーム長を超過 (total_len=%u len=%u) 無視\n",
                    total_len, (unsigned)len);
        return;
    }
    if (total_len < sizeof(ip_header_t)) {
        uart_printf("[IP] total_lengthがヘッダ長未満 (total_len=%u) 無視\n", total_len);
        return;
    }

    uint32_t dst_ip = rd32be(in + IP_OFF_DST_IP);
    if (dst_ip != NET_SELF_IP) {
        return;
    }

    uint8_t protocol = in[IP_OFF_PROTOCOL];
    uint8_t src_ip[4];
    src_ip[0] = in[IP_OFF_SRC_IP + 0];
    src_ip[1] = in[IP_OFF_SRC_IP + 1];
    src_ip[2] = in[IP_OFF_SRC_IP + 2];
    src_ip[3] = in[IP_OFF_SRC_IP + 3];

    size_t hdr_len = sizeof(ip_header_t);
    size_t ip_payload_len = (size_t)total_len - hdr_len;
    const uint8_t *ip_payload = payload + hdr_len;

    if (protocol == IP_PROTO_ICMP) {
        icmp_handle(ip_payload, ip_payload_len, src_ip, src_mac);
    } else if (protocol == IP_PROTO_TCP) {
        uint32_t src_ip_host = ip_from_octets(src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        tcp_input(ip_payload, (uint16_t)ip_payload_len, src_ip_host);
    } else {
        uart_printf("[IP] 未対応プロトコル (protocol=%u) 無視\n", protocol);
    }
}

/*
 * buf の先頭へ Ethernet ヘッダ + IPv4 ヘッダ(20 バイト、オプション無し)を
 * 組み立てる。IP ヘッダチェックサムもここで確定させる。
 *
 * 引数:
 *   buf         - 書き込み先(ETH_HDR_LEN + 20 バイト以上)
 *   dst_ip      - 宛先 IPv4(4 オクテット)
 *   dst_mac     - 宛先 MAC(6 バイト)
 *   protocol    - IP プロトコル番号(IP_PROTO_ICMP / IP_PROTO_TCP)
 *   payload_len - IP ペイロードのバイト数(total_length の算出に使う)
 * コール元:
 *   ip_prepare_send_buf(), tcp_send_segment(), tcp_send_segment_lso(),
 *   tcp_send_bare_ack()
 */
void ip_build_header(uint8_t *buf, const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                      uint8_t protocol, uint16_t payload_len)
{
    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    uint8_t self_ip[4];
    ip_to_octets(NET_SELF_IP, self_ip);

    const volatile uint8_t *vdst_mac = dst_mac;
    const volatile uint8_t *vdst_ip  = dst_ip;

    volatile uint8_t *out = buf;

    /* Ethernetヘッダ */
    for (int i = 0; i < ETH_ALEN; i++) out[i]            = vdst_mac[i];
    for (int i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x08; out[13] = 0x00;  /* EtherType: IPv4 */

    volatile uint8_t *iph = out + ETH_HDR_LEN;
    uint16_t total_len = (uint16_t)(sizeof(ip_header_t) + payload_len);

    iph[IP_OFF_VER_IHL] = 0x45;  /* version=4, IHL=5(20バイト、オプション無し) */
    iph[IP_OFF_TOS]     = 0;
    wr16be(iph + IP_OFF_TOTAL_LEN, total_len);
    wr16be(iph + IP_OFF_ID, s_ip_id[smp_core_index()]++);
    wr16be(iph + IP_OFF_FLAGS_FRAG, 0);
    iph[IP_OFF_TTL]      = IP_DEFAULT_TTL;
    iph[IP_OFF_PROTOCOL] = protocol;
    wr16be(iph + IP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */
    for (int i = 0; i < 4; i++) iph[IP_OFF_SRC_IP + i] = self_ip[i];
    for (int i = 0; i < 4; i++) iph[IP_OFF_DST_IP + i] = vdst_ip[i];

    uint16_t csum = inet_checksum(iph, sizeof(ip_header_t));
    wr16be(iph + IP_OFF_CHECKSUM, csum);
}

/*
 * net_buf を1つ確保し、Ethernet+IPv4 ヘッダまで書いた状態で返す。
 * 呼び出し元はペイロードを IP_PAYLOAD_OFFSET から書き込む。
 *
 * 引数:
 *   dst_ip / dst_mac / protocol / payload_len - ip_build_header() と同じ
 * 戻り値:
 *   ヘッダ構築済みの net_buf。フレーム長超過/プール枯渇なら NULL
 * コール元:
 *   ip_send()
 */
net_buf_t *ip_prepare_send_buf(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                                uint8_t protocol, uint16_t payload_len)
{
    size_t total_needed = ETH_HDR_LEN + sizeof(ip_header_t) + payload_len;
    if (total_needed > NET_BUF_SIZE) {
        uart_printf("[!] ip_prepare_send_buf: フレームサイズ超過 (%u > %u)\n",
                    (unsigned)total_needed, (unsigned)NET_BUF_SIZE);
        return NULL;
    }

    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] ip_prepare_send_buf: net_bufプール枯渇\n");
        return NULL;
    }

    ip_build_header(nb->data, dst_ip, dst_mac, protocol, payload_len);
    nb->len = (uint16_t)(ETH_HDR_LEN + sizeof(ip_header_t) + payload_len);
    return nb;
}

/*
 * ip_prepare_send_buf() で用意しペイロードまで書き終えた net_buf を送信する
 * (IP ヘッダは既に確定済みなので、そのまま eth_send() へ渡すだけ)。
 *
 * 引数:
 *   nb          - 送信する net_buf(所有権は eth_send() へ渡る)
 *   payload_len - 未使用(ヘッダ確定済みのため)
 * 戻り値:
 *   eth_send() の結果。0=送信完了、-1=失敗
 * コール元:
 *   ip_send()
 */
int ip_send_prepared(net_buf_t *nb, uint16_t payload_len)
{
    (void)payload_len;  /* IPヘッダはip_prepare_send_buf()内で既に確定済み(チェックサム込み) */
    return eth_send(nb);
}

/*
 * ペイロードを IPv4 パケットとして 1 つ送信する(バッファ確保・ヘッダ構築・
 * ペイロードコピー・送信をまとめて行う)。
 *
 * 引数:
 *   dst_ip / dst_mac / protocol - ip_build_header() と同じ
 *   payload     - IP ペイロード
 *   payload_len - そのバイト数
 * 戻り値:
 *   0=送信完了、-1=バッファ確保失敗/送信失敗
 * コール元:
 *   icmp_handle()
 */
int ip_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
            uint8_t protocol, const uint8_t *payload, uint16_t payload_len)
{
    net_buf_t *nb = ip_prepare_send_buf(dst_ip, dst_mac, protocol, payload_len);
    if (!nb) {
        return -1;
    }

    const volatile uint8_t *vpayload = payload;
    volatile uint8_t *body = nb->data + IP_PAYLOAD_OFFSET;
    for (uint16_t i = 0; i < payload_len; i++) body[i] = vpayload[i];

    return ip_send_prepared(nb, payload_len);
}
