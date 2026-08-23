#include <stddef.h>
#include "udp.h"
#include "ip.h"
#include "ipv6.h"
#include "net.h"
#include "net_buf.h"
#include "netif.h"
#include "uart.h"
#include "smp.h"

#define UDP_OFF_SRC_PORT 0u
#define UDP_OFF_DST_PORT 2u
#define UDP_OFF_LENGTH   4u
#define UDP_OFF_CHECKSUM 6u

#define UDP_MAX_BINDINGS 8u

typedef struct {
    int           used;
    uint16_t      port;
    udp_handler_t handler;
} udp_binding_t;

static udp_binding_t s_bindings[UDP_MAX_BINDINGS];

/*=================================================================
 * UDP 層を初期化する(全バインドを解除する)。
 *
 * コール元:
 *   run_shell()
 * ===============================================================*/
void udp_init(void)
{
    for (unsigned i = 0; i < UDP_MAX_BINDINGS; i++) {
        s_bindings[i].used = 0;
    }
}

/*=================================================================
 * 宛先ポートに受信ハンドラを登録する。同じポートへの再登録は上書き。
 *
 * 引数:
 *   port    - 待ち受けるポート番号(ホストバイトオーダ)
 *   handler - 受信時に呼ぶ関数
 * 戻り値:
 *   0=登録できた、-1=空きが無い
 * コール元:
 *   (UDP を使う上位プロトコルから。現状はまだ利用者が居ない)
 * ===============================================================*/
int udp_bind(uint16_t port, udp_handler_t handler)
{
    for (unsigned i = 0; i < UDP_MAX_BINDINGS; i++) {
        if (s_bindings[i].used && s_bindings[i].port == port) {
            s_bindings[i].handler = handler;
            return 0;
        }
    }
    for (unsigned i = 0; i < UDP_MAX_BINDINGS; i++) {
        if (!s_bindings[i].used) {
            s_bindings[i].used    = 1;
            s_bindings[i].port    = port;
            s_bindings[i].handler = handler;
            return 0;
        }
    }
    uart_printf("[!] UDP: バインド表が満杯 (port=%u)\n", port);
    return -1;
}

/*=================================================================
 * 登録済みの受信ハンドラを解除する。
 *
 * 引数:
 *   port - 解除するポート番号
 * コール元:
 *   (UDP を使う上位プロトコルから)
 * ===============================================================*/
void udp_unbind(uint16_t port)
{
    for (unsigned i = 0; i < UDP_MAX_BINDINGS; i++) {
        if (s_bindings[i].used && s_bindings[i].port == port) {
            s_bindings[i].used = 0;
            return;
        }
    }
}

/*=================================================================
 * 受信 UDP データグラムを検証してポート別ハンドラへ渡す。IPv4/IPv6 の
 * どちらも同じ入口を通る(疑似ヘッダの形だけ family で分岐する)。
 *
 * 引数:
 *   data    - UDP ヘッダ先頭(L3 ヘッダの直後)
 *   len     - data のバイト数
 *   src/dst - 送信元・宛先アドレス(疑似ヘッダに使う)
 *   src_mac - 送信元 MAC(応答用にハンドラへ渡す)
 * 戻り値:
 *   0=処理した、-1=宛先ポートに待ち受けが無い(呼び出し元が ICMP
 *   Port Unreachable を返す)、-2=不正なデータグラムとして破棄した
 * コール元:
 *   udp_input(), ipv6_handle_frame()
 * ===============================================================*/
int udp_input_addr(const uint8_t *data, size_t len,
                   const netaddr_t *src, const netaddr_t *dst,
                   const uint8_t *src_mac)
{
    if (len < UDP_HDR_LEN) {
        uart_printf("[UDP] ヘッダ長不足 (len=%u)\n", (unsigned)len);
        return -2;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = data;

    uint16_t src_port = rd16be(in + UDP_OFF_SRC_PORT);
    uint16_t dst_port = rd16be(in + UDP_OFF_DST_PORT);
    uint16_t udp_len  = rd16be(in + UDP_OFF_LENGTH);

    if (udp_len < UDP_HDR_LEN || (size_t)udp_len > len) {
        uart_printf("[UDP] length フィールド不正 (udp_len=%u len=%u) 破棄\n",
                    udp_len, (unsigned)len);
        return -2;
    }

    /* IPv4 の UDP チェックサムは省略可(0 なら未計算)。IPv6 では必須なので
     * 0 は本来ありえないが、届いてしまった場合も破棄せず素通しする
     * (相手の実装不備でこちらが通信不能になるのは割に合わない)。 */
    uint16_t rx_csum = rd16be(in + UDP_OFF_CHECKSUM);
    if (rx_csum != 0u && !eth_rx_hw_csum_ok()) {
        uint16_t verify;
        if (src->family == NETADDR_V6) {
            verify = ipv6_pseudo_checksum(src->a, dst->a, IPV6_NH_UDP, in, udp_len);
        } else {
            verify = pseudo_header_checksum(src->a, dst->a, IP_PROTO_UDP, in, udp_len);
        }
        if (verify != 0u) {
            uart_printf("[UDP] チェックサム不正 (計算結果=0x%04X) 破棄\n", verify);
            return -2;
        }
    }

    for (unsigned i = 0; i < UDP_MAX_BINDINGS; i++) {
        if (s_bindings[i].used && s_bindings[i].port == dst_port) {
            s_bindings[i].handler(data + UDP_HDR_LEN, (size_t)udp_len - UDP_HDR_LEN,
                                   src, src_port, src_mac);
            return 0;
        }
    }
    return -1;  /* 待ち受け無し -- 呼び出し元が Port Unreachable を返す */
}

/*=================================================================
 * IPv4 用の受信入口(ip_handle_frame から呼ぶ薄いラッパ)。
 *
 * 引数:
 *   data/len/src_ip/dst_ip/src_mac - udp_input_addr() と同じ
 * 戻り値:
 *   udp_input_addr() の戻り値そのまま
 * コール元:
 *   ip_handle_frame()
 * ===============================================================*/
int udp_input(const uint8_t *data, size_t len,
              const uint8_t src_ip[4], const uint8_t dst_ip[4],
              const uint8_t *src_mac)
{
    netaddr_t s, d;
    s.family = NETADDR_V4; d.family = NETADDR_V4;
    for (unsigned i = 0; i < 16; i++) { s.a[i] = 0; d.a[i] = 0; }
    for (unsigned i = 0; i < 4; i++) { s.a[i] = src_ip[i]; d.a[i] = dst_ip[i]; }
    return udp_input_addr(data, len, &s, &d, src_mac);
}

/*=================================================================
 * UDP データグラムを 1 個送信する。チェックサムは疑似ヘッダ込みで計算する
 * (結果が 0 になった場合は仕様どおり 0xFFFF を入れる。0 は「未計算」の
 * 意味になってしまうため)。
 *
 * 引数:
 *   dst_ip / dst_mac      - 宛先
 *   src_port / dst_port   - ポート番号(ホストバイトオーダ)
 *   payload / payload_len - ペイロード
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_udptest()
 * ===============================================================*/
int udp_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
             uint16_t src_port, uint16_t dst_port,
             const uint8_t *payload, uint16_t payload_len)
{
    static uint8_t s_buf[SMP_MAX_CORES][NET_BUF_SIZE];
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;

    uint32_t total = (uint32_t)UDP_HDR_LEN + payload_len;
    if (total > NET_BUF_SIZE) {
        uart_printf("[!] UDP: ペイロード長超過 (%u)\n", payload_len);
        return -1;
    }

    uint8_t *buf = s_buf[core];
    wr16be(buf + UDP_OFF_SRC_PORT, src_port);
    wr16be(buf + UDP_OFF_DST_PORT, dst_port);
    wr16be(buf + UDP_OFF_LENGTH,   (uint16_t)total);
    wr16be(buf + UDP_OFF_CHECKSUM, 0);  /* 計算前に 0 クリア */
    for (uint16_t i = 0; i < payload_len; i++) {
        buf[UDP_HDR_LEN + i] = payload[i];
    }

    uint32_t self = net_active_ip();
    uint8_t src_ip[4] = { (uint8_t)(self >> 24), (uint8_t)(self >> 16),
                          (uint8_t)(self >> 8),  (uint8_t)self };
    uint16_t csum = pseudo_header_checksum(src_ip, dst_ip, IP_PROTO_UDP,
                                            buf, (uint16_t)total);
    if (csum == 0u) csum = 0xFFFFu;  /* 0 は「チェックサム未計算」の意味になる */
    wr16be(buf + UDP_OFF_CHECKSUM, csum);

    return ip_send(dst_ip, dst_mac, IP_PROTO_UDP, buf, (uint16_t)total);
}

/*=================================================================
 * IPv6 版の UDP 送信。IPv6 ではチェックサムが必須なので必ず計算する。
 *
 * 引数:
 *   dst / dst_mac         - 宛先(16 バイトアドレスと MAC)
 *   src_port / dst_port   - ポート番号(ホストバイトオーダ)
 *   payload / payload_len - ペイロード
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_udptest6()
 * ===============================================================*/
int udp_send6(const uint8_t dst[16], const uint8_t dst_mac[6],
              uint16_t src_port, uint16_t dst_port,
              const uint8_t *payload, uint16_t payload_len)
{
    static uint8_t s_buf6[SMP_MAX_CORES][NET_BUF_SIZE];
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;

    uint32_t total = (uint32_t)UDP_HDR_LEN + payload_len;
    if (total > NET_BUF_SIZE) {
        uart_printf("[!] UDP: ペイロード長超過 (%u)\n", payload_len);
        return -1;
    }

    uint8_t *buf = s_buf6[core];
    wr16be(buf + UDP_OFF_SRC_PORT, src_port);
    wr16be(buf + UDP_OFF_DST_PORT, dst_port);
    wr16be(buf + UDP_OFF_LENGTH,   (uint16_t)total);
    wr16be(buf + UDP_OFF_CHECKSUM, 0);
    for (uint16_t i = 0; i < payload_len; i++) {
        buf[UDP_HDR_LEN + i] = payload[i];
    }

    /* **疑似ヘッダの送信元は「実際に IPv6 ヘッダへ書かれる送信元」でなければ
     * ならない。** ipv6_send() は ipv6_source_for() で選ぶので、ここも同じ
     * 関数を使う。以前はリンクローカル固定で、グローバル宛のときだけ食い違って
     * いた -- **NIC の L4 チェックサムオフロードが正しい値へ上書きするので
     * 気付けなかった**。B4 で断片にはオフロードを掛けないようにした途端、
     * 「断片化された UDP だけ相手が捨てる」という形で表に出た。 */
    uint8_t src[16];
    ipv6_source_for(dst, src);
    uint16_t csum = ipv6_pseudo_checksum(src, dst, IPV6_NH_UDP, buf, (uint16_t)total);
    if (csum == 0u) csum = 0xFFFFu;
    wr16be(buf + UDP_OFF_CHECKSUM, csum);

    return ipv6_send(dst, dst_mac, IPV6_NH_UDP, buf, (uint16_t)total);
}
