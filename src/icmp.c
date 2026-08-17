#include <stddef.h>
#include "icmp.h"
#include "ip.h"
#include "netif.h"
#include "arp.h"
#include "net_buf.h"
#include "net.h"
#include "netif.h"
#include "uart.h"
#include "timer.h"
#include "smp.h"
#include "pmtu.h"
#include "netaddr.h"

#define ICMP_HDR_LEN     8u
#define ICMP_OFF_TYPE    0u
#define ICMP_OFF_CODE    1u
#define ICMP_OFF_CHECKSUM 2u
#define ICMP_OFF_IDENT   4u
#define ICMP_OFF_SEQ     6u

volatile uint32_t g_icmp_echo_request_count[SMP_MAX_CORES];
volatile uint32_t g_icmp_echo_reply_sent_count[SMP_MAX_CORES];
volatile uint64_t g_icmp_echo_reply_time[SMP_MAX_CORES];

static volatile int      s_echo_reply_ready[SMP_MAX_CORES];
static volatile uint16_t s_echo_reply_ident[SMP_MAX_CORES];
static volatile uint16_t s_echo_reply_seq[SMP_MAX_CORES];

/*=================================================================
 * ICMP Destination Unreachable を返す。ペイロードは RFC 792 の規定どおり
 * 「未使用 4 バイト + 元データグラムの IP ヘッダ + 続く 8 バイト」。
 * これを返さないと、相手は届かない宛先へ延々と再送してタイムアウトを待つ
 * ことになる。
 *
 * 引数:
 *   code         - ICMP_CODE_PROTO_UNREACH / ICMP_CODE_PORT_UNREACH
 *   orig_ip_hdr  - 元データグラムの IPv4 ヘッダ先頭
 *   orig_len     - orig_ip_hdr から使える長さ
 *   src_ip       - 元データグラムの送信元(= 返す相手)
 *   src_mac      - 同上の MAC
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ip_handle_frame()
 * ===============================================================*/
int icmp_send_dest_unreach(uint8_t code,
                            const uint8_t *orig_ip_hdr, size_t orig_len,
                            const uint8_t src_ip[4], const uint8_t *src_mac)
{
    /* 元データグラムから引用するのは IP ヘッダ(20)+ 8 バイト。 */
    size_t quote = 20u + 8u;
    if (quote > orig_len) quote = orig_len;

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t msg[SMP_MAX_CORES][ICMP_HDR_LEN + 20u + 8u];

    uint8_t *out = msg[core];
    out[ICMP_OFF_TYPE] = ICMP_TYPE_DEST_UNREACH;
    out[ICMP_OFF_CODE] = code;
    wr16be(out + ICMP_OFF_CHECKSUM, 0);
    wr16be(out + ICMP_OFF_IDENT, 0);   /* Destination Unreachable では未使用 */
    wr16be(out + ICMP_OFF_SEQ,   0);
    for (size_t i = 0; i < quote; i++) {
        out[ICMP_HDR_LEN + i] = orig_ip_hdr[i];
    }

    uint16_t total = (uint16_t)(ICMP_HDR_LEN + quote);
    wr16be(out + ICMP_OFF_CHECKSUM, inet_checksum(out, total));

    return ip_send(src_ip, src_mac, IP_PROTO_ICMP, out, total);
}

/*=================================================================
 * 受信 ICMP メッセージを処理する。Echo Reply なら RTT 計測用に受信時刻と
 * id/seq を記録し(uart_printf より前に時刻を取る)、Echo Request なら
 * Echo Reply を返す。
 *
 * 引数:
 *   data    - ICMP メッセージ本体(IP ヘッダの直後)
 *   len     - data のバイト数
 *   src_ip  - 送信元 IPv4(4 オクテット)
 *   src_mac - 送信元 MAC(reply の宛先に使う)
 * コール元:
 *   ip_handle_frame()
 * ===============================================================*/
void icmp_handle(const uint8_t *data, size_t len,
                 const uint8_t src_ip[4], const uint8_t *src_mac)
{
    if (len < ICMP_HDR_LEN) {
        uart_printf("[ICMP] ヘッダ長不足 (len=%u < %u)\n", (unsigned)len, ICMP_HDR_LEN);
        return;
    }
    if (len > NET_BUF_SIZE) {
        /* 通常有り得ない(IPペイロードは最大1500バイト未満)が念のため */
        uart_printf("[!] icmp_handle: データ長超過 (%u)\n", (unsigned)len);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = data;

    uint8_t  type = in[ICMP_OFF_TYPE];
    uint8_t  code = in[ICMP_OFF_CODE];

    unsigned core = smp_core_index();

    if (type == ICMP_TYPE_ECHO_REPLY) {
        g_icmp_echo_reply_time[core] = timer_now();

        uint16_t ident = rd16be(in + ICMP_OFF_IDENT);
        uint16_t seq   = rd16be(in + ICMP_OFF_SEQ);
        uart_printf("[ICMP] Echo Reply 受信: id=%u seq=%u from %u.%u.%u.%u\n",
                    ident, seq, src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        s_echo_reply_ident[core] = ident;
        s_echo_reply_seq[core]   = seq;
        s_echo_reply_ready[core] = 1;
        return;
    }

    if (type == ICMP_TYPE_DEST_UNREACH && code == ICMP_CODE_FRAG_NEEDED) {
        /* 経路上のルータが「分割が必要だが DF が立っている」と返してきた。
         * RFC 1191 の Path MTU Discovery。**MTU は未使用 4 バイトの下位 16bit**
         * (byte 6-7)に入る -- byte 4-5 を含めた 32bit として読むと桁が狂う。 */
        if (len < ICMP_HDR_LEN + sizeof(ip_header_t)) {
            uart_printf("[ICMP] Fragmentation Needed だが引用が短い (len=%u) 無視\n",
                        (unsigned)len);
            return;
        }
        uint16_t mtu = rd16be(in + 6u);

        /* 学習する宛先は「引用された元データグラムの宛先」。ICMP の送信元
         * (= 文句を言ってきたルータ)ではない。 */
        const volatile uint8_t *quoted = in + ICMP_HDR_LEN;
        uint32_t orig_dst = rd32be(quoted + 16u);  /* IPv4 ヘッダの dst_ip */

        uart_printf("[ICMP] Fragmentation Needed 受信 (次ホップ MTU=%u) from %u.%u.%u.%u"
                    " -- 対象の宛先 %u.%u.%u.%u\n",
                    mtu, src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                    (unsigned)((orig_dst >> 24) & 0xFFu), (unsigned)((orig_dst >> 16) & 0xFFu),
                    (unsigned)((orig_dst >> 8) & 0xFFu), (unsigned)(orig_dst & 0xFFu));

        if (mtu == 0u) {
            /* RFC 1191 以前のルータは MTU を載せてこない。推測して下げる
             * (次に小さい定番の MTU を試す)方法があるが、実装していない。 */
            uart_printf("[ICMP] MTU=0(RFC 1191 非対応のルータ)-- 推測降下は未実装、無視\n");
            return;
        }
        netaddr_t dst = netaddr_v4(orig_dst);
        pmtu_learn(&dst, mtu);
        return;
    }

    if (type == ICMP_TYPE_DEST_UNREACH) {
        /* 相手が「そのポート/プロトコルには誰も居ない」と返してきた。上位へ
         * 通知する経路(接続の即時失敗など)はまだ持たないので記録のみ。 */
        const char *what = (code == ICMP_CODE_PORT_UNREACH)  ? "Port Unreachable"
                         : (code == ICMP_CODE_PROTO_UNREACH) ? "Protocol Unreachable"
                                                             : "Destination Unreachable";
        uart_printf("[ICMP] %s 受信 (code=%u) from %u.%u.%u.%u\n",
                    what, code, src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        return;
    }

    if (type == ICMP_TYPE_TIME_EXCEEDED) {
        /* **送る側は実装しない。** これを返すのは転送するノード(ルータ)で、
         * このスタックは転送しないので出番が無い。受けた側は経路異常の
         * 手掛かりになるので記録する(code=0 は TTL 切れ = ループか TTL が
         * 小さすぎる、code=1 は断片の再構成タイムアウト)。 */
        uart_printf("[ICMP] Time Exceeded 受信 (code=%u: %s) from %u.%u.%u.%u\n",
                    code,
                    (code == 0u) ? "転送中に TTL が 0 になった"
                                 : (code == 1u) ? "断片の再構成がタイムアウト" : "不明",
                    src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        return;
    }

    if (type != ICMP_TYPE_ECHO_REQUEST) {
        uart_printf("[ICMP] type=%u code=%u (Echo Request/Reply以外) 無視\n", type, code);
        return;
    }

    g_icmp_echo_request_count[core]++;

    uint16_t ident = rd16be(in + ICMP_OFF_IDENT);
    uint16_t seq   = rd16be(in + ICMP_OFF_SEQ);

    uart_printf("[ICMP] Echo Request 受信: id=%u seq=%u from %u.%u.%u.%u len=%u\n",
                ident, seq, src_ip[0], src_ip[1], src_ip[2], src_ip[3], (unsigned)len);

    static uint8_t reply[SMP_MAX_CORES][NET_BUF_SIZE];

    for (size_t i = 0; i < len; i++) reply[core][i] = in[i];

    reply[core][ICMP_OFF_TYPE] = ICMP_TYPE_ECHO_REPLY;
    reply[core][ICMP_OFF_CODE] = 0;
    wr16be(reply[core] + ICMP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */

    uint16_t csum = inet_checksum(reply[core], len);
    wr16be(reply[core] + ICMP_OFF_CHECKSUM, csum);

    int ret = ip_send(src_ip, src_mac, IP_PROTO_ICMP, reply[core], (uint16_t)len);
    if (ret == 0) {
        g_icmp_echo_reply_sent_count[core]++;
        uart_printf("[ICMP] Echo Reply 送信完了: id=%u seq=%u\n", ident, seq);
    } else {
        uart_printf("[!] ICMP: Echo Reply 送信失敗 (id=%u seq=%u)\n", ident, seq);
    }
}
