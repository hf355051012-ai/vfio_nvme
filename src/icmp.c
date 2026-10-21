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
#include "tcp.h"
#include "udp.h"
#include "ipfrag.h"

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


/* ICMP エラーを送る頻度の上限(1 秒あたり)。**エラーを返す口は、偽の送信元で
 * 大量に叩かれると反射の踏み台になる**ので、トークンバケツで抑える(RFC 1812 4.3.2.8 の
 * 考え方。IPv4 のホストには MUST ではないが、ICMPv6 は RFC 4443 2.4(f) で MUST)。 */
volatile uint32_t g_icmp_err_rate = 100u;
static uint64_t s_err_last[SMP_MAX_CORES];
static uint32_t s_err_tokens[SMP_MAX_CORES];
volatile uint32_t g_icmp_err_limited;
volatile uint32_t g_icmp_err_sent;

static int icmp_err_allowed(void)
{
    unsigned core = smp_core_index();
    uint64_t now = timer_now();
    uint32_t rate = g_icmp_err_rate;
    if (rate == 0u) return 1;   /* 0 = 制限しない */
    uint64_t gained = (now - s_err_last[core]) * rate / 1000000000ull;
    if (gained > 0u) {
        uint64_t t = s_err_tokens[core] + gained;
        s_err_tokens[core] = (uint32_t)(t > rate ? rate : t);
        s_err_last[core] = now;
    }
    if (s_err_tokens[core] == 0u) { g_icmp_err_limited++; return 0; }
    s_err_tokens[core]--;
    return 1;
}

/* エラーの ICMP を組んで送る(Destination Unreachable / Time Exceeded 共通)。 */
static int icmp_send_error(uint8_t type, uint8_t code,
                           const uint8_t *orig, size_t orig_len,
                           const uint8_t dst_ip[4], const uint8_t *dst_mac)
{
    if (!icmp_err_allowed()) return -1;
    /* 引用は元の IP ヘッダ(オプション込み、最大 60)+ 8 バイト(RFC 792)。 */
    size_t quote = orig_len;
    if (orig_len >= 1u) {
        size_t ihl = (size_t)(orig[0] & 0x0Fu) * 4u;
        if (ihl >= 20u && quote > ihl + 8u) quote = ihl + 8u;
    }
    if (quote > 60u + 8u) quote = 60u + 8u;

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t msg[SMP_MAX_CORES][ICMP_HDR_LEN + 60u + 8u];

    uint8_t *out = msg[core];
    out[ICMP_OFF_TYPE] = type;
    out[ICMP_OFF_CODE] = code;
    wr16be(out + ICMP_OFF_CHECKSUM, 0);
    wr16be(out + ICMP_OFF_IDENT, 0);   /* 未使用 */
    wr16be(out + ICMP_OFF_SEQ,   0);
    for (size_t i = 0; i < quote; i++) out[ICMP_HDR_LEN + i] = orig[i];

    uint16_t total = (uint16_t)(ICMP_HDR_LEN + quote);
    wr16be(out + ICMP_OFF_CHECKSUM, inet_checksum(out, total));
    int rc = ip_send(dst_ip, dst_mac, IP_PROTO_ICMP, out, total);
    if (rc == 0) g_icmp_err_sent++;
    return rc;
}

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
    return icmp_send_error(ICMP_TYPE_DEST_UNREACH, code, orig_ip_hdr, orig_len, src_ip, src_mac);
}

/*=================================================================
 * ICMP Time Exceeded を返す。このスタックは転送しないので code 0(TTL 切れ)は
 * 出番が無く、使うのは code 1 = 断片の組み立ての時間切れ(RFC 1122 3.3.2 の
 * MUST:先頭の断片を受け取っていたなら返す)。
 *
 * コール元:
 *   ipfrag.c(時間切れの回収)
 * ===============================================================*/
int icmp_send_time_exceeded(uint8_t code, const uint8_t *orig, size_t orig_len,
                            const uint8_t dst_ip[4], const uint8_t *dst_mac)
{
    return icmp_send_error(ICMP_TYPE_TIME_EXCEEDED, code, orig, orig_len, dst_ip, dst_mac);
}

/*=================================================================
 * 受けた ICMP エラーが引用した元のデータグラムを、上位(TCP / UDP)へ渡す
 * (RFC 1122 3.2.2.1 / 3.2.2.4 / 3.2.2.5 / 4.1.3.3 の MUST)。
 * **引用の送信元が自分でなければ何もしない**(自分が送っていないものへの
 * エラーは偽物)。TCP は引用の seq も確かめる(tcp_icmp_error、RFC 5927)。
 *
 * 引数:
 *   q / qlen   - 引用(元の IP ヘッダの先頭から)
 *   type/code  - 受けた ICMP の type / code
 *   kind       - TCP へ渡す種類(TCP_ICMP_SOFT / HARD / PMTU)
 * 戻り値:
 *   TCP の引用なら tcp_icmp_error() の戻り値、それ以外は 1(UDP など。経路 MTU は学んでよい)、
 *   引用が壊れている / 自分のものでなければ 0
 * ===============================================================*/
static int icmp_to_transport(const volatile uint8_t *q, size_t qlen,
                             uint8_t type, uint8_t code, int kind)
{
    if (qlen < 20u) return 0;
    size_t ihl = (size_t)(q[0] & 0x0Fu) * 4u;
    if ((q[0] >> 4) != 4u || ihl < 20u || qlen < ihl + 8u) return 0;
    uint32_t qsrc = rd32be(q + 12u), qdst = rd32be(q + 16u);
    if (qsrc != NET_SELF_IP) return 0;
    uint8_t l4[8];
    for (size_t i = 0; i < 8u; i++) l4[i] = q[ihl + i];
    netaddr_t local = netaddr_v4(qsrc), remote = netaddr_v4(qdst);
    uint8_t proto = q[9];
    if (proto == IP_PROTO_TCP) return tcp_icmp_error(&local, &remote, l4, 8u, kind);
    if (proto == IP_PROTO_UDP && kind != TCP_ICMP_PMTU) udp_icmp_error(&remote, l4, 8u, type, code, 0);
    return 1;
}

/* RFC 1191 7 の「よく使われる MTU」の段。MTU を載せない古いルータの Fragmentation Needed で、
 * 引用された元の全長より小さい段へ下げる。 */
static const uint16_t s_plateaus[] = { 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 };

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
    if (len > IPFRAG_MAX_LEN) {
        uart_printf("[!] icmp_handle: データ長超過 (%u)\n", (unsigned)len);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = data;

    /* **チェックサムを確かめる**(RFC 792。NIC の検証の印は L3 と TCP / UDP の分で、
     * ICMP は見ていない)。壊れた Fragmentation Needed で経路 MTU を下げられない
     * ように、どの type でも先に確かめる。 */
    if (inet_checksum(in, len) != 0u) {
        uart_printf("[ICMP] チェックサム不正 -- 破棄\n");
        return;
    }

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

        /* **引用が自分の送ったものかを確かめる**(RFC 5927)。TCP なら生きている
         * コネクションの、送った範囲の seq でなければ偽物として無視する
         * (偽の ICMP 1 通で、ある宛先への全コネクションの MSS を下げられないように)。 */
        if (!icmp_to_transport(quoted, len - ICMP_HDR_LEN, type, code, TCP_ICMP_PMTU)) {
            uart_printf("[ICMP] Fragmentation Needed の引用が自分の通信と合わない -- 無視\n");
            return;
        }

        uart_printf("[ICMP] Fragmentation Needed 受信 (次ホップ MTU=%u) from %u.%u.%u.%u"
                    " -- 対象の宛先 %u.%u.%u.%u\n",
                    mtu, src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                    (unsigned)((orig_dst >> 24) & 0xFFu), (unsigned)((orig_dst >> 16) & 0xFFu),
                    (unsigned)((orig_dst >> 8) & 0xFFu), (unsigned)(orig_dst & 0xFFu));

        if (mtu == 0u) {
            /* **MTU を載せない古いルータ**(RFC 1191 以前)。報告が無くても推定を
             * 下げる MUST(RFC 1191 3)。引用された元の全長より小さい「よく使われる
             * MTU」の段へ下げる(RFC 1191 5 / 7)。 */
            uint16_t qtot = rd16be(quoted + 2u);
            mtu = 68u;
            for (unsigned i = 0; i < sizeof(s_plateaus) / sizeof(s_plateaus[0]); i++) {
                if (s_plateaus[i] < qtot) { mtu = s_plateaus[i]; break; }
            }
            uart_printf("[ICMP] MTU=0(RFC 1191 以前のルータ)-- 元の全長 %u から %u と推定\n",
                        qtot, mtu);
        }
        netaddr_t dst = netaddr_v4(orig_dst);
        pmtu_learn(&dst, mtu);
        return;
    }

    if (type == ICMP_TYPE_DEST_UNREACH) {
        /* 上位へ渡す(RFC 1122 3.2.2.1 の MUST)。**相手に口が無い**(Protocol /
         * Port Unreachable)は TCP の接続の途中なら失敗させる(4.2.3.9 の SHOULD。
         * 確立後は一時的なエラー扱い、RFC 5461)。それ以外(ネットワーク / ホスト
         * 到達不能など)は一時的なエラー。 */
        const char *what = (code == ICMP_CODE_PORT_UNREACH)  ? "Port Unreachable"
                         : (code == ICMP_CODE_PROTO_UNREACH) ? "Protocol Unreachable"
                                                             : "Destination Unreachable";
        uart_printf("[ICMP] %s 受信 (code=%u) from %u.%u.%u.%u\n",
                    what, code, src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        int hard = (code == ICMP_CODE_PORT_UNREACH || code == ICMP_CODE_PROTO_UNREACH);
        icmp_to_transport(in + ICMP_HDR_LEN, len - ICMP_HDR_LEN, type, code,
                          hard ? TCP_ICMP_HARD : TCP_ICMP_SOFT);
        return;
    }

    if (type == ICMP_TYPE_TIME_EXCEEDED || type == ICMP_TYPE_PARAM_PROBLEM) {
        /* 上位へ一時的なエラーとして渡す(RFC 1122 3.2.2.4 / 3.2.2.5 の MUST)。
         * Time Exceeded の code 0 は TTL 切れ(ループか TTL が小さすぎる)、code 1 は
         * 相手での断片の組み立ての時間切れ。 */
        uart_printf("[ICMP] %s 受信 (code=%u) from %u.%u.%u.%u\n",
                    type == ICMP_TYPE_TIME_EXCEEDED ? "Time Exceeded" : "Parameter Problem",
                    code, src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        icmp_to_transport(in + ICMP_HDR_LEN, len - ICMP_HDR_LEN, type, code, TCP_ICMP_SOFT);
        return;
    }

    if (type == ICMP_TYPE_REDIRECT) {
        /* **経路の付け替えを受け入れる**(RFC 1122 3.2.2.2 の MUST)。Network Redirect も
         * Host Redirect として扱う(同節。サブネットの形を知らないため)。ただし次の
         * どれかに当たれば黙って捨てる(同節の SHOULD):
         *  - 引用が自分の送ったものでない
         *  - 送ってきたのが、その宛先のいまの次ホップ(ゲートウェイ)でない
         *    (同じリンクの誰でも経路を書き換えられてしまう)
         *  - 新しいゲートウェイが自分のサブネットに居ない、または自分自身 */
        netif_t *ni = g_active_ctx;
        if (!ni || len < ICMP_HDR_LEN + 20u) return;
        const volatile uint8_t *q = in + ICMP_HDR_LEN;
        uint32_t new_gw = rd32be(in + 4u);
        uint32_t qsrc = rd32be(q + 12u), qdst = rd32be(q + 16u);
        uint32_t from = ip_from_octets(src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        uint32_t cur = netif_next_hop4(ni, qdst);
        int valid = (qsrc == NET_SELF_IP) && (cur != qdst) && (from == cur) &&
                    ni->netmask != 0u && ((new_gw ^ ni->ip) & ni->netmask) == 0u &&
                    new_gw != ni->ip && new_gw != 0u;
        uart_printf("[ICMP] Redirect 受信 (code=%u) from %u.%u.%u.%u: %u.%u.%u.%u 宛ては %u.%u.%u.%u へ -- %s\n",
                    code, src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                    (qdst >> 24) & 0xFFu, (qdst >> 16) & 0xFFu, (qdst >> 8) & 0xFFu, qdst & 0xFFu,
                    (new_gw >> 24) & 0xFFu, (new_gw >> 16) & 0xFFu, (new_gw >> 8) & 0xFFu, new_gw & 0xFFu,
                    valid ? "受け入れる" : "条件に合わないので捨てる");
        if (valid) netif_dest4_set(ni, qdst, new_gw);
        return;
    }

    if (type == ICMP_TYPE_SOURCE_QUENCH) {
        /* 黙って捨てる(RFC 6633:Source Quench は廃止され、ホストは無視する MUST)。 */
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

    /* 要求のデータは全部そのまま返す(RFC 1122 3.2.2.6 の MUST)。断片を組み立てた
     * 64KB 近い要求にも答えられる大きさを持つ(送りは ip_send() が分割する)。 */
    static uint8_t reply[SMP_MAX_CORES][IPFRAG_MAX_LEN];

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
