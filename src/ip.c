#include "ipsec.h"
#include <stddef.h>
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "netif.h"
#include "net_buf.h"
#include "net.h"
#include "uart.h"
#include "smp.h"
#include "pmtu.h"
#include "netaddr.h"
#include "ipfrag.h"

/* [切り分け] Ethernet の受信キューへ届いた RoCEv2(UDP 4791)を数える(`rocedup`)。
 * 宛先 QP 番号(BTH の byte 5-7)ごとに件数と最後の opcode を控える。 */
#define ROCE_DUP_QPN_SLOTS 8u
typedef struct {
    volatile uint64_t total, gsi, other_qpn, ours, not_ours, overflow;
    struct { volatile uint32_t qpn, cnt; volatile uint8_t op; } q[ROCE_DUP_QPN_SLOTS];
} roce_dup_stat_t;
static roce_dup_stat_t s_roce_dup;
/* 数える宛先ポート。既定は 4791。陽性対照のときだけ別のポートにする(`rocedup port N`)。 */
static volatile uint16_t s_roce_dup_port = UDP_PORT_ROCEV2;

static void roce_dup_count(const uint8_t *udp, uint32_t len, const uint8_t dst[4])
{
    s_roce_dup.total++;
    if (netif_find_by_ip(ip_from_octets(dst[0], dst[1], dst[2], dst[3]))) s_roce_dup.ours++;
    else s_roce_dup.not_ours++;
    if (len < 8u + 12u) return;
    const uint8_t *bth = udp + 8;
    uint32_t qpn = ((uint32_t)bth[5] << 16) | ((uint32_t)bth[6] << 8) | bth[7];
    if (qpn == 1u) s_roce_dup.gsi++; else s_roce_dup.other_qpn++;
    for (unsigned i = 0; i < ROCE_DUP_QPN_SLOTS; i++) {
        if (s_roce_dup.q[i].cnt && s_roce_dup.q[i].qpn == qpn) {
            s_roce_dup.q[i].cnt++; s_roce_dup.q[i].op = bth[0]; return;
        }
        if (!s_roce_dup.q[i].cnt) {
            s_roce_dup.q[i].qpn = qpn; s_roce_dup.q[i].op = bth[0]; s_roce_dup.q[i].cnt = 1; return;
        }
    }
    s_roce_dup.overflow++;
}

/*=================================================================
 * シェルの `rocedup port N`。数える宛先ポートを変える(陽性対照用。0 で 4791 に戻す)。
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void ip_roce_dup_set_port(uint16_t port)
{
    s_roce_dup_port = port ? port : UDP_PORT_ROCEV2;
    uart_printf("rocedup: 数える宛先ポート = %u\n", (unsigned)s_roce_dup_port);
}

/*=================================================================
 * シェルの `rocedup`。Ethernet の受信キューへ届いた RoCEv2 の数を出す。
 * 引数:
 *   clear - 非 0 なら 0 に戻す
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void ip_roce_dup_show(int clear)
{
    if (clear) {
        volatile uint8_t *p = (volatile uint8_t *)&s_roce_dup;
        for (unsigned i = 0; i < sizeof(s_roce_dup); i++) p[i] = 0;
        uart_printf("rocedup: 0 に戻しました\n");
        return;
    }
    uart_printf("rocedup: 計 %llu(宛先が自分 %llu / 自分以外 %llu)、宛先 QP=1(GSI)%llu / それ以外 %llu\n",
                (unsigned long long)s_roce_dup.total, (unsigned long long)s_roce_dup.ours,
                (unsigned long long)s_roce_dup.not_ours, (unsigned long long)s_roce_dup.gsi,
                (unsigned long long)s_roce_dup.other_qpn);
    for (unsigned i = 0; i < ROCE_DUP_QPN_SLOTS; i++) {
        if (!s_roce_dup.q[i].cnt) break;
        uart_printf("  qpn=0x%06x 件数=%u 最後の opcode=0x%02x\n",
                    s_roce_dup.q[i].qpn, s_roce_dup.q[i].cnt, s_roce_dup.q[i].op);
    }
    if (s_roce_dup.overflow) uart_printf("  (表に入らなかった %llu)\n", (unsigned long long)s_roce_dup.overflow);
}

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

/* 送るデータグラムの TTL と TOS(RFC 1122 3.2.1.7 は TTL を設定できること、3.2.1.6 は
 * TOS を上位から設定できることを MUST とする)。シェルの `ipttl` / `iptos` で変える。 */
volatile uint8_t g_ip_ttl = IP_DEFAULT_TTL;
volatile uint8_t g_ip_tos = 0;

/* IP の Identification。**DF を立てる TCP(分割されない = atomic)と、分割しうる
 * UDP / ICMP とで数え方を分ける**(RFC 6864)。atomic な方はどんな値でもよい。
 * 分割しうる方は、同じ (送信元, 宛先, プロトコル) で寿命の間に重ならないことが
 * MUST なので、コアごとの数え始めを 4096 ずつずらし、コアどうしで重ならないように
 * する(TCP の大量の送信でこちらの番号を消費しない)。 */
static uint16_t s_ip_id[SMP_MAX_CORES];
static uint16_t s_ip_id_frag[SMP_MAX_CORES];

static inline uint16_t ip_next_frag_id(void)
{
    unsigned core = smp_core_index();
    uint16_t n = s_ip_id_frag[core]++;
    return (uint16_t)(((core & 0xFu) << 12) | (n & 0x0FFFu));
}

/*=================================================================
 * 受信したデータグラムの送信元が、1 台の機器を指す正しいアドレスか
 * (RFC 1122 3.2.1.3。正しくないものは黙って捨てる MUST)。
 * 0.0.0.0、ブロードキャスト(全 1 と、自分のサブネットの全 1)、
 * マルチキャスト(224/4)、予約(240/4)、ループバック(127/8)は正しくない。
 * **比較が数個だけ**なので、TCP の受信ごとに通しても費用は無視できる。
 * ===============================================================*/
static inline int ip_src_valid(uint32_t s)
{
    if (s == 0u || (s >> 28) >= 0xEu || (s >> 24) == 127u) return 0;
    const netif_t *ni = g_active_ctx;
    if (ni && ni->netmask != 0u && ni->netmask != 0xFFFFFFFFu &&
        (s & ~ni->netmask) == ~ni->netmask && (s & ni->netmask) == (ni->ip & ni->netmask)) {
        return 0;   /* 自分のサブネットのブロードキャスト */
    }
    return 1;
}

/*=================================================================
 * 宛先が、自分のサブネットか全体へのブロードキャストか(RFC 1122 3.3.6)。
 * ===============================================================*/
static inline int ip_dst_is_bcast(uint32_t d)
{
    if (d == 0xFFFFFFFFu) return 1;
    const netif_t *ni = g_active_ctx;
    return ni && ni->netmask != 0u && ni->netmask != 0xFFFFFFFFu &&
           (d & ~ni->netmask) == ~ni->netmask && (d & ni->netmask) == (ni->ip & ni->netmask);
}

/*=================================================================
 * ICMP エラーに付ける「元のデータグラムの IP ヘッダ + 続く 8 バイト」を作る
 * (RFC 792 / RFC 1122 3.2.2)。組み立てたデータグラムなら、最後に届いた断片の
 * ヘッダではなく、組み立て後の姿(オフセット 0、MF 無し、全長)と、先頭 8 バイト
 * (上位のヘッダ)を引用する。そうしないと相手は誰宛てのエラーか分からない。
 *
 * 引数:
 *   out            - 書き込み先(60 + 8 バイト以上)
 *   hdr / hdr_len  - 受信した IP ヘッダ
 *   payload / plen - 上位へ渡すペイロード(組み立て後なら全体)
 *   reasm          - 1 なら組み立てたデータグラム
 * 戻り値:
 *   書いたバイト数
 * ===============================================================*/
static size_t ip_icmp_quote(uint8_t *out, const volatile uint8_t *hdr, size_t hdr_len,
                            const uint8_t *payload, size_t plen, int reasm)
{
    for (size_t i = 0; i < hdr_len; i++) out[i] = hdr[i];
    if (reasm) {
        wr16be(out + IP_OFF_TOTAL_LEN, (uint16_t)(hdr_len + plen));
        wr16be(out + IP_OFF_FLAGS_FRAG, (uint16_t)(rd16be(out + IP_OFF_FLAGS_FRAG) & 0x4000u));
        wr16be(out + IP_OFF_CHECKSUM, 0);
        wr16be(out + IP_OFF_CHECKSUM, inet_checksum(out, hdr_len));
    }
    size_t d = plen < 8u ? plen : 8u;
    for (size_t i = 0; i < d; i++) out[hdr_len + i] = payload[i];
    return hdr_len + d;
}

/* 受信した断片を観測するフック(検証専用、既定は無効)。ip.c は断片を
 * 再構成しないので、これを登録しないと送信側の分割が正しいかを確かめられない。 */
static ip_frag_observer_t s_frag_observer;

/*=================================================================
 * 受信断片の観測フックを登録する(NULL で解除)。登録中は断片ごとの
 * 「未対応、破棄」ログを出さない(断片の数だけ行が出て読めなくなるため)。
 *
 * 引数:
 *   fn - 断片ごとに呼ばれる関数。NULL で解除
 * コール元:
 *   shell_fragtest()
 * ===============================================================*/
void ip_set_frag_observer(ip_frag_observer_t fn)
{
    s_frag_observer = fn;
}

/*=================================================================
 * EtherType 0x0800(IPv4)のフレームハンドラを登録する。
 *
 * コール元:
 *   run_shell()
 * ===============================================================*/
void ip_init(void)
{
    eth_register_handler(0x0800u, ip_handle_frame);  /* EtherType: IPv4 */
}

/*=================================================================
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
 * ===============================================================*/
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
    /* **オプション付きのヘッダも受け取る**(RFC 1122 3.2.1.8:知らないオプションは
     * 黙って無視する MUST)。このソフトはオプションを使わないので、ヘッダ長だけ
     * 正しく読み飛ばす。IHL が 5 未満は形が壊れている。 */
    size_t hdr_len = (size_t)ihl * 4u;
    if (ihl < 5u || hdr_len > len) {
        uart_printf("[IP] IHL が不正 (IHL=%u len=%u) 無視\n", ihl, (unsigned)len);
        return;
    }

    if (!eth_rx_hw_csum_ok()) {
        uint16_t verify = inet_checksum(in, hdr_len);
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
    if (total_len < hdr_len) {
        uart_printf("[IP] total_lengthがヘッダ長未満 (total_len=%u) 無視\n", total_len);
        return;
    }

    /* RoCEv2(UDP 4791)は NIC の RDMA の受信が QP へ配るもので、ここへ届いた写しは宛先を問わず
     * 数えて捨てる(`rocedup`。ICMP のエラーも返さない)。宛先の判定より前に置くのは、
     * 自分以外の宛先の写しも数えるため。 */
    if (in[IP_OFF_PROTOCOL] == IP_PROTO_UDP && total_len >= hdr_len + 4u &&
        rd16be(in + hdr_len + 2) == s_roce_dup_port) {
        uint8_t d[4] = { in[IP_OFF_DST_IP], in[IP_OFF_DST_IP + 1], in[IP_OFF_DST_IP + 2], in[IP_OFF_DST_IP + 3] };
        roce_dup_count(payload + hdr_len, (uint32_t)(total_len - hdr_len), d);
        return;
    }

    /* 宛先は自分のアドレス。ブロードキャストは UDP だけへ渡す(RFC 1122 3.3.6 は
     * ブロードキャストを宛先として認識することを MUST とする。TCP はブロードキャストを
     * 使わない。ICMP Echo への応答もしない -- 3.2.2.6 が黙って捨ててよいとしている)。 */
    uint32_t dst_ip = rd32be(in + IP_OFF_DST_IP);
    int dst_bcast = 0;
    if (dst_ip != NET_SELF_IP) {
        if (in[IP_OFF_PROTOCOL] != IP_PROTO_UDP || !ip_dst_is_bcast(dst_ip)) return;
        dst_bcast = 1;
    }

    /* 送信元が 1 台の機器を指していなければ黙って捨てる(RFC 1122 3.2.1.3 の MUST)。
     * ブロードキャストやマルチキャストを名乗るデータグラムに ICMP エラーを返すと、
     * 1 通で全員へ撒くことになる。 */
    if (!ip_src_valid(rd32be(in + IP_OFF_SRC_IP))) return;
    /* **リンク層のブロードキャスト / マルチキャストで届いたのに IP の宛先が自分だけ**
     * というデータグラムは黙って捨てる(RFC 1122 3.3.6 の SHOULD)。ICMP エラーも
     * 返さない(3.2.2 の MUST NOT)。 */
    int l2_mcast = eth_rx_l2_multicast();
    if (l2_mcast && !dst_bcast) return;

    uint8_t protocol = in[IP_OFF_PROTOCOL];
    uint8_t src_ip[4];
    src_ip[0] = in[IP_OFF_SRC_IP + 0];
    src_ip[1] = in[IP_OFF_SRC_IP + 1];
    src_ip[2] = in[IP_OFF_SRC_IP + 2];
    src_ip[3] = in[IP_OFF_SRC_IP + 3];

    size_t ip_payload_len = (size_t)total_len - hdr_len;
    const uint8_t *ip_payload = payload + hdr_len;
    int reasm = 0;

    /* 断片化されたデータグラムは組み立ててから上位へ渡す。**断片のまま
     * 渡してはいけない**(TCP/ICMP が壊れたペイロードを読む)。MF(bit13)が
     * 立っているか、フラグメントオフセット(bit12-0)が非 0 なら断片。
     *
     * 観測フックは残してある -- `fragtest` が「送信側の分割が RFC 791
     * どおりか」を断片単位で確かめるのに使う。**組み立てを実装した今は
     * 素通しの覗き見**にしてあるので、フックを付けたまま往復もできる。 */
    uint16_t flags_frag = rd16be(in + IP_OFF_FLAGS_FRAG);
    if ((flags_frag & 0x2000u) != 0u || (flags_frag & 0x1FFFu) != 0u) {
        uint32_t frag_off = (uint32_t)(flags_frag & 0x1FFFu) * 8u;
        int      more     = (flags_frag & 0x2000u) != 0u;
        if (s_frag_observer) {
            s_frag_observer(rd16be(in + IP_OFF_ID), (uint16_t)frag_off, more,
                            protocol, ip_payload, (uint16_t)ip_payload_len);
        }
        /* IPv4 のデータグラムは IP ヘッダを含めて 65535 バイトまで(RFC 791)。
         * 組み立てた後にそれを越えるものは作らせない。 */
        if (frag_off + ip_payload_len + hdr_len > 65535u) {
            uart_printf("[IP] 断片を組み立てると 65535 バイトを越える (off=%u len=%u) 破棄\n",
                        (unsigned)frag_off, (unsigned)ip_payload_len);
            return;
        }
        netaddr_t fs = netaddr_v4(ip_from_octets(src_ip[0], src_ip[1], src_ip[2], src_ip[3]));
        netaddr_t fd = netaddr_v4(dst_ip);
        const uint8_t *whole = NULL;
        uint32_t whole_len = 0;
        if (!ipfrag_input(&fs, &fd, rd16be(in + IP_OFF_ID), protocol,
                          frag_off, more, ip_payload, (uint32_t)ip_payload_len,
                          payload, (uint32_t)(hdr_len + (ip_payload_len < 8u ? ip_payload_len : 8u)),
                          src_mac, &whole, &whole_len, NULL)) {
            return;  /* まだそろっていない */
        }
        ip_payload     = whole;
        ip_payload_len = whole_len;
        reasm = 1;
    }

    if (g_ipsec_npol) {
        const uint32_t sip = ip_from_octets(src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        if (protocol == IP_PROTO_ESP) {
            /* ESP の受け口は「20 バイトの IP ヘッダ + ESP」を受け取り、その場で復号する。
             * **組み立てたデータグラムとオプション付きのヘッダ**は、20 バイトの
             * ヘッダを付け直した写しを渡す(最後の断片だけを渡すと復号できない)。 */
            if (reasm || hdr_len != sizeof(ip_header_t)) {
                static uint8_t esp_buf[SMP_MAX_CORES][20u + IPFRAG_MAX_LEN] __attribute__((aligned(64)));
                uint8_t *b = esp_buf[smp_core_index()];
                for (size_t i = 0; i < 20u; i++) b[i] = in[i];
                b[IP_OFF_VER_IHL] = 0x45u;
                wr16be(b + IP_OFF_TOTAL_LEN, (uint16_t)(20u + ip_payload_len));
                wr16be(b + IP_OFF_FLAGS_FRAG, 0);
                for (size_t i = 0; i < ip_payload_len; i++) b[20u + i] = ip_payload[i];
                ipsec_esp_input(b, 20u + ip_payload_len, src_mac);
            } else {
                ipsec_esp_input(payload, total_len, src_mac);
            }
            return;
        }
        /* IPsec の方針を持つ相手からの平文(IKE 以外)は捨てる。 */
        if (ipsec_rx_drop_plain(sip, protocol, ip_payload, ip_payload_len)) return;
    }

    if (protocol == IP_PROTO_ICMP) {
        icmp_handle(ip_payload, ip_payload_len, src_ip, src_mac);
    } else if (protocol == IP_PROTO_TCP) {
        uint32_t src_ip_host = ip_from_octets(src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        tcp_input(ip_payload, (uint16_t)ip_payload_len, src_ip_host);
    } else if (protocol == IP_PROTO_UDP) {
        uint8_t dst_ip_oct[4];
        dst_ip_oct[0] = in[IP_OFF_DST_IP + 0];
        dst_ip_oct[1] = in[IP_OFF_DST_IP + 1];
        dst_ip_oct[2] = in[IP_OFF_DST_IP + 2];
        dst_ip_oct[3] = in[IP_OFF_DST_IP + 3];
        if (udp_input(ip_payload, ip_payload_len, src_ip, dst_ip_oct, src_mac) == -1 &&
            !dst_bcast) {
            /* 待ち受けの無いポート宛 -- Port Unreachable を返す。ブロードキャスト宛てには
             * 返さない(RFC 1122 3.2.2 の MUST NOT。全員が一斉に返すことになる)。 */
            uint8_t q[60u + 8u];
            size_t qn = ip_icmp_quote(q, in, hdr_len, ip_payload, ip_payload_len, reasm);
            icmp_send_dest_unreach(ICMP_CODE_PORT_UNREACH, q, qn, src_ip, src_mac);
        }
    } else {
        /* 上位が居ないプロトコルは Protocol Unreachable を返す。相手を無駄に
         * 待たせないため。ICMP エラーに対して ICMP エラーは返さない(RFC 1122 3.2.2)
         * が、ここへ来るのは ICMP/TCP/UDP 以外なのでその条件には当たらない。 */
        uart_printf("[IP] 未対応プロトコル (protocol=%u)、Protocol Unreachable を返します\n",
                    protocol);
        uint8_t q[60u + 8u];
        size_t qn = ip_icmp_quote(q, in, hdr_len, ip_payload, ip_payload_len, reasm);
        icmp_send_dest_unreach(ICMP_CODE_PROTO_UNREACH, q, qn, src_ip, src_mac);
    }
}

/*=================================================================
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
 * ===============================================================*/
static void ip_build_header_frag(uint8_t *buf, const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                                  uint8_t protocol, uint16_t payload_len,
                                  uint16_t id, uint16_t flags_frag)
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
    iph[IP_OFF_TOS]     = g_ip_tos;
    wr16be(iph + IP_OFF_TOTAL_LEN, total_len);
    wr16be(iph + IP_OFF_ID, id);
    wr16be(iph + IP_OFF_FLAGS_FRAG, flags_frag);
    iph[IP_OFF_TTL]      = g_ip_ttl;
    iph[IP_OFF_PROTOCOL] = protocol;
    wr16be(iph + IP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */
    for (int i = 0; i < 4; i++) iph[IP_OFF_SRC_IP + i] = self_ip[i];
    for (int i = 0; i < 4; i++) iph[IP_OFF_DST_IP + i] = vdst_ip[i];

    uint16_t csum = inet_checksum(iph, sizeof(ip_header_t));
    wr16be(iph + IP_OFF_CHECKSUM, csum);
}

/*=================================================================
 * TCP 用。**DF(分割禁止)を立てる**(RFC 1191 6.5:経路 MTU 探索をする経路の
 * データグラムは DF を立てるべき)。立てないと、MTU の小さい経路のルータが
 * 黙って分割し、Fragmentation Needed が返らないので経路 MTU を学べない。
 * 分割されない(atomic な)データグラムなので、ID は数え方を問わない(RFC 6864)。
 * ===============================================================*/
void ip_build_header(uint8_t *buf, const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                      uint8_t protocol, uint16_t payload_len)
{
    ip_build_header_frag(buf, dst_ip, dst_mac, protocol, payload_len,
                          s_ip_id[smp_core_index()]++, 0x4000u);
}

/*=================================================================
 * net_buf を1つ確保し、Ethernet+IPv4 ヘッダまで書いた状態で返す。
 * 呼び出し元はペイロードを IP_PAYLOAD_OFFSET から書き込む。
 *
 * 引数:
 *   dst_ip / dst_mac / protocol / payload_len - ip_build_header() と同じ
 * 戻り値:
 *   ヘッダ構築済みの net_buf。フレーム長超過/プール枯渇なら NULL
 * コール元:
 *   ip_send()
 * ===============================================================*/
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

    /* UDP / ICMP は経路で分割されてよいので DF を立てない。ID は分割しうる側の数え方。 */
    ip_build_header_frag(nb->data, dst_ip, dst_mac, protocol, payload_len, ip_next_frag_id(), 0u);
    nb->len = (uint16_t)(ETH_HDR_LEN + sizeof(ip_header_t) + payload_len);
    return nb;
}

/*=================================================================
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
 * ===============================================================*/
int ip_send_prepared(net_buf_t *nb, uint16_t payload_len)
{
    (void)payload_len;  /* IPヘッダはip_prepare_send_buf()内で既に確定済み(チェックサム込み) */
    return eth_send(nb);
}

/*=================================================================
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
 * ===============================================================*/
/*=================================================================
 * リンク MTU を超えるペイロードを RFC 791 の断片へ分割して送る。
 *
 * 断片化で間違えやすいのは 3 点で、いずれもここで面倒を見ている:
 *  - **フラグメントオフセットは 8 バイト単位**なので、最後以外の断片長は
 *    8 の倍数でなければならない(MTU をそのまま使うと端数が出る)。
 *  - **全断片で IP ID を同じにする。** 受信側は (src, dst, protocol, id) で
 *    束ねるので、断片ごとに ID を振ると再構成できない。
 *  - **上位プロトコルのヘッダは先頭断片にしか入らない。** だから分割は
 *    「UDP データグラム全体を IP ペイロードとして」行う(ここが正しい層)。
 *
 * 引数:
 *   dst_ip / dst_mac / protocol - 全断片で共通
 *   payload / payload_len       - 分割対象の IP ペイロード全体
 *   max_payload                 - 1 断片に入れられる IP ペイロードの上限
 * 戻り値:
 *   0=全断片を送信できた、-1=いずれかで失敗
 * コール元:
 *   ip_send()
 * ===============================================================*/
static int ip_send_fragmented(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                               uint8_t protocol, const uint8_t *payload,
                               uint16_t payload_len, uint16_t max_payload)
{
    uint16_t chunk = (uint16_t)(max_payload & ~7u);  /* オフセットは 8 バイト単位 */
    if (chunk == 0u) {
        uart_printf("[!] IP: MTU が小さすぎて断片化できない (max_payload=%u)\n", max_payload);
        return -1;
    }

    const uint16_t id = ip_next_frag_id();  /* 全断片で共通 */
    uint16_t off = 0;
    unsigned count = 0;

    while (off < payload_len) {
        uint16_t remain = (uint16_t)(payload_len - off);
        uint16_t this_len = (remain > chunk) ? chunk : remain;
        int more = (uint16_t)(off + this_len) < payload_len;

        net_buf_t *nb = net_buf_alloc();
        if (!nb) {
            uart_printf("[!] IP: 断片送信中に net_buf プール枯渇 (offset=%u)\n", off);
            return -1;
        }
        uint16_t flags_frag = (uint16_t)((more ? 0x2000u : 0u) | (off / 8u));
        ip_build_header_frag(nb->data, dst_ip, dst_mac, protocol, this_len, id, flags_frag);

        const volatile uint8_t *vpayload = payload + off;
        volatile uint8_t *body = nb->data + IP_PAYLOAD_OFFSET;
        for (uint16_t i = 0; i < this_len; i++) body[i] = vpayload[i];
        nb->len = (uint16_t)(IP_PAYLOAD_OFFSET + this_len);

        if (eth_send(nb) != 0) {  /* eth_send() が net_buf を解放する */
            uart_printf("[!] IP: 断片の送信失敗 (offset=%u len=%u)\n", off, this_len);
            return -1;
        }
        off = (uint16_t)(off + this_len);
        count++;
    }

    uart_printf("[IP] %u バイトを %u 個の断片へ分割して送信 (id=%u 断片長=%u)\n",
                payload_len, count, id, chunk);
    return 0;
}

int ip_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
            uint8_t protocol, const uint8_t *payload, uint16_t payload_len)
{
    /* リンク MTU を超えるなら断片へ分割する。TCP は MSS で自分で収めるので
     * ここへは来ない(来るのは UDP と ICMP)。経路 MTU を学習済みなら、
     * リンク MTU ではなくそちらに合わせる(Path MTU Discovery の反映先)。 */
    uint16_t ip_mtu = net_active_ip_mtu();
    {
        netaddr_t d = netaddr_v4(((uint32_t)dst_ip[0] << 24) | ((uint32_t)dst_ip[1] << 16) |
                                  ((uint32_t)dst_ip[2] << 8) | (uint32_t)dst_ip[3]);
        uint16_t pm = pmtu_lookup(&d);
        if (pm != 0u && pm < ip_mtu) ip_mtu = pm;
    }
    uint16_t max_payload = (ip_mtu > (uint16_t)sizeof(ip_header_t))
                               ? (uint16_t)(ip_mtu - sizeof(ip_header_t)) : 0u;
    if (payload_len > max_payload) {
        return ip_send_fragmented(dst_ip, dst_mac, protocol, payload, payload_len, max_payload);
    }

    net_buf_t *nb = ip_prepare_send_buf(dst_ip, dst_mac, protocol, payload_len);
    if (!nb) {
        return -1;
    }

    const volatile uint8_t *vpayload = payload;
    volatile uint8_t *body = nb->data + IP_PAYLOAD_OFFSET;
    for (uint16_t i = 0; i < payload_len; i++) body[i] = vpayload[i];

    return ip_send_prepared(nb, payload_len);
}
