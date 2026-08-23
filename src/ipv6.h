#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
#include <stddef.h>
#include "netif.h"
#include "smp.h"

#define IPV6_ADDR_LEN 16u
#define IPV6_HDR_LEN  40u

/* Next Header(IPv4 の protocol 相当)。値は Linux の
 * `include/net/ipv6.h` の NEXTHDR_* と同じ。 */
#define IPV6_NH_HOPOPTS  0u   /* Hop-by-Hop Options(拡張ヘッダ) */
#define IPV6_NH_TCP      6u
#define IPV6_NH_UDP      17u
#define IPV6_NH_ROUTING  43u  /* Routing(拡張ヘッダ) */
#define IPV6_NH_FRAGMENT 44u  /* Fragment(拡張ヘッダ) */
#define IPV6_NH_ICMPV6   58u
#define IPV6_NH_NONE     59u  /* 上位ヘッダ無し */
#define IPV6_NH_DSTOPTS  60u  /* Destination Options(拡張ヘッダ) */

/* Hop-by-Hop / Destination Options の TLV 種別(Linux の `linux/in6.h`)。 */
#define IPV6_TLV_PAD1         0u
#define IPV6_TLV_PADN         1u
#define IPV6_TLV_ROUTER_ALERT 5u

/* **未知のオプションをどう扱うかは type の上位 2 ビットが決める**
 * (RFC 8200 4.2)。ここを無視して一律に読み飛ばすと、相手が「捨ててくれ」と
 * 指定したパケットを受け入れてしまう。 */
#define IPV6_TLV_ACT_MASK     0xC0u
#define IPV6_TLV_ACT_SKIP     0x00u  /* 00: 読み飛ばして処理を続ける */
#define IPV6_TLV_ACT_DISCARD  0x40u  /* 01: 破棄 */
/* 10/11 も破棄(加えて ICMPv6 Parameter Problem を返すべきだが未実装)。 */

/* Fragment 拡張ヘッダ(RFC 8200 4.5、glibc の struct ip6_frag)。8 バイト固定。
 *   nxt(0) / reserved(1) / offset+flags(2-3) / identification(4-7)
 * offset は **8 バイト単位で上位 13 ビット**、最下位ビットが More Fragments。 */
#define IPV6_FRAG_HDR_LEN 8u
#define IPV6_FRAG_MORE    0x0001u
#define IPV6_FRAG_OFF_MASK 0xFFF8u

/* ICMPv6 type */
/* Packet Too Big は IPv4 の「Fragmentation Needed」に相当するが、**MTU の
 * 置き場所が違う**。ICMPv6 は 4-7 バイトの 32bit 全体が MTU で、IPv4 は
 * 未使用 4 バイトの下位 16bit だけ。ここを取り違えやすい。
 * IPv6 は経路上で分割しない仕様なので、これを処理しないと MTU の小さい経路で
 * **通信が完全に成立しない**(IPv4 なら経路が分割してくれる)。 */
#define ICMPV6_TYPE_PACKET_TOO_BIG 2u
#define ICMPV6_TYPE_TIME_EXCEEDED  3u
#define ICMPV6_TYPE_ECHO_REQUEST 128u
#define ICMPV6_TYPE_ECHO_REPLY   129u
/* MLD(Multicast Listener Discovery、RFC 2710 = v1 / RFC 3810 = v2)。
 * 値は Linux の `linux/icmpv6.h` の ICMPV6_MGM_* / ICMPV6_MLD2_REPORT。 */
#define ICMPV6_TYPE_MLD_QUERY   130u  /* Query(v1/v2 共通。長さで区別する) */
#define ICMPV6_TYPE_MLD_REPORT  131u  /* MLDv1 Report */
#define ICMPV6_TYPE_MLD_DONE    132u  /* MLDv1 Done(離脱) */
#define ICMPV6_TYPE_MLD2_REPORT 143u  /* MLDv2 Report */
#define ICMPV6_TYPE_RS           133u  /* Router Solicitation */
#define ICMPV6_TYPE_RA           134u  /* Router Advertisement */
#define ICMPV6_TYPE_NS           135u  /* Neighbor Solicitation */
#define ICMPV6_TYPE_NA           136u  /* Neighbor Advertisement */

/* NDP オプション種別(RFC 4861 4.6。glibc の <netinet/icmp6.h> の
 * ND_OPT_* と同じ値)。 */
#define NDP_OPT_SRC_LLADDR   1u
#define NDP_OPT_TGT_LLADDR   2u
#define NDP_OPT_PREFIX_INFO  3u
#define NDP_OPT_MTU          5u

/* Router Advertisement のバイト配置(glibc の struct nd_router_advert で確認)。
 * ICMPv6 ヘッダ 8 バイトのうち 4-7 が type 固有領域で、RA では
 * cur hop limit(4)/ フラグ(5)/ ルータ寿命(6-7)。その後ろに
 * reachable time(8-11)と retrans timer(12-15)が続き、**オプションは 16 から**。 */
#define RA_OFF_CUR_HOP_LIMIT  4u
#define RA_OFF_FLAGS          5u
#define RA_OFF_ROUTER_LIFETIME 6u
#define RA_OFF_REACHABLE      8u
#define RA_OFF_RETRANS       12u
#define RA_OPT_OFF           16u
#define RA_FLAG_MANAGED    0x80u  /* M: アドレスも DHCPv6 で取れ */
#define RA_FLAG_OTHER      0x40u  /* O: その他の情報を DHCPv6 で取れ */

/* Prefix Information オプション(RFC 4861 4.6.2、32 バイト固定)。 */
#define PIO_LEN            32u
#define PIO_OFF_PREFIX_LEN  2u
#define PIO_OFF_FLAGS       3u
#define PIO_OFF_VALID       4u
#define PIO_OFF_PREFERRED   8u
#define PIO_OFF_PREFIX     16u
#define PIO_FLAG_ONLINK  0x80u  /* L */
#define PIO_FLAG_AUTO    0x40u  /* A: これで自動設定してよい */

typedef struct __attribute__((packed)) {
    uint8_t  ver_tc_fl[4];   /* [31:28]version(6) [27:20]traffic class [19:0]flow label */
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[IPV6_ADDR_LEN];
    uint8_t  dst[IPV6_ADDR_LEN];
} ipv6_header_t;

void ipv6_init(void);

void ipv6_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac);

/* このインターフェースのリンクローカルアドレス(fe80::/64 + EUI-64)を得る。 */
void ipv6_link_local_addr(uint8_t out[IPV6_ADDR_LEN]);

/* addr がこのノード宛か(リンクローカル / 要請ノードマルチキャスト / 全ノード)。 */
int ipv6_addr_is_ours(const uint8_t addr[IPV6_ADDR_LEN]);

/* addr に対応する要請ノードマルチキャスト ff02::1:ffXX:XXXX を組む。 */
void ipv6_solicited_node_addr(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out[IPV6_ADDR_LEN]);
int ipv6_global_addr(uint8_t out[IPV6_ADDR_LEN]);
void ipv6_source_for(const uint8_t dst[IPV6_ADDR_LEN], uint8_t out[IPV6_ADDR_LEN]);

int ipv6_send(const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
              uint8_t next_header, const uint8_t *payload, uint16_t payload_len);

/* 送信元アドレスを指定する版。DAD の NS だけは送信元が未指定アドレス(::)で
 * なければならないので要る。通常の送信は ipv6_send() を使う。 */
int ipv6_send_from(const uint8_t src[IPV6_ADDR_LEN],
                   const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
                   uint8_t next_header, const uint8_t *payload, uint16_t payload_len);

/* 重複アドレス検出(RFC 4862)。target を使い始める前に呼ぶ。
 * 0=空き、1=既に使われている(out_mac に相手の MAC)、-1=送信失敗。
 * 「応答が返ってこないこと」で判定するので probes*interval_ms かかる。 */
int ipv6_dad(const uint8_t target[IPV6_ADDR_LEN], unsigned probes, uint32_t interval_ms,
             uint8_t out_mac[6]);

/* Ethernet + IPv6 ヘッダを buf の先頭に組み立てる(ip_build_header の IPv6 版)。
 * 呼び出し元はペイロードを buf + ETH_HDR_LEN + IPV6_HDR_LEN から書き込む。 */
void ipv6_build_header(uint8_t *buf, const uint8_t src[IPV6_ADDR_LEN],
                        const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
                        uint8_t next_header, uint16_t payload_len);

/* IPv6 の疑似ヘッダを含むチェックサム。data/len は上位プロトコルのメッセージ全体。
 * チェックサム欄は 0 にしてから渡すこと。 */
uint16_t ipv6_pseudo_checksum(const uint8_t src[IPV6_ADDR_LEN],
                               const uint8_t dst[IPV6_ADDR_LEN],
                               uint8_t next_hdr,
                               const volatile uint8_t *data, uint16_t len);

/* 疑似ヘッダだけのチェックサム(HW チェックサムオフロード用の種)。 */
uint16_t ipv6_pseudo_checksum_only(const uint8_t src[IPV6_ADDR_LEN],
                                    const uint8_t dst[IPV6_ADDR_LEN],
                                    uint8_t next_hdr, uint16_t len);

/* 上位プロトコルのヘッダとデータが分かれている場合のチェックサム。 */
uint16_t ipv6_pseudo_checksum2(const uint8_t src[IPV6_ADDR_LEN],
                                const uint8_t dst[IPV6_ADDR_LEN], uint8_t next_hdr,
                                const volatile uint8_t *hdr, uint16_t hdr_len,
                                const void *data, uint16_t data_len);

/* 近隣キャッシュ(NDP)。ARP と役割は同じ。 */
void ndp_cache_insert(const uint8_t addr[IPV6_ADDR_LEN], const uint8_t mac[6]);
int  ndp_cache_lookup(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out_mac[6]);
int  ndp_resolve(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out_mac[6]);

/* 上位層の到達確認(RFC 4861 7.3.1)を受け取れる版。confirmed=1 なら確認要求を
 * 出さずに延命する。TCP の送信経路だけが使う。 */
int  ndp_cache_lookup_nud(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out_mac[6],
                          int confirmed);

/* 到達確認(NUD)用のユニキャスト NS(RFC 4861 7.2.4)。MAC を知っている相手に
 * 「まだそこに居るか」を聞くので、要請ノードマルチキャストへ投げない。 */
int  ndp_send_ns_unicast(const uint8_t target[IPV6_ADDR_LEN], const uint8_t mac[6]);

/* Neighbor Advertisement 1 通ぶんのキャッシュ更新(RFC 4861 7.2.5)。
 * solicited=1 のときだけ到達確認として延命し、override=0 なら既存の MAC を
 * 書き換えない(偽の NA でキャッシュを乗っ取られないため)。 */
void ndp_cache_update_na(const uint8_t addr[IPV6_ADDR_LEN], const uint8_t mac[6],
                          int solicited, int override_flag);

/* キャッシュを引かずに寿命だけを見る(`arptest` の観測用)。
 * 0=fresh、1=stale(猶予中)、-1=未登録。 */
int  ndp_cache_peek(const uint8_t addr[IPV6_ADDR_LEN], uint32_t *remain_ms);

/* 受信した IPv6 断片を捨てる直前に呼ばれるフック(`ext6test` の観測用)。
 * **受信側の再構成は実装していない**(IPv4 と同じ方針)ので、送信側の
 * 断片化はこれでしか確かめられない。ip_set_frag_observer() と同じ考え方。 */
typedef void (*ipv6_frag_observer_t)(uint32_t id, uint16_t frag_off, int more,
                                      uint8_t next_header,
                                      const uint8_t *payload, uint16_t len);
void ipv6_set_frag_observer(ipv6_frag_observer_t fn);

/* 全ノードマルチキャスト(ff02::1)へ ICMPv6 Echo Request を 1 個送る。
 * 直結リンクなので相手の MAC 解決なしに疎通確認できる。 */
int ipv6_send_echo_request(uint16_t ident, uint16_t seq, uint16_t payload_len);

/* ---- ステートレスアドレス自動設定(SLAAC、RFC 4861/4862)---- */

/* Router Solicitation を全ルータマルチキャスト(ff02::2)へ 1 個送る。 */
int ipv6_send_rs(void);

/* ni へ RS を送り、RA が来てグローバルアドレスが決まるまで待つ。
 * 決まったら **その場で DAD を実行**してから使用可能にする(RA 受信ハンドラ
 * からは DAD を走らせられない -- 受信ポーリングの再入になるため)。
 * 戻り値: 1=グローバルアドレスを設定した、0=RA が来なかった/採用しなかった、
 *         -1=RS の送信に失敗。 */
int ipv6_slaac_solicit(netif_t *ni, unsigned solicits, uint32_t interval_ms);

/* RA から得た寿命(グローバルアドレスとデフォルトルータ)の満了を判定し、
 * 切れていれば解除する。**冷たい経路からのみ呼ぶこと。** */
void ipv6_slaac_age(netif_t *ni);

/* 起動時に送る RS の回数と間隔。**RFC 4861 は 3 回 x 4 秒**だが、そのままだと
 * ルータの居ないこのリンクでは起動が 12 秒延びるだけなので短くしてある
 * (ARP Probe / DAD と同じ扱い。実 LAN へ出すときは RFC 値へ戻すこと)。
 * 非要請 RA はいつ届いても処理するので、RS はあくまで初回を早める手段。 */
#define SLAAC_RS_NUM          1u
#define SLAAC_RS_INTERVAL_MS  150u

/* ---- MLD(Multicast Listener Discovery、RFC 2710 / 3810)---- */

/* MLDv2 の Multicast Address Record 種別(Linux の `linux/icmpv6.h`)。 */
#define MLD2_MODE_IS_EXCLUDE   2u  /* Query への応答 */
#define MLD2_CHANGE_TO_INCLUDE 3u  /* 離脱 */
#define MLD2_CHANGE_TO_EXCLUDE 4u  /* 参加 */

/* 報告対象のマルチキャストグループを列挙する(要請ノードマルチキャスト)。
 * **ff02::1(全ノード)は含めない** -- RFC 3810 6 が報告対象外としている。
 * 戻り値は書き込んだ個数。 */
#define IPV6_MCAST_MAX 4u
unsigned ipv6_mcast_groups(netif_t *ni, uint8_t out[][IPV6_ADDR_LEN], unsigned max);

/* いま参加している全グループを報告する(非要請 Report)。
 * 戻り値: 送った Report の数、-1=失敗。 */
int ipv6_mld_report_all(netif_t *ni);

/* 1 グループの離脱を通知する(v1=Done、v2=CHANGE_TO_INCLUDE)。 */
int ipv6_mld_leave(const uint8_t group[IPV6_ADDR_LEN]);

/* いま MLDv1 互換モードか(v1 の Query を受けると一定時間そうなる)。 */
int ipv6_mld_v1_mode(void);

/* v1 互換モードを即座に解除する(`mldtest` の後始末用。通常は時間で切れる)。 */
void ipv6_mld_clear_v1_mode(void);

/* MLD の送信を止める/再開する。**スヌーピングするスイッチ配下では止めると
 * 通信が死ぬ**(それを見せるための陰性対照。`txdrop` と同じ扱いで、
 * 戻し忘れに注意)。 */
void ipv6_mld_set_enabled(int on);
int  ipv6_mld_enabled(void);

/* 送信する MLD メッセージを覗くフック(`mldtest` の観測用)。
 * ip_set_frag_observer() と同じ考え方 -- 相手が居ないと自分の送信を
 * 確かめられないので、送る直前にテスト側へ渡す。 */
typedef void (*ipv6_mld_observer_t)(const uint8_t *msg, unsigned len,
                                     const uint8_t dst[IPV6_ADDR_LEN]);
void ipv6_set_mld_observer(ipv6_mld_observer_t fn);

/* 非要請 Report を何回送るか(RFC 3810 の Robustness Variable)。 */
#define MLD_UNSOLICITED_REPORTS 2u

/* v1 の Query を受けてから v1 互換モードを保つ時間(RFC 3810 9.12 の
 * Older Version Querier Present Timeout = RV * QI + QRI = 2*125+10)。 */
#define MLD_V1_COMPAT_MS 260000u

extern volatile uint32_t g_ipv6_mld_query_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_mld_report_tx[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_ra_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_echo_request_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_echo_reply_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_ns_count[SMP_MAX_CORES];

#endif /* IPV6_H */
