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
#define IPV6_TLV_ACT_PP       0x80u  /* 10: 破棄して Parameter Problem code 2(宛先がマルチキャストでも) */
#define IPV6_TLV_ACT_PP_UNI   0xC0u  /* 11: 破棄して、宛先がマルチキャストでなければ Parameter Problem code 2 */

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
#define ICMPV6_TYPE_DEST_UNREACH   1u
#define ICMPV6_TYPE_PACKET_TOO_BIG 2u
#define ICMPV6_TYPE_TIME_EXCEEDED  3u
#define ICMPV6_TYPE_PARAM_PROBLEM  4u
/* Destination Unreachable の code(RFC 4443 3.1) */
#define ICMPV6_CODE_NO_ROUTE       0u
#define ICMPV6_CODE_ADMIN_PROHIB   1u
#define ICMPV6_CODE_ADDR_UNREACH   3u
#define ICMPV6_CODE_PORT_UNREACH   4u
/* Parameter Problem の code(RFC 4443 3.4、RFC 7112) */
#define ICMPV6_CODE_PP_HEADER      0u  /* ヘッダの欄が不正 */
#define ICMPV6_CODE_PP_NEXTHDR     1u  /* 知らない Next Header */
#define ICMPV6_CODE_PP_OPTION      2u  /* 知らないオプション */
#define ICMPV6_CODE_PP_CHAIN       3u  /* 先頭の断片がヘッダの並びを全部含まない(RFC 7112) */
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
#define ICMPV6_TYPE_REDIRECT     137u  /* Redirect(RFC 4861 4.5) */

/* Redirect のバイト配置(RFC 4861 4.5): ICMPv6 ヘッダ 4 + reserved 4、Target(8-23)、
 * Destination(24-39)、オプションは 40 から。 */
#define REDIRECT_OFF_TARGET  8u
#define REDIRECT_OFF_DEST   24u
#define REDIRECT_OPT_OFF    40u
#define NDP_OPT_REDIRECTED   4u   /* Redirected Header オプション(読み飛ばす) */

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
/* 1 つ目のグローバルアドレス。**DAD 中(tentative)・有効期間切れのものは返さない**
 * (RFC 4862 5.4。SLAAC で作ったものだけ。手動設定は常に返す)。 */
int ipv6_global_addr(uint8_t out[IPV6_ADDR_LEN]);
/* 宛先に合わせた送信元(RFC 6724 の rule 2 / 3 / 8 の簡略版)。 */
void ipv6_source_for(const uint8_t dst[IPV6_ADDR_LEN], uint8_t out[IPV6_ADDR_LEN]);

/* NDP 以外の送信に使う hop limit(RFC 4861 6.3.4 の CurHopLimit。RA の Cur Hop Limit が
 * 0 でなければそれ、無ければ 64)。NDP(RS / RA / NS / NA / Redirect)だけは 255。 */
uint8_t ipv6_default_hop_limit(void);

/* SLAAC で作ったアドレスの DAD の待ち時間(RFC 4862 の DupAddrDetectTransmits=1 x
 * RetransTimer)。RFC の RetransTimer は 1 秒だが、ルータの居ないこのリンクでは起動と
 * 試験が延びるだけなので、手動設定の DAD(2 回 x 50ms)と同じ 100ms にしてある。 */
#define IPV6_SLAAC_DAD_MS 100u

/* 時間で進める仕事(DAD の判定、MLD の Report / 離脱の再送、寿命切れの掃除)を進める。
 * **冷たい経路から呼ぶこと**(仕事が無ければ volatile の旗を 1 つ読むだけで戻る)。
 * IPv6 のフレームを受けるたびにも呼ばれるが、受信が無いと進まないので、定期的に
 * 回る冷たい経路(ポーリングループの数百回に 1 回など)からも呼ぶのが望ましい。 */
void ipv6_timer_tick(void);

/* 送信する IPv6 パケット(ipv6_send_from() の経路)を覗くフック(`rfctest ipv6` の観測用)。
 * hop limit と上位の種類、上位のメッセージの先頭を渡す。 */
typedef void (*ipv6_tx_observer_t)(uint8_t hop_limit, uint8_t next_header,
                                    const uint8_t *payload, uint16_t len);
void ipv6_set_tx_observer(ipv6_tx_observer_t fn);

/* 受けた ICMPv6 のエラーの数と、最後のエラーの種類(`rfctest ipv6` の観測用)。 */
extern volatile uint32_t g_icmpv6_err_rx;
extern volatile uint8_t  g_icmpv6_err_rx_type;
extern volatile uint8_t  g_icmpv6_err_rx_code;
extern volatile uint32_t g_icmpv6_err_rx_param;
/* 送った ICMPv6 のエラーの数と、頻度の制限で送らなかった数。 */
extern volatile uint32_t g_icmpv6_err_tx;
extern volatile uint32_t g_icmpv6_err_ratelimited;
/* 受け付けた Redirect の数。 */
extern volatile uint32_t g_ipv6_redirect_count;
/* ICMPv6 のエラーの送る頻度の上限(RFC 4443 2.4(f)。トークンバケツの 1 秒あたりの
 * 補充数と、溜められる上限)。 */
#define ICMPV6_ERR_RATE_PER_SEC 10u
#define ICMPV6_ERR_BURST        10u

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
/* 相手が名乗った対応を stale で覚える(NS / RA の Source Link-Layer Address)。 */
void ndp_cache_learn(const uint8_t addr[IPV6_ADDR_LEN], const uint8_t mac[6]);
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
 * 0=fresh、1=stale、-1=未登録または確認要求がすべて無応答。 */
int  ndp_cache_peek(const uint8_t addr[IPV6_ADDR_LEN], uint32_t *remain_ms);

/* 受信した IPv6 断片を組み立てへ渡す直前に呼ばれるフック(`ext6test` / `rfctest ipv6` の
 * 観測用)。組み立てた結果からは「何個に割れて、識別子とオフセットがいくつか」が
 * 見えないので、断片単位の形はこれで確かめる。ip_set_frag_observer() と同じ考え方。 */
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
 * DAD は RA の処理が待たずに始めている(TENTATIVE)ので、その結果が出るまで待つ。
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
#define IPV6_MCAST_MAX 6u   /* リンクローカル + 1 つ目 + 2 つ目以降(NETIF_IP6_EXTRA)ぶん */
unsigned ipv6_mcast_groups(netif_t *ni, uint8_t out[][IPV6_ADDR_LEN], unsigned max);

/* いま参加している全グループを報告する(非要請 Report)。
 * 戻り値: 送った Report の数、-1=失敗。 */
int ipv6_mld_report_all(netif_t *ni);

/* 1 グループの離脱を通知する(v1=Done、v2=CHANGE_TO_INCLUDE)。 */
int ipv6_mld_leave(const uint8_t group[IPV6_ADDR_LEN]);

/* アクティブなインターフェースがいま MLDv1 互換モードか(v1 の Query を受けると
 * 一定時間そうなる)。**インターフェースごと**(RFC 3810 8.2.1。Querier はリンクごと)。 */
int ipv6_mld_v1_mode(void);

/* v1 互換モードを即座に解除する(全インターフェース。`mldtest` の後始末用。
 * 通常は時間で切れる)。 */
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

/* 非要請 Report / 離脱通知を合わせて何回送るか(RFC 3810 9.1 の Robustness Variable)。 */
#define MLD_ROBUSTNESS 2u
/* そのうち、その場ですぐに送る数。**残り(MLD_ROBUSTNESS - これ)は間隔を空けて
 * 再送する**(RFC 3810 6.1 / RFC 2710 4。続けて送ると同じ理由で両方落ちうる)。
 * ipv6_mld_report_all() / ipv6_mld_leave() はこの数だけ送って戻る。 */
#define MLD_UNSOLICITED_REPORTS 1u
/* 再送の間隔の上限(Unsolicited Report Interval)。v2 は 1 秒(RFC 3810 9.11)、
 * v1 互換モードは 10 秒(RFC 2710 7.10)。実際の間隔は (0, 上限] の乱数。 */
#define MLD_UNSOL_INTERVAL_MS    1000u
#define MLD_V1_UNSOL_INTERVAL_MS 10000u

/* v1 の Query を受けてから v1 互換モードを保つ時間(RFC 3810 9.12 の
 * Older Version Querier Present Timeout = RV * QI + QRI = 2*125+10)。 */
#define MLD_V1_COMPAT_MS 260000u

extern volatile uint32_t g_ipv6_mld_query_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_mld_report_tx[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_ra_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_echo_request_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_echo_reply_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_ns_count[SMP_MAX_CORES];

/* ---- ICMPv6 のエラーを送る(RFC 4443)----
 * invoking は誘因になったパケット(IPv6 ヘッダの先頭から)。最小 MTU(1280)に収まる
 * 長さまで引用する。RFC 4443 2.4(e) の「エラーにエラーを返さない」「マルチキャスト宛て /
 * マルチキャスト送信元には返さない(Packet Too Big と Parameter Problem code 2 を除く)」と、
 * 2.4(f) の送る頻度の制限(MUST)はこの関数の中で守る。アクティブなインターフェースから送る。
 * 戻り値: 0=送った、-1=送らなかった(制限・条件・失敗)。 */
int icmpv6_send_error(uint8_t type, uint8_t code, uint32_t param,
                      const uint8_t *invoking, size_t len,
                      const uint8_t dst[IPV6_ADDR_LEN], const uint8_t *dst_mac);

#endif /* IPV6_H */
