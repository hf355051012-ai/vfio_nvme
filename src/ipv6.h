#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
#include <stddef.h>
#include "netif.h"
#include "smp.h"

#define IPV6_ADDR_LEN 16u
#define IPV6_HDR_LEN  40u

/* Next Header(IPv4 の protocol 相当) */
#define IPV6_NH_TCP     6u
#define IPV6_NH_UDP     17u
#define IPV6_NH_ICMPV6  58u

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
#define ICMPV6_TYPE_NS           135u  /* Neighbor Solicitation */
#define ICMPV6_TYPE_NA           136u  /* Neighbor Advertisement */

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

/* キャッシュを引かずに寿命だけを見る(`arptest` の観測用)。
 * 0=fresh、1=stale(猶予中)、-1=未登録。 */
int  ndp_cache_peek(const uint8_t addr[IPV6_ADDR_LEN], uint32_t *remain_ms);

/* 全ノードマルチキャスト(ff02::1)へ ICMPv6 Echo Request を 1 個送る。
 * 直結リンクなので相手の MAC 解決なしに疎通確認できる。 */
int ipv6_send_echo_request(uint16_t ident, uint16_t seq, uint16_t payload_len);

extern volatile uint32_t g_ipv6_echo_request_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_echo_reply_count[SMP_MAX_CORES];
extern volatile uint32_t g_ipv6_ns_count[SMP_MAX_CORES];

#endif /* IPV6_H */
