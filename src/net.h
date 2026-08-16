#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>
#include "netif.h"
#if defined(__x86_64__)
#include <string.h>   /* volatile_fast_copy() の x86 高速パス(glibc memcpy) */
#endif

static inline uint16_t htons(uint16_t x)
{
    return (uint16_t)((x << 8) | (x >> 8));
}
static inline uint16_t ntohs(uint16_t x) { return htons(x); }

static inline uint32_t htonl(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8)  |
           ((x & 0x00FF0000u) >> 8)  |
           ((x & 0xFF000000u) >> 24);
}
static inline uint32_t ntohl(uint32_t x) { return htonl(x); }

/* ------------------------------------------------------------------ */
/* 自機IPv4アドレス                                                    */
/* ------------------------------------------------------------------ */

#define NET_SELF_IP_A 192u
#define NET_SELF_IP_B 168u
#define NET_SELF_IP_C 100u
#define NET_SELF_IP_D 2u

#define NET_RP1_DEFAULT_IP  (((uint32_t)NET_SELF_IP_A << 24) | \
                             ((uint32_t)NET_SELF_IP_B << 16) | \
                             ((uint32_t)NET_SELF_IP_C << 8)  | \
                              (uint32_t)NET_SELF_IP_D)

#define NET_RP1_CORE1_IP    (NET_RP1_DEFAULT_IP + 2u)

/* 現在アクティブなインターフェース(netif.h)の自機IPv4。 */
#define NET_SELF_IP  (net_active_ip())

/* オクテット4個 -> ホストバイトオーダーの32bit値 */
static inline uint32_t ip_from_octets(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

/* ホストバイトオーダーの32bit値 -> オクテット4個 (octets[0]が最上位) */
static inline void ip_to_octets(uint32_t ip, uint8_t octets[4])
{
    octets[0] = (uint8_t)(ip >> 24);
    octets[1] = (uint8_t)(ip >> 16);
    octets[2] = (uint8_t)(ip >> 8);
    octets[3] = (uint8_t)ip;
}

/* ------------------------------------------------------------------ */
/* バイト単位ビッグエンディアン読み書きヘルパ                            */
/* ------------------------------------------------------------------ */

static inline uint16_t rd16be(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

static inline uint32_t rd32be(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
}

static inline void wr16be(volatile void *p, uint16_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}

static inline void wr32be(volatile void *p, uint32_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

/* ------------------------------------------------------------------ */
/* リトルエンディアン読み書きヘルパ (NVMe/NVMe-TCP用)                    */
/* ------------------------------------------------------------------ */

static inline uint16_t rd16le(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}

static inline uint32_t rd32le(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline uint64_t rd64le(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint64_t)b[0]       | ((uint64_t)b[1] << 8)  |
           ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
           ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
           ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static inline void wr16le(volatile void *p, uint16_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}

static inline void wr32le(volatile void *p, uint32_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

static inline void wr64le(volatile void *p, uint64_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    b[4] = (uint8_t)(v >> 32);
    b[5] = (uint8_t)(v >> 40);
    b[6] = (uint8_t)(v >> 48);
    b[7] = (uint8_t)(v >> 56);
}

/* ------------------------------------------------------------------ */
/* アライメント適応コピー(MMU無効環境でのバイト単位コピー高速化)         */
/* ------------------------------------------------------------------ */
static inline void volatile_fast_copy(volatile void *dst, const volatile void *src, size_t len)
{
#if defined(__x86_64__)
    memcpy((void *)(uintptr_t)dst, (const void *)(uintptr_t)src, len);
    return;
#else
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;
    size_t i = 0;

    if ((((uintptr_t)d | (uintptr_t)s) & 7u) == 0) {
        for (; i + 8 <= len; i += 8)
            *(volatile uint64_t *)(d + i) = *(const volatile uint64_t *)(s + i);
    } else if ((((uintptr_t)d | (uintptr_t)s) & 3u) == 0) {
        for (; i + 4 <= len; i += 4)
            *(volatile uint32_t *)(d + i) = *(const volatile uint32_t *)(s + i);
    } else if ((((uintptr_t)d | (uintptr_t)s) & 1u) == 0) {
        for (; i + 2 <= len; i += 2)
            *(volatile uint16_t *)(d + i) = *(const volatile uint16_t *)(s + i);
    }

    for (; i < len; i++)
        d[i] = s[i];
#endif /* __x86_64__ */
}

/* ------------------------------------------------------------------ */
/* インターネットチェックサム (RFC 1071)                                */
/* ------------------------------------------------------------------ */
static inline uint32_t checksum_accumulate(uint32_t sum, const volatile void *data, size_t len)
{
    const volatile uint8_t *p = (const volatile uint8_t *)data;
    size_t i = 0;

    if (((uintptr_t)p & 7u) == 0) {
        for (; i + 8 <= len; i += 8) {
            uint64_t be = __builtin_bswap64(*(const volatile uint64_t *)(p + i));
            sum += (uint32_t)((be >> 48) & 0xFFFFu);
            sum += (uint32_t)((be >> 32) & 0xFFFFu);
            sum += (uint32_t)((be >> 16) & 0xFFFFu);
            sum += (uint32_t)(be & 0xFFFFu);
        }
    } else if (((uintptr_t)p & 3u) == 0) {
        for (; i + 4 <= len; i += 4) {
            uint32_t be = __builtin_bswap32(*(const volatile uint32_t *)(p + i));
            sum += (be >> 16) & 0xFFFFu;
            sum += be & 0xFFFFu;
        }
    }

    for (; i + 1 < len; i += 2)
        sum += ((uint32_t)p[i] << 8) | (uint32_t)p[i + 1];
    if (i < len)
        sum += ((uint32_t)p[i] << 8);

    return sum;
}

/*=================================================================
 * IPv4 ヘッダチェックサム(RFC1071 の 1 の補数和)を計算する。検証時は
 * ヘッダ全体に対して呼び、結果が 0 なら正しい。
 *
 * 引数:
 *   data - 対象バイト列(IPv4 ヘッダ)
 *   len  - そのバイト数
 * 戻り値:
 *   チェックサム値(検証時は 0 であるべき)
 * コール元:
 *   ip_build_header(), ip_handle_frame(), icmp_handle()
 * ===============================================================*/
static inline uint16_t inet_checksum(const volatile void *data, size_t len)
{
    uint32_t sum = checksum_accumulate(0, data, len);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

/*=================================================================
 * TCP チェックサムを疑似ヘッダ + TCP ヘッダ + ペイロード全体から計算する
 * (受信セグメントの検証用)。
 *
 * 引数:
 *   src_ip / dst_ip - 送信元/宛先 IPv4(ホストバイトオーダー)
 *   protocol        - IP プロトコル番号
 *   payload         - TCP ヘッダ先頭
 *   payload_len     - TCP ヘッダ + ペイロードのバイト数
 * 戻り値:
 *   チェックサム値(検証時は 0 であるべき)
 * コール元:
 *   tcp_input()
 * ===============================================================*/
static inline uint16_t pseudo_header_checksum(const uint8_t src_ip[4],
                                               const uint8_t dst_ip[4],
                                               uint8_t protocol,
                                               const volatile void *l4_data,
                                               size_t l4_len)
{
    const volatile uint8_t *sip = src_ip;
    const volatile uint8_t *dip = dst_ip;

    uint32_t sum = 0;
    sum += ((uint32_t)sip[0] << 8) | (uint32_t)sip[1];
    sum += ((uint32_t)sip[2] << 8) | (uint32_t)sip[3];
    sum += ((uint32_t)dip[0] << 8) | (uint32_t)dip[1];
    sum += ((uint32_t)dip[2] << 8) | (uint32_t)dip[3];
    sum += (uint32_t)protocol;   /* 上位バイト0 + protocol の16bitワードとして加算 */
    sum += (uint32_t)l4_len;     /* L4長(16bit) */

    sum = checksum_accumulate(sum, l4_data, l4_len);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

/*=================================================================
 * 疑似ヘッダ 12 バイトだけのチェックサムを返す(O(1)、実データを読まない)。
 * HW チェックサムオフロード時は、この部分和をチェックサムフィールドへ
 * 書いておき、残りは NIC が計算して完成させる。
 *
 * 引数:
 *   src_ip / dst_ip / protocol / payload_len - 疑似ヘッダの各フィールド
 * 戻り値:
 *   疑似ヘッダ部分の部分和
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso()
 * ===============================================================*/
static inline uint16_t pseudo_header_checksum_only(const uint8_t src_ip[4],
                                                     const uint8_t dst_ip[4],
                                                     uint8_t protocol,
                                                     size_t l4_len)
{
    const volatile uint8_t *sip = src_ip;
    const volatile uint8_t *dip = dst_ip;

    uint32_t sum = 0;
    sum += ((uint32_t)sip[0] << 8) | (uint32_t)sip[1];
    sum += ((uint32_t)sip[2] << 8) | (uint32_t)sip[3];
    sum += ((uint32_t)dip[0] << 8) | (uint32_t)dip[1];
    sum += ((uint32_t)dip[2] << 8) | (uint32_t)dip[3];
    sum += (uint32_t)protocol;
    sum += (uint32_t)l4_len;

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

/*=================================================================
 * ヘッダとペイロードが別バッファに分かれている送信経路用の TCP チェック
 * サム計算(疑似ヘッダ + ヘッダ + ペイロードを 1 つの和にまとめる)。
 *
 * 引数:
 *   src_ip / dst_ip / protocol - 疑似ヘッダのフィールド
 *   hdr / hdr_len              - TCP ヘッダ
 *   payload / payload_len      - ペイロード(無ければ NULL/0)
 * 戻り値:
 *   チェックサム値
 * コール元:
 *   tcp_send_segment(), tcp_send_bare_ack()
 * ===============================================================*/
static inline uint16_t pseudo_header_checksum2(const uint8_t src_ip[4],
                                                const uint8_t dst_ip[4],
                                                uint8_t protocol,
                                                const volatile void *l4_data1, size_t l4_len1,
                                                const volatile void *l4_data2, size_t l4_len2)
{
    const volatile uint8_t *sip = src_ip;
    const volatile uint8_t *dip = dst_ip;

    uint32_t sum = 0;
    sum += ((uint32_t)sip[0] << 8) | (uint32_t)sip[1];
    sum += ((uint32_t)sip[2] << 8) | (uint32_t)sip[3];
    sum += ((uint32_t)dip[0] << 8) | (uint32_t)dip[1];
    sum += ((uint32_t)dip[2] << 8) | (uint32_t)dip[3];
    sum += (uint32_t)protocol;
    sum += (uint32_t)(l4_len1 + l4_len2);

    sum = checksum_accumulate(sum, l4_data1, l4_len1);
    sum = checksum_accumulate(sum, l4_data2, l4_len2);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

#endif /* NET_H */
