#ifndef NETADDR_H
#define NETADDR_H

#include <stdint.h>

/* IPv4 と IPv6 のどちらでも同じ型で持ち回るためのアドレス。TCP/UDP のコネクション
 * 状態や 4-tuple 比較はこの型を使い、L3 ヘッダを組み立てる直前にだけ family を見て
 * 分岐する。IPv4 は a[0..3] のみ使い、a[4..15] は常に 0 にしておく(比較を memcmp
 * 相当で済ませるため)。バイト順はネットワークバイトオーダー(先頭が最上位)。 */

#define NETADDR_V4 4u
#define NETADDR_V6 6u

typedef struct {
    uint8_t family;
    uint8_t a[16];
} netaddr_t;

/*=================================================================
 * ホストバイトオーダーの IPv4 を netaddr_t にする。
 *
 * 引数:
 *   host - IPv4(ホストバイトオーダー)
 * 戻り値:
 *   family=V4 の netaddr_t
 * ===============================================================*/
static inline netaddr_t netaddr_v4(uint32_t host)
{
    netaddr_t n;
    n.family = NETADDR_V4;
    n.a[0] = (uint8_t)(host >> 24);
    n.a[1] = (uint8_t)(host >> 16);
    n.a[2] = (uint8_t)(host >> 8);
    n.a[3] = (uint8_t)host;
    /* a[4..15] は IPv4 では一切参照されない(netaddr_eq は family=V4 なら
     * 先頭 4 バイトしか比較しない)。受信パケットごとに 2 個作るので、
     * 使わない 12 バイトのゼロ埋めは省く。 */
    return n;
}

/*=================================================================
 * 16 バイトの IPv6 アドレスを netaddr_t にする。
 *
 * 引数:
 *   a16 - IPv6 アドレス(ネットワークバイトオーダー)
 * 戻り値:
 *   family=V6 の netaddr_t
 * ===============================================================*/
static inline netaddr_t netaddr_v6(const uint8_t a16[16])
{
    netaddr_t n;
    n.family = NETADDR_V6;
    for (unsigned i = 0; i < 16; i++) n.a[i] = a16[i];
    return n;
}

/*=================================================================
 * netaddr_t から IPv4 をホストバイトオーダーで取り出す(family=V4 前提)。
 *
 * 引数:
 *   n - 取り出す元
 * 戻り値:
 *   IPv4(ホストバイトオーダー)。V6 なら 0
 * ===============================================================*/
static inline uint32_t netaddr_v4_host(const netaddr_t *n)
{
    if (n->family != NETADDR_V4) return 0u;
    return ((uint32_t)n->a[0] << 24) | ((uint32_t)n->a[1] << 16) |
           ((uint32_t)n->a[2] << 8)  |  (uint32_t)n->a[3];
}

/*=================================================================
 * 2 つのアドレスが等しいか(family も含めて比較する)。
 *
 * 引数:
 *   x / y - 比較する 2 つ
 * 戻り値:
 *   1=等しい、0=異なる
 * ===============================================================*/
static inline int netaddr_eq(const netaddr_t *x, const netaddr_t *y)
{
    if (x->family != y->family) return 0;
    unsigned n = (x->family == NETADDR_V4) ? 4u : 16u;
    for (unsigned i = 0; i < n; i++) {
        if (x->a[i] != y->a[i]) return 0;
    }
    return 1;
}

/*=================================================================
 * アドレスが未設定(family が V4/V6 のどちらでもない)か。
 *
 * 引数:
 *   n - 判定するアドレス
 * 戻り値:
 *   1=未設定、0=設定済み
 * ===============================================================*/
static inline int netaddr_is_unset(const netaddr_t *n)
{
    return (n->family != NETADDR_V4 && n->family != NETADDR_V6);
}

#endif /* NETADDR_H */
