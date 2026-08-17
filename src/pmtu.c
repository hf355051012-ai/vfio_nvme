#include <stddef.h>
#include "pmtu.h"
#include "tcp.h"
#include "timer.h"
#include "uart.h"
#include "smp.h"

/* 宛先 -> PMTU の表。ARP/NDP キャッシュと違い per-core に分けない -- PMTU は
 * インターフェースではなく経路の性質なので、どのコアで ICMP を受けても同じ表を
 * 更新するのが正しい。書き込みは ICMP 受信時だけの冷たい経路なので、
 * per-core 化して整合を気にするより spinlock 1 個で済ませる。 */
typedef struct {
    netaddr_t dst;
    uint16_t  mtu;
    int       valid;
    uint64_t  expires_at;
} pmtu_entry_t;

static pmtu_entry_t   s_cache[PMTU_CACHE_SIZE];
static smp_spinlock_t s_lock;

/*=================================================================
 * 宛先の family に応じた PMTU の下限を返す。
 *
 * 引数:
 *   dst - 宛先アドレス(family だけ見る)
 * 戻り値:
 *   採用してよい最小の MTU
 * コール元:
 *   pmtu_learn()
 * ===============================================================*/
static uint16_t pmtu_floor(const netaddr_t *dst)
{
    return (dst->family == NETADDR_V6) ? (uint16_t)PMTU_MIN_V6 : (uint16_t)PMTU_MIN_V4;
}

/*=================================================================
 * ICMP Fragmentation Needed / ICMPv6 Packet Too Big で報告された MTU を
 * 記憶する。**PMTU は下げる方向にしか動かさない**(RFC 1191 6.3)。上げ直しは
 * TTL の満了に任せる -- そうしないと、偽の大きい値を送り込まれるだけで
 * 学習を無効化できてしまう。
 *
 * 採用したときは確立済み TCP コネクションの snd_mss も切り下げる。
 * 「学習したが適用を忘れる」を構造的に防ぐため、ここから呼んでいる。
 *
 * 引数:
 *   dst          - PMTU を学習する宛先(引用された元パケットの宛先)
 *   reported_mtu - ICMP が報告してきた MTU
 * 戻り値:
 *   1=採用した、0=採用しなかった
 * コール元:
 *   icmp_handle(), ipv6_handle_icmpv6()
 * ===============================================================*/
int pmtu_learn(const netaddr_t *dst, uint32_t reported_mtu)
{
    uint16_t floor = pmtu_floor(dst);

    if (reported_mtu < floor || reported_mtu > 0xFFFFu) {
        uart_printf("[PMTU] 報告 MTU=%u は下限 %u を下回る(または大きすぎる)ので採用しない\n",
                    (unsigned)reported_mtu, floor);
        return 0;
    }
    uint16_t mtu = (uint16_t)reported_mtu;
    uint64_t now = timer_now();
    uint64_t expiry = now + (uint64_t)PMTU_TTL_MS * 1000000ull;

    smp_spin_lock(&s_lock);

    int free_slot = -1;
    for (unsigned i = 0; i < PMTU_CACHE_SIZE; i++) {
        if (!s_cache[i].valid) {
            if (free_slot < 0) free_slot = (int)i;
            continue;
        }
        if ((int64_t)(now - s_cache[i].expires_at) >= 0) {
            s_cache[i].valid = 0;               /* 寿命切れは掃除しておく */
            if (free_slot < 0) free_slot = (int)i;
            continue;
        }
        if (!netaddr_eq(&s_cache[i].dst, dst)) continue;

        if (mtu >= s_cache[i].mtu) {
            /* 既に学習済みの値以上の報告。下げる方向にしか動かさない。 */
            smp_spin_unlock(&s_lock);
            uart_printf("[PMTU] 報告 MTU=%u は学習済みの %u 以上なので無視\n",
                        mtu, s_cache[i].mtu);
            return 0;
        }
        s_cache[i].mtu        = mtu;
        s_cache[i].expires_at = expiry;
        smp_spin_unlock(&s_lock);
        uart_printf("[PMTU] 更新: MTU=%u\n", mtu);
        tcp_pmtu_update(dst, mtu);
        return 1;
    }

    unsigned slot = (free_slot >= 0) ? (unsigned)free_slot : 0u;  /* 空きが無ければ先頭を潰す */
    s_cache[slot].dst        = *dst;
    s_cache[slot].mtu        = mtu;
    s_cache[slot].valid      = 1;
    s_cache[slot].expires_at = expiry;
    smp_spin_unlock(&s_lock);

    uart_printf("[PMTU] 学習: MTU=%u (family=%s)\n",
                mtu, (dst->family == NETADDR_V6) ? "IPv6" : "IPv4");
    tcp_pmtu_update(dst, mtu);
    return 1;
}

/*=================================================================
 * 宛先の学習済み PMTU を引く。寿命切れは 0 を返す(掃除は learn 側に任せ、
 * ここでは書き換えない -- 送信経路から呼ばれるので短く済ませる)。
 *
 * 引数:
 *   dst - 宛先アドレス
 * 戻り値:
 *   学習済みの MTU。未学習/寿命切れなら 0
 * コール元:
 *   tcp_mss_cap_for(), ip_send()
 * ===============================================================*/
uint16_t pmtu_lookup(const netaddr_t *dst)
{
    uint64_t now = timer_now();
    uint16_t found = 0;

    smp_spin_lock(&s_lock);
    for (unsigned i = 0; i < PMTU_CACHE_SIZE; i++) {
        if (!s_cache[i].valid) continue;
        if ((int64_t)(now - s_cache[i].expires_at) >= 0) continue;
        if (!netaddr_eq(&s_cache[i].dst, dst)) continue;
        found = s_cache[i].mtu;
        break;
    }
    smp_spin_unlock(&s_lock);
    return found;
}

/*=================================================================
 * 全エントリを破棄する。**コネクションの snd_mss は戻らない**(TCP は
 * セグメント境界を自由に変えてよいので下げるのは安全だが、上げ直すには
 * 相手の広告 MSS を覚え直す必要があり、そこまではやらない)。
 *
 * コール元:
 *   shell_pmtutest()
 * ===============================================================*/
void pmtu_clear(void)
{
    smp_spin_lock(&s_lock);
    for (unsigned i = 0; i < PMTU_CACHE_SIZE; i++) s_cache[i].valid = 0;
    smp_spin_unlock(&s_lock);
}

/*=================================================================
 * 学習済みエントリを一覧表示する。
 *
 * コール元:
 *   shell_pmtutest()
 * ===============================================================*/
void pmtu_dump(void)
{
    uint64_t now = timer_now();
    unsigned shown = 0;

    smp_spin_lock(&s_lock);
    for (unsigned i = 0; i < PMTU_CACHE_SIZE; i++) {
        if (!s_cache[i].valid) continue;
        int expired = ((int64_t)(now - s_cache[i].expires_at) >= 0);
        uint32_t remain_ms = expired ? 0u
                             : (uint32_t)((s_cache[i].expires_at - now) / 1000000ull);
        const netaddr_t *d = &s_cache[i].dst;
        if (d->family == NETADDR_V6) {
            uart_printf("  IPv6 ...%02x%02x:%02x%02x -> MTU=%u (残り %ums)\n",
                        d->a[12], d->a[13], d->a[14], d->a[15], s_cache[i].mtu, remain_ms);
        } else {
            uart_printf("  %u.%u.%u.%u -> MTU=%u (残り %ums)\n",
                        d->a[0], d->a[1], d->a[2], d->a[3], s_cache[i].mtu, remain_ms);
        }
        shown++;
    }
    smp_spin_unlock(&s_lock);
    if (shown == 0) uart_printf("  (学習済みエントリなし)\n");
}
