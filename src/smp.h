#ifndef SMP_H
#define SMP_H

#include <stdint.h>

void secondary_main(void);

extern volatile uint64_t g_core1_heartbeat;

extern volatile int g_core1_alive;

int smp_boot_core1(void);

/* core2/core3用。g_core1_*と同じ規約(単一ライタ=そのコア、複数リーダ)。 */
extern volatile uint64_t g_core2_heartbeat;
extern volatile int      g_core2_alive;

extern volatile uint64_t g_core3_heartbeat;
extern volatile int      g_core3_alive;

/* core2/core3 は現時点で呼び出し元が無い。複数コネクションの受信を複数コアへ
 * 振り分ける scale-out で使う部品として意図的に残してある(bench/tcpbench は
 * core0+core1 の2コアで動くため配線していない)。未使用に見えても削除しないこと
 * -- 詳細は hal_smp.c の smp_boot_core2() のコメント参照。 */
int smp_boot_core2(void);
int smp_boot_core3(void);

/* 任意のコア(1..SMP_MAX_CORES-1)のワーカを起こす。smp_boot_core1/2/3 はこれの
 * 薄いラッパ。0=起動済み/成功、-1=失敗(範囲外を含む)。 */
int smp_boot_core(unsigned core);
/* core1..coreN をまとめて起こす(N=0/1 なら core1 だけ)。0=全部成功。 */
int smp_boot_cores_upto(unsigned n);

#if defined(__x86_64__)
/* **core0(シェル)+ RSS で受信を配る core1..core8 の 9 本。**
 * `netmt` / `rdmacores` が最大 8 コアまで散らせる。**1 コア増やすと .bss が
 * 約 135MB 増える**(大半は tcp.c の s_priv[コア][TCP_MAX_CONNS])。.bss は
 * 起動時に VFIO が丸ごとピン留めするので、その分だけ常駐する。 */
#define SMP_MAX_CORES 9u
#else
#define SMP_MAX_CORES 2u
#endif

unsigned smp_core_index(void);

extern volatile uint32_t g_sim_delay_us[SMP_MAX_CORES];

void sim_delay_tick(void);

typedef volatile uint32_t smp_spinlock_t;

static inline void smp_spin_lock(smp_spinlock_t *lock)
{
    while (__atomic_exchange_n(lock, 1u, __ATOMIC_ACQUIRE)) {
        __builtin_ia32_pause();
    }
}

static inline void smp_spin_unlock(smp_spinlock_t *lock)
{
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

#endif /* SMP_H */
