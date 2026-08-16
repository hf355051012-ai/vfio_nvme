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

#if defined(__x86_64__)
#define SMP_MAX_CORES 4u
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
