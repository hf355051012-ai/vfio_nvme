// platform/x86-linux/hal_timer.c
//
// 単調タイマ(timer.h 契約)の x86-linux 実装(x86-vfio-port Phase 3、
// ~/.claude/plans/x86-vfio-port.md §3 参照)。RPi5 は ARM generic timer
// (CNTPCT/CNTFRQ、timer.h の static inline)。x86 では
// clock_gettime(CLOCK_MONOTONIC) を「1ns=1tick」の仮想カウンタとして使い、
// timer_freq() は 1e9(Hz)を返す -- これにより ticks_to_*/get_*_from/timeout_*
// (timer.c、arch 非依存の変換ロジック)がそのまま流用できる。

#include "timer.h"

#include <time.h>
#include <stdint.h>

/* 現在の単調カウンタ値(ns 単位)。CLOCK_MONOTONIC はシステム起動からの
 * 単調増加時刻でウォールクロック補正の影響を受けない -- RPi5 の CNTPCT
 * (電源投入からの単調カウント)と同じ性質。 */
uint64_t timer_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* カウンタ周波数(Hz)。ns カウンタなので 1e9。 */
uint64_t timer_freq(void)
{
    return 1000000000ull;
}
