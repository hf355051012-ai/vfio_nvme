#include "timer.h"

#include <time.h>
#include <stdint.h>

uint64_t timer_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/*
 * タイマカウンタの周波数(Hz)を返す。timer_now() が ns 単位なので 1e9 固定。
 *
 * 戻り値:
 *   1000000000
 * コール元:
 *   ticks_to_ns/us/ms/sec(), timer_selftest()
 */
uint64_t timer_freq(void)
{
    return 1000000000ull;
}
