#include "timer.h"

#include <time.h>
#include <stdint.h>

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
