#include "timer.h"

uint64_t ticks_to_ns(uint64_t ticks)
{
    uint64_t freq = timer_freq();
    if (freq == 0) return 0;
    uint64_t sec = ticks / freq;
    uint64_t rem = ticks % freq;
    return sec * 1000000000ull + (rem * 1000000000ull) / freq;
}

uint64_t ticks_to_us(uint64_t ticks)
{
    uint64_t freq = timer_freq();
    if (freq == 0) return 0;
    uint64_t sec = ticks / freq;
    uint64_t rem = ticks % freq;
    return sec * 1000000ull + (rem * 1000000ull) / freq;
}

uint64_t ticks_to_ms(uint64_t ticks)
{
    uint64_t freq = timer_freq();
    if (freq == 0) return 0;
    uint64_t sec = ticks / freq;
    uint64_t rem = ticks % freq;
    return sec * 1000ull + (rem * 1000ull) / freq;
}

uint64_t ticks_to_sec(uint64_t ticks)
{
    uint64_t freq = timer_freq();
    if (freq == 0) return 0;
    return ticks / freq;
}

uint64_t get_ns_from(uint64_t ticks)
{
    return ticks_to_ns(timer_now() - ticks);
}

uint64_t get_us_from(uint64_t ticks)
{
    return ticks_to_us(timer_now() - ticks);
}

uint64_t get_ms_from(uint64_t ticks)
{
    return ticks_to_ms(timer_now() - ticks);
}

uint64_t get_sec_from(uint64_t ticks)
{
    return ticks_to_sec(timer_now() - ticks);
}

int timeout_us(uint64_t start, uint64_t threshold_us)
{
    return get_us_from(start) >= threshold_us;
}

int timeout_ms(uint64_t start, uint32_t threshold_ms)
{
    return get_ms_from(start) >= (uint64_t)threshold_ms;
}

int timeout_sec(uint64_t start, uint32_t threshold_sec)
{
    return get_sec_from(start) >= (uint64_t)threshold_sec;
}
