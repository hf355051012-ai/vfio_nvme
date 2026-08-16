#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

uint64_t timer_now(void);
uint64_t timer_freq(void);

uint64_t ticks_to_ns(uint64_t ticks);
uint64_t ticks_to_us(uint64_t ticks);
uint64_t ticks_to_ms(uint64_t ticks);
uint64_t ticks_to_sec(uint64_t ticks);

uint64_t get_ns_from(uint64_t ticks);
uint64_t get_us_from(uint64_t ticks);
uint64_t get_ms_from(uint64_t ticks);
uint64_t get_sec_from(uint64_t ticks);

int timeout_us(uint64_t start, uint64_t threshold_us);
int timeout_ms(uint64_t start, uint32_t threshold_ms);
int timeout_sec(uint64_t start, uint32_t threshold_sec);

// msミリ秒だけビジーウェイトする。
static inline void timer_delay_ms(uint32_t ms) {
    uint64_t start = timer_now();
    while (!timeout_ms(start, ms)) {
    }
}

// usマイクロ秒だけビジーウェイトする(timer_delay_ms()のus版)。
static inline void timer_delay_us(uint32_t us) {
    uint64_t start = timer_now();
    while (!timeout_us(start, us)) {
    }
}

#endif
