#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

// ================================================================
// HAL 契約: 単調タイマ(x86-vfio-port の platform 継ぎ目、
// ~/.claude/plans/x86-vfio-port.md §3 参照)。core 全体のタイムアウト/経過
// 計測が timer_now()/get_*_from()/timeout_*() に依存する。下記の timer_now/
// timer_freq は RPi5 実装(ARM generic timer CNTPCT/CNTFRQ)。x86-linux では
// clock_gettime(CLOCK_MONOTONIC)、VxWorks では tickGet/sysTimestamp に差し
// 替わる(ticks_to_*/get_*_from/timeout_* の変換ヘルパは timer.c 実装で core 共有)。
// ================================================================

// x86-linux: clock_gettime(CLOCK_MONOTONIC) 実装(platform/x86-linux/
// hal_timer.c)。timer_now() は ns 値、timer_freq() は 1e9(Hz)を返すので、
// 下記の ticks_to_*/get_*_from/timeout_*(timer.c、arch 非依存)がそのまま
// 使える。VxWorks では tickGet/sysTimestamp に差し替わる。
uint64_t timer_now(void);
uint64_t timer_freq(void);

/* ================================================================
 * ticks<->時間単位の変換ヘルパ(timer.c実装)。
 *
 * このプロジェクトはタイムアウト計測・経過時間チェックのほぼ全箇所で
 * 「start = timer_now()を採取 → 後で(timer_now() - start) * 単位 /
 * timer_freq()を計算」という定型コードを個別に書いていた(オーバーフロー
 * 対策の有無もファイルごとにまちまちだった)。これを一箇所(timer.c)に
 * 集約する -- stateprof.cが最初に導入した「秒部と端数部に分けてから
 * 乗算する」オーバーフロー安全な変換ロジック(ticks*1e9のような単純な
 * 掛け算は稼働時間が伸びるとuint64_tを超えうる)を汎用化したもの。
 *
 * ticks_to_*(): 単なる期間(2つのtimer_now()の差、または任意のtick数)を
 * ns/us/ms/secへ変換する。
 * get_*_from(ticks): 「以前にtimer_now()で採取したticks」から現在までの
 * 経過時間をns/us/ms/secで返す(内部でtimer_now() - ticksを計算してから
 * ticks_to_*()へ渡すだけ)。タイムアウト計測の定型コードはこれで置き換わる:
 *
 *   旧: uint64_t start = timer_now();
 *       uint64_t timeout_ticks = (timer_freq() / 1000) * TIMEOUT_MS;
 *       while (timer_now() - start < timeout_ticks) { ... }
 *
 *   新: uint64_t start = timer_now();
 *       while (get_ms_from(start) < TIMEOUT_MS) { ... }
 * ================================================================ */
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
