// stateprof.c
//
// 明示的ステートマシンの「各ステート滞在時間」プロファイラ(stateprof.h参照)。

#include "stateprof.h"
#include "timer.h"
#include "uart.h"

void state_prof_reset(state_prof_t *p)
{
    p->started       = 0;
    p->entry_ticks   = 0;
    p->current_state = -1;
    for (unsigned i = 0; i < STATEPROF_MAX_STATES; i++) {
        p->total_ticks[i]  = 0;
        p->max_ticks[i]    = 0;
        p->enter_count[i]  = 0;
        p->poll_count[i]   = 0;
    }
}

void state_prof_mark(state_prof_t *p, int state)
{
    if (state < 0 || (unsigned)state >= STATEPROF_MAX_STATES) {
        return;  // 呼び出し側のenumとSTATEPROF_MAX_STATESの食い違い等に対する安全弁
    }

    uint64_t now = timer_now();

    // 初回呼び出し(startedフラグ経由、ゼロ初期化された固定物理アドレス
    // 上の構造体(nvmet_ctx_t等)でも、明示的なstate_prof_reset()を経て
    // いても、常に正しく「今から計測開始」として扱う -- current_stateを
    // 目印にすると、ゼロ初期化直後にたまたま最初の遷移先がstate値0
    // (多くのステートマシンの初期値)だった場合、「前回から変化無し」と
    // 誤認識し、entry_ticks=0(起動時刻)からの経過を初回のステートの
    // 滞在時間として誤って積算してしまう(stateprof.hのstartedコメント
    // 参照)。
    if (!p->started) {
        p->started       = 1;
        p->current_state = state;
        p->entry_ticks   = now;
        p->enter_count[state]++;
        p->poll_count[state]++;
        return;
    }

    if (p->current_state != state) {
        uint64_t dt = now - p->entry_ticks;
        p->total_ticks[p->current_state] += dt;
        if (dt > p->max_ticks[p->current_state]) {
            p->max_ticks[p->current_state] = dt;
        }
        p->current_state = state;
        p->entry_ticks   = now;
        p->enter_count[state]++;
    }

    p->poll_count[state]++;
}

void state_prof_flush(state_prof_t *p)
{
    if (!p->started) {
        return;
    }
    uint64_t now = timer_now();
    uint64_t dt  = now - p->entry_ticks;
    p->total_ticks[p->current_state] += dt;
    if (dt > p->max_ticks[p->current_state]) {
        p->max_ticks[p->current_state] = dt;
    }
    p->entry_ticks = now;  // current_stateは変えない(以後も同じステートの継続として計測する)
}

// ticks(64bit)のus/msへの変換自体はtimer.h(timer.c)のticks_to_us()/
// ticks_to_ms()汎用ヘルパへ集約済み(以前はここに専用の実装があった)。
// uart_printfは64bit値の直接出力(%llu等)に対応していないため
// (CLAUDE.md記載の既知の制約)、本ファイル内で64bit10進出力だけは
// 自前で行う。

// uint64_tを10進数でそのまま出力する(uart_printfの%uは32bit引数前提の
// ため使えない、CLAUDE.md「NVMe/TCP制御のステートマシン化」節と同じ
// 割り切りをここでも踏襲)。
static void print_u64(uint64_t v)
{
    char buf[20];
    int  n = 0;
    if (v == 0) {
        uart_putc('0');
        return;
    }
    while (v > 0) {
        buf[n++] = (char)('0' + (unsigned)(v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        uart_putc(buf[--n]);
    }
}

// print_u64()を右詰め幅指定付きで出力する(表の列を揃えるため)。
static void print_u64_w(uint64_t v, int width)
{
    uint64_t t = v;
    int digits = 1;
    while (t >= 10u) { t /= 10u; digits++; }
    for (int i = digits; i < width; i++) uart_putc(' ');
    print_u64(v);
}

void state_prof_dump(const state_prof_t *p, const char *const *names, unsigned name_count,
                      const char *label)
{
    uint64_t freq = timer_freq();
    uint64_t now  = timer_now();

    uart_printf("[stateprof] %s (timer_freq=%uHz)\n", label, (unsigned)freq);
    uart_printf("  %-24s %10s %8s %10s %10s %8s\n",
                "state", "total_ms", "count", "avg_us", "max_us", "polls");

    int any = 0;
    for (unsigned i = 0; i < STATEPROF_MAX_STATES; i++) {
        if (p->enter_count[i] == 0 && p->poll_count[i] == 0) {
            continue;  // 一度も観測されていないステートは表示しない
        }
        any = 1;

        uint64_t total = p->total_ticks[i];
        if ((int)i == p->current_state) {
            // 現在も滞在中のステートは、ここまでの経過分を暫定的に
            // 加算して表示する(pの内容自体は変更しない、読み取り専用)。
            total += now - p->entry_ticks;
        }

        uint64_t total_ms = ticks_to_ms(total);
        uint64_t avg_us   = p->enter_count[i] ? (ticks_to_us(total) / p->enter_count[i]) : 0;
        uint64_t max_us   = ticks_to_us(p->max_ticks[i]);
        const char *name  = (i < name_count) ? names[i] : "?";

        uart_printf("  %-24s ", name);
        print_u64_w(total_ms, 10); uart_putc(' ');
        uart_printf("%8u ", p->enter_count[i]);
        print_u64_w(avg_us, 10); uart_putc(' ');
        print_u64_w(max_us, 10); uart_putc(' ');
        uart_printf("%8u\n", p->poll_count[i]);
    }
    if (!any) {
        uart_printf("  (記録なし -- state_prof_reset()後にこのステートマシンが一度も"
                    "動いていない可能性があります)\n");
    }
}
