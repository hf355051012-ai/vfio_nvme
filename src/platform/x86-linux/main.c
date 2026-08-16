#include "uart.h"
#include "timer.h"
#include "smp.h"
#include "crc32c.h"
#include "vfio.h"
#include "mlx5.h"
#include "nvme_rdma.h"
#include "net.h"
#include "arp.h"
#include "ip.h"
#include "netif.h"
#include "job.h"
#include "nvme.h"
#include "nvmet.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>   /* read/usleep(常駐シェルの非ブロッキング入力・アイドル待ち) */
#include <fcntl.h>
#include <stdlib.h>   /* atoi/strtoul/exit */
#include <termios.h>  /* raw モード(履歴/矢印キーのため canonical/echo を無効化) */
#include <stdio.h>    /* setvbuf(raw モードで1文字ずつ即時エコーするため無バッファ化) */
#include "timestamp.h" /* ts コマンド(ts_log ダンプ) */
#include "tcp.h"       /* ackthresh コマンド(g_tcp_ack_threshold) */

/*
 * CRC32C の既知テストベクタ CRC32C("123456789")=0xE3069283 を確認する。
 * crc32c() は生の実行中 CRC を返す規約なので、ここで ~ を取る。
 *
 * 戻り値:
 *   0=一致、-1=不一致
 * コール元:
 *   main()
 */
static int crc32c_selftest(void)
{
    const char *v = "123456789";
    uint32_t raw = crc32c(0xFFFFFFFFu, v, 9);
    uint32_t digest = ~raw;
    uart_printf("[selftest] crc32c(\"123456789\") = 0x%08X (期待 0xE3069283) -> %s\n",
                digest, (digest == 0xE3069283u) ? "OK" : "NG");
    return (digest == 0xE3069283u) ? 0 : -1;
}

/*
 * タイマ周波数を表示し、timer_delay_ms(10) の実測経過を出す。
 *
 * コール元:
 *   main()
 */
static void timer_selftest(void)
{
    uart_printf("[selftest] timer_freq = %u Hz\n", (uint32_t)timer_freq());
    uint64_t t0 = timer_now();
    timer_delay_ms(10u);
    uint64_t us = get_us_from(t0);
    uart_printf("[selftest] timer_delay_ms(10) 実測経過 = %u us (>=10000 なら OK)\n",
                (uint32_t)us);
}

/*
 * スピンロックの lock/unlock が期待通り状態を変えるかを確認する。
 *
 * コール元:
 *   main()
 */
static void spinlock_selftest(void)
{
    smp_spinlock_t lock = 0;
    smp_spin_lock(&lock);
    int held = (lock != 0);
    smp_spin_unlock(&lock);
    int freed = (lock == 0);
    uart_printf("[selftest] spinlock lock/unlock -> %s\n",
                (held && freed) ? "OK" : "NG");
}

/*
 * core1 を起動し、ハートビートが増加すること(pthread が実際に回っている
 * こと)を確認する。
 *
 * コール元:
 *   main()
 */
static void smp_selftest(void)
{
    uart_printf("[selftest] smp_core_index()(メインスレッド) = %u (期待 0)\n",
                smp_core_index());
    if (smp_boot_core1() != 0) {
        uart_printf("[selftest] smp_boot_core1 失敗\n");
        return;
    }
    uint64_t hb0 = g_core1_heartbeat;
    timer_delay_ms(50u);
    uint64_t hb1 = g_core1_heartbeat;
    uart_printf("[selftest] core1 alive=%d heartbeat %u -> %u (増加していれば pthread 稼働) -> %s\n",
                g_core1_alive, (uint32_t)hb0, (uint32_t)hb1,
                (hb1 > hb0) ? "OK" : "NG");
}

static mlx5_dev_t s_dev0, s_dev1; /* 大きい構造体なので static */

/*
 * VFIO スロットの PF を掴んで ConnectX を bring-up する。Bus Master を
 * 有効化し BAR0 を mmap して dev->bar0_base に入れ、mlx5_hca_bringup() を
 * 通す。
 *
 * 引数:
 *   slot     - vfio_init() が返したスロット番号
 *   dev      - 初期化する HCA ハンドル
 *   pf_index - 0=PF0 / 1=PF1(DMA 領域の前半後半の割り当てに使う)
 *   label    - ログ用の名前("PF0" 等)
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   run_dual_pf()
 */
static int bringup_pf(int slot, mlx5_dev_t *dev, uint8_t pf_index, const char *label)
{
    if (slot < 0) {
        uart_printf("[main] %s: vfio_init 失敗 -- vfio-pci バインド / IOMMU を確認\n", label);
        return -1;
    }
    vfio_enable_bus_master(slot);
    uint32_t id = vfio_cfg_read32(slot, 0x00);
    uart_printf("[main] %s Vendor=0x%04X Device=0x%04X\n", label, id & 0xffffu, (id >> 16) & 0xffffu);

    uint64_t bar_size = 0;
    void *bar0 = vfio_map_bar(slot, 0, &bar_size);
    if (!bar0) {
        uart_printf("[main] %s BAR0 mmap 失敗\n", label);
        return -1;
    }
    memset(dev, 0, sizeof(*dev));
    dev->bar0_base = (uint64_t)(uintptr_t)bar0;
    dev->pf_index  = pf_index;

    int rc = mlx5_hca_bringup(dev, label, 0);
    uart_printf("[main] %s mlx5_hca_bringup -> %d (%s)\n", label, rc, rc == 0 ? "OK" : "FAILED");
    return rc;
}

nvme_ctx_t s_nvme_ctx;

static nvmet_ctx_t s_x86_nvmet; /* .bss(内蔵 RAM ディスク含む、TCP 経路は CPU 側) */

static uint8_t s_nvmetcp_buf[262144] __attribute__((aligned(4096)));

/*
 * mlx5_monitor_summary3() へ渡す PCI コンフィグ空間リード関数。
 *
 * 引数:
 *   ctx - VFIO スロット番号を intptr_t で包んだもの
 *   off - コンフィグ空間オフセット
 * 戻り値:
 *   読んだ 32bit 値
 * コール元:
 *   shell_dispatch() から関数ポインタとして
 */
static uint32_t x86_cfg_rd(void *ctx, uint32_t off)
{
    return vfio_cfg_read32((int)(intptr_t)ctx, off);
}

/* ====================================================================== */
/* 常駐シェル(rpi5 の command_shell_run() 相当)                          */
/*                                                                        */
/* rpi5 は main() が対話ループ(command_shell_run)に入り job_scheduler_tick */
/* を回し続けるため、一度ブリングアップしたカードも nvmet ターゲットジョブも */
/* プロセスが終わらない限り常駐する。x86 はこれまで「1モード実行して return */
/* →プロセス終了」だったので毎回コールドスタートになっていた。ここで同じ    */
/* 常駐ループを持たせる: 起動時に1回だけフルブリングアップし、以後は          */
/* コマンドを対話的に受け付け、アイドル時に job_scheduler_tick() を回す。     */
/* これで monitor は再初期化なしで即実行でき、nvmet ターゲットも常駐する。    */
/* ====================================================================== */

static int s_shell_nvmet_started = 0;
static int s_shell_tcp_connected = 0;

/*
 * NVMe/TCP の常駐セッション(target@core1 + initiator@core0)を 1 回だけ
 * 確立し、以後の tcpbench で再利用する。`nvmet` コマンドで既にターゲットが
 * 常駐していればそれを使う。
 *
 * 戻り値:
 *   0=確立済み、-1=インターフェース未登録/接続タイムアウト
 * コール元:
 *   shell_tcpbench()
 */
static int shell_ensure_tcp_session(void)
{
    if (s_shell_tcp_connected) return 0;
    netif_t *ctx0 = netif_find("mlx5-pf0");
    netif_t *ctx1 = netif_find("mlx5-pf1");
    if (!ctx0 || !ctx1) { uart_printf("netif 未登録\n"); return -1; }

    if (!s_shell_nvmet_started) {
        if (smp_boot_core1() == 0) netif_set_owner_core(ctx1, 1u);
        netif_activate(ctx1);
        if (nvmet_job_start(&s_x86_nvmet, 4421u, ctx1, "manual") != 0) {
            uart_printf("tcpbench: ターゲット起動失敗\n"); return -1;
        }
        s_shell_nvmet_started = 1;
        uart_printf("tcpbench: ターゲット常駐起動 (pf1, core1)\n");
    }

    netif_activate(ctx0);
    static char subnqn[128] = "nqn.2014-08.org.nvmexpress:uuid:deadbeef-cafe-babe-dead-beefcafebabe";
    nvme_connect_job_start(&s_nvme_ctx, ip_from_octets(192, 168, 101, 11), 4421u, subnqn);
    uint64_t t = timer_now();
    while (s_nvme_ctx.busy) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        if (timeout_ms(t, 15000u)) { uart_printf("tcpbench: connect タイムアウト\n"); return -1; }
    }
    if (s_nvme_ctx.lba_size == 0u) { uart_printf("tcpbench: lba_size=0\n"); return -1; }
    s_shell_tcp_connected = 1;
    uart_printf("tcpbench: initiator 接続完了 (lba_size=%u)\n", s_nvme_ctx.lba_size);
    return 0;
}

/* ---- ベンチ引数パース + サマリ表示(bench/tcpbench 共通) ---- */
#define BENCH_MAX_CHUNKS 8u
typedef struct { uint32_t chunk; int is_read; uint32_t mbps_x100; } bench_res_t;
typedef struct { uint32_t chunks[BENCH_MAX_CHUNKS]; unsigned nchunks; int do_r, do_w; uint32_t qd; } bench_plan_t;

/*
 * 文字列を空白区切りで最大 n トークンに分割する(s を破壊する)。
 *
 * 引数:
 *   s   - 分割対象(書き換えられる)
 *   tok - 各トークン先頭の格納先
 *   n   - tok の要素数
 * 戻り値:
 *   実際に得られたトークン数
 * コール元:
 *   bench_plan_parse(), shell_simdelay(), shell_ts()
 */
static unsigned shell_tokenize(char *s, char *tok[], unsigned n)
{
    unsigned c = 0;
    while (*s && c < n) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        tok[c++] = s;
        while (*s && *s != ' ' && *s != '\t') s++;
        if (*s) *s++ = 0;
    }
    return c;
}

/*
 * ベンチ引数 "[KB[,KB...]] [r|w|rw] [qd]" を解析する。省略時は
 * 8/64/256KB・read+write・qd=8。
 *
 * 引数:
 *   args - 引数文字列(破壊される)
 *   pl   - 解析結果の格納先
 * コール元:
 *   shell_tcpbench(), shell_rdmabench()
 */
static void bench_plan_parse(char *args, bench_plan_t *pl)
{
    char *tok[3];
    unsigned nt = shell_tokenize(args, tok, 3);
    pl->qd = 8u; pl->do_r = 1; pl->do_w = 1;
    if (nt == 0) {
        pl->chunks[0] = 8192u; pl->chunks[1] = 65536u; pl->chunks[2] = 262144u; pl->nchunks = 3;
    } else {
        /* tok[0] = カンマ区切りのKBリスト。atoi は ',' で止まるので順に読む。 */
        pl->nchunks = 0;
        char *p = tok[0];
        while (*p && pl->nchunks < BENCH_MAX_CHUNKS) {
            uint32_t kb = (uint32_t)atoi(p);
            pl->chunks[pl->nchunks++] = (kb ? kb : 64u) * 1024u;
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
        }
        if (pl->nchunks == 0) { pl->chunks[0] = 65536u; pl->nchunks = 1; }
    }
    if (nt >= 2) {
        if (tok[1][0] == 'r' && tok[1][1] == 0) pl->do_w = 0;
        else if (tok[1][0] == 'w' && tok[1][1] == 0) pl->do_r = 0;
        /* "rw" その他は read+write 両方 */
    }
    if (nt >= 3) { uint32_t q = (uint32_t)atoi(tok[2]); if (q) pl->qd = q; }
}

/*
 * ベンチ結果を chunk ごとの write/read 表として表示する。
 *
 * 引数:
 *   tag - 見出し("NVMe/TCP" / "RDMA")
 *   qd  - 表示する queue depth
 *   r   - 測定結果の配列
 *   n   - その件数
 * コール元:
 *   shell_tcpbench(), shell_rdmabench()
 */
static void bench_summary(const char *tag, uint32_t qd, const bench_res_t *r, unsigned n)
{
    uart_printf("\n==== %s スループットまとめ (qd=%u, MB/s) ====\n", tag, qd);
    uart_printf("   chunk       write        read\n");
    uint32_t seen[BENCH_MAX_CHUNKS]; unsigned ns = 0;
    for (unsigned i = 0; i < n; i++) {
        int f = 0;
        for (unsigned j = 0; j < ns; j++) if (seen[j] == r[i].chunk) f = 1;
        if (!f && ns < BENCH_MAX_CHUNKS) seen[ns++] = r[i].chunk;
    }
    for (unsigned s = 0; s < ns; s++) {
        int32_t w = -1, rd = -1;
        for (unsigned i = 0; i < n; i++) if (r[i].chunk == seen[s]) {
            if (r[i].is_read) rd = (int32_t)r[i].mbps_x100; else w = (int32_t)r[i].mbps_x100;
        }
        uart_printf("  %5uK  ", seen[s] / 1024u);
        if (w >= 0) uart_printf("%8u.%02u", (unsigned)(w / 100), (unsigned)(w % 100)); else uart_printf("       -   ");
        uart_printf("  ");
        if (rd >= 0) uart_printf("%8u.%02u", (unsigned)(rd / 100), (unsigned)(rd % 100)); else uart_printf("       -   ");
        uart_printf("\n");
    }
}

/*
 * NVMe/TCP を 1 条件だけ 3 秒間回してスループットを測る。
 *
 * 引数:
 *   chunk   - 1 コマンドあたりの転送バイト数
 *   is_read - 1=read、0=write
 * 戻り値:
 *   MB/s の 100 倍固定小数点値
 * コール元:
 *   shell_tcpbench()
 */
static uint32_t tcp_measure(uint32_t chunk, int is_read)
{
    uint32_t nlb = chunk / s_nvme_ctx.lba_size;
    uint32_t cnt = 0, el = 0; uint64_t by = 0;
    if (is_read) nvme_read_pipelined_run(&s_nvme_ctx, 1u, 0u, s_nvmetcp_buf, nlb, 3000u, &cnt, &by, &el);
    else         nvme_write_pipelined_run(&s_nvme_ctx, 1u, 0u, s_nvmetcp_buf, nlb, 3000u, &cnt, &by, &el);
    uart_printf("[tcp] chunk=%u %s: %u 回, %u ms\n", chunk, is_read ? "read " : "write", cnt, el);
    return (el > 0) ? (uint32_t)((by * 100000ull) / ((uint64_t)el * 1000000ull)) : 0u;
}

/*
 * シェルの `tcpbench`。セッションを確立(既にあれば再利用)し、指定 chunk ×
 * read/write でスループットを測って表を出す。
 *
 * 引数:
 *   args - "[KB[,KB...]] [r|w|rw]"
 * コール元:
 *   shell_dispatch()
 */
static void shell_tcpbench(char *args)
{
    if (shell_ensure_tcp_session() != 0) return;
    bench_plan_t pl; bench_plan_parse(args, &pl);
    for (unsigned i = 0; i < sizeof(s_nvmetcp_buf); i++) s_nvmetcp_buf[i] = (uint8_t)(0x5au ^ (i * 7u));
    bench_res_t res[2u * BENCH_MAX_CHUNKS]; unsigned nr = 0;
    for (unsigned c = 0; c < pl.nchunks; c++) {
        if (pl.do_w) { res[nr].chunk = pl.chunks[c]; res[nr].is_read = 0; res[nr].mbps_x100 = tcp_measure(pl.chunks[c], 0); nr++; }
        if (pl.do_r) { res[nr].chunk = pl.chunks[c]; res[nr].is_read = 1; res[nr].mbps_x100 = tcp_measure(pl.chunks[c], 1); nr++; }
    }
    bench_summary("NVMe/TCP", 8u, res, nr);
}

/*
 * シェルの `bench`。NVMe-oF RDMA のスループットを指定 chunk × read/write ×
 * qdepth で測って表を出す。
 *
 * 引数:
 *   args - "[KB[,KB...]] [r|w|rw] [qd]"
 * コール元:
 *   shell_dispatch()
 */
static void shell_rdmabench(char *args)
{
    bench_plan_t pl; bench_plan_parse(args, &pl);
    bench_res_t res[2u * BENCH_MAX_CHUNKS]; unsigned nr = 0;
    for (unsigned c = 0; c < pl.nchunks; c++) {
        if (pl.do_w) { uint32_t m = 0; nvme_rdma_run_bench(&s_dev0, &s_dev1, 3000u, 0, pl.chunks[c], pl.qd, &m); res[nr].chunk = pl.chunks[c]; res[nr].is_read = 0; res[nr].mbps_x100 = m; nr++; }
        if (pl.do_r) { uint32_t m = 0; nvme_rdma_run_bench(&s_dev0, &s_dev1, 3000u, 1, pl.chunks[c], pl.qd, &m); res[nr].chunk = pl.chunks[c]; res[nr].is_read = 1; res[nr].mbps_x100 = m; nr++; }
    }
    bench_summary("RDMA", pl.qd, res, nr);
}

/*
 * シェルの `ts`。ts_log リングのダンプと pause/resume/mode 切り替えを行う。
 *
 * 引数:
 *   args - "[core N] [num N] [mask M V] | pause | resume"
 * コール元:
 *   shell_dispatch()
 */
static void shell_ts(char *args)
{
    char *tok[8];
    unsigned nt = shell_tokenize(args, tok, 8);
    unsigned core = 0, num = 20; uint32_t mask = 0, val = 0; int have_mask = 0; int pause = -1;
    for (unsigned i = 0; i < nt; ) {
        if (strcmp(tok[i], "pause") == 0) { pause = 1; i++; }
        else if (strcmp(tok[i], "resume") == 0) { pause = 0; i++; }
        else if (strcmp(tok[i], "mode") == 0 && i + 1 < nt) {
            ts_log_mode_set((uint32_t)strtoul(tok[i + 1], 0, 0));
            uart_printf("ts: mode=0x%x (bit0=cmd, bit2=hotpath per-frame)\n", ts_log_mode());
            return;
        }
        else if (strcmp(tok[i], "core") == 0 && i + 1 < nt) { core = (unsigned)atoi(tok[i + 1]); i += 2; }
        else if (strcmp(tok[i], "num") == 0 && i + 1 < nt) { num = (unsigned)atoi(tok[i + 1]); i += 2; }
        else if (strcmp(tok[i], "mask") == 0 && i + 2 < nt) {
            mask = (uint32_t)strtoul(tok[i + 1], 0, 0); val = (uint32_t)strtoul(tok[i + 2], 0, 0);
            have_mask = 1; i += 3;
        } else i++;
    }
    if (pause == 1) { ts_log_set_paused_core(core, 1); uart_printf("ts: core%u paused\n", core); return; }
    if (pause == 0) { ts_log_set_paused_core(core, 0); uart_printf("ts: core%u resumed\n", core); return; }
    uint64_t start = have_mask ? ts_log_query_start_last_n_matching(core, mask, val, num)
                               : ts_log_query_start_last_n(core, num);
    ts_log_dump_core(core, start, num, mask, val);
}

/*
 * シェルの `simdelay`。指定コアのメインループへ注入する人為的遅延(us)を
 * 設定する(律速要因の切り分け用)。
 *
 * 引数:
 *   args - "<core> <us>" または "show"
 * コール元:
 *   shell_dispatch()
 */
static void shell_simdelay(char *args)
{
    char *tok[2];
    unsigned nt = shell_tokenize(args, tok, 2);
    if (nt >= 1 && strcmp(tok[0], "show") == 0) {
        for (unsigned c = 0; c < SMP_MAX_CORES; c++)
            uart_printf("simdelay: core%u = %uus\n", c, (unsigned)g_sim_delay_us[c]);
        return;
    }
    if (nt < 2) { uart_printf("usage: simdelay <core> <us> | simdelay show\n"); return; }
    unsigned core = (unsigned)atoi(tok[0]);
    if (core >= SMP_MAX_CORES) { uart_printf("simdelay: core は 0..%u\n", SMP_MAX_CORES - 1); return; }
    g_sim_delay_us[core] = (uint32_t)atoi(tok[1]);
    uart_printf("simdelay: core%u = %uus\n", core, (unsigned)g_sim_delay_us[core]);
}

/*
 * シェルの `ackthresh`。TCP の遅延 ACK 閾値(フルサイズ何セグメントごとに
 * ACK するか)を設定/表示する。
 *
 * 引数:
 *   args - 新しい閾値。省略時は現在値を表示
 * コール元:
 *   shell_dispatch()
 */
static void shell_ackthresh(char *args)
{
    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
        unsigned n = (unsigned)atoi(args);
        if (n < 1u) n = 1u;
        g_tcp_ack_threshold = n;
    }
    uart_printf("ackthresh: %u (フルサイズ%uセグメント毎にACK)\n",
                (unsigned)g_tcp_ack_threshold, (unsigned)g_tcp_ack_threshold);
}

/*
 * 入力 1 行をコマンドとして解釈し実行する(monitor / nvmet / tcpbench /
 * bench / simdelay / ackthresh / ts / jobs / help / quit)。
 *
 * 引数:
 *   line   - 入力行(破壊される)
 *   s0, s1 - PF0/PF1 の VFIO スロット番号(monitor が config 空間を読む)
 * コール元:
 *   run_shell()
 */
static void shell_dispatch(char *line, int s0, int s1)
{
    /* 先頭の空白を飛ばし、コマンド語を取り出す。 */
    while (*line == ' ' || *line == '\t') line++;
    if (*line == 0) return;

    if (strncmp(line, "monitor", 7) == 0 || strncmp(line, "mon", 3) == 0) {
        /* 再初期化なし: 既にブリングアップ済みの s_dev0/s_dev1 を読むだけ。 */
        mlx5_monitor_summary3(&s_dev0, &s_dev1, x86_cfg_rd,
                              (void *)(intptr_t)s0, (void *)(intptr_t)s1);
    } else if (strncmp(line, "nvmet", 5) == 0) {
        if (s_shell_nvmet_started) {
            uart_printf("nvmet: 既に常駐起動済み\n");
            return;
        }
        uint16_t port = 4421u;
        const char *p = line + 5;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9') port = (uint16_t)atoi(p);
        netif_t *ctx1 = netif_find("mlx5-pf1");
        if (!ctx1) { uart_printf("nvmet: mlx5-pf1 未登録\n"); return; }
        if (smp_boot_core1() == 0) netif_set_owner_core(ctx1, 1u);
        if (nvmet_job_start(&s_x86_nvmet, port, ctx1, "manual") != 0) {
            uart_printf("nvmet: nvmet_job_start 失敗\n"); return;
        }
        s_shell_nvmet_started = 1;
        uart_printf("nvmet: ターゲット常駐起動 (pf1, port %u) -- 接続待ち\n", port);
    } else if (strncmp(line, "tcpbench", 8) == 0) {
        shell_tcpbench(line + 8);
    } else if (strncmp(line, "bench", 5) == 0) {
        shell_rdmabench(line + 5);
    } else if (strncmp(line, "simdelay", 8) == 0) {
        shell_simdelay(line + 8);
    } else if (strncmp(line, "ackthresh", 9) == 0) {
        shell_ackthresh(line + 9);
    } else if (strncmp(line, "ts", 2) == 0 && (line[2] == 0 || line[2] == ' ')) {
        shell_ts(line + 2);
    } else if (strncmp(line, "jobs", 4) == 0) {
        job_list_dump();
    } else if (strncmp(line, "help", 4) == 0) {
        uart_printf("commands:\n"
                    "  monitor                              HW状態(温度/エラー/PCIe/リンク)\n"
                    "  bench [KB[,KB...]] [r|w|rw] [qd]      NVMe-oF RDMA スループット\n"
                    "  tcpbench [KB[,KB...]] [r|w|rw]        NVMe/TCP スループット(qdは内部固定)\n"
                    "  ts [core N] [num N] [mask M V] | ts pause|resume   ts_log ダンプ\n"
                    "  simdelay <core> <us> | simdelay show   律速切り分け(遅延注入)\n"
                    "  nvmet [port] | jobs | help | quit    (↑↓で履歴呼び出し)\n"
                    "  例: bench 8,64,256 rw 8 / tcpbench 64,256 w / ts core 1 num 40\n");
    } else if (strncmp(line, "quit", 4) == 0 || strncmp(line, "exit", 4) == 0) {
        uart_printf("bye\n");
        exit(0);
    } else {
        uart_printf("unknown: %s  (help でコマンド一覧)\n", line);
    }
}

/* ---- 常駐シェルの行編集(64件履歴 + ↑↓ 呼び出し + backspace) ---- */
#define SHELL_LINE_MAX 128
#define SHELL_HIST_MAX 64

static char     s_hist[SHELL_HIST_MAX][SHELL_LINE_MAX];
static unsigned s_hist_count = 0;

typedef struct {
    char     line[SHELL_LINE_MAX];
    unsigned len;
    char     draft[SHELL_LINE_MAX];
    unsigned draft_len;
    unsigned hist_idx;
    int      browsing;   /* 履歴閲覧中か */
    int      esc;        /* 0=通常, 1=ESC受信, 2=ESC[受信 */
} shell_editor_t;

/*
 * 確定した入力行をコマンド履歴へ積む(上下キーで呼び出せるようにする)。
 *
 * 引数:
 *   l - 積む行
 * コール元:
 *   run_shell()
 */
static void shell_hist_push(const char *l)
{
    if (l[0] == 0) return;
    if (s_hist_count > 0 && strcmp(s_hist[s_hist_count - 1], l) == 0) return; /* 直前と同一は積まない */
    if (s_hist_count == SHELL_HIST_MAX) {                                     /* 満杯なら最古を捨てる */
        for (unsigned i = 1; i < SHELL_HIST_MAX; i++) memcpy(s_hist[i - 1], s_hist[i], SHELL_LINE_MAX);
        s_hist_count--;
    }
    unsigned i = 0;
    for (; l[i] && i < SHELL_LINE_MAX - 1; i++) s_hist[s_hist_count][i] = l[i];
    s_hist[s_hist_count][i] = 0;
    s_hist_count++;
}

/*
 * 行編集バッファの内容を src で置き換え、画面の表示も更新する
 * (履歴の呼び出しに使う)。
 *
 * 引数:
 *   ed  - 行エディタ状態
 *   src - 新しい行内容
 * コール元:
 *   shell_editor_byte()
 */
static void shell_set_line(shell_editor_t *ed, const char *src)
{
    unsigned i = 0;
    for (; src[i] && i < SHELL_LINE_MAX - 1; i++) ed->line[i] = src[i];
    ed->line[i] = 0; ed->len = i;
    uart_printf("\r\033[K> %s", ed->line);   /* 行クリア + プロンプト + 再描画 */
}

/*
 * 入力 1 バイトを行エディタへ与える。通常文字の挿入・バックスペース・
 * 上下キー(履歴)・改行による行確定を扱う。
 *
 * 引数:
 *   ed - 行エディタ状態
 *   ch - 入力バイト
 * 戻り値:
 *   1=行が確定した(ed->line が有効)、0=編集継続中
 * コール元:
 *   run_shell()
 */
static int shell_editor_byte(shell_editor_t *ed, unsigned char ch)
{
    if (ed->esc == 1) { ed->esc = (ch == '[') ? 2 : 0; return 0; }
    if (ed->esc == 2) {
        ed->esc = 0;
        if (ch == 'A') {                          /* ↑: 履歴を遡る */
            if (s_hist_count == 0) return 0;
            if (!ed->browsing) {
                for (unsigned i = 0; i < ed->len; i++) ed->draft[i] = ed->line[i];
                ed->draft_len = ed->len; ed->browsing = 1; ed->hist_idx = s_hist_count;
            }
            if (ed->hist_idx > 0) { ed->hist_idx--; shell_set_line(ed, s_hist[ed->hist_idx]); }
        } else if (ch == 'B') {                   /* ↓: 履歴を進む/下書きへ */
            if (!ed->browsing) return 0;
            ed->hist_idx++;
            if (ed->hist_idx >= s_hist_count) {
                ed->draft[ed->draft_len] = 0; shell_set_line(ed, ed->draft); ed->browsing = 0;
            } else {
                shell_set_line(ed, s_hist[ed->hist_idx]);
            }
        }
        return 0;   /* C/D(左右カーソル)は未対応 -- 末尾編集のみ */
    }
    if (ch == 0x1b) { ed->esc = 1; return 0; }
    if (ch == '\r' || ch == '\n') { ed->line[ed->len] = 0; uart_putc('\r'); uart_putc('\n'); return 1; }
    if (ch == 0x7f || ch == 0x08) { if (ed->len > 0) { ed->len--; ed->line[ed->len] = 0; uart_puts("\b \b"); } return 0; }
    if (ch >= 0x20 && ch < 0x7f) {
        if (ed->len < SHELL_LINE_MAX - 1) { ed->line[ed->len++] = (char)ch; ed->line[ed->len] = 0; uart_putc((char)ch); }
        return 0;
    }
    return 0;
}

static struct termios s_orig_tio;
static int s_raw_active = 0;
static void shell_restore_tty(void) { if (s_raw_active) { tcsetattr(0, TCSANOW, &s_orig_tio); s_raw_active = 0; } }
/*
 * 端末を raw モード(canonical/echo 無効)にする。矢印キーと 1 文字ずつの
 * 即時エコーのため。プロセス終了時に元へ戻す atexit ハンドラも登録する。
 *
 * コール元:
 *   run_shell()
 */
static void shell_raw_mode(void)
{
    if (!isatty(0)) return;
    if (tcgetattr(0, &s_orig_tio) != 0) return;
    struct termios t = s_orig_tio;
    t.c_lflag &= ~((tcflag_t)(ICANON | ECHO));
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
    if (tcsetattr(0, TCSANOW, &t) == 0) { s_raw_active = 1; atexit(shell_restore_tty); }
}

/*
 * 常駐シェル。起動時に 1 回だけ arp/ip ハンドラ登録と netif 登録を行い、
 * 以後はコマンドを対話的に受け付けつつ、アイドル時に job_scheduler_tick()
 * と net_poll_all_and_dispatch() を回し続ける(戻らない)。
 *
 * 引数:
 *   s0, s1 - PF0/PF1 の VFIO スロット番号
 * コール元:
 *   run_dual_pf()
 */
static void run_shell(int s0, int s1)
{
    /* Ethernet/TCP/nvmet 用の net_ctx を1回だけ登録(以後のコマンドで再利用)。 */
    arp_init();
    ip_init();
    mlx5_net_register_dual(&s_dev0, &s_dev1);

    int fl = fcntl(0, F_GETFL, 0);
    if (fl != -1) (void)fcntl(0, F_SETFL, fl | O_NONBLOCK);
    shell_raw_mode();
    setvbuf(stdout, NULL, _IONBF, 0);

    uart_printf("\n==== x86 常駐シェル(bring-up 済み、再初期化なし、↑↓で履歴呼び出し) ====\n");
    uart_printf("commands: monitor | bench [KB[,KB..]] [r|w|rw] [qd] | tcpbench [..] | ts [..] | nvmet [port] | jobs | help | quit\n> ");

    shell_editor_t ed = {0};
    ed.hist_idx = s_hist_count;
    for (;;) {
        unsigned char ch;
        while (read(0, &ch, 1) == 1) {
            if (shell_editor_byte(&ed, ch)) {
                if (ed.len > 0) { shell_hist_push(ed.line); shell_dispatch(ed.line, s0, s1); }
                ed.len = 0; ed.line[0] = 0; ed.browsing = 0; ed.hist_idx = s_hist_count;
                uart_printf("> ");
            }
        }
        /* アイドル: 常駐ジョブ(nvmet ターゲット等)と受信ポーリングを回す。 */
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        usleep(1000);
    }
}

/*
 * PF0/PF1 を両方 bring-up し、常駐シェルへ入る(戻らない)。
 *
 * 引数:
 *   bdf0, bdf1 - 2 つの PF の PCI アドレス
 * 戻り値:
 *   -1=bring-up 失敗(成功時は run_shell() から戻らない)
 * コール元:
 *   main()
 */
static int run_dual_pf(const char *bdf0, const char *bdf1)
{
    uart_printf("\n========== dual-PF bring-up: %s + %s ==========\n", bdf0, bdf1);
    int s0 = vfio_init(bdf0);
    int s1 = vfio_init(bdf1);
    if (bringup_pf(s0, &s_dev0, 0u, "PF0") != 0) return -1;
    if (bringup_pf(s1, &s_dev1, 1u, "PF1") != 0) return -1;
    run_shell(s0, s1);
    return 0;
}

/*
 * エントリポイント。自己テスト(crc32c / timer / spinlock / smp)を行い、
 * 引数に 2 つの PCI アドレスが与えられていれば bring-up + 常駐シェルへ。
 *
 * 引数:
 *   argc, argv - argv[1], argv[2] が PF0/PF1 の PCI アドレス
 * 戻り値:
 *   0=正常、1=自己テスト失敗または bring-up 失敗
 */
int main(int argc, char **argv)
{
    uart_puts("\nvfio_nvme -- ConnectX-4 / VFIO / NVMe-oF (RoCEv2 + TCP)\n\n");

    int rc = 0;
    rc |= crc32c_selftest();
    timer_selftest();
    spinlock_selftest();
    smp_selftest();

    if (argc >= 3) {
        return run_dual_pf(argv[1], argv[2]) ? 1 : 0;
    }

    uart_puts("\n使い方:\n"
              "  sudo ./vfio_nvme <BDF0> <BDF1>   dual PF bring-up + 常駐シェル\n"
              "  例: sudo ./vfio_nvme 0000:01:00.0 0000:01:00.1\n");
    uart_printf("\nself-tests %s\n", (rc == 0) ? "PASSED" : "had FAILURES");
    return rc ? 1 : 0;
}
