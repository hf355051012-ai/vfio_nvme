#include "command.h"
#include "pl011.h"
#include "fwupdate.h"
#include "mmio.h"
#include "board.h"
#include "pcie.h"
#include "pcie1.h"
#include "mlx5.h"
#include "nvmet_rdma.h"
#include "netctx.h"
#include "version.h"
#include "fan.h"
#include "pcidump.h"
#include "eth.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "test.h"
#include "bench.h"
#include "err.h"
#include "net.h"
#include "net_buf.h"
#include "uart.h"
#include "timer.h"
#include "nvme.h"
#include "nvmet.h"
#include "rxcopy.h"
#include "timestamp.h"
#include "iperf3.h"
#include "job.h"
#include "platform_init.h"
#include "telnet.h"
#include "ftpd.h"
#include "psci.h"
#include "smp.h"

extern pl011_t debug_uart; // main.cで定義

/* 現在dispatch()を呼び出している論理セッション(0=物理UART/telnet
 * インスタンス0の共有セッション、1=telnetインスタンス1、telnet.h参照)。
 * command_shell_run()が各インスタンスのdispatch()呼び出し直前に設定する
 * -- cmd_exit()が「今操作されているセッションのtelnet接続だけを切る」
 * ために参照する(このプロジェクトは単一物理コア上で複数の論理セッション
 * を協調的に切り替える設計のため、単純なグローバル変数で安全に表現
 * できる、g_active_ctx等と同じ考え方)。 */
static unsigned s_current_console = 0;

typedef struct {
    const char *name;
    const char *help;
    void (*handler)(const char *args);
} command_t;

static void cmd_help(const char *args);
static void cmd_test(const char *args);
static void cmd_fwupdate(const char *args);
static void cmd_reboot(const char *args);
static void cmd_pcie(const char *args);
static void cmd_pcie1(const char *args);
static void cmd_mlx5(const char *args);
static void cmd_mlx5stat(const char *args);
static void cmd_mlx5hw(const char *args);
static void cmd_mlx5netdump(const char *args);
static void cmd_mlx5txlat(const char *args);
static void cmd_mlx5roce(const char *args);
static void cmd_mlx5qp(const char *args);
static void cmd_mlx5mad(const char *args);
static void cmd_mlx5rdmacm(const char *args);
static void cmd_mlx5rdmaconnect(const char *args);
static void cmd_nvmerdmaconnect(const char *args);
static void cmd_nvmermabench(const char *args);
static void cmd_nvmetrdmastart(const char *args);
static void cmd_nvmetrdmastat(const char *args);
static void cmd_mlx5fteskip(const char *args);
static void cmd_version(const char *args);
static void cmd_fan(const char *args);
static void cmd_mw(const char *args);
static void cmd_md(const char *args);
static void cmd_rp1(const char *args);
static void cmd_pcicfg(const char *args);
static void cmd_pcicfg1(const char *args);
static void cmd_net(const char *args);
static void cmd_arp(const char *args);
static void cmd_ping(const char *args);
static void cmd_tcp(const char *args);
static void cmd_tcptest(const char *args);
static void cmd_tcplooptest(const char *args);
static void cmd_tcploopbench(const char *args);
static void cmd_tcpbench(const char *args);
static void cmd_sendbench(const char *args);
static void cmd_err(const char *args);
static void cmd_cpuon(const char *args);
static void cmd_smpstat(const char *args);
static void cmd_simdelay(const char *args);
static void cmd_txdump(const char *args);
static void cmd_nvme(const char *args);
static void cmd_nvmet(const char *args);
static void cmd_nprof(const char *args);
static void cmd_ts(const char *args);
static void cmd_iperf3(const char *args);
static void cmd_jobs(const char *args);
static void cmd_nvmetpull(const char *args);
static void cmd_rxoff(const char *args);
static void cmd_job(const char *args);
static void cmd_platform_init(const char *args);
static void cmd_telnet(const char *args);
static void cmd_telnet2(const char *args);
static void cmd_exit(const char *args);

// lineの先頭len文字がnameと完全一致するかを判定する(サブコマンド解析でも使う)。
static int cmd_name_eq(const char *line, unsigned len, const char *name);

static const command_t COMMANDS[] = {
    {"help", "help [コマンド名]  (list all commands, or show one command's detail if a name is given)", cmd_help},
    {"test", "list available commands", cmd_test},
    {"version", "show the firmware build version (src/version.h)", cmd_version},
    {"fwupdate", "receive a new firmware image via Xmodem and run it; `fwupdate lan [port] [data_port]` instead starts a persistent LAN/FTP update server (PASV only, default 21/20001, requires `net init` and running from the primary image; STOR boot/payload_2712.img, NOT kernel_2712.img; to stop, use `job stop <番号>`)", cmd_fwupdate},
    {"reboot", "reset the board via the PM watchdog", cmd_reboot},
    {"pcie", "bring up the PCIe link to RP1 and read its vendor/device ID", cmd_pcie},
    {"pcie1", "bring up the PCIe1 link and probe/assign BAR0, or `pcie1 reset` to PERST#-cycle ConnectX without a full reboot", cmd_pcie1},
    {"mlx5", "bring up ConnectX PF0+PF1 (dual-port), init both HCAs, and cross-port loopback test", cmd_mlx5},
    {"mlx5stat", "re-query ConnectX internal registers (PPCNT phys-port counters, RQ/SQ/CQ hw state) from the last `mlx5` bring-up, no re-init", cmd_mlx5stat},
    {"mlx5hw", "ConnectX HW monitor: temperature(MTMP), FW health(synd), PCIe HW errors(MPCNT: crc/rx/tx/L0-recovery), link-layer errors(PPCNT), PCIe link speed/width/MPS/MRRS", cmd_mlx5hw},
    {"mlx5netdump", "mlx5netdump <0|1>  (dump mlx5_net.c's raw SQ CQ ring + WQE ring bytes and sq_pc/sq_cc for PF0/PF1, read-only, safe to call while an SQ TX timeout is stuck)", cmd_mlx5netdump},
    {"mlx5txlat", "mlx5txlat <0|1> [iterations]  (measure pure BlueFlame doorbell post->CQE-completion round-trip latency in isolation, default 200 iterations)", cmd_mlx5txlat},
    {"mlx5roce", "mlx5roce <0|1>  (RoCEv2 addressing phase(a): check general/detailed RoCE HCA caps, build an IPv4-mapped GID, SET_ROCE_ADDRESS + QUERY_ROCE_ADDRESS readback check; requires `mlx5` or `net init mlx5` first)", cmd_mlx5roce},
    {"mlx5qp", "mlx5qp create|query|loop <0|1> | mlx5qp pingpong | mlx5qp rdma  (RoCEv2 phase(b)/(c): create/query a diagnostic RC QP, `loop <0|1>` connects 2 QPs on the SAME PF (cross-PF isolation test), `pingpong` runs the full PF0<->PF1 SEND/RECV test, `rdma` runs bidirectional RDMA_WRITE/READ; requires `mlx5` or `net init mlx5` first)", cmd_mlx5qp},
    {"mlx5mad", "mlx5mad probe <0|1> <ud|gsi> | mlx5mad test <ud|gsi>  (RoCEv2 phase(d): `probe` tries CREATE_QP with UD[st=0x2] or GSI/QP1[st=0x8] transport on the given PF and reports FW's reaction, `test` runs a PF0->PF1 single-MAD SEND/RECV using whichever transport succeeded; requires `mlx5` or `net init mlx5` first)", cmd_mlx5mad},
    {"mlx5rdmacm", "mlx5rdmacm test  (RoCEv2 phase(e): drives standard IB CM REQ->REP->RTU over GSI to establish an RC QP automatically [PF0 active, PF1 passive], then verifies with a SEND/RECV ping-pong on the CM-established QP; requires `mlx5` or `net init mlx5` first)", cmd_mlx5rdmacm},
    {"mlx5rdmaconnect", "mlx5rdmaconnect  (RoCEv2 phase(f), (c)+(e) combined: CM connect -> auto QP establish -> bidirectional RDMA_WRITE/READ over the established QP, all in one command; requires `mlx5` or `net init mlx5` first)", cmd_mlx5rdmaconnect},
    {"nvmerdmaconnect", "nvmerdmaconnect  (RoCEv2 phase(g): NVMe-oF RDMA transport -- CM connect -> Fabrics Connect -> CC enable -> Identify Controller/Namespace -> write -> read, all in one command; requires `mlx5` or `net init mlx5` first)", cmd_nvmerdmaconnect},
    {"nvmermabench", "nvmermabench <duration_ms> <read|write> [chunk_bytes] [qdepth]  (RoCEv2 phase(h): sustained NVMe-oF RDMA write/read throughput over PF0<->PF1 loopback; qdepth>1 enables command pipelining; requires `mlx5` or `net init mlx5` first)", cmd_nvmermabench},
    {"nvmetrdmastart", "nvmetrdmastart <0|1> [peer_mac xx:xx:xx:xx:xx:xx]  (RoCEv2 phase(i): start a resident nvmet_rdma target on the given PF, waiting indefinitely for an external host's CM connect; peer_mac is needed for real hosts since IBTA CM carries no MAC; requires `mlx5` or `net init mlx5` first)", cmd_nvmetrdmastart},
    {"nvmetrdmastat", "nvmetrdmastat  (RoCEv2 phase(i): dump RC/GSI QP state and HW/SW counters for the resident nvmetrdmastart target)", cmd_nvmetrdmastat},
    {"mlx5fteskip", "mlx5fteskip <0|1>  (TEMP EXPERIMENT: skip the catch-all flow table entry in mlx5_hca_bringup(), to test whether it's swallowing RoCEv2 frames before they reach verbs QPs; takes effect on next `mlx5`/`net init mlx5`)", cmd_mlx5fteskip},
    {"fan", "spin the case fan: fan [duty]  (0-100, default 100; via RP1 PWM1)", cmd_fan},
    {"mw", "write a 32-bit word: mw <addr> <val>  (0x prefix = hex, otherwise decimal)", cmd_mw},
    {"md", "dump 32-bit words: md <addr> [count]  (0x prefix = hex, otherwise decimal)", cmd_md},
    {"rp1", "dump RP1 registers: rp1 <offset> [count]  (offset from RP1 base; 0x prefix = hex, otherwise decimal)", cmd_rp1},
    {"pcicfg", "dump a device's full PCI config space: pcicfg <bus> <devfn>  (0x prefix = hex, otherwise decimal)", cmd_pcicfg},
    {"pcicfg1", "dump a device's PCI config space on PCIe1 (ConnectX slot): pcicfg1 <bus> <devfn>  (bus 0 devfn 0 = root port, readable even if link training failed)", cmd_pcicfg1},
    {"net", "net init [mlx5] | net poll | net use <name>  (bring up RP1 or ConnectX dual-loopback + ARP/IPv4 handlers, poll one RX frame, or switch the active interface)", cmd_net},
    {"arp", "arp who <IP>  (send an ARP request for the given IPv4 address)", cmd_arp},
    {"ping", "ping <IP>  (send an ICMP Echo Request to the given IPv4 address)", cmd_ping},
    {"tcp", "tcp connect <IP> <port> | tcp send <text> | tcp recv [timeout_ms] | tcp close", cmd_tcp},
    {"tcptest", "tcptest <IP> <port> <bytes>  (connect+send+recv-echo+close, verify byte-for-byte)", cmd_tcptest},
    {"tcplooptest", "tcplooptest <server_IP> <client_IP> <port> <bytes>  (self-contained TCP test over 2 registered interfaces, e.g. ConnectX mlx5-pf0/pf1 loopback; no external peer needed)", cmd_tcplooptest},
    {"tcploopbench", "tcploopbench <server_IP> <client_IP> <port> <duration_ms> [mode] [xfer_len]  (self-contained sustained one-way throughput bench over 2 registered interfaces, e.g. ConnectX mlx5-pf0/pf1 loopback; no external peer. mode bit0=pin server/target to core1 via job.h so `ts core 0`/`ts core 1` separate sender/receiver logs, bit1=single-shot transfer instead of looping; xfer_len=bytes per tcp_send() call, 0=default TCP_TEST_MAX_LEN)", cmd_tcploopbench},
    {"tcpbench", "tcpbench <IP> <port> [phase_duration_ms]  (throughput test, ramps chunk size, logs telemetry every 1s)", cmd_tcpbench},
    {"sendbench", "sendbench <IP> <port> [duration_ms]  (one-way send-only throughput test, no echo wait; needs script/sink.ps1 on the peer)", cmd_sendbench},
    {"err", "check PCIe AER (root port + RP1) and GEM TSR for real hardware-level errors", cmd_err},
    {"cpuon", "PSCI CPU_ON (multicore Phase 2, see ~/.claude/plans/wondrous-baking-gadget.md): probe PSCI_VERSION then boot core1 (target_cpu affinity1=1) into secondary_entry (src/boot.S), which sets up its own C stack/MMU/exception vectors (src/smp.c's secondary_main()) and enters an idle loop -- use `smpstat` to confirm it's alive", cmd_cpuon},
    {"smpstat", "check whether core1 (started via `cpuon`) is alive: samples g_core1_heartbeat (src/smp.c) twice ~200ms apart and shows the delta", cmd_smpstat},
    {"simdelay", "perf-isolation tool (temporary, src/smp.c g_sim_delay_us): `simdelay <core> <us>` injects a busy-wait of <us> microseconds per main-loop iteration on the given core (0/1), simulating a slower clock; `simdelay show` prints current values", cmd_simdelay},
    {"txdump", "dump the TX ring descriptor snapshot captured at the last "
               "TX-slot-wait timeout (survives ts_log ring overwrite, see eth.c)", cmd_txdump},
    {"nvme", "nvme connect <IP> <port> <subnqn> | disconnect | id-ctrl | id-ns <nsid> | "
             "read <nsid> <lba> [count] | write <nsid> <lba> <hex...> | "
             "bench <nsid>  (read+write IOPS/throughput across 8K/32K/64K/256K)", cmd_nvme},
    {"nvmet", "nvmet [port]  (start NVMe/TCP target on port, default 4420; serves 4MB RAM disk; to stop, use `job stop <番号>`)", cmd_nvmet},
    {"nprof", "nprof [reset]  (dump or reset per-state dwell-time stats for the nvme.c/nvmet.c state machines -- nvme-connect/exec (core0) and nvmet slot 0-3 admin/io (rp1=0, mlx5-pf0=1, mlx5-pf1=2, manual=3, whichever core they're pinned to); "
              "`nprof reset` right before a `test`/benchmark run, `nprof` right after, to see where time went between core0 and core1)", cmd_nprof},
    {"ts", "ts [core <N>] [num <N>] [mask <mask> <value>] [start <N>] [end <N>] [tick <値>] [frozen] | ts pause | ts resume  "
           "(dump ts_log() entries; all options are named -- core: target core, default 0; num: max entries, default 20; "
           "mask: filter by (tag & mask)==value, tag=File#[31:24]|Func#[23:16]|info[15:0] (e.g. `ts mask 0x00f00000 0x00200000` = all mlx5_net.c funcs); "
           "start/end: dump通し番号#start-#end range (both required); "
           "tick: start from the first entry after this tick value (cross-core correlation); "
           "frozen: dump the pre-failure ts_log_freeze() snapshot instead of the live ring; "
           "pause/resume stop new entries from overwriting the buffer while you read it)", cmd_ts},
    {"iperf3", "iperf3 [port]  (run one iperf3 server session; TCP only, single stream -P 1; default port 5201)", cmd_iperf3},
    {"jobs", "list currently active background jobs (job.h scheduler, e.g. an in-flight `ping`)", cmd_jobs},
    {"nvmetpull", "nvmetpull <0|1>  (非digest接続をpull型に強制、push vs pull コピー時間A/B、検証用)", cmd_nvmetpull},
    {"rxoff", "rxoff <0|1>  (push受信のRAM_diskコピーをcore1へオフロード、A/B検証用)", cmd_rxoff},
    {"job", "job stop <番号>  (request the job at `jobs`' [N] index to stop; not all job types honor this, e.g. one-shot ping/nvme jobs finish on their own)", cmd_job},
    {"platform_init", "run environment bring-up: fan 50%, RP1 net init + nvmet, and ConnectX (if present) + nvmet on both ports (platform_init.c; not run automatically at boot, see comment)", cmd_platform_init},
    {"telnet", "telnet [port]  (start a persistent telnet server mirroring this same shell session over TCP, default port 23; requires `net init` first; to stop, use `job stop <番号>`)", cmd_telnet},
    {"telnet2", "telnet2 [port]  (start a fully independent second telnet session for core1, own IP/port/line-editor/history/output, no physical UART involvement; default port 2323; requires `net init` first; to stop, use `job stop <番号>`)", cmd_telnet2},
    {"exit", "disconnect the current telnet client (if any) so the PC side can end the session without killing the client process; the telnet server itself keeps listening for the next connection. No effect over the serial console.", cmd_exit},
    {"quit", "alias for `exit`", cmd_exit},
};
#define NUM_COMMANDS (sizeof(COMMANDS) / sizeof(COMMANDS[0]))

// 先頭の空白を読み飛ばす。
static const char *skip_spaces(const char *s) {
    while (*s == ' ') {
        s++;
    }
    return s;
}

// 数値を読み取る("0x"接頭辞で16進、なければ10進)。成功時0、失敗時-1。
static int parse_number(const char **s, uint64_t *out) {
    const char *p = *s;
    int hex = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        hex = 1;
        p += 2;
    }
    uint64_t val = 0;
    int digits = 0;
    while (1) {
        char c = *p;
        uint32_t d;
        if (c >= '0' && c <= '9') {
            d = (uint32_t)(c - '0');
        } else if (hex && c >= 'a' && c <= 'f') {
            d = (uint32_t)(c - 'a' + 10);
        } else if (hex && c >= 'A' && c <= 'F') {
            d = (uint32_t)(c - 'A' + 10);
        } else {
            break;
        }
        val = hex ? (val << 4) | d : val * 10 + d;
        p++;
        digits++;
    }
    if (digits == 0) {
        return -1;
    }
    *out = val;
    *s = p;
    return 0;
}

// "a.b.c.d" 形式のIPv4アドレスを読み取る。成功時0、失敗時-1(0-255の範囲外含む)。
static int parse_ip(const char **s, uint8_t ip[4]) {
    for (int i = 0; i < 4; i++) {
        uint64_t octet;
        if (parse_number(s, &octet) != 0 || octet > 255) {
            return -1;
        }
        ip[i] = (uint8_t)octet;
        if (i < 3) {
            if (**s != '.') {
                return -1;
            }
            (*s)++;
        }
    }
    return 0;
}

// baseからcount個の32ビットワードを1行4個ずつダンプする。md/rp1で共用。
static void hexdump32(uint64_t base, uint64_t count, const char *label) {
    for (uint64_t i = 0; i < count; i++) {
        uint64_t addr = base + i * 4;
        if (i % 4 == 0) {
            if (i != 0) {
                pl011_puts(&debug_uart, "\n");
            }
            pl011_puts(&debug_uart, label);
            pl011_hex64(&debug_uart, addr);
            pl011_puts(&debug_uart, ": ");
        } else {
            pl011_puts(&debug_uart, " ");
        }
        pl011_hex32(&debug_uart, mmio_read32(addr));
    }
    pl011_puts(&debug_uart, "\n");
}

// `help`: コマンド一覧を表示する。`help <コマンド名>`ならそのコマンドの
// 詳細(usage文言含む)だけを表示する。
static void cmd_help(const char *args) {
    args = skip_spaces(args);
    if (*args != '\0') {
        unsigned name_len = 0;
        while (args[name_len] != '\0' && args[name_len] != ' ') {
            name_len++;
        }
        for (unsigned i = 0; i < NUM_COMMANDS; i++) {
            if (cmd_name_eq(args, name_len, COMMANDS[i].name)) {
                pl011_puts(&debug_uart, COMMANDS[i].name);
                pl011_puts(&debug_uart, " - ");
                pl011_puts(&debug_uart, COMMANDS[i].help);
                pl011_puts(&debug_uart, "\n");
                return;
            }
        }
        uart_printf("help: unknown command: '%.*s'\n", (int)name_len, args);
        return;
    }
    pl011_puts(&debug_uart, "available commands:\n");
    for (unsigned i = 0; i < NUM_COMMANDS; i++) {
        pl011_puts(&debug_uart, "  ");
        pl011_puts(&debug_uart, COMMANDS[i].name);
        pl011_puts(&debug_uart, " - ");
        pl011_puts(&debug_uart, COMMANDS[i].help);
        pl011_puts(&debug_uart, "\n");
    }
    pl011_puts(&debug_uart, "(コマンド名を指定すると詳細のみ表示: help <コマンド名>)\n");
}

static void cmd_test(const char *args) {
    args = skip_spaces(args);
    uint64_t param[TESTPARAM];
    int i;

    for(i=0;i<TESTPARAM;i++){
        param[i] = 0;
    }
    for(i=0;i<TESTPARAM;i++){
        if (*args == '\0') break;
        parse_number(&args, &param[i]);
        args = skip_spaces(args);
    }
    temp_test(param);
}

static void cmd_version(const char *args) {
    (void)args;
    uart_printf("firmware version: 0x%08x\n", (unsigned)FW_VERSION);
}

// `fwupdate`: UART Xmodem経由の従来のファームウェア更新を開始する
// (引数無し、ブロッキング)。`fwupdate lan [port] [data_port]`は代わりに
// LAN/FTP経由の常駐サーバを起動する(ftpd.h参照、job化されており即座に
// シェルへ戻る、停止は`job stop <番号>`)。プライマリイメージから実行中
// でない場合は起動を拒否する(ftpd.hコメント参照 -- UART版と違い自動で
// プライマリへ戻ることはしない)。
static void cmd_fwupdate(const char *args) {
    args = skip_spaces(args);
    if (*args == '\0') {
        fwupdate_run();
        return;
    }

    unsigned word_len = 0;
    while (args[word_len] != '\0' && args[word_len] != ' ') word_len++;

    if (!cmd_name_eq(args, word_len, "lan")) {
        uart_printf("usage: fwupdate                          (UART Xmodem)\n"
                    "       fwupdate lan [port] [data_port]    (LAN FTP, PASV only; default 21/20001; requires `net init` first)\n");
        return;
    }

    uint64_t port = 21u;
    uint64_t data_port = 20001u;
    const char *rest = skip_spaces(args + word_len);
    if (*rest != '\0') {
        if (parse_number(&rest, &port) != 0 || port == 0 || port >= 65536u) {
            uart_printf("usage: fwupdate lan [port] [data_port]\n");
            return;
        }
        rest = skip_spaces(rest);
        if (*rest != '\0') {
            if (parse_number(&rest, &data_port) != 0 || data_port == 0 || data_port >= 65536u) {
                uart_printf("usage: fwupdate lan [port] [data_port]\n");
                return;
            }
        }
    }

    ftpd_start((uint16_t)port, (uint16_t)data_port, NULL);
}

// `reboot`: PMウォッチドッグでボードをフルリセットする。
static void cmd_reboot(const char *args) {
    (void)args;
    pl011_puts(&debug_uart, "rebooting...\n");

    mmio_write32(PM_WDOG, PM_PASSWORD | PM_RESET_TIMEOUT);

    uint32_t rstc = mmio_read32(PM_RSTC);
    rstc &= ~PM_RSTC_WRCFG_MASK;
    rstc |= PM_PASSWORD | PM_RSTC_WRCFG_FULL_RESET;
    mmio_write32(PM_RSTC, rstc);

    while (1) {
        __asm__ volatile("wfe");
    }
}

// `pcie`: PCIeリンクを立ち上げ、RP1のvendor/device IDを表示する。
static void cmd_pcie(const char *args) {
    (void)args;
    if (pcie_rc_init() != 0) {
        pl011_puts(&debug_uart, "pcie: bring-up failed (see log above)\n");
        return;
    }
    uint32_t id = pcie_cfg_read32(1, 0, 0x00);
    pl011_puts(&debug_uart, "RP1 config[0x00] (device:vendor) = 0x");
    pl011_hex32(&debug_uart, id);
    pl011_puts(&debug_uart, "\n");
}

// `pcie1`: PCIe1(SoC直結の外部スロット、ConnectX)リンクを立ち上げ、
// Vendor/Device IDを表示した上でBAR0をプローブ・割り当てする。
static void cmd_pcie1(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }
    if (cmd_name_eq(args, len, "reset")) {
        // job.hのジョブテーブルは.bssにあり、この後のPERST#(pcie1_reset_
        // link())やnet init mlx5では消えない。ConnectXに紐づくRoCEv2
        // ジョブ(nvmetrdmastartの常駐target/IOキュー/CM listener、万一
        // 残っているループバックのinitiator/target/CM)が宙に浮いたまま
        // 残ると、再度nvmetrdmastartを実行した際に重複する/`job stop`でも
        // 消せない(2026-08-13/14ユーザー報告)。ハードウェアをリセットする
        // 前に、全RoCEv2系ジョブへ停止要求を出し、除去され切るまで
        // スケジューラを回す(core1にpinされたジョブはcore1のidleループが
        // 処理する)。cancelを毎tick再発行するのは、停止処理中に稀に生成
        // される後続のCM/IOジョブ(nvmetr_reset_admin_for_reconnect()等)も
        // 確実に畳むため。1.5秒はcore1が毎秒数百万tick回す前提で十分な上限
        // (実際は最初の数ミリ秒で除去され切る)。
        {
            uint64_t drain_start = timer_now();
            do {
                nvmet_rdma_stop_all();
                nvmet_stop_connectx_instances();  // ConnectXにbindしたNVMe/TCP nvmetも畳む
                job_scheduler_tick();
            } while (!timeout_ms(drain_start, 1500u));
        }
        // PCIe1のPERST#サイクルだけを行い、ConnectX側の残存FW状態をクリア
        // する(pcie1.hのpcie1_reset_link()コメント参照) -- 電源再投入や
        // `reboot`(RP1/Ethernet等の無関係な状態まで巻き込む)を経由せずに
        // 済む。ConnectX自身のconfig space(BAR0等)はリセットで電源オン
        // デフォルトへ戻るため、この後は`mlx5`を実行すること(内部で
        // pcie1_rc_init()+BAR0再割り当てを毎回行う設計)。
        if (pcie1_reset_link() != 0) {
            pl011_puts(&debug_uart, "pcie1: reset failed (see log above)\n");
            return;
        }
        pl011_puts(&debug_uart, "pcie1: reset complete (RoCEv2 jobs + mlx5-bound TCP nvmet stopped), run `mlx5` (one-shot test) or `net init mlx5` (for tcploopbench/nvme) to reinitialize ConnectX -- pick ONE, not both\n");
        return;
    }

    if (pcie1_rc_init() != 0) {
        pl011_puts(&debug_uart, "pcie1: bring-up failed (see log above)\n");
        return;
    }
    uint32_t id = pcie1_cfg_read32(1, 0, 0x00);
    pl011_puts(&debug_uart, "ConnectX config[0x00] (device:vendor) = 0x");
    pl011_hex32(&debug_uart, id);
    pl011_puts(&debug_uart, "\n");

    uint64_t bar_size = 0;
    int is64 = 0;
    if (pcie1_assign_bar0(&bar_size, &is64) != 0) {
        pl011_puts(&debug_uart, "pcie1: BAR0 assignment failed (see log above)\n");
        return;
    }
    pl011_puts(&debug_uart, "pcie1: BAR0 ready at PCI addr 0x0, size=0x");
    pl011_hex32(&debug_uart, (uint32_t)bar_size);
    pl011_puts(&debug_uart, is64 ? " (64bit)\n" : " (32bit)\n");
}

// `mlx5`: PCIe1立ち上げ、PF0(devfn=0)/PF1(devfn=1)双方のBAR0割り当て・
// HCA初期化・クロスポートループバック送受信テストまでを一貫して行う
// (mlx5.hのmlx5_dual_port_bringup_and_test()参照 -- このConnectXは
// マルチファンクションデバイスで物理ポートごとに別々のPCI関数を持つと
// 判明したため、CLAUDE.md「ConnectXデュアルポート対応」節参照)。
static void cmd_mlx5(const char *args) {
    (void)args;
    mlx5_dual_port_bringup_and_test();
}

// `mlx5stat`: 直近の`mlx5`ブリングアップで初期化済みのPF0/PF1に対し、
// PPCNT(physical port統計カウンタ)・QUERY_RQ/QUERY_SQ/QUERY_CQ(HW内部
// 状態)を再クエリして表示するだけ(mlx5.hのmlx5_monitor_dump_saved()
// 参照)。ENABLE_HCA等の非冪等なコマンド列は一切実行しないため、`mlx5`を
// 一度実行した後は何度でも安全に呼べる -- ケーブル抜き差し等の手動操作の
// 前後でカウンタの変化を見る用途を想定。
static void cmd_mlx5stat(const char *args) {
    (void)args;
    mlx5_monitor_dump_saved();
}

// mlx5_pcie_decode_cfg() 用の config space 読み関数(rpi5=pcie1)。
// ConnectXは bus1、ctx=devfn(0=PF0/1=PF1)。
static uint32_t mlx5hw_cfg_rd(void *ctx, uint32_t off) {
    return pcie1_cfg_read32(1, (uint8_t)(uintptr_t)ctx, (uint16_t)off);
}

// `mlx5hw`: ConnectXのHWモニタ。温度/FW health(synd等)/PCIe HWエラー
// (MPCNT: crc_error_dllp/tlp, rx/tx_errors, L0->recovery)/リンク層エラー
// (PPCNT)を BAR0/ACCESS_REG 経由で、PCIeリンク速度・幅・MPS・MRRS を
// config space 経由で表示する。直近の`mlx5`/`net init mlx5`ブリングアップの
// PF0/PF1を対象にする(mlx5statと同じく非冪等コマンドは一切実行しない)。
static void cmd_mlx5hw(const char *args) {
    (void)args;
    mlx5_dev_t *d0 = mlx5_monitor_saved_dev(0);
    mlx5_dev_t *d1 = mlx5_monitor_saved_dev(1);
    if (!d0 || !d1) {
        uart_printf("mlx5hw: PF未初期化(先に `mlx5` または `net init mlx5` を実行)\n");
        return;
    }
    mlx5_monitor_summary3(d0, d1, mlx5hw_cfg_rd, (void *)(uintptr_t)0, (void *)(uintptr_t)1);
}

static void cmd_mlx5netdump(const char *args) {
    args = skip_spaces(args);
    uint64_t pf;
    if (parse_number(&args, &pf) != 0 || (pf != 0 && pf != 1)) {
        uart_printf("usage: mlx5netdump <0|1>\n");
        return;
    }
    mlx5_net_dump_sq_debug((int)pf);
}

// `mlx5roce`: ConnectX RoCEv2 NVMe-oF実装計画フェーズ(a)の診断コマンド。
// mlx5_roce_probe()参照 -- cap確認・GID構築・SET/QUERY_ROCE_ADDRESS読返し
// 一致確認までを一発で行う。
static void cmd_mlx5roce(const char *args) {
    args = skip_spaces(args);
    uint64_t pf;
    if (parse_number(&args, &pf) != 0 || (pf != 0 && pf != 1)) {
        uart_printf("usage: mlx5roce <0|1>\n");
        return;
    }
    mlx5_roce_probe((int)pf);
}

// `mlx5qp`: ConnectX RoCEv2 NVMe-oF実装計画フェーズ(b)の診断コマンド。
// mlx5_qp_cmd_create()/mlx5_qp_cmd_query()/mlx5_qp_cmd_pingpong()参照。
static void cmd_mlx5qp(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }
    if (cmd_name_eq(args, len, "pingpong")) {
        mlx5_qp_cmd_pingpong();
        return;
    }
    if (cmd_name_eq(args, len, "rdma")) {
        mlx5_qp_cmd_rdma();
        return;
    }
    if (cmd_name_eq(args, len, "create") || cmd_name_eq(args, len, "query") || cmd_name_eq(args, len, "loop")) {
        int is_create = cmd_name_eq(args, len, "create");
        int is_loop = cmd_name_eq(args, len, "loop");
        const char *rest = args + len;
        rest = skip_spaces(rest);
        uint64_t pf;
        if (parse_number(&rest, &pf) != 0 || (pf != 0 && pf != 1)) {
            uart_printf("usage: mlx5qp create|query|loop <0|1>\n");
            return;
        }
        if (is_create) {
            mlx5_qp_cmd_create((int)pf);
        } else if (is_loop) {
            mlx5_qp_cmd_loop((int)pf);
        } else {
            mlx5_qp_cmd_query((int)pf);
        }
        return;
    }
    uart_printf("usage: mlx5qp create|query|loop <0|1> | mlx5qp pingpong | mlx5qp rdma\n");
}

// `mlx5mad`: ConnectX RoCEv2 NVMe-oF実装計画フェーズ(d)の診断コマンド。
// mlx5_gsi_cmd_probe()/mlx5_gsi_cmd_test()参照。
static void cmd_mlx5mad(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }
    if (cmd_name_eq(args, len, "probe")) {
        const char *rest = skip_spaces(args + len);
        uint64_t pf;
        if (parse_number(&rest, &pf) != 0 || (pf != 0 && pf != 1)) {
            uart_printf("usage: mlx5mad probe <0|1> <ud|gsi>\n");
            return;
        }
        rest = skip_spaces(rest);
        unsigned tlen = 0;
        while (rest[tlen] != '\0' && rest[tlen] != ' ') {
            tlen++;
        }
        int is_gsi;
        if (cmd_name_eq(rest, tlen, "ud")) {
            is_gsi = 0;
        } else if (cmd_name_eq(rest, tlen, "gsi")) {
            is_gsi = 1;
        } else {
            uart_printf("usage: mlx5mad probe <0|1> <ud|gsi>\n");
            return;
        }
        mlx5_gsi_cmd_probe((int)pf, is_gsi);
        return;
    }
    if (cmd_name_eq(args, len, "test")) {
        const char *rest = skip_spaces(args + len);
        unsigned tlen = 0;
        while (rest[tlen] != '\0' && rest[tlen] != ' ') {
            tlen++;
        }
        int is_gsi;
        if (cmd_name_eq(rest, tlen, "ud")) {
            is_gsi = 0;
        } else if (cmd_name_eq(rest, tlen, "gsi")) {
            is_gsi = 1;
        } else {
            uart_printf("usage: mlx5mad test <ud|gsi>\n");
            return;
        }
        mlx5_gsi_cmd_test(is_gsi);
        return;
    }
    uart_printf("usage: mlx5mad probe <0|1> <ud|gsi> | mlx5mad test <ud|gsi>\n");
}

// `mlx5rdmacm`: ConnectX RoCEv2 NVMe-oF実装計画フェーズ(e)の診断コマンド。
// mlx5_rdma_cm_cmd_test()参照。
static void cmd_mlx5rdmacm(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }
    if (cmd_name_eq(args, len, "test")) {
        mlx5_rdma_cm_cmd_test();
        return;
    }
    uart_printf("usage: mlx5rdmacm test\n");
}

// `mlx5rdmaconnect`: ConnectX RoCEv2 NVMe-oF実装計画フェーズ(f)の診断
// コマンド。mlx5_rdma_cm_cmd_connect()参照。引数無し(mlx5mad/mlx5rdmacm
// と異なりサブコマンドを持たない、計画の完了条件通り一発コマンド)。
static void cmd_mlx5rdmaconnect(const char *args) {
    (void)args;
    mlx5_rdma_cm_cmd_connect();
}

// `nvmerdmaconnect`: ConnectX RoCEv2 NVMe-oF実装計画フェーズ(g)の診断
// コマンド。mlx5_nvme_rdma_cmd_connect()参照。引数無し(mlx5rdmaconnectと
// 同じく計画の完了条件通り一発コマンド)。
static void cmd_nvmerdmaconnect(const char *args) {
    (void)args;
    mlx5_nvme_rdma_cmd_connect();
}

// "xx:xx:xx:xx:xx:xx"形式(16進数2桁×6、コロン区切り)のMACアドレスを
// パースする(nvmetrdmastartの[peer_mac]引数専用、他に同種のパーサーが
// このプロジェクトに無いためここで実装)。
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int parse_mac(const char *s, uint8_t out[6]) {
    for (int i = 0; i < 6; i++) {
        int hi = hex_nibble(s[0]);
        int lo = (hi >= 0) ? hex_nibble(s[1]) : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
        s += 2;
        if (i < 5) {
            if (*s != ':') return -1;
            s++;
        }
    }
    return (*s == '\0' || *s == ' ') ? 0 : -1;
}

// `nvmetrdmastart <0|1> [peer_mac]`: ConnectX RoCEv2 NVMe-oF実装計画
// フェーズ(i)。mlx5_nvmet_rdma_cmd_start()参照 -- 指定PFで常駐targetを
// 起動し、実Linuxホストからの`nvme connect -t rdma`を待ち受ける。
// peer_mac("xx:xx:xx:xx:xx:xx")は省略可 -- IBTA CMメッセージにはMACが
// 含まれないため(nvmet_rdma.hコメント参照)、実ホストと接続する場合は
// 相手の実MAC(`ip link show <iface>`で確認できる)を指定する必要がある。
static void cmd_nvmetrdmastart(const char *args) {
    args = skip_spaces(args);
    uint64_t pf;
    if (parse_number(&args, &pf) != 0 || (pf != 0 && pf != 1)) {
        uart_printf("usage: nvmetrdmastart <0|1> [peer_mac xx:xx:xx:xx:xx:xx]\n");
        return;
    }
    args = skip_spaces(args);
    uint8_t mac[6];
    const uint8_t *mac_ptr = NULL;
    if (*args != '\0') {
        if (parse_mac(args, mac) != 0) {
            uart_printf("usage: nvmetrdmastart <0|1> [peer_mac xx:xx:xx:xx:xx:xx]\n");
            return;
        }
        mac_ptr = mac;
    }
    mlx5_nvmet_rdma_cmd_start((int)pf, mac_ptr);
}

// `nvmetrdmastat`: nvmet_rdma_run_standalone_dump()参照。
static void cmd_nvmetrdmastat(const char *args) {
    (void)args;
    nvmet_rdma_run_standalone_dump();
}

// `mlx5fteskip <0|1>`: TEMP EXPERIMENT、g_mlx5_skip_fte_experiment参照。
static void cmd_mlx5fteskip(const char *args) {
    args = skip_spaces(args);
    uint64_t v;
    if (parse_number(&args, &v) != 0 || (v != 0 && v != 1)) {
        uart_printf("usage: mlx5fteskip <0|1>\n");
        return;
    }
    g_mlx5_skip_fte_experiment = (int)v;
    uart_printf("mlx5fteskip: g_mlx5_skip_fte_experiment=%d (takes effect on next `mlx5`/`net init mlx5`)\n",
                g_mlx5_skip_fte_experiment);
}

// `nvmermabench <duration_ms> <read|write> [chunk_bytes] [qdepth]`:
// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(h)のベンチマークコマンド。
// mlx5_nvme_rdma_cmd_bench()参照。qdepth(2026-08-12追加)は省略時1
// (単一コマンド逐次発行)、2以上でコマンドパイプライン化する。
static void cmd_nvmermabench(const char *args) {
    args = skip_spaces(args);
    uint64_t duration_ms = 0;
    if (parse_number(&args, &duration_ms) != 0 || duration_ms == 0) {
        uart_printf("usage: nvmermabench <duration_ms> <read|write> [chunk_bytes] [qdepth]\n");
        return;
    }
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }
    int is_read;
    if (cmd_name_eq(args, len, "read")) {
        is_read = 1;
    } else if (cmd_name_eq(args, len, "write")) {
        is_read = 0;
    } else {
        uart_printf("usage: nvmermabench <duration_ms> <read|write> [chunk_bytes] [qdepth]\n");
        return;
    }
    const char *rest = skip_spaces(args + len);
    uint64_t chunk_bytes = 0;
    if (*rest != '\0') {
        if (parse_number(&rest, &chunk_bytes) != 0) {
            uart_printf("usage: nvmermabench <duration_ms> <read|write> [chunk_bytes] [qdepth]\n");
            return;
        }
    }
    rest = skip_spaces(rest);
    uint64_t qdepth = 1;
    if (*rest != '\0') {
        if (parse_number(&rest, &qdepth) != 0) {
            uart_printf("usage: nvmermabench <duration_ms> <read|write> [chunk_bytes] [qdepth]\n");
            return;
        }
    }
    mlx5_nvme_rdma_cmd_bench((uint32_t)duration_ms, is_read, (uint32_t)chunk_bytes, (uint32_t)qdepth);
}

// `mlx5txlat`: 診断専用(2026-08-11、原因特定後に削除すること)。
// mlx5_net_measure_bf_latency()参照 -- BlueFlameドアベル往復の純粋な
// レイテンシを、他のソフトウェア処理を挟まずに直接計測する。
static void cmd_mlx5txlat(const char *args) {
    args = skip_spaces(args);
    uint64_t pf;
    if (parse_number(&args, &pf) != 0 || (pf != 0 && pf != 1)) {
        uart_printf("usage: mlx5txlat <0|1> [iterations]  (default iterations=200)\n");
        return;
    }
    uint64_t iterations = 200;
    args = skip_spaces(args);
    if (*args != '\0') {
        parse_number(&args, &iterations);
    }
    if (iterations == 0 || iterations > 100000) {
        uart_printf("usage: mlx5txlat <0|1> [iterations]  (1-100000, default 200)\n");
        return;
    }
    mlx5_net_measure_bf_latency((int)pf, (unsigned)iterations);
}

// `fan`: PCIeリンクを立ち上げ、ケースファンを指定duty(省略時100)で駆動する。
static void cmd_fan(const char *args) {
    uint64_t duty = 100;
    args = skip_spaces(args);
    if (*args != '\0' && parse_number(&args, &duty) != 0) {
        pl011_puts(&debug_uart, "usage: fan [duty]  (0-100, default 100)\n");
        return;
    }

    if (pcie_rc_init() != 0) {
        pl011_puts(&debug_uart, "fan: PCIe bring-up failed (see log above)\n");
        return;
    }
    fan_set_speed((uint32_t)duty);
}

// `mw`: 指定アドレスに32ビット値を書き込む。
static void cmd_mw(const char *args) {
    uint64_t addr, val;
    if (parse_number(&args, &addr) != 0) {
        pl011_puts(&debug_uart, "usage: mw <addr> <val>  (0x prefix = hex, otherwise decimal)\n");
        return;
    }
    args = skip_spaces(args);
    if (parse_number(&args, &val) != 0) {
        pl011_puts(&debug_uart, "usage: mw <addr> <val>  (0x prefix = hex, otherwise decimal)\n");
        return;
    }

    mmio_write32(addr, (uint32_t)val);

    pl011_puts(&debug_uart, "wrote 0x");
    pl011_hex32(&debug_uart, (uint32_t)val);
    pl011_puts(&debug_uart, " to 0x");
    pl011_hex64(&debug_uart, addr);
    pl011_puts(&debug_uart, "\n");
}

// `md`: 指定アドレスから32ビットワードをダンプする。
static void cmd_md(const char *args) {
    uint64_t addr;
    if (parse_number(&args, &addr) != 0) {
        pl011_puts(&debug_uart, "usage: md <addr> [count]  (0x prefix = hex, otherwise decimal)\n");
        return;
    }
    uint64_t count = 1;
    args = skip_spaces(args);
    if (*args != '\0' && parse_number(&args, &count) != 0) {
        pl011_puts(&debug_uart, "usage: md <addr> [count]  (0x prefix = hex, otherwise decimal)\n");
        return;
    }
    if (count == 0) {
        count = 1;
    }

    hexdump32(addr, count, "0x");
}

// `rp1`: PCIeリンクを立ち上げ、RP1ベースからのオフセットをダンプする。
static void cmd_rp1(const char *args) {
    uint64_t offset;
    if (parse_number(&args, &offset) != 0) {
        pl011_puts(&debug_uart, "usage: rp1 <offset> [count]  (offset from RP1 base; 0x prefix = hex, otherwise decimal)\n");
        return;
    }
    uint64_t count = 1;
    args = skip_spaces(args);
    if (*args != '\0' && parse_number(&args, &count) != 0) {
        pl011_puts(&debug_uart, "usage: rp1 <offset> [count]  (offset from RP1 base; 0x prefix = hex, otherwise decimal)\n");
        return;
    }
    if (count == 0) {
        count = 1;
    }

    if (pcie_rc_init() != 0) {
        pl011_puts(&debug_uart, "rp1: PCIe bring-up failed (see log above)\n");
        return;
    }

    hexdump32(PCIE_OUTBOUND_CPU_BASE + offset, count, "rp1+0x");
}

// `pcicfg`: PCIeリンクを立ち上げ、コンフィグ空間全体をダンプする。
static void cmd_pcicfg(const char *args) {
    uint64_t bus, devfn;
    if (parse_number(&args, &bus) != 0) {
        pl011_puts(&debug_uart, "usage: pcicfg <bus> <devfn>  (0x prefix = hex, otherwise decimal)\n");
        return;
    }
    args = skip_spaces(args);
    if (parse_number(&args, &devfn) != 0) {
        pl011_puts(&debug_uart, "usage: pcicfg <bus> <devfn>  (0x prefix = hex, otherwise decimal)\n");
        return;
    }

    if (pcie_rc_init() != 0) {
        pl011_puts(&debug_uart, "pcicfg: PCIe bring-up failed (see log above)\n");
        return;
    }

    pci_dump_config((uint8_t)bus, (uint8_t)devfn, pcie_cfg_read32);
}

// `pcicfg1`: PCIe1(ConnectXスロット)のコンフィグ空間をダンプする。
// pcie1_rc_init()がリンクトレーニング失敗で-1を返しても続行する -- bus 0
// devfn 0(ルートポート自身)へのconfigアクセスはPCIE1_RC_BASEへの直接MMIO
// 読み出しであり、リンク確立状態に依存しない(pcie1_cfg_read32()のbus==0分岐
// 参照)。リンクが上がらない原因調査では、この「上がらないなりの」ルート
// ポート自身のレジスタ状態(Link Capabilities/Status等)を見ること自体に意味
// があるため、他コマンド(pcie1/rp1等)のように早期returnはしない。
static void cmd_pcicfg1(const char *args) {
    uint64_t bus, devfn;
    if (parse_number(&args, &bus) != 0) {
        pl011_puts(&debug_uart, "usage: pcicfg1 <bus> <devfn>  (0x prefix = hex, otherwise decimal)\n");
        return;
    }
    args = skip_spaces(args);
    if (parse_number(&args, &devfn) != 0) {
        pl011_puts(&debug_uart, "usage: pcicfg1 <bus> <devfn>  (0x prefix = hex, otherwise decimal)\n");
        return;
    }

    if (pcie1_rc_init() != 0) {
        pl011_puts(&debug_uart, "pcicfg1: PCIe1 bring-up failed (see log above) -- dumping raw config space anyway for diagnostics\n");
    }

    pci_dump_config((uint8_t)bus, (uint8_t)devfn, pcie1_cfg_read32);
}

// `net init`: Ethernetを初期化し、ARP/IPv4ハンドラを登録してMACアドレスを表示する。
// ハンドラ登録(eth_register_handler)はeth_init()内では行わず、ここ(arp_init()/
// ip_init()経由)で行う -- eth_init()はEthernetそのものの初期化に専念させ、
// どのEtherTypeにどのハンドラを結びつけるかは上位(シェルコマンド)の判断にする。
//
// `net init mlx5`: RP1の代わりにConnectX(mlx5) PF0/PF1をブリングアップし、
// 両方をnet_ctx_t(netctx.h)として登録する(mlx5_net_init_dual_loopback()、
// 現状はPF0<->PF1のループバックケーブル配線でのARP/ICMP動作確認用、
// CLAUDE.md「TCP/IPスタックのConnectX統合」節参照)。arp_init()/ip_init()
// によるEtherTypeハンドラ登録はRP1経路と共有(グローバルなハンドラ
// テーブル、eth.cのg_handlers参照 -- ハンドラ関数自体はどのコンテキストが
// アクティブかに依らず正しく動作するため、バックエンドごとに登録し直す
// 必要は無い)。
static void net_init(const char *rest) {
    rest = skip_spaces(rest);
    unsigned len = 0;
    while (rest[len] != '\0' && rest[len] != ' ') {
        len++;
    }

    if (len != 0 && !cmd_name_eq(rest, len, "mlx5")) {
        uart_printf("usage: net init [mlx5]\n");
        return;
    }

    if (len != 0) {
        if (mlx5_net_init_dual_loopback() != 0) {
            uart_printf("net init mlx5: bring-up失敗(上記ログ参照)\n");
            return;
        }
    } else {
        eth_init();
    }

    arp_init();  // EtherType 0x0806(ARP)  -> arp_handle_frame
    ip_init();   // EtherType 0x0800(IPv4) -> ip_handle_frame

    uint8_t mac[ETH_ALEN];
    eth_get_mac(mac);
    uart_printf("net: アクティブなインターフェース=%s MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
                g_active_ctx ? g_active_ctx->name : "(none)",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// `net use <name>`: 登録済みインターフェース(net_ctx_t、netctx.h)を
// name(net_ctx_t.name、例"rp1"/"mlx5-pf0"/"mlx5-pf1")で切り替える。
// 以降のarp/ping/net poll等は、切り替え先のMAC/IP/ARPキャッシュ/送受信
// バックエンドを使う。
static void net_use(const char *rest) {
    rest = skip_spaces(rest);
    unsigned len = 0;
    while (rest[len] != '\0' && rest[len] != ' ') {
        len++;
    }
    if (len == 0) {
        uart_printf("usage: net use <name>  (例: rp1, mlx5-pf0, mlx5-pf1)\n");
        return;
    }

    char namebuf[16];
    if (len >= sizeof(namebuf)) len = sizeof(namebuf) - 1;
    for (unsigned i = 0; i < len; i++) namebuf[i] = rest[i];
    namebuf[len] = '\0';

    net_ctx_t *ctx = net_ctx_find(namebuf);
    if (!ctx) {
        uart_printf("net use: 未知のインターフェース '%s'\n", namebuf);
        return;
    }
    net_ctx_activate(ctx);
    uart_printf("net use: アクティブなインターフェース = %s\n", ctx->name);
}

// `net poll`: RXを1回だけポーリングし、フレームがあればヘッダ情報をログ出力して解放する。
static void net_poll(void) {
    net_buf_t *nb = eth_poll_recv();
    if (!nb) {
        uart_printf("net poll: no frame received\n");
        return;
    }

    const uint8_t *dst_mac = &nb->data[0];
    const uint8_t *src_mac = &nb->data[6];
    uint16_t ethertype = (uint16_t)((nb->data[12] << 8) | nb->data[13]);

    uart_printf("net poll: ethertype=0x%04x src=%02x:%02x:%02x:%02x:%02x:%02x "
                "dst=%02x:%02x:%02x:%02x:%02x:%02x len=%u\n",
                ethertype,
                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
                dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                (unsigned)nb->len);

    net_buf_free(nb);
}

// `net`: init/pollサブコマンドをディスパッチする。
static void cmd_net(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }

    if (cmd_name_eq(args, len, "init")) {
        net_init(args + len);
    } else if (cmd_name_eq(args, len, "poll")) {
        net_poll();
    } else if (cmd_name_eq(args, len, "use")) {
        net_use(args + len);
    } else {
        uart_printf("usage: net init [mlx5] | net poll | net use <name>\n");
    }
}

// `arp who <IP>`: 指定IPv4アドレスへARP requestを送信し、応答を待つ。
static void cmd_arp(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }

    if (!cmd_name_eq(args, len, "who")) {
        uart_printf("usage: arp who <IP>\n");
        return;
    }

    const char *ip_str = skip_spaces(args + len);
    uint8_t ip[4];
    if (parse_ip(&ip_str, ip) != 0) {
        uart_printf("usage: arp who <IP>\n");
        return;
    }

    uint32_t target = ip_from_octets(ip[0], ip[1], ip[2], ip[3]);
    uint8_t mac[ETH_ALEN];
    if (arp_resolve(target, mac) == 0) {
        uart_printf("ARP reply: %u.%u.%u.%u is-at %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ip[0], ip[1], ip[2], ip[3],
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        uart_printf("timeout\n");
    }
}

#define PING_IDENT       0x0001u
#define PING_REPLY_TIMEOUT_MS 1000u

// `ping <IP>`: 指定IPv4アドレスへICMP Echo Requestを送信し、応答を待つ。
// `ping`のジョブ化(job.h、CLAUDE.md「NVMe/TCP制御のステートマシン化」
// 節参照) -- 基盤(job_spawn()/job_scheduler_tick())の実地検証を、
// nvmet.c/nvme.cに触れずに行うための最初の変換対象。Echo Reply待ちを
// icmp_wait_echo_reply()(ブロッキング)ではなくicmp_echo_reply_ready()
// (非ブロッキング、1回確認するだけ)で行い、実際の受信ポーリングは
// メインループ(command_shell_run())が毎tick呼ぶnet_poll_all_and_
// dispatch()に任せる。
//
// 同時に1本のpingジョブしか許可しない(s_ping_job_in_flight)。ジョブの
// コンテキスト(s_ping_job_ctx)はstatic単一インスタンスのため、2本目を
// 許可すると1本目が上書きされて壊れる(mallocの無い環境でジョブごとに
// 動的確保できないための単純化 -- 複数本を同時に扱うにはコンテキストの
// プールが必要になる、将来nvmet.c/nvme.c変換時にadmin/IO queue等
// 複数ジョブを同時に持つ場合はこのパターンを拡張すること)。
typedef struct {
    uint8_t  ip[4];
    uint16_t ident;
    uint16_t seq;
    uint64_t sent_at;
} ping_job_ctx_t;

static ping_job_ctx_t s_ping_job_ctx;
static int            s_ping_job_in_flight = 0;

static job_result_t ping_job_step(job_t *self) {
    ping_job_ctx_t *pc = (ping_job_ctx_t *)self->ctx;

    if (icmp_echo_reply_ready(pc->ident, pc->seq)) {
        /* timer_now()をここで取り直すと、icmp_handle()内の受信ログ
         * (uart_printf、115200bpsで数ms)がRTTに混入してしまう。
         * g_icmp_echo_reply_time(icmp.c、ログ出力より前に記録)を使う
         * (timer_now()から独立した2つの採取済みtick値の差なので、
         * get_us_from()ではなくticks_to_us()を使う)。 */
        uint64_t elapsed_us = ticks_to_us(g_icmp_echo_reply_time[smp_core_index()] - pc->sent_at);
        uart_printf("reply from %u.%u.%u.%u: seq=%u time=%u.%03ums\n",
                    pc->ip[0], pc->ip[1], pc->ip[2], pc->ip[3], pc->seq,
                    (unsigned)(elapsed_us / 1000u), (unsigned)(elapsed_us % 1000u));
        s_ping_job_in_flight = 0;
        return JOB_DONE;
    }
    if (timeout_ms(pc->sent_at, PING_REPLY_TIMEOUT_MS)) {
        uart_printf("timeout\n");
        s_ping_job_in_flight = 0;
        return JOB_DONE;
    }
    return JOB_WAITING;
}

static void cmd_ping(const char *args) {
    args = skip_spaces(args);
    uint8_t ip[4];
    if (parse_ip(&args, ip) != 0) {
        uart_printf("usage: ping <IP>\n");
        return;
    }
    if (s_ping_job_in_flight) {
        uart_printf("[!] ping: 前回のpingがまだ応答待ちです(同時に1本まで)\n");
        return;
    }

    static uint16_t s_ping_seq = 0;
    uint16_t seq = s_ping_seq++;

    /* ARP解決(icmp_send_echo_request()が未キャッシュ時に内部で呼ぶ
     * arp_resolve())自体はこのフェーズの変換対象外のため、ここは従来
     * 通りブロッキングしうる(最大約900ms、arp.cのARP_RESOLVE_*参照)。
     * Echo Reply自体の待ち(こちらの方が時間が読めない)だけをジョブ化
     * する。 */
    uint64_t sent_at = timer_now();
    if (icmp_send_echo_request(ip, PING_IDENT, seq) != 0) {
        return;
    }

    s_ping_job_ctx.ip[0] = ip[0]; s_ping_job_ctx.ip[1] = ip[1];
    s_ping_job_ctx.ip[2] = ip[2]; s_ping_job_ctx.ip[3] = ip[3];
    s_ping_job_ctx.ident = PING_IDENT;
    s_ping_job_ctx.seq   = seq;
    s_ping_job_ctx.sent_at = sent_at;

    if (!job_spawn(ping_job_step, &s_ping_job_ctx, "ping")) {
        uart_printf("[!] ping: ジョブテーブル満杯\n");
        return;
    }
    s_ping_job_in_flight = 1;
}

// `jobs`: job.hのスケジューラに登録されている全ジョブを表示する
// (診断用 -- 例えば`ping`実行直後にこれを打つと"ping"ジョブが
// state=0(応答待ち)のまま表示され、シェルがブロッキングしていない
// ことを確認できる)。
static void cmd_jobs(const char *args) {
    (void)args;
    job_list_dump();
}

/* rxoff <0|1> : push受信の唯一のコピー(RQ→ram_disk)を core1 へオフロード
 * する(1=有効、core1起動含む)。core0は受信/ACK専任になり、コピーが
 * ワイヤ待ちの裏に隠れる(rxcopy.h)。次の接続からではなく即時に効く
 * (upcall内で毎回rxcopy_enabled()を見る)。A/B検証用。 */
static void cmd_rxoff(const char *args) {
    args = skip_spaces(args);
    if (args[0] == '1') {
        rxcopy_set_enabled(1);
    } else if (args[0] == '0') {
        rxcopy_set_enabled(0);
    } else {
        uart_printf("rxoff: 現在 %s。usage: rxoff <0|1>\n",
                    rxcopy_enabled() ? "オフロード有効(core1)" : "無効(core0同期)");
    }
}

/* nvmetpull <0|1> : 非digest接続でも強制的にpull型RX(二重コピー)に
 * するトグル。push(既定)との同一トラフィックA/B比較用(検証後に撤去)。
 * 次の接続から反映される。コピー時間の計測は`ts mask 0xff000000 0x04000000`(nvmet.c)
 * (push=0x40、pull=0x41)で行う。 */
static void cmd_nvmetpull(const char *args) {
    args = skip_spaces(args);
    if (args[0] == '1') {
        nvmet_set_force_pull(1);
        uart_printf("nvmetpull: 非digest接続もPULL型に強制(次の接続から)。ts DBGT 0x41で計測\n");
    } else if (args[0] == '0') {
        nvmet_set_force_pull(0);
        uart_printf("nvmetpull: 非digest接続はpush型(既定、次の接続から)。ts DBGT 0x40で計測\n");
    } else {
        uart_printf("nvmetpull: 現在 %s。usage: nvmetpull <0|1>\n",
                    nvmet_get_force_pull() ? "PULL強制" : "push(既定)");
    }
}


// `job stop <番号>`: `jobs`が表示する`[N]`の番号を指定してジョブへ停止を
// 要求する(job.hのjob_request_cancel())。実際にいつ止まるかはジョブの
// 種類次第 -- telnetは即座に、nvmetのadmin/ioジョブはインスタンスが
// 誰も接続していない待受中に戻ったタイミングで安全に停止する
// (nvmet_admin_job_step()/nvmet_io_job_step()参照)。全てのジョブ種別が
// 対応しているわけではない(ping等の一時的なジョブは自然に完了するため
// 未対応 -- その場合は黙って無視される)。
static void cmd_job(const char *args) {
    args = skip_spaces(args);
    unsigned word_len = 0;
    while (args[word_len] != '\0' && args[word_len] != ' ') word_len++;

    if (!cmd_name_eq(args, word_len, "stop")) {
        uart_printf("usage: job stop <番号>  (番号は`jobs`が表示する[N])\n");
        return;
    }

    const char *num_arg = skip_spaces(args + word_len);
    uint64_t index;
    if (parse_number(&num_arg, &index) != 0) {
        uart_printf("usage: job stop <番号>  (番号は`jobs`が表示する[N])\n");
        return;
    }

    if (job_request_cancel((unsigned)index) != 0) {
        uart_printf("[!] job stop: 番号%uのジョブは稼働していません(`jobs`で確認)\n", (unsigned)index);
        return;
    }
    uart_printf("job stop: 番号%uへ停止要求を送りました\n", (unsigned)index);
}

// `platform_init`: 環境の共通初期化(ファン起動、RP1のnet init+nvmet
// 常駐サーバ、ConnectXが接続されていればPF0/PF1双方のnvmet常駐サーバ)を
// 明示的に実行する。main()からは自動で呼ばない(platform_init.hコメント
// 参照 -- チェインロード直後は古いページテーブルが残っている可能性が
// あり、ConnectXブリングアップが自動実行されると実機でクラッシュする
// 障害を経験したため、このコマンドで明示的に呼び出す形にした)。
static void cmd_platform_init(const char *args) {
    (void)args;
    platform_init();
}

// `telnet [port]`: このシリアルコンソールと同じシェルセッションを
// TCP/telnet経由でも操作できるようにする(telnet.h参照 -- 新しい独立した
// シェルではなく、既存のs_editorへのもう1つの入出力口)。nvmetと同じ
// 常駐ジョブとして起動し、クライアント切断後も次の接続を待ち続ける。
// 停止は`job stop <番号>`(cmd_job()参照)で行う。
static void cmd_telnet(const char *args) {
    uint64_t port = 23u;
    args = skip_spaces(args);
    if (*args != '\0' && (parse_number(&args, &port) != 0 || port == 0 || port >= 65536u)) {
        uart_printf("usage: telnet [port]  (default 23; to stop, use `job stop <番号>` -- see `jobs`)\n");
        return;
    }
    telnet_server_start_instance(0, (uint16_t)port, NULL);
}

// `telnet2 [port]`: コア1向けの完全に独立したtelnetセッション(インスタンス
// 1、telnet.h参照)を起動する。物理UARTとは一切共有しない別々の入出力・
// IPアドレス(net.hのNET_RP1_CORE1_IP)・ポート(既定2323)を持つ。
static void cmd_telnet2(const char *args) {
    uint64_t port = 2323u;
    args = skip_spaces(args);
    if (*args != '\0' && (parse_number(&args, &port) != 0 || port == 0 || port >= 65536u)) {
        uart_printf("usage: telnet2 [port]  (default 2323; independent core1 session, see `jobs`/`job stop`)\n");
        return;
    }
    net_ctx_t *ctx = net_ctx_find("rp1-core1");
    telnet_server_start_instance(1, (uint16_t)port, ctx);
}

// `exit`/`quit`: PC側からtelnet接続だけを能動的に終える手段
// (telnet_request_exit()参照、telnet.h)。telnet/シリアルどちらから
// 打っても効果は「今操作している論理セッション(s_current_console)の
// telnetクライアントを切断する」-- インスタンス0(物理UART+telnet0共有
// セッション)から打てばインスタンス0の接続を、インスタンス1のtelnet
// クライアントから打てばインスタンス1自身の接続を切る。telnetクライアント
// 側で標準telnetクライアント(Windows付属telnet.exe等)を使っているなら、
// Ctrl+]でエスケープし`close`/`quit`を打つ方法もあるが、これはクライアント
// 機能でこちらの実装とは無関係 -- 生ソケット(pythonスクリプト等)で接続
// している場合はこのコマンドが唯一のPC側からの切断手段になる。
static void cmd_exit(const char *args) {
    (void)args;
    if (!telnet_request_exit(s_current_console)) {
        uart_printf("現在telnet接続はありません\n");
        return;
    }
    uart_printf("telnet接続を切断します\n");
}

// tcpコマンドのサブコマンドが操作する唯一のコネクション(並列接続不要)。
static tcp_conn_t s_tcp_conn;

// `tcp connect <IP> <port>`: 指定IPv4:portへ3-way handshakeを行う。
static void tcp_cmd_connect(const char *args) {
    uint8_t ip[4];
    if (parse_ip(&args, ip) != 0) {
        uart_printf("usage: tcp connect <IP> <port>\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t port;
    if (parse_number(&args, &port) != 0 || port > 0xFFFFu) {
        uart_printf("usage: tcp connect <IP> <port>\n");
        return;
    }

    uint32_t dst_ip = ip_from_octets(ip[0], ip[1], ip[2], ip[3]);
    if (tcp_connect(&s_tcp_conn, dst_ip, (uint16_t)port) == 0) {
        uart_printf("tcp: connected\n");
    } else {
        uart_printf("tcp: connect failed\n");
    }
}

// `tcp send <text>`: ESTABLISHED状態のコネクションへtextをそのまま送信する。
static void tcp_cmd_send(const char *args) {
    if (*args == '\0') {
        uart_printf("usage: tcp send <text>\n");
        return;
    }
    unsigned len = 0;
    while (args[len] != '\0') {
        len++;
    }

    int ret = tcp_send(&s_tcp_conn, args, (uint16_t)len);
    if (ret >= 0) {
        uart_printf("tcp: sent %d bytes\n", ret);
    } else {
        uart_printf("tcp: send failed\n");
    }
}

// `tcp recv [timeout_ms]`: データ受信(またはFINによるクローズ)を待つ(省略時1000ms)。
static void tcp_cmd_recv(const char *args) {
    /* timer.hのtimeout_ms()関数と名前が衝突するため、変数名は
     * timeout_val_msにしてある。 */
    uint64_t timeout_val_ms = 1000;
    args = skip_spaces(args);
    if (*args != '\0' && parse_number(&args, &timeout_val_ms) != 0) {
        uart_printf("usage: tcp recv [timeout_ms]\n");
        return;
    }

    static uint8_t buf[1460];
    int ret = tcp_recv(&s_tcp_conn, buf, sizeof(buf), (uint32_t)timeout_val_ms);
    if (ret > 0) {
        uart_printf("tcp: received %d bytes: ", ret);
        for (int i = 0; i < ret; i++) {
            uart_putc((char)buf[i]);
        }
        uart_printf("\n");
    } else if (ret == 0) {
        uart_printf("tcp: connection closed by peer\n");
    } else {
        uart_printf("tcp: recv timeout\n");
    }
}

// `tcp close`: FINを送りコネクションを閉じる。
static void tcp_cmd_close(const char *args) {
    (void)args;
    tcp_close(&s_tcp_conn);
    uart_printf("tcp: closed\n");
}

// `tcp`: connect/send/recv/closeサブコマンドをディスパッチする。
static void cmd_tcp(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }
    const char *sub_args = skip_spaces(args + len);

    if (cmd_name_eq(args, len, "connect")) {
        tcp_cmd_connect(sub_args);
    } else if (cmd_name_eq(args, len, "send")) {
        tcp_cmd_send(sub_args);
    } else if (cmd_name_eq(args, len, "recv")) {
        tcp_cmd_recv(sub_args);
    } else if (cmd_name_eq(args, len, "close")) {
        tcp_cmd_close(sub_args);
    } else {
        uart_printf("usage: tcp connect <IP> <port> | tcp send <text> | tcp recv [timeout_ms] | tcp close\n");
    }
}

// `tcptest <IP> <port> <bytes>`: connect+send+recv(echo)+closeを一括実行し、
// 送受信データの一致まで検証する(tcp_test_run()参照、対向にechoサーバが必要)。
static void cmd_tcptest(const char *args) {
    uint8_t ip[4];
    if (parse_ip(&args, ip) != 0) {
        uart_printf("usage: tcptest <IP> <port> <bytes>\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t port;
    if (parse_number(&args, &port) != 0 || port > 0xFFFFu) {
        uart_printf("usage: tcptest <IP> <port> <bytes>\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t len;
    if (parse_number(&args, &len) != 0 || len == 0 || len > 0xFFFFFFFFu) {
        uart_printf("usage: tcptest <IP> <port> <bytes>\n");
        return;
    }

    uint32_t dst_ip = ip_from_octets(ip[0], ip[1], ip[2], ip[3]);
    tcp_test_run(dst_ip, (uint16_t)port, (uint32_t)len);
}

// `tcplooptest <server_IP> <client_IP> <port> <bytes>`: 外部ピア不要の
// 自己完結TCPテスト(test.hのtcp_loopback_test()参照)。server_IP/
// client_IPは共に登録済みインターフェース(netctx.h)のIPである必要が
// ある(`net init mlx5`実行後のPF0=192.168.101.10/PF1=192.168.101.11等)。
static void cmd_tcplooptest(const char *args) {
    uint8_t server_ip_octets[4];
    if (parse_ip(&args, server_ip_octets) != 0) {
        uart_printf("usage: tcplooptest <server_IP> <client_IP> <port> <bytes>\n");
        return;
    }
    args = skip_spaces(args);
    uint8_t client_ip_octets[4];
    if (parse_ip(&args, client_ip_octets) != 0) {
        uart_printf("usage: tcplooptest <server_IP> <client_IP> <port> <bytes>\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t port;
    if (parse_number(&args, &port) != 0 || port > 0xFFFFu) {
        uart_printf("usage: tcplooptest <server_IP> <client_IP> <port> <bytes>\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t len;
    if (parse_number(&args, &len) != 0 || len == 0 || len > 0xFFFFFFFFu) {
        uart_printf("usage: tcplooptest <server_IP> <client_IP> <port> <bytes>\n");
        return;
    }

    uint32_t server_ip = ip_from_octets(server_ip_octets[0], server_ip_octets[1], server_ip_octets[2], server_ip_octets[3]);
    uint32_t client_ip = ip_from_octets(client_ip_octets[0], client_ip_octets[1], client_ip_octets[2], client_ip_octets[3]);
    tcp_loopback_test(server_ip, client_ip, (uint16_t)port, (uint32_t)len);
}

// `tcploopbench <server_IP> <client_IP> <port> <duration_ms> [mode] [xfer_len]`:
// 外部ピア不要の自己完結持続スループット計測(test.hのtcp_loopback_bench()
// 参照)。tcplooptestと違いjob.h/nvmet.cには(mode=0の既定では)一切触れない
// 同期実装のため、`nvme bench`で見つかったジョブスケジューラ飢餓の影響を
// 受けない。
// mode(省略時0)はビットOR: 0x1=TCPLOOPBENCH_MODE_CORE_SPLIT(target側を
// core1のjobへピン止め、`ts core 0`/`ts core 1`で送信側/受信側を分離)、
// 0x2=TCPLOOPBENCH_MODE_SINGLE_SHOT(継続送信ではなくtcp_send()を1回だけ、
// 単発転送の`ts`ログを見たい場合用)。test.hのマクロ定義参照。
// xfer_len(省略時0=既定のTCP_TEST_MAX_LEN、test.c参照)は1回のtcp_send()で
// 送るバイト数 -- 単発モードでLSOがトリガーされる塊のサイズを細かく
// 制御したい場合に指定する。
#define CMD_TCPLOOPBENCH_USAGE \
    "usage: tcploopbench <server_IP> <client_IP> <port> <duration_ms> [mode] [xfer_len]\n"
static void cmd_tcploopbench(const char *args) {
    uint8_t server_ip_octets[4];
    if (parse_ip(&args, server_ip_octets) != 0) {
        uart_printf(CMD_TCPLOOPBENCH_USAGE);
        return;
    }
    args = skip_spaces(args);
    uint8_t client_ip_octets[4];
    if (parse_ip(&args, client_ip_octets) != 0) {
        uart_printf(CMD_TCPLOOPBENCH_USAGE);
        return;
    }
    args = skip_spaces(args);
    uint64_t port;
    if (parse_number(&args, &port) != 0 || port > 0xFFFFu) {
        uart_printf(CMD_TCPLOOPBENCH_USAGE);
        return;
    }
    args = skip_spaces(args);
    uint64_t duration_ms;
    if (parse_number(&args, &duration_ms) != 0 || duration_ms == 0) {
        uart_printf(CMD_TCPLOOPBENCH_USAGE);
        return;
    }
    args = skip_spaces(args);
    uint64_t mode = 0;
    if (*args != '\0' && parse_number(&args, &mode) != 0) {
        uart_printf(CMD_TCPLOOPBENCH_USAGE);
        return;
    }
    args = skip_spaces(args);
    uint64_t xfer_len = 0;
    if (*args != '\0' && parse_number(&args, &xfer_len) != 0) {
        uart_printf(CMD_TCPLOOPBENCH_USAGE);
        return;
    }

    uint32_t server_ip = ip_from_octets(server_ip_octets[0], server_ip_octets[1], server_ip_octets[2], server_ip_octets[3]);
    uint32_t client_ip = ip_from_octets(client_ip_octets[0], client_ip_octets[1], client_ip_octets[2], client_ip_octets[3]);
    tcp_loopback_bench(server_ip, client_ip, (uint16_t)port, (uint32_t)duration_ms,
                        (uint32_t)mode, (uint32_t)xfer_len);
}

// `tcpbench <IP> <port> [phase_duration_ms]`: スループット計測を実行する
// (tcp_bench_run()参照、対向にストリーミングechoサーバが必要)。
static void cmd_tcpbench(const char *args) {
    uint8_t ip[4];
    if (parse_ip(&args, ip) != 0) {
        uart_printf("usage: tcpbench <IP> <port> [phase_duration_ms]\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t port;
    if (parse_number(&args, &port) != 0 || port > 0xFFFFu) {
        uart_printf("usage: tcpbench <IP> <port> [phase_duration_ms]\n");
        return;
    }
    uint64_t phase_ms = 5000;
    args = skip_spaces(args);
    if (*args != '\0' && parse_number(&args, &phase_ms) != 0) {
        uart_printf("usage: tcpbench <IP> <port> [phase_duration_ms]\n");
        return;
    }

    uint32_t dst_ip = ip_from_octets(ip[0], ip[1], ip[2], ip[3]);
    tcp_bench_run(dst_ip, (uint16_t)port, (uint32_t)phase_ms);
}

// `sendbench <IP> <port> [duration_ms]`: 一方向送信スループット計測を実行する
// (tcp_send_bench_run()参照、対向にsink(受信を読み捨てるだけ)サーバが必要)。
static void cmd_sendbench(const char *args) {
    uint8_t ip[4];
    if (parse_ip(&args, ip) != 0) {
        uart_printf("usage: sendbench <IP> <port> [duration_ms]\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t port;
    if (parse_number(&args, &port) != 0 || port > 0xFFFFu) {
        uart_printf("usage: sendbench <IP> <port> [duration_ms]\n");
        return;
    }
    uint64_t duration_ms = 5000;
    args = skip_spaces(args);
    if (*args != '\0' && parse_number(&args, &duration_ms) != 0) {
        uart_printf("usage: sendbench <IP> <port> [duration_ms]\n");
        return;
    }

    uint32_t dst_ip = ip_from_octets(ip[0], ip[1], ip[2], ip[3]);
    tcp_send_bench_run(dst_ip, (uint16_t)port, (uint32_t)duration_ms);
}

// `err`: PCIe AER(ルートポート+RP1)とGEMのTSRを確認する(err.c参照)。
// tcptest/tcpbenchが失敗した直後に実行し、ハードウェアレベルで実際に
// エラーが記録されているか確認する用途。
static void cmd_err(const char *args) {
    (void)args;
    int any = err_check_all();
    if (any) {
        uart_printf("err: ハードウェアレベルのエラーを検出\n");
    } else {
        uart_printf("err: 検出されたハードウェアエラー無し\n");
    }
}

// `cpuon`: マルチコア化 Phase 1(PSCI CPU_ON疎通確認)で追加したコマンド。
// Phase 2(~/.claude/plans/wondrous-baking-gadget.md参照)でsecondary_entry
// (src/boot.S)自体がCスタック/MMU/例外ベクタを設定しsecondary_main()
// (src/smp.c)の空ループへ入るようになったため、このコマンドが起動する
// core1は今やPhase 1当時より実質的なことをしている -- ただしcpuon自体の
// 処理内容(PSCI_VERSION確認→CPU_ON呼び出し)は変えていない。CPU_ONの
// 成功後、実際にcore1が動き続けているかは`smpstat`で確認すること
// (secondary_entryの生UART出力はtelnetから見えないという罠がある、
// Phase 1「実機で踏んだ罠」節参照 -- smpstatはメモリ上のハートビート
// カウンタを見るだけなのでtelnet越しでも確実に確認できる)。
// main()からの自動実行はしない(手動で何度でも安全に再試行できるように
// する)。secondary_entryはboot.S側の.globalラベル、main.cの
// `extern char _start[];`と同じパターンでリンカシンボルとして参照する。
extern char secondary_entry[];

static void cmd_cpuon(const char *args) {
    (void)args;
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    uart_printf("cpuon: 自分自身(core0)のMPIDR_EL1 = 0x%x (affinity0=%u)\n",
                (unsigned)mpidr, (unsigned)(mpidr & 0xFFu));

    uint64_t ver = psci_version();
    uint32_t major = (uint32_t)(ver >> 16);
    uint32_t minor = (uint32_t)(ver & 0xFFFFu);
    uart_printf("cpuon: PSCI_VERSION = %u.%u (raw=0x%x)\n", major, minor, (unsigned)ver);

    /* target_cpu: BCM2712はMPIDRのAffinity 0が全コア0固定で、コア番号は
     * Affinity 1(bits[15:8])にエンコードされている(通常のAArch64 SoC
     * とは異なる非標準的な構成 -- 実機のcpuon初回テストでAffinity 0=1を
     * 渡したところALREADY_ONという紛らわしい結果になり、Web調査
     * (DIY OS on Raspberry Pi 5 Part 4, zenn.dev)で判明した)。 */
    uint64_t target_cpu = 1u << 8;
    int64_t affinity_before = psci_affinity_info(target_cpu, 0u);
    uart_printf("cpuon: AFFINITY_INFO(core1, target=0x%x, 呼び出し前) = %d (%s)\n",
                (unsigned)target_cpu, (int)affinity_before,
                affinity_before == 0 ? "ON" : affinity_before == 1 ? "OFF" :
                affinity_before == 2 ? "ON_PENDING" : "?");

    int64_t ret = psci_cpu_on(target_cpu, (uint64_t)secondary_entry, 0u);
    uart_printf("cpuon: CPU_ON戻り値 = %d (%s)\n", (int)ret, psci_error_str(ret));
    if (ret == 0) {
        uart_printf("cpuon: SUCCESS -- `smpstat`でcore1が実際に動き続けているか確認すること\n");
    } else if (ret == -4) {
        uart_printf("cpuon: ALREADY_ON -- core1は既に起動済み(前回のcpuon以降)。"
                    "そのまま`smpstat`で生存確認できる\n");
    }

    int64_t affinity_after = psci_affinity_info(target_cpu, 0u);
    uart_printf("cpuon: AFFINITY_INFO(core1, target=0x%x, 呼び出し後) = %d (%s)\n",
                (unsigned)target_cpu, (int)affinity_after,
                affinity_after == 0 ? "ON" : affinity_after == 1 ? "OFF" :
                affinity_after == 2 ? "ON_PENDING" : "?");
}

// `smpstat`: マルチコア化 Phase 2(~/.claude/plans/wondrous-baking-gadget.md
// 参照)。core1(`cpuon`で起動)がsecondary_main()(src/smp.c)の空ループへ
// 実際に到達し、独立して動き続けているかを確認する。secondary_entryの
// 生UART出力は物理シリアルコンソールでしか見えない(Phase 1「実機で
// 踏んだ罠」節参照)のに対し、こちらはメモリ上のg_core1_heartbeatを
// core0側から読むだけなのでtelnet越しでも確実に使える。
static void cmd_smpstat(const char *args) {
    (void)args;
    uart_printf("smpstat: g_core1_alive = %u (secondary_main()の空ループへ到達済みか)\n",
                (unsigned)g_core1_alive);

    /* g_core1_heartbeatはuint64_tだが、uart_printf()の%uは32bit引数
     * 前提の実装(uart_shim.cのpf_fmt_uint()参照)で64bit全体は表示
     * できない -- 単調増加値であり下位32bitだけ見ても増分の有無は
     * 判定できるため、既存のnsze表示等と同じ(unsigned)キャストで
     * 表示する(CLAUDE.md「NVMe/TCP制御のステートマシン化」節と同じ
     * 割り切り)。 */
    uint64_t hb1 = g_core1_heartbeat;
    timer_delay_ms(200);
    uint64_t hb2 = g_core1_heartbeat;
    uint64_t delta = hb2 - hb1;

    uart_printf("smpstat: g_core1_heartbeat 0x%x -> 0x%x (200ms間の増分=%u)\n",
                (unsigned)hb1, (unsigned)hb2, (unsigned)delta);
    if (delta > 0) {
        uart_printf("smpstat: core1は独立して動作中\n");
    } else if (g_core1_alive) {
        uart_printf("smpstat: WARNING -- alive=1なのに増分無し(core1がハング/停止した可能性)\n");
    } else {
        uart_printf("smpstat: core1は未起動(先に`cpuon`を実行すること)\n");
    }

    /* 3コア化: core2(RXコピーオフロード専任)。別の200ms窓で増分を採る。 */
    uart_printf("smpstat: g_core2_alive = %u (コピーオフロード専任コア)\n",
                (unsigned)g_core2_alive);
    uint64_t d1 = g_core2_heartbeat;
    timer_delay_ms(200);
    uint64_t d2 = g_core2_heartbeat;
    uint64_t cd = d2 - d1;
    uart_printf("smpstat: g_core2_heartbeat 0x%x -> 0x%x (200ms間の増分=%u)\n",
                (unsigned)d1, (unsigned)d2, (unsigned)cd);
    if (cd > 0) {
        uart_printf("smpstat: core2は独立して動作中(コピー待機ループ)\n");
    } else if (g_core2_alive) {
        uart_printf("smpstat: WARNING -- core2 alive=1なのに増分無し(ハング)\n");
    } else {
        uart_printf("smpstat: core2は未起動(`rxoff 1`等でオフロード有効化時に起動)\n");
    }
}

// `simdelay <core> <us>` / `simdelay show`: initiator(core0)/target(core1)
// のどちらが実際のスループットの律速要因かを切り分けるための一時計装
// (smp.hのg_sim_delay_us/sim_delay_tick()コメント参照、2026-08-11
// ユーザー指示、原因特定後に削除すること)。
static void cmd_simdelay(const char *args) {
    args = skip_spaces(args);
    unsigned word_len = 0;
    while (args[word_len] != '\0' && args[word_len] != ' ') word_len++;

    if (cmd_name_eq(args, word_len, "show")) {
        for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
            uart_printf("simdelay: core%u = %uus\n", c, (unsigned)g_sim_delay_us[c]);
        }
        return;
    }

    uint64_t core, us;
    const char *p = args;
    if (parse_number(&p, &core) != 0 || core >= SMP_MAX_CORES) {
        uart_printf("usage: simdelay <core 0..%u> <us> | simdelay show\n", SMP_MAX_CORES - 1u);
        return;
    }
    p = skip_spaces(p);
    if (parse_number(&p, &us) != 0) {
        uart_printf("usage: simdelay <core 0..%u> <us> | simdelay show\n", SMP_MAX_CORES - 1u);
        return;
    }

    g_sim_delay_us[core] = (uint32_t)us;
    uart_printf("simdelay: core%u = %uus に設定しました\n", (unsigned)core, (unsigned)us);
}

// `txdump`: 直近の「TXリング枠待ちタイムアウト」検出時点で保存された
// TXリング記述子スナップショットを表示する(eth.c参照)。ts_log()の
// リングバッファ上書きの影響を受けない専用バッファなので、`ts mask 0xffff0000 0x07600000`
// が後始末処理の大量ログで押し出されて見えなくなった場合でも確認できる。
static void cmd_txdump(const char *args) {
    (void)args;
    eth_print_tx_ring_snapshot();
}

// `ts`: ts_log()(timestamp.c、性能分析用の汎用タイムスタンプロガー)が
// 記録した内容をデコード表示する。`pause`/`resume`以外は全て
// 「オプション名 値」の形式で指定する(2026-08-08、ユーザー指示 --
// 以前は位置引数と`type`/`frozen`等のサブコマンドが混在しわかりにくかった):
//
//   ts pause                                   記録を一時停止する
//   ts resume                                   記録を再開する
//   ts [core <N>] [num <N>] [type <TAG>]
//      [start <N>] [end <N>] [tick <値>] [frozen]
//
//     core   対象コア番号(省略時0 -- `ts`自体は常にcore0のシェルから
//            dispatch()されるため、core1にpin止めしたジョブ(nvmet-io等)
//            の記録を見るには明示指定が必要)
//     num    表示件数の上限(省略時20)
//     type   タグ(英数字4文字、例: IDAT)で絞り込む。deltaは絞り込み後の
//            系列における直前の一致エントリとの差になる点に注意
//     start  end  通し番号#start〜#endの範囲を表示(両方指定すること、
//            numは無視される)
//     tick   このtick値(他コアの`ts`/`nprof`出力にある
//            "tick=XXXXXXXXYYYYYYYY"の16桁hexを1つの数値として渡す)より
//            後の最初のエントリからnum件を表示する -- 他コアの記録で
//            見つけたおおよその実時刻を起点に、このコアで何が起きて
//            いたかを追うために使う
//     frozen 生のリングバッファではなくts_log_freeze()のスナップショット
//            を対象にする(numのみ組み合わせ可、type/start/end/tickとは
//            未対応)
//
//   複数のモード選択オプション(tick/start・end/type/frozen)を同時に
//   指定した場合はtick > start・end > type > frozenの優先順で1つだけ
//   有効になる(通常は組み合わせない)。
static void ts_usage(void) {
    uart_printf("usage: ts [core <N>] [num <N>] [mask <mask> <value>] [start <N>] [end <N>] "
                "[tick <値>] [frozen]\n"
                "       ts pause | ts resume\n"
                "  mask: (tag & mask)==value のみ表示。tag=File#[31:24]|Func#[23:16]|info[15:0]\n"
                "        例 ts mask 0x00f00000 0x00200000 (mlx5_net.cの全関数)\n"
                "  mode <値>: 診断ts記録の有効ビット。bit0=tcp診断, bit1=nvmet受信\n"
                "        per-CMD診断(既定OFF)。計測時 ts mode 3、通常運用 ts mode 1\n");
}

static void cmd_ts(const char *args) {
    args = skip_spaces(args);
    unsigned word_len = 0;
    while (args[word_len] != '\0' && args[word_len] != ' ') word_len++;

    /* `ts pause`/`ts resume`: ts_log()系の記録を一時停止/再開する
     * (timestamp.hのts_log_set_paused()コメント参照)。UARTダンプが
     * 115200bpsで数十秒かかる間もリングバッファが新規エントリで
     * 上書きされ続け、直前に見ていた文脈が消えてしまう問題への対策
     * (2026-08-07、ユーザー指示)。ダンプしたい場面の直後に`ts pause`
     * してからじっくり読み、読み終えたら`ts resume`で記録を再開する
     * 運用を想定。 */
    if (cmd_name_eq(args, word_len, "pause")) {
        ts_log_set_paused(1);
        uart_printf("ts: 記録を一時停止しました(累計%u件で静止)\n",
                    (uint32_t)ts_log_total());
        return;
    }
    if (cmd_name_eq(args, word_len, "resume")) {
        ts_log_set_paused(0);
        uart_printf("ts: 記録を再開しました(累計%u件から継続)\n",
                    (uint32_t)ts_log_total());
        return;
    }

    uint64_t core = 0;
    uint64_t num  = 20;
    uint64_t tag_start = 0, tag_end = 0;  // start/endオプション用
    uint64_t mask = 0, value = 0;         // mask絞り込み用((tag & mask)==value)
    uint64_t tick = 0;
    int has_mask  = 0;
    int has_start = 0;
    int has_end   = 0;
    int has_tick  = 0;
    int frozen    = 0;
    uint64_t mode = 0;

    while (*args != '\0') {
        unsigned opt_len = 0;
        while (args[opt_len] != '\0' && args[opt_len] != ' ') opt_len++;

        if (cmd_name_eq(args, opt_len, "core")) {
            args = skip_spaces(args + opt_len);
            if (parse_number(&args, &core) != 0) { ts_usage(); return; }
        } else if (cmd_name_eq(args, opt_len, "num")) {
            args = skip_spaces(args + opt_len);
            if (parse_number(&args, &num) != 0) { ts_usage(); return; }
        } else if (cmd_name_eq(args, opt_len, "mask")) {
            /* ts mask <mask> <value>: (tag & mask)==value のエントリだけ表示。
             * 例: ts mask 0xffff0000 0x03290000 -> File#=0x03(mlx5_net.c)
             *     かつFunc#=0x29(mlx5_net_poll_recv)。
             *     ts mask 0x00f00000 0x00200000 -> Func#=0x20〜0x2f(mlx5_net.c
             *     の全関数)。 */
            args = skip_spaces(args + opt_len);
            if (parse_number(&args, &mask) != 0) { ts_usage(); return; }
            args = skip_spaces(args);
            if (parse_number(&args, &value) != 0) { ts_usage(); return; }
            has_mask = 1;
        } else if (cmd_name_eq(args, opt_len, "start")) {
            args = skip_spaces(args + opt_len);
            if (parse_number(&args, &tag_start) != 0) { ts_usage(); return; }
            has_start = 1;
        } else if (cmd_name_eq(args, opt_len, "end")) {
            args = skip_spaces(args + opt_len);
            if (parse_number(&args, &tag_end) != 0) { ts_usage(); return; }
            has_end = 1;
        } else if (cmd_name_eq(args, opt_len, "tick")) {
            args = skip_spaces(args + opt_len);
            if (parse_number(&args, &tick) != 0) { ts_usage(); return; }
            has_tick = 1;
        } else if (cmd_name_eq(args, opt_len, "frozen")) {
            frozen = 1;
            args += opt_len;
        } else if (cmd_name_eq(args, opt_len, "mode")) {
            args = skip_spaces(args + opt_len);
            if (parse_number(&args, &mode) != 0) { ts_usage(); return; }
            ts_log_mode_set(mode);
            return;
        } else {
            ts_usage();
            return;
        }
        args = skip_spaces(args);
    }

    /* ここから先はどのモードでも「(必要なら)開始通し番号を timestamp.c の
     * query関数へ問い合わせる → 唯一の表示関数ts_log_dump_core()を
     * (core, start, count, tag)で呼ぶ」という同じ2段階になる
     * (timestamp.h冒頭コメント参照、2026-08-08ユーザー指示)。 */
    if (has_start || has_end) {
        if (!has_start || !has_end) {
            uart_printf("usage: startとendは両方指定してください\n");
            return;
        }
        uint64_t count = (tag_end >= tag_start) ? (tag_end - tag_start + 1) : 0;
        ts_log_dump_core((unsigned)core, tag_start, (uint32_t)count, 0, 0);
        return;
    }
    if (has_tick) {
        uint64_t start = ts_log_query_start_after_tick((unsigned)core, tick);
        ts_log_dump_core((unsigned)core, start, (uint32_t)num,
                         has_mask ? (uint32_t)mask : 0, (uint32_t)value);
        return;
    }
    if (has_mask) {
        uint64_t start = ts_log_query_start_last_n_matching((unsigned)core,
                             (uint32_t)mask, (uint32_t)value, (uint32_t)num);
        ts_log_dump_core((unsigned)core, start, (uint32_t)num, (uint32_t)mask, (uint32_t)value);
        return;
    }
    if (frozen) {
        ts_log_dump_frozen_core((unsigned)core, (uint32_t)num);
        return;
    }
    {
        uint64_t start = ts_log_query_start_last_n((unsigned)core, (uint32_t)num);
        ts_log_dump_core((unsigned)core, start, (uint32_t)num, 0, 0);
    }
}

// nvmeコマンドが操作する唯一のコンテキスト(並列接続不要 -- adminとIOの
// 2本のTCPコネクションはnvme_ctx_t内部で管理される)。
// static外し+extern公開(nvme.h参照): 以前test.cのtemp_test()が独自に
// 別インスタンス(同名だがstatic、別実体)を持っていたため、temp_test()が
// 確立した接続をこちら(nvme disconnect等のシェルコマンド)が一切認識
// できず、`nvme disconnect`が「一度も接続していない方」を操作して
// 何も切断できないという実機バグを引き起こした。単一の共有インスタンスに
// 一本化して再発を防ぐ。
nvme_ctx_t s_nvme_ctx;

// nvme read/writeの作業バッファ(malloc無し環境のためstatic BSS確保)。
// aligned(64): nvme_write()がtcp_send()経由でこのバッファのアドレスを
// 直接使う可能性がある(tcp.hのtcp_send()ドキュメント参照、tcp.cの
// s_seg_buf/H2CDataステージングバッファと同じ規約)。read/writeで共用する
// (双方とも1回の呼び出し中はブロッキングなので同時使用にはならない)。
// 256KB: nvme benchの最大転送長パターン(262144B)をそのまま読み出せる
// サイズに合わせている(NVME_BENCH_SIZES参照)。
#define NVME_CMD_BUF_MAX (256u * 1024u)
static uint8_t s_nvme_buf[NVME_CMD_BUF_MAX] __attribute__((aligned(64)));

// bufの内容を16バイト/行でダンプする(hexdump32とは別 -- こちらは
// 生バッファに対する単純なバイト列ダンプ、MMIOレジスタ読み出しではない)。
static void nvme_hexdump(const uint8_t *buf, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 16) {
        uart_printf("  %04x: ", i);
        for (uint32_t j = 0; j < 16 && i + j < len; j++) {
            uart_printf("%02x ", buf[i + j]);
        }
        uart_printf("\n");
    }
}

// Identify Controller応答内のASCII文字列フィールド(SN/MN/FR等)を、
// 末尾の空白パディングを除いてlen文字までコピーする(NVMe仕様のASCII
// フィールドは右側を空白0x20でパディングする)。
static void nvme_print_ascii_field(const char *label, const uint8_t *field, uint32_t len) {
    char buf[41];  // MN(40)が最長
    uint32_t n = (len < sizeof(buf) - 1) ? len : (uint32_t)(sizeof(buf) - 1);
    uint32_t i;
    for (i = 0; i < n; i++) {
        buf[i] = (char)field[i];
    }
    while (i > 0 && buf[i - 1] == ' ') {
        i--;
    }
    buf[i] = '\0';
    uart_printf("  %s: %s\n", label, buf);
}

// hex文字列(空白区切り可、"0x"接頭辞不要)をバイト列へ変換する。
// 戻り値: 変換できたバイト数(max_lenで頭打ち)。
static uint32_t parse_hex_bytes(const char *s, uint8_t *out, uint32_t max_len) {
    uint32_t count = 0;
    while (*s != '\0' && count < max_len) {
        while (*s == ' ') s++;
        if (*s == '\0') break;

        uint8_t byte = 0;
        int digits = 0;
        while (digits < 2) {
            char c = *s;
            uint8_t d;
            if (c >= '0' && c <= '9') {
                d = (uint8_t)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                d = (uint8_t)(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                d = (uint8_t)(c - 'A' + 10);
            } else {
                break;
            }
            byte = (uint8_t)((byte << 4) | d);
            s++;
            digits++;
        }
        if (digits == 0) {
            break;  // hex文字が読めない(区切りでも数字でもない) -- 打ち切り
        }
        out[count++] = byte;
    }
    return count;
}

// `nvme`サブコマンドの結果表示ジョブ(job.h、CLAUDE.md「NVMe/TCP制御の
// ステートマシン化」節参照)。SQE組み立て・exec開始・busy管理は全て
// nvme.c側のnvme_write_begin()/nvme_read_begin()/nvme_identify_ctrl_
// begin()/nvme_identify_ns_begin()に一本化されている(command.cは
// nvme_sqe_t等のNVMeプロトコルの詳細を一切扱わない) -- ここではその
// 完了(nvme_io_job_done())を待って結果を表示するだけの、CLI固有の
// 関心事(`cmd_ping()`のping_job_step()と同じ配置パターン)を担う。
typedef enum {
    NVME_CLI_KIND_ID_CTRL,
    NVME_CLI_KIND_ID_NS,
    NVME_CLI_KIND_READ,
    NVME_CLI_KIND_WRITE,
} nvme_cli_kind_t;

typedef struct {
    nvme_cli_kind_t kind;
    uint32_t        nsid;
    uint32_t        nlb;      // read: 読み出しブロック数、write: ゼロパディング後のブロック数
    uint32_t        raw_len;  // write: パディング前の実データバイト数(表示用)
} nvme_cli_report_ctx_t;

static nvme_cli_report_ctx_t s_nvme_cli_report_ctx;

static job_result_t nvme_cli_report_job_step(job_t *self) {
    nvme_cli_report_ctx_t *jc = (nvme_cli_report_ctx_t *)self->ctx;
    /* nvme_write_begin()等が既にctx->busyを管理しているため、ここでは
     * 単に表示を諦めて終わるだけでよい(job stopされてもnvme_io_job_
     * done()が返り、その時点のnvme_io_job_result()で判断する設計上、
     * 表示ジョブ自身にcancel_requested対応は不要 -- 実際の送受信job
     * (nvme.c内、"nvme-write"等)側のcancel_requested対応で十分)。 */
    if (!nvme_io_job_done()) {
        return JOB_WAITING;
    }
    int result = nvme_io_job_result();

    switch (jc->kind) {
    case NVME_CLI_KIND_ID_CTRL:
        if (result != 0) {
            uart_printf("nvme: id-ctrl失敗\n");
            break;
        }
        uart_printf("nvme: Identify Controller:\n");
        nvme_print_ascii_field("SN (serial number)",    s_nvme_buf + 4,  20);
        nvme_print_ascii_field("MN (model number)",     s_nvme_buf + 24, 40);
        nvme_print_ascii_field("FR (firmware revision)", s_nvme_buf + 64, 8);
        uart_printf("  NN (number of namespaces): %u\n", rd32le(s_nvme_buf + 516));
        break;

    case NVME_CLI_KIND_ID_NS:
        if (result != 0) {
            uart_printf("nvme: id-ns失敗\n");
            break;
        }
        nvme_update_lba_size_from_id_ns(&s_nvme_ctx, jc->nsid, s_nvme_buf);
        {
            uint64_t nsze = rd32le(s_nvme_buf + 0) | ((uint64_t)rd32le(s_nvme_buf + 4) << 32);
            uint64_t ncap = rd32le(s_nvme_buf + 8) | ((uint64_t)rd32le(s_nvme_buf + 12) << 32);
            uint64_t nuse = rd32le(s_nvme_buf + 16) | ((uint64_t)rd32le(s_nvme_buf + 20) << 32);
            uart_printf("nvme: Identify Namespace %u:\n", jc->nsid);
            uart_printf("  NSZE (size)=%u NCAP (capacity)=%u NUSE (utilization)=%u ブロック\n",
                        (unsigned)nsze, (unsigned)ncap, (unsigned)nuse);
            uart_printf("  LBAサイズ=%u バイト\n", s_nvme_ctx.lba_size);
        }
        break;

    case NVME_CLI_KIND_READ:
        if (result != 0) {
            uart_printf("nvme read: 失敗 (status=0x%x)\n", result);
            break;
        }
        uart_printf("nvme read: %u ブロック (%u バイト) 読み出し完了\n",
                    jc->nlb, jc->nlb * s_nvme_ctx.lba_size);
        nvme_hexdump(s_nvme_buf, jc->nlb * s_nvme_ctx.lba_size);
        break;

    case NVME_CLI_KIND_WRITE:
        if (result != 0) {
            uart_printf("nvme write: 失敗 (status=0x%x)\n", result);
            break;
        }
        uart_printf("nvme write: %u バイト(%u ブロックへゼロパディング後)書き込み完了\n",
                    jc->raw_len, jc->nlb);
        break;
    }

    return JOB_DONE;
}

// kind/nsid/nlb/raw_len(表示用パラメータ)をs_nvme_cli_report_ctxへ設定し、
// 結果表示ジョブをspawnする(実際のNVMeコマンド自体は呼び出し元が既に
// nvme_*_begin()で開始済みという前提)。
static void nvme_cli_report_spawn(nvme_cli_kind_t kind, uint32_t nsid, uint32_t nlb, uint32_t raw_len) {
    s_nvme_cli_report_ctx.kind    = kind;
    s_nvme_cli_report_ctx.nsid    = nsid;
    s_nvme_cli_report_ctx.nlb     = nlb;
    s_nvme_cli_report_ctx.raw_len = raw_len;
    if (!job_spawn(nvme_cli_report_job_step, &s_nvme_cli_report_ctx, "nvme-report")) {
        uart_printf("[!] nvme: 結果表示ジョブ生成失敗(コマンド自体は続行中)\n");
    }
}

// `nvme connect <IP> <port> <subnqn>`: admin queue(qid=0)+IO queue(qid=1)を
// 確立するジョブ(nvme_connect_job_start())をspawnし、即座に戻る。
static void nvme_cmd_connect(const char *args) {
    uint8_t ip[4];
    if (parse_ip(&args, ip) != 0) {
        uart_printf("usage: nvme connect <IP> <port> <subnqn>\n");
        return;
    }
    args = skip_spaces(args);
    uint64_t port;
    if (parse_number(&args, &port) != 0 || port > 0xFFFFu) {
        uart_printf("usage: nvme connect <IP> <port> <subnqn>\n");
        return;
    }
    args = skip_spaces(args);
    if (*args == '\0') {
        uart_printf("usage: nvme connect <IP> <port> <subnqn>\n");
        return;
    }

    uint32_t dst_ip = ip_from_octets(ip[0], ip[1], ip[2], ip[3]);
    nvme_connect_job_start(&s_nvme_ctx, dst_ip, (uint16_t)port, args);
}

// `nvme disconnect`(tcp_close()のみでブロッキングしないため無変更)
static void nvme_cmd_disconnect(const char *args) {
    (void)args;
    if (s_nvme_ctx.busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return;
    }
    nvme_disconnect(&s_nvme_ctx);
    uart_printf("nvme: 切断完了\n");
}

// `nvme id-ctrl`: Identify Controllerを実行し、主要フィールドを表示する。
// SQE組み立て・exec開始はnvme_identify_ctrl_begin()(nvme.c)に一本化
// されている -- command.cはNVMeプロトコルの詳細を一切扱わない。
static void nvme_cmd_id_ctrl(const char *args) {
    (void)args;
    if (nvme_identify_ctrl_begin(&s_nvme_ctx, s_nvme_buf) != 0) {
        return;
    }
    nvme_cli_report_spawn(NVME_CLI_KIND_ID_CTRL, 0, 0, 0);
}

// `nvme id-ns <nsid>`: Identify Namespaceを実行し、主要フィールドを表示する。
static void nvme_cmd_id_ns(const char *args) {
    args = skip_spaces(args);
    uint64_t nsid;
    if (parse_number(&args, &nsid) != 0 || nsid == 0 || nsid > 0xFFFFFFFFu) {
        uart_printf("usage: nvme id-ns <nsid>\n");
        return;
    }
    if (nvme_identify_ns_begin(&s_nvme_ctx, (uint32_t)nsid, s_nvme_buf) != 0) {
        return;
    }
    nvme_cli_report_spawn(NVME_CLI_KIND_ID_NS, (uint32_t)nsid, 0, 0);
}

// `nvme read <nsid> <lba> [count]`: countブロック読み出し、16進ダンプする。
// SQE組み立て・exec開始はnvme_read_begin()(nvme.c)に一本化されている。
static void nvme_cmd_read(const char *args) {
    args = skip_spaces(args);
    uint64_t nsid, lba, count = 1;
    if (parse_number(&args, &nsid) != 0 || nsid == 0 || nsid > 0xFFFFFFFFu) {
        uart_printf("usage: nvme read <nsid> <lba> [count]\n");
        return;
    }
    args = skip_spaces(args);
    if (parse_number(&args, &lba) != 0) {
        uart_printf("usage: nvme read <nsid> <lba> [count]\n");
        return;
    }
    args = skip_spaces(args);
    if (*args != '\0' && (parse_number(&args, &count) != 0 || count == 0)) {
        uart_printf("usage: nvme read <nsid> <lba> [count]\n");
        return;
    }

    uint32_t lba_size = s_nvme_ctx.lba_size;
    if (lba_size == 0 || count * lba_size > NVME_CMD_BUF_MAX) {
        uart_printf("nvme read: count過大 (最大 %u バイト分)、またはlba_size不明(先にnvme connectすること)\n",
                    NVME_CMD_BUF_MAX);
        return;
    }

    if (nvme_read_begin(&s_nvme_ctx, (uint32_t)nsid, lba, s_nvme_buf, (uint32_t)count) != 0) {
        return;
    }
    nvme_cli_report_spawn(NVME_CLI_KIND_READ, (uint32_t)nsid, (uint32_t)count, 0);
}

// `nvme write <nsid> <lba> <hex...>`: 最大512Bのインラインhexデータを書き込む。
// LBAサイズに満たない端数はゼロパディングし、ちょうどLBA境界まで書く。
// SQE組み立て・exec開始はnvme_write_begin()(nvme.c)に一本化されている。
static void nvme_cmd_write(const char *args) {
    args = skip_spaces(args);
    uint64_t nsid, lba;
    if (parse_number(&args, &nsid) != 0 || nsid == 0 || nsid > 0xFFFFFFFFu) {
        uart_printf("usage: nvme write <nsid> <lba> <hex...>\n");
        return;
    }
    args = skip_spaces(args);
    if (parse_number(&args, &lba) != 0) {
        uart_printf("usage: nvme write <nsid> <lba> <hex...>\n");
        return;
    }
    args = skip_spaces(args);
    if (*args == '\0') {
        uart_printf("usage: nvme write <nsid> <lba> <hex...>\n");
        return;
    }

    uint32_t lba_size = s_nvme_ctx.lba_size;
    if (lba_size == 0) {
        uart_printf("nvme write: lba_size不明(先にnvme connectすること)\n");
        return;
    }

#define NVME_WRITE_MAX_INLINE 512u
    uint8_t raw[NVME_WRITE_MAX_INLINE];
    uint32_t raw_len = parse_hex_bytes(args, raw, NVME_WRITE_MAX_INLINE);
    if (raw_len == 0) {
        uart_printf("nvme write: hexデータを読み取れず\n");
        return;
    }

    uint32_t nlb = (raw_len + lba_size - 1) / lba_size;
    uint32_t total_len = nlb * lba_size;
    if (total_len > NVME_CMD_BUF_MAX) {
        uart_printf("nvme write: データがLBAサイズ丸め込みでバッファ上限を超過\n");
        return;
    }

    /* s_nvme_bufへ書き込みデータを組み立てる(ジョブのSEND状態が
     * nvme_tcp_send_cmd()経由でこのバッファをin-capsuleデータとして
     * 直接参照するため、nvme_write_begin()を呼ぶ前に確定させておく
     * 必要がある -- nvme_write_begin()はポインタを保存するだけで
     * コピーしない、nvme.hのコメント参照)。 */
    for (uint32_t i = 0; i < total_len; i++) {
        s_nvme_buf[i] = (i < raw_len) ? raw[i] : 0;
    }

    if (nvme_write_begin(&s_nvme_ctx, (uint32_t)nsid, lba, s_nvme_buf, nlb) != 0) {
        return;
    }
    nvme_cli_report_spawn(NVME_CLI_KIND_WRITE, (uint32_t)nsid, nlb, raw_len);
}

// `nvme bench <nsid>`: read/writeそれぞれについて複数の転送長で
// スループット/IOPSを計測する(sequentialな読み出し/書き込みを一定時間
// 繰り返し、1秒ごとに集計を報告した上で、最後にMB/s・kIOPSの一覧を出す)。
// writeはNVME_TCP_INLINE_DATA_MAX(8192B)が1コマンドあたりの上限 --
// nvme_tcp.cのコメント参照、in-capsule送信のみでR2T分割は未実装なため、
// それを超える転送長は物理的に単一コマンドで送れず計測をスキップする
// (複数の8KBコマンドをつなげて疑似的に大きなwriteを装うことはしない --
// 実際に1コマンドで送れる量を正直に報告する方針)。
// 1コマンドごとにResponse Capsuleを待つ(パイプライン化なし)ので、write
// はreadよりも往復レイテンシの影響を強く受け、スループットはreadより
// かなり低く出る -- これは実装の制約であってバグではない。
#define NVME_BENCH_DURATION_MS 5000u

// 計測する転送長パターン(バイト)。lba_size(512B)の倍数であること。
static const uint32_t NVME_BENCH_SIZES[] = { 8192u, 32768u, 65536u, 262144u };
#define NVME_BENCH_NUM_SIZES (sizeof(NVME_BENCH_SIZES) / sizeof(NVME_BENCH_SIZES[0]))

// size_bytesの転送長でread(is_write=0)/write(is_write=1)をduration_msの間
// 繰り返し、1秒ごとに進捗をログ出力する。集計は*out_bytes/*out_ms/
// *out_roundsへ書く。
// 戻り値: 0=完走(duration_ms経過)、-1=途中でread/write失敗(集計は失敗
//         直前までの値)
static int nvme_bench_run_one(uint32_t nsid, int is_write, uint32_t size_bytes,
                               uint32_t lba_size, uint32_t duration_ms,
                               uint64_t *out_bytes, uint32_t *out_ms, uint64_t *out_rounds)
{
    uint32_t count = size_bytes / lba_size;

    // write時はs_nvme_bufに適当なパターンを1度だけ詰めておく(内容自体は
    // スループット計測には無関係、tcp.h/bench.cのbench_fill_pattern()と
    // 同じ考え方)。readはnvme_read()が毎ラウンド上書きするので不要。
    if (is_write) {
        for (uint32_t i = 0; i < size_bytes; i++) {
            s_nvme_buf[i] = (uint8_t)(i & 0xFFu);
        }
    }

    uart_printf("[NVME-BENCH] ---- %s %uB ----\n", is_write ? "write" : "read", size_bytes);

    uint64_t test_start = timer_now();
    uint64_t last_report = test_start;

    uint64_t total_bytes = 0;
    uint64_t total_rounds = 0;
    uint32_t bytes_since_report = 0;
    uint32_t rounds_since_report = 0;
    uint64_t lba = 0;
    int ok = 1;

    while (!timeout_ms(test_start, duration_ms)) {
        int status = is_write
            ? nvme_write(&s_nvme_ctx, nsid, lba, s_nvme_buf, count)
            : nvme_read(&s_nvme_ctx, nsid, lba, s_nvme_buf, count);
        if (status != 0) {
            uart_printf("[NVME-BENCH] %s失敗(status=0x%x)、計測を中断\n",
                        is_write ? "書き込み" : "読み出し", status);
            ok = 0;
            break;
        }
        total_bytes += size_bytes;
        bytes_since_report += size_bytes;
        total_rounds++;
        rounds_since_report++;
        lba += count;
        // namespace末尾を超える手前でLBA0へ折り返す(小さいbacking storeでも
        // 長時間ベンチを回せるように -- ラップ自体はスループット計測に影響
        // しない、単に読み書きするLBA範囲が周回するだけ)。
        if (s_nvme_ctx.nsze != 0 && lba + count > s_nvme_ctx.nsze) {
            lba = 0;
        }

        if (timeout_sec(last_report, 1)) {
            uint64_t now = timer_now();
            uart_printf("[NVME-BENCH] t=%us %s=%uB/s rounds=%u total=%uB\n",
                        (unsigned)get_sec_from(test_start),
                        is_write ? "write" : "read",
                        bytes_since_report, rounds_since_report,
                        (unsigned)total_bytes);
            bytes_since_report = 0;
            rounds_since_report = 0;
            last_report = now;
        }
    }

    *out_bytes  = total_bytes;
    *out_ms     = (uint32_t)get_ms_from(test_start);
    *out_rounds = total_rounds;
    return ok ? 0 : -1;
}

// total_bytes/total_ms/total_roundsから"X.YMB/s Z.WkIOPS"を出力する
// (uart_printf()は%fに非対応なため、整数演算で小数第1位まで手計算する)。
// MBは10進(1,000,000バイト、ネットワークスループットの慣例に合わせた --
// 2進MiBではない)。
static void nvme_bench_print_rate(uint64_t total_bytes, uint32_t total_ms, uint64_t total_rounds)
{
    if (total_ms == 0) {
        uart_printf("0.0MB/s 0.0kIOPS");
        return;
    }
    uint64_t bps = (total_bytes * 1000ull) / total_ms;
    uint32_t mb_int  = (uint32_t)(bps / 1000000ull);
    uint32_t mb_frac = (uint32_t)((bps / 100000ull) % 10ull);

    uint64_t iops_x10  = (total_rounds * 10000ull) / total_ms;
    uint32_t kiops_int  = (uint32_t)(iops_x10 / 10000ull);
    uint32_t kiops_frac = (uint32_t)((iops_x10 / 1000ull) % 10ull);

    uart_printf("%u.%uMB/s %u.%ukIOPS", mb_int, mb_frac, kiops_int, kiops_frac);
}

static void nvme_cmd_bench(const char *args) {
    args = skip_spaces(args);
    uint64_t nsid;
    if (parse_number(&args, &nsid) != 0 || nsid == 0 || nsid > 0xFFFFFFFFu) {
        uart_printf("usage: nvme bench <nsid>\n");
        return;
    }
    /* benchは既存のブロッキングnvme_identify_ns()/nvme_read()/nvme_write()を
     * 直接呼ぶ設計のまま(CLAUDE.md「NVMe/TCP制御のステートマシン化」節、
     * フェーズ3の対象外)。ジョブ化されたconnect/id-ctrl/id-ns/read/write
     * (s_nvme_ctx.busy)が実行中に呼ぶと同じconnへ二重に送信してしまう
     * ため、その間は拒否する。 */
    if (s_nvme_ctx.busy) {
        uart_printf("[!] nvme bench: 前回の操作がまだ実行中です\n");
        return;
    }

    /* `nvme connect`(ジョブ化済み、nvme_connect_job_step()のNCONN_ST_
     * EXEC_IDENTIFY_NS状態)は接続シーケンスの一部として既にこのnsidの
     * Identify Namespaceを実行し、s_nvme_ctx.lba_size/nszeへ結果を格納
     * 済みのはず。ここで同じコマンドを(このブロッキング専用の
     * nvme_identify_ns()経由で)重ねて送り直すと、実機でnvmetのadmin
     * queueが非ゼロのステータスを返して失敗する事象を確認した --
     * nvmet.c側のadmin定常ループ(接続ハンドシェイク後の任意の追加admin
     * コマンド)がこのプロジェクトで十分検証されていない領域だったため
     * と考えられる(CLAUDE.md参照)。接続済みなら既知のlba_sizeをそのまま
     * 再利用し、この二重送信自体を避ける -- 未接続稼働(lba_size==0)の
     * 場合のみ、フォールバックとして送信する。 */
    uint32_t lba_size = s_nvme_ctx.lba_size;
    if (lba_size == 0) {
        if (nvme_identify_ns(&s_nvme_ctx, (uint32_t)nsid, s_nvme_buf) != 0) {
            uart_printf("nvme bench: Identify Namespace失敗\n");
            return;
        }
        lba_size = s_nvme_ctx.lba_size;
    }
    if (lba_size == 0 || lba_size > NVME_CMD_BUF_MAX) {
        uart_printf("nvme bench: 不正なLBAサイズ (%u)\n", lba_size);
        return;
    }

    uart_printf("[NVME-BENCH] ===== NVMe/TCP IOPS/スループット計測開始 "
                "(nsid=%u lba_size=%u) =====\n", (unsigned)nsid, lba_size);

    uint64_t read_bytes[NVME_BENCH_NUM_SIZES]  = {0};
    uint32_t read_ms[NVME_BENCH_NUM_SIZES]     = {0};
    uint64_t read_rounds[NVME_BENCH_NUM_SIZES] = {0};
    int      read_ok[NVME_BENCH_NUM_SIZES]     = {0};

    for (unsigned i = 0; i < NVME_BENCH_NUM_SIZES; i++) {
        uint32_t size = NVME_BENCH_SIZES[i];
        if (size % lba_size != 0 || size > NVME_CMD_BUF_MAX) {
            uart_printf("[NVME-BENCH] read %uB: スキップ(lba_sizeで割り切れない、"
                        "またはバッファ上限%uBを超過)\n", size, NVME_CMD_BUF_MAX);
            continue;
        }
        read_ok[i] = (nvme_bench_run_one((uint32_t)nsid, 0, size, lba_size,
                                          NVME_BENCH_DURATION_MS,
                                          &read_bytes[i], &read_ms[i], &read_rounds[i]) == 0);
        if (!read_ok[i]) {
            /* 失敗した接続状態のまま次のサイズへ進むと、ストリームが
             * desyncしたままの二次的な失敗を重ねるだけで診断上ノイズに
             * なる(実機で確認)。最初の失敗で打ち切り、以降のサイズは
             * N/A(未計測)として扱う。 */
            uart_printf("[NVME-BENCH] read %uBが失敗したため、以降のread計測を中断します\n", size);
            break;
        }
    }

    // write: NVME_TCP_INLINE_DATA_MAXを超える転送長はそもそも単一コマンド
    // で送れないため計測せずスキップする(関数コメント参照)。
    uint64_t write_bytes = 0;
    uint32_t write_ms = 0;
    uint64_t write_rounds = 0;
    int write_ok = 0;
    for (unsigned i = 0; i < NVME_BENCH_NUM_SIZES; i++) {
        uint32_t size = NVME_BENCH_SIZES[i];
        if (size > NVME_TCP_INLINE_DATA_MAX) {
            uart_printf("[NVME-BENCH] write %uB: スキップ(NVME_TCP_INLINE_DATA_MAX=%uBを"
                        "超える単一コマンドは未対応 -- in-capsule送信のみ、R2T分割未実装)\n",
                        size, (unsigned)NVME_TCP_INLINE_DATA_MAX);
            continue;
        }
        if (size % lba_size != 0) {
            uart_printf("[NVME-BENCH] write %uB: スキップ(lba_sizeで割り切れない)\n", size);
            continue;
        }
        write_ok = (nvme_bench_run_one((uint32_t)nsid, 1, size, lba_size,
                                        NVME_BENCH_DURATION_MS,
                                        &write_bytes, &write_ms, &write_rounds) == 0);
        if (!write_ok) {
            uart_printf("[NVME-BENCH] write %uBが失敗したため、以降のwrite計測を中断します\n", size);
            break;
        }
    }

    uart_printf("[NVME-BENCH] ---- まとめ ----\n");
    for (unsigned i = 0; i < NVME_BENCH_NUM_SIZES; i++) {
        uart_printf("[NVME-BENCH] read  %6uB: ", (unsigned)NVME_BENCH_SIZES[i]);
        if (read_ok[i]) {
            nvme_bench_print_rate(read_bytes[i], read_ms[i], read_rounds[i]);
            uart_printf("\n");
        } else {
            uart_printf("N/A\n");
        }
    }
    uart_printf("[NVME-BENCH] write    8192B: ");
    if (write_ok) {
        nvme_bench_print_rate(write_bytes, write_ms, write_rounds);
        uart_printf("\n");
    } else {
        uart_printf("N/A\n");
    }
    uart_printf("[NVME-BENCH] write 32768B/65536B/262144B: 非対応(8KB上限、上記コメント参照)\n");
    uart_printf("[NVME-BENCH] ===== 計測終了 =====\n");
}

// `nvme`: connect/disconnect/id-ctrl/id-ns/read/write/benchサブコマンドをディスパッチする。
static void cmd_nvme(const char *args) {
    args = skip_spaces(args);
    unsigned len = 0;
    while (args[len] != '\0' && args[len] != ' ') {
        len++;
    }
    const char *sub_args = skip_spaces(args + len);

    if (cmd_name_eq(args, len, "connect")) {
        nvme_cmd_connect(sub_args);
    } else if (cmd_name_eq(args, len, "disconnect")) {
        nvme_cmd_disconnect(sub_args);
    } else if (cmd_name_eq(args, len, "id-ctrl")) {
        nvme_cmd_id_ctrl(sub_args);
    } else if (cmd_name_eq(args, len, "id-ns")) {
        nvme_cmd_id_ns(sub_args);
    } else if (cmd_name_eq(args, len, "read")) {
        nvme_cmd_read(sub_args);
    } else if (cmd_name_eq(args, len, "write")) {
        nvme_cmd_write(sub_args);
    } else if (cmd_name_eq(args, len, "bench")) {
        nvme_cmd_bench(sub_args);
    } else {
        uart_printf("usage: nvme connect <IP> <port> <subnqn> | disconnect | id-ctrl | "
                    "id-ns <nsid> | read <nsid> <lba> [count] | write <nsid> <lba> <hex...> | "
                    "bench <nsid>\n");
    }
}

/* .bssグローバルではなく固定物理アドレス(nvmet.hのNVMET_CTX_SLOT()、
 * board.hのNVMET_INSTANCES_BASE)を使う -- platform_init.cのs_nvmet_rp1
 * 等と同じ理由(fwupdateのLOAD_ADDR受信窓との物理衝突の防止)。slot 3を
 * 使う(0-2はplatform_init.cのRP1/mlx5-pf0/mlx5-pf1が固定で使うため)。 */
#define s_nvmet_ctx (*NVMET_CTX_SLOT(3))

// `nvmet`: NVMe/TCPターゲットを起動する。admin/IOキューをそれぞれ独立した
// ジョブ(job.h、CLAUDE.md「NVMe/TCP制御のステートマシン化」節参照)として
// spawnし、即座にシェルへ戻る -- 以後の実際のaccept/ICReq/コマンド処理は
// job_scheduler_tick()が毎tick進める。セッションの進行状況は`jobs`
// コマンド(nvmet-admin/nvmet-io)で確認できる。同時に1セッションのみ
// 許可する(nvmet_job_start()内のctx->session_activeガード、cmd_ping()の
// s_ping_job_in_flightと同じ考え方)。
static void cmd_nvmet(const char *args) {
    uint64_t port = 4420u;
    args = skip_spaces(args);
    if (*args != '\0' && (parse_number(&args, &port) != 0 || port == 0 || port >= 65536u)) {
        pl011_puts(&debug_uart, "usage: nvmet [port]  (default 4420; to stop, use `job stop <番号>` -- see `jobs`)\n");
        return;
    }

    /* bound_ctx=現在アクティブなインターフェース(g_active_ctx)。
     * 以前はNULL(全インターフェースで受付)だったが、
     * (1) `net use mlx5-pf1`→`nvmet`が「mlx5-pf1のターゲット」という直感に
     *     一致する、
     * (2) `pcie1 reset`がConnectX(mlx5-pf0/pf1)bindのTCP nvmetだけを畳める
     *     ようになる(nvmet_stop_connectx_instances()、bound_ctx=NULLだと
     *     ConnectX bindか判別できず対象外になっていた)、
     * という2つの理由でアクティブI/Fへbindする。net init前(g_active_ctx==
     * NULL)は従来通り全I/F受付にフォールバックする。RP1をアクティブにして
     * 起動したnvmetはRP1 bindになり、`pcie1 reset`では畳まれない(正しい)。 */
    const char *ifname = (g_active_ctx && g_active_ctx->name) ? g_active_ctx->name : "any";
    uart_printf("[nvmet] NVMe/TCPターゲット起動 (port=%u, 4MB RAMディスク, if=%s)\n",
                (unsigned)port, ifname);
    uart_printf("[nvmet] subnqn: %s\n", NVMET_SUBNQN);
    if (nvmet_job_start(&s_nvmet_ctx, (uint16_t)port, g_active_ctx, "manual") != 0) {
        uart_printf("[!] nvmet: 起動失敗\n");
    }
}

// `nprof`: nvme.c/nvmet.cのステートマシン(nvmet-admin/nvmet-io、
// nvme-connect(+その中のexecサブステートマシン)、nvme-io/exec)それぞれの
// 「各ステートに合計何ms滞在したか」をstateprof.h経由で表示する
// (~/.claude/plans/wondrous-baking-gadget.md「次回セッションへの申し
// 送り」節: ジャンボフレーム化の前に、core0(nvme、initiator)と
// core1(nvmet、target)のどちらがボトルネックかを判断するための計測)。
// `nprof reset`で全統計をゼロに戻す -- `test`コマンド等のベンチマーク
// 直前に呼び、ベンチ終了後に`nprof`(引数無し)でその区間だけの内訳を
// 見る使い方を想定している(そうしないと、接続待ち(ACCEPT_WAIT等)の
// 滞在時間が支配的になり実処理の内訳が埋もれてしまう、stateprof.h
// 冒頭コメント参照)。
static void cmd_nprof(const char *args) {
    unsigned word_len = 0;
    while (args[word_len] != '\0' && args[word_len] != ' ') word_len++;

    if (cmd_name_eq(args, word_len, "reset")) {
        nvme_connect_prof_reset();
        nvme_io_exec_prof_reset();
        for (unsigned i = 0; i < NVMET_MAX_INSTANCES; i++) {
            nvmet_ctx_prof_reset(NVMET_CTX_SLOT(i));
        }
        uart_printf("nprof: 全ステートマシンの滞在時間統計をリセットしました\n");
        return;
    }

    uart_printf("=== nvme (initiator側、常にcore0固定) ===\n");
    nvme_connect_prof_dump();
    nvme_io_exec_prof_dump();

    static const char *const NVMET_SLOT_LABELS[NVMET_MAX_INSTANCES] = {
        "slot0=rp1", "slot1=mlx5-pf0", "slot2=mlx5-pf1", "slot3=manual",
    };
    uart_printf("=== nvmet (target側、net_ctx_set_owner_core()で指定した"
                "コアに固定されうる) ===\n");
    for (unsigned i = 0; i < NVMET_MAX_INSTANCES; i++) {
        const nvmet_ctx_t *ctx = NVMET_CTX_SLOT(i);
        uart_printf("--- %s (session_active=%u) ---\n",
                    NVMET_SLOT_LABELS[i], (unsigned)ctx->session_active);
        nvmet_ctx_prof_dump(ctx);
    }
}

// `iperf3`: 標準iperf3クライアント(PC側)と相互接続できるiperf3サーバを
// 起動し、1セッションを処理する(TCPのみ、単一データストリーム -P 1)。
// クライアントが切断するまでブロックする(iperf3_run()参照)。
static void cmd_iperf3(const char *args) {
    uint64_t port = 5201u;
    args = skip_spaces(args);
    if (*args != '\0' && (parse_number(&args, &port) != 0 || port == 0 || port >= 65536u)) {
        pl011_puts(&debug_uart, "usage: iperf3 [port]  (default 5201)\n");
        return;
    }

    uart_printf("[iperf3] iperf3サーバ起動 (port=%u, TCPのみ, 単一ストリーム)\n", (unsigned)port);
    if (iperf3_run((uint16_t)port) != 0) {
        uart_printf("[!] iperf3: 失敗\n");
    }
}

// lineの先頭len文字がnameと完全一致するかを判定する。
static int cmd_name_eq(const char *line, unsigned len, const char *name) {
    for (unsigned i = 0; i < len; i++) {
        if (line[i] != name[i]) {
            return 0;
        }
    }
    return name[len] == '\0';
}

// 1行をコマンド名と引数に分割し、該当ハンドラを呼び出す。
static void dispatch(const char *line) {
    if (line[0] == '\0') {
        return;
    }

    unsigned name_len = 0;
    while (line[name_len] != '\0' && line[name_len] != ' ') {
        name_len++;
    }
    const char *args = skip_spaces(line + name_len);

    for (unsigned i = 0; i < NUM_COMMANDS; i++) {
        if (cmd_name_eq(line, name_len, COMMANDS[i].name)) {
            /* 直前のコマンド中に押されたCtrl+Cが残っていると、今回の
             * コマンドが開始した瞬間に即中断してしまう(tcp.hの
             * tcp_abort_requested()参照) -- 呼び出し直前に必ずクリアする。 */
            tcp_clear_abort_request();
            COMMANDS[i].handler(args);
            return;
        }
    }
    /* uart_printf()(pl011_puts(&debug_uart,...)直接呼びではなく)を使う --
     * telnetインスタンス1のdispatch()実行中はtelnet_output_redirect_*()
     * (uart_shim.cのuart_putc()参照)によりこの出力が正しくインスタンス1
     * 側へルーティングされる必要があるため。 */
    uart_printf("unknown command: '%s' (type 'help')\n", line);
}

#define LINE_MAX 128
#define HISTORY_MAX 64

/* 【2026-08-08変更、telnetのコアごと分離】コマンド履歴・行編集状態・
 * echo/入力の全てをTELNET_INSTANCE_COUNT個(インスタンス0=物理UART+
 * telnet0共有セッション、インスタンス1=telnet専用の完全独立セッション)
 * ぶん複製した -- ユーザー指示「print文も完全に独立」に合わせ、履歴も
 * 混ざらないようにする。 */
static char     history[TELNET_INSTANCE_COUNT][HISTORY_MAX][LINE_MAX];
static unsigned history_count[TELNET_INSTANCE_COUNT];

// 確定した1行をコマンド履歴に追加する。
static void history_push(unsigned instance, const char *line) {
    if (line[0] == '\0') {
        return;
    }
    if (history_count[instance] == HISTORY_MAX) {
        for (unsigned i = 1; i < HISTORY_MAX; i++) {
            for (unsigned j = 0; j < LINE_MAX; j++) {
                history[instance][i - 1][j] = history[instance][i][j];
            }
        }
        history_count[instance]--;
    }
    unsigned i = 0;
    while (line[i] != '\0' && i < LINE_MAX - 1) {
        history[instance][history_count[instance]][i] = line[i];
        i++;
    }
    history[instance][history_count[instance]][i] = '\0';
    history_count[instance]++;
}

/* 行編集のecho出力先(物理UART、またはtelnetインスタンス1のtx_ring)を
 * 抽象化する。インスタンス0は既存通りpl011_putc(&debug_uart,...)を直接
 * 使う(pl011_set_tap()経由でtelnetインスタンス0へも自動的にミラーされる、
 * telnet.h参照)。インスタンス1はtelnet_instance_putc(1,...)を直接使い、
 * 物理UARTには一切触れない(ユーザー指示「print文も完全に独立」)。 */
/* [関数ポインタ登録先 -- ctagsジャンプ補助] shell_line_poll_ex()へ渡される具体関数:
 *   echo_uart(このファイル、UART=instance0) / echo_telnet1(telnet=instance1)。 */
typedef void (*console_echo_fn)(char c);

static void echo_uart(char c) {
    pl011_putc(&debug_uart, c);
}

static void echo_telnet1(char c) {
    telnet_instance_putc(1u, c);
}

static void echo_puts(console_echo_fn echo, const char *s) {
    while (*s) echo(*s++);
}

// 表示中の行を消去し、new_contentに置き換えて表示する(履歴切り替え用)。
static void redraw_line_replace(console_echo_fn echo, char *line, unsigned *len,
                                 unsigned *pos, const char *new_content) {
    for (unsigned i = 0; i < *pos; i++) {
        echo('\b');
    }
    for (unsigned i = 0; i < *len; i++) {
        echo(' ');
    }
    for (unsigned i = 0; i < *len; i++) {
        echo('\b');
    }

    unsigned n = 0;
    while (new_content[n] != '\0' && n < LINE_MAX - 1) {
        line[n] = new_content[n];
        n++;
    }
    line[n] = '\0';
    *len = n;
    *pos = n;
    echo_puts(echo, line);
}

// 行編集の状態(カーソル位置・履歴呼び出し中のドラフト等)。以前は
// read_line()内のスタックローカル変数だったが、シェルのメインループを
// ノンブロッキング化する(job.h、CLAUDE.md「NVMe/TCP制御のステート
// マシン化」節参照)にあたり、「1文字読むごとにすぐ呼び出し元へ戻る」
// shell_line_poll()が呼び出しをまたいで状態を保持できるようstaticへ
// 格上げした。
typedef enum {
    LINE_ST_NORMAL = 0,  /* 通常の文字入力待ち */
    LINE_ST_ESC,         /* ESC受信、'['を待っている(最大50ms) */
    LINE_ST_ESC_SEQ,     /* ESC '[' 受信、方向文字(A/B/C/D)を待っている(最大50ms) */
} line_edit_state_t;

typedef struct {
    char     line[LINE_MAX];
    unsigned len;
    unsigned pos;
    char     draft[LINE_MAX];
    unsigned draft_len;
    unsigned hist_idx;
    int      browsing;
    line_edit_state_t state;
    uint64_t esc_started_ticks;  /* LINE_ST_ESC/LINE_ST_ESC_SEQへ入った時刻(50msタイムアウト起点) */
    /* 直前に読んだバイトが'\r'だったか(NVT改行"CR LF"/"CR NUL"の2バイト目
     * を読み捨てるための状態、telnet.cのtelnet_feed_byte()のlast_was_cr
     * と同じ理由・同じロジック)。物理UARTの生バイト列にはtelnet.cの
     * ような事前のCRLF正規化が無いため、この行編集レベルでも同じ対策が
     * 必要 -- 無いと、シリアル端末がEnterで"\r\n"の2バイトを送る場合、
     * '\r'で1行確定した直後に届く'\n'が新たな(空行の)Enterとして誤って
     * 二重に処理され、確定するたびにプロンプトの表示位置が徐々にずれる
     * 実機バグになる(shell_line_reset()では意図的にリセットしない --
     * 行確定をまたいで次の呼び出しまで持ち越す必要があるため)。 */
    int      last_was_cr;
} line_editor_t;

static line_editor_t s_editor_arr[TELNET_INSTANCE_COUNT];

static void shell_line_reset(unsigned instance) {
    line_editor_t *ed = &s_editor_arr[instance];
    ed->len       = 0;
    ed->pos       = 0;
    ed->draft_len = 0;
    ed->hist_idx  = history_count[instance];
    ed->browsing  = 0;
    ed->state     = LINE_ST_NORMAL;
}

// 1回のshell_line_poll_ex()呼び出しでRXドレインできる文字数の上限。以前は
// 1回の呼び出しにつき最大1文字しか読まなかったため、高速バースト入力時
// (tmux send-keys等による一括送信)にエコー送信(pl011_putc()、TX FIFOが
// 空くまでブロッキング待ち)の分だけ次のRXポーリングまでの間隔が空き、
// PL011のRX FIFO(16バイト)を溢れさせ、以降の文字が失われる/処理が
// 極端に遅延する事象を実機で確認した(CLAUDE.md「シェル入力の文字化け/
// ハング問題」節参照 -- LINE_MAXの大小とは無関係だった)。1回の呼び出しで
// RX FIFOが空になるまで(または本上限まで)まとめてドレインすることで、
// エコー送信のブロッキング時間がRXポーリング間隔に累積しないようにする。
// 16(PL011 RX FIFO実サイズ)より十分大きい値にしつつ、job_scheduler_
// tick()/net_poll_all_and_dispatch()を1回のメインループ反復内で
// 飢餓させないよう上限を設ける(無制限ループにはしない)。
#define SHELL_POLL_MAX_CHARS_PER_CALL 64u

/* 1文字読み取りを試みる関数の型。読めれば*outへ格納し1、無ければ0を
 * 返す(ブロッキングしない)。instance0は物理UART優先+telnetインスタンス0
 * を束ねた従来の入力窓、instance1はtelnetインスタンス1単独。 */
/* [関数ポインタ登録先 -- ctagsジャンプ補助] shell_line_poll_ex()へ渡される具体関数:
 *   instance0_try_read(このファイル、UART) / instance1_try_read(telnet)。 */
typedef int (*console_try_read_fn)(char *out);

static int instance0_try_read(char *out) {
    // 物理UARTとtelnetインスタンス0のクライアント(telnet.h参照)の
    // どちらから届いたバイトも同じ行編集ステートマシンで処理する --
    // 同じシェルセッションを覗く2つの窓として振る舞わせるため、意図的に
    // ソースを区別しない(telnet.hコメント参照)。
    if (pl011_tstc(&debug_uart)) {
        *out = pl011_getc(&debug_uart);  // tstc()で存在確認済みなのでブロックしない
        return 1;
    }
    if (telnet_console_tstc(0u)) {
        *out = telnet_console_getc(0u);
        return 1;
    }
    return 0;
}

static int instance1_try_read(char *out) {
    // インスタンス1は物理UARTに一切触れない(telnet.h参照)。
    if (telnet_console_tstc(1u)) {
        *out = telnet_console_getc(1u);
        return 1;
    }
    return 0;
}

// カーソル編集+履歴呼び出し付きの1行読み取り(Linuxシェルのreadline相当)を
// 進める。1回の呼び出しでRX FIFO(または相当のリングバッファ)に溜まって
// いる文字を(上記上限まで)まとめて処理し、それ以上届いていなければ即座に
// 0を返す(ブロッキングしない)。行が確定した(\r/\n受信)場合はその時点で
// 直ちに1を返し、s_editor_arr[instance].lineに確定行(NUL終端)が入る
// (行確定後に同じ入力窓に残っている文字は次の行の先頭のため、消費せず
// 次回呼び出しへ持ち越す)。矢印キーはESC `[` A/B/C/D の3バイトシーケンス
// として届くため、ESC受信後は専用のstate(LINE_ST_ESC/_SEQ)へ遷移し、
// 後続バイトが来なければ50ms相当で通常状態へ戻す。
static int shell_line_poll_ex(unsigned instance, console_try_read_fn try_read,
                               console_echo_fn echo) {
    line_editor_t *ed  = &s_editor_arr[instance];
    char     *line = ed->line;
    unsigned *len  = &ed->len;
    unsigned *pos  = &ed->pos;

    for (unsigned iter = 0; iter < SHELL_POLL_MAX_CHARS_PER_CALL; iter++) {
        if (ed->state != LINE_ST_NORMAL && timeout_ms(ed->esc_started_ticks, 50u)) {
            ed->state = LINE_ST_NORMAL;
        }

        char c;
        if (!try_read(&c)) {
            return 0;
        }

        if (ed->state == LINE_ST_ESC) {
            if (c == '[') {
                ed->state = LINE_ST_ESC_SEQ;
                ed->esc_started_ticks = timer_now();
            } else {
                ed->state = LINE_ST_NORMAL;
            }
            continue;
        }
        if (ed->state == LINE_ST_ESC_SEQ) {
            ed->state = LINE_ST_NORMAL;
            if (c == 'A') { // 上
                if (history_count[instance] == 0) {
                    continue;
                }
                if (!ed->browsing) {
                    for (unsigned i = 0; i < *len; i++) {
                        ed->draft[i] = line[i];
                    }
                    ed->draft_len = *len;
                    ed->browsing  = 1;
                    ed->hist_idx  = history_count[instance];
                }
                if (ed->hist_idx > 0) {
                    ed->hist_idx--;
                    redraw_line_replace(echo, line, len, pos, history[instance][ed->hist_idx]);
                }
            } else if (c == 'B') { // 下
                if (!ed->browsing) {
                    continue;
                }
                if (ed->hist_idx < history_count[instance] - 1) {
                    ed->hist_idx++;
                    redraw_line_replace(echo, line, len, pos, history[instance][ed->hist_idx]);
                } else {
                    ed->draft[ed->draft_len] = '\0';
                    redraw_line_replace(echo, line, len, pos, ed->draft);
                    ed->browsing = 0;
                }
            } else if (c == 'C') { // 右
                if (*pos < *len) {
                    echo(line[*pos]);
                    (*pos)++;
                }
            } else if (c == 'D') { // 左
                if (*pos > 0) {
                    (*pos)--;
                    echo('\b');
                }
            }
            continue;
        }

        // LINE_ST_NORMAL
        if (ed->last_was_cr && c == '\n') {
            // NVT改行の2バイト目("\r\n"のLF側)を読み捨てる(上記
            // line_editor_t.last_was_crコメント参照) -- 捨てないと
            // 空行のEnterが二重に確定し、確定のたびにプロンプトの
            // 表示位置が右へずれていく実機バグになる。
            ed->last_was_cr = 0;
            continue;
        }
        ed->last_was_cr = 0;

        if (c == '\r' || c == '\n') {
            ed->last_was_cr = (c == '\r');
            echo_puts(echo, "\r\n");
            line[*len] = '\0';
            return 1;
        }

        if (c == 0x1b) { // ESC -- 矢印キーの可能性
            ed->state = LINE_ST_ESC;
            ed->esc_started_ticks = timer_now();
            continue;
        }

        if (c == 0x03) { // Ctrl+C -- tcp_poll_once()のuart_check_ctrl_c()経由の
            // 検出と競合する(どちらが先にUARTからこのバイトを読むか次第で、
            // job側(nvmet等)が永久にCtrl+Cを検知できなくなることがあった。
            // tcp.hのtcp_request_abort()コメント参照)。ここで読んだ分は
            // 自分で同じフラグを立てて、job側からも見えるようにする
            // (2026-08-08時点でtcp_abort_requestedは単一の共有フラグ)。
            tcp_request_abort();
            continue;
        }

        if (c == 0x15) { // Ctrl+U -- 行全体をクリアする(カーソル位置・履歴呼び出し状態は不問)
            for (unsigned i = 0; i < *pos; i++) {
                echo('\b');
            }
            for (unsigned i = 0; i < *len; i++) {
                echo(' ');
            }
            for (unsigned i = 0; i < *len; i++) {
                echo('\b');
            }
            *len = 0;
            *pos = 0;
            continue;
        }

        if ((c == 0x7f || c == 0x08) && *pos > 0) { // バックスペース / DEL
            for (unsigned i = *pos - 1; i < *len - 1; i++) {
                line[i] = line[i + 1];
            }
            (*len)--;
            (*pos)--;
            echo('\b');
            for (unsigned i = *pos; i < *len; i++) {
                echo(line[i]);
            }
            echo(' ');
            unsigned back = (*len - *pos) + 1;
            for (unsigned i = 0; i < back; i++) {
                echo('\b');
            }
            continue;
        }

        if (c < 0x20 || c > 0x7e) {
            continue; // その他の制御文字は無視する
        }

        if (*len < LINE_MAX - 1) {
            for (unsigned i = *len; i > *pos; i--) {
                line[i] = line[i - 1];
            }
            line[*pos] = c;
            (*len)++;
            for (unsigned i = *pos; i < *len; i++) {
                echo(line[i]);
            }
            for (unsigned i = *pos + 1; i < *len; i++) {
                echo('\b');
            }
            (*pos)++;
        }
    }
    return 0;
}

// コマンドシェルのメインループ(戻らない)。以前はread_line()が1行分
// まるごとブロッキングしていたため、実行中のコマンド以外は何もできな
// かった。CLAUDE.md「NVMe/TCP制御のステートマシン化」節の方針に沿い、
// 毎回「1文字ぶんの行編集」「登録済み全ジョブ(job.h)のポーリング」
// 「ネットワーク受信ポーリング(netctx.hのnet_poll_all_and_dispatch()、
// 複数インターフェース対応)」を順に1回ずつ行ってから繰り返す。
// 個々のコマンドハンドラ(dispatch()経由)自体は引き続き同期・ブロッキング
// のまま(このフェーズの対象外) -- コマンド実行中はこのループ自体が
// 一時的に止まる点は従来と同じ。`ping`(cmd_ping())はこのフェーズで
// ジョブ化済みのため、実行中でも他のコマンドを受け付けられる。
//
// 休止(timer_delay_ms(1))は「本当にアイドル」な時だけ行う。フェーズ2
// (nvmet.cのジョブ化)実装直後、fioベンチマークでwrite性能が旧ブロッキング
// 実装比で90%以上低下する深刻な退行を実機で確認した -- 原因は、1コマンドの
// 処理に必要なジョブのstate遷移回数(nvmet_io_job_step()のWRITE経路はCMD
// 受信+H2CDataヘッダ/データ受信で複数PDUにまたがる)×この1ms休止がそのまま
// レイテンシの下限になっていたこと。この修正では「ジョブが1つでも登録
// されていれば休止しない」(job_active_count() == 0)という条件にした。
//
// 【2026-08-07追記: この条件だけでは不十分だったことが判明】`telnet`を
// 起動時に自動起動するようにした(main.c参照)ことで、telnetジョブが
// 常時登録された状態になり、job_active_count()が実質的に常に非ゼロに
// なった。結果、たとえ実際には誰も接続しておらず/どのジョブも進捗して
// いなくても休止が完全に無効化され、メインループが無制限に高速回転し
// 続けるようになった。実機の`ts`ログで、telnet/nvmet-admin/nvmet-ioの
// 各非ブロッキング受信(タイムアウト即返り)がマイクロ秒間隔で際限なく
// 繰り返され(数秒で1000万件超のログ)、実際のデータ受信(IDATタグ)は
// その中にほぼ埋もれるほど希少という状態を確認した -- CPU/RP1のPCIe2
// 経由レジスタアクセス(既知の通り遅い、CLAUDE.md「参照ドライバソース」
// 節等参照)がこの無意味なポーリングの奪い合いに費やされ、実データパスの
// 処理が圧迫されて`bs=256k` write性能が過去の実測(depth8で約71.6MB/s)の
// 1/10程度(約6.3MB/s)まで低下する退行を招いた。
//
// 修正(1回目、2026-08-07当初): 「ジョブが存在するか」ではなく「直近の
// tickで実際にネットワークフレームを受信したか」(net_poll_all_and_
// dispatch()の戻り値)を主な判定基準にし、COMMAND_IDLE_GRACE_TICKS(8)回
// 連続で何も受信しなかった場合のみ休止する版にした。
//
// 修正(2回目、同日中): 上記1回目の修正自体が、NVMe/TCP write性能の
// 実機再計測(fio --bs=256k --iodepth=1)で新たな退行を生んでいたと判明
// した -- depth=1の256KB書き込みが1コマンドあたり実測44.8ms
// (stdev=0.00、ネットワークジッタではなく本ロジックによる決定論的な
// 遅延であることの証拠)という、CLAUDE.md「NVMe/TCP Write性能: ホスト
// 自身の遅延ACKタイマーとの待ち合わせ」節で以前苦労して排除したのと
// ほぼ同じ規模の遅延が再発していた。原因: 256KBの書き込み1コマンドの
// 中でもセグメント間には(相手のTCP送信ペーシング等による)ごく短い
// 自然な間隙が挟まる。nvmet-io等のジョブがアクティブに転送を進めている
// 最中でも、この間隙がたった8回のポーリング(タイマー分解能未満のごく
// 短い時間)を超えるたびに「アイドル」と誤判定され、以後その間隙分
// timer_delay_ms(1)が確実に上乗せされていた。
//
// 修正(3回目、同日中、job_active_count_excluding("telnet")は却下): 上記
// 2回目の修正で「telnetを除いたジョブが1つでもあれば休止しない」に
// したところ、nvmet-admin/nvmet-io自身も(クライアント未接続の待受
// 状態でも)常時登録されたままの「telnetと同種」のジョブだったと判明
// した -- `nvmet <port>`は常駐サーバ化済み(CLAUDE.md「nvmetの常駐
// サーバ化」節参照)で、admin/ioジョブはクライアントの有無に関わらず
// 生き続ける。結果、`nvmet`を起動した時点でこの条件も実質常に非ゼロに
// なり、上記(3.節)と全く同じ「無条件busy-spin→CPU/RP1レジスタアクセス
// 競合→実データパス圧迫」の退行をそのまま再導入していた。Wiresharkで
// 検証したところ、host→board方向で実測1710件の本物の再送(全て1514B、
// LSOオフロードのキャプチャ側アーチファクトではない実サイズ一致)、
// board→host方向で5095件の重複ACKを確認 -- host側のRTOが実際に発火
// している証拠であり、DPUがデータを取りこぼしているのではなく、
// board側が時折(RSR.BNA/OVR/TXリングは共に正常、`err`/`txdump`で確認
// 済み)ACK送出そのものを大きく遅延させていたことを示す。
//
// 恒久修正: 「ジョブが存在するか」という間接的な代理指標をやめ、
// net_poll_all_and_dispatch()が実際にフレームを受信した「実時刻」を
// 直接追跡する。前回(1回目)の失敗はtick*回数*という単位を使った
// ことが原因(1回のポーリングにかかる実時間が短すぎて、データ転送
// 中のごく自然な数マイクロ秒の間隙ですら8tick分を一瞬で使い切って
// しまった)。timer_now()/timer_freq()による実時間の閾値
// (COMMAND_IDLE_GRACE_US、数ミリ秒)に切り替えれば、実データ転送中の
// セグメント間隙(ギガビットリンクでも通常サブミリ秒)はこの閾値を
// 超えず休止に入らない一方、真にアイドル(クライアント未接続、または
// 接続はあるがホスト側の都合でコマンド間隔が空いている)期間は正しく
// 検知して休止し、CPU/PCIeレジスタアクセスの奪い合いを防げる。
#define COMMAND_IDLE_GRACE_US 2000u
/* アイドル休止1回あたりのビジーウェイト時間(2026-08-13、writeパイプ
 * ライン化)。従来は1ms(timer_delay_ms(1))だったが、writeのコマンド間
 * ギャップのたびに最大1msの応答遅延を注入していたため50usへ短縮した
 * (下記command_shell_run()の該当箇所コメント参照)。 */
#define COMMAND_IDLE_SLEEP_US 50u

void command_shell_run(void) {
    pl011_puts(&debug_uart, "\nrpi5-boot command shell. Type 'help' for a list of commands.\n> ");
    shell_line_reset(0u);
    shell_line_reset(1u);

    /* 起動直後は即座にアイドル扱いにしたい(意図はコメント末尾参照) --
     * tick 0からの経過時間はcommand_shell_run()に到達するまでの起動処理
     * (platform_init等)だけで確実にCOMMAND_IDLE_GRACE_USを超えるため、
     * 単純に0で初期化するだけで成立する。 */
    uint64_t last_frame_tick = 0;

    while (1) {
        // インスタンス0: 従来通り、物理UART+telnetインスタンス0の共有
        // セッション。出力は既定のまま物理UART経由(pl011_set_tap()に
        // よりtelnetインスタンス0へも自動的にミラーされる)。
        if (shell_line_poll_ex(0u, instance0_try_read, echo_uart)) {
            s_current_console = 0u;
            history_push(0u, s_editor_arr[0].line);
            dispatch(s_editor_arr[0].line);
            pl011_puts(&debug_uart, "> ");
            shell_line_reset(0u);
        }

        // インスタンス1: telnet専用の完全独立セッション(telnet.h参照)。
        // dispatch()呼び出し全体をtelnet_output_redirect_*()で挟み、
        // 呼び出し先の数百箇所に散らばるuart_printf()呼び出しが物理UART
        // ではなくこのインスタンスのtx_ringへ直接届くようにする
        // (uart_shim.cのuart_putc()参照、ユーザー指示「print文も完全に
        // 独立」)。行編集自体のecho(echo_telnet1)は元々物理UARTに触れて
        // いないため、この窓の外でも安全。
        if (shell_line_poll_ex(1u, instance1_try_read, echo_telnet1)) {
            s_current_console = 1u;
            history_push(1u, s_editor_arr[1].line);
            telnet_output_redirect_begin(1u);
            dispatch(s_editor_arr[1].line);
            telnet_instance_puts(1u, "> ");
            telnet_output_redirect_end();
            shell_line_reset(1u);
        }

        job_scheduler_tick();
        if (net_poll_all_and_dispatch()) {
            last_frame_tick = timer_now();
        }
        if (timeout_us(last_frame_tick, COMMAND_IDLE_GRACE_US)) {
            /* 2026-08-13、writeパイプライン化: 従来の timer_delay_ms(1) は
             * 単なるビジーウェイト(電力節約ではない、timer.h参照)で、その1ms
             * の間ボードはjob処理も受信ポーリングも一切行わない。NVMe/TCP write
             * は「短いデータバースト+コマンド間の短いギャップ」の連続で、
             * ギャップのたびにこの1ms休止に入ると、CQE/ACKの送出が最大1ms遅れ、
             * ホストがそれを待つため1コマンド~5msに膨らんでいた(実機ts計測で
             * SLEPが1コマンドあたり数回発生、CLAUDE.md該当節)。1ms→50usへ短縮し、
             * ギャップ中もボードが~50us間隔でjob/受信を回して即応できるようにする
             * (真アイドル時のCPUスピンは増えるが、ビジーウェイトである以上元々
             * 電力は消費しており実害は無い)。 */
            timer_delay_us(COMMAND_IDLE_SLEEP_US);
        }
    }
}
