// icmp.c
//
// ICMP Echo応答(ping応答) — フェーズ3
// Echo Request(type=8)を受けたら、識別子/シーケンス番号/データを
// そのままコピーしたEcho Reply(type=0)を構築し、チェックサムを
// 再計算してip_send()で送信元へ返す。
//
// 全ての多バイトフィールドアクセスは net.h の rd16be/rd32be/wr16be/wr32be
// (volatile経由のバイト単位アクセス)のみを使う。理由は net.h と arp.c の
// コメントを参照(SCTLR_EL1.M=0環境でのAlignment fault対策)。

#include <stddef.h>
#include "icmp.h"
#include "ip.h"
#include "netif.h"
#include "arp.h"
#include "net_buf.h"
#include "net.h"
#include "netif.h"
#include "uart.h"
#include "timer.h"
#include "smp.h"

/* ICMPヘッダ: type(1) + code(1) + checksum(2) + identifier(2) + sequence(2) = 8バイト。
 * それ以降は可変長データ(Echoの場合はそのまま折り返す)。 */
#define ICMP_HDR_LEN     8u
#define ICMP_OFF_TYPE    0u
#define ICMP_OFF_CODE    1u
#define ICMP_OFF_CHECKSUM 2u
#define ICMP_OFF_IDENT   4u
#define ICMP_OFF_SEQ     6u

volatile uint32_t g_icmp_echo_request_count[SMP_MAX_CORES];
volatile uint32_t g_icmp_echo_reply_sent_count[SMP_MAX_CORES];
volatile uint64_t g_icmp_echo_reply_time[SMP_MAX_CORES];

/* icmp_wait_echo_reply()向けの「直近に受信したEcho Reply」の記録。
 * ポーリング専用(割り込み無し)の単一コマンドループ前提なので、コア
 * ごとに一件分の記録で十分(同一コア内で複数の応答待ちが同時並行する
 * ことはない)。マルチコア化 Phase 4によりコアごとに独立配列化した --
 * icmp_handle()はフレームを受信したコアで実行されるため(net_poll_all_
 * and_dispatch()参照)、Phase 6で複数コアが並行してping/Echo応答を
 * 処理するようになっても混ざらない。 */
static volatile int      s_echo_reply_ready[SMP_MAX_CORES];
static volatile uint16_t s_echo_reply_ident[SMP_MAX_CORES];
static volatile uint16_t s_echo_reply_seq[SMP_MAX_CORES];

void icmp_handle(const uint8_t *data, size_t len,
                 const uint8_t src_ip[4], const uint8_t *src_mac)
{
    if (len < ICMP_HDR_LEN) {
        uart_printf("[ICMP] ヘッダ長不足 (len=%u < %u)\n", (unsigned)len, ICMP_HDR_LEN);
        return;
    }
    if (len > NET_BUF_SIZE) {
        /* 通常有り得ない(IPペイロードは最大1500バイト未満)が念のため */
        uart_printf("[!] icmp_handle: データ長超過 (%u)\n", (unsigned)len);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = data;

    uint8_t  type = in[ICMP_OFF_TYPE];
    uint8_t  code = in[ICMP_OFF_CODE];

    unsigned core = smp_core_index();

    if (type == ICMP_TYPE_ECHO_REPLY) {
        /* RTT計測用の時刻はここ、uart_printf()より前に取る。115200bpsの
         * ブロッキング出力は日本語混じりのこの1行だけで数ms掛かり、後で
         * timer_now()を取ると印字時間までRTTに混入してしまう(pingコマンドの
         * time=表示が実測より数ms大きくなる原因になっていた)。 */
        g_icmp_echo_reply_time[core] = timer_now();

        uint16_t ident = rd16be(in + ICMP_OFF_IDENT);
        uint16_t seq   = rd16be(in + ICMP_OFF_SEQ);
        uart_printf("[ICMP] Echo Reply 受信: id=%u seq=%u from %u.%u.%u.%u\n",
                    ident, seq, src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        s_echo_reply_ident[core] = ident;
        s_echo_reply_seq[core]   = seq;
        s_echo_reply_ready[core] = 1;
        return;
    }

    if (type != ICMP_TYPE_ECHO_REQUEST) {
        uart_printf("[ICMP] type=%u code=%u (Echo Request/Reply以外) 無視\n", type, code);
        return;
    }

    g_icmp_echo_request_count[core]++;

    uint16_t ident = rd16be(in + ICMP_OFF_IDENT);
    uint16_t seq   = rd16be(in + ICMP_OFF_SEQ);

    uart_printf("[ICMP] Echo Request 受信: id=%u seq=%u from %u.%u.%u.%u len=%u\n",
                ident, seq, src_ip[0], src_ip[1], src_ip[2], src_ip[3], (unsigned)len);

    /* Echo Reply構築用の作業バッファ。static(コンパイラ管理下の静的領域)
     * なので素のアクセスで安全 — スタック消費を避けるためにもstaticにする。
     * マルチコア化 Phase 4によりコアごとに独立配列化した -- 複数コアが
     * 並行してicmp_handle()を実行しうる(Phase 6参照)ため、共有のままだと
     * 送信内容が競合して壊れる。 */
    static uint8_t reply[SMP_MAX_CORES][NET_BUF_SIZE];

    /* 受信データ(識別子・シーケンス番号・ペイロード含む全体)をそのまま
     * コピーし、type だけ書き換える(RFC792: Echo Replyの要件どおり)。 */
    for (size_t i = 0; i < len; i++) reply[core][i] = in[i];

    reply[core][ICMP_OFF_TYPE] = ICMP_TYPE_ECHO_REPLY;
    reply[core][ICMP_OFF_CODE] = 0;
    wr16be(reply[core] + ICMP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */

    uint16_t csum = inet_checksum(reply[core], len);
    wr16be(reply[core] + ICMP_OFF_CHECKSUM, csum);

    int ret = ip_send(src_ip, src_mac, IP_PROTO_ICMP, reply[core], (uint16_t)len);
    if (ret == 0) {
        g_icmp_echo_reply_sent_count[core]++;
        uart_printf("[ICMP] Echo Reply 送信完了: id=%u seq=%u\n", ident, seq);
    } else {
        uart_printf("[!] ICMP: Echo Reply 送信失敗 (id=%u seq=%u)\n", ident, seq);
    }
}
