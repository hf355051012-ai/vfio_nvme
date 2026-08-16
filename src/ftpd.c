// ftpd.c
//
// ftpd.h参照。LAN経由(FTP、書き込み専用の最小実装)でのファームウェア
// 更新。telnet.c/nvmet.cと同じ「常駐ジョブ、1接続ずつ順に処理」パターン。

#include "ftpd.h"
#include "fwupdate.h"
#include "board.h"
#include "tcp.h"
#include "job.h"
#include "uart.h"
#include "timer.h"

extern char _start[]; // main.c/fwupdate.c参照。現在実行中のこのイメージの開始アドレス

/* データ接続待ちタイムアウト・チャンクサイズ等の定数。 */
#define FTPD_DATA_ACCEPT_TIMEOUT_MS 10000u
#define FTPD_CTRL_LINE_MAX          128u
#define FTPD_CTRL_RECV_CHUNK        128u
#define FTPD_DATA_RECV_CHUNK        4096u

typedef struct {
    int      ctrl_listener;
    int      data_listener;
    uint16_t ctrl_port;
    uint16_t data_port;
} ftpd_job_ctx_t;

static ftpd_job_ctx_t s_job_ctx;
static tcp_conn_t     s_ctrl_conn;
static tcp_conn_t     s_data_conn;
static int            s_started       = 0;
static int            s_data_armed    = 0;  // PASV済み、データ接続の到着待ち
static int            s_data_connected = 0;
static uint32_t       s_recv_total    = 0;
static uint64_t       s_data_wait_started = 0;  // FTPD_ST_WAIT_DATAへ入った時刻(タイムアウト起点)

/* 制御接続への応答送信用(tcp_send()は64バイト境界アラインを要求する、
 * telnet.cのs_flush_bufコメント参照)。 */
static uint8_t s_ctrl_reply_buf[256] __attribute__((aligned(64)));

static char     s_cmdline[FTPD_CTRL_LINE_MAX];
static unsigned s_cmdline_len = 0;

/* ------------------------------------------------------------------
 * 小さなヘルパ群(このプロジェクトはnostdlib、strlen/snprintf等は
 * 使わない -- pl011.c/uart_shim.cと同じ流儀で必要な分だけ自前実装)。
 * ------------------------------------------------------------------ */

static void ctrl_reply(const char *s)
{
    unsigned n = 0;
    while (s[n] != '\0' && n < sizeof(s_ctrl_reply_buf)) {
        s_ctrl_reply_buf[n] = (uint8_t)s[n];
        n++;
    }
    tcp_send(&s_ctrl_conn, s_ctrl_reply_buf, n);
}

static unsigned append_udec(uint8_t *buf, unsigned pos, unsigned val)
{
    char tmp[10];
    unsigned n = 0;
    if (val == 0) {
        tmp[n++] = '0';
    } else {
        while (val > 0) {
            tmp[n++] = (char)('0' + (val % 10u));
            val /= 10u;
        }
    }
    while (n > 0) {
        buf[pos++] = (uint8_t)tmp[--n];
    }
    return pos;
}

/* PASV応答の(h1,h2,h3,h4,p1,p2)。IPはs_ctrl_conn.local_ip(この接続を
 * 実際に受けたインターフェース自身のIP)を使う -- net_active_ip()
 * (g_active_ctx)はnet_poll_all_and_dispatch()が呼び出し前の状態へ復元
 * してしまうため、このタイミングでは「制御接続を受けたインターフェース」
 * と一致する保証が無い(netctx.hコメント参照、tcp_send_segment()が
 * net_ctx_find_by_ip()で同じ問題を回避しているのと同じ理由)。 */
static void send_pasv_reply(void)
{
    uint32_t ip = (uint32_t)s_ctrl_conn.local_ip;
    unsigned pos = 0;
    static const char pre[] = "227 Entering Passive Mode (";
    for (unsigned i = 0; pre[i] != '\0'; i++) {
        s_ctrl_reply_buf[pos++] = (uint8_t)pre[i];
    }
    pos = append_udec(s_ctrl_reply_buf, pos, (ip >> 24) & 0xFFu);
    s_ctrl_reply_buf[pos++] = ',';
    pos = append_udec(s_ctrl_reply_buf, pos, (ip >> 16) & 0xFFu);
    s_ctrl_reply_buf[pos++] = ',';
    pos = append_udec(s_ctrl_reply_buf, pos, (ip >> 8) & 0xFFu);
    s_ctrl_reply_buf[pos++] = ',';
    pos = append_udec(s_ctrl_reply_buf, pos, ip & 0xFFu);
    s_ctrl_reply_buf[pos++] = ',';
    pos = append_udec(s_ctrl_reply_buf, pos, ((unsigned)s_job_ctx.data_port >> 8) & 0xFFu);
    s_ctrl_reply_buf[pos++] = ',';
    pos = append_udec(s_ctrl_reply_buf, pos, (unsigned)s_job_ctx.data_port & 0xFFu);
    s_ctrl_reply_buf[pos++] = ')';
    s_ctrl_reply_buf[pos++] = '\r';
    s_ctrl_reply_buf[pos++] = '\n';
    tcp_send(&s_ctrl_conn, s_ctrl_reply_buf, pos);
}

static void send_226_complete(uint32_t total)
{
    static const char pre[] = "226 Transfer complete (";
    static const char post[] = " bytes).\r\n";
    unsigned pos = 0;
    for (unsigned i = 0; pre[i] != '\0'; i++) s_ctrl_reply_buf[pos++] = (uint8_t)pre[i];
    pos = append_udec(s_ctrl_reply_buf, pos, total);
    for (unsigned i = 0; post[i] != '\0'; i++) s_ctrl_reply_buf[pos++] = (uint8_t)post[i];
    tcp_send(&s_ctrl_conn, s_ctrl_reply_buf, pos);
}

static int word_eq_ci(const char *s, unsigned len, const char *name)
{
    for (unsigned i = 0; i < len; i++) {
        char c = s[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        if (c != name[i]) return 0;
    }
    return name[len] == '\0';
}

/* ------------------------------------------------------------------
 * ジョブ本体。telnet.c/nvmet.cと同じ「常駐サーバ」パターン。
 * ------------------------------------------------------------------ */
typedef enum {
    FTPD_ST_ARM = 0,
    FTPD_ST_WAIT_CTRL,
    FTPD_ST_CMD,
    FTPD_ST_WAIT_DATA,
    FTPD_ST_RECEIVING,
} ftpd_state_t;

static job_result_t ftpd_job_step(job_t *self)
{
    ftpd_job_ctx_t *jc = (ftpd_job_ctx_t *)self->ctx;

    /* `job stop <番号>`(job.hのjob_request_cancel())による汎用の停止
     * 要求。telnetと同じくどの状態でも即座に反映する。 */
    if (self->cancel_requested) {
        if (s_data_connected) {
            tcp_close(&s_data_conn);
            s_data_connected = 0;
        }
        if (s_ctrl_conn.state != TCP_CLOSED) {
            tcp_close(&s_ctrl_conn);
        }
        s_data_armed = 0;
        tcp_unlisten(jc->data_listener);
        tcp_unlisten(jc->ctrl_listener);
        s_started = 0;
        uart_printf("[ftpd] 停止しました\n");
        return JOB_DONE;
    }

    switch ((ftpd_state_t)self->state) {

    case FTPD_ST_ARM:
        s_data_armed = 0;
        s_data_connected = 0;
        s_recv_total = 0;
        s_cmdline_len = 0;
        tcp_accept_begin(jc->ctrl_listener, &s_ctrl_conn);
        self->state = FTPD_ST_WAIT_CTRL;
        return JOB_WAITING;

    case FTPD_ST_WAIT_CTRL:
        if (tcp_accept_ready_poll(jc->ctrl_listener)) {
            uart_printf("[ftpd] 制御接続完了\n");
            ctrl_reply("220 rpi5-boot fwupdate FTP ready.\r\n");
            self->state = FTPD_ST_CMD;
        }
        return JOB_WAITING;

    case FTPD_ST_CMD: {
        uint8_t buf[FTPD_CTRL_RECV_CHUNK];
        int n = tcp_recv_no_ack(&s_ctrl_conn, buf, sizeof(buf), 0);
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                uint8_t c = buf[i];
                if (c == '\r') {
                    continue;
                }
                if (c == '\n') {
                    s_cmdline[s_cmdline_len] = '\0';

                    unsigned wlen = 0;
                    while (wlen < s_cmdline_len && s_cmdline[wlen] != ' ') wlen++;

                    if (word_eq_ci(s_cmdline, wlen, "USER") || word_eq_ci(s_cmdline, wlen, "PASS")) {
                        ctrl_reply("230 OK, no login required.\r\n");
                    } else if (word_eq_ci(s_cmdline, wlen, "SYST")) {
                        ctrl_reply("215 UNIX Type: L8\r\n");
                    } else if (word_eq_ci(s_cmdline, wlen, "TYPE")) {
                        ctrl_reply("200 Type set.\r\n");
                    } else if (word_eq_ci(s_cmdline, wlen, "PWD")) {
                        ctrl_reply("257 \"/\" is the current directory.\r\n");
                    } else if (word_eq_ci(s_cmdline, wlen, "CWD")) {
                        ctrl_reply("250 OK.\r\n");
                    } else if (word_eq_ci(s_cmdline, wlen, "NOOP")) {
                        ctrl_reply("200 OK.\r\n");
                    } else if (word_eq_ci(s_cmdline, wlen, "PASV")) {
                        if (!s_data_armed) {
                            tcp_accept_begin(jc->data_listener, &s_data_conn);
                            s_data_armed = 1;
                        }
                        send_pasv_reply();
                    } else if (word_eq_ci(s_cmdline, wlen, "STOR")) {
                        if (!s_data_armed) {
                            ctrl_reply("503 PASV first.\r\n");
                        } else {
                            /* LOAD_ADDR/LOAD_MAX_SIZE(board.h)は既存のUART
                             * Xmodem版fwupdateと共有する受信先で、通常の
                             * .bss領域内にある(DMA_BSS_BASE等と違い固定
                             * アドレスへ切り出されていない) -- nvmet
                             * インスタンス等の大きな静的バッファがリンク
                             * 時にこの範囲へ配置されている場合、転送中に
                             * それらを上書きしうる。この制約はLAN経由でも
                             * UART経由でも同じで、本機能固有の問題ではない
                             * ため、ここでは新たな制限は課さない(受信先
                             * を安全な固定アドレスへ切り出す根本対応は
                             * 別課題)。 */
                            uart_printf("[ftpd] STOR受理、データ受信を開始します\n");
                            ctrl_reply("150 Opening data connection.\r\n");
                            s_recv_total = 0;
                            s_data_wait_started = timer_now();
                            self->state = FTPD_ST_WAIT_DATA;
                        }
                    } else if (word_eq_ci(s_cmdline, wlen, "QUIT")) {
                        ctrl_reply("221 Bye.\r\n");
                        if (s_data_connected) {
                            tcp_close(&s_data_conn);
                            s_data_connected = 0;
                        }
                        s_data_armed = 0;
                        tcp_close(&s_ctrl_conn);
                        self->state = FTPD_ST_ARM;
                    } else {
                        ctrl_reply("502 Command not implemented.\r\n");
                    }

                    s_cmdline_len = 0;
                    if (self->state != FTPD_ST_CMD) {
                        /* STOR/QUITで状態が変わった -- この受信バッチの
                         * 残りバイト(通常無い)は処理せず打ち切る。 */
                        break;
                    }
                    continue;
                }
                if (s_cmdline_len < FTPD_CTRL_LINE_MAX - 1) {
                    s_cmdline[s_cmdline_len++] = (char)c;
                }
                /* 上限超過分は黙って捨てる(異常に長い行、通常起こらない)。 */
            }
        } else if (n == 0 || s_ctrl_conn.state != TCP_ESTABLISHED) {
            uart_printf("[ftpd] 制御接続切断、次の接続を待ちます\n");
            if (s_data_connected) {
                tcp_close(&s_data_conn);
                s_data_connected = 0;
            }
            s_data_armed = 0;
            tcp_close(&s_ctrl_conn);
            self->state = FTPD_ST_ARM;
        }
        return JOB_WAITING;
    }

    case FTPD_ST_WAIT_DATA:
        if (tcp_accept_ready_poll(jc->data_listener)) {
            s_data_connected = 1;
            self->state = FTPD_ST_RECEIVING;
            return JOB_WAITING;
        }
        if (timeout_ms(s_data_wait_started, FTPD_DATA_ACCEPT_TIMEOUT_MS)) {
            uart_printf("[!] ftpd: データ接続待ちタイムアウト\n");
            ctrl_reply("425 Can't open data connection (timeout).\r\n");
            s_data_armed = 0;
            self->state = FTPD_ST_CMD;
        }
        return JOB_WAITING;

    case FTPD_ST_RECEIVING: {
        uint8_t buf[FTPD_DATA_RECV_CHUNK];
        int n = tcp_recv_no_ack(&s_data_conn, buf, sizeof(buf), 0);
        if (n > 0) {
            if (s_recv_total + (uint32_t)n > LOAD_MAX_SIZE) {
                uart_printf("[!] ftpd: 受信サイズがLOAD_MAX_SIZE(0x%x)を超過、中断します\n",
                            (unsigned)LOAD_MAX_SIZE);
                ctrl_reply("552 Requested file action aborted (too large).\r\n");
                tcp_close(&s_data_conn);
                s_data_connected = 0;
                s_data_armed = 0;
                self->state = FTPD_ST_CMD;
                return JOB_WAITING;
            }
            /* xmodem.cのblock_buf->buffer[]コピー(同じLOAD_ADDR受信先)と
             * 同じ、素朴な非volatileバイトコピー -- 可変データのコピー
             * ループはCLAUDE.md「ローカルスクラッチバッファへの逐次1バイト
             * 代入」節が警告する「同一定数の逐次代入をコンパイラが1回の
             * ワイドストアへ結合する」パターンには該当しない(結合される
             * とすればソース側の非アライン読み出しと組み合わさった
             * ベクトル化だが、実機で長期間動いているxmodem.cの前例に
             * 倣う)。 */
            uint8_t *dst = (uint8_t *)(LOAD_ADDR) + s_recv_total;
            for (int i = 0; i < n; i++) {
                dst[i] = buf[i];
            }
            s_recv_total += (uint32_t)n;
        } else if (n == 0) {
            /* 相手がFINを送った(半クローズ) -- クライアントがSTORの
             * データを送り終えて能動的に閉じた合図。TCPストリームの
             * バイト順序が保証されているため、ここまでに受信済みの
             * s_recv_totalバイトは完全なファイルとして安全に扱える
             * (telnet.c/nvmet_tcp.cの同種コメント参照)。 */
            tcp_close(&s_data_conn);
            s_data_connected = 0;
            s_data_armed = 0;

            if (s_recv_total == 0) {
                ctrl_reply("552 No data received.\r\n");
                self->state = FTPD_ST_CMD;
                return JOB_WAITING;
            }

            uart_printf("[ftpd] %u バイト受信完了 (0x%x)、ジャンプします。\n",
                        (unsigned)s_recv_total, (unsigned)LOAD_ADDR);
            /* 新しいイメージへジャンプする前に、クライアントへ成功応答が
             * 実際に届くのを待つ(tcp_send()は相手のACKを待つ同期送信、
             * fwupdate.cのUART版が最後にメッセージを表示してからジャンプ
             * するのと同じ考え方 -- ジャンプ後は全ての接続状態が失われる
             * ため、この応答を送りそびれるとクライアントは正常終了か
             * どうか分からずタイムアウトするまで待たされる)。 */
            send_226_complete(s_recv_total);
            fwupdate_jump_to_image(LOAD_ADDR, (uint64_t)s_recv_total, 0);
            /* 到達しない(成功時)。以後のコードは書かない。 */
        } else if (s_data_conn.state != TCP_ESTABLISHED) {
            /* RST等でデータ接続を失った -- 不完全なデータなので絶対に
             * ジャンプしてはならない(壊れた/未完了のイメージへジャンプ
             * すると即座にクラッシュするか、最悪未定義動作になる)。 */
            uart_printf("[!] ftpd: データ接続が失われました(%u バイト受信時点、"
                        "転送失敗)\n", (unsigned)s_recv_total);
            ctrl_reply("426 Connection closed; transfer aborted.\r\n");
            s_data_connected = 0;
            s_data_armed = 0;
            self->state = FTPD_ST_CMD;
        }
        return JOB_WAITING;
    }
    }

    return JOB_WAITING;
}

int ftpd_start(uint16_t port, uint16_t data_port, net_ctx_t *bound_ctx)
{
    if (s_started) {
        uart_printf("[ftpd] 既に稼働中です(port=%u)\n", (unsigned)s_job_ctx.ctrl_port);
        return -1;
    }

    if ((uint64_t)_start != PRIMARY_BASE) {
        uart_printf("[!] ftpd: プライマリイメージから実行中でないため起動できません"
                    "(チェインロードされたペイロード上ではfwupdateの受信先を安全に"
                    "扱えない、fwupdate.hコメント参照)。`reboot`でプライマリへ戻って"
                    "から再実行してください\n");
        return -1;
    }

    int ctrl_listener = tcp_listen(port, bound_ctx);
    if (ctrl_listener < 0) {
        uart_printf("[!] ftpd: 制御リスナー確保失敗(TCP_MAX_LISTENERSに空きが無い)\n");
        return -1;
    }
    int data_listener = tcp_listen(data_port, bound_ctx);
    if (data_listener < 0) {
        uart_printf("[!] ftpd: データリスナー確保失敗(TCP_MAX_LISTENERSに空きが無い)\n");
        tcp_unlisten(ctrl_listener);
        return -1;
    }

    s_job_ctx.ctrl_listener = ctrl_listener;
    s_job_ctx.data_listener = data_listener;
    s_job_ctx.ctrl_port     = port;
    s_job_ctx.data_port     = data_port;
    s_data_armed = 0;
    s_data_connected = 0;
    s_recv_total = 0;
    s_cmdline_len = 0;

    if (!job_spawn(ftpd_job_step, &s_job_ctx, "ftpd")) {
        uart_printf("[!] ftpd: ジョブ生成失敗\n");
        tcp_unlisten(data_listener);
        tcp_unlisten(ctrl_listener);
        return -1;
    }

    s_started = 1;
    uart_printf("[ftpd] 待受開始 (制御port=%u, データport=%u、PASVのみ対応)\n",
                (unsigned)port, (unsigned)data_port);
    return 0;
}
