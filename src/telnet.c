// telnet.c
//
// telnet.h参照。シリアルコンソール(command.cのs_editor)へのもう1つの
// 入出力口をTCP port 23(既定)経由で提供する(インスタンス0)。加えて
// 2026-08-08、完全に独立した2つ目のセッション(インスタンス1、コア1向け)
// を追加した -- 設計意図・実行コアについての注記はtelnet.hコメント参照。

#include "telnet.h"
#include "tcp.h"
#include "pl011.h"
#include "uart.h"
#include "job.h"
#include "netctx.h"
#include "smp.h"

/* telnetプロトコル(RFC 854)の制御バイト。 */
#define TELNET_IAC   0xFFu
#define TELNET_DONT  0xFEu
#define TELNET_DO    0xFDu
#define TELNET_WONT  0xFCu
#define TELNET_WILL  0xFBu
#define TELNET_SB    0xFAu
#define TELNET_SE    0xF0u
#define TELNET_IP    0xF4u  /* Interrupt Process -- 一部のクライアントは
                             * ローカルのCtrl+Cを生バイト(0x03)ではなく
                             * このコマンドへ翻訳して送ってくる */

#define TELOPT_ECHO  1u
#define TELOPT_SGA   3u  /* Suppress Go-Ahead */

#define TELNET_TX_RING_SIZE 16384u
#define TELNET_RX_RING_SIZE 512u
#define TELNET_RECV_CHUNK   256u

typedef enum {
    TNP_DATA = 0,
    TNP_IAC,      /* IACを読んだ直後 */
    TNP_IAC_CMD,  /* WILL/WONT/DO/DONTの直後、オプション番号を待つ */
    TNP_SB,       /* サブネゴシエーション中(IAC SB ... IAC SE) */
    TNP_SB_IAC,   /* サブネゴ中にIACを見た(次がSEなら終了) */
} telnet_parse_state_t;

typedef enum {
    TELNET_ST_ARM = 0,
    TELNET_ST_WAIT_CONN,
    TELNET_ST_ACTIVE,
} telnet_state_t;

/* 1インスタンス分の全状態(送受信リング・ワイヤプロトコルパーサ・
 * コネクション/ジョブ状態)。インスタンス間で一切共有しない -- ユーザー
 * 指示「telnetをコアごとにできるようにしてほしい。print文も完全に独立」
 * を満たすため、telnet.hコメントの通り各フィールドを完全に複製した。 */
typedef struct {
    /* 出力(このインスタンスのクライアントへ送るバイト列)。
     *
     * tx_lock(マルチコア化 Phase 6、~/.claude/plans/wondrous-baking-
     * gadget.md参照): インスタンス0のtx_ring/tx_head/tx_tail/tx_countは、
     * pl011_set_tap()経由でどのコアのuart_printf()からも書き込まれうる
     * (core1にpin止めされたnvmet-admin/nvmet-io等のログも含む、
     * uart_printf()自身はpl011_lock()で1回の呼び出し全体を排他するが、
     * これは「複数コアの出力メッセージ同士が混線しない」ことしか保証
     * しない)一方、telnet_flush_tx()(tx_ringを読み出して消費する側、
     * telnet0のjobはcore0にpin止めされているため常にcore0から呼ばれる)は
     * pl011_lock()を一切取らない別経路であり、これら読み書き両側の
     * 排他を一切していなかった。実機でcore1オフロード(core=1へpin止め
     * したnvmet-io等)が稼働中にtelnet0(port 23)へ接続すると、tx_ring/
     * tx_countの非アトミックな複数フィールド更新がcore0(flush)とcore1
     * (書き込み)の間で競合し、telnetストリームへNULバイトが混入する
     * (リングバッファのインデックス破損)実機バグを発見した。tx_push()/
     * telnet_flush_tx()、および両方が触れるtx_head/tx_tail/tx_countの
     * 初期化箇所をこのロックで保護する。 */
    smp_spinlock_t tx_lock;
    volatile uint8_t tx_ring[TELNET_TX_RING_SIZE];
    volatile unsigned tx_head;
    volatile unsigned tx_tail;
    volatile unsigned tx_count;
    /* tcp_send()に渡す実際の送信バッファ(旧コメント参照: 送信中に
     * 再入でtx_ringへ新規バイトが積まれても、送信中のバッファ自身を
     * 書き換えないよう分離している)。64バイト境界アラインはtcp_send()の
     * ゼロコピー送信が要求する制約。 */
    uint8_t flush_buf[TELNET_TX_RING_SIZE] __attribute__((aligned(64)));

    /* 入力(このインスタンスのクライアントから受け取ったバイト列、
     * telnet_feed_byte()がIAC除去・CRLF正規化した後の平文データのみ)。 */
    volatile uint8_t rx_ring[TELNET_RX_RING_SIZE];
    volatile unsigned rx_head;
    volatile unsigned rx_tail;
    volatile unsigned rx_count;

    /* telnetワイヤプロトコルのパーサ状態。 */
    telnet_parse_state_t parse_state;
    uint8_t              pending_cmd;
    int                  last_was_cr;

    /* コネクション/ジョブ状態。 */
    volatile int    connected;
    volatile int    exit_requested;
    tcp_conn_t      conn;
    int             listener;
    uint16_t        port;
    int             started;
    unsigned        index;  /* 0または1、ログ/ジョブ名の表示にのみ使う */
} telnet_instance_t;

static telnet_instance_t s_inst[TELNET_INSTANCE_COUNT];

/* ------------------------------------------------------------------
 * インスタンス1専用の出力リダイレクト(telnet.hコメント参照)。
 * dispatch()の呼び出し全体を1つの単位として、そのインスタンス番号を
 * ここへ設定する -- このプロジェクトは単一物理コア上で複数の論理
 * セッションを協調的に切り替える設計(telnet.h冒頭の「実行コアに
 * ついての正直な注記」参照)なので、ネストや競合を心配する必要は無い。
 * ------------------------------------------------------------------ */
static volatile int s_redirect_instance = -1;  /* -1 = リダイレクト無し */

static void tx_push(telnet_instance_t *ti, uint8_t c)
{
    if (!ti->connected) {
        return;
    }
    smp_spin_lock(&ti->tx_lock);
    if (ti->tx_count >= TELNET_TX_RING_SIZE) {
        smp_spin_unlock(&ti->tx_lock);
        return;  /* 満杯 -- 黙って捨てる(シリアル側の表示には影響しない) */
    }
    ti->tx_ring[ti->tx_tail] = c;
    ti->tx_tail = (ti->tx_tail + 1u) % TELNET_TX_RING_SIZE;
    ti->tx_count++;
    smp_spin_unlock(&ti->tx_lock);
}

static void tx_push_bytes(telnet_instance_t *ti, const uint8_t *buf, unsigned len)
{
    for (unsigned i = 0; i < len; i++) {
        tx_push(ti, buf[i]);
    }
}

static void tx_push_str(telnet_instance_t *ti, const char *s)
{
    while (*s) {
        tx_push(ti, (uint8_t)*s++);
    }
}

void telnet_instance_putc(unsigned instance, char c)
{
    if (instance >= TELNET_INSTANCE_COUNT) return;
    tx_push(&s_inst[instance], (uint8_t)c);
}

void telnet_instance_puts(unsigned instance, const char *s)
{
    if (instance >= TELNET_INSTANCE_COUNT) return;
    tx_push_str(&s_inst[instance], s);
}

void telnet_output_redirect_begin(unsigned instance)
{
    if (instance >= TELNET_INSTANCE_COUNT) return;
    s_redirect_instance = (int)instance;
}

void telnet_output_redirect_end(void)
{
    s_redirect_instance = -1;
}

int telnet_output_redirect_active(void)
{
    return s_redirect_instance >= 0;
}

int telnet_output_redirect_putc(char c)
{
    if (s_redirect_instance < 0) {
        return 0;
    }
    tx_push(&s_inst[s_redirect_instance], (uint8_t)c);
    return 1;
}

/* pl011_set_tap()(pl011.h)に登録するフック本体。**インスタンス0専用**
 * -- debug_uartへ書かれた全バイトのコピーをインスタンス0のtx_ringへも
 * 流す(既存の「シリアルとインスタンス0のtelnetは同じセッションを覗く
 * 2つの窓」という設計、telnet.h参照)。インスタンス1は物理UARTに一切
 * 触れない設計のため、この仕組みの対象外(telnet_output_redirect_*()が
 * 代わりを担う)。 */
static void telnet_pl011_tap(char c)
{
    tx_push(&s_inst[0], (uint8_t)c);
}

/* ------------------------------------------------------------------
 * 入力側。
 * ------------------------------------------------------------------ */
static void rx_push(telnet_instance_t *ti, uint8_t c)
{
    if (ti->rx_count >= TELNET_RX_RING_SIZE) {
        return;  /* 満杯(通常は起こらない、shell_line_poll()の消費が速いため) */
    }
    ti->rx_ring[ti->rx_tail] = c;
    ti->rx_tail = (ti->rx_tail + 1u) % TELNET_RX_RING_SIZE;
    ti->rx_count++;
}

int telnet_console_tstc(unsigned instance)
{
    if (instance >= TELNET_INSTANCE_COUNT) return 0;
    return s_inst[instance].rx_count > 0;
}

char telnet_console_getc(unsigned instance)
{
    telnet_instance_t *ti = &s_inst[instance];
    uint8_t c = ti->rx_ring[ti->rx_head];
    ti->rx_head = (ti->rx_head + 1u) % TELNET_RX_RING_SIZE;
    ti->rx_count--;
    return (char)c;
}

/* ------------------------------------------------------------------
 * telnetワイヤプロトコルのパーサ(IAC WILL/WONT/DO/DONT/SBの最小限の
 * 処理)。オプション折衝はECHO/SGAをこちらが担う(WILL)以外は全て拒否
 * する(DONT/WONT)最小実装。
 * ------------------------------------------------------------------ */
static void telnet_reset_parser(telnet_instance_t *ti)
{
    ti->parse_state = TNP_DATA;
    ti->pending_cmd  = 0;
    ti->last_was_cr  = 0;
}

static void telnet_feed_byte(telnet_instance_t *ti, uint8_t c)
{
    switch (ti->parse_state) {
    case TNP_DATA:
        if (c == TELNET_IAC) {
            ti->parse_state = TNP_IAC;
            return;
        }
        /* NVT(RFC 854)の改行は"CR LF"または"CR NUL"の2バイト -- 1行分の
         * 改行として既にCRの時点でshell_line_poll()に渡しているので、
         * 直後に届く2バイト目は読み捨てる(捨てないと空行のEnterが
         * 二重に確定してしまう)。 */
        if (ti->last_was_cr && (c == '\n' || c == '\0')) {
            ti->last_was_cr = 0;
            return;
        }
        ti->last_was_cr = (c == '\r');
        rx_push(ti, c);
        return;

    case TNP_IAC:
        if (c == TELNET_IAC) {
            /* エスケープされた0xFFデータバイト(IAC IAC)。 */
            ti->last_was_cr = 0;
            rx_push(ti, c);
            ti->parse_state = TNP_DATA;
            return;
        }
        if (c == TELNET_WILL || c == TELNET_WONT || c == TELNET_DO || c == TELNET_DONT) {
            ti->pending_cmd  = c;
            ti->parse_state = TNP_IAC_CMD;
            return;
        }
        if (c == TELNET_SB) {
            ti->parse_state = TNP_SB;
            return;
        }
        if (c == TELNET_IP) {
            /* command.cのshell_line_poll()が生バイト0x03を見た場合と同じ
             * 経路(rx_push()経由)へ流す -- あちら側でtcp_request_abort()
             * が呼ばれる。 */
            rx_push(ti, 0x03u);
            ti->parse_state = TNP_DATA;
            return;
        }
        /* NOP/AYT/GA等、オプション番号を伴わない他の単純なコマンドは無視。 */
        ti->parse_state = TNP_DATA;
        return;

    case TNP_IAC_CMD: {
        uint8_t opt = c;
        if (ti->pending_cmd == TELNET_DO) {
            uint8_t reply[3] = {
                TELNET_IAC,
                (uint8_t)((opt == TELOPT_ECHO || opt == TELOPT_SGA) ? TELNET_WILL : TELNET_WONT),
                opt,
            };
            tx_push_bytes(ti, reply, 3);
        } else if (ti->pending_cmd == TELNET_WILL) {
            /* クライアント側が提供しようとするオプションは全て拒否する
             * (NAWS/TERM等、このCLIでは使わない)。 */
            uint8_t reply[3] = { TELNET_IAC, TELNET_DONT, opt };
            tx_push_bytes(ti, reply, 3);
        }
        /* WONT/DONTには返信不要(RFC 854)。 */
        ti->parse_state = TNP_DATA;
        return;
    }

    case TNP_SB:
        if (c == TELNET_IAC) {
            ti->parse_state = TNP_SB_IAC;
        }
        return;

    case TNP_SB_IAC:
        if (c == TELNET_SE) {
            ti->parse_state = TNP_DATA;
        } else if (c == TELNET_IAC) {
            ti->parse_state = TNP_SB;  /* エスケープされたIAC、サブネゴ継続 */
        } else {
            ti->parse_state = TNP_SB;
        }
        return;
    }
}

/* `exit`/`quit`シェルコマンド(command.cのcmd_exit())からの、現在接続中の
 * telnetクライアントだけを切断する要求(job停止=`job stop`とは別物 --
 * こちらはリスナー自体は維持し、次のクライアントを引き続き受け付ける)。 */
int telnet_request_exit(unsigned instance)
{
    if (instance >= TELNET_INSTANCE_COUNT) return 0;
    telnet_instance_t *ti = &s_inst[instance];
    if (!ti->connected) {
        return 0;
    }
    ti->exit_requested = 1;
    return 1;
}

/* s_telnet_tx_ringに溜まった出力をflush_bufへ退避してから1回の
 * tcp_send()で流す(退避理由は上記flush_bufコメント参照)。 */
static void telnet_flush_tx(telnet_instance_t *ti)
{
    /* tx_ring/tx_head/tx_countの読み出し・消費はtx_lock保持下で行う
     * (上記telnet_instance_t.tx_lockコメント参照) -- 他コアのtx_push()と
     * 排他する。flush_bufへ退避し終えたらロックを解放してからtcp_send()
     * する(ネットワーク送信という時間のかかりうる処理の間、他コアの
     * uart_printf()を待たせないため)。 */
    smp_spin_lock(&ti->tx_lock);
    if (ti->tx_count == 0) {
        smp_spin_unlock(&ti->tx_lock);
        return;
    }
    unsigned n2 = 0;
    while (ti->tx_count > 0 && n2 < TELNET_TX_RING_SIZE) {
        ti->flush_buf[n2++] = ti->tx_ring[ti->tx_head];
        ti->tx_head = (ti->tx_head + 1u) % TELNET_TX_RING_SIZE;
        ti->tx_count--;
    }
    smp_spin_unlock(&ti->tx_lock);
    /* 【重要】tcp_send()呼び出しをグローバルなCtrl+C中断フラグ
     * (tcp_abort_requested())から意図的に隔離している -- telnetのflushは
     * 単なるコンソール出力のミラーリングであり中断すべき対象ではない
     * (旧実装のコメント、実機で確認した無限ループ回避策、CLAUDE.md
     * 「NVMe/TCP制御のステートマシン化」節参照)。 */
    int had_abort = tcp_abort_requested();
    if (had_abort) {
        tcp_clear_abort_request();
    }
    /* tcp_send()->tcp_send_segment()は自分のconnへ向けてg_active_ctxを
     * 書き換える副作用を持つ(呼び出し後に元へ戻さない設計)。telnetの
     * flushは「他のシェル操作の合間に割り込む背景処理」であり、これが
     * 野放図にg_active_ctxを書き換えてしまうと、ユーザーが明示的に選んだ
     * インターフェースが背景送信1回で上書きされうる(旧実装のコメント、
     * 実機で確認したバグの経緯参照)。net_poll_all_and_dispatch()と同じ
     * 「呼び出し前の状態へ復元する」パターンをここにも適用する。 */
    net_ctx_t *prev_ctx = g_active_ctx;
    tcp_send(&ti->conn, ti->flush_buf, n2);
    net_ctx_activate(prev_ctx);
    if (had_abort) {
        tcp_request_abort();
    }
}

/* ------------------------------------------------------------------
 * ジョブ本体。nvmet.cのnvmet_admin_job_step()と同じ「常駐サーバ」
 * パターン(CLAUDE.md「nvmet: 常駐サーバ化」節参照) -- クライアントが
 * 切断してもJOB_DONEにはならず、次の接続を待つARM状態へ自動的に戻る。
 * インスタンス0・1のどちらでも共通で使う(self->ctxがtelnet_instance_t*
 * を指す)。
 * ------------------------------------------------------------------ */
static job_result_t telnet_job_step(job_t *self)
{
    telnet_instance_t *ti = (telnet_instance_t *)self->ctx;

    /* `job stop <番号>`(job.hのjob_request_cancel())による汎用の停止
     * 要求。nvmetのインスタンス単位の停止要求と違い、進行中のプロトコル
     * 交換を保護する必要が無いので(telnetは端末を1本切るだけ)、
     * ARM/WAIT_CONN/ACTIVEのどの状態でも即座に反映する。 */
    if (self->cancel_requested) {
        if (ti->connected) {
            tcp_close(&ti->conn);
            ti->connected = 0;
        }
        ti->exit_requested = 0;
        tcp_unlisten(ti->listener);
        ti->started = 0;
        uart_printf("[telnet%u] 停止しました\n", ti->index);
        return JOB_DONE;
    }

    switch ((telnet_state_t)self->state) {

    case TELNET_ST_ARM:
        tcp_accept_begin(ti->listener, &ti->conn);
        self->state = TELNET_ST_WAIT_CONN;
        return JOB_WAITING;

    case TELNET_ST_WAIT_CONN:
        if (tcp_accept_ready_poll(ti->listener)) {
            uart_printf("[telnet%u] クライアント接続完了\n", ti->index);
            telnet_reset_parser(ti);
            ti->rx_head = ti->rx_tail = ti->rx_count = 0;
            smp_spin_lock(&ti->tx_lock);
            ti->tx_head = ti->tx_tail = ti->tx_count = 0;
            smp_spin_unlock(&ti->tx_lock);
            ti->connected = 1;

            /* ECHO/SGAをこちらが担う(RFC 857/858) -- クライアントに
             * ローカルエコーを止めさせ、1文字ずつの生ストリームに
             * させる(shell_line_poll()の行編集は生バイト列を前提と
             * している)。 */
            {
                static const uint8_t negotiate[] = {
                    TELNET_IAC, TELNET_WILL, TELOPT_ECHO,
                    TELNET_IAC, TELNET_WILL, TELOPT_SGA,
                };
                tx_push_bytes(ti, negotiate, sizeof(negotiate));
            }
            tx_push_str(ti, "\r\nrpi5-boot telnet console. Type 'help' for a list of commands.\r\n> ");
            self->state = TELNET_ST_ACTIVE;
        }
        return JOB_WAITING;

    case TELNET_ST_ACTIVE: {
        /* `exit`/`quit`コマンドによる、このクライアントだけの切断要求
         * (telnet_request_exit()参照)。job stop(cancel_requested)と違い
         * リスナーは維持し、ARM状態へ戻って次の接続を待つ。 */
        if (ti->exit_requested) {
            ti->exit_requested = 0;
            tx_push_str(ti, "\r\n[telnet] 接続を終了します。\r\n");
            telnet_flush_tx(ti);
            uart_printf("[telnet%u] exitコマンドによりクライアントを切断しました\n", ti->index);
            tcp_close(&ti->conn);
            ti->connected = 0;
            self->state = TELNET_ST_ARM;
            return JOB_WAITING;
        }

        /* 受信: 1tickにつき1回だけの非ブロッキング試行(tcp_recv_no_ack()
         * のtimeout_ms=0トリック)。明示ACKを送らない(send_ack=0)理由:
         * 受信するたびに(通常は1文字ごとに)shell側のエコーが即座に
         * tcp_send()で流れる設計のため、ウィンドウ更新はそちらに
         * 自然に便乗する。 */
        uint8_t buf[TELNET_RECV_CHUNK];
        int n = tcp_recv_no_ack(&ti->conn, buf, sizeof(buf), 0);
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                telnet_feed_byte(ti, buf[i]);
            }
        } else if (n == 0 || ti->conn.state != TCP_ESTABLISHED) {
            /* n==0: 相手がFINを送った(半クローズ)。
             * n<0かつstateがESTABLISHEDでない: RST等でconnが失われた。 */
            uart_printf("[telnet%u] クライアント切断、次の接続を待ちます\n", ti->index);
            tcp_close(&ti->conn);
            ti->connected = 0;
            ti->exit_requested = 0;
            self->state = TELNET_ST_ARM;
            return JOB_WAITING;
        }

        /* 送信: このインスタンスのtx_ringに溜まった出力をまとめて流す。 */
        telnet_flush_tx(ti);
        return JOB_WAITING;
    }
    }

    return JOB_WAITING;
}

int telnet_server_start_instance(unsigned instance, uint16_t port, net_ctx_t *bound_ctx)
{
    if (instance >= TELNET_INSTANCE_COUNT) {
        uart_printf("[!] telnet: 無効なインスタンス番号 %u\n", instance);
        return -1;
    }
    telnet_instance_t *ti = &s_inst[instance];

    if (ti->started) {
        uart_printf("[telnet%u] 既に稼働中です(port=%u)\n", instance, (unsigned)ti->port);
        return -1;
    }

    int listener = tcp_listen(port, bound_ctx);
    if (listener < 0) {
        uart_printf("[!] telnet%u: リスナー確保失敗(TCP_MAX_LISTENERSに空きが無い)\n", instance);
        return -1;
    }

    ti->index    = instance;
    ti->listener = listener;
    ti->port     = port;
    ti->connected = 0;
    ti->tx_head = ti->tx_tail = ti->tx_count = 0;
    ti->rx_head = ti->rx_tail = ti->rx_count = 0;
    telnet_reset_parser(ti);

    if (instance == 0) {
        /* インスタンス0のみ物理UARTの出力をミラーする(telnet.h参照)。 */
        pl011_set_tap(telnet_pl011_tap);
    }

    /* job_spawn()のname引数は呼び出し元が生存期間中保持する静的文字列
     * である必要がある(job.hコメント参照) -- インスタンスごとの固定
     * 文字列リテラルをそのまま使う(mallocの無い環境のため動的生成しない)。 */
    static const char *const names[TELNET_INSTANCE_COUNT] = { "telnet0", "telnet1" };
    if (!job_spawn(telnet_job_step, ti, names[instance])) {
        uart_printf("[!] telnet%u: ジョブ生成失敗\n", instance);
        tcp_unlisten(listener);
        return -1;
    }

    ti->started = 1;
    uart_printf("[telnet%u] 待受開始 (port=%u)\n", instance, (unsigned)port);
    return 0;
}

int telnet_server_start(uint16_t port, net_ctx_t *bound_ctx)
{
    return telnet_server_start_instance(0, port, bound_ctx);
}
