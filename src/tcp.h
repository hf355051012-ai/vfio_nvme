#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stddef.h>
#include "netif.h"
#include "smp.h"
#include "netaddr.h"

extern volatile uint32_t g_tcp_retransmit_count[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_fast_retransmit_count[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_dup_ack_count[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_ack_threshold;

/* ロス注入(シェルの `txdrop <N>`)。0=無効、N ならデータセグメント N 個に 1 個を
 * 送らずに捨てる。ループバックではロスが起きないため、高速再送の検証に要る。 */
extern volatile uint32_t g_tcp_tx_drop_every;
extern volatile uint32_t g_tcp_tx_dropped_count[SMP_MAX_CORES];

/* 握手のロス注入(シェルの `synackdrop <N>`)。次に送る SYN|ACK を N 個捨てる。
 * txdrop はデータを持つセグメントしか捨てないので、「相手の SYN 再送に
 * SYN|ACK を送り直す」経路を実機で通すにはこちらが要る。 */
extern volatile uint32_t g_tcp_synack_drop_next;
extern volatile uint32_t g_tcp_synack_retx_count;

uint32_t tcp_rx_buf_size(void);

int  tcp_abort_requested(void);
void tcp_clear_abort_request(void);

#define TCP_HDR_LEN 20u

/* フラグ(byteの下位6bit) */
#define TCP_FLAG_FIN 0x01u
#define TCP_FLAG_SYN 0x02u
#define TCP_FLAG_RST 0x04u
#define TCP_FLAG_PSH 0x08u
#define TCP_FLAG_ACK 0x10u
#define TCP_FLAG_URG 0x20u

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;  /* 上位4bit = ヘッダ長(32bitワード数、オプション無しなら5)。下位4bitは予約(0) */
    uint8_t  flags;        /* 下位6bit使用: URG ACK PSH RST SYN FIN (TCP_FLAG_*参照) */
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

typedef enum {
    TCP_CLOSED,
    TCP_SYN_SENT,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_TIME_WAIT,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_SYN_RCVD,
} tcp_state_t;

/* 毎パケット触るスカラを前半へ固め、17 バイトのアドレスは後半へ置く
 * (tcp_input() の 4-tuple 照合はポートを先に見るので、一致しないコネクション
 * のアドレスまで読みに行かずに済む)。アドレスの netaddr_t 化でこの構造体は
 * 36 -> 64 バイトに膨らんでおり、1 コマンドあたり約 180ns の固定コストとして
 * 残っている(CLAUDE.md「IPv6 対応の代償」参照)。
 *
 * ちょうど 64 バイト(パディング込み)にして 64 バイト境界へ揃えてある。
 * 実測では整列の有無で差は出なかったが、揃えておかないと「キャッシュライン
 * を跨いでいるせいでは」という疑いを毎回消せないので、疑う余地を無くす方を
 * 選んだ。パディングは明示し、サイズは _Static_assert で固定する
 * (フィールドを足してあふれたらビルドで落ちる)。 */
typedef struct __attribute__((aligned(64))) {
    volatile tcp_state_t state;        /*  0: 4 */
    volatile uint16_t    local_port;   /*  4: 2 */
    volatile uint16_t    remote_port;  /*  6: 2 */
    volatile uint32_t    snd_seq;      /*  8: 4  次に送るシーケンス番号 */
    volatile uint32_t    rcv_seq;      /* 12: 4  次に期待する受信シーケンス番号 */
    volatile uint32_t    snd_win;      /* 16: 4 */
    volatile uint16_t    snd_mss;      /* 20: 2 */
    uint8_t              pad0[2];      /* 22: 2  owner_core の 4 バイト整列用 */
    volatile unsigned    owner_core;   /* 24: 4 */
    /* IPv4/IPv6 の両方をこの型で持つ。L3 ヘッダを組み立てる直前にだけ
     * family を見て分岐する(tcp_send_segment 系)。 */
    netaddr_t            local_ip;     /* 28:17 */
    netaddr_t            remote_ip;    /* 45:17 */
    uint8_t              pad1[2];      /* 62: 2  64 バイトちょうどに揃える */
} tcp_conn_t;

_Static_assert(sizeof(tcp_conn_t) == 64,
               "tcp_conn_t は 1 キャッシュラインちょうどに収める(パディングを調整すること)");
_Static_assert(_Alignof(tcp_conn_t) == 64,
               "tcp_conn_t はキャッシュライン境界に揃える");

uint32_t tcp_conn_arg(const tcp_conn_t *conn, uint32_t value);

void tcp_connect_begin(tcp_conn_t *conn, uint32_t dst_ip, uint16_t dst_port);

/* IPv6 版。dst は 16 バイトのアドレス。ローカルアドレスはアクティブな
 * インターフェースのリンクローカルを使う。 */
void tcp_connect_begin6(tcp_conn_t *conn, const uint8_t dst_ip[16], uint16_t dst_port);

/* family を問わない能動 open。自分側アドレスは dst の family に合わせて
 * アクティブなインターフェースから決める(v4=netif の IPv4、v6=リンクローカル)。 */
void tcp_connect_begin_to(tcp_conn_t *conn, const netaddr_t *dst, uint16_t dst_port);

int  tcp_connect_poll(tcp_conn_t *conn);

int  tcp_send(tcp_conn_t *conn, const void *buf, uint32_t len);

#define TCP_ASYNC_MAX_LEN 32768u
int  tcp_send_async(tcp_conn_t *conn, const void *buf, uint16_t len);

int  tcp_send_async_ref(tcp_conn_t *conn, const void *buf, uint16_t len);

int  tcp_recv(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms);

int  tcp_recv_no_ack(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms);

typedef void (*tcp_recv_upcall_fn)(void *ctx, const volatile uint8_t *data, uint16_t len);

void tcp_set_recv_upcall(tcp_conn_t *conn, tcp_recv_upcall_fn fn, void *ctx);
void tcp_clear_recv_upcall(tcp_conn_t *conn);

/* pull型二重コピー時間計測(push vs pull 比較、検証後に撤去)。 */
void tcp_copy_stats_get(uint64_t *c2_ns, uint64_t *c2_by,
                        uint64_t *c3_ns, uint64_t *c3_by);

void tcp_close(tcp_conn_t *conn);

/* src / dst は L3 ヘッダから取り出した送信元・宛先。IPv4 でも IPv6 でも
 * 同じ入口を通る(4-tuple 照合は netaddr_t のまま行う)。dst は
 * 「アクティブなインターフェースの IPv4」と分かっているなら NULL でよい。 */
void tcp_input_addr(const uint8_t *pkt, uint16_t len,
                    const netaddr_t *src, const netaddr_t *dst);

/* IPv4 用の薄いラッパ(ip.c から呼ぶ)。 */
void tcp_input(const uint8_t *pkt, uint16_t len, uint32_t src_ip);

#define TCP_MAX_LISTENERS 8u

int tcp_listen(uint16_t port, netif_t *ctx);

void tcp_accept_begin(int listener, tcp_conn_t *conn);

/* listen backlog(シェルの `backlog [N]`)。0=無効(受け皿が用意されている
 * ときだけ SYN を受理する従来の挙動 = 陰性対照)。既定は TCP_BACKLOG。 */
extern volatile uint32_t g_tcp_backlog_max;
extern volatile uint32_t g_tcp_backlog_overflow_count;  /* 満杯で捨てた SYN */
extern volatile uint32_t g_tcp_backlog_accept_count;    /* 待ち行列から引き渡した数 */
void     tcp_backlog_set_max(unsigned depth);
void     tcp_backlog_stats(unsigned *waiting, unsigned *estab);
unsigned tcp_backlog_capacity(void);

int  tcp_accept_ready_poll(int listener);

void tcp_unlisten(int listener);

/* 経路 MTU を学習したとき、その宛先の確立済みコネクションの snd_mss を
 * 切り下げる(pmtu_learn() から呼ばれる)。上げ直しはしない。 */
void tcp_pmtu_update(const netaddr_t *dst, uint16_t pmtu);

int tcp_window_scaling_enabled(const tcp_conn_t *conn);

void tcp_debug_dump_rx(const tcp_conn_t *conn);

#endif /* TCP_H */
