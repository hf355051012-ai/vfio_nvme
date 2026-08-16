#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stddef.h>
#include "netif.h"
#include "smp.h"
#include "netaddr.h"

extern volatile uint32_t g_tcp_retransmit_count[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_ack_threshold;

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
 * 36 -> 62 バイトに膨らんでおり、1 コマンドあたり約 180ns の固定コストとして
 * 残っている(CLAUDE.md「IPv6 対応の代償」参照)。64 バイト境界への整列も
 * 試したが実測で差が出なかったので付けていない。 */
typedef struct {
    volatile tcp_state_t state;
    volatile uint16_t    local_port;
    volatile uint16_t    remote_port;
    volatile uint32_t    snd_seq;   /* 次に送るシーケンス番号 */
    volatile uint32_t    rcv_seq;   /* 次に期待する受信シーケンス番号 */
    volatile uint32_t    snd_win;
    volatile uint16_t    snd_mss;
    volatile unsigned    owner_core;
    /* IPv4/IPv6 の両方をこの型で持つ。L3 ヘッダを組み立てる直前にだけ
     * family を見て分岐する(tcp_send_segment 系)。 */
    netaddr_t            local_ip;
    netaddr_t            remote_ip;
} tcp_conn_t;

uint32_t tcp_conn_arg(const tcp_conn_t *conn, uint32_t value);

void tcp_connect_begin(tcp_conn_t *conn, uint32_t dst_ip, uint16_t dst_port);

/* IPv6 版。dst は 16 バイトのアドレス。ローカルアドレスはアクティブな
 * インターフェースのリンクローカルを使う。 */
void tcp_connect_begin6(tcp_conn_t *conn, const uint8_t dst_ip[16], uint16_t dst_port);

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

int  tcp_accept_ready_poll(int listener);

void tcp_unlisten(int listener);

int tcp_window_scaling_enabled(const tcp_conn_t *conn);

void tcp_debug_dump_rx(const tcp_conn_t *conn);

#endif /* TCP_H */
