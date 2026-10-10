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
/* ACK を間引く対象とする受信セグメントの最小長(0 = MSS/8)。`ackminseg`。 */
extern volatile uint32_t g_tcp_ack_min_seg;

/* ロス注入(シェルの `txdrop <N>`)。0=無効、N ならデータセグメント N 個に 1 個を
 * 送らずに捨てる。ループバックではロスが起きないため、高速再送の検証に要る。 */
extern volatile uint32_t g_tcp_tx_drop_every;
extern volatile uint32_t g_tcp_tx_dropped_count[SMP_MAX_CORES];

/* 握手のロス注入(シェルの `synackdrop <N>`)。次に送る SYN|ACK を N 個捨てる。
 * txdrop はデータを持つセグメントしか捨てないので、「相手の SYN 再送に
 * SYN|ACK を送り直す」経路を実機で通すにはこちらが要る。 */
extern volatile uint32_t g_tcp_synack_drop_next;
extern volatile uint32_t g_tcp_synack_retx_count;

/* Timestamps(RFC 7323)を提案するか(シェルの `tcpts on|off`)。0=提案しない
 * (陰性対照)。**コネクション単位で SYN の交換のときに決まる**ので、途中で
 * 変えても既存のコネクションには効かない。 */
extern volatile uint32_t g_tcp_ts_enable;
extern volatile uint32_t g_tcp_ts_rtt_samples;   /* TSecr から RTT を測った回数 */
extern volatile uint32_t g_tcp_paws_drop_count;  /* PAWS で捨てたセグメント数 */
extern volatile uint32_t g_tcp_rtt_update_count; /* RTT 推定を更新した総回数 */

/* SACK(RFC 2018)を提案するか(シェルの `tcpsack on|off`)。0=提案しない
 * (**段階 2 の Go-Back-N 一式へ戻る**。陰性対照)。 */
extern volatile uint32_t g_tcp_sack_enable;
extern volatile uint32_t g_tcp_sack_skipped_count; /* SACK 済みで送り直さずに済んだ数 */
extern volatile uint32_t g_tcp_sack_sent_count;    /* SACK ブロックを載せた ACK の数 */
extern volatile uint32_t g_tcp_sack_rx_count;      /* SACK オプションを読み取った回数 */
extern volatile uint32_t g_tcp_sack_probe_count;   /* 判定を試みた回数(切り分け用) */
extern volatile uint32_t g_tcp_sack_noinfo_count;  /* scoreboard が空だった回数 */
extern volatile uint32_t g_tcp_sack_debug;         /* `tcpsack debug` で 8 回ダンプ */
/* **重複 ACK がどの分岐で終わったかの内訳。** 「高速再送が 1 回も発火しない」
 * ときに原因を切り分けるのはこれしかない(recover ガードが ISN 次第で
 * 永久に効きっぱなしになるバグを、この内訳で見つけた)。 */
extern volatile uint32_t g_tcp_dup_suppressed;     /* Go-Back-N 補正で消費 */
extern volatile uint32_t g_tcp_dup_in_recovery;    /* 既に回復中(cwnd を膨らませただけ) */
extern volatile uint32_t g_tcp_dup_recover_guard;  /* recover ガードで却下 */
extern volatile uint32_t g_tcp_dup_rate_limited;   /* 1 RTT に 1 回の制限 */
extern volatile uint32_t g_tcp_dup_threshold_hit;  /* 3 個そろって高速再送を要求 */
extern volatile uint32_t g_tcp_fr_empty;           /* 要求されたのに 0 個しか送らなかった */
extern volatile uint32_t g_tcp_sack_use_tx;        /* 0=再送だけ Go-Back-N に戻す */
extern volatile uint32_t g_tcp_sack_partial_retx;  /* partial ACK で穴を送り直した回数 */

/* **実際に送り直したセグメント数。** g_tcp_retransmit_count は「再送を始めた
 * 回数」なので、Go-Back-N と SACK の差はこちらでないと見えない。 */
extern volatile uint32_t g_tcp_retransmit_segs;

/* Keepalive(RFC 1122 4.2.3.6)。シェルの `tcpkeepalive`。
 * **既定は慣例どおり 2 時間 + 75 秒 x 9 回。短くすると無通信だが生きている
 * 接続を切ってしまう**ので、検証のとき以外は縮めないこと。 */
extern volatile uint32_t g_tcp_keepalive_enable;
extern volatile uint32_t g_tcp_keepalive_idle_ms;
extern volatile uint32_t g_tcp_keepalive_intvl_ms;
extern volatile uint32_t g_tcp_keepalive_probes;
extern volatile uint32_t g_tcp_keepalive_probe_count;  /* 送った probe 数 */

/* 短い非同期送信の再送リングの実効本数と、満杯で待たされた回数
 * (シェルの `tcpasync`)。**ここがイニシエータのスループット上限**で、
 * 512B の in-capsule write はヘッダとデータで 2 本使う。 */
extern volatile unsigned g_tcp_async_short_cap;
/* 1 = これから送る長さまで含めて受信ウィンドウに収まるまで待つ(既定)。
 * 0 = 従来の「未確認 < ウィンドウ」だけを見る判定(陰性対照、`tcpasync winlen off`)。 */
extern volatile unsigned g_tcp_short_win_len;
/* 相手の受信ウィンドウを超えて送った回数(0=通常、1=LSO)と最後の様子(計測)。 */
extern volatile uint64_t g_tcp_win_over[2];
extern volatile uint32_t g_tcp_win_over_last_off, g_tcp_win_over_last_len, g_tcp_win_over_last_win;
extern volatile uint64_t g_tcp_zwp_count;   /* 窓が足りないときに送った窓の確認の数 */
extern volatile uint64_t g_tcp_async_short_stalls;
extern volatile uint64_t g_tcp_async_short_winwait;
extern volatile uint32_t g_tcp_win_last_usable;
extern volatile uint32_t g_tcp_win_last_outstanding;
extern volatile uint32_t g_tcp_win_last_cwnd;
extern volatile uint32_t g_tcp_win_last_sndwin;
#define TCP_ASYNC_SHORT_CAP_MAX 64u
extern volatile uint32_t g_tcp_keepalive_drop_count;   /* 応答が無くて畳んだ数 */
extern volatile uint32_t g_tcp_keepalive_reply_count;  /* 相手の probe に応えた数 */

/* 純 ACK(データを持たないセグメント)のロス注入。Keepalive の probe や
 * その応答を落として「相手が無反応」を作るのに使う(`txdrop` はデータを
 * 持つセグメントしか捨てない)。シェルの `ackdrop <N>`。 */
extern volatile uint32_t g_tcp_ack_drop_next;
extern volatile uint32_t g_tcp_ack_dropped_count;

/* RST の検証(RFC 5961 3)。窓外で捨てた数と challenge ACK を返した数。 */
extern volatile uint32_t g_tcp_rst_dropped_count;
extern volatile uint32_t g_tcp_rst_challenge_count;

uint32_t tcp_rx_buf_size(void);

int  tcp_abort_requested(void);

/* 冷たい経路のポーリングを 1 回(再送・TIME_WAIT・Keepalive の期限確認を
 * 含む)。net_poll_all_and_dispatch() だけでは時間で動く処理が進まない。 */
void tcp_poll(void);
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

/* 短い非同期送信の 1 セグメント上限。**512 ではなく 640 にしてある** --
 * NVMe/TCP の in-capsule write は「72 バイトのヘッダ + 512 バイトのデータ」で
 * 584 バイトになり、これを 1 セグメントで出せないと 1 コマンドが 2 パケットに
 * 割れて、相手のパケット処理能力を 2 倍消費する。
 *
 * **これは tcp_send_async() がどちらの経路を選ぶかの閾値**で、従来どおり
 * 小さい制御 PDU だけを短経路へ回す。 */
#define TCP_ASYNC_SHORT_MAX_LEN 640u

/* 短経路スロット 1 個のバッファ長。**閾値(上)とは別に大きく取ってある。**
 * tcp_send_async2() は「複数の PDU をまとめた 1 セグメント」をここへ入れる。
 * まとめたものを長経路(LSO)へ流すと壊れたので、短経路で 1 セグメントとして
 * 送り切る(CLAUDE.md「まとめた送信を長経路へ流してはいけない」)。 */
#define TCP_ASYNC_SHORT_SLOT_BYTES 9216u
int  tcp_send_async(tcp_conn_t *conn, const void *buf, uint16_t len);

int  tcp_send_async_ref(tcp_conn_t *conn, const void *buf, uint16_t len);

/* 2 断片を 1 セグメントとして送る。**PDU のヘッダと本体を別々に送ると
 * 相手が 2 パケットとして処理する**ので、小さい PDU はまとめること。
 * 合計が収まらなければ自動で 2 回に分けて従来動作へ落ちる。 */
int  tcp_send_async2(tcp_conn_t *conn, const void *buf1, uint16_t len1,
                     const void *buf2, uint16_t len2);
/* 短経路のスロットを予約して書き込み先を返し(NULL=失敗)、書いたら commit で送る。
 * 間に同じコネクションへの別の送信を挟まないこと(TLS の送信用、段階 G)。 */
uint8_t *tcp_send_async_reserve(tcp_conn_t *conn, uint16_t len);
int      tcp_send_async_commit(tcp_conn_t *conn, uint16_t len);

/* まだ ACK されていない送信済みバイト数(Nagle 的な溜め込みの判定用)。 */
uint32_t tcp_unacked_bytes(const tcp_conn_t *conn);

/* 借りている ACK を返す / 借りているかを見る(相乗りの後始末)。 */
int tcp_ack_flush(tcp_conn_t *conn);
void tcp_ack_flush_deferred(void);   /* ポーリング先頭で呼ぶ */
void tcp_set_ack_piggyback(tcp_conn_t *conn, int on);
int tcp_ack_owed(const tcp_conn_t *conn);
extern volatile uint32_t g_tcp_ack_piggyback;

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

/* 用意した受け皿を取り下げる。1=取り下げた時点で既に確立していた
 * (呼び出し側が tcp_close() すること)。 */
int  tcp_accept_cancel(int listener, tcp_conn_t *conn);

void tcp_unlisten(int listener);

/* 経路 MTU を学習したとき、その宛先の確立済みコネクションの snd_mss を
 * 切り下げる(pmtu_learn() から呼ばれる)。上げ直しはしない。 */
void tcp_pmtu_update(const netaddr_t *dst, uint16_t pmtu);

int tcp_window_scaling_enabled(const tcp_conn_t *conn);

/* 対象コネクションの Timestamps の状態と RTT 推定を返す(シェルの表示用)。
 * 戻り値 1=Timestamps 合意済み。srtt_us / rto_ms は NULL 可。 */
int tcp_conn_ts_info(const tcp_conn_t *conn, uint64_t *srtt_us, uint32_t *rto_ms);

/* 対象コネクションで SACK を合意しているか(シェルの表示用)。 */
int tcp_conn_sack_enabled(const tcp_conn_t *conn);

/* 検証用: 相手を騙って victim へ RST を 1 つ撃ち込む(`rsttest` の陰性対照)。
 * 正しい相手は窓外の RST を送ってこないので、自分で作るしかない。 */
void tcp_debug_inject_rst(const tcp_conn_t *victim, uint32_t seq);

void tcp_debug_dump_rx(const tcp_conn_t *conn);

#endif /* TCP_H */
