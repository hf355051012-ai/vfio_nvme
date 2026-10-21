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
/* **受信側で、届いたセグメントをそのまま使えなかった数(`nicstat`)。** コアごと。
 *   rx_ooo      : 順序が飛んだセグメントを先読みに入れた(その前が欠けている)
 *   rx_ooo_drop : 順序外の置き場に置けずに捨てた(接続の予算 tcprcvbuf 超え / 共有の置き場切れ)
 *   rx_dup      : 既に受け取った範囲を含むセグメント(相手の再送が無駄だった印)
 *   rx_nospace  : 順番どおりだが受信バッファに空きが無く受け取れなかった
 *   rx_csum_drop / rx_paws_drop : チェックサム不正 / PAWS で捨てた */
extern volatile uint32_t g_tcp_rx_ooo[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_rx_ooo_drop[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_rx_dup[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_rx_nospace[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_rx_csum_drop[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_rx_paws_drop[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_ack_threshold;
extern volatile uint32_t g_tcp_rwin_cap;
extern volatile uint8_t  g_tcp_rcv_wscale;
/* 接続ごとの受信の予算(順序外の置き場の上限、窓はその半分)。`tcprcvbuf`。 */
extern volatile uint32_t g_tcp_rcvbuf;
/* 陰性対照: 順序外を接続ごとに 64 セグメント・窓 64 x MSS にする。`tcpooo legacy`。 */
extern volatile uint8_t  g_tcp_ooo_legacy;
extern volatile uint32_t g_tcp_rx_ooo_pool_drop[];
void tcp_ooo_pool_stats(uint32_t *used, uint32_t *total, uint32_t *peak);
/* ACK を間引く対象とする受信セグメントの最小長(0 = MSS/8)。`ackminseg`。 */
extern volatile uint32_t g_tcp_ack_min_seg;
extern volatile uint32_t g_tcp_ack_hold;
extern volatile uint32_t g_tcp_ack_adapt;
extern volatile uint32_t g_tcp_ack_by_count[];
extern volatile uint32_t g_tcp_ack_by_expiry[];
extern volatile uint32_t g_tcp_ack_thin_off[];

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
extern volatile uint32_t g_tcp_dsack_enable;       /* 受け取り済みのデータに DSACK を返す(既定 1)*/
extern volatile uint32_t g_tcp_dsack_sent_count;   /* DSACK を載せた ACK の数 */
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

/* RACK-TLP(RFC 8985)と undo(RFC 3708 / 3522)。シェルの `tcprack`。既定はどれも有効。
 * RACK / TLP は SACK を合意した接続の非同期送信だけで働く(一括送信 tcp_send() は従来どおり)。 */
extern volatile uint32_t g_tcp_rack_enable;
extern volatile uint32_t g_tcp_tlp_enable;
extern volatile uint32_t g_tcp_undo_enable;
extern volatile uint32_t g_tcp_rack_lost;
extern volatile uint32_t g_tcp_rack_lost_timer;
extern volatile uint32_t g_tcp_rack_recovery;
extern volatile uint32_t g_tcp_rack_dup_skip;
extern volatile uint32_t g_tcp_rack_reord;
extern volatile uint32_t g_tcp_tlp_probes;
extern volatile uint32_t g_tcp_tlp_recovered;
extern volatile uint32_t g_tcp_tlp_redundant;
extern volatile uint32_t g_tcp_dsack_rx;
extern volatile uint32_t g_tcp_undo_armed;
extern volatile uint32_t g_tcp_undo_dsack;
extern volatile uint32_t g_tcp_undo_ts;
extern volatile uint32_t g_tcp_prr_enable;        /* PRR(RFC 6937)。既定 1 */
extern volatile uint32_t g_tcp_prr_deferred;      /* PRR の枠が無くて送り直しを後回しにした回数 */
extern volatile uint32_t g_tcp_prr_unstall;       /* 回復中に何も届かず PRR の枠を 1 MSS 開けた回数 */
extern volatile uint32_t g_tcp_undo_log_over;     /* 送り直しの控えが入り切らなかった回復 */
extern volatile uint32_t g_tcp_undo_dsack_foreign;/* この回復で送り直していない範囲への DSACK */
extern volatile uint32_t g_tcp_rack_minrtt_win_ms;/* 最小の往復時間の窓(既定 10,000 ms)*/
/* 接続ごとの RACK / PRR / undo の状態を表示する(`tcprack show`)。 */
void tcp_rack_show(void);

/* **実際に送り直したセグメント数。** g_tcp_retransmit_count は「再送を始めた
 * 回数」なので、Go-Back-N と SACK の差はこちらでないと見えない。 */
extern volatile uint32_t g_tcp_retransmit_segs;

/* Keepalive(RFC 1122 4.2.3.6)。シェルの `tcpkeepalive`。
 * **g_tcp_keepalive_enable は「これから張る接続の既定」**(既定 0 = 使わない。RFC 1122 の
 * MUST-25「既定は無効」)。接続ごとの有効 / 無効は tcp_set_keepalive() で変える(MUST-24)。
 * 時間は慣例どおり 2 時間 + 75 秒 x 9 回。**短くすると無通信だが生きている
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
extern volatile uint64_t g_tcp_async_long_winwait, g_tcp_async_long_cwndlim, g_tcp_async_long_full;
extern volatile uint32_t g_tcp_long_last_outstanding, g_tcp_long_last_cwnd, g_tcp_long_last_sndwin;
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
    /* 同時クローズ(RFC 9293 3.6)。自分の FIN がまだ ACK されないうちに相手の FIN が届いた。
     * 既存の値を変えないよう末尾に足した(ほかのファイルが数値で比べている所は無いが念のため)。 */
    TCP_CLOSING,
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
/* 3 断片版(ヘッダ + データ + データダイジェストを 1 セグメントで送る)。 */
int  tcp_send_async3(tcp_conn_t *conn, const void *buf1, uint16_t len1,
                     const void *buf2, uint16_t len2,
                     const void *buf3, uint16_t len3);
/* 短経路のスロットを予約して書き込み先を返し(NULL=失敗)、書いたら commit で送る。
 * 間に同じコネクションへの別の送信を挟まないこと(TLS の送信用、段階 G)。 */
uint8_t *tcp_send_async_reserve(tcp_conn_t *conn, uint16_t len);
int      tcp_send_async_commit(tcp_conn_t *conn, uint16_t len);

/* まだ ACK されていない送信済みバイト数(Nagle 的な溜め込みの判定用)。 */
uint32_t tcp_unacked_bytes(const tcp_conn_t *conn);
/* いま送れるバイト数(相手の受信窓と cwnd の小さいほう - 未確認)。足りないと長経路の送信は
 * その場で窓が空くのを待つ。 */
uint32_t tcp_send_room(const tcp_conn_t *conn, uint32_t *usable_out);
/* 相手がこれまでに広告した最大の受信窓(0 = まだ分からない)。 */
uint32_t tcp_peer_win_max(const tcp_conn_t *conn);
/* 短経路(tcp_send_async2/3)の再送用の枠の空きの数と、枠の数(`tcpasync` の実効本数)。 */
unsigned tcp_send_short_free(const tcp_conn_t *conn, unsigned *cap_out);
/* 長経路(LSO・ゼロコピー)の再送用の枠の空きの数と、枠の数。足りないと長経路の送信は
 * その場で ACK を待つ(その間、同じコアのほかのジョブは回らない)。 */
unsigned tcp_send_long_free(const tcp_conn_t *conn, unsigned *cap_out);

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
/* 自コアが持ち主の、確立済みの待ち行列エントリを受け皿へ渡す(ポーリングの先頭で呼ぶ)。 */
void tcp_backlog_service(void);

/* 用意した受け皿を取り下げる。1=取り下げた時点で既に使われていた(確立済み、
 * または SYN を直接受理して握手の途中。呼び出し側が tcp_close() すること)。 */
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
void tcp_conns_show(void);

/* ---- ICMP / ICMPv6 のエラーを TCP へ伝える(RFC 1122 4.2.3.9、RFC 5461、RFC 5927)----
 * 引用された TCP ヘッダ(quoted_tcp、先頭 8 バイト以上)の 4-tuple でコネクションを探し、
 * 引用の seq が SND.UNA <= seq < SND.NXT(送った範囲)に入っているかを確かめる
 * (外れていれば偽の ICMP として何もしない)。
 *   TCP_ICMP_SOFT - 一時的なエラー(Net/Host Unreachable、Time Exceeded、Parameter Problem)。
 *                   接続は切らず、記録だけする。
 *   TCP_ICMP_HARD - 相手にその口が無い(Protocol / Port Unreachable、ICMPv6 の Port
 *                   Unreachable)。接続の途中(SYN_SENT / SYN_RCVD)なら接続を失敗させる。
 *                   確立した後は SOFT と同じ扱い(RFC 5461)。
 *   TCP_ICMP_PMTU - Fragmentation Needed / Packet Too Big。検査だけして結果を返す
 *                   (呼び出し側が 1 のときだけ経路 MTU を学ぶ)。
 * local は引用の送信元(= 自分)、remote は引用の宛先(= 相手)。
 * 戻り値: 1=引用が自分の生きているコネクションのもので、seq も範囲内。0=それ以外。 */
#define TCP_ICMP_SOFT 0
#define TCP_ICMP_HARD 1
#define TCP_ICMP_PMTU 2
int tcp_icmp_error(const netaddr_t *local, const netaddr_t *remote,
                   const uint8_t *quoted_tcp, size_t qlen, int kind);
/* ICMP エラーの計数: 引用が自分の接続と範囲に合った(SOFT / HARD / PMTU)、合わなかった(偽物か古い)、
 * HARD で接続の途中を失敗させた。 */
extern volatile uint32_t g_tcp_icmp_soft_count, g_tcp_icmp_hard_count, g_tcp_icmp_pmtu_ok;
extern volatile uint32_t g_tcp_icmp_bogus_count, g_tcp_icmp_hard_abort;

/* ---- RFC に合わせて足した検査の計数(`rfctest tcp` と `tcpconns` が見る)---- */
extern volatile uint32_t g_tcp_ack_unsent_drop;    /* SND.NXT を越える ACK を捨てた(RFC 9293 3.10.7.4)*/
extern volatile uint32_t g_tcp_rx_oow_drop;        /* 受信窓の外のセグメントを捨てた(同 first check)*/
extern volatile uint32_t g_tcp_syn_challenge;      /* 同期済みの接続への SYN に challenge ACK(RFC 5961 4)*/
extern volatile uint32_t g_tcp_oow_ack_limited;    /* 窓外への ACK / challenge ACK を頻度の上限で省いた(RFC 5961 7)*/
extern volatile uint32_t g_tcp_noack_drop;         /* 同期済みで ACK ビットの無いセグメントを捨てた */
extern volatile uint32_t g_tcp_listen_rst;         /* 待ち受けのポートへの SYN 以外の ACK 付きに RST を返した */
extern volatile uint32_t g_tcp_ts_missing_drop;    /* Timestamps を合意したのに TS の無いセグメントを捨てた(RFC 7323 3.2)*/
extern volatile uint32_t g_tcp_retx_abort;         /* 再送の上限で接続を RST で閉じた(RFC 9293 3.8.3)*/
extern volatile uint32_t g_tcp_ack_time_flush;     /* 返していない ACK を時間の上限で返した(RFC 1122 4.2.3.2)*/
extern volatile uint32_t g_tcp_urg_rx;             /* 緊急ポインタが進んだ回数(RFC 9293 3.8.5)*/
extern volatile uint32_t g_tcp_synsent_rst;        /* SYN_SENT / SYN_RCVD で受け入れられない ACK に RST を返した */

/* 接続ごとの Keepalive の有効 / 無効(RFC 1122 4.2.3.6 の MUST-24)。既定は張ったときの
 * g_tcp_keepalive_enable。 */
void tcp_set_keepalive(tcp_conn_t *conn, int on);

/* 緊急データ(URG)。相手が送った緊急ポインタが、アプリがまだ読んでいない位置より先にあるか
 * (RFC 9293 3.8.5 の MUST-30/31「上位へ知らせる」)。データ自体は普段どおりストリームの中で渡す。
 * 戻り値: 1=緊急データの終わり(ポインタの位置)が読み出し位置より先にある、0=無い。
 * bytes_ahead: 読み出し位置から緊急データの終わりまでのバイト数(NULL 可)。 */
int tcp_urgent_mark(const tcp_conn_t *conn, uint32_t *bytes_ahead);

/* 送った最大の seq(SND.NXT。tcp_send() の再送中や高速再送中でも下がらない)。試験用。 */
uint32_t tcp_snd_max(const tcp_conn_t *conn);

/* 検証用: 相手を騙って victim へ任意のセグメントを 1 つ撃ち込む。victim が Timestamps を
 * 合意していれば TS を付ける(付けないと RFC 7323 の検査で捨てられる)。window は相手の
 * 広告窓としてそのまま(Window Scale 前の 16 ビット)書く。 */
void tcp_debug_inject(const tcp_conn_t *victim, uint8_t flags, uint32_t seq, uint32_t ack,
                      uint16_t window, const void *data, uint16_t len);
/* 検証用: 接続を持たない 4-tuple から任意のセグメントを撃ち込む(待ち受けへの ACK など)。
 * mss >= 0 なら MSS オプション(その値)を付ける(-1 = 付けない)。 */
void tcp_debug_inject_to(const netaddr_t *from, uint16_t from_port,
                         const netaddr_t *to, uint16_t to_port,
                         uint8_t flags, uint32_t seq, uint32_t ack, int mss);

#endif /* TCP_H */
