#include "ipsec.h"
#include <stddef.h>
#include "tcp.h"
#include "ip.h"
#include "ipv6.h"
#include "netif.h"
#include "arp.h"
#include "net_buf.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "cache.h"
#include "job.h"
#include "smp.h"
#include "pmtu.h"
#include "crypto.h"   /* ISN と一時ポートの鍵付きハッシュ(RFC 6528 / RFC 6056)*/

uint64_t g_tcp_copy2_ns = 0, g_tcp_copy2_bytes = 0;
uint64_t g_tcp_copy3_ns = 0, g_tcp_copy3_bytes = 0;
/*=================================================================
 * 受信経路のコピー時間累積(rx_buf への push とそこからの排出)を取り出す。
 * 律速要因の切り分け用の計装。
 *
 * 引数:
 *   c2_ns / c2_by - net_buf -> rx_buf コピーの累積 ns とバイト数
 *   c3_ns / c3_by - rx_buf -> 呼び出し元バッファのコピーの累積 ns とバイト数
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
void tcp_copy_stats_get(uint64_t *c2_ns, uint64_t *c2_by,
                        uint64_t *c3_ns, uint64_t *c3_by)
{
    if (c2_ns) *c2_ns = g_tcp_copy2_ns;
    if (c2_by) *c2_by = g_tcp_copy2_bytes;
    if (c3_ns) *c3_ns = g_tcp_copy3_ns;
    if (c3_by) *c3_by = g_tcp_copy3_bytes;
}

#define TCP_OFF_SRC_PORT    offsetof(tcp_header_t, src_port)
#define TCP_OFF_DST_PORT    offsetof(tcp_header_t, dst_port)
#define TCP_OFF_SEQ         offsetof(tcp_header_t, seq)
#define TCP_OFF_ACK         offsetof(tcp_header_t, ack)
#define TCP_OFF_DATA_OFFSET offsetof(tcp_header_t, data_offset)
#define TCP_OFF_FLAGS       offsetof(tcp_header_t, flags)
#define TCP_OFF_WINDOW      offsetof(tcp_header_t, window)
#define TCP_OFF_CHECKSUM    offsetof(tcp_header_t, checksum)
#define TCP_OFF_URGENT      offsetof(tcp_header_t, urgent_ptr)

/* TCPオプションのkind値 (RFC793/RFC879/RFC7323)。 */
#define TCP_OPT_KIND_END    0u
#define TCP_OPT_KIND_NOP    1u
#define TCP_OPT_KIND_MSS    2u
#define TCP_OPT_KIND_WSCALE 3u
#define TCP_OPT_KIND_TS     8u  /* Timestamps (RFC 7323) */

/* Timestamps はオプション本体が 10 バイト。4 バイト境界へ揃えるため NOP を
 * 2 個前置して 12 バイトで送る(慣例。Linux も同じ並びで出す)。
 * **有効にすると 1 セグメントあたりのペイロードが 12 バイト減る**ので、
 * conn->snd_mss から引くのを忘れないこと(引き忘れるとフルサイズの
 * セグメントだけがリンク MTU を超えて NIC に無言で捨てられる)。 */
#define TCP_TS_OPT_LEN      12u

#define TCP_OPT_KIND_SACK_PERM 4u  /* SACK-Permitted (RFC 2018) */
#define TCP_OPT_KIND_SACK      5u  /* SACK ブロック本体 */

/* SACK-Permitted は kind+len の 2 バイト。4 バイト境界へ揃えるため NOP を
 * 2 個付けて 4 バイトで送る。 */
#define TCP_SACK_PERM_OPT_LEN  4u

/* 1 つの ACK に載せる SACK ブロックの最大数。Timestamps(12)と同居すると
 * 12 + (2 + 2 + 8*n) <= 40 から n <= 3。オプション領域の上限 40 バイトを
 * 超えるとデータオフセット(4bit、最大 15 ワード = 60 バイト)に入らない。 */
#define TCP_SACK_MAX_BLOCKS    3u
#define TCP_UNDO_LOG          16u   /* 1 回の回復で控える送り直しの範囲の数 */

/* 受信側で保持する「届いている区間」の数。穴の数だけあればよく、実際には
 * 1〜2 個しか使わない。溢れたら古いものを捨てる(相手が余分に送り直す
 * だけで、正しさは失われない)。 */
#define TCP_SACK_TX_MAX        4u

#define TCP_MSS_LOCAL           10182u
/* 相手が MSS オプションを付けなかった場合の既定値(RFC 9293 3.7.1 の MUST-15)。
 * IPv4 は 576 - 20 - 20 = 536、IPv6 は最小 MTU 1280 - 40 - 20 = 1220(RFC 8200 / RFC 9293)。 */
#define TCP_MSS_DEFAULT_RFC879   536u
#define TCP_MSS_DEFAULT_V6      1220u
/* 相手が名乗る MSS の下限。**0 や極端に小さい値をそのまま使うと、MSS で割る所(LSO のセグメント数、
 * cwnd の増分)が 0 除算になり、1 バイトずつ送る送信ループが事実上止まる。** Linux の TCP_MIN_MSS と同じ 88
 * (IPv4 の最小 MTU 576 から余裕を見た値)。 */
#define TCP_MSS_MIN               88u

/* 再送を諦めるまでの時間(RFC 1122 4.2.3.5 の R2)。**回数ではなく時間で決める** -- RTO の最大値
 * (TCP_MAX_RTO_MS = 8 秒)は性能のための意図的な値なので、回数だけで決めると 23 秒ほどで切れてしまう。
 *   データ: 100 秒以上(RFC 1122 4.2.3.5)
 *   SYN  : 3 分以上(同 MUST-23)。アプリはそれより早く諦めてよい(呼び出し側の時間切れ)。 */
#define TCP_R2_DATA_MS      100000u
#define TCP_R2_SYN_MS       180000u

/* 返していない ACK を返すまでの時間の上限(RFC 1122 4.2.3.2 の MUST-40 は 500 ms 未満)。
 * 普段は受信の周回数(ackhold)で返すので、これはポーリングが止まりがちなときの保険。Linux の
 * 遅延 ACK の上限(200 ms)に揃えた。 */
#define TCP_DELACK_MAX_MS     200u

/* 窓外のセグメントへの ACK と challenge ACK の頻度の上限(RFC 5961 7)。
 * 接続ごとに 500 ms に 1 回(Linux の tcp_invalid_ratelimit)、challenge ACK はさらにコアごとに 1 秒 1000 回
 * (Linux の tcp_challenge_ack_limit)。**データを運ぶセグメントへの ACK は絞らない**(DSACK を運ぶため。
 * Linux の tcp_oow_rate_limited() も同じ)。 */
#define TCP_OOW_ACK_GAP_MS    500u
#define TCP_CHALLENGE_PER_SEC 1000u

/* コアごとのコネクション数の上限。1 セッションで admin 1 + IO
 * NVMET_IO_QUEUES(16)本を握り、さらに listen backlog(4)と内蔵
 * イニシエータ(admin+IO の 2 本)が同時に生きうるので 23 本。余裕を見て 32。
 * **`tcp_priv_t` が rx_buf を抱えているのでここは .bss へ直結する** --
 * 増やす前に TCP_RX_BUF_SIZE の見積もりを確認すること。 */
#define TCP_MAX_CONNS 32u

/* **順番どおり届いたデータの置き場(コネクションごと)。**
 * **広告ウィンドウはここではなく `ooo[]` の容量(64 x MSS = 約 589KB)で
 * 頭打ちになる**(tcp_wire_window())ので、16MB は 27 倍の過剰だった。
 * `s_priv[SMP_MAX_CORES][TCP_MAX_CONNS]` に埋まっているため、16MB のままだと
 * **4 コア x 12 本で約 800MB**を .bss に置くことになり、IO キューを
 * 増やすとそれだけで破綻する。ウィンドウの上限(589KB)の 3.5 倍あれば
 * 「アプリが読み出すのが遅れたぶんの余裕」として十分。 */
#define TCP_RX_BUF_SIZE (2u * 1024u * 1024u)

#define TCP_RECV_NOACK_ACK_THRESHOLD_MSS 2u

/* 自分が名乗る Window Scale。窓は最大 65535 << 7 = 約 8.4MB まで表せる
 * (既定の窓 = tcprcvbuf の半分 = 4MB に足りる値。Linux は tcp_rmem の上限に合わせて決める)。 */
#define TCP_RCV_WSCALE 7u

#define TCP_INITIAL_RTO_MS      500u
#define TCP_RTO_MIN_MS           200u
#define TCP_MAX_RTO_MS         8000u
#define TCP_MAX_RETRIES            5

/* RFC 5681 の Fast Retransmit は重複 ACK 3 個で発火する。3 未満にすると
 * 単なる順序入れ替えを損失と誤検出して無駄な再送が増える。 */
#define TCP_DUP_ACK_THRESHOLD      3u

/* tcp_send() の全体の打ち切りは「相手から何も届かない時間」= TCP_R2_DATA_MS(MUST-37。以前は送り始めて 30 秒)。 */
#define TCP_CLOSE_FIN_WAIT_MS        2000u  /* 自分のFINがACKされた後、相手のFINを待つ時間 */

/* 陰性対照(`tcpooo legacy`)のときだけ使う、接続ごとの順序外のセグメント数の上限と窓の上限
 * (64 x MSS)。既定はバイト数の予算(g_tcp_rcvbuf)で抑える。 */
#define TCP_OOO_SLOTS 64u

/* **順序外に届いたセグメントの置き場は、全接続で共有する領域から取る**(Linux と同じく
 * 個数ではなく量で抑えるため)。枠は 2 種類で、セグメントの長さで使い分ける。
 * 使用量は枠の大きさで数える(Linux が skb の truesize で数えるのと同じ)。
 *   小: 2KB  x 8192 = 16MB(MSS 1448 の相手や小さい PDU)
 *   大: 10KB x 6144 = 60MB(ジャンボフレームの 1 セグメント。TCP_MSS_LOCAL が収まる) */
#define TCP_OOO_SMALL_BYTES 2048u
#define TCP_OOO_SMALL_N     8192u
#define TCP_OOO_BIG_BYTES   10240u
#define TCP_OOO_BIG_N       6144u
#define TCP_OOO_NODES       (TCP_OOO_SMALL_N + TCP_OOO_BIG_N)
#define TCP_OOO_NONE        0xFFFFu

#define TCP_ASYNC_SLOTS 16u

#define TCP_ASYNC_SLOTS_MLX5_EXTRA    16u
#define TCP_ASYNC_MLX5_OVERFLOW_CONNS 8u

/* 短い非同期送信の再送スロット数(配列の大きさ)。**実際に使う本数は
 * `g_tcp_async_short_cap`(既定 16 = 従来値)** で、`tcpasync` から変えられる。
 *
 * **ここがイニシエータのスループット上限を決めている。** 満杯になると
 * tcp_send_async_short() が ACK を待って**その場でブロックする**ので、
 * 「NVMe の深さをいくら上げても、ACK されていないセグメントは
 * この本数まで」になる。512B の in-capsule write は**ヘッダとデータで
 * 2 本使う**ので、16 本 = 同時 8 コマンドぶんしかパイプに入らない。 */
#define TCP_ASYNC_SHORT_SLOTS   64u

/* 実効本数(1..TCP_ASYNC_SHORT_SLOTS)。**ベンチの合間に変えること** --
 * リングに要素が残っている状態で変えると添字がずれて再送内容が壊れる。 */
/* **既定は 64。** 16(元の値)だと、受信をまとめて進めたときに 1 周で
 * 多数のコマンドが送信され、スロットを使い切って ACK 待ちでブロックする
 * (4K write で実測 91k、64 本なら 118k)。配列は最初から
 * TCP_ASYNC_SHORT_SLOTS 本あるので、増やしてもメモリは増えない。 */
volatile unsigned g_tcp_async_short_cap = 64u;
volatile unsigned g_tcp_short_win_len = 1u;

/* 満杯で待たされた回数(`tcpasync` で表示)。**送信側が詰まっているかを
 * 見る唯一の手段。** */
volatile uint64_t g_tcp_async_short_stalls;

/* 送信ウィンドウ(相手の広告窓 or 自分の cwnd)が空くのを待った回数と、
 * 最後に待たされたときの値。**write だけが遅い**ときにここを見る --
 * read はコマンド 72B しか送らないので窓を使い切らない。 */
volatile uint64_t g_tcp_async_short_winwait;
volatile uint32_t g_tcp_win_last_usable;
volatile uint32_t g_tcp_win_last_outstanding;
volatile uint32_t g_tcp_win_last_cwnd;
volatile uint32_t g_tcp_win_last_sndwin;
/* 長経路(tcp_send_async / _ref)で待った回数。窓が空くのを待ち始めた回数(うち自分の cwnd が
 * 相手の窓より小さかった回数)と、再送スロットが満杯で待った回数。最後の値も控える。 */
volatile uint64_t g_tcp_async_long_winwait;
volatile uint64_t g_tcp_async_long_cwndlim;
volatile uint64_t g_tcp_async_long_full;
volatile uint32_t g_tcp_long_last_outstanding;
volatile uint32_t g_tcp_long_last_cwnd;
volatile uint32_t g_tcp_long_last_sndwin;

volatile uint32_t g_tcp_retransmit_count[SMP_MAX_CORES];

/* 高速再送で実際に送り直したセグメント数。g_tcp_retransmit_count(全再送)の
 * 内数なので、差が RTO 由来の再送になる。「RTO ではなく 3 dup ACK で再送された」
 * ことを実機で確認するための計測点。再送を要求した回数ではなく**送った回数**を
 * 数える(要求だけ立って未確認データが無く空振りした分を混ぜないため)。 */
volatile uint32_t g_tcp_fast_retransmit_count[SMP_MAX_CORES];

/* 受信した重複 ACK の総数。高速再送の発火数と突き合わせると、検出が
 * 効きすぎていないか(1 回のロスに対し何回入り直しているか)が分かる。 */
volatile uint32_t g_tcp_dup_ack_count[SMP_MAX_CORES];

/* 受信側で使えなかったセグメントの数(tcp.h の説明を参照)。どれも冷たい経路でだけ増える。 */
volatile uint32_t g_tcp_rx_ooo[SMP_MAX_CORES];
volatile uint32_t g_tcp_rx_ooo_drop[SMP_MAX_CORES];
volatile uint32_t g_tcp_rx_dup[SMP_MAX_CORES];
volatile uint32_t g_tcp_rx_nospace[SMP_MAX_CORES];
volatile uint32_t g_tcp_rx_csum_drop[SMP_MAX_CORES];
volatile uint32_t g_tcp_rx_paws_drop[SMP_MAX_CORES];

/* **既定 4(= 大きい受信セグメント 4 個ごとに ACK)。** 受信セグメントごとに ACK を返すと、相手(送り手)は
 * その ACK の受信処理に CPU を取られる。OptiPlex の Linux / SPDK のイニシエータから自作のターゲットへ書き込むとき、
 * 送り手の時間の約 1 割が ACK の受信処理だった。4 にすると(MiB/s、ターゲット 1 コア):
 *
 * | イニシエータ | 条件 | ackthresh 1 | 2 | 4 |
 * |---|---|---|---|---|
 * | Linux(fio、2 ポート)| 書き込み 64KiB / 256KiB | 3,619 / 3,770 | 3,819 / 3,999 | 4,596 / 5,002 |
 * | Linux | 読み出し 8k / 64k / 256k | 1,760 / 4,338 / 4,377 | 1,622 / 4,344 / 4,343 | 1,793 / 4,371 / 4,452 |
 * | spdk_nvme_perf | 書き込み 256KiB | 4,779〜4,845 | 5,030〜5,055 | 5,133〜5,196 |
 *
 * 返していない ACK は、次にこちらから送るセグメント(応答など)に相乗りするか、受信の周回
 * `g_tcp_ack_hold` 回のうちに必ず返す(相手がデータを送り終えて黙ったときに、相手の再送タイマまで
 * 待たせないため)。`ackthresh 1` が 1 セグメントごとに ACK する陰性対照。 */
volatile uint32_t g_tcp_ack_threshold = 4u;
/* 間引いて返していない ACK を返すまでの受信の周回数(`ackhold N`、0 = 上限なし = 次に送るセグメントまで待つ)。
 * 1 周は 0.3〜0.4 マイクロ秒なので、64 で約 25 マイクロ秒。 */
volatile uint32_t g_tcp_ack_hold = 64u;
/* 間引きをやめる判定(`ackadapt N`、既定 50、0 = 判定しない)。間引いて返さなかった ACK が、4 個溜まって返る前に
 * 期限切れで返った割合が N% 以上なら、その接続では間引きをやめる(以後 1 個ごとに ACK)。相手が送信バッファの
 * 小さい送り手で、ACK が返るまで次を送れずに止まっていることの印である。判定は返し方 256 回ごと。
 * 期限切れの割合は、spdk_nvme_perf の平文の書き込みで 2〜9%、Linux の iSCSI で 0%、spdk_nvme_perf の TLS(OpenSSL の
 * ssl ソケット)で 95〜99%。TLS の接続を間引き続けると、64KiB 以上の書き込みが 1,608 / 1,840 → 1,117 MiB/s に落ちる。 */
volatile uint32_t g_tcp_ack_adapt = 50u;
/* 間引いた ACK の返し方の計数(コアごと): 4 個溜まって返した / 期限切れで返した / 間引きをやめた接続の数 */
volatile uint32_t g_tcp_ack_by_count[SMP_MAX_CORES];
volatile uint32_t g_tcp_ack_by_expiry[SMP_MAX_CORES];
volatile uint32_t g_tcp_ack_thin_off[SMP_MAX_CORES];
/* [試験] 受信窓の上限を手で決める(`tcprwin <バイト>`、0 = 既定の上限 = 順序外の枠と受信キューの容量)。
 * 1,048,560 を超えるときは、次に張る接続から Window Scale を 6 にする(4 では 65535 << 4 で頭打ち)。 */
volatile uint32_t g_tcp_rwin_cap = 0u;
volatile uint8_t  g_tcp_rcv_wscale = TCP_RCV_WSCALE;
/* 接続ごとの受信の予算(バイト、Linux の sk_rcvbuf に当たる。`tcprcvbuf`)。順序外の置き場の使用量
 * (枠の大きさで数える)をこの値まで許し、**広告する窓はその半分にする**(Linux の
 * tcp_adv_win_scale = 1 と同じ。枠の大きさとデータの長さの差を吸収する余白)。 */
volatile uint32_t g_tcp_rcvbuf = 8u * 1024u * 1024u;
/* 陰性対照: 1 にすると順序外を接続ごとに 64 セグメント・窓 64 x MSS までにする(`tcpooo legacy`)。 */
volatile uint8_t  g_tcp_ooo_legacy = 0u;
/* 共有の置き場が尽きて捨てた数(コアごと)と、置き場の使用量の最大(バイト)。 */
volatile uint32_t g_tcp_rx_ooo_pool_drop[SMP_MAX_CORES];
volatile uint32_t g_tcp_ooo_pool_peak;

/* ACK を間引く対象とする受信セグメントの最小長(0 = MSS/8 を使う)。
 * **小さいセグメント(write の応答 PDU など)を待たせないため。** */
volatile uint32_t g_tcp_ack_min_seg = 0u;

/* **ACK を応答セグメントへ相乗りさせるとき、何周まで借りておくか**
 * (`ackpiggy N`)。**0 が相乗り前の挙動 = 陰性対照。**
 * 1 = ポーリング 1 周だけ待つ。大きくすると応答が出るまで待つ確率が上がり
 * パケットは減るが、応答が出ない条件では ACK が遅れる。
 * upcall を持つコネクション(nvmet の IO キュー)でだけ効く。 */
volatile uint32_t g_tcp_ack_piggyback = 2u;

/* 人為的な送信破棄(高速再送の検証用)。0=無効、N なら「データを持つセグメント」
 * N 個に 1 個を、送ったことにして捨てる。DAC 直結ループバックではパケットロスが
 * まず起きないので、ロス検出経路(3 dup ACK -> 高速再送)を実機で通すには
 * これしか手が無い。シェルの `txdrop <N>` で切り替える。
 *
 * ホットパスに入るのは g_tcp_tx_drop_every のロードと分岐 1 つだけ(無効時は
 * tcp_tx_should_drop() を呼びさえしない)。 */
volatile uint32_t g_tcp_tx_drop_every;
static uint32_t   s_tcp_tx_drop_counter[SMP_MAX_CORES];
volatile uint32_t g_tcp_tx_dropped_count[SMP_MAX_CORES];

/* 次に送る SYN|ACK を N 個だけ捨てる(シェルの `synackdrop <N>`)。
 * txdrop はデータを持つセグメントしか捨てないので、握手そのものを落として
 * 「SYN の再送に SYN|ACK を送り直す」経路を実機で通すにはこれが要る。
 * ホットパスには乗らない(SYN が立っているときしか読まない)。 */
volatile uint32_t g_tcp_synack_drop_next;

/* 再送された SYN に応えて SYN|ACK を送り直した回数。 */
volatile uint32_t g_tcp_synack_retx_count;

/* Timestamps(RFC 7323)を提案するか(シェルの `tcpts on|off`)。0 にすると
 * SYN に付けなくなり、相手が付けてきても使わない(陰性対照)。
 * **コネクション単位で SYN の交換のときに決まる**ので、途中で変えても既存の
 * コネクションには効かない。 */
volatile uint32_t g_tcp_ts_enable = 1u;

/* TSecr から RTT を測った回数と、PAWS で捨てたセグメント数。 */
volatile uint32_t g_tcp_ts_rtt_samples;
volatile uint32_t g_tcp_paws_drop_count;

/* RTT 推定を更新した総回数(経路を問わない)。**Karn のアルゴリズムでは
 * 再送したウィンドウの RTT を測れない**ので、ロス注入下でこの数を
 * Timestamps の有無で比べると効果がそのまま見える。 */
volatile uint32_t g_tcp_rtt_update_count;

/* SACK(RFC 2018)を提案するか(シェルの `tcpsack on|off`)。0 にすると
 * SYN に SACK-Permitted を付けず、相手が付けてきても使わない。
 * **無効にすると段階 2 の Go-Back-N 一式へ戻る**(陰性対照)。 */
volatile uint32_t g_tcp_sack_enable = 1u;

/* SACK 済みと分かって**送り直さずに済んだ**セグメント数。Go-Back-N なら
 * 送っていたぶんなので、これがそのまま削減量になる。 */
volatile uint32_t g_tcp_sack_skipped_count;

/* 受信側として SACK ブロックを載せた ACK の数。 */
volatile uint32_t g_tcp_sack_sent_count;
/* DSACK(RFC 2883)。受け取り済みのデータが届いたら、次の純 ACK の先頭の SACK ブロックでその範囲を
 * 知らせる。送り手(Linux)はこれで「送り直しは無駄だった」と知り、届く順番の入れ替わりを
 * ロスと見て下げた cwnd を戻す。0 = 返さない(陰性対照、`tcpsack dsack off`)。 */
volatile uint32_t g_tcp_dsack_enable = 1u;
volatile uint32_t g_tcp_dsack_sent_count;

/* 送信側として SACK オプションを読み取った回数(scoreboard の更新回数)。 */
volatile uint32_t g_tcp_sack_rx_count;

/* 一時的な切り分け用: SACK 判定を試みた回数と、scoreboard が空だった回数。 */
volatile uint32_t g_tcp_sack_probe_count;
volatile uint32_t g_tcp_sack_noinfo_count;
/* `tcpsack debug` で 8 回だけ scoreboard と送信スロットをダンプする。
 * **「SACK は届いているのに送信を省略できない」の原因(ブロックより先は
 * まだ飛行中なのに送り直していた)はこのダンプで分かった。** */
volatile uint32_t g_tcp_sack_debug;

/* 重複 ACK がどの分岐で終わったかの内訳(`tcpsack` で表示)。
 * **「高速再送が 1 回も発火しない」ときの切り分けはこれしかない。**
 * recover ガードが ISN 次第で永久に効きっぱなしになるバグを、
 * この内訳(重複 ACK 1292 個が全部 recover ガード行き)で見つけた。 */
volatile uint32_t g_tcp_dup_suppressed;
volatile uint32_t g_tcp_dup_in_recovery;
volatile uint32_t g_tcp_dup_recover_guard;
volatile uint32_t g_tcp_dup_threshold_hit;
volatile uint32_t g_tcp_dup_rate_limited;

/* 高速再送を要求されたのに 1 セグメントも送らなかった回数(切り分け用)。 */
volatile uint32_t g_tcp_fr_empty;

/* 切り分け用: SACK の情報を「再送を減らす」ために使うか。0 にすると
 * 合意もブロック送出もしたまま、再送だけ Go-Back-N に戻る。 */
volatile uint32_t g_tcp_sack_use_tx = 1u;

/* partial ACK で次の穴を送り直した回数。 */
volatile uint32_t g_tcp_sack_partial_retx;

/* RACK-TLP(RFC 8985)と、無駄だった再送の取り消し(undo。RFC 3708 の DSACK と RFC 3522 の
 * Timestamps)。Linux と同じく既定で有効(シェルの `tcprack`)。**RACK と TLP は SACK を合意した接続の
 * 非同期送信(tcp_send_async 系)だけで働く** -- 一括送信の tcp_send() はスロットを持たないので
 * 従来の重複 ACK 3 個と Go-Back-N のまま。undo はどちらの経路でも効く。 */
volatile uint32_t g_tcp_rack_enable = 1u;
volatile uint32_t g_tcp_tlp_enable  = 1u;
volatile uint32_t g_tcp_undo_enable = 1u;
volatile uint32_t g_tcp_rack_lost;        /* RACK が失われたと見て送り直したスロット */
volatile uint32_t g_tcp_rack_lost_timer;  /* そのうち入れ替わりの窓が過ぎるのを待ってから見たもの */
volatile uint32_t g_tcp_rack_recovery;    /* RACK で回復に入った回数 */
volatile uint32_t g_tcp_rack_dup_skip;    /* 重複 ACK が 3 個そろったが RACK に任せた回数 */
volatile uint32_t g_tcp_rack_reord;       /* 順序の入れ替わりを見つけた接続の数 */
volatile uint32_t g_tcp_tlp_probes;
volatile uint32_t g_tcp_tlp_recovered;    /* probe が損失を直した(cwnd を下げた) */
volatile uint32_t g_tcp_tlp_redundant;    /* probe は無駄だった(DSACK) */
volatile uint32_t g_tcp_dsack_rx;         /* 受け取った DSACK ブロック */
volatile uint32_t g_tcp_undo_armed;       /* 回復に入って cwnd を控えた回数 */
volatile uint32_t g_tcp_undo_dsack;       /* DSACK で戻した回数 */
volatile uint32_t g_tcp_undo_ts;          /* Timestamps で戻した回数 */
volatile uint32_t g_tcp_prr_enable = 1u;  /* PRR(RFC 6937)。0 = 従来の ssthresh + 3 MSS と重複 ACK ごとの膨張 */
volatile uint32_t g_tcp_prr_deferred;     /* PRR の枠が無くて送り直しを後回しにした回数 */
volatile uint32_t g_tcp_prr_unstall;      /* 回復中に何も届かず、PRR の枠を 1 MSS 開けた回数 */
volatile uint32_t g_tcp_undo_log_over;    /* 送り直しの控えが入り切らず、DSACK で戻さなかった回復 */
volatile uint32_t g_tcp_undo_dsack_foreign; /* この回復で送り直していない範囲への DSACK(勘定に入れない) */
volatile uint32_t g_tcp_rack_minrtt_win_ms = 10000u;  /* 最小の往復時間の窓 */

/* Keepalive(RFC 1122 4.2.3.6)。**既定値は慣例どおり 2 時間 + 75 秒 x 9 回**。
 * 短くすると「無通信だが生きている」正常な接続を切ってしまうので、
 * 検証のとき以外は縮めないこと(`keepalivetest` は必ず元へ戻す)。
 *
 * **g_tcp_keepalive_enable は「これから張る接続の既定」で、既定は 0(使わない)。**
 * RFC 1122 4.2.3.6 は「Keepalive を使うかはアプリが接続ごとに選べ(MUST-24)、既定は無効
 * (MUST-25)」と決めている。以前はソケットオプションが無いので全接続で有効にしていた。
 * 上位はどれも自分の生存確認を持っている(NVMe/TCP は Keep Alive Timer = KATO、iSCSI は
 * NOP-In)ので、TCP の Keepalive に頼っている接続は無い。接続ごとには tcp_set_keepalive()。 */
volatile uint32_t g_tcp_keepalive_enable   = 0u;
volatile uint32_t g_tcp_keepalive_idle_ms  = 7200000u;  /* 2 時間 */
volatile uint32_t g_tcp_keepalive_intvl_ms = 75000u;    /* probe の間隔 */
volatile uint32_t g_tcp_keepalive_probes   = 9u;        /* 諦めるまでの probe 数 */

volatile uint32_t g_tcp_keepalive_probe_count;  /* 送った probe の総数 */
volatile uint32_t g_tcp_keepalive_drop_count;   /* 応答が無くて畳んだ接続数 */
volatile uint32_t g_tcp_keepalive_reply_count;  /* 相手の probe に ACK を返した数 */

/* 純 ACK のロス注入(シェルの `ackdrop <N>`)。次に送るデータ無しの
 * セグメントを N 個捨てる。**`txdrop` はデータを持つセグメントしか
 * 捨てない**ので、Keepalive の probe や応答を落とすにはこちらが要る。 */
volatile uint32_t g_tcp_ack_drop_next;
volatile uint32_t g_tcp_ack_dropped_count;

/* RST の検証(RFC 5961 3)。窓外で捨てた数と、窓内だが RCV.NXT でないため
 * challenge ACK を返した数。**検証を入れる前は 4-tuple 一致だけで畳んで
 * いた**ので、前の接続の遅延 RST が生きた接続を殺せた。 */
volatile uint32_t g_tcp_rst_dropped_count;
volatile uint32_t g_tcp_rst_challenge_count;

/* **実際に送り直したセグメントの数**。g_tcp_retransmit_count は「再送を
 * 始めた回数」なので、Go-Back-N と SACK の差(穴の後ろまで送り直すか)は
 * こちらでないと見えない。 */
volatile uint32_t g_tcp_retransmit_segs;

/* RFC に合わせて足した検査の計数(tcp.h の説明を参照)。どれも冷たい経路でだけ増える。 */
volatile uint32_t g_tcp_ack_unsent_drop;
volatile uint32_t g_tcp_rx_oow_drop;
volatile uint32_t g_tcp_syn_challenge;
volatile uint32_t g_tcp_oow_ack_limited;
volatile uint32_t g_tcp_noack_drop;
volatile uint32_t g_tcp_listen_rst;
volatile uint32_t g_tcp_ts_missing_drop;
volatile uint32_t g_tcp_retx_abort;
volatile uint32_t g_tcp_ack_time_flush;
volatile uint32_t g_tcp_urg_rx;
volatile uint32_t g_tcp_synsent_rst;
volatile uint32_t g_tcp_icmp_soft_count, g_tcp_icmp_hard_count, g_tcp_icmp_pmtu_ok;
volatile uint32_t g_tcp_icmp_bogus_count, g_tcp_icmp_hard_abort;

/*=================================================================
 * Timestamps オプションに入れる自分の時刻を返す。
 *
 * timer_now() は ns なので 1024 で割って約 1.024us 刻みにする(除算ではなく
 * シフト -- この関数は送信 1 セグメントごとに通るホットパスにある)。
 * 32bit が一周するのに約 73 分かかるので、PAWS の前提(一周が MSL より
 * 十分長い)を満たす。
 *
 * 戻り値:
 *   TSval に入れる値
 * コール元:
 *   tcp_build_options(), tcp_ts_rtt_sample()
 * ===============================================================*/
static inline uint32_t tcp_ts_now(void)
{
    return (uint32_t)(timer_now() >> 10);
}

/*=================================================================
 * このデータセグメントを人為的に捨てるか判定する(g_tcp_tx_drop_every が
 * 非 0 のときだけ呼ばれる)。
 *
 * 引数:
 *   data_len - ペイロード長(0 なら捨てない。純 ACK は対象外)
 * 戻り値:
 *   1=捨てる、0=送る
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso()
 * ===============================================================*/
static int tcp_tx_should_drop(uint32_t data_len)
{
    if (data_len == 0u) return 0;
    unsigned c = smp_core_index();
    s_tcp_tx_drop_counter[c]++;
    if ((s_tcp_tx_drop_counter[c] % g_tcp_tx_drop_every) != 0u) return 0;
    g_tcp_tx_dropped_count[c]++;
    return 1;
}

/*=================================================================
 * 受信循環バッファの容量を返す(パイプライン受信の in-flight 上限計算用)。
 *
 * 戻り値:
 *   TCP_RX_BUF_SIZE
 * コール元:
 *   nvme_read_pipelined_run()
 * ===============================================================*/
uint32_t tcp_rx_buf_size(void)
{
    return TCP_RX_BUF_SIZE;
}

typedef struct {
    uint32_t seq;      /* このセグメントの先頭seq */
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_MAX_LEN];
    const uint8_t *ref;
    uint64_t sent_at;  /* 直近の送信(初回または再送)時刻 */
    uint32_t rto_ms;
    int      retries;
    uint8_t  sacked;   /* 相手が SACK で「届いた」と言った(RACK) */
    uint8_t  retx;     /* 一度でも送り直した(その ACK はどちらの送信への応答か分からない) */
    uint8_t  lost;     /* RACK が失われたと見たが、PRR の枠が無くてまだ送り直していない */
} tcp_async_slot_t;

typedef struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_SHORT_SLOT_BYTES];
    uint64_t sent_at;
    uint32_t rto_ms;
    int      retries;
    uint8_t  sacked;
    uint8_t  retx;
    uint8_t  lost;
} tcp_async_short_slot_t;

typedef struct {
    volatile int      ack_received;
    volatile uint32_t expected_ack;

    volatile uint32_t snd_una;
    volatile int      ack_advanced;
    /* **上位層による到達確認**(RFC 4861 7.3.1 / NUD)。累積 ACK が進んだ =
     * 相手が自分の送ったデータを確かに受け取った、なので近隣キャッシュを
     * 延命してよい。`ack_advanced` は送信ループが消費してしまうラッチなので
     * 別に持つ。次の送信で近隣キャッシュを引くときに消費する。 */
    volatile int      neigh_confirm;

    uint64_t srtt_us;
    uint64_t rttvar_us;
    uint32_t rto_ms;

    uint32_t cwnd;
    uint32_t ssthresh;

    /* 高速再送 / 高速回復(RFC 5681)。重複 ACK を数え、3 個目で RTO を待たずに
     * 再送する。検出は tcp_input_addr() で行い、実際の再送は fast_retransmit を
     * 拾った既存の再送経路(tcp_send() の Go-Back-N ループと tcp_async_poll())が
     * 行う -- 再送機構を新しく作らない。 */
    uint32_t          dup_ack_count;     /* 同一 ACK 番号の連続受信数 */
    uint32_t          recover;           /* 回復の目標 seq。ここまで ACK されるまで次の回復を始めない */
    uint32_t          dup_ack_suppress;  /* 自分の Go-Back-N が生む重複 ACK の予想数(この数だけ無視する) */
    uint64_t          fr_last_at;        /* 直近に高速再送を要求した時刻(1 RTT に 1 回へ制限する) */
    int               in_fast_recovery;

    /* 高速再送の要求は「世代番号」で渡す。未確認データを持ちうる送信経路が
     * 3 つ(tcp_send() の一括送信、async キュー、async short キュー)あり、
     * 単純な 1 ビットのフラグだと最初に見た 1 つが消費してしまって残りが
     * 再送しない。各経路が最後に処理した世代を覚え、世代が進んだら再送する。 */
    volatile uint32_t fast_retransmit_gen;
    uint32_t          fr_gen_bulk;
    uint32_t          fr_gen_async;
    uint32_t          fr_gen_short;

    uint8_t           rx_buf[TCP_RX_BUF_SIZE];
    volatile uint32_t rx_read;
    volatile uint32_t rx_count;
    volatile int      fin_received;

    tcp_recv_upcall_fn recv_upcall;
    void              *recv_upcall_ctx;

    int      wscale_enabled;
    uint8_t  snd_wscale;
    uint8_t  rcv_wscale;   /* SYN で名乗った自分の shift(g_tcp_rcv_wscale をそのときに写す) */
    /* 相手がこれまでに広告した最大の受信窓(tcp_peer_win_max())。1 レコード = 1 セグメントで送る
     * TLS が、窓より大きいレコードを作って永久に待たないための上限に使う(SPDK の ssl ソケットは
     * Window Scale 無しの 4KB しか広告しない)。 */
    uint32_t snd_win_max;

    /* Timestamps(RFC 7323)。SYN の交換で双方が出したときだけ有効になる。
     * ts_recent は相手へ echo し返す値、ts_last_ack_sent は「どこまで ACK した
     * 時点の ts_recent か」(R3 の更新条件に要る)。 */
    uint8_t           ts_enabled;
    uint32_t          ts_recent;
    uint32_t          ts_last_ack_sent;
    uint32_t          ts_last_sent;     /* 最後に送ったセグメントの TSval */

    /* SACK(RFC 2018)。SYN で双方が SACK-Permitted を出したときだけ有効。
     * sack_rx[] は**相手が「届いた」と言ってきた範囲**(送信側の scoreboard)で、
     * 高速再送のときにここに入っている範囲を送り直さない。 */
    uint8_t           sack_enabled;
    uint8_t           sack_rx_count;
    struct { uint32_t start, end; } sack_rx[TCP_SACK_MAX_BLOCKS];
    /* sack_rx を書き換えるたびに進める(RACK がスロットへ SACK 済みの印を付け直す契機)。 */
    uint8_t           sack_gen;
    uint8_t           sack_gen_seen;

    /* RACK(RFC 8985)。**「届いたと分かった中で一番後に送ったセグメント」より前に送ったのに、
     * まだ届いていないセグメントは、往復時間と順序入れ替わりの窓が過ぎたら失われたと見る。**
     * 重複 ACK の数ではなく時刻で決めるので、末尾の喪失や送り直しの喪失も拾える。 */
    uint64_t          rack_xmit_at;     /* その送信時刻(timer_now() の ns。0 = まだ無い) */
    uint32_t          rack_end_seq;
    uint64_t          rack_rtt_ns;      /* そのときの往復時間 */
    uint64_t          rack_rtt_last_ns; /* 直近の RTT の標本(tcp_rtt_update()) */
    /* 最小の往復時間(直近 g_tcp_rack_minrtt_win_ms の窓の最小値)。Linux の lib/win_minmax.c と同じ
     * 「標本 3 つ」の窓付き最小値で、[0] が答え。経路が変わって往復時間が伸びても、窓が過ぎれば追従する
     * (接続の間の最小値だと、一度だけ速かった標本に入れ替わりの窓が引きずられる)。 */
    struct { uint64_t t, v; } rack_mm[3];
    uint8_t           rack_mm_valid;
    uint32_t          rack_fack;        /* 届いた範囲の最も先(入れ替わりの検出) */
    uint8_t           rack_fack_valid;
    uint8_t           rack_reord_seen;  /* 順序の入れ替わりを見た */
    uint8_t           rack_reo_mult;    /* 入れ替わりの窓 = min_rtt/4 x これ(DSACK で増やす) */
    uint8_t           rack_reo_persist; /* この回数の回復のあいだ reo_mult を保つ */
    uint8_t           rack_dirty;       /* rack_xmit_at が進んだ(判定し直す) */
    uint8_t           rack_dsack_round_valid;
    uint32_t          rack_dsack_round; /* ここまで ACK されるまで reo_mult を再び上げない */
    uint64_t          rack_timer_at;    /* 入れ替わりの窓が過ぎて判定し直す時刻(0 = 無し) */

    /* TLP(RFC 8985 7 章)。**末尾が失われると重複 ACK も SACK も来ないので RTO まで待つ。**
     * 往復時間の約 2 倍たっても ACK が無ければ最後のセグメントを 1 つ送り直し(probe)、
     * その ACK / SACK で RACK に失われたものを見つけさせる。 */
    uint64_t          tlp_tx_at;        /* 最後にデータを送った時刻 */
    uint64_t          tlp_ack_at;       /* 最後に累積 ACK が進んだ時刻 */
    uint8_t           tlp_active;       /* probe を送って結果待ち */
    uint8_t           tlp_dsack;        /* probe が無駄だった(DSACK が来た) */
    uint32_t          tlp_high_seq;     /* probe を送ったときの snd_nxt */
    uint32_t          tlp_probe_seq;    /* probe の先頭 */

    /* undo(RFC 3708 / RFC 3522)。回復に入る前の cwnd / ssthresh を控え、送り直しが全部無駄だったと
     * DSACK で分かるか、Timestamps で元の送信への ACK だと分かったら戻す。 */
    uint8_t           undo_valid;
    uint8_t           undo_ts_ok;
    uint8_t           undo_ended;       /* 回復の範囲(undo_high)まで ACK された */
    uint32_t          undo_marker;      /* 回復を始めたときの snd_una */
    uint32_t          undo_high;        /* 回復を始めたときの snd_nxt */
    uint32_t          undo_limit;       /* ここを超えて ACK されたら undo をやめる */
    uint32_t          undo_retrans;     /* 送り直した(が DSACK で返ってきていない)バイト数 */
    /* まだ確認されていない送り直しのうち、最初のものを送ったときの自分の TSval(0 = 無い)と、
     * 送り直した範囲の右端(Linux の retrans_stamp)。Eifel の判定はこれと比べる。 */
    uint32_t          retx_ts;
    uint32_t          retx_end;
    uint32_t          prior_cwnd;
    uint32_t          prior_ssthresh;
    /* この回復で送り直した範囲の控え(DSACK の勘定用)。隣り合う範囲はまとめる。同じ範囲を 2 度送り直したら
     * 2 つ控える(DSACK も 2 つ来るはず)。入り切らなかったら、この回復では DSACK で戻さない。 */
    uint8_t           undo_log_n;
    uint8_t           undo_log_over;
    struct { uint32_t s, e; } undo_log[TCP_UNDO_LOG];

    /* PRR(RFC 6937)。回復中に送ってよい量を、届いた量(prr_delivered)に比例させる。cwnd は ACK ごとに
     * 「飛んでいる量 + 送ってよい量」へ置き直す。 */
    uint8_t           prr_active;
    uint32_t          prr_delivered;
    uint32_t          prr_out;          /* 回復に入ってから送ったバイト(送り直しも新しいデータも) */
    uint32_t          prr_recover_fs;   /* 回復に入ったときに飛んでいた量 */
    uint32_t          lost_bytes;       /* lost の印のスロットの合計(飛んでいる量に数えない) */

    /* 順序外に持っているセグメントの数。 */
    unsigned          ooo_count;

    /* 受信側として相手へ知らせる「届いている区間」。**順序不正セグメントを
     * 置くたびに差分で更新する。** 送るたびに順序外の列から作り直すと
     * 結合が O(n^3) になり、順序不正が数十個たまる read の経路で実測 2.5 倍
     * 遅くなった(ACK 1 個ごとに 2 回呼ばれるため)。 */
    uint8_t           sack_tx_count;
    uint8_t           sack_tx_recent;  /* 直近に触った添字(先頭に置く) */
    /* 次の純 ACK で知らせる DSACK の範囲(受け取り済みのデータが届いた)。1 回知らせたら消す。 */
    uint8_t           dsack_valid;
    uint32_t          dsack_start, dsack_end;
    struct { uint32_t start, end; } sack_tx[TCP_SACK_TX_MAX];

    /* Keepalive(RFC 1122 4.2.3.6)。**受信のたびに時刻を書かない** --
     * ホットパスに置くのは「何か届いた」という 1 バイトの旗だけで、
     * 時刻の読み出しと期限の判定は冷たい経路(tcp_keepalive_check())で行う。
     *
     * **D7 の「既にあるカウンタを冷たい経路から観測する」手はここでは使えない。**
     * probe への応答は**データを運ばない純 ACK**なので、rcv_seq も snd_una も
     * 進まない -- 既存のどのカウンタにも痕跡が残らない。スナップショット方式で
     * 作ったところ、**応答が返っているのに接続を切った**(陰性対照で判明)。
     *
     * 印は「受け取ったセグメントの数」(rx_segs)にしてある。以前の 1 バイトの旗(ka_seen)は
     * Keepalive の確認が消費してしまうので、ほかの用途(tcp_send() の「相手から何か来ているか」=
     * 窓 0 の間も相手が応えているなら切らない、MUST-37)と共有できなかった。数なら各自が
     * 前回の値と比べるだけで済み、ホットパスの費用は 1 バイトの store が 4 バイトの加算に変わるだけ。 */
    volatile uint32_t rx_segs;         /* この接続で受け取ったセグメントの数(ホットパスで加算) */
    uint32_t          ka_rx_snap;      /* Keepalive が最後に見た rx_segs */
    uint8_t           ka_enabled;      /* この接続で Keepalive を使う(MUST-24、既定は張ったときの g_tcp_keepalive_enable)*/
    uint64_t          ka_idle_since;   /* 無通信になった時刻(0=まだ初期化前) */
    uint32_t          ka_probes;       /* 応答が無いまま送った probe の数 */

    /* ---- RFC 9293 に合わせて足した送受信の状態 ----
     * snd_max  : 送った最大の seq + 1(SND.NXT)。conn->snd_seq は tcp_send() の再送中や高速再送の間は
     *            巻き戻っているので、「まだ送っていないものへの ACK」の判定には使えない(3.10.7.4)。
     *            tcp_send_segment() / _lso() で SYN / FIN のぶんも含めて進める。
     * snd_wl1/2: 送信窓を最後に更新したセグメントの seq / ack(3.10.7.4 の SND.WL1 / WL2)。古い
     *            セグメントが後から届いても窓を古い値へ戻さない。
     * rcv_wnd_edge: 最後に広告した受信窓の右端(RCV.NXT + RCV.WND)。受信窓の外のセグメントの判定
     *            (first check)と、窓を縮めない(SHLD-14)・小さく広げない(MUST-39、受け手の SWS 回避)
     *            の基準。rcv_wnd_valid は ACK 付きで一度でも広告したか。 */
    uint32_t          snd_max;
    uint32_t          snd_wl1, snd_wl2;
    uint32_t          rcv_wnd_edge;
    uint8_t           rcv_wnd_valid;
    /* 順序外の FIN(RFC 9293 3.10.7.4 eighth)。穴があるうちに届いた FIN の位置を覚え、穴が埋まって
     * rcv_seq がそこへ届いたときに処理する。 */
    uint8_t           fin_pend;
    uint32_t          fin_pend_seq;
    /* 緊急ポインタ(RFC 9293 3.8.5)。rcv_up = 緊急データの終わりの seq(RFC 6093)。 */
    uint8_t           urg_valid;
    uint32_t          rcv_up;
    /* 窓外への ACK / challenge ACK を最後に送った時刻(RFC 5961 7 の頻度の上限)。 */
    uint64_t          oow_last_at;
    /* 再送の時間切れ(R2)。RTO で送り直し始めた時刻(0 = いまは再送していない)。累積 ACK で
     * スロットを返したら 0 に戻す。 */
    uint64_t          rto_since;
    /* 能動 open を始めた時刻(SYN の R2 = 3 分の起点)。 */
    uint64_t          connect_start;
    /* ICMP エラー(RFC 5927)。HARD を別のコアで受けたときは旗だけ立て、持ち主のコアが畳む。 */
    volatile uint8_t  icmp_hard;
    uint32_t          icmp_soft_err;
    /* TS.Recent の 24 日の失効(RFC 7323 5.5)。冷たい経路で ts_recent が動いたかを見張り、
     * 24 日動かなければ ts_recent_stale を立てる(PAWS で 1 回だけ素通しする)。ホットパスには
     * 時刻を置かない(PAWS で捨てる側の枝で旗を 1 つ見るだけ)。 */
    uint32_t          ts_recent_snap;
    uint64_t          ts_recent_snap_at;
    uint8_t           ts_recent_stale;
    /* 返していない ACK に冷たい経路が最初に気付いた時刻(時間の上限、MUST-40)。0 = 借りが無い。
     * ack_owed_mark はそのときの last_ack_sent(その後 ACK を送っていれば測り直す)。 */
    uint64_t          ack_owed_since;
    uint32_t          ack_owed_mark;
    /* 窓 0 の確認の後退(SHLD-29/30)。最初は RTO 後、以後は倍々(TCP_MAX_RTO_MS で頭打ち)。 */
    uint32_t          zwp_interval_ms;

    uint32_t          unacked_full_segments;

    /* **ACK の相乗り(piggyback)。** 受信のたびに裸の ACK を別セグメントで
     * 返すと、応答 PDU と合わせて 1 コマンド 2 パケットになる。応答は
     * 同じ tick のうちに出るので、**裸の ACK を出さずに応答へ載せれば
     * 遅延を増やさずにパケットを半減できる**(kernel nvmet は 1 コマンド
     * あたり 0.27〜0.37 パケットなのに対し自製は 1.18〜2.00 だった)。
     * upcall を持つコネクション(= 応答が必ず出る)だけで使う。 */
    uint8_t           ack_deferred;   /* 残り何周まで借りておけるか(0=借り無し)*/
    uint8_t           ack_hold_thin;  /* ack_deferred が間引きの期限(相乗り待ちではない)*/
    uint8_t           ack_thin_off;   /* この接続では間引きをやめた(ackadapt の判定)*/
    uint16_t          thin_n;         /* 判定の窓: 間引いた ACK を返した回数 */
    uint16_t          thin_exp;       /* そのうち期限切れで返した回数 */
    uint8_t           ack_piggy_ok;   /* このコネクションで相乗りしてよいか */

    uint32_t          unacked_consumed_bytes;

    /* 直近に広告した (ACK 番号, ウィンドウ)。両方とも前回と同じウィンドウ更新
     * ACK は相手に伝える情報がゼロなので送らない(tcp_recv_internal())。 */
    uint32_t          last_ack_sent;
    uint16_t          last_win_sent;

    /* 順序外に届いたセグメントの列(seq の順、重なり無し)。中身は共有の置き場(s_ooo_*)にある。 */
    uint16_t          ooo_head;
    uint32_t          ooo_bytes;   /* この接続が使っている置き場の量(枠の大きさの合計) */

    tcp_async_slot_t async_slots[TCP_ASYNC_SLOTS];
    unsigned          async_head;
    unsigned          async_count;
    int               async_overflow_idx;
    unsigned          async_cap;
    uint8_t           async_overflow_ever_init;

    tcp_async_short_slot_t async_short_slots[TCP_ASYNC_SHORT_SLOTS];
    unsigned                async_short_head;
    unsigned                async_short_count;

    volatile int      in_bulk_send;

    uint32_t connect_attempt;
    uint32_t connect_rto_ms;
    uint64_t connect_sent_at;
} tcp_priv_t;

static tcp_conn_t *s_conns[SMP_MAX_CORES][TCP_MAX_CONNS];
static tcp_priv_t  s_priv[SMP_MAX_CORES][TCP_MAX_CONNS];

/* TIME_WAIT の表(全コア共有、ロック 1 本)。
 *
 * **2MSL は 60 秒**(Linux の TCP_TIMEWAIT_LEN と同じ。RFC 9293 の MSL 2 分 x 2 = 4 分より短いが、
 * 自分側の一時ポートは RFC 6056 で散らしており、Timestamps の PAWS も効くので、Linux と同じ判断を採る)。
 * 以前は 4 秒・コアごとに 4 個だったので、能動クローズした直後に相手の FIN の再送が来ても、
 * 表が既に消えていて RST を返すことがあった。
 *
 * 大きさは 256(1 エントリ約 64 バイト)。**満杯なら一番古いもの(最も早く期限が来るもの)を
 * 置き換える**(以前は「先頭」を置き換えていて、それが一番古いとは限らなかった)。Linux は満杯なら
 * TIME_WAIT を作らずに閉じる(tw bucket overflow)が、こちらは古いものを捨てる方を選ぶ -- どちらも
 * 失うのは「期限切れ間近の 1 本の保護」だけで、新しく閉じた接続の保護のほうが役に立つ。
 *
 * 掃除は冷たい経路(ポーリング 256 回に 1 回)で行う。以前は受信のポーリングのたびに全コアが
 * 同じロックを取って表を舐めていた。 */
#define TCP_TIMEWAIT_TOTAL 256u
#define TCP_TIMEWAIT_MS  60000u

typedef struct {
    int       in_use;
    netaddr_t local_ip;
    uint16_t  local_port;
    netaddr_t remote_ip;
    uint16_t  remote_port;
    uint32_t local_seq;      /* 応答ACKのSEQフィールドに使う自分のFIN後のseq(不変) */
    uint64_t started_ticks;  /* TIME_WAIT開始時刻(相手の FIN の再送が来たら測り直す、RFC 9293 3.10.7.4) */
    /* Timestamps を合意していた接続か(RFC 7323)。合意していたなら応答の ACK にも TS を載せる
     * (載せないと、相手の TS 必須の検査で捨てられ、相手は LAST_ACK から抜けられない)。 */
    uint8_t  ts_ok;
    uint32_t ts_recent;
} tcp_timewait_t;

static tcp_timewait_t s_timewait[TCP_TIMEWAIT_TOTAL];
static smp_spinlock_t s_timewait_lock;

/*=================================================================
 * TIME_WAIT テーブルから 4-tuple が一致するエントリを探す。閉じた直後の
 * コネクション宛に届いた再送セグメントへ ACK を返すため、と、一時ポートを
 * 選ぶとき(tcp_pick_port())に使う。
 *
 * 引数:
 *   remote_ip / remote_port / local_port - 探す 4-tuple
 *   out - 見つかったエントリの写し(NULL 可。ロックの外で使うので写しを返す)
 * 戻り値:
 *   1=見つかった、0=無い
 * コール元:
 *   tcp_input_addr(), tcp_pick_port()
 * ===============================================================*/
static int tcp_timewait_find(const netaddr_t *remote_ip, uint16_t remote_port, uint16_t local_port,
                             tcp_timewait_t *out)
{
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use &&
            s_timewait[i].remote_port == remote_port &&
            s_timewait[i].local_port == local_port &&
            netaddr_eq(&s_timewait[i].remote_ip, remote_ip)) {
            if (out) *out = s_timewait[i];
            smp_spin_unlock(&s_timewait_lock);
            return 1;
        }
    }
    smp_spin_unlock(&s_timewait_lock);
    return 0;
}

/*=================================================================
 * 相手の FIN の再送が来た TIME_WAIT の期限を測り直す(RFC 9293 3.10.7.4: TIME-WAIT で FIN を
 * 受けたら ACK を返し、2MSL を測り直す)。
 * ===============================================================*/
static void tcp_timewait_restart(const netaddr_t *remote_ip, uint16_t remote_port, uint16_t local_port)
{
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use &&
            s_timewait[i].remote_port == remote_port &&
            s_timewait[i].local_port == local_port &&
            netaddr_eq(&s_timewait[i].remote_ip, remote_ip)) {
            s_timewait[i].started_ticks = timer_now();
            break;
        }
    }
    smp_spin_unlock(&s_timewait_lock);
}

/*=================================================================
 * クローズしたコネクションを TIME_WAIT テーブルへ登録する(スロットを
 * 解放した後も、相手の再送に ACK を返せるようにするため)。
 *
 * 引数:
 *   local_ip / local_port / remote_ip / remote_port - 4-tuple
 *   local_seq - 応答 ACK に使う自分の seq(FIN の後)
 *   ts_ok / ts_recent - Timestamps を合意していたか、相手の最後の TSval
 * コール元:
 *   tcp_close()
 * ===============================================================*/
static void tcp_timewait_register(const netaddr_t *local_ip, uint16_t local_port,
                                   const netaddr_t *remote_ip, uint16_t remote_port,
                                   uint32_t local_seq, uint8_t ts_ok, uint32_t ts_recent)
{
    const uint64_t now = timer_now();
    smp_spin_lock(&s_timewait_lock);
    int slot = -1;
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        /* 同じ 4-tuple が既にあれば上書きする(二重に持たない)。 */
        if (s_timewait[i].in_use && s_timewait[i].remote_port == remote_port &&
            s_timewait[i].local_port == local_port &&
            netaddr_eq(&s_timewait[i].remote_ip, remote_ip)) { slot = (int)i; break; }
    }
    if (slot < 0) {
        for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
            if (!s_timewait[i].in_use) { slot = (int)i; break; }
        }
    }
    if (slot < 0) {
        /* 満杯: 一番古いもの(最も早く期限が来るもの)を置き換える。 */
        slot = 0;
        for (unsigned i = 1; i < TCP_TIMEWAIT_TOTAL; i++) {
            if (s_timewait[i].started_ticks < s_timewait[slot].started_ticks) slot = (int)i;
        }
    }
    s_timewait[slot].in_use       = 1;
    s_timewait[slot].local_ip     = *local_ip;
    s_timewait[slot].local_port   = local_port;
    s_timewait[slot].remote_ip    = *remote_ip;
    s_timewait[slot].remote_port  = remote_port;
    s_timewait[slot].local_seq    = local_seq;
    s_timewait[slot].started_ticks = now;
    s_timewait[slot].ts_ok        = ts_ok;
    s_timewait[slot].ts_recent    = ts_recent;
    smp_spin_unlock(&s_timewait_lock);
}

/*=================================================================
 * 期限切れの TIME_WAIT エントリを掃除する(冷たい経路。時刻は呼び出し側が 1 回だけ読む)。
 *
 * コール元:
 *   tcp_poll_once_ex()(ポーリング 256 回に 1 回)
 * ===============================================================*/
static void tcp_timewait_reap(uint64_t now)
{
    const uint64_t life = (uint64_t)TCP_TIMEWAIT_MS * 1000000u;
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use && now - s_timewait[i].started_ticks >= life) {
            s_timewait[i].in_use = 0;
        }
    }
    smp_spin_unlock(&s_timewait_lock);
}

/* リスナ 1 本あたりの待ち行列(listen backlog)の深さ。呼び出し側が
 * tcp_accept_begin() で受け皿を用意していない間に届いた SYN を、ここに
 * 積んで先に確立まで進めておく。積まずに捨てると相手の SYN 再送
 * (Linux の初期値は 1 秒)ぶんだけ接続確立が遅れる。
 *
 * **IO キューの本数(NVMET_IO_QUEUES = 16)に合わせて 16。** 4 本だった頃、
 * SPDK の spdk_nvme_perf が 16 本の qpair を同時に張りに来ると(-c 0xF -P 4)、
 * 受け皿は 1 本ずつしか立たないので残りがあふれ、1 コアのときは捨てた SYN の
 * 再送待ち(1・3・7 秒後)が積み重なって SPDK の接続待ち(10 秒)を超えた。
 * 待ち行列の接続は引き渡し後も同じ s_priv のスロットを使い続けるので、
 * TCP_MAX_CONNS の見積もり(admin 1 + IO 16 + 内蔵イニシエータ 2)は変わらない。 */
#define TCP_BACKLOG 16u

/* 待ち行列に積んだまま確立しない(相手が消えた)エントリを回収するまでの
 * 時間。確立済みで引き渡し待ちのものは対象にしない(Linux も accept 待ちの
 * コネクションを勝手に切らない)。 */
#define TCP_BACKLOG_SYN_TIMEOUT_MS 10000u

typedef struct {
    int         in_use;
    uint16_t    port;
    netif_t  *bound_ctx;    /* NULL = インターフェースを問わず受け付ける */
    tcp_conn_t *accept_conn;  /* tcp_accept_begin()が渡してきたconn */
    volatile int accept_ready; /* ESTABLISHEDになった = 1(backlog 無効時の直接受理) */

    /* listen backlog。SYN を受けた時点でこの中の 1 本を使って SYN_RCVD へ
     * 進み、tcp_accept_ready_poll() が呼び出し側の tcp_conn_t へ引き渡す。 */
    tcp_conn_t       pending[TCP_BACKLOG];
    uint64_t         pending_since[TCP_BACKLOG];  /* SYN を受けた時刻(ns) */
    volatile uint8_t pending_used[TCP_BACKLOG];   /* 1=使用中 */
    volatile uint8_t pending_estab[TCP_BACKLOG];  /* 1=ESTABLISHED(引き渡し待ち) */
} tcp_listener_slot_t;

#define TCP_LISTENER_TOTAL (TCP_MAX_LISTENERS * SMP_MAX_CORES)
static tcp_listener_slot_t s_listeners[TCP_LISTENER_TOTAL];
static smp_spinlock_t      s_listener_lock;

/* 待ち行列の実効深さ。0 にすると backlog を使わず「受け皿が用意されている
 * ときだけ SYN を受理する」従来の挙動へ戻る(陰性対照。`txdrop` / `mld off`
 * と同じ「機能を止める手段を恒久的に残す」考え方)。シェルの `backlog <N>`。 */
volatile uint32_t g_tcp_backlog_max = TCP_BACKLOG;

/* 待ち行列が満杯で捨てた SYN の数(Linux と同じく RST は返さない)。 */
volatile uint32_t g_tcp_backlog_overflow_count;

/* **確立して引き渡し待ちの待ち行列エントリの数(持ち主のコアごと)。**
 * 引き渡しは持ち主のコアだけが行う(tcp_backlog_service())ので、0 のコアは
 * リスナの走査をまるごと飛ばす。 */
static volatile uint32_t s_backlog_estab_cnt[SMP_MAX_CORES];

/* 待ち行列を経由して引き渡した accept の数。「受け皿の用意前に届いた SYN を
 * 実際に拾えているか」はこれが増えるかどうかで分かる。 */
volatile uint32_t g_tcp_backlog_accept_count;

/*=================================================================
 * 待ち行列の空きスロットを探す。
 *
 * 引数:
 *   l - リスナースロット
 * 戻り値:
 *   空きの添字。満杯(または backlog 無効)なら -1
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static int tcp_backlog_find_free(tcp_listener_slot_t *l)
{
    unsigned max = g_tcp_backlog_max;
    if (max > TCP_BACKLOG) max = TCP_BACKLOG;
    for (unsigned p = 0; p < max; p++) {
        if (!l->pending_used[p]) return (int)p;
    }
    return -1;
}

/*=================================================================
 * conn が待ち行列の中のどのエントリかを返す。
 *
 * 引数:
 *   l    - リスナースロット
 *   conn - 対象コネクション
 * 戻り値:
 *   添字。このリスナのものでなければ -1
 * コール元:
 *   tcp_input_addr(), tcp_backlog_reap()
 * ===============================================================*/
static int tcp_backlog_index_of(const tcp_listener_slot_t *l, const tcp_conn_t *conn)
{
    if (conn < &l->pending[0] || conn > &l->pending[TCP_BACKLOG - 1u]) return -1;
    return (int)(conn - &l->pending[0]);
}

/*=================================================================
 * 待ち行列のエントリを解放する。s_conns[] からも外すので、引き渡さずに
 * 捨てる経路(相手が消えた/リッスン終了)でも使える。
 *
 * 引数:
 *   l - リスナースロット
 *   p - 添字
 * コール元:
 *   tcp_accept_ready_poll(), tcp_backlog_reap(), tcp_unlisten()
 * ===============================================================*/
static void tcp_backlog_release(tcp_listener_slot_t *l, unsigned p)
{
    tcp_conn_t *c = &l->pending[p];
    unsigned    core = c->owner_core;
    if (l->pending_estab[p] && core < SMP_MAX_CORES)
        (void)__atomic_sub_fetch(&s_backlog_estab_cnt[core], 1u, __ATOMIC_ACQ_REL);
    if (core < SMP_MAX_CORES) {
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[core][i] == c) { s_conns[core][i] = NULL; break; }
        }
    }
    c->state = TCP_CLOSED;
    l->pending_estab[p] = 0;
    l->pending_used[p]  = 0;
}

/*=================================================================
 * 待ち行列の掃除。畳まれたエントリ(相手からの RST など)と、確立まで
 * 進まないまま放置されたエントリを回収する。回収しないとコネクション
 * スロット(TCP_MAX_CONNS)を握ったままになる。
 *
 * 確立済みで引き渡し待ちのものは時間では回収しない(呼び出し側が
 * tcp_accept_begin() を遅らせているだけかもしれない)。
 *
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
static void tcp_backlog_reap(void)
{
    /* 冷たい経路は各コアが回すので、同じエントリを 2 つのコアが同時に回収しないようロックを取る
     * (引き渡し tcp_backlog_handoff() と tcp_unlisten() も同じロックの中で触る)。 */
    smp_spin_lock(&s_listener_lock);
    for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
        tcp_listener_slot_t *l = &s_listeners[li];
        if (!l->in_use) continue;
        for (unsigned p = 0; p < TCP_BACKLOG; p++) {
            if (!l->pending_used[p]) continue;
            if (l->pending[p].state == TCP_CLOSED) {
                tcp_backlog_release(l, p);
                continue;
            }
            if (!l->pending_estab[p] &&
                timeout_ms(l->pending_since[p], TCP_BACKLOG_SYN_TIMEOUT_MS)) {
                uart_printf("[TCP] backlog: 確立しないまま %ums 経過したエントリを回収 "
                            "(local_port=%u)\n",
                            (unsigned)TCP_BACKLOG_SYN_TIMEOUT_MS, (unsigned)l->port);
                tcp_backlog_release(l, p);
            }
        }
    }
    smp_spin_unlock(&s_listener_lock);
}

/*=================================================================
 * リッスンハンドルからリスナースロットを引く。
 *
 * 引数:
 *   listener - tcp_listen() が返したハンドル
 * 戻り値:
 *   リスナースロット。範囲外/未使用なら NULL
 * コール元:
 *   tcp_accept_begin(), tcp_accept_ready_poll(), tcp_unlisten()
 * ===============================================================*/
static tcp_listener_slot_t *tcp_listener_for(int listener)
{
    if (listener < 0 || (unsigned)listener >= TCP_LISTENER_TOTAL) return NULL;
    if (!s_listeners[listener].in_use) return NULL;
    return &s_listeners[listener];
}

/*=================================================================
 * コネクションに対応するプライベート状態(受信バッファ・輻輳制御・非同期
 * 送信キュー等、tcp_conn_t には収まらない大きな状態)を引く。
 *
 * 引数:
 *   conn - 対象コネクション
 * 戻り値:
 *   プライベート状態。s_conns[] に未登録なら NULL
 * コール元:
 *   tcp_close(), tcp_connect_poll(), tcp_send(), tcp_recv_internal() ほか
 * ===============================================================*/
static tcp_priv_t *tcp_priv_for(tcp_conn_t *conn)
{
    unsigned core = conn->owner_core;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == conn) {
            return &s_priv[core][i];
        }
    }
    return NULL;
}

/*=================================================================
 * コネクションスロットの空きを探す。
 *
 * 戻り値:
 *   スロット番号。満杯なら -1
 * コール元:
 *   tcp_connect_begin(), tcp_input()
 * ===============================================================*/
static int tcp_find_free_slot(void)
{
    unsigned core = smp_core_index();
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == NULL) {
            return (int)i;
        }
    }
    return -1;
}

/*=================================================================
 * コネクションが s_conns[] のどのスロットに登録されているかを返す
 * (ts_log の識別子に埋める)。
 *
 * 引数:
 *   conn - 対象コネクション
 * 戻り値:
 *   スロット番号。未登録なら TCP_MAX_CONNS
 * コール元:
 *   tcp_conn_arg(), tcp_connect_poll(), tcp_input()
 * ===============================================================*/
static unsigned tcp_conn_slot(const tcp_conn_t *conn)
{
    /* tcp_priv_for()と同じ理由でconn->owner_coreを使う(上記コメント参照)。 */
    unsigned core = conn->owner_core;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == conn) {
            return i;
        }
    }
    return TCP_MAX_CONNS;
}

uint32_t tcp_conn_arg(const tcp_conn_t *conn, uint32_t value)
{
    return ((uint32_t)tcp_conn_slot(conn) << 24) | (value & 0x00FFFFFFu);
}

static inline int tcp_seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int tcp_seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }

/* 順序外の置き場(全コア共通)。番号 0〜8191 が小、8192〜 が大の枠。順序外が起きるのは
 * ロスのときだけなので、1 本のロックで足りる(受け取った側のコアと、接続を初期化するコアが
 * 違うことがあるので、コアごとには分けない)。 */
static smp_spinlock_t s_ooo_lock;
static uint8_t  s_ooo_small[TCP_OOO_SMALL_N][TCP_OOO_SMALL_BYTES] __attribute__((aligned(64)));
static uint8_t  s_ooo_big[TCP_OOO_BIG_N][TCP_OOO_BIG_BYTES] __attribute__((aligned(64)));
static uint32_t s_ooo_seq[TCP_OOO_NODES];
static uint16_t s_ooo_len[TCP_OOO_NODES];
static uint16_t s_ooo_next[TCP_OOO_NODES];
static uint16_t s_ooo_free_small[TCP_OOO_SMALL_N];
static uint16_t s_ooo_free_big[TCP_OOO_BIG_N];
static uint32_t s_ooo_nfree_small;
static uint32_t s_ooo_nfree_big;
static uint8_t  s_ooo_ready;
static uint32_t s_ooo_used;   /* 置き場全体の使用量(バイト) */

static inline uint32_t tcp_ooo_node_bytes(uint16_t n)
{
    return (n < TCP_OOO_SMALL_N) ? TCP_OOO_SMALL_BYTES : TCP_OOO_BIG_BYTES;
}

static inline uint8_t *tcp_ooo_data(uint16_t n)
{
    return (n < TCP_OOO_SMALL_N) ? s_ooo_small[n] : s_ooo_big[n - TCP_OOO_SMALL_N];
}

/*=================================================================
 * 置き場の空き一覧を初めて使うときに作る(s_ooo_lock を持って呼ぶ)。
 * ===============================================================*/
static void tcp_ooo_pool_init_locked(void)
{
    if (s_ooo_ready) return;
    for (uint32_t i = 0; i < TCP_OOO_SMALL_N; i++) {
        s_ooo_free_small[i] = (uint16_t)(TCP_OOO_SMALL_N - 1u - i);
    }
    for (uint32_t i = 0; i < TCP_OOO_BIG_N; i++) {
        s_ooo_free_big[i] = (uint16_t)(TCP_OOO_SMALL_N + TCP_OOO_BIG_N - 1u - i);
    }
    s_ooo_nfree_small = TCP_OOO_SMALL_N;
    s_ooo_nfree_big   = TCP_OOO_BIG_N;
    s_ooo_ready = 1;
}

/*=================================================================
 * 枠を 1 つ返す(s_ooo_lock を持って呼ぶ)。
 * ===============================================================*/
static void tcp_ooo_node_free_locked(tcp_priv_t *priv, uint16_t n)
{
    uint32_t b = tcp_ooo_node_bytes(n);
    if (n < TCP_OOO_SMALL_N) s_ooo_free_small[s_ooo_nfree_small++] = n;
    else                     s_ooo_free_big[s_ooo_nfree_big++] = n;
    s_ooo_used -= b;
    priv->ooo_bytes -= b;
    if (priv->ooo_count > 0) priv->ooo_count--;
}

/*=================================================================
 * 接続が持っている順序外のセグメントを全部捨てる(接続の初期化・後始末)。
 *
 * コール元:
 *   tcp_priv_init(), tcp_ooo_sweep()
 * ===============================================================*/
static void tcp_ooo_release_all(tcp_priv_t *priv)
{
    /* 一度も使っていない枠(.bss のゼロ = ooo_head 0)もここを通るので、数で判定する。 */
    if (priv->ooo_count == 0u && priv->ooo_bytes == 0u) { priv->ooo_head = TCP_OOO_NONE; return; }
    smp_spin_lock(&s_ooo_lock);
    uint16_t n = priv->ooo_head;
    while (n != TCP_OOO_NONE) {
        uint16_t nx = s_ooo_next[n];
        tcp_ooo_node_free_locked(priv, n);
        n = nx;
    }
    priv->ooo_head  = TCP_OOO_NONE;
    priv->ooo_bytes = 0;
    priv->ooo_count = 0;
    smp_spin_unlock(&s_ooo_lock);
}

/*=================================================================
 * 順序外に届いたセグメントを列へ入れる。**seq の順・重なり無し**を保つ:
 *   - 前のセグメントと重なる先頭は切り詰める(先に届いたほうを残す)
 *   - 丸ごと含んでしまう後ろのセグメントは捨てて、新しいほうで置き換える
 *   - 後ろのセグメントと重なる末尾は切り詰める
 * Linux の tcp_data_queue_ofo() と同じ扱い。
 *
 * 引数:
 *   priv / rcv_seq     - 接続の状態と、今の受信位置(seq > rcv_seq が前提)
 *   seq / data / len   - 受け取ったセグメント
 * 戻り値:
 *   1 = 置いた、0 = 全部持っていた(重複)、-1 = 接続の予算を超えるので捨てた
 *   -2 = 陰性対照の 64 個の上限で捨てた、-3 = 共有の置き場が尽きて捨てた
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static int tcp_ooo_insert(tcp_priv_t *priv, uint32_t seq,
                          const volatile uint8_t *data, uint16_t len)
{
    uint32_t s = seq, e = seq + len;
    smp_spin_lock(&s_ooo_lock);
    tcp_ooo_pool_init_locked();

    uint16_t prev = TCP_OOO_NONE, cur = priv->ooo_head;
    /* 新しい区間より完全に前にあるものは飛ばす。 */
    while (cur != TCP_OOO_NONE &&
           !tcp_seq_lt(s, s_ooo_seq[cur] + s_ooo_len[cur])) {   /* cur の終わり <= s */
        prev = cur;
        cur  = s_ooo_next[cur];
    }
    /* 前のセグメントが新しい区間の先頭にかかっている。 */
    if (cur != TCP_OOO_NONE && tcp_seq_lt(s_ooo_seq[cur], s)) {
        uint32_t cend = s_ooo_seq[cur] + s_ooo_len[cur];
        if (!tcp_seq_lt(cend, e)) {          /* 丸ごと持っている */
            smp_spin_unlock(&s_ooo_lock);
            return 0;
        }
        s    = cend;
        prev = cur;
        cur  = s_ooo_next[cur];
    }
    /* 新しい区間に丸ごと含まれるものは捨てる(新しいほうが同じ範囲を運んでいる)。 */
    while (cur != TCP_OOO_NONE &&
           !tcp_seq_lt(e, s_ooo_seq[cur] + s_ooo_len[cur])) {   /* cur の終わり <= e */
        uint16_t nx = s_ooo_next[cur];
        if (prev == TCP_OOO_NONE) priv->ooo_head = nx; else s_ooo_next[prev] = nx;
        tcp_ooo_node_free_locked(priv, cur);
        cur = nx;
    }
    /* 後ろのセグメントが末尾にかかっている。 */
    if (cur != TCP_OOO_NONE && tcp_seq_lt(s_ooo_seq[cur], e)) e = s_ooo_seq[cur];
    if (s == e) {
        smp_spin_unlock(&s_ooo_lock);
        return 0;
    }

    uint32_t n_len = e - s;
    int small = (n_len <= TCP_OOO_SMALL_BYTES);
    uint32_t nbytes = small ? TCP_OOO_SMALL_BYTES : TCP_OOO_BIG_BYTES;
    if (g_tcp_ooo_legacy) {
        if (priv->ooo_count >= TCP_OOO_SLOTS) {
            smp_spin_unlock(&s_ooo_lock);
            return -2;
        }
    } else if (priv->ooo_bytes + nbytes > g_tcp_rcvbuf) {
        smp_spin_unlock(&s_ooo_lock);
        return -1;
    }
    uint16_t node;
    if (small && s_ooo_nfree_small > 0u) {
        node = s_ooo_free_small[--s_ooo_nfree_small];
    } else if (s_ooo_nfree_big > 0u) {
        node = s_ooo_free_big[--s_ooo_nfree_big];   /* 小が尽きたら大で代用する */
        nbytes = TCP_OOO_BIG_BYTES;
        if (!g_tcp_ooo_legacy && priv->ooo_bytes + nbytes > g_tcp_rcvbuf) {
            s_ooo_free_big[s_ooo_nfree_big++] = node;
            smp_spin_unlock(&s_ooo_lock);
            return -1;
        }
    } else {
        smp_spin_unlock(&s_ooo_lock);
        return -3;
    }
    volatile_fast_copy(tcp_ooo_data(node), data + (s - seq), n_len);
    s_ooo_seq[node]  = s;
    s_ooo_len[node]  = (uint16_t)n_len;
    s_ooo_next[node] = cur;
    if (prev == TCP_OOO_NONE) priv->ooo_head = node; else s_ooo_next[prev] = node;
    priv->ooo_bytes += nbytes;
    priv->ooo_count++;
    s_ooo_used += nbytes;
    if (s_ooo_used > g_tcp_ooo_pool_peak) g_tcp_ooo_pool_peak = s_ooo_used;
    smp_spin_unlock(&s_ooo_lock);
    return 1;
}

/*=================================================================
 * 閉じた接続が持ったままの順序外のセグメントを返す(冷たい経路で、自コアの接続だけ)。
 * 接続が閉じる道は多いので、それぞれで返す代わりにここでまとめて拾う。
 *
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
static void tcp_ooo_sweep(unsigned core)
{
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        tcp_priv_t *pv = &s_priv[core][i];
        if (pv->ooo_head == TCP_OOO_NONE) continue;
        tcp_conn_t *c = s_conns[core][i];
        if (c == NULL || c->state == TCP_CLOSED || c->state == TCP_TIME_WAIT) {
            tcp_ooo_release_all(pv);
        }
    }
}

/*=================================================================
 * 置き場の状態(シェルの `tcprcvbuf` 表示用)。NULL 可。
 * ===============================================================*/
void tcp_ooo_pool_stats(uint32_t *used, uint32_t *total, uint32_t *peak)
{
    if (used)  *used  = s_ooo_used;
    if (total) *total = TCP_OOO_SMALL_N * TCP_OOO_SMALL_BYTES + TCP_OOO_BIG_N * TCP_OOO_BIG_BYTES;
    if (peak)  *peak  = g_tcp_ooo_pool_peak;
}

/*=================================================================
 * data を受信循環バッファへ追記する。折り返しをまたぐ場合は 2 回に分けて
 * volatile_fast_copy() を呼ぶ。呼び出し元が事前に空き容量を確認しておくこと。
 *
 * 引数:
 *   priv     - コネクションのプライベート状態
 *   data     - 追記するバイト列
 *   data_len - そのバイト数
 * コール元:
 *   tcp_deliver_data()
 * ===============================================================*/
static void tcp_rx_buf_push(tcp_priv_t *priv, const volatile uint8_t *data, uint16_t data_len)
{
    uint32_t write_pos = (uint32_t)((priv->rx_read + priv->rx_count) % TCP_RX_BUF_SIZE);

    uint32_t first_len = TCP_RX_BUF_SIZE - write_pos;
    if (first_len > data_len) first_len = data_len;

    uint64_t cpt0 = timer_now();
    volatile_fast_copy((volatile uint8_t *)&priv->rx_buf[write_pos], data, first_len);
    if (first_len < data_len) {
        volatile_fast_copy((volatile uint8_t *)&priv->rx_buf[0], data + first_len,
                            (uint16_t)(data_len - first_len));
    }
    g_tcp_copy2_ns    += get_ns_from(cpt0);
    g_tcp_copy2_bytes += data_len;
    priv->rx_count = priv->rx_count + data_len;
}

/*=================================================================
 * in-order で届いたデータを配置する。upcall が登録されていればその場で
 * upcall へ渡し(rx_buf を経由しない push 型受信)、無ければ rx_buf へ積む。
 *
 * 引数:
 *   priv / data / data_len - tcp_rx_buf_push() と同じ
 * コール元:
 *   tcp_input()
 * ===============================================================*/
static void tcp_deliver_data(tcp_priv_t *priv, const volatile uint8_t *data, uint16_t data_len)
{
    if (priv->recv_upcall) { // tcp_set_recv_upcall()で設定されるhandler
        // -> nvmet_io_rx_upcall(nvmet.c) / nvme_read_rx_upcall(nvme.c)
        priv->recv_upcall(priv->recv_upcall_ctx, data, data_len);
    } else {
        tcp_rx_buf_push(priv, data, data_len);
    }
}

/*=================================================================
 * push 型受信の upcall を登録する。以後このコネクションの in-order データは
 * rx_buf へ積まれず upcall へ直接渡る。
 *
 * 引数:
 *   conn - 対象コネクション
 *   fn   - 受信ハンドラ
 *   ctx  - ハンドラへ渡す任意のポインタ
 * コール元:
 *   nvme_read_pipelined_run(), nvmet_io_job_step_impl()
 * ===============================================================*/
static int tcp_send_segment(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags,
                             const void *data, uint16_t data_len);

/* [計測] 相手の受信ウィンドウの右端(snd_una + snd_win)を超えるデータを送った回数。
 * Linux は超えた分を捨てる(TcpExtBeyondWindow)ので、0 でなければ再送待ちが起きる。
 * path: 0=通常の 1 セグメント、1=LSO。`tcpasync` が表示する。 */
volatile uint64_t g_tcp_win_over[2];
volatile uint32_t g_tcp_win_over_last_off, g_tcp_win_over_last_len, g_tcp_win_over_last_win;

/*=================================================================
 * 相手の受信ウィンドウが 0 の間に、窓が開いたかを確かめる(持続タイマ、RFC 9293 3.8.6.1)。
 *
 * **ウィンドウ 0 のときにデータを送ってはいけない。** 以前は 0 を 1 と
 * みなして 1 バイト送っていたが、Linux は窓を超えた分を捨てる
 * (TcpExtBeyondWindow)ので、その 1 バイトの再送タイムアウト(200 ms)を
 * ウィンドウが 0 になるたびに待っていた(256KiB 書き込み qd32 が 30 MiB/s)。
 *
 * 確認は Linux の tcp_xmit_probe_skb() と同じ「**seq = 未確認の先頭 - 1、
 * 長さ 0**」。相手は既に受け取った範囲なので、現在のウィンドウを載せた
 * ACK を必ず返す。ウィンドウの更新は相手から自発的にも来るので、これは
 * その更新が落ちたときの保険である。
 *
 * 引数:
 *   conn / priv - 対象コネクション
 *   since       - 呼び出し側が持つ待ち始めの時刻(0 で初期化しておく)
 *   stuck       - 窓が足りずに送れない状態か(窓が 0、または未確認が無いのに
 *                 窓が次のセグメントより小さい)。0 なら待ち時間を初期化する
 * コール元:
 *   tcp_send(), tcp_short_wait(), tcp_send_async_ex()
 * ===============================================================*/
/* **間隔は RTO から始めて倍々にする**(RFC 9293 3.8.6.1 の SHLD-29/30: 持続タイマは
 * RTO で始め、指数で後退する)。以前は 200 ms 固定で、相手が長く窓を閉じていると
 * 200 ms ごとに確認を送り続けていた。上限は TCP_MAX_RTO_MS(8 秒)。窓が開いたら
 * (stuck = 0 で呼ばれたら)RTO へ戻す。
 * **窓 0 の間に送るものが溜まっているのは、送り手が窓待ちで止まっている間だけ**
 * (この実装の送信は窓が足りないとその場で待つ。キューに積んだまま放っておく経路は無い)。
 * 待っている送り手が毎回ここを呼ぶので、確認を送る役が居なくなることは無い。 */
volatile uint64_t g_tcp_zwp_count;

static void tcp_window_probe(tcp_conn_t *conn, tcp_priv_t *priv, uint64_t *since, int stuck)
{
    if (!stuck) {
        *since = 0;
        priv->zwp_interval_ms = 0;
        return;
    }
    if (priv->zwp_interval_ms == 0u) priv->zwp_interval_ms = priv->rto_ms ? priv->rto_ms : TCP_INITIAL_RTO_MS;
    if (*since == 0) {
        *since = timer_now();
        return;
    }
    if (!timeout_ms(*since, priv->zwp_interval_ms)) return;
    uint32_t saved = conn->snd_seq;
    conn->snd_seq = priv->snd_una - 1u;
    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
    conn->snd_seq = saved;
    g_tcp_zwp_count++;
    priv->zwp_interval_ms *= 2u;
    if (priv->zwp_interval_ms > TCP_MAX_RTO_MS) priv->zwp_interval_ms = TCP_MAX_RTO_MS;
    *since = timer_now();
}

static inline void tcp_win_check(const tcp_conn_t *conn, const tcp_priv_t *priv,
                                 uint32_t data_len, unsigned path)
{
    if (data_len == 0u || conn->state != TCP_ESTABLISHED) return;
    if (tcp_seq_gt(conn->snd_seq + data_len, priv->snd_una + conn->snd_win)) {
        g_tcp_win_over[path]++;
        g_tcp_win_over_last_off = conn->snd_seq - priv->snd_una;
        g_tcp_win_over_last_len = data_len;
        g_tcp_win_over_last_win = conn->snd_win;
    }
}

/* このコアで ACK を借りているコネクションがあるか。**0 のときは走査を
 * まるごと飛ばす**ので、nvmet を動かしていない経路には費用がかからない。 */
static uint8_t s_ack_deferred_any[SMP_MAX_CORES];

/*=================================================================
 * 借りたままの ACK をまとめて返す。**ポーリングの先頭で呼ぶ**ことで、
 * 「前回の巡回で応答が出なかったぶん」だけをここで返す形になり、
 * **遅延はポーリング 1 周に収まる**(ジョブの巡回待ちにしない)。
 *
 * ジョブ側の `tcp_ack_flush()` だけに任せると、1 コアで 3〜4 本の IO キューを
 * 回すときに自分の番が来るまで待つことになり、**512B の高速な条件で
 * 12〜15% 落ちた**。
 *
 * コール元:
 *   net_poll_all_and_dispatch()
 * ===============================================================*/
static void tcp_ack_thin_note(tcp_priv_t *priv, unsigned core, int expired)
{
    if (expired) { g_tcp_ack_by_expiry[core]++; priv->thin_exp++; }
    else g_tcp_ack_by_count[core]++;
    if (++priv->thin_n < 256u) return;
    if (g_tcp_ack_adapt != 0u && (uint32_t)priv->thin_exp * 100u >= g_tcp_ack_adapt * (uint32_t)priv->thin_n) {
        priv->ack_thin_off = 1;
        g_tcp_ack_thin_off[core]++;
    }
    priv->thin_n = 0;
    priv->thin_exp = 0;
}

void tcp_ack_flush_deferred(void)
{
    unsigned core = smp_core_index();
    if (!s_ack_deferred_any[core]) return;
    uint8_t still = 0;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        tcp_conn_t *c = s_conns[core][i];
        if (c == NULL) continue;
        tcp_priv_t *priv = &s_priv[core][i];
        if (!priv->ack_deferred) continue;
        if (--priv->ack_deferred != 0u) { still = 1; continue; }
        if (priv->ack_hold_thin) tcp_ack_thin_note(priv, core, 1);
        tcp_send_segment(c, priv, TCP_FLAG_ACK, NULL, 0);
    }
    s_ack_deferred_any[core] = still;
}

/*=================================================================
 * 借りている ACK があれば裸の ACK で返す。**応答を出し終えた直後に
 * 必ず呼ぶこと** -- 応答が出ていれば相乗り済みで何もしないが、
 * 出なかった(PDU が途中までしか届いていない等)ときはここで返さないと
 * 相手が RTO まで待つ。
 *
 * 引数:
 *   conn - 対象コネクション
 * 戻り値:
 *   1=裸の ACK を送った、0=借りが無い
 * コール元:
 *   nvmet_io_job_step_impl() の ready-ring 排出ループ
 * ===============================================================*/
/*=================================================================
 * このコネクションで ACK の相乗りを使うかどうかを設定する。
 *
 * **既定は無効。** 相乗りが得かどうかは相手の状態で逆転する --
 * 相手に余裕があるとき(IO キュー 4 本)は +9% だが、相手が飽和している
 * とき(1〜3 本、相手の cpu0 が 85〜90%)は **ACK が送信のペーシングに
 * 効いている**ので 4〜16% 損をする。**そのため呼び出し側(nvmet)が
 * キュー数を見て決める。**
 *
 * 引数:
 *   conn - 対象コネクション
 *   on   - 1=相乗りする
 * コール元:
 *   nvmet_io_job_step_impl()(IO キュー確立時)
 * ===============================================================*/
void tcp_set_ack_piggyback(tcp_conn_t *conn, int on)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->ack_piggy_ok = on ? 1u : 0u;
    if (!on) priv->ack_deferred = 0u;
}

int tcp_ack_flush(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv || !priv->ack_deferred) return 0;
    priv->ack_deferred = 0;
    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
    return 1;
}

/*=================================================================
 * ACK を借りたままかどうか(ジョブが眠ってよいかの判定に使う)。
 * コール元: nvmet_io_job_step_impl()
 * ===============================================================*/
int tcp_ack_owed(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return (priv && priv->ack_deferred) ? 1 : 0;
}

void tcp_set_recv_upcall(tcp_conn_t *conn, tcp_recv_upcall_fn fn, void *ctx)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->recv_upcall     = fn;
    priv->recv_upcall_ctx = ctx;
}

/*=================================================================
 * push 型受信の upcall を解除し、以後は rx_buf 経由の pull 型受信へ戻す。
 *
 * 引数:
 *   conn - 対象コネクション
 * コール元:
 *   nvme_read_pipelined_run(), nvmet_io_job_end(), nvmet_io_job_step_impl()
 * ===============================================================*/
void tcp_clear_recv_upcall(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->recv_upcall     = NULL;
    priv->recv_upcall_ctx = NULL;
}

/*=================================================================
 * RTT 推定を更新する(RFC 6298 の SRTT/RTTVAR、alpha=1/8・beta=1/4・K=4)。
 * Karn のアルゴリズムに従い、再送したセグメントの計測値は呼び出し元が除く。
 *
 * 引数:
 *   priv           - コネクションのプライベート状態
 *   measured_ticks - 実測 RTT(tick 差分)
 * コール元:
 *   tcp_connect_poll(), tcp_send(), tcp_send_reliable()
 * ===============================================================*/
/*=================================================================
 * 窓付きの最小値(Linux の lib/win_minmax.c の minmax_running_min() を写した)。標本を 3 つ持ち、
 * [0] が窓の中の最小、[1] / [2] は窓の後ろ 3/4・後ろ 1/2 の最小の候補。古い [0] が窓から外れたら
 * [1] を繰り上げる。
 *
 * 引数:
 *   priv - コネクションのプライベート状態
 *   now  - 標本の時刻(timer_now() の ns)
 *   v    - 標本(往復時間 ns)
 * コール元:
 *   tcp_rtt_update()
 * ===============================================================*/
static void tcp_minrtt_update(tcp_priv_t *priv, uint64_t now, uint64_t v)
{
    const uint64_t win = (uint64_t)g_tcp_rack_minrtt_win_ms * 1000000u;
    if (!priv->rack_mm_valid || v <= priv->rack_mm[0].v || now - priv->rack_mm[2].t > win) {
        for (unsigned i = 0; i < 3u; i++) { priv->rack_mm[i].t = now; priv->rack_mm[i].v = v; }
        priv->rack_mm_valid = 1;
        return;
    }
    if (v <= priv->rack_mm[1].v) {
        priv->rack_mm[2].t = priv->rack_mm[1].t = now;
        priv->rack_mm[2].v = priv->rack_mm[1].v = v;
    } else if (v <= priv->rack_mm[2].v) {
        priv->rack_mm[2].t = now; priv->rack_mm[2].v = v;
    }
    const uint64_t dt = now - priv->rack_mm[0].t;
    if (dt > win) {
        /* 最小の標本が窓から外れた: 後ろの候補を繰り上げる(2 段外れていることもある)。 */
        priv->rack_mm[0] = priv->rack_mm[1];
        priv->rack_mm[1] = priv->rack_mm[2];
        priv->rack_mm[2].t = now; priv->rack_mm[2].v = v;
        if (now - priv->rack_mm[0].t > win) {
            priv->rack_mm[0] = priv->rack_mm[1];
            priv->rack_mm[1] = priv->rack_mm[2];
            priv->rack_mm[2].t = now; priv->rack_mm[2].v = v;
        }
    } else if (priv->rack_mm[1].t == priv->rack_mm[0].t && dt > win / 4u) {
        /* 窓の 1/4 が過ぎても候補が [0] と同じなら、今の標本を 2 番目・3 番目の候補にする。 */
        priv->rack_mm[2].t = priv->rack_mm[1].t = now;
        priv->rack_mm[2].v = priv->rack_mm[1].v = v;
    } else if (priv->rack_mm[2].t == priv->rack_mm[1].t && dt > win / 2u) {
        priv->rack_mm[2].t = now; priv->rack_mm[2].v = v;
    }
}

/* 窓の中の最小の往復時間(ns。まだ標本が無ければ 0)。 */
static inline uint64_t tcp_minrtt(const tcp_priv_t *priv)
{
    return priv->rack_mm_valid ? priv->rack_mm[0].v : 0u;
}

static void tcp_rtt_update(tcp_priv_t *priv, uint64_t measured_ticks, uint64_t now)
{
    g_tcp_rtt_update_count++;
    uint64_t measured_us = ticks_to_us(measured_ticks);
    /* RACK の往復時間(直近の標本と窓付きの最小値)。timer_now() は ns なので ticks のまま持つ。 */
    priv->rack_rtt_last_ns = measured_ticks;
    if (measured_ticks != 0u) tcp_minrtt_update(priv, now, measured_ticks);

    if (priv->srtt_us == 0) {
        priv->srtt_us = measured_us;
        priv->rttvar_us = measured_us / 2u;
    } else {
        int64_t delta = (int64_t)measured_us - (int64_t)priv->srtt_us;
        uint64_t abs_delta = (uint64_t)((delta < 0) ? -delta : delta);
        priv->rttvar_us = (priv->rttvar_us * 3u + abs_delta) / 4u;
        priv->srtt_us = (priv->srtt_us * 7u + measured_us) / 8u;
    }

    uint64_t rto_us = priv->srtt_us + 4u * priv->rttvar_us;
    uint32_t rto_ms = (uint32_t)(rto_us / 1000u);
    if (rto_ms < TCP_RTO_MIN_MS) rto_ms = TCP_RTO_MIN_MS;
    if (rto_ms > TCP_MAX_RTO_MS) rto_ms = TCP_MAX_RTO_MS;
    priv->rto_ms = rto_ms;
}

/* フレームは常に seg_buf の先頭から始まり、TCP ヘッダの位置だけが family で
 * 変わる(IPv4=14+20=34、IPv6=14+40=54)。IPv4 のレイアウトを一切変えないため
 * この形にしてある -- 一度「TCP ヘッダ位置を family 非依存にする」ために L3 を
 * 右詰めしたところ、IPv4 のフレーム開始が 64 バイト境界から外れ、8KB の小さい
 * I/O で TCP スループットが 6〜9% 落ちることを実測した。
 * スロットサイズは 64 の倍数へ切り上げ、どのスロットも 64 バイト境界から
 * 始まるようにする(NIC が読む先頭を揃える)。 */
#define TCP_L4_OFFSET_V6 (ETH_HDR_LEN + IPV6_HDR_LEN)   /* 54 */
/* オプション領域の最大長。SYN のとき MSS(4) + NOP+WScale(4) +
 * NOP+NOP+Timestamps(12) + NOP+NOP+SACK-Permitted(4) = 24 バイト。
 * 確立後の純 ACK は Timestamps(12) + NOP+NOP+SACK 3 ブロック(28) = 40 で、
 * こちらのほうが大きい(データオフセットの上限ちょうど)。 */
#define TCP_OPT_MAX_LEN  40u
#define TCP_SEG_BUF_RAW  (TCP_L4_OFFSET_V6 + TCP_HDR_LEN + TCP_OPT_MAX_LEN + TCP_MSS_LOCAL)
#define TCP_SEG_BUF_SIZE (((TCP_SEG_BUF_RAW) + 63u) & ~63u)

/* [コア][送信キュー(PF)][スロット]。**送信キューでも分ける**(netif.h の txq_index)。 */
static uint8_t s_seg_bufs[SMP_MAX_CORES][NETIF_TXQ_MAX][ETH_TX_RING_SIZE][TCP_SEG_BUF_SIZE]
    __attribute__((aligned(64)));

/*=================================================================
 * seg_buf 内で TCP ヘッダが始まるオフセットを返す(L2+L3 ヘッダ長)。
 *
 * 引数:
 *   a - コネクションのアドレス(family だけ見る)
 * 戻り値:
 *   IPv4=34、IPv6=54
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_bare_ack()
 * ===============================================================*/
static inline unsigned tcp_l4_off(const netaddr_t *a)
{
    return (a->family == NETADDR_V6) ? TCP_L4_OFFSET_V6 : IP_PAYLOAD_OFFSET;
}

/*=================================================================
 * 相手の family に応じた広告 MSS の上限を返す。
 *
 * 引数:
 *   remote - 相手のアドレス(family だけ見る)
 * 戻り値:
 *   広告してよい MSS の上限
 * コール元:
 *   tcp_send_segment() 系(SYN の MSS オプション組み立て)
 * ===============================================================*/
/*=================================================================
 * 宛先の family に応じた L3 ヘッダ長を返す(IPv4=20、IPv6=40)。
 *
 * 引数:
 *   a - アドレス(family だけ見る)
 * 戻り値:
 *   L3 ヘッダのバイト数
 * コール元:
 *   tcp_mss_cap_for(), tcp_pmtu_update()
 * ===============================================================*/
static inline unsigned tcp_l3_hdr_len(const netaddr_t *a)
{
    return (a->family == NETADDR_V6) ? IPV6_HDR_LEN : (unsigned)sizeof(ip_header_t);
}

static inline uint16_t tcp_mss_cap_for(const netaddr_t *remote)
{
    uint16_t cap = net_active_mss_cap();
    if (remote->family == NETADDR_V6) {
        /* netif_t.mss_cap は IPv4(L3 ヘッダ 20 バイト)前提で決めてある。
         * IPv6 は L3 が 40 バイトなので差分の 20 を引かないと、フルサイズ
         * セグメントがリンク MTU を 20 バイト超え、NIC に無言で捨てられる
         * (CLAUDE.md「境界値ぴったりのサイズだけが失敗する」の再来になる)。 */
        cap = (cap > 20u) ? (uint16_t)(cap - 20u) : cap;
    }
    /* 経路 MTU を学習済みならそちらで頭打ちにする。この関数は SYN を組む
     * ときだけ呼ばれる冷たい経路なので、表を引くコストは問題にならない
     * (セグメントごとの上限は conn->snd_mss 側で持っている)。 */
    uint16_t pm = pmtu_lookup(remote);
    if (pm != 0u) {
        uint16_t overhead = (uint16_t)(tcp_l3_hdr_len(remote) + TCP_HDR_LEN);
        if (pm > overhead) {
            uint16_t pcap = (uint16_t)(pm - overhead);
            if (pcap < cap) cap = pcap;
        }
    }
    return cap;
}

/*=================================================================
 * 経路 MTU を学習したとき、その宛先の確立済みコネクションの snd_mss を
 * 切り下げる。**全コアのスロットを走査する**(ICMP を受けたコアと
 * コネクションを持つコアは違いうる)。
 *
 * 途中で MSS を下げても、既に送信済み・未確認のセグメントとの整合は要らない
 * -- TCP はセグメント境界を自由に変えてよいので「以後の新規セグメントから
 * 小さくする」で足りる。ただし**再送は保存済みのスロットをそのまま送り直す**
 * ので、下げた直後の再送だけは新しい PMTU を超えることがある(再分割は
 * 実装していない)。
 *
 * 引数:
 *   dst  - PMTU を学習した宛先
 *   pmtu - 学習した MTU
 * コール元:
 *   pmtu_learn()
 * ===============================================================*/
void tcp_pmtu_update(const netaddr_t *dst, uint16_t pmtu)
{
    uint16_t overhead = (uint16_t)(tcp_l3_hdr_len(dst) + TCP_HDR_LEN);
    if (pmtu <= overhead) return;
    uint16_t mss = (uint16_t)(pmtu - overhead);
    /* 呼ぶ側(icmp.c / ipv6.c)は tcp_icmp_error(..., TCP_ICMP_PMTU) が 1 を返した(引用の seq が
     * 送った範囲に入っていた)ときだけ pmtu_learn() に進む(RFC 5927 の検査)。ここでは下限だけ守る。 */
    if (mss < TCP_MSS_MIN) mss = TCP_MSS_MIN;

    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            tcp_conn_t *cn = s_conns[c][i];
            if (!cn || cn->state == TCP_CLOSED) continue;
            if (!netaddr_eq((const netaddr_t *)&cn->remote_ip, dst)) continue;
            /* Timestamps を載せているぶん、ペイロードの上限はさらに小さい
             * (tcp_parse_syn_options() の末尾と同じ理由)。 */
            uint16_t conn_mss = mss;
            if (s_priv[c][i].ts_enabled && conn_mss > TCP_TS_OPT_LEN * 4u) {
                conn_mss = (uint16_t)(conn_mss - TCP_TS_OPT_LEN);
            }
            if (cn->snd_mss <= conn_mss) continue;
            uart_printf("[PMTU] コネクション (port %u->%u) の snd_mss を %u -> %u へ切り下げ\n",
                        cn->local_port, cn->remote_port, cn->snd_mss, conn_mss);
            cn->snd_mss = conn_mss;
        }
    }
}

/*=================================================================
 * 送信先 MAC を解決する。IPv4 は ARP、IPv6 は NDP。宛先が自分のサブネット
 * 外ならゲートウェイの MAC を引く(netif_next_hop4/6)。
 *
 * 引数:
 *   remote  - 相手のアドレス
 *   out_mac - 解決した MAC の格納先
 * 戻り値:
 *   0=解決できた、-1=失敗
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_bare_ack()
 * ===============================================================*/
/*=================================================================
 * 上位層の到達確認フラグを 1 回ぶん消費する(NUD、RFC 4861 7.3.1)。
 *
 * 「累積 ACK が進んだ」は 1 回きりの事実なので、近隣キャッシュの延命に
 * 使ったら落とす。落とさないと、相手が居なくなっても延命し続けてしまう。
 *
 * 引数:
 *   priv - コネクションの内部状態
 * 戻り値:
 *   1=前回の送信以降に累積 ACK が進んだ、0=進んでいない
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso()
 * ===============================================================*/
static inline int tcp_take_confirm(tcp_priv_t *priv)
{
    if (!priv || !priv->neigh_confirm) return 0;
    priv->neigh_confirm = 0;
    return 1;
}

static inline int tcp_resolve_mac(const netaddr_t *remote, uint8_t out_mac[ETH_ALEN],
                                   int confirmed)
{
    /* 解決する相手は「宛先」ではなく「次ホップ」。同一サブネットなら両者は
     * 同じで、サブネット外ならゲートウェイになる(L3 の宛先は変えず、L2 の
     * 宛先だけをルータへ向ける)。ゲートウェイ未設定なら分岐 1 個で素通りする。
     *
     * confirmed は「相手が自分のデータを受け取ったことを TCP が確認した」の
     * 意味(NUD の上位層確認、RFC 4861 7.3.1)。**時刻の読み出しはキャッシュ
     * 照合が当たったときにしか起きない**ので、ホットパスへの追加コストは
     * 引数 1 個ぶんの分岐だけ。 */
    if (remote->family == NETADDR_V6) {
        const uint8_t *nh = netif_next_hop6(g_active_ctx, remote->a);
        if (ndp_cache_lookup_nud(nh, out_mac, confirmed) == 0) return 0;
        return ndp_resolve(nh, out_mac);
    }
    uint32_t ip = netif_next_hop4(g_active_ctx, netaddr_v4_host(remote));
    if (arp_cache_lookup_nud(ip, out_mac, confirmed) == 0) return 0;
    return arp_resolve(ip, out_mac);
}

/*=================================================================
 * コネクションのローカルアドレスから送信元インターフェースを引く。
 *
 * 引数:
 *   local - 自分側のアドレス
 * 戻り値:
 *   見つかった netif_t、無ければ NULL
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_bare_ack() 等
 * ===============================================================*/
static inline netif_t *tcp_netif_for(const netaddr_t *local)
{
    if (local->family == NETADDR_V6) return netif_find_by_ip6(local->a);
    return netif_find_by_ip(netaddr_v4_host(local));
}

/*=================================================================
 * seg_buf に Ethernet + L3 ヘッダを右詰めで組み立てる。
 *
 * 引数:
 *   seg_buf  - セグメントバッファ先頭
 *   conn     - アドレスを持つコネクション
 *   dst_mac  - 宛先 MAC
 *   seg_len  - TCP ヘッダ + データのバイト数(L3 ペイロード長)
 * コール元:
 *   tcp_send_segment(), tcp_send_bare_ack()
 * ===============================================================*/
static inline void tcp_build_l3(uint8_t *seg_buf, const netaddr_t *local, const netaddr_t *remote,
                          const uint8_t dst_mac[ETH_ALEN], uint16_t seg_len)
{
    if (remote->family == NETADDR_V6) {
        ipv6_build_header(seg_buf, local->a, remote->a, dst_mac, IP_PROTO_TCP, seg_len);
    } else {
        uint8_t dst_octets[4];
        for (unsigned i = 0; i < 4; i++) dst_octets[i] = remote->a[i];
        ip_build_header(seg_buf, dst_octets, dst_mac, IP_PROTO_TCP, seg_len);
    }
}

/*=================================================================
 * TCP チェックサムを計算する(疑似ヘッダは family ごとに形が違う)。
 * hw_partial が真なら疑似ヘッダだけの部分和を返す(残りは NIC が完成させる)。
 *
 * 引数:
 *   local / remote - 疑似ヘッダのアドレス
 *   tcph / hdr_len - TCP ヘッダ(オプション込み)
 *   data/data_len  - ペイロード(無ければ NULL/0)
 *   hw_partial     - 1=疑似ヘッダのみ、0=全体を計算
 * 戻り値:
 *   チェックサム値
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_bare_ack()
 * ===============================================================*/
static inline uint16_t tcp_checksum(const netaddr_t *local, const netaddr_t *remote,
                              const volatile uint8_t *tcph, uint16_t hdr_len,
                              const void *data, uint16_t data_len, int hw_partial)
{
    uint16_t seg_len = (uint16_t)(hdr_len + data_len);
    if (remote->family == NETADDR_V6) {
        if (hw_partial) {
            return ipv6_pseudo_checksum_only(local->a, remote->a, IP_PROTO_TCP, seg_len);
        }
        return ipv6_pseudo_checksum2(local->a, remote->a, IP_PROTO_TCP,
                                      tcph, hdr_len, data, data_len);
    }
    if (hw_partial) {
        return pseudo_header_checksum_only(local->a, remote->a, IP_PROTO_TCP, seg_len);
    }
    return pseudo_header_checksum2(local->a, remote->a, IP_PROTO_TCP,
                                    tcph, hdr_len, data, data_len);
}

/*=================================================================
 * 広告する受信ウィンドウの「ワイヤ上の値」を計算する(Window Scale 適用後)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   flags       - 送出するフラグ(SYN のときはスケールを掛けない)
 * 戻り値:
 *   TCP ヘッダの window フィールドに書く 16bit 値
 * コール元:
 *   tcp_send_segment(), tcp_recv_internal()
 * ===============================================================*/
static uint32_t tcp_rcv_window_bytes(const tcp_conn_t *conn, const tcp_priv_t *priv)
{
    /* 受信キューの容量の半分。窓いっぱいのデータが一度に届いても、受信キューの
     * 枠が尽きないようにする。 */
    uint32_t cap = (uint32_t)net_active_rx_ring_size() * (uint32_t)conn->snd_mss / 2u;
    /* **順序外で保持できる量より大きな窓を広告しない。** 広告値だけ大きいと、
     * 穴が 1 つできた瞬間に受信側が自分で捨てることになり、その損失は相手からは
     * 見えない(SACK では再送されず RTO 待ちになる)。予算は枠の大きさで数えるので、
     * 窓はその半分にして余白を取る(tcp_ooo_insert())。 */
    uint32_t ooo_cap = g_tcp_ooo_legacy ? (uint32_t)TCP_OOO_SLOTS * (uint32_t)conn->snd_mss
                                        : g_tcp_rcvbuf / 2u;
    if (cap > ooo_cap) cap = ooo_cap;
    if (g_tcp_rwin_cap) cap = g_tcp_rwin_cap;   /* [試験] tcprwin */
    /* upcall の無い接続は、順番どおりのデータを rx_buf に積むので、その空きも上限になる。 */
    if (priv->recv_upcall == NULL) {
        uint32_t room = TCP_RX_BUF_SIZE - priv->rx_count;
        if (cap > room) cap = room;
    }
    return cap;
}

/*=================================================================
 * 広告する受信窓のワイヤ上の値と、その右端(RCV.NXT + RCV.WND)を計算する。**記録はしない**
 * (送ったときだけ呼び出し側が rcv_wnd_edge に入れる。送らずに捨てる窓の更新 ACK で右端だけ
 * 進めると、相手が知らない右端を基準に受信窓の外を判定してしまう)。
 *
 * 右端の決め方(RFC 9293 3.8.6.2.2 / RFC 1122 4.2.3.3):
 *   - **縮めない**(SHLD-14)。前回広告した右端より手前には戻さない。**ただし pull 型(rx_buf)の
 *     接続は例外**で、rx_buf の実際の空きより先は約束しない(下の Window Scale の枝の説明)。
 *   - **小さく広げない**(MUST-39、受け手の SWS 回避)。右端を進めるのは、増やせる量が
 *     min(受信の余地の半分, MSS) 以上になったときだけ。少しずつ広げると、相手は小さな
 *     セグメントを送り続ける(silly window)。upcall の接続は窓がほぼ一定なので、MSS 未満の
 *     受信のぶん広告が少し小さく見えるだけ(既定の窓 1.15MB に対して高々 1 MSS)。
 *   - Window Scale のときは切り上げる(切り捨てると、rcv_seq が 2^shift の倍数でないぶん
 *     右端が毎回少し縮む。Linux も切り上げる)。
 * 同じ ack・同じ右端なら同じ値になるので、相手が数える重複 ACK も崩さない。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   flags       - 送出するフラグ(SYN のときはスケールを掛けない、RFC 7323 2.2)
 *   edge_out    - 広告する右端(NULL 可)
 * 戻り値:
 *   TCP ヘッダの window フィールドに書く 16bit 値
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso(), tcp_send_window_update()
 * ===============================================================*/
static uint16_t tcp_wire_window(const tcp_conn_t *conn, const tcp_priv_t *priv, uint8_t flags,
                                uint32_t *edge_out)
{
    uint32_t actual_window = tcp_rcv_window_bytes(conn, priv);
    const uint32_t rcv = conn->rcv_seq;
    if ((flags & TCP_FLAG_SYN) || !priv->wscale_enabled) {
        if (actual_window > 0xFFFFu) actual_window = 0xFFFFu;
        if (!(flags & TCP_FLAG_SYN) && priv->rcv_wnd_valid) {
            const uint32_t old = priv->rcv_wnd_edge;
            const uint32_t ne  = rcv + actual_window;
            uint32_t thr = conn->snd_mss;
            if (thr > actual_window / 2u) thr = actual_window / 2u;
            if (!tcp_seq_gt(ne, old) || (ne - old) < thr) {
                /* 縮めない / 小さく広げない: 前回の右端のまま(rcv がそれを越えていれば 0)。 */
                actual_window = tcp_seq_gt(old, rcv) ? old - rcv : 0u;
                if (actual_window > 0xFFFFu) actual_window = 0xFFFFu;
            }
        }
        if (priv->recv_upcall == NULL) {
            /* pull 型は rx_buf の実際の空きより先を約束しない(下の Window Scale の枝と同じ理由)。 */
            uint32_t room = TCP_RX_BUF_SIZE - priv->rx_count;
            if (actual_window > room) actual_window = room;
        }
        if (edge_out) *edge_out = rcv + actual_window;
        return (uint16_t)actual_window;
    }
    const uint8_t sc = priv->rcv_wscale;
    const uint32_t maxw = (uint32_t)0xFFFFu << sc;
    if (actual_window > maxw) actual_window = maxw;
    if (priv->rcv_wnd_valid) {
        const uint32_t old = priv->rcv_wnd_edge;
        const uint32_t ne  = rcv + actual_window;
        uint32_t thr = conn->snd_mss;
        if (thr > actual_window / 2u) thr = actual_window / 2u;
        if (!tcp_seq_gt(ne, old) || (ne - old) < thr) {
            actual_window = tcp_seq_gt(old, rcv) ? old - rcv : 0u;
        }
    }
    uint32_t scaled;
    if (priv->recv_upcall == NULL) {
        /* **pull 型(rx_buf に積む)の接続は、rx_buf の実際の空きより先を約束しない。**
         * 縮めない規則(SHLD-14)をここでは破る:読み出しが遅れて空きが減ったときに右端を
         * 据え置くと、約束したぶんが置けずに捨てることになり、相手は高速再送と RTO で
         * cwnd を下げる(2 ポートを 1 コアで受ける ESP 越しの iSCSI の書き込みで、捨てが
         * 10 秒に約 600 回起き、書き込みが 13% 落ちた)。Window Scale も同じ理由で切り捨てる
         * (切り上げると空きより最大 2^shift - 1 バイト多く約束する)。 */
        uint32_t room = TCP_RX_BUF_SIZE - priv->rx_count;
        if (actual_window > room) actual_window = room;
        scaled = actual_window >> sc;                                /* 切り捨て */
    } else {
        scaled = (actual_window + ((1u << sc) - 1u)) >> sc;          /* 切り上げ */
    }
    if (scaled > 0xFFFFu) scaled = 0xFFFFu;
    if (edge_out) *edge_out = rcv + (scaled << sc);
    return (uint16_t)scaled;
}

typedef struct { uint32_t start, end; } tcp_sack_range_t;

/* 受け取り済みのデータ [s, e) が届いた。SACK を合意した接続なら、次の純 ACK で DSACK として知らせる。 */
static inline void tcp_dsack_note(tcp_priv_t *priv, uint32_t s, uint32_t e)
{
    if (!priv->sack_enabled || !g_tcp_dsack_enable || s == e) return;
    priv->dsack_valid = 1;
    priv->dsack_start = s;
    priv->dsack_end   = e;
}

/*=================================================================
 * 受信側として相手へ知らせる SACK ブロックを組み立てる。順序不正のまま
 * 保持しているセグメント(ooo[])を連続する区間へまとめ、RFC 2018 に
 * 従って**直近に受け取った区間を先頭**に置く。
 *
 * 引数:
 *   priv / conn - 対象コネクションとプライベート状態
 *   out         - 最大 TCP_SACK_MAX_BLOCKS 個の格納先
 * 戻り値:
 *   ブロック数(0 なら SACK オプションを載せない)
 * コール元:
 *   tcp_options_len(), tcp_build_options()
 * ===============================================================*/
static unsigned tcp_sack_collect(const tcp_priv_t *priv, const tcp_conn_t *conn,
                                  tcp_sack_range_t out[TCP_SACK_MAX_BLOCKS])
{
    unsigned n = 0;
    /* **DSACK は先頭のブロックに置く**(RFC 2883 4)。相手は「先頭のブロックが累積 ACK より前か、
     * 2 番目のブロックに含まれる」ことで DSACK と見分ける。 */
    if (priv->dsack_valid) {
        out[0].start = priv->dsack_start;
        out[0].end   = priv->dsack_end;
        n = 1;
    }
    if (priv->sack_tx_count == 0u) return n;

    /* 直近に触った区間を先頭に置く(RFC 2018 4: 相手はこれで最新の状況を
     * 必ず受け取れる -- 後ろのブロックは ACK が落ちると失われうる)。 */
    unsigned first = priv->sack_tx_recent;
    for (unsigned k = 0; k < priv->sack_tx_count && n < TCP_SACK_MAX_BLOCKS; k++) {
        unsigned i = (k == 0) ? first : ((k <= first) ? (k - 1u) : k);
        uint32_t s = priv->sack_tx[i].start;
        uint32_t e = priv->sack_tx[i].end;
        /* 累積 ACK で既に伝えた範囲は SACK に入れない(RFC 2018 4)。 */
        if (!tcp_seq_lt(conn->rcv_seq, e)) continue;
        if (tcp_seq_lt(s, conn->rcv_seq)) s = conn->rcv_seq;
        out[n].start = s;
        out[n].end   = e;
        n++;
    }
    return n;
}

/*=================================================================
 * 順序不正で受け取った区間を、受信側の「届いている区間」リストへ足す。
 * 既存の区間と隣接/重複していれば伸ばし、その結果さらに別の区間と
 * つながったら結合する。**1 セグメントあたり O(区間数)** で済ませるための
 * 差分更新(送るたびに ooo[] から作り直すと ACK ごとに O(n^3) になる)。
 *
 * 引数:
 *   priv     - コネクションのプライベート状態
 *   seq, len - 受け取った区間
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static void tcp_sack_tx_add(tcp_priv_t *priv, uint32_t seq, uint16_t len)
{
    uint32_t s = seq, e = seq + len;
    int idx = -1;
    for (unsigned i = 0; i < priv->sack_tx_count; i++) {
        if (!tcp_seq_lt(s, priv->sack_tx[i].start) && !tcp_seq_lt(priv->sack_tx[i].end, e)) {
            idx = (int)i;  /* 既に含まれている */
            break;
        }
        if (priv->sack_tx[i].end == s)   { priv->sack_tx[i].end = e;   idx = (int)i; break; }
        if (priv->sack_tx[i].start == e) { priv->sack_tx[i].start = s; idx = (int)i; break; }
    }
    if (idx < 0) {
        if (priv->sack_tx_count < TCP_SACK_TX_MAX) {
            idx = (int)priv->sack_tx_count++;
        } else {
            /* 溢れた。直近のもの以外を 1 つ捨てる(相手が余分に送り直すだけ)。 */
            idx = (int)((priv->sack_tx_recent + 1u) % TCP_SACK_TX_MAX);
        }
        priv->sack_tx[idx].start = s;
        priv->sack_tx[idx].end   = e;
    }
    /* 伸びた結果ほかの区間とつながったら結合する。 */
    for (unsigned j = 0; j < priv->sack_tx_count; ) {
        if ((int)j == idx) { j++; continue; }
        if (tcp_seq_lt(priv->sack_tx[idx].end, priv->sack_tx[j].start) ||
            tcp_seq_lt(priv->sack_tx[j].end, priv->sack_tx[idx].start)) {
            j++;
            continue;
        }
        if (tcp_seq_lt(priv->sack_tx[j].start, priv->sack_tx[idx].start)) {
            priv->sack_tx[idx].start = priv->sack_tx[j].start;
        }
        if (tcp_seq_lt(priv->sack_tx[idx].end, priv->sack_tx[j].end)) {
            priv->sack_tx[idx].end = priv->sack_tx[j].end;
        }
        priv->sack_tx_count--;
        priv->sack_tx[j] = priv->sack_tx[priv->sack_tx_count];
        if (idx == (int)priv->sack_tx_count) idx = (int)j;  /* 末尾を動かした */
        /* j はそのまま(入れ替えた要素を見る) */
    }
    priv->sack_tx_recent = (uint8_t)idx;
}

/*=================================================================
 * 累積 ACK が進んだぶんを「届いている区間」リストから落とす。
 *
 * 引数:
 *   priv    - コネクションのプライベート状態
 *   rcv_seq - 新しい累積 ACK 位置
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static void tcp_sack_tx_trim(tcp_priv_t *priv, uint32_t rcv_seq)
{
    for (unsigned i = 0; i < priv->sack_tx_count; ) {
        if (!tcp_seq_lt(rcv_seq, priv->sack_tx[i].end)) {
            priv->sack_tx_count--;
            priv->sack_tx[i] = priv->sack_tx[priv->sack_tx_count];
            if (priv->sack_tx_recent >= priv->sack_tx_count) priv->sack_tx_recent = 0;
            continue;  /* 入れ替えた要素をもう一度見る */
        }
        if (tcp_seq_lt(priv->sack_tx[i].start, rcv_seq)) priv->sack_tx[i].start = rcv_seq;
        i++;
    }
}

static inline unsigned tcp_sack_block_count(const tcp_priv_t *priv, const tcp_conn_t *conn)
{
    tcp_sack_range_t tmp[TCP_SACK_MAX_BLOCKS];
    return tcp_sack_collect(priv, conn, tmp);
}

/*=================================================================
 * [seq, seq+len) が「相手に届いている」と SACK で分かっているかを返す。
 * 高速再送のときに、届いている範囲を送り直さないために使う。
 *
 * **範囲が丸ごと 1 つのブロックに収まっているときだけ真**にする。
 * 部分的に届いている範囲は送り直す(分割して送る仕組みを増やすより、
 * 1 セグメント余分に送るほうが安い)。
 *
 * 引数:
 *   priv     - コネクションのプライベート状態
 *   seq, len - 対象の範囲
 * 戻り値:
 *   1=送り直さなくてよい、0=送り直す
 * コール元:
 *   tcp_send(), tcp_async_poll(), tcp_async_short_poll()
 * ===============================================================*/
/*=================================================================
 * SACK で「ここまでは相手に届いている」と分かっている一番先の seq を返す。
 *
 * **高速再送でどこまで送り直すかの上限になる。** この先はまだ飛行中で、
 * 失われたかどうか分かっていない -- Go-Back-N はそこまで全部送り直すが、
 * SACK があるならその必要は無い(RFC 6675 の考え方)。実測では、穴が
 * 見つかった時点で未確認ウィンドウが 480KB あり、そのうち実際に失われて
 * いたのは 32KB だけだった。
 *
 * 引数:
 *   priv - コネクションのプライベート状態
 * 戻り値:
 *   最も先の SACK ブロックの右端。使える情報が無ければ 0
 * コール元:
 *   tcp_send(), tcp_async_poll(), tcp_async_short_poll()
 * ===============================================================*/
static inline uint32_t tcp_sack_high(const tcp_priv_t *priv)
{
    if (!priv->sack_enabled || priv->sack_rx_count == 0u || !g_tcp_sack_use_tx) return 0;
    uint32_t high = 0;
    int found = 0;
    for (unsigned i = 0; i < priv->sack_rx_count; i++) {
        uint32_t be = priv->sack_rx[i].end;
        /* 累積 ACK より前のブロックは古い情報(相手はもう先へ進んでいる)。 */
        if (!tcp_seq_lt(priv->snd_una, be)) continue;
        if (!found || tcp_seq_lt(high, be)) { high = be; found = 1; }
    }
    return found ? high : 0u;
}

/*=================================================================
 * SACK で「もう相手に届いている」と分かっているバイト数を返す。
 *
 * **輻輳ウィンドウと比べる「飛行中の量」から差し引くために要る**
 * (RFC 6675 の pipe)。差し引かないと、回復中は未確認バイト数が
 * cwnd を超えたままになり、**穴が埋まるまで新しいデータを 1 バイトも
 * 送れなくなる**。Go-Back-N のときは大量の重複 ACK が cwnd を膨らませて
 * いたので表面化しなかった。
 *
 * 引数:
 *   priv - コネクションのプライベート状態
 * 戻り値:
 *   SACK 済みのバイト数(累積 ACK より先のぶんだけ)
 * コール元:
 *   tcp_send(), tcp_send_async_ex()
 * ===============================================================*/
static inline uint32_t tcp_sacked_bytes(const tcp_priv_t *priv)
{
    if (!priv->sack_enabled || priv->sack_rx_count == 0u) return 0;
    uint32_t total = 0;
    for (unsigned i = 0; i < priv->sack_rx_count; i++) {
        uint32_t s = priv->sack_rx[i].start;
        uint32_t e = priv->sack_rx[i].end;
        if (!tcp_seq_lt(priv->snd_una, e)) continue;   /* 累積 ACK 済み */
        if (tcp_seq_lt(s, priv->snd_una)) s = priv->snd_una;
        total += e - s;
    }
    return total;
}

static inline int tcp_sack_covered(const tcp_priv_t *priv, uint32_t seq, uint32_t len)
{
    if (!priv->sack_enabled || len == 0u || !g_tcp_sack_use_tx) return 0;
    if (priv->sack_rx_count == 0u) { g_tcp_sack_noinfo_count++; return 0; }
    g_tcp_sack_probe_count++;
    uint32_t end = seq + len;
    for (unsigned i = 0; i < priv->sack_rx_count; i++) {
        uint32_t bs = priv->sack_rx[i].start;
        uint32_t be = priv->sack_rx[i].end;
        /* 累積 ACK より前のブロックは古い情報なので使わない。 */
        if (tcp_seq_lt(be, priv->snd_una)) continue;
        if (!tcp_seq_lt(seq, bs) && !tcp_seq_lt(be, end)) return 1;
    }
    return 0;
}

/*=================================================================
 * このセグメントに載せる TCP オプションのバイト数を返す。
 *
 * SYN のときだけ MSS / Window Scale が載り、Timestamps は
 * (合意していれば)**全セグメントに載る**(RFC 7323 の要求)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   flags       - 送出するフラグ
 * 戻り値:
 *   オプション領域のバイト数(常に 4 の倍数)
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso()
 * ===============================================================*/
static inline uint8_t tcp_options_len(const tcp_conn_t *conn, const tcp_priv_t *priv,
                                       uint8_t flags, uint16_t data_len)
{
    (void)conn;
    uint8_t len = 0;
    if (flags & TCP_FLAG_SYN) {
        len = 4u;  /* MSS */
        /* SYN|ACK のときは相手が出してきた場合だけ返す(能動 open は常に出す)。 */
        if ((flags & TCP_FLAG_ACK) ? priv->wscale_enabled : 1) len = (uint8_t)(len + 4u);
        if ((flags & TCP_FLAG_ACK) ? priv->ts_enabled : (g_tcp_ts_enable != 0u)) {
            len = (uint8_t)(len + TCP_TS_OPT_LEN);
        }
        if ((flags & TCP_FLAG_ACK) ? priv->sack_enabled : (g_tcp_sack_enable != 0u)) {
            len = (uint8_t)(len + TCP_SACK_PERM_OPT_LEN);
        }
        return len;
    }
    if (priv->ts_enabled) len = TCP_TS_OPT_LEN;
    /* **SACK ブロックは、データを運ぶセグメントにも MSS に収まるぶんだけ載せる**(RFC 2018 4:
     * 受け手のキューの最大の seq を ACK しない ACK にはすべて SACK を載せるべき)。
     * conn->snd_mss は Timestamps のぶんを引いた固定値なので、データ + SACK が snd_mss を超えると
     * リンク MTU を超えて NIC に無言で捨てられる。超えるならブロックを減らし、0 なら載せない
     * (フルサイズのデータには載らない。そのときは穴を見つけた時点ですぐ純 ACK を返しているので
     * 相手は最新の SACK を受け取れる、tcp_input_addr())。
     * LSO はヘッダを WQE に写す長さに上限があるので、呼び出し側が data_len に大きな値を渡して載せない。
     * ロスが無ければ sack_tx_count も dsack_valid も 0 なので、ホットパスは OR 1 つで抜ける。 */
    if (priv->sack_enabled && (flags & TCP_FLAG_ACK) && (priv->sack_tx_count | priv->dsack_valid)) {
        unsigned n = tcp_sack_block_count(priv, conn);
        if (data_len != 0u) {
            while (n > 0u && (uint32_t)data_len + 4u + 8u * n > (uint32_t)conn->snd_mss) n--;
        }
        if (n > 0) len = (uint8_t)(len + 4u + 8u * n);
    }
    return len;
}

/*=================================================================
 * TCP ヘッダ直後のオプション領域を組み立てる。並びは
 * MSS / NOP+Window Scale / NOP+NOP+Timestamps。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   flags       - 送出するフラグ
 *   tcph        - TCP ヘッダ先頭
 *   opt_len     - tcp_options_len() が返した長さ
 * コール元:
 *   tcp_send_segment(), tcp_send_segment_lso()
 * ===============================================================*/
static void tcp_build_options(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags,
                               volatile uint8_t *tcph, uint8_t opt_len, uint16_t data_len)
{
    if (opt_len == 0) return;
    unsigned o   = TCP_HDR_LEN;
    unsigned end = (unsigned)(TCP_HDR_LEN + opt_len);
    if (flags & TCP_FLAG_SYN) {
        tcph[o + 0] = TCP_OPT_KIND_MSS;
        tcph[o + 1] = 4;
        wr16be(tcph + o + 2, tcp_mss_cap_for((const netaddr_t *)&conn->remote_ip));
        o += 4u;
        if ((flags & TCP_FLAG_ACK) ? priv->wscale_enabled : 1) {
            tcph[o + 0] = TCP_OPT_KIND_NOP;
            tcph[o + 1] = TCP_OPT_KIND_WSCALE;
            tcph[o + 2] = 3;               /* オプション長(kind+len+shiftの3バイト) */
            if (flags & TCP_FLAG_SYN) priv->rcv_wscale = g_tcp_rcv_wscale;
            tcph[o + 3] = priv->rcv_wscale;  /* shift count */
            o += 4u;
        }
    }
    if ((flags & TCP_FLAG_SYN) ?
        ((flags & TCP_FLAG_ACK) ? priv->ts_enabled : (g_tcp_ts_enable != 0u)) :
        priv->ts_enabled) {
        /* Timestamps。NOP 2 個で 4 バイト境界へ揃える(慣例)。 */
        tcph[o + 0] = TCP_OPT_KIND_NOP;
        tcph[o + 1] = TCP_OPT_KIND_NOP;
        tcph[o + 2] = TCP_OPT_KIND_TS;
        tcph[o + 3] = 10;
        {
            /* 書いた TSval を控える(送り直しの時刻として Eifel が使う。送った後で時刻を読み直すと
             * 1 刻み(1.024us)ずれ、送り直しへの ACK を元の送信への ACK と取り違えた)。 */
            const uint32_t tsv = tcp_ts_now();
            wr32be(tcph + o + 4, tsv);
            priv->ts_last_sent = tsv;
        }
        /* TSecr は「相手から最後に受け取った TSval」。まだ何も受け取って
         * いない能動 open の SYN では 0 を入れる(RFC 7323 3.2)。 */
        wr32be(tcph + o + 8, priv->ts_recent);
        o += TCP_TS_OPT_LEN;
    }
    if (flags & TCP_FLAG_SYN) {
        if (o < end) {
            /* SACK-Permitted。こちらも NOP 2 個で 4 バイトに揃える。 */
            tcph[o + 0] = TCP_OPT_KIND_NOP;
            tcph[o + 1] = TCP_OPT_KIND_NOP;
            tcph[o + 2] = TCP_OPT_KIND_SACK_PERM;
            tcph[o + 3] = 2;
            o += 4u;
        }
        return;
    }
    (void)data_len;
    if (end - o >= 12u && priv->sack_enabled && (flags & TCP_FLAG_ACK)) {
        /* 載せるブロックの数は tcp_options_len() が決めた長さから逆算する(データに相乗りさせるときは
         * MSS に収まるぶんへ減らしてある。ここで数え直すと長さと中身が食い違う)。 */
        tcp_sack_range_t blk[TCP_SACK_MAX_BLOCKS];
        unsigned n = tcp_sack_collect(priv, conn, blk);
        unsigned room = (end - o - 4u) / 8u;
        if (n > room) n = room;
        if (priv->dsack_valid && n > 0u) {    /* DSACK(先頭のブロック)は 1 回だけ知らせる */
            priv->dsack_valid = 0;
            g_tcp_dsack_sent_count++;
        }
        if (n > 0) {
            tcph[o + 0] = TCP_OPT_KIND_NOP;
            tcph[o + 1] = TCP_OPT_KIND_NOP;
            tcph[o + 2] = TCP_OPT_KIND_SACK;
            tcph[o + 3] = (uint8_t)(2u + 8u * n);
            o += 4u;
            for (unsigned i = 0; i < n; i++) {
                wr32be(tcph + o,     blk[i].start);
                wr32be(tcph + o + 4, blk[i].end);
                o += 8u;
            }
            g_tcp_sack_sent_count++;
        }
    }
}

static int tcp_send_segment(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags,
                             const void *data, uint16_t data_len)
{
    unsigned core = smp_core_index();
    tcp_win_check(conn, priv, data_len, 0u);
    if (priv->prr_active) priv->prr_out += data_len;   /* 回復中に送った量(PRR) */
    /* SND.NXT(送った最大)を進める。SYN と FIN は 1 つずつ seq を使う。SYN は ISN から数え直す
     * (SYN|ACK の送り直しで snd_seq を一時的に ISN へ戻すので、その時点の値で決めてよい)。
     * 窓の確認や Keepalive(snd_seq - 1、長さ 0)では進まない。比較 1 つと store 1 つ。 */
    {
        const uint32_t e = conn->snd_seq + data_len + ((flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) ? 1u : 0u);
        if ((flags & TCP_FLAG_SYN) || tcp_seq_gt(e, priv->snd_max)) priv->snd_max = e;
    }

    /* **確立後のセグメントは必ず ACK ビットを立てて現在の rcv_seq を運ぶ**
     * ので、借りていた ACK はこれで返せる(相乗り)。 */
    priv->ack_deferred = 0;
    priv->unacked_full_segments = 0;
    priv->ack_hold_thin = 0;

    if (g_tcp_tx_drop_every != 0u && tcp_tx_should_drop(data_len)) {
        return 0;  /* 送ったことにして捨てる(ロス注入、txdrop) */
    }
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) &&
        g_tcp_synack_drop_next != 0u) {
        g_tcp_synack_drop_next--;
        return 0;  /* 同じく「送ったことにして捨てる」(synackdrop) */
    }
    if (data_len == 0u && (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) == 0u &&
        g_tcp_ack_drop_next != 0u) {
        g_tcp_ack_drop_next--;
        g_tcp_ack_dropped_count++;
        return 0;  /* データ無しのセグメントを捨てる(ackdrop) */
    }

    netif_t *conn_ctx = tcp_netif_for((const netaddr_t *)&conn->local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (tcp_resolve_mac((const netaddr_t *)&conn->remote_ip, dst_mac, tcp_take_confirm(priv)) != 0) {
        uart_printf("[!] TCP: 宛先MACの解決失敗、送信中止\n");
        return -1;
    }

    uint8_t opt_len = tcp_options_len(conn, priv, flags, data_len);
    uint16_t hdr_total = (uint16_t)(TCP_HDR_LEN + opt_len);  /* TCPヘッダ+オプション(データ抜き) */
    uint16_t seg_len = (uint16_t)(hdr_total + data_len);      /* IPペイロード全体(ヘッダ+データ) */

    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 0), tcp_conn_arg(conn, data_len));
    unsigned slot = eth_tx_wait_free_slot();
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 1), tcp_conn_arg(conn, data_len));
    uint8_t *seg_buf = s_seg_bufs[core][netif_active_txq()][slot];

    unsigned l4_off = tcp_l4_off((const netaddr_t *)&conn->remote_ip);
    tcp_build_l3(seg_buf, (const netaddr_t *)&conn->local_ip,
                  (const netaddr_t *)&conn->remote_ip, dst_mac, seg_len);

    volatile uint8_t *tcph = seg_buf + l4_off;
    wr16be(tcph + TCP_OFF_SRC_PORT, conn->local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, conn->remote_port);
    wr32be(tcph + TCP_OFF_SEQ, conn->snd_seq);
    wr32be(tcph + TCP_OFF_ACK, (flags & TCP_FLAG_ACK) ? conn->rcv_seq : 0u);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((hdr_total / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = flags;
    uint32_t wnd_edge;
    uint16_t wire_window = tcp_wire_window(conn, priv, flags, &wnd_edge);
    wr16be(tcph + TCP_OFF_WINDOW, wire_window);
    /* 広告した右端を覚える(受信窓の外の判定と、窓を縮めない基準)。ACK を運ぶものだけ --
     * 能動 open の SYN はまだ rcv_seq が決まっていない。 */
    if (flags & TCP_FLAG_ACK) { priv->rcv_wnd_edge = wnd_edge; priv->rcv_wnd_valid = 1; }
    /* 直近に広告した (ack, window) を覚えておく。ウィンドウ更新目的の純 ACK が
     * 「どちらも前回と同じ」なら送らずに済ませるため(tcp_recv_internal())。 */
    priv->last_ack_sent = (flags & TCP_FLAG_ACK) ? conn->rcv_seq : 0u;
    priv->last_win_sent = wire_window;
    /* PAWS の R3(ts_recent を更新してよいのは「ACK 済みの範囲に続く
     * セグメント」だけ)に要る。last_ack_sent と違い非 ACK でも 0 にしない。 */
    if (flags & TCP_FLAG_ACK) priv->ts_last_ack_sent = conn->rcv_seq;
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */
    wr16be(tcph + TCP_OFF_URGENT, 0);
    tcp_build_options(conn, priv, flags, tcph, opt_len, data_len);

    /* HW チェックサムオフロードは v4/v6 共通で使える。種として書き込む疑似
     * ヘッダ部分和は tcp_checksum() が family ごとに正しい形で計算するし、
     * mlx5 が立てる cs_flags の L3_CSUM ビットは IPv6 では埋める対象が無いので
     * 無視される(L4_CSUM だけが効く)。 */
    int hw_partial = net_active_hw_csum_offload();
    uint16_t csum = tcp_checksum((const netaddr_t *)&conn->local_ip,
                                  (const netaddr_t *)&conn->remote_ip,
                                  tcph, hdr_total, data, data_len, hw_partial);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 2), tcp_conn_arg(conn, data_len));

    uint8_t *frame = seg_buf;
    uint16_t hdr_bytes = (uint16_t)(l4_off + hdr_total);

    if (net_active_tx_zerocopy() && data_len >= 512u) {
        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 3), tcp_conn_arg(conn, data_len)); // コピー無し(即座)

        dcache_clean_range(frame, hdr_bytes);
        dcache_clean_range((const void *)data, data_len);
        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 4), tcp_conn_arg(conn, data_len));

        eth_frag_t frags[2];
        frags[0].data = frame;
        frags[0].len  = hdr_bytes;
        frags[1].data = data;
        frags[1].len  = data_len;

        return eth_send_frags_async(frags, 2u);
    }

    const volatile uint8_t *vdata = data;
    volatile_fast_copy((volatile uint8_t *)(frame + hdr_bytes), vdata, data_len);
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 5), tcp_conn_arg(conn, data_len));

    eth_frag_t frag;
    frag.data = frame;
    frag.len  = (uint16_t)(hdr_bytes + data_len);

    dcache_clean_range(frame, frag.len);
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 6), tcp_conn_arg(conn, data_len));

    return eth_send_frags_async(&frag, 1u);
}

#define TCP_LSO_MAX_DATA_LEN (0xFFFFu - (uint32_t)sizeof(ip_header_t) - (uint32_t)TCP_HDR_LEN)

/*=================================================================
 * ペイロードを MSS ごとに切って 1 セグメントずつ送る(LSO が使えない
 * ときのフォールバック)。conn->snd_seq は呼び出し時の値へ戻すので、
 * 呼び出し側から見た振る舞いは tcp_send_segment_lso() と同じ。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   data / len  - 送るペイロード(複数 MSS 分)
 * 戻り値:
 *   0=全部キューイングできた、-1=途中で失敗
 * コール元:
 *   tcp_send_segment_lso()
 * ===============================================================*/
static int tcp_send_segments_split(tcp_conn_t *conn, tcp_priv_t *priv,
                                    const void *data, uint32_t data_len)
{
    const uint8_t *src = (const uint8_t *)data;
    uint32_t base = conn->snd_seq;
    uint32_t off  = 0;
    int rc = 0;
    while (off < data_len) {
        uint32_t chunk = data_len - off;
        if (chunk > conn->snd_mss) chunk = conn->snd_mss;
        conn->snd_seq = base + off;
        rc = tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                               src + off, (uint16_t)chunk);
        if (rc != 0) break;
        off += chunk;
    }
    conn->snd_seq = base;
    return rc;
}

/*=================================================================
 * LSO 対応の送信ヘルパ。ヘッダを 1 つ組み立て、複数 MSS 分のペイロードを
 * まとめて NIC へ渡して HW に分割させる(LSO 非対応なら呼ばれない)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   flags       - TCP フラグ
 *   data / len  - 送るペイロード(複数 MSS 分)
 *   seq         - 先頭セグメントのシーケンス番号
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   tcp_send(), tcp_async_poll(), tcp_send_async_enqueue()
 * ===============================================================*/
static int tcp_send_segment_lso(tcp_conn_t *conn, tcp_priv_t *priv,
                                 const void *data, uint32_t data_len)
{
    unsigned core = smp_core_index();
    tcp_win_check(conn, priv, data_len, 1u);
    if (priv->prr_active) priv->prr_out += data_len;
    if (tcp_seq_gt(conn->snd_seq + data_len, priv->snd_max)) priv->snd_max = conn->snd_seq + data_len;

    if (g_tcp_tx_drop_every != 0u && tcp_tx_should_drop(data_len)) {
        return 0;  /* 送ったことにして捨てる(ロス注入、txdrop) */
    }

    netif_t *conn_ctx = tcp_netif_for((const netaddr_t *)&conn->local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (tcp_resolve_mac((const netaddr_t *)&conn->remote_ip, dst_mac, tcp_take_confirm(priv)) != 0) {
        uart_printf("[!] TCP: 宛先MACの解決失敗、送信中止(LSO)\n");
        return -1;
    }

    /* LSO でも Timestamps は要る(RFC 7323 は RST 以外の全セグメントに求める)。
     * NIC はヘッダをそのまま各セグメントへ複製するので、オプションも一緒に
     * 複製される(TSval が同じ値で並ぶのは正常)。 */
    /* data_len に TCP_MSS_LOCAL を渡すのは「SACK ブロックを載せない」の意味(LSO のヘッダは WQE へ
     * 写す長さに上限がある。tcp_options_len() の説明)。 */
    uint8_t  opt_len = tcp_options_len(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, (uint16_t)TCP_MSS_LOCAL);
    uint16_t hdr_total = (uint16_t)(TCP_HDR_LEN + opt_len);

    unsigned l4_off = tcp_l4_off((const netaddr_t *)&conn->remote_ip);

    /* **ヘッダは LSO の WQE へインライン化される**ので長さに上限がある
     * (mlx5 で 82 バイト)。IPv6(54)+ TCP(20)+ Timestamps(12)= 86 は
     * 超えるので、その組み合わせだけ 1 セグメントずつ送る。ここで諦めずに
     * -1 を返すと、呼び出し側の送信ループが止まってしまう。 */
    uint16_t lso_hdr_max = net_active_lso_max_hdr();
    if (lso_hdr_max != 0u && (uint16_t)(l4_off + hdr_total) > lso_hdr_max) {
        return tcp_send_segments_split(conn, priv, data, data_len);
    }

    uint32_t seg_len32 = (uint32_t)hdr_total + data_len;
    if (seg_len32 > 0xFFFFu) {
        uart_printf("[!] TCP: LSO data_lenが大きすぎる(%u)、送信中止\n", (unsigned)data_len);
        return -1;
    }
    uint16_t seg_len = (uint16_t)seg_len32;

    /* tcp_send_segment()と同じスロット確保規約(コメント参照)。 */
    unsigned slot = eth_tx_wait_free_slot();
    uint8_t *seg_buf = s_seg_bufs[core][netif_active_txq()][slot];

    tcp_build_l3(seg_buf, (const netaddr_t *)&conn->local_ip,
                  (const netaddr_t *)&conn->remote_ip, dst_mac, seg_len);

    volatile uint8_t *tcph = seg_buf + l4_off;
    wr16be(tcph + TCP_OFF_SRC_PORT, conn->local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, conn->remote_port);
    wr32be(tcph + TCP_OFF_SEQ, conn->snd_seq);
    wr32be(tcph + TCP_OFF_ACK, conn->rcv_seq);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((hdr_total / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = TCP_FLAG_PSH | TCP_FLAG_ACK;
    priv->ts_last_ack_sent = conn->rcv_seq;

    /* 窓は tcp_send_segment() と同じ決め方(縮めない・小さく広げない)。 */
    uint32_t wnd_edge;
    uint16_t wire_window = tcp_wire_window(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, &wnd_edge);
    priv->rcv_wnd_edge  = wnd_edge;
    priv->rcv_wnd_valid = 1;
    priv->last_ack_sent = conn->rcv_seq;   /* 最後に広告した (ack, 窓)(tcp_send_segment() と同じ)*/
    priv->last_win_sent = wire_window;
    /* LSO のセグメントも全部 ACK と現在の rcv_seq を運ぶので、借りている ACK はこれで返せる
     * (tcp_send_segment() と同じ)。 */
    priv->ack_deferred = 0;
    priv->unacked_full_segments = 0;
    priv->ack_hold_thin = 0;
    wr16be(tcph + TCP_OFF_WINDOW, wire_window);
    wr16be(tcph + TCP_OFF_URGENT, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */
    tcp_build_options(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, tcph, opt_len, (uint16_t)TCP_MSS_LOCAL);

    /* LSO は NIC が IPv4 ヘッダの total_length/ID を書き換える前提の機能で、
     * 現在の実装は IPv4 でしか使わない(v6 の呼び出し元は tcp_can_use_lso()
     * で弾いている)。ここでは疑似ヘッダ部分和を種として渡す。 */
    uint16_t csum = tcp_checksum((const netaddr_t *)&conn->local_ip,
                                  (const netaddr_t *)&conn->remote_ip,
                                  tcph, hdr_total, data, (uint16_t)data_len, 1);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    uint8_t *frame = seg_buf;
    uint16_t hdr_bytes = (uint16_t)(l4_off + hdr_total);

    dcache_clean_range(frame, hdr_bytes);
    dcache_clean_range((const void *)data, data_len);

    return eth_send_lso_async(frame, hdr_bytes, data, data_len, conn->snd_mss);
}

/*=================================================================
 * 登録済みコネクションを持たない相手(既にスロットから外れた TIME_WAIT の
 * 相手、閉じたポートを叩いてきた相手など)へ、データを持たない単発の
 * セグメントを送る tcp_send_segment() の最小構成版。flags を引数に取るので
 * ACK / RST / RST|ACK のいずれも同じ経路で送れる。
 *
 * 引数:
 *   local_ip / local_port / remote_ip / remote_port - 4-tuple
 *   flags     - 送出するフラグ(TCP_FLAG_ACK / TCP_FLAG_RST 等)
 *   seq / ack - 送出する シーケンス/確認応答番号
 * コール元:
 *   tcp_send_bare_ack(), tcp_send_bare_rst()
 * ===============================================================*/
/* tcp_send_bare_ex() の任意のオプション。 */
typedef struct {
    uint16_t    window;     /* window フィールドにそのまま書く値 */
    uint8_t     ts_on;      /* 1 = Timestamps(NOP NOP TS)を付ける */
    uint32_t    tsval, tsecr;
    int         mss;        /* >= 0 なら MSS オプション(試験用) */
    const void *data;       /* ペイロード(試験用、NULL 可) */
    uint16_t    dlen;
} tcp_bare_opt_t;

static void tcp_send_bare_ex(const netaddr_t *local_ip, uint16_t local_port,
                             const netaddr_t *remote_ip, uint16_t remote_port,
                             uint8_t flags, uint32_t seq, uint32_t ack, const tcp_bare_opt_t *opt)
{
    unsigned core = smp_core_index();

    netif_t *conn_ctx = tcp_netif_for(local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (tcp_resolve_mac(remote_ip, dst_mac, 0) != 0) {
        return;
    }

    unsigned olen = 0;
    if (opt && opt->mss >= 0) olen += 4u;
    if (opt && opt->ts_on)    olen += TCP_TS_OPT_LEN;
    const uint16_t hdr = (uint16_t)(TCP_HDR_LEN + olen);
    uint16_t dlen = (opt && opt->data) ? opt->dlen : 0u;
    if (dlen > TCP_MSS_LOCAL) dlen = 0;

    unsigned slot = eth_tx_wait_free_slot();
    uint8_t *seg_buf = s_seg_bufs[core][netif_active_txq()][slot];

    unsigned l4_off = tcp_l4_off(remote_ip);
    tcp_build_l3(seg_buf, local_ip, remote_ip, dst_mac, (uint16_t)(hdr + dlen));

    volatile uint8_t *tcph = seg_buf + l4_off;
    wr16be(tcph + TCP_OFF_SRC_PORT, local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, remote_port);
    wr32be(tcph + TCP_OFF_SEQ, seq);
    wr32be(tcph + TCP_OFF_ACK, ack);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((hdr / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = flags;
    wr16be(tcph + TCP_OFF_WINDOW, opt ? opt->window : 0u);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);
    wr16be(tcph + TCP_OFF_URGENT, 0);
    unsigned o = TCP_HDR_LEN;
    if (opt && opt->mss >= 0) {
        tcph[o] = TCP_OPT_KIND_MSS; tcph[o + 1] = 4;
        wr16be(tcph + o + 2, (uint16_t)opt->mss);
        o += 4u;
    }
    if (opt && opt->ts_on) {
        tcph[o] = TCP_OPT_KIND_NOP; tcph[o + 1] = TCP_OPT_KIND_NOP;
        tcph[o + 2] = TCP_OPT_KIND_TS; tcph[o + 3] = 10;
        wr32be(tcph + o + 4, opt->tsval);
        wr32be(tcph + o + 8, opt->tsecr);
        o += TCP_TS_OPT_LEN;
    }
    if (dlen) volatile_fast_copy(tcph + hdr, (const volatile uint8_t *)opt->data, dlen);

    uint16_t csum = tcp_checksum(local_ip, remote_ip, tcph, hdr,
                                 dlen ? opt->data : NULL, dlen, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    eth_frag_t frag;
    frag.data = seg_buf;
    frag.len  = (uint16_t)(l4_off + hdr + dlen);

    dcache_clean_range(seg_buf, frag.len);
    eth_send_frags_async(&frag, 1u);
}

static void tcp_send_bare(const netaddr_t *local_ip, uint16_t local_port,
                           const netaddr_t *remote_ip, uint16_t remote_port,
                           uint8_t flags, uint32_t seq, uint32_t ack)
{
    tcp_send_bare_ex(local_ip, local_port, remote_ip, remote_port, flags, seq, ack, NULL);
}

/*=================================================================
 * TIME_WAIT の相手からの再送へ返す単発 ACK。
 *
 * 引数:
 *   local_ip / local_port / remote_ip / remote_port - 4-tuple
 *   seq / ack - 送出する シーケンス/確認応答番号
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static void tcp_send_bare_ack(const netaddr_t *local_ip, uint16_t local_port,
                               const netaddr_t *remote_ip, uint16_t remote_port,
                               uint32_t seq, uint32_t ack, uint8_t ts_on, uint32_t tsecr)
{
    /* Timestamps を合意していた接続なら TS を載せる(RFC 7323 3.2。載せないと、相手は
     * 「TS の無いセグメント」として捨て、LAST_ACK から抜けられない)。 */
    tcp_bare_opt_t o = { 0 };
    o.mss   = -1;
    o.ts_on = ts_on;
    o.tsval = tcp_ts_now();
    o.tsecr = tsecr;
    tcp_send_bare_ex(local_ip, local_port, remote_ip, remote_port, TCP_FLAG_ACK, seq, ack, &o);
}

/*=================================================================
 * どのコネクションにもリスナにも一致しないセグメントへ RST を返す
 * (RFC 793 "SEGMENT ARRIVES / CLOSED STATE")。これが無いと相手は接続失敗を
 * 即座に知れず、SYN 再送のタイムアウト(数秒〜十数秒)まで待たされる。
 *
 * 引数:
 *   local_ip / local_port / remote_ip / remote_port - 応答する 4-tuple
 *                                                     (受信の src/dst を入れ替えたもの)
 *   seg_flags - 受信セグメントのフラグ
 *   seg_seq / seg_ack - 受信セグメントのシーケンス/確認応答番号
 *   seg_len   - 受信セグメントのペイロード長(SYN/FIN 分は含まない)
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static void tcp_send_bare_rst(const netaddr_t *local_ip, uint16_t local_port,
                               const netaddr_t *remote_ip, uint16_t remote_port,
                               uint8_t seg_flags, uint32_t seg_seq, uint32_t seg_ack,
                               uint16_t seg_len)
{
    if (seg_flags & TCP_FLAG_ACK) {
        /* 相手が ACK を持っている -- その番号を自分の seq にして裸の RST を返す。 */
        tcp_send_bare(local_ip, local_port, remote_ip, remote_port,
                       TCP_FLAG_RST, seg_ack, 0u);
    } else {
        /* ACK が無い -- seq=0 で、受信分を確認応答する RST|ACK を返す。
         * SYN と FIN はそれぞれ 1 バイト分のシーケンス番号を消費する。 */
        uint32_t ack = seg_seq + seg_len;
        if (seg_flags & TCP_FLAG_SYN) ack++;
        if (seg_flags & TCP_FLAG_FIN) ack++;
        tcp_send_bare(local_ip, local_port, remote_ip, remote_port,
                       TCP_FLAG_RST | TCP_FLAG_ACK, 0u, ack);
    }
}

/*=================================================================
 * 指定コネクション宛に、相手を騙って RST を 1 つ撃ち込む(検証用)。
 *
 * **RST の検証(RFC 5961)には「窓外の RST では切れない」という陰性対照が
 * 要る**が、正しい相手は窓外の RST を送ってこないので、自分で作るしかない。
 * `txdrop` / `synackdrop` と同じ恒久的な検証道具。
 *
 * 引数:
 *   victim - 撃ち込む先のコネクション
 *   seq    - RST に載せるシーケンス番号
 * コール元:
 *   shell_rsttest()
 * ===============================================================*/
void tcp_debug_inject_rst(const tcp_conn_t *victim, uint32_t seq)
{
    /* 送信元と宛先を入れ替えて、相手から届いたように見せる。 */
    tcp_send_bare((const netaddr_t *)&victim->remote_ip, victim->remote_port,
                   (const netaddr_t *)&victim->local_ip, victim->local_port,
                   TCP_FLAG_RST, seq, 0u);
}

/*=================================================================
 * 指定コネクション宛に、相手を騙って任意のセグメントを 1 つ撃ち込む(`rfctest tcp`)。
 * 正しい相手は送ってこない形(まだ送っていないものへの ACK、窓の外のデータ、確立済みの
 * 4-tuple への SYN など)を作るため。victim が Timestamps を合意していれば TS を付ける
 * (TSval は今の時刻 = 相手も同じプロセスの時計なので PAWS で捨てられない)。
 *
 * 引数:
 *   victim      - 撃ち込む先のコネクション
 *   flags / seq / ack / window - TCP ヘッダの値
 *   data / len  - ペイロード(NULL / 0 可)
 * コール元:
 *   rfctest_tcp()
 * ===============================================================*/
void tcp_debug_inject(const tcp_conn_t *victim, uint8_t flags, uint32_t seq, uint32_t ack,
                      uint16_t window, const void *data, uint16_t len)
{
    tcp_priv_t *vp = tcp_priv_for((tcp_conn_t *)victim);
    tcp_bare_opt_t o = { 0 };
    o.window = window;
    o.mss    = -1;
    o.ts_on  = (vp && vp->ts_enabled) ? 1u : 0u;
    o.tsval  = tcp_ts_now();
    o.tsecr  = vp ? vp->ts_last_sent : 0u;
    o.data   = data;
    o.dlen   = data ? len : 0u;
    tcp_send_bare_ex((const netaddr_t *)&victim->remote_ip, victim->remote_port,
                     (const netaddr_t *)&victim->local_ip, victim->local_port,
                     flags, seq, ack, &o);
}

/*=================================================================
 * 接続を持たない 4-tuple から任意のセグメントを撃ち込む(`rfctest tcp`。待ち受けへの ACK、
 * MSS 0 の SYN|ACK など)。Timestamps は付けない。
 * ===============================================================*/
void tcp_debug_inject_to(const netaddr_t *from, uint16_t from_port,
                         const netaddr_t *to, uint16_t to_port,
                         uint8_t flags, uint32_t seq, uint32_t ack, int mss)
{
    tcp_bare_opt_t o = { 0 };
    o.window = 65535u;
    o.mss    = mss;
    tcp_send_bare_ex(from, from_port, to, to_port, flags, seq, ack, &o);
}

/*=================================================================
 * 指定ポートで待ち受けているリスナが 1 つでもあるか。
 *
 * 受動 open のマッチ条件(accept_conn が用意済みで CLOSED)より緩く、
 * 「ポートが開いているか」だけを見る。armed でないリスナへ届いた SYN に
 * RST を返してしまうと、accept を張り直す一瞬の隙間(nvmet が admin キュー
 * 確立後に IO キューの accept を arm するまでの間など)で相手の接続が即座に
 * 失敗する。Linux が accept キュー溢れで黙って捨てるのと同じ扱いにして、
 * 相手の SYN 再送に任せる。
 *
 * 引数:
 *   port - 宛先ポート
 * 戻り値:
 *   1=リスナあり、0=無し
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static int tcp_port_has_listener(uint16_t port)
{
    for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
        if (s_listeners[li].in_use && s_listeners[li].port == port) return 1;
    }
    return 0;
}

/*=================================================================
 * 全コアのコネクションスロットから 4-tuple が一致するものを探す。
 *
 * 受信ホットパスの照合は自コアぶんしか見ない(他コアのコネクション宛
 * パケットは届かない前提)。RST を返す直前だけは、その前提が崩れていた場合に
 * 自分のコネクションを自分で撃つことになるので、冷たい経路で全コアを確認する。
 *
 * 引数:
 *   src / src_port / dst_port - 探す 4-tuple
 * 戻り値:
 *   1=どこかのコアに存在する、0=無し
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static int tcp_conn_exists_any_core(const netaddr_t *src, uint16_t src_port, uint16_t dst_port)
{
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            tcp_conn_t *cn = s_conns[c][i];
            if (cn != NULL &&
                src_port == cn->remote_port &&
                dst_port == cn->local_port &&
                netaddr_eq(src, (const netaddr_t *)&cn->remote_ip)) {
                return 1;
            }
        }
    }
    return 0;
}

/* ---- ISN と一時ポート(RFC 6528 / RFC 6056)---- */

/* 起動後に 1 回だけ作る秘密の鍵(32 バイト)。ISN と一時ポートの鍵付きハッシュに使う。 */
static uint8_t          s_tcp_secret[32];
static volatile uint8_t s_tcp_secret_ready;
static smp_spinlock_t   s_tcp_secret_lock;
/* RFC 6056 Algorithm 3 の next_ephemeral(全コア共有、試すたびに進める)。 */
static volatile uint32_t s_tcp_next_ephemeral;

/*=================================================================
 * 秘密の鍵を初めて使うときに作る(getrandom)。乱数が取れなければ時刻から作る(推測は
 * されうるが、時計をそのまま使うよりはまし。起動時に一度表示して気付けるようにする)。
 * 複数のコアが同時に初めて接続を張ることがあるのでロックで守る(冷たい経路)。
 * ===============================================================*/
static void tcp_secret_init(void)
{
    if (__atomic_load_n(&s_tcp_secret_ready, __ATOMIC_ACQUIRE)) return;
    smp_spin_lock(&s_tcp_secret_lock);
    if (!s_tcp_secret_ready) {
        if (crypto_random(s_tcp_secret, sizeof(s_tcp_secret)) != 0) {
            const uint64_t t = timer_now();
            for (unsigned i = 0; i < sizeof(s_tcp_secret); i++) {
                s_tcp_secret[i] = (uint8_t)((t >> ((i % 8u) * 8u)) ^ (i * 0x9Du));
            }
            uart_printf("[!] TCP: 乱数が取れないので ISN / 一時ポートの鍵を時刻から作りました\n");
        }
        s_tcp_next_ephemeral = (uint32_t)s_tcp_secret[0] | ((uint32_t)s_tcp_secret[1] << 8);
        __atomic_store_n(&s_tcp_secret_ready, 1u, __ATOMIC_RELEASE);
    }
    smp_spin_unlock(&s_tcp_secret_lock);
}

/* アドレスの意味のあるバイトだけを並べる(IPv4 の a[4..15] は未初期化のことがある、netaddr.h)。 */
static unsigned tcp_addr_bytes(const netaddr_t *a, uint8_t *out)
{
    const unsigned n = (a->family == NETADDR_V6) ? 16u : 4u;
    out[0] = a->family;
    for (unsigned i = 0; i < n; i++) out[1 + i] = a->a[i];
    return 1u + n;
}

/*=================================================================
 * 秘密の鍵付きのハッシュ F(tag, 自分, 自分のポート, 相手, 相手のポート)の上位 32 ビット。
 * SHA-256(secret || tag || ...)。接続を張るときにしか呼ばない(冷たい経路)。
 * ===============================================================*/
static uint32_t tcp_keyed_hash(uint8_t tag, const netaddr_t *l, uint16_t lport,
                               const netaddr_t *r, uint16_t rport)
{
    uint8_t buf[32 + 1 + 17 + 2 + 17 + 2];
    unsigned n = 0;
    for (unsigned i = 0; i < sizeof(s_tcp_secret); i++) buf[n++] = s_tcp_secret[i];
    buf[n++] = tag;
    n += tcp_addr_bytes(l, buf + n);
    buf[n++] = (uint8_t)(lport >> 8); buf[n++] = (uint8_t)lport;
    n += tcp_addr_bytes(r, buf + n);
    buf[n++] = (uint8_t)(rport >> 8); buf[n++] = (uint8_t)rport;
    uint8_t h[32];
    crypto_hash(CRYPTO_SHA256, buf, n, h);
    return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
}

/*=================================================================
 * ISN を決める(RFC 6528)。ISN = M + F(4-tuple, 秘密)。M は約 4 マイクロ秒で 1 進む時計
 * (timer_now() の ns を 4096 で割る。RFC 793 の 4 us 刻みと同じ速さ)。
 *
 * **以前は timer_now() の下位 32 ビットそのものだった。** 相手から見て次の ISN が推測でき、
 * 経路の外から接続へデータや RST を差し込む攻撃(RFC 6528 の動機)に弱い。4-tuple ごとに鍵付きの
 * ずらしを足すと、同じ 4-tuple の中では時計どおりに単調に進む(古い重複セグメントと混ざらない、
 * RFC 793 の性質)まま、ほかの 4-tuple からは推測できない。
 *
 * コール元:
 *   tcp_connect_begin_addr(), tcp_input_addr()(受動 open)
 * ===============================================================*/
static uint32_t tcp_isn_gen(const netaddr_t *local, uint16_t lport,
                            const netaddr_t *remote, uint16_t rport)
{
    tcp_secret_init();
    return (uint32_t)(timer_now() >> 12) + tcp_keyed_hash('I', local, lport, remote, rport);
}

/*=================================================================
 * 能動 open の自分側のポートを選ぶ(RFC 6056 Algorithm 3「Simple Hash-Based」)。
 * port = 49152 + (F(自分, 相手, 相手のポート, 秘密) + next_ephemeral + k) mod 16384。
 * 相手ごとに出発点が変わるので外から推測しにくく、同じ相手には順に使っていくので重なりにくい。
 *
 * 次のものは飛ばす:
 *   - 同じ (相手, 相手のポート, 自分のポート) の接続が(どのコアにでも)ある
 *   - TIME_WAIT の表にある(閉じた直後の 4-tuple を使い回すと、遅れて届く古いセグメントと混ざる)
 *   - そのポートで誰かが待ち受けている
 *   - RSS で受信を散らしているとき、相手からの受信が自分のコアに来ない(TCP の接続は張った
 *     コアの表にしか載らない。tcp_connect_begin_addr() の説明)
 * **以前は ISN(= 時計)の下位 14 ビットそのもの**で、既存の接続や TIME_WAIT と重なるかを
 * 確かめていなかった。
 *
 * 戻り値: ポート番号。全部使えなければ 0
 * コール元: tcp_connect_begin_addr()
 * ===============================================================*/
#define TCP_EPHEMERAL_BASE 49152u
#define TCP_EPHEMERAL_NUM  16384u

static uint16_t tcp_pick_port(unsigned core, const netaddr_t *local, const netaddr_t *dst, uint16_t dport)
{
    tcp_secret_init();
    const uint32_t off = tcp_keyed_hash('P', local, 0u, dst, dport);
    int      rss = 0;
    uint32_t rip = 0, lip = 0;
    if (dst->family == NETADDR_V4 && core >= 1u) {
        rip = ((uint32_t)dst->a[0] << 24) | ((uint32_t)dst->a[1] << 16) |
              ((uint32_t)dst->a[2] << 8) | dst->a[3];
        lip = ((uint32_t)local->a[0] << 24) | ((uint32_t)local->a[1] << 16) |
              ((uint32_t)local->a[2] << 8) | local->a[3];
        rss = (net_rss_core_v4(rip, lip, dport, (uint16_t)TCP_EPHEMERAL_BASE) >= 0);
    }
    const uint32_t next = __atomic_load_n(&s_tcp_next_ephemeral, __ATOMIC_RELAXED);
    for (uint32_t k = 0; k < TCP_EPHEMERAL_NUM; k++) {
        const uint16_t p = (uint16_t)(TCP_EPHEMERAL_BASE + ((off + next + k) % TCP_EPHEMERAL_NUM));
        if (rss && net_rss_core_v4(rip, lip, dport, p) != (int)core) continue;
        if (tcp_port_has_listener(p)) continue;
        if (tcp_conn_exists_any_core(dst, dport, p)) continue;
        if (tcp_timewait_find(dst, dport, p, NULL)) continue;
        (void)__atomic_add_fetch(&s_tcp_next_ephemeral, k + 1u, __ATOMIC_RELAXED);
        return p;
    }
    return 0;
}

/* ---- 接続を閉じる共通の手続き ---- */

/* conn を持ち主のコアの表から外す(以後、受信は「接続の無い 4-tuple」として扱う)。 */
static void tcp_conn_unregister(tcp_conn_t *conn)
{
    const unsigned core = conn->owner_core;
    if (core >= SMP_MAX_CORES) return;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == conn) { s_conns[core][i] = NULL; break; }
    }
}

/*=================================================================
 * 接続を諦めて閉じる(RFC 9293 3.10.4 の ABORT と同じ形)。RST(seq = SND.NXT)を送り、
 * 状態を CLOSED にして表から外す。上位は state が CLOSED になったこと(tcp_send_async() などが
 * -1 を返す)で知る -- 相手から RST を受けたときと同じ見え方にしてある。
 *
 * **再送の上限で諦めたときに seq を巻き戻して続けてはいけない**(RFC 9293 3.8.3 の MUST-20:
 * 上限に達したら接続を閉じて上位へ知らせる)。以前は snd_seq = snd_una に戻して送信キューを
 * 空にしていたので、上位はデータが失われたことを知らないまま、相手とずれたストリームで続けていた。
 *
 * 引数:
 *   conn / priv - 対象
 *   why         - 表示する理由
 * コール元:
 *   tcp_async_poll(), tcp_async_short_poll(), tcp_send(), tcp_close(), tcp_keepalive_check()
 * ===============================================================*/
static void tcp_abort_conn(tcp_conn_t *conn, tcp_priv_t *priv, const char *why)
{
    uart_printf("[TCP] %s: RST を送って接続を閉じます (local_port=%u remote_port=%u)\n",
                why, (unsigned)conn->local_port, (unsigned)conn->remote_port);
    if (conn->state != TCP_SYN_SENT && conn->state != TCP_CLOSED) {
        tcp_send_bare((const netaddr_t *)&conn->local_ip, conn->local_port,
                      (const netaddr_t *)&conn->remote_ip, conn->remote_port,
                      TCP_FLAG_RST, priv->snd_max, 0u);
    }
    conn->state = TCP_CLOSED;
    priv->async_head = 0;        priv->async_count = 0;
    priv->async_short_head = 0;  priv->async_short_count = 0;
    priv->lost_bytes = 0;
    priv->ack_deferred = 0;
    priv->unacked_full_segments = 0;
    tcp_conn_unregister(conn);
}

/* challenge ACK の頻度(コアごと、1 秒の窓)。1 コア 1 キャッシュライン。 */
static struct { uint64_t start; uint32_t n; } __attribute__((aligned(64))) s_challenge[SMP_MAX_CORES];

/*=================================================================
 * 受け入れられないセグメントへの ACK(RFC 9293 3.10.7.4)と challenge ACK(RFC 5961 3〜5)。
 * **頻度に上限を付ける**(RFC 5961 7)。付けないと、偽のセグメントを撃ち込むだけでこちらに
 * 同じ数の ACK を送らせられる(反射と、challenge ACK の数から窓を推測する攻撃)。
 *   - データを運ばないセグメントへの ACK: 接続ごとに 500 ms に 1 回
 *   - challenge ACK: さらにコアごとに 1 秒に 1000 回
 *   - データを運ぶセグメント(相手の無駄な再送)への ACK は絞らない。DSACK を運ぶため(Linux の
 *     tcp_oow_rate_limited() も同じ)
 * 時刻を読むのは絞る場合だけ(受け入れられないセグメントは冷たい経路)。
 *
 * 引数:
 *   conn / priv - 対象
 *   limited     - 1 = 頻度の上限をかける
 *   challenge   - 1 = challenge ACK(コアごとの上限もかける)
 * 戻り値: 1 = 送った、0 = 上限で省いた
 * ===============================================================*/
static int tcp_send_oow_ack(tcp_conn_t *conn, tcp_priv_t *priv, int limited, int challenge)
{
    if (limited || challenge) {
        const uint64_t now = timer_now();
        if (priv->oow_last_at != 0u && now - priv->oow_last_at < (uint64_t)TCP_OOW_ACK_GAP_MS * 1000000u) {
            g_tcp_oow_ack_limited++;
            return 0;
        }
        if (challenge) {
            const unsigned c = smp_core_index();
            if (now - s_challenge[c].start >= 1000000000u) { s_challenge[c].start = now; s_challenge[c].n = 0; }
            if (++s_challenge[c].n > TCP_CHALLENGE_PER_SEC) { g_tcp_oow_ack_limited++; return 0; }
        }
        priv->oow_last_at = now;
    }
    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
    return 1;
}

/*=================================================================
 * 握手の途中の接続を ICMP の HARD エラーで失敗させる(持ち主のコアから呼ぶ)。
 * SYN_SENT は tcp_connect_poll() が CLOSED(または表に無い)を見て -1 を返す。SYN_RCVD は
 * 表から外す(受け皿へ直接受理していたものは CLOSED に戻るので次の SYN を受けられる、待ち行列の
 * ものは tcp_backlog_reap() が回収する)。
 * ===============================================================*/
static void tcp_icmp_hard_close(tcp_conn_t *cn, tcp_priv_t *priv)
{
    priv->icmp_hard = 0;
    if (cn->state != TCP_SYN_SENT && cn->state != TCP_SYN_RCVD) return;
    g_tcp_icmp_hard_abort++;
    uart_printf("[TCP] ICMP(相手にその口が無い)を受けたので接続の途中で諦めます "
                "(local_port=%u remote_port=%u)\n", (unsigned)cn->local_port, (unsigned)cn->remote_port);
    cn->state = TCP_CLOSED;
    tcp_conn_unregister(cn);
}

/*=================================================================
 * ICMP / ICMPv6 のエラーを TCP へ伝える(tcp.h の説明を参照)。
 *
 * **引用の seq が「送ったがまだ ACK されていない範囲」に入っているかを確かめる**(RFC 5927 4.1)。
 * 4-tuple だけで信じると、経路の外から偽の ICMP を送るだけで接続を切ったり(HARD)、MSS を
 * 下げたり(PMTU)できる。
 *   範囲: SYN_SENT / SYN_RCVD は [ISN, SND.NXT)、それ以外は [SND.UNA, SND.NXT)
 * HARD は握手の途中だけ接続を失敗させる(RFC 1122 4.2.3.9 / RFC 5461: 確立した後の Port
 * Unreachable などは一時的な経路の乱れでも起きるので切らない)。**SYN_SENT ならすぐ失敗させる**
 * -- 相手にその口が無いと分かっているのに 3 分 SYN を送り続けない。
 * 別のコアの接続なら旗だけ立てて、持ち主のコアが畳む(tcp_connect_poll() と冷たい経路)。
 *
 * コール元: icmp.c / ipv6.c(ICMP エラーの受信)
 * ===============================================================*/
int tcp_icmp_error(const netaddr_t *local, const netaddr_t *remote,
                   const uint8_t *quoted_tcp, size_t qlen, int kind)
{
    if (remote == NULL || quoted_tcp == NULL || qlen < 8u) { g_tcp_icmp_bogus_count++; return 0; }
    const uint16_t sport = rd16be(quoted_tcp);       /* 引用は自分が送ったもの: 送信元 = 自分 */
    const uint16_t dport = rd16be(quoted_tcp + 2);
    const uint32_t qseq  = rd32be(quoted_tcp + 4);

    tcp_conn_t *cn = NULL;
    tcp_priv_t *priv = NULL;
    unsigned    owner = 0;
    for (unsigned c = 0; c < SMP_MAX_CORES && !cn; c++) {
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            tcp_conn_t *x = s_conns[c][i];
            if (x == NULL || x->state == TCP_CLOSED) continue;
            if (x->local_port != sport || x->remote_port != dport) continue;
            if (!netaddr_eq(remote, (const netaddr_t *)&x->remote_ip)) continue;
            if (local && !netaddr_eq(local, (const netaddr_t *)&x->local_ip)) continue;
            cn = x; priv = &s_priv[c][i]; owner = c;
            break;
        }
    }
    if (cn == NULL) { g_tcp_icmp_bogus_count++; return 0; }

    const int handshake = (cn->state == TCP_SYN_SENT || cn->state == TCP_SYN_RCVD);
    const uint32_t una = handshake ? priv->expected_ack - 1u : priv->snd_una;
    if (tcp_seq_lt(qseq, una) || !tcp_seq_lt(qseq, priv->snd_max)) {
        g_tcp_icmp_bogus_count++;
        return 0;
    }

    if (kind == TCP_ICMP_PMTU) {
        g_tcp_icmp_pmtu_ok++;
        return 1;
    }
    if (kind == TCP_ICMP_HARD) {
        g_tcp_icmp_hard_count++;
        if (handshake) {
            if (owner == smp_core_index()) tcp_icmp_hard_close(cn, priv);
            else priv->icmp_hard = 1;
        } else {
            priv->icmp_soft_err++;   /* 確立後は記録だけ(RFC 5461)*/
        }
        return 1;
    }
    g_tcp_icmp_soft_count++;
    priv->icmp_soft_err++;
    return 1;
}

static volatile int s_abort_requested;

int tcp_abort_requested(void)
{
    return s_abort_requested;
}

/*=================================================================
 * Ctrl+C による中断要求フラグをクリアする。長時間コマンドの開始前に必ず
 * 呼び、前回の Ctrl+C が次のコマンドを即座に中断しないようにする。
 *
 * コール元:
 *   nvmet_io_job_recv_fail(), nvmet_io_job_step_impl()
 * ===============================================================*/
void tcp_clear_abort_request(void)
{
    s_abort_requested = 0;
}

static void tcp_cwnd_grow_on_ack(tcp_priv_t *priv, uint16_t mss);

static tcp_async_slot_t *tcp_async_slot_at(tcp_priv_t *priv, unsigned core, unsigned logical_idx);

/*=================================================================
 * undo(無駄だった再送の取り消し)の準備。回復に入る直前の cwnd / ssthresh と、どこから送り直すか
 * (snd_una)、自分の時刻(Timestamps)を控える。**既に回復中なら控え直さない** -- 控え直すと、
 * 下げた後の cwnd を「元の値」として覚えてしまう(Linux の tcp_enter_loss() も同じ判断)。
 *
 * 引数:
 *   priv    - コネクションのプライベート状態
 *   snd_nxt - 回復を始めたときに送り終えていた seq
 * コール元:
 *   tcp_enter_recovery(), tcp_send()(RTO)
 * ===============================================================*/
static void tcp_undo_arm(tcp_priv_t *priv, uint32_t snd_nxt)
{
    if (!g_tcp_undo_enable) { priv->undo_valid = 0; return; }
    priv->undo_valid     = 1;
    priv->undo_ended     = 0;
    priv->undo_marker    = priv->snd_una;
    priv->undo_high      = snd_nxt;
    priv->undo_retrans   = 0;
    priv->undo_log_n     = 0;
    priv->undo_log_over  = 0;
    priv->undo_ts_ok     = priv->ts_enabled;
    priv->prior_cwnd     = priv->cwnd;
    priv->prior_ssthresh = priv->ssthresh;
    g_tcp_undo_armed++;
}

/* 送り直した時刻を控える(未確認の送り直しのうち最初のもの)。Eifel は「ACK の TSecr がこれより前 =
 * 送り直しより前に送った元のセグメントへの ACK」で判定する。回復を始めた時刻と比べると、前の回復で
 * 送り直したものがまだ届いていないときに、その ACK を元の送信への ACK と取り違える(実測で、
 * 本物のロスだけの試験で 172 回 undo した)。 */
static inline void tcp_retx_stamp(tcp_priv_t *priv, uint32_t seq, uint32_t bytes)
{
    if (!priv->ts_enabled) return;
    if (priv->retx_ts == 0u) {
        /* 呼ぶのは送り直した直後なので、最後に送った TSval = 送り直しの TSval。 */
        uint32_t t = priv->ts_last_sent;
        priv->retx_ts  = t ? t : 1u;
        priv->retx_end = seq + bytes;
    } else if (tcp_seq_gt(seq + bytes, priv->retx_end)) {
        priv->retx_end = seq + bytes;
    }
}

/*=================================================================
 * 送り直した範囲を undo の勘定に入れる(DSACK で全部返ってきたら無駄だったと分かる)。範囲はこの回復の
 * 控え(undo_log)に入れ、DSACK はそこと重なった分だけ引く(tcp_on_dsack_rx())。**前の回復で送り直した
 * ものへの DSACK を今の回復から引かない**ため(DSACK はスロットが確認されて解放された後に届くので、
 * スロットの印では結び付けられない)。
 * ===============================================================*/
static inline void tcp_undo_note(tcp_priv_t *priv, uint32_t seq, uint32_t bytes)
{
    tcp_retx_stamp(priv, seq, bytes);
    if (!priv->undo_valid || tcp_seq_lt(seq, priv->undo_marker) || bytes == 0u) return;
    priv->undo_retrans += bytes;
    const unsigned n = priv->undo_log_n;
    if (n > 0u && priv->undo_log[n - 1u].e == seq) {
        priv->undo_log[n - 1u].e = seq + bytes;   /* 続けて送り直した(Go-Back-N や隣のスロット) */
    } else if (n < TCP_UNDO_LOG) {
        priv->undo_log[n].s = seq;
        priv->undo_log[n].e = seq + bytes;
        priv->undo_log_n = (uint8_t)(n + 1u);
    } else if (!priv->undo_log_over) {
        priv->undo_log_over = 1;
        g_tcp_undo_log_over++;
    }
}

/*=================================================================
 * DSACK の範囲 [bs, be) のうち、この回復で送り直した範囲(控え)と重なるバイト数を数え、控えから外す。
 * 1 つの DSACK は 1 回の重複した到着なので、同じ範囲を 2 度送り直した控えがあっても 1 つ分だけ外す。
 *
 * 戻り値:
 *   控えと重なったバイト数
 * コール元:
 *   tcp_on_dsack_rx()
 * ===============================================================*/
static uint32_t tcp_undo_log_take(tcp_priv_t *priv, uint32_t bs, uint32_t be)
{
    uint32_t got = 0;
    unsigned i = 0;
    while (i < priv->undo_log_n && tcp_seq_lt(bs, be)) {
        uint32_t ls = priv->undo_log[i].s, le = priv->undo_log[i].e;
        uint32_t os = tcp_seq_gt(bs, ls) ? bs : ls;
        uint32_t oe = tcp_seq_lt(be, le) ? be : le;
        if (!tcp_seq_lt(os, oe)) { i++; continue; }
        got += oe - os;
        /* 控えから重なった部分を外す。 */
        if (os == ls && oe == le) {
            for (unsigned k = i + 1u; k < priv->undo_log_n; k++) priv->undo_log[k - 1u] = priv->undo_log[k];
            priv->undo_log_n--;
        } else if (os == ls) {
            priv->undo_log[i].s = oe; i++;
        } else if (oe == le) {
            priv->undo_log[i].e = os; i++;
        } else if (priv->undo_log_n < TCP_UNDO_LOG) {
            /* 真ん中だけ外れた: 2 つに分ける。 */
            for (unsigned k = priv->undo_log_n; k > i + 1u; k--) priv->undo_log[k] = priv->undo_log[k - 1u];
            priv->undo_log[i + 1u].s = oe; priv->undo_log[i + 1u].e = le;
            priv->undo_log[i].e = os;
            priv->undo_log_n++;
            i += 2u;
        } else {
            priv->undo_log_over = 1;   /* 分けられない: 以後この回復では DSACK で戻さない */
            g_tcp_undo_log_over++;
            return got;
        }
        /* DSACK の残り(重なりより前か後ろ)。前後両方に残ることはまず無いので、後ろを優先する。 */
        if (os == bs) bs = oe; else be = os;
    }
    return got;
}

/*=================================================================
 * 送り直しは全部無駄だった(相手は元の送信を受け取っていた)。下げた cwnd / ssthresh を戻し、
 * 回復を終える(Linux の tcp_undo_cwnd_reduction())。届く順番の入れ替わりがある経路なので、
 * RACK の入れ替わりの窓も使うようにする。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   by_ts       - 1=Timestamps で分かった、0=DSACK で分かった
 * コール元:
 *   tcp_on_dsack_rx(), tcp_input_addr()
 * ===============================================================*/
static void tcp_lost_clear(tcp_conn_t *conn, tcp_priv_t *priv);

static void tcp_undo_do(tcp_conn_t *conn, tcp_priv_t *priv, int by_ts)
{
    tcp_lost_clear(conn, priv);   /* 失われたと見て送り直し待ちだったものは、失われていなかった */
    priv->prr_active = 0;
    if (priv->prior_cwnd > priv->cwnd) priv->cwnd = priv->prior_cwnd;
    if (priv->prior_ssthresh > priv->ssthresh) priv->ssthresh = priv->prior_ssthresh;
    priv->in_fast_recovery = 0;
    priv->dup_ack_count    = 0;
    priv->recover          = priv->snd_una;   /* recover ガードを外す(次の本当の損失で回復に入れる) */
    priv->undo_valid       = 0;
    priv->rack_reord_seen  = 1;
    if (by_ts) g_tcp_undo_ts++; else g_tcp_undo_dsack++;
}

/* cwnd と比べるときに飛んでいる量から外すもの: SACK 済み(RFC 6675 の pipe)と、失われたと見て
 * まだ送り直していないもの。 */
static inline uint32_t tcp_cwnd_credit(const tcp_priv_t *priv)
{
    return tcp_sacked_bytes(priv) + priv->lost_bytes;
}

/* 飛んでいる量(RFC 6675 の pipe): 未確認のうち、SACK 済みでも失われたと見たものでもないもの。 */
static inline uint32_t tcp_pipe(const tcp_conn_t *conn, const tcp_priv_t *priv)
{
    const uint32_t out = conn->snd_seq - priv->snd_una;
    const uint32_t c = tcp_cwnd_credit(priv);
    return (out > c) ? out - c : 0u;
}

/*=================================================================
 * PRR(RFC 6937)。回復中の ACK ごとに、届いた量(累積 ACK の進み + 新しく SACK された量)を足し、
 * 送ってよい量 sndcnt を決めて cwnd = pipe + sndcnt に置き直す。飛んでいる量が ssthresh を超えている
 * 間は「届いた量 x ssthresh / 回復に入ったときの量」に比例して減らし、下回ったら ssthresh まで
 * (1 回の ACK で届いた量 + 1 MSS を上限に)戻す(PRR-SSRB)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   delivered   - この ACK で届いたと分かったバイト数
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static void tcp_prr_on_ack(tcp_conn_t *conn, tcp_priv_t *priv, uint32_t delivered)
{
    const uint32_t mss = conn->snd_mss;
    priv->prr_delivered += delivered;
    const uint32_t pipe = tcp_pipe(conn, priv);
    int64_t sndcnt;
    if (pipe > priv->ssthresh) {
        uint64_t want = ((uint64_t)priv->prr_delivered * priv->ssthresh + priv->prr_recover_fs - 1u) /
                        priv->prr_recover_fs;
        sndcnt = (int64_t)want - (int64_t)priv->prr_out;
    } else {
        int64_t limit = (int64_t)priv->prr_delivered - (int64_t)priv->prr_out;
        if (limit < (int64_t)delivered) limit = delivered;
        limit += mss;
        sndcnt = (int64_t)priv->ssthresh - (int64_t)pipe;
        if (sndcnt > limit) sndcnt = limit;
    }
    if (sndcnt < 0) sndcnt = 0;
    if (priv->prr_out == 0u && sndcnt < (int64_t)mss) sndcnt = mss;
    priv->cwnd = pipe + (uint32_t)sndcnt;
    if (priv->lost_bytes != 0u) priv->rack_dirty = 1;   /* 送り直し待ちがあれば RACK に見直させる */
}

/* 送り直してよいか(PRR)。飛んでいる量が cwnd 未満なら 1 スロット送ってよい(Linux も 1 パケット単位で
 * 「pipe >= cwnd なら止める」)。 */
static inline int tcp_prr_can_send(const tcp_conn_t *conn, const tcp_priv_t *priv)
{
    if (!priv->prr_active) return 1;
    return tcp_pipe(conn, priv) < priv->cwnd;
}

/*=================================================================
 * 高速回復に入る(重複 ACK 3 個か RACK が損失を見つけたとき)。ssthresh を飛んでいる量の半分にする。
 * PRR が有効なら cwnd は以後の ACK ごとに決め、無効なら ssthresh + 3 MSS にする(RFC 5681)。
 * その前に undo の準備をする。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_on_dup_ack(), tcp_rack_detect()
 * ===============================================================*/
static void tcp_enter_recovery(tcp_conn_t *conn, tcp_priv_t *priv)
{
    const uint32_t mss = conn->snd_mss;
    tcp_undo_arm(priv, conn->snd_seq);
    /* flight は「未確認バイト数」。conn->snd_seq は楽観的に進めてあるので
     * これがそのまま snd_nxt 相当になる。 */
    uint32_t flight = conn->snd_seq - priv->snd_una;
    uint32_t half   = flight / 2u;
    priv->ssthresh = (half > 2u * mss) ? half : 2u * mss;
    priv->recover  = conn->snd_seq;
    priv->in_fast_recovery = 1;
    if (g_tcp_prr_enable && !priv->in_bulk_send) {
        /* PRR: 送ってよい量は以後の ACK ごとに決める(tcp_prr_on_ack())。最初の送り直し 1 つ分だけは
         * すぐ送れるようにする(Linux の tcp_cwnd_reduction() の「prr_out が 0 なら最低 1」)。 */
        priv->prr_active     = 1;
        priv->prr_delivered  = 0;
        priv->prr_out        = 0;
        priv->prr_recover_fs = flight ? flight : 1u;
        priv->cwnd           = tcp_pipe(conn, priv) + mss;
    } else {
        priv->prr_active = 0;
        priv->cwnd       = priv->ssthresh + 3u * mss;
    }
}

/* RACK で判定するか。SACK が無いと「後から送ったものが届いた」が分からない。一括送信は対象外。 */
static inline int tcp_rack_on(const tcp_priv_t *priv)
{
    return g_tcp_rack_enable && priv->sack_enabled && g_tcp_sack_use_tx && !priv->in_bulk_send;
}

/*=================================================================
 * 相手から DSACK(受け取り済みのデータがもう一度届いた、RFC 2883)を受けた。
 * (1) 順序の入れ替わりがあると見て RACK の窓を広げる(1 往復に 1 回まで)、
 * (2) TLP の probe が無駄だったと記録する、
 * (3) 送り直したバイトを undo の勘定から引き、全部返ってきたら cwnd を戻す。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   bs / be     - DSACK の範囲
 * コール元:
 *   tcp_input_options()
 * ===============================================================*/
static void tcp_on_dsack_rx(const tcp_conn_t *conn, tcp_priv_t *priv, uint32_t bs, uint32_t be)
{
    g_tcp_dsack_rx++;
    if (!tcp_seq_lt(bs, be)) return;
    /* TLP の probe(最後のセグメントの送り直し)への DSACK。probe は undo の勘定に入れておらず、
     * 届く順番の入れ替わりの証拠でもない(元のセグメントが先に届いていただけ)。 */
    if (priv->tlp_active && !tcp_seq_lt(bs, priv->tlp_probe_seq) &&
        !tcp_seq_lt(be, priv->tlp_high_seq)) {
        priv->tlp_dsack = 1;
        return;
    }
    if (!priv->rack_reord_seen) g_tcp_rack_reord++;
    priv->rack_reord_seen = 1;
    if (!priv->rack_dsack_round_valid || !tcp_seq_lt(priv->snd_una, priv->rack_dsack_round)) {
        if (priv->rack_reo_mult < 255u) priv->rack_reo_mult++;
        priv->rack_reo_persist       = 16u;
        priv->rack_dsack_round       = conn->snd_seq;
        priv->rack_dsack_round_valid = 1;
    }
    if (priv->undo_valid && priv->undo_retrans > 0u && !priv->undo_log_over) {
        uint32_t b = tcp_undo_log_take(priv, bs, be);
        if (b == 0u) { g_tcp_undo_dsack_foreign++; return; }
        priv->undo_retrans = (b >= priv->undo_retrans) ? 0u : priv->undo_retrans - b;
        if (priv->undo_retrans == 0u) tcp_undo_do((tcp_conn_t *)conn, priv, 0);
    }
}

/*=================================================================
 * RACK の「順序入れ替わりの窓」(RFC 8985 6.2)。入れ替わりを見ていないうちは、回復中か、
 * 3 セグメント以上 SACK されていれば 0(すぐ失われたと見る)。それ以外は min_rtt/4 x reo_mult
 * を SRTT で頭打ちにする。
 * ===============================================================*/
static inline uint64_t tcp_rack_reo_wnd(const tcp_conn_t *conn, const tcp_priv_t *priv)
{
    if (!priv->rack_reord_seen) {
        if (priv->in_fast_recovery) return 0;
        if (tcp_sacked_bytes(priv) >= 3u * (uint32_t)conn->snd_mss) return 0;
    }
    uint64_t w = (tcp_minrtt(priv) / 4u) * priv->rack_reo_mult;
    uint64_t srtt_ns = priv->srtt_us * 1000u;
    if (srtt_ns != 0u && w > srtt_ns) w = srtt_ns;
    return w;
}

/*=================================================================
 * セグメントが届いた(累積 ACK か SACK)ことを RACK に知らせる。届いた中で一番後に送ったものを
 * 覚える。送り直したセグメントは、往復時間が最小の往復時間より短ければ元の送信への応答かもしれない
 * ので使わない(RFC 8985 6.2 の Step 1)。
 *
 * 引数:
 *   priv    - コネクションのプライベート状態
 *   sent_at - そのセグメントを(最後に)送った時刻
 *   end_seq - その右端
 *   retx    - 送り直したことがあるか
 *   rtt_ns  - 往復時間
 * コール元:
 *   tcp_async_poll(), tcp_async_short_poll(), tcp_rack_mark_sacked()
 * ===============================================================*/
static inline void tcp_rack_deliver(tcp_priv_t *priv, uint64_t sent_at, uint32_t end_seq,
                                    uint8_t retx, uint64_t rtt_ns)
{
    if (priv->rack_fack_valid && tcp_seq_lt(end_seq, priv->rack_fack)) {
        /* 後から送ったものより先に届かなかった = 入れ替わり(送り直していないものに限る)。 */
        if (!retx && !priv->rack_reord_seen) { priv->rack_reord_seen = 1; g_tcp_rack_reord++; }
    } else {
        priv->rack_fack = end_seq;
        priv->rack_fack_valid = 1;
    }
    if (retx && rtt_ns < tcp_minrtt(priv)) return;
    if (sent_at > priv->rack_xmit_at ||
        (sent_at == priv->rack_xmit_at && tcp_seq_gt(end_seq, priv->rack_end_seq))) {
        priv->rack_xmit_at = sent_at;
        priv->rack_end_seq = end_seq;
        priv->rack_rtt_ns  = rtt_ns;
        priv->rack_dirty   = 1;
    }
}

/* lost の印を全部消す(undo: 失われていなかった)。 */
static void tcp_lost_clear(tcp_conn_t *conn, tcp_priv_t *priv)
{
    if (priv->lost_bytes == 0u) return;
    for (unsigned k = 0; k < priv->async_count; k++) {
        tcp_async_slot_at(priv, conn->owner_core, (priv->async_head + k) % priv->async_cap)->lost = 0;
    }
    for (unsigned k = 0; k < priv->async_short_count; k++) {
        priv->async_short_slots[(priv->async_short_head + k) % g_tcp_async_short_cap].lost = 0;
    }
    priv->lost_bytes = 0;
}

/* lost の印のスロットが届いた(累積 ACK / SACK)か送り直された: 飛んでいる量の勘定から外す。 */
static inline void tcp_lost_drop(tcp_priv_t *priv, uint8_t *lost, uint32_t len)
{
    if (!*lost) return;
    *lost = 0;
    priv->lost_bytes = (priv->lost_bytes > len) ? priv->lost_bytes - len : 0u;
}

/*=================================================================
 * 届いた SACK ブロックに含まれるスロットへ「SACK 済み」の印を付け、RACK に知らせる。
 * SACK ブロックが変わったときだけ呼ぶ(ロスのある間だけ)。
 * ===============================================================*/
static void tcp_rack_mark_sacked(tcp_conn_t *conn, tcp_priv_t *priv, uint64_t now)
{
    for (unsigned k = 0; k < priv->async_count; k++) {
        tcp_async_slot_t *s = tcp_async_slot_at(priv, conn->owner_core,
                                                 (priv->async_head + k) % priv->async_cap);
        if (s->sacked || !tcp_seq_lt(priv->snd_una, s->seq + s->len)) continue;
        if (!tcp_sack_covered(priv, s->seq, s->len)) continue;
        s->sacked = 1;
        tcp_lost_drop(priv, &s->lost, s->len);
        tcp_rack_deliver(priv, s->sent_at, s->seq + s->len, s->retx,
                         (now > s->sent_at) ? now - s->sent_at : 0u);
    }
    for (unsigned k = 0; k < priv->async_short_count; k++) {
        tcp_async_short_slot_t *s =
            &priv->async_short_slots[(priv->async_short_head + k) % g_tcp_async_short_cap];
        if (s->sacked || !tcp_seq_lt(priv->snd_una, s->seq + s->len)) continue;
        if (!tcp_sack_covered(priv, s->seq, s->len)) continue;
        s->sacked = 1;
        tcp_lost_drop(priv, &s->lost, s->len);
        tcp_rack_deliver(priv, s->sent_at, s->seq + s->len, s->retx,
                         (now > s->sent_at) ? now - s->sent_at : 0u);
    }
}

/* 1 つのスロット(長経路 / 短経路)を送り直す。0=送った。 */
static int tcp_retx_slot(tcp_conn_t *conn, tcp_priv_t *priv, uint32_t seq, const uint8_t *src,
                         uint16_t len)
{
    uint32_t saved = conn->snd_seq;
    conn->snd_seq = seq;
    int rc = (len > conn->snd_mss)
        ? tcp_send_segment_lso(conn, priv, src, len)
        : tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, src, len);
    conn->snd_seq = saved;
    if (rc == 0) g_tcp_retransmit_segs += ((uint32_t)len + conn->snd_mss - 1u) / conn->snd_mss;
    return rc;
}

/* RACK の判定: このスロットはもう失われたか(1)、まだ待つか(0、*next に判定し直す時刻)、対象外か(-1)。 */
static inline int tcp_rack_lost_at(const tcp_priv_t *priv, uint64_t sent_at, uint32_t end_seq,
                                   uint64_t win, uint64_t now, uint64_t *next)
{
    if (!(sent_at < priv->rack_xmit_at ||
          (sent_at == priv->rack_xmit_at && tcp_seq_lt(end_seq, priv->rack_end_seq)))) return -1;
    uint64_t dl = sent_at + win;
    if (now >= dl) return 1;
    if (*next == 0u || dl < *next) *next = dl;
    return 0;
}

/*=================================================================
 * RACK の損失判定(RFC 8985 6.2 の Step 5)。「届いた中で一番後に送ったもの」より前に送り、まだ
 * 届いていないスロットのうち、送ってから往復時間 + 入れ替わりの窓が過ぎたものを失われたと見て
 * 送り直す。最初の 1 つで回復に入る。まだ窓の中のものがあれば、判定し直す時刻を覚える。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   now         - 現在時刻
 *   by_timer    - 窓が過ぎるのを待ってから呼んだ(統計用)
 * コール元:
 *   tcp_rack_tlp_poll()
 * ===============================================================*/
static void tcp_rack_detect(tcp_conn_t *conn, tcp_priv_t *priv, uint64_t now, int by_timer)
{
    priv->rack_timer_at = 0;
    if (priv->rack_xmit_at == 0u) return;
    const uint64_t win = priv->rack_rtt_ns + tcp_rack_reo_wnd(conn, priv);
    uint64_t next = 0;
    unsigned lost = 0;

    /* 失われた印(lost)はまず付ける。送り直すのは PRR の枠があるものだけで、残りは次の ACK で
     * 枠ができたとき(tcp_prr_on_ack() が rack_dirty を立てる)に送る。 */
    int stop = 0;
    for (unsigned k = 0; k < priv->async_count && !stop; k++) {
        tcp_async_slot_t *s = tcp_async_slot_at(priv, conn->owner_core,
                                                 (priv->async_head + k) % priv->async_cap);
        if (s->sacked || !tcp_seq_lt(priv->snd_una, s->seq + s->len)) continue;
        if (!s->lost) {
            if (tcp_rack_lost_at(priv, s->sent_at, s->seq + s->len, win, now, &next) != 1) continue;
            if (!priv->in_fast_recovery) { tcp_enter_recovery(conn, priv); g_tcp_rack_recovery++; }
            s->lost = 1;
            priv->lost_bytes += s->len;
        }
        if (!tcp_prr_can_send(conn, priv)) { g_tcp_prr_deferred++; continue; }
        if (tcp_retx_slot(conn, priv, s->seq, s->ref ? s->ref : s->buf, s->len) != 0) { stop = 1; break; }
        s->lost = 0;
        priv->lost_bytes = (priv->lost_bytes > s->len) ? priv->lost_bytes - s->len : 0u;
        tcp_undo_note(priv, s->seq, s->len);
        s->sent_at = now;
        s->retx    = 1;
        lost++;
    }
    for (unsigned k = 0; k < priv->async_short_count && !stop; k++) {
        tcp_async_short_slot_t *s =
            &priv->async_short_slots[(priv->async_short_head + k) % g_tcp_async_short_cap];
        if (s->sacked || !tcp_seq_lt(priv->snd_una, s->seq + s->len)) continue;
        if (!s->lost) {
            if (tcp_rack_lost_at(priv, s->sent_at, s->seq + s->len, win, now, &next) != 1) continue;
            if (!priv->in_fast_recovery) { tcp_enter_recovery(conn, priv); g_tcp_rack_recovery++; }
            s->lost = 1;
            priv->lost_bytes += s->len;
        }
        if (!tcp_prr_can_send(conn, priv)) { g_tcp_prr_deferred++; continue; }
        if (tcp_retx_slot(conn, priv, s->seq, s->buf, s->len) != 0) break;
        s->lost = 0;
        priv->lost_bytes = (priv->lost_bytes > s->len) ? priv->lost_bytes - s->len : 0u;
        tcp_undo_note(priv, s->seq, s->len);
        s->sent_at = now;
        s->retx    = 1;
        lost++;
    }
    if (lost) {
        g_tcp_rack_lost += lost;
        if (by_timer) g_tcp_rack_lost_timer += lost;
        g_tcp_retransmit_count[smp_core_index()]++;
        g_tcp_fast_retransmit_count[smp_core_index()]++;   /* RTO 由来ではない */
        priv->tlp_tx_at = now;
    }
    priv->rack_timer_at = next;
}

/*=================================================================
 * TLP の probe を送るか見る(RFC 8985 7.2〜7.3)。回復中でなく、probe の結果待ちでもなく、最後に
 * 送るか ACK が進んでから PTO(2 x SRTT。飛んでいるのが 1 セグメントだけなら相手の遅延 ACK のぶん
 * 200 ms 足す、それ以外は 2 ms 足す)が過ぎたら、一番後ろのスロットを 1 つ送り直す。
 * **PTO が RTO の残りより長ければ送らない**(RTO に任せる。Linux は PTO を RTO の残りに縮めて
 * RTO の代わりに probe を出す。こちらの非同期送信の RTO も今は cwnd を 1 MSS へ下げる
 * (tcp_rto_fire()、RFC 5681)ので、probe で済むなら済ませる Linux の形のほうが得な場面はあるが、
 * 1 セグメントだけ飛んでいるときの PTO は RTO 以上になるので差は小さい)。
 * ===============================================================*/
static void tcp_tlp_check(tcp_conn_t *conn, tcp_priv_t *priv, uint64_t now)
{
    if (priv->in_fast_recovery || priv->tlp_active || priv->srtt_us == 0u ||
        priv->rack_timer_at != 0u) return;
    const uint32_t flight = conn->snd_seq - priv->snd_una;
    if (flight == 0u) return;
    uint64_t pto = 2u * priv->srtt_us * 1000u +
                   ((flight <= conn->snd_mss) ? (uint64_t)TCP_RTO_MIN_MS * 1000000u : 2000000u);
    uint64_t ref = (priv->tlp_ack_at > priv->tlp_tx_at) ? priv->tlp_ack_at : priv->tlp_tx_at;
    if (now < ref + pto) return;

    /* 一番後ろ(seq が最大)のスロットを選ぶ。長経路と短経路は同じ seq の並びに混ざっている。 */
    tcp_async_slot_t *ls = NULL;
    tcp_async_short_slot_t *ss = NULL;
    uint64_t first_sent = 0;
    uint32_t first_rto  = 0;
    if (priv->async_count > 0u) {
        ls = tcp_async_slot_at(priv, conn->owner_core,
                               (priv->async_head + priv->async_count - 1u) % priv->async_cap);
        tcp_async_slot_t *h = tcp_async_slot_at(priv, conn->owner_core, priv->async_head);
        first_sent = h->sent_at; first_rto = h->rto_ms;
    }
    if (priv->async_short_count > 0u) {
        ss = &priv->async_short_slots[(priv->async_short_head + priv->async_short_count - 1u) %
                                      g_tcp_async_short_cap];
        tcp_async_short_slot_t *h = &priv->async_short_slots[priv->async_short_head];
        if (first_sent == 0u || h->sent_at < first_sent) { first_sent = h->sent_at; first_rto = h->rto_ms; }
    }
    if (ls && ss) { if (tcp_seq_lt(ls->seq, ss->seq)) ls = NULL; else ss = NULL; }
    const uint64_t rto_at = first_sent + (uint64_t)first_rto * 1000000u;
    if (now >= rto_at || ref + pto >= rto_at) return;   /* RTO に任せる */

    uint32_t seq;
    if (ls) {
        if (ls->sacked || !tcp_seq_lt(priv->snd_una, ls->seq + ls->len)) return;
        if (tcp_retx_slot(conn, priv, ls->seq, ls->ref ? ls->ref : ls->buf, ls->len) != 0) return;
        seq = ls->seq; ls->sent_at = now; ls->retx = 1; tcp_retx_stamp(priv, ls->seq, ls->len);
    } else if (ss) {
        if (ss->sacked || !tcp_seq_lt(priv->snd_una, ss->seq + ss->len)) return;
        if (tcp_retx_slot(conn, priv, ss->seq, ss->buf, ss->len) != 0) return;
        seq = ss->seq; ss->sent_at = now; ss->retx = 1; tcp_retx_stamp(priv, ss->seq, ss->len);
    } else {
        return;
    }
    priv->tlp_active    = 1;
    priv->tlp_dsack     = 0;
    priv->tlp_high_seq  = conn->snd_seq;
    priv->tlp_probe_seq = seq;
    priv->tlp_tx_at     = now;
    g_tcp_tlp_probes++;
}

/*=================================================================
 * TLP の probe の結果(RFC 8985 7.4)。probe のときの snd_nxt まで ACK されたうえで、DSACK が来て
 * いれば probe は無駄だった(何もしない)。DSACK が無いまま、その先まで ACK されたら、probe が
 * 損失を直した = 1 回の回復と同じだけ cwnd を下げる。そこで止まったまま新しい情報の無い純 ACK が
 * 来たら諦める(Linux の tcp_process_tlp_ack() と同じ)。
 * ===============================================================*/
static void tcp_tlp_on_ack(tcp_conn_t *conn, tcp_priv_t *priv, uint32_t ack, int pure_dup)
{
    if (tcp_seq_lt(ack, priv->tlp_high_seq)) return;
    if (priv->tlp_dsack) {
        priv->tlp_active = 0;
        g_tcp_tlp_redundant++;
        return;
    }
    if (tcp_seq_gt(ack, priv->tlp_high_seq)) {
        priv->tlp_active = 0;
        const uint32_t mss = conn->snd_mss;
        uint32_t half = priv->cwnd / 2u;
        priv->ssthresh = (half > 2u * mss) ? half : 2u * mss;
        priv->cwnd     = priv->ssthresh;
        g_tcp_tlp_recovered++;
        return;
    }
    if (pure_dup) priv->tlp_active = 0;
}

/*=================================================================
 * RACK と TLP のポーリング(tcp_async_poll() / tcp_async_short_poll() の後に呼ぶ)。
 * SACK ブロックが変わったか、RACK の「一番後に送って届いたもの」が進んだときに損失を判定する。
 * 時刻で動く部分(入れ替わりの窓が過ぎたか、PTO が過ぎたか)は timed のときだけ見る
 * (この環境では時刻の読み出しが高いことがあるので、ポーリングの毎回は読まない)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   timed       - 時刻で動く部分も見る
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
static void tcp_rack_tlp_poll(tcp_conn_t *conn, tcp_priv_t *priv, int timed)
{
    if (!priv->sack_enabled || priv->in_bulk_send) return;
    if (priv->async_count == 0u && priv->async_short_count == 0u) {
        priv->rack_timer_at = 0;
        return;
    }
    uint64_t now = 0;
    int need = 0;
    if (tcp_rack_on(priv)) {
        if (priv->sack_gen != priv->sack_gen_seen) {
            priv->sack_gen_seen = priv->sack_gen;
            now = timer_now();
            tcp_rack_mark_sacked(conn, priv, now);
            need = 1;
        }
        if (priv->rack_dirty) {
            priv->rack_dirty = 0;
            if (priv->lost_bytes != 0u) need = 1;   /* PRR の枠ができたら送り直し待ちを送る */
            /* 一番前の未確認のスロットが「届いた一番後のもの」より前に送ったものなら判定する。
             * ロスが無ければ前のほうから順に届くので、ここで止まる。 */
            if (!need) {
                if (priv->async_count > 0u &&
                    tcp_async_slot_at(priv, conn->owner_core, priv->async_head)->sent_at < priv->rack_xmit_at) need = 1;
                if (priv->async_short_count > 0u &&
                    priv->async_short_slots[priv->async_short_head].sent_at < priv->rack_xmit_at) need = 1;
            }
        }
        int by_timer = 0;
        if (timed && !need && priv->rack_timer_at != 0u) {
            now = timer_now();
            if (now >= priv->rack_timer_at) { need = 1; by_timer = 1; }
        }
        if (need) {
            if (now == 0u) now = timer_now();
            tcp_rack_detect(conn, priv, now, by_timer);
        }
    }
    if (timed && priv->prr_active && priv->in_fast_recovery && priv->srtt_us != 0u) {
        /* **PRR の手詰まりを解く。** 飛んでいる量が ssthresh を超えている間、PRR は届いた量に比例してしか
         * 送らせない。飛んでいるはずのものが実は相手に捨てられていると(届く順番の入れ替わりで RACK が
         * 無駄に送り直し、新しい TSval の送り直しが先に着くと、受け手の Linux は遅れて着いた元のセグメントを
         * PAWS で捨てる。Linux どうしは TSval が 1 ms 刻みなので起きない)、何も届かないので枠が開かず、
         * 新しいデータも出ないので RACK は捨てられたものに気付けず、RTO まで止まる。2 x SRTT + 2 ms 何も
         * 届かなければ 1 MSS だけ送らせ、それが SACK されれば RACK が見つける(TLP と同じ考え方)。 */
        if (now == 0u) now = timer_now();
        const uint32_t pipe = tcp_pipe(conn, priv);
        const uint64_t ref = (priv->tlp_ack_at > priv->tlp_tx_at) ? priv->tlp_ack_at : priv->tlp_tx_at;
        if (pipe >= priv->cwnd && now >= ref + 2u * priv->srtt_us * 1000u + 2000000u) {
            priv->cwnd = pipe + conn->snd_mss;
            priv->tlp_tx_at = now;   /* 次に開けるのはさらに 2 x SRTT 後 */
            g_tcp_prr_unstall++;
        }
    }
    if (timed && g_tcp_tlp_enable) {
        if (now == 0u) now = timer_now();
        tcp_tlp_check(conn, priv, now);
    }
}

/*=================================================================
 * 非同期送信(tcp_send_async)キューの背後処理。届いた ACK で確認済みの
 * スロットを解放し、RTO を超えた未確認スロットを再送する。呼び出し元は
 * 一切ブロックされない。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
/*=================================================================
 * 非同期送信のスロットで RTO が切れたときの共通の手続き(送り直す前に呼ぶ)。
 *
 * (1) **再送の時間切れ(R2)**: RTO で送り直し始めてから TCP_R2_DATA_MS(100 秒)たっても
 *     累積 ACK が進まなければ、接続を RST で閉じる(RFC 1122 4.2.3.5 / RFC 9293 3.8.3)。
 *     以前は回数(5 回、RTO 倍々で約 23 秒)で諦め、seq を巻き戻して続けていた。
 * (2) **輻輳ウィンドウを下げる**(RFC 5681 3.1 の式 4 と「LW」)。そのセグメントを RTO で
 *     初めて送り直すときだけ ssthresh = max(飛んでいる量 / 2, 2 MSS)、毎回 cwnd = 1 MSS。
 *     以前は非同期送信の RTO では cwnd を下げておらず、一括送信(tcp_send())だけが下げていた。
 *     回復中でなければ undo の準備をする(RTO が無駄だったと Timestamps / DSACK で分かれば戻す)。
 * 時刻を読むのは RTO が切れたとき(冷たい経路)だけ。
 *
 * 引数:
 *   conn / priv - 対象
 *   retries     - そのスロットの RTO の回数(1 = 初めて)
 *   what        - 表示する経路名
 * 戻り値: 1 = 諦めて接続を閉じた(呼び出し側はすぐ戻ること)、0 = 送り直してよい
 * コール元: tcp_async_poll(), tcp_async_short_poll()
 * ===============================================================*/
static int tcp_rto_fire(tcp_conn_t *conn, tcp_priv_t *priv, int retries, const char *what)
{
    const uint64_t now = timer_now();
    if (priv->rto_since == 0u) {
        priv->rto_since = now;
    } else if (now - priv->rto_since >= (uint64_t)TCP_R2_DATA_MS * 1000000u) {
        g_tcp_retx_abort++;
        uart_printf("[!] TCP: %s の再送が %u 秒たっても確認されない\n", what, (unsigned)(TCP_R2_DATA_MS / 1000u));
        tcp_abort_conn(conn, priv, "再送の上限(R2)");
        return 1;
    }
    const uint32_t mss = conn->snd_mss;
    if (retries == 1) {
        if (!priv->in_fast_recovery) tcp_undo_arm(priv, conn->snd_seq);
        const uint32_t flight = conn->snd_seq - priv->snd_una;
        const uint32_t half = flight / 2u;
        priv->ssthresh = (half > 2u * mss) ? half : 2u * mss;
    }
    priv->cwnd = mss;
    priv->in_fast_recovery = 0;
    priv->prr_active       = 0;
    priv->dup_ack_count    = 0;
    /* RTO の後は、ここまで送ったものが ACK されるまで重複 ACK で回復に入らない(RFC 6582 4)。 */
    priv->recover          = conn->snd_seq;
    return 0;
}

static void tcp_async_poll(tcp_conn_t *conn, tcp_priv_t *priv)
{
    if (priv->ack_advanced && !priv->in_bulk_send) {
        priv->ack_advanced = 0;
        tcp_cwnd_grow_on_ack(priv, conn->snd_mss);
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 0), tcp_conn_arg(conn, priv->cwnd));
    }

    while (priv->async_count > 0) {
        tcp_async_slot_t *s = tcp_async_slot_at(priv, conn->owner_core, priv->async_head);
        uint32_t end_seq = s->seq + s->len;
        if (!tcp_seq_lt(priv->snd_una, end_seq)) {
            /* 累積 ACK で届いた。往復時間は直近の RTT の標本を使う(ここで時刻を読まない)。
             * 送り直したものは、どちらの送信への ACK か分からないので使わない。 */
            if (!s->sacked && !s->retx && tcp_rack_on(priv)) {
                tcp_rack_deliver(priv, s->sent_at, end_seq, 0, priv->rack_rtt_last_ns);
            }
            tcp_lost_drop(priv, &s->lost, s->len);
            priv->async_head = (priv->async_head + 1u) % priv->async_cap;
            priv->async_count--;
            priv->rto_since = 0;   /* 進んだので再送の時間切れ(R2)を測り直す */
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 1), tcp_conn_arg(conn, s->len));
            continue;
        }

        /* 高速再送。RTO 経路と同じ Go-Back-N で、キューに残っている未確認
         * スロットを先頭から全部送り直す。RTO 由来ではないので retries と
         * RTO の指数バックオフには触らない(ここで retries を進めると、
         * ロスが続いたときに再送上限へ早く到達して接続を諦めてしまう)。 */
        if (priv->fr_gen_async != priv->fast_retransmit_gen) {
            priv->fr_gen_async = priv->fast_retransmit_gen;
            g_tcp_retransmit_count[smp_core_index()]++;
            g_tcp_fast_retransmit_count[smp_core_index()]++;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 3), tcp_conn_arg(conn, priv->async_count));
            uint32_t fr_saved_snd_seq = conn->snd_seq;
            uint64_t fr_now = timer_now();
            if (g_tcp_sack_debug && priv->sack_enabled) {
                uart_printf("[SACKDBG] async una=%u count=%u mss=%u blocks=%u",
                            priv->snd_una, priv->async_count, conn->snd_mss,
                            (unsigned)priv->sack_rx_count);
                for (unsigned bi = 0; bi < priv->sack_rx_count; bi++) {
                    uart_printf(" [%u,%u)", priv->sack_rx[bi].start, priv->sack_rx[bi].end);
                }
                for (unsigned k = 0; k < priv->async_count && k < 4u; k++) {
                    tcp_async_slot_t *ds = tcp_async_slot_at(priv, conn->owner_core,
                                                             (priv->async_head + k) % priv->async_cap);
                    uart_printf(" slot%u=(%u,+%u)", k, ds->seq, (unsigned)ds->len);
                }
                uart_printf("\n");
                g_tcp_sack_debug--;
            }
            uint32_t fr_sack_high = tcp_sack_high(priv);
            unsigned fr_sent = 0;
            for (unsigned k = 0; k < priv->async_count; k++) {
                tcp_async_slot_t *rs = tcp_async_slot_at(priv, conn->owner_core,
                                                          (priv->async_head + k) % priv->async_cap);
                /* **SACK ブロックより先はまだ飛行中**なので送り直さない。
                 * Go-Back-N はここで未確認ウィンドウ全部を送り直していた。 */
                if (fr_sack_high != 0u && !tcp_seq_lt(rs->seq, fr_sack_high)) {
                    g_tcp_sack_skipped_count++;
                    break;
                }
                /* 相手に届いていると分かっている範囲も送り直さない。
                 * **ただし RTO タイマは押し直す。** 送らないままにすると
                 * 古い sent_at が残り、「相手が確かに持っているスロット」で
                 * RTO が発火する。RTO は scoreboard を捨てて Go-Back-N へ
                 * 戻すので、そこから連鎖して回復が 200ms 単位で遅れる
                 * (Go-Back-N のときは毎回全スロットを送り直していたので
                 * タイマも一緒に押し直されており、表面化しなかった)。 */
                if (tcp_sack_covered(priv, rs->seq, rs->len)) {
                    g_tcp_sack_skipped_count++;
                    rs->sent_at = fr_now;
                    continue;
                }
                conn->snd_seq = rs->seq;
                const uint8_t *fr_src = rs->ref ? rs->ref : rs->buf;
                if (rs->len > conn->snd_mss) {
                    if (tcp_send_segment_lso(conn, priv, fr_src, rs->len) != 0) break;
                } else {
                    if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                          fr_src, rs->len) != 0) break;
                }
                /* LSO スロットは HW が複数セグメントに分割するので、線上の
                 * セグメント数で数える(相手はその数だけ ACK を返す)。
                 * **SACK があるときは補正そのものが要らない**(穴だけを
                 * 送り直すので、相手は重複 ACK ではなく新しい ACK を返す)。 */
                if (!priv->sack_enabled) {
                    priv->dup_ack_suppress +=
                        ((uint32_t)rs->len + conn->snd_mss - 1u) / conn->snd_mss;
                }
                g_tcp_retransmit_segs += ((uint32_t)rs->len + conn->snd_mss - 1u) / conn->snd_mss;
                tcp_undo_note(priv, rs->seq, rs->len);
                fr_sent++;
                rs->sent_at = fr_now;
                rs->retx    = 1;
            }
            if (fr_sent == 0u) g_tcp_fr_empty++;
            priv->tlp_tx_at = fr_now;
            conn->snd_seq = fr_saved_snd_seq;
            return;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;  /* まだRTO未満、様子見(呼び出し元はブロックしていない) */
        }

        s->retries++;
        if (tcp_rto_fire(conn, priv, s->retries, "tcp_send_async")) return;   /* R2 で諦めた */
        g_tcp_retransmit_count[smp_core_index()]++;
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 2), tcp_conn_arg(conn, (uint32_t)s->retries));

        uint32_t saved_snd_seq = conn->snd_seq;
        conn->snd_seq = s->seq;
        const uint8_t *rsrc = s->ref ? s->ref : s->buf;
        if (s->len > conn->snd_mss) {
            tcp_send_segment_lso(conn, priv, rsrc, s->len);
        } else {
            tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, rsrc, s->len);
        }
        /* SACK があるときは補正しない -- 相手は SACK ブロックで「どこが
         * 抜けているか」を伝えてくるので、こちらの再送が生む重複 ACK を
         * 差し引く必要が無い。**差し引くと重複 ACK を全部食い潰して高速再送が
         * 一度も発火しなくなる**(実測で 1628 個の重複 ACK に対し発火 0)。 */
        if (!priv->sack_enabled) {
            priv->dup_ack_suppress += ((uint32_t)s->len + conn->snd_mss - 1u) / conn->snd_mss;
        }
        g_tcp_retransmit_segs += ((uint32_t)s->len + conn->snd_mss - 1u) / conn->snd_mss;
        tcp_undo_note(priv, s->seq, s->len);
        s->retx = 1;
        tcp_lost_drop(priv, &s->lost, s->len);
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        priv->tlp_tx_at = s->sent_at;   /* 送り直した直後に TLP が同じものを送らないように */
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
        /* 後退した RTO を接続の RTO にも引き継ぐ(RFC 6298 5.5)。これから積むスロットは
         * この値から始まる。次に RTT を測れたら tcp_rtt_update() が計算し直す。 */
        if (s->rto_ms > priv->rto_ms) priv->rto_ms = s->rto_ms;
        return;
    }
}

/*=================================================================
 * tcp_async_poll() の短小 PDU 専用キュー版(CMD/RSP/R2T/ICResp のような
 * 小さい単発 PDU を、大きいデータ送信とは別のキューで追跡する)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
static void tcp_async_short_poll(tcp_conn_t *conn, tcp_priv_t *priv)
{
    while (priv->async_short_count > 0) {
        tcp_async_short_slot_t *s = &priv->async_short_slots[priv->async_short_head];
        uint32_t end_seq = s->seq + s->len;
        if (!tcp_seq_lt(priv->snd_una, end_seq)) {
            if (!s->sacked && !s->retx && tcp_rack_on(priv)) {
                tcp_rack_deliver(priv, s->sent_at, end_seq, 0, priv->rack_rtt_last_ns);
            }
            tcp_lost_drop(priv, &s->lost, s->len);
            priv->async_short_head = (priv->async_short_head + 1u) % g_tcp_async_short_cap;
            priv->async_short_count--;
            priv->rto_since = 0;   /* 進んだので再送の時間切れ(R2)を測り直す */
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_short_poll, 0), tcp_conn_arg(conn, s->len));
            continue;
        }

        /* 高速再送(tcp_async_poll() と同じ扱い)。 */
        if (priv->fr_gen_short != priv->fast_retransmit_gen) {
            priv->fr_gen_short = priv->fast_retransmit_gen;
            g_tcp_retransmit_count[smp_core_index()]++;
            g_tcp_fast_retransmit_count[smp_core_index()]++;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_short_poll, 2), tcp_conn_arg(conn, priv->async_short_count));
            uint32_t fr_saved_snd_seq = conn->snd_seq;
            uint64_t fr_now = timer_now();
            uint32_t fr_sack_high = tcp_sack_high(priv);
            for (unsigned k = 0; k < priv->async_short_count; k++) {
                tcp_async_short_slot_t *rs =
                    &priv->async_short_slots[(priv->async_short_head + k) % g_tcp_async_short_cap];
                if (fr_sack_high != 0u && !tcp_seq_lt(rs->seq, fr_sack_high)) {
                    g_tcp_sack_skipped_count++;
                    break;
                }
                if (tcp_sack_covered(priv, rs->seq, rs->len)) {
                    g_tcp_sack_skipped_count++;
                    rs->sent_at = fr_now;  /* 上と同じ理由(RTO の空振りを防ぐ) */
                    continue;
                }
                conn->snd_seq = rs->seq;
                if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                      rs->buf, rs->len) != 0) break;
                /* short スロットは常に 1 セグメント。SACK があるときは補正不要。 */
                if (!priv->sack_enabled) priv->dup_ack_suppress++;
                g_tcp_retransmit_segs++;
                tcp_undo_note(priv, rs->seq, rs->len);
                rs->sent_at = fr_now;
                rs->retx    = 1;
            }
            priv->tlp_tx_at = fr_now;
            conn->snd_seq = fr_saved_snd_seq;
            return;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;
        }

        s->retries++;
        if (tcp_rto_fire(conn, priv, s->retries, "tcp_send_async(short)")) return;   /* R2 で諦めた */
        g_tcp_retransmit_count[smp_core_index()]++;
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_short_poll, 1), tcp_conn_arg(conn, (uint32_t)s->retries));

        uint32_t saved_snd_seq = conn->snd_seq;
        conn->snd_seq = s->seq;
        tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, s->buf, s->len);
        if (!priv->sack_enabled) priv->dup_ack_suppress++;
        g_tcp_retransmit_segs++;
        tcp_undo_note(priv, s->seq, s->len);
        s->retx = 1;
        tcp_lost_drop(priv, &s->lost, s->len);
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        priv->tlp_tx_at = s->sent_at;   /* 送り直した直後に TLP が同じものを送らないように */
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
        if (s->rto_ms > priv->rto_ms) priv->rto_ms = s->rto_ms;   /* RFC 6298 5.5(上と同じ)*/
        return;
    }
}

/*=================================================================
 * TCP の共通ポーリング 1 回分。受信ポーリング、非同期送信の ACK 確認と
 * 再送、TIME_WAIT の掃除を行う。check_ctrl_c=0 なら UART の未読バイトを
 * 一切消費しない(ジョブ化された非ブロッキング受信から呼ぶとき用)。
 *
 * 引数:
 *   check_ctrl_c - 1=Ctrl+C 検出も行う、0=UART に触れない
 * コール元:
 *   tcp_poll_once(), tcp_recv_internal(), tcp_accept_ready_poll()
 * ===============================================================*/
/*=================================================================
 * Keepalive(RFC 1122 4.2.3.6)。無通信のまま相手が消えた接続を検出する。
 *
 * 「相手が生きているか」は **受け取ったセグメントの数(rx_segs)が増えたか**で判定する
 * -- 受信のたびに時刻を書くとホットパスに時計が乗るため(A2 / D7 と同じ方針)。
 * 増えなくなってから idle_ms が過ぎたら probe を送り、intvl_ms ごとに繰り返して
 * probes 回で諦める。
 *
 * **Keepalive を使うのは ka_enabled の接続だけ**(既定は無効、RFC 1122 の MUST-24/25)。
 * **未確認データがある接続には probe を送らない。** そちらは RTO の担当で、
 * 重ねて叩いても意味が無い(相手の ACK を重複 ACK と数える経路にも触れる)。
 * 諦めたら RST を送って閉じる(Linux も Keepalive の時間切れで RST を送る)。
 *
 * 引数:
 *   cn / priv - 対象(ESTABLISHED、ka_enabled)
 *   now       - 今の時刻
 * コール元:
 *   tcp_cold_check()
 * ===============================================================*/
static void tcp_keepalive_one(tcp_conn_t *cn, tcp_priv_t *priv, uint64_t now)
{
    /* 相手から何か来ていれば「生きている」。**probe への応答は純 ACK
     * なので、データや累積 ACK の進みでは検出できない**(数を使う理由)。 */
    const uint32_t rs = priv->rx_segs;
    if (rs != priv->ka_rx_snap || priv->ka_idle_since == 0) {
        priv->ka_rx_snap    = rs;
        priv->ka_idle_since = now;
        priv->ka_probes     = 0;
        return;
    }
    /* 未確認データがあるなら RTO の担当。 */
    if (tcp_seq_gt(cn->snd_seq, priv->snd_una)) return;

    uint32_t wait_ms = (priv->ka_probes == 0) ? g_tcp_keepalive_idle_ms
                                              : g_tcp_keepalive_intvl_ms;
    if (now - priv->ka_idle_since < (uint64_t)wait_ms * 1000000u) return;

    if (priv->ka_probes >= g_tcp_keepalive_probes) {
        g_tcp_keepalive_drop_count++;
        tcp_abort_conn(cn, priv, "keepalive の応答が無い");
        return;
    }

    /* probe は「**1 バイト過去の seq を持つ 0 バイトのセグメント**」。
     * 相手は既に受け取った範囲なので、必ず ACK を返す(RFC 1122)。 */
    uint32_t saved = cn->snd_seq;
    cn->snd_seq = saved - 1u;
    tcp_send_segment(cn, priv, TCP_FLAG_ACK, NULL, 0);
    cn->snd_seq = saved;

    priv->ka_probes++;
    priv->ka_idle_since = now;
    g_tcp_keepalive_probe_count++;
}

/* TS.Recent を無効とみなすまでの時間(RFC 7323 5.5 の 24 日)。 */
#define TCP_TS_RECENT_LIFE_NS (24ull * 24u * 3600u * 1000000000ull)

/*=================================================================
 * 接続ごとの、時間で動く冷たい検査(ポーリング 256 回に 1 回、時刻は 1 回だけ読む)。
 *   - 返していない ACK の時間の上限(TCP_DELACK_MAX_MS、MUST-40)。普段は受信の周回数
 *     (ackhold)で返るので、ここに来るのは周回が止まりがちなときか ackhold 0 のときだけ。
 *   - 別のコアで受けた ICMP の HARD(握手の途中なら畳む)
 *   - TS.Recent の 24 日(動かなければ PAWS で 1 回素通しする印を立てる)
 *   - Keepalive(ka_enabled の接続だけ)
 *
 * 引数:
 *   core - 対象コア(自分のコネクションスロットだけ見る)
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
static void tcp_cold_check(unsigned core, uint64_t now)
{
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        tcp_conn_t *cn = s_conns[core][i];
        if (cn == NULL) continue;
        tcp_priv_t *priv = &s_priv[core][i];

        if (priv->icmp_hard) {
            tcp_icmp_hard_close(cn, priv);
            if (s_conns[core][i] != cn) continue;
        }

        /* 「受け取った所(rcv_seq)まで ACK していない」状態が、ACK を 1 つも送らないまま続いたか。
         * 間引きで 4 セグメントごとに返している間は last_ack_sent が動くので測り直しになり、
         * 余計な ACK は出さない。 */
        if (priv->rcv_wnd_valid && cn->rcv_seq != priv->last_ack_sent &&
            (cn->state == TCP_ESTABLISHED || cn->state == TCP_FIN_WAIT_1 || cn->state == TCP_FIN_WAIT_2)) {
            if (priv->ack_owed_since == 0u || priv->ack_owed_mark != priv->last_ack_sent) {
                priv->ack_owed_since = now;
                priv->ack_owed_mark  = priv->last_ack_sent;
            } else if (now - priv->ack_owed_since >= (uint64_t)TCP_DELACK_MAX_MS * 1000000u) {
                g_tcp_ack_time_flush++;
                tcp_send_segment(cn, priv, TCP_FLAG_ACK, NULL, 0);
                priv->ack_owed_since = 0;
            }
        } else {
            priv->ack_owed_since = 0;
        }

        if (priv->ts_enabled) {
            if (priv->ts_recent != priv->ts_recent_snap || priv->ts_recent_snap_at == 0u) {
                priv->ts_recent_snap    = priv->ts_recent;
                priv->ts_recent_snap_at = now;
                priv->ts_recent_stale   = 0;
            } else if (now - priv->ts_recent_snap_at >= TCP_TS_RECENT_LIFE_NS) {
                priv->ts_recent_stale = 1;
            }
        }

        if (priv->ka_enabled && cn->state == TCP_ESTABLISHED) tcp_keepalive_one(cn, priv, now);
    }
}

/* コアごとのポーリング回数(RACK / TLP の時刻の確認と、冷たい検査を間引く)。1 コア 1 キャッシュライン。 */
static struct { unsigned v; } __attribute__((aligned(64))) s_rack_tick[SMP_MAX_CORES];

static void tcp_poll_once_ex(int check_ctrl_c)
{
    unsigned core = smp_core_index();

    /* Ctrl-C を見るのはシェルのコア(core0)だけ。ほかのコアのジョブ(ターゲットの送信窓待ちなど)が
     * ここを通ると、1 回ごとに標準入力の read(システムコール)を払い、しかもシェルへ送った
     * コマンドの文字を読んで捨てていた(1 コアの iSCSI の読み出しで core1 の約 3 割。SPEC 27.14)。 */
    if (check_ctrl_c && core == 0u && uart_check_ctrl_c()) {
        s_abort_requested = 1;
    }

    net_poll_all_and_dispatch();

    /* RACK の入れ替わりの窓と TLP の PTO(どちらも ms 前後)は 64 回に 1 回だけ時刻で見る。 */
    const unsigned tick = ++s_rack_tick[core].v;
    const int rack_timed = ((tick & 63u) == 0u);
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        /* **各段の後で表を見直す。** 再送の上限で諦めると(tcp_abort_conn())その場で表から
         * 外れるので、外れた接続を次の段へ渡さない。 */
        tcp_conn_t *c = s_conns[core][i];
        if (c == NULL) continue;
        tcp_async_poll(c, &s_priv[core][i]);
        if (s_conns[core][i] != c) continue;
        tcp_async_short_poll(c, &s_priv[core][i]);
        if (s_conns[core][i] != c) continue;
        tcp_rack_tlp_poll(c, &s_priv[core][i], rack_timed);
    }

    /* TIME_WAIT の掃除・待ち行列の掃除・時間で動く接続ごとの検査は、秒〜時間単位の話なので
     * ポーリング 1 回ごとに走査する必要はない(この関数は受信ポーリングのたびに通る)。
     * 時刻の読み出しもこの中に閉じ込める。**以前は TIME_WAIT の掃除だけ毎回、全コアが
     * 同じロックを取って表を舐めていた。** 数えるのはコアごと(以前は全コア共有の数で、
     * どのコアが掃除するかが偶然で決まっていた)。 */
    if ((tick & 0xFFu) == 0u) {
        const uint64_t now = timer_now();
        tcp_timewait_reap(now);
        tcp_backlog_reap();
        tcp_cold_check(core, now);
        tcp_ooo_sweep(core);
    }
}

/*=================================================================
 * tcp_poll_once_ex(1) の薄いラッパ(Ctrl+C 検出あり)。あらゆる長時間
 * ブロックする待ちループがここを経由する。
 *
 * コール元:
 *   tcp_send(), tcp_close(), tcp_send_async_ex(),
 *   tcp_async_flush_until_room()
 * ===============================================================*/
static void tcp_poll_once(void)
{
    tcp_poll_once_ex(1);
}

/*=================================================================
 * 冷たい経路のポーリングを 1 回だけ回す(受信の取り込み、非同期送信の
 * 再送、TIME_WAIT の掃除、待ち行列の回収、Keepalive の期限確認)。
 * UART には触らない。
 *
 * `net_poll_all_and_dispatch()` だけでは**時間で動く処理が進まない**ので、
 * 「何もせず待つ」テストはこちらを回す必要がある。
 *
 * コール元:
 *   shell_keepalivetest()
 * ===============================================================*/
void tcp_poll(void)
{
    tcp_poll_once_ex(0);
}

/*=================================================================
 * セグメントを送信し、priv->expected_ack に一致する ACK が返るまで RTO の
 * 指数バックオフで再送する(FIN のような制御セグメント用)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   flags       - TCP フラグ
 *   data / len  - ペイロード(制御セグメントなら NULL/0)
 * 戻り値:
 *   0=ACK を得た、-1=再送上限に達した
 * コール元:
 *   tcp_close()
 * ===============================================================*/
static int tcp_send_reliable(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags,
                              const void *data, uint16_t data_len,
                              uint32_t expected_ack)
{
    priv->expected_ack = expected_ack;
    priv->ack_received = 0;

    uint32_t rto_ms = priv->rto_ms;
    const uint32_t seq0 = conn->snd_seq;
    for (int attempt = 0; attempt <= TCP_MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            g_tcp_retransmit_count[smp_core_index()]++;
            uart_printf("[TCP] 再送 (%d/%d, RTO=%ums)\n", attempt, TCP_MAX_RETRIES, rto_ms);
        }
        uint64_t sent_at = timer_now();
        conn->snd_seq = seq0;
        int rc = tcp_send_segment(conn, priv, flags, data, data_len);
        /* 待っている間に送る純 ACK(同時クローズで相手の FIN に返す ACK など)は SEQ=SND.NXT
         * (= FIN の次)で出す(RFC 9293 3.10.7.4)。FIN の seq のままだと、相手はこちらの FIN を
         * 受け取った後なので窓の外として捨てる。 */
        conn->snd_seq = expected_ack;
        if (rc != 0) {
            return -1;  /* 送信自体の失敗(ARP解決失敗等)は再送しても無駄 */
        }

        do {
            tcp_poll_once();
            if (tcp_abort_requested()) {
                return -1;  /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照) */
            }
            if (priv->ack_received) {
                if (attempt == 0) {
                    { const uint64_t t = timer_now(); tcp_rtt_update(priv, t - sent_at, t); }
                }
                return 0;
            }
            if (conn->state == TCP_TIME_WAIT) {
                return 0;
            }
            if (conn->state == TCP_CLOSED) {
                return -1;  /* RST等でコネクションが失われた */
            }
        } while (!timeout_ms(sent_at, rto_ms));

        rto_ms *= 2;
        if (rto_ms > TCP_MAX_RTO_MS) rto_ms = TCP_MAX_RTO_MS;
    }

    uart_printf("[!] TCP: 再送上限到達、ACK確認できず\n");
    return -1;
}

/*=================================================================
 * 受信した SYN / SYN-ACK のオプション領域から MSS と Window Scale を
 * 取り出してコネクションへ反映する。MSS は自分の上限との小さい方を採る。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   opts        - オプション領域の先頭
 *   opts_len    - そのバイト数
 * コール元:
 *   tcp_input()
 * ===============================================================*/
static void tcp_parse_syn_options(tcp_conn_t *conn, tcp_priv_t *priv,
                                   const volatile uint8_t *opts, uint8_t opts_len)
{
    uint8_t i = 0;
    while (i < opts_len) {
        uint8_t kind = opts[i];
        if (kind == TCP_OPT_KIND_END) {
            break;
        }
        if (kind == TCP_OPT_KIND_NOP) {
            i++;
            continue;
        }
        if ((uint8_t)(i + 1) >= opts_len) {
            break;  /* 長さバイトが読めない、壊れたオプション列 */
        }
        uint8_t opt_len = opts[i + 1];
        if (opt_len < 2 || (uint8_t)(i + opt_len) > opts_len) {
            break;  /* 不正な長さ */
        }
        if (kind == TCP_OPT_KIND_MSS && opt_len == 4) {
            uint16_t peer_mss = rd16be(opts + i + 2);
            uint16_t local_cap = tcp_mss_cap_for((const netaddr_t *)&conn->remote_ip);
            if (peer_mss > local_cap) peer_mss = local_cap;
            /* **下限で抑える**(0 や極端に小さい値を信じると、MSS で割る所が 0 除算になり、
             * 送信が事実上止まる。TCP_MSS_MIN の説明)。 */
            if (peer_mss < TCP_MSS_MIN) peer_mss = TCP_MSS_MIN;
            conn->snd_mss = peer_mss;
            uart_printf("[TCP] 相手のMSSオプション受信: %u (採用値=%u)\n",
                        rd16be(opts + i + 2), conn->snd_mss);
        } else if (kind == TCP_OPT_KIND_WSCALE && opt_len == 3) {
            uint8_t peer_shift = opts[i + 2];
            if (peer_shift > 14u) peer_shift = 14u;
            priv->wscale_enabled = 1;
            priv->snd_wscale = peer_shift;
            uart_printf("[TCP] 相手のWindow Scaleオプション受信: shift=%u\n", peer_shift);
        } else if (kind == TCP_OPT_KIND_SACK_PERM && opt_len == 2 && g_tcp_sack_enable) {
            /* 相手が出してきたときだけ有効になる(SYN|ACK を組むのはこの後)。 */
            priv->sack_enabled = 1;
            uart_printf("[TCP] 相手のSACK-Permittedオプション受信\n");
        } else if (kind == TCP_OPT_KIND_TS && opt_len == 10 && g_tcp_ts_enable) {
            /* 相手が出してきたときだけ有効になる(SYN|ACK を組むのはこの後
             * なので、受動 open でもここで決まった値がそのまま使われる)。 */
            priv->ts_enabled = 1;
            priv->ts_recent  = rd32be(opts + i + 2);  /* 相手の TSval を echo 用に保持 */
            uart_printf("[TCP] 相手のTimestampsオプション受信: TSval=%u\n",
                        (unsigned)priv->ts_recent);
        }
        i = (uint8_t)(i + opt_len);
    }

    /* **Timestamps を使うぶんペイロードが 12 バイト減る。** MSS オプションの
     * 値は「ペイロードの上限」なので、自分が載せるオプションのぶんは送信側で
     * 引く(RFC 6691)。引き忘れるとフルサイズのセグメントだけがリンク MTU を
     * 超えて NIC に無言で捨てられる -- IPv6 対応のときと同じ形の不具合になる。
     * オプションの並び順に依存しないよう、走査を終えてから引く。 */
    if (priv->ts_enabled && conn->snd_mss > TCP_TS_OPT_LEN * 4u) {
        conn->snd_mss = (uint16_t)(conn->snd_mss - TCP_TS_OPT_LEN);
    }
    /* **IPsec(ESP)で包む相手には、ESP で増えるぶんも送信側で引く。** 相手が広告する
     * MSS は相手のリンク MTU だけから決まっていて、ESP の分を含まない(Linux も
     * 送る側で xfrm のヘッダ長を引く)。引かないとフルサイズのセグメントだけが
     * 相手の MTU を超えて落ちる。 */
    if (g_ipsec_npol && conn->remote_ip.family == NETADDR_V4 &&
        ipsec_policy_match(netaddr_v4_host((const netaddr_t *)&conn->remote_ip)) &&
        conn->snd_mss > IPSEC_ESP_OVERHEAD * 4u) {
        conn->snd_mss = (uint16_t)(conn->snd_mss - IPSEC_ESP_OVERHEAD);
    }
}

/*=================================================================
 * 確立済みコネクションのセグメントから Timestamps を取り出し、PAWS
 * (RFC 7323 5.3)の判定と TS.Recent の更新を行う。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   in          - TCP ヘッダ先頭
 *   hdr_len     - オプション込みの TCP ヘッダ長
 *   seq         - このセグメントの先頭 seq
 *   end_seq     - このセグメントの終わりの seq(seq + ペイロード長、FIN なら + 1)
 *   out_tsecr   - 相手が echo してきた自分の TSval(RTT 計測用)
 * 戻り値:
 *   1=処理を続けてよい、0=PAWS で破棄した、-1=Timestamps を合意したのに TS が無いので破棄した
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static int tcp_input_options(tcp_conn_t *conn, tcp_priv_t *priv,
                              const volatile uint8_t *in, uint8_t hdr_len,
                              uint32_t seq, uint32_t end_seq, uint32_t *out_tsecr)
{
    /* 相手が付けてこなかった。Timestamps を合意した接続なら捨てる(RFC 7323 3.2: TS を合意した後の
     * RST 以外のセグメントに TS が無ければ黙って捨てるべき)。RST はここより前で処理している。 */
    if (hdr_len <= TCP_HDR_LEN) return priv->ts_enabled ? -1 : 1;

    const volatile uint8_t *o = in + TCP_HDR_LEN;
    uint8_t olen = (uint8_t)(hdr_len - TCP_HDR_LEN);
    uint32_t tsval, tsecr;

    if (priv->ts_enabled && olen == TCP_TS_OPT_LEN &&
        o[0] == TCP_OPT_KIND_NOP && o[1] == TCP_OPT_KIND_NOP &&
        o[2] == TCP_OPT_KIND_TS  && o[3] == 10) {
        /* 定番の並び(NOP NOP TS)だけ。ロスが無ければ確立後はこれしか
         * 来ないので、走査せずに読む(SACK ブロックが付くのは穴があるときだけ)。 */
        tsval = rd32be(o + 4);
        tsecr = rd32be(o + 8);
    } else {
        uint8_t i = 0;
        int found = 0;
        tsval = 0; tsecr = 0;
        while (i < olen) {
            uint8_t kind = o[i];
            if (kind == TCP_OPT_KIND_END) break;
            if (kind == TCP_OPT_KIND_NOP) { i++; continue; }
            if ((uint8_t)(i + 1) >= olen) break;
            uint8_t l = o[i + 1];
            if (l < 2 || (uint8_t)(i + l) > olen) break;
            if (kind == TCP_OPT_KIND_TS && l == 10 && priv->ts_enabled) {
                tsval = rd32be(o + i + 2);
                tsecr = rd32be(o + i + 6);
                found = 1;
            } else if (kind == TCP_OPT_KIND_SACK && priv->sack_enabled &&
                       l >= 10 && ((l - 2u) % 8u) == 0u) {
                /* 相手が「届いた」と言ってきた範囲。高速再送のときに
                 * ここに入っている範囲は送り直さない。 */
                unsigned n = (unsigned)(l - 2u) / 8u;
                if (n > TCP_SACK_MAX_BLOCKS) n = TCP_SACK_MAX_BLOCKS;
                g_tcp_sack_rx_count++;
                /* 累積 ACK より前のブロック(相手の DSACK)は scoreboard に入れない。送り直しの判定に使わない
                 * 範囲で、3 つしかない枠を 1 つ埋めてしまうため。 */
                uint32_t seg_ack = rd32be(in + TCP_OFF_ACK);
                unsigned k = 0;
                for (unsigned b = 0; b < n; b++) {
                    uint32_t bs = rd32be(o + i + 2 + 8u * b);
                    uint32_t be = rd32be(o + i + 6 + 8u * b);
                    if (b == 0u) {
                        /* 先頭のブロックが DSACK か(RFC 2883: 累積 ACK より前か、2 つ目のブロックの中)。 */
                        int dsack = !tcp_seq_gt(be, seg_ack);
                        if (!dsack && n > 1u) {
                            uint32_t b1s = rd32be(o + i + 10);
                            uint32_t b1e = rd32be(o + i + 14);
                            dsack = !tcp_seq_lt(bs, b1s) && !tcp_seq_gt(be, b1e);
                        }
                        if (dsack) { tcp_on_dsack_rx(conn, priv, bs, be); continue; }
                    }
                    if (!tcp_seq_gt(be, seg_ack)) continue;
                    priv->sack_rx[k].start = bs;
                    priv->sack_rx[k].end   = be;
                    k++;
                }
                priv->sack_rx_count = (uint8_t)k;
                priv->sack_gen++;
            }
            i = (uint8_t)(i + l);
        }
        /* Timestamps が無効(SACK だけ合意)ならここで終わり。合意したのに付いていない
         * ときは捨てる(RFC 7323 3.2、上と同じ)。PAWS は Timestamps があってこそ。 */
        if (!found) return priv->ts_enabled ? -1 : 1;
    }

    /* R1: TSval が TS.Recent より古ければ「一周した古いセグメント」。
     * ACK を返して破棄する(相手にこちらの状態を伝えるため)。
     * **TS.Recent が 24 日動いていなければ無効とみなして通す**(RFC 7323 5.5。相手の時計が
     * 一周しても長く黙っていた接続を、PAWS で永久に締め出さない)。印は冷たい経路が立てる
     * (tcp_cold_check())ので、ここで見るのは捨てる側の枝の旗 1 つだけ。 */
    if ((int32_t)(tsval - priv->ts_recent) < 0) {
        if (priv->ts_recent_stale) {
            priv->ts_recent_stale = 0;
            priv->ts_recent = tsval;
        } else {
            g_tcp_paws_drop_count++;
            /* データも FIN も運ばないものへの ACK は頻度に上限(RFC 5961 7。Linux も PAWS の
             * ACK を tcp_oow_rate_limited() で絞る)。 */
            (void)tcp_send_oow_ack(conn, priv, end_seq == seq, 0);
            return 0;
        }
    }

    /* R3: ACK 済みの範囲に続くセグメントのときだけ TS.Recent を進める
     * (順序不正のセグメントで進めると、後から届く正しいものを弾いてしまう)。
     *
     * **範囲全体が受け取り済みの古いセグメントでは進めない**(seq <= Last.ACK.sent <= end_seq。
     * Linux の tcp_sequence() + tcp_replace_ts_recent() と同じ)。以前は seq だけを見ていたので、
     * 相手の無駄な再送(新しい TSval が付く)で TS.Recent が進み、その再送より前に送られて遅れて届く
     * **新しいデータ**(古い TSval)を R1 で捨てていた。相手から見ると新たな穴で、再送の時間切れ
     * (200 ms)まで待つことになる(256KiB の書き込みで 15 秒に 55〜321 回。SPEC 27.11.2)。 */
    if (!tcp_seq_lt(priv->ts_last_ack_sent, seq) && !tcp_seq_lt(end_seq, priv->ts_last_ack_sent)) {
        priv->ts_recent = tsval;
    }

    *out_tsecr = tsecr;
    return 1;
}

typedef tcp_async_slot_t tcp_async_mlx5_extra_t[TCP_ASYNC_SLOTS_MLX5_EXTRA];
static tcp_async_mlx5_extra_t s_async_mlx5_overflow[SMP_MAX_CORES][TCP_ASYNC_MLX5_OVERFLOW_CONNS];
static uint8_t s_async_mlx5_overflow_used[SMP_MAX_CORES][TCP_ASYNC_MLX5_OVERFLOW_CONNS];

/*=================================================================
 * このコネクションが借りていた非同期送信のオーバーフロースロット群を
 * 共有プールへ返す。
 *
 * 引数:
 *   core - 対象コア
 *   idx  - 返すプールブロックの番号
 * コール元:
 *   tcp_priv_init()
 * ===============================================================*/
static void tcp_async_overflow_release(unsigned core, int idx)
{
    if (idx >= 0 && (unsigned)idx < TCP_ASYNC_MLX5_OVERFLOW_CONNS) {
        s_async_mlx5_overflow_used[core][idx] = 0u;
    }
}

/*=================================================================
 * 共有プールから非同期送信のオーバーフロースロット群を 1 ブロック借りる。
 *
 * 引数:
 *   core - 対象コア
 * 戻り値:
 *   ブロック番号。空きが無ければ -1
 * コール元:
 *   tcp_priv_try_grant_mlx5_async_overflow()
 * ===============================================================*/
static int tcp_async_overflow_acquire(unsigned core)
{
    for (unsigned i = 0; i < TCP_ASYNC_MLX5_OVERFLOW_CONNS; i++) {
        if (!s_async_mlx5_overflow_used[core][i]) {
            s_async_mlx5_overflow_used[core][i] = 1u;
            return (int)i;
        }
    }
    return -1;  /* プール枯渇 -- 呼び出し元はTCP_ASYNC_SLOTS基礎値のままフォールバックする */
}

/*=================================================================
 * 論理スロット番号から実際の非同期送信スロットを引く(前半は priv 自身の
 * 配列、後半は借りたオーバーフロープール)。
 *
 * 引数:
 *   priv        - コネクションのプライベート状態
 *   core        - 対象コア
 *   logical_idx - 論理スロット番号(0..priv->async_cap-1)
 * 戻り値:
 *   スロットへのポインタ
 * コール元:
 *   tcp_async_poll(), tcp_send_async_enqueue(), tcp_debug_dump_rx()
 * ===============================================================*/
static tcp_async_slot_t *tcp_async_slot_at(tcp_priv_t *priv, unsigned core, unsigned logical_idx)
{
    if (logical_idx < TCP_ASYNC_SLOTS) {
        return &priv->async_slots[logical_idx];
    }
    unsigned extra_idx = logical_idx - TCP_ASYNC_SLOTS;
    if (priv->async_overflow_idx >= 0 && extra_idx < TCP_ASYNC_SLOTS_MLX5_EXTRA) {
        return &s_async_mlx5_overflow[core][priv->async_overflow_idx][extra_idx];
    }
    return NULL;  /* async_cap管理が正しければ到達しないはず */
}

/*=================================================================
 * 送信元インターフェースが mlx5 なら、非同期送信スロットを共有プールから
 * 増やして深いパイプラインを許可する(帯域が広く in-flight を稼ぐ必要が
 * あるバックエンドだけを対象にする)。
 *
 * 引数:
 *   priv     - コネクションのプライベート状態
 *   core     - 対象コア
 *   local_ip - 自機アドレス(インターフェース判定に使う)
 * コール元:
 *   tcp_connect_begin_addr(), tcp_input_addr()
 * ===============================================================*/
static void tcp_priv_try_grant_mlx5_async_overflow(tcp_priv_t *priv, unsigned core,
                                                    const netaddr_t *local_ip)
{
    netif_t *ctx = tcp_netif_for(local_ip);
    if (!ctx || !ctx->hw_csum_offload) {
        return;  /* RP1、または未解決 -- TCP_ASYNC_SLOTSのまま */
    }
    int idx = tcp_async_overflow_acquire(core);
    if (idx >= 0) {
        priv->async_overflow_idx = idx;
        priv->async_cap = TCP_ASYNC_SLOTS + TCP_ASYNC_SLOTS_MLX5_EXTRA;
    }
}

/*=================================================================
 * コネクションのプライベート状態を初期値へ戻す(能動 open と受動 open の
 * 両方から呼ぶ)。借りていたオーバーフロースロットもここで返す。
 *
 * 引数:
 *   priv - 初期化する状態
 *   core - 対象コア
 * コール元:
 *   tcp_connect_begin(), tcp_input()
 * ===============================================================*/
static void tcp_priv_init(tcp_priv_t *priv, unsigned core)
{
    if (priv->async_overflow_ever_init) {
        tcp_async_overflow_release(core, priv->async_overflow_idx);
    }
    priv->async_overflow_ever_init = 1u;
    priv->async_overflow_idx = -1;
    priv->async_cap = TCP_ASYNC_SLOTS;

    priv->ack_received  = 0;
    priv->expected_ack  = 0;
    priv->snd_una       = 0;
    priv->ack_advanced  = 0;
    priv->srtt_us       = 0;
    priv->rttvar_us     = 0;
    priv->rto_ms        = TCP_INITIAL_RTO_MS;
    priv->cwnd          = 0;
    priv->ssthresh      = 0xFFFFFFFFu;
    priv->dup_ack_count       = 0;
    priv->recover             = 0;
    priv->dup_ack_suppress    = 0;
    priv->fr_last_at          = 0;
    priv->in_fast_recovery    = 0;
    priv->fast_retransmit_gen = 0;
    priv->fr_gen_bulk         = 0;
    priv->fr_gen_async        = 0;
    priv->fr_gen_short        = 0;
    priv->rx_read       = 0;
    priv->rx_count      = 0;
    priv->fin_received  = 0;
    priv->recv_upcall     = NULL;
    priv->recv_upcall_ctx = NULL;
    priv->wscale_enabled = 0;
    priv->snd_wscale     = 0;
    priv->rcv_wscale     = g_tcp_rcv_wscale;
    priv->snd_win_max    = 0;
    priv->ts_enabled       = 0;
    priv->ts_recent        = 0;
    priv->ts_last_ack_sent = 0;
    priv->ts_last_sent     = 0;
    priv->sack_enabled     = 0;
    priv->sack_rx_count    = 0;
    priv->sack_tx_count    = 0;
    priv->sack_tx_recent   = 0;
    priv->dsack_valid      = 0;
    priv->sack_gen         = 0;
    priv->sack_gen_seen    = 0;
    priv->rack_xmit_at     = 0;
    priv->rack_end_seq     = 0;
    priv->rack_rtt_ns      = 0;
    priv->rack_rtt_last_ns = 0;
    priv->rack_mm_valid    = 0;
    priv->undo_log_n       = 0;
    priv->undo_log_over    = 0;
    priv->prr_active       = 0;
    priv->prr_delivered    = 0;
    priv->prr_out          = 0;
    priv->prr_recover_fs   = 0;
    priv->rack_fack        = 0;
    priv->rack_fack_valid  = 0;
    priv->rack_reord_seen  = 0;
    priv->rack_reo_mult    = 1;
    priv->rack_reo_persist = 0;
    priv->rack_dirty       = 0;
    priv->rack_dsack_round_valid = 0;
    priv->rack_dsack_round = 0;
    priv->rack_timer_at    = 0;
    priv->tlp_tx_at        = 0;
    priv->tlp_ack_at       = 0;
    priv->tlp_active       = 0;
    priv->tlp_dsack        = 0;
    priv->tlp_high_seq     = 0;
    priv->tlp_probe_seq    = 0;
    priv->undo_valid       = 0;
    priv->undo_ts_ok       = 0;
    priv->retx_ts          = 0;
    priv->retx_end         = 0;
    priv->undo_ended       = 0;
    priv->undo_retrans     = 0;
    priv->rx_segs          = 0;
    priv->ka_rx_snap       = 0;
    priv->ka_enabled       = g_tcp_keepalive_enable ? 1u : 0u;   /* 張ったときの既定(MUST-24/25)*/
    priv->ka_idle_since    = 0;
    priv->ka_probes        = 0;
    priv->snd_max          = 0;
    priv->snd_wl1          = 0;
    priv->snd_wl2          = 0;
    priv->rcv_wnd_edge     = 0;
    priv->rcv_wnd_valid    = 0;
    priv->fin_pend         = 0;
    priv->fin_pend_seq     = 0;
    priv->urg_valid        = 0;
    priv->rcv_up           = 0;
    priv->oow_last_at      = 0;
    priv->rto_since        = 0;
    priv->connect_start    = 0;
    priv->icmp_hard        = 0;
    priv->icmp_soft_err    = 0;
    priv->ts_recent_snap   = 0;
    priv->ts_recent_snap_at = 0;
    priv->ts_recent_stale  = 0;
    priv->ack_owed_since   = 0;
    priv->ack_owed_mark    = 0;
    priv->zwp_interval_ms  = 0;
    tcp_ooo_release_all(priv);
    priv->ooo_head         = TCP_OOO_NONE;
    priv->ooo_bytes        = 0;
    priv->ooo_count        = 0;
    priv->unacked_full_segments = 0;
    priv->unacked_consumed_bytes = 0;
    priv->ack_deferred = 0;
    priv->ack_hold_thin = 0;
    priv->ack_thin_off  = 0;
    priv->thin_n = 0;
    priv->thin_exp = 0;
    priv->ack_piggy_ok = 0;   /* 前にこの枠を使った接続の設定を持ち越さない */
    priv->last_ack_sent = 0;
    priv->last_win_sent = 0;
    priv->async_head  = 0;
    priv->async_count = 0;
    priv->async_short_head  = 0;
    priv->async_short_count = 0;
    priv->lost_bytes = 0;
    priv->in_bulk_send = 0;
    priv->connect_attempt = 0;
    priv->connect_rto_ms  = TCP_INITIAL_RTO_MS;
    priv->connect_sent_at = 0;
}

/*=================================================================
 * RFC5681 の初期ウィンドウ IW = min(4*MSS, max(2*MSS, 4380)) で cwnd と
 * ssthresh を設定する(MSS が確定した時点で呼ぶ)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_connect_poll(), tcp_input()
 * ===============================================================*/
static void tcp_cwnd_init(tcp_conn_t *conn, tcp_priv_t *priv)
{
    uint32_t four_mss  = 4u * conn->snd_mss;
    uint32_t two_mss   = 2u * conn->snd_mss;
    uint32_t floor_val = (two_mss > 4380u) ? two_mss : 4380u;
    priv->cwnd = (four_mss < floor_val) ? four_mss : floor_val;
    priv->ssthresh = 0xFFFFFFFFu;  /* 初回はロスがあるまで実質無制限(スロースタート主導) */
    /* **recover は「まだ何も回復していない」= 今のシーケンス番号で初期化する。**
     * 0 のままにすると、ISN が 2^31 以上のときに
     * `tcp_seq_lt(snd_una, recover)` が真になり(符号付き差分で判定するため)、
     * recover ガードが**そのコネクションの高速再送を永久に止める**。
     * ISN は timer_now() の下位 32bit なので**約半分のコネクションが該当する**。
     * 実測では 1292 個の重複 ACK が全部このガードで捨てられ、再送が
     * すべて RTO 由来になっていた。 */
    priv->recover = conn->snd_seq;
}

/*=================================================================
 * 能動 open を開始する。スロットを確保して SYN を送り、ブロックせずに返る
 * (完了確認は tcp_connect_poll())。
 *
 * 引数:
 *   conn     - 初期化するコネクション
 *   local_ip - 自分側のアドレス(family がそのままコネクションの family になる)
 *   dst      - 接続先アドレス
 *   dst_port - 接続先ポート
 * コール元:
 *   tcp_connect_begin(), tcp_connect_begin6()
 * ===============================================================*/
static void tcp_connect_begin_addr(tcp_conn_t *conn, const netaddr_t *local_ip,
                                    const netaddr_t *dst, uint16_t dst_port)
{
    unsigned core = smp_core_index();
    int slot = tcp_find_free_slot();
    if (slot < 0) {
        uart_printf("[!] TCP: 空きコネクションスロットが無い(最大%u本)\n", TCP_MAX_CONNS);
        conn->state = TCP_CLOSED;
        return;
    }
    tcp_priv_t *priv = &s_priv[core][slot];

    conn->state       = TCP_CLOSED;
    conn->local_ip    = *local_ip;
    conn->remote_ip   = *dst;
    conn->remote_port = dst_port;
    conn->snd_win     = 0;                     /* 相手の最初のACKで確定するまでは未知 */
    /* 相手が MSS オプションを付けなければこの既定値のまま(IPv4 536 / IPv6 1220、MUST-15)。 */
    conn->snd_mss     = (dst->family == NETADDR_V6) ? TCP_MSS_DEFAULT_V6 : TCP_MSS_DEFAULT_RFC879;
    conn->rcv_seq     = 0;

    /* 自分側のポート(RFC 6056)。**RSS で受信を散らしているときは、相手からの受信が自分のコアの
     * 受信キューに来るものを選ぶ。** TCP の接続は張ったコアの表(s_conns[core])にしか載らず、
     * 別のコアに届いた SYN|ACK は捨てられる(tcp_pick_port() が NIC と同じハッシュで確かめる)。 */
    const uint16_t lport = tcp_pick_port(core, local_ip, dst, dst_port);
    if (lport == 0u) {
        uart_printf("[!] TCP: 使える一時ポートが無い\n");
        conn->state = TCP_CLOSED;
        return;
    }
    conn->local_port = lport;
    /* ISN(RFC 6528)。ポートが決まってから 4-tuple で決める。 */
    uint32_t isn = tcp_isn_gen(local_ip, lport, dst, dst_port);
    conn->snd_seq   = isn;

    tcp_priv_init(priv, core);
    tcp_priv_try_grant_mlx5_async_overflow(priv, core, (const netaddr_t *)&conn->local_ip);

    conn->owner_core = core;
    s_conns[core][slot] = conn;

    if (dst->family == NETADDR_V6) {
        uart_printf("[TCP] connect: [IPv6]:%u へSYN送信 (local_port=%u, isn=%u, slot=%d)\n",
                    dst_port, conn->local_port, isn, slot);
    } else {
        uart_printf("[TCP] connect: %u.%u.%u.%u:%u へSYN送信 (local_port=%u, isn=%u, slot=%d)\n",
                    dst->a[0], dst->a[1], dst->a[2], dst->a[3],
                    dst_port, conn->local_port, isn, slot);
    }

    conn->state = TCP_SYN_SENT;
    priv->expected_ack    = isn + 1;
    priv->ack_received     = 0;
    priv->connect_attempt  = 0;
    priv->connect_rto_ms   = priv->rto_ms;  /* tcp_priv_init()直後はTCP_INITIAL_RTO_MS */
    priv->connect_sent_at  = timer_now();
    priv->connect_start    = priv->connect_sent_at;   /* SYN の R2(3 分)の起点 */

    if (tcp_send_segment(conn, priv, TCP_FLAG_SYN, NULL, 0) != 0) {
        uart_printf("[!] TCP: SYN送信失敗\n");
        conn->state = TCP_CLOSED;
        s_conns[core][slot] = NULL;
    }
}

/*=================================================================
 * 能動 open(IPv4)。自分側はアクティブなインターフェースの IPv4 を使う。
 *
 * 引数:
 *   conn / dst_ip / dst_port - コネクションと接続先
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
void tcp_connect_begin(tcp_conn_t *conn, uint32_t dst_ip, uint16_t dst_port)
{
    netaddr_t local = netaddr_v4(NET_SELF_IP);
    netaddr_t dst   = netaddr_v4(dst_ip);
    tcp_connect_begin_addr(conn, &local, &dst, dst_port);
}

/*=================================================================
 * 能動 open(IPv6)。自分側アドレスは宛先のスコープに合わせて選ぶ。
 *
 * **リンクローカル固定にしてはいけない。** グローバルアドレス宛の接続で
 * 送信元をリンクローカルにすると、相手はリンクローカル宛に返してくる。
 * 別名インターフェース(A1 の検証で使う、対向 PF と MAC を共有するもの)は
 * リンクローカルが対向 PF と同一なので、その応答をどちらのインターフェースの
 * ものか区別できず、近隣キャッシュが別名ではなく対向 PF 側に入って
 * 解決に失敗する。実機で `routetest` の IPv6 エンドツーエンドが
 * 「NA は届いているのに宛先MACの解決失敗」になる形で出た。
 *
 * 引数:
 *   conn / dst_ip / dst_port - コネクションと接続先(16 バイトアドレス)
 * コール元:
 *   shell_tcp6test(), tcp_connect_begin_to()
 * ===============================================================*/
void tcp_connect_begin6(tcp_conn_t *conn, const uint8_t dst_ip[16], uint16_t dst_port)
{
    uint8_t ll[16];
    ipv6_source_for(dst_ip, ll);
    netaddr_t local = netaddr_v6(ll);
    netaddr_t dst   = netaddr_v6(dst_ip);
    tcp_connect_begin_addr(conn, &local, &dst, dst_port);
}

/*=================================================================
 * family を問わない能動 open。自分側アドレスは dst の family に合わせて
 * アクティブなインターフェースから決める。
 *
 * 引数:
 *   conn / dst / dst_port - コネクションと接続先
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
void tcp_connect_begin_to(tcp_conn_t *conn, const netaddr_t *dst, uint16_t dst_port)
{
    if (dst->family == NETADDR_V6) {
        tcp_connect_begin6(conn, dst->a, dst_port);
    } else {
        tcp_connect_begin(conn, netaddr_v4_host(dst), dst_port);
    }
}

/*=================================================================
 * tcp_connect_begin() で始めた接続を 1 tick 分進める。SYN の RTO を自前で
 * 見て再送し、SYN-ACK 到着(tcp_input() が処理)で ESTABLISHED になる。
 *
 * 引数:
 *   conn - 対象コネクション
 * 戻り値:
 *   1=確立した、0=継続中、-1=再送上限に達した
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
int tcp_connect_poll(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        return -1;  /* tcp_connect_begin()を呼んでいない(呼び出し規約違反) */
    }

    if (tcp_abort_requested()) {
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    /* 別のコアで受けた ICMP の HARD(相手にその口が無い)。SYN を送り続けずにすぐ失敗させる
     * (RFC 1122 4.2.3.9 / RFC 5461)。 */
    if (priv->icmp_hard && conn->state == TCP_SYN_SENT) {
        tcp_icmp_hard_close(conn, priv);
        return -1;
    }

    if (priv->ack_received) {
        if (conn->state == TCP_ESTABLISHED) {
            if (priv->connect_attempt == 0) {
                { const uint64_t t = timer_now(); tcp_rtt_update(priv, t - priv->connect_sent_at, t); }
            } else if (priv->srtt_us == 0u && priv->rto_ms < 3000u) {
                /* SYN を送り直したのに RTT の標本が無い: データを送り始めるときの RTO を 3 秒にする
                 * (RFC 6298 5.7)。SYN が落ちる経路では初期 RTO が短すぎた可能性がある。
                 * Timestamps があれば最初の ACK で測り直される。 */
                priv->rto_ms = 3000u;
            }
            conn->snd_seq = priv->expected_ack;  /* SYNは1バイト分のシーケンス番号を消費する */
            /* **未確認の先頭もここで揃える。** 以前は最初の送信を同期の tcp_send() で
             * 送る前提で(NVMe/TCP の ICReq)、そこで初めて snd_una が入っていた。
             * 最初から非同期の短経路で送ると(iSCSI の Login、2026-10-10 に踏んだ)、
             * 未確認 = snd_seq - 0 が約 38 億に見えてウィンドウが空くのを永久に待つ。 */
            priv->snd_una = conn->snd_seq;
            tcp_cwnd_init(conn, priv);
            uart_printf("[TCP] connect: ESTABLISHED (peer MSS=%u, 初期cwnd=%u)\n",
                        conn->snd_mss, priv->cwnd);
            return 1;
        }
    }

    if (conn->state == TCP_CLOSED) {
        /* RST等でtcp_input()がstateを落としたケース。 */
        uart_printf("[!] TCP: connect失敗 (state=%d)\n", (int)conn->state);
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    if (!timeout_ms(priv->connect_sent_at, priv->connect_rto_ms)) {
        return 0;  /* まだ待つ */
    }

    /* RTOタイムアウト -- 再送するか、再送上限なら諦める。**上限は回数ではなく時間**
     * (RFC 1122 4.2.3.5 の MUST-23: SYN は 3 分以上送り直す)。以前は 5 回(RTO 倍々で約 15 秒)。
     * それより早く諦めたいアプリは自分の時間切れで止める(呼び出し側が tcp_connect_poll() を
     * 呼ぶのをやめて tcp_close() する)。 */
    priv->connect_attempt++;
    if (timeout_ms(priv->connect_start, TCP_R2_SYN_MS)) {
        uart_printf("[!] TCP: SYN送信/再送すべて失敗(%u 秒)\n", (unsigned)(TCP_R2_SYN_MS / 1000u));
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    g_tcp_retransmit_count[smp_core_index()]++;
    uart_printf("[TCP] SYN 再送 (%u 回目、上限 %u 秒, RTO=%ums)\n",
                priv->connect_attempt, (unsigned)(TCP_R2_SYN_MS / 1000u), priv->connect_rto_ms);
    priv->connect_rto_ms *= 2;
    if (priv->connect_rto_ms > TCP_MAX_RTO_MS) priv->connect_rto_ms = TCP_MAX_RTO_MS;
    priv->connect_sent_at = timer_now();

    if (tcp_send_segment(conn, priv, TCP_FLAG_SYN, NULL, 0) != 0) {
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }
    return 0;
}

/*=================================================================
 * ACK でウィンドウが進んだときの cwnd 成長(RFC5681 簡易版のスロースタート
 * と輻輳回避)。
 *
 * 引数:
 *   priv - コネクションのプライベート状態
 *   mss  - 現在の MSS
 * コール元:
 *   tcp_send(), tcp_async_poll()
 * ===============================================================*/
/*=================================================================
 * 受信バッファを読み出した後のウィンドウ更新 ACK。ACK 番号もウィンドウも
 * 前回広告した値と同じなら**送らない**。
 *
 * 相手に伝える新しい情報がゼロなので純粋な無駄、というだけでなく、
 * **相手から見ると重複 ACK そのものに見える**のが問題だった。この受信
 * ウィンドウは safe_window_cap で頭打ちされているため、バッファがどれだけ
 * 空こうがワイヤ上の値は動かない。つまり「ack 据え置き・データ無し・
 * ウィンドウ不変」となり、RFC 5681 の重複 ACK の定義に完全に一致してしまう。
 * 高速再送(C2)を入れた直後、**ロスが 1 つも無いのに重複 ACK を 419 万個
 * 検出し、高速再送が 10 万回空振りしていた**のはこれが原因。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_recv_internal()
 * ===============================================================*/
static void tcp_send_window_update(tcp_conn_t *conn, tcp_priv_t *priv)
{
    uint16_t win = tcp_wire_window(conn, priv, TCP_FLAG_ACK, NULL);
    if (conn->rcv_seq == priv->last_ack_sent && win == priv->last_win_sent) {
        return;  /* 前回と同じ -- 送っても情報が増えない */
    }
    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
}

static void tcp_cwnd_grow_on_ack(tcp_priv_t *priv, uint16_t mss)
{
    if (priv->in_fast_recovery) {
        /* Fast Recovery 中は cwnd を dup ACK ごとに膨らませる(tcp_on_dup_ack())。
         * 通常の成長を重ねると二重に増える。 */
        return;
    }
    /* **相手が広告した最大の受信窓の 2 倍で頭打ちにする。** 受信窓が送る量を抑えている間も ACK ごとに
     * 増やし続けると、長く流した接続で 32 ビットを一周して小さな値に戻る(負荷 40 秒で 39 億まで
     * 増えていた)。それ以上大きくしても受信窓が先に効くので意味が無い。 */
    const uint32_t cap = (priv->snd_win_max > (1u << 30)) ? 0x7FFFFFFFu : 2u * priv->snd_win_max;
    if (priv->cwnd >= cap && cap >= 4u * (uint32_t)mss) return;
    if (priv->cwnd < priv->ssthresh) {
        priv->cwnd += mss;
    } else {
        uint32_t inc = ((uint32_t)mss * mss) / priv->cwnd;
        if (inc == 0) inc = 1u;
        priv->cwnd += inc;
    }
}

/*=================================================================
 * 重複 ACK を 1 個数える。3 個目で高速再送(RFC 5681 の Fast Retransmit)を
 * 要求するフラグを立て、以後は Fast Recovery のウィンドウ膨張を行う。
 *
 * 実際の再送はここでは行わない。送信側の既存の再送経路(tcp_send() の
 * Go-Back-N ループ / tcp_async_poll() / tcp_async_short_poll())が
 * priv->fast_retransmit を拾って送る。受信ハンドラの中から送信ループを
 * 呼ぶと再入するため。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static void tcp_on_dup_ack(tcp_conn_t *conn, tcp_priv_t *priv)
{
    uint16_t mss = conn->snd_mss;

    g_tcp_dup_ack_count[smp_core_index()]++;

    /* **自分の Go-Back-N が生んだ重複 ACK を差し引く。これが無いと発散する。**
     * 高速再送は RTO 経路と同じ Go-Back-N で未確認ウィンドウ全体(K セグメント)を
     * 送り直す。その大半は相手が既に受け取っている分で、この受信側は
     * 「in-order で受理できなかったセグメント」に即座に ACK を返す規約なので、
     * **K 個送り直せばほぼ K 個の重複 ACK が返ってくる**。K >= 3 ならそれだけで
     * 次の高速再送の条件を満たしてしまい、再送 -> 重複 ACK -> 再送 の正の
     * フィードバックになる(実測で破棄 1318 個に対し再送 517527 回)。
     * 送り直したセグメント数を数えておき、その分の重複 ACK は損失の証拠として
     * 数えない。本当に穴が残っていれば相手はそれ以上の重複 ACK を出すので、
     * 検出は遅れるだけで失われない。 */
    if (priv->dup_ack_suppress > 0u) {
        priv->dup_ack_suppress--;
        priv->dup_ack_count = 0;
        g_tcp_dup_suppressed++;
        return;
    }

    if (priv->in_fast_recovery) {
        g_tcp_dup_in_recovery++;
        /* 追加の dup ACK = 1 セグメントがネットワークから抜けた証拠なので、
         * その分だけ送信を許す(RFC 5681 のウィンドウ膨張)。PRR のときは tcp_prr_on_ack() が決める。 */
        if (!priv->prr_active) priv->cwnd += mss;
        return;
    }

    /* **recover ガード(RFC 6582)。これが無いと発散する。**
     * 高速再送は RTO 経路と同じ Go-Back-N で未確認ウィンドウ全体を送り直す。
     * 送り直した中には相手が既に受け取っている分も含まれ、この受信側は
     * 「in-order で受理できなかったセグメント」に即座に ACK を返すので、
     * **再送 1 回につき大量の重複 ACK が返ってくる**。それをそのまま次の
     * 高速再送の根拠にすると、再送 -> 重複 ACK -> 再送 の正のフィードバックに
     * なる。実測では破棄 1331 個に対して再送 533935 回まで膨れた。
     * 直前の回復で送り直した範囲(recover)が ACK されきるまでは、重複 ACK が
     * 来ても新しい回復を始めない。 */
    if (tcp_seq_lt(priv->snd_una, priv->recover)) {
        priv->dup_ack_count = 0;
        g_tcp_dup_recover_guard++;
        return;
    }

    priv->dup_ack_count++;
    if (priv->dup_ack_count != TCP_DUP_ACK_THRESHOLD) {
        return;  /* 1〜2 個目は順序入れ替えかもしれないので何もしない */
    }
    g_tcp_dup_threshold_hit++;

    /* **RACK を使う接続では、重複 ACK の数では回復に入らない**(Linux の tcp_recovery の bit2 と
     * 同じ)。重複 ACK には SACK ブロックが載っているので、失われたかは RACK が時刻で決める。
     * 数で決めると、届く順番が 3 つ入れ替わっただけで無駄に送り直して cwnd を半分にする。 */
    if (tcp_rack_on(priv)) {
        priv->dup_ack_count = 0;
        g_tcp_rack_dup_skip++;
        return;
    }

    /* 高速再送は 1 RTT に 1 回まで。dup_ack_suppress で自分が生む重複 ACK を
     * 差し引いてもなお、見積もりの誤差(受信側は full-size セグメントを
     * g_tcp_ack_threshold 個に 1 回しか ACK しない等)で漏れた分が次の再送を
     * 呼ぶ。送り直したウィンドウの結果が返ってくるまでは、何度要求されても
     * 1 回しか送り直さない -- 標準的な TCP 実装の "at most once per RTT" と
     * 同じ考え方で、これを入れると再送回数が実測で 274542 -> 大幅に減る。 */
    uint64_t min_gap_us = priv->srtt_us ? priv->srtt_us : 200u;
    if (priv->fr_last_at != 0 && get_us_from(priv->fr_last_at) < min_gap_us) {
        priv->dup_ack_count = 0;
        g_tcp_dup_rate_limited++;
        return;
    }
    priv->fr_last_at = timer_now();

    tcp_enter_recovery(conn, priv);
    priv->fast_retransmit_gen++;

    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 10), tcp_conn_arg(conn, priv->snd_una));
}

/*=================================================================
 * 新しい ACK が届いたときの Fast Recovery の後始末。送り直した範囲
 * (recover)まで累積 ACK が進んだら回復を終え、cwnd を ssthresh へ落として
 * 通常の輻輳回避へ戻る。
 *
 * **partial ACK ごとに次のセグメントを再送する NewReno 本来の動作は入れて
 * いない。** 一度実装して撤回した -- このスタックの高速再送は 1 セグメントでは
 * なくウィンドウ全体の Go-Back-N なので、partial ACK のたびに再送を重ねると
 * 再送回数が爆発する(実測で破棄 71 個に対し再送 3184 回)。穴が 2 つ以上
 * あるときは、recover を追い越した後の次の 3 dup ACK か RTO が拾う。
 *
 * 引数:
 *   priv / ack - コネクションのプライベート状態と受信した ACK 番号
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static void tcp_on_new_ack(tcp_priv_t *priv, uint32_t ack)
{
    priv->dup_ack_count = 0;
    if (!priv->in_fast_recovery) return;
    if (tcp_seq_lt(ack, priv->recover)) {
        /* **partial ACK -- 回復の途中。** 穴が 2 つ以上あるか、送り直した
         * ものまで失われた場合、ここで次の穴を送り直さないと RTO 待ちになる。
         *
         * 段階 2 では「Go-Back-N と組むと再送が爆発する」ので入れなかったが、
         * SACK があるなら送り直すのは**本当に届いていない範囲だけ**なので
         * 安全。ただし 1 RTT に 1 回までに抑える(高速再送と同じ制限)。 */
        if (priv->sack_enabled && g_tcp_sack_use_tx && !tcp_rack_on(priv)) {
            uint64_t min_gap_us = priv->srtt_us ? priv->srtt_us : 200u;
            if (priv->fr_last_at == 0 || get_us_from(priv->fr_last_at) >= min_gap_us) {
                priv->fr_last_at = timer_now();
                priv->fast_retransmit_gen++;
                g_tcp_sack_partial_retx++;
            }
        }
        return;
    }

    priv->cwnd = priv->ssthresh;
    priv->in_fast_recovery = 0;
    priv->prr_active = 0;
    /* 入れ替わりの窓を広げたまま保つのは、DSACK の無い回復を 16 回終えるまで(RFC 8985 6.2)。
     * **数えるのは undo せずに終えた回復だけ。** 入るたびに数えると、入れ替わりで undo して
     * すぐ抜け、また入るのを繰り返すうちに 0 になり、窓が最小に戻って入れ替わりを損失と
     * 見続けた(5% を 1 ms 追い越させると 64KiB 読み出しが 160〜225 MiB/s、RACK 無しは 430)。 */
    if (priv->rack_reo_persist > 0u && --priv->rack_reo_persist == 0u) priv->rack_reo_mult = 1u;
}

/*=================================================================
 * データを送信し、全バイトが ACK されるまでブロックする。内側のバースト
 * ループで cwnd と相手の広告ウィンドウが許すだけ連続送信し(1 セグメント
 * ごとに tcp_poll_once() を呼んで受信を飢えさせない)、RTO で再送する。
 *
 * 引数:
 *   conn - 対象コネクション
 *   buf  - 送信データ
 *   len  - そのバイト数
 * 戻り値:
 *   送信できたバイト数。失敗/中断なら -1
 * コール元:
 *   nvme_tcp_send_cmd(), nvme_tcp_send_h2c_data_ex(), nvmet_tcp_send_c2h()
 * ===============================================================*/
int tcp_send(tcp_conn_t *conn, const void *buf, uint32_t len)
{
    if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
        uart_printf("[!] tcp_send: ESTABLISHED/CLOSE_WAITでない (state=%d)\n", (int)conn->state);
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_send: 未登録のconn(tcp_connect()を呼んでいない)\n");
        return -1;
    }

    const uint8_t *data = buf;

    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 0), tcp_conn_arg(conn, len));

    uint32_t base_seq = conn->snd_seq;
    uint32_t end_seq   = base_seq + len;
    uint32_t snd_nxt    = base_seq;   /* 次に新規送信するseq */

    priv->snd_una = base_seq;
    priv->ack_advanced = 0;
    /* 前の転送で誰にも回収されずに残った要求を持ち越さない(持ち越すと
     * 今回の先頭セグメントをいきなり無駄に送り直す)。 */
    priv->fr_gen_bulk = priv->fast_retransmit_gen;

    priv->in_bulk_send = 1;

    /* **全体の打ち切りは「相手から何も届かない時間」で測る**(RFC 1122 4.2.2.17 の MUST-37:
     * 相手が窓 0 の確認に応え続けている間は接続を切ってはいけない)。以前は送り始めてから
     * 30 秒で打ち切っていたので、相手が長く窓を閉じているだけで送信が失敗していた。
     * 相手が応えなくなってから R2(100 秒)で諦める(再送の上限と同じ値)。 */
    uint64_t last_rx_at = timer_now();
    uint32_t rx_snap    = priv->rx_segs;
    uint64_t rto_episode_at = 0;        /* RTO で送り直し始めた時刻(R2 の起点、進んだら 0)*/

    uint32_t last_logged_swin = 0xFFFFFFFFu;

    int      rto_active = 0;            /* 未確認データがあり再送タイマが有効か */
    uint64_t window_sent_at = 0;        /* 現在の未確認ウィンドウの先頭を送った時刻(RTT計測用) */
    uint32_t rto_ms = priv->rto_ms;
    int      window_retransmitted = 0;  /* 現在の未確認ウィンドウ内で再送が起きたか(Karnのアルゴリズム) */
    int      retransmit_attempts = 0;   /* 連続再送回数(進捗があるたびリセット) */
    uint64_t zwp_since = 0;             /* 相手の窓が 0 になってからの時刻(持続タイマ) */

    while (tcp_seq_lt(priv->snd_una, end_seq)) {
        if (priv->rx_segs != rx_snap) {
            rx_snap    = priv->rx_segs;
            last_rx_at = timer_now();
        } else if (timeout_ms(last_rx_at, TCP_R2_DATA_MS)) {
            uart_printf("[!] TCP: tcp_send 相手から %u 秒何も届かない (%u/%u バイト送信済み)\n",
                        (unsigned)(TCP_R2_DATA_MS / 1000u), (unsigned)(priv->snd_una - base_seq), len);
            g_tcp_retx_abort++;
            tcp_abort_conn(conn, priv, "相手の応答が無い(R2)");
            break;
        }
        if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
            uart_printf("[!] TCP: 送信中にESTABLISHED/CLOSE_WAITでなくなった (state=%d)\n",
                        (int)conn->state);
            break;
        }
        if (tcp_abort_requested()) {
            /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照)。 */
            uart_printf("[TCP] Ctrl+Cで送信を中断 (%u/%u バイト送信済み)\n",
                        (unsigned)(priv->snd_una - base_seq), len);
            break;
        }

        uint32_t usable_window = conn->snd_win;
        /* SACK 済みのぶんはもうネットワークに居ないので、輻輳ウィンドウとの
         * 比較からは外す(RFC 6675 の pipe)。相手の広告ウィンドウ側は
         * そのまま -- そのデータは相手の順序不正バッファを占めているため。 */
        uint32_t cwnd_window = priv->cwnd + tcp_cwnd_credit(priv);
        if (cwnd_window < usable_window) usable_window = cwnd_window;
        /* ウィンドウ 0 の間は送らない(下の送信ループに入らない)。窓が開いたかは
         * tcp_zero_window_probe() が確かめる。 */
        tcp_window_probe(conn, priv, &zwp_since, conn->snd_win == 0u);

        if (tcp_seq_lt(snd_nxt, end_seq) && !tcp_seq_lt(snd_nxt, priv->snd_una + usable_window)) {
            if (usable_window != last_logged_swin) {
                if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 1), tcp_conn_arg(conn, usable_window));
                last_logged_swin = usable_window;
            }
        }

        while (tcp_seq_lt(snd_nxt, end_seq) &&
               tcp_seq_lt(snd_nxt, priv->snd_una + usable_window)) {
            uint32_t remaining_in_window = (priv->snd_una + usable_window) - snd_nxt;
            uint32_t remaining_data = end_seq - snd_nxt;
            /* **送り手の SWS 回避**(RFC 1122 4.2.3.4 の MUST-38)。未確認のデータがあり、窓の空きが
             * MSS 未満で、しかも残りのデータより小さいときは送らずに ACK を待つ(小さなセグメントを
             * 刻んで送り続けない)。Linux の tcp_snd_wnd_test() と同じ形で、未確認が無いときや残りが
             * 全部入るときは待たない(qd=1 の小さい PDU の遅延を増やさない)。 */
            if (remaining_in_window < conn->snd_mss && remaining_in_window < remaining_data &&
                tcp_seq_gt(snd_nxt, priv->snd_una)) {
                break;
            }
            uint32_t chunk32 = (remaining_in_window < remaining_data) ? remaining_in_window : remaining_data;
            uint32_t lso_max = net_active_lso_max_bytes();
            if (lso_max > TCP_LSO_MAX_DATA_LEN) lso_max = TCP_LSO_MAX_DATA_LEN;
            uint32_t seg_cap = (lso_max > 0u) ? lso_max : conn->snd_mss;
            if (chunk32 > seg_cap) chunk32 = seg_cap;
            if (chunk32 == 0) break;
            uint16_t chunk = (uint16_t)chunk32; // TCP_LSO_MAX_DATA_LEN/snd_mssいずれもuint16_tへ安全に収まる

            conn->snd_seq = snd_nxt;  /* tcp_send_segment()/tcp_send_segment_lso()共通、conn->snd_seqをSEQフィールドに使う */
            int seg_send_rc = (lso_max > 0u && chunk32 > conn->snd_mss)
                ? tcp_send_segment_lso(conn, priv, data + (snd_nxt - base_seq), chunk32)
                : tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                    data + (snd_nxt - base_seq), chunk);
            if (seg_send_rc != 0) {
                break;
            }
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 2), tcp_conn_arg(conn, chunk));
            snd_nxt += chunk;
            /* **conn->snd_seq は SND.NXT に置いておく。** この間に送る純 ACK(受信への ACK や窓の確認の応答)は
             * SEQ=SND.NXT で出すべきもの(RFC 9293 3.10.7.4)で、以前は送った塊の先頭のままだった。相手は
             * RCV.NXT より前の seq の純 ACK を窓の外として捨てる(Linux も、今のこちらも)ので、ACK が届かない。 */
            conn->snd_seq = snd_nxt;

            if (!rto_active) {
                rto_active = 1;
                window_sent_at = timer_now();
                window_retransmitted = 0;
            }

            tcp_poll_once();
            if (tcp_abort_requested()) {
                break;
            }
        }

        tcp_poll_once();

        if (priv->ack_advanced) {
            priv->ack_advanced = 0;
            retransmit_attempts = 0;  /* 進捗があったので連続再送カウントをリセット */
            rto_episode_at = 0;

            /* Timestamps が有効なら RTT は受信側(TSecr)で測っているので、
             * ここで二重に更新しない(再送の有無に関わらず測れるぶん、
             * こちらの Karn 制約つきの推定より良い)。 */
            if (!window_retransmitted && !priv->ts_enabled) {
                { const uint64_t t = timer_now(); tcp_rtt_update(priv, t - window_sent_at, t); }
            }

            tcp_cwnd_grow_on_ack(priv, conn->snd_mss);

            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 3), tcp_conn_arg(conn, priv->cwnd));

            if (tcp_seq_lt(priv->snd_una, snd_nxt)) {
                rto_active = 1;
                window_sent_at = timer_now();
            } else {
                rto_active = 0;
            }
            rto_ms = priv->rto_ms;
        }

        if (priv->fr_gen_bulk != priv->fast_retransmit_gen) {
            /* 3 個の重複 ACK で tcp_on_dup_ack() が要求した高速再送。RTO を
             * 待たずに、RTO 経路と**同じ Go-Back-N** で未確認ウィンドウ全体を
             * 送り直す。cwnd/ssthresh は要求側で調整済みなのでここでは触らない。 */
            priv->fr_gen_bulk = priv->fast_retransmit_gen;
            if (tcp_seq_lt(priv->snd_una, snd_nxt)) {
                uint32_t resend_seq = priv->snd_una;
                uint32_t resent = 0;
                uint32_t fr_sack_high = tcp_sack_high(priv);
                if (g_tcp_sack_debug && priv->sack_enabled) {
                    uart_printf("[SACKDBG] bulk una=%u nxt=%u mss=%u blocks=%u",
                                priv->snd_una, snd_nxt, conn->snd_mss,
                                (unsigned)priv->sack_rx_count);
                    for (unsigned bi = 0; bi < priv->sack_rx_count; bi++) {
                        uart_printf(" [%u,%u)", priv->sack_rx[bi].start, priv->sack_rx[bi].end);
                    }
                    uart_printf("\n");
                    g_tcp_sack_debug--;
                }
                while (tcp_seq_lt(resend_seq, snd_nxt)) {
                    uint32_t remain = snd_nxt - resend_seq;
                    uint16_t rchunk = (uint16_t)((remain > conn->snd_mss) ? conn->snd_mss : remain);
                    /* **SACK ブロックより先はまだ飛行中**なので送り直さない
                     * (Go-Back-N との一番大きな違いはここ)。 */
                    if (fr_sack_high != 0u && !tcp_seq_lt(resend_seq, fr_sack_high)) {
                        g_tcp_sack_skipped_count++;
                        break;
                    }
                    /* 相手に届いていると分かっている範囲も飛ばす。 */
                    if (tcp_sack_covered(priv, resend_seq, rchunk)) {
                        g_tcp_sack_skipped_count++;
                        resend_seq += rchunk;
                        continue;
                    }
                    conn->snd_seq = resend_seq;
                    if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                          data + (resend_seq - base_seq), rchunk) != 0) {
                        break;
                    }
                    tcp_undo_note(priv, resend_seq, rchunk);
                    resend_seq += rchunk;
                    resent     += rchunk;
                    /* SACK があるときは自分の再送が重複 ACK を生まないので補正不要。 */
                    if (!priv->sack_enabled) priv->dup_ack_suppress++;
                    g_tcp_retransmit_segs++;
                }
                g_tcp_retransmit_count[smp_core_index()]++;
                g_tcp_fast_retransmit_count[smp_core_index()]++;
                if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 6), tcp_conn_arg(conn, resent));
                /* RTO タイマを張り直し、この往復では RTT を測らない(Karn)。 */
                conn->snd_seq = snd_nxt;   /* 送り直しの後は SND.NXT へ戻す(塊を送った後と同じ理由) */
                window_sent_at = timer_now();
                window_retransmitted = 1;
                rto_active = 1;
            }
        }

        if (rto_active && timeout_ms(window_sent_at, rto_ms)) {
            retransmit_attempts++;
            /* 再送の上限は回数ではなく時間(R2 = 100 秒、RFC 1122 4.2.3.5)。諦めたら seq を
             * 巻き戻さずに RST で閉じる(RFC 9293 3.8.3 の MUST-20、tcp_abort_conn())。 */
            if (rto_episode_at == 0u) {
                rto_episode_at = timer_now();
            } else if (timeout_ms(rto_episode_at, TCP_R2_DATA_MS)) {
                uart_printf("[!] TCP: 再送上限到達、送信を諦める (%u/%u バイト送信済み)\n",
                            (unsigned)(priv->snd_una - base_seq), len);
                g_tcp_retx_abort++;
                tcp_abort_conn(conn, priv, "再送の上限(R2)");
                break;
            }
            g_tcp_retransmit_count[smp_core_index()]++;
            uart_printf("[TCP] 送信ウィンドウ再送 (%d 回目, una=%u nxt=%u RTO=%ums)\n",
                        retransmit_attempts, priv->snd_una, snd_nxt, rto_ms);
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 4), tcp_conn_arg(conn, (uint32_t)retransmit_attempts));

            /* 回復中でなければ undo の準備(RTO が無駄だったと Timestamps / DSACK で分かれば戻す)。
             * 回復中なら、回復に入る前の値を控えたまま。 */
            if (!priv->in_fast_recovery && retransmit_attempts == 1) tcp_undo_arm(priv, snd_nxt);
            uint32_t flight = snd_nxt - priv->snd_una;
            uint32_t half = flight / 2u;
            priv->ssthresh = (half > 2u * conn->snd_mss) ? half : 2u * conn->snd_mss;
            priv->cwnd = conn->snd_mss;
            /* RTO はウィンドウ全体を失ったということなので、Fast Recovery は
             * 打ち切ってスロースタートからやり直す(RFC 5681)。 */
            priv->in_fast_recovery = 0;
            priv->prr_active       = 0;
            priv->dup_ack_count    = 0;
            priv->recover          = priv->snd_una;  /* recover ガードを解除 */
            priv->fr_gen_bulk      = priv->fast_retransmit_gen;
            /* **RTO では SACK の scoreboard を捨てる**(RFC 6675 5.1)。
             * 相手が保持を撤回した(reneging)可能性があるので、届いたと
             * 言われた範囲も含めて全部送り直す。 */
            priv->sack_rx_count    = 0;

            rto_ms *= 2;
            if (rto_ms > TCP_MAX_RTO_MS) rto_ms = TCP_MAX_RTO_MS;

            uint32_t resend_seq = priv->snd_una;
            while (tcp_seq_lt(resend_seq, snd_nxt)) {
                uint32_t remain = snd_nxt - resend_seq;
                uint16_t rchunk = (uint16_t)((remain > conn->snd_mss) ? conn->snd_mss : remain);
                conn->snd_seq = resend_seq;
                if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                      data + (resend_seq - base_seq), rchunk) != 0) {
                    break;
                }
                /* TCP層の性能分析用: Go-Back-Nで実際に再送されたバイト数。 */
                if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 5), tcp_conn_arg(conn, rchunk));
                tcp_undo_note(priv, resend_seq, rchunk);
                resend_seq += rchunk;
                if (!priv->sack_enabled) priv->dup_ack_suppress++;
                g_tcp_retransmit_segs++;
            }
            conn->snd_seq = snd_nxt;   /* 送り直しの後は SND.NXT へ戻す(塊を送った後と同じ理由) */
            window_sent_at = timer_now();
            window_retransmitted = 1;
        }
    }

    conn->snd_seq = priv->snd_una;  /* 実際に確認された分だけ進める */
    uint32_t sent_total = priv->snd_una - base_seq;
    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 6), tcp_conn_arg(conn, sent_total));
    priv->in_bulk_send = 0;
    return sent_total > 0 ? (int)sent_total : -1;
}

/*=================================================================
 * 非同期送信キューが満杯のとき、少なくとも 1 件空くまでブロッキングで
 * 解決する(ACK 待ちと必要なら再送)。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_send_async_ex()
 * ===============================================================*/
static void tcp_async_flush_until_room(tcp_conn_t *conn, tcp_priv_t *priv)
{
    (void)conn;
    while (priv->async_count >= priv->async_cap) {
        tcp_poll_once();
        if (tcp_abort_requested()) {
            /* Ctrl+C中断、追跡を打ち切る。 */
            priv->async_head  = 0;
            priv->async_count = 0;
            break;
        }
    }
}

/*=================================================================
 * 1 チャンク(MSS 以下)を非同期送信スロットへキューする共通処理。
 * 呼び出し元が事前に空きを確保しておくこと。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   buf / len   - このチャンクのデータ
 *   is_ref      - 1=バッファをコピーせずポインタ保持(ゼロコピー)
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   tcp_send_async_ex()
 * ===============================================================*/
static int tcp_send_async_enqueue(tcp_conn_t *conn, tcp_priv_t *priv,
                                   const void *buf, uint16_t len, int use_lso,
                                   int is_ref)
{
    uint32_t seq = conn->snd_seq;

    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_async_enqueue, 0), tcp_conn_arg(conn, len));

    int rc = use_lso
        ? tcp_send_segment_lso(conn, priv, buf, len)
        : tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, buf, len);
    if (rc != 0) {
        return -1;
    }

    unsigned slot_idx = (priv->async_head + priv->async_count) % priv->async_cap;
    tcp_async_slot_t *slot = tcp_async_slot_at(priv, conn->owner_core, slot_idx);

    if (is_ref) {
        slot->ref = (const uint8_t *)buf;
    } else {
        volatile_fast_copy(slot->buf, buf, len);
        slot->ref = 0;
    }
    slot->seq     = seq;
    slot->len     = len;
    slot->sent_at = timer_now();
    slot->rto_ms  = priv->rto_ms;
    slot->retries = 0;
    slot->sacked  = 0;
    slot->retx    = 0;
    slot->lost    = 0;
    priv->tlp_tx_at = slot->sent_at;
    priv->async_count++;

    conn->snd_seq = seq + len;  /* ACKを待たず楽観的に進める */
    return 0;
}

/*=================================================================
 * 短小 PDU(CMD/RSP/R2T/ICResp)専用の非同期送信経路。大きいデータ送信とは
 * 別のキューを使うことで、小さい制御 PDU が大きい転送の背後で待たされない
 * ようにする。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 *   buf / len   - 送る PDU(TCP_ASYNC_SHORT_MAX_LEN 以下)
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   tcp_send_async_ex()
 * ===============================================================*/
/* 短経路のスロットが空き、送信ウィンドウに余地ができるまで待つ。0=空いた、-1=中断。
 * tcp_send_async_short3() と tcp_send_async_reserve() が共有する。 */
static int tcp_short_wait(tcp_conn_t *conn, tcp_priv_t *priv, uint32_t len)
{
    while (priv->async_short_count >= g_tcp_async_short_cap) {
        g_tcp_async_short_stalls++;
        tcp_poll_once();
        if (tcp_abort_requested()) {
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            priv->lost_bytes = 0;
            return -1;
        }
    }

    /* **これから送る長さまで含めてウィンドウに収まるまで待つ。** 以前は
     * 「未確認のバイト数 < ウィンドウ」だけを見ていたので、窓の残りが 1 バイト
     * でもあれば 8KB のセグメントを丸ごと送っていた。Linux は窓を超えた分を
     * 捨てる(TcpExtBeyondWindow)ので、こちらは再送タイムアウトの 200 ms を
     * 待つことになる。方向 A の 4KiB 書き込み qd128 が 0.5〜5k IOPS に落ち、
     * TLS で相手が落としていないのに再送していたのはこれだった。 */
    /* **輻輳ウィンドウ(cwnd)で止めるのは未確認のデータがあるときだけ。**
     * 未確認が 0 なら cwnd に関係なく 1 セグメントは送ってよい(RFC 5681 の
     * 「cwnd は 1 SMSS を下回らない」)。短経路の ACK は cwnd を育てないので、
     * 確立時の小さい cwnd(実測 4,280)のまま 2 コマンドをまとめた 8,336 バイトを
     * 送ろうとして、未確認 0 のまま永久に待った(2026-10-10 に踏んだ)。
     * 相手の受信ウィンドウ(snd_win)は常に守る。 */
    uint32_t outstanding   = conn->snd_seq - priv->snd_una;
    /* SACK 済みと失われたと見たものは飛んでいる量に数えない(長経路と同じ。PRR の cwnd は pipe 基準)。 */
#define TCP_SHORT_USABLE()                                                        \
    ((outstanding > 0u && priv->cwnd + tcp_cwnd_credit(priv) < conn->snd_win)     \
     ? priv->cwnd + tcp_cwnd_credit(priv) : conn->snd_win)
    uint32_t usable_window = TCP_SHORT_USABLE();
    const int legacy = !g_tcp_short_win_len;
    if (legacy) {                       /* 陰性対照: 従来の判定(outstanding < window、窓 0 は 1 とみなす) */
        len = 1u;
        if (usable_window == 0) usable_window = 1u;
    }
    uint64_t probe_since = 0;
    while (outstanding + len > usable_window) {
        /* 窓が 0、または未確認が無いのに窓がこのセグメントより小さいときは、
         * 相手の窓の更新を待ちつつ、来なければ窓を確かめる(データは送らない)。 */
        if (!legacy) {
            tcp_window_probe(conn, priv, &probe_since,
                             conn->snd_win == 0u || (outstanding == 0u && conn->snd_win < len));
        }
        g_tcp_async_short_winwait++;
        g_tcp_win_last_usable      = usable_window;
        g_tcp_win_last_outstanding = outstanding;
        g_tcp_win_last_cwnd        = priv->cwnd;
        g_tcp_win_last_sndwin      = conn->snd_win;
        tcp_poll_once();
        if (tcp_abort_requested() ||
            (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT)) {
            return -1;
        }
        outstanding   = conn->snd_seq - priv->snd_una;
        usable_window = TCP_SHORT_USABLE();
        if (legacy && usable_window == 0) usable_window = 1u;
    }
#undef TCP_SHORT_USABLE

    return 0;
}

static int tcp_send_async_short3(tcp_conn_t *conn, tcp_priv_t *priv,
                                 const void *buf, uint16_t len,
                                 const void *buf2, uint16_t len2,
                                 const void *buf3, uint16_t len3)
{
    if (tcp_short_wait(conn, priv, (uint32_t)len + len2 + len3) != 0) return -1;

    uint32_t seq = conn->snd_seq;
    uint16_t total = (uint16_t)(len + len2 + len3);
    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_async_short, 0), tcp_conn_arg(conn, total));

    /* **先に再送スロットへ連結してから、そこから送る。** こうすると 2 つの
     * 断片が **1 つの TCP セグメント**として出る。以前は断片ごとに
     * tcp_send_segment() を呼んでいたので、in-capsule write が
     * 「ヘッダ 72B」と「データ 512B」の 2 パケットに分かれ、**相手の
     * パケット処理能力を 1 コマンドで 2 個消費していた**(実測で 1 コマンド
     * あたり 2.13 パケット)。コピー回数は増えていない -- どのみち再送用に
     * スロットへ写す必要がある。 */
    unsigned slot_idx = (priv->async_short_head + priv->async_short_count) % g_tcp_async_short_cap;
    tcp_async_short_slot_t *slot = &priv->async_short_slots[slot_idx];
    volatile_fast_copy(slot->buf, buf, len);
    if (len2 > 0) volatile_fast_copy(slot->buf + len, buf2, len2);
    if (len3 > 0) volatile_fast_copy(slot->buf + len + len2, buf3, len3);

    if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, slot->buf, total) != 0) {
        return -1;
    }

    slot->seq     = seq;
    slot->len     = total;
    slot->sent_at = timer_now();
    slot->rto_ms  = priv->rto_ms;
    slot->retries = 0;
    slot->sacked  = 0;
    slot->retx    = 0;
    slot->lost    = 0;
    priv->tlp_tx_at = slot->sent_at;
    priv->async_short_count++;

    conn->snd_seq = seq + total;
    return (int)total;
}

/*=================================================================
 * tcp_send_async()(コピー版)と tcp_send_async_ref()(ゼロコピー版)の共通
 * 実装。短小 PDU は専用経路へ、それ以外は MSS 単位に分割してキューする。
 *
 * 引数:
 *   conn      - 対象コネクション
 *   buf / len - 送るデータ
 *   is_ref    - 1=ポインタ保持(呼び出し元が ACK まで buf を保持すること)
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   tcp_send_async(), tcp_send_async_ref()
 * ===============================================================*/
static int tcp_send_async_ex(tcp_conn_t *conn, const void *buf, uint16_t len, int is_ref)
{
    if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
        uart_printf("[!] tcp_send_async: ESTABLISHED/CLOSE_WAITでない (state=%d)\n", (int)conn->state);
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_send_async: 未登録のconn(tcp_connect()を呼んでいない)\n");
        return -1;
    }

    if (!is_ref && len <= TCP_ASYNC_SHORT_MAX_LEN) {
        return tcp_send_async_short3(conn, priv, buf, len, NULL, 0, NULL, 0);
    }

    if (len > TCP_ASYNC_MAX_LEN) {
        return tcp_send(conn, buf, len);
    }

    netif_t *conn_ctx = tcp_netif_for((const netaddr_t *)&conn->local_ip);
    uint32_t lso_cap = conn_ctx ? conn_ctx->hw_lso_max_bytes : 0u;
    if (lso_cap > TCP_ASYNC_MAX_LEN) lso_cap = TCP_ASYNC_MAX_LEN;

    uint32_t sent_total = 0;
    const uint8_t *src = (const uint8_t *)buf;

    while (sent_total < (uint32_t)len) {
        if (priv->async_count >= priv->async_cap) {
            /* キュー満杯 -- 最低1件空くまで待ってから続ける。 */
            g_tcp_async_long_full++;
            tcp_async_flush_until_room(conn, priv);
        }

        uint32_t outstanding = conn->snd_seq - priv->snd_una;
        uint32_t usable_window = conn->snd_win;
        /* SACK 済みはパイプに居ない(RFC 6675)。 */
        {
            uint32_t cw = priv->cwnd + tcp_cwnd_credit(priv);
            if (cw < usable_window) usable_window = cw;
        }
        uint32_t room = (usable_window > outstanding) ? (usable_window - outstanding) : 0u;
        uint64_t probe_since = 0;
        const uint32_t remain_all = (uint32_t)len - sent_total;
        /* 待つ条件: 窓に余地が無い、または**送り手の SWS 回避**(RFC 1122 4.2.3.4 の MUST-38):
         * 未確認があり、余地が MSS 未満で残りより小さい(tcp_send() と同じ形)。 */
#define TCP_LONG_MUST_WAIT() \
        (room == 0u || (outstanding > 0u && room < (uint32_t)conn->snd_mss && room < remain_all))
        if (TCP_LONG_MUST_WAIT()) {
            g_tcp_async_long_winwait++;
            if (priv->cwnd + tcp_cwnd_credit(priv) < conn->snd_win) g_tcp_async_long_cwndlim++;
            g_tcp_long_last_outstanding = outstanding;
            g_tcp_long_last_cwnd        = priv->cwnd;
            g_tcp_long_last_sndwin      = conn->snd_win;
        }
        while (TCP_LONG_MUST_WAIT()) {
            /* 窓が 0 の間は送らずに待つ(以前は 1 とみなして 1 バイト送り、
             * Linux に捨てられて再送タイムアウトを待っていた)。 */
            tcp_window_probe(conn, priv, &probe_since, conn->snd_win == 0u);
            tcp_poll_once();
            if (tcp_abort_requested() ||
                (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT)) {
                return (sent_total > 0) ? (int)sent_total : -1;
            }
            outstanding = conn->snd_seq - priv->snd_una;
            usable_window = conn->snd_win;
            {
                uint32_t cw = priv->cwnd + tcp_cwnd_credit(priv);
                if (cw < usable_window) usable_window = cw;
            }
            room = (usable_window > outstanding) ? (usable_window - outstanding) : 0u;
        }

#undef TCP_LONG_MUST_WAIT

        uint32_t remaining = (uint32_t)len - sent_total;
        uint32_t max_chunk = (lso_cap > conn->snd_mss) ? lso_cap : (uint32_t)conn->snd_mss;
        uint32_t chunk32 = (remaining < max_chunk) ? remaining : max_chunk;
        if (chunk32 > room) chunk32 = room;
        int use_lso = (lso_cap > conn->snd_mss) && (chunk32 > conn->snd_mss);
        uint16_t chunk = (uint16_t)chunk32;

        if (tcp_send_async_enqueue(conn, priv, src + sent_total, chunk, use_lso, is_ref) != 0) {
            return (sent_total > 0) ? (int)sent_total : -1;
        }
        sent_total += chunk;
    }

    return (int)sent_total;
}

/*=================================================================
 * データを非同期送信キューへ積み、ACK を待たずに即座に返る。信頼性は
 * tcp_async_poll() が背後で ACK 確認と RTO 再送を行って担保する。
 *
 * 引数:
 *   conn - 対象コネクション
 *   buf  - 送信データ(内部でスロットへコピーされる)
 *   len  - そのバイト数
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   nvme_tcp_send_cmd_async(), nvme_pipeline_h2c_pump(),
 *   nvmet_tcp_send_r2t(), nvmet_tcp_send_resp(), nvmet_tcp_send_icresp()
 * ===============================================================*/
int tcp_send_async(tcp_conn_t *conn, const void *buf, uint16_t len)
{
    return tcp_send_async_ex(conn, buf, len, 0);
}

/*=================================================================
 * 2 つの断片を **1 つの TCP セグメント**として非同期に送る。
 *
 * **PDU のヘッダと本体を別々に送ると、相手はそれを 2 パケットとして
 * 処理する。** NVMe/TCP の in-capsule write(ヘッダ 72B + データ 512B)で
 * これが効き、実測で 1 コマンドあたり 2.13 パケットを相手へ届けていた。
 * 弱いホスト(Pi5)ではパケット処理率が先に飽和するので、まとめるだけで
 * 上限が倍になる。
 *
 * 合計が TCP_ASYNC_SHORT_MAX_LEN を超えるときは**まとめずに 2 回に分けて**
 * 従来どおり送る(呼び出し側は成否だけ見ればよい)。
 *
 * 引数:
 *   conn        - 対象コネクション
 *   buf1 / len1 - 前半(PDU ヘッダなど)
 *   buf2 / len2 - 後半(データ本体)。len2=0 なら 1 断片と同じ
 * 戻り値:
 *   キューイングした合計バイト数、-1=失敗
 * コール元:
 *   nvme_tcp_send_cmd_inline_async()
 * ===============================================================*/
/*=================================================================
 * まだ ACK されていない送信済みバイト数。**Nagle 的な溜め込みの判定に使う**
 * -- 「相手からの ACK を待っている間は小さいセグメントを出さずに溜める」の
 * 「待っている間」がこれ。0 なら溜めずにすぐ出してよい(だから qd=1 の
 * レイテンシは悪化しない)。
 *
 * 引数:
 *   conn - 対象コネクション
 * 戻り値:
 *   未 ACK のバイト数(未登録なら 0)
 * コール元:
 *   nvme_tcp_tx_batch_end()
 * ===============================================================*/
uint32_t tcp_unacked_bytes(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    if (!priv) return 0u;
    return conn->snd_seq - priv->snd_una;
}

/* 相手がこれまでに広告した最大の受信窓(Window Scale を掛けた後)。まだ分からなければ 0。 */
uint32_t tcp_peer_win_max(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return priv ? priv->snd_win_max : 0u;
}

/* いま送れるバイト数(相手の受信窓と自分の cwnd の小さいほうから未確認を引いた残り)。
 * tcp_send_async_ex() が「窓が空くまでその場で待つ」かどうかの判定と同じ式。 */
uint32_t tcp_send_room(const tcp_conn_t *conn, uint32_t *usable_out)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    if (usable_out) *usable_out = 0u;
    if (!priv) return 0u;
    uint32_t usable = conn->snd_win;
    const uint32_t cw = priv->cwnd + tcp_cwnd_credit(priv);
    if (cw < usable) usable = cw;
    if (usable_out) *usable_out = usable;
    const uint32_t outstanding = conn->snd_seq - priv->snd_una;
    return (usable > outstanding) ? (usable - outstanding) : 0u;
}

/*=================================================================
 * 短経路の再送用の枠の空きの数を返す(ACK 済みの枠はここで返す)。
 *
 * 引数:
 *   conn    - 対象コネクション
 *   cap_out - 枠の数(NULL 可)
 * コール元:
 *   iscsit_conn_step()(`iscsit txyield short`)
 * ===============================================================*/
unsigned tcp_send_short_free(const tcp_conn_t *conn, unsigned *cap_out)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    const unsigned cap = g_tcp_async_short_cap;
    if (cap_out) *cap_out = cap;
    if (!priv) return 0u;
    /* ACK 済みの枠を返す(返すのは普段 tcp_poll_once_ex() の tcp_async_short_poll() だけで、
     * net_poll_all_and_dispatch() で ACK を拾っても枠の数は減らない。これをしないと、譲った側が
     * 枠の空きを待ち続けて止まりかけた)。 */
    while (priv->async_short_count > 0) {
        const tcp_async_short_slot_t *sl = &priv->async_short_slots[priv->async_short_head];
        if (tcp_seq_lt(priv->snd_una, sl->seq + sl->len)) break;
        priv->async_short_head = (priv->async_short_head + 1u) % g_tcp_async_short_cap;
        priv->async_short_count--;
        priv->rto_since = 0;   /* 進んだので R2 を測り直す */
    }
    return priv->async_short_count < cap ? cap - priv->async_short_count : 0u;
}

/*=================================================================
 * 長経路(LSO・ゼロコピー)の再送用の枠の空きの数を返す(ACK 済みの枠はここで返す)。
 * tcp_send_short_free() の長経路版。**このコネクションを受け持つコアから呼ぶこと。**
 *
 * 引数:
 *   conn    - 対象コネクション
 *   cap_out - 枠の数(NULL 可)
 * コール元:
 *   nvmet_io_job_step_impl()(`nvmettxyield room`)
 * ===============================================================*/
unsigned tcp_send_long_free(const tcp_conn_t *conn, unsigned *cap_out)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    if (cap_out) *cap_out = priv ? priv->async_cap : 0u;
    if (!priv) return 0u;
    while (priv->async_count > 0) {
        const tcp_async_slot_t *sl = tcp_async_slot_at(priv, conn->owner_core, priv->async_head);
        if (tcp_seq_lt(priv->snd_una, sl->seq + sl->len)) break;
        priv->async_head = (priv->async_head + 1u) % priv->async_cap;
        priv->async_count--;
        priv->rto_since = 0;
    }
    return priv->async_count < priv->async_cap ? priv->async_cap - priv->async_count : 0u;
}

int tcp_send_async2(tcp_conn_t *conn, const void *buf1, uint16_t len1,
                    const void *buf2, uint16_t len2)
{
    return tcp_send_async3(conn, buf1, len1, buf2, len2, NULL, 0);
}

/*=================================================================
 * 3 つの断片を **1 つの TCP セグメント**として非同期に送る。
 * tcp_send_async2() の 3 断片版で、NVMe/TCP のデータダイジェスト
 * (ヘッダ + データ + DDGST 4 バイト)を 1 セグメントで出すために使う。
 * 合計が 1 セグメントに収まらなければ、断片ごとに分けて従来どおり送る。
 *
 * 引数:
 *   conn        - 対象コネクション
 *   buf1 / len1 - 1 断片目(PDU ヘッダなど)
 *   buf2 / len2 - 2 断片目(データ本体。無ければ NULL / 0)
 *   buf3 / len3 - 3 断片目(データダイジェスト。無ければ NULL / 0)
 * 戻り値:
 *   キューイングした合計バイト数、-1=失敗
 * コール元:
 *   tcp_send_async2(), nvme_tcp_tx_put(), nvmet_tcp_tx_put()
 * ===============================================================*/
int tcp_send_async3(tcp_conn_t *conn, const void *buf1, uint16_t len1,
                    const void *buf2, uint16_t len2,
                    const void *buf3, uint16_t len3)
{
    uint32_t seg_cap = conn->snd_mss ? (uint32_t)conn->snd_mss : 1400u;
    if (seg_cap > TCP_ASYNC_SHORT_SLOT_BYTES) seg_cap = TCP_ASYNC_SHORT_SLOT_BYTES;
    if ((uint32_t)len1 + (uint32_t)len2 + (uint32_t)len3 > seg_cap) {
        int r1 = tcp_send_async(conn, buf1, len1);
        if (r1 < 0) return -1;
        int r2 = 0, r3 = 0;
        if (len2 != 0 && (r2 = tcp_send_async(conn, buf2, len2)) < 0) return -1;
        if (len3 != 0 && (r3 = tcp_send_async(conn, buf3, len3)) < 0) return -1;
        return r1 + r2 + r3;
    }
    if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
        uart_printf("[!] tcp_send_async3: ESTABLISHED/CLOSE_WAITでない (state=%d)\n", (int)conn->state);
        return -1;
    }
    if (len1 + len2 + len3 == 0) return 0;
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_send_async3: 未登録のconn\n");
        return -1;
    }
    return tcp_send_async_short3(conn, priv, buf1, len1, buf2, len2, buf3, len3);
}

/*=================================================================
 * 短経路のスロットを予約して、その書き込み先を返す(段階 G)。呼び出し側は
 * len バイトを書いてから tcp_send_async_commit() で送る。**間に同じ
 * コネクションへの別の送信を挟まないこと**(スロットの順番がずれる)。
 *
 * TLS の送信で使う: 暗号化の出力を再送スロットへ直接書けば、平文を
 * レコード用のバッファへ写す 1 回と、レコードをスロットへ写す 1 回が要らない
 * (再送は同じ暗号文を送り直すだけなので、暗号化は 1 回でよい)。
 *
 * 引数:
 *   conn - 対象コネクション
 *   len  - 書くバイト数(1 セグメント・TCP_ASYNC_SHORT_SLOT_BYTES 以下)
 * 戻り値:
 *   書き込み先(NULL=送れない状態 / 大きすぎる / 中断)
 * コール元:
 *   nvmet_tls_send()
 * ===============================================================*/
uint8_t *tcp_send_async_reserve(tcp_conn_t *conn, uint16_t len)
{
    if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) return NULL;
    if (len == 0 || len > TCP_ASYNC_SHORT_SLOT_BYTES) return NULL;
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return NULL;
    if (tcp_short_wait(conn, priv, len) != 0) return NULL;
    const unsigned slot_idx = (priv->async_short_head + priv->async_short_count) % g_tcp_async_short_cap;
    return (uint8_t *)priv->async_short_slots[slot_idx].buf;
}

/*=================================================================
 * tcp_send_async_reserve() で予約したスロットの中身(len バイト)を送る。
 * 戻り値: len、-1=失敗
 * ===============================================================*/
int tcp_send_async_commit(tcp_conn_t *conn, uint16_t len)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return -1;
    const unsigned slot_idx = (priv->async_short_head + priv->async_short_count) % g_tcp_async_short_cap;
    tcp_async_short_slot_t *slot = &priv->async_short_slots[slot_idx];
    const uint32_t seq = conn->snd_seq;
    if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, slot->buf, len) != 0) return -1;
    slot->seq     = seq;
    slot->len     = len;
    slot->sent_at = timer_now();
    slot->rto_ms  = priv->rto_ms;
    slot->retries = 0;
    slot->sacked  = 0;
    slot->retx    = 0;
    slot->lost    = 0;
    priv->tlp_tx_at = slot->sent_at;
    priv->async_short_count++;
    conn->snd_seq = seq + len;
    return (int)len;
}

/*=================================================================
 * 送信元バッファをコピーせずポインタだけ保持する非同期送信(再送もそこ
 * から読む)。呼び出し元は ACK されるまでバッファを書き換えないこと。
 *
 * 引数:
 *   conn / buf / len - tcp_send_async() と同じ
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   nvmet_tcp_send_c2h_async()
 * ===============================================================*/
int tcp_send_async_ref(tcp_conn_t *conn, const void *buf, uint16_t len)
{
    return tcp_send_async_ex(conn, buf, len, 1);
}

/*=================================================================
 * tcp_recv() / tcp_recv_no_ack() の共通実装。do-while 構造なので
 * timeout_val_ms=0 でも本体を必ず 1 回実行してから返る(=「1 回だけ試す」
 * 非ブロッキング受信として使える)。send_ack=0 でも消費バイト数が閾値を
 * 超えたらウィンドウ更新 ACK を送る。
 *
 * 引数:
 *   conn / buf / maxlen - 対象コネクションと受信先
 *   timeout_val_ms      - 待ち時間(0=1 回だけ試す)
 *   send_ack            - 1=読み取りごとに ACK、0=閾値方式
 * 戻り値:
 *   受信バイト数。0=FIN/RST、-1=タイムアウト/中断
 * コール元:
 *   tcp_recv(), tcp_recv_no_ack()
 * ===============================================================*/
static int tcp_recv_internal(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_val_ms, int send_ack)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_recv: 未登録のconn(tcp_connect()を呼んでいない)\n");
        return -1;
    }

    volatile uint8_t *vout = buf;

    int log_idle_poll = (timeout_val_ms != 0);
    if (log_idle_poll) {
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 0), tcp_conn_arg(conn, maxlen));
    }

    uint64_t start = timer_now();
    int check_ctrl_c = (timeout_val_ms != 0);
    do {
        tcp_poll_once_ex(check_ctrl_c);

        if (check_ctrl_c && tcp_abort_requested()) {
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 1), tcp_conn_arg(conn, 0x00FFFFFEu));
            return -1;
        }

        if (priv->rx_count > 0) {
            uint32_t n = priv->rx_count;
            if (n > maxlen) n = maxlen;
            uint64_t cpt0 = timer_now();
            uint32_t first_len = TCP_RX_BUF_SIZE - priv->rx_read;
            if (first_len > n) first_len = n;
            volatile_fast_copy(vout, &priv->rx_buf[priv->rx_read], first_len);
            if (first_len < n) {
                volatile_fast_copy(vout + first_len, &priv->rx_buf[0], n - first_len);
            }
            g_tcp_copy3_ns    += get_ns_from(cpt0);
            g_tcp_copy3_bytes += n;
            priv->rx_read = (priv->rx_read + n) % TCP_RX_BUF_SIZE;
            priv->rx_count = priv->rx_count - n;

            if (send_ack && (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT)) {
                tcp_send_window_update(conn, priv);
            } else if (!send_ack && (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT)) {
                priv->unacked_consumed_bytes += n;
                uint32_t threshold = (uint32_t)conn->snd_mss * TCP_RECV_NOACK_ACK_THRESHOLD_MSS;
                if (threshold == 0) threshold = TCP_RECV_NOACK_ACK_THRESHOLD_MSS * 536u;
                if (priv->unacked_consumed_bytes >= threshold) {
                    TS_HOT(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 2), tcp_conn_arg(conn, priv->unacked_consumed_bytes));
                    tcp_send_window_update(conn, priv);
                    priv->unacked_consumed_bytes = 0;
                }
            }
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 3), tcp_conn_arg(conn, n));
            return (int)n;
        }
        if (priv->fin_received) {
            priv->fin_received = 0;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 4), tcp_conn_arg(conn, 0u));
            return 0;  /* 相手がFINを送りコネクションを閉じた */
        }
    } while (!timeout_ms(start, timeout_val_ms));

    if (log_idle_poll) {
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 5), tcp_conn_arg(conn, 0x00FFFFFFu));  /* タイムアウト */
    }
    return -1;  /* タイムアウト */
}

/*=================================================================
 * 受信バッファからデータを取り出し、読み取りごとにウィンドウ更新 ACK を
 * 送る。
 *
 * 引数:
 *   conn / buf / maxlen / timeout_ms - tcp_recv_internal() と同じ
 * 戻り値:
 *   受信バイト数。0=FIN/RST、-1=タイムアウト/中断
 * コール元:
 *   nvme_tcp_recv_poll()
 * ===============================================================*/
int tcp_recv(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms)
{
    return tcp_recv_internal(conn, buf, maxlen, timeout_ms, 1);
}

/*=================================================================
 * tcp_recv() と同じだが、読み取りごとの明示的な ACK を送らない(閾値を
 * 超えたときだけウィンドウ更新 ACK を出す)。
 *
 * 引数:
 *   conn / buf / maxlen / timeout_ms - tcp_recv() と同じ
 * 戻り値:
 *   受信バイト数。0=FIN/RST、-1=タイムアウト/中断
 * コール元:
 *   nvmet_tcp_recv_poll()
 * ===============================================================*/
int tcp_recv_no_ack(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms)
{
    return tcp_recv_internal(conn, buf, maxlen, timeout_ms, 0);
}

/*=================================================================
 * コネクションを閉じる。FIN を再送付きで送り、スロットを解放して
 * TIME_WAIT テーブルへ登録する(閉じた後に届く再送へ ACK を返せるように)。
 *
 * 引数:
 *   conn - 閉じるコネクション
 * コール元:
 *   nvme_tcp_close(), nvmet_tcp_close()
 * ===============================================================*/
void tcp_close(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        conn->state = TCP_CLOSED;
        return;  /* 未登録(既にclose済み等) */
    }

    if (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT) {
        int active = (conn->state == TCP_ESTABLISHED);
        uart_printf("[TCP] close: FIN送信 (%s)\n", active ? "能動close" : "受動close完了");
        uint32_t fin_seq = conn->snd_seq;
        conn->state = active ? TCP_FIN_WAIT_1 : TCP_LAST_ACK;

        if (tcp_send_reliable(conn, priv, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, fin_seq + 1) == 0) {
            conn->snd_seq = fin_seq + 1;  /* FINは1バイト分のシーケンス番号を消費する */

            if (active) {
                uint64_t start = timer_now();
                while (conn->state != TCP_TIME_WAIT && conn->state != TCP_CLOSED &&
                       !timeout_ms(start, TCP_CLOSE_FIN_WAIT_MS)) {
                    tcp_poll_once();
                }
                /* **能動クローズは TIME_WAIT を必ず残す**(RFC 9293 3.6)。相手の FIN を受けて
                 * TIME_WAIT に入った場合も、FIN_WAIT_2 のまま待ち切れなかった場合も。以前は
                 * TIME_WAIT に入ったときに限って登録していなかったので、こちらの最後の ACK が
                 * 落ちて相手が FIN を送り直すと、表に無い 4-tuple として RST を返していた。 */
                if (conn->state != TCP_CLOSED) {
                    tcp_timewait_register((const netaddr_t *)&conn->local_ip, conn->local_port,
                                           (const netaddr_t *)&conn->remote_ip, conn->remote_port,
                                           conn->snd_seq, priv->ts_enabled, priv->ts_recent);
                }
            }
        } else if (conn->state != TCP_CLOSED) {
            /* FIN の再送を諦めた(相手から RST が来たのではない): 黙って消えずに RST を送る
             * (RFC 9293 3.8.3 の MUST-20、相手が半端な状態で残らないように)。tcp_close() は
             * 呼び出し側を待たせるので、ここの上限は回数(TCP_MAX_RETRIES、約 13 秒)のまま
             * にしてある(アプリが決める linger の時間、RFC 9293 3.10.4 の ABORT と同じ扱い)。 */
            uart_printf("[!] TCP: FIN再送上限到達、RST を送って閉じる\n");
            g_tcp_retx_abort++;
            tcp_abort_conn(conn, priv, "FIN の再送の上限");
        }
    }

    conn->state = TCP_CLOSED;
    {
        unsigned core = conn->owner_core;
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[core][i] == conn) {
                s_conns[core][i] = NULL;
                break;
            }
        }
    }
}

/*=================================================================
 * 指定インターフェースの port でリッスンを開始する。
 *
 * 引数:
 *   port - リッスンポート
 *   ctx  - 待ち受けるインターフェース
 * 戻り値:
 *   リッスンハンドル。空きが無ければ -1
 * コール元:
 *   nvmet_job_start()
 * ===============================================================*/
int tcp_listen(uint16_t port, netif_t *ctx)
{
    smp_spin_lock(&s_listener_lock);
    for (unsigned i = 0; i < TCP_LISTENER_TOTAL; i++) {
        if (!s_listeners[i].in_use) {
            s_listeners[i].in_use       = 1;
            s_listeners[i].port         = port;
            s_listeners[i].bound_ctx    = ctx;
            s_listeners[i].accept_conn  = NULL;
            s_listeners[i].accept_ready = 0;
            for (unsigned p = 0; p < TCP_BACKLOG; p++) {
                s_listeners[i].pending_used[p]  = 0;
                s_listeners[i].pending_estab[p] = 0;
                s_listeners[i].pending[p].state = TCP_CLOSED;
            }
            smp_spin_unlock(&s_listener_lock);
            return (int)i;
        }
    }
    smp_spin_unlock(&s_listener_lock);
    return -1;
}

/*=================================================================
 * リッスンを終了しスロットを解放する。
 *
 * 引数:
 *   listener - tcp_listen() が返したハンドル
 * コール元:
 *   nvmet_job_start(), nvmet_admin_job_step()
 * ===============================================================*/
void tcp_unlisten(int listener)
{
    smp_spin_lock(&s_listener_lock);
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (l) {
        /* 待ち行列に残っているものは引き取り手が居なくなるので、
         * s_conns[] から外して回収する(コネクションスロットの解放)。 */
        for (unsigned p = 0; p < TCP_BACKLOG; p++) {
            if (l->pending_used[p]) tcp_backlog_release(l, p);
        }
        l->in_use       = 0;
        l->accept_conn  = NULL;
        l->accept_ready = 0;
    }
    smp_spin_unlock(&s_listener_lock);
}

/*=================================================================
 * このコネクションで Window Scale オプションが双方合意できたかを返す。
 *
 * 引数:
 *   conn - 対象コネクション
 * 戻り値:
 *   1=有効、0=無効
 * コール元:
 *   nvmet_tcp_max_h2c_data()
 * ===============================================================*/
int tcp_window_scaling_enabled(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return priv ? priv->wscale_enabled : 0;
}

/*=================================================================
 * 全コアの確立済みコネクションの送信側の状態を 1 行ずつ表示する
 * (シェルの `tcpconns`。負荷の最中に、どの接続が何で止まっているかを見る)。
 * 別のコアが更新している最中の値を読むので、表示は目安。
 *
 * コール元:
 *   シェルの tcpconns コマンド
 * ===============================================================*/
void tcp_conns_show(void)
{
    for (unsigned core = 0; core < SMP_MAX_CORES; core++) {
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            const tcp_conn_t *c = s_conns[core][i];
            if (!c || c->state != TCP_ESTABLISHED) continue;
            const tcp_priv_t *pv = &s_priv[core][i];
            uart_printf("  core%u %u->%u 未確認=%u cwnd=%u ssthresh=%u 相手の窓=%u(最大 %u)長経路の枠=%u/%u 短経路の枠=%u"
                        " 高速回復=%d rto=%ums snd_seq=%u snd_max=%u 受信窓の右端=+%u keepalive=%s ICMP=%u\n",
                        core, (unsigned)c->local_port, (unsigned)c->remote_port,
                        (unsigned)(c->snd_seq - pv->snd_una), pv->cwnd, pv->ssthresh, (unsigned)c->snd_win, pv->snd_win_max,
                        pv->async_count, pv->async_cap, pv->async_short_count,
                        pv->in_fast_recovery, pv->rto_ms, (unsigned)c->snd_seq, (unsigned)pv->snd_max,
                        (unsigned)(pv->rcv_wnd_edge - c->rcv_seq), pv->ka_enabled ? "有" : "無",
                        (unsigned)pv->icmp_soft_err);
        }
    }
    uart_printf("  RFC の検査: SND.NXT 越えの ACK=%u 窓外=%u 同期済みへの SYN=%u ACK 無し=%u 待ち受けへの RST=%u"
                " TS 無し=%u 窓外 ACK の省略=%u 再送の上限で RST=%u ACK の時間切れ=%u URG=%u 握手の RST=%u\n",
                (unsigned)g_tcp_ack_unsent_drop, (unsigned)g_tcp_rx_oow_drop, (unsigned)g_tcp_syn_challenge,
                (unsigned)g_tcp_noack_drop, (unsigned)g_tcp_listen_rst, (unsigned)g_tcp_ts_missing_drop,
                (unsigned)g_tcp_oow_ack_limited, (unsigned)g_tcp_retx_abort, (unsigned)g_tcp_ack_time_flush,
                (unsigned)g_tcp_urg_rx, (unsigned)g_tcp_synsent_rst);
    uart_printf("  ICMP: soft=%u hard=%u(握手を失敗させた %u) PMTU=%u 引用が合わない=%u\n",
                (unsigned)g_tcp_icmp_soft_count, (unsigned)g_tcp_icmp_hard_count, (unsigned)g_tcp_icmp_hard_abort,
                (unsigned)g_tcp_icmp_pmtu_ok, (unsigned)g_tcp_icmp_bogus_count);
}

/*=================================================================
 * コネクションの受信バッファ・シーケンス番号・非同期送信キューの状態を
 * 表示する(ストリーム desync 疑いのときの診断用)。
 *
 * 引数:
 *   conn - 対象コネクション
 * コール元:
 *   nvmet_io_debug_desync()
 * ===============================================================*/
void tcp_debug_dump_rx(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    if (!priv) {
        uart_printf("[DEBUG] tcp_debug_dump_rx: 未登録のconn\n");
        return;
    }

    uart_printf("[DEBUG] TCP: state=%d snd_seq=%u rcv_seq=%u snd_win=%u snd_mss=%u\n",
                (int)conn->state, conn->snd_seq, conn->rcv_seq,
                (unsigned)conn->snd_win, (unsigned)conn->snd_mss);
    uart_printf("[DEBUG] rx_read=%u rx_count=%u wscale_enabled=%d snd_wscale=%u\n",
                priv->rx_read, priv->rx_count, priv->wscale_enabled,
                (unsigned)priv->snd_wscale);
    uart_printf("[DEBUG] async_count=%u async_head=%u async_cap=%u\n",
                priv->async_count, priv->async_head, priv->async_cap);
    for (unsigned i = 0; i < priv->async_count; i++) {
        tcp_async_slot_t *s = tcp_async_slot_at(priv, conn->owner_core, (priv->async_head + i) % priv->async_cap);
        uart_printf("[DEBUG] async_slots[%u]: seq=%u len=%u retries=%d\n",
                    i, s->seq, (unsigned)s->len, s->retries);
    }
    uart_printf("[DEBUG] async_short_count=%u async_short_head=%u async_short_cap=%u\n",
                priv->async_short_count, priv->async_short_head, g_tcp_async_short_cap);
    for (unsigned i = 0; i < priv->async_short_count; i++) {
        tcp_async_short_slot_t *s = &priv->async_short_slots[(priv->async_short_head + i) % g_tcp_async_short_cap];
        uart_printf("[DEBUG] async_short_slots[%u]: seq=%u len=%u retries=%d\n",
                    i, s->seq, (unsigned)s->len, s->retries);
    }
    uart_printf("[DEBUG] unacked_full_segments=%u\n", priv->unacked_full_segments);

    int any_ooo = 0;
    for (uint16_t n = priv->ooo_head; n != TCP_OOO_NONE; n = s_ooo_next[n]) {
        uart_printf("[DEBUG] ooo[%u]: seq=%u len=%u\n",
                    (unsigned)n, s_ooo_seq[n], (unsigned)s_ooo_len[n]);
        any_ooo = 1;
    }
    if (!any_ooo) {
        uart_printf("[DEBUG] ooo: 全スロット空き\n");
    }

    uart_printf("[DEBUG] rx_buf base=%p size=%u (mdコマンドでさらに広い範囲を確認可能)\n",
                (void *)priv->rx_buf, (unsigned)TCP_RX_BUF_SIZE);

    uint32_t dump_start = (priv->rx_read + TCP_RX_BUF_SIZE - 32u) % TCP_RX_BUF_SIZE;
    uart_printf("[DEBUG] rx_buf hexdump (rx_read-32 から192バイト、"
                "rx_read自体は+32行目の先頭):\n");
    for (uint32_t off = 0; off < 192u; off += 16u) {
        uart_printf("  +%3u:", off);
        for (uint32_t j = 0; j < 16u; j++) {
            uint32_t idx = (dump_start + off + j) % TCP_RX_BUF_SIZE;
            uart_printf(" %02x", priv->rx_buf[idx]);
        }
        uart_printf("\n");
    }
}

/*=================================================================
 * ブロックせずに accept の受け皿だけを用意する。待ち行列(backlog)を
 * 入れた今は「受け皿の用意前に届いた SYN」も取りこぼさないが、確立した
 * コネクションを引き渡す先はここで渡す conn なので、呼ぶ必要は変わらない。
 *
 * 引数:
 *   listener - リッスンハンドル
 *   conn     - 受け皿にするコネクション
 * コール元:
 *   nvmet_tcp_accept_arm()
 * ===============================================================*/
void tcp_accept_begin(int listener, tcp_conn_t *conn)
{
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return;
    /* SYN の処理(別のコアのこともある)と引き渡しが受け皿をロックの中で見るので揃える。 */
    smp_spin_lock(&s_listener_lock);
    conn->state    = TCP_CLOSED;
    l->accept_conn  = conn;
    l->accept_ready = 0;
    smp_spin_unlock(&s_listener_lock);
}

/*=================================================================
 * 用意した受け皿を取り下げる(まだ確立していない場合のみ)。
 *
 * **受け皿は 1 本しか無い**ので、複数のジョブが順番に accept する構成では
 * 「待つのをやめる」手段が要る。取り下げずに放置すると、次に別のジョブが
 * arm するまでの間に確立したコネクションが、待つのをやめたジョブの
 * tcp_conn_t へ引き渡されてしまう。
 *
 * **取り下げる瞬間に確立していることがある。** その場合も受け皿は外すが、
 * **コネクション自体は呼び出し側が畳まなければならない**(戻り値 1)。
 * 外さずに `accept_ready` を残すと、次に arm したジョブがその旗を拾って
 * 「自分が accept した」と誤認する。
 *
 * 引数:
 *   listener - リッスンハンドル
 *   conn     - tcp_accept_begin() で渡した受け皿(別のものなら何もしない)
 * 戻り値:
 *   1=取り下げたが既に確立していた(呼び出し側が close すること)
 *   0=何もしなかった、または確立前に取り下げた
 * コール元:
 *   nvmet_io_release_arm()
 * ===============================================================*/
int tcp_accept_cancel(int listener, tcp_conn_t *conn)
{
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return 0;
    smp_spin_lock(&s_listener_lock);
    if (l->accept_conn != conn) {
        smp_spin_unlock(&s_listener_lock);
        return 0;
    }
    /* **SYN を受け皿へ直接受理して握手の途中(SYN_RCVD)のものも「使われていた」。**
     * s_conns[] に登録済みなので、黙って取り下げると呼び出し側の tcp_conn_t を
     * 指したままの孤児が残る。呼び出し側に閉じさせる(tcp_close() が外す)。 */
    int was_used = l->accept_ready || conn->state != TCP_CLOSED;
    l->accept_conn  = NULL;
    l->accept_ready = 0;
    smp_spin_unlock(&s_listener_lock);
    return was_used ? 1 : 0;
}

/*=================================================================
 * 待ち行列で確立済みのコネクションを、呼び出し側が用意した受け皿へ
 * 引き渡す。tcp_conn_t は 64 バイトの POD で、プライベート状態
 * (tcp_priv_t)は s_conns[] のポインタ一致で引くので、構造体を複製して
 * s_conns[] の指す先を差し替えるだけで移せる(rx_buf も ooo も
 * 受信済みのデータもスロット側に残ったまま)。
 *
 * 引数:
 *   l    - リスナースロット
 *   core - 呼んでいるコア(このコアが持ち主のエントリだけを渡す)
 * 戻り値:
 *   1=引き渡した(accept_ready を立てた)、0=引き渡せるものが無い
 * コール元:
 *   tcp_accept_ready_poll(), tcp_backlog_service()
 * ===============================================================*/
static int tcp_backlog_handoff(tcp_listener_slot_t *l, unsigned core)
{
    smp_spin_lock(&s_listener_lock);
    /* **受け皿が未使用のときだけ渡す。** 受け皿には SYN が直接受理されることがあり
     * (tcp_input_addr() の backlog=-1)、握手の途中(SYN_RCVD)や確立直後
     * (accept_ready)の受け皿へ複製すると、その接続の中身を上書きして消してしまう。
     * 以前はこれを見ておらず、SPDK が 16 本を同時に張ると、直接受理した 1〜2 本の
     * ACK と ICReq が行き場を失い、SPDK の接続待ち(10 秒)が切れた。 */
    tcp_conn_t *to = l->accept_conn;
    if (to == NULL || to->state != TCP_CLOSED || l->accept_ready) {
        smp_spin_unlock(&s_listener_lock);
        return 0;
    }

    /* 先に確立したものから渡す(FIFO)。**自コアが持ち主のものだけ。** 持ち主の
     * コアは同じ接続の受信を処理している最中かもしれないので、別のコアから
     * 64 バイトを複製すると壊れた状態を写しうる(RSS で受信を散らしたとき)。 */
    int oldest = -1;
    for (unsigned p = 0; p < TCP_BACKLOG; p++) {
        if (!l->pending_used[p] || !l->pending_estab[p]) continue;
        if (l->pending[p].owner_core != core) continue;
        if (oldest < 0 || l->pending_since[p] < l->pending_since[oldest]) oldest = (int)p;
    }
    if (oldest < 0) {
        smp_spin_unlock(&s_listener_lock);
        return 0;
    }

    tcp_conn_t *from = &l->pending[oldest];
    *to = *from;  /* 64 バイトの複製 */

    int moved = 0;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == from) { s_conns[core][i] = to; moved = 1; break; }
    }
    if (!moved) {
        /* s_conns[] に居ない = 既に畳まれている。引き渡さずに回収する。 */
        uart_printf("[!] TCP: backlog のエントリが s_conns[] に居ません(引き渡し中止)\n");
        to->state = TCP_CLOSED;
        tcp_backlog_release(l, (unsigned)oldest);
        smp_spin_unlock(&s_listener_lock);
        return 0;
    }

    from->state = TCP_CLOSED;
    l->pending_estab[oldest] = 0;
    l->pending_used[oldest]  = 0;
    (void)__atomic_sub_fetch(&s_backlog_estab_cnt[core], 1u, __ATOMIC_ACQ_REL);
    /* **引き取りは呼び出し側の tcp_accept_ready_poll() が見る**(受け皿へ直接受理して
     * 確立したときと同じ印)。引き渡しは持ち主のコアで、待っているジョブは別の
     * コアに居てよい。 */
    l->accept_ready = 1;
    g_tcp_backlog_accept_count++;
    smp_spin_unlock(&s_listener_lock);
    return 1;
}

/*=================================================================
 * 自コアが持ち主の、確立済みの待ち行列エントリを受け皿へ引き渡す。
 * **ポーリングの先頭で呼ぶ。** 引き渡し待ちが無いコアは数を見るだけで返る。
 *
 * コール元:
 *   net_poll_all_and_dispatch()
 * ===============================================================*/
void tcp_backlog_service(void)
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES || !s_backlog_estab_cnt[core]) return;
    for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
        tcp_listener_slot_t *l = &s_listeners[li];
        if (l->in_use && l->accept_conn != NULL) (void)tcp_backlog_handoff(l, core);
    }
}

/*=================================================================
 * accept が成立したかを 1 回だけ確認する(ブロックしない)。
 *
 * 引数:
 *   listener - リッスンハンドル
 * 戻り値:
 *   1=接続確立、0=まだ、-1=エラー
 * コール元:
 *   nvmet_admin_job_step(), nvmet_io_job_step_impl()
 * ===============================================================*/
int tcp_accept_ready_poll(int listener)
{
    tcp_poll_once_ex(0);
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return 0;
    if (tcp_abort_requested()) {
        return 0;
    }
    /* 同じコアが持ち主のエントリはここで渡す。別のコアのものは、そのコアの
     * tcp_backlog_service() が渡して accept_ready を立てる。 */
    (void)tcp_backlog_handoff(l, smp_core_index());
    smp_spin_lock(&s_listener_lock);
    int ready = l->accept_ready;
    if (ready) {
        l->accept_ready = 0;
        l->accept_conn  = NULL;
    }
    smp_spin_unlock(&s_listener_lock);
    return ready;
}

/*=================================================================
 * 待ち行列の深さと統計を返す(シェルの `backlog` 表示用)。
 *
 * 引数:
 *   waiting - NULL 可。いま待ち行列に居るコネクション数
 *   estab   - NULL 可。そのうち確立済み(引き渡し待ち)の数
 * コール元:
 *   shell_backlog()
 * ===============================================================*/
void tcp_backlog_stats(unsigned *waiting, unsigned *estab)
{
    unsigned w = 0, e = 0;
    for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
        if (!s_listeners[li].in_use) continue;
        for (unsigned p = 0; p < TCP_BACKLOG; p++) {
            if (!s_listeners[li].pending_used[p]) continue;
            w++;
            if (s_listeners[li].pending_estab[p]) e++;
        }
    }
    if (waiting) *waiting = w;
    if (estab)   *estab   = e;
}

/*=================================================================
 * 待ち行列の深さを変える。0 にすると「受け皿が用意されているときだけ
 * SYN を受理する」従来の挙動へ戻る(陰性対照)。
 *
 * 引数:
 *   depth - 0〜TCP_BACKLOG
 * コール元:
 *   shell_backlog()
 * ===============================================================*/
void tcp_backlog_set_max(unsigned depth)
{
    if (depth > TCP_BACKLOG) depth = TCP_BACKLOG;
    g_tcp_backlog_max = depth;
}

unsigned tcp_backlog_capacity(void) { return TCP_BACKLOG; }

/*=================================================================
 * コネクションの Timestamps 合意状態と RTT 推定を返す。
 *
 * 「ロス中も RTT が更新され続けているか」を外から見るために要る
 * (`g_tcp_ts_rtt_samples` が増えているだけでは、値が動いている証拠に
 * ならない)。
 *
 * 引数:
 *   conn    - 対象コネクション
 *   srtt_us - NULL 可。平滑化 RTT(us)
 *   rto_ms  - NULL 可。現在の RTO
 * 戻り値:
 *   1=Timestamps 合意済み、0=未合意/不明
 * コール元:
 *   shell_tcpts()
 * ===============================================================*/
int tcp_conn_ts_info(const tcp_conn_t *conn, uint64_t *srtt_us, uint32_t *rto_ms)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    if (!priv) return 0;
    if (srtt_us) *srtt_us = priv->srtt_us;
    if (rto_ms)  *rto_ms  = priv->rto_ms;
    return priv->ts_enabled ? 1 : 0;
}

/*=================================================================
 * コネクションが SACK を合意しているかを返す。
 *
 * 引数:
 *   conn - 対象コネクション
 * 戻り値:
 *   1=合意済み、0=未合意/不明
 * コール元:
 *   shell_sacktest()
 * ===============================================================*/
/*=================================================================
 * 接続ごとの RACK / PRR / undo の状態を表示する(シェルの `tcprack show`)。各コアの接続表を読むだけ
 * (別のコアが書いている途中の値が混ざりうる。見るためのもの)。
 * ===============================================================*/
void tcp_rack_show(void)
{
    for (unsigned c = 0; c < SMP_MAX_CORES; c++) {
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            const tcp_conn_t *cn = s_conns[c][i];
            if (cn == NULL || cn->state != TCP_ESTABLISHED) continue;
            const tcp_priv_t *pv = &s_priv[c][i];
            if (!pv->sack_enabled) continue;
            uart_printf("  core%u slot%u %u->%u: srtt=%lluus min_rtt=%lluns(窓 %ums) reo_mult=%u 入れ替わり=%s "
                        "回復中=%s PRR=%s cwnd=%u ssthresh=%u pipe=%u lost=%u undo=%s(控え %u%s)\n",
                        c, i, cn->local_port, cn->remote_port,
                        (unsigned long long)pv->srtt_us, (unsigned long long)tcp_minrtt(pv),
                        (unsigned)g_tcp_rack_minrtt_win_ms, (unsigned)pv->rack_reo_mult,
                        pv->rack_reord_seen ? "有" : "無", pv->in_fast_recovery ? "有" : "無",
                        pv->prr_active ? "有" : "無", pv->cwnd,
                        pv->ssthresh, tcp_pipe(cn, pv), pv->lost_bytes,
                        pv->undo_valid ? "準備中" : "無", (unsigned)pv->undo_log_n,
                        pv->undo_log_over ? " 溢れ" : "");
        }
    }
}

int tcp_conn_sack_enabled(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return (priv && priv->sack_enabled) ? 1 : 0;
}

/*=================================================================
 * 接続ごとに Keepalive を使うかを決める(RFC 1122 4.2.3.6 の MUST-24)。既定は張ったときの
 * g_tcp_keepalive_enable(既定 0、MUST-25)。時間(idle / 間隔 / 回数)は全体の設定を使う。
 * コール元: 上位(Keepalive を使いたい接続)
 * ===============================================================*/
void tcp_set_keepalive(tcp_conn_t *conn, int on)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->ka_enabled    = on ? 1u : 0u;
    priv->ka_idle_since = 0;   /* 次の冷たい検査で測り始める */
    priv->ka_probes     = 0;
}

/*=================================================================
 * 緊急ポインタ(URG)が、アプリがまだ読んでいない位置より先にあるかを返す(RFC 9293 3.8.5 の
 * MUST-30/31「緊急データが来たことを上位へ知らせる」)。読み出し位置は、pull 型なら rx_buf に
 * 溜まっている分だけ rcv_seq より手前、upcall 型なら rcv_seq(渡し済み)。通り過ぎたら印を消す。
 * ===============================================================*/
int tcp_urgent_mark(const tcp_conn_t *conn, uint32_t *bytes_ahead)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    if (bytes_ahead) *bytes_ahead = 0;
    if (!priv || !priv->urg_valid) return 0;
    const uint32_t read_pos = conn->rcv_seq - (priv->recv_upcall ? 0u : priv->rx_count);
    if (!tcp_seq_gt(priv->rcv_up, read_pos)) {
        priv->urg_valid = 0;
        return 0;
    }
    if (bytes_ahead) *bytes_ahead = priv->rcv_up - read_pos;
    return 1;
}

/* 送った最大の seq(SND.NXT)。試験と表示用。 */
uint32_t tcp_snd_max(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return priv ? priv->snd_max : conn->snd_seq;
}

/*=================================================================
 * 受信したセグメントのオプションから TSval を探す(冷たい経路。TIME_WAIT の応答の TSecr 用)。
 * 戻り値: 1=見つかった
 * ===============================================================*/
static int tcp_find_tsval(const volatile uint8_t *in, uint8_t hdr_len, uint32_t *tsval)
{
    const volatile uint8_t *o = in + TCP_HDR_LEN;
    const unsigned olen = (hdr_len > TCP_HDR_LEN) ? (unsigned)(hdr_len - TCP_HDR_LEN) : 0u;
    unsigned i = 0;
    while (i < olen) {
        const uint8_t kind = o[i];
        if (kind == TCP_OPT_KIND_END) break;
        if (kind == TCP_OPT_KIND_NOP) { i++; continue; }
        if (i + 1u >= olen) break;
        const uint8_t l = o[i + 1];
        if (l < 2u || i + l > olen) break;
        if (kind == TCP_OPT_KIND_TS && l == 10u) { *tsval = rd32be(o + i + 2); return 1; }
        i += l;
    }
    return 0;
}

/*=================================================================
 * 待ち受けているポートへの SYN(ACK / RST / FIN の無いもの)を受ける(受動 open)。
 * 受け皿(tcp_accept_begin())が用意されていればそこへ、無ければ待ち行列(backlog)へ
 * SYN_RCVD で受理して SYN|ACK を返す。
 *
 * 戻り値: 1=待ち受けが見つかった(受理した、または受け皿も待ち行列も無く黙って捨てた)、
 *         0=このインターフェースでそのポートを待ち受けていない
 * コール元: tcp_input_noconn()
 * ===============================================================*/
static int tcp_input_listen(unsigned core, const volatile uint8_t *in, uint16_t len, uint8_t hdr_len,
                            const netaddr_t *src, const netaddr_t *dst,
                            uint16_t src_port, uint16_t dst_port)
{
    int matched_listener = -1;
    int backlog_index    = -1;  /* >=0 = 待ち行列のエントリ、-1 = 受け皿へ直接 */
    /* **リスナは全コアで共有している。** RSS で受信を複数コアへ散らすと、
     * 別々の 4-tuple の SYN が同時にここへ入りうるので、「受け皿を掴む /
     * 待ち行列の枠を取る」までは排他する。**受け皿の奪い合いは
     * `accept_conn->state` を SYN_RCVD にするところまで守らないと防げない**
     * (見てから書くまでの間に他コアが同じ受け皿を見てしまう)。
     * SYN のときしか通らない冷たい経路なので費用は無い。 */
    smp_spin_lock(&s_listener_lock);
    for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
        tcp_listener_slot_t *l = &s_listeners[li];
        if (l->in_use &&
            l->port == dst_port &&
            (l->bound_ctx == NULL || l->bound_ctx == g_active_ctx)) {
            matched_listener = (int)li;
            break;
        }
    }
    if (matched_listener < 0) {
        smp_spin_unlock(&s_listener_lock);
        return 0;
    }
    /* 受け皿が用意されているなら従来どおりそこへ直接受理する
     * (複製が要らないぶん素直で、既存の経路がそのまま残る)。
     * 用意されていない隙間に届いたぶんだけ待ち行列へ積む。 */
    tcp_listener_slot_t *l = &s_listeners[matched_listener];
    if (l->accept_conn != NULL && l->accept_conn->state == TCP_CLOSED) {
        backlog_index = -1;
    } else {
        backlog_index = tcp_backlog_find_free(l);
        if (backlog_index < 0) {
            /* 待ち行列が無効/満杯。Linux が accept キュー溢れでそう
             * するのと同じく黙って捨てる(RST を返すと相手の接続が
             * 即死する -- 段階 1 の教訓)。 */
            g_tcp_backlog_overflow_count++;
            smp_spin_unlock(&s_listener_lock);
            if (g_tcp_backlog_overflow_count <= 8u) {
                uart_printf("[TCP] backlog: 受け皿も待ち行列も無く SYN を破棄 "
                            "(local_port=%u, 深さ=%u)\n",
                            (unsigned)dst_port, (unsigned)g_tcp_backlog_max);
            }
            return 1;
        }
    }
    int slot = tcp_find_free_slot();
    if (slot < 0) {
        smp_spin_unlock(&s_listener_lock);
        uart_printf("[!] TCP: 空きコネクションスロットが無く受動openのSYNを破棄 "
                    "(local_port=%u, 最大%u本)\n", dst_port, TCP_MAX_CONNS);
        return 1;
    }
    tcp_conn_t *aconn = (backlog_index >= 0) ? &l->pending[backlog_index] : l->accept_conn;
    tcp_priv_t *apriv = &s_priv[core][slot];
    tcp_priv_init(apriv, core);

    const uint32_t seg_seq = rd32be(in + TCP_OFF_SEQ);

    aconn->local_ip    = dst ? *dst : netaddr_v4(NET_SELF_IP);
    tcp_priv_try_grant_mlx5_async_overflow(apriv, core, (const netaddr_t *)&aconn->local_ip);
    aconn->remote_ip   = *src;
    aconn->remote_port = src_port;
    aconn->local_port  = dst_port;
    aconn->state       = TCP_SYN_RCVD;
    /* ISN(RFC 6528。tcp_isn_gen() の説明)。 */
    aconn->snd_seq     = tcp_isn_gen((const netaddr_t *)&aconn->local_ip, dst_port, src, src_port);

    aconn->owner_core = core;
    s_conns[core][slot] = aconn;
    if (backlog_index >= 0) {
        l->pending_since[backlog_index] = timer_now();
        l->pending_estab[backlog_index] = 0;
        l->pending_used[backlog_index]  = 1;
    }
    /* ここまでで受け皿(state=SYN_RCVD)と待ち行列の枠を確保し終えた。
     * 以降は自分が掴んだ tcp_conn_t しか触らないので排他を外す
     * (SYN|ACK の送信をロックの中でやらない)。 */
    smp_spin_unlock(&s_listener_lock);

    aconn->rcv_seq = seg_seq + 1;  /* SYN消費分 */
    /* 相手が MSS オプションを付けなかったときの既定(IPv4 536 / IPv6 1220、MUST-15)。 */
    aconn->snd_mss = (src->family == NETADDR_V6) ? TCP_MSS_DEFAULT_V6 : TCP_MSS_DEFAULT_RFC879;
    if (hdr_len > TCP_HDR_LEN && hdr_len <= len) {
        tcp_parse_syn_options(aconn, apriv, in + TCP_HDR_LEN, (uint8_t)(hdr_len - TCP_HDR_LEN));
    }
    /* SYN の窓は Window Scale を掛けない(RFC 7323 2.2)。WL1 / WL2 は握手を終える ACK で決める。 */
    aconn->snd_win = rd16be(in + TCP_OFF_WINDOW);
    apriv->snd_win_max = aconn->snd_win;
    apriv->snd_wl1 = seg_seq;
    apriv->snd_wl2 = 0;

    uart_printf("[TCP] accept: SYN受信、SYN|ACK送信 (local_port=%u, slot=%d, backlog=%d)\n",
                dst_port, slot, backlog_index);

    tcp_send_segment(aconn, apriv, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);

    aconn->snd_seq++;  /* SYNは1バイト分のシーケンス番号を消費する */
    apriv->expected_ack = aconn->snd_seq;
    apriv->ack_received = 0;
    return 1;
}

/*=================================================================
 * どの接続にも一致しないセグメント(冷たい経路)。
 *   - 待ち受けのポートへの SYN(ACK / RST / FIN の無いもの)は受動 open
 *   - TIME_WAIT の表にあれば、FIN の再送に ACK を返す(2MSL を測り直す)
 *   - 待ち受けのポートへの **ACK 付き**のセグメント(SYN|ACK を含む)には RST
 *     (RFC 9293 3.10.7.2 LISTEN: "any acknowledgment is bad ... send a reset")
 *   - 待ち受けのポートへの ACK の無いもの(受け皿の隙間に当たった SYN、SYN|FIN など)は黙って捨てる
 *     (**SYN に RST を返すと、accept を張り直す一瞬の隙間で相手の接続が即死する** -- 段階 1 の
 *     教訓。SYN|FIN は Linux も捨てる)
 *   - それ以外(閉じたポート)は RST(RFC 9293 3.10.7.1 CLOSED)
 * ===============================================================*/
static void tcp_input_noconn(unsigned core, const volatile uint8_t *in, uint16_t len, uint8_t hdr_len,
                             uint8_t flags, const netaddr_t *src, const netaddr_t *dst,
                             uint16_t src_port, uint16_t dst_port)
{
    const int pure_syn = ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN)) == TCP_FLAG_SYN);
    if (pure_syn && tcp_input_listen(core, in, len, hdr_len, src, dst, src_port, dst_port)) return;

    /* TIME_WAIT は 4-tuple 一致だけで先に判定する(FIN のときだけ引くのでは
     * なく)。閉じた直後の相手から届く遅延セグメントを「閉じたポート宛」と
     * 誤判定して RST を返すと、相手の TIME_WAIT を勝手に潰すことになる。 */
    tcp_timewait_t tw;
    if (tcp_timewait_find(src, src_port, dst_port, &tw)) {
        if ((flags & TCP_FLAG_FIN) && !(flags & TCP_FLAG_RST)) {
            const uint32_t fin_seq = rd32be(in + TCP_OFF_SEQ);
            const uint16_t fin_payload_len = (uint16_t)(len - hdr_len);
            uint32_t tsecr = tw.ts_recent;
            if (tw.ts_ok) (void)tcp_find_tsval(in, hdr_len, &tsecr);
            tcp_send_bare_ack(&tw.local_ip, tw.local_port, &tw.remote_ip, tw.remote_port,
                              tw.local_seq, fin_seq + fin_payload_len + 1u, tw.ts_ok, tsecr);
            tcp_timewait_restart(src, src_port, dst_port);
        }
        return;
    }
    /* RST を返さない条件(順に確認する):
     *  - 受信が RST -- RST に RST を返すと無限ループになる(最重要)。
     *  - 宛先がマルチキャスト -- 誰宛か特定できないものへ RST は返さない。
     *  - そのポートにリスナが居て、ACK が無い -- accept を張り直す隙間に届いた SYN など。
     *  - 他コアに 4-tuple 一致のコネクションが居る -- 自分のコネクションを
     *    自分で撃たないための保険。 */
    if (flags & TCP_FLAG_RST) return;
    if (dst && dst->family == NETADDR_V6 && dst->a[0] == 0xFFu) return;
    const int listening = tcp_port_has_listener(dst_port);
    if (listening && !(flags & TCP_FLAG_ACK)) return;
    if (tcp_conn_exists_any_core(src, src_port, dst_port)) return;

    netaddr_t nm_local = dst ? *dst : netaddr_v4(NET_SELF_IP);
    tcp_send_bare_rst(&nm_local, dst_port, src, src_port,
                      flags, rd32be(in + TCP_OFF_SEQ), rd32be(in + TCP_OFF_ACK),
                      (uint16_t)(len - hdr_len));
    if (listening) {
        g_tcp_listen_rst++;
        uart_printf("[TCP] 待ち受けのポートへの ACK 付きセグメント (local_port=%u, remote_port=%u) へ RST を返しました\n",
                    (unsigned)dst_port, (unsigned)src_port);
    } else {
        uart_printf("[TCP] 待ち受けの無いポート宛 (local_port=%u, remote_port=%u) へ RST を返しました\n",
                    (unsigned)dst_port, (unsigned)src_port);
    }
}

/*=================================================================
 * 順番どおりになった FIN を受け入れる(RFC 9293 3.10.7.4 eighth)。rcv_seq を 1 進め、ACK を
 * 返して状態を進める。
 *   ESTABLISHED → CLOSE_WAIT、FIN_WAIT_1(自分の FIN が未確認)→ CLOSING(同時クローズ)、
 *   FIN_WAIT_2 → TIME_WAIT
 * **FIN は「その前のデータを全部受け取った」ときにだけ処理する。** 以前は FIN が立っていれば
 * 穴があっても、データを受け取れなくても rcv_seq = seq + 長さ + 1 にしていたので、穴の
 * ぶんのデータを失ったまま接続を閉じ、古い seq の FIN+データでは受け取り済みのデータを
 * もう一度上位へ渡していた。
 * ===============================================================*/
static void tcp_fin_accept(tcp_conn_t *conn, tcp_priv_t *priv)
{
    conn->rcv_seq++;
    priv->fin_pend     = 0;
    priv->fin_received = 1;
    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 4), tcp_conn_arg(conn, 0u));
    switch (conn->state) {
    case TCP_ESTABLISHED:
        conn->state = TCP_CLOSE_WAIT;
        uart_printf("[TCP] FIN受信、ACK返送してCLOSE_WAITへ遷移\n");
        break;
    case TCP_FIN_WAIT_1:
        conn->state = TCP_CLOSING;
        uart_printf("[TCP] 同時クローズ: FIN_WAIT_1 で FIN 受信、CLOSING へ遷移\n");
        break;
    case TCP_FIN_WAIT_2:
        conn->state = TCP_TIME_WAIT;
        break;
    default:
        break;
    }
}

/*=================================================================
 * 緊急ポインタを記録する(RFC 9293 3.8.5、RFC 6093)。緊急データの終わり = seq + 緊急ポインタ。
 * 進んだときだけ記録し、上位は tcp_urgent_mark() で知る(MUST-30/31)。データ自体はストリームの
 * 中で普段どおり渡す(RFC 6093 の推奨どおり、帯域外のデータとしては扱わない)。
 * ===============================================================*/
static void tcp_urg_note(tcp_conn_t *conn, tcp_priv_t *priv, uint32_t seq, uint16_t up)
{
    (void)conn;
    if (up == 0u) return;
    const uint32_t mark = seq + up;
    if (!priv->urg_valid || tcp_seq_gt(mark, priv->rcv_up)) {
        priv->rcv_up    = mark;
        priv->urg_valid = 1;
        g_tcp_urg_rx++;
    }
}

/*=================================================================
 * 受信 TCP セグメントを処理する。RFC 9293 3.10.7.4 の順に:
 *   チェックサム → 4-tuple の照合(無ければ tcp_input_noconn())→ 同期済みへの SYN(challenge ACK)
 *   → RST の検証(RFC 5961)→ SYN_SENT → PAWS / Timestamps → シーケンスの受け入れ判定
 *   → ACK ビット → SYN_RCVD の確立 → SND.NXT を越える ACK → 送信窓(WL1/WL2)→ ACK の処理
 *   → 緊急ポインタ → データ → FIN
 *
 * **ホットパス(確立済みで順番どおりのデータ / ACK)に足したのは比較数個だけ**
 * (seq == rcv_seq なら受け入れ判定を飛ばす、ACK > SND.NXT、WL1/WL2、ACK ビット)。
 * 時刻の読み出しや表の走査は、受け入れられないセグメントの側にしか無い。
 *
 * 引数:
 *   pkt    - TCP ヘッダ先頭(IP ヘッダの直後)
 *   len    - そのバイト数
 *   src - L3 ヘッダから取り出した送信元
 *   dst - 同じく宛先。IPv4 で「アクティブなインターフェースの IPv4」と
 *         分かっている場合は NULL を渡してよい(受信 1 パケットごとに
 *         netaddr_t を組み立てる無駄を避けるため。実際に使うのは受動 open と
 *         ソフトウェアチェックサム検証と RST の 3 箇所だけ)
 * コール元:
 *   tcp_input(), ipv6_handle_frame()
 * ===============================================================*/
void tcp_input_addr(const uint8_t *pkt, uint16_t len,
                    const netaddr_t *src, const netaddr_t *dst)
{
    unsigned core = smp_core_index();

    if (len < TCP_HDR_LEN) {
        uart_printf("[TCP] ヘッダ長不足 (len=%u < %u)\n", (unsigned)len, TCP_HDR_LEN);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = pkt;

    uint16_t src_port = rd16be(in + TCP_OFF_SRC_PORT);
    uint16_t dst_port = rd16be(in + TCP_OFF_DST_PORT);
    uint8_t  flags    = in[TCP_OFF_FLAGS];
    uint8_t  hdr_len  = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);
    if (hdr_len < TCP_HDR_LEN || hdr_len > len) {
        uart_printf("[TCP] 不正なヘッダ長 (hdr_len=%u len=%u) 無視\n",
                    hdr_len, (unsigned)len);
        return;
    }

    /* **チェックサムは何をするより先に確かめる**(RFC 9293 3.10.7 の MUST-2/3)。以前は 4-tuple が
     * 一致した後でしか確かめておらず、壊れた SYN で受動 open したり、壊れたセグメントに RST を
     * 返したりしていた。HW が確かめた普段の受信では分岐 1 つ(以前と同じ費用)。 */
    if (!eth_rx_hw_csum_ok()) {
        uint16_t csum_check;
        netaddr_t dst_v4;
        const netaddr_t *d = dst;
        if (!d) { dst_v4 = netaddr_v4(NET_SELF_IP); d = &dst_v4; }
        if (src->family == NETADDR_V6) {
            csum_check = ipv6_pseudo_checksum(src->a, d->a, IP_PROTO_TCP, pkt, len);
        } else {
            csum_check = pseudo_header_checksum(src->a, d->a, IP_PROTO_TCP, pkt, len);
        }
        if (csum_check != 0) {
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 1), len);
            uart_printf("[TCP] チェックサム不正 (計算結果=0x%04X、0であるべき) セグメント破棄\n",
                        csum_check);
            g_tcp_rx_csum_drop[core]++;
            return;
        }
    }

    tcp_conn_t *conn = NULL;
    tcp_priv_t *priv = NULL;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        /* ポートを先に見る。ポートは構造体前半(スカラ側)にあり 2 バイトの
         * 比較で済むうえ選択性が高いので、後半にある 17 バイトのアドレスへ
         * 触る回数を最小化できる(アドレスを netaddr_t 化した直後、この順序
         * が逆だったために 8KB read が 6% 落ちていた)。 */
        if (s_conns[core][i] != NULL &&
            src_port == s_conns[core][i]->remote_port &&
            dst_port == s_conns[core][i]->local_port &&
            netaddr_eq(src, (const netaddr_t *)&s_conns[core][i]->remote_ip)) {
            conn = s_conns[core][i];
            priv = &s_priv[core][i];
            break;
        }
    }
    if (!conn) {
        tcp_input_noconn(core, in, len, hdr_len, flags, src, dst, src_port, dst_port);
        return;
    }
    if (conn->state == TCP_CLOSED) return;

    /* Keepalive / tcp_send() の「相手は生きている」印。**ホットパスに置くのはこの 1 つの
     * 加算だけ**で、時刻の読み出しと期限の判定は冷たい経路が行う(tcp_keepalive_one())。
     * probe への応答は純 ACK なので、ここで数えないと**応答が返っていることを知る手段が無い**。 */
    priv->rx_segs++;

    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 2), tcp_conn_arg(conn, len));

    uint32_t seq   = rd32be(in + TCP_OFF_SEQ);
    uint32_t ack   = rd32be(in + TCP_OFF_ACK);

    const volatile uint8_t *payload = in + hdr_len;
    uint16_t payload_len = (uint16_t)(len - hdr_len);

    if (flags & TCP_FLAG_SYN) {
        /* 再送された SYN を新しい接続として受理しない。既に SYN_RCVD まで進んでいるなら
         * SYN|ACK を送り直す -- こちらの SYN|ACK が落ちた場合、相手は SYN を再送してくるので、
         * 無視すると永久に確立しない。 */
        if (conn->state == TCP_SYN_RCVD && !(flags & (TCP_FLAG_ACK | TCP_FLAG_RST))) {
            uint32_t saved = conn->snd_seq;
            conn->snd_seq = priv->expected_ack - 1u;  /* SYN 消費前の ISN */
            tcp_send_segment(conn, priv, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
            conn->snd_seq = saved;
            g_tcp_synack_retx_count++;
            uart_printf("[TCP] accept: SYN 再送を受けて SYN|ACK を送り直し "
                        "(local_port=%u)\n", (unsigned)dst_port);
            return;
        }
        /* **同期済みの接続への SYN は、seq によらず challenge ACK を返して捨てる**(RFC 5961 4、
         * RFC 9293 3.10.7.4 fourth)。以前は既存の接続を見つけても待ち受けの処理へ進み、
         * 同じ 4-tuple の 2 つ目の TCB を作っていた。相手が本当に作り直したのなら、challenge
         * ACK を受けて RST を返してくるので、それで古い接続が閉じる。 */
        if (conn->state != TCP_SYN_SENT && conn->state != TCP_SYN_RCVD && !(flags & TCP_FLAG_RST)) {
            g_tcp_syn_challenge++;
            (void)tcp_send_oow_ack(conn, priv, 1, 1);
            return;
        }
    }

    if (flags & TCP_FLAG_RST) {
        /* **RST はシーケンス番号を検証してから受け入れる**(RFC 5961 3)。
         * 4-tuple が一致しただけで畳むと、**前の接続の遅延 RST が生きた
         * 接続を殺す**(4-tuple は使い回される)。窓外の RST は捨て、
         * 窓内だが RCV.NXT でないものには challenge ACK を返して確認する。
         *
         * SYN_SENT だけは別扱い。受信ウィンドウがまだ無いので、
         * RFC 793 どおり「自分の SYN を ACK しているか」で判断する
         * (閉じたポートへ繋ぎに行ったときの RST がこれ。`rsttest`)。 */
        int rst_ok;
        if (conn->state == TCP_SYN_SENT) {
            rst_ok = (flags & TCP_FLAG_ACK) && (ack == priv->expected_ack);
        } else if (seq == conn->rcv_seq) {
            rst_ok = 1;
        } else {
            /* 窓は最後に広告した右端で測る(以前は直前に送った窓の値。LSO の送信では
             * 控えていなかった)。窓 0 でも RCV.NXT の 1 個だけは窓内。 */
            uint32_t rwnd = (priv->rcv_wnd_valid && tcp_seq_gt(priv->rcv_wnd_edge, conn->rcv_seq))
                          ? priv->rcv_wnd_edge - conn->rcv_seq : 0u;
            if (rwnd == 0) rwnd = 1u;
            int in_window = !tcp_seq_lt(seq, conn->rcv_seq) &&
                             tcp_seq_lt(seq, conn->rcv_seq + rwnd);
            if (in_window) {
                /* 窓内だが RCV.NXT ではない -- challenge ACK を返して、
                 * 本物なら相手が正しい seq で送り直すのを待つ(頻度に上限、RFC 5961 7)。 */
                g_tcp_rst_challenge_count++;
                (void)tcp_send_oow_ack(conn, priv, 1, 1);
            } else {
                g_tcp_rst_dropped_count++;
            }
            rst_ok = 0;
        }
        if (!rst_ok) return;

        uart_printf("[TCP] RST受信、コネクションを閉じる\n");
        conn->state = TCP_CLOSED;
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[core][i] == conn) {
                s_conns[core][i] = NULL;
                break;
            }
        }
        return;
    }

    if (conn->state == TCP_SYN_SENT) {
        /* RFC 9293 3.10.7.3。**受け入れられない ACK(自分の SYN を確認していない)には RST**
         * (相手は前の接続の半端な状態かもしれない。以前は黙って捨てていたので、相手は
         * SYN|ACK を送り直し続けた)。ACK だけで SYN が無いものは捨てる。 */
        if ((flags & TCP_FLAG_ACK) && ack != priv->expected_ack) {
            g_tcp_synsent_rst++;
            tcp_send_bare((const netaddr_t *)&conn->local_ip, conn->local_port,
                          (const netaddr_t *)&conn->remote_ip, conn->remote_port,
                          TCP_FLAG_RST, ack, 0u);
            return;
        }
        if (!(flags & TCP_FLAG_SYN)) return;
        conn->rcv_seq = seq + 1;
        tcp_parse_syn_options(conn, priv, in + TCP_HDR_LEN, (uint8_t)(hdr_len - TCP_HDR_LEN));
        /* SYN の窓は Window Scale を掛けない(RFC 7323 2.2)。 */
        conn->snd_win      = rd16be(in + TCP_OFF_WINDOW);
        priv->snd_win_max  = conn->snd_win;
        priv->snd_wl1      = seq;
        priv->snd_wl2      = ack;
        if (flags & TCP_FLAG_ACK) {
            conn->state = TCP_ESTABLISHED;
            priv->ack_received = 1;
            conn->snd_seq = ack;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        } else {
            /* **同時オープン**(RFC 9293 3.5 図 7)。相手も SYN を送ってきた: SYN_RCVD へ進み、
             * 同じ ISN で SYN|ACK を返す。相手の SYN|ACK(か ACK)で ESTABLISHED になる。
             * 以前は捨てていたので、同時オープンは両側の SYN 再送が尽きるまで確立しなかった。 */
            conn->state = TCP_SYN_RCVD;
            tcp_send_segment(conn, priv, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
            uart_printf("[TCP] connect: 同時オープン、SYN_RCVD へ\n");
        }
        return;
    }

    /* Timestamps(RFC 7323)。合意していないコネクションでは分岐 1 つで抜ける。
     * PAWS(古いセグメントの検出)はここで行う -- RST より後に置いてあるので
     * RST は PAWS の対象外(相手を切れなくなるのを避ける)。 */
    uint32_t seg_tsecr = 0;
    const uint8_t sack_gen0 = priv->sack_gen;   /* このセグメントが SACK を運んだか(TLP の判定) */
    /* PRR: この ACK で新しく SACK された量を出すため、読む前の SACK 済みの量を控える(回復中だけ)。 */
    const uint32_t prr_una0    = priv->snd_una;
    const uint32_t prr_sacked0 = priv->prr_active ? tcp_sacked_bytes(priv) : 0u;
    const int fin = (flags & TCP_FLAG_FIN) != 0;
    const uint32_t seg_end = seq + (uint32_t)payload_len + (fin ? 1u : 0u);
    if (priv->ts_enabled || priv->sack_enabled) {
        const int r = tcp_input_options(conn, priv, in, hdr_len, seq, seg_end, &seg_tsecr);
        if (r <= 0) {
            if (r == 0) g_tcp_rx_paws_drop[core]++;   /* PAWS(ACK は tcp_input_options() が返している)*/
            else        g_tcp_ts_missing_drop++;      /* TS が無い(RFC 7323 3.2: 黙って捨てる)*/
            return;
        }
    }

    /* **シーケンスの受け入れ判定**(RFC 9293 3.10.7.4 first check)。受信窓 = 最後に広告した
     * 右端まで。窓の外のセグメントは(RST 以外)ACK を返して捨てる。以前はこの判定が無く、
     * 窓のはるか先のデータでも順序外の置き場へ入れていた。
     * **seq == RCV.NXT のときは判定を飛ばす**(ホットパス)。窓 0 でも RCV.NXT 上のセグメントは
     * ACK を処理する(3.10.7.4 の注: 窓 0 でも正しい ACK は受け付ける)。データは受け取れなければ
     * 下で捨てる(rx_nospace)。 */
    if (seq != conn->rcv_seq) {
        const uint32_t rcv = conn->rcv_seq;
        const uint32_t seg_len = seg_end - seq;
        uint32_t wnd;
        if (priv->rcv_wnd_valid) wnd = tcp_seq_gt(priv->rcv_wnd_edge, rcv) ? priv->rcv_wnd_edge - rcv : 0u;
        else                     wnd = 0xFFFFu;
        int ok;
        if (seg_len == 0u) ok = (wnd != 0u) && !tcp_seq_lt(seq, rcv) && tcp_seq_lt(seq, rcv + wnd);
        else               ok = (wnd != 0u) && tcp_seq_lt(seq, rcv + wnd) && tcp_seq_gt(seq + seg_len, rcv);
        if (!ok) {
            if (payload_len > 0u && !tcp_seq_gt(seq + payload_len, rcv)) {
                /* 全部受け取り済みのデータ(相手の無駄な再送)。DSACK で知らせる(RFC 2883)。 */
                g_tcp_rx_dup[core]++;
                tcp_dsack_note(priv, seq, seq + payload_len);
            }
            g_tcp_rx_oow_drop++;
            /* データも FIN も運ばないものへの ACK は頻度に上限(RFC 5961 7)。 */
            const int limited = (payload_len == 0u && !fin);
            if (tcp_send_oow_ack(conn, priv, limited, 0) && limited && tcp_seq_lt(seq, rcv)) {
                /* **相手の Keepalive probe(1 バイト過去の seq で 0 バイト)。** RFC 1122 4.2.3.6 は
                 * ACK を返すことを求める。返さないと相手はこちらが死んだと判断して接続を切る
                 * (Linux は既定で Keepalive を使う)。 */
                g_tcp_keepalive_reply_count++;
            }
            return;
        }
    }

    /* **ACK ビットの無いセグメントは捨てる**(RFC 9293 3.10.7.4 fifth: "if the ACK bit is off,
     * drop the segment and return")。SYN_RCVD も同じ。 */
    if (!(flags & TCP_FLAG_ACK)) {
        g_tcp_noack_drop++;
        return;
    }

    if (conn->state == TCP_SYN_RCVD) {
        /* 握手を終える ACK。**受け入れられない ACK には RST**(RFC 9293 3.10.7.4 SYN-RECEIVED)。 */
        if (ack != priv->expected_ack) {
            g_tcp_synsent_rst++;
            tcp_send_bare((const netaddr_t *)&conn->local_ip, conn->local_port,
                          (const netaddr_t *)&conn->remote_ip, conn->remote_port,
                          TCP_FLAG_RST, ack, 0u);
            return;
        }
        priv->snd_una = ack;
        priv->ack_received = 1;   /* 同時オープンの能動側は tcp_connect_poll() がこれを見る */
        conn->state = TCP_ESTABLISHED;
        tcp_cwnd_init(conn, priv);
        /* 送信窓はこのセグメントから(Window Scale は SYN で合意済み)。 */
        conn->snd_win = (uint32_t)rd16be(in + TCP_OFF_WINDOW) << (priv->wscale_enabled ? priv->snd_wscale : 0u);
        if (conn->snd_win > priv->snd_win_max) priv->snd_win_max = conn->snd_win;
        priv->snd_wl1 = seq;
        priv->snd_wl2 = ack;
        for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
            if (!s_listeners[li].in_use) continue;
            if (s_listeners[li].accept_conn == conn) {
                s_listeners[li].accept_ready = 1;  /* 受け皿へ直接受理した経路 */
                break;
            }
            int bp = tcp_backlog_index_of(&s_listeners[li], conn);
            if (bp >= 0) {
                /* 待ち行列の中で確立した。呼び出し側が受け皿を用意した
                 * 時点で tcp_accept_ready_poll() が引き渡す。 */
                s_listeners[li].pending_estab[bp] = 1;
                (void)__atomic_add_fetch(&s_backlog_estab_cnt[core], 1u, __ATOMIC_ACQ_REL);
                break;
            }
        }
        uart_printf("[TCP] accept: ESTABLISHED (peer MSS=%u, 初期cwnd=%u)\n",
                    conn->snd_mss, priv->cwnd);
        /* **この ACK に載ったデータと FIN も続けて処理する**(RFC 9293 3.10.7.4 SYN-RECEIVED:
         * "continue processing")。以前はここで終わり、データは相手の再送を待っていた。 */
    }

    /* **まだ送っていないものへの ACK は受け入れない**(RFC 9293 3.10.7.4 fifth、RFC 5961 5.2)。
     * ACK を返して捨てる(頻度に上限)。SND.NXT は snd_max で見る -- conn->snd_seq は tcp_send() の
     * 再送中は巻き戻っている。以前はこの検査が無く、偽の ACK で snd_una を送った量より先へ
     * 進められ、未確認の量が負(4G 近く)になって送信が止まった。 */
    if (tcp_seq_gt(ack, priv->snd_max)) {
        g_tcp_ack_unsent_drop++;
        (void)tcp_send_oow_ack(conn, priv, 1, 1);
        return;
    }

    /* 送信窓の更新(RFC 9293 3.10.7.4 fifth の SND.WL1 / WL2)。**古いセグメント(seq が前に
     * 窓を更新したものより前)では窓を戻さない。** 以前は届いた順に上書きしていたので、
     * 順序が入れ替わった古いセグメントが、開いた窓を閉じた値へ戻すことがあった。
     * 重複 ACK の判定には更新前の値が要る。 */
    const uint32_t prev_snd_win = conn->snd_win;
    if ((tcp_seq_lt(priv->snd_wl1, seq) ||
         (priv->snd_wl1 == seq && !tcp_seq_lt(ack, priv->snd_wl2))) &&
        !tcp_seq_lt(ack, priv->snd_una)) {
        uint32_t w = rd16be(in + TCP_OFF_WINDOW);
        if (priv->wscale_enabled) w <<= priv->snd_wscale;
        conn->snd_win = w;
        priv->snd_wl1 = seq;
        priv->snd_wl2 = ack;
        if (w > priv->snd_win_max) priv->snd_win_max = w;
    }

    /* ---- ACK の処理(同期済みの全状態で同じ。以前は ESTABLISHED だけが RTT / 回復 / PRR を
     * 見ていて、CLOSE_WAIT では snd_una しか進めていなかった)---- */
    if (ack == priv->expected_ack) {
        priv->ack_received = 1;  /* 単発の信頼送信(tcp_send_reliable())向け */
    }
    if (priv->tlp_active && ack == priv->snd_una) {
        /* 進まない ACK。probe が無駄だったと分かる DSACK か、情報の無い純 ACK で TLP を終える。 */
        tcp_tlp_on_ack(conn, priv, ack,
                       payload_len == 0 && priv->sack_gen == sack_gen0 && !priv->tlp_dsack);
    }
    if (tcp_seq_gt(ack, priv->snd_una)) {
        priv->snd_una = ack;     /* パイプライン送信(tcp_send())向け、累積ACKで進める */
        priv->ack_advanced = 1;
        priv->neigh_confirm = 1;   /* 上位層の到達確認(NUD)*/
        tcp_on_new_ack(priv, ack);
        /* **Timestamps があれば再送中でも RTT を測れる。** Karn の
         * アルゴリズム(再送したウィンドウの RTT は測らない)は
         * 「どちらの送信への ACK か分からない」ことへの対処なので、
         * TSecr で判別できるなら制約そのものが消える。 */
        uint64_t ack_now = 0;   /* 時刻を読んだら TLP の起点に使う(余分に読まない) */
        if (priv->ts_enabled && seg_tsecr != 0u) {
            ack_now = timer_now();
            uint32_t elapsed = (uint32_t)(ack_now >> 10) - seg_tsecr;   /* = tcp_ts_now() - TSecr */
            /* 異常値(相手が変な echo を返した)は捨てる。1.024us 刻みで
             * 10 秒ぶん(約 977 万)を超えたら採らない。 */
            if (elapsed < 10000000u) {
                tcp_rtt_update(priv, (uint64_t)elapsed << 10, ack_now);
                g_tcp_ts_rtt_samples++;
            }
        }
        if (priv->sack_enabled) {   /* TLP と PRR の手詰まりの判定の起点 */
            priv->tlp_ack_at = ack_now ? ack_now : timer_now();
        }
        if (priv->undo_valid) {
            /* **Eifel(RFC 3522)。** 送り直した範囲が全部 ACK されたとき、その ACK の TSecr が
             * 最初の送り直しより前の自分の時刻なら、相手は送り直しより前に送った元のセグメントで
             * 穴を埋めている = 送り直しは要らなかった(Linux の tcp_packet_delayed())。
             * **送り直した範囲の途中で判定しない** -- RACK が送り直すのは snd_una の位置とは限らず、
             * その手前の届いていたセグメントへの ACK は古い TSecr を返すので、本物のロスでも
             * undo してしまう(実測で 167 回)。 */
            if (priv->undo_ts_ok && seg_tsecr != 0u && priv->undo_retrans > 0u &&
                priv->retx_ts != 0u && !tcp_seq_lt(ack, priv->retx_end) &&
                (int32_t)(seg_tsecr - priv->retx_ts) < 0) {
                tcp_undo_do(conn, priv, 1);
            } else if (!priv->undo_ended) {
                /* 回復の範囲まで ACK されたら、後から来る DSACK を待つのはもう 1 往復だけ。 */
                if (!tcp_seq_lt(ack, priv->undo_high)) {
                    priv->undo_ended = 1;
                    priv->undo_limit = conn->snd_seq;
                }
            } else if (tcp_seq_gt(ack, priv->undo_limit)) {
                priv->undo_valid = 0;
            }
        }
        if (priv->retx_ts != 0u && !tcp_seq_lt(ack, priv->retx_end)) priv->retx_ts = 0;
        if (priv->tlp_active) tcp_tlp_on_ack(conn, priv, ack, 0);
    } else if (ack == priv->snd_una &&
               payload_len == 0 &&
               !fin &&
               conn->snd_win == prev_snd_win &&
               tcp_seq_gt(conn->snd_seq, priv->snd_una)) {
        /* RFC 5681 の重複 ACK の定義: 累積 ACK が進まず、データを運ばず、
         * SYN/FIN も無く、広告ウィンドウも変わっておらず、**未確認データが
         * 存在する**もの。
         *
         * 最後の条件(RFC 5681 の condition 1)を落とすと、このスタックでは
         * 誤検出が壊滅的になる。`tcp_recv_internal()` はアプリが受信バッファ
         * から読み出すたびにウィンドウ更新の純 ACK を送るが(tcp.c の
         * send_ack 経路)、広告ウィンドウは safe_window_cap で頭打ちなので
         * **ワイヤ上の値が変わらない** -- つまり「ack 据え置き・データ無し・
         * ウィンドウ不変」となり、条件 5 では弾けない。
         * 実測では、ロスがゼロのときでも重複 ACK を 419 万個・高速再送を
         * 10 万回誤検出していた。 */
        tcp_on_dup_ack(conn, priv);
    }
    if (priv->prr_active && priv->in_fast_recovery) {
        /* 届いた量 = 累積 ACK の進み + SACK 済みの増え(累積 ACK に吸われた SACK 済みは引かれる)。
         * SACK が無い相手は、重複 ACK 1 個を 1 MSS 届いたとみなす(RFC 6937)。 */
        int64_t d = (int64_t)(uint32_t)(priv->snd_una - prr_una0) +
                    (int64_t)tcp_sacked_bytes(priv) - (int64_t)prr_sacked0;
        if (!priv->sack_enabled && priv->snd_una == prr_una0 && payload_len == 0) d = conn->snd_mss;
        tcp_prr_on_ack(conn, priv, d > 0 ? (uint32_t)d : 0u);
    }
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log_tcp_ack(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 3), (uint8_t)tcp_conn_slot(conn),
                   seq, ack, conn->snd_win, flags);

    /* 自分の FIN が確認された(RFC 9293 3.10.7.4 fifth の各状態)。expected_ack は tcp_close() が
     * 送った FIN の次の seq。 */
    switch (conn->state) {
    case TCP_FIN_WAIT_1:
        if (!tcp_seq_lt(ack, priv->expected_ack)) conn->state = TCP_FIN_WAIT_2;
        break;
    case TCP_CLOSING:
        if (!tcp_seq_lt(ack, priv->expected_ack)) conn->state = TCP_TIME_WAIT;
        return;   /* 相手の FIN は受け取り済み(データも来ない)*/
    case TCP_LAST_ACK:
        /* tcp_close() が送った自分の FIN への ACK を待っている。 */
        if (!tcp_seq_lt(ack, priv->expected_ack)) {
            priv->ack_received = 1;
            conn->state = TCP_CLOSED;
        }
        return;
    case TCP_CLOSE_WAIT:
    case TCP_TIME_WAIT:
        return;   /* 相手の FIN は受け取り済み。データと FIN は来ない(来ても窓の外) */
    default:
        break;    /* ESTABLISHED / FIN_WAIT_1 / FIN_WAIT_2: データと FIN へ */
    }

    /* 緊急ポインタ(RFC 9293 3.8.5)。URG は滅多に来ないので分岐 1 つ。 */
    if (flags & TCP_FLAG_URG) tcp_urg_note(conn, priv, seq, rd16be(in + TCP_OFF_URGENT));

    /* FIN の位置(データの後ろ)。データを切り詰める前の seq で決める。 */
    const uint32_t fin_at = seq + payload_len;
    int ack_now_req   = 0;   /* すぐ ACK を返す理由がある(順序外 / 穴が埋まった / 受け取れない) */
    int accepted_inorder = 0;
    if (payload_len > 0) {
        uint32_t free_space = TCP_RX_BUF_SIZE - priv->rx_count;
        /* **先頭が受け取り済みの範囲にかかるセグメントは、新しい部分だけ受け取る**
         * (送り直しの区切りが前回と違うと、こういうセグメントが来る)。 */
        if (tcp_seq_lt(seq, conn->rcv_seq) && tcp_seq_lt(conn->rcv_seq, seq + payload_len)) {
            uint32_t d = conn->rcv_seq - seq;
            tcp_dsack_note(priv, seq, conn->rcv_seq);
            payload     += d;
            payload_len  = (uint16_t)(payload_len - d);
            seq          = conn->rcv_seq;
        }
        if (seq == conn->rcv_seq && (priv->recv_upcall || payload_len <= free_space)) {
            accepted_inorder = 1;
            tcp_deliver_data(priv, payload, payload_len);
            conn->rcv_seq += payload_len;
            /* 累積 ACK が進んだので、そこまでの区間は SACK で伝えない。 */
            if (priv->sack_tx_count) tcp_sack_tx_trim(priv, conn->rcv_seq);
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 5), tcp_conn_arg(conn, payload_len));

            /* 穴が埋まった。続きを順序外の列の先頭から渡す(列は seq の順)。 */
            while (priv->ooo_head != TCP_OOO_NONE) {
                uint16_t n = priv->ooo_head;
                uint32_t nseq = s_ooo_seq[n];
                uint32_t nend = nseq + s_ooo_len[n];
                if (tcp_seq_gt(nseq, conn->rcv_seq)) break;          /* まだ穴がある */
                ack_now_req = 1;   /* 穴が埋まった: すぐ ACK を返す(RFC 5681 4.2)*/
                if (!tcp_seq_lt(conn->rcv_seq, nend)) {              /* 全部受け取り済み */
                    smp_spin_lock(&s_ooo_lock);
                    priv->ooo_head = s_ooo_next[n];
                    tcp_ooo_node_free_locked(priv, n);
                    smp_spin_unlock(&s_ooo_lock);
                    continue;
                }
                uint32_t off = conn->rcv_seq - nseq;
                uint16_t nlen = (uint16_t)(nend - conn->rcv_seq);
                free_space = TCP_RX_BUF_SIZE - priv->rx_count;
                if (!priv->recv_upcall && nlen > free_space) break;  /* 読まれるのを待つ */
                tcp_deliver_data(priv, tcp_ooo_data(n) + off, nlen);
                conn->rcv_seq += nlen;
                smp_spin_lock(&s_ooo_lock);
                priv->ooo_head = s_ooo_next[n];
                tcp_ooo_node_free_locked(priv, n);
                smp_spin_unlock(&s_ooo_lock);
                if (priv->sack_tx_count) tcp_sack_tx_trim(priv, conn->rcv_seq);
            }
        } else if (seq == conn->rcv_seq) {
            g_tcp_rx_nospace[core]++;
            ack_now_req = 1;
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 6), tcp_conn_arg(conn, payload_len));
        } else if (tcp_seq_gt(seq, conn->rcv_seq) && payload_len <= TCP_MSS_LOCAL) {
            /* **順序外の到着はすぐ ACK を返す**(RFC 5681 4.2 / RFC 9293 3.10.7.4。相手の高速再送と
             * SACK の材料。以前は相乗りを頼んだ接続では借りにして遅らせていた)。 */
            ack_now_req = 1;
            int r = tcp_ooo_insert(priv, seq, payload, payload_len);
            if (r == 1) {
                if (priv->sack_enabled) tcp_sack_tx_add(priv, seq, payload_len);
                g_tcp_rx_ooo[core]++;
                /* ここは ts_log だけにしてある(順序外の到着は回復の途中で普通に起きるので、
                 * 1 セグメントごとにコンソールへ出すと受信が出力に支配される)。 */
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 7), tcp_conn_arg(conn, payload_len));
            } else if (r == 0) {
                g_tcp_rx_dup[core]++;    /* 全部持っていた */
                tcp_dsack_note(priv, seq, seq + payload_len);
            } else {
                if (r == -3) g_tcp_rx_ooo_pool_drop[core]++;
                g_tcp_rx_ooo_drop[core]++;
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 8), tcp_conn_arg(conn, payload_len));
                /* 表示は 1, 2, 4, 8 .. 回目だけ(溢れ続けると受信が出力に支配される)。 */
                uint32_t nd = g_tcp_rx_ooo_drop[core];
                if ((nd & (nd - 1u)) == 0u) {
                    uart_printf("[!] TCP: 順序外のセグメントを破棄(%s、接続の使用 %u / 予算 %u バイト、%u 個)"
                                "(seq=%u rcv_seq=%u len=%u、%u 回目)\n",
                                (r == -2) ? "陰性対照の 64 個" : (r == -3) ? "共有の置き場が尽きた" : "接続の予算を超えた",
                                (unsigned)priv->ooo_bytes, (unsigned)g_tcp_rcvbuf, priv->ooo_count,
                                seq, conn->rcv_seq, payload_len, (unsigned)nd);
                }
            }
            /* 順序外の FIN: 位置を覚え、穴が埋まったら処理する(データを置けたときだけ)。 */
            if (fin && r >= 0) { priv->fin_pend = 1; priv->fin_pend_seq = fin_at; }
        } else if (tcp_seq_gt(seq, conn->rcv_seq)) {
            ack_now_req = 1;
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 9), tcp_conn_arg(conn, payload_len));
        } else {
            g_tcp_rx_dup[core]++;   /* 既に受け取った範囲(受け入れ判定を通った後なので普通は来ない)*/
            tcp_dsack_note(priv, seq, seq + payload_len);
            ack_now_req = 1;
        }
    } else if (fin && tcp_seq_gt(fin_at, conn->rcv_seq)) {
        /* データの無い FIN が穴の向こうに来た: 位置を覚える。 */
        priv->fin_pend     = 1;
        priv->fin_pend_seq = fin_at;
        ack_now_req = 1;
    }

    /* ---- FIN(RFC 9293 3.10.7.4 eighth)。**その前のデータを全部受け取ったときだけ**処理する。
     * このセグメントの FIN か、前に覚えた順序外の FIN の位置に rcv_seq が届いたか。 ---- */
    if ((fin && fin_at == conn->rcv_seq) ||
        (priv->fin_pend && priv->fin_pend_seq == conn->rcv_seq)) {
        tcp_fin_accept(conn, priv);   /* ACK も返す */
        return;
    }
    if (fin) ack_now_req = 1;          /* FIN を受け取れなかった(穴 / 空き無し): 今の位置を知らせる */
    if (payload_len == 0 && !ack_now_req) return;   /* 純 ACK: 返すものは無い */

    /* **「ちょうどフルサイズのときだけ間引く」ではいけない。**
     * NVMe/TCP の PDU は 4120B / 8240B のように MSS(9204)ちょうどには
     * ならないので、この条件だと**間引きが一度も効かず毎セグメント
     * ACK を返す**ことになる。実測で、相手が送るデータセグメント
     * 1 個につき **1.22 個の ACK** を返しており(Linux の遅延 ACK なら
     * 0.5)、**相手の CPU をこちらの ACK 処理で食い潰していた**
     * (4K read で相手の cpu0 が 100%)。
     *
     * 受け取ったセグメントの大きさによらず数えて、
     * `g_tcp_ack_threshold` 個ごとに 1 回返す。**遅らせても止まらない
     * のは、次のコマンドを送るときに ACK が相乗りするから**
     * (確立後のセグメントは常に ACK ビットを立てる)。
     * `ackthresh 1` が従来の挙動 = 陰性対照。
     *
     * **ただし小さいセグメントは即 ACK する。** 間引く対象を大きさで
     * 絞らないと、write の応答 PDU(24 バイト)まで待たせてしまい
     * 512B write が 5〜8% 落ちる。閾値は MSS の 1/8
     * (`g_tcp_ack_min_seg` で調整可能。0 = 大きさを見ない)。 */
    uint32_t ack_min = (g_tcp_ack_min_seg != 0u)
                     ? g_tcp_ack_min_seg : (uint32_t)(conn->snd_mss / 8u);
    uint32_t ack_th = priv->ack_thin_off ? 1u : g_tcp_ack_threshold;
    if (priv->dsack_valid || ack_now_req) {
        /* **DSACK はすぐ純 ACK で返す。** SACK のブロックはデータを運ばないセグメントにしか
         * 載らないので、応答への相乗りや間引きを待つと届かない。順序外の到着・穴が埋まった
         * ときも同じくすぐ返す(RFC 5681 4.2)。 */
        tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        priv->unacked_full_segments = 0;
    } else if (accepted_inorder && payload_len >= ack_min) {
        priv->unacked_full_segments++;
        if (priv->unacked_full_segments >= ack_th) {
            if (priv->ack_hold_thin) tcp_ack_thin_note(priv, core, 0);
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            priv->unacked_full_segments = 0;
        } else if (g_tcp_ack_hold != 0u && priv->ack_deferred == 0u) {
            /* **返していない ACK の期限。** 最初に返さなかったセグメントから数えて
             * 受信の周回 g_tcp_ack_hold 回で tcp_ack_flush_deferred() が返す(延長はしない)。
             * こちらから何か送れば相乗りして消える。ackhold 0(周回の上限なし)でも、
             * 冷たい経路が TCP_DELACK_MAX_MS で必ず返す(tcp_cold_check()、MUST-40)。 */
            priv->ack_deferred = (uint8_t)((g_tcp_ack_hold > 255u) ? 255u : g_tcp_ack_hold);
            priv->ack_hold_thin = 1;
            s_ack_deferred_any[core] = 1;
        }
    } else if (g_tcp_ack_piggyback && priv->ack_piggy_ok) {
        /* **応答へ相乗りさせる。** 相乗りを頼んだコネクション(nvmet の IO
         * キュー、`iscsit ackpiggy on`)は受け取ったものに対して必ず応答を
         * 出すので、ここで裸の ACK を出すと 1 コマンドが 2 パケットになる。
         * 以前は upcall を持つことも条件にしていて、**受信を pull で読む
         * iSCSI ターゲットでは一度も効いていなかった**(SPEC 17.14)。
         * 応答は同じ tick のうちに出て ACK を運ぶので、**遅延は
         * 増えない**。応答が出なかったときは呼び出し側が
         * `tcp_ack_flush()` で必ず吐き出す(下の nvmet の排出ループ)。 */
        priv->ack_deferred = (uint8_t)((g_tcp_ack_piggyback > 255u)
                                       ? 255u : g_tcp_ack_piggyback);
        s_ack_deferred_any[core] = 1;
        priv->unacked_full_segments = 0;
    } else {
        tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        priv->unacked_full_segments = 0;
    }
}

/*=================================================================
 * IPv4 用の受信入口。ip_handle_frame() から呼ばれ、アドレスを netaddr_t へ
 * 包んで共通処理へ渡すだけ。宛先はアクティブなインターフェースの IPv4
 * (ip.c が宛先一致を確認済みなのでそれと同じ値になる)。
 *
 * 引数:
 *   pkt / len - TCP セグメント
 *   src_ip    - 送信元 IPv4(ホストバイトオーダー)
 * コール元:
 *   ip_handle_frame()
 * ===============================================================*/
void tcp_input(const uint8_t *pkt, uint16_t len, uint32_t src_ip)
{
    netaddr_t src = netaddr_v4(src_ip);
    /* 宛先は「アクティブなインターフェースの IPv4」なので、実際に必要になる
     * 場面(受動 open / SW チェックサム)まで組み立てを遅らせる。 */
    tcp_input_addr(pkt, len, &src, NULL);
}
