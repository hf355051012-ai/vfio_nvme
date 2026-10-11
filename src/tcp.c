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

/* 受信側で保持する「届いている区間」の数。穴の数だけあればよく、実際には
 * 1〜2 個しか使わない。溢れたら古いものを捨てる(相手が余分に送り直す
 * だけで、正しさは失われない)。 */
#define TCP_SACK_TX_MAX        4u

#define TCP_MSS_LOCAL           10182u
#define TCP_MSS_DEFAULT_RFC879   536u  /* 相手がMSSオプションを付けなかった場合の既定値 */

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

#define TCP_RCV_WSCALE 4u

#define TCP_INITIAL_RTO_MS      500u
#define TCP_RTO_MIN_MS           200u
#define TCP_MAX_RTO_MS         8000u
#define TCP_MAX_RETRIES            5

/* RFC 5681 の Fast Retransmit は重複 ACK 3 個で発火する。3 未満にすると
 * 単なる順序入れ替えを損失と誤検出して無駄な再送が増える。 */
#define TCP_DUP_ACK_THRESHOLD      3u

#define TCP_SEND_OVERALL_TIMEOUT_MS 30000u  /* tcp_send()全体(複数セグメント/再送込み)の上限 */
#define TCP_CLOSE_FIN_WAIT_MS        2000u  /* 自分のFINがACKされた後、相手のFINを待つ時間 */

#define TCP_OOO_SLOTS 64u

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

volatile uint32_t g_tcp_retransmit_count[SMP_MAX_CORES];

/* 高速再送で実際に送り直したセグメント数。g_tcp_retransmit_count(全再送)の
 * 内数なので、差が RTO 由来の再送になる。「RTO ではなく 3 dup ACK で再送された」
 * ことを実機で確認するための計測点。再送を要求した回数ではなく**送った回数**を
 * 数える(要求だけ立って未確認データが無く空振りした分を混ぜないため)。 */
volatile uint32_t g_tcp_fast_retransmit_count[SMP_MAX_CORES];

/* 受信した重複 ACK の総数。高速再送の発火数と突き合わせると、検出が
 * 効きすぎていないか(1 回のロスに対し何回入り直しているか)が分かる。 */
volatile uint32_t g_tcp_dup_ack_count[SMP_MAX_CORES];

/* **既定 1(= 受信セグメントごとに ACK)。** 4 にすると相手の ACK 処理は
 * 減るが、**得か損かは相手が飽和しているかで逆になる**:
 *
 * | | 相手の状態 | ackthresh 4 の効果 |
 * |---|---|---|
 * | 方向A(自製=イニシエータ、相手 nvmet)| **cpu0 が 100%** | **+12〜38%** |
 * | 方向B(自製=ターゲット、相手 nvme-tcp)| 余裕あり(25〜32%)| **-7〜10%** |
 *
 * **相手に余裕があるときは、ACK を間引くと送信の駆動(ACK clocking)が
 * 粗くなって損をする。** 既定は 1 にして退行させず、**相手が飽和して
 * いると分かっている条件でだけ `ackthresh 4` を使う。** */
volatile uint32_t g_tcp_ack_threshold = 1u;

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

/* Keepalive(RFC 1122 4.2.3.6)。**既定値は慣例どおり 2 時間 + 75 秒 x 9 回**。
 * 短くすると「無通信だが生きている」正常な接続を切ってしまうので、
 * 検証のとき以外は縮めないこと(`keepalivetest` は必ず元へ戻す)。
 *
 * ソケット API のある OS では SO_KEEPALIVE で個別に有効化する慣例だが、
 * このスタックにはソケットオプションが無いので既定で有効にしてある
 * (2 時間の無通信を検出するだけなので実害が無い)。 */
volatile uint32_t g_tcp_keepalive_enable   = 1u;
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

/* 順序入れ替わりセグメント1件分の保持スロット(tcp_priv_t.ooo[]参照)。 */
typedef struct {
    volatile int      valid;
    volatile uint32_t seq;
    uint8_t           buf[TCP_MSS_LOCAL];
    volatile uint16_t len;
} tcp_ooo_slot_t;

typedef struct {
    uint32_t seq;      /* このセグメントの先頭seq */
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_MAX_LEN];
    const uint8_t *ref;
    uint64_t sent_at;  /* 直近の送信(初回または再送)時刻 */
    uint32_t rto_ms;
    int      retries;
} tcp_async_slot_t;

typedef struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_SHORT_SLOT_BYTES];
    uint64_t sent_at;
    uint32_t rto_ms;
    int      retries;
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

    /* Timestamps(RFC 7323)。SYN の交換で双方が出したときだけ有効になる。
     * ts_recent は相手へ echo し返す値、ts_last_ack_sent は「どこまで ACK した
     * 時点の ts_recent か」(R3 の更新条件に要る)。 */
    uint8_t           ts_enabled;
    uint32_t          ts_recent;
    uint32_t          ts_last_ack_sent;

    /* SACK(RFC 2018)。SYN で双方が SACK-Permitted を出したときだけ有効。
     * sack_rx[] は**相手が「届いた」と言ってきた範囲**(送信側の scoreboard)で、
     * 高速再送のときにここに入っている範囲を送り直さない。 */
    uint8_t           sack_enabled;
    uint8_t           sack_rx_count;
    struct { uint32_t start, end; } sack_rx[TCP_SACK_MAX_BLOCKS];
    /* 有効な ooo スロットの数。**純 ACK ごとに 64 スロットを走査しない**ため
     * だけに持つ(0 なら SACK ブロックの組み立てを丸ごと省ける)。 */
    unsigned          ooo_count;

    /* 受信側として相手へ知らせる「届いている区間」。**順序不正セグメントを
     * 置くたびに差分で更新する。** 送るたびに ooo[] 64 スロットから作り直すと
     * 結合が O(n^3) になり、順序不正が数十個たまる read の経路で実測 2.5 倍
     * 遅くなった(ACK 1 個ごとに 2 回呼ばれるため)。 */
    uint8_t           sack_tx_count;
    uint8_t           sack_tx_recent;  /* 直近に触った添字(先頭に置く) */
    struct { uint32_t start, end; } sack_tx[TCP_SACK_TX_MAX];

    /* Keepalive(RFC 1122 4.2.3.6)。**受信のたびに時刻を書かない** --
     * ホットパスに置くのは「何か届いた」という 1 バイトの旗だけで、
     * 時刻の読み出しと期限の判定は冷たい経路(tcp_keepalive_check())で行う。
     *
     * **D7 の「既にあるカウンタを冷たい経路から観測する」手はここでは使えない。**
     * probe への応答は**データを運ばない純 ACK**なので、rcv_seq も snd_una も
     * 進まない -- 既存のどのカウンタにも痕跡が残らない。スナップショット方式で
     * 作ったところ、**応答が返っているのに接続を切った**(陰性対照で判明)。 */
    volatile uint8_t  ka_seen;         /* 何か受け取った(冷たい経路が消費する) */
    uint64_t          ka_idle_since;   /* 無通信になった時刻(0=まだ初期化前) */
    uint32_t          ka_probes;       /* 応答が無いまま送った probe の数 */

    uint32_t          unacked_full_segments;

    /* **ACK の相乗り(piggyback)。** 受信のたびに裸の ACK を別セグメントで
     * 返すと、応答 PDU と合わせて 1 コマンド 2 パケットになる。応答は
     * 同じ tick のうちに出るので、**裸の ACK を出さずに応答へ載せれば
     * 遅延を増やさずにパケットを半減できる**(kernel nvmet は 1 コマンド
     * あたり 0.27〜0.37 パケットなのに対し自製は 1.18〜2.00 だった)。
     * upcall を持つコネクション(= 応答が必ず出る)だけで使う。 */
    uint8_t           ack_deferred;   /* 残り何周まで借りておけるか(0=借り無し)*/
    uint8_t           ack_piggy_ok;   /* このコネクションで相乗りしてよいか */

    uint32_t          unacked_consumed_bytes;

    /* 直近に広告した (ACK 番号, ウィンドウ)。両方とも前回と同じウィンドウ更新
     * ACK は相手に伝える情報がゼロなので送らない(tcp_recv_internal())。 */
    uint32_t          last_ack_sent;
    uint16_t          last_win_sent;

    tcp_ooo_slot_t ooo[TCP_OOO_SLOTS];

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

#define TCP_TIMEWAIT_MAX 4u
#define TCP_TIMEWAIT_MS  4000u  /* TCP_CLOSE_FIN_WAIT_MSより十分長い安全マージン */

typedef struct {
    int       in_use;
    netaddr_t local_ip;
    uint16_t  local_port;
    netaddr_t remote_ip;
    uint16_t  remote_port;
    uint32_t local_seq;      /* 応答ACKのSEQフィールドに使う自分のFIN後のseq(不変) */
    uint64_t started_ticks;  /* TIME_WAIT開始時刻(TCP_TIMEWAIT_MS、timeout_ms()で判定) */
} tcp_timewait_t;

#define TCP_TIMEWAIT_TOTAL (TCP_TIMEWAIT_MAX * SMP_MAX_CORES)
static tcp_timewait_t s_timewait[TCP_TIMEWAIT_TOTAL];
static smp_spinlock_t s_timewait_lock;

/*=================================================================
 * TIME_WAIT テーブルから 4-tuple が一致するエントリを探す。閉じた直後の
 * コネクション宛に届いた再送セグメントへ ACK を返すために使う。
 *
 * 引数:
 *   remote_ip / remote_port / local_port - 探す 4-tuple
 * 戻り値:
 *   見つかったエントリ。無ければ NULL
 * コール元:
 *   tcp_input()
 * ===============================================================*/
static tcp_timewait_t *tcp_timewait_find(const netaddr_t *remote_ip, uint16_t remote_port, uint16_t local_port)
{
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use &&
            netaddr_eq(&s_timewait[i].remote_ip, remote_ip) &&
            s_timewait[i].remote_port == remote_port &&
            s_timewait[i].local_port == local_port) {
            smp_spin_unlock(&s_timewait_lock);
            return &s_timewait[i];
        }
    }
    smp_spin_unlock(&s_timewait_lock);
    return NULL;
}

/*=================================================================
 * クローズしたコネクションを TIME_WAIT テーブルへ登録する(スロットを
 * 解放した後も、相手の再送に ACK を返せるようにするため)。
 *
 * 引数:
 *   local_ip / local_port / remote_ip / remote_port - 4-tuple
 *   snd_seq / rcv_seq - 応答 ACK に使うシーケンス番号
 * コール元:
 *   tcp_close()
 * ===============================================================*/
static void tcp_timewait_register(const netaddr_t *local_ip, uint16_t local_port,
                                   const netaddr_t *remote_ip, uint16_t remote_port,
                                   uint32_t local_seq)
{
    smp_spin_lock(&s_timewait_lock);
    int slot = -1;
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (!s_timewait[i].in_use) { slot = (int)i; break; }
    }
    if (slot < 0) slot = 0;  /* 空きが無ければ一番古い(先頭)のエントリを再利用する */
    s_timewait[slot].in_use       = 1;
    s_timewait[slot].local_ip     = *local_ip;
    s_timewait[slot].local_port   = local_port;
    s_timewait[slot].remote_ip    = *remote_ip;
    s_timewait[slot].remote_port  = remote_port;
    s_timewait[slot].local_seq    = local_seq;
    s_timewait[slot].started_ticks = timer_now();
    smp_spin_unlock(&s_timewait_lock);
}

/*=================================================================
 * 期限切れの TIME_WAIT エントリを掃除する(ポーリングのたびに呼ぶ軽量処理)。
 *
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
static void tcp_timewait_reap(void)
{
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use && timeout_ms(s_timewait[i].started_ticks, TCP_TIMEWAIT_MS)) {
            s_timewait[i].in_use = 0;
        }
    }
    smp_spin_unlock(&s_timewait_lock);
}

/* リスナ 1 本あたりの待ち行列(listen backlog)の深さ。呼び出し側が
 * tcp_accept_begin() で受け皿を用意していない間に届いた SYN を、ここに
 * 積んで先に確立まで進めておく。積まずに捨てると相手の SYN 再送
 * (Linux の初期値は 1 秒)ぶんだけ接続確立が遅れる。 */
#define TCP_BACKLOG 4u

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
#define TCP_ZWP_INTERVAL_MS 200u
volatile uint64_t g_tcp_zwp_count;

static void tcp_window_probe(tcp_conn_t *conn, tcp_priv_t *priv, uint64_t *since, int stuck)
{
    if (!stuck) {
        *since = 0;
        return;
    }
    if (*since == 0) {
        *since = timer_now();
        return;
    }
    if (!timeout_ms(*since, TCP_ZWP_INTERVAL_MS)) return;
    uint32_t saved = conn->snd_seq;
    conn->snd_seq = priv->snd_una - 1u;
    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
    conn->snd_seq = saved;
    g_tcp_zwp_count++;
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
static void tcp_rtt_update(tcp_priv_t *priv, uint64_t measured_ticks)
{
    g_tcp_rtt_update_count++;
    uint64_t measured_us = ticks_to_us(measured_ticks);

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

static uint8_t s_seg_bufs[SMP_MAX_CORES][ETH_TX_RING_SIZE][TCP_SEG_BUF_SIZE]
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
static uint16_t tcp_wire_window(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags)
{
    uint32_t ring_capacity_bytes = (uint32_t)net_active_rx_ring_size() * (uint32_t)conn->snd_mss;
    uint32_t safe_window_cap = (ring_capacity_bytes >= TCP_RX_BUF_SIZE)
                                   ? TCP_RX_BUF_SIZE
                                   : (ring_capacity_bytes / 2u);
    /* **順序不正で保持できる量より大きなウィンドウを広告しない。**
     * rx_buf(16MB)は「順番どおり届いたデータ」の置き場で、穴が空いている
     * 間に届く先のデータは ooo[] の 64 スロットにしか置けない。広告値だけ
     * 大きいと、穴が 1 つできた瞬間に**受信側が自分で捨てる**ことになり、
     * その損失は相手からは見えない(SACK では再送されず RTO 待ちになる)。
     * 実測で 4136 個を捨てていた。 */
    uint32_t ooo_capacity = (uint32_t)TCP_OOO_SLOTS * (uint32_t)conn->snd_mss;
    if (safe_window_cap > ooo_capacity) safe_window_cap = ooo_capacity;
    uint32_t actual_window = TCP_RX_BUF_SIZE - priv->rx_count;
    if (actual_window > safe_window_cap) actual_window = safe_window_cap;
    if ((flags & TCP_FLAG_SYN) || !priv->wscale_enabled) {
        return (actual_window > 0xFFFFu) ? 0xFFFFu : (uint16_t)actual_window;
    }
    uint32_t scaled = actual_window >> TCP_RCV_WSCALE;
    return (scaled > 0xFFFFu) ? 0xFFFFu : (uint16_t)scaled;
}

typedef struct { uint32_t start, end; } tcp_sack_range_t;

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
    if (priv->sack_tx_count == 0u) return 0;

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
    /* **SACK ブロックはデータを運ばないセグメントにだけ載せる。**
     * conn->snd_mss は SYN のときに決めた固定値なので、データを積んだ
     * セグメントでオプションを増やすとリンク MTU を超えてしまう
     * (Linux は毎回 MSS を計算し直すが、この実装はそうしていない)。
     * ロスがあるときの受信側は純 ACK を出しているので実用上これで足りる。 */
    if (priv->sack_enabled && data_len == 0u && (flags & TCP_FLAG_ACK)) {
        unsigned n = tcp_sack_block_count(priv, conn);
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
            tcph[o + 3] = TCP_RCV_WSCALE;  /* shift count */
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
        wr32be(tcph + o + 4, tcp_ts_now());
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
    if (o < end && priv->sack_enabled && data_len == 0u && (flags & TCP_FLAG_ACK)) {
        tcp_sack_range_t blk[TCP_SACK_MAX_BLOCKS];
        unsigned n = tcp_sack_collect(priv, conn, blk);
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

    /* **確立後のセグメントは必ず ACK ビットを立てて現在の rcv_seq を運ぶ**
     * ので、借りていた ACK はこれで返せる(相乗り)。 */
    priv->ack_deferred = 0;

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
    uint8_t *seg_buf = s_seg_bufs[core][slot];

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
    uint16_t wire_window = tcp_wire_window(conn, priv, flags);
    wr16be(tcph + TCP_OFF_WINDOW, wire_window);
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
    uint8_t  opt_len = tcp_options_len(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, 1u);
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
    uint8_t *seg_buf = s_seg_bufs[core][slot];

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

    uint32_t ring_capacity_bytes = (uint32_t)ETH_RX_RING_SIZE * (uint32_t)conn->snd_mss;
    uint32_t safe_window_cap = ring_capacity_bytes / 2u;
    /* tcp_wire_window() と同じ理由で ooo[] の容量で頭打ちにする。 */
    uint32_t ooo_capacity = (uint32_t)TCP_OOO_SLOTS * (uint32_t)conn->snd_mss;
    if (safe_window_cap > ooo_capacity) safe_window_cap = ooo_capacity;
    uint32_t actual_window = TCP_RX_BUF_SIZE - priv->rx_count;
    if (actual_window > safe_window_cap) actual_window = safe_window_cap;
    uint16_t wire_window;
    if (!priv->wscale_enabled) {
        wire_window = (actual_window > 0xFFFFu) ? 0xFFFFu : (uint16_t)actual_window;
    } else {
        uint32_t scaled = actual_window >> TCP_RCV_WSCALE;
        wire_window = (scaled > 0xFFFFu) ? 0xFFFFu : (uint16_t)scaled;
    }
    wr16be(tcph + TCP_OFF_WINDOW, wire_window);
    wr16be(tcph + TCP_OFF_URGENT, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */
    tcp_build_options(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, tcph, opt_len, 1u);

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
static void tcp_send_bare(const netaddr_t *local_ip, uint16_t local_port,
                           const netaddr_t *remote_ip, uint16_t remote_port,
                           uint8_t flags, uint32_t seq, uint32_t ack)
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

    unsigned slot = eth_tx_wait_free_slot();
    uint8_t *seg_buf = s_seg_bufs[core][slot];

    unsigned l4_off = tcp_l4_off(remote_ip);
    tcp_build_l3(seg_buf, local_ip, remote_ip, dst_mac, TCP_HDR_LEN);

    volatile uint8_t *tcph = seg_buf + l4_off;
    wr16be(tcph + TCP_OFF_SRC_PORT, local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, remote_port);
    wr32be(tcph + TCP_OFF_SEQ, seq);
    wr32be(tcph + TCP_OFF_ACK, ack);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((TCP_HDR_LEN / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = flags;
    wr16be(tcph + TCP_OFF_WINDOW, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);
    wr16be(tcph + TCP_OFF_URGENT, 0);

    uint16_t csum = tcp_checksum(local_ip, remote_ip, tcph, TCP_HDR_LEN, NULL, 0, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    eth_frag_t frag;
    frag.data = seg_buf;
    frag.len  = (uint16_t)(l4_off + TCP_HDR_LEN);

    dcache_clean_range(seg_buf, frag.len);
    eth_send_frags_async(&frag, 1u);
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
                               uint32_t seq, uint32_t ack)
{
    tcp_send_bare(local_ip, local_port, remote_ip, remote_port,
                   TCP_FLAG_ACK, seq, ack);
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
 * 非同期送信(tcp_send_async)キューの背後処理。届いた ACK で確認済みの
 * スロットを解放し、RTO を超えた未確認スロットを再送する。呼び出し元は
 * 一切ブロックされない。
 *
 * 引数:
 *   conn / priv - 対象コネクションとプライベート状態
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
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
            priv->async_head = (priv->async_head + 1u) % priv->async_cap;
            priv->async_count--;
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
                fr_sent++;
                rs->sent_at = fr_now;
            }
            if (fr_sent == 0u) g_tcp_fr_empty++;
            conn->snd_seq = fr_saved_snd_seq;
            return;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;  /* まだRTO未満、様子見(呼び出し元はブロックしていない) */
        }

        s->retries++;
        if (s->retries > TCP_MAX_RETRIES) {
            uart_printf("[!] TCP: tcp_send_async再送上限到達、ACK確認できず (seq=%u len=%u)\n",
                        s->seq, (unsigned)s->len);
            conn->snd_seq = priv->snd_una;
            priv->async_head  = 0;
            priv->async_count = 0;
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            return;
        }
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
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
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
            priv->async_short_head = (priv->async_short_head + 1u) % g_tcp_async_short_cap;
            priv->async_short_count--;
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
                rs->sent_at = fr_now;
            }
            conn->snd_seq = fr_saved_snd_seq;
            return;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;
        }

        s->retries++;
        if (s->retries > TCP_MAX_RETRIES) {
            uart_printf("[!] TCP: tcp_send_async(short)再送上限到達、ACK確認できず (seq=%u len=%u)\n",
                        s->seq, (unsigned)s->len);
            conn->snd_seq = priv->snd_una;
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            priv->async_head  = 0;
            priv->async_count = 0;
            return;
        }
        g_tcp_retransmit_count[smp_core_index()]++;
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_short_poll, 1), tcp_conn_arg(conn, (uint32_t)s->retries));

        uint32_t saved_snd_seq = conn->snd_seq;
        conn->snd_seq = s->seq;
        tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, s->buf, s->len);
        if (!priv->sack_enabled) priv->dup_ack_suppress++;
        g_tcp_retransmit_segs++;
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
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
 * 「相手が生きているか」は **rcv_seq(データが届いた)と snd_una(ACK が
 * 届いた)が進んだか**で判定する -- 受信のたびに時刻を書くとホットパスに
 * 時計が乗るため(A2 / D7 と同じ方針)。進まなくなってから idle_ms が
 * 過ぎたら probe を送り、intvl_ms ごとに繰り返して probes 回で諦める。
 *
 * **未確認データがある接続には probe を送らない。** そちらは RTO の担当で、
 * 重ねて叩いても意味が無い(相手の ACK を重複 ACK と数える経路にも触れる)。
 *
 * 引数:
 *   core - 対象コア(自分のコネクションスロットだけ見る)
 * コール元:
 *   tcp_poll_once_ex()
 * ===============================================================*/
static void tcp_keepalive_check(unsigned core)
{
    uint64_t now = timer_now();
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        tcp_conn_t *cn = s_conns[core][i];
        if (cn == NULL || cn->state != TCP_ESTABLISHED) continue;
        tcp_priv_t *priv = &s_priv[core][i];

        /* 相手から何か来ていれば「生きている」。**probe への応答は純 ACK
         * なので、データや累積 ACK の進みでは検出できない**(旗を使う理由)。 */
        if (priv->ka_seen || priv->ka_idle_since == 0) {
            priv->ka_seen       = 0;
            priv->ka_idle_since = now;
            priv->ka_probes     = 0;
            continue;
        }
        /* 未確認データがあるなら RTO の担当。 */
        if (tcp_seq_gt(cn->snd_seq, priv->snd_una)) continue;

        uint32_t wait_ms = (priv->ka_probes == 0) ? g_tcp_keepalive_idle_ms
                                                  : g_tcp_keepalive_intvl_ms;
        if (!timeout_ms(priv->ka_idle_since, wait_ms)) continue;

        if (priv->ka_probes >= g_tcp_keepalive_probes) {
            uart_printf("[TCP] keepalive: 応答が %u 回無いのでコネクションを畳みます "
                        "(local_port=%u remote_port=%u)\n",
                        (unsigned)priv->ka_probes, cn->local_port, cn->remote_port);
            g_tcp_keepalive_drop_count++;
            cn->state = TCP_CLOSED;
            s_conns[core][i] = NULL;
            continue;
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
}

static void tcp_poll_once_ex(int check_ctrl_c)
{
    unsigned core = smp_core_index();

    if (check_ctrl_c && uart_check_ctrl_c()) {
        s_abort_requested = 1;
    }

    net_poll_all_and_dispatch();

    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] != NULL) {
            tcp_async_poll(s_conns[core][i], &s_priv[core][i]);
            tcp_async_short_poll(s_conns[core][i], &s_priv[core][i]);
        }
    }

    tcp_timewait_reap();

    /* 待ち行列の掃除と Keepalive は秒〜時間単位の話なので、ポーリング 1 回
     * ごとに走査する必要はない(この関数は受信ポーリングのたびに通る)。
     * 時刻の読み出しもこの中に閉じ込める。 */
    static unsigned s_cold_tick;
    if ((++s_cold_tick & 0xFFu) == 0u) {
        tcp_backlog_reap();
        if (g_tcp_keepalive_enable) tcp_keepalive_check(core);
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
    for (int attempt = 0; attempt <= TCP_MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            g_tcp_retransmit_count[smp_core_index()]++;
            uart_printf("[TCP] 再送 (%d/%d, RTO=%ums)\n", attempt, TCP_MAX_RETRIES, rto_ms);
        }
        uint64_t sent_at = timer_now();
        if (tcp_send_segment(conn, priv, flags, data, data_len) != 0) {
            return -1;  /* 送信自体の失敗(ARP解決失敗等)は再送しても無駄 */
        }

        do {
            tcp_poll_once();
            if (tcp_abort_requested()) {
                return -1;  /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照) */
            }
            if (priv->ack_received) {
                if (attempt == 0) {
                    tcp_rtt_update(priv, timer_now() - sent_at);
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
 *   out_tsecr   - 相手が echo してきた自分の TSval(RTT 計測用)
 * 戻り値:
 *   1=処理を続けてよい、0=PAWS で破棄した
 * コール元:
 *   tcp_input_addr()
 * ===============================================================*/
static int tcp_input_options(tcp_conn_t *conn, tcp_priv_t *priv,
                              const volatile uint8_t *in, uint8_t hdr_len,
                              uint32_t seq, uint32_t *out_tsecr)
{
    if (hdr_len <= TCP_HDR_LEN) return 1;  /* 相手が付けてこなかった */

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
                priv->sack_rx_count = (uint8_t)n;
                g_tcp_sack_rx_count++;
                for (unsigned b = 0; b < n; b++) {
                    priv->sack_rx[b].start = rd32be(o + i + 2 + 8u * b);
                    priv->sack_rx[b].end   = rd32be(o + i + 6 + 8u * b);
                }
            }
            i = (uint8_t)(i + l);
        }
        /* Timestamps が無効(SACK だけ合意)か、合意したのに付いていない
         * ときはここで終わり。PAWS は Timestamps があってこそ。 */
        if (!found) return 1;
    }

    /* R1: TSval が TS.Recent より古ければ「一周した古いセグメント」。
     * ACK を返して破棄する(相手にこちらの状態を伝えるため)。 */
    if ((int32_t)(tsval - priv->ts_recent) < 0) {
        g_tcp_paws_drop_count++;
        tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        return 0;
    }

    /* R3: ACK 済みの範囲に続くセグメントのときだけ TS.Recent を進める
     * (順序不正のセグメントで進めると、後から届く正しいものを弾いてしまう)。 */
    if (!tcp_seq_lt(priv->ts_last_ack_sent, seq)) {
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
    priv->ts_enabled       = 0;
    priv->ts_recent        = 0;
    priv->ts_last_ack_sent = 0;
    priv->sack_enabled     = 0;
    priv->sack_rx_count    = 0;
    priv->sack_tx_count    = 0;
    priv->sack_tx_recent   = 0;
    priv->ka_seen          = 0;
    priv->ka_idle_since    = 0;
    priv->ka_probes        = 0;
    priv->ooo_count        = 0;
    priv->unacked_full_segments = 0;
    priv->unacked_consumed_bytes = 0;
    priv->last_ack_sent = 0;
    priv->last_win_sent = 0;
    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
        priv->ooo[i].valid = 0;
    }
    priv->async_head  = 0;
    priv->async_count = 0;
    priv->async_short_head  = 0;
    priv->async_short_count = 0;
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
    conn->snd_mss     = TCP_MSS_DEFAULT_RFC879; /* 相手がMSSオプションを付けなければこの既定値のまま */
    conn->rcv_seq     = 0;

    uint32_t isn = (uint32_t)timer_now();
    conn->snd_seq   = isn;
    conn->local_port = (uint16_t)(49152u + (isn & 0x3fffu));

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

    if (priv->ack_received) {
        if (conn->state == TCP_ESTABLISHED) {
            if (priv->connect_attempt == 0) {
                tcp_rtt_update(priv, timer_now() - priv->connect_sent_at);
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

    /* RTOタイムアウト -- 再送するか、再送上限なら諦める。 */
    priv->connect_attempt++;
    if (priv->connect_attempt > TCP_MAX_RETRIES) {
        uart_printf("[!] TCP: SYN送信/再送すべて失敗\n");
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    g_tcp_retransmit_count[smp_core_index()]++;
    uart_printf("[TCP] 再送 (%u/%d, RTO=%ums)\n",
                priv->connect_attempt, TCP_MAX_RETRIES, priv->connect_rto_ms);
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
    uint16_t win = tcp_wire_window(conn, priv, TCP_FLAG_ACK);
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
         * その分だけ送信を許す(RFC 5681 のウィンドウ膨張)。 */
        priv->cwnd += mss;
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

    /* flight は「未確認バイト数」。conn->snd_seq は楽観的に進めてあるので
     * これがそのまま snd_nxt 相当になる。 */
    uint32_t flight = conn->snd_seq - priv->snd_una;
    uint32_t half   = flight / 2u;
    uint32_t floor_val = 2u * (uint32_t)mss;
    priv->ssthresh = (half > floor_val) ? half : floor_val;
    priv->cwnd     = priv->ssthresh + 3u * (uint32_t)mss;
    priv->recover  = conn->snd_seq;
    priv->in_fast_recovery = 1;
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
        if (priv->sack_enabled && g_tcp_sack_use_tx) {
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

    uint64_t overall_start = timer_now();

    uint32_t last_logged_swin = 0xFFFFFFFFu;

    int      rto_active = 0;            /* 未確認データがあり再送タイマが有効か */
    uint64_t window_sent_at = 0;        /* 現在の未確認ウィンドウの先頭を送った時刻(RTT計測用) */
    uint32_t rto_ms = priv->rto_ms;
    int      window_retransmitted = 0;  /* 現在の未確認ウィンドウ内で再送が起きたか(Karnのアルゴリズム) */
    int      retransmit_attempts = 0;   /* 連続再送回数(進捗があるたびリセット) */
    uint64_t zwp_since = 0;             /* 相手の窓が 0 になってからの時刻(持続タイマ) */

    while (tcp_seq_lt(priv->snd_una, end_seq)) {
        if (timeout_ms(overall_start, TCP_SEND_OVERALL_TIMEOUT_MS)) {
            uart_printf("[!] TCP: tcp_send全体タイムアウト (%u/%u バイト送信済み)\n",
                        (unsigned)(priv->snd_una - base_seq), len);
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
        uint32_t cwnd_window = priv->cwnd + tcp_sacked_bytes(priv);
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

            /* Timestamps が有効なら RTT は受信側(TSecr)で測っているので、
             * ここで二重に更新しない(再送の有無に関わらず測れるぶん、
             * こちらの Karn 制約つきの推定より良い)。 */
            if (!window_retransmitted && !priv->ts_enabled) {
                tcp_rtt_update(priv, timer_now() - window_sent_at);
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
                window_sent_at = timer_now();
                window_retransmitted = 1;
                rto_active = 1;
            }
        }

        if (rto_active && timeout_ms(window_sent_at, rto_ms)) {
            retransmit_attempts++;
            if (retransmit_attempts > TCP_MAX_RETRIES) {
                uart_printf("[!] TCP: 再送上限到達、送信を諦める (%u/%u バイト送信済み)\n",
                            (unsigned)(priv->snd_una - base_seq), len);
                break;
            }
            g_tcp_retransmit_count[smp_core_index()]++;
            uart_printf("[TCP] 送信ウィンドウ再送 (%d/%d, una=%u nxt=%u RTO=%ums)\n",
                        retransmit_attempts, TCP_MAX_RETRIES, priv->snd_una, snd_nxt, rto_ms);
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 4), tcp_conn_arg(conn, (uint32_t)retransmit_attempts));

            uint32_t flight = snd_nxt - priv->snd_una;
            uint32_t half = flight / 2u;
            priv->ssthresh = (half > 2u * conn->snd_mss) ? half : 2u * conn->snd_mss;
            priv->cwnd = conn->snd_mss;
            /* RTO はウィンドウ全体を失ったということなので、Fast Recovery は
             * 打ち切ってスロースタートからやり直す(RFC 5681)。 */
            priv->in_fast_recovery = 0;
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
                resend_seq += rchunk;
                if (!priv->sack_enabled) priv->dup_ack_suppress++;
                g_tcp_retransmit_segs++;
            }
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
#define TCP_SHORT_USABLE()                                                        \
    ((outstanding > 0u && priv->cwnd < conn->snd_win) ? priv->cwnd : conn->snd_win)
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
            tcp_async_flush_until_room(conn, priv);
        }

        uint32_t outstanding = conn->snd_seq - priv->snd_una;
        uint32_t usable_window = conn->snd_win;
        /* SACK 済みはパイプに居ない(RFC 6675)。 */
        {
            uint32_t cw = priv->cwnd + tcp_sacked_bytes(priv);
            if (cw < usable_window) usable_window = cw;
        }
        uint32_t room = (usable_window > outstanding) ? (usable_window - outstanding) : 0u;
        uint64_t probe_since = 0;
        while (room == 0) {
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
                uint32_t cw = priv->cwnd + tcp_sacked_bytes(priv);
                if (cw < usable_window) usable_window = cw;
            }
            room = (usable_window > outstanding) ? (usable_window - outstanding) : 0u;
        }

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
                if (conn->state != TCP_TIME_WAIT && conn->state != TCP_CLOSED) {
                    tcp_timewait_register((const netaddr_t *)&conn->local_ip, conn->local_port,
                                           (const netaddr_t *)&conn->remote_ip, conn->remote_port,
                                           conn->snd_seq);
                }
            }
        } else {
            uart_printf("[!] TCP: FIN再送上限到達、ローカルで強制クローズ\n");
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
    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
        if (priv->ooo[i].valid) {
            uart_printf("[DEBUG] ooo[%u]: seq=%u len=%u\n",
                        i, priv->ooo[i].seq, (unsigned)priv->ooo[i].len);
            any_ooo = 1;
        }
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
    conn->state    = TCP_CLOSED;
    l->accept_conn  = conn;
    l->accept_ready = 0;
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
    if (l->accept_conn != conn) return 0;
    int was_ready = l->accept_ready;
    l->accept_conn  = NULL;
    l->accept_ready = 0;
    return was_ready ? 1 : 0;
}

/*=================================================================
 * 待ち行列で確立済みのコネクションを、呼び出し側が用意した受け皿へ
 * 引き渡す。tcp_conn_t は 64 バイトの POD で、プライベート状態
 * (tcp_priv_t)は s_conns[] のポインタ一致で引くので、構造体を複製して
 * s_conns[] の指す先を差し替えるだけで移せる(rx_buf も ooo も
 * 受信済みのデータもスロット側に残ったまま)。
 *
 * 引数:
 *   l - リスナースロット
 * 戻り値:
 *   1=引き渡した、0=引き渡せるものが無い
 * コール元:
 *   tcp_accept_ready_poll()
 * ===============================================================*/
static int tcp_backlog_handoff(tcp_listener_slot_t *l)
{
    if (l->accept_conn == NULL) return 0;

    /* 先に確立したものから渡す(FIFO)。 */
    int oldest = -1;
    for (unsigned p = 0; p < TCP_BACKLOG; p++) {
        if (!l->pending_used[p] || !l->pending_estab[p]) continue;
        if (oldest < 0 || l->pending_since[p] < l->pending_since[oldest]) oldest = (int)p;
    }
    if (oldest < 0) return 0;

    tcp_conn_t *from = &l->pending[oldest];
    tcp_conn_t *to   = l->accept_conn;
    unsigned    pcore = from->owner_core;

    *to = *from;  /* 64 バイトの複製 */

    int moved = 0;
    if (pcore < SMP_MAX_CORES) {
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[pcore][i] == from) { s_conns[pcore][i] = to; moved = 1; break; }
        }
    }
    if (!moved) {
        /* s_conns[] に居ない = 既に畳まれている。引き渡さずに回収する。 */
        uart_printf("[!] TCP: backlog のエントリが s_conns[] に居ません(引き渡し中止)\n");
        to->state = TCP_CLOSED;
        tcp_backlog_release(l, (unsigned)oldest);
        return 0;
    }

    from->state = TCP_CLOSED;
    l->pending_estab[oldest] = 0;
    l->pending_used[oldest]  = 0;
    l->accept_conn = NULL;
    g_tcp_backlog_accept_count++;
    return 1;
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
    if (l->accept_ready) {
        l->accept_ready = 0;
        l->accept_conn  = NULL;
        return 1;
    }
    return tcp_backlog_handoff(l);
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
int tcp_conn_sack_enabled(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return (priv && priv->sack_enabled) ? 1 : 0;
}

/*=================================================================
 * 受信 TCP セグメントを処理する。チェックサム検証(HW 検証済みなら省略)、
 * リスナーへの SYN 受け付け、既存コネクションの状態遷移、in-order データの
 * 配置(upcall か rx_buf)、順序不正セグメントの先読み保持、ACK 処理と
 * 遅延 ACK、TIME_WAIT 宛の再送への応答までを行う。
 *
 * 引数:
 *   pkt    - TCP ヘッダ先頭(IP ヘッダの直後)
 *   len    - そのバイト数
 *   src - L3 ヘッダから取り出した送信元
 *   dst - 同じく宛先。IPv4 で「アクティブなインターフェースの IPv4」と
 *         分かっている場合は NULL を渡してよい(受信 1 パケットごとに
 *         netaddr_t を組み立てる無駄を避けるため。実際に使うのは受動 open と
 *         ソフトウェアチェックサム検証の 2 箇所だけ)
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

    int matched_listener = -1;
    int backlog_index    = -1;  /* >=0 = 待ち行列のエントリ、-1 = 受け皿へ直接 */
    if (in[TCP_OFF_FLAGS] & TCP_FLAG_SYN) {
        /* 再送された SYN を新しい接続として受理しない(待ち行列を作ると、
         * 同じ相手の SYN 再送がエントリを食い潰す)。既に SYN_RCVD まで
         * 進んでいるなら SYN|ACK を送り直す -- こちらの SYN|ACK が落ちた場合、
         * 相手は SYN を再送してくるので、無視すると永久に確立しない。 */
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            tcp_conn_t *ec = s_conns[core][i];
            if (ec != NULL &&
                src_port == ec->remote_port &&
                dst_port == ec->local_port &&
                netaddr_eq(src, (const netaddr_t *)&ec->remote_ip)) {
                if (ec->state == TCP_SYN_RCVD) {
                    tcp_priv_t *epriv = &s_priv[core][i];
                    uint32_t    saved = ec->snd_seq;
                    ec->snd_seq = epriv->expected_ack - 1u;  /* SYN 消費前の ISN */
                    tcp_send_segment(ec, epriv, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
                    ec->snd_seq = saved;
                    g_tcp_synack_retx_count++;
                    uart_printf("[TCP] accept: SYN 再送を受けて SYN|ACK を送り直し "
                                "(local_port=%u)\n", (unsigned)dst_port);
                    return;
                }
                break;  /* SYN|ACK など、既存コネクションの通常処理へ落とす */
            }
        }
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
        if (matched_listener >= 0) {
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
                    return;
                }
            }
        }
        if (matched_listener < 0) smp_spin_unlock(&s_listener_lock);
    }
    if (matched_listener >= 0) {
        tcp_listener_slot_t *l = &s_listeners[matched_listener];
        int slot = tcp_find_free_slot();
        if (slot < 0) {
            smp_spin_unlock(&s_listener_lock);
            uart_printf("[!] TCP: 空きコネクションスロットが無く受動openのSYNを破棄 "
                        "(local_port=%u, 最大%u本)\n", dst_port, TCP_MAX_CONNS);
        }
        if (slot >= 0) {
            tcp_conn_t *aconn = (backlog_index >= 0) ? &l->pending[backlog_index]
                                                     : l->accept_conn;
            tcp_priv_t *apriv = &s_priv[core][slot];
            tcp_priv_init(apriv, core);

            uint32_t seg_seq  = rd32be(in + TCP_OFF_SEQ);
            uint8_t  hdr_len2 = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);

            aconn->local_ip    = dst ? *dst : netaddr_v4(NET_SELF_IP);
            tcp_priv_try_grant_mlx5_async_overflow(apriv, core, (const netaddr_t *)&aconn->local_ip);
            aconn->remote_ip   = *src;
            aconn->remote_port = src_port;
            aconn->local_port  = dst_port;
            aconn->state       = TCP_SYN_RCVD;
            aconn->snd_seq     = (uint32_t)timer_now();  /* ISN(tcp_connect()と同じ採り方) */

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
            aconn->snd_mss = TCP_MSS_DEFAULT_RFC879;
            if (hdr_len2 > TCP_HDR_LEN && hdr_len2 <= len) {
                tcp_parse_syn_options(aconn, apriv, in + TCP_HDR_LEN, (uint8_t)(hdr_len2 - TCP_HDR_LEN));
            }
            aconn->snd_win = rd16be(in + TCP_OFF_WINDOW);

            uart_printf("[TCP] accept: SYN受信、SYN|ACK送信 (local_port=%u, slot=%d, backlog=%d)\n",
                        dst_port, slot, backlog_index);

            tcp_send_segment(aconn, apriv, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);

            aconn->snd_seq++;  /* SYNは1バイト分のシーケンス番号を消費する */
            apriv->expected_ack = aconn->snd_seq;
            apriv->ack_received = 0;
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
        uint8_t nm_flags = in[TCP_OFF_FLAGS];
        /* TIME_WAIT は 4-tuple 一致だけで先に判定する(FIN のときだけ引くのでは
         * なく)。閉じた直後の相手から届く遅延セグメントを「閉じたポート宛」と
         * 誤判定して RST を返すと、相手の TIME_WAIT を勝手に潰すことになる。 */
        tcp_timewait_t *tw = tcp_timewait_find(src, src_port, dst_port);
        if (tw) {
            if (nm_flags & TCP_FLAG_FIN) {
                uint8_t fin_hdr_len = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);
                if (fin_hdr_len >= TCP_HDR_LEN && fin_hdr_len <= len) {
                    uint32_t fin_seq = rd32be(in + TCP_OFF_SEQ);
                    uint16_t fin_payload_len = (uint16_t)(len - fin_hdr_len);
                    tcp_send_bare_ack(&tw->local_ip, tw->local_port,
                                       &tw->remote_ip, tw->remote_port,
                                       tw->local_seq, fin_seq + fin_payload_len + 1u);
                }
            }
            return;
        }
        /* TIME_WAIT にも一致しない -- 閉じたポート宛。RFC 793 に従って RST を
         * 返し、相手を SYN 再送のタイムアウトまで待たせない。
         *
         * RST を返さない条件(順に確認する):
         *  - 受信が RST -- RST に RST を返すと無限ループになる(最重要)。
         *  - 宛先がマルチキャスト -- 誰宛か特定できないものへ RST は返さない。
         *  - そのポートにリスナが居る -- accept を張り直す隙間に届いた SYN。
         *  - 他コアに 4-tuple 一致のコネクションが居る -- 自分のコネクションを
         *    自分で撃たないための保険。 */
        if (nm_flags & TCP_FLAG_RST) return;
        if (dst && dst->family == NETADDR_V6 && dst->a[0] == 0xFFu) return;
        if (tcp_port_has_listener(dst_port)) return;
        if (tcp_conn_exists_any_core(src, src_port, dst_port)) return;

        uint8_t nm_hdr_len = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);
        if (nm_hdr_len < TCP_HDR_LEN || nm_hdr_len > len) return;

        netaddr_t nm_local = dst ? *dst : netaddr_v4(NET_SELF_IP);
        tcp_send_bare_rst(&nm_local, dst_port, src, src_port,
                           nm_flags, rd32be(in + TCP_OFF_SEQ), rd32be(in + TCP_OFF_ACK),
                           (uint16_t)(len - nm_hdr_len));
        uart_printf("[TCP] 待ち受けの無いポート宛 (local_port=%u, remote_port=%u) へ RST を返しました\n",
                    (unsigned)dst_port, (unsigned)src_port);
        return;
    }

    /* Keepalive の「相手は生きている」印。**ホットパスに置くのはこの 1 バイトの
     * store だけ**で、時刻の読み出しと期限の判定は冷たい経路が行う
     * (tcp_keepalive_check())。probe への応答は純 ACK なので、ここで印を
     * 付けないと**応答が返っていることを知る手段が無い**。 */
    priv->ka_seen = 1;

    int hw_ok = eth_rx_hw_csum_ok();
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 0), tcp_conn_arg(conn, len));
    if (!hw_ok) {
        uint16_t csum_check;
        netaddr_t dst_v4;
        if (!dst) { dst_v4 = netaddr_v4(NET_SELF_IP); dst = &dst_v4; }
        if (src->family == NETADDR_V6) {
            csum_check = ipv6_pseudo_checksum(src->a, dst->a, IP_PROTO_TCP, pkt, len);
        } else {
            csum_check = pseudo_header_checksum(src->a, dst->a, IP_PROTO_TCP, pkt, len);
        }
        if (csum_check != 0) {
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 1), tcp_conn_arg(conn, len));
            uart_printf("[TCP] チェックサム不正 (計算結果=0x%04X、0であるべき) セグメント破棄\n",
                        csum_check);
            return;
        }
    }
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 2), tcp_conn_arg(conn, len));

    uint32_t seq   = rd32be(in + TCP_OFF_SEQ);
    uint32_t ack   = rd32be(in + TCP_OFF_ACK);
    uint8_t  flags = in[TCP_OFF_FLAGS];
    uint8_t  hdr_len = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);

    if (hdr_len < TCP_HDR_LEN || hdr_len > len) {
        uart_printf("[TCP] 不正なヘッダ長 (hdr_len=%u len=%u) 無視\n",
                    hdr_len, (unsigned)len);
        return;
    }

    const volatile uint8_t *payload = in + hdr_len;
    uint16_t payload_len = (uint16_t)(len - hdr_len);

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
            uint32_t rwnd = (uint32_t)priv->last_win_sent;
            if (priv->wscale_enabled) rwnd <<= TCP_RCV_WSCALE;
            if (rwnd == 0) rwnd = 1u;   /* 窓 0 でも RCV.NXT の 1 個だけは窓内 */
            int in_window = !tcp_seq_lt(seq, conn->rcv_seq) &&
                             tcp_seq_lt(seq, conn->rcv_seq + rwnd);
            if (in_window) {
                /* 窓内だが RCV.NXT ではない -- challenge ACK を返して、
                 * 本物なら相手が正しい seq で送り直すのを待つ。 */
                g_tcp_rst_challenge_count++;
                tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
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

    /* Timestamps(RFC 7323)。合意していないコネクションでは分岐 1 つで抜ける。
     * PAWS(古いセグメントの検出)はここで行う -- RST より後に置いてあるので
     * RST は PAWS の対象外(相手を切れなくなるのを避ける)。 */
    uint32_t seg_tsecr = 0;
    if ((priv->ts_enabled || priv->sack_enabled) &&
        !tcp_input_options(conn, priv, in, hdr_len, seq, &seg_tsecr)) {
        return;  /* PAWS で破棄(ACK は tcp_input_options() が返している) */
    }

    uint32_t prev_snd_win = conn->snd_win;  /* dup ACK 判定に要る(更新前の値) */
    if (priv->wscale_enabled) {
        conn->snd_win = (uint32_t)rd16be(in + TCP_OFF_WINDOW) << priv->snd_wscale;
    } else {
        conn->snd_win = rd16be(in + TCP_OFF_WINDOW);
    }

    switch (conn->state) {
    case TCP_SYN_RCVD:
        if ((flags & TCP_FLAG_ACK) && ack == priv->expected_ack) {
            priv->snd_una = ack;
            conn->state = TCP_ESTABLISHED;
            tcp_cwnd_init(conn, priv);
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
                    break;
                }
            }
            uart_printf("[TCP] accept: ESTABLISHED (peer MSS=%u, 初期cwnd=%u)\n",
                        conn->snd_mss, priv->cwnd);
        }
        break;

    case TCP_SYN_SENT:
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) &&
            ack == priv->expected_ack) {
            conn->rcv_seq = seq + 1;
            conn->state = TCP_ESTABLISHED;
            priv->ack_received = 1;
            tcp_parse_syn_options(conn, priv, in + TCP_HDR_LEN, (uint8_t)(hdr_len - TCP_HDR_LEN));
            conn->snd_seq = ack;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        }
        break;

    case TCP_ESTABLISHED:
        if (flags & TCP_FLAG_ACK) {
            if (ack == priv->expected_ack) {
                priv->ack_received = 1;  /* 単発の信頼送信(tcp_send_reliable())向け */
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
                if (priv->ts_enabled && seg_tsecr != 0u) {
                    uint32_t elapsed = tcp_ts_now() - seg_tsecr;
                    /* 異常値(相手が変な echo を返した)は捨てる。1.024us 刻みで
                     * 10 秒ぶん(約 977 万)を超えたら採らない。 */
                    if (elapsed < 10000000u) {
                        tcp_rtt_update(priv, (uint64_t)elapsed << 10);
                        g_tcp_ts_rtt_samples++;
                    }
                }
            } else if (ack == priv->snd_una &&
                       payload_len == 0 &&
                       (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) == 0 &&
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
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log_tcp_ack(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 3), (uint8_t)tcp_conn_slot(conn),
                           seq, ack, conn->snd_win, flags);
        }
        if (flags & TCP_FLAG_FIN) {
            uint32_t free_space = TCP_RX_BUF_SIZE - priv->rx_count;
            if (payload_len > 0 && (priv->recv_upcall || payload_len <= free_space)) {
                tcp_deliver_data(priv, payload, payload_len);
            }
            conn->rcv_seq = seq + payload_len + 1;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_CLOSE_WAIT;
            priv->fin_received = 1;
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 4), tcp_conn_arg(conn, payload_len));
            uart_printf("[TCP] FIN受信、ACK返送してCLOSE_WAITへ遷移\n");
        } else if (payload_len == 0 && (flags & TCP_FLAG_SYN) == 0 &&
                   tcp_seq_lt(seq, conn->rcv_seq)) {
            /* **相手の Keepalive probe(1 バイト過去の seq で 0 バイト)。**
             * RFC 1122 4.2.3.6 は ACK を返すことを求める。返さないと、
             * **相手はこちらが死んだと判断して接続を切る**(Linux は
             * 既定で Keepalive を使う)。データを運ぶ経路だけで ACK を
             * 返していたので、ここに来る 0 バイトのセグメントは黙殺していた。
             *
             * 「既に受け取った範囲の再送」もここに来るが、ACK を返すのは
             * RFC 793 的にも正しい(相手にこちらの受信位置を伝える)。 */
            g_tcp_keepalive_reply_count++;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        } else if (payload_len > 0) {
            uint32_t free_space = TCP_RX_BUF_SIZE - priv->rx_count;
            int accepted_inorder = 0;
            if (seq == conn->rcv_seq && (priv->recv_upcall || payload_len <= free_space)) {
                accepted_inorder = 1;
                tcp_deliver_data(priv, payload, payload_len);
                conn->rcv_seq += payload_len;
                /* 累積 ACK が進んだので、そこまでの区間は SACK で伝えない。 */
                if (priv->sack_tx_count) tcp_sack_tx_trim(priv, conn->rcv_seq);
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 5), tcp_conn_arg(conn, payload_len));

                for (;;) {
                    int spliced = 0;
                    free_space = TCP_RX_BUF_SIZE - priv->rx_count;
                    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
                        if (priv->ooo[i].valid && priv->ooo[i].seq == conn->rcv_seq &&
                            (priv->recv_upcall || priv->ooo[i].len <= free_space)) {
                            tcp_deliver_data(priv, priv->ooo[i].buf, priv->ooo[i].len);
                            conn->rcv_seq += priv->ooo[i].len;
                            priv->ooo[i].valid = 0;
                            if (priv->ooo_count > 0) priv->ooo_count--;
                            if (priv->sack_tx_count) tcp_sack_tx_trim(priv, conn->rcv_seq);
                            spliced = 1;
                            break;
                        }
                    }
                    if (!spliced) break;
                }
            } else if (seq == conn->rcv_seq) {
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 6), tcp_conn_arg(conn, payload_len));
            } else if (tcp_seq_gt(seq, conn->rcv_seq) && payload_len <= TCP_MSS_LOCAL) {
                int already = 0;
                for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
                    if (priv->ooo[i].valid && priv->ooo[i].seq == seq) {
                        already = 1;
                        break;
                    }
                }
                if (!already) {
                    int stored = 0;
                    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
                        if (!priv->ooo[i].valid) {
                            for (uint16_t j = 0; j < payload_len; j++) {
                                priv->ooo[i].buf[j] = payload[j];
                            }
                            priv->ooo[i].seq = seq;
                            priv->ooo[i].len = payload_len;
                            priv->ooo[i].valid = 1;
                            priv->ooo_count++;
                            if (priv->sack_enabled) tcp_sack_tx_add(priv, seq, payload_len);
                            /* ここは ts_log だけにしてある。以前は 1 セグメントごとに
                             * uart_printf していたが、高速再送(C2)を入れて順序不正の
                             * 到着が「異常」ではなく通常の回復過程になると、受信ホット
                             * パスでコンソール出力が延々と走る。実測でロス注入時の
                             * スループットがこの出力に支配され、さらに RX リングが
                             * 溢れて二次的なロスを生んでいた。 */
                            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 7), tcp_conn_arg(conn, payload_len));
                            stored = 1;
                            break;
                        }
                    }
                    if (!stored) {
                        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 8), tcp_conn_arg(conn, payload_len));
                        uart_printf("[!] TCP: 順序不正セグメントを破棄(先読みバッファ満杯 "
                                    "TCP_OOO_SLOTS=%u) (seq=%u rcv_seq=%u len=%u)\n",
                                    TCP_OOO_SLOTS, seq, conn->rcv_seq, payload_len);
                    }
                }
            } else if (tcp_seq_gt(seq, conn->rcv_seq)) {
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 9), tcp_conn_arg(conn, payload_len));
            }
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
            if (accepted_inorder && payload_len >= ack_min) {
                priv->unacked_full_segments++;
                if (priv->unacked_full_segments >= g_tcp_ack_threshold) {
                    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
                    priv->unacked_full_segments = 0;
                }
            } else if (g_tcp_ack_piggyback && priv->ack_piggy_ok &&
                       priv->recv_upcall != NULL) {
                /* **応答へ相乗りさせる。** upcall を持つ = 受け取ったものに
                 * 対して必ず応答を出すコネクション(nvmet の IO キュー)なので、
                 * ここで裸の ACK を出すと 1 コマンドが 2 パケットになる。
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
        break;

    case TCP_CLOSE_WAIT:
        if (flags & TCP_FLAG_ACK) {
            if (ack == priv->expected_ack) {
                priv->ack_received = 1;
            }
            if (tcp_seq_gt(ack, priv->snd_una)) {
                priv->snd_una = ack;
                priv->ack_advanced = 1;
                priv->neigh_confirm = 1;   /* 上位層の到達確認(NUD)*/
            }
        }
        if (flags & TCP_FLAG_FIN) {
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        }
        break;

    case TCP_LAST_ACK:
        /* tcp_close()が送った自分のFINへのACKを待っている。 */
        if ((flags & TCP_FLAG_ACK) && ack == priv->expected_ack) {
            priv->ack_received = 1;
            conn->state = TCP_CLOSED;
        }
        break;

    case TCP_FIN_WAIT_1:
        if ((flags & TCP_FLAG_ACK) && ack == priv->expected_ack) {
            priv->ack_received = 1;
            conn->state = TCP_FIN_WAIT_2;
        }
        if (flags & TCP_FLAG_FIN) {
            conn->rcv_seq = seq + 1;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_TIME_WAIT;
        }
        break;

    case TCP_FIN_WAIT_2:
        if (flags & TCP_FLAG_FIN) {
            conn->rcv_seq = seq + 1;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_TIME_WAIT;
        }
        break;

    case TCP_TIME_WAIT:
    case TCP_CLOSED:
    default:
        break;
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
