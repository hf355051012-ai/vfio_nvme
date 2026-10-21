#include <stddef.h>
#include "ipv6.h"
#include "netif.h"
#include "net.h"
#include "net_buf.h"
#include "uart.h"
#include "smp.h"
#include "timer.h"
#include "netaddr.h"
#include "tcp.h"
#include "udp.h"
#include "pmtu.h"
#include "ipfrag.h"
#include "crypto.h"

#define ICMPV6_OFF_TYPE     0u
#define ICMPV6_OFF_CODE     1u
#define ICMPV6_OFF_CHECKSUM 2u

/* Neighbor Solicitation/Advertisement の本体レイアウト(ICMPv6 ヘッダの後)。
 * NS:  reserved[4] + target[16] + option...
 * NA:  flags[4]    + target[16] + option...  flags の bit31=R bit30=S bit29=O */
/* NS/NA のメッセージ配置(RFC 4861 4.3/4.4)。この 2 つは **`8u + ...` の形で
 * 使う**。8 = ICMPv6 ヘッダ 4(type/code/checksum)+ reserved/flags 4。
 *
 * **以前は NDP_OFF_TARGET=4 / NDP_BODY_LEN=20 になっていて、reserved の 4 を
 * 二重に数えていた**(target を offset 12 から読み書きし、メッセージ長も
 * 32 ではなく 36 にしていた)。自作 <-> 自作では送信側も受信側も同じズレ方を
 * するので `ping6`/`tcp6test`/`udptest6` は全部通り、**Linux から NS が来て
 * 初めて露見した**(target が一致せず無言で捨てるので、相手からは IPv6 が
 * 一切通らないようにしか見えない)。CRC32C で踏んだのと同じ形の穴。 */
#define NDP_OFF_TARGET  0u   /* target は msg+8 から 16 バイト */
#define NDP_BODY_LEN    16u  /* target 16。オプションは msg+8+16 = msg+24 から */
#define NDP_OFF_FLAGS   4u   /* NA の R/S/O フラグは msg+4 の上位 3 ビット */

/* NDP_OPT_* は ipv6.h(RA のオプションと共用するため)。 */

/*=================================================================
 * NDP のオプションの並びが正しいか(RFC 4861 7.1.1 / 7.1.2 / 6.1.2 の
 * 「含まれるオプションはどれも長さが 0 でない」)。長さ 0 や、途中で切れて
 * いるオプションがあれば 0 を返す。**中身を使う前に、メッセージ全体で
 * 確かめる**(途中まで適用してから捨てると、壊れたメッセージの前半だけが
 * 効いてしまう)。
 *
 * 引数:
 *   in / len - ICMPv6 メッセージ
 *   off      - 最初のオプションの位置
 * 戻り値:
 *   1=正しい、0=壊れている
 * コール元:
 *   ipv6_handle_icmpv6(), ipv6_handle_ra()
 * ===============================================================*/
static int ndp_opts_valid(const volatile uint8_t *in, size_t len, size_t off)
{
    while (off < len) {
        if (off + 2u > len) return 0;
        size_t olen = (size_t)in[off + 1u] * 8u;
        if (olen == 0u || off + olen > len) return 0;
        off += olen;
    }
    return 1;
}

/* ff02::1:ffXX:XXXX(要請ノードマルチキャスト)なら 1。 */
static int ipv6_is_solicited_node(const uint8_t a[IPV6_ADDR_LEN])
{
    static const uint8_t pfx[13] = { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF };
    for (unsigned i = 0; i < 13u; i++) if (a[i] != pfx[i]) return 0;
    return 1;
}

/* ndp_cache_lookup() が stale なエントリの確認に使う(定義は下の方)。 */
static int ndp_send_ns(const uint8_t target[IPV6_ADDR_LEN]);

/* ---- 重複アドレス検出(DAD、RFC 4862)の実行中状態 ----
 *
 * DAD は起動時とシェルからしか走らない冷たい直列処理なので、per-core では
 * なく素のファイルスコープで持つ。受信ハンドラ(NA / DAD の NS)がここへ
 * 衝突を書き、ipv6_dad() が読む。 */
static volatile int s_dad_active;
static volatile int s_dad_conflict;
static uint8_t      s_dad_target[IPV6_ADDR_LEN];
static uint8_t      s_dad_conflict_mac[ETH_ALEN];
/* 検査を始めたインターフェースの MAC。この装置はマルチキャストを送信元へ
 * ループバックする(ping6 の「Echo Request 受信」が 1 回の送信で 2 行出るのが
 * 同じ現象)ので、自分が出した DAD NS と、それに自分が返した NA が自分に
 * 戻ってくる。これを衝突と数えないための比較相手。受信時の eth_get_mac() は
 * 処理側インターフェースの MAC を返すので代用にならない。 */
static uint8_t      s_dad_self_mac[ETH_ALEN];

/* ---- SLAAC(RFC 4862)----
 *
 * RA は非要請でもいつ届くか分からないので、処理そのものは受信ハンドラに置く。
 * ipv6_slaac_solicit() は「RS を送って、RA が処理されたか」を見るだけなので、
 * 受信ハンドラが RA を 1 個処理するごとにこのカウンタを進める。 */
static volatile uint32_t s_slaac_ra_seen;
/* **どのインターフェースが処理した RA か**も持つ。2 つの PF が同じリンクに
 * 居るので、片方の RS に対する RA をもう片方が受け取ることがある(実機で
 * 起きた: PF1 の RS に対する RA が eth2 経由で PF0 に届いた)。カウンタだけを
 * 見ると「RA が来た」と誤って打ち切ってしまう。 */
static netif_t * volatile s_slaac_ra_if;

/* ---- MLD(RFC 2710 / 3810)----
 *
 * v1 互換モードの期限は netif_t.mld_v1_until(インターフェースごと。RFC 3810 8.2.1 の
 * Older Version Querier Present はリンクの Querier の版で決まるので、2 つの PF が
 * 別々のリンクに居れば別々に決まる)。**Linux ブリッジの既定は `mcast_mld_version 1`**
 * なので、実スイッチ配下ではまずそちらに落ちる。
 * 送信する MLD メッセージの観測フック(`mldtest` 用)。相手(ルータ/スイッチ)が
 * 居ないと自分の送信を確かめられないので、送る直前にテスト側へ渡す。 */
static ipv6_mld_observer_t s_mld_observer;
/* 1 = MLD を一切送らない(`mld off`)。**スヌーピングするスイッチの配下では
 * これで通信が止まる** -- 「MLD が効いていること」の陰性対照を作るための
 * 恒久的なデバッグ機能で、`txdrop` と同じ位置づけ。戻し忘れに注意。 */
static volatile int s_mld_suppress;

/* ---- Fragment 拡張ヘッダ ----
 *
 * 送信側の断片で使う Identification(RFC 8200 4.5 は 32bit)。**全コアで 1 つの数を
 * 原子的に進め、起点は起動時の乱数**にする。
 *  - コアごとの数にすると、同じ (送信元, 宛先) へ別々のコアが送ったときに同じ値が
 *    出て、受信側が別のデータグラムの断片を 1 つに組み立てる(RFC 8200 4.5 の
 *    「同じ送信元・宛先の間で、生きている断片化したパケットどうしで重ならない」)。
 *  - 起点を 0 にすると値が推測でき、外から偽の断片を混ぜて組み立てを壊せる
 *    (RFC 7739 3)。
 * 断片化して送るのは UDP と大きな ICMPv6 だけ(TCP は MSS で収める)なので、
 * 原子的な加算の費用は問題にならない。 */
static volatile uint32_t s_ipv6_frag_id;
/* 受信した断片を組み立てへ渡す直前に呼ぶ観測フック(`ext6test` 用)。 */
static ipv6_frag_observer_t s_ipv6_frag_observer;
/* 送信の観測フック(`rfctest ipv6` 用)。 */
static ipv6_tx_observer_t s_ipv6_tx_observer;

/* ---- ICMPv6 のエラー(RFC 4443)---- */
volatile uint32_t g_icmpv6_err_rx;
volatile uint8_t  g_icmpv6_err_rx_type;
volatile uint8_t  g_icmpv6_err_rx_code;
volatile uint32_t g_icmpv6_err_rx_param;
volatile uint32_t g_icmpv6_err_tx;
volatile uint32_t g_icmpv6_err_ratelimited;
volatile uint32_t g_ipv6_redirect_count;
/* 送る頻度の制限(RFC 4443 2.4(f) の MUST)。**ノード全体で 1 つのトークンバケツ**
 * (コアごとにすると、受信を 8 コアへ散らしたときに 8 倍まで送ってしまう)。
 * エラーを送るのは冷たい経路なので、小さなスピンロックで守る。 */
static volatile char     s_err_lock;
static uint64_t          s_err_last;     /* 最後に補充した時刻(0=未初期化) */
static uint32_t          s_err_tokens;

/* ---- 時間で進める仕事(ipv6_timer_tick())----
 * DAD の判定と MLD の再送を待っているインターフェース。s_timer_pending が 0 なら
 * ipv6_timer_tick() は旗を 1 つ読むだけで戻る。 */
#define IPV6_TIMER_IFS 4u
static netif_t * volatile s_timer_if[IPV6_TIMER_IFS];
static volatile int  s_timer_pending;
static volatile char s_timer_lock;

/* 再送の間隔のばらしに使う乱数(暗号の強さは要らない。xorshift)。 */
static uint32_t s_ipv6_rng = 0x9E3779B9u;

volatile uint32_t g_ipv6_mld_query_count[SMP_MAX_CORES];
volatile uint32_t g_ipv6_mld_report_tx[SMP_MAX_CORES];

/*=================================================================
 * いま MLDv1 互換モードか。
 *
 * 戻り値:
 *   1=v1 で喋る、0=v2 で喋る
 * コール元:
 *   ipv6_mld_report_all(), ipv6_mld_leave(), mld_handle_query(), shell_mld()
 * ===============================================================*/
static int ipv6_mld_v1_mode_of(const netif_t *ni)
{
    if (!ni) return 0;
    uint64_t until = ni->mld_v1_until;
    if (until == 0u) return 0;
    if ((int64_t)(timer_now() - until) >= 0) return 0;
    return 1;
}

int ipv6_mld_v1_mode(void)
{
    return ipv6_mld_v1_mode_of(g_active_ctx);
}

/*=================================================================
 * v1 互換モードを即座に解除する(全インターフェース)。通常は MLD_V1_COMPAT_MS で
 * 切れるが、`mldtest` が v1 の Query を注入した後に元へ戻すために要る。
 *
 * コール元:
 *   shell_mldtest()
 * ===============================================================*/
void ipv6_mld_clear_v1_mode(void)
{
    static const char *names[] = { "mlx5-pf0", "mlx5-pf1" };
    for (unsigned i = 0; i < 2u; i++) {
        netif_t *ni = netif_find(names[i]);
        if (ni) ni->mld_v1_until = 0;
    }
    if (g_active_ctx) g_active_ctx->mld_v1_until = 0;
}

/*=================================================================
 * MLD の送信を止める/再開する(`mld off` / `mld on`)。
 *
 * **スヌーピングするスイッチの配下では、止めると相手からの NS が届かなく
 * なって通信が死ぬ。** それを実際に見せるための陰性対照であって、
 * 「MLD を実装した」ことの意味を確かめる唯一の手段でもある(止められないと
 * 「元々フラッディングで通っていただけ」と区別がつかない)。`txdrop` と
 * 同じく**戻し忘れると以後の測定が全部おかしくなる**。
 *
 * 引数:
 *   on - 1=送る(既定)、0=送らない
 * コール元:
 *   shell_mld()
 * ===============================================================*/
void ipv6_mld_set_enabled(int on)
{
    s_mld_suppress = on ? 0 : 1;
}

int ipv6_mld_enabled(void)
{
    return s_mld_suppress ? 0 : 1;
}

/*=================================================================
 * 送信 MLD の観測フックを登録する(NULL で解除)。
 *
 * コール元:
 *   shell_mldtest()
 * ===============================================================*/
void ipv6_set_mld_observer(ipv6_mld_observer_t fn)
{
    s_mld_observer = fn;
}

/*=================================================================
 * 受信 IPv6 断片の観測フックを登録する(NULL で解除)。断片を組み立てへ渡す
 * 直前に、断片ごとの形(識別子・オフセット・M)を渡す。組み立てた結果からは
 * 「何個に割れて、中間断片のオフセットがいくつか」が見えないので残してある
 * (`ip_set_frag_observer()` と同じ考え方)。
 *
 * コール元:
 *   shell_ext6test(), rfctest_ipv6()
 * ===============================================================*/
void ipv6_set_frag_observer(ipv6_frag_observer_t fn)
{
    s_ipv6_frag_observer = fn;
}

/*=================================================================
 * 送信の観測フックを登録する(NULL で解除)。ipv6_send_from() の経路(UDP / ICMPv6 /
 * 断片)で、組み立てたパケットの hop limit と上位を渡す。
 *
 * コール元:
 *   rfctest_ipv6()
 * ===============================================================*/
void ipv6_set_tx_observer(ipv6_tx_observer_t fn)
{
    s_ipv6_tx_observer = fn;
}

/* 乱数(xorshift32)。MLD の再送の間隔をばらすだけなので暗号の強さは要らない。 */
static uint32_t ipv6_rand32(void)
{
    uint32_t x = s_ipv6_rng;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    s_ipv6_rng = x ? x : 0x9E3779B9u;
    return x;
}

/* 16 バイトが全部 0(未指定アドレス ::)か。 */
static int ipv6_addr_unspec(const uint8_t a[IPV6_ADDR_LEN])
{
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) if (a[i]) return 0;
    return 1;
}

/* fe80::/10(リンクローカル)か。 */
static int ipv6_addr_ll(const uint8_t a[IPV6_ADDR_LEN])
{
    return a[0] == 0xFEu && (a[1] & 0xC0u) == 0x80u;
}

/* 2 つの 16 バイトが等しいか(どちらも普通のメモリ)。 */
static int ipv6_eq16(const uint8_t a[IPV6_ADDR_LEN], const uint8_t b[IPV6_ADDR_LEN])
{
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) if (a[i] != b[i]) return 0;
    return 1;
}

/*=================================================================
 * NDP 以外の送信に使う hop limit(RFC 4861 6.3.4 の CurHopLimit)。RA の Cur Hop
 * Limit が 0 でなければそれ、無ければ 64(RFC 8200 3 が勧める既定値の慣例。
 * Linux も 64)。
 *
 * **255 は NDP 専用。** 以前は ipv6_send_from() が全部 255 で送っていて、UDP や
 * Echo Reply がルータを 254 段越えて届く形になっていた(害は小さいが、NDP の
 * 「255 で届いた = 同じリンクから来た」という検査の前提を、こちらの送信が崩す)。
 *
 * 戻り値:
 *   hop limit
 * コール元:
 *   ipv6_build_header(), ipv6_hop_for(), rfctest_ipv6()
 * ===============================================================*/
uint8_t ipv6_default_hop_limit(void)
{
    const netif_t *ni = g_active_ctx;
    return (ni && ni->ra_cur_hop_limit) ? ni->ra_cur_hop_limit : 64u;
}

/* 送るメッセージに合わせた hop limit。NDP(RS / RA / NS / NA / Redirect)だけ 255
 * (RFC 4861 6.1 / 7.1 の受信側の検査が 255 を要求する)。 */
static uint8_t ipv6_hop_for(uint8_t next_header, const uint8_t *payload, uint16_t len)
{
    if (next_header == IPV6_NH_ICMPV6 && len >= 1u &&
        payload[0] >= ICMPV6_TYPE_RS && payload[0] <= ICMPV6_TYPE_REDIRECT) {
        return 255u;
    }
    return ipv6_default_hop_limit();
}

/*=================================================================
 * 16 バイトのアドレスが等しいか。
 *
 * 引数:
 *   a / b - 比較する 2 つ
 * 戻り値:
 *   1=等しい、0=異なる
 * コール元:
 *   ipv6_handle_icmpv6(), ipv6_dad()
 * ===============================================================*/
static int ipv6_addr_eq(const uint8_t a[IPV6_ADDR_LEN], const volatile uint8_t *b)
{
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

/*=================================================================
 * その MAC が、いま DAD を実行しているインターフェース自身のものか。
 * ループバックしてきた自分のフレームを衝突と数えないために使う。
 *
 * 引数:
 *   mac - 判定する MAC
 * 戻り値:
 *   1=自分が出したもの、0=他ノード由来
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
static int dad_mac_is_prober(const volatile uint8_t *mac)
{
    for (unsigned i = 0; i < ETH_ALEN; i++) {
        if (mac[i] != s_dad_self_mac[i]) return 0;
    }
    return 1;
}

volatile uint32_t g_ipv6_ra_count[SMP_MAX_CORES];
volatile uint32_t g_ipv6_echo_request_count[SMP_MAX_CORES];
volatile uint32_t g_ipv6_echo_reply_count[SMP_MAX_CORES];
volatile uint32_t g_ipv6_ns_count[SMP_MAX_CORES];

/*=================================================================
 * EtherType 0x86DD(IPv6)のフレームハンドラを登録する。
 *
 * コール元:
 *   run_shell()
 * ===============================================================*/
void ipv6_init(void)
{
    /* 断片の識別子の起点と、再送の間隔の乱数の種。getrandom が使えなければ時刻で代える
     * (起点が推測しにくくなればよいので、それで足りる)。 */
    uint32_t seed[2] = { 0, 0 };
    if (crypto_random(seed, sizeof(seed)) != 0) {
        uint64_t t = timer_now();
        seed[0] = (uint32_t)t ^ (uint32_t)(t >> 32) ^ 0xA5A5A5A5u;
        seed[1] = (uint32_t)(t * 2654435761u);
    }
    __atomic_store_n(&s_ipv6_frag_id, seed[0], __ATOMIC_RELAXED);
    s_ipv6_rng = seed[1] ? seed[1] : 0x9E3779B9u;
    eth_register_handler(0x86DDu, ipv6_handle_frame);
}

/*=================================================================
 * 自分の MAC から EUI-64 を作り、リンクローカルアドレス fe80::/64 を組む。
 * IPv4 のような静的設定を持たなくてもこのアドレスだけは常に存在するので、
 * IPv6 の疎通確認(ping6)はこれで足りる。
 *
 * 引数:
 *   out - 16 バイトの格納先
 * コール元:
 *   ipv6_addr_is_ours(), ipv6_send(), ipv6_handle_icmpv6()
 * ===============================================================*/
void ipv6_link_local_addr(uint8_t out[IPV6_ADDR_LEN])
{
    uint8_t mac[ETH_ALEN];
    eth_get_mac(mac);

    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[i] = 0;
    out[0] = 0xFE; out[1] = 0x80;
    /* EUI-64: MAC の上位3バイト + FF FE + 下位3バイト、先頭バイトの U/L を反転 */
    out[8]  = (uint8_t)(mac[0] ^ 0x02u);
    out[9]  = mac[1];
    out[10] = mac[2];
    out[11] = 0xFF;
    out[12] = 0xFE;
    out[13] = mac[3];
    out[14] = mac[4];
    out[15] = mac[5];
}

/*=================================================================
 * アドレスに対応する要請ノードマルチキャスト ff02::1:ffXX:XXXX を組む
 * (RFC 4291 2.7.1)。バイト列では ff 02 00..00 01 ff XX XX XX。
 *
 * 引数:
 *   addr - 元のアドレス、out - 16 バイトの格納先
 * コール元:
 *   ipv6_mcast_groups(), ndp_send_ns(), ndp_send_dad_ns()
 * ===============================================================*/
void ipv6_solicited_node_addr(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out[IPV6_ADDR_LEN])
{
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[i] = 0;
    out[0] = 0xFF; out[1] = 0x02; out[11] = 0x01; out[12] = 0xFF;
    out[13] = addr[13]; out[14] = addr[14]; out[15] = addr[15];
}

/* ---- アドレスの枠 ----
 * グローバルアドレスは「1 つ目」(netif_t の ip6_global 一式。手動設定と、最初の
 * SLAAC のアドレス)と「2 つ目以降」(ip6_extra[]。SLAAC だけ)に分かれている。
 * **1 つ目の欄は main.c(`ip6addr` / `slaac` / 試験)が直接読み書きするので
 * 形を変えられない。** そこで枠の番号(0 = 1 つ目、1.. = 2 つ目以降)で両方を
 * 同じ形に見せる。 */
typedef struct {
    uint8_t  *addr;
    uint8_t  *plen;
    uint8_t  *dad;
    uint64_t *valid_until;
    uint64_t *pref_until;
    uint64_t *dad_until;
    int       set;
    int       from_ra;
} a6slot_t;

/*=================================================================
 * 枠 i の見え方を作る。
 *
 * 引数:
 *   ni - インターフェース
 *   i  - 0 = 1 つ目(ip6_global)、1.. = ip6_extra[i-1]
 *   s  - 出力
 * 戻り値:
 *   1=枠がある(s->set が 0 なら空き)、0=範囲外
 * コール元:
 *   アドレスを扱う関数の全部
 * ===============================================================*/
static int a6_slot(netif_t *ni, unsigned i, a6slot_t *s)
{
    if (i != 0u && i - 1u >= ni->ip6_extra_cnt) {
        /* 範囲外。読まれても害の無い 1 つ目を指しておき、空きとして返す。 */
        a6_slot(ni, 0u, s);
        s->set = 0;
        return 0;
    }
    if (i == 0u) {
        s->addr        = ni->ip6_global;
        s->plen        = &ni->ip6_prefix_len;
        s->dad         = &ni->ip6_global_dad;
        s->valid_until = &ni->ip6_global_valid_until;
        s->pref_until  = &ni->ip6_global_pref_until;
        s->dad_until   = &ni->ip6_global_dad_until;
        s->set         = ni->ip6_global_set ? 1 : 0;
        s->from_ra     = ni->ip6_global_from_ra ? 1 : 0;
        return 1;
    }
    if (i - 1u >= ni->ip6_extra_cnt) return 0;
    netif_ip6addr_t *e = &ni->ip6_extra[i - 1u];
    s->addr        = e->addr;
    s->plen        = &e->plen;
    s->dad         = &e->dad;
    s->valid_until = &e->valid_until;
    s->pref_until  = &e->pref_until;
    s->dad_until   = &e->dad_until;
    s->set         = 1;
    s->from_ra     = 1;
    return 1;
}

/* 枠の数(1 つ目 + 2 つ目以降)。 */
static unsigned a6_count(const netif_t *ni)
{
    return 1u + ni->ip6_extra_cnt;
}

/* 時刻を、要るときに 1 回だけ読む(*now が 0 なら読む)。 */
static uint64_t a6_now(uint64_t *now)
{
    if (*now == 0u) *now = timer_now();
    return *now;
}

static void ipv6_timer_arm(netif_t *ni);
static int  ndp_send_dad_ns(const uint8_t target[IPV6_ADDR_LEN]);

/*=================================================================
 * DAD 中(TENTATIVE)の枠の判定時刻が来ていれば PASSED にする。
 *
 * **DAD は待ち時間の間に衝突の知らせ(NA / 相手の DAD の NS)が来なければ空き**
 * (RFC 4862 5.4)。衝突の知らせは受信ハンドラが ipv6_dad_conflict() で即座に
 * 処理するので、ここは「時間が来たら通す」だけでよい。受信処理の中から
 * net_poll_all_and_dispatch() を回す必要が無い(以前の DAD は待つ間に受信を回す
 * 同期処理で、受信ハンドラから呼べなかった。CLAUDE.md の「DAD は RA 受信ハンドラから
 * 実行できない」)。
 *
 * 引数:
 *   s   - 枠
 *   now - 時刻(0 なら必要なときに読む)
 * 戻り値:
 *   1=使ってよい(PASSED)、0=まだ / 衝突
 * コール元:
 *   ipv6_global_addr(), a6_rx_ok(), ipv6_timer_tick()
 * ===============================================================*/
static int ipv6_dad_settle(netif_t *ni, a6slot_t *s, uint64_t *now)
{
    if (*s->dad == NETIF_DAD_PASSED) return 1;
    if (*s->dad != NETIF_DAD_TENTATIVE) return 0;
    if ((int64_t)(a6_now(now) - *s->dad_until) < 0) return 0;
    *s->dad = NETIF_DAD_PASSED;
    uart_printf("[IPv6] DAD: %s の ...%02x%02x:%02x%02x に衝突なし -- 使い始めます\n",
                ni->name ? ni->name : "?", s->addr[12], s->addr[13], s->addr[14], s->addr[15]);
    return 1;
}

/*=================================================================
 * 枠 i のアドレスを外す。1 つ目は欄を落とし、2 つ目以降は詰める。
 *
 * 引数:
 *   ni - インターフェース
 *   i  - 枠の番号
 * コール元:
 *   ipv6_age_addrs(), ipv6_dad_conflict(), rfctest_ipv6() の後始末
 * ===============================================================*/
static void a6_remove(netif_t *ni, unsigned i)
{
    if (i == 0u) {
        ni->ip6_global_set         = 0;
        ni->ip6_global_from_ra     = 0;
        ni->ip6_global_valid_until = 0;
        ni->ip6_global_pref_until  = 0;
        return;
    }
    unsigned k = i - 1u;
    if (k >= ni->ip6_extra_cnt) return;
    unsigned last = ni->ip6_extra_cnt - 1u;
    if (k != last) ni->ip6_extra[k] = ni->ip6_extra[last];
    ni->ip6_extra_cnt = (uint8_t)last;
}

/*=================================================================
 * アクティブなインターフェースの 1 つ目のグローバル IPv6 アドレスを返す。
 *
 * **SLAAC で作ったアドレスは DAD を通るまで返さない**(RFC 4862 5.4 の tentative。
 * 返すと送信元にも、受信の「自分宛て」の判定にも使われてしまい、検査中のアドレスで
 * 通信を始めることになる)。手動設定(`ip6addr`)は従来どおり常に返す
 * (手動設定の DAD は「検出しても使い続ける」方針。CLAUDE.md の A3)。
 *
 * 引数:
 *   out - 16 バイトの格納先(未設定なら触らない)
 * 戻り値:
 *   1=使ってよいアドレスがある、0=無い
 * コール元:
 *   ipv6_addr_is_ours(), ipv6_source_for(), ipv6_handle_icmpv6()
 * ===============================================================*/
int ipv6_global_addr(uint8_t out[IPV6_ADDR_LEN])
{
    netif_t *ni = g_active_ctx;
    if (!ni || !ni->ip6_global_set) return 0;
    /* **時刻を読むのは SLAAC 由来のときだけ。** 手動設定と未設定は期限も DAD の待ちも
     * 持たないので、この関数が時刻を読むことはない。ここは受信フレームごと
     * (ipv6_addr_is_ours)と送信ごと(ipv6_source_for)に通るので、無条件に
     * timer_now() を呼ぶとホットパスへ時刻読み出しが乗る。 */
    if (ni->ip6_global_from_ra) {
        uint64_t now = 0;
        if (ni->ip6_global_dad != NETIF_DAD_PASSED) {
            a6slot_t s;
            a6_slot(ni, 0u, &s);
            if (!ipv6_dad_settle(ni, &s, &now)) return 0;
        }
        if (ni->ip6_global_valid_until != 0u &&
            (int64_t)(a6_now(&now) - ni->ip6_global_valid_until) >= 0) {
            ipv6_slaac_age(ni);
            if (!ni->ip6_global_set) return 0;
        }
    } else if (ni->ip6_global_valid_until != 0u) {
        ipv6_slaac_age(ni);
        if (!ni->ip6_global_set) return 0;
    }
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[i] = ni->ip6_global[i];
    return 1;
}

/*=================================================================
 * 枠 i のアドレスを「自分宛て」として受けてよいか(DAD を通っていて、有効期間内)。
 * 2 つ目以降の枠に使う(1 つ目は ipv6_global_addr())。
 *
 * 引数:
 *   ni  - インターフェース
 *   s   - 枠
 *   now - 時刻(0 なら必要なときに読む)
 * 戻り値:
 *   1=使ってよい、0=使わない
 * コール元:
 *   ipv6_unicast_is_ours(), ipv6_global_source()
 * ===============================================================*/
static int a6_rx_ok(netif_t *ni, a6slot_t *s, uint64_t *now)
{
    if (!s->set) return 0;
    if (!s->from_ra) return 1;
    if (!ipv6_dad_settle(ni, s, now)) return 0;
    if (*s->valid_until != 0u && (int64_t)(a6_now(now) - *s->valid_until) >= 0) return 0;
    return 1;
}

static void ipv6_router_select(netif_t *ni, int avoid_current);
static void ipv6_router_remove_at(netif_t *ni, unsigned i);

/*=================================================================
 * RA から得た寿命(アドレス・on-link のプレフィックス・デフォルトルータ)が満了して
 * いたら外す。
 *
 * **冷たい経路からのみ呼ぶ。** ルータ寿命は netif_next_hop6() という送信ホットパス
 * (inline)から参照されるが、そこへ時刻読み出しを持ち込みたくないので、判定はここに
 * 寄せてある。呼ばれる契機は
 *   - RA を受信したとき
 *   - SLAAC 由来の 1 つ目のアドレスの期限を過ぎて使おうとしたとき(ipv6_global_addr)
 *   - ipv6_timer_tick()
 *   - シェルの `slaac` / `ip6addr` / `route` 表示
 * **ルータが黙って消えたまま誰もこのインターフェースを使わない場合、gateway6 は
 * 次に呼ばれるまで残る**(残っていても実害が出るのは、そのゲートウェイ宛に
 * 送ろうとしたときだけ)。
 *
 * 引数:
 *   ni - 対象インターフェース(NULL 可)
 * コール元:
 *   ipv6_global_addr(), ipv6_handle_ra(), ipv6_timer_tick(), shell_slaac(), shell_route()
 * ===============================================================*/
void ipv6_slaac_age(netif_t *ni)
{
    if (!ni) return;
    if (ni->ip6_global_valid_until == 0u && ni->gateway6_valid_until == 0u &&
        ni->ip6_extra_cnt == 0u && ni->prefix6_cnt == 0u && ni->router6_cnt == 0u) {
        return;
    }

    uint64_t now = timer_now();
    if (ni->ip6_global_set && ni->ip6_global_valid_until != 0u &&
        (int64_t)(now - ni->ip6_global_valid_until) >= 0) {
        uart_printf("[IPv6] SLAAC: %s のグローバルアドレスが有効期間切れ -- 解除します\n",
                    ni->name ? ni->name : "?");
        a6_remove(ni, 0u);
    }
    for (unsigned i = ni->ip6_extra_cnt; i > 0u; i--) {
        netif_ip6addr_t *e = &ni->ip6_extra[i - 1u];
        if (e->valid_until != 0u && (int64_t)(now - e->valid_until) >= 0) {
            uart_printf("[IPv6] SLAAC: %s の %u 番目のグローバルアドレスが有効期間切れ -- 解除します\n",
                        ni->name ? ni->name : "?", i + 1u);
            a6_remove(ni, i);
        }
    }
    for (unsigned i = ni->prefix6_cnt; i > 0u; i--) {
        netif_prefix6_t *p = &ni->prefix6[i - 1u];
        if (p->valid_until != 0u && (int64_t)(now - p->valid_until) >= 0) {
            unsigned last = ni->prefix6_cnt - 1u;
            if (i - 1u != last) ni->prefix6[i - 1u] = ni->prefix6[last];
            ni->prefix6_cnt = (uint8_t)last;
        }
    }
    int routers_changed = 0;
    for (unsigned i = ni->router6_cnt; i > 0u; i--) {
        netif_router6_t *r = &ni->router6[i - 1u];
        if (r->valid_until != 0u && (int64_t)(now - r->valid_until) >= 0) {
            ipv6_router_remove_at(ni, i - 1u);
            routers_changed = 1;
        }
    }
    if (ni->gateway6_set && ni->gateway6_from_ra && ni->gateway6_valid_until != 0u &&
        (int64_t)(now - ni->gateway6_valid_until) >= 0) {
        uart_printf("[IPv6] SLAAC: %s のデフォルトルータが寿命切れ -- 解除します\n",
                    ni->name ? ni->name : "?");
        ni->gateway6_set        = 0;
        ni->gateway6_from_ra    = 0;
        ni->gateway6_valid_until = 0;
        routers_changed = 1;
    }
    if (routers_changed) ipv6_router_select(ni, 0);
}

/*=================================================================
 * a がこのインターフェースのユニキャストアドレス(リンクローカルと、使ってよい
 * グローバルアドレス)か。**DAD 中のアドレスは含めない**(RFC 4862 5.4:
 * tentative なアドレス宛てのパケットは捨て、そのアドレスを対象とする NS には
 * 答えない)。
 *
 * 引数:
 *   ni - インターフェース(アクティブなもの)
 *   a  - 調べるアドレス
 * 戻り値:
 *   1=自分のアドレス、0=それ以外
 * コール元:
 *   ipv6_addr_is_ours(), ipv6_handle_icmpv6()(NS の Target)
 * ===============================================================*/
static int ipv6_unicast_is_ours(netif_t *ni, const uint8_t a[IPV6_ADDR_LEN])
{
    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);
    if (ipv6_eq16(a, ll)) return 1;
    if (!ni) return 0;

    uint8_t g[IPV6_ADDR_LEN];
    if (ipv6_global_addr(g) && ipv6_eq16(a, g)) return 1;
    if (ni->ip6_extra_cnt) {
        uint64_t now = 0;
        for (unsigned i = 1; i < a6_count(ni); i++) {
            a6slot_t s;
            if (!a6_slot(ni, i, &s)) break;
            if (ipv6_eq16(a, s.addr) && a6_rx_ok(ni, &s, &now)) return 1;
        }
    }
    return 0;
}

/*=================================================================
 * a を対象に DAD をしている(TENTATIVE の)枠を探す。
 *
 * 戻り値:
 *   枠の番号、無ければ -1
 * コール元:
 *   ipv6_handle_icmpv6()(NS / NA)
 * ===============================================================*/
static int a6_find_tentative(netif_t *ni, const uint8_t a[IPV6_ADDR_LEN])
{
    if (!ni) return -1;
    uint64_t now = 0;
    for (unsigned i = 0; i < a6_count(ni); i++) {
        a6slot_t s;
        if (!a6_slot(ni, i, &s)) break;
        if (!s.set || *s.dad != NETIF_DAD_TENTATIVE || !ipv6_eq16(a, s.addr)) continue;
        /* 判定時刻を過ぎていれば、ここで PASSED にする(判定は「時間が来たら通す」
         * だけで、誰かが見るまで状態が変わらないため)。 */
        if (ipv6_dad_settle(ni, &s, &now)) return -1;
        return (int)i;
    }
    return -1;
}

/*=================================================================
 * 送信元に使うグローバルアドレスを選ぶ(RFC 6724 5 の簡略版)。候補は使ってよい
 * (DAD を通った、有効期間内の)グローバルアドレスだけで、順位は
 *   rule 3: 推奨寿命が切れた(deprecated)ものを避ける
 *   rule 8: 宛先とプレフィックスが一致するものを選ぶ
 * の順。同点なら若い枠(1 つ目)。**deprecated でも、グローバル宛てにリンクローカルを
 * 使うよりはよい**(rule 2 のスコープが rule 3 より先)ので、候補が deprecated しか
 * 無ければそれを使う。
 *
 * 引数:
 *   ni  - インターフェース
 *   dst - 宛先
 *   out - 選んだアドレス
 * 戻り値:
 *   1=選んだ、0=使えるグローバルアドレスが無い
 * コール元:
 *   ipv6_source_for()
 * ===============================================================*/
static int ipv6_global_source(netif_t *ni, const uint8_t dst[IPV6_ADDR_LEN],
                              uint8_t out[IPV6_ADDR_LEN])
{
    /* 速い道: 2 つ目以降が無く、1 つ目に推奨寿命が無い(手動設定など)なら従来どおり。 */
    if (ni->ip6_extra_cnt == 0u &&
        (!ni->ip6_global_from_ra || ni->ip6_global_pref_until == 0u)) {
        return ipv6_global_addr(out);
    }

    uint64_t now = 0;
    int best = -1, best_score = -1;
    for (unsigned i = 0; i < a6_count(ni); i++) {
        a6slot_t s;
        if (!a6_slot(ni, i, &s)) break;
        if (i == 0u) {
            uint8_t g[IPV6_ADDR_LEN];
            if (!ipv6_global_addr(g)) continue;
            a6_slot(ni, 0u, &s);   /* 有効期間切れで外れた場合に備えて見直す */
            if (!s.set) continue;
        } else if (!a6_rx_ok(ni, &s, &now)) {
            continue;
        }
        int score = 0;
        /* 推奨寿命は SLAAC のものだけが持つ(手動設定の欄に前の SLAAC の値が残って
         * いても見ない)。 */
        if (!s.from_ra || *s.pref_until == 0u ||
            (int64_t)(a6_now(&now) - *s.pref_until) < 0) {
            score += 2;
        }
        if (*s.plen && netif_prefix6_match(dst, s.addr, *s.plen)) score += 1;
        if (score > best_score) { best_score = score; best = (int)i; }
    }
    if (best < 0) return 0;
    a6slot_t s;
    a6_slot(ni, (unsigned)best, &s);
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[i] = s.addr[i];
    return 1;
}

/*=================================================================
 * 宛先に応じて送信元 IPv6 アドレスを選ぶ(RFC 6724 の簡略版)。
 *
 * リンクローカル宛てと、スコープがリンク以下(ff01:: / ff02::)のマルチキャスト宛ては
 * リンクローカルから送る。それ以外(グローバル宛て、**サイト以上のスコープの
 * マルチキャスト宛て**)はグローバルアドレスがあればそれから送る(rule 2: 宛先の
 * スコープに届くアドレスを選ぶ。ff0e:: 宛てをリンクローカルから送ると、ルータは
 * 送信元のスコープの外へ転送できないので捨てる)。
 *
 * 引数:
 *   dst - 宛先、out - 送信元の格納先
 * コール元:
 *   ipv6_send(), ipv6_send_icmpv6(), tcp.c, udp.c
 * ===============================================================*/
void ipv6_source_for(const uint8_t dst[IPV6_ADDR_LEN], uint8_t out[IPV6_ADDR_LEN])
{
    int link_scope = (dst[0] == 0xFFu && (dst[1] & 0x0Fu) <= 2u) ||  /* ff01:: / ff02:: */
                     ipv6_addr_ll(dst);                              /* fe80::/10 */
    netif_t *ni = g_active_ctx;
    if (!link_scope && ni && ipv6_global_source(ni, dst, out)) return;
    ipv6_link_local_addr(out);
}

/*=================================================================
 * 受信アドレスが自ノード宛かを判定する。受けるのは
 *   - リンクローカル本体と、使ってよい(DAD を通った)グローバルアドレス
 *   - 全ノードマルチキャスト ff02::1
 *   - 要請ノードマルチキャスト ff02::1:ffXX:XXXX(リンクローカルと、**DAD 中のものも
 *     含めた**全部のグローバルアドレスのもの。RFC 4862 5.4.2:DAD の NS を出す前に
 *     そのグループへ参加する。参加していないと、相手の DAD の NS が届かず、衝突を
 *     見つけられない)
 * の 3 種。**DAD 中のアドレスそのもの(ユニキャスト)宛ては受けない**(5.4)。
 *
 * 引数:
 *   addr - 判定する宛先アドレス
 * 戻り値:
 *   1=自分宛、0=それ以外
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
int ipv6_addr_is_ours(const uint8_t addr[IPV6_ADDR_LEN])
{
    netif_t *ni = g_active_ctx;
    if (addr[0] != 0xFFu) return ipv6_unicast_is_ours(ni, addr);

    if (addr[1] != 0x02u) return 0;
    /* ff02::1 (全ノード) */
    int zero_mid = 1;
    for (unsigned i = 2; i < 15; i++) {
        if (addr[i] != 0) { zero_mid = 0; break; }
    }
    if (zero_mid && addr[15] == 0x01) return 1;

    /* ff02::1:ffXX:XXXX (要請ノードマルチキャスト)。バイト列では
     * ff 02 00..00 01 ff XX XX XX なので、addr[11]=0x01 / addr[12]=0xFF で、
     * addr[13..15] が自分のアドレスの下位 3 バイトと一致する。 */
    if (!ipv6_is_solicited_node(addr)) return 0;
    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);
    if (addr[13] == ll[13] && addr[14] == ll[14] && addr[15] == ll[15]) return 1;
    if (!ni) return 0;
    /* **グローバルアドレス由来の要請ノードマルチキャストも受ける。** 下位 3 バイトが
     * リンクローカル(EUI-64 由来)と違うことがあり、ここを足さないと相手の NS が
     * 届かず、そのアドレスへは到達できない。DAD 中のものも受ける(上の説明)。 */
    for (unsigned i = 0; i < a6_count(ni); i++) {
        a6slot_t s;
        if (!a6_slot(ni, i, &s)) break;
        if (!s.set) continue;
        if (addr[13] == s.addr[13] && addr[14] == s.addr[14] && addr[15] == s.addr[15]) return 1;
    }
    return 0;
}

/*=================================================================
 * IPv6 の疑似ヘッダを含めたチェックサムを計算する(ICMPv6/TCP/UDP 共通)。
 * IPv6 では ICMPv6 でもチェックサムが必須で、疑似ヘッダを必ず含める。
 *
 * 引数:
 *   src / dst - 送信元・宛先アドレス
 *   next_hdr  - 上位プロトコル番号
 *   data/len  - 上位プロトコルのメッセージ全体
 * 戻り値:
 *   格納すべきチェックサム値
 * コール元:
 *   ipv6_handle_icmpv6(), ipv6_send_icmpv6()
 * ===============================================================*/
static uint32_t ipv6_pseudo_sum(const uint8_t src[IPV6_ADDR_LEN],
                                 const uint8_t dst[IPV6_ADDR_LEN],
                                 uint8_t next_hdr, uint32_t len)
{
    uint32_t sum = 0;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i += 2) {
        sum += ((uint32_t)src[i] << 8) | src[i + 1];
        sum += ((uint32_t)dst[i] << 8) | dst[i + 1];
    }
    /* IPv6 の疑似ヘッダは長さが 32bit、next header は 32bit フィールドの
     * 最下位バイト。16bit ワードの和としてはどちらも下記で足りる。 */
    sum += (len >> 16) & 0xFFFFu;
    sum += len & 0xFFFFu;
    sum += (uint32_t)next_hdr;
    return sum;
}

uint16_t ipv6_pseudo_checksum(const uint8_t src[IPV6_ADDR_LEN],
                               const uint8_t dst[IPV6_ADDR_LEN],
                               uint8_t next_hdr,
                               const volatile uint8_t *data, uint16_t len)
{
    uint32_t sum = ipv6_pseudo_sum(src, dst, next_hdr, len);
    sum = checksum_accumulate(sum, data, len);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

uint16_t ipv6_pseudo_checksum_only(const uint8_t src[IPV6_ADDR_LEN],
                                    const uint8_t dst[IPV6_ADDR_LEN],
                                    uint8_t next_hdr, uint16_t len)
{
    uint32_t sum = ipv6_pseudo_sum(src, dst, next_hdr, len);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

uint16_t ipv6_pseudo_checksum2(const uint8_t src[IPV6_ADDR_LEN],
                                const uint8_t dst[IPV6_ADDR_LEN], uint8_t next_hdr,
                                const volatile uint8_t *hdr, uint16_t hdr_len,
                                const void *data, uint16_t data_len)
{
    uint32_t sum = ipv6_pseudo_sum(src, dst, next_hdr,
                                    (uint32_t)hdr_len + (uint32_t)data_len);
    sum = checksum_accumulate(sum, hdr, hdr_len);
    sum = checksum_accumulate(sum, data, data_len);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

/*=================================================================
 * Ethernet + IPv6 ヘッダを buf の先頭へ組み立てる(ip_build_header の IPv6 版)。
 * IPv6 ヘッダにチェックサムは無いので、ここで計算するものは無い。
 *
 * 引数:
 *   buf         - 書き込み先(ETH_HDR_LEN + IPV6_HDR_LEN 以上の余裕が必要)
 *   src / dst   - 送信元・宛先 IPv6 アドレス
 *   dst_mac     - 宛先 MAC
 *   next_header - 上位プロトコル番号
 *   payload_len - 上位プロトコルのバイト数
 * コール元:
 *   tcp_send_segment() 系、udp_send6()
 * ===============================================================*/
void ipv6_build_header(uint8_t *buf, const uint8_t src[IPV6_ADDR_LEN],
                        const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
                        uint8_t next_header, uint16_t payload_len)
{
    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);

    const volatile uint8_t *vdst_mac = dst_mac;
    volatile uint8_t *out = buf;

    for (int i = 0; i < ETH_ALEN; i++) out[i]            = vdst_mac[i];
    for (int i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x86; out[13] = 0xDD;  /* EtherType: IPv6 */

    volatile uint8_t *h = out + ETH_HDR_LEN;
    h[0] = 0x60; h[1] = 0; h[2] = 0; h[3] = 0;   /* version=6, TC=0, flow label=0 */
    wr16be(h + offsetof(ipv6_header_t, payload_len), payload_len);
    h[offsetof(ipv6_header_t, next_header)] = next_header;
    /* RA の Cur Hop Limit があればそれ(RFC 4861 6.3.4)。読むのは 1 バイトだけ。 */
    h[offsetof(ipv6_header_t, hop_limit)]   = ipv6_default_hop_limit();
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        h[offsetof(ipv6_header_t, src) + i] = src[i];
        h[offsetof(ipv6_header_t, dst) + i] = dst[i];
    }
}

/*=================================================================
 * ICMPv6 メッセージを 1 個送る。Ethernet + IPv6 ヘッダを組み立て、
 * 疑似ヘッダ込みのチェックサムを埋めてから送出する。
 *
 * 引数:
 *   dst / dst_mac - 宛先
 *   msg / msg_len - ICMPv6 メッセージ全体(チェックサム欄は 0 にしておく)
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
static int ipv6_send_icmpv6_from(const uint8_t src[IPV6_ADDR_LEN],
                                  const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
                                  uint8_t *msg, uint16_t msg_len)
{
    /* チェックサムの疑似ヘッダには実際に送る送信元アドレスを使う。DAD の NS は
     * :: で送るので、ここを自分のリンクローカルで計算すると相手が捨てる。 */
    wr16be(msg + ICMPV6_OFF_CHECKSUM, 0);
    uint16_t csum = ipv6_pseudo_checksum(src, dst, IPV6_NH_ICMPV6, msg, msg_len);
    wr16be(msg + ICMPV6_OFF_CHECKSUM, csum);

    return ipv6_send_from(src, dst, dst_mac, IPV6_NH_ICMPV6, msg, msg_len);
}

static int ipv6_send_icmpv6(const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
                             uint8_t *msg, uint16_t msg_len)
{
    uint8_t src[IPV6_ADDR_LEN];
    ipv6_source_for(dst, src);
    return ipv6_send_icmpv6_from(src, dst, dst_mac, msg, msg_len);
}

/*=================================================================
 * 拡張ヘッダを長さだけ見て辿り、上位のヘッダの位置と種類を返す(中身の検査は
 * しない。引用されたパケットや、送ろうとしているエラーの誘因を読むためのもの)。
 *
 * 引数:
 *   p / total - IPv6 ヘッダの先頭と、使える長さ
 *   nh_out    - 上位の種類(Fragment の 2 つ目以降の断片なら IPV6_NH_FRAGMENT)
 * 戻り値:
 *   上位のヘッダの位置(p からのバイト数)、辿れなければ -1
 * コール元:
 *   icmpv6_send_error(), icmpv6_error_to_upper()
 * ===============================================================*/
static long ipv6_walk_light(const uint8_t *p, size_t total, uint8_t *nh_out)
{
    if (total < IPV6_HDR_LEN) return -1;
    uint8_t nh  = p[6];
    size_t  off = IPV6_HDR_LEN;
    for (unsigned depth = 0; depth < 8u; depth++) {
        if (nh == IPV6_NH_HOPOPTS || nh == IPV6_NH_ROUTING || nh == IPV6_NH_DSTOPTS) {
            if (off + 2u > total) return -1;
            uint8_t next = p[off];
            off += ((size_t)p[off + 1u] + 1u) * 8u;
            nh = next;
            continue;
        }
        if (nh == IPV6_NH_FRAGMENT) {
            if (off + IPV6_FRAG_HDR_LEN > total) return -1;
            if ((rd16be(p + off + 2u) & IPV6_FRAG_OFF_MASK) != 0u) {
                *nh_out = IPV6_NH_FRAGMENT;   /* 先頭でない断片には上位のヘッダが無い */
                return (long)off;
            }
            nh = p[off];
            off += IPV6_FRAG_HDR_LEN;
            continue;
        }
        *nh_out = nh;
        return (long)off;
    }
    return -1;
}

/*=================================================================
 * ICMPv6 のエラーを送ってよい頻度か(RFC 4443 2.4(f) の MUST)。トークンバケツで、
 * 1 秒に ICMPV6_ERR_RATE_PER_SEC 個を補充し、ICMPV6_ERR_BURST 個まで溜める。
 *
 * **制限が無いと、壊れたパケットを撃ち込むだけでこちらに同じ数のエラーを送らせ
 * られる**(反射・増幅に使われる。送信元を偽った相手へ撃たせることもできる)。
 *
 * 戻り値:
 *   1=送ってよい(トークンを 1 つ使った)、0=制限
 * コール元:
 *   icmpv6_send_error()
 * ===============================================================*/
static int icmpv6_err_ratelimit_ok(void)
{
    while (__atomic_test_and_set(&s_err_lock, __ATOMIC_ACQUIRE)) { }
    const uint64_t step = 1000000000ull / ICMPV6_ERR_RATE_PER_SEC;   /* 1 個ぶんの ns */
    uint64_t now = timer_now();
    if (s_err_last == 0u) {
        s_err_last   = now;
        s_err_tokens = ICMPV6_ERR_BURST;
    } else if (now > s_err_last) {
        uint64_t add = (now - s_err_last) / step;
        if (add > 0u) {
            if ((uint64_t)s_err_tokens + add >= ICMPV6_ERR_BURST) {
                s_err_tokens = ICMPV6_ERR_BURST;
                s_err_last   = now;
            } else {
                s_err_tokens += (uint32_t)add;
                s_err_last   += add * step;
            }
        }
    }
    int ok = 0;
    if (s_err_tokens > 0u) { s_err_tokens--; ok = 1; }
    __atomic_clear(&s_err_lock, __ATOMIC_RELEASE);
    return ok;
}

/*=================================================================
 * ICMPv6 のエラーを 1 個送る(RFC 4443 2.4)。
 *
 * 送らない条件(2.4(e)、どれも MUST NOT):
 *   (e.1) 誘因が ICMPv6 のエラー(type < 128)。エラーにエラーを返すと、2 台で
 *         エラーを投げ合い続ける。
 *   (e.2) 誘因が Redirect。
 *   (e.3) 誘因の宛先がマルチキャスト(Packet Too Big と Parameter Problem code 2 を
 *         除く。この 2 つは送り手が知らないと直せないので、全員宛てでも返す)。
 *   (e.6) 誘因の送信元が 1 台を指さない(:: / マルチキャスト)。全員へ撒くことになる。
 * 加えて 2.4(f) の頻度の制限。
 *
 * 送信元は、誘因が自分のユニキャストアドレス宛てならそのアドレス(相手が誰からの
 * エラーか分かるように。2.2)、そうでなければ宛先に合わせて選ぶ。引用は IPv6 の
 * 最小 MTU(1280)に収まる分(2.4(c))。
 *
 * 引数:
 *   type / code / param - ICMPv6 の type / code と、4-7 バイト目(Pointer / MTU など)
 *   invoking / len      - 誘因のパケット(IPv6 ヘッダの先頭から)
 *   dst / dst_mac       - 送り先(普通は誘因の送信元とその MAC)。dst_mac が NULL なら
 *                         近隣キャッシュを引く(引けなければ送らない)
 * 戻り値:
 *   0=送った、-1=送らなかった
 * コール元:
 *   ipv6_handle_frame()、ipfrag.c(断片の時間切れ)
 * ===============================================================*/
int icmpv6_send_error(uint8_t type, uint8_t code, uint32_t param,
                      const uint8_t *invoking, size_t len,
                      const uint8_t dst[IPV6_ADDR_LEN], const uint8_t *dst_mac)
{
    if (!invoking || len < IPV6_HDR_LEN || !g_active_ctx) return -1;

    uint8_t inv_dst[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) inv_dst[i] = invoking[24u + i];

    /* (e.6) 送り先が 1 台を指さない */
    if (ipv6_addr_unspec(dst) || dst[0] == 0xFFu) return -1;
    /* (e.3) 誘因の宛先がマルチキャスト */
    int exempt = (type == ICMPV6_TYPE_PACKET_TOO_BIG) ||
                 (type == ICMPV6_TYPE_PARAM_PROBLEM && code == ICMPV6_CODE_PP_OPTION);
    if (inv_dst[0] == 0xFFu && !exempt) return -1;
    /* (e.1)(e.2) 誘因がエラーか Redirect */
    {
        uint8_t nh = 0;
        long off = ipv6_walk_light(invoking, len, &nh);
        if (off >= 0 && nh == IPV6_NH_ICMPV6) {
            if ((size_t)off + 1u > len) return -1;   /* 種類が読めないなら送らない(安全側) */
            uint8_t t = invoking[off];
            if (t < 128u || t == ICMPV6_TYPE_REDIRECT) return -1;
        }
    }
    /* (f) 頻度の制限 */
    if (!icmpv6_err_ratelimit_ok()) {
        g_icmpv6_err_ratelimited++;
        return -1;
    }

    uint8_t mac[ETH_ALEN];
    if (!dst_mac) {
        if (ndp_cache_lookup(netif_next_hop6(g_active_ctx, dst), mac) != 0) return -1;
        dst_mac = mac;
    }

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t msg[SMP_MAX_CORES][1280u - IPV6_HDR_LEN];
    size_t qlen = len;
    if (qlen > sizeof(msg[0]) - 8u) qlen = sizeof(msg[0]) - 8u;
    uint8_t *m = msg[core];
    m[ICMPV6_OFF_TYPE] = type;
    m[ICMPV6_OFF_CODE] = code;
    m[2] = 0; m[3] = 0;
    wr32be(m + 4u, param);
    for (size_t i = 0; i < qlen; i++) m[8u + i] = invoking[i];

    uint8_t src[IPV6_ADDR_LEN];
    if (inv_dst[0] != 0xFFu && ipv6_unicast_is_ours(g_active_ctx, inv_dst)) {
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) src[i] = inv_dst[i];
    } else {
        ipv6_source_for(dst, src);
    }
    g_icmpv6_err_tx++;
    return ipv6_send_icmpv6_from(src, dst, dst_mac, m, (uint16_t)(8u + qlen));
}

/*=================================================================
 * いま処理している受信フレームを誘因にしてエラーを返す。icmpv6_send_error() の
 * 条件に加えて、**リンク層のマルチキャスト / ブロードキャストで届いたもの**にも返さない
 * (RFC 4443 2.4(e.4)(e.5)。例外は (e.3) と同じ)。
 *
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static void icmpv6_error_rx(uint8_t type, uint8_t code, uint32_t param,
                            const uint8_t *invoking, size_t len,
                            const uint8_t src[IPV6_ADDR_LEN], const uint8_t *src_mac)
{
    int exempt = (type == ICMPV6_TYPE_PACKET_TOO_BIG) ||
                 (type == ICMPV6_TYPE_PARAM_PROBLEM && code == ICMPV6_CODE_PP_OPTION);
    if (!exempt && eth_rx_l2_multicast()) return;
    /* 自分が出したマルチキャストがループバックしてきたもの(送信元 MAC が自分)には
     * 返さない(NS / RA のループバックを無視するのと同じ理由。自分宛てにエラーを
     * 送ることになる)。 */
    if (src_mac && g_active_ctx) {
        int self_lb = 1;
        for (unsigned i = 0; i < ETH_ALEN; i++) {
            if (src_mac[i] != g_active_ctx->mac[i]) { self_lb = 0; break; }
        }
        if (self_lb) return;
    }
    icmpv6_send_error(type, code, param, invoking, len, src, src_mac);
}

/*=================================================================
 * addr のエントリを探す。無ければ新しく使う枠(空き、無ければ確かめた時刻が
 * いちばん古いもの)を返す。arp_cache_slot() の IPv6 版。
 *
 * 引数:
 *   addr  - 相手の IPv6 アドレス
 *   found - 既存のエントリなら 1、新しく使う枠なら 0 を返す
 * コール元:
 *   ndp_cache_insert(), ndp_cache_learn(), ndp_cache_update_na()
 * ===============================================================*/
static ndp_cache_entry_t *ndp_cache_slot(const uint8_t addr[IPV6_ADDR_LEN], int *found)
{
    ndp_cache_entry_t *cache = g_active_ctx->ndp_cache;
    unsigned free_slot = NDP_CACHE_SIZE;
    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            if (free_slot == NDP_CACHE_SIZE) free_slot = i;
            continue;
        }
        int same = 1;
        for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) {
            if (cache[i].addr[j] != addr[j]) { same = 0; break; }
        }
        if (same) { *found = 1; return &cache[i]; }
    }
    *found = 0;
    if (free_slot < NDP_CACHE_SIZE) return &cache[free_slot];
    /* 空きが無ければ、確認できた時刻がいちばん古いものを潰す(失効したエントリは
     * 時間では消えないので、空きが無くなるのは普通に起きる)。 */
    unsigned slot = 0;
    for (unsigned i = 1; i < NDP_CACHE_SIZE; i++) {
        if ((int64_t)(cache[i].expires_at - cache[slot].expires_at) < 0) slot = i;
    }
    return &cache[slot];
}

/* エントリへ MAC を書き、fresh(期限を入れ直す)か stale(期限切れ扱い)にする。 */
static void ndp_cache_store(ndp_cache_entry_t *e, const uint8_t addr[IPV6_ADDR_LEN],
                            const uint8_t mac[ETH_ALEN], int fresh)
{
    for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) e->addr[j] = addr[j];
    for (unsigned j = 0; j < ETH_ALEN; j++) e->mac[j] = mac[j];
    e->valid      = 1;
    e->expires_at = fresh ? neigh_expiry_from_now() : timer_now();
    e->probe_at   = 0;
}

static int ndp_mac_eq(const uint8_t a[ETH_ALEN], const uint8_t b[ETH_ALEN])
{
    for (unsigned j = 0; j < ETH_ALEN; j++) if (a[j] != b[j]) return 0;
    return 1;
}

/*=================================================================
 * 到達を確かめた対応を近隣キャッシュへ登録する(fresh)。既存エントリがあれば
 * MAC を更新して延命する。ARP キャッシュと同じく、アクティブなインターフェースの
 * キャッシュに入れる。
 *
 * 引数:
 *   addr - 相手の IPv6 アドレス
 *   mac  - 対応する MAC
 * コール元:
 *   shell_arptest(), shell_nudtest()
 * ===============================================================*/
void ndp_cache_insert(const uint8_t addr[IPV6_ADDR_LEN], const uint8_t mac[ETH_ALEN])
{
    int found;
    ndp_cache_store(ndp_cache_slot(addr, &found), addr, mac, 1);
}

/*=================================================================
 * 相手が名乗った対応を覚える(RFC 4861 7.2.3 の NS、6.3.4 の RA の Source
 * Link-Layer Address)。無ければ stale で作り、あって MAC が違えば書き換えて
 * stale にする。MAC が同じなら状態は変えない。
 *
 * 相手が自分の MAC を名乗っただけで、こちらから届くことは確かめていないので
 * fresh にはしない(次に使うときに DELAY -> 確認を経る)。
 *
 * 引数:
 *   addr - 相手の IPv6 アドレス
 *   mac  - 相手が名乗った MAC
 * コール元:
 *   ipv6_handle_icmpv6()(NS)、ipv6_handle_ra()
 * ===============================================================*/
void ndp_cache_learn(const uint8_t addr[IPV6_ADDR_LEN], const uint8_t mac[ETH_ALEN])
{
    int found;
    ndp_cache_entry_t *e = ndp_cache_slot(addr, &found);
    if (found && ndp_mac_eq(e->mac, mac)) return;
    ndp_cache_store(e, addr, mac, 0);
}

/*=================================================================
 * Neighbor Advertisement 1 通ぶんのキャッシュ更新(RFC 4861 7.2.5)。
 *
 * **無条件に上書きしてはいけない。** NA には Solicited と Override の 2 つの
 * フラグがあり、意味が違う:
 *
 *  - **Solicited=1**: こちらの NS への応答。**到達性が確認できた証拠**なので
 *    fresh にする。非要請の NA(相手が MAC を変えたときなどに撒く)は
 *    「その MAC を名乗った」以上の情報を持たないので、MAC が変わったときに
 *    stale にするだけで延命はしない。
 *  - **Override=0** で、キャッシュ済みの MAC と違う値を持ってきた NA は
 *    **MAC を書き換えない**(fresh なら stale へ落として次の使用で確かめさせる)。
 *    ここを無条件上書きにしていると、**偽の NA を 1 通投げるだけで他人宛の
 *    トラフィックを奪える**(NDP スプーフィング)。
 *
 * 引数:
 *   addr          - NA の Target Address
 *   mac           - 相手の MAC(Target Link-Layer Address または送信元 MAC)
 *   solicited     - S フラグ
 *   override_flag - O フラグ
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
void ndp_cache_update_na(const uint8_t addr[IPV6_ADDR_LEN], const uint8_t mac[ETH_ALEN],
                          int solicited, int override_flag)
{
    int found;
    ndp_cache_entry_t *e = ndp_cache_slot(addr, &found);

    if (!found) {
        /* **エントリが無ければ黙って捨てる**(RFC 4861 7.2.5)。ただしこのスタックは
         * INCOMPLETE のエントリを作らない(ndp_resolve() が NS を出してから NA を
         * 待つ形)ので、「いま解決している最中の相手」を INCOMPLETE とみなし、
         * その相手の NA だけを受け付ける(S=1 なら fresh、S=0 なら stale。
         * INCOMPLETE のエントリが NA を受けたときと同じ)。頼んでいない相手の NA で
         * 表を埋めない。 */
        netaddr_t na = netaddr_v6(addr);
        if (!neigh_req_pending(&na)) return;
        ndp_cache_store(e, addr, mac, solicited);
        return;
    }

    int mac_same = ndp_mac_eq(e->mac, mac);
    if (!mac_same && !override_flag) {
        uart_printf("[NDP] Override 無しの NA が既存と違う MAC を主張 -- MAC は書き換えない"
                    "(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        /* fresh だったものは stale へ落とす(RFC 4861 7.2.5)。 */
        uint64_t now = timer_now();
        if ((int64_t)(now - e->expires_at) < 0) {
            e->expires_at = now;
            e->probe_at   = 0;
        }
        return;
    }
    if (solicited) {
        ndp_cache_store(e, addr, mac, 1);      /* 到達を確かめた */
    } else if (!mac_same) {
        ndp_cache_store(e, addr, mac, 0);      /* MAC だけ変わった。確かめていない */
    }
    /* S=0 で MAC が同じなら何も変えない。 */
}

/*=================================================================
 * 近隣キャッシュを引く。有効期限を過ぎたエントリは時間では捨てず、MAC を
 * 返しつつ DELAY の後に Neighbor Solicitation を投げる(ARP 側の
 * arp_cache_lookup() と同じ方針。理由は netif.h の説明にある)。
 *
 * 引数:
 *   addr    - 探す IPv6 アドレス
 *   out_mac - 見つかった MAC の格納先
 * 戻り値:
 *   0=見つかった(fresh または stale)、-1=無い/寿命切れ
 * コール元:
 *   ndp_resolve(), tcp_resolve_mac()
 * ===============================================================*/
int ndp_cache_lookup_nud(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out_mac[ETH_ALEN],
                          int confirmed)
{
    ndp_cache_entry_t *cache = g_active_ctx->ndp_cache;
    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) {
        if (!cache[i].valid) continue;
        int same = 1;
        for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) {
            if (cache[i].addr[j] != addr[j]) { same = 0; break; }
        }
        if (!same) continue;

        /* **上位層の到達確認**(RFC 4861 7.3.1)。ARP 側と同じ理由。 */
        if (confirmed) {
            g_neigh_confirm_count++;
            cache[i].expires_at = neigh_expiry_from_now();
            cache[i].probe_at   = 0;
            for (unsigned j = 0; j < ETH_ALEN; j++) out_mac[j] = cache[i].mac[j];
            return 0;
        }

        /* 時刻の読み出しは照合が当たったときだけ(1 回)。 */
        int age = neigh_check_age(timer_now(), cache[i].expires_at, &cache[i].probe_at,
                                  &cache[i].probes);
        if (age == NEIGH_DEAD) {
            cache[i].valid = 0;
            /* **届かなくなった相手がいま選んでいるデフォルトルータなら、別のルータへ
             * 切り替える**(RFC 4861 6.3.6:到達できる / できそうなルータを優先する)。
             * ここを通るのは確認要求が全部無応答だった 1 回だけなので、ホットパスの
             * 費用にはならない。 */
            netif_t *ni = g_active_ctx;
            if (ni && ni->gateway6_set && ni->gateway6_from_ra && ipv6_eq16(addr, ni->gateway6)) {
                ipv6_router_select(ni, 1);
            }
            return -1;
        }
        for (unsigned j = 0; j < ETH_ALEN; j++) out_mac[j] = cache[i].mac[j];
        if (age == NEIGH_STALE_PROBE) {
            /* **到達確認はユニキャスト NS**(RFC 4861 7.2.4)。要請ノード
             * マルチキャストへ投げる必要があるのは MAC を知らないときだけで、
             * ここでは既に持っている。**B2 を入れた後はこの差が効く** --
             * スヌーピングするスイッチの配下でマルチキャストが刈られていても、
             * ユニキャストの確認要求は必ず届く。 */
            ndp_send_ns_unicast(addr, cache[i].mac);
        }
        return 0;
    }
    return -1;
}

int ndp_cache_lookup(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out_mac[ETH_ALEN])
{
    return ndp_cache_lookup_nud(addr, out_mac, 0);
}

/*=================================================================
 * NDP エントリの寿命だけを観測する(arp_cache_peek() の IPv6 版)。
 * キャッシュは書き換えない。
 *
 * 引数:
 *   addr      - 探す IPv6 アドレス
 *   remain_ms - NULL 可。fresh なら失効まで、stale なら次の確認要求までの残り
 * 戻り値:
 *   0=fresh、1=stale、-1=未登録、または確認要求がすべて無応答(次の lookup で破棄)
 * コール元:
 *   shell_arptest()
 * ===============================================================*/
int ndp_cache_peek(const uint8_t addr[IPV6_ADDR_LEN], uint32_t *remain_ms)
{
    const ndp_cache_entry_t *cache = g_active_ctx->ndp_cache;
    uint64_t now = timer_now();

    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) {
        if (!cache[i].valid) continue;
        int same = 1;
        for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) {
            if (cache[i].addr[j] != addr[j]) { same = 0; break; }
        }
        if (!same) continue;

        return neigh_peek_state(now, cache[i].expires_at, cache[i].probe_at,
                                cache[i].probes, remain_ms);
    }
    return -1;
}

/*=================================================================
 * Neighbor Solicitation を 1 個送る。宛先は target の要請ノードマルチキャスト
 * (ff02::1:ffXX:XXXX)で、L2 は 33:33 + そのアドレス下位 4 バイト。Source
 * Link-Layer Address オプションを付けて相手が NA を返せるようにする。
 *
 * 引数:
 *   target - 解決したい相手の IPv6 アドレス
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ndp_resolve()
 * ===============================================================*/
static int ndp_send_ns_to(const uint8_t target[IPV6_ADDR_LEN],
                           const uint8_t *unicast_mac)
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t ns[SMP_MAX_CORES][8u + NDP_BODY_LEN + 8u];

    uint8_t *m = ns[core];
    for (unsigned i = 0; i < 8u + NDP_BODY_LEN + 8u; i++) m[i] = 0;
    m[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_NS;
    m[ICMPV6_OFF_CODE] = 0;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) m[8u + NDP_OFF_TARGET + i] = target[i];

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    m[8u + NDP_BODY_LEN + 0] = NDP_OPT_SRC_LLADDR;
    m[8u + NDP_BODY_LEN + 1] = 1u;
    for (unsigned i = 0; i < ETH_ALEN; i++) m[8u + NDP_BODY_LEN + 2u + i] = self_mac[i];

    /* **到達確認(NUD)のときは宛先もユニキャスト**(RFC 4861 7.2.4)。
     * 相手の MAC もアドレスも既に知っているので、要請ノードマルチキャストへ
     * 投げる必要が無い。マルチキャストが必要なのは「MAC を知らない初回の解決」
     * だけ。 */
    uint8_t sol[IPV6_ADDR_LEN];
    uint8_t dst_mac[ETH_ALEN];
    if (unicast_mac) {
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) sol[i] = target[i];
        for (unsigned i = 0; i < ETH_ALEN; i++) dst_mac[i] = unicast_mac[i];
    } else {
        ipv6_solicited_node_addr(target, sol);
        dst_mac[0] = 0x33; dst_mac[1] = 0x33; dst_mac[2] = 0xFF;
        dst_mac[3] = target[13]; dst_mac[4] = target[14]; dst_mac[5] = target[15];
    }
    neigh_probe_notify(1, unicast_mac ? 1 : 0, dst_mac);

    /* **送信元は「解決したい対象」のスコープに合わせる。** 宛先である要請ノード
     * マルチキャストで選ぶと常にリンクローカルになり、相手の NA もこちらの
     * リンクローカル宛に返ってくる。対向 PF と MAC(=リンクローカル)を共有する
     * 別名インターフェースでは、その NA をどちらのものか区別できず近隣キャッシュ
     * が別名に入らない。RFC 4861 4.3 も「その後のトラフィックで使う送信元を
     * 選ぶ」ことを求めている。 */
    uint8_t ns_src[IPV6_ADDR_LEN];
    ipv6_source_for(target, ns_src);
    return ipv6_send_icmpv6_from(ns_src, sol, dst_mac, m,
                                 (uint16_t)(8u + NDP_BODY_LEN + 8u));
}

static int ndp_send_ns(const uint8_t target[IPV6_ADDR_LEN])
{
    return ndp_send_ns_to(target, NULL);
}

/*=================================================================
 * 到達確認(NUD)用のユニキャスト NS(RFC 4861 7.2.4)。
 *
 * 引数:
 *   target - 確認したい相手のアドレス
 *   mac    - キャッシュしている相手の MAC
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ndp_cache_lookup_nud()
 * ===============================================================*/
int ndp_send_ns_unicast(const uint8_t target[IPV6_ADDR_LEN], const uint8_t mac[ETH_ALEN])
{
    return ndp_send_ns_to(target, mac);
}

/*=================================================================
 * Router Solicitation を全ルータマルチキャスト(ff02::2、L2 は
 * 33:33:00:00:00:02)へ 1 個送る(RFC 4861 6.3.7)。
 *
 * ルータは通常 RA を定期的に撒いているが、その間隔は数分に及ぶ。RS は
 * 「起動直後に 1 回だけ催促する」ためのもので、**これが無くても非要請 RA を
 * 受け取れば SLAAC は動く**。
 *
 * 送信元は自分のリンクローカル(MAC から必ず導出できるので未指定アドレスに
 * する必要が無い)。したがって Source Link-Layer Address オプションを付けて
 * よい -- RFC 4861 が禁じているのは「送信元が :: のとき」だけ。
 *
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_slaac_solicit()
 * ===============================================================*/
int ipv6_send_rs(void)
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t rs[SMP_MAX_CORES][8u + 8u];

    uint8_t *m = rs[core];
    for (unsigned i = 0; i < 8u + 8u; i++) m[i] = 0;
    m[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_RS;
    m[ICMPV6_OFF_CODE] = 0;
    /* m[4..7] は reserved(0)。RS は本体を持たず、直後がオプション。 */

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);
    m[8] = NDP_OPT_SRC_LLADDR;
    m[9] = 1u;  /* 長さ(8 バイト単位) */
    for (unsigned i = 0; i < ETH_ALEN; i++) m[10u + i] = self_mac[i];

    uint8_t all_routers[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) all_routers[i] = 0;
    all_routers[0] = 0xFF; all_routers[1] = 0x02; all_routers[15] = 0x02;  /* ff02::2 */
    const uint8_t dst_mac[ETH_ALEN] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x02 };

    uint8_t src[IPV6_ADDR_LEN];
    ipv6_link_local_addr(src);
    return ipv6_send_icmpv6_from(src, all_routers, dst_mac, m, (uint16_t)(8u + 8u));
}

/*=================================================================
 * 重複アドレス検出用の Neighbor Solicitation を 1 個送る。通常の NS との
 * 違いは 2 点で、どちらも RFC で決まっている:
 *
 *  - **送信元アドレスは未指定アドレス(::)。** まだそのアドレスを使って
 *    よいと確定していないので、送信元に置けない(RFC 4862 5.4.2)。
 *  - **Source Link-Layer Address オプションを付けてはいけない**
 *    (RFC 4861 4.3: 送信元が :: のとき MUST NOT)。相手はこれで学習できない
 *    ので、代わりに全ノードマルチキャストへ NA を返してくる。
 *
 * 引数:
 *   target - 使う前に検査したいアドレス
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_dad()
 * ===============================================================*/
static int ndp_send_dad_ns(const uint8_t target[IPV6_ADDR_LEN])
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t ns[SMP_MAX_CORES][8u + NDP_BODY_LEN];

    uint8_t *m = ns[core];
    for (unsigned i = 0; i < 8u + NDP_BODY_LEN; i++) m[i] = 0;
    m[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_NS;
    m[ICMPV6_OFF_CODE] = 0;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) m[8u + NDP_OFF_TARGET + i] = target[i];

    /* 宛先は target の要請ノードマルチキャスト ff02::1:ffXX:XXXX */
    uint8_t sol[IPV6_ADDR_LEN];
    ipv6_solicited_node_addr(target, sol);

    const uint8_t dst_mac[ETH_ALEN] = { 0x33, 0x33, 0xFF,
                                        target[13], target[14], target[15] };

    uint8_t unspec[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) unspec[i] = 0;

    return ipv6_send_icmpv6_from(unspec, sol, dst_mac, m, (uint16_t)(8u + NDP_BODY_LEN));
}

/*=================================================================
 * 重複アドレス検出(RFC 4862)。target を使い始める前に、その address を
 * 既に誰かが使っていないかを確かめる。DAD 用の NS を probes 個送り、
 * 各回 interval_ms のあいだ受信を回して、
 *
 *  - target を target とする **NA** が返ってくる  -> 既に使われている
 *  - 同じ target の **DAD NS** が返ってくる        -> 相手も同時に検査中(衝突)
 *
 * のどちらも衝突として扱う。何も返ってこなければ空きと判断する。
 * **「返ってこないこと」で判定するので、待ち時間ぶんは必ずかかる。**
 *
 * 引数:
 *   target      - 検査するアドレス
 *   probes      - NS を送る回数
 *   interval_ms - 1 回ごとに応答を待つ時間
 *   out_mac     - NULL 可。衝突時に相手の MAC を入れる
 * 戻り値:
 *   0=空き、1=既に使われている、-1=送信失敗
 * コール元:
 *   net_dup_addr_detect(), shell_dadtest()
 * ===============================================================*/
int ipv6_dad(const uint8_t target[IPV6_ADDR_LEN], unsigned probes, uint32_t interval_ms,
             uint8_t out_mac[ETH_ALEN])
{
    eth_get_mac(s_dad_self_mac);
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) s_dad_target[i] = target[i];
    s_dad_conflict = 0;
    s_dad_active = 1;

    for (unsigned attempt = 0; attempt < probes && !s_dad_conflict; attempt++) {
        if (ndp_send_dad_ns(target) != 0) {
            s_dad_active = 0;
            return -1;
        }
        uint64_t start = timer_now();
        while (!timeout_ms(start, interval_ms)) {
            net_poll_all_and_dispatch();
            if (s_dad_conflict) break;
        }
    }

    s_dad_active = 0;
    if (s_dad_conflict) {
        if (out_mac) {
            for (unsigned i = 0; i < ETH_ALEN; i++) out_mac[i] = s_dad_conflict_mac[i];
        }
        return 1;
    }
    return 0;
}

/*=================================================================
 * ステートレスアドレス自動設定(SLAAC)を 1 回試みる。RS を送って RA を待ち、
 * RA から作られたグローバルアドレスの DAD の結果が出るまで待つ。
 *
 * RA の解釈そのものは受信ハンドラ(ipv6_handle_ra)にある。非要請 RA も
 * 同じ経路を通るので、この関数は「最初の 1 通を早く貰うための催促」と
 * 「結果が出るまで待って返す」を担当する。
 *
 * **DAD は受信ハンドラの中で始めて、待たない**(ipv6_slaac_apply_prefix() が
 * NS を出して TENTATIVE にし、衝突の知らせは受信ハンドラが、時間切れ = 空きの
 * 判定は ipv6_dad_settle() が行う)。以前は ipv6_dad()(待つ間に受信を回す)を
 * ここでしか呼べず、**非要請 RA だけで作ったアドレスは DAD をしないまま使って
 * いた**(受信処理の中から受信を回すと再入する)。
 *
 * 引数:
 *   ni          - 対象インターフェース(NULL ならアクティブなもの)
 *   solicits    - RS を送る回数
 *   interval_ms - 1 回ごとに RA を待つ時間
 * 戻り値:
 *   1=グローバルアドレスを設定した、0=RA が来ない/採用しなかった、-1=送信失敗
 * コール元:
 *   run_shell(), shell_slaac()
 * ===============================================================*/
int ipv6_slaac_solicit(netif_t *ni, unsigned solicits, uint32_t interval_ms)
{
    netif_t *prev = g_active_ctx;
    if (ni) netif_activate(ni); else ni = g_active_ctx;
    if (!ni) return -1;

    uint32_t before = s_slaac_ra_seen;
    int got = 0;
    int rc = 0;

    for (unsigned attempt = 0; attempt < solicits && !got; attempt++) {
        if (ipv6_send_rs() != 0) {
            if (prev) netif_activate(prev);
            return -1;
        }
        uint64_t start = timer_now();
        while (!timeout_ms(start, interval_ms)) {
            net_poll_all_and_dispatch();
            /* **このインターフェースが処理した RA だけを数える。** 対向 PF が
             * 受け取った RA で打ち切ると「RA は来たのにアドレスが無い」という
             * 結果になる(実機で踏んだ)。 */
            if (s_slaac_ra_seen != before && s_slaac_ra_if == ni) { got = 1; break; }
        }
    }

    if (!got) {
        if (prev) netif_activate(prev);
        return 0;   /* RA を出すルータが居ない(このリンクでは通常こちら) */
    }

    /* RA は届いた。RA の処理(ipv6_slaac_apply_prefix())が DAD の NS を出して
     * TENTATIVE にしてあるので、判定時刻まで受信を回して結果を待つ(衝突の知らせは
     * 受信ハンドラが処理する)。 */
    netif_activate(ni);
    {
        uint64_t t0 = timer_now();
        while (ni->ip6_global_set && ni->ip6_global_from_ra &&
               ni->ip6_global_dad == NETIF_DAD_TENTATIVE &&
               !timeout_ms(t0, IPV6_SLAAC_DAD_MS * 3u)) {
            net_poll_all_and_dispatch();
            ipv6_timer_tick();
            netif_activate(ni);
        }
    }
    if (ni->ip6_global_set && ni->ip6_global_dad == NETIF_DAD_PASSED) {
        rc = 1;
    } else if (ni->ip6_global_set && ni->ip6_global_from_ra &&
        ni->ip6_global_dad == NETIF_DAD_UNKNOWN) {
        /* RA の処理を通らずに作られたもの(普通は無い)。従来どおりその場で検査する。 */
        uint8_t mac[ETH_ALEN];
        int used = ipv6_dad(ni->ip6_global, 2u, 50u, mac);
        if (used == 1) {
            /* **SLAAC のアドレスは衝突したら使わない**(RFC 4862 5.4.5)。
             * 手動設定のアドレス(net_dup_addr_detect)は「検出しても使い続ける」
             * 方針だが、あれは 2 つの PF を同一プロセスで駆動しているせいで
             * 誤検出が起きうるための妥協。RA から勝手に作ったアドレスまで
             * 使い続ける理由は無い。 */
            ni->ip6_global_dad     = NETIF_DAD_CONFLICT;
            ni->ip6_global_set     = 0;
            ni->ip6_global_from_ra = 0;
            for (unsigned i = 0; i < ETH_ALEN; i++) ni->dup_mac6[i] = mac[i];
            uart_printf("[!] SLAAC: 作ったアドレスが既に使われています "
                        "(%02x:%02x:%02x:%02x:%02x:%02x)-- 使用しません\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            rc = 0;
        } else if (used == 0) {
            ni->ip6_global_dad = NETIF_DAD_PASSED;
            rc = 1;
        } else {
            rc = 0;
        }
    } else if (ni->ip6_global_set) {
        rc = 1;
    }

    if (prev) netif_activate(prev);
    return rc;
}

/*=================================================================
 * IPv6 アドレスから MAC を得る。キャッシュに無ければ NS を送って NA を待つ。
 * arp_resolve() と同じ「送って待つ」同期解決で、**同じ宛先へ NS を出すのは
 * RETRANS_TIMER(1 秒)に 1 回まで**(RFC 4861 7.2.2 の MUST)。1 回の呼び出しで
 * 出すのは 1 個だけで、応答を最大 1 秒待つ。
 *
 * 引数:
 *   addr    - 解決したい相手の IPv6 アドレス
 *   out_mac - 見つかった MAC の格納先
 * 戻り値:
 *   0=解決できた、-1=時間切れ
 * コール元:
 *   tcp_send_segment() 系、udp_send6()
 * ===============================================================*/
int ndp_resolve(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out_mac[ETH_ALEN])
{
    if (ndp_cache_lookup(addr, out_mac) == 0) return 0;

    netaddr_t a = netaddr_v6(addr);
    uint64_t *last = neigh_req_stamp(&a);
    const uint64_t iv = (uint64_t)NEIGH_RETRANS_MS * 1000000ull;
    uint64_t now = timer_now();
    if (*last == 0u || now - *last >= iv) {
        if (ndp_send_ns(addr) != 0) return -1;
        *last = now;
    }
    const uint64_t until = *last + iv;
    netif_t *ni = g_active_ctx;
    do {
        net_poll_all_and_dispatch();
        ipv6_timer_tick();
        if (ndp_cache_lookup(addr, out_mac) == 0) return 0;
    } while ((int64_t)(timer_now() - until) < 0);
    /* 解決できなかった相手がいま選んでいる RA のデフォルトルータなら、次に送るときは
     * 別のルータを使う(RFC 4861 6.3.6。到達できないルータに送り続けない)。 */
    if (ni && ni->gateway6_set && ni->gateway6_from_ra && ipv6_eq16(addr, ni->gateway6)) {
        ipv6_router_select(ni, 1);
    }
    return -1;
}

/*=================================================================
 * 報告対象のマルチキャストグループを列挙する。
 *
 * このスタックが参加しているのは
 *   ff02::1(全ノード)/ 要請ノードマルチキャスト(リンクローカル由来)/
 *   要請ノードマルチキャスト(グローバル由来、設定されていれば)
 * の 3 つだが、**ff02::1 は MLD の報告対象外**(RFC 3810 6:「リンクスコープの
 * 全ノードアドレスについては報告しない」)。ルータは全ノードアドレスへ配送
 * できることを前提にしてよいので、報告する意味が無い。
 *
 * 引数:
 *   ni  - 対象インターフェース(NULL ならアクティブなもの)
 *   out - 16 バイト x max の格納先
 * 戻り値:
 *   書き込んだグループ数
 * コール元:
 *   ipv6_mld_report_all(), mld_handle_query(), shell_mld()
 * ===============================================================*/
unsigned ipv6_mcast_groups(netif_t *ni, uint8_t out[][IPV6_ADDR_LEN], unsigned max)
{
    netif_t *prev = g_active_ctx;
    if (ni) netif_activate(ni);

    unsigned n = 0;
    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);
    if (n < max) {
        ipv6_solicited_node_addr(ll, out[n]);
        n++;
    }
    /* グローバルアドレスの要請ノード。**DAD 中のアドレスのものも含める**
     * (RFC 4862 5.4.2:DAD の NS を出す前に、そのアドレスの要請ノードマルチキャストへ
     * 参加する。スヌーピングするスイッチの配下では、参加していないと相手の DAD の
     * NS が届かず、衝突を見つけられない)。 */
    netif_t *cur = g_active_ctx;
    for (unsigned k = 0; cur && k < a6_count(cur); k++) {
        a6slot_t s;
        if (!a6_slot(cur, k, &s)) break;
        if (!s.set) continue;
        uint8_t sol[IPV6_ADDR_LEN];
        ipv6_solicited_node_addr(s.addr, sol);
        /* リンクローカルと下位 24bit が同じなら要請ノードも同じになる
         * (SLAAC は EUI-64 を使うので実際そうなる)。重複して報告しない。 */
        int dup = 0;
        for (unsigned j = 0; j < n && !dup; j++) dup = ipv6_eq16(sol, out[j]);
        if (!dup && n < max) {
            for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[n][i] = sol[i];
            n++;
        }
    }

    if (prev) netif_activate(prev);
    return n;
}

/*=================================================================
 * MLD メッセージを 1 個送る。**通常の ipv6_send() は使えない**:
 *
 *  - **Hop-by-Hop の Router Alert オプションが必須**(RFC 2710 3)。
 *    これが無いとスイッチ/ルータは中身を見ずに転送してしまう。
 *  - **hop limit は 1**(リンクから出さない)。ipv6_send_from() は 255 固定。
 *
 * **チェックサムの疑似ヘッダに使う next header は 58(ICMPv6)で、IPv6 ヘッダ
 * に書く 0(Hop-by-Hop)ではない。** 長さも ICMPv6 メッセージ長だけで、
 * 拡張ヘッダは含めない。ここを取り違えると相手だけが静かに捨てる。
 *
 * 引数:
 *   dst / dst_mac - 宛先(マルチキャスト)
 *   msg / msg_len - ICMPv6 メッセージ(チェックサム欄は 0 でよい)
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   mld_send_v1(), mld_send_v2_report()
 * ===============================================================*/
static int mld_send(const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[ETH_ALEN],
                     uint8_t *msg, uint16_t msg_len)
{
    if (s_mld_suppress) return 0;   /* `mld off`(陰性対照用) */

    uint8_t src[IPV6_ADDR_LEN];
    ipv6_link_local_addr(src);   /* RFC 3810 5.1.14: 送信元はリンクローカル */

    wr16be(msg + ICMPV6_OFF_CHECKSUM, 0);
    wr16be(msg + ICMPV6_OFF_CHECKSUM,
           ipv6_pseudo_checksum(src, dst, IPV6_NH_ICMPV6, msg, msg_len));

    if (s_mld_observer) s_mld_observer(msg, msg_len, dst);

    uint32_t frame_len = (uint32_t)ETH_HDR_LEN + IPV6_HDR_LEN + 8u + msg_len;
    if (frame_len > NET_BUF_SIZE) return -1;
    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] MLD: net_buf 確保失敗\n");
        return -1;
    }

    /* Ethernet + IPv6(next header = Hop-by-Hop)。payload_length には
     * 拡張ヘッダ 8 バイトも含める。 */
    ipv6_build_header(nb->data, src, dst, dst_mac, IPV6_NH_HOPOPTS,
                      (uint16_t)(8u + msg_len));
    nb->data[ETH_HDR_LEN + offsetof(ipv6_header_t, hop_limit)] = 1u;

    /* Hop-by-Hop(8 バイトちょうど): next header / 長さ 0(=8 バイト)/
     * Router Alert(type 5、長さ 2、値 0 = MLD、RFC 2711)/ PadN で埋める。 */
    uint8_t *hbh = nb->data + ETH_HDR_LEN + IPV6_HDR_LEN;
    hbh[0] = IPV6_NH_ICMPV6;
    hbh[1] = 0;
    hbh[2] = IPV6_TLV_ROUTER_ALERT;
    hbh[3] = 2;
    hbh[4] = 0; hbh[5] = 0;
    hbh[6] = IPV6_TLV_PADN;
    hbh[7] = 0;

    for (uint16_t i = 0; i < msg_len; i++) hbh[8u + i] = msg[i];
    nb->len = (uint16_t)frame_len;

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    g_ipv6_mld_report_tx[core]++;
    return eth_send(nb);
}

/*=================================================================
 * マルチキャストアドレスに対応する Ethernet の宛先 MAC(33:33 + 下位 4 バイト、
 * RFC 2464)。
 *
 * コール元:
 *   mld_send_v1(), mld_send_v2_report()
 * ===============================================================*/
static void ipv6_mcast_mac(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out[ETH_ALEN])
{
    out[0] = 0x33; out[1] = 0x33;
    out[2] = addr[12]; out[3] = addr[13]; out[4] = addr[14]; out[5] = addr[15];
}

/*=================================================================
 * MLDv1 の Report / Done を 1 個送る(RFC 2710)。24 バイト固定。
 *
 * **宛先が種類で違う**: Report はそのグループ自身へ、Done は全ルータ
 * マルチキャスト ff02::2 へ。
 *
 * 引数:
 *   type  - ICMPV6_TYPE_MLD_REPORT または ICMPV6_TYPE_MLD_DONE
 *   group - 対象グループ
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_mld_report_all(), ipv6_mld_leave()
 * ===============================================================*/
static int mld_send_v1(uint8_t type, const uint8_t group[IPV6_ADDR_LEN])
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t msg[SMP_MAX_CORES][24];

    uint8_t *m = msg[core];
    for (unsigned i = 0; i < 24u; i++) m[i] = 0;
    m[ICMPV6_OFF_TYPE] = type;
    m[ICMPV6_OFF_CODE] = 0;
    /* m[4..5] = Maximum Response Delay(Report/Done では 0)、m[6..7] = reserved */
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) m[8u + i] = group[i];

    uint8_t dst[IPV6_ADDR_LEN], dst_mac[ETH_ALEN];
    if (type == ICMPV6_TYPE_MLD_DONE) {
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) dst[i] = 0;
        dst[0] = 0xFF; dst[1] = 0x02; dst[15] = 0x02;   /* ff02::2 全ルータ */
    } else {
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) dst[i] = group[i];
    }
    ipv6_mcast_mac(dst, dst_mac);
    return mld_send(dst, dst_mac, m, 24u);
}

/*=================================================================
 * MLDv2 の Report を 1 個送る(RFC 3810)。複数グループを 1 通にまとめられる。
 *
 * 本体 8 バイト(type/code/checksum/reserved/レコード数)の後ろに
 * Multicast Address Record が並ぶ。1 レコードは 20 バイト
 * (種別 1 + 補助語数 1 + 送信元数 2 + グループ 16)+ 送信元。
 * 送信元指定は使わないので常に 20 バイト。
 *
 * 宛先は **ff02::16(全 MLDv2 対応ルータ)**。v1 と違いグループ自身ではない。
 *
 * 引数:
 *   rec_type - MLD2_CHANGE_TO_EXCLUDE(参加)/ MODE_IS_EXCLUDE(Query 応答)/
 *              CHANGE_TO_INCLUDE(離脱)
 *   groups   - グループの配列、n - 個数
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_mld_report_all(), ipv6_mld_leave(), mld_handle_query()
 * ===============================================================*/
static int mld_send_v2_report(uint8_t rec_type,
                               const uint8_t groups[][IPV6_ADDR_LEN], unsigned n)
{
    if (n == 0u) return 0;
    if (n > IPV6_MCAST_MAX) n = IPV6_MCAST_MAX;

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t msg[SMP_MAX_CORES][8u + IPV6_MCAST_MAX * 20u];

    uint8_t *m = msg[core];
    unsigned len = 8u + n * 20u;
    for (unsigned i = 0; i < len; i++) m[i] = 0;
    m[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_MLD2_REPORT;
    m[ICMPV6_OFF_CODE] = 0;
    /* m[4..5] は reserved。**レコード数は 6-7**(4-5 ではない)。 */
    wr16be(m + 6u, (uint16_t)n);

    for (unsigned r = 0; r < n; r++) {
        uint8_t *rec = m + 8u + r * 20u;
        rec[0] = rec_type;
        rec[1] = 0;              /* 補助データ無し */
        wr16be(rec + 2u, 0);     /* 送信元指定無し */
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) rec[4u + i] = groups[r][i];
    }

    uint8_t dst[IPV6_ADDR_LEN], dst_mac[ETH_ALEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) dst[i] = 0;
    dst[0] = 0xFF; dst[1] = 0x02; dst[15] = 0x16;   /* ff02::16 */
    ipv6_mcast_mac(dst, dst_mac);
    return mld_send(dst, dst_mac, m, (uint16_t)len);
}

/* 再送までの待ち((0, Unsolicited Report Interval] の乱数、ns)。 */
static uint64_t mld_unsol_delay_ns(const netif_t *ni)
{
    uint32_t iv = ipv6_mld_v1_mode_of(ni) ? MLD_V1_UNSOL_INTERVAL_MS : MLD_UNSOL_INTERVAL_MS;
    uint32_t ms = 1u + (ipv6_rand32() % iv);
    return (uint64_t)ms * 1000000ull;
}

/*=================================================================
 * アクティブなインターフェースの参加グループを 1 回報告する(v1 互換モードなら
 * グループごとに v1 Report、そうでなければ v2 Report 1 通)。
 *
 * 戻り値:
 *   送った Report の数
 * コール元:
 *   ipv6_mld_report_all(), ipv6_timer_tick()
 * ===============================================================*/
static int mld_send_report_now(netif_t *ni)
{
    uint8_t groups[IPV6_MCAST_MAX][IPV6_ADDR_LEN];
    unsigned n = ipv6_mcast_groups(ni, groups, IPV6_MCAST_MAX);
    int sent = 0;
    if (ipv6_mld_v1_mode_of(ni)) {
        for (unsigned i = 0; i < n; i++) {
            if (mld_send_v1(ICMPV6_TYPE_MLD_REPORT, groups[i]) == 0) sent++;
        }
    } else if (mld_send_v2_report(MLD2_CHANGE_TO_EXCLUDE,
                                  (const uint8_t (*)[IPV6_ADDR_LEN])groups, n) == 0) {
        sent++;
    }
    return sent;
}

/*=================================================================
 * いま参加しているグループをすべて報告する(非要請 Report)。
 *
 * **v1 互換モードならグループごとに v1 Report、そうでなければ v2 Report 1 通。**
 * その場で MLD_UNSOLICITED_REPORTS 通送り、Robustness Variable の残りは間隔を空けて
 * ipv6_timer_tick() が再送する(1 通目が落ちてもスイッチが学習できるように)。
 *
 * 引数:
 *   ni - 対象インターフェース(NULL ならアクティブなもの)
 * 戻り値:
 *   その場で送った Report の数、-1=失敗
 * コール元:
 *   run_shell(), shell_mld(), ipv6_slaac_apply_prefix()
 * ===============================================================*/
int ipv6_mld_report_all(netif_t *ni)
{
    netif_t *prev = g_active_ctx;
    if (ni) netif_activate(ni); else ni = g_active_ctx;
    if (!ni) return -1;

    int sent = 0;
    for (unsigned rep = 0; rep < MLD_UNSOLICITED_REPORTS; rep++) sent += mld_send_report_now(ni);

    /* **残りは間隔を空けて再送する**(RFC 3810 6.1 / RFC 2710 4:Robustness - 1 回を、
     * (0, Unsolicited Report Interval] の乱数の間隔で)。続けて送ると、スイッチが
     * 一時的に取りこぼしたときに 2 通とも落ちる。再送は ipv6_timer_tick() が送る。
     * **参加し直したので、同じインターフェースの離脱の再送は取り消す**(離脱の後に
     * 参加し直したのに、遅れて Done が届くとスイッチがグループを外してしまう)。 */
    ni->mld_leave_left = 0;
    if (MLD_ROBUSTNESS > MLD_UNSOLICITED_REPORTS) {
        ni->mld_rep_left = (uint8_t)(MLD_ROBUSTNESS - MLD_UNSOLICITED_REPORTS);
        ni->mld_rep_at   = timer_now() + mld_unsol_delay_ns(ni);
        ipv6_timer_arm(ni);
    }

    if (prev) netif_activate(prev);
    return sent;
}

/*=================================================================
 * 1 グループの離脱を通知する。
 *
 * 引数:
 *   group - 離脱するグループ
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_mldtest(), shell_dispatch()(ip6addr off)
 * ===============================================================*/
static int mld_send_leave_now(const uint8_t group[IPV6_ADDR_LEN])
{
    if (ipv6_mld_v1_mode()) return mld_send_v1(ICMPV6_TYPE_MLD_DONE, group);

    uint8_t one[1][IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) one[0][i] = group[i];
    return mld_send_v2_report(MLD2_CHANGE_TO_INCLUDE,
                              (const uint8_t (*)[IPV6_ADDR_LEN])one, 1u);
}

int ipv6_mld_leave(const uint8_t group[IPV6_ADDR_LEN])
{
    int rc = mld_send_leave_now(group);
    /* **離脱も間隔を空けて繰り返す**(RFC 3810 6.1 の State Change Report は
     * Robustness 回。v1 の Done は RFC 2710 では 1 回だが、Linux も v1 互換時に
     * 同じ回数を送る)。再送するのは最後に離脱したグループ 1 つだけ(このスタックが
     * 離脱するのは `mld leave` とアドレスを外したときだけで、続けて複数を離脱する
     * ことはまれ。取りこぼしても次の Query に答えないことで最後は外れる)。 */
    netif_t *ni = g_active_ctx;
    if (ni && MLD_ROBUSTNESS > 1u) {
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) ni->mld_leave_group[i] = group[i];
        ni->mld_leave_left = (uint8_t)(MLD_ROBUSTNESS - 1u);
        ni->mld_leave_at   = timer_now() + mld_unsol_delay_ns(ni);
        ipv6_timer_arm(ni);
    }
    return rc;
}

/*=================================================================
 * MLD の Query を処理して Report を返す(RFC 3810 5.1 / 6.2)。
 *
 * **v1 と v2 の Query は ICMPv6 メッセージ長で区別する**(v1=24、v2>=28)。
 * Linux も同じ判定をしている。v1 の Query を受けたら一定時間 v1 互換モードに
 * 入り、以後の Report を v1 で送る -- **Linux ブリッジの既定は
 * `mcast_mld_version 1`** なので、実際にこの経路を通る。
 *
 * Multicast Address が :: なら General Query(全グループを報告)、
 * そうでなければそのグループだけを報告する。
 *
 * **応答は遅延させず即座に返す。** RFC は Maximum Response Delay までの
 * 乱数遅延を求めているが(応答の集中を避けるため)、このリンクにホストは
 * 2 つしか居ないので意味が無い。実 LAN へ出すなら入れること。
 *
 * 引数:
 *   in / len - ICMPv6 メッセージ全体
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
static void mld_handle_query(const volatile uint8_t *in, size_t len)
{
    netif_t *ni = g_active_ctx;
    if (!ni) return;
    /* **長さは 24(v1)か 28 以上(v2)だけ**(RFC 3810 8.1:それ以外の長さの Query は
     * 黙って捨てる)。25〜27 を v2 として読むと、ある筈の QRV / QQIC / 送信元の数を
     * メッセージの外から読むことになる。 */
    if (len != 24u && len < 28u) {
        uart_printf("[MLD] Query の長さが %u(24 でも 28 以上でもない)-- 破棄\n", (unsigned)len);
        return;
    }

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    g_ipv6_mld_query_count[core]++;

    int v1 = (len == 24u);
    if (v1) {
        /* v1 の Querier が居るあいだは v1 で喋る(RFC 3810 8.2.1)。**受けた
         * インターフェースだけ**(Querier の版はリンクごとに違いうる)。 */
        ni->mld_v1_until = timer_now() + (uint64_t)MLD_V1_COMPAT_MS * 1000000ull;
    }

    uint8_t mca[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) mca[i] = in[8u + i];
    int general = 1;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        if (mca[i] != 0) { general = 0; break; }
    }

    uint8_t groups[IPV6_MCAST_MAX][IPV6_ADDR_LEN];
    unsigned n = ipv6_mcast_groups(ni, groups, IPV6_MCAST_MAX);

    if (!general) {
        /* Multicast Address Specific Query -- 参加していれば 1 個だけ報告する。 */
        unsigned k = n;
        for (unsigned i = 0; i < n; i++) {
            int same = 1;
            for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) {
                if (groups[i][j] != mca[j]) { same = 0; break; }
            }
            if (same) { k = i; break; }
        }
        if (k == n) {
            uart_printf("[MLD] %s Query: 参加していないグループなので応答しません\n",
                        v1 ? "v1" : "v2");
            return;
        }
        for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) groups[0][j] = groups[k][j];
        n = 1;
    }

    uart_printf("[MLD] %s %s Query 受信 -> %u グループを報告します(%s)\n",
                v1 ? "v1" : "v2", general ? "General" : "Group-Specific", n,
                ipv6_mld_v1_mode() ? "v1 Report" : "v2 Report");

    if (ipv6_mld_v1_mode()) {
        for (unsigned i = 0; i < n; i++) mld_send_v1(ICMPV6_TYPE_MLD_REPORT, groups[i]);
    } else {
        mld_send_v2_report(MLD2_MODE_IS_EXCLUDE,
                           (const uint8_t (*)[IPV6_ADDR_LEN])groups, n);
    }
    /* **General Query に全グループを答えたら、非要請 Report の再送は取り消す。**
     * 再送の目的は「最初の 1 通が落ちてもスイッチ / ルータが参加を知ること」で、
     * いま答えた Current State Report が同じ内容を Querier へ届けている
     * (RFC 2710 4 の v1 でも、Query への Report で非要請の報告は役目を終える)。
     * 残しておくと、Query に答えた直後に同じ Report が重ねて出る。 */
    if (general) ni->mld_rep_left = 0;
}

/* ==== デフォルトルータの一覧(RFC 4861 6.3.4 / 6.3.6)====
 *
 * **一覧は router6[] に持ち、netif_t.gateway6 は「いま選んでいる 1 つ」の写し**に
 * する。gateway6 は送信ホットパス(netif_next_hop6())と main.c の表示・試験が直接
 * 読むので、形を変えずに残した。選び直すのは冷たい経路(RA の受信、R=0 の NA、
 * 寿命切れ、ルータに届かないと分かったとき)だけ。
 * **手動設定のゲートウェイ(`route`)があれば、一覧は覚えるだけで gateway6 は
 * 書き換えない**(運用者の設定を RA で上書きしない。CLAUDE.md の SLAAC の節)。 */

/* addr が一覧の何番目か。無ければ -1。 */
static int ipv6_router_find(const netif_t *ni, const uint8_t a[IPV6_ADDR_LEN])
{
    for (unsigned i = 0; i < ni->router6_cnt; i++) {
        if (ipv6_eq16(ni->router6[i].addr, a)) return (int)i;
    }
    return -1;
}

/*=================================================================
 * 宛先キャッシュから、次ホップが router のものを消す(RFC 4861 6.3.5:ルータを
 * 一覧から外したら、そのルータを次ホップにしている宛先は次ホップを決め直す)。
 *
 * コール元:
 *   ipv6_router_remove_at(), ipv6_handle_icmpv6()(R=0 の NA)
 * ===============================================================*/
static void ipv6_dest_purge(netif_t *ni, const uint8_t router[IPV6_ADDR_LEN])
{
    for (unsigned i = ni->dest6_cnt; i > 0u; i--) {
        if (!ipv6_eq16(ni->dest6[i - 1u].nexthop, router)) continue;
        unsigned last = ni->dest6_cnt - 1u;
        if (i - 1u != last) ni->dest6[i - 1u] = ni->dest6[last];
        ni->dest6_cnt = (uint8_t)last;
    }
}

/* 一覧の i 番目を外す(詰める)。そのルータ経由の宛先キャッシュも消す。 */
static void ipv6_router_remove_at(netif_t *ni, unsigned i)
{
    if (i >= ni->router6_cnt) return;
    uint8_t a[IPV6_ADDR_LEN];
    for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) a[j] = ni->router6[i].addr[j];
    unsigned last = ni->router6_cnt - 1u;
    if (i != last) ni->router6[i] = ni->router6[last];
    ni->router6_cnt = (uint8_t)last;
    ipv6_dest_purge(ni, a);
}

/*=================================================================
 * ルータが「届く、または届きそう」か(RFC 4861 6.3.6 の reachable / probably
 * reachable = 近隣キャッシュに INCOMPLETE 以外のエントリがある)。このスタックは
 * INCOMPLETE を作らないので、「エントリがあって、確認要求が尽きていない」で見る。
 *
 * コール元:
 *   ipv6_router_select()
 * ===============================================================*/
static int ipv6_router_reachable(netif_t *ni, const uint8_t a[IPV6_ADDR_LEN])
{
    uint64_t now = timer_now();
    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) {
        const ndp_cache_entry_t *e = &ni->ndp_cache[i];
        if (!e->valid || !ipv6_eq16(e->addr, a)) continue;
        return neigh_peek_state(now, e->expires_at, e->probe_at, e->probes, NULL) >= 0;
    }
    return 0;
}

/*=================================================================
 * デフォルトルータを選び直して gateway6 へ写す(RFC 4861 6.3.6)。
 *
 *  - 今のルータが一覧にあって届きそうなら**そのまま使う**(RFC は届くルータの間で
 *    回すことを求めていない。むやみに替えると近隣キャッシュの引き直しが増える)。
 *  - そうでなければ、一覧の先頭から最初の「届きそう」なもの。
 *  - 届きそうなものが 1 つも無ければ、今のものの次(ラウンドロビン。6.3.6 の
 *    「どれも届かないなら順に試す」)。
 *  - 一覧が空なら gateway6 を外す。
 *
 * 引数:
 *   ni            - インターフェース
 *   avoid_current - 1 なら今のルータは届かないものとして扱う(NUD / NDP の失敗の後)
 * コール元:
 *   ipv6_handle_ra(), ipv6_slaac_age(), ipv6_handle_icmpv6()(NA)、
 *   ndp_cache_lookup_nud(), ndp_resolve()
 * ===============================================================*/
static void ipv6_router_select(netif_t *ni, int avoid_current)
{
    if (!ni) return;
    if (ni->gateway6_set && !ni->gateway6_from_ra) return;   /* 手動設定を優先 */

    int cur = (ni->gateway6_set && ni->gateway6_from_ra) ? ipv6_router_find(ni, ni->gateway6) : -1;
    int pick = -1;
    if (cur >= 0 && !avoid_current && ipv6_router_reachable(ni, ni->router6[cur].addr)) pick = cur;
    for (unsigned i = 0; pick < 0 && i < ni->router6_cnt; i++) {
        if ((int)i == cur && avoid_current) continue;
        if (ipv6_router_reachable(ni, ni->router6[i].addr)) pick = (int)i;
    }
    if (pick < 0 && ni->router6_cnt) {
        pick = (cur >= 0) ? (int)(((unsigned)cur + 1u) % ni->router6_cnt) : 0;
    }
    if (pick < 0) {
        if (ni->gateway6_set) {
            uart_printf("[IPv6] %s: デフォルトルータが無くなりました\n", ni->name ? ni->name : "?");
        }
        ni->gateway6_set         = 0;
        ni->gateway6_from_ra     = 0;
        ni->gateway6_valid_until = 0;
        return;
    }
    const netif_router6_t *r = &ni->router6[pick];
    int changed = !ni->gateway6_set || !ipv6_eq16(ni->gateway6, r->addr);
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) ni->gateway6[i] = r->addr[i];
    ni->gateway6_set         = 1;
    ni->gateway6_from_ra     = 1;
    ni->gateway6_valid_until = r->valid_until;
    if (changed) {
        uart_printf("[IPv6] %s: デフォルトルータを fe80::...%02x%02x にしました(一覧 %u 件)\n",
                    ni->name ? ni->name : "?", r->addr[14], r->addr[15], ni->router6_cnt);
    }
}

/*=================================================================
 * on-link のプレフィックスの一覧を RA の Prefix Information(L=1)で更新する
 * (RFC 4861 6.3.4)。
 *   - 一覧に無く valid != 0 なら加える
 *   - 一覧にあって valid != 0 なら寿命を入れ直す
 *   - 一覧にあって valid == 0 ならすぐに外す
 *   - 一覧に無く valid == 0 なら何もしない
 * (アドレスの寿命と違い、on-link の寿命に 2 時間ルールは無い。)
 *
 * コール元:
 *   ipv6_ra_prefix()
 * ===============================================================*/
static void ipv6_onlink_update(netif_t *ni, const uint8_t prefix[IPV6_ADDR_LEN], uint8_t plen,
                               uint32_t valid)
{
    int idx = -1;
    for (unsigned i = 0; i < ni->prefix6_cnt; i++) {
        if (ni->prefix6[i].plen == plen && ipv6_eq16(ni->prefix6[i].prefix, prefix)) { idx = (int)i; break; }
    }
    if (valid == 0u) {
        if (idx >= 0) {
            unsigned last = ni->prefix6_cnt - 1u;
            if ((unsigned)idx != last) ni->prefix6[idx] = ni->prefix6[last];
            ni->prefix6_cnt = (uint8_t)last;
            uart_printf("[IPv6] RA: on-link のプレフィックス(/%u)を外しました\n", plen);
        }
        return;
    }
    if (idx < 0) {
        if (ni->prefix6_cnt >= NETIF_PREFIX6_MAX) {
            uart_printf("[IPv6] RA: on-link のプレフィックスの一覧が満杯 -- /%u は覚えません\n", plen);
            return;
        }
        idx = ni->prefix6_cnt++;
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) ni->prefix6[idx].prefix[i] = prefix[i];
        ni->prefix6[idx].plen = plen;
    }
    ni->prefix6[idx].valid_until = (valid == 0xFFFFFFFFu) ? 0u
                                 : timer_now() + (uint64_t)valid * 1000000000ull;
}

/*=================================================================
 * 宛先キャッシュに「dst は nexthop へ」を入れる(Redirect、RFC 4861 8.3)。
 * 満杯なら古いものから順に上書きする。
 *
 * コール元:
 *   ipv6_handle_redirect()
 * ===============================================================*/
static void ipv6_dest_set(netif_t *ni, const uint8_t dst[IPV6_ADDR_LEN],
                          const uint8_t nexthop[IPV6_ADDR_LEN])
{
    static unsigned s_next;   /* 満杯のときに上書きする位置(冷たい経路なので共有でよい) */
    int idx = -1;
    for (unsigned i = 0; i < ni->dest6_cnt; i++) {
        if (ipv6_eq16(ni->dest6[i].dst, dst)) { idx = (int)i; break; }
    }
    if (idx < 0) {
        if (ni->dest6_cnt < NETIF_DEST6_MAX) {
            idx = ni->dest6_cnt;
        } else {
            idx = (int)(s_next++ % NETIF_DEST6_MAX);
        }
    }
    /* 次ホップを先に書いてから数を増やす(送信ホットパスは数だけ見て引くので、
     * 書きかけの枠を見せない)。 */
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        ni->dest6[idx].dst[i]     = dst[i];
        ni->dest6[idx].nexthop[i] = nexthop[i];
    }
    __atomic_thread_fence(__ATOMIC_RELEASE);
    if ((unsigned)idx >= ni->dest6_cnt) ni->dest6_cnt = (uint8_t)(idx + 1);
}

/*=================================================================
 * DAD で衝突が分かった枠を外す(RFC 4862 5.4.5:そのアドレスは使わない)。
 *
 * **SLAAC のアドレスは衝突したら使わない。** 手動設定のアドレス
 * (net_dup_addr_detect)は「検出しても使い続ける」方針だが、あれは 2 つの PF を
 * 同一プロセスで駆動しているせいで誤検出が起きうるための妥協。RA から作った
 * アドレスまで使い続ける理由は無い。
 *
 * 引数:
 *   ni   - インターフェース
 *   slot - 枠の番号
 *   mac  - 衝突の相手の MAC
 * コール元:
 *   ipv6_handle_icmpv6()(相手の DAD の NS / NA)
 * ===============================================================*/
static void ipv6_dad_conflict(netif_t *ni, unsigned slot, const uint8_t *mac)
{
    a6slot_t s;
    if (!a6_slot(ni, slot, &s) || !s.set) return;
    uint8_t addr[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) addr[i] = s.addr[i];
    for (unsigned i = 0; i < ETH_ALEN; i++) ni->dup_mac6[i] = mac[i];
    uart_printf("[!] SLAAC: %s の ...%02x%02x:%02x%02x は既に使われています "
                "(%02x:%02x:%02x:%02x:%02x:%02x)-- 使用しません(RFC 4862 5.4.5)\n",
                ni->name ? ni->name : "?", addr[12], addr[13], addr[14], addr[15],
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    a6_remove(ni, slot);
    if (slot == 0u) ni->ip6_global_dad = NETIF_DAD_CONFLICT;

    /* そのアドレスのためだけに参加していた要請ノードマルチキャストから抜ける。 */
    uint8_t sol[IPV6_ADDR_LEN];
    ipv6_solicited_node_addr(addr, sol);
    uint8_t groups[IPV6_MCAST_MAX][IPV6_ADDR_LEN];
    unsigned n = ipv6_mcast_groups(ni, groups, IPV6_MCAST_MAX);
    int still = 0;
    for (unsigned i = 0; i < n && !still; i++) still = ipv6_eq16(groups[i], sol);
    if (!still) ipv6_mld_leave(sol);
}

/*=================================================================
 * Prefix Information の A=1 から SLAAC のアドレスを組む(RFC 4862 5.5.3)。
 * プレフィックス上位 64bit + 自分の EUI-64。
 *
 * 採用しない条件(どれも RFC が明示的に「無視せよ」と言っているもの):
 *   - A(Autonomous)フラグが立っていない
 *   - **prefix_len + インターフェース識別子長 != 128**。ここは EUI-64 固定
 *     なので prefix_len が 64 でなければ組めない
 *   - preferred lifetime > valid lifetime(壊れた RA)
 *   (リンクローカルのプレフィックスは呼び出し側で捨ててある)
 *
 * **プレフィックスごとに別の枠に入れる**(1 つ目が埋まっていれば ip6_extra[])。
 * 以前は 1 つの ip6_global を上書きしていたので、複数の Prefix Information を持つ
 * RA を受けると、最後のプレフィックスのアドレスしか残らず、前のプレフィックスの
 * アドレスで張った通信が突然届かなくなった。
 *
 * **手動設定(`ip6addr`)の 1 つ目は RA で潰さない**(運用者の設定を優先する。
 * routetest / pmtutest が名乗らせるアドレスを RA が書き換えると、テストが原因
 * 不明で落ちる)。手動のアドレスがあるときの SLAAC のアドレスは 2 つ目以降に入る。
 *
 * 新しいアドレスは **DAD が済むまで使わない**(TENTATIVE、RFC 4862 5.4)。その前に
 * 要請ノードマルチキャストへの参加を MLD で知らせ(5.4.2)、DAD の NS を 1 個出して
 * 戻る(待たない。判定は ipv6_dad_settle())。
 *
 * 引数:
 *   ni     - 設定先インターフェース
 *   prefix - プレフィックス(プレフィックス長より下は 0 にしてある)
 *   plen / flags / valid / pref - Prefix Information の値
 * コール元:
 *   ipv6_ra_prefix()
 * ===============================================================*/
static void ipv6_slaac_apply_prefix(netif_t *ni, const uint8_t prefix[IPV6_ADDR_LEN],
                                    uint8_t plen, uint8_t flags, uint32_t valid, uint32_t pref)
{
    if (!(flags & PIO_FLAG_AUTO)) {
        uart_printf("[IPv6] RA: prefix(/%u)は A フラグ無し -- 自動設定しません\n", plen);
        return;
    }
    if (plen != 64u) {
        uart_printf("[IPv6] RA: prefix_len=%u -- EUI-64(64bit)と合わせて 128 に"
                    "ならないので無視します\n", plen);
        return;
    }
    if (pref > valid) {
        uart_printf("[IPv6] RA: preferred(%u) > valid(%u) の壊れた prefix -- 無視します\n",
                    (unsigned)pref, (unsigned)valid);
        return;
    }

    uint8_t addr[IPV6_ADDR_LEN];
    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);
    for (unsigned i = 0; i < 8u; i++)  addr[i] = prefix[i];
    for (unsigned i = 8u; i < 16u; i++) addr[i] = ll[i];   /* EUI-64 の 64bit */

    /* 同じアドレスを既に持っている枠を探す。 */
    int slot = -1;
    for (unsigned k = 0; k < a6_count(ni); k++) {
        a6slot_t s;
        if (!a6_slot(ni, k, &s)) break;
        if (s.set && ipv6_eq16(s.addr, addr)) { slot = (int)k; break; }
    }
    if (slot == 0 && !ni->ip6_global_from_ra) {
        uart_printf("[IPv6] RA: %s の手動設定のアドレスと同じ -- 自動設定しません\n",
                    ni->name ? ni->name : "?");
        return;
    }
    int is_new = (slot < 0);

    if (valid == 0u && is_new) {
        /* 新規アドレスは作らない(RFC 4862 5.5.3 d)。 */
        uart_printf("[IPv6] RA: valid lifetime=0 の prefix -- 自動設定しません\n");
        return;
    }
    if (is_new) {
        if (!ni->ip6_global_set) {
            slot = 0;
        } else if (ni->ip6_extra_cnt < NETIF_IP6_EXTRA) {
            slot = 1 + ni->ip6_extra_cnt;
            netif_ip6addr_t *e = &ni->ip6_extra[ni->ip6_extra_cnt];
            for (unsigned i = 0; i < sizeof(*e); i++) ((uint8_t *)e)[i] = 0;
            ni->ip6_extra_cnt++;
        } else {
            uart_printf("[IPv6] RA: %s のアドレスの枠が満杯 -- このプレフィックスでは"
                        "自動設定しません\n", ni->name ? ni->name : "?");
            return;
        }
    }
    a6slot_t s;
    a6_slot(ni, (unsigned)slot, &s);

    /* ---- 有効期間の更新(RFC 4862 5.5.3 e の「2 時間ルール」)----
     * 既存アドレスの寿命を **縮める** 方向の RA は、残りが 2 時間以下なら
     * 無視し、それ以外でも 2 時間までしか縮めない。これが無いと、偽の RA を
     * 1 個投げるだけで他人のアドレスを即座に失効させられる。valid=0 もこの規則で
     * 扱う(即座には消さない)。新規アドレスには適用しない。
     * **推奨寿命はこの規則の外で、言われた値をそのまま入れる**(5.5.3 e。推奨寿命が
     * 切れても受信は続くので、縮められても通信は切れない)。 */
    const uint64_t NS_PER_SEC = 1000000000ull;
    const uint32_t TWO_HOURS  = 2u * 60u * 60u;
    uint64_t now = timer_now();
    uint64_t new_until = (valid == 0xFFFFFFFFu) ? 0u : now + (uint64_t)valid * NS_PER_SEC;
    if (!is_new) {
        uint64_t cur = *s.valid_until;
        int remain_infinite = (cur == 0u);
        uint64_t remain_ns  = remain_infinite ? 0u
                            : ((int64_t)(cur - now) > 0 ? (cur - now) : 0u);
        if (valid == 0xFFFFFFFFu) {
            /* 無期限化は常に受け入れる(延ばす方向) */
        } else if (valid > TWO_HOURS ||
                   (!remain_infinite && (uint64_t)valid * NS_PER_SEC > remain_ns)) {
            /* 延ばす方向、または 2 時間より長い指定はそのまま受け入れる */
        } else if (!remain_infinite && remain_ns <= (uint64_t)TWO_HOURS * NS_PER_SEC) {
            uart_printf("[IPv6] RA: valid lifetime=%us は残り寿命を縮めるだけなので"
                        "無視します(RFC 4862 の 2 時間ルール)\n", (unsigned)valid);
            new_until = cur;
        } else {
            new_until = now + (uint64_t)TWO_HOURS * NS_PER_SEC;
            uart_printf("[IPv6] RA: valid lifetime=%us -- 2 時間までしか縮めません"
                        "(RFC 4862 の 2 時間ルール)\n", (unsigned)valid);
        }
    }
    uint64_t pref_until = (pref == 0xFFFFFFFFu) ? 0u : now + (uint64_t)pref * NS_PER_SEC;
    if (pref == 0u) pref_until = now;   /* 0 は「今すぐ deprecated」(0 の値は無期限の印なので避ける) */

    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) s.addr[i] = addr[i];
    *s.plen        = plen;
    *s.valid_until = new_until;
    *s.pref_until  = pref_until;
    if (slot == 0) {
        ni->ip6_global_set     = 1;
        ni->ip6_global_from_ra = 1;
    }
    if (is_new) {
        *s.dad       = NETIF_DAD_TENTATIVE;
        *s.dad_until = now + (uint64_t)IPV6_SLAAC_DAD_MS * 1000000ull;
        /* **新しいアドレスは新しい要請ノードマルチキャストへの参加**なので、MLD で
         * 報告しないとスヌーピングするスイッチがそのグループを転送してくれない
         * (= 誰もこのアドレスへ NS を届けられず、相手の DAD とも衝突を見つけ
         * 合えない)。**DAD の NS より先に送る**(RFC 4862 5.4.2)。 */
        ipv6_mld_report_all(ni);
        ndp_send_dad_ns(addr);
        ipv6_timer_arm(ni);
        uart_printf("[IPv6] SLAAC: %s の %u 番目の枠に ", ni->name ? ni->name : "?", slot + 1);
        for (unsigned j = 0; j < 8u; j++) {
            uart_printf("%s%02x%02x", (j ? ":" : ""), addr[j * 2u], addr[j * 2u + 1u]);
        }
        uart_printf("/%u を設定(valid=%us preferred=%us、DAD %ums の後に使い始める)\n",
                    plen, (unsigned)valid, (unsigned)pref, IPV6_SLAAC_DAD_MS);
    }
}

/*=================================================================
 * Prefix Information オプション 1 個を処理する。L=1 は on-link の一覧
 * (RFC 4861 6.3.4)、A=1 は SLAAC(RFC 4862 5.5.3)へ。**2 つは独立**で、
 * L=0 A=1(アドレスは作るが on-link ではない)も L=1 A=0 もありうる(RFC 5942)。
 *
 * 引数:
 *   ni  - 設定先インターフェース
 *   opt - オプション先頭(type バイト)。長さは PIO_LEN であることを確認済み
 * コール元:
 *   ipv6_handle_ra()
 * ===============================================================*/
static void ipv6_ra_prefix(netif_t *ni, const volatile uint8_t *opt)
{
    uint8_t  plen  = opt[PIO_OFF_PREFIX_LEN];
    uint8_t  flags = opt[PIO_OFF_FLAGS];
    uint32_t valid = rd32be(opt + PIO_OFF_VALID);
    uint32_t pref  = rd32be(opt + PIO_OFF_PREFERRED);
    if (plen > 128u) {
        uart_printf("[IPv6] RA: prefix_len=%u は不正 -- 無視します\n", plen);
        return;
    }
    /* プレフィックス長より下のビットは受信側が無視する(RFC 4861 4.6.2)。 */
    uint8_t prefix[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        unsigned bit = i * 8u;
        uint8_t b = opt[PIO_OFF_PREFIX + i];
        if (bit >= plen) b = 0;
        else if (bit + 8u > plen) b = (uint8_t)(b & (0xFFu << (8u - (plen - bit))));
        prefix[i] = b;
    }
    if (ipv6_addr_ll(prefix)) {
        uart_printf("[IPv6] RA: リンクローカルのプレフィックスは無視します\n");
        return;
    }
    if (flags & PIO_FLAG_ONLINK) ipv6_onlink_update(ni, prefix, plen, valid);
    ipv6_slaac_apply_prefix(ni, prefix, plen, flags, valid, pref);
}

/*=================================================================
 * Router Advertisement(type 134)を処理する。RFC 4861 6.3.4 / 4862 5.5.3。
 *
 * ここでやること:
 *   - デフォルトルータの一覧の更新(Router Lifetime。0 なら外す)と選び直し
 *   - Cur Hop Limit(0 でなければ以後の送信の hop limit にする)
 *   - Source Link-Layer Address オプションからルータの MAC を学習
 *   - Prefix Information オプション(on-link の一覧と SLAAC)
 *   - MTU オプションは**記録するだけ**(理由は下のコメント)
 *
 * 引数:
 *   in / len - ICMPv6 メッセージ全体
 *   src      - RA の送信元(リンクローカルでなければならない)
 *   src_mac  - 送信元 MAC
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
static void ipv6_handle_ra(const volatile uint8_t *in, size_t len,
                            const uint8_t src[IPV6_ADDR_LEN], const uint8_t *src_mac)
{
    netif_t *ni = g_active_ctx;
    if (!ni) return;
    if (len < RA_OPT_OFF) {
        uart_printf("[IPv6] RA 長不足 (len=%u)\n", (unsigned)len);
        return;
    }
    if (!ndp_opts_valid(in, len, RA_OPT_OFF)) {
        uart_printf("[IPv6] RA: 長さ 0 か途中で切れたオプションがある -- 破棄(RFC 4861 6.1.2)\n");
        return;
    }
    /* **RA の送信元はリンクローカルでなければならない**(RFC 4861 6.1.2)。
     * グローバルアドレスから来た RA を受けると、リンク外のノードが経路と
     * プレフィックスを注入できてしまう。 */
    if (!ipv6_addr_ll(src)) {
        uart_printf("[IPv6] RA の送信元がリンクローカルでない -- 破棄\n");
        return;
    }
    /* この装置はマルチキャストを送信元へループバックする(ping6 の Echo
     * Request が 1 回の送信で 2 行出るのと同じ)。自分が出した RA を自分で
     * 処理すると、2 つの PF が同じプレフィックスから同じ EUI-64 を作って
     * 衝突する。 */
    {
        uint8_t self_mac[ETH_ALEN];
        eth_get_mac(self_mac);
        int loopback = 1;
        for (unsigned i = 0; i < ETH_ALEN; i++) {
            if (src_mac[i] != self_mac[i]) { loopback = 0; break; }
        }
        if (loopback) return;
    }

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    g_ipv6_ra_count[core]++;

    /* 満了したものを先に掃除してから新しい RA を適用する。 */
    ipv6_slaac_age(ni);

    uint8_t  cur_hop = in[RA_OFF_CUR_HOP_LIMIT];
    uint8_t  flags   = in[RA_OFF_FLAGS];
    uint16_t rlife   = rd16be(in + RA_OFF_ROUTER_LIFETIME);
    uint32_t reach   = rd32be(in + RA_OFF_REACHABLE);
    uint32_t retrans = rd32be(in + RA_OFF_RETRANS);

    /* cur_hop_limit は「送信時に使う既定の hop limit」で、上で検査した
     * IPv6 ヘッダの hop limit(NDP は 255 必須)とは別物。ログで紛らわしい
     * ので curhop と書く。 */
    uart_printf("[IPv6] RA 受信 (curhop=%u flags=%s%s router_lifetime=%us "
                "reachable=%ums retrans=%ums)\n",
                cur_hop, (flags & RA_FLAG_MANAGED) ? "M" : "-",
                (flags & RA_FLAG_OTHER) ? "O" : "-",
                rlife, (unsigned)reach, (unsigned)retrans);
    if (flags & RA_FLAG_MANAGED) {
        uart_printf("[IPv6] RA: M フラグが立っている(DHCPv6 は未実装なので"
                    "SLAAC だけで進めます)\n");
    }
    /* **Cur Hop Limit は採用する**(RFC 4861 6.3.4 の SHOULD。0 は「指定しない」)。
     * reachable time / retrans timer は**採用しない**。近隣キャッシュの TTL は
     * 全インターフェース共通の g_neigh_cache_ttl_ms で、`arpage`/`arptest` が
     * 前提にしている値でもある。ルータの言い値で勝手に変わると、検証中に
     * 「なぜか TTL が違う」という追いにくい形で出る。 */
    if (cur_hop != 0u) ni->ra_cur_hop_limit = cur_hop;

    /* ---- デフォルトルータの一覧(選び直しは SLL を覚えた後で行う)---- */
    int ri = ipv6_router_find(ni, src);
    if (rlife == 0u) {
        /* 寿命 0 は「自分をデフォルトルータから外せ」の意味(RFC 4861 6.3.4)。 */
        if (ri >= 0) {
            ipv6_router_remove_at(ni, (unsigned)ri);
            uart_printf("[IPv6] RA: router_lifetime=0 -- デフォルトルータの一覧から外しました\n");
        }
        /* 一覧に無くても、今 gateway6 に入っているのがこのルータなら外す。 */
        if (ni->gateway6_set && ni->gateway6_from_ra && ipv6_eq16(ni->gateway6, src)) {
            ni->gateway6_set         = 0;
            ni->gateway6_from_ra     = 0;
            ni->gateway6_valid_until = 0;
        }
    } else {
        uint64_t until = timer_now() + (uint64_t)rlife * 1000000000ull;
        if (ri >= 0) {
            ni->router6[ri].valid_until = until;
        } else if (ni->router6_cnt < NETIF_ROUTER6_MAX) {
            netif_router6_t *r = &ni->router6[ni->router6_cnt];
            for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) r->addr[i] = src[i];
            r->valid_until = until;
            ni->router6_cnt++;
        } else {
            uart_printf("[IPv6] RA: デフォルトルータの一覧が満杯 -- fe80::...%02x%02x は"
                        "覚えません\n", src[14], src[15]);
        }
    }

    /* ---- オプション走査 ---- */
    size_t off = RA_OPT_OFF;
    while (off + 2u <= len) {
        uint8_t  t   = in[off];
        uint8_t  l8  = in[off + 1u];
        if (l8 == 0u) {
            /* 長さ 0 は不正。そのまま進むと無限ループになる(RFC 4861 4.6 も
             * 「長さ 0 のオプションを含むパケットは黙って破棄」と言っている)。 */
            uart_printf("[IPv6] RA: 長さ 0 のオプション -- 以降を破棄\n");
            return;
        }
        size_t olen = (size_t)l8 * 8u;
        if (off + olen > len) {
            uart_printf("[IPv6] RA: オプションが途中で切れている (type=%u) -- 以降を破棄\n", t);
            return;
        }
        if (t == NDP_OPT_SRC_LLADDR && olen >= 8u) {
            static uint8_t opt_mac[SMP_MAX_CORES][ETH_ALEN];
            for (unsigned i = 0; i < ETH_ALEN; i++) opt_mac[core][i] = in[off + 2u + i];
            /* 相手が名乗った MAC。確かめてはいないので stale で覚える(6.3.4)。 */
            ndp_cache_learn(src, opt_mac[core]);
        } else if (t == NDP_OPT_PREFIX_INFO) {
            if (olen != PIO_LEN) {
                uart_printf("[IPv6] RA: Prefix Information の長さが %u -- 無視\n",
                            (unsigned)olen);
            } else {
                ipv6_ra_prefix(ni, in + off);
            }
        } else if (t == NDP_OPT_MTU && olen >= 8u) {
            /* **記録するだけで適用しない。** リンク MTU を下げると mss_cap も
             * 下がり、`txdrop` を 0 に戻し忘れたときと同じで「以後の測定が
             * 全部おかしい」という戻しにくい状態になる。経路ごとの MTU 低下は
             * A5/A6(PMTUD)が宛先単位で扱うので、実害も無い。 */
            ni->ra_link_mtu = rd32be(in + off + 4u);
            uart_printf("[IPv6] RA: MTU オプション=%u(記録のみ。リンク MTU は"
                        "変更しません)\n", (unsigned)ni->ra_link_mtu);
        }
        off += olen;
    }

    /* ---- デフォルトルータを選び直す ---- */
    if (ni->gateway6_set && !ni->gateway6_from_ra) {
        uart_printf("[IPv6] RA: %s には手動設定のゲートウェイがあるので"
                    "RA のルータは一覧に覚えるだけにします\n", ni->name ? ni->name : "?");
    }
    ipv6_router_select(ni, 0);

    s_slaac_ra_if = ni;
    s_slaac_ra_seen++;
}

/*=================================================================
 * Redirect(type 137)を処理する(RFC 4861 8.1 の検査、8.3 の更新)。
 *
 * 受け付ける条件(8.1。満たさないものは黙って捨てる MUST):
 *   - 送信元がリンクローカル、hop limit 255、Code 0、長さ 40 以上
 *     (hop limit と Code は ipv6_handle_icmpv6() の NDP 共通の検査で見てある)
 *   - **送信元が、Destination へのいまの次ホップ(ルータ)である**
 *     (これが無いと、同じリンクの誰でも他人宛ての通信を自分へ向けさせられる)
 *   - Destination がマルチキャストでない
 *   - Target がリンクローカル(別のルータ)か、Destination と同じ(相手は on-link)
 *   - オプションの長さがどれも 0 でない
 * 更新(8.3): 宛先キャッシュに「Destination は Target へ」を入れる。Target
 * Link-Layer Address があれば近隣キャッシュを STALE で更新する。
 *
 * **ホストは Redirect を送らない**ので、受けるだけ。
 *
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
static void ipv6_handle_redirect(const volatile uint8_t *in, size_t len,
                                 const uint8_t src[IPV6_ADDR_LEN])
{
    netif_t *ni = g_active_ctx;
    if (!ni) return;
    if (len < REDIRECT_OPT_OFF) {
        uart_printf("[IPv6] Redirect 長不足 (len=%u) -- 破棄\n", (unsigned)len);
        return;
    }
    if (!ipv6_addr_ll(src)) {
        uart_printf("[IPv6] Redirect の送信元がリンクローカルでない -- 破棄(RFC 4861 8.1)\n");
        return;
    }
    uint8_t target[IPV6_ADDR_LEN], dest[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        target[i] = in[REDIRECT_OFF_TARGET + i];
        dest[i]   = in[REDIRECT_OFF_DEST + i];
    }
    if (dest[0] == 0xFFu) {
        uart_printf("[IPv6] Redirect の Destination がマルチキャスト -- 破棄(RFC 4861 8.1)\n");
        return;
    }
    int onlink = ipv6_eq16(target, dest);
    if (!onlink && !ipv6_addr_ll(target)) {
        uart_printf("[IPv6] Redirect の Target がリンクローカルでも Destination でもない -- "
                    "破棄(RFC 4861 8.1)\n");
        return;
    }
    if (!ndp_opts_valid(in, len, REDIRECT_OPT_OFF)) {
        uart_printf("[IPv6] Redirect: 長さ 0 か途中で切れたオプションがある -- 破棄(RFC 4861 8.1)\n");
        return;
    }
    const uint8_t *fh = netif_next_hop6(ni, dest);
    if (fh == dest || !ipv6_eq16(fh, src)) {
        uart_printf("[IPv6] Redirect の送信元がその宛先のいまの次ホップ(ルータ)でない -- "
                    "破棄(RFC 4861 8.1)\n");
        return;
    }

    for (size_t off = REDIRECT_OPT_OFF; off + 2u <= len; off += (size_t)in[off + 1u] * 8u) {
        if (in[off] == NDP_OPT_TGT_LLADDR && (size_t)in[off + 1u] * 8u >= 8u) {
            uint8_t mac[ETH_ALEN];
            for (unsigned i = 0; i < ETH_ALEN; i++) mac[i] = in[off + 2u + i];
            ndp_cache_learn(target, mac);   /* 確かめていないので STALE(8.3) */
        }
    }
    ipv6_dest_set(ni, dest, onlink ? dest : target);
    g_ipv6_redirect_count++;
    uart_printf("[IPv6] Redirect 受け付け: 宛先 ...%02x%02x:%02x%02x は %s へ\n",
                dest[12], dest[13], dest[14], dest[15],
                onlink ? "直接(on-link)" : "別のルータ");
}

/*=================================================================
 * 受けた ICMPv6 のエラー(Destination Unreachable / Packet Too Big / Time Exceeded /
 * Parameter Problem)を、引用されたパケットの上位(TCP / UDP)へ渡す
 * (RFC 4443 3、RFC 1122 4.2.3.9 / 4.1.3.3、RFC 5461)。
 *
 * 引用の IPv6 ヘッダから拡張ヘッダを飛ばして上位の種類と位置を求め、
 *   TCP: Destination Unreachable の code 4(Port Unreachable)と code 1(管理上禁止)は
 *        「相手にその口が無い」として TCP_ICMP_HARD、それ以外は TCP_ICMP_SOFT。
 *   UDP: udp_icmp_error() へそのまま。
 * **Packet Too Big は、TCP の引用なら tcp_icmp_error(..., TCP_ICMP_PMTU) が 1 を
 * 返したとき(引用の seq が送った範囲に入る、生きている接続のもの)だけ経路 MTU を
 * 学ぶ**(RFC 5927 / 8201 5.2。そうしないと、4-tuple を推測しただけの偽の Packet Too
 * Big で MSS を 1280 まで落とされる)。UDP などの引用は従来どおり学ぶ(確かめる
 * 手がかりが無い)。
 *
 * 引数:
 *   type / code - ICMPv6 の type / code
 *   in / len    - ICMPv6 メッセージ全体
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
static void icmpv6_error_to_upper(uint8_t type, uint8_t code, const volatile uint8_t *in,
                                  size_t len)
{
    uint32_t param = rd32be(in + 4u);
    g_icmpv6_err_rx_type  = type;
    g_icmpv6_err_rx_code  = code;
    g_icmpv6_err_rx_param = param;
    g_icmpv6_err_rx++;

    if (len < 8u + IPV6_HDR_LEN) {
        uart_printf("[IPv6] ICMPv6 エラー(type=%u)の引用が短い (len=%u) -- 上位へは渡しません\n",
                    type, (unsigned)len);
        return;
    }
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t q[SMP_MAX_CORES][1280u];
    size_t qlen = len - 8u;
    if (qlen > sizeof(q[0])) qlen = sizeof(q[0]);
    for (size_t i = 0; i < qlen; i++) q[core][i] = in[8u + i];
    const uint8_t *qp = q[core];

    uint8_t nh = 0;
    long off = ipv6_walk_light(qp, qlen, &nh);
    netaddr_t local  = netaddr_v6(qp + 8u);
    netaddr_t remote = netaddr_v6(qp + 24u);

    if (type == ICMPV6_TYPE_PACKET_TOO_BIG) {
        int learn = 1;
        if (off >= 0 && nh == IPV6_NH_TCP) {
            learn = (tcp_icmp_error(&local, &remote, qp + off, qlen - (size_t)off,
                                    TCP_ICMP_PMTU) == 1);
        } else if (off >= 0 && nh == IPV6_NH_UDP) {
            udp_icmp_error(&remote, qp + off, qlen - (size_t)off, type, code, 1);
        }
        uart_printf("[IPv6] Packet Too Big 受信 (MTU=%u) -- 対象の宛先 ...%02x%02x:%02x%02x%s\n",
                    (unsigned)param, qp[36], qp[37], qp[38], qp[39],
                    learn ? "" : "(TCP の生きた接続の引用でないので学ばない)");
        if (learn) pmtu_learn(&remote, param);
        return;
    }

    uart_printf("[IPv6] ICMPv6 エラー受信 (type=%u code=%u param=%u、引用の上位=%u)\n",
                type, code, (unsigned)param, off >= 0 ? nh : 255u);
    if (off < 0) return;
    if (nh == IPV6_NH_TCP) {
        int kind = (type == ICMPV6_TYPE_DEST_UNREACH &&
                    (code == ICMPV6_CODE_PORT_UNREACH || code == ICMPV6_CODE_ADMIN_PROHIB))
                   ? TCP_ICMP_HARD : TCP_ICMP_SOFT;
        tcp_icmp_error(&local, &remote, qp + off, qlen - (size_t)off, kind);
    } else if (nh == IPV6_NH_UDP) {
        udp_icmp_error(&remote, qp + off, qlen - (size_t)off, type, code, 1);
    }
}

/* ==== 時間で進める仕事 ==== */

/*=================================================================
 * ni に時間待ちの仕事(DAD の判定・MLD の再送)があることを登録する。
 *
 * コール元:
 *   ipv6_slaac_apply_prefix(), ipv6_mld_report_all(), ipv6_mld_leave()
 * ===============================================================*/
static void ipv6_timer_arm(netif_t *ni)
{
    if (!ni) return;
    while (__atomic_test_and_set(&s_timer_lock, __ATOMIC_ACQUIRE)) { }
    int found = 0;
    for (unsigned i = 0; i < IPV6_TIMER_IFS && !found; i++) found = (s_timer_if[i] == ni);
    for (unsigned i = 0; i < IPV6_TIMER_IFS && !found; i++) {
        if (!s_timer_if[i]) { s_timer_if[i] = ni; found = 1; }
    }
    if (found) s_timer_pending = 1;
    __atomic_clear(&s_timer_lock, __ATOMIC_RELEASE);
}

/*=================================================================
 * 時間で進める仕事を進める(ipv6.h の説明を参照)。
 *   - DAD 中のアドレスの判定時刻が来ていれば PASSED にする
 *   - MLD の非要請 Report / 離脱通知の再送時刻が来ていれば送る
 *   - 寿命切れの掃除(ipv6_slaac_age())
 * 仕事の無くなったインターフェースは登録から外し、全部無くなれば旗を下ろす。
 *
 * **複数のコアが同時に呼んでも 1 つだけが進める**(取れなければすぐ戻る)。
 *
 * コール元:
 *   ipv6_handle_frame()(旗が立っているときだけ)、ndp_resolve()、ipv6_slaac_solicit()、
 *   冷たい経路の定期処理(他の層から)
 * ===============================================================*/
void ipv6_timer_tick(void)
{
    if (!s_timer_pending) return;
    if (__atomic_test_and_set(&s_timer_lock, __ATOMIC_ACQUIRE)) return;

    netif_t *prev = g_active_ctx;
    uint64_t now = timer_now();
    int more = 0;
    for (unsigned i = 0; i < IPV6_TIMER_IFS; i++) {
        netif_t *ni = s_timer_if[i];
        if (!ni) continue;
        netif_activate(ni);
        int busy = 0;

        for (unsigned k = 0; k < a6_count(ni); k++) {
            a6slot_t s;
            if (!a6_slot(ni, k, &s)) break;
            if (!s.set || *s.dad != NETIF_DAD_TENTATIVE) continue;
            uint64_t n2 = now;
            if (!ipv6_dad_settle(ni, &s, &n2)) busy = 1;
        }
        if (ni->mld_rep_left) {
            if ((int64_t)(now - ni->mld_rep_at) >= 0) {
                mld_send_report_now(ni);
                ni->mld_rep_left--;
                ni->mld_rep_at = now + mld_unsol_delay_ns(ni);
            }
            if (ni->mld_rep_left) busy = 1;
        }
        if (ni->mld_leave_left) {
            if ((int64_t)(now - ni->mld_leave_at) >= 0) {
                uint8_t g[IPV6_ADDR_LEN];
                for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) g[j] = ni->mld_leave_group[j];
                mld_send_leave_now(g);
                ni->mld_leave_left--;
                ni->mld_leave_at = now + mld_unsol_delay_ns(ni);
            }
            if (ni->mld_leave_left) busy = 1;
        }
        ipv6_slaac_age(ni);

        if (busy) more = 1; else s_timer_if[i] = NULL;
    }
    netif_activate(prev);
    s_timer_pending = more;
    __atomic_clear(&s_timer_lock, __ATOMIC_RELEASE);
}

/*=================================================================
 * 受信 ICMPv6 を処理する。Echo Request には Echo Reply、Neighbor
 * Solicitation には Neighbor Advertisement を返す(NA を返さないと相手は
 * こちらの MAC を解決できず、IPv6 通信が一切成立しない)。
 *
 * 引数:
 *   msg / len - ICMPv6 メッセージ本体
 *   src / dst - IPv6 ヘッダの送信元・宛先
 *   hop_limit - IPv6 ヘッダの hop limit(NDP の 255 検査に要る)
 *   router_alert - Hop-by-Hop に Router Alert が付いていたか(MLD の検査に要る)
 *   src_mac   - 送信元 MAC(応答の宛先に使う)
 *   fragmented - Fragment ヘッダを通って届いたか(原子断片も含む。NDP の検査に要る)
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static void ipv6_handle_icmpv6(const uint8_t *msg, size_t len,
                                const uint8_t src[IPV6_ADDR_LEN],
                                const uint8_t dst[IPV6_ADDR_LEN],
                                uint8_t hop_limit, uint8_t router_alert,
                                const uint8_t *src_mac, int fragmented)
{
    if (len < 8u) {
        uart_printf("[IPv6] ICMPv6 長不足 (len=%u)\n", (unsigned)len);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = msg;
    uint8_t type = in[ICMPV6_OFF_TYPE];
    int is_ndp = (type >= ICMPV6_TYPE_RS && type <= ICMPV6_TYPE_REDIRECT);

    /* **断片で届いた NDP は捨てる**(RFC 6980 5 の MUST。原子断片も同じ)。NDP は
     * どれも 1 つのパケットに収まる大きさで、断片にする理由が無い。断片を許すと、
     * RA Guard のような「最初の断片を見て RA を止める」仕組みを、上位のヘッダを
     * 2 つ目の断片へ押し出すだけですり抜けられる。 */
    if (is_ndp && fragmented) {
        uart_printf("[IPv6] 断片で届いた NDP(type=%u)-- 破棄(RFC 6980)\n", type);
        return;
    }
    /* **NDP のメッセージは hop limit が 255 でなければ捨てる**(RFC 4861 6.1 / 8.1)。
     * ルータは転送のたびに hop limit を減らすので、255 で届いたということは
     * 同一リンク上から来たということ。この検査が無いと、リンク外のノードが
     * RA を送り込んでデフォルトルータとプレフィックスを乗っ取れる。
     * 自作側の NDP の送信は ipv6_hop_for() が 255 にしている。 */
    if (is_ndp && hop_limit != 255u) {
        uart_printf("[IPv6] NDP(type=%u)の hop limit が %u -- 破棄(255 必須)\n",
                    type, hop_limit);
        return;
    }
    /* **NDP の Code は 0 でなければ捨てる**(RFC 4861 6.1.1 / 6.1.2 / 7.1.1 /
     * 7.1.2 / 8.1 の MUST)。未定義の Code は、規格が後から別の意味を持たせる余地。
     * 知らない意味のメッセージで表を書き換えないため。 */
    if (is_ndp && in[ICMPV6_OFF_CODE] != 0u) {
        uart_printf("[IPv6] NDP(type=%u)の Code が %u -- 破棄(0 必須)\n",
                    type, in[ICMPV6_OFF_CODE]);
        return;
    }
    /* **送信元が未指定(::)で正当なのは DAD の NS と MLD の Report だけ**
     * (RFC 4862 5.4.2 / RFC 3810 5.2.13)。それ以外(Echo Request など)は捨てる。
     * 返事の宛先が無いメッセージに返事を作ると、:: 宛ての送信を試みることになる。 */
    if (ipv6_addr_unspec(src) && type != ICMPV6_TYPE_NS &&
        type != ICMPV6_TYPE_MLD_REPORT && type != ICMPV6_TYPE_MLD2_REPORT &&
        type != ICMPV6_TYPE_MLD_DONE) {
        return;
    }

    if (!eth_rx_hw_csum_ok()) {
        uint16_t verify = ipv6_pseudo_checksum(src, dst, IPV6_NH_ICMPV6, in, (uint16_t)len);
        if (verify != 0u) {
            uart_printf("[IPv6] ICMPv6 チェックサム不正 (0x%04X) 破棄\n", verify);
            return;
        }
    }

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    /* 応答の作業領域。**組み立てた大きな Echo Request(最大 65535 バイト)にも答える**
     * ので 64KB(RFC 4443 4.2:Echo Request のデータはそのまま返す MUST)。
     * 送るときは ipv6_send_from() が MTU に合わせて断片にする。 */
    static uint8_t out[SMP_MAX_CORES][65536u];

    if (type == ICMPV6_TYPE_ECHO_REQUEST) {
        if (len > sizeof(out[0])) {
            uart_printf("[IPv6] Echo Request が大きすぎる (%u)\n", (unsigned)len);
            return;
        }
        g_ipv6_echo_request_count[core]++;
        for (size_t i = 0; i < len; i++) out[core][i] = in[i];
        out[core][ICMPV6_OFF_TYPE] = ICMPV6_TYPE_ECHO_REPLY;
        out[core][ICMPV6_OFF_CODE] = 0;
        uart_printf("[IPv6] Echo Request 受信 (len=%u)、Echo Reply を返します\n",
                    (unsigned)len);
        ipv6_send_icmpv6(src, src_mac, out[core], (uint16_t)len);
        return;
    }

    if (type == ICMPV6_TYPE_NS) {
        if (len < 8u + NDP_BODY_LEN) {
            uart_printf("[IPv6] NS 長不足 (len=%u)\n", (unsigned)len);
            return;
        }
        /* 送信元が未指定アドレス(::)なら相手の DAD。通常の NS とは扱いが
         * 3 点違う(RFC 4861 4.3 / RFC 4862 5.4.3):近隣キャッシュへ入れない、
         * NA は全ノードマルチキャストへ返す、Solicited フラグを立てない。 */
        uint8_t unspec[IPV6_ADDR_LEN];
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) unspec[i] = 0;
        int src_unspec = ipv6_addr_eq(unspec, src);

        /* ---- 妥当性の検査(RFC 4861 7.1.1、満たさないものは黙って捨てる MUST)----
         * - Target がマルチキャストでない(マルチキャストに MAC の対応は無い)
         * - オプションの長さがどれも 0 でない
         * - 送信元が :: (DAD)なら、宛先は要請ノードマルチキャストで、Source
         *   Link-Layer Address は付いていない(:: は自分のアドレスを持っていない
         *   印なので、MAC を名乗るのは矛盾している) */
        if (in[8u + NDP_OFF_TARGET] == 0xFFu) {
            uart_printf("[IPv6] NS の Target がマルチキャスト -- 破棄(RFC 4861 7.1.1)\n");
            return;
        }
        if (!ndp_opts_valid(in, len, 8u + NDP_BODY_LEN)) {
            uart_printf("[IPv6] NS: 長さ 0 か途中で切れたオプションがある -- 破棄(RFC 4861 7.1.1)\n");
            return;
        }
        if (src_unspec) {
            int has_sll = 0;
            for (size_t o = 8u + NDP_BODY_LEN; o + 2u <= len; o += (size_t)in[o + 1u] * 8u) {
                if (in[o] == NDP_OPT_SRC_LLADDR) has_sll = 1;
            }
            if (!ipv6_is_solicited_node(dst) || has_sll) {
                uart_printf("[IPv6] 送信元 :: の NS の宛先が要請ノードマルチキャストでないか、"
                            "Source Link-Layer Address が付いている -- 破棄(RFC 4861 7.1.1)\n");
                return;
            }
        }

        /* 自分が DAD 中で、同じアドレスを相手も検査していたら衝突
         * (同時 DAD、RFC 4862 5.4.5)。target が自分のものかを見る前に
         * 判定する -- `dadtest` が自分以外のアドレスを検査することもある。 */
        if (src_unspec && s_dad_active && !dad_mac_is_prober(src_mac) &&
            ipv6_addr_eq(s_dad_target, in + 8u + NDP_OFF_TARGET)) {
            for (unsigned i = 0; i < ETH_ALEN; i++) s_dad_conflict_mac[i] = src_mac[i];
            s_dad_conflict = 1;
        }

        uint8_t ns_target[IPV6_ADDR_LEN];
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) ns_target[i] = in[8u + NDP_OFF_TARGET + i];

        /* **自分が DAD 中(TENTATIVE)のアドレスを対象とする NS**(RFC 4862 5.4.3):
         *  - 送信元が ::(相手も同じアドレスを DAD している)なら衝突。そのアドレスは
         *    使わない。ただし自分の DAD の NS がループバックしてきたもの(送信元 MAC が
         *    自分)は数えない。
         *  - それ以外(普通の解決の NS)には**答えない**。まだ自分のものと決まって
         *    いないアドレスで NA を返すと、本当の持ち主と取り合いになる。 */
        {
            int ti = a6_find_tentative(g_active_ctx, ns_target);
            if (ti >= 0) {
                netif_t *tni = g_active_ctx;
                int self_lb = 1;
                for (unsigned i = 0; i < ETH_ALEN; i++) {
                    if (src_mac[i] != tni->mac[i]) { self_lb = 0; break; }
                }
                if (src_unspec && !self_lb) ipv6_dad_conflict(tni, (unsigned)ti, src_mac);
                return;
            }
        }

        /* 要請対象が自分のアドレス(リンクローカル or 使ってよいグローバル)でなければ無視 */
        if (!ipv6_unicast_is_ours(g_active_ctx, ns_target)) return;
        g_ipv6_ns_count[core]++;

        /* 自分が出したマルチキャストがループバックしてきたぶんには応答しない
         * (ARP 側と同じ理由。ここで NA を返すと、その NA も自分に戻ってきて
         * 自分の DAD が自分を衝突相手として検出する)。 */
        {
            uint8_t self_mac_now[ETH_ALEN];
            eth_get_mac(self_mac_now);
            int loopback = 1;
            for (unsigned i = 0; i < ETH_ALEN; i++) {
                if (src_mac[i] != self_mac_now[i]) { loopback = 0; break; }
            }
            if (loopback) return;
        }

        /* 相手を近隣キャッシュへ入れておく(RFC 4861 7.2.3)。これで「NS を
         * 受けた側」も相手の MAC を学習でき、以後の応答でこちらから NS を
         * 撃ち直さずに済む。使うのは **Source Link-Layer Address オプションだけ**
         * (付いていないのはユニキャストの確認の NS で、そのときは表を変えない)。
         * 相手が名乗っただけで確かめてはいないので stale で覚える。
         * **DAD の NS(送信元 ::)からは学習してはいけない** -- :: は正当な
         * 送信元アドレスではない。 */
        if (!src_unspec && len >= 8u + NDP_BODY_LEN + 8u &&
            in[8u + NDP_BODY_LEN] == NDP_OPT_SRC_LLADDR) {
            static uint8_t opt_mac[SMP_MAX_CORES][ETH_ALEN];
            for (unsigned i = 0; i < ETH_ALEN; i++) {
                opt_mac[core][i] = in[8u + NDP_BODY_LEN + 2u + i];
            }
            ndp_cache_learn(src, opt_mac[core]);
        }

        /* NA を組み立てる: flags に S(Solicited)|O(Override)、target は自分、
         * オプションに Target Link-Layer Address を付ける。 */
        uint8_t *na = out[core];
        for (unsigned i = 0; i < 8u + NDP_BODY_LEN + 8u; i++) na[i] = 0;
        na[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_NA;
        na[ICMPV6_OFF_CODE] = 0;
        na[NDP_OFF_FLAGS] = src_unspec ? 0x20u : 0x60u;  /* O=1、S=1 は DAD 応答では立てない */
        /* **NA の Target Address は「要請された対象」をそのまま返す。**
         * ここを自分のリンクローカル固定にすると、グローバルアドレス宛の NS に
         * 対してリンクローカルを名乗る NA を返すことになり、相手(Linux)は
         * solicited した対象と一致しないので捨てる。実機ではリンクローカルへの
         * ping6 だけ通ってグローバルへの ping6 が通らない、という形で出た。 */
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
            na[8u + NDP_OFF_TARGET + i] = in[8u + NDP_OFF_TARGET + i];
        }
        uint8_t self_mac[ETH_ALEN];
        eth_get_mac(self_mac);
        na[8u + NDP_BODY_LEN + 0] = NDP_OPT_TGT_LLADDR;
        na[8u + NDP_BODY_LEN + 1] = 1u;  /* 長さ(8バイト単位) */
        for (unsigned i = 0; i < ETH_ALEN; i++) na[8u + NDP_BODY_LEN + 2u + i] = self_mac[i];

        /* DAD の NS には返信先アドレスが無い(送信元が ::)。全ノード
         * マルチキャスト ff02::1 / L2 33:33:00:00:00:01 へ返す。 */
        const uint8_t all_nodes_mac[ETH_ALEN] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };
        uint8_t all_nodes[IPV6_ADDR_LEN];
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) all_nodes[i] = 0;
        all_nodes[0] = 0xFF; all_nodes[1] = 0x02; all_nodes[15] = 0x01;

        uart_printf("[IPv6] %s 受信、Advertisement を返します\n",
                    src_unspec ? "Neighbor Solicitation(DAD、送信元 ::)"
                                : "Neighbor Solicitation");
        if (src_unspec) {
            ipv6_send_icmpv6(all_nodes, all_nodes_mac, na, (uint16_t)(8u + NDP_BODY_LEN + 8u));
        } else {
            ipv6_send_icmpv6(src, src_mac, na, (uint16_t)(8u + NDP_BODY_LEN + 8u));
        }
        return;
    }

    if (type == ICMPV6_TYPE_RA) {
        ipv6_handle_ra(in, len, src, src_mac);
        return;
    }

    if (type == ICMPV6_TYPE_REDIRECT) {
        ipv6_handle_redirect(in, len, src);
        return;
    }

    if (type == ICMPV6_TYPE_MLD_QUERY) {
        /* **MLD の妥当性検査は 3 つ**(RFC 3810 6.2)。どれも「リンク外から
         * 撃たれないこと」を担保する:hop limit が 1、Router Alert が付いて
         * いる、送信元がリンクローカル。上の NDP の 255 検査と同じ考え方で、
         * 抜けるとリンク外のノードにマルチキャスト受信を止められる。 */
        if (hop_limit != 1u) {
            uart_printf("[MLD] Query の hop limit が %u -- 破棄(1 必須)\n", hop_limit);
            return;
        }
        if (!router_alert) {
            uart_printf("[MLD] Query に Router Alert が無い -- 破棄\n");
            return;
        }
        if (!(src[0] == 0xFEu && (src[1] & 0xC0u) == 0x80u)) {
            uart_printf("[MLD] Query の送信元がリンクローカルでない -- 破棄\n");
            return;
        }
        mld_handle_query(in, len);
        return;
    }

    if (type == ICMPV6_TYPE_MLD_REPORT || type == ICMPV6_TYPE_MLD2_REPORT ||
        type == ICMPV6_TYPE_MLD_DONE) {
        /* 他ノードの Report/Done。**ルータでもスイッチでもないので何もしない。**
         * MLDv1 の Report 抑止(同じグループを他所が報告したら自分は黙る)は
         * 実装しない -- 応答を遅延させていないので抑止する余地が無く、余分な
         * Report が 1 通増えるだけ。ログも出さない(定期的に飛んでくる)。 */
        return;
    }

    if (type == ICMPV6_TYPE_RS) {
        /* **このスタックはホストであってルータではない。** RS に RA を返す
         * ことはしない(返すと相手に誤ったデフォルトルータを教えることになる)。
         * 自分が出した RS のループバックもここに来るので、ログは出さない。 */
        return;
    }

    if (type == ICMPV6_TYPE_DEST_UNREACH || type == ICMPV6_TYPE_PACKET_TOO_BIG ||
        type == ICMPV6_TYPE_TIME_EXCEEDED || type == ICMPV6_TYPE_PARAM_PROBLEM) {
        /* エラーは引用されたパケットの上位(TCP / UDP)へ渡す(RFC 4443 3、
         * RFC 1122 4.2.3.9)。Packet Too Big は IPv4 の Fragmentation Needed に相当し、
         * **MTU は 4-7 バイトの 32bit 全体**(IPv4 は未使用 4 バイトの下位 16bit だけ)。
         * 学習する宛先は「引用された元パケットの宛先」で、ICMPv6 の送信元
         * (= 文句を言ってきたルータ)ではない。IPv6 は経路上で分割しないので、
         * これを処理しないと MTU の小さい経路で通信が完全に成立しない。 */
        icmpv6_error_to_upper(type, in[ICMPV6_OFF_CODE], in, len);
        return;
    }

    if (type == ICMPV6_TYPE_ECHO_REPLY) {
        g_ipv6_echo_reply_count[core]++;
        uart_printf("[IPv6] Echo Reply 受信 (id=%u seq=%u)\n",
                    rd16be(in + 4), rd16be(in + 6));
        return;
    }
    if (type == ICMPV6_TYPE_NA) {
        if (len < 8u + NDP_BODY_LEN) return;
        /* Target Link-Layer Address オプションがあればそれを、無ければ送信元 MAC を
         * 近隣キャッシュへ入れる。target は本文中のアドレス(IPv6 ヘッダの src とは
         * 別。プロキシ NA では両者が異なる)。 */
        uint8_t target[IPV6_ADDR_LEN];
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) target[i] = in[8u + NDP_OFF_TARGET + i];
        uint8_t na_flags = in[NDP_OFF_FLAGS];

        /* ---- 妥当性の検査(RFC 4861 7.1.2、満たさないものは黙って捨てる MUST)----
         * - Target がマルチキャストでない
         * - 宛先がマルチキャストなら Solicited が立っていない(問い合わせへの
         *   答えは問い合わせた相手へユニキャストで返すもので、全員宛ての答えは
         *   あり得ない。立っていれば偽物か壊れている)
         * - オプションの長さがどれも 0 でない */
        if (target[0] == 0xFFu) {
            uart_printf("[IPv6] NA の Target がマルチキャスト -- 破棄(RFC 4861 7.1.2)\n");
            return;
        }
        if (dst[0] == 0xFFu && (na_flags & 0x40u)) {
            uart_printf("[IPv6] マルチキャスト宛ての NA に Solicited が立っている -- 破棄(RFC 4861 7.1.2)\n");
            return;
        }
        if (!ndp_opts_valid(in, len, 8u + NDP_BODY_LEN)) {
            uart_printf("[IPv6] NA: 長さ 0 か途中で切れたオプションがある -- 破棄(RFC 4861 7.1.2)\n");
            return;
        }

        const uint8_t *mac = src_mac;
        if (len >= 8u + NDP_BODY_LEN + 8u && in[8u + NDP_BODY_LEN] == NDP_OPT_TGT_LLADDR) {
            static uint8_t opt_mac[SMP_MAX_CORES][ETH_ALEN];
            for (unsigned i = 0; i < ETH_ALEN; i++) {
                opt_mac[core][i] = in[8u + NDP_BODY_LEN + 2u + i];
            }
            mac = opt_mac[core];
        }
        /* DAD 中に検査対象への NA が来たら、そのアドレスは既に使われている
         * (RFC 4862 5.4.4)。キャッシュへは通常どおり入れる -- 相手が実在する
         * のは事実なので、覚えておいて損はない。 */
        if (s_dad_active && !dad_mac_is_prober(mac) && ipv6_addr_eq(s_dad_target, target)) {
            for (unsigned i = 0; i < ETH_ALEN; i++) s_dad_conflict_mac[i] = mac[i];
            s_dad_conflict = 1;
        }
        /* SLAAC のアドレスの DAD 中(TENTATIVE)に、そのアドレスの NA が来たら衝突
         * (RFC 4862 5.4.4)。 */
        {
            netif_t *tni = g_active_ctx;
            int ti = a6_find_tentative(tni, target);
            if (ti >= 0) {
                int self_lb = 1;
                for (unsigned i = 0; i < ETH_ALEN; i++) {
                    if (mac[i] != tni->mac[i]) { self_lb = 0; break; }
                }
                if (!self_lb) ipv6_dad_conflict(tni, (unsigned)ti, mac);
            }
        }
        /* **フラグを見てから更新する**(RFC 4861 7.2.5)。S=1 のときだけ到達確認
         * として延命し、O=0 で既存と違う MAC を主張する NA は無視する。
         * フラグは本文先頭の 32bit の上位 3 ビット(bit31=R bit30=S bit29=O)。 */
        ndp_cache_update_na(target, mac,
                            (na_flags & 0x40u) ? 1 : 0,   /* S: Solicited */
                            (na_flags & 0x20u) ? 1 : 0);  /* O: Override */

        /* **ルータをやめた相手をデフォルトルータから外す**(RFC 4861 7.2.5 の
         * MUST:IsRouter が TRUE から FALSE に変わったら Default Router List から
         * 外す)。R(Router)の印が 0 の NA を、RA で覚えたデフォルトルータ自身が
         * 出したなら、その相手はもうルータではない。外さないと、Router Lifetime が
         * 切れるまで(最大 9000 秒)転送してくれない相手へ送り続ける。
         * **一覧から外して選び直す**(他にルータが居ればそちらへ切り替わる)。
         * 手動設定のゲートウェイ(`route`)は RA の一覧ではないので触らない。 */
        netif_t *ni = g_active_ctx;
        if (!(na_flags & 0x80u) && ni) {
            int was = 0;
            int ri = ipv6_router_find(ni, target);
            if (ri >= 0) { ipv6_router_remove_at(ni, (unsigned)ri); was = 1; }
            if (ni->gateway6_set && ni->gateway6_from_ra && ipv6_addr_eq(ni->gateway6, target)) {
                ni->gateway6_set         = 0;
                ni->gateway6_from_ra     = 0;
                ni->gateway6_valid_until = 0;
                ipv6_dest_purge(ni, target);
                was = 1;
            }
            if (was) {
                uart_printf("[IPv6] RA で覚えたデフォルトルータが R=0 の NA を出した -- "
                            "ルータでなくなったので外します(RFC 4861 7.2.5)\n");
                ipv6_router_select(ni, 0);
            }
        }
        return;
    }
    uart_printf("[IPv6] 未対応の ICMPv6 type=%u 無視\n", type);
}

/* 拡張ヘッダを辿って見つけた誤りのうち、ICMPv6 Parameter Problem を返すべきもの。 */
typedef struct {
    int      send;        /* 1 = 返す */
    uint8_t  code;        /* ICMPV6_CODE_PP_* */
    uint32_t ptr;         /* Pointer(誘因のパケットの先頭からのバイト位置) */
    int      even_mcast;  /* 1 = 宛先がマルチキャストでも返す(オプションの動作ビット 10) */
} ipv6_pp_t;

/*=================================================================
 * 拡張ヘッダのチェーンを辿って上位プロトコルまで進む(RFC 8200 4)。
 *
 * IPv6 は「IPv4 のオプション」に相当するものを**別のヘッダを数珠つなぎに
 * する**形で表す。各拡張ヘッダは先頭 2 バイトが {next header, 長さ} で、
 * 長さは **8 バイト単位・最初の 8 バイトを含まない**(= (len+1)*8)。
 * これを辿らないと、Hop-by-Hop が 1 つ付いただけで上位が読めなくなる。
 * **MLD の Query は必ず Hop-by-Hop(Router Alert)付きで来る**ので、
 * B2 にはこの処理が必須。
 *
 * 捨てるときに Parameter Problem を返すべきもの(RFC 8200 4 / 4.2 / 4.4)は pp に書く:
 *   - 知らない Next Header(Hop-by-Hop が IPv6 ヘッダの直後以外に出てきたものも含む)
 *     -> code 1、Pointer はその Next Header の欄
 *   - Segments Left が 0 でない Routing ヘッダ -> code 0、Pointer は Routing Type
 *   - 動作ビットが 10 / 11 の知らないオプション -> code 2、Pointer はそのオプション
 *     (10 は宛先がマルチキャストでも返す、11 はユニキャストのときだけ)
 *
 * 引数:
 *   in           - 先頭(IPv6 ヘッダ、または組み立てた後のデータグラム)
 *   total        - in から使える長さ
 *   nh_io        - 入出力。入力は最初の next header、出力は上位プロトコル
 *   off_io       - 入出力。入力は最初の拡張ヘッダの位置、出力は上位プロトコルの先頭
 *   router_alert - 出力。Hop-by-Hop に Router Alert があれば 1
 *   nh_field     - 最初の next header が書いてある位置(Pointer に使う)
 *   hbh_ok       - 1 なら最初のヘッダに限って Hop-by-Hop を許す(IPv6 ヘッダの直後)
 *   pp           - 出力。Parameter Problem を返すべきなら send=1
 * 戻り値:
 *   1=上位プロトコル(または Fragment ヘッダ)まで到達した、0=これ以上進めない(破棄する)
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static int ipv6_skip_ext_headers(const volatile uint8_t *in, size_t total,
                                  uint8_t *nh_io, size_t *off_io, uint8_t *router_alert,
                                  size_t nh_field, int hbh_ok, ipv6_pp_t *pp)
{
    uint8_t nh  = *nh_io;
    size_t  off = *off_io;
    *router_alert = 0;
    pp->send = 0;

    /* 上限を置く。長さ 0 の連鎖は作れない造りだが、壊れたパケットで
     * 無限ループにしないための保険(ARP/NDP のオプション走査と同じ方針)。 */
    for (unsigned depth = 0; depth < 8u; depth++) {
        if (nh == IPV6_NH_TCP || nh == IPV6_NH_UDP || nh == IPV6_NH_ICMPV6) {
            *nh_io = nh; *off_io = off;
            return 1;
        }
        if (nh == IPV6_NH_NONE) return 0;   /* 上位ヘッダ無し(RFC 8200 4.7) */

        if (nh == IPV6_NH_FRAGMENT) {
            /* **ここでは組み立てない。** 組み立てた結果は別のバッファに
             * 入るので、フレーム内のオフセットで返すこの関数では表せない。
             * 「Fragment ヘッダの位置」を返して、呼び出し側(ipv6_handle_frame)
             * に組み立てさせ、完成したバッファでもう一度この関数を通す。 */
            if (off + IPV6_FRAG_HDR_LEN > total) {
                uart_printf("[IPv6] Fragment ヘッダが途中で切れている -- 破棄\n");
                return 0;
            }
            *nh_io = IPV6_NH_FRAGMENT;
            *off_io = off;
            return 1;
        }
        /* **Hop-by-Hop は IPv6 ヘッダの直後にしか置けない**(RFC 8200 4.1)。
         * それ以外の位置のものは「知らない Next Header」と同じ扱い(Linux も同じ)。
         * 途中の Hop-by-Hop を受けると、経路上のルータが見ていないオプションを
         * 終点だけが解釈することになる。 */
        int known = (nh == IPV6_NH_ROUTING || nh == IPV6_NH_DSTOPTS ||
                     (nh == IPV6_NH_HOPOPTS && hbh_ok && depth == 0u));
        if (!known) {
            uart_printf("[IPv6] %s next_header=%u -- 破棄(Parameter Problem code 1)\n",
                        nh == IPV6_NH_HOPOPTS ? "IPv6 ヘッダの直後でない Hop-by-Hop、"
                                              : "未対応の", nh);
            pp->send = 1; pp->code = ICMPV6_CODE_PP_NEXTHDR;
            pp->ptr = (uint32_t)nh_field; pp->even_mcast = 0;
            return 0;
        }
        if (off + 2u > total) {
            uart_printf("[IPv6] 拡張ヘッダが途中で切れている (nh=%u) 破棄\n", nh);
            return 0;
        }

        uint8_t  next = in[off];
        size_t   hlen = ((size_t)in[off + 1u] + 1u) * 8u;
        if (off + hlen > total) {
            uart_printf("[IPv6] 拡張ヘッダ長がフレームを超過 (nh=%u len=%u) 破棄\n",
                        nh, (unsigned)hlen);
            return 0;
        }

        /* **Routing ヘッダは Segments Left で扱いが変わる**(RFC 8200 4.4)。
         * 0 なら「自分が終点」なので読み飛ばしてよいが、0 でなければ
         * **知らない routing type として破棄し、Parameter Problem code 0 で
         * Routing Type の欄を指す**(このスタックは転送しない)。一律に読み飛ばすと、
         * RFC 5095 で廃止された Routing Type 0 を使った経路指定を受け入れることになる。 */
        if (nh == IPV6_NH_ROUTING) {
            uint8_t rtype    = in[off + 2u];
            uint8_t segleft  = in[off + 3u];
            if (segleft != 0u) {
                uart_printf("[IPv6] Routing ヘッダ(type=%u segments_left=%u)-- "
                            "転送しないので破棄\n", rtype, segleft);
                pp->send = 1; pp->code = ICMPV6_CODE_PP_HEADER;
                pp->ptr = (uint32_t)(off + 2u); pp->even_mcast = 0;
                return 0;
            }
        }

        /* Hop-by-Hop / Destination Options の TLV を走査する。
         * **PAD1(type 0)だけは長さフィールドを持たない 1 バイト**なので、
         * 一律に {type,len} で読むとずれる。
         * **オプションが拡張ヘッダの外へはみ出すものは捨てる**(長さの欄を信じて
         * 進むと、次のヘッダや上位のデータをオプションとして読んでしまう)。
         * **未知のオプションの扱いは type の上位 2 ビットが決める**
         * (RFC 8200 4.2)。00 は読み飛ばし、01 は黙って破棄、10 / 11 は破棄して
         * Parameter Problem code 2。 */
        if (nh == IPV6_NH_HOPOPTS || nh == IPV6_NH_DSTOPTS) {
            size_t p = off + 2u;
            const size_t end = off + hlen;
            while (p < end) {
                uint8_t t = in[p];
                if (t == IPV6_TLV_PAD1) { p++; continue; }
                if (p + 2u > end || p + 2u + (size_t)in[p + 1u] > end) {
                    uart_printf("[IPv6] オプション(type=0x%02x)が拡張ヘッダの外へはみ出している "
                                "-- 破棄\n", t);
                    return 0;
                }
                size_t olen = in[p + 1u];
                if (t == IPV6_TLV_ROUTER_ALERT && nh == IPV6_NH_HOPOPTS) {
                    *router_alert = 1;
                } else if (t != IPV6_TLV_PADN &&
                           (t & IPV6_TLV_ACT_MASK) != IPV6_TLV_ACT_SKIP) {
                    uint8_t act = (uint8_t)(t & IPV6_TLV_ACT_MASK);
                    uart_printf("[IPv6] 未知のオプション type=0x%02x(上位 2bit=%u%u)-- パケットを破棄\n",
                                t, (act >> 7) & 1u, (act >> 6) & 1u);
                    if (act == IPV6_TLV_ACT_PP || act == IPV6_TLV_ACT_PP_UNI) {
                        pp->send = 1; pp->code = ICMPV6_CODE_PP_OPTION;
                        pp->ptr = (uint32_t)p;
                        pp->even_mcast = (act == IPV6_TLV_ACT_PP);
                    }
                    return 0;
                }
                p += 2u + olen;
            }
        }

        nh_field = off;
        nh  = next;
        off += hlen;
    }
    uart_printf("[IPv6] 拡張ヘッダが 8 段を超えた -- 破棄\n");
    return 0;
}

/*=================================================================
 * 先頭の断片(オフセット 0)が、上位のヘッダまでの拡張ヘッダの並びを全部含んで
 * いるか(RFC 7112 / RFC 8200 4.5)。上位のヘッダそのものの最低限(TCP 20、UDP 8、
 * ICMPv6 4)まで含むことを見る。
 *
 * **含まない先頭の断片は捨てる。** 上位のヘッダ(ポート番号など)を 2 つ目の断片へ
 * 押し出すと、最初の断片だけを見る検査(ファイアウォールや RA Guard)をすり抜け
 * られる。
 *
 * 引数:
 *   nh   - Fragment ヘッダの next header
 *   d / len - Fragment ヘッダの後ろ(この断片が運ぶデータ)
 * 戻り値:
 *   1=含む、0=含まない
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static int ipv6_frag_chain_complete(uint8_t nh, const volatile uint8_t *d, uint32_t len)
{
    size_t off = 0;
    for (unsigned depth = 0; depth < 8u; depth++) {
        if (nh == IPV6_NH_HOPOPTS || nh == IPV6_NH_ROUTING || nh == IPV6_NH_DSTOPTS) {
            if (off + 2u > len) return 0;
            uint8_t next = d[off];
            off += ((size_t)d[off + 1u] + 1u) * 8u;
            if (off > len) return 0;
            nh = next;
            continue;
        }
        size_t need = (nh == IPV6_NH_TCP) ? 20u : (nh == IPV6_NH_UDP) ? 8u
                    : (nh == IPV6_NH_ICMPV6) ? 4u : 0u;
        return off + need <= len;
    }
    return 0;
}

/*=================================================================
 * 受信 IPv6 フレームを検証して上位へ渡す。IPv6 ヘッダにチェックサムは無い。
 * 拡張ヘッダが付いていればチェーンを辿ってから上位プロトコルへ渡す。
 *
 * 捨てるもの(上位へ渡さない):
 *   - 送信元がマルチキャスト(RFC 4291 2.7。送信元に使えないアドレス。答えると
 *     全員へ撒くことになる)
 *   - 送信元が :: で、ICMPv6 でないもの(:: が正当なのは DAD の NS と MLD だけ)
 *   - 宛先が自分のアドレスでないもの(DAD 中のアドレス宛ても、RFC 4862 5.4)
 *   - 拡張ヘッダの検査に通らないもの(必要なら Parameter Problem を返す)
 *   - 長さ・オフセットが不正な断片(Parameter Problem code 0)と、上位のヘッダまでを
 *     含まない先頭の断片(code 3)
 *
 * 引数:
 *   payload - IPv6 ヘッダ先頭(Ethernet ヘッダの直後)
 *   len     - payload のバイト数
 *   src_mac - 送信元 MAC
 * コール元:
 *   eth_dispatch() から関数ポインタ経由(ipv6_init() で登録)
 * ===============================================================*/
void ipv6_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac)
{
    /* 時間で進める仕事が溜まっていれば進める(無ければ旗を 1 つ読むだけ)。 */
    if (s_timer_pending) ipv6_timer_tick();

    if (len < IPV6_HDR_LEN) {
        uart_printf("[IPv6] フレーム長不足 (len=%u)\n", (unsigned)len);
        return;
    }

    const volatile uint8_t *in = payload;
    if ((in[0] >> 4) != 6u) {
        uart_printf("[IPv6] version フィールドが 6 でない 無視\n");
        return;
    }

    uint16_t plen = rd16be(in + offsetof(ipv6_header_t, payload_len));
    uint8_t  nh   = in[offsetof(ipv6_header_t, next_header)];
    if ((size_t)plen + IPV6_HDR_LEN > len) {
        uart_printf("[IPv6] payload_length がフレーム長を超過 (plen=%u len=%u) 無視\n",
                    plen, (unsigned)len);
        return;
    }
    const size_t total = (size_t)plen + IPV6_HDR_LEN;

    uint8_t src[IPV6_ADDR_LEN], dst[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        src[i] = in[offsetof(ipv6_header_t, src) + i];
        dst[i] = in[offsetof(ipv6_header_t, dst) + i];
    }
    /* 送信元がマルチキャストのものは黙って捨てる(エラーも返さない。RFC 4443 2.4(e))。
     * Echo Request に答えると、ff02::1 を名乗る 1 通でリンクの全員から返事を集められる。 */
    if (src[0] == 0xFFu) return;
    if (!ipv6_addr_is_ours(dst)) {
        return;
    }

    /* 拡張ヘッダを飛ばして上位プロトコルの位置を求める。**上位プロトコルの
     * 長さは payload_length から拡張ヘッダぶんを引いた値**になる(TCP/UDP の
     * チェックサム検証がこの長さを使うので、引き忘れると全部壊れる)。 */
    size_t  off = IPV6_HDR_LEN;
    uint8_t router_alert = 0;
    ipv6_pp_t pp;
    if (!ipv6_skip_ext_headers(in, total, &nh, &off, &router_alert,
                               offsetof(ipv6_header_t, next_header), 1, &pp)) {
        if (pp.send && (dst[0] != 0xFFu || pp.even_mcast)) {
            icmpv6_error_rx(ICMPV6_TYPE_PARAM_PROBLEM, pp.code, pp.ptr, payload, total,
                            src, src_mac);
        }
        return;
    }
    const uint8_t *body = payload + off;
    uint16_t body_len = (uint16_t)(total - off);
    int fragmented = 0;
    int reassembled = 0;

    if (nh == IPV6_NH_FRAGMENT) {
        /* Fragment ヘッダ(8 バイト)= {next header, 予約, オフセット+M(16bit),
         * 識別子(32bit)}。**元の上位プロトコル番号はここに移っている**
         * (IPv6 ヘッダ側は 44 になる)。 */
        uint8_t  fnh   = in[off];
        uint16_t offlg = rd16be(in + off + 2u);
        uint32_t fid   = rd32be(in + off + 4u);
        uint32_t foff  = (uint32_t)(offlg & IPV6_FRAG_OFF_MASK);
        int      more  = (offlg & IPV6_FRAG_MORE) ? 1 : 0;
        const uint8_t *fdata = payload + off + IPV6_FRAG_HDR_LEN;
        uint32_t flen = (uint32_t)(total - off - IPV6_FRAG_HDR_LEN);
        fragmented = 1;

        /* 観測フックは残してある(`ext6test` が断片単位で形を確かめる)。
         * 組み立てを実装した今は素通しの覗き見。 */
        if (s_ipv6_frag_observer) {
            s_ipv6_frag_observer(fid, (uint16_t)foff, more, fnh, fdata, (uint16_t)flen);
        }

        /* ---- 断片の形の検査(RFC 8200 4.5)。組み立ての表に入れる前に見る ----
         * - 最後でない断片の長さは 8 の倍数(でないと次の断片のオフセットと
         *   隙間か重なりができる)。Pointer は Payload Length の欄。
         * - 組み立てた結果が 65535 バイトを超えない。Pointer は Fragment Offset の欄。 */
        if (more && (flen & 7u) != 0u) {
            uart_printf("[IPv6] 最後でない断片の長さ %u が 8 の倍数でない -- 破棄\n", (unsigned)flen);
            icmpv6_error_rx(ICMPV6_TYPE_PARAM_PROBLEM, ICMPV6_CODE_PP_HEADER,
                            offsetof(ipv6_header_t, payload_len), payload, total, src, src_mac);
            return;
        }
        if ((off - IPV6_HDR_LEN) + foff + flen > 65535u) {
            uart_printf("[IPv6] 断片を組み立てると 65535 バイトを超える (off=%u len=%u) -- 破棄\n",
                        (unsigned)foff, (unsigned)flen);
            icmpv6_error_rx(ICMPV6_TYPE_PARAM_PROBLEM, ICMPV6_CODE_PP_HEADER,
                            (uint32_t)(off + 2u), payload, total, src, src_mac);
            return;
        }
        /* 先頭の断片は上位のヘッダまでを全部含む(RFC 7112、8200 4.5)。Pointer は 0。 */
        if (foff == 0u && !ipv6_frag_chain_complete(fnh, fdata, flen)) {
            uart_printf("[IPv6] 先頭の断片が上位のヘッダまでを含まない -- 破棄(RFC 7112)\n");
            icmpv6_error_rx(ICMPV6_TYPE_PARAM_PROBLEM, ICMPV6_CODE_PP_CHAIN, 0u,
                            payload, total, src, src_mac);
            return;
        }

        if (foff == 0u && !more) {
            /* **原子断片**(オフセット 0 で M=0。中身は 1 つで完結している)は組み立ての
             * 表に入れず、その場で処理する(RFC 6946 4 の MUST)。表に入れると、同じ
             * 識別子の偽の断片を先に送り込まれたときに、本物の原子断片がそれと混ざって
             * 壊れる(または重なりとして捨てられる)。 */
            nh       = fnh;
            body     = fdata;
            body_len = (uint16_t)flen;
        } else {
            netaddr_t fs = netaddr_v6(src);
            netaddr_t fd = netaddr_v6(dst);
            const uint8_t *whole = NULL;
            uint32_t whole_len = 0;
            uint8_t whole_nh = fnh;
            if (!ipfrag_input(&fs, &fd, fid, fnh, foff, more, fdata, flen,
                              payload, (uint32_t)total, src_mac,
                              &whole, &whole_len, &whole_nh)) {
                return;  /* まだそろっていない */
            }
            nh       = whole_nh;   /* オフセット 0 の断片の next header(RFC 8200 4.5) */
            body     = whole;
            body_len = (uint16_t)whole_len;
            reassembled = 1;
        }
        /* **NIC のチェックサム検証済みの印は使わない。** 印は最後に受けた断片 1 つに
         * ついてのもので、組み立てたデータグラム全体を検証したものではない
         * (そもそも NIC は断片の上位のチェックサムを検証しない)。落としておけば、
         * 上位(UDP / ICMPv6 / TCP)がソフトウェアで検証する。 */
        eth_rx_set_hw_csum_ok(0);

        /* **Fragment ヘッダの後ろにも拡張ヘッダがありうる**(断片化される部分の
         * Destination Options など、RFC 8200 4.1)。組み立てたものをもう一度辿る。
         * ここでの Hop-by-Hop は位置の誤りなので許さない。2 つ目の Fragment ヘッダも
         * 捨てる(入れ子の断片化は無い)。 */
        size_t boff = 0;
        uint8_t ra2 = 0;
        ipv6_pp_t pp2;
        if (!ipv6_skip_ext_headers(body, body_len, &nh, &boff, &ra2, 0u, 0, &pp2)) return;
        if (nh == IPV6_NH_FRAGMENT) {
            uart_printf("[IPv6] 断片の中にもう 1 つ Fragment ヘッダ -- 破棄\n");
            return;
        }
        body     += boff;
        body_len  = (uint16_t)(body_len - boff);
    }

    /* 送信元 :: が正当なのは ICMPv6(DAD の NS と MLD)だけ。 */
    if (nh != IPV6_NH_ICMPV6 && ipv6_addr_unspec(src)) return;

    if (nh == IPV6_NH_ICMPV6) {
        ipv6_handle_icmpv6(body, body_len, src, dst,
                           in[offsetof(ipv6_header_t, hop_limit)], router_alert, src_mac,
                           fragmented);
    } else if (nh == IPV6_NH_TCP) {
        netaddr_t s = netaddr_v6(src);
        netaddr_t d = netaddr_v6(dst);
        tcp_input_addr(body, body_len, &s, &d);
    } else if (nh == IPV6_NH_UDP) {
        netaddr_t s = netaddr_v6(src);
        netaddr_t d = netaddr_v6(dst);
        int r = udp_input_addr(body, body_len, &s, &d, src_mac);
        /* **待ち受けの無いポート宛てには Destination Unreachable code 4**(RFC 4443 3.1
         * の SHOULD。相手は待ち続けずに済む)。ただし
         *   - マルチキャスト宛てには返さない(icmpv6_send_error() の (e.3))
         *   - **RoCEv2 の UDP 4791 には返さない**(IPv4 側と同じ。RDMA を使っている
         *     最中に NIC の RDMA の受信を通らなかったフレームが来ても、エラーで相手の
         *     RDMA を乱さない)
         *   - 頻度の制限(icmpv6_send_error() の中)。 */
        if (r == -1 && body_len >= 8u && dst[0] != 0xFFu &&
            rd16be(body + 2u) != UDP_PORT_ROCEV2) {
            if (!reassembled && !fragmented) {
                icmpv6_error_rx(ICMPV6_TYPE_DEST_UNREACH, ICMPV6_CODE_PORT_UNREACH, 0u,
                                payload, total, src, src_mac);
            } else {
                /* 断片から組み立てたものは、IPv6 ヘッダを付け直して引用する
                 * (Fragment ヘッダを外した形。Linux も組み立てた後のものを引用する)。 */
                unsigned core = smp_core_index();
                if (core >= SMP_MAX_CORES) core = 0;
                static uint8_t qbuf[SMP_MAX_CORES][1280u - IPV6_HDR_LEN - 8u];
                uint8_t *q = qbuf[core];
                for (unsigned i = 0; i < IPV6_HDR_LEN; i++) q[i] = in[i];
                q[offsetof(ipv6_header_t, next_header)] = IPV6_NH_UDP;
                wr16be(q + offsetof(ipv6_header_t, payload_len), body_len);
                size_t n = body_len;
                if (n > sizeof(qbuf[0]) - IPV6_HDR_LEN) n = sizeof(qbuf[0]) - IPV6_HDR_LEN;
                for (size_t i = 0; i < n; i++) q[IPV6_HDR_LEN + i] = body[i];
                icmpv6_error_rx(ICMPV6_TYPE_DEST_UNREACH, ICMPV6_CODE_PORT_UNREACH, 0u,
                                q, IPV6_HDR_LEN + n, src, src_mac);
            }
        }
    }
}

/*=================================================================
 * MTU を超えるデータグラムを Fragment 拡張ヘッダで分割して送る
 * (RFC 8200 4.5)。
 *
 * **IPv4 との違いが 3 つある**:
 *   - 分割情報は IP ヘッダではなく **8 バイトの拡張ヘッダ**に載る。
 *     したがって 1 断片に載せられるデータは MTU - 40 - 8。
 *   - IPv6 ヘッダの next_header は **44(Fragment)**になり、元の上位
 *     プロトコル番号は Fragment ヘッダの中へ移る。
 *   - Identification は **32bit**(IPv4 は 16bit)。
 * 同じなのは「オフセットは 8 バイト単位」「最後以外の断片長は 8 の倍数」。
 *
 * 引数:
 *   src / dst / dst_mac   - 送信元・宛先
 *   next_header           - 元の上位プロトコル番号
 *   payload / payload_len - 分割するデータグラム全体
 *   mtu                   - この経路で送ってよい IPv6 パケット長(ヘッダ込み)
 * 戻り値:
 *   0=全断片を送った、-1=失敗
 * コール元:
 *   ipv6_send_from()
 * ===============================================================*/
static int ipv6_send_fragmented(const uint8_t src[IPV6_ADDR_LEN],
                                 const uint8_t dst[IPV6_ADDR_LEN],
                                 const uint8_t dst_mac[ETH_ALEN], uint8_t next_header,
                                 const uint8_t *payload, uint16_t payload_len,
                                 uint16_t mtu)
{
    if (mtu <= IPV6_HDR_LEN + IPV6_FRAG_HDR_LEN) {
        uart_printf("[!] IPv6: MTU が小さすぎて断片化できない (mtu=%u)\n", mtu);
        return -1;
    }
    uint16_t chunk = (uint16_t)((mtu - IPV6_HDR_LEN - IPV6_FRAG_HDR_LEN) & ~7u);
    if (chunk == 0u) {
        uart_printf("[!] IPv6: MTU が小さすぎて断片化できない (mtu=%u)\n", mtu);
        return -1;
    }

    /* 全断片で共通。全コアで 1 つの数を原子的に進める(起点は起動時の乱数)。 */
    const uint32_t id = __atomic_add_fetch(&s_ipv6_frag_id, 1u, __ATOMIC_RELAXED);
    const uint8_t hop = ipv6_hop_for(next_header, payload, payload_len);
    uint16_t off = 0;
    unsigned count = 0;

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);

    while (off < payload_len) {
        uint16_t remain   = (uint16_t)(payload_len - off);
        uint16_t this_len = (remain > chunk) ? chunk : remain;
        int      more     = (uint16_t)(off + this_len) < payload_len;

        net_buf_t *nb = net_buf_alloc();
        if (!nb) {
            uart_printf("[!] IPv6: 断片送信中に net_buf プール枯渇 (offset=%u)\n", off);
            return -1;
        }

        volatile uint8_t *out = nb->data;
        for (unsigned i = 0; i < ETH_ALEN; i++) out[i]            = dst_mac[i];
        for (unsigned i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
        out[12] = 0x86; out[13] = 0xDD;

        volatile uint8_t *h = out + ETH_HDR_LEN;
        h[0] = 0x60; h[1] = 0; h[2] = 0; h[3] = 0;
        wr16be(h + offsetof(ipv6_header_t, payload_len),
               (uint16_t)(IPV6_FRAG_HDR_LEN + this_len));
        h[offsetof(ipv6_header_t, next_header)] = IPV6_NH_FRAGMENT;
        h[offsetof(ipv6_header_t, hop_limit)]   = hop;
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
            h[offsetof(ipv6_header_t, src) + i] = src[i];
            h[offsetof(ipv6_header_t, dst) + i] = dst[i];
        }

        /* Fragment 拡張ヘッダ。**オフセットは 8 バイト単位で上位 13 ビット**
         * なので、バイトオフセットをそのまま入れてはいけない。 */
        volatile uint8_t *fh = h + IPV6_HDR_LEN;
        fh[0] = next_header;
        fh[1] = 0;
        wr16be(fh + 2, (uint16_t)((off & IPV6_FRAG_OFF_MASK) |
                                   (more ? IPV6_FRAG_MORE : 0u)));
        wr32be(fh + 4, id);

        const volatile uint8_t *vp = payload + off;
        volatile uint8_t *body = fh + IPV6_FRAG_HDR_LEN;
        for (uint16_t i = 0; i < this_len; i++) body[i] = vp[i];

        nb->len = (uint16_t)(ETH_HDR_LEN + IPV6_HDR_LEN + IPV6_FRAG_HDR_LEN + this_len);
        if (s_ipv6_tx_observer) {
            s_ipv6_tx_observer(hop, IPV6_NH_FRAGMENT, nb->data + ETH_HDR_LEN + IPV6_HDR_LEN,
                               (uint16_t)(IPV6_FRAG_HDR_LEN + this_len));
        }
        if (eth_send(nb) != 0) {   /* eth_send() が net_buf を解放する */
            uart_printf("[!] IPv6: 断片の送信失敗 (offset=%u len=%u)\n", off, this_len);
            return -1;
        }
        off = (uint16_t)(off + this_len);
        count++;
    }

    uart_printf("[IPv6] %u バイトを %u 個の断片へ分割して送信 (id=%u 断片長=%u nh=%u)\n",
                payload_len, count, (unsigned)id, chunk, next_header);
    return 0;
}

/*=================================================================
 * IPv6 データグラムを 1 個送信する(送信元アドレス指定版)。拡張ヘッダは
 * 付けない。DAD の NS だけは送信元を未指定アドレス(::)にする必要があるので、
 * 送信元を引数に取る形をこちらに置き、ipv6_send() を薄いラッパにしてある。
 *
 * 引数:
 *   src                   - 送信元アドレス(DAD なら ::)
 *   dst / dst_mac         - 宛先
 *   next_header           - 上位プロトコル番号
 *   payload / payload_len - 上位プロトコルのメッセージ
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_send(), ipv6_send_icmpv6_from()
 * ===============================================================*/
int ipv6_send_from(const uint8_t src[IPV6_ADDR_LEN],
                   const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
                   uint8_t next_header, const uint8_t *payload, uint16_t payload_len)
{
    /* **IPv6 は経路上で分割しない**(RFC 8200 4.5)。IPv4 ならルータが割って
     * くれるが、IPv6 で MTU を超えたら送信元が Fragment 拡張ヘッダを付けて
     * 自分で割るしかない。TCP は MSS で自分で収めるのでここへは来ない
     * (来るのは UDP と大きな ICMPv6)。 */
    {
        uint16_t mtu = net_active_ip_mtu();
        netaddr_t d = netaddr_v6(dst);
        uint16_t pm = pmtu_lookup(&d);
        if (pm != 0u && pm < mtu) mtu = pm;
        if ((uint32_t)IPV6_HDR_LEN + payload_len > mtu) {
            return ipv6_send_fragmented(src, dst, dst_mac, next_header,
                                         payload, payload_len, mtu);
        }
    }

    uint32_t frame_len = (uint32_t)ETH_HDR_LEN + IPV6_HDR_LEN + payload_len;
    if (frame_len > NET_BUF_SIZE) {
        uart_printf("[!] IPv6: フレーム長超過 (%u)\n", (unsigned)frame_len);
        return -1;
    }

    net_buf_t *nb = net_buf_alloc();
    if (!nb) {
        uart_printf("[!] IPv6: net_buf 確保失敗\n");
        return -1;
    }

    uint8_t self_mac[ETH_ALEN];
    eth_get_mac(self_mac);

    volatile uint8_t *out = nb->data;
    for (unsigned i = 0; i < ETH_ALEN; i++) out[i]            = dst_mac[i];
    for (unsigned i = 0; i < ETH_ALEN; i++) out[ETH_ALEN + i] = self_mac[i];
    out[12] = 0x86; out[13] = 0xDD;  /* EtherType: IPv6 */

    volatile uint8_t *h = out + ETH_HDR_LEN;
    h[0] = 0x60; h[1] = 0; h[2] = 0; h[3] = 0;  /* version=6, TC=0, flow label=0 */
    wr16be(h + offsetof(ipv6_header_t, payload_len), payload_len);
    h[offsetof(ipv6_header_t, next_header)] = next_header;
    /* **255 は NDP だけ**(RFC 4861 6.1 / 7.1 の受信側の検査のため)。それ以外は
     * CurHopLimit(RA の Cur Hop Limit か 64)。 */
    const uint8_t hop = ipv6_hop_for(next_header, payload, payload_len);
    h[offsetof(ipv6_header_t, hop_limit)]   = hop;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        h[offsetof(ipv6_header_t, src) + i] = src[i];
        h[offsetof(ipv6_header_t, dst) + i] = dst[i];
    }
    for (uint16_t i = 0; i < payload_len; i++) {
        out[ETH_HDR_LEN + IPV6_HDR_LEN + i] = payload[i];
    }
    if (s_ipv6_tx_observer) s_ipv6_tx_observer(hop, next_header, payload, payload_len);

    nb->len = (uint16_t)frame_len;
    /* eth_send() は成否によらず内部で net_buf_free() する。ここで重ねて
     * 解放してはいけない(net_buf_free は冪等なので従来は無害だったが、
     * 二重解放の形は残さない)。 */
    return eth_send(nb);
}

/*=================================================================
 * IPv6 データグラムを 1 個送信する。送信元は自分のリンクローカル。
 *
 * 引数:
 *   dst / dst_mac         - 宛先
 *   next_header           - 上位プロトコル番号
 *   payload / payload_len - 上位プロトコルのメッセージ
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   ipv6_send_icmpv6(), udp_send6(), ipv6_send_echo_request()
 * ===============================================================*/
int ipv6_send(const uint8_t dst[IPV6_ADDR_LEN], const uint8_t dst_mac[6],
              uint8_t next_header, const uint8_t *payload, uint16_t payload_len)
{
    uint8_t src[IPV6_ADDR_LEN];
    ipv6_source_for(dst, src);
    return ipv6_send_from(src, dst, dst_mac, next_header, payload, payload_len);
}

/*=================================================================
 * ICMPv6 Echo Request を全ノードマルチキャスト(ff02::1、L2 は
 * 33:33:00:00:00:01)へ 1 個送る。直結リンクなので近隣探索でアドレス解決を
 * しなくても相手に届き、疎通確認ができる。
 *
 * 引数:
 *   ident / seq - Echo の識別子と通番
 *   payload_len - Echo ヘッダ(8)の後ろに付けるデータ長
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   shell_ping6()
 * ===============================================================*/
int ipv6_send_echo_request(uint16_t ident, uint16_t seq, uint16_t payload_len)
{
    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    static uint8_t req[SMP_MAX_CORES][NET_BUF_SIZE];

    uint32_t total = 8u + payload_len;
    if (total > NET_BUF_SIZE) return -1;

    uint8_t *m = req[core];
    for (uint32_t i = 0; i < total; i++) m[i] = (uint8_t)(i);
    m[ICMPV6_OFF_TYPE] = ICMPV6_TYPE_ECHO_REQUEST;
    m[ICMPV6_OFF_CODE] = 0;
    wr16be(m + ICMPV6_OFF_CHECKSUM, 0);
    wr16be(m + 4, ident);
    wr16be(m + 6, seq);

    uint8_t dst[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) dst[i] = 0;
    dst[0] = 0xFF; dst[1] = 0x02; dst[15] = 0x01;   /* ff02::1 */
    const uint8_t dst_mac[ETH_ALEN] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };

    return ipv6_send_icmpv6(dst, dst_mac, m, (uint16_t)total);
}
