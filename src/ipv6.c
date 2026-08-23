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

#define NDP_RESOLVE_TIMEOUT_MS  200u
#define NDP_RESOLVE_MAX_ATTEMPTS 3u

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
 * v1 互換モードの期限。**Linux ブリッジの既定は `mcast_mld_version 1`** なので、
 * 実スイッチ配下ではまずこちらに落ちる。0 = v2 で喋る。 */
static volatile uint64_t s_mld_v1_until;
/* 送信する MLD メッセージの観測フック(`mldtest` 用)。相手(ルータ/スイッチ)が
 * 居ないと自分の送信を確かめられないので、送る直前にテスト側へ渡す。 */
static ipv6_mld_observer_t s_mld_observer;
/* 1 = MLD を一切送らない(`mld off`)。**スヌーピングするスイッチの配下では
 * これで通信が止まる** -- 「MLD が効いていること」の陰性対照を作るための
 * 恒久的なデバッグ機能で、`txdrop` と同じ位置づけ。戻し忘れに注意。 */
static volatile int s_mld_suppress;

/* ---- Fragment 拡張ヘッダ ----
 *
 * 送信側の断片で使う Identification(RFC 8200 は 32bit)。受信側の再構成は
 * 実装していないので、こちらは送るだけ。 */
static uint32_t s_ipv6_frag_id[SMP_MAX_CORES];
/* 受信した断片を捨てる直前に呼ぶ観測フック(`ext6test` 用)。 */
static ipv6_frag_observer_t s_ipv6_frag_observer;

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
int ipv6_mld_v1_mode(void)
{
    uint64_t until = s_mld_v1_until;
    if (until == 0u) return 0;
    if ((int64_t)(timer_now() - until) >= 0) return 0;
    return 1;
}

/*=================================================================
 * v1 互換モードを即座に解除する。通常は MLD_V1_COMPAT_MS で切れるが、
 * `mldtest` が v1 の Query を注入した後に元へ戻すために要る。
 *
 * コール元:
 *   shell_mldtest()
 * ===============================================================*/
void ipv6_mld_clear_v1_mode(void)
{
    s_mld_v1_until = 0;
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
 * 受信 IPv6 断片の観測フックを登録する(NULL で解除)。**受信側の再構成を
 * 実装していない**ので、送信側の断片化はこれでしか確かめられない
 * (`ip_set_frag_observer()` と同じ考え方)。登録中は断片ごとの破棄ログを
 * 抑止する。
 *
 * コール元:
 *   shell_ext6test()
 * ===============================================================*/
void ipv6_set_frag_observer(ipv6_frag_observer_t fn)
{
    s_ipv6_frag_observer = fn;
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

/*=================================================================
 * アクティブなインターフェースのグローバル IPv6 アドレスを返す。
 *
 * 引数:
 *   out - 16 バイトの格納先(未設定なら触らない)
 * 戻り値:
 *   1=設定済み、0=未設定
 * コール元:
 *   ipv6_addr_is_ours(), ipv6_source_for()
 * ===============================================================*/
int ipv6_global_addr(uint8_t out[IPV6_ADDR_LEN])
{
    netif_t *ni = g_active_ctx;
    if (!ni || !ni->ip6_global_set) return 0;
    /* **寿命の判定は SLAAC 由来のときだけ。** 手動設定(`ip6addr`)と未設定は
     * 期限を持たないので、この関数が時刻を読むこともない。ここは受信フレーム
     * ごと(ipv6_addr_is_ours)と送信ごと(ipv6_source_for)に通るので、
     * 無条件に timer_now() を呼ぶとホットパスへ時刻読み出しが乗る。 */
    if (ni->ip6_global_valid_until != 0u) {
        ipv6_slaac_age(ni);
        if (!ni->ip6_global_set) return 0;
    }
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[i] = ni->ip6_global[i];
    return 1;
}

/*=================================================================
 * RA から得た寿命(グローバルアドレスとデフォルトルータ)が満了していたら
 * 解除する。
 *
 * **冷たい経路からのみ呼ぶ。** ルータ寿命だけは netif_next_hop6() という
 * 送信ホットパス(inline)から参照されるが、そこへ時刻読み出しを持ち込みたく
 * ないので、判定はここに寄せてある。呼ばれる契機は
 *   - RA を受信したとき(次の RA まで最大でも RA 間隔ぶんの遅れ)
 *   - SLAAC 由来のグローバルアドレスを使うとき(ipv6_global_addr)
 *   - シェルの `slaac` / `ip6addr` / `route` 表示
 * の 3 つ。**ルータが黙って消えたまま誰もこのインターフェースを使わない場合、
 * gateway6 は次に使われるまで残る**(残っていても実害が出るのは、その
 * ゲートウェイ宛に送ろうとしたときだけ)。
 *
 * 引数:
 *   ni - 対象インターフェース(NULL 可)
 * コール元:
 *   ipv6_global_addr(), ipv6_handle_ra(), shell_slaac(), shell_route()
 * ===============================================================*/
void ipv6_slaac_age(netif_t *ni)
{
    if (!ni) return;
    if (ni->ip6_global_valid_until == 0u && ni->gateway6_valid_until == 0u) return;

    uint64_t now = timer_now();
    if (ni->ip6_global_set && ni->ip6_global_valid_until != 0u &&
        (int64_t)(now - ni->ip6_global_valid_until) >= 0) {
        uart_printf("[IPv6] SLAAC: %s のグローバルアドレスが有効期間切れ -- 解除します\n",
                    ni->name ? ni->name : "?");
        ni->ip6_global_set        = 0;
        ni->ip6_global_from_ra    = 0;
        ni->ip6_global_valid_until = 0;
    }
    if (ni->gateway6_set && ni->gateway6_valid_until != 0u &&
        (int64_t)(now - ni->gateway6_valid_until) >= 0) {
        uart_printf("[IPv6] SLAAC: %s のデフォルトルータが寿命切れ -- 解除します\n",
                    ni->name ? ni->name : "?");
        ni->gateway6_set        = 0;
        ni->gateway6_from_ra    = 0;
        ni->gateway6_valid_until = 0;
    }
}

/*=================================================================
 * 宛先に応じて送信元 IPv6 アドレスを選ぶ。リンクローカル宛とマルチキャスト
 * 宛はリンクローカルから、それ以外はグローバルがあればグローバルから送る
 * (RFC 6724 の簡略版。スコープを跨いだ送信元を使わないことだけが目的)。
 *
 * 引数:
 *   dst - 宛先、out - 送信元の格納先
 * コール元:
 *   ipv6_send(), ipv6_send_icmpv6()
 * ===============================================================*/
void ipv6_source_for(const uint8_t dst[IPV6_ADDR_LEN], uint8_t out[IPV6_ADDR_LEN])
{
    int link_scope = (dst[0] == 0xFFu) ||                       /* マルチキャスト */
                     (dst[0] == 0xFEu && (dst[1] & 0xC0u) == 0x80u); /* fe80::/10 */
    if (!link_scope && ipv6_global_addr(out)) return;
    ipv6_link_local_addr(out);
}

/*=================================================================
 * 受信アドレスが自ノード宛かを判定する。リンクローカル本体、そのアドレスの
 * 要請ノードマルチキャスト(ff02::1:ffXX:XXXX)、全ノードマルチキャスト
 * (ff02::1)の 3 つを受ける。
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
    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);

    int same = 1;
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        if (addr[i] != ll[i]) { same = 0; break; }
    }
    if (same) return 1;

    /* グローバルアドレス(設定されていれば) */
    uint8_t g[IPV6_ADDR_LEN];
    if (ipv6_global_addr(g)) {
        int gsame = 1;
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
            if (addr[i] != g[i]) { gsame = 0; break; }
        }
        if (gsame) return 1;
    }

    /* ff02::1 (全ノード) */
    if (addr[0] == 0xFF && addr[1] == 0x02) {
        int zero_mid = 1;
        for (unsigned i = 2; i < 15; i++) {
            if (addr[i] != 0) { zero_mid = 0; break; }
        }
        if (zero_mid && addr[15] == 0x01) return 1;

        /* ff02::1:ffXX:XXXX (要請ノードマルチキャスト)。バイト列では
         * ff 02 00..00 01 ff XX XX XX なので、addr[11]=0x01 / addr[12]=0xFF で、
         * addr[13..15] が自分のリンクローカル下位 3 バイトと一致する。 */
        if (addr[11] == 0x01 && addr[12] == 0xFF &&
            addr[13] == ll[13] && addr[14] == ll[14] && addr[15] == ll[15]) {
            return 1;
        }
        /* **グローバルアドレス由来の要請ノードマルチキャストも受ける。**
         * 下位 3 バイトがリンクローカル(EUI-64 由来)と違うので、ここを
         * 足さないと相手の NS が届かず、グローバルアドレスへは到達できない。 */
        if (addr[11] == 0x01 && addr[12] == 0xFF && ipv6_global_addr(g) &&
            addr[13] == g[13] && addr[14] == g[14] && addr[15] == g[15]) {
            return 1;
        }
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
    h[offsetof(ipv6_header_t, hop_limit)]   = 64u;
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
 * 近隣キャッシュへ 1 件登録する(既存エントリがあれば MAC を更新)。空きが
 * 無ければ先頭を潰す。ARP キャッシュと同じく、アクティブなインターフェースの
 * キャッシュに入れる。
 *
 * 引数:
 *   addr - 相手の IPv6 アドレス
 *   mac  - 対応する MAC
 * コール元:
 *   ipv6_handle_icmpv6()
 * ===============================================================*/
void ndp_cache_insert(const uint8_t addr[IPV6_ADDR_LEN], const uint8_t mac[ETH_ALEN])
{
    ndp_cache_entry_t *cache = g_active_ctx->ndp_cache;
    unsigned free_slot = NDP_CACHE_SIZE;
    uint64_t expiry = neigh_expiry_from_now();

    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            if (free_slot == NDP_CACHE_SIZE) free_slot = i;
            continue;
        }
        int same = 1;
        for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) {
            if (cache[i].addr[j] != addr[j]) { same = 0; break; }
        }
        if (same) {
            for (unsigned j = 0; j < ETH_ALEN; j++) cache[i].mac[j] = mac[j];
            cache[i].expires_at = expiry;   /* NS/NA を受けるたびに延命する */
            cache[i].probe_at   = 0;
            return;
        }
    }

    unsigned slot = (free_slot < NDP_CACHE_SIZE) ? free_slot : 0u;
    for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) cache[slot].addr[j] = addr[j];
    for (unsigned j = 0; j < ETH_ALEN; j++) cache[slot].mac[j] = mac[j];
    cache[slot].valid      = 1;
    cache[slot].expires_at = expiry;
    cache[slot].probe_at   = 0;
}

/*=================================================================
 * Neighbor Advertisement 1 通ぶんのキャッシュ更新(RFC 4861 7.2.5)。
 *
 * **無条件に上書きしてはいけない。** NA には Solicited と Override の 2 つの
 * フラグがあり、意味が違う:
 *
 *  - **Solicited=1**: こちらの NS への応答。**到達性が確認できた証拠**なので
 *    延命してよい。非要請の NA(相手がアドレスを変えたときなどに撒く)は
 *    「そこに居るらしい」以上の情報を持たないので、延命の根拠にはならない。
 *  - **Override=0** で、キャッシュ済みの MAC と違う値を持ってきた NA は
 *    **無視する**。ここを無条件上書きにしていると、**偽の NA を 1 通投げる
 *    だけで他人宛のトラフィックを奪える**(NDP スプーフィング)。
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
    ndp_cache_entry_t *cache = g_active_ctx->ndp_cache;

    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) {
        if (!cache[i].valid) continue;
        int same = 1;
        for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) {
            if (cache[i].addr[j] != addr[j]) { same = 0; break; }
        }
        if (!same) continue;

        int mac_same = 1;
        for (unsigned j = 0; j < ETH_ALEN; j++) {
            if (cache[i].mac[j] != mac[j]) { mac_same = 0; break; }
        }
        if (!mac_same && !override_flag) {
            uart_printf("[NDP] Override 無しの NA が既存と違う MAC を主張 -- 無視"
                        "(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
        if (!mac_same) {
            for (unsigned j = 0; j < ETH_ALEN; j++) cache[i].mac[j] = mac[j];
        }
        /* **延命するのは solicited のときだけ。** 非要請 NA は到達性の証拠に
         * ならない(RFC 4861 7.2.5 は STALE のままにせよと言っている)。 */
        if (solicited) {
            cache[i].expires_at = neigh_expiry_from_now();
            cache[i].probe_at   = 0;
        }
        return;
    }

    /* エントリが無い場合、RFC 4861 7.2.5 は「黙って捨てよ」と言っているが、
     * **このスタックは INCOMPLETE のエントリを作らない**(ndp_resolve() が
     * NS を送ってから NA を待つ形)。捨てるとアドレス解決が一切できなくなる
     * ので、ここでは新規登録する。意図的な逸脱。 */
    ndp_cache_insert(addr, mac);
}

/*=================================================================
 * 近隣キャッシュを引く。有効期限を過ぎたエントリは即座に捨てず、猶予の
 * あいだは MAC を返しつつ Neighbor Solicitation を投げる(ARP 側の
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
        int age = neigh_check_age(timer_now(), cache[i].expires_at, &cache[i].probe_at);
        if (age == NEIGH_DEAD) {
            cache[i].valid = 0;
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
 *   remain_ms - NULL 可。fresh なら失効まで、stale なら破棄までの残り
 * 戻り値:
 *   0=fresh、1=stale(猶予中)、-1=未登録または猶予切れ
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

        uint64_t grace_ns = (uint64_t)(g_neigh_cache_ttl_ms / 6u) * 1000000ull;
        uint64_t deadline;
        int state;
        if ((int64_t)(now - cache[i].expires_at) < 0) {
            deadline = cache[i].expires_at;
            state = 0;
        } else if ((int64_t)(now - (cache[i].expires_at + grace_ns)) >= 0) {
            return -1;
        } else {
            deadline = cache[i].expires_at + grace_ns;
            state = 1;
        }
        if (remain_ms) *remain_ms = (uint32_t)((deadline - now) / 1000000ull);
        return state;
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
 * RA から作られたグローバルアドレスに対して **DAD をここで実行する**。
 *
 * RA の解釈そのものは受信ハンドラ(ipv6_handle_ra)にある。非要請 RA も
 * 同じ経路を通るので、この関数は「最初の 1 通を早く貰うための催促」と
 * 「受信ハンドラでは実行できない DAD の代行」を担当する。
 *
 * **DAD をハンドラ側でやらない理由**: ipv6_dad() は内部で
 * net_poll_all_and_dispatch() を回すので、受信処理の中から呼ぶと受信が
 * 再入する(arp_resolve() を送信ホットパスから呼んだときと同じ形)。
 * したがって**非要請 RA だけで設定されたアドレスは DAD 未実施のまま**に
 * なる(netif_t.ip6_global_dad が NETIF_DAD_UNKNOWN で残る)。
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

    /* RA は届いた。グローバルアドレスが作られていれば DAD を行う。 */
    netif_activate(ni);
    if (ni->ip6_global_set && ni->ip6_global_from_ra &&
        ni->ip6_global_dad == NETIF_DAD_UNKNOWN) {
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
 * arp_resolve() と同じ「送って待つ」同期解決。
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

    for (unsigned attempt = 0; attempt < NDP_RESOLVE_MAX_ATTEMPTS; attempt++) {
        if (ndp_send_ns(addr) != 0) return -1;

        uint64_t start = timer_now();
        do {
            net_poll_all_and_dispatch();
            if (ndp_cache_lookup(addr, out_mac) == 0) return 0;
        } while (!timeout_ms(start, NDP_RESOLVE_TIMEOUT_MS));
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
    uint8_t g[IPV6_ADDR_LEN];
    if (ipv6_global_addr(g)) {
        uint8_t sol[IPV6_ADDR_LEN];
        ipv6_solicited_node_addr(g, sol);
        /* リンクローカルと下位 24bit が同じなら要請ノードも同じになる
         * (SLAAC は EUI-64 を使うので実際そうなる)。重複して報告しない。 */
        int same = 1;
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
            if (sol[i] != out[0][i]) { same = 0; break; }
        }
        if (!same && n < max) {
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

/*=================================================================
 * いま参加しているグループをすべて報告する(非要請 Report)。
 *
 * **v1 互換モードならグループごとに v1 Report、そうでなければ v2 Report 1 通。**
 * RFC 3810 の Robustness Variable に従って複数回送る(1 通目が落ちても
 * スイッチが学習できるように)。
 *
 * 引数:
 *   ni - 対象インターフェース(NULL ならアクティブなもの)
 * 戻り値:
 *   送った Report の数、-1=失敗
 * コール元:
 *   run_shell(), shell_mld(), ipv6_slaac_apply_prefix()
 * ===============================================================*/
int ipv6_mld_report_all(netif_t *ni)
{
    netif_t *prev = g_active_ctx;
    if (ni) netif_activate(ni); else ni = g_active_ctx;
    if (!ni) return -1;

    uint8_t groups[IPV6_MCAST_MAX][IPV6_ADDR_LEN];
    unsigned n = ipv6_mcast_groups(ni, groups, IPV6_MCAST_MAX);
    int sent = 0;

    for (unsigned rep = 0; rep < MLD_UNSOLICITED_REPORTS; rep++) {
        if (ipv6_mld_v1_mode()) {
            for (unsigned i = 0; i < n; i++) {
                if (mld_send_v1(ICMPV6_TYPE_MLD_REPORT, groups[i]) == 0) sent++;
            }
        } else {
            if (mld_send_v2_report(MLD2_CHANGE_TO_EXCLUDE,
                                    (const uint8_t (*)[IPV6_ADDR_LEN])groups, n) == 0) {
                sent++;
            }
        }
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
int ipv6_mld_leave(const uint8_t group[IPV6_ADDR_LEN])
{
    if (ipv6_mld_v1_mode()) return mld_send_v1(ICMPV6_TYPE_MLD_DONE, group);

    uint8_t one[1][IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) one[0][i] = group[i];
    return mld_send_v2_report(MLD2_CHANGE_TO_INCLUDE,
                              (const uint8_t (*)[IPV6_ADDR_LEN])one, 1u);
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
    if (len < 24u) {
        uart_printf("[MLD] Query 長不足 (len=%u)\n", (unsigned)len);
        return;
    }

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    g_ipv6_mld_query_count[core]++;

    int v1 = (len == 24u);
    if (v1) {
        /* v1 の Querier が居るあいだは v1 で喋る(RFC 3810 8.2.1)。 */
        s_mld_v1_until = timer_now() + (uint64_t)MLD_V1_COMPAT_MS * 1000000ull;
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
}

/*=================================================================
 * Prefix Information オプション 1 個から SLAAC のアドレスを組む
 * (RFC 4862 5.5.3)。プレフィックス上位 64bit + 自分の EUI-64。
 *
 * 採用しない条件(どれも RFC が明示的に「無視せよ」と言っているもの):
 *   - A(Autonomous)フラグが立っていない
 *   - プレフィックスがリンクローカル(fe80::/64)
 *   - **prefix_len + インターフェース識別子長 != 128**。ここは EUI-64 固定
 *     なので prefix_len が 64 でなければ組めない
 *   - preferred lifetime > valid lifetime(壊れた RA)
 *
 * 引数:
 *   ni  - 設定先インターフェース
 *   opt - オプション先頭(type バイト)。長さは PIO_LEN であることを確認済み
 * コール元:
 *   ipv6_handle_ra()
 * ===============================================================*/
static void ipv6_slaac_apply_prefix(netif_t *ni, const volatile uint8_t *opt)
{
    uint8_t  plen  = opt[PIO_OFF_PREFIX_LEN];
    uint8_t  flags = opt[PIO_OFF_FLAGS];
    uint32_t valid = rd32be(opt + PIO_OFF_VALID);
    uint32_t pref  = rd32be(opt + PIO_OFF_PREFERRED);

    if (!(flags & PIO_FLAG_AUTO)) {
        uart_printf("[IPv6] RA: prefix(/%u)は A フラグ無し -- 自動設定しません\n", plen);
        return;
    }
    if (opt[PIO_OFF_PREFIX] == 0xFEu && (opt[PIO_OFF_PREFIX + 1u] & 0xC0u) == 0x80u) {
        uart_printf("[IPv6] RA: リンクローカルのプレフィックスは無視します\n");
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
    if (valid == 0u) {
        /* 新規アドレスは作らない(RFC 4862 5.5.3 d)。**既にそのプレフィックスで
         * 設定済みの場合も、ここで即座に解除はしない** -- 下の 2 時間ルールと
         * 同じ理由で、valid=0 の RA 1 個でアドレスを消せると DoS になるため。
         * 厳密には残り寿命が 2 時間より長いとき「2 時間へ縮める」のが RFC の
         * 動作だが、ここでは常に無視する(安全側)。 */
        uart_printf("[IPv6] RA: valid lifetime=0 の prefix -- 自動設定しません\n");
        return;
    }

    /* **手動設定(`ip6addr`)は RA で潰さない。** ルータの言うことより運用者の
     * 設定を優先する(routetest / pmtutest が名乗らせるアドレスを RA が
     * 書き換えると、テストが原因不明で落ちる)。 */
    if (ni->ip6_global_set && !ni->ip6_global_from_ra) {
        uart_printf("[IPv6] RA: %s には手動設定のグローバルアドレスがあるので"
                    "自動設定しません\n", ni->name ? ni->name : "?");
        return;
    }

    uint8_t addr[IPV6_ADDR_LEN];
    uint8_t ll[IPV6_ADDR_LEN];
    ipv6_link_local_addr(ll);
    for (unsigned i = 0; i < 8u; i++)  addr[i] = opt[PIO_OFF_PREFIX + i];
    for (unsigned i = 8u; i < 16u; i++) addr[i] = ll[i];   /* EUI-64 の 64bit */

    int same = ni->ip6_global_set;
    if (same) {
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
            if (ni->ip6_global[i] != addr[i]) { same = 0; break; }
        }
    }

    /* ---- 有効期間の更新(RFC 4862 5.5.3 e の「2 時間ルール」)----
     * 既存アドレスの寿命を **縮める** 方向の RA は、残りが 2 時間以下なら
     * 無視し、それ以外でも 2 時間までしか縮めない。これが無いと、偽の RA を
     * 1 個投げるだけで他人のアドレスを即座に失効させられる。
     * 新規アドレスには適用しない(受け取った値をそのまま使う)。 */
    const uint64_t NS_PER_SEC = 1000000000ull;
    const uint32_t TWO_HOURS  = 2u * 60u * 60u;
    uint64_t now = timer_now();
    uint64_t new_until;

    if (valid == 0xFFFFFFFFu) {
        new_until = 0;              /* 無期限 */
    } else {
        new_until = now + (uint64_t)valid * NS_PER_SEC;
    }
    if (same) {
        uint64_t cur = ni->ip6_global_valid_until;
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

    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) ni->ip6_global[i] = addr[i];
    ni->ip6_global_set         = 1;
    ni->ip6_global_from_ra     = 1;
    ni->ip6_prefix_len         = plen;
    ni->ip6_global_valid_until = new_until;
    if (!same) {
        /* **DAD はここでは実行しない。** この関数は受信ポーリングの中から
         * 呼ばれているので、ipv6_dad() の内側の net_poll_all_and_dispatch()
         * が再入することになる(arp_resolve() で同じ形の連鎖を踏んでいる)。
         * 冷たい経路である ipv6_slaac_solicit() が RA 処理の後に実行する。 */
        ni->ip6_global_dad = NETIF_DAD_UNKNOWN;
        /* **新しいアドレスは新しい要請ノードマルチキャストへの参加**なので、
         * MLD で報告しないとスヌーピングするスイッチがそのグループを転送して
         * くれない(= 誰もこのアドレスへ NS を届けられない)。 */
        ipv6_mld_report_all(ni);
        uart_printf("[IPv6] SLAAC: %s に ", ni->name ? ni->name : "?");
        for (unsigned j = 0; j < 8u; j++) {
            uart_printf("%s%02x%02x", (j ? ":" : ""), addr[j * 2u], addr[j * 2u + 1u]);
        }
        uart_printf("/%u を設定(valid=%us preferred=%us)\n",
                    plen, (unsigned)valid, (unsigned)pref);
    }
}

/*=================================================================
 * Router Advertisement(type 134)を処理する。RFC 4861 6.3.4 / 4862 5.5.3。
 *
 * ここでやること:
 *   - デフォルトルータの登録/削除(Router Lifetime)
 *   - Source Link-Layer Address オプションからルータの MAC を学習
 *   - Prefix Information オプションから SLAAC でグローバルアドレスを作る
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
    /* **RA の送信元はリンクローカルでなければならない**(RFC 4861 6.1.2)。
     * グローバルアドレスから来た RA を受けると、リンク外のノードが経路と
     * プレフィックスを注入できてしまう。 */
    if (!(src[0] == 0xFEu && (src[1] & 0xC0u) == 0x80u)) {
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
    /* reachable time / retrans timer は**採用しない**。近隣キャッシュの TTL は
     * 全インターフェース共通の g_neigh_cache_ttl_ms で、`arpage`/`arptest` が
     * 前提にしている値でもある。ルータの言い値で勝手に変わると、検証中に
     * 「なぜか TTL が違う」という追いにくい形で出る。 */

    /* ---- デフォルトルータ ---- */
    if (ni->gateway6_set && !ni->gateway6_from_ra) {
        uart_printf("[IPv6] RA: %s には手動設定のゲートウェイがあるので"
                    "RA のルータは採用しません\n", ni->name ? ni->name : "?");
    } else if (rlife == 0u) {
        /* 寿命 0 は「自分をデフォルトルータから外せ」の意味(RFC 4861 6.3.4)。
         * 登録しているのがこのルータのときだけ外す。 */
        int same = ni->gateway6_set;
        for (unsigned i = 0; same && i < IPV6_ADDR_LEN; i++) {
            if (ni->gateway6[i] != src[i]) same = 0;
        }
        if (same) {
            ni->gateway6_set        = 0;
            ni->gateway6_from_ra    = 0;
            ni->gateway6_valid_until = 0;
            uart_printf("[IPv6] RA: router_lifetime=0 -- デフォルトルータから外しました\n");
        }
    } else {
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) ni->gateway6[i] = src[i];
        ni->gateway6_set         = 1;
        ni->gateway6_from_ra     = 1;
        ni->gateway6_valid_until = timer_now() + (uint64_t)rlife * 1000000000ull;
        uart_printf("[IPv6] RA: デフォルトルータを fe80::...%02x%02x に設定(%us)\n",
                    src[14], src[15], rlife);
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
            ndp_cache_insert(src, opt_mac[core]);
        } else if (t == NDP_OPT_PREFIX_INFO) {
            if (olen != PIO_LEN) {
                uart_printf("[IPv6] RA: Prefix Information の長さが %u -- 無視\n",
                            (unsigned)olen);
            } else {
                ipv6_slaac_apply_prefix(ni, in + off);
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

    s_slaac_ra_if = ni;
    s_slaac_ra_seen++;
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
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static void ipv6_handle_icmpv6(const uint8_t *msg, size_t len,
                                const uint8_t src[IPV6_ADDR_LEN],
                                const uint8_t dst[IPV6_ADDR_LEN],
                                uint8_t hop_limit, uint8_t router_alert,
                                const uint8_t *src_mac)
{
    if (len < 8u) {
        uart_printf("[IPv6] ICMPv6 長不足 (len=%u)\n", (unsigned)len);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = msg;
    uint8_t type = in[ICMPV6_OFF_TYPE];

    /* **NDP のメッセージは hop limit が 255 でなければ捨てる**(RFC 4861 6.1)。
     * ルータは転送のたびに hop limit を減らすので、255 で届いたということは
     * 同一リンク上から来たということ。この検査が無いと、リンク外のノードが
     * RA を送り込んでデフォルトルータとプレフィックスを乗っ取れる。
     * 自作側の送信は ipv6_send_from() が常に 255 を書いているので影響しない。 */
    if ((type == ICMPV6_TYPE_RS || type == ICMPV6_TYPE_RA ||
         type == ICMPV6_TYPE_NS || type == ICMPV6_TYPE_NA) && hop_limit != 255u) {
        uart_printf("[IPv6] NDP(type=%u)の hop limit が %u -- 破棄(255 必須)\n",
                    type, hop_limit);
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
    static uint8_t out[SMP_MAX_CORES][NET_BUF_SIZE];

    if (type == ICMPV6_TYPE_ECHO_REQUEST) {
        if (len > NET_BUF_SIZE) {
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

        /* 自分が DAD 中で、同じアドレスを相手も検査していたら衝突
         * (同時 DAD、RFC 4862 5.4.5)。target が自分のものかを見る前に
         * 判定する -- `dadtest` が自分以外のアドレスを検査することもある。 */
        if (src_unspec && s_dad_active && !dad_mac_is_prober(src_mac) &&
            ipv6_addr_eq(s_dad_target, in + 8u + NDP_OFF_TARGET)) {
            for (unsigned i = 0; i < ETH_ALEN; i++) s_dad_conflict_mac[i] = src_mac[i];
            s_dad_conflict = 1;
        }

        /* 要請対象が自分のアドレス(リンクローカル or グローバル)でなければ無視 */
        uint8_t ll[IPV6_ADDR_LEN];
        ipv6_link_local_addr(ll);
        int target_is_ours = ipv6_addr_eq(ll, in + 8u + NDP_OFF_TARGET);
        if (!target_is_ours) {
            uint8_t gg[IPV6_ADDR_LEN];
            if (ipv6_global_addr(gg)) {
                target_is_ours = ipv6_addr_eq(gg, in + 8u + NDP_OFF_TARGET);
            }
        }
        if (!target_is_ours) return;
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

        /* 相手を近隣キャッシュへ入れておく。Source Link-Layer Address
         * オプションがあればそれを使う(無ければ Ethernet の送信元 MAC)。
         * これで「NS を受けた側」も相手の MAC を学習でき、以後の応答で
         * こちらから NS を撃ち直さずに済む。**DAD の NS(送信元 ::)からは
         * 学習してはいけない** -- :: は正当な送信元アドレスではない。 */
        if (!src_unspec) {
            const uint8_t *learn_mac = src_mac;
            if (len >= 8u + NDP_BODY_LEN + 8u && in[8u + NDP_BODY_LEN] == NDP_OPT_SRC_LLADDR) {
                static uint8_t opt_mac[SMP_MAX_CORES][ETH_ALEN];
                for (unsigned i = 0; i < ETH_ALEN; i++) {
                    opt_mac[core][i] = in[8u + NDP_BODY_LEN + 2u + i];
                }
                learn_mac = opt_mac[core];
            }
            ndp_cache_insert(src, learn_mac);
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

    if (type == ICMPV6_TYPE_PACKET_TOO_BIG) {
        /* IPv4 の Fragmentation Needed に相当。**MTU は 4-7 バイトの 32bit 全体**
         * (IPv4 は未使用 4 バイトの下位 16bit だけ。layout が違う)。
         * IPv6 は経路上で分割しないので、これを処理しないと MTU の小さい経路で
         * 通信が完全に成立しない。 */
        if (len < 8u + IPV6_HDR_LEN) {
            uart_printf("[IPv6] Packet Too Big だが引用が短い (len=%u) 無視\n", (unsigned)len);
            return;
        }
        uint32_t mtu = rd32be(in + 4u);

        /* 学習する宛先は「引用された元パケットの宛先」。ICMPv6 の送信元
         * (= 文句を言ってきたルータ)ではない。 */
        uint8_t orig_dst[IPV6_ADDR_LEN];
        for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
            orig_dst[i] = in[8u + offsetof(ipv6_header_t, dst) + i];
        }
        uart_printf("[IPv6] Packet Too Big 受信 (MTU=%u) -- 対象の宛先 ...%02x%02x:%02x%02x\n",
                    (unsigned)mtu, orig_dst[12], orig_dst[13], orig_dst[14], orig_dst[15]);

        netaddr_t dst = netaddr_v6(orig_dst);
        pmtu_learn(&dst, mtu);
        return;
    }

    if (type == ICMPV6_TYPE_TIME_EXCEEDED) {
        /* **送る側は実装しない**(このスタックは転送しない)。受けた側は経路
         * 異常の手掛かりになるので記録する。 */
        uart_printf("[IPv6] Time Exceeded 受信 (code=%u: %s)\n", in[ICMPV6_OFF_CODE],
                    (in[ICMPV6_OFF_CODE] == 0u) ? "転送中に hop limit が 0 になった"
                                                : "断片の再構成がタイムアウト");
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
        /* **フラグを見てから更新する**(RFC 4861 7.2.5)。S=1 のときだけ到達確認
         * として延命し、O=0 で既存と違う MAC を主張する NA は無視する。
         * フラグは本文先頭の 32bit の上位 3 ビット(bit31=R bit30=S bit29=O)。 */
        uint8_t na_flags = in[NDP_OFF_FLAGS];
        ndp_cache_update_na(target, mac,
                            (na_flags & 0x40u) ? 1 : 0,   /* S: Solicited */
                            (na_flags & 0x20u) ? 1 : 0);  /* O: Override */
        return;
    }
    uart_printf("[IPv6] 未対応の ICMPv6 type=%u 無視\n", type);
}

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
 * 引数:
 *   in           - IPv6 ヘッダ先頭
 *   total        - in から使える長さ
 *   nh_io        - 入出力。入力は IPv6 ヘッダの next header、出力は上位プロトコル
 *   off_io       - 入出力。入力は IPV6_HDR_LEN、出力は上位プロトコルの先頭
 *   router_alert - 出力。Hop-by-Hop に Router Alert があれば 1
 * 戻り値:
 *   1=上位プロトコルまで到達した、0=これ以上進めない(破棄する)
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static int ipv6_skip_ext_headers(const volatile uint8_t *in, size_t total,
                                  uint8_t *nh_io, size_t *off_io, uint8_t *router_alert)
{
    uint8_t nh  = *nh_io;
    size_t  off = *off_io;
    *router_alert = 0;

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
             * に組み立てさせ、完成したバッファで上位へ入り直させる。 */
            if (off + IPV6_FRAG_HDR_LEN > total) {
                uart_printf("[IPv6] Fragment ヘッダが途中で切れている -- 破棄\n");
                return 0;
            }
            *nh_io = IPV6_NH_FRAGMENT;
            *off_io = off;
            return 1;
        }
        if (nh != IPV6_NH_HOPOPTS && nh != IPV6_NH_ROUTING && nh != IPV6_NH_DSTOPTS) {
            uart_printf("[IPv6] 未対応の next_header=%u 無視\n", nh);
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
         * **未知の routing type として破棄する**(このスタックは転送しない)。
         * 一律に読み飛ばすと、RFC 5095 で廃止された Routing Type 0 を
         * 使った経路指定を受け入れることになる。 */
        if (nh == IPV6_NH_ROUTING) {
            if (off + 4u > total) {
                uart_printf("[IPv6] Routing ヘッダが途中で切れている -- 破棄\n");
                return 0;
            }
            uint8_t rtype    = in[off + 2u];
            uint8_t segleft  = in[off + 3u];
            if (segleft != 0u) {
                uart_printf("[IPv6] Routing ヘッダ(type=%u segments_left=%u)-- "
                            "転送しないので破棄\n", rtype, segleft);
                return 0;
            }
        }

        /* Hop-by-Hop / Destination Options の TLV を走査する。
         * **PAD1(type 0)だけは長さフィールドを持たない 1 バイト**なので、
         * 一律に {type,len} で読むとずれる。
         * **未知のオプションの扱いは type の上位 2 ビットが決める**
         * (RFC 8200 4.2)。00 以外は破棄する。 */
        if (nh == IPV6_NH_HOPOPTS || nh == IPV6_NH_DSTOPTS) {
            size_t p = off + 2u;
            while (p < off + hlen) {
                uint8_t t = in[p];
                if (t == IPV6_TLV_PAD1) { p++; continue; }
                if (p + 2u > off + hlen) break;
                size_t olen = in[p + 1u];
                if (t == IPV6_TLV_ROUTER_ALERT && nh == IPV6_NH_HOPOPTS) {
                    *router_alert = 1;
                } else if (t != IPV6_TLV_PADN &&
                           (t & IPV6_TLV_ACT_MASK) != IPV6_TLV_ACT_SKIP) {
                    uart_printf("[IPv6] 未知のオプション type=0x%02x(上位 2bit が"
                                "「破棄」を指示)-- パケットを破棄\n", t);
                    return 0;
                }
                p += 2u + olen;
            }
        }

        nh  = next;
        off += hlen;
    }
    uart_printf("[IPv6] 拡張ヘッダが 8 段を超えた -- 破棄\n");
    return 0;
}

/*=================================================================
 * 受信 IPv6 フレームを検証して上位へ渡す。IPv6 ヘッダにチェックサムは無い。
 * 拡張ヘッダが付いていればチェーンを辿ってから上位プロトコルへ渡す。
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

    uint8_t src[IPV6_ADDR_LEN], dst[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        src[i] = in[offsetof(ipv6_header_t, src) + i];
        dst[i] = in[offsetof(ipv6_header_t, dst) + i];
    }
    if (!ipv6_addr_is_ours(dst)) {
        return;
    }

    /* 拡張ヘッダを飛ばして上位プロトコルの位置を求める。**上位プロトコルの
     * 長さは payload_length から拡張ヘッダぶんを引いた値**になる(TCP/UDP の
     * チェックサム検証がこの長さを使うので、引き忘れると全部壊れる)。 */
    size_t  off = IPV6_HDR_LEN;
    uint8_t router_alert = 0;
    if (!ipv6_skip_ext_headers(in, (size_t)plen + IPV6_HDR_LEN, &nh, &off, &router_alert)) {
        return;
    }
    const uint8_t *body = payload + off;
    uint16_t body_len = (uint16_t)((size_t)plen + IPV6_HDR_LEN - off);

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
        uint32_t flen = (uint32_t)((size_t)plen + IPV6_HDR_LEN - off - IPV6_FRAG_HDR_LEN);

        /* 観測フックは残してある(`ext6test` が断片単位で形を確かめる)。
         * 組み立てを実装した今は素通しの覗き見。 */
        if (s_ipv6_frag_observer) {
            s_ipv6_frag_observer(fid, (uint16_t)foff, more, fnh, fdata, (uint16_t)flen);
        }

        netaddr_t fs = netaddr_v6(src);
        netaddr_t fd = netaddr_v6(dst);
        const uint8_t *whole = NULL;
        uint32_t whole_len = 0;
        if (!ipfrag_input(&fs, &fd, fid, fnh, foff, more, fdata, flen,
                          &whole, &whole_len)) {
            return;  /* まだそろっていない */
        }
        nh       = fnh;
        body     = whole;
        body_len = (uint16_t)whole_len;
    }

    if (nh == IPV6_NH_ICMPV6) {
        ipv6_handle_icmpv6(body, body_len, src, dst,
                           in[offsetof(ipv6_header_t, hop_limit)], router_alert, src_mac);
    } else if (nh == IPV6_NH_TCP) {
        netaddr_t s = netaddr_v6(src);
        netaddr_t d = netaddr_v6(dst);
        tcp_input_addr(body, body_len, &s, &d);
    } else if (nh == IPV6_NH_UDP) {
        netaddr_t s = netaddr_v6(src);
        netaddr_t d = netaddr_v6(dst);
        udp_input_addr(body, body_len, &s, &d, src_mac);
        /* 待ち受けが無くても ICMPv6 Destination Unreachable は返さない
         * (IPv4 側と違い、RoCEv2 の複製フレームのような自分宛の大量の
         * 「宛先無し」がまだ観測されていないので、送る動機が無い)。 */
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

    unsigned core = smp_core_index();
    if (core >= SMP_MAX_CORES) core = 0;
    const uint32_t id = ++s_ipv6_frag_id[core];   /* 全断片で共通 */
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
        h[offsetof(ipv6_header_t, hop_limit)]   = 255u;
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
    h[offsetof(ipv6_header_t, hop_limit)]   = 255u;  /* NDP は 255 必須、それ以外も無害 */
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) {
        h[offsetof(ipv6_header_t, src) + i] = src[i];
        h[offsetof(ipv6_header_t, dst) + i] = dst[i];
    }
    for (uint16_t i = 0; i < payload_len; i++) {
        out[ETH_HDR_LEN + IPV6_HDR_LEN + i] = payload[i];
    }

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
