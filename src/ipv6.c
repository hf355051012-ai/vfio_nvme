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

#define NDP_OPT_SRC_LLADDR 1u
#define NDP_OPT_TGT_LLADDR 2u

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
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) out[i] = ni->ip6_global[i];
    return 1;
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
int ndp_cache_lookup(const uint8_t addr[IPV6_ADDR_LEN], uint8_t out_mac[ETH_ALEN])
{
    ndp_cache_entry_t *cache = g_active_ctx->ndp_cache;
    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) {
        if (!cache[i].valid) continue;
        int same = 1;
        for (unsigned j = 0; j < IPV6_ADDR_LEN; j++) {
            if (cache[i].addr[j] != addr[j]) { same = 0; break; }
        }
        if (!same) continue;

        /* 時刻の読み出しは照合が当たったときだけ(1 回)。 */
        int age = neigh_check_age(timer_now(), cache[i].expires_at, &cache[i].probe_at);
        if (age == NEIGH_DEAD) {
            cache[i].valid = 0;
            return -1;
        }
        for (unsigned j = 0; j < ETH_ALEN; j++) out_mac[j] = cache[i].mac[j];
        if (age == NEIGH_STALE_PROBE) {
            ndp_send_ns(addr);  /* NA が返れば ndp_cache_insert() が延命する */
        }
        return 0;
    }
    return -1;
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
static int ndp_send_ns(const uint8_t target[IPV6_ADDR_LEN])
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

    /* 要請ノードマルチキャスト ff02::1:ffXX:XXXX */
    uint8_t sol[IPV6_ADDR_LEN];
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) sol[i] = 0;
    sol[0] = 0xFF; sol[1] = 0x02; sol[11] = 0x01; sol[12] = 0xFF;
    sol[13] = target[13]; sol[14] = target[14]; sol[15] = target[15];

    const uint8_t dst_mac[ETH_ALEN] = { 0x33, 0x33, 0xFF,
                                        target[13], target[14], target[15] };

    return ipv6_send_icmpv6(sol, dst_mac, m, (uint16_t)(8u + NDP_BODY_LEN + 8u));
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
    for (unsigned i = 0; i < IPV6_ADDR_LEN; i++) sol[i] = 0;
    sol[0] = 0xFF; sol[1] = 0x02; sol[11] = 0x01; sol[12] = 0xFF;
    sol[13] = target[13]; sol[14] = target[14]; sol[15] = target[15];

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
 * 受信 ICMPv6 を処理する。Echo Request には Echo Reply、Neighbor
 * Solicitation には Neighbor Advertisement を返す(NA を返さないと相手は
 * こちらの MAC を解決できず、IPv6 通信が一切成立しない)。
 *
 * 引数:
 *   msg / len - ICMPv6 メッセージ本体
 *   src / dst - IPv6 ヘッダの送信元・宛先
 *   src_mac   - 送信元 MAC(応答の宛先に使う)
 * コール元:
 *   ipv6_handle_frame()
 * ===============================================================*/
static void ipv6_handle_icmpv6(const uint8_t *msg, size_t len,
                                const uint8_t src[IPV6_ADDR_LEN],
                                const uint8_t dst[IPV6_ADDR_LEN],
                                const uint8_t *src_mac)
{
    if (len < 8u) {
        uart_printf("[IPv6] ICMPv6 長不足 (len=%u)\n", (unsigned)len);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = msg;
    uint8_t type = in[ICMPV6_OFF_TYPE];

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
        ndp_cache_insert(target, mac);
        return;
    }
    uart_printf("[IPv6] 未対応の ICMPv6 type=%u 無視\n", type);
}

/*=================================================================
 * 受信 IPv6 フレームを検証して上位へ渡す。IPv6 ヘッダにチェックサムは無く、
 * 拡張ヘッダも未対応なので next_header をそのまま見る。
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

    const uint8_t *body = payload + IPV6_HDR_LEN;
    if (nh == IPV6_NH_ICMPV6) {
        ipv6_handle_icmpv6(body, plen, src, dst, src_mac);
    } else if (nh == IPV6_NH_TCP) {
        netaddr_t s = netaddr_v6(src);
        netaddr_t d = netaddr_v6(dst);
        tcp_input_addr(body, plen, &s, &d);
    } else if (nh == IPV6_NH_UDP) {
        netaddr_t s = netaddr_v6(src);
        netaddr_t d = netaddr_v6(dst);
        udp_input_addr(body, plen, &s, &d, src_mac);
        /* 待ち受けが無くても ICMPv6 Destination Unreachable は返さない
         * (IPv4 側と違い、RoCEv2 の複製フレームのような自分宛の大量の
         * 「宛先無し」がまだ観測されていないので、送る動機が無い)。 */
    } else {
        uart_printf("[IPv6] 未対応の next_header=%u 無視\n", nh);
    }
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
