#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>
#include "netif.h"
#if defined(__x86_64__)
#include <string.h>   /* volatile_fast_copy() の x86 高速パス(glibc memcpy) */
#endif

/* ================================================================
 * net.h — バイトオーダー変換ヘルパ + 自機IPv4アドレス設定
 *
 * AArch64はリトルエンディアンだが、ネットワークプロトコル
 * (ARP/IP/TCP等)はビッグエンディアン(ネットワークバイトオーダー)。
 * htons/htonl/ntohs/ntohl相当のヘルパをここに集約し、フェーズ2以降の
 * 全プロトコル実装で共用する。
 * ================================================================ */

static inline uint16_t htons(uint16_t x)
{
    return (uint16_t)((x << 8) | (x >> 8));
}
static inline uint16_t ntohs(uint16_t x) { return htons(x); }

static inline uint32_t htonl(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8)  |
           ((x & 0x00FF0000u) >> 8)  |
           ((x & 0xFF000000u) >> 24);
}
static inline uint32_t ntohl(uint32_t x) { return htonl(x); }

/* ------------------------------------------------------------------ */
/* 自機IPv4アドレス                                                    */
/* ------------------------------------------------------------------ */
/*
 * 以前はここが唯一のコンパイル時固定値だったが、ConnectX統合
 * (RP1に加えmlx5の複数ポートを同一プログラム内で並行運用する、
 * netif.h参照)に伴い、「自機IP」は実行時にアクティブなインター
 * フェース(netif_t)ごとに異なりうる値へ変わった。
 *
 * NET_SELF_IP_A〜Dは、eth_init()(RP1バックエンド)がnetif_tを
 * 作る際の既定IPとしてのみ使う(下記NET_RP1_DEFAULT_IP)。ConnectX側
 * (mlx5_net.c)は別のIPをnetif_t.ipへ直接設定する。
 *
 * NET_SELF_IPマクロ自体はnet_active_ip()(netif.h、g_active_ctx->ipを
 * 読むだけ)を指すよう変更した -- arp.c/ip.c/tcp.c等の既存の参照側は
 * ソース上一切変更していない(マクロ定義を変えるだけで透過的に対応)。
 */

#define NET_SELF_IP_A 192u
#define NET_SELF_IP_B 168u
#define NET_SELF_IP_C 100u
#define NET_SELF_IP_D 2u

/* ホストバイトオーダーの32bit表現 (0xC0A86402 = 192.168.100.2)。
 * RP1バックエンドの既定IP。 */
#define NET_RP1_DEFAULT_IP  (((uint32_t)NET_SELF_IP_A << 24) | \
                             ((uint32_t)NET_SELF_IP_B << 16) | \
                             ((uint32_t)NET_SELF_IP_C << 8)  | \
                              (uint32_t)NET_SELF_IP_D)

/* コア1向けtelnetセッション(command.c/telnet.h参照)用のRP1別名IP
 * (netif.hのnetif_register_alias()参照)。下1桁だけNET_RP1_DEFAULT_IP
 * と異なる値にすることで、コア0向け/コア1向けのセッションをIPアドレス
 * だけでも区別できるようにする(ユーザー指示)。物理NIC自体はRP1
 * 1枚のままで、実ハードウェアのポーリング/送信は引き続きowner_core
 * (RP1を登録したコア)だけが行う。
 *
 * 【2026-08-08、実機で本物のバグとして確認】当初+1(192.168.100.3)を
 * 使っていたが、これがユーザーのPC自身のLAN上の実IPアドレスと衝突し、
 * ARPが混乱してLANセグメント全体(pingすら)が一時的に無応答になる障害を
 * 実機で確認した(このLANでは192.168.100.2/.3が既存の機器で使用中、
 * ユーザー確認により.4以降が未使用と判明)。+2(192.168.100.4)へ変更。
 * 今後この値を変える場合は、必ず対象LANで実際に未使用のアドレスか
 * ユーザーに確認してから決めること -- ボード側だけの都合で自由に
 * 選んでよい値ではない(このプロジェクトが動く環境は実LANに接続される
 * ことが前提のため)。 */
#define NET_RP1_CORE1_IP    (NET_RP1_DEFAULT_IP + 2u)

/* 現在アクティブなインターフェース(netif.h)の自機IPv4。 */
#define NET_SELF_IP  (net_active_ip())

/* オクテット4個 -> ホストバイトオーダーの32bit値 */
static inline uint32_t ip_from_octets(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

/* ホストバイトオーダーの32bit値 -> オクテット4個 (octets[0]が最上位) */
static inline void ip_to_octets(uint32_t ip, uint8_t octets[4])
{
    octets[0] = (uint8_t)(ip >> 24);
    octets[1] = (uint8_t)(ip >> 16);
    octets[2] = (uint8_t)(ip >> 8);
    octets[3] = (uint8_t)ip;
}

/* ------------------------------------------------------------------ */
/* バイト単位ビッグエンディアン読み書きヘルパ                            */
/* ------------------------------------------------------------------ */
/*
 * この環境はMMU無効(SCTLR_EL1.M=0)のため全メモリがDeviceメモリ相当
 * となり、アラインされていない多バイトアクセスは即Alignment fault
 * (Data Abort, DFSC=0x21)になる。ARP/IP/TCP等のプロトコルヘッダの
 * 多バイトフィールドは、Ethernetヘッダ(14)やRSB(64B)+2byteパッド等の
 * 影響でnet_buf.data内の絶対オフセットが4/8バイト境界に一致するとは
 * 限らない(例: ARPのIPフィールドはフレーム先頭から28バイト目)。
 *
 * さらに厄介なことに、素の uint8_t 配列を手でシフト/ORして数値を
 * 組み立てる書き方(例: (p[0]<<24)|(p[1]<<16)|...)や、固定長ループでの
 * バイト単位コピーであっても、-O2最適化でコンパイラが複数の隣接バイト
 * アクセスを1回のワイドロード/ストアへ結合してしまうことがある
 * (ethwireのアライメントフォルト、および本ARP受信処理のアライメント
 * フォルトの両方でこれが実際の原因だった)。
 *
 * 下記ヘルパは volatile 経由でバイト単位アクセスを強制するため、
 * コンパイラによる結合が起こらず、アライメントにもバイトオーダーにも
 * 依存しない。ARP/IP/ICMP/TCP等、プロトコルヘッダの多バイトフィールド
 * (2バイト以上)へは直接 uint16_t/uint32_t アクセスを行わず、
 * 必ずこれらのヘルパのみを使うこと。
 * (1バイト単体の読み書きは元々アライメント非依存なので対象外)
 */

static inline uint16_t rd16be(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

static inline uint32_t rd32be(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
}

static inline void wr16be(volatile void *p, uint16_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}

static inline void wr32be(volatile void *p, uint32_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

/* ------------------------------------------------------------------ */
/* リトルエンディアン読み書きヘルパ (NVMe/NVMe-TCP用)                    */
/* ------------------------------------------------------------------ */
/*
 * ARP/IP/TCP等と異なり、NVMe仕様のワイヤ/メモリ上フィールド(SQE/CQE/
 * SGLディスクリプタ、NVMe/TCP PDUヘッダ等)は全てリトルエンディアン
 * (AArch64のネイティブバイトオーダーと同じ)。だがrd16be/rd32be等と
 * 同じ理由(packed構造体への直接多バイトアクセスを禁止し、常にvolatile
 * 経由のバイト単位アクセスへ強制する -- コンパイラが-O2で隣接フィールド
 * アクセスを1回のワイドロード/ストアへ結合するのを防ぐ、このファイル
 * 冒頭コメント参照)で、NVMe関連の多バイトフィールドも直接アクセスせず
 * 必ずこれらのヘルパ経由でアクセスすること。
 */

static inline uint16_t rd16le(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}

static inline uint32_t rd32le(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline uint64_t rd64le(const volatile void *p)
{
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint64_t)b[0]       | ((uint64_t)b[1] << 8)  |
           ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
           ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
           ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static inline void wr16le(volatile void *p, uint16_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}

static inline void wr32le(volatile void *p, uint32_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

static inline void wr64le(volatile void *p, uint64_t v)
{
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    b[4] = (uint8_t)(v >> 32);
    b[5] = (uint8_t)(v >> 40);
    b[6] = (uint8_t)(v >> 48);
    b[7] = (uint8_t)(v >> 56);
}

/* ------------------------------------------------------------------ */
/* アライメント適応コピー(MMU無効環境でのバイト単位コピー高速化)         */
/* ------------------------------------------------------------------ */
/*
 * non-Gathering(このファイル冒頭コメント参照)が禁止するのは「複数の
 * 別々のアクセスをハードウェア/コンパイラが自動的に1つへ結合すること」
 * であって、「1個の命令で複数バイトをロード/ストアすること」自体は
 * 禁止しない。つまりuint64_t/uint32_t単位のvolatileアクセスは、8/4バイト
 * 境界に整列している限り、依然として単一のDevice-nGnRnEトランザクション
 * として正しく完結する(非キャッシュ・順序保証ありという性質は変わらない
 * ままバイト単位より最大8倍広い転送になる)。
 *
 * これまでバイト単位に統一してきたのはDevice-nGnRnEそのものが理由では
 * なく、循環バッファの折り返しや任意オフセットでアライメントを保証
 * できなかったため安全側に倒していただけ(net.hの元のコメント参照)。
 * 実行時にdst/srcの実アドレスを見て、両方が同じ境界に整列している場合
 * のみワイドアクセスを使い、整列していなければ従来通りバイト単位へ
 * フォールバックする — 未整列アクセスはDevice-nGnRnEで即Alignment fault
 * (Data Abort, DFSC=0x21)になるため、この判定を誤ってはならない。
 */
static inline void volatile_fast_copy(volatile void *dst, const volatile void *src, size_t len)
{
#if defined(__x86_64__)
    /* 【2026-08-15、x86ポートのHWネック追い込み】x86-linuxポートはlibcを
     * リンクしたホストプロセスなので、glibcの最適化memcpy(CPU機能に応じて
     * ERMS[rep movsb]/AVX/非一時ストアを自動選択、実効メモリ帯域に近い)を
     * 使う。ARMのようなアラインメントフォルトが無く、下のvolatileは
     * コード生成上の保険に過ぎない(このハードでは不要)ためキャストして
     * 通常コピーに委ねる。
     *
     * 背景: NVMe/TCP read受信で「RQバッファ→NVMe宛先」への配置コピーが
     * per-frameコストの約72%(~936ns/9KB)を占め、従来の下記scalar 8バイト
     * volatileループ(x86実測~9.77GB/s)はx86のscalarストアスループットで
     * 頭打ちだった(net_buf_alloc/CQドアベル等のper-frame固定コストは合計でも
     * ~3%と実測で確認済み、真の律速はこのコピー)。memcpyはx86の実効帯域
     * (20〜40GB/s級)まで引き上げる。
     *
     * ARM/rpi5(aarch64、__x86_64__非定義)は下の#elseで従来通りのscalar
     * ループを使う -- このハードでは実効メモリ帯域律速で3案とも不発だった
     * 経緯があり(下記コメント参照)、変更しない。rpi5イメージはこの
     * #ifガードによりbyte-identicalを維持する。 */
    memcpy((void *)(uintptr_t)dst, (const void *)(uintptr_t)src, len);
    return;
#else
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;
    size_t i = 0;

    /* 【2026-08-11、ユーザー指摘を受け実測(ts_log)で3案を検証、いずれも
     * 有意な改善なしと確定 -- 元のシンプルな実装のまま維持する】
     * 基準値: 262144バイトの単発コピーが約88-89us(約2.9GB/s)。
     * (1) ループ制御(比較・分岐)を4回分(32バイト)手展開 -- 実機再計測で
     *     全く効果なし(同じ約88-89us)。ボトルネックはループ制御では
     *     ないと判明。
     * (2) NEON(128bitのQレジスタ、ldp/stp q、実機でCPTR_EL2.TFP=0=
     *     FP/SIMDはEL2でトラップされないことを確認済み、有効化コード
     *     不要)で1命令16バイト・4本展開 -- 実機再計測で約102-104usへ
     *     "悪化"した。
     * (3) dstへの通常cacheableストアがwrite-allocateミス(書き込み前に
     *     古い内容をDRAMから読む)を起こしている可能性を疑い、非一時
     *     (non-temporal)ストア`stnp`(NEON、キャッシュ割り当てを避ける)
     *     を試したが、約86us(誤差範囲、有意差なし)。
     * 3案とも改善が見られなかったことから、このコピーは命令幅/ループ
     * オーバーヘッド/write-allocateのいずれでもなく、このハードウェアの
     * 実効メモリ帯域そのもので頭打ちになっていると判断し、単純さを
     * 優先してシンプルな8バイト単位の実装のまま据え置く。今後同種の
     * 高速化を試す際は、この3案が既に不発だったことを踏まえること。 */
    if ((((uintptr_t)d | (uintptr_t)s) & 7u) == 0) {
        for (; i + 8 <= len; i += 8)
            *(volatile uint64_t *)(d + i) = *(const volatile uint64_t *)(s + i);
    } else if ((((uintptr_t)d | (uintptr_t)s) & 3u) == 0) {
        for (; i + 4 <= len; i += 4)
            *(volatile uint32_t *)(d + i) = *(const volatile uint32_t *)(s + i);
    } else if ((((uintptr_t)d | (uintptr_t)s) & 1u) == 0) {
        for (; i + 2 <= len; i += 2)
            *(volatile uint16_t *)(d + i) = *(const volatile uint16_t *)(s + i);
    }

    for (; i < len; i++)
        d[i] = s[i];
#endif /* __x86_64__ */
}

/* 【2026-08-11、ユーザー提案「volatileではなくmemcpyでは」を受け実機
 * 検証(撤回済み)】volatile_fast_copy()の非volatile版(fast_copy()、
 * dst/srcがNormal cacheable RAMであることが確認できる場合はvolatile
 * 自体は不要、tcp.cのtcp_recv_internal()コメント参照)を試作した。
 * 単純なバイト単位ループでは、このプロジェクトのビルド(-O2、-O3では
 * ない)ではGCCのループ自動ベクトル化が既定で無効なため実機で約35分の1
 * (5.5-5.7MB/s)まで悪化し、volatile_fast_copy()と同じ8バイト手動
 * ワイド化をvolatile無しで再現しても実測は元のvolatile版と同水準
 * (有意差なし)だった -- volatile自体はこの経路のボトルネックでは
 * なかったと確認できたため、余分な複雑さ(2つ目のコピーヘルパ)を
 * 持ち込まずvolatile_fast_copy()一本に統一したまま維持している。 */

/* ------------------------------------------------------------------ */
/* インターネットチェックサム (RFC 1071)                                */
/* ------------------------------------------------------------------ */
/*
 * 16bit ones' complement sum の否定。IPヘッダ・ICMP双方で共用する。
 * rd16be等と同じ理由でバイト単位(volatile経由)にアクセスするため、
 * アラインされていないバッファにもそのまま安全に使える。
 *
 * 検証時: チェックサムフィールドを含めた全体を計算し、結果が0であれば
 *         正常(受信データはそのまま渡せばよい、フィールドを触る必要はない)。
 * 計算時: チェックサムフィールド自体を0にしてから呼び出し、
 *         戻り値をチェックサムフィールドへ書き込むこと。
 */
/* dataの内容を16bitワード単位で走査し、実行中の合計sumへ加算した結果を
 * 返す(繰り上がり折り畳みは呼び出し側の最後でまとめて行う)。奇数長の
 * 場合は最後の1バイトを上位バイトとして加算する(RFC1071)。
 * 複数バッファにまたがってチェックサムを計算する場合の内部ヘルパ
 * (pseudo_header_checksum2()参照) — sumへの累積は加算の結合則により
 * バッファをどう分割して呼んでも結果は同じになるが、各バッファの長さが
 * 奇数の場合は次のバッファとの境界で16bitワードの区切りがずれるため、
 * 「奇数長のバッファの直後に別のバッファを続ける」呼び出し方はしない
 * こと(境界をまたぐバイト対応は行わない)。 */
static inline uint32_t checksum_accumulate(uint32_t sum, const volatile void *data, size_t len)
{
    const volatile uint8_t *p = (const volatile uint8_t *)data;
    size_t i = 0;

    /* volatile_fast_copy()と同じ理由(このファイル冒頭コメント参照)で、
     * pが8/4バイト境界に整列している場合はワイドロード1回で4/2ワード
     * (16bitチェックサムワード)分をまとめて処理する。AArch64はリトル
     * エンディアンなのでネイティブロードした値はそのままでは各16bit
     * ワードの意味が逆(バイト順)になるため、__builtin_bswap*で
     * バイトスワップしてから上位/下位16bitずつを取り出す — スワップ後の
     * 値は元のバイト列をビッグエンディアンの64/32bit整数として解釈した
     * ものと一致するため、それを16bitずつに割ればbe単位での加算と
     * 完全に同じ結果になる(結合則によりsumへの累積順序は結果に影響
     * しない)。整列していなければ従来通りバイト単位にフォールバックする。 */
    if (((uintptr_t)p & 7u) == 0) {
        for (; i + 8 <= len; i += 8) {
            uint64_t be = __builtin_bswap64(*(const volatile uint64_t *)(p + i));
            sum += (uint32_t)((be >> 48) & 0xFFFFu);
            sum += (uint32_t)((be >> 32) & 0xFFFFu);
            sum += (uint32_t)((be >> 16) & 0xFFFFu);
            sum += (uint32_t)(be & 0xFFFFu);
        }
    } else if (((uintptr_t)p & 3u) == 0) {
        for (; i + 4 <= len; i += 4) {
            uint32_t be = __builtin_bswap32(*(const volatile uint32_t *)(p + i));
            sum += (be >> 16) & 0xFFFFu;
            sum += be & 0xFFFFu;
        }
    }

    for (; i + 1 < len; i += 2)
        sum += ((uint32_t)p[i] << 8) | (uint32_t)p[i + 1];
    if (i < len)
        sum += ((uint32_t)p[i] << 8);

    return sum;
}

static inline uint16_t inet_checksum(const volatile void *data, size_t len)
{
    uint32_t sum = checksum_accumulate(0, data, len);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

/* ------------------------------------------------------------------ */
/* IPv4疑似ヘッダ込みチェックサム (UDP/TCP共用、フェーズ4/5)             */
/* ------------------------------------------------------------------ */
/*
 * 疑似ヘッダ(12バイト: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) +
 * l4_len(2)) に続けてL4(UDP/TCP)ヘッダ+データを連結してinet_checksumと
 * 同じ処理を行う。大きな連結バッファを都度確保しないよう、疑似ヘッダ分は
 * その場で16bitワード単位の和に加算し、L4部分だけバイト単位でループする。
 *
 * 計算時: l4_data のチェックサムフィールドは0にしてから呼び出し、
 *         戻り値をチェックサムフィールドへ書き込むこと。
 * 検証時: 受信した生のl4_data(チェックサムフィールドも含む)をそのまま
 *         渡す。結果が0であれば正常。
 *
 * src_ip/dst_ip はローカル配列(呼び出し側で抽出済みのIPオクテット列)を
 * 渡す前提だが、念のためvolatile経由でアクセスする。l4_dataはnet_buf等の
 * 生パケットバッファを指すことがあるため const volatile void* を受ける。
 */
static inline uint16_t pseudo_header_checksum(const uint8_t src_ip[4],
                                               const uint8_t dst_ip[4],
                                               uint8_t protocol,
                                               const volatile void *l4_data,
                                               size_t l4_len)
{
    const volatile uint8_t *sip = src_ip;
    const volatile uint8_t *dip = dst_ip;

    uint32_t sum = 0;
    sum += ((uint32_t)sip[0] << 8) | (uint32_t)sip[1];
    sum += ((uint32_t)sip[2] << 8) | (uint32_t)sip[3];
    sum += ((uint32_t)dip[0] << 8) | (uint32_t)dip[1];
    sum += ((uint32_t)dip[2] << 8) | (uint32_t)dip[3];
    sum += (uint32_t)protocol;   /* 上位バイト0 + protocol の16bitワードとして加算 */
    sum += (uint32_t)l4_len;     /* L4長(16bit) */

    sum = checksum_accumulate(sum, l4_data, l4_len);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

/* 2026-08-09、ハードウェアチェックサムオフロード対応。pseudo_header_
 * checksum()からl4_data本体の走査(checksum_accumulate())を省いた、
 * 疑似ヘッダ12バイトのみのチェックサム。Linux net/ipv4のtcp_v4_check()
 * /__tcp_v4_send_check()(include/net/tcp.h、実際に取得して確認済み)が
 * `th->check = ~tcp_v4_check(skb->len, saddr, daddr, base=0)`という、
 * まさにこの「pseudo headerのみ」の値をNIC送信前のチェックサムフィールド
 * へ書き込んでいるのと同じ設計 -- CHECKSUM_PARTIALオフロードでは、
 * ソフトウェアはチェックサムフィールドを0にするのではなく、疑似ヘッダ
 * 分だけを事前計算して書き込んでおき、HW(mlx5のcs_flags=L3_CSUM|
 * L4_CSUM)が実際のヘッダ+ペイロードのチェックサムをこの値を起点に加算
 * 完成させる。l4_len(L4ヘッダ+データの全長)はO(1)で求まる値のため、
 * この関数自体は実際のデータサイズに関わらず一定コスト(実測1us未満、
 * checksum_accumulate()が占めていた9938Bあたり9-12usを丸ごと削減できる
 * -- CLAUDE.md「性能分析基盤の整備」節参照)。 */
static inline uint16_t pseudo_header_checksum_only(const uint8_t src_ip[4],
                                                     const uint8_t dst_ip[4],
                                                     uint8_t protocol,
                                                     size_t l4_len)
{
    const volatile uint8_t *sip = src_ip;
    const volatile uint8_t *dip = dst_ip;

    uint32_t sum = 0;
    sum += ((uint32_t)sip[0] << 8) | (uint32_t)sip[1];
    sum += ((uint32_t)sip[2] << 8) | (uint32_t)sip[3];
    sum += ((uint32_t)dip[0] << 8) | (uint32_t)dip[1];
    sum += ((uint32_t)dip[2] << 8) | (uint32_t)dip[3];
    sum += (uint32_t)protocol;
    sum += (uint32_t)l4_len;

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

/* pseudo_header_checksum()の2バッファ版。l4_data1(l4_len1バイト)に続けて
 * l4_data2(l4_len2バイト)が論理的に連結されたものとして扱い、疑似ヘッダ
 * 込みでチェックサムを計算する。TCPのゼロコピー送信(ヘッダ用の小さな
 * バッファ+呼び出し元のデータバッファ)のように、L4データが物理的に
 * 連続していない2つのバッファにまたがる場合に使う。
 * 制約: l4_len1は偶数であること(checksum_accumulate()参照 — 境界を
 * またぐ奇数バイト対応は行わない)。TCPヘッダ長(オプション込みでも)は
 * 常に4の倍数なのでこの制約は自然に満たされる。 */
static inline uint16_t pseudo_header_checksum2(const uint8_t src_ip[4],
                                                const uint8_t dst_ip[4],
                                                uint8_t protocol,
                                                const volatile void *l4_data1, size_t l4_len1,
                                                const volatile void *l4_data2, size_t l4_len2)
{
    const volatile uint8_t *sip = src_ip;
    const volatile uint8_t *dip = dst_ip;

    uint32_t sum = 0;
    sum += ((uint32_t)sip[0] << 8) | (uint32_t)sip[1];
    sum += ((uint32_t)sip[2] << 8) | (uint32_t)sip[3];
    sum += ((uint32_t)dip[0] << 8) | (uint32_t)dip[1];
    sum += ((uint32_t)dip[2] << 8) | (uint32_t)dip[3];
    sum += (uint32_t)protocol;
    sum += (uint32_t)(l4_len1 + l4_len2);

    sum = checksum_accumulate(sum, l4_data1, l4_len1);
    sum = checksum_accumulate(sum, l4_data2, l4_len2);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

#endif /* NET_H */
