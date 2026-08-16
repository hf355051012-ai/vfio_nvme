#ifndef NETIF_H
#define NETIF_H

#include <stdint.h>
#include <stddef.h>
#include "net_buf.h"
#include "smp.h"

/* ================================================================
 * Ethernet フレーム層(旧 eth.h)。実際の送受信は nic_ops_t 経由で
 * バックエンド(mlx5_net.c)へ委譲し、ここは EtherType ディスパッチと
 * アクティブインターフェースへの振り分けだけを持つ。
 * ================================================================ */

#define ETH_ALEN            6
#define ETH_HDR_LEN         14      /* dst(6) + src(6) + ethertype(2) */
#define ETH_JUMBO_MAX_LEN   10240u  /* ジャンボフレームの最大長(ヘッダ+ペイロード+FCS) */

/* 送信フレームを構成する1個の断片(スキャッタ・ギャザー送信用)。 */
typedef struct {
    const void *data;
    uint16_t    len;
} eth_frag_t;

/* 1回の送信で使える最大断片数。TCP のゼロコピー送信(ヘッダ用の小さな
 * バッファ + 呼び出し元のデータバッファの2断片)を想定した値。 */
#define ETH_TX_MAX_FRAGS 2

/* RX/TX リング段数の既定値。バックエンドが netif_t.rx_ring_size を
 * 設定しない場合の受信ウィンドウ計算のフォールバック(ETH_RX_RING_SIZE)と、
 * tcp.c がスロット別送信バッファを確保する個数(ETH_TX_RING_SIZE)に使う。 */
#define ETH_RX_RING_SIZE 128
#define ETH_TX_RING_SIZE 256

/* 自機の MAC アドレス(アクティブインターフェースのもの)を取得する。 */
void eth_get_mac(uint8_t mac[ETH_ALEN]);

/* Ethernet フレーム(dst+src+ethertype+payload、FCS 抜き)を1つ送信する。
 * nb の所有権は本関数に渡り、成否によらず内部で net_buf_free() される。
 * 戻り値: 0=送信完了, -1=引数エラー/送信失敗 */
int eth_send(net_buf_t *nb);

/* frags[0..frag_count) を連結した1つのフレームとして送信し、ハードウェアの
 * 送信完了まで待つ(戻った時点で全断片のメモリを再利用してよい)。
 * frag_count は 1 以上 ETH_TX_MAX_FRAGS 以下。戻り値: 0=完了, -1=失敗 */
int eth_send_frags(const eth_frag_t *frags, unsigned frag_count);

/* eth_send_frags() と同じキューイングを行うが送信完了を待たずに返る。
 * 信頼性は呼び出し元(TCP の ACK ベース再送)が担保する前提。
 * 戻り値: 0=キューイング成功, -1=失敗 */
int eth_send_frags_async(const eth_frag_t *frags, unsigned frag_count);

/* LSO(TCP Segmentation Offload)送信。hdr(L2+L3+L4)をテンプレートに
 * payload を HW が mss 単位で分割送出する。非対応バックエンドでは常に -1
 * (net_active_lso_max_bytes() で事前に確認すること)。
 * 戻り値: 0=キューイング成功, -1=非対応/失敗 */
int eth_send_lso_async(const void *hdr, uint16_t hdr_len,
                       const void *payload, uint32_t payload_len, uint16_t mss);

/* 次に eth_send_frags_async()(frag_count=1)が使う TX スロット番号を返す。
 * そのスロットの前回のフレームが未完了なら完了までブロックする。呼び出し元は
 * 戻ってから初めて、そのスロット専用の送信バッファへ書き込んでよい。 */
unsigned eth_tx_wait_free_slot(void);

/* 受信を1回ポーリングする(ブロックしない)。フレームがあれば net_buf を
 * 確保して返す(呼び出し側が net_buf_free() する)。無ければ NULL。 */
net_buf_t *eth_poll_recv(void);

/* EtherType 別ハンドラ。登録される具体関数:
 *   0x0806(ARP)  -> arp_handle_frame(arp.c、arp_init() で登録)
 *   0x0800(IPv4) -> ip_handle_frame(ip.c、ip_init() で登録) */
typedef void (*eth_handler_t)(const uint8_t *payload, size_t len, const uint8_t *src_mac);

/* EtherType に対するハンドラを登録する(再登録は上書き、NULL で解除)。 */
void eth_register_handler(uint16_t ethertype, eth_handler_t handler);

/* nb の EtherType に応じて登録済みハンドラを呼ぶ。nb の解放は呼び出し側の責任。 */
void eth_dispatch(net_buf_t *nb);

/* 「今 eth_dispatch() が処理中のフレームは HW で L3/L4 チェックサム検証済みか」。
 * ip.c/tcp.c がソフトウェア再検証をスキップしてよいかの判定に使う。 */
int eth_rx_hw_csum_ok(void);

/* ================================================================
 * netif.h — 複数NIC/複数ネットワークインターフェースの並行運用抽象化
 *
 * 背景: 従来このプロジェクトのarp.c/ip.c/icmp.c/tcp.cは「自機のMAC/IP
 * アドレスはただ1つ、送受信バックエンドもRP1のGEMただ1つ」という前提の
 * グローバル単一インスタンス設計だった。ConnectX(mlx5)統合により、同一
 * プログラム内でRP1に加えConnectXの複数ポート(PF0/PF1)を、それぞれ
 * 別のMAC/IP/ARPキャッシュを持つ独立した「ネットワークインターフェース」
 * として扱う必要が生じた(特にConnectXの2ポートをループバックケーブルで
 * 直結した構成でのARP/ICMP動作確認 -- CLAUDE.md「TCP/IPスタックの
 * ConnectX統合」節参照)。
 *
 * 設計方針: このプロジェクトはポーリング専用・単一スレッドの協調的
 * 実行モデル(割り込み無し)なので、真の並行動作ではなく「今どの
 * インターフェースとして振る舞うか」を頻繁に切り替える方式で複数
 * インターフェースを扱える。netif_t が1つのインターフェースの識別情報
 * (MAC/IP/ARPキャッシュ)と送受信バックエンド(nic_ops_t)をまとめ、
 * g_active_ctx が「現在アクティブな」コンテキストを指す。
 *
 * arp.c/ip.c/icmp.c/tcp.cの既存コードは一切変更不要(または最小限)で
 * 済むよう設計している:
 * - eth_get_mac()/eth_send()/eth_poll_recv()等(eth.hの公開API)は、
 *   eth.c内部でg_active_ctxを経由するようディスパッチ層へ変更した
 *   だけで、呼び出し側のシグネチャ・呼び出し方は不変。
 * - net.hのNET_SELF_IPマクロは、従来のコンパイル時定数から
 *   net_active_ip()(g_active_ctx->ipを読むだけ)へ変更した。マクロを
 *   参照する側(arp.c/ip.c/tcp.c)のソース上の見た目は完全に不変。
 * ================================================================ */

#define ARP_CACHE_SIZE 8u

typedef struct {
    uint32_t ip;
    uint8_t  mac[ETH_ALEN];
    int      valid;
} arp_cache_entry_t;

/* NICバックエンドが実装すべき最小限の操作セット。eth.c(RP1)と
 * mlx5_net.c(ConnectX)がそれぞれ静的なテーブルとして実装し、
 * netif_t.nic経由で呼ばれる。priv引数はバックエンドごとの内部状態
 * (RP1は単一グローバル実装のため常にNULL、mlx5はmlx5_net_state_t*)。
 * 意味・戻り値の規約はeth.hの同名公開関数(eth_send_frags()等)と同じ。 */
/* [関数ポインタ登録先一覧 -- ctagsジャンプ補助] 各メンバに登録される具体関数:
 *   send_frags        : rp1_send_frags(eth.c) / mlx5_net_send_frags(mlx5_net.c)
 *   send_frags_async  : rp1_send_frags_async(eth.c) / mlx5_net_send_frags_async(mlx5_net.c)
 *   send_lso          : (RP1はNULL) / mlx5_net_send_lso_async(mlx5_net.c)
 *   tx_wait_free_slot : rp1_tx_wait_free_slot(eth.c) / mlx5_net_tx_wait_free_slot(mlx5_net.c)
 *   poll_recv         : rp1_poll_recv(eth.c) / mlx5_net_poll_recv(mlx5_net.c)
 * 登録テーブル: s_rp1_ops(eth.c) / s_mlx5_net_ops(mlx5_net.c)。 */
typedef struct {
    int (*send_frags)(void *priv, const eth_frag_t *frags, unsigned frag_count);
    int (*send_frags_async)(void *priv, const eth_frag_t *frags, unsigned frag_count);
    /* 2026-08-10、LSO(TCP Segmentation Offload)対応。hdr(hdr_lenバイト、
     * L2+L3+L4ヘッダ全体、ペイロード抜き)をテンプレートとして、payload
     * (payload_lenバイト、複数MSS分をまとめてよい)をHWがmss単位に自動
     * 分割・送出する。NULL許容 -- LSO非対応バックエンド(RP1のeth.c)は
     * このフィールドをNULLのままにする(netif_t.hw_lso_max_bytes=0と
     * 対で、tcp.cはhw_lso_max_bytes>0の時だけこの関数ポインタを呼ぶため、
     * NULLを呼んでしまうことはない)。 */
    int (*send_lso)(void *priv, const void *hdr, uint16_t hdr_len,
                     const void *payload, uint32_t payload_len, uint16_t mss);
    unsigned (*tx_wait_free_slot)(void *priv);
    net_buf_t *(*poll_recv)(void *priv);
} nic_ops_t;

typedef struct netif {
    const char *name;   /* ログ/`net use`コマンド用の識別子("rp1","mlx5-pf0"等) */
    uint8_t     mac[ETH_ALEN];
    uint32_t    ip;      /* 自機IPv4(ホストバイトオーダー)。net.hのNET_SELF_IPが参照する */
    const nic_ops_t *nic;
    void       *nic_priv;
    arp_cache_entry_t arp_cache[ARP_CACHE_SIZE];
    /* このバックエンドが安全に送受信できるTCP MSS上限(tcp.cが自分の
     * SYNオプションで広告する値・相手の広告値を上限する値の両方に使う、
     * net_active_mss_cap()参照)。RP1(eth.c)・ConnectX(mlx5_net.c)いずれも
     * ジャンボフレーム対応済み(RQバッファ/送信ステージングバッファが
     * 共にMLX5_JUMBO_MAX_LEN=10240バイト、mlx5.hのMLX5_RQ_BUF_PER_WQE/
     * MLX5_NET_TX_STAGE_SIZE参照、2026-08-09拡張)なのでtcp.cのTCP_MSS_
     * LOCAL(10182)と同値。tcp.c側の静的バッファ(s_seg_bufs等)は常に
     * TCP_MSS_LOCAL(最大値)でサイズ確保されているため、これより小さい
     * 値を使う分には安全(オーバーフローしない) -- 非ジャンボの相手と
     * 接続する場合はtcp_parse_syn_options()がmin(相手の値,mss_cap)を
     * 採用するため引き続き相互接続できる。 */
    uint16_t    mss_cap;
    /* 2026-08-13、writeパイプライン化。このインターフェースのRX
     * ディスクリプタリングのエントリ数(=同時に吸収できる受信フレーム数)。
     * tcp.cのtcp_send_segment()が広告受信ウィンドウの安全上限
     * (safe_window_cap = rx_ring_size * snd_mss / 2)を計算するのに使う
     * -- 広告ウィンドウがリング容量を超えるとホストが送ってきた分がリングを
     * 枯渇させ取りこぼす(CLAUDE.md「Write性能デグレード」節参照)。従来は
     * tcp.cが常にETH_RX_RING_SIZE(128、RP1 GEMのリング)を決め打ちしていたが、
     * mlx5(RQ=MLX5_RQ_NUM_WQES=256エントリ、RP1の2倍の容量)でも128で計算
     * していたため広告ウィンドウが実容量の半分に抑えられ、NVMe/TCP writeの
     * 実効パイプライン深度が2程度に制限されていた(実ホストfio計測+
     * tcpdumpで確認、CLAUDE.md該当節参照)。0の場合は net_active_rx_ring_
     * size() が ETH_RX_RING_SIZE(RP1既定)へフォールバックするため、RP1の
     * s_rp1_ctx(この値を設定しない)は従来通りの挙動になる。mlx5_net.cの
     * mlx5_netif_setup()のみMLX5_RQ_NUM_WQESを設定する。 */
    uint16_t    rx_ring_size;
    /* 2026-08-09、ハードウェアチェックサムオフロード対応。1ならこの
     * インターフェースの送受信経路がHWでL3(IP)/L4(TCP)チェックサムを
     * 計算・検証する(mlx5_net.c、SQ WQEのeth_seg.cs_flags=
     * MLX5_ETH_WQE_L3_CSUM|L4_CSUM、CQEのhds_ip_ext参照) -- tcp.c/ip.cは
     * この値を見て送信前のソフトウェアチェックサム計算をスキップする
     * (受信側はnet_buf_t.hw_csum_okを個別に見るため、こちらは送信側
     * 専用の判定に使う)。RP1(eth.c)は常に0(チェックサムオフロード
     * 機能は未確認、CLAUDE.md「GEMのハードウェアチェックサムオフロード」
     * 節参照、引き続きソフトウェア計算)。 */
    uint8_t     hw_csum_offload;
    /* 2026-08-09、TCP送信の真のゼロコピー対応。1ならこのインターフェース
     * (mlx5_net.c)がeth_send_frags_async()へ2フラグメント(ヘッダ+呼び
     * 出し元の元データバッファ)をそのまま渡してよい -- tcp.cは
     * tcp_send_segment()内でこの値を見て、従来の「seg_bufへコピーして
     * から単一フラグメントで送る」経路と、「ヘッダのみseg_bufへ書き、
     * データはコピーせず2番目のフラグメントとして直接渡す」経路を
     * 切り替える。RP1(eth.c)は0のまま(GEMがscatter-gather TXに対応
     * しないため、CLAUDE.md「NVMe/TCPの残TODO」節の実機確認済みの制約
     * 参照、常に単一バッファへの結合コピーが必要)。 */
    uint8_t     tx_zerocopy_2frag;
    /* 2026-08-10、LSO(TCP Segmentation Offload)対応。0以外ならこの
     * インターフェース(mlx5_net.c)がnic->send_lso()経由でハードウェア
     * TCPセグメンテーションに対応しており、tcp.c(tcp_send()のバースト
     * 送信ループ)は1 MSSを超えるチャンク(最大この値のバイト数)を1回の
     * send_lso()呼び出しでまとめて送ってよい。0(既定、RP1のeth.cは常に
     * この値)なら非対応 -- tcp.cは従来通りMSS単位でtcp_send_segment()を
     * 呼ぶ。mlx5側はmlx5_hca_bringup()がQUERY_HCA_CAP(ETHERNET_OFFLOADS)
     * から読んだ値(mlx5.hのMLX5_LSO_MAX_BYTES_CAPでクランプ済み)を
     * mlx5_netif_setup()で設定する。 */
    uint32_t    hw_lso_max_bytes;
    /* このインターフェースの実ハードウェア(RXリング等)を実際に
     * ポーリングして良いコア(マルチコア化 Phase 6準備、
     * ~/.claude/plans/wondrous-baking-gadget.md参照)。netif_register()
     * が登録した瞬間のsmp_core_index()を記録する -- eth.c/mlx5_net.cの
     * NICドライバ実装はコアをまたいだ同時アクセスに対して一切スレッド
     * セーフでない(ロック無し)ため、あるインターフェースを実際に
     * poll_recv()して良いのは常にこの1コアだけに限定する(net_poll_all_
     * and_dispatch()参照)。netif_find()/netif_find_by_ip()による
     * *検索*自体はowner_coreに関係なくどのコアからでも行える(job step
     * がctx経由で自分の担当リソースを見つける用途、下記コメント参照) --
     * 「見つける・activateする」ことと「実際にハードウェアへポーリング
     * しに行く」ことは別の話であり、後者だけがコア固定という制約を持つ。 */
    unsigned    owner_core;
    /* 【2026-08-08追加、telnetのコアごと分離用】この netif_t が実際に
     * net_poll_all_and_dispatch()からpoll_recv()を呼ばれるべき「代表」
     * かどうか。1(既定、netif_register()が設定)なら通常通りポーリング
     * 対象になる。0は「別名(alias)」を意味し、同じ物理NIC(nic/nic_priv
     * が代表と同一)を共有しつつ別のIPアドレスを名乗るだけの論理識別子
     * であり、それ自体はポーリングされない(netif_register_alias()
     * 参照) -- 1個の物理NICを2回ポーリングして受信フレームを重複処理
     * してしまうのを防ぐため。 */
    int         is_poll_owner;
} netif_t;

/* 現在「アクティブ」なコンテキスト。eth.c(eth_get_mac/eth_send_frags等の
 * ディスパッチ)とnet.h(NET_SELF_IPマクロ)が参照する。NULLの間は
 * まだどのインターフェースも初期化されていない(`net init`前)ことを表す。
 *
 * マルチコア化 Phase 4(~/.claude/plans/wondrous-baking-gadget.md参照):
 * 実体はnetif.cで定義するg_netif_active_slots[SMP_MAX_CORES]。
 * 「現在アクティブなコンテキスト」はコアごとに独立していなければ
 * ならない(Phase 6でcore0=PF0クライアント/core1=PF1サーバのように
 * 各コアが別々のインターフェースを並行してactivateする設計のため、
 * 単一の共有ポインタのままだと片方のactivate()がもう片方の送受信先を
 * 書き換えてしまう)。
 *
 * 既存の呼び出し箇所(eth.c/arp.c/tcp.c/telnet.c/nvme.c/command.c等、
 * `g_active_ctx`を直接読み書きする箇所多数)を一切変更せずに済むよう、
 * シンボル名`g_active_ctx`はそのまま維持しつつ、「呼び出し元が実行中の
 * コアのスロットを指すポインタへのポインタを介したアクセス」を行う
 * マクロへ変更した(net.hのNET_SELF_IPマクロと同じ設計方針 -- 既存
 * コード側の見た目・挙動を変えず、内部実装だけ差し替える)。
 * netif_active_slot()はstatic inlineなので、実際のオーバーヘッドは
 * MRS 1命令+シフト/マスク+配列インデックス計算だけで済む(smp.hの
 * smp_core_index()参照 -- volatileを付けていないため、同一関数内での
 * 複数回参照はコンパイラが正当にCSEできる)。 */
extern netif_t *g_netif_active_slots[SMP_MAX_CORES];

static inline netif_t **netif_active_slot(void)
{
    return &g_netif_active_slots[smp_core_index()];
}
#define g_active_ctx (*netif_active_slot())

void netif_activate(netif_t *ctx);

/* net_poll_all_and_dispatch()が巡回する「受信ポーリング対象」の登録簿。
 * activate(「今どれとして送信/自機IP解決するか」)とは独立した別の
 * 概念 -- 例えばmlx5のPF0/PF1は両方register()されるが、activate()される
 * のは呼び出しごとにどちらか一方。同じctxを二重登録しても無害(無視)。
 *
 * 【2026-08-08変更】マルチコア化Phase 4では登録簿自体をコアごとに
 * 独立させていたが、これだと「あるコアで生成されたTCPコネクション/
 * job stepを、後から別のコアがctx経由で正しく見つけて処理する」
 * (job.hの「job stepのctx経由リソース参照化」)ことができなくなる --
 * netif_find_by_ip()はtcp.cのtcp_send_segment()がconnのlocal_ipから
 * 送信先インターフェースを逆引きするために使われるが、そのconnを
 * *生成した*コアと*今tickしている*コアが違えば(job.cが共有スケジューラ
 * で任意のコアにジョブを割り当てうる)、探す側のコアの登録簿にしか
 * 無いエントリを見つけられず壊れる。
 *
 * このため登録簿自体は単一の共有配列に戻し(netif.c参照、s_registered_
 * lockで保護)、netif_find()/netif_find_by_ip()はどのコアからでも
 * 全登録済みコンテキストを検索できるようにした。一方、実ハードウェアへの
 * ポーリング(net_poll_all_and_dispatch())だけは、登録時に記録した
 * netif_t.owner_coreと一致するコンテキストのみを対象にする(NICドライバ
 * 自体はコア間で共有できないため、「見つけられる」ことと「ポーリングして
 * 良い」ことを分離した設計、netif_t.owner_coreのコメント参照)。 */
#define NETIF_MAX_REGISTERED 4u
void netif_register(netif_t *ctx);

/* 【2026-08-08追加】1つの物理NIC(RP1)を「論理的に」2つの識別子へ分ける
 * ための別名登録。telnetをコアごとに独立させる際、コア0向け/コア1向けの
 * 2つのtelnetセッションをそれぞれ別のIPアドレス(下1桁違い)で区別できる
 * ようにする目的で追加した -- 実ハードウェア(RXリング/TXリング)は
 * primaryが代表して1コアだけがポーリング/送信する(owner_coreの制約は
 * 従来通り)ため、真の意味で2コアが同時にNICへアクセスするわけではない
 * (このプロジェクトのNICドライバはコア間排他を持たないため、それ自体は
 * 今回も変更しない)。
 *
 * ctx: 呼び出し元が用意した別名用の netif_t(name/ip/mac/mss_capは
 *      呼び出し元が設定してから渡す -- macはprimaryと同じ値を使うのが
 *      通常、mss_capはprimaryと揃えるのが通常)。
 * primary: 実体を共有する代表ctx(既にnetif_register()済みであること)。
 *
 * 効果: ctx->nic/nic_priv/owner_coreをprimaryからコピーし、
 * ctx->is_poll_owner=0にしてから登録する。net_poll_all_and_dispatch()は
 * is_poll_owner==0のctxをポーリング対象から除外するが、受信フレームの
 * 宛先IPがこのctxのipと一致すれば、そのフレームの処理中だけこのctxを
 * activateする(netif.cのnetif_resolve_frame_owner()参照) -- IP
 * エイリアシング(1枚のNICに複数IPを持たせる一般的な手法)と同じ考え方。
 * netif_find()/netif_find_by_ip()からは通常のctxと同様に検索できる
 * ため、tcp_send_segment()等の既存コードは変更不要。 */
void netif_register_alias(netif_t *ctx, const netif_t *primary);

/* 【マルチコア化 Phase 6】netif_register()が記録したowner_coreを
 * 明示的に上書きする -- ConnectXブリングアップ自体は常にcore0が単独で
 * 行う(PCIeコンフィグ空間の同時競合を避けるため、~/.claude/plans/
 * wondrous-baking-gadget.md「Phase 6」節参照)ため、登録直後の
 * owner_coreは常にcore0になる。実際にそのインターフェースの受信
 * ポーリング/送信をcore1へ引き渡したい場合、この関数でcore1へ再ピン
 * してから(platform_init.cのplatform_init_connectx()参照)、対応する
 * nvmet_job_start()等でジョブをspawnすること -- nvmet_job_start()は
 * spawn時点のbound_ctx->owner_coreをjob_pin_to_core()へそのまま渡す
 * ため、呼び出し順序(先にowner_core変更、後でjob spawn)を守る必要が
 * ある。
 *
 * 安全に呼べるタイミング: このctxに対応するjob(NIC RX/TXへ触れる)が
 * まだ1つもspawnされていない/tickされていない間だけ -- 実行中の
 * ポーリング先を実行時に安全に切り替える機構ではない(単なるフィールド
 * 上書き、ロックは取らない)。 */
void netif_set_owner_core(netif_t *ctx, unsigned core);

/* 登録済みコンテキストをname(netif_t.name、NUL終端)で検索する。
 * `net use <name>`シェルコマンドから使う。どのコアからでも、登録した
 * コアに関わらず全コンテキストを検索できる(上記コメント参照)。
 * 見つからなければNULL。 */
netif_t *netif_find(const char *name);

/* 登録済みコンテキストを自機IPv4(netif_t.ip)で検索する。tcp.c
 * (tcp_send_segment())が、送信しようとしているconnのlocal_ipから
 * 「このコネクションが属するインターフェース」を逆引きし、送信直前に
 * netif_activate()するために使う -- 複数コンテキスト(ConnectXの
 * PF0/PF1等)を同一プログラム内で並行運用する際、tcp_poll_once()
 * (net_poll_all_and_dispatch()経由)がコンテキストを切り替えながら
 * ポーリングする合間に、呼び出し元が意図しないコンテキストがアクティブ
 * なままtcp_send()等が呼ばれるケースに対応するため。どのコアからでも
 * 検索できる(上記コメント参照 -- job migrationでconn生成コアと異なる
 * コアがtcp_send_segment()を呼んでも正しく見つかる)。見つからなければ
 * NULL(呼び出し元は現在のg_active_ctxをそのまま使う)。 */
netif_t *netif_find_by_ip(uint32_t ip);

/* 登録済みコンテキストのうち、呼び出し元(このコア)がowner_coreである
 * ものだけを順に1回ずつactivateしてpoll_recv()し、受信フレームがあれば
 * そのコンテキストをactiveにしたままeth_dispatch()する(ハンドラが
 * 正しい自機MAC/IP/ARPキャッシュを参照できるように)。呼び出し前に
 * activeだったコンテキストへ最後に復元してから返る。
 * arp_resolve()/icmp_wait_echo_reply()の待ちループが、複数コンテキストを
 * 同時に相手取る場合(ConnectXループバック等)にeth_poll_recv()+
 * eth_dispatch()の代わりに使う -- 登録数が1つ(通常のRP1単体運用)でも
 * 従来と同じ動作になる。他コアがowner_coreのコンテキストは一切触らない
 * (NICドライバ自体がコアをまたいだ同時アクセスに対してスレッドセーフで
 * ないため、netif_t.owner_coreのコメント参照)。
 *
 * 戻り値: 今回の呼び出しでいずれかのコンテキストから実際にフレームを
 * 1つ以上受信・処理していれば1、何も受信しなければ0(2026-08-07追加、
 * command.cのアイドル検出に使う -- 既存の呼び出し元(arp.c/icmp.c/tcp.c)
 * は戻り値を無視するだけで挙動は変わらない)。 */
int net_poll_all_and_dispatch(void);

/* g_active_ctxの自機IPv4を返す(net.hのNET_SELF_IPマクロが使う)。
 * 未初期化(g_active_ctx==NULL)なら0を返す -- `net init`より前に
 * 呼ばれることは通常無い(arp/ping/net poll等のコマンドはnet init後
 * にしか意味を持たない)。 */
static inline uint32_t net_active_ip(void)
{
    return g_active_ctx ? g_active_ctx->ip : 0u;
}

/* g_active_ctxのTCP MSS上限を返す(tcp.cが使う、netif_t.mss_capの
 * コメント参照)。未初期化(g_active_ctx==NULL)なら安全側の小さい値
 * (1460、標準Ethernet MTU相当)を返す。 */
static inline uint16_t net_active_mss_cap(void)
{
    return g_active_ctx ? g_active_ctx->mss_cap : 1460u;
}

/* g_active_ctxのRXリングエントリ数を返す(netif_t.rx_ring_sizeコメント
 * 参照、tcp.cのsafe_window_cap計算に使う)。フィールドが0(RP1のように
 * 明示設定しないインターフェース)、または未初期化(g_active_ctx==NULL)なら
 * ETH_RX_RING_SIZE(RP1 GEMのリング、従来の決め打ち値)へフォールバックする
 * -- これによりRP1側の広告ウィンドウ挙動は一切変わらない。 */
static inline uint16_t net_active_rx_ring_size(void)
{
    return (g_active_ctx && g_active_ctx->rx_ring_size) ? g_active_ctx->rx_ring_size
                                                        : (uint16_t)ETH_RX_RING_SIZE;
}

/* g_active_ctxがハードウェアチェックサムオフロードに対応しているかを
 * 返す(netif_t.hw_csum_offloadコメント参照)。未初期化(g_active_ctx==
 * NULL)なら安全側の0(ソフトウェア計算を行う)を返す。 */
static inline int net_active_hw_csum_offload(void)
{
    return g_active_ctx ? g_active_ctx->hw_csum_offload : 0;
}

/* g_active_ctxがTCP送信の真のゼロコピー(2フラグメント)に対応している
 * かを返す(netif_t.tx_zerocopy_2fragコメント参照)。未初期化なら
 * 安全側の0(従来通りコピーする)を返す。 */
static inline int net_active_tx_zerocopy(void)
{
    return g_active_ctx ? g_active_ctx->tx_zerocopy_2frag : 0;
}

/* g_active_ctxがLSO(TCP Segmentation Offload)に対応しているかを返す
 * (netif_t.hw_lso_max_bytesコメント参照)。0なら非対応。未初期化
 * (g_active_ctx==NULL)なら安全側の0(従来通りMSS単位で送る)を返す。 */
static inline uint32_t net_active_lso_max_bytes(void)
{
    return g_active_ctx ? g_active_ctx->hw_lso_max_bytes : 0u;
}

#endif /* NETIF_H */
