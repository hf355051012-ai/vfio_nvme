#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include <stddef.h>
#include "net_buf.h"

/* ================================================================
 * eth.h — RPi5 (BCM2712) RP1内蔵Ethernet ベアメタルドライバ
 *
 * RP1のEthernetブロックは Cadence MACB/GEM IP (dtbの compatible =
 * "raspberrypi,rp1-gem", "cdns,macb"; phy-mode = "rgmii-id") -- Synopsys
 * DesignWare GMAC(dwmac4)ではない。過去に dwmac4 を前提に調査していたが、
 * raspberrypi/linux の実際の rp1.dtsi を確認して Cadence MACB/GEM
 * (drivers/net/ethernet/cadence/macb_main.c, macb.h) だと判明したため、
 * このヘッダ/eth.c はそちらを参照して実装している。
 *
 * レジスタオフセット・ビットフィールド・記述子フォーマットは
 * drivers/net/ethernet/cadence/macb.h, macb_main.c (raspberrypi/linux,
 * rpi-6.6.y) を参照して決定している。ベースアドレスは
 * include/dt-bindings/mfd/rp1.h の RP1_ETH_IP_BASE(=0x100000, BAR1内オフセット)
 * を PCIE_OUTBOUND_CPU_BASE に加算したもの(board.h/pcie.hの既存パターンに倣う)。
 *
 * 実装済み: PHYハードウェアリセット(dtbの phy-reset-gpios、RP1 GPIO32、
 * active-lowをGPIO_CTRLのOUTOVER/OEOVERハードオーバーライドでパルスする。
 * オフセットはdrivers/pinctrl/pinctrl-rp1.cのrp1_iobanks[]参照)、
 * リンク確立(オートネゴシエーション完了)を最大数秒待つポーリング、
 * 標準MIIレジスタ(GTSR/ANAR/ANLPAR)からの実ネゴシエート速度/デュプレックス
 * 解決とNCFGR(SPD/FD/GBE)への反映、MAC初期化(NCFGR/DMACFG/USRIO)、
 * net_buf固定バッファプールによるTX/RX記述子リング(RXは事前ポスト式、
 * TXは単発busy-wait)。実機(実際のRP1+外部PHY)でGPIOリセット後の
 * リンクアップ(BMSR経由)までは確認済み。TX/RXのDMA自体はまだ実機で
 * 成功確認できていない(2026-07-17時点、arp who実行時にTXタイムアウト
 * -- リンク未確立のまま送信していたのが原因の可能性が高く、本コミットの
 * 速度/デュプレックス解決の追加でどう変わるか再テスト待ち)。
 * 未実装(既知の制限): RP1のクロック(RP1_CLK_ETH等)は起動時デフォルトで
 * 有効という前提(RP1クロックマネージャのレジスタ操作は未実装)。
 * ================================================================ */

#define ETH_ALEN            6
#define ETH_HDR_LEN          14   /* dst(6) + src(6) + ethertype(2) */

/* RP1のGEM(Cadence)がジャンボフレームとして受け付ける最大フレーム長。
 * raspberrypi/linux (rpi-6.6.y) drivers/net/ethernet/cadence/macb_main.c の
 * raspberrypi_rp1_config (.caps に MACB_CAPS_JUMBO を含む) が
 * .jumbo_max_len = 10240 と定義しており、これがそのままRP1のGEM_JML
 * レジスタに書き込まれる値 -- 実機ドライバから取得した値であり推測では
 * ない(CLAUDE.md「参照ドライバソース」節の方法論通り)。ヘッダ+ペイロード
 * +FCS込みの値(同ドライバのdev->max_mtu = jumbo_max_len - ETH_HLEN -
 * ETH_FCS_LEN(4) = 10222計算より逆算可能)。HWがFCSを自動付加/除去する
 * ため、net_buf_t側のバッファ(FCSを含まない)はこの値から4引いた
 * 10236バイトあれば足りるが、net_buf.hのNET_BUF_SIZEは切りの良い
 * 10240バイトを採用している(eth.c/net_buf.h参照)。 */
#define ETH_JUMBO_MAX_LEN  10240u

/* テレメトリ用の統計カウンタ(tcpbench等が使う)。RSR.BNAはRXリング全
 * 記述子が埋まったままフレームが届いてハードウェアが破棄した回数、
 * RSR.OVRは受信オーバーランの回数。eth_poll_recv()内で検出のたびに
 * インクリメントされる(write-1-clearでハードウェア側もクリアする)。 */
extern volatile uint32_t g_eth_rsr_bna_count;
extern volatile uint32_t g_eth_rsr_ovr_count;

/* RP1 MACB/GEM初期化: pcie_rc_init()でPCIeリンク+RP1 BARを立ち上げた上で、
 * net_bufプールの初期化、MAC設定(NCFGR/DMACFG/USRIO)、TX/RX記述子リングの
 * 構築、MACアドレス設定、RX/TXの有効化までを行う。EtherType別ハンドラの
 * 登録(eth_register_handler)はここでは行わない -- 呼び出し側(net init
 * コマンド)が eth_init() の後で arp_init()/ip_init() 等を呼ぶこと。
 */
void eth_init(void);

/* 自機の MAC アドレスを取得（フェーズ0では固定のローカル管理アドレスを使用）*/
void eth_get_mac(uint8_t mac[ETH_ALEN]);

/* 未実装(スタブ)。RGMII-ID接続の外部PHY(dtbの ethernet-phy@1、MDIOアドレス1)
 * に対する標準MII BMSRレジスタでのリンク確認は、eth_init()内で診断ログ
 * 目的の一回読みとしてのみ行っている(このスタブ自体は使っていない)。
 * PHYのハードウェアリセット(phy-reset-gpios経由、GPIO32)は
 * eth_init()内のphy_hw_reset()で実施済み -- 本関数を実装する場合は
 * それより後(MDIOが応答可能になった後)に読むこと。
 * 戻り値: 1=リンクアップ, 0=リンクダウン
 */
int eth_phy_link_up(void);

/* 未実装(スタブ)。eth_phy_link_up()と同様の理由でBMSR bit5を読んでいない。
 * 戻り値: 1=オートネゴシエーション完了, 0=未完了
 */
int eth_phy_aneg_complete(void);

/* 未実装(スタブ)。eth_init()は現状、リンク確立を待たずGBE+FD固定で
 * NCFGRを設定している(コメント参照)。実際のリンク速度/デュプレックスに
 * 追従する必要が出た場合はここを実装すること。
 * 戻り値: 1=リンクアップ(速度/デュプレックス反映済み), 0=タイムアウト
 */
int eth_wait_link_up(uint32_t timeout_ms);

/* 未実装(スタブ)。MACB/GEMのループバックはNCR.LLBビットで行う想定だが
 * 未着手。
 */
void eth_set_loopback(int enable);

/* Ethernetフレーム(dst+src+ethertype+payload、FCS抜き)を1つ送信する。
 * HW が CRC(FCS)を自動付加するため、呼び出し側はFCSを含めない。
 * nb の所有権は本関数に渡り、成否によらず内部で net_buf_free() される
 * (呼び出し側は eth_send() 後に nb へアクセスしてはならない)。
 * 戻り値: 0=送信完了(HW消費確認), -1=タイムアウト/引数エラー
 */
int eth_send(net_buf_t *nb);

/* 送信フレームを構成する1個の断片(スキャッタ・ギャザー送信用)。 */
typedef struct {
    const void *data;
    uint16_t    len;
} eth_frag_t;

/* 1回の送信で使える最大断片数。TCPのゼロコピー送信(ヘッダ用の小さな
 * バッファ+呼び出し元のデータバッファの2断片)を想定した値 — 3断片以上
 * が必要になったら増やすこと。 */
#define ETH_TX_MAX_FRAGS 2

/* RXリングのエントリ数(詳細な経緯コメントはeth.c参照だったが、tcp.cが
 * 広告受信ウィンドウをRXリング容量で頭打ちにする際にも使うため、ここ
 * (ヘッダ)で公開する -- ETH_TX_RING_SIZEと同じ理由)。
 *
 * 元は4→8→32→256と拡張してきた(32への拡張理由はtcp.cのTCP_RX_BUF_SIZE
 * 拡張に合わせたバースト吸収、256への拡張の経緯はCLAUDE.md「NVMe/TCP
 * Write スループット」節参照 -- 当時は確証の無いまま拡張優先で行った
 * 変更だったと明記されている)。
 *
 * 2026-07-25、768へ再拡張した。tcp.cにWindow Scaling(RFC7323)を実装し
 * 広告できる受信ウィンドウを最大512KB相当まで引き上げたところ、実機の
 * NVMe/TCP write(fio iodepth>=4)でRSR.BNA/OVRが実際に増加し(この時点で
 * 初めて非ゼロを実機確認 -- 2026-07-19時点の256への拡張時とは異なり、
 * 今回は「[IP] total_lengthがフレーム長を超過」という具体的な取りこぼし
 * 症状と`err`コマンドでの実測(RSR.BNA/OVR共に非ゼロ)の両方で裏付けが
 * 取れている)、`fio`のIOが停止する事象につながった。原因は単純な容量
 * 不足: 旧256エントリ×net_buf_t(1536B)=384KBのRXリングに対し、こちらが
 * 広告する受信ウィンドウの理論上限(512KB)の方が大きく、ホストが正直に
 * その広告を信じて送ってくると原理的に溢れる。768エントリ×1536B≒1.125MB
 * とし、512KBの広告上限に対して倍以上の余裕(処理遅延吸収分)を持たせた。
 * .dma_bss総使用量は768でも約1.14MB(mmu.cが.dma_bss用に確保する単一
 * 2MB L2ブロックの約57%)なので、その制約には抵触しない。
 *
 * 2026-07-25、ジャンボフレーム対応(net_buf.h参照、NET_BUF_SIZE 1518→
 * 10240)に合わせ128へ縮小した。net_buf_t 1個が約6.8倍(1536B→10304B、
 * aligned(64)込みの実サイズ)に膨らんだため、768のまま据え置くと
 * s_rx_ring_bufsだけで768*10304B≒7.5MBとなり、mmu.cが.dma_bss用に
 * 確保する単一2MB L2ブロックに全く収まらない(超過分は次のL2エントリ
 * ヘ静かに溢れ、そこは通常のNormal cacheable RAM属性になるため、DMAが
 * そこへ書いてもCPUから見えない/コヒーレンシが壊れるという、検出困難な
 * 形で発現する重大なバグになる -- mmu.cに追加した__dma_bss_sizeの
 * 2MB超過アサート(fatal_hang)参照)。
 * ジャンボフレームは1フレームあたりの実効ペイロードが約1460B→約10182B
 * (tcp.cのTCP_MSS_LOCAL参照)へ約7倍に増えるため、同じバイト量のバースト
 * を受けるのに必要なフレーム数(=リング深さ)はその分減ってよい —
 * 512KBの広告ウィンドウ(tcp.cのTCP_RX_BUF_SIZE)を128エントリ×10240B
 * ≒1.28MBで受けると、旧768エントリ×1460B≒1.09MB/512KB(約2.19倍の
 * 余裕)とほぼ同じ倍率(約2.5倍)の余裕を維持できる。
 * .dma_bss総使用量(s_rx_ring_bufs 128*10304B + リング記述子等の端数)は
 * 約1.32MB、2MB L2ブロックの約63%(旧設計の約57%と近い水準)。
 * s_seg_bufs(tcp.c)は2026-07-25にDMAコヒーレンシ方式を変更し.dma_bssから
 * 通常のNormal cacheable RAMへ移した(tcp.cのs_seg_bufs宣言のコメント
 * 参照)ため、ここには含まれない。
 *
 * 2026-07-25追加: この128という値はジャンボMSS(約10182B/フレーム)を
 * 前提にした余裕計算であり、非ジャンボ接続(MSS=1460)では128*1460B≒182KB
 * しか実際には吸収できず、512KB固定の広告ウィンドウ(tcp.cのTCP_RX_BUF_
 * SIZE)とは大きく食い違う。この不整合がtcp_send_segment()(tcp.c)で
 * 再発し(非ジャンボ接続のfio write iodepth>=4でRSR.BNA/OVR再発、
 * 上記768エントリ時代と全く同じ症状)、広告ウィンドウをconn->snd_mss×
 * ETH_RX_RING_SIZEで動的に頭打ちする対策を追加した(tcp.cのtcp_send_
 * segment()コメント参照)。 */
#define ETH_RX_RING_SIZE 128

/* TXリングのエントリ数(eth.c参照、詳細な経緯コメントはそちら)。tcp.cが
 * eth_tx_wait_free_slot()と組み合わせてスロットごとの送信バッファを
 * 確保する際に使うため、ここ(ヘッダ)で公開する。
 *
 * 2026-07-25、TX_WRAP折り返し時の再ラッチ処理(eth_tx_queue()の
 * s_tx_wrap_pending処理)のコストが実機計測で約400〜470us/回(8セグメント
 * に1回発生)と判明し、頻度を下げる目的で8→256へ拡大を試みたところ実機で
 * 「TXリング枠待ちタイムアウト (entry=ETH_TX_RING_SIZE-1)」→
 * eth_tx_recover() を繰り返す事象が発生した。当初リングサイズ拡大が
 * 引き金と疑い256→32→8と段階的に戻したが、**8のままでも同じ症状
 * (entry=7)がnvmetのIOキュー接続直後という同じタイミングで再現する
 * ことを実機で確認した** -- つまりリングサイズは無関係で、admin queue
 * (conn 0)とIO queue(conn 1)という2つのTCPコネクションが同じ物理TX
 * リングを共有し始める、そのタイミング固有の(未特定の)問題だと判明した。
 * 単一コネクションでのtcpbench/fio read/write(この会話中の全テスト)は
 * 一度も再現しなかったことと整合する。リングサイズは無罪と確定した
 * ため、TX_WRAP再ラッチ頻度低減の効果を得るため256へ戻した。 */
#define ETH_TX_RING_SIZE 256

/* frags[0..frag_count)を連結した1つのEthernetフレームとして送信する
 * (ゼロコピー — 各断片のメモリをそのままGEMのDMAに読ませ、コピーしない)。
 * eth_send()と違いnet_bufを介さない — 各断片は呼び出し元が所有する任意の
 * バッファ(net_buf、tcp.cの小さな静的ヘッダバッファ、呼び出し元自身の
 * 送信データバッファ等)を直接指してよい。この関数はどの断片のメモリも
 * 解放しない(呼び出し側の責任のまま)。ハードウェアの送信完了(HW消費
 * 確認)まで内部でブロッキングして待つため、戻った時点で全断片のメモリは
 * 再利用してよい。
 * frag_count: 1以上ETH_TX_MAX_FRAGS以下であること。
 * 戻り値: 0=送信完了(HW消費確認), -1=タイムアウト/引数エラー
 */
int eth_send_frags(const eth_frag_t *frags, unsigned frag_count);

/* eth_send_frags()と同じ引数・キューイング処理(TXリングへの記述子書き込み
 * +NCR_TSTART)を行うが、このフレームの送信完了は待たずに即座に返る点が
 * 違う。TXリング(ETH_TX_RING_SIZE個)の空きスロットを使い切るまでは
 * ブロックしないため、呼び出し元は完了を待たず次々と送信をキューイング
 * できる(パイプライン化)。リングが一杯になった場合のみ、最も古い未完了
 * フレームの完了を待ってからキューイングする(内部でeth_send_frags()と
 * 同じ待ち合わせ処理を行う)。
 * 信頼性(このフレームが実際に送信/到達したか)は呼び出し元が別途担保する
 * 前提 — TCP層はACKベースの再送(Go-Back-N)で担保している
 * (eth_tx_recover()のコメント参照)。単発のARP/ICMP等、送信完了を
 * 同期的に確認したい呼び出し元は引き続きeth_send_frags()を使うこと。
 * 戻り値: 0=キューイング成功, -1=引数エラー/リング空き待ちタイムアウト
 */
int eth_send_frags_async(const eth_frag_t *frags, unsigned frag_count);

/* 2026-08-10、LSO(TCP Segmentation Offload)対応。アクティブなインター
 * フェースがLSOに対応している場合のみ意味がある(netctx.hのnet_active_
 * lso_max_bytes()で事前に確認すること、非対応バックエンドでは常に-1)。
 * hdr(hdr_lenバイト、L2+L3+L4ヘッダ全体、ペイロードは含まない)を
 * テンプレートとして、payload(payload_lenバイト、複数MSSぶんをまとめて
 * 良い)をHWがmss単位に自動分割・送出する。WQEをポストしたら送信完了は
 * 待たずに返る(eth_send_frags_async()と同じ非同期パイプライン)。
 * 戻り値: 0=キューイング成功, -1=非対応/引数エラー/リング空き待ち
 * タイムアウト。 */
int eth_send_lso_async(const void *hdr, uint16_t hdr_len,
                        const void *payload, uint32_t payload_len, uint16_t mss);

/* 次にeth_send_frags_async()(frag_count=1の場合)が使うTXリングスロットの
 * インデックスを返す。そのスロットの記述子がまだハードウェアの処理中
 * (前回そのスロットを使ったフレームの送信が完了していない)なら、完了する
 * までブロックする(タイムアウト時の扱いはeth_send_frags()と同じ)。
 * 呼び出し元は、この関数が返った後で初めて、返されたスロットに対応する
 * 専用の送信バッファ(呼び出し元がETH_TX_RING_SIZE個用意する)へ新しい
 * フレームデータを書き込んでよい — ハードウェアが前回のDMA読み出しを
 * まだ終えていないバッファへCPUが上書きするデータ競合を避けるための
 * 呼び出し順序(tcp.cのtcp_send_segment()参照)。
 * 単一スレッド・ポーリング専用モデル前提: この関数が返ってから対応する
 * eth_send_frags_async()を呼ぶまでの間に、他のeth_send()系関数を挟んでは
 * ならない(挟むとs_tx_headがずれ、この関数が返したスロット番号と実際に
 * 使われるスロットが食い違う)。
 * frag_count>1(ETH_TX_MAX_FRAGS)の送信は本関数を経由せずeth_send_frags()/
 * eth_send_frags_async()を直接呼ぶこと(内部で必要なスロットを自前で待つ)。
 */
unsigned eth_tx_wait_free_slot(void);

/* GEMのTSR(Transmit Status Register)を読み、write-1-clearでクリアして
 * 返す。TX不具合調査用(err.c参照) -- bit4のBEXはAHBバスエラーによる
 * TXフレーム破損を示す、DMAアドレス関連の問題を直接示しうる重要な
 * ビット。ビット定義はeth.cのR_TSR/TSR_*マクロ参照。 */
uint32_t eth_read_tsr_and_clear(void);

/* GEMのISR(Interrupt Status Register)を生の値のまま読んで返す(読み出しで
 * クリアされる設計が一般的、err.c参照)。ビット定義はこのコードベースで
 * 未裏取りのため、呼び出し側は0/非0の参考情報としてのみ使うこと。
 * eth_init()の初期化時に1回読み捨てて以降、TXハング調査用にerr.cから
 * 呼ばれる以外では読まれない。 */
uint32_t eth_read_isr(void);

/* 直近の「TXリング枠待ちタイムアウト」検出時点で保存したTXリング全体の
 * 記述子スナップショット(USED/WRAP/LAST/FRMLEN)をUARTへ表示する。
 * ts_log()とは独立した専用バッファに保存されているため、その後どれだけ
 * ts_log()が呼ばれても上書きされない(eth.cのeth_dump_tx_ring_debug()
 * コメント参照)。タイムアウトが一度も発生していなければその旨を表示する。
 * コマンド`txdump`(command.c)から呼ばれる。 */
void eth_print_tx_ring_snapshot(void);

/* RXリング直後のガード領域(ETH_RX_RING_ALLOC_SIZE - ETH_RX_RING_SIZE件、
 * eth.cのETH_RX_RING_ALLOC_SIZEコメント参照)を確認する。ここは正規の
 * インデックス計算では一切書き込まれないはずの領域なので、非ゼロが
 * 見つかれば「s_rx_ring[ETH_RX_RING_SIZE]以降への実在しないインデックス
 * 書き込み」という既知の未解決バグ(CLAUDE.md「RXリング境界のメモリ
 * 破壊」参照)が実際に発生した直接証拠になる(err.c経由でerrコマンドから
 * 呼ぶ)。
 * 戻り値: 1=ガード領域が非ゼロ(破壊を検出)、0=クリーン */
int eth_check_rx_guard(void);

/* TXリング直後のガード/プリフェッチパディング領域(ETH_TX_RING_ALLOC_SIZE
 * - ETH_TX_RING_SIZE件、eth.cのETH_TX_RING_ALLOC_SIZEコメント参照)を
 * 確認する。2026-07-25、GEMのディスクリプタ先読み(BD_RD_PREFETCH、実機の
 * DCFG10読み出しでTXBD_RDBUFF=4を確認済み)がTX_WRAPディスクリプタ
 * 無視バグの原因である可能性を受けて追加したパディングと同じ領域を、
 * RX側と同様にガードとしても監視する(err.c経由でerrコマンドから呼ぶ)。
 * 戻り値: 1=ガード領域が非ゼロ(破壊を検出)、0=クリーン */
int eth_check_tx_guard(void);

/* RXリングを1回ポーリングする（ブロックしない）。
 * フレームが届いていれば net_buf プールから1個確保して内容をコピーし、
 * その所有権を呼び出し側に渡す(使い終わったら net_buf_free() すること)。
 * 戻り値: 受信フレームがあれば非NULL、無い場合/不正フレーム/プール枯渇はNULL
 */
net_buf_t *eth_poll_recv(void);

/* ------------------------------------------------------------------ */
/* EtherType別ハンドラディスパッチ(骨組み)                              */
/* ------------------------------------------------------------------ */

/* [関数ポインタ登録先 -- ctagsジャンプ補助] eth_register_handler()で登録される具体関数:
 *   0x0806(ARP)  -> arp_handle_frame(arp.c、arp_init()で登録)
 *   0x0800(IPv4) -> ip_handle_frame(ip.c、ip_init()で登録)
 * 間接呼び出しは eth.c の eth_dispatch() 内 g_handlers[i].handler(...)。 */
typedef void (*eth_handler_t)(const uint8_t *payload, size_t len, const uint8_t *src_mac);

/* EtherType(例: 0x0800=IPv4, 0x0806=ARP)に対するハンドラを登録する。
 * 同一EtherTypeへの再登録は上書きになる。handler=NULLで登録解除。
 */
void eth_register_handler(uint16_t ethertype, eth_handler_t handler);

/* nb の EtherType に応じて登録済みハンドラを呼び出す。
 * 該当ハンドラが無い場合は何もしない。nbの解放は呼び出し側の責任。
 */
void eth_dispatch(net_buf_t *nb);

/* 2026-08-09、ハードウェアチェックサムオフロード対応。eth_dispatch()が
 * 呼び出し直前に nb->hw_csum_ok(net_buf.hコメント参照)をこの呼び出し
 * コアのスロットへ書き込み、ハンドラ呼び出し完了後に0へ戻す。ip.c/
 * tcp.cのeth_register_handler()経由のハンドラ(ip_handle_frame()→
 * tcp_input())は、この関数で「今処理中のフレームはHWでL3/L4チェック
 * サム検証済みか」を確認し、真ならソフトウェア再検証(inet_checksum()/
 * pseudo_header_checksum())をスキップする。eth_dispatch()呼び出しの
 * ネスト(ハンドラ内から別のeth_dispatch()を呼ぶ設計は現状存在しない)
 * が無い前提の単純なper-coreスカラー実装。 */
int eth_rx_hw_csum_ok(void);

#endif /* ETH_H */
