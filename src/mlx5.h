#ifndef MLX5_H
#define MLX5_H

#include <stdint.h>

#define LOG_SET 0
#define LOG_GET 1 
#define LOG_CLR 2 
// ConnectXとの通信に使う全DMAバッファの固定物理アドレス。
//
// 実機で見つかった本物のバグ(CLAUDE.md「ConnectX(mlx5) HCA初期化」節):
// 以前はstatic配列+`aligned()`属性でコンパイラ/リンカに配置を委ねており、
// メールボックスの1つ(s_in_mbox)が1024バイト境界を満たさず
// `MLX5_CMD_DELIVERY_STAT_IN_PTR_ALIGN_ERR`で拒否された(直前に置かれた
// 別シンボルのサイズ次第でアドレスが決まる、という宣言順依存の脆さが
// 原因)。以後は個々のバッファのアドレス・アライメントを宣言順やコン
// パイラ判断に委ねず、オフセット値そのものへ直接焼き込む。
//
// **`MLX5_DMA_BASE`/`MLX5_DMA_SIZE`(board.h参照)は`.dma_bss`とは独立
// した専用128MB領域。この領域を実際に使うにはSDカードのkernel_2712.img
// を本ビルドへ書き換えて真のコールドブートを行う必要がある**(理由は
// board.hのコメント参照 -- チェインロードではmmu.cの変更が反映されない)。
// 128MBという広さは、MANAGE_PAGES(GIVE)がフェーズごとに要求するページ数が
// 実機で大きく変動すると判明した(boot pages=6ページ=24KB、init pages=
// 2489ページ=約9.7MB)ことを受け、将来のEQ/CQ/WQ等の追加分も見込んで
// 十分な余裕を持たせたもの(ユーザー指示)。
//
// **デュアルポート対応(CLAUDE.md「ConnectXデュアルポート対応」節):**
// このConnectXは物理ポートごとに別々のPCI関数(devfn=0/1)を持つマルチ
// ファンクションデバイスと判明した -- 各PCI関数は別々のBAR0・別々の
// コマンドインターフェースを持つ独立したHCAインスタンスとして扱う必要が
// ある。以下の全アドレスマクロは、以前は単一の`MLX5_DMA_BASE`(グローバル
// 定数)から直接計算していたが、`base`引数(呼び出し元が`mlx5_dev_t.
// dma_base`を渡す -- PF0なら`MLX5_DMA_BASE`そのもの、PF1なら
// `MLX5_DMA_BASE + MLX5_DMA_PF_SIZE`)を取る関数マクロへ変更した。
// 内部の相対オフセットの積み上げ構造自体は変えていない。
#define MLX5_MAX_FW_PAGES 8192u  // FWへMANAGE_PAGES(GIVE)で譲渡するスクラッチページ数の上限(32MB分)。実測のinit pages要求: ConnectX-4 Lx=2489、フルConnectX-4(MCX456A、100GbE)=4521。後者が4096を超えたため8192へ拡大(64MB/PFのDMA領域に収まる、下記_Static_assert検証)
#define MLX5_FW_PAGE_SIZE 4096u

// デュアルポート対応: 既存の128MB(MLX5_DMA_SIZE、board.h)を前半/後半で
// PF0/PF1へ2分割する(mmu.cのマッピングはMLX5_DMA_BASE..+MLX5_DMA_SIZEの
// まま変更不要 -- 単に同じ領域の使い方を割るだけ)。2MB境界(mmu.cのL2
// ブロック粒度)を保つよう、MLX5_DMA_SIZEが2MBの倍数であることを前提とする
// (board.hで64個の2MB L2ブロックとコメントされている通り)。実使用量は
// 現状PF1個あたり約17MB(MLX5_MAX_FW_PAGESの16MBが支配的)なので、
// 64MBあれば十分な余裕がある。

// mlx5_cmd_prot_block_t(576バイト、mlx5.c)のDMAプールアライメント要件。
// Linux cmd.cのmlx5_cmd_enable()の`roundup_pow_of_two(sizeof(struct
// mlx5_cmd_prot_block))`(576→1024)と同値 -- 実機で確認済み(上記参照)。
#define MLX5_CMD_MBOX_ALIGN 1024u

// メールボックスチェイン: CREATE_FLOW_GROUP等、単一メールボックスブロック
// (576バイト)を大きく超える固定長フィールドを持つコマンド向けに、複数の
// mlx5_cmd_prot_block_tを`next`で連結して送受信する(mlx5.cの
// mlx5_cmd_exec()参照)。各ブロックを互いに1024バイト間隔で配置し、
// 個々のブロックが単独でも1024バイト境界を満たすようにする -- 実機で
// 見つかったメールボックスアライメントバグ(`roundup_pow_of_two(576)=
// 1024`、上記コメント参照)と同じ理由で、チェインの2番目以降のブロックも
// 同じ制約を受ける。
#define MLX5_CMD_MBOX_CHAIN_BLOCKS 4u // 方向あたり最大 16+4*512=2064バイト

// CREATE_EQ用のEQバッファ(1ページ=4096バイト、EQE(mlx5_ifc.hのstruct
// mlx5_eqe相当)は64バイト固定なので64エントリ分)。fw_pagesの直後に配置。
#define MLX5_EQ_BUF_SIZE    4096u

// CREATE_CQ用のCQバッファとドアベルレコード(consumer_index/arm_indexの
// 2つのBE32、cqc.dbr_addrが指す先 -- 実際には8バイトしか使わないが将来
// SQ/RQ用にも同じ64バイト枠を使う想定で確保)。
// 2026-08-11、64エントリ(1ページ=4096バイト)→1024エントリ(16ページ=
// 65536バイト)へ拡張(board.hのMLX5_CQ_CACHE_PF_SIZEコメント参照 --
// 非同期送信スロット拡張時に旧64エントリのRQ用CQが実機でオーバーラン
// [status=9]したため、RQのWQE深さ[MLX5_RQ_NUM_WQES=256]に対して十分
// 余裕を持たせた)。log_page_size=0(4KBページ単位)のままなので、
// CREATE_CQのpas[]は16エントリ(mlx5_create_cq()参照)。
#define MLX5_CQ_BUF_SIZE    65536u
#define MLX5_CQ_DBR_SIZE    64u

// CREATE_RQ用のWQE(Work Queue Entry)リング(1ページ=4096バイト、各WQEは
// struct mlx5_wqe_data_seg(qp.h)相当で16バイト固定なので256エントリ分、
// log_wq_sz=8/log_wq_stride=4)、ドアベルレコード、実際の受信データバッファ
// (WQEエントリ数と同じ256個、1個あたり2048バイト -- 標準的なEthernet
// フレーム(最大1518バイト程度)を余裕を持って収める、cq.cのCQバッファと
// 同じくfw_pages/EQ/CQバッファの直後に配置)。
//
// 実機で見つかった本物のバグ(修正済み): 以前は
// `MLX5_CQ_DBR_ADDR + MLX5_CQ_DBR_SIZE`(4096アライン済みのアドレス+
// 64バイト)をそのままMLX5_RQ_WQE_ADDRとしていたため、4096の倍数には
// ならず(0x...040のようなオフセットになる)、CREATE_RQがwq.pas[0]の
// アライメント不正で実機からBAD_PARAM_ERR(status=0x03)を返された
// (log_wq_pg_sz=0=4KBページ単位でpas[]を渡す設計のため、各ページの
// 物理アドレスは4096バイト境界に整列している必要がある -- CLAUDE.md
// 「ConnectX(mlx5) HCA初期化」節のメールボックス1024バイト境界バグと
// 同種)。ドアベル(64バイトしか使わない)の直後から素朴に次のバッファを
// 置くのではなく、明示的に次の4096バイト境界へ切り上げるよう修正した。
#define MLX5_RQ_WQE_SIZE    4096u
#define MLX5_RQ_DBR_SIZE    64u
#define MLX5_RQ_NUM_WQES    256u
// ジャンボフレーム対応(2026-08-09): RP1(eth.hのETH_JUMBO_MAX_LEN)と同じ
// 10240バイトへ拡張した。mlx5.hはeth.hをincludeしない(mlx5.cが依存しない
// 独立ヘッダのため)ので、ここで同値の定数を自己完結で定義する -- 実際に
// これで最大何バイトのEthernetフレームを送受信できるかは、mlx5.cの
// mlx5_set_port_mtu()(PMTUレジスタ、実Linux port.c/mlx5_ifc.hから確認
// 済み、admin_mtuフィールドはワイヤ上のフレーム最大長そのもの)がこの値を
// 実際にHCAへ設定して初めて有効になる。net_buf.hのNET_BUF_SIZE(=10240)
// と同値に揃えている(mlx5_net_poll_recv()のbyte_cnt<=NET_BUF_SIZEチェック
// が上限になるため、これより大きくしても受信側で切り詰められる)。
#define MLX5_JUMBO_MAX_LEN  10240u
#define MLX5_RQ_BUF_PER_WQE MLX5_JUMBO_MAX_LEN

// RX headroom(NET_IP_ALIGN相当、2026-08-13): NICが各フレームをRQバッファの
// 先頭からではなく+MLX5_RX_HEADROOMバイトの位置へ書くようにする。目的は
// **TCPペイロードを8バイト境界へ乗せること**。スロット先頭は8整列、Ethernet
// (14)+IPv4(20、オプション無し)+TCP(20、オプション無し)=54でペイロードが
// 始まるので、+2すると 2+54=56(=8整列)にペイロードが着地する。これにより
// push型受信(nvmet_io_rx_upcall)の唯一のコピー(RQバッファ→ram_disk[slba])
// の src/dst が共に8整列となり、volatile_fast_copy()がバイト/2バイト単位
// フォールバックではなく8バイトワイドコピー経路に乗る(コピー時間の実測で
// この効果を検証中、CLAUDE.md参照)。ジャンボ運用が前提(非ジャンボでも
// アライメント自体は同様に効くが、断片数が多く効果が見えにくい)。
#define MLX5_RX_HEADROOM    2u
// 注意: 4096アラインではない(MLX5_RQ_DBR_ADDR+64バイト)。RQ自身は各WQEの
// data_seg.addrで個々のバッファを直接参照するためアライン不要 -- 下記
// MLX5_SQ_CQ_BUF_ADDRのコメント参照(この隣接配置に依存してアライメント
// バグを踏んだ経緯があるため、後続の定義を追加する際は必ず4096境界の
// 要否を個別に確認すること)。
#define MLX5_RQ_DATA_SIZE   ((uint64_t)MLX5_RQ_NUM_WQES * MLX5_RQ_BUF_PER_WQE) // 512KB

// 2026-08-09、ユーザー指摘による受信側ゼロコピー化: 上記MLX5_RQ_DATA_ADDR
// (dma_base相対、すなわちMLX5_DMA_BASE領域内=Device-nGnRnE)は、
// mlx5_net_poll_recv()がここから読み出すコピーで「非キャッシュ領域からの
// 読み出しが遅い」という、TX側でzero-copy化する前に踏んだのと同型の
// コストを負っていた(実機`ts`計測で示唆、CLAUDE.md「RXバッファは本当に
// キャッシュ可能RAMになっているか」節参照)。実際のRQ DMA先バッファを
// board.hのMLX5_RQ_CACHE_BASE(通常のNormal cacheable RAM、
// NVMET_INSTANCES_BASE領域の直後)へ移す -- PCIe1のインバウンドRC_BAR2窓
// (pcie1.c)はCPU物理アドレス空間全体に対する単純なオフセット変換のため、
// MLX5_DMA_BASE領域内に限らずどこでもDMA先として有効(mlx5_dma_addr()の
// コメント、board.hのMLX5_RQ_CACHE_BASEコメント参照)。
//
// 上記の旧MLX5_RQ_DATA_ADDR(dma_base相対、Device領域)は、後続の
// MLX5_SQ_CQ_BUF_ADDR等のレイアウト計算を変更しないよう、予約領域として
// そのまま残す(実際には未使用、約2.5MB/PFが無駄になるがMLX5_DMA_SIZE
// [128MB]の予算に対しては無視できる)。

// CREATE_SQ用の専用CQ(送信完了確認用)。RQ用のMLX5_CQ_BUF_ADDR/DBR_ADDRとは
// 別の独立したCQ -- 実ドライバもTX/RXで別々のCQを使う(en/params.cの
// mlx5e_build_tx_cq_param()/mlx5e_build_rx_cq_param()参照、詳細はmlx5.cの
// mlx5_create_sq()コメント参照)。RQ用データバッファの直後に配置。
//
// 実機で見つかった本物のバグ(修正済み): 「MLX5_RQ_DATA_ADDRは4096アライン」
// という上のコメント(旧)を信じてその直後に素朴に置いたところ、実際には
// MLX5_RQ_DATA_ADDRはMLX5_RQ_DBR_ADDR(4096アライン)+64バイト(ドアベル
// サイズ)であり4096アラインではなかった(RQ自身はWQEごとのdata_seg.addr
// で個々に参照するためアラインが不要で実害が無かっただけ)。CREATE_CQは
// log_page_size=0(4KBページ単位)でpas[0]を渡すため、CQバッファのアドレス
// 自体は4096バイト境界が必須 -- 実機でCREATE_CQ(SQ)がBAD_PARAM_ERR
// (status=0x03)で拒否されて発覚した(MLX5_RQ_WQE_ADDR/MLX5_SQ_WQE_ADDRで
// 既に踏んだのと同じバグの再発、上記コメント参照)。MLX5_RQ_DATA_ADDRの
// コメントも「4096アライン」は誤りだったため訂正した。
// 2026-08-11、RQ用と同じ理由(上記MLX5_CQ_BUF_SIZEコメント参照)で
// 64→1024エントリへ拡張。
#define MLX5_SQ_CQ_BUF_SIZE 65536u
#define MLX5_SQ_CQ_DBR_SIZE 64u

// 2026-08-09、CQバッファ+ドアベルレコードのキャッシュ可能領域移行
// (ユーザーへの生TCPスループット・ネック説明の過程で発見)。実機`ts`計測で
// CQE刈り取り+CQドアベル更新1回(mlx5_net.cのMTXCタグ)あたり約14-19us
// かかっており、ペイロードがほぼ0バイトのadminキューkeepaliveパケットでも
// 同水準の遅延が観測された -- データ量に無関係な固定コストであり、上記
// MLX5_RQ_DATA_CACHE_ADDRで対策したのと同型の「Device-nGnRnE[MLX5_DMA_BASE
// 領域内]への非キャッシュアクセスが遅い」問題。上記のMLX5_CQ_BUF_ADDR/
// MLX5_CQ_DBR_ADDR(RQ用)・MLX5_SQ_CQ_BUF_ADDR/MLX5_SQ_CQ_DBR_ADDR(SQ用)は
// 後続レイアウト計算を変更しないよう予約領域としてそのまま残し(未使用)、
// 実際の作成先はboard.hのMLX5_CQ_CACHE_BASE(通常のNormal cacheable RAM)
// 側の下記マクロへ切り替える。
// 注意: 上記MLX5_RQ_DATA_CACHE_ADDR等と異なり、このマクロ族は
// `(dma_base - MLX5_DMA_BASE)`という減算ベースの計算のため、他の
// (baseへの単純加算だけの)マクロ群で使われる`(0)`によるテストパターンは
// 使えない(0 - MLX5_DMA_BASEがuint64_tの下でアンダーフローし、桁違いの
// 値になる)。PF0の実際のdma_base(=MLX5_DMA_BASEそのもの、減算結果が
// ちょうど0になる)をテスト値として使う。
// MLX5_CQ_CACHE_BASEを差し引いてPF内相対オフセットへ戻してから比較する
// (CACHE_ADDR系マクロは絶対アドレスを返すため、そのままでは
// MLX5_CQ_CACHE_PF_SIZEという「PF内予算」とは比較できない)。

// CREATE_SQ用のWQE(Work Queue Entry)リング。RQのWQE(16バイト固定の
// mlx5_wqe_data_seg)と異なり、SQのWQEは64バイト固定のWQEBB(Work Queue
// Entry Basic Block、qp.hのMLX5_SEND_WQE_BB)単位 -- log_wq_stride=
// ilog2(64)=6固定(Linux en/params.cのmlx5e_build_sq_param_common()を
// 実際に確認済み、可変にはできない。2026-08-09、一度128バイト固定
// ストライドへ拡張しようとして実機でCREATE_SQがBAD_PARAM_ERRになった
// 経緯の教訓、下記MLX5_SQ_WQE_COUNTコメント参照)。
// log_wq_sz=4(16WQEBB)、テストフレーム1個の送信に十分な最小リング。
// RQのMLX5_RQ_WQE_ADDRと同じ理由(実機で見つかった本物のバグ、上記
// コメント参照)で、pas[0]がCREATE_SQでも4096バイト境界を要求するため
// 明示的に切り上げる。
#define MLX5_SQ_WQE_SIZE    4096u
// 2026-08-09、TCPゼロコピー送信(ヘッダ+データの2 data_seg構成、
// tcp_send_segment()/mlx5_net_post_frame()参照)対応。可変長WQE(1〜2
// WQEBB)にすると、CQEのwqe_counterからWQEBB単位のcc値を復元する必要が
// 生じ複雑化するため、「偶数アライン方式」(ユーザー承認済み)を採用:
// **常に1論理WQEにつき2 WQEBB固定で消費する**(ds_cnt=4の従来経路
// [frag_count==1]も、後半のWQEBBを未使用のまま空費する)。これにより
// CQE1件=論理WQE1件の完了、という従来の単純な1:1対応をそのまま維持
// でき、sq_pc/sq_ccは以前と同じ「論理WQE単位」のカウンタのままでよい
// (mlx5_net_state_tコメント参照)。
// この定数は「論理WQEエントリ数」を表す(以前は16=WQEBB数と同義
// だったが、2WQEBB固定化により意味が変わった)。物理WQEBB総数は
// MLX5_SQ_WQE_COUNT*2=16のまま、mlx5.cのmlx5_create_sq()の
// log_wq_sz=4(2^4=16 WQEBB)と対応する。トレードオフとしてSQの
// 実質同時アウトスタンディング数が16→8へ半減するが、NVMe/TCP write
// はdepth=8で既に実測確認済みの水準のため実害は小さいと判断
// (CLAUDE.md「NVMe/TCPコマンドパイプライン化」節参照)。
#define MLX5_SQ_WQE_COUNT   8u
#define MLX5_SQ_DBR_SIZE    64u

// 送信テストフレーム本体(最小Ethernetフレーム、IEEE802.3最小フレーム
// サイズ60バイトへゼロパディング、FCSはHWが付加する)。mlx5_sq_send_
// test_frame()(診断用、`mlx5`コマンド)専用 -- 下記MLX5_NET_TX_STAGE_ADDR
// (mlx5_net.c、TCP/IPスタック統合用の実送信経路)とは別の領域。
#define MLX5_SQ_TX_FRAME_SIZE 64u

// mlx5_net.c(TCP/IPスタック統合用のnic_ops_tバックエンド、CLAUDE.md
// 「TCP/IPスタックのConnectX統合」節参照)が使う低頻度フォールバック用
// ステージバッファ。ジャンボフレーム対応のためMLX5_JUMBO_MAX_LEN(10240)
// バイトを確保する。
//
// 2026-08-09、ゼロコピー送信への変更時に一度「単一の共有バッファ」へ
// 縮小したが、実機で本物のバグとして踏み、WQEスロットごと
// (MLX5_SQ_WQE_COUNT個)の専用バッファへ差し戻した(下記「実機で発見した
// 本物のバグ」参照)。このバッファが実際に使われるのは、(1)frag_count>1
// (複数フラグメントの連結、現状このコードベースに呼び出し元は存在しない、
// eth.hのETH_TX_MAX_FRAGSコメント参照)、(2)IEEE802.3最小フレーム長
// (60バイト)未満でパディングが必要なケース、の2パターン。
//
// **実機で発見した本物のバグ(2026-08-09、単一共有バッファ版で発生・
// 修正済み)**: 「(2)は同期送信(mlx5_net_send_frags())経由でのみ発生する
// ため単一バッファで安全」という当初の想定は誤りだった -- tcp.cの
// tcp_send_segment()はデータ長に関わらず常に非同期送信
// (eth_send_frags_async())を呼ぶため、ペイロード無しの純粋なACK等
// (IPヘッダ20B+TCPヘッダ20B=40B<60B)も非同期経路でフォールバックへ
// 入る。単一共有バッファのままだと、admin/IO両キューの小さいACK等が
// 短時間に連続すると、前のACKのWQEをHWがまだ読み終えていないうちに
// 次のACKが同じバッファへ上書きしてしまう -- 実機のNVMe/TCPループバック
// テスト(admin+IO両キューが同一PFのSQを共有)で「[IP]ヘッダチェック
// サム不正」「[TCP]チェックサム不正」が実機で複数回再現した(生TCP単一
// コネクションのtcploopbenchでは一度も再現しなかった -- ACK等の小さい
// 制御セグメントの発生頻度がtcploopbenchでは低かったため、レース自体は
// 存在してもほぼ踏まなかっただけだった)。fcs_err/align_errは共に0の
// まま(物理層は正常、ワイヤ上で壊れたのではない)、`ts type MTXE`/
// `MTXR`もゼロ件(SQ自体は一度もエラー/自動復帰していない)を確認した
// 上で、ソフトウェア側のバッファ生存期間レースだと結論した。
// **修正**: WQEスロットごとの専用バッファへ戻し、フォールバック経路も
// ゼロコピー経路と同じスロット(pc % MLX5_SQ_WQE_COUNT)で排他されるように
// した -- mlx5_net_tx_wait_free_slot()/mlx5_net_sq_wait_room()による
// 「そのスロットの前回占有者のHW処理完了待ち」が、フォールバック経路にも
// 等しく適用される。
//
// 実際のTCPデータセグメント送信(頻度が高く、性能を左右する経路)は
// frag_count==1かつ60バイト以上のため、このバッファを一切経由しない
// ゼロコピー経路を通る -- mlx5_net_post_frame()は呼び出し元のバッファ
// (frags[0].data)をWQEのデータセグメントから直接参照する。呼び出し元
// (tcp.cのtcp_send_segment())は既にeth_tx_wait_free_slot()でスロットの
// 空き(=前回そのスロットを使ったWQEのHW処理完了)を待ってから書き込んで
// おり、dcache_clean_range()でDMAコヒーレンシも確保済み(eth.hの
// eth_send_frags()呼び出し規約)であるため、追加のコピー・キャッシュ
// クリーンは不要 -- 2026-08-09の実機`ts`計測で、mlx5専用ステージバッファ
// (旧実装、Device-nGnRnEマップされたMLX5_DMA_BASE領域)への1セグメント
// (約9938バイト)あたりのコピーが約30-38usと、TCP/NVMe-oFパイプライン
// 全体の支配的コストだったと判明したため、この経路を廃止した(CLAUDE.md
// 「性能分析基盤の整備」節参照)。
#define MLX5_NET_TX_STAGE_SIZE MLX5_JUMBO_MAX_LEN
#define MLX5_NET_TX_STAGE_TOTAL_SIZE ((uint64_t)MLX5_SQ_WQE_COUNT * MLX5_NET_TX_STAGE_SIZE)

// **アライメント系static assertを`base=0`固定で評価している理由**:
// 全てのアドレスマクロは`base + <相対オフセットの積み上げ>`という形を
// しており、4096/1024バイトアライメントは`base`自体がその境界に整列
// している限りオフセット部分だけで決まる(`(base+off)%N == (base%N +
// off%N)%N`、`base%N==0`なら`off%N`と一致)。`mlx5_dev_t.dma_base`は
// 常に`MLX5_DMA_BASE`(4096アラインどころか2MBアライン、mmu.cのL2ブロック
// 粒度)か、そこから`MLX5_DMA_PF_SIZE`(後述、2MBの倍数)だけ進めた値の
// いずれかにしかならないため、base=0で検証しておけば実際のPF0/PF1どちら
// のbaseでも成立する。

// ============================================================================
// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)
// フェーズ(b): RC QP用DMAレイアウト。1PFあたりRC QP 1本のみ(手動QP確立
// でのping-pong検証用、将来複数QPが必要になれば既存パターンと同じ「新しい
// オフセットチェーンを追加する」方式で拡張する -- Ethernet側もRQ/SQそれぞれ
// 1本しか事前確保していない設計を踏襲)。
//
// WQEバッファはEthernet RQ/SQと異なり単一の連続領域(RQ region→SQ region
// の順) -- drivers/net/ethernet/mellanox/mlx5/core/wq.cのmlx5_wq_qp_
// create()(実際に取得して確認済み)の通り、QPは1つのWQ(Work Queue)に
// RQ/SQ両方を収める設計(RQが常に先頭、SQがその直後)。
// - RQ region: log_rq_size=8(256エントリ)×stride 16B(qpc.log_rq_stride
//   フィールド値0 = 実際のstride 2^(0+4)=16B、wq.cの`log_rq_stride =
//   MLX5_GET(qpc,qpc,log_rq_stride)+4`で確認)=4096B。
// - SQ region: log_sq_size=6(64 WQEBB)×64B(WQEBB固定サイズ)=4096B。
// 合計8192B=2ページ(log_page_size=0)、pas[0]=RQ region先頭、
// pas[1]=SQ region先頭。
#define MLX5_QP_WQE_BUF_SIZE 8192u
#define MLX5_QP_DBR_SIZE     64u   // 実際に使うのは8B(RCV counter 4B+
                                    // SND counter 4B、include/linux/mlx5/
                                    // qp.hのMLX5_RCV_DBR=0/MLX5_SND_DBR=1
                                    // で確認済み、CQドアベルとは別物)だが
                                    // 既存の64B枠規約に揃える。

// RC QP用の完了確認CQ(送受信共有)。既存のRQ/SQ用CQと同じ理由でNormal
// cacheable RAM(board.hのMLX5_QP_CACHE_BASE)に置く -- 上記MLX5_RQ_CQ_BUF_
// CACHE_ADDR等と同じ「dma_baseからPF0/PF1判別してcacheable領域側オフセット
// へ変換する」パターン。

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(d): GSI/UD QP(QP1相当)用の
// DMAレイアウト。RC QPと全く同じ理由・同じ構造(WQEバッファ=RQ region
// 4096B+SQ region 4096B、log_rq_size=8/log_sq_size=6、ドアベル64B)で
// 単純に複製する -- RC QPの領域(MLX5_QP_WQE_ADDR/MLX5_QP_DBR_ADDR)とは
// 別の、この専用の領域に置く(RC QPとGSI QPを同一PF上で同時に持てるよう
// にするため)。既存RC QP領域の終端の直後に配置。
#define MLX5_GSI_WQE_BUF_SIZE 8192u
#define MLX5_GSI_DBR_SIZE     64u

// GSI用の完了確認CQ(送受信共有)。RC QP用CQと同じ理由でNormal cacheable
// RAM(board.hのMLX5_GSI_CACHE_BASE)に置く。

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(i)続報(2026-08-13): IOキュー用
// 2本目のRC QP(mlx5_qp_t.qp_index==1)用のDMAレイアウト。1本目
// (MLX5_QP_WQE_ADDR/MLX5_QP_DBR_ADDR)と全く同じ構造を、GSI用領域の終端の
// 直後に単純に複製する(このプロジェクト一貫のパターン、上記GSI節の
// コメント参照)。

// IOキュー用RC QPの完了確認CQ(送受信共有)。board.hのMLX5_QP2_CACHE_BASE
// (RC QP用CQ領域の複製)に置く -- 既存の各*_CQ_*_CACHE_ADDRマクロと同じ
// 「dma_baseからPF0/PF1判別してcacheable領域側オフセットへ変換する」
// パターン。

// PCIE1のインバウンドRC_BAR2窓のPCI側ベース(pcie1.cのrc_bar2_offset =
// 0x1000000000ullと同値)。ConnectX(mlx5)がDMAで読み書きするアドレスは、
// このCPU物理アドレスへの単純な+0x10_00000000オフセットで届く -- RP1の
// GEMで踏んだのと全く同じ罠(eth.cのDMA_ADDR_HI32参照、CLAUDE.md「RP1
// Ethernet: DMAには64bitアドレッシングが必要」節)なので、コマンドキュー・
// メールボックス・RQ/SQ/CQのアドレスも生のCPU物理アドレスをそのまま
// 渡してはならない。mlx5.c(コマンドキュー/RQ/SQ/CQ作成)とmlx5_net.c
// (nic_ops_tバックエンド、送受信のたびにWQE/CQEのアドレスを扱う)の
// 両方が必要とするためヘッダで共有する(以前はmlx5.c内のみのstatic
// inlineだった)。
//
// x86-vfio-port(Phase 2 段階5): これが core に残る唯一の cpu->dev 変換の
// 継ぎ目。RPi5 では上記の固定オフセット(MLX5_DMA_ADDR_HI32、board.h)。
// x86-linux(Phase 3)では dev=IOMMU の IOVA でこの単純変換は成り立たない
// ため、この関数を platform で再実装する(cpu->IOVA ルックアップ、または
// dma_alloc が返す dev を各バッファに保持して直接使う)。バッファ自体の
// アドレスは既に dma_alloc 経由(固定アドレスマクロは段階1-4で全廃)。
/* x86-linux: dev=IOMMU の IOVA。cpu ポインタから IOVA を引く変換は
 * platform/x86-linux/hal_dma.c が dma_alloc の払い出し表を使って実装する。 */
uint64_t mlx5_dma_addr(const volatile void *cpu_ptr);

// SQ WQE(Send Queue Work Queue Entry)組み立てに使うハードウェア定数
// (Linux mlx5_core `include/linux/mlx5/qp.h`/`doorbell.h`より、実機で
// 検証済み -- mlx5.cのmlx5_sq_send_test_frame()コメント参照)。mlx5.c
// (診断用テストフレーム送信)とmlx5_net.c(TCP/IPスタック統合用の実
// 送信経路)の両方が同じWQEフォーマットを組み立てるため共有する。
#define MLX5_OPCODE_SEND        0x0au
// 2026-08-09、「偶数アライン方式」(MLX5_SQ_WQE_COUNTコメント参照)で
// 単一WQEBBのWQE(frag_count==1)を送る際、2つ目のWQEBBを未使用のまま
// 放置すると、HWが「次に処理すべきWQEBB」としてそこを読みに行った
// 際に有効なWQEが無く処理が止まる(実機で確認済みの本物のバグ -- CQEが
// 最初の1件しか生成されず、以降の送信が全てタイムアウトした)。
// linux-rdma/rdma-core providers/mlx5/mlx5dv.hで値を実際に確認済み。
// ctrl_segのみ(ds_cnt=1)、CQ_UPDATEフラグは立てない(このWQEBB単体の
// 完了報告は不要、メインWQEのCQ_UPDATEだけでよい)構成で使う。
#define MLX5_OPCODE_NOP         0x00u
// 2026-08-10、LSO(TCP Segmentation Offload)対応。linux-rdma/rdma-core
// providers/mlx5/mlx5dv.hでは同じ値が`MLX5_OPCODE_TSO`という名前で
// 定義されている(Linuxカーネル側のドライバ命名`LSO`と同一opcode)。
// ctrl_seg.opmod_idx_opcodeの下位8bitへMLX5_OPCODE_SENDの代わりに書く
// (mlx5_net.cのmlx5_net_post_lso_frame()参照)。
#define MLX5_OPCODE_LSO         0x0eu
// フェーズ(c)、RC QP用RDMA_WRITE/READ。linux-rdma/rdma-core
// providers/mlx5/mlx5dv.hで実際に確認済み。ctrl_seg.opmod_idx_opcode
// の下位8bitへ書く(mlx5_qp.cのmlx5_qp_post_rdma_write()/_read()参照)。
#define MLX5_OPCODE_RDMA_WRITE      0x08u
#define MLX5_OPCODE_RDMA_WRITE_IMM  0x09u
#define MLX5_OPCODE_RDMA_READ       0x10u
// LSO 1回の送信で許容する最大バイト数(ペイロードのみ、ヘッダ抜き)。
// QUERY_HCA_CAP(ETHERNET_OFFLOADS).max_lso_capが報告する実際のハード
// ウェア上限(実測は256KB程度と推定、mlx5.cのmlx5_query_hca_cap_eth_
// offloads()参照)とは別に、このプロジェクトが実際に使う値を保守的に
// 固定する(ユーザー承認済み方針 -- ETH_TX_RING_SIZE/BENCH_MAX_CHUNK等
// でも一貫して踏んできた「まず小さく、実機で確認してから広げる」)。
#define MLX5_LSO_MAX_BYTES_CAP  65536u
#define MLX5_WQE_CTRL_CQ_UPDATE 0x08u
// ハードウェア定義のWQEBB基本単位(64バイト)。WQEリング内のWQEBB
// インデックス→バイトオフセット変換に使う(`index * MLX5_SEND_WQE_BB`)。
// mlx5_net.cのTCP/IPスタック統合経路は1論理WQEあたり1〜2 WQEBBを
// 消費する可変長設計(MLX5_SQ_WQE_COUNTコメント参照)。
#define MLX5_SEND_WQE_BB        64u
#define MLX5_BF_OFFSET          0x800u

// PCI関数(物理ポート)ごとのHCAインスタンス状態。CLAUDE.md「ConnectX
// デュアルポート対応」節参照 -- このConnectXは物理ポートごとに別々の
// PCI関数(devfn=0/1)を持つマルチファンクションデバイスであり、各関数は
// 別々のBAR0(bar0_base)・別々のDMAバッファ群(x86-vfio-port Phase 2 で
// dma_alloc 経由の *_cpu フィールドへ移行、下記)を持つ、完全に独立した
// HCA インスタンスとして扱う必要がある。`mlx5_hca_bringup()`が`bar0_base`/
// `pf_index`を入力とし、残りのフィールド(生成したオブジェクトの番号・
// DMA バッファの CPU アドレス)を埋めて返す。
// pf_index(x86-vfio-port Phase 2 段階5): 旧 dma_base(固定 DMA 領域先頭)を
// 置換。dma_alloc への移行で dma_base の**アドレスとしての役割**は消え、
// 残るのは「PF0(0)か PF1(1)か」の判別だけになったため、固定アドレス値
// (MLX5_DMA_BASE ベース)ではなく素の 0/1 を持つ(x86 でも同じ形で使える)。
// aligned(16): 実機で発見した本物のバグ(2026-08-02)。mlx5_monitor_
// set_devs()(下記)の`*dst = *src;`という素朴な全体コピーを、GCC -O2が
// `ldp q0,q1,[x1]`(128bit NEON SIMDレジスタペア、16バイト境界必須)を
// 使う実装へ最適化することがある一方、この構造体は最大メンバがuint64_t
// (8バイト境界のみ保証)のため、この属性が無いと個々の実体(s_dev_pf0/
// s_dev_pf1/s_last_dev0/s_last_dev1等)がリンカにより8バイト境界にしか
// 配置されない場合がありうる -- 実際に.bssの配置がたまたま16バイト境界に
// 乗らなかったインスタンスで、実機がAlignment fault(esr=0x96000021、
// timestamp.c「ローカルスクラッチバッファへの逐次1バイト代入も
// volatileが必須」節と同種だが、こちらはフィールド単位の逐次代入では
// なく構造体まるごとのコピーがコンパイラ生成のSIMD命令で結合される
// パターン)を起こした。8バイトアラインを"たまたま"16バイトアライン
// でも満たしていたことに依存するのではなく、型自体に16バイトアライン
// を明示することで、この構造体のあらゆるインスタンス(グローバル/
// ローカル/引数として渡されるポインタ先いずれも)について、この種の
// コンパイラ最適化が常に安全になるようにした。
/* マルチコネクション/受信並列化(2026-08-15): PFあたりの RX キュー数。
 * 各 RQ は専用の CQ・受信データ/WQEリング・ドアベル・TIR を持ち、フロー
 * ステアリングで接続(L4宛先ポート)ごとに担当RQへ振り分け、担当コアが
 * 専任ポーリングする。まず2(2 initiator コア+2 target コア)、後で16へ。 */
#define MLX5_NUM_RXQ 2u
typedef struct {
    uint32_t  cqn;         // このRQ専用のCQ
    uint32_t  rqn;
    uint32_t  tirn;
    uintptr_t cq_buf_cpu;  // 旧 dev->rq_cq_buf_cpu
    uintptr_t cq_dbr_cpu;  // 旧 dev->rq_cq_dbr_cpu
    uintptr_t data_cpu;    // 旧 dev->rq_data_cpu(受信データバッファ)
    uintptr_t wqe_cpu;     // 旧 dev->rq_wqe_cpu(WQEリング)
    uintptr_t dbr_cpu;     // 旧 dev->rq_dbr_cpu(RQドアベル)
} mlx5_rxq_t;

typedef struct {
    uint64_t bar0_base;     // このPFのBAR0 CPUアドレス
    uint8_t  pf_index;      // 0=PF0 / 1=PF1(旧 dma_base の PF 判別用途を置換)
    uint32_t fw_pages_used; // MANAGE_PAGES(GIVE)で既に譲渡したページ数(PFごとに独立)
    uint32_t uarn;
    uint32_t eqn;
    uint32_t pdn;
    uint32_t mkey;
    mlx5_rxq_t rxq[MLX5_NUM_RXQ];  // RX キュー配列(旧 cqn/rqn/tirn/rq_*_cpu を集約)
    uint32_t tdn;
    uint32_t tisn;
    uint32_t sq_cqn; // SQ用CQ(RQ用とは別)
    uint32_t sqn;
    // 2026-08-09、ジャンボフレーム対応: mlx5_hca_bringup()がPMTUレジスタ
    // (mlx5.cのmlx5_set_port_mtu())で実際に設定できたワイヤ上の最大
    // フレーム長(ETH_HLEN込み、admin_mtuと同じ規約)。実機ではHW上限
    // (max_mtu)がMLX5_JUMBO_MAX_LEN(10240)より小さい場合がある(実測
    // 10000)ため、mlx5_netif_setup()がnetif_t.mss_capをこの値から
    // 逆算する -- 固定でTCP_MSS_LOCAL(10182)相当を使うと、実際のワイヤ
    // 上限を超えるTCPセグメントを送ってしまう(PMTUはRXだけでなくTXにも
    // 適用される可能性が高く未検証、安全側に倒す)。PMTU設定/クエリが
    // 両方失敗した場合は標準Ethernet(非ジャンボ)相当の1518へフォール
    // バックする。
    uint32_t port_mtu;
    // 2026-08-09、MTXC/MRXF待ち(SQ/RQ完了ポーリングのdelta)がソフト
    // ウェア側のポーリング粒度由来かHW処理時間由来かを切り分けるための
    // 「方針1」(CLAUDE.md「MTXC/MRXF待ち改善の検討方針」節参照)。
    // struct mlx5_ifc_cmd_hca_cap_bits(Linux include/linux/mlx5/
    // mlx5_ifc.h、このセッションで実際に取得して確認済み)の
    // device_frequency_khz(ビットオフセット0x4e0=1248→バイトオフセット
    // 156、u8[0x20]=4バイト、cmd_hca_cap_bits単体の先頭からの相対値)を
    // mlx5_hca_bringup()がQUERY_HCA_CAP(general)の応答から読み取って
    // 格納する。CQEのtimestamp_h/timestamp_l(struct mlx5_cqe64、Linux
    // device.hのget_cqe_ts()で確認したbyte48-55のペア)はこの周波数
    // (kHz)で刻むフリーランニングカウンタ(mlx5_real_time_mode()が
    // falseの通常構成、drivers/.../lib/clock.cで確認済み)なので、
    // delta_ns = delta_cycles * 1000000 / clock_khzで変換できる。
    // 0ならクエリ失敗/値が0だったことを示し、HW-domain計測はスキップする
    // (mlx5_net.c参照) -- 実機で実際に非ゼロの妥当な値が返るかは
    // 未検証のまま、憶測で使わないこと。
    uint32_t clock_khz;
    // 2026-08-10、LSO対応。mlx5_hca_bringup()がQUERY_HCA_CAP
    // (ETHERNET_OFFLOADS)から読んだmax_lso_cap(5bit、1<<値が最大バイト数)
    // を`MLX5_LSO_MAX_BYTES_CAP`でクランプした値。0ならLSO非対応
    // (クエリ失敗、またはHWがmax_lso_cap=0を報告)。
    uint32_t max_lso_bytes;
    // 2026-08-12、RC QPのRDMA_READ同時実行数(RRA/RESPONDER RESOURCES)
    // パイプライン化調査で発見: RTR2RTS_QPのlog_rra_max/log_sra_maxを
    // ハードコード値(2、4件のつもり)で送っていたが、実機のこのHCAは
    // log_max_ra_res_qp=0(=1件、responderとして同時に受け付けられる
    // RDMA_READ/ATOMIC数の上限)を報告した -- ハードコード値(4)を要求
    // すると、要求自体はエラーにならず通ってしまうが、実際には未定義
    // 動作(タイミング依存でREMOTE_INVAL_REQ_ERRを引き起こす)になる。
    // 以後はここに格納した実際のcapability値でクランプすること
    // (CLAUDE.md「nvmermabenchのボトルネック切り分け」節以降参照)。
    uint8_t log_max_ra_req_qp; // 自分がinitiatorとして持てる同時RDMA_READ/ATOMIC数
    uint8_t log_max_ra_res_qp; // 自分がresponderとして受け付けられる同時RDMA_READ/ATOMIC数
    // 2026-08-12、nvme_rdma.cの接続再利用機構向け: `mlx5_hca_bringup()`
    // が呼ばれるたび(=`net init mlx5`/`mlx5`が実行されるたび)に1つ
    // インクリメントする世代番号。ConnectX自身のFW状態は`pcie1 reset`
    // でしか初期状態へ戻らず(CPU側のリセット/チェインロードでは一切
    // 変化しない、CLAUDE.md「ConnectX(mlx5) HCA初期化」節参照)、この
    // 世代番号が変わっていなければ「前回このdevで確立したRC QP/PD/MKey
    // 等のFWオブジェクトはまだ有効なはず」と判断してよい -- 変わって
    // いれば(pcie1 reset+net init mlx5をやり直した)、古いオブジェクト
    // ハンドルは全て無意味な値になっているため再利用してはならない。
    uint32_t bringup_generation;

    /* Phase 2 (x86-vfio-port): QP系CQ(RC QP 1本目/2本目/GSI)の完了確認CQ
     * バッファ+ドアベルレコードの CPU アドレス(COHERENT DMA アリーナから
     * dma_alloc で確保)。従来の MLX5_{QP,QP2,GSI}_CQ_{BUF,DBR}_CACHE_ADDR
     * (dma_base 相対の固定オフセット)を置換 -- mlx5_hca_bringup() が PF
     * ごとに初回のみ確保(mlx5.c の関数内 static 経由で冪等)しここへ設定。
     * dev アドレスは使用箇所が mlx5_dma_addr() で計算する(段階移行の最後に
     * dma_base と共に整理する)。 */
    uintptr_t qp_cq_buf_cpu;
    uintptr_t qp_cq_dbr_cpu;
    uintptr_t qp2_cq_buf_cpu;
    uintptr_t qp2_cq_dbr_cpu;
    uintptr_t gsi_cq_buf_cpu;
    uintptr_t gsi_cq_dbr_cpu;

    /* Phase 2 段階3 (x86-vfio-port): Ethernet(mlx5_net)経路の RQ/SQ 完了確認
     * CQ バッファ+ドアベルと、RQ 受信データバッファ(NIC が DMA する実体)の
     * CPU アドレス(いずれも COHERENT DMA アリーナから dma_alloc)。従来の
     * MLX5_{RQ,SQ}_CQ_{BUF,DBR}_CACHE_ADDR / MLX5_RQ_DATA_CACHE_ADDR を置換。
     * 段階2の QP 系 CQ と同じ流儀で mlx5_hca_bringup() が PF ごと初回のみ確保。
     * dev アドレスは使用箇所が mlx5_dma_addr() で計算する。 */
    uintptr_t sq_cq_buf_cpu;
    uintptr_t sq_cq_dbr_cpu;

    /* Phase 2 段階4 (x86-vfio-port): DEVICE(Device-nGnRnE)アリーナのバッファ
     * 群 -- bring-up の中核(cmdq/mailbox/fw_pages/EQ)と各種 WQE リング/
     * ドアベル/TX ステージ。従来の dma_base 相対固定オフセットマクロ
     * (MLX5_CMDQ_ADDR/MLX5_{IN,OUT}_MBOX_ADDR/MLX5_FW_PAGES_ADDR/
     * MLX5_EQ_BUF_ADDR/MLX5_{RQ,SQ}_{WQE,DBR}_ADDR/MLX5_SQ_TX_FRAME_ADDR/
     * MLX5_NET_TX_STAGE_ADDR/MLX5_{QP,QP2,GSI}_{WQE,DBR}_ADDR)を置換。
     * mlx5_hca_bringup() が PF ごと初回のみ DMA_DEVICE アリーナから確保。
     * mailbox/fw_pages/net_tx_stage はチェイン/インデックスの先頭(各要素は
     * base + i*要素サイズ)。dev アドレスは使用箇所が mlx5_dma_addr() で計算。 */
    uintptr_t cmdq_cpu;
    uintptr_t out_mbox_cpu;   /* チェイン先頭。ブロック i = base + i*MLX5_CMD_MBOX_ALIGN */
    uintptr_t in_mbox_cpu;
    uintptr_t fw_pages_cpu;   /* 先頭。ページ idx = base + idx*MLX5_FW_PAGE_SIZE */
    uintptr_t eq_buf_cpu;
    uintptr_t sq_wqe_cpu;
    uintptr_t sq_dbr_cpu;
    uintptr_t sq_tx_frame_cpu;
    uintptr_t net_tx_stage_cpu; /* 先頭。スロット slot = base + slot*MLX5_NET_TX_STAGE_SIZE */
    uintptr_t qp_wqe_cpu;
    uintptr_t qp_dbr_cpu;
    uintptr_t gsi_wqe_cpu;
    uintptr_t gsi_dbr_cpu;
    uintptr_t qp2_wqe_cpu;
    uintptr_t qp2_dbr_cpu;
} __attribute__((aligned(16))) mlx5_dev_t;

// mlx5_qp_modify_rtr2rts()が実際に設定するRC QPの同時RDMA_READ/ATOMIC数
// (min(log_max_ra_req_qp, log_max_ra_res_qp)、mlx5.cのコメント参照)を
// 線形値で返す。RDMA_READをソフトウェア側でこの数までしか同時発行しない
// よう自前でスロットリングする必要がある呼び出し元(nvmet_rdma.cの
// パイプライン化データ移動等)向け。
uint32_t mlx5_qp_max_concurrent_rdma_read(mlx5_dev_t *dev);

// ConnectX-4 Lx (mlx5) HCA初期化。
//
// `dev->bar0_base`/`dev->dma_base`を呼び出し元が設定済みであることが
// 前提(pcie1_assign_bar0_at()でBAR0を割り当てた後、対応するCPUアドレスと
// このPF専用のDMA領域先頭を入れておく)。ENABLE_HCA〜フローステアリング
// 〜CREATE_SQ/MODIFY_SQ〜PAOSでのadmin状態UP設定〜oper_status(リンク
// アップ)待ちまでを行い、`dev`の残りフィールド(uarn/eqn/pdn/mkey/cqn/
// tdn/tisn/rqn/tirn/sq_cqn/sqn)を埋める。実際のフレーム送受信テストは
// 含まない(2つのPF両方のbringupが終わってからクロスポートで検証する
// 設計、下記mlx5_dual_port_bringup_and_test()参照)。
// `label`はログ出力の区切り(例"PF0(port1)")にのみ使う。
// 成功時0、失敗時負値を返す。
// 一時的な実験用フラグ(2026-08-13、原因特定後に削除すること) --
// mlx5_hca_bringup()内のcatch-all FTE(Ethernet受信ルール)設定を
// スキップするかどうか。`mlx5fteskip <0|1>`シェルコマンドから設定する。
extern int g_mlx5_skip_fte_experiment;

// monitor_only=1: INIT_HCA以降のデータパス資源作成をスキップした軽量版
// (HWモニタ用、温度/エラー/PCIe/リンク状態の読み出しだけに必要な最小限)。
// 通常の送受信を行う呼び出しは 0 を渡すこと。
int mlx5_hca_bringup(mlx5_dev_t *dev, const char *label, int monitor_only);

// SQ(dev->sqn)がERROR状態に落ちている場合、MODIFY_SQ(ERR->RST)→
// MODIFY_SQ(RST->RDY)で復帰させる(macb_main.cのTHALT相当、
// ~/.claude/plans/wondrous-baking-gadget.md「mlx5net TX回復ロジック」
// 節参照)。mlx5_net.cが送信完了待ち(CQE)のタイムアウトを検出した際に
// 呼ぶ -- タイムアウト自体はソフトウェア側の推測(1秒待っても完了
// しない)に過ぎないため、まずQUERY_SQで実際にERROR状態かを確認してから
// 復帰処理を行う(RDYのまま単に遅いだけの場合に無用な状態遷移をしない
// ため)。
// 戻り値: 0=ERROR状態から正常にRDYへ復帰(または既にRDYだった)、
// 負値=クエリ/復帰コマンド自体が失敗(HW自体が応答不能な、より深刻な
// 状態の可能性)。呼び出し元は成功時、ソフトウェア側のWQE生成/消費
// カウンタ(sq_pc/sq_cc相当)を0へリセットすること -- RST遷移でHW側の
// WQEカウンタもリセットされるため。
int mlx5_recover_sq(mlx5_dev_t *dev);

// mlx5_dual_port_bringup_and_test()が最後に初期化したPF0/PF1のハンドルを
// 使い、PPCNT(Ports Performance Counters, physical port統計カウンタ)・
// QUERY_RQ/QUERY_SQ(hw_counter/sw_counter, RQ/SQのstate)・QUERY_CQ
// (producer_counter/consumer_counter)を再クエリして表示する。CQ/RQが
// 応答しない問題の調査用に、ENABLE_HCA等の非冪等なコマンドを再実行せず
// (`mlx5stat`シェルコマンドから)いつでも呼べる。dual_port_bringup_and_
// test()がまだ一度も成功していなければその旨を表示するだけで何もしない。
void mlx5_monitor_dump_saved(void);

// mlx5_monitor_dump_saved()が使う「最後に初期化されたPF0/PF1」を外部から
// 上書きする。mlx5_net.c(TCP/IPスタック統合バックエンド、下記
// mlx5_net_init_dual_loopback()参照)がbringupしたPF0/PF1でも
// `mlx5stat`から再クエリできるようにするため。
void mlx5_monitor_set_devs(const mlx5_dev_t *dev0, const mlx5_dev_t *dev1);

// 2026-08-15、HWモニタの3行サマリ(PF0/PF1集約)。エラーが無ければ
// 「No Error」の1行、続けてEtherポートのリンク状態1行、PCIeリンク
// (速度/幅/MPS/MRRS)1行の計3行を表示する。異常のみ検出(FWアサート/
// PCIe CRC・致命的DevSta/Etherフレーム破損)し、ブリングアップ時に増える
// 良性カウンタ(tx/rx_errors, L0->recovery, link_down等)は無視する。
// register系(温度/MPCNT/PPCNT/health)はBAR0/ACCESS_REGで共通、PCIe config
// のみ読み出し機構がプラットフォーム依存なので rd(ctx,off) を関数ポインタで
// 受け取る(x86=vfio_cfg_read32、rpi5=pcie1_cfg_read32 のラッパ。cx0=PF0/cx1=PF1)。
void mlx5_monitor_summary3(mlx5_dev_t *d0, mlx5_dev_t *d1,
                           uint32_t (*rd)(void *ctx, uint32_t off), void *cx0, void *cx1);

/* x86-vfio-port Phase 5: 既に bring-up 済みの 2 PF を net_ctx(mlx5-pf0/pf1)
 * として登録する -- mlx5_net_init_dual_loopback() から pcie1 bring-up 部分を
 * 除いた「登録のみ」版。x86 は VFIO で bring-up 済みの dev を渡して呼ぶ
 * (RPi5 の pcie1 経由 bring-up を使わないため)。IP/MAC は dual-loopback と
 * 同一(pf0=192.168.101.10/…10:10、pf1=192.168.101.11/…10:11)。 */
int mlx5_net_register_dual(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

// ============================================================================
// フェーズ(a): RoCEv2アドレッシング土台(GIDテーブル)。ConnectX RoCEv2
// NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)フェーズ(a)。
// 実装・バイトオフセットの根拠はmlx5.cの各関数コメント参照。
// ============================================================================

// IPv4-mapped IPv6形式のRoCEv2 GID(::ffff:a.b.c.d)を構築する。
void mlx5_build_roce_gid_v4(uint32_t ipv4_host_order, uint8_t out_gid[16]);

// SET_ROCE_ADDRESS(opcode 0x761)でGIDテーブルのindexへgid/macを書き込む。
// roce_version=RoCEv2固定、roce_l3_type=IPv4固定。
int mlx5_set_roce_address(mlx5_dev_t *dev, uint32_t index, const uint8_t gid[16], const uint8_t mac[6]);

// ============================================================================
// フェーズ(b): RC QP(mlx5.cに実装 -- FWコマンド[mlx5_cmd_exec()]を発行する
// 全ての関数は既存のmlx5_hca_bringup()等と同じくこのファイルに置く、という
// 既存アーキテクチャ上の境界を踏襲する。WQE組み立て/ドアベル/CQEポーリング
// [FWコマンド不要、純粋なメモリ/MMIO操作]はmlx5_net.cと同じ役割分担で
// src/mlx5_qp.c[新規]に置く)。
// ============================================================================

// 1本のRC QPが持つソフトウェア側の状態。mlx5_dev_t(Ethernet用の固定
// リソースセット)とは独立 -- pd/uar/mkey/cqも専用に新規作成し、既存の
// dev->pdn/uarn/mkey/cqnには一切触れない(影響範囲を局所化)。
typedef struct {
    int      in_use;
    uint32_t qpn;
    uint32_t pdn;
    uint32_t uarn;
    uint32_t mkey;        // rw/rr有効なQP専用MKey(既存Ethernet用MKeyとは別)
    uint32_t cqn;         // 送受信共有CQ
    uint32_t sq_pc;       // 投稿した送信WQE数の累積(常に単純増加、mlx5_net_state_tと同じ規約)
    uint32_t rq_pc;       // 投稿したRECV WQE数の累積
    uint32_t cq_cc;       // 共有CQの消費カウンタ(送受信の完了が同じCQ
                           // リングへ混在して届くため、sq/rq個別ではなく
                           // 1つの通し番号で消費する)
    uint32_t local_psn;   // 自分のnext_send_psn初期値(乱数)
    uint32_t remote_qpn;
    uint32_t remote_psn;  // 相手のnext_send_psn(手動設定またはCM経由で受け取る、フェーズb/e)
    uint8_t  remote_gid[16]; // IPv4-mapped IPv6 (RoCEv2)
    uint8_t  remote_mac[6];
    uint16_t remote_udp_sport;
    uint8_t  local_gid_index;
    // フェーズ(d): UD/GSI(QP1相当)QP用。RC QPでは未使用(0のまま)。
    // st(qpc.st、mlx5.cのMLX5_QP_ST_UD/MLX5_QP_ST_QP1と同値)はどちらの
    // create関数で作られたかで暗黙に決まるため、ここでは実際に使う
    // qkeyだけを保持する(SEND WQEのAV/RST2INIT_QPの両方が参照する)。
    uint32_t qkey;
    // フェーズ(i)続報(2026-08-13): RC QPが1PFあたり複数本(admin queue用/
    // IOキュー用)必要になったことを受け追加。mlx5_qp_create_rc()の
    // qp_index引数の値をそのまま保持し、以後のWQE投稿/CQEポーリング
    // (mlx5_qp.c)がどのDMAアドレスチェイン(MLX5_QP_WQE_ADDR系 vs
    // MLX5_QP2_WQE_ADDR系、下記参照)を使うべきかをこのフィールドだけで
    // 判断できるようにする(呼び出し元に毎回インデックスを持ち回らせない
    // ため)。GSI/UD QPでは常に0のまま(GSI用の別アドレスチェインは
    // qp_indexを見ない)。
    uint8_t  qp_index;
    /* RoCE path MTU(IB_MTU値: 1=256/2=512/3=1024/4=2048/5=4096)。
     * mlx5_qp_modify_init2rtr()がqpc[8]のmtuフィールドに使う。0(未設定、
     * 既定)ならIB_MTU_1024へフォールバックする -- RC接続の両端は同じ
     * path MTUを使わねばならず(IBTA)、passive側(nvmetrdmastart)は相手の
     * CM REQが広告したPATH_PACKET_PAYLOAD_MTU(rdma_cm.cのpeer_path_mtu)を
     * ここへ設定してから init2rtr を呼ぶ。これを怠り 1024 固定にすると、
     * host が jumbo(MTU9000→path MTU 4096)で接続してきた場合に、複数
     * パケットになる RDMA_WRITE(Identify応答等)が host 側で
     * REMOTE_INVAL_REQ_ERR として拒否される(2026-08-14実機で確認)。 */
    uint8_t  path_mtu;
} mlx5_qp_t;

// mlx5_qp_t.qp_indexに応じてWQE/ドアベル/CQアドレスチェインを選ぶ
// ヘルパー(mlx5.c/mlx5_qp.cの複数箇所[CREATE_QP、WQE投稿、CQEポーリング]
// から共通で使う、呼び出し元に毎回`qp_index==0 ? MLX5_QP_*_ADDR(...) :
// MLX5_QP2_*_ADDR(...)`を書かせないための集約)。qp_index>=2は未対応
// (現状admin/IOの2本のみ、呼び出し元は0/1のみを渡すこと)。mlx5_dev_t/
// mlx5_qp_tの両方が完全に定義された後(このファイルの末尾寄り)に置く
// 必要がある -- 定義前に参照すると"unknown type name"になる。
static inline uint64_t mlx5_qp_wqe_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_wqe_cpu : (uint64_t)dev->qp2_wqe_cpu;
}
static inline uint64_t mlx5_qp_dbr_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_dbr_cpu : (uint64_t)dev->qp2_dbr_cpu;
}
static inline uint64_t mlx5_qp_cq_buf_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_cq_buf_cpu : (uint64_t)dev->qp2_cq_buf_cpu;
}
static inline uint64_t mlx5_qp_cq_dbr_addr(const mlx5_dev_t *dev, const mlx5_qp_t *qp) {
    return (qp->qp_index == 0) ? (uint64_t)dev->qp_cq_dbr_cpu : (uint64_t)dev->qp2_cq_dbr_cpu;
}

// CREATE_QP: RC QPを1本作成する(初期状態RST)。内部でALLOC_UAR/ALLOC_PD/
// rw+rr有効なCREATE_MKEY/CREATE_CQを新規に行い、qp->{uarn,pdn,mkey,cqn,qpn}
// を埋める。qp->local_psnは乱数(timer_now()ベース)で初期化する。
// 呼び出し前にqp->in_use=0であること(スロット再利用チェックは呼び出し元
// の責務、フェーズbは1PF1QPのみのため単純な固定インスタンスで足りる)。
// qp_index(0または1、フェーズi続報で追加): このRC QPが使うDMAアドレス
// チェイン(mlx5_qp_wqe_addr()等参照) -- 1PFあたり2本目のRC QP(IOキュー用)
// を作る場合は1を渡す。qp->qp_indexへそのまま保存され、以後のWQE投稿/
// CQEポーリング(mlx5_qp.c)がこの値を見て自動的に正しいアドレスを使う。
int mlx5_qp_create_rc(mlx5_dev_t *dev, mlx5_qp_t *qp, uint8_t qp_index);

// RST2INIT_QP: pd/vhca_port_num(=1)のみ設定する。**実機で確認済み
// (2026-08-11)**: rre/rwe/raeを含めるとBAD_PARAM_ERR(syndrome=
// 0x69efe)で拒否される -- このFWではRST2INIT_QPにアクセス権を含めては
// ならない。
int mlx5_qp_modify_rst2init(mlx5_dev_t *dev, mlx5_qp_t *qp);

// INIT2RTR_QP: path_mtu(IB_MTU_1024固定)・remote_qpn・primary_address_
// path(相手のGID/MAC、GIDテーブルindex、hop_limit/udp_sport等)・
// next_rcv_psn(=remote_start_psn、相手が送ってくるSEND開始PSN)・
// min_rnr_nak・log_rra_max・rre/rwe(リモートRDMA_WRITE/READアクセス
// 許可)を設定する。呼び出し前にmlx5_set_roce_address()で自分の
// GIDテーブル(local_gid_index)へのエントリが登録済みであること。
// **実機で確認済み(2026-08-12)**: rae(atomic許可)を含めるとBAD_PARAM_ERR
// (syndrome=0x69efe)で拒否される -- ATOMIC capabilityを一切有効化して
// いないためと考えられる。rre|rwe(atomicを除く)のみなら成功する
// (CLAUDE.md「フェーズ(c)」節参照)。
int mlx5_qp_modify_init2rtr(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t remote_qpn,
                             const uint8_t remote_gid[16], const uint8_t remote_mac[6],
                             uint32_t remote_start_psn);

// RTR2RTS_QP: next_send_psn(=qp->local_psn)・retry_count/rnr_retry/
// ack_timeout/log_sra_max・pm_state(MIGRATED)を設定する。成功すればQPは
// RTS状態(データ送受信可能)になる。
int mlx5_qp_modify_rtr2rts(mlx5_dev_t *dev, mlx5_qp_t *qp);

// QUERY_QP診断拡張: このQP自身のRQ/SQでHWが実際に処理したWQE数
// (hw_rq_counter/hw_sq_wqebb_counter)とソフトウェアが投稿したWQE数
// (sw_rq_counter/sw_sq_wqebb_counter)を読む。mlx5stat/QUERY_RQ/QUERY_SQ
// はEthernetバックエンド固定のdev->rqn/dev->sqnしか見ないため、個々の
// mlx5_qp_t(RC/UD/GSI)が持つRQ/SQの状態はこちらで確認する。いずれかの
// 出力ポインタはNULLでよい。
int mlx5_qp_query_counters(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t *out_hw_rq, uint32_t *out_sw_rq,
                            uint16_t *out_hw_sq, uint16_t *out_sw_sq);

// DESTROY_QP。
int mlx5_qp_destroy(mlx5_dev_t *dev, mlx5_qp_t *qp);

// ============================================================================
// フェーズ(d): GSI/MAD/UD QP1相当(最重要リスク領域)。ConnectX RoCEv2
// NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)フェーズ(d)。
// FWコマンド(CREATE_QP等)はmlx5.c、UD WQE組み立て/CQEポーリングは
// mlx5_qp.c、という既存の役割分担を踏襲する。MAD送受信の一発診断・
// 実機プローブはsrc/mlx5_gsi.c[新規]に置く。
// ============================================================================

// CREATE_QP: GSI(QP1相当、st=0x8、drivers/infiniband/hw/mlx5/qp.cの
// to_mlx5_st()でMLX5_IB_QPT_HW_GSI->MLX5_QP_ST_QP1と確認済み)QPを1本
// 作成する。mlx5_qp_create_ud()と全く同じ手順・同じDMA領域を共有し、
// qpc.stの値だけが異なる(同一PF上でUD/GSIを同時に複数持つ設計は
// 現時点では想定していない -- どちらか一方を使う)。
int mlx5_qp_create_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp);

// RST2INIT_QP(UD/GSI共通): pd/vhca_port_num(=1)/qkeyを設定する。qkeyは
// GSIならIB_QP1_QKEY(0x80010000、include/rdma/ib_mad.hで確認済み)、
// 汎用UDなら呼び出し元が決めた任意の32bit値。
int mlx5_qp_modify_rst2init_ud(mlx5_dev_t *dev, mlx5_qp_t *qp, uint32_t qkey);

// INIT2RTR_QP(UD/GSI共通): UDはRCと異なりQPC自体に相手のQPN/GID/PATHを
// 持たない(相手のアドレスは送信WQEのAV[Address Vector]に毎回埋め込む、
// mlx5_qp_post_send_ud()参照) -- 実ドライバのmodify_to_rts()(gsi.c)が
// INIT->RTR遷移でIB_QP_STATEしか指定していないのと同じ理由で、pd/mtu/
// uar_page/cqn/dbr_addr等の常設フィールドの再送のみ行う。
int mlx5_qp_modify_init2rtr_ud(mlx5_dev_t *dev, mlx5_qp_t *qp);

// RTR2RTS_QP(UD/GSI共通): next_send_psn(=qp->local_psn)のみ設定する
// (実ドライバのmodify_to_rts()がIB_QP_STATE|IB_QP_SQ_PSNのみ指定するのと
// 同じ)。成功すればQPはRTS状態(送受信可能)になる。
int mlx5_qp_modify_rtr2rts_ud(mlx5_dev_t *dev, mlx5_qp_t *qp);

// rdma_calc_flow_label()/rdma_flow_label_to_udp_sport()(include/rdma/
// ib_verbs.h)と同じアルゴリズム(flow_label=0固定の場合のフォールバック
// 経路)。RC QPのADS(mlx5.c、フェーズ(b))とUD/GSIのAV(mlx5_qp.c、
// フェーズ(d))の両方が使うため、mlx5.c内のstaticから外部公開へ変更した。
uint16_t mlx5_calc_udp_sport(uint32_t lqpn, uint32_t rqpn);

// UD/GSI QPのSEND WQE組み立て(mlx5_qp_post_send_ud())/RECV WQE組み立て
// (mlx5_qp_post_recv_gsi())/CQEポーリング(mlx5_qp_poll_cqe_gsi())は
// 既存の役割分担(FWコマンド不要な純粋なメモリ/MMIO操作はmlx5_qp.c)通り
// mlx5_qp.h/mlx5_qp.cに置く。RECV用のbuf_lenには実ペイロード用途の長さ
// だけでなく、先頭40バイトのGRH(struct ib_grh相当、RoCEv2でも常にHWが
// 書き込む -- drivers/infiniband/core/mad.cの`recv->header.recv_wc.
// mad_len = wc->byte_len - sizeof(struct ib_grh);`で実際に確認済み)分の
// 余裕を含めること。CQEのbyte_cntにはGRH込みの長さが報告される。
#define MLX5_GRH_BYTES 40u

// ============================================================================
// フェーズ(e): RDMA CM(REQ/REP/RTU)。実際の状態機械・MAD組み立てはsrc/
// rdma_cm.c/rdma_cm.h(新規、job.hのnon-blocking契約に準拠)に置く。
// ここにあるのは`s_last_dev0/dev1`(mlx5.c内static)にアクセスする必要が
// ある`mlx5rdmacm test`シェルコマンド用の薄いラッパーのみ(既存の
// mlx5_qp_cmd_pingpong()/mlx5_gsi_cmd_test()と同じパターン)。
// ============================================================================

// mlx5_net.cのs_state_pf0/s_state_pf1(TCP/IPスタック統合バックエンド用の
// sq_pc/sq_cc)とdev->sqn/sq_cqnから、SQのCQバッファ・WQEリングの実際の
// 物理アドレスを計算し、sq_cc周辺のCQEの生バイト(op_own/wqe_counter/
// byte_cnt)と全WQEリングの先頭バイトをuart_printfで生ダンプする
// (2026-08-08、mlx5 SQ TXタイムアウトの実機調査用に追加、ロジックは
// 一切変更しない純粋な読み取り専用の診断)。pf_indexは0または1。
void mlx5_net_dump_sq_debug(int pf_index);

#endif /* MLX5_H */
