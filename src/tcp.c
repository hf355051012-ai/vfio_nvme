// tcp.c
//
// TCP (RFC 793) 実装 — フェーズ6(多重コネクション対応版)
//
// tcp.hのファイル冒頭コメント参照。tcp_conn_t自体(呼び出し側がスタックに
// 置くこともある小さな識別/ハンドシェイク状態)と、コネクションごとの
// 大きな可変ランタイム状態(受信循環バッファ・順序入れ替わり先読み・
// ACK追跡・RTT推定・輻輳制御 -- 以前はモジュール静的変数として単一
// コネクション専用に持っていたもの)を分離し、後者はtcp_conn_t*をキーに
// 引くプライベートなスロット配列(s_priv[], s_conns[]と同じインデックス)
// に保持する。これによりtcp_conn_tのサイズは変わらないまま
// (test.c/bench.cが引き続きスタックに`tcp_conn_t conn;`を安全に置ける)、
// 最大TCP_MAX_CONNS本の同時コネクションをサポートする。
//
// 全ての多バイトフィールドアクセスは net.h の rd16be/rd32be/wr16be/wr32be
// (volatile経由のバイト単位アクセス)のみを使う。理由は net.h と arp.c の
// コメントを参照(SCTLR_EL1.M=0環境でのAlignment fault対策)。
// パケットバッファ由来、または呼び出し元から渡された任意のポインタ
// (tcp_send()のbuf引数等)は、単発の1バイトアクセスであっても念のため
// volatile経由で統一している(ip_send()のvpayloadと同じ理由)。

#include <stddef.h>
#include "tcp.h"
#include "ip.h"
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

/* pull型受信の二重コピー時間計測(push vs pull 比較、検証後に撤去)。
 * copy2 = net_buf→rx_buf(tcp_rx_buf_push)、copy3 = rx_buf→呼び出し元
 * バッファ(tcp_recv_internalのドレイン、nvmet視点ではram_disk行き)。
 * command.cの`copystat`が読み出す。 */
uint64_t g_tcp_copy2_ns = 0, g_tcp_copy2_bytes = 0;
uint64_t g_tcp_copy3_ns = 0, g_tcp_copy3_bytes = 0;
void tcp_copy_stats_get(uint64_t *c2_ns, uint64_t *c2_by,
                        uint64_t *c3_ns, uint64_t *c3_by)
{
    if (c2_ns) *c2_ns = g_tcp_copy2_ns;
    if (c2_by) *c2_by = g_tcp_copy2_bytes;
    if (c3_ns) *c3_ns = g_tcp_copy3_ns;
    if (c3_by) *c3_by = g_tcp_copy3_bytes;
}
void tcp_copy_stats_reset(void)
{
    g_tcp_copy2_ns = g_tcp_copy2_bytes = 0;
    g_tcp_copy3_ns = g_tcp_copy3_bytes = 0;
}

/* マルチコア化 Phase 4(~/.claude/plans/wondrous-baking-gadget.md参照):
 * このファイルのモジュール静的状態(s_conns/s_priv/s_timewait/
 * s_listeners/s_seg_bufs/s_abort_requested/g_tcp_retransmit_count)は
 * すべて[SMP_MAX_CORES]で配列化し、各関数の先頭でsmp_core_index()を
 * 呼んで自コアのスロットだけを読み書きする(net_buf.c/timestamp.cの
 * Phase 3と同じ方針)。呼び出し側(tcp.hの公開API)のシグネチャは
 * 一切変更していない -- 「どのコアのTCP接続か」は引数ではなく実行中の
 * コアが暗黙に決める設計(Phase 6でcore0=PF0クライアント/core1=PF1
 * サーバのように、各コアが完全に独立したTCP接続集合を持つ想定)。 */

/* tcp_header_t 内のバイトオフセット (packed, 20バイト)。
 * offsetof はコンパイル時定数であり、メモリアクセスは発生しない。 */
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

/* 自分が受信可能な最大セグメントサイズ(SYNのMSSオプションで広告)。
 * 2026-07-25、ジャンボフレーム対応に合わせ1460→10182へ拡張した。
 * 導出: net_buf.hのNET_BUF_SIZE(=eth.hのETH_JUMBO_MAX_LEN=10240、実機
 * ドライバraspberrypi_rp1_config.jumbo_max_lenから取得した値)から、
 * オプション無しの1フルサイズデータセグメントが占めるヘッダ分
 * (IP_PAYLOAD_OFFSET=34 + TCP_HDR_LEN=20 = 54)を引いた10186ではなく、
 * さらに実機HWのFCS自動除去分の余裕を差し引いた10236(ETH_JUMBO_MAX_LEN-
 * FCS4バイト、net_buf.hコメント参照)を基準に54を引いた10182とした
 * (=IP_PAYLOAD_OFFSET+TCP_HDR_LEN+TCP_MSS_LOCAL = 10236、ちょうど
 * net_buf.hが実際に受信しうる最大データ長と一致する)。
 * 相手がこれより小さいMSSしか広告しない場合はtcp_parse_syn_options()が
 * min(相手の広告値, TCP_MSS_LOCAL)を採用するため、非ジャンボの相手とも
 * 引き続き相互接続できる(下位互換、tcp_parse_syn_options()参照)。
 *
 * 影響: TCP_MSS_LOCALに連動する各バッファ(s_seg_bufs、tcp_ooo_slot_t.buf、
 * 下記TCP_OOO_SLOTSコメント参照)がおよそ7倍(1460→10182)に膨らむ。
 * s_seg_bufsは2026-07-25にDMAコヒーレンシ方式を変更し.dma_bssから
 * 通常のNormal cacheable RAMへ移した(下記s_seg_bufs宣言のコメント参照
 * -- .dma_bssへの直接コピーが実測で著しく遅かったため、eth_send()と
 * 同じdcache_clean_range()方式に切り替えた)。tcp_priv_t.ooo[]も同じく
 * 通常のNormal cacheable RAM(.bss)側で、いずれも.dma_bssの2MB制約を
 * 受けない(linker.ldの.dma_bss固定アドレスまで約19.5MBの余裕がある)ため、
 * TCP_OOO_SLOTSは据え置いた(下記コメント参照)。 */
#define TCP_MSS_LOCAL           10182u
#define TCP_MSS_DEFAULT_RFC879   536u  /* 相手がMSSオプションを付けなかった場合の既定値 */

/* 同時に扱える最大コネクション数。nvmet常駐サーバ最大3系統(RP1+ConnectX
 * PF0/PF1、platform_init.c参照)がそれぞれadmin queue(qid=0)+IO queue
 * (qid=1)を同時に持ちうるため6は起動時点で予約済みになる -- `nvme
 * connect`(admin+io)や手動`nvmet`(admin+io)等の一時的な用途にも余裕を
 * 残すため12にしてある(job.hのJOB_MAX=12と揃えた値)。1コネクションあたり
 * rx_buf(TCP_RX_BUF_SIZE)+ooo[](下記TCP_OOO_SLOTS)で数百KB〜1MB強を使う
 * ため、12本でも十数MB程度でRAM予算上の問題は無い。 */
#define TCP_MAX_CONNS 12u

/* 受信バッファ(循環バッファ、コネクションごと)の容量。8セグメント分
 * (約11.7KB)だった旧値はtcpbenchの実測で明確なボトルネックだった:
 * bench_round()が1ラウンドで送る量(BENCH_MAX_CHUNK)がこのウィンドウ
 * (および相手の広告ウィンドウ)を大きく下回っていたため、tcp_send()が
 * 内部に持つcwnd主導の複数セグメント同時送信(パイプライン化、tcp.h
 * 冒頭のTier3コメント参照)が実力を出せず、「1ラウンドの往復レイテンシ」
 * が支配的要因になっていた(会話履歴のtcpbench調査参照)。44セグメント分
 * (約62.7KB)へ拡張し、相手が広告するウィンドウ(実測65535)に近い量を
 * 1ラウンドで送受信できるようにした。
 *
 * 2026-07-25、Window Scaling(RFC7323、tcp.h冒頭コメント参照)の導入に
 * 合わせて512KBへ再拡張した -- NVMe/TCPの256KB書き込み(nvmet.hの
 * NVMET_MAX_TRANSFER_BYTES)をR2T+H2CData 1ラウンドで受け切るには、
 * 256KB分を同時にバッファできる受信ウィンドウが必要なため。Window
 * Scalingが成立しないコネクション(相手がオプション未対応)向けには
 * 依然として生の16bit値(65535)にクランプして広告する(tcp_send_segment()
 * 参照) -- TCP_RX_BUF_SIZE自体が65535を超えても、クランプさえ正しく
 * 効いていれば無害(rx_read/rx_count/free_space等の内部管理はuint32_tへ
 * 拡張済み、超過分は単にscaling成立コネクションでのみ実際に使われる)。
 *
 * 2026-08-08、2MBへ再拡張(test.cのTCP_TEST_MAX_LEN拡張に伴う)。
 * tcp_loopback_test()(test.c)は「送信側のtcp_send()が完全に終わって
 * から受信側がtcp_recv()を呼び始める」設計のため、受信側のrx_bufが
 * 埋まりきるとウィンドウが0のまま開かず(相手はtcp_recv()を呼んで
 * いないためrx_countが減らない)、TCP_RX_BUF_SIZEを超える一括転送は
 * 送信側の再送上限到達で失敗する(512KB時代に524140/2097152バイトで
 * 実機確認)。実際に相手へ広告するウィンドウ値はETH_RX_RING_SIZE由来の
 * safe_window_cap(下記tcp_send_segment()参照、非ジャンボ接続で約91KB、
 * ジャンボ接続で約636KB)で別途クランプされるため、TCP_RX_BUF_SIZE
 * 自体を2MBまで拡張しても16bit windowフィールドへの書き込みが
 * オーバーフローすることはない(scaled > 0xFFFFuの保護も既存)。 */
#if defined(__aarch64__)
#define TCP_RX_BUF_SIZE (2u * 1024u * 1024u)
#else
/* x86(VFIO)は RAM 潤沢なので rx_buf を 2MB→16MB へ拡大する。write の受信側
 * (target)がバースト受信を大きく吸収でき、単一コアで受信と処理が競合しても
 * バックプレッシャが減るため、実機で 256KB write が ~1006→~1865MB/s(+85%)へ
 * 向上した(read は窓律速で ~1360MB/s のまま、下記 TCP_RCV_WSCALE 注参照)。
 * 実測での最適点は 16MB で、64MB へ増やすと逆にキャッシュスラッシングで write が
 * ~1512MB/s へ低下した。s_priv[SMP_MAX_CORES][TCP_MAX_CONNS]=2×12=24 インスタンス
 * 分なので 16MB×24≒384MB(x86 の .bss、hal_dma が VFIO で pin する)。 */
#define TCP_RX_BUF_SIZE (16u * 1024u * 1024u)
#endif

/* tcp_recv_no_ack()(send_ack=0)経由で消費したバイト数が、相手の実MSS
 * (conn->snd_mss)の何倍に達したら強制的にウィンドウ更新ACKを送るかの
 * 閾値(2026-08-07追加、tcp_priv_t.unacked_consumed_bytesコメント参照)。
 * 既存の入力側遅延ACK(unacked_full_segments、フルサイズセグメント2個で
 * 1回ACK)と同じ「2」を採用し、両方向で同じ粒度感になるよう揃えた。 */
#define TCP_RECV_NOACK_ACK_THRESHOLD_MSS 2u

/* 自分の受信ウィンドウのスケール係数(shift、SYN/SYN-ACKのWindow Scale
 * オプションで相手に広告する固定値)。TCP_RX_BUF_SIZE(512KB)>>4=32768が
 * 常に16bitのwindowフィールドに収まるよう選んだ(相手の広告ウィンドウを
 * 解釈する側のシフト量は、相手ごとに違いうるためtcp_priv_t.snd_wscaleに
 * 保持する -- 固定値ではない)。 */
/* 注(x86 VFIO、2026-08-15 に「送信経路再設計で read 高速化」を検討し不採用と結論):
 * 当初「read は窓律速で、wscale を 4→7(最大窓 ~1MB→~8MB)へ拡大すれば速くなる」と
 * 考えたが、実測で 2 つの事実が判明し不採用とした:
 * (1) **read は現状(~2090MB/s)では窓律速ではない** -- wscale=7 の実効窓は
 *     safe_window_cap により ~1.14MB(RX リング容量由来)に頭打ちで、256KB read は
 *     wscale=4(窓 1MB)と同じ ~2067MB/s のまま。窓律速なら向上するはずが、しなかった。
 * (2) wscale=7 の粗い窓(128B 粒度)は 8KB read を ~688→~180MB/s へ悪化させた。
 * また、以前 wscale=7 で 256KB read が崩壊した原因(C2HData の 24B ヘッダ[short キュー]と
 * データ[regular キュー]が別 RTO で持続的 gap を生む)を、ヘッダをデータと結合して
 * 単一 Go-Back-N キューに乗せる方式で修正してみたが、8KB read を悪化させた上に
 * (1) の通り throughput 上の利得が無いため撤回した(git 履歴参照)。
 * 結論: read の頭打ち(~2090 vs RDMA ~2860)は窓ではなく受信側(initiator)の
 * per-command 処理コストが要因と考えられ、wscale/送信経路ではなく受信処理の
 * 最適化が次の課題。wscale は 4 のまま(rpi5/x86 共通)。 */
#define TCP_RCV_WSCALE 4u

/* RTOベース再送の初期値/上下限。実測RTT(SRTT/RTTVAR)が得られるまでは
 * TCP_INITIAL_RTO_MSを使う。RFC6298のガイドラインは初期RTO=1000msだが、
 * 直結LAN環境であることを踏まえてやや短めにしている。 */
#define TCP_INITIAL_RTO_MS      500u
#define TCP_RTO_MIN_MS           200u
#define TCP_MAX_RTO_MS         8000u
#define TCP_MAX_RETRIES            5

#define TCP_SEND_OVERALL_TIMEOUT_MS 30000u  /* tcp_send()全体(複数セグメント/再送込み)の上限 */
#define TCP_CLOSE_FIN_WAIT_MS        2000u  /* 自分のFINがACKされた後、相手のFINを待つ時間 */

/* 順序が入れ替わって届いたセグメントを同時に保持できる最大件数。
 * tcp_priv_t.oooコメント参照 -- 実機のNVMe/TCPベンチマーク(16KB〜256KBの
 * write)で複数セグメントが同時に順序を崩すケースが頻発したため、
 * 1件だけの旧設計から拡張した。
 *
 * 2026-07-25、8→64へ再拡張した。Window Scaling(RFC7323)導入とETH_RX_
 * RING_SIZE拡張(256→768、eth.c参照)でRXリング枯渇を解消した後、実機の
 * fio write(iodepth>=4)で「順序不正セグメントを先読みバッファに保持」が
 * 毎回ちょうど8件(=TCP_OOO_SLOTS)で頭打ちになる事象を確認した -- 全
 * スロット使用中の場合にそれ以上のセグメントを保持できず黙って破棄する
 * 分岐(下記tcp_input()のTCP_ESTABLISHEDケース参照、2026-07-25にログ追加)
 * に達しており、実際の入れ替わり幅が8件を超えていたと推測される
 * (Window Scalingで広告ウィンドウが最大512KB相当まで広がり、ホストが
 * 送れる先行量そのものが増えたことで、以前より深い順序入れ替わりが
 * 起こりうるようになった)。破棄された分はホストの再送に頼ることになり、
 * それがスループット不安定の一因になっていたと考えられる。1件あたり
 * 最大TCP_MSS_LOCALバイトなので、64件でもコネクションあたり約93KB
 * (TCP_MAX_CONNS=4本で約374KB)に収まっていた(旧TCP_MSS_LOCAL=1460時点)。
 *
 * 2026-07-25、ジャンボフレーム対応でTCP_MSS_LOCALを1460→10182へ拡張した
 * ことに伴い、この見積もりは64件×約10182B≒約637KB(TCP_MAX_CONNS=4本で
 * 約2.5MB)まで増えている。1フレームあたりのペイロードが約7倍になった分、
 * 同じバイト量のバーストを保持するのに必要な件数は本来減らせるはずだが、
 * 実測に基づかず件数を減らすと上記(2026-07-25以前)と同じ「頭打ちに気付き
 * にくい」失敗を繰り返しかねないため、件数は据え置いた(容量が要件を
 * 満たさなくなる方向ではなく、余裕が増える方向の変化なので安全側)。
 * tcp_priv_t.ooo[]はNormal cacheable RAM(.bss)側にあり.dma_bssの2MB
 * 制約を受けない(linker.ldの.dma_bss固定アドレス0x1400000まで約19.5MBの
 * 余裕がある)ため、この増加量自体は問題にならない。 */
#define TCP_OOO_SLOTS 64u

/* tcp_send_async()(tcp.h参照)が同時にキューできる「送りっぱなし」未確認
 * セグメントの最大件数。2026-07-25、NVMe/TCPターゲット(nvmet.c)のIOキュー
 * パイプライン対応で1件だけの旧設計から拡張した -- 複数の書き込み
 * コマンドが同時にoutstandingになると、同じコネクション上でR2T/CQEを
 * 連続してtcp_send_async()する場面が増える。1件だけの追跡だと2件目以降が
 * 前の1件のACK確認を待ってブロックし、ホストの遅延ACKタイマー(標準
 * 約40ms)を毎回踏んでIOPSが劣化する実機バグを確認した(iodepth=2→4で
 * スループットが約55MB/s→約17MB/sへ悪化、レイテンシがほぼ40〜50ms刻みで
 * 積み上がっていた)。nvmet.cのNVMET_MAX_PENDING_WRITESより余裕を持たせた
 * 値にしてある(1件のoutstanding書き込みにつきR2T送信時とCQE送信完了時の
 * 2箇所でtcp_send_async()を使うため)。
 *
 * 2026-08-10、16→32へ拡張(READ性能改善、CLAUDE.md「READ性能: 生TCPとの
 * 一番大きな差分」節参照)を試したが、この時点ではTCP_ASYNC_MAX_LENが
 * まだ10182(MSS単位の手動チャンク化)だったため1PDU(256KB)あたり約27
 * チャンク必要で、32スロットでも1PDU分すら余裕を持ってキューし切れず、
 * かつ`tcp_priv_t.async_slots[]`のメモリ増分(当時約3.9MB)によると
 * 見られるキャッシュ局所性悪化で実機write性能が約173→約162MB/s
 * (約6.5%)退行したため16へ差し戻した(未解決のまま棚上げ)。
 *
 * 2026-08-11、mlx5コネクションだけスロット数を16→32(基礎16+mlx5専用
 * オーバーフロープール16)へ増やす実装(RP1は無変更のまま、ユーザー指示
 * 「RP1とMLX5で分けて、MLX5だけ増やす」)を一度実装・実機投入したが、
 * write負荷テストが必ず約4〜7コマンド目で完全にハングする退行を確認
 * した。`mlx5stat`で原因を特定: PF1のRQ用CQ(受信完了キュー、当時64
 * エントリ)が`status=9`(オーバーラン)になっていた -- スロット数を
 * 増やしたことで送信側が実際にそれだけ速くデータを押し込めるように
 * なった結果、受信側(`mlx5_net_poll_recv()`)が旧64エントリのRQ用CQを
 * 排出しきれずハードウェアのCQオーバーラン(以後そのCQは新規完了を
 * 一切生成しなくなる)を実機で誘発してしまった。
 *
 * 2026-08-11、根本対策としてRQ用/SQ用CQを64→1024エントリへ拡張済み
 * (mlx5.hのMLX5_CQ_BUF_SIZE/board.hのMLX5_CQ_CACHE_PF_SIZEコメント参照
 * -- RQのWQE深さ[mlx5.hのMLX5_RQ_NUM_WQES=256]に対して4倍の余裕、SW側の
 * 排出が完全に止まってもRQ自身が生成しうる完了数[256]を上回るため
 * 理論上オーバーランしえない)。これを受けて、mlx5コネクションだけへ
 * 追加スロットを与える設計を再度有効化する(下記TCP_ASYNC_SLOTS_MLX5_
 * EXTRA/tcp_priv_t.async_overflow_idx参照)。 */
#define TCP_ASYNC_SLOTS 16u

/* mlx5(ConnectX)バックエンドのコネクションだけに追加で与える非同期
 * 送信スロット数、および同時にこの追加分を持てるコネクション数
 * (2026-08-11、上記TCP_ASYNC_SLOTSコメント参照)。RP1はこの値を一切
 * 変更せず、基礎のTCP_ASYNC_SLOTS(16)のみを使い続ける。TCP_ASYNC_MLX5_
 * OVERFLOW_CONNSは実際に同時にmlx5経由の深いパイプラインを必要と
 * するコネクション数(このプロジェクトの実運用ではnvmet admin/io×
 * PF0/PF1 + nvme initiator admin/io、合計でも片コアあたり高々4〜6本)
 * より十分大きい値(8)を選び、枯渇時は安全側(TCP_ASYNC_SLOTS基礎値の
 * ままフォールバック、エラーにはしない)に倒す。
 * メモリ増分: SMP_MAX_CORES(2)×TCP_ASYNC_MLX5_OVERFLOW_CONNS(8)×
 * TCP_ASYNC_SLOTS_MLX5_EXTRA(16)×TCP_ASYNC_MAX_LEN(32768) ≈ 8.4MB
 * (通常のNormal cacheable RAM、`.dma_bss`の2MB単一ブロック制約とは
 * 無関係)。 */
#define TCP_ASYNC_SLOTS_MLX5_EXTRA    16u
#define TCP_ASYNC_MLX5_OVERFLOW_CONNS 8u

/* 2026-08-11、CMD/RSP/R2T/ICResp等の小さいヘッダ専用PDU向け専用プール
 * (ユーザー指示 -- NVMe/TCP write pipelineの`ts`計測で、CMD送信(72B)が
 * 進行中のH2CDataチャンク送信(最大TCP_ASYNC_MAX_LEN=32768B)と同じ
 * TCP_ASYNC_SLOTS/オーバーフロープールを奪い合い、H2C側がスロットを
 * 使い切るたびにCMD送信までブロックされる実機挙動を確認したため
 * 分離した)。上記の基礎プール/mlx5オーバーフロープールとは完全に
 * 独立した第2のFIFO(tcp_priv_t.async_short_*)として実装する --
 * 呼び出し元(nvme_tcp_send_cmd_async()/nvmet_tcp_send_icresp()/
 * nvmet_tcp_send_r2t()/nvmet_tcp_send_resp()等)は一切変更不要で、
 * tcp_send_async()がlen<=TCP_ASYNC_SHORT_MAX_LENなら自動的にこちらへ
 * 振り分ける(tcp_send_async_short()参照)。
 *
 * サイズの根拠: このプロジェクトのヘッダ専用PDUはICResp(128B)が最大
 * (CMD=72B、RSP/R2T=24〜28B)であり、512Bはこれに十分な余裕を持つ。
 * かつ実際のMSS(最小でも数百B、通常1460〜9938B)を確実に下回るため、
 * tcp_send_async()の複数チャンク分割/LSO判定ロジックを一切経由せず
 * 常に単一セグメントで送れる(tcp_send_async_short()の実装がこれを
 * 前提にしている)。TCP_ASYNC_SHORT_SLOTS(16)はNVME_IO_QDEPTH/
 * NVMET_MAX_PENDING_WRITES(いずれも8)の2倍の余裕。
 * メモリ増分: SMP_MAX_CORES(2)×TCP_MAX_CONNS×TCP_ASYNC_SHORT_SLOTS(16)×
 * (TCP_ASYNC_SHORT_MAX_LEN(512)+約20バイトの付随フィールド) -- 全
 * コネクション共通(mlx5専用ではない)で数百KB程度、無視できる規模。 */
#define TCP_ASYNC_SHORT_MAX_LEN 512u
#define TCP_ASYNC_SHORT_SLOTS   16u

/* テレメトリ用の統計カウンタ(tcp.h参照)。マルチコア化 Phase 4により
 * コアごとに独立配列化した(呼び出し元のbench.cはsmp_core_index()で
 * 自コア分を参照する)。 */
volatile uint32_t g_tcp_retransmit_count[SMP_MAX_CORES];

/* 遅延ACKの閾値(フルサイズin-orderセグメント何個に1回ACKするか)。
 * push受信では広告ウィンドウが常に最大のため、受信側(core0のread受信等)では
 * これを上げてACK送信(mlx5 SQ TX ~18us/回)を間引き、per-segment処理コストを
 * 下げられる。tcp_input()のin-order分岐が参照。
 *
 * 【2026-08-15、100GbEループバック実測で既定2→4へ変更】tcpbench 256(NVMe/TCP)で
 * 閾値を2→4→8→16とA/Bした結果、read +13.6%(4203→4776MB/s)/write +4.4%
 * (2570→2683MB/s)が閾値4で得られ、8以上は頭打ち(全ゲインを4で回収)。両方向とも
 * 退行なし。readのcore0律速の約75%はTCPセグメント処理(主体=ACK送信TX)であり、
 * ACKを毎2→毎4に間引くことでそのTX回数を半減できるのが効いた。RFC5681は「毎2
 * セグメント以内にACK」だが、自前スタック間・push受信(ウィンドウ常時最大)では
 * 送信側が詰まらないため毎4でも安全。`ackthresh`コマンドで実行時変更可。 */
volatile uint32_t g_tcp_ack_threshold = 4u;

/* 受信循環バッファの容量(tcp.h、パイプライン受信の in-flight 上限計算に使う)。 */
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

/* tcp_send_async()の「送りっぱなし」未確認セグメント1件分の保持スロット
 * (tcp_priv_t.async_slots[]参照)。TCP_ASYNC_SLOTSコメントの経緯参照。 */
typedef struct {
    uint32_t seq;      /* このセグメントの先頭seq */
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_MAX_LEN];
    /* 2026-08-15、ゼロコピー送信(tcp_send_async_ref())。呼び出し元が「ACKされるまで
     * 生存し続ける安定バッファ(例: nvmetのram_disk、C2HData read)」を保証する場合、
     * bufへコピーせずこのポインタに送信元を保持し、再送もここから行う(256KB級の
     * copyをまるごと省いてメモリ帯域を節約 -- 100GbE で律速だったメモリトラフィック
     * 削減が目的)。NULL=通常経路(buf[]のコピーを使う)。 */
    const uint8_t *ref;
    uint64_t sent_at;  /* 直近の送信(初回または再送)時刻 */
    uint32_t rto_ms;
    int      retries;
} tcp_async_slot_t;

/* tcp_async_slot_tと同じ形だが、CMD/RSP/R2T/ICResp等のヘッダ専用PDU
 * (TCP_ASYNC_SHORT_MAX_LEN以下)専用の小さいbufを持つ第2のスロット型
 * (tcp_priv_t.async_short_slots[]参照、上記TCP_ASYNC_SHORT_MAX_LEN
 * コメント参照)。 */
typedef struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_SHORT_MAX_LEN];
    uint64_t sent_at;
    uint32_t rto_ms;
    int      retries;
} tcp_async_short_slot_t;

/* コネクションごとのプライベートなランタイム状態。tcp_conn_t*(呼び出し側が
 * 所有する識別/ハンドシェイク状態)とs_conns[]/s_priv[]で同じインデックスに
 * 対応させて紐付ける(tcp_priv_for()参照)。tcp_conn_t自体には含めない
 * 理由はこのファイル冒頭コメント参照(スタックサイズ)。 */
typedef struct {
    /* 「直前に送った(再送対象の)セグメントがACKされたか」の記録。
     * SYN/FIN/純ACKのような単発の信頼送信(tcp_send_reliable())専用。
     * 複数セグメントのパイプライン送信(tcp_send())はsnd_una/ack_advanced
     * (下記)を使う -- 両者は独立していて構わない(同時に「アクティブ」
     * なのは常にどちらか一方であり、tcp_input()側は両方を無条件に
     * 更新するだけで呼び出し元が自分に関係する方だけを見る)。 */
    volatile int      ack_received;
    volatile uint32_t expected_ack;

    /* tcp_send()のパイプライン送信エンジンが使う、累積ACK進捗の状態。
     * tcp_send()呼び出しごとにその時点のconn->snd_seqへリセットされ、
     * tcp_input()が「それより後ろのACKを見た」らsnd_unaを進めて
     * ack_advancedを立てる(単発の厳密一致ではなく累積ACKとしての
     * 前進を見る、より本来のTCPらしい判定 -- tcp_seq_gt()参照)。 */
    volatile uint32_t snd_una;
    volatile int      ack_advanced;

    /* RTT推定(RFC 6298簡易版)。SRTT/RTTVARから動的にRTOを計算する。
     * 0 = 未測定(tcp_connect()ごとにリセットされる)。 */
    uint64_t srtt_us;
    uint64_t rttvar_us;
    uint32_t rto_ms;

    /* 輻輳制御(RFC 5681簡易版)。スロースタート+輻輳回避のみ実装 --
     * 重複ACKによる高速再送/高速回復はSACK等の追加情報無しでは効果が
     * 薄く複雑になるため未実装(RTOタイムアウトのみをロスシグナルと
     * して使う)。 */
    uint32_t cwnd;
    uint32_t ssthresh;

    /* tcp_recv()向けの受信バッファ(循環バッファ)。rx_readが次に読み出す
     * 位置、(rx_read+rx_count)%TCP_RX_BUF_SIZEが次に書き込む位置。
     * TCP_RX_BUF_SIZEが512KB(65535を超える)に拡張されたため、rx_read/
     * rx_countはuint16_tのままだと静かに切り詰められる -- uint32_tへ
     * 拡張済み(2026-07-25、Window Scaling導入時)。 */
    uint8_t           rx_buf[TCP_RX_BUF_SIZE];
    volatile uint32_t rx_read;
    volatile uint32_t rx_count;
    volatile int      fin_received;

    /* 受信upcall(inline receive、二重コピー削減の基盤、2026-08-13):
     * このコネクションにupcallが登録されていると、tcp_input()はin-orderで
     * 届いたデータをrx_bufへ積む代わりにupcall(recv_upcall_ctx, data, len)を
     * *その場で*呼ぶ。ULP(nvmet等)はストリームをパースしながら最終バッファ
     * (ram_disk等)へ直接配置できる -- rx_bufステージング(copy2)+別ジョブの
     * drain(copy3)という二重コピーを回避する(tcp.hのtcp_set_recv_upcall()
     * コメント参照)。NULLなら従来通りrx_bufへ積む(完全後方互換)。 */
    tcp_recv_upcall_fn recv_upcall;
    void              *recv_upcall_ctx;

    /* Window Scaling(RFC7323、tcp.h冒頭コメント参照)のコネクションごとの
     * 状態。wscale_enabled: 双方のSYN/SYN-ACKでオプション交換が成立した
     * ら1(不成立なら0のまま、生の16bit windowにフォールバック)。
     * snd_wscale: 相手が自分のSYN/SYN-ACKで広告してきたスケール係数
     * (相手の送信ウィンドウ、すなわちこちらのsnd_winを解釈するために使う
     * -- 自分の受信ウィンドウ側のスケール係数はTCP_RCV_WSCALEで固定)。
     * tcp_priv_init()で0にリセットする。 */
    int      wscale_enabled;
    uint8_t  snd_wscale;

    /* 遅延ACK(tcp_input()のESTABLISHEDケース参照)用のカウンタ。順序通り
     * 届いたフルサイズ(TCP_MSS_LOCAL)セグメントを1個受信するたびに1、
     * ACKを送ったら0に戻す -- 1になっている状態でもう1個フルサイズの
     * セグメントを受信したら(累計2個)そこでまとめてACKする。実機で
     * 「受信セグメント1個につき即座にACK」が相手側のACKクロッキングを
     * 引き起こし、大きめのin-capsule書き込み/H2CData受信のスループットが
     * 約11.8MB/sで頭打ちになる問題を確認したため導入した(一度試して
     * `type=0`退行で撤回したが、真因は`.dma_bss`未初期化と
     * nvmet_tcp_recv_exact()のタイムアウトバグという無関係な別バグ2件
     * だったと判明し、修正済み。CLAUDE.md参照)。 */
    uint32_t          unacked_full_segments;

    /* tcp_recv_no_ack()(send_ack=0)経由で消費したが、まだ相手へウィンドウ
     * 更新ACKとして伝えていないバイト数の累積(2026-08-07追加)。job化された
     * nvmet_tcp.cの非ブロッキング受信(nvmet_tcp_recv_poll())は全てこの
     * 経路を通るため、send_ack=0の設計のまま(下記コメント参照、意図的に
     * 毎回のACKを避けている)だと消費してもウィンドウが相手に一切伝わらず、
     * 実機のfioベンチマークでNVMe/TCP write性能が過去の実測比1/10程度まで
     * 低下する退行を招いた(`ss`の`rwnd_limited`が76.5%という実測で確認 --
     * 相手が広告ウィンドウ不足でほとんどの時間送信をブロックされていた)。
     * この累積が閾値(TCP_RECV_NOACK_ACK_THRESHOLD)を超えたら、tcp_recv_
     * no_ack()経由でも強制的にウィンドウ更新ACKを送る -- 「1回の読み取り
     * ごとに毎回ACK」という当初避けていたパターン(GEM TXリング空き待ちが
     * 読み取り回数分発生する)には戻さず、ある程度まとまった量が空くまで
     * 束ねることで両立させる。 */
    uint32_t          unacked_consumed_bytes;

    /* 順序が入れ替わって届いた(まだギャップがある)セグメントを
     * TCP_OOO_SLOTS件まで保持できる先読みバッファ。rx_bufとは別領域
     * -- ギャップがある間はrx_bufの続きとして書き込めないため。
     * ギャップを埋めるセグメントが届いてrcv_seqが追いつくたびに、
     * 該当するスロットをtcp_input()の中で即座にrx_bufへ繋げる
     * (1回の繋ぎ込みで複数スロットが連鎖的に解決することもあるため
     * ループで確認する)。
     *
     * 当初は1件だけ保持する設計だったが、実機のNVMe/TCPベンチマーク
     * (16KB〜256KBのwrite、複数のMSSサイズセグメントに分割されて届く)
     * で複数セグメントが同時に順序を崩すケースが頻発し、1件を超えた
     * 分を保持できず相手の再送待ちを繰り返すことでwrite性能が大きく
     * 劣化する事象を実機で確認したため、複数スロット化した。 */
    tcp_ooo_slot_t ooo[TCP_OOO_SLOTS];

    /* tcp_send_async()(tcp.h参照)の「送りっぱなし」送信の未確認追跡状態。
     * 循環キュー(TCP_ASYNC_SLOTS件まで同時に未確認のままキューできる、
     * 2026-07-25に1件だけの設計から拡張 -- TCP_ASYNC_SLOTSコメントの
     * 経緯参照)。async_headが最古の未確認スロットのインデックス、
     * async_countが現在未確認のスロット数。TCPのACKは累積確認のため、
     * 先頭(最古)がACK済みになったかどうかだけ見ればよい(tcp_send()の
     * Go-Back-N再送と同じ考え方をこの小さい単発メッセージ集合に適用
     * したもの、tcp_async_poll()参照)。各スロットが送信データ自体を
     * コピーして保持する理由は元の設計と同じ(呼び出し元のbufの生存を
     * 前提にできないため)。 */
    tcp_async_slot_t async_slots[TCP_ASYNC_SLOTS];
    unsigned          async_head;
    unsigned          async_count;
    /* 2026-08-11、mlx5専用の追加スロットプール(TCP_ASYNC_SLOTS_MLX5_
     * EXTRAコメント参照)からこのコネクションへ割り当てられたエントリの
     * 番号、未割り当てなら-1。tcp_priv_init()で-1にリセット、その後
     * local_ipが確定した時点でtcp_priv_try_grant_mlx5_async_overflow()
     * が(mlx5バックエンドかつプールに空きがあれば)実際の番号を入れる。
     * async_capは現在このコネクションが使える論理スロット総数
     * (TCP_ASYNC_SLOTS、または割り当て成功時はTCP_ASYNC_SLOTS+
     * TCP_ASYNC_SLOTS_MLX5_EXTRA) -- 以後のasync_head/async_count関連の
     * 剰余演算は全てTCP_ASYNC_SLOTSではなくこのasync_capを使う
     * (tcp_async_slot_at()参照)。 */
    int               async_overflow_idx;
    unsigned          async_cap;
    /* `s_priv[][]`はBSSゼロ初期化される静的配列のため、この priv用
     * スロットが一度もtcp_priv_init()を通っていない場合でもasync_
     * overflow_idxはゼロ初期化により0になる -- 「一度も使われたことが
     * ない(0は無意味)」と「実際にオーバーフロープールの0番を保持
     * している」を区別できず、初回のtcp_priv_init()が無関係な別
     * コネクションの0番を誤って解放してしまう(stateprof.cのstarted
     * フラグ、mlx5_net.cのhas_last_*_hw_tsと同じ「0を有効値として使う
     * フィールドには専用の初期化済みフラグが要る」パターン)。 */
    uint8_t           async_overflow_ever_init;

    /* 2026-08-11、CMD/RSP/R2T/ICResp等のヘッダ専用PDU向け専用キュー
     * (上記TCP_ASYNC_SHORT_MAX_LENコメント参照)。async_slots[]/
     * async_overflow_idx/async_capとは完全に独立した第2のFIFOで、
     * 固定サイズ(オーバーフロープールなし)。async_head/async_countと
     * 同じ意味・同じGo-Back-N的な確認方式(tcp_async_short_poll()参照)。 */
    tcp_async_short_slot_t async_short_slots[TCP_ASYNC_SHORT_SLOTS];
    unsigned                async_short_head;
    unsigned                async_short_count;

    /* 2026-08-10、実機で発見した本物の性能バグの修正: cwnd(輻輳ウィンドウ)
     * の成長ロジック(priv->ack_advancedを見てRFC5681のスロースタート/
     * 輻輳回避を適用する処理)は元々tcp_send()自身のバーストループの中に
     * しか無かった -- tcp_send_async()専用のコネクション(NVMe/TCPの
     * job経路、CQE/R2T/SQE/H2CData等はtcp_send()を一度も呼ばない)では
     * priv->ack_advancedがtcp_input()によってセットされても誰も消費・
     * 成長させず、priv->cwndがtcp_cwnd_init()の初期値(実測約19876)から
     * 一生成長しないままだった。tcp_send_async()にウィンドウ/cwnd尊重の
     * チェックを追加した際(このコメントのすぐ下、tcp_send_async()参照)、
     * この「一生成長しないcwnd」に縛られて実機のNVMe/TCP write/read
     * パイプラインのスループットが激減する退行を招いた(修正前163〜
     * 173MB/s→修正直後74〜75MB/s)。
     * 対処: cwnd成長ロジックを共有関数tcp_cwnd_grow_on_ack()へ抽出し、
     * tcp_async_poll()(全アクティブconnについて毎tcp_poll_once()で
     * 呼ばれる)からも呼ぶようにした。ただしtcp_send()が今まさにその
     * コネクションを駆動中(呼び出し元のバーストループ自身がpriv->
     * ack_advancedを消費して同じ成長処理を行う)の間は、tcp_async_poll()
     * 側では二重に消費してtcp_send()自身のRTT/RTO計測(Karnのアルゴリズム
     * 等、ack_advancedフラグの検知に依存)を横取りしないよう、この
     * in_bulk_sendフラグで排他する(tcp_send()の間だけ1、それ以外は0)。 */
    volatile int      in_bulk_send;

    /* tcp_connect_begin()/tcp_connect_poll()(非ブロッキングconnect、
     * CLAUDE.md「NVMe/TCP制御のステートマシン化」節参照)専用のSYN再送
     * 状態。旧tcp_connect()内でローカル変数として持っていた再送回数/
     * バックオフRTOを、複数tickにまたがって保持するためここへ移した。
     * connect_rto_msは意図的にrto_ms(上記、接続確立後の定常RTO推定)とは
     * 別フィールドにしてある -- 旧tcp_send_reliable()もローカル変数
     * rto_msをpriv->rto_msから初期値だけコピーして倍々に増やし、
     * priv->rto_ms自体は(RTT実測による更新以外では)書き換えなかった
     * のと同じ理由(再送バックオフの一時的な膨張が、確立後のtcp_send()等
     * が使う定常RTO推定を汚染しないようにするため)。tcp_priv_init()で
     * リセットする。 */
    uint32_t connect_attempt;
    uint32_t connect_rto_ms;
    uint64_t connect_sent_at;
} tcp_priv_t;

/* アクティブなコネクション(tcp_connect()が登録、tcp_close()が解除)。
 * インデックスはs_priv[]と対応する。tcp_input()はこの配列全体を走査して
 * ディスパッチ先を探す。 */
static tcp_conn_t *s_conns[SMP_MAX_CORES][TCP_MAX_CONNS];
static tcp_priv_t  s_priv[SMP_MAX_CORES][TCP_MAX_CONNS];

/* 簡易TIME_WAIT相当のテーブル(2026-08-08追加、実機で発見した問題への
 * 対処)。tcp_close()の能動close(ESTABLISHED始まり)は、自分のFINが
 * ACKされた後、相手のFINをTCP_CLOSE_FIN_WAIT_MSだけ待つが、それでも
 * 届かなければ相手の応答を待たずs_conns[]から即座に登録解除していた
 * (「TIME_WAITの2MSL待ちは省略」という既存の設計判断、tcp_close()の
 * コメント参照)。この設計は通常の相手(実OS)には問題ないが、client/
 * serverが同一プログラム内に同居する構成(ConnectX PF0<->PF1
 * ループバック等)では、相手側のFIN送信がjob_scheduler_tick()を
 * 経由するため、こちらの待ち時間内には間に合わないことが多い --
 * 相手が遅れて送ってきたFINは、s_conns[]から既に消えたconnに対して
 * 一致するものが無く(tcp_input()の`if (!conn) return;`)、ACKすら
 * 返らないまま完全に無視される。相手はこれをパケットロストして
 * RTO再送(最大5回、合計約15秒)を繰り返した末に諦める、という
 * 実機で確認された無駄な遅延の直接原因だった。
 *
 * 対処: 能動closeが相手のFINを受け取れないままタイムアウトした場合、
 * s_conns[]からconnを外す(呼び出し元は即座に同じtcp_conn_t*を新しい
 * 接続に再利用できる、という既存の契約は変えない)前に、この軽量な
 * テーブルへ4-tuple+応答用ACK値だけを登録しておく。tcp_input()は
 * s_conns[]に一致が無いFINセグメントについて、諦める前にこちらも
 * 確認し、一致すればtcp_conn_t/tcp_priv_t無しで送れる専用の
 * バレアACK送信(tcp_send_bare_ack())で応答する。エントリは
 * TCP_TIMEWAIT_MS後に自動的に失効する(tcp_poll_once()から毎回
 * 軽量に掃除する、TCP_TIMEWAIT_MAXが小さいため走査コストは無視できる)。
 *
 * 本来のTCP TIME_WAIT(2MSL、通常30秒〜数分)ほど長くは保持しない --
 * このプロジェクトは同一4-tupleでの即再接続を想定しない(tcp_close()
 * 既存コメント参照)ミニマル実装であり、ここでの目的は「遅れてきた
 * 1回のFINに正しくACKを返し、相手の無駄なRTO再送を防ぐ」ことに限定
 * している。 */
#define TCP_TIMEWAIT_MAX 4u
#define TCP_TIMEWAIT_MS  4000u  /* TCP_CLOSE_FIN_WAIT_MSより十分長い安全マージン */

typedef struct {
    int      in_use;
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;
    uint32_t local_seq;      /* 応答ACKのSEQフィールドに使う自分のFIN後のseq(不変) */
    uint64_t started_ticks;  /* TIME_WAIT開始時刻(TCP_TIMEWAIT_MS、timeout_ms()で判定) */
} tcp_timewait_t;

/* 【2026-08-08変更、job stepのctx経由リソース参照化】s_timewait[]は
 * tcp_close()(能動close、任意のコアのjob stepから呼ばれうる)が書き、
 * tcp_input()(常にそのSYN/FINを受信したNICのowner_coreだけが呼ぶ、
 * netif.hのnetif_t.owner_core参照)が読む。両者が同じコアとは限らない
 * ため、以前のようにコアごとに独立配列化していると、書いたコアと違う
 * コアが読むケースで一致するはずのエントリが見つからない(遅れてきた
 * FINへの応答が失われ、相手が無駄なRTO再送を繰り返す、上記コメントの
 * 症状がまさに再発する)。単一の共有配列+スピンロックへ変更した --
 * エントリ数が小さい(TCP_TIMEWAIT_MAX×コア数)ため走査コストは無視できる。 */
#define TCP_TIMEWAIT_TOTAL (TCP_TIMEWAIT_MAX * SMP_MAX_CORES)
static tcp_timewait_t s_timewait[TCP_TIMEWAIT_TOTAL];
static smp_spinlock_t s_timewait_lock;

static tcp_timewait_t *tcp_timewait_find(uint32_t remote_ip, uint16_t remote_port, uint16_t local_port)
{
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use &&
            s_timewait[i].remote_ip == remote_ip &&
            s_timewait[i].remote_port == remote_port &&
            s_timewait[i].local_port == local_port) {
            smp_spin_unlock(&s_timewait_lock);
            return &s_timewait[i];
        }
    }
    smp_spin_unlock(&s_timewait_lock);
    return NULL;
}

static void tcp_timewait_register(uint32_t local_ip, uint16_t local_port,
                                   uint32_t remote_ip, uint16_t remote_port,
                                   uint32_t local_seq)
{
    smp_spin_lock(&s_timewait_lock);
    int slot = -1;
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (!s_timewait[i].in_use) { slot = (int)i; break; }
    }
    if (slot < 0) slot = 0;  /* 空きが無ければ一番古い(先頭)のエントリを再利用する */
    s_timewait[slot].in_use       = 1;
    s_timewait[slot].local_ip     = local_ip;
    s_timewait[slot].local_port   = local_port;
    s_timewait[slot].remote_ip    = remote_ip;
    s_timewait[slot].remote_port  = remote_port;
    s_timewait[slot].local_seq    = local_seq;
    s_timewait[slot].started_ticks = timer_now();
    smp_spin_unlock(&s_timewait_lock);
}

/* 期限切れエントリを掃除する(tcp_poll_once()から毎回呼ぶ軽量処理)。 */
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

/* tcp_listen()/tcp_accept()向けの受動open状態(複数リスナー対応、
 * CLAUDE.md「nvmet: 複数インターフェース同時待受」節参照)。各スロットは
 * tcp_unlisten()(または次のtcp_listen())まで有効に保つ -- 複数回
 * tcp_accept()を同じlistenerで呼べるようにするため、NVMe/TCPのadmin
 * queue+IO queueのように2本のコネクションを順に受け付ける用途を想定。
 * bound_ctx!=NULLなら、そのnetif_t(netif.h)が受信したSYNのみに一致
 * させる(tcp_input()参照) -- 複数のリスナーが同じportで異なる
 * インターフェースへそれぞれ独立にbindできるようにするため。 */
typedef struct {
    int         in_use;
    uint16_t    port;
    netif_t  *bound_ctx;    /* NULL = インターフェースを問わず受け付ける */
    tcp_conn_t *accept_conn;  /* tcp_accept_begin()が渡してきたconn */
    volatile int accept_ready; /* ESTABLISHEDになった = 1 */
} tcp_listener_slot_t;

/* 【2026-08-08変更、job stepのctx経由リソース参照化】従来はコアごとに
 * 独立配列化していたが、tcp_listen()(リスナーを作るコア)とtcp_input()の
 * SYNマッチング(常にそのnet_ctxのowner_core、上記s_timewaitコメントと
 * 同じ理由)が別コアになりうるため、s_listeners[job作成コア][listener]と
 * s_listeners[NIC owner core][listener]が食い違い、SYNが永久にどの
 * リスナーにもマッチしない(接続が無応答でタイムアウトし続ける)バグに
 * なりうる。単一の共有配列+スピンロック(構造フィールドin_use/port/
 * bound_ctxの書き込みのみ保護、accept_conn/accept_readyはtcp_input()と
 * tcp_accept_wait()/tcp_accept_ready_poll()が高頻度にポーリングし合う
 * ため volatile 指定のみとしロック無しで読み書きする、tcp_conn_tの
 * volatileフィールドと同じ設計方針)へ変更した。 */
#define TCP_LISTENER_TOTAL (TCP_MAX_LISTENERS * SMP_MAX_CORES)
static tcp_listener_slot_t s_listeners[TCP_LISTENER_TOTAL];
static smp_spinlock_t      s_listener_lock;

static tcp_listener_slot_t *tcp_listener_for(int listener)
{
    if (listener < 0 || (unsigned)listener >= TCP_LISTENER_TOTAL) return NULL;
    if (!s_listeners[listener].in_use) return NULL;
    return &s_listeners[listener];
}

/* connに対応するプライベート状態を引く。s_conns[]に登録されていない
 * (呼び出し側の使い方が誤っている)場合はNULLを返す -- 呼び出し元は
 * ESTABLISHED等の状態チェックを先に行うため通常は発生しない。
 *
 * マルチコア化 Phase 4-6準備(2026-08-08、tcp.hのtcp_conn_t.owner_core
 * コメント参照): 「今このコードを実行しているコア」(smp_core_index())
 * ではなく、conn自身が生成時に記録した所有コア(conn->owner_core)で
 * s_conns[]/s_priv[]を引く -- job.cの共有スケジューラにより、この
 * connを扱うjob stepが生成時と異なるコアでtickされることがあるため
 * (「別コアで実行された瞬間にconnが見つからなくなる」というバグ
 * クラスを構造的に防ぐ)。 */
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

/* 空きスロットを探す。無ければ-1。 */
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

/* TCP層の性能分析用(timestamp.h参照): connがs_conns[]のどのスロット
 * (0..TCP_MAX_CONNS-1)に登録されているかを返す(見つからなければ
 * TCP_MAX_CONNS)。NVMe/TCPではadmin queue/IO queueが別々のtcp_conn_tと
 * して同時に生きるため、ts_log()のtagだけでは "どちらの接続のイベントか"
 * が区別できない -- 複数コネクションの記録が同じリングバッファに
 * インターリーブして書き込まれると、後から読んだ際にどちらの接続の
 * イベント系列なのか取り違える実害があった。tcp_conn_arg()がこのスロット
 * 番号をargの上位8bit(bit31:24)に埋め込むことで解決する。接続確立時に
 * uart_printfで表示される"slot=%d"と同じ番号なので、起動ログの
 * "[TCP] accept: ... slot=%d"/"[TCP] connect: ... slot=%d"と突き合わせて
 * "どちらがadmin/ioか"を判別できる。 */
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

/* ts_log()のargへ渡す値を組み立てる: 上位8bit(bit31:24)=接続スロット
 * 番号(tcp_conn_slot()参照)、下位24bit=valueそのまま。valueはこの
 * ファイル内で実際に記録している全ての値(バイト数・cwnd・再送回数等)
 * が2^24(16M)を大きく下回るため切り詰めは発生しない。タイムアウト
 * センチネル(0xFFFFFFFF)は呼び出し側がvalue=0x00FFFFFFuを渡すことで、
 * 下位24bitが全て1という区別可能なパターンのまま上位8bitのスロット
 * 番号だけは保持できるようにする(RDONのタイムアウトケース参照)。
 * tcp.hで公開(nvme_tcp.cが同じエンコーディングを再利用するため)。 */
uint32_t tcp_conn_arg(const tcp_conn_t *conn, uint32_t value)
{
    return ((uint32_t)tcp_conn_slot(conn) << 24) | (value & 0x00FFFFFFu);
}

/* 32bitシーケンス番号の巡回(ラップアラウンド)安全な順序比較。
 * 差分を符号付き32bit整数として解釈することで、0付近をまたぐ
 * ラップアラウンドでも正しい前後関係を判定できる(単純な</>比較は
 * 0xFFFFFFFF付近で壊れる)。Linuxカーネルのnet/tcp.hのbefore()/after()と
 * 同じ考え方。等価判定(==)はラップアラウンドの影響を受けないため
 * 従来通り素の==を使ってよい。 */
static inline int tcp_seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int tcp_seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }

/* data(data_len)バイトを受信循環バッファpriv->rx_bufに追記する。呼び出し元は
 * 事前に空き容量(TCP_RX_BUF_SIZE - priv->rx_count >= data_len)を確認しておくこと
 * (このヘルパ自体は溢れチェックをしない)。 */
static void tcp_rx_buf_push(tcp_priv_t *priv, const volatile uint8_t *data, uint16_t data_len)
{
    /* write_pos/first_lenはTCP_RX_BUF_SIZE(512KB)を扱うためuint32_t
     * (2026-07-25、Window Scaling導入時にuint16_tから拡張 --
     * data_len自体は1セグメント分でMSS上限のためuint16_tのまま)。 */
    uint32_t write_pos = (uint32_t)((priv->rx_read + priv->rx_count) % TCP_RX_BUF_SIZE);

    /* 折り返し境界をまたぐ場合のみ2回に分けた線形コピーにする(バイト
     * ごとのmodulo計算を避け、各区間をvolatile_fast_copy()でワイド
     * アクセス可能にするため -- net.hのvolatile_fast_copy()コメント参照)。 */
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


/* ================================================================
 * tcp_input()で使われるゼロコピー用handlerの登録関数
 * nvmet_io_job_step_impl()からコールされる
 * ================================================================ */
/* in-orderで届いたデータを配置する(inline receive対応、2026-08-13)。
 * このコネクションにupcallが登録されていればデータをその場でupcallへ渡す
 * (ULPがストリームをパースしながら最終バッファへ直接配置、rx_buf/copy2/
 * copy3を回避)、無ければ従来通りrx_bufへ積む。rcv_seqの前進は呼び出し元が
 * 行う(data_len全体分)。tcp_input()のin-order受信・OOO繋ぎ込み・FIN便乗
 * データの全push箇所で使う。 */
static void tcp_deliver_data(tcp_priv_t *priv, const volatile uint8_t *data, uint16_t data_len)
{
    if (priv->recv_upcall) { // tcp_set_recv_upcall()で設定されるhandler
        // -> nvmet_io_rx_upcall(nvmet.c) / nvme_read_rx_upcall(nvme.c)
        priv->recv_upcall(priv->recv_upcall_ctx, data, data_len);
    } else {
        tcp_rx_buf_push(priv, data, data_len);
    }
}

/* 受信upcallの登録/解除(inline receive、tcp.hのコメント参照)。登録すると
 * 以後のin-orderデータはrx_bufへ積まれずupcallへ直接渡される。 */
void tcp_set_recv_upcall(tcp_conn_t *conn, tcp_recv_upcall_fn fn, void *ctx)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->recv_upcall     = fn;
    priv->recv_upcall_ctx = ctx;
}

void tcp_clear_recv_upcall(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->recv_upcall     = NULL;
    priv->recv_upcall_ctx = NULL;
}

/* RTT推定(RFC 6298 3.のSRTT/RTTVAR更新式、alpha=1/8, beta=1/4, K=4)。
 * measured_ticksは実測RTT(timer_now()の差分)。呼び出し元がKarnの
 * アルゴリズム(再送が絡んだ測定を除外する)を適用済みであることを前提に、
 * ここでは無条件にpriv->srtt_us/rttvar_us/rto_msを更新する。 */
static void tcp_rtt_update(tcp_priv_t *priv, uint64_t measured_ticks)
{
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

/* conn宛にflags/data(data_len)のTCPセグメントを1本構築して送信する
 * (再送は行わない -- 単発送信。呼び出し元が再送要否を判断する)。
 * ACK番号はflagsにTCP_FLAG_ACKが立っている場合のみconn->rcv_seqを使う
 * (立っていなければ0、SYNのみの初回送信で使う)。送信元seqはconn->snd_seq
 * を使うため、呼び出し元は送るセグメントのseqに合わせて事前に
 * conn->snd_seqを設定しておくこと(パイプライン送信では複数セグメントを
 * 異なるseqで送るためこの呼び出し規約にしている)。
 * priv: 広告ウィンドウ計算(priv->rx_count)にのみ使う。
 * TCP_FLAG_SYNが立っている場合はMSSオプション(4バイト)を付加する
 * (再送のたびに同一内容が再構築されるため、再送セグメントの冪等性が保たれる)。
 * 宛先MACはARPキャッシュから引き、無ければarp_resolve()でその場で
 * 解決する(icmp_send_echo_request()と同じパターン)。
 *
 * 送信バッファ: Ethernet+IP+TCPヘッダ(+オプション)とデータ本体を1本の
 * バッファ(s_seg_bufs[]、TXリングスロットごとに1つ、下記コメント参照)へ
 * 組み立ててから、eth_send_frags_async()へ単一断片(frag_count=1)で渡す。
 *
 * 以前はヘッダのみs_hdr_bufへ構築し、data部分はコピーせずeth_send_frags()
 * の第2断片としてdataのアドレスをそのまま渡すゼロコピー方式(GEMのDMAが
 * 2本のディスクリプタ(TX_LAST=0のヘッダ断片 -> TX_LAST=1のデータ断片)を
 * チェインして1フレームとして読む想定)だった。実機のtcptestで、この
 * 2断片送信だけが常に(単一断片送信は正常なのに)TSR.UBRを立てて
 * ハードウェアが完了せずタイムアウトすることを確認した -- 診断用に
 * ヘッダ+データを1本の線形バッファにコピーしfrag_count=1の単一
 * ディスクリプタ送信に切り替えたところ、同じ4096バイト送信が1回も
 * タイムアウトせず完了した(entry=3,4,5がそれぞれ即座にTX_USEDを立てた)。
 * これによりRP1のCadence GEMインスタンスがscatter-gather(複数ディスクリプタ
 * チェイン)TXに対応していないことが実機で確定したため、常時この単一
 * バッファ方式にした。データのコピーが1回増える分だけ以前のゼロコピー
 * より遅いが、正しく動くことが優先。
 * チェックサムはヘッダ/データを別々のポインタとして
 * pseudo_header_checksum2()へ渡して計算する(コピー前のdata由来ポインタで
 * 計算する方が、後段のバイト単位コピーループと責務が分かれてわかりやすい
 * ため。TCPヘッダ長は常に4の倍数=偶数なので、ヘッダ/データの境界が16bit
 * ワード境界とずれる心配は無い -- net.hのpseudo_header_checksum2()コメント
 * 参照)。
 * 戻り値: eth_send_frags_async()の戻り値をそのまま返す(0=キュー成功、
 * -1=失敗 -- ハードウェアへの送信完了ではなくキューイングの成否である点に
 * 注意、下記tcp_send_segment()末尾のコメント参照)。 */
/* Ethernet+IP+TCPヘッダ(+オプション)+データ全体を保持する送信バッファ。
 * 最大サイズ = IP_PAYLOAD_OFFSET+TCP_HDR_LEN+8(ヘッダ、SYNのMSSオプション
 * (4B)+NOP(1B)+Window Scaleオプション(3B)込み、2026-07-25にWindow
 * Scaling対応で4→8へ拡張) + TCP_MSS_LOCAL(データ、tcp_parse_syn_options()が
 * conn->snd_mssをTCP_MSS_LOCAL以下に上限しているため常にこれ以下)。
 * ETH_TX_RING_SIZE個(TXリングのエントリ数と同数)を確保し、
 * eth_tx_wait_free_slot()が返すスロット番号でインデックスする --
 * eth_send_frags_async()によるパイプライン化(複数セグメントの送信完了を
 * 待たずに次々キューイングする)後は、まだハードウェアが送信中かもしれ
 * ない古いセグメントのバッファを、次のtcp_send_segment()呼び出しが
 * 上書きしてしまわないようにするため、単一の共有バッファ(旧実装)では
 * 足りない -- スロットごとに独立したバッファが必要(下記
 * tcp_send_segment()のeth_tx_wait_free_slot()呼び出し参照)。
 * aligned(64): RP1 GEMのTXディスクリプタへ直接アドレスを渡す唯一の断片
 * になる(frags[0]) -- net_buf_t/tcp.hのtcp_send()ドキュメントと同じ
 * アライメント要求(実機のTXタイムアウト調査で気づいた)。
 *
 * 2026-07-25、ジャンボフレーム対応後の実機計測(`ts_log()`のSSLT/SCKS/
 * SSEGタグ)で、`.dma_bss`(Device-nGnRnE、非バッファリング)への
 * データ本体コピーが1セグメント(8960B)あたり約82〜84usかかっており、
 * 同じデータを読むだけのチェックサム計算(約9〜10us)の8〜9倍遅い
 * ことを確認した。差の約72〜74usはコピー先が非キャッシュメモリで
 * ストア命令1回ごとに完了を待つ(early write acknowledgementが無い)
 * ことに起因すると判断し、`s_seg_bufs`を`.dma_bss`から通常のキャッシュ
 * 可能RAMへ移し、`eth_send_frags_async()`へ渡す直前に
 * `dcache_clean_range()`(`cache.h`、Point of Coherencyまでクリーン)を
 * 明示的に呼ぶ方式へ変更した -- `net_buf.c`のs_pool(ARP/ICMP等の送信、
 * `eth_send()`)で既に実績のある同じパターンをTCPセグメント送信にも
 * 適用したもの。キャッシュラインクリーン(64B単位)の方が、非キャッシュ
 * ストアを1バイト/ワードごとに個別発行するより速いはずという読みだが、
 * 実機での効果測定はまだ行っていない。 */
static uint8_t s_seg_bufs[SMP_MAX_CORES][ETH_TX_RING_SIZE][IP_PAYLOAD_OFFSET + TCP_HDR_LEN + 8 + TCP_MSS_LOCAL]
    __attribute__((aligned(64)));

static int tcp_send_segment(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags,
                             const void *data, uint16_t data_len)
{
    unsigned core = smp_core_index();

    // 複数ネットワークインターフェース(netif.h、CLAUDE.md「TCP/IPスタック
    // のConnectX統合」節参照)を同一プログラム内で並行運用する場合、
    // tcp_poll_once()がnet_poll_all_and_dispatch()経由でコンテキストを
    // 切り替えながらポーリングするため、この関数が呼ばれた時点で
    // g_active_ctxがconn自身の所属インターフェースとは限らない
    // (例: 別connのtcp_async_poll()再送処理から呼ばれた直後等)。
    // conn->local_ip(接続確立時に固定)から所属コンテキストを逆引きし、
    // 以降のarp_cache_lookup()/eth_send_frags_async()が正しいMAC/IP/
    // ARPキャッシュ/送受信バックエンドを参照するよう明示的に切り替える
    // (単一インターフェース運用時はnetif_find_by_ip()が同じ
    // コンテキストを返すだけで実害無し)。
    netif_t *conn_ctx = netif_find_by_ip(conn->local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (arp_cache_lookup(conn->remote_ip, dst_mac) != 0) {
        if (arp_resolve(conn->remote_ip, dst_mac) != 0) {
            uart_printf("[!] TCP: %u.%u.%u.%u のARP解決失敗、送信中止\n",
                        (unsigned)(conn->remote_ip >> 24) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 16) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 8) & 0xFFu,
                        (unsigned)conn->remote_ip & 0xFFu);
            return -1;
        }
    }

    /* SYNのみMSSオプション(kind=2,len=4,mss=TCP_MSS_LOCAL)を付加する。
     * Window Scaleオプション(kind=3,len=3,shift=TCP_RCV_WSCALE)は
     * 条件付きで追加する(RFC7323): 能動openの最初のSYN(ACKフラグ無し)は
     * 常に自分から提案する。受動openのSYN|ACKは、相手の元のSYNが
     * Window Scaleオプションを含んでいた場合のみ返す(tcp_input()の
     * SYN受け付けブロックがtcp_parse_syn_options()でpriv->wscale_enabled
     * を先に確定させてから、この関数を呼んでSYN|ACKを送る -- 呼び出し順序
     * については上記関数コメントおよびtcp_input()参照)。オプション無しで
     * 付ければ、そのコネクション全体でスケーリングが有効になる
     * (tcp.h冒頭のWindow Scalingコメント参照)。NOP(1B)を挟んで4バイト
     * 境界に揃える(MSS 4B + NOP 1B + WScale 3B = 8B)。 */
    int include_wscale = 0;
    if (flags & TCP_FLAG_SYN) {
        include_wscale = (flags & TCP_FLAG_ACK) ? priv->wscale_enabled : 1;
    }
    uint8_t opt_len = 0;
    if (flags & TCP_FLAG_SYN) {
        opt_len = include_wscale ? 8u : 4u;
    }
    uint16_t hdr_total = (uint16_t)(TCP_HDR_LEN + opt_len);  /* TCPヘッダ+オプション(データ抜き) */
    uint16_t seg_len = (uint16_t)(hdr_total + data_len);      /* IPペイロード全体(ヘッダ+データ) */

    uint8_t src_ip_octets[4];
    uint8_t dst_ip_octets[4];
    ip_to_octets(conn->local_ip, src_ip_octets);
    ip_to_octets(conn->remote_ip, dst_ip_octets);

    /* このセグメントが使うTXリングスロットを確保する。そのスロットの
     * 前回の占有者がまだハードウェア送信中なら、ここでブロックして待つ
     * (eth_tx_wait_free_slot()参照) -- ARP解決(上記、内部でeth_send()を
     * 呼びうる)より後で呼ぶこと。これより後、eth_send_frags_async()を
     * 呼ぶまでの間に他のeth_send*()を挟んではならない(s_seg_bufs[slot]の
     * 前提とs_tx_headがずれる、eth_tx_wait_free_slot()のコメント参照)。 */
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 0), tcp_conn_arg(conn, data_len));
    unsigned slot = eth_tx_wait_free_slot();
    /* 計装専用(2026-07-25、READのC2HData送信がなぜ生の送信時間より遅いか
     * 切り分けるため一時的に追加): 直前のSSEG(前回セグメントの送信完了)
     * からここまでの時間 -- ARP参照(通常キャッシュ済みで無視できる)と
     * このeth_tx_wait_free_slot()自体(TXリングスロット空き待ち)の
     * コストを他と分離する。 */
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 1), tcp_conn_arg(conn, data_len));
    uint8_t *seg_buf = s_seg_bufs[core][slot];

    ip_build_header(seg_buf, dst_ip_octets, dst_mac, IP_PROTO_TCP, seg_len);

    volatile uint8_t *tcph = seg_buf + IP_PAYLOAD_OFFSET;
    wr16be(tcph + TCP_OFF_SRC_PORT, conn->local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, conn->remote_port);
    wr32be(tcph + TCP_OFF_SEQ, conn->snd_seq);
    wr32be(tcph + TCP_OFF_ACK, (flags & TCP_FLAG_ACK) ? conn->rcv_seq : 0u);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((hdr_total / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = flags;
    /* 実受信ウィンドウ: 受信循環バッファの実際の空き容量を広告する。
     * 旧実装は1セグメント分の単一スロットしか無く0/固定値の二値だったが、
     * 循環バッファ化により相手は実際に複数セグメントをパイプライン送信
     * できるようになった。
     *
     * Window Scaling(RFC7323): SYNが立っているセグメント自身(SYN単体/
     * SYN|ACKのどちらも)のwindowフィールドは仕様上スケーリングしない --
     * `flags & TCP_FLAG_SYN`を明示的に見て強制的に生値にする(受動open側の
     * SYN|ACKを送る時点ではpriv->wscale_enabledは直前のtcp_parse_syn_
     * options()で既に1に確定しているが、このSYN|ACK自身のwindowは
     * それとは無関係に常に生値、というのがRFC7323の規則そのもの)。
     * それ以外でscaling不成立のコネクション(priv->wscale_enabled==0)も
     * 同様に生値。TCP_RX_BUF_SIZEが65535を超えうるため、いずれの場合も
     * 16bitへクランプすることが必須(超えた分をそのまま(uint16_t)
     * キャストすると値が静かに壊れる)。
     *
     * RXリング容量による頭打ち(2026-07-25追加): TCP_RX_BUF_SIZE(512KB)は
     * MSSに関係なく固定の論理バッファサイズだが、実際にホストが送ってこれる
     * ペース(=RXディスクリプタ消費速度)はETH_RX_RING_SIZE(eth.h)個の物理
     * バッファでしか吸収できない。ETH_RX_RING_SIZEはジャンボMSS(約10182B)を
     * 前提に128エントリへサイジングされている(eth.cのETH_RX_RING_SIZE
     * コメント参照)ため、非ジャンボ接続(conn->snd_mss=1460)では
     * 128*1460B≒182KBしか実際には吸収できない。512KBをそのまま広告すると
     * ホストがその広告を信じて送ってきた分がリングを枯渇させ、RSR.BNA/OVR
     * →フレーム取りこぼし→再送→最終的に接続断につながる実機バグを確認した
     * (fio write iodepth>=4、非ジャンボMTUで再現)。conn->snd_mssは
     * ハンドシェイク時点で既に確定済み(default値536または相手のMSS
     * オプション、tcp_connect()/accept処理参照)なので0にはならない。
     * 過去の実績(768エントリ×1460B≒1.09MB/512KB広告で約2.19倍、128
     * エントリ×10240Bジャンボ想定で約2.5倍)に倣い、リング容量の半分を
     * 安全上限として広告する。
     *
     * 2026-08-13、writeパイプライン化: リングエントリ数を固定の
     * ETH_RX_RING_SIZE(128、RP1 GEM)ではなく net_active_rx_ring_size()
     * (アクティブインターフェースの実RXリング容量、netif.h参照)から取る
     * ように変更した。mlx5(ConnectX)のRQは256エントリありRP1の2倍の受信
     * フレームを吸収できるため、従来128決め打ちで計算していた広告ウィンドウ
     * (ジャンボで約573KB)が実容量の半分に抑えられ、NVMe/TCP writeの実効
     * パイプライン深度が2程度に制限されていた(実ホストfio計測+tcpdumpで
     * 確認、CLAUDE.md「NVMe/TCP over ConnectX」節参照)。256エントリで計算
     * すると広告ウィンドウが約1.14MB(ジャンボ)まで広がり、256KB writeを
     * 4〜5個outstandingにできるようになる -- 各コマンドのR2T/CQE往復
     * レイテンシが重なり合い、writeスループットが向上する。RP1(rx_ring_
     * sizeを設定しない)はnet_active_rx_ring_size()がETH_RX_RING_SIZEへ
     * フォールバックするため従来と完全に同じ挙動。 */
    uint32_t ring_capacity_bytes = (uint32_t)net_active_rx_ring_size() * (uint32_t)conn->snd_mss;
    /* 2026-08-13、writeパイプライン深度の律速調査(CLAUDE.md「受信ゼロコピー」
     * 以降の節): アイドル休止1ms→50us修正後、writeスループットがqd4=qd8で
     * 頭打ち(約240MB/s)になる原因を、広告受信ウィンドウがring容量の半分
     * (mlx5ジャンボで約1.14MB)にクランプされ、qd8(2MB)分の先行送信を
     * ホストが行えないためと特定した。ringがTCP_RX_BUF_SIZE全体を吸収できる
     * バックエンド(mlx5: RQ=256×ジャンボmss≒2.29MB ≥ 2MB)では、実際の
     * 律速はring容量ではなくTCP_RX_BUF_SIZE側なので、safe_window_capは
     * TCP_RX_BUF_SIZEまで開いてよい(ウィンドウ最大2MB≒223ジャンボフレーム
     * < RQ 256枠で、受信ゼロコピーの遅延再武装で1枠減っても余裕がある)。
     * ringが小さいバックエンド(RP1: 128×mss)は従来通りring容量の半分を
     * 安全上限に保つ(広告ウィンドウがringを溢れさせRSR.BNA/OVRを招く
     * 実機バグの再発防止、上記コメント参照)。 */
    uint32_t safe_window_cap = (ring_capacity_bytes >= TCP_RX_BUF_SIZE)
                                   ? TCP_RX_BUF_SIZE
                                   : (ring_capacity_bytes / 2u);
    uint32_t actual_window = TCP_RX_BUF_SIZE - priv->rx_count;
    if (actual_window > safe_window_cap) actual_window = safe_window_cap;
    uint16_t wire_window;
    if ((flags & TCP_FLAG_SYN) || !priv->wscale_enabled) {
        wire_window = (actual_window > 0xFFFFu) ? 0xFFFFu : (uint16_t)actual_window;
    } else {
        uint32_t scaled = actual_window >> TCP_RCV_WSCALE;
        wire_window = (scaled > 0xFFFFu) ? 0xFFFFu : (uint16_t)scaled;
    }
    wr16be(tcph + TCP_OFF_WINDOW, wire_window);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */
    wr16be(tcph + TCP_OFF_URGENT, 0);
    if (opt_len > 0) {
        tcph[TCP_HDR_LEN + 0] = TCP_OPT_KIND_MSS;
        tcph[TCP_HDR_LEN + 1] = 4;
        // TCP_MSS_LOCAL(静的バッファの最大容量、ジャンボ前提)ではなく
        // net_active_mss_cap()(現在アクティブなバックエンドが実際に
        // 安全に扱える上限、netif.hのnetif_t.mss_cap参照)を広告する
        // -- ConnectX(標準MTU相当の1460)等、ジャンボ非対応のバックエンド
        // へジャンボサイズのセグメントを送ろうとして送信段で失敗するのを
        // 防ぐ。RP1はmss_cap=TCP_MSS_LOCALなので従来と同じ値になる。
        wr16be(tcph + TCP_HDR_LEN + 2, net_active_mss_cap());
        if (include_wscale) {
            tcph[TCP_HDR_LEN + 4] = TCP_OPT_KIND_NOP;
            tcph[TCP_HDR_LEN + 5] = TCP_OPT_KIND_WSCALE;
            tcph[TCP_HDR_LEN + 6] = 3;               /* オプション長(kind+len+shiftの3バイト) */
            tcph[TCP_HDR_LEN + 7] = TCP_RCV_WSCALE;  /* shift count */
        }
    }

    /* データはtcp_send()の呼び出し元が持つ任意のバッファを指しうるため、
     * 他のパケットバッファ由来ポインタと同じ理由でvolatile経由で
     * チェックサムを計算する(pseudo_header_checksum2()参照)。
     * 2026-08-09、ハードウェアチェックサムオフロード対応: このインター
     * フェースがHWオフロードに対応(net_active_hw_csum_offload()、
     * mlx5_net.cのSQ WQE cs_flags=L3_CSUM|L4_CSUM設定と対)していれば、
     * ヘッダ+データ全体を読む重い計算(9938Bあたり実測9-12us、CLAUDE.md
     * 「性能分析基盤の整備」節参照)を、疑似ヘッダのみのO(1)計算
     * (pseudo_header_checksum_only()、net.hコメント参照、Linux
     * __tcp_v4_send_check()と同じ設計)へ置き換える -- HWがこの値を起点に
     * 実際のヘッダ+ペイロードのチェックサムを計算・完成させる。 */
    uint16_t csum;
    if (net_active_hw_csum_offload()) {
        csum = pseudo_header_checksum_only(src_ip_octets, dst_ip_octets, IP_PROTO_TCP, seg_len);
    } else {
        csum = pseudo_header_checksum2(src_ip_octets, dst_ip_octets, IP_PROTO_TCP,
                                        tcph, hdr_total, data, data_len);
    }
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    /* 計装専用(上記SSLTと対、2026-07-25一時追加): SSLTからここまでで
     * ip_build_header()+TCPヘッダ書き込み(小さいDevice書き込み数個)+
     * pseudo_header_checksum2()(データ全体を読むだけ、コピー元は通常の
     * キャッシュ可能RAM)のコストが分かる。 */
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 2), tcp_conn_arg(conn, data_len));

    uint16_t hdr_bytes = (uint16_t)(IP_PAYLOAD_OFFSET + hdr_total);

    /* 2026-08-09、真のゼロコピー送信(net_active_tx_zerocopy()、
     * netif.hコメント参照)。従来は常にデータ本体をヘッダに続けて
     * seg_bufへコピーしてから単一ディスクリプタで送っていたが(RP1の
     * GEMがscatter-gather TXに対応しないための設計、下記else節に
     * そのまま残す)、mlx5(cs_flags経路と対、mlx5_net_post_frame()の
     * two_dseg対応参照)は2つのdata_seg(ヘッダ+呼び出し元データ)を
     * 直接WQEへ渡せるため、seg_bufへのコピー(SCPY、実測9938Bあたり
     * 約4us)自体を丸ごと省略できる -- キャッシュクリーン
     * (dcache_clean_range())はヘッダ分(小さい)とデータ分(呼び出し元
     * バッファ、コピー時と同サイズ)の2回に分かれるが、コピー無しで
     * 済む分だけ純減する。data_len==0(純粋なACK等)はコピーするものが
     * 無いため、常に単一フラグメント経路のままでよい。
     *
     * 2026-08-10、実機で発見した本物のバグの修正: ゼロコピー経路は
     * 「呼び出し元のdataバッファがHWのDMA読み出し完了まで内容を保持
     * し続ける」ことを前提にしている(WQEはポインタを直接参照するだけで、
     * コピーは一切行わない)。tcp_send()のバルク送信(大きく安定した
     * バッファ、例えば書き込みデータ全体)ではこの前提が常に成り立つが、
     * tcp_send_async()経由の小さい制御PDU送信(R2T/CQE/SQE等、nvmet_tcp.c/
     * nvme_tcp.cが`static uint8_t s_xxx_buf[...]`という単一の使い回し
     * バッファを毎回同じ場所へ書き直して渡す設計)では、HWがまだ前回の
     * WQEのDMA読み出しを終えていないうちに、次の呼び出しが同じ静的
     * バッファを新しい内容で上書きしてしまう競合が実機で発生した
     * (NVMe/TCP write pipelineで特定のcidのR2Tが消え、別のcidが2回
     * 現れる形で発現、CLAUDE.md参照 -- TCPレベルのSEQ/ACKは完全に整合
     * していたため、ワイヤ上のフレーミングではなくDMAソースの内容が
     * 差し替わっていたことが決め手になった)。CQオーバーフロー修正後に
     * スループットが上がり、R2T等の連続送信間隔がHWのDMA読み出し完了
     * より短くなったことで初めて顕在化したと考えられる。
     * 修正: ゼロコピーは実際に効果のある大きい転送(数千バイト以上、
     * 安定した長寿命バッファ由来)に限定し、小さいデータは(コピー
     * コスト自体無視できるサイズのため)従来通りseg_bufへコピーする
     * 安全な経路へ流す。閾値はR2T/CQE/SQE(いずれも136バイト以下)を
     * 確実に下回り、かつ実際に恩恵のある転送(通常MSSまたはLSOチャンク
     * 単位、数千〜数万バイト)を確実に上回る512バイトとした。 */
    if (net_active_tx_zerocopy() && data_len >= 512u) {
        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 3), tcp_conn_arg(conn, data_len)); // コピー無し(即座)

        dcache_clean_range(seg_buf, hdr_bytes);
        dcache_clean_range((const void *)data, data_len);
        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 4), tcp_conn_arg(conn, data_len));

        eth_frag_t frags[2];
        frags[0].data = seg_buf;
        frags[0].len  = hdr_bytes;
        frags[1].data = data;
        frags[1].len  = data_len;

        /* eth_send_frags_async(): このセグメントの送信完了は待たずに
         * 返る(パイプライン化、CLAUDE.mdの「TCP/IPスタックの性能
         * チューニング」節の残ボトルネック記述参照)。信頼性(実際に
         * 届いたか)はTCP自身のACKベースの再送(tcp_send()のGo-Back-N)
         * が担保するので、ここでハードウェア送信完了を待つ必要はない。 */
        return eth_send_frags_async(frags, 2u);
    }

    /* データ本体をヘッダに続けてseg_bufへコピーし、単一ディスクリプタで
     * 送る(このファイル冒頭のtcp_send_segment()コメント参照 -- scatter-
     * gather TXがこのGEMインスタンスで動かないため)。 */
    const volatile uint8_t *vdata = data;
    volatile_fast_copy((volatile uint8_t *)(seg_buf + hdr_bytes), vdata, data_len);
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 5), tcp_conn_arg(conn, data_len));

    eth_frag_t frag;
    frag.data = seg_buf;
    frag.len  = (uint16_t)(hdr_bytes + data_len);

    /* s_seg_bufsは通常のキャッシュ可能RAM(上記コメント参照、2026-07-25に
     * .dma_bssから移した)なので、GEMのDMAへ渡す前にPoint of Coherency
     * までクリーンする -- eth_send()がnet_buf.cのs_pool(同じくcacheable)
     * に対して行っているのと同じ理由・同じ関数(dcache_clean_range()、
     * cache.h)。ヘッダ+データ全体(seg_buf先頭からfrag.len分)が対象 --
     * ip_build_header()/TCPヘッダ書き込みもこのバッファへの書き込みで
     * あり、コピーしたデータ部分だけでなくヘッダ部分もクリーンが必要。 */
    dcache_clean_range(seg_buf, frag.len);
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 6), tcp_conn_arg(conn, data_len));

    return eth_send_frags_async(&frag, 1u);
}

/* 2026-08-10、LSO(TCP Segmentation Offload)対応。IP total_len(16bit)に
 * IPヘッダ+TCPヘッダ+dataが収まらなければならない(ip_build_header()の
 * payload_len引数もuint16_t) -- net_active_lso_max_bytes()(mlx5.hの
 * MLX5_LSO_MAX_BYTES_CAPで65536までクランプ済み)をそのまま信用せず、
 * tcp_send()側でこのプロトコル上の実容量まで明示的にクランプする
 * (65535 - IPヘッダ20 - TCPヘッダ20 = 65495)。 */
#define TCP_LSO_MAX_DATA_LEN (0xFFFFu - (uint32_t)sizeof(ip_header_t) - (uint32_t)TCP_HDR_LEN)

/* LSO対応の送信ヘルパ。tcp_send()のバースト送信ループから、
 * net_active_lso_max_bytes()>0(ConnectXのみ、RP1は常に0、
 * ~/.claude/plans/lexical-squishing-mitten.md参照)の場合にtcp_send_
 * segment()の代わりに呼ばれる -- data_lenは複数MSS分をまとめてよい
 * (呼び出し元がTCP_LSO_MAX_DATA_LEN/net_active_lso_max_bytes()の両方へ
 * クランプ済み)。ヘッダ(L2+L3+L4、オプション無し)を1つだけ組み立て、
 * ペイロード全体をコピー無しでeth_send_lso_async()へ渡す -- HWがmss単位に
 * 自動分割・送出する。呼び出し元は常にflags=PSH|ACK(SYN/オプション付きは
 * このLSO経路を通らない、tcp_send()のバーストループのみが呼ぶ設計)。
 * 再送(Go-Back-N)・tcp_send_async()・SYN送信は従来通りtcp_send_segment()
 * のまま(このプロジェクトの確認済み方針、LSOに問題があっても再送の
 * 正しさには影響しない)。 */
static int tcp_send_segment_lso(tcp_conn_t *conn, tcp_priv_t *priv,
                                 const void *data, uint32_t data_len)
{
    unsigned core = smp_core_index();

    /* tcp_send_segment()冒頭と同じ理由(コメント参照) -- 複数ネットワーク
     * インターフェース運用時、この関数が呼ばれた時点でg_active_ctxが
     * conn自身の所属インターフェースとは限らない。 */
    netif_t *conn_ctx = netif_find_by_ip(conn->local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (arp_cache_lookup(conn->remote_ip, dst_mac) != 0) {
        if (arp_resolve(conn->remote_ip, dst_mac) != 0) {
            uart_printf("[!] TCP: %u.%u.%u.%u のARP解決失敗、送信中止(LSO)\n",
                        (unsigned)(conn->remote_ip >> 24) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 16) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 8) & 0xFFu,
                        (unsigned)conn->remote_ip & 0xFFu);
            return -1;
        }
    }

    uint32_t seg_len32 = (uint32_t)TCP_HDR_LEN + data_len;
    if (seg_len32 > 0xFFFFu) {
        /* 呼び出し元がTCP_LSO_MAX_DATA_LENへクランプしていれば起こり
         *得ない、防御的チェック(mlx5.hのMLX5_LSO_MAX_BYTES_CAPが将来
         * 変更されても、ここで確実に弾く)。 */
        uart_printf("[!] TCP: LSO data_lenが大きすぎる(%u)、送信中止\n", (unsigned)data_len);
        return -1;
    }
    uint16_t seg_len = (uint16_t)seg_len32;

    uint8_t src_ip_octets[4];
    uint8_t dst_ip_octets[4];
    ip_to_octets(conn->local_ip, src_ip_octets);
    ip_to_octets(conn->remote_ip, dst_ip_octets);

    /* tcp_send_segment()と同じスロット確保規約(コメント参照)。 */
    unsigned slot = eth_tx_wait_free_slot();
    uint8_t *seg_buf = s_seg_bufs[core][slot];

    ip_build_header(seg_buf, dst_ip_octets, dst_mac, IP_PROTO_TCP, seg_len);

    volatile uint8_t *tcph = seg_buf + IP_PAYLOAD_OFFSET;
    wr16be(tcph + TCP_OFF_SRC_PORT, conn->local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, conn->remote_port);
    wr32be(tcph + TCP_OFF_SEQ, conn->snd_seq);
    wr32be(tcph + TCP_OFF_ACK, conn->rcv_seq);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((TCP_HDR_LEN / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = TCP_FLAG_PSH | TCP_FLAG_ACK;

    /* 実受信ウィンドウ(tcp_send_segment()と同じ計算 -- SYN分岐は不要、
     * このLSO経路はSYNを送らない)。 */
    uint32_t ring_capacity_bytes = (uint32_t)ETH_RX_RING_SIZE * (uint32_t)conn->snd_mss;
    uint32_t safe_window_cap = ring_capacity_bytes / 2u;
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

    /* LSOは常にHWチェックサムオフロード必須(mlx5_net_post_lso_frame()が
     * 常にcs_flags=L3_CSUM|L4_CSUMを立てる、実ドライバソースで確認済み
     * -- ~/.claude/plans/lexical-squishing-mitten.md参照)。net_active_
     * lso_max_bytes()>0はConnectXでしか成立せず、ConnectXは常に
     * hw_csum_offload=1のため、ソフトウェア計算(pseudo_header_
     * checksum2())への分岐は不要 -- 常にO(1)の疑似ヘッダのみ計算を使う。
     * 長さはアグリゲート(このLSO送信全体、data_len込み)のseg_lenを使う
     * -- HWが実セグメントごとに再計算・上書きする前提のテンプレート値
     * (Linux __tcp_v4_send_check()と同じ規約、「未検証・要実機確認」
     * 項目2として計画書に記録済み)。 */
    uint16_t csum = pseudo_header_checksum_only(src_ip_octets, dst_ip_octets, IP_PROTO_TCP, seg_len);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    uint16_t hdr_bytes = (uint16_t)(IP_PAYLOAD_OFFSET + TCP_HDR_LEN);

    /* データ本体はコピーせず、呼び出し元のバッファを直接DMA参照する
     * (tcp_send_segment()のtx_zerocopy_2frag経路と同じ考え方)。 */
    dcache_clean_range(seg_buf, hdr_bytes);
    dcache_clean_range((const void *)data, data_len);

    return eth_send_lso_async(seg_buf, hdr_bytes, data, data_len, conn->snd_mss);
}

/* tcp_send_segment()の最小構成版 -- 登録済みのtcp_conn_t/tcp_priv_tを
 * 持たない(s_conns[]から既に外れた)相手へ、単発のACKだけを送る。
 * ウィンドウは常に0を広告する(もう受信する予定が無いため)。オプション
 * (MSS/Window Scale)も付けない(SYNではないため不要)。エラーは
 * ベストエフォートで無視する(呼び出し元は遅れてきたFINへの応答なので、
 * 失敗しても実害は相手のRTO再送が続くだけで、以前の挙動と変わらない)。 */
static void tcp_send_bare_ack(uint32_t local_ip, uint16_t local_port,
                               uint32_t remote_ip, uint16_t remote_port,
                               uint32_t seq, uint32_t ack)
{
    unsigned core = smp_core_index();

    netif_t *conn_ctx = netif_find_by_ip(local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (arp_cache_lookup(remote_ip, dst_mac) != 0) {
        if (arp_resolve(remote_ip, dst_mac) != 0) {
            return;
        }
    }

    uint8_t src_ip_octets[4], dst_ip_octets[4];
    ip_to_octets(local_ip, src_ip_octets);
    ip_to_octets(remote_ip, dst_ip_octets);

    unsigned slot = eth_tx_wait_free_slot();
    uint8_t *seg_buf = s_seg_bufs[core][slot];

    ip_build_header(seg_buf, dst_ip_octets, dst_mac, IP_PROTO_TCP, TCP_HDR_LEN);

    volatile uint8_t *tcph = seg_buf + IP_PAYLOAD_OFFSET;
    wr16be(tcph + TCP_OFF_SRC_PORT, local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, remote_port);
    wr32be(tcph + TCP_OFF_SEQ, seq);
    wr32be(tcph + TCP_OFF_ACK, ack);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((TCP_HDR_LEN / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = TCP_FLAG_ACK;
    wr16be(tcph + TCP_OFF_WINDOW, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);
    wr16be(tcph + TCP_OFF_URGENT, 0);

    uint16_t csum = pseudo_header_checksum2(src_ip_octets, dst_ip_octets, IP_PROTO_TCP,
                                             tcph, TCP_HDR_LEN, NULL, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    eth_frag_t frag;
    frag.data = seg_buf;
    frag.len  = (uint16_t)(IP_PAYLOAD_OFFSET + TCP_HDR_LEN);

    dcache_clean_range(seg_buf, frag.len);
    eth_send_frags_async(&frag, 1u);
}

/* Ctrl+C中断要求フラグ(tcp.hのtcp_abort_requested()コメント参照)。
 *
 * 【2026-08-08変更、job stepのctx経由リソース参照化】マルチコア化
 * Phase 4では「立てるコアと確認するコアは常に同じ」という前提でコアごとに
 * 独立配列化していたが、これは誤りだった -- shell_line_poll()(command.c、
 * UARTは物理的にcore0のシェルにしか無い)がCtrl+Cを検知して
 * tcp_request_abort()を呼ぶのは常にcore0からだが、それを確認する側
 * (nvmet_admin_job_step()等のjob step)はjob.cの共有スケジューラにより
 * core1でtickされることがある。per-core配列のままだと、core0が立てた
 * フラグはs_abort_requested[0]にしか反映されず、core1で実行中のjob
 * step(s_abort_requested[1]を見る)は永久にこの中断要求を観測できない --
 * 「Ctrl+Cを押しても長時間コマンドが中断されない」という無言のバグに
 * なる。単一の共有フラグへ変更した(立てる/消す頻度は極めて低く、
 * ロック無しの単純なvolatile int読み書きで十分、g_core1_heartbeat等と
 * 同じ規約)。 */
static volatile int s_abort_requested;

int tcp_abort_requested(void)
{
    return s_abort_requested;
}

void tcp_clear_abort_request(void)
{
    s_abort_requested = 0;
}

void tcp_request_abort(void)
{
    s_abort_requested = 1;
}

/* tcp_send_async()(tcp.h参照)が送りっぱなしにした未確認セグメントの
 * キュー(先頭=最古)について、ACK到達を確認し、まだ未確認かつRTOを
 * 超えていれば再送する。tcp_poll_once()から全アクティブconn分呼ばれ、
 * 呼び出し元を一切ブロックしない -- 再送するとしても1回のtcp_send_
 * segment()呼び出しのみで、その送信完了(ハードウェアTX)は待たない
 * (eth_send_frags_async()と同じ「キューできれば成功」方針)。
 * priv->snd_unaはtcp_input()のESTABLISHED/CLOSE_WAITケースが受信した
 * 全ACKについて無条件に累積更新し続けているため、ここから読むだけで
 * 「このセグメントは既に確認されたか」を判定できる。
 *
 * 先頭から順に確認できるだけ確認する(TCPのACKは累積確認のため、先頭が
 * 確認済みなら次のスロットも既に確認済みの可能性がある -- 1回のpollで
 * 複数スロットが一気に確認されることがある)。先頭がまだ未確認なら、
 * それより新しいスロットも当然未確認なのでそこで抜ける(RTO判定・
 * 再送は先頭の1件のみ、1回のpollにつき最大1回の再送に留める点は旧設計
 * と同じ)。 */
/* tcp_send()の直前で定義される共有ヘルパへの前方宣言(tcp_priv_t.
 * in_bulk_sendコメント参照) -- tcp_async_poll()はこのファイル内で
 * tcp_send()より前に定義されているため必要。 */
static void tcp_cwnd_grow_on_ack(tcp_priv_t *priv, uint16_t mss);

/* tcp_async_slot_at()の前方宣言(tcp_async_poll()がこのファイル内で
 * その定義より前にあるため必要、上記TCP_ASYNC_SLOTS_MLX5_EXTRA/
 * tcp_priv_t.async_overflow_idxコメント参照)。 */
static tcp_async_slot_t *tcp_async_slot_at(tcp_priv_t *priv, unsigned core, unsigned logical_idx);

static void tcp_async_poll(tcp_conn_t *conn, tcp_priv_t *priv)
{
    /* 2026-08-10、実機で発見した本物の性能バグの修正(tcp_priv_t.
     * in_bulk_sendコメント参照): tcp_send_async()専用コネクションでは
     * cwndが一生成長しないバグがあった。tcp_send()が今このコネクションを
     * 駆動中でなければ(in_bulk_send==0)、ここでack_advancedを消費して
     * cwndを成長させる -- tcp_send()自身が動いている間はそちらが同じ
     * フラグを見て成長させるため、二重処理を避けてスキップする。 */
    if (priv->ack_advanced && !priv->in_bulk_send) {
        priv->ack_advanced = 0;
        tcp_cwnd_grow_on_ack(priv, conn->snd_mss);
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 0), tcp_conn_arg(conn, priv->cwnd));
    }

    while (priv->async_count > 0) {
        tcp_async_slot_t *s = tcp_async_slot_at(priv, conn->owner_core, priv->async_head);
        uint32_t end_seq = s->seq + s->len;
        if (!tcp_seq_lt(priv->snd_una, end_seq)) {
            /* 累積ACKが既にこのセグメントを追い越した = 確認済み。
             * 次の(それより新しい)スロットも確認済みかもしれないので
             * ループを継続する。 */
            priv->async_head = (priv->async_head + 1u) % priv->async_cap;
            priv->async_count--;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 1), tcp_conn_arg(conn, s->len));
            continue;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;  /* まだRTO未満、様子見(呼び出し元はブロックしていない) */
        }

        s->retries++;
        if (s->retries > TCP_MAX_RETRIES) {
            uart_printf("[!] TCP: tcp_send_async再送上限到達、ACK確認できず (seq=%u len=%u)\n",
                        s->seq, (unsigned)s->len);
            /* 先頭が脱落するとキュー全体の前提(先頭より新しいスロットは
             * 全て先頭より後ろのseq)が崩れるうえ、そもそも同一コネクション
             * で1件でも再送上限に達するのはリンク自体が怪しい状況なので、
             * 単純化のためキュー全体を諦める。
             *
             * 2026-08-10、実機で発見した本物のバグの修正: この「諦める」
             * 処理はasync_head/async_count(キューの追跡状態)だけをリセット
             * しており、conn->snd_seq(tcp_send_async()が確認を待たず
             * 楽観的に進めた値)をpriv->snd_una(実際に確認された値)へ
             * 戻していなかった。tcp_send_async()の新しいウィンドウ/cwnd
             * チェック(room = usable_window - (conn->snd_seq-priv->
             * snd_una))はこの2つの値の差分を見るため、諦めた後もこの
             * 差分が一切縮まらず、room==0のまま待ち続けるループが
             * 文字通り無限に終わらなくなる(telnetを含むcore0全体が
             * 応答不能になる重大な実機バグとして発見、CLAUDE.md参照)。
             * conn->snd_seqをpriv->snd_unaまで巻き戻し、諦めた分の
             * バイトを「未送信」として扱い直すことで整合性を復元する
             * (tcp_send()の全体タイムアウト時と同じく、確認できた分
             * [priv->snd_una]だけを正としてsnd_seqと合わせる設計)。 */
            conn->snd_seq = priv->snd_una;
            priv->async_head  = 0;
            priv->async_count = 0;
            /* 2026-08-11、短小PDU専用キュー(async_short_*)を追加した際の
             * 整合性対応: conn->snd_seq/priv->snd_unaはこのコネクション
             * 全体で共有される単一のシーケンス空間であり、上の巻き戻しは
             * async_slots[]側の未確認データだけでなくasync_short_slots[]
             * 側が保持していた(まだ確認されていない)分もまとめて「未送信」
             * 扱いに戻す -- 短小キュー側の追跡だけを残すと、そちらの
             * スロットが指すseqがconn->snd_seqより先の(巻き戻し後は
             * 未使用になった)範囲を指したままになり、次の実送信がその
             * 同じseq範囲を再利用して破綻する。 */
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            return;
        }
        g_tcp_retransmit_count[smp_core_index()]++;
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 2), tcp_conn_arg(conn, (uint32_t)s->retries));

        /* tcp_send_segment()/tcp_send_segment_lso()はconn->snd_seqをSEQ
         * フィールドに使うため、この再送の間だけ元のseqへ戻す。
         * 2026-08-10、LSO対応: このスロットがmssを超える長さ(LSO経由で
         * 送られたチャンク)なら、再送も同じくtcp_send_segment_lso()で
         * 行う必要がある — 通常のtcp_send_segment()にmss超の長さを渡すと
         * 実物理フレームの上限を超えるジャンボフレームより大きい単一
         * フレームを組み立てようとして失敗する(送信元がLSO経由だった
         * 以上、宛先が受け取れる分割はHWしか行えない)。 */
        uint32_t saved_snd_seq = conn->snd_seq;
        conn->snd_seq = s->seq;
        /* 2026-08-15、ゼロコピー送信(s->ref!=NULL): bufへコピーしていない
         * ので再送も安定した送信元(ref)から直接行う。呼び出し元がACK確認
         * までrefの生存を保証している(tcp_send_async_ref()参照)。 */
        const uint8_t *rsrc = s->ref ? s->ref : s->buf;
        if (s->len > conn->snd_mss) {
            tcp_send_segment_lso(conn, priv, rsrc, s->len);
        } else {
            tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, rsrc, s->len);
        }
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
        return;
    }
}

/* tcp_async_poll()の短小PDU専用キュー版(上記TCP_ASYNC_SHORT_MAX_LEN/
 * tcp_priv_t.async_short_slots[]コメント参照)。ack_advanced/cwnd成長
 * 処理は呼び出し元(tcp_poll_once_ex())がtcp_async_poll()の中で既に
 * 1回行っているため、ここでは重複させない -- 確認/再送の追跡だけを
 * async_short_head/async_short_countについて行う、tcp_async_poll()の
 * whileループ以下と全く同じロジック(async_cap固定=TCP_ASYNC_SHORT_
 * SLOTSでオーバーフロープールを持たないため、スロットは直接
 * priv->async_short_slots[]を参照するだけでよい)。 */
static void tcp_async_short_poll(tcp_conn_t *conn, tcp_priv_t *priv)
{
    while (priv->async_short_count > 0) {
        tcp_async_short_slot_t *s = &priv->async_short_slots[priv->async_short_head];
        uint32_t end_seq = s->seq + s->len;
        if (!tcp_seq_lt(priv->snd_una, end_seq)) {
            priv->async_short_head = (priv->async_short_head + 1u) % TCP_ASYNC_SHORT_SLOTS;
            priv->async_short_count--;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_short_poll, 0), tcp_conn_arg(conn, s->len));
            continue;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;
        }

        s->retries++;
        if (s->retries > TCP_MAX_RETRIES) {
            uart_printf("[!] TCP: tcp_send_async(short)再送上限到達、ACK確認できず (seq=%u len=%u)\n",
                        s->seq, (unsigned)s->len);
            /* tcp_async_poll()の同種処理と同じ理由でconn->snd_seqを
             * 巻き戻し、基礎キュー側の追跡も一緒に破棄する(上記
             * tcp_async_poll()の追加コメント参照 -- 単一のシーケンス
             * 空間を共有しているため、片方だけの巻き戻しは他方の
             * スロットが指すseqを無効化してしまう)。 */
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
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
        return;
    }
}

/* 1回のRXポーリング+ディスパッチを行う(tcp_input()経由でアクティブな
 * 全conn(s_conns[])の状態が更新されうる)。arp_resolve()/
 * icmp_wait_echo_reply()と同じパターン。
 * 呼ばれるたびにUARTの未読バイトも確認しCtrl+Cを検出する
 * (tcp_abort_requested()コメント参照) -- このプロジェクトのあらゆる
 * 長時間ブロックする待ちループがtcp_poll_once()を経由するため、ここが
 * Ctrl+C検出の一元的な入口になる。
 * 併せて全アクティブconnのtcp_send_async()未確認セグメントを背後で
 * 確認/再送する(tcp_async_poll()参照) -- このプロジェクトのあらゆる
 * 長時間ブロックする待ちループがここを経由するため、tcp_send_async()の
 * 呼び出し元が次にブロックする待ち(nvmet_tcp_recv_exact()等)の間に
 * 自然に再送機会が回ってくる。 */
/* check_ctrl_c=0: uart_check_ctrl_c()を呼ばない(=UARTの未読バイトを一切
 * 消費しない)版。tcp_recv_internal()がtimeout_val_ms==0(ジョブ化された
 * nvmet-io/telnet/nvmeの受信ポーリング、iperf3の1バイト覗き見等が使う
 * 「1回だけ試して即返る」呼び出し)で使う -- このdo-whileは呼び出しの
 * たびに必ず1周だけで終わる(timeout_ms(start, 0)がget_ms_from(start)>=0
 * より常に真になるため)ため、tcp_abort_requested()の結果はそもそも
 * 戻り値に一切影響しない(むしろチェックしてしまうと、たまたま同じ
 * net_poll_all_and_dispatch()でデータが届いていてもCtrl+C側を先に見て
 * 中断扱いにしてしまう、という逆に不利な副作用すらある)。にもかかわらず
 * 呼ばれるたびにUARTから1バイト読んで(Ctrl+Cでなければ)捨てていたため、
 * ジョブが複数稼働していると`shell_line_poll()`より先にこちらが割り込み
 * ユーザーの入力文字を静かに横取りしていた(実機で確認、CLAUDE.md
 * 参照)。genuine な複数tick/複数秒にまたがる待ち(tcp_send()の再送
 * ループ、tcp_accept_ready_poll()、手動`tcp recv`コマンド等)では
 * Ctrl+Cによる中断が引き続き意味を持つため、そちらはcheck_ctrl_c=1の
 * まま(tcp_poll_once()経由)変更しない。 */
static void tcp_poll_once_ex(int check_ctrl_c)
{
    unsigned core = smp_core_index();

    if (check_ctrl_c && uart_check_ctrl_c()) {
        s_abort_requested = 1;
    }

    // net_poll_all_and_dispatch(): 登録済みの全コンテキストをポーリング
    // する(netif.h、arp.c/icmp.cの待ちループと同じ理由 -- ConnectXの
    // PF0/PF1のように複数インターフェースを並行運用する場合、片方の
    // コネクションの応答待ち中でも、もう片方が受信・自動応答できる
    // 必要があるため)。登録数が1つ(通常のRP1単体運用)でも従来と
    // 同じ動作になる。
    net_poll_all_and_dispatch();

    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] != NULL) {
            // tcp_async_poll()内部の再送はtcp_send_segment()を経由する
            // ため、そちらで各connのコンテキストへ改めて切り替わる
            // (上記コメント参照) -- ここで明示的に切り替える必要は無い。
            tcp_async_poll(s_conns[core][i], &s_priv[core][i]);
            tcp_async_short_poll(s_conns[core][i], &s_priv[core][i]);
        }
    }

    /* s_timewait[](tcp_close()コメント参照)の期限切れエントリを掃除する。
     * TCP_TIMEWAIT_MAXが小さい固定配列なので、この頻度(tcp_poll_once()
     * 経由、あらゆる待ちループから呼ばれる)で毎回走査しても無視できる
     * コスト。 */
    tcp_timewait_reap();
}

static void tcp_poll_once(void)
{
    tcp_poll_once_ex(1);
}

/* flags/data(data_len)のセグメントを送信し、priv->expected_ack(呼び出し前に
 * 設定しておく)に一致するACKが返るまでRTOベースの指数バックオフで再送する
 * (初期RTOはpriv->rto_ms、以降2倍ずつ、TCP_MAX_RTO_MSで頭打ち、
 * 最大TCP_MAX_RETRIES回再送)。SYN/FIN/純ACKなど単発の信頼送信に使う
 * (複数セグメントのパイプライン送信はtcp_send()が別のエンジンで行う)。
 * ACK受信の判定はtcp_input()側の各状態ハンドラがpriv->ack_received=1を
 * セットすることで行う。同一のseq/data再送となるため、conn->snd_seqは
 * 呼び出し元が成功後に進めること(このヘルパの中では進めない)。
 * 初回送信で(再送を経ずに)ACKを確認できた場合のみRTTを測定してSRTT/RTTVAR
 * を更新する(Karnのアルゴリズム -- 再送後のACKはどちらの送信への応答か
 * 曖昧なため測定に使わない)。
 * 戻り値: 0=ACK確認、-1=再送上限到達またはRST等でコネクション断 */
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
            /* 真の同時クローズ(自分のFINへのACKがまだ届く前に、相手も
             * 独立に自分のFINを送ってきた)対応(2026-08-08、マルチコア化
             * Phase 6でcore1オフロードを実機テストした際に発見) --
             * tcp_close()のTCP_FIN_WAIT_1ハンドラ(tcp_input())は、相手の
             * FINを受信した時点でこちらのACKを返しconn->state=TCP_TIME_
             * WAITへ進めるが、この経路はpriv->ack_receivedを一切セット
             * しない(自分のFIN自体へのACKはまだ確認できていないため)。
             * 修正前は、この場合でもack_receivedだけを見て待ち続けるため
             * 無駄なFIN再送(最大5回、RTO指数バックオフで合計約12秒)を
             * 引き起こしていた -- 実機で、initiator(core0)とtarget
             * (core1)がそれぞれ独立にadmin接続をactive closeする構成
             * (nvmet_io_job_end()がIOキュー切断検出時にadmin接続も
             * カスケードでcloseする、CLAUDE.md「nvmet: 常駐サーバ化」節
             * 参照)で高頻度に再現した -- initiator/target が同一コアで
             * 順序立てて実行される非分離構成では踏みにくかったレースが、
             * 真に並行実行されるcore分離構成で顕在化した。TIME_WAITへの
             * 遷移自体が「接続は(少なくとも片方向は)正しく閉じられた」
             * ことを意味するため、これも成功として扱ってよい。 */
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

/* 受信したSYNまたはSYN-ACKのオプション領域(TCPヘッダの後、opts_len
 * バイト)からMSS/Window Scaleオプションを探す。NOP/未知のオプションは
 * それぞれの規則(NOPは1バイト、他はkind+lenで示された長さ)に従って
 * スキップする -- SACK-permitted/timestamps等、相手が付けてくるかも
 * しれない他のオプションが混ざっていても正しく読み飛ばせる。
 *
 * MSSオプションが見つかればconn->snd_mssを更新する(従来のtcp_parse_
 * mss_option()と同じ、2026-07-25にWindow Scale対応も統合してこの名前に
 * 改名した)。
 *
 * Window Scaleオプションが見つかれば、呼び出し元の状況に関わらず常に
 * priv->wscale_enabled=1・priv->snd_wscale=相手のshiftを設定する --
 * これは「相手がこのセグメントでWindow Scalingを提案/確認してきた」と
 * いう事実を記録するだけで、呼び出し元(tcp_input())の文脈に応じて
 * 正しい意味になる: 能動open側がSYN-ACKをパースする場合は「相手も
 * 確認したので双方成立」、受動open側が(相手の)SYNをパースする場合は
 * 「相手が提案してきたので、この直後に送るSYN|ACKで自分も含めれば
 * 双方成立」(tcp_send_segment()のinclude_wscale判定はpriv->wscale_
 * enabledをそのまま見るため、受動open側はこの関数が返った時点で
 * 既に「成立する」ことが確定している -- 呼び出し順序はtcp_input()の
 * SYN受け付けブロック参照)。見つからなければ何もしない(呼び出し前の
 * 値のまま -- tcp_priv_init()で0になっている)。 */
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
            /* 自分がこのコネクションで安全に送信できる上限(net_active_
             * mss_cap()、netif.hのnetif_t.mss_cap参照)で上限する --
             * 静的バッファ容量(TCP_MSS_LOCAL)ではなく、現在アクティブな
             * バックエンド(ConnectX等、ジャンボ非対応の可能性がある)の
             * 実際の送信能力を見る。 */
            uint16_t local_cap = net_active_mss_cap();
            if (peer_mss > local_cap) peer_mss = local_cap;
            conn->snd_mss = peer_mss;
            uart_printf("[TCP] 相手のMSSオプション受信: %u (採用値=%u)\n",
                        rd16be(opts + i + 2), conn->snd_mss);
        } else if (kind == TCP_OPT_KIND_WSCALE && opt_len == 3) {
            uint8_t peer_shift = opts[i + 2];
            /* RFC7323 2.2: shiftは0-14に制限される(15を超える値を
             * 送ってくる実装は無い前提だが、念のためクランプする --
             * クランプせずbit32以上を右シフトする箇所は無いため実害は
             * 無いが、明示しておく)。 */
            if (peer_shift > 14u) peer_shift = 14u;
            priv->wscale_enabled = 1;
            priv->snd_wscale = peer_shift;
            uart_printf("[TCP] 相手のWindow Scaleオプション受信: shift=%u\n", peer_shift);
        }
        i = (uint8_t)(i + opt_len);
    }
}

/* mlx5専用の追加非同期送信スロットプール(2026-08-11、上記TCP_ASYNC_
 * SLOTS_MLX5_EXTRAコメント参照)。tcp_priv_t本体には入れず、コアごとに
 * 独立した固定配列として持つ -- RP1コネクション用のtcp_priv_t.async_
 * slots[](TCP_ASYNC_SLOTS=16のまま)を一切肥大化させないため。 */
typedef tcp_async_slot_t tcp_async_mlx5_extra_t[TCP_ASYNC_SLOTS_MLX5_EXTRA];
static tcp_async_mlx5_extra_t s_async_mlx5_overflow[SMP_MAX_CORES][TCP_ASYNC_MLX5_OVERFLOW_CONNS];
static uint8_t s_async_mlx5_overflow_used[SMP_MAX_CORES][TCP_ASYNC_MLX5_OVERFLOW_CONNS];

static void tcp_async_overflow_release(unsigned core, int idx)
{
    if (idx >= 0 && (unsigned)idx < TCP_ASYNC_MLX5_OVERFLOW_CONNS) {
        s_async_mlx5_overflow_used[core][idx] = 0u;
    }
}

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

/* 論理スロット番号(0..priv->async_cap-1)から実際のtcp_async_slot_tへの
 * ポインタを引く。logical_idx<TCP_ASYNC_SLOTSならpriv自身のasync_slots[]
 * (全コネクション共通、RP1もmlx5もここは同じ)、それ以上はmlx5専用の
 * オーバーフロープール(priv->async_overflow_idx>=0の場合のみ有効)。 */
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

/* local_ipの所属インターフェースがmlx5(hw_csum_offload、netif.hの
 * netif_t.hw_csum_offloadコメント参照 -- mlx5バックエンドのみ1)なら、
 * 空きがある限りオーバーフロープールから1件割り当ててasync_capを
 * TCP_ASYNC_SLOTS+TCP_ASYNC_SLOTS_MLX5_EXTRAへ引き上げる。RP1、または
 * プール枯渇時はasync_cap=TCP_ASYNC_SLOTSのまま(安全側のフォール
 * バック、エラーにはしない)。tcp_priv_init()の直後、conn->local_ipが
 * 確定してから呼ぶこと(tcp_connect_begin()/受動openの両呼び出し元
 * 参照)。 */
static void tcp_priv_try_grant_mlx5_async_overflow(tcp_priv_t *priv, unsigned core, uint32_t local_ip)
{
    netif_t *ctx = netif_find_by_ip(local_ip);
    if (!ctx || !ctx->hw_csum_offload) {
        return;  /* RP1、または未解決 -- TCP_ASYNC_SLOTSのまま */
    }
    int idx = tcp_async_overflow_acquire(core);
    if (idx >= 0) {
        priv->async_overflow_idx = idx;
        priv->async_cap = TCP_ASYNC_SLOTS + TCP_ASYNC_SLOTS_MLX5_EXTRA;
    }
}

/* コネクションごとのプライベート状態を初期値へリセットする。
 * tcp_connect()(能動open)とtcp_input()内のSYN受け付けブロック(受動open)
 * の両方から呼ぶ共通ヘルパ -- 初期化手順が重複しないようにする。
 * coreはこのpriv自身が属するコア(conn->owner_coreと同じ値になる予定の
 * もの) -- 前回このスロットが保持していたmlx5オーバーフロー割り当てを
 * 解放するために使う(tcp_priv_t.async_overflow_idxコメント参照、この
 * 時点ではまだ新しいコネクションのlocal_ipが確定していないため、新規
 * 割り当てはここでは行わない -- tcp_priv_try_grant_mlx5_async_
 * overflow()を別途呼ぶこと)。 */
static void tcp_priv_init(tcp_priv_t *priv, unsigned core)
{
    /* async_overflow_ever_initコメント参照: 初回(BSSゼロ初期化直後)は
     * まだ何も保持していないため解放しない。 */
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
    priv->rx_read       = 0;
    priv->rx_count      = 0;
    priv->fin_received  = 0;
    priv->recv_upcall     = NULL;
    priv->recv_upcall_ctx = NULL;
    priv->wscale_enabled = 0;
    priv->snd_wscale     = 0;
    priv->unacked_full_segments = 0;
    priv->unacked_consumed_bytes = 0;
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

/* RFC5681の初期ウィンドウ(IW)公式でcwnd/ssthreshを設定する:
 * IW = min(4*MSS, max(2*MSS, 4380 bytes))。MSSが確定した
 * (能動openならSYN-ACK、受動openなら相手のSYNのMSSオプションを解析し
 * 終えた)ESTABLISHEDへ遷移するこの時点で呼ぶ。tcp_connect()(能動open)と
 * tcp_input()内のTCP_SYN_RCVDハンドラ(受動open)の両方から呼ぶ共通ヘルパ。 */
static void tcp_cwnd_init(tcp_conn_t *conn, tcp_priv_t *priv)
{
    uint32_t four_mss  = 4u * conn->snd_mss;
    uint32_t two_mss   = 2u * conn->snd_mss;
    uint32_t floor_val = (two_mss > 4380u) ? two_mss : 4380u;
    priv->cwnd = (four_mss < floor_val) ? four_mss : floor_val;
    priv->ssthresh = 0xFFFFFFFFu;  /* 初回はロスがあるまで実質無制限(スロースタート主導) */
}

void tcp_connect_begin(tcp_conn_t *conn, uint32_t dst_ip, uint16_t dst_port)
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
    conn->local_ip    = NET_SELF_IP;
    conn->remote_ip   = dst_ip;
    conn->remote_port = dst_port;
    conn->snd_win     = 0;                     /* 相手の最初のACKで確定するまでは未知 */
    conn->snd_mss     = TCP_MSS_DEFAULT_RFC879; /* 相手がMSSオプションを付けなければこの既定値のまま */
    conn->rcv_seq     = 0;

    /* ISN(初期シーケンス番号)はタイマカウンタから適当に採る。
     * local_portも同じ値から49152-65535の範囲で選ぶ(RFC6335の動的/
     * private port範囲)。複数コネクションが短時間に接続する場合でも
     * timer_now()は単調増加するため、通常は異なる値になる。 */
    uint32_t isn = (uint32_t)timer_now();
    conn->snd_seq   = isn;
    conn->local_port = (uint16_t)(49152u + (isn & 0x3fffu));

    /* プライベート状態をこのコネクション用にリセットする。local_ipは
     * 上で既に確定済みなので、続けてmlx5オーバーフロー割り当ても試みる
     * (tcp_priv_try_grant_mlx5_async_overflow()コメント参照)。 */
    tcp_priv_init(priv, core);
    tcp_priv_try_grant_mlx5_async_overflow(priv, core, conn->local_ip);

    /* tcp_connect_poll()でのポーリング中にtcp_input()がディスパッチ
     * できるよう、送信前に登録しておく。owner_coreもここで確定させる
     * (tcp.hのtcp_conn_t.owner_coreコメント参照 -- 以後tcp_priv_for()等
     * 全てのスロット逆引きがこの値を使う)。 */
    conn->owner_core = core;
    s_conns[core][slot] = conn;

    uint8_t dst_octets[4];
    ip_to_octets(dst_ip, dst_octets);
    uart_printf("[TCP] connect: %u.%u.%u.%u:%u へSYN送信 (local_port=%u, isn=%u, slot=%d)\n",
                dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3],
                dst_port, conn->local_port, isn, slot);

    conn->state = TCP_SYN_SENT;
    /* expected_ack(isn+1)はACK確認だけでなく、ESTABLISHED確定時に
     * conn->snd_seqへそのまま採用する(SYNの1バイト消費分)ためにも使う
     * -- 旧tcp_connect()の`conn->snd_seq = isn + 1;`と同じ値。 */
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

int tcp_connect_poll(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        return -1;  /* tcp_connect_begin()を呼んでいない(呼び出し規約違反) */
    }

    if (tcp_abort_requested()) {
        /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照)。旧tcp_send_
         * reliable()と同じく、中断は接続失敗として扱う。 */
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    if (priv->ack_received) {
        if (conn->state == TCP_ESTABLISHED) {
            /* 初回送信(再送を経ず)でACKを確認できた場合のみRTTを測定する
             * (Karnのアルゴリズム、旧tcp_send_reliable()と同じ)。 */
            if (priv->connect_attempt == 0) {
                tcp_rtt_update(priv, timer_now() - priv->connect_sent_at);
            }
            conn->snd_seq = priv->expected_ack;  /* SYNは1バイト分のシーケンス番号を消費する */
            tcp_cwnd_init(conn, priv);
            uart_printf("[TCP] connect: ESTABLISHED (peer MSS=%u, 初期cwnd=%u)\n",
                        conn->snd_mss, priv->cwnd);
            return 1;
        }
        /* ack_receivedだがESTABLISHEDでない状態は通常起きないはずだが、
         * 念のため下の「接続失敗」経路で処理させる(フォールスルー)。 */
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

int tcp_connect(tcp_conn_t *conn, uint32_t dst_ip, uint16_t dst_port)
{
    tcp_connect_begin(conn, dst_ip, dst_port);
    if (conn->state == TCP_CLOSED) {
        return -1;  /* tcp_connect_begin()内で即座に失敗(スロット枯渇/送信失敗) */
    }

    int r;
    while ((r = tcp_connect_poll(conn)) == 0) {
        /* tcp_connect_poll()自体はtcp_poll_once()を呼ばない(ジョブ化された
         * 呼び出し元は、メインループが毎tick呼ぶnet_poll_all_and_dispatch()
         * に相乗りする設計、CLAUDE.md「NVMe/TCP制御のステートマシン化」
         * 節参照)。このブロッキング版では自前でポーリングを回す必要が
         * ある -- 旧実装のtcp_send_reliable()内のdo-whileループが果たして
         * いたのと同じ役割。 */
        tcp_poll_once();
    }
    return (r == 1) ? 0 : -1;
}

/* cwnd(輻輳ウィンドウ)成長ロジック(RFC5681簡易版、priv->ack_advanced=1を
 * 見た時に呼ぶ)。元はtcp_send()自身のバーストループに直書きされていたが、
 * tcp_send_async()専用コネクション(priv->ack_advancedをtcp_send()以外の
 * 誰も消費しない)ではcwndが初期値のまま一生成長しないバグがあったため
 * (このプロジェクトのtcp_priv_t.in_bulk_sendコメント参照)、tcp_send()と
 * tcp_async_poll()の両方から呼べる共有関数として抽出した。呼び出し前に
 * priv->ack_advancedを見て呼ぶかどうかを判断するのは呼び出し元の責務
 * (この関数自体はack_advancedのクリアも行わない)。 */
static void tcp_cwnd_grow_on_ack(tcp_priv_t *priv, uint16_t mss)
{
    if (priv->cwnd < priv->ssthresh) {
        priv->cwnd += mss;
    } else {
        uint32_t inc = ((uint32_t)mss * mss) / priv->cwnd;
        if (inc == 0) inc = 1u;
        priv->cwnd += inc;
    }
}

int tcp_send(tcp_conn_t *conn, const void *buf, uint32_t len)
{
    /* ESTABLISHEDに加えCLOSE_WAIT(相手が先にFIN済みの半クローズ状態)でも
     * 送信を許可する -- こちらの送信方向はまだ閉じていないため、RFC793上
     * 正当に送信を続けられる(tcp.h冒頭コメント参照)。 */
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

    /* 呼び出し元バッファはtcp_send_segment()へそのまま渡されるため、
     * その中で既にvolatile経由アクセスされる(tcp_send_segment()の
     * vdata)。ここではポインタ演算のみ行う -- このバッファはtcp_send()が
     * 返るまで呼び出し元が保持し続ける前提なので、再送のたびにコピーを
     * 取らずここから直接参照してよい(go-back-N再送)。 */
    const uint8_t *data = buf;

    /* TCP層の性能分析用(timestamp.h参照)。tcp_send()呼び出し1回分の
     * 開始/終了を対応付けられるよう、開始時にlenを記録する。 */
    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 0), tcp_conn_arg(conn, len));

    uint32_t base_seq = conn->snd_seq;
    uint32_t end_seq   = base_seq + len;
    uint32_t snd_nxt    = base_seq;   /* 次に新規送信するseq */

    /* 累積ACK進捗をtcp_input()と共有するための状態をこの呼び出し用に
     * リセットする。 */
    priv->snd_una = base_seq;
    priv->ack_advanced = 0;

    /* tcp_priv_t.in_bulk_sendコメント参照 -- この関数が動いている間、
     * tcp_async_poll()側のcwnd成長処理(同じpriv->ack_advancedを見る)が
     * 二重に消費してこの関数自身のRTT/RTO計測を横取りしないようにする。 */
    priv->in_bulk_send = 1;

    uint64_t overall_start = timer_now();

    /* SWINタグ(下記usable_window計算部参照)の重複ログ抑制用 -- 同じ値が
     * 続く間は毎ループ再ログしない(リングバッファ浪費防止)。 */
    uint32_t last_logged_swin = 0xFFFFFFFFu;

    int      rto_active = 0;            /* 未確認データがあり再送タイマが有効か */
    uint64_t window_sent_at = 0;        /* 現在の未確認ウィンドウの先頭を送った時刻(RTT計測用) */
    uint32_t rto_ms = priv->rto_ms;
    int      window_retransmitted = 0;  /* 現在の未確認ウィンドウ内で再送が起きたか(Karnのアルゴリズム) */
    int      retransmit_attempts = 0;   /* 連続再送回数(進捗があるたびリセット) */

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

        /* 送信可能なウィンドウ = min(相手の広告ウィンドウ, 輻輳ウィンドウ)。
         * 0の間もRFC1122 4.2.2.17のpersist相当として1バイトだけ送る余地を
         * 残す(相手が実際に1バイト分の受け入れ余地を常に確保している
         * 前提の慣行 -- 別立てのプローブ用ステートマシンを持たずに自然と
         * 持続待ちが実現できる)。 */
        uint32_t usable_window = conn->snd_win;
        if (priv->cwnd < usable_window) usable_window = priv->cwnd;
        if (usable_window == 0) usable_window = 1u;

        /* 送るデータはまだ残っているのに、相手の広告ウィンドウ/輻輳
         * ウィンドウのどちらかが尽きていて今は1バイトも新規送信できない
         * (persist相当を除く) -- SEND_H2C等の送信全般の遅延がウィンドウ
         * 枯渇によるものかを直接判別するための計装(2026-08-09、コア0の
         * SEND_H2C/RECV_CQE遅延解析向けにユーザー指示で追加)。argの
         * 下位24bitはusable_window(=ボトルネックとなっている方の値)。
         * 値が変化したときだけ記録する(同じ値の連打でリングバッファを
         * 浪費しないため)。 */
        if (tcp_seq_lt(snd_nxt, end_seq) && !tcp_seq_lt(snd_nxt, priv->snd_una + usable_window)) {
            if (usable_window != last_logged_swin) {
                if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 1), tcp_conn_arg(conn, usable_window));
                last_logged_swin = usable_window;
            }
        }

        /* ウィンドウの許す範囲、かつ送るデータが残っている限り、ACKを
         * 待たずに複数セグメントを連続送信する(パイプライン化 -- Tier3の
         * 核心。旧実装は1セグメント送るごとにACKを待っていた)。 */
        while (tcp_seq_lt(snd_nxt, end_seq) &&
               tcp_seq_lt(snd_nxt, priv->snd_una + usable_window)) {
            uint32_t remaining_in_window = (priv->snd_una + usable_window) - snd_nxt;
            uint32_t remaining_data = end_seq - snd_nxt;
            uint32_t chunk32 = (remaining_in_window < remaining_data) ? remaining_in_window : remaining_data;
            /* 2026-08-10、LSO対応。net_active_lso_max_bytes()>0(ConnectX
             * のみ)なら、1 MSSではなくLSO上限までまとめて送ってよい --
             * TCP_LSO_MAX_DATA_LEN(IP total_lenの16bitフィールドが実際に
             * 表現できる上限)でさらにクランプする(tcp_send_segment_lso()
             * 直前コメント参照)。LSO非対応(RP1、または未初期化)なら
             * lso_max=0のまま、従来通りconn->snd_mssが上限になる。 */
            uint32_t lso_max = net_active_lso_max_bytes();
            if (lso_max > TCP_LSO_MAX_DATA_LEN) lso_max = TCP_LSO_MAX_DATA_LEN;
            uint32_t seg_cap = (lso_max > 0u) ? lso_max : conn->snd_mss;
            if (chunk32 > seg_cap) chunk32 = seg_cap;
            if (chunk32 == 0) break;
            uint16_t chunk = (uint16_t)chunk32; // TCP_LSO_MAX_DATA_LEN/snd_mssいずれもuint16_tへ安全に収まる

            conn->snd_seq = snd_nxt;  /* tcp_send_segment()/tcp_send_segment_lso()共通、conn->snd_seqをSEQフィールドに使う */
            /* chunk32がlso_maxクランプの効果で実際に1 MSSを超えている
             * 場合だけLSO経路を使う(ユーザー確認済みスコープ -- Go-Back-N
             * 再送・tcp_send_async()・SYN送信は対象外のままtcp_send_
             * segment()を使う、~/.claude/plans/lexical-squishing-mitten.md
             * 参照)。lso_max>0でもchunk32がたまたま1 MSS以下(ウィンドウが
             * 狭い等)なら、素直に従来経路のままでよい。 */
            int seg_send_rc = (lso_max > 0u && chunk32 > conn->snd_mss)
                ? tcp_send_segment_lso(conn, priv, data + (snd_nxt - base_seq), chunk32)
                : tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                    data + (snd_nxt - base_seq), chunk);
            if (seg_send_rc != 0) {
                /* eth層で送信失敗(タイムアウト) -- このチャンクはまだ
                 * 「送った」ことにせずsnd_nxtを進めない。直後に次の新規
                 * チャンクを同じ(いま問題を起こしたばかりの)リング
                 * スロットへ重ねて送り込むと、後始末中かもしれない記述子を
                 * 上書きしてハードウェアをさらに混乱させるだけなので、この
                 * バーストはここで打ち切る。次の外側ループの反復で
                 * (snd_una/usable_windowは変わっていないので)同じ
                 * チャンクを素直にやり直す。 */
                break;
            }
            /* TCP層の性能分析用: このセグメントが実際にeth層へキュー
             * された時刻(argはバイト数)。セグメント間の間隔を見れば
             * eth_tx_wait_free_slot()等によるバックプレッシャで送信が
             * 詰まっていないか判別できる。 */
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 2), tcp_conn_arg(conn, chunk));
            snd_nxt += chunk;

            if (!rto_active) {
                rto_active = 1;
                window_sent_at = timer_now();
                window_retransmitted = 0;
            }

            /* このバースト内側ループはtcp_poll_once()を呼ばずに何十セグメントも
             * 連続送信しうる(usable_windowがcwnd/相手の広告ウィンドウの
             * 成長により数十KBに達することがある -- TCP_RX_BUF_SIZE拡張、
             * bench.cのBENCH_MAX_CHUNK拡張後、実機で確認)。その間、相手が
             * 送り返してくるエコーデータはeth_poll_recv()で誰も引き取らず
             * RXリングに溜まり続け、ソフトウェアが1セグメントも受信処理
             * しないまま物理的に溢れてRSR.BNA/OVRを起こしフレームが失われる
             * (実機でフェーズ4=32768Bチャンクにて再送連鎖→接続断で確認・
             * 特定)。以前(BENCH_MAX_CHUNK=4096=3セグメント)はこの無応答
             * 区間が短く問題化しなかっただけで、根本的な欠陥は元から存在
             * した。送信セグメント1本ごとにRXを1回ポーリングし、無応答
             * 区間をリングが溢れない程度に短く保つ。 */
            tcp_poll_once();
            if (tcp_abort_requested()) {
                /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照)。この内側
                 * バーストループは何十セグメントも連続送信しうるため、
                 * 外側ループの確認を待たずここでも打ち切り、応答性を
                 * 上げる。 */
                break;
            }
        }

        tcp_poll_once();

        if (priv->ack_advanced) {
            priv->ack_advanced = 0;
            retransmit_attempts = 0;  /* 進捗があったので連続再送カウントをリセット */

            if (!window_retransmitted) {
                tcp_rtt_update(priv, timer_now() - window_sent_at);
            }

            /* 輻輳制御更新(簡易版、tcp_cwnd_grow_on_ack()参照): スロー
             * スタートはACK進捗ごとに+1MSS、輻輳回避は概ね+1MSS/RTTに
             * なるよう+MSS^2/cwnd。 */
            tcp_cwnd_grow_on_ack(priv, conn->snd_mss);

            /* TCP層の性能分析用: 累積ACKが前進するたびのcwnd(輻輳ウィンドウ)
             * を記録する。ACK到着の間隔(delta)とcwndの伸びを追えば、
             * スロースタート/輻輳回避が育つ前に頭打ちになっていないか、
             * ACKクロッキング自体が疎になっていないかを分析できる。 */
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 3), tcp_conn_arg(conn, priv->cwnd));

            if (tcp_seq_lt(priv->snd_una, snd_nxt)) {
                rto_active = 1;
                window_sent_at = timer_now();
                /* window_retransmittedはここではクリアしない -- 残っている
                 * 未確認データが直前の再送(Go-Back-N)に含まれていた場合、
                 * Karnのアルゴリズムにより引き続きそのデータのACKからは
                 * RTTを測定すべきではない。真に新規のデータを送った時だけ
                 * (下の送信ループの!rto_active分岐)クリアされる。 */
            } else {
                rto_active = 0;
            }
            rto_ms = priv->rto_ms;
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
            /* TCP層の性能分析用: RTOタイムアウトによる再送が起きた回数
             * (argは今回のRTOサイクルでの連続再送回数)。頻発していれば
             * ロス/RTO推定の異常が実際のボトルネックであることが分かる。 */
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 4), tcp_conn_arg(conn, (uint32_t)retransmit_attempts));

            /* 輻輳制御: RTOタイムアウトをロスシグナルとしてスロースタートへ
             * 戻す(RFC5681: ssthresh=flight/2、cwnd=1MSS)。重複ACKによる
             * 高速再送/高速回復(RTOを伴わないより穏やかな半減)は未実装。 */
            uint32_t flight = snd_nxt - priv->snd_una;
            uint32_t half = flight / 2u;
            priv->ssthresh = (half > 2u * conn->snd_mss) ? half : 2u * conn->snd_mss;
            priv->cwnd = conn->snd_mss;

            rto_ms *= 2;
            if (rto_ms > TCP_MAX_RTO_MS) rto_ms = TCP_MAX_RTO_MS;

            /* Go-Back-N: 未確認区間(snd_una..snd_nxt)をまとめて再送する
             * (選択的再送/SACKは未実装 -- 1個でも欠けたら区間全体を
             * 再送する分、効率は劣るが実装は単純)。 */
            uint32_t resend_seq = priv->snd_una;
            while (tcp_seq_lt(resend_seq, snd_nxt)) {
                uint32_t remain = snd_nxt - resend_seq;
                uint16_t rchunk = (uint16_t)((remain > conn->snd_mss) ? conn->snd_mss : remain);
                conn->snd_seq = resend_seq;
                if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                      data + (resend_seq - base_seq), rchunk) != 0) {
                    /* 同上の理由(上のパイプライン送信ループのコメント参照)
                     * -- 失敗したら残りの再送はこのRTOサイクルでは諦め、
                     * 次のRTOサイクルにまとめて任せる。 */
                    break;
                }
                /* TCP層の性能分析用: Go-Back-Nで実際に再送されたバイト数。 */
                if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 5), tcp_conn_arg(conn, rchunk));
                resend_seq += rchunk;
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

/* tcp_send_async()の呼び出しでキューが満杯(async_count==TCP_ASYNC_SLOTS)
 * だった場合にここでブロッキングに解決する -- 少なくとも1件空くまで
 * 待つだけで、キュー全体が空になるまでは待たない(2026-07-25、複数
 * スロット化に伴い「1件でも未確認なら待つ」旧仕様から「満杯の時だけ
 * 待つ」へ緩和 -- これが今回の性能改善の核心)。tcp_async_poll()
 * (tcp_poll_once()経由)が自然にack確認/再送上限到達のどちらかで
 * async_countを減らすまでポーリングし続けるだけで、独自のタイムアウト
 * 計算は持たない(tcp_async_poll()自身のRTO/再送上限が既に上限を
 * 与えているため)。 */
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

/* tcp_async_flush_until_room()と同じ待ちループだが、「最低1件」ではなく
 * キューが完全に空になるまで待つ版。2026-08-09、NVMe/TCPコマンド
 * パイプライン化(nvme.cのnvme_write_pipelined_run()、nvme_tcp.cの
 * nvme_tcp_send_cmd_async()参照)向けに追加 -- 呼び出し規則(tcp.hの
 * tcp_send_async()コメント)「いずれかのtcp_send_async()がまだ未確認の
 * 間に同一connへtcp_send()を呼んではならない」を満たすため、複数の
 * async送信(SQE)をキューした後、同じコネクションへブロッキング
 * tcp_send()(H2CData等、TCP_ASYNC_MAX_LENを超える一括送信)を呼ぶ前に
 * 必ずこれで完全に空にしておく必要がある。 */
void tcp_send_async_drain(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        return;
    }
    /* 2026-08-11、短小PDU専用キュー(async_short_*)追加に伴い、こちらの
     * 未確認分もまとめて空になるまで待つよう拡張した -- 呼び出し元の
     * 契約(この後のtcp_send()呼び出しが安全であること)は、コネクション上の
     * 「いずれの」tcp_send_async()も未確認でないことを要求するため、
     * 基礎キューだけを見て早期に戻ると短小キュー側の未確認分がtcp_send()に
     * よって静かに追跡不能になる(tcp_send_async()呼び出し規則コメント
     * 参照)。 */
    while (priv->async_count > 0 || priv->async_short_count > 0) {
        tcp_poll_once();
        if (tcp_abort_requested()) {
            priv->async_head  = 0;
            priv->async_count = 0;
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            break;
        }
    }
}

/* 1チャンク分(mss以下)をasync_slots[]へキューする共通処理 -- tcp_send_
 * async()の非LSO分割ループ、LSO単発送信のいずれからも呼ぶ。呼び出し前に
 * priv->async_countに空きがあることを呼び出し元が保証すること(この関数
 * 自体は満杯チェック/待ちを行わない)。
 * 戻り値: 0=成功、-1=送信失敗(この場合はキューに積まない、conn->snd_seq
 * も進めない)。 */
static int tcp_send_async_enqueue(tcp_conn_t *conn, tcp_priv_t *priv,
                                   const void *buf, uint16_t len, int use_lso,
                                   int is_ref)
{
    uint32_t seq = conn->snd_seq;

    /* TCP層の性能分析用(timestamp.h参照): 非同期送信の開始 --
     * 対応するAACK(確認)/ARTX(再送)と突き合わせれば、相手のACKが
     * 実際にどれだけ遅れているか(≒ホスト側遅延ACKタイマーの影響)を
     * 後から分析できる。 */
    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_async_enqueue, 0), tcp_conn_arg(conn, len));

    int rc = use_lso
        ? tcp_send_segment_lso(conn, priv, buf, len)
        : tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, buf, len);
    if (rc != 0) {
        return -1;
    }

    /* 呼び出し元へ即座に返るため、再送に備えてデータ自体をコピーして
     * 保持する(bufの生存を前提にできない -- tcp_send()のgo-back-Nが
     * 呼び出し元のbufをそのまま参照し続けられるのとは異なる、tcp.hの
     * tcp_send_async()コメント参照)。キューの末尾(async_head+async_count、
     * 循環)に積む。 */
    unsigned slot_idx = (priv->async_head + priv->async_count) % priv->async_cap;
    tcp_async_slot_t *slot = tcp_async_slot_at(priv, conn->owner_core, slot_idx);

    /* 2026-08-10、実機で発見した本物のバグ: このコピーが1バイトずつの
     * ループのままだった(このプロジェクトで繰り返し見つかっている
     * パターン、CLAUDE.md「NVMe/TCP write性能低下の真因確定」節の
     * tcp_recv_internal()と同型)。volatile_fast_copy()(net.h、8/4/2
     * バイト境界が揃っていればワイドアクセス、揃わなければバイト単位へ
     * 自動フォールバック)へ置き換え済み。 */
    /* 2026-08-15、ゼロコピー送信: is_refなら呼び出し元が安定した送信元の
     * 生存を保証しているので、256KB級のコピーを丸ごと省いてrefだけ保持する
     * (再送もrefから直接、tcp_async_poll()参照)。通常経路はref=NULLにして
     * buf[]へコピー(呼び出し元のbufの生存を前提にできないため)。 */
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

/* tcp_send_async()のlen<=TCP_ASYNC_SHORT_MAX_LEN専用経路(上記TCP_ASYNC_
 * SHORT_MAX_LENコメント参照)。呼び出し元(CMD/RSP/R2T/ICResp送信)は
 * 常にMSSを大きく下回る固定長PDUしか渡さないため、tcp_send_async()本体の
 * 複数チャンク分割/LSO判定ロジックは一切不要 -- 常に単一セグメントで
 * 送り切れる前提で単純化している(この前提はTCP_ASYNC_SHORT_MAX_LEN=512が
 * 現実的な最小MSSより十分小さいことで保証される)。
 * ウィンドウ/cwndチェックはtcp_send_async()の非短小経路と全く同じ式
 * (usable_window=min(snd_win,cwnd)からoutstandingを差し引いたroom)を
 * 使う -- 2026-08-10に発見・修正された「ウィンドウを無視して送ると
 * 相手が黙って破棄し再送も同じ理由で永久に失敗する」実機デッドロックの
 * 再発を避けるため。 */
static int tcp_send_async_short(tcp_conn_t *conn, tcp_priv_t *priv, const void *buf, uint16_t len)
{
    while (priv->async_short_count >= TCP_ASYNC_SHORT_SLOTS) {
        tcp_poll_once();
        if (tcp_abort_requested()) {
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            return -1;
        }
    }

    uint32_t outstanding   = conn->snd_seq - priv->snd_una;
    uint32_t usable_window = conn->snd_win;
    if (priv->cwnd < usable_window) usable_window = priv->cwnd;
    if (usable_window == 0) usable_window = 1u;
    while (usable_window <= outstanding) {
        tcp_poll_once();
        if (tcp_abort_requested() ||
            (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT)) {
            return -1;
        }
        outstanding   = conn->snd_seq - priv->snd_una;
        usable_window = conn->snd_win;
        if (priv->cwnd < usable_window) usable_window = priv->cwnd;
        if (usable_window == 0) usable_window = 1u;
    }

    uint32_t seq = conn->snd_seq;
    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_async_short, 0), tcp_conn_arg(conn, len));

    if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, buf, len) != 0) {
        return -1;
    }

    unsigned slot_idx = (priv->async_short_head + priv->async_short_count) % TCP_ASYNC_SHORT_SLOTS;
    tcp_async_short_slot_t *slot = &priv->async_short_slots[slot_idx];
    volatile_fast_copy(slot->buf, buf, len);
    slot->seq     = seq;
    slot->len     = len;
    slot->sent_at = timer_now();
    slot->rto_ms  = priv->rto_ms;
    slot->retries = 0;
    priv->async_short_count++;

    conn->snd_seq = seq + len;
    return (int)len;
}

/* tcp_send_async()(コピー版)と tcp_send_async_ref()(ゼロコピー版)の共通
 * 実装。is_ref=1 なら各チャンクのスロットに送信元ポインタを保持するだけで
 * コピーしない -- 呼び出し元が「ACK確認までbufが安定」を保証すること
 * (tcp.hのtcp_send_async_ref()コメント参照)。 */
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

    /* 2026-08-11、CMD/RSP/R2T/ICResp等のヘッダ専用PDU向け専用キューへの
     * 振り分け(上記TCP_ASYNC_SHORT_MAX_LENコメント参照) -- 呼び出し元は
     * 変更不要、この関数の内部だけで完結する。
     * 2026-08-15: ゼロコピー(is_ref)は短小キュー(async_short_slots、ref非対応)
     * を経由させず、必ず通常キュー(async_slots)へ回す -- 短小キューは
     * コピー前提だが、そもそもゼロコピーの狙いは256KB級の大きいC2HDataであり
     * TCP_ASYNC_SHORT_MAX_LEN以下の小さいrefが来ることは実運用上ない。 */
    if (!is_ref && len <= TCP_ASYNC_SHORT_MAX_LEN) {
        return tcp_send_async_short(conn, priv, buf, len);
    }

    if (len > TCP_ASYNC_MAX_LEN) {
        /* 呼び出し元の契約(TCP_ASYNC_MAX_LEN以下)を超える場合のみ、
         * tcp_send()(ブロッキング、パイプライン対応)へフォールバックする
         * -- tcp.hのtcp_send_async()コメント参照。 */
        return tcp_send(conn, buf, len);
    }

    /* 2026-08-10、LSO対応: このconnが所属するインターフェース(複数
     * ネットワークインターフェース運用時、呼ばれた時点のg_active_ctxが
     * conn自身のものとは限らない -- tcp_send_segment()冒頭と同じ理由)の
     * LSOケーパビリティを見て、mssを超えるチャンクをtcp_send_segment_
     * lso()の単発呼び出し(LSO対応)にするか、tcp_send_segment()のmss単位
     * 複数回呼び出し(LSO非対応、従来のRP1向け挙動を保つ)にするかを
     * チャンクごとに決める。 */
    netif_t *conn_ctx = netif_find_by_ip(conn->local_ip);
    uint32_t lso_cap = conn_ctx ? conn_ctx->hw_lso_max_bytes : 0u;
    if (lso_cap > TCP_ASYNC_MAX_LEN) lso_cap = TCP_ASYNC_MAX_LEN;

    uint32_t sent_total = 0;
    const uint8_t *src = (const uint8_t *)buf;

    while (sent_total < (uint32_t)len) {
        if (priv->async_count >= priv->async_cap) {
            /* キュー満杯 -- 最低1件空くまで待ってから続ける。 */
            tcp_async_flush_until_room(conn, priv);
        }

        /* 2026-08-10、実機で発見した本物のバグ: 相手の広告ウィンドウ/
         * cwndを一切見ずに送信していた(修正前)。tcp_send()のバースト
         * ループはusable_window=min(snd_win,cwnd)を計算し、outstanding
         * (未確認バイト数、conn->snd_seq-priv->snd_una)がそれを超える
         * 分は送らずACK到達を待つ設計だが、tcp_send_segment()/tcp_send_
         * segment_lso()自体にはこのチェックが無く、tcp_send_async()も
         * それを素通しで呼んでいた。24〜136バイトの小さいCQE/R2T/SQE
         * しか送らなかった間はどんなウィンドウにも収まっていたため
         * 問題化しなかったが、LSO対応で1回の送信を最大32768バイトまで
         * 拡大したところ、受信側(target)の処理が追いつかず実ウィンドウが
         * 縮小している状況でウィンドウ外のデータを送りつけてしまい、
         * 相手がTCP仕様通り黙って破棄→再送も同じ理由で永久に失敗する
         * デッドロックを実機で確認した(NVMe/TCP write pipeline、
         * `ts core 0 type NH2F/NH2L`で特定のcidから12.6秒間キューイングが
         * 完全停止することを確認、CLAUDE.md参照)。
         * 修正: tcp_send()のバーストループと全く同じusable_window計算を
         * ここでも行い、outstanding分を差し引いた「今すぐ送ってよい量」
         * (room)でチャンクをクランプする。room=0なら(ウィンドウが
         * 埋まっている)ACK到達で自然に空くまで待つ -- tcp_async_flush_
         * until_room()と同じ「通常は数十〜数百us程度で解決する軽量な
         * 待ち」という位置づけ(loopback+健全な受信側なら長時間化しない)。
         * conn->snd_seq/priv->snd_unaはtcp_send()のGo-Back-Nと共有の
         * フィールドであり、async専用送信でも正しく維持され続ける
         * (tcp_input()が送信経路によらず全ACKで無条件更新するため)。 */
        uint32_t outstanding = conn->snd_seq - priv->snd_una;
        uint32_t usable_window = conn->snd_win;
        if (priv->cwnd < usable_window) usable_window = priv->cwnd;
        if (usable_window == 0) usable_window = 1u;
        uint32_t room = (usable_window > outstanding) ? (usable_window - outstanding) : 0u;
        while (room == 0) {
            tcp_poll_once();
            if (tcp_abort_requested() ||
                (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT)) {
                return (sent_total > 0) ? (int)sent_total : -1;
            }
            outstanding = conn->snd_seq - priv->snd_una;
            usable_window = conn->snd_win;
            if (priv->cwnd < usable_window) usable_window = priv->cwnd;
            if (usable_window == 0) usable_window = 1u;
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

int tcp_send_async(tcp_conn_t *conn, const void *buf, uint16_t len)
{
    return tcp_send_async_ex(conn, buf, len, 0);
}

/* ゼロコピー版(tcp.h参照)。送信元bufをコピーせずスロットにポインタ保持する
 * (再送もそこから)。呼び出し元はこのconnで前回のtcp_send_async*()がACK
 * されるまでbufの内容を変更・解放してはならない。C2HData read(nvmet、送信元=
 * ram_diskの安定した実体)のように、送信完了までデータが不変な用途向け。 */
int tcp_send_async_ref(tcp_conn_t *conn, const void *buf, uint16_t len)
{
    return tcp_send_async_ex(conn, buf, len, 1);
}

static int tcp_recv_internal(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_val_ms, int send_ack)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_recv: 未登録のconn(tcp_connect()を呼んでいない)\n");
        return -1;
    }

    /* 呼び出し元バッファ(buf)は任意の所有者を持ちうるためvolatile経由で
     * 統一する(tcp_send_segment()のvdataと同じ理由)。 */
    volatile uint8_t *vout = buf;

    /* TCP層の性能分析用: この呼び出しがブロックしている時間そのものが
     * 上位層(nvme/nvmet)から見た待ち時間になる -- RECVとRDONのdeltaが
     * 「相手からデータが来るまでの待ち」に直結する。
     *
     * ただしtimeout_val_ms==0(ジョブ化された非ブロッキングポーリング、
     * nvmet-io/telnet/nvme等が毎tick呼ぶ経路)では、このdo-whileは必ず
     * 1周だけで終わるため「見つからなかった」場合のRECV/RDONペアは
     * delta≒0で情報量が無く、しかも毎tick×複数コネクション分発生する
     * ため`ts`の16384件リングバッファを数百ミリ秒〜数秒で使い切ってしまい、
     * IOWR/NCMD/CACK等の本当に有用なイベントを押し出してしまう
     * (2026-08-07、ユーザー指摘で発覚・対策)。「何も見つからなかった」
     * 場合のログはtimeout_val_ms!=0(本物のブロッキング呼び出し、待ち時間の
     * 計測に意味がある)の時だけ出す -- データを実際に受信できた場合
     * (n>0)やFIN受信は、非ブロッキングでも稀な有用イベントなので
     * timeout_val_msに関わらず引き続き必ず記録する(下記参照)。 */
    int log_idle_poll = (timeout_val_ms != 0);
    if (log_idle_poll) {
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 0), tcp_conn_arg(conn, maxlen));
    }

    uint64_t start = timer_now();
    /* timeout_val_ms==0の呼び出しはこのdo-whileが必ず1周だけで終わるため、
     * Ctrl+C検出(UARTから1バイト消費する)を行っても結果を左右できない
     * -- ジョブ化された受信ポーリング(nvmet-io/telnet/nvme等)がこの
     * パターンで毎tick呼ばれるため、無意味なUARTバイト消費をやめる
     * (tcp_poll_once_ex()コメント参照)。timeout_ms(start, 0)は
     * get_ms_from(start)>=0が常に真であることに基づき常に真を返すため、
     * 「必ず1周だけで終わる」性質は以下のdo-whileでも変わらず保たれる。 */
    int check_ctrl_c = (timeout_val_ms != 0);
    do {
        /* 2026-08-11、ユーザー指示によりtimeout_val_ms==0時にtcp_poll_once_ex()を
         * スキップする最適化を試したが(実機の`ts`計測でこの呼び出し自体が
         * 毎回3-4usかかることが判明したため)、実機の複数回計測で正味の
         * スループット退行(約174-176MB/s→定常約158.5MB/s)を確認し撤回した
         * -- RECV_CMD_SQE/DISPATCH_CMD等は大幅に軽くなった一方、RECV_H2C_DATA
         * (実データ受信)が615us→1286usへ倍増し、正味で悪化した。ポーリング
         * 頻度を下げたことでRXドレイン/ACK送出の機会も同時に減り、相手側の
         * 送信ペース(ACKクロッキング)を遅らせたためと考えられる -- 「無駄に
         * 見えたポーリング」の一部は実際にはこまめなACK送出という有益な
         * 副作用を担っていた。この方向性は再度試さないこと。 */
        tcp_poll_once_ex(check_ctrl_c);

        if (check_ctrl_c && tcp_abort_requested()) {
            /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照)。タイムアウト
             * と同じ-1を返す -- 呼び出し元は既にタイムアウトを「相手から
             * まだ来ていないだけ」として扱えるようになっているため、この
             * 早期リターンだけで十分伝播する(区別が必要な箇所は個別に
             * tcp_abort_requested()を確認する、nvmet_io_loop()等参照)。 */
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 1), tcp_conn_arg(conn, 0x00FFFFFEu));
            return -1;
        }

        if (priv->rx_count > 0) {
            /* nはpriv->rx_count(uint32_t、TCP_RX_BUF_SIZE=512KBに対応)を
             * 一旦保持してからmaxlen(呼び出し元API上の上限、uint16_t)で
             * クランプする -- 先にuint16_tへ代入するとrx_count>65535の
             * 場合に クランプ前に静かに切り詰められてしまう
             * (2026-07-25、Window Scaling導入時に発見・修正)。 */
            uint32_t n = priv->rx_count;
            if (n > maxlen) n = maxlen;
            /* 【2026-08-07、実機実測で発見・修正】以前はここが1バイトずつ+
             * 毎回`% TCP_RX_BUF_SIZE`(除算)を伴う素朴なループだった。
             * ユーザー指示で実測(ts_log計測)したところ、このループ自体が
             * 約8.2〜8.3MB/sという速度上限を持っており、これがNVMe/TCP
             * write性能の全体的なボトルネック(job化以降ずっと約6〜8MB/s
             * で頭打ちだった原因)そのものだったと確定した -- 送信側は既に
             * volatile_fast_copy()(ワイドアクセス最適化済み、net.h参照)を
             * 使っているのに、受信側のこの箇所だけ最適化されていなかった。
             * 循環バッファ(rx_buf、TCP_RX_BUF_SIZE)の折り返しをまたぐ
             * 場合があるため、最大2回のvolatile_fast_copy()呼び出しに
             * 分割する(折り返し無しなら1回で済む)。
             *
             * 【2026-08-11、ユーザー提案「volatileではなくmemcpyでは」を
             * 受け実機検証】非volatile版(net.hのfast_copy())へ切り替える
             * 実験を行った。vout/priv->rx_bufは共にNormal cacheable RAM
             * でありvolatile自体は不要と確認できたが、(a)単純なバイト
             * ループにすると、このプロジェクトのビルド(-O2、-O3ではない)
             * ではGCCのループ自動ベクトル化が既定で無効なため約5.5-5.7MB/s
             * へ壊滅的に悪化し、(b)volatile_fast_copy()と同じ8バイト
             * 手動ワイド化をvolatile無しで再現しても実測約193MB/s(元の
             * volatile版と同水準、有意差なし)だった。いずれの実験でも
             * volatile自体が性能上のボトルネックではなかったと判明した
             * ため、余分な複雑さ(2つ目のコピーヘルパ)を持ち込まない
             * volatile_fast_copy()のまま維持する(net.hのfast_copy()は
             * 撤去済み)。 */
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

            /* バッファに空きができたことを相手に伝える明示的なACK。
             * 送らないと、バッファがほぼ埋まってwindowが小さく/0に
             * なっていた場合、相手はこちらが次に何か送るまで送信を
             * 再開できずデッドロックしうる -- RFC793でも要求される
             * 「相手のバッファに空きができたら能動的にwindow更新を
             * 通知する」責務をここで果たす。CLOSE_WAIT中(半クローズ)
             * でも相手はこちらのACKを見ているので同様に送る。
             * send_ack=0(tcp_recv_no_ack())の場合はこれをスキップする
             * -- 呼び出し元が既知の合計長を複数回に分けて蓄積する用途
             * (nvmet_tcp.cのnvmet_tcp_recv_exact()参照)で、読み取り
             * 1回ごとに明示ACKを送るとGEM TX ring空き待ちを伴う送信が
             * セグメント到着回数だけ発生し、実機で受信(write)側だけが
             * 送信(read)側よりずっと遅くなる性能問題の原因になっていた。
             *
             * ただしsend_ack=0のまま一切ACKを送らないと、今度は逆方向の
             * 実害を生む(2026-08-07、実機で発見): job化されたnvmet_tcp.c
             * の非ブロッキング受信(nvmet_tcp_recv_poll())は全てこの
             * send_ack=0経路を通るため、消費してもウィンドウ更新が相手に
             * 一切伝わらなくなり、`ss`実測で相手が`rwnd_limited`(広告
             * ウィンドウ不足によるブロック)76.5%というほぼ常時ブロック
             * 状態に陥り、write性能が過去実測の1/10程度まで低下した。
             * 「1回の読み取りごとに毎回ACK」には戻さず、消費バイト数を
             * unacked_consumed_bytesへ累積し、閾値を超えた時だけまとめて
             * 強制ACKすることで両立させる。 */
            if (send_ack && (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT)) {
                tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            } else if (!send_ack && (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT)) {
                priv->unacked_consumed_bytes += n;
                uint32_t threshold = (uint32_t)conn->snd_mss * TCP_RECV_NOACK_ACK_THRESHOLD_MSS;
                if (threshold == 0) threshold = TCP_RECV_NOACK_ACK_THRESHOLD_MSS * 536u;
                if (priv->unacked_consumed_bytes >= threshold) {
                    /* 「見せかけの再送」仮説(2026-08-07、ユーザー指示で
                     * ts検証)の検証用タグ -- このACKが実際に発火した瞬間の
                     * 累積消費バイト数を記録する。連続するCACK同士のtick差
                     * (timer_freq=54MHz)を実時間に換算し、相手の実測RTO
                     * (`ss`のrto、通常200ms前後)より長くなっていないかを
                     * 確認するのに使う -- 長ければ、相手はこちらのACKを
                     * 待ちきれずRTOで再送してしまっている(実際のパケット
                     * ロスではない)可能性が高い。 */
                    TS_HOT(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 2), tcp_conn_arg(conn, priv->unacked_consumed_bytes));
                    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
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

int tcp_recv(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms)
{
    return tcp_recv_internal(conn, buf, maxlen, timeout_ms, 1);
}

int tcp_recv_no_ack(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms)
{
    return tcp_recv_internal(conn, buf, maxlen, timeout_ms, 0);
}

void tcp_close(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        conn->state = TCP_CLOSED;
        return;  /* 未登録(既にclose済み等) */
    }

    if (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT) {
        /* 能動close(ESTABLISHEDから): FIN_WAIT_1へ→相手のACK+FINを待つ。
         * 受動close完了(CLOSE_WAITから、相手が先にFIN済み): LAST_ACKへ
         * →自分のFINへのACKだけを待つ(相手のFINは既に受け取っている)。 */
        int active = (conn->state == TCP_ESTABLISHED);
        uart_printf("[TCP] close: FIN送信 (%s)\n", active ? "能動close" : "受動close完了");
        uint32_t fin_seq = conn->snd_seq;
        conn->state = active ? TCP_FIN_WAIT_1 : TCP_LAST_ACK;  /* tcp_send_reliable()内の
                                         * ポーリングでtcp_input()がこのstateを見て
                                         * ACK/FINを処理できるよう先に設定する */

        if (tcp_send_reliable(conn, priv, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, fin_seq + 1) == 0) {
            conn->snd_seq = fin_seq + 1;  /* FINは1バイト分のシーケンス番号を消費する */

            if (active) {
                /* 自分のFINはACKされた。まだ相手からのFINを受けていなければ
                 * (state==FIN_WAIT_2のまま)、短時間だけ追加で待つ。 */
                uint64_t start = timer_now();
                while (conn->state != TCP_TIME_WAIT && conn->state != TCP_CLOSED &&
                       !timeout_ms(start, TCP_CLOSE_FIN_WAIT_MS)) {
                    tcp_poll_once();
                }
                /* 【2026-08-08追加】相手のFINをこの待ちの間に受け取れな
                 * かった(state依然FIN_WAIT_1/2のまま) -- 相手はこの後も
                 * FINを送ってくる可能性がある(client/serverが同一
                 * プログラム内に同居する構成では、相手の送信がjob
                 * スケジューラ経由のため、この短い待ちには通常間に
                 * 合わない、上記s_timewait宣言のコメント参照)。この
                 * connを直後にs_conns[]から外して呼び出し元へ返す前に、
                 * 遅れてくるFINへACKを返せるようタイムウェイト相当の
                 * エントリを登録しておく。 */
                if (conn->state != TCP_TIME_WAIT && conn->state != TCP_CLOSED) {
                    tcp_timewait_register(conn->local_ip, conn->local_port,
                                           conn->remote_ip, conn->remote_port,
                                           conn->snd_seq);
                }
            }
            /* 受動close完了(LAST_ACK)の場合、tcp_send_reliable()の成功
             * (priv->ack_received=1)はtcp_input()のTCP_LAST_ACKハンドラが
             * 同時にstate=CLOSEDへ進めているので追加の待ちは不要。 */
        } else {
            uart_printf("[!] TCP: FIN再送上限到達、ローカルで強制クローズ\n");
        }
    }

    /* TIME_WAITの2MSL待ちは省略(本実装はNVMe/TCP検証用の最小限
     * クライアントであり、同一4-tupleでの即再接続は想定しない)。
     * ここで即座にCLOSEDへ落とし、s_conns[]登録も解除する。 */
    conn->state = TCP_CLOSED;
    {
        /* tcp_close()はconnを生成したコアと別のコアのjob stepから
         * 呼ばれうる(job.cの共有スケジューラ)ため、smp_core_index()
         * ではなくconn->owner_coreを使う(tcp.hのコメント参照) --
         * ここを誤ると、s_conns[]から実際には解除されないまま
         * connポインタだけが呼び出し元で再利用され、後で重複登録の
         * 実害(このファイル内の既存コメント「s_conns[]の中に同一の
         * connポインタが2つのインデックスで重複」参照)を招く。 */
        unsigned core = conn->owner_core;
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[core][i] == conn) {
                s_conns[core][i] = NULL;
                break;
            }
        }
    }
}

int tcp_listen(uint16_t port, netif_t *ctx)
{
    /* 共有配列(上記s_listeners宣言コメント参照) -- 返す番号は
     * s_listeners[]内の生インデックス(コアをまたいでも一意)。 */
    smp_spin_lock(&s_listener_lock);
    for (unsigned i = 0; i < TCP_LISTENER_TOTAL; i++) {
        if (!s_listeners[i].in_use) {
            s_listeners[i].in_use       = 1;
            s_listeners[i].port         = port;
            s_listeners[i].bound_ctx    = ctx;
            s_listeners[i].accept_conn  = NULL;
            s_listeners[i].accept_ready = 0;
            smp_spin_unlock(&s_listener_lock);
            return (int)i;
        }
    }
    smp_spin_unlock(&s_listener_lock);
    return -1;
}

void tcp_unlisten(int listener)
{
    smp_spin_lock(&s_listener_lock);
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (l) {
        l->in_use       = 0;
        l->accept_conn  = NULL;
        l->accept_ready = 0;
    }
    smp_spin_unlock(&s_listener_lock);
}

int tcp_window_scaling_enabled(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return priv ? priv->wscale_enabled : 0;
}

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
                priv->async_short_count, priv->async_short_head, (unsigned)TCP_ASYNC_SHORT_SLOTS);
    for (unsigned i = 0; i < priv->async_short_count; i++) {
        tcp_async_short_slot_t *s = &priv->async_short_slots[(priv->async_short_head + i) % TCP_ASYNC_SHORT_SLOTS];
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

    /* %p: uart_printf()(uart_shim.c)の実装はアドレスを32bitに切り詰めるが、
     * このシステムの静的RAMアドレスは全て4GB未満(実機のRAMマップに収まる
     * 範囲)なので実害は無い -- %llx等64bit書式はこの自作printfが
     * 対応していない(vararg読み出し幅がずれる)ため使わないこと。 */
    uart_printf("[DEBUG] rx_buf base=%p size=%u (mdコマンドでさらに広い範囲を確認可能)\n",
                (void *)priv->rx_buf, (unsigned)TCP_RX_BUF_SIZE);

    /* rx_readの32バイト前(直前に読んだ内容を含む)から192バイト分をhexdump
     * する -- 「直前に読んだバイト列」と「その直後に何が続いているか」の
     * 両方を1回のダンプで見えるようにするため。 */
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

void tcp_accept_begin(int listener, tcp_conn_t *conn)
{
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return;
    conn->state    = TCP_CLOSED;
    l->accept_conn  = conn;
    l->accept_ready = 0;
}

int tcp_accept_wait(int listener, tcp_conn_t *conn, uint32_t timeout_val_ms)
{
    (void)conn;  /* 実体はl->accept_conn(tcp_accept_begin()が設定済み)を見る */
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return -1;
    uint64_t start = timer_now();
    while (!timeout_ms(start, timeout_val_ms)) {
        tcp_poll_once();
        if (tcp_abort_requested()) {
            /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照)。タイムアウトと
             * 同じ-1を返す(呼び出し元は既に接続待ちタイムアウトとして
             * tcp_close()等の後始末を行う設計になっている)。 */
            break;
        }
        if (l->accept_ready) {
            l->accept_ready = 0;
            l->accept_conn  = NULL;
            return 0;
        }
    }
    l->accept_conn = NULL;
    return -1;
}

int tcp_accept(int listener, tcp_conn_t *conn, uint32_t timeout_val_ms)
{
    tcp_accept_begin(listener, conn);
    return tcp_accept_wait(listener, conn, timeout_val_ms);
}

int tcp_accept_ready_poll(int listener)
{
    /* check_ctrl_c=0: tcp_recv_internal()のtimeout_ms==0の場合と同じ理由
     * (tcp_poll_once_ex()コメント参照)。この関数自体は1回呼ばれるごとに
     * 1回チェックして即返るだけ(内部でループしない)なので、UARTから
     * バイトを消費してもこの呼び出し自身の挙動を左右できない。加えて
     * このプロジェクトはジョブ化(job.h)によりメインループが1回の
     * コマンド処理で止まらなくなったため、Ctrl+Cはshell_line_poll()
     * (command.c)自身が毎メインループ反復で確実に検出しtcp_request_
     * abort()を呼ぶ経路が既にある -- ここでの検出は、旧来の「dispatch()
     * が1コマンドの間ずっとブロックし続ける」設計だった頃の名残で、
     * 今は呼び出し元(nvmet_admin_job_step()等)が独自にtcp_abort_
     * requested()を確認する分と完全に重複している。 */
    tcp_poll_once_ex(0);
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return 0;
    if (tcp_abort_requested()) {
        /* tcp_accept_wait()と同じくCtrl+Cをタイムアウト相当として扱う --
         * 呼び出し側(nvmet.cのジョブ)はabort自体を別途確認して終了する
         * 設計のため、ここでは単に「まだ確立していない」を返すだけで
         * 十分(tcp_accept_wait()のようにaccept_connへは触れない --
         * 呼び出し側がabortを検知して自分でtcp_close()等の後始末をする)。
         * このabort検出自体は他の経路(shell_line_poll()の直接検出、
         * 真にブロックする待ち経由のtcp_poll_once())で立ったフラグを
         * 見るだけなので、上でUART消費を止めても意味は変わらない。 */
        return 0;
    }
    if (l->accept_ready) {
        l->accept_ready = 0;
        l->accept_conn  = NULL;
        return 1;
    }
    return 0;
}

void tcp_input(const uint8_t *pkt, uint16_t len, uint32_t src_ip)
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

    /* 受動open(tcp_listen()/tcp_accept())向けのSYN受け付け。既存の
     * アクティブコネクション照合ループより前に置く必要がある(こちらは
     * まだs_conns[]に登録されていない新規接続なので、後段の照合ループでは
     * 一切ヒットしない)。accept_conn->state==TCP_CLOSEDの確認は、
     * 既にSYN_RCVD/ESTABLISHEDへ進んだ後の相手の再送SYNを誤って新規接続
     * として扱わないための防御(tcp.h/nvmet_impl.mdのコメント参照)。
     *
     * 複数リスナー対応(CLAUDE.md「nvmet: 複数インターフェース同時待受」
     * 節参照): port一致に加え、bound_ctx!=NULLのリスナーはg_active_ctx
     * (net_poll_all_and_dispatch()が、このSYNを実際に受信したインター
     * フェースをactivateした上でtcp_input()を呼んでいる)とも一致する
     * ものだけを選ぶ -- 同じport番号で複数のインターフェースへそれぞれ
     * bindされたリスナーが同時に存在しうるため、port一致だけでは
     * 誤ったリスナー(≒誤ったnvmetインスタンス)にSYNを渡してしまう。 */
    int matched_listener = -1;
    if (in[TCP_OFF_FLAGS] & TCP_FLAG_SYN) {
        for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
            tcp_listener_slot_t *l = &s_listeners[li];
            if (l->in_use &&
                l->port == dst_port &&
                (l->bound_ctx == NULL || l->bound_ctx == g_active_ctx) &&
                l->accept_conn != NULL &&
                l->accept_conn->state == TCP_CLOSED) {
                matched_listener = (int)li;
                break;
            }
        }
    }
    if (matched_listener >= 0) {
        tcp_listener_slot_t *l = &s_listeners[matched_listener];
        int slot = tcp_find_free_slot();
        if (slot < 0) {
            /* 能動open(tcp_connect())側は空きスロット無しを
             * ログするが、この受動open経路は元々何も出さず黙って
             * SYNを捨てていた -- ホストの2本目の接続(NVMe/TCPの
             * IOキュー等)だけが無応答でタイムアウトし、Pi側のログには
             * 一切手がかりが残らない事象の原因になり得るため、
             * 同じ形式でログを追加する。 */
            uart_printf("[!] TCP: 空きコネクションスロットが無く受動openのSYNを破棄 "
                        "(local_port=%u, 最大%u本)\n", dst_port, TCP_MAX_CONNS);
        }
        if (slot >= 0) {
            tcp_conn_t *aconn = l->accept_conn;
            tcp_priv_t *apriv = &s_priv[core][slot];
            tcp_priv_init(apriv, core);

            uint32_t seg_seq  = rd32be(in + TCP_OFF_SEQ);
            uint8_t  hdr_len2 = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);

            aconn->local_ip    = NET_SELF_IP;
            /* local_ipが確定したので、mlx5オーバーフロー割り当てを試みる
             * (tcp_priv_try_grant_mlx5_async_overflow()コメント参照 --
             * 能動open[tcp_connect_begin()]と違い、こちらはtcp_priv_init()
             * より後でしかlocal_ipが分からないため呼び出し順が異なる)。 */
            tcp_priv_try_grant_mlx5_async_overflow(apriv, core, aconn->local_ip);
            aconn->remote_ip   = src_ip;
            aconn->remote_port = src_port;
            aconn->local_port  = dst_port;
            aconn->state       = TCP_SYN_RCVD;
            aconn->snd_seq     = (uint32_t)timer_now();  /* ISN(tcp_connect()と同じ採り方) */

            /* owner_coreはここでのcore(=このSYNをdispatchしたNIC所有コア、
             * net_poll_all_and_dispatch()経由で常に固定)を記録する
             * (tcp.hのtcp_conn_t.owner_coreコメント参照)。 */
            aconn->owner_core = core;
            s_conns[core][slot] = aconn;

            aconn->rcv_seq = seg_seq + 1;  /* SYN消費分 */
            aconn->snd_mss = TCP_MSS_DEFAULT_RFC879;
            if (hdr_len2 > TCP_HDR_LEN && hdr_len2 <= len) {
                tcp_parse_syn_options(aconn, apriv, in + TCP_HDR_LEN, (uint8_t)(hdr_len2 - TCP_HDR_LEN));
            }
            /* SYN自身のwindowフィールドはWindow Scaling成立の有無に関わらず
             * 常に生値(RFC7323、上記tcp_send_segment()の同種コメント参照)。 */
            aconn->snd_win = rd16be(in + TCP_OFF_WINDOW);

            uart_printf("[TCP] accept: SYN受信、SYN|ACK送信 (local_port=%u, slot=%d)\n",
                        dst_port, slot);

            tcp_send_segment(aconn, apriv, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);

            aconn->snd_seq++;  /* SYNは1バイト分のシーケンス番号を消費する */
            apriv->expected_ack = aconn->snd_seq;
            apriv->ack_received = 0;
            return;
        }
    }

    /* アクティブな全コネクションを走査し、4-tuple(src_ip/src_port/dst_port、
     * local_ipは常にNET_SELF_IPなので照合不要)が一致するものを探す。 */
    tcp_conn_t *conn = NULL;
    tcp_priv_t *priv = NULL;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] != NULL &&
            src_ip == s_conns[core][i]->remote_ip &&
            src_port == s_conns[core][i]->remote_port &&
            dst_port == s_conns[core][i]->local_port) {
            conn = s_conns[core][i];
            priv = &s_priv[core][i];
            break;
        }
    }
    if (!conn) {
        /* どのアクティブコネクション宛でもない -- ただし、こちらが能動
         * closeでs_conns[]からは既に登録解除済みだが、相手の遅れてきた
         * FIN(こちらの待ちタイムアウトに間に合わなかったもの)かもしれ
         * ない。tcp_close()がs_timewait[]へ登録しているはずなので確認し、
         * 一致すればs_conns[]/tcp_priv_t無しで送れるバレアACKで応答する
         * (tcp_close()コメント、上記s_timewait宣言のコメント参照)。 */
        if (in[TCP_OFF_FLAGS] & TCP_FLAG_FIN) {
            tcp_timewait_t *tw = tcp_timewait_find(src_ip, src_port, dst_port);
            if (tw) {
                uint8_t fin_hdr_len = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);
                if (fin_hdr_len >= TCP_HDR_LEN && fin_hdr_len <= len) {
                    uint32_t fin_seq = rd32be(in + TCP_OFF_SEQ);
                    uint16_t fin_payload_len = (uint16_t)(len - fin_hdr_len);
                    tcp_send_bare_ack(tw->local_ip, tw->local_port, tw->remote_ip, tw->remote_port,
                                       tw->local_seq, fin_seq + fin_payload_len + 1u);
                }
            }
        }
        return;  /* どのアクティブコネクション宛でもない */
    }

    /* チェックサム検証: 受信した生のセグメント(チェックサムフィールドも
     * 含めた全体)をそのまま渡し、結果が0であれば正常
     * (net.hのpseudo_header_checksum()コメント参照)。不正なら即破棄する
     * -- 再送は無効なACKに反応してはならないため、ここで弾いておかないと
     * 破損データをtcp_recv()に渡してしまう恐れがある。 */
    /* RX段階別コスト計測(2026-08-09、mlx5_net_poll_recv()側のMRXF/
     * MRXD計装と対になる -- MRXD(NIC受信処理完了)からここまでの間には
     * eth_dispatch()のプロトコル判定・ip_input()のIPヘッダチェックサム
     * 検証(20バイトのみ、軽い)・ここまでのコネクション照合ループが
     * 挟まる。TCKB→TCKEのdeltaがTCPチェックサム計算(ヘッダ+ペイロード
     * 全体、pseudo_header_checksum())自体のコストを表す。
     * 2026-08-09、ハードウェアチェックサムオフロード対応: HW検証済み
     * (eth_rx_hw_csum_ok())なら、この最も重いソフトウェアチェックサム
     * 計算(実測でTX/RX合計1サイクルの30-40%を占める最大コスト、
     * CLAUDE.md「性能分析基盤の整備」節参照)を丸ごと省略する。
     * TCKB/TCKEのdeltaはこの場合0(または呼ばれない)になる -- 計測上、
     * HWオフロード有効時のコスト消失を直接確認できる。 */
    int hw_ok = eth_rx_hw_csum_ok();
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 0), tcp_conn_arg(conn, len));
    if (!hw_ok) {
        uint8_t src_ip_octets[4];
        uint8_t dst_ip_octets[4];
        ip_to_octets(src_ip, src_ip_octets);
        ip_to_octets(conn->local_ip, dst_ip_octets);
        uint16_t csum_check = pseudo_header_checksum(src_ip_octets, dst_ip_octets,
                                                      IP_PROTO_TCP, pkt, len);
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
    /* 旧版はここにpayload_len > TCP_RX_BUF_SIZEの安全クリップがあったが、
     * TCP_RX_BUF_SIZEが512KBへ拡張されuint16_tの上限(65535)を常に上回る
     * ようになったため、この比較は恒久的に偽になり-Wtype-limitsで
     * 警告される(2026-07-25、Window Scaling導入時に削除)。 */

    if (flags & TCP_FLAG_RST) {
        uart_printf("[TCP] RST受信、コネクションを閉じる\n");
        conn->state = TCP_CLOSED;
        /* tcp_close()と同様にs_conns[]からも登録解除する -- これが無いと
         * (当初の実装)、同じconnポインタ(例えばnvmet_ctx_tのように
         * staticに使い回されるtcp_conn_t)がRSTで閉じられた後に再度
         * tcp_accept()/tcp_connect()され、新しいスロットへ登録された
         * 際、s_conns[]の中に同一のconnポインタが2つのインデックスで
         * 重複して存在してしまう。tcp_input()の照合ループは配列の
         * 先頭から線形一致するため、新しい接続向けのパケットが古い
         * (無関係な)スロットのpriv(expected_ack等が別物)にディスパッチ
         * されてしまい、実機のnvmet再試行検証でESTABLISHEDへ一切遷移
         * できない(3-way handshake完了後もICReqへの応答が無い)事象と
         * して発現した。 */
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[core][i] == conn) {
                s_conns[core][i] = NULL;
                break;
            }
        }
        return;
    }

    /* 相手の広告ウィンドウ(SND.WND)はACKの有無・データの有無に関わらず
     * 全てのセグメントで更新する(RFC793: windowフィールドは常に現在の
     * 受信可能量を示す)。tcp_send()の分割サイズ計算がこれを参照する。
     *
     * Window Scaling(RFC7323): priv->wscale_enabledが立っていれば、相手が
     * 広告してきた16bit値をpriv->snd_wscale(相手のSYN/SYN-ACKから読み
     * 取ったシフト量)だけ左シフトして実際のバイト数に復元する。この行は
     * SYN-ACK自身の処理でも実行されるが、その時点ではまだ下記switch文の
     * TCP_SYN_SENTケースでtcp_parse_syn_options()が呼ばれておらず
     * priv->wscale_enabledが未確定(0)のままなので、結果的にSYN-ACK自身の
     * windowは常に生値として読まれる(RFC7323の「SYN自身のwindowは
     * スケーリングしない」という規則を、この関数内の実行順序だけで
     * 自然に満たしている -- 受動open側のtcp_input()のSYN受け付け
     * ブロックがaconn->snd_winを別途生値のまま設定しているのと対になる)。 */
    if (priv->wscale_enabled) {
        conn->snd_win = (uint32_t)rd16be(in + TCP_OFF_WINDOW) << priv->snd_wscale;
    } else {
        conn->snd_win = rd16be(in + TCP_OFF_WINDOW);
    }

    switch (conn->state) {
    case TCP_SYN_RCVD:
        /* tcp_accept()側(受動open)。相手のACK(こちらのSYN|ACKへの応答)を
         * 待っている。expected_ack(SYN|ACK送信直後にconn->snd_seq、すなわち
         * ISN+1へ設定済み)との厳密一致で判定する(TCP_SYN_SENTケースと
         * 同じ判定方式)。
         *
         * 当初はtcp_seq_gt(ack, priv->snd_una)(priv->snd_unaはtcp_priv_init()
         * が0に初期化したまま)で判定していたが、実機のnvmet接続検証
         * (Wiresharkキャプチャ)で3-way handshakeは完了するのにICReqへの
         * 応答が一切無く、クライアントが10秒間再送を繰り返した末にRSTで
         * 切断される事象を確認した。原因: ISNをtimer_now()から採るため、
         * 生のACK値(ISN+1)のbit31がたまたま立っていると、符号付き差分
         * 比較(tcp_seq_gt)ではこれが0より「前」と解釈され
         * (int32_t)(ack-0)>0が成立しない -- 固定の0という基準そのものが
         * 誤りだった(累積ACK追跡用のsnd_unaは値が0から始まる前提の変数
         * ではなく、ここでは単に「こちらのSYNへの確認」という一点物の
         * 判定にすぎないため、TCP_SYN_SENTと同様expected_ackとの厳密一致
         * にすべきだった)。 */
        if ((flags & TCP_FLAG_ACK) && ack == priv->expected_ack) {
            priv->snd_una = ack;
            conn->state = TCP_ESTABLISHED;
            /* 輻輳制御の初期化(共通ヘルパ、tcp_cwnd_init()コメント参照) --
             * tcp_connect()側と同様、受動openでもESTABLISHEDへ遷移する
             * この時点でIWを設定しないと、cwnd=0(tcp_priv_init()の初期値)
             * のままpersist相当の1バイトずつ送信に落ち込んでしまう。 */
            tcp_cwnd_init(conn, priv);
            /* このconnを armしたリスナーを探して ready を立てる(複数
             * リスナー対応、CLAUDE.md「nvmet: 複数インターフェース同時
             * 待受」節参照) -- l->accept_connはtcp_accept_begin()で
             * このconnへ設定されたまま、tcp_accept_wait()/
             * tcp_accept_ready_poll()が消費するまで保持され続ける。 */
            for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
                if (s_listeners[li].in_use && s_listeners[li].accept_conn == conn) {
                    s_listeners[li].accept_ready = 1;
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
            /* conn->snd_seqはこの時点ではまだisn(SYN自身のseq)のまま --
             * tcp_connect()側の「SYNはseq1バイト消費する」インクリメントは
             * tcp_send_reliable()が返った後に行われるため、このtcp_input()
             * 経由の即時ACK送信より後になる。ここで先にack(==isn+1、上の
             * expected_ack一致チェック済み)へ進めておかないと、下記の
             * 最終ACKが古いseq(isn)のまま送出されてしまう(実機のnvmet-tcp
             * 相互接続検証でWiresharkが古いseqのACKを検出し、後続の
             * ICReqが実際に届いてACKされているのにICRespが一切返らない
             * 事象の調査で発見)。 */
            conn->snd_seq = ack;
            /* ハンドシェイク完了の最終ACKは単発送信(このACK自体は
             * 再送しない -- 万一失われても、相手が保持するデータ送信が
             * 始まればそちらのACK/再送で事実上補われる。相手がSYN-ACKを
             * 再送してくる稀なケースへの厳密な追従は次段階の課題)。 */
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
            }
            /* TCP層の性能分析用: 受信ACKセグメント(TCPのwindowフィールドは
             * ACK/データの有無に関わらず全セグメントに乗る、上記
             * conn->snd_win更新のコメント参照)なので、ACK進行とwindow
             * 変動を1エントリで両方追える -- 別途Window Update専用の
             * タグは設けない(TCPには独立したWindow Update PDUは無く、
             * 実際には全てACKセグメントの一部として運ばれるため)。 */
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log_tcp_ack(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 3), (uint8_t)tcp_conn_slot(conn),
                           seq, ack, conn->snd_win, flags);
        }
        if (flags & TCP_FLAG_FIN) {
            uint32_t free_space = TCP_RX_BUF_SIZE - priv->rx_count;
            if (payload_len > 0 && (priv->recv_upcall || payload_len <= free_space)) {
                tcp_deliver_data(priv, payload, payload_len);
            }
            conn->rcv_seq = seq + payload_len + 1;
            /* 受動close: ここでは相手のFINにACKを返すのみで、自分の
             * FINは送らずCLOSE_WAITへ遷移する(RFC793準拠)。旧実装は
             * FIN|ACKを即座に返してCLOSEDへ落としていたが、それだと
             * 相手のFIN受信後にこちらから送信中のデータがあっても
             * 続けられない(半クローズができない)。tcp_send()は
             * ESTABLISHEDのみを前提にしているわけではなく、呼び出し側が
             * 送信を終えてtcp_close()を呼べばそこでLAST_ACKへ進み、
             * 正しく2段階でCLOSEDに至る。 */
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_CLOSE_WAIT;
            priv->fin_received = 1;
            /* TCP層の性能分析用: 相手のFIN受信(argはこのセグメントに
             * 便乗していたペイロード長)。 */
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 4), tcp_conn_arg(conn, payload_len));
            uart_printf("[TCP] FIN受信、ACK返送してCLOSE_WAITへ遷移\n");
        } else if (payload_len > 0) {
            uint32_t free_space = TCP_RX_BUF_SIZE - priv->rx_count;
            int accepted_inorder = 0;
            if (seq == conn->rcv_seq && (priv->recv_upcall || payload_len <= free_space)) {
                accepted_inorder = 1;
                tcp_deliver_data(priv, payload, payload_len);
                conn->rcv_seq += payload_len;
                /* TCP層の性能分析用: 順序通り届いたデータの到着間隔
                 * (argはpayload_len)。相手の送信ペース(SSEG)と突き合わせれば
                 * ネットワーク上でどれだけ遅延/間引かれているか分析できる。 */
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 5), tcp_conn_arg(conn, payload_len));

                /* 先読みバッファの中に、今取り込んだ分でrcv_seqが
                 * ちょうど追いついたセグメントが無いか繰り返し確認し、
                 * あれば連鎖的に繋げる(循環バッファ化により、
                 * tcp_recv()の取り出しを待たずその場で繋げられる)。
                 * 1つ繋げるとrcv_seq/free_spaceが変わり別のスロットが
                 * 新たに一致することがあるため、一致するものが無くなる
                 * まで最初から探し直す。 */
                for (;;) {
                    int spliced = 0;
                    free_space = TCP_RX_BUF_SIZE - priv->rx_count;
                    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
                        if (priv->ooo[i].valid && priv->ooo[i].seq == conn->rcv_seq &&
                            (priv->recv_upcall || priv->ooo[i].len <= free_space)) {
                            tcp_deliver_data(priv, priv->ooo[i].buf, priv->ooo[i].len);
                            conn->rcv_seq += priv->ooo[i].len;
                            priv->ooo[i].valid = 0;
                            spliced = 1;
                            break;
                        }
                    }
                    if (!spliced) break;
                }
            } else if (seq == conn->rcv_seq) {
                /* 計装専用(一時追加、原因特定後に削除すること) -- 順序は
                 * 正しい(seq==rcv_seq)のに受信バッファの空きが足りず
                 * 無言で破棄していた既存の分岐(以前はログが一切無く、
                 * TCP層でセグメントが消えているのかアプリ層の問題かを
                 * 直接切り分けられなかった)。ここに来た場合、rcv_seqは
                 * 進めないため相手は必ず再送してくる(下記dup ACK参照)
                 * -- 恒久的なデータ損失にはならないはずだが、実際に
                 * この分岐を通っているかどうか自体が未確認だったため
                 * 可視化する。 */
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 6), tcp_conn_arg(conn, payload_len));
            } else if (tcp_seq_gt(seq, conn->rcv_seq) && payload_len <= TCP_MSS_LOCAL) {
                /* 順序が入れ替わって届いた(まだギャップがある)セグメント
                 * -- 空いているスロットに保持しておく(最大TCP_OOO_SLOTS
                 * 件まで同時に保持できる、tcp_priv_t.oooコメント参照)。
                 * ギャップを埋めるはずのセグメント(通常は相手の再送)が
                 * 届いたら上の分岐で自動的に繋がる。同じseqを既に保持
                 * 済みなら(相手の重複再送)何もしない。全スロット使用中
                 * なら諦める(相手はいずれ再送してくる)。 */
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
                            /* TCP層の性能分析用: 順序入れ替わり発生
                             * (argはpayload_len)。多発していれば、それが
                             * 再送待ち/OOO繋ぎ込みコストの形でwrite性能を
                             * 引き下げている実際の要因になりうる。 */
                            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 7), tcp_conn_arg(conn, payload_len));
                            uart_printf("[TCP] 順序不正セグメントを先読みバッファに保持 "
                                        "(seq=%u rcv_seq=%u len=%u slot=%u)\n",
                                        seq, conn->rcv_seq, payload_len, i);
                            stored = 1;
                            break;
                        }
                    }
                    if (!stored) {
                        /* 全スロット使用中 -- このセグメントは破棄する
                         * (相手はいずれ再送してくる)。2026-07-25追加:
                         * 以前はここが無言で、TCP_OOO_SLOTSが実際の
                         * 入れ替わり幅に対して不足しているケースに実機で
                         * 気付けなかった(「順序不正セグメントを先読み
                         * バッファに保持」が毎回ちょうどTCP_OOO_SLOTS件で
                         * 頭打ちになっていたのが後から判明した唯一の
                         * 手がかりだった)。このログが多発するようなら
                         * TCP_OOO_SLOTSを見直すこと。 */
                        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 8), tcp_conn_arg(conn, payload_len));
                        uart_printf("[!] TCP: 順序不正セグメントを破棄(先読みバッファ満杯 "
                                    "TCP_OOO_SLOTS=%u) (seq=%u rcv_seq=%u len=%u)\n",
                                    TCP_OOO_SLOTS, seq, conn->rcv_seq, payload_len);
                    }
                }
            } else if (tcp_seq_gt(seq, conn->rcv_seq)) {
                /* 計装専用(一時追加、原因特定後に削除すること) -- 順序
                 * 不正だがpayload_len>TCP_MSS_LOCALでOOOスロットに収まらず
                 * 無言で破棄していた既存の分岐(以前はログ無し)。LSOに
                 * よる大きいペイロードのセグメントがこの条件に該当し
                 * うるため、原因調査のため可視化する。 */
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 9), tcp_conn_arg(conn, payload_len));
            }
            /* 順序不正、またはバッファ空き不足でも現在のrcv_seqでdup ACK
             * を返す(相手の再送トリガになる。この時点のrx_countが
             * tcp_send_segment()内でwindowフィールドに反映される)。
             *
             * 【2026-08-07、実機のWiresharkキャプチャで発見・修正】
             * 過去のセッションで「遅延ACK(フルサイズセグメント2個に1回
             * だけACKする、RFC5681ライク、`unacked_full_segments`
             * カウンタ)がホスト側Nagleアルゴリズムと悪い相互作用を
             * 起こしているのでは」という仮説を検証するため、診断目的で
             * 毎セグメント即時ACKへ一時的に戻す実験がされていたが、
             * その後この行が元に戻されないまま放置されていた
             * (`unacked_full_segments`は宣言・初期化されたまま一度も
             * 参照されない、実質デッドコード化していた)。
             *
             * 実機のWiresharkキャプチャ(bs=256k write、iodepth=8)で
             * write用IO queueのトラフィックを解析したところ、8.47秒間で
             * ボードから48,417件ものゼロ長ACKが送出されており(データ
             * パケット9,812件の約5倍)、これが送信側のペーシングを乱し
             * write性能を実測の1/10程度まで低下させていた実際の原因
             * だったと判明した。
             *
             * 遅延ACKロジック自体を復元するが、「フルサイズ」の判定基準を
             * `TCP_MSS_LOCAL`(自分のジャンボ対応上限、10182)から
             * `conn->snd_mss`(このコネクションで実際に合意したMSS)へ
             * 変更する点が重要な修正——`TCP_MSS_LOCAL`のままでは、
             * 非ジャンボ接続(相手のMSSが1460等)で相手が送ってくる
             * セグメントが決して10182に到達しないため、たとえロジックを
             * 復元しても常に「フルサイズ未満」と誤判定され続け、実質的に
             * 毎セグメント即時ACKのままになってしまう(=今回の問題が
             * 形を変えて再発する)。 */
            /* 遅延ACK(2026-08-13復元、CLAUDE.md「core0が1フレーム1ACKで
             * writeを律速」節): フルサイズのin-orderセグメントは2個に1回
             * だけACKする。ACK送信(tcp_send_segment→eth_tx_wait_free_slot→
             * mlx5 SQ TX完了ペーシング ~18us)がフレームごとに走ると、
             * eth_dispatchが実測~20us/frameになり受信を~26us/frame≒331MB/sへ
             * ペーシングしてwriteを律速していた(read=400MB/s[PCIe天井]との
             * 差の主因)。push型ではrx_count=0で広告ウィンドウは常に最大の
             * ため、以前pull経路で観測された「window full」問題は起きない。
             * 順序不正/バッファ空き不足/フルサイズ未満(コマンド末尾等)は
             * 即座にACK(dup ACKで再送を促す/末尾を確定させる)。 */
            if (accepted_inorder && payload_len == conn->snd_mss) {
                priv->unacked_full_segments++;
                if (priv->unacked_full_segments >= g_tcp_ack_threshold) {
                    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
                    priv->unacked_full_segments = 0;
                }
            } else {
                tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
                priv->unacked_full_segments = 0;
            }
        }
        break;

    case TCP_CLOSE_WAIT:
        /* CLOSE_WAIT中もtcp_send()で送信を続けられる(半クローズ)ため、
         * ESTABLISHEDと同様にACK進捗を検知する必要がある -- これが無いと
         * tcp_send()は相手が正しくACKしていても検知できず、必ず再送上限
         * まで失敗する。 */
        if (flags & TCP_FLAG_ACK) {
            if (ack == priv->expected_ack) {
                priv->ack_received = 1;
            }
            if (tcp_seq_gt(ack, priv->snd_una)) {
                priv->snd_una = ack;
                priv->ack_advanced = 1;
            }
        }
        /* 相手は既に送信方向をFIN済みなので新しいデータは来ないはずだが、
         * こちらのACKが失われて相手がFINを再送してくることがあるので、
         * 同じrcv_seqでACKを返し続ける(何もstateは変えない)。 */
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
