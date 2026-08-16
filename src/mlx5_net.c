// mlx5_net.c
//
// ConnectX(mlx5) PF0/PF1を、既存のTCP/IPスタック(arp.c/ip.c/icmp.c、
// netif.hのnic_ops_t)向けの継続動作可能なNICバックエンドとして使うための
// 送受信実装。mlx5.cが用意するRQ/SQ/CQ(mlx5_hca_bringup())をそのまま使う
// が、診断用の一発テスト(mlx5.cのmlx5_sq_send_test_frame()/
// mlx5_cq_poll_any())と違い、継続的な送受信に必要な2点を新たに実装する:
//
// 1. CQEのowner-bit周回トグルに基づく正しいポーリング。mlx5_cq_poll_any()
//    は「CQE[0]のop_ownが初期値(INVALID)から変化したか」だけを見る
//    一回きりの判定だったが、これは最初の1件にしか通用しない
//    (CLAUDE.md「CQポーリングによるライブ確認を実装」節の設計判断
//    参照)。継続動作にはLinux mlx5_core(`drivers/net/ethernet/
//    mellanox/mlx5/core/wq.h`のmlx5_cqwq_get_cqe())と同じ、consumer
//    counter(折り返さず単調増加)の巻き戻り回数の偶奇でowner bitの
//    期待値を決める方式が必要。
// 2. RQドアベルの再武装。mlx5_create_rq()は作成時に256個のWQE全てを
//    一括でHWへ「投稿」するが(CLAUDE.md「モニタ機能でCQ/RQ無応答の
//    原因を特定」節参照)、256回受信した後もHWに受信を継続させるには、
//    処理済みの完了1件ごとにドアベルの「投稿済みWQE数」カウンタを
//    1つ進めて再度書き込む必要がある(WQE自体の中身は固定バッファを
//    指すだけなので書き直し不要、カウンタの再送信だけでよい)。
//
// 送信: 当初は同期実装(完了を待ってから返る)のみだったが、2026-08-09
// 「性能分析基盤の整備」節の実機計測で、ConnectXループバックのwrite性能が
// 25Gbpsリンクでも約35MB/sで頭打ちになる原因が、この同期実装(1セグメント
// ごとにハードウェア送信完了を待つストップ&ウェイト)だと判明したため、
// RP1のeth.c(eth_send_frags_async()/eth_tx_wait_free_slot()、TXリングの
// パイプライン化、CLAUDE.md「TCP/IPスタックの性能チューニング」節5.参照)
// と同じ設計で真の非同期送信を実装した:
// - mlx5_net_send_frags_async(): WQEをポストしたら、ハードウェアの送信
//   完了(CQE)を待たずに即座に返る。SQリング(MLX5_SQ_WQE_COUNT=16スロット)
//   に空きが無い場合のみ、空きが出るまで待つ(バックプレッシャ)。
// - mlx5_net_send_frags(): 上記に加え、投稿した自分のWQEの完了(CQE)まで
//   明示的に待つ(ARP/ICMP等、完了確認が必要な呼び出し元向け)。
// - WQEスロットごとに独立したステージバッファ(mlx5.hのMLX5_NET_TX_STAGE_
//   ADDR(base,slot)参照)を使うことで、複数WQEが未完了のまま連続して
//   ポストされても互いのデータを上書きしない。

#include "mlx5.h"
#include "netif.h"
#include "net.h"
#include "net_buf.h"
#include "uart.h"
#include "timer.h"
#include "mmio.h"
#include "cache.h"
#include "timestamp.h"
#include "smp.h"
#include <stddef.h>

// 2026-08-09、ゼロコピー化に伴うmlx5_net_tx_wait_free_slot()の前提条件:
// この関数が返す値(0..MLX5_SQ_WQE_COUNT-1、mlx5.h参照)は、tcp.cの
// s_seg_bufs[core][ETH_TX_RING_SIZE]をそのままインデックスするため、
// 常に有効な範囲でなければならない。
_Static_assert(MLX5_SQ_WQE_COUNT <= ETH_TX_RING_SIZE,
               "mlx5_net_tx_wait_free_slot() returns pc % MLX5_SQ_WQE_COUNT as an index into "
               "tcp.c's s_seg_bufs[core][ETH_TX_RING_SIZE] -- MLX5_SQ_WQE_COUNT must not exceed it");

// CQE(struct mlx5_cqe64、Linux mlx5_core device.h)関連の定数・バイト
// オフセット。累積ビットオフセットからの手計算(このプロジェクトの
// 他コマンドと同じ方法論、mlx5.cのCREATE_EQ/CREATE_RQ等のコメント参照):
// byte_cnt=44(32bit BE)、wqe_counter=60(16bit BE)、op_own=63。
#define MLX5_NET_CQE_SIZE         64u
// 2026-08-11、mlx5.cのMLX5_CQ_LOG_SIZE_VAL/MLX5_CQ_NUM_ENTRIES拡張
// (64→1024エントリ、board.hのMLX5_CQ_CACHE_PF_SIZEコメント参照)に合わせる。
#define MLX5_NET_CQ_NUM_ENTRIES   1024u // mlx5_create_cq()のlog_cq_size=10(2^10)と対応
#define MLX5_NET_CQ_LOG_SIZE      10u
#define MLX5_CQE_OWNER_MASK       0x1u
#define MLX5_CQE_OP_INVALID       0xFu
#define MLX5_CQE_OFF_BYTE_CNT     44u
#define MLX5_CQE_OFF_WQE_COUNTER  60u
#define MLX5_CQE_OFF_OP_OWN       63u
// 2026-08-09、MTXC/MRXF待ち切り分け「方針1」(CLAUDE.md「MTXC/MRXF待ち
// 改善の検討方針」節参照)。struct mlx5_cqe64のtimestamp_h/timestamp_l
// (Linux device.hのget_cqe_ts()で確認、byte48-51/52-55)-- device_
// frequency_khz(mlx5_dev_t.clock_khz、mlx5.c参照)で刻むフリーランニング
// カウンタ。同一ConnectXシリコン上のPF0のSQ完了とPF1のRQ到着は同じ
// クロックドメインを共有するため、ここから求めたHW-domain deltaは
// ソフトウェアのポーリング粒度に一切影響されない「実際にワイヤ上で
// 起きた時間」を表す(はず、実機で妥当な値か要検証)。
#define MLX5_CQE_OFF_TIMESTAMP_H  48u
#define MLX5_CQE_OFF_TIMESTAMP_L  52u
// 2026-08-09、ハードウェアチェックサムオフロード対応。struct
// mlx5_cqe64(Linux include/linux/mlx5/device.h、実際に取得して確認
// 済み)のhds_ip_extはoffset28(byte28)。bit0=CQE_L2_OK、bit1=CQE_L3_OK
// (IPヘッダ検証OK)、bit2=CQE_L4_OK(TCP/UDP検証OK) --
// drivers/net/ethernet/mellanox/mlx5/core/en_rx.cのmlx5e_handle_csum()
// の`CHECKSUM_UNNECESSARY`分岐(`cqe->hds_ip_ext & CQE_L3_OK &&
// cqe->hds_ip_ext & CQE_L4_OK`)と同じ判定を踏襲する。
#define MLX5_CQE_OFF_HDS_IP_EXT   28u
#define MLX5_CQE_L3_OK            0x02u
#define MLX5_CQE_L4_OK            0x04u

/* CQE opcode(op_own上位nibble)の意味(2026-08-08、ユーザー指示のcore分離
 * 調査で追加、実機実測opcode=0xd=13の正体を特定するためlinux-rdma/
 * rdma-coreのproviders/mlx5/mlx5dv.hを実際に取得して確認した値、推測
 * ではない)。MLX5_CQE_REQ(0)=正常な送信完了、MLX5_CQE_REQ_ERR(13)/
 * MLX5_CQE_SIG_ERR(12)=エラー完了。mlx5_net_cqe_if_ready()はowner bit
 * 一致+opcode!=INVALID(0xF)だけを見て「到着済み」と判定しており、
 * REQ_ERR/SIG_ERRを正常完了と区別せず見過ごしていた -- 実際に実機で
 * PF0のSQ's CQ(cqn=17)のCQ[30]にopcode=0xd(REQ_ERR)のCQEが記録されて
 * いるのを確認した(mlx5netdumpコマンド)。エラーCQEは通常のCQEとは
 * レイアウトが異なる(struct mlx5_err_cqe、同じくrdma-coreのソースから
 * 確認): vendor_err_syndはbyte54、syndromeはbyte55、s_wqe_opcode_qpnは
 * byte56-59、wqe_counterはbyte60-61(通常CQEと同じ位置)。syndrome値の
 * 一覧もmlx5dv.hのMLX5_CQE_SYNDROME_*から取得済み(下記コメント参照)。 */
#define MLX5_CQE_OPCODE_REQ       0x0u
#define MLX5_CQE_OPCODE_SIG_ERR   0xCu
#define MLX5_CQE_OPCODE_REQ_ERR   0xDu
#define MLX5_ERR_CQE_OFF_VENDOR_SYND 54u
#define MLX5_ERR_CQE_OFF_SYNDROME    55u

/* MLX5_CQE_SYNDROME_*(rdma-core mlx5dv.hから実際に取得した値、推測しない)。
 * エラーログ表示用。 */
static const char *mlx5_cqe_syndrome_str(uint8_t syndrome)
{
    switch (syndrome) {
    case 0x01: return "LOCAL_LENGTH_ERR";
    case 0x02: return "LOCAL_QP_OP_ERR";
    case 0x04: return "LOCAL_PROT_ERR";
    case 0x05: return "WR_FLUSH_ERR";
    case 0x06: return "MW_BIND_ERR";
    case 0x10: return "BAD_RESP_ERR";
    case 0x11: return "LOCAL_ACCESS_ERR";
    case 0x12: return "REMOTE_INVAL_REQ_ERR";
    case 0x13: return "REMOTE_ACCESS_ERR";
    case 0x14: return "REMOTE_OP_ERR";
    case 0x15: return "TRANSPORT_RETRY_EXC_ERR";
    case 0x16: return "RNR_RETRY_EXC_ERR";
    case 0x22: return "REMOTE_ABORTED_ERR";
    default:   return "UNKNOWN";
    }
}

typedef struct {
    mlx5_dev_t *dev;
    uint32_t rq_cc;         // RQ用CQの消費カウンタ(単調増加、折り返さない)
    uint32_t rq_posted_ctr; // RQドアベルへ最後に書いた「投稿済みWQE数」の累計
    /* 2026-08-13、受信ゼロコピー(CLAUDE.md「受信ゼロコピー」節): まだRQドアベルへ
     * 反映していない「消費済みだが再武装待ち」のWQE数。ゼロコピーではnet_bufが
     * RQバッファを直接指すため、そのnet_bufがdispatch+freeされるまでバッファを
     * 再武装できない。net_poll_all_and_dispatch()のバッチループは1フレームを
     * dispatch+freeしてから次のpoll_recv()を呼ぶので、poll_recv()冒頭で「前回まで
     * のpending分」をまとめて再武装する(1フレーム遅延、mlx5_net_rq_flush_rearm())。 */
    uint32_t rq_rearm_pending;
    // 2026-08-09、TCPゼロコピー送信(2 data_seg構成)対応: 「偶数アライン
    // 方式」(mlx5.hのMLX5_SQ_WQE_COUNTコメント参照)を採用したため、
    // sq_pc/sq_ccは以前と同じ「論理WQE単位」の単純な累積カウンタの
    // まま(1論理WQE=常に2 WQEBB固定消費、1CQE=1論理WQE完了)で済む
    // -- WQEBB単位への変換はアドレス計算とHWへ渡すインデックス値の
    // 計算時にのみ行う(mlx5_net_post_frame()参照)。
    uint32_t sq_pc;         // SQのWQE生成カウンタ(単調増加、論理WQE単位)
    uint32_t sq_cc;         // SQ占有量の消費カウンタ(論理WQE単位、占有量=sq_pc-sq_cc)
    // 2026-08-15、core-split の SQ recovery バグ修正(CLAUDE.md 追記予定):
    // Linux mlx5e が sq->cc(SQ消費) と cq->wq.cc(CQ消費) を別カウンタで持つのに
    // 倣い、CQ の消費位置を sq_cc から分離した。sq_cq_cc は CQ リングの index/
    // owner-bit/CQ ドアベルにのみ使う「純粋な CQ consumer」で、SQ の ERR->RST->RDY
    // 復帰時にも絶対にリセットしない(CQ は SQ と別オブジェクトで再作成されず、HW の
    // CQ producer 位置が数百万のまま継続するため、sq_cq_cc もそれを追い続ける必要が
    // ある)。正常時は sq_cq_cc==sq_cc で完全に同一挙動 -- 両者が食い違うのは
    // 「SQ を 0 起点にリセットしたが CQ は継続」という復帰の瞬間だけ。
    uint32_t sq_cq_cc;      // SQ用CQの消費カウンタ(CQ index/owner/doorbell専用、復帰でリセットしない)

    // 2026-08-09、MTXC/MRXF待ち切り分け「方針1」用(CLAUDE.md「MTXC/
    // MRXF待ち改善の検討方針」節参照)。前回読んだCQEのHWタイムスタンプ
    // (生サイクル値、mlx5_dev_t.clock_khzで変換)。has_last_*_hw_tsは
    // stateprof.cのstartedフラグと同じ理由(0が「未初期化」と「実際に
    // 読んだ値が0」を区別できない問題への対処)で明示的に持つ。
    uint64_t last_tx_hw_ts_cycles;
    uint8_t  has_last_tx_hw_ts;
    uint64_t last_rx_hw_ts_cycles;
    uint8_t  has_last_rx_hw_ts;
} mlx5_net_state_t;

static mlx5_net_state_t s_state_pf0;
static mlx5_net_state_t s_state_pf1;
static netif_t        s_ctx_pf0;
static netif_t        s_ctx_pf1;

/* 2026-08-08、ユーザー指示: 「TXタイムアウトが起きた瞬間に停止し、
 * その場でハード情報を採取する」ため追加。0=PF0, 1=PF1。一度でも
 * TXタイムアウトを検出したSQは、以後mlx5_net_send_frags()が新規の
 * WQEポスト・1秒待ちを一切行わず即座に-1を返すようにする(既に壊れたと
 * 確定したSQへ延々とリトライを重ね、詳細情報が失われた古い状態の上に
 * さらに新しい詰まりが積み重なる、というこれまでの調査で繰り返し
 * 直面した問題を防ぐ)。mlx5_netif_setup()(bring-upのたびに呼ばれる)
 * でPFごとにクリアする。 */
static volatile int s_sq_halted[2];

// 2026-08-08、ユーザー指示: s_sq_halted[]の自動復帰(mlx5_recover_sq()、
// mlx5.h参照)をサーキットブレーカー付きで再導入する。以前は無条件で
// 呼んでいたところ、根本原因(なぜ最初にSQがタイムアウトするか)が未解決
// のまま「復帰→即座に同じ理由で再ハング→また復帰を試みる」というサイクル
// に陥り、実機でtelnet/シリアルコンソール双方が数分以上無応答になる重大な
// 症状を引き起こした(電源の物理再投入が必要になった、mlx5.cのmlx5_
// recover_sq()コメント参照)。直近MLX5_NET_SQ_RECOVER_WINDOW_MS以内に
// MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS回を超えて復帰が必要になったら、それ以上は
// 諦めてs_sq_halted[]を立てたままにする(RP1のeth_tx_recover()には無い、
// mlx5固有の安全弁 -- HCAコマンド1往復が最大2秒[MLX5_CMD_TIMEOUT_MS]と
// 重いため、RP1のTHALT[最大14ms]と同じ頻度で無制限に繰り返すのは危険)。
#define MLX5_NET_SQ_RECOVER_WINDOW_MS    10000u
#define MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS 3u
// 2026-08-15、進捗ベースのサーキットブレーカー(mlx5_net_try_recover()参照)。
// 前回の復帰以降に SQ がこの数以上の論理 WQE を正常に処理(sq_cq_cc が前進)して
// いれば、一過性エラーで健全に復帰したとみなして試行回数をリセットする。SQ 深さ
// (16)よりはるかに大きい値にして「本当に稼働した」ことを担保する。
#define MLX5_NET_SQ_RECOVER_PROGRESS_WQES 1000u
static int      s_recover_attempts[2];
static uint64_t s_recover_window_start[2];
static uint32_t s_recover_last_cq_cc[2];

static int mlx5_net_pf_index(const mlx5_net_state_t *st)
{
    return (st == &s_state_pf0) ? 0 : 1;
}

// mlx5_net_dump_sq_debug()より前で使うための前方宣言(定義はmlx5_net_dump_
// sq_debug()の直後、mlx5_net_send_frags()より後にある)。
static int mlx5_net_try_recover(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st);

// ============================================================================
// CQEポーリング共通ヘルパ
// ============================================================================

// cq_buf上のCQE[cc & (num_entries-1)]について、owner bit(bit0)が
// (cc>>log_size)の偶奇と一致していれば、そのCQEの生ポインタを返す
// (=HWが書き込み済み)。一致しなければNULL(=まだ未到着)。呼び出し元が
// 消費後にcc自身をインクリメントする(mlx5_cqwq_get_cqe()と同じ規約)。
// 実機で発見した本物のバグ(修正済み): owner bitの一致だけでは
// 「HWが実際に書いたCQE」と「mlx5_create_cq()が焼き込んだ初期化用
// センチネル(0xF0、CLAUDE.md「CQポーリングによるライブ確認を実装」
// 節参照)」を区別できない。センチネルのop_own(0xF0)はbit0(owner)が
// 0であり、これは最初の周回(cc=0..num_entries-1、wrap_cnt=0)の期待値
// (0)とたまたま一致してしまう -- 「HWがまだ何も書いていない」状態と
// 「HWがwrap 0でowner=0の本物の完了を書いた」状態が、owner bitだけでは
// 見分けられない。
//
// デバッグ用に一時的にuart_printf()を挟んで実機検証したところ、この
// 曖昧さは実際にレースコンディションとして顕在化した: 送信直後
// ソフトウェアがタイトループでポーリングを開始すると、実際のフレームが
// 物理的に届いて完了が書き込まれるより前に、センチネルへの誤マッチが
// 何度も発生してrq_cc/CQドアベルが空振りで進んでしまい(64エントリ
// 全てを一瞬で「消費」してwrap_cnt=1・期待値=1の状態まで進んでしまう)、
// 実際にHWがwrap 0・owner=0で書いた本物の完了を二度と拾えなくなる
// (無限に取りこぼす)ことを実機で確認した。printfによるタイミングの
// 偶然の遅延が「たまたま動く」結果を生んだだけで、修正としては不十分
// だった。
//
// 修正: owner bitの一致に加え、opcode(上位nibble)がMLX5_CQE_OP_INVALID
// (0xF、ソフトウェアが意図的に選んだ「未書き込み」を表すセンチネル値
// であり、実際のHW完了opcodeとして使われることはない)でないことも
// 併せて確認する。診断用の一発ポーリング(mlx5.cのmlx5_cq_poll_any()、
// opcode!=INVALIDのみで判定)と同じ考え方を、継続ポーリング用の
// owner-bitトグル判定と組み合わせた。
static volatile uint8_t *mlx5_net_cqe_if_ready(uint64_t cq_buf_addr, uint32_t cc)
{
    uint32_t ci = cc & (MLX5_NET_CQ_NUM_ENTRIES - 1u);
    volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf_addr + (uint64_t)ci * MLX5_NET_CQE_SIZE);
    /* 2026-08-09: CQバッファをDevice-nGnRnE(MLX5_DMA_BASE)からNormal
     * cacheable RAM(MLX5_xQ_CQ_BUF_CACHE_ADDR)へ移した -- CPUキャッシュに
     * 残った古い値(前回のop_own)を読み続けないよう、判定前に必ず
     * invalidateする。この関数はRQ/SQ双方のCQポーリングで共有される
     * ホットパスのため、ここ1箇所の変更で両方に効く。 */
    dcache_invalidate_range((const void *)cqe, MLX5_NET_CQE_SIZE);
    uint8_t op_own = cqe[MLX5_CQE_OFF_OP_OWN];
    uint8_t owner_bit = (uint8_t)(op_own & MLX5_CQE_OWNER_MASK);
    uint8_t expected = (uint8_t)((cc >> MLX5_NET_CQ_LOG_SIZE) & 1u);
    if (owner_bit != expected) {
        return NULL;
    }
    if ((uint8_t)(op_own >> 4) == MLX5_CQE_OP_INVALID) {
        return NULL;
    }
    return cqe;
}

// CQEのHWタイムスタンプ(timestamp_h/timestamp_l、生サイクル値)を64bitへ
// 復元する。呼び出し前提: cqeは既にmlx5_net_cqe_if_ready()のinvalidateを
// 経ており、64バイト全体がコヒーレント(2026-08-09、方針1)。
static uint64_t mlx5_cqe_hw_ts_cycles(volatile uint8_t *cqe)
{
    uint32_t hi = ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H] << 24) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H + 1] << 16) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H + 2] << 8) |
                   (uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H + 3];
    uint32_t lo = ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L] << 24) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L + 1] << 16) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L + 2] << 8) |
                   (uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L + 3];
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

// 前回読んだHWタイムスタンプとの差分をns換算してtagで記録する
// (dev->clock_khzが0=未取得/取得失敗の場合は何もしない、憶測で換算
// しない)。初回呼び出し(has_last==0)は前回値が無いため記録せず、
// 現在値を保存するだけ。delta_nsがuint32_tへ収まらない場合は
// 0xFFFFFFFF(飽和)にする -- 通常はus〜低ms オーダーのdeltaしか
// 想定していないため、この飽和自体が「何かおかしい」シグナルになる。
static void mlx5_net_log_hw_ts_delta(mlx5_dev_t *dev, uint64_t cur_cycles,
                                      uint64_t *last_cycles, uint8_t *has_last,
                                      uint32_t tag)
{
    if (!(ts_log_mode() & TS_MODE_HOTPATH)) return;  /* per-frame計装、既定OFF */
    if (dev->clock_khz == 0u) {
        return;
    }
    if (*has_last) {
        uint64_t delta_cycles = cur_cycles - *last_cycles; // unsigned、折り返しも安全
        uint64_t delta_ns = (delta_cycles * 1000000ULL) / (uint64_t)dev->clock_khz;
        uint32_t arg = (delta_ns > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : (uint32_t)delta_ns;
        ts_log(tag, arg);
    }
    *last_cycles = cur_cycles;
    *has_last = 1u;
}

// ============================================================================
// 送信
// ============================================================================

// 2026-08-10、LSO対応で追加: mlx5_net_post_frame()(通常送信)/
// mlx5_net_post_lso_frame()(LSO送信)共通の「WQE本体を書き終えた後」の
// 処理(ドアベルレコード更新+2本のdsbバリア+BlueFlame書き込み+sq_pc
// 更新)を1箇所にまとめる。この部分は実機で複数回バグを踏んで確定させた
// 最も壊れやすいロジック(2026-08-08、WQE→ドアベル間のバリア欠落による
// LOCAL_QP_OP_ERR、BlueFlame書き込みのアクセスサイズ非アトミックによる
// 2コア間インターリーブ、いずれも「TXハングの真因候補」以降の節参照)
// なので、WQE内容の組み立て(呼び出し元ごとに異なる)とは切り離し、
// 複製せず共有することでこのロジックの二重管理・将来の修正漏れを防ぐ。
// wqeは呼び出し元が既に全フィールドを書き終えた状態のWQE(ctrl_seg
// 先頭8バイトを含む)を指すこと。
static void mlx5_net_wqe_commit(mlx5_dev_t *dev, mlx5_net_state_t *st,
                                 uint32_t pc, volatile uint8_t *wqe)
{
    dma_wmb();

    // 2026-08-09、「偶数アライン方式」: new_pc(論理WQE単位、+1)は
    // ソフトウェア内部の管理用カウンタ(st->sq_pcへそのまま保存する)だが、
    // ドアベルへ書く値はHW視点の実WQEBB累積消費数(new_pc*2)でなければ
    // ならない(ctrl_seg.opmod_idx_opcodeのwqe indexフィールドと同じ
    // 単位)。
    volatile uint8_t *sq_dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->sq_dbr_cpu;
    uint32_t new_pc = pc + 1u;
    uint32_t hw_new_pc = new_pc * 2u;
    sq_dbr[0] = (uint8_t)(hw_new_pc >> 24);
    sq_dbr[1] = (uint8_t)(hw_new_pc >> 16);
    sq_dbr[2] = (uint8_t)(hw_new_pc >> 8);
    sq_dbr[3] = (uint8_t)hw_new_pc;

    dma_wmb();

    // BlueFlame: ctrl_seg先頭8バイトをUARへ単一の64bitストアで書く
    // (アクセスサイズのアトミック性についてはmlx5_net_post_frame()の
    // 既存コメント参照、CLAUDE.md「core分離のSQ LOCAL_QP_OP_ERR」節)。
    uint32_t raw0 = (uint32_t)wqe[0] | ((uint32_t)wqe[1] << 8) |
                    ((uint32_t)wqe[2] << 16) | ((uint32_t)wqe[3] << 24);
    uint32_t raw1 = (uint32_t)wqe[4] | ((uint32_t)wqe[5] << 8) |
                    ((uint32_t)wqe[6] << 16) | ((uint32_t)wqe[7] << 24);
    uint64_t raw64 = (uint64_t)raw0 | ((uint64_t)raw1 << 32);
    uint64_t uar_addr = dev->bar0_base + (uint64_t)dev->uarn * 4096u;
    mmio_write64(uar_addr + MLX5_BF_OFFSET, raw64);

    st->sq_pc = new_pc;
}

// nic_ops_t.send_frags()/send_frags_async()共通の下位実装。
// mlx5_sq_send_test_frame()と同じ構造のWQEを組み立ててドアベルを鳴らす。
//
// 2026-08-09、ゼロコピー化(ユーザー指示「0コピーにできませんか」への
// 対応)。以前は呼び出し元のframs[].dataをこのWQEスロット専用のステージ
// バッファ(mlx5専用DMA領域内、Device-nGnRnEマップ)へ毎回コピーしてから
// 送信していたが、実機`ts`計測(SCPY/SDCCタグ、CLAUDE.md「性能分析基盤の
// 整備」節参照)でこのコピー自体が1セグメント(約9938バイト)あたり
// 約30-38usかかっており、TCP/NVMe-oFパイプライン全体の支配的コストだと
// 判明した。frag_count==1かつ60バイト以上(実際のTCPデータセグメント送信
// が常に満たす条件、MSSはIEEE802.3最小フレーム長よりはるかに大きい)の
// 場合、呼び出し元のバッファ(tcp.cのs_seg_bufs[core][slot])を一切コピー
// せず、WQEのデータセグメントから直接参照する -- 呼び出し元は既に
// eth_tx_wait_free_slot()でこのスロットの空き(前回そのスロットを使った
// WQEのHW処理完了)を待ってから書き込み、dcache_clean_range()でDMA
// コヒーレンシも確保済み(eth.hのeth_send_frags()呼び出し規約、
// tcp_send_segment()参照)であるため、追加のコピー・キャッシュクリーンは
// 不要。frag_count>1、または60バイト未満(IEEE802.3最小フレーム長への
// パディングが必要、ペイロード無しの純粋なACK等が該当する -- 非同期
// 送信[eth_send_frags_async()]経由でも普通に発生する、mlx5.hの
// MLX5_NET_TX_STAGE_ADDR直前のコメント参照)のケースは、このWQEスロット
// 専用のフォールバックバッファへ一旦連結する。
//
// 前提: 呼び出し元がmlx5_net_sq_wait_room()でこのWQEスロットの空きを
// 確認済みであること(=st->sq_pc-st->sq_cc < MLX5_SQ_WQE_COUNT)。この
// 関数自体は待たない -- ポストするだけ。
static int mlx5_net_post_frame(mlx5_net_state_t *st, const eth_frag_t *frags, unsigned frag_count)
{
    if (frag_count < 1u || frag_count > ETH_TX_MAX_FRAGS) {
        uart_printf("[mlx5net] send: invalid frag_count (%u)\n", frag_count);
        return -1;
    }

    mlx5_dev_t *dev = st->dev;
    uint32_t pc = st->sq_pc;
    uint32_t slot = pc % MLX5_SQ_WQE_COUNT;

    uint32_t total_len = 0;
    for (unsigned f = 0; f < frag_count; f++) {
        total_len += frags[f].len;
    }
    if (total_len < ETH_HDR_LEN || total_len > MLX5_NET_TX_STAGE_SIZE) {
        uart_printf("[mlx5net] send: invalid frame length (%u)\n", total_len);
        return -1;
    }

    const volatile uint8_t *header_src; // インラインヘッダ(先頭18バイト)の参照元
    uint64_t data_pa;                   // data_seg1のDMAアドレス(18バイト目以降)
    uint32_t frame_total = total_len;   // パディング後の実フレーム長
    uint64_t data2_pa = 0;              // data_seg2のDMAアドレス
    uint32_t remaining1 = 0;            // data_seg1のバイト数
    uint32_t remaining2 = 0;            // data_seg2のバイト数
    const uint32_t ihs = 18u;           // インラインヘッダ(ETH_HLEN+VLAN_HLEN、L2モード)

    /* 2026-08-15、NOPフィラー撤廃(ユーザー要望、実機のエラーCQE調査より)。
     * LOCAL_QP_OP_ERRのエラーCQEが、失敗したWQEのopcodeを0x00(NOP)と報告した
     * -- 「偶数アライン方式」で小フレームの2番目のWQEBBに詰めていたNOPフィラーが、
     * このFW(14.32.1900含む)で稀にLOCAL_QP_OP_ERRを起こしていた。
     *
     * 対策: 別WQEとしてのNOPを一切使わず、全ての送信を「2つのdata_segを持つ単一
     * SEND WQE(ds_cnt=5=ctrl+eth+inline_hdr+data_seg1+data_seg2)」にする。ds_cnt=5は
     * 80バイト=2WQEBBを占有するので、SEND WQE自身が2 WQEBBぶんを埋める -- これで
     * 「1論理WQE=常に2WQEBB=1CQE」という設計(sq_pc/sq_cc/buffer-reuseの単純さ)を
     * 保ったまま、NOPが構造的に不要になる。frag_count==2(ヘッダ/ペイロード別バッファ)は
     * 元から2 data_segでNOP不使用。frag_count==1(単一バッファ)は、インライン18バイト後の
     * データを2つのdata_seg(内容はワイヤ上連続=不変)に分割する。フレームは常に60バイト
     * 以上(未満はパディング)なのでインライン後は42バイト以上あり、必ず2分割できる。 */
    if (frag_count == 2u && frags[0].len >= ihs && total_len >= 60u) {
        /* frags[0]=ヘッダ(Ethernet+IP+TCP)、frags[1]=ペイロード(呼び出し元バッファを
         * 直接参照)。インライン18バイトはfrags[0]、frags[0]の残り(IP/TCPヘッダ)を
         * data_seg1、frags[1]全体をdata_seg2にする(2026-08-09のゼロコピー2フラグ経路)。 */
        header_src = (const volatile uint8_t *)frags[0].data;
        data_pa = mlx5_dma_addr((const volatile void *)((const uint8_t *)frags[0].data + ihs));
        remaining1 = frags[0].len - ihs;
        data2_pa = mlx5_dma_addr((const volatile void *)frags[1].data);
        remaining2 = frags[1].len;
    } else if (frag_count == 1u && total_len >= 60u) {
        /* 単一バッファのゼロコピー経路。インライン後のデータを2つのdata_segへ分割
         * (末尾8バイトをdata_seg2)-- NOP撤廃のため常に2 data_seg。 */
        header_src = (const volatile uint8_t *)frags[0].data;
        uint32_t d = frame_total - ihs;
        remaining2 = 8u;
        remaining1 = d - remaining2;
        data_pa  = mlx5_dma_addr((const volatile void *)((const uint8_t *)frags[0].data + ihs));
        data2_pa = mlx5_dma_addr((const volatile void *)((const uint8_t *)frags[0].data + ihs + remaining1));
    } else {
        /* フォールバック(低頻度)。2026-08-09、mlx5.hのMLX5_NET_TX_STAGE_ADDR直前の
         * コメントで詳述した実機バグ(単一共有バッファだと非同期送信された小さいACK等が
         * 互いを上書きしうる)の修正により、このWQEスロット(slot)専用のバッファを使う
         * -- ゼロコピー経路と同じ排他が効く。ここも2 data_segに分割してNOPを使わない。 */
        volatile uint8_t *stage = (volatile uint8_t *)(uintptr_t)
            ((uint64_t)dev->net_tx_stage_cpu + (uint64_t)(slot) * MLX5_NET_TX_STAGE_SIZE);
        uint32_t off = 0;
        for (unsigned f = 0; f < frag_count; f++) {
            volatile_fast_copy(stage + off, frags[f].data, frags[f].len);
            off += frags[f].len;
        }
        // IEEE802.3最小フレーム長(60バイト、FCS抜き)未満はゼロパディング
        // する(mlx5_sq_send_test_frame()と同じ理由)。
        if (total_len < 60u) {
            for (uint32_t i = total_len; i < 60u; i++) stage[i] = 0;
            frame_total = 60u;
        }
        header_src = stage;
        uint32_t d = frame_total - ihs;
        remaining2 = 8u;
        remaining1 = d - remaining2;
        data_pa  = mlx5_dma_addr((const volatile void *)(stage + ihs));
        data2_pa = mlx5_dma_addr((const volatile void *)(stage + ihs + remaining1));
    }

    // 2026-08-09、「偶数アライン方式」: 1論理WQE=常に2 WQEBB(128バイト)
    // 固定で消費するため、物理WQEBBオフセットは`slot * 2 * MLX5_SEND_
    // WQE_BB`(論理slotをWQEBBインデックスへ変換)。
    volatile uint8_t *wqe =
        (volatile uint8_t *)(uintptr_t)((uint64_t)dev->sq_wqe_cpu +
                                         (uint64_t)slot * 2u * MLX5_SEND_WQE_BB);
    // 1論理WQE分(2 WQEBB=128バイト)全体をゼロクリアする -- 2つ目の
    // WQEBB(data_seg2を含む)も前回内容の残骸を持たないようにする。
    for (unsigned i = 0; i < 2u * MLX5_SEND_WQE_BB; i++) wqe[i] = 0;

    // 2026-08-15、NOP撤廃: 常に2 data_seg(ctrl+eth+inline_hdr+data_seg1+
    // data_seg2=5)。ds_cnt=5=80バイトは2 WQEBBを占有するので、この単一
    // SEND WQE自身が「偶数アライン方式」の2 WQEBBぶんを埋める(別NOP不要)。
    // ihsは上のsetupで定義済み(インラインヘッダ18バイト、L2モード)。
    uint32_t ds_cnt = 5u;
    /* 【2026-08-08、実機で発見した本物のバグの修正】opmod_idx_opcodeの
     * レイアウトは上位8bit=opmod(常に0)/中間16bit=wqe index/下位8bit=
     * opcode(include/linux/mlx5/qp.hのstruct mlx5_wqe_ctrl_seg、実ソース
     * torvalds/linux include/linux/mlx5/mlx5_ifc.hのwq_bitsと合わせて
     * 実際に取得し確認済み)。pcは32bitの単調増加カウンタなので、16bit
     * のwqe indexフィールドへ収める前に必ず0xFFFFでマスクすること --
     * マスクせずに`pc << 8`していたため、pcが65536(0x10000、2^16)に
     * 達した瞬間、本来0であるべきopmodバイト(wqe[0])へpcのビット17が
     * 漏れ出し、`opmod=1`という不正な値を持つWQEをHWへ送っていた。
     * 実機調査(mlx5netdumpコマンド)で、SQがERROR状態(state=3)に落ちた
     * 瞬間のWQE[0]が実際に`opmod_idx_opcode=0x0100000a`(pc=65536で
     * opmod=0x01)になっていることを直接確認した -- HWの限界ではなく、
     * 65536回目の送信で確定的に再現するソフトウェアバグだった。
     *
     * 2026-08-09、「偶数アライン方式」採用に伴い、このフィールドが
     * 期待するのはHW視点の実WQEBBインデックスであり、pc(論理WQE単位)
     * ではなく`pc*2`(WQEBB単位)を使う必要がある(Linux en_tx.cの
     * `cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | opcode)`の
     * sq->pcはWQEBB単位カウンタそのもの)。 */
    uint32_t hw_wqe_idx = (pc * 2u) & 0xFFFFu;
    uint32_t opmod_idx_opcode = (hw_wqe_idx << 8) | MLX5_OPCODE_SEND;
    wqe[0] = (uint8_t)(opmod_idx_opcode >> 24);
    wqe[1] = (uint8_t)(opmod_idx_opcode >> 16);
    wqe[2] = (uint8_t)(opmod_idx_opcode >> 8);
    wqe[3] = (uint8_t)opmod_idx_opcode;

    /* MTXB: このWQEの実際のopcode(ctrl_seg、常にMLX5_OPCODE_SEND=0x0a)と
     * byte count(frame_total、パディング後の実フレーム長)。argは
     * (opcode<<24)|(frame_total&0xFFFFFF) -- frame_totalはMLX5_JUMBO_
     * MAX_LEN(10240)以下なので24bitに余裕で収まる。MTXS(直前、
     * WQEポスト前のsq_pc/sq_cc)と対で見ることで、そのポストで実際に
     * 何が送られたかをtsコマンドから直接確認できる。 */
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_post_frame, 0),
           ((uint32_t)MLX5_OPCODE_SEND << 24) | (frame_total & 0xFFFFFFu));

    uint32_t qpn_ds = (dev->sqn << 8) | ds_cnt;
    wqe[4] = (uint8_t)(qpn_ds >> 24);
    wqe[5] = (uint8_t)(qpn_ds >> 16);
    wqe[6] = (uint8_t)(qpn_ds >> 8);
    wqe[7] = (uint8_t)qpn_ds;
    wqe[11] = (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE;

    /* 2026-08-09、ハードウェアチェックサムオフロード対応。eth_seg
     * (wqe[16..31]、struct mlx5_wqe_eth_seg、Linux include/linux/mlx5/
     * qp.hを実際に取得して確認済み)のcs_flagsはeth_seg相対byte4=
     * wqe[16+4]=wqe[20]。MLX5_ETH_WQE_L3_CSUM(1<<6)|MLX5_ETH_WQE_L4_CSUM
     * (1<<7)を立てると、HWがIPヘッダ/TCPヘッダのチェックサムを実際に
     * 計算してフレームへ書き込む(en_tx.cのmlx5e_txwqe_build_eseg_csum()
     * と同じ設定、CHECKSUM_PARTIAL相当)。tcp.c/ip.cはnetif_t.
     * hw_csum_offload(このmlx5経路では常に1)を見て、送信前のソフト
     * ウェアチェックサム計算を省略する(送信するチェックサムフィールドの
     * 実際の値はHWが上書きするため0のままでよい)。 */
    wqe[20] = 0xC0u; // MLX5_ETH_WQE_L3_CSUM(0x40) | MLX5_ETH_WQE_L4_CSUM(0x80)

    wqe[28] = (uint8_t)(ihs >> 8);
    wqe[29] = (uint8_t)ihs;
    wqe[30] = header_src[0];
    wqe[31] = header_src[1];
    for (unsigned i = 0; i < (ihs - 2u); i++) wqe[32 + i] = header_src[2 + i];
    uint32_t dseg_off = 32u + (ihs - 2u);

    /* data_seg1: setupで計算したremaining1バイト(data_paから)。 */
    uint32_t remaining = remaining1;
    wqe[dseg_off + 0] = (uint8_t)(remaining >> 24);
    wqe[dseg_off + 1] = (uint8_t)(remaining >> 16);
    wqe[dseg_off + 2] = (uint8_t)(remaining >> 8);
    wqe[dseg_off + 3] = (uint8_t)remaining;
    wqe[dseg_off + 4] = (uint8_t)(dev->mkey >> 24);
    wqe[dseg_off + 5] = (uint8_t)(dev->mkey >> 16);
    wqe[dseg_off + 6] = (uint8_t)(dev->mkey >> 8);
    wqe[dseg_off + 7] = (uint8_t)dev->mkey;
    for (unsigned b = 0; b < 8; b++) {
        wqe[dseg_off + 8 + b] = (uint8_t)(data_pa >> (56 - 8 * b));
    }

    /* data_seg2: 常に書く(NOP撤廃、setupで全経路がremaining2/data2_paを設定済み)。
     * data_seg1の直後(dseg_off+16)。ctrl16+eth16+inline16+data_seg1 16+data_seg2 16=
     * 80バイトで2 WQEBB(128バイト)に収まり、この単一SEND WQEが2 WQEBBを占有する。 */
    {
        uint32_t dseg2_off = dseg_off + 16u;
        wqe[dseg2_off + 0] = (uint8_t)(remaining2 >> 24);
        wqe[dseg2_off + 1] = (uint8_t)(remaining2 >> 16);
        wqe[dseg2_off + 2] = (uint8_t)(remaining2 >> 8);
        wqe[dseg2_off + 3] = (uint8_t)remaining2;
        wqe[dseg2_off + 4] = (uint8_t)(dev->mkey >> 24);
        wqe[dseg2_off + 5] = (uint8_t)(dev->mkey >> 16);
        wqe[dseg2_off + 6] = (uint8_t)(dev->mkey >> 8);
        wqe[dseg2_off + 7] = (uint8_t)dev->mkey;
        for (unsigned b = 0; b < 8; b++) {
            wqe[dseg2_off + 8 + b] = (uint8_t)(data2_pa >> (56 - 8 * b));
        }
    }

    /* 2026-08-08、ユーザー指摘("ベンダのドライバでもロックを取っているのか"/
     * "アクセスサイズに違いはないか")を受けて発見した2件の本物のバグ
     * (WQE→ドアベル間のバリア欠落によるLOCAL_QP_OP_ERR、BlueFlame書き込み
     * のアクセスサイズ非アトミックによる2コア間インターリーブ)の詳細は
     * mlx5_net_wqe_commit()のコメント参照。2026-08-10、LSO対応でこの
     * 「WQE本体を書き終えた後」の処理を共有ヘルパへ切り出した(元々この
     * 場所にあった詳細な調査記録コメントもそちらへ移動)。 */
    mlx5_net_wqe_commit(dev, st, pc, wqe);
    return 0;
}

// 2026-08-10、LSO(TCP Segmentation Offload)対応。tcp.cのtcp_send_
// segment_lso()から、既に組み立て済みのL2+L3+L4ヘッダ(hdr、hdr_len
// バイト、TCPデータオフセット以降=ペイロードは含まない)と、送信したい
// ペイロード全体(payload、payload_lenバイト、複数MSS分をまとめてよい、
// tcp.c側のバッファをコピー無しでそのまま参照)を渡される。HWはこの
// ヘッダをテンプレートとして、payloadをmss単位に自動分割し、実セグメント
// ごとにIP total length/IP ID/TCP seq/チェックサムを再計算・上書きして
// 送出する(実ドライバソースで確認した挙動、mlx5.hのMLX5_OPCODE_LSO
// コメント、`~/.claude/plans/lexical-squishing-mitten.md`参照)。
//
// 通常送信(mlx5_net_post_frame())と異なり、LSOはL2ヘッダだけでなく
// L3/L4ヘッダも含めた全体をインラインでWQEへ埋め込む必要がある(HWが
// ヘッダをそのまま複製・書き換えるため、DMA読み出しでは済まない) --
// このプロジェクトのTCPデータセグメント(SYNではない、オプション無し)
// では hdr_len は常に54バイト(ETH_HLEN14+IPヘッダ20+TCPヘッダ20)。
static int mlx5_net_post_lso_frame(mlx5_net_state_t *st, const void *hdr, uint16_t hdr_len,
                                    const void *payload, uint32_t payload_len, uint16_t mss)
{
    if (hdr_len < 18u || payload_len == 0u) {
        uart_printf("[mlx5net] lso: invalid hdr_len/payload_len (%u/%u)\n",
                    (unsigned)hdr_len, (unsigned)payload_len);
        return -1;
    }

    mlx5_dev_t *dev = st->dev;
    uint32_t pc = st->sq_pc;
    uint32_t slot = pc % MLX5_SQ_WQE_COUNT;

    // ds_cnt = ctrl(1) + eth(1) + インライン超過分(inline_hdr.startの
    // 2バイトを除いた残りを16バイト単位に切り上げ) + data_seg(1、payload)。
    // mlx5_net_post_frame()のヘッダコメントと同じ式
    // (`ds_cnt += DIV_ROUND_UP(ihs - INL_HDR_START_SZ, MLX5_SEND_WQE_DS)`)。
    uint32_t inline_ds = ((uint32_t)hdr_len - 2u + 15u) / 16u;
    uint32_t ds_cnt = 2u + inline_ds + 1u;
    // 「偶数アライン方式」は1論理WQEにつき常に2 WQEBB(128バイト=8 DS)を
    // 予約する -- ds_cntがこれを超える場合は安全に失敗させる(呼び出し元
    // は常にhdr_len=54の固定値を渡す設計のためds_cnt=7で収まるはずだが、
    // 将来の変更で超過しても静かに隣接WQEBBを破壊しないための防御)。
    if (ds_cnt * 16u > 2u * MLX5_SEND_WQE_BB) {
        uart_printf("[mlx5net] lso: hdr_len too large for WQE budget (hdr_len=%u ds_cnt=%u)\n",
                    (unsigned)hdr_len, ds_cnt);
        return -1;
    }

    volatile uint8_t *wqe =
        (volatile uint8_t *)(uintptr_t)((uint64_t)dev->sq_wqe_cpu +
                                         (uint64_t)slot * 2u * MLX5_SEND_WQE_BB);
    for (unsigned i = 0; i < 2u * MLX5_SEND_WQE_BB; i++) wqe[i] = 0;

    uint32_t hw_wqe_idx = (pc * 2u) & 0xFFFFu;
    uint32_t opmod_idx_opcode = (hw_wqe_idx << 8) | MLX5_OPCODE_LSO;
    wqe[0] = (uint8_t)(opmod_idx_opcode >> 24);
    wqe[1] = (uint8_t)(opmod_idx_opcode >> 16);
    wqe[2] = (uint8_t)(opmod_idx_opcode >> 8);
    wqe[3] = (uint8_t)opmod_idx_opcode;

    /* MTXB: 実際にポストするWQEのopcode/byte countをtsコマンドから確認
     * できるようにする(通常送信のmlx5_net_post_frame()と同じタグ、argの
     * 上位8bit=opcode/下位24bit=バイト数。LSOはヘッダではなくペイロード
     * バイト数[HWが実際に分割送出する対象]を記録する)。 */
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_post_lso_frame, 0),
           ((uint32_t)MLX5_OPCODE_LSO << 24) | (payload_len & 0xFFFFFFu));

    uint32_t qpn_ds = (dev->sqn << 8) | ds_cnt;
    wqe[4] = (uint8_t)(qpn_ds >> 24);
    wqe[5] = (uint8_t)(qpn_ds >> 16);
    wqe[6] = (uint8_t)(qpn_ds >> 8);
    wqe[7] = (uint8_t)qpn_ds;
    wqe[11] = (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE;

    // eth_seg: cs_flags(通常送信と同じL3_CSUM|L4_CSUM、LSOでも必須
    // -- 実ドライバのmlx5e_txwqe_build_eseg_csum()で確認済み)+
    // mss(eth_seg相対byte6-7=wqe[22..23]、BE16、通常送信では未使用の
    // フィールド)。
    wqe[20] = 0xC0u; // MLX5_ETH_WQE_L3_CSUM(0x40) | MLX5_ETH_WQE_L4_CSUM(0x80)
    wqe[22] = (uint8_t)(mss >> 8);
    wqe[23] = (uint8_t)mss;

    // インラインヘッダ全体(L2+L3+L4、hdr_lenバイト)をコピーする
    // (mlx5_net_post_frame()のheader_srcコピーと同じ配置ロジック、
    // ihsが固定18ではなく可変[通常54]になっただけ)。
    const volatile uint8_t *hdr_src = (const volatile uint8_t *)hdr;
    wqe[28] = (uint8_t)(hdr_len >> 8);
    wqe[29] = (uint8_t)hdr_len;
    wqe[30] = hdr_src[0];
    wqe[31] = hdr_src[1];
    for (unsigned i = 0; i < ((unsigned)hdr_len - 2u); i++) wqe[32 + i] = hdr_src[2 + i];
    /* 【実装中に発見した本物のバグ、修正済み】data_segの配置はインライン
     * ヘッダの実バイト数(hdr_len-2)直後ではなく、DS(16バイト単位)境界へ
     * 切り上げた位置でなければならない -- ds_cnt/HWは固定16バイト単位の
     * DSでWQEを解釈するため、inline_ds*16バイト(切り上げ済み、上記
     * 計算済み)がインライン領域の実際の占有幅。mlx5_net_post_frame()の
     * 通常送信経路(ihs=18固定)は`ihs-2=16`がたまたま16の倍数ぴったり
     * だったため、この2つの計算(実バイト数 vs DS境界切り上げ)が偶然
     * 一致しており見分けが付きにくかった -- hdr_len=54(52=3*16+4、
     * 端数あり)で初めて2つの式が食い違うことに気付いた。 */
    uint32_t dseg_off = 32u + inline_ds * 16u;

    // data_seg(1個のみ): ペイロード全体を直接参照(ゼロコピー、通常送信の
    // two_dsegのdata_seg2と同じパターン)。HWがmss単位に分割する対象。
    uint64_t payload_pa = mlx5_dma_addr((const volatile void *)payload);
    wqe[dseg_off + 0] = (uint8_t)(payload_len >> 24);
    wqe[dseg_off + 1] = (uint8_t)(payload_len >> 16);
    wqe[dseg_off + 2] = (uint8_t)(payload_len >> 8);
    wqe[dseg_off + 3] = (uint8_t)payload_len;
    wqe[dseg_off + 4] = (uint8_t)(dev->mkey >> 24);
    wqe[dseg_off + 5] = (uint8_t)(dev->mkey >> 16);
    wqe[dseg_off + 6] = (uint8_t)(dev->mkey >> 8);
    wqe[dseg_off + 7] = (uint8_t)dev->mkey;
    for (unsigned b = 0; b < 8; b++) {
        wqe[dseg_off + 8 + b] = (uint8_t)(payload_pa >> (56 - 8 * b));
    }

    // 2番目のWQEBBがこのWQE自身のDSで完全には埋まらない場合(hdr_lenが
    // 現状より小さい将来の呼び出しがあった場合の防御、通常のhdr_len=54
    // では常にds_cnt=7で2番目のWQEBBが埋まるため実際には通らない)、
    // mlx5_net_post_frame()の単一WQEBB経路と同じ理由でNOPパディングが
    // 必要(実機で確認済みの本物のバグ、同関数のコメント参照)。
    if (ds_cnt * 16u <= MLX5_SEND_WQE_BB) {
        volatile uint8_t *nop_wqe = wqe + MLX5_SEND_WQE_BB;
        uint32_t nop_hw_idx = (hw_wqe_idx + 1u) & 0xFFFFu;
        uint32_t nop_opmod = (nop_hw_idx << 8) | MLX5_OPCODE_NOP;
        nop_wqe[0] = (uint8_t)(nop_opmod >> 24);
        nop_wqe[1] = (uint8_t)(nop_opmod >> 16);
        nop_wqe[2] = (uint8_t)(nop_opmod >> 8);
        nop_wqe[3] = (uint8_t)nop_opmod;
        uint32_t nop_qpn_ds = (dev->sqn << 8) | 1u;
        nop_wqe[4] = (uint8_t)(nop_qpn_ds >> 24);
        nop_wqe[5] = (uint8_t)(nop_qpn_ds >> 16);
        nop_wqe[6] = (uint8_t)(nop_qpn_ds >> 8);
        nop_wqe[7] = (uint8_t)nop_qpn_ds;
    }

    mlx5_net_wqe_commit(dev, st, pc, wqe);
    return 0;
}

// 2026-08-08、ユーザー指摘("core0だけなら動く、core1を動かすと事象が
// 起きるのは何かが重複している証拠"/"ベンダのドライバでもロックを
// 取っているのか")を受けた調査の記録: 当初、PF0/PF1間でこの関数全体を
// 排他するグローバルスピンロックを追加し、実機で25回連続成功を確認した。
// しかしLinux mlx5_core(drivers/net/ethernet/mellanox/mlx5/core/en/
// txrx.hのmlx5e_notify_hw())を実際に確認したところ、実ドライバは
// ロックを一切使わず、正確な2段階メモリバリア(dma_wmb()->db更新->
// wmb()->BlueFlame書き込み)だけで複数SQ/複数ポート間の並行動作を
// 成立させていた。このプロジェクトの実装(mlx5_net_post_frame()参照)
// には「WQE本体書き込み完了後・ドアベルレコード更新前」のバリアが
// 欠落しており、これが真の原因だったと判断してバリアを追加した(修正
// 済み)。ロックは対症療法(2コアの真の並行実行を強制的に排除すること
// で、たまたまバリア欠落の影響を覆い隠していただけ)と判断して撤去し、
// バリア修正だけで実機再検証する。

// このSQ用CQから、現在到着済み(owner bit一致・opcode!=INVALID)な完了を
// 最大1件だけ非ブロッキングで処理する(reap)。パイプライン化された複数の
// 未完了WQEを、呼び出し元がタイムアウト付きのwhileループで繰り返し呼ぶ
// ことで少しずつ刈り取っていく設計 -- eth.cのeth_tx_wait_slot()が
// TX_USEDビットを記述子から直接読むのに対し、mlx5は完了専用のリング
// (CQ)を経由する必要があるための対応。エラーCQE(REQ_ERR/SIG_ERR)の判別・
// mlx5_net_try_recover()呼び出しは、旧mlx5_net_send_frags()(完全同期版)
// が持っていたロジックをそのまま踏襲する。
//
// 戻り値:
//   0 : 到着済みの完了なし(呼び出し元は再ポーリングかタイムアウト判定へ)
//   1 : 正常完了を1件消費した(st->sq_ccが+1進んだ)
//   2 : エラーCQEを検出し、mlx5_net_try_recover()による自動復帰が成功
//       した -- st->sq_pc/sq_ccは共に0へリセットされている(=このエラー
//       CQEより後にポスト済みだったWQEを含め、リング上の状態は全て
//       失われた)。呼び出し元は自分が待っていた特定のpc値がもう存在
//       しないことを踏まえて判断すること。
//  -1 : エラーCQEの復帰に失敗、またはサーキットブレーカー発動
//       (s_sq_halted[]が立った、このSQは以後使用不可)。
static int mlx5_net_sq_reap_one(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    uint64_t cq_buf = (uint64_t)dev->sq_cq_buf_cpu;
    // CQ の index/owner-bit は sq_cq_cc(純粋な CQ consumer)で判定する。
    // sq_cc(SQ占有量)は復帰で 0 起点に戻りうるため CQ index には使えない。
    volatile uint8_t *cqe = mlx5_net_cqe_if_ready(cq_buf, st->sq_cq_cc);
    if (!cqe) {
        return 0;
    }

    /* 2026-08-09、TCPゼロコピー送信(2 data_seg構成)対応: 常に「1論理
     * WQE=2 WQEBB固定」(偶数アライン方式、mlx5.hのMLX5_SQ_WQE_COUNT
     * コメント参照、単一WQEBBのWQEも後半を空費して2WQEBB分を消費する)
     * にしたため、CQE1件は常に論理WQE1件の完了を意味し、st->sq_cc
     * (論理エントリ単位)を単純に+1するだけでよい -- CQEのwqe_counter
     * (実際のWQEBBインデックス)を読んで32bit復元する必要は無い(その
     * ロジックは可変長WQEの場合にのみ必要だったが、固定2WQEBB化に
     * より不要になった)。 */

    /* 【2026-08-08、ユーザー指示で発見・修正した本物のバグ】CQEが「到着
     * 済み」(owner bit一致・opcode!=INVALID)であることと「送信が成功
     * したこと」は別物 -- mlx5のCQE opcodeにはMLX5_CQE_REQ_ERR(13)/
     * MLX5_CQE_SIG_ERR(12)という明示的なエラー完了が存在する
     * (linux-rdma/rdma-core providers/mlx5/mlx5dv.hで値を実際に確認、
     * 推測ではない)。 */
    uint8_t op_own = cqe[MLX5_CQE_OFF_OP_OWN];
    uint8_t opcode = (uint8_t)(op_own >> 4);
    if (opcode == MLX5_CQE_OPCODE_REQ_ERR || opcode == MLX5_CQE_OPCODE_SIG_ERR) {
        uint8_t vendor_synd = cqe[MLX5_ERR_CQE_OFF_VENDOR_SYND];
        uint8_t syndrome    = cqe[MLX5_ERR_CQE_OFF_SYNDROME];

        TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_reap_one, 0),
               ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
        uart_printf("[mlx5net] SQ完了エラーCQE検出 (sqn=%u, opcode=0x%x=%s, "
                    "syndrome=0x%02x(%s), vendor_synd=0x%02x)\n",
                    dev->sqn, opcode,
                    (opcode == MLX5_CQE_OPCODE_SIG_ERR) ? "SIG_ERR" : "REQ_ERR",
                    syndrome, mlx5_cqe_syndrome_str(syndrome), vendor_synd);

        /* このエラーCQE自体は「刈り取り済み」として消費しておく(cc/
         * ドアベル更新) -- タイムアウト分岐と異なりCQEは実在するため、
         * sq_pcの巻き戻しは不要(送信自体はHWに正しく認識されており、
         * その処理結果がエラーだった、という違い)。この直後でmlx5_net_
         * try_recover()が成功すればsq_pc/sq_ccは改めて0/0へ揃えられる
         * (このインクリメント自体は復帰失敗/サーキットブレーカー発動時の
         * 診断ダンプに正確なsq_ccを残すため)。 */
        st->sq_cq_cc++;   // CQ consumer(復帰でリセットしない)
        st->sq_cc++;      // SQ占有量(この直後の try_recover で 0 リセットされうる)
        /* 2026-08-09: ドアベルレコードもDevice-nGnRnEからNormal cacheable
         * RAMへ移した -- 4回の個別1バイトstoreを整列済み単一32bit storeへ
         * まとめ(cc24は24bit値のためbyte0は常に0、__builtin_bswap32()で
         * 元の4バイトvolatile書き込みと同一のバイト列になる)、CPU書き込み
         * をHWから見えるようdcache_clean_range()で明示的にPoCまでクリーン
         * する。CQ ドアベルは sq_cq_cc(CQ consumer)で更新する。 */
        volatile uint32_t *cq_dbr_err = (volatile uint32_t *)(uintptr_t)dev->sq_cq_dbr_cpu;
        uint32_t cc24_err = st->sq_cq_cc & 0xFFFFFFu;
        *cq_dbr_err = __builtin_bswap32(cc24_err);
        dcache_clean_range((const void *)cq_dbr_err, sizeof(*cq_dbr_err));

        if (mlx5_net_try_recover(pf_index, dev, st) != 0) {
            return -1;
        }
        return 2;
    }

    /* MTXC: 正常完了1件を刈り取った。argは刈り取り直後のsq_pc/sq_cc
     * (sq_ccはまだインクリメント前の値)。 */
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_reap_one, 1),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    /* MHTC: 方針1(CLAUDE.md「MTXC/MRXF待ち改善の検討方針」節)。前回の
     * SQ完了CQEからのHW-domain delta(ns、ConnectXのフリーランニング
     * クロック基準)。argはSW側のポーリング粒度に一切左右されない --
     * MTXC同士のtick delta(SW-domain)と比較することで、MTXC waitの
     * 実体がHW処理時間なのかポーリング遅延なのかを切り分けられる。 */
    mlx5_net_log_hw_ts_delta(dev, mlx5_cqe_hw_ts_cycles(cqe),
                              &st->last_tx_hw_ts_cycles, &st->has_last_tx_hw_ts,
                              TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_reap_one, 2));

    st->sq_cq_cc++;   // CQ consumer(復帰でリセットしない)
    st->sq_cc++;      // SQ占有量(正常時は sq_cq_cc と歩調が揃う)

    // SQ用CQのドアベル(consumer counter)も更新しておく -- RQ側と同じ
    // 理由(mlx5_cqwq_update_db_record()と同じ式)。2026-08-09: 上記
    // エラー分岐と同じくキャッシュ可能RAM+単一32bit store化。CQ ドアベルは
    // sq_cq_cc(CQ consumer)で更新する。
    volatile uint32_t *cq_dbr = (volatile uint32_t *)(uintptr_t)dev->sq_cq_dbr_cpu;
    uint32_t cc24 = st->sq_cq_cc & 0xFFFFFFu;
    *cq_dbr = __builtin_bswap32(cc24);
    dcache_clean_range((const void *)cq_dbr, sizeof(*cq_dbr));

    return 1;
}

// 次のWQE(st->sq_pc)をポストできるだけの空きがSQリングにできるまで待つ
// (st->sq_pc - st->sq_cc < MLX5_SQ_WQE_COUNT)。空きが無ければ
// mlx5_net_sq_reap_one()で到着済みの完了を刈り取りながら再確認する
// (eth.cのeth_tx_wait_slot()と同じバックプレッシャの考え方 -- パイプ
// ライン化された非同期送信で複数WQEが未完了のまま連続ポストされている
// 状況では、この待ちが実際に発生する)。
// 戻り値: 0=空きあり(またはできた)、-1=タイムアウト/エラーで諦めた
// (s_sq_halted[]が立った可能性がある)。
static int mlx5_net_sq_wait_room(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    /* 【2026-08-09、実機で発見した本物のバグの修正】以前はこの関数の
     * while条件(pc-cc>=COUNT)が満たされたときだけmlx5_net_sq_reap_one()
     * を呼んでいた -- つまりSQリング(16スロット)が実質的に一杯になる
     * まで、到着済みの完了(CQE)を一切刈り取らない設計だった。しかし
     * `tcploopbench`の実機テストで、TCPが1〜2セグメント送っただけで
     * (pc-ccの差はせいぜい数個)延々とACKが来ず全滅する事象が発生し、
     * `mlx5netdump`でCQリングを直接確認したところ、sq_ccが指す位置に
     * まさに正常な完了(op_own=0x00、opcode=REQ、エラーではない)が
     * 到着済みのまま放置されていることを確認した -- つまり完了はHW側で
     * 正しく生成され続けていたのに、ソフトウェア側が「リングが一杯に
     * なるまで見に行かない」設計のせいで、それを一切刈り取らないまま
     * st->sq_ccが凍結し続けていた。
     *
     * 修正: 毎回の呼び出しで、まず到着済みの完了を非ブロッキングで
     * 全て刈り取ってから(この時点でリングに空きが無ければ)本来の
     * 空き待ちループへ進む -- RP1のeth_tx_wait_slot()が記述子の
     * TX_USEDビットを都度直接読むのと違い、mlx5は完了専用のCQを
     * 経由するため、この能動的な刈り取りが無いと完了がCQに溜まった
     * まま気づかれない(CLAUDE.md「NVMe/TCP write性能低下の真因確定」
     * 節等、このプロジェクトで繰り返し確認してきた「実測せよ」の
     * 教訓通り、`mlx5netdump`の生データが直接の決め手になった)。 */
    for (;;) {
        int r = mlx5_net_sq_reap_one(pf_index, dev, st);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            break;
        }
    }

    uint64_t start = timer_now();
    while ((st->sq_pc - st->sq_cc) >= MLX5_SQ_WQE_COUNT) {
        int r = mlx5_net_sq_reap_one(pf_index, dev, st);
        if (r < 0) {
            return -1;
        }
        if (r != 0) {
            continue; // 刈り取れた(または復帰でpc/ccが0/0にリセットされ、条件は自然に満たされる) -- 直ちに再確認
        }
        if (timeout_ms(start, 1000u)) { // 1秒(eth.cのeth_tx_wait_slot()と同じ)
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_wait_room, 0),
                   ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
            uart_printf("[mlx5net] TXリング枠待ちタイムアウト (sqn=%u sq_pc=%u sq_cc=%u)\n",
                        dev->sqn, st->sq_pc, st->sq_cc);
            mlx5_net_try_recover(pf_index, dev, st);
            return -1;
        }
    }
    return 0;
}

// nic_ops_t.send_frags_async()の実体 -- WQEをポストしたら、ハードウェアの
// 送信完了(CQE)を待たずに即座に返る(RP1のeth_send_frags_async()と同じ
// 考え方、CLAUDE.md「性能分析基盤の整備」節参照)。SQリングに空きが無い
// 場合のみ、空きが出るまでmlx5_net_sq_wait_room()でブロックする。
static int mlx5_net_send_frags_async(void *priv, const eth_frag_t *frags, unsigned frag_count)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    /* 既にこのSQでTXタイムアウトを検出し、詳細診断を採取済み(下記参照)
     * -- 以後は新規WQEポスト・1秒待ちを行わず即座に失敗を返す。 */
    if (s_sq_halted[pf_index]) {
        return -1;
    }
    /* MTXW: mlx5_net_sq_wait_room()呼び出し直前(2026-08-09、MTXS/MRXF
     * 待ちの追加調査)。MTXW→MTXSのdeltaが、SQリング空き待ち+到着済み
     * CQEの能動的刈り取りだけのコストを表す(SCPY/SDCC=tcp.c側のコピー/
     * キャッシュクリーンとは別)。 */
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags_async, 0),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
    if (mlx5_net_sq_wait_room(pf_index, dev, st) != 0) {
        return -1;
    }

    /* MTXS: WQEポスト直前のsq_pc/sq_cc(2026-08-08、ユーザー指示のcore1
     * オフロード調査で追加) -- 「WQEをポストできたか」と「その完了(CQE)
     * を実際に刈り取れたか」を切り分けるための計装。真の非同期送信では
     * ポスト後に完了を待たないため、このタグの直後に対応するMTXCが
     * 現れるとは限らない(複数のMTXSの後にまとめてMTXCが現れるのが、
     * パイプライン化された送信の正常な姿)。 */
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags_async, 1),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    return mlx5_net_post_frame(st, frags, frag_count);
}

// nic_ops_t.send_frags()の実体 -- send_frags_async()と同じくWQEをポスト
// するが、加えて自分がポストしたWQEの完了(CQE)まで明示的に待ってから
// 返る(ARP/ICMP等、送信成否をその場で確認したい呼び出し元向け)。
static int mlx5_net_send_frags(void *priv, const eth_frag_t *frags, unsigned frag_count)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    if (s_sq_halted[pf_index]) {
        return -1;
    }
    if (mlx5_net_sq_wait_room(pf_index, dev, st) != 0) {
        return -1;
    }

    uint32_t target_pc = st->sq_pc; // このWQEに割り当てられるpc(post後はst->sq_pcが+1される)

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags, 0),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    if (mlx5_net_post_frame(st, frags, frag_count) != 0) {
        return -1;
    }

    // 自分がポストしたWQE(target_pc)の完了(sq_cc > target_pc)まで待つ。
    uint64_t start = timer_now();
    while ((int32_t)(st->sq_cc - (target_pc + 1u)) < 0) {
        int r = mlx5_net_sq_reap_one(pf_index, dev, st);
        if (r < 0) {
            return -1;
        }
        if (r == 2) {
            // このSQは自動復帰でpc/ccが共に0へリセットされた -- 自分が
            // ポストしたWQE(target_pc)はもはや存在せず、完了を待つ対象が
            // 消滅した。送信は失敗として扱う(呼び出し元の上位層の再送に
            // 委ねる、ARP/ICMPともに再試行前提の設計のため安全)。
            return -1;
        }
        if (r == 1) {
            continue;
        }
        if (timeout_ms(start, 1000u)) { // 1秒(eth.cのrp1_send_frags()と同じ)
            /* MTXT: CQE刈り取りタイムアウト(1秒経過してもCQEが来ない)。
             * argはタイムアウト時点のsq_pc/sq_cc(MTXSと同じ形式) --
             * sq_pcがMTXS時点から進んでいなければWQEポスト自体が何らかの
             * 理由で反映されていない可能性、進んでいれば「ポストはできて
             * いるが完了が返ってこない」ことを示す。 */
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags, 1),
                   ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
            uart_printf("[mlx5net] TXタイムアウト (sqn=%u)\n", dev->sqn);
            mlx5_net_try_recover(pf_index, dev, st);
            return -1;
        }
    }
    return 0;
}

// nic_ops_t.send_lso()の実体(netif.hのnic_ops_t.send_lso参照、RP1側は
// NULL)。mlx5_net_send_frags_async()と同じ非同期パイプライン方式
// (SQリングに空きが無い時だけmlx5_net_sq_wait_room()で待つ、完了[CQE]は
// 待たない)。呼び出し元(tcp.cのtcp_send_segment_lso())はこのWQE1個で
// 複数MSS分のデータを送ったことになるが、SQリング上は依然として1論理
// WQE(=1エントリ)として扱われる。
static int mlx5_net_send_lso_async(void *priv, const void *hdr, uint16_t hdr_len,
                                    const void *payload, uint32_t payload_len, uint16_t mss)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    if (s_sq_halted[pf_index]) {
        return -1;
    }
    if (payload_len == 0u || payload_len > dev->max_lso_bytes) {
        return -1;
    }

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_lso_async, 0),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
    if (mlx5_net_sq_wait_room(pf_index, dev, st) != 0) {
        return -1;
    }

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_lso_async, 1),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    return mlx5_net_post_lso_frame(st, hdr, hdr_len, payload, payload_len, mss);
}

// mlx5.hのmlx5_net_dump_sq_debug()コメント参照。読み取り専用、HCAコマンド
// インターフェースには一切触れない(生のDMAメモリを読むだけ)ので、SQが
// TXタイムアウトで詰まった状態でも安全に呼べる。
void mlx5_net_dump_sq_debug(int pf_index)
{
    mlx5_net_state_t *st = (pf_index == 0) ? &s_state_pf0 : &s_state_pf1;
    mlx5_dev_t *dev = st->dev;
    if (!dev) {
        uart_printf("[mlx5netdbg] PF%d: 未初期化(dev==NULL)\n", pf_index);
        return;
    }

    uint64_t cq_buf   = (uint64_t)dev->sq_cq_buf_cpu;
    uint64_t wqe_ring = (uint64_t)dev->sq_wqe_cpu;

    uart_printf("[mlx5netdbg] PF%d: sqn=%u sq_cqn=%u sq_wqe_cpu=0x%08x%08x\n",
                pf_index, dev->sqn, dev->sq_cqn,
                (uint32_t)((uint64_t)dev->sq_wqe_cpu >> 32), (uint32_t)(uint64_t)dev->sq_wqe_cpu);
    uart_printf("[mlx5netdbg] PF%d: sq_pc=%u sq_cc=%u (diff=%d)\n",
                pf_index, st->sq_pc, st->sq_cc, (int)(st->sq_pc - st->sq_cc));
    uart_printf("[mlx5netdbg] PF%d: cq_buf=0x%08x%08x wqe_ring=0x%08x%08x\n",
                pf_index, (uint32_t)(cq_buf >> 32), (uint32_t)cq_buf,
                (uint32_t)(wqe_ring >> 32), (uint32_t)wqe_ring);

    // sq_cc周辺(1つ前〜3つ先)のCQEの生バイト(op_own/wqe_counter/byte_cnt)。
    // ソフトウェアが「ここを待っている」位置(sq_cc)と、その前後に実際に
    // 何が書かれているか(owner bitの状態、opcode、対応するWQE番号)を見る。
    for (int delta = -1; delta <= 3; delta++) {
        uint32_t idx = (uint32_t)((int64_t)(st->sq_cc & (MLX5_NET_CQ_NUM_ENTRIES - 1u)) + delta) &
                       (MLX5_NET_CQ_NUM_ENTRIES - 1u);
        volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf + (uint64_t)idx * MLX5_NET_CQE_SIZE);
        // 2026-08-09: cq_bufがキャッシュ可能RAMになったため、読む前に
        // invalidateしないとCPUキャッシュの古い値を見てしまう(診断用
        // ダンプなので、ホットパスと違い1回のコスト増は無視できる)。
        dcache_invalidate_range((const void *)cqe, MLX5_NET_CQE_SIZE);
        uint8_t  op_own       = cqe[MLX5_CQE_OFF_OP_OWN];
        uint16_t wqe_counter  = (uint16_t)(((uint16_t)cqe[MLX5_CQE_OFF_WQE_COUNTER] << 8) |
                                            cqe[MLX5_CQE_OFF_WQE_COUNTER + 1]);
        uint32_t byte_cnt     = ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT] << 24) |
                                 ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 1] << 16) |
                                 ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 2] << 8) |
                                 cqe[MLX5_CQE_OFF_BYTE_CNT + 3];
        uart_printf("  CQ[%u]%s op_own=0x%02x(owner=%u opcode=0x%x) wqe_counter=%u byte_cnt=%u\n",
                    idx, (delta == 0) ? " <-sq_cc" : "",
                    op_own, (unsigned)(op_own & MLX5_CQE_OWNER_MASK), (unsigned)(op_own >> 4),
                    wqe_counter, byte_cnt);
    }

    // WQEリング全エントリ(MLX5_SQ_WQE_COUNT個、「偶数アライン方式」
    // により各2 WQEBB間隔)の先頭8バイト(opmod_idx_opcode/qpn_ds) --
    // mlx5_net_post_frame()が書き込む値。ds_cntは4(単一data_seg、
    // frag_count==1)または5(2 data_seg、frag_count==2)のいずれかが
    // 正常値(2026-08-09、ゼロコピー2フラグメント対応)。opmod_idx_
    // opcodeのpcフィールドはHW視点のWQEBBインデックス(論理エントリ
    // 番号の2倍)であることに注意。
    for (uint32_t i = 0; i < MLX5_SQ_WQE_COUNT; i++) {
        volatile uint8_t *w = (volatile uint8_t *)(uintptr_t)(wqe_ring + (uint64_t)i * 2u * MLX5_SEND_WQE_BB);
        uint32_t opmod = ((uint32_t)w[0] << 24) | ((uint32_t)w[1] << 16) | ((uint32_t)w[2] << 8) | w[3];
        uint32_t qpnds = ((uint32_t)w[4] << 24) | ((uint32_t)w[5] << 16) | ((uint32_t)w[6] << 8) | w[7];
        uint32_t pc_for_slot = (opmod >> 8);
        uart_printf("  WQE[%2u] opmod_idx_opcode=0x%08x(pc=%u opcode=0x%02x) qpn_ds=0x%08x(ds_cnt=%u)\n",
                    i, opmod, pc_for_slot, (unsigned)(opmod & 0xFFu), qpnds, (unsigned)(qpnds & 0xFFu));
    }
}

// タイムアウト/エラーCQE検出時の共通復帰ロジック(2026-08-08、ユーザー
// 指示で再導入)。サーキットブレーカーの範囲内であればmlx5_recover_sq()
// (mlx5.h、QUERY_SQ→ERR確認→ERR→RST→RDY遷移)を1回試みる。成功すれば
// st->sq_pc/sq_cc をCREATE_SQ直後と同じ初期状態(0/0)へ揃えて0を返す
// (ERR→RST遷移でHW側のWQE/CQE内部カウンタもクリアされる想定 -- 実機で
// 検証すること、もし食い違うようならCQ自体の再作成やproducer_counter
// 読み取りによる調整を検討する)。失敗、またはサーキットブレーカー発動時は
// s_sq_halted[]を立てて-1を返す -- 重い診断(mlx5_net_dump_sq_debug()/
// mlx5_monitor_dump_saved())はこの「本当に諦める」経路でのみ採取する
// (毎回の軽いリトライでは呼ばない、ログ出力量を抑えるため)。
// 2026-08-15、core-split の SQ recovery バグ修正。ERR->RST->RDY で SQ を 0 起点に
// リセットする「前」に、CQ に溜まった全ての完了(エラー本体+残り outstanding WQE の
// flush-error CQE)を消費し切り、sq_cq_cc を HW の CQ producer 位置(hw_cq_pi)まで
// 追いつかせる。これをやらずに sq_pc/sq_cc を 0 に戻すと、CQ に残った古い CQE が後で
// 刈り取られ sq_cc を pc より先へ進めて占有量が underflow し「永久に満杯」になる
// (実機ログ sq_pc=0 sq_cc=908 の正体)。Linux mlx5e の mlx5e_wait_for_sq_flush()
// +NAPI ドレイン相当。ERR->RST->RDY 後(SQ は空・新規ポスト無し=hw_cq_pi 凍結)に
// 呼ぶので、見えるのは古い flush CQE だけ。owner-bit プロトコルにより sq_cq_cc が
// hw_cq_pi に達した時点で cqe_if_ready が NULL を返しドレインは自然終了する。
static void mlx5_net_drain_sq_cq(mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    uint64_t cq_buf = (uint64_t)dev->sq_cq_buf_cpu;
    volatile uint32_t *cq_dbr = (volatile uint32_t *)(uintptr_t)dev->sq_cq_dbr_cpu;
    uint64_t idle_start = timer_now();
    unsigned drained = 0;
    for (;;) {
        volatile uint8_t *cqe = mlx5_net_cqe_if_ready(cq_buf, st->sq_cq_cc);
        if (cqe) {
            st->sq_cq_cc++;   // CQ consumer のみ進める(sq_cc は直後に 0 リセットするので触らない)
            *cq_dbr = __builtin_bswap32(st->sq_cq_cc & 0xFFFFFFu);
            dcache_clean_range((const void *)cq_dbr, sizeof(*cq_dbr));
            drained++;
            idle_start = timer_now();
        } else if (timeout_ms(idle_start, 50u)) {
            // 50ms 何も来なければ flush 完了とみなす(残る WQE は SQ リセットで破棄済み)
            break;
        }
    }
    uart_printf("[mlx5net] SQ復帰: CQを%uエントリ drainし sq_cq_cc=%u へ同期\n",
                drained, st->sq_cq_cc);
}

static int mlx5_net_try_recover(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    if (timeout_ms(s_recover_window_start[pf_index], MLX5_NET_SQ_RECOVER_WINDOW_MS)) {
        s_recover_window_start[pf_index] = timer_now();
        s_recover_attempts[pf_index] = 0;
    }

    /* 2026-08-15、進捗ベースのサーキットブレーカー。旧来は「10秒以内に3回」で
     * 永久 halt していたが、(1) recovery を正しく修正した(sq_cq_cc 分離+drain、
     * ハングしない)、(2) LOCAL_QP_OP_ERR は FW 14.32.1900 で発生頻度が激減したが
     * 稀に残る一過性の HW/FW 事象(Linux mlx5e も devlink health reporter で SQ
     * リセット回復する既知の条件)であることが判明した。したがって「稀な一過性
     * エラーのたびに SQ を正しくリセットして継続する」のが正しい応答であり、
     * 数回で永久 halt するのは過剰。前回の復帰以降に SQ が十分な数の WQE を正常に
     * 送信できていれば(=一過性エラーで、その後健全に稼働した)、試行回数を 0 へ
     * リセットする。真に詰まったループ(復帰→即エラーで WQE がほとんど進まない)
     * だけが試行を累積して halt に至る。sq_cq_cc は復帰でリセットされない単調増加の
     * CQ consumer なので、健全稼働の指標として使える。 */
    if (st->sq_cq_cc - s_recover_last_cq_cc[pf_index] >= MLX5_NET_SQ_RECOVER_PROGRESS_WQES) {
        s_recover_attempts[pf_index] = 0;
    }
    s_recover_last_cq_cc[pf_index] = st->sq_cq_cc;

    /* 2026-08-08、ユーザー指示(根本原因調査): 今回のウィンドウで最初の
     * 検出時点で、自コアの直近tsログを凍結保存する(ts_log_freeze()は
     * 呼び出し時点で実行中のコアのリングバッファのみを保存する設計 --
     * mlx5_net_send_frags()はPF0=core0/PF1=core1からしか呼ばれないため、
     * これでPF0側/PF1側それぞれの直近文脈が個別に残る。両コアの記録は
     * timer_now()由来の絶対tick値を共有しているため、後から`ts core 0
     * frozen`/`ts core 1 frozen`を突き合わせれば、PF0/PF1が実際にどれだけ
     * 近接したタイミングで送信していたか[core分離特有の競合の有無]を
     * 時系列で確認できる。 */
    if (s_recover_attempts[pf_index] == 0) {
        ts_log_freeze();
    }

    if ((uint32_t)s_recover_attempts[pf_index] >= MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS) {
        uart_printf("[mlx5net] PF%d(sqn=%u): 直近%us間に%u回の自動復帰を試みたため、"
                    "これ以上は諦めます(サーキットブレーカー発動)\n",
                    pf_index, dev->sqn, MLX5_NET_SQ_RECOVER_WINDOW_MS / 1000u,
                    (unsigned)s_recover_attempts[pf_index]);
        s_sq_halted[pf_index] = 1;
        mlx5_net_dump_sq_debug(pf_index);
        mlx5_monitor_dump_saved();
        return -1;
    }

    s_recover_attempts[pf_index]++;
    ts_log(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_try_recover, 0), ((uint32_t)pf_index << 24) | (uint32_t)s_recover_attempts[pf_index]);
    uart_printf("[mlx5net] PF%d(sqn=%u): SQ自動復帰を試みます (%u/%u回目)\n",
                pf_index, dev->sqn, (unsigned)s_recover_attempts[pf_index],
                MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS);
    int rc = mlx5_recover_sq(dev);
    if (rc < 0) {
        uart_printf("[mlx5net] PF%d(sqn=%u): SQ自動復帰に失敗しました\n", pf_index, dev->sqn);
        s_sq_halted[pf_index] = 1;
        mlx5_net_dump_sq_debug(pf_index);
        mlx5_monitor_dump_saved();
        return -1;
    }

    if (rc == 1) {
        /* 2026-08-15、core-split で発見・修正: SQ は RDY のまま(エラーでは
         * なく完了が遅くタイムアウトが誤発火しただけ)。ハードは一切リセット
         * されていないので、ソフトの sq_pc/sq_cc を触ってはならない(触ると
         * desync して永久破壊)。カウンタはそのまま、この試行を無かったことに
         * (attempts を戻す)して wait_room の再試行に任せる -- 完了はいずれ
         * 到着し、reap で sq_cc が進めば自然に枠が空く。 */
        s_recover_attempts[pf_index]--;
        return 0;
    }

    /* rc == 0: 実際に ERR->RST->RDY でリセットした -- ハード SQ の WQE index は
     * 0 起点に戻る(Linux mlx5e_reset_txqsq_cc_pc と同じ、SQ doorbell も sq_pc
     * ベースなので pc=0 で正しく再開できる)。ただし CQ は再作成されず HW の CQ
     * producer 位置は継続するため、まず CQ に残った全完了(エラー本体+flush CQE)を
     * drain して sq_cq_cc を hw_cq_pi まで追いつかせてから、SQ 占有量カウンタ
     * (sq_pc/sq_cc)だけを 0 へ揃える。sq_cq_cc は絶対にリセットしない。 */
    mlx5_net_drain_sq_cq(dev, st);
    st->sq_pc = 0;
    st->sq_cc = 0;
    uart_printf("[mlx5net] PF%d(sqn=%u): SQ自動復帰成功、送信を再試行します\n", pf_index, dev->sqn);
    return 0;
}

// nic_ops_t.tx_wait_free_slot()の実体。2026-08-09、ゼロコピー化に伴い
// 「常に0を返す」スタブから、RP1のrp1_tx_wait_free_slot()と実質同じ意味を
// 持つ実装へ変更した -- mlx5_net_post_frame()は(frag_count==1かつ60バイト
// 以上の高速経路で)呼び出し元のバッファをコピーせず、WQEのデータ
// セグメントから直接参照するようになったため、そのスロット(pc %
// MLX5_SQ_WQE_COUNT)に対応する前回のWQEがハードウェアの処理を終える
// (CQEが返る)まで、呼び出し元は同じ物理バッファへ新しいデータを
// 書き込んではならない -- mlx5_net_sq_wait_room()(mlx5_net_send_frags_
// async()が内部でも呼ぶのと同じ関数)でこの完了を待ってから、次に使われる
// スロット番号を返す。
//
// s_seg_bufs[core][slot](tcp.c)はETH_TX_RING_SIZE(eth.h、256)個確保
// されているが、mlx5自身のWQEリング(MLX5_SQ_WQE_COUNT=16)より深い分は
// 単に未使用のまま -- 16<=256なので返す値は常に有効なインデックスになる
// (下記_Static_assert参照)。
static unsigned mlx5_net_tx_wait_free_slot(void *priv)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    if (!s_sq_halted[pf_index]) {
        mlx5_net_sq_wait_room(pf_index, dev, st); // 失敗時もベストエフォートでスロット番号だけ返す(直後のsend_frags_async()が改めてエラーを返す)
    }
    return (unsigned)(st->sq_pc % MLX5_SQ_WQE_COUNT);
}

// ============================================================================
// 受信
// ============================================================================

/* 受信ゼロコピー(net_buf.h参照): 前回までに消費したが再武装を遅延していた
 * RQ WQE(それらのnet_bufは呼び出し元が既にdispatch+free済み)を、まとめて
 * RQドアベルへ反映する。poll_recv()冒頭で呼ぶ。 */
static inline void mlx5_net_rq_write_dbr(mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    volatile uint8_t *rq_dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->rxq[0].dbr_cpu;
    rq_dbr[0] = (uint8_t)(st->rq_posted_ctr >> 24);
    rq_dbr[1] = (uint8_t)(st->rq_posted_ctr >> 16);
    rq_dbr[2] = (uint8_t)(st->rq_posted_ctr >> 8);
    rq_dbr[3] = (uint8_t)st->rq_posted_ctr;
}

static inline void mlx5_net_rq_flush_rearm(mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    if (st->rq_rearm_pending == 0u) {
        return;
    }
    st->rq_posted_ctr += st->rq_rearm_pending;
    st->rq_rearm_pending = 0u;
    mlx5_net_rq_write_dbr(dev, st);
}

static net_buf_t *mlx5_net_poll_recv(void *priv)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;

    /* 受信ゼロコピー: 前回のpoll_recv()が返したnet_buf(RQバッファを直接指す)は
     * 呼び出し元が既にdispatch+free済みなので、そのバッファをここで再武装する。 */
    mlx5_net_rq_flush_rearm(dev, st);

    uint64_t cq_buf = (uint64_t)dev->rxq[0].cq_buf_cpu;
    volatile uint8_t *cqe = mlx5_net_cqe_if_ready(cq_buf, st->rq_cc);
    if (!cqe) {
        return NULL;
    }

    uint8_t opcode = (uint8_t)(cqe[MLX5_CQE_OFF_OP_OWN] >> 4);
    uint32_t byte_cnt = ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT] << 24) |
                        ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 1] << 16) |
                        ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 2] << 8) |
                         (uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 3];
    uint16_t wqe_idx = (uint16_t)(((uint16_t)cqe[MLX5_CQE_OFF_WQE_COUNTER] << 8) |
                                    cqe[MLX5_CQE_OFF_WQE_COUNTER + 1]);
    uint8_t hds_ip_ext = cqe[MLX5_CQE_OFF_HDS_IP_EXT];
    int csum_ok = ((hds_ip_ext & MLX5_CQE_L3_OK) != 0) && ((hds_ip_ext & MLX5_CQE_L4_OK) != 0);

    st->rq_cc++;

    /* wqe_idxは実機観測で256(MLX5_RQ_NUM_WQES)を超える値
     * (連続テストを重ねた後、281,282,...のように)を報告することを
     * 確認した -- HWが返すこのフィールドはリングサイズで折り返し
     * 済みではなく、生の累積カウンタである可能性が高い(mlx5世代/
     * 実装依存)。RQは256個の物理バッファをラウンドロビンで再利用する
     * 設計(mlx5_create_rq()コメント参照)なので、実際にDMAされた
     * 物理バッファを指すにはソフトウェア側でリングサイズの剰余を
     * 取る必要がある -- 剰余を取らずに`wqe_idx < MLX5_RQ_NUM_WQES`
     * で単純に範囲外として破棄すると、256回を超えて受信した以降の
     * 全フレームが常に破棄され続けてしまう(実機で確認したバグ)。 */
    uint16_t buf_idx = (uint16_t)(wqe_idx % MLX5_RQ_NUM_WQES);

    // RX段階別コスト計測(2026-08-09、TX側SSLT/SCKS/MTXS/MTXCと同じ手法)。
    // MRXF: CQE発見直後(argはbyte_cnt)。以後MRXI(invalidate完了)→
    // MRXC(コピー完了)→MRXQ(CQドアベル更新完了)→MRXD(RQ再武装完了、関数末尾)
    // の4区間deltaで、どの段階が支配的コストかを切り分ける。
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 0), byte_cnt);

    /* MHRF: 方針1(CLAUDE.md「MTXC/MRXF待ち改善の検討方針」節)。前回の
     * RQ到着CQEからのHW-domain delta(ns) -- MRXF同士のtick delta
     * (SW-domain)と比較する。 */
    mlx5_net_log_hw_ts_delta(dev, mlx5_cqe_hw_ts_cycles(cqe),
                              &st->last_rx_hw_ts_cycles, &st->has_last_rx_hw_ts,
                              TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 1));

    net_buf_t *out = NULL;
    if (opcode != MLX5_CQE_OP_INVALID && byte_cnt > 0u && byte_cnt <= NET_BUF_SIZE) {
        out = net_buf_alloc();
        if (out) {
            // ring_nb/out共にnet_buf_t/mlx5専用DMA領域内バッファのため
            // アライメントが保証されており、volatile_fast_copy()の
            // ワイドアクセス経路に乗る(eth.cのrp1_poll_recv()と同じ)。
            // 2026-08-09: RQ DMA先バッファをNormal cacheable RAM
            // (MLX5_RQ_DATA_CACHE_ADDR)へ移した(mlx5.hコメント参照)ため、
            // CPUが読む前に明示的なキャッシュinvalidateが必要
            // (dcache_invalidate_range()、cache.h)-- 怠るとDMA前の古い
            // キャッシュ内容を読んでしまう恐れがある。
            // RX headroom(mlx5.hのMLX5_RX_HEADROOM参照): CREATE_RQで
            // NICはフレームをスロット先頭+HEADROOMへ書いているので、CPU側の
            // 参照ポインタも同じだけずらす。これでフレーム先頭が(8整列
            // スロット+2)=2 mod 8となり、TCPペイロード(+54)が8整列に乗る。
            volatile uint8_t *src = (volatile uint8_t *)(uintptr_t)
                ((uint64_t)dev->rxq[0].data_cpu + (uint64_t)buf_idx * MLX5_RQ_BUF_PER_WQE
                 + MLX5_RX_HEADROOM);
            dcache_invalidate_range((const void *)src, byte_cnt);
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 2), byte_cnt);
            /* 受信ゼロコピー(2026-08-13、CLAUDE.md「受信ゼロコピー」節): 従来は
             * ここで src(RQ DMAバッファ)→out->data(net_buf storage)へ丸ごと
             * コピー(コピー1、実測約2.2us/フレーム)していたが、out->dataを
             * srcへ直接向けてコピーを省く。dcache_invalidate_range()済みなので
             * 後段のeth_dispatch/tcp_inputはこのRQバッファを直接読める。このRQ
             * バッファ(buf_idx)は、outがdispatch+freeされる次回poll_recv()冒頭の
             * mlx5_net_rq_flush_rearm()まで再武装しない(下記rq_rearm_pending)。 */
            out->data = (uint8_t *)(uintptr_t)src;
            out->len = (uint16_t)byte_cnt;
            // 2026-08-09、ハードウェアチェックサムオフロード対応
            // (net_buf.h/eth.hコメント参照)。IPv4以外(ARP等)のフレームは
            // hds_ip_extがそもそも意味を持たない(HWがL3/L4ヘッダを認識
            // できていない)ため、CQE_L3_OK/L4_OKが自然に立たず、ip.c側は
            // 元々IPv4以外を経由しないので実害は無い。
            out->hw_csum_ok = (uint8_t)csum_ok;
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 3), byte_cnt);
        } else {
            uart_printf("[mlx5net] poll: net_bufプール枯渇、フレーム破棄\n");
        }
    } else if (opcode != MLX5_CQE_OP_INVALID) {
        uart_printf("[mlx5net] poll: 想定外のCQE (opcode=0x%x byte_cnt=%u wqe_idx=%u) 破棄\n",
                    opcode, byte_cnt, wqe_idx);
    }

    // CQドアベル(consumer counter)を更新する -- HWがこのスロットへ新しい
    // 完了を書き込めるようになる。2026-08-09: SQ側と同じくキャッシュ
    // 可能RAM+単一32bit store化。
    {
        volatile uint32_t *cq_dbr = (volatile uint32_t *)(uintptr_t)dev->rxq[0].cq_dbr_cpu;
        uint32_t cc24 = st->rq_cc & 0xFFFFFFu;
        *cq_dbr = __builtin_bswap32(cc24);
        dcache_clean_range((const void *)cq_dbr, sizeof(*cq_dbr));
    }
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 4), byte_cnt);

    // RQを再武装する: このスロットのバッファ内容は元々「net_bufへコピー
    // 済み」ならこの場で即再武装できたが、受信ゼロコピー(2026-08-13、
    // net_buf.h参照)ではnet_buf(out)がこのRQバッファ(buf_idx)を*直接指す*
    // ため、outがdispatch+freeされるまで再武装できない。1フレーム遅延させ、
    // 次回poll_recv()冒頭のmlx5_net_rq_flush_rearm()でまとめて再武装する
    // (バッチループはoutをdispatch+freeしてから次のpoll_recv()を呼ぶ、
    // net_poll_all_and_dispatch()参照)。ここではpendingを1増やすだけ
    // (out==NULLでフレームをドロップした場合も、そのバッファは誰も保持して
    // いないが1フレーム遅れて再武装されるだけで無害)。
    // WQE自体の書き直しは不要で、ドアベルの「投稿済みWQE数」カウンタを進める
    // だけでHWに再利用を許可できる(mlx5_wq_cyc_update_db_record()と同じ規約、
    // mlx5.cのmlx5_create_rq()コメント「実機で発見した本物のバグ」参照)。
    st->rq_rearm_pending++;
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 5), byte_cnt);

    return out;
}

// ============================================================================
// ブリングアップ
// ============================================================================

static const nic_ops_t s_mlx5_net_ops = {
    .send_frags        = mlx5_net_send_frags,
    .send_frags_async  = mlx5_net_send_frags_async,
    .send_lso          = mlx5_net_send_lso_async, // 2026-08-10、LSO対応(RP1側はNULLのまま)
    .tx_wait_free_slot = mlx5_net_tx_wait_free_slot,
    .poll_recv         = mlx5_net_poll_recv,
};

static void mlx5_netif_setup(netif_t *ctx, mlx5_net_state_t *st, mlx5_dev_t *dev,
                                const char *name, uint32_t ip, uint8_t mac_low_octet)
{
    ctx->name = name;
    // ローカル管理アドレス(RP1のeth_get_mac()と同じ規約、eth.cのRP1_MAC
    // 参照) -- ConnectX側はフローステアリングがcatch-all(宛先MAC等を
    // 一切見ない、mlx5.cのmlx5_create_flow_group_catchall()参照)なので、
    // このMAC値をHWへ設定する必要は無く、純粋にソフトウェア上の識別子。
    ctx->mac[0] = 0x02; ctx->mac[1] = 0x00; ctx->mac[2] = 0x00;
    ctx->mac[3] = 0x00; ctx->mac[4] = 0x10; ctx->mac[5] = mac_low_octet;
    ctx->ip = ip;
    ctx->nic = &s_mlx5_net_ops;
    ctx->nic_priv = st;
    // 2026-08-09、ジャンボフレーム対応: RQバッファ/送信ステージング
    // バッファを共にMLX5_JUMBO_MAX_LEN(10240、mlx5.hのMLX5_RQ_BUF_PER_WQE/
    // MLX5_NET_TX_STAGE_SIZE参照)へ拡張したが、mss_capは`dev->port_mtu`
    // (mlx5_hca_bringup()がPMTUレジスタへ実際に設定できた値、mlx5.hの
    // mlx5_dev_t.port_mtuコメント参照)から逆算する -- 固定でTCP_MSS_
    // LOCAL(10182)相当を決め打ちすると、実機のHW上限(max_mtu、本ソフト
    // では実測10000)がMLX5_JUMBO_MAX_LENより小さい場合に、実際のワイヤ
    // 上限を超えるTCPセグメントを送ってしまう恐れがある。
    // 計算式: 当初`port_mtu - ETH_HDR_LEN(14) - IPヘッダ(20) - TCPヘッダ
    // (20)`(=port_mtu-54)としていたが、実機の`tcploopbench`テストで
    // ちょうどこの上限(admin_mtu=10000のとき総フレーム長=10000ぴったり)
    // のセグメントが「WQEの完了(CQE)は正常に返るのに実際には一切ワイヤへ
    // 出ない」(mlx5statのtx_octets_okが増えない)という、エラーも返らない
    // 静かな送信失敗を起こすことを確認した -- ARP/ICMP等の小さいフレーム
    // (数十バイト)は同じ経路(async送信)で問題なく成功するため、フレーム
    // サイズがadmin_mtuの境界ぴったりに達することが原因と判断した。Linux
    // en.hの`MLX5E_ETH_HARD_MTU`(=ETH_HLEN+VLAN_HLEN+ETH_FCS_LEN=14+4+4=22)
    // は、実際にVLANタグを使わない場合でも常にVLAN分(4B)を予約している
    // ことを示しており、これに倣ってVLAN_HLEN(4)+ETH_FCS_LEN(4)の余裕を
    // 追加で差し引く(port_mtu - 14 - 4 - 4 - 20 - 20 = port_mtu - 62)。
    // これによりフレーム長が常にadmin_mtuより真に小さくなり、実機で
    // このクラスの境界問題を回避できることを確認した。
    // 上限はTCP_MSS_LOCAL(10182、静的バッファの実容量)を超えないように
    // クランプする -- 万一port_mtuがMLX5_JUMBO_MAX_LENと同値以上でも、
    // tcp.cのs_seg_bufs等のバッファ容量を超えて書き込むことはない。
    {
        const uint32_t eth_vlan_fcs_ip_tcp_hdr = 14u + 4u + 4u + 20u + 20u; // = 62
        const uint32_t tcp_mss_local_max = 10182u; // tcp.cのTCP_MSS_LOCALと同値(非公開のため複製)
        uint32_t mss = (dev->port_mtu > eth_vlan_fcs_ip_tcp_hdr) ? (dev->port_mtu - eth_vlan_fcs_ip_tcp_hdr) : 0u;
        if (mss > tcp_mss_local_max) {
            mss = tcp_mss_local_max;
        }
        mss = 9216;
        ctx->mss_cap = (uint16_t)mss;
    }
    // 2026-08-13、writeパイプライン化(netif.hのnetif_t.rx_ring_size
    // コメント参照)。mlx5のRQは256エントリ(MLX5_RQ_NUM_WQES、各
    // MLX5_JUMBO_MAX_LEN=10240バイト)あり、RP1 GEMのETH_RX_RING_SIZE(128)の
    // 2倍の受信フレームを吸収できる。tcp.cのsafe_window_capがこの実容量を
    // 使って広告受信ウィンドウを計算できるよう明示的に設定する -- これにより
    // NVMe/TCP writeの実効パイプライン深度が上がる(従来は128決め打ちで
    // ウィンドウが半分に抑えられdepth~2に制限されていた)。
    ctx->rx_ring_size = (uint16_t)MLX5_RQ_NUM_WQES;
    // 2026-08-09、ハードウェアチェックサムオフロード対応(netif.hの
    // netif_t.hw_csum_offloadコメント参照)。mlx5_net_post_frame()が
    // 常にSQ WQEのcs_flags(L3_CSUM|L4_CSUM)を立てるため、この
    // インターフェース経由の送信は常にHWがIP/TCPチェックサムを計算する。
    ctx->hw_csum_offload = 1;
    // 2026-08-09、TCP送信の真のゼロコピー対応(netif.hのnetif_t.
    // tx_zerocopy_2fragコメント参照)。mlx5_net_post_frame()が
    // frag_count==2の専用経路(2 data_seg構成)を持つため有効化する。
    ctx->tx_zerocopy_2frag = 1;
    // 2026-08-10、LSO対応(netif.hのnetif_t.hw_lso_max_bytesコメント
    // 参照)。mlx5_hca_bringup()がQUERY_HCA_CAP(ETHERNET_OFFLOADS)から
    // 読み取り、MLX5_LSO_MAX_BYTES_CAPでクランプ済みの値をそのまま渡す
    // (0ならHWが非対応、またはクエリ失敗 -- tcp.cはこの場合LSOを使わない)。
    ctx->hw_lso_max_bytes = dev->max_lso_bytes;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) ctx->arp_cache[i].valid = 0;

    st->dev = dev;
    st->rq_cc = 0;
    st->rq_posted_ctr = MLX5_RQ_NUM_WQES; // mlx5_create_rq()が既にこの値でドアベルへ書き込み済み
    st->rq_rearm_pending = 0u;             // 受信ゼロコピーの遅延再武装カウンタ(net init mlx5/再ブリングアップでリセット)
    st->sq_pc = 0;
    st->sq_cc = 0;
    st->sq_cq_cc = 0;   // CQ consumer(setup/再ブリングアップ時は CQ も新規なので 0 起点)
    {
        int pfi = mlx5_net_pf_index(st);
        s_sq_halted[pfi] = 0;
        s_recover_attempts[pfi] = 0;
        s_recover_window_start[pfi] = timer_now();
    }
}

/* x86-vfio-port Phase 5: bring-up 済みの 2 PF を net_ctx として登録する
 * (mlx5_net_init_dual_loopback() の pcie1 bring-up を除いた後半)。x86 は VFIO で
 * bring-up 済みの dev を渡して呼ぶ。mlx5_net の static ctx/state を再利用する
 * (RPi5 の net init mlx5 と x86 は排他運用なので競合しない)。 */
int mlx5_net_register_dual(mlx5_dev_t *dev0, mlx5_dev_t *dev1)
{
    mlx5_netif_setup(&s_ctx_pf0, &s_state_pf0, dev0, "mlx5-pf0",
                        ip_from_octets(192, 168, 101, 10), 0x10);
    mlx5_netif_setup(&s_ctx_pf1, &s_state_pf1, dev1, "mlx5-pf1",
                        ip_from_octets(192, 168, 101, 11), 0x11);
    netif_register(&s_ctx_pf0);
    netif_register(&s_ctx_pf1);
    netif_activate(&s_ctx_pf0);
    mlx5_monitor_set_devs(dev0, dev1);
    uart_printf("[mlx5net] dual registered: pf0=192.168.101.10 pf1=192.168.101.11 (active=pf0)\n");
    return 0;
}
