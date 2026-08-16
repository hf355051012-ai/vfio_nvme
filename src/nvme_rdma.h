#ifndef NVME_RDMA_H
#define NVME_RDMA_H

#include <stdint.h>
#include "mlx5_qp.h"
#include "rdma_cm.h"
#include "job.h"
#include "nvme_types.h"

/* ================================================================
 * nvme_rdma.h -- NVMe-oF RDMAトランスポート、イニシエータ側。
 * ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-
 * lamport.md)フェーズ(g)。既存nvme.c(TCPトランスポート)には一切触れず、
 * 完全に並行する新規実装として追加する(計画5.4節の方針、CLAUDE.md
 * 「ConnectX RoCEv2 NVMe-oF実装計画フェーズ(g)」節参照)。
 *
 * 【スコープの簡略化、重要】既存のDMAレイアウト(mlx5.h)は「1PFあたり
 * RC QP 1本のみ」を前提に設計されている(MLX5_QP_WQE_ADDR(base)等が
 * QPインデックスを取らない固定オフセットで、2本目のRC QPを同一PF上に
 * 作ると物理的に同じWQE/CQ領域を取り合って破壊する)。admin queue/IO
 * queueを別々のRC QP(実NVMe-oF RDMAの標準設計)にするにはこのDMA
 * レイアウト自体の拡張(QPインデックス引数の追加)が必要になり、
 * フェーズ(g)の主目的(SEND capsule + Keyed SGL + RDMA_WRITE/READという
 * データパス自体の実証)に対して不釣り合いに大きい変更になるため、
 * このフェーズでは admin queue と IO queue を単一のRC QPへ統合する
 * (Fabrics Connectをqid=0で一度だけ行い、以後同じQP上でIOコマンドも
 * 発行する -- 複数コマンドの同時outstandingも行わない、単一コマンド
 * ごとの同期的なやり取り)。複数QP対応は将来必要になった時点で、
 * mlx5.hのQPアドレスマクロにインデックス引数を追加する形で拡張する。
 * ================================================================ */

#define NVME_RDMA_MSG_MAX    2048u  /* SEND/RECVメッセージバッファの上限
                                      * (SQE 64B + Connect data 1024Bが最大) */
#define NVME_RDMA_ID_BUF_LEN 4096u  /* Identify Controller/Namespace応答長 */
#define NVME_RDMA_TEST_LEN    512u  /* write/read検証(nvmerdmaconnect)に使うテストデータ長 */

/* フェーズ(h): `nvmermabench`が使うwrite/readバッファの上限(バイト)。
 * RDMAはTCPのR2T/C2HDataのような1コマンドあたりのPDU分割が無く単一の
 * RDMA_WRITE/READ WQEで完結するため、TCP側のような細かいチャンク上限
 * (NVMET_IOCCSZ_MAX_BYTES等)を踏襲する必要は無い -- ターゲットのnamespace
 * 容量(nvmet_rdma.hのNVMET_RDMA_NS_LBA_COUNT=2048×512B=1MB、常にLBA0への
 * 上書き)に収まる範囲で、TCP版ベンチ(CLAUDE.md「NVMe/TCPコマンド
 * パイプライン化」節等)がよく使う256KBスケールに合わせた。 */
#define NVME_RDMA_BENCH_BUF_MAX 262144u

typedef enum {
    NVMER_ST_CM_SPAWN = 0,
    NVMER_ST_CM_WAIT,
    NVMER_ST_SEND_CONNECT,
    NVMER_ST_WAIT_CONNECT,
    NVMER_ST_SEND_PROP_SET_CC,
    NVMER_ST_WAIT_PROP_SET_CC,
    NVMER_ST_SEND_PROP_GET_CSTS,
    NVMER_ST_WAIT_PROP_GET_CSTS,
    NVMER_ST_CSTS_POLL_WAIT,
    NVMER_ST_SEND_ID_CTRL,
    NVMER_ST_WAIT_ID_CTRL,
    NVMER_ST_SEND_ID_NS,
    NVMER_ST_WAIT_ID_NS,
    NVMER_ST_SEND_WRITE,
    NVMER_ST_WAIT_WRITE,
    NVMER_ST_SEND_READ,
    NVMER_ST_WAIT_READ,
    /* コマンドパイプライン化(2026-08-12、ユーザー指示 -- CLAUDE.md
     * 「nvmermabenchのボトルネック切り分け」節参照)。bench_qdepth>1の
     * 場合のみWAIT_ID_NS完了直後にここへ分岐する(既定は単一コマンド
     * 逐次処理[SEND_WRITE/SEND_READ]のまま、`nvmerdmaconnect`は無変更)。
     * 詳細はnvme_rdma.c参照。 */
    NVMER_ST_PIPELINE_SETUP,
    NVMER_ST_PIPELINE_LOOP,
    NVMER_ST_DONE_OK,
    NVMER_ST_DONE_FAIL,
} nvme_rdma_state_t;

/* パイプライン化で同時にoutstandingにできるコマンド数の上限。
 *
 * **2026-08-12実機で発見: nvmet_rdma.hのNVMET_RDMA_MAX_PENDING(target側が
 * 常に事前投稿しているRECV WQE総数)と厳密に一致させてはならない。**
 * target側のRQは常に固定バッファ数を維持する設計(初期化時に投稿、
 * 各コマンドの応答SEND完了後に同じスロットへ再投稿)だが、CM層は
 * hrqsize/hsqsize相当のRQクレジット交渉を実際には行っていない(REQ/REP
 * private dataの該当フィールドは未実装のプレースホルダ、
 * ~/.claude/plans/peppy-wobbling-lamport.mdフェーズ(g)参照)。qdepthが
 * NVMET_RDMA_MAX_PENDINGと**厳密に等しい**場合、initiatorが最後の1個の
 * コマンドを送信するタイミングでtarget側RQの空きバッファが一時的に
 * ゼロになる競合が発生しうる -- これがRNR(Receiver Not Ready)NAKを
 * 誘発し、そのリトライタイマー(数msオーダー、通常のACKタイムアウトより
 * 大幅に長い)によってスループットが数十分の1まで壊滅的に低下することを
 * 実機で確認した(当時MAX_PENDING=8の下でdepth=8のみ約1.7MB/s、
 * depth=4/6/7はいずれも約246-248MB/s -- depth=MAX_PENDINGだけが際立って
 * 悪化するという症状そのものが、このRQバッファ枯渇境界条件の直接証拠)。
 * target側のRQバッファ数より**厳密に少ない**depthを保つ(NVMET_RDMA_
 * MAX_PENDING-1)ことで、target側に常に最低1個の空きRQバッファを保証し、
 * この競合を構造的に回避する。2026-08-13、ユーザー指示でNVMET_RDMA_
 * MAX_PENDINGを8→16へ拡大したことに合わせ、この値も7→15へ更新した
 * (nvmet_rdma.hのNVMET_RDMA_MAX_PENDINGを変更する際は、必ずこちらも
 * NVMET_RDMA_MAX_PENDING-1へ同期させること -- 2つのヘッダ間で手動同期が
 * 必要な値、プリプロセッサでは自動導出していない)。 */
#define NVME_RDMA_PL_QDEPTH_MAX 15u

typedef struct {
    rdma_cm_ctx_t cm;   /* CM確立(established後、cm.dev/cm.rc_qpが本命のQP) */

    uint16_t cntlid;
    uint32_t lba_size;
    uint64_t nsze;           /* Identify Namespace の NSZE(名前空間の総ブロック数)。
                              * ベンチで LBA をシーケンシャルに進める際の
                              * ラップ位置に使う(nvmer_next_lba)。 */
    uint64_t bench_cur_lba;  /* ベンチで次に発行するコマンドの開始 LBA。 */
    uint32_t nsid;
    unsigned csts_poll_count;
    uint64_t wait_started_ticks;

    /* write/read検証(nvmerdmaconnect)・write/readベンチ(nvmermabench)の
     * いずれも共有するバッファ(フェーズ(h)でNVME_RDMA_TEST_LEN→
     * NVME_RDMA_BENCH_BUF_MAXへ拡張)。完結型のジョブなので呼び出し元は
     * 保持不要 -- 自インスタンス内で完結する。 */
    volatile uint8_t write_buf[NVME_RDMA_BENCH_BUF_MAX] __attribute__((aligned(64)));
    volatile uint8_t read_buf[NVME_RDMA_BENCH_BUF_MAX] __attribute__((aligned(64)));
    volatile uint8_t id_ctrl[NVME_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));
    volatile uint8_t id_ns[NVME_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));

    /* 1コマンド分のSEND/RECVステージングバッファ(逐次再利用 -- 複数
     * コマンドを同時にoutstandingにはしない設計、上記スコープ簡略化
     * 参照)。 */
    volatile uint8_t send_buf[NVME_RDMA_MSG_MAX] __attribute__((aligned(64)));
    volatile uint8_t recv_buf[NVME_RDMA_MSG_MAX] __attribute__((aligned(64)));

    int      send_done;
    int      recv_done;
    uint32_t recv_len;
    uint64_t cmd_deadline;
    uint16_t cur_cid;
    nvme_cqe_t cqe_out;

    int failed;
    int done;     /* トップレベルのCONNECT->WRITE->READ(またはbenchループ)が完走したら1 */
    int write_ok;
    int read_ok;

    /* nvmet_rdma_ctx_t.stop_requestedと同じ理由・同じ使い方(一発診断
     * コマンドの後始末、CM_WAIT等の無期限待ちステートに保険として)。 */
    volatile int stop_requested;

    /* フェーズ(h): `nvmermabench`用の持続write/readループ設定・実績値。
     * 呼び出し元(nvme_rdma_run_bench())がjob_spawn()前に bench_enabled/
     * bench_is_read/bench_chunk_bytes/bench_duration_ms を設定しておく
     * (bench_enabled=0がnvmerdmaconnect相当の単発検証、既定動作)。
     * WAIT_ID_NS完了直後にbench_start_ticksを記録し、以後SEND_WRITE/
     * WAIT_WRITE(またはSEND_READ/WAIT_READ)がbench_duration_msの間
     * ループし続け、bench_count/bench_bytesを積算する。 */
    int      bench_enabled;
    int      bench_is_read;      /* 1=read繰り返し、0=write繰り返し */
    uint32_t bench_chunk_bytes;  /* 1コマンドあたりの転送バイト数(lba_sizeの倍数) */
    uint32_t bench_duration_ms;
    uint64_t bench_start_ticks;
    uint32_t bench_count;
    uint64_t bench_bytes;

    /* コマンドパイプライン化(2026-08-12)用。1(既定)なら従来通り単一
     * コマンド逐次処理、2以上ならNVME_RDMA_PL_QDEPTH_MAXまでの深さで
     * パイプライン化する(nvme_rdma_run_bench()が設定)。 */
    uint32_t bench_qdepth;

    /* 2026-08-12、接続再利用機構(ユーザー指示: 「次回の実行時に引き継いで
     * 実行する、CREATE系はスキップする、解放処理は一切必要ない」)。
     * Identify Namespaceまで完了した時点で reusable=1・established_
     * generation=cm.dev->bringup_generationを記録する。次回`nvmermabench`
     * 呼び出し時、reusable かつ established_generation が現在のdev->
     * bringup_generationと一致していれば、CM確立(QP作成)〜Fabrics
     * Connect〜Identifyまでを一切やり直さず、直接I/Oステートへ飛ぶ
     * (nvme_rdma.cのnvmer_conn_reusable()/nvme_rdma_run_bench()参照)。
     * `pcie1 reset`+`net init mlx5`をやり直すとbringup_generationが
     * 変わるため、古い接続は自動的に再利用不可と判定される。 */
    int      reusable;
    uint32_t established_generation;
} nvme_rdma_ctx_t;

/* job.hのjob_step_fn契約に従う。selfのctx(void*)はnvme_rdma_ctx_t*。
 * 呼び出し前にctx->cm.dev/is_active=1/skip_ping=1/own_ipや相手の
 * peer_ip等(rdma_cm_ctx_tのフィールド)を設定しておくこと(rdma_cm_
 * fill_addr()相当は呼び出し元が行う、nvme_rdma_run_connect_test()参照)。 */
job_result_t nvme_rdma_connect_job_step(job_t *self);

/* `nvmerdmaconnect`シェルコマンド用。dev0(initiator)/dev1(target)で
 * nvme_rdma_connect_job_step()とnvmet_rdma_job_step()(nvmet_rdma.h)を
 * 協調動作させ、CM確立->Fabrics Connect->CC有効化->Identify Controller/
 * Namespace->write->readまで一気通貫で確認する。 */
void nvme_rdma_run_connect_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

/* フェーズ(h): `nvmermabench`シェルコマンド用。dev0(initiator)/
 * dev1(target)でCM確立->Fabrics Connect->CC有効化->Identify Namespace
 * まではnvme_rdma_run_connect_test()と全く同じ手順を踏んだ上で、
 * write(is_read=0)またはread(is_read=1)コマンドをduration_ms間
 * 同一LBA(0)へ繰り返し発行し、スループット/IOPSを計測・報告する。
 * chunk_bytesは1コマンドあたりの転送量(lba_size[512]の倍数、
 * NVME_RDMA_BENCH_BUF_MAX[256KB]以下、0なら既定値65536を使う)。
 * 既存`nvme_rdma_connect_job_step()`のCONNECT〜IDENTIFY部分をそのまま
 * 再利用し(bench_enabledフラグで分岐)。
 *
 * qdepth(2026-08-12追加、ユーザー指示 -- CLAUDE.md「nvmermabenchの
 * ボトルネック切り分け」節参照): 1(または0)なら従来通り単一コマンド
 * 逐次発行(フェーズgのスコープ簡略化のまま)。2以上ならNVME_RDMA_PL_
 * QDEPTH_MAXまでの深さでコマンドパイプライン化する -- 「ソフトウェア
 * 処理をハード転送の裏に完全に隠す」ことで、固定オーバーヘッドの
 * 比率が高い小さいI/Oサイズほど大きな改善が見込める設計(nvme_rdma.c/
 * nvmet_rdma.cのパイプライン化コメント参照)。 */
/* out_mbps_x100!=NULL のとき、スループット(MB/s の100倍固定小数点、失敗時0)を
 * そこへ返す(呼び出し元がサマリ表を組むため)。従来の呼び出しは NULL でよい。 */
void nvme_rdma_run_bench(mlx5_dev_t *dev0, mlx5_dev_t *dev1, uint32_t duration_ms,
                         int is_read, uint32_t chunk_bytes, uint32_t qdepth,
                         uint32_t *out_mbps_x100);

#endif /* NVME_RDMA_H */
