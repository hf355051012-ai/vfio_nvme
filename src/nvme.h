#ifndef NVME_H
#define NVME_H

#include <stdint.h>
#include "nvme_tcp.h"
#include "nvme_types.h"

/* ================================================================
 * nvme.h — NVMeプロトコル層。SQEの組み立てとCQEの解釈だけを担う
 * (PDU/TCPの詳細はnvme_tcp.hへ委譲する、CLAUDE.md記載のレイヤ構成)。
 *
 * admin queue(qid=0)とIO queue(qid=1)は、NVMe-oF Fabricsの仕様上
 * それぞれ別々のTCPコネクション(nvme_tcp_conn_t)として確立する --
 * PCIe NVMeと違い、Fabricsトランスポートでは「Create I/O Completion/
 * Submission Queue」Adminコマンドは使わない(あれはPCIeのメモリマップド
 * リングバッファをホストが直接構築する場合専用で、Fabricsではキューは
 * TCP/RDMA接続そのものとFabrics Connectコマンドのqidフィールドによって
 * 暗黙に確立される -- 実際にnvmet-tcpへCreate I/O CQ/SQを送っても
 * サポートされない)。nvme_connect()はこの実際のNVMe-oF仕様に従う。
 * ================================================================ */

#define NVME_SUBNQN_MAX 224u  /* nvmf_connect_data_tのsubsysnqn/hostnqnフィールド(256B)より
                                * 少し余裕を持たせた、呼び出し側から渡される文字列の
                                * 保持用上限(NUL終端込み)。 */

typedef struct {
    nvme_tcp_conn_t admin;
    nvme_tcp_conn_t io;
    int      io_connected;
    uint16_t ctrlr_id;   /* admin queueのFabrics Connect応答で割り当てられたController ID
                          * (IO queueのFabrics Connectでcntlidとして使う、下記参照) */
    uint32_t lba_size;   /* nvme_identify_ns()が設定する、現在のnamespaceのLBAサイズ(バイト) */
    uint64_t nsze;       /* nvme_identify_ns()が設定する、現在のnamespaceの総ブロック数(NSZE)。
                          * `nvme bench`がシーケンシャルread/writeのLBAをラップさせるのに使う。 */
    char     subnqn[NVME_SUBNQN_MAX];

    /* NVMe/TCP制御のジョブ化(job.h基盤、CLAUDE.md「NVMe/TCP制御の
     * ステートマシン化」節参照)向け。connect job(admin/IO両キューの
     * 確立シーケンス)またはexec job(id-ctrl/id-ns/read/write単発
     * コマンド)のいずれかが実行中の間は立てておき、新規ジョブの
     * spawnを拒否するガードに使う(同一connへの二重送信はtcp_send()の
     * seq管理を壊す -- tcp.hのtcp_send_async()呼び出し規則コメントと
     * 同種の制約)。 */
    volatile int busy;
} nvme_ctx_t;

/* `nvme`シェルコマンド群(command.c)が操作する唯一の共有インスタンス。
 * temp_test()等、command.c以外から`nvme connect`相当の操作を行う場合は
 * 必ずこれを使うこと -- 独自に別の`nvme_ctx_t`インスタンスを作ると、
 * `nvme disconnect`等の通常のシェルコマンドがその接続を一切認識できず
 * (別実体なので)、実際には何も切断されないまま「切断完了」と表示される
 * バグを引き起こす(実機で確認・修正済み)。 */
extern nvme_ctx_t s_nvme_ctx;

/* ================================================================
 * NVMe/TCP制御のジョブ化(job.h基盤、CLAUDE.md「NVMe/TCP制御の
 * ステートマシン化」節参照)向けAPI。上記のブロッキング関数群
 * (nvme_connect()等)は一切変更せず残す(nvme benchが引き続き使う)。
 * ================================================================ */

/* SQE送信→応答待ち(RSP直行、C2HData(+RSP or DATA_SUCCESS)、または
 * R2T→H2CData送信の繰り返し)という受信オーケストレーションを1つの
 * 共有サブステートマシンとして実装したもの -- Identify/Property Set/
 * Get/Fabrics Connect/Read/Writeいずれでも共通のパターンなので、
 * nvme_connect_job(このファイル内部)とcommand.cの各exec job
 * (id-ctrl/id-ns/read/write)の両方から呼ぶ。既存の
 * nvme_tcp_send_cmd()/nvme_tcp_recv_resp()(ブロッキング)と同じ
 * ロジックを状態遷移へ展開したもの(複製ではなく、送信は
 * nvme_tcp_send_cmd()を、R2T応答送信はnvme_tcp_send_h2c_data()を
 * そのまま呼ぶ)。 */
typedef struct {
    int               state;   /* nvme_exec_state_t(nvme.c)、呼び出し側は直接見ない */
    nvme_tcp_conn_t  *conn;
    const nvme_sqe_t *sqe;
    const void       *send_data;
    uint32_t          send_len;
    void             *recv_buf;
    uint32_t          recv_buflen;
    nvme_tcp_xfer_t   xfer;
    uint8_t           hdr_buf[8];   /* NVME_TCP_HDR_LEN */
    uint8_t           rest_buf[16];
    uint32_t          datao;
    uint32_t          datal;
    uint16_t          ttag;
    nvme_cqe_t        cqe_out;
    int               result;  /* 完了時: CQEステータス(0=success)、通信エラー等は-1 */
} nvme_exec_ctx_t;

/* ecを初期状態にし、次のnvme_exec_step()呼び出しからSQE送信を開始する
 * よう準備する。sqe/send_data/recv_bufは呼び出し側が(ecの生存期間中)
 * 保持し続けること(ポインタを保存するだけでコピーしない)。 */
void nvme_exec_begin(nvme_exec_ctx_t *ec, nvme_tcp_conn_t *conn, const nvme_sqe_t *sqe,
                      const void *send_data, uint32_t send_len,
                      void *recv_buf, uint32_t recv_buflen);

/* 1回だけ非ブロッキングで進める。
 * 戻り値: 0=継続中(次tickにまた呼ぶ)、1=完了(ec->result/ec->cqe_out確定) */
int nvme_exec_step(nvme_exec_ctx_t *ec);

/* SQE組み立てヘルパ(既存のブロッキング関数群から抽出、ロジックは
 * 無変更 -- command.cのexec jobがnvme_exec_begin()へ渡すSQEを組み立てる
 * のに使う)。 */
void nvme_build_identify_sqe(nvme_sqe_t *sqe, uint8_t cns, uint32_t nsid);
/* total_len = nlb * ctx->lba_size(呼び出し側が計算して渡す -- 既存の
 * nvme_read()/nvme_write()も内部でこの計算をしてから渡している)。 */
void nvme_build_read_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len);
void nvme_build_write_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len);

/* Identify Namespace応答(buf4096)からLBAサイズを読み取りctx->lba_sizeを
 * 更新する(既存nvme_identify_ns()から抽出、ロジックは無変更)。
 * command.cのid-ns exec jobが完了時に呼ぶ。 */
void nvme_update_lba_size_from_id_ns(nvme_ctx_t *ctx, uint32_t nsid, const void *buf4096);

/* admin queue確立(TCP+ICReq/ICResp+Fabrics Connect qid=0+CC有効化+
 * CSTS.RDY待ち+Identify Controller/Namespace(nsid=1)+Set Features)→
 * IO queue確立(TCP+ICReq/ICResp+Fabrics Connect qid=1)という
 * nvme_connect()の全シーケンスを1本のjob_t(job.h)としてspawnし、
 * 即座に呼び出し元へ戻る。進行状況・完了/失敗のログはこのジョブ自身が
 * 出す(nvmet_job_start()と同じパターン)。
 * 戻り値: 0=spawn成功、-1=ジョブテーブル満杯またはctx->busy中 */
int nvme_connect_job_start(nvme_ctx_t *ctx, uint32_t ip, uint16_t port, const char *subnqn);

/* ================================================================
 * NVMe/TCPコマンドパイプライン化(2026-08-09、PCIe Gen2 x1帯域ネックを
 * 追い込む取り組みの一環)。上記nvme_write_begin()系は`ctx->busy`が
 * 単一フラグ(=同時に1コマンドしか発行できない、実質queue depth=1)
 * だったため、1write=1コマンド往復(SEND→R2T待ち→H2CData送信→CQE
 * 受信)のレイテンシがそのままスループット上限になっていた
 * (`test`コマンドのstateprof実測、SEND_H2C=1790us/RECV_CQE=911us等が
 * 支配的)。target側(nvmet.c)は元々`NVMET_MAX_PENDING_WRITES`(8)まで
 * 複数コマンドを並行処理できる設計だったため、初期側(このファイル)を
 * 拡張して実際に複数コマンドを同時に発行できるようにした。
 *
 * 設計: NVME_IO_QDEPTH個のスロットを持ち、各スロットが独立したSQE/
 * data/cid/完了状態を保持する。単一のIO queue TCP接続(ctx->io)上を
 * 流れるPDU列(Response/R2T)は、CQEのcidフィールド・R2Tのcccidフィールド
 * (いずれも送信時にnvme_tcp_send_cmd()が採番したcidと一致)で該当スロット
 * へルーティングする -- nvmet.cのs_pending_writes[]がH2CDataをcccidで
 * ルーティングするのと対になる、初期側での実装。
 *
 * 既存のnvme_exec_step()/nvme_tcp_send_h2c_data()(単一コマンド前提、
 * conn->pending_cid/pending_data/pending_lenを暗黙参照)は一切変更せず
 * 残す -- このパイプラインは完全に別実装(nvme.c内のstatic状態)として
 * 追加し、conn->pending_*を汚さない(nvme_tcp_send_h2c_data_ex()の明示
 * 引数版を使う)。 */
/* 2026-08-09、depth=4→8を2回(SQE同期送信時・非同期送信時それぞれ)
 * 実機で試したが、いずれも4の方が優れていた(同期送信時: 121.2MB/s
 * [depth=8] <124.8MB/s[depth=4]、非同期送信時: 122.3MB/s[depth=8]
 * <126.0MB/s[depth=4])。`ts core 1 type IOWR`の実機トレースで
 * 決定的な証拠が得られた: depth=8では確かに8件ずつのバーストで
 * コマンドが受理されている(depth自体は正しく機能)が、バースト間の
 * 待ち時間が約8ms(depth=4)→約16.5ms(depth=8)とほぼ正確に2倍へ
 * 伸びていた -- つまり「1バッチあたりの処理時間」もdepthに比例して
 * 伸びており、単位時間あたりのコマンド処理数(実効スループット)は
 * depthを増やしても変わらない。これは「コマンドdepth不足」ではなく
 * 「TCPリンクの実効帯域そのものが上限」であることを示す -- 単一の
 * IO queue TCP接続は本質的に1バイトストリームであり、複数コマンドを
 * 同時にoutstandingにしても、そのデータの受信処理(RECV_H2C_DATA)は
 * target側で必ずシーケンシャルに進む(target-io stateprofのRECV_H2C_
 * DATA合計時間が全体時間の6割強を占めていたことからも整合する)。
 * depth=4の時点で既にリンクの実効帯域(tcploopbenchの生TCP実測、
 * 約115MB/s)に近い水準まで使い切れていたため、depthをさらに増やす
 * 方向はこれ以上追求しない -- と結論していたが、この結論は
 * mlx5_net_post_frame()がコピーベース(1セグメントあたり約30-38usの
 * Device-nGnRnEへのコピー、CLAUDE.md「mlx5_net_post_frame()のゼロ
 * コピー化」節参照)だった当時の「送信コピーコストがリンク実効帯域を
 * 頭打ちにしていた」状況下でのみ成立していた前提だった。ゼロコピー化
 * 後、生TCPスループットが約115MB/s→約153.2MB/sへ改善したにもかかわらず
 * write負荷テスト(depth=4)は横ばいだったため、2026-08-09再度depth=8を
 * 実機で試したところ、[IP]/[TCP]チェックサム不正が発生した -- ただし
 * これはdepth=8固有の問題ではなく、ゼロコピー化のフォールバック経路
 * (mlx5.hのMLX5_NET_TX_STAGE_ADDR直前のコメント参照、非同期送信される
 * 60バイト未満のACK等が単一共有バッファを取り合うバグ)が原因で、
 * depth=4でも(発生頻度は低いが)再現した。この本物のバグを修正した後、
 * depth=4のwrite負荷テストは約120.8〜141.4MB/s(実行毎の変動あり、
 * チェックサムエラーは一度も再発せず)まで改善した。改めてdepth=8を
 * 試したところ約137.4〜138.8MB/s(depth=4よりばらつきが小さい)を記録し、
 * チェックサムエラーも一度も再発しなかった -- depth=4/8間の差は実行毎の
 * 変動の範囲内でどちらとも言えないが、target側(nvmet.h)が元々
 * NVMET_MAX_PENDING_WRITES=8を前提にしている設計に初期側を合わせる方が
 * 自然と判断し、8を採用する。 */
/* 注(x86 VFIO で実測): qd を 8→32 へ増やすと単一コア(target+initiator が
 * core0 同居)では read/write とも悪化するため 8 のまま据え置く。深い qd の
 * 恩恵を受けるには target を別コアへ分離する必要がある(core-split は別途未達)。 */
#define NVME_IO_QDEPTH 8u

/* nsid/lba(先頭ブロック番号)へ、buf(呼び出し側が用意する、少なくとも
 * nlb*ctx->lba_sizeバイト、読み取り専用として複数コマンドから同時参照
 * される)をnlbブロック分書き込むコマンドを、NVME_IO_QDEPTH並列で
 * duration_ms間繰り返す(同じlba/bufへ毎回上書きする、性能測定専用)。
 * 呼び出し中は内部でjob_scheduler_tick()を回し続けるブロッキング関数
 * (temp_test()の既存ループと同じ「呼び出し元スレッドが直接ポーリングを
 * 回す」設計、job_delay_ms()と同じ考え方)。
 * out_count/out_bytes/out_elapsed_ms: 完了した(成功した)write数・
 * 合計バイト数・実際にかかった時間(ms、drain待ち込み)。いずれもNULL可。
 * 戻り値: 0=正常終了(個々のwrite失敗はout_count/ログで分かる)、
 *         -1=未接続またはbusy中で開始できなかった */
int nvme_write_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                              const void *buf, uint32_t nlb, uint32_t duration_ms,
                              uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms);

/* nvme_write_pipelined_run()のREAD版(2026-08-10)。応答経路(C2HData直送、
 * R2T往復無し)が異なるため内部の状態機械はwrite版と完全に独立している
 * (nvme.cコメント参照)が、呼び出し規約は同一 -- bufは読み出し先
 * (呼び出し元所有、少なくともnlb*ctx->lba_sizeバイト)。 */
int nvme_read_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                             void *buf, uint32_t nlb, uint32_t duration_ms,
                             uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms);

#endif /* NVME_H */
