#ifndef RDMA_CM_H
#define RDMA_CM_H

#include "mlx5_qp.h"
#include "job.h"

// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)
// フェーズ(e): 標準IB CM(REQ/REP/RTU)によるRC QP自動確立。
//
// ワイヤフォーマットは本セッションで実際にtorvalds/linux(master)から
// 取得し裏取り済み:
//   - MADヘッダ: drivers/infiniband/core/cm.c の cm_format_mad_hdr()
//     (base_version=1, mgmt_class=IB_MGMT_CLASS_CM(0x07), class_version=2
//     [IB_CM_CLASS_VERSION、drivers/infiniband/core/cm_msgs.hで確認]、
//     method=IB_MGMT_METHOD_SEND(0x03))。
//   - 属性ID: include/rdma/ib_cm.h(CM_REQ_ATTR_ID=0x0010/CM_REP_ATTR_ID=
//     0x0013/CM_RTU_ATTR_ID=0x0014)。
//   - REQ/REP/RTUの各フィールドのバイトオフセット:
//     include/rdma/ibta_vol1_c12.h(Table 106/110/111、IBTA Volume1
//     Chapter12の宣言そのもの)。IBA_FIELD*_LOC系マクロのビット位置は
//     「バイトNのMSB=bit0」という、このプロジェクト一貫のbit-numbering
//     規約と完全に一致することを確認済み(include/rdma/iba.hのGENMASK式
//     から導出)。
//   - REQ private data(cma_hdr[36B]+ULP private data): drivers/
//     infiniband/core/cma.cのcma_format_hdr()/cma_connect_ib()。REPは
//     cma_hdrを含まずULP private dataのみ(cma_accept_ib()で確認)。RTUは
//     NVMe-oFでは通常private data無し。
//   - NVMe-oF固有のULP private data: include/linux/nvme-rdma.hの
//     struct nvme_rdma_cm_req(32B)/struct nvme_rdma_cm_rep(32B)。
//
// **フェーズ(e)の完了条件はPF0(active)→PF1(passive)のCM確立+ping-pong
// 成功のみ**なので、NVMe-oF固有フィールド(qid/hrqsize等)は将来の
// フェーズ(g)向けに正しいバイト位置へ書き込むが、値そのものはこの
// フェーズでは意味を持たないプレースホルダのままでよい。
// SERVICE_ID(rdma_get_service_id()相当、本来は(ps<<16)+port)も同様に
// 固定プレースホルダ値を使う -- 実NVMe-oFホストとの相互接続(フェーズi)
// までに正しい値を確認・実装すること。
//
// GID/MAC等の相手アドレス知識は、フェーズ(b)/(c)/(d)の診断コードと同じ
// netif_find()+ハードコードされたフォールバック値のパターンを踏襲する
// (固定トポロジのループバック検証が目的であり、ARP等の動的発見は範囲外)。
// MACはIBTA CMメッセージ自体には一切含まれないため常に呼び出し元の
// 事前設定値を使う。GIDはREQペイロードから学習した値で上書きする
// (実接続[フェーズi]での動的な相手方を見据えた設計)。

#define RDMA_CM_MAD_SIZE       256u  // ib_mad.hのIB_MGMT_MAD_SIZEと同値
#define RDMA_CM_REQ_PRIV_LEN   92u   // (140*8+736)/8 - 140 = 92バイト
#define RDMA_CM_REP_PRIV_LEN   196u  // (36*8+1568)/8 - 36 = 196バイト
#define RDMA_CM_RTU_PRIV_LEN   224u  // (8*8+1792)/8 - 8 = 224バイト

typedef enum {
    RDMA_CM_ST_ACTIVE_SETUP = 0,
    RDMA_CM_ST_ACTIVE_SEND_REQ,
    RDMA_CM_ST_ACTIVE_WAIT_REP,
    RDMA_CM_ST_ACTIVE_MODIFY_QP,
    RDMA_CM_ST_ACTIVE_SEND_RTU,
    RDMA_CM_ST_ACTIVE_PING_SEND,  // 確立後の検証: RC QPでSENDを1個投稿
    RDMA_CM_ST_ACTIVE_PING_WAIT,  // 自分のSQ CQE(送信完了)を待つ
    RDMA_CM_ST_PASSIVE_SETUP,
    RDMA_CM_ST_PASSIVE_WAIT_REQ,
    RDMA_CM_ST_PASSIVE_MODIFY_QP,
    RDMA_CM_ST_PASSIVE_SEND_REP,
    RDMA_CM_ST_PASSIVE_WAIT_RTU,
    RDMA_CM_ST_PASSIVE_PING_WAIT, // 確立後の検証: RC QPのRQ CQE(受信)を待ち内容確認
    RDMA_CM_ST_DONE_OK,
    RDMA_CM_ST_DONE_FAIL,
} rdma_cm_state_t;

typedef struct {
    mlx5_dev_t *dev;
    // CM MAD送受信用(常にGSI、st=0x8、宛先QPN=1固定 -- フェーズ(d)で確認
    // 済みの規約)。**ポインタである点が重要**(2026-08-13、実機で発見した
    // 本物のバグの修正): 当初`mlx5_qp_t gsi_qp;`という値メンバだったが、
    // IOキュー用ctx(reuse_gsi=1)がadmin queueの確立済みGSI QPを「構造体
    // まるごとコピー」して使い回す設計にしたところ、sq_pc/rq_pc/cq_cc
    // (ドアベル計算に使う進行カウンタ)がコピー時点で凍結され、admin側の
    // 実際のハードウェア状態と即座に乖離した -- IOキュー側が自分の
    // (古い)ローカルコピーのカウンタでSEND WQEを投稿すると、ハードウェア
    // 側は既にadminの送信で進んでいる実際のプロデューサカウント値と
    // 一致しないドアベル値を受け取ることになり、HWが「新しい作業は無い」
    // と誤認してWQEを一切フェッチしない(REPを送ったつもりでも実際には
    // 一度もワイヤへ出ない)という、エラーも一切返らない静かな失敗を
    // 実機で確認した(IOキューのRTUが常に届かずタイムアウトする症状)。
    // 修正: `gsi_qp`を「実体を指すポインタ」にし、`gsi_qp_storage`
    // (下記)が実際の唯一のインスタンスを保持する。通常(GSI新規作成)の
    // ctxは`gsi_qp = &gsi_qp_storage`(自己参照)、IOキュー用ctxは
    // `gsi_qp = &admin_ctx->cm.gsi_qp_storage`と、ADMIN側の実体を直接
    // 指すことで、admin/IO双方が常に同一の物理QP状態(同じsq_pc/rq_pc/
    // cq_cc)を参照するようになる -- 構造体コピーではなく共有。
    mlx5_qp_t  *gsi_qp;
    mlx5_qp_t  gsi_qp_storage; // gsi_qpが指す実体(このctxがGSIの本来の
                                // 所有者である場合のみ実際に使われる)
    mlx5_qp_t  rc_qp;    // CM経由で確立する本命のRC QP
    int        is_active; // 1=REQ送信側、0=REQ待ち側

    uint32_t local_comm_id;
    uint32_t remote_comm_id;
    uint64_t tid;

    uint8_t  own_gid[16];
    uint8_t  own_mac[6];
    uint32_t own_ip;   // host-order、cma_hdr.src_addr用(プレースホルダ)
    uint8_t  peer_gid[16];
    uint8_t  peer_mac[6];
    uint32_t peer_ip;  // host-order、cma_hdr.dst_addr用(プレースホルダ)
    uint32_t peer_rc_qpn;      // 相手のRC QPN(REQ/REPペイロードから学習)
    uint32_t peer_starting_psn; // 相手のnext_send_psn(REQ/REPペイロードから学習)
    uint8_t  peer_path_mtu;    // 相手がCM REQで広告したPATH_PACKET_PAYLOAD_MTU
                               // (IB_MTU値、passive側でparse。RC QPのpath MTUを
                               // 相手に合わせるため -- mlx5.hのmlx5_qp_t.path_mtu参照)

    uint16_t nvme_qid; // ULPプレースホルダ(フェーズg以降で実際に使う)

    // フェーズ(g): 確立後の検証ping(PING_SEND/PING_WAIT、SEND1個で
    // rc_recv_bufを消費する)をスキップし、RTU送信/受信の直後に即座に
    // DONE_OKへ抜ける。nvme_rdma.c/nvmet_rdma.cは確立されたrc_qp自体を
    // 実際のNVMe-oFトラフィックに使うため、ping専用のRECV WQE消費・
    // SEND消費を避ける必要がある(rdma_cm.cコメント参照)。0(既定、
    // rdma_cm_fill_addr()のゼロ初期化)なら従来通りping検証を行う。
    int skip_ping;

    // フェーズ(i)続報(2026-08-13): IOキュー(2本目のRC QP)用のCM接続を
    // 表すctxで使う。GSI/QP1相当は1PFにつき物理的に1つしか存在できない
    // (フェーズdの「宛先QPN=1固定」規約)ため、admin queueが確立した
    // GSI QPをそのまま使い回す -- reuse_gsiが真の場合、PASSIVE_SETUP/
    // ACTIVE_SETUPはGSIのCREATE_QP等を一切行わず、呼び出し元が
    // rdma_cm_fill_addr()の直後に手動で設定した`gsi_qp`(既に確立済みの
    // ものをそのままコピーしたもの)へRECV WQEを1個再武装するだけに
    // とどめる。rc_qp_indexはmlx5_qp_create_rc()へそのまま渡す
    // (0=admin用の1本目、1=IOキュー用の2本目、mlx5.hのmlx5_qp_wqe_addr()
    // 等参照)。
    int      reuse_gsi;
    uint8_t  rc_qp_index;

    volatile uint8_t send_buf[RDMA_CM_MAD_SIZE];
    volatile uint8_t recv_buf[MLX5_GRH_BYTES + RDMA_CM_MAD_SIZE];
    volatile uint8_t rc_recv_buf[128]; // passive側、確立後のping検証用RECVバッファ

    uint64_t state_deadline;
    uint8_t  retry_count;
    int      established; // RC QPがRTSに達した時点で1(active/passive共通)
    int      ping_ok;     // 確立後のping-pong検証が成功したら1
    int      failed;

    // 2026-08-13、切断検出(nvmet_rdma.cのDREQ監視)用: passive+skip_ping
    // 側がRTU処理(またはRTUタイムアウト後の続行)を終えてこの"cm" jobを
    // 終了する直前に1が立つ。呼び出し元(nvmet_rdma.c)はこれを見て
    // 「GSIへもう1個RECV WQEが構えてある」ことを確認してからGSIの
    // DREQポーリングを開始する -- 立つ前にポーリングを始めると、まだ
    // このjob自身が受信中のRTUメッセージを誤って横取りしてしまう競合を
    // 避けるため(rdma_cm.cの該当箇所コメント参照)。
    int      rtu_phase_done;
} rdma_cm_ctx_t;

// job.hのjob_step_fn契約(non-blocking、JOB_WAITING/JOB_DONE)に従う。
// 呼び出し前にctx->dev/is_active/own_gid/own_mac/own_ip/peer_gid/
// peer_mac/peer_ip(固定トポロジのため呼び出し元が既知の値を設定する)を
// 設定しておくこと。
job_result_t rdma_cm_job_step(job_t *self);

// 受信済みGSIバッファ(recv_buf、mlx5_qp_poll_cqe_gsi()+dcache_invalidate_
// range()済み)からCM MADのattr_idフィールドを読む。rdma_cm.c内部の
// REQ/REP/RTU判定に加え、nvmet_rdma.cのDREQ監視(2026-08-13)も同じ
// ロジックを再利用するため公開した。
uint16_t rdma_cm_recv_attr_id(const volatile uint8_t *recv_buf);

// ctxをゼロクリアした上でdev/own_*/peer_*を設定する(netif_find()で
// 見つかればそちらを優先、見つからなければfallback値を使う)。フェーズ
// (f)まではrdma_cm.c内部のstatic関数だったが、フェーズ(g)のnvme_rdma.c/
// nvmet_rdma.cが自前のrdma_cm_ctx_tインスタンスに対して同じ初期化ロジック
// (特にゼロクリア後のdcache_clean_range()、CLAUDE.md「REQ/REP受信でCQEが
// 直前のデータを上書きするバグ」節参照)を再利用する必要があるため公開した。
void rdma_cm_fill_addr(rdma_cm_ctx_t *ctx, mlx5_dev_t *dev, const char *self_label,
                       const char *peer_label, uint32_t self_ip_fallback,
                       uint32_t peer_ip_fallback, const uint8_t self_mac_fallback[6],
                       const uint8_t peer_mac_fallback[6]);

// PF0をactive、PF1をpassiveとしてrdma_cm_job_step()を2つ協調動作させ、
// CM確立(REQ->REP->RTU)から、確立されたRC QPでのSEND/RECV ping-pong
// (mlx5_qp_pingpong_test()相当)まで一気通貫で確認する。job_spawn()で
// 実際にjob.hのスケジューラへ登録した上で、完了(または失敗/タイムアウト)
// までjob_scheduler_tick()を同期的に回す(既存のmlx5qp pingpong等と同じ
// 「実行結果をその場でPASS/FAILとして返す」診断コマンドのUXを維持しつつ、
// 内部実装は計画通りjob.hのnon-blocking契約に完全準拠させる)。
void rdma_cm_run_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(f)((c)+(e)の統合)。PF0を
// active、PF1をpassiveとしてCM(REQ->REP->RTU)でRC QPを自動確立した
// 直後、確立されたQP自体でRDMA_WRITE(active->passive)・RDMA_READ
// (passive->active)を実行し、フェーズ(c)の`mlx5qp rdma`と同じデータ
// 完全一致確認を行う。「CM接続要求→自動QP確立→即RDMA_WRITE/READ疎通」
// を1コマンドで完走させる、というフェーズ(f)の完了条件そのもの。
void rdma_cm_run_connect(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

#endif /* RDMA_CM_H */
