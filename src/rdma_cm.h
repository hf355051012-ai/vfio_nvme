#ifndef RDMA_CM_H
#define RDMA_CM_H

#include "mlx5_qp.h"
#include "job.h"

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
    /* CM REQ の RESPONDER_RESOURCES(相手が responder として受け付ける同時
     * RDMA_READ 数)。**passive 側はこれを超えて RDMA_READ を投げてはならない。**
     * 超えると相手が REMOTE_INVAL_REQ_ERR(syndrome=0x12)を返す。 */
    uint8_t  peer_responder_resources;
    uint8_t  peer_initiator_depth;   // 同 INITIATOR_DEPTH(相手が initiator として投げる数)
    /* REP の INITIATOR_DEPTH として広告した値。**相手はこれを自分の QP の
     * max_dest_rd_atomic に設定する**ので、こちらの同時 RDMA_READ 数の上限も
     * これになる(nvmet_rdma.c の rra_max がこれを見る)。 */
    uint8_t  negotiated_initiator_depth;

    uint16_t nvme_qid; // CM private data の nvme_rdma_cm_req.qid(0=admin)

    /* CM REQ に載せる値。0 のときは rdma_cm_fill_addr() が既定を入れる。
     * **Linux の rdma_cm はリスナを SERVICE_ID で引く**ので、
     * service_port を間違えると相手は「該当なし」で REJ を返す。 */
    uint16_t service_port; // 接続先の NVMe-oF ポート(既定 4420)
    uint16_t src_port;     // cma_hdr.port(相手から見た自分の擬似ソースポート)
    uint16_t hsqsize;      // nvme_rdma_cm_req.hsqsize(**0's based**)
    uint16_t hrqsize;      // nvme_rdma_cm_req.hrqsize(1's based)
    uint16_t cntlid;       // IO キューのときだけ載せる(admin は 0xFFFF)

    int skip_ping;

    int      reuse_gsi;
    uint8_t  rc_qp_index;
    uint8_t  rc_cs_req;   /* RC QP の qpc.cs_req(0=無効、0x11=read/atomic の応答を CQE へ)*/

    volatile uint8_t send_buf[RDMA_CM_MAD_SIZE];
    volatile uint8_t recv_buf[MLX5_GRH_BYTES + RDMA_CM_MAD_SIZE];
    volatile uint8_t rc_recv_buf[128]; // passive側、確立後のping検証用RECVバッファ

    uint64_t state_deadline;
    uint8_t  retry_count;
    int      established; // RC QPがRTSに達した時点で1(active/passive共通)
    int      ping_ok;     // 確立後のping-pong検証が成功したら1
    int      failed;
    uint16_t rej_reason;  // REJ を受けたときの理由コード(0=なし)

    int      rtu_phase_done;

    /* REP の PRIVATE_DATA 先頭(active 側のみ)。**librdmacm の rdma_accept() に
     * 渡した private_data がそのままここに載る**ので、相手が登録した MR の
     * アドレスと rkey を受け取る経路になる(rdma_short.c)。 */
    uint8_t  rep_priv[64];

    /* REP(passive 側)/ REQ(active 側、cma_hdr の後ろ)の PRIVATE_DATA に載せる ULP のデータ。
     * rep_priv_out_len が 0 なら NVMe-oF の nvme_rdma_cm_rep / _req を載せる(従来どおり)。
     * iSER は iser_cm_hdr(4 バイト)を載せる。 */
    uint8_t  rep_priv_out[8];
    uint8_t  rep_priv_out_len;
    /* active 側の REQ で名乗る経路 MTU(IB の符号 1=256 .. 5=4096。0 = 従来どおり 1024)。
     * 確立した QP もこの値で動く。 */
    uint8_t  req_path_mtu;
    /* passive 側で受け付ける REQ の SERVICE_ID のポート(0 = 問わない。従来どおり)。 */
    uint16_t listen_port;
} rdma_cm_ctx_t;

/* 確立済みの接続を CM の DREQ で畳み、DREP を待つ(同期、GSI を直接回す)。
 * **CM ジョブが終わってから呼ぶこと**(GSI の CQ を取り合う)。
 * 戻り値: 0=DREP を受けた、-1=送信失敗、1=待ち切れ(相手は TIMEWAIT へ進む)。 */
int rdma_cm_disconnect(rdma_cm_ctx_t *ctx, uint32_t wait_ms);

/* 共有 GSI から DREQ を 1 つ取り出して ctx->recv_buf へ写す(宛先は問わない)。
 * GSI の受信は rdma_cm.c が振り分けているので、**GSI の CQ を直接ポーリング
 * しないこと**(ほかの受け皿宛ての REQ / RTU を横取りする)。
 * 戻り値: 1=取り出した、0=無い、-1=GSI の CQE エラー */
int rdma_cm_take_dreq(rdma_cm_ctx_t *ctx, uint32_t *out_len);

job_result_t rdma_cm_job_step(job_t *self);

uint16_t rdma_cm_recv_attr_id(const volatile uint8_t *recv_buf);
/* CM REQ の RESPONDER_RESOURCES を手で固定する(0=HCA 上限)。A/B 測定用。 */
void    rdma_cm_set_responder_resources_override(uint8_t v);
uint8_t rdma_cm_responder_resources_override(void);

void rdma_cm_fill_addr(rdma_cm_ctx_t *ctx, mlx5_dev_t *dev, const char *self_label,
                       const char *peer_label, uint32_t self_ip_fallback,
                       uint32_t peer_ip_fallback, const uint8_t self_mac_fallback[6],
                       const uint8_t peer_mac_fallback[6]);

#endif /* RDMA_CM_H */
