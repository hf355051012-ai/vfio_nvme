#include "rdma_cm.h"
#include "mlx5.h"
#include "ib_mad.h"
#include "netif.h"
#include "net.h"
#include "timer.h"
#include "cache.h"
#include "uart.h"
#include "job.h"

#define CM_REQ_ATTR_ID 0x0010u
#define CM_REJ_ATTR_ID 0x0012u

/* REJ の理由コード(IBTA Vol1 Table 113 / Linux の enum ib_cm_rej_reason)。
 * **これを見ないと「相手が拒否した」しか分からず、
 * リスナが無いのか古い接続が残っているのかを切り分けられない。 */
#define CM_REJ_STALE_CONN            10u
#define CM_REJ_INVALID_SERVICE_ID     8u

/* `rdmarra` で設定する RESPONDER_RESOURCES の手動固定値(0=HCA 上限)。 */
static uint8_t s_rr_override;

void rdma_cm_set_responder_resources_override(uint8_t v) { s_rr_override = v; }
uint8_t rdma_cm_responder_resources_override(void) { return s_rr_override; }
#define CM_REJ_CONSUMER_DEFINED      28u

#define CM_REP_ATTR_ID 0x0013u
#define CM_RTU_ATTR_ID 0x0014u
#define CM_DREQ_ATTR_ID 0x0015u
#define CM_DREP_ATTR_ID 0x0016u
#define IB_CM_CLASS_VERSION 2u // drivers/infiniband/core/cm_msgs.hで確認済み

/* Linux の rdma_cm はサービス ID を (port_space << 16) + port で作り、
 * 受け取った REQ のサービス ID からリスナを引く
 * (drivers/infiniband/core/cma.c の rdma_get_service_id() /
 *  rdma_ps_from_service_id() / cma_port_from_service_id())。
 * RDMA_PS_TCP は include/uapi/rdma/rdma_user_cm.h より 0x0106。
 * **ここを固定値にしていると相手は「リスナ無し」で REJ を返す。** */
#define RDMA_CM_PORT_SPACE_TCP 0x0106ull
#define RDMA_CM_DEFAULT_PORT   4420u
#define RDMA_CM_DEFAULT_SRC_PORT 0xC000u /* 擬似的な ephemeral ポート */

/* nvme_rdma_cm_req のキューサイズ。Linux のホスト側
 * (drivers/nvme/host/rdma.c nvme_rdma_route_resolved())は admin キューで
 * hrqsize=NVME_AQ_DEPTH(32)、hsqsize=NVME_AQ_DEPTH-1(31)を送る。
 * **hsqsize は 0's based** で、ターゲットは hsqsize+1 を受信キュー長として
 * 見る(nvmet_rdma_parse_cm_req())。32 を入れると 33 > NVME_AQ_DEPTH に
 * なって INVALID_HSQSIZE で拒否される。 */
#define RDMA_CM_DEFAULT_HRQSIZE 32u
#define RDMA_CM_DEFAULT_HSQSIZE 31u

#define RDMA_CM_REQ_RETRY_TIMEOUT_MS 2000u
#define RDMA_CM_REQ_MAX_RETRIES      3u
#define RDMA_CM_RTU_WAIT_TIMEOUT_MS  3000u
#define RDMA_CM_PING_TIMEOUT_MS      3000u

static const char RDMA_CM_PING_MSG[] = "rdma_cm phase(e) established ping-pong";

/*=================================================================
 * 受信した MAD の attribute id(REQ=0x0010 / REP=0x0013 / RTU=0x0014)を
 * 読む。GRH 40 バイトの直後が MAD ヘッダである前提。
 *
 * 引数:
 *   recv_buf - GSI RQ が受信したバッファ先頭(GRH から)
 * 戻り値:
 *   attribute id
 * コール元:
 *   rdma_cm_job_step(), nvmetr_check_gsi_disconnect()
 * ===============================================================*/
uint16_t rdma_cm_recv_attr_id(const volatile uint8_t *recv_buf) {
    return rd16be_ib(&recv_buf[MLX5_GRH_BYTES + 16]);
}

/*=================================================================
 * CM REQ を組み立てる。フィールドのバイトオフセットは IBTA Vol1 Ch12 の
 * Table 106。private data には cma_hdr(36 バイト)+ ULP private data を
 * 載せる(REQ にだけ cma_hdr が付く)。
 *
 * 引数:
 *   ctx - 送信バッファと自 QPN/PSN/GID を持つ CM コンテキスト
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static void rdma_cm_build_req(rdma_cm_ctx_t *ctx) {
    volatile uint8_t *buf = ctx->send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) {
        buf[i] = 0;
    }
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND,
                     ctx->tid, CM_REQ_ATTR_ID, 0);
    volatile uint8_t *p = &buf[IB_MAD_HDR_LEN];

    wr32be_ib(&p[0], ctx->local_comm_id); // LOCAL_COMM_ID
    /* SERVICE_ID = (RDMA_PS_TCP << 16) + 接続先ポート。相手はこれでリスナを引く。 */
    wr64be(&p[8], (RDMA_CM_PORT_SPACE_TCP << 16) | (uint64_t)ctx->service_port);
    /* LOCAL_CA_GUID: 自分の MAC から EUI-64 を作る。**0 のままにしない。**
     * Linux の ib_cm は (remote_ca_guid, remote_qpn) で重複接続と
     * TIMEWAIT を引くので(cm.c の cm_insert_remote_qpn())、GUID が 0 だと
     * 別のノードと見分けられない。 */
    {
        uint64_t guid = 0;
        for (unsigned i = 0; i < 3u; i++) guid = (guid << 8) | ctx->own_mac[i];
        guid = (guid << 16) | 0xFFFEu;
        for (unsigned i = 3; i < 6u; i++) guid = (guid << 8) | ctx->own_mac[i];
        wr64be(&p[16], guid); // LOCAL_CA_GUID
    } // LOCAL_CA_GUID(プレースホルダ、未使用)
    wr32be_ib(&p[28], 0); // LOCAL_Q_KEY(RCでは不要)
    p[32] = (uint8_t)(ctx->rc_qp.qpn >> 16);
    p[33] = (uint8_t)(ctx->rc_qp.qpn >> 8);
    p[34] = (uint8_t)ctx->rc_qp.qpn; // LOCAL_QPN(24bit)
    /* **ここを固定値にしてはいけない**(REP 側と同じ理由)。
     *
     * RESPONDER_RESOURCES は「こちらが responder として同時に受け付ける
     * RDMA_READ 数」= 自 QP の max_dest_rd_atomic。**NVMe-oF の write は
     * ターゲットがホストのメモリから RDMA_READ で引く構造**なので、
     * ここを小さく広告すると**相手ターゲットがその本数までしかデータを
     * 引き込めず、write のスループットがそこで頭打ちになる**。
     * INIT2RTR / RTR2RTS では既に log_rra_max = min(cap, 4) = 16 本を
     * 設定しているのに、CM では 4 と名乗っていた(食い違っていた)。
     *
     * INITIATOR_DEPTH は「こちらが initiator として投げる数」。相手は
     * これを自分の max_dest_rd_atomic に設定する。 */
    {
        uint32_t res_cap = 1u << ((ctx->dev->log_max_ra_res_qp > 4u)
                                  ? 4u : ctx->dev->log_max_ra_res_qp);
        uint32_t ini_cap = mlx5_qp_max_concurrent_rdma_read(ctx->dev);
        if (res_cap == 0u) res_cap = 1u;
        if (ini_cap == 0u) ini_cap = 1u;
        if (res_cap > 255u) res_cap = 255u;
        if (ini_cap > 255u) ini_cap = 255u;
        if (s_rr_override != 0u) res_cap = s_rr_override;
        p[35] = (uint8_t)res_cap; // RESPONDER_RESOURCES(= INIT2RTR の log_rra_max)
        p[39] = (uint8_t)ini_cap; // INITIATOR_DEPTH(= RTR2RTS の log_sra_max)
    }
    p[43] = (uint8_t)(20u << 3); // REMOTE_CM_RESPONSE_TIMEOUT(pos0-4)=20、
    p[44] = (uint8_t)(ctx->rc_qp.local_psn >> 16);
    p[45] = (uint8_t)(ctx->rc_qp.local_psn >> 8);
    p[46] = (uint8_t)ctx->rc_qp.local_psn; // STARTING_PSN(24bit)
    p[47] = (uint8_t)((20u << 3) | 7u); // LOCAL_CM_RESPONSE_TIMEOUT(pos0-4)=20、RETRY_COUNT(pos5-7)=7
    p[48] = 0xFF;
    p[49] = 0xFF; // PARTITION_KEY(pkey、フル権限0xFFFF)
    p[50] = (uint8_t)(((ctx->req_path_mtu ? ctx->req_path_mtu : 3u) << 4) | 7u); // PATH_PACKET_PAYLOAD_MTU(pos0-3)=既定 IB_MTU_1024(3)、
                                        // RDC_EXISTS(pos4)=0、RNR_RETRY_COUNT(pos5-7)=7
    p[51] = (uint8_t)(3u << 4); // MAX_CM_RETRIES(pos0-3)=3、SRQ(pos4)=0、EXTENDED_TRANSPORT_TYPE(pos5-7)=0(RC)
    for (unsigned i = 0; i < 16; i++) {
        p[56 + i] = ctx->own_gid[i]; // PRIMARY_LOCAL_PORT_GID
        p[72 + i] = ctx->peer_gid[i]; // PRIMARY_REMOTE_PORT_GID
    }
    // PRIMARY_FLOW_LABEL(p88-90上位nibble)/PACKET_RATE/TRAFFIC_CLASS: 0のまま。
    p[93] = 64; // PRIMARY_HOP_LIMIT
    p[95] = (uint8_t)(14u << 3); // PRIMARY_LOCAL_ACK_TIMEOUT(pos0-4)=14

    // PRIVATE_DATA(p[140..231]、92バイト) = cma_hdr(36B)+nvme_rdma_cm_req(32B)+padding(24B)。
    volatile uint8_t *priv = &p[140];
    priv[0] = 0; // cma_hdr.cma_version = CMA_VERSION(0)
    priv[1] = (uint8_t)(4u << 4); // cma_hdr.ip_version = 4(IPv4)<<4
    wr16be_ib(&priv[2], ctx->src_port); // cma_hdr.port(相手から見た自分のポート)
    // priv[4..19] = src_addr(union cma_ip_addr、16B) -- IPv4は末尾4Bのみ使用。
    wr32be_ib(&priv[16], ctx->own_ip);
    // priv[20..35] = dst_addr(16B)。
    wr32be_ib(&priv[32], ctx->peer_ip);
    if (ctx->rep_priv_out_len) {   /* NVMe-oF 以外(iSER の iser_cm_hdr)*/
        for (unsigned i = 0; i < ctx->rep_priv_out_len && i < sizeof(ctx->rep_priv_out); i++)
            priv[36 + i] = ctx->rep_priv_out[i];
        return;
    }
    wr16le(&priv[36], 0); // recfmt = NVME_RDMA_CM_FMT_1_0
    wr16le(&priv[38], ctx->nvme_qid); // qid
    wr16le(&priv[40], ctx->hrqsize); // hrqsize(1's based)
    wr16le(&priv[42], ctx->hsqsize); // hsqsize(**0's based**)
    wr16le(&priv[44], ctx->cntlid);  // cntlid(admin は 0xFFFF)
}

/*=================================================================
 * CM REP を組み立てる(Table 110)。REQ と違い cma_hdr は含めない。
 *
 * 引数:
 *   ctx - CM コンテキスト
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static void rdma_cm_build_rep(rdma_cm_ctx_t *ctx) {
    volatile uint8_t *buf = ctx->send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) {
        buf[i] = 0;
    }
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND,
                     ctx->tid, CM_REP_ATTR_ID, 0);
    volatile uint8_t *p = &buf[IB_MAD_HDR_LEN];

    wr32be_ib(&p[0], ctx->local_comm_id); // LOCAL_COMM_ID(responder自身)
    wr32be_ib(&p[4], ctx->remote_comm_id); // REMOTE_COMM_ID(REQのLOCAL_COMM_IDをecho)
    wr32be_ib(&p[8], 0); // LOCAL_Q_KEY
    p[12] = (uint8_t)(ctx->rc_qp.qpn >> 16);
    p[13] = (uint8_t)(ctx->rc_qp.qpn >> 8);
    p[14] = (uint8_t)ctx->rc_qp.qpn; // LOCAL_QPN(24bit)
    p[20] = (uint8_t)(ctx->rc_qp.local_psn >> 16);
    p[21] = (uint8_t)(ctx->rc_qp.local_psn >> 8);
    p[22] = (uint8_t)ctx->rc_qp.local_psn; // STARTING_PSN(24bit)
    /* **ここを固定値にしてはいけない。** INITIATOR_DEPTH は「こちらが
     * initiator として同時に投げる RDMA_READ 数」で、**相手はこの値を自分の
     * QP の max_dest_rd_atomic に設定する**。4 固定のまま 16 本投げていたため、
     * Linux ホストを繋ぐと数千コマンドに 1 回 REMOTE_INVAL_REQ_ERR
     * (syndrome=0x12)で落ちていた(自作イニシエータは 4 本しか投げないので
     * 自作どうしでは表に出ない)。
     * 相手の RESPONDER_RESOURCES(受け付けられる数)とこちらの HCA 上限の
     * 小さいほうを採る。 */
    {
        uint32_t own_cap = mlx5_qp_max_concurrent_rdma_read(ctx->dev);
        if (own_cap == 0u)   own_cap = 1u;
        if (own_cap > 255u)  own_cap = 255u;
        uint32_t depth = own_cap;
        if (ctx->peer_responder_resources != 0u && ctx->peer_responder_resources < depth) {
            depth = ctx->peer_responder_resources;
        }
        ctx->negotiated_initiator_depth = (uint8_t)depth;
        p[24] = (uint8_t)own_cap;  // RESPONDER_RESOURCES(こちらが受け付ける数)
        p[25] = (uint8_t)depth;    // INITIATOR_DEPTH(こちらが投げる数)
    }
    p[26] = (uint8_t)(14u << 3); // TARGET_ACK_DELAY(pos0-4)=14
    p[27] = (uint8_t)(7u << 5); // RNR_RETRY_COUNT(pos0-2)=7
    wr64be(&p[28], 0); // LOCAL_CA_GUID(プレースホルダ)

    // PRIVATE_DATA(p[36..231]、196バイト) = nvme_rdma_cm_rep(32B)+padding。
    volatile uint8_t *priv = &p[36];
    if (ctx->rep_priv_out_len) {
        for (unsigned i = 0; i < ctx->rep_priv_out_len && i < sizeof(ctx->rep_priv_out); i++)
            priv[i] = ctx->rep_priv_out[i];
        return;
    }
    wr16le(&priv[0], 0); // recfmt
    wr16le(&priv[2], 32); // crqsize(プレースホルダ)
}

/*=================================================================
 * CM RTU を組み立てる(Table 111)。NVMe-oF では private data 無し。
 *
 * 引数:
 *   ctx - CM コンテキスト
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static void rdma_cm_build_rtu(rdma_cm_ctx_t *ctx) {
    volatile uint8_t *buf = ctx->send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) {
        buf[i] = 0;
    }
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND,
                     ctx->tid, CM_RTU_ATTR_ID, 0);
    volatile uint8_t *p = &buf[IB_MAD_HDR_LEN];
    wr32be_ib(&p[0], ctx->local_comm_id);
    wr32be_ib(&p[4], ctx->remote_comm_id);
}

/*=================================================================
 * 受信 REQ から相手の RC QPN / 開始 PSN / comm_id / GID / path MTU を
 * 取り出す。GID とワイヤ上の path MTU は事前設定値より優先する。
 *
 * 引数:
 *   ctx      - 結果を書き込む CM コンテキスト
 *   recv_buf - 受信バッファ(GRH から)
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static void rdma_cm_parse_req(rdma_cm_ctx_t *ctx, const volatile uint8_t *recv_buf) {
    const volatile uint8_t *p = &recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    ctx->remote_comm_id = rd32be_ib(&p[0]);
    ctx->peer_rc_qpn = ((uint32_t)p[32] << 16) | ((uint32_t)p[33] << 8) | p[34];
    ctx->peer_starting_psn = ((uint32_t)p[44] << 16) | ((uint32_t)p[45] << 8) | p[46];
    ctx->peer_path_mtu = (uint8_t)((p[50] >> 4) & 0x0Fu);
    ctx->peer_responder_resources = p[35];
    ctx->peer_initiator_depth     = p[39];
    for (unsigned i = 0; i < 16; i++) {
        ctx->peer_gid[i] = p[56 + i];
    }
}

/*=================================================================
 * 受信 REP から相手の RC QPN / 開始 PSN / comm_id を取り出す。
 *
 * 引数:
 *   ctx      - 結果を書き込む CM コンテキスト
 *   recv_buf - 受信バッファ(GRH から)
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static void rdma_cm_parse_rep(rdma_cm_ctx_t *ctx, const volatile uint8_t *recv_buf) {
    const volatile uint8_t *p = &recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    ctx->remote_comm_id = rd32be_ib(&p[0]);
    ctx->peer_rc_qpn = ((uint32_t)p[12] << 16) | ((uint32_t)p[13] << 8) | p[14];
    ctx->peer_starting_psn = ((uint32_t)p[20] << 16) | ((uint32_t)p[21] << 8) | p[22];
    for (unsigned i = 0; i < sizeof(ctx->rep_priv); i++) {
        ctx->rep_priv[i] = p[36 + i]; // PRIVATE_DATA(p[36..231])
    }
}

/*=================================================================
 * 共有 GSI の受信の振り分け。
 *
 * GSI(QP1)は 1 ポートに 1 本しか無く、自作 RDMA ターゲットでは admin と
 * IO キューの CM、それに admin の切断検出(DREQ 待ち)が同じ 1 本を
 * のぞいている。**受信完了を拾った側がその MAD の宛先とは限らない**ので、
 * 拾った MAD はいったんここの待ち行列に入れ、各自が「自分の欲しいもの」を
 * 取り出す(REQ は REQ 待ちの受け皿、RTU は comm_id が合う受け皿、DREQ は
 * admin の切断処理)。以前は拾った側が自分に関係なければ捨てていたので、
 * IO キューの RTU を admin が横取りして 3 秒待たせ、DREQ を取りこぼして
 * 繋ぎ直しが通らなくなっていた。
 *
 * 拾われずに残った MAD は CM_MUX_AGE_MS で捨てる(相手が再送してくる)。
 * GSI の CQ は複数のコアから触られるので、ポーリングごと spinlock で守る。
 * ===============================================================*/
#define CM_MUX_SLOTS  8u
#define CM_MUX_AGE_MS 3000u
#define CM_MUX_PREPOST 16u          /* GSI を作ったときに投稿しておく受信 WQE の数 */

typedef struct {
    mlx5_dev_t *dev;
    volatile uint32_t lock;
    struct {
        uint8_t  used;
        uint16_t attr;
        uint32_t len;
        uint64_t t;
        uint8_t  mad[MLX5_GRH_BYTES + RDMA_CM_MAD_SIZE];
    } q[CM_MUX_SLOTS];
} cm_mux_t;

static cm_mux_t s_cm_mux[2];

static cm_mux_t *cm_mux_for(mlx5_dev_t *dev) {
    for (unsigned i = 0; i < 2; i++) {
        if (s_cm_mux[i].dev == dev) return &s_cm_mux[i];
    }
    for (unsigned i = 0; i < 2; i++) {
        mlx5_dev_t *expected = NULL;
        if (__atomic_compare_exchange_n(&s_cm_mux[i].dev, &expected, dev, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) || expected == dev) {
            return &s_cm_mux[i];
        }
    }
    return &s_cm_mux[0];
}

static void cm_mux_lock(cm_mux_t *m) {
    while (__atomic_exchange_n(&m->lock, 1u, __ATOMIC_ACQUIRE)) {
        __builtin_ia32_pause();
    }
}

static void cm_mux_unlock(cm_mux_t *m) {
    __atomic_store_n(&m->lock, 0u, __ATOMIC_RELEASE);
}

/* GSI を作り直したら、前の GSI で拾って残っている MAD を捨てる。 */
static void cm_mux_reset(mlx5_dev_t *dev) {
    cm_mux_t *m = cm_mux_for(dev);
    cm_mux_lock(m);
    for (unsigned i = 0; i < CM_MUX_SLOTS; i++) m->q[i].used = 0;
    cm_mux_unlock(m);
}

/* MAD のペイロード(MAD ヘッダの後ろ)。CM の各メッセージは先頭が
 * LOCAL_COMM_ID、その次が REMOTE_COMM_ID。 */
static inline const uint8_t *cm_mad_payload(const uint8_t *mad) {
    return &mad[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
}

static inline uint32_t cm_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/*=================================================================
 * GSI の CQ を空になるまで拾って待ち行列へ入れ、want() が受け取ると
 * 言った最も古い MAD を ctx->recv_buf へ写して返す。
 *
 * 引数:
 *   ctx       - 取り出す側の CM コンテキスト(GSI と recv_buf を使う)
 *   want      - attr とペイロードを見て、受け取るなら 1 を返す
 *   out_len   - 受け取った長さ(NULL 可)
 *   out_synd  - CQE エラーのときの syndrome(NULL 可)
 * 戻り値:
 *   1=受け取った、0=無い、-1=GSI の CQE エラー
 * コール元:
 *   rdma_cm_job_step(), rdma_cm_disconnect(), rdma_cm_take_dreq()
 * ===============================================================*/
typedef int (*cm_want_fn)(const rdma_cm_ctx_t *ctx, uint16_t attr, const uint8_t *payload);

static int cm_gsi_take(rdma_cm_ctx_t *ctx, cm_want_fn want, uint32_t *out_len, uint8_t *out_synd) {
    cm_mux_t *m = cm_mux_for(ctx->dev);
    int ret = 0;
    cm_mux_lock(m);
    for (unsigned n = 0; n < 32u; n++) {
        int is_send = 0;
        uint32_t len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe_gsi(ctx->dev, ctx->gsi_qp, &is_send, &len, &synd);
        if (rc == 0) break;
        if (rc < 0) {
            if (out_synd) *out_synd = synd;
            ret = -1;
            break;
        }
        if (is_send) continue;      /* 自分たちが送った MAD の送信完了 */
        const volatile uint8_t *rx = mlx5_qp_gsi_last_rx(ctx->dev);
        unsigned slot = 0;
        for (unsigned i = 0; i < CM_MUX_SLOTS; i++) {   /* 空き、無ければ最も古い枠 */
            if (!m->q[i].used) { slot = i; break; }
            if (m->q[i].t < m->q[slot].t) slot = i;
        }
        if (len > sizeof(m->q[slot].mad)) len = sizeof(m->q[slot].mad);
        for (uint32_t b = 0; rx && b < len; b++) m->q[slot].mad[b] = rx[b];
        m->q[slot].len  = len;
        m->q[slot].attr = rx ? rdma_cm_recv_attr_id(rx) : 0;
        m->q[slot].t    = timer_now();
        m->q[slot].used = (rx != NULL);
        /* 消費した受信 WQE の代わりを投稿する(受信先は GSI のリング) */
        mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                              sizeof(ctx->recv_buf));
    }
    if (ret == 0) {
        int pick = -1;
        for (unsigned i = 0; i < CM_MUX_SLOTS; i++) {
            if (!m->q[i].used) continue;
            if (timeout_ms(m->q[i].t, CM_MUX_AGE_MS)) {
                /* 誰も受け取らなかった。相手の再送に任せる。**捨てたものは必ず
                 * 表示する** -- 相手が REJ を返していたのに捨てていて 3 時間
                 * 気付かなかったことがある(CLAUDE.md)。 */
                const uint8_t *pl = cm_mad_payload(m->q[i].mad);
                uart_printf("rdma_cm: 受け手の居ない MAD を捨てた attr_id=0x%04x "
                            "local_comm=0x%08x remote_comm=0x%08x\n",
                            m->q[i].attr, cm_be32(&pl[0]), cm_be32(&pl[4]));
                m->q[i].used = 0;
                continue;
            }
            if (!want(ctx, m->q[i].attr, cm_mad_payload(m->q[i].mad))) continue;
            if (pick < 0 || m->q[i].t < m->q[pick].t) pick = (int)i;
        }
        if (pick >= 0) {
            for (uint32_t b = 0; b < m->q[pick].len; b++) ctx->recv_buf[b] = m->q[pick].mad[b];
            if (out_len) *out_len = m->q[pick].len;
            m->q[pick].used = 0;
            ret = 1;
        }
    }
    cm_mux_unlock(m);
    return ret;
}

static int cm_want_rep_or_rej(const rdma_cm_ctx_t *ctx, uint16_t attr, const uint8_t *pl) {
    /* REP / REJ の REMOTE_COMM_ID はこちらの LOCAL_COMM_ID */
    return (attr == CM_REP_ATTR_ID || attr == CM_REJ_ATTR_ID) && cm_be32(&pl[4]) == ctx->local_comm_id;
}

static int cm_want_req(const rdma_cm_ctx_t *ctx, uint16_t attr, const uint8_t *pl) {
    if (attr != CM_REQ_ATTR_ID) return 0;
    if (ctx->listen_port == 0) return 1;
    /* SERVICE_ID(REQ の 8〜15 バイト)= (RDMA_PS_TCP << 16) + ポート。下位 16 ビットだけ見る。 */
    return (uint16_t)(((uint16_t)pl[14] << 8) | pl[15]) == ctx->listen_port;
}

static int cm_want_rtu(const rdma_cm_ctx_t *ctx, uint16_t attr, const uint8_t *pl) {
    return attr == CM_RTU_ATTR_ID && cm_be32(&pl[4]) == ctx->local_comm_id;
}

static int cm_want_drep(const rdma_cm_ctx_t *ctx, uint16_t attr, const uint8_t *pl) {
    return attr == CM_DREP_ATTR_ID && cm_be32(&pl[4]) == ctx->local_comm_id;
}

static int cm_want_dreq(const rdma_cm_ctx_t *ctx, uint16_t attr, const uint8_t *pl) {
    (void)ctx; (void)pl;
    return attr == CM_DREQ_ATTR_ID;
}

/* 共有 GSI から DREQ を 1 つ取り出して ctx->recv_buf へ写す(宛先は問わない。
 * どの接続の DREQ かは呼び出し側が REMOTE_COMM_ID で判断する)。 */
int rdma_cm_take_dreq(rdma_cm_ctx_t *ctx, uint32_t *out_len) {
    return cm_gsi_take(ctx, cm_want_dreq, out_len, NULL);
}

/*=================================================================
 * GSI QP を 1 本作って RTS まで遷移させ、初回 RECV WQE を投稿する。
 * GID テーブル index0 への自 GID 登録(RC QP 側とも共有)もここで行う。
 *
 * 引数:
 *   ctx - CM コンテキスト
 * 戻り値:
 *   0=成功、-1=作成/遷移失敗
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static int rdma_cm_setup_gsi(rdma_cm_ctx_t *ctx) {
    if (mlx5_qp_create_gsi(ctx->dev, ctx->gsi_qp) != 0) {
        uart_printf("rdma_cm: FAILED (GSI CREATE_QP)\n");
        return -1;
    }
    if (mlx5_set_roce_address(ctx->dev, 0, ctx->own_gid, ctx->own_mac) != 0) {
        uart_printf("rdma_cm: FAILED (SET_ROCE_ADDRESS)\n");
        return -1;
    }
    /* [切り分け] 登録した GID テーブル index0 を読み戻す。vhca_port_num を
     * 0 と 1 の両方で引いて、どちらの表に入ったのかを見る。 */
    for (uint8_t vp = 0; vp <= 1u; vp++) {
        uint8_t g[16], m[6], l3 = 0, ver = 0;
        if (mlx5_query_roce_address(ctx->dev, 0, vp, g, m, &l3, &ver) == 0) {
            uart_printf("rdma_cm: [DBG] GID[0] vhca_port=%u -> ipv4=%u.%u.%u.%u "
                        "mac=%02x:%02x:%02x:%02x:%02x:%02x l3=%u ver=%u\n",
                        vp, g[12], g[13], g[14], g[15],
                        m[0], m[1], m[2], m[3], m[4], m[5], l3, ver);
        }
    }
    uart_printf("rdma_cm: [DBG] 期待値 own=%u.%u.%u.%u/%02x:%02x:%02x:%02x:%02x:%02x "
                "peer=%u.%u.%u.%u/%02x:%02x:%02x:%02x:%02x:%02x\n",
                ctx->own_gid[12], ctx->own_gid[13], ctx->own_gid[14], ctx->own_gid[15],
                ctx->own_mac[0], ctx->own_mac[1], ctx->own_mac[2],
                ctx->own_mac[3], ctx->own_mac[4], ctx->own_mac[5],
                ctx->peer_gid[12], ctx->peer_gid[13], ctx->peer_gid[14], ctx->peer_gid[15],
                ctx->peer_mac[0], ctx->peer_mac[1], ctx->peer_mac[2],
                ctx->peer_mac[3], ctx->peer_mac[4], ctx->peer_mac[5]);
    ctx->gsi_qp->local_gid_index = 0;
    if (mlx5_qp_modify_rst2init_ud(ctx->dev, ctx->gsi_qp, IB_QP1_QKEY) != 0 ||
        mlx5_qp_modify_init2rtr_ud(ctx->dev, ctx->gsi_qp) != 0 ||
        mlx5_qp_modify_rtr2rts_ud(ctx->dev, ctx->gsi_qp) != 0) {
        uart_printf("rdma_cm: FAILED (GSI QP state transitions)\n");
        return -1;
    }
    cm_mux_reset(ctx->dev);
    for (unsigned i = 0; i < CM_MUX_PREPOST; i++) {
        if (mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                                  sizeof(ctx->recv_buf)) != 0) {
            uart_printf("rdma_cm: FAILED (GSI post_recv)\n");
            return -1;
        }
    }
    return 0;
}

/*=================================================================
 * GSI を新規作成せず、呼び出し元が ctx->gsi_qp に共有させた既存の(既に
 * RTS の)GSI QP をそのまま使う。1 PF につき GSI は物理的に 1 本しか無い
 * ため、2 本目の CM(IO キュー用)はこちらを使う。RECV WQE の再武装だけ行う。
 *
 * 引数:
 *   ctx - CM コンテキスト(gsi_qp が既に設定済みであること)
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static int rdma_cm_setup_gsi_reused(rdma_cm_ctx_t *ctx) {
    /* 受信 WQE は GSI を作った側が投稿済みで、拾うたびに cm_gsi_take() が
     * 補充する(受信先も GSI のリング)。ここで足すことは無い。 */
    (void)ctx;
    return 0;
}

/*=================================================================
 * RC QP を 1 本作り RST->INIT まで遷移させる(相手の情報が揃うのは REQ/REP
 * 受信後なので、ここでは INIT 止まり)。
 *
 * 引数:
 *   ctx - CM コンテキスト(rc_qp_index で admin 用/IO 用を選ぶ)
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   rdma_cm_job_step()
 * ===============================================================*/
static int rdma_cm_setup_rc(rdma_cm_ctx_t *ctx) {
    if (mlx5_qp_create_rc_ex(ctx->dev, &ctx->rc_qp, ctx->rc_qp_index, ctx->rc_cs_req) != 0) {
        uart_printf("rdma_cm: FAILED (RC CREATE_QP)\n");
        return -1;
    }
    ctx->rc_qp.local_gid_index = 0;
    if (mlx5_qp_modify_rst2init(ctx->dev, &ctx->rc_qp) != 0) {
        uart_printf("rdma_cm: FAILED (RC RST2INIT_QP)\n");
        return -1;
    }
    return 0;
}

/*=================================================================
 * IB CM(REQ/REP/RTU)のステートマシン 1 tick。active 側は
 * GSI/RC 準備 -> REQ 送信 -> REP 受信 -> RC を RTR/RTS へ -> RTU 送信、
 * passive 側は REQ 受信 -> RC を RTR/RTS へ -> REP 送信 -> RTU 受信 と進み、
 * RC QP が RTS になった時点で established を立てる。
 *
 * 引数:
 *   self - このジョブ(self->state が CM のステート)
 * 戻り値:
 *   JOB_WAITING=継続、JOB_DONE=確立完了/失敗で終了
 * コール元:
 *   job_scheduler_tick() から関数ポインタ経由
 * ===============================================================*/
job_result_t rdma_cm_job_step(job_t *self) {
    rdma_cm_ctx_t *ctx = (rdma_cm_ctx_t *)self->ctx;

    if (self->cancel_requested) {
        ctx->failed = 1;
        self->state = RDMA_CM_ST_DONE_FAIL;
        return JOB_DONE;
    }

    switch (self->state) {

    case RDMA_CM_ST_ACTIVE_SETUP: {
        int gsi_rc = ctx->reuse_gsi ? rdma_cm_setup_gsi_reused(ctx) : rdma_cm_setup_gsi(ctx);
        if (gsi_rc != 0 || rdma_cm_setup_rc(ctx) != 0) {
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        self->state = RDMA_CM_ST_ACTIVE_SEND_REQ;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_ACTIVE_SEND_REQ: {
        ctx->local_comm_id = (uint32_t)(timer_now() & 0xFFFFFFFFu) ^ 0xA5A5A5A5u;
        ctx->tid = timer_now() ^ 0x1122334455667788ull;
        rdma_cm_build_req(ctx);
        dcache_clean_range((const void *)(uintptr_t)ctx->send_buf, sizeof(ctx->send_buf));
        if (mlx5_qp_post_send_ud(ctx->dev, ctx->gsi_qp, (const void *)(uintptr_t)ctx->send_buf,
                                  RDMA_CM_MAD_SIZE, 1u /* GSI宛は常にQPN=1固定[フェーズd] */,
                                  IB_QP1_QKEY, ctx->peer_gid, ctx->peer_mac) != 0) {
            uart_printf("rdma_cm: FAILED (post REQ)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        uart_printf("rdma_cm: REQ sent (local_comm_id=0x%08x local_qpn=%u)\n",
                    ctx->local_comm_id, ctx->rc_qp.qpn);
        ctx->state_deadline = timer_now();
        self->state = RDMA_CM_ST_ACTIVE_WAIT_REP;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_ACTIVE_WAIT_REP: {
        uint8_t synd = 0;
        int rc = cm_gsi_take(ctx, cm_want_rep_or_rej, NULL, &synd);
        if (rc < 0) {
            uart_printf("rdma_cm: FAILED (GSI CQE error syndrome=0x%02x)\n", synd);
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        if (rc == 1) {
            dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, sizeof(ctx->recv_buf));
            if (rdma_cm_recv_attr_id(ctx->recv_buf) == CM_REP_ATTR_ID) {
                rdma_cm_parse_rep(ctx, ctx->recv_buf);
                uart_printf("rdma_cm: REP received (remote_comm_id=0x%08x peer_qpn=%u peer_psn=%u)\n",
                            ctx->remote_comm_id, ctx->peer_rc_qpn, ctx->peer_starting_psn);
                self->state = RDMA_CM_ST_ACTIVE_MODIFY_QP;
                return JOB_WAITING;
            }
            if (rdma_cm_recv_attr_id(ctx->recv_buf) == CM_REJ_ATTR_ID) {
                /* REJ の REASON はペイロード先頭から 10-11 バイト目。 */
                const volatile uint8_t *pp = &ctx->recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
                uint16_t reason = (uint16_t)(((uint16_t)pp[10] << 8) | pp[11]);
                const char *why = "?";
                if (reason == CM_REJ_STALE_CONN)              why = "古い接続が残っている(stale connection)";
                else if (reason == CM_REJ_INVALID_SERVICE_ID) why = "その SERVICE_ID で待ち受けていない";
                else if (reason == CM_REJ_CONSUMER_DEFINED)   why = "上位(NVMe-oF)が拒否";
                uart_printf("rdma_cm: REJ received (reason=%u %s)\n", (unsigned)reason, why);
                ctx->rej_reason = reason;
                ctx->failed = 1;
                self->state = RDMA_CM_ST_DONE_FAIL;
                return JOB_DONE;
            }
            return JOB_WAITING;
        }
        if (timeout_ms(ctx->state_deadline, RDMA_CM_REQ_RETRY_TIMEOUT_MS)) {
            ctx->retry_count++;
            if (ctx->retry_count >= RDMA_CM_REQ_MAX_RETRIES) {
                uart_printf("rdma_cm: FAILED (REP timeout, retries exhausted)\n");
                ctx->failed = 1;
                self->state = RDMA_CM_ST_DONE_FAIL;
                return JOB_DONE;
            }
            uart_printf("rdma_cm: REP timeout, retrying REQ (attempt %u)\n", ctx->retry_count + 1);
            self->state = RDMA_CM_ST_ACTIVE_SEND_REQ;
        }
        return JOB_WAITING;
    }

    case RDMA_CM_ST_ACTIVE_MODIFY_QP: {
        if (ctx->req_path_mtu) ctx->rc_qp.path_mtu = ctx->req_path_mtu;
        if (mlx5_qp_modify_init2rtr(ctx->dev, &ctx->rc_qp, ctx->peer_rc_qpn, ctx->peer_gid,
                                     ctx->peer_mac, ctx->peer_starting_psn) != 0 ||
            mlx5_qp_modify_rtr2rts(ctx->dev, &ctx->rc_qp) != 0) {
            uart_printf("rdma_cm: FAILED (RC QP INIT2RTR/RTR2RTS)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        ctx->established = 1;
        self->state = RDMA_CM_ST_ACTIVE_SEND_RTU;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_ACTIVE_SEND_RTU: {
        rdma_cm_build_rtu(ctx);
        dcache_clean_range((const void *)(uintptr_t)ctx->send_buf, sizeof(ctx->send_buf));
        if (mlx5_qp_post_send_ud(ctx->dev, ctx->gsi_qp, (const void *)(uintptr_t)ctx->send_buf,
                                  RDMA_CM_MAD_SIZE, 1u, IB_QP1_QKEY, ctx->peer_gid, ctx->peer_mac) != 0) {
            uart_printf("rdma_cm: FAILED (post RTU)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        uart_printf("rdma_cm: RTU sent -- RC QP established (active)\n");
        if (ctx->skip_ping) {
            ctx->rtu_phase_done = 1;   /* 能動側も「RTU まで済んだ」を見られるように(iSER のイニシエータ)*/
            self->state = RDMA_CM_ST_DONE_OK;
            return JOB_DONE;
        }
        self->state = RDMA_CM_ST_ACTIVE_PING_SEND;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_ACTIVE_PING_SEND: {
        if (mlx5_qp_post_send(ctx->dev, &ctx->rc_qp, RDMA_CM_PING_MSG, (uint32_t)sizeof(RDMA_CM_PING_MSG)) != 0) {
            uart_printf("rdma_cm: FAILED (RC QP post_send ping)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        ctx->state_deadline = timer_now();
        self->state = RDMA_CM_ST_ACTIVE_PING_WAIT;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_ACTIVE_PING_WAIT: {
        int is_send = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe(ctx->dev, &ctx->rc_qp, &is_send, NULL, &synd);
        if (rc == 1 && is_send) {
            uart_printf("rdma_cm: RC QP SEND completed (active) -- PASS\n");
            ctx->ping_ok = 1;
            self->state = RDMA_CM_ST_DONE_OK;
            return JOB_DONE;
        }
        if (rc < 0) {
            uart_printf("rdma_cm: FAILED (RC QP CQE error syndrome=0x%02x)\n", synd);
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        if (timeout_ms(ctx->state_deadline, RDMA_CM_PING_TIMEOUT_MS)) {
            uart_printf("rdma_cm: FAILED (RC QP ping send CQE timeout)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        return JOB_WAITING;
    }

    case RDMA_CM_ST_PASSIVE_SETUP: {
        int gsi_rc = ctx->reuse_gsi ? rdma_cm_setup_gsi_reused(ctx) : rdma_cm_setup_gsi(ctx);
        if (gsi_rc != 0 || rdma_cm_setup_rc(ctx) != 0) {
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        uart_printf("rdma_cm: passive side armed (rc_qp_index=%u reuse_gsi=%d), waiting for REQ...\n",
                    ctx->rc_qp_index, ctx->reuse_gsi);
        self->state = RDMA_CM_ST_PASSIVE_WAIT_REQ;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_PASSIVE_WAIT_REQ: {
        uint8_t synd = 0;
        int rc = cm_gsi_take(ctx, cm_want_req, NULL, &synd);
        if (rc < 0) {
            uart_printf("rdma_cm: FAILED (GSI CQE error syndrome=0x%02x)\n", synd);
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        if (rc == 1) {
            rdma_cm_parse_req(ctx, ctx->recv_buf);
            ctx->tid = rd64be(&ctx->recv_buf[MLX5_GRH_BYTES + 8]); // MADヘッダのtidをそのまま流用(REP/RTUで踏襲)
            ctx->local_comm_id = (uint32_t)(timer_now() & 0xFFFFFFFFu) ^ 0x5A5A5A5Au;
            uart_printf("rdma_cm: REQ received (remote_comm_id=0x%08x peer_qpn=%u peer_psn=%u)\n",
                        ctx->remote_comm_id, ctx->peer_rc_qpn, ctx->peer_starting_psn);
            self->state = RDMA_CM_ST_PASSIVE_MODIFY_QP;
            return JOB_WAITING;
        }
        return JOB_WAITING; // クライアント接続待ちはタイムアウトしない(nvmet.cのACCEPT_WAITと同じ方針)
    }

    case RDMA_CM_ST_PASSIVE_MODIFY_QP: {
        ctx->rc_qp.path_mtu = ctx->peer_path_mtu;
        if (mlx5_qp_modify_init2rtr(ctx->dev, &ctx->rc_qp, ctx->peer_rc_qpn, ctx->peer_gid,
                                     ctx->peer_mac, ctx->peer_starting_psn) != 0 ||
            mlx5_qp_modify_rtr2rts(ctx->dev, &ctx->rc_qp) != 0) {
            uart_printf("rdma_cm: FAILED (RC QP INIT2RTR/RTR2RTS)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        ctx->established = 1;
        if (!ctx->skip_ping) {
            if (mlx5_qp_post_recv(ctx->dev, &ctx->rc_qp, (void *)(uintptr_t)ctx->rc_recv_buf,
                                  sizeof(ctx->rc_recv_buf)) != 0) {
                uart_printf("rdma_cm: FAILED (RC QP post_recv for ping)\n");
                ctx->failed = 1;
                self->state = RDMA_CM_ST_DONE_FAIL;
                return JOB_DONE;
            }
        }
        self->state = RDMA_CM_ST_PASSIVE_SEND_REP;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_PASSIVE_SEND_REP: {
        rdma_cm_build_rep(ctx);
        dcache_clean_range((const void *)(uintptr_t)ctx->send_buf, sizeof(ctx->send_buf));
        if (mlx5_qp_post_send_ud(ctx->dev, ctx->gsi_qp, (const void *)(uintptr_t)ctx->send_buf,
                                  RDMA_CM_MAD_SIZE, 1u, IB_QP1_QKEY, ctx->peer_gid, ctx->peer_mac) != 0) {
            uart_printf("rdma_cm: FAILED (post REP)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        uart_printf("rdma_cm: REP sent (local_comm_id=0x%08x local_qpn=%u) -- RC QP already RTS\n",
                    ctx->local_comm_id, ctx->rc_qp.qpn);
        ctx->state_deadline = timer_now();
        self->state = RDMA_CM_ST_PASSIVE_WAIT_RTU;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_PASSIVE_WAIT_RTU: {
        int rc = cm_gsi_take(ctx, cm_want_rtu, NULL, NULL);
        if (rc == 1) {
            uart_printf("rdma_cm: RTU received (passive)\n");
            if (ctx->skip_ping) {
                ctx->rtu_phase_done = 1;
                self->state = RDMA_CM_ST_DONE_OK;
                return JOB_DONE;
            }
            self->state = RDMA_CM_ST_PASSIVE_PING_WAIT;
            return JOB_WAITING;
        }
        if (timeout_ms(ctx->state_deadline, RDMA_CM_RTU_WAIT_TIMEOUT_MS)) {
            uart_printf("rdma_cm: RTU not observed within %ums, but RC QP is already RTS "
                        "-- proceeding anyway (IBTA semantics)\n",
                        RDMA_CM_RTU_WAIT_TIMEOUT_MS);
            if (ctx->skip_ping) {
                ctx->rtu_phase_done = 1;
                self->state = RDMA_CM_ST_DONE_OK;
                return JOB_DONE;
            }
            self->state = RDMA_CM_ST_PASSIVE_PING_WAIT;
            ctx->state_deadline = timer_now();
        }
        return JOB_WAITING;
    }

    case RDMA_CM_ST_PASSIVE_PING_WAIT: {
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe(ctx->dev, &ctx->rc_qp, &is_send, &recv_len, &synd);
        if (rc == 1 && !is_send) {
            dcache_invalidate_range((const void *)(uintptr_t)ctx->rc_recv_buf, sizeof(ctx->rc_recv_buf));
            int match = (recv_len == sizeof(RDMA_CM_PING_MSG));
            for (unsigned i = 0; match && i < sizeof(RDMA_CM_PING_MSG); i++) {
                if (ctx->rc_recv_buf[i] != (uint8_t)RDMA_CM_PING_MSG[i]) {
                    match = 0;
                }
            }
            uart_printf("rdma_cm: RC QP RECV completed (passive, len=%u) -- %s\n",
                        recv_len, match ? "PASS" : "MISMATCH");
            ctx->ping_ok = match;
            self->state = match ? RDMA_CM_ST_DONE_OK : RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        if (rc < 0) {
            uart_printf("rdma_cm: FAILED (RC QP CQE error syndrome=0x%02x)\n", synd);
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        if (timeout_ms(ctx->state_deadline, RDMA_CM_PING_TIMEOUT_MS)) {
            uart_printf("rdma_cm: FAILED (RC QP ping recv timeout)\n");
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        return JOB_WAITING;
    }

    default:
        return JOB_DONE;
    }
}

/*=================================================================
 * CM コンテキストをゼロクリアし、HCA・自分/相手のラベル・IP・MAC から
 * GID と MAC を埋める。ゼロクリアで生じたダーティキャッシュラインが
 * 後の dcache_invalidate_range() で DMA 済みデータを上書きしないよう、
 * 最後に dcache_clean_range() をかける。
 *
 * 引数:
 *   ctx                - 初期化する CM コンテキスト
 *   dev                - 使用する HCA
 *   self_label         - 自分のインターフェース名(netif_find() で引く)
 *   peer_label         - 相手のインターフェース名(無ければ引けない名前)
 *   self_ip / peer_ip  - ラベルで引けない場合に使う IPv4
 *   self_mac_fallback  - 同上の自 MAC
 *   peer_mac_fallback  - 同上の相手 MAC(実ホスト接続では必須)
 * コール元:
 *   nvme_rdma_run_bench(), nvmetr_reset_admin_for_reconnect()
 * ===============================================================*/
void rdma_cm_fill_addr(rdma_cm_ctx_t *ctx, mlx5_dev_t *dev, const char *self_label,
                              const char *peer_label, uint32_t self_ip_fallback,
                              uint32_t peer_ip_fallback, const uint8_t self_mac_fallback[6],
                              const uint8_t peer_mac_fallback[6]) {
    for (unsigned i = 0; i < sizeof(*ctx); i++) {
        ((uint8_t *)ctx)[i] = 0;
    }
    dcache_clean_range((const void *)ctx, sizeof(*ctx));
    ctx->dev = dev;
    ctx->gsi_qp = &ctx->gsi_qp_storage;

    netif_t *self_nc = netif_find(self_label);
    if (self_nc != NULL) {
        ctx->own_ip = self_nc->ip;
        for (unsigned i = 0; i < 6; i++) ctx->own_mac[i] = self_nc->mac[i];
    } else {
        ctx->own_ip = self_ip_fallback;
        for (unsigned i = 0; i < 6; i++) ctx->own_mac[i] = self_mac_fallback[i];
    }
    netif_t *peer_nc = netif_find(peer_label);
    if (peer_nc != NULL) {
        ctx->peer_ip = peer_nc->ip;
        for (unsigned i = 0; i < 6; i++) ctx->peer_mac[i] = peer_nc->mac[i];
    } else {
        ctx->peer_ip = peer_ip_fallback;
        for (unsigned i = 0; i < 6; i++) ctx->peer_mac[i] = peer_mac_fallback[i];
    }
    mlx5_build_roce_gid_v4(ctx->own_ip, ctx->own_gid);
    mlx5_build_roce_gid_v4(ctx->peer_ip, ctx->peer_gid);

    /* CM REQ に載せる既定値。呼び出し側はこの後で上書きしてよい。 */
    ctx->service_port = RDMA_CM_DEFAULT_PORT;
    ctx->src_port     = RDMA_CM_DEFAULT_SRC_PORT;
    ctx->hrqsize      = RDMA_CM_DEFAULT_HRQSIZE;
    ctx->hsqsize      = RDMA_CM_DEFAULT_HSQSIZE;
    ctx->cntlid       = 0xFFFFu;
}

/*=================================================================
 * 確立済みの接続を CM の DREQ(IBTA Vol1 Table 114)で畳み、DREP を待つ。
 *
 * **これを送らないと相手(Linux の ib_cm)に接続が残る。** 次に同じ
 * (CA GUID, QPN) で REQ を出すと REJ reason=10(stale connection)で
 * 弾かれる。こちらは QP を作り直すと同じ QPN が再利用されるので当たりやすい。
 *
 * DREQ の REMOTE_QPN は**相手の QPN**(Linux の cm_dreq_handler() は
 * 自分の local_qpn と照合して、違えば黙って捨てる)。
 *
 * 引数:
 *   ctx        - 確立済みの CM コンテキスト(GSI と comm_id を使う)
 *   wait_ms    - DREP を待つ上限
 * 戻り値:
 *   0=DREP を受けた、-1=送信失敗、1=待ち切れ
 * コール元:
 *   rdma_short_disconnect()、nvme_rdma.c の nvmer_send_dreq()
 * ===============================================================*/
int rdma_cm_disconnect(rdma_cm_ctx_t *ctx, uint32_t wait_ms) {
    volatile uint8_t *buf = ctx->send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) {
        buf[i] = 0;
    }
    ctx->tid = timer_now() ^ 0x5566778899AABBCCull;
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND,
                     ctx->tid, CM_DREQ_ATTR_ID, 0);
    volatile uint8_t *p = &buf[IB_MAD_HDR_LEN];
    wr32be_ib(&p[0], ctx->local_comm_id);
    wr32be_ib(&p[4], ctx->remote_comm_id);
    p[8]  = (uint8_t)(ctx->peer_rc_qpn >> 16);
    p[9]  = (uint8_t)(ctx->peer_rc_qpn >> 8);
    p[10] = (uint8_t)ctx->peer_rc_qpn; // REMOTE_QPN(24bit)
    dcache_clean_range((const void *)(uintptr_t)ctx->send_buf, sizeof(ctx->send_buf));
    if (mlx5_qp_post_send_ud(ctx->dev, ctx->gsi_qp, (const void *)(uintptr_t)ctx->send_buf,
                              RDMA_CM_MAD_SIZE, 1u, IB_QP1_QKEY, ctx->peer_gid, ctx->peer_mac) != 0) {
        return -1;
    }
    uart_printf("rdma_cm: DREQ sent (local_comm_id=0x%08x remote_comm_id=0x%08x)\n",
                ctx->local_comm_id, ctx->remote_comm_id);

    uint64_t start = timer_now();
    while (!timeout_ms(start, wait_ms)) {
        uint8_t synd = 0;
        int rc = cm_gsi_take(ctx, cm_want_drep, NULL, &synd);
        if (rc < 0) {
            uart_printf("rdma_cm: DREQ: GSI CQE error syndrome=0x%02x\n", synd);
            return -1;
        }
        if (rc == 1) {
            uart_printf("rdma_cm: DREP received -- 切断完了\n");
            return 0;
        }
    }
    uart_printf("rdma_cm: DREP を待ち切れませんでした(%ums)\n", wait_ms);
    return 1;
}
