// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)
// フェーズ(e): 標準IB CM(REQ/REP/RTU)によるRC QP自動確立。
//
// ワイヤフォーマットの根拠はrdma_cm.hコメント参照(torvalds/linuxの
// drivers/infiniband/core/cm.c・cma.c・include/rdma/ibta_vol1_c12.h・
// include/linux/nvme-rdma.hを本セッションで実際に取得し裏取り済み)。
//
// GSI/UD QPのWQE組み立て(mlx5_qp_post_send_ud()等)・「GSI宛は常に宛先
// QPN=1固定」という規約は全てフェーズ(d)で確立・実機確認済みのものを
// そのまま再利用する。RC QPのWQE組み立て(mlx5_qp_post_send()/
// mlx5_qp_post_recv()/mlx5_qp_poll_cqe())はフェーズ(b)のものをそのまま
// 再利用する。

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
#define CM_REP_ATTR_ID 0x0013u
#define CM_RTU_ATTR_ID 0x0014u
#define IB_CM_CLASS_VERSION 2u // drivers/infiniband/core/cm_msgs.hで確認済み

// rdma_get_service_id()相当(実際は(ps<<16)+port)のプレースホルダ。
// フェーズ(e)はCM確立のみが目的でNVMe-oF Fabrics Connect自体は行わない
// ため、両端が一致していれば値そのものに意味は無い -- 実NVMe-oFホストとの
// 相互接続(フェーズi)までに正しい値を確認・実装すること。
#define RDMA_CM_SERVICE_ID_PLACEHOLDER 0x0000000000000001ull

#define RDMA_CM_REQ_RETRY_TIMEOUT_MS 2000u
#define RDMA_CM_REQ_MAX_RETRIES      3u
#define RDMA_CM_RTU_WAIT_TIMEOUT_MS  3000u
#define RDMA_CM_PING_TIMEOUT_MS      3000u

static const char RDMA_CM_PING_MSG[] = "rdma_cm phase(e) established ping-pong";

uint16_t rdma_cm_recv_attr_id(const volatile uint8_t *recv_buf) {
    return rd16be_ib(&recv_buf[MLX5_GRH_BYTES + 16]);
}

// REQペイロード(24バイトMADヘッダの直後を先頭とする)の各フィールドの
// バイトオフセットはinclude/rdma/ibta_vol1_c12.hのTable 106そのもの。
static void rdma_cm_build_req(rdma_cm_ctx_t *ctx) {
    volatile uint8_t *buf = ctx->send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) {
        buf[i] = 0;
    }
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND,
                     ctx->tid, CM_REQ_ATTR_ID, 0);
    volatile uint8_t *p = &buf[IB_MAD_HDR_LEN];

    wr32be_ib(&p[0], ctx->local_comm_id); // LOCAL_COMM_ID
    wr64be(&p[8], RDMA_CM_SERVICE_ID_PLACEHOLDER); // SERVICE_ID
    wr64be(&p[16], 0); // LOCAL_CA_GUID(プレースホルダ、未使用)
    wr32be_ib(&p[28], 0); // LOCAL_Q_KEY(RCでは不要)
    p[32] = (uint8_t)(ctx->rc_qp.qpn >> 16);
    p[33] = (uint8_t)(ctx->rc_qp.qpn >> 8);
    p[34] = (uint8_t)ctx->rc_qp.qpn; // LOCAL_QPN(24bit)
    p[35] = 4; // RESPONDER_RESOURCES(max_dest_rd_atomic、log_rra_max=2->4と揃える)
    p[39] = 4; // INITIATOR_DEPTH(log_sra_max=2->4)
    p[43] = (uint8_t)(20u << 3); // REMOTE_CM_RESPONSE_TIMEOUT(pos0-4)=20、
                                  // TRANSPORT_SERVICE_TYPE(pos5-6)=0(RC)、
                                  // END_TO_END_FLOW_CONTROL(pos7)=0
    p[44] = (uint8_t)(ctx->rc_qp.local_psn >> 16);
    p[45] = (uint8_t)(ctx->rc_qp.local_psn >> 8);
    p[46] = (uint8_t)ctx->rc_qp.local_psn; // STARTING_PSN(24bit)
    p[47] = (uint8_t)((20u << 3) | 7u); // LOCAL_CM_RESPONSE_TIMEOUT(pos0-4)=20、RETRY_COUNT(pos5-7)=7
    p[48] = 0xFF;
    p[49] = 0xFF; // PARTITION_KEY(pkey、フル権限0xFFFF)
    p[50] = (uint8_t)((3u << 4) | 7u); // PATH_PACKET_PAYLOAD_MTU(pos0-3)=IB_MTU_1024(3)、
                                        // RDC_EXISTS(pos4)=0、RNR_RETRY_COUNT(pos5-7)=7
    p[51] = (uint8_t)(3u << 4); // MAX_CM_RETRIES(pos0-3)=3、SRQ(pos4)=0、EXTENDED_TRANSPORT_TYPE(pos5-7)=0(RC)
    // PRIMARY_LOCAL_PORT_LID/PRIMARY_REMOTE_PORT_LID(p[52..55]): RoCEでは
    // LID概念自体が無いため0のまま(GID[p56..87]がRoCEv2の実アドレス)。
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
    wr16be_ib(&priv[2], 0); // cma_hdr.port(プレースホルダ)
    // priv[4..19] = src_addr(union cma_ip_addr、16B) -- IPv4は末尾4Bのみ使用。
    wr32be_ib(&priv[16], ctx->own_ip);
    // priv[20..35] = dst_addr(16B)。
    wr32be_ib(&priv[32], ctx->peer_ip);
    // nvme_rdma_cm_req(priv[36..67]、32B、全フィールドLE -- include/linux/
    // nvme-rdma.hのstruct nvme_rdma_cm_reqと同じ、net.hのwr16le流儀)。
    wr16le(&priv[36], 0); // recfmt = NVME_RDMA_CM_FMT_1_0
    wr16le(&priv[38], ctx->nvme_qid); // qid
    wr16le(&priv[40], 32); // hrqsize(プレースホルダ)
    wr16le(&priv[42], 32); // hsqsize(プレースホルダ)
    wr16le(&priv[44], 0xFFFFu); // cntlid(未接続)
}

// REPペイロード(Table 110)。cma_hdrは含まない(cma_accept_ib()確認済み)。
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
    p[24] = 4; // RESPONDER_RESOURCES
    p[25] = 4; // INITIATOR_DEPTH
    p[26] = (uint8_t)(14u << 3); // TARGET_ACK_DELAY(pos0-4)=14
    p[27] = (uint8_t)(7u << 5); // RNR_RETRY_COUNT(pos0-2)=7
    wr64be(&p[28], 0); // LOCAL_CA_GUID(プレースホルダ)

    // PRIVATE_DATA(p[36..231]、196バイト) = nvme_rdma_cm_rep(32B)+padding。
    volatile uint8_t *priv = &p[36];
    wr16le(&priv[0], 0); // recfmt
    wr16le(&priv[2], 32); // crqsize(プレースホルダ)
}

// RTUペイロード(Table 111)。NVMe-oFではprivate data無しが通常。
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

// 受信したREQペイロードから、相手のRC QPN/開始PSN/comm_idを取り出す。
// GID(PRIMARY_LOCAL_PORT_GID、REQ送信者自身のGID)も取り出して上書きする
// -- 呼び出し元がpeer_gidを事前設定済みでも、ワイヤ上の実際の値を正とする
// (実接続[フェーズi]で動的な相手を扱うことを見据えた設計)。MACはIBTA CM
// メッセージに一切含まれないため、呼び出し元が事前設定した値をそのまま
// 使う(このプロジェクトのフェーズ(b)/(c)/(d)診断コードと同じ、固定
// トポロジのループバック検証という前提に基づく)。
static void rdma_cm_parse_req(rdma_cm_ctx_t *ctx, const volatile uint8_t *recv_buf) {
    const volatile uint8_t *p = &recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    ctx->remote_comm_id = rd32be_ib(&p[0]);
    ctx->peer_rc_qpn = ((uint32_t)p[32] << 16) | ((uint32_t)p[33] << 8) | p[34];
    ctx->peer_starting_psn = ((uint32_t)p[44] << 16) | ((uint32_t)p[45] << 8) | p[46];
    // PATH_PACKET_PAYLOAD_MTU: REQ byte50のbits[7:4](高nibble、IBTA
    // pos0-3、この関数の送信側ビルドp[50]=(mtu<<4)|...と対称)。RC接続の
    // 両端が同じpath MTUを使うため、passive側はこれをRC QPへ反映する
    // (rdma_cm.cのPASSIVE_MODIFY_QP参照)。
    ctx->peer_path_mtu = (uint8_t)((p[50] >> 4) & 0x0Fu);
    for (unsigned i = 0; i < 16; i++) {
        ctx->peer_gid[i] = p[56 + i];
    }
}

static void rdma_cm_parse_rep(rdma_cm_ctx_t *ctx, const volatile uint8_t *recv_buf) {
    const volatile uint8_t *p = &recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    ctx->remote_comm_id = rd32be_ib(&p[0]);
    ctx->peer_rc_qpn = ((uint32_t)p[12] << 16) | ((uint32_t)p[13] << 8) | p[14];
    ctx->peer_starting_psn = ((uint32_t)p[20] << 16) | ((uint32_t)p[21] << 8) | p[22];
}

// GSI QPを1本作りRTSまで遷移させ、初回のRECV WQEを1個投稿する
// (フェーズ(d)のmlx5_gsi_mad_test()と同じ手順)。共通のGID登録
// (自分のGIDテーブルindex0、RC QP側もこれを共有する)もここで行う。
static int rdma_cm_setup_gsi(rdma_cm_ctx_t *ctx) {
    if (mlx5_qp_create_gsi(ctx->dev, ctx->gsi_qp) != 0) {
        uart_printf("rdma_cm: FAILED (GSI CREATE_QP)\n");
        return -1;
    }
    if (mlx5_set_roce_address(ctx->dev, 0, ctx->own_gid, ctx->own_mac) != 0) {
        uart_printf("rdma_cm: FAILED (SET_ROCE_ADDRESS)\n");
        return -1;
    }
    ctx->gsi_qp->local_gid_index = 0;
    if (mlx5_qp_modify_rst2init_ud(ctx->dev, ctx->gsi_qp, IB_QP1_QKEY) != 0 ||
        mlx5_qp_modify_init2rtr_ud(ctx->dev, ctx->gsi_qp) != 0 ||
        mlx5_qp_modify_rtr2rts_ud(ctx->dev, ctx->gsi_qp) != 0) {
        uart_printf("rdma_cm: FAILED (GSI QP state transitions)\n");
        return -1;
    }
    if (mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                              sizeof(ctx->recv_buf)) != 0) {
        uart_printf("rdma_cm: FAILED (GSI post_recv)\n");
        return -1;
    }
    return 0;
}

// フェーズ(i)続報(2026-08-13): GSIを新規作成せず、呼び出し元が事前に
// ctx->gsi_qpへコピーした既存の(既にRTS状態の)GSI QPをそのまま使い
// 回す -- 1PFにつきGSI/QP1相当は物理的に1つしか存在できないため
// (rdma_cm.hのreuse_gsiコメント参照、フェーズdの「宛先QPN=1固定」規約)。
// 次の受信に備えてRECV WQEを1個だけ再武装する(SET_ROCE_ADDRESS/状態
// 遷移は不要 -- 既に確立済みのGSI QPをそのまま流用するだけ)。
static int rdma_cm_setup_gsi_reused(rdma_cm_ctx_t *ctx) {
    if (mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                              sizeof(ctx->recv_buf)) != 0) {
        uart_printf("rdma_cm: FAILED (GSI post_recv, reused)\n");
        return -1;
    }
    return 0;
}

// RC QPを1本作りRST->INITまで遷移させる(相手の情報はまだ無いためここまで)。
// rc_qp_index(0=admin用、1=IOキュー用)はctxのフィールドをそのまま
// mlx5_qp_create_rc()へ渡す(rdma_cm.hのコメント参照)。
static int rdma_cm_setup_rc(rdma_cm_ctx_t *ctx) {
    if (mlx5_qp_create_rc(ctx->dev, &ctx->rc_qp, ctx->rc_qp_index) != 0) {
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

job_result_t rdma_cm_job_step(job_t *self) {
    rdma_cm_ctx_t *ctx = (rdma_cm_ctx_t *)self->ctx;

    /* `job stop <番号>`(job_request_cancel())やRoCEv2一括停止
     * (job_cancel_all_by_step()、pcie1 resetから)で停止要求が来たら、
     * どのステートでも即座に自己終了する -- passive側のREQ無期限待ち等、
     * 通常は自然にJOB_DONEへ到達しないステートでも確実に畳めるようにする
     * ため(job.hのジョブテーブルは.bssにあり pcie1 reset では消えない)。
     * 進行中のCMハンドシェイクを放棄しても、呼び出し元がこの直後に
     * ConnectXをリセット/再初期化する想定のため実害はない。 */
    if (self->cancel_requested) {
        ctx->failed = 1;
        self->state = RDMA_CM_ST_DONE_FAIL;
        return JOB_DONE;
    }

    switch (self->state) {

    // ------------------------------------------------------------------
    // active(REQ送信側)
    // ------------------------------------------------------------------
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
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe_gsi(ctx->dev, ctx->gsi_qp, &is_send, &recv_len, &synd);
        if (rc < 0) {
            uart_printf("rdma_cm: FAILED (GSI CQE error syndrome=0x%02x)\n", synd);
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        if (rc == 1 && !is_send) {
            dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, sizeof(ctx->recv_buf));
            if (rdma_cm_recv_attr_id(ctx->recv_buf) == CM_REP_ATTR_ID) {
                rdma_cm_parse_rep(ctx, ctx->recv_buf);
                uart_printf("rdma_cm: REP received (remote_comm_id=0x%08x peer_qpn=%u peer_psn=%u)\n",
                            ctx->remote_comm_id, ctx->peer_rc_qpn, ctx->peer_starting_psn);
                self->state = RDMA_CM_ST_ACTIVE_MODIFY_QP;
                return JOB_WAITING;
            }
            // REP以外(想定外)は無視して再度RECVを構える。
            mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                                  sizeof(ctx->recv_buf));
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
            // フェーズ(g): 確立検証pingを省略し、確立済みrc_qpをそのまま
            // 呼び出し元(nvme_rdma.c等)の実トラフィックへ引き渡す。
            self->state = RDMA_CM_ST_DONE_OK;
            return JOB_DONE;
        }
        self->state = RDMA_CM_ST_ACTIVE_PING_SEND;
        return JOB_WAITING;
    }

    case RDMA_CM_ST_ACTIVE_PING_SEND: {
        // 確立検証: CM経由で確立されたRC QP自体でSEND/RECVが成立するかを
        // フェーズ(b)のmlx5_qp_post_send()/mlx5_qp_poll_cqe()そのままで
        // 確認する(「手動QP確立をCM経由の自動確立へ置き換える」という
        // フェーズ(e)完了条件の核心 -- RC QPのWQE/CQE層は一切変更しない)。
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

    // ------------------------------------------------------------------
    // passive(REQ待ち側)
    // ------------------------------------------------------------------
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
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe_gsi(ctx->dev, ctx->gsi_qp, &is_send, &recv_len, &synd);
        if (rc < 0) {
            uart_printf("rdma_cm: FAILED (GSI CQE error syndrome=0x%02x)\n", synd);
            ctx->failed = 1;
            self->state = RDMA_CM_ST_DONE_FAIL;
            return JOB_DONE;
        }
        if (rc == 1 && !is_send) {
            dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, sizeof(ctx->recv_buf));
            if (rdma_cm_recv_attr_id(ctx->recv_buf) == CM_REQ_ATTR_ID) {
                rdma_cm_parse_req(ctx, ctx->recv_buf);
                ctx->tid = rd64be(&ctx->recv_buf[MLX5_GRH_BYTES + 8]); // MADヘッダのtidをそのまま流用(REP/RTUで踏襲)
                ctx->local_comm_id = (uint32_t)(timer_now() & 0xFFFFFFFFu) ^ 0x5A5A5A5Au;
                uart_printf("rdma_cm: REQ received (remote_comm_id=0x%08x peer_qpn=%u peer_psn=%u)\n",
                            ctx->remote_comm_id, ctx->peer_rc_qpn, ctx->peer_starting_psn);
                mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                                      sizeof(ctx->recv_buf)); // 次に来るRTU用に構え直す
                self->state = RDMA_CM_ST_PASSIVE_MODIFY_QP;
                return JOB_WAITING;
            }
            mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                                  sizeof(ctx->recv_buf));
        }
        return JOB_WAITING; // クライアント接続待ちはタイムアウトしない(nvmet.cのACCEPT_WAITと同じ方針)
    }

    case RDMA_CM_ST_PASSIVE_MODIFY_QP: {
        // RC接続の両端は同じpath MTUを使う(IBTA)。相手のCM REQが広告した
        // MTUをRC QPへ反映してからINIT2RTRする -- 1024固定のままだとhostが
        // jumbo(path MTU>1024)で接続してきた際にRDMA_WRITEが
        // REMOTE_INVAL_REQ_ERRで拒否される(mlx5.hのmlx5_qp_t.path_mtu参照)。
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
        // 確立検証用: activeがpingを送ってくる前にRECV WQEを構えておく
        // (RC QPはTCPと違い自動バッファリングされないため必須)。
        // フェーズ(g): skip_pingならこのRECV WQEを消費させない(呼び出し
        // 元が確立後に自分のRECV WQEを投稿する、rdma_cm.hコメント参照)。
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
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe_gsi(ctx->dev, ctx->gsi_qp, &is_send, &recv_len, &synd);
        if (rc == 1 && !is_send) {
            dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, sizeof(ctx->recv_buf));
            if (rdma_cm_recv_attr_id(ctx->recv_buf) == CM_RTU_ATTR_ID) {
                uart_printf("rdma_cm: RTU received (passive)\n");
                if (ctx->skip_ping) {
                    // 2026-08-13、切断検出のため: この"cm" jobはここで終了
                    // する(既存動作を変えない)が、その前にGSIへもう1個
                    // RECV WQEを構えておく -- これが無いと、job終了後は
                    // 誰もGSIをポーリングしなくなり、ホストが後で送って
                    // くる実際のCM DREQ(nvme disconnect時)を受け取る
                    // バッファが存在しないことになる(CLAUDE.md
                    // 「nvmet_rdma.cの切断検出」節参照)。nvmet_rdma.cの
                    // DREQ監視はrtu_phase_done==1を確認してからしか
                    // GSIをポーリングしないため、まだこの"cm" job自身が
                    // 受信中のRTUを誤って横取りする競合は起きない。
                    mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                                          sizeof(ctx->recv_buf));
                    ctx->rtu_phase_done = 1;
                    self->state = RDMA_CM_ST_DONE_OK;
                    return JOB_DONE;
                }
                self->state = RDMA_CM_ST_PASSIVE_PING_WAIT;
                return JOB_WAITING;
            }
        }
        if (timeout_ms(ctx->state_deadline, RDMA_CM_RTU_WAIT_TIMEOUT_MS)) {
            uart_printf("rdma_cm: RTU not observed within %ums, but RC QP is already RTS "
                        "-- proceeding anyway (IBTA semantics)\n",
                        RDMA_CM_RTU_WAIT_TIMEOUT_MS);
            if (ctx->skip_ping) {
                // 上と同じ理由でGSIへもう1個RECV WQEを構えてから終了する。
                mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                                      sizeof(ctx->recv_buf));
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

// PF0(active)/PF1(passive)それぞれのctxを固定static領域に置く(mallocが
// 無い環境のため、既存nvmet.c/nvme.cのjob ctxプールと同じパターン)。
static rdma_cm_ctx_t s_active_ctx;
static rdma_cm_ctx_t s_passive_ctx;

void rdma_cm_fill_addr(rdma_cm_ctx_t *ctx, mlx5_dev_t *dev, const char *self_label,
                              const char *peer_label, uint32_t self_ip_fallback,
                              uint32_t peer_ip_fallback, const uint8_t self_mac_fallback[6],
                              const uint8_t peer_mac_fallback[6]) {
    for (unsigned i = 0; i < sizeof(*ctx); i++) {
        ((uint8_t *)ctx)[i] = 0;
    }
    // 実機で発見した本物のバグ(2026-08-12): 上のゼロクリアは`(uint8_t *)ctx`
    // という非volatileキャスト経由の書き込みのため、recv_buf/rc_recv_buf
    // (構造体内でvolatile宣言されているが、この書き込み自体はvolatile性を
    // 失っている)へダーティなキャッシュラインを残す。dcache_invalidate_
    // range()(cache.h)は`dc civac`(クリーン+無効化)を使うため、HWが
    // 実際にDMA書き込みした直後にこれを呼ぶと、「クリーン」の部分が
    // このダーティな(ゼロの)キャッシュラインをメインメモリへ書き戻し、
    // HWが書いたばかりの実データを無言で上書きしてしまう -- 初回のRECV
    // WQEを投稿する前に明示的にクリーンしておき、ダーティな状態を残さない。
    dcache_clean_range((const void *)ctx, sizeof(*ctx));
    ctx->dev = dev;
    // 既定では自分自身のgsi_qp_storageを指す(通常の新規GSI作成ケース)。
    // IOキュー用ctx(reuse_gsi=1)を作る呼び出し元は、この直後に
    // admin側の実体を指すよう明示的に上書きすること(rdma_cm.hのgsi_qp
    // コメント参照)。
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
}

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(f): (c)+(e)の統合。CM経由で
// RC QPを確立するjob駆動ロジック(rdma_cm_run_test()の中核)を、
// フェーズ(f)の`mlx5rdmaconnect`(RDMA_WRITE/READ検証)とフェーズ(e)の
// `mlx5rdmacm test`(SEND/RECV ping-pong検証)の両方から共有できるよう
// 抽出した。s_active_ctx/s_passive_ctxを設定・job_spawn()・完了(または
// タイムアウト)までjob_scheduler_tick()を回す、という一連の手順は
// 両者で全く同じ -- 違いは「確立後に何を検証するか」だけ。
// 戻り値: 1=両端ともESTABLISHED(RC QPがRTS)に到達、0=いずれか失敗/
// タイムアウト。ping_ok(SEND/RECV検証)の成否はここでは問わない
// (呼び出し元がそれぞれの目的に応じて別途確認する)。
static int rdma_cm_establish_via_jobs(mlx5_dev_t *dev0, mlx5_dev_t *dev1) {
    static const uint8_t mac0_fallback[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x10};
    static const uint8_t mac1_fallback[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x11};
    uint32_t ip0_fallback = ip_from_octets(192, 168, 101, 10);
    uint32_t ip1_fallback = ip_from_octets(192, 168, 101, 11);

    rdma_cm_fill_addr(&s_active_ctx, dev0, "mlx5-pf0", "mlx5-pf1", ip0_fallback, ip1_fallback,
                      mac0_fallback, mac1_fallback);
    s_active_ctx.is_active = 1;

    rdma_cm_fill_addr(&s_passive_ctx, dev1, "mlx5-pf1", "mlx5-pf0", ip1_fallback, ip0_fallback,
                      mac1_fallback, mac0_fallback);
    s_passive_ctx.is_active = 0;

    job_t *active_job = job_spawn(rdma_cm_job_step, &s_active_ctx, "rdma-cm-active");
    job_t *passive_job = job_spawn(rdma_cm_job_step, &s_passive_ctx, "rdma-cm-passive");
    if (active_job == NULL || passive_job == NULL) {
        uart_printf("rdma_cm: FAILED (job table full)\n");
        return 0;
    }
    active_job->state = RDMA_CM_ST_ACTIVE_SETUP;
    passive_job->state = RDMA_CM_ST_PASSIVE_SETUP;

    // 実際にjob.hのスケジューラへ登録した上で、完了までjob_scheduler_
    // tick()を同期的に回す -- 既存のmlx5qp pingpong等と同じ「その場で
    // PASS/FAILを返す」診断コマンドのUXを保ちつつ、内部の状態遷移自体は
    // 計画通りjob.hのnon-blocking契約に完全準拠させる。
    uint64_t start = timer_now();
    while (1) {
        job_scheduler_tick();
        if ((s_active_ctx.failed || s_active_ctx.ping_ok) &&
            (s_passive_ctx.failed || s_passive_ctx.ping_ok)) {
            break;
        }
        if (timeout_ms(start, 20000u)) {
            uart_printf("rdma_cm: FAILED (overall timeout waiting for both sides)\n");
            break;
        }
    }

    uart_printf("rdma_cm: active established=%d ping_ok=%d failed=%d\n",
                s_active_ctx.established, s_active_ctx.ping_ok, s_active_ctx.failed);
    uart_printf("rdma_cm: passive established=%d ping_ok=%d failed=%d\n",
                s_passive_ctx.established, s_passive_ctx.ping_ok, s_passive_ctx.failed);
    return s_active_ctx.established && s_passive_ctx.established;
}

void rdma_cm_run_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1) {
    if (!rdma_cm_establish_via_jobs(dev0, dev1)) {
        uart_printf("rdma_cm test: FAILED (CM establishment)\n");
        return;
    }
    if (s_active_ctx.ping_ok && s_passive_ctx.ping_ok) {
        uart_printf("rdma_cm test: PASS (CM REQ->REP->RTU established RC QP, "
                    "ping-pong over CM-established QP confirmed)\n");
    } else {
        uart_printf("rdma_cm test: FAILED (ping-pong verification)\n");
    }
}

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(f): `mlx5rdmaconnect`シェル
// コマンド用。CM(REQ->REP->RTU)でRC QPを自動確立した直後、確立された
// QP自体でRDMA_WRITE(active->passive)・RDMA_READ(passive->active)を
// 実際に行い、フェーズ(c)の`mlx5qp rdma`と同じデータ完全一致確認を行う。
// rkey(mkey)交換は標準IB CMメッセージには含まれない(mlx5固有のFW
// オブジェクト番号でありIBTA仕様の管轄外 -- 実NVMe-oFではNVMe SQEの
// Keyed SGLディスクリプタで別途交換される、フェーズ(g)の領域)ため、
// このフェーズ(f)は引き続き同一プログラム内のループバック検証という
// 前提のもと、s_active_ctx.rc_qp.mkey/s_passive_ctx.rc_qp.mkeyを直接
// 参照する(mlx5_qp_rdma_test()が同一関数内でqp0.mkey/qp1.mkeyを直接
// 参照していたのと同じ考え方)。
void rdma_cm_run_connect(mlx5_dev_t *dev0, mlx5_dev_t *dev1) {
    if (!rdma_cm_establish_via_jobs(dev0, dev1)) {
        uart_printf("rdma_cm connect: FAILED (CM establishment)\n");
        return;
    }
    uart_printf("rdma_cm connect: CM established -- verifying RDMA_WRITE/READ over the CM-established QP\n");

    // active(PF0) -> passive(PF1): RDMA_WRITE。
    static volatile uint8_t src0[64];
    static volatile uint8_t dst1[64];
    for (unsigned i = 0; i < sizeof(src0); i++) {
        src0[i] = (uint8_t)(0xB0u + i);
        dst1[i] = 0;
    }
    dcache_clean_range((const void *)(uintptr_t)src0, sizeof(src0));
    dcache_clean_range((const void *)(uintptr_t)dst1, sizeof(dst1));
    uint64_t dst1_pa = mlx5_dma_addr((const void *)(uintptr_t)dst1);
    if (mlx5_qp_post_rdma_write(s_active_ctx.dev, &s_active_ctx.rc_qp, (const void *)(uintptr_t)src0,
                                 (uint32_t)sizeof(src0), dst1_pa, s_passive_ctx.rc_qp.mkey) != 0) {
        uart_printf("rdma_cm connect: FAILED (post_rdma_write active->passive)\n");
        return;
    }
    {
        int done = 0;
        uint64_t start = timer_now();
        while (!done) {
            if (timeout_ms(start, 3000u)) {
                uart_printf("rdma_cm connect: TIMEOUT waiting for RDMA_WRITE CQE\n");
                return;
            }
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(s_active_ctx.dev, &s_active_ctx.rc_qp, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                done = 1;
                uart_printf("rdma_cm connect: RDMA_WRITE completed (active->passive)\n");
            } else if (rc < 0) {
                uart_printf("rdma_cm connect: FAILED (RDMA_WRITE CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
    }
    dcache_invalidate_range((const void *)(uintptr_t)dst1, sizeof(dst1));
    int wmatch = 1;
    for (unsigned i = 0; i < sizeof(src0); i++) {
        if (dst1[i] != src0[i]) {
            wmatch = 0;
            break;
        }
    }
    uart_printf("rdma_cm connect: active->passive RDMA_WRITE data %s\n", wmatch ? "MATCH" : "MISMATCH");
    if (!wmatch) {
        uart_printf("rdma_cm connect: FAILED (RDMA_WRITE data mismatch)\n");
        return;
    }

    // passive(PF1) -> active(PF0): RDMA_READ(passiveがactive[src0]から読み出す)。
    static volatile uint8_t dst0[64];
    for (unsigned i = 0; i < sizeof(dst0); i++) {
        dst0[i] = 0;
    }
    dcache_clean_range((const void *)(uintptr_t)dst0, sizeof(dst0));
    uint64_t src0_pa = mlx5_dma_addr((const void *)(uintptr_t)src0);
    if (mlx5_qp_post_rdma_read(s_passive_ctx.dev, &s_passive_ctx.rc_qp, (void *)(uintptr_t)dst0,
                                (uint32_t)sizeof(dst0), src0_pa, s_active_ctx.rc_qp.mkey) != 0) {
        uart_printf("rdma_cm connect: FAILED (post_rdma_read passive->active)\n");
        return;
    }
    {
        int done = 0;
        uint64_t start = timer_now();
        while (!done) {
            if (timeout_ms(start, 3000u)) {
                uart_printf("rdma_cm connect: TIMEOUT waiting for RDMA_READ CQE\n");
                return;
            }
            int is_send = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(s_passive_ctx.dev, &s_passive_ctx.rc_qp, &is_send, NULL, &synd);
            if (rc == 1 && is_send) {
                done = 1;
                uart_printf("rdma_cm connect: RDMA_READ completed (passive<-active)\n");
            } else if (rc < 0) {
                uart_printf("rdma_cm connect: FAILED (RDMA_READ CQE error syndrome=0x%02x)\n", synd);
                return;
            }
        }
    }
    dcache_invalidate_range((const void *)(uintptr_t)dst0, sizeof(dst0));
    int rmatch = 1;
    for (unsigned i = 0; i < sizeof(dst0); i++) {
        if (dst0[i] != src0[i]) {
            rmatch = 0;
            break;
        }
    }
    uart_printf("rdma_cm connect: passive<-active RDMA_READ data %s\n", rmatch ? "MATCH" : "MISMATCH");
    if (!rmatch) {
        uart_printf("rdma_cm connect: FAILED (RDMA_READ data mismatch)\n");
        return;
    }

    uart_printf("rdma_cm connect: PASS (CM connect -> RDMA_WRITE/READ over the established QP, "
                "one command, confirmed)\n");
}
