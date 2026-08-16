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

#define RDMA_CM_SERVICE_ID_PLACEHOLDER 0x0000000000000001ull

#define RDMA_CM_REQ_RETRY_TIMEOUT_MS 2000u
#define RDMA_CM_REQ_MAX_RETRIES      3u
#define RDMA_CM_RTU_WAIT_TIMEOUT_MS  3000u
#define RDMA_CM_PING_TIMEOUT_MS      3000u

static const char RDMA_CM_PING_MSG[] = "rdma_cm phase(e) established ping-pong";

uint16_t rdma_cm_recv_attr_id(const volatile uint8_t *recv_buf) {
    return rd16be_ib(&recv_buf[MLX5_GRH_BYTES + 16]);
}

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
    p[44] = (uint8_t)(ctx->rc_qp.local_psn >> 16);
    p[45] = (uint8_t)(ctx->rc_qp.local_psn >> 8);
    p[46] = (uint8_t)ctx->rc_qp.local_psn; // STARTING_PSN(24bit)
    p[47] = (uint8_t)((20u << 3) | 7u); // LOCAL_CM_RESPONSE_TIMEOUT(pos0-4)=20、RETRY_COUNT(pos5-7)=7
    p[48] = 0xFF;
    p[49] = 0xFF; // PARTITION_KEY(pkey、フル権限0xFFFF)
    p[50] = (uint8_t)((3u << 4) | 7u); // PATH_PACKET_PAYLOAD_MTU(pos0-3)=IB_MTU_1024(3)、
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
    wr16be_ib(&priv[2], 0); // cma_hdr.port(プレースホルダ)
    // priv[4..19] = src_addr(union cma_ip_addr、16B) -- IPv4は末尾4Bのみ使用。
    wr32be_ib(&priv[16], ctx->own_ip);
    // priv[20..35] = dst_addr(16B)。
    wr32be_ib(&priv[32], ctx->peer_ip);
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

static void rdma_cm_parse_req(rdma_cm_ctx_t *ctx, const volatile uint8_t *recv_buf) {
    const volatile uint8_t *p = &recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    ctx->remote_comm_id = rd32be_ib(&p[0]);
    ctx->peer_rc_qpn = ((uint32_t)p[32] << 16) | ((uint32_t)p[33] << 8) | p[34];
    ctx->peer_starting_psn = ((uint32_t)p[44] << 16) | ((uint32_t)p[45] << 8) | p[46];
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

static int rdma_cm_setup_gsi_reused(rdma_cm_ctx_t *ctx) {
    if (mlx5_qp_post_recv_gsi(ctx->dev, ctx->gsi_qp, (void *)(uintptr_t)ctx->recv_buf,
                              sizeof(ctx->recv_buf)) != 0) {
        uart_printf("rdma_cm: FAILED (GSI post_recv, reused)\n");
        return -1;
    }
    return 0;
}

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
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe_gsi(ctx->dev, ctx->gsi_qp, &is_send, &recv_len, &synd);
        if (rc == 1 && !is_send) {
            dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, sizeof(ctx->recv_buf));
            if (rdma_cm_recv_attr_id(ctx->recv_buf) == CM_RTU_ATTR_ID) {
                uart_printf("rdma_cm: RTU received (passive)\n");
                if (ctx->skip_ping) {
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
}
