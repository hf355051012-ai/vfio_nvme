#include <stddef.h>
#include "nvme.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "job.h"
#include "timestamp.h"
#include "smp.h"
#include "netif.h"

#define NVME_QSIZE               32u    /* admin/IO両queueのsqsize(Fabrics Connectで通知) */
#define NVME_ADMIN_CMD_TIMEOUT_MS 5000u
#define NVME_IO_CMD_TIMEOUT_MS   10000u

#define NVME_CONNECT_ICRESP_TIMEOUT_MS 3000u

#define NVME_CTRL_READY_POLL_MAX     20u
#define NVME_CTRL_READY_POLL_MS     100u

static const uint8_t NVME_HOST_ID[16] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
};
#define NVME_HOST_NQN "nqn.2014-08.org.nvmexpress:uuid:a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf"

#define NVME_CNTLID_DYNAMIC 0xFFFFu  /* Fabrics Connect(admin queue): controller ID割り当てをtargetに任せる */

typedef struct __attribute__((packed)) {
    uint8_t  hostid[16];
    uint16_t cntlid;
    uint8_t  reserved1[238];
    char     subsysnqn[256];
    char     hostnqn[256];
    uint8_t  reserved2[256];
} nvmf_connect_data_t;

static void nvme_zero(void *p, size_t len)
{
    volatile uint8_t *b = p;
    for (size_t i = 0; i < len; i++) b[i] = 0;
}

static void nvme_copy_str(char *dst, size_t capacity, const char *src)
{
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < capacity) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static void nvme_set_sgl(nvme_sqe_t *sqe, uint32_t len)
{
    wr64le(&sqe->dptr[0], 0);
    wr32le(&sqe->dptr[8], len);
    sqe->dptr[12] = 0;
    sqe->dptr[13] = 0;
    sqe->dptr[14] = 0;
    sqe->dptr[15] = (uint8_t)NVME_SGL_TYPE_TRANSPORT;
}

static void nvme_set_sgl_inline(nvme_sqe_t *sqe, uint32_t len)
{
    wr64le(&sqe->dptr[0], 0);
    wr32le(&sqe->dptr[8], len);
    sqe->dptr[12] = 0;
    sqe->dptr[13] = 0;
    sqe->dptr[14] = 0;
    sqe->dptr[15] = (uint8_t)NVME_SGL_TYPE_DATA_BLOCK_OFFSET;
}

typedef enum {
    NVEXEC_ST_SEND = 0,
    NVEXEC_ST_RECV_HDR,
    NVEXEC_ST_RECV_CQE,
    NVEXEC_ST_RECV_C2H_REST,
    NVEXEC_ST_RECV_C2H_DATA,
    NVEXEC_ST_RECV_R2T_REST,
    NVEXEC_ST_SEND_H2C,
    NVEXEC_ST_DONE,
} nvme_exec_state_t;

#define NVEXEC_STATE_NAME_COUNT (sizeof(NVEXEC_STATE_NAMES) / sizeof(NVEXEC_STATE_NAMES[0]))

void nvme_exec_begin(nvme_exec_ctx_t *ec, nvme_tcp_conn_t *conn, const nvme_sqe_t *sqe,
                      const void *send_data, uint32_t send_len,
                      void *recv_buf, uint32_t recv_buflen)
{
    ec->state       = NVEXEC_ST_SEND;
    ec->conn        = conn;
    ec->sqe         = sqe;
    ec->send_data   = send_data;
    ec->send_len    = send_len;
    ec->recv_buf    = recv_buf;
    ec->recv_buflen = recv_buflen;
}

int nvme_exec_step(nvme_exec_ctx_t *ec)
{
    switch ((nvme_exec_state_t)ec->state) {

    case NVEXEC_ST_SEND:
        if (nvme_tcp_send_cmd(ec->conn, ec->sqe, ec->send_data, ec->send_len) != 0) {
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        {
            const uint8_t *sqe_bytes = (const uint8_t *)ec->sqe;
            uint8_t  sgl_type = sqe_bytes[39];
            int use_r2t = (ec->send_data != NULL && ec->send_len > 0 &&
                           sgl_type == (uint8_t)NVME_SGL_TYPE_TRANSPORT);
            int has_inline_data = (!use_r2t && ec->send_data != NULL && ec->send_len > 0);

            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_CMD;
            info.hlen        = (uint8_t)NVME_TCP_CMD_PDU_LEN;
            info.pdo         = has_inline_data ? (uint8_t)NVME_TCP_CMD_PDU_LEN : 0;
            info.plen        = NVME_TCP_CMD_PDU_LEN + (has_inline_data ? ec->send_len : 0u);
            info.cid         = ec->conn->pending_cid;
            info.opcode      = sqe_bytes[0];
            info.sgl_type    = sgl_type;
            info.data_length = rd32le(&sqe_bytes[32]);  /* LEN(SGL宣言転送量) */
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 0), &info);
        }
        nvme_tcp_xfer_reset(&ec->xfer, ec->hdr_buf, NVME_TCP_HDR_LEN);
        ec->state = NVEXEC_ST_RECV_HDR;
        return 0;

    case NVEXEC_ST_RECV_HDR: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

        uint8_t type = ec->hdr_buf[0];
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, NVME_CQE_LEN);
            ec->state = NVEXEC_ST_RECV_CQE;
        } else if (type == NVME_TCP_PDU_C2H_DATA) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, 16u);
            ec->state = NVEXEC_ST_RECV_C2H_REST;
        } else if (type == NVME_TCP_PDU_R2T) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, 16u);
            ec->state = NVEXEC_ST_RECV_R2T_REST;
        } else {
            uart_printf("[!] NVMe/TCP: 未対応のPDU種別 (type=%u) 受信、応答待ちを中断\n", type);
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        return 0;
    }

    case NVEXEC_ST_RECV_CQE: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

        uint16_t cid    = rd16le(&ec->rest_buf[12]);
        uint16_t status = rd16le(&ec->rest_buf[14]);
        wr32le(&ec->cqe_out.dw0, rd32le(&ec->rest_buf[0]));
        wr32le(&ec->cqe_out.dw1, rd32le(&ec->rest_buf[4]));
        wr16le(&ec->cqe_out.sq_head, rd16le(&ec->rest_buf[8]));
        wr16le(&ec->cqe_out.sq_id, rd16le(&ec->rest_buf[10]));
        wr16le(&ec->cqe_out.cid, cid);
        wr16le(&ec->cqe_out.status, status);
        if (cid != ec->conn->pending_cid) {
            uart_printf("[!] NVMe/TCP: CQEのCIDが不一致 (期待=%u 受信=%u)\n",
                        ec->conn->pending_cid, cid);
        }
        /* NRCV: Response Capsule(CQE)受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_RSP;
            info.hlen     = ec->hdr_buf[2];
            info.pdo      = ec->hdr_buf[3];
            info.plen     = rd32le(&ec->hdr_buf[4]);
            info.cid      = cid;
            info.status   = status;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 1), &info);
        }
        ec->result = (int)nvme_cqe_status_code(status);
        ec->state = NVEXEC_ST_DONE;
        return 1;
    }

    case NVEXEC_ST_RECV_C2H_REST: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

        uint8_t  hlen = ec->hdr_buf[2];
        uint32_t plen = rd32le(&ec->hdr_buf[4]);
        ec->datao = rd32le(&ec->rest_buf[4]);
        ec->datal = rd32le(&ec->rest_buf[8]);

        uint32_t data_in_pdu = plen - hlen;
        if (data_in_pdu != ec->datal) {
            uart_printf("[!] NVMe/TCP: C2HDataのplen/datal不一致 (plen=%u datal=%u)\n",
                        plen, ec->datal);
        }
        if ((uint64_t)ec->datao + (uint64_t)ec->datal > (uint64_t)ec->recv_buflen) {
            uart_printf("[!] NVMe/TCP: C2HDataが呼び出し側バッファを超過 "
                        "(datao=%u datal=%u buflen=%u)\n", ec->datao, ec->datal, ec->recv_buflen);
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        nvme_tcp_xfer_reset(&ec->xfer, (uint8_t *)ec->recv_buf + ec->datao, ec->datal);
        ec->state = NVEXEC_ST_RECV_C2H_DATA;
        return 0;
    }

    case NVEXEC_ST_RECV_C2H_DATA: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

        uint8_t flags = ec->hdr_buf[1];
        /* NRCV: C2HData受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_C2H_DATA;
            info.hlen        = ec->hdr_buf[2];
            info.pdo         = ec->hdr_buf[3];
            info.plen        = rd32le(&ec->hdr_buf[4]);
            info.cccid       = ec->conn->pending_cid;
            info.data_offset = ec->datao;
            info.data_length = ec->datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 2), &info);
        }
        if (flags & NVME_TCP_F_DATA_SUCCESS) {
            nvme_zero(&ec->cqe_out, sizeof(ec->cqe_out));
            wr16le(&ec->cqe_out.cid, ec->conn->pending_cid);
            ec->result = 0;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        nvme_tcp_xfer_reset(&ec->xfer, ec->hdr_buf, NVME_TCP_HDR_LEN);
        ec->state = NVEXEC_ST_RECV_HDR;
        return 0;
    }

    case NVEXEC_ST_RECV_R2T_REST: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

        ec->ttag  = rd16le(&ec->rest_buf[2]);
        ec->datao = rd32le(&ec->rest_buf[4]);  /* r2to(SEND_H2Cへそのまま渡す) */
        ec->datal = rd32le(&ec->rest_buf[8]);  /* r2tl */
        /* NRCV: R2T受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_R2T;
            info.hlen        = ec->hdr_buf[2];
            info.pdo         = ec->hdr_buf[3];
            info.plen        = rd32le(&ec->hdr_buf[4]);
            info.cccid       = ec->conn->pending_cid;
            info.ttag        = ec->ttag;
            info.data_offset = ec->datao;
            info.data_length = ec->datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 3), &info);
        }
        ec->state = NVEXEC_ST_SEND_H2C;
        return 0;
    }

    case NVEXEC_ST_SEND_H2C:
        if (nvme_tcp_send_h2c_data(ec->conn, ec->ttag, ec->datao, ec->datal) != 0) {
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        /* NSND: H2CData送信(R2T応答)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_H2C_DATA;
            info.hlen        = (uint8_t)NVME_TCP_DATA_PDU_LEN;
            info.pdo         = (uint8_t)NVME_TCP_DATA_PDU_LEN;
            info.plen        = NVME_TCP_DATA_PDU_LEN + ec->datal;
            info.cccid       = ec->conn->pending_cid;
            info.ttag        = ec->ttag;
            info.data_offset = ec->datao;
            info.data_length = ec->datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 4), &info);
        }
        nvme_tcp_xfer_reset(&ec->xfer, ec->hdr_buf, NVME_TCP_HDR_LEN);
        ec->state = NVEXEC_ST_RECV_HDR;
        return 0;

    default:
        return 1;
    }
}

static void nvme_build_property_set_sqe(nvme_sqe_t *sqe, uint32_t offset, uint64_t value)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, NVME_FABRIC_FCTYPE_PROPERTY_SET);
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0u);  /* attrib=0: 4バイトプロパティ */
    wr32le(&sqe->cdw11, offset);
    wr32le(&sqe->cdw12, (uint32_t)(value & 0xFFFFFFFFu));
    wr32le(&sqe->cdw13, (uint32_t)(value >> 32));
}

static void nvme_build_property_get_sqe(nvme_sqe_t *sqe, uint32_t offset)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, NVME_FABRIC_FCTYPE_PROPERTY_GET);
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0u);  /* attrib=0: 4バイトプロパティ */
    wr32le(&sqe->cdw11, offset);
}

static void nvme_build_connect_data(nvmf_connect_data_t *data, uint16_t cntlid, const char *subnqn)
{
    nvme_zero(data, sizeof(*data));
    for (int i = 0; i < 16; i++) data->hostid[i] = NVME_HOST_ID[i];
    wr16le(&data->cntlid, cntlid);
    nvme_copy_str(data->subsysnqn, sizeof(data->subsysnqn), subnqn);
    nvme_copy_str(data->hostnqn, sizeof(data->hostnqn), NVME_HOST_NQN);
}

static void nvme_build_fabrics_connect_sqe(nvme_sqe_t *sqe, uint16_t qid, uint32_t connect_data_len)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, NVME_FABRIC_FCTYPE_CONNECT);  /* fctypeはnsidフィールドの下位バイトにオーバーレイされる */
    nvme_set_sgl_inline(sqe, connect_data_len);
    wr32le(&sqe->cdw10, (uint32_t)qid << 16);                 /* recfmt=0(下位16bit), qid(上位16bit) */
    wr32le(&sqe->cdw11, (uint32_t)(NVME_QSIZE - 1) & 0xFFFFu); /* sqsize(0's based) */
    wr32le(&sqe->cdw12, 0u);
}

void nvme_build_identify_sqe(nvme_sqe_t *sqe, uint8_t cns, uint32_t nsid)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_ADM_CMD_IDENTIFY | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    nvme_set_sgl(sqe, 4096u);
    wr32le(&sqe->cdw10, (uint32_t)cns);  /* CNS: bits[7:0]、残りは予約 */
}

void nvme_update_lba_size_from_id_ns(nvme_ctx_t *ctx, uint32_t nsid, const void *buf4096)
{
    const uint8_t *b = buf4096;
    uint8_t flbas = (uint8_t)(b[NVME_ID_NS_OFF_FLBAS] & 0x0Fu);  /* bits[3:0] = LBA Format Index */
    uint32_t lbaf_off = NVME_ID_NS_OFF_LBAF0 + (uint32_t)flbas * 4u;
    uint8_t ds = b[lbaf_off + 2];  /* nvme_lbaf_t: ms(2B)+ds(1B)+rp(1B) -- dsは3バイト目 */
    ctx->lba_size = (uint32_t)1u << ds;
    /* NSZE: Identify Namespaceデータ構造の先頭8バイト(オフセット0、リトルエンディアン)。 */
    ctx->nsze = (uint64_t)rd32le(b + 0) | ((uint64_t)rd32le(b + 4) << 32);
    uart_printf("[nvme] identify namespace %u: flbas=%u lba_size=%u バイト nsze=%u ブロック\n",
                nsid, flbas, ctx->lba_size, (unsigned)ctx->nsze);
}

static void nvme_build_set_features_num_queues_sqe(nvme_sqe_t *sqe)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_ADM_CMD_SET_FEATURES | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0x07u);        /* FID=7: Number of Queues */
    wr32le(&sqe->cdw11, 0x00010001u);  /* NSQR=1, NCQR=1 (IO SQ/CQ各1本を要求) */
}

typedef enum {
    NCONN_ST_TCP_ADMIN_BEGIN = 0,
    NCONN_ST_TCP_ADMIN_WAIT,
    NCONN_ST_ICRESP_ADMIN_RECV,
    NCONN_ST_EXEC_FABRIC_CONNECT_ADMIN,
    NCONN_ST_EXEC_PROPSET_CC,
    NCONN_ST_CSTS_POLL_WAIT,
    NCONN_ST_CSTS_POLL_EXEC,
    NCONN_ST_EXEC_IDENTIFY_CTRL,
    NCONN_ST_EXEC_IDENTIFY_NS,
    NCONN_ST_EXEC_SET_FEATURES,
    NCONN_ST_TCP_IO_WAIT,
    NCONN_ST_ICRESP_IO_RECV,
    NCONN_ST_EXEC_FABRIC_CONNECT_IO,
} nvme_connect_state_t;

#define NCONN_STATE_NAME_COUNT (sizeof(NCONN_STATE_NAMES) / sizeof(NCONN_STATE_NAMES[0]))

typedef struct {
    nvme_ctx_t         *ctx;
    uint32_t             ip;
    uint16_t              port;
    netif_t            *src_ctx;  /* spawn時点のg_active_ctx、下記コメント参照 */
    uint64_t              wait_started_ticks;
    nvme_tcp_xfer_t       xfer;
    uint8_t               icresp_buf[NVME_TCP_ICRESP_LEN];
    nvmf_connect_data_t   connect_data;
    nvme_sqe_t            sqe;
    nvme_exec_ctx_t       exec;
    uint32_t              csts_poll_count;
    uint8_t               id_buf[4096] __attribute__((aligned(64)));

} nvme_connect_job_ctx_t;

static nvme_connect_job_ctx_t s_nvme_connect_job_ctx;

static job_result_t nvme_connect_job_fail(nvme_connect_job_ctx_t *jc, int close_admin, int close_io,
                                           const char *reason)
{
    uart_printf("[!] nvme: 接続失敗 (%s)\n", reason);
    if (close_io) {
        nvme_tcp_close(&jc->ctx->io);
    }
    if (close_admin) {
        nvme_tcp_close(&jc->ctx->admin);
    }
    jc->ctx->io_connected = 0;
    jc->ctx->busy = 0;
    return JOB_DONE;
}

static job_result_t nvme_connect_job_step(job_t *self)
{
    nvme_connect_job_ctx_t *jc  = (nvme_connect_job_ctx_t *)self->ctx;
    nvme_ctx_t              *ctx = jc->ctx;

    if (self->cancel_requested) {
        int admin_open = (self->state > NCONN_ST_TCP_ADMIN_WAIT);
        int io_open    = (self->state > NCONN_ST_TCP_IO_WAIT);
        return nvme_connect_job_fail(jc, admin_open, io_open, "job stopでキャンセル");
    }

    switch ((nvme_connect_state_t)self->state) {

    case NCONN_ST_TCP_ADMIN_BEGIN:
        if (jc->src_ctx) netif_activate(jc->src_ctx);
        tcp_connect_begin(&ctx->admin.tcp, jc->ip, jc->port);
        self->state = NCONN_ST_TCP_ADMIN_WAIT;
        return JOB_WAITING;

    case NCONN_ST_TCP_ADMIN_WAIT: {
        int r = tcp_connect_poll(&ctx->admin.tcp);
        if (r < 0) return nvme_connect_job_fail(jc, 0, 0, "admin TCP接続失敗");
        if (r == 0) return JOB_WAITING;
        if (nvme_tcp_send_icreq(&ctx->admin) != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "admin ICReq送信失敗");
        }
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICREQ;
            info.hlen     = (uint8_t)NVME_TCP_ICREQ_LEN;
            info.pdo      = 0;
            info.plen     = NVME_TCP_ICREQ_LEN;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 0), &info);
        }
        nvme_tcp_xfer_reset(&jc->xfer, jc->icresp_buf, NVME_TCP_ICRESP_LEN);
        jc->wait_started_ticks = timer_now();
        self->state = NCONN_ST_ICRESP_ADMIN_RECV;
        return JOB_WAITING;
    }

    case NCONN_ST_ICRESP_ADMIN_RECV: {
        int r = nvme_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0) return nvme_connect_job_fail(jc, 1, 0, "admin ICResp受信失敗");
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVME_CONNECT_ICRESP_TIMEOUT_MS)) {
                return nvme_connect_job_fail(jc, 1, 0, "admin ICResp受信タイムアウト");
            }
            return JOB_WAITING;
        }
        if (nvme_tcp_verify_icresp(&ctx->admin, jc->icresp_buf) != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "admin ICResp不正");
        }
        /* NRCV: ICResp受信完了(admin queue)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICRESP;
            info.hlen     = jc->icresp_buf[2];
            info.pdo      = jc->icresp_buf[3];
            info.plen     = rd32le(&jc->icresp_buf[4]);
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 1), &info);
        }
        nvme_build_connect_data(&jc->connect_data, (uint16_t)NVME_CNTLID_DYNAMIC, ctx->subnqn);
        nvme_build_fabrics_connect_sqe(&jc->sqe, 0u, sizeof(jc->connect_data));
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe,
                         &jc->connect_data, sizeof(jc->connect_data), NULL, 0);
        self->state = NCONN_ST_EXEC_FABRIC_CONNECT_ADMIN;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_FABRIC_CONNECT_ADMIN: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "admin Fabrics Connect失敗");
        ctx->ctrlr_id = (uint16_t)(rd32le(&jc->exec.cqe_out.dw0) & 0xFFFFu);
        uart_printf("[nvme] admin queue接続完了 (controller id=%u)\n", ctx->ctrlr_id);

        uint32_t cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_AMS_RR | NVME_CC_SHN_NONE |
                      NVME_CC_IOSQES | NVME_CC_IOCQES;
        nvme_build_property_set_sqe(&jc->sqe, NVME_REG_CC, cc);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_EXEC_PROPSET_CC;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_PROPSET_CC: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "CC(Controller Configuration)有効化失敗");
        }
        jc->csts_poll_count = 0;
        nvme_build_property_get_sqe(&jc->sqe, NVME_REG_CSTS);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_CSTS_POLL_EXEC;
        return JOB_WAITING;
    }

    case NCONN_ST_CSTS_POLL_WAIT:
        if (!timeout_ms(jc->wait_started_ticks, NVME_CTRL_READY_POLL_MS)) return JOB_WAITING;
        nvme_build_property_get_sqe(&jc->sqe, NVME_REG_CSTS);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_CSTS_POLL_EXEC;
        return JOB_WAITING;

    case NCONN_ST_CSTS_POLL_EXEC: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "CSTS読み出し失敗");
        uint32_t csts = rd32le(&jc->exec.cqe_out.dw0);
        if (csts & NVME_CSTS_CFS) {
            return nvme_connect_job_fail(jc, 1, 0,
                "CSTS.CFS(Controller Fatal Status)、CC値の不整合の可能性");
        }
        if (csts & NVME_CSTS_RDY) {
            uart_printf("[nvme] コントローラ有効化完了 (CSTS.RDY=1)\n");
            nvme_build_identify_sqe(&jc->sqe, (uint8_t)NVME_IDENTIFY_CNS_CONTROLLER, 0);
            nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, jc->id_buf, sizeof(jc->id_buf));
            self->state = NCONN_ST_EXEC_IDENTIFY_CTRL;
            return JOB_WAITING;
        }
        jc->csts_poll_count++;
        if (jc->csts_poll_count >= NVME_CTRL_READY_POLL_MAX) {
            return nvme_connect_job_fail(jc, 1, 0, "CSTS.RDY待ちタイムアウト");
        }
        jc->wait_started_ticks = timer_now();
        self->state = NCONN_ST_CSTS_POLL_WAIT;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_IDENTIFY_CTRL: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "Identify Controller失敗");
        nvme_build_identify_sqe(&jc->sqe, (uint8_t)NVME_IDENTIFY_CNS_NAMESPACE, 1u);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, jc->id_buf, sizeof(jc->id_buf));
        self->state = NCONN_ST_EXEC_IDENTIFY_NS;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_IDENTIFY_NS: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "Identify Namespace(nsid=1)失敗");
        nvme_update_lba_size_from_id_ns(ctx, 1u, jc->id_buf);

        nvme_build_set_features_num_queues_sqe(&jc->sqe);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_EXEC_SET_FEATURES;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_SET_FEATURES: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "Set Features(Number of Queues)失敗");
        }
        if (jc->src_ctx) netif_activate(jc->src_ctx);
        tcp_connect_begin(&ctx->io.tcp, jc->ip, jc->port);
        self->state = NCONN_ST_TCP_IO_WAIT;
        return JOB_WAITING;
    }

    case NCONN_ST_TCP_IO_WAIT: {
        int r = tcp_connect_poll(&ctx->io.tcp);
        if (r < 0) return nvme_connect_job_fail(jc, 1, 0, "IO TCP接続失敗");
        if (r == 0) return JOB_WAITING;
        if (nvme_tcp_send_icreq(&ctx->io) != 0) {
            return nvme_connect_job_fail(jc, 1, 1, "IO ICReq送信失敗");
        }
        /* NSND: ICReq送信(IO queue)。admin queueの同種コメント参照。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICREQ;
            info.hlen     = (uint8_t)NVME_TCP_ICREQ_LEN;
            info.pdo      = 0;
            info.plen     = NVME_TCP_ICREQ_LEN;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 2), &info);
        }
        nvme_tcp_xfer_reset(&jc->xfer, jc->icresp_buf, NVME_TCP_ICRESP_LEN);
        jc->wait_started_ticks = timer_now();
        self->state = NCONN_ST_ICRESP_IO_RECV;
        return JOB_WAITING;
    }

    case NCONN_ST_ICRESP_IO_RECV: {
        int r = nvme_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvme_connect_job_fail(jc, 1, 1, "IO ICResp受信失敗");
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVME_CONNECT_ICRESP_TIMEOUT_MS)) {
                return nvme_connect_job_fail(jc, 1, 1, "IO ICResp受信タイムアウト");
            }
            return JOB_WAITING;
        }
        if (nvme_tcp_verify_icresp(&ctx->io, jc->icresp_buf) != 0) {
            return nvme_connect_job_fail(jc, 1, 1, "IO ICResp不正");
        }
        /* NRCV: ICResp受信完了(IO queue)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICRESP;
            info.hlen     = jc->icresp_buf[2];
            info.pdo      = jc->icresp_buf[3];
            info.plen     = rd32le(&jc->icresp_buf[4]);
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 3), &info);
        }
        nvme_build_connect_data(&jc->connect_data, ctx->ctrlr_id, ctx->subnqn);
        nvme_build_fabrics_connect_sqe(&jc->sqe, 1u, sizeof(jc->connect_data));
        nvme_exec_begin(&jc->exec, &ctx->io, &jc->sqe,
                         &jc->connect_data, sizeof(jc->connect_data), NULL, 0);
        self->state = NCONN_ST_EXEC_FABRIC_CONNECT_IO;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_FABRIC_CONNECT_IO: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 1, "IO Fabrics Connect失敗");
        ctx->io_connected = 1;
        uart_printf("[nvme] IO queue接続完了 (qid=1)\n");
        uart_printf("[nvme] 接続完了 (subnqn=%s, lba_size=%u)\n", ctx->subnqn, ctx->lba_size);
        ctx->busy = 0;
        return JOB_DONE;
    }

    default:
        return JOB_DONE;
    }
}

int nvme_connect_job_start(nvme_ctx_t *ctx, uint32_t ip, uint16_t port, const char *subnqn)
{
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    if (ctx->io_connected) {
        uart_printf("[!] nvme: 既に接続済みです(先に`nvme disconnect`してください)\n");
        return -1;
    }
    if (job_active_count() > (unsigned)(JOB_MAX - 1)) {
        uart_printf("[!] nvme: ジョブテーブルに空きが不足\n");
        return -1;
    }

    ctx->io_connected = 0;
    ctx->ctrlr_id     = NVME_CNTLID_DYNAMIC;
    ctx->lba_size     = 512u;  /* nvme_update_lba_size_from_id_ns()が上書きするまでの暫定値 */
    nvme_copy_str(ctx->subnqn, sizeof(ctx->subnqn), subnqn);
    ctx->busy = 1;

    s_nvme_connect_job_ctx.ctx     = ctx;
    s_nvme_connect_job_ctx.ip      = ip;
    s_nvme_connect_job_ctx.port    = port;
    s_nvme_connect_job_ctx.src_ctx = g_active_ctx;

    job_t *connect_job = job_spawn(nvme_connect_job_step, &s_nvme_connect_job_ctx, "nvme-connect");
    if (!connect_job) {
        uart_printf("[!] nvme: ジョブ生成失敗\n");
        ctx->busy = 0;
        return -1;
    }
    job_set_affinity(connect_job, s_nvme_connect_job_ctx.src_ctx);
    return 0;
}

void nvme_build_read_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_IO_CMD_READ | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    nvme_set_sgl(sqe, total_len);
    wr32le(&sqe->cdw10, (uint32_t)(slba & 0xFFFFFFFFu));  /* SLBA下位32bit */
    wr32le(&sqe->cdw11, (uint32_t)(slba >> 32));           /* SLBA上位32bit */
    wr32le(&sqe->cdw12, (uint32_t)(nlb - 1) & 0xFFFFu);    /* NLB(0's based) */
}

void nvme_build_write_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_IO_CMD_WRITE | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    if (total_len > NVME_TCP_INLINE_DATA_MAX) {
        nvme_set_sgl(sqe, total_len);
    } else {
        nvme_set_sgl_inline(sqe, total_len);
    }
    wr32le(&sqe->cdw10, (uint32_t)(slba & 0xFFFFFFFFu));
    wr32le(&sqe->cdw11, (uint32_t)(slba >> 32));
    wr32le(&sqe->cdw12, (uint32_t)(nlb - 1) & 0xFFFFu);
}

static volatile int    s_io_job_done = 0;

typedef struct {
    int        in_use;   /* このスロットが現在1件のwriteを担当中か */
    int        sent;     /* SQEを送信済みか(R2T/RSP待ちの間だけ1) */
    int        done;     /* 完了(結果確定)したか -- in_useのままresultを取り出す猶予を与える */
    int        result;   /* 完了時のCQEステータス(0=success)、通信エラー等は-1 */
    uint16_t   cid;
    nvme_sqe_t sqe;
    const void *data;
    uint32_t   len;
} nvme_pipeline_slot_t;

static nvme_pipeline_slot_t s_pl_slots[NVME_IO_QDEPTH];

typedef enum {
    PL_RX_HDR = 0,
    PL_RX_RSP_REST,
    PL_RX_R2T_REST,
} nvme_pipeline_rx_state_t;

static nvme_pipeline_rx_state_t s_pl_rx_state;
static nvme_tcp_xfer_t          s_pl_xfer;
static uint8_t                  s_pl_hdr_buf[NVME_TCP_HDR_LEN];
static uint8_t                  s_pl_rest_buf[16];

static int nvme_pipeline_find_slot(uint16_t cid)
{
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        if (s_pl_slots[i].in_use && s_pl_slots[i].sent && !s_pl_slots[i].done &&
            s_pl_slots[i].cid == cid) {
            return (int)i;
        }
    }
    return -1;
}

typedef struct {
    int      valid;
    int      slot;
    uint16_t cid;
    uint16_t ttag;
    uint32_t r2to;
    uint32_t r2tl;
} nvme_h2c_pending_t;

#define NVME_H2C_PENDING_MAX NVME_IO_QDEPTH
static nvme_h2c_pending_t s_h2c_pending[NVME_H2C_PENDING_MAX];
static unsigned s_h2c_pending_head;
static unsigned s_h2c_pending_count;

static int nvme_h2c_pending_push(int slot, uint16_t cid, uint16_t ttag, uint32_t r2to, uint32_t r2tl)
{
    if (s_h2c_pending_count >= NVME_H2C_PENDING_MAX) {
        return -1;
    }
    unsigned idx = (s_h2c_pending_head + s_h2c_pending_count) % NVME_H2C_PENDING_MAX;
    s_h2c_pending[idx].valid = 1;
    s_h2c_pending[idx].slot  = slot;
    s_h2c_pending[idx].cid   = cid;
    s_h2c_pending[idx].ttag  = ttag;
    s_h2c_pending[idx].r2to  = r2to;
    s_h2c_pending[idx].r2tl  = r2tl;
    s_h2c_pending_count++;
    return 0;
}

static void nvme_pipeline_rx_tick(nvme_ctx_t *ctx)
{
    int r = nvme_tcp_recv_poll(&ctx->io, &s_pl_xfer);
    if (r < 0) {
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use && s_pl_slots[i].sent && !s_pl_slots[i].done) {
                s_pl_slots[i].done   = 1;
                s_pl_slots[i].result = -1;
            }
        }
        return;
    }
    if (r == 0) {
        return;  /* このPDUの受信途中、次tickへ */
    }

    ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 0),
           ((uint32_t)s_pl_rx_state << 28) | (ctx->io.tcp.rcv_seq & 0x0FFFFFFFu));

    switch (s_pl_rx_state) {
    case PL_RX_HDR: {
        uint8_t type = s_pl_hdr_buf[0];
        ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 1),
               ((uint32_t)type << 24) | ((uint32_t)s_pl_hdr_buf[2] << 16) |
               ((uint32_t)rd32le(&s_pl_hdr_buf[4]) & 0xFFFFu));
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_rest_buf, NVME_CQE_LEN);
            s_pl_rx_state = PL_RX_RSP_REST;
        } else if (type == NVME_TCP_PDU_R2T) {
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_rest_buf, 16u);
            s_pl_rx_state = PL_RX_R2T_REST;
        } else {
            uart_printf("[!] nvme pipeline: 未対応のPDU種別 (type=%u)、読み捨てて再同期を試みます\n", type);
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
            s_pl_rx_state = PL_RX_HDR;
        }
        break;
    }

    case PL_RX_RSP_REST: {
        uint16_t cid    = rd16le(&s_pl_rest_buf[12]);
        uint16_t status = rd16le(&s_pl_rest_buf[14]);
        /* NRCV: Response Capsule(CQE)受信完了(write pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_RSP;
            info.hlen     = s_pl_hdr_buf[2];
            info.pdo      = s_pl_hdr_buf[3];
            info.plen     = rd32le(&s_pl_hdr_buf[4]);
            info.cid      = cid;
            info.status   = status;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 2), &info);
        }
        int slot = nvme_pipeline_find_slot(cid);
        if (slot >= 0) {
            s_pl_slots[slot].done   = 1;
            s_pl_slots[slot].result = (int)nvme_cqe_status_code(status);
        } else {
            uart_printf("[!] nvme pipeline: RSPのCIDが未知のスロット (cid=%u)\n", cid);
        }
        nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
        s_pl_rx_state = PL_RX_HDR;
        break;
    }

    case PL_RX_R2T_REST: {
        uint16_t cccid = rd16le(&s_pl_rest_buf[0]);
        uint16_t ttag  = rd16le(&s_pl_rest_buf[2]);
        uint32_t r2to  = rd32le(&s_pl_rest_buf[4]);
        uint32_t r2tl  = rd32le(&s_pl_rest_buf[8]);
        /* NRCV: R2T受信完了(write pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_R2T;
            info.hlen        = s_pl_hdr_buf[2];
            info.pdo         = s_pl_hdr_buf[3];
            info.plen        = rd32le(&s_pl_hdr_buf[4]);
            info.cccid       = cccid;
            info.ttag        = ttag;
            info.data_offset = r2to;
            info.data_length = r2tl;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 3), &info);
        }
        int slot = nvme_pipeline_find_slot(cccid);
        if (slot >= 0) {
            if (nvme_h2c_pending_push(slot, cccid, ttag, r2to, r2tl) != 0) {
                uart_printf("[!] nvme pipeline: H2C送信キュー満杯 (cccid=%u)\n", cccid);
                s_pl_slots[slot].done   = 1;
                s_pl_slots[slot].result = -1;
            }
        } else {
            uart_printf("[!] nvme pipeline: R2TのCCCIDが未知のスロット (cccid=%u)\n", cccid);
        }
        nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
        s_pl_rx_state = PL_RX_HDR;
        break;
    }
    }
}

typedef struct {
    int      active;
    int      slot;
    uint16_t cid;
    uint16_t ttag;
    uint32_t r2to;
    uint32_t r2tl;
    uint32_t queued;      /* データ部のうち、既にtcp_send_async()でキューした量 */
    int      header_sent;
} nvme_h2c_cursor_t;

static nvme_h2c_cursor_t s_h2c_cursor;

static void nvme_h2c_pipeline_reset(void)
{
    s_h2c_pending_head  = 0;
    s_h2c_pending_count = 0;
    for (unsigned i = 0; i < NVME_H2C_PENDING_MAX; i++) {
        s_h2c_pending[i].valid = 0;
    }
    s_h2c_cursor.active = 0;
}

static void nvme_pipeline_h2c_pump(nvme_ctx_t *ctx)
{
    if (!s_h2c_cursor.active) {
        if (s_h2c_pending_count == 0) {
            return;
        }
        nvme_h2c_pending_t *p = &s_h2c_pending[s_h2c_pending_head];
        s_h2c_cursor.active      = 1;
        s_h2c_cursor.slot        = p->slot;
        s_h2c_cursor.cid         = p->cid;
        s_h2c_cursor.ttag        = p->ttag;
        s_h2c_cursor.r2to        = p->r2to;
        s_h2c_cursor.r2tl        = p->r2tl;
        s_h2c_cursor.queued      = 0;
        s_h2c_cursor.header_sent = 0;
        p->valid = 0;
        s_h2c_pending_head = (s_h2c_pending_head + 1u) % NVME_H2C_PENDING_MAX;
        s_h2c_pending_count--;
    }

    if (!s_h2c_cursor.header_sent) {
        uint8_t hdr[NVME_TCP_DATA_PDU_LEN];
        hdr[0] = NVME_TCP_PDU_H2C_DATA;
        hdr[1] = NVME_TCP_F_DATA_LAST;
        hdr[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        hdr[3] = (uint8_t)NVME_TCP_DATA_PDU_LEN;  /* pdo: データはこのPDU内の固定部直後 */
        wr32le(&hdr[4], NVME_TCP_DATA_PDU_LEN + s_h2c_cursor.r2tl);
        wr16le(&hdr[8],  s_h2c_cursor.cid);
        wr16le(&hdr[10], s_h2c_cursor.ttag);
        wr32le(&hdr[12], s_h2c_cursor.r2to);
        wr32le(&hdr[16], s_h2c_cursor.r2tl);
        wr32le(&hdr[20], 0);  /* reserved */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = hdr[0];
            info.hlen        = hdr[2];
            info.pdo         = hdr[3];
            info.plen        = NVME_TCP_DATA_PDU_LEN + s_h2c_cursor.r2tl;
            info.cccid       = s_h2c_cursor.cid;
            info.ttag        = s_h2c_cursor.ttag;
            info.data_offset = s_h2c_cursor.r2to;
            info.data_length = s_h2c_cursor.r2tl;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_h2c_pump, 0), &info);
        }
        if (tcp_send_async(&ctx->io.tcp, hdr, (uint16_t)NVME_TCP_DATA_PDU_LEN) < 0) {
            uart_printf("[!] nvme pipeline: H2CDataヘッダ送信失敗 (cid=%u)\n", s_h2c_cursor.cid);
            s_pl_slots[s_h2c_cursor.slot].done   = 1;
            s_pl_slots[s_h2c_cursor.slot].result = -1;
            s_h2c_cursor.active = 0;
            return;
        }
        s_h2c_cursor.header_sent = 1;
    }

    const uint8_t *src = (const uint8_t *)s_pl_slots[s_h2c_cursor.slot].data;
    while (s_h2c_cursor.queued < s_h2c_cursor.r2tl) {
        uint32_t remaining = s_h2c_cursor.r2tl - s_h2c_cursor.queued;
        uint16_t chunk = (remaining > TCP_ASYNC_MAX_LEN) ? (uint16_t)TCP_ASYNC_MAX_LEN : (uint16_t)remaining;
        if (s_h2c_cursor.queued == 0) {
            ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_h2c_pump, 1), s_h2c_cursor.cid);
        }
        int rc = tcp_send_async(&ctx->io.tcp,
                                 src + s_h2c_cursor.r2to + s_h2c_cursor.queued, chunk);
        if (rc < 0) {
            uart_printf("[!] nvme pipeline: H2CDataデータ送信失敗 (cid=%u offset=%u)\n",
                        s_h2c_cursor.cid, s_h2c_cursor.r2to + s_h2c_cursor.queued);
            s_pl_slots[s_h2c_cursor.slot].done   = 1;
            s_pl_slots[s_h2c_cursor.slot].result = -1;
            s_h2c_cursor.active = 0;
            return;
        }
        s_h2c_cursor.queued += (uint32_t)rc;
    }
    ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_h2c_pump, 2), s_h2c_cursor.cid);

    /* このPDUは完全にキューし終えた -- 次回の呼び出しで次のPDU(あれば)へ進む。 */
    s_h2c_cursor.active = 0;
}

static uint64_t nvme_bench_next_lba(const nvme_ctx_t *ctx, uint64_t cur,
                                    uint64_t base, uint32_t nlb)
{
    uint64_t next = cur + (uint64_t)nlb;
    if (ctx->nsze == 0u || next + (uint64_t)nlb > ctx->nsze) {
        return base;
    }
    return next;
}

int nvme_write_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                              const void *buf, uint32_t nlb, uint32_t duration_ms,
                              uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms)
{
    if (!ctx->io_connected) {
        uart_printf("[!] nvme pipeline: IO queue未接続\n");
        return -1;
    }
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    ctx->busy = 1;

    uint32_t total_len = nlb * ctx->lba_size;
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        s_pl_slots[i].in_use = 0;
    }
    nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
    s_pl_rx_state = PL_RX_HDR;
    nvme_h2c_pipeline_reset();

    uint64_t cur_lba = lba;  /* fio 同様、コマンドごとに進める(nvme_bench_next_lba) */
    uint32_t count = 0;
    uint64_t bytes = 0;
    uint64_t start = timer_now();

    while (!timeout_ms(start, duration_ms)) {
        sim_delay_tick();  /* 2026-08-11、性能切り分け用の一時計装(smp.h参照) */
        /* 完了済みスロットを刈り取り、集計してから空ける。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use && s_pl_slots[i].done) {
                if (s_pl_slots[i].result == 0) {
                    count++;
                    bytes += s_pl_slots[i].len;
                } else {
                    uart_printf("[!] nvme pipeline: write失敗 (cid=%u result=%d)\n",
                                s_pl_slots[i].cid, s_pl_slots[i].result);
                }
                s_pl_slots[i].in_use = 0;
            }
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (!s_pl_slots[i].in_use) {
                s_pl_slots[i].in_use = 1;
                s_pl_slots[i].sent   = 0;
                s_pl_slots[i].done   = 0;
                s_pl_slots[i].result = 0;
                s_pl_slots[i].data   = buf;
                s_pl_slots[i].len    = total_len;
                nvme_build_write_sqe(&s_pl_slots[i].sqe, nsid, cur_lba, nlb, total_len);
                cur_lba = nvme_bench_next_lba(ctx, cur_lba, lba, nlb);
            }
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use && !s_pl_slots[i].sent) {
                uint16_t cid = 0;
                if (nvme_tcp_send_cmd_async(&ctx->io, &s_pl_slots[i].sqe, &cid) != 0) {
                    s_pl_slots[i].done   = 1;
                    s_pl_slots[i].result = -1;
                    continue;
                }
                {
                    const uint8_t *sqe_bytes = (const uint8_t *)&s_pl_slots[i].sqe;
                    volatile ts_nvme_pdu_t info = {0};
                    info.pdu_type    = NVME_TCP_PDU_CMD;
                    info.hlen        = (uint8_t)NVME_TCP_CMD_PDU_LEN;
                    info.pdo         = 0;
                    info.plen        = NVME_TCP_CMD_PDU_LEN;
                    info.cid         = cid;
                    info.opcode      = sqe_bytes[0];
                    info.sgl_type    = sqe_bytes[39];
                    info.data_length = rd32le(&sqe_bytes[32]);  /* LEN(SGL宣言転送量) */
                    ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_write_pipelined_run, 0), &info);
                }
                s_pl_slots[i].cid  = cid;
                s_pl_slots[i].sent = 1;
            }
        }
        nvme_pipeline_rx_tick(ctx);
        nvme_pipeline_h2c_pump(ctx);
        job_scheduler_tick();
    }

    {
        uint64_t drain_start = timer_now();
        while (!timeout_ms(drain_start, NVME_IO_CMD_TIMEOUT_MS)) {
            int any_outstanding = 0;
            for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
                if (s_pl_slots[i].in_use && !s_pl_slots[i].done) {
                    any_outstanding = 1;
                }
            }
            if (!any_outstanding) break;
            nvme_pipeline_rx_tick(ctx);
            nvme_pipeline_h2c_pump(ctx);
            job_scheduler_tick();
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use) {
                if (s_pl_slots[i].done && s_pl_slots[i].result == 0) {
                    count++;
                    bytes += s_pl_slots[i].len;
                } else if (!s_pl_slots[i].done) {
                    uart_printf("[!] nvme pipeline: drainタイムアウト、未完了のまま諦めます (cid=%u)\n",
                                s_pl_slots[i].cid);
                }
                s_pl_slots[i].in_use = 0;
            }
        }
    }

    uint32_t elapsed_ms = (uint32_t)get_ms_from(start);
    ctx->busy = 0;
    if (out_count)      *out_count      = count;
    if (out_bytes)      *out_bytes      = bytes;
    if (out_elapsed_ms) *out_elapsed_ms = elapsed_ms;
    return 0;
}

typedef struct {
    int        in_use;
    int        sent;
    int        done;
    int        result;
    uint16_t   cid;
    nvme_sqe_t sqe;
    void      *data;   /* 読み出し先バッファ(呼び出し元所有) */
    uint32_t   len;    /* 期待する合計長 */
} nvme_pipeline_read_slot_t;

typedef enum {
    PL_READ_RX_HDR = 0,
    PL_READ_RX_RSP_REST,
    PL_READ_RX_C2H_REST,
    PL_READ_RX_C2H_DATA,
} nvme_pipeline_read_rx_state_t;

static uint8_t s_pl_read_discard_buf[262144] __attribute__((aligned(64)));

typedef enum { NRX_HDR, NRX_PSH, NRX_DATA } nvme_read_prx_phase_t;

typedef struct {
    nvme_pipeline_read_slot_t     slots[NVME_IO_QDEPTH];
    nvme_pipeline_read_rx_state_t rx_state;
    nvme_tcp_xfer_t               xfer;
    uint8_t                       hdr_buf[NVME_TCP_HDR_LEN];
    uint8_t                       rest_buf[16];
    int                           cur_slot;
    uint16_t                      cur_cccid;
    uint32_t                      cur_datao;
    uint32_t                      cur_datal;
    /* push型受信(upcall)パーサ状態 */
    nvme_read_prx_phase_t nrx_phase;
    uint8_t   nrx_hdr[NVME_TCP_HDR_LEN];
    uint32_t  nrx_hdr_off;
    uint8_t   nrx_psh[16];
    uint32_t  nrx_psh_off, nrx_psh_need;
    uint8_t   nrx_type;
    volatile uint8_t *nrx_data_dst;
    uint32_t  nrx_data_off, nrx_data_need;
    int       nrx_slot;
    int       nrx_error;
} nvme_rd_state_t;
static nvme_rd_state_t s_rd[SMP_MAX_CORES];

static int nvme_pipeline_read_find_slot(uint16_t cid)
{
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        if (rd->slots[i].in_use && rd->slots[i].sent && !rd->slots[i].done &&
            rd->slots[i].cid == cid) {
            return (int)i;
        }
    }
    return -1;
}

static void nvme_read_rx_upcall(void *arg, const volatile uint8_t *data, uint16_t len)
{
    (void)arg;
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    uint32_t i = 0;
    while (i < (uint32_t)len && !rd->nrx_error) {
        switch (rd->nrx_phase) {
        case NRX_HDR: {
            uint32_t take = (uint32_t)NVME_TCP_HDR_LEN - rd->nrx_hdr_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) rd->nrx_hdr[rd->nrx_hdr_off + k] = data[i + k];
            rd->nrx_hdr_off += take; i += take;
            if (rd->nrx_hdr_off == (uint32_t)NVME_TCP_HDR_LEN) {
                rd->nrx_type = rd->nrx_hdr[0];
                uint8_t hlen = rd->nrx_hdr[2];
                rd->nrx_psh_need = (hlen > NVME_TCP_HDR_LEN) ? (uint32_t)(hlen - NVME_TCP_HDR_LEN) : 0u;
                if (rd->nrx_psh_need == 0u || rd->nrx_psh_need > sizeof(rd->nrx_psh)) { rd->nrx_error = 1; break; }
                rd->nrx_psh_off = 0; rd->nrx_phase = NRX_PSH;
            }
            break;
        }
        case NRX_PSH: {
            uint32_t take = rd->nrx_psh_need - rd->nrx_psh_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) rd->nrx_psh[rd->nrx_psh_off + k] = data[i + k];
            rd->nrx_psh_off += take; i += take;
            if (rd->nrx_psh_off < rd->nrx_psh_need) break;

            if (rd->nrx_type == NVME_TCP_PDU_C2H_DATA) {
                uint16_t cccid = rd16le(&rd->nrx_psh[0]);
                uint32_t datao = rd32le(&rd->nrx_psh[4]);
                uint32_t datal = rd32le(&rd->nrx_psh[8]);
                int slot = nvme_pipeline_read_find_slot(cccid);
                if (slot < 0 || (uint64_t)datao + (uint64_t)datal > (uint64_t)rd->slots[slot].len) {
                    if (slot >= 0) { rd->slots[slot].done = 1; rd->slots[slot].result = -1; }
                    rd->nrx_slot = -1;   /* データは読み捨て(下記でコピーせず消費のみ) */
                } else {
                    rd->nrx_slot = slot;
                    rd->nrx_data_dst = (volatile uint8_t *)rd->slots[slot].data + datao;
                }
                rd->nrx_data_need = datal;
                if (datal == 0u) {
                    if (rd->nrx_slot >= 0 && (rd->nrx_hdr[1] & NVME_TCP_F_DATA_SUCCESS)) {
                        rd->slots[rd->nrx_slot].done = 1; rd->slots[rd->nrx_slot].result = 0;
                    }
                    rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0;
                } else {
                    rd->nrx_data_off = 0; rd->nrx_phase = NRX_DATA;
                }
            } else if (rd->nrx_type == NVME_TCP_PDU_RSP) {
                uint16_t cid    = rd16le(&rd->nrx_psh[12]);
                uint16_t status = rd16le(&rd->nrx_psh[14]);
                int slot = nvme_pipeline_read_find_slot(cid);
                if (slot >= 0) {
                    rd->slots[slot].done = 1;
                    rd->slots[slot].result = (int)nvme_cqe_status_code(status);
                }
                rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0;
            } else {
                rd->nrx_error = 1;
            }
            break;
        }
        case NRX_DATA: {
            uint32_t need  = rd->nrx_data_need - rd->nrx_data_off;
            uint32_t avail = (uint32_t)len - i;
            uint32_t take  = (need > avail) ? avail : need;
            if (rd->nrx_slot >= 0) {
                volatile_fast_copy(rd->nrx_data_dst + rd->nrx_data_off, data + i, take);
            }
            rd->nrx_data_off += take; i += take;
            if (rd->nrx_data_off == rd->nrx_data_need) {
                if (rd->nrx_slot >= 0 && (rd->nrx_hdr[1] & NVME_TCP_F_DATA_SUCCESS)) {
                    rd->slots[rd->nrx_slot].done = 1; rd->slots[rd->nrx_slot].result = 0;
                }
                rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0;
            }
            break;
        }
        }
    }
}

static void nvme_pipeline_read_rx_tick(nvme_ctx_t *ctx)
{
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    int r = nvme_tcp_recv_poll(&ctx->io, &rd->xfer);
    if (r < 0) {
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use && rd->slots[i].sent && !rd->slots[i].done) {
                rd->slots[i].done   = 1;
                rd->slots[i].result = -1;
            }
        }
        return;
    }
    if (r == 0) {
        return;  /* このPDUの受信途中、次tickへ */
    }

    switch (rd->rx_state) {
    case PL_READ_RX_HDR: {
        uint8_t type = rd->hdr_buf[0];
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&rd->xfer, rd->rest_buf, NVME_CQE_LEN);
            rd->rx_state = PL_READ_RX_RSP_REST;
        } else if (type == NVME_TCP_PDU_C2H_DATA) {
            nvme_tcp_xfer_reset(&rd->xfer, rd->rest_buf, 16u);
            rd->rx_state = PL_READ_RX_C2H_REST;
        } else {
            uart_printf("[!] nvme read pipeline: 未対応のPDU種別 (type=%u)、読み捨てて再同期を試みます\n", type);
            nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
            rd->rx_state = PL_READ_RX_HDR;
        }
        break;
    }

    case PL_READ_RX_RSP_REST: {
        uint16_t cid    = rd16le(&rd->rest_buf[12]);
        uint16_t status = rd16le(&rd->rest_buf[14]);
        /* NRCV: Response Capsule(CQE)受信完了(read pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_RSP;
            info.hlen     = rd->hdr_buf[2];
            info.pdo      = rd->hdr_buf[3];
            info.plen     = rd32le(&rd->hdr_buf[4]);
            info.cid      = cid;
            info.status   = status;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_read_rx_tick, 0), &info);
        }
        int slot = nvme_pipeline_read_find_slot(cid);
        if (slot >= 0) {
            rd->slots[slot].done   = 1;
            rd->slots[slot].result = (int)nvme_cqe_status_code(status);
        } else {
            uart_printf("[!] nvme read pipeline: RSPのCIDが未知のスロット (cid=%u)\n", cid);
        }
        nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
        rd->rx_state = PL_READ_RX_HDR;
        break;
    }

    case PL_READ_RX_C2H_REST: {
        uint16_t cccid = rd16le(&rd->rest_buf[0]);
        uint32_t datao = rd32le(&rd->rest_buf[4]);
        uint32_t datal = rd32le(&rd->rest_buf[8]);
        int slot = nvme_pipeline_read_find_slot(cccid);
        if (slot < 0) {
            uart_printf("[!] nvme read pipeline: C2HDataのCCCIDが未知のスロット (cccid=%u)、読み捨てます\n", cccid);
            rd->cur_slot = -1;
        } else if ((uint64_t)datao + (uint64_t)datal > (uint64_t)rd->slots[slot].len) {
            uart_printf("[!] nvme read pipeline: C2HDataがバッファ超過 (datao=%u datal=%u len=%u)\n",
                        datao, datal, rd->slots[slot].len);
            rd->slots[slot].done   = 1;
            rd->slots[slot].result = -1;
            rd->cur_slot = -1;
        } else {
            rd->cur_slot = slot;
        }
        rd->cur_cccid = cccid;
        rd->cur_datao = datao;
        rd->cur_datal = datal;
        if (rd->cur_slot >= 0) {
            nvme_tcp_xfer_reset(&rd->xfer,
                                 (uint8_t *)rd->slots[rd->cur_slot].data + datao, datal);
        } else {
            uint32_t discard_len = (datal > sizeof(s_pl_read_discard_buf))
                                        ? (uint32_t)sizeof(s_pl_read_discard_buf) : datal;
            nvme_tcp_xfer_reset(&rd->xfer, s_pl_read_discard_buf, discard_len);
        }
        rd->rx_state = PL_READ_RX_C2H_DATA;
        break;
    }

    case PL_READ_RX_C2H_DATA: {
        uint8_t flags = rd->hdr_buf[1];
        /* NRCV: C2HData受信完了(read pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_C2H_DATA;
            info.hlen        = rd->hdr_buf[2];
            info.pdo         = rd->hdr_buf[3];
            info.plen        = rd32le(&rd->hdr_buf[4]);
            info.cccid       = rd->cur_cccid;
            info.data_offset = rd->cur_datao;
            info.data_length = rd->cur_datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_read_rx_tick, 1), &info);
        }
        if (rd->cur_slot >= 0 && (flags & NVME_TCP_F_DATA_SUCCESS)) {
            rd->slots[rd->cur_slot].done   = 1;
            rd->slots[rd->cur_slot].result = 0;
        }
        nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
        rd->rx_state = PL_READ_RX_HDR;
        break;
    }
    }
}

int nvme_read_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                             void *buf, uint32_t nlb, uint32_t duration_ms,
                             uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms)
{
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    if (!ctx->io_connected) {
        uart_printf("[!] nvme read pipeline: IO queue未接続\n");
        return -1;
    }
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    ctx->busy = 1;

    uint32_t total_len = nlb * ctx->lba_size;
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        rd->slots[i].in_use = 0;
    }
    nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
    rd->rx_state = PL_READ_RX_HDR;
    rd->cur_slot = -1;

    rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0; rd->nrx_error = 0; rd->nrx_slot = -1;
    tcp_set_recv_upcall(&ctx->io.tcp, nvme_read_rx_upcall, NULL);

    uint64_t cur_lba = lba;  /* fio 同様、コマンドごとに進める(nvme_bench_next_lba) */
    uint32_t count = 0;
    uint64_t bytes = 0;
    uint64_t start = timer_now();

    while (!timeout_ms(start, duration_ms)) {
        sim_delay_tick();  /* 2026-08-11、性能切り分け用の一時計装(smp.h参照) */
        /* 完了済みスロットを刈り取り、集計してから空ける。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use && rd->slots[i].done) {
                if (rd->slots[i].result == 0) {
                    count++;
                    bytes += rd->slots[i].len;
                } else {
                    uart_printf("[!] nvme read pipeline: read失敗 (cid=%u result=%d)\n",
                                rd->slots[i].cid, rd->slots[i].result);
                }
                rd->slots[i].in_use = 0;
            }
        }
        uint32_t rx_cap = tcp_rx_buf_size();
        unsigned max_inflight = NVME_IO_QDEPTH;
        if (total_len > 0u && rx_cap > total_len) {
            uint32_t m = rx_cap / total_len;
            if (m > 0u) m -= 1u;               /* 1 転送分の headroom を残す */
            if (m == 0u) m = 1u;
            if (m < max_inflight) max_inflight = (unsigned)m;
        }
        unsigned inflight = 0;
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use) inflight++;
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH && inflight < max_inflight; i++) {
            if (!rd->slots[i].in_use) {
                inflight++;
                rd->slots[i].in_use = 1;
                rd->slots[i].sent   = 0;
                rd->slots[i].done   = 0;
                rd->slots[i].result = 0;
                rd->slots[i].data   = buf;
                rd->slots[i].len    = total_len;
                nvme_build_read_sqe(&rd->slots[i].sqe, nsid, cur_lba, nlb, total_len);
                cur_lba = nvme_bench_next_lba(ctx, cur_lba, lba, nlb);
            }
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use && !rd->slots[i].sent) {
                uint16_t cid = 0;
                if (nvme_tcp_send_cmd_async(&ctx->io, &rd->slots[i].sqe, &cid) != 0) {
                    rd->slots[i].done   = 1;
                    rd->slots[i].result = -1;
                    continue;
                }
                {
                    const uint8_t *sqe_bytes = (const uint8_t *)&rd->slots[i].sqe;
                    volatile ts_nvme_pdu_t info = {0};
                    info.pdu_type    = NVME_TCP_PDU_CMD;
                    info.hlen        = (uint8_t)NVME_TCP_CMD_PDU_LEN;
                    info.pdo         = 0;
                    info.plen        = NVME_TCP_CMD_PDU_LEN;
                    info.cid         = cid;
                    info.opcode      = sqe_bytes[0];
                    info.sgl_type    = sqe_bytes[39];
                    info.data_length = rd32le(&sqe_bytes[32]);  /* LEN(SGL宣言転送量) */
                    ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_read_pipelined_run, 0), &info);
                }
                rd->slots[i].cid  = cid;
                rd->slots[i].sent = 1;
            }
        }
        nvme_pipeline_read_rx_tick(ctx);
        job_scheduler_tick();
    }

    {
        uint64_t drain_start = timer_now();
        while (!timeout_ms(drain_start, NVME_IO_CMD_TIMEOUT_MS)) {
            int any_outstanding = 0;
            for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
                if (rd->slots[i].in_use && !rd->slots[i].done) {
                    any_outstanding = 1;
                }
            }
            if (!any_outstanding) break;
            nvme_pipeline_read_rx_tick(ctx);
            job_scheduler_tick();
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use) {
                if (rd->slots[i].done && rd->slots[i].result == 0) {
                    count++;
                    bytes += rd->slots[i].len;
                } else if (!rd->slots[i].done) {
                    uart_printf("[!] nvme read pipeline: drainタイムアウト、未完了のまま諦めます (cid=%u)\n",
                                rd->slots[i].cid);
                }
                rd->slots[i].in_use = 0;
            }
        }
    }

    tcp_clear_recv_upcall(&ctx->io.tcp);  /* push型受信を解除(pull経路へ戻す) */
    uint32_t elapsed_ms = (uint32_t)get_ms_from(start);
    ctx->busy = 0;
    if (out_count)      *out_count      = count;
    if (out_bytes)      *out_bytes      = bytes;
    if (out_elapsed_ms) *out_elapsed_ms = elapsed_ms;
    return 0;
}
