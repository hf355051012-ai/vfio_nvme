#include "nvme_rdma.h"
#include "net.h"
#include "nvme_types.h"
#include "uart.h"
#include "timer.h"
#include "cache.h"
#include "job.h"
#include "nvmet_rdma.h"
#include "smp.h"
#include "platform.h"

static volatile uint8_t *nvmer_ramdisk_slot1(void)
{
    static volatile uint8_t *s_rd1 = 0;
    if (s_rd1 == 0) {
        s_rd1 = (volatile uint8_t *)dma_alloc(NVMET_RDMA_RAMDISK_SLOT_SIZE,
                                              0x200000ULL, DMA_COHERENT).cpu;
    }
    return s_rd1;
}

#define NVME_RDMA_QSIZE               32u
#define NVME_RDMA_CTRL_READY_POLL_MAX 20u
#define NVME_RDMA_CTRL_READY_POLL_MS 100u
#define NVME_RDMA_CMD_TIMEOUT_MS    5000u

static const uint8_t NVME_RDMA_HOST_ID[16] = {
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
};
#define NVME_RDMA_HOST_NQN "nqn.2014-08.org.nvmexpress:uuid:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf"

static void nvmer_zero_v(volatile uint8_t *p, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) p[i] = 0;
}

static void nvmer_copy_str_v(volatile uint8_t *dst, uint32_t field_len, const char *src)
{
    uint32_t i = 0;
    while (src[i] != '\0' && i < field_len) {
        dst[i] = (uint8_t)src[i];
        i++;
    }
}

static void nvmer_set_ksgl(volatile uint8_t *dptr, uint64_t addr, uint32_t len, uint32_t key)
{
    wr64le(&dptr[0], addr);
    dptr[8]  = (uint8_t)len;
    dptr[9]  = (uint8_t)(len >> 8);
    dptr[10] = (uint8_t)(len >> 16);
    dptr[11] = (uint8_t)key;
    dptr[12] = (uint8_t)(key >> 8);
    dptr[13] = (uint8_t)(key >> 16);
    dptr[14] = (uint8_t)(key >> 24);
    dptr[15] = (uint8_t)NVME_SGL_TYPE_KEYED_DATA_BLOCK;
}

static uint32_t nvmer_build_connect(nvme_rdma_ctx_t *ctx, uint16_t qid, const char *subnqn)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u + 1024u);
    wr32le(&b[0], NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], NVME_FABRIC_FCTYPE_CONNECT);
    wr32le(&b[32], 1024u);
    b[39] = (uint8_t)NVME_SGL_TYPE_DATA_BLOCK_OFFSET;
    wr32le(&b[40], (uint32_t)qid << 16);
    wr32le(&b[44], (uint32_t)(NVME_RDMA_QSIZE - 1) & 0xFFFFu);
    wr32le(&b[48], 0);

    volatile uint8_t *cd = &b[64];
    for (unsigned i = 0; i < 16; i++) cd[i] = NVME_RDMA_HOST_ID[i];
    wr16le(&cd[16], 0xFFFFu); /* cntlid: dynamic */
    nvmer_copy_str_v(&cd[256], 256u, subnqn);
    nvmer_copy_str_v(&cd[512], 256u, NVME_RDMA_HOST_NQN);
    return 64u + 1024u;
}

static uint32_t nvmer_build_prop_set(nvme_rdma_ctx_t *ctx, uint32_t offset, uint64_t value)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], NVME_FABRIC_FCTYPE_PROPERTY_SET);
    nvmer_set_ksgl(&b[24], 0, 0, 0);
    wr32le(&b[40], 0u); /* attrib=0 */
    wr32le(&b[44], offset);
    wr32le(&b[48], (uint32_t)(value & 0xFFFFFFFFu));
    wr32le(&b[52], (uint32_t)(value >> 32));
    return 64u;
}

static uint32_t nvmer_build_prop_get(nvme_rdma_ctx_t *ctx, uint32_t offset)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], NVME_FABRIC_FCTYPE_PROPERTY_GET);
    nvmer_set_ksgl(&b[24], 0, 0, 0);
    wr32le(&b[40], 0u);
    wr32le(&b[44], offset);
    return 64u;
}

static uint32_t nvmer_build_identify(nvme_rdma_ctx_t *ctx, uint8_t cns, uint32_t nsid,
                                     volatile uint8_t *dest, uint32_t dest_len)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], NVME_ADM_CMD_IDENTIFY | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], nsid);
    nvmer_set_ksgl(&b[24], mlx5_dma_addr((const void *)(uintptr_t)dest), dest_len, ctx->cm.rc_qp.mkey);
    wr32le(&b[40], (uint32_t)cns);
    return 64u;
}

static uint32_t nvmer_build_io_ex(nvme_rdma_ctx_t *ctx, volatile uint8_t *out, uint16_t cid,
                                  uint8_t opcode, uint32_t nsid, uint64_t slba,
                                  uint32_t nlb, volatile uint8_t *buf, uint32_t total_len)
{
    volatile uint8_t *b = out;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], (uint32_t)opcode | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], cid);
    wr32le(&b[4], nsid);
    nvmer_set_ksgl(&b[24], mlx5_dma_addr((const void *)(uintptr_t)buf), total_len, ctx->cm.rc_qp.mkey);
    wr32le(&b[40], (uint32_t)(slba & 0xFFFFFFFFu));
    wr32le(&b[44], (uint32_t)(slba >> 32));
    wr32le(&b[48], (uint32_t)(nlb - 1u) & 0xFFFFu);
    return 64u;
}

static uint64_t nvmer_next_lba(nvme_rdma_ctx_t *ctx, uint32_t nlb)
{
    uint64_t lba = ctx->bench_cur_lba;
    uint64_t next = lba + (uint64_t)nlb;
    if (ctx->nsze == 0u || next + (uint64_t)nlb > ctx->nsze) {
        next = 0u;
    }
    ctx->bench_cur_lba = next;
    return lba;
}

static uint32_t nvmer_build_io(nvme_rdma_ctx_t *ctx, uint8_t opcode, uint32_t nsid, uint64_t slba,
                               uint32_t nlb, volatile uint8_t *buf, uint32_t total_len)
{
    return nvmer_build_io_ex(ctx, ctx->send_buf, ctx->cur_cid, opcode, nsid, slba, nlb, buf, total_len);
}

static int nvmer_post_recv(nvme_rdma_ctx_t *ctx)
{
    return mlx5_qp_post_recv(ctx->cm.dev, &ctx->cm.rc_qp, (void *)(uintptr_t)ctx->recv_buf,
                             sizeof(ctx->recv_buf));
}

static void nvmer_post_send(nvme_rdma_ctx_t *ctx, uint32_t len)
{
    dcache_clean_range((const void *)(uintptr_t)ctx->send_buf, len);
    mlx5_qp_post_send(ctx->cm.dev, &ctx->cm.rc_qp, (const void *)(uintptr_t)ctx->send_buf, len);
    ctx->send_done = 0;
    ctx->recv_done = 0;
    ctx->cmd_deadline = timer_now();
}

static int nvmer_wait_exec(nvme_rdma_ctx_t *ctx)
{
    if (!ctx->send_done || !ctx->recv_done) {
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe(ctx->cm.dev, &ctx->cm.rc_qp, &is_send, &recv_len, &synd);
        if (rc < 0) {
            uart_printf("[!] nvme-rdma: CQEエラー syndrome=0x%02x\n", synd);
            return -1;
        }
        if (rc == 1) {
            if (is_send) {
                ctx->send_done = 1;
            } else {
                dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, recv_len);
                ctx->recv_len = recv_len;
                ctx->recv_done = 1;
            }
        }
    }
    if (ctx->send_done && ctx->recv_done) return 1;
    if (timeout_ms(ctx->cmd_deadline, NVME_RDMA_CMD_TIMEOUT_MS)) {
        uart_printf("[!] nvme-rdma: 応答待ちタイムアウト (send_done=%d recv_done=%d)\n",
                    ctx->send_done, ctx->recv_done);
        return -1;
    }
    return 0;
}

static job_result_t nvmer_fail(nvme_rdma_ctx_t *ctx, const char *msg)
{
    uart_printf("[!] nvme-rdma: %s\n", msg);
    ctx->failed = 1;
    ctx->done = 1;
    return JOB_DONE;
}

typedef struct {
    int      in_use;
    uint16_t cid;
} nvme_rdma_pl_slot_t;

static nvme_rdma_pl_slot_t s_pl_slots[NVME_RDMA_PL_QDEPTH_MAX];
static volatile uint8_t s_pl_send_bufs[NVME_RDMA_PL_QDEPTH_MAX][64] __attribute__((aligned(64)));
static volatile uint8_t s_pl_recv_bufs[NVME_RDMA_PL_QDEPTH_MAX][64] __attribute__((aligned(64)));
static unsigned s_pl_rq_order[NVME_RDMA_PL_QDEPTH_MAX];
static unsigned s_pl_rq_head, s_pl_rq_tail;

static int nvmer_pl_post_recv_slot(nvme_rdma_ctx_t *ctx, unsigned slot)
{
    if (mlx5_qp_post_recv(ctx->cm.dev, &ctx->cm.rc_qp, (void *)(uintptr_t)s_pl_recv_bufs[slot],
                          sizeof(s_pl_recv_bufs[slot])) != 0) {
        return -1;
    }
    s_pl_rq_order[s_pl_rq_tail % NVME_RDMA_PL_QDEPTH_MAX] = slot;
    s_pl_rq_tail++;
    return 0;
}

static nvme_rdma_state_t nvmer_resume_state_after_identify(nvme_rdma_ctx_t *ctx)
{
    if (ctx->bench_enabled && ctx->bench_qdepth > 1u) {
        return NVMER_ST_PIPELINE_SETUP;
    } else if (ctx->bench_enabled) {
        ctx->bench_start_ticks = timer_now();
        ctx->bench_count = 0;
        ctx->bench_bytes = 0;
        return ctx->bench_is_read ? NVMER_ST_SEND_READ : NVMER_ST_SEND_WRITE;
    }
    return NVMER_ST_SEND_WRITE;
}

job_result_t nvme_rdma_connect_job_step(job_t *self)
{
    nvme_rdma_ctx_t *ctx = (nvme_rdma_ctx_t *)self->ctx;

    if (ctx->stop_requested || self->cancel_requested) {
        ctx->done = 1;
        return JOB_DONE;
    }

    switch (self->state) {

    case NVMER_ST_CM_SPAWN: {
        ctx->cm.is_active = 1;
        ctx->cm.skip_ping = 1;
        job_t *cmjob = job_spawn(rdma_cm_job_step, &ctx->cm, "nvme-rdma-cm");
        if (!cmjob) return nvmer_fail(ctx, "CM用ジョブ生成失敗");
        cmjob->state = RDMA_CM_ST_ACTIVE_SETUP;
        self->state = NVMER_ST_CM_WAIT;
        return JOB_WAITING;
    }

    case NVMER_ST_CM_WAIT: {
        if (ctx->cm.failed) return nvmer_fail(ctx, "CM確立失敗");
        if (!ctx->cm.established) return JOB_WAITING;
        uart_printf("[nvme-rdma] RC QP確立完了 (qpn=%u)\n", ctx->cm.rc_qp.qpn);
        ctx->nsid = 1u;
        ctx->cur_cid = 0x100u;
        self->state = NVMER_ST_SEND_CONNECT;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_CONNECT: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Connect)失敗");
        uint32_t len = nvmer_build_connect(ctx, 0u, NVMET_RDMA_SUBNQN);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_CONNECT;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_CONNECT: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Fabrics Connect失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Fabrics Connect: 応答エラー");
        ctx->cntlid = (uint16_t)(rd32le(&ctx->recv_buf[0]) & 0xFFFFu);
        uart_printf("[nvme-rdma] Fabrics Connect完了 (cntlid=%u)\n", ctx->cntlid);
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_PROP_SET_CC;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_PROP_SET_CC: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(PropSet CC)失敗");
        uint32_t cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_AMS_RR | NVME_CC_SHN_NONE |
                      NVME_CC_IOSQES | NVME_CC_IOCQES;
        uint32_t len = nvmer_build_prop_set(ctx, NVME_REG_CC, cc);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_PROP_SET_CC;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_PROP_SET_CC: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Property Set(CC)失敗");
        ctx->csts_poll_count = 0;
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_PROP_GET_CSTS;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_PROP_GET_CSTS: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(PropGet CSTS)失敗");
        uint32_t len = nvmer_build_prop_get(ctx, NVME_REG_CSTS);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_PROP_GET_CSTS;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_PROP_GET_CSTS: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Property Get(CSTS)失敗");
        uint32_t csts = rd32le(&ctx->recv_buf[0]);
        if (csts & NVME_CSTS_CFS) return nvmer_fail(ctx, "CSTS.CFS(コントローラ致命的状態)");
        if (csts & NVME_CSTS_RDY) {
            uart_printf("[nvme-rdma] コントローラ有効化完了 (CSTS.RDY=1)\n");
            ctx->cur_cid++;
            self->state = NVMER_ST_SEND_ID_CTRL;
            return JOB_WAITING;
        }
        ctx->csts_poll_count++;
        if (ctx->csts_poll_count >= NVME_RDMA_CTRL_READY_POLL_MAX) {
            return nvmer_fail(ctx, "CSTS.RDY待ちタイムアウト");
        }
        ctx->wait_started_ticks = timer_now();
        self->state = NVMER_ST_CSTS_POLL_WAIT;
        return JOB_WAITING;
    }

    case NVMER_ST_CSTS_POLL_WAIT: {
        if (!timeout_ms(ctx->wait_started_ticks, NVME_RDMA_CTRL_READY_POLL_MS)) return JOB_WAITING;
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_PROP_GET_CSTS;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_ID_CTRL: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Identify Ctrl)失敗");
        uint32_t len = nvmer_build_identify(ctx, (uint8_t)NVME_IDENTIFY_CNS_CONTROLLER, 0u,
                                            ctx->id_ctrl, NVME_RDMA_ID_BUF_LEN);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_ID_CTRL;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_ID_CTRL: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Identify Controller失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Identify Controller: 応答エラー");
        dcache_invalidate_range((const void *)(uintptr_t)ctx->id_ctrl, NVME_RDMA_ID_BUF_LEN);
        uart_printf("[nvme-rdma] Identify Controller完了\n");
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_ID_NS;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_ID_NS: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Identify NS)失敗");
        uint32_t len = nvmer_build_identify(ctx, (uint8_t)NVME_IDENTIFY_CNS_NAMESPACE, ctx->nsid,
                                            ctx->id_ns, NVME_RDMA_ID_BUF_LEN);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_ID_NS;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_ID_NS: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Identify Namespace失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Identify Namespace: 応答エラー");
        dcache_invalidate_range((const void *)(uintptr_t)ctx->id_ns, NVME_RDMA_ID_BUF_LEN);
        uint8_t flbas = (uint8_t)(ctx->id_ns[NVME_ID_NS_OFF_FLBAS] & 0x0Fu);
        uint32_t lbaf_off = NVME_ID_NS_OFF_LBAF0 + (uint32_t)flbas * 4u;
        uint8_t ds = ctx->id_ns[lbaf_off + 2];
        ctx->lba_size = (uint32_t)1u << ds;
        ctx->nsze = rd64le(&ctx->id_ns[0]);
        uart_printf("[nvme-rdma] Identify Namespace完了 (lba_size=%u バイト nsze=%u ブロック)\n",
                    ctx->lba_size, (unsigned)ctx->nsze);
        ctx->cur_cid++;
        ctx->reusable = 1;
        ctx->established_generation = ctx->cm.dev->bringup_generation;
        self->state = nvmer_resume_state_after_identify(ctx);
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_WRITE: {
        uint32_t len = ctx->bench_enabled ? ctx->bench_chunk_bytes : ctx->lba_size;
        if (len == 0 || len > sizeof(ctx->write_buf)) len = NVME_RDMA_TEST_LEN;
        uint32_t nlb = (ctx->lba_size != 0) ? (len / ctx->lba_size) : 1u;
        if (nlb == 0) nlb = 1u;
        if (!ctx->bench_enabled || ctx->bench_count == 0) {
            for (uint32_t i = 0; i < len; i++) ctx->write_buf[i] = (uint8_t)(0xC0u + (i & 0x3Fu));
            dcache_clean_range((const void *)(uintptr_t)ctx->write_buf, len);
        }
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Write)失敗");
        uint64_t slba = ctx->bench_enabled ? nvmer_next_lba(ctx, nlb) : 0u;
        uint32_t slen = nvmer_build_io(ctx, NVME_IO_CMD_WRITE, ctx->nsid, slba, nlb, ctx->write_buf, len);
        nvmer_post_send(ctx, slen);
        self->state = NVMER_ST_WAIT_WRITE;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_WRITE: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Write失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        int ok = (nvme_cqe_status_code(status) == 0);
        if (ctx->bench_enabled) {
            if (!ok) return nvmer_fail(ctx, "Write(bench): 応答エラー");
            ctx->bench_count++;
            ctx->bench_bytes += ctx->bench_chunk_bytes;
            ctx->cur_cid++;
            if (timeout_ms(ctx->bench_start_ticks, ctx->bench_duration_ms)) {
                ctx->done = 1;
                self->state = NVMER_ST_DONE_OK;
                return JOB_DONE;
            }
            self->state = NVMER_ST_SEND_WRITE;
            return JOB_WAITING;
        }
        ctx->write_ok = ok;
        uart_printf("[nvme-rdma] Write完了 (%s)\n", ctx->write_ok ? "成功" : "エラー応答");
        if (!ctx->write_ok) return nvmer_fail(ctx, "Write: 応答エラー");
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_READ;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_READ: {
        uint32_t len = ctx->bench_enabled ? ctx->bench_chunk_bytes : ctx->lba_size;
        if (len == 0 || len > sizeof(ctx->read_buf)) len = NVME_RDMA_TEST_LEN;
        uint32_t nlb = (ctx->lba_size != 0) ? (len / ctx->lba_size) : 1u;
        if (nlb == 0) nlb = 1u;
        if (!ctx->bench_enabled || ctx->bench_count == 0) {
            nvmer_zero_v(ctx->read_buf, len);
            dcache_clean_range((const void *)(uintptr_t)ctx->read_buf, len);
        }
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Read)失敗");
        uint64_t slba = ctx->bench_enabled ? nvmer_next_lba(ctx, nlb) : 0u;
        uint32_t slen = nvmer_build_io(ctx, NVME_IO_CMD_READ, ctx->nsid, slba, nlb, ctx->read_buf, len);
        nvmer_post_send(ctx, slen);
        self->state = NVMER_ST_WAIT_READ;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_READ: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Read失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Read: 応答エラー");
        uint32_t len = ctx->bench_enabled ? ctx->bench_chunk_bytes : ctx->lba_size;
        if (len == 0 || len > sizeof(ctx->read_buf)) len = NVME_RDMA_TEST_LEN;
        dcache_invalidate_range((const void *)(uintptr_t)ctx->read_buf, len);
        if (ctx->bench_enabled) {
            ctx->bench_count++;
            ctx->bench_bytes += ctx->bench_chunk_bytes;
            ctx->cur_cid++;
            if (timeout_ms(ctx->bench_start_ticks, ctx->bench_duration_ms)) {
                ctx->done = 1;
                self->state = NVMER_ST_DONE_OK;
                return JOB_DONE;
            }
            self->state = NVMER_ST_SEND_READ;
            return JOB_WAITING;
        }
        int match = 1;
        for (uint32_t i = 0; i < len; i++) {
            if (ctx->read_buf[i] != ctx->write_buf[i]) { match = 0; break; }
        }
        ctx->read_ok = match;
        uart_printf("[nvme-rdma] Read完了、データ%s\n", match ? "完全一致" : "不一致");
        self->state = match ? NVMER_ST_DONE_OK : NVMER_ST_DONE_FAIL;
        ctx->failed = !match;
        ctx->done = 1;
        return JOB_DONE;
    }

    case NVMER_ST_PIPELINE_SETUP: {
        unsigned qdepth = ctx->bench_qdepth;
        if (qdepth > NVME_RDMA_PL_QDEPTH_MAX) qdepth = NVME_RDMA_PL_QDEPTH_MAX;
        if (qdepth == 0) qdepth = 1;
        ctx->bench_qdepth = qdepth;
        for (unsigned i = 0; i < NVME_RDMA_PL_QDEPTH_MAX; i++) s_pl_slots[i].in_use = 0;
        s_pl_rq_head = s_pl_rq_tail = 0;
        if (!ctx->bench_is_read) {
            uint32_t len = ctx->bench_chunk_bytes;
            if (len > sizeof(ctx->write_buf)) len = (uint32_t)sizeof(ctx->write_buf);
            for (uint32_t i = 0; i < len; i++) ctx->write_buf[i] = (uint8_t)(0xC0u + (i & 0x3Fu));
            dcache_clean_range((const void *)(uintptr_t)ctx->write_buf, len);
        }
        ctx->bench_start_ticks = timer_now();
        ctx->bench_count = 0;
        ctx->bench_bytes = 0;
        uart_printf("[nvme-rdma] パイプライン化ループ開始 (depth=%u)\n", qdepth);
        self->state = NVMER_ST_PIPELINE_LOOP;
        return JOB_WAITING;
    }

    case NVMER_ST_PIPELINE_LOOP: {
        unsigned qdepth = ctx->bench_qdepth;

        for (unsigned iter = 0; iter < NVME_RDMA_PL_QDEPTH_MAX * 3u; iter++) {
            int is_send = 0;
            uint32_t recv_len = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(ctx->cm.dev, &ctx->cm.rc_qp, &is_send, &recv_len, &synd);
            if (rc == 0) break;
            if (rc < 0) {
                uint32_t hw_rq = 0, sw_rq = 0;
                uint16_t hw_sq = 0, sw_sq = 0;
                mlx5_qp_query_counters(ctx->cm.dev, &ctx->cm.rc_qp, &hw_rq, &sw_rq, &hw_sq, &sw_sq);
                uint8_t last_op = mlx5_qp_last_cqe_opcode(ctx->cm.dev, &ctx->cm.rc_qp);
                uart_printf("[!] nvme-rdma pipeline: CQEエラー syndrome=0x%02x cqe_opcode=0x%x is_send=%d "
                            "rq_head=%u rq_tail=%u hw_rq=%u sw_rq=%u hw_sq=%u sw_sq=%u sq_pc=%u cq_cc=%u\n",
                            synd, last_op, is_send, s_pl_rq_head, s_pl_rq_tail, hw_rq, sw_rq, hw_sq, sw_sq,
                            ctx->cm.rc_qp.sq_pc, ctx->cm.rc_qp.cq_cc);
                return nvmer_fail(ctx, "pipeline CQEエラー");
            }
            if (is_send) continue;
            if (s_pl_rq_head == s_pl_rq_tail) return nvmer_fail(ctx, "pipeline: 予期しないRQ完了");
            unsigned slot = s_pl_rq_order[s_pl_rq_head % NVME_RDMA_PL_QDEPTH_MAX];
            s_pl_rq_head++;
            dcache_invalidate_range((const void *)(uintptr_t)s_pl_recv_bufs[slot], recv_len);
            uint16_t status = rd16le(&s_pl_recv_bufs[slot][14]);
            if (nvme_cqe_status_code(status) == 0) {
                ctx->bench_count++;
                ctx->bench_bytes += ctx->bench_chunk_bytes;
            } else {
                uart_printf("[!] nvme-rdma pipeline: コマンド失敗応答 (cid=%u)\n", s_pl_slots[slot].cid);
            }
            s_pl_slots[slot].in_use = 0;
        }

        if (!timeout_ms(ctx->bench_start_ticks, ctx->bench_duration_ms)) {
            /* 空きスロットへ新規コマンドを詰める。 */
            uint32_t nlb = (ctx->lba_size != 0) ? (ctx->bench_chunk_bytes / ctx->lba_size) : 1u;
            if (nlb == 0) nlb = 1u;
            volatile uint8_t *data_buf = ctx->bench_is_read ? ctx->read_buf : ctx->write_buf;
            uint8_t opcode = ctx->bench_is_read ? (uint8_t)NVME_IO_CMD_READ : (uint8_t)NVME_IO_CMD_WRITE;
            for (unsigned i = 0; i < qdepth; i++) {
                if (s_pl_slots[i].in_use) continue;
                ctx->cur_cid++;
                nvmer_build_io_ex(ctx, s_pl_send_bufs[i], ctx->cur_cid, opcode, ctx->nsid,
                                  nvmer_next_lba(ctx, nlb),
                                  nlb, data_buf, ctx->bench_chunk_bytes);
                dcache_clean_range((const void *)(uintptr_t)s_pl_send_bufs[i], 64u);
                if (nvmer_pl_post_recv_slot(ctx, i) != 0) return nvmer_fail(ctx, "pipeline post_recv失敗");
                if (mlx5_qp_post_send(ctx->cm.dev, &ctx->cm.rc_qp, (const void *)(uintptr_t)s_pl_send_bufs[i],
                                      64u) != 0) {
                    return nvmer_fail(ctx, "pipeline post_send失敗");
                }
                s_pl_slots[i].in_use = 1;
                s_pl_slots[i].cid = ctx->cur_cid;
            }
        } else {
            int any_outstanding = 0;
            for (unsigned i = 0; i < qdepth; i++) {
                if (s_pl_slots[i].in_use) { any_outstanding = 1; break; }
            }
            if (!any_outstanding) {
                ctx->done = 1;
                self->state = NVMER_ST_DONE_OK;
                return JOB_DONE;
            }
        }
        return JOB_WAITING;
    }

    default:
        ctx->done = 1;
        return JOB_DONE;
    }
}

static nvme_rdma_ctx_t s_init_ctx;
static nvmet_rdma_ctx_t s_target_ctx;
static nvmet_rdma_ctrl_t s_target_ctrl;

static int s_target_resident;
static uint32_t s_target_resident_generation;

static int nvmer_conn_reusable(nvme_rdma_ctx_t *ctx, mlx5_dev_t *dev)
{
    return ctx->reusable && !ctx->failed &&
           ctx->established_generation == dev->bringup_generation;
}

static void nvmer_destroy_qp_if_valid(mlx5_dev_t *dev, mlx5_qp_t *qp)
{
    if (dev != 0 && qp->qpn != 0) {
        mlx5_qp_destroy(dev, qp);
    }
}

static void nvmer_pin_target_to_core1(job_t *target_job)
{
    if (smp_boot_core1() == 0) {
        job_pin_to_core(target_job, 1u);
    } else {
        uart_printf("[!] nvme-rdma: core1起動に失敗、targetはcore0のまま動作します\n");
    }
}

void nvme_rdma_run_bench(mlx5_dev_t *dev0, mlx5_dev_t *dev1, uint32_t duration_ms,
                         int is_read, uint32_t chunk_bytes, uint32_t qdepth,
                         uint32_t *out_mbps_x100)
{
    if (out_mbps_x100) *out_mbps_x100 = 0u;  /* 失敗時は0のまま */
    if (qdepth > NVME_RDMA_PL_QDEPTH_MAX) qdepth = NVME_RDMA_PL_QDEPTH_MAX;
    if (qdepth == 0) qdepth = 1u;

    if (chunk_bytes == 0) chunk_bytes = 65536u;
    if (chunk_bytes > NVME_RDMA_BENCH_BUF_MAX) chunk_bytes = NVME_RDMA_BENCH_BUF_MAX;
    chunk_bytes -= chunk_bytes % 512u;
    if (chunk_bytes == 0) chunk_bytes = 512u;

    static const uint8_t mac0_fallback[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x10};
    static const uint8_t mac1_fallback[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x11};
    uint32_t ip0_fallback = ip_from_octets(192, 168, 101, 10);
    uint32_t ip1_fallback = ip_from_octets(192, 168, 101, 11);

    int target_ok = s_target_resident && !s_target_ctx.failed &&
                     s_target_resident_generation == dev1->bringup_generation;
    int init_ok = target_ok && nvmer_conn_reusable(&s_init_ctx, dev0);

    if (!target_ok) {
        nvmer_destroy_qp_if_valid(s_target_ctx.cm.dev, &s_target_ctx.cm.rc_qp);
        nvmer_destroy_qp_if_valid(s_target_ctx.cm.dev, s_target_ctx.cm.gsi_qp);
        for (uint32_t i = 0; i < sizeof(s_target_ctx); i++) ((uint8_t *)&s_target_ctx)[i] = 0;
        dcache_clean_range((const void *)&s_target_ctx, sizeof(s_target_ctx));
        rdma_cm_fill_addr(&s_target_ctx.cm, dev1, "mlx5-pf1", "mlx5-pf0", ip1_fallback, ip0_fallback,
                          mac1_fallback, mac0_fallback);
        s_target_ctx.ctrl = &s_target_ctrl; // フェーズ(i)続報: コントローラ状態の分離に伴い必須
        s_target_ctrl.ram_disk = nvmer_ramdisk_slot1(); // Phase 2 (x86-vfio-port): COHERENT DMA アリーナから確保(旧 NVMET_RDMA_RAMDISK_SLOT(1))
        s_target_ctx.pipeline_enabled = 1;
        job_t *target_job = job_spawn(nvmet_rdma_job_step, &s_target_ctx, "nvmet-rdma-bench-target");
        if (!target_job) {
            uart_printf("nvmermabench: FAILED (job table full)\n");
            return;
        }
        target_job->state = NVMETR_ST_CM_SPAWN;
        nvmer_pin_target_to_core1(target_job);
        s_target_resident = 1;
        s_target_resident_generation = dev1->bringup_generation;
        uart_printf("nvmermabench: targetを新規確立します(前回接続を再利用できません)\n");
    }

    job_t *init_job;
    if (init_ok) {
        s_init_ctx.bench_enabled = 1;
        s_init_ctx.bench_is_read = is_read ? 1 : 0;
        s_init_ctx.bench_chunk_bytes = chunk_bytes;
        s_init_ctx.bench_duration_ms = duration_ms;
        s_init_ctx.bench_qdepth = qdepth;
        s_init_ctx.bench_cur_lba = 0;
        s_init_ctx.done = 0;
        s_init_ctx.failed = 0;
        s_init_ctx.stop_requested = 0;
        init_job = job_spawn(nvme_rdma_connect_job_step, &s_init_ctx, "nvme-rdma-bench-init");
        if (!init_job) {
            uart_printf("nvmermabench: FAILED (job table full)\n");
            return;
        }
        init_job->state = nvmer_resume_state_after_identify(&s_init_ctx);
    } else {
        nvmer_destroy_qp_if_valid(s_init_ctx.cm.dev, &s_init_ctx.cm.rc_qp);
        nvmer_destroy_qp_if_valid(s_init_ctx.cm.dev, s_init_ctx.cm.gsi_qp);
        for (uint32_t i = 0; i < sizeof(s_init_ctx); i++) ((uint8_t *)&s_init_ctx)[i] = 0;
        dcache_clean_range((const void *)&s_init_ctx, sizeof(s_init_ctx));
        rdma_cm_fill_addr(&s_init_ctx.cm, dev0, "mlx5-pf0", "mlx5-pf1", ip0_fallback, ip1_fallback,
                          mac0_fallback, mac1_fallback);
        s_init_ctx.bench_enabled = 1;
        s_init_ctx.bench_is_read = is_read ? 1 : 0;
        s_init_ctx.bench_chunk_bytes = chunk_bytes;
        s_init_ctx.bench_duration_ms = duration_ms;
        s_init_ctx.bench_qdepth = qdepth;
        s_init_ctx.bench_cur_lba = 0;
        init_job = job_spawn(nvme_rdma_connect_job_step, &s_init_ctx, "nvme-rdma-bench-init");
        if (!init_job) {
            uart_printf("nvmermabench: FAILED (job table full)\n");
            return;
        }
        init_job->state = NVMER_ST_CM_SPAWN;
    }

    uart_printf("nvmermabench: %s chunk_bytes=%u duration_ms=%u qdepth=%u 開始\n",
                is_read ? "read" : "write", chunk_bytes, duration_ms, qdepth);

    uint64_t start = timer_now();
    while (1) {
        sim_delay_tick();
        job_scheduler_tick();
        if (s_init_ctx.done || s_target_ctx.failed) break;
        if (timeout_ms(start, (uint64_t)duration_ms + 15000u)) {
            uart_printf("nvmermabench: FAILED (overall timeout)\n");
            break;
        }
    }

    if (s_init_ctx.done && !s_init_ctx.failed && !s_target_ctx.failed) {
        s_init_ctx.stop_requested = 1;
    } else {
        s_target_ctx.stop_requested = 1;
        s_init_ctx.stop_requested = 1;
        s_target_resident = 0;
    }
    {
        uint64_t stop_start = timer_now();
        while (!timeout_ms(stop_start, 2000u)) {
            job_scheduler_tick();
        }
    }

    if (!s_init_ctx.done || s_init_ctx.failed || s_target_ctx.failed) {
        uart_printf("nvmermabench: FAILED (count=%u)\n", s_init_ctx.bench_count);
        return;
    }

    uint32_t count = s_init_ctx.bench_count;
    uint64_t total_bytes = s_init_ctx.bench_bytes;
    uint32_t elapsed_ms = duration_ms;
    uint64_t mbps_x100 = (elapsed_ms != 0) ? (total_bytes * 100000ull) / ((uint64_t)elapsed_ms * 1000000ull) : 0;
    uint64_t iops_x100 = (elapsed_ms != 0) ? ((uint64_t)count * 100000ull) / (uint64_t)elapsed_ms : 0;
    uart_printf("nvmermabench: %s完了 count=%u bytes_hi32=%u bytes_lo32=%u elapsed_ms=%u\n",
                is_read ? "read" : "write", count, (unsigned)(total_bytes >> 32),
                (unsigned)(total_bytes & 0xFFFFFFFFu), elapsed_ms);
    uart_printf("nvmermabench: スループット=約%u.%02uMB/s IOPS=約%u.%02u\n",
                (unsigned)(mbps_x100 / 100u), (unsigned)(mbps_x100 % 100u),
                (unsigned)(iops_x100 / 100u), (unsigned)(iops_x100 % 100u));
    if (out_mbps_x100) *out_mbps_x100 = (uint32_t)mbps_x100;
}
