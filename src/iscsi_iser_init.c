/* iSER イニシエータ(RFC 7145)。PLAN_iscsi.md 段階 I。
 *
 * 形式は iscsit_iser.c(ターゲット)と同じ。Linux の drivers/infiniband/ulp/iser/ の作法に合わせる:
 *   - CM の REQ の private data は iser_cm_hdr。flags = 0x80(ZBVA を使えない = 仮想アドレスで指す)|
 *     0x40(SEND_WITH_INVALIDATE を受けない)。
 *   - コマンドの SEND: iSER ヘッダ(読み出しなら read_stag / read_va、書き込みで即時データの後に
 *     残りがあれば write_stag / write_va = 即時データの直後)+ BHS + 即時データ。
 *     鍵はこの QP の mkey(リモートの読み書きを許したもの)、アドレスは IOVA。
 *   - ログインの鍵: RDMAExtensions=Yes、InitiatorRecvDataSegmentLength / TargetRecvDataSegmentLength。
 *     ダイジェストは使わない。 */
#include "iscsi_iser_init.h"
#include "iscsi_init.h"
#include "iscsi.h"
#include "iscsi_text.h"
#include "rdma_cm.h"
#include "mlx5_qp.h"
#include "net.h"
#include "netif.h"
#include "job.h"
#include "timer.h"
#include "uart.h"
#include "cache.h"
#include <string.h>

#define ISER_HDR_LEN   28u
#define ISER_F_CTRL    0x10u
#define ISER_F_WSV     0x08u
#define ISER_F_RSV     0x04u
#define II_RX_SLOTS    160u
#define II_RX_BYTES    8576u
#define II_RX_DATA     8192u      /* InitiatorRecvDataSegmentLength */
#define II_TASKS       256u
#define II_BLOCK       512u
#define II_BUF_MAX     (1024u * 1024u)
#define II_RANGE       (64u * 1024u * 1024u)
#define II_QP_INDEX    6u

typedef struct {
    uint8_t  in_use, done, status, is_read;
    uint32_t itt, len;
    uint8_t  tx[ISER_HDR_LEN + ISCSI_BHS_LEN] __attribute__((aligned(64)));
} ii_task_t;

typedef struct {
    int           connected;
    mlx5_dev_t   *dev;
    rdma_cm_ctx_t cm;
    uint32_t      cmdsn, expstatsn, maxcmdsn;
    uint16_t      tsih;
    uint8_t       isid[6];
    char          target[ISCSI_NAME_MAX];
    uint32_t      first_burst, max_burst, tgt_recv_dsl, imm_max;
    uint8_t       immediate_data;
    uint64_t      nblocks;
    uint32_t      rq_head, rq_tail;
    uint16_t      rq_order[II_RX_SLOTS];
    uint32_t      outstanding, errors, rejects, nop_in, sends_inflight;
    int           logout_req;
    /* 最後に受けた Login / Logout の応答 */
    uint8_t       last_bhs[ISCSI_BHS_LEN];
    uint8_t       last_data[ISCSI_LOGIN_MAX_DSL];
    uint32_t      last_dlen;
    int           last_ready;
    ii_task_t     task[II_TASKS];
    uint8_t       ctl_tx[ISER_HDR_LEN + ISCSI_BHS_LEN + ISCSI_LOGIN_MAX_DSL] __attribute__((aligned(64)));
    uint8_t       rx[II_RX_SLOTS][II_RX_BYTES] __attribute__((aligned(64)));
} ii_t;

static ii_t s;
static uint8_t s_wbuf[II_BUF_MAX] __attribute__((aligned(4096)));
static uint8_t s_rbuf[II_BUF_MAX] __attribute__((aligned(4096)));
static uint8_t s_sbuf[4096] __attribute__((aligned(4096)));

static void put64(uint8_t *p, uint64_t v) { iscsi_put32(p, (uint32_t)(v >> 32)); iscsi_put32(p + 4, (uint32_t)v); }

static int post_rx(unsigned slot)
{
    if (mlx5_qp_post_recv(s.dev, &s.cm.rc_qp, s.rx[slot], II_RX_BYTES) != 0) return -1;
    s.rq_order[s.rq_tail++ % II_RX_SLOTS] = (uint16_t)slot;
    return 0;
}

/* 制御 PDU(Login / Logout / NOP-Out)を送る。iSER ヘッダに鍵は載せない。 */
static int send_ctl(const uint8_t *bhs, const uint8_t *data, uint32_t dlen)
{
    memset(s.ctl_tx, 0, ISER_HDR_LEN);
    s.ctl_tx[0] = ISER_F_CTRL;
    memcpy(&s.ctl_tx[ISER_HDR_LEN], bhs, ISCSI_BHS_LEN);
    iscsi_put24(&s.ctl_tx[ISER_HDR_LEN + ISCSI_OFF_DSL], dlen);
    const uint32_t pad = (4u - (dlen & 3u)) & 3u;
    if (dlen) memcpy(&s.ctl_tx[ISER_HDR_LEN + ISCSI_BHS_LEN], data, dlen);
    if (pad) memset(&s.ctl_tx[ISER_HDR_LEN + ISCSI_BHS_LEN + dlen], 0, pad);
    if (mlx5_qp_post_send(s.dev, &s.cm.rc_qp, s.ctl_tx, ISER_HDR_LEN + ISCSI_BHS_LEN + dlen + pad) != 0) return -1;
    s.sends_inflight++;
    return 0;
}

static ii_task_t *task_by_itt(uint32_t itt)
{
    const unsigned i = itt % II_TASKS;
    return (s.task[i].in_use && s.task[i].itt == itt) ? &s.task[i] : NULL;
}

/* 受信した 1 メッセージ。 */
static void rx_msg(const uint8_t *m, uint32_t len)
{
    if (len < ISER_HDR_LEN + ISCSI_BHS_LEN) return;
    const uint8_t *b = m + ISER_HDR_LEN;
    const uint8_t op = b[0] & ISCSI_OP_MASK;
    uint32_t dlen = iscsi_be24(&b[ISCSI_OFF_DSL]);
    if (ISER_HDR_LEN + ISCSI_BHS_LEN + dlen > len) dlen = len - ISER_HDR_LEN - ISCSI_BHS_LEN;
    const uint8_t *data = b + ISCSI_BHS_LEN;
    if (op != ISCSI_OP_DATA_IN && op != ISCSI_OP_R2T) {
        const uint32_t ssn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);
        if (iscsi_sn_le(s.expstatsn, ssn)) s.expstatsn = ssn + 1u;
    }
    if (op != ISCSI_OP_LOGIN_RSP) {
        const uint32_t mx = iscsi_be32(&b[ISCSI_OFF_MAXCMDSN]);
        if (iscsi_sn_lt(s.maxcmdsn, mx)) s.maxcmdsn = mx;
    }
    switch (op) {
    case ISCSI_OP_SCSI_RSP: {
        ii_task_t *t = task_by_itt(iscsi_be32(&b[ISCSI_OFF_ITT]));
        if (!t) return;
        t->status = b[ISCSI_RSP_OFF_STATUS];
        if (b[ISCSI_RSP_OFF_RESPONSE] != 0) t->status = 0xFF;
        if (t->status != SCSI_STATUS_GOOD) s.errors++;
        t->done = 1;
        return;
    }
    case ISCSI_OP_NOOP_IN: {
        s.nop_in++;
        if (iscsi_be32(&b[ISCSI_OFF_TTT]) == ISCSI_RSVD_TAG) return;   /* こちらの ping への答え */
        uint8_t o[ISCSI_BHS_LEN] = {0};
        o[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_NOOP_OUT;
        o[1] = 0x80;
        memcpy(&o[ISCSI_OFF_LUN], &b[ISCSI_OFF_LUN], 8);
        iscsi_put32(&o[ISCSI_OFF_ITT], ISCSI_RSVD_TAG);
        memcpy(&o[ISCSI_OFF_TTT], &b[ISCSI_OFF_TTT], 4);
        iscsi_put32(&o[ISCSI_OFF_CMDSN], s.cmdsn);
        iscsi_put32(&o[ISCSI_OFF_EXPSTATSN], s.expstatsn);
        (void)send_ctl(o, NULL, 0);
        return;
    }
    case ISCSI_OP_ASYNC:
        if (b[36] == 1) s.logout_req = 1;
        return;
    case ISCSI_OP_REJECT:
        s.rejects++;
        uart_printf("[iser-ini] Reject(理由 0x%02x)\n", b[2]);
        return;
    default:
        memcpy(s.last_bhs, b, ISCSI_BHS_LEN);
        s.last_dlen = dlen < sizeof(s.last_data) ? dlen : sizeof(s.last_data);
        memcpy(s.last_data, data, s.last_dlen);
        s.last_ready = 1;
        return;
    }
}

/* CQ を回す。戻り値 <0 = 接続が壊れた。 */
static int pump(unsigned max)
{
    for (unsigned i = 0; i < max; i++) {
        int is_send = 0;
        uint32_t rlen = 0;
        uint8_t synd = 0;
        const int rc = mlx5_qp_poll_cqe(s.dev, &s.cm.rc_qp, &is_send, &rlen, &synd);
        if (rc == 0) return 0;
        if (rc < 0) { uart_printf("[iser-ini] CQE エラー(syndrome=0x%02x)\n", synd); return -1; }
        if (is_send) { if (s.sends_inflight) s.sends_inflight--; continue; }
        const unsigned slot = s.rq_order[s.rq_head++ % II_RX_SLOTS];
        dcache_invalidate_range(s.rx[slot], rlen);
        rx_msg(s.rx[slot], rlen);
        if (post_rx(slot) != 0) return -1;
    }
    return 0;
}

static int wait_last(uint32_t ms)
{
    const uint64_t t0 = timer_now();
    s.last_ready = 0;
    while (!s.last_ready) {
        if (pump(64) < 0) return -1;
        if (timeout_ms(t0, ms)) return -1;
    }
    return 0;
}

/* SCSI コマンドを 1 つ出す。buf は読み出し先 / 書き込み元(DMA 可能な .bss)。 */
static int submit(ii_task_t *t, const uint8_t cdb[16], uint8_t *buf)
{
    uint8_t *x = t->tx;
    memset(x, 0, ISER_HDR_LEN + ISCSI_BHS_LEN);
    uint8_t *b = x + ISER_HDR_LEN;
    uint32_t imm = 0;
    x[0] = ISER_F_CTRL;
    b[0] = ISCSI_OP_SCSI_CMD;
    b[1] = (uint8_t)(ISCSI_CMD_F | (t->is_read ? ISCSI_CMD_R : ISCSI_CMD_W) | 0x01u);   /* SIMPLE */
    iscsi_put32(&b[ISCSI_OFF_ITT], t->itt);
    iscsi_put32(&b[ISCSI_CMD_OFF_EDTL], t->len);
    iscsi_put32(&b[ISCSI_OFF_CMDSN], s.cmdsn++);
    iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
    memcpy(&b[ISCSI_CMD_OFF_CDB], cdb, 16);
    const uint64_t va = mlx5_dma_addr(buf);
    if (t->is_read) {
        x[0] |= ISER_F_RSV;
        iscsi_put32(&x[16], s.cm.rc_qp.mkey);
        put64(&x[20], va);
    } else {
        imm = s.immediate_data ? (t->len < s.imm_max ? t->len : s.imm_max) : 0u;
        iscsi_put24(&b[ISCSI_OFF_DSL], imm);
        if (imm < t->len) {
            x[0] |= ISER_F_WSV;
            iscsi_put32(&x[4], s.cm.rc_qp.mkey);
            put64(&x[8], va + imm);   /* 即時データの直後から(Linux の iser と同じ)*/
        }
    }
    if (mlx5_qp_post_send2(s.dev, &s.cm.rc_qp, x, ISER_HDR_LEN + ISCSI_BHS_LEN, imm ? buf : NULL, imm) != 0) return -1;
    s.sends_inflight++;
    s.outstanding++;
    return 0;
}

static ii_task_t *task_alloc(void)
{
    static uint32_t next_itt = 1;
    for (unsigned n = 0; n < II_TASKS; n++) {
        const uint32_t itt = next_itt++;
        if (next_itt == ISCSI_RSVD_TAG) next_itt = 1;
        ii_task_t *t = &s.task[itt % II_TASKS];
        if (t->in_use) continue;
        memset(t, 0, sizeof(*t) - sizeof(t->tx));
        t->in_use = 1;
        t->itt = itt;
        return t;
    }
    return NULL;
}

static int scsi_sync(const uint8_t cdb[16], uint8_t *buf, uint32_t len)
{
    ii_task_t *t = task_alloc();
    if (!t) return -1;
    t->is_read = 1;
    t->len = len;
    if (submit(t, cdb, buf) < 0) return -1;
    const uint64_t t0 = timer_now();
    while (!t->done) {
        if (pump(64) < 0 || timeout_ms(t0, 5000u)) return -1;
    }
    const int st = t->status;
    t->in_use = 0;
    s.outstanding--;
    return st;
}

/* 応答の鍵から値を読む。 */
static void parse_keys(const uint8_t *d, uint32_t len)
{
    const char *k, *v;
    uint32_t kl, vl, pos = 0;
    while (iscsi_kv_next(d, len, &pos, &k, &kl, &v, &vl)) {
        uint32_t num = 0;
        for (uint32_t i = 0; i < vl && v[i] >= '0' && v[i] <= '9'; i++) num = num * 10u + (uint32_t)(v[i] - '0');
#define K(name) (kl == sizeof(name) - 1u && memcmp(k, name, kl) == 0)
        if (K("FirstBurstLength")) s.first_burst = num;
        else if (K("MaxBurstLength")) s.max_burst = num;
        else if (K("TargetRecvDataSegmentLength")) s.tgt_recv_dsl = num;
        else if (K("ImmediateData")) s.immediate_data = (vl == 3 && memcmp(v, "Yes", 3) == 0);
#undef K
    }
}

static int login(const char *target)
{
    uint8_t kv[2048];
    uint32_t n = 0;
    iscsi_kv_put(kv, sizeof(kv), &n, "InitiatorName", ISCSI_INI_DEFAULT_NAME);
    iscsi_kv_put(kv, sizeof(kv), &n, "InitiatorAlias", "vfio_nvme");
    iscsi_kv_put(kv, sizeof(kv), &n, "TargetName", target);
    iscsi_kv_put(kv, sizeof(kv), &n, "SessionType", "Normal");
    iscsi_kv_put(kv, sizeof(kv), &n, "HeaderDigest", "None");
    iscsi_kv_put(kv, sizeof(kv), &n, "DataDigest", "None");
    iscsi_kv_put(kv, sizeof(kv), &n, "DefaultTime2Wait", "2");
    iscsi_kv_put(kv, sizeof(kv), &n, "DefaultTime2Retain", "0");
    iscsi_kv_put(kv, sizeof(kv), &n, "IFMarker", "No");
    iscsi_kv_put(kv, sizeof(kv), &n, "OFMarker", "No");
    iscsi_kv_put(kv, sizeof(kv), &n, "ErrorRecoveryLevel", "0");
    iscsi_kv_put(kv, sizeof(kv), &n, "InitialR2T", "Yes");
    iscsi_kv_put(kv, sizeof(kv), &n, "ImmediateData", "Yes");
    iscsi_kv_put(kv, sizeof(kv), &n, "MaxBurstLength", "262144");
    iscsi_kv_put(kv, sizeof(kv), &n, "FirstBurstLength", "65536");
    iscsi_kv_put(kv, sizeof(kv), &n, "MaxOutstandingR2T", "1");
    iscsi_kv_put(kv, sizeof(kv), &n, "MaxConnections", "1");
    iscsi_kv_put(kv, sizeof(kv), &n, "DataPDUInOrder", "Yes");
    iscsi_kv_put(kv, sizeof(kv), &n, "DataSequenceInOrder", "Yes");
    iscsi_kv_put_u32(kv, sizeof(kv), &n, "InitiatorRecvDataSegmentLength", II_RX_DATA);
    iscsi_kv_put_u32(kv, sizeof(kv), &n, "TargetRecvDataSegmentLength", 8192u);
    iscsi_kv_put(kv, sizeof(kv), &n, "RDMAExtensions", "Yes");
    s.first_burst = 65536u;
    s.max_burst = 262144u;
    s.tgt_recv_dsl = 8192u;
    s.immediate_data = 1;
    s.isid[0] = 0x80; s.isid[1] = 'v'; s.isid[2] = 'f'; s.isid[3] = 'i'; s.isid[4] = 'o'; s.isid[5] = 0x10;
    s.cmdsn = 1;
    s.expstatsn = 0;
    const uint8_t *payload = kv;
    uint32_t plen = n;
    for (int step = 0; step < 4; step++) {
        uint8_t b[ISCSI_BHS_LEN] = {0};
        b[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_LOGIN;
        b[1] = (uint8_t)(ISCSI_LOGIN_T | (ISCSI_STAGE_OP << 2) | ISCSI_STAGE_FFP);
        memcpy(&b[ISCSI_LOGIN_OFF_ISID], s.isid, 6);
        iscsi_put32(&b[ISCSI_OFF_CMDSN], s.cmdsn);
        iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
        if (send_ctl(b, payload, plen) < 0) return -1;
        if (wait_last(5000u) < 0) { uart_printf("[iser-ini] Login 応答が来ない\n"); return -1; }
        const uint8_t *r = s.last_bhs;
        if ((r[0] & ISCSI_OP_MASK) != ISCSI_OP_LOGIN_RSP) { uart_printf("[iser-ini] Login 応答でない PDU\n"); return -1; }
        const uint16_t st = (uint16_t)((r[ISCSI_LOGIN_OFF_STATUS] << 8) | r[ISCSI_LOGIN_OFF_STATUS + 1]);
        if (st != 0) { uart_printf("[iser-ini] Login を断られた(状態 0x%04x)\n", st); return -1; }
        parse_keys(s.last_data, s.last_dlen);
        {
            const char *k, *v;
            uint32_t kl, vl, p = 0;
            uart_printf("[iser-ini] Login 応答:");
            while (iscsi_kv_next(s.last_data, s.last_dlen, &p, &k, &kl, &v, &vl))
                uart_printf(" %.*s=%.*s", (int)kl, k, (int)vl, v);
            uart_printf("\n");
        }
        s.expstatsn = iscsi_be32(&r[ISCSI_OFF_CMDSN]) + 1u;
        s.cmdsn = iscsi_be32(&r[ISCSI_OFF_EXPSTATSN]);
        s.maxcmdsn = iscsi_be32(&r[ISCSI_OFF_MAXCMDSN]);
        s.tsih = iscsi_be16(&r[ISCSI_LOGIN_OFF_TSIH]);
        if ((r[1] & ISCSI_LOGIN_T) && (r[1] & 3u) == ISCSI_STAGE_FFP && !(r[1] & ISCSI_LOGIN_C)) {
            s.imm_max = s.first_burst < s.tgt_recv_dsl ? s.first_burst : s.tgt_recv_dsl;
            return 0;
        }
        payload = NULL;
        plen = 0;
    }
    return -1;
}

static void teardown(void)
{
    if (s.cm.rc_qp.qpn) mlx5_qp_destroy(s.dev, &s.cm.rc_qp);
    if (s.cm.gsi_qp && s.cm.gsi_qp->qpn) mlx5_qp_destroy(s.dev, s.cm.gsi_qp);
    s.connected = 0;
}

int iscsi_iser_connect(mlx5_dev_t *dev, uint32_t ip, const uint8_t mac[6], const char *target_iqn)
{
    if (s.connected) iscsi_iser_close();
    memset(s.task, 0, sizeof(s.task));
    s.dev = dev;
    s.outstanding = s.errors = s.rejects = s.nop_in = s.sends_inflight = 0;
    s.logout_req = 0;
    s.rq_head = s.rq_tail = 0;
    netif_t *pf0 = netif_find("mlx5-pf0");
    if (pf0) netif_activate(pf0);
    static const uint8_t zero_mac[6] = {0};
    rdma_cm_fill_addr(&s.cm, dev, "mlx5-pf0", "__override__", 0u, ip, zero_mac, mac);
    s.cm.is_active = 1;
    s.cm.skip_ping = 1;
    s.cm.rc_qp_index = II_QP_INDEX;
    s.cm.service_port = 3260u;
    s.cm.req_path_mtu = 5u;                  /* 4096(相手の Linux も netdev の MTU 9000 から 4096 を使う)*/
    s.cm.rep_priv_out[0] = 0x80u | 0x40u;   /* ZBVA を使えない / SEND_WITH_INVALIDATE を受けない */
    s.cm.rep_priv_out_len = 4;
    job_t *cj = job_spawn(rdma_cm_job_step, &s.cm, "iser-ini-cm");
    if (!cj) return -1;
    cj->state = RDMA_CM_ST_ACTIVE_SETUP;
    const uint64_t t0 = timer_now();
    while (!s.cm.rtu_phase_done && !s.cm.failed) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        if (timeout_ms(t0, 8000u)) break;
    }
    if (!s.cm.established || s.cm.failed) {
        uart_printf("[iser-ini] RDMA CM の接続に失敗(REJ 理由 %u)\n", s.cm.rej_reason);
        teardown();
        return -1;
    }
    for (unsigned i = 0; i < II_RX_SLOTS; i++) {
        if (post_rx(i) != 0) { teardown(); return -1; }
    }
    if (login(target_iqn) < 0) { (void)rdma_cm_disconnect(&s.cm, 500u); teardown(); return -1; }
    {
        size_t l = strlen(target_iqn);
        if (l >= sizeof(s.target)) l = sizeof(s.target) - 1u;
        memcpy(s.target, target_iqn, l);
        s.target[l] = 0;
    }
    s.connected = 1;
    uint8_t cdb[16] = {0};
    cdb[0] = 0x9E; cdb[1] = 0x10; cdb[13] = 32;
    const int st = scsi_sync(cdb, s_sbuf, 32);
    s.nblocks = st == 0 ? (((uint64_t)iscsi_be32(&s_sbuf[0]) << 32) | iscsi_be32(&s_sbuf[4])) + 1u : 0;
    uart_printf("[iser-ini] ログイン完了: %s tsih=%u burst=%u/%u 即時データ上限 %u、LUN 0: %llu ブロック(READ CAPACITY 0x%02x)\n",
                s.target, s.tsih, s.first_burst, s.max_burst, s.imm_max, (unsigned long long)s.nblocks, (unsigned)st);
    return 0;
}

void iscsi_iser_close(void)
{
    if (!s.connected) return;
    uint8_t b[ISCSI_BHS_LEN] = {0};
    b[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_LOGOUT;
    b[1] = 0x80;
    iscsi_put32(&b[ISCSI_OFF_ITT], 0x7FFFFFF0u);
    iscsi_put32(&b[ISCSI_OFF_CMDSN], s.cmdsn);
    iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
    if (send_ctl(b, NULL, 0) == 0 && wait_last(3000u) == 0)
        uart_printf("[iser-ini] ログアウト(応答 %u)\n", s.last_bhs[2]);
    (void)rdma_cm_disconnect(&s.cm, 1000u);
    teardown();
}

int iscsi_iser_connected(void) { return s.connected; }

int iscsi_iser_bench(int is_read, uint32_t chunk, uint32_t qd, uint32_t runtime_ms,
                     uint64_t *bytes, uint32_t *count, uint32_t *elapsed_ms, uint32_t *mismatch)
{
    *bytes = 0; *count = 0; *elapsed_ms = 0; *mismatch = 0;
    if (!s.connected) return -1;
    if (chunk == 0 || chunk > II_BUF_MAX || chunk % II_BLOCK) { uart_printf("iserbench: 長さは 512 の倍数で 1MiB まで\n"); return -1; }
    if (qd > II_TASKS - 8u) qd = II_TASKS - 8u;
    for (uint32_t i = 0; i < chunk; i++) s_wbuf[i] = (uint8_t)(0x5Au ^ (i * 7u));
    const uint32_t step = chunk / II_BLOCK;
    uint64_t range = s.nblocks < II_RANGE / II_BLOCK ? s.nblocks : II_RANGE / II_BLOCK;
    range -= range % step;
    if (range == 0) return -1;
    uint64_t lba = 0, by = 0;
    uint32_t completed = 0, err0 = s.errors;
    const uint64_t t0 = timer_now();
    int stop = 0;
    for (;;) {
        while (!stop && s.outstanding < qd && iscsi_sn_le(s.cmdsn, s.maxcmdsn) && s.sends_inflight < 400u) {
            ii_task_t *t = task_alloc();
            if (!t) break;
            t->is_read = (uint8_t)is_read;
            t->len = chunk;
            uint8_t cdb[16] = {0};
            cdb[0] = is_read ? 0x88 : 0x8A;
            for (int k = 0; k < 8; k++) cdb[2 + k] = (uint8_t)(lba >> (56 - 8 * k));
            iscsi_put32(&cdb[10], step);
            if (submit(t, cdb, is_read ? s_rbuf : s_wbuf) < 0) { uart_printf("iserbench: 送信に失敗\n"); return -1; }
            lba += step;
            if (lba >= range) lba = 0;
        }
        if (pump(128) < 0) { uart_printf("iserbench: 接続が壊れた\n"); teardown(); return -1; }
        for (unsigned i = 0; i < II_TASKS; i++) {
            ii_task_t *t = &s.task[i];
            if (!t->in_use || !t->done) continue;
            if (t->status == SCSI_STATUS_GOOD) {
                completed++;
                by += t->len;
                if (t->is_read && (completed & 63u) == 0 && memcmp(s_rbuf, s_wbuf, t->len) != 0) (*mismatch)++;
            }
            t->in_use = 0;
            s.outstanding--;
        }
        if (!stop && (timeout_ms(t0, runtime_ms) || s.logout_req)) stop = 1;
        if (stop && s.outstanding == 0) break;
        if (timeout_ms(t0, runtime_ms + 10000u)) { uart_printf("iserbench: 応答が返らないコマンドが残った(%u)\n", s.outstanding); return -1; }
    }
    *elapsed_ms = (uint32_t)((timer_now() - t0) / 1000000ull);
    *bytes = by;
    *count = completed;
    if (s.errors != err0) uart_printf("iserbench: 失敗したコマンド %u\n", s.errors - err0);
    if (s.logout_req) { uart_printf("iserbench: 相手がログアウトを求めたので畳む\n"); iscsi_iser_close(); }
    return 0;
}

void iscsi_iser_status(void)
{
    if (!s.connected) { uart_printf("iser-ini: 未接続\n"); return; }
    uart_printf("iser-ini: %s tsih=%u CmdSN=%u MaxCmdSN=%u ExpStatSN=%u 未完了 %u、失敗 %u、Reject %u、NOP-In %u、即時データ上限 %u\n",
                s.target, s.tsih, s.cmdsn, s.maxcmdsn, s.expstatsn, s.outstanding, s.errors, s.rejects, s.nop_in, s.imm_max);
}
