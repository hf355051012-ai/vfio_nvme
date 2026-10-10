/* iSER ターゲット(RFC 7145)。PLAN_iscsi.md 段階 I。
 *
 * 形式と手順は Linux の drivers/infiniband/ulp/isert/ib_isert.c(ターゲット)と
 * drivers/infiniband/ulp/iser/(イニシエータ)、include/scsi/iser.h から写した。
 *
 *   - RDMA CM: SERVICE_ID は TCP と同じ (RDMA_PS_TCP << 16) + 3260。REQ / REP の private data は
 *     iser_cm_hdr(4 バイト。flags の 0x80 = ZBVA を使わない、0x40 = SEND_WITH_INVALIDATE を使わない)。
 *   - SEND の中身: iSER ヘッダ 28 バイト(flags、write_stag / write_va、read_stag / read_va)+ BHS 48 +
 *     データ。flags の上位 4 ビット 0x10 = iSCSI の制御 PDU、0x08 = write_stag が有効、0x04 = read_stag が有効。
 *   - 読み出し: SCSI のデータをこちらから RDMA_WRITE で (read_stag, read_va) へ書き、続けて SCSI Response を
 *     SEND する(SQ は投稿順なので、相手にはデータの後に応答が届く)。
 *   - 書き込み: 即時データ(ImmediateData)は SEND に載って来る。残りはこちらから RDMA_READ で
 *     (write_stag, write_va) から引く。**write_va は即時データのぶん既に進めてある**(Linux の
 *     iser_prepare_write_cmd())。読み終えてから SCSI Response を SEND する。
 *   - **イニシエータの受信バッファは Full Feature Phase では 28 + 48 + 128 バイトしかない**
 *     (ISER_RX_PAYLOAD_SIZE)。応答のデータ(センス、NOP-In)は 128 バイト以内にする。
 *     ログインの応答だけは 8192 バイトまで受けられる(ISER_RX_LOGIN_SIZE)。
 *   - ダイジェストは使わない(RDMA の CRC が守る)。HeaderDigest / DataDigest は None だけ受ける。 */
#include "iscsit_iser.h"
#include "iscsit.h"
#include "iscsi.h"
#include "iscsi_text.h"
#include "scsi.h"
#include "rdma_cm.h"
#include "mlx5_qp.h"
#include "ib_mad.h"
#include "net.h"
#include "netif.h"
#include "job.h"
#include "timer.h"
#include "uart.h"
#include "cache.h"
#include "smp.h"
#include <string.h>

#define ISER_HDR_LEN      28u
#define ISER_F_CTRL       0x10u
#define ISER_F_WSV        0x08u
#define ISER_F_RSV        0x04u
#define ISER_ZBVA_NOT_USED      0x80u
#define ISER_SEND_W_INV_NOT_USED 0x40u

#define ISERT_TRDSL       8192u                 /* TargetRecvDataSegmentLength(LIO の既定と同じ)*/
#define ISERT_RX_SLOTS    160u                  /* 窓 128 + NOP / TMF / Logout の余裕 */
#define ISERT_RX_BYTES    8576u                 /* 28 + 48 + 8192 を 64 バイト単位へ */
#define ISERT_TASKS       192u
#define ISERT_TX_BYTES    256u                  /* 28 + 48 + センス(2 + 18)に余裕 */
#define ISERT_SQ_RING     512u
#define ISERT_QP_INDEX    6u                    /* rcqp[]: 0〜4 = NVMe-oF RDMA、7 = rshort */
#define ISERT_WINDOW      128u                  /* MaxCmdSN = ExpCmdSN + 127 */
#define ISERT_INI_RX_DATA 128u                  /* イニシエータの受信バッファのデータ部 */
#define ISERT_LINGER_MS   2000u

#define CM_DREP_ATTR_ID   0x0016u
#define IB_CM_CLASS_VERSION 2u

enum { SQ_SEND_FREE = 1, SQ_SEND_LOGIN, SQ_WRITE, SQ_READ };
enum { ST_IDLE = 0, ST_CM_WAIT, ST_RUN };

typedef struct {
    uint8_t  in_use;
    uint8_t  aborted;         /* TMF で捨てた(応答を出さない)*/
    uint8_t  verify;
    uint32_t itt, edtl, total;
    uint8_t  lun8[8];
    uint8_t  tx[ISERT_TX_BYTES] __attribute__((aligned(64)));
    uint8_t  buf[4096] __attribute__((aligned(64)));   /* INQUIRY などの応答 */
} isert_task_t;

typedef struct {
    int           started;
    int           st;
    mlx5_dev_t   *dev;
    const char   *self_label;
    uint8_t       peer_mac[6];
    rdma_cm_ctx_t cm;
    job_t        *job;
    iscsi_tgt_pref_t pref;
    /* ---- 受信 ---- */
    uint32_t      rq_head, rq_tail;
    uint16_t      rq_order[ISERT_RX_SLOTS];
    /* ---- 送信(SQ の完了は投稿順に返る)---- */
    uint32_t      sq_head, sq_tail;
    struct { uint8_t op; uint16_t task; } sq[ISERT_SQ_RING];
    uint32_t      rra_inflight, rra_max;
    uint16_t      rra_pend[ISERT_TASKS];
    uint32_t      rra_pend_head, rra_pend_tail;
    struct { uint64_t va; uint32_t stag, len; uint8_t *dst; } rd[ISERT_TASKS];
    /* ---- セッション ---- */
    uint8_t       ffp, login_started, logged_out;
    uint8_t       isid[6];
    uint16_t      tsih, tsih_next;
    uint32_t      stat_sn, exp_cmd_sn;
    iscsi_neg_t   neg;
    uint32_t      text_len;
    uint8_t       text[16384];
    uint8_t       login_busy;
    uint64_t      t_logout;
    /* ---- 統計 ---- */
    uint32_t      logins, logouts, rejects, check_cond, tmf, nop, cqe_err, disconnects;
    uint64_t      cmds, reads, writes, bytes_read, bytes_written;
    isert_task_t  task[ISERT_TASKS];
    uint8_t       login_tx[ISER_HDR_LEN + ISCSI_BHS_LEN + ISCSI_LOGIN_MAX_DSL] __attribute__((aligned(64)));
    uint8_t       rx[ISERT_RX_SLOTS][ISERT_RX_BYTES] __attribute__((aligned(64)));
} isert_t;

static isert_t s_i;

/* ---------------------------------------------------------------- 送信 */

static int sq_room(void) { return (s_i.sq_tail - s_i.sq_head) + 4u < ISERT_SQ_RING; }

static void sq_push(uint8_t op, unsigned task)
{
    s_i.sq[s_i.sq_tail % ISERT_SQ_RING].op = op;
    s_i.sq[s_i.sq_tail % ISERT_SQ_RING].task = (uint16_t)task;
    s_i.sq_tail++;
}

static int task_alloc(void)
{
    for (unsigned i = 0; i < ISERT_TASKS; i++) {
        if (!s_i.task[i].in_use) {
            s_i.task[i].in_use = 1;
            s_i.task[i].aborted = 0;
            s_i.task[i].verify = 0;
            return (int)i;
        }
    }
    return -1;
}

static void fill_sn(uint8_t *bhs, int advance)
{
    iscsi_put32(&bhs[ISCSI_OFF_CMDSN], advance ? s_i.stat_sn++ : s_i.stat_sn);
    iscsi_put32(&bhs[ISCSI_OFF_EXPSTATSN], s_i.exp_cmd_sn);
    iscsi_put32(&bhs[ISCSI_OFF_MAXCMDSN], s_i.exp_cmd_sn + ISERT_WINDOW - 1u);
}

/* タスクの tx に組み立てた PDU(iSER ヘッダ + BHS + data)を SEND する。完了でタスクを返す。 */
static int send_task_pdu(unsigned ti, const uint8_t *bhs, const uint8_t *data, uint32_t dlen)
{
    isert_task_t *t = &s_i.task[ti];
    if (dlen > ISERT_INI_RX_DATA) dlen = ISERT_INI_RX_DATA;   /* 相手の受信バッファに収める */
    memset(t->tx, 0, ISER_HDR_LEN);
    t->tx[0] = ISER_F_CTRL;
    memcpy(&t->tx[ISER_HDR_LEN], bhs, ISCSI_BHS_LEN);
    iscsi_put24(&t->tx[ISER_HDR_LEN + ISCSI_OFF_DSL], dlen);
    const uint32_t pad = (4u - (dlen & 3u)) & 3u;
    if (dlen) memcpy(&t->tx[ISER_HDR_LEN + ISCSI_BHS_LEN], data, dlen);
    if (pad) memset(&t->tx[ISER_HDR_LEN + ISCSI_BHS_LEN + dlen], 0, pad);
    if (mlx5_qp_post_send(s_i.dev, &s_i.cm.rc_qp, t->tx, ISER_HDR_LEN + ISCSI_BHS_LEN + dlen + pad) != 0) {
        t->in_use = 0;
        return -1;
    }
    sq_push(SQ_SEND_FREE, ti);
    return 0;
}

/* タスクを持たない応答(NOP-In / Logout / TMF / Reject)。送信のためにタスクを 1 つ借りる。 */
static int send_pdu(const uint8_t *bhs, const uint8_t *data, uint32_t dlen)
{
    const int ti = task_alloc();
    if (ti < 0) return -1;
    return send_task_pdu((unsigned)ti, bhs, data, dlen);
}

static int send_reject(uint8_t reason, const uint8_t *bad_bhs)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_REJECT;
    bhs[1] = 0x80;
    bhs[2] = reason;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], ISCSI_RSVD_TAG);
    fill_sn(bhs, 1);
    s_i.rejects++;
    return send_pdu(bhs, bad_bhs, ISCSI_BHS_LEN);
}

static void residual(uint32_t edtl, uint32_t actual, uint8_t *flags, uint32_t *resid)
{
    *flags = 0;
    *resid = 0;
    if (edtl > actual) { *flags = ISCSI_RSP_FLAG_U; *resid = edtl - actual; }
    else if (edtl < actual) { *flags = ISCSI_RSP_FLAG_O; *resid = actual - edtl; }
}

/* SCSI Response(GOOD、residual 付き)をタスクの tx から送る。 */
static int send_good(unsigned ti, uint32_t edtl, uint32_t actual)
{
    isert_task_t *t = &s_i.task[ti];
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    uint8_t rf;
    uint32_t resid;
    residual(edtl, actual, &rf, &resid);
    bhs[0] = ISCSI_OP_SCSI_RSP;
    bhs[1] = (uint8_t)(0x80 | rf);
    bhs[ISCSI_RSP_OFF_STATUS] = SCSI_STATUS_GOOD;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], t->itt);
    fill_sn(bhs, 1);
    iscsi_put32(&bhs[ISCSI_RSP_OFF_RESID], resid);
    return send_task_pdu(ti, bhs, NULL, 0);
}

static int send_check(unsigned ti, uint8_t key, uint8_t asc, uint8_t ascq, uint8_t rflags, uint32_t resid)
{
    isert_task_t *t = &s_i.task[ti];
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_SCSI_RSP;
    bhs[1] = (uint8_t)(0x80 | rflags);
    bhs[ISCSI_RSP_OFF_STATUS] = SCSI_STATUS_CHECK_CONDITION;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], t->itt);
    fill_sn(bhs, 1);
    iscsi_put32(&bhs[ISCSI_RSP_OFF_RESID], resid);
    uint8_t d[2 + 18] = {0};
    iscsi_put16(d, 18);
    d[2 + 0] = 0x70;
    d[2 + 2] = key;
    d[2 + 7] = 10;
    d[2 + 12] = asc;
    d[2 + 13] = ascq;
    s_i.check_cond++;
    return send_task_pdu(ti, bhs, d, sizeof(d));
}

/* ---------------------------------------------------------------- Login */

static int send_login_rsp(uint8_t flags, uint16_t status, uint32_t itt, const uint8_t *data, uint32_t dlen)
{
    uint8_t *b = &s_i.login_tx[ISER_HDR_LEN];
    memset(s_i.login_tx, 0, ISER_HDR_LEN + ISCSI_BHS_LEN);
    s_i.login_tx[0] = ISER_F_CTRL;
    b[0] = ISCSI_OP_LOGIN_RSP;
    b[1] = flags;
    memcpy(&b[ISCSI_LOGIN_OFF_ISID], s_i.isid, 6);
    iscsi_put16(&b[ISCSI_LOGIN_OFF_TSIH], s_i.tsih);
    iscsi_put32(&b[ISCSI_OFF_ITT], itt);
    fill_sn(b, 1);
    b[ISCSI_LOGIN_OFF_STATUS] = (uint8_t)(status >> 8);
    b[ISCSI_LOGIN_OFF_STATUS + 1] = (uint8_t)status;
    iscsi_put24(&b[ISCSI_OFF_DSL], dlen);
    const uint32_t pad = (4u - (dlen & 3u)) & 3u;
    if (dlen) memcpy(&b[ISCSI_BHS_LEN], data, dlen);
    if (pad) memset(&b[ISCSI_BHS_LEN + dlen], 0, pad);
    if (mlx5_qp_post_send(s_i.dev, &s_i.cm.rc_qp, s_i.login_tx, ISER_HDR_LEN + ISCSI_BHS_LEN + dlen + pad) != 0)
        return -1;
    s_i.login_busy = 1;
    sq_push(SQ_SEND_LOGIN, 0);
    return 0;
}

static int login_fail(uint16_t status, uint32_t itt, uint8_t csg, const char *why)
{
    uart_printf("[iser] Login を断る(0x%04x): %s\n", status, why);
    return send_login_rsp((uint8_t)(csg << 2), status, itt, NULL, 0);
}

static int login_rx(const uint8_t *b, const uint8_t *data, uint32_t dlen)
{
    const uint8_t fl = b[1];
    const int T = (fl & ISCSI_LOGIN_T) != 0, C = (fl & ISCSI_LOGIN_C) != 0;
    const uint8_t csg = (uint8_t)((fl >> 2) & 3u), nsg = (uint8_t)(fl & 3u);
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    if (!s_i.login_started) {
        s_i.login_started = 1;
        memcpy(s_i.isid, &b[ISCSI_LOGIN_OFF_ISID], 6);
        s_i.tsih = 0;
        s_i.exp_cmd_sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);
        s_i.stat_sn = (uint32_t)timer_now() * 2654435761u;
        iscsi_neg_init(&s_i.neg);
        if (iscsi_be16(&b[ISCSI_LOGIN_OFF_TSIH]) != 0)
            return login_fail(ISCSI_LS_NO_SESSION, itt, csg, "接続の追加(TSIH != 0)は扱わない");
    }
    if (csg == 2u || csg == 3u) return login_fail(ISCSI_LS_INVALID_REQUEST, itt, csg, "CSG が不正");
    if (T && (nsg == 2u || nsg <= csg)) return login_fail(ISCSI_LS_INVALID_REQUEST, itt, csg, "NSG が不正");
    if (s_i.text_len + dlen > sizeof(s_i.text)) return login_fail(ISCSI_LS_INIT_ERR, itt, csg, "鍵が長すぎる");
    memcpy(&s_i.text[s_i.text_len], data, dlen);
    s_i.text_len += dlen;
    if (C) return send_login_rsp((uint8_t)(csg << 2), ISCSI_LS_SUCCESS, itt, NULL, 0);

    uint8_t rsp[ISCSI_LOGIN_MAX_DSL];
    const int rl = iscsi_neg_target(&s_i.neg, &s_i.pref, csg, s_i.text, s_i.text_len, rsp, sizeof(rsp));
    /* 受け取った鍵を表示する(Linux の iSER イニシエータが何を送るかを見るため)。 */
    {
        const char *k, *v;
        uint32_t kl, vl, p = 0;
        uart_printf("[iser] Login 要求 CSG=%u NSG=%u T=%d:", csg, nsg, T);
        while (iscsi_kv_next(s_i.text, s_i.text_len, &p, &k, &kl, &v, &vl))
            uart_printf(" %.*s=%.*s", (int)kl, k, (int)vl, v);
        uart_printf("\n");
    }
    s_i.text_len = 0;
    if (rl < 0) return login_fail(ISCSI_LS_INIT_ERR, itt, csg, "鍵の形式が不正");
    iscsi_neg_t *n = &s_i.neg;
    if (!n->got_initiator_name) return login_fail(ISCSI_LS_MISSING_PARAM, itt, csg, "InitiatorName が無い");
    if (n->p.discovery) return login_fail(ISCSI_LS_NO_SESSION_TYPE, itt, csg, "iSER では Discovery を扱わない");
    if (!n->got_target_name) return login_fail(ISCSI_LS_MISSING_PARAM, itt, csg, "TargetName が無い");
    if (strcmp(n->target_name, ISCSIT_DEFAULT_IQN) != 0) return login_fail(ISCSI_LS_NOT_FOUND, itt, csg, "TargetName が違う");
    if (csg == ISCSI_STAGE_SEC && T && !n->auth_none)
        return login_fail(ISCSI_LS_AUTH_FAILED, itt, csg, "AuthMethod で None を選べない");
    const int to_ffp = T && nsg == ISCSI_STAGE_FFP;
    if (to_ffp && !n->p.rdma_ext)
        return login_fail(ISCSI_LS_INIT_ERR, itt, csg, "RDMAExtensions=Yes になっていない");
    if (to_ffp) {
        if (++s_i.tsih_next == 0) s_i.tsih_next = 1;
        s_i.tsih = s_i.tsih_next;
    }
    const uint8_t rfl = (uint8_t)((T ? ISCSI_LOGIN_T : 0) | (csg << 2) | (T ? nsg : 0));
    if (send_login_rsp(rfl, ISCSI_LS_SUCCESS, itt, rsp, (uint32_t)rl) < 0) return -1;
    if (!to_ffp) return 0;
    s_i.ffp = 1;
    s_i.logins++;
    uart_printf("[iser] ログイン完了: %s tsih=%u burst=%u/%u R2T=%s Imm=%s 受信長 I=%u T=%u\n",
                n->initiator_name, s_i.tsih, n->p.first_burst, n->p.max_burst,
                n->p.initial_r2t ? "Yes" : "No", n->p.immediate_data ? "Yes" : "No",
                n->p.ini_recv_dsl, n->p.tgt_recv_dsl);
    return 0;
}

/* ---------------------------------------------------------------- Full Feature Phase */

static int cmdsn_accept(const uint8_t *b)
{
    if (b[0] & ISCSI_OP_IMMEDIATE) return 1;
    const uint32_t sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);
    const uint32_t max = s_i.exp_cmd_sn + ISERT_WINDOW - 1u;
    if (iscsi_sn_lt(sn, s_i.exp_cmd_sn) || iscsi_sn_lt(max, sn)) return 0;
    s_i.exp_cmd_sn = sn + 1u;
    return 1;
}

static int issue_read(unsigned ti)
{
    if (mlx5_qp_post_rdma_read(s_i.dev, &s_i.cm.rc_qp, s_i.rd[ti].dst, s_i.rd[ti].len,
                               s_i.rd[ti].va, s_i.rd[ti].stag) != 0)
        return -1;
    sq_push(SQ_READ, ti);
    s_i.rra_inflight++;
    return 0;
}

static int handle_scsi_cmd(const uint8_t *iser, const uint8_t *b, const uint8_t *data, uint32_t dlen)
{
    if (!cmdsn_accept(b)) return 0;
    const int ti = task_alloc();
    if (ti < 0) return -1;
    isert_task_t *t = &s_i.task[ti];
    t->itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    t->edtl = iscsi_be32(&b[ISCSI_CMD_OFF_EDTL]);
    memcpy(t->lun8, &b[ISCSI_OFF_LUN], 8);
    s_i.cmds++;
    scsi_result_t r;
    scsi_exec(scsi_decode_lun(&b[ISCSI_OFF_LUN]), &b[ISCSI_CMD_OFF_CDB], t->buf, sizeof(t->buf), &r);    if (r.status != SCSI_STATUS_GOOD) return send_check((unsigned)ti, r.sk, r.asc, r.ascq, 0, 0);
    if (r.dir == SCSI_DIR_READ) {
        const uint32_t n = r.len < t->edtl ? r.len : t->edtl;
        if (n) {
            if (!(iser[0] & ISER_F_RSV)) {   /* 読み出し先を教えてもらっていない */
                t->in_use = 0;
                return send_reject(ISCSI_REJECT_PROTOCOL_ERR, b);
            }
            const uint32_t stag = iscsi_be32(&iser[16]);
            const uint64_t va = ((uint64_t)iscsi_be32(&iser[20]) << 32) | iscsi_be32(&iser[24]);
            if (mlx5_qp_post_rdma_write(s_i.dev, &s_i.cm.rc_qp, r.data, n, va, stag) != 0) return -1;
            sq_push(SQ_WRITE, (unsigned)ti);
            s_i.reads++;
            s_i.bytes_read += n;
        }
        /* RDMA_WRITE の完了を待たずに応答を積む(SQ は投稿順。nvmet_rdma.c と同じ)。 */
        return send_good((unsigned)ti, t->edtl, r.len);
    }
    if (r.dir == SCSI_DIR_WRITE) {
        if (!(b[1] & ISCSI_CMD_W)) return send_check((unsigned)ti, 0x05, 0x24, 0x00, 0, 0);
        if (t->edtl != r.len) {   /* LIO と同じ規則(iscsit.c の start_write)*/
            uint8_t rf;
            uint32_t resid;
            residual(t->edtl, r.len, &rf, &resid);
            if (t->edtl == 0) return send_good((unsigned)ti, 0, r.len);
            return send_check((unsigned)ti, 0x05, 0x0E, 0x03, rf, resid);
        }
        const uint32_t imm = dlen;
        if (imm > r.len || imm > s_i.neg.p.first_burst || (imm && !s_i.neg.p.immediate_data)) {
            t->in_use = 0;
            return send_reject(ISCSI_REJECT_PROTOCOL_ERR, b);
        }
        if (imm) memcpy(r.data, data, imm);
        t->total = r.len;
        s_i.writes++;
        s_i.bytes_written += r.len;
        if (imm == r.len) return send_good((unsigned)ti, t->edtl, r.len);
        if (!(iser[0] & ISER_F_WSV)) {   /* 残りを引く先を教えてもらっていない */
            t->in_use = 0;
            return send_reject(ISCSI_REJECT_PROTOCOL_ERR, b);
        }
        s_i.rd[ti].stag = iscsi_be32(&iser[4]);
        s_i.rd[ti].va = ((uint64_t)iscsi_be32(&iser[8]) << 32) | iscsi_be32(&iser[12]);
        s_i.rd[ti].len = r.len - imm;
        s_i.rd[ti].dst = r.data + imm;
        if (s_i.rra_inflight >= s_i.rra_max) {
            s_i.rra_pend[s_i.rra_pend_tail++ % ISERT_TASKS] = (uint16_t)ti;
            return 0;
        }
        return issue_read((unsigned)ti);
    }
    if (r.dir == SCSI_DIR_VERIFY) {
        /* データを比べる VERIFY は iSER では受けない(sd は投げない)。 */
        return send_check((unsigned)ti, 0x05, 0x20, 0x00, 0, 0);
    }
    return send_good((unsigned)ti, t->edtl, 0);
}

static int handle_nop(const uint8_t *b, const uint8_t *data, uint32_t dlen)
{
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    if (!cmdsn_accept(b)) return 0;
    if (itt == ISCSI_RSVD_TAG) return 0;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_NOOP_IN;
    bhs[1] = 0x80;
    memcpy(&bhs[ISCSI_OFF_LUN], &b[ISCSI_OFF_LUN], 8);
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    iscsi_put32(&bhs[ISCSI_OFF_TTT], ISCSI_RSVD_TAG);
    fill_sn(bhs, 1);
    s_i.nop++;
    return send_pdu(bhs, data, dlen);
}

static int handle_logout(const uint8_t *b)
{
    if (!cmdsn_accept(b)) return 0;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_LOGOUT_RSP;
    bhs[1] = 0x80;
    const uint8_t reason = b[1] & ISCSI_LOGOUT_REASON_MASK;
    bhs[2] = (reason == 2u) ? 2u : 0u;
    memcpy(&bhs[ISCSI_OFF_ITT], &b[ISCSI_OFF_ITT], 4);
    fill_sn(bhs, 1);
    s_i.logouts++;
    s_i.logged_out = 1;
    s_i.t_logout = timer_now();
    uart_printf("[iser] ログアウト(reason=%u)\n", reason);
    return send_pdu(bhs, NULL, 0);
}

static int handle_tmf(const uint8_t *b)
{
    if (!cmdsn_accept(b)) return 0;
    const uint8_t fn = b[1] & 0x7Fu;
    const uint32_t ref = iscsi_be32(&b[20]);
    uint8_t rsp = 0;   /* Function complete */
    if (fn == 1) {      /* ABORT TASK: RDMA_READ を待っている書き込みだけが実行中になりうる */
        rsp = 1;        /* Task does not exist */
        for (unsigned i = 0; i < ISERT_TASKS; i++) {
            if (s_i.task[i].in_use && !s_i.task[i].aborted && s_i.task[i].itt == ref && s_i.rd[i].len) {
                s_i.task[i].aborted = 1;
                rsp = 0;
            }
        }
    } else if (fn == 3 || fn == 14) {
        rsp = (fn == 3) ? 5u : 4u;   /* CLEAR ACA は対応しない / TASK REASSIGN は ERL=0 では持たない */
    } else if (fn > 8) {
        rsp = 255u;
    }
    s_i.tmf++;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_TMF_RSP;
    bhs[1] = 0x80;
    bhs[2] = rsp;
    memcpy(&bhs[ISCSI_OFF_ITT], &b[ISCSI_OFF_ITT], 4);
    fill_sn(bhs, 1);
    return send_pdu(bhs, NULL, 0);
}

/* 受信した 1 メッセージ(iSER ヘッダ + BHS + データ)。 */
static int dispatch(const uint8_t *m, uint32_t len)
{
    if (len < ISER_HDR_LEN + ISCSI_BHS_LEN) return -1;
    const uint8_t *iser = m, *b = m + ISER_HDR_LEN;
    if ((iser[0] & 0xF0u) != ISER_F_CTRL) {
        uart_printf("[iser] 知らない iSER ヘッダ(flags=0x%02x)\n", iser[0]);
        return 0;
    }
    uint32_t ahs = (uint32_t)b[ISCSI_OFF_AHSLEN] * 4u;
    uint32_t dlen = iscsi_be24(&b[ISCSI_OFF_DSL]);
    if (ISER_HDR_LEN + ISCSI_BHS_LEN + ahs + dlen > len) {
        uart_printf("[iser] 長さが合わない(dlen=%u、受信 %u)\n", dlen, len);
        return -1;
    }
    const uint8_t *data = b + ISCSI_BHS_LEN + ahs;
    const uint8_t op = b[0] & ISCSI_OP_MASK;
    if (!s_i.ffp) {
        if (op != ISCSI_OP_LOGIN) return -1;
        return login_rx(b, data, dlen);
    }
    switch (op) {
    case ISCSI_OP_SCSI_CMD: return handle_scsi_cmd(iser, b, data, dlen);
    case ISCSI_OP_NOOP_OUT: return handle_nop(b, data, dlen);
    case ISCSI_OP_LOGOUT:   return handle_logout(b);
    case ISCSI_OP_TMF_REQ:  return handle_tmf(b);
    default:                return send_reject(ISCSI_REJECT_CMD_NOT_SUPP, b);
    }
}

/* ---------------------------------------------------------------- 接続 */

static int post_rx(unsigned slot)
{
    if (mlx5_qp_post_recv(s_i.dev, &s_i.cm.rc_qp, s_i.rx[slot], ISERT_RX_BYTES) != 0) return -1;
    s_i.rq_order[s_i.rq_tail++ % ISERT_RX_SLOTS] = (uint16_t)slot;
    return 0;
}

static void session_reset(void)
{
    s_i.ffp = s_i.login_started = s_i.logged_out = s_i.login_busy = 0;
    s_i.text_len = 0;
    s_i.rq_head = s_i.rq_tail = 0;
    s_i.sq_head = s_i.sq_tail = 0;
    s_i.rra_inflight = 0;
    s_i.rra_pend_head = s_i.rra_pend_tail = 0;
    for (unsigned i = 0; i < ISERT_TASKS; i++) { s_i.task[i].in_use = 0; s_i.rd[i].len = 0; }
}

static int arm_cm(void)
{
    static const uint8_t zero_mac[6] = {0};
    rdma_cm_fill_addr(&s_i.cm, s_i.dev, s_i.self_label, "__no_such_net_ctx__", 0u, 0u, zero_mac, s_i.peer_mac);
    s_i.cm.is_active = 0;
    s_i.cm.skip_ping = 1;
    s_i.cm.rc_qp_index = ISERT_QP_INDEX;
    s_i.cm.listen_port = ISCSIT_ISER_PORT;
    s_i.cm.rep_priv_out[0] = ISER_ZBVA_NOT_USED | ISER_SEND_W_INV_NOT_USED;
    s_i.cm.rep_priv_out_len = 4;
    job_t *cj = job_spawn(rdma_cm_job_step, &s_i.cm, "iser-cm");
    if (!cj) return -1;
    cj->state = RDMA_CM_ST_PASSIVE_SETUP;
    s_i.st = ST_CM_WAIT;
    return 0;
}

static void conn_down(const char *why)
{
    uart_printf("[iser] 接続を畳む: %s\n", why);
    s_i.disconnects++;
    if (s_i.cm.rc_qp.qpn) mlx5_qp_destroy(s_i.dev, &s_i.cm.rc_qp);
    if (s_i.cm.gsi_qp && s_i.cm.gsi_qp->qpn) mlx5_qp_destroy(s_i.dev, s_i.cm.gsi_qp);
    session_reset();
    if (arm_cm() != 0) {
        uart_printf("[!] iser: CM ジョブを作れない\n");
        s_i.st = ST_IDLE;
    }
}

/* DREQ が来ていれば DREP を返して 1。 */
static int check_dreq(void)
{
    if (!s_i.cm.rtu_phase_done || rdma_cm_take_dreq(&s_i.cm, NULL) != 1) return 0;
    const volatile uint8_t *p = &s_i.cm.recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    const uint64_t tid = rd64be(&s_i.cm.recv_buf[MLX5_GRH_BYTES + 8]);
    const uint32_t their = rd32be_ib(&p[0]), mine = rd32be_ib(&p[4]);
    volatile uint8_t *buf = s_i.cm.send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) buf[i] = 0;
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND, tid, CM_DREP_ATTR_ID, 0);
    volatile uint8_t *q = &buf[IB_MAD_HDR_LEN];
    wr32be_ib(&q[0], mine);
    wr32be_ib(&q[4], their);
    dcache_clean_range((const void *)(uintptr_t)s_i.cm.send_buf, sizeof(s_i.cm.send_buf));
    mlx5_qp_post_send_ud(s_i.dev, s_i.cm.gsi_qp, (const void *)(uintptr_t)s_i.cm.send_buf, RDMA_CM_MAD_SIZE,
                         1u, IB_QP1_QKEY, s_i.cm.peer_gid, s_i.cm.peer_mac);
    return mine == s_i.cm.local_comm_id;
}

static job_result_t isert_step(job_t *self)
{
    (void)self;
    switch (s_i.st) {
    case ST_CM_WAIT:
        if (s_i.cm.failed) { conn_down("CM の確立に失敗"); return JOB_WAITING; }
        if (!s_i.cm.established) return JOB_WAITING;
        session_reset();
        s_i.rra_max = mlx5_qp_max_concurrent_rdma_read(s_i.dev);
        if (s_i.cm.negotiated_initiator_depth && s_i.rra_max > s_i.cm.negotiated_initiator_depth)
            s_i.rra_max = s_i.cm.negotiated_initiator_depth;
        if (s_i.rra_max == 0) s_i.rra_max = 1;
        for (unsigned i = 0; i < ISERT_RX_SLOTS; i++) {
            if (post_rx(i) != 0) { conn_down("RECV を投稿できない"); return JOB_WAITING; }
        }
        uart_printf("[iser] RC QP 確立(qpn=%u、相手の RDMA_READ 受け付け %u 本 -> こちらの同時 READ %u 本)\n",
                    s_i.cm.rc_qp.qpn, s_i.cm.peer_responder_resources, s_i.rra_max);
        s_i.st = ST_RUN;
        return JOB_WAITING;

    case ST_RUN: {
        if (check_dreq()) { conn_down("相手が切断した(DREQ)"); return JOB_WAITING; }
        if (s_i.logged_out && timeout_ms(s_i.t_logout, ISERT_LINGER_MS)) {
            /* ログアウトの後、相手の DREQ が来ないまま。こちらから畳む。 */
            (void)rdma_cm_disconnect(&s_i.cm, 200u);
            conn_down("ログアウトの後");
            return JOB_WAITING;
        }
        for (unsigned it = 0; it < 64u; it++) {
            int is_send = 0;
            uint32_t rlen = 0;
            uint8_t synd = 0;
            const int rc = mlx5_qp_poll_cqe(s_i.dev, &s_i.cm.rc_qp, &is_send, &rlen, &synd);
            if (rc == 0) break;
            if (rc < 0) {
                s_i.cqe_err++;
                uart_printf("[iser] CQE エラー(syndrome=0x%02x)\n", synd);
                conn_down("CQE エラー");
                return JOB_WAITING;
            }
            if (is_send) {
                if (s_i.sq_head == s_i.sq_tail) continue;
                const uint8_t op = s_i.sq[s_i.sq_head % ISERT_SQ_RING].op;
                const unsigned ti = s_i.sq[s_i.sq_head % ISERT_SQ_RING].task;
                s_i.sq_head++;
                if (op == SQ_SEND_FREE) {
                    s_i.task[ti].in_use = 0;
                } else if (op == SQ_SEND_LOGIN) {
                    s_i.login_busy = 0;
                } else if (op == SQ_READ) {
                    s_i.rra_inflight--;
                    s_i.rd[ti].len = 0;
                    if (s_i.task[ti].aborted) s_i.task[ti].in_use = 0;   /* 捨てたタスクには応答しない */
                    else if (send_good(ti, s_i.task[ti].edtl, s_i.task[ti].total) < 0) {
                        conn_down("応答を送れない");
                        return JOB_WAITING;
                    }
                    while (s_i.rra_inflight < s_i.rra_max && s_i.rra_pend_head != s_i.rra_pend_tail) {
                        const unsigned nt = s_i.rra_pend[s_i.rra_pend_head++ % ISERT_TASKS];
                        if (issue_read(nt) != 0) { conn_down("RDMA_READ を出せない"); return JOB_WAITING; }
                    }
                }
                continue;
            }
            /* 受信。投稿した順に完了する。 */
            const unsigned slot = s_i.rq_order[s_i.rq_head++ % ISERT_RX_SLOTS];
            dcache_invalidate_range(s_i.rx[slot], rlen);
            if (!sq_room()) {
                /* 送信の枠が無い(相手が窓を守っていれば起きない)。 */
                conn_down("SQ があふれた");
                return JOB_WAITING;
            }
            if (dispatch(s_i.rx[slot], rlen) < 0) {
                conn_down("PDU を処理できない");
                return JOB_WAITING;
            }
            if (post_rx(slot) != 0) { conn_down("RECV を再投稿できない"); return JOB_WAITING; }
        }
        return JOB_WAITING;
    }
    default:
        return JOB_WAITING;
    }
}

/* ---------------------------------------------------------------- 公開 */

int iscsit_iser_started(void) { return s_i.started; }

int iscsit_iser_start(mlx5_dev_t *dev, const char *self_label, const uint8_t peer_mac[6])
{
    if (s_i.started) {
        uart_printf("iser: 既に起動済み\n");
        return -1;
    }
    s_i.dev = dev;
    s_i.self_label = self_label;
    memcpy(s_i.peer_mac, peer_mac, 6);
    memset(&s_i.pref, 0, sizeof(s_i.pref));
    s_i.pref.max_recv_dsl = ISERT_TRDSL;
    s_i.pref.first_burst = 65536u;
    s_i.pref.max_burst = 262144u;
    s_i.pref.max_outstanding_r2t = 1u;
    s_i.pref.initial_r2t = 1;
    s_i.pref.immediate_data = 1;
    s_i.pref.allow_crc32c = 0;    /* iSER ではダイジェストを使わない */
    s_i.pref.tpgt = 1;
    s_i.pref.target_alias = "vfio_nvme";
    s_i.pref.iser = 1;
    s_i.pref.target_recv_dsl = ISERT_TRDSL;
    session_reset();
    if (arm_cm() != 0) {
        uart_printf("iser: CM ジョブを作れない\n");
        return -1;
    }
    s_i.job = job_spawn(isert_step, &s_i, "iser-target");
    if (!s_i.job) {
        uart_printf("iser: ジョブを作れない\n");
        return -1;
    }
    if (smp_boot_core1() == 0) job_pin_to_core(s_i.job, 1u);
    s_i.started = 1;
    uart_printf("[iser] %s で iSER ターゲットを開始(%s、ポート %u)\n", self_label, ISCSIT_DEFAULT_IQN,
                ISCSIT_ISER_PORT);
    return 0;
}

void iscsit_iser_stats_clear(void)
{
    s_i.logins = s_i.logouts = s_i.rejects = s_i.check_cond = s_i.tmf = s_i.nop = s_i.cqe_err = s_i.disconnects = 0;
    s_i.cmds = s_i.reads = s_i.writes = s_i.bytes_read = s_i.bytes_written = 0;
}

void iscsit_iser_status(void)
{
    if (!s_i.started) {
        uart_printf("iser: 未起動(`iscsitiser <相手の MAC>`)\n");
        return;
    }
    uart_printf("iser: %s  状態 %s  qpn=%u  RDMA_READ 同時 %u 本\n", ISCSIT_DEFAULT_IQN,
                s_i.st == ST_RUN ? (s_i.ffp ? "Full Feature" : "login") : "接続待ち",
                s_i.cm.rc_qp.qpn, s_i.rra_max);
    uart_printf("  ログイン %u、ログアウト %u、切断 %u、Reject %u、CHECK CONDITION %u、TMF %u、NOP %u、CQE エラー %u\n",
                s_i.logins, s_i.logouts, s_i.disconnects, s_i.rejects, s_i.check_cond, s_i.tmf, s_i.nop, s_i.cqe_err);
    uart_printf("  SCSI %llu(読み %llu / 書き %llu)、読 %llu / 書 %llu バイト\n",
                (unsigned long long)s_i.cmds, (unsigned long long)s_i.reads, (unsigned long long)s_i.writes,
                (unsigned long long)s_i.bytes_read, (unsigned long long)s_i.bytes_written);
}
