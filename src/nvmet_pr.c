/* 予約(Reservation)。説明は nvmet_pr.h。
 *
 * 振る舞いの手本は Linux の drivers/nvme/target/pr.c(6.18)。関数の分け方も
 * 合わせてあるので、食い違いを疑ったときは同じ名前の関数を見比べること。
 * Linux と違うのは 2 点だけ:
 *  - 登録者を連結リストではなく固定の表で持つ(登録の順番は ord で覚える。
 *    「最初の登録者」が要る場面があるため)。
 *  - Preempt and Abort は Preempt と同じに動く。このターゲットはコマンドを
 *    受けた場で完了させるので、取り消すべき処理中のコマンドが無い
 *    (R2T / RDMA_READ でデータを待っている書き込みだけは別で、それは取り消さない)。 */

#include <stddef.h>
#include "nvmet_pr.h"
#include "nvme_types.h"
#include "net.h"
#include "smp.h"
#include "uart.h"

/* CQE の status(nvmet.c の NVMET_SC_* と同じ作り: Linux の NVME_SC_* を 1 ビット
 * 左シフトし、DNR は bit15)。 */
#define PR_SC_INVALID_OPCODE  0x8002u   /* SC=0x01 Invalid Command Opcode + DNR */
#define PR_SC_INVALID_FIELD   0x8004u   /* SC=0x02 Invalid Field in Command + DNR */
#define PR_SC_INVALID_NS      0x8016u   /* SC=0x0B Invalid Namespace or Format + DNR */
#define PR_SC_SGL_LEN_INVALID 0x801Eu   /* SC=0x0F Data SGL Length Invalid + DNR */
#define PR_SC_HOST_ID_INCONS  0x8030u   /* SC=0x18 Host Identifier Inconsistent Format + DNR */
#define PR_SC_CONFLICT        0x8106u   /* SC=0x83 Reservation Conflict + DNR */
#define PR_SC_INTERNAL        0x000Cu   /* SC=0x06 Internal Error */

#define NSID_BROADCAST 0xFFFFFFFFu

/* 予約の種類(cdw10 bit15:8 の RTYPE)。値は Linux の enum nvme_pr_type。 */
#define PR_WRITE_EXCLUSIVE           1u
#define PR_EXCLUSIVE_ACCESS          2u
#define PR_WRITE_EXCLUSIVE_REG_ONLY  3u
#define PR_EXCLUSIVE_ACCESS_REG_ONLY 4u
#define PR_WRITE_EXCLUSIVE_ALL_REGS  5u
#define PR_EXCLUSIVE_ACCESS_ALL_REGS 6u

/* 通知の種類(LID=0x80 の type)と、それを止める Notification Mask のビット。 */
#define PR_LOG_REG_PREEMPTED   1u
#define PR_LOG_RESV_RELEASED   2u
#define PR_LOG_RESV_PREEMPTED  3u
#define PR_MASK_ALL ((1u << PR_LOG_REG_PREEMPTED) | (1u << PR_LOG_RESV_RELEASED) | \
                     (1u << PR_LOG_RESV_PREEMPTED))

/* Report の拡張形式(EDS=1)。struct nvme_reservation_status_ext /
 * struct nvme_registered_ctrl_ext(Linux の include/linux/nvme.h)。 */
#define PR_REPORT_HDR_LEN   64u
#define PR_REPORT_ENT_LEN   64u

typedef struct {
    uint8_t  used;
    uint8_t  hostid[16];
    uint64_t rkey;
    uint32_t ord;        /* 登録の順番(小さいほど先)*/
} pr_reg_t;

typedef struct {
    pr_reg_t reg[NVMET_PR_MAX_REGS];
    int      holder;     /* reg[] の添字。-1 = 予約なし */
    uint8_t  rtype;      /* 保持者の予約の種類(holder >= 0 のときだけ意味を持つ)*/
    uint32_t generation; /* PRGENERATION(登録者の顔ぶれが変わるたびに増やす)*/
    uint32_t next_ord;
    uint32_t notify_mask;
    uint8_t  dom, nsidx; /* 自分がどのドメインのどの名前空間か(通知と g_nvmet_pr_held 用)*/
} pr_ns_t;

volatile uint8_t g_nvmet_pr_held[NVMET_PR_DOMAINS][NVMET_PR_NSID_MAX];

static pr_ns_t        s_pr[NVMET_PR_DOMAINS][NVMET_PR_NSID_MAX];
/* **予約の状態は IO ジョブ(複数のコア、2 つの実体)から触る**ので 1 本のロックで守る。
 * 予約のコマンドは稀で、IO の毎コマンドの判定は保持者がいるときだけここを通る。 */
static smp_spinlock_t  s_pr_lock;
static nvmet_pr_ctrl_t *s_pr_ctrls[NVMET_PR_MAX_CTRLS];
static int             s_pr_inited;

static int pr_hostid_eq(const uint8_t *a, const uint8_t *b)
{
    for (unsigned i = 0; i < 16u; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static void pr_copy_id(uint8_t *dst, const uint8_t *src)
{
    for (unsigned k = 0; k < 16u; k++) dst[k] = src[k];
}

static void pr_init_once(void)
{
    if (s_pr_inited) return;
    for (unsigned d = 0; d < NVMET_PR_DOMAINS; d++) {
        for (unsigned n = 0; n < NVMET_PR_NSID_MAX; n++) {
            s_pr[d][n].holder = -1;
            s_pr[d][n].dom    = (uint8_t)d;
            s_pr[d][n].nsidx  = (uint8_t)n;
            g_nvmet_pr_held[d][n] = 0;
        }
    }
    s_pr_inited = 1;
}

void nvmet_pr_attach(nvmet_pr_ctrl_t *c, uint8_t domain)
{
    smp_spin_lock(&s_pr_lock);
    pr_init_once();
    c->domain = (domain < NVMET_PR_DOMAINS) ? domain : 0u;
    for (unsigned i = 0; i < NVMET_PR_MAX_CTRLS; i++) {
        if (s_pr_ctrls[i] == c) { smp_spin_unlock(&s_pr_lock); return; }
    }
    for (unsigned i = 0; i < NVMET_PR_MAX_CTRLS; i++) {
        if (s_pr_ctrls[i] == NULL) { s_pr_ctrls[i] = c; break; }
    }
    smp_spin_unlock(&s_pr_lock);
}

void nvmet_pr_connect(nvmet_pr_ctrl_t *c, const uint8_t *hostid16, uint16_t cntlid)
{
    smp_spin_lock(&s_pr_lock);
    for (unsigned k = 0; k < 16u; k++) c->hostid[k] = hostid16 ? hostid16[k] : 0u;
    c->cntlid = cntlid;
    c->log_head = c->log_tail = 0;
    c->log_lost = 0;
    c->aer_notify = 0;
    c->live = 1;
    smp_spin_unlock(&s_pr_lock);
}

void nvmet_pr_session_reset(nvmet_pr_ctrl_t *c)
{
    smp_spin_lock(&s_pr_lock);
    c->live = 0;
    for (unsigned k = 0; k < 16u; k++) c->hostid[k] = 0;
    c->log_head = c->log_tail = 0;
    c->log_counter = 0;
    c->log_lost = 0;
    c->aer_notify = 0;
    smp_spin_unlock(&s_pr_lock);
}

static int pr_find(const pr_ns_t *pr, const uint8_t *hostid)
{
    for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
        if (pr->reg[i].used && pr_hostid_eq(pr->reg[i].hostid, hostid)) return (int)i;
    }
    return -1;
}

/* 登録の順番がいちばん先の登録者(Linux の list_first_or_null_rcu())。 */
static int pr_first(const pr_ns_t *pr)
{
    int best = -1;
    for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
        if (!pr->reg[i].used) continue;
        if (best < 0 || pr->reg[i].ord < pr->reg[best].ord) best = (int)i;
    }
    return best;
}

static void pr_set_holder(pr_ns_t *pr, int idx, uint8_t rtype)
{
    pr->holder = idx;
    if (idx >= 0) pr->rtype = rtype;
    g_nvmet_pr_held[pr->dom][pr->nsidx] = (idx >= 0) ? 1u : 0u;
}

/* ---- 通知(Linux の nvmet_pr_add_resv_log() と nvmet_add_async_event())---- */

static void pr_add_log(nvmet_pr_ctrl_t *c, uint8_t type, uint32_t nsid)
{
    c->log_counter++;
    if (c->log_counter == 0) c->log_counter = 1;
    if (c->log_head - c->log_tail >= NVMET_PR_LOG_SLOTS) {
        c->log_lost++;
        uart_printf("[nvmet-pr] 通知ログが溢れて 1 件捨てた (cntlid=%u type=%u nsid=%u)\n",
                    c->cntlid, type, nsid);
    } else {
        nvmet_pr_log_t *e = &c->log[c->log_head % NVMET_PR_LOG_SLOTS];
        e->count = c->log_counter;
        e->type  = type;
        e->nsid  = nsid;
        c->log_head++;
    }
    /* AER の CQE を送るのは admin ジョブ(このコマンドを処理しているコアではない)。 */
    c->aer_notify = 1;
}

/* 予約が解放された: 解放したホスト以外の、登録しているホストのコントローラへ。 */
static void pr_resv_released(pr_ns_t *pr, const uint8_t *hostid)
{
    if (pr->notify_mask & (1u << PR_LOG_RESV_RELEASED)) return;
    for (unsigned i = 0; i < NVMET_PR_MAX_CTRLS; i++) {
        nvmet_pr_ctrl_t *c = s_pr_ctrls[i];
        if (c == NULL || !c->live || c->domain != pr->dom || pr_hostid_eq(c->hostid, hostid)) continue;
        if (pr_find(pr, c->hostid) >= 0) pr_add_log(c, PR_LOG_RESV_RELEASED, pr->nsidx + 1u);
    }
}

/* 特定のホストのコントローラへ。 */
static void pr_send_event_to_host(pr_ns_t *pr, const uint8_t *hostid, uint8_t type)
{
    for (unsigned i = 0; i < NVMET_PR_MAX_CTRLS; i++) {
        nvmet_pr_ctrl_t *c = s_pr_ctrls[i];
        if (c != NULL && c->live && c->domain == pr->dom && pr_hostid_eq(c->hostid, hostid)) {
            pr_add_log(c, type, pr->nsidx + 1u);
        }
    }
}

static void pr_resv_preempted(pr_ns_t *pr, const uint8_t *hostid)
{
    if (pr->notify_mask & (1u << PR_LOG_RESV_PREEMPTED)) return;
    pr_send_event_to_host(pr, hostid, PR_LOG_RESV_PREEMPTED);
}

static void pr_registration_preempted(pr_ns_t *pr, const uint8_t *hostid)
{
    if (pr->notify_mask & (1u << PR_LOG_REG_PREEMPTED)) return;
    pr_send_event_to_host(pr, hostid, PR_LOG_REG_PREEMPTED);
}

/* ---- 登録 ---- */

/* 登録者を 1 人外す(Linux の nvmet_pr_unregister_one())。保持者だったときは、
 * 全登録者型(5 / 6)なら最初の登録者へ引き継ぎ、それ以外は予約を解放する。 */
static void pr_unregister_one(pr_ns_t *pr, int idx)
{
    uint8_t hostid[16];
    pr_copy_id(hostid, pr->reg[idx].hostid);
    pr->reg[idx].used = 0;

    if (pr->holder != idx) return;
    const uint8_t rtype = pr->rtype;
    if (rtype == PR_WRITE_EXCLUSIVE_ALL_REGS || rtype == PR_EXCLUSIVE_ACCESS_ALL_REGS) {
        pr_set_holder(pr, pr_first(pr), rtype);
    } else {
        pr_set_holder(pr, -1, 0);
        if (rtype == PR_WRITE_EXCLUSIVE_REG_ONLY || rtype == PR_EXCLUSIVE_ACCESS_REG_ONLY) {
            pr_resv_released(pr, hostid);
        }
    }
}

static uint16_t pr_register(const nvmet_pr_ctrl_t *c, pr_ns_t *pr, uint64_t nrkey)
{
    int idx = pr_find(pr, c->hostid);
    if (idx >= 0) {
        /* 同じ鍵で登録し直すのは成功(何も変えない)、違う鍵なら衝突。 */
        return (pr->reg[idx].rkey != nrkey) ? PR_SC_CONFLICT : 0u;
    }
    for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
        if (pr->reg[i].used) continue;
        pr->reg[i].used = 1;
        pr_copy_id(pr->reg[i].hostid, c->hostid);
        pr->reg[i].rkey = nrkey;
        pr->reg[i].ord  = pr->next_ord++;
        return 0u;
    }
    uart_printf("[nvmet-pr] nsid=%u の登録者が上限(%u)に達した\n", pr->nsidx + 1u, NVMET_PR_MAX_REGS);
    return PR_SC_INTERNAL;
}

static uint16_t pr_unregister(const nvmet_pr_ctrl_t *c, pr_ns_t *pr, uint64_t crkey, int ignore_key)
{
    int idx = pr_find(pr, c->hostid);
    if (idx < 0) return PR_SC_CONFLICT;
    if (!ignore_key && pr->reg[idx].rkey != crkey) return PR_SC_CONFLICT;
    pr_unregister_one(pr, idx);
    return 0u;
}

static uint16_t pr_replace(const nvmet_pr_ctrl_t *c, pr_ns_t *pr, uint64_t crkey, uint64_t nrkey,
                           int ignore_key)
{
    int idx = pr_find(pr, c->hostid);
    if (idx < 0) return PR_SC_CONFLICT;
    if (!ignore_key && pr->reg[idx].rkey != crkey) return PR_SC_CONFLICT;
    pr->reg[idx].rkey = nrkey;   /* 保持者のままでよい(予約は登録者に付く)*/
    return 0u;
}

/* ---- 取得・横取り ---- */

static uint16_t pr_acquire(pr_ns_t *pr, int idx, uint8_t rtype)
{
    if (pr->holder >= 0 && pr->holder != idx) return PR_SC_CONFLICT;
    if (pr->holder == idx) return (pr->rtype == rtype) ? 0u : PR_SC_CONFLICT;
    pr_set_holder(pr, idx, rtype);
    return 0u;
}

/* 鍵が prkey の登録者を全部外す(送ったホストは通知しない)。1 人もいなければ衝突。 */
static uint16_t pr_unreg_all_host_by_prkey(pr_ns_t *pr, uint64_t prkey, const uint8_t *send_hostid)
{
    uint16_t st = PR_SC_CONFLICT;
    for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
        if (!pr->reg[i].used || pr->reg[i].rkey != prkey) continue;
        uint8_t hostid[16];
        pr_copy_id(hostid, pr->reg[i].hostid);
        st = 0u;
        pr_unregister_one(pr, (int)i);
        if (!pr_hostid_eq(hostid, send_hostid)) pr_registration_preempted(pr, hostid);
    }
    return st;
}

/* 鍵が prkey で、送ったホスト以外の登録者を外す。 */
static void pr_unreg_all_others_by_prkey(pr_ns_t *pr, uint64_t prkey, const uint8_t *send_hostid)
{
    for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
        if (!pr->reg[i].used || pr->reg[i].rkey != prkey) continue;
        if (pr_hostid_eq(pr->reg[i].hostid, send_hostid)) continue;
        uint8_t hostid[16];
        pr_copy_id(hostid, pr->reg[i].hostid);
        pr_unregister_one(pr, (int)i);
        pr_registration_preempted(pr, hostid);
    }
}

/* 送ったホスト以外の登録者を全部外す。 */
static void pr_unreg_all_others(pr_ns_t *pr, const uint8_t *send_hostid)
{
    for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
        if (!pr->reg[i].used || pr_hostid_eq(pr->reg[i].hostid, send_hostid)) continue;
        uint8_t hostid[16];
        pr_copy_id(hostid, pr->reg[i].hostid);
        pr_unregister_one(pr, (int)i);
        pr_registration_preempted(pr, hostid);
    }
}

/* Linux の nvmet_pr_preempt()。分岐の順番もそのまま。 */
static uint16_t pr_preempt(const nvmet_pr_ctrl_t *c, pr_ns_t *pr, int idx, uint8_t rtype, uint64_t prkey)
{
    if (pr->holder < 0) return pr_unreg_all_host_by_prkey(pr, prkey, c->hostid);

    const uint8_t original = pr->rtype;
    if (original == PR_WRITE_EXCLUSIVE_ALL_REGS || original == PR_EXCLUSIVE_ACCESS_ALL_REGS) {
        if (prkey == 0) {
            /* 先に保持者を自分にしてから他を外す(外している間に他のホストが通らないように)。 */
            pr_set_holder(pr, idx, rtype);
            pr_unreg_all_others(pr, c->hostid);
            return 0u;
        }
        return pr_unreg_all_host_by_prkey(pr, prkey, c->hostid);
    }

    if (pr->holder == idx) {
        pr_set_holder(pr, idx, rtype);
        if (original != rtype) pr_resv_released(pr, c->hostid);
        return 0u;
    }

    if (prkey == pr->reg[pr->holder].rkey) {
        pr_set_holder(pr, idx, rtype);
        pr_unreg_all_others_by_prkey(pr, prkey, c->hostid);
        if (original != rtype) pr_resv_released(pr, c->hostid);
        return 0u;
    }

    if (prkey) return pr_unreg_all_host_by_prkey(pr, prkey, c->hostid);
    return PR_SC_INVALID_FIELD;
}

/* ---- 解放・消去 ---- */

static uint16_t pr_release(const nvmet_pr_ctrl_t *c, pr_ns_t *pr, int idx, uint8_t rtype)
{
    /* 保持者でない登録者の Release は何もしない成功(全登録者型でも、Linux と同じく
     * 保持者として記録している 1 人だけが解放できる)。 */
    if (pr->holder < 0 || pr->holder != idx) return 0u;
    const uint8_t original = pr->rtype;
    if (original != rtype) return PR_SC_CONFLICT;
    pr_set_holder(pr, -1, 0);
    if (original != PR_WRITE_EXCLUSIVE && original != PR_EXCLUSIVE_ACCESS) {
        pr_resv_released(pr, c->hostid);
    }
    return 0u;
}

static void pr_clear(const nvmet_pr_ctrl_t *c, pr_ns_t *pr)
{
    pr_set_holder(pr, -1, 0);
    for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
        if (!pr->reg[i].used) continue;
        pr->reg[i].used = 0;
        if (!pr_hostid_eq(pr->reg[i].hostid, c->hostid)) pr_resv_preempted(pr, pr->reg[i].hostid);
    }
    pr->generation++;
}

/* ---- Report ---- */

static uint16_t pr_report(const pr_ns_t *pr, uint32_t cdw10, uint32_t cdw11,
                          uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    const uint64_t num_bytes = 4ull * ((uint64_t)cdw10 + 1u);   /* cdw10 = NUMD(0's based の dword 数)*/

    /* ホスト識別子は 128 ビットなので、64 ビットの欄しかない旧形式(EDS=0)では返せない。 */
    if (!(cdw11 & 1u)) return PR_SC_HOST_ID_INCONS;
    if (num_bytes < PR_REPORT_HDR_LEN) return PR_SC_INVALID_FIELD;
    if (out == NULL || out_max < PR_REPORT_HDR_LEN) return PR_SC_INTERNAL;

    /* 応答はこちらの置き場の大きさまで(登録者 16 人でも 64 + 16 x 64 = 1,088 バイト)。 */
    const uint32_t len = (num_bytes > out_max) ? out_max : (uint32_t)num_bytes;
    for (uint32_t i = 0; i < len; i++) out[i] = 0;

    const uint8_t rtype = (pr->holder >= 0) ? pr->rtype : 0u;
    wr32le(&out[0], pr->generation);
    out[4] = rtype;
    out[9] = 0;   /* PTPLS: 電源断をまたいで残さない */

    /* 登録の順番に並べる(Linux のリストの順番と同じ)。 */
    uint16_t n = 0;
    uint32_t last_ord = 0;
    int      have_last = 0;
    for (;;) {
        int best = -1;
        for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
            if (!pr->reg[i].used) continue;
            if (have_last && pr->reg[i].ord <= last_ord) continue;
            if (best < 0 || pr->reg[i].ord < pr->reg[best].ord) best = (int)i;
        }
        if (best < 0) break;
        last_ord = pr->reg[best].ord;
        have_last = 1;
        const uint32_t off = PR_REPORT_HDR_LEN + (uint32_t)n * PR_REPORT_ENT_LEN;
        n++;
        if (off + PR_REPORT_ENT_LEN > len) continue;   /* 入りきらなくても数は数える */
        uint8_t *e = &out[off];
        wr16le(&e[0], 0xFFFFu);   /* 動的コントローラ(Linux と同じ)*/
        if (rtype == PR_WRITE_EXCLUSIVE_ALL_REGS || rtype == PR_EXCLUSIVE_ACCESS_ALL_REGS ||
            pr->holder == best) {
            e[2] = 1;            /* RCSTS: 予約を持っている */
        }
        wr64le(&e[8], pr->reg[best].rkey);
        for (unsigned k = 0; k < 16u; k++) e[16 + k] = pr->reg[best].hostid[k];
    }
    wr16le(&out[5], n);   /* REGCTL */
    *out_len = len;
    return 0u;
}

uint16_t nvmet_pr_execute(nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t opcode, uint32_t cdw10,
                          uint32_t cdw11, const uint8_t *data, uint32_t dlen,
                          uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    const int      ignore_key = (int)((cdw10 >> 3) & 1u);   /* IEKEY */
    const uint8_t  rtype = (uint8_t)((cdw10 >> 8) & 0xFFu);
    const uint32_t act   = cdw10 & 0x7u;
    uint16_t st;

    *out_len = 0;
    if (nsid < 1u || nsid > NVMET_PR_NSID_MAX) return PR_SC_INVALID_NS;

    smp_spin_lock(&s_pr_lock);
    pr_init_once();
    pr_ns_t *pr = &s_pr[c->domain][nsid - 1u];

    switch (opcode) {
    case NVME_IO_CMD_RESV_REGISTER: {
        /* データ 16 バイト: CRKEY(現在の鍵)、NRKEY(新しい鍵)。 */
        if (data == NULL || dlen < 16u) { st = PR_SC_SGL_LEN_INVALID; break; }
        const uint64_t crkey = rd64le(&data[0]);
        const uint64_t nrkey = rd64le(&data[8]);
        if (act == 0u)      st = pr_register(c, pr, nrkey);
        else if (act == 1u) st = pr_unregister(c, pr, crkey, ignore_key);
        else if (act == 2u) st = pr_replace(c, pr, crkey, nrkey, ignore_key);
        else                st = PR_SC_INVALID_OPCODE;
        if (st == 0u) pr->generation++;
        break;
    }
    case NVME_IO_CMD_RESV_ACQUIRE: {
        /* データ 16 バイト: CRKEY、PRKEY(横取りする相手の鍵)。IEKEY は使えない。 */
        if (ignore_key || rtype < PR_WRITE_EXCLUSIVE || rtype > PR_EXCLUSIVE_ACCESS_ALL_REGS) {
            st = PR_SC_INVALID_FIELD;
            break;
        }
        if (data == NULL || dlen < 16u) { st = PR_SC_SGL_LEN_INVALID; break; }
        const uint64_t crkey = rd64le(&data[0]);
        const uint64_t prkey = rd64le(&data[8]);
        const int idx = pr_find(pr, c->hostid);
        if (idx < 0 || pr->reg[idx].rkey != crkey) { st = PR_SC_CONFLICT; break; }
        if (act == 0u) {
            st = pr_acquire(pr, idx, rtype);
        } else if (act == 1u || act == 2u) {   /* 2 = Preempt and Abort(取り消すものが無いので 1 と同じ)*/
            st = pr_preempt(c, pr, idx, rtype, prkey);
            if (st == 0u) pr->generation++;
        } else {
            st = PR_SC_INVALID_OPCODE;
        }
        break;
    }
    case NVME_IO_CMD_RESV_RELEASE: {
        /* データ 8 バイト: CRKEY。 */
        if (ignore_key) { st = PR_SC_INVALID_FIELD; break; }
        if (data == NULL || dlen < 8u) { st = PR_SC_SGL_LEN_INVALID; break; }
        const uint64_t crkey = rd64le(&data[0]);
        const int idx = pr_find(pr, c->hostid);
        if (idx < 0 || pr->reg[idx].rkey != crkey) { st = PR_SC_CONFLICT; break; }
        if (act == 0u)      st = pr_release(c, pr, idx, rtype);
        else if (act == 1u) { pr_clear(c, pr); st = 0u; }
        else                st = PR_SC_INVALID_OPCODE;
        break;
    }
    case NVME_IO_CMD_RESV_REPORT:
        st = pr_report(pr, cdw10, cdw11, out, out_max, out_len);
        break;
    default:
        st = PR_SC_INVALID_OPCODE;
        break;
    }
    smp_spin_unlock(&s_pr_lock);
    return st;
}

/* Linux の nvmet_is_req_write_cmd_group() / nvmet_is_req_read_cmd_group()。
 * Compare は読み出しの組、Copy は書き込みの組(読む元も同じ名前空間なので
 * 書き込みの組の判定で足りる)。 */
static int pr_is_write_group(uint32_t opcode)
{
    return opcode == NVME_IO_CMD_FLUSH || opcode == NVME_IO_CMD_WRITE ||
           opcode == NVME_IO_CMD_WRITE_ZEROES || opcode == NVME_IO_CMD_DSM ||
           opcode == NVME_IO_CMD_COPY;
}

static int pr_is_read_group(uint32_t opcode)
{
    return opcode == NVME_IO_CMD_READ || opcode == NVME_IO_CMD_COMPARE;
}

uint16_t nvmet_pr_check_access(const nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t opcode)
{
    if (nsid < 1u || nsid > NVMET_PR_NSID_MAX) return 0u;
    const int w = pr_is_write_group(opcode);
    const int r = pr_is_read_group(opcode);
    if (!w && !r) return 0u;   /* 予約のコマンドは実行するときに判定する */

    uint16_t st = 0u;
    smp_spin_lock(&s_pr_lock);
    const pr_ns_t *pr = &s_pr[c->domain][nsid - 1u];
    if (pr->holder >= 0 && !pr_hostid_eq(pr->reg[pr->holder].hostid, c->hostid)) {
        switch (pr->rtype) {
        case PR_WRITE_EXCLUSIVE:
            if (w) st = PR_SC_CONFLICT;
            break;
        case PR_EXCLUSIVE_ACCESS:
            st = PR_SC_CONFLICT;
            break;
        case PR_WRITE_EXCLUSIVE_REG_ONLY:
        case PR_WRITE_EXCLUSIVE_ALL_REGS:
            if (w && pr_find(pr, c->hostid) < 0) st = PR_SC_CONFLICT;
            break;
        case PR_EXCLUSIVE_ACCESS_REG_ONLY:
        case PR_EXCLUSIVE_ACCESS_ALL_REGS:
            if (pr_find(pr, c->hostid) < 0) st = PR_SC_CONFLICT;
            break;
        default:
            break;
        }
    }
    smp_spin_unlock(&s_pr_lock);
    return st;
}

uint16_t nvmet_pr_set_notify_mask(nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t mask, uint32_t *result)
{
    if (mask & ~PR_MASK_ALL) return PR_SC_INVALID_FIELD;
    if (nsid != NSID_BROADCAST && (nsid < 1u || nsid > NVMET_PR_NSID_MAX)) return PR_SC_INVALID_NS;
    smp_spin_lock(&s_pr_lock);
    pr_init_once();
    for (unsigned n = 0; n < NVMET_PR_NSID_MAX; n++) {
        if (nsid == NSID_BROADCAST || nsid == n + 1u) s_pr[c->domain][n].notify_mask = mask;
    }
    smp_spin_unlock(&s_pr_lock);
    *result = mask;
    return 0u;
}

uint16_t nvmet_pr_get_notify_mask(nvmet_pr_ctrl_t *c, uint32_t nsid, uint32_t *result)
{
    if (nsid < 1u || nsid > NVMET_PR_NSID_MAX) return PR_SC_INVALID_NS;
    *result = s_pr[c->domain][nsid - 1u].notify_mask;
    return 0u;
}

/* Linux の nvmet_execute_get_log_page_resv()。1 回の読み出しで 1 件取り出し、
 * 待ち行列の残りを nr_pages に、捨てた数を count の飛びで表す。 */
void nvmet_pr_build_log(nvmet_pr_ctrl_t *c, uint8_t *buf)
{
    for (unsigned i = 0; i < 64u; i++) buf[i] = 0;
    smp_spin_lock(&s_pr_lock);
    if (c->log_head != c->log_tail) {
        const nvmet_pr_log_t cur = c->log[c->log_tail % NVMET_PR_LOG_SLOTS];
        c->log_tail++;
        uint64_t lost;
        if (c->log_head != c->log_tail) {
            const uint64_t next = c->log[c->log_tail % NVMET_PR_LOG_SLOTS].count;
            lost = (next > cur.count) ? next - cur.count - 1u : UINT64_MAX - cur.count + next - 1u;
        } else {
            lost = c->log_lost;
        }
        const uint64_t count = cur.count + lost;
        wr64le(&buf[0], count == 0 ? 1u : count);
        c->log_lost -= lost;
        buf[8] = cur.type;
        buf[9] = (uint8_t)(c->log_head - c->log_tail);   /* nr_pages: 残りの件数 */
        wr32le(&buf[12], cur.nsid);
    }
    smp_spin_unlock(&s_pr_lock);
}

void nvmet_pr_show(void)
{
    static const char *const names[7] = {
        "なし", "Write Exclusive", "Exclusive Access", "Write Exclusive(登録者のみ)",
        "Exclusive Access(登録者のみ)", "Write Exclusive(全登録者)", "Exclusive Access(全登録者)",
    };
    static const char *const doms[NVMET_PR_DOMAINS] = { "NVMe/TCP", "NVMe-oF RDMA" };
    smp_spin_lock(&s_pr_lock);
    pr_init_once();
    for (unsigned d = 0; d < NVMET_PR_DOMAINS; d++) {
        for (unsigned n = 0; n < NVMET_PR_NSID_MAX; n++) {
            const pr_ns_t *pr = &s_pr[d][n];
            const unsigned t = (pr->holder >= 0 && pr->rtype <= 6u) ? pr->rtype : 0u;
            uart_printf("%s nsid=%u 予約=%s 世代=%u 通知マスク=0x%x\n", doms[d], n + 1u, names[t],
                        pr->generation, pr->notify_mask);
            for (unsigned i = 0; i < NVMET_PR_MAX_REGS; i++) {
                if (!pr->reg[i].used) continue;
                const uint8_t *h = pr->reg[i].hostid;
                uart_printf("  登録者%s: hostid=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                            "%02x%02x%02x%02x%02x%02x 鍵=0x%llx\n", pr->holder == (int)i ? "(保持者)" : "",
                            h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11],
                            h[12], h[13], h[14], h[15], (unsigned long long)pr->reg[i].rkey);
            }
        }
    }
    smp_spin_unlock(&s_pr_lock);
}
