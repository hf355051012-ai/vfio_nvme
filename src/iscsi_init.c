/* iSCSI イニシエータ(RFC 7143、TCP)。PLAN_iscsi.md 段階 D。
 *
 * シェル(core0)の上で同期的に動く。受信は流れとして読み(BHS -> AHS -> ヘッダダイジェスト
 * -> データ -> パディング -> データダイジェスト)、**Data-In は読み出し先のバッファへ直接受ける**。
 * 書き込みは ImmediateData(FirstBurstLength と相手の MaxRecvDataSegmentLength まで)を
 * コマンドの PDU に付け、残りは R2T に応えて Data-Out で送る。InitialR2T=Yes を提案する
 * (未要請の Data-Out は持たない)。コマンドは窓(MaxCmdSN)の中でだけ出す。 */
#include "iscsi_init.h"
#include "iscsi.h"
#include "iscsi_text.h"
#include "iscsi_pdu.h"
#include "iscsi_chap.h"
#include "crypto.h"
#include "tcp.h"
#include "net.h"
#include "netif.h"
#include "job.h"
#include "timer.h"
#include "uart.h"
#include "crc32c.h"
#include <string.h>

#define INI_MAX_TASKS   256u
#define INI_RX_DATA_MAX 262144u
#define INI_BLOCK       512u
#define INI_BENCH_RANGE (64u * 1024u * 1024u)   /* ベンチで回す範囲(先頭から)*/
#define INI_BUF_MAX     (1024u * 1024u)          /* 1 コマンドの最大長 */

typedef struct {
    uint8_t   in_use;
    uint8_t   is_read;
    uint8_t   done;
    uint8_t   status;
    uint8_t   sk, asc, ascq;
    uint32_t  itt;
    uint8_t  *buf;
    uint32_t  len;
    uint32_t  got;              /* 読み出しで受けた長さ */
} ini_task_t;

typedef struct {
    tcp_conn_t tcp;
    int        connected;
    int        hd, dd;
    iscsi_params_t p;           /* max_xmit_dsl = 相手の MaxRecvDataSegmentLength */
    uint8_t    isid[6];
    uint16_t   tsih;
    uint32_t   cmdsn, expstatsn, maxcmdsn;
    uint16_t   gen;
    char       target[ISCSI_NAME_MAX];
    netaddr_t  dst;
    uint16_t   port;
    uint64_t   nblocks;
    /* 受信 */
    uint8_t    ph;
    uint8_t   *rx_dst;
    uint32_t   want, got, dlen, dpad;
    uint8_t    bhs[ISCSI_BHS_LEN];
    uint8_t    ahs[1024];
    uint8_t    dgst[4];
    uint8_t    pad[4];
    uint8_t   *data_dst;
    /* 最後に受けた Login / Text / Logout の応答(同期の手続き用)*/
    uint8_t    last_bhs[ISCSI_BHS_LEN];
    uint32_t   last_dlen;
    int        last_ready;
    /* 統計 */
    uint32_t   outstanding, completed, errors, rejects, nop_in, r2t;
    int        logout_req;      /* 相手が Async Message でログアウトを求めた */
    uint64_t   bytes;
    ini_task_t task[INI_MAX_TASKS];
    uint8_t    data[INI_RX_DATA_MAX + 8u] __attribute__((aligned(64)));
} ini_t;

static ini_t s;
static uint8_t s_wbuf[INI_BUF_MAX] __attribute__((aligned(4096)));   /* 書き込みの模様 */
static uint8_t s_rbuf[INI_BUF_MAX] __attribute__((aligned(4096)));   /* 読み出し先 */
static uint8_t s_sbuf[4096];                                          /* 同期コマンド用 */

enum { PH_BHS = 0, PH_AHS, PH_HDGST, PH_DATA, PH_PAD, PH_DDGST };

/* ---------------------------------------------------------------- 受信 */

static void rx_expect(uint8_t ph, uint8_t *dst, uint32_t n)
{
    s.ph = ph; s.rx_dst = dst; s.want = n; s.got = 0;
}

/* Data-In の行き先(タスクの読み出し先 + オフセット)。合わなければ作業場所へ受けて捨てる。 */
static void route_data_in(void)
{
    s.data_dst = s.data;
    const uint32_t itt = iscsi_be32(&s.bhs[ISCSI_OFF_ITT]);
    const unsigned slot = itt & 0xFFFFu;
    if (slot >= INI_MAX_TASKS) return;
    ini_task_t *t = &s.task[slot];
    const uint32_t off = iscsi_be32(&s.bhs[40]);
    if (!t->in_use || t->itt != itt || !t->is_read || off + s.dlen > t->len) return;
    s.data_dst = t->buf + off;
}

static int rx_after(uint8_t done)
{
    if (done < PH_AHS && s.bhs[ISCSI_OFF_AHSLEN]) { rx_expect(PH_AHS, s.ahs, (uint32_t)s.bhs[ISCSI_OFF_AHSLEN] * 4u); return 0; }
    if (done < PH_HDGST && s.hd) { rx_expect(PH_HDGST, s.dgst, 4); return 0; }
    if (done < PH_DATA && s.dlen) { rx_expect(PH_DATA, s.data_dst, s.dlen); return 0; }
    if (done < PH_PAD && s.dpad != s.dlen) { rx_expect(PH_PAD, s.pad, s.dpad - s.dlen); return 0; }
    if (done < PH_DDGST && s.dd && s.dlen) { rx_expect(PH_DDGST, s.dgst, 4); return 0; }
    return 1;
}

static void task_done(ini_task_t *t, uint8_t status)
{
    t->done = 1;
    t->status = status;
    if (status != SCSI_STATUS_GOOD) {
        if (s.errors++ < 4)
            uart_printf("[iscsi-ini] itt=%08x 状態 0x%02x センス %x/%02x/%02x\n", t->itt, status, t->sk, t->asc, t->ascq);
    }
}

static int send_data_out(ini_task_t *t, uint32_t ttt, uint32_t off, uint32_t want);

/* 受信した PDU 1 つの処理。 */
static int dispatch(void)
{
    const uint8_t *b = s.bhs;
    const uint8_t op = b[0] & ISCSI_OP_MASK;
    /* 窓の更新(ExpCmdSN / MaxCmdSN は Login 以外のほとんどの応答に入っている)。 */
    if (op != ISCSI_OP_LOGIN_RSP) {
        const uint32_t mx = iscsi_be32(&b[ISCSI_OFF_MAXCMDSN]);
        if (iscsi_sn_lt(s.maxcmdsn, mx)) s.maxcmdsn = mx;
    }
    const int status_pdu = (op == ISCSI_OP_SCSI_RSP || op == ISCSI_OP_TEXT_RSP || op == ISCSI_OP_LOGOUT_RSP ||
                            op == ISCSI_OP_TMF_RSP || op == ISCSI_OP_REJECT || op == ISCSI_OP_ASYNC ||
                            (op == ISCSI_OP_DATA_IN && (b[1] & 1u)) ||
                            (op == ISCSI_OP_NOOP_IN && iscsi_be32(&b[ISCSI_OFF_ITT]) != ISCSI_RSVD_TAG));
    if (status_pdu) s.expstatsn = iscsi_be32(&b[ISCSI_OFF_CMDSN]) + 1u;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    const unsigned slot = itt & 0xFFFFu;
    ini_task_t *t = (slot < INI_MAX_TASKS && s.task[slot].in_use && s.task[slot].itt == itt) ? &s.task[slot] : NULL;

    switch (op) {
    case ISCSI_OP_DATA_IN:
        if (t) t->got += s.dlen;
        if ((b[1] & 1u) && t) task_done(t, b[3]);
        return 0;
    case ISCSI_OP_SCSI_RSP:
        if (!t) return 0;
        if (b[3] == SCSI_STATUS_CHECK_CONDITION && s.dlen >= 2u + 14u) {
            t->sk = s.data[2 + 2] & 0x0Fu; t->asc = s.data[2 + 12]; t->ascq = s.data[2 + 13];
        }
        if (b[2] != 0) { t->sk = 0xFF; }   /* iSCSI の応答コードが「完了」でない */
        task_done(t, b[2] ? 0xFFu : b[3]);
        return 0;
    case ISCSI_OP_R2T:
        s.r2t++;
        if (!t) return 0;
        return send_data_out(t, iscsi_be32(&b[ISCSI_OFF_TTT]), iscsi_be32(&b[40]), iscsi_be32(&b[44]));
    case ISCSI_OP_NOOP_IN:
        if (itt == ISCSI_RSVD_TAG && iscsi_be32(&b[ISCSI_OFF_TTT]) != ISCSI_RSVD_TAG) {
            /* 相手からの生存確認。同じ TTT とデータで NOP-Out を返す(Immediate)。 */
            uint8_t o[ISCSI_BHS_LEN] = {0};
            o[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_NOOP_OUT;
            o[1] = 0x80;
            memcpy(&o[ISCSI_OFF_LUN], &b[ISCSI_OFF_LUN], 8);
            iscsi_put32(&o[ISCSI_OFF_ITT], ISCSI_RSVD_TAG);
            memcpy(&o[ISCSI_OFF_TTT], &b[ISCSI_OFF_TTT], 4);
            iscsi_put32(&o[ISCSI_OFF_CMDSN], s.cmdsn);
            iscsi_put32(&o[ISCSI_OFF_EXPSTATSN], s.expstatsn);
            s.nop_in++;
            return iscsi_pdu_send(&s.tcp, s.hd, s.dd, o, s.data, s.dlen, 0);
        }
        return 0;
    case ISCSI_OP_REJECT:
        s.rejects++;
        uart_printf("[iscsi-ini] Reject 理由 0x%02x(断られた op=0x%02x)\n", b[2], s.dlen ? s.data[0] & ISCSI_OP_MASK : 0);
        if (s.dlen >= ISCSI_BHS_LEN) {
            const uint32_t ritt = iscsi_be32(&s.data[ISCSI_OFF_ITT]);
            const unsigned rs = ritt & 0xFFFFu;
            if (rs < INI_MAX_TASKS && s.task[rs].in_use && s.task[rs].itt == ritt) task_done(&s.task[rs], 0xFFu);
        }
        return 0;
    case ISCSI_OP_ASYNC:
        uart_printf("[iscsi-ini] Async Message event=%u\n", b[36]);
        /* 1 = ターゲットがログアウトを求めている。出しているコマンドを終えたら畳む
         * (ベンチは新しいコマンドを出すのをやめる)。次の iscsibench で張り直す。 */
        if (b[36] == 1) s.logout_req = 1;
        return 0;
    default:
        /* Login / Text / Logout の応答は同期の手続きが読む。 */
        memcpy(s.last_bhs, b, ISCSI_BHS_LEN);
        s.last_dlen = s.dlen;
        s.last_ready = 1;
        return 0;
    }
}

/* 1 歩進める。戻り値 1 = 進んだ / 0 = 届いていない / -1 = 切れた */
static int rx_step(void)
{
    if (s.got < s.want) {
        const int n = tcp_recv_no_ack(&s.tcp, s.rx_dst + s.got, s.want - s.got, 0u);
        if (n == 0) { uart_printf("[iscsi-ini] 相手が閉じた\n"); s.connected = 0; return -1; }
        if (n < 0) {
            if (s.tcp.state == TCP_CLOSED) { s.connected = 0; return -1; }
            return 0;
        }
        s.got += (uint32_t)n;
        if (s.got < s.want) return 1;
    }
    int ready = 0;
    switch (s.ph) {
    case PH_BHS:
        s.dlen = iscsi_be24(&s.bhs[ISCSI_OFF_DSL]);
        s.dpad = (s.dlen + 3u) & ~3u;
        if (s.dlen > INI_RX_DATA_MAX) { uart_printf("[iscsi-ini] 長すぎる PDU(%u)\n", s.dlen); return -1; }
        s.data_dst = s.data;
        if ((s.bhs[0] & ISCSI_OP_MASK) == ISCSI_OP_DATA_IN) route_data_in();
        ready = rx_after(PH_BHS);
        break;
    case PH_AHS:   ready = rx_after(PH_AHS); break;
    case PH_HDGST: {
        uint32_t crc = crc32c(0xFFFFFFFFu, s.bhs, ISCSI_BHS_LEN);
        if (s.bhs[ISCSI_OFF_AHSLEN]) crc = crc32c(crc, s.ahs, (uint32_t)s.bhs[ISCSI_OFF_AHSLEN] * 4u);
        if (~crc != iscsi_get_le32(s.dgst)) { uart_printf("[iscsi-ini] ヘッダダイジェストが合わない\n"); return -1; }
        ready = rx_after(PH_HDGST);
        break;
    }
    case PH_DATA:  ready = rx_after(PH_DATA); break;
    case PH_PAD:   ready = rx_after(PH_PAD); break;
    case PH_DDGST: {
        uint32_t crc = crc32c(0xFFFFFFFFu, s.data_dst, s.dlen);
        if (s.dpad != s.dlen) crc = crc32c(crc, s.pad, s.dpad - s.dlen);
        if (~crc != iscsi_get_le32(s.dgst)) { uart_printf("[iscsi-ini] データダイジェストが合わない\n"); return -1; }
        ready = 1;
        break;
    }
    }
    if (!ready) return 1;
    const int r = dispatch();
    rx_expect(PH_BHS, s.bhs, ISCSI_BHS_LEN);
    return r < 0 ? -1 : 1;
}

/* 受信を回す(届いた分だけ)。戻り値 -1 = 切れた。 */
static int rx_pump(unsigned max)
{
    for (unsigned i = 0; i < max; i++) {
        const int r = rx_step();
        if (r < 0) return -1;
        if (r == 0) break;
    }
    return 0;
}

/* Login / Text / Logout の応答を待つ。 */
static int wait_last(uint32_t ms)
{
    s.last_ready = 0;
    const uint64_t t0 = timer_now();
    while (!s.last_ready) {
        if (rx_pump(16) < 0) return -1;
        if (timeout_ms(t0, ms)) return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- 送信 */

static ini_task_t *task_alloc(void)
{
    for (unsigned i = 0; i < INI_MAX_TASKS; i++) {
        ini_task_t *t = &s.task[i];
        if (t->in_use) continue;
        memset(t, 0, sizeof(*t));
        t->in_use = 1;
        t->itt = i | ((uint32_t)(++s.gen) << 16);
        if (t->itt == ISCSI_RSVD_TAG) t->itt = i;
        return t;
    }
    return NULL;
}

static int submit(ini_task_t *t, const uint8_t cdb[16])
{
    uint8_t b[ISCSI_BHS_LEN] = {0};
    b[0] = ISCSI_OP_SCSI_CMD;
    b[1] = (uint8_t)(ISCSI_CMD_F | (t->len ? (t->is_read ? ISCSI_CMD_R : ISCSI_CMD_W) : 0) | 1u);   /* 単純タスク */
    iscsi_put32(&b[ISCSI_OFF_ITT], t->itt);
    iscsi_put32(&b[ISCSI_CMD_OFF_EDTL], t->len);
    iscsi_put32(&b[ISCSI_OFF_CMDSN], s.cmdsn++);
    iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
    memcpy(&b[ISCSI_CMD_OFF_CDB], cdb, 16);
    uint32_t imm = 0;
    if (!t->is_read && t->len && s.p.immediate_data) {
        imm = t->len;
        if (imm > s.p.first_burst) imm = s.p.first_burst;
        if (imm > s.p.max_xmit_dsl) imm = s.p.max_xmit_dsl;
    }
    s.outstanding++;
    return iscsi_pdu_send(&s.tcp, s.hd, s.dd, b, t->buf, imm, 0);
}

/* R2T に応える: [off, off+want) を相手の MaxRecvDataSegmentLength ずつの Data-Out で送る。 */
static int send_data_out(ini_task_t *t, uint32_t ttt, uint32_t off, uint32_t want)
{
    if (off + want > t->len) return -1;
    uint32_t sn = 0, pos = off;
    while (pos < off + want) {
        uint32_t n = off + want - pos;
        if (n > s.p.max_xmit_dsl) n = s.p.max_xmit_dsl;
        uint8_t b[ISCSI_BHS_LEN] = {0};
        b[0] = ISCSI_OP_DATA_OUT;
        b[1] = (uint8_t)((pos + n == off + want) ? 0x80 : 0);
        iscsi_put32(&b[ISCSI_OFF_ITT], t->itt);
        iscsi_put32(&b[ISCSI_OFF_TTT], ttt);
        iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
        iscsi_put32(&b[36], sn++);
        iscsi_put32(&b[40], pos);
        if (iscsi_pdu_send(&s.tcp, s.hd, s.dd, b, t->buf + pos, n, 0) < 0) return -1;
        pos += n;
    }
    return 0;
}

/* 同期の 1 コマンド。戻り値は SCSI の状態(0xFF = 失敗)。 */
static int scsi_sync(const uint8_t cdb[16], int is_read, uint8_t *buf, uint32_t len, ini_task_t *out)
{
    ini_task_t *t = task_alloc();
    if (!t) return 0xFF;
    t->is_read = (uint8_t)is_read;
    t->buf = buf;
    t->len = len;
    if (submit(t, cdb) < 0) { t->in_use = 0; return 0xFF; }
    const uint64_t t0 = timer_now();
    while (!t->done) {
        if (rx_pump(16) < 0 || timeout_ms(t0, 5000u)) { t->in_use = 0; s.outstanding--; return 0xFF; }
    }
    if (out) *out = *t;
    const int st = t->status;
    t->in_use = 0;
    s.outstanding--;
    return st;
}

/* ---------------------------------------------------------------- 接続とログイン */

static int tcp_open(const netaddr_t *dst, uint16_t port)
{
    netif_t *pf0 = netif_find("mlx5-pf0");
    if (pf0) netif_activate(pf0);
    memset(&s.tcp, 0, sizeof(s.tcp));
    tcp_connect_begin_to(&s.tcp, dst, port);
    const uint64_t t0 = timer_now();
    for (;;) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        const int r = tcp_connect_poll(&s.tcp);
        if (r > 0) break;
        if (r < 0 || timeout_ms(t0, 5000u)) { uart_printf("[iscsi-ini] TCP 接続に失敗\n"); return -1; }
    }
    s.ph = PH_BHS;
    rx_expect(PH_BHS, s.bhs, ISCSI_BHS_LEN);
    s.hd = s.dd = 0;
    return 0;
}

/* 応答の鍵から結果を読む(イニシエータ側の交渉の結果)。 */
static void parse_login_keys(const uint8_t *d, uint32_t len)
{
    const char *k, *v;
    uint32_t kl, vl, pos = 0;
    while (iscsi_kv_next(d, len, &pos, &k, &kl, &v, &vl)) {
        uint32_t num = 0;
        for (uint32_t i = 0; i < vl && v[i] >= '0' && v[i] <= '9'; i++) num = num * 10u + (uint32_t)(v[i] - '0');
#define K(name) (kl == sizeof(name) - 1u && memcmp(k, name, kl) == 0)
#define V(val)  (vl == sizeof(val) - 1u && memcmp(v, val, vl) == 0)
        if (K("HeaderDigest")) s.hd = V("CRC32C");
        else if (K("DataDigest")) s.dd = V("CRC32C");
        else if (K("MaxRecvDataSegmentLength")) s.p.max_xmit_dsl = num;
        else if (K("FirstBurstLength")) s.p.first_burst = num;
        else if (K("MaxBurstLength")) s.p.max_burst = num;
        else if (K("InitialR2T")) s.p.initial_r2t = V("Yes");
        else if (K("ImmediateData")) s.p.immediate_data = V("Yes");
        else if (K("MaxOutstandingR2T")) s.p.max_outstanding_r2t = num;
#undef K
#undef V
    }
}

/* 応答の鍵から 1 つ取り出す(NUL 終端して out へ)。戻り値 1 = あった。 */
static int find_key(const uint8_t *d, uint32_t len, const char *name, char *out, uint32_t cap)
{
    const char *k, *v;
    uint32_t kl, vl, pos = 0;
    const uint32_t nl = (uint32_t)strlen(name);
    while (iscsi_kv_next(d, len, &pos, &k, &kl, &v, &vl)) {
        if (kl != nl || memcmp(k, name, kl) != 0) continue;
        if (vl + 1u > cap) return 0;
        memcpy(out, v, vl);
        out[vl] = 0;
        return 1;
    }
    return 0;
}

/* Login 要求を 1 つ送って応答を待つ。戻り値は応答の BHS(状態が 0 でなければ NULL)。 */
static const uint8_t *login_pdu(uint8_t csg, uint8_t nsg, int T, const uint8_t *payload, uint32_t plen)
{
    uint8_t b[ISCSI_BHS_LEN] = {0};
    b[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_LOGIN;
    b[1] = (uint8_t)((T ? ISCSI_LOGIN_T : 0) | (csg << 2) | (T ? nsg : 0));
    memcpy(&b[ISCSI_LOGIN_OFF_ISID], s.isid, 6);
    iscsi_put32(&b[ISCSI_OFF_ITT], 0);
    iscsi_put32(&b[ISCSI_OFF_CMDSN], s.cmdsn);
    iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
    if (iscsi_pdu_send(&s.tcp, 0, 0, b, payload, plen, 0) < 0) return NULL;
    if (wait_last(5000u) < 0) { uart_printf("[iscsi-ini] Login 応答が来ない\n"); return NULL; }
    const uint8_t *r = s.last_bhs;
    if ((r[0] & ISCSI_OP_MASK) != ISCSI_OP_LOGIN_RSP) { uart_printf("[iscsi-ini] Login 応答でない PDU\n"); return NULL; }
    const uint16_t st = (uint16_t)((r[ISCSI_LOGIN_OFF_STATUS] << 8) | r[ISCSI_LOGIN_OFF_STATUS + 1]);
    if (st != 0) { uart_printf("[iscsi-ini] Login を断られた(状態 0x%04x)\n", st); return NULL; }
    s.expstatsn = iscsi_be32(&r[ISCSI_OFF_CMDSN]) + 1u;
    s.cmdsn = iscsi_be32(&r[ISCSI_OFF_EXPSTATSN]);
    s.maxcmdsn = iscsi_be32(&r[ISCSI_OFF_MAXCMDSN]);
    s.tsih = iscsi_be16(&r[ISCSI_LOGIN_OFF_TSIH]);
    return r;
}

static iscsi_chap_cfg_t s_chap;   /* `iscsichap` */
static uint32_t s_chap_ok, s_chap_fail;

void iscsi_ini_set_chap(const iscsi_chap_cfg_t *cfg)
{
    if (cfg) s_chap = *cfg;
    else memset(&s_chap, 0, sizeof(s_chap));
}

/*=================================================================
 * 認証の段(CSG=0)で CHAP を済ませる(RFC 7143 12.1.3)。names は InitiatorName などの宣言。
 *   1. AuthMethod=CHAP(T=0)            -> AuthMethod=CHAP
 *   2. CHAP_A=7,6,5,8                    -> CHAP_A / CHAP_I / CHAP_C
 *   3. CHAP_N / CHAP_R(双方向なら CHAP_I / CHAP_C も)、T=1 NSG=Op
 *                                         -> T=1(双方向なら相手の CHAP_N / CHAP_R を確かめる)
 * ===============================================================*/
static int chap_login(const uint8_t *names, uint32_t nlen)
{
    uint8_t kv[2048];
    uint32_t n = 0;
    char val[ISCSI_CHAP_STR_MAX];
    memcpy(kv, names, nlen);
    n = nlen;
    iscsi_kv_put(kv, sizeof(kv), &n, "AuthMethod", "CHAP");
    const uint8_t *r = login_pdu(ISCSI_STAGE_SEC, ISCSI_STAGE_OP, 0, kv, n);
    if (!r) return -1;
    if (!find_key(s.data, s.last_dlen, "AuthMethod", val, sizeof(val)) || strcmp(val, "CHAP") != 0) {
        uart_printf("[iscsi-ini] 相手が AuthMethod=CHAP を受けない\n");
        return -1;
    }
    n = 0;
    iscsi_kv_put(kv, sizeof(kv), &n, "CHAP_A", "7,6,5,8");
    if (!(r = login_pdu(ISCSI_STAGE_SEC, ISCSI_STAGE_OP, 0, kv, n))) return -1;
    char sa[16], si[16];
    uint8_t chal[ISCSI_CHAP_BIN_MAX];
    if (!find_key(s.data, s.last_dlen, "CHAP_A", sa, sizeof(sa)) || !find_key(s.data, s.last_dlen, "CHAP_I", si, sizeof(si)) ||
        !find_key(s.data, s.last_dlen, "CHAP_C", val, sizeof(val))) {
        uart_printf("[iscsi-ini] CHAP_A / CHAP_I / CHAP_C が来ない\n");
        return -1;
    }
    const int alg = iscsi_chap_num(sa, (uint32_t)strlen(sa));
    const int id = iscsi_chap_num(si, (uint32_t)strlen(si));
    const int cl = iscsi_chap_decode(val, (uint32_t)strlen(val), chal, sizeof(chal));
    if (iscsi_chap_hash(alg) < 0 || id < 0 || id > 255 || cl < 1) {
        uart_printf("[iscsi-ini] 相手の CHAP_A / CHAP_I / CHAP_C が不正(%s / %s)\n", sa, si);
        return -1;
    }
    uint8_t resp[64], my_chal[32], my_id = 0;
    char hex[2u * 64u + 4u];
    const uint32_t rl = iscsi_chap_response(alg, (uint8_t)id, s_chap.secret, s_chap.slen, chal, (uint32_t)cl, resp);
    iscsi_chap_hex(resp, rl, hex);
    n = 0;
    iscsi_kv_put(kv, sizeof(kv), &n, "CHAP_N", s_chap.user);
    iscsi_kv_put(kv, sizeof(kv), &n, "CHAP_R", hex);
    const uint32_t hl = (uint32_t)crypto_hash_len((crypto_hash_id_t)iscsi_chap_hash(alg));
    if (s_chap.mutual) {
        if (crypto_random(&my_id, 1) != 0 || crypto_random(my_chal, hl) != 0) return -1;
        iscsi_kv_put_u32(kv, sizeof(kv), &n, "CHAP_I", my_id);
        iscsi_chap_hex(my_chal, hl, hex);
        iscsi_kv_put(kv, sizeof(kv), &n, "CHAP_C", hex);
    }
    if (!(r = login_pdu(ISCSI_STAGE_SEC, ISCSI_STAGE_OP, 1, kv, n))) { s_chap_fail++; return -1; }
    if (s_chap.mutual) {
        char rn[ISCSI_CHAP_NAME_MAX];
        uint8_t got[ISCSI_CHAP_BIN_MAX], want[64];
        if (!find_key(s.data, s.last_dlen, "CHAP_N", rn, sizeof(rn)) || !find_key(s.data, s.last_dlen, "CHAP_R", val, sizeof(val))) {
            uart_printf("[iscsi-ini] 双方向なのに相手の CHAP_N / CHAP_R が無い\n");
            s_chap_fail++;
            return -1;
        }
        const int gl = iscsi_chap_decode(val, (uint32_t)strlen(val), got, sizeof(got));
        const uint32_t wl = iscsi_chap_response(alg, my_id, s_chap.msecret, s_chap.mlen, my_chal, hl, want);
        if (strcmp(rn, s_chap.muser) != 0 || gl < 0 || (uint32_t)gl != wl || !crypto_equal(got, want, wl)) {
            uart_printf("[iscsi-ini] ターゲットの CHAP 応答が合わない(%s)\n", rn);
            s_chap_fail++;
            return -1;
        }
    }
    if (!(r[1] & ISCSI_LOGIN_T) || (r[1] & 3u) != ISCSI_STAGE_OP) {
        uart_printf("[iscsi-ini] CHAP の後に Op へ移れない\n");
        return -1;
    }
    s_chap_ok++;
    uart_printf("[iscsi-ini] CHAP 済み(CHAP_A=%d%s)\n", alg, s_chap.mutual ? "、双方向" : "");
    return 0;
}

/* ログイン。CHAP を使うなら認証の段を先に済ませ、Op -> FFP を 1 段で済ませる。
 * 相手が T=0 で引き留めたら空の Login を送り直す。 */
static int login(int discovery, const char *target, int want_hd, int want_dd)
{
    uint8_t kv[2048];
    uint32_t n = 0;
    const char *dg_h = want_hd ? "CRC32C,None" : "None";
    const char *dg_d = want_dd ? "CRC32C,None" : "None";
    iscsi_kv_put(kv, sizeof(kv), &n, "InitiatorName", ISCSI_INI_DEFAULT_NAME);
    iscsi_kv_put(kv, sizeof(kv), &n, "InitiatorAlias", "vfio_nvme");
    if (!discovery) iscsi_kv_put(kv, sizeof(kv), &n, "TargetName", target);
    iscsi_kv_put(kv, sizeof(kv), &n, "SessionType", discovery ? "Discovery" : "Normal");
    const uint32_t names_len = n;
    iscsi_kv_put(kv, sizeof(kv), &n, "HeaderDigest", dg_h);
    iscsi_kv_put(kv, sizeof(kv), &n, "DataDigest", dg_d);
    iscsi_kv_put(kv, sizeof(kv), &n, "DefaultTime2Wait", "2");
    iscsi_kv_put(kv, sizeof(kv), &n, "DefaultTime2Retain", "0");
    iscsi_kv_put(kv, sizeof(kv), &n, "IFMarker", "No");
    iscsi_kv_put(kv, sizeof(kv), &n, "OFMarker", "No");
    iscsi_kv_put(kv, sizeof(kv), &n, "ErrorRecoveryLevel", "0");
    if (!discovery) {
        iscsi_kv_put(kv, sizeof(kv), &n, "InitialR2T", "Yes");
        iscsi_kv_put(kv, sizeof(kv), &n, "ImmediateData", "Yes");
        iscsi_kv_put(kv, sizeof(kv), &n, "MaxBurstLength", "262144");
        iscsi_kv_put(kv, sizeof(kv), &n, "FirstBurstLength", "65536");
        iscsi_kv_put(kv, sizeof(kv), &n, "MaxOutstandingR2T", "1");
        iscsi_kv_put(kv, sizeof(kv), &n, "MaxConnections", "1");
        iscsi_kv_put(kv, sizeof(kv), &n, "DataPDUInOrder", "Yes");
        iscsi_kv_put(kv, sizeof(kv), &n, "DataSequenceInOrder", "Yes");
    }
    iscsi_kv_put_u32(kv, sizeof(kv), &n, "MaxRecvDataSegmentLength", INI_RX_DATA_MAX);

    /* RFC 7143 の既定値から始める(相手が答えなかった鍵はこの値)。 */
    memset(&s.p, 0, sizeof(s.p));
    s.p.max_xmit_dsl = ISCSI_LOGIN_MAX_DSL;
    s.p.first_burst = 65536u;
    s.p.max_burst = 262144u;
    s.p.initial_r2t = 1;
    s.p.immediate_data = 1;
    s.p.max_outstanding_r2t = 1;
    s.isid[0] = 0x80; s.isid[1] = 'v'; s.isid[2] = 'f'; s.isid[3] = 'i'; s.isid[4] = 'o'; s.isid[5] = discovery ? 1 : 0;
    s.cmdsn = 1;
    s.expstatsn = 0;
    const uint8_t *payload = kv;
    uint32_t plen = n;
    if (s_chap.set && !discovery) {
        /* 名前は認証の段で宣言済み。Op の段では残りの鍵だけを送る。 */
        if (chap_login(kv, names_len) < 0) return -1;
        payload = kv + names_len;
        plen = n - names_len;
    }
    for (int step = 0; step < 4; step++) {
        const uint8_t *r = login_pdu(ISCSI_STAGE_OP, ISCSI_STAGE_FFP, 1, payload, plen);
        if (!r) return -1;
        parse_login_keys(s.data, s.last_dlen);
        if ((r[1] & ISCSI_LOGIN_T) && (r[1] & 3u) == ISCSI_STAGE_FFP && !(r[1] & ISCSI_LOGIN_C)) {
            s.hd = (s.hd && want_hd);
            s.dd = (s.dd && want_dd);
            return 0;
        }
        payload = NULL;   /* 引き留められた / 続きがある: 空の Login で先を求める */
        plen = 0;
    }
    uart_printf("[iscsi-ini] Login が終わらない\n");
    return -1;
}

static int logout(void)
{
    uint8_t b[ISCSI_BHS_LEN] = {0};
    b[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_LOGOUT;
    b[1] = 0x80;   /* reason 0 = セッションを閉じる */
    iscsi_put32(&b[ISCSI_OFF_ITT], 0x7FFFFFF0u);
    iscsi_put32(&b[ISCSI_OFF_CMDSN], s.cmdsn);
    iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
    if (iscsi_pdu_send(&s.tcp, s.hd, s.dd, b, NULL, 0, 0) < 0) return -1;
    if (wait_last(3000u) < 0) return -1;
    return (s.last_bhs[0] & ISCSI_OP_MASK) == ISCSI_OP_LOGOUT_RSP && s.last_bhs[2] == 0 ? 0 : -1;
}

int iscsi_ini_discover(const netaddr_t *dst, uint16_t port, char *first, unsigned cap)
{
    if (first && cap) first[0] = 0;
    if (tcp_open(dst, port) < 0) return -1;
    if (login(1, NULL, 0, 0) < 0) { tcp_close(&s.tcp); return -1; }
    uint8_t kv[64];
    uint32_t n = 0;
    iscsi_kv_put(kv, sizeof(kv), &n, "SendTargets", "All");
    uint8_t b[ISCSI_BHS_LEN] = {0};
    b[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_TEXT;
    b[1] = ISCSI_TEXT_F;
    iscsi_put32(&b[ISCSI_OFF_ITT], 1);
    iscsi_put32(&b[ISCSI_OFF_TTT], ISCSI_RSVD_TAG);
    iscsi_put32(&b[ISCSI_OFF_CMDSN], s.cmdsn);
    iscsi_put32(&b[ISCSI_OFF_EXPSTATSN], s.expstatsn);
    int ok = -1;
    if (iscsi_pdu_send(&s.tcp, 0, 0, b, kv, n, 0) == 0 && wait_last(3000u) == 0 &&
        (s.last_bhs[0] & ISCSI_OP_MASK) == ISCSI_OP_TEXT_RSP) {
        const char *k, *v;
        uint32_t kl, vl, pos = 0;
        while (iscsi_kv_next(s.data, s.last_dlen, &pos, &k, &kl, &v, &vl)) {
            uart_printf("  %.*s=%.*s\n", (int)kl, k, (int)vl, v);
            if (first && !first[0] && kl == 10 && memcmp(k, "TargetName", 10) == 0 && vl < cap) {
                memcpy(first, v, vl);
                first[vl] = 0;
            }
        }
        ok = 0;
    }
    (void)logout();
    tcp_close(&s.tcp);
    return ok;
}

int iscsi_ini_connect(const netaddr_t *dst, uint16_t port, const char *target_iqn, int hdgst, int ddgst)
{
    if (s.connected) iscsi_ini_close();
    char tn[ISCSI_NAME_MAX];
    if (!target_iqn || !target_iqn[0]) {
        if (iscsi_ini_discover(dst, port, tn, sizeof(tn)) < 0 || !tn[0]) {
            uart_printf("[iscsi-ini] Discovery で対象が見つからない\n");
            return -1;
        }
        target_iqn = tn;
    }
    if (tcp_open(dst, port) < 0) return -1;
    memset(s.task, 0, sizeof(s.task));
    s.logout_req = 0;
    s.outstanding = 0;
    if (login(0, target_iqn, hdgst, ddgst) < 0) { tcp_close(&s.tcp); return -1; }
    {
        size_t l = strlen(target_iqn);
        if (l >= sizeof(s.target)) l = sizeof(s.target) - 1u;
        memcpy(s.target, target_iqn, l);
        s.target[l] = 0;
    }
    s.dst = *dst;
    s.port = port;
    s.connected = 1;
    /* 装置を確かめる(INQUIRY と READ CAPACITY(16))。 */
    uint8_t cdb[16] = {0};
    cdb[0] = 0x12; cdb[4] = 96;
    const int st1 = scsi_sync(cdb, 1, s_sbuf, 96, NULL);
    char vendor[9] = {0}, product[17] = {0};
    memcpy(vendor, &s_sbuf[8], 8);
    memcpy(product, &s_sbuf[16], 16);
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = 0x9E; cdb[1] = 0x10; cdb[13] = 32;
    const int st2 = scsi_sync(cdb, 1, s_sbuf, 32, NULL);
    s.nblocks = st2 == 0 ? (((uint64_t)iscsi_be32(&s_sbuf[0]) << 32) | iscsi_be32(&s_sbuf[4])) + 1u : 0;
    const uint32_t bl = iscsi_be32(&s_sbuf[8]);
    uart_printf("[iscsi-ini] ログイン完了: %s tsih=%u digest=%s/%s 相手の MRDSL=%u burst=%u/%u R2T=%s Imm=%s\n",
                s.target, s.tsih, s.hd ? "CRC32C" : "None", s.dd ? "CRC32C" : "None", s.p.max_xmit_dsl,
                s.p.first_burst, s.p.max_burst, s.p.initial_r2t ? "Yes" : "No", s.p.immediate_data ? "Yes" : "No");
    uart_printf("[iscsi-ini] LUN 0: %s %s / %llu ブロック x %u(INQUIRY 0x%02x / READ CAPACITY 0x%02x)\n",
                vendor, product, (unsigned long long)s.nblocks, bl, st1, st2);
    if (st1 != 0 || st2 != 0 || bl != INI_BLOCK) {
        uart_printf("[iscsi-ini] 装置が使えない(ブロック長 512 だけ扱う)\n");
        iscsi_ini_close();
        return -1;
    }
    return 0;
}

void iscsi_ini_close(void)
{
    if (!s.connected) return;
    if (logout() < 0) uart_printf("[iscsi-ini] ログアウトの応答が無い(閉じる)\n");
    tcp_close(&s.tcp);
    s.connected = 0;
}

int iscsi_ini_connected(void) { return s.connected; }

int iscsi_ini_digest(int *hd, int *dd)
{
    *hd = s.hd; *dd = s.dd;
    return s.connected;
}

/* ---------------------------------------------------------------- ベンチ */

int iscsi_ini_bench(int is_read, uint32_t chunk, uint32_t qd, uint32_t runtime_ms,
                    uint64_t *bytes, uint32_t *count, uint32_t *elapsed_ms, uint32_t *mismatch)
{
    *bytes = 0; *count = 0; *elapsed_ms = 0; *mismatch = 0;
    if (!s.connected) return -1;
    if (chunk == 0 || chunk > INI_BUF_MAX || chunk % INI_BLOCK) { uart_printf("iscsibench: 長さは 512 の倍数で 1MiB まで\n"); return -1; }
    if (qd > INI_MAX_TASKS - 1u) qd = INI_MAX_TASKS - 1u;
    for (uint32_t i = 0; i < chunk; i++) s_wbuf[i] = (uint8_t)(0x5Au ^ (i * 7u));   /* tcpbench と同じ模様 */
    const uint32_t step = chunk / INI_BLOCK;
    uint64_t range = s.nblocks < INI_BENCH_RANGE / INI_BLOCK ? s.nblocks : INI_BENCH_RANGE / INI_BLOCK;
    range -= range % step;
    if (range == 0) return -1;
    uint64_t lba = 0;
    uint32_t done0 = s.errors;
    uint32_t completed = 0, issued = 0;
    uint64_t by = 0;
    const uint64_t t0 = timer_now();
    int stop = 0;
    for (;;) {
        /* 窓と qd の中で出せるだけ出す */
        while (!stop && s.outstanding < qd && iscsi_sn_le(s.cmdsn, s.maxcmdsn)) {
            ini_task_t *t = task_alloc();
            if (!t) break;
            t->is_read = (uint8_t)is_read;
            t->buf = is_read ? s_rbuf : s_wbuf;   /* 中身はどれも同じ模様なので共有する */
            t->len = chunk;
            uint8_t cdb[16] = {0};
            cdb[0] = is_read ? 0x88 : 0x8A;        /* READ(16) / WRITE(16) */
            for (int k = 0; k < 8; k++) cdb[2 + k] = (uint8_t)(lba >> (56 - 8 * k));
            iscsi_put32(&cdb[10], step);
            if (submit(t, cdb) < 0) { uart_printf("iscsibench: 送信に失敗\n"); return -1; }
            issued++;
            lba += step;
            if (lba >= range) lba = 0;
        }
        if (rx_pump(64) < 0) { uart_printf("iscsibench: 接続が切れた\n"); s.connected = 0; return -1; }
        /* 終わったタスクを回収 */
        for (unsigned i = 0; i < INI_MAX_TASKS; i++) {
            ini_task_t *t = &s.task[i];
            if (!t->in_use || !t->done) continue;
            if (t->status == SCSI_STATUS_GOOD) {
                completed++;
                by += t->len;
                /* 抜き取りの照合(64 回に 1 回)。読み出し先は全コマンドで共有だが、
                 * 書いた模様が全部同じなので内容は揃う。 */
                if (t->is_read && (completed & 63u) == 0 && memcmp(t->buf, s_wbuf, t->len) != 0) (*mismatch)++;
            }
            t->in_use = 0;
            s.outstanding--;
        }
        if (!stop && (timeout_ms(t0, runtime_ms) || s.logout_req)) stop = 1;
        if (stop && s.outstanding == 0) break;
        if (timeout_ms(t0, runtime_ms + 10000u)) { uart_printf("iscsibench: 応答が返らないコマンドが残った(%u)\n", s.outstanding); return -1; }
    }
    *elapsed_ms = (uint32_t)((timer_now() - t0) / 1000000ull);
    *bytes = by;
    *count = completed;
    if (s.logout_req) {
        uart_printf("iscsibench: 相手がログアウトを求めたので畳む\n");
        iscsi_ini_close();
    }
    if (s.errors != done0) uart_printf("iscsibench: 失敗したコマンド %u\n", s.errors - done0);
    (void)issued;
    return 0;
}

void iscsi_ini_status(void)
{
    uart_printf("iscsi-ini: CHAP %s(成功 %u / 失敗 %u)\n",
                s_chap.set ? (s_chap.mutual ? "双方向" : "片方向") : "使わない", s_chap_ok, s_chap_fail);
    if (!s.connected) { uart_printf("iscsi-ini: 未接続\n"); return; }
    uart_printf("iscsi-ini: %s tsih=%u CmdSN=%u MaxCmdSN=%u ExpStatSN=%u 未完了 %u、失敗 %u、Reject %u、R2T %u、NOP-In %u\n",
                s.target, s.tsih, s.cmdsn, s.maxcmdsn, s.expstatsn, s.outstanding, s.errors, s.rejects, s.r2t, s.nop_in);
}
