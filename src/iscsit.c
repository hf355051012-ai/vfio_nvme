/* iSCSI ターゲット(RFC 7143、TCP)。PLAN_iscsi.md 段階 A。
 *
 * 構造は NVMe/TCP ターゲット(nvmet.c)と同じ: 待ち受けは 1 本、接続ごとにジョブを
 * 1 本持ち、**listener の受け皿は 1 本しか無いので arm 権を 1 ジョブずつ回す**
 * (arm 権を持たないジョブが tcp_accept_ready_poll() を呼ぶと、他のジョブ宛に確立した
 * 接続を横取りする)。確立したら、その接続の受信を担当するコアへジョブを移す。
 *
 * 受信は流れとして読む: BHS(48)-> AHS -> ヘッダダイジェスト -> データ(4 の倍数まで
 * パディング)-> データダイジェスト -> 処理。**open-iscsi は BHS とデータを別々の
 * TCP セグメントで送ってくる**(段階 0 の記録)ので、1 セグメント = 1 PDU を仮定しない。
 *
 * 送信は短経路(tcp_send_async3)だけ。1 セグメントに収まらない PDU はセグメント
 * ずつに刻んで、やはり短経路で送る(長経路と混ぜると TLS で順序が崩れた。CLAUDE.md)。 */
#include "iscsit.h"
#include "iscsi.h"
#include "iscsi_text.h"
#include "tcp.h"
#include "job.h"
#include "timer.h"
#include "uart.h"
#include "crc32c.h"
#include "scsi.h"
#include "iscsi_pdu.h"
#include "iscsi_chap.h"
#include "crypto.h"
#include <string.h>

typedef enum {
    CS_ARM = 0,        /* 受け皿を立てる番を待つ */
    CS_ACCEPT_WAIT,    /* 受け皿を立てて接続を待つ */
    CS_RX,             /* 接続中(Login と Full Feature Phase)*/
    CS_LINGER,         /* Logout 応答 / Login 失敗の後、相手が閉じるのを待つ */
} iscsit_cstate_t;

typedef enum { PH_BHS = 0, PH_AHS, PH_HDGST, PH_DATA, PH_PAD, PH_DDGST } iscsit_phase_t;

/* 書き込み中のコマンド(R2T でデータを引いている間だけ持つ)。読み出しは処理の中で
 * 送り切るので持たない。MaxOutstandingR2T=1 なので 1 タスクにつき R2T は同時 1 本。 */
typedef struct {
    uint8_t   in_use;
    uint32_t  itt, ttt;
    uint8_t   lun8[8];
    uint8_t  *dst;            /* 書き込み先の先頭(RAM ディスクを直接指す)*/
    uint32_t  total;          /* 書く長さ(SCSI 側)*/
    uint32_t  edtl;           /* イニシエータが言った長さ(residual の計算用)*/
    uint32_t  got;            /* 受け取った長さ(先頭から連続)*/
    uint32_t  r2t_off, r2t_len;
    uint32_t  r2tsn;          /* 次に出す R2TSN(= これまでに出した R2T の数)*/
    uint32_t  datasn;         /* 今の R2T の中で次に来るはずの DataSN */
    uint8_t   verify;         /* VERIFY(データを媒体と比べる。書かない)*/
    uint8_t   miscompare;
    scsi_result_t vr;         /* VERIFY の比べ方 */
} iscsit_task_t;

#define ISCSIT_MAX_TASKS ISCSIT_CMD_WINDOW

static const char *const CS_NAME[] = { "arm", "accept", "rx", "linger" };

typedef struct iscsit_ctx iscsit_ctx_t;

typedef struct {
    iscsit_ctx_t *t;
    unsigned      idx;
    job_t        *job;
    tcp_conn_t    tcp;
    volatile int  st;
    volatile int  kill;            /* session reinstatement で捨てる(他の接続のジョブが立てる)*/
    uint64_t      t_accept;
    uint64_t      t_linger;
    /* ---- 受信 ---- */
    uint8_t       ph;
    uint8_t       hd, dd;          /* Full Feature Phase に入ってから有効 */
    uint8_t      *rx_dst;
    uint32_t      want, got;
    uint32_t      dlen, dpad;
    uint8_t       bhs[ISCSI_BHS_LEN];
    uint8_t       ahs[1024];
    uint8_t       dgst[4];
    uint8_t       pad[4];
    uint8_t      *data_dst;       /* この PDU のデータの行き先(Data-Out なら RAM ディスク)*/
    iscsit_task_t *cur_task;      /* この Data-Out が属するタスク(NULL = 合わないので捨てる)*/
    uint8_t       dataout_stale;  /* 捨てたタスク宛ての Data-Out(黙って捨てる)*/
    /* ターゲットからの生存確認(NOP-In)。 */
    uint32_t      nop_ttt;        /* 0 = 出していない */
    uint64_t      nop_sent_at;
    uint64_t      last_check;
    uint32_t      seen_rx;        /* 前に見たときの pdu_rx(進んでいれば相手は生きている)*/
    uint64_t      idle_since;
    uint32_t      ticks;
    volatile int  async_req;      /* `iscsit logout <n>` が立てる(送るのはこの接続のジョブ)*/
    uint16_t      task_gen;
    iscsit_task_t task[ISCSIT_MAX_TASKS];
    uint8_t       cmdbuf[4096];   /* INQUIRY などの応答を組み立てる場所 */
    uint64_t      bytes_read, bytes_written;
    /* ---- Login / セッション ---- */
    uint8_t       ffp;             /* Full Feature Phase */
    uint8_t       login_started;
    uint8_t       isid[6];
    uint16_t      tsih;
    uint16_t      cid;
    uint32_t      stat_sn;
    uint32_t      exp_cmd_sn;
    iscsi_neg_t   neg;
    uint8_t       auth_st;         /* CHAP の手順(chap_step())*/
    uint8_t       chap_alg, chap_id;
    uint32_t      chap_clen;
    uint8_t       chap_chal[64];
    uint32_t      text_len;        /* C ビットで分けて来た Login / Text の続きを溜める */
    uint8_t       text[16384];
    /* ---- 統計(この接続)---- */
    uint32_t      pdu_rx, pdu_tx, scsi_cmds;
    /* ---- 受信データ(1 PDU ぶん)---- */
    uint8_t       data[ISCSIT_MAX_RECV_DSL + 4u] __attribute__((aligned(64)));
} iscsit_conn_t;

struct iscsit_ctx {
    int           started;
    int           listener;
    uint16_t      port;
    netif_t      *nif;
    volatile int  arm_owner;       /* -1 = 空き */
    uint16_t      tsih_next;
    char          target_name[ISCSI_NAME_MAX];
    iscsi_tgt_pref_t pref;
    iscsi_chap_cfg_t chap;         /* `iscsitchap`。set なら通常セッションに CHAP を求める */
    volatile uint32_t chap_ok, chap_fail;
    /* 統計 */
    volatile uint32_t logins_ok, logins_fail, discovery, reinstated, rejects;
    volatile uint32_t hdgst_err, ddgst_err, window_drop, nop, logouts;
    volatile uint32_t check_cond, bad_dataout, r2t_sent;
    volatile uint32_t tmf, tasks_aborted, stale_dataout, nopin_sent, nopin_timeout, async_sent;
    iscsit_conn_t conn[ISCSIT_MAX_CONNS];
};

static iscsit_ctx_t s_t;

/* 次に送る N 個のヘッダ / データダイジェストをわざと壊す(`iscsit corrupt h|d N`)。
 * 相手(open-iscsi)が壊れたダイジェストを見つけて接続を張り直すことの確認に使う。 */
volatile uint32_t g_iscsit_corrupt_hdgst;
volatile uint32_t g_iscsit_corrupt_ddgst;
/* 受信の ACK を応答の PDU へ相乗りさせる(NVMe/TCP の `ackpiggy` と同じ仕組み)。次の接続から効く。 */
volatile uint32_t g_iscsit_ackpiggy;

/* ---------------------------------------------------------------- 送信 */

/* PDU を 1 つ送る(iscsi_pdu.c)。`iscsit corrupt h|d` が立っていれば次のダイジェストを壊す。 */
static int send_pdu(iscsit_conn_t *c, uint8_t *bhs, const uint8_t *data, uint32_t dlen)
{
    unsigned corrupt = 0;
    if (c->hd && g_iscsit_corrupt_hdgst) { g_iscsit_corrupt_hdgst--; corrupt |= ISCSI_SEND_CORRUPT_HDGST; }
    if (c->dd && dlen && g_iscsit_corrupt_ddgst) { g_iscsit_corrupt_ddgst--; corrupt |= ISCSI_SEND_CORRUPT_DDGST; }
    c->pdu_tx++;
    return iscsi_pdu_send(&c->tcp, c->hd, c->dd, bhs, data, dlen, corrupt);
}

/* 応答の共通部分: StatSN / ExpCmdSN / MaxCmdSN。advance=1 なら StatSN を進める。 */
static void fill_sn(iscsit_conn_t *c, uint8_t *bhs, int advance)
{
    iscsi_put32(&bhs[ISCSI_OFF_CMDSN], advance ? c->stat_sn++ : c->stat_sn);
    iscsi_put32(&bhs[ISCSI_OFF_EXPSTATSN], c->exp_cmd_sn);
    iscsi_put32(&bhs[ISCSI_OFF_MAXCMDSN], c->exp_cmd_sn + ISCSIT_CMD_WINDOW - 1u);
}

static int send_reject(iscsit_conn_t *c, uint8_t reason, const uint8_t *bad_bhs)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_REJECT;
    bhs[1] = 0x80;
    bhs[2] = reason;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], ISCSI_RSVD_TAG);
    fill_sn(c, bhs, 1);
    c->t->rejects++;
    return send_pdu(c, bhs, bad_bhs, ISCSI_BHS_LEN);   /* データは断った PDU のヘッダ */
}

/* ---------------------------------------------------------------- 接続 */

static void conn_reset(iscsit_conn_t *c)
{
    c->ph = PH_BHS;
    c->rx_dst = c->bhs;
    c->want = ISCSI_BHS_LEN;
    c->got = 0;
    c->hd = c->dd = 0;
    c->ffp = 0;
    c->login_started = 0;
    c->tsih = 0;
    c->text_len = 0;
    c->kill = 0;
    c->pdu_rx = c->pdu_tx = c->scsi_cmds = 0;
    c->bytes_read = c->bytes_written = 0;
    c->data_dst = c->data;
    c->cur_task = NULL;
    c->dataout_stale = 0;
    c->nop_ttt = 0;
    c->idle_since = 0;
    c->seen_rx = 0;
    c->ticks = 0;
    c->async_req = 0;
    c->auth_st = 0;
    for (unsigned i = 0; i < ISCSIT_MAX_TASKS; i++) c->task[i].in_use = 0;
    iscsi_neg_init(&c->neg);
}

static void conn_close(iscsit_conn_t *c, const char *why)
{
    uart_printf("[iscsit] 接続%u を閉じる: %s\n", c->idx, why);
    tcp_close(&c->tcp);
    conn_reset(c);
    c->st = CS_ARM;
}

/* 相手が閉じるのを待ってから閉じる(Logout 応答・Login 失敗の応答を確実に届けるため)。 */
static void conn_linger(iscsit_conn_t *c)
{
    c->st = CS_LINGER;
    c->t_linger = timer_now();
}

/* ---------------------------------------------------------------- Login */

static int send_login_rsp(iscsit_conn_t *c, uint8_t flags, uint16_t status, uint32_t itt,
                          const uint8_t *data, uint32_t dlen)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_LOGIN_RSP;
    bhs[1] = flags;
    bhs[2] = 0;   /* VersionMax */
    bhs[3] = 0;   /* VersionActive */
    memcpy(&bhs[ISCSI_LOGIN_OFF_ISID], c->isid, 6);
    iscsi_put16(&bhs[ISCSI_LOGIN_OFF_TSIH], c->tsih);
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    /* **Login 応答も 1 つごとに StatSN を進める**(11.13.4: 次の応答はどれでも + 1)。 */
    fill_sn(c, bhs, 1);
    bhs[ISCSI_LOGIN_OFF_STATUS] = (uint8_t)(status >> 8);
    bhs[ISCSI_LOGIN_OFF_STATUS + 1] = (uint8_t)status;
    return send_pdu(c, bhs, data, dlen);
}

static int login_fail(iscsit_conn_t *c, uint16_t status, uint32_t itt, uint8_t csg, const char *why)
{
    uart_printf("[iscsit] 接続%u Login を断る(0x%04x): %s\n", c->idx, status, why);
    c->t->logins_fail++;
    (void)send_login_rsp(c, (uint8_t)(csg << 2), status, itt, NULL, 0);
    conn_linger(c);
    return 0;
}

/*=================================================================
 * CHAP の手順を 1 歩進める(ターゲット側)。応答の鍵は rsp の pos から書き足す。
 * 戻り値 1 = 済んだ(移行してよい)/ 0 = 途中 / -1 = 断った(login_fail を送った)。
 *   auth_st 0 -> AuthMethod=CHAP に決まった -> 1 -> CHAP_A を受けて CHAP_A / I / C を返した -> 2
 *   -> CHAP_N / R を確かめた(双方向なら相手の CHAP_I / C に答えた)-> 3
 * ===============================================================*/
static int chap_step(iscsit_conn_t *c, uint8_t *rsp, uint32_t cap, uint32_t *pos, uint32_t itt, uint8_t csg)
{
    iscsi_neg_t *n = &c->neg;
    const iscsi_chap_cfg_t *cfg = &c->t->chap;
    switch (c->auth_st) {
    case 0:
        if (!n->auth_chap) { login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "AuthMethod で CHAP を選べない"); return -1; }
        c->auth_st = 1;
        if (!n->got_chap_a) return 0;   /* 普通は次の要求で CHAP_A が来る */
        __attribute__((fallthrough));   /* 同じ要求に CHAP_A が載っていた */
    case 1: {
        if (!n->got_chap_a) return 0;
        const int a = iscsi_chap_pick(n->chap_a, (uint32_t)strlen(n->chap_a));
        if (a < 0) { login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "CHAP_A に使えるものが無い"); return -1; }
        c->chap_alg = (uint8_t)a;
        c->chap_clen = (uint32_t)crypto_hash_len((crypto_hash_id_t)iscsi_chap_hash(a));
        if (crypto_random(&c->chap_id, 1) != 0 || crypto_random(c->chap_chal, c->chap_clen) != 0) {
            login_fail(c, ISCSI_LS_TARGET_ERR, itt, csg, "乱数が取れない");
            return -1;
        }
        char hex[2u * 64u + 4u];
        iscsi_chap_hex(c->chap_chal, c->chap_clen, hex);
        if (iscsi_kv_put_u32(rsp, cap, pos, "CHAP_A", (uint32_t)a) < 0 ||
            iscsi_kv_put_u32(rsp, cap, pos, "CHAP_I", c->chap_id) < 0 ||
            iscsi_kv_put(rsp, cap, pos, "CHAP_C", hex) < 0) {
            login_fail(c, ISCSI_LS_TARGET_ERR, itt, csg, "応答が長すぎる");
            return -1;
        }
        c->auth_st = 2;
        return 0;
    }
    case 2: {
        if (!n->got_chap_n || !n->got_chap_r) { login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "CHAP_N / CHAP_R が無い"); return -1; }
        if (strcmp(n->chap_n, cfg->user) != 0) { login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "CHAP_N が違う"); return -1; }
        uint8_t got[ISCSI_CHAP_BIN_MAX], want[64];
        const int gl = iscsi_chap_decode(n->chap_r, (uint32_t)strlen(n->chap_r), got, sizeof(got));
        const uint32_t wl = iscsi_chap_response(c->chap_alg, c->chap_id, cfg->secret, cfg->slen,
                                                c->chap_chal, c->chap_clen, want);
        if (gl < 0 || (uint32_t)gl != wl || !crypto_equal(got, want, wl)) {
            c->t->chap_fail++;
            login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "CHAP_R が合わない");
            return -1;
        }
        const int peer_mutual = n->got_chap_i || n->got_chap_c;
        if (peer_mutual != cfg->mutual) {
            login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg,
                       cfg->mutual ? "双方向にしたいが相手が CHAP_I / CHAP_C を出さない"
                                   : "相手が双方向を求めたが、こちらの鍵が無い");
            return -1;
        }
        if (peer_mutual) {
            const int id = iscsi_chap_num(n->chap_i, (uint32_t)strlen(n->chap_i));
            uint8_t ci[ISCSI_CHAP_BIN_MAX];
            const int cl = iscsi_chap_decode(n->chap_c, (uint32_t)strlen(n->chap_c), ci, sizeof(ci));
            if (!n->got_chap_i || !n->got_chap_c || id < 0 || id > 255 || cl < 1) {
                login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "相手の CHAP_I / CHAP_C が不正");
                return -1;
            }
            /* **こちらが出した挑戦値をそのまま返してくる相手は断る**(反射攻撃。RFC 7143 12.1.3。
             * DH-HMAC-CHAP の「C2 == C1」と同じ規則)。 */
            if ((uint32_t)cl == c->chap_clen && memcmp(ci, c->chap_chal, (size_t)cl) == 0) {
                login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "相手の挑戦値がこちらのものと同じ");
                return -1;
            }
            uint8_t r[64];
            char hex[2u * 64u + 4u];
            const uint32_t rl = iscsi_chap_response(c->chap_alg, (uint8_t)id, cfg->msecret, cfg->mlen, ci, (uint32_t)cl, r);
            iscsi_chap_hex(r, rl, hex);
            if (iscsi_kv_put(rsp, cap, pos, "CHAP_N", cfg->muser) < 0 ||
                iscsi_kv_put(rsp, cap, pos, "CHAP_R", hex) < 0) {
                login_fail(c, ISCSI_LS_TARGET_ERR, itt, csg, "応答が長すぎる");
                return -1;
            }
        }
        c->auth_st = 3;
        c->t->chap_ok++;
        uart_printf("[iscsit] 接続%u CHAP 済み(CHAP_A=%u%s)\n", c->idx, c->chap_alg, peer_mutual ? "、双方向" : "");
        return 1;
    }
    default:
        return 1;
    }
}

/* TSIH が同じセッションを探す(接続の追加は MaxConnections=1 なので受けない)。 */
static iscsit_conn_t *find_session(uint16_t tsih)
{
    for (unsigned i = 0; i < ISCSIT_MAX_CONNS; i++) {
        iscsit_conn_t *o = &s_t.conn[i];
        if (o->st == CS_RX && o->ffp && o->tsih == tsih) return o;
    }
    return NULL;
}

/*=================================================================
 * Login 要求 1 つ(RFC 7143 6.3 / 11.12)。
 *   - 最初の要求で ISID / TSIH / CID / CmdSN を控え、版を確かめる。
 *   - C ビット: 続きを溜めて、空の応答で続きを求める。
 *   - T ビット: 相手の求める段へ移ることに同意する(こちらから引き留める理由は今は無い)。
 *   - NSG=FFP への移行で名前を確かめ、TSIH を振り、ダイジェストを有効にする。
 * ===============================================================*/
static int login_rx(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    const uint8_t fl = b[1];
    const int T = (fl & ISCSI_LOGIN_T) != 0, C = (fl & ISCSI_LOGIN_C) != 0;
    const uint8_t csg = (uint8_t)((fl >> 2) & 3u), nsg = (uint8_t)(fl & 3u);
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);

    if (!c->login_started) {
        c->login_started = 1;
        memcpy(c->isid, &b[ISCSI_LOGIN_OFF_ISID], 6);
        c->tsih = 0;
        c->cid = iscsi_be16(&b[ISCSI_LOGIN_OFF_CID]);
        c->exp_cmd_sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);   /* Login は Immediate。最初の CmdSN になる */
        c->stat_sn = (uint32_t)timer_now() * 2654435761u;   /* 初期値は任意(LIO も乱数)*/
        iscsi_neg_init(&c->neg);
        const uint16_t tsih = iscsi_be16(&b[ISCSI_LOGIN_OFF_TSIH]);
        if (b[3] > 0) return login_fail(c, ISCSI_LS_NO_VERSION, itt, csg, "VersionMin > 0");
        if (tsih != 0) {
            /* 既存セッションへの接続の追加(MC/S)。MaxConnections=1 なので断る。 */
            return login_fail(c, find_session(tsih) ? ISCSI_LS_TOO_MANY_CONN : ISCSI_LS_NO_SESSION, itt, csg,
                              "接続の追加(TSIH != 0)は扱わない");
        }
    }
    if (csg == 2u || csg == 3u) return login_fail(c, ISCSI_LS_INVALID_REQUEST, itt, csg, "CSG が不正");
    if (T && (nsg == 2u || nsg <= csg)) return login_fail(c, ISCSI_LS_INVALID_REQUEST, itt, csg, "NSG が不正");

    /* 鍵を溜める(C ビットの続きも含めて 1 つの並びとして解釈する)。 */
    if (c->text_len + c->dlen > sizeof(c->text))
        return login_fail(c, ISCSI_LS_INIT_ERR, itt, csg, "鍵が長すぎる");
    memcpy(&c->text[c->text_len], c->data, c->dlen);
    c->text_len += c->dlen;
    if (C) {
        /* 続きを求める空の応答(T=0、C=0)。 */
        return send_login_rsp(c, (uint8_t)(csg << 2), ISCSI_LS_SUCCESS, itt, NULL, 0);
    }

    uint8_t rsp[ISCSI_LOGIN_MAX_DSL];
    const int rl = iscsi_neg_target(&c->neg, &c->t->pref, csg, c->text, c->text_len, rsp, sizeof(rsp));
    c->text_len = 0;
    if (rl < 0) return login_fail(c, ISCSI_LS_INIT_ERR, itt, csg, "鍵の形式が不正");
    iscsi_neg_t *n = &c->neg;
    if (!n->got_initiator_name)
        return login_fail(c, ISCSI_LS_MISSING_PARAM, itt, csg, "InitiatorName が無い");
    if (n->bad_session_type)
        return login_fail(c, ISCSI_LS_NO_SESSION_TYPE, itt, csg, "SessionType が不正");
    if (!n->p.discovery) {
        if (!n->got_target_name)
            return login_fail(c, ISCSI_LS_MISSING_PARAM, itt, csg, "TargetName が無い");
        if (strcmp(n->target_name, c->t->target_name) != 0)
            return login_fail(c, ISCSI_LS_NOT_FOUND, itt, csg, "TargetName が違う");
    }

    /* ---- 認証(RFC 7143 12.1.3)---- */
    uint32_t pos = (uint32_t)rl;
    int agree = T;   /* 相手の求める段へ移ることに同意するか */
    const int chap_req = c->t->chap.set && !n->p.discovery;
    if (csg == ISCSI_STAGE_SEC) {
        if (chap_req) {
            const int r = chap_step(c, rsp, sizeof(rsp), &pos, itt, csg);
            n->got_chap_a = n->got_chap_i = n->got_chap_c = n->got_chap_n = n->got_chap_r = 0;
            if (r < 0) return 0;          /* 断った(chap_step が応答を送った)*/
            if (r == 0) agree = 0;        /* 手順の途中: 相手が移行を求めても引き留める */
        } else if (T && !n->auth_none) {
            return login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "AuthMethod で None を選べない");
        }
    }
    /* CHAP を求めているのに済ませずに先へ進もうとする(認証の段を飛ばして Op から来たときも)。 */
    if (chap_req && agree && c->auth_st != 3 && (csg == ISCSI_STAGE_SEC || nsg == ISCSI_STAGE_FFP))
        return login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "CHAP を済ませていない");

    const int to_ffp = agree && nsg == ISCSI_STAGE_FFP;
    if (to_ffp) {
        /* 新しいセッション。**TSIH は最後の Login 応答に入れる**(それまでは 0)。 */
        if (++c->t->tsih_next == 0) c->t->tsih_next = 1;
        c->tsih = c->t->tsih_next;
    }
    const uint8_t rfl = (uint8_t)((agree ? ISCSI_LOGIN_T : 0) | (csg << 2) | (agree ? nsg : 0));
    if (send_login_rsp(c, rfl, ISCSI_LS_SUCCESS, itt, rsp, pos) < 0) return -1;
    if (!to_ffp) return 0;

    /* ---- Full Feature Phase へ ---- */
    c->ffp = 1;
    c->hd = n->p.hdgst;   /* **応答を送った後から**ダイジェストが付く */
    c->dd = n->p.ddgst;
    c->t->logins_ok++;
    if (n->p.discovery) c->t->discovery++;
    /* session reinstatement: 同じイニシエータ・同じ ISID の古いセッションを捨てる(6.3.5)。 */
    if (!n->p.discovery) {
        for (unsigned i = 0; i < ISCSIT_MAX_CONNS; i++) {
            iscsit_conn_t *o = &c->t->conn[i];
            if (o == c || o->st != CS_RX || !o->ffp || o->neg.p.discovery) continue;
            if (memcmp(o->isid, c->isid, 6) == 0 && strcmp(o->neg.initiator_name, n->initiator_name) == 0) {
                o->kill = 1;
                c->t->reinstated++;
                uart_printf("[iscsit] 接続%u: 同じ ISID の古いセッション(接続%u)を捨てる\n", c->idx, o->idx);
            }
        }
    }
    uart_printf("[iscsit] 接続%u ログイン完了: %s %s isid=%02x%02x%02x%02x%02x%02x tsih=%u "
                "digest=%s/%s MRDSL 受=%u 送=%u burst=%u/%u R2T=%s Imm=%s\n",
                c->idx, n->p.discovery ? "Discovery" : "Normal", n->initiator_name,
                c->isid[0], c->isid[1], c->isid[2], c->isid[3], c->isid[4], c->isid[5], c->tsih,
                c->hd ? "CRC32C" : "None", c->dd ? "CRC32C" : "None",
                n->p.max_recv_dsl, n->p.max_xmit_dsl, n->p.first_burst, n->p.max_burst,
                n->p.initial_r2t ? "Yes" : "No", n->p.immediate_data ? "Yes" : "No");
    return 0;
}

/* ---------------------------------------------------------------- Full Feature Phase */

/* CmdSN の確認(Immediate 以外)。戻り値 1 = 処理する / 0 = 窓の外なので黙って捨てる。 */
static int cmdsn_accept(iscsit_conn_t *c, const uint8_t *b)
{
    if (b[0] & ISCSI_OP_IMMEDIATE) return 1;
    const uint32_t sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);
    const uint32_t max = c->exp_cmd_sn + ISCSIT_CMD_WINDOW - 1u;
    if (iscsi_sn_lt(sn, c->exp_cmd_sn) || iscsi_sn_lt(max, sn)) {
        c->t->window_drop++;
        return 0;   /* 窓の外は黙って捨てる(LIO と同じ。RFC 7143 4.2.2.1)*/
    }
    /* 1 接続・順序どおりの TCP なので先回りは起きないはずだが、来たら追いつかせる。 */
    c->exp_cmd_sn = sn + 1u;
    return 1;
}

static int handle_nop(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    if (!cmdsn_accept(c, b)) return 0;
    if (itt == ISCSI_RSVD_TAG) {
        /* こちらの NOP-In への応答。TTT が合えば生存確認の待ちを解く。 */
        if (c->nop_ttt && iscsi_be32(&b[ISCSI_OFF_TTT]) == c->nop_ttt) c->nop_ttt = 0;
        return 0;
    }
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_NOOP_IN;
    bhs[1] = 0x80;
    memcpy(&bhs[ISCSI_OFF_LUN], &b[ISCSI_OFF_LUN], 8);
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    iscsi_put32(&bhs[ISCSI_OFF_TTT], ISCSI_RSVD_TAG);
    fill_sn(c, bhs, 1);
    c->t->nop++;
    uint32_t n = c->dlen;
    if (n > c->neg.p.max_xmit_dsl) n = c->neg.p.max_xmit_dsl;
    return send_pdu(c, bhs, c->data, n);   /* 同じデータを返す */
}

/* SendTargets の答え(段階 A は自分 1 つだけ)。 */
static int build_send_targets(iscsit_conn_t *c, const char *v, uint32_t vl, uint8_t *out, uint32_t cap, uint32_t *pos)
{
    const char *tn = c->t->target_name;
    const int all = (vl == 3 && memcmp(v, "All", 3) == 0);
    const int match = (vl == strlen(tn) && memcmp(v, tn, vl) == 0);
    const int is_name = vl > 4 && (memcmp(v, "iqn.", 4) == 0 || memcmp(v, "eui.", 4) == 0 ||
                                   memcmp(v, "naa.", 4) == 0);
    /* 値の決まり(RFC 7143 付録 C、振る舞いは LIO の iscsit_process_text_cmd() と同じ):
     *   All -> 全部(Normal セッションでも返す)/ iSCSI 名 -> 一致すればそれ /
     *   空 -> Normal セッションならいまの対象 / それ以外 -> 不正(呼び出し側が Reject で断る)。 */
    if (!all && !is_name && !(vl == 0 && !c->neg.p.discovery)) return -2;
    if (!all && !match && vl != 0) return 0;
    char addr[48];
    const uint32_t ip = c->t->nif->ip;
    unsigned o = 0;
    for (int i = 3; i >= 0; i--) {
        unsigned x = (ip >> (i * 8)) & 0xFFu;
        if (x >= 100) addr[o++] = (char)('0' + x / 100);
        if (x >= 10) addr[o++] = (char)('0' + (x / 10) % 10);
        addr[o++] = (char)('0' + x % 10);
        addr[o++] = i ? '.' : ':';
    }
    unsigned p = c->t->port, d = 10000;
    int lead = 1;
    while (d) {
        unsigned x = (p / d) % 10;
        if (x || !lead || d == 1) { addr[o++] = (char)('0' + x); lead = 0; }
        d /= 10;
    }
    addr[o++] = ',';
    addr[o++] = (char)('0' + c->t->pref.tpgt % 10);   /* tpgt は 1 桁(1)*/
    addr[o] = 0;
    if (iscsi_kv_put(out, cap, pos, "TargetName", tn) < 0) return -1;
    if (iscsi_kv_put(out, cap, pos, "TargetAddress", addr) < 0) return -1;
    return 0;
}

static int handle_text(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    if (!cmdsn_accept(c, b)) return 0;
    const int C = (b[1] & ISCSI_TEXT_C) != 0;
    if (c->text_len + c->dlen > sizeof(c->text)) return send_reject(c, ISCSI_REJECT_PROTOCOL_ERR, b);
    memcpy(&c->text[c->text_len], c->data, c->dlen);
    c->text_len += c->dlen;

    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_TEXT_RSP;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    if (C) {
        /* 続きを求める: F=0、TTT はこちらが決める(次の要求がこれを返してくる)。 */
        bhs[1] = 0;
        iscsi_put32(&bhs[ISCSI_OFF_TTT], 0x1000u + c->idx);
        fill_sn(c, bhs, 1);
        return send_pdu(c, bhs, NULL, 0);
    }
    uint8_t out[4096];
    uint32_t pos = 0;
    const char *k, *v;
    uint32_t kl, vl, p = 0;
    while (iscsi_kv_next(c->text, c->text_len, &p, &k, &kl, &v, &vl)) {
        if (kl == 11 && memcmp(k, "SendTargets", 11) == 0) {
            const int st = build_send_targets(c, v, vl, out, sizeof(out), &pos);
            if (st == -2) {   /* 値が不正(SendTargets=Alle など)*/
                c->text_len = 0;
                return send_reject(c, ISCSI_REJECT_PROTOCOL_ERR, b);
            }
            if (st < 0) break;
        } else {
            /* SendTargets 以外(Full Feature Phase での再交渉など)は扱わない。**Reject で断る**
             * (LIO の iscsit_process_text_cmd() と同じ。iscsi-test-cu の iSCSISendTargets.Invalid は
             * 鍵ごとの "Reject" の応答では先へ進まず待ち続けた)。 */
            c->text_len = 0;
            return send_reject(c, ISCSI_REJECT_PROTOCOL_ERR, b);
        }
    }
    c->text_len = 0;
    bhs[1] = ISCSI_TEXT_F;
    iscsi_put32(&bhs[ISCSI_OFF_TTT], ISCSI_RSVD_TAG);
    fill_sn(c, bhs, 1);
    return send_pdu(c, bhs, out, pos);
}

static int handle_logout(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    if (!cmdsn_accept(c, b)) return 0;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_LOGOUT_RSP;
    bhs[1] = 0x80;
    /* reason 0 = セッションを閉じる / 1 = この接続を閉じる。どちらも同じ(1 接続 1 セッション)。
     * 2(回復のための除去)は ERL=0 なので「回復はできない」(2)。 */
    const uint8_t reason = b[1] & ISCSI_LOGOUT_REASON_MASK;
    bhs[2] = (reason == 2u) ? 2u : 0u;
    memcpy(&bhs[ISCSI_OFF_ITT], &b[ISCSI_OFF_ITT], 4);
    fill_sn(c, bhs, 1);
    c->t->logouts++;
    if (send_pdu(c, bhs, NULL, 0) < 0) return -1;
    uart_printf("[iscsit] 接続%u ログアウト(reason=%u)\n", c->idx, reason);
    conn_linger(c);
    return 0;
}

/* SCSI のセンス(固定形式 0x70)付きの CHECK CONDITION。 */
/* rflags / resid は residual(U / O ビットと残りの長さ)。無ければ 0。 */
static int send_check_condition_r(iscsit_conn_t *c, uint32_t itt, uint8_t key, uint8_t asc, uint8_t ascq,
                                  uint8_t rflags, uint32_t resid)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_SCSI_RSP;
    bhs[1] = (uint8_t)(0x80 | rflags);
    bhs[ISCSI_RSP_OFF_RESPONSE] = 0;   /* Command Completed at Target */
    bhs[ISCSI_RSP_OFF_STATUS] = SCSI_STATUS_CHECK_CONDITION;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    fill_sn(c, bhs, 1);
    iscsi_put32(&bhs[ISCSI_RSP_OFF_RESID], resid);
    uint8_t d[2 + 18] = {0};
    iscsi_put16(d, 18);                /* SenseLength */
    d[2 + 0] = 0x70;                   /* 現在のエラー、固定形式 */
    d[2 + 2] = key;
    d[2 + 7] = 10;                     /* 追加センス長 */
    d[2 + 12] = asc;
    d[2 + 13] = ascq;
    return send_pdu(c, bhs, d, sizeof(d));
}

static int send_check_condition(iscsit_conn_t *c, uint32_t itt, uint8_t key, uint8_t asc, uint8_t ascq)
{
    return send_check_condition_r(c, itt, key, asc, ascq, 0, 0);
}

/* residual(EDTL と実際に運んだ長さの差)。U = 足りない、O = あふれた(11.4.5)。 */
static void residual(uint32_t edtl, uint32_t actual, uint8_t *flags, uint32_t *resid)
{
    *flags = 0;
    *resid = 0;
    if (edtl > actual) { *flags = ISCSI_RSP_FLAG_U; *resid = edtl - actual; }
    else if (edtl < actual) { *flags = ISCSI_RSP_FLAG_O; *resid = actual - edtl; }
}

/* 状態だけの SCSI Response(GOOD)。expdatasn = この コマンドで出した R2T / Data-In の数。 */
static int send_scsi_good(iscsit_conn_t *c, uint32_t itt, uint32_t edtl, uint32_t actual, uint32_t expdatasn)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    uint8_t rf;
    uint32_t resid;
    residual(edtl, actual, &rf, &resid);
    bhs[0] = ISCSI_OP_SCSI_RSP;
    bhs[1] = (uint8_t)(0x80 | rf);
    bhs[ISCSI_RSP_OFF_STATUS] = SCSI_STATUS_GOOD;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    fill_sn(c, bhs, 1);
    iscsi_put32(&bhs[36], expdatasn);
    iscsi_put32(&bhs[ISCSI_RSP_OFF_RESID], resid);
    return send_pdu(c, bhs, NULL, 0);
}

/*=================================================================
 * 読み出しのデータを Data-In で送る。1 PDU は相手の MaxRecvDataSegmentLength まで、
 * MaxBurstLength ごとに F ビットで区切り、**最後の PDU に S ビットで状態を相乗り**させる
 * (SCSI Response を出さない。段階 0 の LIO と同じ)。
 * ===============================================================*/
static int send_data_in(iscsit_conn_t *c, const uint8_t *cmd, const uint8_t *data, uint32_t len, uint32_t edtl)
{
    const uint32_t itt = iscsi_be32(&cmd[ISCSI_OFF_ITT]);
    const uint32_t n = len < edtl ? len : edtl;
    if (n == 0) return send_scsi_good(c, itt, edtl, len, 0);   /* 運ぶものが無い(EDTL=0 など)*/
    uint8_t rf;
    uint32_t resid;
    residual(edtl, len, &rf, &resid);
    const uint32_t mx = c->neg.p.max_xmit_dsl, burst = c->neg.p.max_burst;
    uint32_t off = 0, datasn = 0, left_in_burst = burst;
    while (off < n) {
        uint32_t seg = n - off;
        if (seg > mx) seg = mx;
        if (seg > left_in_burst) seg = left_in_burst;
        const int last = (off + seg == n);
        uint8_t bhs[ISCSI_BHS_LEN] = {0};
        bhs[0] = ISCSI_OP_DATA_IN;
        bhs[1] = (uint8_t)((last || seg == left_in_burst) ? 0x80 : 0);   /* F: 列の終わり */
        if (last) bhs[1] |= (uint8_t)(0x01 | rf);                        /* S + residual */
        bhs[ISCSI_RSP_OFF_STATUS] = SCSI_STATUS_GOOD;
        memcpy(&bhs[ISCSI_OFF_LUN], &cmd[ISCSI_OFF_LUN], 8);
        iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
        iscsi_put32(&bhs[ISCSI_OFF_TTT], ISCSI_RSVD_TAG);
        fill_sn(c, bhs, last);
        if (!last) iscsi_put32(&bhs[ISCSI_OFF_CMDSN], 0);   /* StatSN は S のときだけ意味を持つ */
        iscsi_put32(&bhs[36], datasn++);
        iscsi_put32(&bhs[40], off);
        if (last) iscsi_put32(&bhs[ISCSI_RSP_OFF_RESID], resid);
        if (send_pdu(c, bhs, data + off, seg) < 0) return -1;
        off += seg;
        left_in_burst -= seg;
        if (left_in_burst == 0) left_in_burst = burst;
    }
    c->bytes_read += n;
    return 0;
}

/* R2T を 1 本出す(残りのうち MaxBurstLength まで)。 */
static int send_r2t(iscsit_conn_t *c, iscsit_task_t *t)
{
    t->r2t_off = t->got;
    t->r2t_len = t->total - t->got;
    if (t->r2t_len > c->neg.p.max_burst) t->r2t_len = c->neg.p.max_burst;
    t->datasn = 0;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_R2T;
    bhs[1] = 0x80;
    memcpy(&bhs[ISCSI_OFF_LUN], t->lun8, 8);
    iscsi_put32(&bhs[ISCSI_OFF_ITT], t->itt);
    iscsi_put32(&bhs[ISCSI_OFF_TTT], t->ttt);
    fill_sn(c, bhs, 0);                     /* R2T は StatSN を進めない */
    iscsi_put32(&bhs[36], t->r2tsn++);
    iscsi_put32(&bhs[40], t->r2t_off);
    iscsi_put32(&bhs[44], t->r2t_len);
    c->t->r2t_sent++;
    return send_pdu(c, bhs, NULL, 0);
}

/* データを受け終わったコマンドの完了。VERIFY で食い違っていれば MISCOMPARE。 */
static int finish_data_out(iscsit_conn_t *c, uint32_t itt, uint32_t edtl, uint32_t total, uint32_t expdatasn,
                           int verify, int miscompare)
{
    if (verify && miscompare) {
        c->t->check_cond++;
        return send_check_condition(c, itt, SCSI_SK_MISCOMPARE, SCSI_ASC_MISCOMPARE_VERIFY, 0x00);
    }
    if (!verify) c->bytes_written += total;
    return send_scsi_good(c, itt, edtl, total, expdatasn);
}

/*=================================================================
 * データを受けるコマンドの開始(WRITE と、データを比べる VERIFY)。ImmediateData
 * (コマンドの PDU に付いて来た分)を書き込み先へ写す(VERIFY なら媒体と比べる)。
 * 足りなければ R2T で残りを求める。InitialR2T=Yes なので未要請の Data-Out は来ない。
 * ===============================================================*/
static int start_write(iscsit_conn_t *c, const uint8_t *cmd, const scsi_result_t *r, uint32_t edtl)
{
    const uint32_t itt = iscsi_be32(&cmd[ISCSI_OFF_ITT]);
    const int verify = (r->dir == SCSI_DIR_VERIFY);
    uint8_t *dst = r->data;
    const uint32_t total = r->len;
    if (edtl != total) {
        /* EDTL と SCSI の長さの食い違い。**LIO と同じ規則**(段階 B で iscsi-test-cu の
         * iSCSIResiduals を LIO に流して記録した):
         *   - EDTL = 0 : 何も書かずに GOOD + O(residual = SCSI の長さ)
         *   - それ以外 : CHECK CONDITION / ILLEGAL REQUEST / 0x0E03(INVALID FIELD IN COMMAND
         *                INFORMATION UNIT)+ U / O の residual。書けるぶんだけ書くと媒体の中身が
         *                CDB と食い違うので書かない。 */
        uint8_t rf;
        uint32_t resid;
        residual(edtl, total, &rf, &resid);
        if (edtl == 0) return send_scsi_good(c, itt, 0, total, 0);
        c->t->check_cond++;
        return send_check_condition_r(c, itt, 0x05, 0x0E, 0x03, rf, resid);
    }
    const uint32_t imm = c->dlen;
    if (imm > total || imm > c->neg.p.first_burst || (imm && !c->neg.p.immediate_data))
        return send_reject(c, ISCSI_REJECT_PROTOCOL_ERR, cmd);
    int mis = 0;
    if (imm) {
        if (verify) mis = scsi_verify_cmp(r, 0, c->data, imm);
        else memcpy(dst, c->data, imm);
    }
    if (imm == total) return finish_data_out(c, itt, edtl, total, 0, verify, mis);
    iscsit_task_t *t = NULL;
    for (unsigned i = 0; i < ISCSIT_MAX_TASKS; i++) {
        if (!c->task[i].in_use) { t = &c->task[i]; t->ttt = i | ((uint32_t)(++c->task_gen) << 16); break; }
    }
    if (!t) {
        /* 窓と同じ数だけ用意してあるので来ないはず。 */
        uint8_t bhs[ISCSI_BHS_LEN] = {0};
        bhs[0] = ISCSI_OP_SCSI_RSP;
        bhs[1] = 0x80;
        bhs[ISCSI_RSP_OFF_STATUS] = SCSI_STATUS_BUSY;
        iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
        fill_sn(c, bhs, 1);
        return send_pdu(c, bhs, NULL, 0);
    }
    if (t->ttt == ISCSI_RSVD_TAG) t->ttt = 0;
    t->in_use = 1;
    t->itt = itt;
    memcpy(t->lun8, &cmd[ISCSI_OFF_LUN], 8);
    t->dst = dst;
    t->total = total;
    t->edtl = edtl;
    t->got = imm;
    t->r2tsn = 0;
    t->verify = (uint8_t)verify;
    t->miscompare = (uint8_t)mis;
    t->vr = *r;
    return send_r2t(c, t);
}

static int handle_scsi_cmd(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    if (c->neg.p.discovery) return send_reject(c, ISCSI_REJECT_CMD_NOT_SUPP, b);   /* Discovery では SCSI を受けない */
    if (!cmdsn_accept(c, b)) return 0;
    c->scsi_cmds++;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    const uint32_t edtl = iscsi_be32(&b[ISCSI_CMD_OFF_EDTL]);
    scsi_result_t r;
    scsi_exec(scsi_decode_lun(&b[ISCSI_OFF_LUN]), &b[ISCSI_CMD_OFF_CDB], c->cmdbuf, sizeof(c->cmdbuf), &r);
    if (r.status != SCSI_STATUS_GOOD) {
        c->t->check_cond++;
        return send_check_condition(c, itt, r.sk, r.asc, r.ascq);
    }
    switch (r.dir) {
    case SCSI_DIR_READ:
        return send_data_in(c, b, r.data, r.len, edtl);
    case SCSI_DIR_WRITE:
    case SCSI_DIR_VERIFY:
        if (!(b[1] & ISCSI_CMD_W)) {
            /* データを受けるコマンドなのに W ビットが無い = データを送ってくる気が無い。 */
            c->t->check_cond++;
            return send_check_condition(c, itt, 0x05, 0x24, 0x00);
        }
        return start_write(c, b, &r, edtl);
    default:
        return send_scsi_good(c, itt, edtl, 0, 0);
    }
}

/* Data-Out の BHS を読んだところで、データの行き先を決める(**RAM ディスクへ直接受ける**)。 */
static void dataout_route(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]), ttt = iscsi_be32(&b[ISCSI_OFF_TTT]);
    const uint32_t datasn = iscsi_be32(&b[36]), off = iscsi_be32(&b[40]);
    c->cur_task = NULL;
    c->data_dst = c->data;
    c->dataout_stale = 0;
    const unsigned slot = ttt & 0xFFFFu;
    if (ttt == ISCSI_RSVD_TAG || slot >= ISCSIT_MAX_TASKS) return;
    iscsit_task_t *t = &c->task[slot];
    if (!t->in_use || t->ttt != ttt) {
        /* こちらが出した TTT の形だが、そのタスクはもう無い(TMF で捨てた)。 */
        c->dataout_stale = 1;
        return;
    }
    if (t->itt != itt) return;
    /* 順序どおり(DataPDUInOrder=Yes)・R2T の範囲の中・DataSN が続いていること。 */
    if (off != t->got || off + c->dlen > t->r2t_off + t->r2t_len || datasn != t->datasn) return;
    c->cur_task = t;
    /* VERIFY は媒体へ書かない: 作業場所へ受けて、処理のときに媒体と比べる。 */
    c->data_dst = t->verify ? c->data : t->dst + off;
}

static int handle_data_out(iscsit_conn_t *c)
{
    iscsit_task_t *t = c->cur_task;
    if (!t) {
        if (c->dataout_stale) {
            /* TMF で捨てた(あるいは既に終えた)タスク宛ての遅れて届いた Data-Out。黙って捨てる。 */
            c->t->stale_dataout++;
            return 0;
        }
        /* 範囲の外 / 順序の乱れ / DataSN の飛び。ERL=0 では立て直せないので断って閉じる。 */
        c->t->bad_dataout++;
        send_reject(c, ISCSI_REJECT_INVALID_FIELD, c->bhs);
        return -1;
    }
    if (t->verify && !t->miscompare)
        t->miscompare = (uint8_t)scsi_verify_cmp(&t->vr, t->got, c->data, c->dlen);
    t->got += c->dlen;
    t->datasn++;
    if (!(c->bhs[1] & 0x80)) return 0;   /* F が立つまでは同じ R2T の続き */
    if (t->got != t->r2t_off + t->r2t_len) {
        c->t->bad_dataout++;
        send_reject(c, ISCSI_REJECT_PROTOCOL_ERR, c->bhs);
        t->in_use = 0;
        return -1;
    }
    if (t->got < t->total) return send_r2t(c, t);
    t->in_use = 0;
    return finish_data_out(c, t->itt, t->edtl, t->total, t->r2tsn, t->verify, t->miscompare);
}

/* TMF の応答コード(RFC 7143 11.6.1)。 */
#define TMF_RSP_COMPLETE       0u
#define TMF_RSP_NO_TASK        1u
#define TMF_RSP_NO_LUN         2u
#define TMF_RSP_NOT_SUPPORTED  5u
#define TMF_RSP_REASSIGN_NS    4u
#define TMF_RSP_REJECTED       255u

/* 書き込み中のタスクを捨てる(lun8 が NULL なら全部)。捨てた数を返す。 */
static unsigned abort_tasks(iscsit_conn_t *c, const uint8_t *lun8, uint32_t only_itt, int by_itt)
{
    unsigned n = 0;
    for (unsigned i = 0; i < ISCSIT_MAX_TASKS; i++) {
        iscsit_task_t *t = &c->task[i];
        if (!t->in_use) continue;
        if (by_itt && t->itt != only_itt) continue;
        if (lun8 && memcmp(t->lun8, lun8, 8) != 0) continue;
        t->in_use = 0;
        n++;
    }
    c->t->tasks_aborted += n;
    return n;
}

/*=================================================================
 * タスク管理(RFC 7143 11.5 / 11.6)。このターゲットで「実行中」のタスクは、R2T で
 * データを待っている書き込みだけ(読み出しや問い合わせは受けた時点で答え切る)。
 * **捨てたタスクの SCSI Response は出さない**(11.5.1: 中断したタスクには応答しない)。
 * 捨てたタスク宛てに遅れて届く Data-Out は黙って捨てる(dataout_route)。
 * ===============================================================*/
static int handle_tmf(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    if (!cmdsn_accept(c, b)) return 0;
    const uint8_t fn = b[1] & 0x7Fu;
    const uint32_t ref_itt = iscsi_be32(&b[20]);
    const uint8_t *lun8 = &b[ISCSI_OFF_LUN];
    const int lun_ok = scsi_get_lun(scsi_decode_lun(lun8)) != NULL;
    uint8_t rsp;
    int cold = 0;
    switch (fn) {
    case 1:   /* ABORT TASK */
        /* 見つからなければ「タスクが無い」。既に完了して応答を送ったタスクもこれに当たる
         * (イニシエータは応答を受けていれば中断しない)。 */
        rsp = abort_tasks(c, NULL, ref_itt, 1) ? TMF_RSP_COMPLETE : TMF_RSP_NO_TASK;
        break;
    case 2:   /* ABORT TASK SET */
    case 4:   /* CLEAR TASK SET */
        if (!lun_ok) { rsp = TMF_RSP_NO_LUN; break; }
        abort_tasks(c, lun8, 0, 0);
        rsp = TMF_RSP_COMPLETE;
        break;
    case 3:   /* CLEAR ACA(NormACA=0 なので ACA は起きない)*/
        rsp = TMF_RSP_NOT_SUPPORTED;
        break;
    case 5:   /* LOGICAL UNIT RESET */
        if (!lun_ok) { rsp = TMF_RSP_NO_LUN; break; }
        abort_tasks(c, lun8, 0, 0);
        rsp = TMF_RSP_COMPLETE;
        break;
    case 6:   /* TARGET WARM RESET */
    case 7:   /* TARGET COLD RESET(応答の後に接続を畳む)*/
        abort_tasks(c, NULL, 0, 0);
        rsp = TMF_RSP_COMPLETE;
        cold = (fn == 7);
        break;
    case 14:  /* TASK REASSIGN(ERL=0 では持たない)*/
        rsp = TMF_RSP_REASSIGN_NS;
        break;
    default:
        rsp = TMF_RSP_REJECTED;
        break;
    }
    c->t->tmf++;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_TMF_RSP;
    bhs[1] = 0x80;
    bhs[2] = rsp;
    memcpy(&bhs[ISCSI_OFF_ITT], &b[ISCSI_OFF_ITT], 4);
    fill_sn(c, bhs, 1);
    if (send_pdu(c, bhs, NULL, 0) < 0) return -1;
    if (cold) conn_linger(c);
    return 0;
}

/* 受信した PDU 1 つの処理。戻り値 <0 = 接続を閉じる。 */
static int dispatch(iscsit_conn_t *c)
{
    const uint8_t op = c->bhs[0] & ISCSI_OP_MASK;
    c->pdu_rx++;
    if (!c->ffp) {
        if (op != ISCSI_OP_LOGIN) {
            uart_printf("[iscsit] 接続%u Login 中に op=0x%02x\n", c->idx, op);
            return -1;   /* Login 中は Login 以外を受けない(6.3)*/
        }
        return login_rx(c);
    }
    switch (op) {
    case ISCSI_OP_NOOP_OUT: return handle_nop(c);
    case ISCSI_OP_SCSI_CMD: return handle_scsi_cmd(c);
    case ISCSI_OP_TEXT:     return handle_text(c);
    case ISCSI_OP_LOGOUT:   return handle_logout(c);
    case ISCSI_OP_TMF_REQ:  return handle_tmf(c);
    case ISCSI_OP_DATA_OUT: return handle_data_out(c);
    case ISCSI_OP_LOGIN:
    case ISCSI_OP_SNACK:
    default:
        return send_reject(c, ISCSI_REJECT_PROTOCOL_ERR, c->bhs);
    }
}

/* ---------------------------------------------------------------- 受信の相 */

static void rx_expect(iscsit_conn_t *c, uint8_t ph, uint8_t *dst, uint32_t n)
{
    c->ph = ph;
    c->rx_dst = dst;
    c->want = n;
    c->got = 0;
}

/* BHS の後の相へ: AHS -> ヘッダダイジェスト -> データ -> データダイジェスト -> 処理。
 * 戻り値: 0 = 次の相を待つ / 1 = 処理まで来た */
static int rx_next_after(iscsit_conn_t *c, uint8_t done)
{
    if (done < PH_AHS && c->bhs[ISCSI_OFF_AHSLEN] != 0) {
        rx_expect(c, PH_AHS, c->ahs, (uint32_t)c->bhs[ISCSI_OFF_AHSLEN] * 4u);
        return 0;
    }
    if (done < PH_HDGST && c->hd) {
        rx_expect(c, PH_HDGST, c->dgst, 4);
        return 0;
    }
    if (done < PH_DATA && c->dlen) {
        rx_expect(c, PH_DATA, c->data_dst, c->dlen);
        return 0;
    }
    if (done < PH_PAD && c->dpad != c->dlen) {
        rx_expect(c, PH_PAD, c->pad, c->dpad - c->dlen);   /* パディングは行き先へ書かない */
        return 0;
    }
    if (done < PH_DDGST && c->dd && c->dlen) {
        rx_expect(c, PH_DDGST, c->dgst, 4);
        return 0;
    }
    return 1;
}

/* 1 歩進める。戻り値 1 = 進んだ / 0 = 届いていない / -1 = 閉じる */
static int rx_step(iscsit_conn_t *c)
{
    if (c->got < c->want) {
        const int n = tcp_recv_no_ack(&c->tcp, c->rx_dst + c->got, c->want - c->got, 0u);
        if (n == 0) { conn_close(c, "相手が閉じた"); return -1; }
        if (n < 0) {
            if (c->tcp.state == TCP_CLOSED) { conn_close(c, "接続が切れた"); return -1; }
            return 0;
        }
        c->got += (uint32_t)n;
        if (c->got < c->want) return 1;
    }
    int ready = 0;
    switch (c->ph) {
    case PH_BHS: {
        c->dlen = iscsi_be24(&c->bhs[ISCSI_OFF_DSL]);
        c->dpad = (c->dlen + 3u) & ~3u;
        const uint32_t limit = c->ffp ? c->neg.p.max_recv_dsl : ISCSI_LOGIN_MAX_DSL;
        if (c->dlen > limit) {
            uart_printf("[iscsit] 接続%u データが長すぎる(%u > %u)\n", c->idx, c->dlen, limit);
            conn_close(c, "長すぎる PDU");
            return -1;
        }
        /* データの行き先。Data-Out はタスクの書き込み先(RAM ディスク)へ直接受ける
         * (ヘッダダイジェストが合わなければその前に閉じるので、行き先を先に決めてよい)。 */
        c->cur_task = NULL;
        c->data_dst = c->data;
        if (c->ffp && (c->bhs[0] & ISCSI_OP_MASK) == ISCSI_OP_DATA_OUT) dataout_route(c);
        ready = rx_next_after(c, PH_BHS);
        break;
    }
    case PH_AHS:
        ready = rx_next_after(c, PH_AHS);
        break;
    case PH_HDGST: {
        uint32_t crc = crc32c(0xFFFFFFFFu, c->bhs, ISCSI_BHS_LEN);
        const uint32_t ahs = (uint32_t)c->bhs[ISCSI_OFF_AHSLEN] * 4u;
        if (ahs) crc = crc32c(crc, c->ahs, ahs);
        if (~crc != iscsi_get_le32(c->dgst)) {
            /* ヘッダが壊れていれば次の PDU の位置が分からない。ERL=0 なので接続を閉じる
             * (LIO と同じ。段階 0 の iscsi_probe.py hdigest)。 */
            c->t->hdgst_err++;
            conn_close(c, "ヘッダダイジェストが合わない");
            return -1;
        }
        ready = rx_next_after(c, PH_HDGST);
        break;
    }
    case PH_DATA:
        ready = rx_next_after(c, PH_DATA);
        break;
    case PH_PAD:
        ready = rx_next_after(c, PH_PAD);
        break;
    case PH_DDGST: {
        uint32_t crc = crc32c(0xFFFFFFFFu, c->data_dst, c->dlen);
        if (c->dpad != c->dlen) crc = crc32c(crc, c->pad, c->dpad - c->dlen);
        if (~crc != iscsi_get_le32(c->dgst)) {
            /* RFC 7143 7.8: データダイジェストが合わない PDU には Reject(Data Digest Error)で
             * 答えて捨てる。ERL=0 では立て直せないので、Reject を届けてから接続を畳む
             * (LIO も即時データでは Reject してから閉じる。Data-Out / NOP は黙って閉じる)。
             * **Data-Out はダイジェストを確かめる前に RAM ディスクへ書いている** -- 接続が
             * 落ちたコマンドはイニシエータが書き直す。 */
            c->t->ddgst_err++;
            uart_printf("[iscsit] 接続%u データダイジェストが合わない(op=0x%02x、%u バイト)\n",
                        c->idx, c->bhs[0] & ISCSI_OP_MASK, c->dlen);
            send_reject(c, ISCSI_REJECT_DIGEST_ERR, c->bhs);
            conn_linger(c);
            return -1;
        }
        ready = 1;
        break;
    }
    }
    if (!ready) return 1;
    const int r = dispatch(c);
    if (c->st != CS_RX) return -1;   /* dispatch の中で linger / close へ移った */
    rx_expect(c, PH_BHS, c->bhs, ISCSI_BHS_LEN);
    if (r < 0) { conn_close(c, "処理で失敗"); return -1; }
    return 1;
}

/* ---------------------------------------------------------------- 生存確認と Async */

/* NOP-In を打つまでの無通信の時間と、応答を待つ時間(`iscsit nopin <秒> [待つ秒]`、0 = 打たない)。
 * LIO の既定(nopin_timeout / nopin_response_timeout)と同じ 15 秒ずつ。 */
volatile uint32_t g_iscsit_nopin_ms = 15000u;
volatile uint32_t g_iscsit_nopin_wait_ms = 15000u;

/*=================================================================
 * 生存確認(RFC 7143 11.19)。ケーブル抜けや相手のクラッシュでは FIN が来ないので、
 * 無通信が続いたら NOP-In(ITT = 0xFFFFFFFF、TTT = こちらの印)を打ち、同じ TTT の
 * NOP-Out が返らなければ畳む。**受けた PDU の数が進んでいれば相手は生きている**ので
 * 打たない(NVMe の Keep Alive で使った「既存のカウンタを冷たい経路から見る」手)。
 * 戻り値 -1 = 応答が無かった(呼び出し側が閉じる)。
 * ===============================================================*/
static int keepalive(iscsit_conn_t *c)
{
    if (!g_iscsit_nopin_ms) return 0;
    const uint64_t now = timer_now();
    if (c->pdu_rx != c->seen_rx) {
        c->seen_rx = c->pdu_rx;
        c->idle_since = now;
        c->nop_ttt = 0;   /* 何か届いた = 生きている */
        return 0;
    }
    if (c->nop_ttt) {
        if (!timeout_ms(c->nop_sent_at, g_iscsit_nopin_wait_ms)) return 0;
        c->t->nopin_timeout++;
        return -1;
    }
    if (!c->idle_since) c->idle_since = now;
    if (!timeout_ms(c->idle_since, g_iscsit_nopin_ms)) return 0;
    static uint32_t gen;
    c->nop_ttt = 0x4E000000u | (++gen & 0xFFFFu);
    c->nop_sent_at = now;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_NOOP_IN;
    bhs[1] = 0x80;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], ISCSI_RSVD_TAG);
    iscsi_put32(&bhs[ISCSI_OFF_TTT], c->nop_ttt);
    fill_sn(c, bhs, 0);   /* ITT = 0xFFFFFFFF の NOP-In は StatSN を進めない */
    c->t->nopin_sent++;
    return send_pdu(c, bhs, NULL, 0) < 0 ? -1 : 0;
}

/* Async Message(11.9)の「ターゲットがログアウトを求める」(AsyncEvent = 1)。 */
static void send_async_logout(iscsit_conn_t *c)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_ASYNC;
    bhs[1] = 0x80;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], ISCSI_RSVD_TAG);
    fill_sn(c, bhs, 1);
    bhs[36] = 1;                     /* AsyncEvent: ログアウトの要求 */
    iscsi_put16(&bhs[42], 10);       /* Parameter3: この秒数のうちにログアウトすること */
    c->t->async_sent++;
    uart_printf("[iscsit] 接続%u にログアウトを求める(Async Message)\n", c->idx);
    (void)send_pdu(c, bhs, NULL, 0);
}

void iscsit_request_logout(unsigned idx)
{
    if (idx < ISCSIT_MAX_CONNS && s_t.conn[idx].st == CS_RX && s_t.conn[idx].ffp) s_t.conn[idx].async_req = 1;
    else uart_printf("iscsit: 接続%u はログイン済みでない\n", idx);
}

/* ---------------------------------------------------------------- ジョブ */

static job_result_t iscsit_conn_step(job_t *self)
{
    iscsit_conn_t *c = (iscsit_conn_t *)self->ctx;
    iscsit_ctx_t *t = c->t;
    job_unpark(self);

    switch (c->st) {
    case CS_ARM:
        if (t->arm_owner >= 0) {
            job_park(self, NULL, NULL);   /* 先客が accept して手放すまで眠る */
            return JOB_WAITING;
        }
        t->arm_owner = (int)c->idx;
        conn_reset(c);
        tcp_accept_begin(t->listener, &c->tcp);
        c->st = CS_ACCEPT_WAIT;
        return JOB_WAITING;

    case CS_ACCEPT_WAIT:
        if (t->arm_owner != (int)c->idx) return JOB_WAITING;
        if (tcp_accept_ready_poll(t->listener)) {
            t->arm_owner = -1;   /* 受け皿を次のジョブへ譲る */
            job_pin_to_core(self, c->tcp.owner_core);
            c->t_accept = timer_now();
            c->st = CS_RX;
            tcp_set_ack_piggyback(&c->tcp, g_iscsit_ackpiggy ? 1 : 0);
            uart_printf("[iscsit] 接続%u 確立(core%u)\n", c->idx, c->tcp.owner_core);
        }
        return JOB_WAITING;

    case CS_RX:
        if (c->kill) { conn_close(c, "session reinstatement で捨てた"); return JOB_WAITING; }
        if (!c->ffp && timeout_ms(c->t_accept, ISCSIT_LOGIN_TIMEOUT_MS)) {
            conn_close(c, "Login が終わらない");
            return JOB_WAITING;
        }
        for (int i = 0; i < 8; i++) {
            const int r = rx_step(c);
            if (r <= 0) break;
        }
        /* 応答へ相乗りできなかった ACK を返す(`iscsit ackpiggy on` のときだけ借りがある)。 */
        if (c->st == CS_RX) (void)tcp_ack_flush(&c->tcp);
        if (c->st == CS_RX && c->ffp) {
            if (c->async_req) { c->async_req = 0; send_async_logout(c); }
            if ((++c->ticks & 1023u) == 0 && keepalive(c) < 0) conn_close(c, "NOP-In に応答が無い");
        }
        return JOB_WAITING;

    case CS_LINGER: {
        /* 送った応答が届くまで閉じない。相手が閉じた(FIN)か、時間切れで閉じる。 */
        uint8_t sink[64];
        const int n = tcp_recv_no_ack(&c->tcp, sink, sizeof(sink), 0u);
        if (n == 0 || c->tcp.state == TCP_CLOSED || c->tcp.state == TCP_CLOSE_WAIT ||
            timeout_ms(c->t_linger, ISCSIT_LINGER_MS)) {
            conn_close(c, "ログアウト / 失敗の応答の後");
        }
        return JOB_WAITING;
    }
    }
    return JOB_WAITING;
}

/* ---------------------------------------------------------------- 公開 */

int iscsit_started(void) { return s_t.started; }

int iscsit_start(uint16_t port, netif_t *nif)
{
    if (s_t.started) {
        uart_printf("iscsit: 既に起動済み(port %u)\n", s_t.port);
        return -1;
    }
    if (job_active_count() + ISCSIT_MAX_CONNS > (unsigned)JOB_MAX) {
        uart_printf("iscsit: ジョブの空きが足りない\n");
        return -1;
    }
    const int l = tcp_listen(port, nif);
    if (l < 0) {
        uart_printf("iscsit: tcp_listen 失敗\n");
        return -1;
    }
    s_t.listener = l;
    s_t.port = port;
    s_t.nif = nif;
    s_t.arm_owner = -1;
    s_t.tsih_next = 0;
    if (!s_t.target_name[0]) memcpy(s_t.target_name, ISCSIT_DEFAULT_IQN, sizeof(ISCSIT_DEFAULT_IQN));
    s_t.pref.max_recv_dsl = ISCSIT_MAX_RECV_DSL;
    s_t.pref.first_burst = 65536u;
    s_t.pref.max_burst = 262144u;
    s_t.pref.max_outstanding_r2t = 1u;
    s_t.pref.initial_r2t = 1;
    s_t.pref.immediate_data = 1;
    s_t.pref.allow_crc32c = 1;
    s_t.pref.tpgt = 1;
    s_t.pref.target_alias = "vfio_nvme";
    for (unsigned i = 0; i < ISCSIT_MAX_CONNS; i++) {
        iscsit_conn_t *c = &s_t.conn[i];
        c->t = &s_t;
        c->idx = i;
        conn_reset(c);
        c->st = CS_ARM;
        c->job = job_spawn(iscsit_conn_step, c, "iscsit-conn");
        if (!c->job) {
            uart_printf("iscsit: job_spawn 失敗\n");
            return -1;
        }
        job_set_affinity(c->job, nif);
    }
    s_t.started = 1;
    return 0;
}

void iscsit_set_chap(const iscsi_chap_cfg_t *cfg)
{
    if (cfg) s_t.chap = *cfg;
    else memset(&s_t.chap, 0, sizeof(s_t.chap));
    s_t.pref.chap_required = s_t.chap.set ? 1 : 0;
}

void iscsit_stats_clear(void)
{
    s_t.logins_ok = s_t.logins_fail = s_t.discovery = s_t.reinstated = s_t.rejects = 0;
    s_t.hdgst_err = s_t.ddgst_err = s_t.window_drop = s_t.nop = s_t.logouts = 0;
    s_t.check_cond = s_t.r2t_sent = s_t.bad_dataout = 0;
    s_t.tmf = s_t.tasks_aborted = s_t.stale_dataout = s_t.nopin_sent = s_t.nopin_timeout = s_t.async_sent = 0;
    s_t.chap_ok = s_t.chap_fail = 0;
}

void iscsit_status(void)
{
    if (!s_t.started) {
        uart_printf("iscsit: 未起動(`iscsit [port]` で起動)\n");
        return;
    }
    uart_printf("iscsit: %s  port %u  window %u  MRDSL %u\n", s_t.target_name, s_t.port,
                ISCSIT_CMD_WINDOW, s_t.pref.max_recv_dsl);
    uart_printf("  ログイン 成功 %u(Discovery %u)/ 失敗 %u、ログアウト %u、reinstatement %u\n",
                s_t.logins_ok, s_t.discovery, s_t.logins_fail, s_t.logouts, s_t.reinstated);
    uart_printf("  Reject %u、NOP %u、窓の外 %u、ダイジェスト不一致 ヘッダ %u / データ %u\n",
                s_t.rejects, s_t.nop, s_t.window_drop, s_t.hdgst_err, s_t.ddgst_err);
    uart_printf("  CHECK CONDITION %u、R2T %u、合わない Data-Out %u\n",
                s_t.check_cond, s_t.r2t_sent, s_t.bad_dataout);
    uart_printf("  TMF %u(捨てたタスク %u、捨てたタスク宛ての Data-Out %u)、NOP-In %u(応答なしで畳んだ %u)、"
                "Async %u、生存確認 %u 秒 / 待ち %u 秒\n",
                s_t.tmf, s_t.tasks_aborted, s_t.stale_dataout, s_t.nopin_sent, s_t.nopin_timeout,
                s_t.async_sent, g_iscsit_nopin_ms / 1000u, g_iscsit_nopin_wait_ms / 1000u);
    if (s_t.chap.set)
        uart_printf("  CHAP: 求める(user %s%s%s)成功 %u / 応答が合わない %u\n", s_t.chap.user,
                    s_t.chap.mutual ? "、双方向 " : "", s_t.chap.mutual ? s_t.chap.muser : "",
                    s_t.chap_ok, s_t.chap_fail);
    else
        uart_printf("  CHAP: 求めない(AuthMethod=None)\n");
    for (unsigned l = 0; l < SCSI_MAX_LUNS; l++) {
        const scsi_lun_t *L = scsi_get_lun(l);
        if (L) uart_printf("  LUN %u: %llu ブロック x %u(%s)\n", l, (unsigned long long)L->nblocks,
                           SCSI_BLOCK_SIZE, L->serial);
    }
    for (unsigned i = 0; i < ISCSIT_MAX_CONNS; i++) {
        iscsit_conn_t *c = &s_t.conn[i];
        if (c->st != CS_RX && c->st != CS_LINGER) {
            uart_printf("  接続%u: %s\n", i, CS_NAME[c->st]);
            continue;
        }
        uart_printf("  接続%u: %s %s %s tsih=%u ExpCmdSN=%u StatSN=%u PDU 受%u/送%u SCSI %u digest=%s/%s "
                    "読 %llu / 書 %llu バイト\n",
                    i, CS_NAME[c->st], c->ffp ? (c->neg.p.discovery ? "Discovery" : "Normal") : "login",
                    c->neg.initiator_name[0] ? c->neg.initiator_name : "-", c->tsih, c->exp_cmd_sn,
                    c->stat_sn, c->pdu_rx, c->pdu_tx, c->scsi_cmds, c->hd ? "CRC32C" : "None",
                    c->dd ? "CRC32C" : "None", (unsigned long long)c->bytes_read,
                    (unsigned long long)c->bytes_written);
    }
}
