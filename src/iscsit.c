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
#include "iscsit_iser.h"
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
    uint8_t   aborting;       /* ABORT / CLEAR TASK SET で捨てる。出した R2T の Data-Out(F=1)を待っている */
    uint8_t   crc_err;        /* Data-Out のデータダイジェストが合わなかった(RFC 7143 7.8 (b))*/
    scsi_result_t vr;         /* VERIFY の比べ方 */
} iscsit_task_t;

#define ISCSIT_MAX_TASKS ISCSIT_CMD_WINDOW

/*=================================================================
 * CmdSN の先回り(RFC 7143 4.2.2.1)。窓の中だが ExpCmdSN より先の CmdSN のコマンドは、
 * 穴が埋まるまで**順番どおりに保留**する(捨てると、ERL=0 のイニシエータは送り直さないので
 * そのコマンドは永久に返らない)。穴ができるのは、こちらが Reject したコマンドの CmdSN を
 * 受け取ったことにしないとき(7.2)と、イニシエータが ABORT TASK の RefCmdSN で穴を埋めるとき
 * くらいで、**普段は空**。ホットパスの費用は CmdSN が ExpCmdSN と等しいかの比較 1 つと、
 * 処理の後の hold_n の確認 1 つだけ。
 * 保留の中身(BHS + AHS + 即時データ)は接続ごとの 64KiB の作業場所へ写す(先頭から詰め、保留が
 * 空になったら先頭へ戻す)。入りきらないものは捨てて数える(window_drop / hold_drop)。
 * phantom = 「受け取ったことにする」印(ABORT TASK が保留中のコマンドを消したときと、
 * RefCmdSN で穴を埋めたとき。11.5.1 の b))。
 * ===============================================================*/
#define ISCSIT_HOLD_MAX   8u
#define ISCSIT_HOLD_DATA  65536u
#define ISCSIT_HOLD_AHS   64u
typedef struct {
    uint8_t  used, phantom, ahslen;
    uint32_t sn, dlen, doff;
    uint8_t  bhs[ISCSI_BHS_LEN];
    uint8_t  ahs[ISCSIT_HOLD_AHS];
} iscsit_hold_t;

/* 他のセッション(別のコアで動くジョブ)への頼み(xreq)。下位 16 ビット = 対象の LUN。 */
#define ISCSIT_XREQ_LUN_MASK  0x0000FFFFu
#define ISCSIT_XREQ_UA_IF_ABORTED 0x00010000u   /* 捨てた仕事があったときだけ UA を立てる(CLEAR TASK SET)*/
/* ABORT / CLEAR TASK SET が R2T の答えを待つ上限(イニシエータが答えなかったときの逃げ道)。 */
#define ISCSIT_TMF_WAIT_MS    5000u
/* session reinstatement で古いセッションが止まるのを待つ上限。 */
#define ISCSIT_REINST_WAIT_MS 2000u

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
    uint8_t       ddgst_bad;      /* この PDU のデータダイジェストが合わなかった(Data-Out だけ処理へ回す)*/
    /* ---- 他のセッションからの頼み(LU / TARGET RESET、CLEAR TASK SET。自分のジョブが処理する)---- */
    volatile uint32_t xreq;
    volatile uint16_t xreq_ua;      /* asc << 8 | ascq */
    scsi_ua_t     ua;               /* この I_T nexus の Unit Attention */
    /* ---- TMF の応答待ち(ABORT / CLEAR TASK SET が R2T の答えを待つ。11.5.1)---- */
    uint8_t       tmf_wait;
    uint32_t      tmf_itt;
    uint64_t      tmf_since;
    /* ---- session reinstatement の待ち(6.3.5。古いセッションが止まってから最後の応答を送る)---- */
    uint8_t       reinst_wait;
    uint8_t       reinst_flags;
    uint32_t      reinst_mask;      /* 止めるのを待っている接続のビット */
    uint32_t      reinst_itt, reinst_len;
    uint64_t      reinst_since;
    /* ---- Text の続き(11.10 / 11.11)---- */
    uint32_t      txt_ttt;          /* こちらが出した TTT(0 = 続きの無い状態)*/
    uint32_t      txt_itt;
    uint32_t      txt_ttt_gen;
    uint32_t      txt_out_len, txt_out_off;
    uint8_t       txt_out[4096];
    /* ---- CmdSN の保留 ---- */
    uint8_t       hold_n;
    uint32_t      hold_used, hold_drop;
    iscsit_hold_t hold[ISCSIT_HOLD_MAX];
    uint8_t       hold_data[ISCSIT_HOLD_DATA];
    /* ターゲットからの生存確認(NOP-In)。 */
    uint32_t      nop_ttt;        /* 0 = 出していない */
    uint64_t      nop_sent_at;
    uint64_t      last_check;
    uint32_t      seen_rx;        /* 前に見たときの pdu_rx(進んでいれば相手は生きている)*/
    uint64_t      idle_since;
    uint32_t      ticks;
    netif_t      *tx_nif;         /* 送るポート(accept したときに決める)。送信キューの空きを見る */
    uint64_t      tx_yield;       /* 送信キューの空きが無くて順番を譲った回数 */
    uint64_t      tx_win_yield;   /* TCP の窓が足りなくて順番を譲った回数 */
    volatile int  async_req;      /* `iscsit logout <n>` が立てる(送るのはこの接続のジョブ)*/
    uint16_t      task_gen;
    iscsit_task_t task[ISCSIT_MAX_TASKS];
    uint8_t       cmdbuf[4096];   /* INQUIRY などの応答を組み立てる場所 */
    uint64_t      bytes_read, bytes_written;
    /* ---- Login / セッション ---- */
    uint8_t       ffp;             /* Full Feature Phase */
    uint8_t       ackpiggy;        /* tcp_set_ack_piggyback() に渡した値 */
    uint8_t       login_started;
    iscsi_login_state_t lst;       /* ログイン要求の BHS の検査(iscsi_login_check)*/
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
    volatile uint32_t held, crc_fail, login_reject;
    iscsit_conn_t conn[ISCSIT_MAX_CONNS];
};

static iscsit_ctx_t s_t;

/* 次に送る N 個のヘッダ / データダイジェストをわざと壊す(`iscsit corrupt h|d N`)。
 * 相手(open-iscsi)が壊れたダイジェストを見つけて接続を張り直すことの確認に使う。 */
volatile uint32_t g_iscsit_corrupt_hdgst;
volatile uint32_t g_iscsit_corrupt_ddgst;
/* 受信の ACK を応答の PDU へ相乗りさせる(NVMe/TCP の `ackpiggy` と同じ仕組み)。張ったままの接続にも効く。 */
volatile uint32_t g_iscsit_ackpiggy;
/* 送信キューの空きがこれ未満なら、受信した PDU の処理を次の周回へ回す(下の CS_RX 参照)。
 * NVMe/TCP ターゲットの NVMET_TX_ROOM_MIN と同じ(送信キューは 8 枠、SPEC 27.15)。 */
#define ISCSIT_TX_ROOM_MIN 4u
/* TCP の送れる量(相手の受信窓・cwnd の残り)がこれ未満でも同じく譲る。読み出し 1 個(256KiB)を
 * 送り切れないと、送信は途中で窓が空くのをその場で待つ。**窓(相手の窓と cwnd の小さいほう)が
 * 小さいときは窓の半分まで下げる** -- 確立直後の cwnd は数 KB なので、256KiB を待つと一度も送れず
 * cwnd も育たない(実際にそれで止まった)。 */
#define ISCSIT_TX_WIN_MIN  262144u
/* `iscsit txyield off|on|win|short`。0 = off(直す前の挙動、陰性対照)/ 1 = on(送信キューの空きだけ見る)/
 * 2 = win(既定。TCP の窓も見る)/ 3 = short(win に加えて、短経路の再送用の枠が半分を切っても譲る)。 */
volatile uint32_t g_iscsit_tx_yield = 2u;

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

/* Reject(11.17)。データは断った PDU の**ヘッダ全体 = BHS + AHS**(11.17.4。ダイジェストは含めない)。
 * bad_bhs が受信中の PDU(c->bhs)なら c->ahs を続ける。 */
static int send_reject(iscsit_conn_t *c, uint8_t reason, const uint8_t *bad_bhs)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    uint8_t hdr[ISCSI_BHS_LEN + sizeof(c->ahs)];
    uint32_t hl = ISCSI_BHS_LEN;
    memcpy(hdr, bad_bhs, ISCSI_BHS_LEN);
    if (bad_bhs == c->bhs && c->bhs[ISCSI_OFF_AHSLEN]) {
        const uint32_t al = (uint32_t)c->bhs[ISCSI_OFF_AHSLEN] * 4u;
        memcpy(&hdr[ISCSI_BHS_LEN], c->ahs, al);
        hl += al;
    }
    bhs[0] = ISCSI_OP_REJECT;
    bhs[1] = 0x80;
    bhs[2] = reason;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], ISCSI_RSVD_TAG);
    fill_sn(c, bhs, 1);
    c->t->rejects++;
    return send_pdu(c, bhs, hdr, hl);
}

/* **断ったコマンドの CmdSN は受け取ったことにしない**(RFC 7143 7.2: 「CmdSN の穴があるものとし、
 * イニシエータが同じ CmdSN で送り直すか ABORT TASK で埋める」)。cmdsn_accept() で進めた ExpCmdSN を
 * 戻してから Reject を送る(Reject の ExpCmdSN / MaxCmdSN も戻した値になる)。Immediate は CmdSN を
 * 進めないので戻さない。 */
static int send_reject_cmd(iscsit_conn_t *c, uint8_t reason, const uint8_t *b)
{
    if (!(b[0] & ISCSI_OP_IMMEDIATE)) {
        const uint32_t sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);
        if (sn + 1u == c->exp_cmd_sn) c->exp_cmd_sn = sn;
    }
    return send_reject(c, reason, b);
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
    c->tx_nif = NULL;
    c->tx_yield = c->tx_win_yield = 0;
    c->data_dst = c->data;
    c->cur_task = NULL;
    c->dataout_stale = 0;
    c->ddgst_bad = 0;
    c->nop_ttt = 0;
    c->idle_since = 0;
    c->seen_rx = 0;
    c->ticks = 0;
    c->async_req = 0;
    c->auth_st = 0;
    memset(&c->lst, 0, sizeof(c->lst));
    c->xreq = 0;
    memset(&c->ua, 0, sizeof(c->ua));
    c->tmf_wait = 0;
    c->reinst_wait = 0;
    c->reinst_mask = 0;
    c->txt_ttt = 0;
    c->txt_out_len = c->txt_out_off = 0;
    c->hold_n = 0;
    c->hold_used = 0;
    for (unsigned i = 0; i < ISCSIT_HOLD_MAX; i++) c->hold[i].used = 0;
    if (c->job) job_set_affinity(c->job, c->t);   /* ログインの間は接続どうしで排他する */
    for (unsigned i = 0; i < ISCSIT_MAX_TASKS; i++) { c->task[i].in_use = 0; c->task[i].aborting = 0; }
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
    /* 段に合わない CHAP の鍵(挑戦を出す前の CHAP_N / CHAP_R、挑戦を出した後の CHAP_A など)は
     * Initiator error(RFC 7143 12.1.3 の手順の順番、6.2)。 */
    const int resp_keys = n->got_chap_n || n->got_chap_r || n->got_chap_i || n->got_chap_c;
    switch (c->auth_st) {
    case 0:
        if (!n->auth_chap) { login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "AuthMethod で CHAP を選べない"); return -1; }
        if (resp_keys) { login_fail(c, ISCSI_LS_INIT_ERR, itt, csg, "挑戦を出す前に CHAP_N / R / I / C が来た"); return -1; }
        c->auth_st = 1;
        if (!n->got_chap_a) return 0;   /* 普通は次の要求で CHAP_A が来る */
        __attribute__((fallthrough));   /* 同じ要求に CHAP_A が載っていた */
    case 1: {
        /* AuthMethod=CHAP に決まった次の要求には CHAP_A が要る。**来なければ待ち続けずに断る**
         * (Missing Parameter。以前はログインの時間切れ 15 秒まで黙って待っていた)。 */
        if (!n->got_chap_a) { login_fail(c, ISCSI_LS_MISSING_PARAM, itt, csg, "CHAP_A が来ない"); return -1; }
        if (resp_keys) { login_fail(c, ISCSI_LS_INIT_ERR, itt, csg, "挑戦を出す前に CHAP_N / R / I / C が来た"); return -1; }
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
        if (n->got_chap_a) { login_fail(c, ISCSI_LS_INIT_ERR, itt, csg, "挑戦を出した後に CHAP_A が来た"); return -1; }
        /* 答えが無いのは「足りない鍵」(Missing Parameter、11.13.5 の 0x0207)。認証の失敗ではない。 */
        if (!n->got_chap_n || !n->got_chap_r) { login_fail(c, ISCSI_LS_MISSING_PARAM, itt, csg, "CHAP_N / CHAP_R が無い"); return -1; }
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
        /* **受けた答えが、こちらが同じ挑戦に自分の秘密(双方向でこちらが答えるときの秘密)で答えた値と
         * 等しければ失敗**(RFC 7143 12.1.3。同じ秘密が両方向に使われていることの検出。設定の検査
         * iscsi_chap_cfg_check() をすり抜けた場合の受信側の守り)。 */
        if (cfg->mutual && iscsi_chap_is_own_response(c->chap_alg, c->chap_id, cfg->msecret, cfg->mlen,
                                                      c->chap_chal, c->chap_clen, got, (uint32_t)gl)) {
            c->t->chap_fail++;
            login_fail(c, ISCSI_LS_AUTH_FAILED, itt, csg, "相手の答えがこちらの秘密での答えと同じ(両方向に同じ秘密)");
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

/* 最後の Login 応答を送り、Full Feature Phase へ移る(session reinstatement の待ちの後にも呼ぶ)。 */
static int login_finish(iscsit_conn_t *c, uint8_t rfl, uint32_t itt, const uint8_t *rsp, uint32_t len)
{
    iscsi_neg_t *n = &c->neg;
    if (send_login_rsp(c, rfl, ISCSI_LS_SUCCESS, itt, rsp, len) < 0) return -1;
    c->ffp = 1;
    /* ここから先で共有の状態に触るのは統計の数だけなので、接続どうしの排他を外す
     * (2 ポートで受けるとき、別々のポートの接続を別々のコアで同時に動かせる)。
     * ログイン中は TSIH の採番と session reinstatement の走査があるので、
     * 排他したまま(conn_reset() が戻す)。 */
    job_set_affinity(c->job, NULL);
    c->hd = n->p.hdgst;   /* **応答を送った後から**ダイジェストが付く */
    c->dd = n->p.ddgst;
    c->t->logins_ok++;
    if (n->p.discovery) c->t->discovery++;
    uart_printf("[iscsit] 接続%u ログイン完了: %s %s isid=%02x%02x%02x%02x%02x%02x tsih=%u "
                "digest=%s/%s MRDSL 受=%u 送=%u burst=%u/%u R2T=%s Imm=%s level=%u\n",
                c->idx, n->p.discovery ? "Discovery" : "Normal", n->initiator_name,
                c->isid[0], c->isid[1], c->isid[2], c->isid[3], c->isid[4], c->isid[5], c->tsih,
                c->hd ? "CRC32C" : "None", c->dd ? "CRC32C" : "None",
                n->p.max_recv_dsl, n->p.max_xmit_dsl, n->p.first_burst, n->p.max_burst,
                n->p.initial_r2t ? "Yes" : "No", n->p.immediate_data ? "Yes" : "No", n->p.proto_level);
    return 0;
}

/*=================================================================
 * session reinstatement(RFC 7143 6.3.5)。同じ InitiatorName・同じ ISID(・同じ種類)の古いセッションを
 * 捨てる。**古いセッションの仕事を止め、止まったことを確かめてから**新しいセッションの最後の Login
 * 応答を送る(「新しいセッションの最初のコマンドより前に古いセッションの仕事が終わっている」こと)。
 * 古いセッションは別のコアで動くジョブなので、kill を立てて、そのジョブが自分で閉じる(conn_reset()
 * で kill が 0 に戻る)のを reinst_poll() で待つ。
 * **Discovery セッションも作り直す**(7.4.2 の「同じ ISID のセッション」に種類の区別は無い)。ただし
 * 種類の違うセッションは別のもの(TargetName が無い Discovery と Normal を 1 つとみなすと、open-iscsi の
 * Discovery が通常セッションを殺しうる)なので、種類と TargetName も一致するものだけ。
 * 戻り値 = 止めるのを待つ接続のビット(0 = 無い)。
 * ===============================================================*/
static uint32_t reinstate_begin(iscsit_conn_t *c)
{
    iscsi_neg_t *n = &c->neg;
    uint32_t mask = 0;
    for (unsigned i = 0; i < ISCSIT_MAX_CONNS; i++) {
        iscsit_conn_t *o = &c->t->conn[i];
        if (o == c || o->st != CS_RX || !o->ffp) continue;
        if (o->neg.p.discovery != n->p.discovery) continue;
        if (memcmp(o->isid, c->isid, 6) != 0 || strcmp(o->neg.initiator_name, n->initiator_name) != 0) continue;
        if (!n->p.discovery && strcmp(o->neg.target_name, n->target_name) != 0) continue;
        o->kill = 1;
        mask |= 1u << i;
        c->t->reinstated++;
        uart_printf("[iscsit] 接続%u: 同じ ISID の古い%sセッション(接続%u)を止めてから応答する\n",
                    c->idx, n->p.discovery ? " Discovery " : "", o->idx);
    }
    return mask;
}

/* 戻り値 1 = 待ちが終わった(応答を送った / 断った)/ 0 = まだ待つ / -1 = 閉じる */
static int reinst_poll(iscsit_conn_t *c)
{
    for (unsigned i = 0; i < ISCSIT_MAX_CONNS; i++) {
        if (!(c->reinst_mask & (1u << i))) continue;
        const iscsit_conn_t *o = &c->t->conn[i];
        /* conn_close() -> conn_reset() が kill を 0 に戻す = 古いセッションのジョブが仕事を捨てて閉じた。 */
        if (!o->kill || o->st != CS_RX) c->reinst_mask &= ~(1u << i);
    }
    if (c->reinst_mask) {
        if (!timeout_ms(c->reinst_since, ISCSIT_REINST_WAIT_MS)) return 0;
        /* 止まったことを確かめられない。新しいセッションを受けない(6.3.5: 古い仕事が残ったまま
         * 新しいセッションを始めない)。 */
        c->reinst_wait = 0;
        login_fail(c, ISCSI_LS_TARGET_ERR, c->reinst_itt, ISCSI_STAGE_OP, "古いセッションが止まらない");
        return 1;
    }
    c->reinst_wait = 0;
    return login_finish(c, c->reinst_flags, c->reinst_itt, c->text, c->reinst_len) < 0 ? -1 : 1;
}

/*=================================================================
 * Login 要求 1 つ(RFC 7143 6.3 / 11.12)。
 *   - 最初の要求で ISID / TSIH / CID / ITT / 段 / CmdSN を控え、版を確かめる。以後の要求で
 *     それらが変わる・C と T が両方立つ・CSG が今の段と違う、を断る(iscsi_login_check())。
 *   - C ビット: 続きを溜めて、空の応答で続きを求める。
 *   - T ビット: 相手の求める段へ移ることに同意する(CHAP の途中は引き留める)。
 *   - NSG=FFP への移行で名前を確かめ、TSIH を振り、古いセッションを止めてから最後の応答を送り、
 *     ダイジェストを有効にする。
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
    const char *why;
    const uint16_t ls = iscsi_login_check(&c->lst, b, &why);
    if (ls) return login_fail(c, ls, itt, csg, why);

    /* 鍵を溜める(C ビットの続きも含めて 1 つの並びとして解釈する)。**黙って切らない**。 */
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
    iscsi_neg_t *n = &c->neg;
    if (rl < 0) return login_fail(c, n->fail_status ? n->fail_status : ISCSI_LS_INIT_ERR, itt, csg,
                                  n->err ? n->err : "鍵の形式が不正");
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
    const int chap_keys = n->got_chap_a || n->got_chap_i || n->got_chap_c || n->got_chap_n || n->got_chap_r;
    if (csg == ISCSI_STAGE_SEC) {
        if (chap_req) {
            const int r = chap_step(c, rsp, sizeof(rsp), &pos, itt, csg);
            n->got_chap_a = n->got_chap_i = n->got_chap_c = n->got_chap_n = n->got_chap_r = 0;
            if (r < 0) return 0;          /* 断った(chap_step が応答を送った)*/
            if (r == 0) agree = 0;        /* 手順の途中: 相手が移行を求めても引き留める */
        } else {
            /* CHAP を使わない(AuthMethod=None)のに CHAP の鍵が来た = 段に合わない鍵。 */
            if (chap_keys) return login_fail(c, ISCSI_LS_INIT_ERR, itt, csg, "CHAP を使わないのに CHAP の鍵が来た");
            if (T && !n->auth_none)
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
    if (agree) iscsi_login_transit(&c->lst, nsg);
    if (!to_ffp) return send_login_rsp(c, rfl, ISCSI_LS_SUCCESS, itt, rsp, pos);

    /* ---- Full Feature Phase へ。古いセッションがあれば止まるのを待ってから最後の応答を送る ---- */
    const uint32_t mask = reinstate_begin(c);
    if (mask) {
        memcpy(c->text, rsp, pos);   /* 待つ間、応答を控えておく(c->text はもう使わない)*/
        c->reinst_len = pos;
        c->reinst_flags = rfl;
        c->reinst_itt = itt;
        c->reinst_mask = mask;
        c->reinst_since = timer_now();
        c->reinst_wait = 1;
        return 0;
    }
    return login_finish(c, rfl, itt, rsp, pos);
}

/* ---------------------------------------------------------------- Full Feature Phase */

/* 受信中の PDU(c->bhs / c->ahs / c->data)を保留へ写す。 */
static void cmdsn_hold(iscsit_conn_t *c, uint32_t sn)
{
    const uint32_t ahs = (uint32_t)c->bhs[ISCSI_OFF_AHSLEN] * 4u;
    iscsit_hold_t *h = NULL;
    for (unsigned i = 0; i < ISCSIT_HOLD_MAX; i++) {
        if (c->hold[i].used && c->hold[i].sn == sn) { c->t->window_drop++; return; }   /* 窓の中の重複は捨てる */
        if (!c->hold[i].used && !h) h = &c->hold[i];
    }
    if (!h || ahs > ISCSIT_HOLD_AHS || c->hold_used + c->dlen > ISCSIT_HOLD_DATA) {
        /* 入りきらない。捨てるとこのコマンドは返らないので、表示して数える(普段は起きない)。 */
        c->hold_drop++;
        c->t->window_drop++;
        uart_printf("[iscsit] 接続%u CmdSN %u(ExpCmdSN %u)を保留できず捨てた\n", c->idx, sn, c->exp_cmd_sn);
        return;
    }
    h->used = 1;
    h->phantom = 0;
    h->sn = sn;
    h->ahslen = (uint8_t)ahs;
    h->dlen = c->dlen;
    h->doff = c->hold_used;
    memcpy(h->bhs, c->bhs, ISCSI_BHS_LEN);
    if (ahs) memcpy(h->ahs, c->ahs, ahs);
    if (c->dlen) memcpy(&c->hold_data[h->doff], c->data, c->dlen);
    c->hold_used += (c->dlen + 63u) & ~63u;
    c->hold_n++;
    c->t->held++;
}

/* CmdSN を「受け取ったことにする」(ABORT TASK の RefCmdSN、11.5.1 の b))。sn が ExpCmdSN なら
 * そのまま進め、先なら印(phantom)を保留に置く。 */
static void cmdsn_plug(iscsit_conn_t *c, uint32_t sn)
{
    if (sn == c->exp_cmd_sn) { c->exp_cmd_sn++; return; }
    for (unsigned i = 0; i < ISCSIT_HOLD_MAX; i++) {
        iscsit_hold_t *h = &c->hold[i];
        if (h->used && h->sn == sn) { h->phantom = 1; return; }
    }
    for (unsigned i = 0; i < ISCSIT_HOLD_MAX; i++) {
        iscsit_hold_t *h = &c->hold[i];
        if (h->used) continue;
        h->used = 1;
        h->phantom = 1;
        h->sn = sn;
        h->dlen = 0;
        c->hold_n++;
        return;
    }
}

/*=================================================================
 * CmdSN の確認(Immediate 以外。RFC 7143 4.2.2.1)。
 *   - ExpCmdSN と等しい -> 処理する(普段はここだけ。比較 1 つ)
 *   - 窓の外 / 窓の中の重複(ExpCmdSN より前)-> 黙って捨てる(LIO と同じ)
 *   - 窓の中で ExpCmdSN より先 -> 穴が埋まるまで保留(cmdsn_hold())。以前は ExpCmdSN を飛ばして
 *     受けていたので、穴の手前のコマンドが後から来ても「重複」として捨てていた。
 * 戻り値 1 = 処理する / 0 = 処理しない(捨てた / 保留した)。
 * ===============================================================*/
static int cmdsn_accept(iscsit_conn_t *c, const uint8_t *b)
{
    if (b[0] & ISCSI_OP_IMMEDIATE) return 1;
    const uint32_t sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);
    if (__builtin_expect(sn == c->exp_cmd_sn, 1)) {
        c->exp_cmd_sn = sn + 1u;
        return 1;
    }
    const uint32_t max = c->exp_cmd_sn + ISCSIT_CMD_WINDOW - 1u;
    if (iscsi_sn_lt(sn, c->exp_cmd_sn) || iscsi_sn_lt(max, sn)) {
        c->t->window_drop++;
        return 0;
    }
    cmdsn_hold(c, sn);
    return 0;
}

static int dispatch(iscsit_conn_t *c);

/* 穴が埋まった保留を順番どおりに処理する(処理の後、hold_n が 0 でないときだけ呼ぶ)。
 * 戻り値 <0 = 接続を閉じる。 */
/* 保留から CmdSN = ExpCmdSN のものを取り出す。phantom は ExpCmdSN を進めて読み飛ばす。
 * 返したものは保留から外してある(中身は次に保留するまで残る)。無ければ NULL。 */
static iscsit_hold_t *hold_take(iscsit_conn_t *c)
{
    while (c->hold_n) {
        iscsit_hold_t *h = NULL;
        for (unsigned i = 0; i < ISCSIT_HOLD_MAX; i++)
            if (c->hold[i].used && c->hold[i].sn == c->exp_cmd_sn) { h = &c->hold[i]; break; }
        if (!h) return NULL;
        h->used = 0;
        if (--c->hold_n == 0) c->hold_used = 0;
        if (!h->phantom) return h;
        c->exp_cmd_sn++;
    }
    return NULL;
}

static int cmdsn_drain(iscsit_conn_t *c)
{
    while (c->hold_n && c->st == CS_RX && c->ffp) {
        iscsit_hold_t *h = hold_take(c);
        if (!h) return 0;
        /* 受信の作業場所へ戻して、受けた直後と同じ形で処理する(この時点で受信中の PDU は無い)。 */
        memcpy(c->bhs, h->bhs, ISCSI_BHS_LEN);
        if (h->ahslen) memcpy(c->ahs, h->ahs, h->ahslen);
        memcpy(c->data, &c->hold_data[h->doff], h->dlen);
        c->dlen = h->dlen;
        c->dpad = (h->dlen + 3u) & ~3u;
        c->cur_task = NULL;
        c->ddgst_bad = 0;
        c->data_dst = c->data;
        c->pdu_rx--;   /* dispatch() が数え直す */
        if (dispatch(c) < 0) return -1;
    }
    return 0;
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
    /* 自分のアドレスは、この接続を受けたポートのもの(2 ポートで受けるとき両方ありうる)。 */
    const uint32_t ip = netaddr_v4_host((const netaddr_t *)&c->tcp.local_ip);
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

/* Text の続きの状態を捨てる。 */
static void text_reset(iscsit_conn_t *c)
{
    c->text_len = 0;
    c->txt_ttt = 0;
    c->txt_out_len = c->txt_out_off = 0;
}

/* Text 応答の続きを示す TTT(0 と 0xffffffff 以外。11.11.4)。 */
static uint32_t text_new_ttt(iscsit_conn_t *c)
{
    uint32_t t = 0x54000000u | ((++c->txt_ttt_gen & 0xFFFFu) << 8) | c->idx;
    return t;
}

/* 控えてある応答(txt_out)の次の部分を送る。相手の MaxRecvDataSegmentLength を超える分は C=1 で
 * 分け(11.11.6)、要求が F=0 なら最後の部分も F=0 にする(11.11.2: F=0 の要求に F=1 で答えない)。 */
static int text_send_part(iscsit_conn_t *c, uint32_t itt, int req_final)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_TEXT_RSP;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    uint32_t n = c->txt_out_len - c->txt_out_off;
    const uint32_t mx = c->neg.p.max_xmit_dsl;
    int more = 0;
    if (n > mx) { n = mx; more = 1; }
    const int final = !more && req_final;
    bhs[1] = (uint8_t)((final ? ISCSI_TEXT_F : 0) | (more ? ISCSI_TEXT_C : 0));
    if (final) {
        /* F=1 の応答の TTT は 0xffffffff(11.11.4)。これで交渉の並びが終わる。 */
        iscsi_put32(&bhs[ISCSI_OFF_TTT], ISCSI_RSVD_TAG);
    } else {
        if (!c->txt_ttt) c->txt_ttt = text_new_ttt(c);
        iscsi_put32(&bhs[ISCSI_OFF_TTT], c->txt_ttt);
    }
    fill_sn(c, bhs, 1);
    const uint32_t off = c->txt_out_off;
    c->txt_out_off += n;
    c->txt_itt = itt;
    const int r = send_pdu(c, bhs, c->txt_out + off, n);
    if (final) text_reset(c);
    return r;
}

/*=================================================================
 * Text 要求(RFC 7143 11.10 / 11.11)。
 *   - TTT = 0xffffffff の要求は**新しい交渉の始まり**: 前の続きの状態を捨てる(11.10.4)。
 *     それ以外の TTT は、こちらが前の応答で出した TTT でなければならない(違えば Reject)。
 *   - C=1: 続きを溜めて、空の応答(F=0、C=0、TTT = こちら)で続きを求める。
 *   - 応答が相手の MaxRecvDataSegmentLength を超えるなら C=1 で分け、相手の空の要求ごとに続きを出す。
 *   - F=0 の要求には F=1 で答えない(相手はまだ続けるつもり)。最後の部分も F=0 + TTT で返し、
 *     相手の次の要求(F=1)で F=1 の空の応答を返して終わる。
 * SendTargets 以外の鍵・不正な値は Reject(LIO の iscsit_process_text_cmd() と同じ。iscsi-test-cu の
 * iSCSISendTargets.Invalid は鍵ごとの "Reject" の応答では先へ進まず待ち続けた)。
 * ===============================================================*/
static int handle_text(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    const uint32_t ttt = iscsi_be32(&b[ISCSI_OFF_TTT]);
    if (!cmdsn_accept(c, b)) return 0;
    const int C = (b[1] & ISCSI_TEXT_C) != 0, F = (b[1] & ISCSI_TEXT_F) != 0;
    if (C && F) return send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b);   /* C=1 なら F=0(11.10.2)*/
    if (ttt == ISCSI_RSVD_TAG) {
        text_reset(c);                    /* 新しい交渉(11.10.4)*/
    } else if (ttt != c->txt_ttt || itt != c->txt_itt) {
        return send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b);   /* こちらが出していない TTT */
    }

    /* 控えてある応答の続きを求められた(空の要求)。 */
    if (c->txt_out_off < c->txt_out_len) {
        if (c->dlen) return send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b);
        return text_send_part(c, itt, F);
    }
    /* 前の応答(F=0)を出し切った後の F=1 の空の要求 = 並びの終わり。 */
    if (c->txt_ttt && c->txt_out_len && c->text_len == 0 && c->dlen == 0) {
        c->txt_out_len = c->txt_out_off = 0;
        return text_send_part(c, itt, F);
    }

    if (c->text_len + c->dlen > sizeof(c->text)) { text_reset(c); return send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b); }
    memcpy(&c->text[c->text_len], c->data, c->dlen);
    c->text_len += c->dlen;
    c->txt_itt = itt;

    if (C) {
        /* 続きを求める: F=0、C=0、TTT はこちらが決める(次の要求がこれを返してくる)。 */
        uint8_t bhs[ISCSI_BHS_LEN] = {0};
        bhs[0] = ISCSI_OP_TEXT_RSP;
        iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
        if (!c->txt_ttt) c->txt_ttt = text_new_ttt(c);
        iscsi_put32(&bhs[ISCSI_OFF_TTT], c->txt_ttt);
        fill_sn(c, bhs, 1);
        return send_pdu(c, bhs, NULL, 0);
    }
    uint32_t pos = 0;
    const char *k, *v;
    uint32_t kl, vl, p = 0;
    while (iscsi_kv_next(c->text, c->text_len, &p, &k, &kl, &v, &vl)) {
        if (kl == 11 && memcmp(k, "SendTargets", 11) == 0) {
            const int st = build_send_targets(c, v, vl, c->txt_out, sizeof(c->txt_out), &pos);
            if (st == -2) {   /* 値が不正(SendTargets=Alle など)*/
                text_reset(c);
                return send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b);
            }
            if (st < 0) break;
        } else {
            /* SendTargets 以外(Full Feature Phase での再交渉など)は扱わない(上の説明)。 */
            text_reset(c);
            return send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b);
        }
    }
    c->text_len = 0;
    c->txt_out_len = pos;
    c->txt_out_off = 0;
    return text_send_part(c, itt, F);
}

/*=================================================================
 * Logout(RFC 7143 11.14 / 11.15)。
 *   reason 0 = セッションを閉じる / 1 = 接続を閉じる(1 接続 1 セッションなので同じ)/
 *   2 = 回復のために接続を外す(ERL=0 なので「回復はできない」= 2)。
 *   reason 1 / 2 の CID が知らない接続なら「CID が無い」(1)で答え、接続は閉じない(11.15.1)。
 * ===============================================================*/
static int handle_logout(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    if (!cmdsn_accept(c, b)) return 0;
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_LOGOUT_RSP;
    bhs[1] = 0x80;
    const uint8_t reason = b[1] & ISCSI_LOGOUT_REASON_MASK;
    const uint16_t cid = iscsi_be16(&b[ISCSI_LOGOUT_OFF_CID]);
    uint8_t rsp = ISCSI_LOGOUT_RSP_OK;
    if (reason != 0u && cid != c->cid) rsp = ISCSI_LOGOUT_RSP_NO_CID;
    else if (reason == 2u) rsp = ISCSI_LOGOUT_RSP_NO_RECOVERY;
    bhs[2] = rsp;
    memcpy(&bhs[ISCSI_OFF_ITT], &b[ISCSI_OFF_ITT], 4);
    fill_sn(c, bhs, 1);
    c->t->logouts++;
    if (send_pdu(c, bhs, NULL, 0) < 0) return -1;
    uart_printf("[iscsit] 接続%u ログアウト(reason=%u CID=%u -> 応答 %u)\n", c->idx, reason, cid, rsp);
    if (rsp == ISCSI_LOGOUT_RSP_OK) conn_linger(c);
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
        return send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, cmd);
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
    t->aborting = 0;
    t->crc_err = 0;
    t->vr = *r;
    return send_r2t(c, t);
}

/*=================================================================
 * 普段と違う形の SCSI Command の検査(RFC 7143 11.3、まれなのでホットパスの外)。
 *   - F=0(未要請の Data-Out が続く)なのに InitialR2T=Yes -> Reject(protocol error。10.? / 13.10。
 *     このターゲットは InitialR2T=Yes にしか決めないので、F=0 は常にこれ)
 *   - タスク属性 4(ACA)/ 5〜7(予約)-> CHECK CONDITION / ILLEGAL REQUEST / INVALID FIELD IN CDB
 *     (NormACA=0 なので ACA は使えない。LIO の TCM_INVALID_CDB_FIELD と同じ)
 *   - AHS の Extended CDB / 双方向(AHS 2 か R と W の両方)-> 同じく INVALID FIELD IN CDB
 *     (16 バイトを超える CDB と双方向の転送は扱わない)。知らない種類の AHS -> Reject
 * 戻り値 1 = 断った(応答を送った)/ 0 = 普通に処理してよい / <0 = 閉じる。
 * ===============================================================*/
static int scsi_cmd_irregular(iscsit_conn_t *c, const uint8_t *b, uint32_t itt)
{
    if (!(b[1] & ISCSI_CMD_F)) {
        const int r = send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b);
        return r < 0 ? r : 1;
    }
    int bad_field = (b[1] & ISCSI_CMD_ATTR_MASK) >= 4u ||
                    ((b[1] & (ISCSI_CMD_R | ISCSI_CMD_W)) == (ISCSI_CMD_R | ISCSI_CMD_W));
    const uint32_t ahs = (uint32_t)b[ISCSI_OFF_AHSLEN] * 4u;
    for (uint32_t o = 0; o + 4u <= ahs; ) {
        const uint32_t al = iscsi_be16(&c->ahs[o]);
        const uint8_t type = c->ahs[o + 2];
        if (type == ISCSI_AHS_EXT_CDB || type == ISCSI_AHS_BIDI_RLEN) bad_field = 1;
        else {
            const int r = send_reject_cmd(c, ISCSI_REJECT_PROTOCOL_ERR, b);
            return r < 0 ? r : 1;
        }
        o += (4u + al + 3u) & ~3u;
    }
    if (!bad_field) return 0;
    c->t->check_cond++;
    const int r = send_check_condition(c, itt, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0x00);
    return r < 0 ? r : 1;
}

static int handle_scsi_cmd(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    if (!cmdsn_accept(c, b)) return 0;
    if (c->neg.p.discovery) return send_reject_cmd(c, ISCSI_REJECT_CMD_NOT_SUPP, b);   /* Discovery では SCSI を受けない */
    c->scsi_cmds++;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    const uint32_t edtl = iscsi_be32(&b[ISCSI_CMD_OFF_EDTL]);
    /* 普段の形(F=1、タスク属性 0〜3、AHS 無し、R と W の両方は立たない)かを 1 回の分岐で見る。 */
    if (__builtin_expect(((b[1] & (ISCSI_CMD_F | 0x04u)) != ISCSI_CMD_F) |
                         (b[ISCSI_OFF_AHSLEN] != 0) |
                         ((b[1] & (ISCSI_CMD_R | ISCSI_CMD_W)) == (ISCSI_CMD_R | ISCSI_CMD_W)), 0)) {
        const int r = scsi_cmd_irregular(c, b, itt);
        if (r) return r < 0 ? r : 0;
    }
    const unsigned lun = scsi_decode_lun(&b[ISCSI_OFF_LUN]);
    scsi_result_t r;
    scsi_exec(lun, &b[ISCSI_CMD_OFF_CDB], c->cmdbuf, sizeof(c->cmdbuf), &r);
    /* Unit Attention(LU / TARGET RESET の後)と、合意した iSCSIProtocolLevel の版記述子。どちらも
     * 普段は 0 なので分岐 1 つ。 */
    if (__builtin_expect(c->ua.any | c->neg.p.proto_level, 0)) {
        if (c->ua.any) (void)scsi_ua_apply(&c->ua, lun, &b[ISCSI_CMD_OFF_CDB], &r);
        if (c->neg.p.proto_level) scsi_inquiry_set_iscsi_level(&b[ISCSI_CMD_OFF_CDB], &r, c->neg.p.proto_level);
    }
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
    if (t->aborting) {
        /* ABORT / CLEAR TASK SET で捨てるタスク。R2T の答え(F=1)を数えるだけで媒体へは書かない。 */
        c->cur_task = t;
        return;
    }
    /* 順序どおり(DataPDUInOrder=Yes)・R2T の範囲の中・DataSN が続いていること。 */
    if (off != t->got || off + c->dlen > t->r2t_off + t->r2t_len || datasn != t->datasn) return;
    c->cur_task = t;
    /* VERIFY は媒体へ書かない: 作業場所へ受けて、処理のときに媒体と比べる。 */
    c->data_dst = t->verify ? c->data : t->dst + off;
}

static int send_tmf_rsp(iscsit_conn_t *c, uint32_t itt, uint8_t rsp)
{
    uint8_t bhs[ISCSI_BHS_LEN] = {0};
    bhs[0] = ISCSI_OP_TMF_RSP;
    bhs[1] = 0x80;
    bhs[2] = rsp;
    iscsi_put32(&bhs[ISCSI_OFF_ITT], itt);
    fill_sn(c, bhs, 1);
    return send_pdu(c, bhs, NULL, 0);
}

/* 待っていた ABORT / CLEAR TASK SET の応答を、捨てるタスクの R2T の答えが揃ったら送る。
 * force = 1 なら揃っていなくても(時間切れ)残りを捨てて送る。 */
static int tmf_try_finish(iscsit_conn_t *c, int force)
{
    if (!c->tmf_wait) return 0;
    for (unsigned i = 0; i < ISCSIT_MAX_TASKS; i++) {
        iscsit_task_t *t = &c->task[i];
        if (!t->in_use || !t->aborting) continue;
        if (!force) return 0;
        t->in_use = 0;
        t->aborting = 0;
        c->t->tasks_aborted++;
    }
    c->tmf_wait = 0;
    return send_tmf_rsp(c, c->tmf_itt, ISCSI_TMF_RSP_COMPLETE);
}

static int handle_data_out(iscsit_conn_t *c)
{
    iscsit_task_t *t = c->cur_task;
    const int F = (c->bhs[1] & 0x80) != 0;
    if (!t) {
        if (c->dataout_stale || c->ddgst_bad) {
            /* TMF で捨てた(あるいは既に終えた)タスク宛ての遅れて届いた Data-Out / ダイジェストが合わず
             * Reject 済みで宛先も分からないもの。黙って捨てる。 */
            c->t->stale_dataout++;
            return 0;
        }
        /* 範囲の外 / 順序の乱れ / DataSN の飛び。ERL=0 では立て直せないので断って閉じる。 */
        c->t->bad_dataout++;
        send_reject(c, ISCSI_REJECT_INVALID_FIELD, c->bhs);
        return -1;
    }
    if (t->aborting) {
        /* 捨てるタスクの R2T の答えが揃った(11.5.1: ABORT / CLEAR TASK SET は R2T への答えを待つ)。 */
        if (!F) return 0;
        t->in_use = 0;
        t->aborting = 0;
        c->t->tasks_aborted++;
        return tmf_try_finish(c, 0);
    }
    if (c->ddgst_bad) t->crc_err = 1;
    if (t->verify && !t->miscompare && !t->crc_err)
        t->miscompare = (uint8_t)scsi_verify_cmp(&t->vr, t->got, c->data, c->dlen);
    t->got += c->dlen;
    t->datasn++;
    if (!F) return 0;   /* F が立つまでは同じ R2T の続き */
    if (t->got != t->r2t_off + t->r2t_len) {
        c->t->bad_dataout++;
        send_reject(c, ISCSI_REJECT_PROTOCOL_ERR, c->bhs);
        t->in_use = 0;
        return -1;
    }
    if (t->crc_err) {
        /* RFC 7143 7.8 (b): データダイジェストが合わない Data-Out があった。R2T で出し直しを求めず
         * (ERL=0 では recovery R2T を持たない)、出した R2T の答えが揃ったところで CHECK CONDITION /
         * ABORTED COMMAND / PROTOCOL SERVICE CRC ERROR(47/05、11.4.7.2)で終える。**残りの R2T は出さない。**
         * 壊れたデータは既に RAM ディスクへ書いてあるが、WRITE は失敗として返るので(SBC: 失敗した
         * WRITE の範囲の中身は不定)、「壊れたまま成功」にはならない。 */
        t->in_use = 0;
        c->t->crc_fail++;
        c->t->check_cond++;
        return send_check_condition(c, t->itt, SCSI_SK_ABORTED_COMMAND, SCSI_ASC_PROTOCOL_CRC, SCSI_ASCQ_PROTOCOL_CRC);
    }
    if (t->got < t->total) return send_r2t(c, t);
    t->in_use = 0;
    return finish_data_out(c, t->itt, t->edtl, t->total, t->r2tsn, t->verify, t->miscompare);
}

/*=================================================================
 * 書き込み中のタスクと保留中のコマンドを捨てる。lun < 0 なら全部、by_itt なら ITT が一致するもの。
 * wait = 1 なら捨てる印(aborting)を付けるだけで、出した R2T の答えを待つ(ABORT / CLEAR TASK SET)。
 * 保留中のコマンド(CmdSN の穴の先)は phantom にする(応答せず、CmdSN は受け取ったことにする)。
 * 戻り値 = 捨てたタスクの数(保留のぶんは *held へ)。
 * ===============================================================*/
static unsigned abort_tasks(iscsit_conn_t *c, int lun, uint32_t only_itt, int by_itt, int wait, unsigned *held)
{
    unsigned n = 0, h = 0;
    for (unsigned i = 0; i < ISCSIT_MAX_TASKS; i++) {
        iscsit_task_t *t = &c->task[i];
        if (!t->in_use || t->aborting) continue;
        if (by_itt && t->itt != only_itt) continue;
        if (lun >= 0 && scsi_decode_lun(t->lun8) != (unsigned)lun) continue;
        if (wait) {
            t->aborting = 1;
        } else {
            t->in_use = 0;
            c->t->tasks_aborted++;
        }
        n++;
    }
    for (unsigned i = 0; c->hold_n && i < ISCSIT_HOLD_MAX; i++) {
        iscsit_hold_t *e = &c->hold[i];
        if (!e->used || e->phantom) continue;
        if (by_itt && iscsi_be32(&e->bhs[ISCSI_OFF_ITT]) != only_itt) continue;
        if (lun >= 0 && scsi_decode_lun(&e->bhs[ISCSI_OFF_LUN]) != (unsigned)lun) continue;
        e->phantom = 1;
        h++;
    }
    if (held) *held = h;
    return n;
}

/* 他のセッションからの頼み(LU / TARGET RESET、CLEAR TASK SET)をこの接続のジョブで処理する。 */
static void apply_xreq(iscsit_conn_t *c)
{
    const uint32_t x = __atomic_exchange_n(&c->xreq, 0u, __ATOMIC_ACQ_REL);
    const uint16_t ua = c->xreq_ua;
    unsigned aborted = 0;
    for (unsigned l = 0; l < SCSI_MAX_LUNS; l++) {
        if (!(x & (1u << l))) continue;
        unsigned held = 0;
        aborted += abort_tasks(c, (int)l, 0, 0, 0, &held) + held;
    }
    /* 捨てた書き込みの応答は出さない(TAS=0。他の nexus の仕事は黙って捨て、UA で知らせる)。 */
    if (!(x & ISCSIT_XREQ_UA_IF_ABORTED) || aborted)
        scsi_ua_set(&c->ua, x & ISCSIT_XREQ_LUN_MASK, (uint8_t)(ua >> 8), (uint8_t)ua);
}

void iscsit_xreset(unsigned lun_mask, uint8_t asc, uint8_t ascq, unsigned flags, int cold, const void *except)
{
    if (!s_t.started) return;
    for (unsigned i = 0; i < ISCSIT_MAX_CONNS; i++) {
        iscsit_conn_t *o = &s_t.conn[i];
        if ((const void *)o == except || o->st != CS_RX || !o->ffp || o->neg.p.discovery) continue;
        if (cold) { o->kill = 1; continue; }   /* TARGET COLD RESET は全部の接続を閉じる(11.5.1)*/
        o->xreq_ua = (uint16_t)((asc << 8) | ascq);
        __atomic_or_fetch(&o->xreq, (lun_mask & ISCSIT_XREQ_LUN_MASK) | flags, __ATOMIC_ACQ_REL);
    }
}

/* 他のセッション(TCP の別の接続と iSER)へ頼む。 */
static void xreset_others(iscsit_conn_t *c, unsigned lun_mask, uint8_t asc, uint8_t ascq, unsigned flags, int cold)
{
    iscsit_xreset(lun_mask, asc, ascq, flags, cold, c);
    iscsit_iser_xreset(lun_mask, asc, ascq, flags, cold, NULL);
}

/*=================================================================
 * タスク管理(RFC 7143 11.5 / 11.6、番号は 11.5.1 と RFC 7144 4.1)。このターゲットで「実行中」の
 * タスクは、R2T でデータを待っている書き込みだけ(読み出しや問い合わせは受けた時点で答え切る)と、
 * CmdSN の穴の先で保留しているコマンド。
 *   - **捨てたタスクの SCSI Response は出さない**(11.5.1)。捨てたタスク宛てに遅れて届く Data-Out は
 *     黙って捨てる(dataout_route)。
 *   - ABORT TASK: 見つからなくても RefCmdSN が窓の中・まだ受けていない・TMF の CmdSN より前なら、
 *     その CmdSN を受け取ったことにして「完了」(11.5.1 の b)。CmdSN の穴を埋める手段)。
 *   - ABORT / CLEAR TASK SET: **出した R2T の答え(F=1 の Data-Out)を待ってから応答する**(11.5.1)。
 *     CLEAR TASK SET はタスクの集合(TST=0 = 全 nexus で 1 つ)を消すので、他のセッションの仕事も捨て、
 *     捨てた相手に UA(2F/00)を立てる。
 *   - LU RESET / TARGET WARM・COLD RESET: 他のセッションの仕事も捨て、全 nexus に UA(29/03、29/00)。
 *     COLD RESET は応答の後に全部の接続を閉じる(11.5.1)。
 *   - TASK REASSIGN(8)は ERL=0 では持てない(4)、CLEAR ACA と RFC 7144 の 9〜12 は対応しない(5)、
 *     それ以外は Function rejected(255)(iscsi_tmf_static_rsp())。
 * ===============================================================*/
static int handle_tmf(iscsit_conn_t *c)
{
    const uint8_t *b = c->bhs;
    const uint32_t tmf_sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);
    const uint32_t exp_before = c->exp_cmd_sn;
    if (!cmdsn_accept(c, b)) return 0;
    const uint8_t fn = b[1] & 0x7Fu;
    const uint32_t itt = iscsi_be32(&b[ISCSI_OFF_ITT]);
    const uint32_t ref_itt = iscsi_be32(&b[20]);
    const unsigned lun = scsi_decode_lun(&b[ISCSI_OFF_LUN]);
    const int lun_ok = scsi_get_lun(lun) != NULL;
    const unsigned lmask = lun_ok ? 1u << lun : 0u;
    const unsigned all = (1u << SCSI_MAX_LUNS) - 1u;
    uint8_t rsp = iscsi_tmf_static_rsp(fn);
    int cold = 0;
    c->t->tmf++;
    if (rsp == 0 && c->tmf_wait) rsp = ISCSI_TMF_RSP_REJECTED;   /* 前の TASK SET の応答待ちの間は受けない */
    if (rsp == 0) {
        switch (fn) {
        case ISCSI_TMF_ABORT_TASK: {
            unsigned held = 0;
            if (abort_tasks(c, -1, ref_itt, 1, 0, &held) || held) {
                rsp = ISCSI_TMF_RSP_COMPLETE;
            } else {
                const uint32_t ref_sn = iscsi_be32(&b[ISCSI_TMF_OFF_REFCMDSN]);
                const uint32_t max = exp_before + ISCSIT_CMD_WINDOW - 1u;
                if (iscsi_sn_le(c->exp_cmd_sn, ref_sn) && iscsi_sn_le(ref_sn, max) && iscsi_sn_lt(ref_sn, tmf_sn)) {
                    cmdsn_plug(c, ref_sn);
                    rsp = ISCSI_TMF_RSP_COMPLETE;
                } else {
                    /* 既に完了して応答を送ったタスクもこれに当たる(イニシエータは応答を受けていれば中断しない)。 */
                    rsp = ISCSI_TMF_RSP_NO_TASK;
                }
            }
            break;
        }
        case ISCSI_TMF_ABORT_TASK_SET:
        case ISCSI_TMF_CLEAR_TASK_SET: {
            if (!lun_ok) { rsp = ISCSI_TMF_RSP_NO_LUN; break; }
            unsigned held = 0;
            const unsigned n = abort_tasks(c, (int)lun, 0, 0, 1, &held);
            if (fn == ISCSI_TMF_CLEAR_TASK_SET)
                xreset_others(c, lmask, SCSI_ASC_CMDS_CLEARED, 0x00, ISCSIT_XREQ_UA_IF_ABORTED, 0);
            if (n) {
                /* R2T の答えを待つ。応答は handle_data_out() / 時間切れ(CS_RX)が tmf_try_finish() で送る。 */
                c->tmf_wait = 1;
                c->tmf_itt = itt;
                c->tmf_since = timer_now();
                return 0;
            }
            rsp = ISCSI_TMF_RSP_COMPLETE;
            break;
        }
        case ISCSI_TMF_LU_RESET:
            if (!lun_ok) { rsp = ISCSI_TMF_RSP_NO_LUN; break; }
            abort_tasks(c, (int)lun, 0, 0, 0, NULL);
            scsi_ua_set(&c->ua, lmask, SCSI_ASC_RESET_OCCURRED, SCSI_ASCQ_BUS_DEVICE_RESET);
            xreset_others(c, lmask, SCSI_ASC_RESET_OCCURRED, SCSI_ASCQ_BUS_DEVICE_RESET, 0, 0);
            rsp = ISCSI_TMF_RSP_COMPLETE;
            break;
        default:   /* TARGET WARM / COLD RESET */
            abort_tasks(c, -1, 0, 0, 0, NULL);
            cold = (fn == ISCSI_TMF_TARGET_COLD_RESET);
            scsi_ua_set(&c->ua, all, SCSI_ASC_RESET_OCCURRED, 0x00);
            xreset_others(c, all, SCSI_ASC_RESET_OCCURRED, 0x00, 0, cold);
            rsp = ISCSI_TMF_RSP_COMPLETE;
            break;
        }
    }
    if (send_tmf_rsp(c, itt, rsp) < 0) return -1;
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
            /* ログイン中は Login 以外を受けない。**Login reject(0x020B Invalid request during login)を
             * 送ってから**閉じる(RFC 7143 6.3 / 11.13.5。黙って切ると相手は理由が分からない)。 */
            uart_printf("[iscsit] 接続%u Login 中に op=0x%02x\n", c->idx, op);
            c->t->login_reject++;
            return login_fail(c, ISCSI_LS_INVALID_REQUEST, iscsi_be32(&c->bhs[ISCSI_OFF_ITT]),
                              c->lst.started ? c->lst.stage : 0u, "ログイン中にログイン要求以外の PDU");
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
        c->ddgst_bad = 0;
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
            /* RFC 7143 7.8: データダイジェストが合わない PDU には Reject(Data Digest Error)で答えて
             * その PDU を捨てる。**接続は保つ**(ヘッダは正しいので次の PDU の位置は分かる)。
             *   - Data-Out(宛先のタスクが分かるもの): (b) を選ぶ。recovery R2T(ERL>0)は持たないので、
             *     出した R2T の答えが揃ったところで CHECK CONDITION(47/05)で仕事を終える
             *     (handle_data_out() の crc_err)。
             *   - それ以外(コマンド・NOP-Out・Text): 捨てるだけ。CmdSN は受け取ったことにしない
             *     (処理へ回さないので cmdsn_accept() を通らない)ので、イニシエータは同じ CmdSN で送り直す
             *     (7.2 / 7.8「即時データはタスクの再試行で取り戻される」)。
             * **Data-Out はダイジェストを確かめる前に RAM ディスクへ書いている。** 写し直す領域を
             * 持たずに直接受ける作りはそのまま: 壊れたデータで WRITE が「成功」になることは無く
             * (CHECK CONDITION で失敗として返す。SBC は失敗した WRITE の範囲の中身を不定とする)、
             * 確かめてから書く形にすると Data-Out のたびに 1 回余分に写すことになる。
             * LIO は ERL=0 では Data-Out / NOP の誤りで接続を落とす(ここは LIO と違う)。 */
            c->t->ddgst_err++;
            const uint8_t op = c->bhs[0] & ISCSI_OP_MASK;
            uart_printf("[iscsit] 接続%u データダイジェストが合わない(op=0x%02x、%u バイト)\n", c->idx, op, c->dlen);
            if (send_reject(c, ISCSI_REJECT_DIGEST_ERR, c->bhs) < 0) { conn_close(c, "Reject を送れない"); return -1; }
            if (op == ISCSI_OP_DATA_OUT && c->ffp && (c->cur_task || c->dataout_stale)) {
                c->ddgst_bad = 1;
                ready = 1;   /* handle_data_out() で R2T の答えとして数える */
                break;
            }
            rx_expect(c, PH_BHS, c->bhs, ISCSI_BHS_LEN);
            return 1;
        }
        ready = 1;
        break;
    }
    }
    if (!ready) return 1;
    int r = dispatch(c);
    if (c->st != CS_RX) return -1;   /* dispatch の中で linger / close へ移った */
    /* CmdSN の穴が埋まったら、保留していたコマンドを順番どおりに処理する(普段は hold_n = 0)。 */
    if (r >= 0 && __builtin_expect(c->hold_n != 0, 0)) {
        r = cmdsn_drain(c);
        if (c->st != CS_RX) return -1;
    }
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
            c->tx_nif = (c->tcp.local_ip.family == NETADDR_V4)
                      ? netif_find_by_ip(netaddr_v4_host((const netaddr_t *)&c->tcp.local_ip)) : NULL;
            c->t_accept = timer_now();
            c->st = CS_RX;
            c->ackpiggy = g_iscsit_ackpiggy ? 1u : 0u;
            tcp_set_ack_piggyback(&c->tcp, c->ackpiggy);
            uart_printf("[iscsit] 接続%u 確立(core%u)\n", c->idx, c->tcp.owner_core);
        }
        return JOB_WAITING;

    case CS_RX:
        if (c->kill) { conn_close(c, "session reinstatement / TARGET COLD RESET で捨てた"); return JOB_WAITING; }
        if (__builtin_expect(c->reinst_wait, 0)) {
            /* 古いセッションが止まるのを待つ間は受信を進めない(最後の Login 応答の前)。 */
            if (reinst_poll(c) < 0) conn_close(c, "最後の Login 応答を送れない");
            return JOB_WAITING;
        }
        if (__builtin_expect(c->xreq != 0, 0)) apply_xreq(c);
        if (!c->ffp && timeout_ms(c->t_accept, ISCSIT_LOGIN_TIMEOUT_MS)) {
            conn_close(c, "Login が終わらない");
            return JOB_WAITING;
        }
        /* `iscsit ackpiggy` を張ったままの接続にも効かせる(同じ接続で交互に測るため)。 */
        if (c->ackpiggy != (g_iscsit_ackpiggy ? 1u : 0u)) {
            c->ackpiggy = g_iscsit_ackpiggy ? 1u : 0u;
            tcp_set_ack_piggyback(&c->tcp, c->ackpiggy);
        }
        for (int i = 0; i < 8; i++) {
            /* **送信キューの空きが半分を切ったら、続きは次の周回へ回す。** 送信キューが満杯だと
             * 送信はその場で空きを待つので、1 つのコアが 2 つのポートを扱うとき、片方の接続が
             * 受けた読み出しを出し切るまでもう片方の接続が回らず、そちらの線が遊んでいた
             * (1 コアの 256KiB 読み出しが約 2,400 MiB/s で頭打ち、perf の半分が空き待ち。SPEC 27.14)。
             * ここで返せばスケジューラが同じコアのほかのジョブを回す。NVMe/TCP と同じ手当て(27.15)。 */
            if (c->ffp && c->tx_nif && g_iscsit_tx_yield) {
                if (eth_tx_room_of(c->tx_nif) < ISCSIT_TX_ROOM_MIN) {
                    c->tx_yield++;
                    break;
                }
                /* **TCP の窓が足りないときも譲る。** 相手(Linux)の受信窓は 1 接続 80 万バイト前後で、
                 * 256KiB の読み出しを 3 個積むと埋まる。窓待ちはその場で回るので、1 コアでは
                 * もう片方の接続が回らない。譲る前に受信を 1 回見て ACK を拾う(全部の接続が
                 * 譲り合うと誰も ACK を拾わず止まる)。 */
                if (g_iscsit_tx_yield >= 2u) {
                    uint32_t usable;
                    const uint32_t room = tcp_send_room(&c->tcp, &usable);
                    uint32_t want = usable / 2u;
                    if (want > ISCSIT_TX_WIN_MIN) want = ISCSIT_TX_WIN_MIN;
                    if (room < want) {
                        (void)net_poll_all_and_dispatch();
                        if (tcp_send_room(&c->tcp, NULL) < want) {
                            c->tx_win_yield++;
                            break;
                        }
                    }
                }
                /* **短経路の再送用の枠が半分を切ったときも譲る(short)。** ESP の相手には大きい Data-In も
                 * 短経路で刻んで送る(iscsi_pdu.c の auto)ので、枠が埋まると送信はその場で ACK を待ち、
                 * 1 コアで 2 本の接続を回すと、もう片方の接続が回らない(窓の場合と同じ形)。 */
                if (g_iscsit_tx_yield >= 3u) {
                    unsigned cap;
                    if (tcp_send_short_free(&c->tcp, &cap) < cap / 2u) {
                        (void)net_poll_all_and_dispatch();
                        if (tcp_send_short_free(&c->tcp, NULL) < cap / 2u) {
                            c->tx_win_yield++;
                            break;
                        }
                    }
                }
            }
            const int r = rx_step(c);
            if (r <= 0) break;
        }
        /* 応答へ相乗りできなかった ACK を返す(`iscsit ackpiggy on` のときだけ借りがある)。 */
        if (c->st == CS_RX) (void)tcp_ack_flush(&c->tcp);
        if (c->st == CS_RX && c->ffp) {
            if (c->async_req) { c->async_req = 0; send_async_logout(c); }
            if ((++c->ticks & 1023u) == 0) {
                /* ABORT / CLEAR TASK SET の応答待ちの逃げ道(イニシエータが R2T に答えないとき)。 */
                if (c->tmf_wait && timeout_ms(c->tmf_since, ISCSIT_TMF_WAIT_MS) && tmf_try_finish(c, 1) < 0)
                    conn_close(c, "TMF の応答を送れない");
                else if (keepalive(c) < 0) conn_close(c, "NOP-In に応答が無い");
            }
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
        job_set_affinity(c->job, &s_t);
    }
    s_t.started = 1;
    return 0;
}

int iscsit_set_chap(const iscsi_chap_cfg_t *cfg)
{
    /* 両方向に同じ秘密の設定は受けない(RFC 7143 12.1.3 の MUST NOT)。96 ビット未満は警告だけ。 */
    const char *why, *warn;
    if (iscsi_chap_cfg_check(cfg, &why, &warn) < 0) {
        uart_printf("iscsit: CHAP の設定を断った: %s\n", why);
        return -1;
    }
    if (warn) uart_printf("iscsit: 警告: %s\n", warn);
    if (cfg) s_t.chap = *cfg;
    else memset(&s_t.chap, 0, sizeof(s_t.chap));
    s_t.pref.chap_required = s_t.chap.set ? 1 : 0;
    return 0;
}

/*=================================================================
 * 試験の口(`rfctest iscsi`)。実機の接続を使わずに CmdSN の窓と保留を確かめる。
 * mem は iscsit_selftest_size() バイト(呼び出し側が用意する。.bss を増やさないため)。
 * 戻り値 = 食い違った項目の数(0 = 全部よい)。項目ごとに「rfctest iscsi: OK / NG」を出す。
 * ===============================================================*/
size_t iscsit_selftest_size(void) { return sizeof(iscsit_conn_t); }

static uint8_t *st_cmd(uint8_t *b, uint32_t sn, uint32_t itt, int imm)
{
    memset(b, 0, ISCSI_BHS_LEN);
    b[0] = (uint8_t)(ISCSI_OP_SCSI_CMD | (imm ? ISCSI_OP_IMMEDIATE : 0));
    b[1] = ISCSI_CMD_F | 1u;
    iscsi_put32(&b[ISCSI_OFF_ITT], itt);
    iscsi_put32(&b[ISCSI_OFF_CMDSN], sn);
    return b;
}

int iscsit_selftest_cmdsn(void *mem, int (*report)(int ok, const char *what))
{
    iscsit_conn_t *c = (iscsit_conn_t *)mem;
    memset(c, 0, sizeof(*c));
    c->t = &s_t;
    c->st = CS_RX;
    c->ffp = 1;
    c->exp_cmd_sn = 0xFFFFFFFEu;   /* 2^32 の折り返しをまたがせる(素の < で比べていれば落ちる)*/
    int ng = 0;
    #define ST(cond, what) do { const int ok_ = (cond); ng += !ok_; report(ok_, what); } while (0)
    /* 順番どおり */
    ST(cmdsn_accept(c, st_cmd(c->bhs, 0xFFFFFFFEu, 1, 0)) == 1 && c->exp_cmd_sn == 0xFFFFFFFFu,
       "CmdSN = ExpCmdSN は受けて ExpCmdSN を進める");
    /* Immediate は進めない、窓の外でも受ける */
    ST(cmdsn_accept(c, st_cmd(c->bhs, 0x12345u, 2, 1)) == 1 && c->exp_cmd_sn == 0xFFFFFFFFu,
       "Immediate は CmdSN を進めない(窓の外でも受ける)");
    /* 重複 / 窓の外 */
    ST(cmdsn_accept(c, st_cmd(c->bhs, 0xFFFFFFFEu, 3, 0)) == 0 && c->hold_n == 0, "ExpCmdSN より前(重複)は捨てる");
    ST(cmdsn_accept(c, st_cmd(c->bhs, 0xFFFFFFFFu + ISCSIT_CMD_WINDOW, 4, 0)) == 0 && c->hold_n == 0,
       "MaxCmdSN より先(窓の外)は捨てる");
    /* 先回りは保留(2^32 をまたぐ: Exp = 0xFFFFFFFF、来るのは 0 と 1)*/
    c->dlen = 4;
    memcpy(c->data, "abcd", 4);
    ST(cmdsn_accept(c, st_cmd(c->bhs, 1u, 11, 0)) == 0 && c->hold_n == 1 && c->exp_cmd_sn == 0xFFFFFFFFu,
       "窓の中の先回り(CmdSN 1、Exp 0xFFFFFFFF)は保留して ExpCmdSN を飛ばさない");
    c->dlen = 0;
    ST(cmdsn_accept(c, st_cmd(c->bhs, 0u, 10, 0)) == 0 && c->hold_n == 2, "2 つ目の先回り(CmdSN 0)も保留");
    ST(cmdsn_accept(c, st_cmd(c->bhs, 1u, 12, 0)) == 0 && c->hold_n == 2, "保留中と同じ CmdSN の重複は捨てる");
    /* 穴(0xFFFFFFFF)が埋まると 0 -> 1 の順に出てくる */
    ST(cmdsn_accept(c, st_cmd(c->bhs, 0xFFFFFFFFu, 9, 0)) == 1 && c->exp_cmd_sn == 0u, "穴の CmdSN が来たら受ける");
    iscsit_hold_t *h0 = NULL, *h1 = NULL;
    for (unsigned i = 0; i < ISCSIT_HOLD_MAX; i++) {
        if (c->hold[i].used && c->hold[i].sn == 0u) h0 = &c->hold[i];
        if (c->hold[i].used && c->hold[i].sn == 1u) h1 = &c->hold[i];
    }
    ST(h0 && h1 && iscsi_be32(&h0->bhs[ISCSI_OFF_ITT]) == 10u && h1->dlen == 4 &&
       memcmp(&c->hold_data[h1->doff], "abcd", 4) == 0, "保留に BHS と即時データが控えてある");
    /* Reject したら CmdSN を受け取ったことにしない(7.2): 受けた直後に戻す */
    {
        uint8_t b[ISCSI_BHS_LEN];
        const uint32_t e = c->exp_cmd_sn;
        (void)cmdsn_accept(c, st_cmd(b, e, 20, 0));
        if (!(b[0] & ISCSI_OP_IMMEDIATE) && iscsi_be32(&b[ISCSI_OFF_CMDSN]) + 1u == c->exp_cmd_sn)
            c->exp_cmd_sn = iscsi_be32(&b[ISCSI_OFF_CMDSN]);   /* send_reject_cmd() と同じ戻し方 */
        ST(c->exp_cmd_sn == e, "Reject したコマンドの CmdSN は ExpCmdSN を進めない");
    }
    /* 保留は CmdSN の順に取り出す(cmdsn_drain() と同じ hold_take())。取り出したものを処理すると
     * dispatch() の cmdsn_accept() が ExpCmdSN を進める。 */
    {
        iscsit_hold_t *h = hold_take(c);
        ST(h == h0 && c->hold_n == 1, "保留は CmdSN の順(0 が先)に取り出す");
        if (h) ST(cmdsn_accept(c, h->bhs) == 1 && c->exp_cmd_sn == 1u, "取り出したものは窓の確認を通る");
    }
    /* ABORT TASK が保留中のコマンドを消すと phantom(受け取ったことにする)*/
    {
        unsigned held = 0;
        const unsigned n = abort_tasks(c, -1, 11u, 1, 0, &held);
        ST(n == 0 && held == 1 && h1->phantom, "ABORT TASK は保留中のコマンドを応答なしで消す(CmdSN は数える)");
        ST(hold_take(c) == NULL && c->hold_n == 0 && c->exp_cmd_sn == 2u,
           "phantom は取り出さずに ExpCmdSN を進める");
    }
    /* RefCmdSN で穴を埋める(11.5.1 の b)) */
    cmdsn_plug(c, 2u);
    ST(c->hold_n == 0 && c->exp_cmd_sn == 3u, "RefCmdSN = ExpCmdSN ならそのまま進める");
    cmdsn_plug(c, 5u);
    ST(c->hold_n == 1 && c->exp_cmd_sn == 3u, "RefCmdSN が先なら phantom を保留に置く");
    #undef ST
    memset(c, 0, sizeof(*c));
    return ng;
}

void iscsit_stats_clear(void)
{
    s_t.logins_ok = s_t.logins_fail = s_t.discovery = s_t.reinstated = s_t.rejects = 0;
    s_t.hdgst_err = s_t.ddgst_err = s_t.window_drop = s_t.nop = s_t.logouts = 0;
    s_t.check_cond = s_t.r2t_sent = s_t.bad_dataout = 0;
    s_t.tmf = s_t.tasks_aborted = s_t.stale_dataout = s_t.nopin_sent = s_t.nopin_timeout = s_t.async_sent = 0;
    s_t.chap_ok = s_t.chap_fail = 0;
    s_t.held = s_t.crc_fail = s_t.login_reject = 0;
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
    uart_printf("  CHECK CONDITION %u、R2T %u、合わない Data-Out %u、CRC 誤りで終えた書き込み %u、"
                "CmdSN の先回りを保留 %u、ログイン中の別の PDU %u\n",
                s_t.check_cond, s_t.r2t_sent, s_t.bad_dataout, s_t.crc_fail, s_t.held, s_t.login_reject);
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
                    "読 %llu / 書 %llu バイト / 譲った 送信キュー %llu 回・窓 %llu 回\n",
                    i, CS_NAME[c->st], c->ffp ? (c->neg.p.discovery ? "Discovery" : "Normal") : "login",
                    c->neg.initiator_name[0] ? c->neg.initiator_name : "-", c->tsih, c->exp_cmd_sn,
                    c->stat_sn, c->pdu_rx, c->pdu_tx, c->scsi_cmds, c->hd ? "CRC32C" : "None",
                    c->dd ? "CRC32C" : "None", (unsigned long long)c->bytes_read,
                    (unsigned long long)c->bytes_written, (unsigned long long)c->tx_yield,
                    (unsigned long long)c->tx_win_yield);
    }
}
