#include "rfctest.h"
#include "uart.h"
#include "iscsi.h"
#include "iscsi_text.h"
#include "iscsi_chap.h"
#include "iscsit.h"
#include "scsi.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/*=================================================================
 * シェルの `rfctest iscsi`。RFC 7143 / 7144 / 7145 に合わせて直した動きを、実機の接続を使わずに
 * 確かめる(鍵の交渉の関数に作った並びを渡す、ログイン要求の BHS の検査、CHAP、TMF の番号、
 * Unit Attention、CmdSN の窓と保留)。接続を伴う動き(Text の分割、TMF の応答待ち、session
 * reinstatement の待ち、データダイジェストの誤り、Logout の CID)は実機で確かめる。
 * 各項目「rfctest iscsi: OK [n] ...」、最後に「rfctest iscsi: PASS / NG」。
 * ===============================================================*/

static unsigned s_n, s_ng;

static int report(int ok, const char *what)
{
    s_n++;
    if (!ok) s_ng++;
    uart_printf("rfctest iscsi: %s [%u] %s\n", ok ? "OK" : "NG", s_n, what);
    return ok;
}

/* "k=v" を並べて key=value\0 の並びを作る(NULL で終わり)。戻り値は長さ。 */
static uint32_t kvs(uint8_t *buf, uint32_t cap, ...)
{
    va_list ap;
    va_start(ap, cap);
    uint32_t n = 0;
    const char *e;
    while ((e = va_arg(ap, const char *)) != NULL) {
        const uint32_t l = (uint32_t)strlen(e);
        if (n + l + 1u > cap) break;
        memcpy(&buf[n], e, l + 1u);
        n += l + 1u;
    }
    va_end(ap);
    return n;
}

/* 並びの中の key の値が want か(want = NULL なら「鍵が無いこと」)。 */
static int has_kv(const uint8_t *buf, int len, const char *key, const char *want)
{
    if (len < 0) return 0;
    const char *k, *v;
    uint32_t kl, vl, pos = 0;
    while (iscsi_kv_next(buf, (uint32_t)len, &pos, &k, &kl, &v, &vl)) {
        if (kl == strlen(key) && memcmp(k, key, kl) == 0)
            return want && vl == strlen(want) && memcmp(v, want, vl) == 0;
    }
    return want == NULL;
}

static iscsi_tgt_pref_t pref_tcp(void)
{
    iscsi_tgt_pref_t p;
    memset(&p, 0, sizeof(p));
    p.max_recv_dsl = 262144u;
    p.first_burst = 65536u;
    p.max_burst = 262144u;
    p.max_outstanding_r2t = 1u;
    p.initial_r2t = 1;
    p.immediate_data = 1;
    p.allow_crc32c = 1;
    p.tpgt = 1;
    return p;
}

/* ログイン要求の BHS を作る。 */
static void login_bhs(uint8_t *b, int T, int C, uint8_t csg, uint8_t nsg, uint32_t itt, uint16_t cid, uint8_t isid5)
{
    memset(b, 0, ISCSI_BHS_LEN);
    b[0] = ISCSI_OP_IMMEDIATE | ISCSI_OP_LOGIN;
    b[1] = (uint8_t)((T ? ISCSI_LOGIN_T : 0) | (C ? ISCSI_LOGIN_C : 0) | (csg << 2) | (T ? nsg : 0));
    b[ISCSI_LOGIN_OFF_ISID] = 0x80;
    b[ISCSI_LOGIN_OFF_ISID + 5] = isid5;
    iscsi_put32(&b[ISCSI_OFF_ITT], itt);
    iscsi_put16(&b[ISCSI_LOGIN_OFF_CID], cid);
}

static void test_tmf(void)
{
    report(iscsi_tmf_static_rsp(ISCSI_TMF_TASK_REASSIGN) == ISCSI_TMF_RSP_REASSIGN_NS && ISCSI_TMF_TASK_REASSIGN == 8u,
           "TMF: TASK REASSIGN は 8 で、ERL=0 なので応答 4(RFC 7143 11.5.1 / 11.6.1)");
    int ok = 1;
    for (uint8_t f = 9; f <= 12; f++) ok &= iscsi_tmf_static_rsp(f) == ISCSI_TMF_RSP_NOT_SUPPORTED;
    report(ok, "TMF: RFC 7144 の 9〜12(QUERY TASK など)は「対応しない」(5)");
    ok = iscsi_tmf_static_rsp(0) == ISCSI_TMF_RSP_REJECTED && iscsi_tmf_static_rsp(13) == ISCSI_TMF_RSP_REJECTED &&
         iscsi_tmf_static_rsp(14) == ISCSI_TMF_RSP_REJECTED && iscsi_tmf_static_rsp(127) == ISCSI_TMF_RSP_REJECTED;
    report(ok, "TMF: 割り当ての無い番号(0、13〜127。以前 TASK REASSIGN と読んでいた 14 を含む)は Function rejected");
    ok = 1;
    for (uint8_t f = 1; f <= 7; f++) if (f != ISCSI_TMF_CLEAR_ACA) ok &= iscsi_tmf_static_rsp(f) == 0;
    report(ok && iscsi_tmf_static_rsp(ISCSI_TMF_CLEAR_ACA) == ISCSI_TMF_RSP_NOT_SUPPORTED,
           "TMF: 1〜7 は処理へ回す(CLEAR ACA だけ 5)");
}

static void test_login_check(void)
{
    uint8_t b[ISCSI_BHS_LEN];
    const char *why;
    iscsi_login_state_t st;
    memset(&st, 0, sizeof(st));
    login_bhs(b, 0, 0, ISCSI_STAGE_SEC, 0, 0x10, 1, 0);
    report(iscsi_login_check(&st, b, &why) == 0, "ログイン: 最初の要求を受けて ISID / CID / ITT / 段を控える");
    login_bhs(b, 1, 1, ISCSI_STAGE_SEC, ISCSI_STAGE_OP, 0x10, 1, 0);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INIT_ERR, "ログイン: C と T が両方立つと Initiator error(11.12.2)");
    login_bhs(b, 0, 0, ISCSI_STAGE_SEC, 0, 0x11, 1, 0);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INIT_ERR, "ログイン: 途中で ITT が変わると断る");
    login_bhs(b, 0, 0, ISCSI_STAGE_SEC, 0, 0x10, 2, 0);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INIT_ERR, "ログイン: 途中で CID が変わると断る");
    login_bhs(b, 0, 0, ISCSI_STAGE_SEC, 0, 0x10, 1, 7);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INIT_ERR, "ログイン: 途中で ISID が変わると断る");
    login_bhs(b, 0, 0, ISCSI_STAGE_SEC, 0, 0x10, 1, 0);
    iscsi_put16(&b[ISCSI_LOGIN_OFF_TSIH], 5);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INIT_ERR, "ログイン: 途中で TSIH が変わると断る");
    login_bhs(b, 0, 0, ISCSI_STAGE_OP, 0, 0x10, 1, 0);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INIT_ERR, "ログイン: 同意の無い段の移行(CSG が今の段と違う)を断る");
    iscsi_login_transit(&st, ISCSI_STAGE_OP);
    login_bhs(b, 0, 0, ISCSI_STAGE_SEC, 0, 0x10, 1, 0);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INIT_ERR, "ログイン: CSG の後戻り(Op -> Security)を断る");
    login_bhs(b, 1, 0, ISCSI_STAGE_OP, ISCSI_STAGE_FFP, 0x10, 1, 0);
    report(iscsi_login_check(&st, b, &why) == 0, "ログイン: 同意した段(Op)からの要求は通る");
    login_bhs(b, 1, 0, ISCSI_STAGE_OP, ISCSI_STAGE_SEC, 0x10, 1, 0);
    report(iscsi_login_check(&st, b, &why) == ISCSI_LS_INVALID_REQUEST, "ログイン: NSG <= CSG は 0x020B");
}

static void test_neg_target(void)
{
    static iscsi_neg_t n;
    uint8_t req[2048], rsp[ISCSI_LOGIN_MAX_DSL];
    const iscsi_tgt_pref_t pref = pref_tcp();
    uint32_t l;
    int r;

    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "SessionType=Normal", "TargetName=iqn.x:t",
            "TaskReporting=FastAbort,RFC3720", "iSCSIProtocolLevel=5", "X#NodeArchitecture=foo/1.0",
            "IFMarkInt=2048~8192", "OFMarker=Yes", "X-com.example.foo=1", NULL);
    r = iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    report(r > 0 && has_kv(rsp, r, "TaskReporting", "RFC3720"), "鍵: TaskReporting は RFC3720 を選ぶ(NotUnderstood にしない。13.23)");
    report(has_kv(rsp, r, "iSCSIProtocolLevel", "1") && n.p.proto_level == 1, "鍵: iSCSIProtocolLevel=5 には最小値 1 で答える(13.24)");
    report(has_kv(rsp, r, "X#NodeArchitecture", NULL), "鍵: X#NodeArchitecture は宣言として受け、答えない(13.26)");
    report(has_kv(rsp, r, "IFMarkInt", "Reject"), "鍵: 廃止された IFMarkInt は Reject(13.25)");
    report(has_kv(rsp, r, "OFMarker", "No"), "鍵: OFMarker は No(NotUnderstood ではない。13.25)");
    report(has_kv(rsp, r, "X-com.example.foo", "NotUnderstood"), "鍵: 知らない私的な鍵は NotUnderstood");

    /* 名前の宣言のし直し: 同じ値なら受ける(libiscsi)、違う値・同じ要求に 2 回は断る */
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "SessionType=Normal", "MaxBurstLength=131072", NULL);
    r = iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    report(r >= 0 && n.p.max_burst == 131072u, "鍵: 前の要求と同じ値の InitiatorName / SessionType の宣言し直しは受ける(libiscsi)");
    l = kvs(req, sizeof(req), "MaxBurstLength=65536", NULL);
    r = iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    report(r < 0 && n.fail_status == ISCSI_LS_INIT_ERR, "鍵: 同じ鍵の 2 回目の交渉は Login reject(Initiator error。6.2)");
    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "X-a=1", NULL);
    (void)iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    l = kvs(req, sizeof(req), "X-a=1", NULL);
    report(iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp)) < 0, "鍵: 知らない鍵でも 2 回目は断る");
    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "InitiatorName=iqn.x:i", NULL);
    report(iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp)) < 0, "鍵: 同じ要求に同じ宣言が 2 回あれば断る");
    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", NULL);
    (void)iscsi_neg_target(&n, &pref, ISCSI_STAGE_SEC, req, l, rsp, sizeof(rsp));
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:j", NULL);
    report(iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp)) < 0, "鍵: 宣言の値をログインの途中で変えると断る");

    /* 範囲外の値・長すぎる値は黙って切らずに断る */
    static const char *const bad[] = {
        "ErrorRecoveryLevel=3", "DefaultTime2Wait=3601", "DefaultTime2Retain=3601", "MaxBurstLength=16777216",
        "FirstBurstLength=511", "MaxOutstandingR2T=65536", "MaxConnections=0", "iSCSIProtocolLevel=32",
    };
    int ok = 1;
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        iscsi_neg_init(&n);
        l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", bad[i], NULL);
        if (iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp)) >= 0) {
            ok = 0;
            uart_printf("rfctest iscsi:   通ってしまった: %s\n", bad[i]);
        }
    }
    report(ok, "鍵: 範囲外(ERL>2、Time2Wait>3600、Burst>2^24-1 など)を断る(13 章)");
    {
        char name[300] = "InitiatorName=iqn.";
        memset(name + 18, 'a', 224 - 4);   /* 名前は 224 バイト(上限 223)*/
        name[18 + 220] = 0;
        iscsi_neg_init(&n);
        l = kvs(req, sizeof(req), name, NULL);
        report(iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp)) < 0,
               "鍵: 223 バイトを超える iSCSI 名は切らずに断る(4.2.7.1)");
        char alias[300] = "InitiatorAlias=";
        memset(alias + 15, 'b', 256);
        alias[15 + 256] = 0;
        iscsi_neg_init(&n);
        l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", alias, NULL);
        report(iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp)) < 0,
               "鍵: 255 バイトを超える値は切らずに断る(6.1)");
    }
    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "AuthMethod=None", NULL);
    report(iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp)) < 0, "鍵: 運用の段の AuthMethod(段に合わない鍵)を断る");
    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "SessionType=Discovery", "TaskReporting=RFC3720", NULL);
    r = iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    report(has_kv(rsp, r, "TaskReporting", "Irrelevant"), "鍵: Discovery では TaskReporting は Irrelevant");

    /* iSER: TaggedBufferForSolicitedDataOnly と RDMAExtensions の申し出(RFC 7145 6.3 / 6.9) */
    iscsi_tgt_pref_t ip = pref_tcp();
    ip.iser = 1;
    ip.allow_crc32c = 0;
    ip.target_recv_dsl = 8192u;
    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "SessionType=Normal", "TargetName=iqn.x:t",
            "TaggedBufferForSolicitedDataOnly=No", NULL);
    r = iscsi_neg_target(&n, &ip, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    report(r > 0 && n.p.tbsdo_set && !n.p.tbsdo && has_kv(rsp, r, "TaggedBufferForSolicitedDataOnly", "No"),
           "iSER: TaggedBufferForSolicitedDataOnly=No を受けて意味を覚える(6.9)");
    report(has_kv(rsp, r, "RDMAExtensions", "Yes") && n.rdma_offered,
           "iSER: 相手が出さなければ最初の運用の段の応答で RDMAExtensions=Yes を申し出る(6.3)");
    l = kvs(req, sizeof(req), "RDMAExtensions=Yes", NULL);
    r = iscsi_neg_target(&n, &ip, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    report(r >= 0 && n.p.rdma_ext && n.rdma_answered && has_kv(rsp, r, "RDMAExtensions", NULL),
           "iSER: 申し出への答えには答え直さない");
    iscsi_neg_init(&n);
    l = kvs(req, sizeof(req), "InitiatorName=iqn.x:i", "TaggedBufferForSolicitedDataOnly=Yes", NULL);
    r = iscsi_neg_target(&n, &pref, ISCSI_STAGE_OP, req, l, rsp, sizeof(rsp));
    report(has_kv(rsp, r, "TaggedBufferForSolicitedDataOnly", "Irrelevant") && !n.p.tbsdo_set,
           "iSER: TCP の接続では TaggedBufferForSolicitedDataOnly は Irrelevant");
}

static void test_neg_initiator(void)
{
    static iscsi_ini_neg_t n;
    uint8_t off[1024], rsp[1024], ans[512];
    uint32_t ol, rl, al;
    ol = kvs(off, sizeof(off), "HeaderDigest=None", "InitialR2T=Yes", "ImmediateData=No", "MaxBurstLength=262144",
             "DefaultTime2Wait=2", NULL);
#define INI_CASE(desc, expect_ok, ...) do { \
        memset(&n.p, 0, sizeof(n.p)); n.p.max_burst = 262144u; n.p.first_burst = 65536u; \
        iscsi_ini_neg_init(&n, 0, 0); \
        rl = kvs(rsp, sizeof(rsp), __VA_ARGS__, NULL); \
        const int r_ = iscsi_ini_neg_rsp(&n, off, ol, rsp, rl, ans, sizeof(ans), &al); \
        report((r_ == 0) == (expect_ok), desc); \
    } while (0)
    INI_CASE("イニシエータ: 規則どおりの答えは受ける", 1,
             "HeaderDigest=None", "InitialR2T=Yes", "ImmediateData=No", "MaxBurstLength=131072", "DefaultTime2Wait=5");
    INI_CASE("イニシエータ: 並びに無い HeaderDigest が選ばれたら切る", 0, "HeaderDigest=CRC32C");
    INI_CASE("イニシエータ: OR の InitialR2T(こちら Yes)に No が返ったら切る", 0, "InitialR2T=No");
    INI_CASE("イニシエータ: AND の ImmediateData(こちら No)に Yes が返ったら切る", 0, "ImmediateData=Yes");
    INI_CASE("イニシエータ: 最小値の MaxBurstLength がこちらより大きければ切る", 0, "MaxBurstLength=524288");
    INI_CASE("イニシエータ: 最大値の DefaultTime2Wait がこちらより小さければ切る", 0, "DefaultTime2Wait=1");
    INI_CASE("イニシエータ: ターゲットが同じ鍵を 2 回出したら切る(6.2)", 0, "TargetAlias=a", "TargetAlias=a");
    {
        memset(&n.p, 0, sizeof(n.p));
        iscsi_ini_neg_init(&n, 0, 0);
        rl = kvs(rsp, sizeof(rsp), "TaskReporting=RFC3720", "X-foo=1", NULL);
        const int r = iscsi_ini_neg_rsp(&n, off, ol, rsp, rl, ans, sizeof(ans), &al);
        report(r == 0 && has_kv(ans, (int)al, "TaskReporting", "RFC3720") && has_kv(ans, (int)al, "X-foo", "NotUnderstood"),
               "イニシエータ: ターゲットが申し出た鍵に答える(知らない鍵は NotUnderstood)");
    }
#undef INI_CASE
}

static void test_chap(void)
{
    iscsi_chap_cfg_t c;
    const char *why, *warn;
    memset(&c, 0, sizeof(c));
    c.set = 1;
    memcpy(c.user, "u", 2);
    memcpy(c.secret, "0123456789abcdef", 16);
    c.slen = 16;
    c.mutual = 1;
    memcpy(c.muser, "m", 2);
    memcpy(c.msecret, "0123456789abcdef", 16);
    c.mlen = 16;
    report(iscsi_chap_cfg_check(&c, &why, &warn) < 0, "CHAP: 両方向に同じ秘密の設定を断る(12.1.3)");
    memcpy(c.msecret, "short", 5);
    c.mlen = 5;
    report(iscsi_chap_cfg_check(&c, &why, &warn) == 0 && warn != NULL, "CHAP: 96 ビット未満の秘密は断らずに警告(SHOULD)");
    memcpy(c.msecret, "fedcba9876543210", 16);
    c.mlen = 16;
    report(iscsi_chap_cfg_check(&c, &why, &warn) == 0 && warn == NULL, "CHAP: 別々の 16 バイトの秘密は通る");
    uint8_t chal[32], r1[64], r2[64];
    for (unsigned i = 0; i < sizeof(chal); i++) chal[i] = (uint8_t)(i * 37u + 1u);
    const uint32_t l1 = iscsi_chap_response(7, 9, c.secret, c.slen, chal, 32, r1);
    const uint32_t l2 = iscsi_chap_response(7, 9, c.msecret, c.mlen, chal, 32, r2);
    report(iscsi_chap_is_own_response(7, 9, c.secret, c.slen, chal, 32, r1, l1) == 1,
           "CHAP: 受けた答えが自分の秘密での答えと等しければ失敗とみなす(12.1.3)");
    report(iscsi_chap_is_own_response(7, 9, c.secret, c.slen, chal, 32, r2, l2) == 0,
           "CHAP: 別の秘密での答えは自分のものとみなさない");
}

static void test_scsi(void)
{
    scsi_ua_t ua;
    memset(&ua, 0, sizeof(ua));
    scsi_ua_set(&ua, 1u, SCSI_ASC_RESET_OCCURRED, SCSI_ASCQ_BUS_DEVICE_RESET);
    uint8_t cdb[16] = {0}, buf[96] = {0};
    scsi_result_t r;
    memset(&r, 0, sizeof(r));
    r.status = SCSI_STATUS_GOOD;
    r.dir = SCSI_DIR_READ;
    r.data = buf;
    r.len = 36;
    cdb[0] = 0x12;   /* INQUIRY */
    report(scsi_ua_apply(&ua, 0, cdb, &r) == 0 && r.status == SCSI_STATUS_GOOD && ua.any,
           "UA: INQUIRY は Unit Attention を報告せずに通す(SPC-4 5.14)");
    cdb[0] = 0x88;   /* READ(16) */
    report(scsi_ua_apply(&ua, 0, cdb, &r) == 1 && r.status == SCSI_STATUS_CHECK_CONDITION &&
           r.sk == SCSI_SK_UNIT_ATTENTION && r.asc == 0x29 && r.ascq == 0x03 && !ua.any,
           "UA: LU RESET の後の最初のコマンドは CHECK CONDITION / UNIT ATTENTION 29/03 で消える");
    scsi_ua_set(&ua, 1u, SCSI_ASC_CMDS_CLEARED, 0);
    memset(&r, 0, sizeof(r));
    memset(buf, 0, sizeof(buf));
    r.status = SCSI_STATUS_GOOD;
    r.data = buf;
    r.len = 18;
    cdb[0] = 0x03;   /* REQUEST SENSE */
    report(scsi_ua_apply(&ua, 0, cdb, &r) == 1 && r.status == SCSI_STATUS_GOOD && buf[2] == SCSI_SK_UNIT_ATTENTION &&
           buf[12] == 0x2F && !ua.any, "UA: REQUEST SENSE はセンスとして返して消す");
    memset(&r, 0, sizeof(r));
    memset(buf, 0, sizeof(buf));
    iscsi_put16(&buf[60], 0x0960);
    r.status = SCSI_STATUS_GOOD;
    r.data = buf;
    r.len = 96;
    cdb[0] = 0x12;
    cdb[1] = 0;
    scsi_inquiry_set_iscsi_level(cdb, &r, 1);
    report(iscsi_be16(&buf[60]) == 0x0961, "INQUIRY: 版記述子は 0960h + 合意した iSCSIProtocolLevel(RFC 7144 4.2)");
}

static void test_cmdsn(void)
{
    const size_t sz = iscsit_selftest_size();
    void *mem = malloc(sz);
    if (!mem) { report(0, "CmdSN: 試験の領域が取れない"); return; }
    (void)iscsit_selftest_cmdsn(mem, report);
    free(mem);
}

void rfctest_iscsi(const char *args)
{
    (void)args;
    s_n = s_ng = 0;
    test_tmf();
    test_login_check();
    test_neg_target();
    test_neg_initiator();
    test_chap();
    test_scsi();
    test_cmdsn();
    uart_printf("rfctest iscsi: %s(%u 項目中 NG %u)\n", s_ng ? "NG" : "PASS", s_n, s_ng);
}
