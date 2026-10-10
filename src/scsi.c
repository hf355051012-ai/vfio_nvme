/* SCSI のブロック装置(SBC-3 / SPC-4 の最小集合)。scsi.h の説明を参照。
 *
 * **Linux の sd がログイン直後に投げてくるものは全部さばく**のが基準(段階 0 の記録):
 * INQUIRY(標準 / VPD 0x00 / 0x80 / 0x83 / 0xB0 / 0xB1 / 0xB2)、TEST UNIT READY、
 * READ CAPACITY(10 / 16)、REPORT LUNS、MODE SENSE(6 / 10)、REPORT SUPPORTED OPERATION
 * CODES、READ / WRITE(6 / 10 / 12 / 16)、SYNCHRONIZE CACHE。
 * **知らないものには CHECK CONDITION / ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE を返す。
 * 黙って成功を返さない**(NVMe の Set Features で踏んだ「知らない値にも成功」を繰り返さない)。 */
#include "scsi.h"
#include "iscsi.h"   /* SCSI_STATUS_* */
#include <string.h>

static scsi_lun_t s_lun[SCSI_MAX_LUNS];

void scsi_set_lun(unsigned lun, uint8_t *disk, uint64_t nblocks, const char *serial)
{
    if (lun >= SCSI_MAX_LUNS) return;
    s_lun[lun].disk = disk;
    s_lun[lun].nblocks = nblocks;
    memset(s_lun[lun].serial, 0, sizeof(s_lun[lun].serial));
    if (serial) strncpy(s_lun[lun].serial, serial, sizeof(s_lun[lun].serial) - 1u);
}

const scsi_lun_t *scsi_get_lun(unsigned lun)
{
    return (lun < SCSI_MAX_LUNS && s_lun[lun].disk) ? &s_lun[lun] : NULL;
}

unsigned scsi_decode_lun(const uint8_t l[8])
{
    switch (l[0] >> 6) {
    case 0: return l[1];                                   /* 周辺デバイスの番地(バス 0)*/
    case 1: return ((unsigned)(l[0] & 0x3Fu) << 8) | l[1];  /* フラット */
    default: return 0xFFFFu;
    }
}

static uint32_t be32(const uint8_t *p) { return iscsi_be32(p); }
static uint64_t be64(const uint8_t *p) { return ((uint64_t)be32(p) << 32) | be32(p + 4); }
static void put64(uint8_t *p, uint64_t v) { iscsi_put32(p, (uint32_t)(v >> 32)); iscsi_put32(p + 4, (uint32_t)v); }

static void check(scsi_result_t *r, uint8_t sk, uint8_t asc, uint8_t ascq)
{
    r->status = SCSI_STATUS_CHECK_CONDITION;
    r->sk = sk; r->asc = asc; r->ascq = ascq;
    r->dir = SCSI_DIR_NONE;
    r->data = NULL;
    r->len = 0;
}

/* buf に組み立てた応答を、CDB の割り当て長で切って返す。 */
static void reply(scsi_result_t *r, uint8_t *buf, uint32_t n, uint32_t alloc)
{
    r->status = SCSI_STATUS_GOOD;
    r->dir = SCSI_DIR_READ;
    r->data = buf;
    r->len = n < alloc ? n : alloc;
}

/* ---- INQUIRY ---- */

/* VPD 0x83 の識別子。**NVMe の NGUID / EUI-64 と同じ考え方**: 先頭にローカル管理を示す値を
 * 置いて実在の OUI を騙らず、末尾に LUN を入れる。NAA 3(ローカル割り当て、8 バイト)。 */
static uint32_t vpd_devid(unsigned lun, const scsi_lun_t *L, uint8_t *b)
{
    uint32_t o = 4;
    /* NAA 3 */
    b[o++] = 0x01;           /* プロトコル 0 / コードセット 1 = バイナリ */
    b[o++] = 0x03;           /* PIV 0 / 関連付け 0 = 論理装置 / 種類 3 = NAA */
    b[o++] = 0;
    b[o++] = 8;
    b[o++] = 0x30; b[o++] = 0x02; b[o++] = 'v'; b[o++] = 'f';
    b[o++] = 'i'; b[o++] = 'o'; b[o++] = 0x00; b[o++] = (uint8_t)lun;
    /* T10 ベンダ識別子(ASCII): "VFIONVME" + 通し番号 */
    const uint32_t sl = (uint32_t)strlen(L->serial);
    b[o++] = 0x02;           /* コードセット 2 = ASCII */
    b[o++] = 0x01;           /* 種類 1 = T10 ベンダ識別子 */
    b[o++] = 0;
    b[o++] = (uint8_t)(8u + sl);
    memcpy(&b[o], "VFIONVME", 8); o += 8;
    memcpy(&b[o], L->serial, sl); o += sl;
    b[0] = 0; b[1] = 0x83;
    iscsi_put16(&b[2], (uint16_t)(o - 4u));
    return o;
}

static void do_inquiry(unsigned lun, const uint8_t *cdb, uint8_t *b, uint32_t cap, scsi_result_t *r)
{
    const scsi_lun_t *L = scsi_get_lun(lun);
    const uint32_t alloc = iscsi_be16(&cdb[3]);
    const int evpd = cdb[1] & 1;
    memset(b, 0, cap < 256u ? cap : 256u);
    if (!evpd) {
        if (cdb[2] != 0) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0); return; }
        /* 無い LUN には「周辺装置は接続されていない」(PQ=3、PDT=0x1F)を返す(SPC-4 6.6.2)。 */
        b[0] = L ? 0x00 : 0x7F;
        b[2] = 0x06;              /* SPC-4 */
        b[3] = 0x02;              /* 応答データ形式 2 */
        b[4] = 96 - 5;            /* 追加長 */
        b[7] = 0x02;              /* CmdQue */
        memcpy(&b[8], "VFIONVME", 8);
        memcpy(&b[16], "RAMDISK         ", 16);
        memcpy(&b[32], "0001", 4);
        /* 版記述子(SPC-4 6.6.2 / 表 49)。**SBC-3 への準拠はここで宣言する** -- 宣言しないで
         * SBC-3 の長さの VPD 0xB0 を返すと iscsi-test-cu の Inquiry.BlockLimits が咎める。 */
        iscsi_put16(&b[58], 0x00A0);   /* SAM-5 */
        iscsi_put16(&b[60], 0x0960);   /* iSCSI */
        iscsi_put16(&b[62], 0x0460);   /* SPC-4 */
        iscsi_put16(&b[64], 0x04C0);   /* SBC-3 */
        reply(r, b, 96, alloc);
        return;
    }
    if (!L) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_LUN_NOT_SUPPORTED, 0); return; }
    uint32_t n = 0;
    switch (cdb[2]) {
    case 0x00: {   /* 対応する VPD の一覧 */
        static const uint8_t pages[] = { 0x00, 0x80, 0x83, 0xB0, 0xB1, 0xB2 };
        b[1] = 0x00;
        b[3] = sizeof(pages);
        memcpy(&b[4], pages, sizeof(pages));
        n = 4u + sizeof(pages);
        break;
    }
    case 0x80: {   /* 通し番号 */
        const uint32_t sl = (uint32_t)strlen(L->serial);
        b[1] = 0x80;
        b[3] = (uint8_t)sl;
        memcpy(&b[4], L->serial, sl);
        n = 4u + sl;
        break;
    }
    case 0x83:
        n = vpd_devid(lun, L, b);
        break;
    case 0xB0:     /* Block Limits(SBC-3 6.6.3)*/
        b[1] = 0xB0;
        b[3] = 0x3C;
        iscsi_put32(&b[8], 0x4000u);    /* 最大転送長 16384 ブロック = 8MiB(LIO と同じ)*/
        iscsi_put32(&b[12], 0x4000u);   /* 最適転送長 */
        /* UNMAP は持たない(最大 UNMAP 数は 0 のまま)。 */
        n = 64;
        break;
    case 0xB1:     /* Block Device Characteristics */
        b[1] = 0xB1;
        b[3] = 0x3C;
        iscsi_put16(&b[4], 1);          /* 回転しない媒体 */
        n = 64;
        break;
    case 0xB2:     /* Logical Block Provisioning(thin provisioning は持たない)*/
        b[1] = 0xB2;
        b[3] = 4;
        n = 8;
        break;
    default:
        check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0);
        return;
    }
    reply(r, b, n, alloc);
}

/* ---- MODE SENSE ---- */

/* ページを 1 つ書き足す。pc = 0 現在値 / 1 変更可能(全部 0 = 変えられない)/ 2 既定値。 */
static uint32_t mode_page(uint8_t page, uint8_t pc, uint8_t *b)
{
    switch (page) {
    case 0x01:     /* Read-Write Error Recovery */
        memset(b, 0, 12);
        b[0] = 0x01; b[1] = 0x0A;
        return 12;
    case 0x08:     /* Caching。**WCE=0**(書き込みは RAM へ直接入る。LIO も 0)*/
        memset(b, 0, 20);
        b[0] = 0x08; b[1] = 0x12;
        (void)pc;
        return 20;
    case 0x0A:     /* Control */
        memset(b, 0, 12);
        b[0] = 0x0A; b[1] = 0x0A;
        if (pc != 1) b[2] = 0x02;   /* GLTSD */
        return 12;
    default:
        return 0;
    }
}

static void do_mode_sense(unsigned lun, const uint8_t *cdb, int ten, uint8_t *b, uint32_t cap, scsi_result_t *r)
{
    const scsi_lun_t *L = scsi_get_lun(lun);
    if (!L) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_LUN_NOT_SUPPORTED, 0); return; }
    const int dbd = (cdb[1] & 0x08) != 0;
    const uint8_t pc = (uint8_t)(cdb[2] >> 6), page = cdb[2] & 0x3Fu, sub = cdb[3];
    const uint32_t alloc = ten ? iscsi_be16(&cdb[7]) : cdb[4];
    if (pc == 3) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_SAVING_NOT_SUPPORTED, 0); return; }
    /* サブページは持たない(0x3F / 0xFF の「全部」だけ受ける)。sd はページ 0x0A の
     * サブページ 0x05 を問い合わせてくる -- LIO も 5 / 24 で断る(段階 0 の記録)。 */
    if (sub != 0 && !(page == 0x3F && sub == 0xFF)) {
        check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0);
        return;
    }
    memset(b, 0, cap < 512u ? cap : 512u);
    const uint32_t hdr = ten ? 8u : 4u;
    uint32_t o = hdr;
    if (!dbd) {   /* ブロック記述子(短い形 8 バイト)*/
        const uint64_t nb = L->nblocks > 0xFFFFFFu && !ten ? 0xFFFFFFu : L->nblocks;
        if (ten) iscsi_put32(&b[o], nb > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)nb);
        else iscsi_put24(&b[o + 1], (uint32_t)nb);
        iscsi_put24(&b[o + 5], SCSI_BLOCK_SIZE);
        o += 8;
    }
    if (page == 0x3F) {
        o += mode_page(0x01, pc, &b[o]);
        o += mode_page(0x08, pc, &b[o]);
        o += mode_page(0x0A, pc, &b[o]);
    } else {
        const uint32_t n = mode_page(page, pc, &b[o]);
        if (n == 0) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0); return; }
        o += n;
    }
    /* 装置固有の値: DPOFUA=1。**RAM へ直接書くので FUA(媒体へ届いてから完了)も DPO も
     * 自明に満たせる。** 0 を広告すると、CDB の DPO / FUA を INVALID FIELD で断る義務が出る。 */
    if (ten) {
        iscsi_put16(&b[0], (uint16_t)(o - 2u));   /* モードデータ長(自分を除く)*/
        b[3] = 0x10;
        iscsi_put16(&b[6], dbd ? 0 : 8);
    } else {
        b[0] = (uint8_t)(o - 1u);
        b[2] = 0x10;
        b[3] = dbd ? 0 : 8;
    }
    reply(r, b, o, alloc);
}

/* ---- REPORT SUPPORTED OPERATION CODES(SPC-4 6.35)---- */

typedef struct { uint8_t op; uint16_t sa; uint8_t has_sa; uint8_t cdb_len; } opinfo_t;

static const opinfo_t s_ops[] = {
    { 0x00, 0, 0, 6 },  { 0x03, 0, 0, 6 },  { 0x08, 0, 0, 6 },  { 0x0A, 0, 0, 6 },
    { 0x12, 0, 0, 6 },  { 0x1A, 0, 0, 6 },  { 0x1B, 0, 0, 6 },  { 0x25, 0, 0, 10 },
    { 0x28, 0, 0, 10 }, { 0x2A, 0, 0, 10 }, { 0x2F, 0, 0, 10 }, { 0x35, 0, 0, 10 },
    { 0x5A, 0, 0, 10 }, { 0x88, 0, 0, 16 }, { 0x8A, 0, 0, 16 }, { 0x8F, 0, 0, 16 },
    { 0x91, 0, 0, 16 }, { 0x9E, 0x10, 1, 16 }, { 0xA0, 0, 0, 12 }, { 0xA3, 0x0C, 1, 12 },
    { 0xA8, 0, 0, 12 }, { 0xAA, 0, 0, 12 },
};

/* コマンドのタイムアウト記述子(SPC-4 6.35.4、12 バイト)。RCTD=1 のときに付ける。 */
static uint32_t put_timeouts(uint8_t *p)
{
    memset(p, 0, 12);
    iscsi_put16(&p[0], 0x000A);   /* 記述子長 */
    iscsi_put32(&p[4], 1);        /* 標準の処理時間(秒)*/
    iscsi_put32(&p[8], 30);       /* 推奨のタイムアウト(秒)*/
    return 12;
}

static void do_rsoc(const uint8_t *cdb, uint8_t *b, uint32_t cap, scsi_result_t *r)
{
    const uint8_t opt = cdb[2] & 7u, rop = cdb[3];
    const int rctd = (cdb[2] & 0x80) != 0;
    const uint16_t rsa = iscsi_be16(&cdb[4]);
    const uint32_t alloc = be32(&cdb[6]);
    const unsigned nops = sizeof(s_ops) / sizeof(s_ops[0]);
    if (opt == 0) {
        uint32_t o = 4;
        for (unsigned i = 0; i < nops && o + 20u <= cap; i++) {
            memset(&b[o], 0, 8);
            b[o] = s_ops[i].op;
            iscsi_put16(&b[o + 2], s_ops[i].sa);
            b[o + 5] = (uint8_t)((s_ops[i].has_sa ? 0x01 : 0x00) | (rctd ? 0x02 : 0x00));   /* SERVACTV / CTDP */
            iscsi_put16(&b[o + 6], s_ops[i].cdb_len);
            o += 8;
            if (rctd) o += put_timeouts(&b[o]);
        }
        iscsi_put32(&b[0], o - 4u);
        reply(r, b, o, alloc);
        return;
    }
    if (opt != 1 && opt != 2) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0); return; }
    const opinfo_t *hit = NULL;
    for (unsigned i = 0; i < nops; i++) {
        if (s_ops[i].op != rop) continue;
        /* 1 = サービスアクションの無いコマンドとして、2 = サービスアクション付きで問う。
         * 食い違えば ILLEGAL REQUEST(SPC-4 6.35.2)。 */
        if (opt == 1 && s_ops[i].has_sa) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0); return; }
        if (opt == 2 && !s_ops[i].has_sa) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0); return; }
        if (opt == 2 && s_ops[i].sa != rsa) continue;
        hit = &s_ops[i];
        break;
    }
    memset(b, 0, 4u + 16u);
    if (!hit) {
        b[1] = 0x01;   /* 対応していない */
        reply(r, b, 4, alloc);
        return;
    }
    b[1] = (uint8_t)(0x03 | (rctd ? 0x80 : 0));   /* 規格どおりに対応している / CTDP */
    iscsi_put16(&b[2], hit->cdb_len);
    /* CDB の使い方の地図: 1 バイト目はオペコード、残りは全部のビットを解釈する、とする
     * (DPO / FUA も受け付けるので立てたままでよい)。 */
    b[4] = hit->op;
    for (unsigned i = 1; i < hit->cdb_len; i++) b[4 + i] = 0xFF;
    if (hit->has_sa) b[5] = (uint8_t)(hit->sa & 0x1Fu);
    uint32_t o = 4u + hit->cdb_len;
    if (rctd) o += put_timeouts(&b[o]);
    reply(r, b, o, alloc);
}

/* ---- READ / WRITE ---- */

static void do_rw(unsigned lun, uint64_t lba, uint32_t nblk, int write, scsi_result_t *r)
{
    const scsi_lun_t *L = scsi_get_lun(lun);
    if (!L) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_LUN_NOT_SUPPORTED, 0); return; }
    if (lba > L->nblocks || (uint64_t)nblk > L->nblocks - lba) {
        check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_LBA_OUT_OF_RANGE, 0);
        return;
    }
    r->status = SCSI_STATUS_GOOD;
    r->dir = nblk ? (write ? SCSI_DIR_WRITE : SCSI_DIR_READ) : SCSI_DIR_NONE;
    r->data = L->disk + lba * SCSI_BLOCK_SIZE;
    r->len = nblk * SCSI_BLOCK_SIZE;
}

int scsi_verify_cmp(const scsi_result_t *r, uint32_t off, const uint8_t *buf, uint32_t len)
{
    if (r->verify_mode == 1) return memcmp(r->data + off, buf, len) != 0;
    /* BYTCHK=3: 1 ブロックを範囲の全ブロックと比べる(受け取りは 1 ブロック = 1 回で済む)。 */
    if (off != 0 || len != SCSI_BLOCK_SIZE) return 1;
    for (uint32_t i = 0; i < r->verify_blocks; i++)
        if (memcmp(r->data + (uint64_t)i * SCSI_BLOCK_SIZE, buf, SCSI_BLOCK_SIZE) != 0) return 1;
    return 0;
}

void scsi_exec(unsigned lun, const uint8_t cdb[16], uint8_t *b, uint32_t cap, scsi_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->status = SCSI_STATUS_GOOD;
    const scsi_lun_t *L = scsi_get_lun(lun);
    const uint8_t op = cdb[0];

    /* LUN が無くても答えるもの: INQUIRY / REPORT LUNS / REQUEST SENSE。 */
    switch (op) {
    case 0x12:   /* INQUIRY */
        do_inquiry(lun, cdb, b, cap, r);
        return;
    case 0xA0: { /* REPORT LUNS */
        const uint32_t alloc = be32(&cdb[6]);
        if (alloc < 16u) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0); return; }
        uint32_t o = 8;
        memset(b, 0, 8u + 8u * SCSI_MAX_LUNS);
        for (unsigned i = 0; i < SCSI_MAX_LUNS; i++) {
            if (!s_lun[i].disk) continue;
            b[o + 1] = (uint8_t)i;   /* 周辺デバイスの番地 */
            o += 8;
        }
        iscsi_put32(&b[0], o - 8u);
        reply(r, b, o, alloc);
        return;
    }
    case 0x03: { /* REQUEST SENSE(自動センスなので、ここでは「何もない」を返す)*/
        memset(b, 0, 18);
        b[0] = 0x70;
        b[7] = 10;
        if (!L) { b[2] = SCSI_SK_ILLEGAL_REQUEST; b[12] = SCSI_ASC_LUN_NOT_SUPPORTED; }
        reply(r, b, 18, cdb[4]);
        return;
    }
    default:
        break;
    }
    if (!L) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_LUN_NOT_SUPPORTED, 0); return; }

    switch (op) {
    case 0x00:   /* TEST UNIT READY */
    case 0x1B:   /* START STOP UNIT */
    case 0x35:   /* SYNCHRONIZE CACHE(10)。RAM なので永続化するものが無い(NVMe の Flush と同じ)*/
    case 0x91:   /* SYNCHRONIZE CACHE(16) */
        return;
    case 0x2F:   /* VERIFY(10) */
    case 0x8F: { /* VERIFY(16) */
        /* BYTCHK(SBC-3 5.33): 0 = 媒体を確かめるだけ(RAM なので範囲の確認だけ)/
         * 1 = 受け取ったデータと範囲全体を比べる / 3 = 受け取った 1 ブロックを範囲の
         * 全ブロックと比べる / 2 = 予約。VRPROTECT は持たない。 */
        const uint8_t bytchk = (cdb[1] >> 1) & 3u;
        if (bytchk == 2 || (cdb[1] & 0xE0)) { check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0); return; }
        const uint64_t lba = op == 0x2F ? be32(&cdb[2]) : be64(&cdb[2]);
        const uint32_t n = op == 0x2F ? iscsi_be16(&cdb[7]) : be32(&cdb[10]);
        do_rw(lun, lba, n, 0, r);
        if (r->status != SCSI_STATUS_GOOD) return;
        if (bytchk == 0 || n == 0) {
            r->dir = SCSI_DIR_NONE;
            r->len = 0;
            return;
        }
        r->dir = SCSI_DIR_VERIFY;
        r->verify_mode = bytchk;
        r->verify_blocks = n;
        if (bytchk == 3) r->len = SCSI_BLOCK_SIZE;   /* 受け取るのは 1 ブロックだけ */
        return;
    }
    case 0x25: { /* READ CAPACITY(10) */
        memset(b, 0, 8);
        const uint64_t last = L->nblocks - 1u;
        iscsi_put32(&b[0], last > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)last);
        iscsi_put32(&b[4], SCSI_BLOCK_SIZE);
        reply(r, b, 8, 8);
        return;
    }
    case 0x9E:   /* SERVICE ACTION IN(16) */
        if ((cdb[1] & 0x1Fu) == 0x10) {   /* READ CAPACITY(16) */
            memset(b, 0, 32);
            put64(&b[0], L->nblocks - 1u);
            iscsi_put32(&b[8], SCSI_BLOCK_SIZE);
            /* LBPME=0(thin provisioning なし)、保護なし、物理ブロック = 論理ブロック */
            reply(r, b, 32, be32(&cdb[10]));
            return;
        }
        break;
    case 0x1A:   /* MODE SENSE(6) */
        do_mode_sense(lun, cdb, 0, b, cap, r);
        return;
    case 0x5A:   /* MODE SENSE(10) */
        do_mode_sense(lun, cdb, 1, b, cap, r);
        return;
    case 0xA3:   /* MAINTENANCE IN */
        if ((cdb[1] & 0x1Fu) == 0x0C) { do_rsoc(cdb, b, cap, r); return; }
        break;
    /* ---- READ / WRITE。RDPROTECT / WRPROTECT は持たない(0 以外は断る)---- */
    case 0x08: case 0x0A: {   /* READ(6) / WRITE(6)。転送長 0 は 256 ブロック */
        const uint32_t lba = ((uint32_t)(cdb[1] & 0x1Fu) << 16) | ((uint32_t)cdb[2] << 8) | cdb[3];
        do_rw(lun, lba, cdb[4] ? cdb[4] : 256u, op == 0x0A, r);
        return;
    }
    /* DPO / FUA(byte1 の 0x10 / 0x08)は受け付ける(MODE SENSE で DPOFUA=1 を広告している)。 */
    case 0x28: case 0x2A:     /* READ(10) / WRITE(10) */
        if (cdb[1] & 0xE0) break;
        do_rw(lun, be32(&cdb[2]), iscsi_be16(&cdb[7]), op == 0x2A, r);
        return;
    case 0xA8: case 0xAA:     /* READ(12) / WRITE(12) */
        if (cdb[1] & 0xE0) break;
        do_rw(lun, be32(&cdb[2]), be32(&cdb[6]), op == 0xAA, r);
        return;
    case 0x88: case 0x8A:     /* READ(16) / WRITE(16) */
        if (cdb[1] & 0xE0) break;
        do_rw(lun, be64(&cdb[2]), be32(&cdb[10]), op == 0x8A, r);
        return;
    default:
        check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_OPCODE, 0);
        return;
    }
    /* ここへ来るのは「オペコードは知っているが欄が不正」 */
    if (op == 0x28 || op == 0x2A || op == 0xA8 || op == 0xAA || op == 0x88 || op == 0x8A)
        check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_CDB, 0);
    else
        check(r, SCSI_SK_ILLEGAL_REQUEST, SCSI_ASC_INVALID_OPCODE, 0);
}
