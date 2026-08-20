#include <stddef.h>
#include "nvmet.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "job.h"
#include "tcp.h"
#include "crc32c.h"

int g_nvmet_force_pull = 0;

#define NVMET_ACCEPT_TIMEOUT_MS    30000u
/* IO キューが切れてから admin キューを相手が閉じるのを待つ上限。Linux は
 * 即座に CC.SHN を書いて閉じるので通常は数 ms しか使わない。 */
#define NVMET_ADMIN_LINGER_MS      10000u

#define NVMET_ADMIN_DATA_BUF_MAX NVME_TCP_INLINE_DATA_MAX

#define NVMET_IO_DATA_BUF_MAX NVMET_MAX_TRANSFER_BYTES

#define NVMET_SC_GENERIC_ERROR 0x0002u

static void nvmet_zero(void *p, size_t len)
{
    uint8_t *b = p;
    for (size_t i = 0; i < len; i++) b[i] = 0;
}

static void nvmet_copy_padded(volatile uint8_t *dst, const char *src, uint32_t field_len)
    __attribute__((noinline));

static void nvmet_copy_padded(volatile uint8_t *dst, const char *src, uint32_t field_len)
{
    uint32_t src_len = 0;
    while (src[src_len] != '\0') src_len++;
    if (src_len > field_len) src_len = field_len;

    volatile_fast_copy(dst, (const volatile uint8_t *)src, src_len);
    for (uint32_t i = src_len; i < field_len; i++) {
        dst[i] = ' ';
    }
}

/*=================================================================
 * 16bit 値を 10 進 ASCII 文字列にする(Discovery Log Page の trsvcid 用)。
 * 書き込み先はゼロ埋め済みである前提なので NUL 終端は書かない。
 *
 * 引数:
 *   dst - 書き込み先(6 バイト以上)
 *   v   - 変換する値
 * コール元:
 *   nvmet_build_disc_log()
 * ===============================================================*/
static void nvmet_u16_to_dec(uint8_t *dst, uint16_t v)
{
    char tmp[6];
    unsigned n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0 && n < sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    }
    for (unsigned i = 0; i < n; i++) dst[i] = (uint8_t)tmp[n - 1u - i];
}

/*=================================================================
 * netaddr_t を Discovery Log Page の traddr に載せる ASCII 表記へ変換する
 * (IPv4 は "192.168.101.11"、IPv6 は RFC 4291 の完全表記
 * "fe80:0000:...:1010" -- "::" 省略はしない)。
 *
 * 省略しないのは、ホスト側(nvme-cli / カーネル)が inet_pton 相当で読むので
 * 完全表記でも問題が無く、実装が単純で間違えにくいため。書き込み先は
 * ゼロ埋め済みである前提なので NUL 終端は書かない。
 *
 * 引数:
 *   dst  - 書き込み先(46 バイト以上)
 *   addr - 変換するアドレス(NULL や未設定なら何も書かない)
 * コール元:
 *   nvmet_build_disc_log()
 * ===============================================================*/
static void nvmet_addr_to_str(uint8_t *dst, const netaddr_t *addr)
{
    static const char hex[] = "0123456789abcdef";
    unsigned o = 0;
    if (addr == NULL || netaddr_is_unset(addr)) return;

    if (addr->family == NETADDR_V6) {
        for (unsigned g = 0; g < 8; g++) {
            if (g > 0) dst[o++] = ':';
            dst[o++] = (uint8_t)hex[(addr->a[g * 2] >> 4) & 0xFu];
            dst[o++] = (uint8_t)hex[addr->a[g * 2] & 0xFu];
            dst[o++] = (uint8_t)hex[(addr->a[g * 2 + 1] >> 4) & 0xFu];
            dst[o++] = (uint8_t)hex[addr->a[g * 2 + 1] & 0xFu];
        }
        return;
    }
    for (unsigned i = 0; i < 4; i++) {
        if (i > 0) dst[o++] = '.';
        uint8_t v = addr->a[i];
        if (v >= 100u) dst[o++] = (uint8_t)('0' + (v / 100u));
        if (v >= 10u)  dst[o++] = (uint8_t)('0' + ((v / 10u) % 10u));
        dst[o++] = (uint8_t)('0' + (v % 10u));
    }
}

/*=================================================================
 * Fabrics Connect のデータに入っていた subnqn が Discovery NQN かを判定する。
 *
 * 比較対象は固定長 256 バイトのフィールドなので、NUL 終端されていない場合も
 * 考慮して「期待文字列の長さぶん一致し、その次がフィールド終端か NUL」で見る。
 *
 * 引数:
 *   nqn - Connect データの subsysnqn フィールド先頭(256 バイト)
 * 戻り値:
 *   1=Discovery NQN、0=それ以外
 * コール元:
 *   nvmet_admin_dispatch()
 * ===============================================================*/
static int nvmet_nqn_is_discovery(const uint8_t *nqn)
{
    const char *want = NVMET_DISCOVERY_NQN;
    unsigned i = 0;
    for (; want[i] != '\0'; i++) {
        if (i >= 256u || nqn[i] != (uint8_t)want[i]) return 0;
    }
    return (i >= 256u) || (nqn[i] == 0u);
}

/*=================================================================
 * Identify Controller 応答(4096 バイト)を組み立てる。SN/MN/FR、MDTS、
 * IOCCSZ/IORCSZ(in-capsule 上限)、MAXCMD、CAP 相当の値を設定する。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * コール元:
 *   nvmet_job_start()
 * ===============================================================*/
static void nvmet_build_id_ctrl(nvmet_ctx_t *ctx)
{
    nvmet_zero(ctx->id_ctrl, sizeof(ctx->id_ctrl));
    wr16le(&ctx->id_ctrl[0], 0x1AF4);                                       /* VID (Red Hatで代用) */
    nvmet_copy_padded(&ctx->id_ctrl[4],  "RPI5-NVMET", 20);                 /* SN [4..23] */
    nvmet_copy_padded(&ctx->id_ctrl[24], "RPi5 Bare-Metal NVMe Target", 40); /* MN [24..63] */
    nvmet_copy_padded(&ctx->id_ctrl[64], "1.0", 8);                         /* FR [64..71] */
    ctx->id_ctrl[77] = 6;                       /* MDTS = 6 (2^6 * 4KB = 256KB、NVMET_MAX_TRANSFER_BYTES参照) */

    wr16le(&ctx->id_ctrl[78], 1);                /* CNTLID = 1 (ctx->ctrlr_idと一致させる) */

    ctx->id_ctrl[111] = 1;                      /* CNTRLTYPE = 1 (I/O controller) */

    wr16le(&ctx->id_ctrl[320], 2);               /* KAS = 2 (200ms単位、値自体は非0であれば可) */

    wr32le(&ctx->id_ctrl[536], 1u);              /* SGLS bit0 = SGL Supported */

    {
        const char *subnqn = NVMET_SUBNQN;
        uint32_t len = 0;
        while (subnqn[len] != '\0') len++;
        volatile_fast_copy(&ctx->id_ctrl[768], (const volatile uint8_t *)subnqn, len);
    }

    wr32le(&ctx->id_ctrl[516], 1);               /* NN: namespace count = 1 */

    ctx->id_ctrl[512] = (6u << 4) | 6u;          /* SQES: 64バイト固定 */
    ctx->id_ctrl[513] = (4u << 4) | 4u;          /* CQES: 16バイト固定 */

    wr16le(&ctx->id_ctrl[514], 32);              /* MAXCMD = 32 */

    wr32le(&ctx->id_ctrl[1792], (64u + NVMET_IOCCSZ_MAX_BYTES) / 16u);
    wr32le(&ctx->id_ctrl[1796], NVME_CQE_LEN / 16u);                   /* IORCSZ: CQE(16B)分のみ */
    ctx->id_ctrl[1803] = 1;                      /* MSDBD = 1 */
}

/*=================================================================
 * Discovery コントローラ用の Identify Controller 応答を組み立てる。
 *
 * 通常のコントローラとの違いは 3 つだけ:
 *  - CNTRLTYPE = 2(Discovery controller。Linux の enum nvme_ctrl_type の
 *    NVME_CTRL_DISC)
 *  - SUBNQN = Discovery NQN
 *  - 名前空間を持たないので NN = 0(名前空間関連のフィールドも設定しない)
 *
 * MAXCMD / SGLS / IOCCSZ / IORCSZ は Fabrics に必須なので通常側と同じ値を
 * 入れる(これらが 0 だとホストが接続を諦める)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * コール元:
 *   nvmet_job_start()
 * ===============================================================*/
static void nvmet_build_id_ctrl_disc(nvmet_ctx_t *ctx)
{
    nvmet_zero(ctx->id_ctrl_disc, sizeof(ctx->id_ctrl_disc));
    wr16le(&ctx->id_ctrl_disc[0], 0x1AF4);                                   /* VID */
    nvmet_copy_padded(&ctx->id_ctrl_disc[4],  "RPI5-NVMET", 20);             /* SN */
    nvmet_copy_padded(&ctx->id_ctrl_disc[24], "RPi5 Discovery Controller", 40); /* MN */
    nvmet_copy_padded(&ctx->id_ctrl_disc[64], "1.0", 8);                     /* FR */
    ctx->id_ctrl_disc[77] = 6;                   /* MDTS */

    wr16le(&ctx->id_ctrl_disc[78], 1);            /* CNTLID */
    ctx->id_ctrl_disc[111] = 2;                  /* CNTRLTYPE = 2 (Discovery controller) */

    wr16le(&ctx->id_ctrl_disc[320], 2);           /* KAS */
    wr32le(&ctx->id_ctrl_disc[536], 1u);          /* SGLS bit0 = SGL Supported */

    {
        const char *nqn = NVMET_DISCOVERY_NQN;
        uint32_t len = 0;
        while (nqn[len] != '\0') len++;
        volatile_fast_copy(&ctx->id_ctrl_disc[768], (const volatile uint8_t *)nqn, len);
    }

    /* NN = 0 のまま(Discovery コントローラは名前空間を持たない)。 */
    ctx->id_ctrl_disc[512] = (6u << 4) | 6u;      /* SQES */
    ctx->id_ctrl_disc[513] = (4u << 4) | 4u;      /* CQES */
    wr16le(&ctx->id_ctrl_disc[514], 32);          /* MAXCMD */

    wr32le(&ctx->id_ctrl_disc[1792], (64u + NVMET_IOCCSZ_MAX_BYTES) / 16u);
    wr32le(&ctx->id_ctrl_disc[1796], NVME_CQE_LEN / 16u);
    ctx->id_ctrl_disc[1803] = 1;                 /* MSDBD */
}

/*=================================================================
 * Discovery Log Page(LID=0x70)を組み立てる。
 *
 * レイアウトは Linux の include/linux/nvme.h の
 * struct nvmf_disc_rsp_page_hdr / struct nvmf_disc_rsp_page_entry
 * (どちらも 1024 バイト)。**オフセットは推測ではなく
 * tools/disc_log_check.c の offsetof で確認した値**を nvmet.h に定数化してある。
 *
 * このターゲットはサブシステムを 1 つしか持たないのでエントリは 1 個。
 * 文字列フィールド(trsvcid / subnqn / traddr)はゼロ埋め済みの領域へ
 * そのまま書くので NUL 終端される。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   addr - このターゲットが待ち受けているアドレス(traddr / adrfam に使う)
 * コール元:
 *   nvmet_admin_dispatch()
 * ===============================================================*/
static void nvmet_build_disc_log(nvmet_ctx_t *ctx, const netaddr_t *addr)
{
    nvmet_zero(ctx->disc_log, sizeof(ctx->disc_log));

    /* ---- ヘッダ ---- */
    wr64le(&ctx->disc_log[NVMET_DISC_OFF_GENCTR], 1u);            /* 変更のたびに増やす世代番号 */
    wr64le(&ctx->disc_log[NVMET_DISC_OFF_NUMREC], NVMET_DISC_NUMREC);
    wr16le(&ctx->disc_log[NVMET_DISC_OFF_RECFMT], 0u);            /* 0 固定 */

    /* ---- エントリ 0 ---- */
    uint8_t *e = &ctx->disc_log[NVMET_DISC_HDR_LEN];
    e[NVMET_DISC_ENT_OFF_TRTYPE]  = 3u;   /* NVMF_TRTYPE_TCP */
    e[NVMET_DISC_ENT_OFF_ADRFAM]  = (addr && addr->family == NETADDR_V6) ? 2u : 1u; /* IP6 : IP4 */
    e[NVMET_DISC_ENT_OFF_SUBTYPE] = 2u;   /* NVME_NQN_NVME (NVMe subsystem) */
    e[NVMET_DISC_ENT_OFF_TREQ]    = 0u;   /* NVMF_TREQ_NOT_SPECIFIED */
    wr16le(&e[NVMET_DISC_ENT_OFF_PORTID], 1u);
    wr16le(&e[NVMET_DISC_ENT_OFF_CNTLID], 0xFFFFu); /* dynamic controller */
    wr16le(&e[NVMET_DISC_ENT_OFF_ASQSZ],  32u);     /* 32 以上でなければならない */

    nvmet_u16_to_dec(&e[NVMET_DISC_ENT_OFF_TRSVCID], ctx->listen_port);

    {
        const char *nqn = NVMET_SUBNQN;
        uint32_t len = 0;
        while (nqn[len] != '\0') len++;
        volatile_fast_copy(&e[NVMET_DISC_ENT_OFF_SUBNQN], (const volatile uint8_t *)nqn, len);
    }

    nvmet_addr_to_str(&e[NVMET_DISC_ENT_OFF_TRADDR], addr);

    /* TSAS: TCP は先頭 1 バイトが sectype。0 = No Security。 */
    e[NVMET_DISC_ENT_OFF_TSAS] = 0u;
}

/*=================================================================
 * Identify Namespace 応答(4096 バイト)を組み立てる。NSZE/NCAP/NUSE と
 * LBA フォーマットを設定する。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * コール元:
 *   nvmet_job_start()
 * ===============================================================*/
static void nvmet_build_id_ns(nvmet_ctx_t *ctx)
{
    nvmet_zero(ctx->id_ns, sizeof(ctx->id_ns));
    wr64le(&ctx->id_ns[0],  NVMET_NS_LBA_COUNT);  /* NSZE */
    wr64le(&ctx->id_ns[8],  NVMET_NS_LBA_COUNT);  /* NCAP */
    wr64le(&ctx->id_ns[16], 0);                   /* NUSE */
    ctx->id_ns[26]  = 0;                          /* FLBAS: LBA Format Index = 0 */
    ctx->id_ns[130] = 9;                          /* LBAF[0].ds = 9 (512B = 2^9) */
}

static void nvmet_build_cqe(nvme_cqe_t *cqe, uint16_t cid,
                            uint32_t result, uint16_t status)
{
    nvmet_zero(cqe, sizeof(*cqe));
    wr32le(&cqe->dw0, result);
    wr32le(&cqe->dw1, 0);
    wr16le(&cqe->sq_head, 0);
    wr16le(&cqe->sq_id, 0);
    wr16le(&cqe->cid, cid);
    wr16le(&cqe->status, status);
}

/*=================================================================
 * admin queue の 1 コマンド(受信済み SQE)を解釈して応答する。Fabrics
 * Connect / Property Set / Property Get(CAP・CC・CSTS)/ Identify /
 * Set Features / Keep Alive を扱う。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 *   sqe - 受信した SQE
 * 戻り値:
 *   0=応答送信まで完了、-1=送信失敗
 * コール元:
 *   nvmet_admin_job_step()
 * ===============================================================*/
static int nvmet_admin_dispatch(nvmet_ctx_t *ctx, const nvme_sqe_t *sqe,
                                 const uint8_t *data, uint32_t dlen)
{
    uint32_t   opcode = rd32le(&sqe->cdw0) & 0xFFu;
    nvme_cqe_t cqe;

    ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_admin_dispatch, 0),
           (opcode == NVME_FABRIC_CMD)
               ? ((rd32le(&sqe->nsid) & 0xFFu) << 8) | opcode
               : opcode);

    if (opcode == NVME_FABRIC_CMD) {
        uint32_t fctype = rd32le(&sqe->nsid) & 0xFFu;

        if (fctype == NVME_FABRIC_FCTYPE_CONNECT) {
            uint32_t qid = rd32le(&sqe->cdw10) >> 16;
            if (qid == 0) {
                ctx->ctrlr_id = 1;
                /* Connect のデータは struct nvmf_connect_data(1024 バイト)で、
                 * offset 256 から subsysnqn[256]。ここが Discovery NQN なら
                 * このセッションは Discovery コントローラになる。 */
                ctx->is_discovery = 0;
                if (data != NULL && dlen >= 512u) {
                    ctx->is_discovery = nvmet_nqn_is_discovery(&data[256]);
                }
                /* 通常のサブシステムのときだけ IO キューの受け皿を用意する
                 * (Discovery コントローラは admin のみ)。 */
                if (!ctx->is_discovery) ctx->io_armed = 1;
                nvmet_build_cqe(&cqe, ctx->admin.last_cid, 1u, 0);
                uart_printf("[nvmet:%s] Fabrics Connect (qid=0, admin) 受理 (ctrlr_id=1%s)\n",
                            ctx->label, ctx->is_discovery ? ", Discovery コントローラ" : "");
            } else {
                uart_printf("[!] nvmet: adminキューで想定外のqid=%u\n", qid);
                nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            }
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        } else if (fctype == NVME_FABRIC_FCTYPE_PROPERTY_SET) {
            uint32_t offset = rd32le(&sqe->cdw11);
            if (offset == NVME_REG_CC) {
                ctx->cc    = rd32le(&sqe->cdw12);
                ctx->cc_en = (ctx->cc & NVME_CC_EN) ? 1 : 0;
                /* **CC.SHN を受けたらシャットダウン完了を報告する。** ホストは CC を
                 * 書いたあと CSTS.SHST が 10b になるまで待つ(Linux は 5 秒)。
                 * 実装しないと切断のたびに
                 * `Device not ready; aborting shutdown, CSTS=0x1` で待たされる。 */
                if (ctx->cc & NVME_CC_SHN_MASK) {
                    ctx->shutdown_complete = 1;
                    ctx->cc_en             = 0;   /* シャットダウンしたので RDY は下ろす */
                }
                uart_printf("[nvmet:%s] Property Set: CC=0x%x (EN=%d SHN=%u)\n",
                            ctx->label, ctx->cc, ctx->cc_en,
                            (unsigned)((ctx->cc & NVME_CC_SHN_MASK) >> 14));
            }
            nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, 0);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        } else if (fctype == NVME_FABRIC_FCTYPE_PROPERTY_GET) {
            uint32_t offset = rd32le(&sqe->cdw11);
            if (offset == NVME_REG_CAP) {
                uint32_t cap_lo = 0xFFu | (0x1Eu << 24);
                nvmet_build_cqe(&cqe, ctx->admin.last_cid, cap_lo, 0);
                wr32le(&cqe.dw1, 0x20u);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            } else {
                uint32_t value = 0;
                if (offset == NVME_REG_CC) {
                    value = ctx->cc;
                } else if (offset == NVME_REG_CSTS) {
                    value = (ctx->cc_en ? NVME_CSTS_RDY : 0u) |
                            (ctx->shutdown_complete ? NVME_CSTS_SHST_CMPLT : 0u);
                }
                nvmet_build_cqe(&cqe, ctx->admin.last_cid, value, 0);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            }
        } else {
            uart_printf("[!] nvmet: 未対応のFabricsコマンド (fctype=0x%x)\n", fctype);
            nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        }
        return 0;
    }

    if (opcode == NVME_ADM_CMD_IDENTIFY) {
        uint32_t cns = rd32le(&sqe->cdw10) & 0xFFu;
        nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, 0);
        if (cns == NVME_IDENTIFY_CNS_CONTROLLER) {
            /* Discovery コントローラは CNTRLTYPE / SUBNQN / NN が違う別の応答。 */
            const uint8_t *idc = ctx->is_discovery ? ctx->id_ctrl_disc : ctx->id_ctrl;
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe, idc, sizeof(ctx->id_ctrl), 1);
        } else if (cns == NVME_IDENTIFY_CNS_NAMESPACE) {
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe, ctx->id_ns, sizeof(ctx->id_ns), 1);
        } else {
            uart_printf("[!] nvmet: 未対応のIdentify CNS=0x%x\n", cns);
            nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        }
        return 0;
    }

    if (opcode == NVME_ADM_CMD_SET_FEATURES) {
        uint32_t fid = rd32le(&sqe->cdw10) & 0xFFu;
        if (fid == 0x07u) {
            nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0x00000000u, 0);  /* NSQA=0, NCQA=0 (0's based) = SQ/CQ各1本 */
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
            return 1;
        }
        nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, 0);
        nvmet_tcp_send_resp(&ctx->admin, &cqe);
        return 0;
    }

    if (opcode == NVME_ADM_CMD_KEEP_ALIVE) {
        nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, 0);
        nvmet_tcp_send_resp(&ctx->admin, &cqe);
        return 0;
    }

    if (opcode == NVME_ADM_CMD_GET_LOG_PAGE) {
        /* NUMD は 0's based の dword 数(cdw10 の上位16bit + cdw11 の下位16bit)。
         * LPO(Log Page Offset)は cdw12(下位32bit)/cdw13(上位32bit)のバイト
         * オフセット。 */
        uint32_t lid   = rd32le(&sqe->cdw10) & 0xFFu;
        uint32_t numdl = (rd32le(&sqe->cdw10) >> 16) & 0xFFFFu;
        uint32_t numdu = rd32le(&sqe->cdw11) & 0xFFFFu;
        uint32_t bytes = (((numdu << 16) | numdl) + 1u) * 4u;
        uint32_t lpo   = rd32le(&sqe->cdw12);  /* 上位 32bit(cdw13)は使わない -- ログは 2KB しかない */

        if (lid == NVME_LOG_LID_DISCOVERY) {
            /* **オフセット付きの読み出しに対応しないと `nvme discover` は動かない。**
             * ホストはまずヘッダ(16 バイト)だけを読んで NUMREC を確認し、
             * 続けて全体を読み直す(実装によってはエントリ部分だけを
             * LPO=1024 で読む)。 */
            nvmet_build_disc_log(ctx, (const netaddr_t *)&ctx->admin.tcp.local_ip);

            uint32_t avail = (lpo < NVMET_DISC_LOG_LEN) ? (NVMET_DISC_LOG_LEN - lpo) : 0u;
            uint32_t send  = (bytes < avail) ? bytes : avail;
            uart_printf("[nvmet:%s] Get Log Page: Discovery (lpo=%u 要求=%u 返却=%u numrec=%u)\n",
                        ctx->label, lpo, bytes, send, NVMET_DISC_NUMREC);
            nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, 0);
            if (send == 0u) {
                /* 範囲外 -- データ無しで正常完了させる(エラーにはしない)。 */
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            } else {
                nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                    &ctx->disc_log[lpo], send, 1);
            }
            return 0;
        }

        /* それ以外の LID はエラー情報も SMART も持たないので、要求された長さの
         * ゼロ埋めを返す。ホスト(nvme-cli / カーネル)はこれを正常応答として
         * 扱う。返さないと接続後の Get Log Page でエラーになる。 */
        if (bytes > sizeof(ctx->log_page)) bytes = sizeof(ctx->log_page);
        for (uint32_t i = 0; i < bytes; i++) ctx->log_page[i] = 0;
        nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, 0);
        nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                            ctx->log_page, bytes, 1);
        return 0;
    }

    if (opcode == NVME_ADM_CMD_ASYNC_EVENT) {
        /* 非同期イベント要求は「イベントが起きるまで完了させない」のが正しい
         * 挙動(実コントローラも同じ)。ここで成功を返すとホストが即座に
         * 再発行して無限ループになる。このターゲットはイベントを生成しない
         * ので、受理だけして CQE を返さず放置する。切断時は接続ごと消える。 */
        uart_printf("[nvmet:%s] Async Event Request を受理(イベント発生まで保留)\n",
                    ctx->label);
        return 0;
    }

    uart_printf("[!] nvmet: 未対応のadminコマンド (opcode=0x%x)\n", opcode);
    nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
    nvmet_tcp_send_resp(&ctx->admin, &cqe);
    return 0;
}

typedef enum {
    NADM_ST_ARM = 0,
    NADM_ST_ACCEPT_WAIT,
    NADM_ST_ICREQ_RECV,
    NADM_ST_ICRESP_SEND,
    NADM_ST_RECV_HDR,
    NADM_ST_RECV_SQE,
    NADM_ST_RECV_HDGST,
    NADM_ST_RECV_DATA,
    NADM_ST_RECV_DDGST,
    NADM_ST_DISPATCH,
} nvmet_admin_state_t;

#define NADM_STATE_NAME_COUNT (sizeof(NADM_STATE_NAMES) / sizeof(NADM_STATE_NAMES[0]))

typedef struct {
    nvmet_ctx_t      *ctx;
    uint16_t          port;
    uint64_t          wait_started_ticks;  /* ARM〜ICRESP_SEND段階での待ち開始時刻(NVMET_ACCEPT_TIMEOUT_MS、timeout_ms()で判定) */
    nvmet_tcp_xfer_t  xfer;
    uint8_t           icreq_buf[NVME_TCP_ICREQ_LEN];
    uint8_t           hdr_buf[NVME_TCP_HDR_LEN];
    uint8_t           sqe_buf[NVME_SQE_LEN];
    uint8_t           dgst_buf[4];
    uint32_t          dlen;
    uint8_t           data_buf[NVMET_ADMIN_DATA_BUF_MAX] __attribute__((aligned(64)));
    int               linger_armed;   /* IOキュー切断後、相手がadminを閉じるのを待っている */
    uint64_t          linger_ticks;   /* その待ち開始時刻(NVMET_ADMIN_LINGER_MS で打ち切る) */
} nvmet_admin_job_ctx_t;

static nvmet_admin_job_ctx_t s_admin_job_pool[NVMET_MAX_INSTANCES];

/*=================================================================
 * セッション確立段階(ICReq タイムアウト/受信失敗/ICResp 送信失敗)での
 * 失敗処理。コネクションを閉じて accept 待ちの初期状態へ戻す(サーバ自体は
 * 止めず、次のクライアントを待つ)。
 *
 * 引数:
 *   self - このジョブ
 *   ctx  - ターゲットコンテキスト
 * 戻り値:
 *   JOB_WAITING(常駐サーバとして継続)
 * コール元:
 *   nvmet_admin_job_step()
 * ===============================================================*/
static job_result_t nvmet_admin_job_setup_fail(job_t *self, nvmet_ctx_t *ctx)
{
    nvmet_tcp_close(&ctx->admin);
    self->state = NADM_ST_ARM;
    return JOB_WAITING;
}

/*=================================================================
 * admin キューのセッションを畳んで次のクライアント待ちへ戻す。
 * **コントローラ状態(ctrlr_id/cc/cc_en)をリセットするのはここだけ。**
 * io job 側で消してはいけない -- IO キューが切れたあとも相手は admin へ
 * CC.SHN や Keep Alive を投げてくるので、それに答えるまで状態が要る。
 *
 * 引数:
 *   self / jc / ctx - このジョブ、admin ジョブ状態、ターゲットコンテキスト
 *   reason          - ログに出す終了理由
 * 戻り値:
 *   JOB_WAITING(常駐サーバとして継続。次 tick は NADM_ST_ARM)
 * コール元:
 *   nvmet_admin_job_step()
 * ===============================================================*/
static job_result_t nvmet_admin_session_finish(job_t *self, nvmet_admin_job_ctx_t *jc,
                                               nvmet_ctx_t *ctx, const char *reason)
{
    uart_printf("[nvmet:%s] %s、次のクライアントを待ちます\n", ctx->label, reason);
    nvmet_tcp_close(&ctx->admin);
    ctx->is_discovery = 0;
    ctx->session_done = 0;
    ctx->ctrlr_id          = 0;
    ctx->cc                = 0;
    ctx->cc_en             = 0;
    ctx->shutdown_complete = 0;
    jc->linger_armed       = 0;
    self->state = NADM_ST_ARM;
    return JOB_WAITING;
}

/*=================================================================
 * admin queue のステートマシン 1 tick。accept 待ち -> ICReq 受信 -> ICResp
 * 送信(この時点で IO キューの受け皿を arm する)-> 以後はコマンド受信と
 * ディスパッチのループ。セッションが終わっても JOB_DONE にはせず、次の
 * クライアントを待つ常駐サーバとして振る舞う。
 *
 * 引数:
 *   self - このジョブ
 * 戻り値:
 *   JOB_WAITING=継続、JOB_DONE=アイドル中の Ctrl+C でサーバ停止
 * コール元:
 *   job_scheduler_tick() から関数ポインタ経由
 * ===============================================================*/
static job_result_t nvmet_admin_job_step(job_t *self)
{
    nvmet_admin_job_ctx_t *jc  = (nvmet_admin_job_ctx_t *)self->ctx;
    nvmet_ctx_t            *ctx = jc->ctx;

    /* **io job が IO キューを畳んでも admin はこちらから閉じない。**
     * 相手(Linux ホスト)は IO キューを切ったあと admin へ CC.SHN
     * (Property Set offset 0x14)を書き、それから admin を閉じる。ここで
     * すぐ ARM へ戻る(= admin を捨てる)と CC.SHN と Keep Alive が無応答に
     * なり、ホスト側で 60 秒のコマンドタイムアウトになる。
     * **どの受信 state に居ても linger を開始できるよう switch の外で見る**
     * -- 受信途中で ARM へ戻ると PDU のヘッダだけ読んでコマンドを捨てること
     * になり、まさにそれで CC.SHN を落としていた。 */
    if (ctx->session_done && !jc->linger_armed) {
        jc->linger_armed = 1;
        jc->linger_ticks = timer_now();
    }

    switch ((nvmet_admin_state_t)self->state) {

    case NADM_ST_ARM:
        nvmet_tcp_accept_arm(&ctx->admin, ctx->listener);
        jc->wait_started_ticks = timer_now();
        self->state = NADM_ST_ACCEPT_WAIT;
        return JOB_WAITING;

    case NADM_ST_ACCEPT_WAIT:
        if (tcp_accept_ready_poll(ctx->listener)) {
            uart_printf("[nvmet:%s] adminキュー接続完了\n", ctx->label);
            nvmet_tcp_xfer_reset(&jc->xfer, jc->icreq_buf, NVME_TCP_ICREQ_LEN);
            jc->wait_started_ticks = timer_now();
            self->state = NADM_ST_ICREQ_RECV;
            return JOB_WAITING;
        }
        if (self->cancel_requested || ctx->stop_requested) {
            ctx->stop_requested = 0;
            uart_printf("[nvmet:%s] サーバを停止します\n", ctx->label);
            nvmet_tcp_close(&ctx->admin);
            tcp_unlisten(ctx->listener);
            ctx->admin_failed = 1;
            return JOB_DONE;
        }
        return JOB_WAITING;

    case NADM_ST_ICREQ_RECV: {
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0) return nvmet_admin_job_setup_fail(self, ctx);
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVMET_ACCEPT_TIMEOUT_MS)) {
                uart_printf("[!] NVMe/TCP target: ICReq受信タイムアウト\n");
                return nvmet_admin_job_setup_fail(self, ctx);
            }
            return JOB_WAITING;
        }
        /* NRCV: ICReq(admin queue)受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICREQ;
            info.hlen     = jc->icreq_buf[2];
            info.pdo      = jc->icreq_buf[3];
            info.plen     = rd32le(&jc->icreq_buf[4]);
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_admin_job_step, 0), &info);
        }
        self->state = NADM_ST_ICRESP_SEND;
        return JOB_WAITING;
    }

    case NADM_ST_ICRESP_SEND:
        if (nvmet_tcp_send_icresp(&ctx->admin, jc->icreq_buf) != 0) {
            return nvmet_admin_job_setup_fail(self, ctx);
        }
        /* **IO キューの arm はここではなく Fabrics Connect(qid=0)の受理後に行う。**
         * この時点ではまだ subnqn を見ていないので、Discovery コントローラかどうかが
         * 分からない。Discovery は admin キューだけで完結する(IO キューを作らない)
         * ので、ここで arm すると **discovery の次に来た通常接続の admin 用 SYN を
         * IO キューの accept が食べてしまう**。実機で踏んだ:
         * discovery -> tcpbench の順で叩くと「IOキューで想定外のFabricsコマンド
         * (fctype=0x0)」で接続に失敗した。 */
        nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
        self->state = NADM_ST_RECV_HDR;
        return JOB_WAITING;

    case NADM_ST_RECV_HDR: {
        /* Discovery セッションは IO キューを作らないので、切断を検出して次の
         * 接続待ちへ戻す io job が居ない。admin 自身で面倒を見る。
         *
         * **CLOSE_WAIT を条件に含めること。** 相手の FIN を受けた側は CLOSE_WAIT で
         * 止まり、自分が close するまで CLOSED にはならない。ここを
         * CLOSED/TIME_WAIT だけで見ていたら、discovery の後 admin job が
         * CLOSE_WAIT のまま固まり、**以後この listener が一切 SYN を受け付けなく
         * なった**(実機で踏んだ。C1 で「リスナが居るポートには RST を返さない」
         * ようにしてあるので、相手からは SYN が黙って捨てられるように見える)。 */
        int peer_gone = (ctx->admin.tcp.state == TCP_CLOSE_WAIT ||
                         ctx->admin.tcp.state == TCP_CLOSED ||
                         ctx->admin.tcp.state == TCP_TIME_WAIT);
        if ((ctx->is_discovery || jc->linger_armed) && peer_gone) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              ctx->is_discovery
                                                  ? "Discovery セッション終了"
                                                  : "セッション終了(adminキューも切断された)");
        }
        if (jc->linger_armed && timeout_ms(jc->linger_ticks, NVMET_ADMIN_LINGER_MS)) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "adminキューを相手が閉じないので打ち切り");
        }
        if (ctx->admin.tcp.state != TCP_ESTABLISHED) return JOB_WAITING;  /* 静かに待機 */

        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0) return JOB_WAITING;  /* 同じstate/xferのまま次tickへ(desync回避、上記コメント参照) */
        if (r == 0) return JOB_WAITING;
        if (jc->hdr_buf[0] != NVME_TCP_PDU_CMD) {
            uart_printf("[!] nvmet: admin想定外のPDU種別 (type=%u、CapsuleCmdを期待)\n", jc->hdr_buf[0]);
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            return JOB_WAITING;
        }
        nvmet_tcp_xfer_reset(&jc->xfer, jc->sqe_buf, NVME_SQE_LEN);
        self->state = NADM_ST_RECV_SQE;
        return JOB_WAITING;
    }

    case NADM_ST_RECV_SQE: {
        /* io job がセッションを終わらせても、**受信中の admin コマンドは
         * 最後まで処理する**。ここで ARM へ戻ると、相手が切断手順で送ってくる
         * CC.SHN(Property Set)をヘッダだけ読んで捨てることになり、ホスト側で
         * 60 秒のコマンドタイムアウトになる(実機で踏んだ)。畳むのは admin
         * コネクション自体が切れたときだけにする。 */
        if (jc->linger_armed &&
            (ctx->admin.tcp.state != TCP_ESTABLISHED ||
             timeout_ms(jc->linger_ticks, NVMET_ADMIN_LINGER_MS))) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "セッション終了(adminキュー切断/待ち切れ)");
        }
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0 || r == 0) return JOB_WAITING;

        jc->dlen = nvmet_tcp_parse_cmd_dlen(&ctx->admin, jc->hdr_buf);
        if (jc->dlen > NVMET_ADMIN_DATA_BUF_MAX) {
            uart_printf("[!] NVMe/TCP target: admin in-capsuleデータが呼び出し側バッファを超過 "
                        "(dlen=%u max=%u)\n", jc->dlen, (unsigned)NVMET_ADMIN_DATA_BUF_MAX);
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NADM_ST_RECV_HDR;
            return JOB_WAITING;
        }
        if (ctx->admin.hdgst) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NADM_ST_RECV_HDGST;
        } else if (jc->dlen > 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->data_buf, jc->dlen);
            self->state = NADM_ST_RECV_DATA;
        } else {
            self->state = NADM_ST_DISPATCH;
        }
        return JOB_WAITING;
    }

    case NADM_ST_RECV_HDGST: {
        /* io job がセッションを終わらせても、**受信中の admin コマンドは
         * 最後まで処理する**。ここで ARM へ戻ると、相手が切断手順で送ってくる
         * CC.SHN(Property Set)をヘッダだけ読んで捨てることになり、ホスト側で
         * 60 秒のコマンドタイムアウトになる(実機で踏んだ)。畳むのは admin
         * コネクション自体が切れたときだけにする。 */
        if (jc->linger_armed &&
            (ctx->admin.tcp.state != TCP_ESTABLISHED ||
             timeout_ms(jc->linger_ticks, NVMET_ADMIN_LINGER_MS))) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "セッション終了(adminキュー切断/待ち切れ)");
        }
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0 || r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_hdgst(&ctx->admin, jc->hdr_buf, NVME_TCP_HDR_LEN,
                                    jc->sqe_buf, NVME_SQE_LEN, jc->dgst_buf) != 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NADM_ST_RECV_HDR;
            return JOB_WAITING;
        }
        if (jc->dlen > 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->data_buf, jc->dlen);
            self->state = NADM_ST_RECV_DATA;
        } else {
            self->state = NADM_ST_DISPATCH;
        }
        return JOB_WAITING;
    }

    case NADM_ST_RECV_DATA: {
        /* io job がセッションを終わらせても、**受信中の admin コマンドは
         * 最後まで処理する**。ここで ARM へ戻ると、相手が切断手順で送ってくる
         * CC.SHN(Property Set)をヘッダだけ読んで捨てることになり、ホスト側で
         * 60 秒のコマンドタイムアウトになる(実機で踏んだ)。畳むのは admin
         * コネクション自体が切れたときだけにする。 */
        if (jc->linger_armed &&
            (ctx->admin.tcp.state != TCP_ESTABLISHED ||
             timeout_ms(jc->linger_ticks, NVMET_ADMIN_LINGER_MS))) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "セッション終了(adminキュー切断/待ち切れ)");
        }
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0 || r == 0) return JOB_WAITING;
        if (ctx->admin.ddgst) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NADM_ST_RECV_DDGST;
        } else {
            self->state = NADM_ST_DISPATCH;
        }
        return JOB_WAITING;
    }

    case NADM_ST_RECV_DDGST: {
        /* io job がセッションを終わらせても、**受信中の admin コマンドは
         * 最後まで処理する**。ここで ARM へ戻ると、相手が切断手順で送ってくる
         * CC.SHN(Property Set)をヘッダだけ読んで捨てることになり、ホスト側で
         * 60 秒のコマンドタイムアウトになる(実機で踏んだ)。畳むのは admin
         * コネクション自体が切れたときだけにする。 */
        if (jc->linger_armed &&
            (ctx->admin.tcp.state != TCP_ESTABLISHED ||
             timeout_ms(jc->linger_ticks, NVMET_ADMIN_LINGER_MS))) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "セッション終了(adminキュー切断/待ち切れ)");
        }
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0 || r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_ddgst(&ctx->admin, jc->data_buf, jc->dlen, jc->dgst_buf) != 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NADM_ST_RECV_HDR;
            return JOB_WAITING;
        }
        self->state = NADM_ST_DISPATCH;
        return JOB_WAITING;
    }

    case NADM_ST_DISPATCH: {
        /* io job がセッションを終わらせても、**受信中の admin コマンドは
         * 最後まで処理する**。ここで ARM へ戻ると、相手が切断手順で送ってくる
         * CC.SHN(Property Set)をヘッダだけ読んで捨てることになり、ホスト側で
         * 60 秒のコマンドタイムアウトになる(実機で踏んだ)。畳むのは admin
         * コネクション自体が切れたときだけにする。 */
        if (jc->linger_armed &&
            (ctx->admin.tcp.state != TCP_ESTABLISHED ||
             timeout_ms(jc->linger_ticks, NVMET_ADMIN_LINGER_MS))) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "セッション終了(adminキュー切断/待ち切れ)");
        }
        nvme_sqe_t sqe;
        volatile_fast_copy((volatile uint8_t *)&sqe,
                            (const volatile uint8_t *)jc->sqe_buf, NVME_SQE_LEN);
        ctx->admin.last_cid = rd16le(&jc->sqe_buf[2]);  /* adminは1コマンドずつ同期処理のためこれで正しい */

        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_CMD;
            info.hlen        = jc->hdr_buf[2];
            info.pdo         = jc->hdr_buf[3];
            info.plen        = rd32le(&jc->hdr_buf[4]);
            info.cid         = ctx->admin.last_cid;
            info.opcode      = (uint8_t)(rd32le(&sqe.cdw0) & 0xFFu);
            info.sgl_type    = jc->sqe_buf[39];
            info.data_length = rd32le(&jc->sqe_buf[32]);  /* LEN(SGL宣言転送量) */
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_admin_job_step, 1), &info);
        }

        if (nvmet_admin_dispatch(ctx, &sqe, jc->data_buf, jc->dlen)) {
            uart_printf("[nvmet:%s] Set Features(Number of Queues)応答完了\n", ctx->label);
        }
        nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
        self->state = NADM_ST_RECV_HDR;
        return JOB_WAITING;
    }

    default:
        return JOB_DONE;
    }
}

/*=================================================================
 * 進行中の write コマンド(R2T を出してデータ待ち)のスロットを 1 つ確保する。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * 戻り値:
 *   スロット番号。空きが無ければ -1
 * コール元:
 *   nvmet_io_dispatch_cmd()
 * ===============================================================*/
static int nvmet_pending_write_alloc(nvmet_ctx_t *ctx)
{
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        if (!ctx->pending_writes[i].in_use) return (int)i;
    }
    return -1;
}

/*=================================================================
 * 進行中の write コマンドから cid が一致するスロットを探す(受信した
 * H2CData をどのコマンドのものか対応付けるのに使う)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 *   cid - 探すコマンド id
 * 戻り値:
 *   スロット番号。見つからなければ -1
 * コール元:
 *   nvmet_io_job_h2c_validate(), nvmet_io_rx_upcall()
 * ===============================================================*/
static int nvmet_pending_write_find(nvmet_ctx_t *ctx, uint16_t cid)
{
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        if (ctx->pending_writes[i].in_use && ctx->pending_writes[i].cid == cid) return (int)i;
    }
    return -1;
}

/*=================================================================
 * IO キューでストリーム desync らしき異常(想定外の PDU 種別、未知の cccid、
 * datao 不一致など)を検出した際に、TCP 層の詳細状態を表示する診断ヘルパ。
 *
 * 引数:
 *   ctx    - ターゲットコンテキスト
 *   reason - 検出した異常の説明
 * コール元:
 *   nvmet_io_job_h2c_validate(), nvmet_io_job_step_impl()
 * ===============================================================*/
static void nvmet_io_debug_desync(nvmet_ctx_t *ctx, const char *reason)
{
    uart_printf("\n[DEBUG] ==== IOキューdesync検出: %s ====\n", reason);
    tcp_debug_dump_rx(&ctx->io.tcp);
    uart_printf("[DEBUG] ==== ここまで ====\n\n");
}

typedef enum {
    NIO_ST_WAIT_ADMIN_READY = 0,
    NIO_ST_ARM,
    NIO_ST_ACCEPT_WAIT,
    NIO_ST_ICREQ_RECV,
    NIO_ST_ICRESP_SEND,
    NIO_ST_RECV_PDU_HDR,
    NIO_ST_RECV_CMD_SQE,
    NIO_ST_RECV_CMD_HDGST,
    NIO_ST_RECV_CMD_DATA,
    NIO_ST_RECV_CMD_DDGST,
    NIO_ST_DISPATCH_CMD,
    NIO_ST_RECV_H2C_REST,
    NIO_ST_RECV_H2C_HDGST,
    NIO_ST_RECV_H2C_DATA,
    NIO_ST_RECV_H2C_DDGST,
    NIO_ST_DISPATCH_H2C,
    NIO_ST_PUSH_RUN,
} nvmet_io_state_t;

#define NIO_STATE_NAME_COUNT (sizeof(NIO_STATE_NAMES) / sizeof(NIO_STATE_NAMES[0]))

/* push型受信のパーサ相(nvmet_io_rx_upcall()、2026-08-13)。 */
typedef enum { PRX_HDR, PRX_PSH, PRX_HDGST, PRX_DATA, PRX_DDGST } nvmet_prx_phase_t;

#define NVMET_READY_RING 64u
#define NVMET_READY_CMD  0u   /* CapsuleCmd受信完了(hdr/sqe/data配置済み) */
#define NVMET_READY_H2C  1u   /* H2CDataラウンド受信完了 */
typedef struct {
    uint8_t   kind;
    uint8_t   hdr[NVME_TCP_HDR_LEN];
    uint8_t   sqe[NVME_SQE_LEN];
    uint16_t  cid;
    uint32_t  dlen;
    uint8_t  *data_dst;
    int       incap_committed;
    int       h2c_slot;
    uint16_t  cccid;
    uint16_t  ttag;
    uint32_t  datao;
    uint32_t  datal;
} nvmet_ready_t;

typedef struct {
    nvmet_ctx_t      *ctx;
    uint16_t          port;
    uint64_t          wait_started_ticks;  /* ARM〜ICRESP_SEND段階での待ち開始時刻(NVMET_ACCEPT_TIMEOUT_MS、timeout_ms()で判定) */
    nvmet_tcp_xfer_t  xfer;
    uint8_t           icreq_buf[NVME_TCP_ICREQ_LEN];
    uint8_t           hdr_buf[NVME_TCP_HDR_LEN];
    uint8_t           sqe_buf[NVME_SQE_LEN];
    uint8_t           h2c_rest_buf[16];
    uint8_t           dgst_buf[4];
    uint32_t          dlen;
    uint16_t          cid;
    uint16_t          cccid;
    uint16_t          ttag;
    uint32_t          datao;
    uint32_t          datal;
    int               h2c_slot;  /* nvmet_io_job_h2c_validate()が確定させるctx->pending_writes[]のインデックス */
    uint8_t          *cmd_data_dst;
    int               incap_write_committed;
    uint8_t           data_buf[NVMET_IO_DATA_BUF_MAX] __attribute__((aligned(64)));

    int               push_mode;
    nvmet_prx_phase_t prx_phase;
    uint8_t           prx_hdr[NVME_TCP_HDR_LEN];
    uint32_t          prx_hdr_off;
    uint8_t           prx_psh[NVME_SQE_LEN];   /* SQE(64B)またはH2C rest(16B) */
    uint32_t          prx_psh_off;
    uint32_t          prx_psh_need;
    uint8_t           prx_type;
    uint8_t           prx_hlen;
    volatile uint8_t *prx_data_dst;
    uint32_t          prx_data_off;
    uint32_t          prx_data_need;
    uint16_t          prx_cid;
    int               prx_incap_committed;
    int               prx_h2c_slot;
    uint16_t          prx_cccid;
    uint16_t          prx_ttag;
    uint32_t          prx_datao;
    uint32_t          prx_datal;
    uint32_t          prx_copy_ns;           /* このPDUの1コピー累積時間(DBGT 0x40、検証後に撤去) */
    uint64_t          pull_copy_base_ns;     /* pull型コピー計測の基準(DBGT 0x41、検証後に撤去) */
    uint64_t          prx_start_tick;        /* このPDUの受信開始tick(DBGT 0x43=受信+処理span、検証後に撤去) */
    volatile int      prx_error;             /* パース致命エラー(ring溢れ/未知PDU等) */
    /* ダイジェスト受信/照合。データはコピーしながら受信ストリームから逐次
     * CRC を積むので、コピー先を読み直す 2 パス目は要らない。 */
    uint8_t           prx_dgst[4];
    uint32_t          prx_dgst_off;
    uint32_t          prx_ddgst_crc;
    nvmet_ready_t     ready[NVMET_READY_RING];
    volatile uint32_t ready_head;            /* upcallが積む(生産) */
    volatile uint32_t ready_tail;            /* jobが取り出す(消費) */
} nvmet_io_job_ctx_t;

static nvmet_io_job_ctx_t s_io_job_pool[NVMET_MAX_INSTANCES];

static nvmet_ctx_t *s_instance_owner[NVMET_MAX_INSTANCES];

static job_result_t nvmet_io_job_end(job_t *self, nvmet_ctx_t *ctx, int close_io, const char *reason)
{
    uart_printf("[nvmet:%s] write内訳: in-capsule=%u件 R2T+H2CData=%u件\n",
                ctx->label, ctx->write_incapsule_count, ctx->write_h2c_count);
    uart_printf("[nvmet:%s] セッション終了(%s)、次のクライアントを待ちます\n", ctx->label, reason);
    tcp_clear_recv_upcall(&ctx->io.tcp);
    if (close_io) {
        nvmet_tcp_close(&ctx->io);
    }
    ctx->io_connected = 0;

    /* **admin キューはここで閉じない。** Linux ホストは切断時に
     * 「IO キュー切断 -> admin へ CC.SHN(Property Set offset 0x14)-> admin 切断」
     * の順で畳む。ここで能動 close すると CC.SHN の応答が返らず、ホスト側で
     * **60 秒のコマンドタイムアウト**になる(実機で踏んだ:
     * `Property Set error: 881` = NVME_SC_HOST_ABORTED_CMD = 0x371)。
     * Keep Alive も同じ理由で取りこぼしていた。相手が閉じるまで admin を
     * 生かして応答を続け、後始末は admin job(nvmet_admin_session_finish())が
     * 行う。コントローラ状態(ctrlr_id/cc/cc_en)もそれまで応答に要るので
     * ここではリセットしない。 */
    ctx->io_armed = 0;
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        ctx->pending_writes[i].in_use = 0;
    }
    ctx->write_incapsule_count = 0;
    ctx->write_h2c_count       = 0;

    ctx->session_done = 1;  /* admin jobへ「セッション終了、ARMし直せ」を伝える */
    self->state = NIO_ST_WAIT_ADMIN_READY;
    return JOB_WAITING;
}

/*=================================================================
 * 定常ループ中の受信エラーを一元処理する。Ctrl+C 中断なら中断として、
 * FIN/RST ならセッション終了として扱い、それ以外は次の PDU ヘッダから
 * 仕切り直す。
 *
 * 引数:
 *   self / jc / ctx - このジョブ、IO ジョブ状態、ターゲットコンテキスト
 * 戻り値:
 *   JOB_WAITING(常駐サーバとして継続)
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
static job_result_t nvmet_io_job_recv_fail(job_t *self, nvmet_io_job_ctx_t *jc, nvmet_ctx_t *ctx)
{
    if (tcp_abort_requested()) {
        tcp_clear_abort_request();
        uart_printf("[nvmet:%s] Ctrl+Cで中断\n", ctx->label);
        return nvmet_io_job_end(self, ctx, 1, "Ctrl+C中断");
    }
    if (ctx->io.tcp.state != TCP_ESTABLISHED) {
        return nvmet_io_job_end(self, ctx, 1, "IOキューが切断された");
    }
    nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
    self->state = NIO_ST_RECV_PDU_HDR;
    return JOB_WAITING;
}

/*=================================================================
 * H2CData ヘッダを受信し終えた直後の検証。未知の cccid、datao の不一致、
 * write_len 超過を、**データ本体を受信する前に**確認する(検証前に受信
 * すると受信先バッファの安全な範囲が保証されない)。
 *
 * 引数:
 *   self / jc / ctx - このジョブ、IO ジョブ状態、ターゲットコンテキスト
 * 戻り値:
 *   JOB_WAITING(検証を通れば受信状態へ、失敗ならセッション終了)
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
static job_result_t nvmet_io_job_h2c_validate(job_t *self, nvmet_io_job_ctx_t *jc, nvmet_ctx_t *ctx)
{
    int slot = nvmet_pending_write_find(ctx, jc->cccid);
    if (slot < 0) {
        uart_printf("[!] nvmet: 未知のcccid=%uのH2CDataを受信\n", jc->cccid);
        nvmet_io_debug_desync(ctx, "未知のcccid");
        return nvmet_io_job_end(self, ctx, 1, "desync検出(未知のcccid)");
    }
    nvmet_pending_write_t *pw = &ctx->pending_writes[slot];
    if (jc->datao != pw->received) {
        uart_printf("[!] nvmet: H2CDataのdataoが不一致 (cid=%u 期待=%u 受信=%u)\n",
                    jc->cccid, pw->received, jc->datao);
        nvmet_io_debug_desync(ctx, "datao不一致");
        return nvmet_io_job_end(self, ctx, 1, "desync検出(datao不一致)");
    }
    if (pw->received + jc->datal > pw->write_len) {
        uart_printf("[!] nvmet: H2CDataがwrite_lenを超過 "
                    "(cid=%u received=%u datal=%u write_len=%u)\n",
                    jc->cccid, pw->received, jc->datal, pw->write_len);
        nvmet_io_debug_desync(ctx, "write_len超過");
        return nvmet_io_job_end(self, ctx, 1, "desync検出(write_len超過)");
    }
    jc->h2c_slot = slot;
    nvmet_tcp_xfer_reset(&jc->xfer, &ctx->ram_disk[pw->slba * NVMET_LBA_SIZE + jc->datao], jc->datal);
    self->state = NIO_ST_RECV_H2C_DATA;
    return JOB_WAITING;
}

/*=================================================================
 * IO キューの 1 コマンド(Command Capsule)を処理して応答する。read は
 * C2HData で返し、write は in-capsule なら即コミット、超過分は R2T を出して
 * H2CData を待つ。
 *
 * 引数:
 *   ctx      - ターゲットコンテキスト
 *   hdr_buf  - 受信した共通ヘッダ
 *   sqe      - 受信した SQE
 *   cid      - コマンド id
 *   dlen     - in-capsule データ長
 *   incap_committed - in-capsule データを既に RAM ディスクへ書き込み済みか
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
static void nvmet_io_dispatch_cmd(nvmet_ctx_t *ctx, const uint8_t *hdr_buf,
                                   const uint8_t *sqe_buf, uint16_t cid,
                                   uint32_t dlen, int incap_committed)
{
    nvme_sqe_t sqe;
    volatile_fast_copy((volatile uint8_t *)&sqe,
                        (const volatile uint8_t *)sqe_buf, NVME_SQE_LEN);
    uint32_t   opcode = rd32le(&sqe.cdw0) & 0xFFu;
    nvme_cqe_t cqe;

    {
        volatile ts_nvme_pdu_t info = {0};
        info.pdu_type    = NVME_TCP_PDU_CMD;
        info.hlen        = hdr_buf[2];
        info.pdo         = hdr_buf[3];
        info.plen        = rd32le(&hdr_buf[4]);
        info.cid         = cid;
        info.opcode      = (uint8_t)opcode;
        info.sgl_type    = sqe_buf[39];
        info.data_length = rd32le(&sqe_buf[32]);
        ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_dispatch_cmd, 0), &info);
    }

    if (opcode == NVME_FABRIC_CMD) {
        uint32_t fctype = rd32le(&sqe.nsid) & 0xFFu;
        if (fctype == NVME_FABRIC_FCTYPE_CONNECT) {
            ctx->io_connected = 1;
            nvmet_build_cqe(&cqe, cid, ctx->ctrlr_id, 0);
            uart_printf("[nvmet:%s] Fabrics Connect (qid=1, IO) 受理\n", ctx->label);
        } else {
            uart_printf("[!] nvmet: IOキューで想定外のFabricsコマンド (fctype=0x%x)\n", fctype);
            nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
        }
        nvmet_tcp_send_resp(&ctx->io, &cqe);
    } else if (!ctx->cc_en) {
        uart_printf("[!] nvmet: CC.EN=0のためIOコマンドを拒否 (opcode=0x%x)\n", opcode);
        nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
        nvmet_tcp_send_resp(&ctx->io, &cqe);
    } else if (opcode == NVME_IO_CMD_READ) {
        uint64_t slba    = (uint64_t)rd32le(&sqe.cdw10) | ((uint64_t)rd32le(&sqe.cdw11) << 32);
        uint32_t nlb     = (rd32le(&sqe.cdw12) & 0xFFFFu) + 1u;
        uint64_t end_lba = slba + nlb;
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_dispatch_cmd, 1), nlb * NVMET_LBA_SIZE);

        if (end_lba > NVMET_NS_LBA_COUNT) {
            uart_printf("[!] nvmet: Read範囲外 (slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
            nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&ctx->io, &cqe);
        } else if ((uint64_t)nlb * NVMET_LBA_SIZE > NVMET_MAX_TRANSFER_BYTES) {
            uart_printf("[!] nvmet: Read転送量がMDTS超過 (slba=%u nlb=%u)\n",
                        (uint32_t)slba, nlb);
            nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&ctx->io, &cqe);
        } else {
            nvmet_build_cqe(&cqe, cid, 0u, 0);
            /* ダイジェスト有効時もゼロコピーのまま送れる
             * (nvmet_tcp_send_c2h_async() が送信元から直接 CRC を算出する)。 */
            int c2h_rc = nvmet_tcp_send_c2h_async(&ctx->io, cid,
                                                   &ctx->ram_disk[slba * NVMET_LBA_SIZE],
                                                   nlb * NVMET_LBA_SIZE);
            if (c2h_rc != 0) {
                uart_printf("[!] nvmet: C2HData送信失敗、エラー応答を試みる "
                            "(slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
                nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
                nvmet_tcp_send_resp(&ctx->io, &cqe);
            }
        }
    } else if (opcode == NVME_IO_CMD_WRITE) {
        uint64_t slba      = (uint64_t)rd32le(&sqe.cdw10) | ((uint64_t)rd32le(&sqe.cdw11) << 32);
        uint32_t nlb       = (rd32le(&sqe.cdw12) & 0xFFFFu) + 1u;
        uint64_t end_lba   = slba + nlb;
        uint32_t write_len = nlb * NVMET_LBA_SIZE;
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_dispatch_cmd, 2), write_len);

        if (dlen > 0) {
            if (incap_committed) {
                ctx->write_incapsule_count++;
                nvmet_build_cqe(&cqe, cid, 0u, 0);
            } else {
                uart_printf("[!] nvmet: Write範囲外/過大 (slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
                nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            }
            nvmet_tcp_send_resp(&ctx->io, &cqe);
        } else if (end_lba > NVMET_NS_LBA_COUNT || write_len > NVMET_IO_DATA_BUF_MAX) {
            uart_printf("[!] nvmet: Write範囲外/過大 (slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
            nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&ctx->io, &cqe);
        } else {
            int slot = nvmet_pending_write_alloc(ctx);
            if (slot < 0) {
                uart_printf("[!] nvmet: 同時書き込み上限(%u件)を超過、"
                            "コマンドを拒否 (cid=%u)\n", NVMET_MAX_PENDING_WRITES, cid);
                nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
                nvmet_tcp_send_resp(&ctx->io, &cqe);
            } else {
                ctx->write_h2c_count++;
                ctx->pending_writes[slot].in_use    = 1;
                ctx->pending_writes[slot].cid       = cid;
                ctx->pending_writes[slot].slba      = slba;
                ctx->pending_writes[slot].write_len = write_len;
                ctx->pending_writes[slot].received  = 0;

                uint32_t max_h2c = nvmet_tcp_max_h2c_data(&ctx->io);
                uint32_t round   = (write_len > max_h2c) ? max_h2c : write_len;
                if (nvmet_tcp_send_r2t(&ctx->io, cid, 0, round) != 0) {
                    uart_printf("[!] nvmet: R2T送信失敗 (cid=%u)\n", cid);
                    ctx->pending_writes[slot].in_use = 0;
                    nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
                    nvmet_tcp_send_resp(&ctx->io, &cqe);
                }
            }
        }
    } else if (opcode == NVME_IO_CMD_FLUSH) {
        /* 名前空間の実体は RAM ディスクで揮発性キャッシュを持たないため、
         * Flush は成功を返すだけでよい(仕様上も準拠)。返さないとホスト側で
         * fsync/sync が失敗する。 */
        nvmet_build_cqe(&cqe, cid, 0u, 0);
        nvmet_tcp_send_resp(&ctx->io, &cqe);
    } else {
        uart_printf("[!] nvmet: 未対応のIOコマンド (opcode=0x%x)\n", opcode);
        nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
        nvmet_tcp_send_resp(&ctx->io, &cqe);
    }
}

/*=================================================================
 * 受信し終えた H2CData を処理する。要求範囲を満たしたら CQE を返し、まだ
 * 残りがあれば次の R2T を出す。
 *
 * 引数:
 *   ctx      - ターゲットコンテキスト
 *   h2c_slot - 対応する write スロット
 *   hdr_buf  - 受信した共通ヘッダ
 *   cccid / ttag / datao / datal - H2CData ヘッダのフィールド
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
static void nvmet_io_dispatch_h2c(nvmet_ctx_t *ctx, int h2c_slot,
                                   const uint8_t *hdr_buf, uint16_t cccid,
                                   uint16_t ttag, uint32_t datao, uint32_t datal)
{
    nvmet_pending_write_t *pw = &ctx->pending_writes[h2c_slot];

    {
        volatile ts_nvme_pdu_t info = {0};
        info.pdu_type    = NVME_TCP_PDU_H2C_DATA;
        info.hlen        = hdr_buf[2];
        info.pdo         = hdr_buf[3];
        info.plen        = rd32le(&hdr_buf[4]);
        info.cccid       = cccid;
        info.ttag        = ttag;
        info.data_offset = datao;
        info.data_length = datal;
        ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_dispatch_h2c, 0), &info);
    }

    pw->received += datal;
    if (pw->received < pw->write_len) {
        uint32_t remain  = pw->write_len - pw->received;
        uint32_t max_h2c = nvmet_tcp_max_h2c_data(&ctx->io);
        uint32_t round   = (remain > max_h2c) ? max_h2c : remain;
        if (nvmet_tcp_send_r2t(&ctx->io, pw->cid, pw->received, round) != 0) {
            uart_printf("[!] nvmet: R2T送信失敗 (cid=%u)\n", pw->cid);
            nvme_cqe_t cqe;
            nvmet_build_cqe(&cqe, pw->cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&ctx->io, &cqe);
            pw->in_use = 0;
        }
    } else {
        nvme_cqe_t cqe;
        nvmet_build_cqe(&cqe, pw->cid, 0u, 0);
        nvmet_tcp_send_resp(&ctx->io, &cqe);
        pw->in_use = 0;
    }
}

/*=================================================================
 * 受信 upcall 側から、完成した 1 コマンドを ready-ring へ積む。リングが
 * 満杯(dispatch が追いつかない)なら prx_error を立てる。
 *
 * 引数:
 *   jc - IO ジョブ状態
 * コール元:
 *   nvmet_io_rx_upcall()
 * ===============================================================*/
static void nvmet_ready_push_cmd(nvmet_io_job_ctx_t *jc)
{
    if (jc->ready_head - jc->ready_tail >= NVMET_READY_RING) { jc->prx_error = 1; return; }
    nvmet_ready_t *rd = &jc->ready[jc->ready_head % NVMET_READY_RING];
    rd->kind = NVMET_READY_CMD;
    for (unsigned k = 0; k < NVME_TCP_HDR_LEN; k++) rd->hdr[k] = jc->prx_hdr[k];
    for (unsigned k = 0; k < NVME_SQE_LEN; k++)     rd->sqe[k] = jc->prx_psh[k];
    rd->cid             = jc->prx_cid;
    rd->dlen            = jc->prx_data_need;
    rd->incap_committed = jc->prx_incap_committed;
    __asm__ volatile("" ::: "memory");
    jc->ready_head++;
}

/*=================================================================
 * 受信 upcall 側から、完成した 1 件の H2CData を ready-ring へ積む。
 *
 * 引数:
 *   jc - IO ジョブ状態
 * コール元:
 *   nvmet_io_rx_upcall()
 * ===============================================================*/
static void nvmet_ready_push_h2c(nvmet_io_job_ctx_t *jc)
{
    if (jc->ready_head - jc->ready_tail >= NVMET_READY_RING) { jc->prx_error = 1; return; }
    nvmet_ready_t *rd = &jc->ready[jc->ready_head % NVMET_READY_RING];
    rd->kind = NVMET_READY_H2C;
    for (unsigned k = 0; k < NVME_TCP_HDR_LEN; k++) rd->hdr[k] = jc->prx_hdr[k];
    rd->h2c_slot = jc->prx_h2c_slot;
    rd->cccid    = jc->prx_cccid;
    rd->ttag     = jc->prx_ttag;
    rd->datao    = jc->prx_datao;
    rd->datal    = jc->prx_datal;
    __asm__ volatile("" ::: "memory");
    jc->ready_head++;
}

/*=================================================================
 * IO キューの push 型受信ハンドラ。tcp_input() から in-order データをその場
 * で受け取り、PDU をストリーム解析する(ヘッダ -> 型固有部 -> データ)。
 * in-capsule write データは rx_buf を経由せず RAM ディスクへ直接配置し、
 * 完成したコマンドは ready-ring へ積む(送信はここでは一切行わない)。
 *
 * 引数:
 *   arg  - IO ジョブ状態
 *   data - 到着した in-order バイト列
 *   len  - そのバイト数
 * コール元:
 *   tcp_input() から tcp_recv_upcall として
 * ===============================================================*/
static void nvmet_prx_finish_pdu(nvmet_io_job_ctx_t *jc)
{
    if (jc->prx_type == NVME_TCP_PDU_CMD) nvmet_ready_push_cmd(jc);
    else                                  nvmet_ready_push_h2c(jc);
    jc->prx_phase = PRX_HDR;
    jc->prx_hdr_off = 0;
}

/*=================================================================
 * push 型受信で、共通ヘッダ + 型固有部(+ヘッダダイジェスト)を読み切った
 * 時点の分岐。CapsuleCmd / H2CData それぞれについてデータ本体の受信先を
 * 決め、データが無ければその場で ready-ring へ積む。
 *
 * 引数:
 *   jc  - IO ジョブ状態
 *   ctx - target コンテキスト
 * コール元:
 *   nvmet_io_rx_upcall()
 * ===============================================================*/
static void nvmet_prx_dispatch(nvmet_io_job_ctx_t *jc, nvmet_ctx_t *ctx)
{
    if (jc->prx_type == NVME_TCP_PDU_CMD) {
        jc->prx_cid = rd16le(&jc->prx_psh[2]);
        uint32_t opcode = rd32le(&jc->prx_psh[0]) & 0xFFu;
        if (ts_log_mode() & 0x2) {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_CMD;
            info.hlen        = jc->prx_hdr[2];
            info.pdo         = jc->prx_hdr[3];
            info.plen        = rd32le(&jc->prx_hdr[4]);
            info.cid         = jc->prx_cid;
            info.opcode      = (uint8_t)opcode;
            info.sgl_type    = jc->prx_psh[39];
            info.data_length = rd32le(&jc->prx_psh[32]);
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_rx_upcall, 2), &info);
        }
        jc->prx_incap_committed = 0;
        jc->prx_data_dst = (volatile uint8_t *)jc->data_buf;
        if (jc->prx_data_need > 0 && opcode == NVME_IO_CMD_WRITE) {
            uint64_t slba = (uint64_t)rd32le(&jc->prx_psh[40]) | ((uint64_t)rd32le(&jc->prx_psh[44]) << 32);
            uint32_t nlb  = (rd32le(&jc->prx_psh[48]) & 0xFFFFu) + 1u;
            uint32_t wl   = nlb * NVMET_LBA_SIZE;
            if (wl == jc->prx_data_need && (slba + nlb) <= NVMET_NS_LBA_COUNT) {
                jc->prx_data_dst = (volatile uint8_t *)&ctx->ram_disk[slba * NVMET_LBA_SIZE];
                jc->prx_incap_committed = 1;
            }
        }
        if (jc->prx_data_need == 0) {
            nvmet_prx_finish_pdu(jc);
        } else {
            if (!jc->prx_incap_committed && jc->prx_data_need > NVMET_IO_DATA_BUF_MAX) {
                jc->prx_error = 1; return;   /* data_bufオーバーフロー防止 */
            }
            jc->prx_data_off = 0;
            jc->prx_ddgst_crc = 0xFFFFFFFFu;
            jc->prx_phase = PRX_DATA;
        }
    } else if (jc->prx_type == NVME_TCP_PDU_H2C_DATA) {
        jc->prx_cccid = rd16le(&jc->prx_psh[0]);
        jc->prx_ttag  = rd16le(&jc->prx_psh[2]);
        jc->prx_datao = rd32le(&jc->prx_psh[4]);
        jc->prx_datal = rd32le(&jc->prx_psh[8]);
        jc->prx_data_need = jc->prx_datal;
        int slot = nvmet_pending_write_find(ctx, jc->prx_cccid);
        if (slot < 0) { jc->prx_error = 1; return; }
        nvmet_pending_write_t *pw = &ctx->pending_writes[slot];
        if (jc->prx_datao != pw->received ||
            pw->received + jc->prx_datal > pw->write_len) {
            jc->prx_error = 1; return;
        }
        jc->prx_h2c_slot = slot;
        jc->prx_data_dst = (volatile uint8_t *)&ctx->ram_disk[pw->slba * NVMET_LBA_SIZE + jc->prx_datao];
        if (jc->prx_datal == 0) {
            nvmet_prx_finish_pdu(jc);
        } else {
            jc->prx_data_off = 0;
            jc->prx_ddgst_crc = 0xFFFFFFFFu;
            jc->prx_phase = PRX_DATA;
        }
    } else {
        jc->prx_error = 1;   /* IOキューで想定外のPDU種別 */
    }
}

static void nvmet_io_rx_upcall(void *arg, const volatile uint8_t *data, uint16_t len)
{
    nvmet_io_job_ctx_t *jc  = (nvmet_io_job_ctx_t *)arg;
    nvmet_ctx_t        *ctx = jc->ctx;
    uint32_t i = 0;
    while (i < len && !jc->prx_error) {
        switch (jc->prx_phase) {
        case PRX_HDR: {
            if (jc->prx_hdr_off == 0 && (ts_log_mode() & 0x2)) jc->prx_start_tick = timer_now();
            uint32_t take = (uint32_t)NVME_TCP_HDR_LEN - jc->prx_hdr_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) jc->prx_hdr[jc->prx_hdr_off + k] = data[i + k];
            jc->prx_hdr_off += take;
            i += take;
            if (jc->prx_hdr_off == NVME_TCP_HDR_LEN) {
                jc->prx_type = jc->prx_hdr[0];
                jc->prx_hlen = jc->prx_hdr[2];
                uint32_t plen = rd32le(&jc->prx_hdr[4]);
                jc->prx_psh_need = (jc->prx_hlen > NVME_TCP_HDR_LEN)
                                     ? (uint32_t)(jc->prx_hlen - NVME_TCP_HDR_LEN) : 0u;
                /* plen はヘッダ・両ダイジェストを含む総長なので、
                 * pull 経路と同じヘルパでデータ本体だけを取り出す。 */
                (void)plen;
                jc->prx_data_need = nvmet_tcp_parse_cmd_dlen(&ctx->io, jc->prx_hdr);
                if (jc->prx_psh_need == 0 || jc->prx_psh_need > NVME_SQE_LEN) {
                    jc->prx_error = 1; break;   /* IOキューのCMD/H2Cはhlen=72/24のみ */
                }
                jc->prx_psh_off = 0;
                jc->prx_phase   = PRX_PSH;
                jc->prx_copy_ns = 0;   /* このPDUの1コピー累積時間を計測開始 */
            }
            break;
        }
        case PRX_PSH: {
            uint32_t take = jc->prx_psh_need - jc->prx_psh_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) jc->prx_psh[jc->prx_psh_off + k] = data[i + k];
            jc->prx_psh_off += take;
            i += take;
            if (jc->prx_psh_off < jc->prx_psh_need) break;

            if (ctx->io.hdgst) {
                jc->prx_dgst_off = 0;
                jc->prx_phase = PRX_HDGST;
            } else {
                nvmet_prx_dispatch(jc, ctx);
            }
            break;
        }
        case PRX_HDGST: {
            uint32_t take = 4u - jc->prx_dgst_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) jc->prx_dgst[jc->prx_dgst_off + k] = data[i + k];
            jc->prx_dgst_off += take;
            i += take;
            if (jc->prx_dgst_off < 4u) break;

            if (nvmet_tcp_verify_hdgst(&ctx->io, jc->prx_hdr, NVME_TCP_HDR_LEN,
                                        jc->prx_psh, jc->prx_psh_need, jc->prx_dgst) != 0) {
                jc->prx_error = 1;
                break;
            }
            nvmet_prx_dispatch(jc, ctx);
            break;
        }
        case PRX_DATA: {
            uint32_t need  = jc->prx_data_need - jc->prx_data_off;
            uint32_t avail = (uint32_t)len - i;
            uint32_t take  = (need > avail) ? avail : need;
            int ts_rx_on = (ts_log_mode() & 0x2) != 0;
            uint64_t cpt0 = ts_rx_on ? timer_now() : 0;
            volatile_fast_copy(jc->prx_data_dst + jc->prx_data_off, data + i, take);
            if (ts_rx_on) jc->prx_copy_ns += (uint32_t)get_ns_from(cpt0);
            /* CRC は受信ストリームから直接積む(コピー先を読み直さない)。 */
            if (ctx->io.ddgst) {
                jc->prx_ddgst_crc = crc32c(jc->prx_ddgst_crc, data + i, take);
            }
            jc->prx_data_off += take;
            i += take;
            if (jc->prx_data_off == jc->prx_data_need) {
                if (ts_rx_on) {
                    ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_rx_upcall, 0), (0x40u << 24) | (jc->prx_copy_ns & 0xFFFFFFu));
                    ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_rx_upcall, 1),
                           (0x43u << 24) | ((uint32_t)get_ns_from(jc->prx_start_tick) & 0xFFFFFFu));
                }
                if (ctx->io.ddgst) {
                    jc->prx_dgst_off = 0;
                    jc->prx_phase = PRX_DDGST;
                } else {
                    nvmet_prx_finish_pdu(jc);
                }
            }
            break;
        }
        case PRX_DDGST: {
            uint32_t take = 4u - jc->prx_dgst_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) jc->prx_dgst[jc->prx_dgst_off + k] = data[i + k];
            jc->prx_dgst_off += take;
            i += take;
            if (jc->prx_dgst_off < 4u) break;

            if (nvmet_tcp_check_ddgst_crc(&ctx->io, jc->prx_ddgst_crc, jc->prx_dgst) != 0) {
                jc->prx_error = 1;
                break;
            }
            nvmet_prx_finish_pdu(jc);
            break;
        }
        }
    }
}

/*=================================================================
 * IO キューのステートマシン本体 1 tick。admin の準備完了を待って accept ->
 * ICReq/ICResp -> 以後はコマンド受信とディスパッチ。非 digest 接続では
 * push 型受信を登録し、ready-ring に積まれたコマンドをここで dispatch する
 * (送信は受信コンテキストの外で行う)。
 *
 * 引数:
 *   self - このジョブ
 * 戻り値:
 *   JOB_WAITING=継続
 * コール元:
 *   nvmet_io_job_step()
 * ===============================================================*/
static job_result_t nvmet_io_job_step_impl(job_t *self)
{
    nvmet_io_job_ctx_t *jc  = (nvmet_io_job_ctx_t *)self->ctx;
    nvmet_ctx_t         *ctx = jc->ctx;

    if (self->cancel_requested && (nvmet_io_state_t)self->state != NIO_ST_WAIT_ADMIN_READY) {
        int io_open = ((nvmet_io_state_t)self->state >= NIO_ST_ICREQ_RECV);
        self->cancel_requested = 0;
        return nvmet_io_job_end(self, ctx, io_open, "job stopでキャンセル");
    }

    if((uint32_t)self->state != 0x10)
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 10), (uint32_t)self->state);

    switch ((nvmet_io_state_t)self->state) {

    case NIO_ST_WAIT_ADMIN_READY:
        if (ctx->admin_failed) {
            ctx->session_active = 0;
            return JOB_DONE;
        }
        if (self->cancel_requested) {
            ctx->stop_requested = 1;
            return JOB_WAITING;
        }
        if (!ctx->io_armed) return JOB_WAITING;
        self->state = NIO_ST_ARM;
        return JOB_WAITING;

    case NIO_ST_ARM:
        uart_printf("[nvmet:%s] IOキュー接続待ち (port=%u)\n", ctx->label, (unsigned)jc->port);
        nvmet_tcp_accept_arm(&ctx->io, ctx->listener);
        jc->wait_started_ticks = timer_now();
        self->state = NIO_ST_ACCEPT_WAIT;
        return JOB_WAITING;

    case NIO_ST_ACCEPT_WAIT:
        if (tcp_accept_ready_poll(ctx->listener)) {
            uart_printf("[nvmet:%s] IOキュー接続完了\n", ctx->label);
            nvmet_tcp_xfer_reset(&jc->xfer, jc->icreq_buf, NVME_TCP_ICREQ_LEN);
            self->state = NIO_ST_ICREQ_RECV;
            return JOB_WAITING;
        }
        if (tcp_abort_requested()) {
            tcp_clear_abort_request();
            uart_printf("[nvmet:%s] Ctrl+Cで中断\n", ctx->label);
            return nvmet_io_job_end(self, ctx, 0, "Ctrl+C中断");
        }
        if (timeout_ms(jc->wait_started_ticks, NVMET_ACCEPT_TIMEOUT_MS)) {
            uart_printf("[!] nvmet: IOキュー接続待ちタイムアウト\n");
            return nvmet_io_job_end(self, ctx, 0, "IOキュー接続待ちタイムアウト");
        }
        return JOB_WAITING;

    case NIO_ST_ICREQ_RECV: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_end(self, ctx, 1, "IO ICReq受信失敗");
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVMET_ACCEPT_TIMEOUT_MS)) {
                uart_printf("[!] NVMe/TCP target: IO ICReq受信タイムアウト\n");
                return nvmet_io_job_end(self, ctx, 1, "IO ICReq受信タイムアウト");
            }
            return JOB_WAITING;
        }
        /* NRCV: ICReq(IO queue)受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICREQ;
            info.hlen     = jc->icreq_buf[2];
            info.pdo      = jc->icreq_buf[3];
            info.plen     = rd32le(&jc->icreq_buf[4]);
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 0), &info);
        }
        self->state = NIO_ST_ICRESP_SEND;
        return JOB_WAITING;
    }

    case NIO_ST_ICRESP_SEND:
        if (nvmet_tcp_send_icresp(&ctx->io, jc->icreq_buf) != 0) {
            return nvmet_io_job_end(self, ctx, 1, "IO ICResp送信失敗");
        }
        /* ダイジェスト有効時も push 型のまま扱える(パーサが PRX_HDGST/
         * PRX_DDGST 相を持ち、データダイジェストは受信ストリームから逐次
         * CRC を積む)。 */
        if (!g_nvmet_force_pull) {
            jc->push_mode   = 1;
            jc->prx_phase   = PRX_HDR;
            jc->prx_hdr_off = 0;
            jc->prx_error   = 0;
            jc->ready_head  = 0;
            jc->ready_tail  = 0;
            tcp_set_recv_upcall(&ctx->io.tcp, nvmet_io_rx_upcall, jc);
            self->state = NIO_ST_PUSH_RUN;
            uart_printf("[nvmet:%s] IOキュー push型(inline upcall)受信を有効化 (hdgst=%u ddgst=%u)\n",
                        ctx->label, ctx->io.hdgst, ctx->io.ddgst);
        } else {
            jc->push_mode = 0;
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
        }
        return JOB_WAITING;

    case NIO_ST_PUSH_RUN: {
        if (tcp_abort_requested()) {
            tcp_clear_abort_request();
            tcp_clear_recv_upcall(&ctx->io.tcp);
            uart_printf("[nvmet:%s] Ctrl+Cで中断\n", ctx->label);
            return nvmet_io_job_end(self, ctx, 1, "Ctrl+C中断");
        }
        if (jc->prx_error) {
            tcp_clear_recv_upcall(&ctx->io.tcp);
            uart_printf("[!] nvmet: push受信パースエラー(ストリーム同期崩れ/ring溢れ)\n");
            return nvmet_io_job_end(self, ctx, 1, "push受信パースエラー");
        }
        while (jc->ready_tail != jc->ready_head) {
            nvmet_ready_t *rd = &jc->ready[jc->ready_tail % NVMET_READY_RING];
            uint64_t dsp0 = timer_now();
            if (rd->kind == NVMET_READY_CMD) {
                nvmet_io_dispatch_cmd(ctx, rd->hdr, rd->sqe, rd->cid, rd->dlen, rd->incap_committed);
            } else {
                nvmet_io_dispatch_h2c(ctx, rd->h2c_slot, rd->hdr, rd->cccid, rd->ttag, rd->datao, rd->datal);
            }
            ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 1), (0x42u << 24) | ((uint32_t)get_ns_from(dsp0) & 0xFFFFFFu));
            jc->ready_tail++;
        }
        /* 相手のFIN(切断) -- ready-ring排出後にセッション終了。 */
        if (ctx->io.tcp.state != TCP_ESTABLISHED && ctx->io.tcp.state != TCP_SYN_RCVD) {
            tcp_clear_recv_upcall(&ctx->io.tcp);
            return nvmet_io_job_end(self, ctx, 1, "IOキューが切断された");
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_PDU_HDR: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) {
            if (ctx->io.tcp.state != TCP_ESTABLISHED) {
                return nvmet_io_job_end(self, ctx, 1, "IOキューが切断された");
            }
            return JOB_WAITING;
        }
        uint8_t pdu_type = jc->hdr_buf[0];
        if (pdu_type == NVME_TCP_PDU_CMD) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->sqe_buf, NVME_SQE_LEN);
            self->state = NIO_ST_RECV_CMD_SQE;
        } else if (pdu_type == NVME_TCP_PDU_H2C_DATA) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->h2c_rest_buf, 16u);
            self->state = NIO_ST_RECV_H2C_REST;
        } else {
            uart_printf("[!] nvmet: IOキューで想定外のPDU種別 (type=%u)\n", pdu_type);
            nvmet_io_debug_desync(ctx, "想定外のPDU種別");
            return nvmet_io_job_end(self, ctx, 1, "desync検出(想定外のPDU種別)");
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_CMD_SQE: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;

        jc->cid  = rd16le(&jc->sqe_buf[2]);
        jc->dlen = nvmet_tcp_parse_cmd_dlen(&ctx->io, jc->hdr_buf);
        if (jc->dlen > NVMET_IO_DATA_BUF_MAX) {
            uart_printf("[!] NVMe/TCP target: in-capsuleデータが呼び出し側バッファを超過 "
                        "(dlen=%u max=%u)\n", jc->dlen, (unsigned)NVMET_IO_DATA_BUF_MAX);
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
            return JOB_WAITING;
        }
        jc->cmd_data_dst = jc->data_buf;
        jc->incap_write_committed = 0;
        if (jc->dlen > 0 && (rd32le(&jc->sqe_buf[0]) & 0xFFu) == NVME_IO_CMD_WRITE) {
            uint64_t slba      = (uint64_t)rd32le(&jc->sqe_buf[40]) | ((uint64_t)rd32le(&jc->sqe_buf[44]) << 32);
            uint32_t nlb       = (rd32le(&jc->sqe_buf[48]) & 0xFFFFu) + 1u;
            uint32_t write_len = nlb * NVMET_LBA_SIZE;
            if (write_len == jc->dlen && (slba + nlb) <= NVMET_NS_LBA_COUNT) {
                jc->cmd_data_dst = (uint8_t *)&ctx->ram_disk[slba * NVMET_LBA_SIZE];
                jc->incap_write_committed = 1;
            }
        }
        if (ctx->io.hdgst) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NIO_ST_RECV_CMD_HDGST;
        } else if (jc->dlen > 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->cmd_data_dst, jc->dlen);
            self->state = NIO_ST_RECV_CMD_DATA;
        } else {
            self->state = NIO_ST_DISPATCH_CMD;
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_CMD_HDGST: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_hdgst(&ctx->io, jc->hdr_buf, NVME_TCP_HDR_LEN,
                                    jc->sqe_buf, NVME_SQE_LEN, jc->dgst_buf) != 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
            return JOB_WAITING;
        }
        if (jc->dlen > 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->cmd_data_dst, jc->dlen);
            self->state = NIO_ST_RECV_CMD_DATA;
        } else {
            self->state = NIO_ST_DISPATCH_CMD;
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_CMD_DATA: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (ctx->io.ddgst) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NIO_ST_RECV_CMD_DDGST;
        } else {
            self->state = NIO_ST_DISPATCH_CMD;
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_CMD_DDGST: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_ddgst(&ctx->io, jc->cmd_data_dst, jc->dlen, jc->dgst_buf) != 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
            return JOB_WAITING;
        }
        self->state = NIO_ST_DISPATCH_CMD;
        return JOB_WAITING;
    }

    case NIO_ST_DISPATCH_CMD: {
        if (jc->dlen > 0) {
            uint64_t c2n, c2b, c3n, c3b;
            tcp_copy_stats_get(&c2n, &c2b, &c3n, &c3b);
            uint64_t now = c2n + c3n;
            uint32_t pull_ns = (uint32_t)(now - jc->pull_copy_base_ns);
            ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 2), (0x41u << 24) | (pull_ns & 0xFFFFFFu));
            jc->pull_copy_base_ns = now;   /* 次コマンドの基準 */
        }
        nvmet_io_dispatch_cmd(ctx, jc->hdr_buf, jc->sqe_buf, jc->cid,
                               jc->dlen, jc->incap_write_committed);
        nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
        self->state = NIO_ST_RECV_PDU_HDR;
        return JOB_WAITING;
    }

    case NIO_ST_RECV_H2C_REST: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        jc->cccid = rd16le(&jc->h2c_rest_buf[0]);
        jc->ttag  = rd16le(&jc->h2c_rest_buf[2]);
        jc->datao = rd32le(&jc->h2c_rest_buf[4]);
        jc->datal = rd32le(&jc->h2c_rest_buf[8]);
        if (ctx->io.hdgst) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NIO_ST_RECV_H2C_HDGST;
            return JOB_WAITING;
        }
        return nvmet_io_job_h2c_validate(self, jc, ctx);
    }

    case NIO_ST_RECV_H2C_HDGST: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_hdgst(&ctx->io, jc->hdr_buf, NVME_TCP_HDR_LEN,
                                    jc->h2c_rest_buf, 16u, jc->dgst_buf) != 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
            return JOB_WAITING;
        }
        return nvmet_io_job_h2c_validate(self, jc, ctx);
    }

    case NIO_ST_RECV_H2C_DATA: {
        uint64_t rp_t0 = timer_now();
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 3), (uint32_t)get_us_from(rp_t0));
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (ctx->io.ddgst && jc->datal > 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NIO_ST_RECV_H2C_DDGST;
        } else {
            self->state = NIO_ST_DISPATCH_H2C;
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_H2C_DDGST: {
        int r = nvmet_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        {
            nvmet_pending_write_t *pw = &ctx->pending_writes[jc->h2c_slot];
            if (nvmet_tcp_verify_ddgst(&ctx->io,
                                        &ctx->ram_disk[pw->slba * NVMET_LBA_SIZE + jc->datao],
                                        jc->datal, jc->dgst_buf) != 0) {
                nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
                self->state = NIO_ST_RECV_PDU_HDR;
                return JOB_WAITING;
            }
        }
        self->state = NIO_ST_DISPATCH_H2C;
        return JOB_WAITING;
    }

    case NIO_ST_DISPATCH_H2C: {
        nvmet_io_dispatch_h2c(ctx, jc->h2c_slot, jc->hdr_buf,
                               jc->cccid, jc->ttag, jc->datao, jc->datal);
        nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
        self->state = NIO_ST_RECV_PDU_HDR;
        return JOB_WAITING;
    }

    default:
        return JOB_DONE;
    }
}

/*=================================================================
 * IO キュージョブのエントリ。停止要求を確認してから
 * nvmet_io_job_step_impl() へ委譲する。
 *
 * 引数:
 *   self - このジョブ
 * 戻り値:
 *   JOB_WAITING=継続、JOB_DONE=停止要求
 * コール元:
 *   job_scheduler_tick() から関数ポインタ経由
 * ===============================================================*/
static job_result_t nvmet_io_job_step(job_t *self)
{
    return nvmet_io_job_step_impl(self);
}

/*=================================================================
 * NVMe/TCP ターゲットを常駐起動する。指定インターフェースで port を
 * リッスンし、admin/IO の 2 本のジョブを spawn して即座に返る。同じ
 * インターフェースで既に別インスタンスが稼働していれば起動を拒否する。
 *
 * 引数:
 *   ctx       - ターゲットコンテキスト(RAM ディスクを含む)
 *   port      - リッスンポート
 *   bound_ctx - 使用するネットワークインターフェース
 *   label     - ログ用の名前
 * 戻り値:
 *   0=起動した、-1=稼働中/リッスン失敗/ジョブテーブル満杯
 * コール元:
 *   shell_dispatch(), shell_ensure_tcp_session()
 * ===============================================================*/
int nvmet_job_start(nvmet_ctx_t *ctx, uint16_t port, netif_t *bound_ctx, const char *label)
{
    if (ctx->session_active) {
        uart_printf("[nvmet:%s] 既に稼働中です(次の接続を待機中、または処理中)\n", ctx->label);
        return -1;
    }

    if (bound_ctx) {
        for (unsigned i = 0; i < NVMET_MAX_INSTANCES; i++) {
            nvmet_ctx_t *other = s_instance_owner[i];
            if (other && other != ctx && other->session_active && other->bound_ctx == bound_ctx) {
                uart_printf("[!] nvmet:%s: このインターフェースは既に別のnvmetインスタンス"
                            "(\"%s\")が稼働中です -- 同一インターフェースへ2組目のサーバを"
                            "起動すると、片方がゾンビ化してcore側のCPU時間を奪います。先に"
                            "そちらを停止するか(`job stop`)、既存のインスタンスをそのまま"
                            "使ってください。\n", label, other->label);
                return -1;
            }
        }
    }

    int slot = -1;
    for (unsigned i = 0; i < NVMET_MAX_INSTANCES; i++) {
        if (s_instance_owner[i] == ctx) { slot = (int)i; break; }
    }
    if (slot < 0) {
        for (unsigned i = 0; i < NVMET_MAX_INSTANCES; i++) {
            if (s_instance_owner[i] == NULL) { slot = (int)i; break; }
        }
    }
    if (slot < 0) {
        uart_printf("[!] nvmet: インスタンス上限(%u)に達しています\n", NVMET_MAX_INSTANCES);
        return -1;
    }

    if (job_active_count() > (unsigned)(JOB_MAX - 2)) {
        uart_printf("[!] nvmet: ジョブテーブルに空きが不足(admin/io用に2枠必要)\n");
        return -1;
    }

    int listener = tcp_listen(port, bound_ctx);
    if (listener < 0) {
        uart_printf("[!] nvmet: リスナー確保失敗(TCP_MAX_LISTENERSに空きが無い)\n");
        return -1;
    }

    ctx->io_connected      = 0;
    ctx->ctrlr_id          = 0;
    ctx->cc                = 0;
    ctx->cc_en             = 0;
    ctx->shutdown_complete = 0;
    ctx->io_armed          = 0;
    ctx->admin_failed   = 0;
    ctx->session_done   = 0;
    ctx->session_active = 1;
    ctx->stop_requested = 0;
    ctx->listener        = listener;
    ctx->bound_ctx        = bound_ctx;
    ctx->label            = label;

    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        ctx->pending_writes[i].in_use = 0;
    }
    ctx->write_incapsule_count = 0;
    ctx->write_h2c_count       = 0;

    ctx->listen_port  = port;   /* Discovery Log Page の trsvcid に載せる */
    ctx->is_discovery = 0;
    nvmet_build_id_ctrl(ctx);
    nvmet_build_id_ctrl_disc(ctx);
    nvmet_build_id_ns(ctx);

    uart_printf("[nvmet:%s] adminキュー接続待ち (port=%u)\n", label, (unsigned)port);

    s_instance_owner[slot] = ctx;

    s_admin_job_pool[slot].ctx  = ctx;
    s_admin_job_pool[slot].port = port;
    job_t *admin_job = job_spawn(nvmet_admin_job_step, &s_admin_job_pool[slot], "nvmet-admin");
    if (!admin_job) {
        uart_printf("[!] nvmet: ジョブ生成失敗(admin)\n");
        ctx->session_active = 0;
        tcp_unlisten(listener);
        s_instance_owner[slot] = NULL;
        return -1;
    }
    job_set_affinity(admin_job, bound_ctx);
    if (bound_ctx) {
        job_pin_to_core(admin_job, bound_ctx->owner_core);
    }

    s_io_job_pool[slot].ctx  = ctx;
    s_io_job_pool[slot].port = port;
    job_t *io_job = job_spawn(nvmet_io_job_step, &s_io_job_pool[slot], "nvmet-io");
    if (!io_job) {
        uart_printf("[!] nvmet: ジョブ生成失敗(io)\n");
        tcp_unlisten(listener);
        s_instance_owner[slot] = NULL;
        ctx->session_active = 0;
        return -1;
    }
    job_set_affinity(io_job, bound_ctx);
    if (bound_ctx) {
        job_pin_to_core(io_job, bound_ctx->owner_core);
    }
    return 0;
}
