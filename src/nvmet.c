#include <stddef.h>
#include "nvmet.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "job.h"
#include "tcp.h"
#include "crc32c.h"
#include "nvmet_tls.h"

int g_nvmet_force_pull = 0;

/* 広告する IO キュー(= 同時に受け付ける IO コネクション)の本数。
 * **1 にすると複数化を入れる前とまったく同じ挙動になる**(陰性対照)。
 * `nvmetqueues` で変えられるが、**効くのは次のセッションから** -- ホストとは
 * Set Features(Number of Queues)で 1 回だけ合意するため。 */
volatile uint32_t g_nvmet_io_queues = NVMET_IO_QUEUES;

/*=================================================================
 * このセッションで arm してよい IO キューの本数。
 *
 * Set Features(Number of Queues)を受ける前は 1 本だけにしておく。
 * **Linux は Connect(qid=0)の直後に必ず Set Features を出す**ので実際には
 * 上書きされるが、出さないホストでも 1 本は繋げるようにしておく
 * (複数化を入れる前の挙動)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * 戻り値:
 *   1..NVMET_IO_QUEUES
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
static unsigned nvmet_io_queue_count(const nvmet_ctx_t *ctx)
{
    uint32_t n = ctx->io_queues_granted;
    if (n == 0u) n = 1u;
    if (n > NVMET_IO_QUEUES) n = NVMET_IO_QUEUES;
    return (unsigned)n;
}

/*=================================================================
 * `g_nvmet_io_queues` を 1..NVMET_IO_QUEUES に丸める。
 * ===============================================================*/
static unsigned nvmet_io_queues_cap(void)
{
    uint32_t n = g_nvmet_io_queues;
    if (n == 0u) n = 1u;
    if (n > NVMET_IO_QUEUES) n = NVMET_IO_QUEUES;
    return (unsigned)n;
}

#define NVMET_ACCEPT_TIMEOUT_MS    30000u
/* IO キューが切れてから admin キューを相手が閉じるのを待つ上限。Linux は
 * 即座に CC.SHN を書いて閉じるので通常は数 ms しか使わない。 */
#define NVMET_ADMIN_LINGER_MS      10000u

#define NVMET_ADMIN_DATA_BUF_MAX NVME_TCP_INLINE_DATA_MAX

#define NVMET_IO_DATA_BUF_MAX NVMET_MAX_TRANSFER_BYTES

/* CQE の status フィールドは bit0=Phase / bit8:1=SC / bit11:9=SCT / bit15=DNR
 * なので、**Linux の enum { NVME_SC_* }(SC と SCT を 1 つの 15bit 値として
 * 持つ)を 1 ビット左シフトした値**になる。DNR(NVME_STATUS_DNR=0x4000)は
 * 「再送しても無駄」の意味で、コマンドの作りが悪い系のエラーに付ける。 */
#define NVMET_SC_GENERIC_ERROR 0x0002u      /* SC=0x01 Invalid Command Opcode */
#define NVMET_SC_INVALID_FIELD 0x8004u      /* SC=0x02 Invalid Field in Command + DNR */
#define NVMET_SC_INVALID_NS    0x8016u      /* SC=0x0B Invalid Namespace or Format + DNR */
#define NVMET_SC_SGL_LEN_INVALID 0x801Eu    /* SC=0x0F Data SGL Length Invalid + DNR */
#define NVMET_SC_LBA_RANGE     0x8100u      /* SC=0x80 LBA Out of Range + DNR */
#define NVMET_SC_KA_INVALID    0x8034u      /* SC=0x1A Keep Alive Timeout Invalid + DNR */
#define NVMET_SC_FEAT_NOT_SAVEABLE 0x821Au  /* SCT=1 SC=0x0D Feature Identifier Not Saveable + DNR */
#define NVMET_SC_ASYNC_LIMIT   0x820Au      /* SCT=1 SC=0x05 Async Event Request Limit Exceeded + DNR */

/* Keep Alive Timeout の粒度。Identify Controller の KAS=2(100ms 単位)と
 * 揃える。ホストの要求値はこの倍数へ切り上げてから受理する。 */
#define NVMET_KATO_GRANULARITY_MS 200u

/* 定義はもっと下(エラー記録のフックを兼ねる)。AER の完了を組み立てる
 * nvmet_aer_complete() がそれより前に来るので前方宣言する。 */
static void nvmet_build_cqe(nvmet_ctx_t *ctx, nvme_cqe_t *cqe, uint16_t cid,
                            uint32_t result, uint16_t status);

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

    wr32le(&ctx->id_ctrl[80], NVME_VS_1_3_0);     /* VER: VS レジスタと同じ値を名乗る */

    wr16le(&ctx->id_ctrl[78], 1);                /* CNTLID = 1 (ctx->ctrlr_idと一致させる) */

    ctx->id_ctrl[111] = 1;                      /* CNTRLTYPE = 1 (I/O controller) */

    wr16le(&ctx->id_ctrl[320], 2);               /* KAS = 2 (200ms単位、値自体は非0であれば可) */

    /* LPA = 0: **名前空間ごとの SMART も Command Effects ログも持たない。**
     * 実装していないビットを立てるとホストがそのログを取りに来て失敗する。
     * ELPE は 0's based なので 0 = Error Information を 1 エントリ保持する。 */
    ctx->id_ctrl[NVME_ID_CTRL_OFF_LPA]  = 0;
    ctx->id_ctrl[NVME_ID_CTRL_OFF_ELPE] = 0;

    /* **OAES を立てないと Linux は AEN を有効化せず、Async Event Request を
     * そもそも送ってこない**(`nvme_enable_aen()` が `ctrl->oaes` を見て
     * 早期 return する。D2 の実測で AER が 1 度も飛んでこなかったのはこれ)。
     * AERL は 0's based なので 0 = 同時 1 件。 */
    wr32le(&ctx->id_ctrl[NVME_ID_CTRL_OFF_OAES], NVME_AEN_CFG_NS_ATTR);
    ctx->id_ctrl[NVME_ID_CTRL_OFF_AERL] = 0;

    wr32le(&ctx->id_ctrl[536], 1u);              /* SGLS bit0 = SGL Supported */

    /* **ONCS を立てないとホストはこのコマンドを発行しない。** 実測で
     * `oncs=0` のときは `blkdiscard` がカーネルの ioctl 段階で弾かれていた
     * (「実装する」と「広告する」はワンセット)。 */
    wr16le(&ctx->id_ctrl[NVME_ID_CTRL_OFF_ONCS],
           NVME_CTRL_ONCS_DSM | NVME_CTRL_ONCS_WRITE_ZEROES);

    {
        const char *subnqn = NVMET_SUBNQN;
        uint32_t len = 0;
        while (subnqn[len] != '\0') len++;
        volatile_fast_copy(&ctx->id_ctrl[768], (const volatile uint8_t *)subnqn, len);
    }

    /* NN は「取りうる最大 nsid」。**実際に有効な数ではない**(未使用の nsid が
     * あってもよく、ホストは CNS=0x02 で有効なものを引く)。 */
    wr32le(&ctx->id_ctrl[516], NVMET_NSID_MAX);

    ctx->id_ctrl[512] = (6u << 4) | 6u;          /* SQES: 64バイト固定 */
    ctx->id_ctrl[513] = (4u << 4) | 4u;          /* CQES: 16バイト固定 */

    wr16le(&ctx->id_ctrl[514], 128);             /* MAXCMD = 128(READY_RING 256 より小さくする)*/

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
    wr32le(&ctx->id_ctrl_disc[80], NVME_VS_1_3_0); /* VER */

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
    wr16le(&ctx->id_ctrl_disc[514], 128);         /* MAXCMD */

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
    /* TREQ の bit1:0 は secure channel(TLS)を求めるかどうか。TLS はまだ無いので
     * 「求めない」(NVMF_TREQ_NOT_REQUIRED = 2)。0(指定なし)だと、ホストは TLS 付きで
     * 繋ぐべきか判断できない。**DH-HMAC-CHAP はここには載らない**(TREQ に認証の
     * ビットは無い。認証を求めることは Connect の応答の ATR で伝える)。
     * bit2(SQ flow control を無効にできる)は対応していないので立てない。
     * Linux nvmet も configfs の addr_treq の bit1:0 をそのまま入れる。 */
    e[NVMET_DISC_ENT_OFF_TREQ]    = 2u;   /* NVMF_TREQ_NOT_REQUIRED */
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
 * 名前空間の EUI-64 / NGUID を組み立てる。
 *
 * **全 0 は「識別子を持たない」の意味になる**ので、Linux は名前空間の同一性を
 * 判断できずスキャンをやり直す。実在の OUI を騙らないよう、先頭バイトに
 * ローカル管理ビット(bit1)を立てた 0x02 を置き、末尾 2 バイトに NSID を
 * 入れて名前空間ごとに異なる値にする(D8 で名前空間が増えても衝突しない)。
 *
 * 引数:
 *   out  - 書き込み先(EUI-64 は 8 バイト、NGUID は 16 バイト)
 *   nsid - 名前空間 ID
 * コール元:
 *   nvmet_build_id_ns() / nvmet_build_ns_desc_list()
 * ===============================================================*/
static void nvmet_ns_eui64(uint8_t *out, uint32_t nsid)
{
    static const uint8_t base[6] = { 0x02, 0x00, 0x00, 'N', 'V', 'M' };
    for (unsigned i = 0; i < 6; i++) out[i] = base[i];
    out[6] = (uint8_t)((nsid >> 8) & 0xFFu);
    out[7] = (uint8_t)(nsid & 0xFFu);
}

static void nvmet_ns_nguid(uint8_t *out, uint32_t nsid)
{
    static const uint8_t base[14] = { 0x02, 0x00, 0x00, 0x00,
                                      'V', 'F', 'I', 'O', 'N', 'V', 'M', 'E',
                                      0x00, 0x00 };
    for (unsigned i = 0; i < 14; i++) out[i] = base[i];
    out[14] = (uint8_t)((nsid >> 8) & 0xFFu);
    out[15] = (uint8_t)(nsid & 0xFFu);
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
static void nvmet_build_id_ns(nvmet_ctx_t *ctx, uint32_t nsid)
{
    nvmet_ns_t *ns = &ctx->ns[nsid - 1u];
    uint8_t    *p  = ns->id_ns;

    nvmet_zero(p, sizeof(ns->id_ns));
    wr64le(&p[0],  ns->lba_count);   /* NSZE */
    wr64le(&p[8],  ns->lba_count);   /* NCAP */
    wr64le(&p[16], 0);               /* NUSE */
    p[26]  = 0;                      /* FLBAS: LBA Format Index = 0 */
    p[130] = 9;                      /* LBAF[0].ds = 9 (512B = 2^9) */

    /* DLFEAT bit2:0 = 001b = **Deallocate した領域を読むと 0 が返る**。
     * ゼロ埋めする実装と整合させる(ここが 0 だと「読み出し値は不定」の
     * 意味になり、ホストは discard 後の内容を信用しない)。 */
    p[NVME_ID_NS_OFF_DLFEAT] = 0x01u;

    /* **CNS=0x03(記述子リスト)と同じ値をここにも入れる。** 片方だけに
     * 入れるとホストが「識別子が食い違う名前空間」と見なす。
     * **nsid ごとに違う値**になるので、名前空間が増えても衝突しない。 */
    nvmet_ns_nguid(&p[NVME_ID_NS_OFF_NGUID], nsid);
    nvmet_ns_eui64(&p[NVME_ID_NS_OFF_EUI64], nsid);
}

/*=================================================================
 * nsid から名前空間を引く。
 *
 * **「範囲外」と「範囲内だが未使用」は区別する。** 前者は Invalid Namespace
 * or Format、後者は Identify Namespace ならゼロ埋めで正常完了(SPDK の
 * `_nvmf_ctrlr_get_ns_safe()` と同じ切り分け)。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   nsid - コマンドの nsid フィールド
 * 戻り値:
 *   有効な名前空間、または NULL(0 / 範囲外 / ブロードキャスト / 未使用)
 * コール元:
 *   nvmet_admin_dispatch() / nvmet_io_dispatch_cmd() / 受信パーサ
 * ===============================================================*/
static nvmet_ns_t *nvmet_ns_get(nvmet_ctx_t *ctx, uint32_t nsid)
{
    if (nsid < 1u || nsid > NVMET_NSID_MAX) return NULL;
    nvmet_ns_t *ns = &ctx->ns[nsid - 1u];
    return ns->active ? ns : NULL;
}

/* nsid が「このコントローラが持ちうる範囲」に入っているか(未使用でも真)。 */
static int nvmet_nsid_in_range(uint32_t nsid)
{
    return (nsid >= 1u && nsid <= NVMET_NSID_MAX);
}

/*=================================================================
 * SMART の 128bit カウンタを 1 つ書く。上位 8 バイトは 0。
 * ===============================================================*/
_Static_assert(NVMET_STAT_CORES == SMP_MAX_CORES,
               "統計スロットの本数は SMP_MAX_CORES と合わせること");

/*=================================================================
 * このコアが使う統計スロットの番号。
 *
 * **IO のホットパスから毎コマンド呼ばれる**ので、`smp_core_index()` を
 * 読んで範囲を切るだけにする(分岐 1 個)。
 *
 * 戻り値:
 *   0..NVMET_STAT_CORES-1
 * コール元:
 *   nvmet_io_dispatch()
 * ===============================================================*/
static inline unsigned nvmet_stat_slot(void)
{
    unsigned c = smp_core_index();
    return (c < NVMET_STAT_CORES) ? c : 0u;
}

/*=================================================================
 * コアごとに分けてある統計を足し合わせる。SMART / Keep Alive / 表示という
 * 冷たい経路からしか呼ばない。NULL のポインタは無視する。
 *
 * 引数:
 *   ctx - 対象コントローラ
 *   read_bytes / write_bytes / read_cmds / write_cmds /
 *   write_incapsule / write_h2c - 合計の格納先(不要なら NULL)
 * コール元:
 *   nvmet_build_smart_log(), nvmet_admin_job_step(), nvmet_io_job_end()
 * ===============================================================*/
void nvmet_stat_totals(const nvmet_ctx_t *ctx, uint64_t *read_bytes, uint64_t *write_bytes,
                       uint64_t *read_cmds, uint64_t *write_cmds,
                       uint32_t *write_incapsule, uint32_t *write_h2c)
{
    uint64_t rb = 0, wb = 0, rc = 0, wc = 0;
    uint32_t wi = 0, wh = 0;
    for (unsigned c = 0; c < NVMET_STAT_CORES; c++) {
        rb += ctx->stat[c].read_bytes;
        wb += ctx->stat[c].write_bytes;
        rc += ctx->stat[c].read_cmds;
        wc += ctx->stat[c].write_cmds;
        wi += ctx->stat[c].write_incapsule;
        wh += ctx->stat[c].write_h2c;
    }
    if (read_bytes)      *read_bytes = rb;
    if (write_bytes)     *write_bytes = wb;
    if (read_cmds)       *read_cmds = rc;
    if (write_cmds)      *write_cmds = wc;
    if (write_incapsule) *write_incapsule = wi;
    if (write_h2c)       *write_h2c = wh;
}

/*=================================================================
 * 統計を全コアぶん 0 に戻す(プロセス起動時だけ)。
 *
 * 引数:
 *   ctx - 対象コントローラ
 * コール元:
 *   nvmet_job_start()
 * ===============================================================*/
void nvmet_stat_clear(nvmet_ctx_t *ctx)
{
    for (unsigned c = 0; c < NVMET_STAT_CORES; c++) {
        ctx->stat[c].read_bytes      = 0;
        ctx->stat[c].write_bytes     = 0;
        ctx->stat[c].read_cmds       = 0;
        ctx->stat[c].write_cmds      = 0;
        ctx->stat[c].write_incapsule = 0;
        ctx->stat[c].write_h2c       = 0;
    }
}

/*=================================================================
 * 128bit のリトルエンディアン値を書く。
 *
 * **必ず 16 バイトぶんゼロにしてから下位を書く。** 上位に残骸があると
 * 値が桁ごと跳ねる(ホストは 128bit として読む)。
 *
 * 引数:
 *   dst - 書き込み先(16 バイト)
 *   v   - 値
 * コール元:
 *   nvmet_build_smart_log()
 * ===============================================================*/
static void nvmet_wr128le(uint8_t *dst, uint64_t v)
{
    wr64le(&dst[0], v);
    wr64le(&dst[8], 0);
}

/*=================================================================
 * SMART / Health Information ログ(LID=0x02、512 バイト)を組み立てる。
 *
 * **温度はケルビン。** 0 のままだと nvme-cli が -273℃(= 0 K)と表示する
 * (実装前の実測がまさにそれ)。data_units_* は 512 バイト x 1000 単位で
 * 切り上げ、host_reads/writes はコマンド数。
 *
 * nsid は見ない。**per-namespace の SMART は持たない**(LPA bit0 = 0)ので、
 * どの nsid で来てもコントローラ全体の値を返すのが正しい。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 *   buf - 書き込み先(512 バイト以上)
 * コール元:
 *   nvmet_admin_dispatch()
 * ===============================================================*/
static void nvmet_build_smart_log(nvmet_ctx_t *ctx, uint8_t *buf)
{
    nvmet_zero(buf, NVME_SMART_LOG_LEN);

    buf[NVME_SMART_OFF_CRIT_WARN]    = 0;
    wr16le(&buf[NVME_SMART_OFF_TEMP], 300u);   /* 300 K = 約 27℃ */
    buf[NVME_SMART_OFF_AVAIL_SPARE]  = 100;
    buf[NVME_SMART_OFF_SPARE_THRESH] = 10;
    buf[NVME_SMART_OFF_PERCENT_USED] = 0;

    /* 512 バイト x 1000 = 512000 バイトで 1 単位。切り上げる。 */
    uint64_t rb = 0, wb = 0, rc = 0, wc = 0;
    nvmet_stat_totals(ctx, &rb, &wb, &rc, &wc, NULL, NULL);
    uint64_t dur = (rb + 511999ull) / 512000ull;
    uint64_t duw = (wb + 511999ull) / 512000ull;
    nvmet_wr128le(&buf[NVME_SMART_OFF_DATA_UNITS_READ], dur);
    nvmet_wr128le(&buf[NVME_SMART_OFF_DATA_UNITS_WRIT], duw);
    nvmet_wr128le(&buf[NVME_SMART_OFF_HOST_READS],  rc);
    nvmet_wr128le(&buf[NVME_SMART_OFF_HOST_WRITES], wc);

    nvmet_wr128le(&buf[NVME_SMART_OFF_CTRL_BUSY_TIME], 0);
    nvmet_wr128le(&buf[NVME_SMART_OFF_POWER_CYCLES],   1);
    /* プロセス起動からの経過時間。timer_now() は ns。 */
    nvmet_wr128le(&buf[NVME_SMART_OFF_POWER_ON_HOURS],
                  (timer_now() - ctx->start_tick) / (3600ull * 1000000000ull));
    nvmet_wr128le(&buf[NVME_SMART_OFF_UNSAFE_SHUTDN], 0);
    nvmet_wr128le(&buf[NVME_SMART_OFF_MEDIA_ERRORS],  0);
    nvmet_wr128le(&buf[NVME_SMART_OFF_NUM_ERR_LOG],   ctx->error_count);
}

/*=================================================================
 * 保留中の Async Event Request を 1 件完了させる。
 *
 * CQE の DW0 は **bit2:0 = Event Type / bit15:8 = Event Info /
 * bit23:16 = Log Page Identifier**。**完了させたら cid はもう使えない**ので
 * 保留を落とす(ホストはすぐ次の AER を発行してくる)。
 *
 * **ホストが Set Features(FID=0x0B)で有効化していないイベントは送らない。**
 * 送ると仕様違反で、ホストは知らないイベントの扱いに困る。
 *
 * 引数:
 *   ctx      - ターゲットコンテキスト
 *   type     - Event Type(NVME_AER_*)
 *   info     - Event Info
 *   lid      - 続けて読ませるログページ
 *   cfg_bit  - このイベントに対応する aen_config のビット
 * 戻り値:
 *   1=送った、0=送らなかった(保留が無い / ホストが無効にしている)
 * コール元:
 *   nvmet_ns_set_active()
 * ===============================================================*/
static int nvmet_aer_complete(nvmet_ctx_t *ctx, uint32_t type, uint32_t info,
                              uint32_t lid, uint32_t cfg_bit)
{
    if (!ctx->aer_pending) return 0;
    if ((ctx->aen_config & cfg_bit) == 0) return 0;

    nvme_cqe_t cqe;
    uint32_t   dw0 = (type & 0x7u) | ((info & 0xFFu) << 8) | ((lid & 0xFFu) << 16);
    nvmet_build_cqe(ctx, &cqe, ctx->aer_cid, dw0, 0);
    ctx->aer_pending = 0;
    if (nvmet_tcp_send_resp(&ctx->admin, &cqe) != 0) {
        uart_printf("[!] nvmet: AER完了の送信に失敗\n");
        return 0;
    }
    uart_printf("[nvmet:%s] 非同期イベント通知 (type=%u info=0x%x lid=0x%x cid=%u)\n",
                ctx->label, type, info, lid, ctx->aer_cid);
    return 1;
}

/*=================================================================
 * Changed Namespace List(LID=0x04)を組み立てる。
 *
 * **読み出したらクリアする**のが仕様(RFC ではなく NVMe Base Spec)。
 * クリアしないとホストは同じ変更を何度も見て再スキャンを繰り返す。
 * 1024 個を超えたら先頭に 0xFFFFFFFF を置いて「全部見直せ」を意味する。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 *   buf - 書き込み先(4096 バイト)
 * コール元:
 *   nvmet_admin_dispatch()
 * ===============================================================*/
static void nvmet_build_changed_ns_log(nvmet_ctx_t *ctx, uint8_t *buf)
{
    nvmet_zero(buf, NVME_MAX_CHANGED_NAMESPACES * 4u);
    if (ctx->changed_nsid_count > NVME_MAX_CHANGED_NAMESPACES) {
        wr32le(&buf[0], NVMET_NSID_BROADCAST);
    } else {
        for (uint32_t i = 0; i < ctx->changed_nsid_count; i++) {
            wr32le(&buf[i * 4u], ctx->changed_nsid[i]);
        }
    }
    ctx->changed_nsid_count = 0;   /* 読み出したらクリア */
}

/*=================================================================
 * CNS=0x06(I/O Command Set specific Identify Controller、CSI=NVM)の応答を
 * 組み立てる。レイアウトは Linux の `struct nvme_id_ctrl_nvm`。
 *
 * **Linux はここから discard の上限を読む**(`nvme_init_non_mdts_limits()` が
 * `dmrl` / `dmrsl` を `max_discard_segments` / `max_hw_discard_sectors` へ
 * 反映する)。広告しないと 1 コマンドで名前空間全体(268MB)の Deallocate が
 * 飛んできて、その memset のあいだジョブスケジューラが止まる。
 *
 * 引数:
 *   buf - 4096 バイトの書き込み先
 * コール元:
 *   nvmet_admin_dispatch()
 * ===============================================================*/
static void nvmet_build_id_ctrl_nvm(uint8_t *buf)
{
    nvmet_zero(buf, 4096);
    buf[NVME_ID_CTRL_NVM_OFF_DMRL] = (uint8_t)NVMET_DSM_MAX_RANGES_ADV;
    wr32le(&buf[NVME_ID_CTRL_NVM_OFF_DMRSL], NVMET_DSM_MAX_RANGE_LBAS);
    wr64le(&buf[NVME_ID_CTRL_NVM_OFF_DMSL],  NVMET_DSM_MAX_TOTAL_LBAS);
    /* VSL / WZSL / WUSL は 0 =「MDTS と同じ上限」の意味。Verify と
     * Write Uncorrectable は実装していないので広告もしない(ONCS で off)。 */
}

/*=================================================================
 * CNS=0x03 の記述子リストへ TLV を 1 つ追加する。
 *
 * 形式は {NIDT(1), NIDL(1), 予約(2), 値(NIDL バイト)} の連結で、**16 バイト
 * 境界へ揃えるのではなく詰めて並べる**。終端はゼロ埋めのまま(NIDT=0)。
 *
 * 引数:
 *   buf  - リストの先頭
 *   off  - 書き込み位置(進めて返す)
 *   nidt - 識別子の型(NVME_NIDT_*)
 *   nid  - 値
 *   nidl - 値の長さ
 * コール元:
 *   nvmet_build_ns_desc_list()
 * ===============================================================*/
static void nvmet_add_ns_desc(uint8_t *buf, uint32_t *off, uint8_t nidt,
                              const uint8_t *nid, uint8_t nidl)
{
    uint8_t *d = &buf[*off];
    d[0] = nidt;
    d[1] = nidl;
    d[2] = 0;
    d[3] = 0;
    for (uint8_t i = 0; i < nidl; i++) d[NVME_NIDT_HDR_LEN + i] = nid[i];
    *off += NVME_NIDT_HDR_LEN + nidl;
}

/*=================================================================
 * エラー応答を Error Information ログ(LID=0x01)へ 1 件記録する。
 *
 * ELPE は 0(= 1 エントリ)を広告しているので、保持するのは直近の 1 件だけ。
 * 累計は `error_count` が持ち、SMART の num_err_log_entries に載る。
 *
 * status_field には **CQE の status ワードをそのまま**入れる(bit0 が phase の
 * 位置に来る 16bit)。Linux の nvmet も `status << 1` を両方へ入れており、
 * nvme-cli は表示するときに 1 ビット右へ寄せる。
 *
 * 引数:
 *   ctx    - ターゲットコンテキスト
 *   cid    - コマンド id
 *   status - CQE の status ワード(非ゼロ)
 * コール元:
 *   nvmet_build_cqe()
 * ===============================================================*/
static void nvmet_record_error(nvmet_ctx_t *ctx, uint16_t cid, uint16_t status)
{
    ctx->error_count++;
    nvmet_zero(ctx->error_slot, sizeof(ctx->error_slot));
    wr64le(&ctx->error_slot[NVME_ERR_OFF_COUNT], ctx->error_count);
    const nvmet_core_stat_t *ecs = &ctx->stat[nvmet_stat_slot()];
    wr16le(&ctx->error_slot[NVME_ERR_OFF_SQID],  ecs->err_sqid);
    wr16le(&ctx->error_slot[NVME_ERR_OFF_CMDID], cid);
    wr16le(&ctx->error_slot[NVME_ERR_OFF_STATUS], status);
    wr64le(&ctx->error_slot[NVME_ERR_OFF_LBA],   ecs->err_lba);
    wr32le(&ctx->error_slot[NVME_ERR_OFF_NSID],  ecs->err_nsid);
}

static void nvmet_build_cqe(nvmet_ctx_t *ctx, nvme_cqe_t *cqe, uint16_t cid,
                            uint32_t result, uint16_t status)
{
    nvmet_zero(cqe, sizeof(*cqe));
    wr32le(&cqe->dw0, result);
    wr32le(&cqe->dw1, 0);
    wr16le(&cqe->sq_head, 0);
    wr16le(&cqe->sq_id, 0);
    wr16le(&cqe->cid, cid);
    wr16le(&cqe->status, status);
    /* **エラー応答は必ずここを通る**ので、記録もここに置けば取りこぼさない
     * (呼び出し側 50 箇所にフックを配るより確実)。 */
    if (status != 0) nvmet_record_error(ctx, cid, status);
}

/*=================================================================
 * Get Features(opcode 0x0A)で返す現在値を求める。
 *
 * **対応していない FID はここで弾いて Invalid Field in Command で返す。**
 * 「知らない FID にも成功を返す」とホストは設定できたつもりで先へ進むので、
 * どこで食い違ったのかが分からなくなる(Set Features も同じ関数で判定する)。
 *
 * Discovery コントローラが持つのは KATO と AEN だけ(SPDK の
 * nvmf_ctrlr_get_features() と同じ切り分け。IO も名前空間も無いので
 * Number of Queues と Volatile Write Cache には意味が無い)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 *   fid - Feature Identifier(cdw10 bit7:0)
 *   out - 現在値の書き込み先(未対応なら触らない)
 * 戻り値:
 *   0=対応、-1=未対応
 * コール元:
 *   nvmet_admin_dispatch()
 * ===============================================================*/
static int nvmet_feat_current(const nvmet_ctx_t *ctx, uint32_t fid, uint32_t *out)
{
    if (ctx->is_discovery && fid != NVME_FEAT_KATO && fid != NVME_FEAT_ASYNC_EVENT) {
        return -1;
    }

    switch (fid) {
    case NVME_FEAT_NUM_QUEUES: {
        /* **0's based**。NSQA=NCQA=(本数-1)。素の本数を入れると 1 本多く
         * 要求されたことになる。合意前(io_queues_granted=0)は 1 本。 */
        uint32_t nq = (uint32_t)nvmet_io_queue_count(ctx) - 1u;
        *out = nq | (nq << 16);
        return 0;
    }
    case NVME_FEAT_VOLATILE_WC:
        /* Identify Controller の VWC=0(揮発書き込みキャッシュ無し)と揃える。 */
        *out = 0u;
        return 0;
    case NVME_FEAT_ASYNC_EVENT:
        *out = ctx->aen_config;
        return 0;
    case NVME_FEAT_KATO:
        *out = ctx->kato_ms;
        return 0;
    default:
        return -1;
    }
}

/*=================================================================
 * Get Features(Select=11b = supported capabilities)が DW0 で返す能力ビット。
 *
 * **「現在値」を返してはいけない場面なので専用に持つ。** 保存領域を持たない
 * ので Saveable は常に 0、名前空間ごとの Feature も無いので NS Specific も 0。
 * Changeable は **Set Features で実際に受理して反映するものだけ** 1 にする。
 *
 * 引数:
 *   fid - Feature Identifier
 * 戻り値:
 *   DW0 に載せる能力ビット
 * コール元:
 *   nvmet_admin_dispatch()
 * ===============================================================*/
static uint32_t nvmet_feat_capabilities(uint32_t fid)
{
    switch (fid) {
    case NVME_FEAT_NUM_QUEUES:
    case NVME_FEAT_ASYNC_EVENT:
    case NVME_FEAT_KATO:
        return NVME_FEAT_CAP_CHANGEABLE;
    default:
        return 0u;   /* Volatile Write Cache は キャッシュが無いので変更できない */
    }
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

    /* **Keep Alive はどのコマンドでも延命する。** Keep Alive(0x18)だけを
     * 見ると、admin が忙しくて Keep Alive が遅れたときに切ってしまう。 */
    ctx->last_cmd_tick = timer_now();

    /* エラーを Error Information ログへ残すための文脈(admin は qid=0)。
     * **Fabrics コマンドは nsid のワードを fctype に使う**ので入れない。 */
    nvmet_core_stat_t *acs = &ctx->stat[nvmet_stat_slot()];
    acs->err_sqid = 0;
    acs->err_nsid = (opcode == NVME_FABRIC_CMD) ? 0u : rd32le(&sqe->nsid);
    acs->err_lba  = 0;

    ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_admin_dispatch, 0),
           (opcode == NVME_FABRIC_CMD)
               ? ((rd32le(&sqe->nsid) & 0xFFu) << 8) | opcode
               : opcode);

    /* **認証が済むまでは Connect と Authentication Send / Receive しか受けない。**
     * Linux は Fabrics コマンド(Property Get / Set)を素通しするが、こちらは
     * CC.EN を立てさせる前に認証を済ませる、より狭い側に倒してある
     * (Linux のホストは Connect の直後に認証するので、どちらでも同じに動く)。 */
    if (nvmet_auth_blocks(&ctx->auth)) {
        const uint32_t fct = rd32le(&sqe->nsid) & 0xFFu;
        const int allowed = (opcode == NVME_FABRIC_CMD) &&
                            (fct == NVME_FABRIC_FCTYPE_CONNECT || fct == NVME_FABRIC_FCTYPE_AUTH_SEND ||
                             fct == NVME_FABRIC_FCTYPE_AUTH_RECV);
        if (!allowed) {
            uart_printf("[auth] 認証前のコマンドを拒否 (opcode=0x%x%s)\n", opcode,
                        opcode == NVME_FABRIC_CMD ? ", Fabrics" : "");
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_AUTH_SC_AUTH_REQUIRED);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
            return 0;
        }
    }

    if (opcode == NVME_FABRIC_CMD) {
        uint32_t fctype = rd32le(&sqe->nsid) & 0xFFu;

        if (fctype == NVME_FABRIC_FCTYPE_CONNECT) {
            uint32_t qid = rd32le(&sqe->cdw10) >> 16;
            if (qid == 0) {
                /* 認証: 通常のサブシステムで鍵が設定されていれば、Connect の
                 * 応答に ATR(認証が要る)を立てる。Connect データの offset 512 が
                 * hostnqn。鍵を設定したホスト以外は Invalid Host で断る。 */
                uint32_t atr = 0;
                const int disc = (data != NULL && dlen >= 512u) ? nvmet_nqn_is_discovery(&data[256]) : 0;
                if (!disc && data != NULL && dlen >= 768u) {
                    const uint16_t ast = nvmet_auth_on_connect_tcp(&ctx->auth, &data[512], &atr,
                                                                   ctx->admin.tls != NULL);
                    if (ast != 0) {
                        nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, ast);
                        nvmet_tcp_send_resp(&ctx->admin, &cqe);
                        return 0;
                    }
                } else {
                    nvmet_auth_reset(&ctx->auth);   /* Discovery は認証しない(Linux も同じ)*/
                }
                ctx->ctrlr_id = 1;
                /* Connect のデータは struct nvmf_connect_data(1024 バイト)で、
                 * offset 256 から subsysnqn[256]。ここが Discovery NQN なら
                 * このセッションは Discovery コントローラになる。 */
                ctx->is_discovery = 0;
                if (data != NULL && dlen >= 512u) {
                    ctx->is_discovery = nvmet_nqn_is_discovery(&data[256]);
                }
                /* **KATO は Connect の cdw12(ミリ秒)。** これまで読み捨てて
                 * いたが、Get Features(FID=0x0F)が返す値なので保存する。
                 * 0 = Keep Alive 無効(Discovery は通常 0 で繋いでくる)。
                 * タイマとして強制するのは D7。 */
                ctx->kato_ms    = rd32le(&sqe->cdw12);
                ctx->aen_config = 0;
                /* 通常のサブシステムのときだけ IO キューの受け皿を用意する
                 * (Discovery コントローラは admin のみ)。
                 *
                 * **合意前は 1 本**。Linux はこの直後に Set Features
                 * (Number of Queues)を出してくるのでそこで本数が決まるが、
                 * 出さないホストでも 1 本は繋げるようにしておく。 */
                ctx->io_queues_granted = 1u;
                /* 前のセッションの KATO 切れの旗が残っていたら捨てる
                 * (IO キューが 1 本も繋がらないまま切れた場合に残りうる)。 */
                ctx->kato_expired = 0;
                /* **IO キューの受け皿はここでは立てない。ホストが CC.EN を立てたとき
                 * に立てる**(段階 H)。secure channel concatenation の Linux ホストは、
                 * 平文の admin で認証して PSK を作ると、**CC.EN を立てずに admin を閉じて
                 * TLS で張り直す**。ここで立てると、admin がその切断で畳まず、張り直しの
                 * SYN を IO 側の受け皿が受け取ってしまう。通常のホストは必ず CC.EN を
                 * 立ててから IO キューを張る。 */
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 1u | atr, 0);
                uart_printf("[nvmet:%s] Fabrics Connect (qid=0, admin) 受理 (ctrlr_id=1%s%s)\n",
                            ctx->label, ctx->is_discovery ? ", Discovery コントローラ" : "",
                            atr ? "、認証を要求" : "");
            } else {
                uart_printf("[!] nvmet: adminキューで想定外のqid=%u\n", qid);
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            }
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        } else if (fctype == NVME_FABRIC_FCTYPE_PROPERTY_SET) {
            uint32_t offset = rd32le(&sqe->cdw11);
            if (offset == NVME_REG_CC) {
                ctx->cc    = rd32le(&sqe->cdw12);
                ctx->cc_en = (ctx->cc & NVME_CC_EN) ? 1 : 0;
                if (ctx->cc_en && !ctx->io_armed && !ctx->is_discovery) {
                    ctx->io_armed = 1;
                    /* **arm 権を admin から手放す。** これで IO ジョブの 1 本が
                     * accept の受け皿を用意できるようになる。 */
                    ctx->io_arm_owner = NVMET_ARM_FREE;
                }
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
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, 0);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        } else if (fctype == NVME_FABRIC_FCTYPE_PROPERTY_GET) {
            uint32_t offset = rd32le(&sqe->cdw11);
            if (offset == NVME_REG_CAP) {
                uint32_t cap_lo = 0xFFu | (0x1Eu << 24);
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, cap_lo, 0);
                wr32le(&cqe.dw1, 0x20u);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            } else {
                uint32_t value = 0;
                if (offset == NVME_REG_CC) {
                    value = ctx->cc;
                } else if (offset == NVME_REG_VS) {
                    /* **0 のままだとホストは「1.0 未満」と見なし、
                     * CNS=0x03(名前空間の識別子)を取りに来ない。** */
                    value = NVME_VS_1_3_0;
                } else if (offset == NVME_REG_CSTS) {
                    value = (ctx->cc_en ? NVME_CSTS_RDY : 0u) |
                            (ctx->shutdown_complete ? NVME_CSTS_SHST_CMPLT : 0u);
                }
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, value, 0);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            }
        } else if (fctype == NVME_FABRIC_FCTYPE_AUTH_SEND) {
            const uint16_t st = nvmet_auth_send(&ctx->auth, rd32le(&sqe->cdw10), rd32le(&sqe->cdw11),
                                                data, dlen, NVMET_SUBNQN);
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, st);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        } else if (fctype == NVME_FABRIC_FCTYPE_AUTH_RECV) {
            /* 応答は 1 コマンドずつ同期で返すので id_scratch を使い回してよい。 */
            uint32_t olen = 0;
            const uint16_t st = nvmet_auth_receive(&ctx->auth, rd32le(&sqe->cdw10), rd32le(&sqe->cdw11),
                                                   ctx->id_scratch, sizeof(ctx->id_scratch), &olen,
                                                   NVMET_SUBNQN);
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, st);
            if (st == 0 && olen != 0) {
                nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe, ctx->id_scratch, olen, 1);
            } else {
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            }
        } else {
            uart_printf("[!] nvmet: 未対応のFabricsコマンド (fctype=0x%x)\n", fctype);
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        }
        return 0;
    }

    if (opcode == NVME_ADM_CMD_IDENTIFY) {
        uint32_t cns  = rd32le(&sqe->cdw10) & 0xFFu;
        uint32_t nsid = rd32le(&sqe->nsid);
        nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, 0);

        /* Discovery コントローラが持つのは Identify Controller だけ
         * (名前空間が無いので他の CNS には返すものが無い)。 */
        if (ctx->is_discovery && cns != NVME_IDENTIFY_CNS_CONTROLLER) {
            uart_printf("[!] nvmet: DiscoveryでのIdentify CNS=0x%x\n", cns);
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
            return 0;
        }

        if (cns == NVME_IDENTIFY_CNS_CONTROLLER) {
            /* Discovery コントローラは CNTRLTYPE / SUBNQN / NN が違う別の応答。 */
            const uint8_t *idc = ctx->is_discovery ? ctx->id_ctrl_disc : ctx->id_ctrl;
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe, idc, sizeof(ctx->id_ctrl), 1);
            return 0;
        }

        if (cns == NVME_IDENTIFY_CNS_NAMESPACE || cns == NVME_IDENTIFY_CNS_CS_NAMESPACE) {
            /* **nsid を見る。** 0 / 範囲外 / ブロードキャストは
             * Invalid Namespace or Format、**範囲内だが未使用ならゼロ埋めで
             * 正常完了**(エラーではない。SPDK の `_nvmf_ctrlr_get_ns_safe()`)。 */
            if (!nvmet_nsid_in_range(nsid)) {
                uart_printf("[!] nvmet: Identify CNS=0x%x の nsid=%u が範囲外\n", cns, nsid);
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_NS);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
                return 0;
            }
            nvmet_ns_t *ns = nvmet_ns_get(ctx, nsid);
            /* CNS=0x05(NVM コマンドセット固有)は**拡張 LBA も保護情報も
             * 持たないのでゼロ埋めが正しい応答**。未使用の nsid も同じ。 */
            if (ns == NULL || cns == NVME_IDENTIFY_CNS_CS_NAMESPACE) {
                nvmet_zero(ctx->id_scratch, sizeof(ctx->id_scratch));
                nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                    ctx->id_scratch, sizeof(ctx->id_scratch), 1);
                return 0;
            }
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                ns->id_ns, sizeof(ns->id_ns), 1);
            return 0;
        }

        if (cns == NVME_IDENTIFY_CNS_NS_ACTIVE_LIST) {
            /* **nsid は「この値より大きい NSID を昇順に並べよ」の意味**で、
             * 対象の名前空間を指すのではない(ホストは 0 から始めて続きを
             * 読む)。0xFFFFFFFE 以上は続きが存在しえないので無効。 */
            if (nsid >= 0xFFFFFFFEu) {
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_NS);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
                return 0;
            }
            nvmet_zero(ctx->id_scratch, sizeof(ctx->id_scratch));
            uint32_t off = 0;
            for (uint32_t id = 1u; id <= NVMET_NSID_MAX; id++) {
                if (id <= nsid) continue;
                if (nvmet_ns_get(ctx, id) == NULL) continue;   /* 未使用は載せない */
                wr32le(&ctx->id_scratch[off], id);
                off += 4u;
            }
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                ctx->id_scratch, sizeof(ctx->id_scratch), 1);
            return 0;
        }

        if (cns == NVME_IDENTIFY_CNS_CS_CONTROLLER) {
            /* CSI は cdw11 bit31:24。NVM 以外(ZNS など)は持っていない。 */
            uint32_t csi = (rd32le(&sqe->cdw11) >> 24) & 0xFFu;
            if (csi != NVME_CSI_NVM) {
                uart_printf("[!] nvmet: Identify CNS=0x06 の CSI=0x%x は未対応\n", csi);
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
                return 0;
            }
            nvmet_build_id_ctrl_nvm(ctx->id_scratch);
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                ctx->id_scratch, sizeof(ctx->id_scratch), 1);
            return 0;
        }

        if (cns == NVME_IDENTIFY_CNS_NS_DESC_LIST) {
            /* 範囲外は Invalid Namespace or Format、**範囲内だが未使用は
             * Invalid Field**(記述子リストには「識別子なし」を表す形が
             * 無いため。SPDK も同じ切り分け)。 */
            if (!nvmet_nsid_in_range(nsid)) {
                uart_printf("[!] nvmet: Identify CNS=0x03 の nsid=%u が範囲外\n", nsid);
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_NS);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
                return 0;
            }
            if (nvmet_ns_get(ctx, nsid) == NULL) {
                uart_printf("[!] nvmet: Identify CNS=0x03 の nsid=%u は未使用\n", nsid);
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
                return 0;
            }
            /* **Linux はこのリストで名前空間の同一性を判断する。**
             * CSI(NIDT=4)は NVM コマンドセット = 0 で、値が全 0 の記述子は
             * 載せないのが慣例(SPDK も同じ)なので EUI-64 と NGUID だけ。 */
            nvmet_zero(ctx->id_scratch, sizeof(ctx->id_scratch));
            uint8_t  nid[16];
            uint32_t off = 0;
            nvmet_ns_eui64(nid, nsid);
            nvmet_add_ns_desc(ctx->id_scratch, &off, NVME_NIDT_EUI64, nid, 8u);
            nvmet_ns_nguid(nid, nsid);
            nvmet_add_ns_desc(ctx->id_scratch, &off, NVME_NIDT_NGUID, nid, 16u);
            /* 残りはゼロのまま = NIDT=0 で終端。 */
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                ctx->id_scratch, sizeof(ctx->id_scratch), 1);
            return 0;
        }

        /* **Invalid Field in Command で返す(以前は Invalid Opcode だった)。**
         * ホストから見て「Identify が無い」のか「その CNS が無い」のかが
         * 区別できるようになる。 */
        uart_printf("[!] nvmet: 未対応のIdentify CNS=0x%x\n", cns);
        nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
        nvmet_tcp_send_resp(&ctx->admin, &cqe);
        return 0;
    }

    if (opcode == NVME_ADM_CMD_SET_FEATURES) {
        uint32_t cdw10 = rd32le(&sqe->cdw10);
        uint32_t fid   = cdw10 & 0xFFu;
        uint32_t save  = (cdw10 >> 31) & 1u;   /* SV: 不揮発領域へ保存せよ */
        uint32_t val   = rd32le(&sqe->cdw11);
        uint32_t cur   = 0;

        if (save) {
            /* 保存領域を持たない(Identify Controller の OACS bit4 = 0)。
             * SPDK の nvmf_ctrlr_set_features() と同じ扱い。 */
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_FEAT_NOT_SAVEABLE);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
            return 0;
        }
        /* **以前はどんな FID でも成功を返していた。** ホストは設定できたつもりで
         * 先へ進むので、Get Features(D2)を入れた今は必ず食い違う。 */
        if (nvmet_feat_current(ctx, fid, &cur) != 0) {
            uart_printf("[!] nvmet: 未対応のSet Features FID=0x%x\n", fid);
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
            return 0;
        }

        switch (fid) {
        case NVME_FEAT_NUM_QUEUES: {
            /* **ホストの要求とこちらの上限の小さいほうを許諾する。**
             * cdw11 は NSQR(15:0)/ NCQR(31:16)でどちらも **0's based**。
             * SQ と CQ は NVMe/TCP では 1 本のコネクションに対 1 なので、
             * 小さいほうに合わせる。
             *
             * **許諾した本数は「これから arm する IO キューの本数」でもある。**
             * ホストが使わない本数まで arm したままにすると、その受け皿が
             * 次の admin 接続の SYN を食べてしまう(Discovery のあとで
             * IO の accept が admin 用 SYN を食べた D1 の事故と同じ形)。 */
            uint32_t nsqr = (val & 0xFFFFu) + 1u;
            uint32_t ncqr = ((val >> 16) & 0xFFFFu) + 1u;
            uint32_t want = (nsqr < ncqr) ? nsqr : ncqr;
            uint32_t cap  = (uint32_t)nvmet_io_queues_cap();
            uint32_t give = (want < cap) ? want : cap;
            ctx->io_queues_granted = give;
            uint32_t nq = give - 1u;   /* 応答も 0's based */
            uart_printf("[nvmet:%s] Set Features(Number of Queues): 要求=%u 許諾=%u本\n",
                        ctx->label, (unsigned)want, (unsigned)give);
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, nq | (nq << 16), 0);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
            return 1;
        }
        case NVME_FEAT_ASYNC_EVENT:
            ctx->aen_config = val;
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, ctx->aen_config, 0);
            break;
        case NVME_FEAT_KATO:
            /* **KATO=0(Keep Alive を無効化する要求)は専用のエラーで返す。**
             * Fabrics の Keep Alive は Connect の cdw12 で決まるもので、
             * あとから 0 にして止めることはできない。 */
            if (val == 0u) {
                nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_KA_INVALID);
                break;
            }
            /* KAS の粒度へ切り上げてから受理し、受理した値を DW0 で返す。 */
            ctx->kato_ms = ((val + NVMET_KATO_GRANULARITY_MS - 1u) / NVMET_KATO_GRANULARITY_MS)
                           * NVMET_KATO_GRANULARITY_MS;
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, ctx->kato_ms, 0);
            break;
        default:
            /* Volatile Write Cache: キャッシュが無いので受理するだけ。 */
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, cur, 0);
            break;
        }
        nvmet_tcp_send_resp(&ctx->admin, &cqe);
        return 0;
    }

    if (opcode == NVME_ADM_CMD_GET_FEATURES) {
        uint32_t cdw10 = rd32le(&sqe->cdw10);
        uint32_t fid   = cdw10 & 0xFFu;
        uint32_t sel   = (cdw10 >> 8) & 0x7u;
        uint32_t value = 0;

        if (nvmet_feat_current(ctx, fid, &value) != 0) {
            uart_printf("[!] nvmet: 未対応のGet Features FID=0x%x\n", fid);
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
        } else if (sel == NVME_FEAT_SEL_SAVED) {
            /* **current の値を返してはいけない。** 保存領域を持たないので
             * 「保存された値」は存在しない。Set Features の SV=1 と同じ理由で
             * Feature Identifier Not Saveable を返す。 */
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_FEAT_NOT_SAVEABLE);
        } else if (sel == NVME_FEAT_SEL_SUPPORTED) {
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, nvmet_feat_capabilities(fid), 0);
        } else if (sel > NVME_FEAT_SEL_SUPPORTED) {
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);  /* 100b-111b は予約 */
        } else {
            /* current と default は同じ値(既定値を別に持たない)。 */
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, value, 0);
        }
        nvmet_tcp_send_resp(&ctx->admin, &cqe);
        return 0;
    }

    if (opcode == NVME_ADM_CMD_KEEP_ALIVE) {
        nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, 0);
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
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, 0);
            if (send == 0u) {
                /* 範囲外 -- データ無しで正常完了させる(エラーにはしない)。 */
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            } else {
                nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                    &ctx->disc_log[lpo], send, 1);
            }
            return 0;
        }

        if (lid == NVME_LOG_LID_CHANGED_NS) {
            /* **AER で通知したあと、ホストは必ずこれを読みに来る。**
             * 返せないと「通知は来たが何が変わったか分からない」で止まる。 */
            nvmet_build_changed_ns_log(ctx, ctx->log_page);
            uint32_t log_len = NVME_MAX_CHANGED_NAMESPACES * 4u;
            uint32_t avail   = (lpo < log_len) ? (log_len - lpo) : 0u;
            uint32_t send    = (bytes < avail) ? bytes : avail;
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, 0);
            if (send == 0u) {
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            } else {
                nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                    &ctx->log_page[lpo], send, 1);
            }
            return 0;
        }

        if (lid == NVME_LOG_LID_SMART || lid == NVME_LOG_LID_ERROR) {
            /* 実体のあるログはいったん log_page へ組み立て、LPO と要求長で
             * 切り出す(Discovery と同じ扱い)。 */
            uint32_t log_len;
            if (lid == NVME_LOG_LID_SMART) {
                nvmet_build_smart_log(ctx, ctx->log_page);
                log_len = NVME_SMART_LOG_LEN;
            } else {
                /* ELPE=0 = 1 エントリ。エラーが 1 件も無ければ error_count=0 の
                 * まま = 「未使用のエントリ」を意味する。 */
                nvmet_zero(ctx->log_page, NVME_ERROR_SLOT_LEN);
                volatile_fast_copy(ctx->log_page, ctx->error_slot, NVME_ERROR_SLOT_LEN);
                log_len = NVME_ERROR_SLOT_LEN;
            }
            uint32_t avail = (lpo < log_len) ? (log_len - lpo) : 0u;
            uint32_t send  = (bytes < avail) ? bytes : avail;
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, 0);
            if (send == 0u) {
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            } else {
                nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                                    &ctx->log_page[lpo], send, 1);
            }
            return 0;
        }

        /* それ以外の LID は持っていないので、要求された長さのゼロ埋めを返す。
         * ホスト(nvme-cli / カーネル)はこれを正常応答として扱う。返さないと
         * 接続後の Get Log Page でエラーになる。 */
        if (bytes > sizeof(ctx->log_page)) bytes = sizeof(ctx->log_page);
        for (uint32_t i = 0; i < bytes; i++) ctx->log_page[i] = 0;
        nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, 0);
        nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe,
                            ctx->log_page, bytes, 1);
        return 0;
    }

    if (opcode == NVME_ADM_CMD_ASYNC_EVENT) {
        /* 非同期イベント要求は「イベントが起きるまで完了させない」のが正しい
         * 挙動。ここで成功を返すとホストが即座に再発行して無限ループになる。
         * **cid を覚えておき、イベントが起きたら nvmet_aer_complete() で
         * 完了させる。** 保留は AERL=0(0's based)= 同時 1 個まで。 */
        if (ctx->aer_pending) {
            /* 上限超過は専用のエラー。黙って捨てるとホストは永久に待つ。 */
            uart_printf("[!] nvmet: Async Event Request が上限(1件)を超過\n");
            nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_ASYNC_LIMIT);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
            return 0;
        }
        ctx->aer_pending = 1;
        ctx->aer_cid     = ctx->admin.last_cid;
        uart_printf("[nvmet:%s] Async Event Request を受理 (cid=%u、イベント発生まで保留)\n",
                    ctx->label, ctx->aer_cid);
        return 0;
    }

    uart_printf("[!] nvmet: 未対応のadminコマンド (opcode=0x%x)\n", opcode);
    nvmet_build_cqe(ctx, &cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
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
    /* 相手から H2C TermReq が来たときに FES を読むためだけの終端状態。
     * ヘッダ 8 バイトの先に FES があるので、あと 16 バイト読んでから畳む。 */
    NADM_ST_RECV_TERM,
    /* TLS 1.3 の握手(`nvmettls` を設定したときだけ。ACCEPT_WAIT と ICREQ_RECV の間)。 */
    NADM_ST_TLS_HS,
} nvmet_admin_state_t;

/* TLS の接続状態。admin は同時に 1 本、IO はキューの番号ごと。
 * **Linux のホストは admin と IO キューの全部の接続で握手してくる。** */
static nvmet_tls_conn_t s_admin_tls;
static nvmet_tls_conn_t s_io_tls[NVMET_IO_QUEUES];

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
    /* Keep Alive の判定に使う「前回見た IO コマンド数」。**IO の hot path に
     * 時刻読み出しを足さずに「相手が生きている」を知るため**、D5 で入れた
     * SMART のカウンタが進んだかどうかで代用する。 */
    uint64_t          kato_last_io_count;
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
    nvmet_auth_reset(&ctx->auth);
    /* **IO キューの受け皿を全部畳ませる。** ARM/ACCEPT_WAIT で待っている
     * ジョブはこれを見て arm 権を手放し、WAIT_ADMIN_READY へ戻る。 */
    ctx->io_armed          = 0;
    ctx->io_queues_granted = 0;
    ctx->ctrlr_id          = 0;
    ctx->cc                = 0;
    ctx->cc_en             = 0;
    ctx->shutdown_complete = 0;
    ctx->kato_ms           = 0;
    ctx->aen_config        = 0;
    /* **保留中の AER はセッションと一緒に捨てる。** 次のホストは自分が
     * 出していない cid の CQE を受け取ることになる。 */
    ctx->aer_pending       = 0;
    ctx->aer_notify_ns     = 0;
    /* **kato_expired はここでリセットしない。** IO ジョブがまだ見ていない
     * (この関数は旗を立てた直後に呼ばれる)。消費するのは IO ジョブ側。 */
    ctx->last_cmd_tick     = 0;
    jc->linger_armed       = 0;
    jc->kato_last_io_count = 0;
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
    if (ctx->session_done) {
        if ((nvmet_admin_state_t)self->state == NADM_ST_ARM ||
            (nvmet_admin_state_t)self->state == NADM_ST_ACCEPT_WAIT) {
            /* **admin が先に畳んだ場合、IO ジョブが後から立てる session_done は
             * 前のセッションの残骸。** 捨てないと linger が始まり、10 秒後に
             * 「相手が閉じない」として**次の(正常な)セッションを畳んでしまう**。
             * D7(Keep Alive タイムアウト)で admin が先に畳む経路ができて
             * 初めて露呈した -- それまでは必ず IO のほうが先に終わっていた。 */
            ctx->session_done = 0;
        } else if (!jc->linger_armed) {
            jc->linger_armed = 1;
            jc->linger_ticks = timer_now();
        }
    }

    /* ---- Keep Alive タイマ(D7)----------------------------------------
     * **KATO=0 は「Keep Alive 無効」**。Discovery コントローラは通常 0 で
     * 繋いでくるので、ここで回すと接続直後に切ってしまう。
     *
     * 延命の契機は admin のコマンド受信(`last_cmd_tick`)と、**IO が流れて
     * いること**。IO は hot path なので時刻を読まず、**D5 で入れた SMART の
     * コマンド数カウンタが進んだかどうか**で代用する(追加コストはゼロ)。
     * これが無いと「IO は流れているのに admin が詰まっている」ときに切れる。
     *
     * `timeout_ms()` は 64bit 除算を含むが、ここは冷たい経路(admin ジョブの
     * step)なので問題ない。 */
    if (ctx->kato_ms != 0 && !ctx->kato_expired &&
        ctx->admin.tcp.state == TCP_ESTABLISHED) {
        uint64_t rc = 0, wc = 0;
        nvmet_stat_totals(ctx, NULL, NULL, &rc, &wc, NULL, NULL);
        uint64_t io_count = rc + wc;
        if (io_count != jc->kato_last_io_count) {
            jc->kato_last_io_count = io_count;
            ctx->last_cmd_tick     = timer_now();
        } else if (timeout_ms(ctx->last_cmd_tick, ctx->kato_ms)) {
            uart_printf("[!] nvmet:%s: Keep Alive タイムアウト (KATO=%u ms) -- "
                        "セッションを畳みます\n", ctx->label, ctx->kato_ms);
            /* **IO キューは IO ジョブ自身に畳ませる**(別ジョブが握って
             * いるコネクションを横から閉じると、受信 upcall の解除が
             * 抜ける)。旗を立てて次の tick に任せる。 */
            ctx->kato_expired = 1;
            return nvmet_admin_session_finish(self, jc, ctx, "Keep Alive タイムアウト");
        }
    }

    /* **名前空間の変化をホストへ通知するのはここ。** シェル(core0)が
     * `nvmens` で旗を立て、admin キューを持っているこのジョブが送る。
     * 保留中の AER が無い / ホストが AEN を無効にしているなら旗は残したまま
     * (次に AER が来たときに送る)。 */
    if (ctx->aer_notify_ns && ctx->aer_pending &&
        ctx->admin.tcp.state == TCP_ESTABLISHED) {
        if (nvmet_aer_complete(ctx, NVME_AER_NOTICE, NVME_AER_NOTICE_NS_CHANGED,
                               NVME_LOG_LID_CHANGED_NS, NVME_AEN_CFG_NS_ATTR)) {
            ctx->aer_notify_ns = 0;
        }
    }

    switch ((nvmet_admin_state_t)self->state) {

    case NADM_ST_ARM:
        /* **arm 権を IO ジョブが握っている間は待つ。** listener の受け皿
         * (`accept_conn`)は 1 本しか無いので、ここで無条件に上書きすると、
         * ACCEPT_WAIT のまま取り残された IO ジョブが次に poll した瞬間に
         * **admin 宛に確立したコネクションを横取りする**。セッション終了で
         * `io_armed` を落としてあるので、IO 側は次の tick で手放す。 */
        if (ctx->io_arm_owner >= 0) return JOB_WAITING;
        ctx->io_arm_owner = NVMET_ARM_ADMIN;
        nvmet_tcp_accept_arm(&ctx->admin, ctx->listener);
        jc->wait_started_ticks = timer_now();
        self->state = NADM_ST_ACCEPT_WAIT;
        return JOB_WAITING;

    case NADM_ST_ACCEPT_WAIT:
        if (tcp_accept_ready_poll(ctx->listener)) {
            /* IO ジョブと同じ理由で、確立したコネクションのコアへ移る
             * (下の NIO_ST_ACCEPT_WAIT のコメント参照)。 */
            job_pin_to_core(self, ctx->admin.tcp.owner_core);
            uart_printf("[nvmet:%s] adminキュー接続完了\n", ctx->label);
            nvmet_tcp_xfer_reset(&jc->xfer, jc->icreq_buf, NVME_TCP_ICREQ_LEN);
            jc->wait_started_ticks = timer_now();
            if (nvmet_tls_enabled()) {
                /* **ICReq より前に TLS の握手**(NVMe/TCP の決まり)。 */
                nvmet_tls_start(&s_admin_tls);
                self->state = NADM_ST_TLS_HS;
                return JOB_WAITING;
            }
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

    case NADM_ST_TLS_HS: {
        const int r = nvmet_tls_poll(&s_admin_tls, &ctx->admin.tcp);
        if (r < 0) {
            crypto_wipe(&s_admin_tls.t, sizeof(s_admin_tls.t));
            return nvmet_admin_job_setup_fail(self, ctx);
        }
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVMET_ACCEPT_TIMEOUT_MS)) {
                uart_printf("[!] nvmet-tls: 握手の待ちがタイムアウト\n");
                crypto_wipe(&s_admin_tls.t, sizeof(s_admin_tls.t));
                return nvmet_admin_job_setup_fail(self, ctx);
            }
            return JOB_WAITING;
        }
        /* **握手が済んだら、以後の送受信は全部レコード層を通る**(段階 E)。
         * ICReq はもう平文の待ち行列に入っているかもしれない。 */
        ctx->admin.tls = &s_admin_tls;
        self->state = NADM_ST_ICREQ_RECV;
        return JOB_WAITING;
    }

    case NADM_ST_ICREQ_RECV: {
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        /* **TLS が必須でなくても受けられるとき(concatenation で鍵を生成した後)は、
         * 最初のバイトで見分ける**: 0x16 = TLS の握手、0x00 = 平文の ICReq。 */
        if (r >= 0 && !ctx->admin.tls && jc->xfer.got > 0 && jc->icreq_buf[0] == 0x16 &&
            nvmet_tls_possible()) {
            nvmet_tls_start(&s_admin_tls);
            const int t = nvmet_tls_preload(&s_admin_tls, &ctx->admin.tcp, jc->icreq_buf, jc->xfer.got);
            if (t < 0) {
                crypto_wipe(&s_admin_tls.t, sizeof(s_admin_tls.t));
                return nvmet_admin_job_setup_fail(self, ctx);
            }
            nvmet_tcp_xfer_reset(&jc->xfer, jc->icreq_buf, NVME_TCP_ICREQ_LEN);
            self->state = NADM_ST_TLS_HS;
            return JOB_WAITING;
        }
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
        /* **IO キューが切断を知らせてこないセッションも admin が自分で畳む。**
         * IO の受け皿を張っていない(Connect を断った / Connect の前に相手が
         * 消えた)ときと、認証が済んでいないとき。段階 A で、設定外のホストの
         * Connect を Invalid Host で断ったあと admin がここで固まり、**以後の SYN を
         * 全部捨てる**ようになった(Discovery で踏んだのと同じ形)。 */
        const int no_io_report = !ctx->io_armed || nvmet_auth_blocks(&ctx->auth);
        if ((ctx->is_discovery || jc->linger_armed || no_io_report) && peer_gone) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              ctx->is_discovery
                                                  ? "Discovery セッション終了"
                                                  : no_io_report && !jc->linger_armed
                                                        ? "セッション終了(IO キュー無しで切断された)"
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
        if (jc->hdr_buf[0] == NVME_TCP_PDU_H2C_TERM) {
            /* **相手が致命的な誤りを見つけて理由を伝えてきた。** FES は
             * 共通ヘッダ(8 バイト)の先にあるので、あと 16 バイト読んでから
             * 記録して畳む(相手はこの後 TCP を閉じる)。 */
            nvmet_tcp_xfer_reset(&jc->xfer, jc->icreq_buf, 16u);
            self->state = NADM_ST_RECV_TERM;
            return JOB_WAITING;
        }
        if (jc->hdr_buf[0] != NVME_TCP_PDU_CMD) {
            uart_printf("[!] nvmet: admin想定外のPDU種別 (type=%u、CapsuleCmdを期待)\n", jc->hdr_buf[0]);
            nvmet_tcp_send_term(&ctx->admin, NVME_TCP_FES_INVALID_PDU_HDR, 0,
                                 jc->hdr_buf, NVME_TCP_HDR_LEN);
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            return JOB_WAITING;
        }
        nvmet_tcp_xfer_reset(&jc->xfer, jc->sqe_buf, NVME_SQE_LEN);
        self->state = NADM_ST_RECV_SQE;
        return JOB_WAITING;
    }

    case NADM_ST_RECV_TERM: {
        /* H2C TermReq の FES/FEI を読み終えたら記録して畳む。読み切れない
         * まま相手が閉じた場合も、次の tick で ARM へ戻る経路に乗る。 */
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0) {
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "セッション終了(H2C TermReq の途中で切断)");
        }
        if (r == 0) return JOB_WAITING;
        /* icreq_buf の先頭が PDU オフセット 8。fes(le16)+ feil(le16)+ feiu(le16)。 */
        uint16_t fes = rd16le(&jc->icreq_buf[0]);
        uint32_t fei = (uint32_t)rd16le(&jc->icreq_buf[2]) |
                       ((uint32_t)rd16le(&jc->icreq_buf[4]) << 16);
        g_nvmet_tcp_term_recv++;
        uart_printf("[!] nvmet: H2C TermReq 受信 (fes=0x%02x fei=0x%x) -- "
                    "相手がプロトコル誤りを検出しました\n",
                    (unsigned)fes, (unsigned)fei);
        return nvmet_admin_session_finish(self, jc, ctx,
                                          "セッション終了(H2C TermReq 受信)");
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
            /* **ヘッダダイジェストの不一致は致命的**(NVMe/TCP)。ヘッダが
             * 壊れている以上、次の PDU がどこから始まるか分からないので、
             * 読み直しても desync するだけ。理由を伝えて畳む。 */
            nvmet_tcp_send_term(&ctx->admin, NVME_TCP_FES_HDR_DIGEST_ERR, 0,
                                 jc->hdr_buf, NVME_TCP_HDR_LEN);
            return nvmet_admin_session_finish(self, jc, ctx,
                                              "セッション終了(ヘッダダイジェスト不一致)");
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
 * LBA 範囲を 1 つゼロで埋める(Write Zeroes と Deallocate の実体)。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   slba - 開始 LBA
 *   nlb  - 論理ブロック数(**0's based ではない実数**)
 * 戻り値:
 *   0=成功、-1=名前空間の外
 * コール元:
 *   nvmet_io_dispatch_cmd()
 * ===============================================================*/
static int nvmet_zero_lba_range(nvmet_ns_t *ns, uint64_t slba, uint64_t nlb)
{
    if (nlb == 0) return 0;
    /* **範囲外は必ずここで止める。** RAM ディスクなので、はみ出した書き込みは
     * そのまま隣のメンバ(別の名前空間や id_ctrl)のメモリ破壊になる。 */
    if (slba > ns->lba_count || nlb > ns->lba_count - slba) return -1;
    volatile_fast_zero(&ns->disk[slba * NVMET_LBA_SIZE], (size_t)nlb * NVMET_LBA_SIZE);
    return 0;
}

/*=================================================================
 * Dataset Management の範囲リストを処理する。
 *
 * Deallocate(cdw11 bit2 = AD)が立っているときだけ実際にゼロで埋める。
 * IDR / IDW はアクセスパターンのヒントなので何もしない(SPDK も同じ)。
 *
 * 引数:
 *   ctx    - ターゲットコンテキスト
 *   ranges - 16 バイト x nr の範囲リスト
 *   nr     - 範囲数(**呼び出し側で 0's based から直してある**)
 *   attr   - cdw11
 * 戻り値:
 *   0=成功、-1=範囲が名前空間の外
 * コール元:
 *   nvmet_io_dispatch_cmd()
 * ===============================================================*/
static int nvmet_dsm_apply(nvmet_ctx_t *ctx, nvmet_ns_t *ns, const uint8_t *ranges,
                           uint32_t nr, uint32_t attr)
{
    if (!(attr & NVME_DSMGMT_AD)) return 0;

    for (uint32_t i = 0; i < nr; i++) {
        const uint8_t *r = &ranges[i * NVME_DSM_RANGE_LEN];
        /* **NLB は 0's based ではない**(nvme_types.h のコメント参照)。 */
        uint32_t nlb  = rd32le(&r[NVME_DSM_OFF_NLB]);
        uint64_t slba = rd64le(&r[NVME_DSM_OFF_SLBA]);
        if (nvmet_zero_lba_range(ns, slba, nlb) != 0) {
            uart_printf("[!] nvmet: DSM範囲が名前空間外 (range=%u slba=%u nlb=%u)\n",
                        i, (uint32_t)slba, nlb);
            ctx->stat[nvmet_stat_slot()].err_lba = slba;   /* Error Information ログに載せる LBA */
            return -1;
        }
    }
    return 0;
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
    /* TLS 1.3 の握手(`nvmettls` のときだけ。ACCEPT_WAIT と ICREQ_RECV の間)。 */
    NIO_ST_TLS_HS,
} nvmet_io_state_t;

#define NIO_STATE_NAME_COUNT (sizeof(NIO_STATE_NAMES) / sizeof(NIO_STATE_NAMES[0]))

/* push型受信のパーサ相(nvmet_io_rx_upcall()、2026-08-13)。 */
typedef enum { PRX_HDR, PRX_PSH, PRX_HDGST, PRX_DATA, PRX_DDGST } nvmet_prx_phase_t;

/* NVMET_READY_RING は nvmet.h(jc->dsm_stage[] と段数を合わせるため)。 */
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
    /* このジョブが担当する IO キューの番号(0..NVMET_IO_QUEUES-1)。
     * **NVMe の qid は +1**(qid=0 は admin)。 */
    unsigned          qidx;
    /* **IO キューのコネクションはジョブごとに持つ。** nvmet_ctx_t に 1 本だけ
     * 置いていた頃の名残で `ctx->io` を参照しているところが残っていると、
     * 2 本目のキューが 1 本目の受信バッファを壊す。 */
    nvmet_tcp_conn_t  io;
    /* accept が成立して ICReq 以降へ進んだ = ctx->io_open に数えられている。 */
    int               connected;
    /* このキューが dispatch した IO コマンド数(`nvmetqueues` で表示)。
     * **セッションをまたいで積む** -- ホストが繋ぎ直しても偏りの傾向を
     * 見たいので、0 に戻すのは `nvmet` の起動時だけ。 */
    uint64_t          stat_cmds;
    /* R2T を出してデータ待ちの write。**キューごとに独立**(cid はキューの
     * 中でしか一意でないので、共有すると別キューの同じ cid と衝突する)。 */
    nvmet_pending_write_t pending_writes[NVMET_MAX_PENDING_WRITES];
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
    int               h2c_slot;  /* nvmet_io_job_h2c_validate()が確定させるjc->pending_writes[]のインデックス */
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
    /* Dataset Management の範囲リスト。**ready-ring のスロットと 1 対 1** で
     * 割り当てるので、DSM が続けて届いても互いを踏まない。ring 側に持たせると
     * スロットの間隔が 4KB 開いて **hot path(通常の read/write)の TLB を
     * 荒らす**ので、こちらへ置いてある。**キューごとに要る**(ready-ring が
     * キューごとに独立しているため)。 */
    uint8_t           dsm_stage[NVMET_READY_RING][NVMET_DSM_STAGE_BYTES] __attribute__((aligned(64)));
} nvmet_io_job_ctx_t;

static nvmet_io_job_ctx_t s_io_job_pool[NVMET_MAX_INSTANCES][NVMET_IO_QUEUES];

static nvmet_ctx_t *s_instance_owner[NVMET_MAX_INSTANCES];

/*=================================================================
 * 進行中の write コマンド(R2T を出してデータ待ち)のスロットを 1 つ確保する。
 *
 * **スロットは IO キューごとに独立**。cid はキューの中でしか一意でないので、
 * 全キューで 1 組を共有すると別キューの同じ cid を掴む。
 *
 * 引数:
 *   jc - IO ジョブ状態
 * 戻り値:
 *   スロット番号。空きが無ければ -1
 * コール元:
 *   nvmet_io_dispatch_cmd()
 * ===============================================================*/
static int nvmet_pending_write_alloc(nvmet_io_job_ctx_t *jc)
{
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        if (!jc->pending_writes[i].in_use) return (int)i;
    }
    return -1;
}

/*=================================================================
 * 進行中の write コマンドから cid が一致するスロットを探す(受信した
 * H2CData をどのコマンドのものか対応付けるのに使う)。
 *
 * 引数:
 *   jc  - IO ジョブ状態
 *   cid - 探すコマンド id
 * 戻り値:
 *   スロット番号。見つからなければ -1
 * コール元:
 *   nvmet_io_job_h2c_validate(), nvmet_io_rx_upcall()
 * ===============================================================*/
static int nvmet_pending_write_find(nvmet_io_job_ctx_t *jc, uint16_t cid)
{
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        if (jc->pending_writes[i].in_use && jc->pending_writes[i].cid == cid) return (int)i;
    }
    return -1;
}

/*=================================================================
 * IO キューでストリーム desync らしき異常(想定外の PDU 種別、未知の cccid、
 * datao 不一致など)を検出した際に、TCP 層の詳細状態を表示する診断ヘルパ。
 *
 * 引数:
 *   jc     - IO ジョブ状態
 *   reason - 検出した異常の説明
 * コール元:
 *   nvmet_io_job_h2c_validate(), nvmet_io_job_step_impl()
 * ===============================================================*/
static void nvmet_io_debug_desync(nvmet_io_job_ctx_t *jc, const char *reason)
{
    uart_printf("\n[DEBUG] ==== IOキュー%u desync検出: %s ====\n", jc->qidx + 1u, reason);
    tcp_debug_dump_rx(&jc->io.tcp);
    uart_printf("[DEBUG] ==== ここまで ====\n\n");
}

/*=================================================================
 * accept の受け皿(arm 権)をこのジョブが握っていれば手放す。
 *
 * **listener の `accept_conn` は 1 本しか無い**ので、待つのをやめるときは
 * 必ず外すこと。外さずに WAIT_ADMIN_READY へ戻ると、次に admin が
 * accept したコネクションの引き渡し先がこのジョブの `jc->io` のままになる。
 *
 * 引数:
 *   jc - IO ジョブ状態
 * コール元:
 *   nvmet_io_job_end(), nvmet_io_job_step_impl()
 * ===============================================================*/
static void nvmet_io_release_arm(nvmet_io_job_ctx_t *jc)
{
    nvmet_ctx_t *ctx = jc->ctx;
    if (ctx->io_arm_owner != (int)jc->qidx) return;
    if (tcp_accept_cancel(ctx->listener, &jc->io.tcp)) {
        /* **取り下げる瞬間に確立していた。** 誰も引き取らないまま放置すると
         * TCP_MAX_CONNS のスロットを握った孤児になるので畳む。 */
        uart_printf("[nvmet:%s] IOキュー%u: 受け皿を外す直前に確立していたので畳みます\n",
                    ctx->label, jc->qidx + 1u);
        nvmet_tcp_close(&jc->io);
    }
    ctx->io_arm_owner = NVMET_ARM_FREE;
}

/*=================================================================
 * IO キュー 1 本を畳んで次の接続待ちへ戻す。
 *
 * **最後の 1 本が閉じたときだけ session_done を立てる。** 複数キューでは
 * ホストが 1 本ずつ順に閉じてくるので、1 本目で立てると admin が linger を
 * 始めてしまい、まだ生きているキューを残したままセッションを畳む。
 *
 * 引数:
 *   self / jc - このジョブ、IO ジョブ状態
 *   close_io  - コネクションを能動 close するか
 *   reason    - ログに出す終了理由
 * 戻り値:
 *   JOB_WAITING(常駐サーバとして継続)
 * コール元:
 *   nvmet_io_job_step_impl() ほか
 * ===============================================================*/
static job_result_t nvmet_io_job_end(job_t *self, nvmet_io_job_ctx_t *jc, int close_io, const char *reason)
{
    nvmet_ctx_t *ctx = jc->ctx;

    tcp_clear_recv_upcall(&jc->io.tcp);
    if (close_io) {
        nvmet_tcp_close(&jc->io);
    }
    /* 受け皿を握ったまま待っている途中で畳まれることがある(セッション終了、
     * Ctrl+C、accept 待ちタイムアウト)。**必ず取り下げる。** */
    nvmet_io_release_arm(jc);

    if (jc->connected) {
        jc->connected = 0;
        if (ctx->io_open > 0) (void)__atomic_sub_fetch(&ctx->io_open, 1u, __ATOMIC_ACQ_REL);
    }
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        jc->pending_writes[i].in_use = 0;
    }

    uart_printf("[nvmet:%s] IOキュー%u 終了(%s)、残り %d 本\n",
                ctx->label, jc->qidx + 1u, reason, ctx->io_open);

    /* **admin キューはここで閉じない。** Linux ホストは切断時に
     * 「IO キュー切断 -> admin へ CC.SHN(Property Set offset 0x14)-> admin 切断」
     * の順で畳む。ここで能動 close すると CC.SHN の応答が返らず、ホスト側で
     * **60 秒のコマンドタイムアウト**になる(実機で踏んだ:
     * `Property Set error: 881` = NVME_SC_HOST_ABORTED_CMD = 0x371)。
     * Keep Alive も同じ理由で取りこぼしていた。相手が閉じるまで admin を
     * 生かして応答を続け、後始末は admin job(nvmet_admin_session_finish())が
     * 行う。コントローラ状態(ctrlr_id/cc/cc_en)もそれまで応答に要るので
     * ここではリセットしない。 */
    if (ctx->io_open == 0) {
        uint32_t w_inc = 0, w_h2c = 0;
        nvmet_stat_totals(ctx, NULL, NULL, NULL, NULL, &w_inc, &w_h2c);
        uart_printf("[nvmet:%s] write内訳: in-capsule=%u件 R2T+H2CData=%u件\n",
                    ctx->label, w_inc, w_h2c);
        uart_printf("[nvmet:%s] セッション終了、次のクライアントを待ちます\n", ctx->label);
        for (unsigned c = 0; c < NVMET_STAT_CORES; c++) {
            ctx->stat[c].write_incapsule = 0;
            ctx->stat[c].write_h2c       = 0;
        }
        ctx->io_armed     = 0;
        /* **KATO 切れの旗はここで消す。** 走っていたキューを全部畳み終えた
         * 印で、1 本目に消すと残りのキューが生き残る。 */
        ctx->kato_expired = 0;
        ctx->session_done = 1;  /* admin jobへ「セッション終了、ARMし直せ」を伝える */
    }

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
        return nvmet_io_job_end(self, jc, 1, "Ctrl+C中断");
    }
    if (jc->io.tcp.state != TCP_ESTABLISHED) {
        return nvmet_io_job_end(self, jc, 1, "IOキューが切断された");
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
 *   self / jc - このジョブ、IO ジョブ状態
 * 戻り値:
 *   JOB_WAITING(検証を通れば受信状態へ、失敗ならセッション終了)
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
static job_result_t nvmet_io_job_h2c_validate(job_t *self, nvmet_io_job_ctx_t *jc)
{
    int slot = nvmet_pending_write_find(jc, jc->cccid);
    if (slot < 0) {
        uart_printf("[!] nvmet: 未知のcccid=%uのH2CDataを受信\n", jc->cccid);
        nvmet_io_debug_desync(jc, "未知のcccid");
        return nvmet_io_job_end(self, jc, 1, "desync検出(未知のcccid)");
    }
    nvmet_pending_write_t *pw = &jc->pending_writes[slot];
    if (jc->datao != pw->received) {
        uart_printf("[!] nvmet: H2CDataのdataoが不一致 (cid=%u 期待=%u 受信=%u)\n",
                    jc->cccid, pw->received, jc->datao);
        nvmet_io_debug_desync(jc, "datao不一致");
        return nvmet_io_job_end(self, jc, 1, "desync検出(datao不一致)");
    }
    if (pw->received + jc->datal > pw->write_len) {
        uart_printf("[!] nvmet: H2CDataがwrite_lenを超過 "
                    "(cid=%u received=%u datal=%u write_len=%u)\n",
                    jc->cccid, pw->received, jc->datal, pw->write_len);
        nvmet_io_debug_desync(jc, "write_len超過");
        return nvmet_io_job_end(self, jc, 1, "desync検出(write_len超過)");
    }
    jc->h2c_slot = slot;
    nvmet_tcp_xfer_reset(&jc->xfer, &pw->disk[pw->slba * NVMET_LBA_SIZE + jc->datao], jc->datal);
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
 *   data     - in-capsule データが実際に置かれた場所(Dataset Management の
 *              範囲リストがここに来る。write は RAM ディスクへ直接置いている
 *              ので使わない)
 * コール元:
 *   nvmet_io_job_step_impl()
 * ===============================================================*/
static void nvmet_io_dispatch_cmd(nvmet_io_job_ctx_t *jc, const uint8_t *hdr_buf,
                                   const uint8_t *sqe_buf, uint16_t cid,
                                   uint32_t dlen, int incap_committed,
                                   const uint8_t *data)
{
    nvmet_ctx_t *ctx = jc->ctx;
    /* **このキューが何コマンド捌いたか。** 複数キュー化してからは「ホストが
     * どのキューへ振っているか」が性能の説明に要る(1 本に偏っているのか
     * 均等なのかで、遅い原因の見当が正反対になる)。`nvmetqueues` で表示。 */
    jc->stat_cmds++;
    nvme_sqe_t sqe;
    volatile_fast_copy((volatile uint8_t *)&sqe,
                        (const volatile uint8_t *)sqe_buf, NVME_SQE_LEN);
    uint32_t    opcode = rd32le(&sqe.cdw0) & 0xFFu;
    nvme_cqe_t  cqe;
    nvmet_ns_t *ns;   /* nsid から引いた対象の名前空間(下の else-if で確定)*/

    /* エラーを Error Information ログへ残すための文脈。**sqid は
     * このジョブが担当する IO キューの番号 + 1**(qid=0 は admin)。
     * LBA を持つコマンドだけが、エラーを返す直前に err_lba を入れる。 */
    nvmet_core_stat_t *dcs = &ctx->stat[nvmet_stat_slot()];
    dcs->err_sqid = (uint16_t)(jc->qidx + 1u);
    dcs->err_nsid = (opcode == NVME_FABRIC_CMD) ? 0u : rd32le(&sqe.nsid);
    dcs->err_lba  = 0;

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
            /* **qid を確認する。** ホストは IO キューを qid=1,2,... の順に
             * 張るが、どの TCP コネクションがどの qid になるかは accept の
             * 順で決まるだけなので、こちらは受け取った qid をそのまま記録して
             * 応答する(NVMe/TCP では 1 コネクション = 1 キューで、キュー間の
             * 対応付けは cntlid だけで足りる)。
             *
             * **qid=0 が来たら、それは admin 用のコネクションを IO の受け皿が
             * 食べてしまったということ。** D1 で discovery のあとに踏んだのと
             * 同じ形なので、黙って受理せずエラーで返す。 */
            uint32_t qid = rd32le(&sqe.cdw10) >> 16;
            if (qid == 0u) {
                uart_printf("[!] nvmet: IOキュー%u に qid=0(admin)のConnectが来た -- "
                            "admin用の接続を横取りしています\n", jc->qidx + 1u);
                nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
            } else if (nvmet_auth_blocks(&ctx->auth)) {
                /* **認証が済んでいないコントローラに IO キューを張らせない。**
                 * Linux はここを確かめていない(IO キューの Connect は cntlid と
                 * hostnqn の照合だけ)が、こちらは塞いでおく。 */
                uart_printf("[auth] 認証前の IO キュー Connect(qid=%u)を拒否\n", (unsigned)qid);
                nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_AUTH_SC_AUTH_REQUIRED);
            } else {
                nvmet_build_cqe(ctx, &cqe, cid, ctx->ctrlr_id, 0);
                uart_printf("[nvmet:%s] Fabrics Connect (qid=%u, IO) 受理 [キュー%u/%u]\n",
                            ctx->label, (unsigned)qid, jc->qidx + 1u,
                            nvmet_io_queue_count(ctx));
            }
        } else {
            uart_printf("[!] nvmet: IOキューで想定外のFabricsコマンド (fctype=0x%x)\n", fctype);
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
        }
        nvmet_tcp_send_resp(&jc->io, &cqe);
    } else if (!ctx->cc_en) {
        uart_printf("[!] nvmet: CC.EN=0のためIOコマンドを拒否 (opcode=0x%x)\n", opcode);
        nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
        nvmet_tcp_send_resp(&jc->io, &cqe);
    } else if (opcode == NVME_IO_CMD_FLUSH) {
        /* 名前空間の実体は RAM ディスクで揮発性キャッシュを持たないため、
         * Flush は成功を返すだけでよい(仕様上も準拠)。返さないとホスト側で
         * fsync/sync が失敗する。**nsid=0xFFFFFFFF(全名前空間)で来ることが
         * あるので、ここは名前空間の解決より前に置く。** */
        nvmet_build_cqe(ctx, &cqe, cid, 0u, 0);
        nvmet_tcp_send_resp(&jc->io, &cqe);
    } else if ((ns = nvmet_ns_get(ctx, rd32le(&sqe.nsid))) == NULL) {
        /* Read / Write / Write Zeroes / DSM は必ず 1 つの名前空間を指す。
         * **ゼロクリアされた領域を返してはいけない**(ホストが実在しない
         * 名前空間を使い始める)。 */
        uart_printf("[!] nvmet: IOコマンドのnsid=%u が無効 (opcode=0x%x)\n",
                    rd32le(&sqe.nsid), opcode);
        nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_INVALID_NS);
        nvmet_tcp_send_resp(&jc->io, &cqe);
    } else if (opcode == NVME_IO_CMD_READ) {
        uint64_t slba    = (uint64_t)rd32le(&sqe.cdw10) | ((uint64_t)rd32le(&sqe.cdw11) << 32);
        uint32_t nlb     = (rd32le(&sqe.cdw12) & 0xFFFFu) + 1u;
        uint64_t end_lba = slba + nlb;
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_dispatch_cmd, 1), nlb * NVMET_LBA_SIZE);
        dcs->err_lba = slba;

        if (end_lba > ns->lba_count) {
            uart_printf("[!] nvmet: Read範囲外 (slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&jc->io, &cqe);
        } else if ((uint64_t)nlb * NVMET_LBA_SIZE > NVMET_MAX_TRANSFER_BYTES) {
            uart_printf("[!] nvmet: Read転送量がMDTS超過 (slba=%u nlb=%u)\n",
                        (uint32_t)slba, nlb);
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&jc->io, &cqe);
        } else {
            nvmet_core_stat_t *cs = &ctx->stat[nvmet_stat_slot()];
            cs->read_bytes += (uint64_t)nlb * NVMET_LBA_SIZE;   /* SMART の data_units_read */
            cs->read_cmds++;
            nvmet_build_cqe(ctx, &cqe, cid, 0u, 0);
            /* ダイジェスト有効時もゼロコピーのまま送れる
             * (nvmet_tcp_send_c2h_async() が送信元から直接 CRC を算出する)。 */
            int c2h_rc = nvmet_tcp_send_c2h_async(&jc->io, cid,
                                                   &ns->disk[slba * NVMET_LBA_SIZE],
                                                   nlb * NVMET_LBA_SIZE);
            if (c2h_rc != 0) {
                uart_printf("[!] nvmet: C2HData送信失敗、エラー応答を試みる "
                            "(slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
                nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
                nvmet_tcp_send_resp(&jc->io, &cqe);
            }
        }
    } else if (opcode == NVME_IO_CMD_WRITE) {
        uint64_t slba      = (uint64_t)rd32le(&sqe.cdw10) | ((uint64_t)rd32le(&sqe.cdw11) << 32);
        uint32_t nlb       = (rd32le(&sqe.cdw12) & 0xFFFFu) + 1u;
        uint64_t end_lba   = slba + nlb;
        uint32_t write_len = nlb * NVMET_LBA_SIZE;
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_dispatch_cmd, 2), write_len);
        dcs->err_lba = slba;

        if (dlen > 0) {
            if (incap_committed) {
                nvmet_core_stat_t *cs = &ctx->stat[nvmet_stat_slot()];
                cs->write_incapsule++;
                cs->write_bytes += write_len;   /* SMART の data_units_written */
                cs->write_cmds++;
                nvmet_build_cqe(ctx, &cqe, cid, 0u, 0);
            } else {
                uart_printf("[!] nvmet: Write範囲外/過大 (slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
                nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            }
            nvmet_tcp_send_resp(&jc->io, &cqe);
        } else if (end_lba > ns->lba_count || write_len > NVMET_IO_DATA_BUF_MAX) {
            uart_printf("[!] nvmet: Write範囲外/過大 (slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&jc->io, &cqe);
        } else {
            int slot = nvmet_pending_write_alloc(jc);
            if (slot < 0) {
                uart_printf("[!] nvmet: 同時書き込み上限(%u件)を超過、"
                            "コマンドを拒否 (cid=%u)\n", NVMET_MAX_PENDING_WRITES, cid);
                nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
                nvmet_tcp_send_resp(&jc->io, &cqe);
            } else {
                nvmet_core_stat_t *cs = &ctx->stat[nvmet_stat_slot()];
                cs->write_h2c++;
                cs->write_bytes += write_len;   /* SMART の data_units_written */
                cs->write_cmds++;
                jc->pending_writes[slot].in_use    = 1;
                jc->pending_writes[slot].cid       = cid;
                jc->pending_writes[slot].slba      = slba;
                jc->pending_writes[slot].write_len = write_len;
                jc->pending_writes[slot].received  = 0;
                jc->pending_writes[slot].disk      = ns->disk;

                uint32_t max_h2c = nvmet_tcp_max_h2c_data(&jc->io);
                uint32_t round   = (write_len > max_h2c) ? max_h2c : write_len;
                if (nvmet_tcp_send_r2t(&jc->io, cid, 0, round) != 0) {
                    uart_printf("[!] nvmet: R2T送信失敗 (cid=%u)\n", cid);
                    jc->pending_writes[slot].in_use = 0;
                    nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
                    nvmet_tcp_send_resp(&jc->io, &cqe);
                }
            }
        }
    } else if (opcode == NVME_IO_CMD_WRITE_ZEROES) {
        /* データ転送を伴わないので C2H も R2T も出さない。cdw12 の NLB は
         * **0's based**(DSM の範囲リストの NLB とは違う)。 */
        uint64_t slba = (uint64_t)rd32le(&sqe.cdw10) | ((uint64_t)rd32le(&sqe.cdw11) << 32);
        uint32_t nlb  = (rd32le(&sqe.cdw12) & 0xFFFFu) + 1u;
        dcs->err_lba = slba;

        if (nvmet_zero_lba_range(ns, slba, nlb) != 0) {
            uart_printf("[!] nvmet: Write Zeroes範囲外 (slba=%u nlb=%u)\n", (uint32_t)slba, nlb);
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_LBA_RANGE);
        } else {
            nvmet_build_cqe(ctx, &cqe, cid, 0u, 0);
        }
        nvmet_tcp_send_resp(&jc->io, &cqe);
    } else if (opcode == NVME_IO_CMD_DSM) {
        /* NR(cdw10 bit7:0)は **0's based**。範囲リストは 16 バイト x NR で
         * ホストから送られてくる。 */
        uint32_t nr    = (rd32le(&sqe.cdw10) & 0xFFu) + 1u;
        uint32_t attr  = rd32le(&sqe.cdw11);
        uint32_t need  = nr * NVME_DSM_RANGE_LEN;

        if (data == NULL || dlen == 0) {
            /* **Linux は discard を in-capsule で送ってくる**(rq_data_dir が
             * WRITE で、16 バイトは ioccsz にまず収まる)。R2T 経路は
             * pending_writes が write 専用の作りなので用意していない。
             * 黙って成功を返すと「消したつもり」になるので必ずエラーにする。 */
            uart_printf("[!] nvmet: DSMにin-capsuleデータが無い(R2T経路は未対応, nr=%u)\n", nr);
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_INVALID_FIELD);
        } else if (dlen < need || need > NVMET_DSM_STAGE_BYTES) {
            uart_printf("[!] nvmet: DSMのデータ長が不足 (nr=%u 必要=%u 受信=%u)\n",
                        nr, need, dlen);
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_SGL_LEN_INVALID);
        } else if (nvmet_dsm_apply(ctx, ns, data, nr, attr) != 0) {
            nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_LBA_RANGE);
        } else {
            nvmet_build_cqe(ctx, &cqe, cid, 0u, 0);
        }
        nvmet_tcp_send_resp(&jc->io, &cqe);
    } else {
        uart_printf("[!] nvmet: 未対応のIOコマンド (opcode=0x%x)\n", opcode);
        nvmet_build_cqe(ctx, &cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
        nvmet_tcp_send_resp(&jc->io, &cqe);
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
static void nvmet_io_dispatch_h2c(nvmet_io_job_ctx_t *jc, int h2c_slot,
                                   const uint8_t *hdr_buf, uint16_t cccid,
                                   uint16_t ttag, uint32_t datao, uint32_t datal)
{
    nvmet_ctx_t           *ctx = jc->ctx;
    nvmet_pending_write_t *pw  = &jc->pending_writes[h2c_slot];

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
        uint32_t max_h2c = nvmet_tcp_max_h2c_data(&jc->io);
        uint32_t round   = (remain > max_h2c) ? max_h2c : remain;
        if (nvmet_tcp_send_r2t(&jc->io, pw->cid, pw->received, round) != 0) {
            uart_printf("[!] nvmet: R2T送信失敗 (cid=%u)\n", pw->cid);
            nvme_cqe_t cqe;
            nvmet_build_cqe(ctx, &cqe, pw->cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
            nvmet_tcp_send_resp(&jc->io, &cqe);
            pw->in_use = 0;
        }
    } else {
        nvme_cqe_t cqe;
        nvmet_build_cqe(ctx, &cqe, pw->cid, 0u, 0);
        nvmet_tcp_send_resp(&jc->io, &cqe);
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
    /* データが実際に置かれた場所。dispatch が読むのは DSM の範囲リストだけ
     * (write は RAM ディスクへ直接置いてある)。 */
    rd->data_dst        = (uint8_t *)jc->prx_data_dst;
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
        if (jc->prx_data_need > 0 && opcode == NVME_IO_CMD_DSM &&
            jc->prx_data_need <= NVMET_DSM_STAGE_BYTES) {
            /* **Dataset Management の範囲リストは dispatch まで生かす必要がある**
             * (write と違い、受信した時点では何もできない)。共有の data_buf に
             * 置くと、次のコマンドが届いた時点で上書きされる。ready-ring の
             * スロットと 1 対 1 の置き場へ落とす -- このスロットは
             * nvmet_ready_push_cmd() が使うのと同じ番号で、dispatch されるまで
             * 再利用されない。 */
            jc->prx_data_dst =
                (volatile uint8_t *)jc->dsm_stage[jc->ready_head % NVMET_READY_RING];
        }
        if (jc->prx_data_need > 0 && opcode == NVME_IO_CMD_WRITE) {
            /* **nsid を見て名前空間を選ぶ。** 無効なら RAM ディスクへ直接置く
             * 最適化をやめ、dispatch にエラーを返させる(data_buf 行き)。 */
            nvmet_ns_t *wns = nvmet_ns_get(ctx, rd32le(&jc->prx_psh[4]));
            uint64_t slba = (uint64_t)rd32le(&jc->prx_psh[40]) | ((uint64_t)rd32le(&jc->prx_psh[44]) << 32);
            uint32_t nlb  = (rd32le(&jc->prx_psh[48]) & 0xFFFFu) + 1u;
            uint32_t wl   = nlb * NVMET_LBA_SIZE;
            if (wns != NULL && wl == jc->prx_data_need && (slba + nlb) <= wns->lba_count) {
                jc->prx_data_dst = (volatile uint8_t *)&wns->disk[slba * NVMET_LBA_SIZE];
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
        int slot = nvmet_pending_write_find(jc, jc->prx_cccid);
        if (slot < 0) { jc->prx_error = 1; return; }
        nvmet_pending_write_t *pw = &jc->pending_writes[slot];
        if (jc->prx_datao != pw->received ||
            pw->received + jc->prx_datal > pw->write_len) {
            jc->prx_error = 1; return;
        }
        jc->prx_h2c_slot = slot;
        jc->prx_data_dst = (volatile uint8_t *)&pw->disk[pw->slba * NVMET_LBA_SIZE + jc->prx_datao];
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
                jc->prx_data_need = nvmet_tcp_parse_cmd_dlen(&jc->io, jc->prx_hdr);
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

            if (jc->io.hdgst) {
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

            if (nvmet_tcp_verify_hdgst(&jc->io, jc->prx_hdr, NVME_TCP_HDR_LEN,
                                        jc->prx_psh, jc->prx_psh_need, jc->prx_dgst) != 0) {
                /* 理由を伝えてから畳む(prx_error は上位が拾って終了させる)。 */
                nvmet_tcp_send_term(&jc->io, NVME_TCP_FES_HDR_DIGEST_ERR, 0,
                                     jc->prx_hdr, NVME_TCP_HDR_LEN);
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
            if (jc->io.ddgst) {
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
                if (jc->io.ddgst) {
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

            if (nvmet_tcp_check_ddgst_crc(&jc->io, jc->prx_ddgst_crc, jc->prx_dgst) != 0) {
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
 * TLS(段階 E)の push 型受信。届いた暗号文をレコード層へ食わせ、
 * **タグの検証が通った平文だけ**を元のパーサ(nvmet_io_rx_upcall)へ渡す。
 * レコードが壊れていた / 相手が alert を送ってきたら、パーサの失敗と同じ
 * 旗を立てて上位に畳ませる。
 * ===============================================================*/
static void nvmet_io_rx_upcall_tls(void *arg, const volatile uint8_t *data, uint16_t len)
{
    nvmet_io_job_ctx_t *jc = (nvmet_io_job_ctx_t *)arg;
    if (!jc->io.tls || nvmet_tls_feed(jc->io.tls, data, len, nvmet_io_rx_upcall, jc) != 0) {
        jc->prx_error = 1;
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

    /* **既定は「毎 tick 走る」。** 眠ってよい状態(未接続の待機、arm 権待ち、
     * コマンド待ち)だけが自分で job_park() して抜ける。ここで一度起こして
     * おくことで、park し忘れではなく unpark し忘れのほうを潰してある
     * (park し忘れは性能が戻るだけ、unpark し忘れは反応が止まる)。 */
    job_unpark(self);

    if (self->cancel_requested && (nvmet_io_state_t)self->state != NIO_ST_WAIT_ADMIN_READY) {
        int io_open = ((nvmet_io_state_t)self->state >= NIO_ST_ICREQ_RECV);
        self->cancel_requested = 0;
        return nvmet_io_job_end(self, jc, io_open, "job stopでキャンセル");
    }

    /* admin ジョブが Keep Alive タイムアウトを検出した(D7)。**自分の
     * コネクションは自分で畳む** -- upcall の解除など後始末が
     * nvmet_io_job_end() に集約してあるため。
     *
     * **旗はここで消さない。** 複数キューでは走っているキュー全部を畳む
     * 必要があるので、1 本目が消すと残りが生き残る。消すのは
     * nvmet_io_job_end() で最後の 1 本が閉じたときと、admin が次の
     * Fabrics Connect(qid=0)を受理したとき。 */
    if (ctx->kato_expired && (nvmet_io_state_t)self->state != NIO_ST_WAIT_ADMIN_READY) {
        int io_open = ((nvmet_io_state_t)self->state >= NIO_ST_ICREQ_RECV);
        return nvmet_io_job_end(self, jc, io_open, "Keep Aliveタイムアウト");
    }

    /* 定常状態(PUSH_RUN)と待機(WAIT_ADMIN_READY)は毎 tick 通るので記録しない。
     * **待機を外したのは IO ジョブが複数になったから** -- 眠っているジョブが
     * 4 本ぶん毎 tick 積むと ts リングが状態遷移で埋まって使い物にならない。 */
    if ((nvmet_io_state_t)self->state != NIO_ST_PUSH_RUN &&
        (nvmet_io_state_t)self->state != NIO_ST_WAIT_ADMIN_READY)
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
        /* **合意した本数を超えるキューは待ち続ける。** 使われない受け皿を
         * arm したまま残すと、その受け皿が次の admin 接続の SYN を食べる。
         *
         * **ここで眠る。** ジョブは常に上限(NVMET_IO_QUEUES)ぶん spawn して
         * あるので、1 本しか使わないセッションでは残り 3 本がこの状態で
         * 待ち続ける。眠らせないと 3 本が毎 tick スケジューラのロックを
         * 取り合い、実際に流れているキューの受信周期がそのぶん延びる。
         * 起床は JOB_IDLE_TICK_DIVISOR 周期の様子見だけで足りる(io_armed が
         * 立つのは接続確立という ms スケールの出来事)。 */
        if (!ctx->io_armed || jc->qidx >= nvmet_io_queue_count(ctx)) {
            job_park(self, NULL, NULL);
            return JOB_WAITING;
        }
        self->state = NIO_ST_ARM;
        return JOB_WAITING;

    case NIO_ST_ARM:
        /* セッションが先に終わっていたら arm しない。 */
        if (!ctx->io_armed || jc->qidx >= nvmet_io_queue_count(ctx)) {
            self->state = NIO_ST_WAIT_ADMIN_READY;
            return JOB_WAITING;
        }
        /* **arm 権は 1 ジョブずつ。** listener の受け皿は 1 本しか無いので、
         * 2 本目以降は先客が accept して手放すまで待つ。ホストは IO キューを
         * 1 本ずつ順に張ってくる(Linux の nvme_tcp_alloc_queue())ので、
         * これで取りこぼさない。間に合わなかった SYN は listen backlog が
         * 拾って ESTABLISHED まで進めておいてくれる。
         *
         * **先客待ちのあいだは眠る。** 手放されるのは前のキューが accept した
         * ときで、これも ms スケールの出来事。 */
        if (ctx->io_arm_owner != NVMET_ARM_FREE) {
            job_park(self, NULL, NULL);
            return JOB_WAITING;
        }
        ctx->io_arm_owner = (int)jc->qidx;
        uart_printf("[nvmet:%s] IOキュー%u 接続待ち (port=%u)\n",
                    ctx->label, jc->qidx + 1u, (unsigned)jc->port);
        nvmet_tcp_accept_arm(&jc->io, ctx->listener);
        jc->wait_started_ticks = timer_now();
        self->state = NIO_ST_ACCEPT_WAIT;
        return JOB_WAITING;

    case NIO_ST_ACCEPT_WAIT:
        /* セッションが終わった(admin が畳んだ / 最後のキューが閉じた)。
         * **受け皿を取り下げてから戻る**(取り下げないと、次に admin が
         * accept したコネクションがこのジョブの jc->io へ渡ってしまう)。 */
        if (!ctx->io_armed) {
            nvmet_io_release_arm(jc);
            self->state = NIO_ST_WAIT_ADMIN_READY;
            return JOB_WAITING;
        }
        /* **poll してよいのは arm 権を持っているジョブだけ。** 持っていない
         * ジョブが呼ぶと、armed なジョブ宛に確立したコネクションを横取りする。 */
        if (ctx->io_arm_owner != (int)jc->qidx) return JOB_WAITING;
        if (tcp_accept_ready_poll(ctx->listener)) {
            /* **受け皿を次のジョブへ譲る。** これで 2 本目以降が arm できる。 */
            ctx->io_arm_owner = NVMET_ARM_FREE;
            /* **確立したコネクションのコアへ自分を移す。**
             *
             * 受信フレームは 4-tuple のハッシュで担当コアへ配られるので、
             * このコネクションを触るのはそのコアだけにしないといけない
             * (受信 upcall と、このジョブの送信が同じ tcp_priv_t を
             * 別コアから同時に触ると壊れる)。**accept したコアが
             * そのまま担当コア**なので、ジョブをそこへ移せば揃う。
             * 単一コアのときは今のコアと同じなので何も起きない。 */
            job_pin_to_core(self, jc->io.tcp.owner_core);
            jc->connected = 1;
            (void)__atomic_add_fetch(&ctx->io_open, 1u, __ATOMIC_ACQ_REL);
            /* **ACK の相乗りはキューが多いときだけ得。** 相手に余裕が
             * ある(= 多キューで直列化して待っている)条件では +9% だが、
             * 相手が飽和している 1〜3 本では **ACK が送信のペーシングに
             * 効いている**ので 4〜16% 損をする。実測に基づく閾値。 */
            tcp_set_ack_piggyback(&jc->io.tcp,
                                  ctx->io_queues_granted >= NVMET_ACKPIGGY_MIN_QUEUES);
            uart_printf("[nvmet:%s] IOキュー%u 接続完了 (%d/%u本)\n",
                        ctx->label, jc->qidx + 1u, ctx->io_open,
                        nvmet_io_queue_count(ctx));
            nvmet_tcp_xfer_reset(&jc->xfer, jc->icreq_buf, NVME_TCP_ICREQ_LEN);
            /* **ICReq のタイムアウトは accept からの経過で測る。** ARM 時刻の
             * ままだと、ホストが繋いでくるまで長く待った 2 本目以降で
             * 残り時間がほとんど無くなる。 */
            jc->wait_started_ticks = timer_now();
            if (nvmet_tls_enabled()) {
                nvmet_tls_start(&s_io_tls[jc->qidx]);
                self->state = NIO_ST_TLS_HS;
                return JOB_WAITING;
            }
            self->state = NIO_ST_ICREQ_RECV;
            return JOB_WAITING;
        }
        if (tcp_abort_requested()) {
            tcp_clear_abort_request();
            uart_printf("[nvmet:%s] Ctrl+Cで中断\n", ctx->label);
            return nvmet_io_job_end(self, jc, 0, "Ctrl+C中断");
        }
        /* **タイムアウトを見るのは「まだ 1 本も繋がっていない」ときだけ。**
         * 既に別のキューが動いているなら、ホストが残りを張ってこないだけ
         * かもしれない(要求より少ない本数しか使わないホストもいる)ので、
         * セッションを畳んではいけない。 */
        if (ctx->io_open == 0 &&
            timeout_ms(jc->wait_started_ticks, NVMET_ACCEPT_TIMEOUT_MS)) {
            uart_printf("[!] nvmet: IOキュー接続待ちタイムアウト\n");
            return nvmet_io_job_end(self, jc, 0, "IOキュー接続待ちタイムアウト");
        }
        return JOB_WAITING;

    case NIO_ST_TLS_HS: {
        const int r = nvmet_tls_poll(&s_io_tls[jc->qidx], &jc->io.tcp);
        if (r < 0) return nvmet_io_job_end(self, jc, 1, "IO の TLS 握手に失敗");
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVMET_ACCEPT_TIMEOUT_MS)) {
                uart_printf("[!] nvmet-tls: IO キューの握手の待ちがタイムアウト\n");
                return nvmet_io_job_end(self, jc, 1, "IO の TLS 握手タイムアウト");
            }
            return JOB_WAITING;
        }
        jc->io.tls = &s_io_tls[jc->qidx];
        self->state = NIO_ST_ICREQ_RECV;
        return JOB_WAITING;
    }

    case NIO_ST_ICREQ_RECV: {
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r >= 0 && !jc->io.tls && jc->xfer.got > 0 && jc->icreq_buf[0] == 0x16 && nvmet_tls_possible()) {
            nvmet_tls_start(&s_io_tls[jc->qidx]);
            if (nvmet_tls_preload(&s_io_tls[jc->qidx], &jc->io.tcp, jc->icreq_buf, jc->xfer.got) < 0)
                return nvmet_io_job_end(self, jc, 1, "IO の TLS 握手に失敗");
            nvmet_tcp_xfer_reset(&jc->xfer, jc->icreq_buf, NVME_TCP_ICREQ_LEN);
            self->state = NIO_ST_TLS_HS;
            return JOB_WAITING;
        }
        if (r < 0) return nvmet_io_job_end(self, jc, 1, "IO ICReq受信失敗");
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVMET_ACCEPT_TIMEOUT_MS)) {
                uart_printf("[!] NVMe/TCP target: IO ICReq受信タイムアウト\n");
                return nvmet_io_job_end(self, jc, 1, "IO ICReq受信タイムアウト");
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
        if (nvmet_tcp_send_icresp(&jc->io, jc->icreq_buf) != 0) {
            return nvmet_io_job_end(self, jc, 1, "IO ICResp送信失敗");
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
            if (jc->io.tls) {
                /* TLS: upcall の前に復号を挟む。握手と ICReq の間に復号済みの
                 * 平文が残っていれば、先にパーサへ渡す。 */
                tcp_set_recv_upcall(&jc->io.tcp, nvmet_io_rx_upcall_tls, jc);
                nvmet_tls_drain(jc->io.tls, nvmet_io_rx_upcall, jc);
            } else {
                tcp_set_recv_upcall(&jc->io.tcp, nvmet_io_rx_upcall, jc);
            }
            self->state = NIO_ST_PUSH_RUN;
            uart_printf("[nvmet:%s] IOキュー%u push型(inline upcall)受信を有効化 (hdgst=%u ddgst=%u)\n",
                        ctx->label, jc->qidx + 1u, jc->io.hdgst, jc->io.ddgst);
        } else {
            jc->push_mode = 0;
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
        }
        return JOB_WAITING;

    case NIO_ST_PUSH_RUN: {
        if (tcp_abort_requested()) {
            tcp_clear_abort_request();
            tcp_clear_recv_upcall(&jc->io.tcp);
            uart_printf("[nvmet:%s] Ctrl+Cで中断\n", ctx->label);
            return nvmet_io_job_end(self, jc, 1, "Ctrl+C中断");
        }
        if (jc->prx_error) {
            tcp_clear_recv_upcall(&jc->io.tcp);
            uart_printf("[!] nvmet: push受信パースエラー(ストリーム同期崩れ/ring溢れ)\n");
            return nvmet_io_job_end(self, jc, 1, "push受信パースエラー");
        }
        /* **この排出の間に出る応答 PDU を 1 セグメントへ束ねる。**
         * kernel/SPDK は応答を 3〜4 個ずつ 1 パケットに載せてくるのに、
         * こちらは 1 PDU = 1 セグメントで、**相手の受信パケット/コマンドが
         * 4〜6 倍**になっていた。**`_end` を必ず通ること**(溜めたまま
         * park すると応答が止まる)。 */
        nvmet_tcp_tx_batch_begin(&jc->io);
        while (jc->ready_tail != jc->ready_head) {
            nvmet_ready_t *rd = &jc->ready[jc->ready_tail % NVMET_READY_RING];
            uint64_t dsp0 = timer_now();
            if (rd->kind == NVMET_READY_CMD) {
                nvmet_io_dispatch_cmd(jc, rd->hdr, rd->sqe, rd->cid, rd->dlen, rd->incap_committed, rd->data_dst);
            } else {
                nvmet_io_dispatch_h2c(jc, rd->h2c_slot, rd->hdr, rd->cccid, rd->ttag, rd->datao, rd->datal);
            }
            ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 1), (0x42u << 24) | ((uint32_t)get_ns_from(dsp0) & 0xFFFFFFu));
            jc->ready_tail++;
        }
        (void)nvmet_tcp_tx_batch_end(&jc->io);
        /* **応答へ相乗りできなかった ACK をここで返す。** 応答を出して
         * いれば何もしない(相乗り済み)。出していないときに返さないと
         * 相手が RTO まで待つ。 */
        (void)tcp_ack_flush(&jc->io.tcp);
        /* 相手のFIN(切断) -- ready-ring排出後にセッション終了。 */
        if (jc->io.tcp.state != TCP_ESTABLISHED && jc->io.tcp.state != TCP_SYN_RCVD) {
            tcp_clear_recv_upcall(&jc->io.tcp);
            return nvmet_io_job_end(self, jc, 1, "IOキューが切断された");
        }
        /* **コマンドが無いあいだは眠る。** 起床条件は ready-ring が空でない
         * ことそのものなので、**反応時間は 1 tick も増えない**(upcall が
         * ready_head を進めた次の tick でスケジューラが起こす)。
         * ホストが繋いだだけで使っていないキューは、これでほぼ無料になる。
         *
         * 上の 3 つ(Ctrl+C / パースエラー / 切断)を見るのが
         * JOB_IDLE_TICK_DIVISOR 周期に落ちるが、いずれも ms を争わない。 */
        if (jc->ready_tail == jc->ready_head && !tcp_ack_owed(&jc->io.tcp)) {
            job_park(self, &jc->ready_head, &jc->ready_tail);
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_PDU_HDR: {
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) {
            if (jc->io.tcp.state != TCP_ESTABLISHED) {
                return nvmet_io_job_end(self, jc, 1, "IOキューが切断された");
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
        } else if (pdu_type == NVME_TCP_PDU_H2C_TERM) {
            /* **相手が致命的な誤りを見つけて理由を伝えてきた。** IO キューは
             * 畳むだけでよい(FES の中身は admin 側で読む -- IO の受信は
             * push 型 upcall と混在していて、追加の読み出し状態を足すと
             * desync の扱いが複雑になる)。 */
            g_nvmet_tcp_term_recv++;
            uart_printf("[!] nvmet: IOキューで H2C TermReq 受信 -- "
                        "相手がプロトコル誤りを検出しました\n");
            return nvmet_io_job_end(self, jc, 1, "H2C TermReq 受信");
        } else {
            uart_printf("[!] nvmet: IOキューで想定外のPDU種別 (type=%u)\n", pdu_type);
            /* **相手に理由を伝えてから畳む。** 伝えないと相手のログには
             * 「接続が切れた」としか残らない。 */
            nvmet_tcp_send_term(&jc->io, NVME_TCP_FES_INVALID_PDU_HDR, 0,
                                 jc->hdr_buf, NVME_TCP_HDR_LEN);
            nvmet_io_debug_desync(jc, "想定外のPDU種別");
            return nvmet_io_job_end(self, jc, 1, "desync検出(想定外のPDU種別)");
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_CMD_SQE: {
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;

        jc->cid  = rd16le(&jc->sqe_buf[2]);
        jc->dlen = nvmet_tcp_parse_cmd_dlen(&jc->io, jc->hdr_buf);
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
            nvmet_ns_t *wns    = nvmet_ns_get(ctx, rd32le(&jc->sqe_buf[4]));   /* nsid */
            uint64_t slba      = (uint64_t)rd32le(&jc->sqe_buf[40]) | ((uint64_t)rd32le(&jc->sqe_buf[44]) << 32);
            uint32_t nlb       = (rd32le(&jc->sqe_buf[48]) & 0xFFFFu) + 1u;
            uint32_t write_len = nlb * NVMET_LBA_SIZE;
            if (wns != NULL && write_len == jc->dlen && (slba + nlb) <= wns->lba_count) {
                jc->cmd_data_dst = (uint8_t *)&wns->disk[slba * NVMET_LBA_SIZE];
                jc->incap_write_committed = 1;
            }
        }
        if (jc->io.hdgst) {
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
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_hdgst(&jc->io, jc->hdr_buf, NVME_TCP_HDR_LEN,
                                    jc->sqe_buf, NVME_SQE_LEN, jc->dgst_buf) != 0) {
            /* ヘッダダイジェストの不一致は致命的(admin 側と同じ理由)。 */
            nvmet_tcp_send_term(&jc->io, NVME_TCP_FES_HDR_DIGEST_ERR, 0,
                                 jc->hdr_buf, NVME_TCP_HDR_LEN);
            return nvmet_io_job_end(self, jc, 1, "ヘッダダイジェスト不一致");
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
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (jc->io.ddgst) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NIO_ST_RECV_CMD_DDGST;
        } else {
            self->state = NIO_ST_DISPATCH_CMD;
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_CMD_DDGST: {
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_ddgst(&jc->io, jc->cmd_data_dst, jc->dlen, jc->dgst_buf) != 0) {
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
        nvmet_io_dispatch_cmd(jc, jc->hdr_buf, jc->sqe_buf, jc->cid,
                               jc->dlen, jc->incap_write_committed, jc->cmd_data_dst);
        nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
        self->state = NIO_ST_RECV_PDU_HDR;
        return JOB_WAITING;
    }

    case NIO_ST_RECV_H2C_REST: {
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        jc->cccid = rd16le(&jc->h2c_rest_buf[0]);
        jc->ttag  = rd16le(&jc->h2c_rest_buf[2]);
        jc->datao = rd32le(&jc->h2c_rest_buf[4]);
        jc->datal = rd32le(&jc->h2c_rest_buf[8]);
        if (jc->io.hdgst) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NIO_ST_RECV_H2C_HDGST;
            return JOB_WAITING;
        }
        return nvmet_io_job_h2c_validate(self, jc);
    }

    case NIO_ST_RECV_H2C_HDGST: {
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (nvmet_tcp_verify_hdgst(&jc->io, jc->hdr_buf, NVME_TCP_HDR_LEN,
                                    jc->h2c_rest_buf, 16u, jc->dgst_buf) != 0) {
            nvmet_tcp_send_term(&jc->io, NVME_TCP_FES_HDR_DIGEST_ERR, 0,
                                 jc->hdr_buf, NVME_TCP_HDR_LEN);
            return nvmet_io_job_end(self, jc, 1, "ヘッダダイジェスト不一致(H2CData)");
        }
        return nvmet_io_job_h2c_validate(self, jc);
    }

    case NIO_ST_RECV_H2C_DATA: {
        uint64_t rp_t0 = timer_now();
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 3), (uint32_t)get_us_from(rp_t0));
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        if (jc->io.ddgst && jc->datal > 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->dgst_buf, 4u);
            self->state = NIO_ST_RECV_H2C_DDGST;
        } else {
            self->state = NIO_ST_DISPATCH_H2C;
        }
        return JOB_WAITING;
    }

    case NIO_ST_RECV_H2C_DDGST: {
        int r = nvmet_tcp_recv_poll(&jc->io, &jc->xfer);
        if (r < 0) return nvmet_io_job_recv_fail(self, jc, ctx);
        if (r == 0) return JOB_WAITING;
        {
            nvmet_pending_write_t *pw = &jc->pending_writes[jc->h2c_slot];
            if (nvmet_tcp_verify_ddgst(&jc->io,
                                        &pw->disk[pw->slba * NVMET_LBA_SIZE + jc->datao],
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
        nvmet_io_dispatch_h2c(jc, jc->h2c_slot, jc->hdr_buf,
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

    /* admin 1 本 + IO キュー NVMET_IO_QUEUES 本。**実行時に本数を減らしても
     * ジョブは上限ぶん spawn する** -- Set Features の合意はセッションごとに
     * 変わるので、そのたびにジョブを作り直すより、余ったジョブを
     * WAIT_ADMIN_READY で眠らせておくほうが単純で安全。 */
    const unsigned need_jobs = 1u + NVMET_IO_QUEUES;
    if (job_active_count() + need_jobs > (unsigned)JOB_MAX) {
        uart_printf("[!] nvmet: ジョブテーブルに空きが不足(admin/io用に%u枠必要)\n", need_jobs);
        return -1;
    }

    int listener = tcp_listen(port, bound_ctx);
    if (listener < 0) {
        uart_printf("[!] nvmet: リスナー確保失敗(TCP_MAX_LISTENERSに空きが無い)\n");
        return -1;
    }

    ctx->io_open           = 0;
    ctx->io_arm_owner      = NVMET_ARM_FREE;
    ctx->io_queues_granted = 0;
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

    /* SMART / Error Information の統計。**ここでしか 0 に戻さない**
     * (ホストが繋ぎ直しても実コントローラの通電中統計は続く)。 */
    ctx->start_tick       = timer_now();
    nvmet_stat_clear(ctx);
    ctx->error_count      = 0;
    nvmet_zero(ctx->error_slot, sizeof(ctx->error_slot));

    /* 名前空間。**既定で有効なのは nsid=1 だけ**で、nsid=2 は `nvmens add 2`
     * で後から生やす(D6 の AER をそこで発火させる)。 */
    ctx->ns[0].active    = 1;
    ctx->ns[0].lba_count = NVMET_NS1_LBA_COUNT;
    ctx->ns[0].disk      = ctx->ram_disk;
    ctx->ns[1].active    = 0;
    ctx->ns[1].lba_count = NVMET_NS2_LBA_COUNT;
    ctx->ns[1].disk      = ctx->ram_disk2;

    ctx->aer_pending        = 0;
    ctx->aer_notify_ns      = 0;
    ctx->kato_expired       = 0;
    ctx->last_cmd_tick      = 0;
    ctx->changed_nsid_count = 0;

    ctx->listen_port  = port;   /* Discovery Log Page の trsvcid に載せる */
    ctx->is_discovery = 0;
    nvmet_build_id_ctrl(ctx);
    nvmet_build_id_ctrl_disc(ctx);
    for (uint32_t id = 1u; id <= NVMET_NSID_MAX; id++) nvmet_build_id_ns(ctx, id);

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

    /* **IO キューのジョブは上限ぶん spawn する。** 実際に使う本数は
     * Set Features(Number of Queues)でセッションごとに決まり、余ったジョブは
     * WAIT_ADMIN_READY で眠っているだけ(accept の受け皿も用意しない)。 */
    for (unsigned q = 0; q < NVMET_IO_QUEUES; q++) {
        nvmet_io_job_ctx_t *ijc = &s_io_job_pool[slot][q];
        ijc->ctx       = ctx;
        ijc->port      = port;
        ijc->qidx      = q;
        ijc->connected = 0;
        ijc->stat_cmds = 0;
        for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
            ijc->pending_writes[i].in_use = 0;
        }
        job_t *io_job = job_spawn(nvmet_io_job_step, ijc, "nvmet-io");
        if (!io_job) {
            uart_printf("[!] nvmet: ジョブ生成失敗(io %u本目)\n", q + 1u);
            /* 既に spawn した IO ジョブと admin ジョブを畳ませる。
             * **job の ctx はプール側の要素**なので ctx では引けない。 */
            job_cancel_by_ctx(&s_admin_job_pool[slot]);
            for (unsigned k = 0; k < q; k++) job_cancel_by_ctx(&s_io_job_pool[slot][k]);
            tcp_unlisten(listener);
            s_instance_owner[slot] = NULL;
            ctx->session_active = 0;
            return -1;
        }
        job_set_affinity(io_job, bound_ctx);
        if (bound_ctx) {
            job_pin_to_core(io_job, bound_ctx->owner_core);
        }
    }
    uart_printf("[nvmet:%s] IOキューを最大 %u 本受け付けます\n",
                label, nvmet_io_queues_cap());
    return 0;
}

/*=================================================================
 * 名前空間を有効化 / 無効化する(シェルの `nvmens` から呼ぶ)。
 *
 * **変更したら Changed Namespace List へ積んで AER を完了させる。** これが
 * D6(非同期イベント)の唯一の発火点で、ホストはこの通知を受けて
 * `nvme_queue_scan()` を回し、CNS=0x02 を引き直して /dev/nvmeXnY を
 * 生やす/消す。通知しなければホストは永久に気付かない。
 *
 * 無効化するときは実体をゼロで埋める。**再度有効にしたときに前の内容が
 * 見えるのは「新しい名前空間」として正しくない。**
 *
 * 引数:
 *   ctx    - ターゲットコンテキスト
 *   nsid   - 名前空間 ID
 *   active - 1=有効化、0=無効化
 * 戻り値:
 *   0=変更した、-1=範囲外か既にその状態
 * コール元:
 *   シェルの nvmens コマンド
 * ===============================================================*/
int nvmet_ns_set_active(nvmet_ctx_t *ctx, uint32_t nsid, int active)
{
    if (!nvmet_nsid_in_range(nsid)) {
        uart_printf("[!] nvmens: nsid=%u は範囲外(1〜%u)\n", nsid, NVMET_NSID_MAX);
        return -1;
    }
    nvmet_ns_t *ns = &ctx->ns[nsid - 1u];
    if (ns->active == active) {
        uart_printf("[!] nvmens: nsid=%u は既に%s\n", nsid, active ? "有効" : "無効");
        return -1;
    }

    if (active) {
        volatile_fast_zero(ns->disk, (size_t)ns->lba_count * NVMET_LBA_SIZE);
        nvmet_build_id_ns(ctx, nsid);
    }
    ns->active = active;
    uart_printf("[nvmet:%s] 名前空間 nsid=%u を%s (%u LBA)\n",
                ctx->label, nsid, active ? "追加" : "削除",
                (unsigned)ns->lba_count);

    /* Changed Namespace List へ積む(読み出されるまで保持)。 */
    if (ctx->changed_nsid_count < NVME_MAX_CHANGED_NAMESPACES) {
        ctx->changed_nsid[ctx->changed_nsid_count] = nsid;
    }
    ctx->changed_nsid_count++;

    /* **ここでは送らない。** この関数はシェル(core0)から呼ばれるが、
     * admin キューへの送信は admin ジョブ(core1)の担当。旗だけ立てる。 */
    ctx->aer_notify_ns = 1;
    if (!ctx->aer_pending) {
        uart_printf("[nvmet:%s] (保留中の AER が無いので通知は次の AER まで待つ)\n",
                    ctx->label);
    }
    return 0;
}

/*=================================================================
 * 名前空間の一覧を表示する(シェルの `nvmens`)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * コール元:
 *   シェルの nvmens コマンド
 * ===============================================================*/
void nvmet_ns_show(nvmet_ctx_t *ctx)
{
    uart_printf("nvmens: nsid  状態    サイズ\n");
    for (uint32_t id = 1u; id <= NVMET_NSID_MAX; id++) {
        nvmet_ns_t *ns = &ctx->ns[id - 1u];
        uart_printf("        %-5u %-7s %u LBA (%u MiB)\n",
                    id, ns->active ? "有効" : "無効",
                    (unsigned)ns->lba_count,
                    (unsigned)(ns->lba_count * NVMET_LBA_SIZE / (1024u * 1024u)));
    }
    if (ctx->aer_pending) {
        uart_printf("  AER: 保留中 (cid=%u) / 未読の変更 %u 件 / AEN 設定 0x%x\n",
                    ctx->aer_cid, ctx->changed_nsid_count, ctx->aen_config);
    } else {
        uart_printf("  AER: 保留なし / 未読の変更 %u 件 / AEN 設定 0x%x\n",
                    ctx->changed_nsid_count, ctx->aen_config);
    }
}

/*=================================================================
 * IO キュー(= 同時に受け付ける IO コネクション)の本数と、いまの状態を表示する
 * (シェルの `nvmetqueues`)。
 *
 * `g_nvmet_io_queues` は**次のセッションから**効く。ホストとは Set Features
 * (Number of Queues)で 1 回だけ合意するので、確立済みのセッションの本数は
 * 変えられない(変えるとホストが張っていないキューを待つことになる)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * コール元:
 *   シェルの nvmetqueues コマンド
 * ===============================================================*/
void nvmet_io_queues_show(const nvmet_ctx_t *ctx)
{
    uart_printf("nvmetqueues: 設定=%u本 (上限 %u)  今のセッション: 許諾=%u本 接続中=%d本\n",
                nvmet_io_queues_cap(), (unsigned)NVMET_IO_QUEUES,
                (unsigned)ctx->io_queues_granted, ctx->io_open);
    for (unsigned i = 0; i < NVMET_MAX_INSTANCES; i++) {
        if (s_instance_owner[i] != ctx) continue;
        for (unsigned q = 0; q < NVMET_IO_QUEUES; q++) {
            const nvmet_io_job_ctx_t *jc = &s_io_job_pool[i][q];
            uart_printf("  キュー%u: %s (tcp state=%u) コマンド %llu 件%s\n", q + 1u,
                        jc->connected ? "接続中" : "未接続",
                        (unsigned)jc->io.tcp.state,
                        (unsigned long long)jc->stat_cmds,
                        jc->ctx && jc->ctx->io_arm_owner == (int)q ? " [accept待ち]" : "");
        }
    }
    uart_printf("  ※ 変更は次のセッションから効きます(Set Features で合意する値のため)\n");
}
