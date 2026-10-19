#include "nvmet_rdma.h"
#if defined(__x86_64__)
#include <emmintrin.h>   /* _mm_stream_si128(非一時ストア)*/
#endif
#include "mlx5.h"
#include "net.h"
#include "nvme_types.h"
#include "uart.h"
#include "timer.h"
#include "cache.h"
#include "job.h"
#include "timestamp.h"
#include "smp.h"
#include "ib_mad.h"
#include "platform.h"
#include <string.h>

extern job_result_t nvme_rdma_connect_job_step(job_t *self);
extern volatile int g_nvmet_multi_ctrl;   /* nvmet.c(2 ポートで受けるとき 1)*/

/* **常駐ターゲットの状態は PF ごとに 1 組**(2 ポートで受けるとき両方を使う。0 = pf1、1 = pf0)。
 * 関数はどれも「いま扱っている組」s_nr を通して触る(下の s_standalone_* はその参照)。
 * **s_nr はスレッド(= コア)ごと**で、ジョブの入口(nvmet_rdma_job_step())と
 * nvmet_rdma_run_standalone() で差し替える。コールバック(on_established など)は
 * その ctx のジョブの中から呼ばれるので、同じ組を指したままである。 */
#define NVMETR_INSTANCES 2u
typedef struct {
    nvmet_rdma_ctx_t  ctx;          /* admin キュー(queue_id=0)*/
    nvmet_rdma_ctrl_t ctrl;         /* admin/IO 共有のコントローラ状態 */
    int               resident;
    uint32_t          resident_generation;
    nvmet_rdma_ctx_t  io_ctx[NVMET_RDMA_IO_QUEUES];
    int               io_spawned;   /* 立てた acceptor の本数 */
    const char       *self_label;
    uint8_t           peer_mac[6];
    nvmet_rdma_ctx_t *admin_ctx_for_io;
} nvmetr_inst_t;
static nvmetr_inst_t s_nr_inst[NVMETR_INSTANCES];
static __thread nvmetr_inst_t *s_nr = &s_nr_inst[0];
#define s_standalone_ctx                 (s_nr->ctx)
#define s_standalone_ctrl                (s_nr->ctrl)
#define s_standalone_resident            (s_nr->resident)
#define s_standalone_resident_generation (s_nr->resident_generation)
#define s_standalone_io_ctx              (s_nr->io_ctx)
#define s_standalone_io_spawned          (s_nr->io_spawned)
#define s_standalone_self_label          (s_nr->self_label)
#define s_standalone_peer_mac            (s_nr->peer_mac)
#define s_standalone_admin_ctx_for_io    (s_nr->admin_ctx_for_io)

/* ctx がどの組のものか(admin でも IO キューでも)。どれでもなければ NULL。 */
static nvmetr_inst_t *nvmetr_inst_of(const nvmet_rdma_ctx_t *ctx)
{
    for (unsigned k = 0; k < NVMETR_INSTANCES; k++) {
        nvmetr_inst_t *in = &s_nr_inst[k];
        if (ctx == &in->ctx || (ctx >= &in->io_ctx[0] && ctx < &in->io_ctx[NVMET_RDMA_IO_QUEUES])) return in;
    }
    return NULL;
}

/* IO キュー(queue_id=1)。admin の CM 確立を検出した時点で spawn する。
 * self_label / peer_mac はコールバックに渡らないのでここへ控えておく。 */
/* **IO キューはコネクションごとに 1 個。** 1 個 1MB 強あるので .bss を見て
 * 増やすこと。**GSI(QP1)は 1 PF に 1 つしか置けない**が、拾った MAD は
 * rdma_cm.c の待ち行列(cm_gsi_take())に入り、受け皿は REQ を 1 つずつ取り出す
 * ので、**同時に来た REQ は次の受け皿が立つまで待ち行列で待つ**(3 秒)。
 * 受け皿は確立するたびに次の 1 本を立てる。admin の受け皿は qid 0 の REQ だけ、
 * IO の受け皿は qid 1 以上の REQ だけを取る(req_qid_class)。
 * **SPDK は同じコントローラの IO キューを複数のコアから同時に張りに来て**、REP を
 * 受けるとすぐ Connect を送るので、受信の投稿が済むまで REP を待たせる(hold_rep)。
 * IO キューだけが切られた枠は受け皿に戻す(requeue)。 */
static void nvmetr_spawn_io_queue(nvmet_rdma_ctx_t *admin_ctx, unsigned idx);
static void nvmetr_on_io_established(nvmet_rdma_ctx_t *self);
static void nvmetr_requeue_io(nvmet_rdma_ctx_t *ctx, job_t *self);
static void nvmetr_after_auth(nvmet_rdma_ctx_t *ctx);
static void nvmetr_parse_admin(nvmet_rdma_ctx_t *ctx, const volatile uint8_t *rb, nvmet_rdma_pl_pending_t *p);
static void nvmetr_parse_io(nvmet_rdma_ctx_t *ctx, const volatile uint8_t *rb, nvmet_rdma_pl_pending_t *p,
                            int split);


/* CQE の status(nvmet.c の NVMET_SC_* と同じ作り)。 */
#define NVMETR_SC_INVALID_FIELD   0x8004u   /* SC=0x02 Invalid Field in Command + DNR */
#define NVMETR_SC_ABORT_REQ       0x000Eu   /* SC=0x07 Command Abort Requested */
#define NVMETR_SC_CMD_SEQ_ERROR   0x8018u   /* SC=0x0C Command Sequence Error + DNR */
#define NVMETR_SC_INVALID_NS      0x8016u   /* SC=0x0B Invalid Namespace or Format + DNR */
#define NVMETR_SC_SGL_LEN_INVALID 0x801Eu   /* SC=0x0F Data SGL Length Invalid + DNR */
#define NVMETR_SC_LBA_RANGE       0x8100u   /* SC=0x80 LBA Out of Range + DNR */
#define NVMETR_SC_ASYNC_LIMIT     0x820Au   /* SCT=1 SC=0x05 Async Event Request Limit Exceeded + DNR */
#define NVMETR_SC_NOT_SAVEABLE    0x821Au   /* SCT=1 SC=0x0D Feature Identifier Not Saveable + DNR */
#define NVMETR_SC_CMD_SIZE_LIMIT  0x8306u   /* SCT=1 SC=0x83 Command Size Limit Exceeded + DNR */
#define NVMETR_SC_COMPARE_FAILED  0x850Au   /* SCT=2 SC=0x85 Compare Failure + DNR */

/* Identify の応答の出どころ(pending.id_sel)。 */
#define NVMETR_ID_CTRL 0u
#define NVMETR_ID_NS   1u
#define NVMETR_ID_LIST 2u
#define NVMETR_ID_DESC 3u
#define NVMETR_ID_NVM  4u
#define NVMETR_ID_ZERO 5u

/* DSM / Write Zeroes / Copy の上限(TCP の nvmet.c と同じ値)。範囲の一覧は置き場(4096 バイト)に受ける。 */
#define NVMETR_DSM_MAX_RANGES  64u
#define NVMETR_MAX_RANGE_LBAS  65536u
#define NVMETR_COPY_MSSRL      32768u
#define NVMETR_COPY_MCL        65536u
#define NVMETR_COPY_MAX_RANGES (NVMET_RDMA_INLINE_MAX / NVME_COPY_RANGE_LEN)

#define CM_DREQ_ATTR_ID 0x0015u
#define CM_DREP_ATTR_ID 0x0016u
#define IB_CM_CLASS_VERSION 2u

static void nvmetr_zero_v(volatile uint8_t *p, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) p[i] = 0;
}

static void nvmetr_zero_v64(volatile uint8_t *p, uint32_t len)
{
    volatile uint64_t *p64 = (volatile uint64_t *)p;
    uint32_t n64 = len / 8u;
    for (uint32_t i = 0; i < n64; i++) p64[i] = 0;
}

/*=================================================================
 * in-capsule で届いた write データを RAM ディスクへ写す。
 *
 * **書き込み先(256MB の RAM ディスク)はキャッシュに載っていないので、
 * 普通のストアだと 1 行ごとに read-for-ownership が入る。** 実測で 4KB の
 * コピーに 725ns(5.6 GB/s)かかっていた。非一時ストアで RFO を避ける。
 * 小さいコピーでは sfence のぶん損なので、閾値以上のときだけ使う。
 *
 * 引数:
 *   dst / src - 書き込み先 / 読み出し元(どちらも 16 バイト整列)、len - バイト数
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
/* **この長さ以上のコピーを非一時ストアにする**(既定 1024)。実行時に
 * 変えられるようにしてある(シェルの `ntcopy`) -- 512B の in-capsule write
 * が直前のトラフィック次第で 600k と 777k を行き来するので、**書き込み先が
 * キャッシュに無いときの read-for-ownership** が原因かを切り分けるため。 */
volatile uint32_t g_nvmetr_nt_copy_min = 1024u;

/* [計装] キューごとのポーリング周回数・空回り・コマンド数(シェルの `rdmastat`)。
 * **4 本の IO キューが 1 コアで順に回るので、どのキューが仕事をしているかが
 * 見えないと「均等に散っている」と「1 本に偏っている」を取り違える。**
 * 統計カウンタは volatile にすること -- 素の uint64_t だとコンパイラが
 * 巡回ループ内の ++ をレジスタにまとめ、他コアの clear が古い値で復活する
 * (`jobpark` のカウンタで実際に踏んだ)。
 * 1 キュー 1 キャッシュライン(8 x 8B)に離して false sharing を避ける。 */
volatile uint64_t g_nvmetr_polls[NVMET_RDMA_IO_QUEUES + 1u][8];
volatile uint64_t g_nvmetr_empty[NVMET_RDMA_IO_QUEUES + 1u][8];
volatile uint64_t g_nvmetr_cmds[NVMET_RDMA_IO_QUEUES + 1u][8];

static void nvmetr_copy_in_capsule(volatile uint8_t *dst, const volatile uint8_t *src,
                                    uint32_t len)
{
#if defined(__x86_64__)
    if (len >= g_nvmetr_nt_copy_min &&
        ((uintptr_t)dst % 16u) == 0u && ((uintptr_t)src % 16u) == 0u) {
        __m128i *d = (__m128i *)(uintptr_t)dst;
        const __m128i *sp = (const __m128i *)(uintptr_t)src;
        uint32_t n = len / 16u;
        for (uint32_t i = 0; i < n; i++) {
            _mm_stream_si128(&d[i], _mm_loadu_si128(&sp[i]));
        }
        _mm_sfence();   /* 非一時ストアは順序が緩いので、応答を出す前に流し切る */
        uint32_t done = n * 16u;
        for (uint32_t i = done; i < len; i++) dst[i] = src[i];
        return;
    }
#endif
    volatile_fast_copy(dst, src, len);
}

static void nvmetr_copy_padded(volatile uint8_t *dst, const char *src, uint32_t field_len)
{
    uint32_t src_len = 0;
    while (src[src_len] != '\0') src_len++;
    if (src_len > field_len) src_len = field_len;
    for (uint32_t i = 0; i < src_len; i++) dst[i] = (uint8_t)src[i];
    for (uint32_t i = src_len; i < field_len; i++) dst[i] = ' ';
}

/*=================================================================
 * Identify Controller 応答(4096 バイト)を組み立てる。SN/MN/FR、MDTS、
 * SGLS の Keyed SGL 対応ビット、MAXCMD などを設定する(バイトオフセットは
 * nvmet.c の同名処理と同一)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト(ctrl->id_ctrl へ書く)
 * コール元:
 *   nvmet_rdma_job_step(), nvmetr_reset_admin_for_reconnect()
 * ===============================================================*/
static void nvmetr_build_id_ctrl(nvmet_rdma_ctx_t *ctx)
{
    nvmetr_zero_v(ctx->ctrl->id_ctrl, sizeof(ctx->ctrl->id_ctrl));
    wr16le(&ctx->ctrl->id_ctrl[0], 0x1AF4);
    nvmetr_copy_padded(&ctx->ctrl->id_ctrl[4],  "RPI5-NVMET-RDMA", 20);
    nvmetr_copy_padded(&ctx->ctrl->id_ctrl[24], "RPi5 Bare-Metal NVMe-oF RDMA Target", 40);
    nvmetr_copy_padded(&ctx->ctrl->id_ctrl[64], "1.0", 8);
    ctx->ctrl->id_ctrl[77] = 0;                          /* MDTS = 0 (無制限) */
    wr32le(&ctx->ctrl->id_ctrl[80], NVME_VS_1_3_0);       /* VER: Property Get の VS と同じ値を名乗る */
    /* OAES: 名前空間の変化を通知できる、と名乗る(TCP と同じ)。**立てないと Linux は Asynchronous Event
     * Request を送ってこない**ので、予約の通知も届かない。AERL = 0(0's based で同時 1 件)。 */
    wr32le(&ctx->ctrl->id_ctrl[NVME_ID_CTRL_OFF_OAES], NVME_AEN_CFG_NS_ATTR);
    ctx->ctrl->id_ctrl[NVME_ID_CTRL_OFF_AERL] = 0;
    ctx->ctrl->id_ctrl[NVME_ID_CTRL_OFF_ACL]  = 3;      /* Abort は受けたその場で答えるので溜まらない */
    /* ONCS: Compare / DSM / Write Zeroes / 予約 / Copy。OCFS: Copy の範囲の書式は Format 0 だけ。 */
    wr16le(&ctx->ctrl->id_ctrl[NVME_ID_CTRL_OFF_ONCS],
           NVME_CTRL_ONCS_COMPARE | NVME_CTRL_ONCS_DSM | NVME_CTRL_ONCS_WRITE_ZEROES |
           NVME_CTRL_ONCS_RESERVATIONS | NVME_CTRL_ONCS_COPY);
    wr16le(&ctx->ctrl->id_ctrl[NVME_ID_CTRL_OFF_OCFS], 0x0001u);
    if (g_nvmet_multi_ctrl) ctx->ctrl->id_ctrl[76] |= 0x02u;   /* CMIC: 複数コントローラ(2 ポートのとき)*/
    wr16le(&ctx->ctrl->id_ctrl[78], ctx->ctrl->ctrlr_id);       /* CNTLID */
    ctx->ctrl->id_ctrl[111] = 1;                          /* CNTRLTYPE = 1 (I/O controller) */
    wr16le(&ctx->ctrl->id_ctrl[320], 2);                  /* KAS(fabricsでは非0が必須) */
    /* SGLS bit0(byte-aligned) | bit2(KSDBDS) | bit20(SAOS = SGL のアドレス欄へ
     * オフセットを書ける)。**SAOS を立てないと Linux は in-capsule write を
     * 使わない**(nvme_rdma_setup_ctrl() が use_inline_data をこのビットだけで
     * 決めている)。 */
    wr32le(&ctx->ctrl->id_ctrl[536], 1u | (1u << 2) | (1u << 20));
    {
        const char *subnqn = NVMET_RDMA_SUBNQN;
        uint32_t len = 0;
        while (subnqn[len] != '\0') len++;
        for (uint32_t i = 0; i < len; i++) ctx->ctrl->id_ctrl[768 + i] = (uint8_t)subnqn[i];
    }
    wr32le(&ctx->ctrl->id_ctrl[516], 1);                  /* NN: namespace count = 1 */
    ctx->ctrl->id_ctrl[512] = (6u << 4) | 6u;              /* SQES: 64バイト固定 */
    ctx->ctrl->id_ctrl[513] = (4u << 4) | 4u;              /* CQES: 16バイト固定 */
    wr16le(&ctx->ctrl->id_ctrl[514], (uint16_t)NVMET_RDMA_MAXCMD); /* MAXCMD */
    /* IOCCSZ: SQE(64B) + in-capsule データ。**4(SQE のみ)にしていると 512B の
     * write でもホストは keyed SGL を使い、ターゲットが RDMA_READ を 1 往復
     * 追加する**(実測 3.2us)。 */
    wr32le(&ctx->ctrl->id_ctrl[1792], (64u + NVMET_RDMA_INLINE_MAX) / 16u);
    wr32le(&ctx->ctrl->id_ctrl[1796], NVME_CQE_LEN / 16u); /* IORCSZ: CQE(16B)分のみ */
    ctx->ctrl->id_ctrl[1803] = 1;                          /* MSDBD = 1 */
    dcache_clean_range((const void *)(uintptr_t)ctx->ctrl->id_ctrl, sizeof(ctx->ctrl->id_ctrl));
}

/*=================================================================
 * Identify Namespace 応答(4096 バイト)を組み立てる。NSZE/NCAP/NUSE と
 * LBA フォーマット(512 バイト)を設定する。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト(ctrl->id_ns へ書く)
 * コール元:
 *   nvmet_rdma_job_step(), nvmetr_reset_admin_for_reconnect()
 * ===============================================================*/
static void nvmetr_build_id_ns(nvmet_rdma_ctx_t *ctx)
{
    nvmetr_zero_v(ctx->ctrl->id_ns, sizeof(ctx->ctrl->id_ns));
    wr64le(&ctx->ctrl->id_ns[0], NVMET_RDMA_NS_LBA_COUNT);  /* NSZE */
    wr64le(&ctx->ctrl->id_ns[8], NVMET_RDMA_NS_LBA_COUNT);  /* NCAP */
    wr64le(&ctx->ctrl->id_ns[16], 0);                        /* NUSE */
    ctx->ctrl->id_ns[26]  = 0;                                /* FLBAS: LBA Format Index = 0 */
    ctx->ctrl->id_ns[130] = 9;                                /* LBAF[0].ds = 9 (512B = 2^9) */
    /* DLFEAT = 001b: Deallocate した領域を読むと 0 が返る(ゼロで埋める実装と揃える)。 */
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_DLFEAT] = 0x01u;
    /* NMIC の「共有」は 2 ポートのときだけ(1 ポートで名乗るとホストがマルチパスの装置名で見せる)。 */
    if (g_nvmet_multi_ctrl) ctx->ctrl->id_ns[NVME_ID_NS_OFF_NMIC] |= 0x01u;
    /* 名前空間の識別子(NGUID / EUI-64)。Linux は 2 つのコントローラから見える名前空間を識別子で
     * 同じものと判断する。値は TCP のターゲット(nvmet.c)と重ならないよう 2 バイト目を 'R' にし、
     * 末尾に nsid(1)を置く。CNS=0x03 の記述子リストにも同じ値を載せる。 */
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_NGUID + 0]  = 0x02u;
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_NGUID + 1]  = 'R';
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_NGUID + 15] = 1u;
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_EUI64 + 0]  = 0x02u;
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_EUI64 + 1]  = 'R';
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_EUI64 + 7]  = 1u;
    /* RESCAP(予約の 6 種類と IEKEY)と Copy の上限(MSRC は 0's based)。 */
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_RESCAP] = NVMET_PR_RESCAP;
    wr16le(&ctx->ctrl->id_ns[NVME_ID_NS_OFF_MSSRL], NVMETR_COPY_MSSRL);
    wr32le(&ctx->ctrl->id_ns[NVME_ID_NS_OFF_MCL],   NVMETR_COPY_MCL);
    ctx->ctrl->id_ns[NVME_ID_NS_OFF_MSRC] = (uint8_t)(NVMETR_COPY_MAX_RANGES - 1u);
    dcache_clean_range((const void *)(uintptr_t)ctx->ctrl->id_ns, sizeof(ctx->ctrl->id_ns));

    /* CNS=0x02: 有効な名前空間は nsid=1 だけ。 */
    nvmetr_zero_v(ctx->ctrl->id_list, sizeof(ctx->ctrl->id_list));
    wr32le(&ctx->ctrl->id_list[0], 1u);
    /* CNS=0x03: EUI-64(NIDT=1、8 バイト)と NGUID(NIDT=2、16 バイト)を詰めて並べ、NIDT=0 で終わる。 */
    nvmetr_zero_v(ctx->ctrl->id_desc, sizeof(ctx->ctrl->id_desc));
    ctx->ctrl->id_desc[0] = NVME_NIDT_EUI64;
    ctx->ctrl->id_desc[1] = 8u;
    for (unsigned i = 0; i < 8u; i++) ctx->ctrl->id_desc[4 + i] = ctx->ctrl->id_ns[NVME_ID_NS_OFF_EUI64 + i];
    ctx->ctrl->id_desc[12] = NVME_NIDT_NGUID;
    ctx->ctrl->id_desc[13] = 16u;
    for (unsigned i = 0; i < 16u; i++) ctx->ctrl->id_desc[16 + i] = ctx->ctrl->id_ns[NVME_ID_NS_OFF_NGUID + i];
    /* CNS=0x06(CSI=NVM): DSM の上限。**広告しないと Linux は 1 コマンドで名前空間全体を消しに来る**
     * (RAM ディスクをゼロで埋めるあいだ、そのキューのポーリングが止まる)。 */
    nvmetr_zero_v(ctx->ctrl->id_nvm, sizeof(ctx->ctrl->id_nvm));
    ctx->ctrl->id_nvm[NVME_ID_CTRL_NVM_OFF_DMRL] = (uint8_t)NVMETR_DSM_MAX_RANGES;
    wr32le(&ctx->ctrl->id_nvm[NVME_ID_CTRL_NVM_OFF_DMRSL], NVMETR_MAX_RANGE_LBAS);
    wr64le(&ctx->ctrl->id_nvm[NVME_ID_CTRL_NVM_OFF_DMSL],  NVMETR_MAX_RANGE_LBAS);
    nvmetr_zero_v(ctx->ctrl->id_zero, sizeof(ctx->ctrl->id_zero));
}

/* Identify の応答の出どころ。 */
static const volatile uint8_t *nvmetr_id_buf(const nvmet_rdma_ctrl_t *c, uint8_t sel)
{
    switch (sel) {
    case NVMETR_ID_CTRL: return c->id_ctrl;
    case NVMETR_ID_NS:   return c->id_ns;
    case NVMETR_ID_LIST: return c->id_list;
    case NVMETR_ID_DESC: return c->id_desc;
    case NVMETR_ID_NVM:  return c->id_nvm;
    default:             return c->id_zero;
    }
}

/*=================================================================
 * SMART / Health Information ログ(512 バイト)。カウンタはこの組の全キューの合計。
 * 温度はケルビン、data_units は 512 バイト x 1000 単位で切り上げ(TCP の nvmet.c と同じ)。
 * ===============================================================*/
static void nvmetr_build_smart(nvmet_rdma_ctx_t *ctx, uint8_t *buf)
{
    for (unsigned i = 0; i < NVME_SMART_LOG_LEN; i++) buf[i] = 0;
    uint64_t rc = ctx->st_rd_cmds, wc = ctx->st_wr_cmds, rb = ctx->st_rd_bytes, wb = ctx->st_wr_bytes;
    for (unsigned k = 0; k < NVMET_RDMA_IO_QUEUES; k++) {
        if (s_standalone_io_ctx[k].ctrl != ctx->ctrl) continue;
        rc += s_standalone_io_ctx[k].st_rd_cmds;
        wc += s_standalone_io_ctx[k].st_wr_cmds;
        rb += s_standalone_io_ctx[k].st_rd_bytes;
        wb += s_standalone_io_ctx[k].st_wr_bytes;
    }
    wr16le(&buf[NVME_SMART_OFF_TEMP], 300u);   /* 300 K */
    buf[NVME_SMART_OFF_AVAIL_SPARE]  = 100;
    buf[NVME_SMART_OFF_SPARE_THRESH] = 10;
    wr64le(&buf[NVME_SMART_OFF_DATA_UNITS_READ], (rb + 511999ull) / 512000ull);
    wr64le(&buf[NVME_SMART_OFF_DATA_UNITS_WRIT], (wb + 511999ull) / 512000ull);
    wr64le(&buf[NVME_SMART_OFF_HOST_READS],  rc);
    wr64le(&buf[NVME_SMART_OFF_HOST_WRITES], wc);
    wr64le(&buf[NVME_SMART_OFF_POWER_CYCLES], 1u);
    wr64le(&buf[NVME_SMART_OFF_POWER_ON_HOURS],
           (timer_now() - ctx->ctrl->start_tick) / (3600ull * 1000000000ull));
}

/* 範囲を 1 つゼロで埋める(Write Zeroes と Deallocate)。nlb は 0's based ではない実数。 */
static int nvmetr_zero_lbas(nvmet_rdma_ctx_t *ctx, uint64_t slba, uint64_t nlb)
{
    if (nlb == 0) return 0;
    if (slba > NVMET_RDMA_NS_LBA_COUNT || nlb > NVMET_RDMA_NS_LBA_COUNT - slba) return -1;
    volatile_fast_zero(&ctx->ctrl->ram_disk[slba * NVMET_RDMA_LBA_SIZE], (size_t)nlb * NVMET_RDMA_LBA_SIZE);
    return 0;
}

/*=================================================================
 * 置き場に届いたデータ(または in-capsule のデータ)で、コマンドを実行して
 * 応答の status を決める。DSM / Copy / Compare(in-capsule の全部)/ 予約の 3 つ。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   p    - コマンド
 *   data - データ(置き場か受信 capsule の中)、len - その長さ
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
static void nvmetr_exec_staged(nvmet_rdma_ctx_t *ctx, nvmet_rdma_pl_pending_t *p,
                               const volatile uint8_t *vdata, uint32_t len)
{
    const uint8_t *data = (const uint8_t *)(uintptr_t)vdata;
    switch (p->opcode) {
    case NVME_IO_CMD_DSM: {
        const uint32_t nr = (p->cdw10 & 0xFFu) + 1u;   /* 0's based */
        if (len < nr * NVME_DSM_RANGE_LEN) { p->resp_status = NVMETR_SC_SGL_LEN_INVALID; return; }
        if (!(p->cdw11 & NVME_DSMGMT_AD)) return;      /* IDR / IDW はヒントなので何もしない */
        for (uint32_t i = 0; i < nr; i++) {
            const uint8_t *r = &data[i * NVME_DSM_RANGE_LEN];
            /* **範囲の NLB は 0's based ではない**(nvme_types.h)。 */
            if (nvmetr_zero_lbas(ctx, rd64le(&r[NVME_DSM_OFF_SLBA]), rd32le(&r[NVME_DSM_OFF_NLB])) != 0) {
                p->resp_status = NVMETR_SC_LBA_RANGE;
                return;
            }
        }
        return;
    }
    case NVME_IO_CMD_COPY: {
        /* TCP の nvmet_copy_apply() と同じ: 全部の範囲を検査してから写し始める。 */
        const uint64_t sdlba = (uint64_t)p->cdw10 | ((uint64_t)p->cdw11 << 32);
        const uint32_t nr    = (p->cdw12 & 0xFFu) + 1u;
        if (((p->cdw12 >> 8) & 0xFu) != 0u) { p->resp_status = NVMETR_SC_INVALID_FIELD; return; }
        if (nr > NVMETR_COPY_MAX_RANGES)    { p->resp_status = NVMETR_SC_CMD_SIZE_LIMIT; return; }
        if (len < nr * NVME_COPY_RANGE_LEN) { p->resp_status = NVMETR_SC_SGL_LEN_INVALID; return; }
        uint64_t sum = 0;
        for (uint32_t i = 0; i < nr; i++) {
            const uint8_t *r = &data[i * NVME_COPY_RANGE_LEN];
            const uint64_t slba = rd64le(&r[NVME_COPY_OFF_SLBA]);
            const uint32_t nlb  = (uint32_t)rd16le(&r[NVME_COPY_OFF_NLB]) + 1u;
            if (nlb > NVMETR_COPY_MSSRL) { p->resp_status = NVMETR_SC_CMD_SIZE_LIMIT; return; }
            if (slba > NVMET_RDMA_NS_LBA_COUNT || nlb > NVMET_RDMA_NS_LBA_COUNT - slba) {
                p->resp_status = NVMETR_SC_LBA_RANGE;
                return;
            }
            sum += nlb;
        }
        if (sum > NVMETR_COPY_MCL) { p->resp_status = NVMETR_SC_CMD_SIZE_LIMIT; return; }
        if (sdlba > NVMET_RDMA_NS_LBA_COUNT || sum > NVMET_RDMA_NS_LBA_COUNT - sdlba) {
            p->resp_status = NVMETR_SC_LBA_RANGE;
            return;
        }
        uint8_t *disk = (uint8_t *)(uintptr_t)ctx->ctrl->ram_disk;
        uint64_t dst = sdlba;
        for (uint32_t i = 0; i < nr; i++) {
            const uint8_t *r = &data[i * NVME_COPY_RANGE_LEN];
            const uint64_t slba = rd64le(&r[NVME_COPY_OFF_SLBA]);
            const uint32_t nlb  = (uint32_t)rd16le(&r[NVME_COPY_OFF_NLB]) + 1u;
            memmove(&disk[dst * NVMET_RDMA_LBA_SIZE], &disk[slba * NVMET_RDMA_LBA_SIZE],
                    (size_t)nlb * NVMET_RDMA_LBA_SIZE);
            dst += nlb;
        }
        ctx->st_wr_cmds++;
        ctx->st_wr_bytes += sum * NVMET_RDMA_LBA_SIZE;
        return;
    }
    case NVME_IO_CMD_COMPARE: {
        const uint8_t *disk = (const uint8_t *)(uintptr_t)ctx->ctrl->ram_disk;
        if (memcmp(&disk[p->io_slba * NVMET_RDMA_LBA_SIZE + p->cmp_off], data, len) != 0) {
            p->resp_status = NVMETR_SC_COMPARE_FAILED;
        }
        return;
    }
    case NVME_IO_CMD_RESV_REGISTER:
    case NVME_IO_CMD_RESV_ACQUIRE:
    case NVME_IO_CMD_RESV_RELEASE: {
        uint32_t olen = 0;
        p->resp_status = nvmet_pr_execute(&ctx->ctrl->pr, p->nsid, p->opcode, p->cdw10, p->cdw11,
                                          data, len, NULL, 0, &olen);
        if (p->resp_status != 0) {
            uart_printf("[nvmet-rdma] 予約のコマンド (opcode=0x%x cdw10=0x%x) -> status=0x%x\n",
                        p->opcode, p->cdw10, p->resp_status);
        }
        return;
    }
    default:
        p->resp_status = NVMET_RDMA_SC_ERROR;
        return;
    }
}

/*=================================================================
 * 受信 SQE の dptr(相対 offset 24)にある Keyed SGL descriptor から、
 * 相手側アドレス・長さ・rkey を取り出す。
 *
 * 引数:
 *   rb        - 受信 capsule 先頭(SQE 64 バイト)
 *   out_addr / out_len / out_key - 取り出した値の格納先
 * コール元:
 *   nvmetr_parse_command()
 * ===============================================================*/
static void nvmetr_parse_ksgl_into(const volatile uint8_t *rb, uint64_t *out_addr,
                                    uint32_t *out_len, uint32_t *out_key,
                                    uint32_t *out_inval_key)
{
    const volatile uint8_t *dptr = &rb[24]; // nvme_sqe_t.dptrはSQE内offset24
    /* 型の下位 4bit が 0xF(NVME_SGL_FMT_INVALIDATE)なら、ホストは
     * 「この rkey を SEND_WITH_INVALIDATE で無効化して返せ」と要求している。
     * **返さないとホストは自分で LOCAL_INV を投げる**ぶん遅くなる。
     * Linux の nvmet_rdma_map_sgl_keyed(rsp, sgl, invalidate) と同じ判定。 */
    if (out_inval_key) {
        *out_inval_key = ((dptr[15] & 0x0Fu) == 0x0Fu)
                       ? ((uint32_t)dptr[11] | ((uint32_t)dptr[12] << 8) |
                          ((uint32_t)dptr[13] << 16) | ((uint32_t)dptr[14] << 24))
                       : 0u;
    }
    *out_addr = rd64le(&dptr[0]);
    *out_len  = (uint32_t)dptr[8] | ((uint32_t)dptr[9] << 8) | ((uint32_t)dptr[10] << 16);
    *out_key  = (uint32_t)dptr[11] | ((uint32_t)dptr[12] << 8) |
                ((uint32_t)dptr[13] << 16) | ((uint32_t)dptr[14] << 24);
}

/*=================================================================
 * 受信 capsule を解釈し、1 コマンド分の情報(opcode / cid / Keyed SGL /
 * LBA 範囲 / 必要なデータ移動の向き)を解析結果構造体へ書き出す。
 * パイプライン化で複数コマンドを同時に扱うため、結果はコンテキストでは
 * なく呼び出し元が指定するスロットへ入れる。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 *   rb  - 受信 capsule
 *   p   - 解析結果の格納先
 * コール元:
 *   nvmet_rdma_job_step(), nvmetr_dispatch()
 * ===============================================================*/
static void nvmetr_parse_command(nvmet_rdma_ctx_t *ctx, const volatile uint8_t *rb,
                                  nvmet_rdma_pl_pending_t *p)
{
    nvmetr_zero_v((volatile uint8_t *)p, (uint32_t)sizeof(*p));

    uint32_t cdw0 = rd32le(&rb[0]);
    p->opcode = (uint8_t)(cdw0 & 0xFFu);
    p->cid    = rd16le(&rb[2]);
    uint32_t nsid_field = rd32le(&rb[4]);
    p->nsid = nsid_field;
    p->cdw10 = rd32le(&rb[40]);
    p->cdw11 = rd32le(&rb[44]);
    p->cdw12 = rd32le(&rb[48]);

    if (p->opcode == NVME_FABRIC_CMD) {
        p->fctype = (uint8_t)(nsid_field & 0xFFu);
    }
    /* **認証が済むまでは Connect と Authentication Send / Receive しか受けない**
     * (TCP 側の nvmet.c と同じ)。IO キューの Connect も admin の認証が済むまで断る。 */
    if (nvmet_auth_blocks(&ctx->ctrl->auth)) {
        const int fab_ok = (p->opcode == NVME_FABRIC_CMD) &&
                           ((p->fctype == NVME_FABRIC_FCTYPE_CONNECT && ctx->queue_id == 0) ||
                            p->fctype == NVME_FABRIC_FCTYPE_AUTH_SEND ||
                            p->fctype == NVME_FABRIC_FCTYPE_AUTH_RECV);
        if (!fab_ok) {
            uart_printf("[auth] nvmet-rdma: 認証前のコマンドを拒否 (queue %u opcode=0x%x)\n",
                        ctx->queue_id, p->opcode);
            p->resp_status = (uint16_t)NVMET_AUTH_SC_AUTH_REQUIRED;
            return;
        }
    }
    if (p->opcode == NVME_FABRIC_CMD) {
        if (p->fctype == NVME_FABRIC_FCTYPE_CONNECT) {
            p->resp_dw0 = ctx->ctrl->ctrlr_id;
            uart_printf("[nvmet-rdma] Fabrics Connect受理 (cntlid=%u queue_id=%u qid=%u t=%uus)\n",
                        ctx->ctrl->ctrlr_id, ctx->queue_id, (unsigned)(p->cdw10 >> 16),
                        (unsigned)(timer_now() / 1000u));
            if (ctx->queue_id == 0) {
                ctx->ctrl->kato_ms = p->cdw12;   /* Keep Alive Timeout(ms、Get Features で返す)*/
                /* **admin の Connect はデータ(1024 バイト、hostnqn を含む)を読む。**
                 * 以前は読まずに受理していた。認証では hostnqn が要る。 */
                nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key, &p->inval_rkey);
                if (p->ksgl_len >= 768u && p->ksgl_len <= NVME_AUTH_RECV_BYTES) {
                    p->need_data_move = 1;
                    p->data_move_is_write = 0;
                    p->fab_data = 1;
                }
            }
        } else if (ctx->queue_id == 0 && p->fctype == NVME_FABRIC_FCTYPE_AUTH_SEND) {
            nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key, &p->inval_rkey);
            if (p->ksgl_len == 0 || p->ksgl_len > NVME_AUTH_RECV_BYTES) {
                p->resp_status = (uint16_t)NVMET_AUTH_SC_INVALID_FIELD;
            } else {
                p->need_data_move = 1;
                p->data_move_is_write = 0;
                p->fab_data = 1;
            }
        } else if (ctx->queue_id == 0 && p->fctype == NVME_FABRIC_FCTYPE_AUTH_RECV) {
            nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key, &p->inval_rkey);
            uint32_t olen = 0;
            p->resp_status = nvmet_auth_receive(&ctx->ctrl->auth, p->cdw10, p->cdw11,
                                                (uint8_t *)(uintptr_t)ctx->ctrl->fab_buf,
                                                NVME_AUTH_RECV_BYTES, &olen, NVMET_RDMA_SUBNQN);
            if (p->resp_status == 0 && olen != 0) {
                if (olen > p->ksgl_len) olen = p->ksgl_len;
                p->ksgl_len = olen;
                p->need_data_move = 1;
                p->data_move_is_write = 1;
                p->fab_data = 1;
            }
        } else if (p->fctype == NVME_FABRIC_FCTYPE_PROPERTY_SET) {
            uint32_t offset = p->cdw11;
            uint64_t value = (uint64_t)p->cdw12 | ((uint64_t)rd32le(&rb[52]) << 32);
            if (offset == NVME_REG_CC) {
                ctx->ctrl->cc = (uint32_t)value;
                ctx->ctrl->cc_en = (ctx->ctrl->cc & NVME_CC_EN) ? 1 : 0;
            }
        } else if (p->fctype == NVME_FABRIC_FCTYPE_PROPERTY_GET) {
            uint32_t offset = p->cdw11;
            if (offset == NVME_REG_CAP) {
                p->resp_dw0 = 0xFFu | (0x1Eu << 24);
                p->resp_dw1 = 0x20u;
            } else if (offset == NVME_REG_CSTS) {
                /* **CC.SHN(停止の通知)を受けたら CSTS.SHST = 10b(停止完了)を返す。** 返さないとホストは
                 * 待ち切るまで待つ(SPDK は 10 秒 `did not shutdown within 10000 milliseconds`、Linux は 5 秒)。
                 * TCP の nvmet.c は以前に直してあった。RAM ディスクなので、受けた時点で止めてよい。 */
                p->resp_dw0 = (ctx->ctrl->cc_en ? NVME_CSTS_RDY : 0) |
                              ((ctx->ctrl->cc & NVME_CC_SHN_MASK) ? NVME_CSTS_SHST_CMPLT : 0u);
            } else if (offset == NVME_REG_CC) {
                p->resp_dw0 = ctx->ctrl->cc;
            } else if (offset == NVME_REG_VS) {
                /* **0 のままだとホストは「1.1 未満」と見なし、CNS=0x02 / 0x03 / 0x06 を問い合わせない**
                 * (Linux の nvme_ctrl_limited_cns())。DSM の上限(CNS=0x06)を読ませるために名乗る。 */
                p->resp_dw0 = NVME_VS_1_3_0;
            }
        } else {
            p->resp_status = NVMET_RDMA_SC_ERROR;
        }
        return;
    }

    if (!ctx->ctrl->cc_en) {
        p->resp_status = NVMET_RDMA_SC_ERROR;
        return;
    }

    /* **admin と IO はオペコードの表が別**(02h は admin では Get Log Page、IO では Read。09h は
     * Set Features と Dataset Management)。常駐ターゲットは admin と IO キューが別の QP なので
     * queue_id で分ける。1 つの QP で両方を受ける古いループバック用の構成(enable_io_queue = 0 かつ
     * queue_id = 0)だけは、従来どおり admin の 4 つ(Identify / Set Features / Get Features /
     * Keep Alive)とそれ以外で分ける。 */
    const int split = ctx->enable_io_queue || ctx->queue_id != 0;
    const int as_admin = split ? (ctx->queue_id == 0)
                               : (p->opcode == NVME_ADM_CMD_IDENTIFY || p->opcode == NVME_ADM_CMD_SET_FEATURES ||
                                  p->opcode == NVME_ADM_CMD_GET_FEATURES || p->opcode == NVME_ADM_CMD_KEEP_ALIVE);
    if (as_admin) {
        nvmetr_parse_admin(ctx, rb, p);
    } else {
        nvmetr_parse_io(ctx, rb, p, split);
    }
}

/*=================================================================
 * admin キューのコマンドを解釈する(nvmetr_parse_command() から)。
 * 応答のデータを返すもの(Identify 以外)は、受信バッファの置き場に組み立てて
 * RDMA_WRITE で返す(stage)。Asynchronous Event Request と Abort の
 * 保留の扱いはパイプラインのループ(nvmetr_admin_post_parse())。
 * ===============================================================*/
static void nvmetr_parse_admin(nvmet_rdma_ctx_t *ctx, const volatile uint8_t *rb,
                               nvmet_rdma_pl_pending_t *p)
{
    volatile uint8_t *stg = (volatile uint8_t *)(uintptr_t)&rb[NVMET_RDMA_STAGE_OFF];
    if (p->opcode == NVME_ADM_CMD_IDENTIFY) {
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key,
                               &p->inval_rkey);
        /* **CNS ごとに応答を分ける。** 名前空間は nsid=1 の 1 つだけ(NN=1)。 */
        const uint8_t cns = (uint8_t)(p->cdw10 & 0xFFu);
        if (cns == NVME_IDENTIFY_CNS_CONTROLLER) {
            p->id_sel = NVMETR_ID_CTRL;
        } else if (cns == NVME_IDENTIFY_CNS_NAMESPACE || cns == NVME_IDENTIFY_CNS_NS_DESC_LIST ||
                   cns == NVME_IDENTIFY_CNS_CS_NAMESPACE) {
            if (p->nsid != 1u) { p->resp_status = NVMETR_SC_INVALID_NS; return; }
            p->id_sel = (cns == NVME_IDENTIFY_CNS_NAMESPACE) ? NVMETR_ID_NS
                      : (cns == NVME_IDENTIFY_CNS_NS_DESC_LIST) ? NVMETR_ID_DESC : NVMETR_ID_ZERO;
        } else if (cns == NVME_IDENTIFY_CNS_NS_ACTIVE_LIST) {
            /* nsid は「この値より大きい NSID を並べよ」の意味。 */
            if (p->nsid >= 0xFFFFFFFEu) { p->resp_status = NVMETR_SC_INVALID_NS; return; }
            p->id_sel = (p->nsid < 1u) ? NVMETR_ID_LIST : NVMETR_ID_ZERO;
        } else if (cns == NVME_IDENTIFY_CNS_CS_CONTROLLER) {
            if (((p->cdw11 >> 24) & 0xFFu) != NVME_CSI_NVM) { p->resp_status = NVMETR_SC_INVALID_FIELD; return; }
            p->id_sel = NVMETR_ID_NVM;
        } else {
            p->resp_status = NVMETR_SC_INVALID_FIELD;
            return;
        }
        p->need_data_move = 1;
        p->data_move_is_write = 1; // ターゲット->ホストへRDMA_WRITEで押し込む
    } else if (p->opcode == NVME_ADM_CMD_SET_FEATURES &&
               ((p->cdw10 & 0xFFu) == NVME_FEAT_HOST_ID || (p->cdw10 & 0xFFu) == NVME_FEAT_RESV_MASK)) {
        /* Host Identifier(0x81)と Reservation Notification Mask(0x82)。TCP の nvmet.c と同じ扱い。 */
        if ((p->cdw10 >> 31) & 1u) {
            p->resp_status = NVMETR_SC_NOT_SAVEABLE;
        } else if ((p->cdw10 & 0xFFu) == NVME_FEAT_HOST_ID) {
            p->resp_status = NVMETR_SC_CMD_SEQ_ERROR;   /* Fabrics ではホスト識別子は Connect で決まる */
        } else {
            p->resp_status = nvmet_pr_set_notify_mask(&ctx->ctrl->pr, p->nsid, p->cdw11, &p->resp_dw0);
        }
    } else if (p->opcode == NVME_ADM_CMD_SET_FEATURES) {
        /* **Number of Queues(FID=0x07)に本数を返す。** 以前は全 FID に
         * dw0=0 を返しており、0's based なので**ホストには「IO キュー
         * 1 本」と伝わっていた**。これが RDMA が 1 コネクションしか
         * 張れなかった直接の原因(RC QP が 2 本しか無かったのとは別の話)。
         * NSQR/NCQR も 0's based なので +1 してから比べる。 */
        if ((p->cdw10 & 0xFFu) == NVME_FEAT_NUM_QUEUES) {
            uint32_t nsqr = (p->cdw11 & 0xFFFFu) + 1u;
            uint32_t ncqr = ((p->cdw11 >> 16) & 0xFFFFu) + 1u;
            uint32_t want = (nsqr < ncqr) ? nsqr : ncqr;
            uint32_t give = (want < NVMET_RDMA_IO_QUEUES) ? want : NVMET_RDMA_IO_QUEUES;
            if (give == 0u) give = 1u;
            ctx->ctrl->io_queues_granted = give;
            p->resp_dw0 = ((give - 1u) << 16) | (give - 1u);
            uart_printf("[nvmet-rdma] Number of Queues: 要求 %u 本 -> %u 本を許諾\n",
                        want, give);
        } else if ((p->cdw10 & 0xFFu) == NVME_FEAT_ASYNC_EVENT) {
            ctx->ctrl->aen_config = p->cdw11;
        } else if ((p->cdw10 & 0xFFu) == NVME_FEAT_KATO) {
            ctx->ctrl->kato_ms = p->cdw11;
        }
    } else if (p->opcode == NVME_ADM_CMD_GET_FEATURES) {
        /* **SPDK のイニシエータは接続の途中で Keep Alive Timer(FID 0x0F)を Get Features で読み、
         * 失敗すると接続をやめる**(`Keep alive timeout Get Feature failed`)。Linux のホストは読まないので
         * 以前は未実装で、未知の opcode として返していた。TCP の nvmet.c(nvmet_feat_current())と同じ
         * 4 つを返し、それ以外の FID は Invalid Field で返す。 */
        const uint32_t fid = p->cdw10 & 0xFFu;
        const uint32_t sel = (p->cdw10 >> 8) & 0x7u;
        uint32_t v = 0;
        int ok = 1;
        if (fid == NVME_FEAT_HOST_ID || fid == NVME_FEAT_RESV_MASK) {
            if (sel == NVME_FEAT_SEL_SAVED || sel > NVME_FEAT_SEL_SUPPORTED) {
                p->resp_status = NVMETR_SC_INVALID_FIELD;
            } else if (sel == NVME_FEAT_SEL_SUPPORTED) {
                p->resp_dw0 = (fid == NVME_FEAT_RESV_MASK) ? (NVME_FEAT_CAP_NS_SPECIFIC | NVME_FEAT_CAP_CHANGEABLE) : 0u;
            } else if (fid == NVME_FEAT_RESV_MASK) {
                p->resp_status = nvmet_pr_get_notify_mask(&ctx->ctrl->pr, p->nsid, &p->resp_dw0);
            } else if (!(p->cdw11 & 1u)) {
                p->resp_status = NVMETR_SC_INVALID_FIELD;   /* 128 ビットの形(EXHID)でしか返せない */
            } else {
                /* ホスト識別子 16 バイトを置き場から RDMA_WRITE で返す。 */
                nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key, &p->inval_rkey);
                for (unsigned k = 0; k < 16u; k++) stg[k] = ctx->ctrl->pr.hostid[k];
                if (p->ksgl_len > 16u) p->ksgl_len = 16u;
                if (p->ksgl_len != 0) {
                    p->stage = 1;
                    p->need_data_move = 1;
                    p->data_move_is_write = 1;
                }
            }
            return;
        }
        if (fid == NVME_FEAT_NUM_QUEUES) {
            uint32_t n = ctx->ctrl->io_queues_granted ? ctx->ctrl->io_queues_granted : 1u;
            v = (n - 1u) | ((n - 1u) << 16);
        } else if (fid == NVME_FEAT_VOLATILE_WC) {
            v = 0;
        } else if (fid == NVME_FEAT_ASYNC_EVENT) {
            v = ctx->ctrl->aen_config;
        } else if (fid == NVME_FEAT_KATO) {
            v = ctx->ctrl->kato_ms;
        } else {
            ok = 0;
        }
        if (!ok || sel == NVME_FEAT_SEL_SAVED) {
            p->resp_status = 0x8004u;   /* SC=0x02 Invalid Field in Command + DNR(保存値は持たない)*/
        } else if (sel == NVME_FEAT_SEL_SUPPORTED) {
            p->resp_dw0 = (fid == NVME_FEAT_ASYNC_EVENT || fid == NVME_FEAT_KATO) ? NVME_FEAT_CAP_CHANGEABLE : 0u;
        } else {
            p->resp_dw0 = v;
        }
    } else if (p->opcode == NVME_ADM_CMD_KEEP_ALIVE) {
        /* 応答するだけ(need_data_move=0 のまま成功 CQE を返す)。 */
    } else if (p->opcode == NVME_ADM_CMD_GET_LOG_PAGE) {
        /* NUMD は 0's based の dword 数(cdw10 の上位 16 ビット + cdw11 の下位 16 ビット)、LPO は cdw12。
         * ページを置き場に組み立て、LPO から要求の長さだけ RDMA_WRITE で返す。 */
        const uint32_t lid   = p->cdw10 & 0xFFu;
        const uint32_t bytes = ((((p->cdw11 & 0xFFFFu) << 16) | ((p->cdw10 >> 16) & 0xFFFFu)) + 1u) * 4u;
        const uint32_t lpo   = p->cdw12;
        uint8_t *buf = (uint8_t *)(uintptr_t)stg;
        uint32_t log_len;
        for (uint32_t i = 0; i < NVMET_RDMA_INLINE_MAX; i++) buf[i] = 0;
        if (lid == NVME_LOG_LID_SMART) {
            nvmetr_build_smart(ctx, buf);
            log_len = NVME_SMART_LOG_LEN;
        } else if (lid == NVME_LOG_LID_ERROR) {
            log_len = NVME_ERROR_SLOT_LEN;   /* エラーは記録していない(ELPE=0 の 1 エントリが空)*/
        } else if (lid == NVME_LOG_LID_RESERVATION) {
            nvmet_pr_build_log(&ctx->ctrl->pr, buf);   /* 読むたびに 1 件取り出す */
            log_len = 64u;
        } else {
            log_len = NVMET_RDMA_INLINE_MAX;   /* 持っていないログはゼロ埋め(Changed Namespace List も空)*/
        }
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key, &p->inval_rkey);
        uint32_t send = (lpo < log_len) ? (log_len - lpo) : 0u;
        if (send > bytes) send = bytes;
        if (send > p->ksgl_len) send = p->ksgl_len;
        if (lpo != 0u && send != 0u) memmove(buf, &buf[lpo], send);
        if (send != 0u) {
            p->ksgl_len = send;
            p->stage = 1;
            p->need_data_move = 1;
            p->data_move_is_write = 1;
        }
    } else if (p->opcode == NVME_ADM_CMD_ASYNC_EVENT) {
        /* イベントが起きるまで完了させない(パイプラインのループが保留にする)。 */
        p->defer = 1;
    } else if (p->opcode == NVME_ADM_CMD_ABORT) {
        /* 既定は「取り消さなかった」(DW0 bit0 = 1)。保留中の AER を指していればループが取り消す。 */
        p->resp_dw0 = 1u;
    } else {
        p->resp_status = NVMET_RDMA_SC_ERROR;
    }
}

/* in-capsule(Data Block + Offset、型 0x01)か keyed SGL かを見てデータの在りかを取り出す。 */
static void nvmetr_parse_data_sgl(const volatile uint8_t *rb, nvmet_rdma_pl_pending_t *p)
{
    const volatile uint8_t *dptr = &rb[24];
    if (dptr[15] == 0x01u) {
        p->data_inline = 1;
        p->inline_off  = (uint32_t)rd64le(&dptr[0]);
        p->ksgl_len    = rd32le(&dptr[8]);
    } else {
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key, &p->inval_rkey);
    }
}

/* ホストから受け取るデータを置き場で扱うと決める。in-capsule ならそのまま、keyed なら RDMA_READ で
 * 置き場へ引く。置き場は 4096 バイト(Compare だけはこれを超えてもよく、4096 バイトずつ引いて比べる)。 */
static void nvmetr_stage_in(nvmet_rdma_pl_pending_t *p)
{
    if (p->ksgl_len == 0) { p->resp_status = NVMETR_SC_INVALID_FIELD; return; }
    if (p->ksgl_len > NVMET_RDMA_INLINE_MAX && (p->data_inline || p->opcode != NVME_IO_CMD_COMPARE)) {
        p->resp_status = NVMETR_SC_SGL_LEN_INVALID;
        return;
    }
    p->stage = 1;
    if (!p->data_inline) {
        p->need_data_move = 1;
        p->data_move_is_write = 0;
    }
}

/*=================================================================
 * IO キューのコマンドを解釈する(nvmetr_parse_command() から)。
 * split が 0(ループバック用の古い構成)のときは Flush / Read / Write だけ扱う。
 * ===============================================================*/
static void nvmetr_parse_io(nvmet_rdma_ctx_t *ctx, const volatile uint8_t *rb,
                            nvmet_rdma_pl_pending_t *p, int split)
{
    volatile uint8_t *stg = (volatile uint8_t *)(uintptr_t)&rb[NVMET_RDMA_STAGE_OFF];
    /* **予約を持つホストがいるときだけ判定する**(いなければ 1 バイト読むだけ)。名前空間は 1 つ。
     * 予約のコマンド自身は nvmet_pr_execute() の中で判定する。 */
    if (split && g_nvmet_pr_held[NVMET_PR_DOM_RDMA][0]) {
        const uint16_t pst = nvmet_pr_check_access(&ctx->ctrl->pr, 1u, p->opcode);
        if (pst != 0) {
            uart_printf("[nvmet-rdma] 予約と衝突 (opcode=0x%x)\n", p->opcode);
            p->resp_status = pst;
            return;
        }
    }
    if (p->opcode == NVME_IO_CMD_FLUSH) {
        /* RAM ディスクなので揮発性キャッシュが無く、成功を返すだけでよい。 */
    } else if (p->opcode == NVME_IO_CMD_READ) {
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key,
                               &p->inval_rkey);
        p->io_slba = (uint64_t)p->cdw10 | ((uint64_t)p->cdw11 << 32);
        uint32_t nlb = (p->cdw12 & 0xFFFFu) + 1u;
        uint64_t end_lba = p->io_slba + nlb;
        if (end_lba > NVMET_RDMA_NS_LBA_COUNT ||
            (uint64_t)nlb * NVMET_RDMA_LBA_SIZE > NVMET_RDMA_RAMDISK_SLOT_SIZE ||
            p->ksgl_len > (uint64_t)nlb * NVMET_RDMA_LBA_SIZE) {
            p->resp_status = NVMET_RDMA_SC_ERROR;
            return;
        }
        ctx->st_rd_cmds++;
        ctx->st_rd_bytes += (uint64_t)nlb * NVMET_RDMA_LBA_SIZE;
        p->need_data_move = 1;
        p->data_move_is_write = 1;
    } else if (p->opcode == NVME_IO_CMD_WRITE) {
        /* SGL descriptor の型は 16 バイト目(dptr[15])。上位 4bit が種別、
         * 下位 4bit が sub-type で、0x01 = Data Block + Offset は
         * 「データは capsule の中にある」の意味(in-capsule)。keyed SGL
         * (0x4X)と長さ欄の位置が違う -- keyed は 3 バイト、こちらは 4 バイト。 */
        const volatile uint8_t *dptr = &rb[24];
        if (dptr[15] == 0x01u) {
            p->data_inline = 1;
            p->inline_off  = (uint32_t)rd64le(&dptr[0]); /* ICDOFF 由来。こちらは 0 を広告 */
            p->ksgl_len    = rd32le(&dptr[8]);
        } else {
            nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key,
                               &p->inval_rkey);
        }
        p->io_slba = (uint64_t)p->cdw10 | ((uint64_t)p->cdw11 << 32);
        uint32_t nlb = (p->cdw12 & 0xFFFFu) + 1u;
        uint64_t end_lba = p->io_slba + nlb;
        if (end_lba > NVMET_RDMA_NS_LBA_COUNT ||
            (uint64_t)nlb * NVMET_RDMA_LBA_SIZE > NVMET_RDMA_RAMDISK_SLOT_SIZE) {
            p->resp_status = NVMET_RDMA_SC_ERROR;
            return;
        }
        if (p->data_inline) {
            if (p->ksgl_len > NVMET_RDMA_INLINE_MAX ||
                p->ksgl_len > (uint64_t)nlb * NVMET_RDMA_LBA_SIZE) {
                p->resp_status = NVMET_RDMA_SC_ERROR;
                return;
            }
            /* データは既に受信バッファにある。RDMA_READ は要らない。 */
            ctx->st_wr_cmds++;
            ctx->st_wr_bytes += (uint64_t)nlb * NVMET_RDMA_LBA_SIZE;
            p->need_data_move = 0;
            return;
        }
        ctx->st_wr_cmds++;
        ctx->st_wr_bytes += (uint64_t)nlb * NVMET_RDMA_LBA_SIZE;
        p->need_data_move = 1;
        p->data_move_is_write = 0; // ホストからRDMA_READで引き込む
    } else if (!split) {
        p->resp_status = NVMET_RDMA_SC_ERROR;
    } else if (p->nsid != 1u) {
        /* ここから下は 1 つの名前空間を指すコマンド。 */
        p->resp_status = NVMETR_SC_INVALID_NS;
    } else if (p->opcode == NVME_IO_CMD_WRITE_ZEROES) {
        /* cdw12 の NLB は 0's based(DSM の範囲の NLB とは違う)。データは送られてこない。 */
        const uint64_t slba = (uint64_t)p->cdw10 | ((uint64_t)p->cdw11 << 32);
        if (nvmetr_zero_lbas(ctx, slba, (p->cdw12 & 0xFFFFu) + 1u) != 0) p->resp_status = NVMETR_SC_LBA_RANGE;
    } else if (p->opcode == NVME_IO_CMD_DSM || p->opcode == NVME_IO_CMD_COPY ||
               p->opcode == NVME_IO_CMD_RESV_REGISTER || p->opcode == NVME_IO_CMD_RESV_ACQUIRE ||
               p->opcode == NVME_IO_CMD_RESV_RELEASE) {
        /* 範囲の一覧・鍵を受け取ってから実行する(nvmetr_exec_staged())。 */
        nvmetr_parse_data_sgl(rb, p);
        nvmetr_stage_in(p);
    } else if (p->opcode == NVME_IO_CMD_COMPARE) {
        p->io_slba = (uint64_t)p->cdw10 | ((uint64_t)p->cdw11 << 32);
        const uint32_t nlb = (p->cdw12 & 0xFFFFu) + 1u;
        if (p->io_slba > NVMET_RDMA_NS_LBA_COUNT || nlb > NVMET_RDMA_NS_LBA_COUNT - p->io_slba) {
            p->resp_status = NVMETR_SC_LBA_RANGE;
            return;
        }
        nvmetr_parse_data_sgl(rb, p);
        if (p->ksgl_len < nlb * NVMET_RDMA_LBA_SIZE) { p->resp_status = NVMETR_SC_SGL_LEN_INVALID; return; }
        p->ksgl_len = nlb * NVMET_RDMA_LBA_SIZE;   /* 比べるのはこの長さ(4096 を超えれば分けて引く)*/
        nvmetr_stage_in(p);
        if (p->resp_status == 0) ctx->st_rd_cmds++;
    } else if (p->opcode == NVME_IO_CMD_RESV_REPORT) {
        /* 応答は置き場に組み立てて RDMA_WRITE で返す。 */
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key, &p->inval_rkey);
        uint32_t olen = 0;
        p->resp_status = nvmet_pr_execute(&ctx->ctrl->pr, p->nsid, p->opcode, p->cdw10, p->cdw11, NULL, 0,
                                          (uint8_t *)(uintptr_t)stg, NVMET_RDMA_INLINE_MAX, &olen);
        if (p->resp_status != 0) {
            uart_printf("[nvmet-rdma] Reservation Report -> status=0x%x\n", p->resp_status);
            return;
        }
        if (olen > p->ksgl_len) olen = p->ksgl_len;
        if (olen != 0) {
            p->ksgl_len = olen;
            p->stage = 1;
            p->need_data_move = 1;
            p->data_move_is_write = 1;
        }
    } else {
        p->resp_status = NVMET_RDMA_SC_ERROR;
    }
}

/*=================================================================
 * 応答 capsule(CQE 16 バイト)を指定バッファへ組み立てる。
 *
 * 引数:
 *   b        - 書き込み先
 *   dw0, dw1 - CQE の dword0/1
 *   cid      - 対応するコマンド id
 *   status   - ステータスフィールド
 * コール元:
 *   nvmetr_build_resp_capsule(), nvmetr_pl_send_response()
 * ===============================================================*/
static void nvmetr_build_resp_capsule_into(volatile uint8_t *b, uint32_t dw0, uint32_t dw1,
                                            uint16_t cid, uint16_t status)
{
    nvmetr_zero_v(b, NVME_CQE_LEN);
    wr32le(&b[0], dw0);       /* dw0 */
    wr32le(&b[4], dw1);       /* dw1 */
    wr16le(&b[8], 0);         /* sq_head */
    wr16le(&b[10], 0);        /* sq_id */
    wr16le(&b[12], cid);      /* cid */
    wr16le(&b[14], status);   /* status */
    dcache_clean_range((const void *)(uintptr_t)b, NVME_CQE_LEN);
}

/*=================================================================
 * 単発コマンド処理経路で、受信済みコマンドを解釈して応答内容
 * (resp_dw0/resp_status)と必要なデータ移動の有無・向きを決める。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
static void nvmetr_dispatch(nvmet_rdma_ctx_t *ctx)
{
    nvmet_rdma_pl_pending_t p;
    nvmetr_parse_command(ctx, ctx->recv_buf, &p);
    ctx->opcode = p.opcode;
    ctx->fctype = p.fctype;
    ctx->cid = p.cid;
    ctx->nsid = p.nsid;
    ctx->cdw10 = p.cdw10;
    ctx->cdw11 = p.cdw11;
    ctx->cdw12 = p.cdw12;
    ctx->ksgl_addr = p.ksgl_addr;
    ctx->ksgl_len = p.ksgl_len;
    ctx->ksgl_key = p.ksgl_key;
    ctx->io_slba = p.io_slba;
    ctx->need_data_move = p.need_data_move;
    ctx->data_inline = p.data_inline;
    ctx->data_move_is_write = p.data_move_is_write;
    ctx->fab_data = p.fab_data;
    ctx->resp_dw0 = p.resp_dw0;
    ctx->resp_dw1 = p.resp_dw1;
    ctx->resp_status = p.resp_status;
    ctx->stage = p.stage;
    ctx->id_sel = p.id_sel;
    if (p.stage || p.defer) {
        /* 置き場と保留はパイプラインの経路でしか扱わない(常駐ターゲットはすべてパイプライン)。 */
        uart_printf("[!] nvmet-rdma: opcode=0x%x は非パイプライン経路では未対応\n", p.opcode);
        ctx->stage = 0;
        ctx->need_data_move = 0;
        ctx->data_inline = 0;
        ctx->resp_status = NVMET_RDMA_SC_ERROR;
    }
}

/*=================================================================
 * コンテキストが保持する応答内容から応答 capsule を組み立てる
 * (単発コマンド処理経路用)。
 *
 * 引数:
 *   ctx - ターゲットコンテキスト
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
static void nvmetr_build_resp_capsule(nvmet_rdma_ctx_t *ctx)
{
    nvmetr_build_resp_capsule_into(ctx->send_buf, ctx->resp_dw0, ctx->resp_dw1, ctx->cid, ctx->resp_status);
}

/*=================================================================
 * QP が作成済みなら DESTROY_QP で FW 側のオブジェクトを解放する
 * (切断検出後の作り直しに備える)。
 *
 * 引数:
 *   dev - この QP を持つ HCA
 *   qp  - 解放する QP(qpn==0 なら何もしない)
 * コール元:
 *   nvmetr_reset_admin_for_reconnect()
 * ===============================================================*/
static void nvmetr_destroy_qp_if_valid(mlx5_dev_t *dev, mlx5_qp_t *qp)
{
    if (dev != NULL && qp != NULL && qp->qpn != 0) {
        mlx5_qp_destroy(dev, qp);
    }
}

/*=================================================================
 * CM DREP MAD(Table 113)を組み立てる。LOCAL_COMM_ID は自分の comm_id、
 * REMOTE_COMM_ID は受信した DREQ の LOCAL_COMM_ID をそのまま返す。
 *
 * 引数:
 *   ctx                 - ターゲットコンテキスト(送信バッファを持つ)
 *   dreq_tid            - 受信 DREQ のトランザクション ID
 *   dreq_local_comm_id  - 受信 DREQ の LOCAL_COMM_ID
 * コール元:
 *   nvmetr_check_gsi_disconnect()
 * ===============================================================*/
static void nvmetr_build_drep(nvmet_rdma_ctx_t *ctx, uint64_t dreq_tid, uint32_t my_comm_id,
                              uint32_t dreq_local_comm_id)
{
    volatile uint8_t *buf = ctx->cm.send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) buf[i] = 0;
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND,
                     dreq_tid, CM_DREP_ATTR_ID, 0);
    volatile uint8_t *p = &buf[IB_MAD_HDR_LEN];
    wr32be_ib(&p[0], my_comm_id);            // LOCAL_COMM_ID(畳まれる接続のこちら側)
    wr32be_ib(&p[4], dreq_local_comm_id);    // REMOTE_COMM_ID = DREQ.LOCAL_COMM_IDのecho
}

/*=================================================================
 * admin queue の切断(DREQ 受信または RC QP のエラー完了)を検出したときに、
 * RC/GSI QP を FW 側から解放し、ペアの IO キューも畳んで、次のクライアント
 * を待てる初期状態へ戻す。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   self - このジョブ
 * コール元:
 *   nvmet_rdma_job_step(), nvmetr_check_gsi_disconnect()
 * ===============================================================*/
static void nvmetr_reset_admin_for_reconnect(nvmet_rdma_ctx_t *ctx, job_t *self)
{
    /* **IO キューのジョブ(と、その受け皿の CM ジョブ)が全部終わってから GSI を作り直す。**
     * IO キューのジョブは rdmacores 2 以上では別のコアで回っている。以前はここで IO キューの QP を
     * こちらのコアから壊し、すぐ GSI を作り直していたので、別のコアで受け皿に戻りかけていた IO キューの
     * ジョブが止め損ねた CM ジョブを残し、古い GSI を触って GSI ごと壊れた(2 コアで 2 回目以降の接続を
     * 受けられなかった原因)。止める要求だけ出し、NVMETR_ST_WAIT_IO_GONE で待つ。 */
    if (ctx->on_disconnected) {
        ctx->on_disconnected(ctx);   // -> nvmetr_on_admin_disconnected(このファイル)
    }
    self->state = NVMETR_ST_WAIT_IO_GONE;
}

/* 同じ組の IO キューのジョブと受け皿の CM ジョブが全部終わったか(終わっていなければ止め直す)。
 * IO キューの ctx の先頭は cm なので、job_count_by_ctx(&io_ctx[k]) は両方を数える。 */
static int nvmetr_io_jobs_gone(void)
{
    int gone = 1;
    for (unsigned k = 0; k < NVMET_RDMA_IO_QUEUES; k++) {
        if (job_count_by_ctx(&s_standalone_io_ctx[k]) != 0) {
            s_standalone_io_ctx[k].stop_requested = 1;
            job_cancel_by_ctx(&s_standalone_io_ctx[k]);   /* 後から生まれた CM ジョブも止める */
            gone = 0;
        }
    }
    return gone;
}

/* nvmetr_reset_admin_for_reconnect() の続き。IO キューのジョブが全部終わってから呼ぶ。 */
static void nvmetr_rearm_admin(nvmet_rdma_ctx_t *ctx, job_t *self)
{
    for (unsigned k = 0; k < NVMET_RDMA_IO_QUEUES; k++) {   /* 止まる前に CM ジョブが作った QP の残り */
        nvmetr_destroy_qp_if_valid(s_standalone_io_ctx[k].cm.dev, &s_standalone_io_ctx[k].cm.rc_qp);
    }
    nvmetr_destroy_qp_if_valid(ctx->cm.dev, &ctx->cm.rc_qp);
    nvmetr_destroy_qp_if_valid(ctx->cm.dev, ctx->cm.gsi_qp);

    mlx5_dev_t *dev = ctx->cm.dev;
    const char *self_label = ctx->self_label;
    uint8_t peer_mac_fallback[6];
    for (unsigned i = 0; i < 6; i++) peer_mac_fallback[i] = ctx->peer_mac_fallback[i];
    static const uint8_t dummy_mac[6] = {0, 0, 0, 0, 0, 0};

    rdma_cm_fill_addr(&ctx->cm, dev, self_label, "__no_such_net_ctx__", 0u, 0u,
                      dummy_mac, peer_mac_fallback);
    ctx->cm.is_active = 0;
    ctx->cm.skip_ping = 1;
    ctx->cm.req_qid_class = RDMA_CM_REQ_ADMIN;
    ctx->cm.hold_rep = 1;
    ctx->established = 0;
    ctx->failed = 0;

    ctx->ctrl->ctrlr_id = ctx->ctrl->cntlid_cfg ? ctx->ctrl->cntlid_cfg : 1u;
    ctx->ctrl->cc = 0;
    ctx->ctrl->cc_en = 0;
    nvmet_auth_reset(&ctx->ctrl->auth);
    nvmetr_build_id_ctrl(ctx);
    nvmetr_build_id_ns(ctx);

    job_t *cmjob = job_spawn(rdma_cm_job_step, &ctx->cm, "nvmet-rdma-cm");
    if (!cmjob) {
        uart_printf("[!] nvmet-rdma: 再接続用CMジョブ生成失敗(ジョブテーブル満杯)\n");
        ctx->failed = 1;
        return;
    }
    cmjob->state = RDMA_CM_ST_PASSIVE_SETUP;
    self->state = NVMETR_ST_CM_WAIT;
    uart_printf("[nvmet-rdma] %sで次のホスト接続を待ちます\n", self_label);
}

/*=================================================================
 * GSI を所有する admin queue 側から毎 tick 呼ばれ、GSI CQ を 1 件だけ
 * 非ブロッキングでポーリングして CM DREQ(切断要求)が来ていないか調べる。
 * 来ていれば DREP を返して再接続待ちへ戻す。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   self - このジョブ
 * 戻り値:
 *   1=切断を検出して処理した、0=何も無い
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
static int nvmetr_check_gsi_disconnect(nvmet_rdma_ctx_t *ctx, job_t *self)
{
    if (ctx->queue_id != 0 || ctx->self_label == NULL || !ctx->cm.rtu_phase_done ||
        ctx->cm.gsi_qp == NULL) {
        return 0;
    }

    /* GSI の CQ を直接のぞかず、rdma_cm.c の振り分けから DREQ だけを受け取る。
     * 以前は直接ポーリングして DREQ 以外を捨てていたので、IO キューの CM が
     * 待っている RTU を横取りして 3 秒待たせていた(段階 C で RDMA の認証つき
     * 接続が 5 秒かかっていたのもこれ)。 */
    if (rdma_cm_take_dreq(&ctx->cm, NULL) != 1) {
        return 0;
    }

    const volatile uint8_t *p = &ctx->cm.recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    uint64_t dreq_tid            = rd64be(&ctx->cm.recv_buf[MLX5_GRH_BYTES + 8]);
    uint32_t dreq_local_comm_id  = rd32be_ib(&p[0]);
    uint32_t dreq_remote_comm_id = rd32be_ib(&p[4]);
    int is_admin = (dreq_remote_comm_id == ctx->cm.local_comm_id);

    /* **どの接続宛ての DREQ にも DREP を返す。** Linux のホストは IO キューの
     * DREQ を先に送り、DREP が来ないとその DREQ の時間切れ(約 5 秒)を待って
     * から admin の DREQ を送る。前の接続の DREQ の再送(こちらの DREP が
     * 落ちた場合)にも、その comm_id のまま DREP を返せば相手は畳める。 */
    const char *who = "admin";
    if (!is_admin) {
        who = "既に畳んだ接続";
        for (int k = 0; k < s_standalone_io_spawned; k++) {
            if (s_standalone_io_ctx[k].cm.local_comm_id == dreq_remote_comm_id) {
                s_standalone_io_ctx[k].requeue = 1;   /* その枠を受け皿に戻す(IO キューのジョブがやる) */
                who = "IOキュー";
                break;
            }
        }
    }
    uart_printf("[nvmet-rdma] CM DREQ受信 (%s、comm_id=0x%08x) -- DREP送信%s\n", who,
                dreq_remote_comm_id, is_admin ? "、次の接続を待つ状態へ戻ります" : "");
    nvmetr_build_drep(ctx, dreq_tid, dreq_remote_comm_id, dreq_local_comm_id);
    dcache_clean_range((const void *)(uintptr_t)ctx->cm.send_buf, sizeof(ctx->cm.send_buf));
    mlx5_qp_post_send_ud(ctx->cm.dev, ctx->cm.gsi_qp, (const void *)(uintptr_t)ctx->cm.send_buf,
                         RDMA_CM_MAD_SIZE, 1u /* GSI宛は常にQPN=1固定[フェーズd] */,
                         IB_QP1_QKEY, ctx->cm.peer_gid, ctx->cm.peer_mac);
    if (!is_admin) {
        return 0;   /* IO キューの QP はそのキューのジョブが捨てて受け皿に戻る(requeue) */
    }

    nvmetr_reset_admin_for_reconnect(ctx, self);
    return 1;
}

/*=================================================================
 * パイプライン用スロットの受信バッファへ RECV WQE を投稿する。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   slot - スロット番号
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
static int nvmetr_pl_post_recv_slot(nvmet_rdma_ctx_t *ctx, unsigned slot)
{
    if (mlx5_qp_post_recv(ctx->cm.dev, &ctx->cm.rc_qp, (void *)(uintptr_t)ctx->pl.recv_bufs[slot],
                          sizeof(ctx->pl.recv_bufs[slot])) != 0) {
        return -1;
    }
    ctx->pl.rq_order[ctx->pl.rq_tail % NVMET_RDMA_MAX_PENDING] = slot;
    ctx->pl.rq_tail++;
    return 0;
}

/*=================================================================
 * write コマンドのデータをホストから引き込む RDMA_READ を 1 件発行する。
 * 同時発行数は HCA の Responder Resources 上限(実測 1)で制限されるため、
 * 上限に達している間は呼び出し元が保留キューへ積む。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   slot - 対象スロット
 * 戻り値:
 *   0=発行成功、-1=失敗
 * コール元:
 *   nvmetr_pl_start_data_move(), nvmet_rdma_job_step()
 * ===============================================================*/
static int nvmetr_pl_issue_rdma_read(nvmet_rdma_ctx_t *ctx, unsigned slot)
{
    nvmet_rdma_pl_pending_t *p = &ctx->pl.pending[slot];
    volatile uint8_t *dst = p->fab_data ? ctx->ctrl->fab_buf
                                        : &ctx->ctrl->ram_disk[p->io_slba * NVMET_RDMA_LBA_SIZE];
    uint32_t len   = p->ksgl_len;
    uint64_t raddr = p->ksgl_addr;
    if (p->stage) {
        /* 置き場へ引く。Compare は 4096 バイトずつ(cmp_off から)。 */
        dst = &ctx->pl.recv_bufs[slot][NVMET_RDMA_STAGE_OFF];
        if (p->opcode == NVME_IO_CMD_COMPARE) {
            len = p->ksgl_len - p->cmp_off;
            if (len > NVMET_RDMA_INLINE_MAX) len = NVMET_RDMA_INLINE_MAX;
            raddr += p->cmp_off;
        }
    }
    if (mlx5_qp_post_rdma_read(ctx->cm.dev, &ctx->cm.rc_qp, (void *)(uintptr_t)dst,
                                len, raddr, p->ksgl_key) != 0) {
        return -1;
    }
    ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].is_resp_send = 0;
    ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].slot = slot;
    ctx->pl.sq_tail++;
    ctx->pl.rra_inflight++;
    return 0;
}

static int nvmetr_pl_send_response(nvmet_rdma_ctx_t *ctx, unsigned slot);

/*=================================================================
 * スロットのデータ移動を開始する。read/Identify(ホストへ RDMA_WRITE)は
 * 無条件で即時発行、write(ホストから RDMA_READ)は RRA 上限に空きがある
 * ときだけ発行し、無ければ保留キューへ積む。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   slot - 対象スロット
 * 戻り値:
 *   0=即時発行した、1=RRA 上限のため保留した、-1=失敗
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
static int nvmetr_pl_start_data_move(nvmet_rdma_ctx_t *ctx, unsigned slot)
{
    nvmet_rdma_pl_pending_t *p = &ctx->pl.pending[slot];
    if (p->data_move_is_write) { // RDMA_WRITE(READ/Identify) -- RRA対象外、常に即時発行
        const volatile uint8_t *src;
        uint32_t len = p->ksgl_len;
        if (p->fab_data) {   /* Authentication Receive の応答(長さは解析時に決めてある)*/
            src = ctx->ctrl->fab_buf;
        } else if (p->stage) {   /* Get Log Page / Get Features / Reservation Report の応答 */
            src = &ctx->pl.recv_bufs[slot][NVMET_RDMA_STAGE_OFF];
        } else if (p->opcode == NVME_ADM_CMD_IDENTIFY) {
            src = nvmetr_id_buf(ctx->ctrl, p->id_sel);
            if (len > NVMET_RDMA_ID_BUF_LEN) len = NVMET_RDMA_ID_BUF_LEN;
        } else { // READ
            src = &ctx->ctrl->ram_disk[p->io_slba * NVMET_RDMA_LBA_SIZE];
        }
        if (mlx5_qp_post_rdma_write(ctx->cm.dev, &ctx->cm.rc_qp, (const void *)(uintptr_t)src,
                                     len, p->ksgl_addr, p->ksgl_key) != 0) {
            return -1;
        }
        ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].is_resp_send = 0;
        ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].slot = slot;
        ctx->pl.sq_tail++;
        /* **RDMA_WRITE の完了を待たずに、応答 SEND も続けて投稿する。**
         * SQ は投稿順に処理されるので、ホストにはデータが届いた後に応答が
         * 届く。待つと完了 CQE の往復(実測 2.35us)がそのまま qd=1 の
         * レイテンシに乗る。Linux の nvmet_rdma_queue_response() も
         * rdma_rw_ctx_wrs(..., &rsp->send_wr) で 1 回の ib_post_send に
         * 鎖でつないでいる(SPDK も同じ)。
         * 代償は「RDMA_WRITE が失敗しても成功応答を先に投げてしまう」こと
         * だが、Linux も SPDK も同じ露出を受け入れている(エラーは CQE で
         * 検出して QP ごと畳む)。 */
        if (nvmetr_pl_send_response(ctx, slot) != 0) return -2;
        return 0;
    }
    // WRITE: RDMA_READでram_diskへ引き込む -- RRA上限に達していれば保留
    if (ctx->pl.rra_inflight >= ctx->pl.rra_max) {
        ctx->pl.rra_pending[ctx->pl.rra_pending_tail % NVMET_RDMA_MAX_PENDING] = slot;
        ctx->pl.rra_pending_tail++;
        return 1;
    }
    return (nvmetr_pl_issue_rdma_read(ctx, slot) == 0) ? 0 : -1;
}

/*=================================================================
 * スロットの応答 capsule(CQE)を組み立てて SEND する。
 *
 * 引数:
 *   ctx  - ターゲットコンテキスト
 *   slot - 対象スロット
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   nvmet_rdma_job_step()
 * ===============================================================*/
static int nvmetr_pl_send_response(nvmet_rdma_ctx_t *ctx, unsigned slot)
{
    nvmet_rdma_pl_pending_t *p = &ctx->pl.pending[slot];
    nvmetr_build_resp_capsule_into(ctx->pl.resp_bufs[slot], p->resp_dw0, p->resp_dw1, p->cid, p->resp_status);
    /* ホストが keyed SGL に invalidate を要求していれば、その rkey を載せて
     * SEND_WITH_INVALIDATE で返す(ホスト側の LOCAL_INV が要らなくなる)。 */
    if (mlx5_qp_post_send_ex(ctx->cm.dev, &ctx->cm.rc_qp,
                             (const void *)(uintptr_t)ctx->pl.resp_bufs[slot],
                             NVME_CQE_LEN, 0, 0, p->inval_rkey) != 0) {
        return -1;
    }
    ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].is_resp_send = 1;
    ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].slot = slot;
    ctx->pl.sq_tail++;
    return 0;
}

/* 保留中の Asynchronous Event Request を完了させる(dw0 = イベント、status は Abort のときだけ非 0)。 */
static int nvmetr_aer_complete(nvmet_rdma_ctx_t *ctx, uint32_t dw0, uint16_t status)
{
    nvmet_rdma_ctrl_t *c = ctx->ctrl;
    if (!c->aer_pending) return 0;
    nvmet_rdma_pl_pending_t *ap = &ctx->pl.pending[c->aer_slot];
    ap->resp_dw0    = dw0;
    ap->resp_dw1    = 0;
    ap->resp_status = status;
    ap->inval_rkey  = 0;
    c->aer_pending  = 0;
    uart_printf("[nvmet-rdma] 非同期イベント通知 (dw0=0x%x status=0x%x cid=%u)\n", dw0, status, c->aer_cid);
    return nvmetr_pl_send_response(ctx, c->aer_slot);
}

/*=================================================================
 * admin キューで解析した直後の保留の扱い(パイプラインのループから)。
 * Asynchronous Event Request は応答を送らずにスロットを握る(AERL=0 なので 1 件まで)。
 * Abort は、保留中の AER を指していれば Command Abort Requested で完了させ、
 * Abort 自身には DW0 = 0 で答える。それ以外は「取り消さなかった」(DW0 = 1)のまま。
 *
 * 戻り値:
 *   1 = このスロットの応答は今は送らない、0 = いつもどおり送る
 * ===============================================================*/
static int nvmetr_admin_post_parse(nvmet_rdma_ctx_t *ctx, unsigned slot)
{
    nvmet_rdma_pl_pending_t *p = &ctx->pl.pending[slot];
    nvmet_rdma_ctrl_t *c = ctx->ctrl;
    if (p->opcode == NVME_ADM_CMD_ASYNC_EVENT && p->defer && p->resp_status == 0) {
        if (c->aer_pending) {
            p->defer = 0;
            p->resp_status = NVMETR_SC_ASYNC_LIMIT;   /* 黙って捨てるとホストは永久に待つ */
            return 0;
        }
        c->aer_pending = 1;
        c->aer_slot    = slot;
        c->aer_cid     = p->cid;
        uart_printf("[nvmet-rdma] Async Event Request を受理 (cid=%u、イベント発生まで保留)\n", p->cid);
        return 1;
    }
    if (p->opcode == NVME_ADM_CMD_ABORT && p->resp_status == 0) {
        const uint16_t sqid = (uint16_t)(p->cdw10 & 0xFFFFu);
        const uint16_t cid  = (uint16_t)(p->cdw10 >> 16);
        if (sqid == 0u && c->aer_pending && c->aer_cid == cid) {
            if (nvmetr_aer_complete(ctx, 0u, NVMETR_SC_ABORT_REQ) == 0) p->resp_dw0 = 0u;
        }
        uart_printf("[nvmet-rdma] Abort (sqid=%u cid=%u) -> %s\n", sqid, cid,
                    p->resp_dw0 ? "取り消さなかった" : "保留中の AER を取り消した");
    }
    return 0;
}

/*=================================================================
 * NVMe-oF RDMA ターゲットのステートマシン 1 tick。CM 待ち受け -> RC QP 確立
 * -> パイプラインループ(RECV 完了でコマンド解析 -> RDMA_READ/WRITE でデータ
 * 移動 -> 応答 SEND -> RECV 再投稿)と進む。admin queue 側は GSI を監視して
 * 切断も検出する。
 *
 * 引数:
 *   self - このジョブ(self->state がターゲットのステート)
 * 戻り値:
 *   JOB_WAITING=継続、JOB_DONE=停止要求で終了
 * コール元:
 *   job_scheduler_tick() から関数ポインタ経由
 * ===============================================================*/
job_result_t nvmet_rdma_job_step(job_t *self)
{
    nvmet_rdma_ctx_t *ctx = (nvmet_rdma_ctx_t *)self->ctx;
    {
        nvmetr_inst_t *in = nvmetr_inst_of(ctx);
        if (in) s_nr = in;
    }

    if (ctx->stop_requested || self->cancel_requested) {
        /* IO キューの QP は自分のコアで壊す(admin のジョブは別のコアにいることがある)。 */
        if (ctx->queue_id != 0) nvmetr_destroy_qp_if_valid(ctx->cm.dev, &ctx->cm.rc_qp);
        if (ctx == &s_standalone_ctx)    s_standalone_resident = 0;
        for (unsigned k = 0; k < NVMET_RDMA_IO_QUEUES; k++) {
            if (ctx == &s_standalone_io_ctx[k] && s_standalone_io_spawned > (int)k) {
                s_standalone_io_spawned = (int)k;
            }
        }
        return JOB_DONE;
    }
    if (ctx->requeue && ctx->queue_id != 0) {
        /* IO キューだけが切られた。ctx->cm を作り直すので、CM ジョブが終わる(RTU を受けたか 3 秒で
         * 諦めた、または失敗した)まで待つ。CM ジョブはこのジョブと同じコアで回る。
         * **job_cancel_by_ctx(&ctx->cm) は使えない** -- cm は ctx の先頭の要素なので &ctx->cm == ctx で、
         * このジョブ自身まで止めてしまう(実機で踏んだ。止まった IO キューのジョブが io_spawned を縮め、
         * admin の切断で畳まれずに次の接続まで残った)。 */
        if (!ctx->cm.rtu_phase_done && !ctx->cm.failed) {
            return JOB_WAITING;
        }
        ctx->requeue = 0;
        nvmetr_requeue_io(ctx, self);
        return JOB_WAITING;
    }

    switch (self->state) {

    case NVMETR_ST_CM_SPAWN: {
        ctx->cm.is_active = 0;
        ctx->cm.skip_ping = 1;
        /* admin の受け皿は qid 0 の REQ だけ、IO キューの受け皿は qid 1 以上の REQ だけを取る
         * (GSI は共有。取り違えると相手のキューの種類と合わない Connect を断ることになる)。 */
        ctx->cm.req_qid_class = (ctx->queue_id == 0) ? RDMA_CM_REQ_ADMIN : RDMA_CM_REQ_IO;
        ctx->cm.hold_rep = 1;   /* 受信を投稿してから REP を送らせる(PIPELINE_SETUP / POST_RECV で外す) */
        if (ctx->queue_id == 0) {
            ctx->ctrl->ctrlr_id = ctx->ctrl->cntlid_cfg ? ctx->ctrl->cntlid_cfg : 1u;
            ctx->ctrl->cc = 0;
            ctx->ctrl->cc_en = 0;
            nvmet_auth_reset(&ctx->ctrl->auth);
            nvmetr_build_id_ctrl(ctx);
            nvmetr_build_id_ns(ctx);
            nvmetr_zero_v64(ctx->ctrl->ram_disk, NVMET_RDMA_RAMDISK_SLOT_SIZE);
            dcache_clean_range((const void *)(uintptr_t)ctx->ctrl->ram_disk, NVMET_RDMA_RAMDISK_SLOT_SIZE);
        }

        job_t *cmjob = job_spawn(rdma_cm_job_step, &ctx->cm, "nvmet-rdma-cm");
        if (!cmjob) {
            uart_printf("[!] nvmet-rdma: CM用ジョブ生成失敗\n");
            ctx->failed = 1;
            return JOB_DONE;
        }
        cmjob->state = RDMA_CM_ST_PASSIVE_SETUP;
        self->state = NVMETR_ST_CM_WAIT;
        return JOB_WAITING;
    }

    case NVMETR_ST_WAIT_IO_GONE: {
        /* admin の切断の後、IO キューのジョブが全部終わるのを待ってから GSI を作り直す。 */
        if (!nvmetr_io_jobs_gone()) return JOB_WAITING;
        nvmetr_rearm_admin(ctx, self);
        return ctx->failed ? JOB_DONE : JOB_WAITING;
    }

    case NVMETR_ST_CM_WAIT: {
        if (ctx->cm.failed) {
            uart_printf("[!] nvmet-rdma: CM確立失敗\n");
            ctx->failed = 1;
            return JOB_DONE;
        }
        if (!ctx->cm.established) return JOB_WAITING;
        ctx->established = 1;
        uart_printf("[nvmet-rdma] RC QP確立完了 (qpn=%u queue_id=%u t=%uus)\n", ctx->cm.rc_qp.qpn,
                    ctx->queue_id, (unsigned)(timer_now() / 1000u));
        if (ctx->on_established) {
            ctx->on_established(ctx);   // -> nvmetr_on_admin_established(このファイル)
        }
        self->state = ctx->pipeline_enabled ? NVMETR_ST_PIPELINE_SETUP : NVMETR_ST_POST_RECV;
        return JOB_WAITING;
    }

    case NVMETR_ST_POST_RECV: {
        if (mlx5_qp_post_recv(ctx->cm.dev, &ctx->cm.rc_qp, (void *)(uintptr_t)ctx->recv_buf,
                              sizeof(ctx->recv_buf)) != 0) {
            uart_printf("[!] nvmet-rdma: post_recv失敗\n");
            ctx->failed = 1;
            return JOB_DONE;
        }
        ctx->cm.hold_rep = 0;
        self->state = NVMETR_ST_WAIT_CAPSULE;
        return JOB_WAITING;
    }

    case NVMETR_ST_WAIT_CAPSULE: {
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe(ctx->cm.dev, &ctx->cm.rc_qp, &is_send, &recv_len, &synd);
        if (rc < 0) {
            uart_printf("[!] nvmet-rdma: CQEエラー syndrome=0x%02x\n", synd);
            ctx->failed = 1;
            return JOB_DONE;
        }
        if (rc == 0) return JOB_WAITING;
        if (is_send) {
            return JOB_WAITING;
        }
        dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, recv_len);
        ctx->recv_len = recv_len;
        nvmetr_dispatch(ctx);
        if (ctx->data_inline) {
            /* in-capsule write はパイプライン側でしか処理していない。admin キューは
             * IO コマンドを運ばないのでここへは来ないが、黙って成功を返すと
             * 「書けたつもり」になるのでエラーにする。 */
            uart_printf("[!] nvmet-rdma: in-capsule writeは非パイプライン経路では未対応\n");
            ctx->resp_status = NVMET_RDMA_SC_ERROR;
        }
        if (ctx->need_data_move) {
            self->state = NVMETR_ST_DATA_MOVE;
        } else {
            self->state = NVMETR_ST_SEND_RESP;
        }
        return JOB_WAITING;
    }

    case NVMETR_ST_DATA_MOVE: {
        int rc;
        if (ctx->fab_data) {
            if (ctx->data_move_is_write) {
                rc = mlx5_qp_post_rdma_write(ctx->cm.dev, &ctx->cm.rc_qp,
                                             (const void *)(uintptr_t)ctx->ctrl->fab_buf, ctx->ksgl_len,
                                             ctx->ksgl_addr, ctx->ksgl_key);
            } else {
                rc = mlx5_qp_post_rdma_read(ctx->cm.dev, &ctx->cm.rc_qp,
                                            (void *)(uintptr_t)ctx->ctrl->fab_buf, ctx->ksgl_len,
                                            ctx->ksgl_addr, ctx->ksgl_key);
            }
        } else if (ctx->data_move_is_write) {
            const volatile uint8_t *src;
            uint32_t len = ctx->ksgl_len;
            if (ctx->opcode == NVME_ADM_CMD_IDENTIFY) {
                src = nvmetr_id_buf(ctx->ctrl, ctx->id_sel);
                if (len > NVMET_RDMA_ID_BUF_LEN) len = NVMET_RDMA_ID_BUF_LEN;
            } else { // READ
                src = &ctx->ctrl->ram_disk[ctx->io_slba * NVMET_RDMA_LBA_SIZE];
            }
            rc = mlx5_qp_post_rdma_write(ctx->cm.dev, &ctx->cm.rc_qp, (const void *)(uintptr_t)src,
                                          len, ctx->ksgl_addr, ctx->ksgl_key);
        } else { // WRITE: ram_diskの該当位置へ直接RDMA_READで引き込む
            volatile uint8_t *dst = &ctx->ctrl->ram_disk[ctx->io_slba * NVMET_RDMA_LBA_SIZE];
            rc = mlx5_qp_post_rdma_read(ctx->cm.dev, &ctx->cm.rc_qp, (void *)(uintptr_t)dst,
                                         ctx->ksgl_len, ctx->ksgl_addr, ctx->ksgl_key);
        }
        if (rc != 0) {
            uart_printf("[!] nvmet-rdma: RDMA_WRITE/READ発行失敗\n");
            ctx->resp_status = NVMET_RDMA_SC_ERROR;
            self->state = NVMETR_ST_SEND_RESP;
            return JOB_WAITING;
        }
        ctx->deadline = timer_now();
        self->state = NVMETR_ST_WAIT_DATA_MOVE;
        return JOB_WAITING;
    }

    case NVMETR_ST_WAIT_DATA_MOVE: {
        int is_send = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe(ctx->cm.dev, &ctx->cm.rc_qp, &is_send, NULL, &synd);
        if (rc == 1 && is_send) {
            if (ctx->fab_data && !ctx->data_move_is_write) {
                /* admin の Connect / Authentication Send のデータが届いた。 */
                const uint8_t *d = (const uint8_t *)(uintptr_t)ctx->ctrl->fab_buf;
                if (ctx->fctype == NVME_FABRIC_FCTYPE_CONNECT) {
                    uint32_t atr = 0;
                    nvmet_pr_connect(&ctx->ctrl->pr, d, ctx->ctrl->ctrlr_id);   /* 先頭 16 バイトがホスト識別子 */
                    const uint16_t st = nvmet_auth_on_connect(&ctx->ctrl->auth, d + 512, &atr);
                    if (st != 0) {
                        ctx->resp_status = st;
                        ctx->resp_dw0 = 0;
                    } else {
                        ctx->resp_dw0 |= atr;
                        if (atr) uart_printf("[nvmet-rdma] 認証を要求 (ホスト %s)\n", ctx->ctrl->auth.hostnqn);
                    }
                } else {
                    ctx->resp_status = nvmet_auth_send(&ctx->ctrl->auth, ctx->cdw10, ctx->cdw11, d,
                                                       ctx->ksgl_len, NVMET_RDMA_SUBNQN);
                }
            } else if (!ctx->data_move_is_write) {
                dcache_invalidate_range(
                    (const void *)(uintptr_t)&ctx->ctrl->ram_disk[ctx->io_slba * NVMET_RDMA_LBA_SIZE],
                    ctx->ksgl_len);
            }
            self->state = NVMETR_ST_SEND_RESP;
            return JOB_WAITING;
        }
        if (rc < 0) {
            uart_printf("[!] nvmet-rdma: RDMA_WRITE/READ CQEエラー syndrome=0x%02x\n", synd);
            ctx->resp_status = NVMET_RDMA_SC_ERROR;
            self->state = NVMETR_ST_SEND_RESP;
            return JOB_WAITING;
        }
        if (timeout_ms(ctx->deadline, 3000u)) {
            uart_printf("[!] nvmet-rdma: RDMA_WRITE/READ完了待ちタイムアウト\n");
            ctx->resp_status = NVMET_RDMA_SC_ERROR;
            self->state = NVMETR_ST_SEND_RESP;
            return JOB_WAITING;
        }
        return JOB_WAITING;
    }

    case NVMETR_ST_SEND_RESP: {
        nvmetr_build_resp_capsule(ctx);
        if (mlx5_qp_post_send(ctx->cm.dev, &ctx->cm.rc_qp, (const void *)(uintptr_t)ctx->send_buf,
                              NVME_CQE_LEN) != 0) {
            uart_printf("[!] nvmet-rdma: 応答capsule送信失敗\n");
            ctx->failed = 1;
            return JOB_DONE;
        }
        ctx->deadline = timer_now();
        self->state = NVMETR_ST_WAIT_RESP_SENT;
        return JOB_WAITING;
    }

    case NVMETR_ST_WAIT_RESP_SENT: {
        int is_send = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe(ctx->cm.dev, &ctx->cm.rc_qp, &is_send, NULL, &synd);
        if (rc == 1 && is_send) {
            self->state = NVMETR_ST_POST_RECV; // 次のコマンドに備える
            return JOB_WAITING;
        }
        if (rc < 0) {
            uart_printf("[!] nvmet-rdma: 応答capsule CQEエラー syndrome=0x%02x\n", synd);
            ctx->failed = 1;
            return JOB_DONE;
        }
        if (timeout_ms(ctx->deadline, 3000u)) {
            uart_printf("[!] nvmet-rdma: 応答capsule送信完了待ちタイムアウト\n");
            ctx->failed = 1;
            return JOB_DONE;
        }
        return JOB_WAITING;
    }

    case NVMETR_ST_PIPELINE_SETUP: {
        for (unsigned i = 0; i < NVMET_RDMA_MAX_PENDING; i++) {
            ctx->pl.pending[i].cid = 0;
        }
        ctx->pl.rq_head = ctx->pl.rq_tail = 0;
        ctx->pl.sq_head = ctx->pl.sq_tail = 0;
        ctx->pl.rra_inflight = 0;
        /* **CM で合意した INITIATOR_DEPTH を超えないこと。** 相手はこの値を
         * max_dest_rd_atomic に設定しているので、超えた瞬間に
         * REMOTE_INVAL_REQ_ERR(syndrome=0x12)が返る。 */
        ctx->pl.rra_max = mlx5_qp_max_concurrent_rdma_read(ctx->cm.dev);
        if (ctx->cm.negotiated_initiator_depth != 0u &&
            ctx->pl.rra_max > (uint32_t)ctx->cm.negotiated_initiator_depth) {
            ctx->pl.rra_max = (uint32_t)ctx->cm.negotiated_initiator_depth;
        }
        if (ctx->pl.rra_max == 0) ctx->pl.rra_max = 1; // 念のための安全弁(0除算/永久停止防止)
        ctx->pl.rra_pending_head = ctx->pl.rra_pending_tail = 0;
        for (unsigned i = 0; i < NVMET_RDMA_MAX_PENDING; i++) {
            if (nvmetr_pl_post_recv_slot(ctx, i) != 0) {
                uart_printf("[!] nvmet-rdma pipeline: post_recv失敗(setup)\n");
                ctx->failed = 1;
                return JOB_DONE;
            }
        }
        ctx->cm.hold_rep = 0;   /* 受信を投稿し終えたので REP を送ってよい */
        uart_printf("[nvmet-rdma] パイプライン化ループ開始 (depth=%u queue_id=%u t=%uus)\n",
                    NVMET_RDMA_MAX_PENDING, ctx->queue_id, (unsigned)(timer_now() / 1000u));
        self->state = NVMETR_ST_PIPELINE_LOOP;
        return JOB_WAITING;
    }

    case NVMETR_ST_PIPELINE_LOOP: {
        /* ポーリング周期の計測用(`ts mode` に TS_MODE_HOTPATH を含めたときだけ記録)。
         * CQE を「消費した瞬間」しか記録しない既定の計装では、NIC が CQE を書いて
         * からこのループが気付くまでの空白が見えない。 */
        TS_HOT(TS_MK(TS_FILE_NVMET_RDMA, TS_FUNC_nvmet_rdma_job_step, 1u), 0u);
        if (nvmetr_check_gsi_disconnect(ctx, self)) {
            return ctx->failed ? JOB_DONE : JOB_WAITING;
        }
        /* **予約の通知はここで AER を完了させて知らせる。** 旗を立てるのは予約のコマンドを処理した
         * IO キューのジョブ(別のコア)で、admin の QP へ送るのはこのジョブだけ。 */
        if (ctx->queue_id == 0 && ctx->ctrl->aer_pending && ctx->ctrl->pr.aer_notify) {
            ctx->ctrl->pr.aer_notify = 0;
            if (nvmetr_aer_complete(ctx, NVME_AER_CSS | (NVME_AEN_RESV_LOG_AVAIL << 8) |
                                         (NVME_LOG_LID_RESERVATION << 16), 0) != 0) {
                ctx->failed = 1;
                return JOB_DONE;
            }
        }

        unsigned qi_stat = (ctx->queue_id <= NVMET_RDMA_IO_QUEUES)
                           ? (unsigned)ctx->queue_id : NVMET_RDMA_IO_QUEUES;
        unsigned recv_stat = 0;
        g_nvmetr_polls[qi_stat][0]++;

        for (unsigned iter = 0; iter < NVMET_RDMA_MAX_PENDING * 3u; iter++) {
            int is_send = 0;
            uint32_t recv_len = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(ctx->cm.dev, &ctx->cm.rc_qp, &is_send, &recv_len, &synd);
            if (rc == 0) break;
            if (rc < 0) {
                uint32_t hw_rq = 0, sw_rq = 0;
                uint16_t hw_sq = 0, sw_sq = 0;
                mlx5_qp_query_counters(ctx->cm.dev, &ctx->cm.rc_qp, &hw_rq, &sw_rq, &hw_sq, &sw_sq);
                uint8_t last_op = mlx5_qp_last_cqe_opcode(ctx->cm.dev, &ctx->cm.rc_qp);
                uart_printf("[!] nvmet-rdma pipeline: CQEエラー syndrome=0x%02x cqe_opcode=0x%x "
                            "rq_head=%u rq_tail=%u sq_head=%u sq_tail=%u hw_rq=%u sw_rq=%u hw_sq=%u sw_sq=%u "
                            "sq_pc=%u rq_pc=%u cq_cc=%u\n",
                            synd, last_op, ctx->pl.rq_head, ctx->pl.rq_tail, ctx->pl.sq_head, ctx->pl.sq_tail,
                            hw_rq, sw_rq, hw_sq, sw_sq,
                            ctx->cm.rc_qp.sq_pc, ctx->cm.rc_qp.rq_pc, ctx->cm.rc_qp.cq_cc);
                for (unsigned qi = ctx->pl.sq_head; qi != ctx->pl.sq_tail; qi++) {
                    nvmet_rdma_pl_sqop_t *op = &ctx->pl.sq_ops[qi % (NVMET_RDMA_MAX_PENDING * 2u)];
                    nvmet_rdma_pl_pending_t *pp = &ctx->pl.pending[op->slot];
                    uart_printf("  sq_ops[%u]: is_resp_send=%d slot=%u cid=%u opcode=0x%x "
                                "need_data_move=%d is_write=%d slba=%u ksgl_len=%u\n",
                                qi, op->is_resp_send, op->slot, pp->cid, pp->opcode,
                                pp->need_data_move, pp->data_move_is_write,
                                (unsigned)pp->io_slba, pp->ksgl_len);
                }
                if (ctx->queue_id == 0 && ctx->self_label != NULL) {
                    uart_printf("[!] nvmet-rdma: RC QPエラーを切断とみなし、次の接続を待ちます\n");
                    nvmetr_reset_admin_for_reconnect(ctx, self);
                    return ctx->failed ? JOB_DONE : JOB_WAITING;
                }
                ctx->failed = 1;
                return JOB_DONE;
            }

            if (!is_send) {
                if (ctx->pl.rq_head == ctx->pl.rq_tail) {
                    uart_printf("[!] nvmet-rdma pipeline: 予期しないRQ完了(未投稿分)\n");
                    ctx->failed = 1;
                    return JOB_DONE;
                }
                unsigned slot = ctx->pl.rq_order[ctx->pl.rq_head % NVMET_RDMA_MAX_PENDING];
                ctx->pl.rq_head++;
                recv_stat++;
                dcache_invalidate_range((const void *)(uintptr_t)ctx->pl.recv_bufs[slot], recv_len);
                nvmetr_parse_command(ctx, ctx->pl.recv_bufs[slot], &ctx->pl.pending[slot]);
                {
                    volatile ts_rdma_t ts_cmd = {0};
                    ts_cmd.rdma_op = TS_RDMA_OP_CMD_RECV;
                    ts_cmd.wqe_cqe_opcode = ctx->pl.pending[slot].opcode;
                    ts_cmd.qpn = ctx->cm.rc_qp.qpn;
                    ts_cmd.counter = ctx->cm.rc_qp.rq_pc;
                    ts_cmd.remote_addr = ctx->pl.pending[slot].cid;
                    ts_cmd.len = ctx->pl.pending[slot].ksgl_len;
                    ts_log_rdma(TS_MK(TS_FILE_NVMET_RDMA, TS_FUNC_nvmet_rdma_job_step, 0), &ts_cmd);
                }
                if (ctx->pl.pending[slot].data_inline && ctx->pl.pending[slot].stage &&
                    ctx->pl.pending[slot].resp_status == 0) {
                    /* in-capsule で届いた範囲の一覧・鍵・比較データ。その場で実行する。 */
                    nvmet_rdma_pl_pending_t *ip = &ctx->pl.pending[slot];
                    uint32_t need = 64u + ip->inline_off + ip->ksgl_len;
                    if (need > recv_len || 64u + ip->inline_off + ip->ksgl_len > NVMET_RDMA_MSG_MAX) {
                        uart_printf("[!] nvmet-rdma: in-capsuleデータが足りない(%u > %u)\n", need, recv_len);
                        ip->resp_status = NVMETR_SC_SGL_LEN_INVALID;
                    } else {
                        nvmetr_exec_staged(ctx, ip, &ctx->pl.recv_bufs[slot][64u + ip->inline_off], ip->ksgl_len);
                    }
                } else if (ctx->pl.pending[slot].data_inline &&
                    ctx->pl.pending[slot].resp_status == 0) {
                    /* データが capsule に載っている場合、RDMA_READ を挟まずに
                     * ここで RAM ディスクへ写して即座に応答できる。**これが
                     * 1 往復(実測 3.2us)の削減そのもの**。 */
                    nvmet_rdma_pl_pending_t *ip = &ctx->pl.pending[slot];
                    uint32_t need = 64u + ip->inline_off + ip->ksgl_len;
                    if (need > recv_len) {
                        uart_printf("[!] nvmet-rdma: in-capsuleデータが足りない(%u > %u)\n",
                                    need, recv_len);
                        ip->resp_status = NVMET_RDMA_SC_ERROR;
                    } else {
                        /* **バイト単位のループにしないこと。** このコピーは
                         * ポーリングループの中なので、4KB を 1 バイトずつ写すと
                         * 深さを上げたときに CQ を拾う手が止まる(実測で 4K
                         * qd=128 が 153k -> 16k IOPS まで落ちた)。 */
                        nvmetr_copy_in_capsule(&ctx->ctrl->ram_disk[ip->io_slba * NVMET_RDMA_LBA_SIZE],
                                               &ctx->pl.recv_bufs[slot][64u + ip->inline_off],
                                               ip->ksgl_len);
                    }
                }
                if (ctx->queue_id == 0 && nvmetr_admin_post_parse(ctx, slot)) {
                    /* Asynchronous Event Request を保留した(応答は送らない)。 */
                } else if (ctx->pl.pending[slot].need_data_move) {
                    int dm_rc = nvmetr_pl_start_data_move(ctx, slot);
                    if (dm_rc == -2) {
                        /* RDMA_WRITE は SQ に載ったのに応答 SEND を積めなかった。
                         * ここで応答を作り直すと二重に送ることになるので畳む。 */
                        uart_printf("[!] nvmet-rdma pipeline: 応答capsule送信失敗(RDMA_WRITE後)\n");
                        ctx->failed = 1;
                        return JOB_DONE;
                    }
                    if (dm_rc < 0) {
                        uart_printf("[!] nvmet-rdma pipeline: RDMA_WRITE/READ発行失敗\n");
                        ctx->pl.pending[slot].resp_status = NVMET_RDMA_SC_ERROR;
                        if (nvmetr_pl_send_response(ctx, slot) != 0) {
                            ctx->failed = 1;
                            return JOB_DONE;
                        }
                    }
                } else {
                    if (nvmetr_pl_send_response(ctx, slot) != 0) {
                        uart_printf("[!] nvmet-rdma pipeline: 応答capsule送信失敗\n");
                        ctx->failed = 1;
                        return JOB_DONE;
                    }
                }
            } else {
                if (ctx->pl.sq_head == ctx->pl.sq_tail) {
                    uart_printf("[!] nvmet-rdma pipeline: 予期しないSQ完了\n");
                    ctx->failed = 1;
                    return JOB_DONE;
                }
                nvmet_rdma_pl_sqop_t op = ctx->pl.sq_ops[ctx->pl.sq_head % (NVMET_RDMA_MAX_PENDING * 2u)];
                ctx->pl.sq_head++;
                if (!op.is_resp_send) {
                    /* RDMA_WRITE 完了 -> 応答は投稿済みなので何もしない。
                     * RDMA_READ 完了 -> ここで応答capsuleを送る。 */
                    if (ctx->pl.pending[op.slot].data_move_is_write) {
                        continue;   /* RDMA_WRITE。応答は発行済み */
                    }
                    if (ctx->pl.pending[op.slot].fab_data) {
                        /* admin の Connect / Authentication Send のデータが届いた。
                         * 処理して応答の中身を決めてから、下で応答を送る。 */
                        nvmet_rdma_pl_pending_t *fp = &ctx->pl.pending[op.slot];
                        const uint8_t *d = (const uint8_t *)(uintptr_t)ctx->ctrl->fab_buf;
                        if (fp->fctype == NVME_FABRIC_FCTYPE_CONNECT) {
                            uint32_t atr = 0;
                            nvmet_pr_connect(&ctx->ctrl->pr, d, ctx->ctrl->ctrlr_id);   /* 先頭 16 バイトがホスト識別子 */
                            const uint16_t st = nvmet_auth_on_connect(&ctx->ctrl->auth, d + 512, &atr);
                            if (st != 0) {
                                fp->resp_status = st;
                                fp->resp_dw0 = 0;
                            } else {
                                fp->resp_dw0 |= atr;
                                if (atr) {
                                    uart_printf("[nvmet-rdma] 認証を要求 (ホスト %s)\n",
                                                ctx->ctrl->auth.hostnqn);
                                }
                            }
                        } else {
                            fp->resp_status = nvmet_auth_send(&ctx->ctrl->auth, fp->cdw10, fp->cdw11, d,
                                                              fp->ksgl_len, NVMET_RDMA_SUBNQN);
                            nvmetr_after_auth(ctx);
                        }
                    }
                    if (ctx->pl.pending[op.slot].stage) {
                        /* 置き場にデータが届いた。Compare は引いた分を比べ、残りがあれば続きを引く
                         * (いま空いた RDMA_READ の枠をそのまま使う)。それ以外はここで実行する。 */
                        nvmet_rdma_pl_pending_t *sp = &ctx->pl.pending[op.slot];
                        const volatile uint8_t *sd = &ctx->pl.recv_bufs[op.slot][NVMET_RDMA_STAGE_OFF];
                        if (sp->opcode == NVME_IO_CMD_COMPARE) {
                            uint32_t chunk = sp->ksgl_len - sp->cmp_off;
                            if (chunk > NVMET_RDMA_INLINE_MAX) chunk = NVMET_RDMA_INLINE_MAX;
                            nvmetr_exec_staged(ctx, sp, sd, chunk);
                            sp->cmp_off += chunk;
                            if (sp->resp_status == 0 && sp->cmp_off < sp->ksgl_len) {
                                ctx->pl.rra_inflight--;
                                if (nvmetr_pl_issue_rdma_read(ctx, op.slot) == 0) continue;
                                ctx->pl.rra_inflight++;   /* 下で 1 つ返すので数を合わせる */
                                sp->resp_status = NVMET_RDMA_SC_ERROR;
                            }
                        } else {
                            nvmetr_exec_staged(ctx, sp, sd, sp->ksgl_len);
                        }
                    }
                    {
                        dcache_invalidate_range(
                            (const void *)(uintptr_t)&ctx->ctrl->ram_disk[
                                ctx->pl.pending[op.slot].io_slba * NVMET_RDMA_LBA_SIZE],
                            ctx->pl.pending[op.slot].ksgl_len);
                        ctx->pl.rra_inflight--;
                        if (ctx->pl.rra_pending_head != ctx->pl.rra_pending_tail) {
                            unsigned next_slot =
                                ctx->pl.rra_pending[ctx->pl.rra_pending_head % NVMET_RDMA_MAX_PENDING];
                            ctx->pl.rra_pending_head++;
                            if (nvmetr_pl_issue_rdma_read(ctx, next_slot) != 0) {
                                uart_printf("[!] nvmet-rdma pipeline: 保留RDMA_READ発行失敗\n");
                                ctx->pl.pending[next_slot].resp_status = NVMET_RDMA_SC_ERROR;
                                if (nvmetr_pl_send_response(ctx, next_slot) != 0) {
                                    ctx->failed = 1;
                                    return JOB_DONE;
                                }
                            }
                        }
                    }
                    if (nvmetr_pl_send_response(ctx, op.slot) != 0) {
                        uart_printf("[!] nvmet-rdma pipeline: 応答capsule送信失敗\n");
                        ctx->failed = 1;
                        return JOB_DONE;
                    }
                } else {
                    /* 応答capsule SEND完了 -> スロット解放、RECV WQE再投稿。 */
                    if (nvmetr_pl_post_recv_slot(ctx, op.slot) != 0) {
                        uart_printf("[!] nvmet-rdma pipeline: post_recv失敗(再投稿)\n");
                        ctx->failed = 1;
                        return JOB_DONE;
                    }
                }
            }
        }
        if (recv_stat == 0u) {
            g_nvmetr_empty[qi_stat][0]++;
        } else {
            g_nvmetr_cmds[qi_stat][0] += recv_stat;
        }
        return JOB_WAITING;
    }

    default:
        return JOB_DONE;
    }
}

/*=================================================================
 * 外部ホスト向けの常駐 NVMe-oF RDMA ターゲット。
 *
 * nvme_rdma.c の s_target_ctx(自作イニシエータとのループバック検証用)とは
 * 完全に独立したインスタンスで、シェルの nvmetrdma コマンドから起動する。
 * 相手が Linux ホストのときはこちらを使う。
 *
 * この一式は初期コミット時点で存在したが、シェルからの入口が無かったため
 * 「未到達コード」として一括削除されていた(8d79bb2)。2 ノード構成で
 * 「自作ターゲット <- Linux イニシエータ」を測れるようにするため復活させた。
 * ===============================================================*/
/*=================================================================
 * 常駐ターゲットの RAM ディスク(256MB)を COHERENT DMA アリーナから確保する。
 * nvme_rdma.c の nvmer_ramdisk_slot1() と同じ作りで、スロットだけ分ける
 * (ループバック用ターゲットと同時に起動しても衝突しない)。
 * ===============================================================*/
static volatile uint8_t *nvmetr_ramdisk_slot0(void)
{
    static volatile uint8_t *s_rd0 = 0;
    if (s_rd0 == 0) {
        s_rd0 = (volatile uint8_t *)dma_alloc(NVMET_RDMA_RAMDISK_SLOT_SIZE,
                                              0x200000ULL, DMA_COHERENT).cpu;
    }
    return s_rd0;
}

/* **既定は 3 コアへ分散。** 1 コアに 4 本の IO キューを載せると、コアの
 * 3/4 が空の CQ を覗くだけで消える(実測: 1 tick 約 93ns x 4000万回 =
 * 5 秒中 3.7 秒)。**その結果 512B write 4 キューが 641〜758k で徘徊し、
 * kernel(772k、ばらつき ±1.8%)に負けていた。** 3 コアへ散らすと 801k で
 * 安定して kernel を上回る。`rdmacores 1` が従来の挙動(陰性対照)。
 *
 * **キュー本数が少ないときの割り当ては変わらない**(idx%ncores は idx が
 * ncores 未満なら idx そのもの)ので、1〜3 本のときの退行はありえない。 */
volatile uint32_t g_nvmet_rdma_cores = 3u;


/*=================================================================
 * IO キュー idx 番の CM acceptor を立てる。
 *
 * **GSI は admin のものをポインタのまま共有する**(値コピーにすると
 * sq_pc/rq_pc/cq_cc が二重管理になり、REP が「送ったつもりでワイヤに
 * 出ない」という静かな失敗を起こす。実機で踏んだ本物のバグ)。
 * **RC QP の添字は idx+1**(0 番は admin が使う)。
 *
 * 引数:
 *   admin_ctx - admin キューの ctx(GSI とコントローラ状態の供給元)
 *   idx       - IO キュー番号(0 起点)
 * コール元:
 *   nvmetr_on_admin_established(), nvmetr_on_io_established()
 * ===============================================================*/
static void nvmetr_spawn_io_queue(nvmet_rdma_ctx_t *admin_ctx, unsigned idx)
{
    if (idx >= NVMET_RDMA_IO_QUEUES) return;
    nvmet_rdma_ctx_t *io = &s_standalone_io_ctx[idx];

    for (uint32_t i = 0; i < sizeof(*io); i++) ((uint8_t *)io)[i] = 0;
    dcache_clean_range((const void *)io, sizeof(*io));

    static const uint8_t dummy_mac[6] = {0, 0, 0, 0, 0, 0};
    rdma_cm_fill_addr(&io->cm, admin_ctx->cm.dev, s_standalone_self_label,
                      "__no_such_net_ctx__", 0u, 0u, dummy_mac, s_standalone_peer_mac);
    /* fill_addr のゼロクリアの「後」に共有すること(先だと消える)。 */
    io->cm.gsi_qp      = admin_ctx->cm.gsi_qp;
    io->cm.reuse_gsi   = 1;
    io->cm.rc_qp_index = (uint8_t)(idx + 1u);
    io->cm.skip_ping   = 1;
    io->cm.is_active   = 0;
    io->ctrl           = admin_ctx->ctrl;  /* コントローラ状態は共有 */
    io->queue_id       = (uint16_t)(idx + 1u);
    io->pipeline_enabled = 1;
    io->on_established = nvmetr_on_io_established;

    job_t *io_job = job_spawn(nvmet_rdma_job_step, io, "nvmet-rdma-io");
    if (!io_job) {
        uart_printf("[!] nvmet-rdma: IOキュー%u用ジョブ生成失敗(ジョブテーブル満杯)\n",
                    idx + 1u);
        return;
    }
    io_job->state = NVMETR_ST_CM_SPAWN;
    /* **SPDK の poll group と同じ考え方で round-robin に配る。**
     * core0 はシェルなので使わない。RC QP の WQE/CQ はキューごとに
     * 独立している(rcqp[])ので、コアをまたいで共有するものは無い。 */
    uint32_t ncores = g_nvmet_rdma_cores;
    if (ncores == 0u) ncores = 1u;
    unsigned core = 1u + (idx % ncores);
    job_pin_to_core(io_job, core);
    s_standalone_io_spawned = (int)idx + 1;
    uart_printf("[nvmet-rdma] IOキュー%u のCM listenerを起動しました(core%u、GSIはadminと共有)\n",
                idx + 1u, core);
}

/*=================================================================
 * IO キューだけが DREQ で切られた枠を、同じ枠の受け皿に戻す(IO キューのジョブ自身が呼ぶ)。
 * RC QP を捨て、CM コンテキストを作り直して CM_SPAWN からやり直す。ctx を別のジョブから
 * ゼロにしないこと(動いているジョブの ctx を消すことになる)。
 * ===============================================================*/
static void nvmetr_requeue_io(nvmet_rdma_ctx_t *ctx, job_t *self)
{
    mlx5_dev_t *dev   = ctx->cm.dev;
    mlx5_qp_t  *gsi   = ctx->cm.gsi_qp;
    uint8_t     rcidx = ctx->cm.rc_qp_index;
    nvmetr_destroy_qp_if_valid(dev, &ctx->cm.rc_qp);
    static const uint8_t dummy_mac[6] = {0, 0, 0, 0, 0, 0};
    rdma_cm_fill_addr(&ctx->cm, dev, s_standalone_self_label, "__no_such_net_ctx__", 0u, 0u,
                      dummy_mac, s_standalone_peer_mac);
    ctx->cm.gsi_qp      = gsi;
    ctx->cm.reuse_gsi   = 1;
    ctx->cm.rc_qp_index = rcidx;
    ctx->cm.skip_ping   = 1;
    ctx->cm.is_active   = 0;
    ctx->established = 0;
    ctx->failed      = 0;
    self->state = NVMETR_ST_CM_SPAWN;
    uart_printf("[nvmet-rdma] IOキュー%u をホストが切ったので、同じ枠の受け皿に戻します\n", ctx->queue_id);
}

/*=================================================================
 * IO キューが確立したら次の 1 本の acceptor を立てる。
 *
 * 確立までの間に来た次の REQ は GSI の待ち行列で待っている(rdma_cm.c の
 * cm_gsi_take())。ホストが要求した本数(Set Features で合意)まで立てる。
 * ===============================================================*/
static void nvmetr_on_io_established(nvmet_rdma_ctx_t *self)
{
    if (!s_standalone_admin_ctx_for_io) return;
    unsigned idx = (unsigned)(self - &s_standalone_io_ctx[0]);
    uint32_t granted = self->ctrl ? self->ctrl->io_queues_granted : 1u;
    if (granted == 0u) granted = 1u;
    /* 作り直した枠(requeue)がもう一度確立したときは、次の枠が既に立っているので立て直さない
     * (立て直すと使用中の枠の ctx をゼロにする)。 */
    if (idx + 1u < granted && idx + 1u < NVMET_RDMA_IO_QUEUES && (int)(idx + 1u) >= s_standalone_io_spawned) {
        nvmetr_spawn_io_queue(s_standalone_admin_ctx_for_io, idx + 1u);
    }
}

/*=================================================================
 * admin キューが established になった直後に 1 度だけ呼ばれる。IO キュー用の
 * 2 本目の CM listener を立てる。
 *
 * GSI(QP1)は 1 PF に 1 つしか置けないので、admin が確立済みのものを
 * ポインタのまま共有する(reuse_gsi)。値コピーにすると sq_pc/rq_pc/cq_cc が
 * 二重管理になり、IO キューの REP が「送ったつもりでワイヤに出ない」という
 * 静かな失敗を起こす(実機で踏んだ本物のバグ)。
 * ===============================================================*/
static void nvmetr_on_admin_established(nvmet_rdma_ctx_t *admin_ctx)
{
    if (!admin_ctx->enable_io_queue || s_standalone_io_spawned > 0) return;
    s_standalone_admin_ctx_for_io = admin_ctx;
    /* **認証を求めるなら、IO キューの受け皿は認証が済んでから立てる。**
     * 先に立てると、認証に失敗したホストが繋ぎ直してきたときの admin 用の REQ を
     * IO 側の受け皿が受け取り、Connect(qid=0)が「認証前」として拒否される
     * (段階 C で踏んだ。TCP で admin が畳まれずに SYN を捨てたのと同じ系統)。 */
    if (nvmet_auth_enabled()) return;
    nvmetr_spawn_io_queue(admin_ctx, 0);
}

/* 認証が済んだら IO キューの受け皿を立てる(nvmetr_on_admin_established() の続き)。 */
static void nvmetr_after_auth(nvmet_rdma_ctx_t *ctx)
{
    if (ctx->queue_id != 0 || !ctx->enable_io_queue || s_standalone_io_spawned > 0) return;
    const nvmet_auth_sess_t *a = &ctx->ctrl->auth;
    if (!a->required || !a->authenticated || a->failed) return;
    s_standalone_admin_ctx_for_io = ctx;
    nvmetr_spawn_io_queue(ctx, 0);
}

/*=================================================================
 * admin キューの切断を検出したときに 1 度だけ呼ばれる。NVMe-oF の意味論上、
 * admin が切れれば同じコントローラの IO キューも意味を失うので道連れにする。
 * GSI は admin 側が破棄するので、ここでは IO 自身の RC QP だけ返す。
 * ===============================================================*/
static void nvmetr_on_admin_disconnected(nvmet_rdma_ctx_t *admin_ctx)
{
    /* 保留中の AER はセッションと一緒に捨て、予約の通知先から外す(登録はホストに付くので残す)。 */
    admin_ctx->ctrl->aer_pending = 0;
    nvmet_pr_session_reset(&admin_ctx->ctrl->pr);
    if (!s_standalone_io_spawned) return;
    for (int k = 0; k < s_standalone_io_spawned; k++) {
        /* まだ REQ を待っている IO キューの受け皿(ホストが張る前に切った等)も止める。残すと
         * 次の接続の REQ を横取りする。**QP はここで壊さない** -- IO キューのジョブは別のコアで回って
         * いることがあるので、止まるときに自分で壊す(nvmet_rdma_job_step() の入口)。
         * cm は ctx の先頭なので、この取り消しで IO キューのジョブと受け皿の CM ジョブの両方が止まる。 */
        s_standalone_io_ctx[k].stop_requested = 1;
        job_cancel_by_ctx(&s_standalone_io_ctx[k].cm);
    }
    s_standalone_io_spawned = 0;
    uart_printf("[nvmet-rdma] IOキューも道連れに終了させます\n");
}

/*=================================================================
 * 常駐ターゲットを起動する(シェルの nvmetrdma コマンド)。
 *
 * 引数:
 *   dev        - 待ち受けるポートの mlx5 デバイス
 *   self_label - その netif 名("mlx5-pf1" 等)
 *   peer_mac   - 相手の MAC。IBTA の CM メッセージに MAC は含まれないので、
 *                REP を返す AV に使う値はここで渡すしかない(NULL ならゼロ)。
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void nvmet_rdma_run_standalone(mlx5_dev_t *dev, const char *self_label, const uint8_t peer_mac[6],
                               unsigned inst, unsigned acore)
{
    if (inst >= NVMETR_INSTANCES) return;
    s_nr = &s_nr_inst[inst];
    if (s_standalone_resident && !s_standalone_ctx.failed &&
        s_standalone_resident_generation == dev->bringup_generation) {
        uart_printf("[nvmet-rdma] 既に%sで稼働中です(接続待ち、または処理中)\n", self_label);
        return;
    }
    if (s_standalone_resident) {
        /* 前回のジョブを確実に止めてから作り直す。止めずに spawn すると
         * 同一 ctx を 2 つのジョブが触る(RDMA CM の segfault と同型)。 */
        s_standalone_ctx.stop_requested = 1;
        for (int k = 0; k < s_standalone_io_spawned; k++) s_standalone_io_ctx[k].stop_requested = 1;
        job_cancel_by_ctx(&s_standalone_ctx.cm);
        for (unsigned k = 0; k < NVMET_RDMA_IO_QUEUES; k++) job_cancel_by_ctx(&s_standalone_io_ctx[k].cm);
        uint64_t t0 = timer_now();
        while (!timeout_ms(t0, 2000u)) job_scheduler_tick();
        for (int k = 0; k < s_standalone_io_spawned; k++) {
            nvmetr_destroy_qp_if_valid(s_standalone_io_ctx[k].cm.dev,
                                       &s_standalone_io_ctx[k].cm.rc_qp);
        }
        nvmetr_destroy_qp_if_valid(s_standalone_ctx.cm.dev, &s_standalone_ctx.cm.rc_qp);
        nvmetr_destroy_qp_if_valid(s_standalone_ctx.cm.dev, s_standalone_ctx.cm.gsi_qp);
        s_standalone_resident   = 0;
        s_standalone_io_spawned = 0;
    }

    for (uint32_t i = 0; i < sizeof(s_standalone_ctx); i++)  ((uint8_t *)&s_standalone_ctx)[i] = 0;
    for (uint32_t i = 0; i < sizeof(s_standalone_ctrl); i++) ((uint8_t *)&s_standalone_ctrl)[i] = 0;
    /* 上のゼロクリアは非 volatile 書き込みなので、recv_buf/id_ctrl/id_ns
     * (DMA 宛先)にダーティなキャッシュラインが残る。最初の RECV を投稿する
     * 前に必ずクリーンしておく。 */
    dcache_clean_range((const void *)&s_standalone_ctx, sizeof(s_standalone_ctx));
    dcache_clean_range((const void *)&s_standalone_ctrl, sizeof(s_standalone_ctrl));

    static const uint8_t dummy_mac[6] = {0, 0, 0, 0, 0, 0};
    const uint8_t *pm = (peer_mac != NULL) ? peer_mac : dummy_mac;
    for (unsigned i = 0; i < 6; i++) s_standalone_peer_mac[i] = pm[i];
    s_standalone_self_label = self_label;

    rdma_cm_fill_addr(&s_standalone_ctx.cm, dev, self_label, "__no_such_net_ctx__",
                      0u, 0u, dummy_mac, pm);
    s_standalone_ctx.ctrl             = &s_standalone_ctrl;
    /* **2 つの組は同じサブシステムの別のコントローラ**なので cntlid を分ける(Linux は同じ
     * サブシステムで cntlid が重なると 2 本目を拒む)。記憶域(RAM ディスク)は共有する。 */
    s_standalone_ctrl.cntlid_cfg      = (uint16_t)(inst + 1u);
    s_standalone_ctrl.ram_disk        = nvmetr_ramdisk_slot0();
    s_standalone_ctrl.start_tick      = timer_now();
    /* 予約は 2 つの組で共有する(RAM ディスクが同じ)。TCP の nvmet.c とは別のドメイン。 */
    nvmet_pr_attach(&s_standalone_ctrl.pr, NVMET_PR_DOM_RDMA);
    s_standalone_ctx.pipeline_enabled = 1;
    s_standalone_ctx.enable_io_queue  = 1;
    s_standalone_ctx.on_established   = nvmetr_on_admin_established;
    s_standalone_ctx.on_disconnected  = nvmetr_on_admin_disconnected;
    s_standalone_ctx.self_label       = self_label;
    for (unsigned i = 0; i < 6; i++) s_standalone_ctx.peer_mac_fallback[i] = pm[i];

    job_t *job = job_spawn(nvmet_rdma_job_step, &s_standalone_ctx, "nvmet-rdma-standalone");
    if (!job) {
        uart_printf("[!] nvmet-rdma: ジョブテーブル満杯\n");
        return;
    }
    job->state = NVMETR_ST_CM_SPAWN;
    /* admin は呼ぶ側が決めたコア(その PF の受信を受け持つコア。pf1 は core1、2 ポートの pf0 は
     * core2、`twoport on 1core` なら pf0 も core1)で回す。 */
    if (acore < 1u || acore > 2u) acore = 1u;
    if ((acore == 1u ? smp_boot_core1() : smp_boot_core2()) == 0) job_pin_to_core(job, acore);
    else uart_printf("[!] nvmet-rdma: core%u起動に失敗、core0のまま動作します\n", acore);

    /* **IO キューを散らす先のコアは、キューを立てる前に起こしておく。**
     * 起きていないコアへ pin すると、そのジョブは誰にも回されず黙って
     * 止まる(接続はするが 1 コマンドも進まない、という形で出る)。
     * 起動に失敗したら分散数をそのぶん下げる。 */
    while (g_nvmet_rdma_cores >= 2u && smp_boot_cores_upto(g_nvmet_rdma_cores) != 0) {
        uart_printf("[!] nvmet-rdma: core1..core%u の起動に失敗、分散を %u コアへ下げます\n",
                    (unsigned)g_nvmet_rdma_cores, (unsigned)g_nvmet_rdma_cores - 1u);
        g_nvmet_rdma_cores--;
    }

    s_standalone_resident            = 1;
    s_standalone_resident_generation = dev->bringup_generation;
    uart_printf("[nvmet-rdma] %s で常駐ターゲットを開始しました(外部ホストの接続待ち)\n",
                self_label);
}
