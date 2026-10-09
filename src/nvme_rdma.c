#include "nvme_rdma.h"
#include "net.h"
#include "nvme_types.h"
#include "uart.h"
#include "timer.h"
#include "cache.h"
#include "job.h"
#include "nvmet_rdma.h"
#include "smp.h"
#include "platform.h"

/*=================================================================
 * ループバック検証用 RAM ディスク(インスタンス 1)を COHERENT DMA アリーナ
 * から初回だけ確保して返す。
 *
 * 戻り値:
 *   RAM ディスク先頭
 * コール元:
 *   nvme_rdma_run_bench()
 * ===============================================================*/
static volatile uint8_t *nvmer_ramdisk_slot1(void)
{
    static volatile uint8_t *s_rd1 = 0;
    if (s_rd1 == 0) {
        s_rd1 = (volatile uint8_t *)dma_alloc(NVMET_RDMA_RAMDISK_SLOT_SIZE,
                                              0x200000ULL, DMA_COHERENT).cpu;
    }
    return s_rd1;
}

/* IO キューの hsqsize(0's based で送る)。admin は RDMA_CM_DEFAULT_HSQSIZE(31)
 * のまま -- **相手は admin を NVME_AQ_DEPTH で上限判定する**。 */
/* IO キューの hsqsize / sqsize(どちらも 0's based で送る)。
 * **Linux の nvmet-rdma は MQES=127(= 128 エントリ)** なので 128 を超えられない
 * (nvmet-tcp は NVMET_QUEUE_SIZE=1024 由来でずっと大きい)。超えると
 * Fabrics Connect が "sqsize N is larger than MQES supported 127" で落ちる。
 * admin は RDMA_CM_DEFAULT_HSQSIZE(31)のまま -- 相手は admin を
 * NVME_AQ_DEPTH で別に上限判定する。 */
#define NVME_RDMA_QSIZE               128u

/* 外部ホストのターゲット設定。nvmer_build_connect() が subnqn を、
 * nvme_rdma_run_bench() が宛先を見るので、両方より前に置く。 */
static nvme_rdma_remote_t s_remote;

/* Identify Namespace の値を手で上書きする(0=上書きしない)。 */
static uint32_t s_ns_ovr_lba_size;
static uint64_t s_ns_ovr_nsze;

void nvme_rdma_set_ns_override(uint32_t lba_size, uint64_t nsze)
{
    s_ns_ovr_lba_size = lba_size;
    s_ns_ovr_nsze = nsze;
}

void nvme_rdma_get_ns_override(uint32_t *lba_size, uint64_t *nsze)
{
    if (lba_size) *lba_size = s_ns_ovr_lba_size;
    if (nsze) *nsze = s_ns_ovr_nsze;
}
#define NVME_RDMA_CTRL_READY_POLL_MAX 20u
#define NVME_RDMA_CTRL_READY_POLL_MS 100u
#define NVME_RDMA_CMD_TIMEOUT_MS    5000u

static const uint8_t NVME_RDMA_HOST_ID[16] = {
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
};
#define NVME_RDMA_HOST_NQN "nqn.2014-08.org.nvmexpress:uuid:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf"

/* `incapsule off` で in-capsule write を止める(A/B 用、TCP 側と共通の操作)。 */
static int s_incapsule_off;

void nvme_rdma_set_incapsule_disable(int off) { s_incapsule_off = off ? 1 : 0; }
uint32_t nvme_rdma_icdsz(void);

static void nvmer_zero_v(volatile uint8_t *p, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) p[i] = 0;
}

static void nvmer_copy_str_v(volatile uint8_t *dst, uint32_t field_len, const char *src)
{
    uint32_t i = 0;
    while (src[i] != '\0' && i < field_len) {
        dst[i] = (uint8_t)src[i];
        i++;
    }
}

/*=================================================================
 * いまコマンドを流すべき QP を返す。IO キューが確立していれば
 * そちら、まだなら admin キュー。**mkey も QP ごとに違う**(PD が別)ので、
 * keyed SGL に入れる鍵もここから取ること。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * 戻り値:
 *   使うべき QP
 * コール元:
 *   nvmer_build_*(), nvmer_post_send/recv(), nvmer_wait_exec()
 * ===============================================================*/
static mlx5_qp_t *nvmer_qp(nvme_rdma_ctx_t *ctx)
{
    return ctx->io_queue_ready ? &ctx->io_cm.rc_qp : &ctx->cm.rc_qp;
}

/*=================================================================
 * Keyed SGL Data Block descriptor(16 バイト)を SQE の dptr へ書く。
 * addr/length/key/type=0x40 の順で、length は 3 バイト LE。
 *
 * 引数:
 *   dptr - 書き込み先(SQE 内 offset 24)
 *   addr - ローカルバッファの IOVA
 *   len  - 転送バイト数
 *   key  - 自分の mkey(相手がこれを使って RDMA する)
 * コール元:
 *   nvmer_build_connect(), nvmer_build_prop_set/get(),
 *   nvmer_build_identify(), nvmer_build_io_ex()
 * ===============================================================*/
static void nvmer_set_ksgl(volatile uint8_t *dptr, uint64_t addr, uint32_t len, uint32_t key)
{
    wr64le(&dptr[0], addr);
    dptr[8]  = (uint8_t)len;
    dptr[9]  = (uint8_t)(len >> 8);
    dptr[10] = (uint8_t)(len >> 16);
    dptr[11] = (uint8_t)key;
    dptr[12] = (uint8_t)(key >> 8);
    dptr[13] = (uint8_t)(key >> 16);
    dptr[14] = (uint8_t)(key >> 24);
    dptr[15] = (uint8_t)NVME_SGL_TYPE_KEYED_DATA_BLOCK;
}

/*=================================================================
 * in-capsule 用の SGL descriptor(Data Block + Offset)を書く。
 * **keyed SGL と形が違う** -- 長さ欄が 3 バイトではなく 4 バイトで、
 * アドレス欄には相手が広告した ICDOFF(こちらは 0 のみ扱う)が入る。
 *
 * 引数:
 *   dptr - 書き込み先(SQE 内 offset 24)
 *   len  - capsule に載せるバイト数
 * コール元:
 *   nvmer_build_io_ex()
 * ===============================================================*/
static void nvmer_set_inline_sgl(volatile uint8_t *dptr, uint32_t len)
{
    wr64le(&dptr[0], 0u);      /* ICDOFF。相手が非 0 なら in-capsule は使わない */
    wr32le(&dptr[8], len);
    dptr[12] = 0; dptr[13] = 0; dptr[14] = 0;
    dptr[15] = 0x01u;          /* Data Block(0x0)+ Offset(0x1) */
}

/*=================================================================
 * このコマンドを in-capsule で送るか判定する。Linux の nvme_rdma_map_data()
 * と同じ条件で、**IO キューの write だけ**が対象(admin キューの RECV は
 * 64 バイト 1 本しか出ていないので、載せると相手が畳む)。
 *
 * 引数:
 *   ctx / opcode / total_len - コンテキストとコマンド種別、データ長
 * 戻り値:
 *   1=in-capsule で送る、0=keyed SGL
 * コール元:
 *   nvmer_build_io_ex()
 * ===============================================================*/
static int nvmer_use_inline(nvme_rdma_ctx_t *ctx, uint8_t opcode, uint32_t total_len)
{
    if (s_incapsule_off) return 0;
    if (opcode != (uint8_t)NVME_IO_CMD_WRITE) return 0;
    if (!ctx->io_queue_ready) return 0;
    if (ctx->icdsz == 0u || total_len == 0u || total_len > ctx->icdsz) return 0;
    return 1;
}

/*=================================================================
 * Fabrics Connect capsule を組み立てる。
 *
 * **connect data(1024B)は in-capsule で送ってはいけない。**
 * Linux の nvmet_rdma は admin キューの RECV に SGE を 1 本
 * (= nvme_command の 64 バイトぶん)しか出さないので
 * (drivers/nvme/target/rdma.c nvmet_rdma_alloc_cmd() の
 *  `c->wr.num_sge = admin ? 1 : ...`)、64 バイトを超える capsule は
 * **local length error** で捨てられ、相手はそのまま接続を畳む。
 * Linux のホスト側も対称で、in-capsule を使うのは
 * `nvme_rdma_queue_idx(queue) != 0`、つまり IO キューだけ
 * (drivers/nvme/host/rdma.c nvme_rdma_map_data())。
 *
 * したがって data は keyed SGL で指し、相手に RDMA_READ させる。
 * 自作ターゲットは connect data を読まない(cntlid を返すだけ)ので、
 * この変更で従来の経路も壊れない。
 *
 * 引数:
 *   ctx   - 送信バッファを持つ initiator コンテキスト
 *   qid   - キュー ID(0=admin、1=IO)
 *   subnqn- 接続先サブシステム NQN
 * 戻り値:
   送信すべき合計バイト数(SQE の 64 のみ。data は相手が RDMA_READ する)
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static uint32_t nvmer_build_connect(nvme_rdma_ctx_t *ctx, uint16_t qid, const char *subnqn)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u + 1024u);
    wr32le(&b[0], NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], NVME_FABRIC_FCTYPE_CONNECT);
    nvmer_set_ksgl(&b[24], mlx5_dma_addr((const void *)(uintptr_t)&b[64]), 1024u,
                   nvmer_qp(ctx)->mkey);
    wr32le(&b[40], (uint32_t)qid << 16);
    wr32le(&b[44], (uint32_t)(NVME_RDMA_QSIZE - 1) & 0xFFFFu);
    wr32le(&b[48], 0);

    volatile uint8_t *cd = &b[64];
    for (unsigned i = 0; i < 16; i++) cd[i] = NVME_RDMA_HOST_ID[i];
    /* cntlid: admin キューは 0xFFFF(dynamic)、IO キューは admin の
     * Connect 応答でもらった値。**違うと相手はどのコントローラの
     * キューか判別できず Connect Invalid Parameters で落とす。** */
    wr16le(&cd[16], (qid == 0u) ? 0xFFFFu : ctx->cntlid);
    nvmer_copy_str_v(&cd[256], 256u, subnqn);
    nvmer_copy_str_v(&cd[512], 256u, NVME_RDMA_HOST_NQN);
    /* **送るのは SQE の 64 バイトだけ。** data は b[64..1087] に置いたまま
     * にして、相手が keyed SGL を使って RDMA_READ で取りに来る。 */
    return 64u;
}

/*=================================================================
 * Authentication Send(fctype 0x05)/ Receive(0x06)の capsule。
 * admin キューは in-capsule を使えない(相手の RECV が 64 バイト)ので、
 * 送るデータは send_buf[64..] を keyed SGL で相手に RDMA_READ させ、
 * 受け取るデータは id_ns へ RDMA_WRITE してもらう。
 * ===============================================================*/
enum { NVMER_AUTH_NEG = 0, NVMER_AUTH_CHAL, NVMER_AUTH_REPLY, NVMER_AUTH_RESULT, NVMER_AUTH_S2 };

static uint32_t nvmer_build_auth(nvme_rdma_ctx_t *ctx, int send, uint32_t len)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], send ? NVME_FABRIC_FCTYPE_AUTH_SEND : NVME_FABRIC_FCTYPE_AUTH_RECV);
    if (send) {
        nvmer_set_ksgl(&b[24], mlx5_dma_addr((const void *)(uintptr_t)&b[64]), len, nvmer_qp(ctx)->mkey);
    } else {
        nvmer_set_ksgl(&b[24], mlx5_dma_addr((const void *)(uintptr_t)ctx->id_ns), len, nvmer_qp(ctx)->mkey);
    }
    wr32le(&b[40], NVME_AUTH_CDW10);
    wr32le(&b[44], len);
    return 64u;
}

/*=================================================================
 * Fabrics Property Set capsule を組み立てる(CC レジスタ書き込み用)。
 *
 * 引数:
 *   ctx    - initiator コンテキスト
 *   offset - プロパティのオフセット(CC=0x14 等)
 *   value  - 書き込む値
 * 戻り値:
 *   送信すべきバイト数
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static uint32_t nvmer_build_prop_set(nvme_rdma_ctx_t *ctx, uint32_t offset, uint64_t value)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], NVME_FABRIC_FCTYPE_PROPERTY_SET);
    nvmer_set_ksgl(&b[24], 0, 0, 0);
    wr32le(&b[40], 0u); /* attrib=0 */
    wr32le(&b[44], offset);
    wr32le(&b[48], (uint32_t)(value & 0xFFFFFFFFu));
    wr32le(&b[52], (uint32_t)(value >> 32));
    return 64u;
}

/*=================================================================
 * Fabrics Property Get capsule を組み立てる(CSTS レジスタ読み出し用)。
 *
 * 引数:
 *   ctx    - initiator コンテキスト
 *   offset - プロパティのオフセット(CSTS=0x1c 等)
 * 戻り値:
 *   送信すべきバイト数
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static uint32_t nvmer_build_prop_get(nvme_rdma_ctx_t *ctx, uint32_t offset)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], NVME_FABRIC_FCTYPE_PROPERTY_GET);
    nvmer_set_ksgl(&b[24], 0, 0, 0);
    wr32le(&b[40], 0u);
    wr32le(&b[44], offset);
    return 64u;
}

/*=================================================================
 * Identify コマンドを組み立てる。応答データはターゲットが RDMA_WRITE で
 * 書き込むので、Keyed SGL で受信先バッファを相手へ開示する。
 *
 * 引数:
 *   ctx  - initiator コンテキスト
 *   cns  - Identify の CNS 値(1=Controller、0=Namespace)
 *   nsid - 名前空間 ID
 *   buf / buf_len - 応答の受信先
 * 戻り値:
 *   送信すべきバイト数
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static uint32_t nvmer_build_identify(nvme_rdma_ctx_t *ctx, uint8_t cns, uint32_t nsid,
                                     volatile uint8_t *dest, uint32_t dest_len)
{
    volatile uint8_t *b = ctx->send_buf;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], NVME_ADM_CMD_IDENTIFY | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], ctx->cur_cid);
    wr32le(&b[4], nsid);
    nvmer_set_ksgl(&b[24], mlx5_dma_addr((const void *)(uintptr_t)dest), dest_len, nvmer_qp(ctx)->mkey);
    wr32le(&b[40], (uint32_t)cns);
    uart_printf("\n");
    return 64u;
}

/*=================================================================
 * Read/Write コマンドを、出力先バッファと cid を明示して組み立てる。
 * パイプライン化では複数コマンドが同時に in-flight になるため、
 * コンテキスト共有の単一バッファではなくスロット別バッファを使う。
 *
 * 引数:
 *   ctx    - initiator コンテキスト
 *   out    - この SQE を書き込む先
 *   cid    - このコマンドの id
 *   opcode - 0x01=write / 0x02=read
 *   nsid / slba / nlb - 対象名前空間と LBA 範囲
 *   data   - データバッファ(Keyed SGL で相手へ開示する)
 * 戻り値:
 *   送信すべきバイト数
 * コール元:
 *   nvmer_build_io(), nvme_rdma_connect_job_step()
 * ===============================================================*/
static uint32_t nvmer_build_io_ex(nvme_rdma_ctx_t *ctx, volatile uint8_t *out, uint16_t cid,
                                  uint8_t opcode, uint32_t nsid, uint64_t slba,
                                  uint32_t nlb, volatile uint8_t *buf, uint32_t total_len)
{
    volatile uint8_t *b = out;
    nvmer_zero_v(b, 64u);
    wr32le(&b[0], (uint32_t)opcode | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr16le(&b[2], cid);
    wr32le(&b[4], nsid);
    if (nvmer_use_inline(ctx, opcode, total_len)) {
        nvmer_set_inline_sgl(&b[24], total_len);
    } else {
        nvmer_set_ksgl(&b[24], mlx5_dma_addr((const void *)(uintptr_t)buf), total_len, nvmer_qp(ctx)->mkey);
    }
    wr32le(&b[40], (uint32_t)(slba & 0xFFFFFFFFu));
    wr32le(&b[44], (uint32_t)(slba >> 32));
    wr32le(&b[48], (uint32_t)(nlb - 1u) & 0xFFFFu);
    return 64u;
}

/*=================================================================
 * ベンチのコマンドごとに開始 LBA を nlb ずつ進め、名前空間の終端でラップ
 * する(fio のシーケンシャルアクセスと条件を揃えるため)。
 *
 * 引数:
 *   ctx - initiator コンテキスト(現在位置を保持)
 *   nlb - 1 コマンドのブロック数
 * 戻り値:
 *   このコマンドで使う開始 LBA
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static uint64_t nvmer_next_lba(nvme_rdma_ctx_t *ctx, uint32_t nlb)
{
    uint64_t lba = ctx->bench_cur_lba;
    uint64_t next = lba + (uint64_t)nlb;
    if (ctx->nsze == 0u || next + (uint64_t)nlb > ctx->nsze) {
        next = 0u;
    }
    ctx->bench_cur_lba = next;
    return lba;
}

/*=================================================================
 * nvmer_build_io_ex() をコンテキスト既定のバッファ/cid で呼ぶ薄いラッパ
 * (単発コマンド用)。
 *
 * 引数:
 *   ctx / opcode / nsid / slba / nlb - nvmer_build_io_ex() と同じ
 * 戻り値:
 *   送信すべきバイト数
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static uint32_t nvmer_build_io(nvme_rdma_ctx_t *ctx, uint8_t opcode, uint32_t nsid, uint64_t slba,
                               uint32_t nlb, volatile uint8_t *buf, uint32_t total_len)
{
    return nvmer_build_io_ex(ctx, ctx->send_buf, ctx->cur_cid, opcode, nsid, slba, nlb, buf, total_len);
}

/*=================================================================
 * 応答 capsule 受信用の RECV WQE を 1 個投稿する。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static int nvmer_post_recv(nvme_rdma_ctx_t *ctx)
{
    return mlx5_qp_post_recv(ctx->cm.dev, nvmer_qp(ctx), (void *)(uintptr_t)ctx->recv_buf,
                             sizeof(ctx->recv_buf));
}

/*=================================================================
 * 組み立て済みの capsule を SEND WQE として投稿する。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 *   len - 送信バイト数
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static void nvmer_post_send_data(nvme_rdma_ctx_t *ctx, uint32_t len,
                                 const volatile uint8_t *data, uint32_t data_len)
{
    dcache_clean_range((const void *)(uintptr_t)ctx->send_buf, len);
    /* **データはコピーせず 2 本目の SGE で送る。** capsule へ写すと
     * 1 コマンドあたり data_len バイトの memcpy が hot path に乗る。 */
    mlx5_qp_post_send2(ctx->cm.dev, nvmer_qp(ctx), (const void *)(uintptr_t)ctx->send_buf, len,
                       (const void *)(uintptr_t)data, data_len);
    ctx->send_done = 0;
    ctx->recv_done = 0;
    ctx->cmd_deadline = timer_now();
}

static void nvmer_post_send(nvme_rdma_ctx_t *ctx, uint32_t len)
{
    nvmer_post_send_data(ctx, len, 0, 0);
}

/*=================================================================
 * 送信完了(SQ CQE)と応答 capsule 到着(RQ CQE)の両方を待つ。1 tick 分だけ
 * ポーリングして状態を進める。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * 戻り値:
 *   1=両方完了(recv_buf に応答 CQE)、0=継続中、-1=エラー/タイムアウト
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static int nvmer_wait_exec(nvme_rdma_ctx_t *ctx)
{
    if (!ctx->send_done || !ctx->recv_done) {
        int is_send = 0;
        uint32_t recv_len = 0;
        uint8_t synd = 0;
        int rc = mlx5_qp_poll_cqe(ctx->cm.dev, nvmer_qp(ctx), &is_send, &recv_len, &synd);
        if (rc < 0) {
            uart_printf("[!] nvme-rdma: CQEエラー syndrome=0x%02x\n", synd);
            return -1;
        }
        if (rc == 1) {
            if (is_send) {
                ctx->send_done = 1;
            } else {
                dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, recv_len);
                ctx->recv_len = recv_len;
                ctx->recv_done = 1;
            }
        }
    }
    if (ctx->send_done && ctx->recv_done) return 1;
    if (timeout_ms(ctx->cmd_deadline, NVME_RDMA_CMD_TIMEOUT_MS)) {
        uart_printf("[!] nvme-rdma: 応答待ちタイムアウト (send_done=%d recv_done=%d)\n",
                    ctx->send_done, ctx->recv_done);
        return -1;
    }
    return 0;
}

static job_result_t nvmer_fail(nvme_rdma_ctx_t *ctx, const char *msg)
{
    uart_printf("[!] nvme-rdma: %s\n", msg);
    ctx->failed = 1;
    ctx->done = 1;
    return JOB_DONE;
}

typedef struct {
    int      in_use;
    uint16_t cid;
} nvme_rdma_pl_slot_t;

static nvme_rdma_pl_slot_t s_pl_slots[NVME_RDMA_PL_QDEPTH_MAX];
static volatile uint8_t s_pl_send_bufs[NVME_RDMA_PL_QDEPTH_MAX][64] __attribute__((aligned(64)));
static volatile uint8_t s_pl_recv_bufs[NVME_RDMA_PL_QDEPTH_MAX][64] __attribute__((aligned(64)));
static unsigned s_pl_rq_order[NVME_RDMA_PL_QDEPTH_MAX];
static unsigned s_pl_rq_head, s_pl_rq_tail;

/*=================================================================
 * パイプライン用スロットの応答受信バッファへ RECV WQE を投稿する。
 *
 * 引数:
 *   ctx  - initiator コンテキスト
 *   slot - スロット番号
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   nvme_rdma_connect_job_step()
 * ===============================================================*/
static int nvmer_pl_post_recv_slot(nvme_rdma_ctx_t *ctx, unsigned slot)
{
    if (mlx5_qp_post_recv(ctx->cm.dev, nvmer_qp(ctx), (void *)(uintptr_t)s_pl_recv_bufs[slot],
                          sizeof(s_pl_recv_bufs[slot])) != 0) {
        return -1;
    }
    s_pl_rq_order[s_pl_rq_tail % NVME_RDMA_PL_QDEPTH_MAX] = slot;
    s_pl_rq_tail++;
    return 0;
}

/*=================================================================
 * Identify Namespace 完了直後に次のステートを決める。ベンチ指定があれば
 * 直接 read/write ループへ、無ければ単発検証シーケンスへ進む。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * 戻り値:
 *   次のステート
 * コール元:
 *   nvme_rdma_connect_job_step(), nvme_rdma_run_bench()
 * ===============================================================*/
static nvme_rdma_state_t nvmer_resume_state_after_identify(nvme_rdma_ctx_t *ctx)
{
    if (ctx->bench_enabled && ctx->bench_qdepth > 1u) {
        return NVMER_ST_PIPELINE_SETUP;
    } else if (ctx->bench_enabled) {
        ctx->bench_start_ticks = timer_now();
        ctx->bench_count = 0;
        ctx->bench_bytes = 0;
        return ctx->bench_is_read ? NVMER_ST_SEND_READ : NVMER_ST_SEND_WRITE;
    }
    return NVMER_ST_SEND_WRITE;
}

/*=================================================================
 * NVMe-oF RDMA initiator のステートマシン 1 tick。CM 確立 -> Fabrics Connect
 * -> Property Set(CC.EN) -> Property Get(CSTS.RDY) -> Identify
 * Controller/Namespace と進み、そのままベンチ(write/read の
 * パイプライン発行と完了回収)まで回す。
 *
 * 引数:
 *   self - このジョブ(self->state が initiator のステート)
 * 戻り値:
 *   JOB_WAITING=継続、JOB_DONE=完了/失敗で終了
 * コール元:
 *   job_scheduler_tick() から関数ポインタ経由
 * ===============================================================*/
job_result_t nvme_rdma_connect_job_step(job_t *self)
{
    nvme_rdma_ctx_t *ctx = (nvme_rdma_ctx_t *)self->ctx;

    if (ctx->stop_requested || self->cancel_requested) {
        ctx->done = 1;
        return JOB_DONE;
    }

    switch (self->state) {

    case NVMER_ST_CM_SPAWN: {
        ctx->cm.is_active = 1;
        ctx->cm.skip_ping = 1;
        job_t *cmjob = job_spawn(rdma_cm_job_step, &ctx->cm, "nvme-rdma-cm");
        if (!cmjob) return nvmer_fail(ctx, "CM用ジョブ生成失敗");
        cmjob->state = RDMA_CM_ST_ACTIVE_SETUP;
        self->state = NVMER_ST_CM_WAIT;
        return JOB_WAITING;
    }

    case NVMER_ST_CM_WAIT: {
        if (ctx->cm.failed) return nvmer_fail(ctx, "CM確立失敗");
        if (!ctx->cm.established) return JOB_WAITING;
        uart_printf("[nvme-rdma] RC QP確立完了 (qpn=%u)\n", ctx->cm.rc_qp.qpn);
        ctx->nsid = 1u;
        ctx->cur_cid = 0x100u;
        self->state = NVMER_ST_SEND_CONNECT;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_CONNECT: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Connect)失敗");
        const char *subnqn = (s_remote.enabled && s_remote.subnqn[0]) ? s_remote.subnqn
                                                                      : NVMET_RDMA_SUBNQN;
        uint32_t len = nvmer_build_connect(ctx, 0u, subnqn);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_CONNECT;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_CONNECT: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Fabrics Connect失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Fabrics Connect: 応答エラー");
        const uint32_t cdw0 = rd32le(&ctx->recv_buf[0]);
        ctx->cntlid = (uint16_t)(cdw0 & 0xFFFFu);
        uart_printf("[nvme-rdma] Fabrics Connect完了 (cntlid=%u%s)\n", ctx->cntlid,
                    (cdw0 & NVME_AUTH_CONNECT_ATR) ? "、相手が認証を求めている" : "");
        ctx->cur_cid++;
        if (cdw0 & NVME_AUTH_CONNECT_ATR) {
            const nvme_auth_key_t *hk = nvme_auth_host_key();
            if (hk->len == 0) return nvmer_fail(ctx, "相手が認証を求めたがイニシエータの鍵が無い(nvmeauth)");
            nvmer_zero_v((volatile uint8_t *)&ctx->auth, (uint32_t)sizeof(ctx->auth));
            ctx->auth.host = *hk;
            ctx->auth.ctrl = *nvme_auth_ctrl_key();
            ctx->auth.hostnqn = NVME_RDMA_HOST_NQN;
            ctx->auth.subnqn = (s_remote.enabled && s_remote.subnqn[0]) ? s_remote.subnqn : NVMET_RDMA_SUBNQN;
            ctx->auth_failed = 0;
            ctx->auth_phase = NVMER_AUTH_NEG;
            ctx->auth_len = nvme_auth_host_negotiate(&ctx->auth, (uint8_t *)(uintptr_t)&ctx->send_buf[64]);
            self->state = NVMER_ST_AUTH_SEND;
            return JOB_WAITING;
        }
        self->state = NVMER_ST_SEND_PROP_SET_CC;
        return JOB_WAITING;
    }

    case NVMER_ST_AUTH_SEND: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(認証)失敗");
        const int send = (ctx->auth_phase == NVMER_AUTH_NEG || ctx->auth_phase == NVMER_AUTH_REPLY ||
                          ctx->auth_phase == NVMER_AUTH_S2);
        nvmer_post_send(ctx, nvmer_build_auth(ctx, send, send ? ctx->auth_len : NVME_AUTH_RECV_LEN));
        self->state = NVMER_ST_AUTH_WAIT;
        return JOB_WAITING;
    }

    case NVMER_ST_AUTH_WAIT: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "認証: 応答が無い");
        const uint16_t st = rd16le(&ctx->recv_buf[14]);
        ctx->cur_cid++;
        if (nvme_cqe_status_code(st) != 0 && ctx->auth_phase != NVMER_AUTH_S2) {
            return nvmer_fail(ctx, "認証: コマンドが拒否された");
        }
        const uint8_t *in = (const uint8_t *)(uintptr_t)ctx->id_ns;
        uint8_t *out = (uint8_t *)(uintptr_t)&ctx->send_buf[64];
        const char *why = "";
        switch (ctx->auth_phase) {
        case NVMER_AUTH_NEG:
            ctx->auth_phase = NVMER_AUTH_CHAL;
            break;
        case NVMER_AUTH_CHAL:
            ctx->auth_len = nvme_auth_host_reply(&ctx->auth, in, NVME_AUTH_RECV_LEN, out,
                                                 NVME_RDMA_MSG_MAX - 64u, &why);
            if (ctx->auth_len == 0) {
                nvme_auth_host_wipe(&ctx->auth);
                uart_printf("[nvme-rdma] 認証: %s\n", why);
                return nvmer_fail(ctx, "認証: Challenge が受け入れられない");
            }
            uart_printf("[nvme-rdma] 認証: Challenge(ハッシュ %u、DH %s)に Reply を返す%s\n",
                        ctx->auth.hashid, nvme_auth_dh_name(ctx->auth.dhgid),
                        ctx->auth.bidir ? "(双方向)" : "");
            ctx->auth_phase = NVMER_AUTH_REPLY;
            break;
        case NVMER_AUTH_REPLY:
            ctx->auth_phase = NVMER_AUTH_RESULT;
            break;
        case NVMER_AUTH_RESULT: {
            uint32_t olen = 0;
            const int ok = nvme_auth_host_result(&ctx->auth, in, NVME_AUTH_RECV_LEN, out, &olen, &why);
            nvme_auth_host_wipe(&ctx->auth);
            if (!ok) uart_printf("[nvme-rdma] 認証: %s\n", why);
            if (olen != 0) {   /* Success2 か Failure2 を送る */
                ctx->auth_failed = !ok;
                ctx->auth_len = olen;
                ctx->auth_phase = NVMER_AUTH_S2;
                break;
            }
            if (!ok) return nvmer_fail(ctx, "認証に失敗");
            uart_printf("[nvme-rdma] 認証: 済んだ(片方向)\n");
            self->state = NVMER_ST_SEND_PROP_SET_CC;
            return JOB_WAITING;
        }
        default:   /* NVMER_AUTH_S2 */
            if (ctx->auth_failed) return nvmer_fail(ctx, "認証: コントローラを認めなかった");
            if (nvme_cqe_status_code(st) != 0) return nvmer_fail(ctx, "認証: Success2 が拒否された");
            uart_printf("[nvme-rdma] 認証: 済んだ(双方向)\n");
            self->state = NVMER_ST_SEND_PROP_SET_CC;
            return JOB_WAITING;
        }
        self->state = NVMER_ST_AUTH_SEND;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_PROP_SET_CC: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(PropSet CC)失敗");
        uint32_t cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_AMS_RR | NVME_CC_SHN_NONE |
                      NVME_CC_IOSQES | NVME_CC_IOCQES;
        uint32_t len = nvmer_build_prop_set(ctx, NVME_REG_CC, cc);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_PROP_SET_CC;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_PROP_SET_CC: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Property Set(CC)失敗");
        ctx->csts_poll_count = 0;
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_PROP_GET_CSTS;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_PROP_GET_CSTS: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(PropGet CSTS)失敗");
        uint32_t len = nvmer_build_prop_get(ctx, NVME_REG_CSTS);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_PROP_GET_CSTS;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_PROP_GET_CSTS: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Property Get(CSTS)失敗");
        uint32_t csts = rd32le(&ctx->recv_buf[0]);
        if (csts & NVME_CSTS_CFS) return nvmer_fail(ctx, "CSTS.CFS(コントローラ致命的状態)");
        if (csts & NVME_CSTS_RDY) {
            uart_printf("[nvme-rdma] コントローラ有効化完了 (CSTS.RDY=1)\n");
            ctx->cur_cid++;
            self->state = NVMER_ST_SEND_ID_CTRL;
            return JOB_WAITING;
        }
        ctx->csts_poll_count++;
        if (ctx->csts_poll_count >= NVME_RDMA_CTRL_READY_POLL_MAX) {
            return nvmer_fail(ctx, "CSTS.RDY待ちタイムアウト");
        }
        ctx->wait_started_ticks = timer_now();
        self->state = NVMER_ST_CSTS_POLL_WAIT;
        return JOB_WAITING;
    }

    case NVMER_ST_CSTS_POLL_WAIT: {
        if (!timeout_ms(ctx->wait_started_ticks, NVME_RDMA_CTRL_READY_POLL_MS)) return JOB_WAITING;
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_PROP_GET_CSTS;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_ID_CTRL: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Identify Ctrl)失敗");
        uint32_t len = nvmer_build_identify(ctx, (uint8_t)NVME_IDENTIFY_CNS_CONTROLLER, 0u,
                                            ctx->id_ctrl, NVME_RDMA_ID_BUF_LEN);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_ID_CTRL;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_ID_CTRL: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Identify Controller失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Identify Controller: 応答エラー");
        dcache_invalidate_range((const void *)(uintptr_t)ctx->id_ctrl, NVME_RDMA_ID_BUF_LEN);
        {   /* 相手のモデル名(offset 24、40 バイト)を出す。**RDMA でデータが
             * 実際に届いたかの一番手軽な確認**で、外部ターゲットのときは
             * 「本当に Linux の nvmet と喋っている」ことの証拠にもなる。 */
            char mn[41];
            unsigned n = 0;
            for (unsigned i = 0; i < 40u; i++) {
                char c = (char)ctx->id_ctrl[24u + i];
                if (c == 0) break;
                mn[n++] = c;
            }
            while (n > 0 && mn[n - 1] == ' ') n--;
            mn[n] = 0;
            uart_printf("[nvme-rdma] Identify Controller完了 (model=\"%s\")\n", mn);
        }
        /* in-capsule write が使えるかを相手の広告から決める。条件は Linux の
         * nvme_rdma_setup_ctrl() と同じ 3 つ:
         *   ICDOFF == 0 / SGLS bit20(SAOS)/ payload <= IOCCSZ*16 - 64。
         * **KSDBDS(bit2)ではなく SAOS(bit20)を見ること。** */
        {
            uint32_t ioccsz = rd32le(&ctx->id_ctrl[1792]);
            uint16_t icdoff = rd16le(&ctx->id_ctrl[1800]);
            uint32_t sgls   = rd32le(&ctx->id_ctrl[536]);
            ctx->icdsz = 0u;
            if (icdoff == 0u && (sgls & (1u << 20)) != 0u && ioccsz > 4u) {
                ctx->icdsz = (ioccsz - 4u) * 16u;
                if (ctx->icdsz > NVME_RDMA_ICD_MAX) ctx->icdsz = NVME_RDMA_ICD_MAX;
            }
            uart_printf("[nvme-rdma] in-capsule write: %s (ioccsz=%u icdoff=%u sgls=0x%x -> %u バイト)\n",
                        ctx->icdsz ? "使う" : "使わない", ioccsz, (unsigned)icdoff, sgls, ctx->icdsz);
        }
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_ID_NS;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_ID_NS: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Identify NS)失敗");
        uint32_t len = nvmer_build_identify(ctx, (uint8_t)NVME_IDENTIFY_CNS_NAMESPACE, ctx->nsid,
                                            ctx->id_ns, NVME_RDMA_ID_BUF_LEN);
        nvmer_post_send(ctx, len);
        self->state = NVMER_ST_WAIT_ID_NS;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_ID_NS: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Identify Namespace失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Identify Namespace: 応答エラー");
        dcache_invalidate_range((const void *)(uintptr_t)ctx->id_ns, NVME_RDMA_ID_BUF_LEN);
        dcache_invalidate_range((const void *)(uintptr_t)ctx->id_ns, NVME_RDMA_ID_BUF_LEN);
        uint8_t flbas = (uint8_t)(ctx->id_ns[NVME_ID_NS_OFF_FLBAS] & 0x0Fu);
        uint32_t lbaf_off = NVME_ID_NS_OFF_LBAF0 + (uint32_t)flbas * 4u;
        uint8_t ds = ctx->id_ns[lbaf_off + 2];
        ctx->lba_size = (uint32_t)1u << ds;
        ctx->nsze = rd64le(&ctx->id_ns[0]);
        if (s_ns_ovr_lba_size != 0u) {
            ctx->lba_size = s_ns_ovr_lba_size;
            ctx->nsze = s_ns_ovr_nsze;
            uart_printf("[nvme-rdma] Identify Namespaceを手動値で上書き "
                        "(lba_size=%u nsze=%u)\n", ctx->lba_size, (unsigned)ctx->nsze);
        } else if (ctx->lba_size < 512u || ctx->lba_size > 65536u ||
                   (ctx->lba_size & (ctx->lba_size - 1u)) != 0u || ctx->nsze == 0u) {
            /* **値がありえないときは黙って進まない。** そのまま使うと
             * LBA が範囲外になって「Write の応答エラー」としか見えない。 */
            uart_printf("[!] nvme-rdma: Identify Namespace の値が不正 "
                        "(lba_size=%u nsze=%u)。rdmans で上書きしてください\n",
                        ctx->lba_size, (unsigned)ctx->nsze);
        } else {
            uart_printf("[nvme-rdma] Identify Namespace完了 (lba_size=%u バイト nsze=%u ブロック)\n",
                        ctx->lba_size, (unsigned)ctx->nsze);
        }
        ctx->cur_cid++;
        ctx->reusable = 1;
        ctx->established_generation = ctx->cm.dev->bringup_generation;
        /* **実ホストは admin キューで IO コマンドを受け付けない。**
         * opcode 0x02 は admin だと Get Log Page になるので、
         * qid=1 の接続を別に立ててから IO を流す。 */
        if (s_remote.enabled && !ctx->io_queue_ready) {
            self->state = NVMER_ST_IOQ_CM_SPAWN;
            return JOB_WAITING;
        }
        self->state = nvmer_resume_state_after_identify(ctx);
        return JOB_WAITING;
    }

    case NVMER_ST_IOQ_CM_SPAWN: {
        /* GSI(QP1)はポートに 1 つしか置けないので admin のものを使い回す。
         * RC QP は qp_index=1 側(qp2_* の DMA バッファ)を使う。 */
        for (unsigned i = 0; i < sizeof(ctx->io_cm); i++) ((uint8_t *)&ctx->io_cm)[i] = 0;
        dcache_clean_range((const void *)&ctx->io_cm, sizeof(ctx->io_cm));
        ctx->io_cm.dev         = ctx->cm.dev;
        ctx->io_cm.gsi_qp      = ctx->cm.gsi_qp;
        ctx->io_cm.reuse_gsi   = 1;
        ctx->io_cm.rc_qp_index = 1;
        ctx->io_cm.is_active   = 1;
        ctx->io_cm.skip_ping   = 1;
        ctx->io_cm.own_ip      = ctx->cm.own_ip;
        ctx->io_cm.peer_ip     = ctx->cm.peer_ip;
        for (unsigned i = 0; i < 6u; i++) {
            ctx->io_cm.own_mac[i]  = ctx->cm.own_mac[i];
            ctx->io_cm.peer_mac[i] = ctx->cm.peer_mac[i];
        }
        for (unsigned i = 0; i < 16u; i++) {
            ctx->io_cm.own_gid[i]  = ctx->cm.own_gid[i];
            ctx->io_cm.peer_gid[i] = ctx->cm.peer_gid[i];
        }
        ctx->io_cm.service_port = ctx->cm.service_port;
        ctx->io_cm.src_port     = (uint16_t)(ctx->cm.src_port + 1u);
        ctx->io_cm.hrqsize      = NVME_RDMA_QSIZE;
        ctx->io_cm.hsqsize      = NVME_RDMA_QSIZE - 1u;
        ctx->io_cm.cntlid       = ctx->cntlid;   /* IO キューでは実値を載せる */
        ctx->io_cm.nvme_qid     = 1u;
        {
            job_t *cmjob = job_spawn(rdma_cm_job_step, &ctx->io_cm, "nvme-rdma-io-cm");
            if (!cmjob) return nvmer_fail(ctx, "IOキュー用CMジョブ生成失敗");
            cmjob->state = RDMA_CM_ST_ACTIVE_SETUP;
        }
        self->state = NVMER_ST_IOQ_CM_WAIT;
        return JOB_WAITING;
    }

    case NVMER_ST_IOQ_CM_WAIT: {
        if (ctx->io_cm.failed) return nvmer_fail(ctx, "IOキューのCM確立失敗");
        if (!ctx->io_cm.established) return JOB_WAITING;
        uart_printf("[nvme-rdma] IOキューのRC QP確立 (qpn=%u)\n", ctx->io_cm.rc_qp.qpn);
        ctx->io_queue_ready = 1;   /* 以後の post/poll は IO QP へ */
        self->state = NVMER_ST_IOQ_SEND_CONNECT;
        return JOB_WAITING;
    }

    case NVMER_ST_IOQ_SEND_CONNECT: {
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(IO Connect)失敗");
        {
            const char *subnqn = (s_remote.enabled && s_remote.subnqn[0]) ? s_remote.subnqn
                                                                         : NVMET_RDMA_SUBNQN;
            uint32_t len = nvmer_build_connect(ctx, 1u, subnqn);
            nvmer_post_send(ctx, len);
        }
        self->state = NVMER_ST_IOQ_WAIT_CONNECT;
        return JOB_WAITING;
    }

    case NVMER_ST_IOQ_WAIT_CONNECT: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "IOキューのFabrics Connect失敗");
        {
            uint16_t status = rd16le(&ctx->recv_buf[14]);
            if (nvme_cqe_status_code(status) != 0)
                return nvmer_fail(ctx, "IOキューのFabrics Connect: 応答エラー");
        }
        uart_printf("[nvme-rdma] IOキューのFabrics Connect完了 (qid=1)\n");
        ctx->cur_cid++;
        self->state = nvmer_resume_state_after_identify(ctx);
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_WRITE: {
        uint32_t len = ctx->bench_enabled ? ctx->bench_chunk_bytes : ctx->lba_size;
        if (len == 0 || len > sizeof(ctx->write_buf)) len = NVME_RDMA_TEST_LEN;
        uint32_t nlb = (ctx->lba_size != 0) ? (len / ctx->lba_size) : 1u;
        if (nlb == 0) nlb = 1u;
        if (!ctx->bench_enabled || ctx->bench_count == 0) {
            for (uint32_t i = 0; i < len; i++) ctx->write_buf[i] = (uint8_t)(0xC0u + (i & 0x3Fu));
            dcache_clean_range((const void *)(uintptr_t)ctx->write_buf, len);
        }
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Write)失敗");
        uint64_t slba = ctx->bench_enabled ? nvmer_next_lba(ctx, nlb) : 0u;
        uint32_t slen = nvmer_build_io(ctx, NVME_IO_CMD_WRITE, ctx->nsid, slba, nlb, ctx->write_buf, len);
        if (nvmer_use_inline(ctx, (uint8_t)NVME_IO_CMD_WRITE, len)) {
            nvmer_post_send_data(ctx, slen, ctx->write_buf, len);
        } else {
            nvmer_post_send(ctx, slen);
        }
        self->state = NVMER_ST_WAIT_WRITE;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_WRITE: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Write失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        int ok = (nvme_cqe_status_code(status) == 0);
        if (ctx->bench_enabled) {
            if (!ok) return nvmer_fail(ctx, "Write(bench): 応答エラー");
            ctx->bench_count++;
            ctx->bench_bytes += ctx->bench_chunk_bytes;
            ctx->cur_cid++;
            if (timeout_ms(ctx->bench_start_ticks, ctx->bench_duration_ms)) {
                ctx->done = 1;
                self->state = NVMER_ST_DONE_OK;
                return JOB_DONE;
            }
            self->state = NVMER_ST_SEND_WRITE;
            return JOB_WAITING;
        }
        ctx->write_ok = ok;
        uart_printf("[nvme-rdma] Write完了 (%s)\n", ctx->write_ok ? "成功" : "エラー応答");
        if (!ctx->write_ok) return nvmer_fail(ctx, "Write: 応答エラー");
        ctx->cur_cid++;
        self->state = NVMER_ST_SEND_READ;
        return JOB_WAITING;
    }

    case NVMER_ST_SEND_READ: {
        uint32_t len = ctx->bench_enabled ? ctx->bench_chunk_bytes : ctx->lba_size;
        if (len == 0 || len > sizeof(ctx->read_buf)) len = NVME_RDMA_TEST_LEN;
        uint32_t nlb = (ctx->lba_size != 0) ? (len / ctx->lba_size) : 1u;
        if (nlb == 0) nlb = 1u;
        if (!ctx->bench_enabled || ctx->bench_count == 0) {
            nvmer_zero_v(ctx->read_buf, len);
            dcache_clean_range((const void *)(uintptr_t)ctx->read_buf, len);
        }
        if (nvmer_post_recv(ctx) != 0) return nvmer_fail(ctx, "post_recv(Read)失敗");
        uint64_t slba = ctx->bench_enabled ? nvmer_next_lba(ctx, nlb) : 0u;
        uint32_t slen = nvmer_build_io(ctx, NVME_IO_CMD_READ, ctx->nsid, slba, nlb, ctx->read_buf, len);
        nvmer_post_send(ctx, slen);
        self->state = NVMER_ST_WAIT_READ;
        return JOB_WAITING;
    }

    case NVMER_ST_WAIT_READ: {
        int rc = nvmer_wait_exec(ctx);
        if (rc == 0) return JOB_WAITING;
        if (rc < 0) return nvmer_fail(ctx, "Read失敗");
        uint16_t status = rd16le(&ctx->recv_buf[14]);
        if (nvme_cqe_status_code(status) != 0) return nvmer_fail(ctx, "Read: 応答エラー");
        uint32_t len = ctx->bench_enabled ? ctx->bench_chunk_bytes : ctx->lba_size;
        if (len == 0 || len > sizeof(ctx->read_buf)) len = NVME_RDMA_TEST_LEN;
        dcache_invalidate_range((const void *)(uintptr_t)ctx->read_buf, len);
        if (ctx->bench_enabled) {
            ctx->bench_count++;
            ctx->bench_bytes += ctx->bench_chunk_bytes;
            ctx->cur_cid++;
            if (timeout_ms(ctx->bench_start_ticks, ctx->bench_duration_ms)) {
                ctx->done = 1;
                self->state = NVMER_ST_DONE_OK;
                return JOB_DONE;
            }
            self->state = NVMER_ST_SEND_READ;
            return JOB_WAITING;
        }
        int match = 1;
        for (uint32_t i = 0; i < len; i++) {
            if (ctx->read_buf[i] != ctx->write_buf[i]) { match = 0; break; }
        }
        ctx->read_ok = match;
        uart_printf("[nvme-rdma] Read完了、データ%s\n", match ? "完全一致" : "不一致");
        self->state = match ? NVMER_ST_DONE_OK : NVMER_ST_DONE_FAIL;
        ctx->failed = !match;
        ctx->done = 1;
        return JOB_DONE;
    }

    case NVMER_ST_PIPELINE_SETUP: {
        unsigned qdepth = ctx->bench_qdepth;
        if (qdepth > NVME_RDMA_PL_QDEPTH_MAX) qdepth = NVME_RDMA_PL_QDEPTH_MAX;
        if (qdepth == 0) qdepth = 1;
        ctx->bench_qdepth = qdepth;
        for (unsigned i = 0; i < NVME_RDMA_PL_QDEPTH_MAX; i++) s_pl_slots[i].in_use = 0;
        s_pl_rq_head = s_pl_rq_tail = 0;
        if (!ctx->bench_is_read) {
            uint32_t len = ctx->bench_chunk_bytes;
            if (len > sizeof(ctx->write_buf)) len = (uint32_t)sizeof(ctx->write_buf);
            for (uint32_t i = 0; i < len; i++) ctx->write_buf[i] = (uint8_t)(0xC0u + (i & 0x3Fu));
            dcache_clean_range((const void *)(uintptr_t)ctx->write_buf, len);
        }
        ctx->bench_start_ticks = timer_now();
        ctx->bench_count = 0;
        ctx->bench_bytes = 0;
        ctx->bench_peeked = 0;
        uart_printf("[nvme-rdma] パイプライン化ループ開始 (depth=%u)\n", qdepth);
        self->state = NVMER_ST_PIPELINE_LOOP;
        return JOB_WAITING;
    }

    case NVMER_ST_PIPELINE_LOOP: {
        unsigned qdepth = ctx->bench_qdepth;

        for (unsigned iter = 0; iter < NVME_RDMA_PL_QDEPTH_MAX * 3u; iter++) {
            int is_send = 0;
            uint32_t recv_len = 0;
            uint8_t synd = 0;
            int rc = mlx5_qp_poll_cqe(ctx->cm.dev, nvmer_qp(ctx), &is_send, &recv_len, &synd);
            if (rc == 0) break;
            if (rc < 0) {
                uint32_t hw_rq = 0, sw_rq = 0;
                uint16_t hw_sq = 0, sw_sq = 0;
                mlx5_qp_query_counters(ctx->cm.dev, nvmer_qp(ctx), &hw_rq, &sw_rq, &hw_sq, &sw_sq);
                uint8_t last_op = mlx5_qp_last_cqe_opcode(ctx->cm.dev, nvmer_qp(ctx));
                uart_printf("[!] nvme-rdma pipeline: CQEエラー syndrome=0x%02x cqe_opcode=0x%x is_send=%d "
                            "rq_head=%u rq_tail=%u hw_rq=%u sw_rq=%u hw_sq=%u sw_sq=%u sq_pc=%u cq_cc=%u\n",
                            synd, last_op, is_send, s_pl_rq_head, s_pl_rq_tail, hw_rq, sw_rq, hw_sq, sw_sq,
                            nvmer_qp(ctx)->sq_pc, nvmer_qp(ctx)->cq_cc);
                return nvmer_fail(ctx, "pipeline CQEエラー");
            }
            if (is_send) continue;
            if (s_pl_rq_head == s_pl_rq_tail) return nvmer_fail(ctx, "pipeline: 予期しないRQ完了");
            unsigned slot = s_pl_rq_order[s_pl_rq_head % NVME_RDMA_PL_QDEPTH_MAX];
            s_pl_rq_head++;
            dcache_invalidate_range((const void *)(uintptr_t)s_pl_recv_bufs[slot], recv_len);
            uint16_t status = rd16le(&s_pl_recv_bufs[slot][14]);
            if (nvme_cqe_status_code(status) == 0) {
                if (ctx->bench_is_read && !ctx->bench_peeked) {
                    /* **最初の read 応答だけ、受け取ったデータの先頭を出す。**
                     * スループットだけ見ても「中身が合っているか」は分からない。 */
                    ctx->bench_peeked = 1;
                    dcache_invalidate_range((const void *)(uintptr_t)ctx->read_buf, 16u);
                    uart_printf("[nvme-rdma] read 先頭16B:");
                    for (unsigned k = 0; k < 16u; k++)
                        uart_printf(" %02x", (unsigned)ctx->read_buf[k]);
                    uart_printf("\n");
                }
                ctx->bench_count++;
                ctx->bench_bytes += ctx->bench_chunk_bytes;
            } else {
                uart_printf("[!] nvme-rdma pipeline: コマンド失敗応答 (cid=%u)\n", s_pl_slots[slot].cid);
            }
            s_pl_slots[slot].in_use = 0;
        }

        if (!timeout_ms(ctx->bench_start_ticks, ctx->bench_duration_ms)) {
            /* 空きスロットへ新規コマンドを詰める。 */
            uint32_t nlb = (ctx->lba_size != 0) ? (ctx->bench_chunk_bytes / ctx->lba_size) : 1u;
            if (nlb == 0) nlb = 1u;
            volatile uint8_t *data_buf = ctx->bench_is_read ? ctx->read_buf : ctx->write_buf;
            uint8_t opcode = ctx->bench_is_read ? (uint8_t)NVME_IO_CMD_READ : (uint8_t)NVME_IO_CMD_WRITE;
            for (unsigned i = 0; i < qdepth; i++) {
                if (s_pl_slots[i].in_use) continue;
                ctx->cur_cid++;
                nvmer_build_io_ex(ctx, s_pl_send_bufs[i], ctx->cur_cid, opcode, ctx->nsid,
                                  nvmer_next_lba(ctx, nlb),
                                  nlb, data_buf, ctx->bench_chunk_bytes);
                dcache_clean_range((const void *)(uintptr_t)s_pl_send_bufs[i], 64u);
                if (nvmer_pl_post_recv_slot(ctx, i) != 0) return nvmer_fail(ctx, "pipeline post_recv失敗");
                {
                    int inl = nvmer_use_inline(ctx, opcode, ctx->bench_chunk_bytes);
                    if (mlx5_qp_post_send2(ctx->cm.dev, nvmer_qp(ctx),
                                           (const void *)(uintptr_t)s_pl_send_bufs[i], 64u,
                                           inl ? (const void *)(uintptr_t)data_buf : 0,
                                           inl ? ctx->bench_chunk_bytes : 0u) != 0) {
                        return nvmer_fail(ctx, "pipeline post_send失敗");
                    }
                }
                s_pl_slots[i].in_use = 1;
                s_pl_slots[i].cid = ctx->cur_cid;
            }
        } else {
            int any_outstanding = 0;
            for (unsigned i = 0; i < qdepth; i++) {
                if (s_pl_slots[i].in_use) { any_outstanding = 1; break; }
            }
            if (!any_outstanding) {
                ctx->done = 1;
                self->state = NVMER_ST_DONE_OK;
                return JOB_DONE;
            }
        }
        return JOB_WAITING;
    }

    default:
        ctx->done = 1;
        return JOB_DONE;
    }
}

static nvme_rdma_ctx_t s_init_ctx;

/* 相手が広告した in-capsule 上限。`incapsule` の表示用。 */
uint32_t nvme_rdma_icdsz(void) { return s_init_ctx.icdsz; }
static nvmet_rdma_ctx_t s_target_ctx;
static nvmet_rdma_ctrl_t s_target_ctrl;

/* [調査用] bench の initiator が使う宛先の上書き。**宛先 MAC と宛先 GID を
 * 独立に振れるようにするための仕掛け。** FW が「ローカル宛」をどちらで判定して
 * いるのかを切り分けるのに使う(rocepeer シェルコマンド)。 */
/*=================================================================
 * 外部ホストのターゲットを接続先に設定する(enable=0 で解除)。
 *
 * 引数:
 *   enable - 1=外部ターゲットを使う、0=従来どおり同一プロセス内に立てる
 *   ip     - 接続先 IPv4(host order)
 *   mac    - 接続先 MAC(RoCEv2 は L2 も自分で解決する必要がある)
 *   port   - NVMe-oF のポート(0 なら 4420)
 *   subnqn - サブシステム NQN(NULL/空なら自作ターゲットの NQN)
 * コール元:
 *   shell_dispatch()
 * ===============================================================*/
void nvme_rdma_set_remote_target(int enable, uint32_t ip, const uint8_t mac[6],
                                 uint16_t port, const char *subnqn)
{
    for (unsigned i = 0; i < sizeof(s_remote); i++) ((uint8_t *)&s_remote)[i] = 0;
    if (!enable) return;
    s_remote.enabled = 1;
    s_remote.ip = ip;
    if (mac) for (unsigned i = 0; i < 6; i++) s_remote.mac[i] = mac[i];
    s_remote.port = (port != 0u) ? port : 4420u;
    if (subnqn && subnqn[0]) {
        unsigned i = 0;
        while (subnqn[i] && i + 1u < NVME_RDMA_SUBNQN_MAX) { s_remote.subnqn[i] = subnqn[i]; i++; }
        s_remote.subnqn[i] = 0;
    }
}

const nvme_rdma_remote_t *nvme_rdma_remote_target(void) { return &s_remote; }

static int      s_peer_override;
static uint32_t s_peer_ip_override;
static uint8_t  s_peer_mac_override[6];

void nvme_rdma_set_peer_override(int enable, uint32_t ip, const uint8_t mac[6])
{
    s_peer_override = enable;
    s_peer_ip_override = ip;
    if (mac) {
        for (unsigned i = 0; i < 6; i++) s_peer_mac_override[i] = mac[i];
    }
}

static int s_target_resident;
static uint32_t s_target_resident_generation;

/*=================================================================
 * 前回の接続(CM 確立〜Identify 完了済み)をそのまま再利用できるかを判定
 * する。HCA の bring-up 世代が変わっていれば古い QP ハンドルは無効。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 *   dev - 現在の HCA
 * 戻り値:
 *   1=再利用可、0=作り直しが必要
 * コール元:
 *   nvme_rdma_run_bench()
 * ===============================================================*/
static int nvmer_conn_reusable(nvme_rdma_ctx_t *ctx, mlx5_dev_t *dev)
{
    return ctx->reusable && !ctx->failed &&
           ctx->established_generation == dev->bringup_generation;
}

/*=================================================================
 * QP が作成済みなら DESTROY_QP で FW 側のオブジェクトを解放する。ジョブを
 * 止めるだけでは FW のリソースは解放されず、作り直しを繰り返すと
 * INIT2RTR_QP が BAD_RES_ERR で失敗するようになるため、再作成の前に必ず呼ぶ。
 *
 * 引数:
 *   dev - この QP を持つ HCA
 *   qp  - 解放する QP(qpn==0 なら何もしない)
 * コール元:
 *   nvme_rdma_run_bench()
 * ===============================================================*/
static void nvmer_destroy_qp_if_valid(mlx5_dev_t *dev, mlx5_qp_t *qp)
{
    if (dev != 0 && qp != 0 && qp->qpn != 0) {
        mlx5_qp_destroy(dev, qp);
    }
}

/*=================================================================
 * ctx を作り直す前に、それを参照しているジョブを止めて完全に抜けるまで待つ。
 *
 * **待たずにゼロクリアすると落ちる。** CM が失敗しても passive 側の CM ジョブ
 * (ctx は `&s_*_ctx.cm`)は誰も止めないので core1 で回り続ける。その状態で
 * ctx をゼロクリアすると `gsi_qp` が NULL になった瞬間を CM ジョブが踏み、
 * `mlx5_qp_poll_cqe_gsi+0xf` で segfault する(実機で 3 回再現した)。
 * `stop_requested` は nvmet_rdma のジョブしか見ないので、CM ジョブには
 * cancel_requested を立てる必要がある。
 *
 * 引数:
 *   ctx_a / ctx_b   - 止めたいジョブのコンテキスト(ctx_b は NULL 可)
 *   timeout_ms_val  - 待ちの上限
 * コール元:
 *   nvme_rdma_run_bench()
 * ===============================================================*/
static void nvmer_quiesce_jobs(const void *ctx_a, const void *ctx_b, unsigned timeout_ms_val)
{
    job_cancel_by_ctx(ctx_a);
    if (ctx_b != 0) job_cancel_by_ctx(ctx_b);

    uint64_t t0 = timer_now();
    while (!timeout_ms(t0, (uint64_t)timeout_ms_val)) {
        if (job_count_by_ctx(ctx_a) == 0 &&
            (ctx_b == 0 || job_count_by_ctx(ctx_b) == 0)) {
            return;
        }
        job_scheduler_tick();   /* core0 に pin されたジョブはこちらで回す */
    }
    uart_printf("[!] nvme-rdma: ジョブが %u ms で止まらなかった(ctx を作り直せない)\n",
                timeout_ms_val);
}

/*=================================================================
 * ターゲット側ジョブを core1 へ pin する(core1 が未起動なら起動する)。
 * initiator=core0 / target=core1 に分けることでレイテンシが下がる。
 * 起動に失敗した場合は core0 のままフォールバックする。
 *
 * 引数:
 *   target_job - pin するターゲットジョブ
 * コール元:
 *   nvme_rdma_run_bench()
 * ===============================================================*/
static void nvmer_pin_target_to_core1(job_t *target_job)
{
    if (smp_boot_core1() == 0) {
        job_pin_to_core(target_job, 1u);
    } else {
        uart_printf("[!] nvme-rdma: core1起動に失敗、targetはcore0のまま動作します\n");
    }
}

/*=================================================================
 * NVMe-oF RDMA のスループットを測る。target/initiator を同一プロセスに立て
 * (接続を再利用できるならそのまま使い)、指定 chunk・queue depth で
 * duration_ms のあいだ read か write を回し続ける。
 *
 * 引数:
 *   dev0, dev1  - initiator 側(PF0)と target 側(PF1)の HCA
 *   duration_ms - 測定時間
 *   is_read     - 1=read、0=write
 *   chunk_bytes - 1 コマンドの転送バイト数
 *   qdepth      - 同時 outstanding コマンド数
 *   out_bytes      - 転送できた総バイト数の格納先(不要なら NULL)
 *   out_count      - 完了コマンド数の格納先(不要なら NULL)
 *   out_elapsed_ms - 実測時間の格納先(不要なら NULL)
 * コール元:
 *   shell_rdmabench()
 * ===============================================================*/
void nvme_rdma_force_reconnect(void)
{
    s_init_ctx.reusable = 0;
}

void nvme_rdma_run_bench(mlx5_dev_t *dev0, mlx5_dev_t *dev1, uint32_t duration_ms,
                         int is_read, uint32_t chunk_bytes, uint32_t qdepth,
                         uint64_t *out_bytes, uint32_t *out_count,
                         uint32_t *out_elapsed_ms)
{
    /* 失敗時は 0 のまま返す(呼び出し側はこれを「測定できず」として扱う)。 */
    if (out_bytes)      *out_bytes = 0;
    if (out_count)      *out_count = 0u;
    if (out_elapsed_ms) *out_elapsed_ms = 0u;
    if (qdepth > NVME_RDMA_PL_QDEPTH_MAX) qdepth = NVME_RDMA_PL_QDEPTH_MAX;
    if (qdepth == 0) qdepth = 1u;

    if (chunk_bytes == 0) chunk_bytes = 65536u;
    if (chunk_bytes > NVME_RDMA_BENCH_BUF_MAX) chunk_bytes = NVME_RDMA_BENCH_BUF_MAX;
    chunk_bytes -= chunk_bytes % 512u;
    if (chunk_bytes == 0) chunk_bytes = 512u;

    static const uint8_t mac0_fallback[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x10};
    static const uint8_t mac1_fallback[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x11};
    uint32_t ip0_fallback = ip_from_octets(192, 168, 101, 10);
    uint32_t ip1_fallback = ip_from_octets(192, 168, 101, 11);

    /* **外部ターゲットのときは同一プロセス内のターゲットを立てない。**
     * dev1 も使わない(PF1 は相手ではなく、ただの遊んでいるポートになる)。 */
    const int use_remote = s_remote.enabled;
    int target_ok = use_remote ? 1
                               : (s_target_resident && !s_target_ctx.failed &&
                                  s_target_resident_generation == dev1->bringup_generation);
    int init_ok = target_ok && nvmer_conn_reusable(&s_init_ctx, dev0);

    if (!target_ok) {
        /* 前回のターゲットジョブと CM ジョブ(core1)を先に止め切る。 */
        nvmer_quiesce_jobs(&s_target_ctx, &s_target_ctx.cm, 2000u);
        nvmer_destroy_qp_if_valid(s_target_ctx.cm.dev, &s_target_ctx.cm.rc_qp);
        nvmer_destroy_qp_if_valid(s_target_ctx.cm.dev, s_target_ctx.cm.gsi_qp);
        for (uint32_t i = 0; i < sizeof(s_target_ctx); i++) ((uint8_t *)&s_target_ctx)[i] = 0;
        dcache_clean_range((const void *)&s_target_ctx, sizeof(s_target_ctx));
        rdma_cm_fill_addr(&s_target_ctx.cm, dev1, "mlx5-pf1", "mlx5-pf0", ip1_fallback, ip0_fallback,
                          mac1_fallback, mac0_fallback);
        s_target_ctx.ctrl = &s_target_ctrl; // フェーズ(i)続報: コントローラ状態の分離に伴い必須
        s_target_ctrl.ram_disk = nvmer_ramdisk_slot1(); // Phase 2 (x86-vfio-port): COHERENT DMA アリーナから確保(旧 NVMET_RDMA_RAMDISK_SLOT(1))
        s_target_ctx.pipeline_enabled = 1;
        job_t *target_job = job_spawn(nvmet_rdma_job_step, &s_target_ctx, "nvmet-rdma-bench-target");
        if (!target_job) {
            uart_printf("nvmermabench: FAILED (job table full)\n");
            return;
        }
        target_job->state = NVMETR_ST_CM_SPAWN;
        nvmer_pin_target_to_core1(target_job);
        s_target_resident = 1;
        s_target_resident_generation = dev1->bringup_generation;
        uart_printf("nvmermabench: targetを新規確立します(前回接続を再利用できません)\n");
    }

    job_t *init_job;
    if (init_ok) {
        s_init_ctx.bench_enabled = 1;
        s_init_ctx.bench_is_read = is_read ? 1 : 0;
        s_init_ctx.bench_chunk_bytes = chunk_bytes;
        s_init_ctx.bench_duration_ms = duration_ms;
        s_init_ctx.bench_qdepth = qdepth;
        s_init_ctx.bench_cur_lba = 0;
        s_init_ctx.done = 0;
        s_init_ctx.failed = 0;
        s_init_ctx.stop_requested = 0;
        init_job = job_spawn(nvme_rdma_connect_job_step, &s_init_ctx, "nvme-rdma-bench-init");
        if (!init_job) {
            uart_printf("nvmermabench: FAILED (job table full)\n");
            return;
        }
        init_job->state = nvmer_resume_state_after_identify(&s_init_ctx);
    } else {
        nvmer_quiesce_jobs(&s_init_ctx, &s_init_ctx.cm, 2000u);
        /* IO キュー側の CM ジョブと QP も先に終わらせる。
         * **残すと ctx をゼロクリアした後も回り続けて事故になる**
         * (RDMA CM で踏んだ segfault と同じ形)。 */
        nvmer_quiesce_jobs(&s_init_ctx, &s_init_ctx.io_cm, 2000u);
        nvmer_destroy_qp_if_valid(s_init_ctx.io_cm.dev, &s_init_ctx.io_cm.rc_qp);
        nvmer_destroy_qp_if_valid(s_init_ctx.cm.dev, &s_init_ctx.cm.rc_qp);
        nvmer_destroy_qp_if_valid(s_init_ctx.cm.dev, s_init_ctx.cm.gsi_qp);
        for (uint32_t i = 0; i < sizeof(s_init_ctx); i++) ((uint8_t *)&s_init_ctx)[i] = 0;
        dcache_clean_range((const void *)&s_init_ctx, sizeof(s_init_ctx));
        if (use_remote) {
            uart_printf("nvmermabench: 外部ターゲットへ接続します "
                        "ip=%u.%u.%u.%u mac=%02x:%02x:%02x:%02x:%02x:%02x port=%u\n",
                        (unsigned)((s_remote.ip >> 24) & 0xFFu),
                        (unsigned)((s_remote.ip >> 16) & 0xFFu),
                        (unsigned)((s_remote.ip >> 8) & 0xFFu),
                        (unsigned)(s_remote.ip & 0xFFu),
                        s_remote.mac[0], s_remote.mac[1], s_remote.mac[2],
                        s_remote.mac[3], s_remote.mac[4], s_remote.mac[5],
                        (unsigned)s_remote.port);
            rdma_cm_fill_addr(&s_init_ctx.cm, dev0, "mlx5-pf0", "__override__", ip0_fallback,
                              s_remote.ip, mac0_fallback, s_remote.mac);
            s_init_ctx.cm.service_port = s_remote.port;
        } else if (s_peer_override) {
            uart_printf("nvmermabench: [調査] 宛先を上書き ip=%u.%u.%u.%u "
                        "mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                        (unsigned)((s_peer_ip_override >> 24) & 0xFFu),
                        (unsigned)((s_peer_ip_override >> 16) & 0xFFu),
                        (unsigned)((s_peer_ip_override >> 8) & 0xFFu),
                        (unsigned)(s_peer_ip_override & 0xFFu),
                        s_peer_mac_override[0], s_peer_mac_override[1], s_peer_mac_override[2],
                        s_peer_mac_override[3], s_peer_mac_override[4], s_peer_mac_override[5]);
            rdma_cm_fill_addr(&s_init_ctx.cm, dev0, "mlx5-pf0", "__override__", ip0_fallback,
                              s_peer_ip_override, mac0_fallback, s_peer_mac_override);
        } else {
            rdma_cm_fill_addr(&s_init_ctx.cm, dev0, "mlx5-pf0", "mlx5-pf1", ip0_fallback, ip1_fallback,
                              mac0_fallback, mac1_fallback);
        }
        s_init_ctx.bench_enabled = 1;
        s_init_ctx.bench_is_read = is_read ? 1 : 0;
        s_init_ctx.bench_chunk_bytes = chunk_bytes;
        s_init_ctx.bench_duration_ms = duration_ms;
        s_init_ctx.bench_qdepth = qdepth;
        s_init_ctx.bench_cur_lba = 0;
        init_job = job_spawn(nvme_rdma_connect_job_step, &s_init_ctx, "nvme-rdma-bench-init");
        if (!init_job) {
            uart_printf("nvmermabench: FAILED (job table full)\n");
            return;
        }
        init_job->state = NVMER_ST_CM_SPAWN;
    }

    uart_printf("nvmermabench: %s chunk_bytes=%u duration_ms=%u qdepth=%u 開始\n",
                is_read ? "read" : "write", chunk_bytes, duration_ms, qdepth);

    uint64_t start = timer_now();
    while (1) {
        sim_delay_tick();
        job_scheduler_tick();
        if (s_init_ctx.done || (!use_remote && s_target_ctx.failed)) break;
        if (timeout_ms(start, (uint64_t)duration_ms + 15000u)) {
            uart_printf("nvmermabench: FAILED (overall timeout)\n");
            break;
        }
    }

    if (s_init_ctx.done && !s_init_ctx.failed && (use_remote || !s_target_ctx.failed)) {
        s_init_ctx.stop_requested = 1;
    } else {
        s_target_ctx.stop_requested = 1;
        s_init_ctx.stop_requested = 1;
        /* **CM ジョブは stop_requested を見ない。** ここで止めておかないと
         * CM 失敗後も core1 で回り続け、次の bench が ctx を作り直すときに
         * 事故になる。 */
        job_cancel_by_ctx(&s_target_ctx.cm);
        job_cancel_by_ctx(&s_init_ctx.cm);
        s_target_resident = 0;
    }
    {
        uint64_t stop_start = timer_now();
        while (!timeout_ms(stop_start, 2000u)) {
            job_scheduler_tick();
        }
    }

    if (!s_init_ctx.done || s_init_ctx.failed || (!use_remote && s_target_ctx.failed)) {
        uart_printf("nvmermabench: FAILED (count=%u)\n", s_init_ctx.bench_count);
        return;
    }

    uint32_t count = s_init_ctx.bench_count;
    uint64_t total_bytes = s_init_ctx.bench_bytes;
    uint32_t elapsed_ms = duration_ms;
    uint64_t mbps_x100 = (elapsed_ms != 0) ? (total_bytes * 100000ull) / ((uint64_t)elapsed_ms * 1000000ull) : 0;
    uint64_t iops_x100 = (elapsed_ms != 0) ? ((uint64_t)count * 100000ull) / (uint64_t)elapsed_ms : 0;
    uart_printf("nvmermabench: %s完了 count=%u bytes_hi32=%u bytes_lo32=%u elapsed_ms=%u\n",
                is_read ? "read" : "write", count, (unsigned)(total_bytes >> 32),
                (unsigned)(total_bytes & 0xFFFFFFFFu), elapsed_ms);
    uart_printf("nvmermabench: スループット=約%u.%02uMB/s IOPS=約%u.%02u\n",
                (unsigned)(mbps_x100 / 100u), (unsigned)(mbps_x100 % 100u),
                (unsigned)(iops_x100 / 100u), (unsigned)(iops_x100 % 100u));
    if (out_bytes)      *out_bytes = total_bytes;
    if (out_count)      *out_count = count;
    if (out_elapsed_ms) *out_elapsed_ms = elapsed_ms;
}
