#include "nvmet_rdma.h"
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

extern job_result_t nvme_rdma_connect_job_step(job_t *self);

static nvmet_rdma_ctx_t  s_standalone_ctx;      /* admin キュー(queue_id=0)*/
static nvmet_rdma_ctrl_t s_standalone_ctrl;     /* admin/IO 共有のコントローラ状態 */
static int      s_standalone_resident;
static uint32_t s_standalone_resident_generation;

/* IO キュー(queue_id=1)。admin の CM 確立を検出した時点で spawn する。
 * self_label / peer_mac はコールバックに渡らないのでここへ控えておく。 */
static nvmet_rdma_ctx_t s_standalone_io_ctx;
static int         s_standalone_io_spawned;
static const char *s_standalone_self_label;
static uint8_t     s_standalone_peer_mac[6];


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
    dcache_clean_range((const void *)(uintptr_t)ctx->ctrl->id_ns, sizeof(ctx->ctrl->id_ns));
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
        if (p->fctype == NVME_FABRIC_FCTYPE_CONNECT) {
            p->resp_dw0 = ctx->ctrl->ctrlr_id;
            uart_printf("[nvmet-rdma] Fabrics Connect受理 (cntlid=%u)\n", ctx->ctrl->ctrlr_id);
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
                p->resp_dw0 = ctx->ctrl->cc_en ? NVME_CSTS_RDY : 0;
            } else if (offset == NVME_REG_CC) {
                p->resp_dw0 = ctx->ctrl->cc;
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

    if (p->opcode == NVME_ADM_CMD_IDENTIFY) {
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key,
                               &p->inval_rkey);
        p->need_data_move = 1;
        p->data_move_is_write = 1; // ターゲット->ホストへRDMA_WRITEで押し込む
    } else if (p->opcode == NVME_ADM_CMD_SET_FEATURES) {
    } else if (p->opcode == NVME_ADM_CMD_KEEP_ALIVE) {
        /* 応答するだけ(need_data_move=0 のまま成功 CQE を返す)。 */
    } else if (p->opcode == NVME_IO_CMD_FLUSH) {
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
            p->need_data_move = 0;
            return;
        }
        p->need_data_move = 1;
        p->data_move_is_write = 0; // ホストからRDMA_READで引き込む
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
    ctx->resp_dw0 = p.resp_dw0;
    ctx->resp_dw1 = p.resp_dw1;
    ctx->resp_status = p.resp_status;
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
static void nvmetr_build_drep(nvmet_rdma_ctx_t *ctx, uint64_t dreq_tid, uint32_t dreq_local_comm_id)
{
    volatile uint8_t *buf = ctx->cm.send_buf;
    for (unsigned i = 0; i < RDMA_CM_MAD_SIZE; i++) buf[i] = 0;
    ib_mad_hdr_build(buf, IB_MGMT_CLASS_CM, IB_CM_CLASS_VERSION, IB_MGMT_METHOD_SEND,
                     dreq_tid, CM_DREP_ATTR_ID, 0);
    volatile uint8_t *p = &buf[IB_MAD_HDR_LEN];
    wr32be_ib(&p[0], ctx->cm.local_comm_id); // LOCAL_COMM_ID(自分自身)
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
    nvmetr_destroy_qp_if_valid(ctx->cm.dev, &ctx->cm.rc_qp);
    nvmetr_destroy_qp_if_valid(ctx->cm.dev, ctx->cm.gsi_qp);

    if (ctx->on_disconnected) {
        ctx->on_disconnected(ctx);   // -> nvmetr_on_admin_disconnected(このファイル)
    }

    mlx5_dev_t *dev = ctx->cm.dev;
    const char *self_label = ctx->self_label;
    uint8_t peer_mac_fallback[6];
    for (unsigned i = 0; i < 6; i++) peer_mac_fallback[i] = ctx->peer_mac_fallback[i];
    static const uint8_t dummy_mac[6] = {0, 0, 0, 0, 0, 0};

    rdma_cm_fill_addr(&ctx->cm, dev, self_label, "__no_such_net_ctx__", 0u, 0u,
                      dummy_mac, peer_mac_fallback);
    ctx->cm.is_active = 0;
    ctx->cm.skip_ping = 1;
    ctx->established = 0;
    ctx->failed = 0;

    ctx->ctrl->ctrlr_id = 1;
    ctx->ctrl->cc = 0;
    ctx->ctrl->cc_en = 0;
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

    int is_send = 0;
    uint32_t recv_len = 0;
    uint8_t synd = 0;
    int rc = mlx5_qp_poll_cqe_gsi(ctx->cm.dev, ctx->cm.gsi_qp, &is_send, &recv_len, &synd);
    if (rc <= 0 || is_send) {
        return 0; // 何も無い、または自分のSEND完了(DREP送信完了通知等)
    }

    dcache_invalidate_range((const void *)(uintptr_t)ctx->cm.recv_buf, recv_len);
    if (rdma_cm_recv_attr_id(ctx->cm.recv_buf) != CM_DREQ_ATTR_ID) {
        // DREQ以外(想定外の再送等) -- 再度RECVを構えて無視する。
        mlx5_qp_post_recv_gsi(ctx->cm.dev, ctx->cm.gsi_qp, (void *)(uintptr_t)ctx->cm.recv_buf,
                              sizeof(ctx->cm.recv_buf));
        return 0;
    }

    const volatile uint8_t *p = &ctx->cm.recv_buf[MLX5_GRH_BYTES + IB_MAD_HDR_LEN];
    uint64_t dreq_tid            = rd64be(&ctx->cm.recv_buf[MLX5_GRH_BYTES + 8]);
    uint32_t dreq_local_comm_id  = rd32be_ib(&p[0]);
    uint32_t dreq_remote_comm_id = rd32be_ib(&p[4]);
    uint32_t dreq_remote_qpn     = ((uint32_t)p[8] << 16) | ((uint32_t)p[9] << 8) | p[10];

    if (dreq_remote_comm_id != ctx->cm.local_comm_id || dreq_remote_qpn != ctx->cm.rc_qp.qpn) {
        mlx5_qp_post_recv_gsi(ctx->cm.dev, ctx->cm.gsi_qp, (void *)(uintptr_t)ctx->cm.recv_buf,
                              sizeof(ctx->cm.recv_buf));
        return 0;
    }

    uart_printf("[nvmet-rdma] CM DREQ受信 (comm_id=0x%08x) -- DREP送信、次の接続を待つ状態へ戻ります\n",
                ctx->cm.local_comm_id);
    nvmetr_build_drep(ctx, dreq_tid, dreq_local_comm_id);
    dcache_clean_range((const void *)(uintptr_t)ctx->cm.send_buf, sizeof(ctx->cm.send_buf));
    mlx5_qp_post_send_ud(ctx->cm.dev, ctx->cm.gsi_qp, (const void *)(uintptr_t)ctx->cm.send_buf,
                         RDMA_CM_MAD_SIZE, 1u /* GSI宛は常にQPN=1固定[フェーズd] */,
                         IB_QP1_QKEY, ctx->cm.peer_gid, ctx->cm.peer_mac);

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
    volatile uint8_t *dst = &ctx->ctrl->ram_disk[p->io_slba * NVMET_RDMA_LBA_SIZE];
    if (mlx5_qp_post_rdma_read(ctx->cm.dev, &ctx->cm.rc_qp, (void *)(uintptr_t)dst,
                                p->ksgl_len, p->ksgl_addr, p->ksgl_key) != 0) {
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
        if (p->opcode == NVME_ADM_CMD_IDENTIFY) {
            uint8_t cns = (uint8_t)(p->cdw10 & 0xFFu);
            src = (cns == NVME_IDENTIFY_CNS_CONTROLLER) ? ctx->ctrl->id_ctrl : ctx->ctrl->id_ns;
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

    if (ctx->stop_requested || self->cancel_requested) {
        if (ctx == &s_standalone_ctx)    s_standalone_resident = 0;
        if (ctx == &s_standalone_io_ctx) s_standalone_io_spawned = 0;
        return JOB_DONE;
    }

    switch (self->state) {

    case NVMETR_ST_CM_SPAWN: {
        ctx->cm.is_active = 0;
        ctx->cm.skip_ping = 1;
        if (ctx->queue_id == 0) {
            ctx->ctrl->ctrlr_id = 1;
            ctx->ctrl->cc = 0;
            ctx->ctrl->cc_en = 0;
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

    case NVMETR_ST_CM_WAIT: {
        if (ctx->cm.failed) {
            uart_printf("[!] nvmet-rdma: CM確立失敗\n");
            ctx->failed = 1;
            return JOB_DONE;
        }
        if (!ctx->cm.established) return JOB_WAITING;
        ctx->established = 1;
        uart_printf("[nvmet-rdma] RC QP確立完了 (qpn=%u queue_id=%u)\n", ctx->cm.rc_qp.qpn, ctx->queue_id);
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
        if (ctx->data_move_is_write) {
            const volatile uint8_t *src;
            uint32_t len = ctx->ksgl_len;
            if (ctx->opcode == NVME_ADM_CMD_IDENTIFY) {
                uint8_t cns = (uint8_t)(ctx->cdw10 & 0xFFu);
                src = (cns == NVME_IDENTIFY_CNS_CONTROLLER) ? ctx->ctrl->id_ctrl : ctx->ctrl->id_ns;
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
            if (!ctx->data_move_is_write) {
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
        uart_printf("[nvmet-rdma] パイプライン化ループ開始 (depth=%u)\n", NVMET_RDMA_MAX_PENDING);
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
                if (ctx->pl.pending[slot].data_inline &&
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
                        volatile_fast_copy(&ctx->ctrl->ram_disk[ip->io_slba * NVMET_RDMA_LBA_SIZE],
                                           &ctx->pl.recv_bufs[slot][64u + ip->inline_off],
                                           ip->ksgl_len);
                    }
                }
                if (ctx->pl.pending[slot].need_data_move) {
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
    if (!admin_ctx->enable_io_queue || s_standalone_io_spawned) return;

    for (uint32_t i = 0; i < sizeof(s_standalone_io_ctx); i++) {
        ((uint8_t *)&s_standalone_io_ctx)[i] = 0;
    }
    dcache_clean_range((const void *)&s_standalone_io_ctx, sizeof(s_standalone_io_ctx));

    static const uint8_t dummy_mac[6] = {0, 0, 0, 0, 0, 0};
    rdma_cm_fill_addr(&s_standalone_io_ctx.cm, admin_ctx->cm.dev, s_standalone_self_label,
                      "__no_such_net_ctx__", 0u, 0u, dummy_mac, s_standalone_peer_mac);
    /* fill_addr のゼロクリアの「後」に共有すること(先だと消える)。 */
    s_standalone_io_ctx.cm.gsi_qp      = admin_ctx->cm.gsi_qp;
    s_standalone_io_ctx.cm.reuse_gsi   = 1;
    s_standalone_io_ctx.cm.rc_qp_index = 1;
    s_standalone_io_ctx.cm.skip_ping   = 1;
    s_standalone_io_ctx.cm.is_active   = 0;
    s_standalone_io_ctx.ctrl           = admin_ctx->ctrl;  /* コントローラ状態は共有 */
    s_standalone_io_ctx.queue_id       = 1;
    s_standalone_io_ctx.pipeline_enabled = 1;

    job_t *io_job = job_spawn(nvmet_rdma_job_step, &s_standalone_io_ctx, "nvmet-rdma-io");
    if (!io_job) {
        uart_printf("[!] nvmet-rdma: IOキュー用ジョブ生成失敗(ジョブテーブル満杯)\n");
        return;
    }
    io_job->state = NVMETR_ST_CM_SPAWN;
    job_pin_to_core(io_job, 1u);
    s_standalone_io_spawned = 1;
    uart_printf("[nvmet-rdma] IOキュー用のCM listenerを起動しました(GSIはadminと共有)\n");
}

/*=================================================================
 * admin キューの切断を検出したときに 1 度だけ呼ばれる。NVMe-oF の意味論上、
 * admin が切れれば同じコントローラの IO キューも意味を失うので道連れにする。
 * GSI は admin 側が破棄するので、ここでは IO 自身の RC QP だけ返す。
 * ===============================================================*/
static void nvmetr_on_admin_disconnected(nvmet_rdma_ctx_t *admin_ctx)
{
    (void)admin_ctx;
    if (!s_standalone_io_spawned) return;
    nvmetr_destroy_qp_if_valid(s_standalone_io_ctx.cm.dev, &s_standalone_io_ctx.cm.rc_qp);
    s_standalone_io_ctx.stop_requested = 1;
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
void nvmet_rdma_run_standalone(mlx5_dev_t *dev, const char *self_label, const uint8_t peer_mac[6])
{
    if (s_standalone_resident && !s_standalone_ctx.failed &&
        s_standalone_resident_generation == dev->bringup_generation) {
        uart_printf("[nvmet-rdma] 既に%sで稼働中です(接続待ち、または処理中)\n", self_label);
        return;
    }
    if (s_standalone_resident) {
        /* 前回のジョブを確実に止めてから作り直す。止めずに spawn すると
         * 同一 ctx を 2 つのジョブが触る(RDMA CM の segfault と同型)。 */
        s_standalone_ctx.stop_requested = 1;
        if (s_standalone_io_spawned) s_standalone_io_ctx.stop_requested = 1;
        job_cancel_by_ctx(&s_standalone_ctx.cm);
        job_cancel_by_ctx(&s_standalone_io_ctx.cm);
        uint64_t t0 = timer_now();
        while (!timeout_ms(t0, 2000u)) job_scheduler_tick();
        if (s_standalone_io_spawned) {
            nvmetr_destroy_qp_if_valid(s_standalone_io_ctx.cm.dev, &s_standalone_io_ctx.cm.rc_qp);
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
    s_standalone_ctrl.ram_disk        = nvmetr_ramdisk_slot0();
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
    if (smp_boot_core1() == 0) job_pin_to_core(job, 1u);
    else uart_printf("[!] nvmet-rdma: core1起動に失敗、core0のまま動作します\n");

    s_standalone_resident            = 1;
    s_standalone_resident_generation = dev->bringup_generation;
    uart_printf("[nvmet-rdma] %s で常駐ターゲットを開始しました(外部ホストの接続待ち)\n",
                self_label);
}
