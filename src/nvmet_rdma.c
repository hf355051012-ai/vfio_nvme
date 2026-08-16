// nvmet_rdma.c
//
// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-
// lamport.md)フェーズ(g)、ターゲット側。既存nvmet.c(NVMe/TCP)には
// 一切触れず、完全に並行する新規実装として追加する(nvmet_rdma.h
// コメント参照)。
//
// 全ての多バイトフィールドアクセスはnet.hのrd16le/rd32le/rd64le/wr16le/
// wr32le/wr64le(volatile経由のバイト単位アクセス)のみを使う。send_buf/
// recv_buf/id_ctrl/id_ns/ram_diskはいずれもmlx5のSEND/RDMA_WRITE/RDMA_
// READのDMAソース/宛先になるため、直接の多バイトアクセス禁止という
// nvme_types.hの規約に加え、書き込み後は必ずdcache_clean_range()、
// HWが書いた後は必ずdcache_invalidate_range()が必要(cache.h、CLAUDE.md
// 「DMAコヒーレンシの落とし穴」節参照)。

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

/* nvme_rdma.c(ループバックinitiator)のジョブstep。nvmet_rdma_stop_all()が
 * pcie1 reset時に、万一残っているループバックの initiator ジョブも巻き込んで
 * 畳むために参照する -- nvme_rdma.hを引き込むと循環includeになりうるので
 * ここで前方宣言する(nvmet_rdma_job_step/rdma_cm_job_stepは自ヘッダ経由で
 * 既に可視)。 */
extern job_result_t nvme_rdma_connect_job_step(job_t *self);

/* nvmetrdmastartの常駐ターゲット用staticの前方宣言(実体の定義は下方、
 * nvmet_rdma_run_standalone()の直前)。nvmet_rdma_job_step()の停止
 * (cancel_requested)処理から、対応する常駐フラグをリセットして
 * `job stop`後でもnvmetrdmastartを再実行可能にするため、ここで参照する
 * (C11 6.9.2、同一型・初期化子無しの複数tentative定義は同一オブジェクトを
 * 指すため合法)。 */
static nvmet_rdma_ctx_t s_standalone_ctx;
static nvmet_rdma_ctx_t s_standalone_io_ctx;
static int s_standalone_resident;
static int s_standalone_io_spawned;

// CM(Communication Manager) DREQ/DREP属性ID(切断検出用、2026-08-13)。
// rdma_cm.cのCM_REQ_ATTR_ID等と同じ値の並び(include/rdma/ib_cm.h、
// 本セッションでssh経由の実機カーネルヘッダから確認済み:
// REQ=0x0010/MRA=0x0011/REJ=0x0012/REP=0x0013/RTU=0x0014/
// DREQ=0x0015/DREP=0x0016)。rdma_cm.cはこれらをprivateな#defineとして
// 持ち公開していないため、ここで必要な2つだけ複製する(既存のREQ/REP/
// RTU用#defineと同じ、ファイルごとに閉じた定義を持つという規約)。
#define CM_DREQ_ATTR_ID 0x0015u
#define CM_DREP_ATTR_ID 0x0016u
// rdma_cm.cのIB_CM_CLASS_VERSION(drivers/infiniband/core/cm_msgs.h)と
// 同値。同じくprivateな#defineのためここで複製する。
#define IB_CM_CLASS_VERSION 2u

/* nvmet_rdma_pl_pending_t/nvmet_rdma_pl_sqop_t/nvmet_rdma_pl_state_tは
 * nvmet_rdma.hへ移動済み(2026-08-13、IOキューのパイプライン対応 --
 * nvmet_rdma_ctx_tがpl(nvmet_rdma_pl_state_t)を埋め込みメンバとして
 * 持つため、ctx定義より前に見える必要がある)。 */

static void nvmetr_zero_v(volatile uint8_t *p, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) p[i] = 0;
}

/* 2026-08-13、RAMディスク拡張(1MB→64MB)に伴い新設: nvmetr_zero_v()の
 * 1バイトずつのvolatileループは、64MBのような大きい範囲では素朴すぎて
 * 遅い(ストア命令が1/8で済む8バイト単位に対し8倍の命令数)。呼び出し元は
 * pが8バイト境界に整列していること(ram_diskの固定物理アドレスは2MB
 * アラインのため常に満たす)・lenが8の倍数であることを保証すること。
 * volatile経由の明示的に整列済みの8バイトストアであるため、CLAUDE.md
 * 「ローカルスクラッチバッファへの逐次1バイト代入もvolatileが必須」節の
 * コンパイラ店舗結合バグ(非整列アドレスへの結合)は原理的に発生しない
 * (最初から整列済み8バイト単位でしか書かないため)。 */
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

// nvmet.cのnvmet_build_id_ctrl()/nvmet_build_id_ns()と同じバイト
// オフセット(実機確認済み、CLAUDE.md該当節参照)をそのまま踏襲する --
// RDMAトランスポート固有のIOCCSZ/IORCSZ(TCP capsuleサイズ専用)だけは
// 書かない(このプロジェクトの自作イニシエータ[nvme_rdma.c]はこれらを
// 読まないため)。MDTS=0(無制限、RDMAはWQE1個で任意長のRDMA_WRITE/READが
// 可能なためチャンク分割不要)。
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
    // **実機で発見(2026-08-13)**: bit0(NVME_CTRL_SGLS_BYTE_ALIGNED)だけでは
    // 不十分だった -- drivers/nvme/host/rdma.c(nvme_rdma_configure_io_queues())
    // が`ctrl->ctrl.sgls & NVME_CTRL_SGLS_KSDBDS`(bit2、include/linux/
    // nvme.hで確認済み、Keyed SGL Data Block Descriptor Supported)を
    // 明示的にチェックしており、これが立っていないと
    // 「Mandatory keyed sgls are not supported!」でIOキュー接続を拒否
    // される(RDMAトランスポートはWrite/ReadともにKeyed SGL経由でしか
    // データを転送しないため、TCPトランスポートでは不要だったこのビットが
    // RDMAでは必須)。
    wr32le(&ctx->ctrl->id_ctrl[536], 1u | (1u << 2));     /* SGLS bit0(byte-aligned) | bit2(KSDBDS) */
    {
        const char *subnqn = NVMET_RDMA_SUBNQN;
        uint32_t len = 0;
        while (subnqn[len] != '\0') len++;
        for (uint32_t i = 0; i < len; i++) ctx->ctrl->id_ctrl[768 + i] = (uint8_t)subnqn[i];
    }
    wr32le(&ctx->ctrl->id_ctrl[516], 1);                  /* NN: namespace count = 1 */
    ctx->ctrl->id_ctrl[512] = (6u << 4) | 6u;              /* SQES: 64バイト固定 */
    ctx->ctrl->id_ctrl[513] = (4u << 4) | 4u;              /* CQES: 16バイト固定 */
    // 2026-08-13、ユーザー指示によるiodepth拡大: 以前は固定値32のままで、
    // 当時のNVMET_RDMA_MAX_PENDING(8)を上回っていた(=ホストへ「実際より
    // 深いキューを受け付けられる」と偽って伝えていた不整合、fioの
    // iodepth>MAX_PENDING時の詰まりの一因になっていた可能性がある)。
    // NVMET_RDMA_MAX_PENDINGと一致させ、ホストへ伝える値と実際にパイプ
    // ライン化で処理できる深さを常に一致させる。
    wr16le(&ctx->ctrl->id_ctrl[514], (uint16_t)NVMET_RDMA_MAX_PENDING); /* MAXCMD */
    // **実機で発見(2026-08-13)**: IOCCSZ/IORCSZ/MSDBD(NVMe-oF Fabrics専用
    // フィールド、offset 1792以降、nvmet.cのnvmet_build_id_ctrl()と同じ
    // レイアウト -- ioccsz(4B)@1792, iorcsz(4B)@1796, msdbd(1B)@1803)を
    // 未設定(0)のままにしていたため、実LinuxホストのRC QP確立・admin
    // queue接続・Identify Controller/Namespaceは全て成功したにも関わらず、
    // IOキュー接続時にLinuxの`nvme_rdma_alloc_queue()`が
    // 「I/O queue command capsule supported size 0 < 4」で拒否していた
    // (自作イニシエータ[nvme_rdma.c]はこれらのフィールドを読まないため
    // ループバック検証では一度も顕在化しなかった)。RDMAトランスポートは
    // in-capsuleデータを一切使わない設計(write/read共にRDMA_READ/WRITEの
    // みでデータ移動、フェーズgの簡略化)のため、IOCCSZはSQE(64B)ちょうど
    // (=4、16バイト単位)、IORCSZはCQE(16B)ちょうど(=1)にする。
    wr32le(&ctx->ctrl->id_ctrl[1792], 64u / 16u);          /* IOCCSZ: SQE(64B)のみ、in-capsuleデータ無し */
    wr32le(&ctx->ctrl->id_ctrl[1796], NVME_CQE_LEN / 16u); /* IORCSZ: CQE(16B)分のみ */
    ctx->ctrl->id_ctrl[1803] = 1;                          /* MSDBD = 1 */
    dcache_clean_range((const void *)(uintptr_t)ctx->ctrl->id_ctrl, sizeof(ctx->ctrl->id_ctrl));
}

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

// Keyed SGL descriptor(nvme_types.hのnvme_keyed_sgl_desc_t参照)を
// 受信済みSQE(rb先頭64バイト)のdptrフィールド(相対offset24)から
// 読み取る。length は24bit LE(3バイト)。
static void nvmetr_parse_ksgl_into(const volatile uint8_t *rb, uint64_t *out_addr,
                                    uint32_t *out_len, uint32_t *out_key)
{
    const volatile uint8_t *dptr = &rb[24]; // nvme_sqe_t.dptrはSQE内offset24
    *out_addr = rd64le(&dptr[0]);
    *out_len  = (uint32_t)dptr[8] | ((uint32_t)dptr[9] << 8) | ((uint32_t)dptr[10] << 16);
    *out_key  = (uint32_t)dptr[11] | ((uint32_t)dptr[12] << 8) |
                ((uint32_t)dptr[13] << 16) | ((uint32_t)dptr[14] << 24);
}

// パイプライン化(下記PIPELINE_LOOP)導入時に、1コマンド分の解析結果を
// ctx(単一命令ぶんしか保持できない)ではなく任意のnvmet_rdma_pl_
// pending_t(複数コマンドを同時に保持できる配列の1要素)へ書けるよう、
// 解析ロジック自体をrb(受信バッファ)/pending出力先を引数にとる形へ
// 括り出した(2026-08-12、ユーザー指示「ソフトウェア処理をハード転送の
// 裏に完全に隠す」ため、CLAUDE.md「nvmermabenchのボトルネック切り分け」
// 節参照)。既存の単一コマンド逐次処理(nvmetr_dispatch(ctx)、下記)は
// このロジックを呼んだ後ctxへコピーするだけの薄いラッパへ変更した --
// 挙動そのものは一切変えていない(`nvmerdmaconnect`の回帰確認で保証)。
static void nvmetr_parse_command(nvmet_rdma_ctx_t *ctx, const volatile uint8_t *rb,
                                  nvmet_rdma_pl_pending_t *p)
{
    /* 実機でData Abort(Alignment fault, ESR=0x96000061)を確認 -- 通常の
     * フィールド単位代入だと-O2がopcode/fctype/nsid等の連続する小さい
     * フィールドを1回の8バイトストア(stur xzr, [x2, #2]のような、構造体
     * 先頭から2バイト目という非8バイト境界へのワイドストア)へ融合して
     * しまい、SCTLR.Aが有効なこの環境でフォルトする(CLAUDE.md「ローカル
     * スクラッチバッファへの逐次1バイト代入もvolatileが必須」節と同じ
     * 病理)。volatile経由のバイト単位ループ(既存nvmetr_zero_v())なら
     * コンパイラが結合できない。 */
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
            // Connect data(1024B)はrb[64..1087]にin-capsuleで届いている
            // (このMVPでは中身[hostnqn/subsysnqn]を検証しない、nvmet.c
            // の既存方針と同じ最小実装)。
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
                /* CAP(Controller Capabilities、8バイト、attrib=1で要求
                 * される)。nvmet.c(NVMe/TCP、CLAUDE.md「NVMe/TCP write
                 * 性能低下の真因確定」節とは別の、Property Get CAPの
                 * バグ)で既に発見・修正済みの同型のバグがnvmet_rdma.c
                 * には移植されていなかった -- dw0=0のまま返すと
                 * MQES(dw0 bits[15:0]、0's based)が実質0(=1エントリ)
                 * になり、実Linuxホストのdmesgに"queue_size 128 > ctrl
                 * sqsize 1, clamping down"と出てIOキュー確立が失敗する
                 * (2026-08-13実機で再現・確定)。nvmet.cと同じ値を使う:
                 * dw0: MQES=0xFF(256エントリ)、TO=0x1E(15秒)。
                 * dw1: CSS(NVM command set対応)ビットを立てる。 */
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
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key);
        p->need_data_move = 1;
        p->data_move_is_write = 1; // ターゲット->ホストへRDMA_WRITEで押し込む
    } else if (p->opcode == NVME_ADM_CMD_SET_FEATURES) {
        // 値そのものは無視(nvmet.cのnvmet_build_set_features_num_
        // queues_sqe()相当、応答は成功のみ)。
    } else if (p->opcode == NVME_IO_CMD_READ) {
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key);
        p->io_slba = (uint64_t)p->cdw10 | ((uint64_t)p->cdw11 << 32);
        uint32_t nlb = (p->cdw12 & 0xFFFFu) + 1u;
        uint64_t end_lba = p->io_slba + nlb;
        /* フェーズ(h)追加: WRITEブランチ(下記)と同じ境界チェック。
         * ksgl_lenはホストが自己申告する値(nvme_rdma.cのnvmer_build_io()
         * がnlbと一致させて送るため通常は一致するが、target側で信頼せず
         * 独立に検証する -- ram_diskのバッファオーバーフローを防ぐ)。 */
        if (end_lba > NVMET_RDMA_NS_LBA_COUNT ||
            (uint64_t)nlb * NVMET_RDMA_LBA_SIZE > NVMET_RDMA_RAMDISK_SLOT_SIZE ||
            p->ksgl_len > (uint64_t)nlb * NVMET_RDMA_LBA_SIZE) {
            p->resp_status = NVMET_RDMA_SC_ERROR;
            return;
        }
        p->need_data_move = 1;
        p->data_move_is_write = 1;
    } else if (p->opcode == NVME_IO_CMD_WRITE) {
        nvmetr_parse_ksgl_into(rb, &p->ksgl_addr, &p->ksgl_len, &p->ksgl_key);
        p->io_slba = (uint64_t)p->cdw10 | ((uint64_t)p->cdw11 << 32);
        uint32_t nlb = (p->cdw12 & 0xFFFFu) + 1u;
        uint64_t end_lba = p->io_slba + nlb;
        if (end_lba > NVMET_RDMA_NS_LBA_COUNT ||
            (uint64_t)nlb * NVMET_RDMA_LBA_SIZE > NVMET_RDMA_RAMDISK_SLOT_SIZE) {
            p->resp_status = NVMET_RDMA_SC_ERROR;
            return;
        }
        p->need_data_move = 1;
        p->data_move_is_write = 0; // ホストからRDMA_READで引き込む
    } else {
        p->resp_status = NVMET_RDMA_SC_ERROR;
    }
}

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

// 受信済みコマンド(ctx->recv_buf)を解釈し、応答内容(resp_dw0/resp_status)
// と必要ならデータ移動(need_data_move/data_move_is_write)を決定する
// (単一コマンド逐次処理[NVMETR_ST_WAIT_CAPSULE]専用、nvmetr_parse_
// command()の薄いラッパ)。
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
    ctx->data_move_is_write = p.data_move_is_write;
    ctx->resp_dw0 = p.resp_dw0;
    ctx->resp_dw1 = p.resp_dw1;
    ctx->resp_status = p.resp_status;
}

static void nvmetr_build_resp_capsule(nvmet_rdma_ctx_t *ctx)
{
    nvmetr_build_resp_capsule_into(ctx->send_buf, ctx->resp_dw0, ctx->resp_dw1, ctx->cid, ctx->resp_status);
}

// 2026-08-13、切断検出用。特定の静的状態(s_standalone_*)には依存しない
// 汎用ヘルパのため、`nvmet_rdma_job_step()`より前(このファイルの先頭寄り)
// に置く -- 元は"standalone"専用のつもりでファイル末尾にあったが、
// nvmetr_reset_admin_for_reconnect()からも参照するためここへ移動した
// (呼び出しのたびに新しいQP/PD/MKey/CQを積み増すと数回でFWリソースが
// 枯渇する、CLAUDE.md「nvmermabenchの接続再利用機構」節参照)。
static void nvmetr_destroy_qp_if_valid(mlx5_dev_t *dev, mlx5_qp_t *qp)
{
    if (dev != NULL && qp->qpn != 0) {
        mlx5_qp_destroy(dev, qp);
    }
}

// DREP MAD(Table 113)を組み立てる。LOCAL_COMM_ID=自分自身のcomm_id、
// REMOTE_COMM_ID=受信したDREQのLOCAL_COMM_IDをそのままecho(drivers/
// infiniband/core/cm.cのcm_issue_drep()と同じフィールド対応、本セッション
// でssh経由の実機カーネルソースから確認済み)。tidはDREQ自身のMADヘッダの
// tidを踏襲する -- REQ/REP/RTUの一連の交換で使うctx->cm.tidとは無関係の、
// DREQ/DREP専用の新しいtransaction。
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

// admin queue(queue_id==0)の切断(DREQ受信、またはRC QP CQEエラー)を
// 検出した際に呼ぶ。RC/GSI QPをFW側から解放し、ペアのIOキュー
// (on_disconnected経由、設定されていれば)も道連れに終了させた上で、
// 次のホスト接続を待てる状態(新しい"cm" job)へ戻す。
//
// ram_disk(ctx->ctrl->ram_disk)には一切触れない -- nvmet.c(NVMe/TCP
// トランスポート)のnvmet_io_job_end()が切断時にram_diskを保持するのと
// 同じ設計(CLAUDE.md「nvmet: 常駐サーバ化」節参照、切断のたびにディスク
// 内容が消えるのは実ディスクとして不自然)。NVMETR_ST_CM_SPAWNを再利用
// しない理由もこれ -- あちらは「電源投入後の初回確立」を想定してram_disk
// を丸ごとゼロクリアする設計であり、再接続のたびに同じ経路を通すと
// ディスク内容が消えてしまう。
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

    // rdma_cm_fill_addr()はctx->cm全体をゼロクリアしてから再設定する
    // (ctx->cm.establishedもここで0へ戻る) -- ctx自身の他フィールド
    // (ctrl/pipeline_enabled/queue_id/enable_io_queue/on_established/
    // on_disconnected/self_label/peer_mac_fallback)には一切触れない。
    rdma_cm_fill_addr(&ctx->cm, dev, self_label, "__no_such_net_ctx__", 0u, 0u,
                      dummy_mac, peer_mac_fallback);
    ctx->cm.is_active = 0;
    ctx->cm.skip_ping = 1;
    ctx->established = 0;
    ctx->failed = 0;

    // 新しいセッションのためコントローラ状態だけリセットする(nvmet.cの
    // nvmet_io_job_end()と同じ考え方: CC/CSTS.RDY相当だけ未接続状態へ
    // 戻す、ram_diskは保持)。
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

// admin queue(queue_id==0、GSIを所有する側)のNVMETR_ST_PIPELINE_LOOPから
// 毎tick呼ばれる。GSI CQを1件だけ非ブロッキングでポーリングし、CM DREQ
// (このctx宛のもの、REMOTE_COMM_ID/REMOTE_QPN_EECNで照合)を検出したら
// DREPを送り返し、切断処理(nvmetr_reset_admin_for_reconnect())を行う。
// 戻り値: 1=切断処理を行った(呼び出し元はこのtickをそこで終える)、
// 0=何もしなかった(呼び出し元は通常のPIPELINE_LOOP処理を続ける)。
//
// self_label==NULL(nvme_rdma.cのループバック検証ctx)の場合は常に0を
// 返す即座リターン -- この監視機構は`nvmetrdmastart`(実ホスト接続)
// 専用で、ループバックの`stop_requested`ベースの終了フローには一切
// 影響しない。rtu_phase_done==0(まだ"cm" jobがRTU処理中で、GSIへ
// もう1個RECV WQEを構え終えていない)の間も同様に即座リターンする
// (rdma_cm.cの該当コメント参照 -- ここでポーリングを始めると"cm" job
// 自身が受信中のRTUを横取りする競合を招く)。
static int nvmetr_check_gsi_disconnect(nvmet_rdma_ctx_t *ctx, job_t *self)
{
    if (ctx->queue_id != 0 || ctx->self_label == NULL || !ctx->cm.rtu_phase_done) {
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
        // 別接続宛のDREQ(この設計では単一クライアント前提のため通常は
        // 起きないはずだが、念のため無視して再度RECVを構える)。
        mlx5_qp_post_recv_gsi(ctx->cm.dev, ctx->cm.gsi_qp, (void *)(uintptr_t)ctx->cm.recv_buf,
                              sizeof(ctx->cm.recv_buf));
        return 0;
    }

    uart_printf("[nvmet-rdma] CM DREQ受信 (comm_id=0x%08x) -- DREP送信、次の接続を待つ状態へ戻ります\n",
                ctx->cm.local_comm_id);
    nvmetr_build_drep(ctx, dreq_tid, dreq_local_comm_id);
    dcache_clean_range((const void *)(uintptr_t)ctx->cm.send_buf, sizeof(ctx->cm.send_buf));
    // ベストエフォート送信(戻り値未確認) -- 失敗してもホスト側は自身の
    // DREQリトライ/タイムアウトで結局ローカルに後始末するため、DREP
    // 送達を確認できなくてもこちら側のリセット処理は続行してよい
    // (nvmet.cの「送信中の再送失敗が続いていればこのエラー応答自体も
    // 同じ理由で失敗しうる -- ベストエフォート」という既存方針と同じ)。
    mlx5_qp_post_send_ud(ctx->cm.dev, ctx->cm.gsi_qp, (const void *)(uintptr_t)ctx->cm.send_buf,
                         RDMA_CM_MAD_SIZE, 1u /* GSI宛は常にQPN=1固定[フェーズd] */,
                         IB_QP1_QKEY, ctx->cm.peer_gid, ctx->cm.peer_mac);

    nvmetr_reset_admin_for_reconnect(ctx, self);
    return 1;
}

/* ================================================================
 * コマンドパイプライン化(2026-08-12、ユーザー指示 -- 「ソフトウェア
 * 処理がハード転送の裏に完全に隠れるようにする」ための設計。CLAUDE.md
 * 「nvmermabenchのボトルネック切り分け」節で確認した通り、256KBの
 * 往復時間の約92%は既にRDMA_WRITE/READのデータ移動そのものに費やされて
 * おり、残り約8%(1コマンドあたり約62us、固定オーバーヘッド)を
 * パイプライン化(複数コマンドを同時にoutstandingにし、コマンドNの
 * データ移動がハードウェア上で進行している間にコマンドN+1のSQE構築/
 * 応答capsule送信等のソフトウェア処理を並行して進める)で隠すのが
 * 目的。8KBのような小さいI/Oでは固定オーバーヘッドの比率が7割超と
 * 大きいため、ここでの改善効果はより顕著に出る見込み。
 *
 * `ctx->pipeline_enabled`が真の場合のみ経由する(既定は偽、
 * `nvmerdmaconnect`の既存の単一コマンド逐次処理[NVMETR_ST_POST_RECV〜
 * NVMETR_ST_WAIT_RESP_SENT]は一切変更していない)。
 *
 * 設計: NVMET_RDMA_MAX_PENDING個の「保留中コマンド」スロットを持つ。
 * 各スロットは専用のRECVバッファ(ctx->pl.recv_bufs[i])・応答capsule
 * 送信バッファ(ctx->pl.resp_bufs[i])を持つ(複数コマンドが同時に
 * outstandingになるため、単一のctx->recv_buf/send_bufでは足りない)。
 * RC QPのRQ完了・SQ完了はいずれも「WQEを投稿した順に届く」というIBTA
 * 仕様上の保証があるため、投稿順を記録するFIFO(ctx->pl.rq_order/
 * sq_ops)を持つだけで、CQEが届くたびに「どのスロットの、どの操作が
 * 完了したか」を追跡できる(cidベースの照合は不要 -- 投稿順とFIFO
 * 消費順が常に一致するため)。SQは「データ移動(RDMA_WRITE/READ)」と
 * 「応答capsule SEND」の2種類の操作を共有するため、FIFOの各エントリに
 * 操作種別(is_resp_send)を記録しておき、完了時にどちらだったかを
 * 判別する。
 *
 * 2026-08-13、IOキューのパイプライン対応: 上記の状態(pending/recv_bufs/
 * resp_bufs/rq_order/sq_ops/rra_*)は当初ファイルスコープのstatic配列
 * だったため、admin queueとIOキューが同時にpipeline_enabled=1になると
 * 同じ配列を取り合って破壊し合っていた(実機で発見: 実ホストからfioで
 * write/readを行うと、IOキュー側が単一コマンド逐次処理[pipeline_
 * enabled=0]のまま複数コマンドを同時に受けられず、RQバッファ枯渇による
 * リトライで1コマンドあたり数秒の遅延が発生していた)。`nvmet_rdma_pl_
 * state_t`(nvmet_rdma.h)として`nvmet_rdma_ctx_t`の埋め込みメンバ
 * (ctx->pl)へ移動したことで、1接続=1RC QP=1ctxごとに完全に独立した
 * パイプライン状態を持つようになり、admin/IO双方が同時に
 * pipeline_enabled=1でも安全に動作する。
 * ================================================================ */

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

// 戻り値: 0=即時発行成功(SQ op投稿済み)、1=RRA上限のためキューへ保留
// (呼び出し元は何もせず次回のRDMA_READ完了を待つ)、-1=失敗。
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

static int nvmetr_pl_send_response(nvmet_rdma_ctx_t *ctx, unsigned slot)
{
    nvmet_rdma_pl_pending_t *p = &ctx->pl.pending[slot];
    nvmetr_build_resp_capsule_into(ctx->pl.resp_bufs[slot], p->resp_dw0, p->resp_dw1, p->cid, p->resp_status);
    if (mlx5_qp_post_send(ctx->cm.dev, &ctx->cm.rc_qp, (const void *)(uintptr_t)ctx->pl.resp_bufs[slot],
                          NVME_CQE_LEN) != 0) {
        return -1;
    }
    ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].is_resp_send = 1;
    ctx->pl.sq_ops[ctx->pl.sq_tail % (NVMET_RDMA_MAX_PENDING * 2u)].slot = slot;
    ctx->pl.sq_tail++;
    return 0;
}

job_result_t nvmet_rdma_job_step(job_t *self)
{
    nvmet_rdma_ctx_t *ctx = (nvmet_rdma_ctx_t *)self->ctx;

    /* 停止要求(nvmet_rdma.hコメント参照)はどのステートでも即座に受理
     * する -- どうせ次の再実行前にpcie1 resetでハードウェア状態ごと
     * リセットされる想定のため、進行中のRDMA操作を放棄しても実害は
     * 無い。重要なのはjob.hの共有ジョブテーブルからこのエントリを
     * 確実に取り除くこと(次回spawnとの重複を防ぐ)。self->cancel_requested
     * は`job stop <番号>`/RoCEv2一括停止(job_cancel_all_by_step()、
     * pcie1 resetから)経由。 */
    if (ctx->stop_requested || self->cancel_requested) {
        /* 常駐ターゲット(standalone/IOキュー)自身が停止する場合は、
         * 対応する常駐フラグも落としておく -- そうしないと`job stop`で
         * ジョブを消しても s_standalone_resident が1のまま残り、次の
         * nvmetrdmastartが「既に稼働中です」と誤判定して再武装しない。
         * pcie1 resetのnvmet_rdma_stop_all()も同じフラグを落とすが、
         * `job stop`単独(pcie1 resetを挟まない)経路のためここでも行う。
         * ループバックのs_target_ctx等、常駐ではないctxはここに該当しない
         * (ポインタ比較で判別)。 */
        if (ctx == &s_standalone_ctx)    s_standalone_resident = 0;
        if (ctx == &s_standalone_io_ctx) s_standalone_io_spawned = 0;
        return JOB_DONE;
    }

    switch (self->state) {

    case NVMETR_ST_CM_SPAWN: {
        ctx->cm.is_active = 0;
        ctx->cm.skip_ping = 1;
        // フェーズ(i)続報: コントローラ状態(id_ctrl/id_ns/ram_disk/cc/
        // cc_en/ctrlr_id)はqueue_id==0(admin queue)の時だけ初期化する --
        // queue_id==1(IOキュー)はctx->ctrlをadmin queueと共有しており
        // (nvmet_rdma_run_standalone()参照)、ここで再初期化するとadmin
        // queueが既に確立したCC.EN状態やIdentify応答内容を消してしまう。
        // nvme_rdma.cのループバックctx(s_target_ctx)は常にqueue_id==0の
        // ままなので、この変更による既存動作への影響は無い。
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
            // 直前の応答capsule SEND完了通知(WAIT_RESP_SENTを経ずここへ
            // 来ることは無いはずだが、念のため読み捨てて継続する)。
            return JOB_WAITING;
        }
        dcache_invalidate_range((const void *)(uintptr_t)ctx->recv_buf, recv_len);
        ctx->recv_len = recv_len;
        nvmetr_dispatch(ctx);
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
                // WRITEコマンド: RDMA_READで受信したデータは既にram_disk
                // の該当位置へ直接届いている(post_rdma_read()のlocal_buf
                // がその位置を直接指しているため、コピー不要)。CPUが
                // 読むのはこの後(将来readバックする際)なのでここでの
                // invalidateは必須ではないが、直後に同じ領域を別コマンド
                // (read)が参照しうるため安全側に倒す。
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
        ctx->pl.rra_max = mlx5_qp_max_concurrent_rdma_read(ctx->cm.dev);
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
        /* 2026-08-13、切断検出(実機で発見: `nvme disconnect`後もこの
         * ステートに永久に留まり続け、次の`nvme connect`がハングする
         * バグの修正、nvmet_rdma.hの「切断検出」節コメント参照)。RC QPの
         * CQEドレインより前に、GSI(CM)側でホストからのDREQが届いていない
         * かを確認する -- 届いていれば切断処理へ分岐しこのtickを終える。 */
        if (nvmetr_check_gsi_disconnect(ctx, self)) {
            return ctx->failed ? JOB_DONE : JOB_WAITING;
        }

        /* 1tickにつき、CQリング上に既に届いている完了を空になるまで処理
         * する(上限付き -- 際限なく1tickを専有しないため、SQ+RQ合計の
         * 理論最大件数で十分)。 */
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
                /* 2026-08-13追加: admin queue(GSIを所有する側)のRC QPが
                 * エラーCQEを出した場合、単に諦める(ctx->failed=1で
                 * JOB_DONE、以後誰も次の接続を受け付けない)のではなく
                 * DREQ検出と同じ「次のホスト接続を待つ」状態へ自動復帰
                 * する -- タスクの想定「RC QPのエラー状態遷移も切断の
                 * シグナルとして扱う」に対応する。ループバックctx
                 * (self_label==NULL)とIOキュー(queue_id==1)は対象外
                 * (既存動作のまま、nvmermabench/nvmerdmaconnectの
                 * stop_requestedベースの終了フローに影響しない)。 */
                if (ctx->queue_id == 0 && ctx->self_label != NULL) {
                    uart_printf("[!] nvmet-rdma: RC QPエラーを切断とみなし、次の接続を待ちます\n");
                    nvmetr_reset_admin_for_reconnect(ctx, self);
                    return ctx->failed ? JOB_DONE : JOB_WAITING;
                }
                ctx->failed = 1;
                return JOB_DONE;
            }

            if (!is_send) {
                /* 新規コマンド到着(RQ完了)。ctx->pl.rq_orderの先頭が、この
                 * 完了が実際に書き込んだ物理バッファ(ctx->pl.recv_bufs[slot])
                 * を示す -- RC QPのRQ完了は投稿順に届くため(IBTA仕様)。 */
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
                    /* 2026-08-12、ユーザー指示「NVMeコマンドを受信した
                     * ときのtimestampも追加してほしい」-- 新規コマンドを
                     * 実際にparseした瞬間を記録する。SQ_RDMA_READ/CQEの
                     * タイムスタンプと突き合わせることで、同時に何コマンド
                     * 受信済み(=RQ完了済みだがまだデータ移動未着手)かを
                     * 直接確認できる。 */
                    volatile ts_rdma_t ts_cmd = {0};
                    ts_cmd.rdma_op = TS_RDMA_OP_CMD_RECV;
                    ts_cmd.wqe_cqe_opcode = ctx->pl.pending[slot].opcode;
                    ts_cmd.qpn = ctx->cm.rc_qp.qpn;
                    ts_cmd.counter = ctx->cm.rc_qp.rq_pc;
                    ts_cmd.remote_addr = ctx->pl.pending[slot].cid;
                    ts_cmd.len = ctx->pl.pending[slot].ksgl_len;
                    ts_log_rdma(TS_MK(TS_FILE_NVMET_RDMA, TS_FUNC_nvmet_rdma_job_step, 0), &ts_cmd);
                }
                if (ctx->pl.pending[slot].need_data_move) {
                    /* 0=即時発行、1=RRA上限のため保留(何もしない、後で
                     * nvmetr_pl_issue_rdma_read()経由で拾われる)、
                     * -1=失敗。 */
                    int dm_rc = nvmetr_pl_start_data_move(ctx, slot);
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
                /* SQ完了(RDMA_WRITE/READ、または応答capsule SEND)。
                 * ctx->pl.sq_opsの先頭がどちらの操作かを示す(同じくSQ
                 * 完了は投稿順に届く)。 */
                if (ctx->pl.sq_head == ctx->pl.sq_tail) {
                    uart_printf("[!] nvmet-rdma pipeline: 予期しないSQ完了\n");
                    ctx->failed = 1;
                    return JOB_DONE;
                }
                nvmet_rdma_pl_sqop_t op = ctx->pl.sq_ops[ctx->pl.sq_head % (NVMET_RDMA_MAX_PENDING * 2u)];
                ctx->pl.sq_head++;
                if (!op.is_resp_send) {
                    /* RDMA_WRITE/READ完了 -> 応答capsuleを送る。 */
                    if (!ctx->pl.pending[op.slot].data_move_is_write) {
                        /* WRITE: RDMA_READで受信したデータは既にram_disk
                         * の該当位置へ直接届いている(post_rdma_read()の
                         * local_bufがその位置を直接指しているためコピー
                         * 不要)。単一コマンド版[WAIT_DATA_MOVE]と同じ
                         * 理由で安全側にinvalidateしておく。 */
                        dcache_invalidate_range(
                            (const void *)(uintptr_t)&ctx->ctrl->ram_disk[
                                ctx->pl.pending[op.slot].io_slba * NVMET_RDMA_LBA_SIZE],
                            ctx->pl.pending[op.slot].ksgl_len);
                        /* このRDMA_READの枠が1つ空いた -- RRA上限で保留
                         * していたスロットがあれば次の1件を発行する
                         * (nvmetr_pl_start_data_move()コメント参照)。 */
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

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(i): `nvmetrdmastart`シェル
// コマンド用の常駐target(nvmet_rdma.hコメント参照)。s_target_ctx
// (nvme_rdma.c、ループバック検証用)とは完全に独立した専用インスタンスを
// ここに置く -- `nvmerdmaconnect`/`nvmermabench`と同時に使っても競合
// しない。
static nvmet_rdma_ctx_t s_standalone_ctx;      // admin queue(queue_id=0)
static int s_standalone_resident;

// フェーズ(i)続報(2026-08-13): IOキュー(qid=1相当)用の2本目のRC QP接続。
// admin queueのCM確立完了(NVMETR_ST_CM_WAIT)を検知した直後に
// nvmetr_on_admin_established()がspawnする。self_label/peer_macは
// nvmet_rdma_run_standalone()の呼び出し時点でしか分からない(コール
// バックには`self`[admin ctx]しか渡らない)ため、ここに保存しておく。
static nvmet_rdma_ctx_t s_standalone_io_ctx;
static int s_standalone_io_spawned;
