// nvmet.c
//
// NVMe/TCPターゲット側プロトコル層 -- SQEの解釈とCQEの組み立て。
// PDU/TCPの詳細はnvmet_tcp.c(移植境界、CLAUDE.md参照)に委譲する。
// イニシエータ側nvme.cと対になるレイヤ構成。
//
// 全ての多バイトフィールドアクセスはnet.hのrd16le/rd32le/rd64le/wr16le/
// wr32le/wr64le(volatile経由のバイト単位アクセス)のみを使う(nvme_types.h
// のコメント参照 -- NVMeはリトルエンディアン)。

#include <stddef.h>
#include "nvmet.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "job.h"
#include "tcp.h"
#include "rxcopy.h"

/* push vs pull の同一(非digest)トラフィックA/B比較用の試験トグル
 * (検証後に撤去)。1なら非digest接続でも従来のpull型RX(copy2+copy3の
 * 二重コピー)を使う。command.cの`nvmetpull <0|1>`で切替、次の接続から。 */
int g_nvmet_force_pull = 0;
void nvmet_set_force_pull(int on) { g_nvmet_force_pull = on ? 1 : 0; }
int  nvmet_get_force_pull(void)   { return g_nvmet_force_pull; }

/* セッション確立(accept待ち・ICReq受信)の許容時間。ジョブ化(job.h、
 * CLAUDE.md「NVMe/TCP制御のステートマシン化」節参照)後もこの段階だけは
 * 明示的な締め切りを持たせる -- 確立済み後の定常ループ(コマンド受信
 * 待ち)には締め切りを設けない設計に変更した(下記admin/io job本体の
 * コメント参照)。 */
#define NVMET_ACCEPT_TIMEOUT_MS    30000u

/* Admin queueが受信するin-capsuleデータ(Fabrics Connectのペイロード、
 * 1024バイト固定)を格納するバッファの容量。中身(hostnqn/subsysnqn等)は
 * 検証しない(doc記載の最小実装方針 -- qidフィールドだけを見る)ため、
 * 既存のNVME_TCP_INLINE_DATA_MAX(nvme_types.h)を流用する。 */
#define NVMET_ADMIN_DATA_BUF_MAX NVME_TCP_INLINE_DATA_MAX

/* IO queueが受信するin-capsule/H2Cデータの最大容量。Identify Controllerの
 * MDTS(nvmet.hのNVMET_MAX_TRANSFER_BYTES、nvmet_build_id_ctrl()参照)と
 * 整合させる -- 行儀の良いホストはMDTSを超える転送を1コマンドで発行
 * しないため、これで十分(2026-07-25: 256KB化に合わせて65536→262144)。 */
#define NVMET_IO_DATA_BUF_MAX NVMET_MAX_TRANSFER_BYTES

/* Property Set/GetでCC.EN=0の間にIOコマンドが来た場合、および範囲外
 * アクセスを拒否する際に使う汎用エラーステータス(nvmet_impl.md記載の
 * 値、CQEのstatusフィールドへそのままwr16leする生の16bit値 -- bit0=
 * phase tag=0、bits[8:1]=SC=0x01=Invalid Command Opcode相当)。 */
#define NVMET_SC_GENERIC_ERROR 0x0002u

/* RAMディスク本体・Identify Controller/Namespaceの応答データは、複数
 * インスタンス(RP1+ConnectX PF0/PF1)を完全に独立させるためnvmet_ctx_t
 * のフィールド(ctx->ram_disk/id_ctrl/id_ns、nvmet.h参照)へ移した。CPUが
 * 直接read/writeするだけでGEMのDMAには触れないため.dma_bss不要(nvmet_
 * impl.md参照)。id_ctrl/id_nsの内容は固定(RAMディスクサイズ等、セッション
 * をまたいで変わらない)なのでnvmet_job_start()の最初に一度だけ構築する。 */

static void nvmet_zero(void *p, size_t len)
{
    uint8_t *b = p;
    for (size_t i = 0; i < len; i++) b[i] = 0;
}

/* srcをdstへfield_lenバイトの空間へコピーし、余った分は空白(' ')で
 * 埋める(NVMeの文字列フィールドの慣行 -- VID/SN/MN/FR等)。バイト単位の
 * コピー自体はvolatile_fast_copy()で行う(nvmet_impl.md指定)。srcは
 * 呼び出し元(このファイル内)がリテラルをその場で渡す関数引数であり、
 * static/constグローバルにポインタとして保持するわけではないため
 * PIE安全性の制約(COMMANDS[]の先例、CLAUDE.md参照)には抵触しない。 */
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

static void nvmet_build_id_ctrl(nvmet_ctx_t *ctx)
{
    nvmet_zero(ctx->id_ctrl, sizeof(ctx->id_ctrl));
    wr16le(&ctx->id_ctrl[0], 0x1AF4);                                       /* VID (Red Hatで代用) */
    nvmet_copy_padded(&ctx->id_ctrl[4],  "RPI5-NVMET", 20);                 /* SN [4..23] */
    nvmet_copy_padded(&ctx->id_ctrl[24], "RPi5 Bare-Metal NVMe Target", 40); /* MN [24..63] */
    nvmet_copy_padded(&ctx->id_ctrl[64], "1.0", 8);                         /* FR [64..71] */
    /* MDTS: nvmet_impl.mdはoffset 76と記載しているが、それはCMIC
     * フィールド(offset 76)であり、実際のMDTSはoffset 77
     * (edk2 MdePkg/Include/IndustryStandard/Nvme.hのNVME_ADMIN_CONTROLLER_DATA、
     * Linuxのstruct nvme_id_ctrlと突き合わせ確認済み -- Cmic(1B)@76の
     * 直後にMdts(1B)@77)。offset 76のままだとCMICへ4(bit2=ANA reporting)
     * を誤って立ててしまい、ホストが未実装のANA関連コマンドを送ってくる
     * 恐れがあるため、ここではoffset 77に修正して書く(nvmet_impl.mdも
     * 同時に修正済み)。
     * 値自体はNVMET_MAX_TRANSFER_BYTES(nvmet.h参照)と整合させること --
     * 2^MDTS * 4096 = NVMET_MAX_TRANSFER_BYTESとなるMDTSを書く
     * (262144 = 2^6 * 4096なのでMDTS=6)。 */
    ctx->id_ctrl[77] = 6;                       /* MDTS = 6 (2^6 * 4KB = 256KB、NVMET_MAX_TRANSFER_BYTES参照) */

    /* CNTLID(offset 78、2バイト)。実際のLinuxカーネルソース
     * (drivers/nvme/host/core.c の nvme_check_ctrl_fabric_info())を
     * 直接取得して確認した結果発見した本物のバグ -- KAS/SGLS/NN等を
     * 修正した後も実機で全く同じ症状(Identify Controller受信直後に
     * ホストがFIN、nvme connect自体は"Invalid argument"で失敗)が
     * 再現し続けたため、推測ではなくカーネルソースを直接取りに行った。
     * nvme_check_ctrl_fabric_info()が最初に行うチェックが
     * 「ctrl->cntlid(Fabrics ConnectのCQE.dw0から来る) != id->cntlid
     * (Identify Controller自身のこのフィールド)」であり、一致しないと
     * "Mismatching cntlid"としてこのチェック*だけ*で即座にEINVALで
     * 拒否される(KAS等それ以降のチェックより前にあるため、KAS修正が
     * 一度もテストされる機会が無かった)。ctx->ctrlr_idは固定値1
     * (nvmet.h参照)なので、ここでも同じ1を書く。 */
    wr16le(&ctx->id_ctrl[78], 1);                /* CNTLID = 1 (ctx->ctrlr_idと一致させる) */

    ctx->id_ctrl[111] = 1;                      /* CNTRLTYPE = 1 (I/O controller) */

    /* KAS(Keep Alive Support, offset 320, 2バイト, 100ms単位)。
     * nvmet_impl.mdはこのフィールドに触れていなかったため0のまま
     * (nvmet_zero()の初期値)だった。実機のnvme-tcpホストで接続検証した
     * ところ、Fabrics Connect/CC有効化/CSTS.RDY確認/Identify Controller
     * まで全て成功するのに、Identify Controller応答を受け取った直後に
     * ホストがFIN→RSTで即切断する事象を確認した -- Wiresharkキャプチャで
     * 他に一切エラー応答が無いことから、TCP層ではなくホスト側のIdentify
     * Controllerデータ内容の検証で弾かれていると判断した。Linuxの
     * nvme_init_ctrl_finish()(drivers/nvme/host/core.c)はfabricsコントローラ
     * に対しKAS==0を"keep-alive support is mandatory for fabrics"として
     * 明示的にEINVALで拒否する仕様になっており、症状と完全に一致する。
     * 値そのもの(granularity)は本実装がKeep Aliveコマンドを処理しない
     * ため実質的に意味を持たないが、0以外であることが必須。 */
    wr16le(&ctx->id_ctrl[320], 2);               /* KAS = 2 (200ms単位、値自体は非0であれば可) */

    /* SGLS(SGL Support, offset 536, 4バイト)。bit0=SGL対応 -- NVMe-oFは
     * 全コマンドでSGLのみを使うため、ファブリクスコントローラは必ず
     * bit0を立てる仕様(NVMe Base Spec)。KASと同様nvmet_impl.mdに記載が
     * 無く見落としていた。 */
    wr32le(&ctx->id_ctrl[536], 1u);              /* SGLS bit0 = SGL Supported */

    /* SUBNQN(NVM Subsystem NQN, offset 768, 256バイト、NUL終端)。
     * ctx->id_ctrlは全ゼロ初期化済みなので、文字列本体だけコピーすれば
     * 残りは自然にゼロ埋め(NUL終端)される -- SN/MN/FRのような空白埋め
     * ではない点に注意(nvmet_copy_padded()は使わない)。 */
    {
        const char *subnqn = NVMET_SUBNQN;
        uint32_t len = 0;
        while (subnqn[len] != '\0') len++;
        volatile_fast_copy(&ctx->id_ctrl[768], (const volatile uint8_t *)subnqn, len);
    }

    /* NN(Number of Namespaces, offset 516、4バイト)。nvmet_impl.mdは
     * offset 512と記載していたが、edk2 Nvme.hのNVME_ADMIN_CONTROLLER_DATA
     * で確認したところ512-515はSqes(1B)+Cqes(1B)+Maxcmd(2B)であり、NNは
     * その直後の516から。512に書くとこれら3フィールドを破壊した上で
     * NN自体は0のまま(namespace無し)残ってしまっていた。 */
    wr32le(&ctx->id_ctrl[516], 1);               /* NN: namespace count = 1 */

    /* SQES/CQES(offset 512/513、各1バイト、bits[3:0]=min bits[7:4]=max、
     * 2のべき乗指数)。NVMe/TCPクライアント(nvme.c)・ターゲット双方が
     * 使うSQE=64B(2^6)/CQE=16B(2^4)に合わせてmin=maxで固定する。 */
    ctx->id_ctrl[512] = (6u << 4) | 6u;          /* SQES: 64バイト固定 */
    ctx->id_ctrl[513] = (4u << 4) | 4u;          /* CQES: 16バイト固定 */

    /* MAXCMD(Maximum Outstanding Commands, offset 514、2バイト)。
     * KAS/SGLS修正後も実機でIdentify Controller応答受信直後にホストが
     * FIN→RSTで切断する事象が再現したため追加調査した結果発見 --
     * Linuxのnvme_init_ctrl_finish()(drivers/nvme/host/core.c)は
     * fabricsコントローラに対しicdoff/ioccsz/iorcsz/maxcmd/sgls/kasを
     * まとめてidから読み取っており(KASの明示的なEINVALチェックと同じ
     * ブロック)、MAXCMD=0のままだと後続のコマンドタグ管理の初期化
     * (キュー深度に応じた配列/ビットマップ確保)がゼロサイズになり
     * 失敗する可能性が高い。自クライアント(nvme.c)のNVME_QSIZE(32)に
     * 合わせておく。 */
    wr16le(&ctx->id_ctrl[514], 32);              /* MAXCMD = 32 */

    /* IOCCSZ/IORCSZ/MSDBD(NVMe-oF Fabrics専用フィールド、offset 1792
     * 以降 -- edk2 Nvme.hのRsvd8[256]("Reserved for NVMe over Fabrics
     * Spec")がこの領域に相当し、edk2ヘッダには個別フィールドの定義が
     * 無かったため、Linux実カーネルのstruct nvme_id_ctrl(rsvd1024[768]
     * の直後、offset 1792から: ioccsz(4B)@1792, iorcsz(4B)@1796,
     * icdoff(2B)@1800, ctrattr(1B)@1802, msdbd(1B)@1803)のレイアウトに
     * 合わせる。ICDOFF/CTRATTRは実ターゲット(Linux nvmet)も0がデフォルト
     * なのでそのままでよいが、IOCCSZ/IORCSZ/MSDBDは0のままだと
     * Command/Response Capsuleサイズが実質ゼロと解釈されうるため
     * 明示的に設定する。 */
    /* IOCCSZ: SQE(64B)+in-capsuleで受け付けるデータの上限。
     * NVMET_MAX_TRANSFER_BYTES(MDTS、1コマンド全体の上限)ではなく
     * NVMET_IOCCSZ_MAX_BYTES(nvmet.h参照、意図的にMDTSより小さく保つ
     * in-capsule専用の上限)を使うこと -- 以前はNVMET_MAX_TRANSFER_BYTESを
     * そのまま使っており、その結果MDTS以下の書き込みは常にin-capsule
     * 上限にも収まってしまいR2T+H2CDataが一度も使われないことが判明した
     * (2026-07-25)。IOCCSZをMDTSより小さく保つことで、それを超える書き
     * 込みはホストがin-capsuleを諦めてR2T+H2CDataへ切り替え、
     * nvmet_io_loop()がctx->pending_writes[]経由で受信する(Window Scaling
     * 導入後はNVMET_MAX_TRANSFER_BYTES=256KBまで1ラウンドで完結する、
     * nvmet.hコメント参照)。 */
    wr32le(&ctx->id_ctrl[1792], (64u + NVMET_IOCCSZ_MAX_BYTES) / 16u);
    wr32le(&ctx->id_ctrl[1796], NVME_CQE_LEN / 16u);                   /* IORCSZ: CQE(16B)分のみ */
    ctx->id_ctrl[1803] = 1;                      /* MSDBD = 1 */
}

static void nvmet_build_id_ns(nvmet_ctx_t *ctx)
{
    nvmet_zero(ctx->id_ns, sizeof(ctx->id_ns));
    wr64le(&ctx->id_ns[0],  NVMET_NS_LBA_COUNT);  /* NSZE */
    wr64le(&ctx->id_ns[8],  NVMET_NS_LBA_COUNT);  /* NCAP */
    wr64le(&ctx->id_ns[16], 0);                   /* NUSE */
    ctx->id_ns[26]  = 0;                          /* FLBAS: LBA Format Index = 0 */
    ctx->id_ns[130] = 9;                          /* LBAF[0].ds = 9 (512B = 2^9) */
}

/* CQEの組み立て共通ルール(nvmet_impl.md参照)。cidは呼び出し元が明示的に
 * 渡す(2026-07-25、IOキューのパイプライン対応でconn->last_cidから変更
 * -- IOキューは複数コマンドが同時にoutstandingになりうるため、
 * "直前に受信したコマンドのCID"という共有フィールドはこのCQEが実際に
 * どのコマンドへの応答かと一致する保証が無くなった。adminキューの
 * 呼び出し元は引き続きctx->admin.last_cidを渡せばよい(adminは1コマンド
 * ずつ同期処理なので有効)。nvmet_tcp.h冒頭コメントの経緯参照。 */
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

/* Admin queueの1コマンド(受信済みSQE)を解釈し応答する共通ディスパッチ。
 * Fabrics Connect(qid=0)/Property Set/Property Get/Identify/
 * Set Features/Keep Aliveを処理する。nvmet_admin_loop()(admin queue
 * 確立直後、Set Features応答まで)とnvmet_admin_service_pending()
 * (IOキュー確立後、セッション終了まで)の両方から呼ぶ -- 実機の
 * Linux nvme-tcpホストはIOキュー確立後もIdentify Namespace等を
 * admin queue経由で送ってくること、KATO(デフォルト5秒)による
 * Keep Aliveが定期的に届くことを実機で確認した
 * (nvmet_impl.mdの「IOキュー確立後もadmin queueのKeep Aliveには
 * 応答し続けること」参照) -- このディスパッチはセッション全体を
 * 通じて利用可能である必要がある。
 * 戻り値: 1=Set Features(Number of Queues)への応答完了(admin
 *         コマンドループを抜けてIOキュー接続待ちへ進んでよい合図、
 *         nvmet_admin_loop()専用の意味 -- nvmet_admin_service_
 *         pending()側は無視してよい)、0=それ以外。 */
static int nvmet_admin_dispatch(nvmet_ctx_t *ctx, const nvme_sqe_t *sqe)
{
    uint32_t   opcode = rd32le(&sqe->cdw0) & 0xFFu;
    nvme_cqe_t cqe;

    /* NADP: admin queueコマンドのディスパッチ(argはopcode、下位8bitに
     * 実行時のみFabricsコマンドのfctypeを追加で読んで詰め直す下記参照)。
     * これでIO queue側のイベント(IORD/IOWR等)と混ざっても、この時刻に
     * 「admin側でKeep Alive(opcode=0x18)を処理していた」等が明確に
     * わかる -- 200ms/5msタイムアウトの並びだけでは admin/io の
     * どちらのイベントか判別できなかった問題への対処(このファイルの
     * 性能分析で必要になった、timestamp.h参照)。 */
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
                nvmet_build_cqe(&cqe, ctx->admin.last_cid, 1u, 0);
                uart_printf("[nvmet:%s] Fabrics Connect (qid=0, admin) 受理 (ctrlr_id=1)\n", ctx->label);
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
                uart_printf("[nvmet:%s] Property Set: CC=0x%x (EN=%d)\n", ctx->label, ctx->cc, ctx->cc_en);
            }
            nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, 0);
            nvmet_tcp_send_resp(&ctx->admin, &cqe);
        } else if (fctype == NVME_FABRIC_FCTYPE_PROPERTY_GET) {
            uint32_t offset = rd32le(&sqe->cdw11);
            if (offset == NVME_REG_CAP) {
                /* CAP(Controller Capabilities, 8バイト、attrib=1で
                 * 要求される)。当初はdw0=0のまま返しており、
                 * MQES(dw0 bits[15:0]、0's based)が実質0(=1エントリ)
                 * になってしまっていた -- 実機のdmesgで
                 * "queue_size 128 > ctrl sqsize 1, clamping down"
                 * と出て、ホストが自身のI/Oキューサイズを1エントリ
                 * まで強制的に縮めてしまい、IOキューのICReq/ICResp
                 * 成功直後の接続断につながっていたと判明した
                 * (本物のバグ)。
                 * dw0: MQES=0xFF(0's based、256エントリ)、
                 *      CQR=0(contiguous queues不要)、AMS=0(round
                 *      robinのみ)、TO=0x1E(15秒、500ms単位)。
                 * dw1: CSSフィールド(bit37、dw1内ではbit5)= 1
                 *      (NVM command set対応) -- 0のままだと
                 *      「対応するコマンドセットが無い」ことになり
                 *      これも別途拒否理由になりうるため設定。
                 *      DSTRD/MPSMIN/MPSMAX等その他は0(標準4KBページ
                 *      等)のままで問題ない。 */
                uint32_t cap_lo = 0xFFu | (0x1Eu << 24);
                nvmet_build_cqe(&cqe, ctx->admin.last_cid, cap_lo, 0);
                wr32le(&cqe.dw1, 0x20u);
                nvmet_tcp_send_resp(&ctx->admin, &cqe);
            } else {
                uint32_t value = 0;
                if (offset == NVME_REG_CC) {
                    value = ctx->cc;
                } else if (offset == NVME_REG_CSTS) {
                    value = ctx->cc_en ? NVME_CSTS_RDY : 0u;
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
            nvmet_tcp_send_c2h(&ctx->admin, ctx->admin.last_cid, &cqe, ctx->id_ctrl, sizeof(ctx->id_ctrl), 1);
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
            /* CQE.dw0: bits[15:0]=NSQA(Number of Submission Queues
             * Allocated), bits[31:16]=NCQA(...Completion...)。
             * いずれも0's based(値N=実際にはN+1個)であり、要求cdw11
             * の符号化と同じ規約 -- 当初0x00010001(NSQA=1,NCQA=1)を
             * 返していたが、これは0's basedであるため実際には
             * 「IO SQ/CQ各2本を許可」を意味していた。実機のLinux
             * nvme-tcpホストはこれを真に受けて2本目のIOキュー用TCP
             * 接続を開こうとし(本実装は最初からIOキュー1本しか
             * accept()しない設計のため)、2本目が永遠に応答されず
             * 全体がタイムアウトする事象をWiresharkキャプチャで
             * 確認した。0's basedで「1本」を許可するには値0
             * (NSQA=0,NCQA=0)を返す必要がある。 */
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

    uart_printf("[!] nvmet: 未対応のadminコマンド (opcode=0x%x)\n", opcode);
    nvmet_build_cqe(&cqe, ctx->admin.last_cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
    nvmet_tcp_send_resp(&ctx->admin, &cqe);
    return 0;
}

/* ================================================================
 * admin queueのジョブ化(job.h、CLAUDE.md「NVMe/TCP制御のステートマシン
 * 化」節参照)。旧nvmet_admin_loop()(Set Features応答までの1回きりの
 * ループ)とnvmet_admin_service_pending()(IOキュー確立後、旧
 * nvmet_io_loop()から間引いてポーリングされていたKeep Alive/Identify
 * 処理)を、この1本の常駐ジョブへ統合した -- admin job自身が毎tick
 * (非ブロッキング)ループするため、間引き(旧NVMET_ADMIN_CHECK_
 * INTERVAL_MS)のハックが丸ごと不要になった。
 *
 * 状態遷移: ARM(listen+accept準備)→ACCEPT_WAIT→ICREQ_RECV→ICRESP_SEND→
 * [RECV_HDR→RECV_SQE→[RECV_HDGST]→[RECV_DATA]→[RECV_DDGST]→DISPATCH]の
 * 無限ループ。DISPATCHがSet Features(Number of Queues)への応答完了を
 * 検出した時点でctx->io_armedを立て、io job(下記)がIOキューのaccept/
 * ICReq処理へ進む。
 *
 * ACCEPT_WAIT(誰も接続してきていない待受)にはタイムアウトを設けない
 * (常駐サーバ化、CLAUDE.md「nvmet: 常駐サーバ化」節参照) -- クライアント
 * が現れるまで何分でも待ち続けるのが正常な状態のため。ICREQ_RECV
 * (TCP接続済み・ICReq未着)のみ明示的な締め切り(NVMET_ACCEPT_TIMEOUT_MS、
 * accept完了時刻から数え直す)を持つ -- 一度TCP接続してきたのにICReqを
 * 送ってこない壊れたクライアントを無期限には待たない、という protocol
 * レベルの安全弁。確立後の定常ループには締め切りを設けない -- KeepAlive/
 * Identify等がいつ届くかは相手(ホスト)次第であり、受信途中
 * (nvmet_tcp_recv_poll()がWAITINGを返す間)はヘッダ/SQE/データの一部を
 * 既にTCPストリームから消費済みの場合があるため、タイムアウトで安易に
 * 状態をリセットするとストリームdesyncを招く(nvmet_tcp_recv_exact()の
 * got>0時の扱いと同じ理由、CLAUDE.md「`nvmet_tcp_recv_exact()`:
 * 部分受信後のタイムアウトで〜」節参照)。Ctrl+C中断/FIN受信による
 * エラー(r<0)も、進行中の受信状態を破棄せず同じstateに留まって次tickに
 * 再試行する設計にした -- Ctrl+Cは一時的(バイトを消費しない)、FINは
 * `nvmet_tcp_recv_poll()`が一度返した後は以後恒久的にWAITING相当を
 * 返すだけで実害無く静止する(admin queueだけ相手都合で閉じられた場合、
 * io queueが生きていればセッション全体は継続し、io jobがセッション終了
 * を検出した時点でctx->session_doneを見てこのジョブもARM状態へ戻る
 * -- 常駐サーバ化により、旧来の「このジョブも終了する」から「次の
 * クライアントを待つ状態へ戻る」へ変更した)。
 *
 * **常駐サーバ化**(2026-08-02): 以前はクライアントとのセッションが
 * 終了する(切断・エラー・タイムアウト)たびに、admin/io両ジョブとも
 * JOB_DONEで完全に終了し、次のクライアントを受け付けるには`nvmet
 * <port>`をユーザーが再度手動実行する必要があった。ConnectXループ
 * バック検証で「毎回タイムアウト前に手早く操作しないと接続できない」
 * という運用上の不便が繰り返し発生したことを受け、**サーバ自体は
 * セッション終了後も停止せず、自動的に次のクライアントを待つ状態へ
 * 戻る**設計に変更した。停止する唯一の方法は、クライアントが一切
 * 接続していない待受状態(NADM_ST_ACCEPT_WAIT)でのCtrl+C -- セッション
 * 中(クライアント接続中)のCtrl+Cは、そのセッションだけを中断して
 * 次のクライアント待ちへ戻る(サーバ自体は止まらない)。 */
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

/* stateprof.h向けの人間可読なステート名(nvmet_admin_state_tと同じ
 * 並び順)。 */
static const char *const NADM_STATE_NAMES[] = {
    "ARM", "ACCEPT_WAIT", "ICREQ_RECV", "ICRESP_SEND",
    "RECV_HDR", "RECV_SQE", "RECV_HDGST", "RECV_DATA",
    "RECV_DDGST", "DISPATCH",
};
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
} nvmet_admin_job_ctx_t;

/* インスタンス(nvmet_ctx_t)ごとのジョブコンテキストプール(job.hの
 * ctx引数は生存期間の長い実体を要求するため、mallocの無いこの環境では
 * 固定配列で持つ -- CLAUDE.md「NVMe/TCP制御のステートマシン化」節と
 * 同じ考え方)。s_instance_owner[]がスロットとnvmet_ctx_tの対応を追跡
 * する: 同じctxで再度nvmet_job_start()が呼ばれた場合(Ctrl+Cで完全停止
 * した後の再起動)は前回と同じスロットを再利用し、初めてのctxなら空き
 * スロットを新規に割り当てる(nvmet_job_start()参照)。 */
static nvmet_admin_job_ctx_t s_admin_job_pool[NVMET_MAX_INSTANCES];

/* セッション確立段階での失敗(ICReqタイムアウト・受信失敗・ICResp送信
 * 失敗)。io jobはまだctx->io_armedを見ていない(=IOキューには一切
 * 触れていない、NIO_ST_WAIT_ADMIN_READYで待機中)前提で、admin側の
 * 後始末だけを行い、**サーバ自体は停止せず**次のクライアントを待つ
 * ARM状態へ直接戻る(常駐サーバ化、CLAUDE.md「nvmet: 常駐サーバ化」
 * 節参照)。io job側への信号(ctx->admin_failed等)は不要 -- io jobは
 * io_armedが立つのを待っているだけで、admin が何回このARM〜ICRESP_
 * SENDをやり直そうと無関係に待ち続けられるため。
 *
 * これとは別に、「一度もクライアントが接続してこないままCtrl+Cが
 * 押された」場合(NADM_ST_ACCEPT_WAIT)は、サーバ自体を停止する扱いに
 * している(そちらは本関数を経由せず、その場でctx->admin_failedを
 * 立ててJOB_DONEする、下記参照)。 */
static job_result_t nvmet_admin_job_setup_fail(job_t *self, nvmet_ctx_t *ctx)
{
    nvmet_tcp_close(&ctx->admin);
    /* ctx->listenerはここでは解除しない -- nvmet_io_job_end()の同種
     * コメント参照(このインスタンス専用のリスナーはインスタンスの
     * 生存期間中ずっと保持し、ARM状態で使い回す)。 */
    self->state = NADM_ST_ARM;
    return JOB_WAITING;
}

static job_result_t nvmet_admin_job_step(job_t *self)
{
    nvmet_admin_job_ctx_t *jc  = (nvmet_admin_job_ctx_t *)self->ctx;
    nvmet_ctx_t            *ctx = jc->ctx;

    /* stateprof.h -- このステートに何回・合計どれだけ滞在したかを記録
     * する(呼ばれるたびに毎回、switchより前で)。 */
    state_prof_mark(&ctx->admin_prof, self->state);

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
            /* ICReqタイムアウトの基準を「実際に接続確立した時刻」から
             * 数え直す -- ACCEPT_WAITはタイムアウト無しで何分でも待ち
             * うるため、ARM開始時刻のまま(古いwait_started_ticks)だと
             * 接続直後に即座にタイムアウト扱いになりかねない。 */
            jc->wait_started_ticks = timer_now();
            self->state = NADM_ST_ICREQ_RECV;
            return JOB_WAITING;
        }
        /* 誰も接続してこないまま待ち続けるのは常駐サーバとして正常な
         * 状態なのでタイムアウトは設けない(CLAUDE.md「nvmet: 常駐
         * サーバ化」節参照)。サーバの停止は`job stop <番号>`(job.hの
         * job_request_cancel())だけで行う -- このadmin job自身が指定
         * された場合(self->cancel_requested)、または対のio jobが指定
         * されそちらからリレーされた場合(ctx->stop_requested、
         * nvmet_io_job_step()参照)。
         *
         * 【2026-08-05、意図的にCtrl+Cを外した】以前はtcp_abort_
         * requested()もこのOR条件に含めていたが、telnetセッションから
         * 押したCtrl+C(グローバルな1個のフラグ、どのコネクション/
         * ジョブが押したかを区別しない)が、たまたまその瞬間ACCEPT_WAIT
         * で待機中だった無関係なnvmetインスタンスを巻き添えで完全停止
         * させてしまう、という分かりにくい副作用があった。`job stop`を
         * 導入した今、サーバの明示的な停止手段はそちらに一本化し、
         * Ctrl+Cは(shell_line_poll()やtcp_send()の再送ループ等、他の
         * 既存の意味のまま)ここでは一切見ないことにした。 */
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
        /* IOキュー用の受け皿をここ(admin自身のICResp送信完了直後、
         * admin コマンドループが始まる前)で立てる -- 旧nvmet_run()が
         * nvmet_admin_loop()を呼ぶより前にnvmet_tcp_accept_arm(&ctx->io,
         * port)を呼んでいたのと同じタイミング(tcp.hのtcp_accept_begin()
         * コメント参照: 早着SYNの取りこぼし防止)。io jobはこの合図で
         * ARM状態へ進み、以後admin jobのコマンドループ(Property Set/Get・
         * Identify・Set Features)と完全に並行してIOキューのTCP
         * ハンドシェイク/ICReq/ICRespを進められる -- Set Features応答
         * 完了を待つ必要はない(host側のIOキュー確立自体はadmin側の
         * プロパティネゴシエーションの完了に依存しないため)。 */
        ctx->io_armed = 1;
        nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
        self->state = NADM_ST_RECV_HDR;
        return JOB_WAITING;

    case NADM_ST_RECV_HDR: {
        if (ctx->session_done) { ctx->session_done = 0; self->state = NADM_ST_ARM; return JOB_WAITING; }  /* io jobがセッションを終了させた -- 常駐継続のためARMへ戻る */
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
        if (ctx->session_done) { ctx->session_done = 0; self->state = NADM_ST_ARM; return JOB_WAITING; }
        int r = nvmet_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0 || r == 0) return JOB_WAITING;

        jc->dlen = nvmet_tcp_parse_cmd_dlen(&ctx->admin, jc->hdr_buf);
        if (jc->dlen > NVMET_ADMIN_DATA_BUF_MAX) {
            /* in-capsuleデータが呼び出し側バッファ(jc->data_buf)を超過 --
             * 旧nvmet_tcp_recv_cmd_body()のdata_buf_maxチェックと同じ
             * 防御(dlenを信頼してそのままjc->data_bufへ受信すると
             * バッファオーバーフローになる)。データ本体は受信せず、
             * 次のヘッダから仕切り直す(admin loopは寛容設計、上記
             * コメント参照)。 */
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
        if (ctx->session_done) { ctx->session_done = 0; self->state = NADM_ST_ARM; return JOB_WAITING; }
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
        if (ctx->session_done) { ctx->session_done = 0; self->state = NADM_ST_ARM; return JOB_WAITING; }
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
        if (ctx->session_done) { ctx->session_done = 0; self->state = NADM_ST_ARM; return JOB_WAITING; }
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
        if (ctx->session_done) { ctx->session_done = 0; self->state = NADM_ST_ARM; return JOB_WAITING; }
        nvme_sqe_t sqe;
        volatile_fast_copy((volatile uint8_t *)&sqe,
                            (const volatile uint8_t *)jc->sqe_buf, NVME_SQE_LEN);
        ctx->admin.last_cid = rd16le(&jc->sqe_buf[2]);  /* adminは1コマンドずつ同期処理のためこれで正しい */

        /* NRCV: Command Capsule PDU(admin queue)の受信完了(ヘッダ+SQE+
         * [ダイジェスト]+[in-capsuleデータ]、この収束点=NADM_ST_DISPATCH
         * への到達で確定)。IO queueのCMD/H2CDataと同じタグで記録する --
         * pdu_typeフィールドで種別を区別するのでFile/Func のmaskで
         * admin/IO両キューの受信完了を時系列に追える。SGLディスクリプタ
         * (sqe.dptr、offset24-39、nvme_types.hのnvme_sgl_desc_t参照)の
         * len(offset32、4B)はコマンド全体の転送量(IORD/IOWRのnlb*LBA_SIZE/
         * write_lenと同じ値、SQE受信時点で既に判明済み)、type(offset39)は
         * in-capsule(0x01)/transport(0x5A)の区別。 */
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

        if (nvmet_admin_dispatch(ctx, &sqe)) {
            /* io_armedは既にICRESP_SEND完了時点で立てている(上記コメント
             * 参照) -- ここではログのみ。 */
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

/* IO queueのコマンドループ。Fabrics Connect(qid=1)/Read/Writeを処理する。
 * イニシエーターが切断するまでブロックし続ける -- これがnvmet_run()の
 * 「切断まで戻らない」という仕様の実体。
 * 戻り値: 0=切断(セッションの正常終了)、-1=Ctrl+C中断またはdesync検出。
 *
 * 2026-07-25、パイプライン対応(nvmet_tcp.h冒頭コメントの経緯も参照):
 * 実機の256KB書き込みテストで、R2T送信直後に次のPDUとして届いたのが
 * そのH2CDataではなく別の書き込みコマンドのCapsule Command PDUだった
 * ためストリームdesyncする事象を確認した -- ホストがR2T往復の完了を
 * 待たず複数の書き込みコマンドをパイプライン発行していたことが原因
 * (Window Scalingでウィンドウが広がり、以前より先行送信が進みやすく
 * なって顕在化した)。これはNVMe-oFとして正当な挙動であり、
 * 「1コマンドずつ完全に同期処理する」という以前の設計を捨てる必要が
 * あった。
 *
 * 新設計: nvmet_tcp_recv_pdu_type()で次に来るPDUの種別だけを見て、
 * CMD(新規コマンド)ならその場で処理する(READ/in-capsule WRITE/エラー系
 * は即座に応答、non-in-capsule WRITEはR2Tを送るだけで応答を待たず
 * ループ先頭へ戻る)。H2C_DATA(先行するR2Tへの応答)ならcccidで対応する
 * outstandingな書き込み(ctx->pending_writes[])を探してデータを組み込み、
 * 全ラウンド完了していれば確定応答する。複数の書き込みコマンドが同時に
 * outstandingになれる(最大NVMET_MAX_PENDING_WRITES件、超過分は即座に
 * エラー応答で拒否する -- ストリームは壊さない)。読み出しコマンドは
 * こちらが送るだけでホストからの追加データ待ちが無いため、元々この
 * 問題の対象外(CMD受信からC2HData送信までを1回のループ反復内で完結
 * させたままでよい)。
 *
 * 書き込みパイプライン追跡状態(write_incapsule_count/write_h2c_count/
 * pending_writes[])は複数インスタンス(RP1+ConnectX PF0/PF1)が同時に
 * outstandingな書き込みを持ちうるため、ファイルスコープstaticではなく
 * nvmet_ctx_tのフィールド(nvmet.h参照)へ移した。NVMET_MAX_PENDING_WRITES/
 * nvmet_pending_write_tもnvmet.hへ移動済み。 */

static int nvmet_pending_write_alloc(nvmet_ctx_t *ctx)
{
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        if (!ctx->pending_writes[i].in_use) return (int)i;
    }
    return -1;
}

static int nvmet_pending_write_find(nvmet_ctx_t *ctx, uint16_t cid)
{
    for (unsigned i = 0; i < NVMET_MAX_PENDING_WRITES; i++) {
        if (ctx->pending_writes[i].in_use && ctx->pending_writes[i].cid == cid) return (int)i;
    }
    return -1;
}

/* デバッグ用: IOキューでストリームdesyncらしき異常(想定外のPDU種別、
 * 未知のcccid、datao不一致等)を検出した際にTCP層の詳細状態をUARTへ
 * 出力する。tcp_debug_dump_rx()(tcp.c、2026-07-25にこのクラスのバグの
 * 調査用に追加)を使う -- 呼び出し元は出力後、通常のエラー応答+続行では
 * なく即座にセッションを終了してシェルへ戻ること(`md`コマンド等で
 * さらにメモリ状態を確認できるようにするため)。 */
static void nvmet_io_debug_desync(nvmet_ctx_t *ctx, const char *reason)
{
    uart_printf("\n[DEBUG] ==== IOキューdesync検出: %s ====\n", reason);
    tcp_debug_dump_rx(&ctx->io.tcp);
    uart_printf("[DEBUG] ==== ここまで ====\n\n");
}

/* ================================================================
 * IO queueのジョブ化(job.h、CLAUDE.md「NVMe/TCP制御のステートマシン化」
 * 節参照)。旧nvmet_io_loop()の「CMD/H2C_DATA PDUをインターリーブして
 * 受け付けるパイプライン対応ループ」という設計自体(2026-07-25、
 * nvmet_tcp.h冒頭コメントの経緯参照)は変更せず、内部の各ブロッキング
 * 受信/接続待ちだけを状態遷移へ置き換える。CMD/H2C_DATAのディスパッチ
 * 本体(SQE解釈・CQE組み立て・ctx->pending_writes[]操作)は旧nvmet_io_loop()
 * から可能な限りそのまま移植した(ロジック自体は変更していない)。
 *
 * admin job(上記)がctx->io_armedを立てた時点(admin自身のICResp送信完了
 * 直後、Set Features応答を待たない -- 上記NADM_ST_ICRESP_SENDコメント
 * 参照)でARM状態へ進む。
 *
 * 定常ループ(RECV_PDU_HDR以降)には明示的な締め切りを設けない(admin job
 * と同じ設計判断、上記コメント参照)。受信エラー(r<0、abort/FIN)は
 * nvmet_io_job_recv_fail()で一元的に処理する: abort中なら
 * (tcp_clear_abort_request()込みで)セッション終了、そうでなければ
 * ctx->io.tcp.stateで実際の切断を確認しセッション終了、いずれでもなければ
 * (稀なケース)次のPDUヘッダから仕切り直す。この仕切り直しは、部分受信
 * 済みバイトを破棄する点で理論上ストリームdesyncのリスクを伴うが、
 * abort/FINは元のnvmet_tcp_recv_exact()も(got>0でも)同様に即座に諦める
 * 設計だった(CLAUDE.md「部分受信後のタイムアウトで〜」節参照、あちらは
 * タイムアウト起因のdesyncバグが対象でabort/FIN起因は元から対象外)ため、
 * 挙動は実質的に旧設計を踏襲している。 */
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
    /* push型受信(inline upcall、非digest接続、2026-08-13)。ICResp送信後、
     * 非digest接続ではupcallを登録してこの状態へ移り、以降のRX(ヘッダ/SQE
     * 解析+in-capsule writeデータのram_disk直接配置)はtcp_input()→upcall
     * (nvmet_io_rx_upcall())がストリームとして行う。この状態のjobは
     * ready-ring(upcallが積む完成コマンド)を取り出してdispatch(応答送信、
     * net_poll外で実行=再入回避)するだけ。digest接続は従来通り上記の
     * pull型RXステートを使う。 */
    NIO_ST_PUSH_RUN,
} nvmet_io_state_t;

/* stateprof.h向けの人間可読なステート名(nvmet_io_state_tと同じ並び順)。 */
static const char *const NIO_STATE_NAMES[] = {
    "WAIT_ADMIN_READY", "ARM", "ACCEPT_WAIT", "ICREQ_RECV", "ICRESP_SEND",
    "RECV_PDU_HDR", "RECV_CMD_SQE", "RECV_CMD_HDGST", "RECV_CMD_DATA",
    "RECV_CMD_DDGST", "DISPATCH_CMD", "RECV_H2C_REST", "RECV_H2C_HDGST",
    "RECV_H2C_DATA", "RECV_H2C_DDGST", "DISPATCH_H2C", "PUSH_RUN",
};
#define NIO_STATE_NAME_COUNT (sizeof(NIO_STATE_NAMES) / sizeof(NIO_STATE_NAMES[0]))

/* push型受信のパーサ相(nvmet_io_rx_upcall()、2026-08-13)。 */
typedef enum { PRX_HDR, PRX_PSH, PRX_DATA } nvmet_prx_phase_t;

/* ready-ring 1件。upcall(RX)が完成した1コマンド/1 H2Cラウンドを積み、
 * jobがdispatch(応答送信)する。送信はjob側=net_poll外で行い、upcall内
 * (net_poll再入コンテキスト)からは送信しない(再入爆発の回避)。 */
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
    uint32_t  copy_wm;   /* RXコピーオフロード時: このコマンドの全データコピーが
                          * 完了する rxcopy submitted seq。dispatch(CQE)は
                          * rxcopy_done()がこれに達してから(rxcopy.h参照)。 */
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
    /* in-capsule書き込みのゼロコピー受信先(2026-08-13、CLAUDE.md「write
     * パイプライン化」節の3段目コピー削減)。RECV_CMD_SQEでWRITEのin-capsule
     * データの受信先を決める -- slba/nlbの範囲検証を通ればcmd_data_dstを
     * ram_disk[slba]へ向け(incap_write_committed=1)、data_bufステージングを
     * 介さず直接受信する(R2T+H2CData経路が既に採用している方式と同じ)。
     * 非WRITEコマンド(Fabrics Connectのconnectデータ等)や範囲外/不整合な
     * writeはdata_bufへ受信する(incap_write_committed=0、DISPATCHが通常処理
     * またはエラー応答)。 */
    uint8_t          *cmd_data_dst;
    int               incap_write_committed;
    uint8_t           data_buf[NVMET_IO_DATA_BUF_MAX] __attribute__((aligned(64)));

    /* push型受信(inline upcall、非digest接続、2026-08-13)。push_mode=1なら
     * RXはupcall(nvmet_io_rx_upcall())がストリームとして処理し、jobは
     * ready-ringをdispatchするだけ(上記NIO_ST_PUSH_RUN参照)。prx_*はupcall
     * のパーサ状態(コネクション全体で1つ、複数tick/upcall呼び出しをまたぐ)。 */
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
    uint32_t          prx_copy_wm;           /* RXコピーオフロード時: このPDUのデータコピーの最新 rxcopy submitted seq */
    volatile int      prx_error;             /* パース致命エラー(ring溢れ/未知PDU等) */
    nvmet_ready_t     ready[NVMET_READY_RING];
    volatile uint32_t ready_head;            /* upcallが積む(生産) */
    volatile uint32_t ready_tail;            /* jobが取り出す(消費) */
} nvmet_io_job_ctx_t;

static nvmet_io_job_ctx_t s_io_job_pool[NVMET_MAX_INSTANCES];

/* s_admin_job_pool[]/s_io_job_pool[]の各スロットが現在どのnvmet_ctx_t
 * (常駐サーバインスタンス)に割り当てられているか。NULL=空き
 * (nvmet_job_start()参照)。 */
static nvmet_ctx_t *s_instance_owner[NVMET_MAX_INSTANCES];

/* セッション終了の一元処理。close_io: ctx->ioのTCPハンドシェイクが
 * 既に完了している(=tcp_close()が必要)ならtrue、accept待ち中/
 * タイムアウト等で一度もESTABLISHEDに達していないならfalse。
 *
 * 常駐サーバ化(CLAUDE.md「nvmet: 常駐サーバ化」節参照)により、
 * **サーバ自体は停止せず**、このセッションの後始末をした上で次の
 * クライアントを待つ状態(io job自身はNIO_ST_WAIT_ADMIN_READY)へ
 * 直接戻る。admin job(呼び出し時点でどのstateにいるか不定 -- 定常
 * ループの途中の可能性がある)へは`ctx->session_done`で「今のセッション
 * は終わったので、次のクライアントへ向けてARMし直せ」と伝える(admin
 * job側の各`session_done`チェック箇所を参照)。`ctx->session_active`は
 * 「サーバが稼働中」を表す常駐フラグとして1のまま維持する(Ctrl+Cに
 * よる完全停止時のみ0に戻す、NADM_ST_ACCEPT_WAIT/NIO_ST_WAIT_ADMIN_
 * READY参照)。 */
static job_result_t nvmet_io_job_end(job_t *self, nvmet_ctx_t *ctx, int close_io, const char *reason)
{
    uart_printf("[nvmet:%s] write内訳: in-capsule=%u件 R2T+H2CData=%u件\n",
                ctx->label, ctx->write_incapsule_count, ctx->write_h2c_count);
    uart_printf("[nvmet:%s] セッション終了(%s)、次のクライアントを待ちます\n", ctx->label, reason);
    /* push型受信(2026-08-13): このコネクションにupcallが残っていると、
     * 次のクライアントの新規accept(tcp_priv_init)前に万一データが来た場合に
     * 古いjcを指してしまうため、念のため明示解除する(PUSH_RUNの各終了
     * パスでも解除済みだが二重の安全策)。 */
    tcp_clear_recv_upcall(&ctx->io.tcp);
    if (close_io) {
        nvmet_tcp_close(&ctx->io);
    }
    ctx->io_connected = 0;
    nvmet_tcp_close(&ctx->admin);
    /* リスナー(ctx->listener)はここでは解除しない -- 常駐サーバ化
     * (CLAUDE.md「nvmet: 常駐サーバ化」節参照)により、admin/IO両方の
     * accept段階で使い回すこのインスタンス専用のリスナーはnvmet_job_
     * start()が確保して以後インスタンスの生存期間中ずっと保持する
     * (Ctrl+Cによる完全停止時のみnvmet_admin_job_step()側で解除する)。 */

    /* 次のセッションへ向けてctxをリセットする(nvmet_job_start()の
     * 初回セットアップと同じ項目)。 */
    ctx->ctrlr_id = 0;
    ctx->cc       = 0;
    ctx->cc_en    = 0;
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

/* 定常ループ中の受信エラー(r<0)を一元処理する。上記コメント参照。 */
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

/* H2Cヘッダ(cccid/datao/datal、ハッシュダイジェスト検証があればそれも
 * 通過済み)を受信し終えた直後の検証。旧nvmet_io_loop()と同じ順序で
 * (未知のcccid→datao不一致→write_len超過の順に)確認し、**いずれも
 * 通過して初めて**データ本体の受信先(ctx->ram_disk[slba*LBA_SIZE+datao]、
 * 2026-08-11以降は専用ステージングバッファを介さず直接ram_disk[]へ受信
 * する、下記のnvmet_tcp_xfer_reset()呼び出し直前のコメント参照)を確定
 * してNIO_ST_RECV_H2C_DATAへ進む。検証に失敗した場合はデータ本体を
 * 一切受信せず即座にセッションを終了する -- 検証前にデータ本体を受信して
 * しまうと、受信先の安全な範囲(write_lenの範囲内である保証)が無くなる
 * (未知のcccidだとs_pending_writes[]に対応スロットが無いため、正しい
 * サイズの上限もslbaも分からない)。 */
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
    /* 【2026-08-11、ユーザー承認済みの最適化】以前はここで受信先を
     * pending_write_bufs[slot]+datao(専用ステージングバッファ)にし、
     * 全ラウンド完了後にNIO_ST_DISPATCH_H2Cでwrite_lenバイトまとめて
     * ram_disk[]へコミットコピーしていた(実機ts計測で約72-120us/
     * コマンドの実コストと確定、CLAUDE.md該当節参照)。宛先LBA(pw->slba)
     * はNIO_ST_DISPATCH_CMD時点で既に判明しているため、H2CDataを最初から
     * ram_disk[]の該当オフセットへ直接受信すれば、このコミットコピーを
     * 丸ごと省略できる。トレードオフ: マルチラウンド書き込みの途中経過
     * (未完成のデータ)がram_disk[]に部分的に見える状態になる(以前は
     * 全ラウンド完了までram_diskには一切触れなかった) -- 同一LBA範囲への
     * 並行readとの厳密な原子性は元々保証していない設計のため許容する。 */
    nvmet_tcp_xfer_reset(&jc->xfer, &ctx->ram_disk[pw->slba * NVMET_LBA_SIZE + jc->datao], jc->datal);
    self->state = NIO_ST_RECV_H2C_DATA;
    return JOB_WAITING;
}

/* ================================================================
 * dispatch(応答送信)を関数化(2026-08-13)。従来はNIO_ST_DISPATCH_CMD/
 * NIO_ST_DISPATCH_H2Cのcase本体だった処理を、pull型(既存ステート)と
 * push型(nvmet_io_rx_upcall()が積んだready-ringをjobがdispatch)の両方から
 * 呼べる関数へ切り出したもの。ロジックは無変更(jc->フィールド参照を引数
 * 参照へ置換しただけ) -- 状態遷移(xfer_reset/self->state)は呼び出し側が行う。
 *
 * in-capsule writeのデータは、pull型ではRECV_CMD_DATAで、push型では
 * nvmet_io_rx_upcall()のPRX_DATAで、いずれも既にcmd_data_dst(=ram_disk[slba]
 * またはdata_buf)へ受信済みなので、ここでは応答するだけ(incap_committedで
 * 成功/エラーを判断)。cmd_data_dst自体はここでは参照しない。
 * ================================================================ */
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
            int c2h_rc;
            if (!ctx->io.hdgst && !ctx->io.ddgst) {
                c2h_rc = nvmet_tcp_send_c2h_async(&ctx->io, cid,
                                                   &ctx->ram_disk[slba * NVMET_LBA_SIZE],
                                                   nlb * NVMET_LBA_SIZE);
            } else {
                c2h_rc = nvmet_tcp_send_c2h(&ctx->io, cid, &cqe,
                                             &ctx->ram_disk[slba * NVMET_LBA_SIZE],
                                             nlb * NVMET_LBA_SIZE, 1);
            }
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
    } else {
        uart_printf("[!] nvmet: 未対応のIOコマンド (opcode=0x%x)\n", opcode);
        nvmet_build_cqe(&cqe, cid, 0u, (uint16_t)NVMET_SC_GENERIC_ERROR);
        nvmet_tcp_send_resp(&ctx->io, &cqe);
    }
}

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

/* ================================================================
 * push型受信(inline upcall、非digest接続、2026-08-13)
 *
 * ICResp送信後、非digest接続ではtcp_set_recv_upcall()でnvmet_io_rx_upcall()を
 * 登録する。以後tcp_input()はin-orderデータをrx_bufへ積む代わりにこの関数へ
 * その場で渡す。パーサはNVMe/TCP IOキューのPDU言語(CapsuleCmd/H2CData、
 * 非digest)をストリームとして解析し、**in-capsule writeデータをram_disk[slba]へ
 * 直接配置**(=ネットワークから最終バッファまで1コピー、従来のcopy2+copy3を
 * 排除)、完成した1コマンド/1 H2Cラウンドをready-ringへ積む。
 *
 * この関数(RXコンテキスト=net_poll再入)からは**一切送信しない** -- 送信を
 * 伴うdispatchはjob(NIO_ST_PUSH_RUN)がnet_poll外で行う(再入爆発の回避)。
 * ================================================================ */

/* ready-ringへ1件積む(生産側=upcall)。ringが満杯(dispatchが追いつかない)
 * ならprx_errorを立てる。rd->*書き込みをhead前進より前に確定させるため
 * コンパイラバリアを挟む(同一コアの協調実行なのでCPUバリアは不要)。 */
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
    rd->copy_wm         = jc->prx_copy_wm;
    __asm__ volatile("" ::: "memory");
    jc->ready_head++;
}

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
    rd->copy_wm  = jc->prx_copy_wm;
    __asm__ volatile("" ::: "memory");
    jc->ready_head++;
}

static void nvmet_io_rx_upcall(void *arg, const volatile uint8_t *data, uint16_t len)
{
    nvmet_io_job_ctx_t *jc  = (nvmet_io_job_ctx_t *)arg;
    nvmet_ctx_t        *ctx = jc->ctx;
    uint32_t i = 0;
    while (i < len && !jc->prx_error) {
        switch (jc->prx_phase) {
        case PRX_HDR: {
            /* このPDUの受信+処理span計測開始。新PDUの最初のバイトを
             * 受け取る瞬間のtickを採る。ts_log_mode()&0x2(push受信の
             * per-CMD診断)が無効な通常運用ではtimer_now()も呼ばず
             * ゼロコスト。 */
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
                jc->prx_data_need = (plen > jc->prx_hlen) ? (plen - jc->prx_hlen) : 0u; /* 非digest */
                if (jc->prx_psh_need == 0 || jc->prx_psh_need > NVME_SQE_LEN) {
                    jc->prx_error = 1; break;   /* IOキューのCMD/H2Cはhlen=72/24のみ */
                }
                jc->prx_psh_off = 0;
                jc->prx_phase   = PRX_PSH;
                jc->prx_copy_ns = 0;   /* このPDUの1コピー累積時間を計測開始 */
                jc->prx_copy_wm = rxcopy_submitted();  /* データ無しPDUでも有効な watermark(以後submitで更新) */
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

            if (jc->prx_type == NVME_TCP_PDU_CMD) {
                jc->prx_cid = rd16le(&jc->prx_psh[2]);
                uint32_t opcode = rd32le(&jc->prx_psh[0]) & 0xFFu;
                /* コマンド(SQE)受信完了時刻。dispatch(応答)やデータコピー
                 * より前、全CMD種別(read/write/fabrics、in-capsuleデータの
                 * 有無に依らず)が必ず通るこの地点で記録する -- これが
                 * 「コマンドを受信した瞬間」のts(nvmet_io_dispatch_cmd#0は
                 * copy/dispatch後なので受信時刻ではない)。infoは
                 * nvmet_io_dispatch_cmdのCMD記録と同じ組み立て。 */
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
                    nvmet_ready_push_cmd(jc);
                    jc->prx_phase = PRX_HDR; jc->prx_hdr_off = 0;
                } else {
                    if (!jc->prx_incap_committed && jc->prx_data_need > NVMET_IO_DATA_BUF_MAX) {
                        jc->prx_error = 1; break;   /* data_bufオーバーフロー防止 */
                    }
                    jc->prx_data_off = 0;
                    jc->prx_phase = PRX_DATA;
                }
            } else if (jc->prx_type == NVME_TCP_PDU_H2C_DATA) {
                jc->prx_cccid = rd16le(&jc->prx_psh[0]);
                jc->prx_ttag  = rd16le(&jc->prx_psh[2]);
                jc->prx_datao = rd32le(&jc->prx_psh[4]);
                jc->prx_datal = rd32le(&jc->prx_psh[8]);
                jc->prx_data_need = jc->prx_datal;
                int slot = nvmet_pending_write_find(ctx, jc->prx_cccid);
                if (slot < 0) { jc->prx_error = 1; break; }
                nvmet_pending_write_t *pw = &ctx->pending_writes[slot];
                if (jc->prx_datao != pw->received ||
                    pw->received + jc->prx_datal > pw->write_len) {
                    jc->prx_error = 1; break;
                }
                jc->prx_h2c_slot = slot;
                jc->prx_data_dst = (volatile uint8_t *)&ctx->ram_disk[pw->slba * NVMET_LBA_SIZE + jc->prx_datao];
                if (jc->prx_datal == 0) {
                    nvmet_ready_push_h2c(jc);
                    jc->prx_phase = PRX_HDR; jc->prx_hdr_off = 0;
                } else {
                    jc->prx_data_off = 0;
                    jc->prx_phase = PRX_DATA;
                }
            } else {
                jc->prx_error = 1;   /* IOキューで想定外のPDU種別 */
            }
            break;
        }
        case PRX_DATA: {
            uint32_t need  = jc->prx_data_need - jc->prx_data_off;
            uint32_t avail = (uint32_t)len - i;
            uint32_t take  = (need > avail) ? avail : need;
            /* 唯一のコピー: RX(net_buf=RQバッファ)→ram_disk[slba] 直接配置。
             * RXコピーオフロード有効時(rxcopy.h)は core1 へ投入するだけで、
             * ここではコピーしない(core0=受信/ACK専任)。off時は従来通り
             * その場で同期コピー。0x40はoff時のみコピー時間の意味を持つ。 */
            /* コピー時間計測(#0)はts_log_mode()&0x2が有効なときだけ。
             * 通常運用ではtimer_now()/get_ns_from()の2回のタイマー読みも
             * 省いてゼロコスト。 */
            int ts_rx_on = (ts_log_mode() & 0x2) != 0;
            uint64_t cpt0 = ts_rx_on ? timer_now() : 0;
            if (rxcopy_enabled()) {
                jc->prx_copy_wm = rxcopy_submit(data + i, jc->prx_data_dst + jc->prx_data_off, take);
            } else {
                volatile_fast_copy(jc->prx_data_dst + jc->prx_data_off, data + i, take);
            }
            if (ts_rx_on) jc->prx_copy_ns += (uint32_t)get_ns_from(cpt0);
            jc->prx_data_off += take;
            i += take;
            if (jc->prx_data_off == jc->prx_data_need) {
                if (ts_rx_on) {
                    /* このPDUの実データ受信(1コピー)にかかった総時間。
                     * arg上位=0x40(push 1コピー)、下位=ns。 */
                    ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_rx_upcall, 0), (0x40u << 24) | (jc->prx_copy_ns & 0xFFFFFFu));
                    /* 0x43: このPDUの受信開始(最初のバイト)から完成
                     * (enqueue直前)までの経過=受信+パース+コピーのspan。
                     * qd8ではこれがワイヤ到着律速を含む1コマンド分の処理時間。 */
                    ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_rx_upcall, 1),
                           (0x43u << 24) | ((uint32_t)get_ns_from(jc->prx_start_tick) & 0xFFFFFFu));
                }
                if (jc->prx_type == NVME_TCP_PDU_CMD) nvmet_ready_push_cmd(jc);
                else                                   nvmet_ready_push_h2c(jc);
                jc->prx_phase = PRX_HDR; jc->prx_hdr_off = 0;
            }
            break;
        }
        }
    }
}

static job_result_t nvmet_io_job_step_impl(job_t *self)
{
    nvmet_io_job_ctx_t *jc  = (nvmet_io_job_ctx_t *)self->ctx;
    nvmet_ctx_t         *ctx = jc->ctx;

    /* stateprof.h -- このステートに何回・合計どれだけ滞在したかを記録
     * する(呼ばれるたびに毎回、switchより前で)。 */
    state_prof_mark(&ctx->io_prof, self->state);

    /* `job stop <番号>`(cancel_requested)対応の追加。以前はNIO_ST_WAIT_
     * ADMIN_READY(セッション未確立、次のadmin準備待ち)にしかこのチェックが
     * 無く、セッション確立後(NIO_ST_ARM以降、`jobs`のstateが1以上)に
     * job stopしても何も起きず、`jobs`の表示が固まったまま(busyや
     * ctx->io_connected等もクリアされない)リブートしないと復旧できない
     * バグだった。ここでの扱いはCtrl+C中断(nvmet_io_job_recv_fail()の
     * tcp_abort_requested()パス)と同じ「このセッションだけを終了し、
     * サーバ自体は次のクライアントを待つ状態へ戻す」(サーバ全体の停止
     * ではない、上記「常駐サーバ化」の設計方針を踏襲)。NIO_ST_WAIT_
     * ADMIN_READY自身は既存の専用ハンドリング(下記、サーバ全体停止の
     * 起点)に任せるためここでは対象外にする。 */
    if (self->cancel_requested && (nvmet_io_state_t)self->state != NIO_ST_WAIT_ADMIN_READY) {
        /* NIO_ST_ICREQ_RECV以降はctx->ioのTCPハンドシェイクが既に完了して
         * いる(=tcp_close()が必要)、NIO_ST_ARM/ACCEPT_WAITはまだ
         * (nvmet_io_job_end()の他の呼び出しパターンと同じ判断基準)。 */
        int io_open = ((nvmet_io_state_t)self->state >= NIO_ST_ICREQ_RECV);
        /* 【実機で発見・修正】ここでcancel_requestedをクリアし忘れると、
         * nvmet_io_job_end()がJOB_WAITINGでNIO_ST_WAIT_ADMIN_READYへ戻す
         * (このjob自体はJOB_DONEにならず常駐し続ける)ため、次tickで
         * state==NIO_ST_WAIT_ADMIN_READYになった途端、まだ立ったままの
         * cancel_requestedを下記の既存チェックが「新たなjob stop」として
         * 誤検出し、ctx->stop_requested経由でサーバ全体を停止させて
         * しまう(セッションだけを終了するはずが、意図せず常駐サーバ
         * ごと落ちた)。 */
        self->cancel_requested = 0;
        return nvmet_io_job_end(self, ctx, io_open, "job stopでキャンセル");
    }

    if((uint32_t)self->state != 0x10)
        ts_log(TS_MK(TS_FILE_NVMET, TS_FUNC_nvmet_io_job_step_impl, 10), (uint32_t)self->state);

    switch ((nvmet_io_state_t)self->state) {

    case NIO_ST_WAIT_ADMIN_READY:
        if (ctx->admin_failed) {
            /* admin jobがCtrl+Cまたは`job stop <番号>`でサーバ自体を
             * 完全停止させた(誰も接続してこないままNADM_ST_ACCEPT_WAIT
             * でそれらが起きた場合のみここが立つ、常駐サーバ化に伴う
             * 新しい意味づけ -- 通常のセッション終了(クライアントとの
             * 切断等)ではここには来ずctx->session_doneの方で処理される)。
             * ctx->ioには一切触れていない -- session_activeをここで0へ
             * 戻す(両ジョブが完全にJOB_DONEになったことの証跡として、
             * 最後に終わる方だけが戻す設計)。 */
            ctx->session_active = 0;
            return JOB_DONE;
        }
        if (self->cancel_requested) {
            /* このio job自身が`job stop <番号>`で指定された場合。実際の
             * リスナー解除等の後始末はadmin job(NADM_ST_ACCEPT_WAIT)側の
             * 責務に一本化してあるので、ここでは直接何もせずctx->stop_
             * requestedを立ててリレーするだけ -- admin側が次にACCEPT_
             * WAITを確認したタイミングで実際に停止する(nvmet.hのstop_
             * requestedコメント参照)。io job自身はadmin_failedが立つ
             * のを待つため、ここではJOB_DONEにしない。 */
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
        /* push型受信(inline upcall、非digest接続、2026-08-13): digest無効の
         * 接続では、以降のRXをupcall(nvmet_io_rx_upcall())へ切り替え、二重
         * コピーを排して1コピーで受信する。digest接続は従来のpull型RXステート
         * (RECV_PDU_HDR〜)のまま(digestのストリーム逐次CRCは次段階で対応)。 */
        if (!ctx->io.hdgst && !ctx->io.ddgst && !g_nvmet_force_pull) {
            jc->push_mode   = 1;
            jc->prx_phase   = PRX_HDR;
            jc->prx_hdr_off = 0;
            jc->prx_error   = 0;
            jc->ready_head  = 0;
            jc->ready_tail  = 0;
            tcp_set_recv_upcall(&ctx->io.tcp, nvmet_io_rx_upcall, jc);
            self->state = NIO_ST_PUSH_RUN;
            uart_printf("[nvmet:%s] IOキュー push型(inline upcall)受信を有効化\n", ctx->label);
        } else {
            jc->push_mode = 0;
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
        }
        return JOB_WAITING;

    case NIO_ST_PUSH_RUN: {
        /* RXはupcallがストリームとして処理する。jobはready-ringを
         * dispatch(応答送信、net_poll外で実行=再入回避)し、
         * 中断/エラー/切断を監視するだけ。 */
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
        /* 完成コマンドをdispatch。dispatchの送信がnet_pollを回して
         * 追加のupcall→ready_head前進を起こしても、tail!=headで拾い続ける。 */
        while (jc->ready_tail != jc->ready_head) {
            nvmet_ready_t *rd = &jc->ready[jc->ready_tail % NVMET_READY_RING];
            /* RXコピーオフロード有効時: このコマンドの全データコピーが core1 で
             * 完了する(rxcopy_done がこのコマンドの copy_wm に達する)まで
             * dispatch(=CQE)しない。まだなら次tickへ回す(coreは他jobを回せる)。 */
            if (rxcopy_enabled() &&
                (int32_t)(rxcopy_done() - rd->copy_wm) < 0) {
                break;
            }
            /* DBGT 0x42(検証後に撤去): dispatch(CQE構築+応答送信 tcp_send_async)
             * 1回の所要時間。受信span(0x43)・コピー(0x40)と並べて内訳を見る。 */
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
        /* in-capsuleデータの受信先を決める(ゼロコピー化、2026-08-13)。
         * WRITEコマンドでin-capsuleデータ(dlen>0)を伴い、slba/nlbが有効
         * 範囲かつwrite_len==dlenなら、data_bufステージングを介さず
         * ram_disk[slba]へ直接受信する(DISPATCHでのコピーが不要になる)。
         * それ以外(非WRITE、範囲外、write_len不整合)は従来通りdata_buf。
         * SQEはこの時点で受信済みなのでここでパースできる(cdw10@40/
         * cdw11@44=slba、cdw12@48下位16bit=nlb-1、opcode=sqe_buf[0])。 */
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
            /* DDP(二重コピー削減、2026-08-13): in-capsule writeで受信先が
             * ram_diskへ直接確定している場合(incap_write_committed)は、
             * rx_bufステージング(copy2+copy3)を回避してram_diskへ直接受信
             * する。ddgst有効時はデータ本体のCRC検証(既存経路がrx_buf前提)
             * との整合を崩さないよう従来のdrain経路を使う(稀なケース)。 */
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
        /* ddgstはin-capsuleデータ本体(cmd_data_dst = ram_disk[slba]または
         * data_buf)に対して検証する -- ゼロコピー化でwriteデータがram_diskへ
         * 直接受信されるようになったため、data_buf固定ではなく実際の受信先を
         * 見る(R2T経路のRECV_H2C_DDGSTがram_diskを見るのと同じ)。 */
        if (nvmet_tcp_verify_ddgst(&ctx->io, jc->cmd_data_dst, jc->dlen, jc->dgst_buf) != 0) {
            nvmet_tcp_xfer_reset(&jc->xfer, jc->hdr_buf, NVME_TCP_HDR_LEN);
            self->state = NIO_ST_RECV_PDU_HDR;
            return JOB_WAITING;
        }
        self->state = NIO_ST_DISPATCH_CMD;
        return JOB_WAITING;
    }

    case NIO_ST_DISPATCH_CMD: {
        /* pull型コピー計測(DBGT 0x41、検証後に撤去): copy2(net_buf→rx_buf、
         * tcp_input/net_poll内で非同期に発生)はコマンドのSQEをパースするより
         * 前にバースト到着分がまとめてrx_bufへ積まれてしまうため、SQE時点で
         * 基準を採ると copy2 を取りこぼす。そこで「前回dispatchからの差分」を
         * 測る -- iodepth=1では前コマンドのCQEを相手が受けてから次コマンドの
         * データが届くので、この差分=当該コマンドのcopy2+copy3全体になる
         * (pipeline時は他コマンド分が混ざるので qd1 で計測すること)。 */
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
        /* 受信先は既にnvmet_io_job_h2c_validate()の時点でs_pending_write_
         * bufs[jc->h2c_slot]+datao(検証済みで安全)へ確定済み。 */
        /* 計装専用(2026-08-11、RECV_H2C_DATAの所要時間切り分け -- この
         * 1回のnvmet_tcp_recv_poll()呼び出し自体が遅いのか[tcp_recv_
         * no_ack()のコピー等]、それとも呼び出し自体は速いが状態が複数
         * tickにまたがって滞在しているだけなのかを区別する。原因特定後に
         * 削除すること。 */
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
        /* データは既にram_disk[]へ直接受信済み(上記nvmet_io_job_h2c_
         * validate()のコメント参照)なので、そちらから検証する。 */
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

static job_result_t nvmet_io_job_step(job_t *self)
{
    return nvmet_io_job_step_impl(self);
}

void nvmet_instances_zero_all(void)
{
    /* nvmet.hのnvmet_instances_zero_all()コメント参照 -- NVMET_CTX_SLOT()
     * の指す領域は`.bss`/`.dma_bss`のどちらでもなく`boot.S`のゼロクリア
     * 対象外なので、ここで明示的にゼロクリアする。8バイト単位の素朴な
     * ループ(volatile不要 -- ワイドストアを妨げる理由が無い、単純な
     * ゼロフィルなので結合されるならむしろ望ましい)。 */
    uint64_t *p = (uint64_t *)NVMET_INSTANCES_BASE;
    uint64_t count = ((uint64_t)NVMET_MAX_INSTANCES * NVMET_INSTANCE_SLOT_SIZE) / sizeof(uint64_t);
    for (uint64_t i = 0; i < count; i++) {
        p[i] = 0;
    }
}

int nvmet_job_start(nvmet_ctx_t *ctx, uint16_t port, net_ctx_t *bound_ctx, const char *label)
{
    if (ctx->session_active) {
        /* 常駐サーバ化(CLAUDE.md「nvmet: 常駐サーバ化」節参照)により、
         * session_activeは「クライアント接続中」ではなく「サーバが
         * 稼働中(次の接続を待っているか、処理中)」を表す。既に稼働中
         * なら何もせず知らせるだけでよい(エラーというより情報)。 */
        uart_printf("[nvmet:%s] 既に稼働中です(次の接続を待機中、または処理中)\n", ctx->label);
        return -1;
    }

    /* 2026-08-09、実機で発見した本物のバグへの対策(CLAUDE.md「MTXC/MRXF
     * 待ち改善の検討方針」節末尾の実装経緯参照): このctx自身は空いていても、
     * *別の*nvmet_ctx_t(異なるスロット、例えば`platform_init`が起動した
     * インスタンスと`test`コマンドの"manual"インスタンス)が既に同じ
     * bound_ctx(同一の物理net_ctx_t、例: mlx5-pf1)へ紐付いたまま稼働中
     * だと、同一インターフェースに対して2組のadmin/ioジョブが同時に
     * job_scheduler_tick()を取り合うことになる -- 両方とも同じbound_ctxの
     * TCP/NICを見に行くが実際のクライアント接続は片方にしか繋がらない
     * ため、もう片方は空回りのACCEPT_WAIT/WAIT_ADMIN_READYを繰り返す
     * だけの「ゾンビ」ジョブとして残り続け、本来動くべき方のジョブへ
     * 回るはずだったcore側のCPU時間(job_scheduler_tick()の1回あたり
     * コスト)を奪う。実機で`platform_init`実行後に`test`コマンドを実行し、
     * この状態(pf1に2組のnvmet-admin/io、うち1組がゾンビ)になった際、
     * write負荷テストのスループットが約171MB/s→(ゾンビ解消後)約194MB/sへ
     * 改善することを確認した -- 気づかずに踏むと原因不明の性能低下として
     * 見えるため、事前に検出して拒否する。 */
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

    /* このctxに対応するジョブコンテキストプールスロットを決める --
     * 過去にこのctxで起動したことがあれば同じスロットを再利用し
     * (Ctrl+Cで完全停止した後の再起動)、無ければ空きスロットを新規に
     * 割り当てる(複数インスタンス対応、CLAUDE.md「nvmet: 複数
     * インターフェース同時待受」節参照)。 */
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

    /* admin/io 2ジョブ分の空きを事前確認する -- 片方だけspawnに成功する
     * 中途半端な状態(片方が生成できず、もう片方だけが永続ジョブとして
     * 残ってしまう)を避けるため。 */
    if (job_active_count() > (unsigned)(JOB_MAX - 2)) {
        uart_printf("[!] nvmet: ジョブテーブルに空きが不足(admin/io用に2枠必要)\n");
        return -1;
    }

    /* このインスタンス専用のリスナーを確保する(admin/IO両方のaccept
     * 段階でインスタンスの生存期間中ずっと使い回す、tcp.hのtcp_listen()
     * コメント参照)。 */
    int listener = tcp_listen(port, bound_ctx);
    if (listener < 0) {
        uart_printf("[!] nvmet: リスナー確保失敗(TCP_MAX_LISTENERSに空きが無い)\n");
        return -1;
    }

    ctx->io_connected   = 0;
    ctx->ctrlr_id       = 0;
    ctx->cc             = 0;
    ctx->cc_en          = 0;
    ctx->io_armed       = 0;
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

    state_prof_reset(&ctx->admin_prof);
    state_prof_reset(&ctx->io_prof);

    nvmet_build_id_ctrl(ctx);
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
    /* admin/ioジョブは同じbound_ctx(net_ctx_t、そのインターフェースの
     * NIC/TCP受信を実際にポーリングして良いのは常にbound_ctx->owner_core
     * だけ、netctx.hのnet_ctx_t.owner_coreコメント参照)を共有するため、
     * job.cのaffinity_key機構(job.h参照)で紐付ける -- これにより
     * job_scheduler_tick()は、同じbound_ctxを共有するジョブが同時に
     * 異なるコアでclaimされないよう保証する(マルチコア化 Phase 4-6
     * 準備、~/.claude/plans/wondrous-baking-gadget.md参照)。 */
    job_set_affinity(admin_job, bound_ctx);
    /* 【Phase 6】さらにbound_ctx->owner_coreへ明示的にピン止めする
     * (job.h冒頭の「core pinning機構」参照) -- job_spawn()の既定
     * (spawnしたコア、通常はcore0のシェル)のままだと、bound_ctxが
     * platform_init.cでcore1へ引き渡し済み(net_ctx_set_owner_core()
     * 呼び出し後)の場合にNICのowner_coreとjobの実行コアが食い違い、
     * core0にジョブが留まったままcore1側のNICへ触れない/一切進行しない
     * バグになる。bound_ctx==NULL(manualコマンド、test.c)の場合は
     * job_spawn()の既定(呼び出し元コア)のままでよいので何もしない。 */
    if (bound_ctx) {
        job_pin_to_core(admin_job, bound_ctx->owner_core);
    }

    s_io_job_pool[slot].ctx  = ctx;
    s_io_job_pool[slot].port = port;
    job_t *io_job = job_spawn(nvmet_io_job_step, &s_io_job_pool[slot], "nvmet-io");
    if (!io_job) {
        /* 事前のjob_active_count()チェックによりここには到達しない想定
         * だが、念のため。admin jobは既にspawn済みでキャンセルAPIが
         * 無いため、ctx->admin_failedを立てて次tickでadmin job自身に
         * (WAIT_ADMIN_READYと同じ理屈は使えないが)自然終了させる手段が
         * 無い -- ログのみに留める、極めて起きにくいケース。 */
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

// pcie1 reset(command.cのcmd_pcie1)から呼ぶ: ConnectX(mlx5-pf0/pf1)へ
// bindされているTCP nvmet常駐サーバだけを停止する(RP1 bindのものは残す)。
// pcie1 resetでmlx5リンクが切れると、これらのadmin/ioジョブはNICが死んだ
// まま宙に浮く -- `pcie1 reset`はRoCEv2(nvmet_rdma系)ジョブしか畳まないため
// (nvmet_rdma_stop_all())、mlx5にbindしたNVMe/TCPのnvmetがそこから漏れる。
// bound_ctxがmlx5-pf0/pf1のインスタンスだけを対象に、`job stop`と同じ
// cancel_requested(job_cancel_by_ctx)+ctx->stop_requested(admin ACCEPT_WAIT
// が見る)で自己終了させる(実際のテーブルからの除去は呼び出し元の
// job_scheduler_tickドレインループ)。net_ctx_find()がNULL(mlx5未初期化)
// なら対象ゼロで何もしない。
void nvmet_stop_connectx_instances(void)
{
    net_ctx_t *pf0 = net_ctx_find("mlx5-pf0");
    net_ctx_t *pf1 = net_ctx_find("mlx5-pf1");
    if (pf0 == NULL && pf1 == NULL) return;
    for (unsigned slot = 0; slot < NVMET_MAX_INSTANCES; slot++) {
        nvmet_ctx_t *ctx = s_instance_owner[slot];
        if (ctx == NULL || !ctx->session_active) continue;
        net_ctx_t *b = ctx->bound_ctx;
        if (b == NULL || (b != pf0 && b != pf1)) continue;  // ConnectX bindのみ対象
        ctx->stop_requested = 1;                 // admin ACCEPT_WAIT(nvmet.c:546)が見る
        job_cancel_by_ctx(&s_admin_job_pool[slot]);
        job_cancel_by_ctx(&s_io_job_pool[slot]);
        uart_printf("[nvmet:%s] ConnectXリセットに伴い停止します\n", ctx->label);
    }
}

void nvmet_ctx_prof_reset(nvmet_ctx_t *ctx)
{
    state_prof_reset(&ctx->admin_prof);
    state_prof_reset(&ctx->io_prof);
}

void nvmet_ctx_prof_dump(const nvmet_ctx_t *ctx)
{
    char label_admin[40];
    char label_io[40];
    const char *label = ctx->label ? ctx->label : "?";

    /* uart_printf()の%sだけでラベルを組み立てられないため(可変長の
     * 埋め込みが必要)、固定長バッファへ簡易連結する。ラベルは
     * nvmet_job_start()が渡す短い静的文字列("rp1"/"mlx5-pf0"/
     * "mlx5-pf1"/"manual")のみを想定しているため、これで十分。 */
    unsigned i = 0;
    const char *prefix1 = "nvmet-admin(";
    while (*prefix1 && i < sizeof(label_admin) - 2) label_admin[i++] = *prefix1++;
    const char *p = label;
    while (*p && i < sizeof(label_admin) - 2) label_admin[i++] = *p++;
    label_admin[i++] = ')';
    label_admin[i] = '\0';

    i = 0;
    const char *prefix2 = "nvmet-io(";
    while (*prefix2 && i < sizeof(label_io) - 2) label_io[i++] = *prefix2++;
    p = label;
    while (*p && i < sizeof(label_io) - 2) label_io[i++] = *p++;
    label_io[i++] = ')';
    label_io[i] = '\0';

    state_prof_dump(&ctx->admin_prof, NADM_STATE_NAMES, (unsigned)NADM_STATE_NAME_COUNT, label_admin);
    state_prof_dump(&ctx->io_prof, NIO_STATE_NAMES, (unsigned)NIO_STATE_NAME_COUNT, label_io);
}
