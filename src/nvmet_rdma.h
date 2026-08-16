#ifndef NVMET_RDMA_H
#define NVMET_RDMA_H

#include <stdint.h>
#include "mlx5_qp.h"
#include "rdma_cm.h"
#include "job.h"
#include "nvme_types.h"

/* ================================================================
 * nvmet_rdma.h -- NVMe-oF RDMAトランスポート、ターゲット側。
 * ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-
 * lamport.md)フェーズ(g)。既存nvmet.c(TCPトランスポート)には一切
 * 触れず、完全に並行する新規実装として追加する。
 *
 * フェーズ(i)続報(2026-08-13): 実Linuxホストは標準通りadmin queue
 * (qid=0)とは別にIOキュー(qid=1)用の独立したRDMA CM接続(=別のRC QP)を
 * 要求するため、「1PFあたりRC QP 1本のみで簡略化」だったフェーズgの
 * スコープを拡張した -- コントローラ状態(id_ctrl/id_ns/ram_disk/cc/
 * cc_en/ctrlr_id)は admin queue と IO queue の間で**共有**する必要が
 * あるため`nvmet_rdma_ctrl_t`として独立させ、`nvmet_rdma_ctx_t`
 * (1接続=1RC QP分の状態)からポインタで参照する形にした。
 * `nvmerdmaconnect`/`nvmermabench`(nvme_rdma.c、PF0<->PF1ループバック
 * 検証)は引き続き「combined single queue」設計のまま(=admin queueの
 * ctxだけを使い、IOキューは一切spawnしない)で変更していない --
 * `nvmet_rdma_ctx_t.enable_io_queue`が既定0(呼び出し元が明示的に立てない
 * 限りIOキューlistenerを一切spawnしない)であるため、既存の
 * ループバック検証には影響しない。
 * ================================================================ */

#define NVMET_RDMA_LBA_SIZE      512u
/* 2026-08-13、ユーザー指示によるRAMディスク拡張: 元は2048(1MB、`.bss`
 * 埋め込み)だったが、board.hのNVMET_RDMA_RAMDISK_SLOT_SIZE(64MB、固定
 * 物理アドレス方式)から逆算する値へ変更した -- 大きいbs(fioのブロック
 * サイズ)を意味のある形でテストするには、名前空間自体がそれを収容できる
 * 大きさである必要があるため。 */
#define NVMET_RDMA_NS_LBA_COUNT (NVMET_RDMA_RAMDISK_SLOT_SIZE / NVMET_RDMA_LBA_SIZE)
#define NVMET_RDMA_MSG_MAX     2048u
#define NVMET_RDMA_ID_BUF_LEN  4096u
#define NVMET_RDMA_SUBNQN "nqn.2014-08.org.nvmexpress:uuid:deadbeef-rdma-babe-dead-beefcafebabe"

/* 汎用エラーステータス(nvmet.hのNVMET_SC_GENERIC_ERRORと同値) --
 * CQEのstatusフィールドへそのままwr16leする生の16bit値(bit0=phase
 * tag=0、bits[8:1]=SC=0x01=Invalid Command Opcode相当)。 */
#define NVMET_RDMA_SC_ERROR 0x0002u

/* コマンドパイプライン化(2026-08-12、nvmet_rdma.cの「パイプライン化」
 * 節参照)で同時にoutstandingにできるコマンド数。2026-08-13、ユーザー
 * 指示によりiodepth拡大のため8→16へ増量した -- RC QPのRQ/SQ深度
 * (mlx5_qp_create_rc()、RQ=256エントリ/SQ=64 WQEBB)に対する余裕を実際に
 * 計算した上での値: 1コマンドは最悪2個のSQ WQE(データ移動+応答SEND)を
 * 消費するため、MAX_PENDING×2=32 WQEBBが同時に必要になりうる -- SQ容量
 * 64 WQEBBの50%に収まる範囲(安全マージンを残す)としてこの値を選んだ。
 * RQ側(256エントリ)には引き続き大きな余裕がある。 */
#define NVMET_RDMA_MAX_PENDING 16u

typedef enum {
    NVMETR_ST_CM_SPAWN = 0,
    NVMETR_ST_CM_WAIT,
    NVMETR_ST_POST_RECV,
    NVMETR_ST_WAIT_CAPSULE,
    NVMETR_ST_DATA_MOVE,
    NVMETR_ST_WAIT_DATA_MOVE,
    NVMETR_ST_SEND_RESP,
    NVMETR_ST_WAIT_RESP_SENT,
    /* 「ソフトウェア処理をハード転送の裏に完全に隠す」ためのコマンド
     * パイプライン化(2026-08-12、ユーザー指示、CLAUDE.md
     * 「nvmermabenchのボトルネック切り分け」節の実測を受けて実施)。
     * 上記の単一コマンド逐次処理ステート群(NVMETR_ST_POST_RECV〜
     * NVMETR_ST_WAIT_RESP_SENT)は`nvmerdmaconnect`(既に実機検証済みの
     * 正しさの基準)のために一切変更せず残し、`ctx->pipeline_enabled`
     * が真の場合のみこちらへ分岐する(nvmet_rdma.c参照)。 */
    NVMETR_ST_PIPELINE_SETUP,
    NVMETR_ST_PIPELINE_LOOP,
} nvmet_rdma_state_t;

/* admin queueとIOキューの間で共有される「コントローラ」状態(接続= RC QP
 * とは独立)。フェーズ(i)続報で`nvmet_rdma_ctx_t`から分離した -- 1台の
 * コントローラは複数のキュー(接続)を持ちうるが、Identify応答/名前空間
 * データ/CC.EN状態は接続をまたいで1つだけ存在するのが正しいNVMe(-oF)の
 * モデル。 */
typedef struct {
    uint16_t ctrlr_id;   /* 固定値1(nvme_rdma.cのcntlidと一致させる) */
    uint32_t cc;
    int      cc_en;

    volatile uint8_t id_ctrl[NVMET_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));
    volatile uint8_t id_ns[NVMET_RDMA_ID_BUF_LEN] __attribute__((aligned(64)));

    /* 2026-08-13: 64MBは`.bss`予算(DMA_BSS_BASEまで約1MBしか残っていな
     * かった)に収まらないため、配列埋め込みではなく固定物理アドレス
     * (下記NVMET_RDMA_RAMDISK_SLOT()、board.hのNVMET_RDMA_RAMDISK_BASE)
     * を指すポインタにした。呼び出し元(nvmet_rdma_run_standalone()/
     * nvme_rdma.c)が`.ctrl`をセットアップする際に必ずこのポインタも
     * `NVMET_RDMA_RAMDISK_SLOT(<instance>)`へ設定すること -- 設定を
     * 忘れるとNULLポインタのまま(構造体ゼロクリアの初期値)になる。
     * sizeof(ram_disk)はもはやポインタのサイズしか返さないため、
     * バッファ長が必要な箇所は必ずNVMET_RDMA_RAMDISK_SLOT_SIZEを直接
     * 使うこと(nvmet_rdma.c、sizeof(ctx->ctrl->ram_disk)は使わない)。 */
    volatile uint8_t *ram_disk;
} nvmet_rdma_ctrl_t;

/* インスタンス番号(0=nvmet_rdma_run_standalone()の実ホスト接続用、
 * 1=nvme_rdma.cのs_target_ctrl、ループバック検証用)から、そのRAM
 * ディスクの固定物理アドレスを返す(nvmet.hのNVMET_CTX_SLOT()と同じ
 * パターン)。 */
#define NVMET_RDMA_RAMDISK_SLOT(i) \
    ((volatile uint8_t *)(NVMET_RDMA_RAMDISK_BASE + (uint64_t)(i) * NVMET_RDMA_RAMDISK_SLOT_SIZE))

#define NVMET_RDMA_MAX_RAMDISK_INSTANCES 2u

/* ram_diskはCQバッファのpas[]のようなDMA記述子ページアライン要件を
 * 持たない(mlx5_qp_post_rdma_write()/post_rdma_read()のローカル
 * バッファ側に整列要件は無い、mlx5_dma_addr()は単純なオフセット加算)
 * ため、2MBアラインは不要 -- 64バイト(キャッシュライン)アラインのみ
 * 検証する。他の*_CACHE_BASE領域(MLX5_QP2_CACHE_BASE等)も同様の理由で
 * 2MBアラインされていない(mmu.cのL1 index 0ループがこの領域を含む
 * 2MBブロック全体を既にNormal cacheable RAMとしてカバーしているため、
 * 個々のバッファ自身が2MB境界に乗る必要はない)。 */
_Static_assert(NVMET_RDMA_RAMDISK_BASE % 64u == 0,
                "NVMET_RDMA_RAMDISK_BASE must be 64-byte-aligned");
_Static_assert((NVMET_RDMA_RAMDISK_BASE + (uint64_t)NVMET_RDMA_MAX_RAMDISK_INSTANCES * NVMET_RDMA_RAMDISK_SLOT_SIZE)
                    <= 0x40000000ULL,
                "NVMET_RDMA_RAMDISK region must stay within L1 index 0 (first 1GB, "
                "identity-mapped Normal cacheable RAM by mmu.c's catch-all sweep)");

/* コマンドパイプライン化(nvmet_rdma.cの「パイプライン化」節参照)で
 * 使う、1コマンド分の解析結果。単一コマンド逐次処理・パイプライン化の
 * 両方から参照する。 */
typedef struct {
    uint16_t cid;
    uint8_t  opcode;
    uint8_t  fctype;
    uint32_t nsid;
    uint32_t cdw10, cdw11, cdw12;
    uint64_t ksgl_addr;
    uint32_t ksgl_len;
    uint32_t ksgl_key;
    uint64_t io_slba;
    int      need_data_move;
    int      data_move_is_write;
    uint32_t resp_dw0;
    uint32_t resp_dw1;
    uint16_t resp_status;
} nvmet_rdma_pl_pending_t;

/* SQ(RDMA_WRITE/READ+応答SEND)の完了を先入れ先出しで追跡する。 */
typedef struct {
    int      is_resp_send;
    unsigned slot;
} nvmet_rdma_pl_sqop_t;

/* パイプライン化用の全内部状態(2026-08-13、IOキューのパイプライン対応で
 * ファイルスコープの共有staticから`nvmet_rdma_ctx_t`の埋め込みメンバへ
 * 移動 -- 以前は`nvmet_rdma.c`のファイルスコープstatic配列だったため、
 * admin queueとIOキューが同時にpipeline_enabled=1になると同じ配列を
 * 取り合って破壊し合っていた。1接続=1RC QP=1`nvmet_rdma_ctx_t`ごとに
 * 独立したパイプライン状態を持つことで、admin/IO双方が同時にパイプ
 * ライン化できるようにする。ctx全体のゼロクリア+dcache_clean_range()
 * (nvmet_rdma_run_standalone()等、既存の呼び出し元)がこのメンバも
 * 自動的にカバーする -- 追加の初期化コードは不要。 */
typedef struct {
    nvmet_rdma_pl_pending_t pending[NVMET_RDMA_MAX_PENDING];
    volatile uint8_t recv_bufs[NVMET_RDMA_MAX_PENDING][NVMET_RDMA_MSG_MAX] __attribute__((aligned(64)));
    volatile uint8_t resp_bufs[NVMET_RDMA_MAX_PENDING][NVME_CQE_LEN] __attribute__((aligned(64)));

    unsigned rq_order[NVMET_RDMA_MAX_PENDING];
    unsigned rq_head, rq_tail;

    nvmet_rdma_pl_sqop_t sq_ops[NVMET_RDMA_MAX_PENDING * 2u];
    unsigned sq_head, sq_tail;

    /* CLAUDE.md「nvmermabenchのボトルネック切り分け」節以降参照: RC QPが
     * 同時に受け付けられるRDMA_READ(RESPONDER RESOURCES、RRA)には実
     * ハードウェア上限がある(このカードは実測1件)ため、WRITEコマンド
     * (target視点でRDMA_READを発行してホストのwrite_bufを引き込む)の
     * 発行だけをHW上限(rra_max)でスロットリングする。 */
    uint32_t rra_inflight;
    uint32_t rra_max;
    unsigned rra_pending[NVMET_RDMA_MAX_PENDING];
    unsigned rra_pending_head, rra_pending_tail;
} nvmet_rdma_pl_state_t;

typedef struct nvmet_rdma_ctx nvmet_rdma_ctx_t;

struct nvmet_rdma_ctx {
    rdma_cm_ctx_t cm;

    /* 上記nvmet_rdma_ctrl_t参照。admin queue(queue_id=0)とIOキュー
     * (queue_id=1)が同一の実体を指すことで、CC.EN状態やIdentify応答
     * 内容が両キューから一貫して見える(nvmet_rdma_run_standalone()が
     * admin用ctxの生成時に1つだけ確保し、IOキュー用ctxにも同じポインタを
     * 渡す)。 */
    nvmet_rdma_ctrl_t *ctrl;

    /* フェーズ(i)続報: 0=admin queue(qid=0相当、常にコントローラ状態を
     * 自分で初期化する)、1=IOキュー(qid=1相当、ctrlは既存のものを
     * 共有するだけで自分では初期化しない)。nvme_rdma.cのループバック
     * ctx(s_target_ctx)は常に0のまま(既定値、変更不要)。 */
    uint8_t  queue_id;

    /* 真の場合、NVMETR_ST_CM_WAITでadmin queue(queue_id==0)の確立が
     * 完了した直後にIOキュー用の2本目のCM listenerを自動的にspawnする
     * (nvmet_rdma.cのnvmetr_on_admin_established()参照)。標準通り2本の
     * キューを要求する実Linuxホストとの接続でのみ真にする
     * (nvmet_rdma_run_standalone()が設定) -- nvme_rdma.cのループバック
     * 検証(`nvmerdmaconnect`/`nvmermabench`)は「combined single queue」
     * のまま変更しないため、既定(0)のままにしておくこと。 */
    int      enable_io_queue;

    volatile uint8_t recv_buf[NVMET_RDMA_MSG_MAX] __attribute__((aligned(64)));
    volatile uint8_t send_buf[NVMET_RDMA_MSG_MAX] __attribute__((aligned(64)));

    /* 現在処理中のコマンドの解析結果(DATA_MOVE/SEND_RESPステートで参照)。 */
    uint32_t recv_len;
    uint8_t  opcode;
    uint8_t  fctype;
    uint32_t nsid;
    uint16_t cid;
    uint32_t cdw10, cdw11, cdw12;
    uint64_t ksgl_addr;
    uint32_t ksgl_len;
    uint32_t ksgl_key;
    uint32_t resp_dw0;
    uint32_t resp_dw1;
    uint16_t resp_status;
    int      need_data_move;      /* 1ならDATA_MOVEステートを経由する */
    int      data_move_is_write;  /* 1=RDMA_WRITE(応答データ送出、Identify/Read)、
                                    * 0=RDMA_READ(データ受信、Write) */
    uint64_t io_slba;             /* Write時、RDMA_READ完了後にram_diskへコミットする位置 */

    uint64_t deadline;
    int      failed;
    int      established;

    /* nvme_rdma_run_connect_test()(nvme_rdma.c)がテスト完了後にこの
     * ジョブを安全に終了させるための要求フラグ。このジョブは本来
     * nvmet.cの常駐サーバと同様に無期限にWAIT_CAPSULEをループし続ける
     * 設計だが、`nvmerdmaconnect`は一発診断コマンド(mlx5rdmaconnect等と
     * 同じUX)であり、2回目以降の実行で新しいジョブを重複spawnすると
     * 同一ctx/同一rc_qpを2つのジョブが同時に触る競合を招く(実機で
     * 発見、CLAUDE.md「実際に見つかった本物のバグ: platform_init+test
     * 併用で同一net_ctxへ2組目のnvmetサーバが起動し...」節と同型)。
     * WAIT_CAPSULE(次のコマンドを待つだけの安全な待機点)でのみ確認する。 */
    volatile int stop_requested;

    /* nvme_rdma_run_bench()がqdepth>1を要求した場合にtarget側もこれを
     * 真にする(nvme_rdma.c参照) -- NVMETR_ST_CM_WAIT完了直後の分岐で
     * NVMETR_ST_PIPELINE_SETUPへ進むか、既存の単一コマンド逐次処理
     * (NVMETR_ST_POST_RECV)へ進むかを決める。2026-08-13、パイプライン
     * 状態がctxごとに独立した(下記pl参照)ことで、admin queueとIOキュー
     * が同時にpipeline_enabled=1でも安全になった -- 実ホスト接続用の
     * IOキュー(nvmetr_on_admin_established())もこれを真にする。 */
    int pipeline_enabled;

    /* パイプライン化用の内部状態(上記nvmet_rdma_pl_state_t参照)。この
     * ctxが単独で所有する(他のctxと共有しない) -- admin/IOそれぞれの
     * `nvmet_rdma_ctx_t`インスタンスが自分専用のRECV/応答バッファ・
     * FIFO・RRAスロットリング状態を持つため、同時にパイプライン化しても
     * 互いに干渉しない。 */
    nvmet_rdma_pl_state_t pl;

    /* フェーズ(i)続報: NVMETR_ST_CM_WAITでctx->established=1が確定した
     * 直後に(NULLでなければ)1度だけ呼ばれるコールバック。
     * nvmet_rdma_job_step()自体はこの用途に特化させたくない(loopback
     * 用のs_target_ctxにも影響しないよう汎用のまま保ちたい)ため、
     * 「admin queue確立完了を検知したらIOキューlistenerをspawnする」
     * という標準ホスト接続専用のロジックはnvmet_rdma.cの
     * nvmetr_on_admin_established()へ切り出し、ここにポインタとして
     * 差し込む形にした(既定NULL、既存の全呼び出し元は無変更のまま
     * 影響を受けない)。 */
    /* [関数ポインタ登録先] nvmetr_on_admin_established(nvmet_rdma.c、s_standalone_ctxに登録)。 */
    void (*on_established)(nvmet_rdma_ctx_t *self);

    /* ================================================================
     * 2026-08-13、切断検出(実機で発見: `nvme disconnect`後、admin/IO
     * 両ジョブがNVMETR_ST_PIPELINE_LOOPに永久に留まり、次の`nvme connect`
     * が応答無しでハングするバグの修正)。
     *
     * 実Linuxホスト(drivers/infiniband/core/cma.cのrdma_disconnect()、
     * drivers/nvme/host/rdma.cのnvme_rdma_stop_queue())は、admin/IO各
     * キューごとに個別のCM DREQ(Disconnect Request)MADをGSI経由で送信
     * する -- これがnvmet_rdma.cのNVMETR_ST_PIPELINE_LOOPが検出すべき
     * 唯一の確実な切断シグナル(TCPトランスポートのnvmet.cがFIN/RST
     * (tcp.cのtcp_recv失敗)で切断を検出するのと同じ位置づけ、CLAUDE.md
     * 「nvmet: 常駐サーバ化」節参照)。
     *
     * DREQはCM層(GSI QP)経由で届く一方、実際にトラフィックが流れる
     * のはRC QPなので、admin queue(queue_id==0、GSIを所有する側)だけが
     * このDREQ監視を行う -- IOキュー(queue_id==1、GSIを共有するだけ)は
     * 自分では監視せず、admin queueが切断を検出した時点でon_disconnected
     * 経由して道連れに終了させる(NVMe-oFの意味論上、admin queueが切れれば
     * 同じコントローラのIOキューも意味を失うため)。
     *
     * self_label!=NULL(nvmet_rdma_run_standalone()のみが設定)の場合に
     * 限りこの監視が有効になる -- nvme_rdma.cのループバック検証
     * (`nvmerdmaconnect`/`nvmermabench`)はself_labelを設定しないため、
     * 既存の`stop_requested`ベースの明示的終了フローが完全に無変更の
     * まま動作し続ける。 */

    /* netif_find()用のラベル(例: "mlx5-pf0")。切断検出後、rdma_cm_
     * fill_addr()を再度呼んでGSI/RC QPを作り直し、次のホスト接続を
     * 待てる状態へ戻すために必要(nvmet_rdma_run_standalone()が設定)。
     * NULL(既定)なら切断監視自体を行わない。 */
    const char *self_label;
    /* rdma_cm_fill_addr()の再呼び出し用フォールバックMAC(IBTA CM
     * メッセージにはMACが一切含まれないため、GID解決だけでは不十分
     * -- rdma_cm.hコメント参照)。 */
    uint8_t peer_mac_fallback[6];
    /* admin queue(queue_id==0)の切断を検出した際、1度だけ呼ばれる
     * コールバック(NULL可) -- nvmet_rdma_run_standalone()が
     * nvmetr_on_admin_disconnected()を設定し、ペアのIOキュー
     * (s_standalone_io_ctx)を道連れに終了させる。on_established()と
     * 対になる設計。 */
    /* [関数ポインタ登録先] nvmetr_on_admin_disconnected(nvmet_rdma.c、s_standalone_ctxに登録)。 */
    void (*on_disconnected)(nvmet_rdma_ctx_t *self);
};

job_result_t nvmet_rdma_job_step(job_t *self);

/* ConnectX RoCEv2 NVMe-oF実装計画フェーズ(i): 実Linuxホストとの接続確認
 * 用。指定PF(dev/self_label)上でnvmet_rdma_job_step()を常駐サーバとして
 * spawnし、外部からのCM接続を無期限に待ち受ける(nvmet.cのcmd_nvmet()と
 * 同じ非ブロッキングUX -- job spawn直後に即座に呼び出し元へ制御を返す)。
 * s_target_ctx(nvme_rdma.c、ループバック検証用)とは完全に独立した専用
 * インスタンスを使うため、`nvmerdmaconnect`/`nvmermabench`と競合しない。
 * peer側はrdma_cm_fill_addr()にダミー値を渡すだけでよい -- rdma_cm.cの
 * RDMA_CM_ST_PASSIVE_WAIT_REQでワイヤ上の実際の値(外部ホストの本物の
 * GID/QPN/PSN)に上書きされる設計のため(rdma_cm.cの「呼び出し元が
 * peer_gidを事前設定済みでも、ワイヤ上の実際の値を正とする」コメント
 * 参照)。既に稼働中なら何もせず案内メッセージだけ出す(重複spawn防止、
 * nvmet.cのnvmet_job_start()と同じ考え方)。 */
/* peer_mac(6バイト、NULL可)は、REQ受信より前にpassive側が送信する必要が
 * あるMAD(GSI宛のREP、RC QP確立後のRECV WQE構え自体はMAC不要)のAVで使う
 * フォールバック値。IBTA CMメッセージにはMACが一切含まれないため
 * (rdma_cm.cのコメント参照)、実ホストとの接続では呼び出し元が相手の
 * 実MACを別途知っている必要がある(NULLならゼロMACのまま、ループバック
 * 診断[mlx5-pf0等]と同じ挙動)。 */
void nvmet_rdma_run_standalone(mlx5_dev_t *dev, const char *self_label, const uint8_t peer_mac[6]);

/* nvmet_rdma_run_standalone()が保持するs_standalone_ctxのRC/GSI QP状態・
 * HW/SWカウンタをダンプする診断コマンド用(実Linuxホストとの接続確認で、
 * 相手が本当にRC QPへ届いているかをmlx5statとは別に切り分けるため --
 * mlx5statはmlx5_net.cのEthernet RQ/SQ[TCP/IPスタック統合バックエンド]
 * しか見えず、nvmet_rdma.cのRC QPは別の独立したFWオブジェクトのため)。 */
void nvmet_rdma_run_standalone_dump(void);

/* pcie1 reset(command.cのcmd_pcie1)から呼ぶ: ConnectXに紐づくRoCEv2系の
 * 全ジョブ(nvmet_rdma_job_step/rdma_cm_job_step/nvme_rdma_connect_job_step)
 * へ停止要求(cancel_requested)を出し、常駐フラグをリセットする。job.hの
 * ジョブテーブルは.bssにあり pcie1 reset(PERST#)/net init mlx5 では消え
 * ないため、ハードウェアをリセットする前にこれを呼んでジョブを畳まないと、
 * 再度nvmetrdmastart等を実行した際に古いジョブが残って重複する。実際の
 * テーブルからの除去は呼び出し元がこの後job_scheduler_tick()を回した時点
 * (nvmet_rdma.c参照)。 */
void nvmet_rdma_stop_all(void);

#endif /* NVMET_RDMA_H */
