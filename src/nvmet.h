#ifndef NVMET_H
#define NVMET_H

#include <stdint.h>
#include "nvmet_tcp.h"
#include "netif.h"

/* ================================================================
 * nvmet.h — NVMe/TCPターゲット側プロトコル層。SQEの解釈とCQEの組み立て
 * だけを担う(PDU/TCPの詳細はnvmet_tcp.hへ委譲する -- イニシエータ側
 * nvme.h/nvme.cと対になるレイヤ構成、CLAUDE.md参照)。
 *
 * 実装するのは単一subsystem・単一namespace(nsid=1)・単一controllerの
 * 最小限のNVMe-oFターゲットで、RAMディスクをバックエンドとする
 * (永続化なし、電源断/再起動で内容は失われる)。admin queue(qid=0)/
 * IO queue(qid=1)はNVMe-oF Fabricsの仕様通り別々のTCPコネクション
 * (nvmet_tcp_conn_t)として受け付ける。
 * ================================================================ */

#define NVMET_LBA_SIZE       512u
#define NVMET_NS_LBA_COUNT  524288u /* 256MB -- Linux(brd/malloc bdev)側と
                                     * 名前空間サイズを揃えて比較するため
                                     * 4MB から拡大した。x86 では
                                     * nvmet_ctx_t は .bss(main.c の
                                     * s_x86_nvmet)なので .bss が増える
                                     * だけ(このツリーは x86 専用のため、
                                     * ARM の固定スロット制約は適用しない)。 */
#define NVMET_SUBNQN "nqn.2014-08.org.nvmexpress:uuid:deadbeef-cafe-babe-dead-beefcafebabe"

/* 1コマンドで許可する最大データ転送量(バイト)。Identify ControllerのMDTS
 * フィールドと整合させること(nvmet.c参照)。
 *
 * 当初64KB(MDTS=4)にしていたが、実機のベンチマークで32KB書き込みから
 * "想定外のPDU種別"が延々と続く実際のバグを確認した。原因は本実装の
 * TCP層(src/tcp.c)がWindow Scalingに未対応で、広告できる受信ウィンドウが
 * 常に16bit(最大65535バイト)に固定されていること -- 64KB(65536バイト)の
 * in-capsuleデータに72バイトヘッダを足すと65,608バイトとなり、そもそも
 * 1コマンド分だけでこのウィンドウ上限を超えてしまう。ホストが
 * MAXCMD=32(nvmet.cのnvmet_build_id_ctrl()参照)を真に受けて32KB前後の
 * 書き込みを複数パイプライン発行すると、TCP受信バッファ(tcp.cの
 * TCP_RX_BUF_SIZE、約62.7KB)を超え、セグメントの取りこぼしから
 * ストリームが恒久的にズレる事象につながっていたと考えられる
 * (8KB書き込みは何百回も成功していたことと整合する)。この経緯から
 * 一度16KBまで下げた。
 *
 * その後、実LinuxホストのnvmeドライバとfioでNVMe/TCP write性能を計測した
 * ところ(`ts type IOWR`によるIOWR間隔の実測)、16KBチャンクでの実効
 * スループットは約10〜10.7MB/sで頭打ちだった。この値はtcpbenchが同じ
 * 16384Bチャンクサイズで記録した生TCPスループット(約8.4〜10.7MB/s、
 * CLAUDE.md「TCP/IPスタックの性能チューニング」節参照)とほぼ一致して
 * おり、nvmet_io_loop()の直列コマンド処理オーバーヘッドではなく、この
 * チャンクサイズでのTCPスタック自体の実効帯域が支配要因だったと判断
 * できる。tcpbenchは32768Bチャンクで約17.7〜17.9MB/sを記録しており
 * (ギガビットリンク化後)、32KBならヘッダ込みでも32,840バイトで
 * 16bitウィンドウ上限(65535バイト)・TCP_RX_BUF_SIZE(約62.7KB)の
 * どちらにも単発PDUとして収まる余裕がある(64KBで実際に踏んだ
 * ウィンドウ超過の再発ではない)ため、32KBへ引き上げた。
 *
 * 2026-07-25: fioで256KB書き込みを試したところ、常に複数の32KBコマンド
 * (MDTSの上限)に分割されてin-capsule送信されるだけで、R2T+H2CDataが
 * 一度も使われないことが判明した(下記NVMET_IOCCSZ_MAX_BYTES参照、当時は
 * IOCCSZもこの値と同じ計算式を使っており、MDTS以下の転送は必ず
 * in-capsule上限にも収まっていたため)。256KBを1コマンドとして発行
 * できるようにするため262144(256KB)へ引き上げ、IOCCSZは
 * NVMET_IOCCSZ_MAX_BYTESへ分離した。
 *
 * 同日、tcp.cにWindow Scaling(RFC7323)を実装しTCP_RX_BUF_SIZEを512KBへ
 * 拡張したことに伴い、R2T 1ラウンドあたりの上限(nvmet_tcp.cの
 * nvmet_tcp_max_h2c_data())もNVMET_MAX_TRANSFER_BYTESと同じ262144(256KB)
 * へ引き上げた -- Window Scaling成立コネクションでは256KBの受信ウィンドウを
 * 安全に広告できるため、R2T+H2CDataは複数ラウンドに分割せず1ラウンドで
 * 完結する(万一Window Scalingが不成立(相手が非対応)の接続では従来通り
 * 32768バイトずつ自動的に複数ラウンドへ分割される)。
 *
 * ただし256KB単発ラウンド化の直後、実機の256KB書き込みテストで
 * ストリームdesync(R2T送信直後に届くPDUが、そのH2CDataではなく別の
 * 書き込みコマンドのCapsule Command PDUだった)を確認した -- 原因は
 * ホストがR2T往復の完了を待たず複数の書き込みコマンドをパイプライン
 * 発行していたこと(Window Scalingでウィンドウが広がり先行送信が進み
 * やすくなって顕在化、正当なNVMe-oFの挙動)。これを受けnvmet_io_loop()
 * (nvmet.c)を「1コマンドずつ完全に同期処理する」設計から、複数の
 * 書き込みコマンドを同時にoutstandingとして追跡できる設計へ書き換えた
 * (nvmet.cのs_pending_writes[]、nvmet_tcp.h冒頭コメントの経緯も参照)。
 * R2Tの1ラウンドあたりの上限自体(この節の値)は変更していない -- 変更
 * したのは「1コマンドの完了を待たず次のPDUを読める」という受信側の
 * 制御フローの方。 */
#define NVMET_MAX_TRANSFER_BYTES 262144u

/* in-capsule(Command Capsule PDUに直接添付されるデータ)として受け付ける
 * データ量の上限(バイト)。
 *
 * 【2026-08-13、writeパイプライン化のためMDTSと同値(256KB)へ引き上げ】
 * 従来は32KBに据え置いていたが、これは「MDTS以下の全writeがin-capsuleに
 * 収まってR2T+H2CData経路が一度もテストされなくなる」というテスト
 * カバレッジ上の理由からの意図的な抑制であり、性能上の制約ではなかった。
 *
 * 実LinuxホストからのNVMe/TCP write計測(2026-08-13、CLAUDE.md「NVMe/TCP
 * over ConnectX」節)で、write性能がread(256k qd4で約400MiB/s、PCIe天井)に
 * 対し約30MiB/sで頭打ちになる原因を特定した: writeはR2T往復
 * (CMD→R2T→H2CData→CQE)を要し、ホストの単一io_workが大きいH2CDataの
 * 送信で占有される+ボードの~4msソフトTCP応答レイテンシで各コマンドが
 * ~8ms直列化され、iodepthを上げてもiops一定(実効depth~1)になっていた。
 * tcpdumpでもストリームがCMD1→data1→(~5ms空き)→CMD2という「1コマンド
 * ずつ」の流れだった。readがR2T往復を持たず(CMD受信後ただちにC2HData
 * 送信)ストリーム的にパイプライン化できるのと対照的。
 *
 * in-capsuleをMDTS(256KB)まで許せば、256KB writeもR2T往復なしに
 * Command Capsule PDU 1個(SQE+256KBデータ)として届き、readと対称に
 * なる -- ホストのio_workはCMD+dataを連続送信でき、ボードは連続受信
 * (2MBのTCP_RX_BUF_SIZE+広げた広告ウィンドウ)するだけになるため、
 * R2T往復由来の直列化が原理的に消える。DISPATCH_CMDのin-capsule経路は
 * データが既にjc->data_bufに届いている前提でR2Tを待たず即コミットする
 * (nvmet.c参照)。
 *
 * トレードオフ: この設定ではR2T+H2CData経路が(MDTS以下のwriteでは)
 * 使われなくなる -- R2Tパスのコードは残すが常時deadになる。MDTSを
 * 超える転送(行儀の良いホストは発行しない)のみR2T経路を通る。256KBの
 * Command Capsule PDU(ヘッダ72+256KB)はTCP_RX_BUF_SIZE(2MB)に単発で
 * 十分収まる。 */
#define NVMET_IOCCSZ_MAX_BYTES 262144u

/* nvmet.cが同時に稼働させられるnvmet_ctx_tインスタンス(常駐サーバ)の
 * 上限。platform_init.cがRP1+ConnectX PF0/PF1の最大3系統を自動起動し、
 * `nvmet`シェルコマンドの手動起動用に1系統の余裕を持たせて4にしてある
 * (nvmet.cのジョブコンテキストプール、job.hのJOB_MAX=12はこの4×2=8 +
 * ping/nvme connect等の一時ジョブ用の余裕を見込んだ値)。 */
#define NVMET_MAX_INSTANCES 1u  /* x86専用ツリー: NVMET_NS_LBA_COUNT を 256MB へ
                                 * 拡大した結果、4 インスタンスでは固定領域が
                                 * 1GB を超え _Static_assert に掛かるため。
                                 * x86 では nvmet_ctx_t は .bss(main.c の
                                 * s_x86_nvmet)1 個だけで、NVMET_CTX_SLOT()
                                 * 自体を使わない(このツリーは x86 専用)。 */

/* 同時にR2T応答待ちにできる書き込みコマンドの最大数(インスタンスごと)。
 * ホストが実際にこれを超える数を先行発行してきた場合、超過分は空き
 * スロットができるまで即座にエラー応答で拒否する(nvmet.cの
 * nvmet_pending_write_alloc()参照) -- ストリームは壊さない(SQE受信
 * 自体は完了させ、単にR2Tを送らずエラーCQEだけ返す)ので安全側の劣化に
 * 留まる。8件×NVMET_MAX_TRANSFER_BYTES(256KB)=2MBのRAMをインスタンス
 * ごとに使う(実機のRAM予算には十分な余裕がある)。 */
#define NVMET_MAX_PENDING_WRITES 8u

typedef struct {
    int      in_use;
    uint16_t cid;
    uint64_t slba;
    uint32_t write_len;
    uint32_t received;   /* このコマンドについてこれまでに受信したH2CDataバイト数 */
} nvmet_pending_write_t;

typedef struct {
    nvmet_tcp_conn_t admin;
    nvmet_tcp_conn_t io;
    int      io_connected;
    uint16_t ctrlr_id;   /* 固定値1 */
    uint32_t cc;         /* CCレジスタ(Property Setで書き込まれる) */
    int      cc_en;      /* cc & NVME_CC_ENが立ったら1 */

    /* NVMe/TCP制御のジョブ化(job.h基盤、CLAUDE.md「NVMe/TCP制御の
     * ステートマシン化」節参照)向け、admin job/io job間の合図用フラグ群。
     * 従来nvmet_run()が単一の関数呼び出し順序(admin_loop→IOキュー
     * accept待ち→io_loop→終了時に両方close)で表現していた制御を、
     * 独立した2本のjob_t間の明示的な信号のやり取りへ分解したもの。
     *
     *   io_armed:      admin jobがSet Features(Number of Queues)への
     *                   応答を送り終えた時点で立てる。io jobはこれを
     *                   見てからIOキューのaccept/ICReq処理へ進む。
     *   admin_failed:  admin jobが「一切クライアントが接続していない
     *                   待受中(NADM_ST_ACCEPT_WAIT)」にCtrl+Cを受けて
     *                   サーバ自体を停止した場合に立てる(常駐サーバ化、
     *                   CLAUDE.md「nvmet: 常駐サーバ化」節参照 --
     *                   セッション確立段階の一時的な失敗はサーバを
     *                   止めず次のクライアントを待つARM状態へ戻るだけ
     *                   なのでこのフラグは立てない)。io jobはWAIT_
     *                   ADMIN_READY状態でこれを見た場合、ctx->ioには
     *                   一切触れず(まだ開いていないため)静かにJOB_DONE
     *                   で終了する。
     *   session_done:  io jobが1クライアントとのセッション終了(正常
     *                   切断・エラー)を検出し、ctx->io/ctx->admin双方の
     *                   close含む後始末を終えた時点で立てる。admin job
     *                   はループの先頭でこれを見て次のクライアントを
     *                   待つARM状態へ戻る(サーバ自体は停止しない)。
     *   session_active: nvmet_job_start()がジョブをspawnした時点で立て、
     *                   admin_failed(Ctrl+Cによる完全停止)に達した時点で
     *                   0に戻す -- 「クライアントが接続中」ではなく
     *                   「サーバが稼働中(次の接続を待っているか、
     *                   処理中)」を表す。cmd_nvmet()やplatform_init()が
     *                   同じctxで二重起動しないためのガードに使う。 */
    volatile int io_armed;
    volatile int admin_failed;
    volatile int session_done;
    volatile int session_active;
    /* `job stop <番号>`シェルコマンド(job.hのjob_request_cancel())で
     * admin/ioどちらのジョブがキャンセルされても、Ctrl+Cと同じ「サーバ
     * 自体を止める」扱いにするための内部リレーフラグ。job_t.cancel_
     * requestedはジョブ単位(admin用/io用の2つ)だが、実際の停止処理
     * (リスナー解除等)はadmin job(NADM_ST_ACCEPT_WAIT)側の責務に一本化
     * してあるため、io job側が自分のcancel_requestedを見た場合は直接は
     * 何もせずこのフラグを立ててadminへリレーする(nvmet_io_job_step()
     * 参照)。Ctrl+Cと同じ理由(進行中のセッションを壊さない)で
     * NADM_ST_ACCEPT_WAIT(誰も接続していない待受中)でのみ実際に反映
     * される。 */
    volatile int stop_requested;

    /* 常駐サーバの待ち受け設定(nvmet_job_start()が設定、インスタンス
     * 生存期間中固定)。複数インターフェース同時待受(CLAUDE.md「nvmet:
     * 複数インターフェース同時待受」節参照)向けにtcp_listen()を
     * インスタンスごとに1回だけ確保し、admin/IO両方のaccept段階で
     * 同じハンドルを使い回す。 */
    int         listener;    /* tcp_listen()ハンドル */
    netif_t  *bound_ctx;   /* 待ち受けるインターフェース、NULL=任意 */
    const char *label;       /* ログ用ラベル(例"rp1"、複数インスタンスの
                               * ログを区別するため) */

    /* admin/io両job stepの「各ステート滞在時間」プロファイラ
     * (stateprof.h参照、~/.claude/plans/wondrous-baking-gadget.md
     * 「次回セッションへの申し送り」節のマルチコア効果測定向け)。
     * nvmet_admin_job_step()/nvmet_io_job_step()の先頭が毎回
     * state_prof_mark()を呼ぶ。ctxが固定物理アドレス(NVMET_CTX_SLOT())
     * に置かれているため、admin(core0固定)とio(core1へpin止め
     * されうる)を異なるコアから読み書きしても、CLAUDE.md「MMUは有効」
     * 節のキャッシュコヒーレンシ設計によりロック無しで安全(jobs/
     * smpstat/ts coreと同じ前提)。 */

    /* このインスタンス専用のNVMe名前空間バックエンド(RAMディスク・
     * Identify応答)。複数インスタンスを完全に独立させるため(各系統が
     * 別々のRAMディスクを持つ、CLAUDE.md「nvmet: 複数インターフェース
     * 同時待受」節参照)、旧実装のファイルスコープstaticから移した。 */
    uint8_t  ram_disk[NVMET_NS_LBA_COUNT * NVMET_LBA_SIZE] __attribute__((aligned(64)));
    uint8_t  id_ctrl[4096] __attribute__((aligned(64)));
    uint8_t  id_ns[4096]   __attribute__((aligned(64)));

    /* IOキューの書き込みパイプライン追跡(旧実装のファイルスコープ
     * staticから移した -- 複数インスタンスが同時にoutstandingな書き込み
     * を持ちうるため、インスタンスごとに独立させる必要がある)。 */
    uint32_t write_incapsule_count;
    uint32_t write_h2c_count;
    /* 2026-08-11、ユーザー承認済みの最適化でpending_write_bufs[]
     * (専用ステージングバッファ、旧実装ではH2CDataを一旦ここへ受信して
     * から全ラウンド完了後にram_disk[]へコミットコピーしていた)を撤去
     * した -- 宛先LBAはコマンド受理時点で判明済みのため、H2CDataは最初
     * からram_disk[]の該当オフセットへ直接受信する(nvmet.cの
     * nvmet_io_job_h2c_validate()参照)。これにより、ステージング
     * バッファ分の8MB(NVMET_MAX_PENDING_WRITES×NVMET_MAX_TRANSFER_BYTES)
     * のメモリと、write完了ごとのwrite_lenバイト分のコミットコピー
     * (実機実測で約72-120us/コマンド)の両方を削減できた。 */
    nvmet_pending_write_t pending_writes[NVMET_MAX_PENDING_WRITES];
} nvmet_ctx_t;

/* portでリッスンするNVMe/TCPターゲットセッションを開始する。admin/IO
 * キューをそれぞれ独立したjob_t(job.h)としてspawnし、即座に呼び出し元へ
 * 戻る -- 実際のaccept/ICReq/コマンド処理は以後job_scheduler_tick()が
 * 毎tick進める(旧nvmet_run()のような「イニシエーターが切断するまで
 * ブロックする」設計ではない、CLAUDE.md参照)。
 *
 * bound_ctx: このインスタンスが待ち受けるインターフェース(netif.h、
 * tcp_listen()へそのまま渡す) -- 複数インスタンスが同じport番号で異なる
 * インターフェースへ同時に待ち受けられるようにするため(CLAUDE.md
 * 「nvmet: 複数インターフェース同時待受」節参照)。NULLならインター
 * フェースを問わず受け付ける(`nvmet`シェルコマンドの手動起動等、単一
 * インターフェース運用向け)。
 * label: `jobs`コマンド等のログでこのインスタンスを識別するための短い
 * 文字列(例"rp1"、呼び出し元が生存期間中保持する静的文字列を渡すこと)。
 * 戻り値: 0=spawn成功、-1=インスタンス上限/ジョブテーブル満杯等で失敗 */
int nvmet_job_start(nvmet_ctx_t *ctx, uint16_t port, netif_t *bound_ctx, const char *label);

/* ================================================================
 * ステート滞在時間プロファイラ(stateprof.h、~/.claude/plans/
 * wondrous-baking-gadget.md「次回セッションへの申し送り」節の
 * マルチコア効果測定向け)へのアクセサ。ctx->admin_prof/io_prof自体は
 * nvmet_admin_job_step()/nvmet_io_job_step()が毎回state_prof_mark()を
 * 呼んで更新し続けるので、これらは「今から計測を始める/今までの結果を
 * 見る」ための区切り操作にすぎない。
 * ================================================================ */

#endif /* NVMET_H */
