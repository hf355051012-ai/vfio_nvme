#ifndef NVMET_TCP_H
#define NVMET_TCP_H

#include <stdint.h>
#include "tcp.h"
#include "nvme_types.h"
#include "nvme_tcp_pdu.h"  /* NVME_TCP_HDR_LEN(下記API群のヘッダバッファサイズに使う) */

/* ================================================================
 * nvmet_tcp.h — NVMe/TCP (NVMe-oF TCPトランスポート) ターゲット側
 * 接続・PDU送受信層。イニシエータ側nvme_tcp.h/nvme_tcp.cの鏡像
 * (tcp_connect/tcp_send/tcp_recvではなくtcp_listen/tcp_acceptを使う点、
 * PDUの往復方向が逆になる点を除き構造は同じ)。プロトコル層(nvmet.c)は
 * このヘッダのAPIのみを使い、TCP/PDUの詳細に触れない(nvme_tcp.h冒頭
 * コメントと同じレイヤ境界 -- CLAUDE.md記載のレイヤ構成)。
 *
 * 2026-07-25、IOキューのパイプライン対応(下記API群参照)に伴いAPIを
 * 拡張した。経緯: 当初nvmet_tcp_recv_cmd()(Command Capsule 1件受信)と
 * nvmet_tcp_recv_h2c()(R2T送信+そのH2CData受信までブロック)という
 * 「1コマンドずつ完全に同期処理する」設計だったが、実機の256KB書き込み
 * テストで、R2T送信後の次PDU読み取りが実際にはH2CDataではなく**別の
 * 書き込みコマンドのCapsule Command PDU**だったために型不一致で
 * ストリームdesyncする事象を確認した。原因はホスト側がR2T往復の完了を
 * 待たず複数の書き込みコマンドをパイプライン発行していたこと(Window
 * Scalingでウィンドウが広がったことで、以前より先行送信が進みやすく
 * なり顕在化した)。これはNVMe-oFとして正当な挙動であり、こちら側が
 * 「1コマンドずつ」という前提を捨てる必要がある。
 *
 * 対応として、IOキューは下記の低レベルAPI(nvmet_tcp_recv_pdu_type()で
 * 種別だけを見てから、CMD/H2C_DATAそれぞれの続きを読む)を使い、
 * nvmet.c側で複数の書き込みコマンドを同時に outstanding として管理する
 * (nvmet.cのs_pending_writes[]参照)。adminキューは元々パイプライン
 * されない(1コマンドずつのFabrics Property Set/Get等)ため、従来通り
 * nvmet_tcp_recv_cmd()(1コマンド分をまとめて読む)を使い続けてよい。
 * ================================================================ */

typedef struct {
    tcp_conn_t tcp;
    uint16_t   maxdata;   /* ICReqで受け取ったinitiatorのmaxr2t(参考値として
                            * 保持するのみ -- こちらがR2Tで実際に使うMAXH2CDATAは
                            * ICRespで送るこちら側の値であり、これとは無関係)。 */
    uint16_t   last_cid;  /* 直前にnvmet_tcp_recv_cmd()で受信したコマンドの
                            * CID -- adminキュー(1コマンドずつ同期処理、パイプ
                            * ライン無し)専用。IOキューはコマンドが同時に複数
                            * outstandingになりうるため、この共有フィールドを
                            * 使わずcid/cccidを呼び出し元(nvmet.c)が明示的に
                            * 引数として運ぶ設計にした(2026-07-25) -- 詳細は
                            * 上記ファイル冒頭コメントの経緯参照。 */
    uint8_t    hdgst;     /* ヘッダダイジェスト(CRC32C)有効/無効。ICReqの
                            * digestバイトbit0から確定し(nvmet_tcp_accept_wait()
                            * 参照)、以後このコネクションの全PDU送受信で
                            * 一貫して使う(PDUごとのflagsビットは見ない --
                            * ネゴシエーション時に一度確定すれば十分という
                            * 単純化、2026-07-25追加)。 */
    uint8_t    ddgst;     /* データダイジェスト(CRC32C)有効/無効。ICReqの
                            * digestバイトbit1から確定(上記hdgstと同じ扱い)。 */
} nvmet_tcp_conn_t;

/* nvmet_tcp_accept()を「受け付け準備(ブロックしない)」と「実際に
 * ESTABLISHED+ICReq/ICResp交換まで待つ」の2段に分けたもの。
 * nvmet_tcp_accept()は内部でtcp_listen()してこの2つを呼ぶだけ(実装は同じ)。
 * listener: 呼び出し元(nvmet.c)がインスタンス単位で1回だけ確保した
 * tcp_listen()ハンドル(複数インターフェース同時待受、CLAUDE.md「nvmet:
 * 複数インターフェース同時待受」節参照) -- admin/IO両方のaccept段階で
 * 同じハンドルを使い回す。
 *
 * 呼び出し側(nvmet.c)は、admin queueの最後の応答(Set Features(Number of
 * Queues)のCQE)を送るより前に、できるだけ早くnvmet_tcp_accept_arm()を
 * 呼んでIO queue用の受け皿を用意しておくこと -- tcp_accept_begin()の
 * コメント参照。相手はこちらの応答送信をまたずIO queue用のSYNを送って
 * くることがあり、受け皿が無い状態でSYNが届くと黙って捨てられ
 * (相手のSYN再送、通常1秒程度、を待つ羽目になる)、実機のnvme-tcpホスト
 * ではこの遅延が全体のキュー確立タイムアウトに食い込んで接続ごと
 * 中断される事象を確認した。 */
void nvmet_tcp_accept_arm(nvmet_tcp_conn_t *c, int listener);

/* R2T PDUを1件送りっぱなしで送信する(応答を待たずすぐ戻る)。cidは
 * 対象コマンドのCID(ワイヤのcccidフィールドに使う)、r2to/r2tlは
 * このラウンドが要求するオフセット/長さ。1コマンドの転送量が単発PDUの
 * 安全上限(nvmet_tcp_max_h2c_data())を超える場合、呼び出し元(nvmet.c)が
 * ラウンドごとにこれを複数回呼ぶこと(2026-07-25、旧nvmet_tcp_recv_h2c()
 * の内部ループを呼び出し元へ移した -- パイプライン対応のため、1コマンド
 * の全ラウンド完了をこの関数の中で待たない設計にした)。
 * 戻り値: 0=成功, -1=送信失敗 */
int nvmet_tcp_send_r2t(nvmet_tcp_conn_t *c, uint16_t cid,
                        uint32_t r2to, uint32_t r2tl);

/* connがいるTCPコネクションでWindow Scalingが成立しているかに応じて、
 * 安全なR2T 1ラウンドあたりの上限を返す(nvmet_tcp.c参照)。nvmet.c側が
 * 複数ラウンドの分割判断に使う。 */
uint32_t nvmet_tcp_max_h2c_data(const nvmet_tcp_conn_t *c);

/* Response Capsule PDU(CQEのみ、24バイト)を送信する。
 * 書き込みコマンド完了・Adminコマンド応答に使う。
 * 戻り値: 0=成功, -1=失敗 */
int nvmet_tcp_send_resp(nvmet_tcp_conn_t *c, const nvme_cqe_t *cqe);

/* C2HData PDUを送信し、必要なら続けてResponse Capsuleも送る(読み出し
 * コマンド用)。cidは対象コマンドのCID(ワイヤのcccidフィールドと、
 * data_success=0の場合に送るCQEのログに使う -- CQE自体の中身はcqe引数が
 * 持つ)。data_success=1の場合はDATA_SUCCESSフラグを立てて
 * Response Capsuleを省略する。
 * 戻り値: 0=成功, -1=失敗 */
int nvmet_tcp_send_c2h(nvmet_tcp_conn_t *c, uint16_t cid, const nvme_cqe_t *cqe,
                       const void *data, uint32_t dlen,
                       int data_success);

/* nvmet_tcp_send_c2h()の非同期版(2026-08-10、READパイプライン化 --
 * CLAUDE.md「READ性能: 生TCPとの一番大きな差分」節参照)。tcp_send()
 * (相手のACKを待つブロッキング)ではなくtcp_send_async()(送りっぱなし)
 * でヘッダ+データを送る。nvme.cのnvme_pipeline_h2c_pump()と同じ
 * ゼロコピー方針でdataから直接キューする(nvmet_tcp_send_c2h()のように
 * s_c2h_bufへコピーしない)ため、以下2点の制約がある:
 * - ヘッダ/データダイジェスト(c->hdgst/c->ddgst)が有効な接続では使えない
 *   (計算にはコピー後の連続バッファか専用ロジックが必要になるため今回の
 *   スコープ外) -- 呼び出し元がc->hdgst/c->ddgstを見て、有効なら代わりに
 *   nvmet_tcp_send_c2h()(data_success=1)を呼ぶこと。
 * - dlenはNVMET_TCP_C2H_CHUNK_MAX(262144、nvmet_tcp.c)以下であること
 *   (複数PDUへの分割は非対応 -- このプロジェクトの全呼び出し元はMDTS/
 *   NVMET_MAX_TRANSFER_BYTESで既にこの範囲を保証している)。
 * data_successは常に1固定(別送のResponse Capsuleは送らない、このC2HData
 * 自体が暗黙の完了応答を兼ねる)。
 * 戻り値: 0=キュー成功(確認はまだ)、-1=送信自体の失敗 */
int nvmet_tcp_send_c2h_async(nvmet_tcp_conn_t *c, uint16_t cid,
                              const void *data, uint32_t dlen);

/* コネクションを閉じる(tcp_close()をそのまま呼ぶ)。 */
void nvmet_tcp_close(nvmet_tcp_conn_t *c);

/* ================================================================
 * NVMe/TCP制御のジョブ化(nvmet.c、job.h基盤、CLAUDE.md「NVMe/TCP制御の
 * ステートマシン化」節参照)向けの非ブロッキング・resumableプリミティブ。
 *
 * 上記の各nvmet_tcp_recv_*()/accept_wait()系はいずれも内部で完了/
 * タイムアウトまでブロックするため、job_step_fn(1tick分だけ処理して
 * 即座に戻らねばならない)からは呼べない。既存関数は(実機実績・バグ
 * 修正済みロジックを壊さないため)一切変更せず、代わりに下記の薄い
 * 非ブロッキング版を追加する。nvmet.c側のジョブは、既存の
 * nvmet_tcp_recv_cmd_body()等と全く同じ順序(ヘッダ8B→SQE/H2C-rest→
 * [hdgst 4B]→[data]→[ddgst 4B])を、状態ごとに1回のtick=1回の
 * nvmet_tcp_recv_poll()呼び出しとして再現する。
 * ================================================================ */

/* 「厳密にwantバイト受信する」ことを複数tickにまたがって追跡するための
 * カーソル。呼び出し側(nvmet.cのジョブコンテキスト)がstateとして保持する。 */
typedef struct {
    uint8_t  *buf;
    uint32_t  want;
    uint32_t  got;
} nvmet_tcp_xfer_t;

/* 新しい受信を開始する(got=0にリセットするだけ)。 */
void nvmet_tcp_xfer_reset(nvmet_tcp_xfer_t *x, void *buf, uint32_t want);

/* xの続きを1回分だけ非ブロッキングで試みる(tcp_recv_no_ack(timeout_ms=0)を
 * 1回だけ呼ぶ -- tcp.cのtcp_recv_internal()はdo-while構造のため、
 * timeout_ms=0でも本体は必ず1回実行されてから即座に抜ける、tcp.c参照)。
 * 呼び出し側は0が返る間、次tickで再度呼ぶこと。
 * 戻り値: 1=want分すべて受信完了、0=まだ途中、-1=FIN/Ctrl+C中断(エラー) */
int nvmet_tcp_recv_poll(nvmet_tcp_conn_t *c, nvmet_tcp_xfer_t *x);

/* hdr_buf(nvmet_tcp_recv_pdu_type()相当、8バイト受信済み)からhlen/plenを
 * 解析し、in-capsule/H2Cデータの実長を返す(nvmet_tcp_recv_cmd_body()内の
 * 既存計算をそのまま切り出したもの、計算式は複製せず共有する)。 */
uint32_t nvmet_tcp_parse_cmd_dlen(const nvmet_tcp_conn_t *c, const uint8_t hdr_buf[NVME_TCP_HDR_LEN]);

/* 受信済みバイト列に対しCRC32C比較のみ行う(I/Oなし、瞬時)。gotは
 * nvmet_tcp_recv_poll()で別途受信済みの4バイト(ダイジェスト値そのもの)。
 * 既存のnvmet_tcp_check_hdgst()/_check_ddgst()(static、受信込み)から
 * 比較部分だけを切り出したもの。
 * 戻り値: 0=無効化(c->hdgst/ddgst=0)または一致、-1=不一致 */
int nvmet_tcp_verify_hdgst(const nvmet_tcp_conn_t *c,
                            const void *hdr1, uint32_t len1,
                            const void *hdr2, uint32_t len2,
                            const uint8_t got[4]);
int nvmet_tcp_verify_ddgst(const nvmet_tcp_conn_t *c,
                            const void *data, uint32_t len,
                            const uint8_t got[4]);

/* ICReq受信済み(icreq_buf、NVME_TCP_ICREQ_LEN分)からdigestビット/maxr2tを
 * 解析してc->hdgst/c->ddgst/c->maxdataへ反映し、ICRespを構築して送信する。
 * nvmet_tcp_accept_wait()内の同処理をこの関数へ切り出し、accept_wait()
 * 自身はこれを呼ぶだけにした(ロジックの実体は1箇所のみ -- ジョブ化の
 * ためのextract-function、外部から見た既存関数の挙動は変えていない)。
 * ジョブ側は、nvmet_tcp_recv_poll()でICREQ_LEN分の受信完了を確認した
 * 直後にこれを呼ぶこと。
 * ICResp送信自体はtcp_send()(ブロッキング、128バイト単発セグメント)の
 * ままとする(CLAUDE.md「NVMe/TCP制御のステートマシン化」節、既知の
 * 残ブロッキングとして許容 -- 十分小さく高速なため)。
 * 戻り値: 0=成功、-1=不正なICReq(type不一致)またはICResp送信失敗 */
int nvmet_tcp_send_icresp(nvmet_tcp_conn_t *c, const uint8_t icreq_buf[NVME_TCP_ICREQ_LEN]);

#endif /* NVMET_TCP_H */
