#ifndef NVME_TCP_H
#define NVME_TCP_H

#include <stdint.h>
#include "tcp.h"
#include "nvme_types.h"
#include "nvme_tcp_pdu.h"  /* NVME_TCP_ICRESP_LEN(下記ジョブ化向けAPI群のヘッダバッファサイズに使う) */

/* ================================================================
 * nvme_tcp.h — NVMe/TCP (NVMe-oF TCPトランスポート) 接続・PDU送受信層。
 * ConnectX-4等の別トランスポートへ移植する際に差し替える境界
 * (CLAUDE.md記載のレイヤ構成) -- nvme.c(プロトコル層)はこのヘッダの
 * API(nvme_tcp_connect/send_cmd/recv_resp/close)のみを使い、TCP/PDUの
 * 詳細に触れない。
 * ================================================================ */

typedef struct {
    tcp_conn_t tcp;
    uint32_t   maxdata;    /* ICRespのMAXH2CDATA -- 1回のH2CDataで送れる最大バイト数 */
    uint16_t   next_cid;   /* コマンドID採番カウンタ(nvme_tcp_send_cmd()が使用) */

    /* nvme_tcp_send_cmd()が(書き込みコマンドの)データを預かり、
     * nvme_tcp_recv_resp()がR2T受信時にH2CDataとして送り返すために保持する
     * 状態。本実装は1コネクションにつき常に1コマンドをブロッキングで
     * 直列実行する設計(admin/IO各キューはnvme.cが別々のnvme_tcp_conn_tを
     * 持つことで区別する)なので、同時に保留できる書き込みは1件のみで
     * 十分。 */
    const uint8_t *pending_data;
    uint32_t       pending_len;
    uint16_t       pending_cid;
} nvme_tcp_conn_t;

/* sqeをCommand Capsule PDUとして送信する。cidはこの関数が採番し
 * (sqeのcdw0内cidフィールドを上書きする)、応答待ち(nvme_tcp_recv_resp())
 * との対応付けに使う。
 * data/dlen: 書き込みコマンドが転送するデータ。実際に送る方式(in-capsule
 *            かR2T+H2CData分割か)はsqeのSGL Descriptor Type(dptr[15]、
 *            nvme_types.hのNVME_SGL_TYPE_*)で決まる -- 呼び出し元
 *            (nvme.cのnvme_build_write_sqe()、NVME_TCP_INLINE_DATA_MAX
 *            以下ならNVME_SGL_TYPE_DATA_BLOCK_OFFSET、超えるなら
 *            NVME_SGL_TYPE_TRANSPORTを設定する)が事前に選んでおく必要が
 *            ある(2026-08-08、R2T分割実装 -- 以前はNVME_TCP_INLINE_
 *            DATA_MAX超過を無条件でエラーにしていた)。TRANSPORT型の
 *            場合、このPDUにはデータを一切付加せず、dlen全体を
 *            pending_data/pending_lenへ保留するだけ -- 続くR2T受信への
 *            応答はnvme_tcp_recv_resp()(ブロッキング版)またはnvme.cの
 *            nvme_exec_step()(ジョブ化版)が既存のR2T処理ロジックで
 *            自動的に行う(nvme_tcp_send_h2c_data()参照)。読み出し
 *            コマンド、またはデータを伴わないコマンドはdata=NULL,
 *            dlen=0でよい。
 * 戻り値: 0=送信成功、-1=失敗(in-capsuleでデータ過大な場合も含む) */
int nvme_tcp_send_cmd(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe,
                      const void *data, uint32_t dlen);

/* nvme_tcp_send_cmd()の非同期版(tcp_send_async()経由、in-capsuleデータ
 * 無し専用)。2026-08-09、NVMe/TCPコマンドパイプライン化
 * (nvme.cのnvme_write_pipelined_run()参照)向け。cidは呼び出し元が
 * 明示的に受け取る(内部で採番、conn->pending_cidは変更しない -- 複数
 * スロットが同時に自分のcidを追跡する必要があるため)。
 * 呼び出し規則: 戻った直後、同一コネクションへブロッキングtcp_send()を
 * 呼ぶ前に必ずtcp_send_async_drain()(tcp.h)で未確認送信を空にすること。
 * 戻り値: 0=キュー成功(*out_cidに採番値)、-1=失敗 */
int nvme_tcp_send_cmd_async(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe, uint16_t *out_cid);

/* コネクションを閉じる(tcp_close()をそのまま呼ぶ)。 */
void nvme_tcp_close(nvme_tcp_conn_t *c);

/* ================================================================
 * NVMe/TCP制御のジョブ化(nvme.c、job.h基盤、CLAUDE.md「NVMe/TCP制御の
 * ステートマシン化」節参照)向けの非ブロッキング・resumableプリミティブ。
 * nvmet_tcp.h(ターゲット側、フェーズ2)と対になる構成 -- 既存の
 * `nvme_tcp_connect()`/`nvme_tcp_send_cmd()`/`nvme_tcp_recv_resp()`/
 * `nvme_tcp_close()`は一切変更せず残す(`nvme bench`が引き続き使う)。
 * ================================================================ */

typedef struct {
    uint8_t  *buf;
    uint32_t  want;
    uint32_t  got;
    /* このxferがnvme_tcp_xfer_reset()された時刻。性能分析用(nvme_tcp.cの
     * nvme_tcp_recv_poll()が記録するNRFB/NRDNタグ、2026-08-09、コア0の
     * SEND_H2C/RECV_CQE遅延解析向けにユーザー指示で追加) -- 「応答その
     * ものが遅い」のか「応答は届いているのに受信処理が遅れて気づいた」
     * のかを切り分けるために使う。 */
    uint64_t  reset_tick;
} nvme_tcp_xfer_t;

void nvme_tcp_xfer_reset(nvme_tcp_xfer_t *x, void *buf, uint32_t want);

/* xの続きを1回分だけ非ブロッキングで試みる(tcp_recv(timeout_ms=0)を
 * 1回だけ呼ぶ -- tcp.cのtcp_recv_internal()はdo-while構造のため、
 * timeout_ms=0でも本体は必ず1回実行されてから即座に抜ける、
 * nvmet_tcp.hの同種コメント参照)。tcp_recv()(ACK付き)を使う点が
 * nvmet_tcp_recv_poll()のtcp_recv_no_ack()と異なる -- 既存の
 * nvme_tcp_recv_exact()も明示的なwindow更新ACKを都度送る設計のため、
 * その挙動を維持する。
 * 戻り値: 1=want分すべて受信完了、0=まだ途中、-1=FIN/Ctrl+C中断(エラー) */
int nvme_tcp_recv_poll(nvme_tcp_conn_t *c, nvme_tcp_xfer_t *x);

/* TCP接続確立(ESTABLISHED)直後に呼ぶ。コネクションごとの状態
 * (maxdata/next_cid/pending_*)を初期化した上でICReq(128B固定)を
 * 構築・送信する(送信は単発ブロッキングtcp_send()のまま許容 --
 * nvmet_tcp_send_icresp()と同じ扱い)。
 * 戻り値: 0=送信成功、-1=送信失敗 */
int nvme_tcp_send_icreq(nvme_tcp_conn_t *c);

/* nvme_tcp_recv_poll()でICRESP_LEN(128B)分の受信完了を確認した直後に
 * 呼ぶ。type/hlen/digestを検証し、問題なければc->maxdataを確定する
 * (既存nvme_tcp_connect()内の検証ロジックを抽出したもの)。
 * 戻り値: 0=成功、-1=不正なICResp(type/hlen不一致)またはdigest要求(未対応) */
int nvme_tcp_verify_icresp(nvme_tcp_conn_t *c, const uint8_t icresp_buf[NVME_TCP_ICRESP_LEN]);

/* R2Tで要求された[r2to, r2to+r2tl)の範囲を、直前のnvme_tcp_send_cmd()が
 * 保留したpending_dataからH2CData PDUとして送出する(単発ブロッキング
 * tcp_send()のまま、ICReq送信等と同じ扱い)。元はnvme_tcp_recv_resp()
 * 専用のstaticヘルパだったが、nvme.cのジョブ化(nvme_exec_step())が
 * R2T受信直後の状態から直接呼べるよう公開した(ロジック自体は無変更、
 * nvme_tcp_recv_resp()自身も引き続きこれを呼ぶ)。
 * 戻り値: 0=成功、-1=失敗(保留データ範囲外・送信失敗) */
int nvme_tcp_send_h2c_data(nvme_tcp_conn_t *c, uint16_t ttag, uint32_t r2to, uint32_t r2tl);

/* nvme_tcp_send_h2c_data()の下位実装 -- cid/data/data_lenを明示引数で
 * 受け取る版(conn->pending_*を暗黙参照しない)。2026-08-09、NVMe/TCP
 * コマンドパイプライン化(nvme.cのnvme_write_pipelined_run()参照)向け:
 * 単一のIO queue接続上で複数コマンドが同時に「保留中の書き込みデータ」を
 * 持つ必要があるため、conn単位の単一pending_data/pending_len/pending_cid
 * では足りない -- 呼び出し元(パイプラインの各スロット)が自分のcid/
 * data/lenを保持し、R2T受信時にそれをそのまま渡す。
 * 戻り値: 0=成功、-1=失敗(範囲外・送信失敗) */
int nvme_tcp_send_h2c_data_ex(nvme_tcp_conn_t *c, uint16_t cid, uint16_t ttag,
                               uint32_t r2to, uint32_t r2tl,
                               const void *data, uint32_t data_len);

#endif /* NVME_TCP_H */
