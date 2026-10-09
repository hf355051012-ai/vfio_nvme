#ifndef NVMET_TCP_H
#define NVMET_TCP_H

#include <stdint.h>
#include "tcp.h"
#include "nvme_types.h"
#include "nvme_tcp_pdu.h"  /* NVME_TCP_HDR_LEN(下記API群のヘッダバッファサイズに使う) */

/* **コマンドをまたいで応答 PDU を 1 セグメントへ束ねる**ときの上限。
 * 短経路スロットの実容量(TCP_ASYNC_SHORT_SLOT_BYTES)と同じにする --
 * まとめたものを長経路(LSO)へ流すと壊れる(CLAUDE.md)。 */
#define NVMET_TCP_TX_BATCH_MAX 9216u

struct nvmet_tls_conn;   /* nvmet_tls.h */

typedef struct {
    tcp_conn_t tcp;
    /* TLS 1.3(段階 E)。NULL なら平文。NULL でなければ送受信が全部
     * nvmet_tls.c のレコード層を通る(握手が済んでから入れる)。 */
    struct nvmet_tls_conn *tls;
    uint16_t   maxdata;
    uint16_t   last_cid;
    uint8_t    hdgst;
    uint8_t    ddgst;
    /* **送信の溜め込み(コネクションごと)。** kernel/SPDK は応答 PDU を
     * 3〜4 個ずつ 1 セグメントに載せてくるのに、こちらは 1 PDU = 1 セグメント
     * だった(実測: 相手の受信パケット/コマンドが自製 1.18〜2.00 に対し
     * kernel 0.27〜0.37 / SPDK 0.23〜0.32)。 */
    uint8_t    tx_batching;
    uint32_t   tx_batch_len;
    uint8_t    tx_batch[NVMET_TCP_TX_BATCH_MAX];
} nvmet_tcp_conn_t;

/* バッチ区間。囲んだ中でだけ溜め込み、`_end` で必ず吐き出す
 * (囲まない経路 -- admin など -- は従来どおり即送信)。 */
void nvmet_tcp_tx_batch_begin(nvmet_tcp_conn_t *c);
int  nvmet_tcp_tx_batch_end(nvmet_tcp_conn_t *c);
int  nvmet_tcp_tx_flush(nvmet_tcp_conn_t *c);

/* コマンドをまたいで応答 PDU を 1 セグメントへ束ねるか(`tcpbatch`)。
 * **0 が束ねる前の挙動 = 陰性対照。** */
extern volatile uint32_t g_nvmet_tcp_batch;

void nvmet_tcp_accept_arm(nvmet_tcp_conn_t *c, int listener);

int nvmet_tcp_send_r2t(nvmet_tcp_conn_t *c, uint16_t cid,
                        uint32_t r2to, uint32_t r2tl);

uint32_t nvmet_tcp_max_h2c_data(const nvmet_tcp_conn_t *c);

int nvmet_tcp_send_resp(nvmet_tcp_conn_t *c, const nvme_cqe_t *cqe);

int nvmet_tcp_send_c2h(nvmet_tcp_conn_t *c, uint16_t cid, const nvme_cqe_t *cqe,
                       const void *data, uint32_t dlen,
                       int data_success);

int nvmet_tcp_send_c2h_async(nvmet_tcp_conn_t *c, uint16_t cid,
                              const void *data, uint32_t dlen);

/* コネクションを閉じる(tcp_close()をそのまま呼ぶ)。 */
void nvmet_tcp_close(nvmet_tcp_conn_t *c);

typedef struct {
    uint8_t  *buf;
    uint32_t  want;
    uint32_t  got;
} nvmet_tcp_xfer_t;

/* 新しい受信を開始する(got=0にリセットするだけ)。 */
void nvmet_tcp_xfer_reset(nvmet_tcp_xfer_t *x, void *buf, uint32_t want);

int nvmet_tcp_recv_poll(nvmet_tcp_conn_t *c, nvmet_tcp_xfer_t *x);

uint32_t nvmet_tcp_parse_cmd_dlen(const nvmet_tcp_conn_t *c, const uint8_t hdr_buf[NVME_TCP_HDR_LEN]);

int nvmet_tcp_verify_hdgst(const nvmet_tcp_conn_t *c,
                            const void *hdr1, uint32_t len1,
                            const void *hdr2, uint32_t len2,
                            const uint8_t got[4]);
int nvmet_tcp_check_ddgst_crc(const nvmet_tcp_conn_t *c, uint32_t running_crc,
                               const uint8_t got[4]);

int nvmet_tcp_verify_ddgst(const nvmet_tcp_conn_t *c,
                            const void *data, uint32_t len,
                            const uint8_t got[4]);

int nvmet_tcp_send_icresp(nvmet_tcp_conn_t *c, const uint8_t icreq_buf[NVME_TCP_ICREQ_LEN]);

/* 検証用: 次に送る N 個のヘッダダイジェストをわざと壊す。 */
/* C2HData の PDU ヘッダと本体を 1 つの TCP セグメントにまとめるか
 * (シェルの `tcpcoalesce` がイニシエータ側と一緒に切り替える)。
 * **0 が「まとめる前」の挙動 = 陰性対照。** まとめないと read 応答 1 個が
 * 2 パケットになり、相手のパケット処理能力を 2 倍消費する。 */
extern volatile uint32_t g_nvmet_tcp_coalesce;

extern volatile uint32_t g_nvmet_tcp_hdgst_corrupt;
extern volatile uint32_t g_nvmet_tcp_hdgst_verify_fail;
extern volatile uint32_t g_nvmet_tcp_term_sent;
extern volatile uint32_t g_nvmet_tcp_term_recv;

/* 致命的なプロトコル誤りを見つけたとき、TCP を閉じる前に理由(FES)を送る。 */
int nvmet_tcp_send_term(nvmet_tcp_conn_t *c, uint16_t fes, uint32_t fei,
                         const uint8_t *pdu, uint32_t pdu_len);

#endif /* NVMET_TCP_H */
