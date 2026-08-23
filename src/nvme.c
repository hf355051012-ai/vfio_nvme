#include <stddef.h>
#include "nvme.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "job.h"
#include "timestamp.h"
#include "smp.h"
#include "netif.h"
#include "crc32c.h"

#define NVME_QSIZE               32u    /* admin/IO両queueのsqsize(Fabrics Connectで通知) */
#define NVME_ADMIN_CMD_TIMEOUT_MS 5000u
#define NVME_IO_CMD_TIMEOUT_MS   10000u

#define NVME_CONNECT_ICRESP_TIMEOUT_MS 3000u

#define NVME_CTRL_READY_POLL_MAX     20u
#define NVME_CTRL_READY_POLL_MS     100u

static const uint8_t NVME_HOST_ID[16] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
};
#define NVME_HOST_NQN "nqn.2014-08.org.nvmexpress:uuid:a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf"

#define NVME_CNTLID_DYNAMIC 0xFFFFu  /* Fabrics Connect(admin queue): controller ID割り当てをtargetに任せる */

typedef struct __attribute__((packed)) {
    uint8_t  hostid[16];
    uint16_t cntlid;
    uint8_t  reserved1[238];
    char     subsysnqn[256];
    char     hostnqn[256];
    uint8_t  reserved2[256];
} nvmf_connect_data_t;

static void nvme_zero(void *p, size_t len)
{
    volatile uint8_t *b = p;
    for (size_t i = 0; i < len; i++) b[i] = 0;
}

static void nvme_copy_str(char *dst, size_t capacity, const char *src)
{
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < capacity) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/*=================================================================
 * 読み出しコマンドやデータを伴わないコマンド用の SGL descriptor を SQE へ
 * 書く(NVME_SGL_TYPE_TRANSPORT)。データはトランスポート(C2HData)が運ぶ。
 *
 * 引数:
 *   sqe - 対象 SQE
 *   len - 転送長
 * コール元:
 *   nvme_build_identify_sqe(), nvme_build_property_set/get_sqe(),
 *   nvme_build_read_sqe()
 * ===============================================================*/
static void nvme_set_sgl(nvme_sqe_t *sqe, uint32_t len)
{
    wr64le(&sqe->dptr[0], 0);
    wr32le(&sqe->dptr[8], len);
    sqe->dptr[12] = 0;
    sqe->dptr[13] = 0;
    sqe->dptr[14] = 0;
    sqe->dptr[15] = (uint8_t)NVME_SGL_TYPE_TRANSPORT;
}

/*=================================================================
 * 書き込みコマンド(Fabrics Connect 含む)用の in-capsule SGL descriptor を
 * SQE へ書く。データは Command Capsule PDU の直後に連結して送る。
 *
 * 引数:
 *   sqe - 対象 SQE
 *   len - in-capsule データ長
 * コール元:
 *   nvme_build_fabrics_connect_sqe(), nvme_build_write_sqe()
 * ===============================================================*/
static void nvme_set_sgl_inline(nvme_sqe_t *sqe, uint32_t len)
{
    wr64le(&sqe->dptr[0], 0);
    wr32le(&sqe->dptr[8], len);
    sqe->dptr[12] = 0;
    sqe->dptr[13] = 0;
    sqe->dptr[14] = 0;
    sqe->dptr[15] = (uint8_t)NVME_SGL_TYPE_DATA_BLOCK_OFFSET;
}

typedef enum {
    NVEXEC_ST_SEND = 0,
    NVEXEC_ST_RECV_HDR,
    NVEXEC_ST_RECV_CQE,
    NVEXEC_ST_RECV_C2H_REST,
    NVEXEC_ST_RECV_C2H_DATA,
    NVEXEC_ST_RECV_C2H_DDGST,
    NVEXEC_ST_RECV_R2T_REST,
    NVEXEC_ST_SEND_H2C,
    NVEXEC_ST_DONE,
} nvme_exec_state_t;

#define NVEXEC_STATE_NAME_COUNT (sizeof(NVEXEC_STATE_NAMES) / sizeof(NVEXEC_STATE_NAMES[0]))

/*=================================================================
 * 1 コマンドの送受信サブステートマシンを初期化する。SQE 送信 -> 応答待ち
 * (RSP 直行 / C2HData / R2T->H2CData)を nvme_exec_step() が進める。
 *
 * 引数:
 *   ec           - 初期化する exec コンテキスト
 *   conn         - 使用する NVMe/TCP コネクション
 *   sqe          - 送る SQE
 *   send_buf / send_len - in-capsule または H2CData で送るデータ
 *   recv_buf / recv_buflen - C2HData を受け取るバッファ
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
void nvme_exec_begin(nvme_exec_ctx_t *ec, nvme_tcp_conn_t *conn, const nvme_sqe_t *sqe,
                      const void *send_data, uint32_t send_len,
                      void *recv_buf, uint32_t recv_buflen)
{
    ec->state       = NVEXEC_ST_SEND;
    ec->conn        = conn;
    ec->sqe         = sqe;
    ec->send_data   = send_data;
    ec->send_len    = send_len;
    ec->recv_buf    = recv_buf;
    ec->recv_buflen = recv_buflen;
}

/*=================================================================
 * 受信済みの共通ヘッダ + 型固有部に対し、直後に続くヘッダダイジェストを
 * 検証する(無効なら何もせず 0)。rest_buf は 型固有部 16 バイトの直後に
 * ダイジェスト 4 バイトが並ぶ形で 1 回にまとめて受信してある。
 *
 * 引数:
 *   ec - exec コンテキスト
 * 戻り値:
 *   0=一致、-1=不一致
 * コール元:
 *   nvme_exec_step()
 * ===============================================================*/
static int nvme_exec_check_hdgst(const nvme_exec_ctx_t *ec)
{
    return nvme_tcp_verify_hdgst(ec->conn, ec->hdr_buf, NVME_TCP_HDR_LEN,
                                  ec->rest_buf, NVME_CQE_LEN, &ec->rest_buf[NVME_CQE_LEN]);
}

/*=================================================================
 * C2HData を 1 個受け切った後の共通処理。DATA_SUCCESS フラグが立っていれば
 * その場で完了(別途 Response Capsule は来ない)、そうでなければ次の PDU
 * ヘッダ待ちへ戻る。データダイジェストの有無で入口が 2 つあるため関数化した。
 *
 * 引数:
 *   ec - exec コンテキスト
 * 戻り値:
 *   1=コマンド完了、0=継続
 * コール元:
 *   nvme_exec_step()
 * ===============================================================*/
static int nvme_exec_c2h_complete(nvme_exec_ctx_t *ec)
{
    if (ec->hdr_buf[1] & NVME_TCP_F_DATA_SUCCESS) {
        nvme_zero(&ec->cqe_out, sizeof(ec->cqe_out));
        wr16le(&ec->cqe_out.cid, ec->conn->pending_cid);
        ec->result = 0;
        ec->state = NVEXEC_ST_DONE;
        return 1;
    }
    nvme_tcp_xfer_reset(&ec->xfer, ec->hdr_buf, NVME_TCP_HDR_LEN);
    ec->state = NVEXEC_ST_RECV_HDR;
    return 0;
}

/*=================================================================
 * nvme_exec_begin() で始めた 1 コマンドを 1 tick 分進める。
 *
 * 引数:
 *   ec - exec コンテキスト
 * 戻り値:
 *   1=完了(ec->cqe_out に CQE)、0=継続中、-1=エラー/タイムアウト
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
int nvme_exec_step(nvme_exec_ctx_t *ec)
{
    switch ((nvme_exec_state_t)ec->state) {

    case NVEXEC_ST_SEND:
        if (nvme_tcp_send_cmd(ec->conn, ec->sqe, ec->send_data, ec->send_len) != 0) {
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        {
            const uint8_t *sqe_bytes = (const uint8_t *)ec->sqe;
            uint8_t  sgl_type = sqe_bytes[39];
            int use_r2t = (ec->send_data != NULL && ec->send_len > 0 &&
                           sgl_type == (uint8_t)NVME_SGL_TYPE_TRANSPORT);
            int has_inline_data = (!use_r2t && ec->send_data != NULL && ec->send_len > 0);

            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_CMD;
            info.hlen        = (uint8_t)NVME_TCP_CMD_PDU_LEN;
            info.pdo         = has_inline_data ? (uint8_t)NVME_TCP_CMD_PDU_LEN : 0;
            info.plen        = NVME_TCP_CMD_PDU_LEN + (has_inline_data ? ec->send_len : 0u);
            info.cid         = ec->conn->pending_cid;
            info.opcode      = sqe_bytes[0];
            info.sgl_type    = sgl_type;
            info.data_length = rd32le(&sqe_bytes[32]);  /* LEN(SGL宣言転送量) */
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 0), &info);
        }
        nvme_tcp_xfer_reset(&ec->xfer, ec->hdr_buf, NVME_TCP_HDR_LEN);
        ec->state = NVEXEC_ST_RECV_HDR;
        return 0;

    case NVEXEC_ST_RECV_HDR: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

        uint8_t type = ec->hdr_buf[0];
        /* 型固有部(16)とヘッダダイジェスト(有効なら4)を1回でまとめて受ける。 */
        uint32_t rest_len = NVME_CQE_LEN + nvme_tcp_hdgst_len(ec->conn);
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, rest_len);
            ec->state = NVEXEC_ST_RECV_CQE;
        } else if (type == NVME_TCP_PDU_C2H_DATA) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, rest_len);
            ec->state = NVEXEC_ST_RECV_C2H_REST;
        } else if (type == NVME_TCP_PDU_R2T) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, rest_len);
            ec->state = NVEXEC_ST_RECV_R2T_REST;
        } else if (type == NVME_TCP_PDU_C2H_TERM) {
            /* **相手が致命的な誤りを見つけて理由を伝えてきた。**
             * 種別を記録して中断する(相手はこの後 TCP を閉じる)。 */
            g_nvme_tcp_term_recv++;
            uart_printf("[!] NVMe/TCP: C2H TermReq 受信 -- "
                        "相手がプロトコル誤りを検出しました\n");
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        } else {
            uart_printf("[!] NVMe/TCP: 未対応のPDU種別 (type=%u) 受信、応答待ちを中断\n", type);
            /* **理由を伝えてから中断する。** 伝えないと相手のログには
             * 「接続が切れた」としか残らない。 */
            nvme_tcp_send_term(ec->conn, NVME_TCP_FES_INVALID_PDU_HDR, 0,
                                ec->hdr_buf, NVME_TCP_HDR_LEN);
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        return 0;
    }

    case NVEXEC_ST_RECV_CQE: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;
        if (nvme_exec_check_hdgst(ec) != 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }

        uint16_t cid    = rd16le(&ec->rest_buf[12]);
        uint16_t status = rd16le(&ec->rest_buf[14]);
        wr32le(&ec->cqe_out.dw0, rd32le(&ec->rest_buf[0]));
        wr32le(&ec->cqe_out.dw1, rd32le(&ec->rest_buf[4]));
        wr16le(&ec->cqe_out.sq_head, rd16le(&ec->rest_buf[8]));
        wr16le(&ec->cqe_out.sq_id, rd16le(&ec->rest_buf[10]));
        wr16le(&ec->cqe_out.cid, cid);
        wr16le(&ec->cqe_out.status, status);
        if (cid != ec->conn->pending_cid) {
            uart_printf("[!] NVMe/TCP: CQEのCIDが不一致 (期待=%u 受信=%u)\n",
                        ec->conn->pending_cid, cid);
        }
        /* NRCV: Response Capsule(CQE)受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_RSP;
            info.hlen     = ec->hdr_buf[2];
            info.pdo      = ec->hdr_buf[3];
            info.plen     = rd32le(&ec->hdr_buf[4]);
            info.cid      = cid;
            info.status   = status;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 1), &info);
        }
        ec->result = (int)nvme_cqe_status_code(status);
        ec->state = NVEXEC_ST_DONE;
        return 1;
    }

    case NVEXEC_ST_RECV_C2H_REST: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;
        if (nvme_exec_check_hdgst(ec) != 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }

        uint8_t  hlen = ec->hdr_buf[2];
        uint32_t plen = rd32le(&ec->hdr_buf[4]);
        ec->datao = rd32le(&ec->rest_buf[4]);
        ec->datal = rd32le(&ec->rest_buf[8]);

        /* plen はヘッダ・両ダイジェストを含む総長。データ本体だけを取り出す。 */
        uint32_t data_in_pdu = plen - hlen - nvme_tcp_hdgst_len(ec->conn)
                                    - nvme_tcp_ddgst_len(ec->conn, ec->datal);
        if (data_in_pdu != ec->datal) {
            uart_printf("[!] NVMe/TCP: C2HDataのplen/datal不一致 (plen=%u datal=%u)\n",
                        plen, ec->datal);
        }
        if ((uint64_t)ec->datao + (uint64_t)ec->datal > (uint64_t)ec->recv_buflen) {
            uart_printf("[!] NVMe/TCP: C2HDataが呼び出し側バッファを超過 "
                        "(datao=%u datal=%u buflen=%u)\n", ec->datao, ec->datal, ec->recv_buflen);
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        nvme_tcp_xfer_reset(&ec->xfer, (uint8_t *)ec->recv_buf + ec->datao, ec->datal);
        ec->state = NVEXEC_ST_RECV_C2H_DATA;
        return 0;
    }

    case NVEXEC_ST_RECV_C2H_DATA: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

        /* NRCV: C2HData受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_C2H_DATA;
            info.hlen        = ec->hdr_buf[2];
            info.pdo         = ec->hdr_buf[3];
            info.plen        = rd32le(&ec->hdr_buf[4]);
            info.cccid       = ec->conn->pending_cid;
            info.data_offset = ec->datao;
            info.data_length = ec->datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 2), &info);
        }
        if (nvme_tcp_ddgst_len(ec->conn, ec->datal) != 0u) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->dgst_buf, NVME_TCP_DGST_LEN);
            ec->state = NVEXEC_ST_RECV_C2H_DDGST;
            return 0;
        }
        return nvme_exec_c2h_complete(ec);
    }

    case NVEXEC_ST_RECV_C2H_DDGST: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;
        if (nvme_tcp_verify_ddgst(ec->conn, (const uint8_t *)ec->recv_buf + ec->datao,
                                   ec->datal, ec->dgst_buf) != 0) {
            ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1;
        }
        return nvme_exec_c2h_complete(ec);
    }

    case NVEXEC_ST_RECV_R2T_REST: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;
        if (nvme_exec_check_hdgst(ec) != 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }

        ec->ttag  = rd16le(&ec->rest_buf[2]);
        ec->datao = rd32le(&ec->rest_buf[4]);  /* r2to(SEND_H2Cへそのまま渡す) */
        ec->datal = rd32le(&ec->rest_buf[8]);  /* r2tl */
        /* NRCV: R2T受信完了。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_R2T;
            info.hlen        = ec->hdr_buf[2];
            info.pdo         = ec->hdr_buf[3];
            info.plen        = rd32le(&ec->hdr_buf[4]);
            info.cccid       = ec->conn->pending_cid;
            info.ttag        = ec->ttag;
            info.data_offset = ec->datao;
            info.data_length = ec->datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 3), &info);
        }
        ec->state = NVEXEC_ST_SEND_H2C;
        return 0;
    }

    case NVEXEC_ST_SEND_H2C:
        if (nvme_tcp_send_h2c_data(ec->conn, ec->ttag, ec->datao, ec->datal) != 0) {
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        /* NSND: H2CData送信(R2T応答)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_H2C_DATA;
            info.hlen        = (uint8_t)NVME_TCP_DATA_PDU_LEN;
            info.pdo         = (uint8_t)NVME_TCP_DATA_PDU_LEN;
            info.plen        = NVME_TCP_DATA_PDU_LEN + ec->datal;
            info.cccid       = ec->conn->pending_cid;
            info.ttag        = ec->ttag;
            info.data_offset = ec->datao;
            info.data_length = ec->datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_exec_step, 4), &info);
        }
        nvme_tcp_xfer_reset(&ec->xfer, ec->hdr_buf, NVME_TCP_HDR_LEN);
        ec->state = NVEXEC_ST_RECV_HDR;
        return 0;

    default:
        return 1;
    }
}

/*=================================================================
 * Fabrics Property Set(fctype=0x00)の SQE を組み立てる。CC レジスタへの
 * 4 バイト書き込みに使う。
 *
 * 引数:
 *   sqe    - 対象 SQE
 *   offset - プロパティオフセット
 *   value  - 書き込む値
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
static void nvme_build_property_set_sqe(nvme_sqe_t *sqe, uint32_t offset, uint64_t value)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, NVME_FABRIC_FCTYPE_PROPERTY_SET);
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0u);  /* attrib=0: 4バイトプロパティ */
    wr32le(&sqe->cdw11, offset);
    wr32le(&sqe->cdw12, (uint32_t)(value & 0xFFFFFFFFu));
    wr32le(&sqe->cdw13, (uint32_t)(value >> 32));
}

/*=================================================================
 * Fabrics Property Get(fctype=0x04)の SQE を組み立てる。読んだ値は CQE の
 * dw0 に載って返る。
 *
 * 引数:
 *   sqe    - 対象 SQE
 *   offset - プロパティオフセット(CC=0x14 / CSTS=0x1c)
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
static void nvme_build_property_get_sqe(nvme_sqe_t *sqe, uint32_t offset)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, NVME_FABRIC_FCTYPE_PROPERTY_GET);
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0u);  /* attrib=0: 4バイトプロパティ */
    wr32le(&sqe->cdw11, offset);
}

/*=================================================================
 * Fabrics Connect のデータペイロード(1024 バイト固定)を組み立てる
 * (admin/IO 共通)。
 *
 * 引数:
 *   data   - 書き込み先
 *   cntlid - 要求する controller id(動的割り当てなら NVME_CNTLID_DYNAMIC)
 *   subnqn - 接続先サブシステム NQN
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
static void nvme_build_connect_data(nvmf_connect_data_t *data, uint16_t cntlid, const char *subnqn)
{
    nvme_zero(data, sizeof(*data));
    for (int i = 0; i < 16; i++) data->hostid[i] = NVME_HOST_ID[i];
    wr16le(&data->cntlid, cntlid);
    nvme_copy_str(data->subsysnqn, sizeof(data->subsysnqn), subnqn);
    nvme_copy_str(data->hostnqn, sizeof(data->hostnqn), NVME_HOST_NQN);
}

/*=================================================================
 * Fabrics Connect(fctype=0x01)の SQE を組み立てる。qid だけが admin(0)と
 * IO(1)の違い。データは in-capsule で送る。
 *
 * 引数:
 *   sqe              - 対象 SQE
 *   qid              - キュー ID
 *   connect_data_len - 続けて送る connect data の長さ
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
static void nvme_build_fabrics_connect_sqe(nvme_sqe_t *sqe, uint16_t qid, uint32_t connect_data_len)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, NVME_FABRIC_FCTYPE_CONNECT);  /* fctypeはnsidフィールドの下位バイトにオーバーレイされる */
    nvme_set_sgl_inline(sqe, connect_data_len);
    wr32le(&sqe->cdw10, (uint32_t)qid << 16);                 /* recfmt=0(下位16bit), qid(上位16bit) */
    wr32le(&sqe->cdw11, (uint32_t)(NVME_QSIZE - 1) & 0xFFFFu); /* sqsize(0's based) */
    wr32le(&sqe->cdw12, 0u);
}

/*=================================================================
 * Identify コマンドの SQE を組み立てる。
 *
 * 引数:
 *   sqe  - 対象 SQE
 *   cns  - CNS 値(1=Controller、0=Namespace)
 *   nsid - 名前空間 ID
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
void nvme_build_identify_sqe(nvme_sqe_t *sqe, uint8_t cns, uint32_t nsid)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_ADM_CMD_IDENTIFY | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    nvme_set_sgl(sqe, 4096u);
    wr32le(&sqe->cdw10, (uint32_t)cns);  /* CNS: bits[7:0]、残りは予約 */
}

/*=================================================================
 * Get Log Page コマンドの SQE を組み立てる。
 *
 * NUMD(返してほしい dword 数)は 0's based で cdw10 の上位 16bit(NUMDL)と
 * cdw11 の下位 16bit(NUMDU)に分かれる。LPO(Log Page Offset)はバイト単位で
 * cdw12(下位 32bit)/ cdw13(上位 32bit)。
 *
 * 引数:
 *   sqe   - 対象 SQE
 *   lid   - Log Page Identifier(Discovery なら NVME_LOG_LID_DISCOVERY)
 *   lpo   - 読み出し開始バイトオフセット
 *   bytes - 読みたいバイト数(4 の倍数へ切り上げて要求する)
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
void nvme_build_get_log_page_sqe(nvme_sqe_t *sqe, uint8_t lid, uint32_t lpo, uint32_t bytes)
{
    uint32_t dwords = (bytes + 3u) / 4u;
    uint32_t numd   = (dwords > 0u) ? (dwords - 1u) : 0u;  /* 0's based */

    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_ADM_CMD_GET_LOG_PAGE | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, 0xFFFFFFFFu);   /* 全体に対するログ */
    nvme_set_sgl(sqe, dwords * 4u);
    wr32le(&sqe->cdw10, (uint32_t)lid | ((numd & 0xFFFFu) << 16));
    wr32le(&sqe->cdw11, (numd >> 16) & 0xFFFFu);
    wr32le(&sqe->cdw12, lpo);
    wr32le(&sqe->cdw13, 0u);
}

/*=================================================================
 * Identify Namespace 応答から LBA サイズ(flbas が指す LBAF の lbads)と
 * 総ブロック数(NSZE)を取り出してコンテキストへ記録する。
 *
 * 引数:
 *   ctx      - 更新する initiator コンテキスト
 *   nsid     - 対象名前空間 ID(ログ用)
 *   buf4096  - Identify Namespace の応答データ
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
void nvme_update_lba_size_from_id_ns(nvme_ctx_t *ctx, uint32_t nsid, const void *buf4096)
{
    const uint8_t *b = buf4096;
    uint8_t flbas = (uint8_t)(b[NVME_ID_NS_OFF_FLBAS] & 0x0Fu);  /* bits[3:0] = LBA Format Index */
    uint32_t lbaf_off = NVME_ID_NS_OFF_LBAF0 + (uint32_t)flbas * 4u;
    uint8_t ds = b[lbaf_off + 2];  /* nvme_lbaf_t: ms(2B)+ds(1B)+rp(1B) -- dsは3バイト目 */
    ctx->lba_size = (uint32_t)1u << ds;
    /* NSZE: Identify Namespaceデータ構造の先頭8バイト(オフセット0、リトルエンディアン)。 */
    ctx->nsze = (uint64_t)rd32le(b + 0) | ((uint64_t)rd32le(b + 4) << 32);
    uart_printf("[nvme] identify namespace %u: flbas=%u lba_size=%u バイト nsze=%u ブロック\n",
                nsid, flbas, ctx->lba_size, (unsigned)ctx->nsze);
}

/*=================================================================
 * Set Features(Number of Queues)の SQE を組み立てる。
 *
 * 引数:
 *   sqe - 対象 SQE
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
static void nvme_build_set_features_num_queues_sqe(nvme_sqe_t *sqe)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_ADM_CMD_SET_FEATURES | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0x07u);        /* FID=7: Number of Queues */
    wr32le(&sqe->cdw11, 0x00010001u);  /* NSQR=1, NCQR=1 (IO SQ/CQ各1本を要求) */
}

typedef enum {
    NCONN_ST_TCP_ADMIN_BEGIN = 0,
    NCONN_ST_TCP_ADMIN_WAIT,
    NCONN_ST_ICRESP_ADMIN_RECV,
    NCONN_ST_EXEC_FABRIC_CONNECT_ADMIN,
    NCONN_ST_EXEC_PROPSET_CC,
    NCONN_ST_CSTS_POLL_WAIT,
    NCONN_ST_CSTS_POLL_EXEC,
    NCONN_ST_EXEC_IDENTIFY_CTRL,
    NCONN_ST_EXEC_DISC_HDR,   /* Discovery: ヘッダ 1024B だけ読んで NUMREC を見る */
    NCONN_ST_EXEC_DISC_FULL,  /* Discovery: NUMREC ぶんを含めて全体を読み直す */
    NCONN_ST_EXEC_IDENTIFY_NS,
    NCONN_ST_EXEC_SET_FEATURES,
    NCONN_ST_TCP_IO_WAIT,
    NCONN_ST_ICRESP_IO_RECV,
    NCONN_ST_EXEC_FABRIC_CONNECT_IO,
} nvme_connect_state_t;

#define NCONN_STATE_NAME_COUNT (sizeof(NCONN_STATE_NAMES) / sizeof(NCONN_STATE_NAMES[0]))

typedef struct {
    nvme_ctx_t         *ctx;
    netaddr_t             addr;   /* 接続先。IPv4/IPv6 のどちらでもよい */
    uint16_t              port;
    netif_t            *src_ctx;  /* spawn時点のg_active_ctx、下記コメント参照 */
    uint64_t              wait_started_ticks;
    nvme_tcp_xfer_t       xfer;
    uint8_t               icresp_buf[NVME_TCP_ICRESP_LEN];
    nvmf_connect_data_t   connect_data;
    nvme_sqe_t            sqe;
    nvme_exec_ctx_t       exec;
    uint32_t              csts_poll_count;
    uint8_t               id_buf[4096] __attribute__((aligned(64)));

} nvme_connect_job_ctx_t;

static nvme_connect_job_ctx_t s_nvme_connect_job_ctx;

static job_result_t nvme_connect_job_fail(nvme_connect_job_ctx_t *jc, int close_admin, int close_io,
                                           const char *reason)
{
    uart_printf("[!] nvme: 接続失敗 (%s)\n", reason);
    if (close_io) {
        nvme_tcp_close(&jc->ctx->io);
    }
    if (close_admin) {
        nvme_tcp_close(&jc->ctx->admin);
    }
    jc->ctx->io_connected = 0;
    jc->ctx->busy = 0;
    return JOB_DONE;
}

/*=================================================================
 * Discovery コントローラとの接続を正常終了させる。
 *
 * Discovery コントローラは **IO キューを作らない**(admin のみ)。ログを
 * 読み終えたらそこで完了で、通常接続のように Set Features(Number of Queues)
 * や 2 本目の TCP 接続へは進まない。admin 接続は呼び出し側がログを読んだ後に
 * 閉じられるよう、ここでは閉じずに残す。
 *
 * 引数:
 *   jc - 接続ジョブのコンテキスト
 * 戻り値:
 *   JOB_DONE
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
static job_result_t nvme_connect_job_finish_discovery(nvme_connect_job_ctx_t *jc)
{
    jc->ctx->io_connected = 0;
    jc->ctx->busy = 0;
    uart_printf("[nvme] Discovery 完了 (IOキューは作らない)\n");
    return JOB_DONE;
}

/*=================================================================
 * NVMe/TCP initiator の接続シーケンス 1 tick。admin TCP 接続 -> ICReq/ICResp
 * -> Fabrics Connect -> CC 有効化 -> CSTS.RDY 待ち -> Identify
 * Controller/Namespace -> Set Features -> IO キューについて同じ手順、と進む。
 *
 * 引数:
 *   self - このジョブ(self->state が接続シーケンスのステート)
 * 戻り値:
 *   JOB_WAITING=継続、JOB_DONE=接続完了/失敗で終了
 * コール元:
 *   job_scheduler_tick() から関数ポインタ経由
 * ===============================================================*/
static job_result_t nvme_connect_job_step(job_t *self)
{
    nvme_connect_job_ctx_t *jc  = (nvme_connect_job_ctx_t *)self->ctx;
    nvme_ctx_t              *ctx = jc->ctx;

    if (self->cancel_requested) {
        int admin_open = (self->state > NCONN_ST_TCP_ADMIN_WAIT);
        int io_open    = (self->state > NCONN_ST_TCP_IO_WAIT);
        return nvme_connect_job_fail(jc, admin_open, io_open, "job stopでキャンセル");
    }

    switch ((nvme_connect_state_t)self->state) {

    case NCONN_ST_TCP_ADMIN_BEGIN:
        if (jc->src_ctx) netif_activate(jc->src_ctx);
        tcp_connect_begin_to(&ctx->admin.tcp, &jc->addr, jc->port);
        self->state = NCONN_ST_TCP_ADMIN_WAIT;
        return JOB_WAITING;

    case NCONN_ST_TCP_ADMIN_WAIT: {
        int r = tcp_connect_poll(&ctx->admin.tcp);
        if (r < 0) return nvme_connect_job_fail(jc, 0, 0, "admin TCP接続失敗");
        if (r == 0) return JOB_WAITING;
        if (nvme_tcp_send_icreq(&ctx->admin) != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "admin ICReq送信失敗");
        }
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICREQ;
            info.hlen     = (uint8_t)NVME_TCP_ICREQ_LEN;
            info.pdo      = 0;
            info.plen     = NVME_TCP_ICREQ_LEN;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 0), &info);
        }
        nvme_tcp_xfer_reset(&jc->xfer, jc->icresp_buf, NVME_TCP_ICRESP_LEN);
        jc->wait_started_ticks = timer_now();
        self->state = NCONN_ST_ICRESP_ADMIN_RECV;
        return JOB_WAITING;
    }

    case NCONN_ST_ICRESP_ADMIN_RECV: {
        int r = nvme_tcp_recv_poll(&ctx->admin, &jc->xfer);
        if (r < 0) return nvme_connect_job_fail(jc, 1, 0, "admin ICResp受信失敗");
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVME_CONNECT_ICRESP_TIMEOUT_MS)) {
                return nvme_connect_job_fail(jc, 1, 0, "admin ICResp受信タイムアウト");
            }
            return JOB_WAITING;
        }
        if (nvme_tcp_verify_icresp(&ctx->admin, jc->icresp_buf) != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "admin ICResp不正");
        }
        /* NRCV: ICResp受信完了(admin queue)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICRESP;
            info.hlen     = jc->icresp_buf[2];
            info.pdo      = jc->icresp_buf[3];
            info.plen     = rd32le(&jc->icresp_buf[4]);
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 1), &info);
        }
        nvme_build_connect_data(&jc->connect_data, (uint16_t)NVME_CNTLID_DYNAMIC, ctx->subnqn);
        nvme_build_fabrics_connect_sqe(&jc->sqe, 0u, sizeof(jc->connect_data));
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe,
                         &jc->connect_data, sizeof(jc->connect_data), NULL, 0);
        self->state = NCONN_ST_EXEC_FABRIC_CONNECT_ADMIN;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_FABRIC_CONNECT_ADMIN: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "admin Fabrics Connect失敗");
        ctx->ctrlr_id = (uint16_t)(rd32le(&jc->exec.cqe_out.dw0) & 0xFFFFu);
        uart_printf("[nvme] admin queue接続完了 (controller id=%u)\n", ctx->ctrlr_id);

        uint32_t cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_AMS_RR | NVME_CC_SHN_NONE |
                      NVME_CC_IOSQES | NVME_CC_IOCQES;
        nvme_build_property_set_sqe(&jc->sqe, NVME_REG_CC, cc);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_EXEC_PROPSET_CC;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_PROPSET_CC: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "CC(Controller Configuration)有効化失敗");
        }
        jc->csts_poll_count = 0;
        nvme_build_property_get_sqe(&jc->sqe, NVME_REG_CSTS);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_CSTS_POLL_EXEC;
        return JOB_WAITING;
    }

    case NCONN_ST_CSTS_POLL_WAIT:
        if (!timeout_ms(jc->wait_started_ticks, NVME_CTRL_READY_POLL_MS)) return JOB_WAITING;
        nvme_build_property_get_sqe(&jc->sqe, NVME_REG_CSTS);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_CSTS_POLL_EXEC;
        return JOB_WAITING;

    case NCONN_ST_CSTS_POLL_EXEC: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "CSTS読み出し失敗");
        uint32_t csts = rd32le(&jc->exec.cqe_out.dw0);
        if (csts & NVME_CSTS_CFS) {
            return nvme_connect_job_fail(jc, 1, 0,
                "CSTS.CFS(Controller Fatal Status)、CC値の不整合の可能性");
        }
        if (csts & NVME_CSTS_RDY) {
            uart_printf("[nvme] コントローラ有効化完了 (CSTS.RDY=1)\n");
            nvme_build_identify_sqe(&jc->sqe, (uint8_t)NVME_IDENTIFY_CNS_CONTROLLER, 0);
            nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, jc->id_buf, sizeof(jc->id_buf));
            self->state = NCONN_ST_EXEC_IDENTIFY_CTRL;
            return JOB_WAITING;
        }
        jc->csts_poll_count++;
        if (jc->csts_poll_count >= NVME_CTRL_READY_POLL_MAX) {
            return nvme_connect_job_fail(jc, 1, 0, "CSTS.RDY待ちタイムアウト");
        }
        jc->wait_started_ticks = timer_now();
        self->state = NCONN_ST_CSTS_POLL_WAIT;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_IDENTIFY_CTRL: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "Identify Controller失敗");

        if (ctx->discovery_mode) {
            /* CNTRLTYPE(byte 111)が 2 = Discovery controller であることを確認する。
             * ここが 1(I/O controller)なら、相手が discovery NQN を見ずに通常の
             * 応答を返しているということなので、その場で分かる。 */
            uint8_t cntrltype = jc->id_buf[111];
            uart_printf("[nvme] Identify Controller完了 (CNTRLTYPE=%u%s)\n", cntrltype,
                        (cntrltype == 2u) ? " = Discovery controller" : " [!] 2 であるべき");

            /* ホストの実際の手順と同じく、まずヘッダだけ読んで NUMREC を見る。
             * ここで **LPO 付きの読み出しに対応していないターゲットは破綻する**。 */
            ctx->disc_log_len = 0;
            ctx->disc_numrec  = 0;
            nvme_build_get_log_page_sqe(&jc->sqe, (uint8_t)NVME_LOG_LID_DISCOVERY,
                                         0u, NVME_DISC_HDR_BYTES);
            nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0,
                             ctx->disc_log, NVME_DISC_HDR_BYTES);
            self->state = NCONN_ST_EXEC_DISC_HDR;
            return JOB_WAITING;
        }

        nvme_build_identify_sqe(&jc->sqe, (uint8_t)NVME_IDENTIFY_CNS_NAMESPACE, 1u);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, jc->id_buf, sizeof(jc->id_buf));
        self->state = NCONN_ST_EXEC_IDENTIFY_NS;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_DISC_HDR: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "Get Log Page(Discovery, ヘッダ)失敗");
        }
        ctx->disc_numrec = rd64le(&ctx->disc_log[NVME_DISC_OFF_NUMREC]);
        uint64_t genctr  = rd64le(&ctx->disc_log[NVME_DISC_OFF_GENCTR]);
        uint16_t recfmt  = rd16le(&ctx->disc_log[NVME_DISC_OFF_RECFMT]);
        uart_printf("[nvme] Discovery Log Page ヘッダ: genctr=%u numrec=%u recfmt=%u\n",
                    (unsigned)genctr, (unsigned)ctx->disc_numrec, recfmt);

        if (ctx->disc_numrec == 0) {
            /* エントリが無い = 公開されているサブシステムが無い。異常ではない。 */
            ctx->disc_log_len = NVME_DISC_HDR_BYTES;
            uart_printf("[nvme] Discovery: 公開サブシステムなし (numrec=0)\n");
            return nvme_connect_job_finish_discovery(jc);
        }

        uint32_t want = NVME_DISC_HDR_BYTES +
                        (uint32_t)ctx->disc_numrec * NVME_DISC_ENTRY_BYTES;
        if (want > NVME_DISC_LOG_MAX) {
            uart_printf("[!] nvme: Discovery エントリが多すぎる (numrec=%u)、先頭 %u 個だけ読む\n",
                        (unsigned)ctx->disc_numrec,
                        (NVME_DISC_LOG_MAX - NVME_DISC_HDR_BYTES) / NVME_DISC_ENTRY_BYTES);
            want = NVME_DISC_LOG_MAX;
        }
        /* 2 回目は全体を読み直す(ヘッダも含めて LPO=0)。 */
        nvme_build_get_log_page_sqe(&jc->sqe, (uint8_t)NVME_LOG_LID_DISCOVERY, 0u, want);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, ctx->disc_log, want);
        ctx->disc_log_len = want;
        self->state = NCONN_ST_EXEC_DISC_FULL;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_DISC_FULL: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) {
            ctx->disc_log_len = 0;
            return nvme_connect_job_fail(jc, 1, 0, "Get Log Page(Discovery, 全体)失敗");
        }
        uart_printf("[nvme] Discovery Log Page 全体を取得 (%u バイト, numrec=%u)\n",
                    ctx->disc_log_len, (unsigned)ctx->disc_numrec);
        return nvme_connect_job_finish_discovery(jc);
    }

    case NCONN_ST_EXEC_IDENTIFY_NS: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 0, "Identify Namespace(nsid=1)失敗");
        nvme_update_lba_size_from_id_ns(ctx, 1u, jc->id_buf);

        nvme_build_set_features_num_queues_sqe(&jc->sqe);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, NULL, 0);
        self->state = NCONN_ST_EXEC_SET_FEATURES;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_SET_FEATURES: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "Set Features(Number of Queues)失敗");
        }
        if (jc->src_ctx) netif_activate(jc->src_ctx);
        tcp_connect_begin_to(&ctx->io.tcp, &jc->addr, jc->port);
        self->state = NCONN_ST_TCP_IO_WAIT;
        return JOB_WAITING;
    }

    case NCONN_ST_TCP_IO_WAIT: {
        int r = tcp_connect_poll(&ctx->io.tcp);
        if (r < 0) return nvme_connect_job_fail(jc, 1, 0, "IO TCP接続失敗");
        if (r == 0) return JOB_WAITING;
        if (nvme_tcp_send_icreq(&ctx->io) != 0) {
            return nvme_connect_job_fail(jc, 1, 1, "IO ICReq送信失敗");
        }
        /* NSND: ICReq送信(IO queue)。admin queueの同種コメント参照。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICREQ;
            info.hlen     = (uint8_t)NVME_TCP_ICREQ_LEN;
            info.pdo      = 0;
            info.plen     = NVME_TCP_ICREQ_LEN;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 2), &info);
        }
        nvme_tcp_xfer_reset(&jc->xfer, jc->icresp_buf, NVME_TCP_ICRESP_LEN);
        jc->wait_started_ticks = timer_now();
        self->state = NCONN_ST_ICRESP_IO_RECV;
        return JOB_WAITING;
    }

    case NCONN_ST_ICRESP_IO_RECV: {
        int r = nvme_tcp_recv_poll(&ctx->io, &jc->xfer);
        if (r < 0) return nvme_connect_job_fail(jc, 1, 1, "IO ICResp受信失敗");
        if (r == 0) {
            if (timeout_ms(jc->wait_started_ticks, NVME_CONNECT_ICRESP_TIMEOUT_MS)) {
                return nvme_connect_job_fail(jc, 1, 1, "IO ICResp受信タイムアウト");
            }
            return JOB_WAITING;
        }
        if (nvme_tcp_verify_icresp(&ctx->io, jc->icresp_buf) != 0) {
            return nvme_connect_job_fail(jc, 1, 1, "IO ICResp不正");
        }
        /* NRCV: ICResp受信完了(IO queue)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_ICRESP;
            info.hlen     = jc->icresp_buf[2];
            info.pdo      = jc->icresp_buf[3];
            info.plen     = rd32le(&jc->icresp_buf[4]);
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_connect_job_step, 3), &info);
        }
        nvme_build_connect_data(&jc->connect_data, ctx->ctrlr_id, ctx->subnqn);
        nvme_build_fabrics_connect_sqe(&jc->sqe, 1u, sizeof(jc->connect_data));
        nvme_exec_begin(&jc->exec, &ctx->io, &jc->sqe,
                         &jc->connect_data, sizeof(jc->connect_data), NULL, 0);
        self->state = NCONN_ST_EXEC_FABRIC_CONNECT_IO;
        return JOB_WAITING;
    }

    case NCONN_ST_EXEC_FABRIC_CONNECT_IO: {
        if (!nvme_exec_step(&jc->exec)) return JOB_WAITING;
        if (jc->exec.result != 0) return nvme_connect_job_fail(jc, 1, 1, "IO Fabrics Connect失敗");
        ctx->io_connected = 1;
        uart_printf("[nvme] IO queue接続完了 (qid=1)\n");
        uart_printf("[nvme] 接続完了 (subnqn=%s, lba_size=%u)\n", ctx->subnqn, ctx->lba_size);
        ctx->busy = 0;
        return JOB_DONE;
    }

    default:
        return JOB_DONE;
    }
}

/*=================================================================
 * 接続シーケンスをジョブとして起動し、即座に呼び出し元へ返る(完了は
 * ctx->busy が 0 になったかで判定する)。同一コンテキストで既に実行中なら
 * 起動を拒否する。
 *
 * 引数:
 *   ctx    - initiator コンテキスト
 *   ip     - 接続先 IPv4(ホストバイトオーダー)
 *   port   - 接続先ポート
 *   subnqn - 接続先サブシステム NQN
 * 戻り値:
 *   0=起動した、-1=実行中/ジョブテーブル満杯
 * コール元:
 *   shell_ensure_tcp_session()
 * ===============================================================*/
int nvme_connect_job_start_addr(nvme_ctx_t *ctx, const netaddr_t *addr, uint16_t port,
                                const char *subnqn)
{
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    if (ctx->io_connected) {
        uart_printf("[!] nvme: 既に接続済みです(先に`nvme disconnect`してください)\n");
        return -1;
    }
    if (job_active_count() > (unsigned)(JOB_MAX - 1)) {
        uart_printf("[!] nvme: ジョブテーブルに空きが不足\n");
        return -1;
    }

    ctx->io_connected = 0;
    ctx->ctrlr_id     = NVME_CNTLID_DYNAMIC;
    ctx->lba_size     = 512u;  /* nvme_update_lba_size_from_id_ns()が上書きするまでの暫定値 */
    nvme_copy_str(ctx->subnqn, sizeof(ctx->subnqn), subnqn);
    /* ICReq で要求するダイジェストを admin/IO 両キューへ配る(実際に有効に
     * なるかは ICResp の合意結果次第)。 */
    ctx->admin.req_hdgst = ctx->io.req_hdgst = ctx->req_hdgst;
    ctx->admin.req_ddgst = ctx->io.req_ddgst = ctx->req_ddgst;
    ctx->busy = 1;

    s_nvme_connect_job_ctx.ctx     = ctx;
    s_nvme_connect_job_ctx.addr    = *addr;
    s_nvme_connect_job_ctx.port    = port;
    s_nvme_connect_job_ctx.src_ctx = g_active_ctx;

    job_t *connect_job = job_spawn(nvme_connect_job_step, &s_nvme_connect_job_ctx, "nvme-connect");
    if (!connect_job) {
        uart_printf("[!] nvme: ジョブ生成失敗\n");
        ctx->busy = 0;
        return -1;
    }
    job_set_affinity(connect_job, s_nvme_connect_job_ctx.src_ctx);
    return 0;
}

/*=================================================================
 * Read コマンドの SQE を組み立てる。
 *
 * 引数:
 *   sqe  - 対象 SQE
 *   nsid - 名前空間 ID
 *   slba - 開始 LBA
 *   nlb  - ブロック数(0's based へはここで変換する)
 *   total_len - 転送バイト数
 * コール元:
 *   nvme_read_pipelined_run()
 * ===============================================================*/
void nvme_build_read_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_IO_CMD_READ | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    nvme_set_sgl(sqe, total_len);
    wr32le(&sqe->cdw10, (uint32_t)(slba & 0xFFFFFFFFu));  /* SLBA下位32bit */
    wr32le(&sqe->cdw11, (uint32_t)(slba >> 32));           /* SLBA上位32bit */
    wr32le(&sqe->cdw12, (uint32_t)(nlb - 1) & 0xFFFFu);    /* NLB(0's based) */
}

/*=================================================================
 * Write コマンドの SQE を組み立てる(データは in-capsule で送るため
 * SGL は inline 型)。
 *
 * 引数:
 *   sqe / nsid / slba / nlb / total_len - nvme_build_read_sqe() と同じ
 * コール元:
 *   nvme_write_pipelined_run()
 * ===============================================================*/
void nvme_build_write_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_IO_CMD_WRITE | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    if (total_len > NVME_TCP_INLINE_DATA_MAX) {
        nvme_set_sgl(sqe, total_len);
    } else {
        nvme_set_sgl_inline(sqe, total_len);
    }
    wr32le(&sqe->cdw10, (uint32_t)(slba & 0xFFFFFFFFu));
    wr32le(&sqe->cdw11, (uint32_t)(slba >> 32));
    wr32le(&sqe->cdw12, (uint32_t)(nlb - 1) & 0xFFFFu);
}

static volatile int    s_io_job_done = 0;

typedef struct {
    int        in_use;   /* このスロットが現在1件のwriteを担当中か */
    int        sent;     /* SQEを送信済みか(R2T/RSP待ちの間だけ1) */
    int        done;     /* 完了(結果確定)したか -- in_useのままresultを取り出す猶予を与える */
    int        result;   /* 完了時のCQEステータス(0=success)、通信エラー等は-1 */
    uint16_t   cid;
    nvme_sqe_t sqe;
    const void *data;
    uint32_t   len;
} nvme_pipeline_slot_t;

static nvme_pipeline_slot_t s_pl_slots[NVME_IO_QDEPTH];

typedef enum {
    PL_RX_HDR = 0,
    PL_RX_RSP_REST,
    PL_RX_R2T_REST,
} nvme_pipeline_rx_state_t;

static nvme_pipeline_rx_state_t s_pl_rx_state;
static nvme_tcp_xfer_t          s_pl_xfer;
static uint8_t                  s_pl_hdr_buf[NVME_TCP_HDR_LEN];
/* 型固有部(16)+ヘッダダイジェスト(4)を1回でまとめて受ける。 */
static uint8_t                  s_pl_rest_buf[16 + 4];

/*=================================================================
 * write パイプラインの送信済み・未完了スロットから cid が一致するものを探す。
 *
 * 引数:
 *   cid - 探すコマンド id
 * 戻り値:
 *   スロット番号。見つからなければ -1
 * コール元:
 *   nvme_pipeline_rx_tick()
 * ===============================================================*/
static int nvme_pipeline_find_slot(uint16_t cid)
{
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        if (s_pl_slots[i].in_use && s_pl_slots[i].sent && !s_pl_slots[i].done &&
            s_pl_slots[i].cid == cid) {
            return (int)i;
        }
    }
    return -1;
}

/*=================================================================
 * write パイプラインの未完了スロットを全て失敗にする(受信エラーや
 * ダイジェスト不一致で、以後ストリームの同期を保証できなくなったとき)。
 *
 * コール元:
 *   nvme_pipeline_rx_tick()
 * ===============================================================*/
static void nvme_pipeline_fail_all_slots(void)
{
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        if (s_pl_slots[i].in_use && s_pl_slots[i].sent && !s_pl_slots[i].done) {
            s_pl_slots[i].done   = 1;
            s_pl_slots[i].result = -1;
        }
    }
}

/*=================================================================
 * write パイプラインで受信した PDU のヘッダダイジェストを検証する。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * 戻り値:
 *   0=一致(無効時も 0)、-1=不一致
 * コール元:
 *   nvme_pipeline_rx_tick()
 * ===============================================================*/
static int nvme_pipeline_check_hdgst(const nvme_ctx_t *ctx)
{
    return nvme_tcp_verify_hdgst(&ctx->io, s_pl_hdr_buf, NVME_TCP_HDR_LEN,
                                  s_pl_rest_buf, NVME_CQE_LEN, &s_pl_rest_buf[NVME_CQE_LEN]);
}

typedef struct {
    int      valid;
    int      slot;
    uint16_t cid;
    uint16_t ttag;
    uint32_t r2to;
    uint32_t r2tl;
} nvme_h2c_pending_t;

#define NVME_H2C_PENDING_MAX NVME_IO_QDEPTH
static nvme_h2c_pending_t s_h2c_pending[NVME_H2C_PENDING_MAX];
static unsigned s_h2c_pending_head;
static unsigned s_h2c_pending_count;

/*=================================================================
 * 受信した R2T を H2CData 送信待ちの FIFO へ積む(送信自体は
 * nvme_pipeline_h2c_pump() が行うので、受信ループはブロックしない)。
 *
 * 引数:
 *   slot        - 対応するスロット番号
 *   cid / ttag  - コマンド id と転送タグ
 *   r2to / r2tl - 要求された範囲
 * 戻り値:
 *   0=積めた、-1=キュー満杯
 * コール元:
 *   nvme_pipeline_rx_tick()
 * ===============================================================*/
static int nvme_h2c_pending_push(int slot, uint16_t cid, uint16_t ttag, uint32_t r2to, uint32_t r2tl)
{
    if (s_h2c_pending_count >= NVME_H2C_PENDING_MAX) {
        return -1;
    }
    unsigned idx = (s_h2c_pending_head + s_h2c_pending_count) % NVME_H2C_PENDING_MAX;
    s_h2c_pending[idx].valid = 1;
    s_h2c_pending[idx].slot  = slot;
    s_h2c_pending[idx].cid   = cid;
    s_h2c_pending[idx].ttag  = ttag;
    s_h2c_pending[idx].r2to  = r2to;
    s_h2c_pending[idx].r2tl  = r2tl;
    s_h2c_pending_count++;
    return 0;
}

/*=================================================================
 * write パイプラインの受信側 1 tick。到着済み PDU を非ブロッキングで 1 段
 * だけ処理し、CQE ならスロットを完了に、R2T なら送信 FIFO へ積む。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * コール元:
 *   nvme_write_pipelined_run()
 * ===============================================================*/
static void nvme_pipeline_rx_tick(nvme_ctx_t *ctx)
{
    int r = nvme_tcp_recv_poll(&ctx->io, &s_pl_xfer);
    if (r < 0) {
        nvme_pipeline_fail_all_slots();
        return;
    }
    if (r == 0) {
        return;  /* このPDUの受信途中、次tickへ */
    }

    ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 0),
           ((uint32_t)s_pl_rx_state << 28) | (ctx->io.tcp.rcv_seq & 0x0FFFFFFFu));

    switch (s_pl_rx_state) {
    case PL_RX_HDR: {
        uint8_t type = s_pl_hdr_buf[0];
        ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 1),
               ((uint32_t)type << 24) | ((uint32_t)s_pl_hdr_buf[2] << 16) |
               ((uint32_t)rd32le(&s_pl_hdr_buf[4]) & 0xFFFFu));
        /* 型固有部(16)とヘッダダイジェスト(有効なら4)を1回でまとめて受ける。 */
        uint32_t rest_len = NVME_CQE_LEN + nvme_tcp_hdgst_len(&ctx->io);
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_rest_buf, rest_len);
            s_pl_rx_state = PL_RX_RSP_REST;
        } else if (type == NVME_TCP_PDU_R2T) {
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_rest_buf, rest_len);
            s_pl_rx_state = PL_RX_R2T_REST;
        } else if (type == NVME_TCP_PDU_C2H_TERM) {
            /* **相手が致命的な誤りを見つけて理由を伝えてきた。** 読み捨てて
             * 再同期しても無駄(相手はこの後 TCP を閉じる)なので中断する。 */
            g_nvme_tcp_term_recv++;
            uart_printf("[!] nvme pipeline: C2H TermReq 受信 -- "
                        "相手がプロトコル誤りを検出しました\n");
            nvme_pipeline_fail_all_slots();
            /* **読み終えた印を付け直さないと、同じヘッダを何度も処理する**
             * (recv_poll は got>=want のとき即座に完了を返すため)。 */
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
            s_pl_rx_state = PL_RX_HDR;
        } else {
            uart_printf("[!] nvme pipeline: 未対応のPDU種別 (type=%u)、読み捨てて再同期を試みます\n", type);
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
            s_pl_rx_state = PL_RX_HDR;
        }
        break;
    }

    case PL_RX_RSP_REST: {
        if (nvme_pipeline_check_hdgst(ctx) != 0) {
            nvme_pipeline_fail_all_slots();
            return;
        }
        uint16_t cid    = rd16le(&s_pl_rest_buf[12]);
        uint16_t status = rd16le(&s_pl_rest_buf[14]);
        /* NRCV: Response Capsule(CQE)受信完了(write pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_RSP;
            info.hlen     = s_pl_hdr_buf[2];
            info.pdo      = s_pl_hdr_buf[3];
            info.plen     = rd32le(&s_pl_hdr_buf[4]);
            info.cid      = cid;
            info.status   = status;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 2), &info);
        }
        int slot = nvme_pipeline_find_slot(cid);
        if (slot >= 0) {
            s_pl_slots[slot].done   = 1;
            s_pl_slots[slot].result = (int)nvme_cqe_status_code(status);
        } else {
            uart_printf("[!] nvme pipeline: RSPのCIDが未知のスロット (cid=%u)\n", cid);
        }
        nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
        s_pl_rx_state = PL_RX_HDR;
        break;
    }

    case PL_RX_R2T_REST: {
        if (nvme_pipeline_check_hdgst(ctx) != 0) {
            nvme_pipeline_fail_all_slots();
            return;
        }
        uint16_t cccid = rd16le(&s_pl_rest_buf[0]);
        uint16_t ttag  = rd16le(&s_pl_rest_buf[2]);
        uint32_t r2to  = rd32le(&s_pl_rest_buf[4]);
        uint32_t r2tl  = rd32le(&s_pl_rest_buf[8]);
        /* NRCV: R2T受信完了(write pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_R2T;
            info.hlen        = s_pl_hdr_buf[2];
            info.pdo         = s_pl_hdr_buf[3];
            info.plen        = rd32le(&s_pl_hdr_buf[4]);
            info.cccid       = cccid;
            info.ttag        = ttag;
            info.data_offset = r2to;
            info.data_length = r2tl;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 3), &info);
        }
        int slot = nvme_pipeline_find_slot(cccid);
        if (slot >= 0) {
            if (nvme_h2c_pending_push(slot, cccid, ttag, r2to, r2tl) != 0) {
                uart_printf("[!] nvme pipeline: H2C送信キュー満杯 (cccid=%u)\n", cccid);
                s_pl_slots[slot].done   = 1;
                s_pl_slots[slot].result = -1;
            }
        } else {
            uart_printf("[!] nvme pipeline: R2TのCCCIDが未知のスロット (cccid=%u)\n", cccid);
        }
        nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
        s_pl_rx_state = PL_RX_HDR;
        break;
    }
    }
}

typedef struct {
    int      active;
    int      slot;
    uint16_t cid;
    uint16_t ttag;
    uint32_t r2to;
    uint32_t r2tl;
    uint32_t queued;      /* データ部のうち、既にtcp_send_async()でキューした量 */
    int      header_sent;
} nvme_h2c_cursor_t;

static nvme_h2c_cursor_t s_h2c_cursor;

/*=================================================================
 * H2CData 送信 FIFO と送信カーソルを初期状態へ戻す(ベンチ開始時)。
 *
 * コール元:
 *   nvme_write_pipelined_run()
 * ===============================================================*/
static void nvme_h2c_pipeline_reset(void)
{
    s_h2c_pending_head  = 0;
    s_h2c_pending_count = 0;
    for (unsigned i = 0; i < NVME_H2C_PENDING_MAX; i++) {
        s_h2c_pending[i].valid = 0;
    }
    s_h2c_cursor.active = 0;
}

/*=================================================================
 * H2CData 送信 FIFO から 1 件取り出し、ヘッダ + データを MSS 単位で
 * tcp_send_async() へ非ブロッキングにキューする。1 PDU 分は必ず連続して
 * キューし切ってから次へ進む(PDU をバイト単位でインターリーブしてはならない)。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * コール元:
 *   nvme_write_pipelined_run()
 * ===============================================================*/
static void nvme_pipeline_h2c_pump(nvme_ctx_t *ctx)
{
    if (!s_h2c_cursor.active) {
        if (s_h2c_pending_count == 0) {
            return;
        }
        nvme_h2c_pending_t *p = &s_h2c_pending[s_h2c_pending_head];
        s_h2c_cursor.active      = 1;
        s_h2c_cursor.slot        = p->slot;
        s_h2c_cursor.cid         = p->cid;
        s_h2c_cursor.ttag        = p->ttag;
        s_h2c_cursor.r2to        = p->r2to;
        s_h2c_cursor.r2tl        = p->r2tl;
        s_h2c_cursor.queued      = 0;
        s_h2c_cursor.header_sent = 0;
        p->valid = 0;
        s_h2c_pending_head = (s_h2c_pending_head + 1u) % NVME_H2C_PENDING_MAX;
        s_h2c_pending_count--;
    }

    uint32_t hd = nvme_tcp_hdgst_len(&ctx->io);
    uint32_t dd = nvme_tcp_ddgst_len(&ctx->io, s_h2c_cursor.r2tl);

    if (!s_h2c_cursor.header_sent) {
        uint8_t hdr[NVME_TCP_DATA_PDU_LEN + NVME_TCP_DGST_LEN];
        hdr[0] = NVME_TCP_PDU_H2C_DATA;
        hdr[1] = (uint8_t)(NVME_TCP_F_DATA_LAST |
                           (ctx->io.hdgst ? NVME_TCP_F_HDGST : 0u) |
                           (dd ? NVME_TCP_F_DDGST : 0u));
        hdr[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        hdr[3] = (uint8_t)(NVME_TCP_DATA_PDU_LEN + hd);  /* pdo: データはヘッダ(+hdgst)直後 */
        wr32le(&hdr[4], NVME_TCP_DATA_PDU_LEN + hd + s_h2c_cursor.r2tl + dd);
        wr16le(&hdr[8],  s_h2c_cursor.cid);
        wr16le(&hdr[10], s_h2c_cursor.ttag);
        wr32le(&hdr[12], s_h2c_cursor.r2to);
        wr32le(&hdr[16], s_h2c_cursor.r2tl);
        wr32le(&hdr[20], 0);  /* reserved */
        nvme_tcp_append_hdgst(&ctx->io, hdr, NVME_TCP_DATA_PDU_LEN);
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = hdr[0];
            info.hlen        = hdr[2];
            info.pdo         = hdr[3];
            info.plen        = NVME_TCP_DATA_PDU_LEN + s_h2c_cursor.r2tl;
            info.cccid       = s_h2c_cursor.cid;
            info.ttag        = s_h2c_cursor.ttag;
            info.data_offset = s_h2c_cursor.r2to;
            info.data_length = s_h2c_cursor.r2tl;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_h2c_pump, 0), &info);
        }
        if (tcp_send_async(&ctx->io.tcp, hdr, (uint16_t)(NVME_TCP_DATA_PDU_LEN + hd)) < 0) {
            uart_printf("[!] nvme pipeline: H2CDataヘッダ送信失敗 (cid=%u)\n", s_h2c_cursor.cid);
            s_pl_slots[s_h2c_cursor.slot].done   = 1;
            s_pl_slots[s_h2c_cursor.slot].result = -1;
            s_h2c_cursor.active = 0;
            return;
        }
        s_h2c_cursor.header_sent = 1;
    }

    const uint8_t *src = (const uint8_t *)s_pl_slots[s_h2c_cursor.slot].data;
    while (s_h2c_cursor.queued < s_h2c_cursor.r2tl) {
        uint32_t remaining = s_h2c_cursor.r2tl - s_h2c_cursor.queued;
        uint16_t chunk = (remaining > TCP_ASYNC_MAX_LEN) ? (uint16_t)TCP_ASYNC_MAX_LEN : (uint16_t)remaining;
        if (s_h2c_cursor.queued == 0) {
            ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_h2c_pump, 1), s_h2c_cursor.cid);
        }
        int rc = tcp_send_async(&ctx->io.tcp,
                                 src + s_h2c_cursor.r2to + s_h2c_cursor.queued, chunk);
        if (rc < 0) {
            uart_printf("[!] nvme pipeline: H2CDataデータ送信失敗 (cid=%u offset=%u)\n",
                        s_h2c_cursor.cid, s_h2c_cursor.r2to + s_h2c_cursor.queued);
            s_pl_slots[s_h2c_cursor.slot].done   = 1;
            s_pl_slots[s_h2c_cursor.slot].result = -1;
            s_h2c_cursor.active = 0;
            return;
        }
        s_h2c_cursor.queued += (uint32_t)rc;
    }
    if (dd) {
        /* データはゼロコピーで送るので、ダイジェストは送信元バッファから
         * まとめて計算して 4 バイトだけ追加でキューする。 */
        uint8_t d[NVME_TCP_DGST_LEN];
        wr32le(d, ~crc32c(0xFFFFFFFFu, src + s_h2c_cursor.r2to, s_h2c_cursor.r2tl));
        if (tcp_send_async(&ctx->io.tcp, d, (uint16_t)NVME_TCP_DGST_LEN) < 0) {
            uart_printf("[!] nvme pipeline: H2CDataダイジェスト送信失敗 (cid=%u)\n",
                        s_h2c_cursor.cid);
            s_pl_slots[s_h2c_cursor.slot].done   = 1;
            s_pl_slots[s_h2c_cursor.slot].result = -1;
            s_h2c_cursor.active = 0;
            return;
        }
    }
    ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_h2c_pump, 2), s_h2c_cursor.cid);

    /* このPDUは完全にキューし終えた -- 次回の呼び出しで次のPDU(あれば)へ進む。 */
    s_h2c_cursor.active = 0;
}

/*=================================================================
 * ベンチのコマンドごとに開始 LBA を nlb ずつ進め、名前空間の終端を超えたら
 * 開始位置へ戻す(fio のシーケンシャルアクセスと条件を揃えるため)。
 *
 * 引数:
 *   ctx  - initiator コンテキスト(nsze を持つ)
 *   cur  - 現在の LBA
 *   base - ラップ時に戻る開始 LBA
 *   nlb  - 1 コマンドのブロック数
 * 戻り値:
 *   次のコマンドで使う LBA
 * コール元:
 *   nvme_write_pipelined_run(), nvme_read_pipelined_run()
 * ===============================================================*/
static uint64_t nvme_bench_next_lba(const nvme_ctx_t *ctx, uint64_t cur,
                                    uint64_t base, uint32_t nlb)
{
    uint64_t next = cur + (uint64_t)nlb;
    if (ctx->nsze == 0u || next + (uint64_t)nlb > ctx->nsze) {
        return base;
    }
    return next;
}

/*=================================================================
 * NVMe/TCP write を NVME_IO_QDEPTH 本まで同時 outstanding にして
 * duration_ms のあいだ回し続け、実行回数とバイト数を返す。SQE は非同期
 * 送信、R2T 受信と H2CData 送信は FIFO を介して分離してある。
 *
 * 引数:
 *   ctx  - initiator コンテキスト
 *   nsid - 名前空間 ID
 *   lba  - 開始 LBA
 *   buf  - 送信データ
 *   nlb  - 1 コマンドのブロック数
 *   duration_ms - 測定時間
 *   out_count / out_bytes / out_elapsed_ms - 結果の格納先
 * 戻り値:
 *   0=正常終了、-1=エラー
 * コール元:
 *   tcp_measure()
 * ===============================================================*/
int nvme_write_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                              const void *buf, uint32_t nlb, uint32_t duration_ms,
                              uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms)
{
    if (!ctx->io_connected) {
        uart_printf("[!] nvme pipeline: IO queue未接続\n");
        return -1;
    }
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    ctx->busy = 1;

    uint32_t total_len = nlb * ctx->lba_size;
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        s_pl_slots[i].in_use = 0;
    }
    nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
    s_pl_rx_state = PL_RX_HDR;
    nvme_h2c_pipeline_reset();

    uint64_t cur_lba = lba;  /* fio 同様、コマンドごとに進める(nvme_bench_next_lba) */
    uint32_t count = 0;
    uint64_t bytes = 0;
    uint64_t start = timer_now();

    while (!timeout_ms(start, duration_ms)) {
        sim_delay_tick();  /* 2026-08-11、性能切り分け用の一時計装(smp.h参照) */
        /* 完了済みスロットを刈り取り、集計してから空ける。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use && s_pl_slots[i].done) {
                if (s_pl_slots[i].result == 0) {
                    count++;
                    bytes += s_pl_slots[i].len;
                } else {
                    uart_printf("[!] nvme pipeline: write失敗 (cid=%u result=%d)\n",
                                s_pl_slots[i].cid, s_pl_slots[i].result);
                }
                s_pl_slots[i].in_use = 0;
            }
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (!s_pl_slots[i].in_use) {
                s_pl_slots[i].in_use = 1;
                s_pl_slots[i].sent   = 0;
                s_pl_slots[i].done   = 0;
                s_pl_slots[i].result = 0;
                s_pl_slots[i].data   = buf;
                s_pl_slots[i].len    = total_len;
                nvme_build_write_sqe(&s_pl_slots[i].sqe, nsid, cur_lba, nlb, total_len);
                cur_lba = nvme_bench_next_lba(ctx, cur_lba, lba, nlb);
            }
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use && !s_pl_slots[i].sent) {
                uint16_t cid = 0;
                if (nvme_tcp_send_cmd_async(&ctx->io, &s_pl_slots[i].sqe, &cid) != 0) {
                    s_pl_slots[i].done   = 1;
                    s_pl_slots[i].result = -1;
                    continue;
                }
                {
                    const uint8_t *sqe_bytes = (const uint8_t *)&s_pl_slots[i].sqe;
                    volatile ts_nvme_pdu_t info = {0};
                    info.pdu_type    = NVME_TCP_PDU_CMD;
                    info.hlen        = (uint8_t)NVME_TCP_CMD_PDU_LEN;
                    info.pdo         = 0;
                    info.plen        = NVME_TCP_CMD_PDU_LEN;
                    info.cid         = cid;
                    info.opcode      = sqe_bytes[0];
                    info.sgl_type    = sqe_bytes[39];
                    info.data_length = rd32le(&sqe_bytes[32]);  /* LEN(SGL宣言転送量) */
                    ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_write_pipelined_run, 0), &info);
                }
                s_pl_slots[i].cid  = cid;
                s_pl_slots[i].sent = 1;
            }
        }
        nvme_pipeline_rx_tick(ctx);
        nvme_pipeline_h2c_pump(ctx);
        job_scheduler_tick();
    }

    {
        uint64_t drain_start = timer_now();
        while (!timeout_ms(drain_start, NVME_IO_CMD_TIMEOUT_MS)) {
            int any_outstanding = 0;
            for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
                if (s_pl_slots[i].in_use && !s_pl_slots[i].done) {
                    any_outstanding = 1;
                }
            }
            if (!any_outstanding) break;
            nvme_pipeline_rx_tick(ctx);
            nvme_pipeline_h2c_pump(ctx);
            job_scheduler_tick();
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use) {
                if (s_pl_slots[i].done && s_pl_slots[i].result == 0) {
                    count++;
                    bytes += s_pl_slots[i].len;
                } else if (!s_pl_slots[i].done) {
                    uart_printf("[!] nvme pipeline: drainタイムアウト、未完了のまま諦めます (cid=%u)\n",
                                s_pl_slots[i].cid);
                }
                s_pl_slots[i].in_use = 0;
            }
        }
    }

    uint32_t elapsed_ms = (uint32_t)get_ms_from(start);
    ctx->busy = 0;
    if (out_count)      *out_count      = count;
    if (out_bytes)      *out_bytes      = bytes;
    if (out_elapsed_ms) *out_elapsed_ms = elapsed_ms;
    return 0;
}

typedef struct {
    int        in_use;
    int        sent;
    int        done;
    int        result;
    uint16_t   cid;
    nvme_sqe_t sqe;
    void      *data;   /* 読み出し先バッファ(呼び出し元所有) */
    uint32_t   len;    /* 期待する合計長 */
} nvme_pipeline_read_slot_t;

typedef enum {
    PL_READ_RX_HDR = 0,
    PL_READ_RX_RSP_REST,
    PL_READ_RX_C2H_REST,
    PL_READ_RX_C2H_DATA,
    PL_READ_RX_C2H_DDGST,
} nvme_pipeline_read_rx_state_t;

static uint8_t s_pl_read_discard_buf[262144] __attribute__((aligned(64)));

typedef enum { NRX_HDR, NRX_PSH, NRX_HDGST, NRX_DATA, NRX_DDGST } nvme_read_prx_phase_t;

typedef struct {
    nvme_pipeline_read_slot_t     slots[NVME_IO_QDEPTH];
    nvme_pipeline_read_rx_state_t rx_state;
    nvme_tcp_xfer_t               xfer;
    uint8_t                       hdr_buf[NVME_TCP_HDR_LEN];
    /* 型固有部(16)+ヘッダダイジェスト(4)を1回でまとめて受ける。 */
    uint8_t                       rest_buf[16 + 4];
    uint8_t                       dgst_buf[4];  /* データダイジェストの受信先 */
    int                           cur_slot;
    uint16_t                      cur_cccid;
    uint32_t                      cur_datao;
    uint32_t                      cur_datal;
    /* push型受信(upcall)パーサ状態 */
    nvme_read_prx_phase_t nrx_phase;
    uint8_t   nrx_hdr[NVME_TCP_HDR_LEN];
    uint32_t  nrx_hdr_off;
    uint8_t   nrx_psh[16];
    uint32_t  nrx_psh_off, nrx_psh_need;
    uint8_t   nrx_type;
    volatile uint8_t *nrx_data_dst;
    uint32_t  nrx_data_off, nrx_data_need;
    int       nrx_slot;
    int       nrx_error;
    /* push型でのダイジェスト受信/照合。データはコピーしながら逐次CRCを積む。 */
    uint8_t   nrx_dgst[4];
    uint32_t  nrx_dgst_off;
    uint32_t  nrx_ddgst_crc;
} nvme_rd_state_t;
static nvme_rd_state_t s_rd[SMP_MAX_CORES];

/*=================================================================
 * read パイプラインの送信済み・未完了スロットから cid が一致するものを探す。
 *
 * 引数:
 *   cid - 探すコマンド id
 * 戻り値:
 *   スロット番号。見つからなければ -1
 * コール元:
 *   nvme_read_rx_upcall(), nvme_pipeline_read_rx_tick()
 * ===============================================================*/
static int nvme_pipeline_read_find_slot(uint16_t cid)
{
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        if (rd->slots[i].in_use && rd->slots[i].sent && !rd->slots[i].done &&
            rd->slots[i].cid == cid) {
            return (int)i;
        }
    }
    return -1;
}

/*=================================================================
 * read パイプラインの push 型受信ハンドラ。tcp_input() から in-order データ
 * をその場で受け取り、C2HData のヘッダを解析してデータ本体を受信先へ直接
 * 配置する(rx_buf を経由しない 1 コピー)。
 *
 * 引数:
 *   arg  - initiator コンテキスト
 *   data - 到着した in-order バイト列
 *   len  - そのバイト数
 * コール元:
 *   tcp_input() から tcp_recv_upcall として
 * ===============================================================*/
/*=================================================================
 * read パイプラインの未完了スロットを全て失敗にする(受信エラーや
 * ダイジェスト不一致で、以後ストリームの同期を保証できなくなったとき)。
 *
 * 引数:
 *   rd - このコアの read パイプライン状態
 * コール元:
 *   nvme_pipeline_read_rx_tick()
 * ===============================================================*/
static void nvme_read_fail_all_slots(nvme_rd_state_t *rd)
{
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        if (rd->slots[i].in_use && rd->slots[i].sent && !rd->slots[i].done) {
            rd->slots[i].done   = 1;
            rd->slots[i].result = -1;
        }
    }
}

/*=================================================================
 * read パイプライン(pull 型)で受信した PDU のヘッダダイジェストを検証する。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 *   rd  - このコアの read パイプライン状態
 * 戻り値:
 *   0=一致(無効時も 0)、-1=不一致
 * コール元:
 *   nvme_pipeline_read_rx_tick()
 * ===============================================================*/
static int nvme_read_check_hdgst(const nvme_ctx_t *ctx, const nvme_rd_state_t *rd)
{
    return nvme_tcp_verify_hdgst(&ctx->io, rd->hdr_buf, NVME_TCP_HDR_LEN,
                                  rd->rest_buf, NVME_CQE_LEN, &rd->rest_buf[NVME_CQE_LEN]);
}

/*=================================================================
 * C2HData を 1 個受け切った後の共通処理(pull 型)。DATA_SUCCESS が立って
 * いればスロットを完了させ、次の PDU ヘッダ待ちへ戻る。データダイジェストの
 * 有無で入口が 2 つあるため関数化した。
 *
 * 引数:
 *   rd - このコアの read パイプライン状態
 * コール元:
 *   nvme_pipeline_read_rx_tick()
 * ===============================================================*/
static void nvme_read_c2h_complete(nvme_rd_state_t *rd)
{
    if (rd->cur_slot >= 0 && (rd->hdr_buf[1] & NVME_TCP_F_DATA_SUCCESS)) {
        rd->slots[rd->cur_slot].done   = 1;
        rd->slots[rd->cur_slot].result = 0;
    }
    nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
    rd->rx_state = PL_READ_RX_HDR;
}

static void nvme_read_prx_finish_pdu(nvme_rd_state_t *rd)
{
    if (rd->nrx_slot >= 0 && (rd->nrx_hdr[1] & NVME_TCP_F_DATA_SUCCESS)) {
        rd->slots[rd->nrx_slot].done = 1;
        rd->slots[rd->nrx_slot].result = 0;
    }
    rd->nrx_phase = NRX_HDR;
    rd->nrx_hdr_off = 0;
}

/*=================================================================
 * push 型受信で、共通ヘッダ + 型固有部(+ヘッダダイジェスト)を読み切った
 * 時点の分岐。C2HData ならデータ受信の準備をし、Response Capsule なら
 * その場でスロットを完了させる。
 *
 * 引数:
 *   ctx - initiator コンテキスト(ダイジェスト設定の参照に使う)
 *   rd  - このコアの read パイプライン状態
 * コール元:
 *   nvme_read_rx_upcall()
 * ===============================================================*/
static void nvme_read_prx_dispatch(nvme_ctx_t *ctx, nvme_rd_state_t *rd)
{
    if (rd->nrx_type == NVME_TCP_PDU_C2H_DATA) {
        uint16_t cccid = rd16le(&rd->nrx_psh[0]);
        uint32_t datao = rd32le(&rd->nrx_psh[4]);
        uint32_t datal = rd32le(&rd->nrx_psh[8]);
        int slot = nvme_pipeline_read_find_slot(cccid);
        if (slot < 0 || (uint64_t)datao + (uint64_t)datal > (uint64_t)rd->slots[slot].len) {
            if (slot >= 0) { rd->slots[slot].done = 1; rd->slots[slot].result = -1; }
            rd->nrx_slot = -1;   /* データは読み捨て(下記でコピーせず消費のみ) */
        } else {
            rd->nrx_slot = slot;
            rd->nrx_data_dst = (volatile uint8_t *)rd->slots[slot].data + datao;
        }
        rd->nrx_data_need = datal;
        if (datal == 0u) {
            nvme_read_prx_finish_pdu(rd);
        } else {
            rd->nrx_data_off = 0;
            rd->nrx_ddgst_crc = 0xFFFFFFFFu;
            rd->nrx_phase = NRX_DATA;
        }
    } else if (rd->nrx_type == NVME_TCP_PDU_RSP) {
        uint16_t cid    = rd16le(&rd->nrx_psh[12]);
        uint16_t status = rd16le(&rd->nrx_psh[14]);
        int slot = nvme_pipeline_read_find_slot(cid);
        if (slot >= 0) {
            rd->slots[slot].done = 1;
            rd->slots[slot].result = (int)nvme_cqe_status_code(status);
        }
        rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0;
    } else {
        rd->nrx_error = 1;
    }
    (void)ctx;
}

static void nvme_read_rx_upcall(void *arg, const volatile uint8_t *data, uint16_t len)
{
    nvme_ctx_t *ctx = (nvme_ctx_t *)arg;
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    uint32_t i = 0;
    while (i < (uint32_t)len && !rd->nrx_error) {
        switch (rd->nrx_phase) {
        case NRX_HDR: {
            uint32_t take = (uint32_t)NVME_TCP_HDR_LEN - rd->nrx_hdr_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) rd->nrx_hdr[rd->nrx_hdr_off + k] = data[i + k];
            rd->nrx_hdr_off += take; i += take;
            if (rd->nrx_hdr_off == (uint32_t)NVME_TCP_HDR_LEN) {
                rd->nrx_type = rd->nrx_hdr[0];
                uint8_t hlen = rd->nrx_hdr[2];
                rd->nrx_psh_need = (hlen > NVME_TCP_HDR_LEN) ? (uint32_t)(hlen - NVME_TCP_HDR_LEN) : 0u;
                if (rd->nrx_psh_need == 0u || rd->nrx_psh_need > sizeof(rd->nrx_psh)) { rd->nrx_error = 1; break; }
                rd->nrx_psh_off = 0; rd->nrx_phase = NRX_PSH;
            }
            break;
        }
        case NRX_PSH: {
            uint32_t take = rd->nrx_psh_need - rd->nrx_psh_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) rd->nrx_psh[rd->nrx_psh_off + k] = data[i + k];
            rd->nrx_psh_off += take; i += take;
            if (rd->nrx_psh_off < rd->nrx_psh_need) break;

            if (nvme_tcp_hdgst_len(&ctx->io) != 0u) {
                rd->nrx_dgst_off = 0;
                rd->nrx_phase = NRX_HDGST;
            } else {
                nvme_read_prx_dispatch(ctx, rd);
            }
            break;
        }
        case NRX_HDGST: {
            uint32_t take = NVME_TCP_DGST_LEN - rd->nrx_dgst_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) rd->nrx_dgst[rd->nrx_dgst_off + k] = data[i + k];
            rd->nrx_dgst_off += take; i += take;
            if (rd->nrx_dgst_off < NVME_TCP_DGST_LEN) break;

            if (nvme_tcp_verify_hdgst(&ctx->io, rd->nrx_hdr, NVME_TCP_HDR_LEN,
                                       rd->nrx_psh, rd->nrx_psh_need, rd->nrx_dgst) != 0) {
                rd->nrx_error = 1;
                break;
            }
            nvme_read_prx_dispatch(ctx, rd);
            break;
        }
        case NRX_DATA: {
            uint32_t need  = rd->nrx_data_need - rd->nrx_data_off;
            uint32_t avail = (uint32_t)len - i;
            uint32_t take  = (need > avail) ? avail : need;
            if (rd->nrx_slot >= 0) {
                volatile_fast_copy(rd->nrx_data_dst + rd->nrx_data_off, data + i, take);
            }
            /* CRC は受信ストリームから直接積む(読み捨て時もダイジェストを
             * 検証でき、コピー先を読み直す 2 パス目も要らない)。 */
            if (ctx->io.ddgst) {
                rd->nrx_ddgst_crc = crc32c(rd->nrx_ddgst_crc, data + i, take);
            }
            rd->nrx_data_off += take; i += take;
            if (rd->nrx_data_off == rd->nrx_data_need) {
                if (ctx->io.ddgst) {
                    rd->nrx_dgst_off = 0;
                    rd->nrx_phase = NRX_DDGST;
                } else {
                    nvme_read_prx_finish_pdu(rd);
                }
            }
            break;
        }
        case NRX_DDGST: {
            uint32_t take = NVME_TCP_DGST_LEN - rd->nrx_dgst_off;
            uint32_t avail = (uint32_t)len - i;
            if (take > avail) take = avail;
            for (uint32_t k = 0; k < take; k++) rd->nrx_dgst[rd->nrx_dgst_off + k] = data[i + k];
            rd->nrx_dgst_off += take; i += take;
            if (rd->nrx_dgst_off < NVME_TCP_DGST_LEN) break;

            if (nvme_tcp_check_ddgst_crc(&ctx->io, rd->nrx_ddgst_crc, rd->nrx_dgst) != 0) {
                if (rd->nrx_slot >= 0) {
                    rd->slots[rd->nrx_slot].done = 1;
                    rd->slots[rd->nrx_slot].result = -1;
                }
                rd->nrx_error = 1;
                break;
            }
            nvme_read_prx_finish_pdu(rd);
            break;
        }
        }
    }
}

/*=================================================================
 * read パイプラインの pull 型受信 1 tick(push 型を使わない経路のフォール
 * バック)。到着済み PDU を非ブロッキングで 1 段だけ処理する。
 *
 * 引数:
 *   ctx - initiator コンテキスト
 * コール元:
 *   nvme_read_pipelined_run()
 * ===============================================================*/
static void nvme_pipeline_read_rx_tick(nvme_ctx_t *ctx)
{
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    int r = nvme_tcp_recv_poll(&ctx->io, &rd->xfer);
    if (r < 0) {
        nvme_read_fail_all_slots(rd);
        return;
    }
    if (r == 0) {
        return;  /* このPDUの受信途中、次tickへ */
    }

    switch (rd->rx_state) {
    case PL_READ_RX_HDR: {
        uint8_t type = rd->hdr_buf[0];
        /* 型固有部(16)とヘッダダイジェスト(有効なら4)を1回でまとめて受ける。 */
        uint32_t rest_len = NVME_CQE_LEN + nvme_tcp_hdgst_len(&ctx->io);
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&rd->xfer, rd->rest_buf, rest_len);
            rd->rx_state = PL_READ_RX_RSP_REST;
        } else if (type == NVME_TCP_PDU_C2H_DATA) {
            nvme_tcp_xfer_reset(&rd->xfer, rd->rest_buf, rest_len);
            rd->rx_state = PL_READ_RX_C2H_REST;
        } else if (type == NVME_TCP_PDU_C2H_TERM) {
            /* 相手が致命的な誤りを見つけて理由を伝えてきた(write 側と同じ)。 */
            g_nvme_tcp_term_recv++;
            uart_printf("[!] nvme read pipeline: C2H TermReq 受信 -- "
                        "相手がプロトコル誤りを検出しました\n");
            rd->nrx_error = 1;   /* 上位が拾って読み出しを打ち切る */
            /* write 側と同じ理由で、読み終えた印を付け直す。 */
            nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
            rd->rx_state = PL_READ_RX_HDR;
        } else {
            uart_printf("[!] nvme read pipeline: 未対応のPDU種別 (type=%u)、読み捨てて再同期を試みます\n", type);
            nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
            rd->rx_state = PL_READ_RX_HDR;
        }
        break;
    }

    case PL_READ_RX_RSP_REST: {
        if (nvme_read_check_hdgst(ctx, rd) != 0) { nvme_read_fail_all_slots(rd); return; }
        uint16_t cid    = rd16le(&rd->rest_buf[12]);
        uint16_t status = rd16le(&rd->rest_buf[14]);
        /* NRCV: Response Capsule(CQE)受信完了(read pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type = NVME_TCP_PDU_RSP;
            info.hlen     = rd->hdr_buf[2];
            info.pdo      = rd->hdr_buf[3];
            info.plen     = rd32le(&rd->hdr_buf[4]);
            info.cid      = cid;
            info.status   = status;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_read_rx_tick, 0), &info);
        }
        int slot = nvme_pipeline_read_find_slot(cid);
        if (slot >= 0) {
            rd->slots[slot].done   = 1;
            rd->slots[slot].result = (int)nvme_cqe_status_code(status);
        } else {
            uart_printf("[!] nvme read pipeline: RSPのCIDが未知のスロット (cid=%u)\n", cid);
        }
        nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
        rd->rx_state = PL_READ_RX_HDR;
        break;
    }

    case PL_READ_RX_C2H_REST: {
        if (nvme_read_check_hdgst(ctx, rd) != 0) { nvme_read_fail_all_slots(rd); return; }
        uint16_t cccid = rd16le(&rd->rest_buf[0]);
        uint32_t datao = rd32le(&rd->rest_buf[4]);
        uint32_t datal = rd32le(&rd->rest_buf[8]);
        int slot = nvme_pipeline_read_find_slot(cccid);
        if (slot < 0) {
            uart_printf("[!] nvme read pipeline: C2HDataのCCCIDが未知のスロット (cccid=%u)、読み捨てます\n", cccid);
            rd->cur_slot = -1;
        } else if ((uint64_t)datao + (uint64_t)datal > (uint64_t)rd->slots[slot].len) {
            uart_printf("[!] nvme read pipeline: C2HDataがバッファ超過 (datao=%u datal=%u len=%u)\n",
                        datao, datal, rd->slots[slot].len);
            rd->slots[slot].done   = 1;
            rd->slots[slot].result = -1;
            rd->cur_slot = -1;
        } else {
            rd->cur_slot = slot;
        }
        rd->cur_cccid = cccid;
        rd->cur_datao = datao;
        rd->cur_datal = datal;
        if (rd->cur_slot >= 0) {
            nvme_tcp_xfer_reset(&rd->xfer,
                                 (uint8_t *)rd->slots[rd->cur_slot].data + datao, datal);
        } else {
            uint32_t discard_len = (datal > sizeof(s_pl_read_discard_buf))
                                        ? (uint32_t)sizeof(s_pl_read_discard_buf) : datal;
            nvme_tcp_xfer_reset(&rd->xfer, s_pl_read_discard_buf, discard_len);
        }
        rd->rx_state = PL_READ_RX_C2H_DATA;
        break;
    }

    case PL_READ_RX_C2H_DATA: {
        uint8_t flags = rd->hdr_buf[1];
        /* NRCV: C2HData受信完了(read pipeline)。 */
        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_C2H_DATA;
            info.hlen        = rd->hdr_buf[2];
            info.pdo         = rd->hdr_buf[3];
            info.plen        = rd32le(&rd->hdr_buf[4]);
            info.cccid       = rd->cur_cccid;
            info.data_offset = rd->cur_datao;
            info.data_length = rd->cur_datal;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_read_rx_tick, 1), &info);
        }
        (void)flags;
        if (nvme_tcp_ddgst_len(&ctx->io, rd->cur_datal) != 0u) {
            nvme_tcp_xfer_reset(&rd->xfer, rd->dgst_buf, NVME_TCP_DGST_LEN);
            rd->rx_state = PL_READ_RX_C2H_DDGST;
            break;
        }
        nvme_read_c2h_complete(rd);
        break;
    }

    case PL_READ_RX_C2H_DDGST: {
        /* 読み捨て中(cur_slot<0)はデータ本体を保持していないので検証できない。
         * 4 バイトを消費してストリームの位置だけ合わせる。 */
        if (rd->cur_slot >= 0 &&
            nvme_tcp_verify_ddgst(&ctx->io,
                                   (const uint8_t *)rd->slots[rd->cur_slot].data + rd->cur_datao,
                                   rd->cur_datal, rd->dgst_buf) != 0) {
            rd->slots[rd->cur_slot].done   = 1;
            rd->slots[rd->cur_slot].result = -1;
            nvme_read_fail_all_slots(rd);
            return;
        }
        nvme_read_c2h_complete(rd);
        break;
    }
    }
}

/*=================================================================
 * NVMe/TCP read を NVME_IO_QDEPTH 本まで同時 outstanding にして
 * duration_ms のあいだ回し続け、実行回数とバイト数を返す。受信は push 型
 * upcall を登録して 1 コピーで済ませる。
 *
 * 引数:
 *   ctx / nsid / lba / buf / nlb / duration_ms
 *              - nvme_write_pipelined_run() と同じ(buf は受信先)
 *   out_count / out_bytes / out_elapsed_ms - 結果の格納先
 * 戻り値:
 *   0=正常終了、-1=エラー
 * コール元:
 *   tcp_measure()
 * ===============================================================*/
int nvme_read_pipelined_run(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba,
                             void *buf, uint32_t nlb, uint32_t duration_ms,
                             uint32_t *out_count, uint64_t *out_bytes, uint32_t *out_elapsed_ms)
{
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    if (!ctx->io_connected) {
        uart_printf("[!] nvme read pipeline: IO queue未接続\n");
        return -1;
    }
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    ctx->busy = 1;

    uint32_t total_len = nlb * ctx->lba_size;
    for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
        rd->slots[i].in_use = 0;
    }
    nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
    rd->rx_state = PL_READ_RX_HDR;
    rd->cur_slot = -1;

    rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0; rd->nrx_error = 0; rd->nrx_slot = -1;
    tcp_set_recv_upcall(&ctx->io.tcp, nvme_read_rx_upcall, ctx);

    uint64_t cur_lba = lba;  /* fio 同様、コマンドごとに進める(nvme_bench_next_lba) */
    uint32_t count = 0;
    uint64_t bytes = 0;
    uint64_t start = timer_now();

    while (!timeout_ms(start, duration_ms)) {
        sim_delay_tick();  /* 2026-08-11、性能切り分け用の一時計装(smp.h参照) */
        /* 完了済みスロットを刈り取り、集計してから空ける。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use && rd->slots[i].done) {
                if (rd->slots[i].result == 0) {
                    count++;
                    bytes += rd->slots[i].len;
                } else {
                    uart_printf("[!] nvme read pipeline: read失敗 (cid=%u result=%d)\n",
                                rd->slots[i].cid, rd->slots[i].result);
                }
                rd->slots[i].in_use = 0;
            }
        }
        uint32_t rx_cap = tcp_rx_buf_size();
        unsigned max_inflight = NVME_IO_QDEPTH;
        if (total_len > 0u && rx_cap > total_len) {
            uint32_t m = rx_cap / total_len;
            if (m > 0u) m -= 1u;               /* 1 転送分の headroom を残す */
            if (m == 0u) m = 1u;
            if (m < max_inflight) max_inflight = (unsigned)m;
        }
        unsigned inflight = 0;
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use) inflight++;
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH && inflight < max_inflight; i++) {
            if (!rd->slots[i].in_use) {
                inflight++;
                rd->slots[i].in_use = 1;
                rd->slots[i].sent   = 0;
                rd->slots[i].done   = 0;
                rd->slots[i].result = 0;
                rd->slots[i].data   = buf;
                rd->slots[i].len    = total_len;
                nvme_build_read_sqe(&rd->slots[i].sqe, nsid, cur_lba, nlb, total_len);
                cur_lba = nvme_bench_next_lba(ctx, cur_lba, lba, nlb);
            }
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use && !rd->slots[i].sent) {
                uint16_t cid = 0;
                if (nvme_tcp_send_cmd_async(&ctx->io, &rd->slots[i].sqe, &cid) != 0) {
                    rd->slots[i].done   = 1;
                    rd->slots[i].result = -1;
                    continue;
                }
                {
                    const uint8_t *sqe_bytes = (const uint8_t *)&rd->slots[i].sqe;
                    volatile ts_nvme_pdu_t info = {0};
                    info.pdu_type    = NVME_TCP_PDU_CMD;
                    info.hlen        = (uint8_t)NVME_TCP_CMD_PDU_LEN;
                    info.pdo         = 0;
                    info.plen        = NVME_TCP_CMD_PDU_LEN;
                    info.cid         = cid;
                    info.opcode      = sqe_bytes[0];
                    info.sgl_type    = sqe_bytes[39];
                    info.data_length = rd32le(&sqe_bytes[32]);  /* LEN(SGL宣言転送量) */
                    ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_read_pipelined_run, 0), &info);
                }
                rd->slots[i].cid  = cid;
                rd->slots[i].sent = 1;
            }
        }
        nvme_pipeline_read_rx_tick(ctx);
        job_scheduler_tick();
    }

    {
        uint64_t drain_start = timer_now();
        while (!timeout_ms(drain_start, NVME_IO_CMD_TIMEOUT_MS)) {
            int any_outstanding = 0;
            for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
                if (rd->slots[i].in_use && !rd->slots[i].done) {
                    any_outstanding = 1;
                }
            }
            if (!any_outstanding) break;
            nvme_pipeline_read_rx_tick(ctx);
            job_scheduler_tick();
        }
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use) {
                if (rd->slots[i].done && rd->slots[i].result == 0) {
                    count++;
                    bytes += rd->slots[i].len;
                } else if (!rd->slots[i].done) {
                    uart_printf("[!] nvme read pipeline: drainタイムアウト、未完了のまま諦めます (cid=%u)\n",
                                rd->slots[i].cid);
                }
                rd->slots[i].in_use = 0;
            }
        }
    }

    tcp_clear_recv_upcall(&ctx->io.tcp);  /* push型受信を解除(pull経路へ戻す) */
    uint32_t elapsed_ms = (uint32_t)get_ms_from(start);
    ctx->busy = 0;
    if (out_count)      *out_count      = count;
    if (out_bytes)      *out_bytes      = bytes;
    if (out_elapsed_ms) *out_elapsed_ms = elapsed_ms;
    return 0;
}

/*=================================================================
 * IPv4 用の薄いラッパ。従来の呼び出し元(シェルなど)がそのまま使える。
 *
 * 引数:
 *   ctx / ip / port / subnqn - 接続先(IPv4 はホストバイトオーダー)
 * 戻り値:
 *   nvme_connect_job_start_addr() の戻り値
 * コール元:
 *   shell_ensure_tcp_session()
 * ===============================================================*/
int nvme_connect_job_start(nvme_ctx_t *ctx, uint32_t ip, uint16_t port, const char *subnqn)
{
    netaddr_t a = netaddr_v4(ip);
    return nvme_connect_job_start_addr(ctx, &a, port, subnqn);
}
