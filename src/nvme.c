// nvme.c
//
// NVMeプロトコル層 -- SQEの組み立てとCQEの解釈。PDU/TCPの詳細は
// nvme_tcp.c(移植境界、CLAUDE.md参照)に委譲する。
//
// 全ての多バイトフィールドアクセスはnet.hのrd16le/rd32le/wr16le/wr32le/
// wr64le(volatile経由のバイト単位アクセス)のみを使う(nvme_types.hの
// コメント参照 -- NVMeはリトルエンディアン)。

#include <stddef.h>
#include "nvme.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "job.h"
#include "timestamp.h"
#include "smp.h"
#include "netctx.h"

#define NVME_QSIZE               32u    /* admin/IO両queueのsqsize(Fabrics Connectで通知) */
#define NVME_ADMIN_CMD_TIMEOUT_MS 5000u
#define NVME_IO_CMD_TIMEOUT_MS   10000u

/* nvme_connect_job_step()(下記)がICResp受信を待つ締め切り。旧
 * nvme_tcp.cのNVME_TCP_ICRESP_TIMEOUT_MSと同じ値(ジョブ化に伴いnvme.c
 * 側で締め切り管理するようになったため、ここに複製した)。 */
#define NVME_CONNECT_ICRESP_TIMEOUT_MS 3000u

/* CC.EN=1書き込み後、CSTS.RDYになるまでのポーリング上限/間隔。
 * ramdiskバックエンドのtargetでは実質即座にRDYになるが、実ストレージ
 * バックエンドでは多少時間がかかることを見込んで余裕を持たせる。 */
#define NVME_CTRL_READY_POLL_MAX     20u
#define NVME_CTRL_READY_POLL_MS     100u

/* このbare-metalクライアントは永続ストレージ(ディスク等)を持たないため、
 * RFC4122準拠の乱数UUIDではなく固定のホストIDを使う -- targetはhostnqn/
 * subsysnqnの組み合わせで十分にホストを識別できるため、hostidの一意性は
 * 本実装の用途(単一ホストからの検証)では問題にならない。 */
static const uint8_t NVME_HOST_ID[16] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
};
#define NVME_HOST_NQN "nqn.2014-08.org.nvmexpress:uuid:a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf"

#define NVME_CNTLID_DYNAMIC 0xFFFFu  /* Fabrics Connect(admin queue): controller ID割り当てをtargetに任せる */

/* NVMe-oF Fabrics Connect コマンドのデータペイロード(1024バイト固定、
 * NVMe-oF仕様)。SQE自体には収まらず、nvme_tcp_send_cmd()のdata/dlenとして
 * 渡しin-capsule(Command Capsule PDUの固定部に続けて実データを送る)で
 * 転送する(nvme_types.hのNVME_SGL_TYPE_DATA_BLOCK_OFFSETコメント参照)。 */
typedef struct __attribute__((packed)) {
    uint8_t  hostid[16];
    uint16_t cntlid;
    uint8_t  reserved1[238];
    char     subsysnqn[256];
    char     hostnqn[256];
    uint8_t  reserved2[256];
} nvmf_connect_data_t;

/* volatile経由のバイト単位ゼロクリア -- 非volatileポインタへの逐次1
 * バイト代入だと、GCCが-O2でこれを1回のワイドストア(8/16バイト等)へ
 * 結合しうる(CLAUDE.md「ローカルスクラッチバッファへの逐次1バイト代入
 * も volatile が必須」節、timestamp.cで実機確認済みの既知パターン)。
 * このゼロクリアはpacked構造体(nvme_cqe_t等)のインスタンスにも使われ、
 * そのインスタンスは親構造体内で必ずしも4/8バイト境界に来ない
 * (実際にnvme_exec_ctx_t.cqe_outがoffset=106(非4アライン)に配置され
 * Alignment faultを起こした実例あり、上記nvme_exec_step()参照)ため、
 * ここも同じ理由でvolatileが必須。 */
static void nvme_zero(void *p, size_t len)
{
    volatile uint8_t *b = p;
    for (size_t i = 0; i < len; i++) b[i] = 0;
}

/* srcをdst(capacityバイト、NUL終端保証)へコピーする -- freestanding環境
 * (-nostdlib)のためstrncpy等の標準ライブラリ関数は使えない。 */
static void nvme_copy_str(char *dst, size_t capacity, const char *src)
{
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < capacity) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* 読み出しコマンド(C2HDataで応答)、およびデータを伴わないコマンド
 * (Set Features/Property Set/Get等)用のSGL。addrはメモリアドレスとして
 * 使われないため常に0 -- Linuxのnvme_tcp_set_sg_host_data()/
 * nvme_tcp_set_sg_null()と同じ規約。書き込みコマンド(データをこちらから
 * 送る)には使わないこと -- nvme_set_sgl_inline()を使う
 * (nvme_types.hのNVME_SGL_TYPE_TRANSPORT/NVME_SGL_TYPE_DATA_BLOCK_OFFSET
 * のコメント参照)。 */
static void nvme_set_sgl(nvme_sqe_t *sqe, uint32_t len)
{
    wr64le(&sqe->dptr[0], 0);
    wr32le(&sqe->dptr[8], len);
    sqe->dptr[12] = 0;
    sqe->dptr[13] = 0;
    sqe->dptr[14] = 0;
    sqe->dptr[15] = (uint8_t)NVME_SGL_TYPE_TRANSPORT;
}

/* 書き込みコマンド(Fabrics Connect含む、データをこちらからin-capsule
 * 送信する)用のSGL -- nvme_tcp_send_cmd()がこの型と整合する形で実際に
 * データをCommand Capsule PDUへ付加する(nvme_types.hのコメント参照)。 */
static void nvme_set_sgl_inline(nvme_sqe_t *sqe, uint32_t len)
{
    wr64le(&sqe->dptr[0], 0);
    wr32le(&sqe->dptr[8], len);
    sqe->dptr[12] = 0;
    sqe->dptr[13] = 0;
    sqe->dptr[14] = 0;
    sqe->dptr[15] = (uint8_t)NVME_SGL_TYPE_DATA_BLOCK_OFFSET;
}

/* sqeを送信し、応答(データ転送込み)を待つ共通ヘルパ。
 * 戻り値: nvme_tcp_recv_resp()の戻り値をそのまま返す
 *         (CQEステータスコード、0=success、通信エラー等は-1) */
static int nvme_exec(nvme_tcp_conn_t *conn, const nvme_sqe_t *sqe,
                     const void *send_data, uint32_t send_len,
                     void *recv_buf, uint32_t recv_buflen,
                     nvme_cqe_t *cqe_out, uint32_t timeout_ms)
{
    if (nvme_tcp_send_cmd(conn, sqe, send_data, send_len) != 0) {
        return -1;
    }
    return nvme_tcp_recv_resp(conn, cqe_out, recv_buf, recv_buflen, timeout_ms);
}

/* ================================================================
 * NVMe/TCP制御のジョブ化(nvme.h冒頭コメント参照)向けの共有低レベル
 * ステートマシン。nvme_exec()(上記、ブロッキング)と同じロジックを
 * 状態遷移へ展開したもの -- 送信はnvme_tcp_send_cmd()を、R2T応答送信は
 * nvme_tcp_send_h2c_data()をそのまま呼ぶ(複製ではなく共有)。
 * ================================================================ */
typedef enum {
    NVEXEC_ST_SEND = 0,
    NVEXEC_ST_RECV_HDR,
    NVEXEC_ST_RECV_CQE,
    NVEXEC_ST_RECV_C2H_REST,
    NVEXEC_ST_RECV_C2H_DATA,
    NVEXEC_ST_RECV_R2T_REST,
    NVEXEC_ST_SEND_H2C,
    NVEXEC_ST_DONE,
} nvme_exec_state_t;

/* stateprof.h向けの人間可読なステート名(nvme_exec_state_tと同じ並び順)。 */
static const char *const NVEXEC_STATE_NAMES[] = {
    "SEND", "RECV_HDR", "RECV_CQE", "RECV_C2H_REST",
    "RECV_C2H_DATA", "RECV_R2T_REST", "SEND_H2C", "DONE",
};
#define NVEXEC_STATE_NAME_COUNT (sizeof(NVEXEC_STATE_NAMES) / sizeof(NVEXEC_STATE_NAMES[0]))

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
    /* ec->profは意図的にリセットしない(nvme.hのnvme_exec_ctx_t.prof
     * コメント参照 -- 複数回のexec呼び出しにまたがって累積させる)。 */
}

int nvme_exec_step(nvme_exec_ctx_t *ec)
{
    /* stateprof.h -- このステートに何回・合計どれだけ滞在したかを記録
     * する(呼ばれるたびに毎回、switchより前で)。 */
    state_prof_mark(&ec->prof, ec->state);

    switch ((nvme_exec_state_t)ec->state) {

    case NVEXEC_ST_SEND:
        if (nvme_tcp_send_cmd(ec->conn, ec->sqe, ec->send_data, ec->send_len) != 0) {
            ec->result = -1;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        /* NSND: CapsuleCmd送信。in-capsuleか(R2T経由の)transportかは
         * nvme_tcp_send_cmd()(nvme_tcp.c)と同じ判定式(SGL descriptor
         * type、sqe->dptr[15]=sqe先頭からoffset39)をここでも使い、
         * 実際に送信されたhlen/pdo/plenを再現する。 */
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
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, NVME_CQE_LEN);
            ec->state = NVEXEC_ST_RECV_CQE;
        } else if (type == NVME_TCP_PDU_C2H_DATA) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, 16u);
            ec->state = NVEXEC_ST_RECV_C2H_REST;
        } else if (type == NVME_TCP_PDU_R2T) {
            nvme_tcp_xfer_reset(&ec->xfer, ec->rest_buf, 16u);
            ec->state = NVEXEC_ST_RECV_R2T_REST;
        } else {
            uart_printf("[!] NVMe/TCP: 未対応のPDU種別 (type=%u) 受信、応答待ちを中断\n", type);
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

        /* nvme_cqe_tはpacked構造体 -- net.h冒頭の規約通り、直接の多バイト
         * フィールドアクセス(読み書き両方)は禁止(親構造体nvme_exec_ctx_t
         * 内でのオフセットが4バイト境界に来る保証が無く、実際に実機で
         * その通りoffset=106(非4アライン)へ配置されコンパイラが生成した
         * stur w1,[x19,#106]がAlignment fault(esr=0x96000061)を起こした
         * -- ConnectXループバック検証中に発見)。wr32le/wr16le(書き込み)
         * ・rd32le/rd16le(読み出し)を必ず使うこと -- ローカル変数へ一度
         * 読んでから使う(cqe_out自体を後から読み返さない)。 */
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

        uint8_t  hlen = ec->hdr_buf[2];
        uint32_t plen = rd32le(&ec->hdr_buf[4]);
        ec->datao = rd32le(&ec->rest_buf[4]);
        ec->datal = rd32le(&ec->rest_buf[8]);

        uint32_t data_in_pdu = plen - hlen;
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

        uint8_t flags = ec->hdr_buf[1];
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
        if (flags & NVME_TCP_F_DATA_SUCCESS) {
            /* このC2HData自体が暗黙のcommand success応答を兼ねる --
             * 別途CapsuleRespは来ない(target側の最適化)。 */
            nvme_zero(&ec->cqe_out, sizeof(ec->cqe_out));
            wr16le(&ec->cqe_out.cid, ec->conn->pending_cid);
            ec->result = 0;
            ec->state = NVEXEC_ST_DONE;
            return 1;
        }
        /* DATA_LASTの有無に関わらずRECV_HDRへ戻り、続くC2HData
         * (LASTでなければ)、またはCapsuleResp(LASTなら)を待つ。 */
        nvme_tcp_xfer_reset(&ec->xfer, ec->hdr_buf, NVME_TCP_HDR_LEN);
        ec->state = NVEXEC_ST_RECV_HDR;
        return 0;
    }

    case NVEXEC_ST_RECV_R2T_REST: {
        int r = nvme_tcp_recv_poll(ec->conn, &ec->xfer);
        if (r < 0) { ec->result = -1; ec->state = NVEXEC_ST_DONE; return 1; }
        if (r == 0) return 0;

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

/* Fabrics Property Set(fctype=0x00): CC等の4バイトプロパティに書き込む
 * (attrib=0固定 -- 本実装が書くのはCCのみで8バイトプロパティは扱わない)。
 * cdw10=attrib, cdw11=offset, cdw12/13=value(下位/上位32bit)。 */
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

static int nvme_property_set(nvme_tcp_conn_t *conn, uint32_t offset, uint64_t value)
{
    nvme_sqe_t sqe;
    nvme_build_property_set_sqe(&sqe, offset, value);

    nvme_cqe_t cqe;
    return nvme_exec(conn, &sqe, NULL, 0, NULL, 0, &cqe, NVME_ADMIN_CMD_TIMEOUT_MS);
}

/* Fabrics Property Get(fctype=0x04): CC/CSTS等の4バイトプロパティを読む
 * (attrib=0固定)。値はCQEのdw0(nvmet側がresult.u64の下位32bitとして
 * 返す、nvme_types.hのnvmet_execute_prop_get()コメント参照)に入る。 */
static void nvme_build_property_get_sqe(nvme_sqe_t *sqe, uint32_t offset)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_FABRIC_CMD | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, NVME_FABRIC_FCTYPE_PROPERTY_GET);
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0u);  /* attrib=0: 4バイトプロパティ */
    wr32le(&sqe->cdw11, offset);
}

static int nvme_property_get(nvme_tcp_conn_t *conn, uint32_t offset, uint32_t *value_out)
{
    nvme_sqe_t sqe;
    nvme_build_property_get_sqe(&sqe, offset);

    /* nvme_cqe_tはpacked構造体(alignment=1) -- ローカル変数として置いても
     * コンパイラがスタック上で4バイト境界に配置する保証は無いため、
     * dw0の読み出しは必ずrd32le経由にする(net.h冒頭の規約、
     * nvme_exec_step()のコメント参照)。 */
    nvme_cqe_t cqe;
    int ret = nvme_exec(conn, &sqe, NULL, 0, NULL, 0, &cqe, NVME_ADMIN_CMD_TIMEOUT_MS);
    if (ret == 0 && value_out) {
        *value_out = rd32le(&cqe.dw0);
    }
    return ret;
}

/* admin queue(qid=0)へのFabrics Connect。成功するとctx->ctrlr_idに
 * targetが割り当てたController IDが入る(IO queue接続時にこれを使う)。
 * さらにController Configuration(CC)を有効化(EN=1)し、Controller
 * Status(CSTS)のRDYビットを待つ -- Fabrics Connect直後はCC.EN=0の
 * 状態でコントローラが生成され、Identify等の通常コマンドを一切受け
 * 付けない(nvme_types.hのNVME_REG_CC/NVME_CC_*コメント参照、実機の
 * nvmet-tcpとの相互接続検証で必須と判明した手順 -- 当初これを見落として
 * いた)。 */
/* Fabrics Connectコマンドのデータペイロード(nvmf_connect_data_t)を
 * 組み立てる(admin/IO両queueで共通)。 */
static void nvme_build_connect_data(nvmf_connect_data_t *data, uint16_t cntlid, const char *subnqn)
{
    nvme_zero(data, sizeof(*data));
    for (int i = 0; i < 16; i++) data->hostid[i] = NVME_HOST_ID[i];
    wr16le(&data->cntlid, cntlid);
    nvme_copy_str(data->subsysnqn, sizeof(data->subsysnqn), subnqn);
    nvme_copy_str(data->hostnqn, sizeof(data->hostnqn), NVME_HOST_NQN);
}

/* Fabrics Connect(fctype=0x01)のSQEを組み立てる(admin(qid=0)/IO(qid=1)
 * 共通、qidだけが違う)。katoはadmin/IOいずれも0(Keep Alive未実装のため
 * 要求しない/IO queueでは予約)。 */
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

static int nvme_connect_admin_queue(nvme_ctx_t *ctx, uint32_t ip, uint16_t port)
{
    if (nvme_tcp_connect(&ctx->admin, ip, port) != 0) {
        uart_printf("[!] nvme: admin queueのTCP/ICReq確立失敗\n");
        return -1;
    }

    static nvmf_connect_data_t s_connect_data __attribute__((aligned(64)));
    nvme_build_connect_data(&s_connect_data, (uint16_t)NVME_CNTLID_DYNAMIC, ctx->subnqn);

    nvme_sqe_t sqe;
    nvme_build_fabrics_connect_sqe(&sqe, 0u, sizeof(s_connect_data));

    nvme_cqe_t cqe;
    int ret = nvme_exec(&ctx->admin, &sqe, &s_connect_data, sizeof(s_connect_data),
                        NULL, 0, &cqe, NVME_ADMIN_CMD_TIMEOUT_MS);
    if (ret != 0) {
        uart_printf("[!] nvme: admin queue Fabrics Connect失敗 (status=0x%x)\n", ret);
        nvme_tcp_close(&ctx->admin);
        return -1;
    }

    ctx->ctrlr_id = (uint16_t)(rd32le(&cqe.dw0) & 0xFFFFu);
    uart_printf("[nvme] admin queue接続完了 (controller id=%u)\n", ctx->ctrlr_id);

    /* コントローラ有効化(CC.EN=1)。IOSQES/IOCQESを規定値(64B/16B)に
     * しないとtarget側がCSTS.CFSへ落ちる(nvme_types.hのNVME_CC_*
     * コメント参照)。 */
    uint32_t cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_AMS_RR | NVME_CC_SHN_NONE |
                  NVME_CC_IOSQES | NVME_CC_IOCQES;
    if (nvme_property_set(&ctx->admin, NVME_REG_CC, cc) != 0) {
        uart_printf("[!] nvme: CC(Controller Configuration)有効化失敗\n");
        nvme_tcp_close(&ctx->admin);
        return -1;
    }

    for (unsigned i = 0; i < NVME_CTRL_READY_POLL_MAX; i++) {
        uint32_t csts;
        if (nvme_property_get(&ctx->admin, NVME_REG_CSTS, &csts) != 0) {
            uart_printf("[!] nvme: CSTS読み出し失敗\n");
            nvme_tcp_close(&ctx->admin);
            return -1;
        }
        if (csts & NVME_CSTS_CFS) {
            uart_printf("[!] nvme: CSTS.CFS(Controller Fatal Status)が立った "
                        "(CC値の不整合、nvme_types.hのNVME_CC_*コメント参照)\n");
            nvme_tcp_close(&ctx->admin);
            return -1;
        }
        if (csts & NVME_CSTS_RDY) {
            uart_printf("[nvme] コントローラ有効化完了 (CSTS.RDY=1)\n");
            return 0;
        }
        timer_delay_ms(NVME_CTRL_READY_POLL_MS);
    }

    uart_printf("[!] nvme: CSTS.RDY待ちタイムアウト\n");
    nvme_tcp_close(&ctx->admin);
    return -1;
}

/* IO queue(qid=1)へのFabrics Connect -- 別TCPコネクション、cntlidは
 * admin queue接続時に割り当てられたctx->ctrlr_idを使う(既存controllerの
 * 2本目のqueueとして接続するため、NVME_CNTLID_DYNAMICは使わない)。 */
static int nvme_connect_io_queue(nvme_ctx_t *ctx, uint32_t ip, uint16_t port)
{
    if (nvme_tcp_connect(&ctx->io, ip, port) != 0) {
        uart_printf("[!] nvme: IO queueのTCP/ICReq確立失敗\n");
        return -1;
    }

    static nvmf_connect_data_t s_io_connect_data __attribute__((aligned(64)));
    nvme_build_connect_data(&s_io_connect_data, ctx->ctrlr_id, ctx->subnqn);

    nvme_sqe_t sqe;
    nvme_build_fabrics_connect_sqe(&sqe, 1u, sizeof(s_io_connect_data));

    nvme_cqe_t cqe;
    int ret = nvme_exec(&ctx->io, &sqe, &s_io_connect_data, sizeof(s_io_connect_data),
                        NULL, 0, &cqe, NVME_ADMIN_CMD_TIMEOUT_MS);
    if (ret != 0) {
        uart_printf("[!] nvme: IO queue Fabrics Connect失敗 (status=0x%x)\n", ret);
        nvme_tcp_close(&ctx->io);
        return -1;
    }

    ctx->io_connected = 1;
    uart_printf("[nvme] IO queue接続完了 (qid=1)\n");
    return 0;
}

void nvme_build_identify_sqe(nvme_sqe_t *sqe, uint8_t cns, uint32_t nsid)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_ADM_CMD_IDENTIFY | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    nvme_set_sgl(sqe, 4096u);
    wr32le(&sqe->cdw10, (uint32_t)cns);  /* CNS: bits[7:0]、残りは予約 */
}

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

static int nvme_identify_common(nvme_tcp_conn_t *conn, uint8_t cns, uint32_t nsid, void *buf4096)
{
    nvme_sqe_t sqe;
    nvme_build_identify_sqe(&sqe, cns, nsid);

    nvme_cqe_t cqe;
    return nvme_exec(conn, &sqe, NULL, 0, buf4096, 4096u, &cqe, NVME_ADMIN_CMD_TIMEOUT_MS);
}

int nvme_identify_ctrl(nvme_ctx_t *ctx, void *buf4096)
{
    return nvme_identify_common(&ctx->admin, (uint8_t)NVME_IDENTIFY_CNS_CONTROLLER, 0, buf4096);
}

int nvme_identify_ns(nvme_ctx_t *ctx, uint32_t nsid, void *buf4096)
{
    int ret = nvme_identify_common(&ctx->admin, (uint8_t)NVME_IDENTIFY_CNS_NAMESPACE, nsid, buf4096);
    if (ret == 0) {
        nvme_update_lba_size_from_id_ns(ctx, nsid, buf4096);
    }
    return ret;
}

static void nvme_build_set_features_num_queues_sqe(nvme_sqe_t *sqe)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_ADM_CMD_SET_FEATURES | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    nvme_set_sgl(sqe, 0);
    wr32le(&sqe->cdw10, 0x07u);        /* FID=7: Number of Queues */
    wr32le(&sqe->cdw11, 0x00010001u);  /* NSQR=1, NCQR=1 (IO SQ/CQ各1本を要求) */
}

static int nvme_set_features_num_queues(nvme_ctx_t *ctx)
{
    nvme_sqe_t sqe;
    nvme_build_set_features_num_queues_sqe(&sqe);

    nvme_cqe_t cqe;
    return nvme_exec(&ctx->admin, &sqe, NULL, 0, NULL, 0, &cqe, NVME_ADMIN_CMD_TIMEOUT_MS);
}

int nvme_connect(nvme_ctx_t *ctx, uint32_t ip, uint16_t port, const char *subnqn)
{
    ctx->io_connected = 0;
    ctx->ctrlr_id     = NVME_CNTLID_DYNAMIC;
    ctx->lba_size     = 512u;  /* nvme_identify_ns()が上書きするまでの暫定値 */
    nvme_copy_str(ctx->subnqn, sizeof(ctx->subnqn), subnqn);

    if (nvme_connect_admin_queue(ctx, ip, port) != 0) {
        return -1;
    }

    static uint8_t s_id_buf[4096] __attribute__((aligned(64)));

    if (nvme_identify_ctrl(ctx, s_id_buf) != 0) {
        uart_printf("[!] nvme: Identify Controller失敗\n");
        nvme_tcp_close(&ctx->admin);
        return -1;
    }

    if (nvme_identify_ns(ctx, 1u, s_id_buf) != 0) {
        uart_printf("[!] nvme: Identify Namespace(nsid=1)失敗\n");
        nvme_tcp_close(&ctx->admin);
        return -1;
    }

    if (nvme_set_features_num_queues(ctx) != 0) {
        uart_printf("[!] nvme: Set Features(Number of Queues)失敗\n");
        nvme_tcp_close(&ctx->admin);
        return -1;
    }

    if (nvme_connect_io_queue(ctx, ip, port) != 0) {
        nvme_tcp_close(&ctx->admin);
        return -1;
    }

    uart_printf("[nvme] 接続完了 (subnqn=%s)\n", ctx->subnqn);
    return 0;
}

/* ================================================================
 * connect job(nvme.h冒頭コメント参照)。admin queue確立(TCP+ICReq/
 * ICResp+Fabrics Connect+CC有効化+CSTS.RDY待ち+Identify Controller/
 * Namespace+Set Features)→IO queue確立(TCP+ICReq/ICResp+Fabrics
 * Connect)という上記nvme_connect()と同じシーケンスを状態遷移へ展開
 * したもの。個々のFabrics/Property/Identify/Set Featuresコマンドは
 * 全てnvme_exec_begin()+nvme_exec_step()(共有ステートマシン、上記)
 * 経由で実行する -- ロジックは上記のブロッキング関数群
 * (nvme_connect_admin_queue()等)から複製せず、SQE組み立てヘルパ
 * (nvme_build_*_sqe())を両方から共有する。
 * ================================================================ */
typedef enum {
    NCONN_ST_TCP_ADMIN_BEGIN = 0,
    NCONN_ST_TCP_ADMIN_WAIT,
    NCONN_ST_ICRESP_ADMIN_RECV,
    NCONN_ST_EXEC_FABRIC_CONNECT_ADMIN,
    NCONN_ST_EXEC_PROPSET_CC,
    NCONN_ST_CSTS_POLL_WAIT,
    NCONN_ST_CSTS_POLL_EXEC,
    NCONN_ST_EXEC_IDENTIFY_CTRL,
    NCONN_ST_EXEC_IDENTIFY_NS,
    NCONN_ST_EXEC_SET_FEATURES,
    NCONN_ST_TCP_IO_WAIT,
    NCONN_ST_ICRESP_IO_RECV,
    NCONN_ST_EXEC_FABRIC_CONNECT_IO,
} nvme_connect_state_t;

/* stateprof.h向けの人間可読なステート名(nvme_connect_state_tと同じ
 * 並び順)。 */
static const char *const NCONN_STATE_NAMES[] = {
    "TCP_ADMIN_BEGIN", "TCP_ADMIN_WAIT", "ICRESP_ADMIN_RECV",
    "EXEC_FABRIC_CONNECT_ADMIN", "EXEC_PROPSET_CC", "CSTS_POLL_WAIT",
    "CSTS_POLL_EXEC", "EXEC_IDENTIFY_CTRL", "EXEC_IDENTIFY_NS",
    "EXEC_SET_FEATURES", "TCP_IO_WAIT", "ICRESP_IO_RECV",
    "EXEC_FABRIC_CONNECT_IO",
};
#define NCONN_STATE_NAME_COUNT (sizeof(NCONN_STATE_NAMES) / sizeof(NCONN_STATE_NAMES[0]))

typedef struct {
    nvme_ctx_t         *ctx;
    uint32_t             ip;
    uint16_t              port;
    net_ctx_t            *src_ctx;  /* spawn時点のg_active_ctx、下記コメント参照 */
    uint64_t              wait_started_ticks;  /* 直近の待ち(ICResp受信/CSTS.RDYポーリング)を
                                                 * 開始した時刻 -- timeout_ms()で判定する */
    nvme_tcp_xfer_t       xfer;
    uint8_t               icresp_buf[NVME_TCP_ICRESP_LEN];
    nvmf_connect_data_t   connect_data;
    nvme_sqe_t            sqe;
    nvme_exec_ctx_t       exec;
    uint32_t              csts_poll_count;
    uint8_t               id_buf[4096] __attribute__((aligned(64)));

    /* NCONN_ST_*(接続シーケンス全体)の各ステート滞在時間プロファイラ
     * (stateprof.h)。execサブステートマシン自身の統計はexec.profに
     * 別途記録される(nvme_exec_step()参照)。 */
    state_prof_t          prof;
} nvme_connect_job_ctx_t;

static nvme_connect_job_ctx_t s_nvme_connect_job_ctx;

/* close_admin/close_io: 失敗した時点でそれぞれのTCP接続が既に
 * ESTABLISHEDに達していた(=tcp_close()が必要)ならtrue -- 上記
 * nvme_connect()/nvme_connect_admin_queue()/nvme_connect_io_queue()の
 * 各失敗分岐が呼ぶtcp_close()呼び出しの有無と同じ判断をジョブ側でも
 * 再現する(tcp_connect_poll()自身がTCP接続確立前の失敗では既に
 * 内部でs_conns[]を解放済みのため、その場合は追加のcloseは不要
 * かつ有害ではないが、元のコードの挙動に忠実に合わせる)。 */
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

static job_result_t nvme_connect_job_step(job_t *self)
{
    nvme_connect_job_ctx_t *jc  = (nvme_connect_job_ctx_t *)self->ctx;
    nvme_ctx_t              *ctx = jc->ctx;

    /* stateprof.h -- このステートに何回・合計どれだけ滞在したかを記録
     * する(呼ばれるたびに毎回、switchより前で)。 */
    state_prof_mark(&jc->prof, self->state);

    /* `job stop <番号>`(job_request_cancel())対応。以前はこのジョブが
     * cancel_requestedを一切見ておらず、`job stop`しても何も起きない
     * (JOB_WAITINGを返し続け、ctx->busyもクリアされないまま)ため、
     * スタックしたnvme connectを止める手段がreboot以外に無かった。
     * 状態(self->state)がどこまで進んでいたかで、admin/io接続それぞれが
     * 実際に確立済み(close対象)かを判定する -- 各状態が対応するTCP
     * 接続待ち(NCONN_ST_TCP_ADMIN_WAIT/NCONN_ST_TCP_IO_WAIT)を通過した
     * 後でなければ、その接続はまだ確立していない(nvme_connect_job_fail()
     * の既存の呼び出しパターン、close_admin/close_ioの使い分けと同じ
     * 判断基準)。 */
    if (self->cancel_requested) {
        int admin_open = (self->state > NCONN_ST_TCP_ADMIN_WAIT);
        int io_open    = (self->state > NCONN_ST_TCP_IO_WAIT);
        return nvme_connect_job_fail(jc, admin_open, io_open, "job stopでキャンセル");
    }

    switch ((nvme_connect_state_t)self->state) {

    case NCONN_ST_TCP_ADMIN_BEGIN:
        if (jc->src_ctx) net_ctx_activate(jc->src_ctx);
        tcp_connect_begin(&ctx->admin.tcp, jc->ip, jc->port);
        self->state = NCONN_ST_TCP_ADMIN_WAIT;
        return JOB_WAITING;

    case NCONN_ST_TCP_ADMIN_WAIT: {
        int r = tcp_connect_poll(&ctx->admin.tcp);
        if (r < 0) return nvme_connect_job_fail(jc, 0, 0, "admin TCP接続失敗");
        if (r == 0) return JOB_WAITING;
        if (nvme_tcp_send_icreq(&ctx->admin) != 0) {
            return nvme_connect_job_fail(jc, 1, 0, "admin ICReq送信失敗");
        }
        /* NSND: ICReq送信(admin queue)。nvme_tcp_send_icreq()(nvme_tcp.c)は
         * 常に固定128バイト・pdo=0で送るため、実際に送信した値をここで
         * そのまま渡せる。 */
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

        /* コントローラ有効化(CC.EN=1)。IOSQES/IOCQESを規定値(64B/16B)に
         * しないとtarget側がCSTS.CFSへ落ちる(nvme_types.hのNVME_CC_*
         * コメント参照)。 */
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
        nvme_build_identify_sqe(&jc->sqe, (uint8_t)NVME_IDENTIFY_CNS_NAMESPACE, 1u);
        nvme_exec_begin(&jc->exec, &ctx->admin, &jc->sqe, NULL, 0, jc->id_buf, sizeof(jc->id_buf));
        self->state = NCONN_ST_EXEC_IDENTIFY_NS;
        return JOB_WAITING;
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
        if (jc->src_ctx) net_ctx_activate(jc->src_ctx);
        tcp_connect_begin(&ctx->io.tcp, jc->ip, jc->port);
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

int nvme_connect_job_start(nvme_ctx_t *ctx, uint32_t ip, uint16_t port, const char *subnqn)
{
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    /* 【実機で発見・修正】ctx->io_connectedのチェックが無いと、既に接続
     * 済み(admin/io両queueがESTABLISHED)の状態でもう一度nvme connectを
     * 呼べてしまい、tcp_connect_begin(&ctx->admin.tcp, ...)がESTABLISHED
     * だったconn(ctx->admin.tcp、s_nvme_ctxの一部)を無条件に上書きして
     * しまう(tcp_connect_begin()自身は「未使用のconnに新規接続を張る」
     * 前提で、既存の生きた接続かどうかを一切確認しない設計)。この2回目の
     * 接続試行自体が失敗(ARP解決失敗等)すると、nvme_connect_job_fail()の
     * close_admin判定は「まだ接続していない」ものとして処理するため
     * admin.tcpは一切closeされず、ESTABLISHED/CLOSE_WAITのどちらでも
     * ない中途半端な状態のまま取り残される。この状態でnvme disconnect
     * (tcp_close())を呼んでも、conn->stateがESTABLISHED/CLOSE_WAITの
     * どちらでもないため`if`にヒットせずFINが一切送信されない
     * ("nvme: 切断完了"とだけ表示されるが実際には何もclose
     * していない)。サーバ側(nvmet)はFINを受け取れないので、前のセッション
     * のまま(`jobs`のstateが固まって見える)取り残される -- という連鎖的
     * な実害が実機で確認された。既に接続済みの状態で誤ってnvme connectを
     * 呼んだ場合はここで即座に拒否し、`nvme disconnect`を先に呼ぶよう
     * 促す(既存のctx->busyガードと同じスタイル)。 */
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
    ctx->busy = 1;

    state_prof_reset(&s_nvme_connect_job_ctx.prof);
    state_prof_reset(&s_nvme_connect_job_ctx.exec.prof);

    s_nvme_connect_job_ctx.ctx     = ctx;
    s_nvme_connect_job_ctx.ip      = ip;
    s_nvme_connect_job_ctx.port    = port;
    /* 送信元インターフェース(`net use`で選んだもの)をこの時点(コマンド
     * 自身のdispatch()内、同期的)のg_active_ctxとして固定する。
     * tcp_connect_begin()はNET_SELF_IP(=g_active_ctx由来)を読むが、この
     * ジョブは複数tickにまたがって進行するため、admin/nvmet等の他ジョブの
     * ポーリング・telnetの出力flush等がその間にg_active_ctxを一時的に
     * 別インターフェースへ切り替えることがある(net_poll_all_and_
     * dispatch()自身は呼び出し前の状態へ復元するが、tcp_send_segment()は
     * 自分のconnのインターフェースへ切り替えたまま戻る設計のため、複数
     * インターフェースが同時に活動していると、あるtickの終わりに
     * g_active_ctxが「たまたま最後に何かを送信したインターフェース」に
     * なる -- 実機でConnectX PF0<->PF1ループバック環境において、`net use
     * mlx5-pf0`の直後に新しいtelnet接続を張り直すと、その接続受理処理の
     * 過程でg_active_ctxがRP1へ固定されてしまい、`nvme connect`が誤って
     * RP1からSYN/ARPを送出する事象を確認した)。呼び出し直後(まだ他の
     * ジョブが割り込む前)に固定しておけば、以降の各tick開始時に明示的に
     * 再アクティブ化するだけで、このレースの影響を受けなくなる。 */
    s_nvme_connect_job_ctx.src_ctx = g_active_ctx;

    job_t *connect_job = job_spawn(nvme_connect_job_step, &s_nvme_connect_job_ctx, "nvme-connect");
    if (!connect_job) {
        uart_printf("[!] nvme: ジョブ生成失敗\n");
        ctx->busy = 0;
        return -1;
    }
    /* このジョブが実際に送受信を発行するインターフェース(src_ctx、上記
     * コメント参照)へaffinity_key(job.h参照)を紐付ける -- src_ctx->
     * owner_coreと異なるコアでこのジョブがclaimされる(=NICへ直接
     * アクセスする)ことをjob.cの共有スケジューラレベルで防ぐ
     * (マルチコア化 Phase 4-6準備、~/.claude/plans/wondrous-baking-
     * gadget.md参照)。 */
    job_set_affinity(connect_job, s_nvme_connect_job_ctx.src_ctx);
    return 0;
}

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

void nvme_build_write_sqe(nvme_sqe_t *sqe, uint32_t nsid, uint64_t slba, uint32_t nlb, uint32_t total_len)
{
    nvme_zero(sqe, sizeof(*sqe));
    wr32le(&sqe->cdw0, NVME_IO_CMD_WRITE | ((uint32_t)NVME_PSDT_SGL_MPTR_CONTIGUOUS << 8));
    wr32le(&sqe->nsid, nsid);
    /* NVME_TCP_INLINE_DATA_MAX(8KiB)以下ならin-capsule、超えるならSGL
     * typeをTRANSPORTにしてR2T+H2CData経由の分割送信にする(2026-08-08、
     * R2T分割実装)。SQE自身にどちらの型で送るかを持たせることで、
     * nvme_tcp_send_cmd()がSGL type(sqe->dptr[15])を見るだけでin-capsule
     * データを実際に付加すべきか、それとも一切送らずpending_dataへ保留
     * するだけにすべきかを判定できる -- 以前デッドロックを踏んだ
     * (nvme_types.hのNVME_SGL_TYPE_TRANSPORTコメント参照)「型と実際の
     * データ送信有無がずれる」設計を構造的に避けるための方針。 */
    if (total_len > NVME_TCP_INLINE_DATA_MAX) {
        nvme_set_sgl(sqe, total_len);
    } else {
        nvme_set_sgl_inline(sqe, total_len);
    }
    wr32le(&sqe->cdw10, (uint32_t)(slba & 0xFFFFFFFFu));
    wr32le(&sqe->cdw11, (uint32_t)(slba >> 32));
    wr32le(&sqe->cdw12, (uint32_t)(nlb - 1) & 0xFFFFu);
}

int nvme_read(nvme_ctx_t *ctx, uint32_t nsid, uint64_t slba, void *buf, uint32_t nlb)
{
    if (!ctx->io_connected) {
        uart_printf("[!] nvme_read: IO queue未接続\n");
        return -1;
    }
    if (nlb == 0) {
        return 0;
    }
    uint32_t total_len = nlb * ctx->lba_size;

    nvme_sqe_t sqe;
    nvme_build_read_sqe(&sqe, nsid, slba, nlb, total_len);

    nvme_cqe_t cqe;
    return nvme_exec(&ctx->io, &sqe, NULL, 0, buf, total_len, &cqe, NVME_IO_CMD_TIMEOUT_MS);
}

int nvme_write(nvme_ctx_t *ctx, uint32_t nsid, uint64_t slba, const void *buf, uint32_t nlb)
{
    if (!ctx->io_connected) {
        uart_printf("[!] nvme_write: IO queue未接続\n");
        return -1;
    }
    if (nlb == 0) {
        return 0;
    }
    uint32_t total_len = nlb * ctx->lba_size;

    nvme_sqe_t sqe;
    nvme_build_write_sqe(&sqe, nsid, slba, nlb, total_len);

    nvme_cqe_t cqe;
    return nvme_exec(&ctx->io, &sqe, buf, total_len, NULL, 0, &cqe, NVME_IO_CMD_TIMEOUT_MS);
}

void nvme_disconnect(nvme_ctx_t *ctx)
{
    if (ctx->io_connected) {
        nvme_tcp_close(&ctx->io);
        ctx->io_connected = 0;
    }
    nvme_tcp_close(&ctx->admin);
}

/* ================================================================
 * nvme_write_begin()/nvme_read_begin()/nvme_identify_ctrl_begin()/
 * nvme_identify_ns_begin() -- 非ブロッキング「開始」API群(job.h基盤)。
 *
 * SQE組み立て(nvme_build_*_sqe())は全てこのファイル内で完結させる --
 * 呼び出し元(command.c/test.c等)がnvme_sqe_tやCNS定数等のNVMeプロトコル
 * の詳細を直接扱うことはない。呼び出し元は「どのqueueを使うか
 * (admin/io)」「送信/受信バッファ」を意識する必要すら無く、意味のある
 * 引数(nsid/lba/buf/nlb等)だけを渡す。
 *
 * 全て同じ下位ヘルパnvme_io_begin()を共有する -- ctx->busyの管理
 * (nvme_connect_job_start()と同じ規約: 開始時に1、完了時に0)も含めて
 * ここに一本化することで、呼び出し元ごとの重複/実装漏れ(busyチェック
 * 忘れ等)を防ぐ。 */

static nvme_ctx_t     *s_io_job_ctx;
static nvme_sqe_t      s_io_job_sqe __attribute__((aligned(64)));
static nvme_exec_ctx_t s_io_job_exec;
static volatile int    s_io_job_done = 0;

static job_result_t nvme_io_job_step(job_t *self)
{
    (void)self;
    if (!nvme_exec_step(&s_io_job_exec)) {
        return JOB_WAITING;
    }
    s_io_job_done = 1;
    if (s_io_job_ctx) {
        s_io_job_ctx->busy = 0;
    }
    return JOB_DONE;
}

/* s_io_job_sqeが呼び出し元(各begin関数)によって既に組み立て済みである
 * ことを前提に、exec開始+job_spawn()を行う共通部分。 */
static int nvme_io_begin(nvme_ctx_t *ctx, nvme_tcp_conn_t *conn,
                          const void *send_data, uint32_t send_len,
                          void *recv_buf, uint32_t recv_buflen,
                          const char *job_name)
{
    if (ctx->busy) {
        uart_printf("[!] nvme: 前回の操作がまだ実行中です\n");
        return -1;
    }
    nvme_exec_begin(&s_io_job_exec, conn, &s_io_job_sqe, send_data, send_len, recv_buf, recv_buflen);
    s_io_job_done = 0;
    s_io_job_ctx  = ctx;
    ctx->busy = 1;
    if (!job_spawn(nvme_io_job_step, NULL, job_name)) {
        uart_printf("[!] nvme: ジョブ生成失敗\n");
        ctx->busy = 0;
        return -1;
    }
    return 0;
}

int nvme_write_begin(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba, const void *buf, uint32_t nlb)
{
    if (!ctx->io_connected) {
        uart_printf("[!] nvme: IO queue未接続\n");
        return -1;
    }
    uint32_t total_len = nlb * ctx->lba_size;
    nvme_build_write_sqe(&s_io_job_sqe, nsid, lba, nlb, total_len);
    return nvme_io_begin(ctx, &ctx->io, buf, total_len, NULL, 0, "nvme-write");
}

int nvme_read_begin(nvme_ctx_t *ctx, uint32_t nsid, uint64_t lba, void *buf, uint32_t nlb)
{
    if (!ctx->io_connected) {
        uart_printf("[!] nvme: IO queue未接続\n");
        return -1;
    }
    uint32_t total_len = nlb * ctx->lba_size;
    nvme_build_read_sqe(&s_io_job_sqe, nsid, lba, nlb, total_len);
    return nvme_io_begin(ctx, &ctx->io, NULL, 0, buf, total_len, "nvme-read");
}

int nvme_identify_ctrl_begin(nvme_ctx_t *ctx, void *buf4096)
{
    nvme_build_identify_sqe(&s_io_job_sqe, (uint8_t)NVME_IDENTIFY_CNS_CONTROLLER, 0);
    return nvme_io_begin(ctx, &ctx->admin, NULL, 0, buf4096, 4096u, "nvme-identify");
}

int nvme_identify_ns_begin(nvme_ctx_t *ctx, uint32_t nsid, void *buf4096)
{
    nvme_build_identify_sqe(&s_io_job_sqe, (uint8_t)NVME_IDENTIFY_CNS_NAMESPACE, nsid);
    return nvme_io_begin(ctx, &ctx->admin, NULL, 0, buf4096, 4096u, "nvme-identify");
}

int nvme_io_job_done(void)
{
    return s_io_job_done;
}

int nvme_io_job_result(void)
{
    return s_io_job_exec.result;
}

/* ================================================================
 * ステート滞在時間プロファイラ(nvme.hコメント参照)へのアクセサ実装。
 * ================================================================ */

void nvme_connect_prof_reset(void)
{
    state_prof_reset(&s_nvme_connect_job_ctx.prof);
    state_prof_reset(&s_nvme_connect_job_ctx.exec.prof);
}

void nvme_connect_prof_dump(void)
{
    state_prof_dump(&s_nvme_connect_job_ctx.prof, NCONN_STATE_NAMES,
                     (unsigned)NCONN_STATE_NAME_COUNT, "nvme-connect");
    state_prof_dump(&s_nvme_connect_job_ctx.exec.prof, NVEXEC_STATE_NAMES,
                     (unsigned)NVEXEC_STATE_NAME_COUNT, "nvme-connect/exec");
}

void nvme_io_exec_prof_reset(void)
{
    state_prof_reset(&s_io_job_exec.prof);
}

void nvme_io_exec_prof_dump(void)
{
    state_prof_dump(&s_io_job_exec.prof, NVEXEC_STATE_NAMES,
                     (unsigned)NVEXEC_STATE_NAME_COUNT, "nvme-io/exec");
}

/* ================================================================
 * NVMe/TCPコマンドパイプライン化(nvme.hのNVME_IO_QDEPTH/
 * nvme_write_pipelined_run()コメント参照)。
 * ================================================================ */

typedef struct {
    int        in_use;   /* このスロットが現在1件のwriteを担当中か */
    int        sent;     /* SQEを送信済みか(R2T/RSP待ちの間だけ1) */
    int        done;     /* 完了(結果確定)したか -- in_useのままresultを取り出す猶予を与える */
    int        result;   /* 完了時のCQEステータス(0=success)、通信エラー等は-1 */
    uint16_t   cid;       /* nvme_tcp_send_cmd_async()が採番したcid(out引数で直接受け取る、
                           * 2026-08-09、tcp_send_async()化に伴いconn->pending_cid経由から変更) */
    nvme_sqe_t sqe;
    const void *data;     /* このwriteが送るデータ(呼び出し元所有、複数スロットが同じ
                           * バッファを読み取り専用で共有してもよい) */
    uint32_t   len;
} nvme_pipeline_slot_t;

static nvme_pipeline_slot_t s_pl_slots[NVME_IO_QDEPTH];

/* 共有PDU受信ディスパッチャの状態 -- IO queue接続は1本のTCPストリーム
 * なので、複数スロットの応答(Response/R2T)は必ず順番に1つずつ届く。
 * ここでヘッダを読んでtype判定→本体を読んでcid/cccidでスロットへ
 * ルーティング、を繰り返す(nvme_exec_step()のRECV_HDR/RECV_CQE/
 * RECV_R2T_RESTと同じパターンだが、単一ecではなく複数スロットへ
 * ルーティングする点が異なる)。 */
typedef enum {
    PL_RX_HDR = 0,
    PL_RX_RSP_REST,
    PL_RX_R2T_REST,
} nvme_pipeline_rx_state_t;

static nvme_pipeline_rx_state_t s_pl_rx_state;
static nvme_tcp_xfer_t          s_pl_xfer;
static uint8_t                  s_pl_hdr_buf[NVME_TCP_HDR_LEN];
static uint8_t                  s_pl_rest_buf[16];

/* 送信済み(sent)かつ未完了(!done)のスロットからcidが一致するものを
 * 探す。C2HData(読み出し応答)はこのパイプラインが扱うwrite専用の
 * 用途では届かない想定のため対応しない(PL_RX_HDRのdefault分岐で
 * ログのみ出して読み捨てる、下記参照)。 */
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

/* H2CData送信をパイプライン化するためのFIFOキュー(2026-08-09、ユーザー
 * 指示)。詳細な設計根拠はnvme_pipeline_h2c_pump()直前のコメント参照 --
 * ここでは前方参照を避けるため、nvme_pipeline_rx_tick()より先に
 * 宣言・定義する(rx_tick()のPL_RX_R2T_RESTケースがnvme_h2c_pending_push()
 * を呼ぶため)。 */
typedef struct {
    int      valid;
    int      slot;
    uint16_t cid;   /* 2026-08-10、実機で発見した本物のバグの修正
                      * (下記nvme_pipeline_h2c_pump()コメント参照) --
                      * 以前はslotだけを保持し、取り出す時点でs_pl_slots
                      * [slot].cidを再読み込みしていたため、そのslotが
                      * 取り出し前に別の新しいwriteへ再利用されると
                      * (新しいcidに上書きされる)、古いpendingエントリが
                      * 誤って新しいcidとして処理されてしまう実機バグ
                      * (cid欠落+別cidの重複処理)を引き起こしていた。
                      * push時点でcidをこの構造体自身に確定・保持する
                      * ことで、以後slotが再利用されても影響を受けない。 */
    uint16_t ttag;
    uint32_t r2to;
    uint32_t r2tl;
} nvme_h2c_pending_t;

#define NVME_H2C_PENDING_MAX NVME_IO_QDEPTH
static nvme_h2c_pending_t s_h2c_pending[NVME_H2C_PENDING_MAX];
static unsigned s_h2c_pending_head;
static unsigned s_h2c_pending_count;

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

/* 到着済みのPDUを1ステップぶんだけ非ブロッキングで処理する
 * (nvme_tcp_recv_poll()自体が「1回だけ試す」非ブロッキング設計、
 * nvme_tcp.hコメント参照)。呼び出し元(nvme_write_pipelined_run())の
 * メインループから毎tick呼ばれる。 */
static void nvme_pipeline_rx_tick(nvme_ctx_t *ctx)
{
    int r = nvme_tcp_recv_poll(&ctx->io, &s_pl_xfer);
    if (r < 0) {
        /* コネクションレベルの失敗(FIN/エラー) -- 送信済み・未完了の
         * 全スロットを失敗として確定させる(これ以上応答は来ない)。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use && s_pl_slots[i].sent && !s_pl_slots[i].done) {
                s_pl_slots[i].done   = 1;
                s_pl_slots[i].result = -1;
            }
        }
        return;
    }
    if (r == 0) {
        return;  /* このPDUの受信途中、次tickへ */
    }

    /* 計装専用(一時追加、原因特定後に削除すること) -- 状態遷移が
     * 完了するたび(r==1で switch へ入る直前)に、現在の状態・
     * ctx->io.tcp.rcv_seq(このPDU分を消費した直後の受信バイト
     * ストリーム位置)・xferのgot/wantを記録する。nvmet_tcp.cの
     * RSSQ(R2T送信時のsnd_seq)と突き合わせれば、TCP層でのバイト位置と
     * アプリ層のPDU処理タイミングを直接対応付けられる。argは
     * (state<<28)|(rcv_seq&0x0FFFFFFF)。 */
    ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 0),
           ((uint32_t)s_pl_rx_state << 28) | (ctx->io.tcp.rcv_seq & 0x0FFFFFFFu));

    switch (s_pl_rx_state) {
    case PL_RX_HDR: {
        uint8_t type = s_pl_hdr_buf[0];
        /* 計装専用(一時追加、原因特定後に削除すること) -- 読み取った
         * 8バイトヘッダの生の型バイト+hlen/pdo+plenを丸ごと記録する。
         * argの上位8bit=type、次の8bit=hlen、下位16bit=plen下位16bit。 */
        ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_rx_tick, 1),
               ((uint32_t)type << 24) | ((uint32_t)s_pl_hdr_buf[2] << 16) |
               ((uint32_t)rd32le(&s_pl_hdr_buf[4]) & 0xFFFFu));
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_rest_buf, NVME_CQE_LEN);
            s_pl_rx_state = PL_RX_RSP_REST;
        } else if (type == NVME_TCP_PDU_R2T) {
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_rest_buf, 16u);
            s_pl_rx_state = PL_RX_R2T_REST;
        } else {
            uart_printf("[!] nvme pipeline: 未対応のPDU種別 (type=%u)、読み捨てて再同期を試みます\n", type);
            nvme_tcp_xfer_reset(&s_pl_xfer, s_pl_hdr_buf, NVME_TCP_HDR_LEN);
            s_pl_rx_state = PL_RX_HDR;
        }
        break;
    }

    case PL_RX_RSP_REST: {
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
            /* 2026-08-09、ユーザー指示 -- 以前はここでブロッキング
             * nvme_tcp_send_h2c_data_ex()(内部でtcp_send()、PDU全体を
             * 送り切りACKを待つまで戻らない)を直接呼んでいたため、次の
             * R2Tを読みに行くまでの間、実質1コマンドずつ完全に直列に
             * なっていた(depth=8を用意してもR2T受信〜H2CData送信の部分は
             * 並行化されていなかった、CLAUDE.md「NVMe/TCP writeの性能が
             * 出ない要因」節参照)。ここでは(slot,ttag,r2to,r2tl)を小さい
             * FIFOキューへ積んで即座に受信ループへ戻るだけにし、実際の
             * 送信はnvme_pipeline_h2c_pump()(呼び出し元のメインループが
             * 毎tick呼ぶ)がtcp_send_async()で非ブロッキングに進める。 */
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

/* ================================================================
 * H2CData送信のパイプライン化(2026-08-09、ユーザー指示)。
 *
 * 従来はR2T受信直後にブロッキングtcp_send()(nvme_tcp_send_h2c_data_ex()
 * 内部)を呼んでおり、PDU全体(ヘッダ24B+データ最大262144B)を送り切り、
 * さらにその末尾バイトのACK到達まで待ってから戻る設計だった。実機の
 * `ts`計測(SSLT/SFLT/TXAK/TACK相関)で、この「末尾ACK待ち」だけで
 * 1コマンドあたり約1msかかっており、depth=8で8回直列に積み重なって
 * 約16.8ms/バッチ(depth=4/8のどちらでもほぼ同じ)というスループット
 * 頭打ちの直接原因になっていることを特定した。
 *
 * 修正: R2T受信(nvme_pipeline_rx_tick())は(slot,ttag,r2to,r2tl)を
 * s_h2c_pending[]へ積むだけにし、実際の送信はここ(nvme_pipeline_h2c_pump()、
 * メインループから毎tick呼ぶ)がtcp_send_async()(MSS単位、ACK到達を
 * 待たず即座に返る、tcp_send_async_poll()が背後で確認・再送を担当)を
 * 繰り返し呼んで進める。1PDU分のバイト列(ヘッダ+データ)は必ず連続して
 * キューし切ってから次のPDUへ進む(NVMe/TCPフレーミング上、複数PDUを
 * バイト単位でインターリーブしてはならない -- ただし「確認[ACK]を
 * 待たない」ことと「連続してキューする」ことは両立する、両者は別の話)。
 * s_h2c_cursorが指す1件の送信は必ずnvme_pipeline_h2c_pump()の1回の
 * 呼び出し内で完結する(完了またはエラーで必ずactive=0に戻す)ため、
 * 呼び出し元のメインループ(SQE送信・R2T受信)が同じコネクションの
 * バイトストリームへ割り込む余地は無い(逐次実行のため自然に排他される)。
 * FIFOキュー本体(s_h2c_pending[]/nvme_h2c_pending_push())は前方参照を
 * 避けるためnvme_pipeline_rx_tick()より前で定義済み。 */

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

static void nvme_h2c_pipeline_reset(void)
{
    s_h2c_pending_head  = 0;
    s_h2c_pending_count = 0;
    for (unsigned i = 0; i < NVME_H2C_PENDING_MAX; i++) {
        s_h2c_pending[i].valid = 0;
    }
    s_h2c_cursor.active = 0;
}

static void nvme_pipeline_h2c_pump(nvme_ctx_t *ctx)
{
    if (!s_h2c_cursor.active) {
        if (s_h2c_pending_count == 0) {
            return;
        }
        nvme_h2c_pending_t *p = &s_h2c_pending[s_h2c_pending_head];
        s_h2c_cursor.active      = 1;
        s_h2c_cursor.slot        = p->slot;
        /* 2026-08-10、実機で発見した本物のバグの修正: push時点で確定
         * させたp->cid(nvme_h2c_pending_t.cidコメント参照)をそのまま
         * 使う -- s_pl_slots[p->slot].cidを取り出す時点で再読み込みして
         * いた旧実装は、slotが別のwriteへ再利用されタイミングによっては
         * 誤ったcidを参照してしまい、あるcidのH2CDataが永久に送られない
         * まま別のcidが重複して処理される実機バグ(`ts core 0 type NH2F`
         * でcid欠落+重複を確認、CLAUDE.md参照)を引き起こしていた。 */
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

    /* ヘッダ(24B、NVME_TCP_DATA_PDU_LEN)を最初に1回だけ送る -- r2tlは
     * 常にNVMET_TCP_MAXH2CDATA_SCALED(262144)以下(target側の1回のR2T
     * オファーの上限)であり、このパイプラインが対象とするwrite専用の
     * 用途では1コマンド=1PDUで足りるため、複数PDUへの分割
     * (NVME_TCP_H2C_CHUNK_MAX相当)は行わない -- 常にF_DATA_LASTを立てる。 */
    if (!s_h2c_cursor.header_sent) {
        uint8_t hdr[NVME_TCP_DATA_PDU_LEN];
        hdr[0] = NVME_TCP_PDU_H2C_DATA;
        hdr[1] = NVME_TCP_F_DATA_LAST;
        hdr[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        hdr[3] = (uint8_t)NVME_TCP_DATA_PDU_LEN;  /* pdo: データはこのPDU内の固定部直後 */
        wr32le(&hdr[4], NVME_TCP_DATA_PDU_LEN + s_h2c_cursor.r2tl);
        wr16le(&hdr[8],  s_h2c_cursor.cid);
        wr16le(&hdr[10], s_h2c_cursor.ttag);
        wr32le(&hdr[12], s_h2c_cursor.r2to);
        wr32le(&hdr[16], s_h2c_cursor.r2tl);
        wr32le(&hdr[20], 0);  /* reserved */
        /* NSND: H2CData送信(旧NMTX)。データ本体(TCP_ASYNC_MAX_LEN単位の
         * 複数チャンク)は下のループでtcp_send_async()により追加でキュー
         * されるが、PDUとしては1個(ヘッダ送信時点でplen/datao/datalが
         * 確定済み)なのでここで1回だけ記録する。 */
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
        if (tcp_send_async(&ctx->io.tcp, hdr, (uint16_t)NVME_TCP_DATA_PDU_LEN) < 0) {
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
        /* 2026-08-10、LSO対応に伴いmssへの切り詰めを撤去した --
         * tcp_send_async()自体が、接続先のLSOケーパビリティに応じて
         * mss単位への分割/LSO単発送信を内部で使い分けるようになった
         * (tcp.hのtcp_send_async()コメント参照)ため、ここは
         * TCP_ASYNC_MAX_LEN単位のチャンクをそのまま渡すだけでよい。 */
        /* 計装専用(上記NRSPコメント参照)。このPDUの最初のデータチャンクを
         * キューする直前。使用後に削除すること。 */
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
    /* 計装専用(上記NRSPコメント参照)。このPDUの最後のデータチャンクを
     * キューし終えた直後。使用後に削除すること。 */
    ts_log(TS_MK(TS_FILE_NVME, TS_FUNC_nvme_pipeline_h2c_pump, 2), s_h2c_cursor.cid);

    /* このPDUは完全にキューし終えた -- 次回の呼び出しで次のPDU(あれば)へ進む。 */
    s_h2c_cursor.active = 0;
}

/* ベンチのコマンドごとに開始 LBA を nlb ずつ進め、名前空間の終端を超えたら
 * 開始位置 base へ戻す(Linux の fio が --rw=write/read で行うシーケンシャル
 * アクセスと同じ挙動)。
 *
 * 以前はパイプラインの全コマンドが常に同じ LBA を指しており、ターゲット側が
 * 同一メモリだけを触り続けるためキャッシュに有利すぎる測定になっていた。
 * Linux 側(fio / SPDK perf)と条件を揃えるために導入した。
 * ctx->nsze が未取得(0)の場合は進めず base のままにする(退行しない側に倒す)。 */
static uint64_t nvme_bench_next_lba(const nvme_ctx_t *ctx, uint64_t cur,
                                    uint64_t base, uint32_t nlb)
{
    uint64_t next = cur + (uint64_t)nlb;
    if (ctx->nsze == 0u || next + (uint64_t)nlb > ctx->nsze) {
        return base;
    }
    return next;
}

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
        /* 空いたスロットへ次のwriteを積む(常に同じlba/bufへ上書きする、
         * 性能測定専用の設計 -- temp_test()の既存ループと同じ)。 */
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
        /* 未送信のスロットを送信する。2026-08-09、ユーザー指示で
         * ブロッキングtcp_send()経由のnvme_tcp_send_cmd()から、
         * tcp_send_async()経由のnvme_tcp_send_cmd_async()へ変更した
         * (TCP_ASYNC_MAX_LENを128へ拡張、tcp.h参照) -- 実機の`ts`計測で
         * 複数スロットを連続送信する際、1件ごとに相手のACKを待つ遅延
         * (バースト内の送信間隔が約110-120us)が観測されたため。この
         * 変更単独ではPDUの受信側処理(R2T待ち・H2CData転送・CQE受信、
         * いずれもR2T往復のレイテンシが支配的)は変わらないが、SQE
         * 送信自体を詰めることでバッチ内の実効並行度を上げる狙い。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (s_pl_slots[i].in_use && !s_pl_slots[i].sent) {
                uint16_t cid = 0;
                if (nvme_tcp_send_cmd_async(&ctx->io, &s_pl_slots[i].sqe, &cid) != 0) {
                    s_pl_slots[i].done   = 1;
                    s_pl_slots[i].result = -1;
                    continue;
                }
                /* NSND: CapsuleCmd送信(write、旧NMTX)。in-capsuleデータは
                 * 使わない設計(常にR2T+H2CData)のためhlen=plen=72,pdo=0。 */
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

    /* drain: 送信済みで未完了のスロットが残っていれば、その完了(または
     * NVME_IO_CMD_TIMEOUT_MS超過)を待つ -- 新規の送信は行わない。
     * ただしH2C送信キューに積まれたまま(R2Tは受けたがまだ送信していない)
     * ものが残っている可能性があるため、ここでもnvme_pipeline_h2c_pump()を
     * 呼び続けて確実に送り切る。 */
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

/* ================================================================
 * NVMe/TCP READコマンドパイプライン化(2026-08-10、ユーザー指示)。
 *
 * 上記WRITE版(nvme_write_pipelined_run())と同じNVME_IO_QDEPTH並列設計
 * だが、応答経路が異なるため状態機械は独立させた: WRITEはSEND→R2T受信→
 * H2CData送信→RSP受信という往復を挟む(H2C送信キュー/pumpが必要)のに
 * 対し、READはSEND直後にtargetがC2HData(読み出しデータ本体)を送って
 * くるだけで、こちらから追加の送信は不要。CLAUDE.md「READ(C2HData送信)
 * の単一PDU化」節の通り、この実装のtarget(nvmet_tcp.c)は1コマンド分の
 * データ全体を単一のC2HData PDU(F_DATA_SUCCESS付き、別途RSPを送らない)
 * で返す設計になっているため、受信したデータをスロットの宛先バッファへ
 * コピーし、F_DATA_SUCCESSを見た時点で完了とするだけで済む。
 *
 * write版の受信ステートマシン/静的バッファは一切共用しない(read/write
 * パイプラインが同時に動くことは無い -- ctx->busyが単一ゲート -- が、
 * R2T往復とC2HData直送という異なるPDUフローを1つの状態機械に無理に
 * 詰め込むと条件分岐が増えて見通しが悪くなるため、素直に分けた)。 */

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
} nvme_pipeline_read_rx_state_t;

/* 未知のcid/cccid宛のC2HData(本来起きないはずの防御的経路)を、ストリーム
 * 同期を保ったまま読み捨てるための破棄先バッファ。1PDUのデータ長は
 * target側のMDTS(NVMET_MAX_TRANSFER_BYTES=262144、nvmet.h)で頭打ちの
 * はずなのでこのサイズで足りる -- ただし万一これを超える場合は
 * datal全体を消費しきれずストリームがずれる(呼び出し元がslot探索に
 * 失敗する状況自体が想定外のため、この防御はベストエフォート)。 */
static uint8_t s_pl_read_discard_buf[262144] __attribute__((aligned(64)));

typedef enum { NRX_HDR, NRX_PSH, NRX_DATA } nvme_read_prx_phase_t;

/* マルチコネクション対応(2026-08-15): read パイプライン状態を per-core 化。
 * 2 initiator コア(core0/core2)が別々の接続で並行して read を駆動するため、
 * 従来ファイルスコープ static だった状態を [SMP_MAX_CORES] 配列にし、
 * smp_core_index() で索引する(各関数先頭で rd = &s_rd[smp_core_index()])。
 * upcall(nvme_read_rx_upcall)は接続を所有するコアの tcp_input から呼ばれる
 * ため、smp_core_index() が正しい索引を返す。s_pl_read_discard_buf(破棄
 * シンク)だけは内容が意味を持たないため共有のまま。 */
typedef struct {
    nvme_pipeline_read_slot_t     slots[NVME_IO_QDEPTH];
    nvme_pipeline_read_rx_state_t rx_state;
    nvme_tcp_xfer_t               xfer;
    uint8_t                       hdr_buf[NVME_TCP_HDR_LEN];
    uint8_t                       rest_buf[16];
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
} nvme_rd_state_t;
static nvme_rd_state_t s_rd[SMP_MAX_CORES];

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

/* ===== push型受信(inline upcall)による read RX。2026-08-15 =====
 * 従来の nvme_pipeline_read_rx_tick(pull型)は NIC→tcp rx_buf→スロット宛先の
 * 二重コピーを伴い、受信側(initiator=core0)の CPU コストが read スループットの
 * 律速になっていた(simdelay で実測: core0 に 5us 注入で read -12%)。target 側の
 * H2CData 受信(nvmet.c の nvmet_io_rx_upcall、CLAUDE.md「push型受信」節)と同じ手法で、
 * tcp_input() が in-order データを rx_buf へ積む代わりにこの upcall へ直接渡し、
 * C2HData 本体を宛先スロットバッファへ 1 コピーで配置する(rx_buf ステージング排除)。
 * パーサ状態は per-core 化した(上記 nvme_rd_state_t、マルチコネクションで
 * 2 initiator コアが並行 read するため)。 */
static void nvme_read_rx_upcall(void *arg, const volatile uint8_t *data, uint16_t len)
{
    (void)arg;
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
                    if (rd->nrx_slot >= 0 && (rd->nrx_hdr[1] & NVME_TCP_F_DATA_SUCCESS)) {
                        rd->slots[rd->nrx_slot].done = 1; rd->slots[rd->nrx_slot].result = 0;
                    }
                    rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0;
                } else {
                    rd->nrx_data_off = 0; rd->nrx_phase = NRX_DATA;
                }
            } else if (rd->nrx_type == NVME_TCP_PDU_RSP) {
                /* 通常はC2HData(F_DATA_SUCCESS)が暗黙完了を兼ねるため来ない想定だが、
                 * targetがエラーを明示RSPで返す場合(範囲外read等)に備える。 */
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
            break;
        }
        case NRX_DATA: {
            uint32_t need  = rd->nrx_data_need - rd->nrx_data_off;
            uint32_t avail = (uint32_t)len - i;
            uint32_t take  = (need > avail) ? avail : need;
            /* 唯一のコピー: RX(in-orderデータ)→宛先スロット直接配置。未知slot(-1)は
             * コピーせず消費のみ(ストリーム同期維持)。 */
            if (rd->nrx_slot >= 0) {
                volatile_fast_copy(rd->nrx_data_dst + rd->nrx_data_off, data + i, take);
            }
            rd->nrx_data_off += take; i += take;
            if (rd->nrx_data_off == rd->nrx_data_need) {
                if (rd->nrx_slot >= 0 && (rd->nrx_hdr[1] & NVME_TCP_F_DATA_SUCCESS)) {
                    rd->slots[rd->nrx_slot].done = 1; rd->slots[rd->nrx_slot].result = 0;
                }
                rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0;
            }
            break;
        }
        }
    }
}

static void nvme_pipeline_read_rx_tick(nvme_ctx_t *ctx)
{
    nvme_rd_state_t *rd = &s_rd[smp_core_index()];
    int r = nvme_tcp_recv_poll(&ctx->io, &rd->xfer);
    if (r < 0) {
        /* コネクションレベルの失敗(FIN/エラー) -- 送信済み・未完了の
         * 全スロットを失敗として確定させる(write版と同じ考え方)。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use && rd->slots[i].sent && !rd->slots[i].done) {
                rd->slots[i].done   = 1;
                rd->slots[i].result = -1;
            }
        }
        return;
    }
    if (r == 0) {
        return;  /* このPDUの受信途中、次tickへ */
    }

    switch (rd->rx_state) {
    case PL_READ_RX_HDR: {
        uint8_t type = rd->hdr_buf[0];
        if (type == NVME_TCP_PDU_RSP) {
            nvme_tcp_xfer_reset(&rd->xfer, rd->rest_buf, NVME_CQE_LEN);
            rd->rx_state = PL_READ_RX_RSP_REST;
        } else if (type == NVME_TCP_PDU_C2H_DATA) {
            nvme_tcp_xfer_reset(&rd->xfer, rd->rest_buf, 16u);
            rd->rx_state = PL_READ_RX_C2H_REST;
        } else {
            uart_printf("[!] nvme read pipeline: 未対応のPDU種別 (type=%u)、読み捨てて再同期を試みます\n", type);
            nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
            rd->rx_state = PL_READ_RX_HDR;
        }
        break;
    }

    case PL_READ_RX_RSP_REST: {
        /* 通常はC2HData(F_DATA_SUCCESS付き)が暗黙の完了応答を兼ねるため
         * ここには来ない想定だが、targetがエラーを明示的なRSPで返す場合
         * (例: 範囲外read)に備える。 */
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
        if (rd->cur_slot >= 0 && (flags & NVME_TCP_F_DATA_SUCCESS)) {
            rd->slots[rd->cur_slot].done   = 1;
            rd->slots[rd->cur_slot].result = 0;
        }
        /* F_DATA_SUCCESS無し(複数PDU分割)はこのtarget実装では起きない
         * 想定だが、来た場合も状態を壊さないよう単純にRECV_HDRへ戻り
         * 続くPDUを待つ(write版と同じ設計方針)。 */
        nvme_tcp_xfer_reset(&rd->xfer, rd->hdr_buf, NVME_TCP_HDR_LEN);
        rd->rx_state = PL_READ_RX_HDR;
        break;
    }
    }
}

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

    /* push型受信を有効化(nvme_read_rx_upcall)。以後 C2HData/RSP は tcp_input() から
     * この upcall へ直接渡り、宛先スロットへ1コピーで配置される(rx_buf ステージング排除)。
     * ループの nvme_pipeline_read_rx_tick() は tcp_poll_once() を回す poll ドライバとして
     * 残る -- upcall 登録中は in-order データが rx_buf に積まれず recv_poll は 0 を返すため、
     * pull 側の状態機械は空回り(no-op)し、実 RX は upcall が担う。 */
    rd->nrx_phase = NRX_HDR; rd->nrx_hdr_off = 0; rd->nrx_error = 0; rd->nrx_slot = -1;
    tcp_set_recv_upcall(&ctx->io.tcp, nvme_read_rx_upcall, NULL);

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
        /* 空いたスロットへ次のreadを積む(常に同じlba/bufへ、性能測定
         * 専用の設計 -- write版・temp_test()の既存ループと同じ)。
         *
         * 【2026-08-15、x86 VFIO ポートで発見・修正した zero-window
         *  デッドロック】READ の in-flight(outstanding × total_len)が受信側の
         *  TCP_RX_BUF_SIZE に達すると、相手が rx_buf を 100% 埋め尽くして WIN=0
         *  になり、受信側は「処理中 PDU の残り」が届かず前進できず、送信側は
         *  1.6 秒 RTO で空転する回復不能なデッドロックに陥る(256KB×qd8=2MB が
         *  rx_buf 2MB と一致する条件。x86 の高速タイミングで顕在化。rpi5 は
         *  広告受信ウィンドウが RX ring 容量で小さく抑えられ in-flight が
         *  そもそもこの上限に達しないため問題化していなかった)。1 転送分の
         *  headroom を常に残し、in-flight を rx_buf 未満に保つ。8KB 等の小さい
         *  転送では max_inflight >> NVME_IO_QDEPTH となり従来通り全スロットを
         *  使う(この cap は 256KB 級の大きい転送でのみ効く)。 */
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
        /* 未送信のスロットを送信する(write版と同じくtcp_send_async()
         * 経由のnvme_tcp_send_cmd_async()を使い、複数スロットのSQE送信
         * 自体を詰める)。 */
        for (unsigned i = 0; i < NVME_IO_QDEPTH; i++) {
            if (rd->slots[i].in_use && !rd->slots[i].sent) {
                uint16_t cid = 0;
                if (nvme_tcp_send_cmd_async(&ctx->io, &rd->slots[i].sqe, &cid) != 0) {
                    rd->slots[i].done   = 1;
                    rd->slots[i].result = -1;
                    continue;
                }
                /* NSND: CapsuleCmd送信(read、旧NMTX)。write版と同じ理由
                 * (in-capsuleデータ無し)でhlen=plen=72,pdo=0。旧実装は
                 * ここでopcode参照元をs_pl_slots(write用配列)と取り違えて
                 * いた(cid自体は関数の戻り値経由のため無関係、表示のみの
                 * バグ) -- 移行のついでにs_pl_read_slotsへ修正した。 */
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

    /* drain: 送信済みで未完了のスロットが残っていれば、その完了(または
     * NVME_IO_CMD_TIMEOUT_MS超過)を待つ -- 新規の送信は行わない。 */
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
