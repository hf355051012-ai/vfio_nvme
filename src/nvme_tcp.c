#include <stddef.h>
#include "nvme_tcp.h"
#include "nvme_tcp_pdu.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "job.h"
#include "timestamp.h"

#define NVME_TCP_ICRESP_TIMEOUT_MS 3000u
#define NVME_TCP_RESP_TIMEOUT_MS   10000u

#define NVME_TCP_H2C_CHUNK_MAX 262144u

/*
 * Command Capsule PDU(固定 72 バイト + 任意の in-capsule データ)を
 * ブロッキング送信する。cid は内部で採番して out_cid へ返す。
 *
 * 引数:
 *   c            - 送信先コネクション
 *   sqe          - 送る SQE(64 バイト)
 *   data/data_len- in-capsule データ(不要なら NULL/0)
 *   out_cid      - 採番された command id の格納先
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   nvme_exec_step()
 */
int nvme_tcp_send_cmd(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe,
                      const void *data, uint32_t dlen)
{
    uint8_t sgl_type = sqe->dptr[15];
    int use_r2t = (data != NULL && dlen > 0 && sgl_type == (uint8_t)NVME_SGL_TYPE_TRANSPORT);

    if (!use_r2t && data && dlen > NVME_TCP_INLINE_DATA_MAX) {
        uart_printf("[!] NVMe/TCP: in-capsule書き込みデータが大きすぎる (%u > %u)\n",
                    dlen, NVME_TCP_INLINE_DATA_MAX);
        return -1;
    }

    static uint8_t s_cmd_buf[NVME_TCP_CMD_PDU_LEN + NVME_TCP_INLINE_DATA_MAX]
        __attribute__((aligned(64)));

    uint16_t cid = c->next_cid++;
    int has_inline_data = (!use_r2t && data != NULL && dlen > 0);

    s_cmd_buf[0] = NVME_TCP_PDU_CMD;
    s_cmd_buf[1] = 0;
    s_cmd_buf[2] = (uint8_t)NVME_TCP_CMD_PDU_LEN;
    s_cmd_buf[3] = has_inline_data ? (uint8_t)NVME_TCP_CMD_PDU_LEN : 0;  /* pdo: in-capsuleデータの開始位置 */
    wr32le(&s_cmd_buf[4], NVME_TCP_CMD_PDU_LEN + (has_inline_data ? dlen : 0u));

    volatile_fast_copy((volatile uint8_t *)&s_cmd_buf[NVME_TCP_HDR_LEN],
                        (const volatile uint8_t *)sqe, NVME_SQE_LEN);
    wr16le(&s_cmd_buf[NVME_TCP_HDR_LEN + 2], cid);

    uint16_t total_len = (uint16_t)NVME_TCP_CMD_PDU_LEN;
    if (has_inline_data) {
        volatile_fast_copy((volatile uint8_t *)&s_cmd_buf[NVME_TCP_CMD_PDU_LEN],
                            (const volatile uint8_t *)data, dlen);
        total_len = (uint16_t)(NVME_TCP_CMD_PDU_LEN + dlen);
    }

    c->pending_cid  = cid;
    c->pending_data = data;   /* use_r2t時: R2Tが来るまでdlen全体をここに保留 */
    c->pending_len  = dlen;

    if (tcp_send(&c->tcp, s_cmd_buf, total_len) != (int)total_len) {
        uart_printf("[!] NVMe/TCP: CapsuleCmd送信失敗 (cid=%u)\n", cid);
        return -1;
    }
    return 0;
}

/*
 * nvme_tcp_send_cmd() の非同期版。in-capsule データ無しの 72 バイト固定
 * PDU を tcp_send_async() で送り、ACK を待たずに返る(コマンド
 * パイプライン化用)。
 *
 * 引数:
 *   c       - 送信先コネクション
 *   sqe     - 送る SQE
 *   out_cid - 採番された command id の格納先
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   nvme_write_pipelined_run(), nvme_read_pipelined_run()
 */
int nvme_tcp_send_cmd_async(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe, uint16_t *out_cid)
{
    static uint8_t s_cmd_async_buf[NVME_TCP_CMD_PDU_LEN] __attribute__((aligned(64)));

    uint16_t cid = c->next_cid++;

    s_cmd_async_buf[0] = NVME_TCP_PDU_CMD;
    s_cmd_async_buf[1] = 0;
    s_cmd_async_buf[2] = (uint8_t)NVME_TCP_CMD_PDU_LEN;
    s_cmd_async_buf[3] = 0;  /* pdo: in-capsuleデータ無し */
    wr32le(&s_cmd_async_buf[4], NVME_TCP_CMD_PDU_LEN);

    volatile_fast_copy((volatile uint8_t *)&s_cmd_async_buf[NVME_TCP_HDR_LEN],
                        (const volatile uint8_t *)sqe, NVME_SQE_LEN);
    wr16le(&s_cmd_async_buf[NVME_TCP_HDR_LEN + 2], cid);

    if (tcp_send_async(&c->tcp, s_cmd_async_buf, (uint16_t)NVME_TCP_CMD_PDU_LEN) < 0) {
        uart_printf("[!] NVMe/TCP: CapsuleCmd非同期送信失敗 (cid=%u)\n", cid);
        return -1;
    }
    if (out_cid) {
        *out_cid = cid;
    }
    return 0;
}

/*
 * R2T で要求された [r2to, r2to+r2tl) を、明示的に渡したバッファから
 * H2CData PDU(NVME_TCP_H2C_CHUNK_MAX ごとに分割)として送出する下位実装。
 * cid も呼び出し元が明示するため、複数コマンドを同時に in-flight にできる。
 *
 * 引数:
 *   c            - 送信先コネクション
 *   cid / ttag   - 対応するコマンドの id と R2T の転送タグ
 *   r2to / r2tl  - 要求された範囲(オフセットと長さ)
 *   data/data_len- 送信元バッファ全体
 * 戻り値:
 *   0=送信完了、-1=範囲不正/送信失敗
 * コール元:
 *   nvme_tcp_send_h2c_data()
 */
int nvme_tcp_send_h2c_data_ex(nvme_tcp_conn_t *c, uint16_t cid, uint16_t ttag,
                               uint32_t r2to, uint32_t r2tl,
                               const void *data, uint32_t data_len)
{
    if (!data || (uint64_t)r2to + (uint64_t)r2tl > (uint64_t)data_len) {
        uart_printf("[!] NVMe/TCP: R2Tが保留データ範囲外 (r2to=%u r2tl=%u data_len=%u)\n",
                    r2to, r2tl, data_len);
        return -1;
    }

    static uint8_t s_h2c_buf[NVME_TCP_DATA_PDU_LEN + NVME_TCP_H2C_CHUNK_MAX]
        __attribute__((aligned(64)));

    const uint8_t *src = (const uint8_t *)data;
    uint32_t sent = 0;
    while (sent < r2tl) {
        uint32_t chunk = r2tl - sent;
        if (chunk > NVME_TCP_H2C_CHUNK_MAX) chunk = NVME_TCP_H2C_CHUNK_MAX;
        int last = (sent + chunk == r2tl);

        s_h2c_buf[0] = NVME_TCP_PDU_H2C_DATA;
        s_h2c_buf[1] = last ? NVME_TCP_F_DATA_LAST : 0;
        s_h2c_buf[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        s_h2c_buf[3] = (uint8_t)NVME_TCP_DATA_PDU_LEN;  /* pdo: データはこのPDU内の固定部直後 */
        wr32le(&s_h2c_buf[4], NVME_TCP_DATA_PDU_LEN + chunk);
        wr16le(&s_h2c_buf[8],  cid);
        wr16le(&s_h2c_buf[10], ttag);
        wr32le(&s_h2c_buf[12], r2to + sent);
        wr32le(&s_h2c_buf[16], chunk);
        wr32le(&s_h2c_buf[20], 0);  /* reserved */

        volatile_fast_copy((volatile uint8_t *)&s_h2c_buf[NVME_TCP_DATA_PDU_LEN],
                            (const volatile uint8_t *)(src + r2to + sent), chunk);

        uint32_t total = NVME_TCP_DATA_PDU_LEN + chunk;
        if (tcp_send(&c->tcp, s_h2c_buf, total) != (int)total) {
            uart_printf("[!] NVMe/TCP: H2CData送信失敗 (offset=%u len=%u)\n", r2to + sent, chunk);
            return -1;
        }
        sent += chunk;
    }
    return 0;
}

/*
 * コネクションが保持する pending_data/pending_cid を使って
 * nvme_tcp_send_h2c_data_ex() を呼ぶ薄いラッパ(単発コマンド用)。
 *
 * 引数:
 *   c           - 送信先コネクション
 *   ttag        - R2T の転送タグ
 *   r2to / r2tl - 要求された範囲
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   nvme_exec_step()
 */
int nvme_tcp_send_h2c_data(nvme_tcp_conn_t *c, uint16_t ttag, uint32_t r2to, uint32_t r2tl)
{
    return nvme_tcp_send_h2c_data_ex(c, c->pending_cid, ttag, r2to, r2tl,
                                      c->pending_data, c->pending_len);
}

void nvme_tcp_xfer_reset(nvme_tcp_xfer_t *x, void *buf, uint32_t want)
{
    x->buf  = (uint8_t *)buf;
    x->want = want;
    x->got  = 0;
    x->reset_tick = timer_now();
}

int nvme_tcp_recv_poll(nvme_tcp_conn_t *c, nvme_tcp_xfer_t *x)
{
    if (x->got >= x->want) return 1;  /* want==0を含む */

    uint32_t remain = x->want - x->got;
    uint32_t got_before = x->got;
    int n = tcp_recv(&c->tcp, x->buf + x->got, remain, 0u);
    if (n == 0) {
        uart_printf("[!] NVMe/TCP: 受信中に相手がFINでクローズ\n");
        return -1;
    }
    if (n < 0) {
        return 0;  /* この1tickでは何も届かなかっただけ */
    }
    if (got_before == 0) {
        ts_log(TS_MK(TS_FILE_NVME_TCP, TS_FUNC_nvme_tcp_recv_poll, 0), tcp_conn_arg(&c->tcp, (uint32_t)get_us_from(x->reset_tick)));
    }
    x->got += (uint32_t)n;
    if (x->got >= x->want) {
        ts_log(TS_MK(TS_FILE_NVME_TCP, TS_FUNC_nvme_tcp_recv_poll, 1), tcp_conn_arg(&c->tcp, (uint32_t)get_us_from(x->reset_tick)));
        return 1;
    }
    return 0;
}

/*
 * コネクション確立直後の ICReq PDU を送信する(PDU データダイジェスト等の
 * ネゴシエーション開始)。
 *
 * 引数:
 *   c - 送信先コネクション
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   nvme_connect_job_step()
 */
int nvme_tcp_send_icreq(nvme_tcp_conn_t *c)
{
    c->maxdata      = 8192u;  /* ICRespが届くまでの暫定値 */
    c->next_cid     = 0;
    c->pending_data = NULL;
    c->pending_len  = 0;
    c->pending_cid  = 0;

    static uint8_t s_icreq_buf[NVME_TCP_ICREQ_LEN] __attribute__((aligned(64)));
    for (uint32_t i = 0; i < NVME_TCP_ICREQ_LEN; i++) s_icreq_buf[i] = 0;

    s_icreq_buf[0] = NVME_TCP_PDU_ICREQ;         /* hdr.type */
    s_icreq_buf[1] = 0;                          /* hdr.flags */
    s_icreq_buf[2] = (uint8_t)NVME_TCP_ICREQ_LEN; /* hdr.hlen */
    s_icreq_buf[3] = 0;                          /* hdr.pdo (可変長データ無し) */
    wr32le(&s_icreq_buf[4], NVME_TCP_ICREQ_LEN);  /* hdr.plen */
    wr16le(&s_icreq_buf[8], 0);   /* pfv */
    s_icreq_buf[10] = 0;          /* hpda */
    s_icreq_buf[11] = 0;          /* digest: header/dataともに要求しない(未対応) */
    wr32le(&s_icreq_buf[12], 0);  /* maxr2t: 0 = 同時に1個のR2Tまで */
    /* reserved[112]は上のループで既に0クリア済み */

    uart_printf("[NVMe/TCP] ICReq送信\n");
    if (tcp_send(&c->tcp, s_icreq_buf, (uint16_t)NVME_TCP_ICREQ_LEN) != (int)NVME_TCP_ICREQ_LEN) {
        uart_printf("[!] NVMe/TCP: ICReq送信失敗\n");
        return -1;
    }
    return 0;
}

/*
 * 受信した ICResp を検証し、type/hlen/digest 設定を確認して c->maxdata
 * (1 回の H2CData で送れる上限)を確定させる。
 *
 * 引数:
 *   c           - 対象コネクション
 *   icresp_buf  - 受信した ICResp(NVME_TCP_ICRESP_LEN バイト)
 * 戻り値:
 *   0=正常、-1=フォーマット不正/非対応設定
 * コール元:
 *   nvme_connect_job_step()
 */
int nvme_tcp_verify_icresp(nvme_tcp_conn_t *c, const uint8_t icresp_buf[NVME_TCP_ICRESP_LEN])
{
    uint8_t type = icresp_buf[0];
    uint8_t hlen = icresp_buf[2];
    if (type != NVME_TCP_PDU_ICRESP || hlen != (uint8_t)NVME_TCP_ICRESP_LEN) {
        uart_printf("[!] NVMe/TCP: 不正なICResp (type=%u hlen=%u)\n", type, hlen);
        return -1;
    }
    uint8_t digest = icresp_buf[11];
    if (digest != 0) {
        uart_printf("[!] NVMe/TCP: targetがdigestを要求 (未対応, digest=0x%02x)\n", digest);
        return -1;
    }
    c->maxdata = rd32le(&icresp_buf[12]);
    uart_printf("[NVMe/TCP] ICResp受信: maxdata=%u\n", c->maxdata);
    return 0;
}

/*
 * NVMe/TCP コネクションの TCP を切断し、状態をクリアする。
 *
 * 引数:
 *   c - 対象コネクション
 * コール元:
 *   nvme_connect_job_fail()
 */
void nvme_tcp_close(nvme_tcp_conn_t *c)
{
    tcp_close(&c->tcp);
}
