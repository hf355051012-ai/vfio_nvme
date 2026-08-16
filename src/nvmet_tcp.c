#include <stddef.h>
#include "nvmet_tcp.h"
#include "nvme_tcp_pdu.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "crc32c.h"

#define NVMET_TCP_C2H_CHUNK_MAX 262144u

#define NVMET_TCP_MAXH2CDATA_UNSCALED 32768u
#define NVMET_TCP_MAXH2CDATA_SCALED   262144u

/*
 * このコネクションで 1 回の H2CData PDU に載せてよい最大データ長を返す
 * (ICResp で相手へ広告した MAXH2CDATA と同じ値)。
 *
 * 引数:
 *   c - 対象コネクション
 * 戻り値:
 *   最大バイト数
 * コール元:
 *   nvmet_tcp_send_icresp(), nvmet_io_dispatch_cmd(), nvmet_io_dispatch_h2c()
 */
uint32_t nvmet_tcp_max_h2c_data(const nvmet_tcp_conn_t *c)
{
    return tcp_window_scaling_enabled(&c->tcp)
        ? NVMET_TCP_MAXH2CDATA_SCALED
        : NVMET_TCP_MAXH2CDATA_UNSCALED;
}

/*
 * ヘッダダイジェストが有効なら buf[0..hlen) の CRC32C を buf[hlen..+4) へ
 * 書く。**呼び出し元は先に flags/plen/pdo など hlen 範囲の全フィールドを
 * 最終状態まで確定させておくこと**(実機で 2 度踏んだ、ダイジェスト計算後に
 * ヘッダを書き換えると相手側の検証だけが静かに失敗する)。
 *
 * 引数:
 *   c    - 対象コネクション(hdgst 有効判定に使う)
 *   buf  - PDU ヘッダ先頭
 *   hlen - ヘッダ長
 * 戻り値:
 *   付加したバイト数(0 か 4)
 * コール元:
 *   nvmet_tcp_send_r2t(), nvmet_tcp_send_resp(), nvmet_tcp_send_c2h()
 */
static uint32_t nvmet_tcp_append_hdgst(nvmet_tcp_conn_t *c, uint8_t *buf, uint32_t hlen)
{
    if (!c->hdgst) return 0;
    uint32_t crc = ~crc32c(0xFFFFFFFFu, buf, hlen);  /* 最終反転(crc32c.hコメント参照) */
    wr32le(&buf[hlen], crc);
    return 4u;
}

/*
 * データダイジェストが有効かつ dlen>0 なら、データ本体の CRC32C を
 * その直後へ書く。対象はデータのみでヘッダは範囲外。
 *
 * 引数:
 *   c        - 対象コネクション
 *   buf      - PDU 先頭
 *   data_off - データ本体のオフセット
 *   dlen     - データ長
 * 戻り値:
 *   付加したバイト数(0 か 4)
 * コール元:
 *   nvmet_tcp_send_c2h()
 */
static uint32_t nvmet_tcp_append_ddgst(nvmet_tcp_conn_t *c, uint8_t *buf,
                                        uint32_t data_off, uint32_t dlen)
{
    if (!c->ddgst || dlen == 0) return 0;
    uint32_t crc = ~crc32c(0xFFFFFFFFu, &buf[data_off], dlen);  /* 最終反転(crc32c.hコメント参照) */
    wr32le(&buf[data_off + dlen], crc);
    return 4u;
}

void nvmet_tcp_xfer_reset(nvmet_tcp_xfer_t *x, void *buf, uint32_t want)
{
    x->buf  = (uint8_t *)buf;
    x->want = want;
    x->got  = 0;
}

int nvmet_tcp_recv_poll(nvmet_tcp_conn_t *c, nvmet_tcp_xfer_t *x)
{
    if (x->got >= x->want) {
        /* want==0を含む(呼び出し側はこの場合すぐDONEにできる) */
        return 1;
    }
    if (tcp_abort_requested()) {
        return -1;
    }

    uint32_t remain = x->want - x->got;
    int n = tcp_recv_no_ack(&c->tcp, x->buf + x->got, remain, 0u);
    if (n == 0) {
        uart_printf("[!] NVMe/TCP target: 受信中に相手がFINでクローズ\n");
        return -1;
    }
    if (n < 0) {
        return 0;  /* この1tickでは何も届かなかっただけ */
    }
    x->got += (uint32_t)n;
    return (x->got >= x->want) ? 1 : 0;
}

/*
 * PDU ヘッダの plen/hlen とダイジェスト設定から、後続データ本体の長さを
 * 求める(I/O を伴わない純粋な計算)。
 *
 * 引数:
 *   c       - 対象コネクション(ダイジェスト有無で差し引く量が変わる)
 *   hdr_buf - 受信済みの共通ヘッダ 8 バイト
 * 戻り値:
 *   データ本体のバイト数
 * コール元:
 *   nvmet_admin_job_step(), nvmet_io_job_step_impl()
 */
uint32_t nvmet_tcp_parse_cmd_dlen(const nvmet_tcp_conn_t *c, const uint8_t hdr_buf[NVME_TCP_HDR_LEN])
{
    uint8_t  hlen = hdr_buf[2];
    uint32_t plen = rd32le(&hdr_buf[4]);
    uint32_t after_hdr = plen - (uint32_t)hlen;
    if (c->hdgst) after_hdr -= 4u;
    uint32_t dlen = after_hdr;
    if (dlen > 0 && c->ddgst) dlen -= 4u;
    return dlen;
}

/*
 * 受信したヘッダダイジェストを検証する(I/O を伴わない純粋な計算)。
 *
 * 引数:
 *   c        - 対象コネクション
 *   hdr / hdr_len   - 共通ヘッダ部
 *   rest / rest_len - 型固有部
 *   dgst     - 受信した 4 バイトのダイジェスト
 * 戻り値:
 *   0=一致、-1=不一致
 * コール元:
 *   nvmet_admin_job_step(), nvmet_io_job_step_impl()
 */
int nvmet_tcp_verify_hdgst(const nvmet_tcp_conn_t *c,
                            const void *hdr1, uint32_t len1,
                            const void *hdr2, uint32_t len2,
                            const uint8_t got[4])
{
    if (!c->hdgst) return 0;
    uint32_t expected = crc32c(0xFFFFFFFFu, hdr1, len1);
    if (hdr2 && len2 > 0) expected = crc32c(expected, hdr2, len2);
    expected = ~expected;  /* 最終反転(crc32c.hコメント参照) */

    uint32_t g = rd32le(got);
    if (g != expected) {
        uart_printf("[!] NVMe/TCP target: ヘッダCRC32C不一致 (expected=%08x got=%08x)\n",
                    expected, g);
        return -1;
    }
    return 0;
}

/*
 * 受信したデータダイジェストを検証する。
 *
 * 引数:
 *   c    - 対象コネクション
 *   data / dlen - データ本体
 *   dgst - 受信した 4 バイトのダイジェスト
 * 戻り値:
 *   0=一致、-1=不一致
 * コール元:
 *   nvmet_admin_job_step(), nvmet_io_job_step_impl()
 */
int nvmet_tcp_verify_ddgst(const nvmet_tcp_conn_t *c,
                            const void *data, uint32_t len,
                            const uint8_t got[4])
{
    if (!c->ddgst || len == 0) return 0;
    uint32_t expected = ~crc32c(0xFFFFFFFFu, data, len);  /* 最終反転 */

    uint32_t g = rd32le(got);
    if (g != expected) {
        uart_printf("[!] NVMe/TCP target: データCRC32C不一致 (expected=%08x got=%08x)\n",
                    expected, g);
        return -1;
    }
    return 0;
}

/*
 * ブロックせずに accept の受け皿だけを用意する。早着 SYN を取りこぼさない
 * よう、実際に待ち始める前に呼んでおく。
 *
 * 引数:
 *   c        - 受け皿にするコネクション
 *   listener - リッスン中のソケット
 * コール元:
 *   nvmet_admin_job_step(), nvmet_io_job_step_impl()
 */
void nvmet_tcp_accept_arm(nvmet_tcp_conn_t *c, int listener)
{
    tcp_accept_begin(listener, &c->tcp);
}

/*
 * 受信した ICReq のダイジェスト設定をそのまま受理してコネクションへ記録し、
 * ICResp を返す(MAXH2CDATA もここで広告する)。
 *
 * 引数:
 *   c          - 対象コネクション
 *   icreq_buf  - 受信した ICReq
 * 戻り値:
 *   0=送信完了、-1=フォーマット不正/送信失敗
 * コール元:
 *   nvmet_admin_job_step(), nvmet_io_job_step_impl()
 */
int nvmet_tcp_send_icresp(nvmet_tcp_conn_t *c, const uint8_t icreq_buf[NVME_TCP_ICREQ_LEN])
{
    uint8_t type = icreq_buf[0];
    if (type != NVME_TCP_PDU_ICREQ) {
        uart_printf("[!] NVMe/TCP target: 不正なICReq (type=%u)\n", type);
        return -1;
    }
    uint8_t digest = icreq_buf[11];
    c->hdgst = (uint8_t)(digest & 0x01u);
    c->ddgst = (uint8_t)((digest >> 1) & 0x01u);
    c->maxdata = (uint16_t)rd32le(&icreq_buf[12]);  /* initiatorのmaxr2t(参考値) */

    static uint8_t s_icresp_buf[NVME_TCP_ICRESP_LEN] __attribute__((aligned(64)));
    for (uint32_t i = 0; i < NVME_TCP_ICRESP_LEN; i++) s_icresp_buf[i] = 0;

    s_icresp_buf[0] = NVME_TCP_PDU_ICRESP;          /* hdr.type */
    s_icresp_buf[1] = 0;                            /* hdr.flags */
    s_icresp_buf[2] = (uint8_t)NVME_TCP_ICRESP_LEN; /* hdr.hlen */
    s_icresp_buf[3] = 0;                            /* hdr.pdo (可変長データ無し) */
    wr32le(&s_icresp_buf[4], NVME_TCP_ICRESP_LEN);  /* hdr.plen */
    wr16le(&s_icresp_buf[8], 0);   /* pfv */
    s_icresp_buf[10] = 0;
    s_icresp_buf[11] = (uint8_t)((c->ddgst << 1) | c->hdgst);  /* 要求された値をそのままエコー(両方対応) */
    wr32le(&s_icresp_buf[12], nvmet_tcp_max_h2c_data(c));
    /* reserved[112]は上のループで既に0クリア済み */

    uart_printf("[NVMe/TCP target] ICReq受信、ICResp送信 (initiator maxr2t=%u hdgst=%u ddgst=%u)\n",
                c->maxdata, c->hdgst, c->ddgst);
    {
        volatile ts_nvme_pdu_t info = {0};
        info.pdu_type = NVME_TCP_PDU_ICRESP;
        info.hlen     = (uint8_t)NVME_TCP_ICRESP_LEN;
        info.pdo      = 0;
        info.plen     = NVME_TCP_ICRESP_LEN;
        ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_icresp, 0), &info);
    }
    if (tcp_send(&c->tcp, s_icresp_buf, (uint16_t)NVME_TCP_ICRESP_LEN) != (int)NVME_TCP_ICRESP_LEN) {
        uart_printf("[!] NVMe/TCP target: ICResp送信失敗\n");
        return -1;
    }
    return 0;
}

/*
 * R2T PDU を送信して、ホストへ [r2to, r2to+r2tl) の H2CData を要求する。
 * 送りっぱなし(tcp_send_async)で、直後に受信フェーズへ進む。
 *
 * 引数:
 *   c           - 対象コネクション
 *   cid / ttag  - 対応するコマンド id と転送タグ
 *   r2to / r2tl - 要求する範囲
 * 戻り値:
 *   0=送信成功、-1=失敗
 * コール元:
 *   nvmet_io_dispatch_cmd(), nvmet_io_dispatch_h2c()
 */
int nvmet_tcp_send_r2t(nvmet_tcp_conn_t *c, uint16_t cid,
                        uint32_t r2to, uint32_t r2tl)
{
    static uint8_t s_r2t_buf[NVME_TCP_R2T_PDU_LEN + 4u] __attribute__((aligned(64)));

    uint32_t total = NVME_TCP_R2T_PDU_LEN + (c->hdgst ? 4u : 0u);

    s_r2t_buf[0] = NVME_TCP_PDU_R2T;
    s_r2t_buf[1] = c->hdgst ? NVME_TCP_F_HDGST : 0;
    s_r2t_buf[2] = (uint8_t)NVME_TCP_R2T_PDU_LEN;
    s_r2t_buf[3] = 0;
    wr32le(&s_r2t_buf[4], total);
    wr16le(&s_r2t_buf[8],  cid);   /* cccid */
    wr16le(&s_r2t_buf[10], 0);
    wr32le(&s_r2t_buf[12], r2to);
    wr32le(&s_r2t_buf[16], r2tl);
    wr32le(&s_r2t_buf[20], 0);     /* reserved */

    nvmet_tcp_append_hdgst(c, s_r2t_buf, NVME_TCP_R2T_PDU_LEN);

    {
        volatile ts_nvme_pdu_t info = {0};
        info.pdu_type    = NVME_TCP_PDU_R2T;
        info.hlen        = (uint8_t)NVME_TCP_R2T_PDU_LEN;
        info.pdo         = 0;
        info.plen        = total;
        info.cccid       = cid;
        info.ttag        = 0;
        info.data_offset = r2to;
        info.data_length = r2tl;
        ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_r2t, 0), &info);
    }
    ts_log(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_r2t, 1), c->tcp.snd_seq);

    if (tcp_send_async(&c->tcp, s_r2t_buf, (uint16_t)total) != (int)total) {
        uart_printf("[!] NVMe/TCP target: R2T送信失敗 (cid=%u offset=%u len=%u)\n", cid, r2to, r2tl);
        return -1;
    }
    return 0;
}

int nvmet_tcp_send_resp(nvmet_tcp_conn_t *c, const nvme_cqe_t *cqe)
{
    static uint8_t s_resp_buf[NVME_TCP_RSP_PDU_LEN + 4u] __attribute__((aligned(64)));

    uint32_t total = NVME_TCP_RSP_PDU_LEN + (c->hdgst ? 4u : 0u);

    s_resp_buf[0] = NVME_TCP_PDU_RSP;
    s_resp_buf[1] = c->hdgst ? NVME_TCP_F_HDGST : 0;
    s_resp_buf[2] = (uint8_t)NVME_TCP_RSP_PDU_LEN;
    s_resp_buf[3] = 0;
    wr32le(&s_resp_buf[4], total);

    volatile_fast_copy((volatile uint8_t *)&s_resp_buf[NVME_TCP_HDR_LEN],
                        (const volatile uint8_t *)cqe, NVME_CQE_LEN);

    nvmet_tcp_append_hdgst(c, s_resp_buf, NVME_TCP_RSP_PDU_LEN);

    {
        volatile ts_nvme_pdu_t info = {0};
        info.pdu_type = NVME_TCP_PDU_RSP;
        info.hlen     = (uint8_t)NVME_TCP_RSP_PDU_LEN;
        info.pdo      = 0;
        info.plen     = total;
        info.cid      = cqe->cid;
        info.status   = cqe->status;
        ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_resp, 0), &info);
    }

    if (tcp_send_async(&c->tcp, s_resp_buf, (uint16_t)total) != (int)total) {
        uart_printf("[!] NVMe/TCP target: Response Capsule送信失敗 (cid=%u)\n", cqe->cid);
        return -1;
    }
    return 0;
}

/*
 * C2HData PDU を送信する(データ本体を C2H 用バッファへコピーしてから
 * 1 回の tcp_send() で送る同期版)。dlen が MDTS 以下なら常に単一 PDU で
 * 収まるため、チャンク境界で送信パイプラインを空にすることがない。
 *
 * 引数:
 *   c    - 対象コネクション
 *   cid  - 対応するコマンド id
 *   cqe  - DATA_SUCCESS で埋め込む CQE(別送しない)
 *   data / dlen - 送るデータ
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   nvmet_io_dispatch_cmd(), nvmet_admin_dispatch()
 */
int nvmet_tcp_send_c2h(nvmet_tcp_conn_t *c, uint16_t cid, const nvme_cqe_t *cqe,
                       const void *data, uint32_t dlen,
                       int data_success)
{
    static uint8_t s_c2h_buf[NVME_TCP_DATA_PDU_LEN + 4u + NVMET_TCP_C2H_CHUNK_MAX + 4u]
        __attribute__((aligned(64)));

    const uint8_t *src = data;
    uint32_t sent = 0;
    while (sent < dlen) {
        uint32_t chunk = dlen - sent;
        if (chunk > NVMET_TCP_C2H_CHUNK_MAX) chunk = NVMET_TCP_C2H_CHUNK_MAX;
        int last = (sent + chunk == dlen);

        uint8_t flags = 0;
        if (last) {
            flags = NVME_TCP_F_DATA_LAST;
            if (data_success) flags = (uint8_t)(flags | NVME_TCP_F_DATA_SUCCESS);
        }
        if (c->hdgst) flags = (uint8_t)(flags | NVME_TCP_F_HDGST);
        if (c->ddgst && chunk > 0) flags = (uint8_t)(flags | NVME_TCP_F_DDGST);

        uint32_t data_off = NVME_TCP_DATA_PDU_LEN + (c->hdgst ? 4u : 0u);
        uint32_t total = data_off + chunk + ((c->ddgst && chunk > 0) ? 4u : 0u);

        s_c2h_buf[0] = NVME_TCP_PDU_C2H_DATA;
        s_c2h_buf[1] = flags;
        s_c2h_buf[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        s_c2h_buf[3] = (uint8_t)data_off;  /* pdo */
        wr32le(&s_c2h_buf[4], total);      /* plen */
        wr16le(&s_c2h_buf[8],  cid);
        wr16le(&s_c2h_buf[10], 0);       /* ttag: C2HDataでは未使用 */
        wr32le(&s_c2h_buf[12], sent);    /* datao */
        wr32le(&s_c2h_buf[16], chunk);   /* datal */
        wr32le(&s_c2h_buf[20], 0);       /* reserved */

        nvmet_tcp_append_hdgst(c, s_c2h_buf, NVME_TCP_DATA_PDU_LEN);

        volatile_fast_copy((volatile uint8_t *)&s_c2h_buf[data_off],
                            (const volatile uint8_t *)(src + sent), chunk);

        /* データダイジェスト(有効かつchunk>0なら4バイト付加、2026-07-25追加)。 */
        nvmet_tcp_append_ddgst(c, s_c2h_buf, data_off, chunk);

        {
            volatile ts_nvme_pdu_t info = {0};
            info.pdu_type    = NVME_TCP_PDU_C2H_DATA;
            info.hlen        = (uint8_t)NVME_TCP_DATA_PDU_LEN;
            info.pdo         = (uint8_t)data_off;
            info.plen        = total;
            info.cccid       = cid;
            info.ttag        = 0;
            info.data_offset = sent;
            info.data_length = chunk;
            ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_c2h, 0), &info);
        }

        if (tcp_send(&c->tcp, s_c2h_buf, total) != (int)total) {
            uart_printf("[!] NVMe/TCP target: C2HData送信失敗 (offset=%u len=%u)\n", sent, chunk);
            return -1;
        }
        sent += chunk;
    }

    if (!data_success) {
        return nvmet_tcp_send_resp(c, cqe);
    }
    return 0;
}

/*
 * nvmet_tcp_send_c2h() の非同期・ゼロコピー版。data から直接 tcp_send_async()
 * へ渡し ACK を待たずに返る。ダイジェスト有効時は連続バッファが要るため
 * 使えない(呼び出し元が同期版へフォールバックする)。
 *
 * 引数:
 *   c / cid / cqe / data / dlen - nvmet_tcp_send_c2h() と同じ
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   nvmet_io_dispatch_cmd()
 */
int nvmet_tcp_send_c2h_async(nvmet_tcp_conn_t *c, uint16_t cid,
                              const void *data, uint32_t dlen)
{
    if (dlen > NVMET_TCP_C2H_CHUNK_MAX) {
        uart_printf("[!] NVMe/TCP target: C2HData非同期送信はdlen<=%u限定 (dlen=%u)\n",
                    NVMET_TCP_C2H_CHUNK_MAX, dlen);
        return -1;
    }

    uint8_t hdr[NVME_TCP_DATA_PDU_LEN];
    hdr[0] = NVME_TCP_PDU_C2H_DATA;
    hdr[1] = (uint8_t)(NVME_TCP_F_DATA_LAST | NVME_TCP_F_DATA_SUCCESS);
    hdr[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
    hdr[3] = (uint8_t)NVME_TCP_DATA_PDU_LEN;  /* pdo: データはこのPDU内の固定部直後 */
    wr32le(&hdr[4], NVME_TCP_DATA_PDU_LEN + dlen);  /* plen */
    wr16le(&hdr[8],  cid);
    wr16le(&hdr[10], 0);       /* ttag: C2HDataでは未使用 */
    wr32le(&hdr[12], 0);       /* datao: 単一PDU限定のため常に0 */
    wr32le(&hdr[16], dlen);    /* datal */
    wr32le(&hdr[20], 0);       /* reserved */

    if (tcp_send_async(&c->tcp, hdr, (uint16_t)NVME_TCP_DATA_PDU_LEN) < 0) {
        uart_printf("[!] NVMe/TCP target: C2HDataヘッダ非同期送信失敗 (cid=%u)\n", cid);
        return -1;
    }

    const uint8_t *src = (const uint8_t *)data;
    uint32_t queued = 0;
    while (queued < dlen) {
        uint32_t remaining = dlen - queued;
        uint16_t chunk = (remaining > TCP_ASYNC_MAX_LEN) ? (uint16_t)TCP_ASYNC_MAX_LEN : (uint16_t)remaining;
        int rc = tcp_send_async_ref(&c->tcp, src + queued, chunk);
        if (rc < 0) {
            uart_printf("[!] NVMe/TCP target: C2HDataデータ非同期送信失敗 (cid=%u offset=%u)\n",
                        cid, queued);
            return -1;
        }
        queued += (uint32_t)rc;
    }

    /* NSND(旧NC2H)。 */
    {
        volatile ts_nvme_pdu_t info = {0};
        info.pdu_type    = NVME_TCP_PDU_C2H_DATA;
        info.hlen        = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        info.pdo         = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        info.plen        = NVME_TCP_DATA_PDU_LEN + dlen;
        info.cccid       = cid;
        info.data_offset = 0;
        info.data_length = dlen;
        ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_c2h_async, 0), &info);
    }
    return 0;
}

/*
 * NVMe/TCP コネクションの TCP を切断し、状態をクリアする。
 *
 * 引数:
 *   c - 対象コネクション
 * コール元:
 *   nvmet_admin_job_step(), nvmet_admin_job_setup_fail(), nvmet_io_job_end()
 */
void nvmet_tcp_close(nvmet_tcp_conn_t *c)
{
    tcp_close(&c->tcp);
}
