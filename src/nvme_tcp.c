#include <stddef.h>
#include "nvme_tcp.h"
#include "nvme_tcp_pdu.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "job.h"
#include "timestamp.h"
#include "crc32c.h"

#define NVME_TCP_ICRESP_TIMEOUT_MS 3000u
#define NVME_TCP_RESP_TIMEOUT_MS   10000u

#define NVME_TCP_H2C_CHUNK_MAX 262144u

/*=================================================================
 * ヘッダダイジェストが有効なら 4、無効なら 0 を返す。PDU の plen/pdo や
 * 受信長の計算を全て同じ式で書けるようにするための共通ヘルパ。
 *
 * 引数:
 *   c - 対象コネクション
 * 戻り値:
 *   0 か 4
 * コール元:
 *   nvme_tcp_send_cmd(), nvme_tcp_send_cmd_async(),
 *   nvme_tcp_send_h2c_data_ex(), nvme_exec_step(),
 *   nvme_pipeline_rx_tick(), nvme_pipeline_h2c_pump(),
 *   nvme_read_rx_upcall(), nvme_pipeline_read_rx_tick()
 * ===============================================================*/
uint32_t nvme_tcp_hdgst_len(const nvme_tcp_conn_t *c)
{
    return c->hdgst ? NVME_TCP_DGST_LEN : 0u;
}

/*=================================================================
 * データダイジェストが有効かつ dlen>0 なら 4、そうでなければ 0 を返す
 * (データ長 0 の PDU にはデータダイジェストを付けない仕様)。
 *
 * 引数:
 *   c    - 対象コネクション
 *   dlen - そのPDUのデータ本体長
 * 戻り値:
 *   0 か 4
 * コール元:
 *   nvme_tcp_send_cmd(), nvme_tcp_send_h2c_data_ex(),
 *   nvme_exec_step(), nvme_pipeline_h2c_pump(),
 *   nvme_read_rx_upcall(), nvme_pipeline_read_rx_tick()
 * ===============================================================*/
uint32_t nvme_tcp_ddgst_len(const nvme_tcp_conn_t *c, uint32_t dlen)
{
    return (c->ddgst && dlen > 0u) ? NVME_TCP_DGST_LEN : 0u;
}

volatile uint32_t g_nvme_tcp_hdgst_corrupt;  /* 検証用(シェルの `hdgstcorrupt`)*/
volatile uint32_t g_nvme_tcp_term_sent;
volatile uint32_t g_nvme_tcp_term_recv;

/*=================================================================
 * ヘッダダイジェストが有効なら buf[0..hlen) の CRC32C を buf[hlen..+4) へ
 * 書く。**呼び出し元は先に flags/plen/pdo など hlen 範囲の全フィールドを
 * 最終状態まで確定させておくこと**(target 側実装で実機 2 回踏んだ罠で、
 * ダイジェスト計算後にヘッダを書き換えると相手側の検証だけが静かに失敗する)。
 *
 * 引数:
 *   c    - 対象コネクション
 *   buf  - PDU ヘッダ先頭
 *   hlen - ヘッダ長
 * 戻り値:
 *   付加したバイト数(0 か 4)
 * コール元:
 *   nvme_tcp_send_cmd(), nvme_tcp_send_cmd_async(), nvme_tcp_send_h2c_data_ex()
 * ===============================================================*/
uint32_t nvme_tcp_append_hdgst(nvme_tcp_conn_t *c, uint8_t *buf, uint32_t hlen)
{
    if (!c->hdgst) return 0u;
    uint32_t crc = ~crc32c(0xFFFFFFFFu, buf, hlen);  /* 最終反転(crc32c.hコメント参照) */
    if (g_nvme_tcp_hdgst_corrupt != 0u) {
        /* 検証用のヘッダダイジェスト破壊(シェルの `hdgstcorrupt`)。
         * ターゲット側の同名の仕掛けと対。 */
        g_nvme_tcp_hdgst_corrupt--;
        crc ^= 0x00000001u;
    }
    wr32le(&buf[hlen], crc);
    return NVME_TCP_DGST_LEN;
}

/*=================================================================
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
 *   nvme_tcp_send_cmd(), nvme_tcp_send_h2c_data_ex()
 * ===============================================================*/
uint32_t nvme_tcp_append_ddgst(nvme_tcp_conn_t *c, uint8_t *buf,
                                uint32_t data_off, uint32_t dlen)
{
    if (!c->ddgst || dlen == 0u) return 0u;
    uint32_t crc = ~crc32c(0xFFFFFFFFu, &buf[data_off], dlen);  /* 最終反転 */
    wr32le(&buf[data_off + dlen], crc);
    return NVME_TCP_DGST_LEN;
}

/*=================================================================
 * 受信したヘッダダイジェストを検証する(I/O を伴わない純粋な計算)。
 * 共通ヘッダ部と型固有部が別バッファに分かれて届くため 2 領域を受ける。
 *
 * 引数:
 *   c               - 対象コネクション
 *   hdr1 / len1     - 共通ヘッダ部
 *   hdr2 / len2     - 型固有部(無ければ NULL / 0)
 *   got             - 受信した 4 バイトのダイジェスト
 * 戻り値:
 *   0=一致(無効時も 0)、-1=不一致
 * コール元:
 *   nvme_exec_step(), nvme_pipeline_rx_tick(),
 *   nvme_read_rx_upcall(), nvme_pipeline_read_rx_tick()
 * ===============================================================*/
int nvme_tcp_verify_hdgst(const nvme_tcp_conn_t *c,
                           const void *hdr1, uint32_t len1,
                           const void *hdr2, uint32_t len2,
                           const uint8_t got[4])
{
    if (!c->hdgst) return 0;
    uint32_t expected = crc32c(0xFFFFFFFFu, hdr1, len1);
    if (hdr2 && len2 > 0u) expected = crc32c(expected, hdr2, len2);
    expected = ~expected;  /* 最終反転 */

    uint32_t g = rd32le(got);
    if (g != expected) {
        uart_printf("[!] NVMe/TCP: ヘッダCRC32C不一致 (expected=%08x got=%08x)\n", expected, g);
        return -1;
    }
    return 0;
}

/*=================================================================
 * 受信したデータダイジェストを、データ本体を一括で読み直して検証する。
 *
 * 引数:
 *   c          - 対象コネクション
 *   data / len - データ本体
 *   got        - 受信した 4 バイトのダイジェスト
 * 戻り値:
 *   0=一致(無効時も 0)、-1=不一致
 * コール元:
 *   nvme_exec_step(), nvme_pipeline_read_rx_tick()
 * ===============================================================*/
int nvme_tcp_verify_ddgst(const nvme_tcp_conn_t *c,
                           const void *data, uint32_t len,
                           const uint8_t got[4])
{
    if (!c->ddgst || len == 0u) return 0;
    return nvme_tcp_check_ddgst_crc(c, crc32c(0xFFFFFFFFu, data, len), got);
}

/*=================================================================
 * データを逐次受け取りながら積み上げた CRC32C(未反転)を、受信した
 * データダイジェストと突き合わせる。push 型受信のようにデータ本体を
 * 後からまとめて読み直せない経路で使う。
 *
 * 引数:
 *   c           - 対象コネクション
 *   running_crc - crc32c() を連鎖させた未反転の途中値
 *   got         - 受信した 4 バイトのダイジェスト
 * 戻り値:
 *   0=一致(無効時も 0)、-1=不一致
 * コール元:
 *   nvme_tcp_verify_ddgst(), nvme_read_rx_upcall()
 * ===============================================================*/
int nvme_tcp_check_ddgst_crc(const nvme_tcp_conn_t *c, uint32_t running_crc,
                              const uint8_t got[4])
{
    if (!c->ddgst) return 0;
    uint32_t expected = ~running_crc;  /* 最終反転 */
    uint32_t g = rd32le(got);
    if (g != expected) {
        uart_printf("[!] NVMe/TCP: データCRC32C不一致 (expected=%08x got=%08x)\n", expected, g);
        return -1;
    }
    return 0;
}

/*=================================================================
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
 * ===============================================================*/
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

    static uint8_t s_cmd_buf[NVME_TCP_CMD_PDU_LEN + 2u * NVME_TCP_DGST_LEN + NVME_TCP_INLINE_DATA_MAX]
        __attribute__((aligned(64)));

    uint16_t cid = c->next_cid++;
    int has_inline_data = (!use_r2t && data != NULL && dlen > 0);

    /* ダイジェスト長を先に確定させ、pdo/plen/flags を最終値で書いてから
     * append_hdgst() を呼ぶ(ヘッダを後から書き換えてはならない)。 */
    uint32_t inline_len = has_inline_data ? dlen : 0u;
    uint32_t hd = nvme_tcp_hdgst_len(c);
    uint32_t dd = nvme_tcp_ddgst_len(c, inline_len);
    uint32_t data_off = NVME_TCP_CMD_PDU_LEN + hd;

    s_cmd_buf[0] = NVME_TCP_PDU_CMD;
    s_cmd_buf[1] = (uint8_t)((c->hdgst ? NVME_TCP_F_HDGST : 0u) | (dd ? NVME_TCP_F_DDGST : 0u));
    s_cmd_buf[2] = (uint8_t)NVME_TCP_CMD_PDU_LEN;
    s_cmd_buf[3] = has_inline_data ? (uint8_t)data_off : 0;  /* pdo: in-capsuleデータの開始位置 */
    wr32le(&s_cmd_buf[4], data_off + inline_len + dd);

    volatile_fast_copy((volatile uint8_t *)&s_cmd_buf[NVME_TCP_HDR_LEN],
                        (const volatile uint8_t *)sqe, NVME_SQE_LEN);
    wr16le(&s_cmd_buf[NVME_TCP_HDR_LEN + 2], cid);

    nvme_tcp_append_hdgst(c, s_cmd_buf, NVME_TCP_CMD_PDU_LEN);

    uint32_t total_len = data_off;
    if (has_inline_data) {
        volatile_fast_copy((volatile uint8_t *)&s_cmd_buf[data_off],
                            (const volatile uint8_t *)data, dlen);
        total_len = data_off + dlen + nvme_tcp_append_ddgst(c, s_cmd_buf, data_off, dlen);
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

/*=================================================================
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
 * ===============================================================*/
int nvme_tcp_send_cmd_async(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe, uint16_t *out_cid)
{
    static uint8_t s_cmd_async_buf[NVME_TCP_CMD_PDU_LEN + NVME_TCP_DGST_LEN]
        __attribute__((aligned(64)));

    uint16_t cid = c->next_cid++;
    uint32_t hd = nvme_tcp_hdgst_len(c);

    s_cmd_async_buf[0] = NVME_TCP_PDU_CMD;
    s_cmd_async_buf[1] = (uint8_t)(c->hdgst ? NVME_TCP_F_HDGST : 0u);
    s_cmd_async_buf[2] = (uint8_t)NVME_TCP_CMD_PDU_LEN;
    s_cmd_async_buf[3] = 0;  /* pdo: in-capsuleデータ無し */
    wr32le(&s_cmd_async_buf[4], NVME_TCP_CMD_PDU_LEN + hd);

    volatile_fast_copy((volatile uint8_t *)&s_cmd_async_buf[NVME_TCP_HDR_LEN],
                        (const volatile uint8_t *)sqe, NVME_SQE_LEN);
    wr16le(&s_cmd_async_buf[NVME_TCP_HDR_LEN + 2], cid);

    nvme_tcp_append_hdgst(c, s_cmd_async_buf, NVME_TCP_CMD_PDU_LEN);

    if (tcp_send_async(&c->tcp, s_cmd_async_buf, (uint16_t)(NVME_TCP_CMD_PDU_LEN + hd)) < 0) {
        uart_printf("[!] NVMe/TCP: CapsuleCmd非同期送信失敗 (cid=%u)\n", cid);
        return -1;
    }
    if (out_cid) {
        *out_cid = cid;
    }
    return 0;
}

/*=================================================================
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
 * ===============================================================*/
int nvme_tcp_send_h2c_data_ex(nvme_tcp_conn_t *c, uint16_t cid, uint16_t ttag,
                               uint32_t r2to, uint32_t r2tl,
                               const void *data, uint32_t data_len)
{
    if (!data || (uint64_t)r2to + (uint64_t)r2tl > (uint64_t)data_len) {
        uart_printf("[!] NVMe/TCP: R2Tが保留データ範囲外 (r2to=%u r2tl=%u data_len=%u)\n",
                    r2to, r2tl, data_len);
        return -1;
    }

    static uint8_t s_h2c_buf[NVME_TCP_DATA_PDU_LEN + 2u * NVME_TCP_DGST_LEN + NVME_TCP_H2C_CHUNK_MAX]
        __attribute__((aligned(64)));

    const uint8_t *src = (const uint8_t *)data;
    uint32_t hd = nvme_tcp_hdgst_len(c);
    uint32_t data_off = NVME_TCP_DATA_PDU_LEN + hd;
    uint32_t sent = 0;
    while (sent < r2tl) {
        uint32_t chunk = r2tl - sent;
        if (chunk > NVME_TCP_H2C_CHUNK_MAX) chunk = NVME_TCP_H2C_CHUNK_MAX;
        int last = (sent + chunk == r2tl);
        uint32_t dd = nvme_tcp_ddgst_len(c, chunk);

        s_h2c_buf[0] = NVME_TCP_PDU_H2C_DATA;
        s_h2c_buf[1] = (uint8_t)((last ? NVME_TCP_F_DATA_LAST : 0u) |
                                 (c->hdgst ? NVME_TCP_F_HDGST : 0u) |
                                 (dd ? NVME_TCP_F_DDGST : 0u));
        s_h2c_buf[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        s_h2c_buf[3] = (uint8_t)data_off;  /* pdo: データはヘッダ(+hdgst)の直後 */
        wr32le(&s_h2c_buf[4], data_off + chunk + dd);
        wr16le(&s_h2c_buf[8],  cid);
        wr16le(&s_h2c_buf[10], ttag);
        wr32le(&s_h2c_buf[12], r2to + sent);
        wr32le(&s_h2c_buf[16], chunk);
        wr32le(&s_h2c_buf[20], 0);  /* reserved */

        nvme_tcp_append_hdgst(c, s_h2c_buf, NVME_TCP_DATA_PDU_LEN);

        volatile_fast_copy((volatile uint8_t *)&s_h2c_buf[data_off],
                            (const volatile uint8_t *)(src + r2to + sent), chunk);
        nvme_tcp_append_ddgst(c, s_h2c_buf, data_off, chunk);

        uint32_t total = data_off + chunk + dd;
        if (tcp_send(&c->tcp, s_h2c_buf, total) != (int)total) {
            uart_printf("[!] NVMe/TCP: H2CData送信失敗 (offset=%u len=%u)\n", r2to + sent, chunk);
            return -1;
        }
        sent += chunk;
    }
    return 0;
}

/*=================================================================
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
 * ===============================================================*/
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

/*=================================================================
 * コネクション確立直後の ICReq PDU を送信する(PDU データダイジェスト等の
 * ネゴシエーション開始)。
 *
 * 引数:
 *   c - 送信先コネクション
 * 戻り値:
 *   0=送信完了、-1=失敗
 * コール元:
 *   nvme_connect_job_step()
 * ===============================================================*/
/*=================================================================
 * Terminate Connection Request(H2C TermReq)を送る。
 *
 * イニシエータ側でプロトコル上の致命的な誤りを見つけたときに、TCP を
 * 閉じる前に理由(FES)を伝える。ターゲット側の nvmet_tcp_send_term() と
 * 対になる(組み立ては nvme_tcp_pdu.h の共通ヘルパ)。
 *
 * 引数:
 *   c       - 対象コネクション
 *   fes     - Fatal Error Status(NVME_TCP_FES_*)
 *   fei     - Fatal Error Information(該当が無ければ 0)
 *   pdu     - 原因になった PDU の先頭(NULL 可)
 *   pdu_len - そのバイト数
 * 戻り値:
 *   0=送信できた、-1=失敗
 * コール元:
 *   nvme_exec_step(), nvme_pipeline_rx_step()
 * ===============================================================*/
int nvme_tcp_send_term(nvme_tcp_conn_t *c, uint16_t fes, uint32_t fei,
                        const uint8_t *pdu, uint32_t pdu_len)
{
    static uint8_t s_term_buf[NVME_TCP_TERM_PLEN_MAX] __attribute__((aligned(64)));
    uint32_t total = nvme_tcp_build_term(s_term_buf, NVME_TCP_PDU_H2C_TERM,
                                          fes, fei, pdu, pdu_len);
    g_nvme_tcp_term_sent++;
    uart_printf("[NVMe/TCP] H2C TermReq 送信 (fes=0x%02x fei=0x%x len=%u)\n",
                (unsigned)fes, (unsigned)fei, (unsigned)total);
    if (c->tcp.state != TCP_ESTABLISHED) return -1;
    if (tcp_send(&c->tcp, s_term_buf, (uint16_t)total) != (int)total) {
        uart_printf("[!] NVMe/TCP: H2C TermReq 送信失敗\n");
        return -1;
    }
    return 0;
}

int nvme_tcp_send_icreq(nvme_tcp_conn_t *c)
{
    c->maxdata      = 8192u;  /* ICRespが届くまでの暫定値 */
    c->next_cid     = 0;
    c->pending_data = NULL;
    c->pending_len  = 0;
    c->pending_cid  = 0;
    /* ICReq/ICResp 自体はダイジェスト対象外。合意結果が確定するまで無効に
     * しておく(req_hdgst/req_ddgst は呼び出し側が接続前に設定済み)。 */
    c->hdgst        = 0;
    c->ddgst        = 0;

    static uint8_t s_icreq_buf[NVME_TCP_ICREQ_LEN] __attribute__((aligned(64)));
    for (uint32_t i = 0; i < NVME_TCP_ICREQ_LEN; i++) s_icreq_buf[i] = 0;

    s_icreq_buf[0] = NVME_TCP_PDU_ICREQ;         /* hdr.type */
    s_icreq_buf[1] = 0;                          /* hdr.flags */
    s_icreq_buf[2] = (uint8_t)NVME_TCP_ICREQ_LEN; /* hdr.hlen */
    s_icreq_buf[3] = 0;                          /* hdr.pdo (可変長データ無し) */
    wr32le(&s_icreq_buf[4], NVME_TCP_ICREQ_LEN);  /* hdr.plen */
    wr16le(&s_icreq_buf[8], 0);   /* pfv */
    s_icreq_buf[10] = 0;          /* hpda */
    /* digest: bit0=header、bit1=data。合意結果はICRespを見て確定させる。 */
    s_icreq_buf[11] = (uint8_t)((c->req_ddgst ? 0x02u : 0u) | (c->req_hdgst ? 0x01u : 0u));
    wr32le(&s_icreq_buf[12], 0);  /* maxr2t: 0 = 同時に1個のR2Tまで */
    /* reserved[112]は上のループで既に0クリア済み */

    uart_printf("[NVMe/TCP] ICReq送信 (hdgst要求=%u ddgst要求=%u)\n",
                c->req_hdgst, c->req_ddgst);
    if (tcp_send(&c->tcp, s_icreq_buf, (uint16_t)NVME_TCP_ICREQ_LEN) != (int)NVME_TCP_ICREQ_LEN) {
        uart_printf("[!] NVMe/TCP: ICReq送信失敗\n");
        return -1;
    }
    return 0;
}

/*=================================================================
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
 * ===============================================================*/
int nvme_tcp_verify_icresp(nvme_tcp_conn_t *c, const uint8_t icresp_buf[NVME_TCP_ICRESP_LEN])
{
    uint8_t type = icresp_buf[0];
    uint8_t hlen = icresp_buf[2];
    if (type != NVME_TCP_PDU_ICRESP || hlen != (uint8_t)NVME_TCP_ICRESP_LEN) {
        uart_printf("[!] NVMe/TCP: 不正なICResp (type=%u hlen=%u)\n", type, hlen);
        return -1;
    }
    /* target は要求したビットのうち受け入れたものだけを返す。要求していない
     * ビットが立っていたら合意できていないので接続を中止する。 */
    uint8_t digest = icresp_buf[11];
    uint8_t acc_h = (uint8_t)(digest & 0x01u);
    uint8_t acc_d = (uint8_t)((digest >> 1) & 0x01u);
    if ((acc_h && !c->req_hdgst) || (acc_d && !c->req_ddgst)) {
        uart_printf("[!] NVMe/TCP: 要求していないdigestをtargetが返した (digest=0x%02x)\n", digest);
        return -1;
    }
    c->hdgst = acc_h;
    c->ddgst = acc_d;

    c->maxdata = rd32le(&icresp_buf[12]);
    uart_printf("[NVMe/TCP] ICResp受信: maxdata=%u hdgst=%u ddgst=%u\n",
                c->maxdata, c->hdgst, c->ddgst);
    return 0;
}

/*=================================================================
 * NVMe/TCP コネクションの TCP を切断し、状態をクリアする。
 *
 * 引数:
 *   c - 対象コネクション
 * コール元:
 *   nvme_connect_job_fail()
 * ===============================================================*/
void nvme_tcp_close(nvme_tcp_conn_t *c)
{
    tcp_close(&c->tcp);
}
