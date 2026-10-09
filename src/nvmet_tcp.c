#include <stddef.h>
#include "nvmet_tcp.h"
#include "nvme_tcp_pdu.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "crc32c.h"
#include "nvmet_tls.h"

#define NVMET_TCP_C2H_CHUNK_MAX 262144u

#define NVMET_TCP_MAXH2CDATA_UNSCALED 32768u
#define NVMET_TCP_MAXH2CDATA_SCALED   262144u

/*=================================================================
 * このコネクションで 1 回の H2CData PDU に載せてよい最大データ長を返す
 * (ICResp で相手へ広告した MAXH2CDATA と同じ値)。
 *
 * 引数:
 *   c - 対象コネクション
 * 戻り値:
 *   最大バイト数
 * コール元:
 *   nvmet_tcp_send_icresp(), nvmet_io_dispatch_cmd(), nvmet_io_dispatch_h2c()
 * ===============================================================*/
uint32_t nvmet_tcp_max_h2c_data(const nvmet_tcp_conn_t *c)
{
    return tcp_window_scaling_enabled(&c->tcp)
        ? NVMET_TCP_MAXH2CDATA_SCALED
        : NVMET_TCP_MAXH2CDATA_UNSCALED;
}

/* **既定は 0 = 束ねない。** 実装して測ったが、パケットは 20% 減るのに
 * スループットは 9% 落ちた(相手の cpu0 は 85%->84% で変わらない)。
 * **相手を律速しているのはパケット数ではなかった。** 応答を溜めるぶん
 * レイテンシが増えるだけ損になる。仕組みは陰性の記録として残す
 * (`tcpnagle` と同じ扱い)。 */
volatile uint32_t g_nvmet_tcp_batch = 0u;

/*=================================================================
 * 溜め込んだ応答 PDU を 1 つの TCP セグメントとして吐き出す。
 *
 * **短経路(tcp_send_async2)で送り切ること。** 長経路(LSO)へ流すと
 * 壊れる(CLAUDE.md「まとめた送信を長経路へ流してはいけない」)。
 *
 * 引数:
 *   c - 対象コネクション
 * 戻り値:
 *   0=送信した/溜まっていない、-1=失敗
 * コール元:
 *   nvmet_tcp_tx_put(), nvmet_tcp_tx_batch_end()
 * ===============================================================*/
int nvmet_tcp_tx_flush(nvmet_tcp_conn_t *c)
{
    if (c->tx_batch_len == 0u) return 0;
    uint32_t n = c->tx_batch_len;
    c->tx_batch_len = 0u;
    if (tcp_send_async2(&c->tcp, c->tx_batch, (uint16_t)n, NULL, 0) < 0) {
        uart_printf("[!] NVMe/TCP target: まとめ送信に失敗 (%u バイト)\n", n);
        return -1;
    }
    return 0;
}

/*=================================================================
 * バッチ区間を開始する。以後 nvmet_tcp_tx_put() は溜め込む。
 * コール元: nvmet_io_job_step_impl() の ready-ring 排出ループ
 * ===============================================================*/
void nvmet_tcp_tx_batch_begin(nvmet_tcp_conn_t *c)
{
    if (g_nvmet_tcp_batch) c->tx_batching = 1u;
}

/*=================================================================
 * バッチ区間を終える。**溜まっているものは必ずここで吐き出す**
 * (残したまま park すると応答が止まる)。
 * コール元: nvmet_io_job_step_impl() の ready-ring 排出ループ
 * ===============================================================*/
int nvmet_tcp_tx_batch_end(nvmet_tcp_conn_t *c)
{
    c->tx_batching = 0u;
    return nvmet_tcp_tx_flush(c);
}

/*=================================================================
 * 1〜2 断片の PDU を送る。バッチ区間の中なら溜め込み、外なら即送信する。
 *
 * 引数:
 *   c        - 対象コネクション
 *   p1 / l1  - 1 断片目(PDU ヘッダ)
 *   p2 / l2  - 2 断片目(本体。無ければ NULL/0)
 * 戻り値:
 *   0=成功、-1=失敗
 * コール元:
 *   nvmet_tcp_send_r2t(), nvmet_tcp_send_resp(), nvmet_tcp_send_c2h_async()
 * ===============================================================*/
static int nvmet_tcp_tx_put(nvmet_tcp_conn_t *c, const void *p1, uint32_t l1,
                             const void *p2, uint32_t l2)
{
    uint32_t need = l1 + l2;
    if (c->tls) return nvmet_tls_send(c->tls, &c->tcp, p1, l1, p2, l2);   /* TLS は束ねない */
    if (!c->tx_batching || need > NVMET_TCP_TX_BATCH_MAX) {
        /* **溜まっているものを先に出してから**送る(順序を崩さない)。 */
        if (nvmet_tcp_tx_flush(c) != 0) return -1;
        return tcp_send_async2(&c->tcp, p1, (uint16_t)l1,
                               p2, (uint16_t)l2) < 0 ? -1 : 0;
    }
    if (c->tx_batch_len + need > NVMET_TCP_TX_BATCH_MAX) {
        if (nvmet_tcp_tx_flush(c) != 0) return -1;
    }
    volatile_fast_copy((volatile uint8_t *)&c->tx_batch[c->tx_batch_len],
                        (const volatile uint8_t *)p1, l1);
    c->tx_batch_len += l1;
    if (l2 != 0u) {
        volatile_fast_copy((volatile uint8_t *)&c->tx_batch[c->tx_batch_len],
                            (const volatile uint8_t *)p2, l2);
        c->tx_batch_len += l2;
    }
    return 0;
}

/* 既定で有効。**`tcpcoalesce off` が陰性対照**(まとめる前の挙動)。 */
volatile uint32_t g_nvmet_tcp_coalesce = 1u;

/* 検証用: 次に送る N 個のヘッダダイジェストをわざと壊す(シェルの
 * `hdgstcorrupt`)。**相手が誤りを検出して TermReq を返してくるかを
 * 確かめる唯一の手段**で、Linux 相手にも効く。 */
volatile uint32_t g_nvmet_tcp_hdgst_corrupt;
/* 検証側をわざと失敗させる(シェルの `hdgstcorrupt v`)。 */
volatile uint32_t g_nvmet_tcp_hdgst_verify_fail;
/* 送った / 受け取った TermReq の数。 */
volatile uint32_t g_nvmet_tcp_term_sent;
volatile uint32_t g_nvmet_tcp_term_recv;

/*=================================================================
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
 * ===============================================================*/
static uint32_t nvmet_tcp_append_hdgst(nvmet_tcp_conn_t *c, uint8_t *buf, uint32_t hlen)
{
    if (!c->hdgst) return 0;
    uint32_t crc = ~crc32c(0xFFFFFFFFu, buf, hlen);  /* 最終反転(crc32c.hコメント参照) */
    if (g_nvmet_tcp_hdgst_corrupt != 0u) {
        /* **検証用のヘッダダイジェスト破壊**(シェルの `hdgstcorrupt`)。
         * 相手が誤りを検出して TermReq を返してくるかを確かめる唯一の手段。
         * 自作 <-> 自作でも Linux 相手でも同じように効く。 */
        g_nvmet_tcp_hdgst_corrupt--;
        crc ^= 0x00000001u;
    }
    wr32le(&buf[hlen], crc);
    return 4u;
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
 *   nvmet_tcp_send_c2h()
 * ===============================================================*/
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
    if (c->tls) {
        /* TLS: 復号済みの平文(タグを検証したもの)から読む */
        int t = nvmet_tls_recv(c->tls, &c->tcp, x->buf + x->got, remain);
        if (t < 0) {
            uart_printf("[!] NVMe/TCP target: 受信中に相手が閉じた / TLS のレコードが壊れていた\n");
            return -1;
        }
        x->got += (uint32_t)t;
        return (x->got >= x->want) ? 1 : 0;
    }
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

/*=================================================================
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
 * ===============================================================*/
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

/*=================================================================
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
 * ===============================================================*/
int nvmet_tcp_verify_hdgst(const nvmet_tcp_conn_t *c,
                            const void *hdr1, uint32_t len1,
                            const void *hdr2, uint32_t len2,
                            const uint8_t got[4])
{
    if (!c->hdgst) return 0;
    uint32_t expected = crc32c(0xFFFFFFFFu, hdr1, len1);
    if (hdr2 && len2 > 0) expected = crc32c(expected, hdr2, len2);
    expected = ~expected;  /* 最終反転(crc32c.hコメント参照) */
    if (g_nvmet_tcp_hdgst_verify_fail != 0u) {
        /* **検証側をわざと失敗させる**(シェルの `hdgstcorrupt v`)。
         * 相手が正しく送ってきていても「壊れている」と判定するので、
         * **こちらが C2H TermReq を送る経路を、相手を選ばず試せる**
         * (Linux のホストは TermReq を送ってこないので、送信側を壊す
         * `hdgstcorrupt t` では相手のログに TermReq が出ない)。 */
        g_nvmet_tcp_hdgst_verify_fail--;
        expected ^= 0x00000001u;
    }

    uint32_t g = rd32le(got);
    if (g != expected) {
        uart_printf("[!] NVMe/TCP target: ヘッダCRC32C不一致 (expected=%08x got=%08x)\n",
                    expected, g);
        return -1;
    }
    return 0;
}

/*=================================================================
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
 * ===============================================================*/
int nvmet_tcp_verify_ddgst(const nvmet_tcp_conn_t *c,
                            const void *data, uint32_t len,
                            const uint8_t got[4])
{
    if (!c->ddgst || len == 0) return 0;
    return nvmet_tcp_check_ddgst_crc(c, crc32c(0xFFFFFFFFu, data, len), got);
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
 *   nvmet_tcp_verify_ddgst(), nvmet_io_rx_upcall()
 * ===============================================================*/
int nvmet_tcp_check_ddgst_crc(const nvmet_tcp_conn_t *c, uint32_t running_crc,
                               const uint8_t got[4])
{
    if (!c->ddgst) return 0;
    uint32_t expected = ~running_crc;  /* 最終反転 */
    uint32_t g = rd32le(got);
    if (g != expected) {
        uart_printf("[!] NVMe/TCP target: データCRC32C不一致 (expected=%08x got=%08x)\n",
                    expected, g);
        return -1;
    }
    return 0;
}

/*=================================================================
 * ブロックせずに accept の受け皿だけを用意する。早着 SYN を取りこぼさない
 * よう、実際に待ち始める前に呼んでおく。
 *
 * 引数:
 *   c        - 受け皿にするコネクション
 *   listener - リッスン中のソケット
 * コール元:
 *   nvmet_admin_job_step(), nvmet_io_job_step_impl()
 * ===============================================================*/
void nvmet_tcp_accept_arm(nvmet_tcp_conn_t *c, int listener)
{
    tcp_accept_begin(listener, &c->tcp);
}

/*=================================================================
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
 * ===============================================================*/
/*=================================================================
 * Terminate Connection Request(C2H TermReq)を送る。
 *
 * **プロトコル上の致命的な誤りを見つけたら、TCP を閉じる前にこれを送る**
 * のが NVMe/TCP の規約。送らないと相手のログには「接続が切れた」としか
 * 残らない(Linux は受け取ると FES を添えて表示する)。
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
 *   nvmet_tcp_send_icresp(), nvmet_admin_job_step(), nvmet_io_job_step_impl()
 * ===============================================================*/
int nvmet_tcp_send_term(nvmet_tcp_conn_t *c, uint16_t fes, uint32_t fei,
                         const uint8_t *pdu, uint32_t pdu_len)
{
    static uint8_t s_term_buf[NVME_TCP_TERM_PLEN_MAX] __attribute__((aligned(64)));
    uint32_t total = nvme_tcp_build_term(s_term_buf, NVME_TCP_PDU_C2H_TERM,
                                          fes, fei, pdu, pdu_len);
    g_nvmet_tcp_term_sent++;
    uart_printf("[NVMe/TCP target] C2H TermReq 送信 (fes=0x%02x fei=0x%x len=%u)\n",
                (unsigned)fes, (unsigned)fei, (unsigned)total);
    if (c->tcp.state != TCP_ESTABLISHED) return -1;
    if (c->tls) return nvmet_tls_send(c->tls, &c->tcp, s_term_buf, total, NULL, 0);
    if (tcp_send(&c->tcp, s_term_buf, (uint16_t)total) != (int)total) {
        uart_printf("[!] NVMe/TCP target: C2H TermReq 送信失敗\n");
        return -1;
    }
    return 0;
}

int nvmet_tcp_send_icresp(nvmet_tcp_conn_t *c, const uint8_t icreq_buf[NVME_TCP_ICREQ_LEN])
{
    uint8_t type = icreq_buf[0];
    if (type != NVME_TCP_PDU_ICREQ) {
        uart_printf("[!] NVMe/TCP target: 不正なICReq (type=%u)\n", type);
        /* ICReq を期待している場所に別の PDU が来た = ヘッダのフィールドが
         * 不正。**相手に理由を伝えてから閉じる。** */
        nvmet_tcp_send_term(c, NVME_TCP_FES_INVALID_PDU_HDR, 0,
                             icreq_buf, NVME_TCP_ICREQ_LEN);
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
    if (c->tls) {
        if (nvmet_tls_send(c->tls, &c->tcp, s_icresp_buf, NVME_TCP_ICRESP_LEN, NULL, 0) != 0) {
            uart_printf("[!] NVMe/TCP target: ICResp送信失敗(TLS)\n");
            return -1;
        }
        return 0;
    }
    if (tcp_send(&c->tcp, s_icresp_buf, (uint16_t)NVME_TCP_ICRESP_LEN) != (int)NVME_TCP_ICRESP_LEN) {
        uart_printf("[!] NVMe/TCP target: ICResp送信失敗\n");
        return -1;
    }
    return 0;
}

/*=================================================================
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
 * ===============================================================*/
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

    if (nvmet_tcp_tx_put(c, s_r2t_buf, total, NULL, 0) != 0) {
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

    if (nvmet_tcp_tx_put(c, s_resp_buf, total, NULL, 0) != 0) {
        uart_printf("[!] NVMe/TCP target: Response Capsule送信失敗 (cid=%u)\n", cqe->cid);
        return -1;
    }
    return 0;
}

/*=================================================================
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
 * ===============================================================*/
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

        if (c->tls ? nvmet_tls_send(c->tls, &c->tcp, s_c2h_buf, total, NULL, 0) != 0
                   : tcp_send(&c->tcp, s_c2h_buf, total) != (int)total) {
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

/*=================================================================
 * nvmet_tcp_send_c2h() の非同期・ゼロコピー版。data から直接 tcp_send_async()
 * へ渡し ACK を待たずに返る。ダイジェストは送信元バッファから直接算出して
 * 4 バイトだけ追加でキューするので、連続バッファへのコピーは要らない
 * (以前は「計算に連続バッファが必要」として同期版へ退避していた)。
 *
 * 引数:
 *   c / cid / data / dlen - nvmet_tcp_send_c2h() と同じ
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   nvmet_io_dispatch_cmd()
 * ===============================================================*/
int nvmet_tcp_send_c2h_async(nvmet_tcp_conn_t *c, uint16_t cid,
                              const void *data, uint32_t dlen)
{
    if (dlen > NVMET_TCP_C2H_CHUNK_MAX) {
        uart_printf("[!] NVMe/TCP target: C2HData非同期送信はdlen<=%u限定 (dlen=%u)\n",
                    NVMET_TCP_C2H_CHUNK_MAX, dlen);
        return -1;
    }

    /* ダイジェスト長を先に確定させ、flags/pdo/plen を最終値で書いてから
     * append_hdgst() を呼ぶ(ヘッダを後から書き換えてはならない)。 */
    uint32_t hd = c->hdgst ? 4u : 0u;
    uint32_t dd = (c->ddgst && dlen > 0u) ? 4u : 0u;
    uint32_t data_off = NVME_TCP_DATA_PDU_LEN + hd;

    uint8_t hdr[NVME_TCP_DATA_PDU_LEN + 4u];
    hdr[0] = NVME_TCP_PDU_C2H_DATA;
    hdr[1] = (uint8_t)(NVME_TCP_F_DATA_LAST | NVME_TCP_F_DATA_SUCCESS |
                       (c->hdgst ? NVME_TCP_F_HDGST : 0u) |
                       (dd ? NVME_TCP_F_DDGST : 0u));
    hdr[2] = (uint8_t)NVME_TCP_DATA_PDU_LEN;
    hdr[3] = (uint8_t)data_off;  /* pdo: データはヘッダ(+hdgst)の直後 */
    wr32le(&hdr[4], data_off + dlen + dd);  /* plen */
    wr16le(&hdr[8],  cid);
    wr16le(&hdr[10], 0);       /* ttag: C2HDataでは未使用 */
    wr32le(&hdr[12], 0);       /* datao: 単一PDU限定のため常に0 */
    wr32le(&hdr[16], dlen);    /* datal */
    wr32le(&hdr[20], 0);       /* reserved */
    nvmet_tcp_append_hdgst(c, hdr, NVME_TCP_DATA_PDU_LEN);

    const uint8_t *src = (const uint8_t *)data;

    if (c->tls) {
        /* TLS: 暗号化先が要るのでゼロコピーは使わない。ヘッダと本体を
         * 同じレコードへ詰め、データダイジェストがあれば続けて送る。 */
        if (nvmet_tls_send(c->tls, &c->tcp, hdr, (uint32_t)NVME_TCP_DATA_PDU_LEN + hd, src, dlen) != 0) {
            uart_printf("[!] NVMe/TCP target: C2HData送信失敗(TLS、cid=%u)\n", cid);
            return -1;
        }
        if (dd) {
            uint8_t d[4];
            wr32le(d, ~crc32c(0xFFFFFFFFu, src, dlen));
            if (nvmet_tls_send(c->tls, &c->tcp, d, 4u, NULL, 0) != 0) return -1;
        }
        goto sent;
    }

    /* **ヘッダと本体を 1 つの TCP セグメントにまとめる。** 別々に送ると
     * **read 応答 1 個が 2 パケットになり、相手のパケット処理を 2 倍消費する**
     * (実測で相手の受信パケット/コマンドが 2.4)。write は 24 バイトの応答
     * 1 個で済むので、**これが「read だけ遅い」という非対称の正体**だった。
     * イニシエータ側の in-capsule write でまったく同じ形を直してある
     * (CLAUDE.md「1 コマンドを 2 パケットで送っていた」)。
     *
     * ゼロコピー(`tcp_send_async_ref`)は捨てて再送スロットへ写すことになるが、
     * **どのみち再送用に控える必要がある**ので増える費用はコピー 1 回だけ。
     * データダイジェストがあるときは 3 断片目が付くのでまとめない。 */
    if (g_nvmet_tcp_coalesce && dd == 0u &&
        (uint32_t)NVME_TCP_DATA_PDU_LEN + hd + dlen <= TCP_ASYNC_SHORT_SLOT_BYTES) {
        if (nvmet_tcp_tx_put(c, hdr, (uint32_t)NVME_TCP_DATA_PDU_LEN + hd,
                             src, dlen) != 0) {
            uart_printf("[!] NVMe/TCP target: C2HData非同期送信失敗 (cid=%u)\n", cid);
            return -1;
        }
        goto sent;
    }

    if (tcp_send_async(&c->tcp, hdr, (uint16_t)(NVME_TCP_DATA_PDU_LEN + hd)) < 0) {
        uart_printf("[!] NVMe/TCP target: C2HDataヘッダ非同期送信失敗 (cid=%u)\n", cid);
        return -1;
    }

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

    if (dd) {
        uint8_t d[4];
        wr32le(d, ~crc32c(0xFFFFFFFFu, src, dlen));  /* 最終反転 */
        if (tcp_send_async(&c->tcp, d, 4u) < 0) {
            uart_printf("[!] NVMe/TCP target: C2HDataダイジェスト送信失敗 (cid=%u)\n", cid);
            return -1;
        }
    }

sent:
    /* NSND(旧NC2H)。 */
    {
        volatile ts_nvme_pdu_t info = {0};
        info.pdu_type    = NVME_TCP_PDU_C2H_DATA;
        info.hlen        = (uint8_t)NVME_TCP_DATA_PDU_LEN;
        info.pdo         = (uint8_t)data_off;
        info.plen        = data_off + dlen + dd;
        info.cccid       = cid;
        info.data_offset = 0;
        info.data_length = dlen;
        ts_log_nvme_tcp_pdu(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_c2h_async, 0), &info);
    }
    return 0;
}

/*=================================================================
 * NVMe/TCP コネクションの TCP を切断し、状態をクリアする。
 *
 * 引数:
 *   c - 対象コネクション
 * コール元:
 *   nvmet_admin_job_step(), nvmet_admin_job_setup_fail(), nvmet_io_job_end()
 * ===============================================================*/
void nvmet_tcp_close(nvmet_tcp_conn_t *c)
{
    if (c->tls) {
        nvmet_tls_close(c->tls, &c->tcp);   /* 溜めた alert と close_notify を送る */
        c->tls = NULL;
    }
    tcp_close(&c->tcp);
}
