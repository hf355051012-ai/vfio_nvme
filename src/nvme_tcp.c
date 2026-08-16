// nvme_tcp.c
//
// NVMe/TCP (NVMe-oF TCPトランスポート) 接続・PDU送受信実装。
// tcp.c(多重コネクション対応後のTCPクライアント)の上に、ICReq/ICResp
// 交換・Command/Response Capsule・C2HData/R2T+H2CDataの送受信を組み立てる。
// プロトコル(SQE/CQEの意味づけ)はここでは扱わない -- nvme.cの責務。
//
// 全ての多バイトフィールドアクセスはnet.hのrd16le/rd32le/wr16le/wr32le
// (volatile経由のバイト単位アクセス)のみを使う(nvme_types.h/
// nvme_tcp_pdu.hのコメント参照 -- NVMeはリトルエンディアン)。

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

/* H2CData 1PDUあたりの最大データ量(このファイル内の静的ステージング
 * バッファのサイズ)。R2Tが要求するr2tlがこれより大きい場合は複数の
 * H2CData PDUに分割して送る(nvme_tcp_send_h2c_data()参照)。
 *
 * target側(nvmet.cのNIO_ST_DISPATCH_H2C)は「1回のR2Tにつき1回の
 * H2CDataが返ってくる」設計(受信量がwrite_lenに満たなければ次の
 * R2Tを送る、というpending_writesの状態遷移)になっており、複数の
 * H2CData PDUへ分割された応答を想定していない -- 旧値(4096)のまま
 * R2T分割(8KiB超のwrite)を実機テストしたところ、target側が1回の
 * R2T(r2tl)に対して届いた2個目以降のH2CDataチャンクでpending_writes
 * エントリを「未知のcccid」として見失いdesyncする実機バグを踏んだ
 * (2026-08-08)。target側の実装を変更するのはリスクが高いため、
 * client側のチャンクサイズをtarget側が1回のR2Tで要求しうる最大値
 * (nvmet_tcp.cのNVMET_TCP_MAXH2CDATA_SCALED=262144、Window Scaling
 * 成立時)以上にし、常に「1R2T=1H2CData」の対応関係を保つ形で回避した。 */
#define NVME_TCP_H2C_CHUNK_MAX 262144u

int nvme_tcp_send_cmd(nvme_tcp_conn_t *c, const nvme_sqe_t *sqe,
                      const void *data, uint32_t dlen)
{
    /* in-capsule送信かR2T+H2CData分割送信かは、呼び出し元(nvme.cの
     * nvme_build_write_sqe()等)がSQE自身に設定したSGL Descriptor Type
     * (sqe->dptr[15]、nvme_types.hのNVME_SGL_TYPE_*)で判定する
     * (2026-08-08、R2T分割実装 -- 以前はdlenの大小だけで無条件に
     * in-capsuleへ倒し8KiB超をエラーにしていた)。SQE自身に意図を
     * 持たせることで、SGL typeと実際のデータ送信有無が常に整合する --
     * 以前実機で踏んだ「型はin-capsuleを示すのに実際にはデータを送らず
     * pending_dataへ保留するだけ」という設計(target側がin-capsuleデータの
     * 続きをTCPストリームから読もうとしてブロックし、こちらはR2Tを
     * 待ってブロックする双方向デッドロック、nvme_types.hの
     * NVME_SGL_TYPE_DATA_BLOCK_OFFSETコメント参照)を、型とデータ送信を
     * 1箇所(呼び出し元のSQE構築)だけで決める構造にすることで再発させない。 */
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
    /* use_r2t の場合はデータを一切このPDUへ付加しない -- target はSGL
     * typeがTRANSPORTであることを見てR2Tを発行し、こちらはpending_data/
     * pending_len(dlen全体)からnvme_tcp_send_h2c_data()経由で応答する
     * (nvme_tcp_recv_resp()/nvme.cのnvme_exec_step()、いずれも既存の
     * R2T受信ロジックがそのまま機能する)。 */
    int has_inline_data = (!use_r2t && data != NULL && dlen > 0);

    s_cmd_buf[0] = NVME_TCP_PDU_CMD;
    s_cmd_buf[1] = 0;
    s_cmd_buf[2] = (uint8_t)NVME_TCP_CMD_PDU_LEN;
    s_cmd_buf[3] = has_inline_data ? (uint8_t)NVME_TCP_CMD_PDU_LEN : 0;  /* pdo: in-capsuleデータの開始位置 */
    wr32le(&s_cmd_buf[4], NVME_TCP_CMD_PDU_LEN + (has_inline_data ? dlen : 0u));

    volatile_fast_copy((volatile uint8_t *)&s_cmd_buf[NVME_TCP_HDR_LEN],
                        (const volatile uint8_t *)sqe, NVME_SQE_LEN);
    /* cidはコネクションごとに採番する(cdw0のbits[31:16]、SQE先頭からの
     * オフセット2-3) -- 呼び出し元(nvme.c)はこのフィールドを0のまま
     * sqeを渡してよい。ここでコピー後のバッファへ上書きする。 */
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

/* nvme_tcp_send_cmd()の非同期版 -- Command Capsule PDU(NVME_TCP_CMD_PDU_LEN
 * =72バイト固定、in-capsuleデータ無し)をtcp_send_async()で送る。
 * 2026-08-09、NVMe/TCPコマンドパイプライン化(nvme.cの
 * nvme_write_pipelined_run()参照)向け -- 複数スロットのSQEを連続送信する
 * 際、ブロッキングtcp_send()(nvme_tcp_send_cmd())では1件ごとに相手の
 * ACKを待つ遅延(実機`ts`計測でバースト内の送信間隔が約110-120us)が
 * 積み重なっていたため、`tcp_send_async()`(TCP_ASYNC_MAX_LEN=128、
 * tcp.h参照)経由に変更した。
 *
 * in-capsuleデータを伴う書き込み・Fabrics Connect等には対応しない
 * (SQEはR2T経路[TRANSPORT SGL type]専用) -- 呼び出し元は
 * nvme_write_pipelined_run()のみを想定する。
 *
 * 呼び出し規則: 戻った直後、呼び出し元は該当コネクション上のasync送信が
 * 全て確認される(tcp_send_async_drain())まで、同じコネクションへ
 * ブロッキングtcp_send()を呼んではならない(tcp.hのtcp_send_async()
 * 呼び出し規則コメント参照 -- H2CData送信[nvme_tcp_send_h2c_data_ex()]は
 * ブロッキングtcp_send()を使うため、呼び出し元[nvme_pipeline_rx_tick()]
 * がR2T受信時に必ずtcp_send_async_drain()を先に呼ぶ)。
 * 戻り値: 0=キュー成功(*out_cidに採番値)、-1=失敗 */
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

/* R2Tで要求された[r2to, r2to+r2tl)の範囲を、明示的に渡されたdata/
 * data_lenからH2CData PDU(1個以上、NVME_TCP_H2C_CHUNK_MAXごとに分割)
 * として送出する下位実装。cidも呼び出し元が明示する(c->pending_cidを
 * 暗黙参照しない) -- 2026-08-09、NVMe/TCPコマンドパイプライン化
 * (nvme.cのnvme_write_pipelined_run()参照)向けに、単一コネクション上で
 * 複数コマンドが同時に「保留中の書き込みデータ」を持てるようにする
 * ため、従来のconn単位の`pending_data/pending_len/pending_cid`から
 * 引数渡しへ切り出した(下記nvme_tcp_send_h2c_data()は互換ラッパとして
 * 従来通りconn->pending_*を渡すだけ、ロジックは完全に共有する)。 */
int nvme_tcp_send_h2c_data_ex(nvme_tcp_conn_t *c, uint16_t cid, uint16_t ttag,
                               uint32_t r2to, uint32_t r2tl,
                               const void *data, uint32_t data_len)
{
    if (!data || (uint64_t)r2to + (uint64_t)r2tl > (uint64_t)data_len) {
        uart_printf("[!] NVMe/TCP: R2Tが保留データ範囲外 (r2to=%u r2tl=%u data_len=%u)\n",
                    r2to, r2tl, data_len);
        return -1;
    }

    /* tcp_send()に渡すバッファは64バイトアラインすること(tcp.hの
     * tcp_send()ドキュメント参照)。ヘッダ(固定24バイト)+データチャンクを
     * 1本のバッファへ組み立ててから送る(tcp_send_segment()が結局データを
     * 内部バッファへコピーするため、ここでのアラインは必須要件では
     * 無くなっているかもしれないが、指示されている規約として維持する)。 */
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

        /* totalはuint32_t(2026-08-08、uint16_tから拡張): NVME_TCP_H2C_
         * CHUNK_MAXを262144へ拡張した際、この変数がuint16_tのまま残って
         * いたため、chunk(64KB以上)ではNVME_TCP_DATA_PDU_LEN(24)+chunkが
         * 65535を超えてuint16_tでオーバーフローし、実際にはヘッダ24
         * バイトだけを送ってペイロード本体を一切送らないまま「送信
         * 成功」と判定してしまうバグを実機で踏んだ(32768+24=32792は
         * 65535以下のため32KB以下のwriteでは問題化せず、64KB以上でのみ
         * 顕在化 -- target側がH2CDataのデータ本体を永久に待ち続けて
         * ハングする形で発現した)。tcp_send()のlen引数は既にuint32_t化
         * 済み(tcp.h参照)なので、こちらの型を合わせるだけで直る。 */
        uint32_t total = NVME_TCP_DATA_PDU_LEN + chunk;
        if (tcp_send(&c->tcp, s_h2c_buf, total) != (int)total) {
            uart_printf("[!] NVMe/TCP: H2CData送信失敗 (offset=%u len=%u)\n", r2to + sent, chunk);
            return -1;
        }
        sent += chunk;
    }
    return 0;
}

/* 元はnvme_tcp_recv_resp()専用のstaticヘルパだったが、ジョブ化
 * (nvme.cのnvme_exec_step()、nvme_tcp.h冒頭コメント参照)が単発の
 * ブロッキング送信状態として直接呼べるようnon-staticへ変更した。
 * 2026-08-09、上記nvme_tcp_send_h2c_data_ex()への薄いラッパへ変更
 * (ロジック自体は無変更、conn->pending_*を明示引数として渡すだけ)。 */
int nvme_tcp_send_h2c_data(nvme_tcp_conn_t *c, uint16_t ttag, uint32_t r2to, uint32_t r2tl)
{
    return nvme_tcp_send_h2c_data_ex(c, c->pending_cid, ttag, r2to, r2tl,
                                      c->pending_data, c->pending_len);
}

/* ================================================================
 * NVMe/TCP制御のジョブ化(nvme.c)向け非ブロッキング・resumable
 * プリミティブの実装(nvme_tcp.h冒頭コメント参照)。
 * ================================================================ */

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
    /* 【2026-08-11、nvmet_tcp.cのnvmet_tcp_recv_poll()で発見・修正した
     * のと同じ不要なuint16_t切り詰めバグ(そちら参照)をこちら[initiator
     * 側、READのC2HData/RSP受信]にも適用。tcp_recv()のmaxlenはuint32_t
     * なので、remainをそのまま渡して1回のポーリングでrx_bufに溜まって
     * いる分を上限なく汲み出せるようにする -- 呼び出し回数(および
     * それに伴うtcp_poll_once_ex()のオーバーヘッド)だけを削減する。 */
    /* timeout_ms=0: tcp_recv_internal()(tcp.c)のdo-while構造により、
     * tcp_poll_once()+受信チェックを1回だけ実行してから即座に返る --
     * nvme_tcp.h冒頭コメント参照。 */
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
        /* このxferで最初のバイトが届くまでにかかった時間(reset()からの
         * 経過us)。nvme.cのnvme_exec_step()の各受信ステート(RECV_HDR,
         * RECV_CQE, RECV_C2H_REST, RECV_C2H_DATA, RECV_R2T_REST)が
         * どれも内部でこの関数を呼ぶだけなので、ここ1箇所の計装で
         * 全ステートをカバーできる。
         * 2026-08-09、コア0のSEND_H2C/RECV_CQE遅延解析向けにユーザー
         * 指示で追加 -- 「相手からの応答そのものが遅い」のか「応答は
         * 届いているのにこちらの受信処理が遅れて気づいた」のかを、
         * NRDN(受信完了、reset()からの合計経過)との差分で切り分ける。 */
        ts_log(TS_MK(TS_FILE_NVME_TCP, TS_FUNC_nvme_tcp_recv_poll, 0), tcp_conn_arg(&c->tcp, (uint32_t)get_us_from(x->reset_tick)));
    }
    x->got += (uint32_t)n;
    if (x->got >= x->want) {
        ts_log(TS_MK(TS_FILE_NVME_TCP, TS_FUNC_nvme_tcp_recv_poll, 1), tcp_conn_arg(&c->tcp, (uint32_t)get_us_from(x->reset_tick)));
        return 1;
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

    /* ICReq(128バイト固定)。tcp_send()に渡すバッファは64バイトアライン
     * すること(tcp.hのtcp_send()ドキュメント参照)。 */
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

void nvme_tcp_close(nvme_tcp_conn_t *c)
{
    tcp_close(&c->tcp);
}
