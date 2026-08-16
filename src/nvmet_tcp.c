// nvmet_tcp.c
//
// NVMe/TCP (NVMe-oF TCPトランスポート) ターゲット側接続・PDU送受信実装。
// tcp.c(tcp_listen()/tcp_accept()による受動open対応後のTCPスタック)の
// 上に、ICReq/ICResp交換・Command Capsule受信・Response Capsule/C2HData
// 送信・R2T+H2CData受信を組み立てる。プロトコル(SQE/CQEの意味づけ)は
// ここでは扱わない -- nvmet.cの責務(イニシエータ側のnvme_tcp.c/nvme.cと
// 同じレイヤ分割)。IOキューのパイプライン対応の経緯はnvmet_tcp.h冒頭
// コメント参照。
//
// 全ての多バイトフィールドアクセスはnet.hのrd16le/rd32le/wr16le/wr32le
// (volatile経由のバイト単位アクセス)のみを使う(nvme_types.h/
// nvme_tcp_pdu.hのコメント参照 -- NVMeはリトルエンディアン)。

#include <stddef.h>
#include "nvmet_tcp.h"
#include "nvme_tcp_pdu.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "crc32c.h"

/* C2HData 1PDUあたりの最大データ量(このファイル内の静的ステージング
 * バッファのサイズ)。読み出しコマンドの応答データがこれより大きい場合は
 * 複数のC2HData PDUに分割して送る(nvmet_tcp_send_c2h()参照、通常は
 * 1コマンド=1PDUで収まる、下記参照)。
 *
 * 2026-07-25、実機でread(fio)がホスト側30秒タイムアウトで恒久的に失敗する
 * バグを発見・修正した。原因: nvmet_tcp_send_c2h()内の
 * `uint16_t total = (uint16_t)(NVME_TCP_DATA_PDU_LEN + chunk)` が、
 * このマクロが65536(=64KB)だった当時 24+65536=65560 となりuint16_tの上限
 * (65535)を25超えて折り返し `total=24` になっていた。折り返した24がその
 * ままtcp_send()に渡り、64KBのデータ本体を一切送らずヘッダ24バイトだけを
 * 送って「成功」と判定してしまう(tcp_send()の戻り値もtotal=24と一致する
 * ため、こちら側は一切エラーを検知できなかった)。tsログ上はSEND/SSEG/
 * SDONまで全て成功に見えるのに、C2HData PDUのLENフィールド(24)と
 * DATALフィールド(65536)が矛盾しているのが決め手になった。ホストは残り
 * 64KBのデータを待ち続け `nvme nvme0: queue 1: timeout cid ... opcode 0x2
 * (I/O Cmd)` でタイムアウトしていた。応急修正としてこのマクロを32768
 * (32KB)へ一旦縮小した。
 *
 * その直後、read(fio)の実効スループットがiodepthを上げても一切スケール
 * せず、常にtcpbenchの32768Bチャンク単発ストリーム性能(約17.7〜17.9MB/s、
 * CLAUDE.md「TCP/IPスタックの性能チューニング」節)にほぼ一致する上限に
 * 張り付く問題を確認した。原因はnvmet_io_loop()(nvmet.c)のREAD処理が
 * nvmet_tcp_send_c2h()を同期呼び出しし完全に完了するまで次のCMD PDUを
 * 読みに戻らないこと(WRITE側のs_pending_writes[]相当の並列処理機構が
 * 無い)、かつtcp_send()自体が「渡されたbuf/len全体が累積ACKされるまで
 * ブロックする」設計であることの組み合わせ。ただし調査の結果、WRITE同様の
 * コマンドレベル並列化(iodepth対応)は有効な処置ではないと判断した --
 * WRITEがdepthでスケールするのはR2T往復(1コマンドあたり最低1RTTの
 * 「データがまだ何も流れていない」空き時間)を複数コマンド間で隠蔽できる
 * ためだが、READにはR2T相当の往復が無く(CMD受信後ただちにC2HDataを
 * 送り始められる)、隠蔽すべきRTTがそもそも存在しない。真の原因は
 * このマクロが32768(32KB)だったため、256KBの読み出し1コマンドが
 * nvmet_tcp_send_c2h()内のwhileループで8個のPDUチャンクに分割され、
 * チャンクの境界ごとに「そのチャンクの最後の1バイトまで完全にACKされる
 * のを待ってから次のチャンクの送信を開始する」という完全ドレインの壁を
 * 8回踏んでいたこと -- 1回のtcp_send()呼び出し内では輻輳ウィンドウが
 * 許す限り複数セグメントを継続的にパイプライン送信できるのに、チャンク
 * 境界をまたぐたびにこのパイプラインを一度空にする分、概ね1RTT相当の
 * 純粋な空き時間をチャンク数だけ繰り返し無駄にしていた(tcp.hの
 * tcp_send()ドキュメント参照)。
 *
 * 恒久修正: tcp_send()のlen引数をuint16_t→uint32_tへ拡張し(tcp.h/tcp.c、
 * 内部のMSSセグメンテーションループは元々uint32_t演算だったため制限は
 * 引数の型だけが課していた人為的なもの)、このマクロをnvmet.hの
 * NVMET_MAX_TRANSFER_BYTES(256KB、1コマンドで許可する最大転送量)と
 * 同じ値まで引き上げた。これにより1コマンド分のデータ全体を単一の
 * PDU・単一のtcp_send()呼び出しで送れるようになり、上記のチャンク境界
 * バブルが原理的に発生しなくなる(dlenがNVMET_MAX_TRANSFER_BYTES以下で
 * ある限り、下のwhileループは常に1回で終わる -- nvmet.cのREAD処理に
 * dlenがこの上限を超えないことを保証する境界チェックを追加済み)。
 *
 * H2CData側(下記NVMET_TCP_MAXH2CDATA_UNSCALED/_SCALED)と異なりこちらは
 * Window Scaling成立/不成立で値を分けていない -- H2C側の2値化は「こちらが
 * 広告する受信ウィンドウが足りないと相手を永久に待たせるデッドロックに
 * なる」という非対称なリスクへの対処だったが、C2Hは向きが逆で、相手
 * (ホスト)の受信ウィンドウ/輻輳ウィンドウが実際にどれだけかはtcp_send()
 * 内部のusable_window計算が呼び出しのたびに動的に反映する(要求した
 * lenより実際に送れる量が少なくても、単に複数RTTかけて送り切るだけで
 * デッドロックにはならない)ため、値を分ける必要が無い。 */
#define NVMET_TCP_C2H_CHUNK_MAX 262144u

/* 単発のR2T/H2CData PDUで安全に要求・受信できるデータ量の上限(バイト)。
 * 2値ある理由: こちらが広告できる実際の受信ウィンドウは、そのTCP
 * コネクションでWindow Scaling(RFC7323、tcp.h参照)が成立しているか
 * どうかで大きく変わる(成立していれば最大TCP_RX_BUF_SIZE=512KB程度、
 * 不成立なら生の16bitフィールド上限65535に固定される、tcp.cの
 * tcp_send_segment()参照)。R2Tの1ラウンドで要求するデータ量が、その時点で
 * 実際に広告できるウィンドウを超えると、こちらはラウンド全体を一括で
 * 広告した後は明示的なwindow更新ACKを送らない設計(nvmet_tcp_recv_exact()
 * が使うtcp_recv_no_ack()、下記コメント参照)のため、相手はウィンドウの
 * 残りを使い切った時点で永久に待たされるデッドロックになる
 * (2026-07-25、256KB化の途中で発見 -- Window Scaling不成立の接続に
 * 256KBラウンドを適用しようとして気付いた)。
 *
 * NVMET_TCP_MAXH2CDATA_UNSCALED(32768): Window Scaling不成立でも常に
 * 安全な値(生のウィンドウ上限65535に対して余裕を持つ、旧来の実機
 * 確認済みの値そのもの)。
 * NVMET_TCP_MAXH2CDATA_SCALED(262144): Window Scaling成立時、
 * nvmet.hのNVMET_MAX_TRANSFER_BYTES(256KB)と同じ値まで安全に使える
 * (値は手動同期させること -- このファイルは下位レイヤなのでnvmet.hを
 * includeしない、レイヤ境界を守るため。linker.ldがboard.hのLOAD_ADDRと
 * 値を手動同期しているのと同じ理由)。
 *
 * どちらを使うかはnvmet_tcp_max_h2c_data()が接続ごとに
 * tcp_window_scaling_enabled()で判定する。1コマンドの転送量がこの値を
 * 超える場合は、いずれにせよ呼び出し元(nvmet.c)が複数ラウンドの
 * R2T+H2CDataに分割する(2026-07-25、パイプライン対応でラウンド分割の
 * ループ自体をnvmet.c側へ移した -- nvmet_tcp.h冒頭コメントの経緯参照)。 */
#define NVMET_TCP_MAXH2CDATA_UNSCALED 32768u
#define NVMET_TCP_MAXH2CDATA_SCALED   262144u

uint32_t nvmet_tcp_max_h2c_data(const nvmet_tcp_conn_t *c)
{
    return tcp_window_scaling_enabled(&c->tcp)
        ? NVMET_TCP_MAXH2CDATA_SCALED
        : NVMET_TCP_MAXH2CDATA_UNSCALED;
}

/* ヘッダ/データダイジェスト(CRC32C、2026-07-25追加)共通ヘルパ群。
 * 初期値0xFFFFFFFFで計算し、最終値は`~`(ビット反転)を取ってから実際の
 * ダイジェスト値として使う(crc32c.hコメント参照 -- 当初「~を取らない」と
 * 誤って実装し、実機のLinux nvme-tcpホストとの初回接続でヘッダCRC32C
 * 不一致になった。ホストの送信値がこちらの計算値のビット反転と完全一致
 * したことで確定した実機バグ、修正済み)。ヘッダダイジェストはPDUヘッダ
 * 全体(hlen分、複数バッファに分かれて既に受信/構築済み)のCRC32Cで、
 * data digestはデータ本体のみのCRC32C -- 対象範囲が違うだけで計算方法は
 * 同じ。 */

/* c->hdgstが有効なら、buf[0..hlen)のCRC32Cをbuf[hlen..hlen+4)へ書く。
 * **呼び出し元は、この関数を呼ぶ*前*にbuf[1](flags)のHDGST/DDGSTビットを
 * 両方とも最終状態まで確定させておくこと**(2026-07-25、実機で発見した
 * 本物のバグの修正: 当初この関数の内部でCRC計算の*後*にHDGSTビットを
 * OR付加していたが、flags自体がbuf[0..hlen)に含まれダイジェスト対象な
 * ため、計算時点でのflagsの値(ビット未設定)と実際に送信されるflags
 * (ビット設定済み)が食い違い、ホスト側の検証が常に失敗していた
 * -- plenを計算前に確定させる必要があるのと全く同じ理由・同じ形の
 * バグで、こちらは一度目の修正時に見落としていた。CLAUDE.md参照)。
 * 呼び出し元のバッファはhlen+4バイト以上確保しておくこと。
 * 戻り値: 追加したバイト数(0または4、送信総長・plenの調整に使う)。 */
static uint32_t nvmet_tcp_append_hdgst(nvmet_tcp_conn_t *c, uint8_t *buf, uint32_t hlen)
{
    if (!c->hdgst) return 0;
    uint32_t crc = ~crc32c(0xFFFFFFFFu, buf, hlen);  /* 最終反転(crc32c.hコメント参照) */
    wr32le(&buf[hlen], crc);
    return 4u;
}

/* c->ddgstが有効かつdlen>0なら、buf[data_off..data_off+dlen)のCRC32Cを
 * buf[data_off+dlen..+4)へ書く。データ本体のみが対象でヘッダ(flagsを
 * 含む)は範囲外のため、こちらはflagsの書き込みタイミングに依存しない
 * (呼び出し元がflagsを確定させるのはnvmet_tcp_append_hdgst()呼び出しより
 * 前である必要がある、そちらのコメント参照)。
 * 呼び出し元のバッファはdata_off+dlen+4バイト以上確保しておくこと。
 * 戻り値: 追加したバイト数(0または4)。 */
static uint32_t nvmet_tcp_append_ddgst(nvmet_tcp_conn_t *c, uint8_t *buf,
                                        uint32_t data_off, uint32_t dlen)
{
    if (!c->ddgst || dlen == 0) return 0;
    uint32_t crc = ~crc32c(0xFFFFFFFFu, &buf[data_off], dlen);  /* 最終反転(crc32c.hコメント参照) */
    wr32le(&buf[data_off + dlen], crc);
    return 4u;
}

/* ================================================================
 * NVMe/TCP制御のジョブ化(nvmet.c)向け非ブロッキング・resumable
 * プリミティブの実装(nvmet_tcp.h冒頭コメント参照)。
 * ================================================================ */

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
    /* 【2026-08-11、実機ts計測(ユーザー指示)で発見した本物の非効率】
     * 以前はここで`remain`を意味なくuint16_t(0xFFFF=65535バイト)へ
     * 切り詰めていた -- tcp_recv_no_ack()のmaxlen自体はuint32_tであり
     * (tcp.h参照、以前uint16_tだった時代の名残の切り詰めバグを既に
     * 修正済み)、この関数のローカル変数だけが古い制限を引きずっていた。
     * 262144バイトのH2CDataボディ1個を受信するには最低ceil(262144/
     * 65535)=5回の`nvmet_tcp_recv_poll()`呼び出しが必要になり、そのうち
     * 実際に新しいネットワークI/Oを伴わない残りの呼び出し(既にrx_bufに
     * 溜まっている分をコピーするだけ)まで含めて、毎回tcp_poll_once_ex()
     * (net_poll_all_and_dispatch()+TCP_MAX_CONNS走査)のオーバーヘッドを
     * 払っていた。tcp_recv_no_ack()自身が`n = priv->rx_count; if (n >
     * maxlen) n = maxlen;`で実際に利用可能な分だけ安全にコピーする設計
     * (呼び出しをブロックしない)なので、`remain`をそのまま渡しても
     * 過剰に長く待つことはなく、単に「その時点でrx_bufに溜まっている分を
     * 上限なく一度に汲み出せる」だけの変更 -- 実際の1回あたりコピー量は
     * 相手の送信ペース次第でこれまでと同程度のままだが、無駄な呼び出し
     * 回数だけを削減できる。 */
    /* timeout_ms=0: tcp_recv_internal()(tcp.c)のdo-while構造により、
     * tcp_poll_once()+受信チェックを1回だけ実行してから即座に返る --
     * nvmet_tcp.h冒頭コメント参照。 */
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

uint32_t nvmet_tcp_parse_cmd_dlen(const nvmet_tcp_conn_t *c, const uint8_t hdr_buf[NVME_TCP_HDR_LEN])
{
    /* nvmet_tcp_recv_cmd_body()内の既存計算をそのまま切り出したもの
     * (計算式は複製ではなくこの1箇所のみ、recv_cmd_body()側は変更せず
     * 独自に同じ式を保持したままにする -- 既存の実機実績コードへの
     * 変更を避けるため、あえて共有関数化はしない)。 */
    uint8_t  hlen = hdr_buf[2];
    uint32_t plen = rd32le(&hdr_buf[4]);
    uint32_t after_hdr = plen - (uint32_t)hlen;
    if (c->hdgst) after_hdr -= 4u;
    uint32_t dlen = after_hdr;
    if (dlen > 0 && c->ddgst) dlen -= 4u;
    return dlen;
}

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

void nvmet_tcp_accept_arm(nvmet_tcp_conn_t *c, int listener)
{
    tcp_accept_begin(listener, &c->tcp);
}

int nvmet_tcp_send_icresp(nvmet_tcp_conn_t *c, const uint8_t icreq_buf[NVME_TCP_ICREQ_LEN])
{
    uint8_t type = icreq_buf[0];
    if (type != NVME_TCP_PDU_ICREQ) {
        uart_printf("[!] NVMe/TCP target: 不正なICReq (type=%u)\n", type);
        return -1;
    }
    /* digest: bit0=header digest要求 bit1=data digest要求(nvme_tcp_pdu.h
     * 参照)。2026-07-25、両方対応したためもう拒否しない -- 要求された
     * ビットをそのまま受理し、以後このコネクションの全PDUで使う
     * (ICRespで同じ値をエコーする、下記参照)。 */
    uint8_t digest = icreq_buf[11];
    c->hdgst = (uint8_t)(digest & 0x01u);
    c->ddgst = (uint8_t)((digest >> 1) & 0x01u);
    c->maxdata = (uint16_t)rd32le(&icreq_buf[12]);  /* initiatorのmaxr2t(参考値) */

    /* ICResp(128バイト固定)。tcp_send()に渡すバッファは64バイトアライン
     * すること(tcp.hのtcp_send()ドキュメント参照)。 */
    static uint8_t s_icresp_buf[NVME_TCP_ICRESP_LEN] __attribute__((aligned(64)));
    for (uint32_t i = 0; i < NVME_TCP_ICRESP_LEN; i++) s_icresp_buf[i] = 0;

    s_icresp_buf[0] = NVME_TCP_PDU_ICRESP;          /* hdr.type */
    s_icresp_buf[1] = 0;                            /* hdr.flags */
    s_icresp_buf[2] = (uint8_t)NVME_TCP_ICRESP_LEN; /* hdr.hlen */
    s_icresp_buf[3] = 0;                            /* hdr.pdo (可変長データ無し) */
    wr32le(&s_icresp_buf[4], NVME_TCP_ICRESP_LEN);  /* hdr.plen */
    wr16le(&s_icresp_buf[8], 0);   /* pfv */
    s_icresp_buf[10] = 0;          /* cpda: 4バイトアラインで十分(hlenは全PDUで
                                     * 4の倍数、4バイトのCRC32Cダイジェストも
                                     * 常に4バイト境界に乗るため追加パディング
                                     * 不要、2026-07-25) */
    s_icresp_buf[11] = (uint8_t)((c->ddgst << 1) | c->hdgst);  /* 要求された値をそのままエコー(両方対応) */
    /* maxdata: MAXH2CDATA。ファイル冒頭のnvmet_tcp_max_h2c_data()参照
     * (単発PDUの安全上限、Window Scaling成立の有無で変わる、値の経緯も
     * そちらのコメントに集約した)。この時点でTCPハンドシェイクは完了
     * 済み(呼び出し側がaccept完了を確認済み)のため、Window Scalingの
     * 成立可否は確定済み。
     * 2026-07-25: 以前はここにNVMET_MAX_TRANSFER_BYTESと同じ値を直接
     * 書いていたため、MDTS以下の書き込みが常にin-capsule上限にも収まって
     * しまいR2T+H2CDataが一度も使われない状態になっていた -- 単発PDUの
     * 安全上限とMDTS(nvmet.hのNVMET_MAX_TRANSFER_BYTES、1コマンド全体の
     * 上限)は別物として扱うこと。 */
    wr32le(&s_icresp_buf[12], nvmet_tcp_max_h2c_data(c));
    /* reserved[112]は上のループで既に0クリア済み */

    uart_printf("[NVMe/TCP target] ICReq受信、ICResp送信 (initiator maxr2t=%u hdgst=%u ddgst=%u)\n",
                c->maxdata, c->hdgst, c->ddgst);
    /* NSND: ICResp送信(admin/IO両queueが共通で通るこの関数1箇所に置くだけで
     * 両方をカバーする)。 */
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

int nvmet_tcp_send_r2t(nvmet_tcp_conn_t *c, uint16_t cid,
                        uint32_t r2to, uint32_t r2tl)
{
    /* +4: ヘッダダイジェスト(有効な場合のみ実際に使う、2026-07-25追加)。
     * R2Tはデータを運ばないためデータダイジェストは付かない。 */
    static uint8_t s_r2t_buf[NVME_TCP_R2T_PDU_LEN + 4u] __attribute__((aligned(64)));

    /* plen(ヘッダダイジェスト分を含む最終値)は、ヘッダダイジェストを計算
     * する*前*に確定・書き込んでおくこと -- ダイジェストはbuf[0..hlen)の
     * 全バイト(plenフィールド自身を含む)のCRC32Cのため、後から書き換える
     * と実際に送信するバイト列と異なる値をダイジェストしてしまう
     * (2026-07-25、実機で発見: ホストへの最初のCQE応答でこの順序を誤り、
     * こちらは何もエラーを出さないままホスト側だけがヘッダダイジェスト
     * 不一致で接続を切っており(こちらの次の受信がタイムアウトするだけで
     * 気付きにくい)、原因特定に手間取った -- 詳細はCLAUDE.md参照)。 */
    uint32_t total = NVME_TCP_R2T_PDU_LEN + (c->hdgst ? 4u : 0u);

    s_r2t_buf[0] = NVME_TCP_PDU_R2T;
    /* flags(HDGSTビット含む)もヘッダダイジェスト計算より前に確定させる
     * こと -- flags自体がダイジェスト対象(buf[0..hlen))に含まれるため、
     * 後からORで立てると計算時と送信時でflagsの値が食い違う(2026-07-25、
     * 実機で発見: 上記plenと全く同じ理由の別バグ、CLAUDE.md参照)。 */
    s_r2t_buf[1] = c->hdgst ? NVME_TCP_F_HDGST : 0;
    s_r2t_buf[2] = (uint8_t)NVME_TCP_R2T_PDU_LEN;
    s_r2t_buf[3] = 0;
    wr32le(&s_r2t_buf[4], total);
    wr16le(&s_r2t_buf[8],  cid);   /* cccid */
    wr16le(&s_r2t_buf[10], 0);     /* ttag: 常に0 -- 同一コマンド内では、次ラウンドのR2Tは
                                     * 前ラウンドのH2CData受信完了後にしか送らない(nvmet.cの
                                     * 設計、同時に2件以上のR2Tを同一コマンドに出さない)ため
                                     * 使い回しても衝突しない。 */
    wr32le(&s_r2t_buf[12], r2to);
    wr32le(&s_r2t_buf[16], r2tl);
    wr32le(&s_r2t_buf[20], 0);     /* reserved */

    /* ここまでで buf[0..hlen) が最終状態 -- ここで初めてヘッダダイジェストを
     * 計算・付加する(R2Tはデータを運ばないためpdoは変わらず0のまま)。 */
    nvmet_tcp_append_hdgst(c, s_r2t_buf, NVME_TCP_R2T_PDU_LEN);

    /* NSND: R2T送信(cccid=cid、data_offset/data_length=r2to/r2tl、旧NR2T)。
     * 1コマンドが複数ラウンドに分割される場合はラウンドごとに、複数
     * コマンドがパイプラインされている場合はコマンドごとに記録される。 */
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
    /* 計装専用(一時追加、原因特定後に削除すること) -- このR2Tが送信
     * バイトストリーム上のどの位置(conn->snd_seq、送信前の値=この
     * PDUの先頭バイトのseq)に乗るかを記録する。initiator側(nvme.c)の
     * PLHT/rcv_seqログと突き合わせ、TCP層でのバイト位置とアプリ層の
     * PDU処理タイミングを直接対応付けるため。 */
    ts_log(TS_MK(TS_FILE_NVMET_TCP, TS_FUNC_nvmet_tcp_send_r2t, 1), c->tcp.snd_seq);

    /* tcp_send_async()(送りっぱなし、tcp.h/nvmet_tcp_send_resp()コメント
     * 参照)を使う -- R2T送信直後はホストのH2CData送信を待つだけで、
     * R2T自体のACK確認を待つ必要は無い。ホストがH2CDataを送り始めれば
     * そのパケットのACKフィールドが自然にR2Tを確認するため、通常は
     * 背後のtcp_async_poll()が再送を必要とする場面にすら至らない。 */
    if (tcp_send_async(&c->tcp, s_r2t_buf, (uint16_t)total) != (int)total) {
        uart_printf("[!] NVMe/TCP target: R2T送信失敗 (cid=%u offset=%u len=%u)\n", cid, r2to, r2tl);
        return -1;
    }
    return 0;
}

int nvmet_tcp_send_resp(nvmet_tcp_conn_t *c, const nvme_cqe_t *cqe)
{
    /* +4: ヘッダダイジェスト(有効な場合のみ実際に使う、2026-07-25追加)。
     * Response Capsuleはデータを運ばないためデータダイジェストは付かない。 */
    static uint8_t s_resp_buf[NVME_TCP_RSP_PDU_LEN + 4u] __attribute__((aligned(64)));

    /* plenはヘッダダイジェスト計算より前に確定・書き込むこと(nvmet_tcp_
     * send_r2t()の同種コメント参照 -- 実機で発見した本物のバグ、CLAUDE.md
     * 参照)。 */
    uint32_t total = NVME_TCP_RSP_PDU_LEN + (c->hdgst ? 4u : 0u);

    s_resp_buf[0] = NVME_TCP_PDU_RSP;
    /* flagsもヘッダダイジェスト計算より前に確定させる(nvmet_tcp_send_r2t()
     * の同種コメント参照)。 */
    s_resp_buf[1] = c->hdgst ? NVME_TCP_F_HDGST : 0;
    s_resp_buf[2] = (uint8_t)NVME_TCP_RSP_PDU_LEN;
    s_resp_buf[3] = 0;
    wr32le(&s_resp_buf[4], total);

    volatile_fast_copy((volatile uint8_t *)&s_resp_buf[NVME_TCP_HDR_LEN],
                        (const volatile uint8_t *)cqe, NVME_CQE_LEN);

    /* ここまでで buf[0..hlen) が最終状態 -- ここで初めてヘッダダイジェストを
     * 計算・付加する。 */
    nvmet_tcp_append_hdgst(c, s_resp_buf, NVME_TCP_RSP_PDU_LEN);

    /* NRSP: Response Capsule(CQE)送信 -- tcp.c側のSEND/SSEG/SACK/SDONは
     * 純粋なバイト長(24)しか記録せず、同じ24バイトを送るR2T(nvmet_tcp_
     * send_r2t()のNR2T参照)と見分けが付かない。cid(このCQEがどの
     * コマンドへの応答か)とstatus(成功/エラー)を残しておけば区別・
     * 対応付けができる。cqe->cid/statusはローカル変数(呼び出し元nvmet.cの
     * スタック上、自然アライン)への直接アクセスなので、nvme.cの
     * cqe.dw0直接アクセスと同じ理由でrd16le()は不要(ワイヤ生バッファでは
     * ない)。2026-07-25: c->last_cidから cqe->cid へ変更した -- IOキューは
     * 複数コマンドが同時にoutstandingになりうるため、"直前に受信した
     * コマンドのCID"という共有フィールドはこのCQEが実際にどのコマンドへの
     * 応答かと一致する保証が無い。CQE自身が保持するcidを使えば常に正しい
     * (nvmet_tcp.h冒頭コメントの経緯参照)。NSND(旧NRSP)。 */
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

    /* tcp_send()(ACK確認まで同期ブロック)ではなくtcp_send_async()
     * (送りっぱなし、tcp.h参照)を使う -- 実機のWiresharkキャプチャで、
     * このCQE送信のtcp_send()が相手のTCP ACKを待つ一方、相手(ホスト)は
     * こちらのCQEを待って次のコマンドを出さないため、ホスト自身の遅延
     * ACKタイマー(Linuxで標準的に約40ms)が双方の待ち合わせを生み、
     * Writeコマンド1回あたり約40〜50msの停止を引き起こしていたことが
     * 判明した(CLAUDE.md参照)。CQEはこの直後呼び出し元が次のPDU受信へ
     * 進むだけで送信完了確認を必要としないため、確認はバックグラウンド
     * (tcp_poll_once()経由のtcp_async_poll())に任せる。 */
    if (tcp_send_async(&c->tcp, s_resp_buf, (uint16_t)total) != (int)total) {
        uart_printf("[!] NVMe/TCP target: Response Capsule送信失敗 (cid=%u)\n", cqe->cid);
        return -1;
    }
    return 0;
}

int nvmet_tcp_send_c2h(nvmet_tcp_conn_t *c, uint16_t cid, const nvme_cqe_t *cqe,
                       const void *data, uint32_t dlen,
                       int data_success)
{
    /* +8: ヘッダダイジェスト(4、ヘッダ直後・データより前)+データ
     * ダイジェスト(4、データ直後)の両方が有効な場合のみ実際に使う枠
     * (2026-07-25追加)。 */
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
        /* flags(HDGST/DDGSTビット含む)もヘッダダイジェスト計算より前に
         * 確定させること -- flags自体がダイジェスト対象(buf[0..hlen))に
         * 含まれるため、後からORで立てると計算時と送信時でflagsの値が
         * 食い違う(2026-07-25、実機で発見した本物のバグ、CLAUDE.md参照)。
         * C2HDataはhdgst/ddgstが両方同時に有効になりうる唯一のPDU種別
         * なので、両方のビットをここでまとめて確定させる。 */
        if (c->hdgst) flags = (uint8_t)(flags | NVME_TCP_F_HDGST);
        if (c->ddgst && chunk > 0) flags = (uint8_t)(flags | NVME_TCP_F_DDGST);

        /* pdo/plenは、いずれもヘッダダイジェスト計算より前に確定・書き込む
         * こと(同上)。data_off(pdo)はc->hdgstだけから、total(plen)は
         * さらにchunk/c->ddgstから、いずれもここで既に判明している値だけで
         * 決まる -- append_hdgst()/append_ddgst()の戻り値を待つ必要は無い。
         * uint32_t: 2026-07-25、chunkが最大NVMET_TCP_C2H_CHUNK_MAX(256KB)
         * まで拡張されたため、24+262144=262168はuint16_tの上限を超える
         * (このマクロ導入時に踏んだオーバーフローバグの再発を避けるため、
         * ここをuint16_tへ戻さないこと -- 上記マクロのコメント参照)。
         * tcp_send()のlen引数も同日uint32_t化済み。 */
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

        /* ここまでで buf[0..hlen) が最終状態 -- ここで初めてヘッダダイジェスト
         * を計算・付加する(buf[hlen..data_off)へ書く、hdgst無効ならdata_off
         * ==hlenなので何もしない)。 */
        nvmet_tcp_append_hdgst(c, s_c2h_buf, NVME_TCP_DATA_PDU_LEN);

        volatile_fast_copy((volatile uint8_t *)&s_c2h_buf[data_off],
                            (const volatile uint8_t *)(src + sent), chunk);

        /* データダイジェスト(有効かつchunk>0なら4バイト付加、2026-07-25追加)。 */
        nvmet_tcp_append_ddgst(c, s_c2h_buf, data_off, chunk);

        /* NSND: 個々のC2HData PDU送信(cccid=コマンドCID、data_offset/
         * data_length=このPDUが運ぶデータ範囲、旧NC2H)。読み出しデータが
         * NVMET_TCP_C2H_CHUNK_MAXを超え複数PDUに分割される場合は
         * チャンクごとに1件記録される -- 個々のtcp_send()自体はtcp.c側の
         * SEND/SDONで見える。 */
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

/* nvmet_tcp_send_c2h_async(): 上記nvmet_tcp_send_c2h()の非同期版
 * (2026-08-10、READパイプライン化)。ヘッダ宣言はnvmet_tcp.h参照 --
 * ゼロコピー(dataから直接tcp_send_async()へ渡す)・単一PDU限定・
 * data_success=1固定・hdgst/ddgst非対応という制約はそちらに記載済み。 */
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
        /* 2026-08-10、LSO対応に伴いmssへの切り詰めを撤去した --
         * tcp_send_async()自体が、接続先のLSOケーパビリティに応じて
         * mss単位への分割/LSO単発送信を内部で使い分けるようになった
         * (tcp.hのtcp_send_async()コメント参照)ため、この呼び出し元は
         * TCP_ASYNC_MAX_LEN単位のチャンクをそのまま渡すだけでよい。
         * 2026-08-15、真のゼロコピー化: 送信元src=data=nvmetのram_disk[slba]
         * (READ処理中は不変な安定バッキングストア、nvmet.cのRead分岐参照)
         * なので、tcp_send_async_ref()でコピーせずポインタ参照だけを渡す
         * (256KB級のコピーを丸ごと省く。100GbEでメモリ帯域が律速だったため)。
         * ACK確認までram_diskが不変であることは、READコマンドの処理中に
         * 同一LBAへの並行WRITEが無いという通常のNVMeセマンティクスで保証。 */
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

void nvmet_tcp_close(nvmet_tcp_conn_t *c)
{
    tcp_close(&c->tcp);
}
