#ifndef NVME_TCP_PDU_H
#define NVME_TCP_PDU_H

#include <stdint.h>
#include "nvme_types.h"

/* ================================================================
 * nvme_tcp_pdu.h — NVMe/TCP (NVMe-oF TCPトランスポート) PDU構造体定義のみ。
 * プロトコルロジックはnvme_tcp.cが持つ -- ここには構造体とPDU種別/フラグ
 * 定数のみを置く。ConnectX-4等の別トランスポートへ移植する際は
 * nvme_tcp.h/nvme_tcp.cだけを差し替え、このファイルとnvme_types.h/
 * nvme.h/nvme.cは変更しない(CLAUDE.md記載のレイヤ境界)。
 *
 * 全フィールドはリトルエンディアン(net.hのrd16le/rd32le/wr16le/wr32le
 * 経由でのみアクセスすること -- nvme_types.hと同じ理由)。
 * ================================================================ */

/* 全PDU共通のヘッダ(8バイト、必ず各PDUの先頭に来る)。
 * hlen: このヘッダを含むPDU固定部分の長さ。
 * pdo:  PDUデータオフセット(可変長データが始まる位置、H2CData/C2HData/
 *       CapsuleCmd(in-capsuleデータ付き)で使う。他は0)。
 * plen: PDU全体の長さ(ヘッダ+固定部+可変長データ)。 */
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  flags;
    uint8_t  hlen;
    uint8_t  pdo;
    uint32_t plen;
} nvme_tcp_hdr_t;

#define NVME_TCP_HDR_LEN 8u

/* PDU種別(nvme_tcp_hdr_t.type、NVMe-oF TCPトランスポート仕様)。 */
#define NVME_TCP_PDU_ICREQ      0x00u  /* Initialize Connection Request (host->target) */
#define NVME_TCP_PDU_ICRESP     0x01u  /* Initialize Connection Response (target->host) */
#define NVME_TCP_PDU_H2C_TERM   0x02u  /* Terminate Connection Request (host->target) */
#define NVME_TCP_PDU_C2H_TERM   0x03u  /* Terminate Connection Request (target->host) */
#define NVME_TCP_PDU_CMD        0x04u  /* Command Capsule (host->target) */
#define NVME_TCP_PDU_RSP        0x05u  /* Response Capsule (target->host) */
#define NVME_TCP_PDU_H2C_DATA   0x06u  /* H2C Data (host->target) */
#define NVME_TCP_PDU_C2H_DATA   0x07u  /* C2H Data (target->host) */
#define NVME_TCP_PDU_R2T        0x09u  /* Ready To Transfer (target->host) */

/* nvme_tcp_hdr_t.flags のビット。header/data digest(CRC32C)は2026-07-25に
 * ターゲット側(nvmet_tcp.c)で対応した -- ICReqのdigestバイト(bit0=hdgst,
 * bit1=ddgst)で要求されたものをICRespでそのままエコーし、以後そのビットを
 * 各PDUのflagsへ立てる(nvmet_tcp_conn_t.hdgst/ddgstで接続単位に保持、
 * nvmet_tcp.cのnvmet_tcp_check_hdgst()/append_hdgst()等参照)。 */
#define NVME_TCP_F_HDGST       0x01u  /* header digest 付与 */
#define NVME_TCP_F_DDGST       0x02u  /* data digest 付与 */
#define NVME_TCP_F_DATA_LAST   0x04u  /* H2C/C2HData: このPDUがこの転送の最後 */
#define NVME_TCP_F_DATA_SUCCESS 0x08u /* C2HData: 別途CapsuleRespを送らず、このC2HDataの
                                        * 完了自体が暗黙のcommand success応答を兼ねる
                                        * (target側の最適化。立っていなければ別途RSPが来る) */

/* ICReq (Initialize Connection Request, host->target, 128バイト固定)。
 * pfv: Payload Fabric Version (現行は0)。hpda: Host PDU Data Alignment
 * (0=16Bアラインで十分、追加アライメント不要という意味)。digest: bit0=
 * header digest希望 bit1=data digest希望 (本実装は両方サポートしないため
 * 常に0を送る -- target側がdigest必須で応答してきた場合は非対応として
 * 扱う、nvme_tcp.c参照)。maxr2t: 同時に受け付けられるR2T数-1
 * (本実装はコマンドを直列にしか送らないため0=1個で十分)。 */
typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    uint16_t       pfv;
    uint8_t        hpda;
    uint8_t        digest;
    uint32_t       maxr2t;
    uint8_t        reserved[112];
} nvme_tcp_icreq_t;

#define NVME_TCP_ICREQ_LEN 128u

/* ICResp (Initialize Connection Response, target->host, 128バイト固定)。
 * cpda: Controller PDU Data Alignment。maxdata: MAXH2CDATA、target が
 * 1回のH2CDataで受け付けられる最大バイト数 -- nvme_tcp_conn_t.maxdataに
 * 保持し、H2C送信の分割サイズ上限として使う(nvme_tcp.c参照)。 */
typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    uint16_t       pfv;
    uint8_t        cpda;
    uint8_t        digest;
    uint32_t       maxdata;
    uint8_t        reserved[112];
} nvme_tcp_icresp_t;

#define NVME_TCP_ICRESP_LEN 128u

/* Command Capsule (host->target, 固定部72バイト = ヘッダ8 + SQE64)。
 * in-capsuleデータ(書き込みコマンドのデータが十分小さい場合、SQEの直後に
 * そのまま続けて送る最適化)を使う場合はhdr.pdoがSQEの直後(=72)を指し、
 * hdr.plenがそのデータ分を含む。本実装はin-capsuleデータを使わず、
 * 書き込みデータは常にR2T+H2CDataで送る(nvme_tcp.c参照、実装を単純に
 * 保つため)。 */
typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    nvme_sqe_t     sqe;
} nvme_tcp_cmd_pdu_t;

#define NVME_TCP_CMD_PDU_LEN (NVME_TCP_HDR_LEN + NVME_SQE_LEN)  /* 72 */

/* Response Capsule (target->host, 24バイト固定 = ヘッダ8 + CQE16)。 */
typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    nvme_cqe_t     cqe;
} nvme_tcp_rsp_pdu_t;

#define NVME_TCP_RSP_PDU_LEN (NVME_TCP_HDR_LEN + NVME_CQE_LEN)  /* 24 */

/* C2HData / H2CData 共通の固定部(24バイト = ヘッダ8 + 16)。実データは
 * hdr.pdo(このPDU内でのデータ開始オフセット、常に24)から始まりhdr.plen
 * まで続く。同一レイアウトをC2H/H2Cで共用する(Linuxのnvme_tcp_data_pdu
 * と同じ、方向はhdr.typeで区別する)。
 * cccid: このデータが属するコマンドのCID (Command Capsule Command ID)。
 * ttag:  H2CDataの場合のみ意味を持つ(R2Tで指定されたTransfer Tagを
 *        そのまま返す)。C2HDataでは未使用(0)。
 * datao: このPDUが運ぶデータの、コマンド全体データ内でのオフセット。
 * datal: このPDUが運ぶデータの長さ(バイト)。 */
typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    uint16_t       cccid;
    uint16_t       ttag;
    uint32_t       datao;
    uint32_t       datal;
    uint32_t       reserved;
} nvme_tcp_data_pdu_t;

#define NVME_TCP_DATA_PDU_LEN (NVME_TCP_HDR_LEN + 16u)  /* 24 */

typedef nvme_tcp_data_pdu_t nvme_tcp_c2h_data_t;
typedef nvme_tcp_data_pdu_t nvme_tcp_h2c_data_t;

/* R2T (Ready To Transfer, target->host, 24バイト固定 = ヘッダ8 + 16)。
 * 実際のワイヤ上フィールド順序(NVMe-oF TCPトランスポート仕様Figure):
 * cccid(2B) + ttag(2B) + r2to(4B) + r2tl(4B) + reserved(4B) -- Linuxの
 * struct nvme_tcp_r2t_pduと同一レイアウト。target実装(nvmet-tcp)との
 * 実相互接続を優先し、この実際の仕様レイアウトを採用する。
 * r2to: 要求するデータのコマンド全体データ内でのオフセット。
 * r2tl: 要求するデータの長さ(バイト) -- MAXH2CDATA(icresp.maxdata)を
 *       超えない範囲でtargetが指定してくる。 */
typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    uint16_t       cccid;
    uint16_t       ttag;
    uint32_t       r2to;
    uint32_t       r2tl;
    uint32_t       reserved;
} nvme_tcp_r2t_t;

#define NVME_TCP_R2T_PDU_LEN (NVME_TCP_HDR_LEN + 16u)  /* 24 */

#endif /* NVME_TCP_PDU_H */
