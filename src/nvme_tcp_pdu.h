#ifndef NVME_TCP_PDU_H
#define NVME_TCP_PDU_H

#include <stdint.h>
#include "nvme_types.h"
#include "net.h"   /* rd16le / wr16le / wr32le(TermReq の組み立てに使う) */

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

/* Terminate Connection Request(H2C/C2H TermReq)。
 * struct nvme_tcp_term_pdu(Linux の include/linux/nvme-tcp.h)より:
 *   hdr(8)+ fes(le16)+ feil(le16)+ feiu(le16)+ rsvd[10] = 24 バイト。
 * plen は 24 〜 152 で、24 を超えるぶんが**エラーの原因になった PDU の
 * 先頭バイト列**(最大 128 バイト)。 */
#define NVME_TCP_TERM_HDR_LEN   24u
#define NVME_TCP_TERM_PLEN_MIN  24u
#define NVME_TCP_TERM_PLEN_MAX 152u

/* Fatal Error Status(enum nvme_tcp_fatal_error_status)。 */
#define NVME_TCP_FES_INVALID_PDU_HDR    0x01u
#define NVME_TCP_FES_PDU_SEQ_ERR        0x02u
#define NVME_TCP_FES_HDR_DIGEST_ERR     0x03u
#define NVME_TCP_FES_DATA_OUT_OF_RANGE  0x04u
#define NVME_TCP_FES_R2T_LIMIT_EXCEEDED 0x05u
#define NVME_TCP_FES_UNSUPPORTED_PARAM  0x06u

#define NVME_TCP_F_HDGST       0x01u  /* header digest 付与 */
#define NVME_TCP_F_DDGST       0x02u  /* data digest 付与 */
#define NVME_TCP_F_DATA_LAST   0x04u  /* H2C/C2HData: このPDUがこの転送の最後 */
#define NVME_TCP_F_DATA_SUCCESS 0x08u

typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    uint16_t       pfv;
    uint8_t        hpda;
    uint8_t        digest;
    uint32_t       maxr2t;
    uint8_t        reserved[112];
} nvme_tcp_icreq_t;

#define NVME_TCP_ICREQ_LEN 128u

typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    uint16_t       pfv;
    uint8_t        cpda;
    uint8_t        digest;
    uint32_t       maxdata;
    uint8_t        reserved[112];
} nvme_tcp_icresp_t;

#define NVME_TCP_ICRESP_LEN 128u

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

typedef struct __attribute__((packed)) {
    nvme_tcp_hdr_t hdr;
    uint16_t       cccid;
    uint16_t       ttag;
    uint32_t       r2to;
    uint32_t       r2tl;
    uint32_t       reserved;
} nvme_tcp_r2t_t;

#define NVME_TCP_R2T_PDU_LEN (NVME_TCP_HDR_LEN + 16u)  /* 24 */

/*=================================================================
 * Terminate Connection Request(H2C/C2H TermReq)を組み立てる。
 *
 * プロトコル上の致命的な誤りを見つけた側は、**接続を閉じる前にこれを送って
 * 理由(FES)を伝える**のが NVMe/TCP の規約。送らずに TCP を閉じるだけだと、
 * 相手のログには「接続が切れた」としか残らない。
 *
 * ヘッダダイジェストは付けない(相手はヘッダが壊れている前提で読むため。
 * Linux の nvmet_tcp も TermReq には付けない)。
 *
 * 引数:
 *   buf     - NVME_TCP_TERM_PLEN_MAX バイト以上の書き込み先
 *   type    - NVME_TCP_PDU_H2C_TERM か NVME_TCP_PDU_C2H_TERM
 *   fes     - Fatal Error Status(NVME_TCP_FES_*)
 *   fei     - Fatal Error Information(該当が無ければ 0)
 *   pdu     - 原因になった PDU の先頭(NULL 可)
 *   pdu_len - そのバイト数(最大 128 バイトまで載る)
 * 戻り値:
 *   組み立てた PDU 全体のバイト数
 * コール元:
 *   nvmet_tcp_send_term(), nvme_tcp_send_term()
 * ===============================================================*/
static inline uint32_t nvme_tcp_build_term(uint8_t *buf, uint8_t type, uint16_t fes,
                                            uint32_t fei, const uint8_t *pdu,
                                            uint32_t pdu_len)
{
    for (uint32_t i = 0; i < NVME_TCP_TERM_HDR_LEN; i++) buf[i] = 0;
    uint32_t max_data = NVME_TCP_TERM_PLEN_MAX - NVME_TCP_TERM_HDR_LEN;  /* 128 */
    if (pdu == NULL) pdu_len = 0;
    if (pdu_len > max_data) pdu_len = max_data;

    buf[0] = type;
    buf[1] = 0;                              /* flags: ダイジェストは付けない */
    buf[2] = (uint8_t)NVME_TCP_TERM_HDR_LEN; /* hlen */
    buf[3] = 0;                              /* pdo */
    wr32le(&buf[4], NVME_TCP_TERM_HDR_LEN + pdu_len);  /* plen */
    wr16le(&buf[8], fes);
    wr16le(&buf[10], (uint16_t)(fei & 0xFFFFu));         /* feil */
    wr16le(&buf[12], (uint16_t)((fei >> 16) & 0xFFFFu)); /* feiu */
    for (uint32_t i = 0; i < pdu_len; i++) {
        buf[NVME_TCP_TERM_HDR_LEN + i] = pdu[i];
    }
    return NVME_TCP_TERM_HDR_LEN + pdu_len;
}

/* 受け取った TermReq から FES / FEI を取り出す(表示用)。 */
static inline uint16_t nvme_tcp_term_fes(const uint8_t *pdu) { return rd16le(&pdu[8]); }
static inline uint32_t nvme_tcp_term_fei(const uint8_t *pdu)
{
    return (uint32_t)rd16le(&pdu[10]) | ((uint32_t)rd16le(&pdu[12]) << 16);
}

#endif /* NVME_TCP_PDU_H */
