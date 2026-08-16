#ifndef NVME_TCP_PDU_H
#define NVME_TCP_PDU_H

#include <stdint.h>
#include "nvme_types.h"

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

#endif /* NVME_TCP_PDU_H */
