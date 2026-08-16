#ifndef NVME_TYPES_H
#define NVME_TYPES_H

#include <stdint.h>

#define NVME_PSDT_SGL_MPTR_CONTIGUOUS 0x40u

typedef struct __attribute__((packed)) {
    uint32_t cdw0;
    uint32_t nsid;
    uint32_t reserved1;
    uint32_t reserved2;
    uint64_t mptr;
    uint8_t  dptr[16];   /* SGL1 (nvme_sgl_desc_t が16バイトそのまま入る) */
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} nvme_sqe_t;

#define NVME_SQE_LEN 64u

/* CQE (Completion Queue Entry) — 16バイト固定フォーマット。 */
typedef struct __attribute__((packed)) {
    uint32_t dw0;
    uint32_t dw1;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t cid;
    uint16_t status;   /* bit0 = phase tag, bits[15:1] = status code + type */
} nvme_cqe_t;

#define NVME_CQE_LEN 16u

static inline uint16_t nvme_cqe_status_code(uint16_t status) { return (uint16_t)(status >> 1); }
static inline int      nvme_cqe_phase(uint16_t status) { return status & 1; }

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t len;
    uint8_t  reserved[3];
    uint8_t  type;      /* [7:4]=SGL Descriptor Type [3:0]=SGL Descriptor Subtype */
} nvme_sgl_desc_t;

#define NVME_SGL_TYPE_DATA_BLOCK_OFFSET 0x01u

#define NVME_SGL_TYPE_TRANSPORT 0x5Au

#define NVME_SGL_TYPE_KEYED_DATA_BLOCK 0x40u

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint8_t  length[3];
    uint8_t  key[4];
    uint8_t  type;
} nvme_keyed_sgl_desc_t;
_Static_assert(sizeof(nvme_keyed_sgl_desc_t) == 16, "must match nvme_sqe_t.dptr[16]");

#define NVME_TCP_INLINE_DATA_MAX 8192u

#define NVME_REG_CAP  0x00u  /* Controller Capabilities (8バイト) */
#define NVME_REG_VS   0x08u  /* Version (4バイト) */
#define NVME_REG_CC   0x14u  /* Controller Configuration (4バイト) */
#define NVME_REG_CSTS 0x1Cu  /* Controller Status (4バイト) */

#define NVME_CC_EN       0x00000001u
#define NVME_CC_CSS_NVM  0x00000000u
#define NVME_CC_AMS_RR   0x00000000u
#define NVME_CC_SHN_NONE 0x00000000u
#define NVME_CC_IOSQES   (6u << 16)  /* 2^6 = 64バイト、nvme_sqe_tと一致 */
#define NVME_CC_IOCQES   (4u << 20)  /* 2^4 = 16バイト、nvme_cqe_tと一致 */

#define NVME_CSTS_RDY 0x00000001u
#define NVME_CSTS_CFS 0x00000002u  /* Controller Fatal Status */

/* Admin Command Set オペコード(NVMe Base Spec)。 */
#define NVME_ADM_CMD_DELETE_SQ     0x00u
#define NVME_ADM_CMD_CREATE_SQ     0x01u
#define NVME_ADM_CMD_DELETE_CQ     0x04u
#define NVME_ADM_CMD_CREATE_CQ     0x05u
#define NVME_ADM_CMD_GET_LOG_PAGE  0x02u
#define NVME_ADM_CMD_IDENTIFY      0x06u
#define NVME_ADM_CMD_ASYNC_EVENT   0x0Cu
#define NVME_ADM_CMD_SET_FEATURES  0x09u
#define NVME_ADM_CMD_GET_FEATURES  0x0Au
#define NVME_ADM_CMD_KEEP_ALIVE    0x18u

/* NVM Command Set (IO queue) オペコード。 */
#define NVME_IO_CMD_FLUSH  0x00u
#define NVME_IO_CMD_WRITE  0x01u
#define NVME_IO_CMD_READ   0x02u

#define NVME_FABRIC_CMD                  0x7Fu
#define NVME_FABRIC_FCTYPE_PROPERTY_SET  0x00u
#define NVME_FABRIC_FCTYPE_CONNECT       0x01u
#define NVME_FABRIC_FCTYPE_PROPERTY_GET  0x04u

/* Get Log Page の cdw10 下位バイト(LID: Log Page Identifier)。
 * 値は Linux の include/linux/nvme.h の NVME_LOG_DISC と同じ。 */
#define NVME_LOG_LID_DISCOVERY  0x70u

/* Identify command の cdw10 下位バイト(CNS: Controller or Namespace Structure)。 */
#define NVME_IDENTIFY_CNS_NAMESPACE   0x00u
#define NVME_IDENTIFY_CNS_CONTROLLER  0x01u

#define NVME_ID_NS_OFF_FLBAS   26u   /* offset within the 4096B Identify Namespace buffer */
#define NVME_ID_NS_OFF_LBAF0   128u  /* LBA Format 0 descriptor offset (4 bytes each) */

typedef struct __attribute__((packed)) {
    uint16_t ms;   /* metadata size */
    uint8_t  ds;   /* LBA data size, reported as a power of 2 */
    uint8_t  rp;   /* relative performance */
} nvme_lbaf_t;

#endif /* NVME_TYPES_H */
