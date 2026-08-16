#ifndef IB_MAD_H
#define IB_MAD_H

#include <stdint.h>

#define IB_MAD_HDR_LEN 24u

#define IB_MGMT_BASE_VERSION 1u
#define IB_MGMT_CLASS_CM     0x07u // Communication Manager(フェーズ(e)用)

#define IB_MGMT_METHOD_GET       0x01u
#define IB_MGMT_METHOD_SET       0x02u
#define IB_MGMT_METHOD_SEND      0x03u
#define IB_MGMT_METHOD_GET_RESP  0x81u
#define IB_MGMT_METHOD_RESP      0x80u

#define IB_QP1_QKEY 0x80010000u

#define IB_MGMT_MAD_DATA 232u
#define IB_MGMT_MAD_SIZE (IB_MAD_HDR_LEN + IB_MGMT_MAD_DATA)

static inline uint64_t rd64be(const volatile void *p) {
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8) | (uint64_t)b[7];
}

static inline void wr64be(volatile void *p, uint64_t v) {
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)v;
}

static inline uint16_t rd16be_ib(const volatile void *p) {
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

static inline void wr16be_ib(volatile void *p, uint16_t v) {
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}

static inline uint32_t rd32be_ib(const volatile void *p) {
    const volatile uint8_t *b = (const volatile uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void wr32be_ib(volatile void *p, uint32_t v) {
    volatile uint8_t *b = (volatile uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

static inline void ib_mad_hdr_build(volatile uint8_t *buf, uint8_t mgmt_class, uint8_t class_version,
                                     uint8_t method, uint64_t tid, uint16_t attr_id, uint32_t attr_mod) {
    buf[0] = (uint8_t)IB_MGMT_BASE_VERSION;
    buf[1] = mgmt_class;
    buf[2] = class_version;
    buf[3] = method;
    wr16be_ib(&buf[4], 0);      // status
    wr16be_ib(&buf[6], 0);      // class_specific
    wr64be(&buf[8], tid);
    wr16be_ib(&buf[16], attr_id);
    wr16be_ib(&buf[18], 0);     // resv
    wr32be_ib(&buf[20], attr_mod);
}

#endif /* IB_MAD_H */
