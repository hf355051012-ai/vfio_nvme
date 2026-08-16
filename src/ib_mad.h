#ifndef IB_MAD_H
#define IB_MAD_H

#include <stdint.h>

// IBTA MAD(Management Datagram)共通ヘッダ。ConnectX RoCEv2 NVMe-oF実装
// 計画(~/.claude/plans/peppy-wobbling-lamport.md)フェーズ(d)(GSI/MAD送受信)
// ・フェーズ(e)(RDMA CM、REQ/REP/RTUもこのMADヘッダに載せて送る)の両方が
// 使う共通定義。include/rdma/ib_mad.h(このセッションで実際に取得・裏取り
// 済み)のstruct ib_mad_hdr(24バイト、以下フィールド順で確認済み)と同じ
// バイトレイアウト:
//   byte0: base_version, byte1: mgmt_class, byte2: class_version,
//   byte3: method, byte4-5: status(BE16), byte6-7: class_specific(BE16),
//   byte8-15: tid(BE64), byte16-17: attr_id(BE16), byte18-19: resv,
//   byte20-23: attr_mod(BE32)。
//
// net.hの規約(「packed構造体への直接多バイトアクセスを禁止し、常に
// volatile経由のバイト単位アクセスへ強制する」CLAUDE.md「ローカル
// スクラッチバッファへの逐次1バイト代入もvolatileが必須」節参照)を
// 踏襲し、構造体ではなく生バイト配列+アクセサ関数の形で定義する
// (net.hのrd16be/rd32be/wr16be/wr32beと同じ流儀、64bit BE版はこの
// ファイル専用に追加-- MADのtidフィールドのみが必要とするため)。

#define IB_MAD_HDR_LEN 24u

#define IB_MGMT_BASE_VERSION 1u
#define IB_MGMT_CLASS_CM     0x07u // Communication Manager(フェーズ(e)用)

#define IB_MGMT_METHOD_GET       0x01u
#define IB_MGMT_METHOD_SET       0x02u
#define IB_MGMT_METHOD_SEND      0x03u
#define IB_MGMT_METHOD_GET_RESP  0x81u
#define IB_MGMT_METHOD_RESP      0x80u

// GSI/QP1の特別qkey(include/rdma/ib_mad.hのIB_QP1_QKEY) -- 最上位ビット
// (bit31)が立っているQPは受信したパケットのqkey値を検査せず受理する
// (IBTA仕様、mlx5.hのMLX5_QP1_QKEYコメント参照)。
#define IB_QP1_QKEY 0x80010000u

// 標準MAD全体サイズ(ヘッダ24B+データ232B、include/rdma/ib_mad.hの
// IB_MGMT_MAD_SIZE=IB_MGMT_MAD_HDR(24)+IB_MGMT_MAD_DATA(232)で確認済み)。
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

// MADヘッダ(先頭IB_MAD_HDR_LEN(24)バイト)を組み立てるヘルパ。bufは
// 少なくとも24バイト。class_versionはMADクラスごとに規定される値
// (フェーズ(d)診断のダミーMADは1、フェーズ(e)のCM[IB_MGMT_CLASS_CM]は
// drivers/infiniband/core/cm_msgs.hのIB_CM_CLASS_VERSION=2)。
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
