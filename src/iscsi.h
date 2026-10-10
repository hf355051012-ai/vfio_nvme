#ifndef ISCSI_H
#define ISCSI_H

/* iSCSI(RFC 7143)の PDU の形式と定数。ターゲット(iscsit.c)とイニシエータで共用する。
 * 配置は RFC 7143 11 章と Linux の include/scsi/iscsi_proto.h から写した。
 * **多バイトの欄はすべてビッグエンディアン**(ダイジェストだけは例外でリトルエンディアン。
 * LIO の記録で確かめた。PLAN_iscsi.md 段階 0)。 */

#include <stdint.h>

#define ISCSI_PORT            3260u
#define ISCSI_BHS_LEN         48u
#define ISCSI_DIGEST_LEN      4u
/* Login 中の MaxRecvDataSegmentLength は双方 8192 に固定(RFC 7143 13.12)。 */
#define ISCSI_LOGIN_MAX_DSL   8192u
#define ISCSI_RSVD_TAG        0xFFFFFFFFu   /* ITT / TTT の「無し」 */

/* ---- オペコード(BHS の byte0 の下位 6 ビット。bit6 は Immediate)---- */
#define ISCSI_OP_IMMEDIATE    0x40u
#define ISCSI_OP_MASK         0x3Fu
#define ISCSI_OP_NOOP_OUT     0x00u
#define ISCSI_OP_SCSI_CMD     0x01u
#define ISCSI_OP_TMF_REQ      0x02u
#define ISCSI_OP_LOGIN        0x03u
#define ISCSI_OP_TEXT         0x04u
#define ISCSI_OP_DATA_OUT     0x05u
#define ISCSI_OP_LOGOUT       0x06u
#define ISCSI_OP_SNACK        0x10u
#define ISCSI_OP_NOOP_IN      0x20u
#define ISCSI_OP_SCSI_RSP     0x21u
#define ISCSI_OP_TMF_RSP      0x22u
#define ISCSI_OP_LOGIN_RSP    0x23u
#define ISCSI_OP_TEXT_RSP     0x24u
#define ISCSI_OP_DATA_IN      0x25u
#define ISCSI_OP_LOGOUT_RSP   0x26u
#define ISCSI_OP_R2T          0x31u
#define ISCSI_OP_ASYNC        0x32u
#define ISCSI_OP_REJECT       0x3Fu

/* ---- 共通の欄の位置 ---- */
#define ISCSI_OFF_AHSLEN      4u    /* TotalAHSLength(4 バイト単位)*/
#define ISCSI_OFF_DSL         5u    /* DataSegmentLength(3 バイト)*/
#define ISCSI_OFF_LUN         8u
#define ISCSI_OFF_ITT         16u
#define ISCSI_OFF_TTT         20u
#define ISCSI_OFF_CMDSN       24u   /* 要求: CmdSN / 応答: StatSN */
#define ISCSI_OFF_EXPSTATSN   28u   /* 要求: ExpStatSN / 応答: ExpCmdSN */
#define ISCSI_OFF_MAXCMDSN    32u

/* ---- Login(11.12 / 11.13)---- */
#define ISCSI_LOGIN_T         0x80u
#define ISCSI_LOGIN_C         0x40u
#define ISCSI_STAGE_SEC       0u
#define ISCSI_STAGE_OP        1u
#define ISCSI_STAGE_FFP       3u
#define ISCSI_LOGIN_OFF_ISID  8u    /* 6 バイト */
#define ISCSI_LOGIN_OFF_TSIH  14u   /* 2 バイト */
#define ISCSI_LOGIN_OFF_CID   20u   /* 2 バイト(要求のみ)*/
#define ISCSI_LOGIN_OFF_STATUS 36u  /* 応答: 状態クラス、詳細 */

/* 状態(クラス << 8 | 詳細)。**RFC 7143 11.13.5 の値**(LIO は一部違う値を返す)。 */
#define ISCSI_LS_SUCCESS          0x0000u
#define ISCSI_LS_INIT_ERR         0x0200u
#define ISCSI_LS_AUTH_FAILED      0x0201u
#define ISCSI_LS_AUTHZ_FAILED     0x0202u
#define ISCSI_LS_NOT_FOUND        0x0203u
#define ISCSI_LS_TGT_REMOVED      0x0204u
#define ISCSI_LS_NO_VERSION       0x0205u
#define ISCSI_LS_TOO_MANY_CONN    0x0206u
#define ISCSI_LS_MISSING_PARAM    0x0207u
#define ISCSI_LS_CANT_INCLUDE     0x0208u
#define ISCSI_LS_NO_SESSION_TYPE  0x0209u
#define ISCSI_LS_NO_SESSION       0x020Au
#define ISCSI_LS_INVALID_REQUEST  0x020Bu
#define ISCSI_LS_TARGET_ERR       0x0300u
#define ISCSI_LS_SVC_UNAVAILABLE  0x0301u
#define ISCSI_LS_NO_RESOURCES     0x0302u

/* ---- Text(11.10 / 11.11)---- */
#define ISCSI_TEXT_F          0x80u
#define ISCSI_TEXT_C          0x40u

/* ---- SCSI Command / Response(11.3 / 11.4)---- */
#define ISCSI_CMD_F           0x80u
#define ISCSI_CMD_R           0x40u
#define ISCSI_CMD_W           0x20u
#define ISCSI_CMD_OFF_EDTL    20u   /* Expected Data Transfer Length */
#define ISCSI_CMD_OFF_CDB     32u   /* 16 バイト */
#define ISCSI_RSP_OFF_RESPONSE 2u
#define ISCSI_RSP_OFF_STATUS  3u
#define ISCSI_RSP_OFF_RESID   44u
#define ISCSI_RSP_FLAG_O      0x04u  /* residual overflow */
#define ISCSI_RSP_FLAG_U      0x02u  /* residual underflow */

/* SCSI の状態(SAM)。 */
#define SCSI_STATUS_GOOD            0x00u
#define SCSI_STATUS_CHECK_CONDITION 0x02u
#define SCSI_STATUS_BUSY            0x08u

/* ---- Logout(11.14 / 11.15)---- */
#define ISCSI_LOGOUT_REASON_MASK 0x7Fu

/* ---- Reject(11.17)の理由 ---- */
#define ISCSI_REJECT_DIGEST_ERR     0x02u
#define ISCSI_REJECT_SNACK          0x03u
#define ISCSI_REJECT_PROTOCOL_ERR   0x04u
#define ISCSI_REJECT_CMD_NOT_SUPP   0x05u
#define ISCSI_REJECT_IMM_REJECT     0x06u
#define ISCSI_REJECT_TASK_IN_PROG   0x07u
#define ISCSI_REJECT_INVALID_FIELD  0x09u
#define ISCSI_REJECT_WAITING_LOGOUT 0x0Cu

/* ---- 多バイトの読み書き ---- */
static inline uint32_t iscsi_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint32_t iscsi_be24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}
static inline uint16_t iscsi_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static inline void iscsi_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void iscsi_put24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
}
static inline void iscsi_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

/* シリアル番号の比較(RFC 1982、CmdSN / StatSN / DataSN / R2TSN)。**素の < で比べない** --
 * 2^31 を越えたところで壊れる(SACK の recover ガードで踏んだのと同じ形)。 */
static inline int iscsi_sn_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int iscsi_sn_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }

/* ---- 交渉で決まる値(片方の接続 = 片方のセッション。MaxConnections=1)---- */
typedef struct {
    uint8_t  hdgst;                /* HeaderDigest=CRC32C */
    uint8_t  ddgst;                /* DataDigest=CRC32C */
    uint8_t  initial_r2t;
    uint8_t  immediate_data;
    uint8_t  data_pdu_in_order;
    uint8_t  data_seq_in_order;
    uint8_t  erl;
    uint8_t  discovery;            /* SessionType=Discovery */
    uint32_t max_recv_dsl;         /* **自分が受け取れる** 1 PDU のデータ長(自分の宣言)*/
    uint32_t max_xmit_dsl;         /* **相手が受け取れる** 1 PDU のデータ長(相手の宣言。送るときはこちら)*/
    uint32_t first_burst;
    uint32_t max_burst;
    uint32_t max_outstanding_r2t;
    uint32_t max_connections;
    uint32_t time2wait;
    uint32_t time2retain;
    /* iSER(RFC 7145)。RDMAExtensions=Yes のとき、MaxRecvDataSegmentLength の代わりに
     * 向きごとの 2 つの長さを使う。 */
    uint8_t  rdma_ext;
    uint32_t ini_recv_dsl;         /* InitiatorRecvDataSegmentLength(イニシエータが受け取れる)*/
    uint32_t tgt_recv_dsl;         /* TargetRecvDataSegmentLength(ターゲットが受け取れる)*/
} iscsi_params_t;

#endif /* ISCSI_H */
