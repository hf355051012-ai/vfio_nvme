#ifndef SCSI_H
#define SCSI_H

/* SCSI のブロック装置(SBC-3 / SPC-4 の最小集合)。**トランスポートを知らない**:
 * CDB を受け取って「読み出すデータの場所と長さ」か「書き込み先の場所と長さ」、または
 * 状態とセンスを返す。iSCSI(iscsit.c)が使う。将来 iSER / SRP に載せ替えられる形にする。
 * 応答の形は Linux の LIO(drivers/target/target_core_spc.c / target_core_sbc.c)が
 * 返しているものを手本にした(PLAN_iscsi.md 段階 0 の記録)。 */

#include <stdint.h>

#define SCSI_MAX_LUNS    2u
#define SCSI_BLOCK_SIZE  512u

/* センスキー / ASC(SPC-4 4.5)。 */
#define SCSI_SK_NO_SENSE        0x0u
#define SCSI_SK_NOT_READY       0x2u
#define SCSI_SK_MEDIUM_ERROR    0x3u
#define SCSI_SK_ILLEGAL_REQUEST 0x5u
#define SCSI_SK_UNIT_ATTENTION  0x6u
#define SCSI_SK_ABORTED_COMMAND 0xBu
#define SCSI_ASC_INVALID_OPCODE 0x20u
#define SCSI_ASC_LBA_OUT_OF_RANGE 0x21u
#define SCSI_ASC_INVALID_FIELD_CDB 0x24u
#define SCSI_ASC_LUN_NOT_SUPPORTED 0x25u
#define SCSI_ASC_SAVING_NOT_SUPPORTED 0x39u

typedef struct {
    uint8_t  *disk;          /* NULL = その LUN は無い */
    uint64_t  nblocks;
    char      serial[24];    /* VPD 0x80 */
} scsi_lun_t;

#define SCSI_SK_MISCOMPARE      0xEu
#define SCSI_ASC_MISCOMPARE_VERIFY 0x1Du

/* VERIFY(BYTCHK=1 / 3)は「データを受け取って媒体と比べる」ので、WRITE と同じく
 * データを受けるが書き込まない。 */
typedef enum { SCSI_DIR_NONE = 0, SCSI_DIR_READ, SCSI_DIR_WRITE, SCSI_DIR_VERIFY } scsi_dir_t;

typedef struct {
    uint8_t   status;        /* SCSI_STATUS_GOOD / CHECK_CONDITION */
    uint8_t   sk, asc, ascq; /* CHECK CONDITION のときのセンス */
    uint8_t   dir;           /* scsi_dir_t */
    uint8_t   verify_mode;   /* VERIFY: 1 = 受けたデータと範囲全体を比べる / 3 = 1 ブロックを範囲の全ブロックと比べる */
    uint32_t  verify_blocks; /* VERIFY の範囲のブロック数 */
    uint8_t  *data;          /* READ: 送るデータ / WRITE: 書き込み先 / VERIFY: 比べる媒体の先頭 */
    uint32_t  len;           /* 転送するバイト数(SCSI 側の長さ。iSCSI の EDTL との差は residual)*/
} scsi_result_t;

/* VERIFY の比較。off は受けたデータの範囲の位置。0 = 一致 / 1 = 食い違い。 */
int scsi_verify_cmp(const scsi_result_t *r, uint32_t off, const uint8_t *buf, uint32_t len);

/* LUN の表を登録する(disk = NULL で外す)。 */
void scsi_set_lun(unsigned lun, uint8_t *disk, uint64_t nblocks, const char *serial);
const scsi_lun_t *scsi_get_lun(unsigned lun);

/* CDB の LUN の欄(SAM の 8 バイト)から LUN 番号を取り出す(周辺 / フラット。それ以外は 0xFFFF)。 */
unsigned scsi_decode_lun(const uint8_t lun8[8]);

/* 1 コマンドを解釈する。buf は INQUIRY などの応答を組み立てる作業場所(cap バイト)。
 * READ / WRITE はディスクの位置を返すだけで、データの移動は呼び出し側がする。 */
void scsi_exec(unsigned lun, const uint8_t cdb[16], uint8_t *buf, uint32_t cap, scsi_result_t *r);

#endif /* SCSI_H */
