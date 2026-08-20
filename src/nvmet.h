#ifndef NVMET_H
#define NVMET_H

#include <stdint.h>
#include "nvmet_tcp.h"
#include "netif.h"

#define NVMET_LBA_SIZE       512u
#define NVMET_NS_LBA_COUNT  524288u
#define NVMET_SUBNQN "nqn.2014-08.org.nvmexpress:uuid:deadbeef-cafe-babe-dead-beefcafebabe"

/* Discovery コントローラの固定 NQN(NVMe-oF 仕様、Linux の
 * include/linux/nvme.h の NVME_DISC_SUBSYS_NAME と同じ文字列)。ホストが
 * Fabrics Connect でこれを指定してきたら通常のサブシステムではなく
 * Discovery コントローラとして応答する。 */
#define NVMET_DISCOVERY_NQN "nqn.2014-08.org.nvmexpress.discovery"

/* Discovery Log Page(LID=0x70)の 1024 バイト固定レイアウト。
 * include/linux/nvme.h の struct nvmf_disc_rsp_page_hdr /
 * struct nvmf_disc_rsp_page_entry のバイトオフセットを
 * tools/disc_log_check.c の offsetof で機械的に確認した値。 */
#define NVMET_DISC_HDR_LEN        1024u
#define NVMET_DISC_ENTRY_LEN      1024u
#define NVMET_DISC_OFF_GENCTR        0u
#define NVMET_DISC_OFF_NUMREC        8u
#define NVMET_DISC_OFF_RECFMT       16u
#define NVMET_DISC_ENT_OFF_TRTYPE    0u
#define NVMET_DISC_ENT_OFF_ADRFAM    1u
#define NVMET_DISC_ENT_OFF_SUBTYPE   2u
#define NVMET_DISC_ENT_OFF_TREQ      3u
#define NVMET_DISC_ENT_OFF_PORTID    4u
#define NVMET_DISC_ENT_OFF_CNTLID    6u
#define NVMET_DISC_ENT_OFF_ASQSZ     8u
#define NVMET_DISC_ENT_OFF_TRSVCID  32u
#define NVMET_DISC_ENT_OFF_SUBNQN  256u
#define NVMET_DISC_ENT_OFF_TRADDR  512u
#define NVMET_DISC_ENT_OFF_TSAS    768u

/* このターゲットは 1 サブシステムしか持たないのでエントリは 1 個。 */
#define NVMET_DISC_NUMREC   1u
#define NVMET_DISC_LOG_LEN  (NVMET_DISC_HDR_LEN + NVMET_DISC_NUMREC * NVMET_DISC_ENTRY_LEN)

#define NVMET_MAX_TRANSFER_BYTES 262144u

#define NVMET_IOCCSZ_MAX_BYTES 262144u

#define NVMET_MAX_INSTANCES 1u

#define NVMET_MAX_PENDING_WRITES 8u

typedef struct {
    int      in_use;
    uint16_t cid;
    uint64_t slba;
    uint32_t write_len;
    uint32_t received;   /* このコマンドについてこれまでに受信したH2CDataバイト数 */
} nvmet_pending_write_t;

typedef struct {
    nvmet_tcp_conn_t admin;
    nvmet_tcp_conn_t io;
    int      io_connected;
    uint16_t ctrlr_id;   /* 固定値1 */
    uint32_t cc;         /* CCレジスタ(Property Setで書き込まれる) */
    int      cc_en;      /* cc & NVME_CC_ENが立ったら1 */
    int      shutdown_complete; /* CC.SHNを受けた=CSTS.SHSTに完了(10b)を返す */

    volatile int io_armed;
    volatile int admin_failed;
    volatile int session_done;
    volatile int session_active;
    volatile int stop_requested;

    int         listener;    /* tcp_listen()ハンドル */
    netif_t  *bound_ctx;   /* 待ち受けるインターフェース、NULL=任意 */
    const char *label;
    uint16_t    listen_port; /* Discovery Log Page の trsvcid に載せる */

    /* Fabrics Connect の subnqn が Discovery NQN だった = このセッションは
     * Discovery コントローラ。Identify Controller と Get Log Page の応答が
     * 通常のサブシステムと変わる。 */
    int      is_discovery;

    uint8_t  ram_disk[NVMET_NS_LBA_COUNT * NVMET_LBA_SIZE] __attribute__((aligned(64)));
    uint8_t  id_ctrl[4096] __attribute__((aligned(64)));
    /* Discovery コントローラ用の Identify Controller。通常のものとは
     * CNTRLTYPE / SUBNQN / NN などが違うので別に持つ。 */
    uint8_t  id_ctrl_disc[4096] __attribute__((aligned(64)));
    uint8_t  id_ns[4096]   __attribute__((aligned(64)));
    /* Get Log Page 応答用。LID=0x70 以外は常にゼロ(エラー情報も SMART も
     * 持たない)。 */
    uint8_t  log_page[4096] __attribute__((aligned(64)));
    /* Discovery Log Page(ヘッダ + エントリ)。 */
    uint8_t  disc_log[NVMET_DISC_LOG_LEN] __attribute__((aligned(64)));

    uint32_t write_incapsule_count;
    uint32_t write_h2c_count;
    nvmet_pending_write_t pending_writes[NVMET_MAX_PENDING_WRITES];
} nvmet_ctx_t;

int nvmet_job_start(nvmet_ctx_t *ctx, uint16_t port, netif_t *bound_ctx, const char *label);

#endif /* NVMET_H */
