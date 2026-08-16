#ifndef NVMET_H
#define NVMET_H

#include <stdint.h>
#include "nvmet_tcp.h"
#include "netif.h"

#define NVMET_LBA_SIZE       512u
#define NVMET_NS_LBA_COUNT  524288u
#define NVMET_SUBNQN "nqn.2014-08.org.nvmexpress:uuid:deadbeef-cafe-babe-dead-beefcafebabe"

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

    volatile int io_armed;
    volatile int admin_failed;
    volatile int session_done;
    volatile int session_active;
    volatile int stop_requested;

    int         listener;    /* tcp_listen()ハンドル */
    netif_t  *bound_ctx;   /* 待ち受けるインターフェース、NULL=任意 */
    const char *label;

    uint8_t  ram_disk[NVMET_NS_LBA_COUNT * NVMET_LBA_SIZE] __attribute__((aligned(64)));
    uint8_t  id_ctrl[4096] __attribute__((aligned(64)));
    uint8_t  id_ns[4096]   __attribute__((aligned(64)));
    /* Get Log Page 応答用。中身は常にゼロ(エラー情報も SMART も持たない)。 */
    uint8_t  log_page[4096] __attribute__((aligned(64)));

    uint32_t write_incapsule_count;
    uint32_t write_h2c_count;
    nvmet_pending_write_t pending_writes[NVMET_MAX_PENDING_WRITES];
} nvmet_ctx_t;

int nvmet_job_start(nvmet_ctx_t *ctx, uint16_t port, netif_t *bound_ctx, const char *label);

#endif /* NVMET_H */
