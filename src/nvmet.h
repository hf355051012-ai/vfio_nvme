#ifndef NVMET_H
#define NVMET_H

#include <stdint.h>
#include "nvmet_tcp.h"
#include "netif.h"

#define NVMET_LBA_SIZE       512u

/* 名前空間は 2 つ。**2 個目を小さくしてあるのは .bss の都合**(1 個目と同じ
 * 256MB にすると `SMP_MAX_CORES` ぶんの約 430MB と合わせて hugepages に
 * 収まらなくなる)。**サイズが違うほうが「名前空間ごとに別の実体を見て
 * いるか」の確認としても強い。** */
#define NVMET_NSID_MAX        2u
#define NVMET_NS1_LBA_COUNT  524288u   /* 256MB */
#define NVMET_NS2_LBA_COUNT   65536u   /* 32MB */

/* 1 個目の名前空間。既存のコードが「唯一の名前空間」を指すのに使っていた
 * 定数で、いまは「既定で有効な名前空間」の意味。 */
#define NVMET_NSID          1u
#define NVMET_NS_LBA_COUNT  NVMET_NS1_LBA_COUNT

/* nsid=0xFFFFFFFF(全名前空間)。Flush と Get Log Page で実際に来る。 */
#define NVMET_NSID_BROADCAST 0xFFFFFFFFu
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

/* push 型受信の ready-ring の段数(`nvmet.c` が使う)。**Dataset Management の
 * 範囲リストを ring のスロットと 1 対 1 で置くためにここに出してある。** */
#define NVMET_READY_RING 64u

/* Dataset Management の範囲リストの置き場(1 コマンドぶん)。
 * NR は 8bit + 0's based なので最大 256 範囲 x 16 バイト = 4096。 */
#define NVMET_DSM_STAGE_BYTES (NVME_DSM_MAX_RANGES * NVME_DSM_RANGE_LEN)

/* CNS=0x06 で広告する discard の上限。**ここを広告しないと Linux は
 * 1 コマンドで名前空間全体を消しに来る**(RAM ディスクを memset する
 * 実装なので、そのぶんジョブスケジューラが止まる)。
 * DMRSL = 65536 ブロック = 32MB は Write Zeroes の NLB 上限(16bit + 1)と
 * 同じ値で、2 つのコマンドの最悪ケースを揃えてある。 */
#define NVMET_DSM_MAX_RANGES_ADV  64u
#define NVMET_DSM_MAX_RANGE_LBAS  65536u
#define NVMET_DSM_MAX_TOTAL_LBAS  65536u

typedef struct {
    int      in_use;
    uint16_t cid;
    uint64_t slba;
    uint32_t write_len;
    uint32_t received;   /* このコマンドについてこれまでに受信したH2CDataバイト数 */
    uint8_t *disk;       /* 対象名前空間の実体。**nsid ごとに違う** */
} nvmet_pending_write_t;

/* 名前空間 1 つ。`active` が 0 なら「nsid の範囲内だが未使用」で、
 * Identify Namespace はゼロ埋めで正常完了する(エラーではない)。 */
typedef struct {
    int      active;
    uint64_t lba_count;
    uint8_t *disk;
    uint8_t  id_ns[4096] __attribute__((aligned(64)));
} nvmet_ns_t;

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

    /* Fabrics Connect の cdw12 で受け取った Keep Alive Timeout(ミリ秒)。
     * 0 = Keep Alive 無効(Discovery コントローラは通常 0 で繋いでくる)。
     * Get Features(FID=0x0F)がそのまま返す。**タイマの強制は D7。** */
    uint32_t kato_ms;
    /* Keep Alive の起点。**「Keep Alive の受信」ではなく「何らかのコマンドの
     * 受信」で延命する**(仕様上もそれでよい)。0 = 未接続。 */
    uint64_t last_cmd_tick;
    /* admin ジョブが KATO 切れを検出したら立てる。**IO ジョブは自分で
     * 畳む**(別ジョブのコネクションを横から閉じない)。 */
    volatile int kato_expired;
    /* Set Features(FID=0x0B)でホストが有効化した非同期イベント。
     * **ここで有効化されたイベントしか送ってはいけない。** */
    uint32_t aen_config;

    /* 保留中の Async Event Request。AERL=0(0's based)= 同時 1 個なので
     * cid を 1 つ覚えるだけでよい。**セッションが切れたら捨てる。** */
    int      aer_pending;
    uint16_t aer_cid;
    /* 「名前空間が変わったことを通知したい」の旗。**シェル(core0)は旗を
     * 立てるだけで、CQE の送信は admin ジョブ(core1)がやる。** 別コアから
     * 同じコネクションへ送ると、受信ポーリング中の admin ジョブと競合する
     * (RDMA CM で同じ形の不具合を踏んでいる)。 */
    volatile int aer_notify_ns;
    /* Changed Namespace List(LID=0x04)。**読み出したらクリアする**のが
     * 仕様なので、溜めておく必要がある。0 = 変更なし。 */
    uint32_t changed_nsid[NVME_MAX_CHANGED_NAMESPACES];
    uint32_t changed_nsid_count;

    /* 名前空間。nsid はこの配列の添字 + 1。 */
    nvmet_ns_t ns[NVMET_NSID_MAX];

    uint8_t  ram_disk[NVMET_NS1_LBA_COUNT * NVMET_LBA_SIZE] __attribute__((aligned(64)));
    uint8_t  ram_disk2[NVMET_NS2_LBA_COUNT * NVMET_LBA_SIZE] __attribute__((aligned(64)));
    uint8_t  id_ctrl[4096] __attribute__((aligned(64)));
    /* Discovery コントローラ用の Identify Controller。通常のものとは
     * CNTRLTYPE / SUBNQN / NN などが違うので別に持つ。 */
    uint8_t  id_ctrl_disc[4096] __attribute__((aligned(64)));
    /* Identify のうちコマンドごとに組み立てるもの(CNS=0x02 の Active
     * Namespace ID List、CNS=0x03 の記述子リスト、CNS=0x05 のゼロ埋め)。
     * admin キューは 1 コマンドずつ同期処理で、送信は nvmet_tcp_send_c2h() が
     * 自前のバッファへコピーするので使い回してよい。 */
    uint8_t  id_scratch[4096] __attribute__((aligned(64)));
    /* Get Log Page 応答用。LID=0x70 以外は常にゼロ(エラー情報も SMART も
     * 持たない)。 */
    uint8_t  log_page[4096] __attribute__((aligned(64)));
    /* Discovery Log Page(ヘッダ + エントリ)。 */
    uint8_t  disc_log[NVMET_DISC_LOG_LEN] __attribute__((aligned(64)));

    /* Dataset Management の範囲リスト。**ready-ring のスロットと 1 対 1** で
     * 割り当てるので、DSM が続けて届いても互いを踏まない。ring 側に持たせると
     * スロットの間隔が 4KB 開いて **hot path(通常の read/write)の TLB を
     * 荒らす**ので、こちらへ置いてある。 */
    uint8_t  dsm_stage[NVMET_READY_RING][NVMET_DSM_STAGE_BYTES] __attribute__((aligned(64)));

    /* SMART / Error Information ログの実体。**セッションをまたいで持ち越す**
     * (実コントローラの通電中の統計はホストが繋ぎ直しても 0 に戻らない)。
     * リセットするのは nvmet_job_start() = プロセス起動時だけ。 */
    uint64_t start_tick;         /* power_on_hours の起点 */
    uint64_t stat_read_bytes;
    uint64_t stat_write_bytes;
    uint64_t stat_read_cmds;
    uint64_t stat_write_cmds;
    uint64_t error_count;        /* 発生したエラーの累計(SMART の num_err_log_entries)*/
    /* 直近 1 件のエラー(ELPE=0 = 1 エントリを広告している)。 */
    uint8_t  error_slot[NVME_ERROR_SLOT_LEN];
    /* エラー記録に使う「いま処理中のコマンド」の文脈。dispatch の入口で
     * 設定し、LBA を持つコマンドだけがエラー直前に err_lba を入れる。 */
    uint16_t err_sqid;
    uint32_t err_nsid;
    uint64_t err_lba;

    uint32_t write_incapsule_count;
    uint32_t write_h2c_count;
    nvmet_pending_write_t pending_writes[NVMET_MAX_PENDING_WRITES];
} nvmet_ctx_t;

int nvmet_job_start(nvmet_ctx_t *ctx, uint16_t port, netif_t *bound_ctx, const char *label);

/* 名前空間の追加/削除(シェルの `nvmens` から呼ぶ)。**D6 の AER は
 * これで発火させる** -- 稼働中に名前空間が増減したことをホストへ通知し、
 * Linux が再スキャンするところまでが 1 つの検証になる。
 * 戻り値: 0=変更した、-1=nsid が範囲外か既にその状態 */
int nvmet_ns_set_active(nvmet_ctx_t *ctx, uint32_t nsid, int active);
void nvmet_ns_show(nvmet_ctx_t *ctx);

#endif /* NVMET_H */
