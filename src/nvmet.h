#ifndef NVMET_H
#define NVMET_H

#include <stdint.h>
#include "nvmet_tcp.h"
#include "netif.h"

/* 統計をコアごとに持つときの本数(SMP_MAX_CORES と同じ。smp.h を引くと
 * ヘッダの依存が増えるので、ここで独立に定義して nvmet.c で検算する)。 */
#define NVMET_STAT_CORES 4u

/* **1 コアぶんでちょうど 1 キャッシュライン。** 隣のコアの更新で自分の行が
 * 無効化されると、分けた意味が無くなる(false sharing)。 */
typedef struct {
    uint64_t read_bytes;
    uint64_t write_bytes;
    uint64_t read_cmds;
    uint64_t write_cmds;
    /* **エラー記録の文脈も毎コマンド書く**ので、同じ行に置いてコア間で
     * 共有しない(値そのものは「直前に処理したコマンド」の意味で、
     * エラーを起こしたコアの値を読めばよい)。 */
    uint64_t err_lba;
    uint32_t write_incapsule;   /* write の内訳: in-capsule で届いた数 */
    uint32_t write_h2c;         /* write の内訳: R2T -> H2CData で届いた数 */
    uint32_t err_nsid;
    uint16_t err_sqid;
    uint8_t  pad[10];
} __attribute__((aligned(64))) nvmet_core_stat_t;
_Static_assert(sizeof(nvmet_core_stat_t) == 64, "nvmet_core_stat_t は 1 キャッシュライン");

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

/* 1 つのコントローラが同時に持てる IO キュー(= TCP コネクション)の本数の
 * **上限**。実際に何本広告するかは実行時に `g_nvmet_io_queues` で決める
 * (シェルの `nvmetqueues`)。**1 にすると従来どおりの 1 本だけ**になるので
 * 陰性対照として使える。
 *
 * **上限は `TCP_MAX_CONNS`(32/コア)と `JOB_MAX`(32)で決まる。** 1 セッションで
 * admin 1 + IO N 本を握り、listen backlog(最大 4)と内蔵イニシエータ
 * (admin+IO の 2 本)が同時に生きうる。**増やすときは両方を一緒に見ること。**
 *
 * **1 キューあたり約 1.1MB**(`dsm_stage[256][4096]` が支配的)なので、
 * 16 本で約 18MB を .bss に置く。
 *
 * **この機材では 4 本より多くは実測できない** -- Linux のホストは
 * `min(要求, オンライン CPU 数)` に丸め、Pi5 は 4 コアだから。16 にして
 * あるのは「本数を決めるのは利用者であってこちらではない」ため。 */
#define NVMET_IO_QUEUES 16u

/* **この本数以上の IO キューを合意したときだけ ACK の相乗りを使う。**
 * 実測(方向B、512B read qd=128): 4 本では 98.0k -> 106.8k(+9%、kernel
 * 108.3k / SPDK 107.6k と並ぶ)。1 本では 245k -> 207k、3 本では
 * 332k -> 281k と**損**になる(相手の cpu0 が 85〜90% で飽和しており、
 * ACK が送信のペーシングに効いているため)。 */
#define NVMET_ACKPIGGY_MIN_QUEUES 4u

#define NVMET_MAX_PENDING_WRITES 8u

/* push 型受信の ready-ring の段数(`nvmet.c` が使う)。**Dataset Management の
 * 範囲リストを ring のスロットと 1 対 1 で置くためにここに出してある。** */
/* 受理済みコマンドのリング。**ホストへ広告する MAXCMD より大きくすること**
 * (同じ値にすると上限ちょうどで詰まる -- nvmet_rdma で踏んだのと同型)。 */
#define NVMET_READY_RING 256u

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

/* `io_arm_owner` の番人。0 以上は IO キュー番号。 */
#define NVMET_ARM_FREE  (-1)
#define NVMET_ARM_ADMIN (-2)

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
    uint16_t ctrlr_id;   /* 固定値1 */
    uint32_t cc;         /* CCレジスタ(Property Setで書き込まれる) */
    int      cc_en;      /* cc & NVME_CC_ENが立ったら1 */
    int      shutdown_complete; /* CC.SHNを受けた=CSTS.SHSTに完了(10b)を返す */

    /* admin が Fabrics Connect(qid=0)を受理したら 1。IO ジョブはこれが
     * 立つまで accept しない。**Discovery コントローラでは立てない**
     * (IO キューを作らないので、arm すると次の接続の admin 用 SYN を
     * IO 側の accept が食べてしまう)。 */
    volatile int io_armed;

    /* ---- 複数 IO キュー(= 複数コネクション)------------------------------
     * **listener の受け皿(`accept_conn`)は 1 本しか無い**ので、admin と N 本の
     * IO ジョブが同時に arm することはできない。この「arm 権」を持てるのは
     * 常に 1 ジョブだけで、`tcp_accept_ready_poll()` を呼んでよいのも
     * 権利を持っているジョブだけ。**持っていないジョブが poll すると、
     * armed なジョブ宛に確立したコネクションを横取りする。** */
    volatile int io_arm_owner;       /* NVMET_ARM_FREE / _ADMIN / IO キュー番号 */
    /* いま確立している IO キューの本数。0 になった時点でセッション終了。 */
    volatile int io_open;
    /* Set Features(Number of Queues)でホストと合意した IO キュー本数。
     * **ホストの要求とこちらの上限の小さいほう。** これ以上は arm しない
     * (arm したまま残すと、その受け皿が次の admin 接続を食べてしまう)。 */
    volatile uint32_t io_queues_granted;

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

    /* SMART / Error Information ログの実体。**セッションをまたいで持ち越す**
     * (実コントローラの通電中の統計はホストが繋ぎ直しても 0 に戻らない)。
     * リセットするのは nvmet_job_start() = プロセス起動時だけ。 */
    uint64_t start_tick;         /* power_on_hours の起点 */
    /* **IO ホットパスで進むカウンタはコアごとに持つ**(合計は冷たい経路で取る)。
     * 複数コアで IO キューを回すようになったので、1 本の共有カウンタだと
     * **1 コマンドごとに同じキャッシュラインをコア間で往復させる**ことになる。
     * 実測で、2 コアへ分散した途端に 512B read が 266k -> 211k、
     * 4K read が 182k -> 147k まで落ちた(分散した効果を自分で食い潰していた)。
     * 読むのは SMART / Keep Alive / 表示だけなので、そこで足し合わせればよい。 */
    nvmet_core_stat_t stat[NVMET_STAT_CORES];
    uint64_t error_count;        /* 発生したエラーの累計(SMART の num_err_log_entries)*/
    /* 直近 1 件のエラー(ELPE=0 = 1 エントリを広告している)。 */
    uint8_t  error_slot[NVME_ERROR_SLOT_LEN];
} nvmet_ctx_t;

/* 全コアぶんを足した統計を取り出す(NULL のポインタは無視する)。 */
void nvmet_stat_totals(const nvmet_ctx_t *ctx, uint64_t *read_bytes, uint64_t *write_bytes,
                       uint64_t *read_cmds, uint64_t *write_cmds,
                       uint32_t *write_incapsule, uint32_t *write_h2c);
void nvmet_stat_clear(nvmet_ctx_t *ctx);

int nvmet_job_start(nvmet_ctx_t *ctx, uint16_t port, netif_t *bound_ctx, const char *label);

/* 広告する IO キュー(= 同時に受け付ける IO コネクション)の本数。
 * 1..NVMET_IO_QUEUES。**1 が従来の挙動(陰性対照)。** `txdrop` などと同じ
 * 恒久デバッグ機能で、**変更は次のセッションから効く**(Set Features で
 * ホストと合意する値なので、確立済みのセッションには反映できない)。 */
extern volatile uint32_t g_nvmet_io_queues;
void nvmet_io_queues_show(const nvmet_ctx_t *ctx);

/* 名前空間の追加/削除(シェルの `nvmens` から呼ぶ)。**D6 の AER は
 * これで発火させる** -- 稼働中に名前空間が増減したことをホストへ通知し、
 * Linux が再スキャンするところまでが 1 つの検証になる。
 * 戻り値: 0=変更した、-1=nsid が範囲外か既にその状態 */
int nvmet_ns_set_active(nvmet_ctx_t *ctx, uint32_t nsid, int active);
void nvmet_ns_show(nvmet_ctx_t *ctx);

#endif /* NVMET_H */
