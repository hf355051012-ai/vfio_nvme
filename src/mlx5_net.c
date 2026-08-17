#include "mlx5.h"
#include "netif.h"
#include "net.h"
#include "net_buf.h"
#include "uart.h"
#include "timer.h"
#include "mmio.h"
#include "cache.h"
#include "timestamp.h"
#include "smp.h"
#include <stddef.h>

_Static_assert(MLX5_SQ_WQE_COUNT <= ETH_TX_RING_SIZE,
               "mlx5_net_tx_wait_free_slot() returns pc % MLX5_SQ_WQE_COUNT as an index into "
               "tcp.c's s_seg_bufs[core][ETH_TX_RING_SIZE] -- MLX5_SQ_WQE_COUNT must not exceed it");

#define MLX5_NET_CQE_SIZE         64u
#define MLX5_NET_CQ_NUM_ENTRIES   1024u // mlx5_create_cq()のlog_cq_size=10(2^10)と対応
#define MLX5_NET_CQ_LOG_SIZE      10u
#define MLX5_CQE_OWNER_MASK       0x1u
#define MLX5_CQE_OP_INVALID       0xFu
#define MLX5_CQE_OFF_BYTE_CNT     44u
#define MLX5_CQE_OFF_WQE_COUNTER  60u
#define MLX5_CQE_OFF_OP_OWN       63u
#define MLX5_CQE_OFF_TIMESTAMP_H  48u
#define MLX5_CQE_OFF_TIMESTAMP_L  52u
#define MLX5_CQE_OFF_HDS_IP_EXT   28u
#define MLX5_CQE_L3_OK            0x02u
#define MLX5_CQE_L4_OK            0x04u

#define MLX5_CQE_OPCODE_REQ       0x0u
#define MLX5_CQE_OPCODE_SIG_ERR   0xCu
#define MLX5_CQE_OPCODE_REQ_ERR   0xDu
#define MLX5_ERR_CQE_OFF_VENDOR_SYND 54u
#define MLX5_ERR_CQE_OFF_SYNDROME    55u

/*=================================================================
 * CQE のエラー syndrome コードを表示用文字列へ変換する。
 *
 * 引数:
 *   syndrome - MLX5_CQE_SYNDROME_* の値
 * 戻り値:
 *   syndrome 名。未知の値なら "?"
 * コール元:
 *   mlx5_net_sq_reap_one()
 * ===============================================================*/
static const char *mlx5_cqe_syndrome_str(uint8_t syndrome)
{
    switch (syndrome) {
    case 0x01: return "LOCAL_LENGTH_ERR";
    case 0x02: return "LOCAL_QP_OP_ERR";
    case 0x04: return "LOCAL_PROT_ERR";
    case 0x05: return "WR_FLUSH_ERR";
    case 0x06: return "MW_BIND_ERR";
    case 0x10: return "BAD_RESP_ERR";
    case 0x11: return "LOCAL_ACCESS_ERR";
    case 0x12: return "REMOTE_INVAL_REQ_ERR";
    case 0x13: return "REMOTE_ACCESS_ERR";
    case 0x14: return "REMOTE_OP_ERR";
    case 0x15: return "TRANSPORT_RETRY_EXC_ERR";
    case 0x16: return "RNR_RETRY_EXC_ERR";
    case 0x22: return "REMOTE_ABORTED_ERR";
    default:   return "UNKNOWN";
    }
}

typedef struct {
    mlx5_dev_t *dev;
    uint32_t rq_cc;         // RQ用CQの消費カウンタ(単調増加、折り返さない)
    uint32_t rq_posted_ctr; // RQドアベルへ最後に書いた「投稿済みWQE数」の累計
    uint32_t rq_rearm_pending;
    uint32_t sq_pc;         // SQのWQE生成カウンタ(単調増加、論理WQE単位)
    uint32_t sq_cc;         // SQ占有量の消費カウンタ(論理WQE単位、占有量=sq_pc-sq_cc)
    uint32_t sq_cq_cc;      // SQ用CQの消費カウンタ(CQ index/owner/doorbell専用、復帰でリセットしない)

    uint64_t last_tx_hw_ts_cycles;
    uint8_t  has_last_tx_hw_ts;
    uint64_t last_rx_hw_ts_cycles;
    uint8_t  has_last_rx_hw_ts;
} mlx5_net_state_t;

static mlx5_net_state_t s_state_pf0;
static mlx5_net_state_t s_state_pf1;
static netif_t        s_ctx_pf0;
static netif_t        s_ctx_pf1;

static volatile int s_sq_halted[2];

#define MLX5_NET_SQ_RECOVER_WINDOW_MS    10000u
#define MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS 3u
#define MLX5_NET_SQ_RECOVER_PROGRESS_WQES 1000u
static int      s_recover_attempts[2];
static uint64_t s_recover_window_start[2];
static uint32_t s_recover_last_cq_cc[2];

/*=================================================================
 * 状態構造体から PF 番号(0/1)を求める。ログ表示と per-PF 配列の添字に使う。
 *
 * 引数:
 *   st - 対象インターフェースの mlx5_net 状態
 * 戻り値:
 *   PF 番号
 * コール元:
 *   mlx5_net_send_frags(), mlx5_net_send_frags_async(),
 *   mlx5_net_send_lso_async(), mlx5_net_tx_wait_free_slot()
 * ===============================================================*/
static int mlx5_net_pf_index(const mlx5_net_state_t *st)
{
    return (st == &s_state_pf0) ? 0 : 1;
}

static int mlx5_net_try_recover(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st);

/*=================================================================
 * CQ の cc 番目の CQE が HW によって書かれ済みかを判定し、書かれていれば
 * その生ポインタを返す。owner bit(周回ごとに反転)と opcode!=INVALID の
 * 両方を見る -- 初期化センチネルの owner が最初の周回とたまたま一致して
 * しまうため、owner だけでは「未書き込み」と区別できない。
 *
 * 引数:
 *   cq_buf_addr - CQ バッファ先頭
 *   cc          - コンシューマカウンタ(累積値)
 * 戻り値:
 *   到着済み CQE のポインタ。まだなら NULL
 * コール元:
 *   mlx5_net_poll_recv(), mlx5_net_sq_reap_one(), mlx5_net_drain_sq_cq()
 * ===============================================================*/
static volatile uint8_t *mlx5_net_cqe_if_ready(uint64_t cq_buf_addr, uint32_t cc)
{
    uint32_t ci = cc & (MLX5_NET_CQ_NUM_ENTRIES - 1u);
    volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf_addr + (uint64_t)ci * MLX5_NET_CQE_SIZE);
    dcache_invalidate_range((const void *)cqe, MLX5_NET_CQE_SIZE);
    uint8_t op_own = cqe[MLX5_CQE_OFF_OP_OWN];
    uint8_t owner_bit = (uint8_t)(op_own & MLX5_CQE_OWNER_MASK);
    uint8_t expected = (uint8_t)((cc >> MLX5_NET_CQ_LOG_SIZE) & 1u);
    if (owner_bit != expected) {
        return NULL;
    }
    if ((uint8_t)(op_own >> 4) == MLX5_CQE_OP_INVALID) {
        return NULL;
    }
    return cqe;
}

/*=================================================================
 * CQE の HW タイムスタンプ(timestamp_h/l)を 64bit の生サイクル値へ復元する。
 *
 * 引数:
 *   cqe - mlx5_net_cqe_if_ready() が返した CQE
 * 戻り値:
 *   生サイクル値
 * コール元:
 *   mlx5_net_poll_recv(), mlx5_net_sq_reap_one()
 * ===============================================================*/
static uint64_t mlx5_cqe_hw_ts_cycles(volatile uint8_t *cqe)
{
    uint32_t hi = ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H] << 24) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H + 1] << 16) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H + 2] << 8) |
                   (uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_H + 3];
    uint32_t lo = ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L] << 24) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L + 1] << 16) |
                  ((uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L + 2] << 8) |
                   (uint32_t)cqe[MLX5_CQE_OFF_TIMESTAMP_L + 3];
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

/*=================================================================
 * 前回読んだ HW タイムスタンプとの差分を ns 換算して ts へ記録する。
 * dev->clock_khz が未取得(0)なら憶測で換算せず何もしない。ソフトウェア側の
 * 計測値と突き合わせて「HW 遅延かポーリング遅延か」を切り分けるための計装。
 *
 * 引数:
 *   dev        - この CQ を持つ HCA(clock_khz を持つ)
 *   cur_cycles - 今回の HW タイムスタンプ
 *   last / has_last - 前回値とその有効フラグ(呼び出し元が保持)
 *   tag        - ts に記録する識別子
 * コール元:
 *   mlx5_net_poll_recv(), mlx5_net_sq_reap_one()
 * ===============================================================*/
static void mlx5_net_log_hw_ts_delta(mlx5_dev_t *dev, uint64_t cur_cycles,
                                      uint64_t *last_cycles, uint8_t *has_last,
                                      uint32_t tag)
{
    if (!(ts_log_mode() & TS_MODE_HOTPATH)) return;  /* per-frame計装、既定OFF */
    if (dev->clock_khz == 0u) {
        return;
    }
    if (*has_last) {
        uint64_t delta_cycles = cur_cycles - *last_cycles; // unsigned、折り返しも安全
        uint64_t delta_ns = (delta_cycles * 1000000ULL) / (uint64_t)dev->clock_khz;
        uint32_t arg = (delta_ns > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : (uint32_t)delta_ns;
        ts_log(tag, arg);
    }
    *last_cycles = cur_cycles;
    *has_last = 1u;
}

/*=================================================================
 * 通常送信/LSO 送信で共通の「WQE 本体を書き終えた後」の処理。ドアベル
 * レコード更新 -> バリア -> BlueFlame への 64bit アトミック書き込み -> sq_pc
 * 更新、の順に行う。BlueFlame は必ず単一の 64bit ストアで書くこと
 * (32bit×2 に分けると 2 コアの書き込みがワイヤ上でインターリーブしうる)。
 *
 * 引数:
 *   dev / st - 対象 HCA と mlx5_net 状態
 *   wqe      - 書き終えた WQE の先頭
 * コール元:
 *   mlx5_net_post_frame(), mlx5_net_post_lso_frame()
 * ===============================================================*/
static void mlx5_net_wqe_commit(mlx5_dev_t *dev, mlx5_net_state_t *st,
                                 uint32_t pc, volatile uint8_t *wqe)
{
    dma_wmb();

    volatile uint8_t *sq_dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->sq_dbr_cpu;
    uint32_t new_pc = pc + 1u;
    uint32_t hw_new_pc = new_pc * 2u;
    sq_dbr[0] = (uint8_t)(hw_new_pc >> 24);
    sq_dbr[1] = (uint8_t)(hw_new_pc >> 16);
    sq_dbr[2] = (uint8_t)(hw_new_pc >> 8);
    sq_dbr[3] = (uint8_t)hw_new_pc;

    dma_wmb();

    uint32_t raw0 = (uint32_t)wqe[0] | ((uint32_t)wqe[1] << 8) |
                    ((uint32_t)wqe[2] << 16) | ((uint32_t)wqe[3] << 24);
    uint32_t raw1 = (uint32_t)wqe[4] | ((uint32_t)wqe[5] << 8) |
                    ((uint32_t)wqe[6] << 16) | ((uint32_t)wqe[7] << 24);
    uint64_t raw64 = (uint64_t)raw0 | ((uint64_t)raw1 << 32);
    uint64_t uar_addr = dev->bar0_base + (uint64_t)dev->uarn * 4096u;
    mmio_write64(uar_addr + MLX5_BF_OFFSET, raw64);

    st->sq_pc = new_pc;
}

/*=================================================================
 * 通常送信の WQE を 1 個組み立ててポストする。frag_count==1 かつ 60 バイト
 * 以上なら呼び出し元バッファを直接 data_seg で指すゼロコピー、それ以外
 * (複数断片/最小フレーム長未満のパディングが要る場合)はスロット別
 * ステージバッファへ連結してから送る。
 *
 * 引数:
 *   st         - 対象インターフェースの mlx5_net 状態
 *   frags      - 断片配列
 *   frag_count - 断片数
 * 戻り値:
 *   0=ポスト成功、-1=引数不正
 * コール元:
 *   mlx5_net_send_frags(), mlx5_net_send_frags_async()
 * ===============================================================*/
static int mlx5_net_post_frame(mlx5_net_state_t *st, const eth_frag_t *frags, unsigned frag_count)
{
    if (frag_count < 1u || frag_count > ETH_TX_MAX_FRAGS) {
        uart_printf("[mlx5net] send: invalid frag_count (%u)\n", frag_count);
        return -1;
    }

    mlx5_dev_t *dev = st->dev;
    uint32_t pc = st->sq_pc;
    uint32_t slot = pc % MLX5_SQ_WQE_COUNT;

    uint32_t total_len = 0;
    for (unsigned f = 0; f < frag_count; f++) {
        total_len += frags[f].len;
    }
    if (total_len < ETH_HDR_LEN || total_len > MLX5_NET_TX_STAGE_SIZE) {
        uart_printf("[mlx5net] send: invalid frame length (%u)\n", total_len);
        return -1;
    }

    const volatile uint8_t *header_src; // インラインヘッダ(先頭18バイト)の参照元
    uint64_t data_pa;                   // data_seg1のDMAアドレス(18バイト目以降)
    uint32_t frame_total = total_len;   // パディング後の実フレーム長
    uint64_t data2_pa = 0;              // data_seg2のDMAアドレス
    uint32_t remaining1 = 0;            // data_seg1のバイト数
    uint32_t remaining2 = 0;            // data_seg2のバイト数
    const uint32_t ihs = 18u;           // インラインヘッダ(ETH_HLEN+VLAN_HLEN、L2モード)

    if (frag_count == 2u && frags[0].len >= ihs && total_len >= 60u) {
        header_src = (const volatile uint8_t *)frags[0].data;
        data_pa = mlx5_dma_addr((const volatile void *)((const uint8_t *)frags[0].data + ihs));
        remaining1 = frags[0].len - ihs;
        data2_pa = mlx5_dma_addr((const volatile void *)frags[1].data);
        remaining2 = frags[1].len;
    } else if (frag_count == 1u && total_len >= 60u) {
        header_src = (const volatile uint8_t *)frags[0].data;
        uint32_t d = frame_total - ihs;
        remaining2 = 8u;
        remaining1 = d - remaining2;
        data_pa  = mlx5_dma_addr((const volatile void *)((const uint8_t *)frags[0].data + ihs));
        data2_pa = mlx5_dma_addr((const volatile void *)((const uint8_t *)frags[0].data + ihs + remaining1));
    } else {
        volatile uint8_t *stage = (volatile uint8_t *)(uintptr_t)
            ((uint64_t)dev->net_tx_stage_cpu + (uint64_t)(slot) * MLX5_NET_TX_STAGE_SIZE);
        uint32_t off = 0;
        for (unsigned f = 0; f < frag_count; f++) {
            volatile_fast_copy(stage + off, frags[f].data, frags[f].len);
            off += frags[f].len;
        }
        if (total_len < 60u) {
            for (uint32_t i = total_len; i < 60u; i++) stage[i] = 0;
            frame_total = 60u;
        }
        header_src = stage;
        uint32_t d = frame_total - ihs;
        remaining2 = 8u;
        remaining1 = d - remaining2;
        data_pa  = mlx5_dma_addr((const volatile void *)(stage + ihs));
        data2_pa = mlx5_dma_addr((const volatile void *)(stage + ihs + remaining1));
    }

    volatile uint8_t *wqe =
        (volatile uint8_t *)(uintptr_t)((uint64_t)dev->sq_wqe_cpu +
                                         (uint64_t)slot * 2u * MLX5_SEND_WQE_BB);
    for (unsigned i = 0; i < 2u * MLX5_SEND_WQE_BB; i++) wqe[i] = 0;

    uint32_t ds_cnt = 5u;
    uint32_t hw_wqe_idx = (pc * 2u) & 0xFFFFu;
    uint32_t opmod_idx_opcode = (hw_wqe_idx << 8) | MLX5_OPCODE_SEND;
    wqe[0] = (uint8_t)(opmod_idx_opcode >> 24);
    wqe[1] = (uint8_t)(opmod_idx_opcode >> 16);
    wqe[2] = (uint8_t)(opmod_idx_opcode >> 8);
    wqe[3] = (uint8_t)opmod_idx_opcode;

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_post_frame, 0),
           ((uint32_t)MLX5_OPCODE_SEND << 24) | (frame_total & 0xFFFFFFu));

    uint32_t qpn_ds = (dev->sqn << 8) | ds_cnt;
    wqe[4] = (uint8_t)(qpn_ds >> 24);
    wqe[5] = (uint8_t)(qpn_ds >> 16);
    wqe[6] = (uint8_t)(qpn_ds >> 8);
    wqe[7] = (uint8_t)qpn_ds;
    wqe[11] = (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE;

    wqe[20] = 0xC0u; // MLX5_ETH_WQE_L3_CSUM(0x40) | MLX5_ETH_WQE_L4_CSUM(0x80)

    wqe[28] = (uint8_t)(ihs >> 8);
    wqe[29] = (uint8_t)ihs;
    wqe[30] = header_src[0];
    wqe[31] = header_src[1];
    for (unsigned i = 0; i < (ihs - 2u); i++) wqe[32 + i] = header_src[2 + i];
    uint32_t dseg_off = 32u + (ihs - 2u);

    /* data_seg1: setupで計算したremaining1バイト(data_paから)。 */
    uint32_t remaining = remaining1;
    wqe[dseg_off + 0] = (uint8_t)(remaining >> 24);
    wqe[dseg_off + 1] = (uint8_t)(remaining >> 16);
    wqe[dseg_off + 2] = (uint8_t)(remaining >> 8);
    wqe[dseg_off + 3] = (uint8_t)remaining;
    wqe[dseg_off + 4] = (uint8_t)(dev->mkey >> 24);
    wqe[dseg_off + 5] = (uint8_t)(dev->mkey >> 16);
    wqe[dseg_off + 6] = (uint8_t)(dev->mkey >> 8);
    wqe[dseg_off + 7] = (uint8_t)dev->mkey;
    for (unsigned b = 0; b < 8; b++) {
        wqe[dseg_off + 8 + b] = (uint8_t)(data_pa >> (56 - 8 * b));
    }

    {
        uint32_t dseg2_off = dseg_off + 16u;
        wqe[dseg2_off + 0] = (uint8_t)(remaining2 >> 24);
        wqe[dseg2_off + 1] = (uint8_t)(remaining2 >> 16);
        wqe[dseg2_off + 2] = (uint8_t)(remaining2 >> 8);
        wqe[dseg2_off + 3] = (uint8_t)remaining2;
        wqe[dseg2_off + 4] = (uint8_t)(dev->mkey >> 24);
        wqe[dseg2_off + 5] = (uint8_t)(dev->mkey >> 16);
        wqe[dseg2_off + 6] = (uint8_t)(dev->mkey >> 8);
        wqe[dseg2_off + 7] = (uint8_t)dev->mkey;
        for (unsigned b = 0; b < 8; b++) {
            wqe[dseg2_off + 8 + b] = (uint8_t)(data2_pa >> (56 - 8 * b));
        }
    }

    mlx5_net_wqe_commit(dev, st, pc, wqe);
    return 0;
}

/*=================================================================
 * LSO 送信の WQE を 1 個組み立ててポストする。hdr(L2+L3+L4)を eth_seg の
 * インラインヘッダとして載せ、payload を data_seg で指すと、HW が mss 単位に
 * 分割して複数フレームとして送出する。
 *
 * 引数:
 *   st                    - mlx5_net 状態
 *   hdr / hdr_len         - ヘッダテンプレート
 *   payload / payload_len - 分割対象のペイロード
 *   mss                   - 分割単位
 * 戻り値:
 *   0=ポスト成功、-1=引数不正
 * コール元:
 *   mlx5_net_send_lso_async()
 * ===============================================================*/
static int mlx5_net_post_lso_frame(mlx5_net_state_t *st, const void *hdr, uint16_t hdr_len,
                                    const void *payload, uint32_t payload_len, uint16_t mss)
{
    if (hdr_len < 18u || payload_len == 0u) {
        uart_printf("[mlx5net] lso: invalid hdr_len/payload_len (%u/%u)\n",
                    (unsigned)hdr_len, (unsigned)payload_len);
        return -1;
    }

    mlx5_dev_t *dev = st->dev;
    uint32_t pc = st->sq_pc;
    uint32_t slot = pc % MLX5_SQ_WQE_COUNT;

    uint32_t inline_ds = ((uint32_t)hdr_len - 2u + 15u) / 16u;
    uint32_t ds_cnt = 2u + inline_ds + 1u;
    if (ds_cnt * 16u > 2u * MLX5_SEND_WQE_BB) {
        uart_printf("[mlx5net] lso: hdr_len too large for WQE budget (hdr_len=%u ds_cnt=%u)\n",
                    (unsigned)hdr_len, ds_cnt);
        return -1;
    }

    volatile uint8_t *wqe =
        (volatile uint8_t *)(uintptr_t)((uint64_t)dev->sq_wqe_cpu +
                                         (uint64_t)slot * 2u * MLX5_SEND_WQE_BB);
    for (unsigned i = 0; i < 2u * MLX5_SEND_WQE_BB; i++) wqe[i] = 0;

    uint32_t hw_wqe_idx = (pc * 2u) & 0xFFFFu;
    uint32_t opmod_idx_opcode = (hw_wqe_idx << 8) | MLX5_OPCODE_LSO;
    wqe[0] = (uint8_t)(opmod_idx_opcode >> 24);
    wqe[1] = (uint8_t)(opmod_idx_opcode >> 16);
    wqe[2] = (uint8_t)(opmod_idx_opcode >> 8);
    wqe[3] = (uint8_t)opmod_idx_opcode;

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_post_lso_frame, 0),
           ((uint32_t)MLX5_OPCODE_LSO << 24) | (payload_len & 0xFFFFFFu));

    uint32_t qpn_ds = (dev->sqn << 8) | ds_cnt;
    wqe[4] = (uint8_t)(qpn_ds >> 24);
    wqe[5] = (uint8_t)(qpn_ds >> 16);
    wqe[6] = (uint8_t)(qpn_ds >> 8);
    wqe[7] = (uint8_t)qpn_ds;
    wqe[11] = (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE;

    wqe[20] = 0xC0u; // MLX5_ETH_WQE_L3_CSUM(0x40) | MLX5_ETH_WQE_L4_CSUM(0x80)
    wqe[22] = (uint8_t)(mss >> 8);
    wqe[23] = (uint8_t)mss;

    const volatile uint8_t *hdr_src = (const volatile uint8_t *)hdr;
    wqe[28] = (uint8_t)(hdr_len >> 8);
    wqe[29] = (uint8_t)hdr_len;
    wqe[30] = hdr_src[0];
    wqe[31] = hdr_src[1];
    for (unsigned i = 0; i < ((unsigned)hdr_len - 2u); i++) wqe[32 + i] = hdr_src[2 + i];
    uint32_t dseg_off = 32u + inline_ds * 16u;

    uint64_t payload_pa = mlx5_dma_addr((const volatile void *)payload);
    wqe[dseg_off + 0] = (uint8_t)(payload_len >> 24);
    wqe[dseg_off + 1] = (uint8_t)(payload_len >> 16);
    wqe[dseg_off + 2] = (uint8_t)(payload_len >> 8);
    wqe[dseg_off + 3] = (uint8_t)payload_len;
    wqe[dseg_off + 4] = (uint8_t)(dev->mkey >> 24);
    wqe[dseg_off + 5] = (uint8_t)(dev->mkey >> 16);
    wqe[dseg_off + 6] = (uint8_t)(dev->mkey >> 8);
    wqe[dseg_off + 7] = (uint8_t)dev->mkey;
    for (unsigned b = 0; b < 8; b++) {
        wqe[dseg_off + 8 + b] = (uint8_t)(payload_pa >> (56 - 8 * b));
    }

    if (ds_cnt * 16u <= MLX5_SEND_WQE_BB) {
        volatile uint8_t *nop_wqe = wqe + MLX5_SEND_WQE_BB;
        uint32_t nop_hw_idx = (hw_wqe_idx + 1u) & 0xFFFFu;
        uint32_t nop_opmod = (nop_hw_idx << 8) | MLX5_OPCODE_NOP;
        nop_wqe[0] = (uint8_t)(nop_opmod >> 24);
        nop_wqe[1] = (uint8_t)(nop_opmod >> 16);
        nop_wqe[2] = (uint8_t)(nop_opmod >> 8);
        nop_wqe[3] = (uint8_t)nop_opmod;
        uint32_t nop_qpn_ds = (dev->sqn << 8) | 1u;
        nop_wqe[4] = (uint8_t)(nop_qpn_ds >> 24);
        nop_wqe[5] = (uint8_t)(nop_qpn_ds >> 16);
        nop_wqe[6] = (uint8_t)(nop_qpn_ds >> 8);
        nop_wqe[7] = (uint8_t)nop_qpn_ds;
    }

    mlx5_net_wqe_commit(dev, st, pc, wqe);
    return 0;
}

/*=================================================================
 * SQ 用 CQ から到着済みの完了を最大 1 件だけ非ブロッキングで刈り取る。
 * エラー CQE なら syndrome を表示して復帰(mlx5_net_try_recover())を試みる。
 *
 * 引数:
 *   pf_index / dev / st - 対象 PF、HCA、mlx5_net 状態
 * 戻り値:
 *   1=1 件処理した、0=まだ到着していない、-1=エラー完了
 * コール元:
 *   mlx5_net_sq_wait_room(), mlx5_net_send_frags()
 * ===============================================================*/
static int mlx5_net_sq_reap_one(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    uint64_t cq_buf = (uint64_t)dev->sq_cq_buf_cpu;
    volatile uint8_t *cqe = mlx5_net_cqe_if_ready(cq_buf, st->sq_cq_cc);
    if (!cqe) {
        return 0;
    }

    uint8_t op_own = cqe[MLX5_CQE_OFF_OP_OWN];
    uint8_t opcode = (uint8_t)(op_own >> 4);
    if (opcode == MLX5_CQE_OPCODE_REQ_ERR || opcode == MLX5_CQE_OPCODE_SIG_ERR) {
        uint8_t vendor_synd = cqe[MLX5_ERR_CQE_OFF_VENDOR_SYND];
        uint8_t syndrome    = cqe[MLX5_ERR_CQE_OFF_SYNDROME];

        TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_reap_one, 0),
               ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
        uart_printf("[mlx5net] SQ完了エラーCQE検出 (sqn=%u, opcode=0x%x=%s, "
                    "syndrome=0x%02x(%s), vendor_synd=0x%02x)\n",
                    dev->sqn, opcode,
                    (opcode == MLX5_CQE_OPCODE_SIG_ERR) ? "SIG_ERR" : "REQ_ERR",
                    syndrome, mlx5_cqe_syndrome_str(syndrome), vendor_synd);

        st->sq_cq_cc++;   // CQ consumer(復帰でリセットしない)
        st->sq_cc++;      // SQ占有量(この直後の try_recover で 0 リセットされうる)
        volatile uint32_t *cq_dbr_err = (volatile uint32_t *)(uintptr_t)dev->sq_cq_dbr_cpu;
        uint32_t cc24_err = st->sq_cq_cc & 0xFFFFFFu;
        *cq_dbr_err = __builtin_bswap32(cc24_err);
        dcache_clean_range((const void *)cq_dbr_err, sizeof(*cq_dbr_err));

        if (mlx5_net_try_recover(pf_index, dev, st) != 0) {
            return -1;
        }
        return 2;
    }

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_reap_one, 1),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    mlx5_net_log_hw_ts_delta(dev, mlx5_cqe_hw_ts_cycles(cqe),
                              &st->last_tx_hw_ts_cycles, &st->has_last_tx_hw_ts,
                              TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_reap_one, 2));

    st->sq_cq_cc++;   // CQ consumer(復帰でリセットしない)
    st->sq_cc++;      // SQ占有量(正常時は sq_cq_cc と歩調が揃う)

    volatile uint32_t *cq_dbr = (volatile uint32_t *)(uintptr_t)dev->sq_cq_dbr_cpu;
    uint32_t cc24 = st->sq_cq_cc & 0xFFFFFFu;
    *cq_dbr = __builtin_bswap32(cc24);
    dcache_clean_range((const void *)cq_dbr, sizeof(*cq_dbr));

    return 1;
}

/*=================================================================
 * 次の WQE をポストできるだけの空きが SQ リングにできるまで待つ。まず
 * 到着済みの完了を刈り取り、それでも空かなければタイムアウトまで繰り返す。
 *
 * 引数:
 *   pf_index / dev / st - 対象 PF、HCA、mlx5_net 状態
 * 戻り値:
 *   0=空きあり、-1=タイムアウト(復帰処理を実施済み)
 * コール元:
 *   mlx5_net_send_frags(), mlx5_net_send_frags_async(),
 *   mlx5_net_send_lso_async(), mlx5_net_tx_wait_free_slot()
 * ===============================================================*/
static int mlx5_net_sq_wait_room(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    for (;;) {
        int r = mlx5_net_sq_reap_one(pf_index, dev, st);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            break;
        }
    }

    uint64_t start = timer_now();
    while ((st->sq_pc - st->sq_cc) >= MLX5_SQ_WQE_COUNT) {
        int r = mlx5_net_sq_reap_one(pf_index, dev, st);
        if (r < 0) {
            return -1;
        }
        if (r != 0) {
            continue; // 刈り取れた(または復帰でpc/ccが0/0にリセットされ、条件は自然に満たされる) -- 直ちに再確認
        }
        if (timeout_ms(start, 1000u)) { // 1秒(eth.cのeth_tx_wait_slot()と同じ)
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_sq_wait_room, 0),
                   ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
            uart_printf("[mlx5net] TXリング枠待ちタイムアウト (sqn=%u sq_pc=%u sq_cc=%u)\n",
                        dev->sqn, st->sq_pc, st->sq_cc);
            mlx5_net_try_recover(pf_index, dev, st);
            return -1;
        }
    }
    return 0;
}

/*=================================================================
 * nic_ops_t.send_frags_async() の実体。WQE をポストしたら送信完了(CQE)を
 * 待たずに即座に返る。SQ リングに空きが無いときだけ待つ。
 *
 * 引数:
 *   priv       - mlx5_net 状態(netif_t.nic_priv)
 *   frags      - 断片配列
 *   frag_count - 断片数
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   eth_send_frags_async() から nic_ops_t 経由
 * ===============================================================*/
static int mlx5_net_send_frags_async(void *priv, const eth_frag_t *frags, unsigned frag_count)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    if (s_sq_halted[pf_index]) {
        return -1;
    }
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags_async, 0),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
    if (mlx5_net_sq_wait_room(pf_index, dev, st) != 0) {
        return -1;
    }

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags_async, 1),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    return mlx5_net_post_frame(st, frags, frag_count);
}

/*=================================================================
 * nic_ops_t.send_frags() の実体。WQE をポストし、自分がポストした WQE の
 * 完了(CQE)まで待ってから返る(ARP/ICMP など送信成否をその場で確認したい
 * 呼び出し元向け)。
 *
 * 引数:
 *   priv / frags / frag_count - send_frags_async() と同じ
 * 戻り値:
 *   0=送信完了、-1=失敗/タイムアウト
 * コール元:
 *   eth_send_frags() から nic_ops_t 経由
 * ===============================================================*/
static int mlx5_net_send_frags(void *priv, const eth_frag_t *frags, unsigned frag_count)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    if (s_sq_halted[pf_index]) {
        return -1;
    }
    if (mlx5_net_sq_wait_room(pf_index, dev, st) != 0) {
        return -1;
    }

    uint32_t target_pc = st->sq_pc; // このWQEに割り当てられるpc(post後はst->sq_pcが+1される)

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags, 0),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    if (mlx5_net_post_frame(st, frags, frag_count) != 0) {
        return -1;
    }

    // 自分がポストしたWQE(target_pc)の完了(sq_cc > target_pc)まで待つ。
    uint64_t start = timer_now();
    while ((int32_t)(st->sq_cc - (target_pc + 1u)) < 0) {
        int r = mlx5_net_sq_reap_one(pf_index, dev, st);
        if (r < 0) {
            return -1;
        }
        if (r == 2) {
            return -1;
        }
        if (r == 1) {
            continue;
        }
        if (timeout_ms(start, 1000u)) { // 1秒(eth.cのrp1_send_frags()と同じ)
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_frags, 1),
                   ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
            uart_printf("[mlx5net] TXタイムアウト (sqn=%u)\n", dev->sqn);
            mlx5_net_try_recover(pf_index, dev, st);
            return -1;
        }
    }
    return 0;
}

/*=================================================================
 * nic_ops_t.send_lso() の実体。LSO WQE をポストして完了を待たずに返る。
 *
 * 引数:
 *   priv                  - mlx5_net 状態
 *   hdr / hdr_len         - ヘッダテンプレート
 *   payload / payload_len - 分割対象のペイロード
 *   mss                   - 分割単位
 * 戻り値:
 *   0=キューイング成功、-1=失敗
 * コール元:
 *   eth_send_lso_async() から nic_ops_t 経由
 * ===============================================================*/
static int mlx5_net_send_lso_async(void *priv, const void *hdr, uint16_t hdr_len,
                                    const void *payload, uint32_t payload_len, uint16_t mss)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    if (s_sq_halted[pf_index]) {
        return -1;
    }
    if (payload_len == 0u || payload_len > dev->max_lso_bytes) {
        return -1;
    }

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_lso_async, 0),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));
    if (mlx5_net_sq_wait_room(pf_index, dev, st) != 0) {
        return -1;
    }

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_send_lso_async, 1),
           ((uint32_t)(st->sq_pc & 0xFFFFu) << 16) | (uint32_t)(st->sq_cc & 0xFFFFu));

    return mlx5_net_post_lso_frame(st, hdr, hdr_len, payload, payload_len, mss);
}

/*=================================================================
 * SQ の WQE リングと CQ の生内容を ts へダンプする(読み取り専用で HCA の
 * コマンドインターフェースには触れないので、SQ が詰まった状態でも安全)。
 *
 * 引数:
 *   pf_index - 対象 PF
 * コール元:
 *   mlx5_net_try_recover()
 * ===============================================================*/
void mlx5_net_dump_sq_debug(int pf_index)
{
    mlx5_net_state_t *st = (pf_index == 0) ? &s_state_pf0 : &s_state_pf1;
    mlx5_dev_t *dev = st->dev;
    if (!dev) {
        uart_printf("[mlx5netdbg] PF%d: 未初期化(dev==NULL)\n", pf_index);
        return;
    }

    uint64_t cq_buf   = (uint64_t)dev->sq_cq_buf_cpu;
    uint64_t wqe_ring = (uint64_t)dev->sq_wqe_cpu;

    uart_printf("[mlx5netdbg] PF%d: sqn=%u sq_cqn=%u sq_wqe_cpu=0x%08x%08x\n",
                pf_index, dev->sqn, dev->sq_cqn,
                (uint32_t)((uint64_t)dev->sq_wqe_cpu >> 32), (uint32_t)(uint64_t)dev->sq_wqe_cpu);
    uart_printf("[mlx5netdbg] PF%d: sq_pc=%u sq_cc=%u (diff=%d)\n",
                pf_index, st->sq_pc, st->sq_cc, (int)(st->sq_pc - st->sq_cc));
    uart_printf("[mlx5netdbg] PF%d: cq_buf=0x%08x%08x wqe_ring=0x%08x%08x\n",
                pf_index, (uint32_t)(cq_buf >> 32), (uint32_t)cq_buf,
                (uint32_t)(wqe_ring >> 32), (uint32_t)wqe_ring);

    for (int delta = -1; delta <= 3; delta++) {
        uint32_t idx = (uint32_t)((int64_t)(st->sq_cc & (MLX5_NET_CQ_NUM_ENTRIES - 1u)) + delta) &
                       (MLX5_NET_CQ_NUM_ENTRIES - 1u);
        volatile uint8_t *cqe = (volatile uint8_t *)(uintptr_t)(cq_buf + (uint64_t)idx * MLX5_NET_CQE_SIZE);
        dcache_invalidate_range((const void *)cqe, MLX5_NET_CQE_SIZE);
        uint8_t  op_own       = cqe[MLX5_CQE_OFF_OP_OWN];
        uint16_t wqe_counter  = (uint16_t)(((uint16_t)cqe[MLX5_CQE_OFF_WQE_COUNTER] << 8) |
                                            cqe[MLX5_CQE_OFF_WQE_COUNTER + 1]);
        uint32_t byte_cnt     = ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT] << 24) |
                                 ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 1] << 16) |
                                 ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 2] << 8) |
                                 cqe[MLX5_CQE_OFF_BYTE_CNT + 3];
        uart_printf("  CQ[%u]%s op_own=0x%02x(owner=%u opcode=0x%x) wqe_counter=%u byte_cnt=%u\n",
                    idx, (delta == 0) ? " <-sq_cc" : "",
                    op_own, (unsigned)(op_own & MLX5_CQE_OWNER_MASK), (unsigned)(op_own >> 4),
                    wqe_counter, byte_cnt);
    }

    for (uint32_t i = 0; i < MLX5_SQ_WQE_COUNT; i++) {
        volatile uint8_t *w = (volatile uint8_t *)(uintptr_t)(wqe_ring + (uint64_t)i * 2u * MLX5_SEND_WQE_BB);
        uint32_t opmod = ((uint32_t)w[0] << 24) | ((uint32_t)w[1] << 16) | ((uint32_t)w[2] << 8) | w[3];
        uint32_t qpnds = ((uint32_t)w[4] << 24) | ((uint32_t)w[5] << 16) | ((uint32_t)w[6] << 8) | w[7];
        uint32_t pc_for_slot = (opmod >> 8);
        uart_printf("  WQE[%2u] opmod_idx_opcode=0x%08x(pc=%u opcode=0x%02x) qpn_ds=0x%08x(ds_cnt=%u)\n",
                    i, opmod, pc_for_slot, (unsigned)(opmod & 0xFFu), qpnds, (unsigned)(qpnds & 0xFFu));
    }
}

/*=================================================================
 * SQ 復帰後に、CQ へ残っている完了(flush CQE を含む)を全て読み捨てて
 * sq_cq_cc をハードウェアと同期させる。
 *
 * 引数:
 *   dev / st - 対象 HCA と mlx5_net 状態
 * コール元:
 *   mlx5_net_try_recover()
 * ===============================================================*/
static void mlx5_net_drain_sq_cq(mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    uint64_t cq_buf = (uint64_t)dev->sq_cq_buf_cpu;
    volatile uint32_t *cq_dbr = (volatile uint32_t *)(uintptr_t)dev->sq_cq_dbr_cpu;
    uint64_t idle_start = timer_now();
    unsigned drained = 0;
    for (;;) {
        volatile uint8_t *cqe = mlx5_net_cqe_if_ready(cq_buf, st->sq_cq_cc);
        if (cqe) {
            st->sq_cq_cc++;   // CQ consumer のみ進める(sq_cc は直後に 0 リセットするので触らない)
            *cq_dbr = __builtin_bswap32(st->sq_cq_cc & 0xFFFFFFu);
            dcache_clean_range((const void *)cq_dbr, sizeof(*cq_dbr));
            drained++;
            idle_start = timer_now();
        } else if (timeout_ms(idle_start, 50u)) {
            // 50ms 何も来なければ flush 完了とみなす(残る WQE は SQ リセットで破棄済み)
            break;
        }
    }
    uart_printf("[mlx5net] SQ復帰: CQを%uエントリ drainし sq_cq_cc=%u へ同期\n",
                drained, st->sq_cq_cc);
}

/*=================================================================
 * SQ の TX タイムアウト/エラー CQE を検出したときの復帰処理。直近
 * MLX5_NET_SQ_RECOVER_WINDOW_MS 内に MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS 回
 * までというサーキットブレーカー付きで、mlx5_recover_sq()(ERR->RST->RDY)
 * を試み、成功したら CQ を drain してカウンタを同期させる。
 *
 * 引数:
 *   pf_index / dev / st - 対象 PF、HCA、mlx5_net 状態
 * 戻り値:
 *   1=復帰成功(送信を再試行してよい)、0=復帰せず
 * コール元:
 *   mlx5_net_send_frags(), mlx5_net_sq_reap_one(), mlx5_net_sq_wait_room()
 * ===============================================================*/
static int mlx5_net_try_recover(int pf_index, mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    if (timeout_ms(s_recover_window_start[pf_index], MLX5_NET_SQ_RECOVER_WINDOW_MS)) {
        s_recover_window_start[pf_index] = timer_now();
        s_recover_attempts[pf_index] = 0;
    }

    if (st->sq_cq_cc - s_recover_last_cq_cc[pf_index] >= MLX5_NET_SQ_RECOVER_PROGRESS_WQES) {
        s_recover_attempts[pf_index] = 0;
    }
    s_recover_last_cq_cc[pf_index] = st->sq_cq_cc;

    if (s_recover_attempts[pf_index] == 0) {
        ts_log_freeze();
    }

    if ((uint32_t)s_recover_attempts[pf_index] >= MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS) {
        uart_printf("[mlx5net] PF%d(sqn=%u): 直近%us間に%u回の自動復帰を試みたため、"
                    "これ以上は諦めます(サーキットブレーカー発動)\n",
                    pf_index, dev->sqn, MLX5_NET_SQ_RECOVER_WINDOW_MS / 1000u,
                    (unsigned)s_recover_attempts[pf_index]);
        s_sq_halted[pf_index] = 1;
        mlx5_net_dump_sq_debug(pf_index);
        mlx5_monitor_dump_saved();
        return -1;
    }

    s_recover_attempts[pf_index]++;
    ts_log(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_try_recover, 0), ((uint32_t)pf_index << 24) | (uint32_t)s_recover_attempts[pf_index]);
    uart_printf("[mlx5net] PF%d(sqn=%u): SQ自動復帰を試みます (%u/%u回目)\n",
                pf_index, dev->sqn, (unsigned)s_recover_attempts[pf_index],
                MLX5_NET_SQ_RECOVER_MAX_ATTEMPTS);
    int rc = mlx5_recover_sq(dev);
    if (rc < 0) {
        uart_printf("[mlx5net] PF%d(sqn=%u): SQ自動復帰に失敗しました\n", pf_index, dev->sqn);
        s_sq_halted[pf_index] = 1;
        mlx5_net_dump_sq_debug(pf_index);
        mlx5_monitor_dump_saved();
        return -1;
    }

    if (rc == 1) {
        s_recover_attempts[pf_index]--;
        return 0;
    }

    mlx5_net_drain_sq_cq(dev, st);
    st->sq_pc = 0;
    st->sq_cc = 0;
    uart_printf("[mlx5net] PF%d(sqn=%u): SQ自動復帰成功、送信を再試行します\n", pf_index, dev->sqn);
    return 0;
}

/*=================================================================
 * nic_ops_t.tx_wait_free_slot() の実体。ゼロコピー送信では呼び出し元の
 * バッファをそのまま DMA ソースにするため、そのスロットの前回の WQE が
 * 完了するまで待ってからスロット番号を返す。
 *
 * 引数:
 *   priv - mlx5_net 状態
 * 戻り値:
 *   次に使う SQ スロット番号
 * コール元:
 *   eth_tx_wait_free_slot() から nic_ops_t 経由
 * ===============================================================*/
static unsigned mlx5_net_tx_wait_free_slot(void *priv)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;
    int pf_index = mlx5_net_pf_index(st);

    if (!s_sq_halted[pf_index]) {
        mlx5_net_sq_wait_room(pf_index, dev, st); // 失敗時もベストエフォートでスロット番号だけ返す(直後のsend_frags_async()が改めてエラーを返す)
    }
    return (unsigned)(st->sq_pc % MLX5_SQ_WQE_COUNT);
}

/*=================================================================
 * RQ ドアベルレコードへ「投稿済み WQE 数の累計」を書き込む。
 *
 * 引数:
 *   dev / st - 対象 HCA と mlx5_net 状態
 * コール元:
 *   mlx5_net_rq_flush_rearm()
 * ===============================================================*/
static inline void mlx5_net_rq_write_dbr(mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    volatile uint8_t *rq_dbr = (volatile uint8_t *)(uintptr_t)(uint64_t)dev->rxq[0].dbr_cpu;
    rq_dbr[0] = (uint8_t)(st->rq_posted_ctr >> 24);
    rq_dbr[1] = (uint8_t)(st->rq_posted_ctr >> 16);
    rq_dbr[2] = (uint8_t)(st->rq_posted_ctr >> 8);
    rq_dbr[3] = (uint8_t)st->rq_posted_ctr;
}

/*=================================================================
 * 受信ゼロコピーのため再武装を遅延していた RQ WQE を、まとめてドアベルへ
 * 反映する。net_buf が RQ バッファを直接指すので、呼び出し元が dispatch+free
 * を終えた次の poll_recv() 冒頭で 1 フレーム遅れて再武装する。
 *
 * 引数:
 *   dev / st - 対象 HCA と mlx5_net 状態
 * コール元:
 *   mlx5_net_poll_recv()
 * ===============================================================*/
static inline void mlx5_net_rq_flush_rearm(mlx5_dev_t *dev, mlx5_net_state_t *st)
{
    if (st->rq_rearm_pending == 0u) {
        return;
    }
    st->rq_posted_ctr += st->rq_rearm_pending;
    st->rq_rearm_pending = 0u;
    mlx5_net_rq_write_dbr(dev, st);
}

/*=================================================================
 * nic_ops_t.poll_recv() の実体。前回分の RQ 再武装を済ませてから RQ 用 CQ を
 * 1 件ポーリングし、受信があれば net_buf の data を RQ バッファへ直接向けて
 * (ゼロコピー)返す。CQE の L3/L4 チェックサム検証結果も net_buf へ載せる。
 *
 * 引数:
 *   priv - mlx5_net 状態
 * 戻り値:
 *   受信フレームの net_buf。無ければ NULL
 * コール元:
 *   net_poll_all_and_dispatch() から nic_ops_t 経由
 * ===============================================================*/
static net_buf_t *mlx5_net_poll_recv(void *priv)
{
    mlx5_net_state_t *st = (mlx5_net_state_t *)priv;
    mlx5_dev_t *dev = st->dev;

    mlx5_net_rq_flush_rearm(dev, st);

    uint64_t cq_buf = (uint64_t)dev->rxq[0].cq_buf_cpu;
    volatile uint8_t *cqe = mlx5_net_cqe_if_ready(cq_buf, st->rq_cc);
    if (!cqe) {
        return NULL;
    }

    uint8_t opcode = (uint8_t)(cqe[MLX5_CQE_OFF_OP_OWN] >> 4);
    uint32_t byte_cnt = ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT] << 24) |
                        ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 1] << 16) |
                        ((uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 2] << 8) |
                         (uint32_t)cqe[MLX5_CQE_OFF_BYTE_CNT + 3];
    uint16_t wqe_idx = (uint16_t)(((uint16_t)cqe[MLX5_CQE_OFF_WQE_COUNTER] << 8) |
                                    cqe[MLX5_CQE_OFF_WQE_COUNTER + 1]);
    uint8_t hds_ip_ext = cqe[MLX5_CQE_OFF_HDS_IP_EXT];
    int csum_ok = ((hds_ip_ext & MLX5_CQE_L3_OK) != 0) && ((hds_ip_ext & MLX5_CQE_L4_OK) != 0);

    st->rq_cc++;

    uint16_t buf_idx = (uint16_t)(wqe_idx % MLX5_RQ_NUM_WQES);

    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 0), byte_cnt);

    mlx5_net_log_hw_ts_delta(dev, mlx5_cqe_hw_ts_cycles(cqe),
                              &st->last_rx_hw_ts_cycles, &st->has_last_rx_hw_ts,
                              TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 1));

    net_buf_t *out = NULL;
    if (opcode != MLX5_CQE_OP_INVALID && byte_cnt > 0u && byte_cnt <= NET_BUF_SIZE) {
        out = net_buf_alloc();
        if (out) {
            volatile uint8_t *src = (volatile uint8_t *)(uintptr_t)
                ((uint64_t)dev->rxq[0].data_cpu + (uint64_t)buf_idx * MLX5_RQ_BUF_PER_WQE
                 + MLX5_RX_HEADROOM);
            dcache_invalidate_range((const void *)src, byte_cnt);
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 2), byte_cnt);
            out->data = (uint8_t *)(uintptr_t)src;
            out->len = (uint16_t)byte_cnt;
            out->hw_csum_ok = (uint8_t)csum_ok;
            TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 3), byte_cnt);
        } else {
            uart_printf("[mlx5net] poll: net_bufプール枯渇、フレーム破棄\n");
        }
    } else if (opcode != MLX5_CQE_OP_INVALID) {
        uart_printf("[mlx5net] poll: 想定外のCQE (opcode=0x%x byte_cnt=%u wqe_idx=%u) 破棄\n",
                    opcode, byte_cnt, wqe_idx);
    }

    {
        volatile uint32_t *cq_dbr = (volatile uint32_t *)(uintptr_t)dev->rxq[0].cq_dbr_cpu;
        uint32_t cc24 = st->rq_cc & 0xFFFFFFu;
        *cq_dbr = __builtin_bswap32(cc24);
        dcache_clean_range((const void *)cq_dbr, sizeof(*cq_dbr));
    }
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 4), byte_cnt);

    st->rq_rearm_pending++;
    TS_HOT(TS_MK(TS_FILE_MLX5_NET, TS_FUNC_mlx5_net_poll_recv, 5), byte_cnt);

    return out;
}

static const nic_ops_t s_mlx5_net_ops = {
    .send_frags        = mlx5_net_send_frags,
    .send_frags_async  = mlx5_net_send_frags_async,
    .send_lso          = mlx5_net_send_lso_async, // 2026-08-10、LSO対応(RP1側はNULLのまま)
    .tx_wait_free_slot = mlx5_net_tx_wait_free_slot,
    .poll_recv         = mlx5_net_poll_recv,
};

/*=================================================================
 * bring-up 済みの HCA を 1 つのネットワークインターフェースとして構成する
 * (名前・IP・MAC・nic_ops・MSS 上限・RX リング段数・HW オフロード能力)。
 * MSS 上限はポートの実 MTU(PMTU で設定できた値)から逆算する。
 *
 * 引数:
 *   ctx        - 構成する netif
 *   st         - このインターフェース用の mlx5_net 状態
 *   dev        - bring-up 済み HCA
 *   name       - インターフェース名("mlx5-pf0" 等)
 *   ip         - 自機 IPv4
 *   mac_last   - MAC の末尾バイト(前半は固定のローカル管理アドレス)
 * コール元:
 *   mlx5_net_register_dual()
 * ===============================================================*/
static void mlx5_netif_setup(netif_t *ctx, mlx5_net_state_t *st, mlx5_dev_t *dev,
                                const char *name, uint32_t ip, uint8_t mac_low_octet)
{
    ctx->name = name;
    ctx->mac[0] = 0x02; ctx->mac[1] = 0x00; ctx->mac[2] = 0x00;
    ctx->mac[3] = 0x00; ctx->mac[4] = 0x10; ctx->mac[5] = mac_low_octet;
    ctx->ip = ip;
    /* 2 ポートは DAC 直結の同一リンクなので、ゲートウェイは未設定(=全ての
     * 宛先を同一リンク上として扱う従来の挙動)。netmask だけ入れておけば、
     * `route` でゲートウェイを設定した瞬間からサブネット判定が効く。 */
    ctx->netmask = ip_from_octets(255, 255, 255, 0);
    ctx->gateway = 0u;
    for (unsigned i = 0; i < 16; i++) ctx->gateway6[i] = 0u;
    ctx->gateway6_set = 0u;
    ctx->nic = &s_mlx5_net_ops;
    ctx->nic_priv = st;
    {
        const uint32_t eth_vlan_fcs_ip_tcp_hdr = 14u + 4u + 4u + 20u + 20u; // = 62
        const uint32_t tcp_mss_local_max = 10182u; // tcp.cのTCP_MSS_LOCALと同値(非公開のため複製)
        uint32_t mss = (dev->port_mtu > eth_vlan_fcs_ip_tcp_hdr) ? (dev->port_mtu - eth_vlan_fcs_ip_tcp_hdr) : 0u;
        if (mss > tcp_mss_local_max) {
            mss = tcp_mss_local_max;
        }
        mss = 9216;
        ctx->mss_cap = (uint16_t)mss;
        /* IP 断片化の基準になる L3 MTU。mss_cap(TCP ペイロード)+ TCP ヘッダ
         * + IP ヘッダ。フルサイズの TCP セグメントが実際に通っている値なので、
         * この total_length までは確実に送れる。 */
        ctx->mtu = (uint16_t)(mss + 20u + 20u);
    }
    ctx->rx_ring_size = (uint16_t)MLX5_RQ_NUM_WQES;
    ctx->hw_csum_offload = 1;
    ctx->tx_zerocopy_2frag = 1;
    ctx->hw_lso_max_bytes = dev->max_lso_bytes;
    for (unsigned i = 0; i < ARP_CACHE_SIZE; i++) ctx->arp_cache[i].valid = 0;
    for (unsigned i = 0; i < NDP_CACHE_SIZE; i++) ctx->ndp_cache[i].valid = 0;

    st->dev = dev;
    st->rq_cc = 0;
    st->rq_posted_ctr = MLX5_RQ_NUM_WQES; // mlx5_create_rq()が既にこの値でドアベルへ書き込み済み
    st->rq_rearm_pending = 0u;             // 受信ゼロコピーの遅延再武装カウンタ(net init mlx5/再ブリングアップでリセット)
    st->sq_pc = 0;
    st->sq_cc = 0;
    st->sq_cq_cc = 0;   // CQ consumer(setup/再ブリングアップ時は CQ も新規なので 0 起点)
    {
        int pfi = mlx5_net_pf_index(st);
        s_sq_halted[pfi] = 0;
        s_recover_attempts[pfi] = 0;
        s_recover_window_start[pfi] = timer_now();
    }
}

/*=================================================================
 * bring-up 済みの 2 つの PF を "mlx5-pf0"/"mlx5-pf1" として netif 登録し、
 * PF0 をアクティブにする。以後 arp/ip/tcp はこの 2 本を使う。
 *
 * 引数:
 *   dev0, dev1 - bring-up 済みの PF0/PF1
 * 戻り値:
 *   0=成功
 * コール元:
 *   run_shell()
 * ===============================================================*/
int mlx5_net_register_dual(mlx5_dev_t *dev0, mlx5_dev_t *dev1)
{
    mlx5_netif_setup(&s_ctx_pf0, &s_state_pf0, dev0, "mlx5-pf0",
                        ip_from_octets(192, 168, 101, 10), 0x10);
    mlx5_netif_setup(&s_ctx_pf1, &s_state_pf1, dev1, "mlx5-pf1",
                        ip_from_octets(192, 168, 101, 11), 0x11);
    netif_register(&s_ctx_pf0);
    netif_register(&s_ctx_pf1);
    netif_activate(&s_ctx_pf0);
    mlx5_monitor_set_devs(dev0, dev1);
    uart_printf("[mlx5net] dual registered: pf0=192.168.101.10 pf1=192.168.101.11 (active=pf0)\n");
    return 0;
}
