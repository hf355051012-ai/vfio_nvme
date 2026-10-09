#include "rdma_short.h"
#include "rdma_cm.h"
#include "mlx5_qp.h"
#include "mmio.h"
#include "net.h"
#include "timer.h"
#include "uart.h"
#include "job.h"

#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include "platform.h"

/* RC QP の資源スロット(mlx5_dev_t.rcqp[])。NVMe-oF は admin=0、IO=1.. を使うので
 * 一番後ろを借りる。**NVMe-oF RDMA と同じ PF で同時に使わないこと**(GSI は
 * 1 ポートに 1 本しか作れないので、接続そのものが失敗する)。 */
#define RS_QP_INDEX   (MLX5_NUM_RCQP - 1u)
#define RS_SQ_WQEBB   512u     /* log_sq_size=9(mlx5_qp_create_rc())*/
#define RS_CQ_ENTRIES 1024u    /* MLX5_QP_CQ_NUM_ENTRIES */
#define RS_SLOTS      128u     /* ローカルの受け皿(read の着地点 / atomic の元値)*/
#define RS_QD_MAX     128u
#define RS_LAT_MAX    200000u
#define RS_FIFO       256u     /* signaled な WQE の待ち行列(2 の冪)*/
#define RS_SPIN_LIMIT_MS 2000u
#define RS_READ_MAX   65536u   /* read の上限(64B を超える分は big バッファへ着地させる)*/
/* BF レジスタ 1 面の大きさ。UAR の 0x800 から 2 面(log_bf_reg_size=9 の半分ずつ)。
 * rdma-core の mlx5 も bf->buf_size = bf_reg_size / 2 で交互に使う。 */
#define RS_BF_BUF_SIZE 256u

/* MCAS / MFAA は拡張(masked)atomic で組む 1〜32B の CAS / FAA。 */
typedef enum { RS_OP_WRITE = 0, RS_OP_READ, RS_OP_CAS, RS_OP_FAA, RS_OP_NOP, RS_OP_MCAS, RS_OP_MFAA } rs_op_t;

static const char *const s_op_name[] = { "write", "read", "cas", "faa", "nop", "mcas", "mfaa" };
/* bw / lat で拡張 atomic を当てる場所(相手の hash の対象外。32B 境界 x 16 か所)。 */
#define RS_XAREA_OFF  6144u

typedef struct {
    rdma_cm_ctx_t cm;
    mlx5_dev_t *dev;
    int connected;
    uint64_t raddr;
    uint32_t rkey;
    uint32_t rlen;
    int res_be;      /* atomic の元値がローカルへ BE で書かれるなら 1 */
    int res_known;

    /* ---- ホットパスが触るものはここから(接続時に一度だけ求める) ---- */
    volatile uint8_t  *sq;       /* SQ 領域(WQE バッファ + 4096)*/
    volatile uint32_t *sq_dbr;   /* doorbell record の送信カウンタ(dbr + 4)*/
    volatile uint8_t  *cq;
    volatile uint32_t *cq_dbr;
    uint64_t db_addr;            /* UAR ページ + MLX5_BF_OFFSET */
    uint32_t qpn8;               /* qpn << 8 */
    uint32_t lkey;
    uint32_t sq_pc;              /* 投稿済み WQEBB 数 */
    uint32_t cq_cc;
    uint64_t lbuf_iova;
    uint64_t wbuf_iova;
    uint64_t big_iova;           /* 64B を超える read の着地点(RS_READ_MAX、全操作で共有)*/
    volatile uint8_t *bf_page;   /* この QP の UAR ページを WC でマップしたもの(BlueFlame 用)*/
    const volatile uint8_t *last_scat; /* 直前の CQE がデータを抱えていればその CQE */
    uint8_t cs_req;              /* この接続の qpc.cs_req(0 / 0x11)*/
    uint32_t bf_off;             /* 2 面ある BF レジスタのどちらを使うか(0 / RS_BF_BUF_SIZE)*/
} rs_conn_t;

/* **接続はポートごとに 1 本**(添字 = PF 番号)。2 ポートを同時に使うときは
 * 両方を張り、bw2 が交互に投稿する。lat / verify などの単独の操作は
 * s_cur(`rshort use pf0|pf1`、または最後に張ったほう)に対して行う。
 * ホットパスの関数は s_rs を通して見るので、bw2 は s_cur を差し替えるだけで
 * 同じ組み立て・ドアベル・回収の関数をそのまま使う。 */
static rs_conn_t  s_rsv[2];
static rs_conn_t *s_cur = &s_rsv[1];
#define s_rs (*s_cur)

/* 受け皿(read の着地点 / atomic の元値)と、inline を使わない write の送り元。
 * プロセスの rw 領域は起動時に VFIO へまるごとマップされているので .bss でよい。 */
static uint8_t s_lbuf[RS_SLOTS * 64u] __attribute__((aligned(64)));
static uint8_t s_wbuf[RS_SLOTS * 64u] __attribute__((aligned(64)));

/* 切り替え(交互 A/B 用の恒久的な陰性対照)。 */
/* write をデータごと WQE へ埋め込むか。0=しない / 1=常に / 2=auto(qd=1 は 32B まで、
 * bw は 1 WQEBB に収まる 28B まで)。 */
static int      s_opt_inline = 2;
#define RS_INLINE_1BB_MAX 28u   /* ctrl16 + raddr16 + inline ヘッダ 4 + 28 = 64 */
static int      s_opt_mfence = 0;   /* 1=既存経路と同じ mfence。0=コンパイラ障壁のみ(x86 TSO)*/
static uint32_t s_opt_sig    = 0;   /* bw の signal 間隔(0=自動)*/
static int      s_opt_spread = 1;   /* bw の宛先を 64 か所へ散らす(0=同じ番地)*/
static int      s_opt_bf     = 1;   /* BlueFlame(WC マップが取れたときだけ効く)*/
static int      s_opt_scqe   = 1;   /* read / atomic の応答を CQE へ(次の connect から)*/

static uint64_t s_tsc_khz;
static uint64_t s_ring_cyc, s_ring_n;   /* rs_one() のドアベル所要(lat の表示用)*/
static uint64_t s_scat_n;               /* rs_one() で CQE からデータを受け取った回数 */
static uint32_t s_lat[RS_LAT_MAX];

/* ------------------------------------------------------------------ */

static uint64_t rs_tsc_khz(void) {
    if (s_tsc_khz == 0) {
        uint64_t t0 = timer_now();
        uint64_t c0 = __rdtsc();
        while (!timeout_ms(t0, 50u)) {
        }
        uint64_t t1 = timer_now();
        uint64_t c1 = __rdtsc();
        s_tsc_khz = (c1 - c0) * 1000000ull / (t1 - t0);
    }
    return s_tsc_khz;
}

static inline uint64_t rs_cyc2ns(uint64_t cyc) {
    return cyc * 1000000ull / s_tsc_khz;
}

static inline void rs_barrier(void) {
    if (s_opt_mfence) {
        dma_wmb();
    } else {
        __asm__ volatile("" ::: "memory");
    }
}

static inline volatile uint64_t *rs_bb(uint32_t pc) {
    return (volatile uint64_t *)(s_rs.sq + (uint64_t)(pc & (RS_SQ_WQEBB - 1u)) * MLX5_SEND_WQE_BB);
}

/* WQE の 8 バイト単位の語 k(0 始まり)へ書く。64 バイトを超えたら次の WQEBB
 * (リングの先頭へ折り返すこともある)へ回す。 */
static inline void rs_wqe_put(uint32_t pc, unsigned k, uint64_t v) {
    rs_bb(pc + (k >> 3))[k & 7u] = v;
}

/* 拡張 atomic: メモリのバイト位置 m(S バイトの塊の中)と WQE 上の位置の対応。
 * 詳しくは rs_mcas() の前の説明。 */
static inline uint32_t rs_m2w(uint32_t S, uint32_t m) {
    const uint32_t W = (S == 4u) ? 4u : 8u;
    return (m / W) * W + (W - 1u - (m % W));
}

/* [roff, roff+len) を含む最小の拡張 atomic の大きさ(4/8/16/32)。32B 境界をまたぐなら 0。 */
static uint32_t rs_masked_size(uint64_t roff, uint32_t len) {
    static const uint32_t sizes[] = { 4, 8, 16, 32 };
    for (unsigned i = 0; i < 4u; i++) {
        const uint32_t S = sizes[i];
        if (len <= S && (roff / S) == ((roff + len - 1u) / S)) return S;
    }
    return 0;
}

/*=================================================================
 * 1 個の WQE を SQ へ書く(ドアベルはまだ鳴らさない)。
 *
 *   write(inline): ctrl(16) + raddr(16) + inline(4 + len) -- 28B までは 1 WQEBB
 *   write/read    : ctrl(16) + raddr(16) + data_seg(16)   -- 48B = 1 WQEBB
 *   cas/faa       : ctrl(16) + raddr(16) + atomic(16) + data_seg(16) = 64B
 *
 * **小さい write は WQE へ埋め込む。** ポインタで渡すと NIC が WQE の取得と
 * データの取得で PCIe の DMA 読みを 2 回する(SEND の inline 化と同じ理屈)。
 *
 * 引数:
 *   op        - 種別
 *   len       - バイト数(atomic は 8 固定)
 *   raddr     - 相手の仮想アドレス
 *   src       - write のデータ(inline のとき WQE へ写す)
 *   laddr     - ローカルの IOVA(read の着地点 / atomic の元値 / 非 inline write の送り元)
 *   swap_add  - CAS の新値 / FAA の加数
 *   cmp       - CAS の比較値
 *   signaled  - 1 なら完了 CQE を要求
 *   inl       - write のデータを WQE へ埋め込む(write 以外では無視)
 *   out_bbs   - 使った WQEBB 数
 * 戻り値:
 *   ドアベルへ書く 8 バイト(ctrl の先頭)
 * コール元:
 *   rs_one(), rs_bw(), rs_bf_probe()
 * ===============================================================*/
static inline uint64_t rs_build(rs_op_t op, uint32_t len, uint64_t raddr, const uint8_t *src,
                                uint64_t laddr, uint64_t swap_add, uint64_t cmp, int signaled,
                                int inl, uint32_t *out_bbs) {
    const uint32_t pc = s_rs.sq_pc;
    uint32_t opcode;
    uint32_t ds;
    switch (op) {
    case RS_OP_WRITE:
        opcode = MLX5_OPCODE_RDMA_WRITE;
        ds = inl ? (2u + (4u + len + 15u) / 16u) : 3u;
        break;
    case RS_OP_READ: opcode = MLX5_OPCODE_RDMA_READ; ds = 3u; break;
    case RS_OP_CAS:  opcode = MLX5_OPCODE_ATOMIC_CS; ds = 4u; break;
    case RS_OP_FAA:  opcode = MLX5_OPCODE_ATOMIC_FA; ds = 4u; break;
    default:         opcode = MLX5_OPCODE_NOP;       ds = 1u; break;
    }
    if (op != RS_OP_WRITE) inl = 0;
    const uint32_t bbs = (ds + 3u) / 4u;

    const uint64_t w0 = (uint64_t)__builtin_bswap32(((pc & 0xFFFFu) << 8) | opcode) |
                        ((uint64_t)__builtin_bswap32(s_rs.qpn8 | ds) << 32);
    rs_wqe_put(pc, 0, w0);
    rs_wqe_put(pc, 1, signaled ? ((uint64_t)MLX5_WQE_CTRL_CQ_UPDATE << 24) : 0u);
    if (op == RS_OP_NOP) {
        *out_bbs = bbs;
        return w0;
    }
    rs_wqe_put(pc, 2, __builtin_bswap64(raddr));
    rs_wqe_put(pc, 3, (uint64_t)__builtin_bswap32(s_rs.rkey));

    if (inl) {
        /* inline_seg: byte_count | 0x80000000(BE)の直後にデータ。16B 単位まで詰める。 */
        uint64_t tmp[5] = {0, 0, 0, 0, 0};
        uint8_t *t = (uint8_t *)tmp;
        uint32_t hdr = __builtin_bswap32(0x80000000u | len);
        memcpy(t, &hdr, 4);
        memcpy(t + 4, src, len);
        const unsigned nw = ((4u + len + 15u) / 16u) * 2u;
        for (unsigned k = 0; k < nw; k++) rs_wqe_put(pc, 4u + k, tmp[k]);
    } else if (op == RS_OP_WRITE || op == RS_OP_READ) {
        rs_wqe_put(pc, 4, (uint64_t)__builtin_bswap32(len) | ((uint64_t)__builtin_bswap32(s_rs.lkey) << 32));
        rs_wqe_put(pc, 5, __builtin_bswap64(laddr));
    } else {
        rs_wqe_put(pc, 4, __builtin_bswap64(swap_add)); // atomic_seg.swap_add(BE)
        rs_wqe_put(pc, 5, __builtin_bswap64(cmp));      // atomic_seg.compare(BE)
        rs_wqe_put(pc, 6, (uint64_t)__builtin_bswap32(8u) | ((uint64_t)__builtin_bswap32(s_rs.lkey) << 32));
        rs_wqe_put(pc, 7, __builtin_bswap64(laddr));
    }
    *out_bbs = bbs;
    return w0;
}

/* doorbell record を進めてからドアベルを鳴らす。x86 は TSO なので WB 領域
 * (WQE / doorbell record)への書き込みが UC の MMIO より後ろへ回ることはない
 * (rdma-core の udma_to_device_barrier() も x86 ではコンパイラ障壁だけ)。 */
static inline void rs_ring(uint64_t w0, uint32_t first_pc, uint32_t nbb) {
    rs_barrier();
    *s_rs.sq_dbr = __builtin_bswap32(s_rs.sq_pc);
    rs_barrier();
    if (s_rs.bf_page != 0 && s_opt_bf) {
        /* **BlueFlame。** WC でマップした UAR の BF レジスタへ WQE 本体を書く。
         * NIC はドアベルと一緒に WQE を受け取るので、ホストメモリから WQE を
         * DMA で読みに来ない(PCIe の読み 1 往復ぶん縮む)。
         * 1 個だけ投稿したときに限る(rdma-core の mlx5 も nreq == 1 のときだけ)。
         * 64 バイトを 16B x 4 で書き、WC バッファで 1 個の TLP にまとめさせる。
         * 書いた後の sfence で WC バッファを吐き出させる(rdma-core の
         * mmio_flush_writes() と同じ)。BF レジスタは 2 面あり、交互に使う。 */
        volatile uint8_t *reg = s_rs.bf_page + MLX5_BF_OFFSET + s_rs.bf_off;
        if (nbb != 0u) {
            for (uint32_t b = 0; b < nbb; b++) {
                const __m128i *src = (const __m128i *)(uintptr_t)rs_bb(first_pc + b);
                volatile __m128i *dst = (volatile __m128i *)(uintptr_t)(reg + b * 64u);
                dst[0] = src[0];
                dst[1] = src[1];
                dst[2] = src[2];
                dst[3] = src[3];
            }
        } else {
            *(volatile uint64_t *)(uintptr_t)reg = w0;
        }
        _mm_sfence();
        s_rs.bf_off ^= RS_BF_BUF_SIZE;
        return;
    }
    mmio_write64(s_rs.db_addr, w0);
    /* **UAR ページを WC にしてあるなら、bf off でも sfence が要る。** 8B の
     * ドアベルが WC バッファに留まったまま NIC へ届かず、割り込み等で吐き出される
     * まで 1 回ごとに長く止まる(実機で踏んだ)。 */
    if (s_rs.bf_page != 0) _mm_sfence();
}

/* CQE を 1 件取り出す。1=成功 / 0=まだ / -1=エラー完了(synd に syndrome)。 */
static inline int rs_poll(uint16_t *wqe_cnt, uint8_t *synd, uint8_t *vsynd) {
    volatile uint8_t *cqe = s_rs.cq + (uint64_t)(s_rs.cq_cc & (RS_CQ_ENTRIES - 1u)) * 64u;
    const uint8_t op_own = cqe[63];
    if ((op_own & 1u) != ((s_rs.cq_cc >> 10) & 1u) || (op_own >> 4) == 0xFu) {
        return 0;
    }
    __asm__ volatile("" ::: "memory");
    *wqe_cnt = (uint16_t)(((uint16_t)cqe[60] << 8) | cqe[61]);
    const uint8_t opc = (uint8_t)(op_own >> 4);
    /* op_own bit2 = 応答データ(32B まで)が CQE の先頭に入っている(cs_req=0x11)。
     * rdma-core の MLX5_INLINE_SCATTER_32 と同じ判定。 */
    s_rs.last_scat = (op_own & 0x04u) ? cqe : 0;
    s_rs.cq_cc++;
    *s_rs.cq_dbr = __builtin_bswap32(s_rs.cq_cc & 0xFFFFFFu);
    if (opc == 0xDu || opc == 0xEu || opc == 0xCu) {
        *synd = cqe[55];
        *vsynd = cqe[54];
        return -1;
    }
    return 1;
}

static void rs_sync_back(void) {
    s_rs.cm.rc_qp.sq_pc = s_rs.sq_pc;
    s_rs.cm.rc_qp.cq_cc = s_rs.cq_cc;
}

static void rs_report_cqe_err(const char *what, uint8_t synd, uint8_t vsynd) {
    const char *why = "";
    switch (synd) {
    case 0x01: why = "LOCAL_LENGTH"; break;
    case 0x02: why = "LOCAL_QP_OP"; break;
    case 0x04: why = "LOCAL_PROT"; break;
    case 0x05: why = "WR_FLUSH(先行するエラーで QP が error 状態)"; break;
    case 0x10: why = "BAD_RESP"; break;
    case 0x11: why = "LOCAL_ACCESS"; break;
    case 0x12: why = "REMOTE_INVAL_REQ(同時 read/atomic 数の超過 / 非対応の操作)"; break;
    case 0x13: why = "REMOTE_ACCESS(rkey / 範囲 / アクセス権)"; break;
    case 0x14: why = "REMOTE_OP"; break;
    case 0x15: why = "TRANSPORT_RETRY_EXC(相手に届かない)"; break;
    case 0x16: why = "RNR_RETRY_EXC"; break;
    default: break;
    }
    uart_printf("rshort: %s: エラー完了 syndrome=0x%02x vendor=0x%02x %s -- QP は error 状態。"
                "rshort disconnect して繋ぎ直すこと\n", what, synd, vsynd, why);
    s_rs.connected = 0;
}

/* 1 個投稿して完了まで待つ(qd=1)。戻り値: 経過サイクル、失敗なら 0。 */
static uint64_t rs_one(rs_op_t op, uint32_t len, uint64_t roff, const uint8_t *src,
                       unsigned slot, uint64_t swap_add, uint64_t cmp) {
    uint32_t bbs;
    const uint64_t laddr = (op == RS_OP_WRITE) ? (s_rs.wbuf_iova + slot * 64u)
                         : (len > 64u) ? s_rs.big_iova : (s_rs.lbuf_iova + slot * 64u);
    /* qd=1 は 32B まで inline(2 WQEBB でもデータの DMA 読みを省くほうが速い)。 */
    const int inl = (op == RS_OP_WRITE) && (s_opt_inline != 0);
    if (op == RS_OP_WRITE && !inl) memcpy(&s_wbuf[slot * 64u], src, len);
    const uint64_t t0 = __rdtsc();
    const uint32_t first_pc = s_rs.sq_pc;
    const uint64_t w0 = rs_build(op, len, s_rs.raddr + roff, src, laddr, swap_add, cmp, 1, inl, &bbs);
    s_rs.sq_pc += bbs;
    const uint64_t tr0 = __rdtsc();
    rs_ring(w0, first_pc, bbs);
    s_ring_cyc += __rdtsc() - tr0; // ドアベル(BF なら WQE 本体の MMIO 書き込み)にかかった CPU 時間
    s_ring_n++;
    uint16_t cnt;
    uint8_t synd = 0, vsynd = 0;
    int rc;
    uint32_t spins = 0;
    while ((rc = rs_poll(&cnt, &synd, &vsynd)) == 0) {
        if ((++spins & 0xFFFFu) == 0 &&
            rs_cyc2ns(__rdtsc() - t0) > (uint64_t)RS_SPIN_LIMIT_MS * 1000000ull) {
            uart_printf("rshort: %s: %ums 待っても完了しない\n", s_op_name[op], RS_SPIN_LIMIT_MS);
            s_rs.connected = 0;
            return 0;
        }
    }
    if (rc > 0 && s_rs.last_scat != 0) {
        /* scatter to CQE: データはバッファへは書かれていない。CQE から写す
         * (受け取って使えるまでを測るので、写す時間も計測に含める)。 */
        const uint32_t n = (op == RS_OP_READ) ? len : 8u;
        for (uint32_t j = 0; j < n; j++) s_lbuf[slot * 64u + j] = s_rs.last_scat[j];
        s_scat_n++;
    }
    const uint64_t t1 = __rdtsc();
    if (rc < 0) {
        rs_report_cqe_err(s_op_name[op], synd, vsynd);
        return 0;
    }
    return (t1 - t0) ? (t1 - t0) : 1u;
}

/* atomic の元値(受け皿 slot に書かれた 8 バイト)を数値として読む。 */
static uint64_t rs_atomic_result(unsigned slot) {
    uint64_t v;
    memcpy(&v, &s_lbuf[slot * 64u], 8);
    return s_rs.res_be ? __builtin_bswap64(v) : v;
}

/* ------------------------------------------------------------------ */

static int rs_parse_ip(const char *s, uint32_t *out) {
    unsigned v[4] = {0, 0, 0, 0};
    for (unsigned i = 0; i < 4u; i++) {
        if (*s < '0' || *s > '9') return -1;
        while (*s >= '0' && *s <= '9') v[i] = v[i] * 10u + (unsigned)(*s++ - '0');
        if (i < 3u && *s++ != '.') return -1;
    }
    *out = ip_from_octets((uint8_t)v[0], (uint8_t)v[1], (uint8_t)v[2], (uint8_t)v[3]);
    return 0;
}

static int rs_parse_mac(const char *s, uint8_t mac[6]) {
    for (unsigned i = 0; i < 6u; i++) {
        unsigned v = 0;
        for (unsigned k = 0; k < 2u; k++) {
            char ch = *s++;
            unsigned d;
            if (ch >= '0' && ch <= '9') d = (unsigned)(ch - '0');
            else if (ch >= 'a' && ch <= 'f') d = (unsigned)(ch - 'a') + 10u;
            else if (ch >= 'A' && ch <= 'F') d = (unsigned)(ch - 'A') + 10u;
            else return -1;
            v = v * 16u + d;
        }
        mac[i] = (uint8_t)v;
        if (i < 5u && *s != ':' && *s != '-') return -1;
        s++;
    }
    return 0;
}

static uint32_t rs_rd32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void rs_release_qps(void) {
    if (s_rs.cm.rc_qp.in_use) mlx5_qp_destroy(s_rs.cm.dev, &s_rs.cm.rc_qp);
    if (s_rs.cm.gsi_qp && s_rs.cm.gsi_qp->in_use) mlx5_qp_destroy(s_rs.cm.dev, s_rs.cm.gsi_qp);
}

/*=================================================================
 * 相手(rdma_short_peer)へ CM で接続し、REP の private data から MR の
 * アドレス・rkey・長さを受け取る。ホットパスが使うポインタもここで求める。
 * ===============================================================*/
static int rs_connect(mlx5_dev_t *dev, int pf, uint32_t peer_ip, const uint8_t peer_mac[6],
                      uint16_t port) {
    static const uint8_t mac0_fb[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x10};
    static const uint8_t mac1_fb[6] = {0x02, 0x00, 0x00, 0x00, 0x10, 0x11};
    const uint32_t ip_fb = ip_from_octets(192, 168, 101, (uint8_t)(pf ? 11 : 10));

    if (job_count_by_ctx(&s_rs.cm) != 0) {
        job_cancel_by_ctx(&s_rs.cm);
        uint64_t t = timer_now();
        while (job_count_by_ctx(&s_rs.cm) != 0 && !timeout_ms(t, 2000u)) job_scheduler_tick();
    }
    rdma_cm_fill_addr(&s_rs.cm, dev, pf ? "mlx5-pf1" : "mlx5-pf0", "__override__", ip_fb, peer_ip,
                      pf ? mac1_fb : mac0_fb, peer_mac);
    s_rs.dev = dev;
    s_rs.connected = 0;
    s_rs.res_known = 0;
    s_rs.cm.service_port = port;
    s_rs.cm.is_active = 1;
    s_rs.cm.skip_ping = 1;
    s_rs.cm.reuse_gsi = 0;
    s_rs.cm.rc_qp_index = (uint8_t)RS_QP_INDEX;
    s_rs.cs_req = s_opt_scqe ? 0x11u : 0u;
    s_rs.cm.rc_cs_req = s_rs.cs_req;

    job_t *job = job_spawn(rdma_cm_job_step, &s_rs.cm, "rshort-cm");
    if (job == NULL) {
        uart_printf("rshort: ジョブ表が満杯\n");
        return -1;
    }
    job->state = RDMA_CM_ST_ACTIVE_SETUP;
    job_pin_to_core(job, 0u); // core0(このシェル)で回す
    uint64_t t = timer_now();
    while (job_count_by_ctx(&s_rs.cm) != 0) {
        job_scheduler_tick();
        if (timeout_ms(t, 15000u)) {
            uart_printf("rshort: CM が 15 秒で終わらない\n");
            job_cancel_by_ctx(&s_rs.cm);
            break;
        }
    }
    if (!s_rs.cm.established || s_rs.cm.failed) {
        uart_printf("rshort: 接続失敗(rej_reason=%u)\n", (unsigned)s_rs.cm.rej_reason);
        rs_release_qps();
        return -1;
    }

    const uint8_t *pd = s_rs.cm.rep_priv;
    if (rs_rd32be(&pd[0]) != RSHORT_PRIV_MAGIC) {
        uart_printf("rshort: REP の private data が rdma_short_peer のものではない "
                    "(magic=0x%08x)\n", rs_rd32be(&pd[0]));
        rdma_cm_disconnect(&s_rs.cm, 1000u);
        rs_release_qps();
        return -1;
    }
    s_rs.raddr = ((uint64_t)rs_rd32be(&pd[8]) << 32) | rs_rd32be(&pd[12]);
    s_rs.rkey = rs_rd32be(&pd[16]);
    s_rs.rlen = rs_rd32be(&pd[20]);
    if (s_rs.rlen < RSHORT_MR_MIN_BYTES) {
        uart_printf("rshort: 相手の MR が小さすぎる(%u < %u)\n", s_rs.rlen, RSHORT_MR_MIN_BYTES);
        rdma_cm_disconnect(&s_rs.cm, 1000u);
        rs_release_qps();
        return -1;
    }

    mlx5_qp_t *qp = &s_rs.cm.rc_qp;
    s_rs.sq = (volatile uint8_t *)(uintptr_t)(mlx5_qp_wqe_addr(dev, qp) + 4096u);
    s_rs.sq_dbr = (volatile uint32_t *)(uintptr_t)(mlx5_qp_dbr_addr(dev, qp) + 4u);
    s_rs.cq = (volatile uint8_t *)(uintptr_t)mlx5_qp_cq_buf_addr(dev, qp);
    s_rs.cq_dbr = (volatile uint32_t *)(uintptr_t)mlx5_qp_cq_dbr_addr(dev, qp);
    s_rs.db_addr = dev->bar0_base + (uint64_t)qp->uarn * 4096u + MLX5_BF_OFFSET;
    s_rs.qpn8 = qp->qpn << 8;
    s_rs.lkey = qp->mkey;
    s_rs.sq_pc = qp->sq_pc;
    s_rs.cq_cc = qp->cq_cc;
    s_rs.lbuf_iova = mlx5_dma_addr(s_lbuf);
    s_rs.wbuf_iova = mlx5_dma_addr(s_wbuf);
    if (s_rs.big_iova == 0) {
        /* 長い read の着地点。DMA プールから取るので IOVA が連続している。 */
        dma_region_t big = dma_alloc(RS_READ_MAX, 4096u, DMA_COHERENT);
        if (big.cpu != 0) s_rs.big_iova = mlx5_dma_addr(big.cpu);
    }
    s_rs.bf_off = 0;
    s_rs.bf_page = (volatile uint8_t *)hal_bar0_map_wc(dev, (uint64_t)qp->uarn * 4096u, 4096u);
    if (s_rs.bf_page == 0) {
        uart_printf("rshort: UAR を WC でマップできない -- BlueFlame 無しで動かす\n");
    }
    s_rs.connected = 1;
    rs_tsc_khz();
    uart_printf("rshort: 接続しました qpn=%u -> peer qpn=%u  MR addr=0x%llx rkey=0x%08x len=%u\n",
                qp->qpn, s_rs.cm.peer_rc_qpn, (unsigned long long)s_rs.raddr, s_rs.rkey, s_rs.rlen);
    return 0;
}

static void rs_disconnect(void) {
    if (s_rs.cm.rc_qp.in_use) {
        rs_sync_back();
        rdma_cm_disconnect(&s_rs.cm, 2000u);
    }
    rs_release_qps();
    if (s_rs.bf_page) {
        hal_bar0_unmap_wc(s_rs.dev, (void *)(uintptr_t)s_rs.bf_page, 4096u);
        s_rs.bf_page = 0;
    }
    s_rs.connected = 0;
    uart_printf("rshort: 切断しました\n");
}

/* ------------------------------------------------------------------ */

static int rs_cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* 相手の atomic 語(8B 境界)/ データ領域(64B 境界)の位置。 */
static inline uint64_t rs_target_off(rs_op_t op, uint32_t i) {
    const uint32_t k = s_opt_spread ? (i & 63u) : 0u;
    if (op == RS_OP_CAS || op == RS_OP_FAA) return RSHORT_ATOMIC_OFF + (uint64_t)k * 8u;
    return (uint64_t)k * 64u;
}

static uint64_t rs_build_masked(int is_cas, uint32_t S, uint64_t raddr, uint64_t laddr,
                                const uint8_t *a, const uint8_t *b, const uint8_t *c,
                                const uint8_t *d, int signaled, uint32_t *out_bbs);
static int rs_lat_masked(rs_op_t op, uint32_t len, uint32_t iters, int quiet, uint32_t *out_p50,
                         uint32_t *out_avg);

/*=================================================================
 * qd=1 のレイテンシ。投稿(WQE を書く)からその CQE を拾うまでを rdtsc で
 * 1 回ずつ測る。CAS は毎回成功するように比較値を前回の値で追いかける。
 * ===============================================================*/
static int rs_lat(rs_op_t op, uint32_t len, uint32_t iters, int quiet, uint32_t *out_p50,
                  uint32_t *out_avg) {
    if (iters > RS_LAT_MAX) iters = RS_LAT_MAX;
    if (op == RS_OP_MCAS || op == RS_OP_MFAA) return rs_lat_masked(op, len, iters, quiet, out_p50, out_avg);
    uint8_t src[RSHORT_MAX_LEN];
    for (unsigned j = 0; j < len && j < RSHORT_MAX_LEN; j++) src[j] = (uint8_t)(0x5Au ^ j);
    const uint32_t warm = iters / 10u + 100u;
    uint64_t cas_cur = 0;
    if (op == RS_OP_CAS) { // 現在値を知る(FAA +0)
        if (rs_one(RS_OP_FAA, 8, RSHORT_ATOMIC_OFF, 0, 0, 0, 0) == 0) return -1;
        cas_cur = rs_atomic_result(0);
    }
    uint64_t sum = 0;
    s_ring_cyc = 0;
    s_ring_n = 0;
    s_scat_n = 0;
    for (uint32_t i = 0; i < warm + iters; i++) {
        uint64_t cyc;
        if (op == RS_OP_CAS) {
            cyc = rs_one(op, 8, RSHORT_ATOMIC_OFF, 0, 0, cas_cur + 1u, cas_cur);
            if (cyc != 0) {
                uint64_t old = rs_atomic_result(0);
                if (old != cas_cur) {
                    uart_printf("rshort: cas が失敗した(期待 %llu / 実際 %llu)\n",
                                (unsigned long long)cas_cur, (unsigned long long)old);
                    return -1;
                }
                cas_cur++;
            }
        } else {
            cyc = rs_one(op, len, (op == RS_OP_FAA) ? RSHORT_ATOMIC_OFF : 0u, src, 0, 1u, 0);
        }
        if (cyc == 0) return -1;
        if (i >= warm) {
            uint32_t ns = (uint32_t)rs_cyc2ns(cyc);
            s_lat[i - warm] = ns;
            sum += ns;
        }
    }
    rs_sync_back();
    qsort(s_lat, iters, sizeof(s_lat[0]), rs_cmp_u32);
    const uint32_t avg = (uint32_t)(sum / iters);
    const uint32_t p50 = s_lat[iters / 2u];
    if (!quiet) {
        uart_printf("rshort lat %s %uB x%u: avg %u ns / min %u / p50 %u / p99 %u / p99.9 %u / max %u\n",
                    s_op_name[op], len, iters, avg, s_lat[0], p50, s_lat[(uint64_t)iters * 99u / 100u],
                    s_lat[(uint64_t)iters * 999u / 1000u], s_lat[iters - 1u]);
        uart_printf("rshort   ドアベル(bf=%d)の CPU 所要 avg %llu ns / 応答を CQE で受けた %llu 回"
                    "(cs_req=0x%02x)\n", (s_rs.bf_page && s_opt_bf) ? 1 : 0,
                    (unsigned long long)(s_ring_n ? rs_cyc2ns(s_ring_cyc / s_ring_n) : 0),
                    (unsigned long long)s_scat_n, s_rs.cs_req);
    }
    if (out_p50) *out_p50 = p50;
    if (out_avg) *out_avg = avg;
    return 0;
}

/*=================================================================
 * スループット。qd 個まで積み、**signal は sig 個に 1 個**だけ立てる
 * (CQE は投稿順に完了するので、signaled の 1 個でそれ以前が全部終わったと
 * 分かる)。ドアベルは 1 回の補充につき 1 回だけ鳴らす。
 * read / atomic の同時数は相手の max_dest_rd_atomic(16)で HW が頭打ちにする。
 * ===============================================================*/
static int rs_bw(rs_op_t op, uint32_t len, uint32_t qd, uint32_t ms, int quiet,
                 uint64_t *out_kops) {
    if (qd == 0) qd = 1;
    if (qd > RS_QD_MAX) qd = RS_QD_MAX;
    uint32_t sig = s_opt_sig ? s_opt_sig : ((qd / 2u) ? ((qd / 2u > 32u) ? 32u : qd / 2u) : 1u);
    /* **read / atomic は全部 signaled にする。** 1) scatter to CQE(cs_req)を
     * 有効にした QP に unsignaled な read を投げると LOCAL_QP_OP(syndrome
     * 0x02 / vendor 0x68)で QP が落ちる(実機で踏んだ。Linux の mlx5_ib が
     * cs_req を sq_sig_all の QP にしか付けないのはこのためと見ている)。
     * 2) 同時数が 16 で頭打ちになるので、1 個ずつ返したほうが窓が早く空く
     *    (qd=16 で 4.13 -> 5.30 Mops)。 */
    if (op != RS_OP_WRITE && (s_rs.cs_req != 0u || s_opt_sig == 0u)) sig = 1u;
    if (sig > qd) sig = qd;
    /* 29〜32B の inline は 2 WQEBB になり、NIC が WQE を読む量が倍になる。
     * 積み上げるときはポインタ渡し(1 WQEBB + データの DMA 読み)が速い
     * (32B qd=64 で 8.18 -> 12.84 Mops)。qd=1 では逆に inline が 290ns 速い。 */
    const int inl = (op == RS_OP_WRITE) &&
                    (s_opt_inline == 1 || (s_opt_inline == 2 && len <= RS_INLINE_1BB_MAX));
    uint8_t src[RSHORT_MAX_LEN];
    for (unsigned j = 0; j < len && j < RSHORT_MAX_LEN; j++) src[j] = (uint8_t)(0xC3u ^ j);
    /* 拡張 atomic: 欄は塊の先頭(o=0)。CAS は外れる比較値でもよい(操作の速さを測る)。 */
    uint8_t ma[32], mb[32], mc[32], md[32];
    uint32_t mS = 0;
    memset(ma, 0, sizeof(ma));
    memset(mb, 0, sizeof(mb));
    memset(mc, 0, sizeof(mc));
    memset(md, 0, sizeof(md));
    if (op == RS_OP_MCAS) {
        mS = rs_masked_size(0, len);
        for (uint32_t j = 0; j < len; j++) {
            const uint32_t p = rs_m2w(mS, j);
            ma[p] = 0x11;
            mb[p] = 0x22;
            mc[p] = 0xFF;
            md[p] = 0xFF;
        }
    } else if (op == RS_OP_MFAA) {
        mS = (len <= 4u) ? 4u : (len <= 8u) ? 8u : len;
        if (len <= 8u) {
            ma[mS - 1u] = 1;                                     /* 語の数値 1(BE)*/
            const uint32_t bit = 8u * len - 1u;                  /* 欄の最上位 */
            mb[mS - 1u - bit / 8u] = (uint8_t)(1u << (bit % 8u));
        } else {
            for (uint32_t l = 0; l < mS / 8u; l++) ma[l * 8u + 7u] = 1; /* 各レーン +1 */
        }
    }
    if (op == RS_OP_WRITE && !inl) {
        for (unsigned s = 0; s < RS_SLOTS; s++) memcpy(&s_wbuf[s * 64u], src, len);
    }

    /* signaled な WQE ごとに「その WQE の先頭 / 末尾の WQEBB 位置」と
     * 「そこまでの投稿数」を控える。CQE の wqe_counter は先頭の下位 16bit。 */
    static uint32_t f_start[RS_FIFO];
    static uint32_t f_end[RS_FIFO];
    static uint64_t f_ops[RS_FIFO];
    uint32_t fh = 0, ft = 0;
    uint64_t posted = 0, done = 0, nops = 0;
    uint32_t sq_free_pc = s_rs.sq_pc;          /* ここまでの WQEBB は回収済み */
    uint32_t since_sig = 0;
    const uint64_t khz = s_tsc_khz;
    const uint64_t t_start = __rdtsc();
    const uint64_t t_end = t_start + (uint64_t)ms * khz;
    uint64_t t_last = t_start;
    int stopping = 0;
    uint64_t mismatch = 0;
    uint32_t idle_spins = 0;

    for (;;) {
        /* ---- 補充 ---- */
        if (!stopping) {
            uint64_t now = __rdtsc();
            if (now >= t_end) stopping = 1;
        }
        uint64_t w0 = 0;
        int any = 0;
        const uint32_t first_pc = s_rs.sq_pc;
        if (!stopping) {
            while (posted - done < qd && (s_rs.sq_pc - sq_free_pc) + 2u <= RS_SQ_WQEBB &&
                   ft - fh < RS_FIFO) {
                const uint32_t i = (uint32_t)posted;
                const int sgn = (++since_sig >= sig) || (posted + 1u - done >= qd);
                const unsigned slot = i & (RS_SLOTS - 1u);
                const uint64_t laddr = (op == RS_OP_WRITE) ? (s_rs.wbuf_iova + slot * 64u)
                                     : (len > 64u) ? s_rs.big_iova : (s_rs.lbuf_iova + slot * 64u);
                const uint32_t start_pc = s_rs.sq_pc;
                uint32_t bbs;
                if (mS != 0u) {
                    const uint64_t xo = RS_XAREA_OFF + (s_opt_spread ? (uint64_t)(i & 15u) * 32u : 0u);
                    w0 = rs_build_masked(op == RS_OP_MCAS, mS, s_rs.raddr + xo, laddr, ma, mb, mc, md,
                                         sgn, &bbs);
                } else {
                    w0 = rs_build(op, len, s_rs.raddr + rs_target_off(op, i), src, laddr, 1u, 0u, sgn,
                                  inl, &bbs);
                }
                s_rs.sq_pc += bbs;
                posted++;
                any++;
                if (sgn) {
                    since_sig = 0;
                    f_start[ft & (RS_FIFO - 1u)] = start_pc;
                    f_end[ft & (RS_FIFO - 1u)] = s_rs.sq_pc;
                    f_ops[ft & (RS_FIFO - 1u)] = posted;
                    ft++;
                }
            }
        } else if (posted != done && fh == ft) {
            /* 最後の投稿が unsignaled のまま止めた。signaled な NOP で締める
             * (投稿順に完了するので、これが返れば手前は全部終わっている)。 */
            const uint32_t start_pc = s_rs.sq_pc;
            uint32_t bbs;
            w0 = rs_build(RS_OP_NOP, 0, 0, 0, 0, 0, 0, 1, 0, &bbs);
            s_rs.sq_pc += bbs;
            f_start[ft & (RS_FIFO - 1u)] = start_pc;
            f_end[ft & (RS_FIFO - 1u)] = s_rs.sq_pc;
            f_ops[ft & (RS_FIFO - 1u)] = posted;
            ft++;
            nops++;
            any = 1;
        }
        if (any) rs_ring(w0, first_pc, (any == 1) ? (s_rs.sq_pc - first_pc) : 0u);

        /* ---- 回収 ---- */
        uint16_t cnt;
        uint8_t synd = 0, vsynd = 0;
        int rc;
        while ((rc = rs_poll(&cnt, &synd, &vsynd)) != 0) {
            if (rc < 0) {
                rs_report_cqe_err(s_op_name[op], synd, vsynd);
                return -1;
            }
            if (fh == ft) { mismatch++; continue; }
            const uint32_t e = fh & (RS_FIFO - 1u);
            if ((uint16_t)f_start[e] != cnt) mismatch++;
            done = f_ops[e];
            sq_free_pc = f_end[e];
            fh++;
            t_last = __rdtsc();
            idle_spins = 0;
        }
        if (stopping && posted == done) break;
        if (++idle_spins > 50000000u) {
            uart_printf("rshort: bw: 完了が返らない(posted=%llu done=%llu)\n",
                        (unsigned long long)posted, (unsigned long long)done);
            s_rs.connected = 0;
            return -1;
        }
    }
    rs_sync_back();

    const uint64_t ns = rs_cyc2ns(t_last - t_start);
    const uint64_t kops = ns ? posted * 1000000ull / ns : 0;            /* 千 ops/s */
    const uint64_t mbps_x10 = ns ? posted * len * 10000ull / ns : 0;     /* MB/s x10 */
    if (!quiet) {
        uart_printf("rshort bw %s %uB qd=%u sig=%u: %llu ops / %llu us -> %llu.%03llu Mops/s  "
                    "%llu.%llu MB/s%s\n",
                    s_op_name[op], len, qd, sig, (unsigned long long)posted,
                    (unsigned long long)(ns / 1000u), (unsigned long long)(kops / 1000u),
                    (unsigned long long)(kops % 1000u), (unsigned long long)(mbps_x10 / 10u),
                    (unsigned long long)(mbps_x10 % 10u),
                    mismatch ? "  (!! CQE の wqe_counter が控えと食い違った)" : "");
    }
    if (out_kops) *out_kops = kops;
    (void)nops;
    return mismatch ? -1 : 0;
}

/*=================================================================
 * **2 ポート同時のスループット。** ポートごとの接続(s_rsv[])を 1 本の
 * ループで交互に回す。補充と回収の中身は rs_bw() と同じで、ポートごとの
 * 状態(signaled の待ち行列・投稿数・回収済みの位置)を lane に分けただけ。
 * mask は使うポート(bit0=PF0 / bit1=PF1)。片方だけにすると同じループで
 * 1 ポートぶんを測れるので、1 本と 2 本を同じ測り方で比べられる。
 * ===============================================================*/
typedef struct {
    rs_conn_t *c;
    uint32_t f_start[RS_FIFO];
    uint32_t f_end[RS_FIFO];
    uint64_t f_ops[RS_FIFO];
    uint32_t fh, ft;
    uint64_t posted, done;
    uint32_t sq_free_pc;
    uint32_t since_sig;
    uint64_t t_last;
    uint64_t mismatch;
} rs_lane_t;

static rs_lane_t s_lanes[2];

static int rs_bw_multi(rs_op_t op, uint32_t len, uint32_t qd, uint32_t ms, uint32_t mask) {
    rs_conn_t *const keep = s_cur;
    unsigned nl = 0;
    rs_lane_t *ln[2];
    for (int pf = 0; pf < 2; pf++) {
        if (!(mask & (1u << pf))) continue;
        if (!s_rsv[pf].connected) {
            uart_printf("rshort: bw2: PF%d が未接続\n", pf);
            return -1;
        }
        rs_lane_t *L = &s_lanes[nl];
        memset(L, 0, sizeof(*L));
        L->c = &s_rsv[pf];
        L->sq_free_pc = L->c->sq_pc;
        ln[nl++] = L;
    }
    if (qd == 0) qd = 1;
    if (qd > RS_QD_MAX) qd = RS_QD_MAX;
    uint32_t sig = s_opt_sig ? s_opt_sig : ((qd / 2u) ? ((qd / 2u > 32u) ? 32u : qd / 2u) : 1u);
    if (op != RS_OP_WRITE) sig = 1u;   /* rs_bw() と同じ理由(scatter to CQE と同時数の上限)*/
    if (sig > qd) sig = qd;
    const int inl = (op == RS_OP_WRITE) &&
                    (s_opt_inline == 1 || (s_opt_inline == 2 && len <= RS_INLINE_1BB_MAX));
    uint8_t src[RSHORT_MAX_LEN];
    for (unsigned j = 0; j < len && j < RSHORT_MAX_LEN; j++) src[j] = (uint8_t)(0xC3u ^ j);
    if (op == RS_OP_WRITE && !inl) {
        for (unsigned s = 0; s < RS_SLOTS; s++) memcpy(&s_wbuf[s * 64u], src, len);
    }

    const uint64_t khz = s_tsc_khz;
    const uint64_t t_start = __rdtsc();
    const uint64_t t_end = t_start + (uint64_t)ms * khz;
    int stopping = 0;
    uint32_t idle_spins = 0;
    int rc_all = 0;

    for (;;) {
        if (!stopping && __rdtsc() >= t_end) stopping = 1;
        int all_done = 1;
        int progressed = 0;
        for (unsigned l = 0; l < nl; l++) {
            rs_lane_t *const L = ln[l];
            s_cur = L->c;
            /* ---- 補充 ---- */
            uint64_t w0 = 0;
            int any = 0;
            const uint32_t first_pc = s_rs.sq_pc;
            if (!stopping) {
                while (L->posted - L->done < qd && (s_rs.sq_pc - L->sq_free_pc) + 2u <= RS_SQ_WQEBB &&
                       L->ft - L->fh < RS_FIFO) {
                    const uint32_t i = (uint32_t)L->posted;
                    const int sgn = (++L->since_sig >= sig) || (L->posted + 1u - L->done >= qd);
                    const unsigned slot = i & (RS_SLOTS - 1u);
                    const uint64_t laddr = (op == RS_OP_WRITE) ? (s_rs.wbuf_iova + slot * 64u)
                                         : (len > 64u) ? s_rs.big_iova : (s_rs.lbuf_iova + slot * 64u);
                    const uint32_t start_pc = s_rs.sq_pc;
                    uint32_t bbs;
                    w0 = rs_build(op, len, s_rs.raddr + rs_target_off(op, i), src, laddr, 1u, 0u, sgn,
                                  inl, &bbs);
                    s_rs.sq_pc += bbs;
                    L->posted++;
                    any++;
                    if (sgn) {
                        L->since_sig = 0;
                        const uint32_t e = L->ft & (RS_FIFO - 1u);
                        L->f_start[e] = start_pc;
                        L->f_end[e] = s_rs.sq_pc;
                        L->f_ops[e] = L->posted;
                        L->ft++;
                    }
                }
            } else if (L->posted != L->done && L->fh == L->ft) {
                /* 最後が unsignaled のまま止めた。signaled な NOP で締める。 */
                const uint32_t start_pc = s_rs.sq_pc;
                uint32_t bbs;
                w0 = rs_build(RS_OP_NOP, 0, 0, 0, 0, 0, 0, 1, 0, &bbs);
                s_rs.sq_pc += bbs;
                const uint32_t e = L->ft & (RS_FIFO - 1u);
                L->f_start[e] = start_pc;
                L->f_end[e] = s_rs.sq_pc;
                L->f_ops[e] = L->posted;
                L->ft++;
                any = 1;
            }
            if (any) rs_ring(w0, first_pc, (any == 1) ? (s_rs.sq_pc - first_pc) : 0u);

            /* ---- 回収 ---- */
            uint16_t cnt;
            uint8_t synd = 0, vsynd = 0;
            int rc;
            while ((rc = rs_poll(&cnt, &synd, &vsynd)) != 0) {
                if (rc < 0) {
                    rs_report_cqe_err(s_op_name[op], synd, vsynd);
                    rc_all = -1;
                    goto out;
                }
                if (L->fh == L->ft) { L->mismatch++; continue; }
                const uint32_t e = L->fh & (RS_FIFO - 1u);
                if ((uint16_t)L->f_start[e] != cnt) L->mismatch++;
                L->done = L->f_ops[e];
                L->sq_free_pc = L->f_end[e];
                L->fh++;
                L->t_last = __rdtsc();
                progressed = 1;
            }
            if (!(stopping && L->posted == L->done)) all_done = 0;
        }
        if (stopping && all_done) break;
        if (progressed) {
            idle_spins = 0;
        } else if (++idle_spins > 50000000u) {
            uart_printf("rshort: bw2: 完了が返らない\n");
            for (unsigned l = 0; l < nl; l++) ln[l]->c->connected = 0;
            rc_all = -1;
            goto out;
        }
    }

    {
        uint64_t sum_ops = 0, ns_max = 0;
        for (unsigned l = 0; l < nl; l++) {
            rs_lane_t *const L = ln[l];
            s_cur = L->c;
            rs_sync_back();
            const uint64_t ns = rs_cyc2ns(L->t_last - t_start);
            const uint64_t kops = ns ? L->posted * 1000000ull / ns : 0;
            const uint64_t mbps_x10 = ns ? L->posted * len * 10000ull / ns : 0;
            uart_printf("rshort bw2 %s %uB qd=%u PF%d: %llu ops / %llu us -> %llu.%03llu Mops/s  "
                        "%llu.%llu MB/s%s\n",
                        s_op_name[op], len, qd, (int)(L->c - s_rsv), (unsigned long long)L->posted,
                        (unsigned long long)(ns / 1000u), (unsigned long long)(kops / 1000u),
                        (unsigned long long)(kops % 1000u), (unsigned long long)(mbps_x10 / 10u),
                        (unsigned long long)(mbps_x10 % 10u),
                        L->mismatch ? "  (!! CQE の wqe_counter が控えと食い違った)" : "");
            sum_ops += L->posted;
            if (ns > ns_max) ns_max = ns;
        }
        const uint64_t kops = ns_max ? sum_ops * 1000000ull / ns_max : 0;
        const uint64_t mbps_x10 = ns_max ? sum_ops * len * 10000ull / ns_max : 0;
        uart_printf("rshort bw2 %s %uB qd=%u 合計(%u ポート): %llu.%03llu Mops/s  %llu.%llu MB/s\n",
                    s_op_name[op], len, qd, nl, (unsigned long long)(kops / 1000u),
                    (unsigned long long)(kops % 1000u), (unsigned long long)(mbps_x10 / 10u),
                    (unsigned long long)(mbps_x10 % 10u));
    }
out:
    s_cur = keep;
    return rc_all;
}

/*=================================================================
 * BlueFlame が本当に使われているかを確かめる。**ホストメモリ上の WQE と
 * BF レジスタへ書く WQE で inline データだけを変えて** 8B の write を 1 個出し、
 * 相手に届いた値を読み戻す。BF の値が届けば NIC は BF の WQE を実行した
 * (= WQE を DMA で読みに来ていない)、メモリの値なら BF を捨てて読みに来た。
 * ===============================================================*/
/*=================================================================
 * 拡張(masked)atomic の WQE を書く。ConnectX-4 以降の独自拡張で、
 * opcode 0x14(masked CAS)/ 0x15(masked FAA)、ctrl の opmod に
 * 0x08 | (log2(S) - 2) を入れて大きさ S(4 / 8 / 16 / 32B)を指定する
 * (UCX の UCT_IB_MLX5_OPMOD_EXT_ATOMIC() と同じ)。
 *
 *   CAS: [swap S][compare S][swap_mask S][compare_mask S]
 *   FAA: [add S][field_boundary S](S=4 のときは 16B へ詰める)
 *
 * 各フィールドは**呼び出し側が並べたバイト列をそのまま**置く(バイト順の
 * 解釈は rs_xprobe で実機から決める)。
 * ===============================================================*/
static uint64_t rs_build_masked(int is_cas, uint32_t S, uint64_t raddr, uint64_t laddr,
                                const uint8_t *a, const uint8_t *b, const uint8_t *c,
                                const uint8_t *d, int signaled, uint32_t *out_bbs) {
    uint8_t seg[128];
    memset(seg, 0, sizeof(seg));
    uint32_t seglen;
    if (is_cas) {
        memcpy(seg, a, S);
        memcpy(seg + S, b, S);
        memcpy(seg + 2u * S, c, S);
        memcpy(seg + 3u * S, d, S);
        seglen = 4u * S;
    } else {
        memcpy(seg, a, S);
        memcpy(seg + S, b, S);
        seglen = (2u * S < 16u) ? 16u : 2u * S;
    }
    uint32_t log_s = 0;
    while ((1u << log_s) < S) log_s++;
    const uint32_t opmod = 0x08u | (log_s - 2u);
    const uint32_t opcode = is_cas ? MLX5_OPCODE_ATOMIC_MASKED_CS : MLX5_OPCODE_ATOMIC_MASKED_FA;
    const uint32_t pc = s_rs.sq_pc;
    const uint32_t ds = 2u + seglen / 16u + 1u;
    const uint64_t w0 = (uint64_t)__builtin_bswap32((opmod << 24) | ((pc & 0xFFFFu) << 8) | opcode) |
                        ((uint64_t)__builtin_bswap32(s_rs.qpn8 | ds) << 32);
    rs_wqe_put(pc, 0, w0);
    rs_wqe_put(pc, 1, signaled ? ((uint64_t)MLX5_WQE_CTRL_CQ_UPDATE << 24) : 0u);
    rs_wqe_put(pc, 2, __builtin_bswap64(raddr));
    rs_wqe_put(pc, 3, (uint64_t)__builtin_bswap32(s_rs.rkey));
    for (unsigned k = 0; k < seglen / 8u; k++) {
        uint64_t v;
        memcpy(&v, seg + 8u * k, 8);
        rs_wqe_put(pc, 4u + k, v);
    }
    const unsigned dk = 4u + seglen / 8u;
    rs_wqe_put(pc, dk, (uint64_t)__builtin_bswap32(S) | ((uint64_t)__builtin_bswap32(s_rs.lkey) << 32));
    rs_wqe_put(pc, dk + 1u, __builtin_bswap64(laddr));
    *out_bbs = (ds + 3u) / 4u;
    return w0;
}

/* 拡張 atomic を 1 個出して完了を待つ。元値(S バイト)は s_lbuf の slot へ。 */
static uint64_t rs_one_masked(int is_cas, uint32_t S, uint64_t roff, unsigned slot,
                              const uint8_t *a, const uint8_t *b, const uint8_t *c,
                              const uint8_t *d) {
    uint32_t bbs;
    const uint64_t t0 = __rdtsc();
    const uint32_t first_pc = s_rs.sq_pc;
    const uint64_t w0 = rs_build_masked(is_cas, S, s_rs.raddr + roff, s_rs.lbuf_iova + slot * 64u,
                                        a, b, c, d, 1, &bbs);
    s_rs.sq_pc += bbs;
    rs_ring(w0, first_pc, bbs);
    uint16_t cnt;
    uint8_t synd = 0, vsynd = 0;
    int rc;
    while ((rc = rs_poll(&cnt, &synd, &vsynd)) == 0) {
        if (rs_cyc2ns(__rdtsc() - t0) > (uint64_t)RS_SPIN_LIMIT_MS * 1000000ull) {
            uart_printf("rshort: masked %s %uB: 完了しない\n", is_cas ? "cas" : "faa", S);
            s_rs.connected = 0;
            return 0;
        }
    }
    if (rc > 0 && s_rs.last_scat != 0) {
        for (uint32_t j = 0; j < S; j++) s_lbuf[slot * 64u + j] = s_rs.last_scat[j];
    }
    const uint64_t t1 = __rdtsc();
    if (rc < 0) {
        rs_report_cqe_err(is_cas ? "masked cas" : "masked faa", synd, vsynd);
        return 0;
    }
    return (t1 - t0) ? (t1 - t0) : 1u;
}

static void rs_hex(const char *tag, const uint8_t *p, uint32_t n) {
    char line[160];
    unsigned o = 0;
    for (uint32_t i = 0; i < n && o + 4u < sizeof(line); i++) {
        static const char hx[] = "0123456789abcdef";
        line[o++] = hx[p[i] >> 4];
        line[o++] = hx[p[i] & 15u];
        if ((i & 3u) == 3u) line[o++] = ' ';
    }
    line[o] = 0;
    uart_printf("rshort:   %s %s\n", tag, line);
}

/* ---- 1〜32B の CAS / FAA(拡張 atomic の上に組む)----
 *
 * 実機で確かめた形式(rs_xprobe):
 *   - WQE の値は W バイト(S=4 なら 4、それ以外は 8)ごとの BE の数。相手の
 *     メモリには語ごとにホスト順(LE)で置かれ、語の並び順は変わらない。
 *     元値も WQE と同じ並びで返る。-> メモリのバイト m と WQE の位置は
 *     「語の中で前後を反転」の対応になる(rs_m2w())。
 *   - FAA の field_boundary の 1 のビットが欄の最上位で、そこから上へは
 *     桁上がりしない。**8B の語をまたいでは桁上がりしない**(16/32B は
 *     8B レーンごとの独立な加算)。 */

/*=================================================================
 * 相手の [roff, roff+len)(1〜32B)を、バイト列として比較して一致すれば
 * 置き換える。欄の外は触らない(マスクで外す)。
 *
 * 引数:
 *   roff / len - 相手の MR 内の位置と長さ(32B 境界をまたがないこと)
 *   cmp / swap - 比較値と新値(相手のメモリでの並び)
 *   old        - それまでの内容(相手のメモリでの並び、len バイト)
 * 戻り値:
 *   1=一致して置き換えた、0=不一致(変更なし)、-1=失敗、-2=境界をまたぐ
 * ===============================================================*/
static int rs_mcas(uint64_t roff, uint32_t len, const uint8_t *cmp, const uint8_t *swap,
                   uint8_t *old, uint64_t *out_cyc) {
    const uint32_t S = rs_masked_size(roff, len);
    if (S == 0u) return -2;
    const uint64_t base = roff & ~(uint64_t)(S - 1u);
    const uint32_t o = (uint32_t)(roff - base);
    uint8_t a[32], b[32], c[32], d[32];
    memset(a, 0, S);
    memset(b, 0, S);
    memset(c, 0, S);
    for (uint32_t i = 0; i < len; i++) {
        const uint32_t p = rs_m2w(S, o + i);
        a[p] = swap[i];
        b[p] = cmp[i];
        c[p] = 0xFF;
    }
    memcpy(d, c, S);
    const uint64_t cyc = rs_one_masked(1, S, base, 0, a, b, c, d);
    if (cyc == 0) return -1;
    if (out_cyc) *out_cyc = cyc;
    int eq = 1;
    for (uint32_t i = 0; i < len; i++) {
        old[i] = s_lbuf[rs_m2w(S, o + i)];
        if (old[i] != cmp[i]) eq = 0;
    }
    return eq;
}

/*=================================================================
 * 相手の [roff, roff+len)(1〜8B、8B の語をまたがないこと)を LE の整数と
 * みなして add を足す。欄の外へは桁上がりしない(欄の幅で折り返す)。
 *
 * 戻り値: 0=成功(*old に足す前の値)、-1=失敗、-2=語をまたぐ
 * ===============================================================*/
static int rs_mfaa(uint64_t roff, uint32_t len, uint64_t add, uint64_t *old, uint64_t *out_cyc) {
    if (len == 0u || len > 8u || (roff / 8u) != ((roff + len - 1u) / 8u)) return -2;
    const uint32_t S = ((roff / 4u) == ((roff + len - 1u) / 4u)) ? 4u : 8u;
    const uint64_t base = roff & ~(uint64_t)(S - 1u);
    const uint32_t o = (uint32_t)(roff - base);
    const uint64_t fmask = (len == 8u) ? ~0ull : ((1ull << (8u * len)) - 1u);
    const uint64_t addw = (add & fmask) << (8u * o);
    const uint64_t bound = 1ull << (8u * (o + len) - 1u);
    uint8_t a[8], b[8];
    for (uint32_t i = 0; i < S; i++) { // 語の数値を BE で並べる
        a[i] = (uint8_t)(addw >> (8u * (S - 1u - i)));
        b[i] = (uint8_t)(bound >> (8u * (S - 1u - i)));
    }
    const uint64_t cyc = rs_one_masked(0, S, base, 0, a, b, 0, 0);
    if (cyc == 0) return -1;
    if (out_cyc) *out_cyc = cyc;
    uint64_t w = 0;
    for (uint32_t i = 0; i < S; i++) w = (w << 8) | s_lbuf[i]; // 元の語(BE で返る)
    *old = (w >> (8u * o)) & fmask;
    return 0;
}

/* 16B / 32B の多レーン FAA: 8B の LE 整数 lanes 本へそれぞれ add[i] を同時に足す。 */
static int rs_mfaa_lanes(uint64_t roff, uint32_t S, const uint64_t *add, uint64_t *old,
                         uint64_t *out_cyc) {
    if ((S != 16u && S != 32u) || (roff % S) != 0u) return -2;
    uint8_t a[32], b[32];
    memset(b, 0, sizeof(b));
    for (uint32_t l = 0; l < S / 8u; l++) {
        for (uint32_t i = 0; i < 8u; i++) a[l * 8u + i] = (uint8_t)(add[l] >> (8u * (7u - i)));
    }
    const uint64_t cyc = rs_one_masked(0, S, roff, 0, a, b, 0, 0);
    if (cyc == 0) return -1;
    if (out_cyc) *out_cyc = cyc;
    for (uint32_t l = 0; l < S / 8u; l++) {
        uint64_t w = 0;
        for (uint32_t i = 0; i < 8u; i++) w = (w << 8) | s_lbuf[l * 8u + i];
        old[l] = w;
    }
    return 0;
}

/*=================================================================
 * 1〜32B の CAS / FAA の qd=1 レイテンシ。CAS は毎回当たるように比較値を
 * 追いかける(外れたら止める)。欄は RS_XAREA_OFF の塊の先頭。
 * ===============================================================*/
static int rs_lat_masked(rs_op_t op, uint32_t len, uint32_t iters, int quiet, uint32_t *out_p50,
                         uint32_t *out_avg) {
    const uint64_t off = RS_XAREA_OFF;
    uint8_t cur[32], nxt[32], old[32];
    if (op == RS_OP_MCAS) {
        if (rs_one(RS_OP_READ, len, off, 0, 2, 0, 0) == 0) return -1;
        memcpy(cur, &s_lbuf[128], len);
    }
    const uint32_t warm = iters / 10u + 100u;
    uint64_t sum = 0;
    s_scat_n = 0;
    for (uint32_t i = 0; i < warm + iters; i++) {
        uint64_t cyc = 0;
        int r;
        if (op == RS_OP_MCAS) {
            memcpy(nxt, cur, len);
            nxt[0]++;
            r = rs_mcas(off, len, cur, nxt, old, &cyc);
            if (r != 1) {
                uart_printf("rshort: mcas %uB が外れた/失敗した(r=%d)\n", len, r);
                return -1;
            }
            memcpy(cur, nxt, len);
        } else if (len <= 8u) {
            uint64_t o64;
            r = rs_mfaa(off, len, 1u, &o64, &cyc);
        } else {
            uint64_t add[4] = { 1u, 1u, 1u, 1u }, o4[4];
            r = rs_mfaa_lanes(off, len, add, o4, &cyc);
        }
        if (r < 0 || cyc == 0) return -1;
        if (i >= warm) {
            const uint32_t ns = (uint32_t)rs_cyc2ns(cyc);
            s_lat[i - warm] = ns;
            sum += ns;
        }
    }
    rs_sync_back();
    qsort(s_lat, iters, sizeof(s_lat[0]), rs_cmp_u32);
    const uint32_t avg = (uint32_t)(sum / iters);
    const uint32_t p50 = s_lat[iters / 2u];
    if (!quiet) {
        uart_printf("rshort lat %s %uB(拡張 atomic %uB)x%u: avg %u ns / min %u / p50 %u / p99 %u / "
                    "p99.9 %u / max %u\n", s_op_name[op], len,
                    (op == RS_OP_MCAS) ? rs_masked_size(off, len) : ((len <= 4u) ? 4u : (len <= 8u) ? 8u : len),
                    iters, avg, s_lat[0], p50, s_lat[(uint64_t)iters * 99u / 100u],
                    s_lat[(uint64_t)iters * 999u / 1000u], s_lat[iters - 1u]);
    }
    if (out_p50) *out_p50 = p50;
    if (out_avg) *out_avg = avg;
    return 0;
}

/*=================================================================
 * 拡張 atomic の形式とバイト順を実機で確かめる(相手の未初期化領域
 * [6144, 6656) を使う。相手は MR を 0 で埋めている)。
 * ===============================================================*/
static int rs_xprobe(void) {
    uint8_t a[32], b[32], c[32], d[32];
    static const uint32_t sizes[] = { 4, 8, 16, 32 };
    for (unsigned si = 0; si < 4u; si++) {
        const uint32_t S = sizes[si];
        const uint64_t off = 6144u + si * 64u;
        /* CAS: 比較値 0(初期値と一致)、新値 = 0x10+i、マスク全 ff */
        for (uint32_t i = 0; i < S; i++) { a[i] = (uint8_t)(0x10u + i); b[i] = 0; c[i] = 0xFF; d[i] = 0xFF; }
        memset(&s_lbuf[64], 0xEE, 64);
        if (rs_one_masked(1, S, off, 1, a, b, c, d) == 0) return -1;
        uart_printf("rshort: [xprobe] masked CAS %uB @%llu(新値 10 11 12..、比較 0)\n", S,
                    (unsigned long long)off);
        rs_hex("元値:", &s_lbuf[64], S);
        if (rs_one(RS_OP_READ, S, off, 0, 2, 0, 0) == 0) return -1;
        rs_hex("相手のメモリ:", &s_lbuf[128], S);
        /* 2 回目: 比較値を「いまのメモリの内容」にすれば成功するはず。 */
        memcpy(b, &s_lbuf[128], S);
        for (uint32_t i = 0; i < S; i++) a[i] = (uint8_t)(0x80u + i);
        if (rs_one_masked(1, S, off, 1, a, b, c, d) == 0) return -1;
        rs_hex("2 回目の元値:", &s_lbuf[64], S);
        if (rs_one(RS_OP_READ, S, off, 0, 2, 0, 0) == 0) return -1;
        rs_hex("2 回目の後のメモリ:", &s_lbuf[128], S);
    }
    for (unsigned si = 0; si < 4u; si++) {
        const uint32_t S = sizes[si];
        const uint64_t off = 6400u + si * 64u;
        /* FAA: 加数の最後のバイトだけ 1(BE で 1)、境界 0 */
        memset(a, 0, S);
        a[S - 1u] = 1;
        memset(b, 0, S);
        if (rs_one_masked(0, S, off, 1, a, b, 0, 0) == 0) return -1;
        if (rs_one_masked(0, S, off, 1, a, b, 0, 0) == 0) return -1;
        uart_printf("rshort: [xprobe] masked FAA %uB @%llu(加数 = 末尾バイト 1、境界 0、2 回)\n", S,
                    (unsigned long long)off);
        rs_hex("2 回目の元値:", &s_lbuf[64], S);
        if (rs_one(RS_OP_READ, S, off, 0, 2, 0, 0) == 0) return -1;
        rs_hex("相手のメモリ:", &s_lbuf[128], S);
    }
    /* 境界と桁上がりの向き。メモリを write で仕込んでから 16B FAA を投げる。 */
    {
        const uint64_t off = 6656u;
        uint8_t m[16];
        /* [T1] 語0 の byte0 = ff。1B の欄として +1、境界 = bit7 -> 欄だけ 0 に戻るか */
        memset(m, 0, 16);
        m[0] = 0xFF;
        if (rs_one(RS_OP_WRITE, 16, off, m, 4, 0, 0) == 0) return -1;
        memset(a, 0, 16);
        memset(b, 0, 16);
        a[7] = 1;      /* 語0 の数値 1(WQE は BE なので末尾バイト)*/
        b[7] = 0x80;   /* 語0 の bit7 = 欄の最上位 */
        if (rs_one_masked(0, 16, off, 1, a, b, 0, 0) == 0) return -1;
        if (rs_one(RS_OP_READ, 16, off, 0, 2, 0, 0) == 0) return -1;
        uart_printf("rshort: [xprobe] T1 メモリ ff 00.. に +1(境界 bit7)\n");
        rs_hex("相手のメモリ:", &s_lbuf[128], 16);
        /* [T2] 語1 = ff..ff に語1 へ +1、境界 0 -> 語0 へ繰り上がるか */
        memset(m, 0, 16);
        memset(m + 8, 0xFF, 8);
        if (rs_one(RS_OP_WRITE, 16, off, m, 4, 0, 0) == 0) return -1;
        memset(a, 0, 16);
        memset(b, 0, 16);
        a[15] = 1;
        if (rs_one_masked(0, 16, off, 1, a, b, 0, 0) == 0) return -1;
        if (rs_one(RS_OP_READ, 16, off, 0, 2, 0, 0) == 0) return -1;
        uart_printf("rshort: [xprobe] T2 メモリ 00x8 ffx8 の語1 に +1(境界 0)\n");
        rs_hex("相手のメモリ:", &s_lbuf[128], 16);
        /* [T3] 語0 = ff..ff に語0 へ +1、境界 0 -> 語1 へ繰り上がるか */
        memset(m, 0, 16);
        memset(m, 0xFF, 8);
        if (rs_one(RS_OP_WRITE, 16, off, m, 4, 0, 0) == 0) return -1;
        memset(a, 0, 16);
        a[7] = 1;
        if (rs_one_masked(0, 16, off, 1, a, b, 0, 0) == 0) return -1;
        if (rs_one(RS_OP_READ, 16, off, 0, 2, 0, 0) == 0) return -1;
        uart_printf("rshort: [xprobe] T3 メモリ ffx8 00x8 の語0 に +1(境界 0)\n");
        rs_hex("相手のメモリ:", &s_lbuf[128], 16);
        /* [T4] 4B: メモリ ff ff 00 00、2B の欄(byte0-1)に +1、境界 bit15 */
        memset(m, 0, 16);
        m[0] = 0xFF;
        m[1] = 0xFF;
        if (rs_one(RS_OP_WRITE, 4, off + 32u, m, 4, 0, 0) == 0) return -1;
        memset(a, 0, 4);
        memset(b, 0, 4);
        a[3] = 1;
        b[2] = 0x80;   /* 4B の BE で bit15 */
        if (rs_one_masked(0, 4, off + 32u, 1, a, b, 0, 0) == 0) return -1;
        if (rs_one(RS_OP_READ, 4, off + 32u, 0, 2, 0, 0) == 0) return -1;
        uart_printf("rshort: [xprobe] T4 4B メモリ ff ff 00 00 の下位 2B 欄に +1(境界 bit15)\n");
        rs_hex("相手のメモリ:", &s_lbuf[128], 4);
    }
    rs_sync_back();
    return 0;
}

static int rs_bf_probe(void) {
    if (s_rs.bf_page == 0) {
        uart_printf("rshort: bfprobe: WC マップが無い\n");
        return -1;
    }
    static const uint8_t mem_val[8] = { 'M', 'E', 'M', 'O', 'R', 'Y', '_', '_' };
    static const uint8_t bf_val[8]  = { 'B', 'L', 'U', 'E', 'F', 'L', 'M', 'E' };
    const uint64_t roff = 3072u;
    uint32_t bbs;
    const uint32_t first_pc = s_rs.sq_pc;
    rs_build(RS_OP_WRITE, 8, s_rs.raddr + roff, mem_val, 0, 0, 0, 1, 1, &bbs);
    s_rs.sq_pc += bbs;
    uint64_t bb[8];
    for (unsigned k = 0; k < 8u; k++) bb[k] = rs_bb(first_pc)[k];
    memcpy((uint8_t *)bb + 36, bf_val, 8); /* ctrl16 + raddr16 + inline ヘッダ 4 の直後 */
    rs_barrier();
    *s_rs.sq_dbr = __builtin_bswap32(s_rs.sq_pc);
    rs_barrier();
    volatile __m128i *dst = (volatile __m128i *)(uintptr_t)(s_rs.bf_page + MLX5_BF_OFFSET + s_rs.bf_off);
    const __m128i *src = (const __m128i *)(const void *)bb;
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    _mm_sfence();
    s_rs.bf_off ^= RS_BF_BUF_SIZE;
    uint16_t cnt;
    uint8_t synd = 0, vsynd = 0;
    int rc;
    const uint64_t t0 = __rdtsc();
    while ((rc = rs_poll(&cnt, &synd, &vsynd)) == 0) {
        if (rs_cyc2ns(__rdtsc() - t0) > 1000000000ull) {
            uart_printf("rshort: bfprobe: 完了しない\n");
            return -1;
        }
    }
    if (rc < 0) {
        rs_report_cqe_err("bfprobe", synd, vsynd);
        return -1;
    }
    if (rs_one(RS_OP_READ, 8, roff, 0, 3, 0, 0) == 0) return -1;
    const uint8_t *got = &s_lbuf[3u * 64u];
    const int is_bf = (memcmp(got, bf_val, 8) == 0);
    const int is_mem = (memcmp(got, mem_val, 8) == 0);
    uart_printf("rshort: bfprobe: 届いた値 \"%c%c%c%c%c%c%c%c\" -> %s\n",
                got[0], got[1], got[2], got[3], got[4], got[5], got[6], got[7],
                is_bf ? "BlueFlame の WQE が実行された(WQE の DMA 読みは省けている)"
                      : is_mem ? "メモリの WQE が実行された(BF は捨てられ、WQE を読みに来ている)"
                               : "どちらでもない(!!)");
    rs_sync_back();
    return 0;
}

/* ------------------------------------------------------------------ */

static uint8_t s_model[RSHORT_DATA_BYTES];

static inline uint8_t rs_init_pattern(uint32_t i) { return (uint8_t)(i * 7u + 3u); }

/* FNV-1a 64(rdma_short_peer の hash と同じ)。 */
static uint64_t rs_fnv(uint64_t h, const uint8_t *p, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

/* 相手のデータ領域を 32B ずつ読み、モデルと比べる。 */
static int rs_check_region(const char *tag) {
    uint32_t bad = 0;
    for (uint32_t off = 0; off < RSHORT_DATA_BYTES; off += 32u) {
        if (rs_one(RS_OP_READ, 32, off, 0, 1, 0, 0) == 0) return -1;
        for (uint32_t j = 0; j < 32u; j++) {
            if (s_lbuf[64u + j] != s_model[off + j]) {
                if (bad < 5u) {
                    uart_printf("rshort:   [%s] off=%u: 読んだ値 0x%02x / 期待 0x%02x\n",
                                tag, off + j, s_lbuf[64u + j], s_model[off + j]);
                }
                bad++;
            }
        }
    }
    uart_printf("rshort: [%s] データ領域 4096B を読み戻して照合: 不一致 %u バイト %s\n",
                tag, bad, bad ? "NG" : "OK");
    return bad ? -1 : 0;
}

/*=================================================================
 * 正しさの検査。**最後に出す hash を、相手側(rdma_short_peer)が自分の
 * メモリから計算した hash と突き合わせる**ことで、自分で書いて自分で
 * 読むだけの自己完結な検証(両側が同じ間違い方をする)を避ける。
 * 接続直後(相手が領域を初期化した状態)で実行すること。
 * ===============================================================*/
static int rs_verify(void) {
    int ng = 0;
    for (uint32_t i = 0; i < RSHORT_DATA_BYTES; i++) s_model[i] = rs_init_pattern(i);

    /* [1] 初期値を 1〜32B のあらゆる長さ・半端な位置で読む。 */
    {
        uint32_t bad = 0;
        for (uint32_t len = 1; len <= RSHORT_MAX_LEN; len++) {
            for (uint32_t k = 0; k < 4u; k++) {
                const uint32_t off = (len * 97u + k * 1031u) % (RSHORT_DATA_BYTES - RSHORT_MAX_LEN);
                memset(&s_lbuf[64], 0xEE, 64);
                if (rs_one(RS_OP_READ, len, off, 0, 1, 0, 0) == 0) return -1;
                for (uint32_t j = 0; j < len; j++) {
                    if (s_lbuf[64u + j] != s_model[off + j]) bad++;
                }
                for (uint32_t j = len; j < 64u; j++) { // 着地点の外を壊していないこと
                    if (s_lbuf[64u + j] != 0xEEu) bad++;
                }
            }
        }
        uart_printf("rshort: [1] read 1〜32B x 4 か所(初期値との照合): 不一致 %u %s\n",
                    bad, bad ? "NG" : "OK");
        ng |= (bad != 0);
    }

    /* [2] write 1〜32B を半端な位置へ。前半は inline、後半はポインタ渡し。 */
    const int save_inline = s_opt_inline;
    for (int pass = 0; pass < 2; pass++) {
        s_opt_inline = (pass == 0);
        for (uint32_t len = 1; len <= RSHORT_MAX_LEN; len++) {
            /* [0, 2560) に収める([2560, 4096) は拡張 atomic の検査で使う)。 */
            const uint32_t off = (uint32_t)pass * 1280u + (len - 1u) * 40u + (len * 3u) % 8u;
            uint8_t d[RSHORT_MAX_LEN];
            for (uint32_t j = 0; j < len; j++) d[j] = (uint8_t)(0xA5u ^ (len * 31u) ^ (j * 13u) ^ (uint32_t)pass);
            if (rs_one(RS_OP_WRITE, len, off, d, (unsigned)len, 0, 0) == 0) { s_opt_inline = save_inline; return -1; }
            memcpy(&s_model[off], d, len);
        }
    }
    s_opt_inline = save_inline;
    uart_printf("rshort: [2] write 1〜32B を inline / ポインタ渡しの両方で 64 回\n");
    ng |= (rs_check_region("2") != 0);

    /* [3] atomic の元値がどちらのバイト順で返るかを見る(相手は LE で
     *     0x0102030405060708 を置いている。FAA +0 で値を変えずに読む)。 */
    if (rs_one(RS_OP_FAA, 8, RSHORT_PROBE_OFF, 0, 0, 0, 0) == 0) return -1;
    {
        const uint8_t *r = &s_lbuf[0];
        uart_printf("rshort: [3] FAA(+0) の元値のバイト列: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
        if (r[0] == 0x01 && r[7] == 0x08) s_rs.res_be = 1;
        else if (r[0] == 0x08 && r[7] == 0x01) s_rs.res_be = 0;
        else { uart_printf("rshort: [3] どちらの順でもない NG\n"); return -1; }
        s_rs.res_known = 1;
        uart_printf("rshort: [3] 元値は %s で返る(値 0x%016llx)OK\n",
                    s_rs.res_be ? "ビッグエンディアン" : "リトルエンディアン",
                    (unsigned long long)rs_atomic_result(0));
    }

    /* [4] FAA: 語 0 へ +1 を 1000 回。元値が 0,1,2,... と並ぶこと。
     *     続けて 2^32 を足す(32bit で折り返していないことの確認)。 */
    {
        uint32_t bad = 0;
        for (uint64_t i = 0; i < 1000u; i++) {
            if (rs_one(RS_OP_FAA, 8, RSHORT_ATOMIC_OFF, 0, 0, 1u, 0) == 0) return -1;
            if (rs_atomic_result(0) != i) bad++;
        }
        if (rs_one(RS_OP_FAA, 8, RSHORT_ATOMIC_OFF, 0, 0, 0x100000000ull, 0) == 0) return -1;
        if (rs_atomic_result(0) != 1000u) bad++;
        uart_printf("rshort: [4] FAA +1 x1000 と +2^32: 元値の食い違い %u %s\n", bad, bad ? "NG" : "OK");
        ng |= (bad != 0);
    }
    /* [5] CAS: 語 1 を 0->1->...->1000 と進める(毎回成功)。最後に外れる
     *     比較値で投げ、元値が返って値が変わらないこと。 */
    {
        uint32_t bad = 0;
        for (uint64_t i = 0; i < 1000u; i++) {
            if (rs_one(RS_OP_CAS, 8, RSHORT_ATOMIC_OFF + 8u, 0, 0, i + 1u, i) == 0) return -1;
            if (rs_atomic_result(0) != i) bad++;
        }
        if (rs_one(RS_OP_CAS, 8, RSHORT_ATOMIC_OFF + 8u, 0, 0, 7u, 0xDEADull) == 0) return -1;
        if (rs_atomic_result(0) != 1000u) bad++;
        uart_printf("rshort: [5] CAS 成功 x1000 + 失敗 x1: 元値の食い違い %u %s\n", bad, bad ? "NG" : "OK");
        ng |= (bad != 0);
    }
    /* [6] 結果を RDMA READ でも見る(相手のメモリはホスト順 = LE)。 */
    uint8_t words[16];
    {
        if (rs_one(RS_OP_READ, 16, RSHORT_ATOMIC_OFF, 0, 2, 0, 0) == 0) return -1;
        memcpy(words, &s_lbuf[128], 16);
        uint64_t w0v, w1v;
        memcpy(&w0v, &words[0], 8);
        memcpy(&w1v, &words[8], 8);
        const int bad = (w0v != 1000ull + 0x100000000ull) || (w1v != 1000u);
        uart_printf("rshort: [6] 語0=%llu(期待 %llu) 語1=%llu(期待 1000) %s\n",
                    (unsigned long long)w0v, 1000ull + 0x100000000ull, (unsigned long long)w1v,
                    bad ? "NG" : "OK");
        ng |= bad;
    }

    /* [7] 1〜32B の CAS(拡張 atomic)。長さごとに 32B 境界をまたがない半端な位置へ、
     *     (a) 外れる比較値 -> 変わらないこと、(b) 当たる比較値 -> 置き換わること。 */
    {
        uint32_t bad = 0, sizes_used = 0;
        for (uint32_t len = 1; len <= RSHORT_MAX_LEN; len++) {
            const uint32_t off = 2560u + (len - 1u) * 32u + (len * 5u) % (33u - len);
            uint8_t cmp[32], swp[32], old[32];
            const uint32_t S = rs_masked_size(off, len);
            sizes_used |= S;
            memcpy(cmp, &s_model[off], len);
            cmp[len - 1u] ^= 0x5Au;                     /* 外れ */
            for (uint32_t j = 0; j < len; j++) swp[j] = (uint8_t)(0x3Cu + len * 7u + j);
            int r = rs_mcas(off, len, cmp, swp, old, 0);
            if (r != 0 || memcmp(old, &s_model[off], len) != 0) bad++;
            cmp[len - 1u] ^= 0x5Au;                     /* 当たり */
            r = rs_mcas(off, len, cmp, swp, old, 0);
            if (r != 1 || memcmp(old, &s_model[off], len) != 0) bad++;
            memcpy(&s_model[off], swp, len);
        }
        uart_printf("rshort: [7] CAS 1〜32B(外れ + 当たり、使った大きさ 0x%02x): 食い違い %u %s\n",
                    sizes_used, bad, bad ? "NG" : "OK");
        ng |= (bad != 0);
    }
    /* [8] 1〜8B の FAA(LE 整数、欄の幅で折り返す)。最大値近くから足して
     *     折り返しも通す。欄の外(隣のバイト)へ桁上がりしないこと。 */
    {
        uint32_t bad = 0;
        for (uint32_t len = 1; len <= 8u; len++) {
            const uint32_t off = 3584u + (len - 1u) * 16u + (len * 3u) % (9u - len);
            const uint64_t fmask = (len == 8u) ? ~0ull : ((1ull << (8u * len)) - 1u);
            static const uint64_t adds[] = { 1u, 0x7Fu, 0xFFFFFFFFFFFFFFFFull, 0x123456789ull, 3u };
            for (unsigned k = 0; k < sizeof(adds) / sizeof(adds[0]); k++) {
                uint64_t cur = 0, old = 0;
                for (uint32_t j = 0; j < len; j++) cur |= (uint64_t)s_model[off + j] << (8u * j);
                if (rs_mfaa(off, len, adds[k], &old, 0) != 0) return -1;
                if (old != cur) bad++;
                const uint64_t nv = (cur + adds[k]) & fmask;
                for (uint32_t j = 0; j < len; j++) s_model[off + j] = (uint8_t)(nv >> (8u * j));
            }
        }
        uart_printf("rshort: [8] FAA 1〜8B x 5 回(折り返しを含む): 元値の食い違い %u %s\n",
                    bad, bad ? "NG" : "OK");
        ng |= (bad != 0);
    }
    /* [9] 16B / 32B の多レーン FAA(8B の LE 整数を 2 / 4 本同時に)。 */
    {
        uint32_t bad = 0;
        static const uint32_t offs[2] = { 3712u, 3744u };
        for (unsigned t = 0; t < 2u; t++) {
            const uint32_t S = t ? 32u : 16u;
            for (unsigned k = 0; k < 3u; k++) {
                uint64_t add[4], old[4], cur[4];
                for (uint32_t l = 0; l < S / 8u; l++) {
                    add[l] = (k == 1u) ? ~0ull - l : (0x1000u * (l + 1u) + k);
                    memcpy(&cur[l], &s_model[offs[t] + l * 8u], 8);
                }
                if (rs_mfaa_lanes(offs[t], S, add, old, 0) != 0) return -1;
                for (uint32_t l = 0; l < S / 8u; l++) {
                    if (old[l] != cur[l]) bad++;
                    const uint64_t nv = cur[l] + add[l];
                    memcpy(&s_model[offs[t] + l * 8u], &nv, 8);
                }
            }
        }
        uart_printf("rshort: [9] 多レーン FAA 16B / 32B x 3 回: 元値の食い違い %u %s\n",
                    bad, bad ? "NG" : "OK");
        ng |= (bad != 0);
    }
    ng |= (rs_check_region("7-9") != 0);

    /* 相手側の hash と照合するための値: データ領域 4096B + atomic 語 2 個(LE)。 */
    uint64_t h = 0xcbf29ce484222325ull;
    h = rs_fnv(h, s_model, RSHORT_DATA_BYTES);
    uint8_t exp_words[16];
    {
        const uint64_t a = 1000ull + 0x100000000ull, b = 1000u;
        memcpy(&exp_words[0], &a, 8);
        memcpy(&exp_words[8], &b, 8);
    }
    h = rs_fnv(h, exp_words, 16);
    uart_printf("rshort: [10] 期待 hash = %016llx(相手側で `kill -USR1` すると相手のメモリの "
                "hash が出る。一致すれば相手のメモリそのものが正しい)\n", (unsigned long long)h);
    rs_sync_back();
    uart_printf("rshort: verify %s\n", ng ? "NG" : "すべて OK");
    return ng ? -1 : 0;
}

/* ------------------------------------------------------------------ */

static int rs_parse_op(const char *s, rs_op_t *op) {
    if (!s) return -1;
    if (!strcmp(s, "w") || !strcmp(s, "write")) { *op = RS_OP_WRITE; return 0; }
    if (!strcmp(s, "r") || !strcmp(s, "read"))  { *op = RS_OP_READ;  return 0; }
    if (!strcmp(s, "cas"))                     { *op = RS_OP_CAS;   return 0; }
    if (!strcmp(s, "faa"))                     { *op = RS_OP_FAA;   return 0; }
    if (!strcmp(s, "mcas"))                    { *op = RS_OP_MCAS;  return 0; }
    if (!strcmp(s, "mfaa"))                    { *op = RS_OP_MFAA;  return 0; }
    return -1;
}

static void rs_help(void) {
    uart_printf(
        "rshort -- 1〜32B の短い RDMA(write / read / cas / faa)\n"
        "  rshort connect <ip> <mac> [port] [pf0|pf1]   相手は tools/rdma_short_peer(既定 port %u, pf1)\n"
        "  rshort disconnect                            CM の DREQ で畳む\n"
        "  rshort caps                                  この HCA の atomic 能力\n"
        "  rshort verify                                正しさの検査(接続直後に)\n"
        "  rshort lat <op> <len> [回数]                 qd=1 のレイテンシ\n"
        "  rshort bw  <op> <len> <qd> [ms]              スループット\n"
        "    op: w | r | cas | faa(8B 固定)| mcas(1〜32B)| mfaa(1〜8B / 16 / 32B)\n"
        "  rshort xprobe                                拡張 atomic の形式を実機で確かめる\n"
        "  rshort sweep [回数]                          lat を全種類・代表長で\n"
        "  rshort opt [inline|mfence|spread|bf|scqe on|off] [sig N]   scqe は次の connect から\n"
        "  rshort bfprobe                               BlueFlame が NIC に使われているか\n"
        "  rshort use pf0|pf1                           単独の操作をどちらの接続に向けるか\n"
        "  rshort bw2 <op> <len> <qd> [ms] [pf0|pf1|both]   2 ポートへ交互に投稿(qd はポートごと)\n"
        "    op: w | r | cas | faa。使うポートを両方 connect しておく\n",
        RSHORT_DEFAULT_PORT);
}

/*=================================================================
 * シェルの入口(`rshort ...`)。
 * ===============================================================*/
void rdma_short_shell(const char *args, mlx5_dev_t *dev0, mlx5_dev_t *dev1) {
    char buf[256];
    strncpy(buf, args ? args : "", sizeof(buf) - 1u);
    buf[sizeof(buf) - 1u] = 0;
    char *tok[8];
    unsigned nt = 0;
    char *save = 0;
    for (char *p = strtok_r(buf, " \t\r\n", &save); p && nt < 8u; p = strtok_r(0, " \t\r\n", &save)) {
        tok[nt++] = p;
    }
    if (nt == 0) {
        if (s_rs.connected) {
            uart_printf("rshort: 接続中 qpn=%u peer=%u.%u.%u.%u MR 0x%llx rkey 0x%08x  "
                        "opt inline=%d mfence=%d spread=%d sig=%u\n",
                        s_rs.cm.rc_qp.qpn, s_rs.cm.peer_ip >> 24, (s_rs.cm.peer_ip >> 16) & 0xFFu,
                        (s_rs.cm.peer_ip >> 8) & 0xFFu, s_rs.cm.peer_ip & 0xFFu,
                        (unsigned long long)s_rs.raddr, s_rs.rkey,
                        s_opt_inline, s_opt_mfence, s_opt_spread, s_opt_sig);
        } else {
            uart_printf("rshort: 未接続\n");
        }
        rs_help();
        return;
    }
    const char *cmd = tok[0];

    if (!strcmp(cmd, "connect")) {
        uint32_t ip;
        uint8_t mac[6];
        if (nt < 3 || rs_parse_ip(tok[1], &ip) != 0 || rs_parse_mac(tok[2], mac) != 0) {
            rs_help();
            return;
        }
        uint16_t port = RSHORT_DEFAULT_PORT;
        int pf = 1;
        for (unsigned i = 3; i < nt; i++) {
            if (!strcmp(tok[i], "pf0")) pf = 0;
            else if (!strcmp(tok[i], "pf1")) pf = 1;
            else port = (uint16_t)atoi(tok[i]);
        }
        s_cur = &s_rsv[pf];
        if (s_rs.cm.rc_qp.in_use) rs_disconnect();
        rs_connect(pf ? dev1 : dev0, pf, ip, mac, port);
        return;
    }
    if (!strcmp(cmd, "disconnect")) {
        /* 引数無しなら張ってあるほう全部。 */
        rs_conn_t *const keep = s_cur;
        for (int pf = 0; pf < 2; pf++) {
            if (nt >= 2 && strcmp(tok[1], pf ? "pf1" : "pf0") != 0) continue;
            s_cur = &s_rsv[pf];
            if (nt >= 2 || s_rs.cm.rc_qp.in_use || s_rs.connected) rs_disconnect();
        }
        s_cur = keep;
        return;
    }
    if (!strcmp(cmd, "use")) {
        if (nt >= 2) s_cur = &s_rsv[!strcmp(tok[1], "pf0") ? 0 : 1];
        uart_printf("rshort: 単独の操作は PF%d の接続に対して行う(%s)\n",
                    (int)(s_cur - s_rsv), s_rs.connected ? "接続中" : "未接続");
        return;
    }
    if (!strcmp(cmd, "bw2")) {
        rs_op_t op;
        if (nt < 4 || rs_parse_op(tok[1], &op) != 0 ||
            (op != RS_OP_WRITE && op != RS_OP_READ && op != RS_OP_CAS && op != RS_OP_FAA)) {
            rs_help();
            return;
        }
        uint32_t len = (uint32_t)atoi(tok[2]);
        {
            const char *q = tok[2];
            while (*q >= '0' && *q <= '9') q++;
            if (*q == 'k' || *q == 'K') len *= 1024u;
        }
        if (op == RS_OP_CAS || op == RS_OP_FAA) len = 8;
        const uint32_t maxlen = (op == RS_OP_READ) ? RS_READ_MAX : RSHORT_MAX_LEN;
        if (len < 1u || len > maxlen) {
            uart_printf("rshort: 長さは 1〜%u\n", maxlen);
            return;
        }
        const uint32_t qd = (uint32_t)atoi(tok[3]);
        const uint32_t ms = (nt >= 5) ? (uint32_t)atoi(tok[4]) : 3000u;
        uint32_t mask = 3u;
        if (nt >= 6) mask = !strcmp(tok[5], "pf0") ? 1u : !strcmp(tok[5], "pf1") ? 2u : 3u;
        rs_bw_multi(op, len, qd, ms, mask);
        return;
    }
    if (!strcmp(cmd, "caps")) {
        mlx5_atomic_caps_t c;
        for (int pf = 0; pf < 2; pf++) {
            mlx5_dev_t *d = pf ? dev1 : dev0;
            if (mlx5_query_atomic_caps(d, &c) != 0) {
                uart_printf("rshort: PF%d: QUERY_HCA_CAP(atomic) 失敗\n", pf);
                continue;
            }
            uart_printf("rshort: PF%d atomic: operations=0x%04x(CS=%u FA=%u 拡張CS=%u 拡張FA=%u) "
                        "size_qp=0x%04x endianness_mode=%u(mode1 対応=%u) "
                        "log_max_ra_req=%u log_max_ra_res=%u\n",
                        pf, c.operations, c.operations & 1u, (c.operations >> 1) & 1u,
                        (c.operations >> 2) & 1u, (c.operations >> 3) & 1u, c.size_qp,
                        c.req_endianness_mode, c.supported_endianness_mode_1,
                        d->log_max_ra_req_qp, d->log_max_ra_res_qp);
        }
        return;
    }
    if (!strcmp(cmd, "opt")) {
        for (unsigned i = 1; i + 1 < nt; i += 2) {
            const int on = !strcmp(tok[i + 1], "on");
            if (!strcmp(tok[i], "inline")) s_opt_inline = !strcmp(tok[i + 1], "auto") ? 2 : on;
            else if (!strcmp(tok[i], "mfence")) s_opt_mfence = on;
            else if (!strcmp(tok[i], "spread")) s_opt_spread = on;
            else if (!strcmp(tok[i], "bf")) s_opt_bf = on;
            else if (!strcmp(tok[i], "scqe")) s_opt_scqe = on;
            else if (!strcmp(tok[i], "sig")) s_opt_sig = (uint32_t)atoi(tok[i + 1]);
        }
        uart_printf("rshort: opt scqe=%d(次の connect から。いまの接続 cs_req=0x%02x)\n",
                    s_opt_scqe, s_rs.cs_req);
        uart_printf("rshort: opt inline=%d mfence=%d spread=%d bf=%d%s sig=%u(0=自動)\n",
                    s_opt_inline, s_opt_mfence, s_opt_spread, s_opt_bf,
                    s_rs.bf_page ? "" : "(WC マップ無し)", s_opt_sig);
        return;
    }

    if (!s_rs.connected) {
        uart_printf("rshort: 未接続(rshort connect <ip> <mac>)\n");
        return;
    }
    if (!strcmp(cmd, "verify")) {
        rs_verify();
        return;
    }
    if (!strcmp(cmd, "bfprobe")) {
        rs_bf_probe();
        return;
    }
    if (!strcmp(cmd, "xprobe")) {
        rs_xprobe();
        return;
    }
    if (!strcmp(cmd, "lat") || !strcmp(cmd, "bw")) {
        rs_op_t op;
        if (nt < 3 || rs_parse_op(tok[1], &op) != 0) { rs_help(); return; }
        uint32_t len = (uint32_t)atoi(tok[2]);
        {   /* 1k / 64k のような k 付きも受ける */
            const char *q = tok[2];
            while (*q >= '0' && *q <= '9') q++;
            if (*q == 'k' || *q == 'K') len *= 1024u;
        }
        if (op == RS_OP_CAS || op == RS_OP_FAA) len = 8;
        /* read だけは 64KB まで(BlueFlame / scatter to CQE の効き方を長さで比べるため)。 */
        const uint32_t maxlen = (op == RS_OP_READ && s_rs.big_iova) ? RS_READ_MAX : RSHORT_MAX_LEN;
        if (len < 1u || len > maxlen || (op == RS_OP_READ && len + 4096u > s_rs.rlen)) {
            uart_printf("rshort: 長さは 1〜%u(read は %u まで)\n", RSHORT_MAX_LEN, maxlen);
            return;
        }
        if (op == RS_OP_MFAA && len > 8u && len != 16u && len != 32u) {
            uart_printf("rshort: mfaa の長さは 1〜8(LE 整数)か 16 / 32(8B レーンの同時加算)\n");
            return;
        }
        if ((op == RS_OP_CAS || op == RS_OP_FAA) && !s_rs.res_known) {
            /* 元値のバイト順を一度だけ確かめておく(verify の [3] と同じ)。 */
            if (rs_one(RS_OP_FAA, 8, RSHORT_PROBE_OFF, 0, 0, 0, 0) == 0) return;
            s_rs.res_be = (s_lbuf[0] == 0x01);
            s_rs.res_known = 1;
        }
        if (!strcmp(cmd, "lat")) {
            uint32_t iters = (nt >= 4) ? (uint32_t)atoi(tok[3]) : 100000u;
            if (iters == 0) iters = 1;
            rs_lat(op, len, iters, 0, 0, 0);
        } else {
            if (nt < 4) { rs_help(); return; }
            uint32_t qd = (uint32_t)atoi(tok[3]);
            uint32_t ms = (nt >= 5) ? (uint32_t)atoi(tok[4]) : 3000u;
            rs_bw(op, len, qd, ms, 0, 0);
        }
        return;
    }
    if (!strcmp(cmd, "sweep")) {
        uint32_t iters = (nt >= 2) ? (uint32_t)atoi(tok[1]) : 50000u;
        static const uint32_t lens[] = { 1, 2, 4, 8, 16, 24, 28, 29, 32 };
        uart_printf("rshort sweep(qd=1、%u 回、単位 ns、p50 / avg)\n", iters);
        uart_printf("  len    write          read\n");
        for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            uint32_t wp, wa, rp, ra;
            if (rs_lat(RS_OP_WRITE, lens[i], iters, 1, &wp, &wa) != 0) return;
            if (rs_lat(RS_OP_READ, lens[i], iters, 1, &rp, &ra) != 0) return;
            uart_printf("  %2u   %5u / %5u   %5u / %5u\n", lens[i], wp, wa, rp, ra);
        }
        uint32_t cp, ca, fp, fa;
        if (!s_rs.res_known) {
            if (rs_one(RS_OP_FAA, 8, RSHORT_PROBE_OFF, 0, 0, 0, 0) == 0) return;
            s_rs.res_be = (s_lbuf[0] == 0x01);
            s_rs.res_known = 1;
        }
        if (rs_lat(RS_OP_CAS, 8, iters, 1, &cp, &ca) != 0) return;
        if (rs_lat(RS_OP_FAA, 8, iters, 1, &fp, &fa) != 0) return;
        uart_printf("  cas 8B %5u / %5u   faa 8B %5u / %5u\n", cp, ca, fp, fa);
        static const uint32_t xlens[] = { 1, 2, 4, 8, 16, 32 };
        uart_printf("  len    mcas           mfaa(16/32 は 8B レーン同時加算)\n");
        for (unsigned i = 0; i < sizeof(xlens) / sizeof(xlens[0]); i++) {
            uint32_t mp, ma, fp2, fa2;
            if (rs_lat(RS_OP_MCAS, xlens[i], iters, 1, &mp, &ma) != 0) return;
            if (rs_lat(RS_OP_MFAA, xlens[i], iters, 1, &fp2, &fa2) != 0) return;
            uart_printf("  %2u   %5u / %5u   %5u / %5u\n", xlens[i], mp, ma, fp2, fa2);
        }
        return;
    }
    rs_help();
}
