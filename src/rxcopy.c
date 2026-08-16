#include "rxcopy.h"
#include "net.h"        /* volatile_fast_copy */
#include "smp.h"        /* smp_boot_core1 */
#include "uart.h"

/* SPSC リング(生産=コピー依頼、消費=コピー実行)。要素数は2の冪。
 * 3コア化: 消費者はコピー専任のcore2(smp.cのsecondary_main()のcore2分岐、
 * rxcopy_worker_drain())。生産者はtarget本体を回すコア(loopbackなら
 * core1、real-host manualならcore0)。SPSC=単一生産者・単一消費者の前提は
 * 変わらない(targetは常に単一コア上で1本のジョブとして受信処理する)。 */
#define RXCOPY_RING 512u
_Static_assert((RXCOPY_RING & (RXCOPY_RING - 1u)) == 0u, "RXCOPY_RING must be power of two");

typedef struct {
    const volatile uint8_t *src;
    volatile uint8_t       *dst;
    uint32_t                len;
} rxcopy_job_t;

/* .bss(Normal cacheable、コア間コヒーレント)。 */
static rxcopy_job_t      s_ring[RXCOPY_RING];
static volatile uint32_t s_head;   /* 生産者(core0)が公開する投入総数。consumerはacquireで読む */
static volatile uint32_t s_done;   /* 消費者(core1)が公開する完了総数。producerはacquireで読む */
static volatile int      s_enabled;

/* 生産者ローカルの高速コピー(共有ラインを毎回読まないための最適化)。 */
static uint32_t s_head_local;      /* producer専用: 現在の投入数 */
static uint32_t s_done_cache;      /* producer専用: s_doneのキャッシュ(満杯判定用) */

/* store-release / load-acquire(単一命令、dmb ishより桁違いに軽い)。
 * SPSCの発行/消費はこれで十分な順序(データ書き込み→head公開、
 * コピー完了→done公開)を保証する(smp.hのspinlockと同じ流儀)。 */
static inline void store_rel_u32(volatile uint32_t *p, uint32_t v) {
#if defined(__aarch64__)
    __asm__ volatile("stlr %w1, %0" : "=Q"(*p) : "r"(v) : "memory");
#else
    __atomic_store_n(p, v, __ATOMIC_RELEASE); /* x86: C11 release(smp.h と同じ流儀) */
#endif
}
static inline uint32_t load_acq_u32(volatile uint32_t *p) {
#if defined(__aarch64__)
    uint32_t v;
    __asm__ volatile("ldar %w0, %1" : "=r"(v) : "Q"(*p) : "memory");
    return v;
#else
    return __atomic_load_n(p, __ATOMIC_ACQUIRE); /* x86: C11 acquire */
#endif
}

int  rxcopy_enabled(void) { return s_enabled; }

void rxcopy_set_enabled(int on)
{
    if (on) {
        s_head = 0; s_done = 0;
        s_head_local = 0; s_done_cache = 0;
#if defined(__aarch64__)
        __asm__ volatile("dmb ish" ::: "memory");
#else
        __atomic_thread_fence(__ATOMIC_SEQ_CST); /* x86: フルフェンス */
#endif
        s_enabled = 1;
        /* 3コア化: コピー専任のcore2を起動する(core1はtarget本体専任、
         * smp.cのsecondary_main()参照)。core2がrxcopy_worker_drain()を
         * 裏で回す。 */
        if (smp_boot_core2() != 0) {
            uart_printf("[rxcopy] core2 起動に失敗、オフロードを無効化します\n");
            s_enabled = 0;
            return;
        }
        uart_printf("[rxcopy] RXコピーオフロード有効(core2が裏でコピー)\n");
    } else {
        s_enabled = 0;
        uart_printf("[rxcopy] RXコピーオフロード無効(core0が同期コピー)\n");
    }
}

/* producer(core0)から呼ぶ。自分が公開した投入総数(=s_head_local)。 */
uint32_t rxcopy_submitted(void) { return s_head_local; }
uint32_t rxcopy_done(void)      { return load_acq_u32(&s_done); }

uint32_t rxcopy_submit(const volatile uint8_t *src, volatile uint8_t *dst, uint32_t len)
{
    uint32_t h = s_head_local;
    /* 満杯判定はまずキャッシュで。満杯に見えるときだけ共有s_doneを読み直す
     * (共有ラインの読み取り=コヒーレンシ往復を、詰まった時だけに限定する)。 */
    if ((h - s_done_cache) >= RXCOPY_RING) {
        do { s_done_cache = load_acq_u32(&s_done); } while ((h - s_done_cache) >= RXCOPY_RING);
    }
    uint32_t i = h & (RXCOPY_RING - 1u);
    s_ring[i].src = src;
    s_ring[i].dst = dst;
    s_ring[i].len = len;
    h++;
    store_rel_u32(&s_head, h);   /* release: 上のリング書き込みを head 公開より前に可視化 */
    s_head_local = h;
    return h;
}

void rxcopy_worker_drain(void)
{
    if (!s_enabled) return;
    uint32_t done = s_done;                 /* consumer専用の値 */
    uint32_t head = load_acq_u32(&s_head);  /* acquire: head以降のリング内容を読める */
    while (done != head) {
        rxcopy_job_t *j = &s_ring[done & (RXCOPY_RING - 1u)];
        volatile_fast_copy(j->dst, j->src, j->len);
        done++;
        store_rel_u32(&s_done, done);        /* release: コピーのストアを done 公開より前に可視化 */
        head = load_acq_u32(&s_head);        /* 追加投入分も続けて処理 */
    }
}
