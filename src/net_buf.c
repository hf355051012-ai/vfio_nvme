// net_buf.c
//
// malloc無し環境向け固定サイズパケットバッファプール。
// 空き管理は NET_BUF_COUNT が小さい(net_buf.h参照)ため、各スロットの
// 使用中/空きフラグを配列で持つ単純な方式で十分。

#include <stddef.h>
#include "net_buf.h"
#include "smp.h"

// RXリング専用バッファ(eth.cのs_rx_ring_bufs、GEMのDMAが直接読み書き
// する実体)はここには含まれない -- 別の専用配列として.dma_bssへ配置
// されている(eth.c参照)。このプールは受信後のコピー先「out」バッファ
// (eth_poll_recv())やARP/ICMP等の短命な送信バッファ専用で、DMAが直接
// 触ることはないため、MMU有効化(mmu.c)後は他の一般RAMと同じくNormal
// cacheableになる -- チェックサム計算等の処理がキャッシュの恩恵を
// 受けられる(~/.claude/plans/glimmering-mapping-waterfall.md参照)。
//
// マルチコア化 Phase 3(~/.claude/plans/wondrous-baking-gadget.md参照):
// 「末端モジュール」としてper-core化した -- コアごとに完全に独立した
// プール(s_pool[core]/s_used[core])を持たせることで、将来core0/core1が
// 別々のTCP/IPスタックインスタンスを並行運用しても(Phase 6でnvmet.c/
// nvme.cをcore1へ割り当てる予定)、ロック無しで安全にnet_buf_alloc()/
// net_buf_free()を呼び合える(同一配列への複数コアからの競合書き込みが
// そもそも起きない設計にする、というper-core化の基本方針)。現状は
// net_buf_alloc()/free()を呼ぶeth.c/arp.c/icmp.c等がまだcore0専用の
// ままなので、smp_core_index()は常に0を返し続け、挙動は従来と完全に
// 同じ(呼び出し側のシグネチャ・挙動を一切変えていない)。
static net_buf_t s_pool[SMP_MAX_CORES][NET_BUF_COUNT];
static uint8_t   s_used[SMP_MAX_CORES][NET_BUF_COUNT];

net_buf_t *net_buf_alloc(void)
{
    unsigned core = smp_core_index();
    for (unsigned i = 0; i < NET_BUF_COUNT; i++) {
        if (!s_used[core][i]) {
            s_used[core][i] = 1;
            s_pool[core][i].len = 0;
            /* 受信ゼロコピー対応(net_buf.h参照): dataを実体storageへ向け直す
             * (mlx5受信でdataをRQバッファへ差し替えたnet_bufが返却・再確保
             * された場合でも、確保時に必ずstorageを指す既定状態へ戻す)。 */
            s_pool[core][i].data = s_pool[core][i].storage;
            return &s_pool[core][i];
        }
    }
    return NULL;
}

void net_buf_free(net_buf_t *buf)
{
    if (!buf) return;

    /* buf が「解放を呼んだコア自身の」プール内のどのスロットかを
     * ポインタ演算で特定する -- 割り当てたコアと同じコアが解放する
     * 設計(コアをまたいでnet_buf_tを受け渡すことは想定しない、
     * per-coreスタック分離の前提そのもの)。他コアのプールに属する
     * ポインタが誤って渡された場合、offsetの引き算がuintptr_tの
     * 範囲で大きく外れた値になり、下のidx<NET_BUF_COUNTチェックで
     * 確実に弾かれる(以前のプール外ポインタ検出と同じ安全策)。 */
    unsigned core = smp_core_index();
    uintptr_t offset = (uintptr_t)buf - (uintptr_t)s_pool[core];
    uintptr_t idx = offset / sizeof(net_buf_t);
    if (idx < NET_BUF_COUNT) s_used[core][idx] = 0;
}
