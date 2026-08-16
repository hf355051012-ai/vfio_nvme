#include <stddef.h>
#include "net_buf.h"
#include "smp.h"

static net_buf_t s_pool[SMP_MAX_CORES][NET_BUF_COUNT];
static uint8_t   s_used[SMP_MAX_CORES][NET_BUF_COUNT];

/*=================================================================
 * 呼び出しコア専用のプールから net_buf を1つ確保する(線形探索)。
 * data は自身の storage を指すようリセットされる。
 *
 * 戻り値:
 *   確保できた net_buf。プール枯渇なら NULL
 * コール元:
 *   arp_handle_frame(), arp_send_request(), ip_prepare_send_buf(),
 *   mlx5_net_poll_recv()
 * ===============================================================*/
net_buf_t *net_buf_alloc(void)
{
    unsigned core = smp_core_index();
    for (unsigned i = 0; i < NET_BUF_COUNT; i++) {
        if (!s_used[core][i]) {
            s_used[core][i] = 1;
            s_pool[core][i].len = 0;
            s_pool[core][i].data = s_pool[core][i].storage;
            return &s_pool[core][i];
        }
    }
    return NULL;
}

/*=================================================================
 * net_buf をプールへ返す。ポインタからインデックスを逆算するだけなので、
 * 確保したのと同じコアから呼ぶこと。
 *
 * 引数:
 *   buf - 返す net_buf(NULL 可)
 * コール元:
 *   eth_send(), net_poll_all_and_dispatch()
 * ===============================================================*/
void net_buf_free(net_buf_t *buf)
{
    if (!buf) return;

    unsigned core = smp_core_index();
    uintptr_t offset = (uintptr_t)buf - (uintptr_t)s_pool[core];
    uintptr_t idx = offset / sizeof(net_buf_t);
    if (idx < NET_BUF_COUNT) s_used[core][idx] = 0;
}
