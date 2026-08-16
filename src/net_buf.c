#include <stddef.h>
#include "net_buf.h"
#include "smp.h"

static net_buf_t s_pool[SMP_MAX_CORES][NET_BUF_COUNT];
static uint8_t   s_used[SMP_MAX_CORES][NET_BUF_COUNT];

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

void net_buf_free(net_buf_t *buf)
{
    if (!buf) return;

    unsigned core = smp_core_index();
    uintptr_t offset = (uintptr_t)buf - (uintptr_t)s_pool[core];
    uintptr_t idx = offset / sizeof(net_buf_t);
    if (idx < NET_BUF_COUNT) s_used[core][idx] = 0;
}
