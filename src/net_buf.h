#ifndef NET_BUF_H
#define NET_BUF_H

#include <stdint.h>

#define NET_BUF_SIZE   10240u
#define NET_BUF_COUNT  40u

typedef struct net_buf {
    uint8_t  storage[NET_BUF_SIZE];
    uint8_t *data;
    uint16_t len;   /* data[0..len) が有効なフレーム内容 (呼び出し側が設定/参照) */
    uint8_t  hw_csum_ok;
} __attribute__((aligned(64))) net_buf_t;

net_buf_t *net_buf_alloc(void);

void net_buf_free(net_buf_t *buf);

#endif /* NET_BUF_H */
