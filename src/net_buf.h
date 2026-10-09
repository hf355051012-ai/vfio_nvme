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
    /* **確保したコア。** プールはコアごとなので、以前は「確保したのと同じ
     * コアから free する」規約だった。**受信フレームを別コアへ渡して処理
     * させる**(マルチコア分散)には、渡した先のコアから free できないと
     * いけないので、所有コアを持たせて free 側がそれを見る。 */
    uint8_t  owner_core;
} __attribute__((aligned(64))) net_buf_t;

net_buf_t *net_buf_alloc(void);

void net_buf_free(net_buf_t *buf);

#endif /* NET_BUF_H */
