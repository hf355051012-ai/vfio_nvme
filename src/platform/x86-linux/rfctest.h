#ifndef RFCTEST_H
#define RFCTEST_H

#include <stdint.h>
#include "netif.h"

/* シェルの `rfctest <層> [引数]`。RFC に合わせて直した動きを、層ごとに確かめる。
 * 各関数は自分のファイル(rfctest_<層>.c)にあり、結果を「rfctest <層>: PASS / NG」で出す。 */
void rfctest_tcp(const char *args);
void rfctest_ipv6(const char *args);
void rfctest_sec(const char *args);
void rfctest_iscsi(const char *args);
void rfctest_ipv4(const char *args);

/* 対向 PF(同じリンクのもう一方のインターフェース)を返し、peer_ll にそのリンク
 * ローカルを入れる。見つからなければ NULL。main.c の shell_peer_ll6() と同じ。 */
netif_t *rfctest_peer(uint8_t peer_ll[16]);

#endif /* RFCTEST_H */
