#ifndef PMTU_H
#define PMTU_H

#include <stdint.h>
#include "netaddr.h"

/* 経路 MTU の記憶(Path MTU Discovery、RFC 1191 / RFC 8201)。
 *
 * **宛先ごとに持つ。** 計画は「近隣キャッシュと同じ粒度で良い」としていたが、
 * A1 でゲートウェイ経路を入れた結果、近隣キャッシュのキーは**次ホップ**に
 * なっている。PMTU は経路の性質なので、サブネット外の宛先が全部 1 つの
 * ゲートウェイのエントリを共有してしまい、別々の経路の PMTU が混ざる。
 * だから netaddr_t(宛先)をキーにした専用の表にしてある。 */

#define PMTU_CACHE_SIZE 8u

/* 報告された MTU の下限。これより小さい値は採用しない。壊れた/悪意ある
 * ICMP で MSS を潰されないための床でもある。
 *  - IPv4: RFC 1191 の絶対下限は 68 だが、実用上は 576(RFC 791 の
 *    「全ホストが受け取れる最小」)を下限にしておく。
 *  - IPv6: RFC 8201 のとおり 1280。これ未満は仕様違反なので受け付けない。 */
#define PMTU_MIN_V4 576u
#define PMTU_MIN_V6 1280u

/* 学習した値の寿命。RFC 1191 6.3 は「10 分ほどで元の MTU を試し直す」ことを
 * 推奨している(経路が変わって大きく送れるようになる場合があるため)。
 * PMTU 自体は下げる方向にしか動かさず、上げ直しはこの満了に任せる。 */
#define PMTU_TTL_MS (10u * 60u * 1000u)

/* ICMP Fragmentation Needed / ICMPv6 Packet Too Big を受けたときに呼ぶ。
 * 床を下回る値や、既に学習済みの値より大きい報告は無視する。採用したときは
 * **確立済み TCP コネクションの snd_mss も同時に切り下げる**
 * (tcp_pmtu_update()。学習と適用が離れて片方だけ忘れるのを防ぐため、
 * ここから呼ぶ形にしてある)。
 * 戻り値: 1=採用した、0=採用しなかった */
int pmtu_learn(const netaddr_t *dst, uint32_t reported_mtu);

/* 宛先の学習済み PMTU。0=未学習または寿命切れ。 */
uint16_t pmtu_lookup(const netaddr_t *dst);

/* 全エントリを破棄する(`pmtutest` の後始末用)。**コネクションの snd_mss は
 * 戻らない** ので、既存セッションは張り直しが要る。 */
void pmtu_clear(void);

/* 学習済みエントリを一覧表示する。 */
void pmtu_dump(void);

#endif /* PMTU_H */
