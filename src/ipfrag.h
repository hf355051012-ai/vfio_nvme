#ifndef IPFRAG_H
#define IPFRAG_H

#include <stdint.h>
#include "netaddr.h"

/* 受信側の IP 断片再構成(IPv4 の RFC 791 / IPv6 の RFC 8200 4.5 共通)。
 *
 * **v4 と v6 で違うのは「断片情報をどこに載せるか」だけ**で、組み立ての
 * 手順は同じなので 1 つの表で扱う。鍵は (送信元, 宛先, 識別子, プロトコル)。
 *
 * 送信側の分割は ip.c / ipv6.c に既にあり(段階 8 = A4 と 14 = B4)、
 * こちらは長らく「断片が来たら捨てる」だった。捨てていると、**断片化して
 * 送ってくる相手からの UDP/ICMP が一切届かない**(TCP は MSS を正しく
 * 交換していれば断片化されないので影響を受けない)。 */

/* 再構成できるデータグラムの最大長。IPv4 の total_length の上限と同じ。 */
#define IPFRAG_MAX_LEN 65535u

/* 組み立て中のデータを置く領域。**数ではなくメモリの量で抑える**
 * (Linux の net.ipv4.ipfrag_high_thresh と同じ 4MB)。データは 4KB の
 * ページ単位で、届いた位置のページだけを使う。小さいデータグラムなら
 * 何百個でも同時に組み立てられ、64KB 近いものでも 60 個ほど持てる。 */
#define IPFRAG_PAGE_BYTES 4096u
#define IPFRAG_POOL_BYTES (4u * 1024u * 1024u)

/* 組み立てを諦めるまでの時間。RFC 8200 4.5 は IPv6 で 60 秒、RFC 1122 3.3.2 は
 * IPv4 で 60〜120 秒を勧める。両方を満たす 60 秒にしてある。
 * **経過の判定はポーリングではなく「次の断片が来たとき」に行う**(この層に
 * 定期実行の入口が無いため)。 */
#define IPFRAG_TIMEOUT_MS 60000u

/* 時間切れで ICMP Time Exceeded(code 1)を返すために、先頭の断片の頭を控える長さ。
 * IPv4 は IP ヘッダ(最大 60)+ 8、IPv6 は入る限り(RFC 4443)だが 128 で足りる。 */
#define IPFRAG_HEAD_SAVE 128u

/* 使ってよい量の上限(バイト)。既定は IPFRAG_POOL_BYTES。シェルの
 * `fraglimit` で下げられる(上げられるのは IPFRAG_POOL_BYTES まで)。
 * **上限を超えている間は新しいデータグラムの組み立てを始めない**
 * (組み立て中のものには断片を受け付け続ける。Linux と同じ)。 */
extern volatile uint32_t g_ipfrag_mem_limit;

/*=================================================================
 * 断片を 1 つ渡す。全部そろったら 1 を返し、out_data/out_len に再構成後の
 * 「上位プロトコルのペイロード」を返す。
 *
 * **IPv4 と IPv6 で規則が 3 つ違う**(src->family で分ける):
 *  - 鍵:IPv4 は (送信元, 宛先, 識別子, プロトコル)、IPv6 は (送信元, 宛先, 識別子)
 *    (RFC 8200 4.5。Next Header は断片ごとに違ってよく、使うのはオフセット 0 の
 *    断片のもの。out_proto で返す)。
 *  - 重なり:IPv4 は先に来たほうを残す。IPv6 は重なりを 1 つでも見つけたら
 *    組み立てごと捨てる(RFC 5722 の MUST。まったく同じ断片の再送は、その断片
 *    だけ捨てる)。
 *  - 時間切れの ICMP:IPv4 は ICMP、IPv6 は ICMPv6 の Time Exceeded code 1。
 *
 * 引数:
 *   src / dst  - L3 の送信元・宛先(鍵の一部)
 *   id         - 識別子(IPv4 は 16bit、IPv6 は 32bit)
 *   protocol   - IPv4 はプロトコル番号、IPv6 はこの断片の Fragment ヘッダの next header
 *   frag_off   - この断片の先頭オフセット(バイト。8 の倍数)
 *   more       - 後続がある(MF / M フラグ)
 *   data / len - この断片が運ぶバイト列
 *   pkt / pkt_len - この断片のパケット(IP ヘッダの先頭から)。オフセット 0 の
 *                断片のとき、時間切れの ICMP に引用するため頭を控える
 *   src_mac    - 送信元 MAC(同上、ICMP の宛先)
 *   out_data / out_len - 完成したデータグラム(1 を返したときだけ有効。
 *                呼んだコアの作業領域を指し、そのコアの次の完成まで有効)
 *   out_proto  - NULL 可。完成したデータグラムの上位プロトコル(オフセット 0 の
 *                断片の protocol)
 * 戻り値:
 *   1=完成した、0=まだ / 捨てた
 * ===============================================================*/
int ipfrag_input(const netaddr_t *src, const netaddr_t *dst,
                 uint32_t id, uint8_t protocol,
                 uint32_t frag_off, int more,
                 const volatile uint8_t *data, uint32_t len,
                 const uint8_t *pkt, uint32_t pkt_len, const uint8_t *src_mac,
                 const uint8_t **out_data, uint32_t *out_len, uint8_t *out_proto);

/* 統計(シェルの `fragstat` 表示用)。NULL 可。 */
void ipfrag_stats(uint32_t *completed, uint32_t *dropped, uint32_t *timeouts,
                  uint32_t *active);

/* メモリの使用量(バイト)・使用量の最大・上限超えで断った数。NULL 可。 */
void ipfrag_mem_stats(uint32_t *used, uint32_t *peak, uint32_t *refused);

/* 組み立て中のものを全部捨てる(テストの後始末用)。 */
void ipfrag_reset(void);

#endif /* IPFRAG_H */
