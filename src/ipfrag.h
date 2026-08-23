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

/* 同時に組み立てられるデータグラムの数(コアごと)。実際に必要なのは
 * 1〜2 個で、4 個あれば「別の相手からの断片が同時に来ても片方を捨てない」。 */
#define IPFRAG_CTX_MAX 4u

/* 組み立てを諦めるまでの時間。RFC 791 は 15〜60 秒、Linux は IPv4 で 30 秒。
 * **経過の判定はポーリングではなく「次の断片が来たとき」に行う**(この層に
 * 定期実行の入口が無いため)。 */
#define IPFRAG_TIMEOUT_MS 30000u

/*=================================================================
 * 断片を 1 つ渡す。全部そろったら 1 を返し、out_data/out_len に再構成後の
 * 「上位プロトコルのペイロード」を返す。
 *
 * 引数:
 *   src / dst  - L3 の送信元・宛先(鍵の一部)
 *   id         - 識別子(IPv4 は 16bit、IPv6 は 32bit)
 *   protocol   - 上位プロトコル番号(鍵の一部。IPv6 では Fragment ヘッダの
 *                next header)
 *   frag_off   - この断片の先頭オフセット(バイト。8 の倍数)
 *   more       - 後続がある(MF / M フラグ)
 *   data / len - この断片が運ぶバイト列
 *   out_data / out_len - 完成したデータグラム(1 を返したときだけ有効)
 * 戻り値:
 *   1=完成した、0=まだ / 捨てた
 * ===============================================================*/
int ipfrag_input(const netaddr_t *src, const netaddr_t *dst,
                 uint32_t id, uint8_t protocol,
                 uint32_t frag_off, int more,
                 const volatile uint8_t *data, uint32_t len,
                 const uint8_t **out_data, uint32_t *out_len);

/* 統計(シェルの `fragstat` 表示用)。NULL 可。 */
void ipfrag_stats(uint32_t *completed, uint32_t *dropped, uint32_t *timeouts,
                  uint32_t *active);

/* 組み立て中のものを全部捨てる(テストの後始末用)。 */
void ipfrag_reset(void);

#endif /* IPFRAG_H */
