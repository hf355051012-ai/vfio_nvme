#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * arp.h — ARP (RFC 826, Ethernet/IPv4) 応答実装 — フェーズ2
 *
 * 自機宛(Target IP == NET_SELF_IP)のARP requestにのみARP replyを
 * 返信する。それ以外(他ホスト宛のARP、gratuitous ARP等)は無視する。
 * ================================================================ */

#define ARP_HTYPE_ETHERNET  1u      /* Hardware type: Ethernet */
#define ARP_PTYPE_IPV4      0x0800u /* Protocol type: IPv4 */
#define ARP_OP_REQUEST      1u
#define ARP_OP_REPLY        2u

/* ARPパケット (Ethernet/IPv4固定, 28バイト)。
 * spa/tpa はネットワークバイトオーダーのIPv4アドレスだが、
 * バイト配列(オクテット単位)で保持するためエンディアン変換は不要。
 * htype/ptype/operは真の16bit数値のため htons/ntohs での変換が必要。 */
typedef struct __attribute__((packed)) {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];  /* Sender Hardware Address */
    uint8_t  spa[4];  /* Sender Protocol Address (IPv4) */
    uint8_t  tha[6];  /* Target Hardware Address */
    uint8_t  tpa[4];  /* Target Protocol Address (IPv4) */
} arp_packet_t;

/* EtherType=0x0806 に対して arp_handle_frame() を登録する。
 * eth_init() 実行後(cmd_ethinitなど)に一度呼び出すこと。 */
void arp_init(void);

/* eth_handler_t のシグネチャに一致するARPフレーム処理本体。
 * Opcode=request かつ Target IP == 自機IP の場合のみARP replyを
 * eth_send()で送信元へ返す。それ以外はログのみで無視する。 */
void arp_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac);

/* target_ip宛にARP request(who-has)をEthernetブロードキャストで送信する。
 * target_ip: ホストバイトオーダーの32bit IPv4アドレス(ip_from_octets()等で構築)。
 * 戻り値: eth_send()の戻り値をそのまま返す(0=成功, -1=失敗) */
int arp_send_request(uint32_t target_ip);

/* IP->MACの簡易キャッシュ(ARP_CACHE_SIZE件、溢れたら先頭エントリを
 * 上書き)から引く。arp_handle_frame()がARP reply受信時に自動で登録する。
 * 戻り値: 0=見つかった(out_macに格納)、-1=無い */
int arp_cache_lookup(uint32_t ip, uint8_t out_mac[6]);

/* ipをMACアドレスへ解決する。キャッシュに既にあれば送信せず即座に返す。
 * 無ければarp_send_request()で要求を送り、最大ARP_RESOLVE_TIMEOUT_MS
 * の間 eth_poll_recv()+eth_dispatch() をポーリングして解決を待つ
 * (ARP reply受信はarp_handle_frame()経由でキャッシュに反映される)。
 * 戻り値: 0=解決成功(out_macに格納)、-1=送信失敗またはタイムアウト */
int arp_resolve(uint32_t ip, uint8_t out_mac[6]);

#endif /* ARP_H */
