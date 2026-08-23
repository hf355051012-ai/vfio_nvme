#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stddef.h>

#define ARP_HTYPE_ETHERNET  1u      /* Hardware type: Ethernet */
#define ARP_PTYPE_IPV4      0x0800u /* Protocol type: IPv4 */
#define ARP_OP_REQUEST      1u
#define ARP_OP_REPLY        2u

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

void arp_init(void);

void arp_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac);

int arp_send_request(uint32_t target_ip);

/* 到達確認(NUD)用のユニキャスト ARP request。MAC を既に知っている相手に
 * 「まだそこに居るか」を聞くので、ブロードキャストにしない(RFC 4861 7.2.4 の
 * ARP 版。Linux の NUD PROBE も同じ)。 */
int arp_send_request_unicast(uint32_t target_ip, const uint8_t mac[6]);

/* 重複アドレス検出(RFC 5227 の ARP Probe)。ip を使い始める前に呼ぶ。
 * 0=空き、1=既に使われている(out_mac に相手の MAC)、-1=失敗。
 * 「応答が返ってこないこと」で判定するので probes*interval_ms かかる。
 *
 * RFC 5227 は PROBE_NUM=3・1〜2 秒間隔を指定するが、あれは DHCP 規模の LAN で
 * 相手の応答が遅い場合を見込んだ値。この装置は DAC 直結(応答まで実測 150us)
 * なので既定はずっと短くしてある。**実 LAN へ出すときは RFC の値へ戻すこと。** */
#define ARP_PROBE_NUM         2u
#define ARP_PROBE_INTERVAL_MS 50u

int arp_probe(uint32_t ip, unsigned probes, uint32_t interval_ms, uint8_t out_mac[6]);

/* 解決済みの IP -> MAC を登録する(= エントリの延命)。通常は ARP reply の
 * 受信時に内部から呼ばれる。`arptest` が応答の来ない相手を仕込むのにも使う。 */
void arp_cache_insert(uint32_t ip, const uint8_t mac[6]);

int arp_cache_lookup(uint32_t ip, uint8_t out_mac[6]);

/* 上位層の到達確認(RFC 4861 7.3.1)を受け取れる版。confirmed=1 なら
 * 「相手が自分のデータを確かに受け取った」ので、確認要求を出さずに延命する。
 * TCP の送信経路だけがこれを使う(累積 ACK が進んだかを知っているため)。 */
int arp_cache_lookup_nud(uint32_t ip, uint8_t out_mac[6], int confirmed);

/* キャッシュを引かずにエントリの寿命だけを見る(`arptest` の観測用)。
 * 0=fresh、1=stale(猶予中)、-1=未登録。remain_ms は残り猶予/寿命。 */
int arp_cache_peek(uint32_t ip, uint32_t *remain_ms);

int arp_resolve(uint32_t ip, uint8_t out_mac[6]);

#endif /* ARP_H */
