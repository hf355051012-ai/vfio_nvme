#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <stddef.h>
#include "net_buf.h"
#include "eth.h"

/* ================================================================
 * ip.h — IPv4ヘッダ処理 — フェーズ3
 *
 * オプション無し(IHL=5, 20バイト)のIPv4ヘッダのみ対応。
 * オプション付きIPパケットは無視する(ログのみ)。
 * ================================================================ */

#define IP_PROTO_ICMP 1u
#define IP_PROTO_TCP  6u

/* IPv4ヘッダ(20バイト、オプション無し)。
 * 多バイトフィールドへの直接アクセスは行わないこと — 必ず
 * net.h の rd16be/rd32be/wr16be/wr32be 経由でアクセスする。 */
typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;      /* [7:4]version(4) [3:0]IHL(ワード数、オプション無しなら5) */
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
} ip_header_t;

/* net_buf->data内でIPペイロード(L4ヘッダ+データ)が始まるオフセット。
 * Ethernetヘッダ(14) + IPv4ヘッダ(20、オプション無し)。
 * ip_prepare_send_buf()が返すnet_bufへ書き込む際、呼び出し側はこの
 * オフセットから書き始めること。 */
#define IP_PAYLOAD_OFFSET (ETH_HDR_LEN + (unsigned)sizeof(ip_header_t))

/* EtherType=0x0800 に ip_handle_frame を登録する。
 * eth_init() 実行後(cmd_ethinitなど)に一度呼び出すこと。 */
void ip_init(void);

/* eth_handler_t のシグネチャに一致するIPv4フレーム処理本体。
 * dst IP == 自機IP かつ ヘッダチェックサムが正しい場合のみ処理する。
 * protocol==ICMPならicmp_handle()へ委譲する。それ以外はログのみで無視。 */
void ip_handle_frame(const uint8_t *payload, size_t len, const uint8_t *src_mac);

/* Ethernet+IPv4ヘッダ(計IP_PAYLOAD_OFFSETバイト、チェックサム確定済み)を
 * bufへ書き込む。bufは少なくともIP_PAYLOAD_OFFSETバイトの書き込み先で
 * あればよく、net_buf である必要はない(ゼロコピー送信用の小さな
 * ヘッダ専用バッファ等、任意のバッファに書ける — tcp.cのtcp_send_segment()
 * 参照。データ本体は別断片としてeth_send_frags()に渡し、コピーしない)。
 * payload_lenはIPヘッダのtotal_len計算に使う実際のペイロード長
 * (このヘッダの直後に続くバイト数 — 同じバッファ内である必要はない)。
 * IPヘッダのチェックサムはペイロードの内容に依存しないため、この関数の
 * 中で確定させる。 */
void ip_build_header(uint8_t *buf, const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                      uint8_t protocol, uint16_t payload_len);

/* IPパケットを構築し、Ethernetフレームとして送信する(応答生成用の共通ヘルパ)。
 * dst_ip/dst_mac: 宛先(4バイト/6バイト、生バイト列)
 * protocol: IP_PROTO_ICMP等
 * payload/payload_len: IPペイロード(ICMPヘッダ+データ等)
 * 内部でip_prepare_send_buf()+ペイロードコピー+ip_send_prepared()を行う
 * 便利関数 — 呼び出し側が既に別バッファにペイロードを持っている
 * (ICMP応答等、小さく頻度も低い)場合はこちらでよい。TCPの送信のように
 * 高頻度・比較的大きいペイロードでは、二重コピーを避けるため
 * ip_prepare_send_buf()/ip_send_prepared()を直接使うこと(tcp.c参照)。
 * 戻り値: eth_send()の戻り値をそのまま返す(0=成功, -1=失敗)
 */
int ip_send(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
            uint8_t protocol, const uint8_t *payload, uint16_t payload_len);

/* IPパケット送信の準備として、Ethernet+IPヘッダを書き込んだnet_bufを
 * 確保して返す。ペイロード領域(payload_lenバイト、戻り値の
 * data+IP_PAYLOAD_OFFSETから)への書き込みは呼び出し側が直接行うこと —
 * ip_send()のような「呼び出し側の別バッファ→net_buf」のコピーを
 * 発生させないための2段階API(tcp_send_segment()のように高頻度・
 * 比較的大きいペイロードを送る場合に二重コピーのオーバーヘッドを
 * 避けられる。実測でこの二重コピーが1セグメントあたりの送信コストの
 * 約2/3を占めていた)。IPヘッダのチェックサムはip_send_prepared()側で
 * 計算する。
 * 戻り値: 確保・ヘッダ構築済みのnet_buf(所有権は呼び出し側 —
 *         ip_send_prepared()に渡すか、使わないならnet_buf_free()する
 *         こと)、NULL=確保失敗またはサイズ超過 */
net_buf_t *ip_prepare_send_buf(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                                uint8_t protocol, uint16_t payload_len);

/* ip_prepare_send_buf()で確保したnet_bufに、呼び出し側がpayload_lenバイトの
 * ペイロードを書き込み終えた後に呼ぶ。IPヘッダチェックサムを計算し、
 * eth_send()で送信する(nbの所有権はeth_send()に渡り、以後呼び出し側は
 * nbへアクセスしてはならない)。
 * 戻り値: eth_send()の戻り値をそのまま返す(0=成功、-1=失敗) */
int ip_send_prepared(net_buf_t *nb, uint16_t payload_len);

#endif /* IP_H */
