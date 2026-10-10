/* iSCSI の PDU を TCP へ送る(iscsi_pdu.h)。 */
#include "iscsi_pdu.h"
#include "iscsi.h"
#include "crc32c.h"
#include <string.h>

volatile uint32_t g_iscsi_pdu_zerocopy = 1;

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

uint32_t iscsi_get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int iscsi_pdu_send(tcp_conn_t *tcp, int hd, int dd, uint8_t *bhs, const uint8_t *data, uint32_t dlen,
                   unsigned corrupt)
{
    uint8_t hdr[ISCSI_BHS_LEN + 4];
    uint8_t tail[8];
    /* **ヘッダのどの欄もダイジェストの計算より前に確定させる**(NVMe/TCP で 3 回踏んだ形)。 */
    bhs[ISCSI_OFF_AHSLEN] = 0;
    iscsi_put24(&bhs[ISCSI_OFF_DSL], dlen);
    memcpy(hdr, bhs, ISCSI_BHS_LEN);
    uint32_t hl = ISCSI_BHS_LEN;
    if (hd) {
        uint32_t d = ~crc32c(0xFFFFFFFFu, hdr, ISCSI_BHS_LEN);
        if (corrupt & ISCSI_SEND_CORRUPT_HDGST) d ^= 1u;
        put_le32(&hdr[ISCSI_BHS_LEN], d);
        hl += 4u;
    }
    const uint32_t pad = (4u - (dlen & 3u)) & 3u;
    memset(tail, 0, sizeof(tail));
    uint32_t tl = pad;
    if (dd && dlen) {
        uint32_t crc = crc32c(0xFFFFFFFFu, data, dlen);
        if (pad) crc = crc32c(crc, tail, pad);           /* パディングもダイジェストの対象 */
        crc = ~crc;
        if (corrupt & ISCSI_SEND_CORRUPT_DDGST) crc ^= 1u;
        put_le32(&tail[pad], crc);
        tl += 4u;
    }
    uint32_t cap = tcp->snd_mss ? (uint32_t)tcp->snd_mss : 1400u;
    if (cap > TCP_ASYNC_SHORT_SLOT_BYTES) cap = TCP_ASYNC_SHORT_SLOT_BYTES;
    if (hl + dlen + tl <= cap)
        return tcp_send_async3(tcp, hdr, (uint16_t)hl, data, (uint16_t)dlen, tail, (uint16_t)tl) < 0 ? -1 : 0;
    if (g_iscsi_pdu_zerocopy) {
        /* **大きい PDU は本体をゼロコピーの長経路(LSO)で送る。** NVMe/TCP ターゲットの
         * C2HData と同じ形(ヘッダは短経路、本体は tcp_send_async_ref で 32KiB ずつ、
         * ダイジェストは短経路)。9KiB ずつ短経路で刻むと 1 セグメントごとに再送用の
         * スロットへ写すことになり、読み出しが約 2 GB/s で頭打ちになった(段階 E)。
         * 本体は ACK されるまで書き換えられない場所(RAM ディスク・送信用の模様)に限る。 */
        if (tcp_send_async(tcp, hdr, (uint16_t)hl) < 0) return -1;
        uint32_t q = 0;
        while (q < dlen) {
            const uint32_t n = (dlen - q > TCP_ASYNC_MAX_LEN) ? TCP_ASYNC_MAX_LEN : dlen - q;
            const int rc = tcp_send_async_ref(tcp, data + q, (uint16_t)n);
            if (rc < 0) return -1;
            q += (uint32_t)rc;
        }
        return tl ? (tcp_send_async(tcp, tail, (uint16_t)tl) < 0 ? -1 : 0) : 0;
    }
    /* 刻む: 1 本目 = ヘッダ + データの頭、以後 = データの続き、最後にパディング + ダイジェスト
     * (データの残りと一緒に収まればそこへ、収まらなければ単独で)。 */
    uint32_t off = cap - hl;
    if (off > dlen) off = dlen;
    if (tcp_send_async3(tcp, hdr, (uint16_t)hl, data, (uint16_t)off, NULL, 0) < 0) return -1;
    while (off < dlen) {
        uint32_t n = dlen - off;
        if (n + tl <= cap)
            return tcp_send_async3(tcp, data + off, (uint16_t)n, tail, (uint16_t)tl, NULL, 0) < 0 ? -1 : 0;
        if (n > cap) n = cap;
        if (tcp_send_async3(tcp, data + off, (uint16_t)n, NULL, 0, NULL, 0) < 0) return -1;
        off += n;
    }
    return tl ? (tcp_send_async3(tcp, tail, (uint16_t)tl, NULL, 0, NULL, 0) < 0 ? -1 : 0) : 0;
}
