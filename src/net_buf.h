#ifndef NET_BUF_H
#define NET_BUF_H

#include <stdint.h>

/* ================================================================
 * net_buf.h — malloc無し環境向け固定サイズパケットバッファプール
 *
 * ジャンボフレーム対応(2026-07-25)。RP1のGEMが実際にサポートする最大
 * フレーム長はeth.hのETH_JUMBO_MAX_LEN(=10240、raspberrypi/linuxの
 * raspberrypi_rp1_config.jumbo_max_lenから取得した実機の値)。ここから
 * FCS(4バイト、HWが自動付加/除去するためバッファには乗らない)を引いた
 * 10236バイトが実際に受信しうる最大データ長だが、切りの良い10240バイト
 * (ETH_JUMBO_MAX_LENと同値)を1単位として採用した — 64バイト境界に
 * 揃っており(eth.cのDMACFG RXBSフィールド計算、64バイト単位)、かつ
 * 実際に必要な10236バイトに対して十分な余裕(4バイト)がある。
 * 旧値は1518(非ジャンボ、Ethernetヘッダ14+MTU1500+FCS4)だった。
 * TX/RX 双方で共有して使う。net_buf_tのサイズが約6.8倍になったため、
 * DMA対象のリング(eth.cのs_rx_ring_bufs)は.dma_bssの2MB予算に収まる
 * よう別途エントリ数を減らしてある(eth.cのETH_RX_RING_SIZEコメント参照)。
 * ================================================================ */

#define NET_BUF_SIZE   10240u
/* RXリング用バッファはこのプールに含まれない(eth.cの専用配列
 * s_rx_ring_bufs、.dma_bss、DMAが直接読み書きするため)。ここは
 * eth_poll_recv()の受信後コピー先「out」バッファやARP/ICMP等の短命な
 * 送信バッファ専用 -- 同時に1〜2個程度しか使わないが、余裕を持たせて
 * 40のままにしておく(MMU有効化後はNormal cacheableなRAMなので、
 * 個数を増やすこと自体のコストは低い)。 */
#define NET_BUF_COUNT  40u

/* aligned(64): SCTLR_EL1.M=0(MMU無効)環境ではメモリがDeviceメモリ相当となり、
 * 非アラインアクセスが即Alignment fault(Data Abort, DFSC=0x21)になる。
 * コンパイラが固定長ループの隣接バイト書き込みを1個のワイドストア
 * (STP等)へ結合した場合でも、少なくともバッファ先頭が境界に乗るようにする
 * (eth.c の s_tx_buf/s_rx_buf と同じ規約)。ただし構造体内の途中オフセットで
 * ワイドストアに結合された場合はこれだけでは防げないため、フレーム構築側
 * (呼び出し側)でも volatile 経由のバイト単位書き込みを徹底すること。 */
typedef struct net_buf {
    /* 2026-08-13、受信ゼロコピー対応(CLAUDE.md「受信ゼロコピー」節): 従来
     * `uint8_t data[NET_BUF_SIZE]` というインライン配列だったが、mlx5の受信で
     * RQ DMAバッファ→net_bufのコピー(コピー1)を省くため、フレーム格納実体
     * (storage)とそれを指すポインタ(data)に分離した。storageをoffset 0に
     * 置くことでRP1のGEM DMA先(&nb->storage)が旧`&nb->data`と同一アドレスに
     * なり、RP1側のDMAリング設定はアドレス上byte互換のまま(eth.c参照)。
     * - 通常: net_buf_alloc()がdata=storageに設定(コピー先/送信元とも実体を使う)。
     * - mlx5受信ゼロコピー: mlx5_net_poll_recv()がdata=RQバッファに設定し、
     *   コピーせずにスタック(eth_dispatch/tcp_input)へ渡す(mlx5_net.c参照)。
     * data[0..len)が有効なフレーム内容(dataはポインタなので既存の`nb->data[i]`/
     * `nb->data`アクセスはそのまま動く)。 */
    uint8_t  storage[NET_BUF_SIZE];
    uint8_t *data;
    uint16_t len;   /* data[0..len) が有効なフレーム内容 (呼び出し側が設定/参照) */
    /* 2026-08-09、ハードウェアチェックサムオフロード対応: このフレームが
     * NICのRXパイプラインで既にL3(IP)/L4(TCP/UDP)チェックサム検証済み
     * (mlx5のCQE hds_ip_ext内のCQE_L3_OK|CQE_L4_OKビット、Linux
     * include/linux/mlx5/device.hから確認)なら1。eth_dispatch()が
     * この値をper-coreのグローバルフラグへ伝搬し、ip.c/tcp.cが
     * ソフトウェアでの再検証(inet_checksum()/pseudo_header_checksum())を
     * スキップするために使う。RP1(eth.c)は常に0(未対応、ソフトウェア
     * 検証を継続)。 */
    uint8_t  hw_csum_ok;
} __attribute__((aligned(64))) net_buf_t;

/* 空きバッファを1個確保する。呼び出したコア自身のプールから確保する
 * (net_buf.c参照)。戻り値: NULL=プール枯渇 */
net_buf_t *net_buf_alloc(void);

/* バッファをプールに返却する。buf=NULLは無害(何もしない)。
 * 割り当てたコアと同じコアが解放すること(コアをまたいだ受け渡しは
 * 想定しない、net_buf.c参照)。 */
void net_buf_free(net_buf_t *buf);

#endif /* NET_BUF_H */
