#ifndef CRC32C_H
#define CRC32C_H

#include <stdint.h>
#include <stddef.h>

/* crc32c.h — CRC32C(Castagnoli多項式)計算。NVMe-oF TCPトランスポートの
 * ヘッダ/データダイジェスト(nvmet_impl_v2.md Phase 2-A/2-E)で使う。
 * BCM2712(Cortex-A76)はARMv8のCRC32命令セットを持つため、GCC組み込み
 * 関数(__builtin_aarch64_crc32c*)でハードウェア計算する(-mcpu=cortex-a76
 * が既にCRC命令を有効にする、Makefile参照)。
 *
 * この関数自体は「生の」実行中CRCレジスタ値を返す(最終反転は行わない)
 * -- 複数バッファにまたがるチェーン計算(checksum_accumulate()と同じ
 * 呼び出し方、crc32c(crc32c(init, buf1, len1), buf2, len2)のように連結)
 * を正しく行うには、途中で反転してはならないため。
 *
 * 2026-07-25、実機のLinux nvme-tcpホストとのヘッダダイジェスト検証で
 * 実際に不一致を確認し、原因を特定した: 当初nvmet_impl_v2.mdの
 * Phase 2-Aコードコメント(「NVMe Base Spec 8.4 — 最後に~を取らない」)を
 * そのまま信じてこの関数の戻り値をダイジェスト値として直接使っていたが、
 * 実際のLinuxホストが送ってきた値は、こちらが計算した値のビット反転
 * (~)と完全に一致した(expected=0x00f16eaf、host送信値=0xff0e9150 =
 * ~0x00f16eaf)。Linuxカーネルの標準crc32c crypto実装
 * (crypto/crc32c.c、chksum_final()の`put_unaligned_le32(~ctx->crc, out)`)
 * が示す通り、NVMe/TCPが使う「CRC32C」は一般的な CRC-32C(Castagnoli)の
 * 慣習(init=0xFFFFFFFF、**最終値をビット反転(~)してから**LEで格納)に
 * 従う -- doc記載の「~を取らない」は誤りだった(このdocは以前Terminate
 * PDUのtype値でも誤りが見つかっている、CLAUDE.md該当節参照 -- 個別の
 * コード片を鵜呑みにせず実機で検証することの重要性がここでも実証された)。
 * **呼び出し側がこの関数の戻り値を実際のダイジェスト値として使う際は
 * 必ず`~`を取ってから4バイトへ書く/比較すること**(nvmet_tcp.cの
 * nvmet_tcp_append_hdgst()/check_hdgst()等参照)。 */

/* crcを初期値としてdata[0..len)を処理した結果を返す(data=NULL/len=0なら
 * crcをそのまま返す — 複数バッファにまたがるチェーン計算に使える、
 * checksum_accumulate()と同じ呼び出し方)。戻り値は生の実行中CRC値であり、
 * 最終ダイジェスト値としてそのまま使ってはならない(上記コメント参照、
 * 呼び出し側が`~`を取ること)。
 * dataはvolatile経由(net.hのvolatile_fast_copy()/checksum_accumulate()と
 * 同じ理由 — 任意にアラインされうるワイヤバッファに安全に使うため)。 */
uint32_t crc32c(uint32_t crc, const volatile void *data, size_t len);

#endif /* CRC32C_H */
