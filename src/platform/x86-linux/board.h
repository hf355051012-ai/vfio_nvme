#ifndef BOARD_H
#define BOARD_H

/* ================================================================
 * platform/x86-linux/board.h -- x86-linux 用ボード定数(x86-vfio-port
 * Phase 3、~/.claude/plans/x86-vfio-port.md §2 参照)。
 *
 * RPi5 の src/board.h は BCM2712 の物理アドレス群(UART/PCIe/固定 DMA
 * レイアウト等)を持つが、x86 では:
 *   - PCIe/BAR は VFIO でmmapするため固定物理アドレスは不要。
 *   - DMA バッファは固定物理アドレスではなく dma_alloc(hal_dma.c)へ委譲
 *     済み(Phase 2 で core から固定アドレスマクロを全廃)。
 *   - MLX5_DMA_ADDR_HI32(RC_BAR2 オフセット)は x86 では使わない(dev=IOVA)。
 * したがってこのヘッダは当面ほぼ空でよい。core(mlx5.c/command.c)が
 * board.h を include するのは Phase 4/5 で x86 リンクへ加わってからで、
 * その際に必要な定数(サイズ/IP 既定等、物理アドレスは除く)をここへ足す。
 *
 * 【board.h のシャドウ方法(Phase 4 で決める)】`#include "board.h"` は
 * インクルード元(src/*.c)と同じディレクトリの src/board.h を先に見つける
 * ため、-I 順だけではこの x86 版に差し替わらない。Phase 4 で core を x86 へ
 * リンクする際、src/board.h をアーキ条件化するか、board.h を src/ の外へ
 * 出すか、いずれかの方式を採る(現時点では未配線 -- Phase 3 の x86 リンク
 * 集合[crc32c + timer + HAL]は board.h を include しない)。
 * ================================================================ */

#endif /* BOARD_H */
