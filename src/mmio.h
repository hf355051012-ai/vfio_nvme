#ifndef MMIO_H
#define MMIO_H

#include <stdint.h>

// ================================================================
// HAL 契約: MMIO レジスタアクセス(x86-vfio-port の platform 継ぎ目、
// ~/.claude/plans/x86-vfio-port.md §3 参照)。core(mlx5*/pcie* 等)が呼ぶ
// 契約であり、下記は RPi5 実装(BAR ベースを直接デリファレンス)。x86-linux
// では VFIO で mmap した BAR 領域へのアクセスに、VxWorks では vxbRead/Write に
// 差し替わる。関数シグネチャ(アドレスは uint64_t)は全 platform 共通に保つ。
// ================================================================

// 32ビットMMIOレジスタへの読み書き。
static inline void mmio_write32(uint64_t addr, uint32_t val) {
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t mmio_read32(uint64_t addr) {
    return *(volatile uint32_t *)addr;
}

// 2026-08-08、ユーザー指摘(「アクセスサイズに違いはないか」)を受け追加。
// Linux include/linux/mlx5/doorbell.hのmlx5_write64()コメント参照:
// 「64bitシステムでは単一のwriteq()でアトミックに書けるが、32bitシステム
// では2回のwritel()に分割されるため非アトミックになり、呼び出し元が
// ロックで保護する必要がある」と明記されている。BCM2712(Cortex-A76、
// ARMv8-A、64bit)でmlx5_net.cのBlueFlameドアベル書き込みがmmio_write32()
// を2回呼ぶ実装になっていたのは、意図せずLinuxの「32bitシステム・
// 非アトミック」パスと同じ実装になっていたことを意味する -- 単一コアでは
// 問題化しなかったが、2コアが真に並行してドアベルを鳴らすと、互いの
// 32bit書き込みがインターリーブしうる(実機でLOCAL_QP_OP_ERRとして観測
// 済み)。64bit CPUの利点を活かし、単一のアラインされた64bitストア命令
// (ARMv8アーキテクチャ上、単一のstr x命令は分割されないことが保証される)
// でアトミックに書き込む。
static inline void mmio_write64(uint64_t addr, uint64_t val) {
    *(volatile uint64_t *)addr = val;
}

// DMA/ドアベル書き込み順序バリア(x86-vfio-port の platform 継ぎ目、§3 の
// 「メモリバリア dmb/dsb」)。ディスクリプタ等の通常メモリ書き込みを、後続の
// ドアベル MMIO 書き込みより前に、全観測者(PCIe 越しの ConnectX 含む)へ
// 可視化する。ARM は dsb sy(system 全体)。x86 は TSO だが MMIO(UC)との
// 順序を確実にするため mfence。**関数ではなくマクロ**にしてあるのは、mlx5.c が
// -O0 でビルドされ(Makefile 参照)、static inline だと -O0 では out-of-line
// 呼び出しになってバイト同一が崩れるため -- マクロなら aarch64 展開が元の
// `__asm__ volatile("dsb sy" ::: "memory")` と字面同一になり byte-identical を保つ。
#if defined(__aarch64__)
#define dma_wmb() __asm__ volatile("dsb sy" ::: "memory")
#else
#define dma_wmb() __asm__ volatile("mfence" ::: "memory")
#endif

#endif
