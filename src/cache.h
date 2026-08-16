#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

// ================================================================
// HAL 契約: DMA キャッシュコヒーレンシ(x86-vfio-port の platform 継ぎ目、
// ~/.claude/plans/x86-vfio-port.md §3 参照)。core(mlx5_net/nvmet_rdma 等の
// DMA バッファ操作)が呼ぶ契約であり、下記は RPi5 実装(dc cvac/civac + dsb)。
// x86-linux / VxWorks-on-x86 は DMA コヒーレントなので **no-op** になる
// (= RPi5 で苦労したコヒーレンシ経路は x86 では無検証のまま残る divergence、
// §7 参照)。呼び出し規約(clean=CPU書込→DMA可視化、invalidate=DMA書込→
// CPU可読化)は全 platform 共通に保つ。
// ================================================================

#if defined(__aarch64__)

// [start, start+len) のデータキャッシュをクリーンし命令キャッシュを無効化する。
// fwupdate.cのfwupdate_jump_to_image()から、新しく受信したコードへジャンプ
// する直前に呼ばれる -- 「このアドレス範囲は今後コードとして実行される」
// ことを保証する関数。
//
// マルチコア化 Phase 5(~/.claude/plans/wondrous-baking-gadget.md参照)で
// 実機発見した本物のバグの修正: 以前は`dc cvau`(Point of Unification =
// 呼び出し元コア自身のI/Dキャッシュ一貫性用、他コアへの可視性は保証しない)
// + `ic ivau`(呼び出し元コアの命令キャッシュのみを無効化、範囲指定、
// 他コアの命令キャッシュには一切影響しない)を使っていた -- これは
// 「このコード自身がこの直後に実行する」場合(fwupdate_jump_to_image()の
// 呼び出し元自身がジャンプする通常のケース)には正しいが、「後で
// *別のコア*がこの範囲を実行する」場合(cpuonでcore1をfwupdateで受信した
// ペイロードへ起動する場合)には不十分だった。実機で、LANチェインロード
// 直後にcpuonでcore1を起動すると、core1がsecondary_main()の最初の一行にも
// 到達せず完全に停止する(g_core1_heartbeatが常に0のまま)ことを確認した
// -- コールドブート(GPUファームウェアがSDカードから直接DRAMへ書き込む
// 経路、このコヒーレンシ問題がそもそも発生しない)では常に成功していた
// ため、この症状が「チェインロード+cpuon」の組み合わせでのみ再現する
// ことから特定した。CLAUDE.md「DMAコヒーレンシの落とし穴」節で確認済みの
// 「`dc cvau`はPCIe越しの外部バスマスタへの可視性を保証しない、`dc cvac`
// (Point of Coherency)が必要」という教訓と全く同じクラスの問題が、
// 「まだ実行を始めていない別コアへの命令可視性」という形で再発していた。
// 修正: `dc cvau`を`dc cvac`(Point of Coherencyまでクリーン、全観測者から
// 見える)に、`ic ivau`(自コアのみ、範囲指定)を`ic ialluis`(全コアの
// 命令キャッシュ全体をInner Shareableドメインへブロードキャストして無効化)
// に変更した。範囲指定ではなく全体無効化になるが、この関数はホットパス
// ではない(fwupdateのジャンプ直前に1回呼ばれるだけ)ため性能上の懸念は
// 無視できる。バリアはdsb ish(Inner Shareable)のまま -- CPU間の共有は
// Inner Shareableドメイン(mmu.cのNormal memory属性の選択と同じ理由)で
// 十分であり、PCIe越しの外部バスマスタ向けにdsb syを使うdcache_clean_
// range()とは対象読者が異なる。
static inline void sync_icache_range(void *start, uint64_t len) {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t dline = 4ULL << ((ctr >> 16) & 0xf);  // CTR_EL0.DminLine

    uint64_t end = (uint64_t)start + len;

    uint64_t addr = (uint64_t)start & ~(dline - 1);
    for (; addr < end; addr += dline) {
        __asm__ volatile("dc cvac, %0" : : "r"(addr) : "memory");
    }
    __asm__ volatile("dsb ish");

    __asm__ volatile("ic ialluis" ::: "memory");
    __asm__ volatile("dsb ish");
    __asm__ volatile("isb");
}

// [start, start+len) のデータキャッシュをPoint of Coherency(PoC)まで
// クリーンする -- PCIe接続の外部バスマスタ(RP1 GEMのDMAエンジン)が
// CPUの書き込みを確実に見えるようにするため。sync_icache_range()も
// 2026-08-08(マルチコア化 Phase 5)以降`dc cvac`を使うようになったが、
// 対象読者が異なる(CPUコア間 vs PCIe越しの外部デバイス)ため、バリアは
// dsb ish(inner shareable)ではなくdsb sy(system全体)を使う --
// PCIe越しの外部デバイスはinner shareableドメインの外にある可能性が高く、
// 安全側に倒す。
static inline void dcache_clean_range(const void *start, uint64_t len) {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t dline = 4ULL << ((ctr >> 16) & 0xf);  // CTR_EL0.DminLine

    uint64_t end = (uint64_t)start + len;
    uint64_t addr = (uint64_t)start & ~(dline - 1);
    for (; addr < end; addr += dline) {
        __asm__ volatile("dc cvac, %0" : : "r"(addr) : "memory");
    }
    __asm__ volatile("dsb sy");
}

// [start, start+len) のデータキャッシュをPoint of Coherency(PoC)まで
// クリーン+無効化する -- dcache_clean_range()の逆方向(PCIe接続の外部
// バスマスタがDMAで書き込んだデータを、CPUが確実に読めるようにする)。
// 2026-08-09、ユーザー指摘でmlx5_net.cのRQ受信バッファ(旧Device-nGnRnE、
// ゼロコピー化に伴いNormal cacheable RAMへ移した)向けに追加 -- DMA書き込み
// 後にCPUが読む前に呼ぶことで、古いキャッシュ内容を読んでしまうのを防ぐ。
// 単純な無効化(`dc ivac`)ではなく`dc civac`(クリーン+無効化)を使う --
// この領域はCPU側が書き込むことは無い前提だが、万一ダーティな行が
// 残っていた場合にDMA直後のデータを無言で破棄してしまう事故を避けるため
// (dcache_clean_range()と同様、対象読者はPCIe越しの外部デバイスなので
// バリアはdsb sy)。
static inline void dcache_invalidate_range(const void *start, uint64_t len) {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t dline = 4ULL << ((ctr >> 16) & 0xf);  // CTR_EL0.DminLine

    uint64_t end = (uint64_t)start + len;
    uint64_t addr = (uint64_t)start & ~(dline - 1);
    for (; addr < end; addr += dline) {
        __asm__ volatile("dc civac, %0" : : "r"(addr) : "memory");
    }
    __asm__ volatile("dsb sy");
}

#else /* !__aarch64__ */

// x86-linux / VxWorks-on-x86: DMA コヒーレント(IOMMU/PCIe が CPU キャッシュと
// 一貫)なので、明示的な clean/invalidate は不要 -- 全て no-op になる
// (~/.claude/plans/x86-vfio-port.md §7 の divergence: RPi5 で苦労した
// コヒーレンシ経路は x86 では無検証のまま残る)。コンパイラ最適化による
// 並べ替えは、DMA バッファ操作の順序保証が要る箇所が別途 mmio_write64() の
// volatile ストア / smp のバリアで担保している前提。
static inline void sync_icache_range(void *start, uint64_t len) {
    (void)start; (void)len;
    __asm__ volatile("" ::: "memory"); /* コンパイラバリア(命令並べ替え抑止) */
}

static inline void dcache_clean_range(const void *start, uint64_t len) {
    (void)start; (void)len;
    __asm__ volatile("" ::: "memory");
}

static inline void dcache_invalidate_range(const void *start, uint64_t len) {
    (void)start; (void)len;
    __asm__ volatile("" ::: "memory");
}

#endif /* __aarch64__ */

#endif
