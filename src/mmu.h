#ifndef MMU_H
#define MMU_H

/* ================================================================
 * mmu.h — MMU有効化(段階的フェーズA/B、EL2)
 *
 * 現在EL2で動作中(EL遷移なし、boot.S参照)のため、TTBR0_EL2/MAIR_EL2/
 * TCR_EL2/SCTLR_EL2を設定する。4KB granule、39-bit VA、恒等写像(VA=PA)。
 *
 * フェーズA: MMU有効化のみ、全域Device-nGnRnE(現状のDevice-only挙動と
 *   論理的に等価な状態でページテーブル配線自体を検証する)。
 * フェーズB: DMAバッファ(net_buf.c/eth.c/tcp.cが`.dma_bss`セクションへ
 *   集約したもの)以外のRAMをNormal cacheableに切り替える。
 *
 * 詳細な設計根拠・検証手順は ~/.claude/plans/glimmering-mapping-waterfall.md
 * を参照(段階的に実機確認しながら進める前提)。
 * ================================================================ */

/* MMUを有効化する。main()内、exceptions_init()/pl011_init()の直後、
 * それ以外の初期化より前に1回だけ呼ぶこと。
 * 途中経過をdebug_uartへ逐次出力する(実機でどこまで進んでハングしたかを
 * 切り分けるため)。HCR_EL2.E2H=1(VHEレイアウト)や
 * ID_AA64MMFR0_EL1.PARange不足など、前提が崩れている場合はUARTに警告を
 * 出してhangする(黙って誤動作するより安全)。 */
void mmu_init(void);

/* マルチコア化 Phase 2(~/.claude/plans/wondrous-baking-gadget.md参照):
 * core1(secondary_entry、src/boot.S/src/smp.cのsecondary_main()から
 * 呼ばれる)専用。TTBR0_EL2/MAIR_EL2/TCR_EL2/SCTLR_EL2はコアごとに
 * 独立したレジスタなので、core0のmmu_init()がMMUを有効化していても
 * core1は自分自身でこれらを設定しない限りMMU無効のまま動く。
 * ページテーブル自体(l1_table/l2_table、MMU_TABLES_BASE)はcore0が
 * mmu_init()で既に構築済みのものをそのまま再利用する(再構築はしない --
 * 恒等写像・マッピング方式はコア非依存で、mmu_init()の「再入の設計」と
 * 同じ理由)。cpuonはcore0のシェルから明示的に実行される後発コマンドの
 * ため、この関数が呼ばれる時点でcore0のmmu_init()は必ず完了している。 */
void mmu_init_secondary(void);

#endif /* MMU_H */
