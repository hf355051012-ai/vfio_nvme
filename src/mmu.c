// mmu.c
//
// MMU有効化(段階的フェーズA/B、EL2) — 詳細はmmu.h、
// ~/.claude/plans/glimmering-mapping-waterfall.md 参照。
//
// ページテーブルはL1(1GB/エントリ、512エントリ)+L1 index 0専用の
// L2(2MB/エントリ、512エントリ)の2段のみ。4KBページ(L3)は使わない —
// このプロジェクトが実際にアクセスする物理アドレスは、RAM(ブロック0)と
// 少数の粗いMMIOクラスタ(board.h参照)だけであり、2MB粒度で十分表現できる。

#include <stdint.h>
#include "mmu.h"
#include "board.h"
#include "pl011.h"

extern pl011_t debug_uart;    // main.cで初期化
extern char __dma_bss_start[]; // linker.ld/linker_payload.ldで定義
extern char __dma_bss_size[];  // 同上(シンボルの"アドレス"自体がサイズ値、boot.Sのmemzero呼び出しと同じ慣習)
extern char __bss_end[];       // 同上(下記MMU_TABLES_BASE衝突検知に使う)

#define PAGE_SIZE       0x1000ULL
#define BLOCK_1G_SHIFT  30
#define BLOCK_2M_SHIFT  21
#define L1_ENTRIES      512u
#define L2_ENTRIES      512u

/* フェーズA/Bの切り替え。0=フェーズA(全域Device-nGnRnE、恒等写像の配線
 * だけを検証)、1=フェーズB(DMAバッファ以外のRAMをNormal cacheable化)。
 * フェーズAは実機で安定確認済み(再送/BNA/OVRなし、tcpbench完走、
 * SCTLR_EL2.Mのみ)。フェーズBへ移行する。 */
#define MMU_PHASE_B_CACHE_RAM 1

/* L1/L2テーブルは`.bss`内の普通のstatic配列ではなく、board.hの
 * MMU_TABLES_BASEという固定物理アドレスへの生ポインタにする(2026-08-02、
 * 実機で発見した本物のバグの修正、board.hのMMU_TABLES_BASEコメント参照)。
 * `static`配列のままだと、プライマリ(リンクベース0x80000)が構築した
 * テーブルの物理アドレスは、チェインロードされる`payload_2712.img`
 * (リンクベース0x300000)自身の`.bss`ゼロクリア範囲(+2.5MBシフトした
 * 同じ物理アドレス空間)に含まれてしまうことがあり、ペイロードの起動
 * シーケンスがMMU有効化中のまさにこのテーブルをゼロ書きしてしまう
 * (Translation Faultで実機ハング、実機のPTEダンプで確認済み)。固定
 * アドレス化によりテーブルの物理アドレスがどちらのイメージの`.bss`
 * サイズ/リンクベースにも一切依存しなくなる。 */
#define l1_table ((uint64_t *)MMU_TABLES_BASE)
#define l2_table ((uint64_t *)(MMU_TABLES_BASE + PAGE_SIZE))

/* ページテーブルディスクリプタのビットフィールド(AArch64 stage-1、
 * 4KB granule、Block/Table記述子共通の下位ビット)。 */
#define PTE_VALID        (1ULL << 0)
#define PTE_TABLE         (1ULL << 1)   /* 立てるとTABLE記述子、立てないとBLOCK記述子 */
#define PTE_ATTRINDX(i)   ((uint64_t)(i) << 2)  /* MAIR_EL2のAttr0/Attr1を選択 */
#define PTE_AP_RW_EL2     (0ULL << 6)   /* AP[2:1]=00: R/W、EL0アクセス不可(EL0は使わない) */
#define PTE_SH_OUTER      (2ULL << 8)
#define PTE_SH_INNER      (3ULL << 8)
#define PTE_AF            (1ULL << 10)  /* Access Flag。AFフォルトハンドラ未実装のため常に1を焼き込む */
#define PTE_XN            (1ULL << 54)  /* 実行不可(MMIO/DMAバッファ用) */

#define MAIR_ATTR_NORMAL_WB      0xFFu  /* Attr0: Normal, Inner/Outer Write-Back RA/WA */
#define MAIR_ATTR_DEVICE_NGNRNE  0x00u  /* Attr1: Device-nGnRnE */
#define ATTRIDX_NORMAL  0u
#define ATTRIDX_DEVICE  1u

static void print_hex(const char *label, uint64_t val)
{
    pl011_puts(&debug_uart, label);
    pl011_hex64(&debug_uart, val);
    pl011_puts(&debug_uart, "\n");
}

static void fatal_hang(const char *label, uint64_t val)
{
    print_hex(label, val);
    pl011_puts(&debug_uart, "[mmu] FATAL: 前提が崩れているため停止する(hang)\n");
    for (;;) { }
}

/* Normal(AttrIndx=0)はInner Shareable、Device(AttrIndx=1)はOuter Shareable
 * を使う(ARMの慣例通り — Device memoryの順序保証自体はshareabilityとは
 * 独立に常に効くが、複数バスマスタ間の可視性のためOuter Shareableにする)。 */
static uint64_t block_desc(uint64_t pa, unsigned attridx, int xn)
{
    uint64_t d = pa | PTE_VALID | PTE_ATTRINDX(attridx) | PTE_AP_RW_EL2 | PTE_AF;
    d |= (attridx == ATTRIDX_DEVICE) ? PTE_SH_OUTER : PTE_SH_INNER;
    if (xn) d |= PTE_XN;
    return d;
}

/* L1/L2テーブルを毎回ゼロから構築する(部分パッチはしない)。呼ばれる
 * 時点で.bssは既にゼロクリア済み(boot.S、primary_core)なので、
 * l1_table/l2_table自体は最初から全エントリ無効(0)から始まっている —
 * ここでの明示的なゼロ書きは「.bssゼロクリアに依存している」という
 * 前提を自己文書化する目的も兼ねる。 */
static void mmu_build_tables(void)
{
    for (unsigned i = 0; i < L1_ENTRIES; i++) l1_table[i] = 0;
    for (unsigned j = 0; j < L2_ENTRIES; j++) l2_table[j] = 0;

    // L1 index 0: RAM領域。L2テーブルへのTABLE記述子(L2テーブル自体は
    // 常にPAGE_SIZE境界に配置されているのでマスク不要)。
    l1_table[0] = (uint64_t)l2_table | PTE_VALID | PTE_TABLE;

    // L1 index 64,65: SoCローカルMMIOクラスタ
    // (PCIE_RC_BASE/RESCAL_BASE/BRIDGE_RESET_BASE、
    //  DEBUG_UART_BASE/PM_BASE、いずれもboard.h参照)。
    l1_table[64] = block_desc(64ULL << BLOCK_1G_SHIFT, ATTRIDX_DEVICE, 1);
    l1_table[65] = block_desc(65ULL << BLOCK_1G_SHIFT, ATTRIDX_DEVICE, 1);

    // L1 index 124-127: PCIeアウトバウンドウィンドウ(PCIE_OUTBOUND_CPU_BASE、
    // 4GB、RP1の全ペリフェラルレジスタがこの単一窓経由でアクセスされる)。
    unsigned win_base_idx = (unsigned)(PCIE_OUTBOUND_CPU_BASE >> BLOCK_1G_SHIFT);
    unsigned win_blocks   = (unsigned)(PCIE_OUTBOUND_SIZE >> BLOCK_1G_SHIFT);
    for (unsigned i = 0; i < win_blocks; i++) {
        unsigned idx = win_base_idx + i;
        l1_table[idx] = block_desc((uint64_t)idx << BLOCK_1G_SHIFT, ATTRIDX_DEVICE, 1);
    }

    // L1 index 110-111: PCIe1(ドメイン1、SoC直結の外部M.2/FFCコネクタ、
    // ConnectX)のアウトバウンドウィンドウ(PCIE1_OUTBOUND_CPU_BASE、2GB)。
    // 上記RP1用の窓(124-127)とは重ならない別範囲(pcie1.cのBAR0割り当て
    // 参照)。
    unsigned win1_base_idx = (unsigned)(PCIE1_OUTBOUND_CPU_BASE >> BLOCK_1G_SHIFT);
    unsigned win1_blocks   = (unsigned)(PCIE1_OUTBOUND_SIZE >> BLOCK_1G_SHIFT);
    for (unsigned i = 0; i < win1_blocks; i++) {
        unsigned idx = win1_base_idx + i;
        l1_table[idx] = block_desc((uint64_t)idx << BLOCK_1G_SHIFT, ATTRIDX_DEVICE, 1);
    }

    // L2テーブル(RAM領域、1エントリ=2MB): .dma_bss(net_buf.c/eth.c/tcp.cの
    // DMA対象バッファを集約したセクション、linker.ld参照)が収まる1エントリ
    // だけDevice-nGnRnEのまま維持し、DMAコヒーレンシ対応を不要にする。
    // 他の全エントリはRAM用属性(フェーズA/Bで切り替わる)。コードもこの
    // 範囲に含まれるためXN=0(実行可)を維持する。
    // .dma_bssは今やboard.hのDMA_BSS_BASEという完全固定の絶対物理アドレス
    // (linker.ld/linker_payload.ld両方で`. = DMA_BSS_BASE;`と直書き)なので、
    // __dma_bss_startは常にDMA_BSS_BASEと一致するはず -- コンパイル時
    // 定数同士なので_Static_assertで前提(1GB未満/2MB境界)を検証できる
    // (以前は.bssのサイズ/リンクベースに依存する実行時にしか分からない
    // 値だったため、実行時fatal_hang()でしか検証できなかった)。
    _Static_assert(DMA_BSS_BASE % (1ULL << BLOCK_2M_SHIFT) == 0,
                    "DMA_BSS_BASE must be 2MB-aligned");
    _Static_assert(DMA_BSS_BASE < (1ULL << BLOCK_1G_SHIFT),
                    "DMA_BSS_BASE must fall within L1 index 0 (first 1GB)");
    uint64_t dma_bss_pa = (uint64_t)__dma_bss_start;
    // それでも実行時に食い違っていないか確認する(linker.ld/board.hの
    // DMA_BSS_BASEを手で同期させる規約が崩れた場合に、黙って壊れず
    // 即座に停止するための最終防衛線 -- 実機で「プライマリとpayloadで
    // .dma_bssの物理アドレスが食い違う」バグを一度踏んでいるため、
    // ここでの検証コストは小さい)。
    if (dma_bss_pa != DMA_BSS_BASE) {
        fatal_hang("[mmu] __dma_bss_start != DMA_BSS_BASE (linker.ld/board.h同期崩れ?): 0x", dma_bss_pa);
    }
    unsigned dma_l2_idx = (unsigned)((dma_bss_pa >> BLOCK_2M_SHIFT) & (L2_ENTRIES - 1));

    // .dma_bssは単一の2MB L2エントリ(dma_l2_idx)だけをDeviceにマップする
    // ため、__dma_bss_sizeがその2MBを超えると、超えた分は「次」のL2
    // エントリへ物理的に食い込む -- そこは通常のRAM属性(フェーズBでは
    // Normal cacheable)でマップされてしまい、DMAバッファのはずの領域が
    // キャッシュコヒーレンシ保証の無いまま使われる、検出困難な形で発現
    // する重大なバグになる(2026-07-25、ジャンボフレーム対応でs_rx_ring_
    // bufs(eth.c)/s_seg_bufs(tcp.c)が大幅に肥大化し、この境界に現実的に
    // 近づいたため追加した安全策)。黙って壊れるよりここで確実に止める。
    uint64_t dma_bss_size = (uint64_t)__dma_bss_size;
    if (dma_bss_size > (1ULL << BLOCK_2M_SHIFT)) {
        fatal_hang("[mmu] __dma_bss_size exceeds 2MB L2 block: 0x", dma_bss_size);
    }

    // ConnectX(mlx5)専用のDMA領域(MLX5_DMA_BASE/SIZE、board.h参照) --
    // .dma_bssとは別の、固定物理アドレスの独立した複数L2ブロック
    // (128MB=64個の2MBブロック)。両方ともコンパイル時定数(リンカ
    // シンボルではない)なので_Static_assertで前提を検証できる。
    _Static_assert(MLX5_DMA_BASE % (1ULL << BLOCK_2M_SHIFT) == 0,
                    "MLX5_DMA_BASE must be 2MB-aligned");
    _Static_assert(MLX5_DMA_SIZE % (1ULL << BLOCK_2M_SHIFT) == 0,
                    "MLX5_DMA_SIZE must be a multiple of 2MB");
    _Static_assert((MLX5_DMA_BASE + MLX5_DMA_SIZE) <= (1ULL << BLOCK_1G_SHIFT),
                    "MLX5_DMA_BASE..+SIZE must fall within L1 index 0 (first 1GB)");
    unsigned mlx5_l2_base = (unsigned)((MLX5_DMA_BASE >> BLOCK_2M_SHIFT) & (L2_ENTRIES - 1));
    unsigned mlx5_l2_count = (unsigned)(MLX5_DMA_SIZE >> BLOCK_2M_SHIFT);
    if (mlx5_l2_base <= dma_l2_idx && dma_l2_idx < mlx5_l2_base + mlx5_l2_count) {
        // .dma_bssの実サイズが伸びてMLX5_DMA_BASEの領域まで食い込んだ場合
        // にここへ来る(通常は上のdma_bss_size>2MBチェックで先に引っかかる
        // はずだが、念のため独立して検知する)。
        fatal_hang("[mmu] MLX5_DMA_BASE range collides with .dma_bss L2 block: 0x", MLX5_DMA_BASE);
    }

    // MMU_TABLES_BASE(このl1_table/l2_table自身の固定物理アドレス、
    // board.h参照)がMLX5_DMA_BASE領域と衝突していないかのコンパイル時
    // 検証、および.dma_bssの実サイズが伸びてこの固定アドレスへ食い込んで
    // いないかの実行時検証。前者は両方ともコンパイル時定数なので
    // _Static_assertで、後者はdma_l2_idx(リンカシンボル由来、実行時にしか
    // 分からない)が絡むため実行時チェックにする。
    _Static_assert(MMU_TABLES_BASE % PAGE_SIZE == 0,
                    "MMU_TABLES_BASE must be 4KB-aligned");
    _Static_assert((MMU_TABLES_BASE + MMU_TABLES_SIZE) <= (1ULL << BLOCK_1G_SHIFT),
                    "MMU_TABLES_BASE..+SIZE must fall within L1 index 0 (first 1GB)");
    _Static_assert(MMU_TABLES_BASE + MMU_TABLES_SIZE <= MLX5_DMA_BASE
                    || MMU_TABLES_BASE >= MLX5_DMA_BASE + MLX5_DMA_SIZE,
                    "MMU_TABLES_BASE..+SIZE must not overlap MLX5_DMA_BASE..+SIZE");
    unsigned mmu_tables_l2_base = (unsigned)((MMU_TABLES_BASE >> BLOCK_2M_SHIFT) & (L2_ENTRIES - 1));
    unsigned mmu_tables_l2_count = (unsigned)(((MMU_TABLES_BASE + MMU_TABLES_SIZE - 1) >> BLOCK_2M_SHIFT)
                                               - (MMU_TABLES_BASE >> BLOCK_2M_SHIFT) + 1);
    if (mmu_tables_l2_base <= dma_l2_idx && dma_l2_idx < mmu_tables_l2_base + mmu_tables_l2_count) {
        fatal_hang("[mmu] MMU_TABLES_BASE range collides with .dma_bss L2 block: 0x", MMU_TABLES_BASE);
    }

    // 今回実機で踏んだバグそのものへの再発防止策: 通常`.bss`の終端
    // (プライマリ自身の`__bss_end`)に、チェインロードされた
    // `payload_2712.img`のリンクベースがプライマリよりどれだけ高いか
    // (LOAD_ADDR-PRIMARY_BASE)を足した「ペイロードの`.bss`終端の最悪値」
    // が、MMU_TABLES_BASEを超えていないかを起動時に検証する。この関数は
    // プライマリの初回コールドブート時にのみ実行される(mmu_init()の
    // 早期returnにより、チェインロードされたペイロードはここへ来ない)
    // ため、この時点のプライマリの`.bss`サイズが分かれば、ペイロード側の
    // 最悪値も計算できる。
    uint64_t bss_end_primary = (uint64_t)__bss_end;
    uint64_t bss_end_payload_worst = bss_end_primary + (LOAD_ADDR - PRIMARY_BASE);
    if (bss_end_payload_worst > MMU_TABLES_BASE) {
        fatal_hang("[mmu] .bss (chainload先payload込みの最悪値)がMMU_TABLES_BASEへ食い込む: 0x",
                   bss_end_payload_worst);
    }

    unsigned ram_attridx = MMU_PHASE_B_CACHE_RAM ? ATTRIDX_NORMAL : ATTRIDX_DEVICE;
    for (unsigned j = 0; j < L2_ENTRIES; j++) {
        int is_mlx5 = (j >= mlx5_l2_base) && (j < mlx5_l2_base + mlx5_l2_count);
        if (j == dma_l2_idx || is_mlx5) {
            l2_table[j] = block_desc((uint64_t)j << BLOCK_2M_SHIFT, ATTRIDX_DEVICE, 1);
        } else {
            l2_table[j] = block_desc((uint64_t)j << BLOCK_2M_SHIFT, ram_attridx, 0);
        }
    }
}

void mmu_init(void)
{
    // 再入(exception_handler()の_startへの生分岐経由、または
    // fwupdate.cのjump_to_image()による別イメージへの素の関数呼び出し
    // 経由)に備える。SCTLR_EL2はリセットされないため、フォルト/チェイン
    // ロード後はMMU(+フェーズBならキャッシュも)が既に有効な状態から
    // 呼ばれうる。
    //
    // 【重要】既に有効なら即座に何もせず抜ける。「無効化→テーブル再構築
    // →TTBR0切り替え→再度有効化」という遷移を経由する実装を最初に試した
    // (M/C/Iを同時に落とす版まで含め)が、実機のfwupdateチェインロード
    // 試験(プライマリで新規ペイロード受信→ジャンプ→ペイロード自身の
    // mmu_init()の中)で、SCTLR_EL2への無効化書き込みそのものでハングする
    // ことを確認した(三分探索で特定、原因はハードウェア側の詳細までは
    // 未特定)。
    //
    // この遷移を経由する必要が実は無い、というのが最終的な設計:
    // プライマリ・ペイロードいずれのイメージも同じmmu.cから生成され、
    // 同じマッピング方式(RAM全体をNormal cacheable化、.dma_bssだけを
    // 固定物理アドレス0x1400000でDeviceに、同じMMIO領域をDeviceに)を
    // 使う。したがって「どちらのイメージが構築したページテーブルか」は
    // 実行中のイメージにとって無関係 -- 恒等写像(VA=PA)かつマッピング
    // 方式そのものがイメージ非依存なので、既に有効なテーブルは常に
    // そのまま正しく使える。危険な無効化/切り替えシーケンスを一切経由
    // しないため、この問題が起きる余地自体が無くなる。
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
    if (sctlr & 1ULL) {
        pl011_puts(&debug_uart, "[mmu] already enabled, reusing existing tables.\n");
        return;
    }

    pl011_puts(&debug_uart, "[mmu] checking HCR_EL2 / ID_AA64MMFR0_EL1...\n");

    // HCR_EL2.E2Hでレジスタレイアウトが全く別物(VHE)になる。本リポジトリの
    // どこにもこのビットへの言及が無く未検証のため、まず実測値をダンプする。
    // 下記のTCR_EL2値はE2H=0(非VHE)前提で計算しているので、E2H=1なら
    // 続行しない。
    uint64_t hcr;
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
    print_hex("[mmu] HCR_EL2 = 0x", hcr);
    if (hcr & (1ULL << 34)) {
        fatal_hang("[mmu] HCR_EL2.E2H=1 (VHE) -- 前提と異なるレイアウト。hcr=0x", hcr);
    }

    // TCR_EL2.PS=0b010(40bit PA)が実機でサポートされることの確認。
    uint64_t mmfr0;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    print_hex("[mmu] ID_AA64MMFR0_EL1 = 0x", mmfr0);
    if ((mmfr0 & 0xFu) < 2u) {
        fatal_hang("[mmu] PARange不足(40bit未満)。mmfr0=0x", mmfr0);
    }

    pl011_puts(&debug_uart, "[mmu] building page tables...\n");
    mmu_build_tables();
    print_hex("[mmu] l1_table @ 0x", (uint64_t)l1_table);
    print_hex("[mmu] l2_table @ 0x", (uint64_t)l2_table);
    print_hex("[mmu] __dma_bss_start = 0x", (uint64_t)__dma_bss_start);

    // ここに到達する時点でMMU/キャッシュは元々無効(上のチェックで
    // 既に有効なら早期returnしている)なので、mmu_build_tables()の書き込み
    // は最初からキャッシュを経由せず物理RAMへ直接反映されている --
    // 明示的なクリーンは不要。

    __asm__ volatile("dsb ish");
    // この呼び出し時点(cpuonより前)ではcore1はまだPSCI CPU_ONで起動
    // されておらずMMUを一切使っていないため、他コアへ向けたTLB
    // invalidateのbroadcast(is)は不要 -- 自コア(core0)のローカル
    // invalidateだけで十分(マルチコア化 Phase 2、mmu_init_secondary()
    // 参照 -- あちらも同じ理由で自コアのみのローカルinvalidateを行う)。
    __asm__ volatile("tlbi alle2");
    __asm__ volatile("dsb ish");
    __asm__ volatile("isb");

    // MAIR_EL2: Attr0=Normal WB, Attr1=Device-nGnRnE。
    uint64_t mair = ((uint64_t)MAIR_ATTR_DEVICE_NGNRNE << 8) | (uint64_t)MAIR_ATTR_NORMAL_WB;

    // TCR_EL2(HCR_EL2.E2H=0前提): T0SZ=25(39bit VA)、IRGN0=ORGN0=0b01(WB
    // RA/WA)、SH0=0b11(Inner Shareable)、TG0=0b00(4KB granule)、
    // PS=0b010(40bit PA)、bit23/bit31=RES1。RES1の位置はU-Bootの
    // `TCR_EL2_RSVD = (1U<<31 | 1<<23)`(arch/arm/include/asm/system.h)で
    // 裏取り済み(TCR_EL1のRES1はbit31のみで、EL2はbit23が追加される点に
    // 注意 — 記憶だけに頼らずソースで確認した)。
    uint64_t tcr = 0x80823519ULL;
    print_hex("[mmu] MAIR_EL2 = 0x", mair);
    print_hex("[mmu] TCR_EL2 = 0x", tcr);

    __asm__ volatile("msr mair_el2, %0" : : "r"(mair));
    __asm__ volatile("msr tcr_el2, %0" : : "r"(tcr));
    __asm__ volatile("msr ttbr0_el2, %0" : : "r"((uint64_t)l1_table));
    __asm__ volatile("isb");

    pl011_puts(&debug_uart, "[mmu] enabling MMU (SCTLR_EL2.M"
#if MMU_PHASE_B_CACHE_RAM
                              "/C/I"
#endif
                              ")...\n");
    // フルの定数書き込みではなくread-modify-writeにする。TF-Aが起動時に
    // 設定した他のビット(RES1候補等、CPU実装依存)を壊さないため。
    // A(アライメントフォルト強制)/SA(SPアライメントチェック)は有効化
    // しない — 新規のフォルト源を増やすだけでメリットが無い。
    __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
    sctlr |= (1ULL << 0);   // M: MMU有効化(フェーズA/B共通)
#if MMU_PHASE_B_CACHE_RAM
    // C/Iはフェーズ B(RAMをNormal cacheable化した後)でのみ有効化する。
    // フェーズAは全域Device-nGnRnEのままMMUの配線だけを検証する段階なので、
    // コード自体がDevice属性の領域から実行されている間にI(命令キャッシュ)
    // だけを有効化するという、検証していない組み合わせを持ち込まない
    // (実機でこれが原因と見られる深刻な性能劣化・再送多発を確認したため
    // 明示的に分離した — Mだけを変数として切り分けるのがフェーズAの
    // 目的そのもの)。
    sctlr |= (1ULL << 2);   // C: データキャッシュ有効化
    sctlr |= (1ULL << 12);  // I: 命令キャッシュ有効化
#endif
    __asm__ volatile("msr sctlr_el2, %0" : : "r"(sctlr));
    __asm__ volatile("isb");

    pl011_puts(&debug_uart, "[mmu] MMU enabled.\n");
}

// マルチコア化 Phase 2(mmu.h参照): core1専用。core0のmmu_init()と対を
// なすが、ページテーブルの構築(mmu_build_tables())は一切行わない --
// l1_table/l2_table(MMU_TABLES_BASE)はcore0が既に構築済みのものを
// そのまま使う。行うのはコアごとに独立したレジスタ(MAIR_EL2/TCR_EL2/
// TTBR0_EL2/SCTLR_EL2)への設定だけ。
void mmu_init_secondary(void)
{
    // mmu_init()と同じ再入対策(exception_handler()経由で_start ->
    // secondary_entry -> secondary_main -> ここへ戻ってくる場合、
    // SCTLR_EL2は前回のフォルトをまたいでリセットされないため既に
    // 有効な状態から呼ばれうる)。無効化して作り直す経路は用意しない
    // (mmu_init()の「再入の設計」節と全く同じ理由 -- 恒等写像・
    // マッピング方式はコア非依存なので、既に有効なら常にそのまま
    // 正しく使える)。
    // マルチコア化 Phase 5(~/.claude/plans/wondrous-baking-gadget.md
    // 参照)でこのファイル全体にUART排他ロック(pl011.cのpl011_lock()/
    // pl011_unlock())を導入したが、この関数内の2箇所のpl011_puts()
    // (このすぐ下、および関数末尾)は意図的にロックしないままにしてある
    // -- ロックを安全に使うにはcore1自身のMMU/キャッシュが既にcore0の
    // マッピングと一致した状態である必要がある(smp.cのsecondary_main()
    // コメント参照)が、この関数自体がまさにその「一致させる」処理
    // そのものであり、呼び出し時点でまだ完了していない。呼び出し元の
    // secondary_main()がこの関数から戻った直後(コヒーレンシが保証
    // された時点)にpl011_lock_reset()を呼んでからロックを使い始める
    // 設計にしたため、この関数内の2つの短い診断メッセージだけは
    // Phase 2時代と同じ「ロック無し、最悪でも文字化けするだけ」の
    // 割り切りのまま残す。
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
    if (sctlr & 1ULL) {
        pl011_puts(&debug_uart, "[mmu2] already enabled on this core, reusing.\n");
        return;
    }

    // HCR_EL2.E2Hはコアごとのレジスタだが、4コアとも同一のCortex-A76
    // でTF-Aの起動シーケンスも共通のため、core0で確認済みの前提
    // (非VHE)がcore1でも成立するはず -- 万一崩れていたら黙って誤動作
    // させず確実に停止する(mmu_init()と同じ方針)。
    uint64_t hcr;
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
    if (hcr & (1ULL << 34)) {
        fatal_hang("[mmu2] HCR_EL2.E2H=1 (VHE) on secondary core -- unexpected. hcr=0x", hcr);
    }

    // MAIR_EL2/TCR_EL2はmmu_init()と全く同じ値(コア非依存の定数) --
    // ページテーブル自体を共有している以上、両コアで解釈が一致していな
    // ければならない。
    uint64_t mair = ((uint64_t)MAIR_ATTR_DEVICE_NGNRNE << 8) | (uint64_t)MAIR_ATTR_NORMAL_WB;
    uint64_t tcr = 0x80823519ULL;

    // このコア(core1)はここまでMMUを一切使っていないため、TLBの内容は
    // アーキテクチャ上未規定 -- 自コアのローカルinvalidateだけで十分
    // (mmu_init()側の同種コメント参照、他コアのTLBへ影響する変更は
    // 行っていないのでbroadcastは不要)。
    __asm__ volatile("dsb ish");
    __asm__ volatile("tlbi alle2");
    __asm__ volatile("dsb ish");
    __asm__ volatile("isb");

    __asm__ volatile("msr mair_el2, %0" : : "r"(mair));
    __asm__ volatile("msr tcr_el2, %0" : : "r"(tcr));
    __asm__ volatile("msr ttbr0_el2, %0" : : "r"((uint64_t)l1_table));
    __asm__ volatile("isb");

    __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
    sctlr |= (1ULL << 0);   // M
#if MMU_PHASE_B_CACHE_RAM
    sctlr |= (1ULL << 2);   // C
    sctlr |= (1ULL << 12);  // I
#endif
    __asm__ volatile("msr sctlr_el2, %0" : : "r"(sctlr));
    __asm__ volatile("isb");

    pl011_puts(&debug_uart, "[mmu2] MMU enabled on secondary core.\n");
}
