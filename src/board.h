#ifndef BOARD_H
#define BOARD_H

// Raspberry Pi 5 (BCM2712) の物理アドレス定義。導出根拠は
// /home/fukud/.claude/plans/rippling-stirring-mountain.md 参照。

// SoCローカルのデバッグUART(PL011)。RP1/PCIeの先ではない。
#define DEBUG_UART_BASE     0x107d001000ULL

// TF-Aが実際に使っている値(dtbのclk-uartとは異なる)。
#define DEBUG_UART_CLK_HZ   44000000u

// GPUファームウェアがプライマリイメージをロードするアドレス(linker.ld参照)。
#define PRIMARY_BASE    0x80000ULL

// fwupdateが受信イメージをステージングするアドレス(linker_payload.ld参照)。
#define LOAD_ADDR       0x300000ULL
#define LOAD_MAX_SIZE   0x1000000ULL

// Power Management: ウォッチドッグによるフルリセット。
#define PM_BASE                     0x107d200000ULL
#define PM_RSTC                     (PM_BASE + 0x1c)
#define PM_RSTS                     (PM_BASE + 0x20)
#define PM_WDOG                     (PM_BASE + 0x24)
#define PM_PASSWORD                 0x5a000000u
#define PM_RSTC_WRCFG_MASK          0x30u
#define PM_RSTC_WRCFG_FULL_RESET    0x20u
#define PM_RESET_TIMEOUT            10u

// PCIe2(x4、ドメイン2) -- RP1を収容する内部リンク。
#define PCIE_RC_BASE            0x1000120000ULL

// rescal(SERDES)リセット。
#define RESCAL_BASE             0x1000119500ULL

// 汎用の"bridge"リセット。
#define BRIDGE_RESET_BASE       0x1001504318ULL
#define BRIDGE_RESET_ID         44u

// アウトバウンドウィンドウ: このCPUアドレス範囲がPCIバスアドレス0x0..に変換される。
#define PCIE_OUTBOUND_CPU_BASE  0x1f00000000ULL
#define PCIE_OUTBOUND_SIZE      0x100000000ULL

// PCIe(x1、ドメイン1) -- SoC直結の外部M.2/FFCコネクタ(config.txtの
// dtparam=pciex1が有効化するリンクそのもの)。ConnectXはこちらに接続。
// dtb(boot/bcm2712-rpi-5-b.dtb)をdtcで逆コンパイルし、aliasesノードの
// `pciex1 = "/axi/pcie@1000110000"`で物理コネクタとの対応を確認済み
// (推測ではない -- ~/.claude/plans/imperative-conjuring-stallman.md参照)。
// レジスタブロック構造はPCIE_RC_BASE(ドメイン2、RP1)と同一(reg size同じ
// 0x9310)なので、pcie.cのR_MISC_*/R_RC_*オフセット定義がそのまま使える。
#define PCIE1_RC_BASE           0x1000110000ULL

// resets = <0x23 0x24 0x2b>(dtb) -- rescalはRESCAL_BASEと共有の物理ブロック
// (全PCIeインスタンス共通)。bridgeリセットのidだけがPCIE_RC_BASE用(0x2c=44)
// と異なる。
#define PCIE1_BRIDGE_RESET_ID   43u

// アウトバウンドウィンドウ: dtbのpcie@1000110000 rangesエントリ1
// (非prefetchable、CPU 0x1b80000000 <-> PCI 0x80000000、2GB)から導出。
#define PCIE1_OUTBOUND_CPU_BASE 0x1b80000000ULL
#define PCIE1_OUTBOUND_SIZE     0x80000000ULL

// ConnectX(mlx5)のDMAバッファ専用領域。`.dma_bss`(linker.ld、net_buf.c/
// eth.c/tcp.cのRP1 DMAバッファが自動的に詰め込まれる共有NOLOADセクション、
// 固定2MBブロック0x1400000-0x1600000)とは完全に独立した、固定物理アドレス
// の専用領域(mmu.cが複数のL2ブロックとしてDevice-nGnRnEにマップする)。
//
// 128MB確保している理由: MANAGE_PAGES(GIVE)でFWへ譲渡するスクラッチページ
// の必要量が、フェーズ(boot/init)ごとに大きく異なることが実機で判明した
// (boot pagesは6ページ=24KBで足りたが、init pagesは2489ページ=約9.7MBを
// 要求した、CLAUDE.md「ConnectX(mlx5) HCA初期化」節参照)。将来EQ/CQ/WQ等
// 追加のDMA構造体も必要になる見込みのため、当面の実測値(約10MB)に対して
// 十分な余裕(ユーザー指示により128MB)を確保しておく。
//
// **この領域を実際に使うには、SDカードのkernel_2712.imgを本ビルドへ
// 実際に書き換えて真のコールドブートを行う必要がある。** チェインロード
// した`payload_2712.img`は、SDカード上のプライマリが最後に実際に
// `mmu_build_tables()`を実行した時点のページテーブルをそのまま再利用する
// ため(mmu.c「再入の設計」参照 — SCTLR_EL2の無効化書き込み自体が実機で
// ハングするため、既に有効なら即座に抜ける設計を変更できない)、この領域を
// 新設するmmu.cの変更は、SDカードの物理的な書き換えを経ない限り一切反映
// されない(実機で`0x1700000`へのアクセスがTranslation faultになることで
// 確認済み)。
//
// `MLX5_DMA_BASE`は元々`.dma_bss`の固定2MBブロック(0x1400000-0x1600000)の
// 直後、`0x1600000`に置いていた -- ただしこれは「`.dma_bss`より手前の
// 通常`.bss`が小さい(20MB未満)」という前提に依存した値だった。
// `.dma_bss`自体は`linker.ld`の`. = MAX(., 0x1400000)`によりリンク時の
// 位置カウンタ(≒通常`.bss`の終端)と固定床値`0x1400000`の大きい方に配置
// されるため、通常`.bss`が20MBを超えて成長すると`.dma_bss`はその直後
// (20MBよりずっと後ろ)へ動く。nvmet.cの複数インスタンス対応(RP1+
// ConnectX PF0/PF1、platform_init.c参照 — 各インスタンスが独立した
// RAMディスク(4MB)+書き込みパイプラインバッファ(2MB)を持つため
// 1インスタンスあたり約6MB、4インスタンスで約24MB)により通常`.bss`が
// 約47MBまで成長し、`.dma_bss`もそれに応じて約46MB地点まで動いた結果、
// 旧`MLX5_DMA_BASE`(22MB)からの128MB領域(22MB-150MB)と物理的に衝突する
// ようになった -- mmu.cの起動時衝突検知(`fatal_hang()`)が実機で実際に
// これを検出して停止した(2026-08-02)。
// 修正: 現在の通常`.bss`+`.dma_bss`の終端(約48MB)に対し十分な余裕を
// 持たせ、128MBへ引き上げた(2MBアライン、mmu.cのL2テーブルが2MB粒度の
// ブロック記述子のみで構成されるため)。将来さらに`.bss`が成長した場合は
// 再びこの値を見直すこと -- mmu.cの起動時衝突検知は残っているため、
// 万一再衝突しても(検出困難な形で壊れるのではなく)確実に`fatal_hang()`
// で停止して知らせてくれる。
//
// 2026-08-08、マルチコア化 Phase 4のtcp.c per-core化による`.bss`肥大化
// (DMA_BSS_BASEコメント参照)に伴い128MB→144MBへ移動(MMU_TABLES_BASEの
// 新しい終端130MBに十分な余裕を持たせた後ろ)。サイズ(128MB)自体は不変。
#define MLX5_DMA_BASE 0x9000000ULL // 144MB
#define MLX5_DMA_SIZE 0x8000000ULL // 128MB = 64個の2MB L2ブロック(終端272MB)

// RC_BAR2 インバウンド窓の PCI 側ベース上位32bit(RPi5 の brcmstb RC が
// PCI アドレス 0x10_00000000 を基点に PCI->RAM を張る、CLAUDE.md「DMA には
// 64bit アドレッシングが必要」節)。ConnectX へ渡す DMA(デバイス)アドレスは
// 「CPU 物理アドレス下位32bit | (この値<<32)」。mlx5.h の mlx5_dma_addr() と
// dma_rpi5.c の dma_alloc() が唯一の参照者(以前は両者が個別に 0x10 を定義して
// いた重複を board.h の単一定義へ集約 -- x86-vfio-port Phase 2 段階5)。
// x86-linux では dev=IOVA でこの変換は使わないため、x86 用 board.h はこの
// 定数を持たず mlx5_dma_addr() を platform で再実装する(Phase 3)。
#define MLX5_DMA_ADDR_HI32 0x10u

// `.dma_bss`(RP1 GEMのTX/RXディスクリプタリング置き場、eth.c/net_buf.c/
// tcp.c参照)自体の固定物理アドレス(2026-08-05、実機で発見した本物の
// バグの修正)。以前は`linker.ld`の`. = MAX(., 0x1400000); . = ALIGN(
// 0x200000);`という「.bss直後を2MB境界に丸める」方式だった -- これは
// .bssが大きくなった場合の2MBアライメント自体は保証するが、**プライマリ
// (リンクベース0x80000)とチェインロードされるpayload(リンクベース
// 0x300000、+0x280000シフト)とで、同じソースコードでも位置カウンタの
// 出発点が異なるため、丸め先の2MB境界そのものが両者で一致する保証が
// 無かった**。実機でこれを踏んだ: プライマリの`.dma_bss`は`0x2c00000`
// (mmu_build_tables()がDevice-nGnRnEにマップする2MBブロック)だったが、
// チェインロードしたpayload自身のC変数`s_tx_ring`のリンク時アドレスは
// `0x3142900`付近になっていた -- payloadは`mmu_init()`の早期return
// (CLAUDE.md「MMUは有効」節の「再入の設計」参照、無効化書き込み自体が
// 実機でハングするため変更できない)によりプライマリが構築したページ
// テーブルをそのまま使うため、実際にDevice-nGnRnEとしてマップされて
// いるのは`0x2a00000`-`0x2c00000`のみ -- payloadの`s_tx_ring`はそこから
// 外れ、Normal cacheableな領域に着地していた。TXディスクリプタの書き込み
// (CPU、キャッシュに留まる)とGEMのDMAリード(キャッシュを経由しない)が
// 非コヒーレントになり、`ping`のARP送信が`entry=0`のTXタイムアウトで
// 毎回失敗する形で発現した(前回の「.bss肥大化によるアライメント喪失」
// バグと表面症状は同じだが、原因は別 -- 前回はサイズ超過、今回はプライマリ/
// payload間の不一致)。
// 修正: `MLX5_DMA_BASE`/`MMU_TABLES_BASE`と同じ「`.bss`にもリンクベースにも
// 一切依存しない完全固定の絶対物理アドレス」方式に変更する
// (linker.ld/linker_payload.ldの`. = DMA_BSS_BASE;`、この値と手動で同期を
// 保つこと -- リンカスクリプトはCヘッダをincludeできない)。これにより
// `.dma_bss`はどちらのイメージでビルドしても常に同じ物理アドレスになる。
// 現在の`.bss`終端(実測約44-48MB)に対し十分な余裕を持たせつつ、
// `MMU_TABLES_BASE`(112MB)より手前に置いた。`.bss`がこの値を超えて
// 肥大化した場合、`. = DMA_BSS_BASE`が位置カウンタを後退させようとして
// **リンク時にエラーになる**(GNU ldの仕様、位置カウンタは前進しか
// できない)ため、MMU_TABLES_BASEのような実行時fatal_hang()を別途
// 用意しなくても、プライマリ・payload双方のビルド時点で確実に検知
// できる。
// 2026-08-08、64MB→96MBへ再移動: TCP_RX_BUF_SIZE(tcp.c)を512KB→2MBへ
// 拡張したところ(test.cのTCP_TEST_MAX_LEN拡張に伴う、tcp_priv_t.rx_bufが
// TCP_MAX_CONNS(12)本ぶん肥大化)、通常`.bss`の終端が約68.25MBまで伸び、
// 旧DMA_BSS_BASE(64MB)と重なってリンクエラーになった(GNU ldが位置
// カウンタの後退を検知して停止 -- 上記コメント通り、実行時ではなく
// リンク時に確実に検知できた)。MMU_TABLES_BASE(112MB)より手前かつ
// 新しい`.bss`終端に対し十分な余裕を持つ96MBへ移動した。
//
// 2026-08-08、マルチコア化 Phase 4(~/.claude/plans/wondrous-baking-
// gadget.md参照)で96MB→128MBへ再移動: job.c以外の全モジュール
// (net_buf.c/timestamp.c/ip.c/icmp.c/netctx.c/tcp.c)をper-core化した
// ことで、コアごとに独立配列(`[SMP_MAX_CORES]`)を持つようになった --
// 特にtcp.cの`s_priv[SMP_MAX_CORES][TCP_MAX_CONNS]`(1コネクションあたり
// TCP_RX_BUF_SIZE=2MBのrx_bufを含む)が2倍化し、通常`.bss`の終端が
// 実測約104.03MB(`0x68006ff`)まで伸びた結果、旧DMA_BSS_BASE(96MB)と
// 重なりリンクエラーになった(GNU ldが検知)。新しい`.bss`終端に対して
// 十分な余裕(約24MB)を持つ128MBへ移動した。job.cだけは意図的に
// per-core化せず単一の共有テーブル+スピンロック方式にした
// (smp.hのsmp_spinlock_t参照、ユーザー指示 -- 将来「空いているコアが
// 他コアのジョブを拾って処理する」work-stealingを実現するため)ので、
// job.c自体はこの`.bss`肥大化には寄与していない。
#define DMA_BSS_BASE 0x8000000ULL // 128MB

// mmu.cのL1/L2ページテーブル自体の固定物理アドレス(2026-08-02、実機で
// 発見した本物のバグの修正)。以前はmmu.c内の`static uint64_t
// l1_table[]/l2_table[]`という普通の`.bss`グローバルだった -- これが
// 致命的だった: プライマリ(リンクベース0x80000)がmmu_build_tables()で
// 実際にテーブルを構築する物理アドレスは、プライマリ自身の`.bss`内の
// どこか(このセッションでnvmet.cの複数インスタンス化により`.bss`が
// 約47MBまで肥大化した結果、実機で0x18f5000/0x18f6000付近になった)。
// チェインロードされる`payload_2712.img`は同じソースだがリンクベースが
// 0x300000(LOAD_ADDR、プライマリ+2.5MB)であるため、ペイロード自身の
// `.bss`ゼロクリア範囲(boot.S)は同じ物理アドレス空間内で+2.5MBだけ
// シフトする -- `.bss`が今や約47MBという大きさである以上、このシフトが
// あっても、ペイロードの`.bss`ゼロクリア範囲はプライマリが構築した
// テーブルの物理アドレスを依然として含んでしまう。結果、ペイロードの
// 起動シーケンス(boot.S、`.bss`ゼロクリア)が、MMUが有効なまま今まさに
// 使われているL1/L2テーブルそのものを踏んでゼロ書きし、Translation
// Fault(実機で`far=0x1a00000`、対応するL2エントリのアドレス`0x18f5068`
// が直前にゼロ化されたことを実機のPTEダンプで確認済み)で
// chainload直後にハングする、という形で実機で再現した。
// 修正: `MLX5_DMA_BASE`と同じ「`.bss`から完全に切り離した固定物理
// アドレス」方式に変更する(mmu.c参照、`l1_table`/`l2_table`は
// `static`配列ではなくこのアドレスへの生ポインタになる) -- これにより
// テーブルの物理アドレスがどちらのイメージのリンクベース/`.bss`サイズ
// にも一切依存しなくなり、このクラスのバグが構造的に起きなくなる。
// `.dma_bss`の現在の終端(実測約48MB)から大きな余裕を取り、かつ
// `MLX5_DMA_BASE`(128MB)の手前に置く(mmu.cが起動時に両方との衝突を
// 検証する)。8KB(L1テーブル4KB+L2テーブル4KB、いずれも4KBアライン
// 必須)しか使わないが、将来`.bss`が成長しても踏まれないよう、
// mmu.c側で`__bss_end`(+チェインロード時の最大シフト分)がこのアドレス
// を超えていないかを起動時に検証する。
//
// 2026-08-08、マルチコア化 Phase 4のtcp.c per-core化による`.bss`肥大化
// (DMA_BSS_BASEコメント参照)に伴い112MB→130MBへ移動(DMA_BSS_BASEの
// 新しい終端130MBのすぐ後ろ)。
#define MMU_TABLES_BASE 0x8200000ULL // 130MB
#define MMU_TABLES_SIZE 0x2000ULL    // 8KB (L1テーブル4KB + L2テーブル4KB)

// nvmet.cの常駐サーバインスタンス(nvmet_ctx_t、RAMディスク4MB+書き込み
// パイプラインバッファ2MB等を含む、実測sizeof(nvmet_ctx_t)=0x6021c0≒6.01MB)
// 専用の固定物理アドレス領域(2026-08-07、実機のnmダンプで発見した本物の
// バグの修正)。以前はplatform_init.c/command.cが`static nvmet_ctx_t
// s_nvmet_rp1;`のような普通の`.bss`グローバルとして確保していた --
// これはMMU_TABLES_BASE/DMA_BSS_BASEで既に修正した2件と全く同じ構造的
// 欠陥を抱えていた: fwupdateがXmodem受信したペイロードをステージング
// するLOAD_ADDR(0x300000)..+LOAD_MAX_SIZE(16MB、0x1300000まで)という
// 範囲は、プライマリ(リンクベース0x80000)の`.bss`の先頭付近と物理的に
// 重なる。実機のnmダンプ(aarch64-linux-gnu-nm build/kernel.elf)で確認:
//   s_nvmet_ctx        @ 0x0aeb40 (command.c、`nvmet`手動起動用)
//   s_nvmet_mlx5_pf1   @ 0x6f0d00 (platform_init.c)
//   s_nvmet_mlx5_pf0   @ 0xcf2ec0 (platform_init.c)
//   s_nvmet_rp1        @ 0x12f5080 (platform_init.c)
// いずれもsizeof=0x6021c0(約6.01MB)。LOAD_ADDR..+LOAD_MAX_SIZE=
// [0x300000, 0x1300000)と比較すると、s_nvmet_ctx/mlx5_pf1/mlx5_pf0は
// 本体の大半(数MB単位)が、s_nvmet_rp1も末尾約44KBがこの範囲内に入って
// いた -- つまり4インスタンス全てが重複していた。
// これが意味する実害: `fwupdate`によるXmodem受信は、たとえその瞬間に
// nvmetサーバ(RP1/ConnectX PF0/PF1いずれか、または`nvmet`手動起動)が
// 実際のNVMe/TCPホストへ応答している最中であっても、そのRAMディスク/
// 書き込みパイプラインバッファ/Identify応答バッファを新しいペイロードの
// バイト列で直接上書きしてしまう -- 「次回起動時に古いデータが残る」
// という穏やかな話ではなく、fwupdate実行中のまさにその瞬間に、稼働中の
// セッションのデータが破壊されうる、という重大な問題だった。
// 修正: MLX5_DMA_BASE/DMA_BSS_BASE/MMU_TABLES_BASEと同じ「`.bss`にも
// リンクベースにも一切依存しない完全固定の絶対物理アドレス」方式に
// 変更する(nvmet.hのNVMET_CTX_SLOT()参照)。MLX5_DMA_BASE領域の終端
// 直後に配置し、既存の全予約領域(LOAD_ADDR/DMA_BSS_BASE/MMU_TABLES_BASE/
// MLX5_DMA_BASE)のいずれとも重ならない(nvmet.hの_Static_assert群で
// 検証)。1インスタンスあたり実測サイズ(約6.01MB)に対し余裕を持たせ
// 7MB(2MBアライン)を割り当て、NVMET_MAX_INSTANCES(4)分確保する
// (合計28MB、L1 index 0の1GB窓に十分収まる)。1インスタンスあたりの
// スロットサイズは2MB境界アライン(mmu.cの他の固定領域と同じ流儀)が
// 必要なため、6.01MBの直近上位である7MBではなく8MB(2MBの倍数)にした。
//
// 2026-08-08、マルチコア化 Phase 4のtcp.c per-core化による`.bss`肥大化
// (DMA_BSS_BASEコメント参照)に伴い256MB→272MBへ移動(MLX5_DMA_BASEの
// 新しい終端272MBの直後、以前と同じ「直後に配置」の関係を維持)。
#define NVMET_INSTANCES_BASE     0x11000000ULL // 272MB (MLX5_DMA_BASE終端の直後)
#define NVMET_INSTANCE_SLOT_SIZE 0x11000000ULL  // 272MB/インスタンス (2MBアライン)
                                                // x86専用ツリー: nvmet.h の
                                                // NVMET_NS_LBA_COUNT を 256MB へ
                                                // 拡大したのに合わせた。このツリーは
                                                // x86 専用で、ARM の固定物理アドレス
                                                // レイアウト制約は適用しない。

// mlx5_net.cのRQ(受信)DMA先バッファ用キャッシュ可能領域(2026-08-09、
// ユーザー指摘 -- 実機`ts`計測でセグメントあたり約30-46usかかっていた
// コストの一部が、mlx5_net_poll_recv()がDevice-nGnRnE[MLX5_DMA_BASE
// 領域内]から読み出すコピーに起因している可能性を検証するため)。従来
// RQのDMA先バッファ(MLX5_RQ_DATA_ADDR、mlx5.h)は`MLX5_DMA_BASE`領域
// 内にありDevice-nGnRnEだった -- TX側で以前zero-copy化する前に踏んだ
// のと同型の「非キャッシュ領域への読み書きが遅い」問題が、RX側にも
// 残っていた。
//
// PCIe1のインバウンドRC_BAR2窓(pcie1.cのrc_bar2_offset=0x10_00000000)
// は「PCIバスアドレス0x10_00000000-0x1f_ffffffffをCPU物理アドレス
// 0x0-0xf_ffffffffへ写す」単純なオフセット変換であり、MLX5_DMA_BASE
// 領域内に限らずCPU物理アドレス空間全体(32bit範囲)がConnectXから見て
// 有効なDMA先になる(mlx5_dma_addr()のコメント参照) -- つまりRQのDMA先
// バッファをMLX5_DMA_BASE領域の外、通常のキャッシュ可能RAMへ移しても
// DMAアドレッシング上は問題ない。
//
// NVMET_INSTANCES_BASE領域の終端(272MB+32MB=304MB、2MBアライン)の
// 直後に配置。この領域自体は通常のNormal cacheable RAM(mmu.cで
// 専用のL2ブロックを割り当てる必要が無い、Device領域ではないため)
// なので、MLX5_DMA_BASE等と異なりサイズ自体は2MBアライン必須ではない。
// MLX5_RQ_DATA_SIZE(mlx5.h、256エントリ×10240B=2.5MB)に余裕を持たせ
// 3MB/PFを確保、PF0/PF1の2ポート分。
#define MLX5_RQ_CACHE_BASE    0x13000000ULL // 304MB (NVMET_INSTANCES_BASE終端の直後)
#define MLX5_RQ_CACHE_PF_SIZE 0x300000ULL   // 3MB/PF

// SQ/RQ双方の完了確認用CQバッファ+ドアベルレコード用キャッシュ可能領域
// (2026-08-09、ユーザーへの生TCPスループット・ネック説明で発見 -- 実機
// `ts`計測でCQE刈り取り+CQドアベル更新1回(MTXCタグ)あたり約14-19usかかって
// おり、ペイロードがほぼ0バイトのadminキューkeepaliveパケットでも同水準の
// 遅延が観測された(=データ量に無関係な固定コスト)。これは上記
// MLX5_RQ_CACHE_BASEで対策したのと同型の「Device-nGnRnE[MLX5_DMA_BASE
// 領域内]への非キャッシュアクセスが遅い」問題 -- SQ/RQのCQバッファ
// (`MLX5_SQ_CQ_BUF_ADDR`/`MLX5_CQ_BUF_ADDR`、mlx5.h)とそのドアベル
// レコードは、RQ_DATAだけ移動した後も依然`MLX5_DMA_BASE`領域内に残って
// いた。MLX5_RQ_CACHE_BASEの2PF分(3MB×2=6MB)の終端の直後に配置。
//
// 2026-08-11、ユーザー指示によりRQ用CQを64エントリ(4KB、1ページ)から
// 1024エントリ(64KB、16ページ)へ拡張(mlx5.hのMLX5_CQ_BUF_SIZE/
// MLX5_SQ_CQ_BUF_SIZE参照) -- 非同期送信スロットを増やした際、送信側が
// 実際にそれだけ速くデータを押し込めるようになった結果、受信側の
// `mlx5_net_poll_recv()`が旧64エントリのRQ用CQを排出しきれずハードウェア
// レベルでCQオーバーラン(`status=9`、以後そのCQは新規完了を一切生成
// しなくなる)を実機で誘発した事象への対策。RQのWQE深さ(mlx5.hの
// MLX5_RQ_NUM_WQES=256)は、SW側の排出が完全に止まってもRQ自身がそれ以上
// 完了を生成できない上限でもあるため、CQを256以上にすれば理論上は
// オーバーランしえないが、将来RQ自体を深くする可能性やジッタへの余裕を
// 見て4倍(1024)を採用した。SQ用CQも同じ関数(mlx5_create_cq())で作る
// ため同時に1024へ揃えた(SQ自体はMLX5_SQ_WQE_COUNT=8までしか同時に
// outstandingにならないため1024は極めて過剰だが、メモリは64KB×2/PF程度
// でごく僅かなコストのため統一を優先した)。
// 新しい必要量: RQ用CQバッファ(65536B)+ドアベル(64B、4096アライン→
// 次の4096境界へ切り上げ)+SQ用CQバッファ(65536B)+ドアベル(64B)
// ≈ 約132KB/PF。192KB/PFを確保して余裕を持たせる。
#define MLX5_CQ_CACHE_BASE    0x13600000ULL // 310MB (MLX5_RQ_CACHE_BASE終端[304MB+6MB]の直後)
#define MLX5_CQ_CACHE_PF_SIZE 0x30000ULL    // 192KB/PF (RQ/SQ用CQ各1024エントリ分+ドアベル+余裕)

// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)
// フェーズ(b): RC QP用の完了確認CQ(送受信共有、qpc.cqn_snd==cqn_rcv --
// Linuxのmlx5_ib_create_cq()の基本形と同じ、送受信別々のCQに分ける必然性は
// 無い)。既存のMLX5_CQ_CACHE_BASE(Ethernet SQ/RQ用CQ)と同じ理由(CPUが
// ポーリングするホットパスのため非キャッシュDevice領域を避ける、CLAUDE.md
// 「CQバッファ+ドアベルレコードのキャッシュ可能領域移行」節参照)で、
// その終端(310MB+192KB×2=約310.375MB)の直後に配置。mlx5.hのMLX5_CQ_BUF_
// SIZE(65536B)+MLX5_CQ_DBR_SIZE(64B、4096境界へ切り上げ)で足りるが、
// 既存MLX5_CQ_CACHE_PF_SIZEと同じ192KB/PFを確保して余裕を持たせる。
#define MLX5_QP_CACHE_BASE    0x13660000ULL // 310.375MB (MLX5_CQ_CACHE_BASE終端の直後)
#define MLX5_QP_CACHE_PF_SIZE 0x30000ULL    // 192KB/PF

// ConnectX RoCEv2 NVMe-oF実装計画(~/.claude/plans/peppy-wobbling-lamport.md)
// フェーズ(d): GSI/UD QP用の完了確認CQ(送受信共有)。MLX5_QP_CACHE_BASE
// (RC QP用)と同じ理由・同じサイズクラスで、その終端(310.375MB+192KB×2=
// 約310.75MB)の直後に配置。
#define MLX5_GSI_CACHE_BASE    0x136C0000ULL // 310.75MB (MLX5_QP_CACHE_BASE終端の直後)
#define MLX5_GSI_CACHE_PF_SIZE 0x30000ULL    // 192KB/PF

// ConnectX RoCEv2 NVMe-oF実装計画フェーズ(i)続報(2026-08-13): 実Linux
// ホストは標準通りadmin queue(qid=0)とは別にIOキュー(qid=1)用の独立した
// RDMA CM接続(=別のRC QP)を要求する(フェーズgで「1PFあたりRC QP 1本の
// みで簡略化」としていたのはここで限界を迎えた)。2本目のRC QP用の完了
// 確認CQを、MLX5_QP_CACHE_BASE(1本目、RC QP用)と全く同じ理由・同じ
// サイズクラスで、既存の最終確保領域(MLX5_GSI_CACHE_BASE終端、310.75MB+
// 192KB×2=約311.125MB)の直後に配置する。GSI QP自体は2本作らない(1PFに
// つきGSI/QP1相当は物理的に1つしか存在できないという規約、フェーズdの
// 「宛先QPN=1固定」参照)-- admin queueのCM確立で作られたGSI QPを、IO
// queueのCM確立でもそのまま使い回す(rdma_cm.hのreuse_gsi参照)。
#define MLX5_QP2_CACHE_BASE    0x13720000ULL // 311.125MB (MLX5_GSI_CACHE_BASE終端の直後)
#define MLX5_QP2_CACHE_PF_SIZE 0x30000ULL    // 192KB/PF (MLX5_QP_CACHE_PF_SIZEと同サイズ)

// nvmet_rdma.cのRAMディスク(2026-08-13、ユーザー指示によるサイズ拡張)。
// 当初`nvmet_rdma_ctrl_t`に埋め込みの`.bss`配列(1MB)だったが、`.bss`の
// 残り予算(DMA_BSS_BASEまで約1MB)ではこれ以上ほぼ拡張できないため、
// MLX5_DMA_BASE/DMA_BSS_BASE/MMU_TABLES_BASE/NVMET_INSTANCES_BASE等と
// 同じ「`.bss`にもリンクベースにも依存しない固定物理アドレス」方式へ
// 移行した。MLX5_QP2_CACHE_BASE領域の終端(311.125MB+192KB×2=約
// 311.5MB)の直後に配置し、既存の全予約領域のいずれとも重ならない
// (nvmet_rdma.hの_Static_assert群で検証)。この領域はDevice属性の
// 特別なL2ブロックを必要としない(mmu.cのL1 index 0ループが、.dma_bssと
// mlx5専用DMA領域[MLX5_DMA_BASE]以外の全域を無条件にNormal cacheable
// RAMとしてマップする既存ロジックでそのままカバーされる、MLX5_RQ_
// CACHE_BASE等と同じ理由)。インスタンス0=nvmet_rdma_run_standalone()
// (実ホスト接続用)、インスタンス1=nvme_rdma.cのs_target_ctrl
// (`nvmerdmaconnect`/`nvmermabench`ループバック検証用)。
#define NVMET_RDMA_RAMDISK_BASE      0x13780000ULL // 311.5MB (MLX5_QP2_CACHE_BASE終端の直後)
#define NVMET_RDMA_RAMDISK_SLOT_SIZE 0x10000000ULL // 256MB/インスタンス(2MBアライン)
                                                   // Linux 側と名前空間サイズを
                                                   // 揃えるため 64MB から拡大。
                                                   // x86 では dma_alloc() 経由で
                                                   // DMA プールから確保される
                                                   // (hal_dma.c の DMA_POOL_SIZE)。

#endif
