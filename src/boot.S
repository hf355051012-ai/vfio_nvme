// Raspberry Pi 5 (BCM2712, AArch64) 用ベアメタルエントリポイント。
// GPUファームウェアが0x80000にロードする(EL2)。

.section ".text.boot"

.global _start

_start:
    // コア判定。BCM2712はMPIDR_EL1のAffinity0が全コア0固定で、コア番号は
    // Affinity1(bits[15:8])にエンコードされる非標準構成(マルチコア化
    // Phase 1で実機確認済み、~/.claude/plans/wondrous-baking-gadget.md
    // 参照 -- Affinity0(bits[1:0])で判定すると全コアが0になり判別
    // できない)。core0(Aff1=0)はprimary_core、それ以外(core1以降、
    // PSCI CPU_ON経由でAff1=1固定で起動される、command.cの`cpuon`参照)は
    // secondary_entryへ分岐する。
    //
    // GPUファームウェアからの冷起動では実機でcore0しか_startに到達しない
    // (Phase 1で診断済み)ため、この分岐が冷起動時に効くのは実質core0の
    // 経路だけ -- しかし`exception_handler()`(exceptions.c)はどのコアで
    // 例外が起きても無条件に`_start`へ分岐する設計であり、core1が
    // secondary_main()の中で例外を起こした場合もここを通る。この分岐が
    // 無い(Aff0だけを見る)実装のままだと、core1の例外がprimary_coreへ
    // 誤って合流し、稼働中のcore0を巻き込んでSP/`.bss`を再初期化する
    // という致命的な事故になる -- マルチコア化 Phase 2で実際に気づき、
    // 修正した。
    mrs     x0, mpidr_el1
    ubfx    x0, x0, #8, #8
    cbz     x0, primary_core
    b       secondary_entry

hang:
    wfe
    b       hang

primary_core:
    // fwupdateの継続magic(x1)を、下のmemzeroに破壊される前に退避する。
    mov     x20, x1

    // adrp+add(PC相対)でSPを設定する。このイメージは別アドレスにも
    // チェインロードされるため、絶対リテラルは使えない。
    adrp    x0, __stack_top
    add     x0, x0, :lo12:__stack_top
    mov     sp, x0

    // .bssをゼロクリアする。
    adrp    x0, __bss_start
    add     x0, x0, :lo12:__bss_start
    ldr     x1, =__bss_size
    bl      memzero

    // .dma_bssもゼロクリアする(以前は.bssしかゼロクリアしておらず、
    // 本物のバグだった)。.dma_bssは(NOLOAD)セクション(linker.ld/
    // linker_payload.ld参照)でイメージファイルには一切データを持たず、
    // アドレス空間の予約のみ -- 実際の物理RAM内容はゼロ初期化されず、
    // 電源投入時のDRAM不定値、または(fwupdateでのチェインロード時)
    // 直前に動いていたイメージがそこに残したデータがそのまま残る。
    // 実機で、eth.cのRXリング直後のガード領域(本来は絶対に書き込まれず
    // 常にゼロのはずの純粋な未使用領域)が電源投入直後から既に非ゼロの
    // 規則的なパターン(2エントリ=32バイト周期の繰り返し)で埋まっている
    // ことをerrコマンドの診断機能(eth_check_rx_guard())で確認し、これが
    // 原因だと特定した。RXリング/TXリング記述子(eth.cのs_rx_ring/
    // s_tx_ring)やtcp.cのs_seg_bufs等、GEMのDMAエンジンが直接読み書き
    // する.dma_bss領域全体がこの影響を受けうる。x20(fwupdate継続magic)
    // はここでも破壊されない(memzeroはx0/x1のみ使用)。
    adrp    x0, __dma_bss_start
    add     x0, x0, :lo12:__dma_bss_start
    ldr     x1, =__dma_bss_size
    bl      memzero

    // C言語のコードへジャンプする。
    mov     x0, x20
    bl      main
    b       hang

// x0 = 開始アドレス、x1 = バイト数(8バイトアライメント必須)
memzero:
    cbz     x1, memzero_done
memzero_loop:
    str     xzr, [x0], #8
    subs    x1, x1, #8
    b.gt    memzero_loop
memzero_done:
    ret

// ================================================================
// マルチコア化 Phase 2(セカンダリコア用Cコード実行環境の確立、
// ~/.claude/plans/wondrous-baking-gadget.md参照)専用のエントリ
// ポイント。src/psci.cのpsci_cpu_on()(cpuonシェルコマンド経由)が
// このシンボルのアドレスをentry_point_addressとして渡す。`_start`の
// 例外リカバリ分岐(上記)からも、core1が例外を起こした場合に再度ここへ
// 来る -- どちらの経路でも「まっさらな状態からCスタックを張り直して
// secondary_main()へ入る」という同じ意味になるため、単一のエントリ
// ポイントで両方をカバーできる。
//
// Phase 1ではここでCスタック/MMU/例外ベクタを一切セットアップせずUARTへ
// 1行書いてwfeするだけだったが、Phase 2では専用スタック(linker.ld/
// linker_payload.ldの__stack2_top)を張った上でC関数(secondary_main、
// src/smp.c)へ入り、MMU(mmu_init_secondary())と例外ベクタ
// (exceptions_init()、core0と共有する同一関数)をcore1自身のレジスタへ
// 設定する。Phase 1から引き続き、CLAUDE.md「デバッグ手法」節の手法
// (即値のみでレジスタ構成、スタックフレーム無し)による生UART
// チェックポイントを、Cコードへ入る直前に1回だけ残す -- secondary_main()
// 以降がハングした場合でも「Cスタックの設定はここまで成功した」と
// 切り分けられるようにするため。
// ================================================================
.global secondary_entry
secondary_entry:
    // 専用Cスタックを設定する(adrp+addのPC相対計算 -- primary_coreの
    // __stack_top設定と全く同じ理由で、チェインロードされたどちらの
    // イメージからでも自身のロード位置を正しく指す)。
    //
    // 3コア化: core1(Aff1=1)とcore2(Aff1=2)は同じsecondary_entryを共有
    // するが、専用スタックを使い分ける(2コアが同じ__stack2_topを使うと
    // 衝突する)。core2(コピーオフロード専任)は__stack3_top、それ以外
    // (core1)は__stack2_top。役割の分岐はsecondary_main()側がsmp_core_
    // index()で行う。x1を作業用に使う(このエントリはprimary_coreと違い
    // 入ってくるx1を必要としない)。ラベルは後続のUARTチェックポイントの
    // ループが使う1:/2:/3:と衝突しないよう7:/8:を使う。
    mrs     x1, mpidr_el1
    ubfx    x1, x1, #8, #8
    cmp     x1, #2
    b.eq    7f
    adrp    x0, __stack2_top
    add     x0, x0, :lo12:__stack2_top
    mov     sp, x0
    b       8f
7:
    adrp    x0, __stack3_top
    add     x0, x0, :lo12:__stack3_top
    mov     sp, x0
8:

    // 生UARTチェックポイント。UART base
    // (board.hのDEBUG_UART_BASE=0x107d001000と同期させること)。
    mov     x9, #0x1000
    movk    x9, #0x7d00, lsl #16
    movk    x9, #0x0010, lsl #32

    adr     x10, secondary_msg
1:
    ldrb    w11, [x10], #1
    cbz     w11, 2f
3:
    // PL011_FR(offset 0x18)のTXFF(bit5, 0x20)が立っている間は待つ
    ldr     w12, [x9, #0x18]
    tst     w12, #0x20
    b.ne    3b
    // PL011_DR(offset 0x00)へ1バイト書き込む
    str     w11, [x9, #0x00]
    b       1b
2:
    bl      secondary_main
    // secondary_main()はハートビートを刻む空ループのまま戻らない設計だが、
    // primary_coreの`bl main; b hang`と同じく、万一戻ってきた場合の
    // 安全網としてwfeループを残す。
secondary_hang:
    wfe
    b       secondary_hang

secondary_msg:
    .asciz "secondary_entry: C stack ready, entering secondary_main\r\n"
