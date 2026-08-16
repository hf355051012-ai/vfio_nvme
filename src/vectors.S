// AArch64例外ベクタテーブル(EL2)。全16ベクタが汎用レジスタとSP/ELR/
// SPSR/ESR/FARを保存し、exception_handler()を呼ぶ(デバッグ用、戻らない)。

.section ".text"

// x30を最初に、x0を最後にpushすることで昇順のx[0..30]レイアウトになる。
.macro save_all
    stp x30, xzr, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x24, x25, [sp, #-16]!
    stp x22, x23, [sp, #-16]!
    stp x20, x21, [sp, #-16]!
    stp x18, x19, [sp, #-16]!
    stp x16, x17, [sp, #-16]!
    stp x14, x15, [sp, #-16]!
    stp x12, x13, [sp, #-16]!
    stp x10, x11, [sp, #-16]!
    stp x8,  x9,  [sp, #-16]!
    stp x6,  x7,  [sp, #-16]!
    stp x4,  x5,  [sp, #-16]!
    stp x2,  x3,  [sp, #-16]!
    stp x0,  x1,  [sp, #-16]!
.endm

.equ SAVE_ALL_SIZE, 256   // stpが16回 = 256バイト
.equ EXTRA_SIZE,    48    // sp, vector, elr, spsr, esr, far (8バイト x 6)

.macro vector_entry, index
.align 7
    save_all
    mov  w8, #\index
    b    exc_common
.endm

.align 11   // VBAR_EL2は2KBアライメントが必須
.global vector_table
vector_table:
    vector_entry 0
    vector_entry 1
    vector_entry 2
    vector_entry 3
    vector_entry 4
    vector_entry 5
    vector_entry 6
    vector_entry 7
    vector_entry 8
    vector_entry 9
    vector_entry 10
    vector_entry 11
    vector_entry 12
    vector_entry 13
    vector_entry 14
    vector_entry 15

exc_common:
    // 例外発生時点のSP == 現在のsp + SAVE_ALL_SIZE
    add  x9, sp, #SAVE_ALL_SIZE
    sub  sp, sp, #EXTRA_SIZE
    mov  x0, sp                  // x0 = exception_frame_t *

    str  x9, [x0, #0]            // frame.sp
    uxtw x8, w8
    str  x8, [x0, #8]            // frame.vector

    mrs  x1, elr_el2
    str  x1, [x0, #16]           // frame.elr
    mrs  x1, spsr_el2
    str  x1, [x0, #24]           // frame.spsr
    mrs  x1, esr_el2
    str  x1, [x0, #32]           // frame.esr
    mrs  x1, far_el2
    str  x1, [x0, #40]           // frame.far

    bl   exception_handler        // 戻らない

1:  wfe
    b    1b
