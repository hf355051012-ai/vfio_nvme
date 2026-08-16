#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <stdint.h>

// vectors.Sのexc_commonが書き込む例外フレーム。
typedef struct {
    uint64_t sp;      // 例外発生時点のSP
    uint64_t vector;  // 発火したベクタ番号 (0-15)
    uint64_t elr;     // ELR_EL2: フォールト/戻り先PC
    uint64_t spsr;    // SPSR_EL2
    uint64_t esr;     // ESR_EL2: 例外シンドローム
    uint64_t far;     // FAR_EL2: フォールトアドレス
    uint64_t x[32];   // x0..x30、x[31]は未使用パディング
} exception_frame_t;

// vector_table (vectors.S) をVBAR_EL2に設定する。
void exceptions_init(void);

// 例外発生時に呼ばれ、フレーム内容を出力して停止する(戻らない)。
void exception_handler(exception_frame_t *frame);

#endif
