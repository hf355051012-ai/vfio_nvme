#include <stddef.h>

/* ================================================================
 * string_min.c -- freestanding memset/memcpy/memmove の最小実装
 * (RPi5 ベアメタル platform、RPI5_PLATFORM_OBJS)。
 *
 * -ffreestanding でも GCC は「集合体(構造体/配列)の代入・ゼロ初期化」を
 * memcpy/memset 呼び出しへ下ろすことが許されている。このプロジェクトは
 * -nostdlib(libc 無し)のため、それらのシンボルを自前で提供する必要がある。
 * これまでは集合体操作が小さくインライン展開されていたため不要だったが、
 * x86-vfio-port Phase 2 段階4で mlx5_dev_t が DMA バッファアドレス群の
 * 追加で大きくなり、`s_last_dev0 = *dev0`(構造体コピー)/
 * `s_dev_pf0 = (mlx5_dev_t){0}`(ゼロ初期化)がインライン閾値を超えて
 * memcpy/memset 呼び出しを生成するようになったため追加した。
 *
 * これらが実際に使われるのは **CPU 側の通常構造体**(mlx5_dev_t 等、
 * スカラーフィールドの集まり、自然アライン済み)の集合体操作のみ。DMA
 * バッファの初期化・コピーは引き続き volatile を使った明示ループ
 * (CLAUDE.md「ローカルスクラッチバッファへの逐次1バイト代入も volatile が
 * 必須」節、nvmetr_zero_v() 等)で行われており、それらは volatile のため
 * コンパイラが memcpy/memset へ置換できない -- したがってこの実装が DMA
 * バッファのワイドストア結合バグ(SCTLR.A アライメントフォルト)を
 * 誘発することはない。実装自体もバイト単位で、ワイドアクセスを一切
 * 行わないため安全側。x86-linux(hosted)では libc がこれらを提供するため
 * この翻訳単位はリンクしない(Makefile の RPI5_PLATFORM_OBJS)。
 * ================================================================ */

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    unsigned char v = (unsigned char)c;
    for (size_t i = 0; i < n; i++) {
        d[i] = v;
    }
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0) {
        return dst;
    }
    if (d < s) {
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }
    return dst;
}
