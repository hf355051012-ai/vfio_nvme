/* AES-128-GCM の 8 ブロックのループ本体(AVX、x86-64 System V)。
 *
 * **このファイルは手で編集しない。** 生成元は tools/gen_aes_asm.py(非公開。
 * python3 tools/gen_aes_asm.py src/crypto_aes_x86.S)。並びを変えるときは crypto_aes.c の
 * C の実装(aes8 / ghash8_mem / kara_acc / kara_fold / gf_reduce)と同じ計算になっていることを
 * tools/crypto_check.c の OpenSSL との突き合わせで確かめる。
 *
 * C の実装との違いは並べ方だけである: **AES の 1 ラウンド(8 本の aesenc)の間に、
 * GHASH の 1 ブロック分の掛け算(Karatsuba 法で 3 回の pclmulqdq)を挟み、
 * 9 ラウンド目に還元を挟む**(OpenSSL の aesni-gcm と同じ考え方)。AES は
 * port 0、掛け算は port 5 の演算器を使うので、交互に並べると両方が同時に埋まり、
 * port 0 に AES 以外の命令が入りにくくなる。C の組込み関数で同じ並べ方をすると
 * コンパイラがレジスタ(16 本)に収めきれずに退避が増えたので、ここだけ手で並べる。
 *
 * void crypto_aesgcm8_avx(const uint8_t *in,       rdi  入力(8 ブロック x iters)
 *                         uint8_t *out,            rsi  出力(in と同じでもよい)
 *                         size_t iters,            rdx  8 ブロックの組の数(1 以上)
 *                         const crypto_aes128gcm_t *c,  rcx  鍵と H の各乗
 *                         uint8_t x[16],           r8   GHASH の値(C の __m128i の並び)。読んで書き戻す
 *                         const uint8_t ctr[16],   r9   1 本目のカウンタのブロック(IV 12 バイト + BE 32 ビット)
 *                         const uint8_t *gh);      [rsp+8]  畳む 8 ブロックの先頭(組ごとに 128 進む)
 *
 * 組 k ごとに: x = GHASH(x, gh + 128k の 8 ブロック)、out + 128k = in + 128k ^ AES(ctr + 8k ..)。
 *   暗号化では gh = out - 128(1 つ前に書き終えた暗号文)、復号では gh = in(今の暗号文。
 *   書き込みより前に読むので in == out でもよい)。
 *
 * レジスタ: xmm0-7 AES の 8 本 / xmm8 lo / xmm9 hi / xmm10 mid / xmm11 x /
 *           xmm12, xmm13 作業用 / xmm14 1 本目のカウンタのブロック / r11d カウンタの値。
 */
    .intel_syntax noprefix
    .section .rodata
    .balign 16
.Lbswap:
    .byte 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
.Linc1:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
.Linc2:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
.Linc3:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3
.Linc4:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4
.Linc5:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5
.Linc6:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6
.Linc7:
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7

    .text
    .globl crypto_aesgcm8_avx
    .type crypto_aesgcm8_avx, @function
crypto_aesgcm8_avx:
    mov     r10, [rsp + 8]                  /* gh */
    test    rdx, rdx
    jz      .Ldone
    vmovdqu xmm11, [r8]                     /* x */
    vmovdqu xmm14, [r9]                     /* 1 本目のカウンタのブロック */
    mov     r11d, [r9 + 12]
    bswap   r11d                            /* カウンタの値 */
.Lloop:
    /* ---- カウンタ 8 本。末尾 1 バイトが 8 本目まで桁上がりしなければ足すだけ ---- */
    mov     eax, r11d
    and     eax, 0xff
    cmp     eax, 248
    ja      .Lslow
    vpxor   xmm0, xmm14, [rcx + 0]
    vpaddb  xmm1, xmm14, [rip + .Linc1]
    vpxor   xmm1, xmm1, [rcx + 0]
    vpaddb  xmm2, xmm14, [rip + .Linc2]
    vpxor   xmm2, xmm2, [rcx + 0]
    vpaddb  xmm3, xmm14, [rip + .Linc3]
    vpxor   xmm3, xmm3, [rcx + 0]
    vpaddb  xmm4, xmm14, [rip + .Linc4]
    vpxor   xmm4, xmm4, [rcx + 0]
    vpaddb  xmm5, xmm14, [rip + .Linc5]
    vpxor   xmm5, xmm5, [rcx + 0]
    vpaddb  xmm6, xmm14, [rip + .Linc6]
    vpxor   xmm6, xmm6, [rcx + 0]
    vpaddb  xmm7, xmm14, [rip + .Linc7]
    vpxor   xmm7, xmm7, [rcx + 0]
    jmp     .Laes
.Lslow:                                     /* 8 本をそれぞれ 32 ビットで足して作る */
    lea     eax, [r11d + 0]
    bswap   eax
    vpinsrd xmm0, xmm14, eax, 3
    vpxor   xmm0, xmm0, [rcx + 0]
    lea     eax, [r11d + 1]
    bswap   eax
    vpinsrd xmm1, xmm14, eax, 3
    vpxor   xmm1, xmm1, [rcx + 0]
    lea     eax, [r11d + 2]
    bswap   eax
    vpinsrd xmm2, xmm14, eax, 3
    vpxor   xmm2, xmm2, [rcx + 0]
    lea     eax, [r11d + 3]
    bswap   eax
    vpinsrd xmm3, xmm14, eax, 3
    vpxor   xmm3, xmm3, [rcx + 0]
    lea     eax, [r11d + 4]
    bswap   eax
    vpinsrd xmm4, xmm14, eax, 3
    vpxor   xmm4, xmm4, [rcx + 0]
    lea     eax, [r11d + 5]
    bswap   eax
    vpinsrd xmm5, xmm14, eax, 3
    vpxor   xmm5, xmm5, [rcx + 0]
    lea     eax, [r11d + 6]
    bswap   eax
    vpinsrd xmm6, xmm14, eax, 3
    vpxor   xmm6, xmm6, [rcx + 0]
    lea     eax, [r11d + 7]
    bswap   eax
    vpinsrd xmm7, xmm14, eax, 3
    vpxor   xmm7, xmm7, [rcx + 0]
.Laes:
    /* ---- ラウンド 1 + GHASH の 1 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 16]
    vaesenc     xmm1, xmm1, [rcx + 16]
    vaesenc     xmm2, xmm2, [rcx + 16]
    vaesenc     xmm3, xmm3, [rcx + 16]
    vmovdqu xmm12, [r10 + 0]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpxor   xmm12, xmm12, xmm11
    vpclmulqdq xmm8, xmm12, [rcx + 288], 0x00
    vpclmulqdq xmm9, xmm12, [rcx + 288], 0x11
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm10, xmm13, [rcx + 416], 0x00
    vaesenc     xmm4, xmm4, [rcx + 16]
    vaesenc     xmm5, xmm5, [rcx + 16]
    vaesenc     xmm6, xmm6, [rcx + 16]
    vaesenc     xmm7, xmm7, [rcx + 16]
    /* ---- ラウンド 2 + GHASH の 2 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 32]
    vaesenc     xmm1, xmm1, [rcx + 32]
    vaesenc     xmm2, xmm2, [rcx + 32]
    vaesenc     xmm3, xmm3, [rcx + 32]
    vmovdqu xmm12, [r10 + 16]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpclmulqdq xmm13, xmm12, [rcx + 272], 0x00
    vpxor   xmm8, xmm8, xmm13
    vpclmulqdq xmm13, xmm12, [rcx + 272], 0x11
    vpxor   xmm9, xmm9, xmm13
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm13, xmm13, [rcx + 400], 0x00
    vpxor   xmm10, xmm10, xmm13
    vaesenc     xmm4, xmm4, [rcx + 32]
    vaesenc     xmm5, xmm5, [rcx + 32]
    vaesenc     xmm6, xmm6, [rcx + 32]
    vaesenc     xmm7, xmm7, [rcx + 32]
    /* ---- ラウンド 3 + GHASH の 3 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 48]
    vaesenc     xmm1, xmm1, [rcx + 48]
    vaesenc     xmm2, xmm2, [rcx + 48]
    vaesenc     xmm3, xmm3, [rcx + 48]
    vmovdqu xmm12, [r10 + 32]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpclmulqdq xmm13, xmm12, [rcx + 256], 0x00
    vpxor   xmm8, xmm8, xmm13
    vpclmulqdq xmm13, xmm12, [rcx + 256], 0x11
    vpxor   xmm9, xmm9, xmm13
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm13, xmm13, [rcx + 384], 0x00
    vpxor   xmm10, xmm10, xmm13
    vaesenc     xmm4, xmm4, [rcx + 48]
    vaesenc     xmm5, xmm5, [rcx + 48]
    vaesenc     xmm6, xmm6, [rcx + 48]
    vaesenc     xmm7, xmm7, [rcx + 48]
    /* ---- ラウンド 4 + GHASH の 4 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 64]
    vaesenc     xmm1, xmm1, [rcx + 64]
    vaesenc     xmm2, xmm2, [rcx + 64]
    vaesenc     xmm3, xmm3, [rcx + 64]
    vmovdqu xmm12, [r10 + 48]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpclmulqdq xmm13, xmm12, [rcx + 240], 0x00
    vpxor   xmm8, xmm8, xmm13
    vpclmulqdq xmm13, xmm12, [rcx + 240], 0x11
    vpxor   xmm9, xmm9, xmm13
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm13, xmm13, [rcx + 368], 0x00
    vpxor   xmm10, xmm10, xmm13
    vaesenc     xmm4, xmm4, [rcx + 64]
    vaesenc     xmm5, xmm5, [rcx + 64]
    vaesenc     xmm6, xmm6, [rcx + 64]
    vaesenc     xmm7, xmm7, [rcx + 64]
    /* ---- ラウンド 5 + GHASH の 5 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 80]
    vaesenc     xmm1, xmm1, [rcx + 80]
    vaesenc     xmm2, xmm2, [rcx + 80]
    vaesenc     xmm3, xmm3, [rcx + 80]
    vmovdqu xmm12, [r10 + 64]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpclmulqdq xmm13, xmm12, [rcx + 224], 0x00
    vpxor   xmm8, xmm8, xmm13
    vpclmulqdq xmm13, xmm12, [rcx + 224], 0x11
    vpxor   xmm9, xmm9, xmm13
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm13, xmm13, [rcx + 352], 0x00
    vpxor   xmm10, xmm10, xmm13
    vaesenc     xmm4, xmm4, [rcx + 80]
    vaesenc     xmm5, xmm5, [rcx + 80]
    vaesenc     xmm6, xmm6, [rcx + 80]
    vaesenc     xmm7, xmm7, [rcx + 80]
    /* ---- ラウンド 6 + GHASH の 6 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 96]
    vaesenc     xmm1, xmm1, [rcx + 96]
    vaesenc     xmm2, xmm2, [rcx + 96]
    vaesenc     xmm3, xmm3, [rcx + 96]
    vmovdqu xmm12, [r10 + 80]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpclmulqdq xmm13, xmm12, [rcx + 208], 0x00
    vpxor   xmm8, xmm8, xmm13
    vpclmulqdq xmm13, xmm12, [rcx + 208], 0x11
    vpxor   xmm9, xmm9, xmm13
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm13, xmm13, [rcx + 336], 0x00
    vpxor   xmm10, xmm10, xmm13
    vaesenc     xmm4, xmm4, [rcx + 96]
    vaesenc     xmm5, xmm5, [rcx + 96]
    vaesenc     xmm6, xmm6, [rcx + 96]
    vaesenc     xmm7, xmm7, [rcx + 96]
    /* ---- ラウンド 7 + GHASH の 7 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 112]
    vaesenc     xmm1, xmm1, [rcx + 112]
    vaesenc     xmm2, xmm2, [rcx + 112]
    vaesenc     xmm3, xmm3, [rcx + 112]
    vmovdqu xmm12, [r10 + 96]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpclmulqdq xmm13, xmm12, [rcx + 192], 0x00
    vpxor   xmm8, xmm8, xmm13
    vpclmulqdq xmm13, xmm12, [rcx + 192], 0x11
    vpxor   xmm9, xmm9, xmm13
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm13, xmm13, [rcx + 320], 0x00
    vpxor   xmm10, xmm10, xmm13
    vaesenc     xmm4, xmm4, [rcx + 112]
    vaesenc     xmm5, xmm5, [rcx + 112]
    vaesenc     xmm6, xmm6, [rcx + 112]
    vaesenc     xmm7, xmm7, [rcx + 112]
    /* ---- ラウンド 8 + GHASH の 8 ブロック目 ---- */
    vaesenc     xmm0, xmm0, [rcx + 128]
    vaesenc     xmm1, xmm1, [rcx + 128]
    vaesenc     xmm2, xmm2, [rcx + 128]
    vaesenc     xmm3, xmm3, [rcx + 128]
    vmovdqu xmm12, [r10 + 112]
    vpshufb xmm12, xmm12, [rip + .Lbswap]
    vpclmulqdq xmm13, xmm12, [rcx + 176], 0x00
    vpxor   xmm8, xmm8, xmm13
    vpclmulqdq xmm13, xmm12, [rcx + 176], 0x11
    vpxor   xmm9, xmm9, xmm13
    vpshufd xmm13, xmm12, 0x4e
    vpxor   xmm13, xmm13, xmm12
    vpclmulqdq xmm13, xmm13, [rcx + 304], 0x00
    vpxor   xmm10, xmm10, xmm13
    vaesenc     xmm4, xmm4, [rcx + 128]
    vaesenc     xmm5, xmm5, [rcx + 128]
    vaesenc     xmm6, xmm6, [rcx + 128]
    vaesenc     xmm7, xmm7, [rcx + 128]
    /* ---- ラウンド 9 + 中間項の振り分けと還元(kara_fold / gf_reduce と同じ計算)---- */
    vaesenc     xmm0, xmm0, [rcx + 144]
    vaesenc     xmm1, xmm1, [rcx + 144]
    vaesenc     xmm2, xmm2, [rcx + 144]
    vaesenc     xmm3, xmm3, [rcx + 144]
    vpxor   xmm12, xmm8, xmm9               /* mid ^= lo ^ hi */
    vpxor   xmm10, xmm10, xmm12
    vpslldq xmm12, xmm10, 8                 /* lo ^= mid << 64 */
    vpxor   xmm8, xmm8, xmm12
    vpsrldq xmm12, xmm10, 8                 /* hi ^= mid >> 64 */
    vpxor   xmm9, xmm9, xmm12
    /* 256 ビットの積 (hi:lo) 全体を 1 ビット左へ */
    vpsrld  xmm10, xmm8, 31                 /* t7 */
    vpsrld  xmm11, xmm9, 31                 /* t8 */
    vpslld  xmm8, xmm8, 1
    vpslld  xmm9, xmm9, 1
    vpsrldq xmm12, xmm10, 12                /* t9 */
    vpslldq xmm11, xmm11, 4
    vpslldq xmm10, xmm10, 4
    vpor    xmm8, xmm8, xmm10
    vpor    xmm9, xmm9, xmm11
    vpor    xmm9, xmm9, xmm12
    vaesenc     xmm4, xmm4, [rcx + 144]
    vaesenc     xmm5, xmm5, [rcx + 144]
    vaesenc     xmm6, xmm6, [rcx + 144]
    vaesenc     xmm7, xmm7, [rcx + 144]
    /* x^128 + x^7 + x^2 + x + 1 で還元 */
    vpslld  xmm10, xmm8, 31
    vpslld  xmm11, xmm8, 30
    vpslld  xmm12, xmm8, 25
    vpxor   xmm10, xmm10, xmm11
    vpxor   xmm10, xmm10, xmm12
    vpsrldq xmm11, xmm10, 4                 /* t8 */
    vpslldq xmm10, xmm10, 12
    vpxor   xmm8, xmm8, xmm10
    vpsrld  xmm12, xmm8, 1
    vpsrld  xmm13, xmm8, 2
    vpsrld  xmm10, xmm8, 7
    vpxor   xmm12, xmm12, xmm13
    vpxor   xmm12, xmm12, xmm10
    vpxor   xmm12, xmm12, xmm11
    vpxor   xmm8, xmm8, xmm12
    vpxor   xmm11, xmm9, xmm8               /* 新しい x */
    /* ---- ラウンド 10 ---- */
    vaesenclast xmm0, xmm0, [rcx + 160]
    vaesenclast xmm1, xmm1, [rcx + 160]
    vaesenclast xmm2, xmm2, [rcx + 160]
    vaesenclast xmm3, xmm3, [rcx + 160]
    vaesenclast xmm4, xmm4, [rcx + 160]
    vaesenclast xmm5, xmm5, [rcx + 160]
    vaesenclast xmm6, xmm6, [rcx + 160]
    vaesenclast xmm7, xmm7, [rcx + 160]
    /* ---- 入力と混ぜて書く ---- */
    vpxor   xmm0, xmm0, [rdi + 0]
    vmovdqu [rsi + 0], xmm0
    vpxor   xmm1, xmm1, [rdi + 16]
    vmovdqu [rsi + 16], xmm1
    vpxor   xmm2, xmm2, [rdi + 32]
    vmovdqu [rsi + 32], xmm2
    vpxor   xmm3, xmm3, [rdi + 48]
    vmovdqu [rsi + 48], xmm3
    vpxor   xmm4, xmm4, [rdi + 64]
    vmovdqu [rsi + 64], xmm4
    vpxor   xmm5, xmm5, [rdi + 80]
    vmovdqu [rsi + 80], xmm5
    vpxor   xmm6, xmm6, [rdi + 96]
    vmovdqu [rsi + 96], xmm6
    vpxor   xmm7, xmm7, [rdi + 112]
    vmovdqu [rsi + 112], xmm7
    add     rdi, 128
    add     rsi, 128
    add     r10, 128
    add     r11d, 8
    mov     eax, r11d
    bswap   eax
    vpinsrd xmm14, xmm14, eax, 3
    dec     rdx
    jnz     .Lloop
    vmovdqu [r8], xmm11
.Ldone:
    vzeroupper
    ret
    .size crypto_aesgcm8_avx, .-crypto_aesgcm8_avx
    .section .note.GNU-stack, "", @progbits
