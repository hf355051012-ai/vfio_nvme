#ifndef RXCOPY_H
#define RXCOPY_H

#include <stdint.h>

/* ============================================================================
 * RX コピーオフロード(core0 producer / core1 consumer、2026-08-13)
 *
 * push型NVMe/TCP受信の唯一のコピー(RQバッファ→ram_disk[slba])を、受信・ACKを
 * 担う core0 から切り離し、専任の core1 が裏で実行するための SPSC(単一生産者・
 * 単一消費者)ジョブリング。目的は「コピーCPU時間をワイヤ待ちの陰へ隠す」こと
 * (CLAUDE.md「なぜCPU処理をワイヤ待ちの裏で実行できないか」の議論参照)。
 *
 * 正しさの要:
 *  - **RQバッファ寿命**: core1 がコピー元(RQバッファ、受信ゼロコピー)を読み
 *    終える前に mlx5_net がそのバッファを再武装(NICへ返却)するとNICが上書き
 *    して破損する。そこで submit のたびに単調増加する「submitted seq」を返し、
 *    mlx5_net は各受信フレームの watermark(=そのフレーム処理後の submitted 値)
 *    を記録、rxcopy_done() がその watermark に達するまで再武装しない。
 *  - **CQE同期**: あるwriteコマンドの全データコピーが終わる前にCQEを返すと
 *    ホストは完了と誤認する。nvmet はコマンドの watermark を記録し、
 *    rxcopy_done() が達してから dispatch(CQE)する。
 *
 * フラグ off(既定)時は submit されないので watermark は据え置きのまま=既存の
 * 同期コピー経路と完全に同一挙動(mlx5_net/nvmet 双方、offが既定)。
 * ========================================================================== */

/* オフロード有効/無効(既定 off)。有効化時は core1 を起動し worker が回る。 */
int  rxcopy_enabled(void);
void rxcopy_set_enabled(int on);   /* 1で有効化(core1起動含む)、0で無効化 */

/* core0: 1コピー分をリングへ積む(実コピーはしない)。戻り値=この投入後の
 * submitted seq(単調増加)。リング満杯時は core1 が消費するまで短くスピン
 * する(core1 はコピーが速いため通常は詰まらない)。 */
uint32_t rxcopy_submit(const volatile uint8_t *src, volatile uint8_t *dst, uint32_t len);

/* 現在の submitted / done seq(単調増加、cross-core で読む)。 */
uint32_t rxcopy_submitted(void);
uint32_t rxcopy_done(void);

/* core1: リングに溜まったコピーを可能な限り処理する(smp.c の core1 ループから
 * 毎周回呼ぶ)。off または空なら即座に戻る。 */
void rxcopy_worker_drain(void);

#endif /* RXCOPY_H */
