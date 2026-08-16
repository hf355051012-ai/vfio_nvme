#ifndef ERR_H
#define ERR_H

/* ================================================================
 * err.h — PCIe AER / RP1 Ethernet(GEM) エラーレジスタ診断 — フェーズ5
 *
 * TX/RXの不具合調査時に、ハードウェアレベルで実際にエラーが記録されて
 * いないかを直接確認するための診断ヘルパ。「見た目の症状(TXタイムアウト
 * 等)」と「実際に何が起きているか」を切り分けるために、推測ではなく
 * ハードウェア自身のエラーレポート機構(AER、GEMのTSR)を見る。
 * ================================================================ */

/* PCIeルートポート(bus0)とRP1(bus1)双方のAER(Advanced Error Reporting)
 * Correctable/Uncorrectable Error Statusと、RP1 Ethernet(GEM)のTSR
 * (Transmit Status Register、TXフレーム破損等を示すBEXビット含む)を
 * 読み、0でなければ内容をログに出す(読んだレジスタはwrite-1-clearで
 * クリアする)。pcie_rc_init()実行後(RP1のコンフィグ空間にアクセス
 * できる状態)に呼ぶこと。
 * 戻り値: 1=何らかのエラービットが検出された、0=クリーン */
int err_check_all(void);

#endif /* ERR_H */
