#ifndef PSCI_H
#define PSCI_H

#include <stdint.h>

/* PSCI(Power State Coordination Interface)経由でのセカンダリコア起動
 * (マルチコア化 Phase 1、~/.claude/plans/wondrous-baking-gadget.md参照)。
 * dtb確認済み: PSCIのmethod="smc"(PSCI 1.0/0.2)。TF-AがSMC経由でPSCI
 * サービスを提供している前提だが、これが実機で実際に機能するかは
 * 未検証 -- 本ファイルはその成立性を確認するための最小実装。 */

/* PSCI_VERSIONを呼び、バージョン値を返す(上位16bit=major, 下位16bit=minor)。
 * smc命令実行自体が実機でハングするリスクを考慮し、呼び出し前後で
 * UARTへ診断ログを出す(CLAUDE.md「デバッグ手法」節の流儀)。 */
uint64_t psci_version(void);

/* CPU_ON(64bit版)を呼び、target_cpuで指定したコア(MPIDR形式、今回は
 * 単純に affinity0 = 1 でよい)をentry_point_addressから起動する。
 * context_idは今回未使用(0固定でよい)。
 * 戻り値: 0=SUCCESS、負値=PSCIエラーコード(psci_error_str()参照)。 */
int64_t psci_cpu_on(uint64_t target_cpu, uint64_t entry_point_address, uint64_t context_id);

/* PSCI戻り値を人間可読文字列に変換する(exceptions.cのesr_ec_name()と同じ流儀)。 */
const char *psci_error_str(int64_t ret);

/* AFFINITY_INFO(64bit版)を呼び、target_affinityで指定したコアの電源状態を
 * 返す(実機でCPU_ONがALREADY_ONを返すのにsecondary_entryのUART出力が
 * 一切現れない謎の切り分け用、2026-08-08追加)。lowest_affinity_levelは
 * 0固定でよい(単一クラスタ、コア単位の粒度のみ扱う)。
 * 戻り値: 0=ON, 1=OFF, 2=ON_PENDING、負値=PSCIエラーコード。 */
int64_t psci_affinity_info(uint64_t target_affinity, uint64_t lowest_affinity_level);

#endif /* PSCI_H */
