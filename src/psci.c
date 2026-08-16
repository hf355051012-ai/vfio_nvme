// psci.c
//
// PSCI(Power State Coordination Interface) SMC呼び出しの最小実装。
// マルチコア化 Phase 1(~/.claude/plans/wondrous-baking-gadget.md参照)専用
// -- 今回はPSCI_VERSION/CPU_ONの2関数のみ。ARM SMC Calling Convention
// (function IDをx0、引数をx1-x3、戻り値をx0で受け取る)に従う。

#include "psci.h"
#include "uart.h"

#define PSCI_FN_VERSION         0x84000000ULL
#define PSCI_FN_CPU_ON_64       0xC4000003ULL
#define PSCI_FN_AFFINITY_INFO_64 0xC4000004ULL

/* smc #0を1回発行し、x0(function_id)/x1-x3(引数)を渡してx0の戻り値を返す。
 * レジスタ変数(register ... asm("xN"))でSMC Calling Conventionのレジスタ
 * 割り当てを明示する -- コンパイラの一般的なレジスタ割り当てに任せると
 * 意図しないレジスタへ引数が乗る可能性があるため。 */
static int64_t psci_smc_call(uint64_t function_id, uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    register uint64_t x0 __asm__("x0") = function_id;
    register uint64_t x1 __asm__("x1") = arg0;
    register uint64_t x2 __asm__("x2") = arg1;
    register uint64_t x3 __asm__("x3") = arg2;
    __asm__ volatile("smc #0"
                      : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                      :
                      : "memory");
    return (int64_t)x0;
}

uint64_t psci_version(void)
{
    uart_printf("[psci] smcを呼び出します (PSCI_VERSION)...\n");
    int64_t ret = psci_smc_call(PSCI_FN_VERSION, 0, 0, 0);
    uart_printf("[psci] smc応答を受信しました (PSCI_VERSION)\n");
    return (uint64_t)ret;
}

int64_t psci_cpu_on(uint64_t target_cpu, uint64_t entry_point_address, uint64_t context_id)
{
    /* target_cpu/entry_point_addressは通常32bitに収まる値のため
     * (unsigned)キャストで表示する -- uart_printf()の%xはuint32_t
     * (va_arg(ap, unsigned int))前提の実装で64bit全体は表示できない
     * (uart_shim.cのcase 'x'/case 'p'参照、上位32bitが切り捨てられる)。 */
    uart_printf("[psci] smcを呼び出します (CPU_ON, target=0x%x entry=0x%x)...\n",
                (unsigned)target_cpu, (unsigned)entry_point_address);
    int64_t ret = psci_smc_call(PSCI_FN_CPU_ON_64, target_cpu, entry_point_address, context_id);
    uart_printf("[psci] smc応答を受信しました (CPU_ON, ret=%d)\n", (int)ret);
    return ret;
}

int64_t psci_affinity_info(uint64_t target_affinity, uint64_t lowest_affinity_level)
{
    uart_printf("[psci] smcを呼び出します (AFFINITY_INFO, target=0x%x)...\n",
                (unsigned)target_affinity);
    int64_t ret = psci_smc_call(PSCI_FN_AFFINITY_INFO_64, target_affinity, lowest_affinity_level, 0);
    uart_printf("[psci] smc応答を受信しました (AFFINITY_INFO, ret=%d)\n", (int)ret);
    return ret;
}

const char *psci_error_str(int64_t ret)
{
    switch (ret) {
    case 0:  return "SUCCESS";
    case -1: return "NOT_SUPPORTED";
    case -2: return "INVALID_PARAMETERS";
    case -3: return "DENIED";
    case -4: return "ALREADY_ON";
    case -5: return "ON_PENDING";
    case -6: return "INTERNAL_FAILURE";
    case -7: return "NOT_PRESENT";
    case -8: return "DISABLED";
    default: return "UNKNOWN";
    }
}
