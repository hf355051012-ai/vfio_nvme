// platform_init.c
//
// 環境の共通初期化(`platform_init`シェルコマンド、command.cの
// cmd_platform_init()から呼ぶ -- main()からは自動で呼ばない、
// platform_init.hコメント参照)。ユーザー指示:
//   - ファンの回転数を50に設定
//   - RP1のnet initのあとnvmetを起動してコネクト待ちのジョブを起動
//   - ConnectXが接続されている場合は初期化して両ポートともにnvmetの
//     コネクト待ちジョブを起動
//
// nvmet常駐サーバの複数インスタンス対応(CLAUDE.md「nvmet: 複数
// インターフェース同時待受」節参照)により、RP1+ConnectX PF0/PF1の
// 最大3系統が完全に独立したセッション(別々のRAMディスク・別々の
// TCPリスナー・別々のjob.hジョブ)として同時に稼働できる。

#include "platform_init.h"
#include "pcie.h"
#include "fan.h"
#include "eth.h"
#include "arp.h"
#include "ip.h"
#include "netctx.h"
#include "mlx5.h"
#include "nvmet.h"
#include "telnet.h"
#include "uart.h"
#include "smp.h"

#define PLATFORM_NVMET_PORT       4420u
#define PLATFORM_TELNET_PORT       23u
#define PLATFORM_FAN_DUTY_PERCENT   50u

/* nvmet常駐サーバインスタンス(RP1+ConnectX PF0/PF1)。nvmet_job_start()
 * がspawnするjob_tはこのctxを生存期間中ずっと参照し続けるため、関数
 * ローカルではなく生存期間の長いストレージが必要(command.cのs_nvmet_ctx
 * と同じ理由)。ただし普通の`.bss`グローバルにはしない -- fwupdateの
 * LOAD_ADDR受信窓と物理的に重なるバグを構造的に防ぐため、board.hの
 * NVMET_INSTANCES_BASEという固定物理アドレスのスロットを直接指す
 * (nvmet.hのNVMET_CTX_SLOT()コメント参照)。slot 3はcommand.cの`nvmet`
 * 手動起動が使う。 */
#define s_nvmet_rp1      (*NVMET_CTX_SLOT(0))
#define s_nvmet_mlx5_pf0 (*NVMET_CTX_SLOT(1))
#define s_nvmet_mlx5_pf1 (*NVMET_CTX_SLOT(2))

// `fan`シェルコマンド(command.c、cmd_fan())と同じ手順: RP1側のPCIe/
// PCIe2ブリングアップ(fan.cがRP1のPWM1経由でファンを駆動するために必要)
// を経てduty 50%で回転を開始する。
static void platform_init_fan(void)
{
    if (pcie_rc_init() != 0) {
        uart_printf("[platform_init] PCIe(RP1)ブリングアップ失敗、ファン制御をスキップします\n");
        return;
    }
    fan_set_speed(PLATFORM_FAN_DUTY_PERCENT);
    uart_printf("[platform_init] fan: duty=%u%%\n", (unsigned)PLATFORM_FAN_DUTY_PERCENT);
}

// `net init`(引数無し、RP1)シェルコマンド(command.cのnet_init())と同じ
// 手順でRP1を立ち上げた上で、nvmet常駐サーバを1系統起動する。bound_ctx
// にRP1のnet_ctx_t(eth_init()内でnet_ctx_register()済み)を渡すことで、
// このインスタンスはRP1が受信したSYNのみに応答する(CLAUDE.md「nvmet:
// 複数インターフェース同時待受」節参照 -- ConnectX側と同じport番号を
// 使っても互いに干渉しない)。
static void platform_init_rp1(void)
{
    eth_init();
    arp_init();  // EtherType 0x0806(ARP)  -> arp_handle_frame
    ip_init();   // EtherType 0x0800(IPv4) -> ip_handle_frame

    uint8_t mac[ETH_ALEN];
    eth_get_mac(mac);
    uart_printf("[platform_init] rp1: MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    net_ctx_t *rp1_ctx = net_ctx_find("rp1");
    if (nvmet_job_start(&s_nvmet_rp1, PLATFORM_NVMET_PORT, rp1_ctx, "rp1") != 0) {
        uart_printf("[!] platform_init: rp1のnvmet起動に失敗しました\n");
    }
}

// ConnectXが接続されていれば(PCIe1リンクが上がれば)初期化し、PF0/PF1
// それぞれに独立したnvmet常駐サーバを起動する。未接続の場合は何もせず
// 静かに戻る(実機で外部M.2/FFCコネクタに何も挿さっていない構成が
// 通常運用でも普通にありうるため、これはエラーではない)。
static void platform_init_connectx(void)
{
    // PERST#による完全リセット(pcie1_reset_link())は意図的に呼ばない --
    // 実機で、ハードリセット後にConnectX自身がPCIeリンクを再トレーニング
    // し終えるまでの時間が1000msでも不足することがある(pcie1.cの
    // pcie1_reset_link()コメント参照、真の所要時間は未確定)一方、
    // リセットを伴わない`pcie1_rc_init()`(pcicfg1シェルコマンド等が使う
    // 経路、mlx5_net_init_dual_loopback()が内部で呼ぶのもこちら)は実機で
    // 繰り返し確実かつ即座に成功することを確認した(2026-08-02)。
    // pcie1_reset_link()が本来必要なのは「同一電源投入内でConnectXへの
    // ENABLE_HCA等を既に一度行った後、その残存FW状態をクリアしてから
    // 再度bring-upする」場面(CLAUDE.md「ConnectX(mlx5) HCA初期化」節・
    // 「`pcie1 reset`」節参照)であり、platform_initは通常そのセッションで
    // 最初にConnectXへ触れる処理のため、この前提が最初から成立しない --
    // クリアすべき残存状態がそもそも無い。もし`mlx5`コマンド等で既に
    // ConnectXを操作した後にplatform_initを再実行したい場合は、先に
    // `pcie1 reset`を手動実行してから呼ぶこと。
    //
    // mlx5_net_init_dual_loopback(): pcie1_rc_init()→PF0/PF1双方のBAR0
    // 割り当て・HCA初期化・net_ctx_tとしての登録まで一括で行う(`net init
    // mlx5`シェルコマンドと同じ関数、CLAUDE.md「TCP/IPスタックのConnectX
    // 統合」節参照)。実際のフレーム送受信テスト(`mlx5`コマンド専用の
    // クロスポートループバック自己診断)は含まないため、外部ホスト/
    // ループバックケーブルいずれの配線でも安全に呼べる。
    if (mlx5_net_init_dual_loopback() != 0) {
        uart_printf("[!] platform_init: ConnectXのbring-upに失敗しました、"
                    "ConnectX側のnvmetはスキップします\n");
        return;
    }

    net_ctx_t *pf0_ctx = net_ctx_find("mlx5-pf0");
    net_ctx_t *pf1_ctx = net_ctx_find("mlx5-pf1");

    if (nvmet_job_start(&s_nvmet_mlx5_pf0, PLATFORM_NVMET_PORT, pf0_ctx, "mlx5-pf0") != 0) {
        uart_printf("[!] platform_init: mlx5-pf0のnvmet起動に失敗しました\n");
    }

    // 【マルチコア化 Phase 6、~/.claude/plans/wondrous-baking-gadget.md
    // 参照】PF1のnvmetサーバをcore1へ引き渡す。ConnectXブリングアップ
    // 自体(PCIeコンフィグ空間へのアクセスを伴う、上のmlx5_net_init_
    // dual_loopback()呼び出し)はここまで全てcore0単独で完了させてある
    // -- 以後core1が行うのはNIC操作(RX/TXポーリング)とTCP/NVMe処理
    // だけで、PCIeコンフィグ空間には一切触れない設計なので安全に引き
    // 渡せる。smp_boot_core1()が失敗した場合(PSCI未対応/タイムアウト)
    // は、pf1_ctxのowner_coreをcore0のまま(net_ctx_register()の既定
    // 値)にしておき、これまで通りcore0だけでmlx5-pf1のnvmetを動かす
    // フォールバックにする -- 起動シーケンス全体を失敗させない。
    if (pf1_ctx) {
        if (smp_boot_core1() == 0) {
            net_ctx_set_owner_core(pf1_ctx, 1u);
            uart_printf("[platform_init] mlx5-pf1のNIC/nvmet処理をcore1へ引き渡します\n");
        } else {
            uart_printf("[!] platform_init: core1起動に失敗、mlx5-pf1はcore0のまま動作します\n");
        }
    }
    if (nvmet_job_start(&s_nvmet_mlx5_pf1, PLATFORM_NVMET_PORT, pf1_ctx, "mlx5-pf1") != 0) {
        uart_printf("[!] platform_init: mlx5-pf1のnvmet起動に失敗しました\n");
    }
}

void platform_init(void)
{
    uart_printf("[platform_init] 起動時初期化を開始します\n");

    platform_init_fan();
    platform_init_rp1();
    platform_init_connectx();

    // ConnectXブリングアップ(mlx5_net_init_dual_loopback())はPF0を
    // アクティブインターフェースにして戻る(mlx5_net.cのコメント参照)。
    // シェル操作(ping/arp who/nvme connect等)の既定インターフェースは
    // RP1のままにしておく方が既存の使用感(`net init`単体運用時)と一致
    // するため、ここで明示的に戻す -- `net use mlx5-pf0`/`mlx5-pf1`で
    // いつでも切り替えられる。
    net_ctx_t *rp1_ctx = net_ctx_find("rp1");
    if (rp1_ctx) {
        net_ctx_activate(rp1_ctx);
    }

    // telnet常駐サーバ(telnet.h参照、command.cのシェルセッションへの
    // もう1つの入出力口)。nvmetと違いインターフェースごとの状態を
    // 持たない単一の共有セッションなので、bound_ctxはNULL(任意の
    // インターフェース)にしておく -- RP1/ConnectXどちら経由でも
    // 同じシェルへログインできる。
    telnet_server_start(PLATFORM_TELNET_PORT, NULL);

    uart_printf("[platform_init] 起動時初期化完了\n");
}
