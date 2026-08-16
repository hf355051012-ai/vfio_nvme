// Raspberry Pi 5 (BCM2712) 用ベアメタルエントリポイント。

#include "board.h"
#include "pl011.h"
#include "exceptions.h"
#include "command.h"
#include "fwupdate.h"
#include "mmu.h"
#include "pcie.h"
#include "fan.h"
#include "eth.h"
#include "arp.h"
#include "ip.h"
#include "telnet.h"
#include "nvmet.h"

extern char _start[]; // リンカが提供するシンボル

// staticにしない: exceptions.cとcommand.cもこの同じコンソールに出力する。
pl011_t debug_uart;

// fwupdate_magicがFWUPDATE_AUTO_MAGICならfwupdateを即座に継続する。
void main(uint64_t fwupdate_magic) {
    exceptions_init();

    pl011_init(&debug_uart, DEBUG_UART_BASE, DEBUG_UART_CLK_HZ, 115200);
    pl011_puts(&debug_uart, "\nrpi5-boot: debug UART up (0x107d001000, 115200 8N1)\n");

    uint64_t here = (uint64_t)_start;
    pl011_puts(&debug_uart, "running from ");
    pl011_puts(&debug_uart, here == PRIMARY_BASE ? "the primary (SD-card) image" : "a chainloaded payload");
    pl011_puts(&debug_uart, " (0x");
    pl011_hex64(&debug_uart, here);
    pl011_puts(&debug_uart, ")\n");

    // exceptions_init()/pl011_init()の直後、他の初期化より前に呼ぶ
    // (mmu_init()内のバグでData Abortが起きても、VBAR_EL2設定済み+UART
    // 使用可能な状態でexception_handler()が捕捉できるようにするため。
    // 詳細は~/.claude/plans/glimmering-mapping-waterfall.md参照)。
    mmu_init();

    // NVMET_INSTANCES_BASE(board.h)は`.bss`/`.dma_bss`と違いboot.Sの
    // ゼロクリア対象に含まれない固定物理アドレス領域のため、ここで明示的に
    // ゼロクリアする(nvmet.hのnvmet_instances_zero_all()コメント参照 --
    // 実機で発見した本物のバグ、未初期化のままだとnvmet_job_start()が
    // ctx->labelという未初期化の生ポインタを参照してクラッシュする)。
    // mmu_init()の直後(この領域がRAMとしてマップ済みになった直後)、かつ
    // fwupdate_run()より前に置く -- .bss/.dma_bssと同じく、真のコールド
    // ブート・チェインロードジャンプ・exception_handler()によるクラッシュ
    // 回復のいずれの`_start`エントリでも毎回実行される必要があるため。
    nvmet_instances_zero_all();

    if (fwupdate_magic == FWUPDATE_AUTO_MAGIC) {
        fwupdate_run();
        // 失敗時のみここに到達し、下の通常シェルに続ける。
    }

    // platform_init()はmain()から自動では呼ばない(ユーザー指示、
    // 2026-08-02) -- ConnectXブリングアップはPCIe1のBAR0アウトバウンド
    // ウィンドウ(PCIE1_OUTBOUND_CPU_BASE)へのMMUマッピングを必要とする
    // (mmu.cのL1 index 110-111)が、チェインロードされたペイロードは
    // 実機で確認済みの通り、SDカード上のプライマリが最後に実際に
    // mmu_build_tables()を実行した時点の(古い)ページテーブルを再利用
    // し続ける(mmu.cの「再入の設計」参照)。もしSDカードのプライマリが
    // この領域を知らない古いビルドのままだと、起動のたびに自動実行
    // されるplatform_init()がConnectX検出に成功するたびTranslation
    // faultでクラッシュし、対話シェルへ一切到達できなくなる(実機で
    // 確認済みの障害モード)。`platform_init`シェルコマンド(cmd_
    // platform_init()、command.c)として明示的に呼び出す形にすることで、
    // 通常の起動は常に安全に対話シェルへ到達できるようにし、
    // ConnectXブリングアップを試すかどうかはユーザー側の判断に委ねる。

    // 一方、`net init`(引数無し=RP1既定)と`fan 50`はユーザー指示
    // (2026-08-07)により自動実行する。上記のplatform_init()回避理由は
    // ここには当てはまらない -- どちらもRP1(PCIe2、PCIE_OUTBOUND_CPU_BASE、
    // mmu.cのL1 index 124-127)だけを使い、この領域はConnectX/PCIe1対応
    // より前からmmu.cに存在する、プロジェクト創設当初からのものなので、
    // チェインロード先が再利用する(古い)ページテーブルであっても
    // Translation faultは起きない。eth_init()内部のPHYリンク待ちにも
    // 上限(ETH_LINK_WAIT_MS)があるため、ケーブル未接続等でも対話シェルへ
    // 到達できなくなることはない(数秒待った後に失敗ログを出して続行する
    // だけ)。失敗しても(PCIe/PHY問題等)対話シェル自体には支障が無いよう、
    // 戻り値は見ない -- ユーザーは`net init`/`fan`を後から手動で再実行
    // できる。`net init`/`fan`コマンド(command.cのnet_init()/cmd_fan())
    // と全く同じ処理を、シェル経由のラッパーを介さず直接呼ぶ。
    eth_init();
    arp_init();  // EtherType 0x0806(ARP)  -> arp_handle_frame
    ip_init();   // EtherType 0x0800(IPv4) -> ip_handle_frame
    if (pcie_rc_init() == 0) {
        fan_set_speed(50u);
    }

    // `telnet`(既定port 23)も同じ理由(2026-08-07、ユーザー指示 --
    // シリアル/USB経由のアクセス無しにtelnet経由でfwupdateを実機テスト
    // できる環境にするため)で自動起動する。telnet.cはtcp_listen()/
    // job_spawn()だけを使う純粋なTCP/RAMベースの機能で、platform_init()
    // が避けているConnectX/PCIe1固有の新規MMU領域には一切依存しない
    // (net_init直後のeth_init()が用意したインターフェースへ乗るだけ)。
    // 戻り値は見ない -- telnet_server_start()は「既に稼働中」を検知して
    // 二重起動を防ぐ設計(telnet.c参照)なので、失敗してもシェルには
    // 影響しない。`fwupdate lan`(ftpd)は意図的に自動起動しない --
    // それ自体をtelnet接続後に実行して試すのが今回の目的のため。
    telnet_server_start(23u, NULL);

    // インスタンス1(コア1向けの完全に独立したtelnetセッション、telnet.h
    // 参照、2026-08-08ユーザー指示「telnetをコアごとにできるようにして
    // ほしい。print文も完全に独立」)も同じ理由で自動起動する。
    //
    // 【2026-08-08実機で発見した本物のバグ、原因判明済み】当初この自動
    // 起動込みでLANデプロイしたところ、実機でARP/ICMPを含むネットワーク
    // 全体が無応答になる障害が発生した。切り分けの結果、原因はtelnet2
    // 自体のバグではなく、net.hのNET_RP1_CORE1_IP(コア1エイリアスIP)に
    // 割り当てていたアドレス(192.168.100.3)が、このLAN上でユーザーの
    // PC自身が実際に使っているIPアドレスと衝突していたことだった --
    // ボードが自分のものとしてARPで.3を名乗り始めたことで、PCとの
    // アドレス重複によりLANセグメント全体のARPが混乱していた
    // (net.hのNET_RP1_CORE1_IPコメント参照、192.168.100.4へ変更して解決)。
    telnet_server_start_instance(1u, 2323u, net_ctx_find("rp1-core1"));

    command_shell_run();
}
