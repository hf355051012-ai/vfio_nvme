#ifndef PLATFORM_INIT_H
#define PLATFORM_INIT_H

/* ================================================================
 * platform_init.h — 環境の共通初期化(`platform_init`シェルコマンド、
 * command.cのcmd_platform_init()から呼ばれる)。
 *
 * main()からは自動で呼ばない(2026-08-02、ユーザー指示) --
 * ConnectXブリングアップはPCIe1のBAR0アウトバウンドウィンドウへの
 * MMUマッピングを必要とするが、チェインロードされたペイロードは
 * SDカード上のプライマリが最後に実際にmmu_build_tables()を実行した
 * 時点の(古い)ページテーブルを再利用し続けるため、SDカードのプライマリ
 * がこの領域を知らない古いビルドのままだと自動実行のたびに実機で
 * クラッシュする障害を経験した(main.cのコメント参照)。明示的なコマンド
 * にすることで、通常の起動は常に安全に対話シェルへ到達できる。
 *
 * 行うことはplatform_init.cのコメント参照:
 *   1. ケースファンをduty 50%で起動
 *   2. RP1のnet init相当(eth_init/arp_init/ip_init) + nvmet常駐サーバ
 *   3. ConnectXが接続されていれば(PCIe1リンクが上がれば)初期化し、
 *      PF0/PF1それぞれに独立したnvmet常駐サーバを起動
 * ================================================================ */

void platform_init(void);

#endif /* PLATFORM_INIT_H */
