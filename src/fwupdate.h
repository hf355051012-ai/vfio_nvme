#ifndef FWUPDATE_H
#define FWUPDATE_H

#include <stdint.h>

// プライマリイメージへ再突入する際、fwupdateを即座に継続させるための合図。
#define FWUPDATE_AUTO_MAGIC 0xDEADBEEFC0FFEE01ULL

// Xmodemで新しいファームウェアを受信し、成功したらジャンプする。
void fwupdate_run(void);

// addrにジャンプする前にキャッシュを同期し、(0, magic)をAAPCS引数として
// 渡して分岐する(boot.SのSP設定/.bssゼロクリアを経由する「素の関数
// 呼び出し」、CLAUDE.md「fwupdateは常にプライマリイメージからインストール
// し、ハードウェアリセットしない」節参照)。fwupdate_run()(UART Xmodem)と
// ftpd.c(LAN FTP)の両方が、新しいイメージの受信完了後にこれを呼ぶ --
// 通信路が違うだけで「受信完了後どうジャンプするか」は同じ処理のため、
// ロジックを重複させずここに一本化してある。戻らない。 */
void fwupdate_jump_to_image(uint64_t addr, uint64_t len, uint64_t magic);

#endif
