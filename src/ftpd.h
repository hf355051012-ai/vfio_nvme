#ifndef FTPD_H
#define FTPD_H

#include <stdint.h>
#include "netctx.h"

/* ================================================================
 * ftpd.h — LAN経由(FTP、書き込み専用の最小実装)でのファームウェア更新
 *
 * 既存のfwupdate(UART Xmodem、fwupdate.c)と受信先(LOAD_ADDR/
 * LOAD_MAX_SIZE、board.h)・完了動作(受信完了後に直接ジャンプ、
 * fwupdate_jump_to_image()、fwupdate.h参照)は完全に共通で、通信路だけを
 * UARTからTCP/FTPに置き換えたもの。
 *
 * なぜNVMe/TCPではなくFTPか: 既存のnvmet実装(nvmet.c)は丸ごと再利用
 * できるが、実際に使うにはPC側でnvme-cli(WSL、要root)を用意し名前空間
 * 経由でブロック単位に書き込む必要があり、単に「ファームウェアイメージを
 * 1個送ってジャンプさせたい」という用途には遠回り。FTPは書き込み専用の
 * STORコマンド1つで済み、Windows PC側もPython標準のftplib/curl/
 * FileZilla等、追加インストール無しで使えるクライアントが豊富なため、
 * こちらを選んだ。
 *
 * 対応コマンド: USER/PASS(認証は一切行わない、常に230)、SYST/TYPE/PWD/
 * CWD/NOOP(引数を無視して形だけ200/215/257/250で応答)、PASV(のみ、能動
 * モードPORTは未実装)、STOR <任意のファイル名、内容は無視>、QUIT。
 * RETR/LIST/DELE等の読み出し・一覧系は一切実装しない(fwupdate専用、
 * 汎用ファイルサーバではない)。認証を一切行わないため、信頼できないLAN
 * 上では使わないこと(このプロジェクト全体の設計方針通り、デバッグ
 * ボード単体でのローカルLAN利用を前提にしている)。
 *
 * 【重要】STORで送るのは`boot/payload_2712.img`(LOAD_ADDR向けにリンク
 * 済み)であって`kernel_2712.img`(0x80000向け)ではない -- 既存のUART
 * Xmodem版fwupdate/`tools/rpi5_update.py`と全く同じ制約(CLAUDE.md
 * 「`fwupdate`によるチェインロード」節参照)。誤って`kernel_2712.img`を
 * 送ると、LOAD_ADDRへ着地したのに0x80000向けにリンクされたコードが動く
 * ことになり、静的データテーブル内のポインタ等が誤ったアドレスを指す
 * ため壊れる。
 *
 * telnet.c/nvmet.cと同じ「常駐ジョブ、1接続ずつ順に処理」パターン。
 * 停止は`job stop <番号>`のみ(専用の停止関数は無い)。
 *
 * プライマリイメージから実行中でない場合は起動を拒否する(fwupdate_run()
 * のUART版と同じ「fwupdateは常にプライマリイメージからインストールする」
 * 制約、CLAUDE.md参照)。UART版と違いチェインロードされたペイロードから
 * 自動でプライマリへ戻ることはしない(ジョブベースゆえ、その場で完結する
 * 単純な関数呼び出しではなく、戻った先でジョブスケジューラ自体を再始動
 * する必要がありジョブ化の枠組みに乗せるには複雑さが見合わない) --
 * ユーザーが`reboot`等で明示的にプライマリへ戻ってから実行すること。
 * ================================================================ */

/* port: 制御接続(既定21)。data_port: PASVで案内するデータ接続用の
 * 固定ポート(能動モードPORT非対応なのでephemeralに毎回変える必要が
 * 無い、既定20001)。bound_ctx: 待ち受けるインターフェース(NULL=任意、
 * telnet_server_start()と同じ意味)。
 * 戻り値: 0=起動成功、-1=失敗(既に起動中、リスナー枠が無い、
 * プライマリイメージから実行中でない、等)。 */
int ftpd_start(uint16_t port, uint16_t data_port, net_ctx_t *bound_ctx);

#endif /* FTPD_H */
