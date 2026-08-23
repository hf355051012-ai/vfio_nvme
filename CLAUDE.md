# vfio_nvme

x86-64 Linux ユーザ空間 + VFIO で ConnectX-4 を直接駆動し、NVMe-oF(RoCEv2)と
NVMe/TCP のターゲットとイニシエータを同一プロセスに立てて性能を測る実験用
ドライバ/スタック。カーネルドライバも libibverbs も使わない。
`rpi5_boot`(Raspberry Pi 5 ベアメタル)の x86 VFIO ポートを切り出したもので、
**このリポジトリは x86 専用**、rpi5 の履歴は引き継いでいない。

構成・レイヤ・シェルコマンド・性能値といった説明は `README.md` にある。

**仕組みそのものの説明は `SPEC.md`(仕様書)にある。** ネットワークもドライバも
知らない読者向けに、前提知識から順に積み上げた文書。**実装を変えたらここも
更新すること**(特に「第 28 章 何がどこまで確かめられているか」の表)。
**左に章ナビゲーションを置いた HTML 版**が `docs/spec.html` にある。SPEC.md を
直したら `tools/build_spec_html.sh` で作り直す(手で編集しない)。

このファイルには**作業上の手順と、実機で踏んだ落とし穴**だけを書く。

**未実装のプロトコル機能とその実装順は `PLAN_protocol_gaps.md` にある。**
**ネットワーク層(段階 1〜14)はすべて完了した(2026-08-22)。** RST 送信 /
高速再送 / RDMA リソース解放 / Discovery / ルーティング / 近隣キャッシュの
エージング / 重複アドレス検出 / 送信側 IP フラグメント / Path MTU Discovery /
SLAAC / MLD / NUD / IPv6 拡張ヘッダ。

**次は段階 15〜22 = D 系(NVMe コントローラとして期待される機能)**:
D2 Get Features / D3 Identify の CNS 網羅 / D4 TRIM・Write Zeroes /
D5 SMART ログ / D6 AER の完了 / D7 Keep Alive タイマ / D8 複数名前空間 /
D9 認証。**D 系は Pi5 の `nvme-cli` で直接叩けるので、B 系のような検証の
工夫は要らない**(現状の実測結果も計画に載せてある)。着手したらあのファイルの
進捗表を更新すること。

**D 系は D2〜D8 が完了した(2026-08-22)** -- Get Features / Identify の CNS
網羅 / TRIM・Write Zeroes / SMART・Error Information ログ / AER / Keep Alive
タイマ / 複数名前空間。**残るは D9(認証)だけ**(計画自身が「TLS は対象外、
やるなら DH-HMAC-CHAP のみ」と判断している)。

## 編集とビルド

**編集は Windows 側 `%USERPROFILE%\Documents\vfio_nvme` が正。** ビルドと実機
テストは ConnectX-4 のある OptiPlex(`ssh rpi5-rdma-target`)で行う。

```bash
wsl -e bash -lc "/mnt/c/Users/<ユーザ名>/Documents/vfio_nvme/tools/sync_to_optiplex.sh"
```

同期は `--delete` 付きの一方向。**OptiPlex 側 `~/vfio_nvme` で直接編集すると次の
同期で失われる。** ビルドは `make -j8`(PLATFORM 分岐なし)。

Windows の `python` は Microsoft Store のスタブで exit 49 になる。スクリプトを
書くなら WSL の `python3` を使い、Git Bash からは `MSYS_NO_PATHCONV=1` を前置
して `/mnt/c/...` 形式のパスを渡す(付けないとパスが壊れる)。

## 実機テストの手順と地雷

- **ConnectX は `mlx5_core` か `vfio-pci` のどちらか一方にしかバインドできない。**
  `vfio_nvme` は vfio-pci、Linux 側比較ベンチ `~/script/linux_loopback.sh` は
  mlx5_core を要求する。テスト後は元のバインドへ戻すこと。
- `~/script/enable_vfio.sh` は **`nr_hugepages` を 128 へ下げる**。256MB
  名前空間には不足の恐れがあるので、バインドだけ手動で行い hugepages は 1024
  のままにする。ホスト再起動でバインドも `/tmp` のスクリプトも消える。
- **単発プロセスの起動を繰り返すと ConnectX/ホストが wedge する**(電源断が要る)。
  必ず引数 2 つで常駐シェルに入り、その中で bench/monitor を回す。
- 常駐シェルへパイプでコマンドを流すとき、`printf ... | binary` は pipe を閉じて
  EOF を送るため、長時間ブロックするコマンドの後続が dispatch されない。
  `(sleep 15; echo cmd1; sleep 45; echo cmd2; sleep 5; echo quit) | binary` の
  ように sleep で間隔を空け、pipe を開いたままにする。
- **常駐シェルが `quit` で終わらず残ると、`vfio-pci` からの unbind が無期限に
  ブロックする。** dmesg に `vfio-pci 0000:01:00.0: No device request channel
  registered, blocked until released by user` が出ていたらこれ。
  `~/script/disable_vfio.sh` が `tee .../unbind` で固まったまま帰ってこない、
  という形で気づく。対処:

  ```bash
  ps aux | grep "[v]fio_nvme/build"      # 残っている PID を探す
  sudo lsof /dev/vfio/*                  # 掴んでいるプロセスの確認
  sudo kill -KILL <pid>                  # 親の sudo も一緒に落とす
  echo 0000:01:00.0 | sudo tee /sys/bus/pci/drivers_probe
  ```

  実際に 15 分以上ブロックした。**vfio-pci へ切り替える前と、実機テストを
  終えた後は必ず残存プロセスの有無を確認すること。**
- シェルの `nvmet <port>` は **4421 以外を指定すると後続の `tcpbench` が壊れる**
  (`tcpbench` は常に 4421 へ繋ぎに行く)。さらにその失敗は後続の `bench` も
  巻き添えにする。
- `monitor` は常に `FW=ASSERT` を表示する。切り出し前のバイナリでも同じ出力に
  なることを確認済みで、退行ではない。
- 起動時に `[vfio] VFIO_IOMMU_MAP_DMA(...) 失敗 (errno=14)` が 1 回出るのも既知。

## 検証手法

- **コメントのみの変更は、リンク後バイナリの md5 完全一致で機械的に検証する**
  (`-g` 無し、`__LINE__`/`assert` 無しなので成立する)。関数ヘッダコメントの
  付与(357 個)と罫線化(360 個)はこれで「コードに一切影響なし」を確認した。
  参照されないコードを足すだけの変更は `objdump -d` の差分で見る(アドレスの
  ずれは想定内、命令の変化は想定外)。
- 性能の退行判定に **TCP 8K write は使えない**。同一バイナリ・同一セッションでも
  942 / 0.01 / 595 MB/s と桁違いにばらつく(0.01 の回は自己修復する既知の
  SQ stall)。64K/256K と 8K read で判断する。
- **bring-up 直後の 1 回目は低めに出る。** 単発比較で判断せず、同一セッションで
  連続測定して定常値を比べること。

## 未使用に見えても消してはいけないもの

`smp_boot_core2()` / `smp_boot_core3()`(`hal_smp.c` / `smp.h`)は呼び出し元が
無いが、複数コネクションの受信を複数コアへ振り分ける scale-out 用の部品として
意図的に残してある。**一度、未到達関数の一括削除で消して復活させた経緯がある。**
`--gc-sections` がリンク後バイナリから落とすのでコストはゼロ。同じ理由で
`SMP_MAX_CORES` は 4 のまま(`.bss` を約 430MB 使うが下げない)。

## NVMe/TCP ダイジェスト(CRC32C)

initiator/target 双方で対応済み。`tcpbench ... hdgst|ddgst|digest` で有効化。
**ダイジェストは NVMe-oF の TCP トランスポート束縛の機能で、RDMA 束縛には無い**
(`bench` に指定しても警告して無視する。`linux_loopback.sh` も `--transport tcp`
専用で、`rocev2` と併用するとエラーにする)。

### 再導入してはいけないバグ(rpi5 時代に実機で踏んだ 3 件)

1. **CRC32C の最終反転(`~`)を忘れる。** `crc32c()` は生の実行中 CRC を返す
   規約なので、ダイジェスト値として使う直前に `~` を取る。
2. **`plen` を確定させる前にヘッダダイジェストを計算する。** ダイジェストは
   `buf[0..hlen)` 全体が対象で、そこには `plen` も含まれる。
3. **`flags` も同じ。** 2 を直したとき `plen` だけ直して `flags`(HDGST/DDGST
   ビット)を見落とし、もう一度同じ形で踏んだ。

いずれも**自分の検証は通るのに相手側だけが静かに接続を切る**という非対称な
症状になる。ヘッダのどのフィールドも、ダイジェスト計算より前に最終値へ
確定させること。

### push 型・ゼロコピーはダイジェスト有効時も維持する

以前は digest が立つと target 側の高速パスが 2 つとも落ちていた(受信の push 型
inline upcall → pull 型、送信のゼロコピー `send_c2h_async` → コピーする
`send_c2h`)。どちらも「digest なら使わない」という単純なゲートで、実装が追いつ
いていなかっただけ。現在はどちらも維持している。

- 受信: パーサに `PRX_HDGST`/`PRX_DDGST` 相を追加し、**データダイジェストは
  受信ストリームから逐次 CRC を積む**(コピー先を読み直す 2 パス目は不要)。
- 送信: ダイジェストを**送信元バッファから直接算出**して 4 バイトだけ追加で
  キューする(連続バッファへのコピーは要らない)。

これで `hdgst` 単体のコストは誤差範囲まで消えた(以前は write −31% / read −55%
落ちていたが、その全部がフォールバック由来だった)。

## CRC32C の実装(`crc32c.c`)

3 本インタリーブ + PCLMULQDQ 合成。`crc32` 命令はレイテンシ 3・スループット
1/cycle なので単一チェーンでは 2.67 B/cycle が上限で、独立 3 本を交互に回して
隠す。合成は `crc32_u64(0, V) = V * x^64 mod P` を使い、clmul の還元前 63bit 積を
そのまま `crc32` 命令へ食わせて還元させる。

- **PCLMULQDQ は本体の折り畳みではなく、合成を数命令に落とすために要る。**
  本体は crc32 命令が 8 B/cycle で頭打ちなので、pclmul 折り畳みにしても ISA-L と
  同じ天井に当たる(超えるには VPCLMULQDQ が要るが Coffee Lake には無い)。
- 合成を GF(2) 行列でやると 1 回約 30us かかり、呼び出し長が変わるたび作り直しに
  なる。64KB 単発なら償却できるが、**逐次呼び出しでは 0.94 GB/s まで落ちて本体の
  利得を食い潰す**。
- 合成定数は `K2 = x^(8*(BLK-8)) mod P`、`K1 = x^(8*(2*BLK-8)) mod P`。
  ブロックを大小 2 段(1024B/128B)にしてあるのは、大きいブロックだけだと端数が
  単一チェーンへ落ちて遅くなるため。
- 正しさは起動時の `crc32c_selftest()` が担保する。既知ベクタに加え
  **オフセット 0〜7 × 4096B で 1 バイト単位の基準計算と一致すること**を確認する
  (全経路を通る。合成定数を間違えればここで落ちる)。この全アライメント検証が
  無かった頃は 1 パスしか検証しておらず、**自作 initiator ↔ 自作 target だけで
  試すと両側が同じ間違い方をして絶対に検出できない**という穴があった。

## RDMA の同時 RDMA_READ 数(write 性能を 2.3 倍にしたバグ 2 件)

NVMe-oF の **write は target が host のメモリから RDMA_READ でデータを引き込む**
構造なので、同時 RDMA_READ 数がそのまま write スループットの上限になる
(read は target が RDMA_WRITE で押し込むだけなので影響を受けない)。
「write だけ depth でスケールしない」ときはここを疑う。

### 1. `log_max_ra_res_qp` のビット抽出が 4bit ずれていた

```c
/* 誤: bit 342-347 を読んでいて常に 0(= 同時 1 本)になる */
dev->log_max_ra_res_qp = ((hca_cap[42] & 0x03u) << 4) | ((hca_cap[43] & 0xF0u) >> 4);
/* 正: struct mlx5_ifc_cmd_hca_cap_bits より bit 0x15a-0x15f = byte43 の下位6bit */
dev->log_max_ra_res_qp = hca_cap[43] & 0x3Fu;
```

実機の真値は req/res とも 4(= 16 本)。`ibv_devinfo -v` の
`max_qp_rd_atom` / `max_qp_init_rd_atom` がカーネルドライバ側の同じ値なので、
**自作の読み取りが正しいかはこれと突き合わせて確認できる**(mlx5_core に
バインドし直す必要はあるが、疑わしいときは必ずやること)。

### 2. `log_rra_max` を RTR2RTS で設定していた(INIT2RTR が正しい)

`log_rra_max`(= IBTA の `max_dest_rd_atomic`、responder として受け付ける
RDMA_READ 数)は **INIT2RTR でしか反映されない**。Linux の
`mlx5_ib_modify_qp()` も `IB_QP_MAX_DEST_RD_ATOMIC` を INIT2RTR でのみ受ける。
RTR2RTS で書いても FW は保持しないので、1. だけ直すと相手が 2 本目の
RDMA_READ を投げた瞬間に **`REMOTE_INVAL_REQ_ERR`(syndrome=0x12)**になる。
`log_sra_max`(`max_rd_atomic`、initiator 側)は RTR2RTS で正しい。

### 3. 併発して露呈した: BlueFlame ドアベルが 32bit x 2 だった

`mlx5_qp.c` のドアベルが `mmio_write32` 2 回で、8 バイトがアトミックに
書かれていなかった(`mlx5_net.c` は修正済みだった)。同時 RDMA_READ を
1 -> 16 に緩めてドアベル発行頻度が上がった途端、**`LOCAL_QP_OP_ERR`
(syndrome=0x02)が数十万コマンドに 1 回**の頻度で出るようになった。
`mmio_write64` 1 回に直して解消。Linux の `mlx5_write64()` が「32bit
システムではロックが必要」と注記しているのと同じ理由で、**64bit CPU なら
必ず単一の 64bit ストアで書くこと**。

## 2 ノード構成(OptiPlex ↔ Raspberry Pi 5)と相互運用テスト

**100GbE MCX456A は外され、25GbE ConnectX-4 Lx(MT27710 `15b3:1015`、
FW 14.32.1900、PCIe Gen3 x8)に置き換わった。** 2 本の DAC は両方とも Pi5 へ
行くので、**PF0↔PF1 の直結ループバックはもう存在しない**。

| OptiPlex | | Pi5(`ssh pi5`)|
|---|---|---|
| PF0 `01:00.0` = 192.168.101.10 | ←DAC→ | `eth2` |
| PF1 `01:00.1` = 192.168.101.11 | ←DAC→ | `eth1` |

**2 台への接続は `~/.ssh/config` のホストエイリアスで行う**(このリポジトリに
実アドレスは書かない)。`rpi5-rdma-target` = OptiPlex、`pi5` = Raspberry Pi 5。
`sync_to_optiplex.sh` などは環境変数 `REMOTE` で上書きできる。

```
Host rpi5-rdma-target          # OptiPlex(ビルド・実機テスト)
    HostName  <管理 LAN の IP>
    User      <ユーザ名>
    IdentityFile ~/.ssh/<鍵>

Host pi5                       # Raspberry Pi 5(相互運用の相手)
    HostName  <管理 LAN の IP>
    User      <ユーザ名>
```

既存の「対向PF」前提のテスト群を生かすため、**Pi5 側で `eth1`+`eth2` を `br0`
にブリッジする**(STP off / MTU 9500 / `192.168.101.20/24`)。この状態で
`ping6`〜`pmtutest` と `bench`/`tcpbench` は従来どおり動く。

- **MTU は 9500 が要る。** 自作側は MSS 9216 = フレーム 9270B を出すので、
  9000 だと**フルサイズのセグメントだけが無言で落ちる**。
- `eth1`/`eth2` は `nmcli device set <if> managed no` にすること。
  **ブリッジ設定は再起動で消える**(非永続)。
- **性能の天井が変わった。** PF0↔PF1 は Pi5 の PCIe Gen3 x1 を通るので
  約 800 MiB/s で頭打ち。上の「最新の性能」の表(100G 直結)とは条件が違うので
  **数字を比べてはいけない**。25G 直結へ戻しても線速上限は約 2980 MiB/s。
- OptiPlex 側の常駐シェルは `~/script/vn_start.sh` / `vn_cmd.sh "<cmd>" [秒]` /
  `vn_stop.sh` で操作する(FIFO を開いたままにするので EOF で死なない)。
  **FIFO は読み手が居ないと書き込みがブロックする**ので `vn_cmd.sh` は先に
  プロセスの生存を確認する。

### 自己ループバックでは絶対に見えなかった不具合(Linux と繋いで判明)

**どちらも「自作イニシエータがその手順を踏まないから見えなかった」形。**

1. **IO キューの切断で admin キューまで能動 close していた。** Linux は
   「IO キュー切断 → admin へ CC.SHN(Property Set offset 0x14)→ admin 切断」の
   順に畳む。途中で admin を切ると CC.SHN が無応答になり、ホスト側で
   **60 秒のコマンドタイムアウト**(`Property Set error: 881` =
   `NVME_SC_HOST_ABORTED_CMD` = 0x371)。
   - 直し方は「IO キューが切れても admin はこちらから閉じない。相手が閉じるか
     `NVMET_ADMIN_LINGER_MS` 経過するまで応答を続ける」。
   - **`session_done` を見て ARM へ戻るショートカットが admin の 6 つの state
     全部にあった。** RECV_HDR だけ直しても、**CC.SHN の PDU ヘッダを読んだ
     直後の RECV_SQE でコマンドを捨てる**ので症状が変わらない。linger の開始は
     switch の外に置き、受信途中の state では「admin が切れた or 待ち切れ」の
     ときだけ畳む。
2. **CC.SHN を受けても CSTS.SHST を返していなかった。** ホストは CC を書いた
   あと CSTS.SHST が 10b になるまで待つ(Linux は 5 秒)。返さないと
   `Device not ready; aborting shutdown, CSTS=0x1` で毎回 5 秒待たされる。
   1 と合わせて **disconnect が 61 秒 → 1 秒未満**になった。
3. **RDMA CM が失敗すると次の `bench` で segfault した**
   (`mlx5_qp_poll_cqe_gsi+0xf` で `gsi_qp` が NULL)。CM が失敗しても
   **passive 側の CM ジョブは誰も止めない**(`stop_requested` を見るのは
   nvmet_rdma のジョブだけで、CM ジョブは `cancel_requested` しか見ない)。
   core1 で回り続けているところへ core0 が ctx をゼロクリアするので、
   `gsi_qp` が NULL になった瞬間を踏む。**ジョブの ctx を作り直す前に
   `job_cancel_by_ctx()` + `job_count_by_ctx()` が 0 になるまで待つこと。**

**教訓**: 「相手も自分と同じ手順で喋る」という前提が、切断のような
**成功パス以外**にこそ残っている。正規実装と繋ぐまで誰も踏まない。

### 未解決: PF0 -> PF1 の RoCEv2 だけが届かない

`bench` が `rdma_cm: FAILED (REP timeout, retries exhausted)` で必ず失敗する。
**RoCEv2 自体は壊れていない** -- 切り分けの結論は「宛先が自装置のもう一方の
PF のときだけフレームがワイヤに出ない」。

| 宛先 | ワイヤに出るか | 結果 |
|---|---|---|
| Pi5(192.168.101.20 / Pi5 の MAC)| **出る**(eth2 の UDP4791 カウンタが増える)| Pi5 の Linux CM が **REJ(attr_id=0x0012)** を返してくる = 正常な往復 |
| PF1(192.168.101.11 / PF1 の MAC)| 出ない | 相手 PF は永久に REQ を受け取らない |
| PF1 の IP + **存在しない MAC** | 出ない | **宛先 MAC ではなく宛先 GID(IP)で決まっている** |

つまり **FW が「自装置に属する GID 宛の RoCE」を内部で処理しようとして
消えている**。100G の MCX456A では PF0/PF1 が直結だったので、ワイヤ経由か
内部折り返しかを区別できていなかった(**そもそも当時から内部折り返しだった
可能性がある**)。

試して効果が無かったこと(繰り返さないための記録):

- **vport のユニキャスト・ローカルループバック無効化**(`disable_uc_local_lb`)。
  cap は uc/mc とも 1 で立てられるが、症状は 1 ミリも変わらない。
- `SET_ROCE_ADDRESS` の `vhca_port_num`。この HCA は **`num_vhca_ports=0`**
  なので不要(Linux も 0 なら入れない)。GID テーブルは
  `QUERY_ROCE_ADDRESS` で読み戻して **登録内容が正しいことを確認済み**
  (PF0=192.168.101.10/02:00:00:00:10:10、RoCEv2、l3=IPv4)。

**切り分けで効いた計測**(`[DBG]` 表示として残してある):

- `mlx5_qp_poll_cqe_gsi()` の CQE ダンプ。ここで **op=2(受信完了)が
  byte_cnt=296 で自分の QP に返っている**ことに気付いた。
- `rdma_cm.c` の「想定外 MAD」表示。これで 296 バイトの正体が
  **自分の REQ のループバックではなく相手からの REJ** だと分かった。
  attr_id を見るまでは自分のパケットが返ってきたと誤読していた。

**教訓**: 「送ったのに何も返らない」ときは、返ってきた**別の何か**を捨てて
いないか先に見る。ここでは REP 以外を無言で捨てていたので、相手が明確に
REJ を返していることが 3 時間見えなかった。

**これは自作ドライバの不具合ではない。Linux 純正の mlx5 でも同じように失敗する。**
`rdma system set netns exclusive` + netns 分離(PF1 を `nsi` へ隔離)で
`ib_send_bw -d rocep1s0f0/f1 -x 3` を回すと、**QP 情報の交換(ワイヤ経由の
TCP)と ping は通るのに RDMA のデータ相が 1 バイトも進まず、Pi5 側の
UDP/4791 カウンタは 0 のまま**になる。自作スタックの症状と完全に一致する。

- **netns で分けない測定は無効。** 両方のIPがローカルだとカーネルが宛先を
  ローカルと判定して lo で短絡し、NIC に一切出ない(`linux_loopback.sh` の
  冒頭コメントに書いてあるとおり)。一度これで測って誤った結論を出しかけた。

### 内部ループバックを抑止する設定は、このカードには無い(2026-08-21 確認)

`mstconfig` に **`MPFS_UC_LOOPBACK_DISABLE_P1/P2`**(MPFS = Multi-Physical
Function Switch)という、まさにこれを止めるためのパラメータが存在する:

> When TRUE, UC traffic from PFs/Hosts will be sent to uplink regardless of
> the destination address

しかし **ConnectX-4 Lx / FW 14.32.1900 はこれをサポートしていない**:

```
$ sudo mstconfig -d 01:00.0 q MPFS_UC_LOOPBACK_DISABLE_P1
-E- The Device doesn't support MPFS_UC_LOOPBACK_DISABLE_P1 parameter
```

`show_confs` は **mstconfig が知っている全 2568 項目**(ConnectX-5/6 や
BlueField 用も含む)を並べるだけなので、**そこに出ることは対応の根拠に
ならない**。この装置の対応項目は `mstconfig -d 01:00.0 q` の出力が正で、
そこに `loopback` を含む行は **0 件**。14.32.1900 は CX-4 Lx の最終 FW
なので、更新で増えることも無い。

同じく効果が無い/存在しないことを確認したもの:

| 探した場所 | 結果 |
|---|---|
| `mstconfig q`(この装置の対応項目)| loopback 系 0 件 |
| `mstconfig q MPFS_*_LOOPBACK_DISABLE_*` | 装置が非対応 |
| `devlink dev param show` | 該当なし(`enable_roce` はあるが別物)|
| `ethtool --show-priv-flags` | 該当なし |
| vport の `disable_uc_local_lb` | **読み戻して 1 になることを確認した上で**症状不変 |
| PPLR の `lb_en`(物理ループバック)| 両ポートとも **0**(`lb_cap=0x6` は対応可能なモードを示すだけ)|
| `devlink dev eswitch show` | 両 PF とも `mode legacy` = 独立した eswitch |

#### NIC vport context の実測値(`QUERY_NIC_VPORT_CONTEXT` = 0x754)

`mlx5_dump_nic_vport_context()` で読める。`nic_vport_context` の先頭 32bit の
bit29/30/31 が `disable_mc_local_lb` / `disable_uc_local_lb` / `roce_en`
(出力側は status+syndrome+reserved の 16 バイト後ろから context なので
`out[16..19]`)。

| 時点 | word0 | roce_en | disable_uc_local_lb |
|---|---|---|---|
| bring-up 直後(未 MODIFY)| `0x01000000` | 0 | 0 |
| `roce_en=1` を書いた後 | `0x01000001` | 1 | 0 |
| `disable_uc_local_lb` も書いた後 | `0x01000003` | 1 | **1** |

つまり **`disable_uc_local_lb` は確かに書けている。書けているのに RoCEv2 は
相変わらずワイヤに出ない**(Pi5 の UDP/4791 カウンタは 0 のまま)。
前回は書きっぱなしで読み戻していなかったので「効かない」と言い切れなかったが、
今回で確定した。原因はこのビットではない。

**`lb_en` は `mlx5_ifc_pplr_reg_bits`(PPLR レジスタ)にある別物**で、
物理層のループバック。`mstreg -d 01:00.0 --reg_name PPLR --get` で読める。
ほかに `self_lb_block`(TIR context、受信側の自己ループバック遮断)と
`no_lb`(`register_loopback_control`)があるが、いずれも今回の症状とは別系統。

#### 何を見て「自装置宛」と判断しているか(2026-08-22 実測)

`rocepeer <ip> <pf1|pi5|bogus>` で**宛先 GID と宛先 MAC を独立に振って**測った。
送信完了 CQE はどの組み合わせでも成功(`synd=0x00`)で返る。

| 宛先 MAC | 宛先 GID | ワイヤに出るか |
|---|---|---|
| Pi5(遠隔)| Pi5 192.168.101.20(遠隔)| **出る** |
| Pi5(遠隔)| PF1 192.168.101.11(**自装置**)| 出ない |
| PF1(**自装置**)| 192.168.101.99(遠隔・未使用)| 出ない |
| PF1(**自装置**)| PF1(**自装置**)| 出ない |

**MAC と GID の両方が自装置に属さないときだけワイヤに出る。** どちらか一方でも
自装置のものなら内部で消える。前回「宛先 GID で決まっている」と書いたのは
不正確で、MAC 側の判定(MPFS の L2 転送)も独立に効いている。

#### VLAN で 2 ポートを分離できるか -> できない

MAC 側は MPFS が (VLAN, MAC) で引くので VLAN で分離できる見込みがあるが、
**GID 側の判定が VLAN を見ていない**ので意味が無い。`SET_ROCE_ADDRESS` の
`roce_addr_layout` には `vlan_valid` / `vlan_id`(roce_address の bit 0x83 /
0x84-0x8f = `in[32..33]`)があるので、`gidvlan 100` で **PF1 の GID だけを
VLAN 100 付きで登録**し、PF0 から「遠隔 MAC(Pi5)+ PF1 の GID」で送る、という
crux だけを切り出した実験ができる。結果は **ワイヤ 0 パケットのまま**だった。

GID 側だけで送信を止めるには十分なので(上表 2 行目)、**VLAN をどう組んでも
PF0 -> PF1 の RoCEv2 はワイヤに出せない。** ついでに、この実験は Pi5 側の
VLAN 設定も自作スタックの 802.1Q 対応も要らない(PF0 が出すかどうかだけを
見ればよい)ので、先に crux を潰すのが安い。

#### フローテーブルで「必ずワイヤへ出す」ことはできるか(2026-08-22)

`ftprobe` / `txuplink` / `fdbprobe` シェルコマンドで実測した。

| テーブル型 | 作成 | 転送先の指定 |
|---|---|---|
| NIC_RX | (bring-up で作成済み)| TIR へ転送(既存)|
| **NIC_TX** | 作れる。ルートにもできる | **不可**。UPLINK(0x8)は syndrome 0x006cdcfa、VPORT(0x0)は 0x0022a5af。通るのは ALLOW/DROP だけ |
| **FDB** | 作れる | **`FWD -> VPORT(0x0) id=0xffff`(uplink vport)が通る** |
| ESW_*_ACL / SNIFFER_* | 作れる | 未評価 |

- NIC_TX に catch-all の ALLOW を入れてルートにしても通信は正常
  (tcpbench 549/626 MiB/s)。**つまり NIC_TX ステアリング自体は使えるが、
  「ワイヤへ出す」という宛先が無い** -- 内部折り返しの判断は NIC_TX より
  下流(MPFS)で行われている。
- **FDB は危険。** catch-all のエントリを置くと、**ルートに設定していなくても
  転送が壊れる**(ARP の解決すら失敗するようになった)。FTE を消せば回復する
  ので `fdbprobe` は後始末を入れてあるが、おかしくなったらプロセスを
  再起動すること(vfio-pci がデバイスをリセットする)。
- FDB を使うなら **`misc_parameters.source_port` で送信元 vport に絞る**必要が
  ある。catch-all のままだと uplink から入ってきたフレームまで uplink へ
  送り返すことになり、**ワイヤ上でループする**。

#### 実在しなかった対策(調べた記録)

| 案 | 結果 |
|---|---|
| ALLOC_TRANSPORT_DOMAIN の `disable_lb` ビット | **フィールドが存在しない**(`alloc_transport_domain_in_bits` は opcode/uid/op_mod/reserved のみ)。そもそも TD は TIS/TIR 用で RC/UD QP は通らない |
| SQ context の `wire_prio` / eSwitch bypass | **`wire_prio` はヘッダに存在しない**(`bypass` は LAG の `port_select_flow_table_bypass` と FEC のみ)。RoCE QP は独立した SQ オブジェクトを持たない(SQ は QP コンテキスト内)ので設定箇所が無い |

**結論: この構成で PF0<->PF1 の RoCEv2 を通す手段は無い。** 相互運用の相手は
Pi5 を使う。

**次にやること**: Pi5 の Linux NVMe-oF RDMA ターゲットへ自作イニシエータを
向ける(`bench` に宛先指定が要る)。Pi5 は `::ffff:192.168.101.20` の
**RoCE v2 GID を持っている**(ブリッジ配下でも生える)ので、相互運用の
相手として使える。PF0<->PF1 のループバックは、この構成では諦めるほうが早い。

**nvmet_rdma.c 側には上記 1・2 の修正を入れていない**(RoCEv2 が動かないので
検証できないため)。動くようになったら同じ手当てが要る。

## 外部ホストとの IPv6(2026-08-22)

**`bench`(RoCEv2)は `PLAN_protocol_gaps.md` の項目ではない。** 残っているのは
B1〜B4 の IPv6 系だけで、どれも RDMA を使わない。Pi5 と繋いだことで、
逆に旧ループバックでは検証できなかった項目が測れるようになった
(RA の送り手・実スイッチのマルチキャストスヌーピング・IPv6 拡張ヘッダの
生成元がすべて Pi5 で用意できる。radvd は無いが python3 の AF_PACKET で足りる)。

### 内部 `tcpbench` を回すと外部ホストの接続を受けられなくなる

**`tcpbench` を 1 回でも実行すると、以後そのプロセスでは Linux からの
`nvme connect` が必ずタイムアウトする**(`failed to connect socket: -110`)。
`tcpbench` が張る自作イニシエータのセッションがターゲットの accept を
占有したままになるため。`nvmet <port>` を叩いても
`nvmet: 既に常駐起動済み` と言われるだけで復旧しない。C1 で「リスナが居る
ポートには RST を返さない」ようにしてあるので、**相手からは SYN が黙って
捨てられるようにしか見えない**(D1 で踏んだのと同じ見え方)。

- 対処: **外部ホストとの相互運用テストは `vn_start.sh` 直後に行う。**
  内部ベンチを回したら、外部テストの前にプロセスを立て直す。
- 実機で確認: フレッシュな起動 -> `nvmet 4421` -> Linux から discover /
  connect / 再接続 x2 / digest 付き 64MB、すべて成功。そのあと
  `tcpbench 64 r` を 1 回流すと、次の `nvme connect` が失敗する。

### Linux と繋いで初めて出た IPv6 の不具合 3 件

**3 件とも「自作 ↔ 自作では両側が同じ振る舞いをするので絶対に検出できない」形。**

1. **vport のマルチキャスト受信が無効だった。** NDP の NS は要請ノード
   マルチキャスト(L2 は `33:33:ff:XX:XX:XX`)宛で来るので、vport の
   マルチキャストフィルタに弾かれ、**外部ホストからの IPv6 が 1 フレームも
   受け取れなかった**。IPv4 は ARP がブロードキャストなので通っていて、
   それで気付かなかった。`MODIFY_NIC_VPORT_CONTEXT` の `promisc_mc`
   (field_select bit27 = `in[15]` の 0x10、context bit 0x781 = `in[496]` の
   0x40)を bring-up で立てる。**RA も MLD も同じ経路なので B1/B2 の前提。**
2. **NS/NA の Target Address のオフセットが 4 バイトずれていた。**
   `NDP_OFF_TARGET=4` かつ `8u + NDP_OFF_TARGET` で読み書きしていたため
   **offset 12 から読んでいた**(RFC 4861 では 8)。メッセージ長も 32 では
   なく 36 になっていた。送信側も受信側も同じズレ方をするので
   `ping6`/`udptest6`/`tcp6test`/`dadtest` は全部通る。正しくは
   `NDP_OFF_TARGET=0` / `NDP_BODY_LEN=16`(`8u` に reserved の 4 が
   含まれている)、NA のフラグは `msg+4`。
3. **NA の Target Address に常に自分のリンクローカルを入れていた。**
   グローバルアドレス宛の NS にリンクローカルを名乗る NA を返すので、
   相手は solicited した対象と一致せず捨てる。**要請された対象をそのまま
   返す**のが正しい。リンクローカルへの ping6 だけ通ってグローバルへの
   ping6 が通らない、という形で出た。

### グローバル IPv6 アドレス(B1 の前提)

`netif_t` に `ip6_global` / `ip6_global_set` / `ip6_prefix_len` を持たせた。
**IPv6 で初めて `netif_t` が持つ状態**(リンクローカルは MAC から毎回導出)。
`ipv6_addr_is_ours()` はグローバル本体とその要請ノードマルチキャストも受け、
`netif_find_by_ip6()` と送信元選択(`ipv6_source_for()`、リンクローカル宛と
マルチキャスト宛以外はグローバルを使う)も対応済み。

- `ip6addr` — 表示 / `ip6addr <if> <addr> [plen]` で設定 / `<if> off` で解除。
  **アドレスは RFC 4291 の完全表記(8 グループ)のみ。** `::` は展開しない。
- これで **グローバルアドレスを名乗る手段が無くて保留になっていた
  A1 の IPv6 エンドツーエンドと A6 の IPv6 UDP 分割が動かせる。**
  B1(SLAAC)は同じ状態を RA から埋める形になる。
- 検証: Pi5 の br0 に `2001:db8:0:1::20/64` を振って
  `ping6 2001:db8:0:1::10` が通ること(NS/NA からエコーまで実際に往復し、
  Linux の近隣キャッシュに `REACHABLE` で載る)。

## IPv6 アドレス自動設定 SLAAC(`PLAN_protocol_gaps.md` 段階 11 = B1)

RS(ICMPv6 type 133)を `ff02::2` へ送り、RA(type 134)の Prefix Information
から **プレフィックス + EUI-64** のグローバルアドレスを作る。デフォルトルータ
(A1 の `gateway6`)も RA から設定する。起動時に各インターフェースへ RS を
1 回だけ出す(`SLAAC_RS_NUM` / `SLAAC_RS_INTERVAL_MS`。RFC 4861 は 3 回 x 4 秒
だが、ルータの居ないこのリンクでは起動が延びるだけ。**実 LAN へ出すときは
RFC 値へ戻すこと**)。**非要請 RA はいつ届いても処理する。**

- `slaac [<if>] [ms]` — RS を送って RA を待ち、結果を表示する。
- `slaactest [dump]` — 対向 PF にルータ役をさせて RA を注入する 12 項目の検査。
- `ip6addr` — 手動設定は SLAAC より優先される(**RA では上書きしない**)。

### 入れないと退行する / 危険になる判断

1. **NDP は hop limit 255 以外を捨てる**(RFC 4861 6.1)。ルータは転送のたびに
   hop limit を減らすので、255 で届いた = 同一リンク上から来た、の意味。
   **これが無いとリンク外のノードが RA でデフォルトルータとプレフィックスを
   乗っ取れる。** RS/RA/NS/NA の 4 つに効かせている。
2. **RA の送信元がリンクローカルでなければ捨てる**(同 6.1.2)。
3. **RFC 4862 の「2 時間ルール」**。既存アドレスの寿命を縮める RA は、残りが
   2 時間以下なら無視する。**無いと偽の RA を 1 個投げるだけで他人のアドレスを
   即座に失効させられる。**
4. **手動設定(`ip6addr` / `route`)を RA で上書きしない。** 外部の RA が
   飛んでくると `routetest` / `pmtutest` が名乗らせるアドレスやゲートウェイが
   原因不明で書き換わる。
5. **MTU オプションは記録するだけで適用しない**(`netif_t.ra_link_mtu`)。
   リンク MTU を下げると `mss_cap` も下がり、**`txdrop` を 0 に戻し忘れたときと
   同じで「以後の測定が全部おかしい」状態**になる。経路ごとの MTU 低下は
   A5/A6(PMTUD)が宛先単位で扱うので実害も無い。`reachable time` /
   `retrans timer` も採用しない(`g_neigh_cache_ttl_ms` は `arpage`/`arptest`
   の前提値)。

### DAD は RA 受信ハンドラから実行できない

`ipv6_dad()` は内部で `net_poll_all_and_dispatch()` を回すので、受信処理の
中から呼ぶと受信が再入する(`arp_resolve()` を送信ホットパスから呼んだときと
同じ形)。冷たい経路の `ipv6_slaac_solicit()` が RA 処理の後に実行する。
**したがって非要請 RA だけで設定されたアドレスは DAD 未実施のまま**になる
(`netif_t.ip6_global_dad` が `NETIF_DAD_UNKNOWN`)。衝突を検出したときは
**そのアドレスを使わない** -- 手動設定の「検出しても使い続ける」方針(A3)は
2 つの PF を同一プロセスで駆動しているせいの妥協で、RA から勝手に作った
アドレスまで使い続ける理由は無い。

### 寿命の判定をホットパスに置かない

`ipv6_global_addr()` は**受信フレームごと**(`ipv6_addr_is_ours`)と
**送信ごと**(`ipv6_source_for`)に通る。無条件に `timer_now()` を呼ぶと
そこへ時刻読み出しが乗るので、**`ip6_global_valid_until != 0` のときだけ**
`ipv6_slaac_age()` を呼ぶ。手動設定と未設定は期限を持たない(=0)ので
コストがかからない。ルータ寿命も同じ関数で判定する(`netif_next_hop6()` は
inline の送信ホットパスなので触らない)。**ルータが消えたまま誰もその
インターフェースを使わなければ `gateway6` は次に使われるまで残る。**

### 検証: 自作でない送り手を必ず 1 つ挟む

`slaactest` は RA を**自作コードで組んで**注入するので、それだけでは
「自分の間違いを自分で受け入れて PASS」になる。2 つで塞ぐ:

- **`tools/ra_check.c`** — `slaactest dump` の 16 進を、このリポジトリのコードを
  一切 include せず glibc の `struct nd_router_advert` /
  `struct nd_opt_prefix_info` で読み直す(`disc_log_check.c` /
  `ip_frag_check.c` / `icmp_mtu_check.c` と同じ考え方)。
- **`tools/send_ra.py`** — Pi5 で動かす**本物の送り手**(radvd が無いので
  AF_PACKET)。`listen` を付けると RS を待って RA を返す「ルータ役」になり、
  **自作の RS がワイヤに出ているかを相手側で確認できる**(Pi5 に tcpdump が
  無いのでこれが唯一の観測手段)。

```bash
ssh rpi5-rdma-target 'cd ~/vfio_nvme && gcc -O2 -Wall -Wextra -o /tmp/ra_check tools/ra_check.c'
scp tools/send_ra.py pi5:/tmp/     # Pi5 側
sudo python3 /tmp/send_ra.py eth2 1800 1800 6 listen
```

**Pi5 で AF_PACKET を使うときの落とし穴 3 つ**(どれも送信は動くので、受信を
書くまで気付けない):protocol を省くと 1 フレームも受信できない /
**`htons()` が要るのは `socket()` の第 3 引数だけ**で `bind()` のタプルに
掛けると二重変換になる / **`ETH_P_IPV6` では駄目で `ETH_P_ALL` が要る**
(br0 のポートである eth1/eth2 では bridge の rx_handler がフレームを先に
消費し、プロトコル別配送まで届かない。br0 側で待っても、ホストが join して
いないマルチキャスト `ff02::2` は上がってこない)。

### 実機で踏んだこと

- **陰性対照そのものが RFC 違反だった。** `prefix_len=48` の陰性対照に `/64`
  用のプレフィックスを長さだけ変えて使い回していたが、**プレフィックス長より
  下のビットは 0 でなければならない**(RFC 4861 4.6.2)。`ra_check` が検出した。
  **陰性対照は「試したい性質以外は正しい」形にする。**
- **外部テストの残骸で `slaactest` が落ちる。** Pi5 から RA を受けた直後だと
  対向 PF に RA 由来の `gateway6` が残っていて、サブネット外宛を Pi5 へ向けて
  しまう(Pi5 はルータではないので Destination Unreachable が返る)。
  テスト側で peer の `gateway6` も退避・復元するようにした。**A1 を入れた後は
  「宛先が同一リンクにある」という暗黙の前提がテストごとに壊れうる。**
- **他インターフェース宛の RA で待機を打ち切っていた。** 2 つの PF が同じ
  リンクに居るので、PF1 の RS に対する RA が PF0 に届くことがある。RA の受信
  カウンタだけでなく**どのインターフェースが処理したか**も見る。

## 到達不能検出 NUD(`PLAN_protocol_gaps.md` 段階 13 = B3)

A2 の「失効 -> 確認要求 -> 延命/破棄」に、RFC 4861 7.3 の残りを足したもの。
検証は `nudtest`(TTL を一時的に縮めて実行し、**必ず元に戻す**)。

1. **DELAY 相**。失効したエントリを**使った瞬間には確認要求を出さない**。
   `probe_at == 0` を「失効後まだ一度も使われていない」印として使い、
   DELAY(TTL/12。既定 60s なら 5 秒 = RFC の DELAY_FIRST_PROBE_TIME)を
   置いてから初めて確認要求を出す。**新しい状態フィールドは足していない。**
2. **上位層の到達確認**。TCP の累積 ACK が進んだ = 相手が自分のデータを
   受け取った、という**確認要求より強い証拠**なので、確認要求を出さずに延命
   する。`priv->neigh_confirm` を `ack_advanced` の隣で立て、次の送信で
   `tcp_resolve_mac()` が消費する。
3. **確認要求はユニキャスト**(ARP request も NS も)。MAC を知っている相手に
   ブロードキャスト/マルチキャストを撃たない。**B2 の後はこの差が効く** --
   スヌーピングするスイッチでマルチキャストが刈られていても必ず届く。
4. **NA のフラグ解釈**: **Solicited のときだけ延命**、**Override 無しで既存と
   違う MAC を主張する NA は無視**。無いと**偽の NA 1 通で他人宛の
   トラフィックを奪える**。

**「使われていないエントリを能動的に確認する」は入れていない。** RFC 4861 も
Linux も確認するのは「使われたとき」だけで、使っていない相手を叩くのは
帯域と相手の割り込みを捨てるだけ。計画にあった項目だが、直さないほうが正しい。

### 検証で取り違えやすい 3 点

- **`arptest` が落ちたら、まず仕様変更を疑う。** DELAY 相を入れたので
  「stale を 1 回引いただけ」では確認要求が出ない。テスト側を合わせる。
- **TCP 往復中のブロードキャスト ARP は NUD の確認要求ではない。**
  猶予切れで破棄された後の再解決。Pi5 のブリッジ越しでは **RTO による
  200ms の停止**が起きるので、猶予(TTL/6)がそれより短いと必ず踏む。
- **「確認要求が 0 個」だけでは検証にならない**(DELAY 中で黙っていただけ
  かもしれない)。`g_neigh_confirm_count` が増えていることを併せて見る。
- **`tools/sniff_neigh.py`** を Pi5 で回すと、**ワイヤ上で本当にユニキャストに
  なっているか**を相手側から読める(初回解決はブロードキャスト/マルチキャスト、
  到達確認はユニキャスト、と並んで出る)。

## MLD と IPv6 拡張ヘッダ(`PLAN_protocol_gaps.md` 段階 12 = B2 / 14 = B4 前半)

参加しているマルチキャストグループ(= 要請ノードマルチキャスト)を MLD で
報告し、Querier の Query に応答する。**スヌーピングするスイッチの配下では、
これが無いと要請ノードマルチキャストが転送されず NDP が一切通らない。**

- `mld` — 参加グループと版(v1 互換 / v2)を表示。
- `mld report` / `mld leave` — 非要請 Report / 離脱通知。
- **`mld off` / `mld on` — MLD の送信を止める/再開する。** `txdrop` と同じ
  恒久デバッグ機能で、**止めると実スイッチ配下では通信が死ぬ**(それが
  「MLD が効いている」ことの唯一の証明手段でもある)。**戻し忘れに注意。**
- `mldtest [dump]` — 対向 PF に Querier 役をさせる 9 項目の検査。

### MLDv1 も要る(Linux ブリッジの既定が v1)

`mcast_mld_version` の既定は **1**。実際に繋ぐと v1 の Query が飛んでくるので、
v2 だけ実装しても片手落ちになる。**v1 と v2 の Query は ICMPv6 メッセージ長で
区別する**(v1=24、v2>=28。Linux も同じ判定)。v1 の Query を受けたら
一定時間 v1 互換モードに入り、Report を v1 で送る。

**宛先が版と種類で違う**: v2 Report は **ff02::16**、v1 Report は**グループ自身**、
v1 Done は **ff02::2**。

### MLD は普通の `ipv6_send()` では送れない

- **Hop-by-Hop の Router Alert が必須**(RFC 2710 3)。
- **hop limit は 1**(`ipv6_send_from()` は 255 固定)。
- **チェックサムの疑似ヘッダに使う next header は 58(ICMPv6)で、IPv6 ヘッダに
  書く 0(Hop-by-Hop)ではない。** 長さも ICMPv6 メッセージ長だけで拡張ヘッダを
  含めない。ここを取り違えると**相手だけが静かに捨てる**。

受信側の妥当性検査は 3 つ(RFC 3810 6.2): hop limit が 1 / Router Alert がある /
送信元がリンクローカル。**抜けるとリンク外のノードにマルチキャスト受信を
止められる**(B1 の hop limit 255 検査と同じ性質)。

### 拡張ヘッダの走査(受信側)

MLD の Query が Hop-by-Hop 付きで届くので、`ipv6_skip_ext_headers()` が
先に要った。Hop-by-Hop / Routing / Destination Options を辿り、Fragment は
ログを出して破棄する(再構成は IPv4 側と同じく未実装)。検証は `ext6test`。

- 長さは **(hdr_ext_len + 1) * 8**(最初の 8 バイトを含まない)。
- **Hop-by-Hop の TLV では PAD1(type 0)だけが長さフィールドを持たない。**
  一律に {type, len} で読むとそこからずれる。
- **未知オプションの扱いは type の上位 2 ビットが決める**(RFC 8200 4.2)。
  00 以外は破棄する。一律に読み飛ばしてはいけない。
- **Routing ヘッダは Segments Left が 0 でなければ破棄する**(同 4.4)。
  読み飛ばすと **RFC 5095 で廃止された Routing Type 0** を受け入れてしまう。
- **上位プロトコルの長さは payload_length から拡張ヘッダぶんを引く。**
  引き忘れると TCP/UDP のチェックサム検証が全部壊れる。

### 送信側の IPv6 断片化と、HW オフロードが壊した 4 バイト

**IPv6 は経路上で分割されない**(RFC 8200 4.5)ので、MTU 超は送信元が
Fragment 拡張ヘッダで割る(`ipv6_send_fragmented()`)。IPv4 との違いは、
分割情報が 8 バイトの拡張ヘッダに載ること(1 断片は MTU−40−8)、
next_header が 44 になり元のプロトコル番号が Fragment ヘッダへ移ること、
Identification が 32bit であること。

**`mlx5_net_post_frame()` は IPv6 の next_header が 44 のフレームでは
L4 チェックサムオフロードを外す。** HW は拡張ヘッダを飛ばした先を L4 ヘッダと
みなしてチェックサムを書き込むので、**2 個目以降の断片のデータ 6-7 バイト目が
潰れる**(1 個目はそこが本物の UDP チェックサム欄なので気付けない)。実機では
「4000 バイト中 4 バイトだけ化ける」という形で出た。

**そして、その修正が別のバグを露出させた。** `udp_send6()` が疑似ヘッダの
送信元に常にリンクローカルを使っており、グローバル宛のときだけ食い違って
いた。**それまでは NIC の L4 オフロードが正しい値へ上書きしていたので誰も
気付かなかった。** 「HW が黙って直してくれる」たぐいの不具合は、HW を止めた
瞬間に別の場所で出る。

### 検証: Linux に再構成させる

自作 ↔ 自作では受信側が再構成しないので、自分で組み直して一致を見るところ
までしか言えない。**`tools/udp6_echo.py` を Pi5 で動かし、`udp6send` で
MTU 超の UDP を送って Linux に再構成させる**のが本筋の確認。

```bash
scp tools/udp6_echo.py pi5:/tmp/   # Pi5 側
sudo ip -6 addr add 2001:db8:0:9::20/64 dev br0
python3 /tmp/udp6_echo.py 7780 40
# 自作側
ip6addr mlx5-pf0 2001:0db8:0000:0009:0000:0000:0000:0010 64
udp6send 2001:0db8:0000:0009:0000:0000:0000:0020 7780 9300
```

`tools/ip6_ext_check.c` は `ext6test dump` の拡張ヘッダを glibc の
`struct ip6_frag` / `ip6_rthdr` / `ip6_hbh` で読み直す。**glibc の
`IP6F_OFF_MASK` などはネットワークバイト順のまま掛ける定数**で、`ntohs()`
した値に掛けると壊れる(このツールを書いたとき実際に間違え、正しい実装を
NG と判定した)。

### 検証: スヌーピングする実スイッチで陰性/陽性の対を取る

Pi5 のブリッジを Querier + スヌーピングにし、ポートの未登録マルチキャストの
フラッディングを止めて測る。**これをやらないと「元々フラッディングで通って
いただけ」と区別がつかない。**

```bash
# Pi5 側(ブリッジをスヌーピング Querier にし、未登録は転送しない)
sudo ip link set br0 type bridge mcast_snooping 1 mcast_querier 1
sudo ip link set dev eth1 type bridge_slave mcast_flood off
sudo ip link set dev eth2 type bridge_slave mcast_flood off
sudo /sbin/bridge mdb show          # 自作の Report で学習したグループが載る
# 終わったら必ず戻す
sudo ip link set dev eth1 type bridge_slave mcast_flood on
sudo ip link set dev eth2 type bridge_slave mcast_flood on
sudo ip link set br0 type bridge mcast_querier 0
```

| 自作側 | MDB | Pi5 から `ping6` |
|---|---|---|
| `mld off` | eth1/eth2 にエントリ無し | **100% ロス** |
| `mld on` + `mld report` | 両 PF のグループが載る | **0% ロス** |

- **`bridge` コマンドは Pi5 にある**(`/sbin/bridge`。非ログインシェルの
  PATH に入っていないのでフルパスで叩く)。`bridge mdb show` が
  **相手側から見た決定的な証拠**になる。
- **`mld leave` では通信は止まらない。** 離脱を通知するとブリッジが
  group-specific query を投げ、こちらはまだリスナなので即座に報告し直す
  (RFC どおりの正しい動作)。陰性対照には `mld off` を使う。
- **`tools/mld_check.c`** — 送信した MLD を libc の `struct mld_hdr` /
  `struct icmp6_hdr` で読み直す。MLDv2 のレコード構造だけは Linux の
  `include/net/mld.h` からの転記(あのヘッダはカーネル専用の型を引くので
  ユーザ空間から include できない)なので、**Linux 自身が出した MLDv2 Report を
  同じツールに食わせて**転記を検算する。
- **`tools/sniff_mld.py`** — Pi5 で MLD を観測して `MLDDUMP` 形式で吐く。
  自作の Report がワイヤに出ているかの確認と、Linux の MLD を `mld_check` へ
  流すための道具。**ブリッジポートでは `ETH_P_ALL` でないと受信できない。**

## Get Features と Identify の CNS(`PLAN_protocol_gaps.md` 段階 15 = D2 / 16 = D3)

Pi5 の `nvme-cli` から叩いて足りないと分かったものを実装した。**D 系は
実ホストで直接叩けるので、B 系のような検証の工夫は要らない。**

- `nvme get-feature -f 6|7|0x0b|0x0f` が値を返す(`-s 1` default /
  `-s 3` supported capabilities も)。
- `nvme list-ns`(CNS=0x02)/ `nvme ns-descs`(CNS=0x03)が通る。
- Linux が接続時に投げる CNS=0x05 はゼロ埋めで正常完了。

### CQE の status は Linux の `NVME_SC_*` を 1bit 左シフトした値

status フィールドは **bit0=Phase / bit8:1=SC / bit11:9=SCT / bit15=DNR**。
Linux の `enum { NVME_SC_* }` は SC と SCT を 1 つの 15bit 値として持って
いる(`NVME_SCT_COMMAND_SPECIFIC = 0x100`、`NVME_STATUS_DNR = 0x4000`)ので、
**そのまま 1bit 左シフトすれば status になる**。

既存の `NVMET_SC_GENERIC_ERROR = 0x0002` は名前と裏腹に
**SC=0x01 Invalid Command Opcode** そのもの。「未対応の FID」「未対応の CNS」
まで全部これで返していたので、ホストからは**コマンドごと無いのか
フィールドが悪いのかが区別できなかった**。

### 「知らない値にも成功を返す」のをやめる

Set Features は**どんな FID でも成功を返していた**。ホストは設定できた
つもりで先へ進むので、Get Features を実装した瞬間に必ず食い違う。
Get / Set が **同じ判定関数(`nvmet_feat_current()`)** を通るようにして、
対応 FID が片方だけ増えることが起きないようにしてある。

同じ理由で **Select=saved と Set Features の SV=1 は「保存できない」で返す**
(current の値を返すと「保存された値がある」という嘘になる)。
Select=supported capabilities は現在値ではなく能力ビットを返す別の関数。

### VS が 0 だと CNS=0x03 は永久に来ない

`nvme ns-descs` は手で叩けば通るが、**ホストが自発的に取りに来るかは
VS レジスタ(Property Get offset 0x08)次第**で、0 のままだと「1.0 未満」と
見なされて 1.3 以降の CNS を一切使わない。Property Get の VS と Identify
Controller の VER(offset 80)に 1.3.0 を入れて初めて接続時に飛んでくる。
**機能を実装しても、能力の広告を直さないとホストは使わない**(`oncs` が 0 だと
`blkdiscard` が ioctl 段階で弾かれるのと同じ構造。D4 でも同じことをする)。

### EUI-64 / NGUID を全 0 のままにしない

全 0 は「識別子を持たない」の意味なので、**ホストは名前空間の同一性を
判断できない**。`id_ns` の nguid(offset 104)/ eui64(120)と CNS=0x03 の
記述子リストに**同じ値**を入れる(片方だけだと食い違う名前空間に見える)。
値は先頭に 0x02(ローカル管理ビット)を置いて実在の OUI を騙らず、末尾
2 バイトに NSID を入れて D8 で増えても衝突しないようにしてある。
dmesg の `No UUID available providing old NGUID` が「読めている」証拠。

### `tools/*_check.c` はもう要らない場面がある

`disc_log_check.c` 系の「相手側の構造体でパースさせる」道具が要ったのは
**実ホストへ繋ぐ経路が無かったから**。Pi5 と繋がった今、`nvme ns-descs` は
Linux の TLV パーサそのもので、カーネルは NGUID を `wwid` に採用する。
**自作でない実装に読ませる、という目的はそれで達成されている**ので、
D3 では新しい check ツールを作っていない。

### nsid の扱いは SPDK の `_nvmf_ctrlr_get_ns_safe()` に合わせた

| 条件 | 応答 |
|---|---|
| nsid が 0 / 範囲外 / ブロードキャスト | Invalid Namespace or Format(SC=0x0B)|
| 範囲内だが未使用 | **ゼロ埋めで正常完了**(エラーではない)|
| CNS=0x02 の nsid | 「**この値より大きい** NSID を並べよ」の意味。対象を指すのではない |

OptiPlex に **SPDK のソースが置いてある**(`~/spdk/lib/nvmf/` の `ctrlr.c` /
`ctrlr_bdev.c`)ので、
NVMe 仕様の細かい振る舞いはこれとカーネルヘッダ
(`/usr/src/linux-headers-*/include/linux/nvme.h`)で確認できる。**推測しない。**

## TRIM(Deallocate)と Write Zeroes(`PLAN_protocol_gaps.md` 段階 17 = D4)

`nvmet.c` に Write Zeroes(0x08)と Dataset Management(0x09)を足し、
ONCS(offset 520)の bit2/bit3 と `id_ns` の DLFEAT(offset 33)で広告する。
実体は `nvmet_zero_lba_range()` の `volatile_fast_zero()`(`net.h` に追加。
**既存の `nvmet_zero()` はバイト単位のループ**なので 32MB には使えない)。

### NLB は 2 つあって、0's based なのは片方だけ

| フィールド | 0's based か |
|---|---|
| Write Zeroes の cdw12 NLB | **そう**(+1 する)|
| DSM の cdw10 NR(範囲数)| **そう**(+1 する)|
| **`struct nvme_dsm_range` の NLB** | **違う**(0 = 0 ブロック。そのまま使う)|

根拠は Linux の `nvme_setup_discard()` が `nlb = bi_size >> lba_shift` を
+1 せず入れていることと、SPDK の `nvmf_bdev_ctrlr_unmap()` が
`lba_count = dsm_range.length` とそのまま使っていること。
**この取り違えはバイト配置の検算(`tools/*_check.c`)では見つからない** --
値の解釈の問題なので、「8 ブロックだけ消えて 9 ブロック目が残る」ことを
実データで確かめるしかない(`blkdiscard -l 4096` の後に 9 ブロック目以降を
`cmp` する)。

### discard の上限を広告しないと 268MB の memset が飛んでくる

DMRL / DMRSL / DMSL は **Identify CNS=0x06(I/O Command Set specific
Identify Controller、CSI=NVM)の `struct nvme_id_ctrl_nvm`** にある。
広告しないと Linux は `max_hw_discard_sectors` を絞らないので、
`blkdiscard` 一発で名前空間全体の Deallocate が来る。RAM ディスクを
memset する実装ではそのあいだジョブスケジューラが止まる。

- DMRSL = 65536 ブロック(32MB)を広告して、Write Zeroes の NLB 上限
  (16bit + 1 = 65536)と最悪ケースを揃えてある。
- 効いていることの確認は **`/sys/block/nvme0n1/queue/discard_max_bytes` が
  33554432 になる**こと。全体 `blkdiscard` は 32MB x 8 に分割されて 67ms。
- **D3 で「CNS=0x06 は未対応のままでよい」と判断したのは早すぎた。**
  Linux が接続時に投げてくる CNS には、たいてい投げてくるだけの理由がある。

### DSM のデータは in-capsule で来る(R2T 経路は作っていない)

Linux は discard を `rq_data_dir()==WRITE` と見なすので
`nvme_tcp_has_inline_data()` が真になり、**16 バイト x NR は必ず
in-capsule で届く**。`pending_writes` は write 専用(受信先が RAM ディスク
固定)なので、そこへ流し込むと**範囲リストを名前空間へ書き込む**。
R2T で来たら黙って成功を返さず Invalid Field で落とす(消したつもりに
させない)。

### dispatch まで生かす必要があるデータは ready-ring と 1 対 1 で置く

write は受信時に RAM ディスクへ直接置くので、**これまで dispatch 時に
受信データを読むコマンドが 1 つも無かった**。共有の `data_buf` に置くと
次のコマンドが届いた時点で上書きされる。かといって ready-ring の要素に
4KB の配列を持たせるとスロットの間隔が 4KB 開いて **hot path の TLB を
荒らす**ので、`nvmet_ctx_t` 側に `dsm_stage[NVMET_READY_RING][4096]` を
置き、ring からは既存の未使用フィールド `data_dst` で指す。

### 検証(Pi5)

**「書いてから消して読む」の 3 段で、かつ境界の外が残っていることまで見る。**
ゼロが返るだけでは元々ゼロだった可能性がある。

```bash
sudo blkdiscard -o 0 -l 4096 /dev/nvme0n1      # 実装前は Operation not supported
sudo mkfs.ext4 -q -F -E discard /dev/nvme0n1   # 実ファイルシステム経由の多範囲 DSM
sudo fstrim -v /mnt/nvt                        # 229.8 MiB trimmed
```

## SMART と Error Information ログ(`PLAN_protocol_gaps.md` 段階 18 = D5)

Get Log Page に LID=0x02(SMART、512 バイト)と LID=0x01(Error Information、
64 バイト)を足した。統計は `nvmet_ctx_t` に持ち、**セッションをまたいで
持ち越す**(実コントローラの通電中統計はホストが繋ぎ直しても 0 に戻らない。
リセットは `nvmet_job_start()` = プロセス起動時だけ)。

- **温度はケルビン。** 0 のままだと nvme-cli が **-273℃(0 K)**と表示する。
- **128bit カウンタは 16 バイトぜんぶ書く**(`nvmet_wr128le()`)。上位 8 バイトに
  残骸があると桁が跳ねる。
- `data_units_read/written` は **512 バイト x 1000 単位で切り上げ**。

### エラー記録のフックは `nvmet_build_cqe()` に置く

エラー応答は 50 箇所あるが、**全部がこの関数を通る**。ここに
`status != 0` の分岐を 1 つ置けば取りこぼさない(呼び出し側に配ると、次に
足すエラーパスで必ず忘れる)。引数へ `ctx` を足す機械的な変更で済む。
sqid / nsid / lba は dispatch の入口で `ctx->err_*` に置き、LBA を持つ
コマンドだけがエラー直前に `err_lba` を入れる。

- **`status_field` には CQE の status ワードをそのまま入れる**(bit0 が
  phase の位置に来る 16bit)。Linux の `nvmet_set_error()` も
  `cqe->status` と `status_field` の両方へ同じ `status << 1` を入れており、
  nvme-cli は表示時に 1 ビット右へ寄せる。**寄せて入れると nvme-cli の
  表示だけが半分の値になる。**
- **Fabrics コマンドは nsid のワードを fctype に使う**ので、そこを nsid として
  記録しない。

### 実装していない能力ビットは立てない(LPA=0)

LPA bit0(名前空間ごとの SMART)も bit1(Command Effects ログ)も持って
いないので 0 のまま。**立てるとホストがそのログを取りに来て失敗する。**
ELPE は 0's based なので 0 = 1 エントリ保持、が正しい。

### 検証: 「増えること」を 3 点で見る

固定値を返しているだけでも 1 点だけ見れば通ってしまう。
**接続直後 → IO を流した後 → わざとエラーを起こした後**で比べる。

| 見るもの | 期待 |
|---|---|
| `nvme smart-log` の `Data Units Written` | 64MiB write のあと 132(= 67.58 MB)|
| `host_write_commands` | 256(= 64MiB / MDTS 256KiB)|
| `nvme error-log` の陽性対照 | 範囲外 write-zeroes で `status_field : 0x4080` / **`lba : 0x7fff8`** / `sqid : 1` |
| admin 側の陽性対照 | `get-feature -f 0x7f` で `sqid : 0` / `0x4002` |
| `num_err_log_entries` | エラーログの `error_count` と一致して増える |

**nvme-cli がフィールド名つきで全項目を展開する**ので、オフセットを間違えれば
「別のフィールドに値が出る」形で必ず見える。`tools/smart_check.c` は
そのぶん要らない。

## 非同期イベントと複数名前空間(`PLAN_protocol_gaps.md` 段階 19 = D6 / 21 = D8)

**この 2 つは組でしか検証できない。** AER は「イベントを生成する何か」が
無いと保留のままだし、名前空間の増減はホストへ通知できないと気付かれない。
シェルの **`nvmens [add|del <nsid>]`** が発火点で、`nvmens` だけなら一覧表示。

名前空間は **nsid=1 が 256MB、nsid=2 が 32MB**(既定では 1 だけ有効)。
サイズを変えてあるのは `.bss` の都合でもあるが、**「名前空間ごとに別の実体と
別の上限を見ているか」の確認としても強い**(ns2 の範囲外 LBA が ns1 なら
有効な値になる)。

### イベントを送る前に「送ってよい」と広告する

**OAES(Identify Controller offset 92)の Namespace Attribute Notices を
立てないと、Linux は Async Event Request をそもそも送ってこない。**
`nvme_enable_aen()` が `ctrl->oaes` を見て早期 return するため、AEN の
Set Features も AER も飛ばない。D2 のときに「AER が 1 度も来なかった」と
記録したのはこれが原因だった。**D4 の ONCS、D3 の VS に続いて 3 例目。**

### AER の CQE を送るのはシェルではなく admin ジョブ

`nvmens` はシェル(core0)から呼ばれるが、admin キューを回しているのは
core1。**別コアから同じコネクションへ送ると、受信ポーリング中の admin
ジョブと競合する**(RDMA CM で同じ形の不具合を踏んでいる)。
`nvmens` は `ctx->aer_notify_ns` の旗を立てるだけにして、送信は
`nvmet_admin_job_step()` の先頭で行う。

- 保留は cid 1 つだけ(AERL=0 = 0's based で同時 1 件)。2 件目は
  **Async Event Request Limit Exceeded** で返す(黙って捨てるとホストは
  永久に待つ)。
- **Changed Namespace List(LID=0x04)は読み出したらクリアする。**
  しないとホストが同じ変更を何度も見て再スキャンを繰り返す。
- **切断時に保留を捨てる。** 次のホストが自分の出していない cid の CQE を
  受け取ることになる。

### nsid を見る場所は dispatch だけではない

書き換えたのは Identify(CNS=0x00/0x02/0x03)、IO の dispatch、
**受信パーサ 2 つ**(push の in-capsule write と pull の同等処理)、
H2CData の受信先、データダイジェストの検証。`nvmet_pending_write_t` に
`disk` を持たせて R2T 経路でも取り違えないようにしてある。
**受信経路を 4 箇所書き換えたので、回帰確認の本命は `tcpbench`。**

- **Flush は名前空間の解決より前に置く。** `nvme smart-log` と同じで
  **nsid=0xFFFFFFFF(全名前空間)で来る**ので、先に解決すると Invalid
  Namespace で落とすことになる。
- **NN は「実際に有効な数」ではなく「取りうる最大 nsid」。** 未使用の nsid が
  あってよく、ホストは CNS=0x02 で有効なものを引く。

### 検証(Pi5)と、ホスト経由では叩けないもの

```
nvmens add 2   → ターゲット: 非同期イベント通知 (type=2 info=0x0 lid=0x4)
               → Pi5: dmesg に "rescanning namespaces"、/dev/nvme0n2 が生える
nvmens del 2   → 同じく再スキャン、/dev/nvme0n2 が消える
```

陰性対照は 3 つ: n1/n2 に別データを書いて**混ざらない**こと、
`write-zeroes /dev/nvme0n2 -s 65530 -c 15` が **LBA Out of Range**
(ns1 なら有効な LBA)、`nvme id-ns -n 3` が Invalid Namespace or Format。

**IO コマンドの「無効な nsid」だけはホスト経由で叩けない。** Linux は
`/dev/nvme0n1` へのパススルーで nsid 不一致をカーネル側で弾き
(`nsid (3) in cmd does not match nsid (1) of namespace`)、`/dev/nvme0` の
IO パススルーは名前空間が複数あると拒否する
(`NVME_IOCTL_IO_CMD not supported when multiple namespaces present!`)。
IO パスが nsid を解決していること自体は上の陰性対照 2 つで示せているので、
未到達なのは「無効だったときの status」の 1 分岐だけ。

### 2 コアが同時に uart_printf すると出力が混ざる

`nvmens add 2` の応答(core0)と AER 通知のログ(core1)が文字単位で
インターリーブして読めなくなる。**既知の性質で害は無いが、実機ログを
読むときは「壊れている」と誤読しないこと。**

## Keep Alive タイマ(`PLAN_protocol_gaps.md` 段階 20 = D7)

Fabrics Connect の **cdw12**(cdw10 ではない)で受け取った KATO を超えて
コマンドが来なければセッションを畳む。TCP の FIN が来ない切断
(ケーブル抜け、相手のクラッシュ)を検出する唯一の手段。

- **KATO=0 は「Keep Alive 無効」。** Discovery コントローラは 0 で繋いで
  くるので、回すと接続直後に切ってしまう。**`nvmediscover` が通ることが
  そのまま「0 のときは回していない」の確認になる。**
- 判定は admin ジョブの step(冷たい経路)。`timeout_ms()` の 64bit 除算を
  ここに置くのは問題ない(A2 で禁じたのはホットパスの話)。

### IO の hot path に時刻読み出しを足さずに「相手が生きている」を知る

Keep Alive だけを見ると、admin が忙しいときに切ってしまう。かといって
IO の dispatch で `timer_now()` を呼ぶと 1 コマンドあたりの固定コストになる
(read 8k は 1 コマンド 3.3us なので効く)。

**D5 で入れた SMART のコマンド数カウンタ(`stat_read_cmds + stat_write_cmds`)が
進んだかどうかを admin ジョブ側で見る**ことで代用した。**追加コストはゼロ。**
「別の目的で既にホットパスにあるカウンタを、冷たい経路から観測して使う」は
ほかにも使える手。

### 畳む順序が変わると、旗で伝え合う後始末が壊れる

**D7 で初めて「admin が先に畳む」経路ができ、既存のバグが露呈した。**

これまでは必ず「IO が先に終わる → admin が linger して待つ」だった。
KATO 切れでは admin が先に `NADM_ST_ARM` へ戻り、**そのあとで IO ジョブが
`session_done` を立てる**。admin はもう次の接続を待っているので、この旗を
「IO が切れた」と解釈して linger を始め、**10 秒後に「相手が閉じないので
打ち切り」として次の(正常な)セッションを畳んでしまう**。

実機ではリンク復旧後の再接続が確立した直後にこれが出た。直し方は
「ARM / ACCEPT_WAIT で `session_done` を見たら前のセッションの残骸として
捨てる」。**新しい「畳む契機」を足したら、既存の旗が逆順でも成立するかを見る。**

- IO キューは **IO ジョブ自身に畳ませる**(`ctx->kato_expired` の旗)。
  別ジョブが握っているコネクションを横から閉じると、受信 upcall の解除など
  `nvmet_io_job_end()` に集約した後始末が抜ける。
- **旗を消費するのは IO ジョブ側。** admin の `session_finish()` でリセット
  すると、立てた直後に消えて IO ジョブが一度も見ない。

### 検証(Pi5)

```bash
sudo nvme connect ... --keep-alive-tmo=5
# 陰性対照: 20 秒放置しても切れない(Linux が Keep Alive を送り続ける)
sudo ip link set eth1 down    # PF1(192.168.101.11)側のリンクを落とす
# → ターゲットが 5 秒強で「Keep Alive タイムアウト」を出して畳む
sudo ip link set eth1 up      # → Linux が Successfully reconnected
```

**陰性対照が無いと「ただのタイムアウト」と区別がつかない。**

## Linux 側比較ベンチ `~/script/linux_loopback.sh`

**このリポジトリ外**(OptiPlex の `~/script/`、バージョン管理されていない)。
kernel/spdk × tcp/rocev2 を同じ書式で測る。`bench`/`tcpbench` の要約表はこの
スクリプトと同じ列・同じ行順に揃えてある。

- **`rdma system` が `shared` のときに rocev2 を実行すると必ず失敗する。**
  `exclusive` へ切り替えるには init_net 以外の net namespace が 1 つも無いことが
  必要だが、`polkitd` が `PrivateNetwork=yes` で常時 1 つ持っているため EBUSY で
  死ぬ。対処は `sudo systemctl stop polkit` の間に一度 `exclusive` を獲得させる
  こと(以後は polkit を戻しても効く)。
- この罠を仕掛けるのは `--teardown` の最終行 `rdma system set netns shared`。
  **必要が無ければ `--teardown` を実行しない**のが一番効く(通常終了は意図的に
  netns と exclusive を残す)。PC のリブートでも `shared` に戻る。
- 切り分けの一手: 実行前に `sudo rdma system show`。
- kernel イニシエータは接続条件(トランスポート + ダイジェスト)を
  `/tmp/linux_loopback_initiator.state` に記録し、前回と違えば自動で
  `nvme disconnect` してから繋ぎ直す(sysfs から digest の現在値は読めない)。

## 最新の性能(2026-08-16)

**この章は 5% 以上の性能変化があったら随時更新すること。** 変化が 5% 未満なら
測定ばらつきの範囲として更新しない(下記「測定条件」の注意も参照)。

### 測定条件

| 項目 | 値 |
|---|---|
| 機材 | OptiPlex 3060 (i3-8100 @3.6GHz, DDR4-2400 dual channel) |
| NIC | ConnectX-4 MCX456A-ECAT (100GbE, MT27700), FW 12.28.2006, PCIe Gen3 x16 |
| 構成 | 2 ポートを DAC 直結したループバック (PF0=initiator / PF1=target) |
| MTU | 9000 |
| queue depth | 8 |
| 計測時間 | 各パターン 3 秒 |
| 単位 | **MiB/s**(1024 進。MB/s ではない) |

「kernel」= カーネル nvmet + nvme-tcp/rdma + fio(io_uring_cmd passthru)、
「spdk」= SPDK nvmf_tgt + spdk_nvme_perf、いずれも `~/script/linux_loopback.sh`。
「独自」= このリポジトリ(`tcpbench` / `bench`)。

### NVMe/TCP(ダイジェスト無し)

| | kernel | spdk | **独自** | 独自/kernel |
|---|---|---|---|---|
| write 8k | 293 | 406 | **1025** | 3.5x |
| write 64k | 779 | 1289 | **3309** | 4.2x |
| write 256k | 1220 | 2068 | **3968** | 3.3x |
| read 8k | 307 | 482 | **2334** | 7.6x |
| read 64k | 902 | 1642 | **5024** | 5.6x |
| read 256k | 1366 | 2175 | **5242** | 3.8x |

write 8k は 856 -> 1025(**+20%**)。高速再送(C2)を入れる過程で、
**情報の変わらないウィンドウ更新 ACK を送らないようにした**副次効果
(下記「無意味なウィンドウ更新 ACK」参照)。read 側が変わらないのは、read の
受信が push 型 upcall で `rx_buf` を経由せず、この ACK 経路を通らないため。
他のセルは測定ばらつきの範囲(連続 2 回で 3348/3489、4060/4054、2308/2305、
5036/5057、5257/5262)。

read 8k は 2453 -> 2334(−4.9%)。IPv6 デュアルスタック化で 1 コマンドあたり
約 180ns の固定コストが乗ったため(上記「IPv6 対応の代償」参照。同一セッション
内の HEAD との A/B で確認済み)。

### NVMe/TCP(ダイジェスト有り: hdgst + ddgst)

括弧内はダイジェスト無しに対する比。

| | kernel | spdk | **独自** |
|---|---|---|---|
| write 8k | 273 (−7%) | 400 (−1%) | **766** (−10%) |
| write 64k | 778 (±0%) | 1035 (−20%) | **3009** (−9%) |
| write 256k | 1065 (−13%) | 1945 (−6%) | **3944** (−1%) |
| read 8k | 300 (−2%) | 513 (+6%) | **1784** (−27%) |
| read 64k | 809 (−10%) | 1321 (−20%) | **4427** (−12%) |
| read 256k | 1257 (−8%) | 1731 (−20%) | **4713** (−10%) |

### NVMe-oF RoCEv2(ダイジェストの概念は無い)

| | kernel | spdk | **独自** | 独自/spdk |
|---|---|---|---|---|
| write 8k | 1315 | 3717 | **4310** | 1.16x |
| write 64k | 2892 | 5206 | **5803** | 1.11x |
| write 256k | 3084 | 5237 | **5787** | 1.11x |
| read 8k | 1207 | 3667 | **4373** | 1.19x |
| read 64k | 3318 | 5774 | **6813** | 1.18x |
| read 256k | 3770 | 5778 | **6070** | 1.05x |

### 読み取り

- **TCP は全条件で独自が最速**(kernel 比 2.9〜8.0 倍、spdk 比 2.1〜5.1 倍)。
  カーネル/SPDK 側は netns + 実 TCP スタックを通るのに対し、独自は同一プロセス
  内でループバックするので条件は対等ではない。順位そのものより、変更前後で
  同じ列を比べることに意味がある。
- **RoCEv2 は全条件で独自が最速**(spdk 比 1.05〜1.19 倍)。以前は write 8k で
  spdk に 2 倍負けていたが、原因は下記「同時 RDMA_READ 数」のバグ 2 件だった。
- ダイジェストのコストは独自で −1〜−27%。**最悪は read 8k の −27%**(小 I/O
  ほど 1 コマンドあたりの固定コストが相対的に重い)。256k write はほぼゼロ。
  spdk が 64k/256k で −20% と大きいのは、ISA-L の CRC が速い分ほかの要因が
  見えているためか未調査。

## 測定で繰り返し間違えたこと

- **代表的でない条件だけで測って結論を出した。** CRC を 64KB 単発でしか測らず
  「PCLMULQDQ は不要」と結論したが、実際の呼ばれ方(TCP セグメントごとの逐次
  計算)で測り直すと逆だった。**実装が実際にどう呼ばれるかと同じ形で測る。**
- **コストの所在は、その処理を無効化して測ると一発で分かる。** digest の内訳は
  `crc32c()` を恒等関数に差し替える(送受とも同じ関数になるのでダイジェストは
  自己無矛盾に一致する)ことで、プロトコル約 3% / CRC 計算 86% と切り分けられた。
  憶測で最適化先を決めない。

## プロトコル機能の追加(IP 断片破棄 / UDP / IPv6 / ICMP エラー / Flush / Get Log Page)

「本来サポートすべきだが未実装」だったものを実装した。いずれも
`ping6` / `udptest` シェルコマンドで実機確認済み。

- **IP 断片(fragment)の破棄**(`ip.c`): MF ビットまたはフラグメントオフセットが
  非 0 のデータグラムを捨てる。従来は断片を完全なデータグラムとして上位へ
  渡していた(MTU の揃ったループバックでは起きないが、実ネットワークでは
  TCP/ICMP が壊れたペイロードを読む)。**受信側の再構成は今も実装していない**
  (送信側の分割は段階 8 = A4 で入れた。下記「送信側の IP フラグメント」参照)。
- **UDP**(`udp.c` / `udp.h`): 8 エントリのポート束縛表 + 疑似ヘッダ込みの
  チェックサム検証。受信時、チェックサムが 0(送信側が省略)か HW オフロードで
  検証済みなら再計算しない。送信時は計算結果が 0 になったら 0xFFFF を書く
  (RFC 768、0 は「チェックサム無し」を意味するため)。
- **ICMP Destination Unreachable**(`icmp.c` / `ip.c`): 待ち受けの無い UDP ポート
  には code=3(Port Unreachable)、上位の居ないプロトコルには code=2(Protocol
  Unreachable)を、元 IP ヘッダ + 先頭 8 バイトを引用して返す(RFC 792)。
- **NVMe Flush** は成功 CQE を返す(RAM ディスクなので永続化するものが無い)。
  **Get Log Page** はゼロ埋めのページを返す。**Async Event Request** は CQE を
  返さず保留する(イベントが起きるまで完了させないのが仕様上の正しい挙動)。
- **IPv6**(`ipv6.c` / `ipv6.h`): EtherType 0x86DD、MAC から EUI-64 を作る
  リンクローカル fe80::/64、要請ノードマルチキャスト、ICMPv6(疑似ヘッダ必須)、
  Echo Request→Reply、Neighbor Solicitation→Advertisement(hop_limit 255)。
  **TCP/UDP over IPv6 はまだ通していない** — tcp.c/udp.c が 32bit の IPv4
  アドレスを前提にしているため、アドレス幅の抽象化が別途必要。

### 実機で踏んだこと: UDP を実装した途端に ICMP Port Unreachable を撒き散らした

RoCEv2 のフレームは HW が QP へ配送すると同時に、catch-all フローステアリング
経由で **Ethernet RX にも複製されて来る**(以前から `[IP] 未対応プロトコル
(protocol=17) 無視` として現れていた既知の挙動)。UDP を実装したことでこれが
「待ち受けの無いポート宛」と判定され、**自分の RDMA トラフィック 1 パケットごとに
Port Unreachable を返す**ようになった。相手側に大量の `[ICMP] type=3 code=3` が
出て初めて気付いた。対策として `ip.c` で UDP 宛先ポート 4791(`UDP_PORT_ROCEV2`)
だけは ICMP エラーを返さず黙って捨てる。

**教訓**: 「今まで黙って捨てていたもの」に処理を付けると、それまで無害だった
異常系が突然表に出る。新しいプロトコルを実装したら、既存の機能(ここでは RDMA)を
必ず回してログの差分を見ること。今回は回帰テストのログに紛れていた 1 行で
気付けた。

### 検証コマンド

- `ping6` — 対向 PF へ ICMPv6 Echo Request(ff02::1 宛、L2 は 33:33:00:00:00:01)を
  送り Echo Reply を待つ。2 ポートとも自作ドライバが握っているので Linux 側から
  ping6 できず、この内部往復で確認する。実測 RTT 約 155〜160us。
- `udptest` — 対向 PF の 7777 番へ UDP を送って受信ハンドラが呼ばれることと、
  待ち受けの無い 7778 番へ送って Port Unreachable が返ることを確認する。

## TCP/UDP over IPv6 対応(netaddr_t によるデュアルスタック化)

これまで IPv6 は受信・ICMPv6・NDP 応答までで、TCP/UDP は IPv4 専用だった。
スタックが 32bit アドレスを前提にしていたのを `netaddr_t` で抽象化して解消した。

- **`src/netaddr.h`(新規)**: `{ family, a[16] }`。IPv4 は `a[0..3]` のみ使う。
  4-tuple 比較や TIME_WAIT テーブルはこの型のまま持ち回り、**L3 ヘッダを
  組み立てる直前にだけ family を見て分岐する**。
- **`tcp.c`**: `tcp_conn_t.local_ip/remote_ip` を `netaddr_t` 化。送信 3 経路
  (通常/LSO/bare ACK)を `tcp_l4_off()` / `tcp_build_l3()` / `tcp_checksum()` /
  `tcp_resolve_mac()` / `tcp_netif_for()` の family 分岐ヘルパへ集約。
  受信は `tcp_input_addr(pkt, len, src, dst)` が共通入口で、`tcp_input()` は
  IPv4 用の薄いラッパ。`tcp_connect_begin6()` を追加。
- **`udp.c`**: `udp_input_addr()` / `udp_send6()`。ハンドラの引数を
  `netaddr_t` 化(v4/v6 を同じハンドラで受けられる)。
- **`ipv6.c`**: NDP 近隣キャッシュ(`netif_t.ndp_cache`)と `ndp_resolve()`
  (NS 送信 → NA 待ち、`arp_resolve()` と同じ同期解決)。NS/NA 受信で相手を
  学習する。`ipv6_build_header()` と 3 種の疑似ヘッダチェックサムを公開。
- **`netif.c`**: `netif_find_by_ip6()`(各インターフェースの MAC から EUI-64 を
  組み立てて比較。IPv6 アドレスは netif_t に持たず毎回導出する)。

### HW オフロードは v6 でもそのまま使える(当初「無効化が必要」と判断したのは誤り)

実装時、HW チェックサムオフロードと LSO は「mlx5 側が IPv4 前提だから」と
考えて v6 では無効化した。しかし**実測すると両方とも v6 でそのまま動き**、
無効化していた間は IPv4 比で write 64k −38% / read 64k −47% という大きな
差が出ていた。有効化後は全条件で IPv4 と同水準になる(下表)。

- **チェックサム**: 種として書く疑似ヘッダ部分和は `tcp_checksum()` が family
  ごとに正しく計算する。mlx5 が立てる `cs_flags` の L3_CSUM ビットは IPv6 では
  埋める対象が無いので無視され、L4_CSUM だけが効く。
- **LSO**: ConnectX は IPv6 の TSO に対応しており、payload_length と TCP seq を
  HW が更新する。`tcp_build_l3()` が v6 ヘッダを組めば、あとは hdr_len が
  74(=14+40+20)になるだけで経路は共通。

**教訓**: 「NIC の機能は IPv4 前提だろう」という推測で機能を切ると、動くはずの
ものを落としたまま気付かない。切る前に一度有効にして実測すること。今回は
`tcp6test`(64KB のバイト一致)で正しさを、`tcpbench ipv6` で速度を確認した。

### 実機で踏んだ本物のバグ

1. **要請ノードマルチキャストの判定がバイト 1 個ずれていた**
   (`ipv6_addr_is_ours()`)。`ff02::1:ffXX:XXXX` はバイト列で
   `..00 01 ff XX XX XX` なので `addr[11]=0x01 / addr[12]=0xFF` を見るのが
   正しいのに、`addr[11]==0xFF` と `addr[12..14]` を見ていた。ping6 は
   `ff02::1`(全ノード)宛だったので露見せず、**NS を実装して初めて
   顕在化**した。
2. **IPv6 の MSS を IPv4 のまま広告していた**。`netif_t.mss_cap` は
   `port_mtu - 62`(L3=20 前提)で決めてあるので、v6 でそのまま使うと
   フルサイズセグメントがリンク MTU を 20 バイト超え、NIC に**無言で
   捨てられる**(過去に踏んだ「境界値ぴったりのサイズだけが失敗する」の
   再来)。`tcp_mss_cap_for()` で v6 は 20 引く。実機で 9216 → 9196 になり、
   64KB(フルサイズ 8 本)が通ることを確認した。
   **2048 バイトのテストでは 1 セグメントに収まって踏まなかった** ——
   テストサイズを MSS 超へ広げて初めて検出できる類のバグ。

### IPv6 対応の代償(実測、A/B 済み)

`tcp_conn_t` が 36 → 62 バイトに膨らみ、受信のたびに `netaddr_t` を組み立てる
ぶんの固定コストが乗る。**同一セッション内で HEAD と A/B した結果**:

| パターン | HEAD | 対応後 | 差 |
|---|---|---|---|
| tcp 8k read | 2468 MB/s(2 回とも同値) | 2331–2334 | **−5.5%** |
| tcp 8k write | 833 / 868(ばらつき 4%) | 831–833 | 誤差内 |
| tcp 64k/256k | — | — | 環境ドリフト内 |
| RDMA 全条件 | — | — | 無影響(tcp.c 非経由) |

**1 コマンドあたり約 180ns の固定コスト**と読める(read 8k は 1 コマンド
3.3us なので −5.5%、write 8k は 9.8us なので誤差に埋もれる)。この解釈は
「write が無回帰で read だけ落ちる」という非対称性を統一的に説明する。

試して**効果が無かった**対策(同じことを繰り返さないよう記録):
- L3 ヘッダを右詰めして TCP ヘッダ位置を family 非依存にする → IPv4 の
  フレーム開始が 64 バイト境界から外れ、**逆に 8k が 6〜9% 落ちた**ので撤回。
  現在は「フレームは常にバッファ先頭、TCP ヘッダ位置だけ family 依存」。
- `tcp_conn_t` への `aligned(64)` → 実測で差が出ず。ただし**現在は付けてある**:
  性能目的ではなく、「キャッシュラインを跨いでいるせいでは」という疑いを
  今後毎回検討し直さずに済ませるため(ユーザ指示)。パディングを明示して
  ちょうど 64 バイトにし、`_Static_assert` でサイズと整列を固定してあるので、
  フィールドを足してあふれたらビルドが落ちる。整列前後で 3 回ずつ測って
  read 8k は 2331–2345 と同水準(差は測定ばらつきの範囲)。
- `tcp_input()` の dst を遅延生成 → 差が出ず(正しさのため残置)。

効果が**あった**もの: ホットスカラを構造体前半へ移動、4-tuple 照合で
ポートを先に比較、`netaddr_v4()` の未使用 12 バイトのゼロ埋め廃止、
family 分岐ヘルパの `static inline` 化(合計で 2247 → 2334 まで回復)。

### 検証コマンド

- `ping6` / `udptest`(v4)/ `udptest6`(v6)/ `tcp6test`(IPv6 上で TCP を
  確立し 64KB 往復してバイト一致確認、MSS=9196 でフルサイズ 8 本)。

## NVMe-oF を IPv6 で待ち受ける

**ターゲット側は何も変えていない。** `nvmet <port>` が使う `tcp_listen()` は
ポートだけで待つ family 非依存の実装で、`nvmet.c`/`nvmet_tcp.c` に IPv4 固有の
コードは 1 行も無い(実際に grep して確認)。IPv6 の SYN が来れば
`tcp_input_addr()` が `aconn->local_ip = *dst` でそのまま v6 コネクションとして
受理する。**必要だったのはイニシエータ側だけ**だった。

- `tcp_connect_begin_to(conn, const netaddr_t *dst, port)`(`tcp.c`)— family を
  問わない能動 open。自分側アドレスは dst の family に合わせてアクティブな
  インターフェースから決める(v4=netif の IPv4、v6=リンクローカル)。
- `nvme_connect_job_start_addr(ctx, const netaddr_t *addr, port, subnqn)`
  (`nvme.c`)— 接続先を `netaddr_t` で受ける本体。従来の
  `nvme_connect_job_start()` は IPv4 用の薄いラッパとして残してある。
- シェル: `tcpbench ... ipv6` で対向 PF のリンクローカルへ IPv6 で接続する。
  ダイジェストと同じく IPv4/IPv6 もコネクション単位で決まるので、指定が
  前回と変われば `shell_ensure_tcp_session()` がセッションを張り直す。

### 実測(同一セッション内、qd=8、対向 PF ループバック)

| | IPv4 | IPv6 | 差 |
|---|---|---|---|
| write 8k | 831 | 835 | +0.4% |
| write 64k | 3325 | 3172 | −4.6% |
| write 256k | 3973 | 3903 | −1.8% |
| read 8k | 2297 | 2317 | +0.9% |
| read 64k | 5038 | 4990 | −1.0% |
| read 256k | 5259 | 5242 | −0.3% |

**IPv6 でも IPv4 と同水準**(差は測定ばらつきの範囲)。admin キュー確立 →
Fabrics Connect → Set Features(Number of Queues)→ IO キュー確立 → read/write
まで、IPv4 と同じ経路をそのまま通る。

## 閉じたポートへの TCP RST(`PLAN_protocol_gaps.md` 段階 1 = C1)

`tcp_input_addr()` の「どのコネクションにもリスナにも一致しない」経路で
RFC 793 どおり RST を返すようにした(以前は黙って捨てていた)。
`tcp_send_bare_ack()` を `tcp_send_bare(..., flags, seq, ack)` へ一般化し、
ACK / RST / RST|ACK を同じ経路で送る。実機の効果は
**接続失敗の確定が 15.5 秒(SYN 再送 5 回)から 134〜191us へ**。

### RST を返してはいけない 4 条件(どれも外すと退行する)

1. **受信が RST のとき。** RST に RST を返すと無限ループになる。
2. **そのポートにリスナが居るとき。** 受動 open のマッチ条件は「`accept_conn`
   が用意済みで `TCP_CLOSED`」なので、**accept を張り直す一瞬の隙間**
   (`nvmet` が admin キュー確立後に IO キューの accept を arm するまでの間)に
   届いた SYN が「閉じたポート宛」に見える。ここで RST を返すとイニシエータの
   **IO キュー接続が即座に失敗する**。`tcp_port_has_listener()` は
   armed かどうかを見ずポート番号だけで判定し、armed でなければ黙って捨てて
   相手の SYN 再送に任せる(Linux が accept キュー溢れで落とすのと同じ)。
3. **TIME_WAIT テーブルに 4-tuple が一致するとき。** 元の実装は FIN が立って
   いるときだけ TIME_WAIT を引いていた。RST を足すと、閉じた直後の相手から
   届く FIN 以外の遅延セグメントを「閉じたポート宛」と誤判定して
   **相手の TIME_WAIT を勝手に潰す**。照合を FIN 限定から外し、一致したら
   FIN のときだけ ACK を返してあとは捨てる。
4. **宛先が IPv6 マルチキャストのとき。**

保険として `tcp_conn_exists_any_core()` を RST 直前に置いてある。受信ホット
パスの 4-tuple 照合は自コアぶんしか見ないので、将来 `smp_boot_core2/3` を
有効にして受信を複数コアへ振ったときに**自分のコネクションを自分で撃つ**のを
防ぐ。冷たい経路なので性能には影響しない。

RoCEv2 の複製フレーム(UDP を実装したとき ICMP Port Unreachable を撒き散らした
前例)は UDP/4791 だけなので TCP には来ない。`bench` を回してログに RST が
1 行も出ないことを確認済み。

### 検証コマンド

- `rsttest` — 対向 PF の待ち受け無しポート(6001)へ v4/v6 の両方で接続し、
  RST で即座に失敗することを確認する。SYN 1 回ぶんの RTO(500ms)より十分
  短いこと(閾値 200ms、実測 134〜191us)を**経過時間で**判定するので、
  RST 送信を壊すと「遅すぎる」で落ちる。単に「接続に失敗した」を見るだけの
  テストでは、RST が無くても SYN 再送タイムアウトで最終的に失敗するので
  退行を検出できない。

## 高速再送 / 高速回復(`PLAN_protocol_gaps.md` 段階 2 = C2)

重複 ACK 3 個で RTO を待たずに再送する(RFC 5681)。検出は `tcp_input_addr()`、
再送は既存の 3 つの再送経路(`tcp_send()` の Go-Back-N ループ /
`tcp_async_poll()` / `tcp_async_short_poll()`)が担う。実機でロスを注入すると
**再送の 97% が RTO ではなく重複 ACK 由来**になる(破棄 540 に対し
高速再送 1379 / RTO 由来 38)。

### 無意味なウィンドウ更新 ACK を送っていた(write 8k が +20% になった話)

**C2 で最も効いたのは高速再送そのものではなく、これを直したことだった。**

`tcp_recv_internal()` はアプリが受信バッファを読み出すたびに純 ACK を送るが、
広告ウィンドウは `safe_window_cap` で頭打ちなので、バッファがどれだけ空いても
**ワイヤ上の値が動かない**。つまり「ACK 番号も据え置き・データ無し・ウィンドウ
不変」の ACK を延々と送っていた。相手に伝える情報はゼロで、送信 CPU と帯域を
捨てているだけだった。

さらに悪いことに、**この ACK は RFC 5681 の重複 ACK の定義に完全一致する**。
C2 を入れた直後、ロスが 1 つも無いのに**重複 ACK を 419 万個検出し、高速再送が
10 万回空振りしていた**。

対策は `tcp_send_window_update()`:「ACK 番号もウィンドウも前回広告した値と
同じなら送らない」。情報の損失はゼロ。これで誤検出が完全に 0 になり、
**write 8k が 856 -> 1025 MB/s(+20%)**。read が変わらないのは、read の受信が
push 型 upcall で `rx_buf` を経由せず、この経路を通らないため。

**教訓**: 「送っても害は無いだろう」で出しているパケットが、後から入れる機能の
判定材料と衝突することがある。しかも 419 万個という数は、誤検出を追いかけて
カウンタを仕込むまで誰も見ていなかった。

### 検出が発散しないために必要だった 3 つの抑制

素直に RFC 5681 を書くとこのスタックでは発散する。**どれも外すと再送が爆発する**
(実測値付きの詳細は `PLAN_protocol_gaps.md` 段階 2)。

1. **高速再送は 1 セグメントではなく Go-Back-N。** この受信側は順序不正
   セグメントを 64 スロット(`TCP_OOO_SLOTS`)しか持てず、未確認ウィンドウは
   それより大きい。RFC どおり穴の先頭 1 個だけ送り直すと先読みバッファが
   溢れて二次的な穴が増え、**ロス注入時のスループットが 8.99 MB/s まで落ちた**。
   RTO 経路と同じ Go-Back-N にしたら 736 MB/s(82 倍)。
2. **Go-Back-N が生む重複 ACK を差し引く(`dup_ack_suppress`)。** K セグメント
   送り直すと相手は既に持っている分にも即座に ACK を返すので、ほぼ K 個の
   重複 ACK が返る。K>=3 なら再送 -> 重複 ACK -> 再送 の正のフィードバックに
   なる(破棄 1318 に対し再送 517527)。
3. **NewReno の partial ACK 再送は入れない。** Go-Back-N と組み合わせると
   再送が爆発する(破棄 71 に対し再送 3184)。`recover` は「回復中に新しい
   回復を始めない」ガードとしてだけ使う。

SACK(C3)を入れれば 1. と 2. の問題は根本的に消える。

### 検証コマンド

- `txdrop [N]` — データセグメント N 個に 1 個を「送ったことにして捨てる」
  ロス注入(0=無効)。引数なしで破棄数・重複 ACK 数・再送数(高速/RTO の内訳)を
  表示する。**DAC 直結ループバックではパケットロスがまず起きないので、これが
  無いと C2 は二度と検証できない**(だから一時デバッグ用ではなく恒久的に残す)。
  値を変えるたびに統計は 0 にリセットされる。
- 使い方: `txdrop 5000` -> `tcpbench 8,64 rw 8` -> `txdrop`(統計)-> `txdrop 0`。
  **`txdrop 0` に戻し忘れると以後の測定が全部おかしくなる**ので注意。
- ロス下の整合性確認は `txdrop 10` + `tcp6test`(64KB バイト一致)。ただし
  64KB=8 セグメントでは重複 ACK が 3 個溜まる前に終わるので、**高速再送そのものは
  発火せず RTO 経路が拾う**(これは正常。発火を見たいなら `tcpbench` を使う)。

## QP に付随する FW リソースの解放(`PLAN_protocol_gaps.md` 段階 3 = E)

`mlx5_qp_create_rc()` / `mlx5_qp_create_ud_common()` は QP 1 本につき
**UAR / PD / MKey / CQ も確保する**。以前は `DESTROY_QP` しか発行しておらず、
作り直すたびに 4 種類が積み上がっていた。`mlx5_qp_destroy()` を「付随する資源も
まとめて返す」形へ拡張した(呼び出し元は変更不要)。

解放順は依存の逆順で **QP → MKey → CQ → PD → UAR**。MKey は PD に属し CQ は
UAR を参照するので、PD/UAR を先に返してはいけない。

- **`DESTROY_MKEY` が取るのは mkey ではなくインデックス。**
  `mlx5_create_mkey_pa*()` は `index << 8` を mkey として保持しているので、
  8bit 戻して渡す。
- **`mlx5_hca_bringup()` が作る Ethernet 用の資源(EQ/PD/MKey/CQ/TIS/RQ/TIR/SQ/
  フローテーブル)は解放してはいけない。** プロセス生存中ずっと使う。
  対象は QP ごとに確保するものだけ。
- 解放が失敗しても致命的にしない(ログを出して続行し、最後にハンドルをゼロ
  クリアする)。切断経路から呼ばれるので、ここで止まると「後始末でハングする」
  パターンになる。
- **作成の失敗パスにもロールバックが要る。** ALLOC_UAR は成功したが ALLOC_PD で
  失敗、というときに漏れる。`mlx5_qp_destroy()` は `qpn==0` でも残りを解放する
  ので、失敗時はそのまま呼べばよい。

opcode(DEALLOC_UAR=0x803 / DEALLOC_PD=0x801 / DESTROY_MKEY=0x202 /
DESTROY_CQ=0x401)と入力構造体は **OptiPlex の
`/usr/src/linux-headers-*/include/linux/mlx5/mlx5_ifc.h` を実際に読んで確認した**。
カーネルヘッダが入っているので clone は要らない。4 つとも 16 バイト入力・
byte9-11 に 24bit ID という同じ形なので `mlx5_destroy_obj24()` にまとめてある。

### 検証コマンド

- `qploop [N]` — RC QP の作成 → RST2INIT → 破棄を N 回繰り返す。**枯渇させるより
  「リソース番号が再利用されるか」を見るほうが安全で証拠として強い。**
  実装前は 252 回で cqn 19→286 / pdn 18→269 / uarn 17→268 と単調増加、
  実装後は 252 回すべて cqn=19 / pdn=18 / uarn=17 で一定になった。
- **FW を一気に枯渇させないこと。** x86 VFIO 版には `pcie1 reset` 相当の手段が
  無く、FW 状態が壊れたらプロセス終了 → bind し直し(それでも駄目ならホスト
  電源断)になる。N は 4 → 8 → 16 → 32 … と段階的に増やす。
- `qploop` は `qp_index=0`(admin QP)と DMA バッファを共有するので、
  **RDMA セッションが生きている間に叩くとそれを壊す**。`bench` の後には使わない。

## NVMe-oF Discovery(`PLAN_protocol_gaps.md` 段階 4 = D1)

Discovery コントローラ(固定 NQN `nqn.2014-08.org.nvmexpress.discovery`)に
対応した。Fabrics Connect の subnqn を見て `nvmet_ctx_t.is_discovery` を立て、
Identify Controller(CNTRLTYPE=2)と Get Log Page(LID=0x70)の応答を変える。
イニシエータ側は `nvme_ctx_t.discovery_mode` を立てて接続する。

### 実ホストの `nvme discover` では検証できない(経路が無い)

- **2 つの PF は同じ IOMMU グループ**(`0000:01:00.0` / `0000:01:00.1` /
  上流の `0000:00:01.0` が group 2)。VFIO はグループ単位でしか扱えないので
  **片方だけ mlx5_core に残すことはできない**。CLAUDE.md 冒頭の
  「どちらか一方にしかバインドできない」の根拠はこれ。
- Linux 側の NIC はオンボード `enp2s0`(管理 LAN 側)だけで、ConnectX の
  2 ポートは DAC 直結。192.168.101.0/24 へ出る物理経路が無い。

### 代わりに「相手側の構造体でパースさせる」で検証する

`tools/disc_log_check.c` は**このリポジトリのコードを一切 include せず**、
Linux カーネルの `include/linux/nvme.h` の構造体だけでバイト列を読む独立
プログラム。`nvmediscover dump` の 16 進出力を食わせて PASS することを確認する。

**これが「自作 initiator ↔ 自作 target だけで試すと両側が同じ間違い方をして
絶対に検出できない」穴(CRC32C で踏んだやつ)への答え。** 構造体オフセットも
`offsetof` で出力させ、それを `nvmet.h` / `nvme.h` の定数として写している
(推測していない)。カーネルヘッダは OptiPlex の
`/usr/src/linux-headers-*/include/linux/nvme.h` にある。

```bash
ssh rpi5-rdma-target 'cd ~/vfio_nvme/tools && gcc -O2 -o /tmp/disc_log_check disc_log_check.c'
```

### 実機で踏んだこと: discovery の後、ターゲットが一切 SYN を受け付けなくなった

**2 件とも「Discovery は IO キューを作らない」ことの波及。**

1. **IO キューの arm が早すぎた。** `io_armed = 1` を ICResp 送信直後に立てて
   いたが、そこではまだ subnqn を見ていないので Discovery か分からない。
   arm しっぱなしになり、**次に来た通常接続の admin 用 SYN を IO キューの
   accept が食べた**(`[!] nvmet: IOキューで想定外のFabricsコマンド
   (fctype=0x0)`)。arm を Fabrics Connect(qid=0)受理後へ移した。
2. **CLOSE_WAIT で固まった。** Discovery には切断を検出して次の接続待ちへ戻す
   io job が居ないので admin job 自身で見る必要がある。`TCP_CLOSED ||
   TCP_TIME_WAIT` だけを見ていたが、**相手の FIN を受けた側は CLOSE_WAIT で
   止まり、自分が close するまで CLOSED にならない**。admin job が CLOSE_WAIT の
   まま固まり、以後 listener が一切 SYN を受け付けなくなった。**C1 で
   「リスナが居るポートには RST を返さない」ようにしてあるため、相手からは
   SYN が黙って捨てられるようにしか見えず、原因が分かりにくい。**

**教訓**: セッションの後始末を別のジョブに任せている構造だと、そのジョブが
動かない経路(ここでは Discovery)を足したときに後始末が誰の担当でもなくなる。
新しいセッション種別を足したら「誰が ARM へ戻すのか」を必ず確認すること。

### 検証コマンド

- `nvmediscover [dump]` — Discovery コントローラへ接続し Discovery Log Page を
  取得して表示する。`dump` を付けると 16 進も出力する(`disc_log_check` へ渡す用)。
  **ホストの実際の手順どおり「ヘッダ 1024B だけ読む → NUMREC を見て全体を
  読み直す」の 2 段で読む**ので、Get Log Page の LPO(オフセット)対応が
  壊れているとここで落ちる。
- **`nvmediscover` の後に `tcpbench` を必ず 1 回流すこと。** 上記 2 件の不具合は
  どちらも「discovery 単体では成功するが、その次の通常接続が死ぬ」形で出た。

## ルーティング / デフォルトゲートウェイ(`PLAN_protocol_gaps.md` 段階 5 = A1)

`netif_t` に `netmask` / `gateway` / `gateway6` を持たせ、**L3 の宛先はそのままに
L2 の宛先だけをルータへ向ける**次ホップ判定を入れた。判定は `netif.h` の
`netif_next_hop4()` / `netif_next_hop6()`(`static inline`、アドレス演算のみ)。

- **TCP は `tcp_resolve_mac()` の 1 箇所だけ**を直せば全経路がカバーされる
  (通常/LSO/bare の 3 経路が全部ここを通る)。UDP やシェルなどの冷たい経路は
  `netif.c` の `net_resolve_mac()` を使う。
- 経路表は作らない。**デフォルトゲートウェイ 1 本のみ**で、`gateway == 0` を
  「未設定」として分岐 1 個で従来どおりの挙動へ抜ける。
- ブロードキャスト(255.255.255.255)、マルチキャスト(224.0.0.0/4、ff00::/8)、
  IPv6 リンクローカル(fe80::/10)はゲートウェイへ渡さない。
- IPv6 の未設定判定に `gateway6_set` フラグを別に持っている。「16 バイトが全部 0」
  で判定すると v6 送信のたびに 16 回走査することになるため。

### DAC 直結で「別セグメント」を作る方法(別名インターフェース)

2 ポートが同一リンク上にいるので素直には検証できない。**対向 PF と同じ物理ポート
(同じ `nic` / `nic_priv` / MAC)を共有する別名 `netif_t` を 10.9.9.9 として
一時登録する**と、既存の `netif_resolve_frame_owner()` が受信フレームの宛先 IP を
見て別名側へ回すので、**宛先 IP と次ホップ IP が異なる状態で実データを流せる**。

この機構は元々あったもので、A1 で新たに足したのは `netif_unregister()` だけ
(テスト後に外して元の状態へ戻す。別名は対向 PF と MAC が同じなので、
登録したままにすると `netif_find_by_ip6()` が同じリンクローカルで衝突する)。

**アドレス演算だけの確認では不十分**な点に注意する。宛先とゲートウェイが同じ
でも通ってしまうので、A1 が壊れても検出できない。決定的な証拠は
**どの IP を ARP したか**(宛先 10.9.9.9 ではなくゲートウェイ 192.168.101.11)。

### 検証コマンド

- `route` — 各インターフェースの IP / netmask / ゲートウェイを表示。
  `route <if> <netmask> <gateway>` で設定(`gateway` に 0.0.0.0 で解除)。
- `routetest` — [1] gw 未設定時の後方互換 → [2] 次ホップ選択 4 ケース →
  [3] サブネット外宛の MAC がゲートウェイのものか → [4] IPv6 の同等確認 →
  [5] 別名インターフェース経由で 64KB 往復(バイト一致)、まで自動で確認して
  **設定を元に戻す**。戻し忘れると以後の `tcpbench`/`bench` が全部
  ゲートウェイ経路を通ることになるので、途中で失敗しても必ず復元する。
- **IPv6 のエンドツーエンドも確認済み(2026-08-22)。** `routetest` の [6] で、
  別名に別プレフィックスのグローバルアドレス(`2001:db8:0:9::9`)を名乗らせ、
  次ホップを対向 PF にして 64KB を往復させる。`ip6addr` でグローバルアドレスを
  持てるようになったので B1(SLAAC)を待たずに済んだ。

  これを通すのに **IPv6 の送信元アドレス選択のバグが 2 件**出た。どちらも
  「別名は対向 PF と MAC を共有する = リンクローカルが同一」なので、
  リンクローカルで喋ると応答をどちらのインターフェースのものか区別できず、
  近隣キャッシュが別名に入らない、という形で表面化する:

  1. **`tcp_connect_begin6()` が送信元を常にリンクローカルにしていた。**
     グローバル宛の接続なのに相手がリンクローカル宛に返してくる。
     `ipv6_source_for()`(宛先がリンクローカル/マルチキャストならリンク
     ローカル、それ以外はグローバル)を使う。
  2. **`ndp_send_ns()` の送信元が要請ノードマルチキャスト宛を基準に
     選ばれていた**(常にリンクローカルになる)。**送信元は「解決したい
     対象」のスコープに合わせる**(RFC 4861 4.3 も「その後のトラフィックで
     使う送信元」を求めている)。

  あわせて `netif_resolve_frame_owner()` を IPv6 対応にした(従来は ARP と
  IPv4 だけで、IPv6 は常にポーリング主体として処理されていた)。
  リンクローカルとマルチキャストは対象外で、グローバルアドレスだけ見る。

## ARP / NDP キャッシュのエージング(`PLAN_protocol_gaps.md` 段階 6 = A2)

一度入れたら永久に有効だったのを、TTL(既定 60 秒)で失効させるようにした。
`expires_at` / `probe_at` は `timer_now()` と同じ ns の絶対時刻で持つ。

### 失効しても即座に捨ててはいけない

**捨てると送信ホットパスがブロックする。** 捨てた直後の送信で `arp_resolve()`
(最大 900ms のポーリング待ち)が `tcp_send()` のバルク送信ループの内側で走り、
しかもその中の `net_poll_all_and_dispatch()` が `tcp_input_addr()` を再入させて
別の送信 → 再びキャッシュミス → 入れ子の `arp_resolve()`、という連鎖を作る
(深さに上限が無い)。

Linux の NUD と同じ 3 段階にしてある。状態フィールドは持たず、時刻の比較だけで
判定する(`neigh_check_age()`):

| 状態 | 条件 | lookup の振る舞い |
|---|---|---|
| fresh | `now < expires_at` | MAC を返す |
| stale | `expires_at <= now < expires_at + 猶予` | **MAC を返す** + 確認要求を投げる |
| dead | `expires_at + 猶予 <= now` | 無効化して未登録を返す |

猶予は TTL/6、確認要求の間隔は TTL/60(最低 10ms)で TTL に連動する。
延命の契機は **ARP reply / NA の受信だけ**(`arp_cache_insert()` /
`ndp_cache_insert()`)。`lookup` は stale なエントリの期限を更新しないので、
外から延命させたいときは明示的に insert し直すこと。

### ホットパスに `timeout_ms()` を置かない

`arp_cache_lookup()` は TCP の送信 1 セグメントごとに通る。**`timer_now()` は
ns を返すので `timeout_ms()` は内部で 64bit 除算を 2 回する。** 絶対期限との差の
比較にして除算を消し、`timer_now()` の呼び出しも 4-tuple の照合が当たったときだけ
1 回に絞ってある(外れたエントリのために時刻を読まない)。

### 検証コマンド

- `arpage [ms]` — TTL の表示/変更(既定 60000ms)。猶予と確認要求の間隔も連動。
- `arptest` — TTL を 600ms へ一時的に落とし、[1] 解決直後 fresh → [2] TTL 経過で
  stale → [3] stale でも lookup が MAC を返す → [4] 応答があれば fresh へ戻る →
  [5] 応答が無ければ猶予切れで破棄、を確認して **TTL を元に戻す**。
  「応答が返ってこない相手」として誰も名乗っていない 192.168.101.99 の
  エントリを `arp_cache_insert()` で直接仕込み、対向 PF と並べて追いかける。
  **[4](延命)と [5](追従)が揃わないと A2 の意味が無い。**
- **`arptest` の待ち時間中に NVMe セッションが動いていると対向 PF のエントリが
  延命される**(正しい動作)。stale を断言できるのは応答の無い相手のほうだけ。

## 重複アドレス検出(`PLAN_protocol_gaps.md` 段階 7 = A3)

IPv4 は RFC 5227 の ARP Probe(送信元 **0.0.0.0**)、IPv6 は RFC 4862 の DAD
(送信元 **::**、SLLA オプション**なし**)。**起動時に全インターフェースへ
1 回ずつ走らせる**(`run_shell()` → `net_dup_addr_detect()`)。結果は
`netif_t.ipv4_dup` / `netif_t.dad_state` に記録する。

- 送信元が `::` の NS への NA は**全ノードマルチキャスト `ff02::1` へ返す**
  (相手は SLLA を送れないので返信先が無い)。Solicited フラグは立てない。
  **`::` 由来の NS からは近隣キャッシュへ学習しない。**
- **衝突を検出してもアドレスの使用は止めない。** 2 ポートを同一プロセスで
  駆動しているので、誤検出でアドレスを封じると全部止まる。検出と警告までを
  実装し、停止の判断は運用に委ねている。
- probe の間隔は RFC より短い(既定 2 回 × 50ms、`ARP_PROBE_NUM` /
  `ARP_PROBE_INTERVAL_MS`)。**実 LAN へ出すときは RFC 5227 の
  3 回 × 1〜2 秒へ戻すこと。** 衝突が無いと待ち時間ぶんが必ず起動時間に乗る。

### この装置はマルチキャスト/ブロードキャストを送信元へループバックする

**以前からログに出ていた。** `ping6` の「Echo Request 受信」が 1 回の送信に
対して 2 行出るのがこれ(1 つは対向 PF、もう 1 つは自分に戻ってきたコピー)。
無害だったので誰も見ていなかったが、重複アドレス検出を入れた途端に
**各インターフェースが自分自身と衝突したと報告する**形で表に出た。

対策は 2 段:送信元ハードウェアアドレスが自分なら**応答しない**
(`arp_handle_frame()` と NS 処理の両方)、かつ衝突判定でも自分由来を数えない。

### `eth_get_mac()` / `NET_SELF_IP` で自分の同一性を判定できない経路がある

**ARP Probe への reply は `tpa` が `0.0.0.0`**(probe の `spa` をそのまま返す)
なので、`netif_resolve_frame_owner()` が宛先 IP で振り分けられず、
**受信した側のインターフェースのコンテキストで処理される**。PF0 が出した
probe への reply は PF1 として `arp_handle_frame()` に入る。

そこで `eth_get_mac()` を使うと検査した側ではない MAC が返り、自分の応答を
他ノードの応答と誤認する。**比較相手は「検査を開始したインターフェースの
MAC」を probe 開始時点で保存しておく**(`s_probe_self_mac` / `s_dad_self_mac`)。
`eth_get_mac()` / `NET_SELF_IP` は「いま active なインターフェース」を指すので、
**送信と受信で active が変わる経路では自分の同一性判定に使えない。**

なお「全インターフェースの MAC と比べる」(RFC の文面に最も忠実)にすると、
陽性対照が対向 PF なので抑止されて検証できなくなる。2 つの PF はアドレスも
キャッシュも独立した別ノードとして扱うのが正しい。

### 検証コマンド

- `dadtest` — [1] 自分の IPv4 は空き → [2] **対向 PF の IPv4 は使用中(陽性
  対照)** → [3] 自分のリンクローカルは空き → [4] **対向 PF のリンクローカルは
  使用中(陽性対照)** → [5] `netif_t` への記録、を確認する。
- **陰性だけを見ても検証にならない。** 「自分のアドレスは空き」は検出処理が
  一切動いていなくても成立する(応答が返ってこないことで判定するため)。
  陽性対照が必ず組で要る。
- **A3 に新しいアドレスは要らない**(陰性=自分、陽性=対向 PF で足りる)。
  DAC 直結リンクはオンボード `enp2s0` と物理的に繋がっていないので、
  ARP Probe / DAD NS はユーザの LAN には 1 フレームも出ない。

## 送信側の IP フラグメント(`PLAN_protocol_gaps.md` 段階 8 = A4)

`ip_send()` にリンク MTU 超えの分割を追加した(**IPv4 のみ**。IPv6 は経路上で
分割しないので Fragment 拡張ヘッダになり、B4 と一緒にやる)。

**分割の単位は「IP ペイロード全体」。** 上位プロトコルのヘッダは先頭断片にしか
入らないので、UDP データグラムを組み立て終わった後の `ip_send()` が正しい層。
`udp_send()` は最後に `ip_send()` を呼ぶので、そこだけ直せば UDP も効く。

### 間違えやすい 3 点

1. **フラグメントオフセットは 8 バイト単位。** 最後以外の断片長は 8 の倍数で
   なければならない。MTU をそのまま断片長にすると端数が出て、次の断片の
   オフセットを 13bit フィールドで表現できない。実機は L3 MTU 9256 →
   IP ペイロード上限 9236 → **切り下げて 9232**。
2. **全断片で IP ID を同じにする。** 受信側は (src, dst, protocol, id) で束ねる。
   `ip_build_header()` は呼ばれるたびに ID を増やすので、断片化経路では先に
   1 個取って使い回す。
3. 上位ヘッダは先頭断片のみ(上記の層の選択)。

`netif_t.mtu`(IPv4 の total_length 上限)は **`mss_cap + 20 + 20` = 9256**。
`mss_cap` はこのリンクでフルサイズ TCP セグメントが実際に通っている値なので、
そこから導けば新しい仮定を持ち込まない(`dev->port_mtu` から計算し直すと、
`mss_cap` が 9216 にハードコードされている理由と食い違う恐れがある)。

### 検証: 受信側の再構成が無いので観測フックで見る

**受信側の再構成は実装していない**(従来どおり破棄)。だから素直な往復では
送信側を確かめられない。`ip.c` に `ip_set_frag_observer()` を入れ、断片を捨てる
直前にテスト側へ渡す(登録中は断片ごとの破棄ログを抑止する)。

- `fragtest [dump]` — [1] MTU 以下は分割されない → [2] MTU の 2 倍超で
  **中間断片(MF=1 かつ offset 非 0)**が生じ、再構成がバイト一致 →
  [3] UDP 経由でも分割される、を確認する。
  **[2] で中間断片の存在を明示的に確認するのが要点**(2 個に割れるだけの
  ケースでは MF=1 かつ offset 非 0 の経路を通らない)。
- **`tools/ip_frag_check.c`** — このリポジトリのコードを一切 include せず、
  Linux の `<netinet/ip.h>` の `struct ip` / `IP_MF` / `IP_OFFMASK` だけで
  断片ヘッダを組み立て直して読み戻す。「8 バイト単位のオフセットを 13bit に
  詰める」を取り違えていればここで必ず食い違う(`disc_log_check.c` と同じ考え方)。

  ```bash
  ssh rpi5-rdma-target 'cd ~/vfio_nvme && gcc -O2 -Wall -Wextra -o /tmp/ip_frag_check tools/ip_frag_check.c'
  ```

**自作 ↔ 自作では断片が届いても上位へ渡らない**(受信側が再構成しない)。
相手が Linux なら再構成するので送信側だけでも意味はあるが、素直な往復テストが
書けないのはこのせい。

## Path MTU Discovery(`PLAN_protocol_gaps.md` 段階 9+10 = A5 + A6)

`src/pmtu.c` / `src/pmtu.h`。ICMP/ICMPv6 のエラーを受けて宛先ごとの PMTU を学習し、
TCP の MSS と IPv4 の断片化へ反映する。**A5 と A6 は 1 つの機能**(A5 の送信側は
転送しないので出番が無く、受信して学習する側が本体)。

### IPv4 と IPv6 で MTU の置き場所が違う

| | MTU の位置 |
|---|---|
| ICMP Destination Unreachable code 4(Fragmentation Needed)| **未使用 4 バイトの下位 16bit**(byte 6-7)。byte 4-5 は 0 |
| ICMPv6 type 2(Packet Too Big)| **byte 4-7 の 32bit 全体** |

片方のつもりでもう片方を書くと、値が 0 になったり桁が狂ったりする。
**自作の送信側と自作の受信側だけで試すと両方が同じ間違い方をして絶対に検出
できない**種類の間違い(CRC32C で踏んだ穴と同じ形)。glibc のヘッダを実際に
読んで確認した:

```c
struct { uint16_t __glibc_reserved; uint16_t mtu; } frag;  /* path mtu discovery */
```

**学習する宛先は「引用された元パケットの宛先」**であって、ICMP の送信元
(= 文句を言ってきたルータ)ではない。ここも取り違えやすい。

### PMTU は近隣キャッシュに入れない(宛先キーの専用表)

**A1 でゲートウェイ経路を入れた結果、近隣キャッシュのキーは「次ホップ」に
なっている。** PMTU は経路の性質なので、そこへ入れるとサブネット外の宛先が全部
1 つのゲートウェイのエントリを共有し、別々の経路の PMTU が混ざる。
`netaddr_t`(宛先)をキーにした 8 エントリの専用表にしてある。

### 安全側の作り

- **床**: v4 は 576、v6 は 1280(RFC 8201 の IPv6 最小 MTU)。これ未満は採用しない。
- **下げる方向にしか動かさない**(RFC 1191 6.3)。学習済みより大きい報告は無視し、
  上げ直しは TTL(10 分)の満了に任せる。**そうしないと、偽の大きい値を送り込む
  だけで学習を無効化できてしまう。**
- MTU=0(RFC 1191 非対応の古いルータ)は無視。推測降下は未実装。

### 反映先とホットパス

`tcp_mss_cap_for()` が PMTU で頭打ちにする。**この関数は SYN を組むときだけ
呼ばれる**ので、表を引くコストはセグメントごとの経路に乗らない。確立済みの
コネクションは `tcp_pmtu_update()` が `snd_mss` を切り下げる(「以後の新規
セグメントから小さくする」だけでよく、送信済み・未確認のセグメントとの整合は
要らない)。ただし**再送は保存済みスロットをそのまま送り直すので、下げた直後の
再送だけは新しい PMTU を超えうる**(再分割は未実装)。

### 検証コマンド

- `pmtutest [dump]` — 対向 PF にルータ役をさせて ICMP Frag Needed / ICMPv6
  Packet Too Big を注入し、[2][5] 学習 → [3][6] 新規コネクションの MSS が
  v4=MTU−40 / v6=MTU−60 になる → [4] `ip_send` が PMTU で分割 → [7] 床 →
  [8] 上げ直さない、を確認して **PMTU キャッシュをクリアする**。
  **[3] と [6] を必ず両方通すこと**(v4/v6 で overhead が 20 対 40 と違うので、
  片方だけでは L3 ヘッダ長の取り違えを見逃す)。
- **`tools/icmp_mtu_check.c`** — 注入した ICMP の**形式そのもの**を glibc の
  `struct icmphdr` / `struct icmp6_hdr` だけで読み直す。注入側も自作なので、
  これが無いと「自分の間違いを自分で受け入れて PASS」になる。

  ```bash
  ssh rpi5-rdma-target 'cd ~/vfio_nvme && gcc -O2 -Wall -Wextra -o /tmp/icmp_mtu_check tools/icmp_mtu_check.c'
  ```

- **IPv4 側の宛先には別名インターフェース(10.9.9.9)を使う。** `nvmet` が使う
  192.168.101.11 を宛先にすると、学習した PMTU が生きているセッションの
  `snd_mss` まで下げてしまい、**`pmtu_clear()` では戻らない**(張り直しが要る)。
