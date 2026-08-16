# vfio_nvme

x86-64 Linux ユーザ空間 + VFIO で ConnectX-4 を直接駆動し、NVMe-oF(RoCEv2)と
NVMe/TCP のターゲットとイニシエータを同一プロセスに立てて性能を測る実験用
ドライバ/スタック。カーネルドライバも libibverbs も使わない。
`rpi5_boot`(Raspberry Pi 5 ベアメタル)の x86 VFIO ポートを切り出したもので、
**このリポジトリは x86 専用**、rpi5 の履歴は引き継いでいない。

構成・レイヤ・シェルコマンド・性能値といった説明は `README.md` にある。
このファイルには**作業上の手順と、実機で踏んだ落とし穴**だけを書く。

## 編集とビルド

**編集は Windows 側 `C:\Users\fukud\Documents\vfio_nvme` が正。** ビルドと実機
テストは ConnectX-4 のある OptiPlex(`ssh rpi5-rdma-target`)で行う。

```bash
wsl -e bash -lc "/mnt/c/Users/fukud/Documents/vfio_nvme/tools/sync_to_optiplex.sh"
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
| write 8k | 293 | 406 | **856** | 2.9x |
| write 64k | 779 | 1289 | **3309** | 4.2x |
| write 256k | 1220 | 2068 | **3968** | 3.3x |
| read 8k | 307 | 482 | **2453** | 8.0x |
| read 64k | 902 | 1642 | **5024** | 5.6x |
| read 256k | 1366 | 2175 | **5242** | 3.8x |

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
