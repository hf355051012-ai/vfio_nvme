# vfio_nvme

x86-64 Linux ユーザ空間 + VFIO で ConnectX-4 を直接駆動し、NVMe-oF (RoCEv2) と
NVMe/TCP のターゲットとイニシエータを同一プロセス内に立てて性能を測るための
実験用ドライバ/スタック。カーネルドライバも libibverbs も使わず、HCA の
bring-up からフローステアリング、TCP/IP、NVMe-oF プロトコルまで全て自前で持つ。

`rpi5_boot`(Raspberry Pi 5 ベアメタル)の x86 VFIO ポートを切り出して独立
させたもの。**このリポジトリは x86 専用**で、rpi5 の履歴は引き継いでいない。

**初めて読む人へ**: 仕組みの説明は **[`SPEC.md`](SPEC.md)(仕様書)** にあります。
ネットワークやドライバの前提知識が無くても読めるように、`MMIO` や `DMA` の
説明から順に積み上げてあります。この README は要約・ビルド手順・性能値です。

## 構成

```
Makefile                     x86 専用の単純なビルド(PLATFORM 分岐なし)
include/platform.h           HAL 契約(DMA アロケータ)
src/                         アーキ非依存コア
src/platform/x86-linux/      VFIO HAL(console / timer / smp / dma / vfio / エントリ)
tools/sync_to_optiplex.sh    Windows -> OptiPlex 一方向同期
```

### レイヤと主要ファイル

| レイヤ | ファイル | 役割 |
|---|---|---|
| エントリ | `platform/x86-linux/main.c` | 自己テスト、bring-up、常駐シェル(コマンド実装) |
| VFIO / HAL | `platform/x86-linux/vfio.c` | デバイスを掴む、BAR mmap、コンフィグ空間、IOMMU マップ |
| | `platform/x86-linux/hal_dma.c` | DMA アロケータ、プロセスメモリの IOVA マップ、cpu->dev 変換 |
| | `platform/x86-linux/hal_smp.c` | pthread によるコアワーカ、affinity、遅延注入 |
| | `platform/x86-linux/hal_timer.c` `console.c` | 単調タイマ、コンソール入出力 |
| mlx5 ドライバ | `mlx5.c` | HCA bring-up(cmdq / ENABLE_HCA / UAR / EQ / PD / MKey / CQ / TIS / RQ / TIR / SQ / フローステアリング)、QP 状態遷移、モニタ |
| | `mlx5_qp.c` | RC/UD QP の WQE 組み立てと CQE ポーリング(SEND / RDMA_WRITE / RDMA_READ / RECV) |
| | `mlx5_net.c` | `nic_ops_t` バックエンド。Ethernet の送受信、LSO、SQ 復帰 |
| RDMA | `rdma_cm.c` | IB CM(REQ/REP/RTU)。GSI QP 経由で RC QP を確立する |
| | `nvme_rdma.c` / `nvmet_rdma.c` | NVMe-oF RDMA の initiator / target |
| TCP/IP | `netif.c` | インターフェース管理 + Ethernet フレームディスパッチ |
| | `arp.c` `ip.c` `icmp.c` `tcp.c` | ARP / IPv4 / ICMP / TCP |
| NVMe/TCP | `nvme_tcp.c` `nvme.c` | initiator(PDU 層 / プロトコル層) |
| | `nvmet_tcp.c` `nvmet.c` | target(同上、常駐サーバ) |
| 基盤 | `job.c` | 協調ジョブスケジューラ(全ステートマシンがこの上で回る) |
| | `timestamp.c` | `ts_log` リングバッファ(性能分析の中核) |
| | `crc32c.c` `timer.c` `net_buf.c` | CRC32C(SSE4.2)、単位変換、フレームバッファプール |

規模: 約 33,000 行(`.c` + `.h` + Makefile)。

## 開発フロー

**編集は Windows 側 (`C:\Users\fukud\Documents\vfio_nvme`) が正**。
ビルドと実機テストは ConnectX-4 のある OptiPlex で行う。

```bash
wsl -e bash -lc "/mnt/c/Users/fukud/Documents/vfio_nvme/tools/sync_to_optiplex.sh"
```

同期は `--delete` 付きの一方向。OptiPlex 側 (`~/vfio_nvme`) で直接編集すると
次の同期で失われる。

## ビルド

```bash
cd ~/vfio_nvme && make -j8
```

成果物: `build/vfio_nvme`

## 実行

ConnectX-4 は `mlx5_core` か `vfio-pci` のどちらか一方にしかバインドできない。
Linux 側の比較用ベンチ(`~/script/linux_loopback.sh`)とは排他。

```bash
~/script/enable_vfio.sh      # vfio-pci へバインド
sudo ~/vfio_nvme/build/vfio_nvme 0000:01:00.0 0000:01:00.1
~/script/disable_vfio.sh     # mlx5_core へ戻す
```

**注意**: `enable_vfio.sh` は `nr_hugepages` を 128 へ下げる。256MB 名前空間には
不足の恐れがあるため、バインドだけ手動で行い hugepages は 1024 のままにする方が安全。

引数を 2 つ渡すと bring-up して常駐シェルへ入る。**単発プロセスの起動を
繰り返すと ConnectX/ホストが wedge する**ため、必ずこの常駐シェルの中で作業する。

### shell コマンド

| コマンド | 内容 |
|---|---|
| `bench [KB[,KB...]] [r\|w\|rw] [qd]` | NVMe-oF RDMA スループット |
| `tcpbench [KB[,KB...]] [r\|w\|rw] [hdgst] [ddgst] [digest]` | NVMe/TCP スループット(qd は内部固定) |
| `monitor` | 温度 / health / PCIe リンク / MAC・PHY エラーカウンタ |
| `nvmet [port]` | NVMe/TCP ターゲットを常駐起動 |
| `ts [core N] [num N] [mask M V]` / `ts pause\|resume` | `ts_log` ダンプ |
| `simdelay <core> <us>` | 律速要因の切り分け(コアへ遅延注入) |
| `ackthresh [n]` | TCP 遅延 ACK 閾値 |
| `jobs` / `help` / `quit` | |

`monitor` の温度表示 `temp 55/55C (peak 65/65, crit 105/105)` は MTMP
レジスタ由来で、それぞれ **現在値 / これまでに記録された最高温度
(`max_temperature`、Linux hwmon の `temp1_highest` 相当。`mtr` ビットで
リセットできる履歴値であって上限ではない) / 許容最大
(`temp_threshold_hi`、hwmon の `temp1_crit` 相当)**。

### ベンチの要約表

`bench` / `tcpbench` の最後に出る要約表は、Linux 側の比較ベンチ
`~/script/linux_loopback.sh` と**同じ書式・同じ列・同じ行順**(write を
全ブロックサイズ分並べたあとに read)で出力する。両者を並べてそのまま
比較できる。

```
スタック: vfio_nvme / トランスポート: rocev2 / qd=8 / runtime=3s

rw         bs       qd            MiB/s         IOPS    avg latency
---------- -------- ------ ------------ ------------ --------------
write      8k       8           1936.09    247819.66       32.28 us
write      64k      8           4747.41     75958.66      105.32 us
write      256k     8           5603.83     22415.33      356.89 us
read       8k       8           3957.12    506511.66       15.79 us
read       64k      8           6761.20    108179.33       73.95 us
read       256k     8           5895.33     23581.33      339.25 us
```

- **単位は MiB/s**(`linux_loopback.sh` に合わせた 1024 進)。後述の「性能」
  節の表は切り出し時に **MB/s**(1000 進)で採取した値なので、約 4.9% ぶん
  数字が食い違う。直接比較しないこと。
- `avg latency` は fio のような実測ではなく、このベンチが qd 本を常時
  outstanding に保つ設計であることから **Little の法則(qd ÷ IOPS)**で
  求めた値。fio 側は iodepth が常に埋まるとは限らないぶん、同じ IOPS でも
  数 % 小さめに出る。

## PDU ダイジェスト(CRC32C)

NVMe/TCP の **ヘッダダイジェスト / データダイジェスト**(いずれも CRC32C)に
initiator・target 双方で対応している。`tcpbench` の引数に `hdgst` / `ddgst` /
`digest`(両方)を足すと有効になる。位置引数ではなくキーワードなので、
`tcpbench 256 rw digest` のように順序を気にせず書ける。

```
tcpbench 64 rw                # ダイジェスト無し
tcpbench 64 rw hdgst          # ヘッダのみ
tcpbench 64 rw digest         # ヘッダ + データ
```

ダイジェストは ICReq/ICResp でコネクション確立時に一度だけ合意するため、
**前回と指定が変わると常駐セッションを自動で張り直す**。実際に合意できた値は
要約表のトランスポート名(`tcp+hdgst+ddgst` 等)と ICResp のログに出る。

**`bench`(NVMe-oF RDMA)には digest はない。** ダイジェストは NVMe-oF の
TCP トランスポート束縛が定義する機能で、RDMA 束縛には対応する仕組みが無い
(RoCE のパケット CRC が担う)。`bench` に指定しても警告を出して無視する。
`~/script/linux_loopback.sh` の `--hdr-digest` / `--data-digest` も同じ理由で
`--transport tcp` 専用で、`rocev2` と併用するとエラーになる。

### 実測(PF0<->PF1 ループバック、qd=8、MiB/s)

| 設定 | write 64k | read 64k | write 256k | read 256k |
|---|---|---|---|---|
| ダイジェスト無し | 3357 | 4889 | 3969 | 5259 |
| `digest`(hdgst+ddgst) | 2992 | 4248 | 3985 | 4718 |

**`hdgst` 単体のコストはほぼゼロ**(誤差範囲)。ヘッダダイジェストの CRC
対象は PDU あたり 24〜72 バイトしかないので当然で、残りは 64KB 全バイトに
対する CRC32C の実コスト。256k write に至ってはダイジェスト有無で差が無い。

digest のコストがどこにあるかは、`crc32c()` を恒等関数に差し替えて
(送受とも同じ関数になるのでダイジェストは自己無矛盾に一致する)測ると
切り分けられる。**プロトコル側のコスト(相の追加・4 バイト余分な送受信)は
約 3% しかなく、残り 86% は純粋に CRC の計算時間**だった。だから
`crc32c()` 自体の速度がそのまま効く(下記)。

当初はここが `hdgst` だけで write −31% / read −55% も落ちていた。原因は
CRC ではなく、ダイジェストが有効だと target 側の高速パスが 2 つとも
フォールバックしていたこと(いずれも「digest 時は使わない」という単純な
ゲートで、実装が追いついていなかっただけ)。

| 落ちていた経路 | 影響 | 対処 |
|---|---|---|
| 受信: push 型(inline upcall)→ pull 型 | write(target が受信側) | パーサに `PRX_HDGST`/`PRX_DDGST` 相を追加。データダイジェストは**受信ストリームから逐次 CRC を積む**ので、コピー先を読み直す 2 パス目は不要 |
| 送信: ゼロコピー `send_c2h_async` → コピーする `send_c2h` | read(target が送信側) | ダイジェストを**送信元バッファから直接算出**して 4 バイトだけ追加でキュー。連続バッファは不要 |

同じ手法を initiator 側(`nvme_read_rx_upcall` / `nvme_pipeline_h2c_pump`)
にも使っており、両側とも digest 有効時にゼロコピー・push 型を維持する。

### CRC32C 実装(`crc32c.c`)

`crc32` 命令はレイテンシ 3・スループット 1/cycle なので、単一チェーンでは
8B/3cycle = **2.67 B/cycle** が上限になる。独立した 3 本を交互に回して
レイテンシを隠し、部分 CRC を PCLMULQDQ で畳み込んでいる。

畳み込みは `crc32_u64(0, V) = V * x^64 mod P` という性質を使い、clmul の
還元前 63bit 積をそのまま `crc32` 命令へ食わせて還元させる(定数は
`K2 = x^(8*(BLK-8)) mod P`、`K1 = x^(8*(2*BLK-8)) mod P`)。大小 2 段の
ブロック(1024B / 128B)にしてあるのは、大きいブロックだけだと端数が
単一チェーンへ落ちて遅くなるため。

i3-8100 @3.6GHz、**64KB を 8960B ずつ逐次計算**(push 型受信の実際の
呼ばれ方)での実測:

| 実装 | GB/s | B/cycle |
|---|---|---|
| 単一チェーン、先頭アライメント決め打ち(旧) | 9.56 | 2.66 |
| 単一チェーン、アライメント非依存 | 9.60 | 2.67 |
| **3 本 + PCLMULQDQ 合成(現行)** | **24.31** | **6.75** |
| ISA-L `crc32_iscsi`(参考) | 28.50 | 7.92 |

**PCLMULQDQ は本体の折り畳みではなく、合成を数命令に落とすために要る。**
本体は crc32 命令が 8 B/cycle で頭打ちなので、pclmul 折り畳みにしても
ISA-L と同じ天井に当たる(これを超えるには VPCLMULQDQ が必要だが、
Coffee Lake には無い)。逆に合成を GF(2) 行列でやると 1 回あたり約 30us
かかり、呼び出し長が変わるたびに作り直しになるため、逐次呼び出しでは
0.94 GB/s まで落ちて本体の利得を食い潰す。

正しさは起動時の `crc32c_selftest()` が担保する。既知ベクタ
`CRC32C("123456789")=0xE3069283` に加え、**オフセット 0〜7 × 4096B で
1 バイト単位の基準計算と一致すること**を確認している(3 本インタリーブ・
2 段ブロック・端数の全経路を通る)。合成定数を間違えればここで落ちる。

### Linux 側比較ベンチ

`~/script/linux_loopback.sh`(このリポジトリ外)にも同じオプションを足してある。
`--hdr-digest` / `--data-digest` / `--digest`。kernel スタックでは
`nvme connect -g/-G`、SPDK スタックでは `spdk_nvme_perf -H/-I` へ渡る。
kernel イニシエータは接続条件(トランスポート + ダイジェスト)を
`/tmp/linux_loopback_initiator.state` に記録し、前回と違えば自動で
`nvme disconnect` してから繋ぎ直す。

| スタック | 64K read ダイジェスト無し | `--digest` |
|---|---|---|
| kernel | 1059 MiB/s | 905 |
| spdk | 1613 | 1506 |

## 性能

同一 shell セッション内で `tcpbench 8,64,256 rw` / `bench 8,64,256 rw 8` を
3 周連続実行した実測(MB/s、PF0<->PF1 ループバック、qd=8)。
「切り出し前」はリファクタリング着手前のベースライン、「切り出し後」は
Phase 6 の最終検証。

| chunk | | 切り出し前 1/2/3 周目 | 切り出し後 1/2/3 周目 |
|---|---|---|---|
| 8K | TCP write | 942.62 / **0.01** / 595.59 | 913.61 / 521.48 / 521.46 |
| | TCP read | 2696 / 2690 / 2694 | 2597 / 2601 / 2613 |
| | RDMA write | 2062 / 1991 / 2055 | 2017 / 2013 / 2014 |
| | RDMA read | 4303 / 4294 / 4292 | 4308 / 4307 / 4305 |
| 64K | TCP write | 3533 / 3490 / 3551 | 3514 / 3502 / 3364 |
| | TCP read | 5255 / 5271 / 5262 | 5280 / 5276 / 5277 |
| | RDMA write | 5015 / 5008 / 5008 | 4963 / 4957 / 4961 |
| | RDMA read | 7032 / 7032 / 6758 | 7095 / 7095 / 6820 |
| 256K | TCP write | 4238 / 4064 / 4226 | 4190 / 4039 / 4211 |
| | TCP read | 5485 / 5492 / 5491 | 5371 / 5512 / 5471 |
| | RDMA write | 5881 / 5879 / 5880 | 5871 / 5636 / 5870 |
| | RDMA read | 6133 / 6320 / 6317 | 6089 / 6332 / 6331 |

8K TCP write を除き、全項目で切り出し前後の差は **±3.5% 以内**。

### 測定上の注意

- **TCP 8K write は退行判定に使えない。** 同一バイナリ・同一セッションでも
  942 / 0.01 / 595 と桁違いにばらつく。0.01 の回は
  `TXリング枠待ちタイムアウト` -> `SQ自動復帰` を踏んだもので、自己修復する
  既知の事象。退行判定は 64K / 256K と 8K read で行うこと。
- **bring-up 直後の 1 回目は低めに出る**(RDMA 64K write が 4703 -> 続けて
  測ると 4984 と回復した実測あり)。単発比較で判断せず、同一セッションで
  連続測定して定常値を比較すること。

## 既知の事象(いずれも切り出し前から存在、リファクタリング起因ではない)

- 起動時に `[vfio] VFIO_IOMMU_MAP_DMA(...) 失敗 (errno=14)` が 1 回出る。
  `remap_process_memory()` のベストエフォートなマッピングが 1 領域で失敗する
  もので、動作には影響しない。
- 高負荷時にごく稀に SQ が `LOCAL_QP_OP_ERR` で止まる。サーキットブレーカー
  付きの `SQ自動復帰`(ERR->RST->RDY)で回復し、TCP の再送で吸収される。
- `monitor` が常に `FW=ASSERT` / `PF0[FW-assert] PF1[FW-assert]` を表示する。
  **切り出し前のバイナリでも全く同じ出力**になることを実機で確認済みで、
  カード自体は全ベンチをフルスピードで完走する。health レジスタの sticky
  ビットか判定ロジックの誤りと思われるが未調査。
- `nvmet <port>` で 4421 以外を指定した後に `tcpbench` を実行すると、
  `tcpbench` 側が常に 4421 へ接続しにいくため `SYN送信/再送すべて失敗` に
  なる。さらにその失敗を挟むと後続の `bench` も巻き添えで壊れる。
  `nvmet` を手動起動する場合はポートを 4421 にすること。

## 環境

- OptiPlex 3060 (i3-8100, Coffee Lake), DDR4-2400 dual channel
- ConnectX-4 MCX456A-ECAT (100GbE, MT27700), FW 12.28.2006, PCIe Gen3 x16
- 2 ポートを DAC 直結したループバック構成 (PF0=initiator / PF1=target)

## 由来

`rpi5_boot` の x86 VFIO ポートから、以下の順で切り出した(各フェーズの
詳細はコミットログ、計画は `~/.claude/plans/vfio-nvme-extraction.md`)。

| Phase | 内容 | 削減 |
|---|---|---:|
| 0 | プロジェクト作成、ベースライン確立 | - |
| 1 | rpi5 専用ファイル削除、argv 直接モード削除、Makefile 簡約 | -11,148 |
| 2 | eth.c を netif へ統合・改名、board.h と aarch64 分岐を撤去 | -3,175 |
| 3 | 未使用関数の削除(nm + gcc 警告で収束まで反復) | -4,590 |
| 4 | 2 行以上のコメント削除 | -9,941 |
| 5 | 関数ヘッダコメント(概要/引数/戻り値/コール元)を 357 個付与 | +3,993 |

Phase 4 と 5 は **リンク後のバイナリが md5 完全一致**することで、コードに
一切影響していないことを機械的に検証した。
