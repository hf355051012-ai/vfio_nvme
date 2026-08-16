# vfio_nvme

x86-64 Linux ユーザ空間 + VFIO で ConnectX-4 を直接駆動し、NVMe-oF (RoCEv2) と
NVMe/TCP のターゲットとイニシエータを同一プロセス内に立てて性能を測るための
実験用ドライバ/スタック。カーネルドライバも libibverbs も使わず、HCA の
bring-up からフローステアリング、TCP/IP、NVMe-oF プロトコルまで全て自前で持つ。

`rpi5_boot`(Raspberry Pi 5 ベアメタル)の x86 VFIO ポートを切り出して独立
させたもの。**このリポジトリは x86 専用**で、rpi5 の履歴は引き継いでいない。

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

規模: 約 20,500 行(`.c` + `.h` + Makefile)。

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
| `tcpbench [KB[,KB...]] [r\|w\|rw]` | NVMe/TCP スループット(qd は内部固定) |
| `monitor` | 温度 / health / PCIe リンク / MAC・PHY エラーカウンタ |

`monitor` の温度表示 `temp 55/55C (peak 65/65, crit 105/105)` は MTMP
レジスタ由来で、それぞれ **現在値 / これまでに記録された最高温度
(`max_temperature`、Linux hwmon の `temp1_highest` 相当。`mtr` ビットで
リセットできる履歴値であって上限ではない) / 許容最大
(`temp_threshold_hi`、hwmon の `temp1_crit` 相当)**。
| `nvmet [port]` | NVMe/TCP ターゲットを常駐起動 |
| `ts [core N] [num N] [mask M V]` / `ts pause\|resume` | `ts_log` ダンプ |
| `simdelay <core> <us>` | 律速要因の切り分け(コアへ遅延注入) |
| `ackthresh [n]` | TCP 遅延 ACK 閾値 |
| `jobs` / `help` / `quit` | |

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
