# vfio_nvme

x86-64 Linux ユーザ空間 + VFIO で ConnectX-4 を直接叩き、NVMe-oF (RoCEv2) と
NVMe/TCP のターゲット/イニシエータを同一プロセス内に立てて性能を測るための
実験用ドライバ/スタック。

`rpi5_boot`(Raspberry Pi 5 ベアメタル)の x86 VFIO ポート `~/rpi5-x86port` を
切り出して独立させたもの。**このリポジトリは x86 専用**で、rpi5 の履歴は
引き継いでいない。切り出し・リファクタリングの計画は
`~/.claude/plans/vfio-nvme-extraction.md` を参照。

## 構成

```
Makefile                     PLATFORM=x86-linux でビルド(rpi5 分岐は Phase 1 で撤去予定)
include/platform.h           HAL 契約(DMA)
src/                         アーキ非依存コア(mlx5 ドライバ / RoCEv2 / NVMe-oF / TCP-IP)
src/platform/x86-linux/      x86 VFIO HAL(console / timer / smp / dma / vfio / main)
tools/sync_to_optiplex.sh    Windows -> OptiPlex 一方向同期
```

主要なレイヤ:

| レイヤ | ファイル |
|---|---|
| VFIO / HAL | `platform/x86-linux/{vfio,hal_dma,hal_timer,hal_smp,console}.c` |
| mlx5 HCA ドライバ | `mlx5.c` (bring-up), `mlx5_qp.c` (QP/WQE/CQE), `mlx5_net.c` (Ethernet NIC) |
| RDMA | `rdma_cm.c` (IB CM), `nvme_rdma.c` (initiator), `nvmet_rdma.c` (target) |
| TCP/IP | `eth.c`, `netctx.c`, `arp.c`, `ip.c`, `icmp.c`, `tcp.c` |
| NVMe/TCP | `nvme_tcp.c`/`nvme.c` (initiator), `nvmet_tcp.c`/`nvmet.c` (target) |
| 計測/基盤 | `timestamp.c` (ts_log), `stateprof.c`, `job.c`, `rxcopy.c`, `crc32c.c` |

## 開発フロー

**編集は Windows 側 (`C:\Users\fukud\Documents\vfio_nvme`) が正**。
ビルドと実機テストは実機(ConnectX-4)のある OptiPlex で行う。

```bash
# Windows -> OptiPlex へ同期(WSL から実行)
wsl -e bash -lc "/mnt/c/Users/fukud/Documents/vfio_nvme/tools/sync_to_optiplex.sh"
```

同期は `--delete` 付きの一方向。OptiPlex 側 (`~/vfio_nvme`) で直接編集すると
次の同期で失われる。

## ビルド

OptiPlex 上で:

```bash
cd ~/vfio_nvme && make PLATFORM=x86-linux -j
```

成果物: `build/rpi5-x86`(Phase 1 で `build/vfio_nvme` へ改名予定)

## 実行

ConnectX-4 は `mlx5_core` か `vfio-pci` のどちらか一方にしかバインドできない。
Linux 側の比較用ベンチ(`~/script/linux_loopback.sh`)とは排他。

```bash
~/script/enable_vfio.sh      # vfio-pci へバインド + hugepages 確保
sudo ~/vfio_nvme/build/rpi5-x86 0000:01:00.0 0000:01:00.1 shell
~/script/disable_vfio.sh     # mlx5_core へ戻す
```

**必ず常駐 `shell` モードを使うこと。** 単発プロセスの起動を繰り返すと
ConnectX/ホストが wedge して電源断が必要になる。

### shell コマンド

| コマンド | 内容 |
|---|---|
| `bench [chunkKB] [r\|w\|rw] [qd]` | NVMe-oF RDMA スループット |
| `tcpbench [chunkKB] [r\|w\|rw] [qd]` | NVMe/TCP スループット |
| `monitor` | ConnectX HW モニタ(温度/health/PCIe/リンク層エラー) |
| `nvmet` | NVMe/TCP ターゲット常駐 |
| `ts [core N] [num N] [mask M V]` | ts_log ダンプ |
| `simdelay` / `ackthresh` | 性能切り分け用のパラメータ注入 |
| `jobs` / `help` / `quit` | |

## ベースライン性能

リファクタリング前の基準値。2026-08-16、同一 shell セッション内で
`tcpbench 8,64,256 rw` / `bench 8,64,256 rw 8` を 3 周連続実行した実測(MB/s):

| chunk | | 1周目 | 2周目 | 3周目 |
|---|---|---:|---:|---:|
| 8K | TCP write | 942.62 | **0.01** | 595.59 |
| | TCP read | 2696.46 | 2690.12 | 2694.57 |
| | RDMA write | 2062.74 | 1991.30 | 2055.21 |
| | RDMA read | 4303.97 | 4294.63 | 4292.26 |
| 64K | TCP write | 3533.50 | 3490.51 | 3551.17 |
| | TCP read | 5255.89 | 5271.78 | 5262.30 |
| | RDMA write | 5015.31 | 5008.82 | 5008.69 |
| | RDMA read | 7032.88 | 7032.31 | 6758.13 |
| 256K | TCP write | 4238.51 | 4064.28 | 4226.46 |
| | TCP read | 5485.53 | 5492.09 | 5491.04 |
| | RDMA write | 5881.28 | 5879.10 | 5880.32 |
| | RDMA read | 6133.47 | 6320.11 | 6317.32 |

**TCP 8K write は退行判定に使えない。** 同一バイナリ・同一セッションで
942.62 / 0.01 / 595.59 と桁違いにばらつく。0.01 の回は
`[mlx5net] TXリング枠待ちタイムアウト` -> `SQ自動復帰` が発生しており、
既知の SQ スタック(自己修復する)を踏んだもの。
**8K write 以外は 3 周とも 1〜4% 以内で安定**しているので、退行判定には
64K / 256K と 8K read を使うこと。

この機械は熱ドリフト等でも変動する。**単発比較で退行を判断せず、同一
セッション内で連続 3 回測って定常値を比較すること。**

## 環境

- OptiPlex 3060 (i3-8100, Coffee Lake), DDR4-2400 dual channel
- ConnectX-4 MCX456A-ECAT (100GbE, MT27700), FW 12.28.2006, PCIe Gen3 x16
- 2 ポートを DAC 直結したループバック構成 (PF0=initiator / PF1=target)
