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

2026-08-16 実測(名前空間 256MB、qd=8、PF0<->PF1 25GbE ループバック、MB/s):

| chunk | TCP write | TCP read | RDMA write | RDMA read |
|---|---:|---:|---:|---:|
| 8K | 948.7 | 2710.8 | 2061.2 | 4319.1 |
| 64K | 3546.1 | 5295.6 | 5016.6 | 6876.9 |
| 256K | 4256.5 | 5508.6 | 5903.8 | 6424.3 |

この機械は熱ドリフト等で 18〜20% の変動が実測されている。**単発比較で退行を
判断せず、同一セッション内で連続 3 回測って定常値を比較すること。**

## 環境

- OptiPlex 3060 (i3-8100, Coffee Lake), DDR4-2400 dual channel
- ConnectX-4 MCX456A-ECAT (100GbE, MT27700), FW 12.28.2006, PCIe Gen3 x16
- 2 ポートを DAC 直結したループバック構成 (PF0=initiator / PF1=target)
