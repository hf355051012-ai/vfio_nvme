#!/usr/bin/env bash
#
# Windows 側(作業の正)-> OptiPlex(ビルド・実機テスト)の一方向同期。
#
# 運用: 編集は必ず Windows 側で行い、このスクリプトで OptiPlex へ配る。
# OptiPlex 側で直接編集すると次回の同期で --delete により失われる。
#
# WSL から実行する:
#   wsl -e bash -lc "/mnt/c/Users/fukud/Documents/vfio_nvme/tools/sync_to_optiplex.sh"
#
# 環境変数で上書きできる:
#   REMOTE      ssh 先        (既定: rpi5-rdma-target)
#   REMOTE_DIR  同期先ディレクトリ (既定: ~/vfio_nvme)
#
set -euo pipefail

REMOTE="${REMOTE:-rpi5-rdma-target}"
REMOTE_DIR="${REMOTE_DIR:-vfio_nvme}"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "sync: ${SRC}/ -> ${REMOTE}:~/${REMOTE_DIR}/"

ssh "$REMOTE" "mkdir -p ~/${REMOTE_DIR}"

# build/ は remote 側の成果物なので送らず、--delete の対象からも外す。
rsync -a --delete \
      --exclude '.git/' \
      --exclude 'build/' \
      --exclude '*.swp' \
      --exclude '*.o' \
      --exclude '*.d' \
      "${SRC}/" "${REMOTE}:~/${REMOTE_DIR}/"

echo "sync: done"
