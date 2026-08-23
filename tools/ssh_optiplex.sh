#!/usr/bin/env bash
#
# OptiPlex(ビルド・実機テスト機)へ入る。
#
# 接続先と鍵は ~/.ssh/config のホストエイリアスで設定する。環境変数
# REMOTE で上書きできる(既定: rpi5-rdma-target)。
#
#   Host rpi5-rdma-target
#       HostName  <OptiPlex の IP>
#       User      <ユーザ名>
#       IdentityFile ~/.ssh/<鍵>
#
exec ssh "${REMOTE:-rpi5-rdma-target}" "$@"
