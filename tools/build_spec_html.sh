#!/usr/bin/env bash
# SPEC.md -> docs/spec.html(左に章ナビゲーションを置いた HTML 版)。
#
# **SPEC.md を直したらこれを実行して docs/spec.html を作り直すこと。**
# 変換は tools/spec_md2html.py(SPEC.md で使っている記法だけを扱う小さな実装)。
# 体裁は tools/spec_template.html。
#
#   wsl -e bash -lc "/mnt/c/Users/fukud/Documents/vfio_nvme/tools/build_spec_html.sh"
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$ROOT/tools/spec_md2html.py" "$ROOT/SPEC.md" "$ROOT/docs/spec.html" "$ROOT/tools/spec_template.html"
