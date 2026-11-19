#!/usr/bin/env bash
# packaging/build-check.sh の確認：版が合えば通し、違う・無いときは止める（root 不要）
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=packaging/build-check.sh
. packaging/build-check.sh
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/target/release"
printf '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "9.9.9"\n\n[workspace.dependencies]\nversion = "0"\n' > "$T/Cargo.toml"
fake() { printf '#!/bin/sh\necho "%s %s"\n' "$1" "$2" > "$T/target/release/$1"; chmod +x "$T/target/release/$1"; }
fail=0
ok() { if "$@" 2>/dev/null; then echo "PASS"; else echo "FAIL: $*"; fail=1; fi; }
ng() { if "$@" 2>/dev/null; then echo "FAIL（止まるはず）: $*"; fail=1; else echo "PASS"; fi; }

fake kanmond 9.9.9
ng check_build_version "$T"            # kanmonctl が無い
fake kanmonctl 9.9.9
ok check_build_version "$T"            # 両方とも同じ版
fake kanmond 0.2.5
ng check_build_version "$T"            # 古いバイナリ
fake kanmond 9.9.9
fake kanmonctl 9.9.10
ng check_build_version "$T"            # 片方だけ違う
# 実際のリポジトリの Cargo.toml から版を読めること
v=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)
if [ -n "$v" ]; then echo "PASS（リポジトリの版 $v）"; else echo "FAIL: 版を読めない"; fail=1; fi
[ "$fail" = 0 ] && echo "RESULT: OK" || { echo "RESULT: NG"; exit 1; }
