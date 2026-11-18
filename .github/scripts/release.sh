#!/usr/bin/env bash
# main への push のたびに実行（.github/workflows/release.yml）。
#   1) Cargo.toml のバージョン v<版> のタグが無く、CHANGELOG に [<版>] の節があれば、HEAD に注釈付きタグを付ける
#   2) CHANGELOG にある各版のうち、タグがあってリリースが無いものを、その節を本文にしてリリースする
#      版に - が付くもの（0.4.0-beta.1 等）はプレリリースにする
#   配布物（Windows の zip、Linux の .deb・.rpm）は release.yml の別のジョブが作って上げる
# バージョンを上げない PR（ドキュメントの修正など）では何もしない。
set -euo pipefail

ver=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -1)
[ -n "$ver" ] || { echo "Cargo.toml からバージョンを読めません" >&2; exit 1; }

# CHANGELOG の「## [版] ...」から次の「## [」までを出す（見出しは含めない）
notes() {
  awk -v v="$1" '
    index($0, "## [" v "]") == 1 { f = 1; next }
    /^## \[/ { if (f) exit }
    f { print }
  ' CHANGELOG.md
}

has_tag() { git rev-parse -q --verify "refs/tags/v$1" >/dev/null; }

if ! has_tag "$ver"; then
  if [ -z "$(notes "$ver" | tr -d '[:space:]')" ]; then
    echo "CHANGELOG.md に [$ver] の節が無いので、タグは付けません"
  else
    git config user.name "github-actions[bot]"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
    git tag -a "v$ver" -m "kanmon v$ver"
    git push origin "v$ver"
    echo "タグ v$ver を付けました（$(git rev-parse --short HEAD)）"
  fi
fi

# 古い版から順に（最新の判定を GitHub に任せるため）
for v in $(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?\]' CHANGELOG.md | tr -d '#[] ' | sort -V); do
  has_tag "$v" || continue
  if gh release view "v$v" >/dev/null 2>&1; then
    continue
  fi
  notes "$v" > "${RUNNER_TEMP:-/tmp}/notes-$v.md"
  pre=()
  case "$v" in *-*) pre=(--prerelease) ;; esac
  gh release create "v$v" --title "kanmon v$v" --notes-file "${RUNNER_TEMP:-/tmp}/notes-$v.md" --verify-tag "${pre[@]}"
  echo "リリース v$v を作りました"
done
