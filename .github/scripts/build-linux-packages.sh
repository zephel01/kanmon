#!/usr/bin/env bash
# Linux のパッケージを dist/ に作る（release.yml・ci.yml から呼ぶ）。
#   build-linux-packages.sh deb   … ubuntu-22.04 で。libpcap.so.0.8（Debian 系の名前）にリンクする
#   build-linux-packages.sh rpm   … almalinux:9 のコンテナで。libpcap.so.1（Fedora・RHEL 系の名前）にリンクする
# libpcap のライブラリの名前が Debian 系と Fedora・RHEL 系で違うので、別々の環境でビルドする。
# 前提：cargo build --release -p kanmond -p kanmonctl 済み、cargo-deb・cargo-generate-rpm が入っている。
# 版は Cargo.toml の [workspace.package] から読む。rpm の版には - が使えないので ~ にする
# （0.5.0-beta.1 → 0.5.0~beta.1。~ は正式版より前に並ぶ）
set -euo pipefail
kind=${1:?deb か rpm}
ver=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -1)
mkdir -p dist
case "$kind" in
  deb)
    cargo deb -p kanmond --no-build
    cp target/debian/*.deb dist/
    ;;
  rpm)
    cargo generate-rpm -p crates/kanmond --set-metadata "version = \"${ver//-/\~}\""
    cp target/generate-rpm/*.rpm dist/
    ;;
  *) echo "deb か rpm" >&2; exit 2 ;;
esac
(cd dist && sha256sum ./*."$kind" | sed 's#  \./#  #' > "SHA256SUMS-$kind.txt" && cat "SHA256SUMS-$kind.txt")
