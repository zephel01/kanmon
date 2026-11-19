#!/bin/sh
# パッケージを入れて、置かれたものを確かめ、外す（ci.yml がコンテナの中で呼ぶ）。
#   check-installed.sh deb|rpm   （/dist にパッケージがあること）
set -eu
kind=$1
# ミラーへの接続が一時的に切れることがある（2026-11-19 に archive.ubuntu.com で失敗）ので、待ち時間を区切って取り直す
APT="-o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30"
if [ "$kind" = deb ]; then
  n=0
  until apt-get $APT update -qq; do
    n=$((n + 1)); [ "$n" -ge 3 ] && exit 1
    echo "apt-get update に失敗。${n} 回目の取り直し" >&2; sleep 10
  done
  apt-get $APT install -y -qq /dist/*.deb
  unit=/lib/systemd/system/kanmond.service
else
  dnf install -y -q --setopt=retries=5 --setopt=timeout=30 /dist/*.rpm
  unit=/usr/lib/systemd/system/kanmond.service
fi
# 起動できる（共有ライブラリ・glibc の版が足りる）
kanmond --version
kanmonctl --version
ldd /usr/sbin/kanmond | grep -E "pcap|not found"
if ldd /usr/sbin/kanmond | grep -q "not found"; then echo "足りないライブラリがある" >&2; exit 1; fi
test -f /etc/kanmon/kanmon.toml
test "$(ls /etc/kanmon/detections/*.yaml | wc -l)" -ge 10
grep -q "^ExecStart=/usr/sbin/kanmond" "$unit"
test -d /var/lib/kanmon
# 設定は利用者の書き換えが更新・削除で消えない
echo "# local edit" >> /etc/kanmon/kanmon.toml
if [ "$kind" = deb ]; then
  dpkg -s kanmon | grep -q "Status: install ok installed"
  apt-get remove -y -qq kanmon
else
  rpm -V kanmon || true
  dnf remove -y -q kanmon
fi
grep -q "# local edit" /etc/kanmon/kanmon.toml* 2>/dev/null || ls /etc/kanmon/
test ! -e /usr/sbin/kanmond
echo "OK: $kind"
