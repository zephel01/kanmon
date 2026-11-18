#!/usr/bin/env bash
# macOS へ導入（sudo）。cargo build --release 済みの前提。
# 旧名 netmon が入っている場合は、設定・拒否リスト・DB（学習期間とベースライン）を引き継ぎ、
# 旧デーモンを止めて旧バイナリと plist を外す。旧データと旧ログは消さずに残す。
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "sudo で実行してください"; exit 1; }
# P はテスト用の接頭辞（通常は空）。例：KANMON_PREFIX=/tmp/macroot で疑似環境に入れる
P="${KANMON_PREFIX:-}"
B="$P/Library/Application Support/kanmon"
install -d -m 0755 "$B" "$B/etc" "$B/etc/detections" $P/Library/Logs/kanmon $P/usr/local/sbin $P/usr/local/bin

# ---- 旧 netmon からの移行
OLD="$P/Library/Application Support/netmon"
if [ -f $P/Library/LaunchDaemons/com.netmon.netmond.plist ] || [ -d "$OLD" ]; then
  echo "旧 netmon を検出。移行します"
  launchctl bootout system/com.netmon.netmond 2>/dev/null || true
  if [ -f "$OLD/etc/netmon.toml" ] && [ ! -f "$B/etc/kanmon.toml" ]; then
    sed -e 's#Application Support/netmon#Application Support/kanmon#g' -e 's#Logs/netmon#Logs/kanmon#g' \
        -e 's#/etc/netmon#/etc/kanmon#g' -e 's#/var/lib/netmon#/var/lib/kanmon#g' -e 's#/var/log/netmon#/var/log/kanmon#g' \
        "$OLD/etc/netmon.toml" > "$B/etc/kanmon.toml"
    chown root:wheel "$B/etc/kanmon.toml"; chmod 0644 "$B/etc/kanmon.toml"
    echo "  設定を引き継ぎ: kanmon.toml"
  fi
  for f in blocklist.txt rules.json; do
    if [ -f "$OLD/etc/$f" ] && [ ! -f "$B/etc/$f" ]; then
      install -o root -g wheel -m 0644 "$OLD/etc/$f" "$B/etc/$f"; echo "  引き継ぎ: $f"
    fi
  done
  if [ -f "$OLD/netmon.db" ] && [ ! -f "$B/kanmon.db" ]; then
    for ext in "" -wal -shm; do
      [ -f "$OLD/netmon.db$ext" ] && cp -p "$OLD/netmon.db$ext" "$B/kanmon.db$ext"
    done
    echo "  DB を引き継ぎ（学習期間・ベースライン）"
  fi
  if [ -d "$OLD/feeds" ] && [ ! -d "$B/feeds" ]; then
    cp -Rp "$OLD/feeds" "$B/feeds"
  fi
  rm -f $P/Library/LaunchDaemons/com.netmon.netmond.plist $P/usr/local/sbin/netmond $P/usr/local/bin/netmonctl
  echo "  旧デーモン・旧バイナリを外しました。旧データは $OLD と $P/Library/Logs/netmon に残しています"
  echo "  （確認後に手動で削除: sudo rm -rf \"$OLD\" $P/Library/Logs/netmon）"
fi

install -m 0755 target/release/kanmond $P/usr/local/sbin/kanmond
install -m 0755 target/release/kanmonctl $P/usr/local/bin/kanmonctl
install -o root -g wheel -m 0644 detections/*.yaml "$B/etc/detections/"
[ -f "$B/etc/kanmon.toml" ] || install -o root -g wheel -m 0644 packaging/kanmon.toml "$B/etc/kanmon.toml"
[ -f "$B/etc/blocklist.txt" ] || install -o root -g wheel -m 0644 /dev/null "$B/etc/blocklist.txt"
install -o root -g wheel -m 0644 packaging/com.kanmon.kanmond.plist $P/Library/LaunchDaemons/com.kanmon.kanmond.plist
launchctl bootout system/com.kanmon.kanmond 2>/dev/null || true
launchctl bootstrap system $P/Library/LaunchDaemons/com.kanmon.kanmond.plist
echo "導入完了。確認: sudo tail -f $P/Library/Logs/kanmon/kanmond.log / sudo kanmonctl alerts --file $P/Library/Logs/kanmon/events.jsonl"
