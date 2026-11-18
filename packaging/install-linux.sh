#!/usr/bin/env bash
# Linux へ導入（root）。cargo build --release 済みの前提。
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "root で実行してください"; exit 1; }
install -d -m 0755 /etc/kanmon /etc/kanmon/detections
install -d -m 0750 /var/lib/kanmon /var/log/kanmon
install -m 0755 target/release/kanmond /usr/local/sbin/kanmond
install -m 0755 target/release/kanmonctl /usr/local/bin/kanmonctl
install -o root -g root -m 0644 detections/*.yaml /etc/kanmon/detections/
[ -f /etc/kanmon/kanmon.toml ] || install -o root -g root -m 0644 packaging/kanmon.toml /etc/kanmon/kanmon.toml
[ -f /etc/kanmon/blocklist.txt ] || install -o root -g root -m 0644 /dev/null /etc/kanmon/blocklist.txt
install -m 0644 packaging/kanmond.service /etc/systemd/system/kanmond.service
systemctl daemon-reload
systemctl enable --now kanmond
echo "導入完了。確認: journalctl -u kanmond -f / kanmonctl tail -f"
