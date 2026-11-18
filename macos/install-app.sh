#!/usr/bin/env bash
# Kanmon.app を /Applications に置き、ログイン時に自動起動する（sudo 不要・自分のユーザーで実行）。
# 先に macos/build-app.sh で組み立てておくこと。
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" != 0 ] || { echo "sudo を付けずに、普段のユーザーで実行してください"; exit 1; }
SRC="build/Kanmon.app"
[ -d "$SRC" ] || { echo "$SRC がありません。先に macos/build-app.sh を実行してください"; exit 1; }

DEST="/Applications/Kanmon.app"
LABEL="com.kanmon.bar"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
pkill -x KanmonBar 2>/dev/null || true
rm -rf "$DEST"
ditto "$SRC" "$DEST"

mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$DEST/Contents/MacOS/KanmonBar</string></array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <!-- ログイン項目に Kanmon の名前とアイコンで表示させる（macOS 13 以降） -->
  <key>AssociatedBundleIdentifiers</key><array><string>io.github.zephel01.kanmon</string></array>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
</plist>
PL
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "導入完了：メニューバーに盾のアイコンが出ます。止めるには launchctl bootout gui/$(id -u)/$LABEL"
