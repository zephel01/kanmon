#!/usr/bin/env bash
# Kanmon.app（メニューバーアプリ）を組み立てる。macOS 13 以降・Xcode（Command Line Tools）が必要。
#   macos/build-app.sh                 → 仮の署名（ad-hoc）。自分の Mac で使う分にはこれで動く
#   KANMON_SIGN_IDENTITY="Developer ID Application: …" macos/build-app.sh
#                                      → Developer ID で署名（Hardened Runtime・タイムスタンプ付き）
# 出力：macos/build/Kanmon.app
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd .. && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
SIGN_ID=${KANMON_SIGN_IDENTITY:--}

( cd KanmonBar && swift build -c release )
BIN="$(cd KanmonBar && swift build -c release --show-bin-path)/KanmonBar"

APP="build/Kanmon.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/KanmonBar"
sed "s/__VERSION__/$VERSION/g" KanmonBar/Resources/Info.plist > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null

if [ "$SIGN_ID" = "-" ]; then
  codesign --force --sign - "$APP"
else
  codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$APP"
fi
codesign --verify --strict --verbose=1 "$APP"
echo "作成：$(pwd)/${APP}（version ${VERSION}、署名：${SIGN_ID}）"
