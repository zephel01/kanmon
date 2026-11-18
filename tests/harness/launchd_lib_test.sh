#!/usr/bin/env bash
# packaging/launchd-lib.sh の動作確認（launchctl・pgrep を差し替えて、どの OS でも動く）。
#   A) bootout が遅れて効く＋bootstrap が「5: Input/output error」で失敗するが、実は登録済み → kickstart で起動
#   B) 登録が許可されない（バックグラウンドでの実行がオフ等） → エラーで終わる
#   C) 何も動いていない状態からの通常の登録
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
T=$(mktemp -d)
cat > "$T/launchctl" <<'SH'
#!/usr/bin/env bash
S="$STATE"
echo "$*" >> "$S/calls"
case "$1" in
  print)
    if [ -f "$S/stopping" ]; then n=$(cat "$S/stopping"); [ "$n" -gt 0 ] && { echo $((n-1)) > "$S/stopping"; exit 0; }; rm -f "$S/stopping" "$S/loaded"; fi
    [ -f "$S/loaded" ] && exit 0 || exit 113 ;;
  bootout) [ -f "$S/loaded" ] && echo 3 > "$S/stopping"; exit 0 ;;
  bootstrap)
    [ -f "$S/deny" ] && { echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; }
    if [ -f "$S/race" ]; then rm -f "$S/race"; touch "$S/loaded"; echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; fi
    touch "$S/loaded" "$S/running"; exit 0 ;;
  kickstart) touch "$S/running"; exit 0 ;;
esac
SH
cat > "$T/pgrep" <<'SH'
#!/usr/bin/env bash
[ -f "$STATE/running" ] && { echo 4242; exit 0; } || exit 1
SH
cat > "$T/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$T/launchctl" "$T/pgrep" "$T/sleep"
ok=1
run() { # name setup expect_rc
  local S="$T/$1"; mkdir -p "$S"; eval "$2"
  ( export STATE="$S" PATH="$T:$PATH"; . packaging/launchd-lib.sh
    launchd_stop system com.kanmon.kanmond && launchd_start system com.kanmon.kanmond /x.plist kanmond ) >"$S/out" 2>&1
  local rc=$?
  if [ "$rc" = "$3" ]; then echo "PASS $1（rc=$rc）"; else echo "FAIL $1（rc=$rc、期待 $3）"; cat "$S/out"; ok=0; fi
}
run A_race 'touch "$S/loaded" "$S/race"' 0
grep -q kickstart "$T/A_race/calls" && echo "PASS A_race: kickstart に切り替えた" || { echo "FAIL A_race: kickstart していない"; ok=0; }
run B_denied 'touch "$S/deny"' 1
grep -q "ログイン項目と機能拡張" "$T/B_denied/out" && echo "PASS B_denied: 対処の案内を出した" || { echo "FAIL B_denied: 案内が無い"; ok=0; }
run C_fresh ':' 0
rm -rf "$T"
[ $ok = 1 ] && echo "RESULT: OK" || { echo "RESULT: NG"; exit 1; }
