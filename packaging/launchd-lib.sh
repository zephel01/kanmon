# shellcheck shell=bash
# launchd のジョブを入れ替える共通の関数（install-macos.sh・macos/install-app.sh から source する）。
#
# `launchctl bootout` は終わるのを待たずに戻るため、直後の `bootstrap` が
# 「Bootstrap failed: 5: Input/output error」で失敗することがある（v0.2.3 で発生）。
# ここでは、止まりきるのを待ってから登録し、失敗したら何度かやり直す。
# すでに登録済みで失敗した場合は、登録し直さずに kickstart -k で再起動する。

# launchd_stop <domain> <label>   例：launchd_stop system com.kanmon.kanmond
launchd_stop() {
  local domain=$1 label=$2
  launchctl print "$domain/$label" >/dev/null 2>&1 || return 0
  launchctl bootout "$domain/$label" 2>/dev/null || true
  for _ in $(seq 1 30); do
    launchctl print "$domain/$label" >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  echo "警告: $label が 15 秒たっても止まりません。続けます" >&2
}

# launchd_start <domain> <label> <plist> <process-name>
launchd_start() {
  local domain=$1 label=$2 plist=$3 proc=$4 err
  err=$(mktemp)
  for _ in 1 2 3 4 5; do
    if launchctl bootstrap "$domain" "$plist" 2>"$err"; then
      break
    fi
    if launchctl print "$domain/$label" >/dev/null 2>&1; then
      # 登録は済んでいる（前の bootstrap が遅れて効いた等）。再起動だけする
      launchctl kickstart -k "$domain/$label" 2>/dev/null || true
      break
    fi
    sleep 1
  done
  if ! launchctl print "$domain/$label" >/dev/null 2>&1; then
    echo "エラー: $label を launchd に登録できません（$(cat "$err")）" >&2
    echo "  システム設定 → 一般 → ログイン項目と機能拡張 で、バックグラウンドでの実行が許可されているか確認してください" >&2
    rm -f "$err"
    return 1
  fi
  rm -f "$err"
  for _ in $(seq 1 20); do
    if pgrep -x "$proc" >/dev/null; then
      echo "$proc を起動しました（pid $(pgrep -x "$proc" | head -1)）"
      return 0
    fi
    sleep 0.5
  done
  echo "エラー: $label は登録されましたが、$proc が起動していません" >&2
  return 1
}
