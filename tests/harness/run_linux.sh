#!/usr/bin/env bash
# Linux 用の動作確認ハーネス（設計書 §21 の安全な方法のみ）。root で実行。
# 宛先は文書用 IP（RFC 5737：198.51.100.0/24, 203.0.113.0/24）とローカルのみ。
# 実在のマルウェアや第三者のサーバーは使わない。
#
# usage: sudo tests/harness/run_linux.sh [kanmond のパス] [kanmonctl のパス]
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
KANMOND=${1:-$ROOT/target/release/kanmond}
KANMONCTL=${2:-$ROOT/target/release/kanmonctl}
W=$(mktemp -d /tmp/kanmon-harness.XXXXXX)
chmod 755 "$W"
echo "work: $W"

# ---- 設定（observe モード・ビーコン集計 10 秒ごと・偽 ntfy へ送信）
mkdir -p "$W/etc/detections" "$W/data"
install -m 0644 "$ROOT"/detections/*.yaml "$W/etc/detections/"
echo "198.51.100.0/24" > "$W/etc/blocklist.txt"
chmod 0644 "$W/etc/blocklist.txt"
cat > "$W/etc/kanmon.toml" <<EOF
mode = "observe"
interval_ms = 200
data_dir = "$W/data"
detections_dir = "$W/etc/detections"
rules_file = "$W/etc/rules.json"
strict_owner = true
local_blocklists = ["$W/etc/blocklist.txt"]
beacon_interval_s = 10
feeds = []
[jsonl]
path = "$W/events.jsonl"
[notify]
local = false
min_level = "notice"
ntfy_url = "http://127.0.0.1:18090"
ntfy_topic = "kanmon-harness"
EOF

# ---- 偽 ntfy（受け取った JSON を保存するだけ）
python3 - "$W/ntfy.jsonl" <<'PY' &
import http.server, sys
out = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        with open(out, "ab") as f:
            f.write(self.rfile.read(n) + b"\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 18090), H).serve_forever()
PY
NTFY=$!

gcc -O2 -o "$W/netclient" "$ROOT/tests/harness/netclient.c"

"$KANMOND" --config "$W/etc/kanmon.toml" 2> "$W/kanmond.log" &
D=$!
cleanup() { kill $D $NTFY 2>/dev/null || true; }
trap cleanup EXIT
sleep 2   # 初回スナップショット（既存の通信）

echo "[A] /tmp の未署名バイナリ → 拒否リスト宛（S1 S2 S3 S4）"
cp "$W/netclient" /tmp/updater-kanmon-test
/tmp/updater-kanmon-test 198.51.100.7 443 1 0 1500
rm -f /tmp/updater-kanmon-test

echo "[B] 0.0.0.0 で新規待受（S15）"
python3 -m http.server 18081 --bind 0.0.0.0 >/dev/null 2>&1 &
P=$!; sleep 1.5; kill $P

echo "[C] 実行中に削除された隠しファイル（S5）"
cp "$W/netclient" "$W/.hidden-del"
"$W/.hidden-del" 203.0.113.5 443 1 0 2500 &
P=$!; sleep 0.5; rm -f "$W/.hidden-del"; wait $P

echo "[D] raw ソケット（S17）"
python3 -c "import socket,time; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); time.sleep(1.5)" \
  || echo "  (raw socket を作れない環境)"

echo "[G] 開発サーバーを 0.0.0.0:8888 で公開（D3）"
python3 -m http.server 8888 --bind 0.0.0.0 >/dev/null 2>&1 &
P=$!; sleep 1.5; kill $P

echo "[H] パッケージマネージャ（npm を名乗るスクリプト）配下の python が外へ（D4）"
cat > "$W/npm" <<'SH'
#!/bin/bash
# インストールスクリプトが外へ接続する想定（接続を 1.5 秒保持して、収集間隔より長くする）
python3 -c "import socket,time; s=socket.create_connection(('203.0.113.50',443),3); time.sleep(1.5)" || true
SH
chmod +x "$W/npm"; "$W/npm"

echo "[E] 疑似ビーコン：1 秒周期 × 10 回（S7）"
"$W/netclient" 203.0.113.20 443 10 1000 500
sleep 12  # ビーコン集計を待つ

kill $D; wait $D 2>/dev/null || true
sleep 0.5

echo
echo "==== kanmonctl tail（notice 以上）"
"$KANMONCTL" tail --file "$W/events.jsonl" --min-level notice --lines 200
echo
echo "==== kanmonctl alerts（新しい 2 件）"
"$KANMONCTL" alerts --file "$W/events.jsonl" --limit 2
echo
echo "==== kanmonctl beacon"
"$KANMONCTL" beacon --db "$W/data/kanmon.db" --min 0.0 | head -5
echo
echo "==== 判定"
python3 - "$W/events.jsonl" "$W/ntfy.jsonl" <<'PY'
import json, sys
evs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
def sig(e): return {s["id"] for s in e["kanmon"]["signals"]}
def find(pred): return [e for e in evs if pred(e)]
ok = True
def check(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name)
    ok &= bool(cond)
a = find(lambda e: e["process"].get("executable","").startswith("/tmp/updater-kanmon-test"))
check("A: S1+S2+S3+S4, critical", a and {"S1","S2","S3","S4"} <= sig(a[0]) and a[0]["kanmon"]["level"] == "critical")
b = find(lambda e: e["network"]["kind"] == "listen" and e.get("source",{}).get("port") == 18081)
check("B: listen 18081 に S15", b and "S15" in sig(b[0]) and b[0]["process"].get("script") == "module:http.server")
c = find(lambda e: (e["process"].get("executable") or "").endswith("/.hidden-del"))
check("C: S5（hidden または deleted）", c and "S5" in sig(c[0]))
d = find(lambda e: e["network"]["kind"] == "raw_socket")
check("D: raw_socket に S17（作れた場合）", (not d) or "S17" in sig(d[0]))
bc = find(lambda e: e["network"]["kind"] == "beacon_report" and e["kanmon"].get("dest_key","").startswith("203.0.113."))
check("E: beacon_report（S7/S7m と S7x）", bc and (sig(bc[0]) & {"S7","S7m"}) and "S7x" in sig(bc[0]))
try:
    n = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
except FileNotFoundError:
    n = []
check("ntfy に通知が届いた（critical を含む）", any(x.get("priority") == 5 for x in n))
check("通知本文に理由の説明が入っている", any("脅威インテル（既知の悪性" in x.get("message","") for x in n))
g = find(lambda e: e["network"]["kind"] == "listen" and e.get("source",{}).get("port") == 8888)
check("G: 0.0.0.0:8888 の待受に D3", g and "D3" in sig(g[0]))
hh = find(lambda e: e["network"]["kind"] == "connect" and "npm" in e["process"].get("parent_chain", []))
check("H: npm 配下の python に D4", hh and "D4" in sig(hh[0]))
print("RESULT:", "OK" if ok else "NG")
sys.exit(0 if ok else 1)
PY
