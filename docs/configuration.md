# 設定・CLI・許可ルール

## 設定ファイル
| OS | パス |
|---|---|
| Linux | `/etc/kanmon/kanmon.toml` |
| macOS | `/Library/Application Support/kanmon/etc/kanmon.toml` |

すべての項目に既定値があります。全項目の説明は [packaging/kanmon.toml](../packaging/kanmon.toml) を見てください。よく変える項目は次のとおりです。

| 項目 | 既定値 | 内容 |
|---|---|---|
| `mode` / `learning_days` | `learning` / 7 | 導入直後の学習期間。この間はベースラインを作り、warn 以上だけを通知する |
| `interval_ms` | 500 | 収集の間隔。短くすると短命な接続を拾いやすくなるが、CPU を使う |
| `[notify] alert_level` | `warn` | このレベル以上を「閉じるまで残る警告」にする |
| `[notify] ntfy_url` / `ntfy_topic` | 空 | ntfy で外部にも通知する（情報のみ。遠隔から許可する機能はない） |
| `[notify] heartbeat_url` | 空 | 死活監視の push URL（healthchecks.io・Uptime Kuma 等）。kanmon が止められたことを外側で検知させる |
| `local_blocklists` | `blocklist.txt` | 改行区切りの拒否リスト（IP・CIDR・ドメイン） |
| `[[feeds]]` | Feodo・Spamhaus DROP | 脅威インテルのフィード。https のみ、日次で更新 |
| `status_socket` | macOS `/var/run/kanmond.sock`、Linux `/run/kanmon/kanmond.sock` | 状態ソケット（読み取り専用）。メニューバーアプリが使う。空文字で無効 |
| `status_allowed_uids` | 空 | 状態ソケットへの接続を追加で許す uid。root とログイン中のユーザーは常に許可 |
| `[notify] defer_to_app` | true | メニューバーアプリが動いている間は、ダイアログとバナーをアプリに任せる（ntfy は送る） |
| `[dns] enabled` | true | DNS 応答と TLS の SNI を受け身で読み、宛先にドメイン名を付ける。DNS の設定は変えない。libpcap が必要 |
| `[dns] interfaces` | 空（自動） | 読むインターフェース。Linux は `any`、macOS は稼働中の全インターフェース（lo0・en*・utun*。60 秒ごとに増えたものを足す） |
| `[dns] hosts_path` / `resolv_conf` | `/etc/hosts` / `/etc/resolv.conf` 等 | hosts と DNS サーバー設定の監視対象（macOS の DNS サーバーは `scutil --dns` で読む） |
| `[dns] check_interval_s` | 60 | hosts・DNS サーバー設定を確かめる間隔 |
| `[dns] crosscheck` / `doh_url` | true / Cloudflare | 監視リストのドメインを DoH で引き直して照合する。外へ問い合わせるのは監視リストのドメインだけで、同じドメインは 30 分に 1 回まで。https のみ |
| `[dns] watch_domains` | パッケージ配布元・GitHub・AI ベンダー等 | 書き換え・食い違いを重く見るドメイン（サブドメインも含む） |
| `[volume] interval_s` / `window_s` / `min_report_kb` | 10 / 600 / 1024 | 送信量を読む間隔、合計する窓（秒）、報告する最小量（KB）。macOS は nettop、Linux は sock_diag で読む |
| `[persistence] roots` / `interval_s` / `max_depth` / `system` | `["~/kanmon-work"]` / 3600 / 6 / true | 居座りの走査。`~/` はログイン中のユーザーのホーム。`node_modules` 等は潜らない。初回は基準の記録だけで、以後は追加・変更をイベントにする |
| `[jsonl] rotate` / `keep_days` | `size` / 30 | `daily` にすると `events.YYYY-MM-DD.jsonl` に日付ごとに切り替え、`keep_days` 日残す（同じ日に `max_mb` を超えたら番号付き） |
| `[log] path` / `keep_days` | macOS `/Library/Logs/kanmon/kanmond.log`、Linux 空（journald） / 14 | kanmond の動作ログ。日付が変わると `kanmond.YYYY-MM-DD.log` に切り替え、`keep_days` 日残す |
| `[dns] private_ok_suffixes` | 空 | プライベート IP に解決されても知らせない接尾辞（社内ドメイン等）。`.local`・`.test`・`ts.net` 等は最初から対象外 |

## 更新・起動・停止
### 更新（macOS）
```bash
cd ~/works/security/kanmon && git pull
cargo build --release
sudo packaging/install-macos.sh             # kanmond を入れ替えて再起動（設定ファイルは残す）
macos/build-app.sh && macos/install-app.sh  # Kanmon.app を入れ替えて再起動（sudo 不要）
```
Linux は `sudo packaging/install-linux.sh`。どちらも、動いている古い方を止めてから新しい方を起動します。検知ルール（YAML）だけを変えたときは再起動は要りません（5 秒以内に読み直します）。

### kanmond（デーモン）
| 操作 | macOS | Linux |
|---|---|---|
| 状態 | `sudo launchctl print system/com.kanmon.kanmond \| grep -E "state\|pid"` | `systemctl status kanmond` |
| 再起動 | `sudo launchctl kickstart -k system/com.kanmon.kanmond` | `sudo systemctl restart kanmond` |
| 停止 | `sudo launchctl bootout system/com.kanmon.kanmond` | `sudo systemctl stop kanmond` |
| 起動 | `sudo launchctl bootstrap system /Library/LaunchDaemons/com.kanmon.kanmond.plist` | `sudo systemctl start kanmond` |
| ログ | `/Library/Logs/kanmon/kanmond.log`（前の日は `kanmond.YYYY-MM-DD.log`。起動直後の失敗は `kanmond.stderr.log`） | `journalctl -u kanmond` |

### うまく起動しないとき（macOS）
- メニューが「kanmond が応答しません」：`pgrep -lx kanmond` でプロセスを確認。無ければ `sudo launchctl print system/com.kanmon.kanmond` で登録を確認する
- `Bootstrap failed: 5: Input/output error`：すでに登録済みのことが多い。`sudo launchctl kickstart -k system/com.kanmon.kanmond` で再起動する。登録されていないのにこのエラーになる場合は、システム設定 → 一般 → ログイン項目と機能拡張 で、バックグラウンドでの実行が許可されているかを見る
- 起動直後に落ちる：`/Library/Logs/kanmon/kanmond.stderr.log` を見る

### Kanmon.app（メニューバー、macOS）
| 操作 | コマンド |
|---|---|
| 起動 | `open /Applications/Kanmon.app` |
| 終了 | メニューの「終了」（ログイン時の自動起動は残る） |
| 自動起動をやめる | `launchctl bootout gui/$(id -u)/com.kanmon.bar` |

## CLI（kanmonctl）
| コマンド | 用途 |
|---|---|
| `kanmonctl alerts [--hours 24]` | 直近の警告を、理由の説明付きで表示（見逃した通知の確認） |
| `kanmonctl tail -f --min-level notice` | イベントを流しながら見る |
| `kanmonctl status` | 直近のレベル別件数と、スコア上位のイベント |
| `kanmonctl beacon --min 0.5` | ビーコン（周期的な通信）の候補 |
| `kanmonctl check --detections DIR [--extra FILE]` | 検知ルールの検証 |
| `kanmonctl replay --events FILE --detections DIR [--only ID]` | 過去ログに検知ルールを当て直す |
| `kanmonctl scan [--root DIR] [--system] [--risky] [--json]` | 居座りの走査（Claude Code のフック、VS Code の folderOpen、`.pth`、Git のフック、自動起動等）。読むだけ。既定は `~/kanmon-work`。`sudo` 不要 |

ログは root 専用なので、通常は `sudo` を付けて実行します。netmon 時代のログ（`netmon.*` 欄）も自動で読み替えます。

## 許可・拒否ルール（rules.json）
設定ディレクトリの `rules.json` に配列で書きます。v0.1 は通信を止めないので、一致したときの扱いは次のとおりです。

| action | 扱い |
|---|---|
| `allow` | 通知を抑える |
| `deny` | `would_deny` として、最低でも warn で通知する |

脅威インテルに一致した通信は、allow より優先します。

```json
[{"id":"vscode-github","action":"allow","direction":"outbound",
  "process":{"match":"signature","team_id":"UBF8T346G9","signing_id":"com.microsoft.VSCode"},
  "remote":{"cidrs":["140.82.112.0/20"],"ports":[443],"protocol":"tcp"}}]
```
- `process.match` に指定できるもの：`signature` / `package` / `hash` / `path` / `any`
- 複数のルールに一致した場合は、具体的なルールを優先します（プロセス指定 ＞ 宛先指定 ＞ ポート指定）。同じ具体度なら deny を優先します。
- 有効期限を付けられます：`"lifetime":{"kind":"until","until":"2026-12-31T00:00:00+09:00"}`

## メニューバーアプリ（macOS）
```bash
macos/build-app.sh      # macos/build/Kanmon.app を作る（仮の署名）
macos/install-app.sh    # /Applications に置き、ログイン時に自動起動（sudo 不要）
```
- 3 秒ごとに状態ソケットを読み、アイコンの色を変えます：緑＝正常、黄＝未読の notice、赤＝未読の warn / critical、灰＝kanmond に接続できない（停止させられた可能性）
- 新しい warn 以上の警告は、閉じるまで残る詳細ウィンドウで出します。メニューから直近 10 件を開けます
- 「既読にする」でアイコンを緑に戻します
- Developer ID で署名するには `KANMON_SIGN_IDENTITY="Developer ID Application: …" macos/build-app.sh` を使います

## 保存先
| 種類 | Linux | macOS |
|---|---|---|
| イベント（JSONL、ECS 互換の項目名） | `/var/log/kanmon/events.jsonl` | `/Library/Logs/kanmon/events.jsonl` |
| DB（SQLite） | `/var/lib/kanmon/kanmon.db` | `/Library/Application Support/kanmon/kanmon.db` |
| デーモンのログ | `journalctl -u kanmond` | `/Library/Logs/kanmon/kanmond.log` |
