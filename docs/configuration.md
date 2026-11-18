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

## CLI（kanmonctl）
| コマンド | 用途 |
|---|---|
| `kanmonctl alerts [--hours 24]` | 直近の警告を、理由の説明付きで表示（見逃した通知の確認） |
| `kanmonctl tail -f --min-level notice` | イベントを流しながら見る |
| `kanmonctl status` | 直近のレベル別件数と、スコア上位のイベント |
| `kanmonctl beacon --min 0.5` | ビーコン（周期的な通信）の候補 |
| `kanmonctl check --detections DIR [--extra FILE]` | 検知ルールの検証 |
| `kanmonctl replay --events FILE --detections DIR [--only ID]` | 過去ログに検知ルールを当て直す |

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
