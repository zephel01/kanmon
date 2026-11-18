# 検知ルールの書き方

kanmon の判定は、すべて `detections/*.yaml` の検知ルールで決まります。新しい手口への対応は、**ルールを 1 ファイル書く → 過去ログで確かめる → 配置する** の 3 手順で行い、再ビルドは要りません。

## 手順
```bash
# 1) 書く（例：examples/detections/60-supply-chain.yaml）
# 2) 文法と既存ルールとの組み合わせを確認
kanmonctl check --detections /etc/kanmon/detections --extra ./my-rule.yaml
# 3) 過去ログに当てて、何件当たるか・誤検知が出ないかを見る
sudo kanmonctl replay --events /var/log/kanmon/events.jsonl \
  --detections /etc/kanmon/detections --extra ./my-rule.yaml --only X2
# 4) 配置（デーモンが 5 秒以内に再読込）
sudo install -o root -m 0644 ./my-rule.yaml /etc/kanmon/detections/
```
- 配置したルールに誤りがあると、デーモンは前のルールのまま動き続け、通知でそのことを知らせます。
- root で動かしている間は、root 所有かつ group/other が書き込めないファイルしか読みません（`strict_owner`）。一般ユーザー権限のマルウェアが「自分の点を下げるルール」を置けないようにするためです。
- ローテーション済みのログ（`events.jsonl.1` 等）も `--events` に渡せます。`-` を渡すと標準入力から読みます。

macOS のパスは `/Library/Application Support/kanmon/etc/detections` と `/Library/Logs/kanmon/events.jsonl` です。

## 書式
```yaml
lists:
  my_hosts: [evil.example, bad.test]
detections:
  - id: X2                      # 一意（重複はエラー）
    name: short_name
    points: 30                  # 負の値で減点
    description: 通知に表示する短い説明（日本語）
    kinds: [connect]            # connect / accept / listen / raw_socket / beacon_report（省略時は全部）
    when:
      all:                      # all / any / not を入れ子にできる
        - { field: destination.registered_domain, op: in, value: "@my_hosts" }
        - not: { field: process.code_signature.status, op: eq, value: apple }
```
- `description` は通知と `kanmonctl alerts` にそのまま表示されます。
- 演算子は次の 15 種類です：`eq` `ne` `in` `not_in` `prefix` `suffix` `contains` `regex` `cidr` `gt` `gte` `lt` `lte` `exists` `missing`。`cidr` は IP アドレスが範囲に含まれるかを判定します（例：`value: ["149.154.160.0/20"]`）。
- `"@名前"` は `lists` の値に展開されます。`ci: true` を付けると大文字・小文字を区別しません。
- フィールドが配列の場合は、どれか 1 つが一致すれば真になります。
- `prefix` の値を `~/` で始めると、`/Users/*/`・`/home/*/`・`/root/` のいずれかに一致します。
- キー名を書き間違えるとエラーになります。

## 点数と動作
| 合計 | レベル | 動作 |
|---|---|---|
| 0–29 | info | 記録のみ |
| 30–59 | notice | 通知 |
| 60–99 | warn | 閉じるまで残る警告（macOS はダイアログ） |
| 100 以上 | critical | 同上（脅威インテルに一致した通信は常にこのレベル） |

導入直後の学習期間（既定 7 日）は、warn 以上だけを通知します。閾値は設定ファイルの `[thresholds]` で変えられます。

## 参照できるフィールド
| フィールド | 内容 |
|---|---|
| `network.kind` / `direction` / `transport` / `scope` | 種別、方向、tcp / udp / raw / packet、loopback / lan / internet / all |
| `process.executable` / `name` / `args` / `user` / `uid` | 実行ファイル、引数、ユーザー |
| `process.code_signature.status` | apple / app_store / developer_id / signed_other / invalid / adhoc / unsigned / package / unmanaged / unknown |
| `process.code_signature.team_id` / `signing_id` / `package` | 署名者、パッケージ名 |
| `process.hash.sha256` / `proc_key` | ハッシュ、安定識別キー |
| `process.parent.name` / `parent_chain` | 親プロセス、親から上へ最大 6 段の実行ファイル名。インタプリタはスクリプト名も入る（`node …/npm-cli.js` → `node`・`npm-cli.js`、`python -m pip` → `pip`） |
| `process.exe_deleted` / `memfd` / `hidden` / `interpreter` / `script` | 削除済み、メモリ上（memfd）、隠しファイル、インタプリタとスクリプト |
| `process.file_age_s` / `first_seen_age_s` | 実行ファイルの更新からの秒数、kanmon が初めて見てからの秒数 |
| `source.ip` / `port`、`destination.ip` / `port` / `domain` / `registered_domain` | 端点（v0.1 では `domain` は空） |
| `kanmon.ti_match` / `ti_source` | 脅威インテルに一致したか、どのリストか |
| `kanmon.dest_first_for_process` / `port_first_for_process` / `listen_new` | ベースラインとの差分（学習期間中は常に false） |
| `kanmon.dga_score` | 自動生成ドメインらしさ（0〜1、ドメインがあるときだけ） |
| `kanmon.beacon.score` / `n` / `median_interval_s` / `mad_s` | ビーコン（`beacon_report` のみ） |

## 同梱ルール
| ID | 内容 | 点 |
|---|---|---|
| S1 | 脅威インテル（既知の悪性 IP・ドメイン）に一致 | +100 |
| S2 / S2b | 未署名・ad-hoc・パッケージ管理外 / 署名の検証に失敗 | +20 / +40 |
| S3 | 実行ファイルが 24 時間以内に作成・更新された | +15 |
| S4 | 一時フォルダ・ダウンロード等から実行 | +25 |
| S5 | 削除済み・memfd・隠しファイル | +35 |
| S6 | 文書・メール・ブラウザの配下でシェル等が通信 | +40 |
| S7 / S7m / S7x | ビーコン（強・中）、信頼できない実行ファイルの周期通信 | +30 / +15 / +20 |
| S9 | 自動生成（DGA）らしいドメイン | +15 |
| S11 / S12 | 非標準ポートを初めて使う / 初めての宛先 | +10 / +10 |
| S14 | ブラウザ以外が DNS を迂回（DoH / DoT） | +15 |
| S15 / S16 / S17 | 新しい待受を外部に公開 / インターネットから着信 / raw ソケット | +25 / +30 / +20 |
| S18 | トンネル・動的 DNS 系ドメイン | +10 |
| T-trusted | Apple 署名・公式パッケージ（curl・bash・ssh 等は除く） | −15 |

### 開発者を狙う手口（`40-developer.yaml`）
| ID | 内容 | 点 |
|---|---|---|
| D1 | 遠隔操作ソフト（AnyDesk・TeamViewer・RustDesk 等）が通信。サポート詐欺で悪用が多い | +40 |
| D2 / D2s | トンネルツール（ngrok・cloudflared・chisel 等）/ SSH のリバーストンネル（`-R`） | +25 / +30 |
| D3 / D3d | 開発・AI サーバー（LiteLLM・Ollama・Jupyter・DB 等）/ デバッガのポートを外部に公開 | +30 / +60 |
| D4 / D4p | パッケージ導入処理（npm・pip・cargo・makepkg 等）の配下から外部へ通信 / 非標準ポートへ通信 | +30 / +20 |
| D5 | スクリプト（node・python 等）がインターネットの非標準ポートへ通信 | +15 |
| D6 | AppleScript（osascript）またはその配下が通信（AMOS 等の情報窃取） | +40 |
| D7 | マイニングプールでよく使われるポートへ通信 | +30 |
| D8 | Telegram 以外のプロセスが Telegram のサーバーへ通信（盗んだ情報の送り先） | +40 |

検知ルールを変えたら、`tests/fixtures/replay-cases.jsonl` に期待値を足してください。`cargo test` が回帰を検出します。
