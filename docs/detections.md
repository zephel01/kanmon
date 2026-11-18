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
| `network.kind` / `direction` / `transport` / `scope` | 種別（connect / accept / listen / raw_socket / beacon_report / dns_integrity / bytes_report / persistence / inspect）、方向、tcp / udp / raw / packet / dns、loopback / lan / internet / all |
| `process.executable` / `name` / `args` / `user` / `uid` | 実行ファイル、引数、ユーザー |
| `process.code_signature.status` | apple / app_store / developer_id / signed_other / invalid / adhoc / unsigned / package / unmanaged / unknown |
| `process.code_signature.team_id` / `signing_id` / `package` | 署名者、パッケージ名 |
| `process.hash.sha256` / `proc_key` | ハッシュ、安定識別キー |
| `process.parent.name` / `parent_chain` | 親プロセス、親から上へ最大 6 段の実行ファイル名。インタプリタはスクリプト名も入る（`node …/npm-cli.js` → `node`・`npm-cli.js`、`python -m pip` → `pip`） |
| `process.exe_deleted` / `memfd` / `hidden` / `interpreter` / `script` | 削除済み、メモリ上（memfd）、隠しファイル、インタプリタとスクリプト |
| `process.file_age_s` / `first_seen_age_s` | 実行ファイルの更新からの秒数、kanmon が初めて見てからの秒数 |
| `source.ip` / `port`、`destination.ip` / `port` / `domain` / `registered_domain` | 端点。`domain` は DNS 応答・TLS の SNI を受け身で読んで付ける（v0.2 以降。名前が分からない接続では空） |
| `destination.domain_source` | 名前の出どころ：`sni`（その接続の TLS ClientHello）/ `dns`（DNS 応答で引かれた名前）/ `sni_ip`（同じ IP への別の接続の SNI） |
| `dns.question.name` / `dns.resolved_ip` | DNS の問い合わせ名と答え（`dns_integrity` のみ） |
| `file.path` | 対象のファイル（hosts の書き換え） |
| `kanmon.dns.finding` | DNS の改ざん検知の種類：`hosts_changed` / `resolver_changed` / `crosscheck_mismatch` / `private_answer` / `conflicting_answer` / `unexpected_resolver` |
| `kanmon.dns.watched` / `redirected` / `unknown_public` | 監視リストのドメインが関わる / hosts で他所へ向けられている / 見慣れない公開 DNS |
| `kanmon.dns.added` / `removed` / `added_scope` / `server` / `other` / `tls` | 追加・削除された行や DNS サーバー、追加先の範囲、応答した DNS サーバー、比較相手の答え、答えの IP ごとの証明書の確認結果（N3） |
| `kanmon.ti_match` / `ti_source` | 脅威インテルに一致したか、どのリストか |
| `kanmon.dest_first_for_process` / `port_first_for_process` / `listen_new` | ベースラインとの差分（学習期間中は常に false） |
| `kanmon.dga_score` | 自動生成ドメインらしさ（0〜1、ドメインがあるときだけ） |
| `kanmon.beacon.score` / `n` / `median_interval_s` / `mad_s` | ビーコン（`beacon_report` のみ） |
| `kanmon.bytes.out` / `window_s` | 1 つの宛先へ窓（既定 10 分）の間に送ったバイト数（`bytes_report` のみ） |
| `kanmon.persist.kind` / `change` / `detail` / `risky` | 居座りの種類（claude_hook / vscode_folderopen / pth_exec / workflow / git_hook / autostart / rc_pipe）、added / changed / removed、中身の要約、怪しい特徴（network / pipe_shell / inline_code / base64 / tmp_path。workflow は secrets_dump / secrets_send / oidc_token）（`persistence` のみ） |
| `package.name` / `version` / `type` | 調べたパッケージ（`inspect` のみ。type は pypi / npm） |
| `kanmon.inspect.features` / `count` / `base_version` | 差分から拾った特徴の一覧（[docs/inspect.md](inspect.md)）、所見の件数、比較した版（`inspect` のみ） |
| `kanmon.persist.module` | `.pth` が最初に読み込むモジュールのトップレベル名（`persistence` の pth_exec のみ） |
| `kanmon.persist_recent` | 直近（既定 24 時間）に、起動のたびに動く仕掛けが追加・変更された種類（pth_exec・claude_hook・vscode_folderopen・git_hook・rc_pipe・autostart）。通信のイベント（`connect`）に付く |
| `kanmon.bytes.open_paths` / `open_exts` / `open_size` / `out_per_open` | 報告の瞬間に開いていた通常ファイルのパス・拡張子・合計容量、送信量 ÷ 合計容量 |

## 同梱ルール
| ID | 内容 | 点 |
|---|---|---|
| S1 | 脅威インテル（既知の悪性 IP・ドメイン）に一致 | +100 |
| S2 / S2b | 未署名・ad-hoc・パッケージ管理外 / 署名の検証に失敗 | +20 / +40 |
| S3 | 実行ファイルが 24 時間以内に作成・更新された | +15 |
| S4 | 一時フォルダ・ダウンロード等から実行 | +25 |
| S5 | 削除済み・memfd・隠しファイル | +35 |
| S6 | 文書・メール・ブラウザの配下でシェル等が通信 | +40 |
| S7 / S7m / S7x | ビーコン（強・中）、信頼できない実行ファイルの周期通信。インターネットの宛先で間隔 1 秒以上のもの | +20 / +10 / +20 |
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
| D4 / D4p | パッケージ導入処理（npm・pip・cargo・makepkg 等）の配下から外部へ通信（宛先が公式の配布元と分かれば対象外）/ 非標準ポートへ通信 | +30 / +20 |
| D5 | スクリプト（node・python 等）がインターネットの非標準ポートへ通信 | +15 |
| D6 | AppleScript（osascript）またはその配下が通信（AMOS 等の情報窃取） | +40 |
| D7 | マイニングプールでよく使われるポートへ通信 | +30 |
| D8 | Telegram 以外のプロセスが Telegram のサーバーへ通信（盗んだ情報の送り先） | +40 |
| D9 | ブラウザ以外が、ペーストサイト・Webhook 受け口など盗んだ情報の置き場に使われやすいサービスへ通信 | +30 |
| D10 | パッケージ導入処理の配下から GitHub の書き込み口（API・Gist）へ通信 | +20 |
| D11 | AI コーディング CLI（claude・codex・grok 等）が公式以外の宛先へ通信 | +30 |
| D9s | D9 に重ねる：送ったのがスクリプト（Python・node 等）かパッケージ導入処理の配下 | +30 |
| D12 / D12s | ブラウザ・ウォレット以外がブロックチェーンの公開 RPC（Ethereum・ICP 等。C2 の連絡先の置き場に使われる）へ通信 / それがスクリプトかパッケージ導入処理の配下 | +30 / +30 |

### DNS の改ざん検知（`25-dns.yaml`）
イベントの `network.kind` は `dns_integrity`。hosts と DNS サーバー設定は読むだけで、書き換えません。

| ID | 内容 | 点 |
|---|---|---|
| N1 / N1w / N1r | hosts が書き換えられた / 監視リストのドメインが含まれる / それが別のサーバーへ向けられている | +30 / +40 / +60 |
| N2 / N2p | DNS サーバーの設定が変わった（Wi-Fi の切り替えでも起きる）/ 見慣れない公開 DNS が設定された | +10 / +50 |
| N3 | 監視リストのドメインの答えが DoH で引き直した答えと食い違い、しかも答えの IP がそのドメインの正しい TLS 証明書を出さない | +70 |
| N4 / N4w | 公開ドメインがループバック・社内の IP に解決された / それが監視リストのドメイン | +30 / +30 |
| N5 / N5w | 同じ問い合わせに中身の違う応答が届いた / それが監視リストのドメイン | +40 / +30 |
| N6 / N6u | 設定にない DNS サーバーから応答 / それがよく使われる公開 DNS でもない（記録のみ） | +10 / +10 |

### 送信量（`55-volume.yaml`）
イベントの `network.kind` は `bytes_report`。kanmond が「プロセス × 宛先」ごとに直近 10 分の送信量を集計し、1MB 以上のものを報告する（TCP のみ）。

| ID | 内容 | 点 |
|---|---|---|
| V1 | 10 分で 100MB 以上を 1 つの宛先へ | +20 |
| V2 | AI コーディング CLI が 50MB 以上 | +40 |
| V3 | パッケージ導入処理の配下から 1MB 以上 | +50 |
| V4 | 秘密情報・リポジトリの中身（`.env`・`~/.ssh`・`.git/objects` 等）を開いたまま 1MB 以上 | +50 |
| V5 | 開いているファイルの合計の 3 倍以上を送った（100MB 以上） | +15 |
| V6 | 名前の分からない宛先へ、署名の無いプロセスが 100MB 以上 | +15 |
| V9 | モデル・データ（GGUF・safetensors 等）を登録済みの置き場（Hugging Face 等）へ上げている | −40 |

正当な置き場は `upload_ok` に足す。開いているファイルは報告の瞬間のもので、送信前に閉じたファイルは見えない。

### 居座り（`60-persistence.yaml`）
イベントの `network.kind` は `persistence`。kanmond が 1 時間ごとに読むだけの走査をし、前回からの追加・変更を評価する（初回は基準の記録だけ）。

| ID | 内容 | 点 |
|---|---|---|
| P1 / P2 | Claude Code のフック / VS Code の folderOpen タスクが追加された | +40 / +40 |
| P3 | Python の `.pth` に import 行（起動のたびに実行）が追加された | +50 |
| P4 | GitHub Actions のワークフローが追加・変更された（記録のみ） | +10 |
| P5 / P6 | Git のフック / 自動起動（LaunchAgents・systemd 等）が追加・変更された | +30 / +30 |
| P7 | シェルの設定に、ダウンロードしてそのまま実行する行が追加された | +60 |
| PR / PRt | 中身にダウンロード・パイプでの実行・インラインのコード・base64 / 一時フォルダの参照がある | +40 / +20 |
| P3u | P3 に重ねる：よく見る種類（`pth_known`）ではないモジュールを読み込む `.pth` | +20 |
| PW1 / PW2 | ワークフローに `toJSON(secrets)` / シークレットを外へ送る形・クラウドの一時認証を直接取る形が入った | +50 / +20 |

`.pth` は、プロジェクトの仮想環境（`.venv` 等）、`pip install --user`、`~/.venv`、pyenv・uv・pipx・conda・poetry の環境、`system = true` のときはシステムの Python（Homebrew・python.org・ディストリの dist-packages）も見る。site-packages の更新時刻を 1 分ごとに確かめ、変わったら 1 時間を待たずに走査し直す（`[persistence] watch_s`）。

### 2 段階の結び付け（`65-chain.yaml`）
盗む処理は「勝手に動き出す → 外へ送る」を省けない。起動のたびに動く仕掛けが増えたあと（`kanmon.persist_recent`）、スクリプトの実行環境が初めての宛先へ送ったら重くする。

| ID | 内容 | 点 |
|---|---|---|
| C1 | `.pth` が増えたあと、Python が初めての宛先へ通信 | +30 |
| C2 | フック・folderOpen・Git のフック・rc・自動起動が増えたあと、スクリプトが初めての宛先へ通信 | +25 |

結び付ける期間は `[persistence] recent_window_s`（既定 24 時間）。Python 環境やプロジェクトの単位では結び付けず、種類の単位で見る（venv の python は実体の実行ファイルに解決されるため）。

監視リスト（`dns.watch_domains`）の既定値は、パッケージ配布元（npm・PyPI・crates.io 等）、GitHub、Hugging Face、AI ベンダーの API、主要なログイン画面です。

### パッケージの更新の検査（`70-inspect.yaml`）
イベントの `network.kind` は `inspect`。`kanmonctl inspect` が作り、特徴（I1〜I20）と組み合わせ（IC1〜IC4）で点数を付ける。一覧と点数は [docs/inspect.md](inspect.md)。

検知ルールを変えたら、`tests/fixtures/replay-cases.jsonl` に期待値を足してください。`cargo test` が回帰を検出します。
