# Changelog

このプロジェクトの主な変更を記録します。書式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、バージョンは [Semantic Versioning](https://semver.org/lang/ja/) に従います（1.0 までは、大きな段階でマイナー、その段階の中での機能追加と修正でパッチを上げます）。

バージョンを上げた変更が main に入ると、GitHub Actions がタグ `v<版>` とリリースを作ります（本文はこのファイルの該当節）。

## [Unreleased]

## [0.2.6] - 2026-11-18
2026-11-17 の agent-framework（PyPI、`.pth` で Python の起動のたびに認証情報を送る）と、ブロックチェーンを連絡先の置き場にする手口（keyv・ChainDrop・CanisterWorm）への対応。

### 追加
- **仕込みと送信の結び付け**（`detections/65-chain.yaml`、C1・C2）：起動のたびに動く仕掛け（`.pth`・フック・folderOpen・Git のフック・rc・自動起動）が増えたあと 24 時間以内に、スクリプトの実行環境が初めての宛先へ送ったら重くする。通信のイベントに `kanmon.persist_recent` を付ける（`[persistence] recent_window_s`）
- **ブロックチェーンの公開 RPC**（D12・D12s、`chain_rpc`・`chain_rpc_suffixes`・`chain_apps`）：ブラウザ・ウォレット以外が Ethereum・ICP の公開 RPC へ繋いだら加点。スクリプトやパッケージ導入処理の配下ならさらに加点
- **D9s**：盗んだ情報の置き場（webhook.site 等）への通信が、スクリプトかパッケージ導入処理の配下なら +30（D9 と合わせて警告）
- **P3u**：よく見る種類（`pth_known`）ではないモジュールを読み込む `.pth` が増えたら +20（P3 と合わせて警告）。イベントに `kanmon.persist.module`
- **PW1・PW2**：ワークフローに `toJSON(secrets)`（+50）/ シークレットを外へ送る形・`ACTIONS_ID_TOKEN_REQUEST_*` の直接利用（+20）が入ったら加点（2026-11 の盗んだ GitHub 認証によるワークフロー注入）
- `.pth` を見る場所を追加：`~/.venv`、pyenv・uv（tools・python）・pipx・conda／miniforge・poetry の環境、`system = true` のときはシステムの Python（Homebrew・python.org の Framework・ディストリの dist-packages）
- site-packages の更新時刻を 1 分ごとに確かめ、変わったら 1 時間を待たずに走査し直す（最短 2 分おき、`[persistence] watch_s`）
- `kanmonctl scan --kind <種類>`：種類で絞る。`--kind pth_exec` はシステムの Python も見て、読み込むモジュール名を添える

### 変更
- 走査の範囲を広げたので、更新後の最初の走査は差分を出さずに基準を取り直す（新しく見る場所のものがまとめて「追加」と出ないように）


## [0.2.5] - 2026-11-18
居座り（開発ツールの設定・自動起動への仕込み）の検知。

### 追加
- **居座りの検知**（`detections/60-persistence.yaml`、P1〜P7・PR・PRt）：kanmond が 1 時間ごとに読むだけの走査をし、前回からの追加・変更をイベント（`persistence`）にする。初回は基準の記録だけ
  - Claude Code のフック（`.claude/settings.json`）、VS Code の folderOpen タスク（`.vscode/tasks.json`、コメント付き JSON に対応）、Python の `.pth` の import 行、`.github/workflows`、Git のフック、LaunchAgents・LaunchDaemons・systemd、シェルの rc のダウンロード実行
  - 中身にダウンロード・パイプでの実行・インラインのコード・base64・一時フォルダの参照があると重くなる。自動起動は「起動するコマンド」（plist の ProgramArguments・systemd の ExecStart）だけを見る。ワークフローは CI の設定として URL 等が普通に書かれるので、特徴は付けず変化だけを知らせる。シェルの rc は `curl … | sh`・`$(curl …)`・`base64 -d | sh` の形だけを拾う
  - 走査の場所は `[persistence] roots`（既定 `~/kanmon-work`）。kanmond は root で動くので、`~/` はログイン中のユーザーのホームに読み替える。`node_modules`・`target` 等は潜らない
- **`kanmonctl scan`**：同じ走査をその場で行い、一覧を表示する（`--risky` で怪しいものだけ、`--json`）。`sudo` 不要

## [0.2.4] - 2026-11-18
macOS の導入スクリプトで kanmond が起動しないことがある問題の修正。

### 修正
- `packaging/install-macos.sh`・`macos/install-app.sh`：`launchctl bootout` の直後の `bootstrap` が「Bootstrap failed: 5: Input/output error」で失敗し、kanmond が登録されないまま終わることがあった（v0.2.3 の更新で発生）。止まりきるのを待ってから入れ替え・登録し、失敗したらやり直す。すでに登録済みなら `kickstart -k` で再起動する。最後にプロセスが起動したかを確かめ、起動していなければ対処の案内つきでエラーにする（`packaging/launchd-lib.sh`）
- 疑似環境（`KANMON_PREFIX`）での導入では launchd に触らない
- CI：導入スクリプトの shellcheck と、launchd の入れ替えの確認（`tests/harness/launchd_lib_test.sh`。launchctl を差し替えて、競合・登録拒否・通常の 3 通り）

## [0.2.3] - 2026-11-18
送信量の検知、S7（周期通信）の誤検知の削減、ログの日付ごとの切り替え。

### 追加
- **送信量の検知**（`detections/55-volume.yaml`、V1〜V6・V9）：「プロセス × 宛先」ごとに直近 10 分の送信量を集計し、1MB 以上を `bytes_report` として報告する。量だけでなく、開いているファイル（名前・拡張子・容量）、宛先、親プロセスと組み合わせて判定する
  - AI コーディング CLI がリポジトリ（`.git/objects`）や `.env` を開いたまま大量に送る、パッケージ導入処理の配下から 1MB 以上を送る、などを加点
  - GGUF・safetensors 等を Hugging Face 等の登録済みの置き場へ上げる正当な送信は減点
  - Linux は netlink の sock_diag（`tcpi_bytes_acked`）、macOS は `nettop` で接続ごとの送信量を読む。TCP のみ（QUIC 等の UDP は対象外）。LAN の宛先は数えない
- **ログの日付ごとの切り替え**：kanmond の動作ログを kanmond 自身が書き、日付が変わったら `kanmond.YYYY-MM-DD.log` に切り替えて 14 日残す（`[log]`）。`events.jsonl` も `[jsonl] rotate = "daily"` で日付ごとにできる（既定はサイズごとのまま）
- 設定 `[volume]`・`[log]`・`[jsonl] rotate` / `keep_days`

### 変更
- **S7 / S7m**：+30 / +15 → +20 / +10。署名のあるアプリの定期的な問い合わせ（更新確認・API のポーリング）だけでは記録のみにした。信頼できない実行ファイル（S7x）と組み合わさると通知になる。LAN の宛先（AirDrop 等）と、間隔が 1 秒未満のもの（連続した通信）は対象外。`beacon_report` に宛先の範囲（`network.scope`）を付けた
- macOS の launchd の標準エラーの出し先を `kanmond.stderr.log` にした（起動直後の失敗だけが入る）

## [0.2.2] - 2026-11-18
v0.2.1 の Kanmon.app が Command Line Tools だけの環境でビルドできなかった問題の修正。

### 修正
- **Kanmon.app のビルドの失敗**：警告の一覧ウィンドウが SwiftUI の `@State`（マクロ）を使っており、Command Line Tools だけの環境ではマクロのプラグインが無いためビルドできなかった。状態を `ObservableObject` で持つように書き換えた。CI に、マクロを使っていないかの検査を追加
- v0.2.0 が記録した N3（DoH と食い違っただけで、証明書は確かめていない）が、再起動後に v0.2.1 の見出し「正しい証明書を出さない」で表示されていた。証明書の確認結果が無いものは「暗号化 DNS の答えと合わない」と出す

### 変更
- kanmond のログ（kanmond.log）の各行に時刻を付けた

## [0.2.1] - 2026-11-18
メニューバーの件数から警告の一覧を開けるようにし、v0.2.0 の DNS 検知の誤検知を減らした。

### 追加
- **警告の一覧ウィンドウ（Kanmon.app）**：メニューの件数（critical・warn・notice）を押すと、そのレベルの 24 時間分の警告を一覧で開く。ルール別の件数で絞り込み、文字列で検索でき、行を押すと詳細を出す。メニュー下部の「一覧」からも開ける
- 状態ソケットの要求 `{"cmd":"alerts","level":"notice","hours":24,"limit":500}`：期間内の警告とルール別の件数を返す（DB を読み取り専用で開く）。警告に当たったルールの ID（`rules`）を付けた
- `docs/configuration.md` に、更新・起動・停止の手順を追加

### 変更
- **N3**：暗号化 DNS（DoH）の答えと食い違うだけでは知らせない。答えの IP に TLS で接続し、そのドメインの正しい証明書が出ないときだけ知らせる（+70、warn）。CDN が問い合わせ元によって違う IP を返すことによる誤検知（github.com・apple.com・google.com 等）をなくした。OS に入っている証明書（社内の TLS 検査用など）も信頼する
- **N6・N6u**：+20 / +20 → +10 / +10（記録のみ）。IPv6 の RA で配られる ISP の DNS 等でも起きるため。偽応答の割り込みは N5 で見る。一度でも設定に出た DNS サーバーは覚えておき、「設定にない」としない

### 修正
- D9（持ち出し先のサービス）と S14（DNS の迂回）が、Chrome の補助プロセス（「Google Chrome Helper (Renderer)」等）をブラウザと見なさず鳴っていた。ブラウザ名の前方一致（`browser_prefixes`）でも除外する

## [0.2.0] - 2026-11-18
宛先のドメイン名と DNS の改ざん検知、macOS メニューバーアプリ。

### 追加
- **宛先のドメイン名**：DNS 応答と TLS ClientHello の SNI を受け身で読み（libpcap、プロミスキャスなし、DNS の設定は変えない）、接続イベントに `destination.domain`・`registered_domain`・`domain_source` を付ける。ドメインでの脅威インテル照合、DGA・トンネル系ドメインのルール（S9・S18）が実際の通信で効くようになった
- **DNS の改ざん検知**（`detections/25-dns.yaml`、N1〜N6）：hosts の書き換え（監視リストのドメインを別サーバーへ向ける行は critical）、DNS サーバー設定の変更（見慣れない公開 DNS は warn）、Cloudflare の DoH での引き直しと照合、公開ドメインのローカル IP への解決、応答の食い違い、設定にない DNS サーバーからの応答
- **開発者向けルール**：D9（ペーストサイト・Webhook 受け口など持ち出しに使われやすいサービス）、D10（パッケージ導入処理の配下から GitHub の書き込み口へ）、D11（AI コーディング CLI が公式以外の宛先へ。追加ルール例 X1 を同梱化）
- 設定 `[dns]`（`enabled`・`interfaces`・`hosts_path`・`resolv_conf`・`check_interval_s`・`crosscheck`・`doh_url`・`crosscheck_interval_min`・`watch_domains`・`private_ok_suffixes`）
- kanmond のビルド機能 `capture`（既定で有効。libpcap が必要。無効にすると名前付けなしでビルドできる）
- **macOS メニューバーアプリ（Kanmon.app）**：アイコンの色で状態を表示（緑・黄・赤・灰）、直近の警告一覧、警告の詳細ウィンドウ（コピー可）、学習期間の残り日数、既読管理。SwiftUI（macOS 13 以降）。`macos/build-app.sh` / `macos/install-app.sh`
- **状態ソケット（読み取り専用）**：kanmond が状態と直近 50 件の警告を Unix ソケットで返す。接続相手の uid を検証する（root・ログイン中のユーザー・許可した uid のみ）
- 設定：`status_socket`、`status_allowed_uids`、`notify.defer_to_app`（アプリが動いている間はローカル通知をアプリに任せる）
- CI：macOS で Kanmon.app のビルドと署名検証
- **開発者を狙う手口の検知ルール**（`detections/40-developer.yaml`、11 件）：遠隔操作ソフト、トンネルツールと SSH のリバーストンネル、開発・AI サーバーとデバッガのポートの外部公開、パッケージ導入処理の配下からの通信、スクリプトによる非標準ポートへの通信、osascript の通信、マイニングプール向けのポート、Telegram 以外のプロセスから Telegram のサーバーへの通信
- 検知ルールの演算子 `cidr`（IP アドレスの範囲判定）
- 親プロセスの列にスクリプト名を追加（`npm-cli.js`・`pip`・`makepkg` 等）。インタプリタ経由のパッケージマネージャも判定できるようにした

### 変更
- D4（パッケージ導入処理の配下からの通信）は、宛先が公式の配布元（npmjs.org・pypi.org・crates.io 等）と分かったときは対象外にした
- Linux でのビルドに libpcap の開発用ファイル（Ubuntu は `libpcap-dev`）が必要になった
- Apple 署名・公式パッケージの減点（T-trusted）を ssh・scp・sftp・rsync には適用しない
- 追加ルールの例を「AI コーディング CLI が公式以外の宛先へ通信（X1）」に差し替え。パッケージ導入時の通信は D4 として正式ルールに入れた

### 修正
- Kanmon.app が kanmond の応答を解釈できず「停止中の可能性」と表示していた問題（`counts_24h` のキー名の変換が一致していなかった）。キーを明示し、Rust と Swift の両方で同じ JSON フィクスチャを検証するテストを追加
- kanmond を再起動するとメニューバーの「直近の警告」が空になっていた問題。起動時に直近 24 時間の警告を DB から読み戻す
- ログイン項目で Kanmon.app と kanmond が汎用アイコン（exec）で表示されていた問題。アプリのアイコンを追加し、launchd のジョブをアプリに関連付けた（`AssociatedBundleIdentifiers`）

### 修正（誤検知・重複）
- macOS の Cryptex 内にある Apple 純正バイナリ（例：com.apple.WebKit.Networking）が「署名の検証に失敗」と誤判定されていた。OS が封印・検証している領域（`/System/`・`/usr/bin/` 等）は検証の対象外とし、`--strict` だけが失敗する場合も改ざんとはみなさない
- kanmond の再起動をまたいで、同じビーコン警告が繰り返し出ていた。抑制の記録を DB でも確認する
- Kanmon.app が、kanmond の再起動で読み戻された古い警告をダイアログで出していた。アプリの起動時刻、または最後に出した警告より新しいものだけを出す

## [0.1.0] - 2026-11-18
第1弾：監視と通知のみ（遮断なし）。

### 追加
- **kanmond**：macOS / Linux の監視デーモン
  - 収集：Linux は `/proc/net` と `/proc/<pid>/fd`、macOS は `lsof` と libproc。どちらもポーリング方式（既定 500ms）
  - プロセス識別：macOS は codesign（Team ID・署名 ID・`--verify --strict` で改ざん検出）、Linux は dpkg / rpm の所有パッケージ。両 OS で SHA-256、親プロセスの列、インタプリタはスクリプト単位で識別
  - 学習モード（既定 7 日）と、ベースラインとの差分（初めての宛先・ポート・待受）
  - 脅威インテル：Feodo Tracker・Spamhaus DROP（https のみ、日次で更新）とローカルの拒否リスト
  - ビーコン周期性のスコア（RITA の考え方を簡略化）、DGA らしさのスコア
  - 通知：warn 以上は閉じるまで残る表示（macOS はダイアログ、Linux は期限なし通知）、理由の説明付き。ntfy への送信、死活監視の heartbeat
  - 保存：JSONL（ECS 互換の項目名、ローテーション付き）と SQLite（WAL）
- **検知ルール（YAML）**：19 件を同梱。14 種類の演算子、共有リスト、ホットリロード、root 所有チェック
- **許可/拒否ルール（rules.json）**：署名・パッケージ・ハッシュ・パスで指定。具体的なルールを優先し、有効期限も付けられる
- **kanmonctl**：`alerts` / `tail` / `status` / `beacon` / `check` / `replay`
- 導入スクリプト（systemd / launchd）。旧名 netmon からの自動移行に対応
- テスト：単体テスト、検知ルールの回帰テスト、Linux ハーネス（RFC 5737 宛のみ）、CI（Linux / macOS）

### 変更
- 旧仮称 netmon から kanmon に改名。netmon 時代のログは kanmonctl が自動で読み替える

### 修正
- macOS の CI で、Linux 専用コードの `dead_code` 警告がエラーになっていた問題（#1）

[Unreleased]: https://github.com/zephel01/kanmon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zephel01/kanmon/releases/tag/v0.1.0
