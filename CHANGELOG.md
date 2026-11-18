# Changelog

このプロジェクトの主な変更を記録します。書式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、バージョンは [Semantic Versioning](https://semver.org/lang/ja/) に従います（1.0 までは、大きな段階でマイナー、その段階の中での機能追加と修正でパッチを上げます）。

バージョンを上げた変更が main に入ると、GitHub Actions がタグ `v<版>` とリリースを作ります（本文はこのファイルの該当節）。

## [Unreleased]

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
