# Changelog

このプロジェクトの主な変更を記録します。書式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、バージョンは [Semantic Versioning](https://semver.org/lang/ja/) に従います（1.0 までは、機能追加でマイナー、修正でパッチを上げます）。

## [Unreleased]

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
