<div align="center">

# kanmon（関門）

**新しい手口に自分で追いつける、macOS / Linux 向けのプロセス単位の通信監視ツール**

[![CI](https://github.com/zephel01/kanmon/actions/workflows/ci.yml/badge.svg)](https://github.com/zephel01/kanmon/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![Rust](https://img.shields.io/badge/rust-1.88%2B-orange)

日本語 | [English](README.en.md)

</div>

---

関門（kanmon）は、関所のように「通るものを改める門」のことです。EDR やウイルス対策の置き換えではなく、それらが手薄になりやすい**通信の出入口**を見る役割です。
kanmon は端末から出入りする通信を 1 本ずつ調べて、次の 2 つを記録します。
- **どの実行ファイルが通信したか**：署名、パッケージ、ハッシュ、親プロセス
- **どこへ通信したか**

そのうえで、怪しい通信は**理由付きで**知らせます。判定ルールは YAML で書けるので、新しい手口が出てきても**再ビルドせずに**自分で対応できます。

<!-- スクリーンショット：docs/images/alert-dialog.png を追加したらコメントを外す
<p align="center"><img src="docs/images/alert-dialog.png" width="480" alt="警告ダイアログ"></p>
-->

> [!NOTE]
> v0.1 は**監視と通知だけ**で、通信の遮断はまだしません。遮断はロードマップの次の段階です。

## 特徴
- 🔍 **プロセス単位で見る**：通信ごとに、実行ファイル・署名（Apple / Developer ID / ad-hoc / 未署名）・所有パッケージ・SHA-256・親プロセスの列を記録します
- 🧩 **ルールは YAML**：書く → `kanmonctl replay` で過去ログに当てて確かめる → 置く、で反映されます。デーモンは 5 秒以内に読み直します
- 💬 **なぜ止めたかが分かる通知**：理由・点数・プロセス・宛先を全文で表示します。warn 以上は閉じるまで残ります
- 📡 **ビーコン検知**：C2 によくある「一定周期の通信」を統計で拾います。正規のクラウドを経由した C2 にも効きます
- 🛡️ **脅威インテル**：Feodo Tracker・Spamhaus DROP・ローカルの拒否リストと照合します
- 🖥️ **メニューバーアプリ（macOS）**：盾のアイコンの色で状態が分かります（緑＝正常、黄＝注意、赤＝警告、灰＝停止）。警告は詳細ウィンドウで全文を表示します
- 🔒 **自分の身も守る**：root 所有でないルールは読みません。通知は引数で渡すので注入できません。外部の死活監視とも連携できます

## クイックスタート
Rust 1.88 以上が必要です。

**macOS**
```bash
git clone https://github.com/zephel01/kanmon.git && cd kanmon
cargo build --release
sudo packaging/install-macos.sh
```

**Linux（systemd）**
```bash
git clone https://github.com/zephel01/kanmon.git && cd kanmon
cargo build --release
sudo packaging/install-linux.sh
```

**メニューバーアプリ（macOS 13 以降）**
```bash
macos/build-app.sh && macos/install-app.sh   # sudo 不要。ログイン時に自動起動
```

警告を見るには次を実行します。
```bash
sudo kanmonctl alerts --file /Library/Logs/kanmon/events.jsonl   # macOS
sudo kanmonctl alerts                                            # Linux
```

導入直後の 7 日間は**学習期間**です。この間は普段の通信を覚え、warn 以上だけを通知します。

## 仕組み
```mermaid
flowchart LR
  subgraph collect["収集（kanmond）"]
    S["ソケット一覧<br/>Linux: /proc/net<br/>macOS: lsof + libproc"]
    P["プロセス識別<br/>署名・パッケージ<br/>SHA-256・親プロセス"]
  end
  subgraph judge["判定（kanmon-core）"]
    F["事実の付与<br/>脅威インテル・ベースライン差分<br/>DGA・ビーコン"]
    D["検知ルール<br/>detections/*.yaml"]
    R["許可/拒否ルール<br/>rules.json"]
  end
  S --> P --> F --> D --> O["点数 → レベル"]
  R --> O
  O --> N["通知<br/>ダイアログ / D-Bus / ntfy"]
  O --> L["保存<br/>JSONL（ECS 互換）/ SQLite"]
  L -. "kanmonctl replay" .-> D
```

## 検知ルールの例
```yaml
detections:
  - id: X1
    name: pkg_install_script_network
    points: 25
    description: パッケージ導入処理の配下から外部へ通信
    kinds: [connect]
    when:
      all:
        - { field: network.scope, op: eq, value: internet }
        - { field: process.parent_chain, op: in, value: [npm, pip, pip3, uv, cargo] }
        - { field: process.name, op: in, value: [sh, bash, curl, wget] }
```
同梱ルールは 30 件です。一般的な手口（S1〜S18）と、開発者を狙う手口（D1〜D8：遠隔操作ソフト、トンネル、開発サーバーの公開、パッケージ導入時の通信など）を含みます。書き方と、ルールから参照できるフィールドは [docs/detections.md](docs/detections.md) にあります。

## ドキュメント
| 文書 | 内容 |
|---|---|
| [docs/detections.md](docs/detections.md) | 検知ルールの書き方、フィールド一覧、同梱ルール |
| [docs/configuration.md](docs/configuration.md) | 設定、CLI、許可/拒否ルール、保存先 |
| [docs/design-v1.md](docs/design-v1.md) | 設計書（脅威モデル・アーキテクチャ・ロードマップ） |
| [CHANGELOG.md](CHANGELOG.md) | 変更履歴 |

## ロードマップ
- [x] **v0.1** 両 OS の監視・検知・通知、YAML ルール、replay、ビーコン、脅威インテル
- [x] macOS メニューバーアプリ（Kanmon.app）と状態ソケット
- [ ] Linux での遮断（eBPF + NFQUEUE、拒否マップのピン留め、フェイルオープン/クローズの切替）
- [ ] macOS での遮断（Network Extension、実行中プロセスの署名検証）
- [ ] DNS の強化（ドメイン名の付与、DoH 迂回の検知）
- [ ] 送信量の急増検知、新規登録ドメイン（NRD）フィード
- [ ] Web UI、syslog / SIEM 連携

## 既知の限界（v0.1）
- **ポーリング方式**なので、収集間隔（既定 500ms）より短い接続は取りこぼすことがあります
- 宛先は IP だけで、**ドメイン名は付きません**。ドメインを使うルールは replay と、将来の DNS 強化で効きます
- root を取られた後は止められてしまいます。`heartbeat_url` で外側から死活を監視してください
- コンテナや別の network namespace の通信は対象外です

## コントリビュート
- Issue・PR を歓迎します。開発ルールは [CLAUDE.md](CLAUDE.md) にあります（テストの宛先は RFC 5737 の文書用 IP に限る、など）
- 脆弱性は公開 Issue ではなく、[SECURITY.md](SECURITY.md) の手順で報告してください

## ライセンス
[Apache License 2.0](LICENSE)
