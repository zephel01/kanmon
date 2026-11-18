# CLAUDE.md — kanmon

防御用の通信監視ツール。設計書は `docs/design-v1.md`、次の作業は `HANDOFF.md`。

## ルール
- 攻撃コードは書かない。テストの宛先は RFC 5737 の文書用 IP（198.51.100.0/24・203.0.113.0/24）、ローカル、ユーザー自身のサーバーだけ。
- main / master へ直接コミット・push しない。`feature/xxx` ブランチで作業する。コミットメッセージは Conventional Commits（`feat:` `fix:` `refactor:` `test:` `docs:`）。PR はユーザーの指示があるときだけ作る。
- 変更のたびに次を通す：
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets`（警告 0）
  - root が使える環境では `sudo tests/harness/run_linux.sh`
- `kanmon-core` に OS 依存コードを入れない。OS 依存は `kanmond` に置き、`#[cfg(target_os = ...)]` で分ける。macOS 専用の解析関数は純関数にして Linux でもテストできるようにする。
- 検知ルール（`detections/*.yaml`）を変えたら、`tests/fixtures/replay-cases.jsonl` に期待値を足す（`crates/kanmon-core/tests/replay_cases.rs` が回帰を見る）。
- イベントのフィールド名は ECS 寄せを保ち、追加したら README のフィールド表を更新する。
- 外部入力（パケット・DNS・フィード・ルールファイル・プロセス名）は信用しない。
  - 通知や外部コマンドには引数として渡し、シェルを経由しない。
  - フィードは https のみ。TLS 検証を無効にしない。
- コメントとドキュメントは日本語。「推測」と「要検証」の区別は設計書の表記に合わせる。
