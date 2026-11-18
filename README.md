# kanmon（関門）— 第1弾：監視のみ

> 旧仮称 netmon。netmon 時代のログ（`netmon.*` 欄）は `kanmonctl` が自動で読み替える。

macOS / Linux 向けの、プロセス単位の通信監視ツール。設計は [docs/design-v1.md](docs/design-v1.md)。

第1弾は **監視と通知だけで、遮断はしない**。各通信について「どの実行ファイルが（署名・パッケージ・ハッシュ・親）」「どこへ」通信したかを記録し、YAML の検知ルールで点数を付けて通知する。
新しい手口が出てきたら、**YAML を 1 ファイル足し → 過去ログに当てて確かめ → 配置する**。デーモンは 5 秒以内に読み直すので、再ビルドは要らない。

| 項目 | 第1弾の状態 |
|---|---|
| 収集 | ポーリング（既定 500ms）。Linux は `/proc/net/*` と `/proc/<pid>/fd`、macOS は `lsof` と libproc |
| 識別 | macOS：codesign（Team ID・署名 ID・Apple / Developer ID / ad-hoc / 未署名・`--verify --strict` で改ざん検出）。Linux：dpkg / rpm の所有パッケージ。両 OS：SHA-256、インタプリタは「インタプリタ＋スクリプト」単位 |
| 検知 | YAML ルール（S1〜S7・S9・S11・S12・S14〜S18、減点ルール）。ビーコン周期性・DGA らしさ・脅威インテル・ベースライン差分 |
| 通知 | macOS 通知センター / Linux notify-send / ntfy。warn 以上は閉じるまで残るダイアログ（macOS）／期限なし通知（Linux）で、理由の説明付きの全文を出す。同じ通知は 10 分に 1 回まで。死活監視の push URL |
| 保存 | SQLite（WAL）と ECS 寄せの JSONL（ローテーション付き） |
| 遮断 | **なし**（第2弾：Linux の eBPF＋NFQUEUE → [HANDOFF.md](HANDOFF.md)、第3弾：macOS の Network Extension） |

## 構成
```
crates/kanmon-core/   OS 非依存：検知ルールエンジン・許可/拒否ルール・スコア・ビーコン・DGA・インテル・保存
crates/kanmond/       監視デーモン（収集・識別・通知・フィード取得）
crates/kanmonctl/     CLI（check / replay / tail / beacon / status）
detections/           同梱の検知ルール（YAML）
examples/detections/  追加ルールの例（パッケージマネージャ配下の通信）
packaging/            設定例・systemd unit・launchd plist・導入スクリプト
tests/harness/        Linux 動作確認ハーネス（文書用 IP とローカルのみに向ける）
tests/fixtures/       再生テスト用イベント
```

## ビルドと導入
```bash
cargo build --release
cargo test --workspace          # 単体テスト＋検知ルールの回帰テスト

# Linux（systemd）
sudo packaging/install-linux.sh
sudo journalctl -u kanmond -f

# macOS（launchd）
sudo packaging/install-macos.sh
sudo tail -f /Library/Logs/kanmon/kanmond.log
```
- root で動かす。root でないと、他ユーザーのプロセスの通信を帰属・識別できない。
- 導入直後の 7 日間は `learning` モードで動く。ベースラインを作り、通知は warn 以上だけにする。
- root 実行時は `strict_owner = true`（既定）により、検知ルール・許可ルール・拒否リストが **root 所有かつ group/other 書込不可** でないと読まない。一般ユーザー権限のマルウェアが「自分の点を下げるルール」を置けないようにするため。

## 新しい事象への対応手順
```bash
# 1) ルールを書く（例：examples/detections/60-supply-chain.yaml）
# 2) 文法と既存ルールとの組み合わせを確認
kanmonctl check --detections /etc/kanmon/detections --extra ./my-rule.yaml
# 3) 過去ログに当てて、何件当たるか・誤検知が出ないかを見る
sudo kanmonctl replay --events /var/log/kanmon/events.jsonl \
  --detections /etc/kanmon/detections --extra ./my-rule.yaml --only X1
# 4) 配置（デーモンが 5 秒以内に再読込。ルールに誤りがあれば前のルールのまま動き、通知で知らせる）
sudo install -o root -m 0644 ./my-rule.yaml /etc/kanmon/detections/
```
ローテーション済みのログ（`events.jsonl.1` 等）も `--events` に渡せる。`-` を渡すと標準入力から読む。

### ルールの書き方
```yaml
lists:
  my_hosts: [evil.example, bad.test]
detections:
  - id: X2                      # 一意（重複はエラー）
    name: short_name
    points: 30                  # 負の値で減点
    kinds: [connect]            # connect / accept / listen / raw_socket / beacon_report（省略時は全部）
    when:
      all:                      # all / any / not を入れ子にできる
        - { field: destination.registered_domain, op: in, value: "@my_hosts" }
        - not: { field: process.code_signature.status, op: eq, value: apple }
```
`description` は通知や `kanmonctl alerts` にそのまま出るので、短い日本語で書く。
演算子は `eq ne in not_in prefix suffix contains regex gt gte lt lte exists missing` の 14 種類。
- `ci: true` で大文字・小文字を区別しない。
- フィールドが配列なら、どれか 1 つが一致すれば真。
- `prefix` の `~/` は `/Users/*/`・`/home/*/`・`/root/` に展開する。
- キー名の誤記はエラーになる（`deny_unknown_fields`）。

### ルールから参照できる主なフィールド
| フィールド | 内容 |
|---|---|
| `network.kind` / `direction` / `transport` / `scope` | 種別、方向、tcp / udp / raw / packet、loopback / lan / internet / all |
| `process.executable` / `name` / `args` / `user` / `uid` | 実行ファイル、引数、ユーザー |
| `process.code_signature.status` | apple / app_store / developer_id / signed_other / invalid / adhoc / unsigned / package / unmanaged / unknown |
| `process.code_signature.team_id` / `signing_id` / `package` | 署名者、パッケージ名 |
| `process.hash.sha256` / `proc_key` | ハッシュ、安定識別キー |
| `process.parent.name` / `parent_chain` | 親、親から上へ最大 6 段の実行ファイル名 |
| `process.exe_deleted` / `memfd` / `hidden` / `interpreter` / `script` | 削除済み、memfd、隠しファイル、インタプリタとスクリプト |
| `process.file_age_s` / `first_seen_age_s` | 実行ファイル更新からの秒数、kanmon が初めて見てからの秒数 |
| `source.ip` / `port`、`destination.ip` / `port` / `domain` / `registered_domain` | 端点（第1弾では `domain` は空） |
| `kanmon.ti_match` / `ti_source` | 脅威インテルに一致したか、どのリストか |
| `kanmon.dest_first_for_process` / `port_first_for_process` / `listen_new` | ベースライン差分（learning 中は常に false） |
| `kanmon.dga_score` | DGA らしさ（0〜1、ドメインがあるときだけ） |
| `kanmon.beacon.score` / `n` / `median_interval_s` / `mad_s` | ビーコン（`beacon_report` のみ） |

## CLI
```bash
kanmonctl alerts                         # 直近 24h の warn 以上を理由の説明付きで（見逃した通知の確認）
kanmonctl tail -f --min-level notice     # 見やすく表示
kanmonctl status                         # 直近 24h のレベル別件数とスコア上位
kanmonctl beacon --min 0.5               # ビーコン候補
kanmonctl check --detections DIR [--extra FILE] [--rules rules.json]
kanmonctl replay --events FILE --detections DIR [--extra FILE] [--only ID] [--json]
```

## 許可/拒否ルール（`rules.json`）
設計書 §18.1 の形式の配列。第1弾は遮断しないので、一致したときの扱いは次のとおり。
- `allow`：通知を抑える。
- `deny`：`would_deny` として最低でも warn で通知する。
- 脅威インテルに一致した通信は、allow ルールより優先する。
```json
[{"id":"vscode-github","action":"allow","direction":"outbound",
  "process":{"match":"signature","team_id":"UBF8T346G9","signing_id":"com.microsoft.VSCode"},
  "remote":{"cidrs":["140.82.112.0/20"],"ports":[443],"protocol":"tcp"}}]
```

## 既知の限界（第1弾）
- **ポーリングのため、間隔より短い接続は取りこぼす**。短い HTTP ビーコンも一部は見えない。確実に取るには第2弾（eBPF）と第3弾（Network Extension）が必要。
- **ドメイン名が付かない**（IP のみ）。DGA（S9）・トンネル系（S18）・新規登録ドメイン（S8）は replay 用か、第5弾の DNS 強化以降に効く。
- 送信量（S13）は未実装。帰属できるのはデーモン自身の network namespace だけで、コンテナ内の通信は見えない。
- macOS の識別はディスク上の署名を見ている（`codesign`）。実行中プロセスの動的な検証（`SecCodeCheckValidity`）は第3弾で行う。
- root を取られた後は止められる。`heartbeat_url` を設定し、途絶を外側で検知させること。
