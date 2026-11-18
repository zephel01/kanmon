# 引き継ぎ：第2弾（Linux の遮断）— Ubuntu 実機の Claude Code 向け

作成：2026-11-18。対象ブランチ：`feature/phase1-core` から `feature/phase2-linux-ebpf` を切る。
前提資料：設計書 [docs/design-v1.md](docs/design-v1.md) の §4.2・§6・§10・§14・§20（フェーズ1〜2）・§21。
**特に §10.4「遮断で守る約束」**（2026-11-18 追記）：過剰な遮断で使われなくなった他製品の例から、TLS を開けない・応答を溜めない・ループバックと LAN は既定で止めない・例外は全検査から外す・理由と「今回だけ許可」を出す・新しいルールはまず記録だけ、の 6 点を守る。

## 0. 着手前に確認すること（利用者に聞く／実機で調べる）
| 項目 | 確認方法 | 決め方 |
|---|---|---|
| カーネル版 | `uname -r` | 6.1 以上なら §4.2 案どおり。5.15〜6.0 なら `fentry/fexit` が無い場合を想定し、tracepoint `sched_process_exec` で代替。5.15 未満は対象外 |
| BTF | `ls /sys/kernel/btf/vmlinux` | 無ければ CO-RE 不可 → /proc＋NFQUEUE のみの縮退モード |
| LSM BPF | `cat /sys/kernel/security/lsm` に `bpf` があるか | 無ければフェーズ3（LSM）は見送り |
| nftables | `nft --version`、既存ルール `nft list ruleset` | 既存の ufw / docker のチェインと衝突しないよう、専用テーブル `inet kanmon` に限定する |
| 端末の種類 | デスクトップかサーバーか | フェイルクローズ（デスクトップ）／フェイルオープン（サーバー）の既定を決める（§10.2） |
| EDR | 導入済みの EDR 製品とその動作方式（eBPF かカーネルモジュールか）を確認 | eBPF バックエンドなら cgroup フックの多重アタッチ（`BPF_F_ALLOW_MULTI`）を前提にする（§15） |

## 1. ゴール（完了条件）
1. すべての外向き接続に **正確な pid / exe / cgroup** が付く。第1弾のポーリングで取りこぼしていた短命の接続も含める。
2. 既知の拒否（脅威インテル一致・ユーザー deny）が **カーネル内で即時に拒否** される。拒否マップは `/sys/fs/bpf/kanmon/` にピン留めし、デーモンが止まっても効き続ける。
3. 未知の新規接続を **NFQUEUE で保留** し、判定（スコア ≥ warn なら拒否）またはユーザーの確認（D-Bus 通知のボタン、30 秒でタイムアウトし今回のみ拒否）で通す・止める。
4. 内向き（input チェイン）と listen の監視ができる。
5. `tests/harness/run_linux.sh` を拡張し、**「止まること」** まで確認できる。

## 2. 第1弾の作り（変更点の当たり）
- `crates/kanmond/src/sockets.rs`：`Collector`（ポーリング）。→ eBPF リングバッファから届くイベントを同じ `Sock` 相当に変換する `EbpfCollector` を足す。`Monitor::handle_new` はそのまま使える作りにしてある。
- `crates/kanmond/src/monitor.rs`：`handle_new` → `scoring::apply()` が `Outcome`（score・level・verdict）を返す。→ この結果を **判定（Verdict）として返す経路** を足す（NFQUEUE の応答、eBPF マップの更新）。
- `crates/kanmon-core`：判定ロジックは OS 非依存のまま保つ。遮断のためにコアへ OS 依存コードを入れない。
- 検知ルール（YAML）とフィールド名は互換を保つ。フィールドを追加する場合は README の表と `tests/fixtures/replay-cases.jsonl` を更新する。

## 3. 実装手順（推奨順）
1. **`crates/kanmon-linux-ebpf`（aya、no_std）**
   - `cgroup_sock_addr connect4/6, sendmsg4/6`：(cookie, 5-tuple, pid, tgid, cgroup id) をリングバッファへ送る。拒否マップ（宛先 IP × exe の (dev, ino)）を引き、一致すれば拒否する。
   - `cgroup_sock sock_create`：raw / packet ソケットの作成を記録する（第1弾 S17 の置き換え）。
   - exec 追跡：`fentry bprm_execve`（無い場合は `sched_process_exec`）と `sched_process_exit`。
   - マップが溢れて帰属できない接続には「unattributed」の印を付け、NFQUEUE 側で拒否寄りに扱う（§4.2-5）。
   - 検証器の命令数制限に当たらないよう、eBPF 側は帰属と単純なマップ照合に絞る。
2. **`crates/kanmond` に `ebpf` feature を追加**：aya でロードし、root cgroup にアタッチ、マップをピン留めする。
3. **nftables**：専用テーブル `inet kanmon` を作る。
   - `output`：`ct state new` かつ ct mark 未確定のものを `queue num 0-3 fanout`。
   - `input`：同様に queue。
   - ループバックと LAN（RFC 1918・リンクローカル・ULA）は既定で除外する（§10.4-3）。LAN も対象にするのは設定で明示したときだけ。SSH の管理ポートは組み込みの許可ルールにする（締め出し防止、§10.2）。
   - キューに入れるのは `ct state new` の最初のパケットだけ。判定後は ct mark で既知にし、以降のパケットはキューに入れない（応答を溜めない、§10.4-2）。
   - まずは `nft -j` を呼び出す方式でよい（crate の成熟度は【要検証】）。
4. **NFQUEUE 受信**（`nfq` crate）：5-tuple から eBPF のイベントキャッシュを引いてプロセスを特定し、`scoring::apply` に通す。決まった結果は eBPF マップと conntrack mark に書き戻す。
5. **確認 UI**：`kanmon-notify`（ユーザーセッションで動かし、`zbus` で org.freedesktop.Notifications のアクションボタンを出す）。デーモンとは Unix ソケットでつなぎ、`SO_PEERCRED` で uid を検証する。
6. **フェイルセーフ**：`fail_mode = "closed" | "open"` を設定に追加する。queue の `bypass` 有無で切り替え、デーモン停止時の挙動をハーネスで確認する。

## 4. 安全に進めるための約束
- まず **VM（multipass / LXD VM）か、物理コンソールのある端末** で試す。SSH だけの遠隔端末ではやらない。
- nftables を変える前に `nft list ruleset > /root/nft-backup-$(date +%s).nft` を取る。異常時は `nft delete table inet kanmon` で戻す手順を README に書く。
- テストの宛先は RFC 5737（`198.51.100.0/24`・`203.0.113.0/24`）、自分の VPS、ローカルに限る。実在のマルウェアは使わない。
- main へ直接コミットしない。`feature/phase2-linux-ebpf` で作業し、PR はユーザーの指示があるときだけ作る。

## 5. 確認項目（第1弾ハーネスへの追加）
| テスト | 期待 |
|---|---|
| 拒否リスト宛（198.51.100.7:443） | connect() が EPERM / ECONNREFUSED で失敗し、イベントの `kanmon.verdict = deny` |
| 未知の未署名バイナリ（/tmp） | NFQUEUE で保留 → スコア ≥ 60 で拒否 |
| 0.0.0.0 待受への LAN からの接続 | input で保留して確認、インターネット側からは拒否 |
| 短命接続（`curl` を 100 回、各数 ms） | 100 件すべてにプロセスが付く（第1弾では取りこぼす） |
| `kill -9 kanmond` | ピン留めした拒否は効き続ける。queue は設定どおり開放または遮断。heartbeat が途絶える |
| 帰属マップの溢れ（大量のローカル接続） | unattributed として扱い、素通りしない |
| 性能（§14） | 既知フローの判定はカーネル内で 10µs 未満、NFQUEUE 経由は p99 で 1ms 未満 |
| LAN・ループバック宛（192.168.x・127.0.0.x の自前サーバー、未署名のクライアント） | 既定では保留も拒否もされない（§10.4-3） |
| ストリーミングの応答（ローカルで数秒かけて少しずつ返すサーバー） | 最初の接続の判定のあとは遅延なく流れ、最後まで届く（§10.4-2） |
| 許可ルールに一致する未署名バイナリ（スコア ≥ 100 になる条件） | どの遮断にも掛からない。記録には残る（§10.4-4） |
| 新しく足したルール（遮断の条件） | 既定の期間は記録だけで、拒否しない。期間後に拒否に切り替わる（§10.4-6） |
| 拒否の通知 | 理由・点数・プロセス・宛先と「今回だけ許可」が出る（§10.4-5） |

## 6. 第1弾の検証結果（2026-11-18、クラウドの Linux 環境）
- `cargo test --workspace`：31 件すべて成功。`cargo clippy --workspace --all-targets`：警告 0。
- `tests/harness/run_linux.sh`：A〜E と ntfy 送信の 6 項目すべて PASS。
- 待機時の CPU：20 秒で 0 tick、RSS 約 2.5MB。ただしソケット 29 個の小さな環境での値。
- この環境ではネットワークスタックの都合で、到達できない宛先への SYN_SENT が見えなかった。実機の Ubuntu では見える想定【要検証】。
