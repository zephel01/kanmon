# パッケージの更新の検査（`kanmonctl inspect`）

パッケージ（PyPI・npm）の「指定した版」と「1 つ前の版」の差分を取り、増えた部分だけから、盗む処理によく出る形を拾って点数を付けます。LLM には接続しません。パッケージのコードは実行も import もせず、アーカイブはディスクに展開しません。

## 使い方
```bash
kanmonctl inspect pypi:名前==版 --detections <検知ルールのディレクトリ>
kanmonctl inspect npm:名前@版   --detections …            # スコープ付き：npm:@scope/name@版
kanmonctl inspect npm:名前@版   --base 前の版 --detections …
kanmonctl inspect --file new.whl --base-file old.whl --detections …   # 手元のファイル（.whl・.tar.gz・.tgz）
```
- 版を省くと最新版を調べます。
- `--json` で機械可読の出力、`--all` で所見をすべて表示します（既定は特徴ごとに 3 件まで）。
- 新しく増えた依存は、レジストリで初公開の日を調べます（パッケージ指定のときは常に。`--file` では `--check-deps` を付けたとき）。
- `--as-of 2026-06-16` で「その時点で調べたことにする」（過去の事件の振り返り用。「出来たばかりの依存」「公開から日が浅い」の基準が変わる）。
- 終了コード：0 = warn 未満、2 = warn、3 = critical、1 = 実行エラー（取得できない・ハッシュが合わない・指定の形が正しくない）。

## 位置づけ
入れる前の防御（レジストリ側のブロックリスト、`min-release-age` 等のクールダウン、npm v12 の install スクリプト既定無効）は kanmon の外にあります。inspect はそれを置き換えません。役目は次の 2 つです。

1. 「この更新は入れて大丈夫か」を、報告が出る前に手元で確かめる
2. kanmond の居座りの走査（P3 等）で引っかかったパッケージを、あとから調べる

1 つの特徴だけでは決め手になりません（正規のパッケージにも出ます）。「勝手に動く仕掛け」と「外への送り先」のような組み合わせで重くなります。

## 流れ
1. **取得**：レジストリの JSON（`https://pypi.org/pypi/<名前>/json`・`https://registry.npmjs.org/<名前>`）から版とファイルを決めます。
   - https のみ。許可するホストは `pypi.org`・`files.pythonhosted.org`・`registry.npmjs.org` だけで、リダイレクト先も同じです。
   - TLS の検証は外しません。同梱のルート証明書に加え、OS の証明書（`SSL_CERT_FILE` も効く）を信頼します。
   - ダウンロードしたファイルは、レジストリが示すハッシュ（PyPI は sha256、npm は `dist.integrity` の sha512）と照合します。
2. **比較する版**：対象より前に公開され、版の番号が対象より小さいもののうち、番号が最も大きいもの。取り下げ（yanked）・削除済み・プレリリースは候補にしません（対象がプレリリースのときは含めます）。公開時刻だけで選ぶと、古い系列の保守版（8.3.8 に対する 6.4.6 等）を選んで差分が大きくなるためです。
3. **展開**：メモリ上で読みます。
   - `..`・絶対パス・`\`・NUL を含むパス、リンク等は中身を読まず、所見 `archive_anomaly` にします。
   - 上限：圧縮 50 MiB、展開後の合計 200 MiB、2 万ファイル、1 ファイル 20 MiB、圧縮比 100 倍。超えたらそこで読むのをやめ、所見 `archive_limit` / `oversize_file` にします（エラーで終えません）。共有ライブラリ等のバイナリが大きいのは普通なので、`oversize_file` はコード・テキストのファイルだけです。
4. **差分**：共通の先頭ディレクトリ（npm の `package/` 等）を外し、パスで突き合わせて中身で比べます。変わったファイルは、前の版に同じ行が無い行だけを見ます。
5. **特徴の抽出**：下の表。README・LICENSE・METADATA 等の説明のファイルは見ません。
6. **点数**：所見を 1 件のイベント（`network.kind = inspect`）にまとめ、`detections/70-inspect.yaml` で点数を付けます。閾値はほかの検知と同じ（notice 30・warn 60・critical 100）。

## 特徴と点数
| 特徴 | ルール | 何を見るか | 点 |
|---|---|---|---|
| `install_script` | I1 | npm の `preinstall`・`install`・`postinstall`・`prepare` の追加・変更、sdist の `setup.py` | +25 |
| `pth_exec` | I2 | 増えた `.pth` の `import` 行（Python の起動のたびに実行される） | +40 |
| `new_top_level` | I3 | 前の版に無いトップレベルのモジュール（wheel）、package.json から呼ばれるルート直下の新しいスクリプト（npm） | +15 |
| `entry_changed` | I4 | `main`・`exports`・`bin` の変更、トップレベルの `__init__.py` に増えた import | +10 |
| `obfuscation` | I5 | 200 文字以上の符号化文字列（エントロピー 4.5 超）、`eval(atob(` 等の復号して実行、`_0x…` の名前の大量の並び | +20 |
| `env_harvest` | I6 | 環境変数を回して TOKEN・SECRET 等で選ぶ、`JSON.stringify(process.env)`、`/proc/*/environ` | +25 |
| `cred_paths` | I7 | `.npmrc`・`.git-credentials`・`.netrc`・`.aws/credentials`・`.azure/`・`.docker/config.json`・`.ssh/id_`・`.kube/config`・Hugging Face のトークン・`gh auth token` | +25 |
| `detach` | I8 | `os.fork` と `os.setsid`、`detached: true` と `.unref()`、`nohup` | +15 |
| `exfil_host` | I9 | `exfil_services`（webhook.site 等）。base64 をデコードした中も見る | +30 |
| `chain_rpc` | I10 | `chain_rpc`・`chain_rpc_suffixes`（Ethereum・ICP の公開 RPC） | +30 |
| `raw_ip_url` | I11 | IP アドレスを直接書いた URL（RFC 1918・ループバックは除く） | +15 |
| `hidden_url` | I12 | base64 に隠した URL | +30 |
| `download_exec` | I13 | `curl … \| sh`・`$(curl …)`、curl 等で GitHub Releases 等から実行ファイルを取って chmod | +25 |
| `ci_secrets` | I14 | `toJSON(secrets)`・`ACTIONS_ID_TOKEN_REQUEST`・`ACTIONS_RUNTIME_TOKEN`、パッケージに増えたワークフロー | +20 |
| `archive_anomaly` | I15 | 不正なパス・リンク、読めない package.json | +30 |
| `archive_limit` / `oversize_file` | I16 | 上限を超えたので途中までしか見ていない | +10 |
| `fresh_release` | I17 | 公開から 7 日未満 | +5 |
| `burst_release` | I18 | 前の版から 2 時間以内の公開 | +10 |
| `publisher_changed` | I19 | 公開した人が前の版と違う（npm） | +15 |
| `attestation_dropped` | I20 | 前の版にあった証明（attestation）が無い（npm） | +20 |
| `drop_exec` | I21 | base64 を復号してファイルに書き、実行する | +25 |
| `import_time_exec` | I22 | `__init__.py`・`setup.py` の読み込み・導入だけで取得・外部コマンドの起動が走る、`.pth` の 1 行に `exec` 等を詰める | +20 |
| `dep_from_url` | I23 | GitHub のコミット・URL・ファイルから取る依存が増えた | +30 |
| `new_dependency` | I24 | 依存が増えた | +5 |
| `new_dep_young` | I25 | 増えた依存が、初公開から 30 日以内か、レジストリに無い。本体と同じ「家族」（`typescript` と `@typescript/…`）は除く | +55 |

`download_exec` は、シェルの `curl … \| sh` のほか、コードの中から取って（urllib・requests・`https.get`・外部コマンドの curl）、置いて（`/tmp`・tempfile・ファイル書き込み）、動かす（subprocess・child_process）形も拾う。Python は別名の import（`import subprocess as _s`）にも対応する。`obfuscation` には、大量の空白で行の右端の外へ押し出したコード、`eval(function(` の詰め込み、隠した PowerShell（`-EncodedCommand`・`-WindowStyle Hidden`。UTF-16 の base64 も復号して中の URL を見る）も含む。`binding.gyp` のコマンド展開（`<!(…)`）は導入時のスクリプトとして扱う。

組み合わせ：

| ルール | 条件 | 点 |
|---|---|---|
| IC1 | `pth_exec` か `install_script` と、`exfil_host`・`hidden_url`・`chain_rpc` のどれか | +30 |
| IC2 | `env_harvest` か `cred_paths` と、`exfil_host`・`hidden_url`・`chain_rpc`・`raw_ip_url` のどれか | +30 |
| IC3 | `detach` と `env_harvest` | +15 |
| IC4 | `burst_release` と、`pth_exec`・`install_script`・`new_top_level` のどれか | +15 |
| IC5 | `import_time_exec`・`pth_exec`・`install_script` のどれかと、`download_exec`・`drop_exec` のどれか | +30 |
| IC6 | `obfuscation` と、`install_script`・`dep_from_url`・`new_top_level`・`pth_exec` のどれか | +30 |

手口をまねた合成のサンプルでの点数：agent-framework 型（.pth・新しいトップレベル・環境変数・認証ファイル・切り離し・隠した URL）は critical、keyv 型（preinstall・実行ファイルの取得・RPC・認証ファイル・難読化）は critical、良性の更新は 0〜5 点です。

## 誤検知の確認（2026-11-18）
よく使う良性パッケージの最新の更新 20 件に実行し、すべて notice 未満でした（最大 25 点）。

- PyPI：requests・urllib3・numpy・pydantic・fastapi・setuptools・pytest-cov・coverage・boto3・openai
- npm：react・lodash・typescript・eslint・vite・esbuild・sharp・playwright・axios・@anthropic-ai/sdk

確認の途中で直したこと：

- **比較する版を公開時刻だけで選んでいた**：vite 8.3.8 に対して古い系列の 6.4.6、axios 1.21.1 に対して 0.35.0 を選び、差分が大きくなって warn になった。版の番号で選ぶようにした
- **長い行だけで難読化としていた**：TypeScript の生成コード・型定義（`.d.ts`）に 1 万バイト超の行が普通にある。長さだけでは出さず、符号化文字列・復号して実行・`_0x…` の名前で見るようにした
- **圧縮された JS をダウンロード実行と判定していた**：axios の `*.min.js` の `"http"` と `|` の並びに反応した。シェルの取得（curl・wget 等）とパイプ・`$(…)` の形だけにした
- **説明のファイルを見ていた**：requests の METADATA の「`.netrc` を読む」に反応した。README・LICENSE・METADATA 等は見ないようにした
- **バイナリの大きさを上限超えとしていた**：numpy の共有ライブラリ（20 MiB 超）。コード・テキストだけにした

残っている軽い所見：vite の生成コードに埋め込まれた base64（I5、20 点）、TypeScript のメジャー更新での入口の変更と公開者の違い（I4・I19、25 点）。どちらも単独では通知になりません。

## 実物の悪性パッケージでの評価（2026-11-19）
DataDog Security Labs の [Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset)（Apache-2.0。実際に見つかった悪性パッケージを人が確認したもの）で測った。

- 隔離したクラウドの Linux 環境で、パスワード付きの zip をメモリ上で開いて `--file` で渡しただけ。実行・インストール・import はしていない。サンプルはリポジトリにも成果物にも入れていない。
- 乗っ取り型（compromised_lib）は、レジストリに残っている正規の前の版と比べた。見つかった日を `--as-of` に渡し、その時点で調べたことにした。
- 1 パッケージにつき 1 版を無作為に選んだ。数字は warn 以上になった割合（通知が「警告」以上で出る割合）。

| 組 | 件数 | warn 以上（直す前 → 後） |
|---|---|---|
| PyPI・乗っ取り型（全件） | 16 | 5 → 14 |
| npm・乗っ取り型（調整に使った 150） | 148 | 109 → 120 |
| npm・乗っ取り型（別の 150。初回は手を付けていない組） | 149 | 118 → 140 |
| PyPI・悪意あり型（新規の悪性パッケージ） | 99 | 30 → 58 |
| npm・悪意あり型 | 100 | 28 → 28 |
| 良性の人気パッケージ 100（最新の更新） | 99 | warn 以上 0、notice 3（typescript・vitest・keyv） |

読み方の注意：
- 直した後の数字は、取りこぼしを見ながらルールを直した組なので甘めに出ている。手を付けていない組での最初の数字（npm 乗っ取り型 79%）が実力に近い。別の 150 の「後」は、その組の取りこぼし（出来たばかりの依存を足すだけの @mastra 型）を見て直したあとの数字。
- 悪意あり型は前の版が無く、全ファイルを見る判定。npm の悪意あり型には、中身が package.json だけのものや、Next.js の雛形をそのまま上げた迷惑パッケージが多く、静的に見て分かるものが少ない（23 件は特徴が 1 つも出ない）。inspect の得意は「正規パッケージの更新に増えた部分」で、新規の悪性パッケージは入れる前の防御（レジストリ側の検査・クールダウン）と kanmond の通信の監視に任せる。
- データセットの形が崩れていて評価できないサンプルがあった（PyPI の ultralytics 8.3.41・num2words 0.5.15・xinference 2.6.1）。

取りこぼしから足したもの（v0.3.1）：コードの中から取って置いて動かす形（別名の import を含む）、復号して書いて動かす形、`__init__.py`・`setup.py`・`.pth` で読み込み・導入時に動く形、GitHub のコミットから取る依存、出来たばかりの依存、`binding.gyp` のコマンド展開、大量の空白で隠したコード、隠した PowerShell。

## 限界
- 静的に読むだけなので、実行時に組み立てる処理（文字列の連結で URL を作る、別のサーバーから本体を取る）は見えにくい。取ってくる処理そのもの（`download_exec`・`chain_rpc`・`hidden_url`）で拾う
- 比較する版が同じ攻撃で汚染されていると、差分に出ない。`--base` で古い版を指定する
- 実物の悪性パッケージでの答え合わせはまだしていない（テストは手口をまねた合成のサンプル）【要検証】
- PyPI の wheel はプラットフォーム別に複数あることがある。`py3-none-any` を優先し、比較する版では同じタグのファイルを選ぶ
