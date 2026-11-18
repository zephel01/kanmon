# Windows 版（beta）

kanmon の Windows 版は beta です。**監視と通知だけ**で、通信を止めることはしません。動作の報告・誤検知・「出てほしいのに出なかった」を GitHub の Issue（「動作報告（beta）」）で集めています。

## 先に要点
- **Sysmon が必要です。** kanmon は Sysmon が書く記録（プロセスの起動・接続・DNS）を読みます。セットアップのスクリプトが入れます。
  - Windows 11 で組み込みの Sysmon が使えればそれを使います（2026 年 3 月の累積更新 KB5079473 以降）。
  - 使えなければ winget で Sysinternals 版（`Microsoft.Sysinternals.Sysmon`）を入れます。
- **導入は zip を展開して `kanmon-setup.ps1` を実行するだけです。** 確認・Sysmon・kanmon 本体・トレイ・最後の確認まで 1 本で行います。何度実行してもよく、済んだ手順は飛ばします。更新も同じ手順です。
- 画面右下の通知領域に丸いアイコン（トレイ）が出ます。緑は問題なし、黄は warn、赤は critical、灰は kanmond に届かない状態です。warn 以上の新しい警告はトーストで知らせます。
- 確かめた環境：Windows 11 Pro 26H2（ビルド 26300）、x64。ARM64 と Windows 10 は未確認です。

## 導入
1. [リリース](https://github.com/zephel01/kanmon/releases)から `kanmon-<版>-windows-x64.zip` と `.sha256` を取り、ハッシュを照合します。
   ```powershell
   Get-FileHash .\kanmon-0.4.0-beta.1-windows-x64.zip -Algorithm SHA256
   # .sha256 の値と一致するか
   ```
2. 展開して実行します。管理者でなければ、昇格の確認が出たあと管理者の窓で続きが動きます。
   ```powershell
   Expand-Archive .\kanmon-0.4.0-beta.1-windows-x64.zip -DestinationPath .
   powershell -ExecutionPolicy Bypass -File .\kanmon-0.4.0-beta.1-windows-x64\kanmon-setup.ps1
   ```
   - `-ExecutionPolicy Bypass` はこの 1 回だけに効きます。端末全体の設定は変えません。
   - 「これから行うこと」が出たら `y` で進みます。`-Yes` を付けると確認を省きます。
   - 組み込みの Sysmon を有効にしたときに再起動を求められたら、再起動して同じコマンドをもう一度実行します（終了コード 3）。
3. beta はコード署名をしていません。SmartScreen の警告が出ることがあります。スクリプトは配布物の中の `SHA256SUMS` で各ファイルを照合し、合わなければ止まります。

### スクリプトがすること
- **Sysmon**：入っていなければ入れます。実行ファイルの Microsoft の署名を確かめてから、kanmon 用の設定（`kanmon-sysmon.xml`）で開始します。
  - すでに入っていて、直近 1 時間に Event ID 1・3・22 が出ていれば、今の設定をそのまま使います。
  - 出ていなければ、差し替えるか聞きます。差し替える前の設定は `C:\ProgramData\kanmon\backup\` に控えます。
- **kanmon**：
  - `C:\Program Files\kanmon\` に `kanmond.exe`・`kanmonctl.exe`・`kanmon-tray.exe`・`kanmon-setup.ps1` を置きます。
  - `C:\ProgramData\kanmon\` に設定・ルール・データ・ログを置きます。`kanmon.toml` と `kanmon-sysmon.xml` は、あれば上書きしません。
  - 2 つのフォルダは、Administrators と SYSTEM だけが書けるようにします。一般ユーザーにルールを書き換えられると、検知を黙らせられるためです。
  - サービス `kanmond` を登録します（自動起動、落ちたら 1 分後に起こし直す）。
  - トレイをログオン時に起動するよう `HKLM\…\Run` に登録します。PATH にも足します。
- 記録は `C:\ProgramData\kanmon\logs\setup-日時.log` に残します。

### 主なオプション
| オプション | 意味 |
|---|---|
| `-CheckOnly` | 確かめるだけ（何も変えない）。`-Json` で報告用の JSON（ユーザー名・ホスト名・ホームのパスは伏せる） |
| `-SysmonOnly` | Sysmon だけを用意する（`-CheckOnly` と一緒なら Sysmon だけ確かめる） |
| `-SysmonMethod Builtin\|Winget` | Sysmon の入れ方を固定する（既定は Auto） |
| `-ReplaceSysmonConfig` | 今の Sysmon の設定を kanmon 用に差し替える |
| `-SkipSysmon` | Sysmon に触らない |
| `-Uninstall` | kanmon を外す。`-Purge` で設定とログも、`-RemoveSysmon` で Sysmon も |

終了コード：0 = すべて OK、1 = WARN あり、2 = NG あり、3 = 再起動が必要、4 = 中止・失敗。

## あとで確かめる
```powershell
powershell -ExecutionPolicy Bypass -File 'C:\Program Files\kanmon\kanmon-setup.ps1' -CheckOnly
kanmonctl tail -f              # 新しく開いた PowerShell で（Ctrl+C で止める）
kanmonctl alerts --hours 1 --min-level notice
```
- kanmond のログ：`C:\ProgramData\kanmon\logs\kanmond.<日付>.log`
- 警告の記録：`C:\ProgramData\kanmon\logs\events.jsonl`
- `notify.local = true` なら、Windows のイベントログ（アプリケーション、ソース `kanmon`）にも書きます。イベント ID は notice 1・warn 2・critical 3 です。

### 通知のテスト
居座りのテストとして、無害な値を Run キーに足して、通知を確かめたら消します。
```powershell
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'kanmon-test' -Value 'C:\Windows\System32\notepad.exe' -PropertyType String
# 通知と kanmonctl alerts を確かめたら消す
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'kanmon-test'
```
居座りの走査は 1 時間おきです。Sysmon が Run キーの変更を記録すると早まります（前回から 2 分以上たっていれば）。初回の走査は基準を取るだけなので、差分は 2 回目から出ます。

## しくみ
| 何を | どうやって |
|---|---|
| 接続の一覧（pid 付き） | `GetExtendedTcpTable`・`GetExtendedUdpTable` を 1 秒ごと |
| 一覧に出る前に終わる短い接続 | Sysmon の Event ID 3 |
| 宛先の名前（どのプロセスが引いたか） | Sysmon の Event ID 22 |
| 親・コマンドライン・ユーザー | Sysmon の Event ID 1（起動時に直近 2 万件を読み戻す）。無ければ Win32 API |
| 署名 | `Get-AuthenticodeSignature`（カタログ署名を含む）。`microsoft` / `signed_other` / `unsigned` / `invalid` / `unknown` |
| 居座り | Run・RunOnce（全ユーザー）・Winlogon・IFEO の Debugger・自動起動のサービス・スタートアップ・タスク スケジューラ・PowerShell のプロファイル・Python の `.pth`・`.claude`・`.vscode`・`.github/workflows`・`.git/hooks` |
| トレイとのやり取り | 名前付きパイプ `\\.\pipe\kanmon`（読むだけ。ACL で SYSTEM・Administrators・対話ログオンのユーザーに限る。ネットワーク経由は拒否。他のプロセスが同じ名前を先に作っていたら起動しない） |

Windows 向けの検知ルール：
- `W1`：rundll32・regsvr32・mshta・certutil 等（LOLBin）がインターネットへ接続（40 点）
- `W2`：PowerShell の `-EncodedCommand`（30 点）
- 既存のルール（S2・S4・S6 等）も、Windows のプロセス名・パスで当たるようにしてあります。Windows のプロセス名は小文字にそろえて比べます。

## 既知の制限（beta）
- **つながらなかった接続は Sysmon に出ません**（実機で確認）。連絡先が落ちている・遮断されている間の接続の試みは見えないので、その間は DNS の問い合わせ（ID 22）で追います。
- 送信量（大きなアップロードの検知、55-volume）は取りません。
- DNS の改ざんの検知のうち、DNS サーバーの変更（N2）と DoH での照合（N3）は Windows では動きません。hosts の書き換え（N1）と、公開ドメインがローカルの IP に解決される件（N4）は動きます。
- 遮断はしません（設計書 §10.4 の約束どおり、まず監視で信頼を作る）。
- トーストの送り主（`Kanmon.Tray`）は HKCU に登録して使います。環境によっては出ないことがあります【要検証】。そのときはトレイの色とメニューで確かめてください。
- MSI・winget のパッケージ・コード署名は後で入れます。

## 外す
```powershell
$s = 'C:\Program Files\kanmon\kanmon-setup.ps1'
powershell -ExecutionPolicy Bypass -File $s -Uninstall                 # kanmon だけ（設定とログは残す）
powershell -ExecutionPolicy Bypass -File $s -Uninstall -Purge          # 設定とログも消す
powershell -ExecutionPolicy Bypass -File $s -Uninstall -RemoveSysmon   # Sysmon も外す（他で使っていなければ）
```

## 報告
GitHub の Issue「動作報告（beta）」に、次を貼ってください。
- `kanmon-setup.ps1 -CheckOnly -Json` の出力（ユーザー名・ホスト名・ホームのパスは伏せられます）
- 誤検知・出なかったものは、`kanmonctl alerts` の該当行と、何をしていたか

ログに社内のドメインなどが入っていないか、貼る前に確かめてください。
