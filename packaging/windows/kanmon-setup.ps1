<#
.SYNOPSIS
  kanmon（Windows 版 beta）の確認・セットアップ・アンインストールを 1 本で行う。

.DESCRIPTION
  引数なしで実行すると、次を順に行う（済んでいる手順は飛ばすので、何度実行してもよい）。
    1. 管理者でなければ、管理者として自分を起動し直す
    2. 今の状態を確かめ、これから行うことを表示して確認を取る（-Yes で省略）
    3. Sysmon を用意する
       - 無ければ入れる：Windows 11 の組み込み Sysmon が使えればそれ、無ければ winget で Sysinternals 版
       - 実行ファイルの Microsoft の署名を確かめてから動かす
       - kanmon 用の設定（kanmon-sysmon.xml）を当てる。すでに別の設定で ID 1・3・22 が
         取れているなら差し替えない（-ReplaceSysmonConfig で差し替える）
    4. kanmon を入れる（更新も同じ手順）
       - C:\Program Files\kanmon に実行ファイル、C:\ProgramData\kanmon に設定とルール
       - 設定フォルダは Administrators と SYSTEM だけが書けるようにする
       - サービス kanmond を登録して開始する。PATH に足す
       - トレイ（kanmon-tray.exe）をログオン時に起動するよう登録し、今の利用者の画面にも起動する
    5. もう一度確かめて結果を表示する

  -CheckOnly：確かめるだけ（何も変えない）
  -Uninstall：kanmon を外す（-Purge で設定とログも、-RemoveSysmon で Sysmon も）

  終了コード：0 = すべて OK、1 = WARN あり、2 = NG あり、3 = 再起動が必要、4 = 中止・失敗

.PARAMETER CheckOnly
  確かめるだけ。何も変更しない。
.PARAMETER Uninstall
  kanmon を外す。
.PARAMETER Purge
  -Uninstall と一緒に使う。C:\ProgramData\kanmon（設定・ルール・ログ）も消す。
.PARAMETER RemoveSysmon
  -Uninstall と一緒に使う。Sysmon も外す（他の用途で使っているなら付けない）。
.PARAMETER SysmonMethod
  Auto（既定）：組み込み版が使えればそれ、無ければ winget。Builtin / Winget で固定もできる。
.PARAMETER ReplaceSysmonConfig
  すでに入っている Sysmon の設定を kanmon 用に差し替える（差し替え前の設定は控えを残す）。
.PARAMETER SkipSysmon
  Sysmon に触らない（入れない・設定も変えない）。
.PARAMETER SysmonOnly
  Sysmon だけを用意する（kanmon は入れない）。-CheckOnly と一緒なら Sysmon だけ確かめる。
  配布物が無くても動く（kanmon 用の Sysmon 設定はこのスクリプトに入っている）。
.PARAMETER Source
  配布物（zip を展開したフォルダ）の場所。既定はこのスクリプトのあるフォルダ。
.PARAMETER Yes
  確認を求めずに進める。
.PARAMETER NoProbe
  確認の試験（DNS の問い合わせと文書用 IP への接続）を行わない。
.PARAMETER Json
  -CheckOnly と一緒に使う。結果を JSON で出す（ユーザー名・ホスト名・ホームのパスは伏せる）。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\kanmon-setup.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\kanmon-setup.ps1 -CheckOnly
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\kanmon-setup.ps1 -SysmonOnly
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File 'C:\Program Files\kanmon\kanmon-setup.ps1' -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$RemoveSysmon,
    [ValidateSet('Auto', 'Builtin', 'Winget')] [string]$SysmonMethod = 'Auto',
    [switch]$ReplaceSysmonConfig,
    [switch]$SkipSysmon,
    [switch]$SysmonOnly,
    [string]$Source = '',
    [switch]$Yes,
    [switch]$NoProbe,
    [switch]$Json
)

# Windows PowerShell 5.1 でも動くように書く（?? や三項演算子は使わない）。
# このファイルは UTF-8（BOM 付き）で保存する。BOM が無いと 5.1 が日本語を読み違える。

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ------------------------------------------------------------------ 定数
$SysmonLog     = 'Microsoft-Windows-Sysmon/Operational'
$SysmonWingetId = 'Microsoft.Sysinternals.Sysmon'
$ProbeIp       = '203.0.113.10'   # RFC 5737 TEST-NET-3。どこにも届かない
$ProbePort     = 443
$ProbeName     = 'example.com'
$KanmonBin     = Join-Path $env:ProgramFiles 'kanmon'
$KanmonData    = Join-Path $env:ProgramData 'kanmon'
$KanmonSvc     = 'kanmond'
$KanmonToml    = Join-Path $KanmonData 'kanmon.toml'
$KanmonDet     = Join-Path $KanmonData 'detections'
$SysmonCfgName = 'kanmon-sysmon.xml'
$KanmondArgs   = "--service --config `"$KanmonToml`""
$TrayRunKey    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$TrayRunName   = 'kanmon-tray'
$KanmondLog    = Join-Path $KanmonData 'logs\kanmond.log'
$RequiredIds   = @(1, 3, 5, 22)
$NeededIds     = @(1, 3, 22)      # これが取れていれば既存の Sysmon 設定を使ってよい

# kanmon 用の Sysmon 設定（配布物の kanmon-sysmon.xml と同じ内容）。
# スクリプト 1 本だけで -SysmonOnly を使えるように埋め込んでおく
$EmbeddedSysmonConfig = @'
<!--
  kanmon 用の Sysmon 設定（beta）
  - 取るもの：プロセスの起動と終了（ID 1・5）、プロセスが始めた接続（ID 3）、
    DNS の問い合わせ（ID 22）、居座りに関わるファイルの作成（ID 11）、
    自動起動に関わるレジストリの変更（ID 12〜14）。
  - 既定の Sysmon は接続（ID 3）を取らない。この設定で有効にする。
  - schemaversion は古めの 4.50 にしてある。新しい Sysmon は古いスキーマを受け付ける。
    【要検証】実機で `sysmon -c` が警告を出さないか（出たら `sysmon -s` で版を確かめる）。
  - ID 3・22 は全部取るのでイベントが多い。重いと感じたら <NetworkConnect onmatch="exclude">
    に除外を足す（例：ブラウザ）。kanmon は全体を見たいので、beta では絞らない。
-->
<Sysmon schemaversion="4.50">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>

    <!-- ID 1：プロセスの起動。全部取る -->
    <RuleGroup name="kanmon-process-create" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>

    <!-- ID 5：プロセスの終了。kanmon のプロセス表を片付けるのに使う -->
    <RuleGroup name="kanmon-process-terminate" groupRelation="or">
      <ProcessTerminate onmatch="exclude"/>
    </RuleGroup>

    <!-- ID 3：接続。kanmond 自身（Webhook の送信）は除く -->
    <RuleGroup name="kanmon-network" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="end with">\kanmond.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- ID 22：DNS の問い合わせ。どのプロセスが引いたかが取れる -->
    <RuleGroup name="kanmon-dns" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <Image condition="end with">\kanmond.exe</Image>
      </DnsQuery>
    </RuleGroup>

    <!-- ID 11：居座りに関わる場所へのファイル作成だけ取る -->
    <RuleGroup name="kanmon-file-create" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="end with">.pth</TargetFilename>
        <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
        <TargetFilename condition="end with">\.claude\settings.json</TargetFilename>
        <TargetFilename condition="end with">\.claude\settings.local.json</TargetFilename>
        <TargetFilename condition="contains">\.github\workflows\</TargetFilename>
        <TargetFilename condition="contains">\.git\hooks\</TargetFilename>
        <TargetFilename condition="contains">\.vscode\</TargetFilename>
        <TargetFilename condition="begin with">C:\Windows\System32\Tasks\</TargetFilename>
        <TargetFilename condition="contains">\WindowsPowerShell\profile.ps1</TargetFilename>
        <TargetFilename condition="contains">\PowerShell\profile.ps1</TargetFilename>
        <TargetFilename condition="end with">_profile.ps1</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- ID 12〜14：自動起動に関わるレジストリだけ取る -->
    <RuleGroup name="kanmon-registry" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\CurrentVersion\Policies\Explorer\Run</TargetObject>
        <TargetObject condition="contains">\Windows NT\CurrentVersion\Winlogon\</TargetObject>
        <TargetObject condition="contains">\Image File Execution Options\</TargetObject>
        <TargetObject condition="end with">\ImagePath</TargetObject>
        <TargetObject condition="contains">\Environment\UserInitMprLogonScript</TargetObject>
      </RegistryEvent>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
'@

$EXIT_OK = 0; $EXIT_WARN = 1; $EXIT_NG = 2; $EXIT_REBOOT = 3; $EXIT_FAIL = 4

if (-not $Source) { $Source = $PSScriptRoot }

# ------------------------------------------------------------------ 表示
function Write-Step { param([string]$Text) Write-Host ''; Write-Host "== $Text" -ForegroundColor Cyan }
function Write-Info { param([string]$Text) Write-Host "   $Text" }
function Write-Done { param([string]$Text) Write-Host "   済：$Text" -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host "   注意：$Text" -ForegroundColor Yellow }
function Stop-Setup {
    param([string]$Text, [int]$Code = 4)
    Write-Host ''
    Write-Host "中止：$Text" -ForegroundColor Red
    exit $Code
}

function Confirm-Step {
    param([string]$Question)
    if ($Yes) { return $true }
    $a = Read-Host "$Question [y/N]"
    return ($a -match '^(y|yes|はい)$')
}

# ------------------------------------------------------------------ 共通
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Arch {
    $a = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $a = $env:PROCESSOR_ARCHITEW6432 }
    return $a
}

# サービスの ImagePath から実行ファイルのパスを取り出す（引用符と引数を外す）
function Get-ServiceExePath {
    param([string]$Name)
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $svc -or -not $svc.PathName) { return $null }
    $raw = $svc.PathName.Trim()
    if ($raw.StartsWith('"')) {
        $end = $raw.IndexOf('"', 1)
        if ($end -gt 1) { return $raw.Substring(1, $end - 1) }
    }
    $exeEnd = $raw.ToLower().IndexOf('.exe')
    if ($exeEnd -gt 0) { return $raw.Substring(0, $exeEnd + 4) }
    return $raw
}

function Test-MicrosoftSigned {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = ''
    if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
    return ($sig.Status -eq 'Valid' -and $subject -match 'O=Microsoft Corporation')
}

# 組み込み Sysmon（Windows の機能）の状態：Enabled / Disabled / EnablePending / Absent
function Get-SysmonFeatureState {
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction Stop
        if ($f) { return [string]$f.State }
    } catch { }
    return 'Absent'
}

# Sysmon のサービス（ドライバ SysmonDrv は除く）
# 注意：関数の戻り値の配列は展開される（0 件なら $null、1 件ならその要素）。
# StrictMode では $null や単体の要素に .Count が無いので、呼ぶ側で必ず @(Get-SysmonServices) と包む
function Get-SysmonServices {
    return @(Get-Service -Name 'sysmon*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'drv$' })
}

# 直近 N 分に出た Sysmon の Event ID ごとの件数
function Get-SysmonIdCounts {
    param([int]$Minutes = 30)
    $seen = @{}
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; StartTime = (Get-Date).AddMinutes(-$Minutes) } -MaxEvents 5000 -ErrorAction Stop |
            ForEach-Object { $seen[[int]$_.Id] = 1 + [int]$seen[[int]$_.Id] }
    } catch { }
    return $seen
}

function Update-SessionPath {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$m;$u"
}

# Users・Authenticated Users・Everyone が書き込めるかを見る（SID で判定し、言語に依存しない）
function Get-WeakWriters {
    param([string]$Path)
    $weakSids = @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0')
    # Modify や FullControl は読み取りの bit も含むので使わない。書き込み系の bit だけを見る。
    # 0x40000000 = GENERIC_WRITE、0x10000000 = GENERIC_ALL（継承用の ACE に出る）
    $writeBits = [int64]([Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership')
    $writeBits = $writeBits -bor 0x40000000 -bor 0x10000000
    $found = @()
    $acl = Get-Acl -LiteralPath $Path
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        try {
            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch { continue }
        if ($weakSids -notcontains $sid) { continue }
        if (([int64]$ace.FileSystemRights -band $writeBits) -ne 0) {
            $found += "$($ace.IdentityReference) ($($ace.FileSystemRights))"
        }
    }
    return $found
}

# ================================================================== 確認
$script:Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [Parameter(Mandatory)] [string]$Area,
        [Parameter(Mandatory)] [string]$Check,
        [Parameter(Mandatory)] [ValidateSet('OK', 'WARN', 'NG', 'SKIP', 'INFO')] [string]$Status,
        [string]$Detail = '',
        [string]$Fix = ''
    )
    $script:Results.Add([pscustomobject]@{ Area = $Area; Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix })
}

function Invoke-Check {
    param([switch]$SysmonOnlyCheck, [switch]$Probe)
    $script:Results.Clear()

    # ---- OS
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $dv = ''
    if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { $dv = $cv.DisplayVersion }
    $arch = Get-Arch
    Add-Result 'OS' '版' 'INFO' "$($os.Caption) $dv（ビルド $($cv.CurrentBuildNumber).$($cv.UBR)、$arch）"
    if ($arch -eq 'AMD64') { Add-Result 'OS' 'アーキテクチャ' 'OK' 'x64' }
    elseif ($arch -eq 'ARM64') { Add-Result 'OS' 'アーキテクチャ' 'WARN' 'ARM64 は beta では未確認' '動作報告に「ARM64」と書いてほしい' }
    else { Add-Result 'OS' 'アーキテクチャ' 'NG' "$arch には対応しない" }

    # ---- Sysmon
    $feature = Get-SysmonFeatureState
    $svcs = @(Get-SysmonServices)
    # Get-Service はカーネルのドライバを返さないので Win32_SystemDriver で見る
    $drv = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name LIKE 'Sysmon%'" -ErrorAction SilentlyContinue)
    if ($feature -eq 'Absent') { Add-Result 'Sysmon' '組み込み版（Windows の機能）' 'INFO' 'この Windows には無い（winget で入れる）' }
    else { Add-Result 'Sysmon' '組み込み版（Windows の機能）' 'INFO' "状態：$feature" }

    if ($svcs.Count -gt 1) {
        Add-Result 'Sysmon' '重複' 'NG' ('Sysmon のサービスが複数ある：' + (($svcs | ForEach-Object Name) -join ', ')) 'どちらか一方を sysmon -u で外す'
    }
    if ($svcs.Count -eq 0) {
        Add-Result 'Sysmon' 'サービス' 'NG' 'Sysmon が動いていない' 'このスクリプトを引数なしで実行すると入れる'
    } else {
        $s = $svcs[0]
        $label = 'Sysinternals 版'
        if ($feature -eq 'Enabled') { $label = '組み込み版' }
        if ($s.Status -eq 'Running') { Add-Result 'Sysmon' 'サービス' 'OK' "$($s.Name)（$label）" }
        else { Add-Result 'Sysmon' 'サービス' 'NG' "$($s.Name) の状態：$($s.Status)" "Start-Service $($s.Name)" }
        $drvRun = @($drv | Where-Object { $_.State -eq 'Running' })
        if ($drvRun.Count -gt 0) { Add-Result 'Sysmon' 'ドライバ' 'OK' (($drvRun | ForEach-Object Name) -join ', ') }
        else { Add-Result 'Sysmon' 'ドライバ' 'WARN' 'ドライバが見つからないか止まっている' 'sysmon -u のあとこのスクリプトを実行し直す' }
        $exe = Get-ServiceExePath $s.Name
        if ($exe -and (Test-Path -LiteralPath $exe)) {
            Add-Result 'Sysmon' '版' 'INFO' "$((Get-Item -LiteralPath $exe).VersionInfo.FileVersion)（$exe）"
            if (Test-MicrosoftSigned $exe) { Add-Result 'Sysmon' '署名' 'OK' 'Microsoft の署名' }
            else { Add-Result 'Sysmon' '署名' 'NG' 'Microsoft の署名が確かめられない' 'Microsoft 以外から入れた Sysmon は使わない。外して入れ直す' }
            if ($feature -ne 'Enabled') {
                Add-Result 'Sysmon' '更新' 'INFO' 'Sysinternals 版は自分で更新する（古い版に権限昇格の脆弱性の報告あり）' "winget upgrade --id $SysmonWingetId --exact"
            }
        }
    }

    $logOk = $false
    $seen = @{}
    try {
        $log = Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop
        $logOk = $true
        $mb = [math]::Round($log.MaximumSizeInBytes / 1MB)
        Add-Result 'Sysmon ログ' 'チャネル' 'OK' "$SysmonLog（$($log.RecordCount) 件）"
        if ($mb -lt 128) { Add-Result 'Sysmon ログ' '上限' 'WARN' "$mb MB。古い記録がすぐ消える" 'このスクリプトを実行すると 256 MB にする' }
        else { Add-Result 'Sysmon ログ' '上限' 'OK' "$mb MB" }
    } catch {
        Add-Result 'Sysmon ログ' 'チャネル' 'NG' "$SysmonLog が無い" 'Sysmon を入れる。組み込み版でチャネル名が違う場合は動作報告に書いてほしい'
    }
    if ($logOk) {
        $seen = Get-SysmonIdCounts 30
        foreach ($id in $RequiredIds) {
            if ($seen.ContainsKey($id)) { Add-Result 'Sysmon ログ' "Event ID $id（直近30分）" 'OK' "$($seen[$id]) 件" }
            elseif ($id -eq 5) { Add-Result 'Sysmon ログ' "Event ID $id（直近30分）" 'INFO' '出ていない' }
            else { Add-Result 'Sysmon ログ' "Event ID $id（直近30分）" 'WARN' '出ていない（設定で無効か、まだ起きていない）' 'このスクリプトに -ReplaceSysmonConfig を付けて実行する' }
        }
    }

    # ---- 試験
    if (-not $Probe) {
        Add-Result '試験' 'DNS・接続の記録' 'SKIP' '省略'
    } elseif (-not $logOk) {
        Add-Result '試験' 'DNS・接続の記録' 'SKIP' 'Sysmon のログが読めない'
    } else {
        $t0 = (Get-Date).AddSeconds(-2)
        # Resolve-DnsName は Windows の DNS クライアントを通るので ID 22 になる（nslookup はならない）
        try { Resolve-DnsName -Name $ProbeName -Type A -ErrorAction Stop | Out-Null } catch { }
        # つながる接続：自分で 127.0.0.1 に待ち受けを作り、そこへつなぐ（外へは出ない）
        $lport = 0
        $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
        $cli = New-Object System.Net.Sockets.TcpClient
        try {
            $listener.Start()
            $lport = $listener.LocalEndpoint.Port
            $cli.Connect('127.0.0.1', $lport)
        } catch { } finally { $cli.Close(); $listener.Stop() }
        # つながらない接続：文書用 IP へ 2 秒だけ試す（記録されるかを知るため。結果は INFO）
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $tcp.BeginConnect($ProbeIp, $ProbePort, $null, $null)
            [void]$iar.AsyncWaitHandle.WaitOne(2000)
        } catch { } finally { $tcp.Close() }

        # Sysmon の接続の記録は数秒遅れることがあるので、最大 15 秒待つ
        $dnsHit = $null; $loopHit = $null; $netHit = $null
        for ($i = 0; $i -lt 15; $i++) {
            Start-Sleep -Seconds 1
            $hits = @()
            try { $hits = @(Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; Id = 3, 22; StartTime = $t0 } -ErrorAction Stop) } catch { }
            $dnsHit  = @($hits | Where-Object { $_.Id -eq 22 -and $_.Message -match [regex]::Escape($ProbeName) -and $_.Message -match "ProcessId: $PID\b" })
            $loopHit = @($hits | Where-Object { $_.Id -eq 3 -and $lport -gt 0 -and $_.Message -match "DestinationPort: $lport\b" })
            $netHit  = @($hits | Where-Object { $_.Id -eq 3 -and $_.Message -match [regex]::Escape($ProbeIp) })
            if ($dnsHit.Count -gt 0 -and $loopHit.Count -gt 0) { break }
        }
        if ($dnsHit.Count -gt 0) { Add-Result '試験' "DNS（$ProbeName）→ ID 22" 'OK' 'このスクリプトの問い合わせとして記録された' }
        else {
            $st = 'NG'; if ($seen.ContainsKey(22)) { $st = 'WARN' }
            Add-Result '試験' "DNS（$ProbeName）→ ID 22" $st '記録されない' 'このスクリプトに -ReplaceSysmonConfig を付けて実行する'
        }
        if ($loopHit.Count -gt 0) { Add-Result '試験' "接続（127.0.0.1:$lport）→ ID 3" 'OK' '記録された' }
        else { Add-Result '試験' "接続（127.0.0.1:$lport）→ ID 3" 'NG' '15 秒待っても記録されない。Sysmon の設定で接続（NetworkConnect）が無効の可能性' 'このスクリプトに -ReplaceSysmonConfig を付けて実行する。直らなければ sysmon -c の出力を動作報告に貼る' }
        if ($netHit.Count -gt 0) { Add-Result '試験' "つながらない接続（${ProbeIp}:$ProbePort）→ ID 3" 'INFO' '記録された' }
        else { Add-Result '試験' "つながらない接続（${ProbeIp}:$ProbePort）→ ID 3" 'INFO' '記録されない（つながらない接続は記録されない）' }
    }

    if ($SysmonOnlyCheck) { return }

    # ---- kanmon
    $ks = Get-Service -Name $KanmonSvc -ErrorAction SilentlyContinue
    $installed = ($ks -or (Test-Path -LiteralPath (Join-Path $KanmonBin 'kanmond.exe')))
    if (-not $installed) {
        Add-Result 'kanmon' '導入' 'NG' 'kanmon は入っていない' 'このスクリプトを配布物のフォルダで引数なしで実行する'
        # 前回の途中で作られたフォルダがあれば、権限だけは見る
        if (Test-Path -LiteralPath $KanmonData) {
            $weak = @(Get-WeakWriters $KanmonData)
            if ($weak.Count -gt 0) { Add-Result 'kanmon' "権限 $KanmonData" 'WARN' ('一般ユーザーが書ける：' + ($weak -join '; ')) '導入時に絞り直す。使わないならフォルダを消してよい' }
        }
        return
    }
    if (-not $ks) {
        Add-Result 'kanmon' 'サービス' 'NG' "$KanmonSvc が無い" 'このスクリプトを引数なしで実行する'
    } else {
        $kc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$KanmonSvc'"
        if ($ks.Status -eq 'Running') { Add-Result 'kanmon' 'サービス' 'OK' "Running（$($kc.StartMode)、$($kc.StartName)）" }
        else { Add-Result 'kanmon' 'サービス' 'NG' "状態：$($ks.Status)" "Start-Service $KanmonSvc。起動しない場合は Get-WinEvent -LogName Application -MaxEvents 20 を見る" }
        if ($kc.StartMode -ne 'Auto') { Add-Result 'kanmon' '自動起動' 'WARN' "StartMode = $($kc.StartMode)" "Set-Service $KanmonSvc -StartupType Automatic" }
    }
    foreach ($f in @('kanmond.exe', 'kanmonctl.exe', 'kanmon-tray.exe')) {
        $p = Join-Path $KanmonBin $f
        if (Test-Path -LiteralPath $p) { Add-Result 'kanmon' $f 'OK' ((Get-Item -LiteralPath $p).VersionInfo.FileVersion) }
        else { Add-Result 'kanmon' $f 'NG' "$p が無い" 'このスクリプトを引数なしで実行する' }
    }
    # kanmond が Sysmon を読めているか（kanmond.log の起動時の行）
    $logs = @(Get-ChildItem -LiteralPath (Split-Path $KanmondLog) -Filter 'kanmond*.log' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($logs.Count -gt 0) {
        # kanmond のログは BOM なしの UTF-8。5.1 の既定（ANSI）で読むと日本語が化けるので指定する
        $tail = Get-Content -LiteralPath $logs[0].FullName -Tail 400 -Encoding UTF8 -ErrorAction SilentlyContinue
        # 最後に出た「購読した／できない」の行で判断する（再起動のたびに 1 行出る）
        $last = @($tail | Where-Object { $_ -match 'Sysmon の記録を購読' }) | Select-Object -Last 1
        if (-not $last) {
            Add-Result 'kanmon' 'Sysmon の購読' 'INFO' 'ログに起動時の行が無い（ログが回った可能性）'
        } elseif ($last -match '購読できません') {
            Add-Result 'kanmon' 'Sysmon の購読' 'NG' 'kanmond が Sysmon の記録を読めない' "$($logs[0].FullName) を見る。Sysmon を入れたあとは Restart-Service kanmond"
        } else {
            Add-Result 'kanmon' 'Sysmon の購読' 'OK' 'kanmond が Sysmon の記録を読んでいる'
        }
    } else {
        Add-Result 'kanmon' 'Sysmon の購読' 'WARN' 'kanmond のログが無い' 'Get-Service kanmond で動いているか見る'
    }
    # トレイ：ログオン時の起動の登録と、今動いているか
    $run = Get-ItemProperty -LiteralPath $TrayRunKey -Name $TrayRunName -ErrorAction SilentlyContinue
    if ($run) { Add-Result 'kanmon' 'トレイの自動起動' 'OK' $run.$TrayRunName }
    else { Add-Result 'kanmon' 'トレイの自動起動' 'WARN' '登録が無い' 'このスクリプトを引数なしで実行する' }
    if (@(Get-Process -Name 'kanmon-tray' -ErrorAction SilentlyContinue).Count -gt 0) { Add-Result 'kanmon' 'トレイ' 'OK' '動いている' }
    else { Add-Result 'kanmon' 'トレイ' 'INFO' '動いていない（次のログオンで起動する）' "`"$KanmonBin\kanmon-tray.exe`" を実行すれば今すぐ出る" }
    if (Test-Path -LiteralPath $KanmonToml) { Add-Result 'kanmon' '設定' 'OK' $KanmonToml }
    else { Add-Result 'kanmon' '設定' 'NG' "$KanmonToml が無い" 'このスクリプトを引数なしで実行する' }
    $n = 0
    if (Test-Path -LiteralPath $KanmonDet) { $n = @(Get-ChildItem -LiteralPath $KanmonDet -Filter '*.yaml' -File).Count }
    if ($n -gt 0) { Add-Result 'kanmon' 'ルール' 'OK' "$n ファイル" }
    else { Add-Result 'kanmon' 'ルール' 'NG' 'YAML が無い' 'このスクリプトを引数なしで実行する' }
    # 設定・ルールを一般ユーザーが書き換えられると、検知を黙らせられる
    foreach ($p in @($KanmonData, $KanmonDet, $KanmonBin)) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $weak = @(Get-WeakWriters $p)
        if ($weak.Count -eq 0) { Add-Result 'kanmon' "権限 $p" 'OK' '一般ユーザーは書けない' }
        else { Add-Result 'kanmon' "権限 $p" 'NG' ('一般ユーザーが書ける：' + ($weak -join '; ')) 'このスクリプトを引数なしで実行する（権限を絞り直す）' }
    }
    $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (($mp -split ';') -contains $KanmonBin) { Add-Result 'kanmon' 'PATH' 'OK' $KanmonBin }
    else { Add-Result 'kanmon' 'PATH' 'WARN' 'PATH に無い' 'このスクリプトを引数なしで実行する' }
}

function Get-CheckExitCode {
    $ng   = @($script:Results | Where-Object Status -eq 'NG').Count
    $warn = @($script:Results | Where-Object Status -eq 'WARN').Count
    if ($ng -gt 0) { return $EXIT_NG }
    if ($warn -gt 0) { return $EXIT_WARN }
    return $EXIT_OK
}

function Show-Check {
    $color = @{ OK = 'Green'; WARN = 'Yellow'; NG = 'Red'; SKIP = 'DarkGray'; INFO = 'Cyan' }
    $area = ''
    foreach ($r in $script:Results) {
        if ($r.Area -ne $area) { $area = $r.Area; Write-Host ''; Write-Host "[$area]" }
        Write-Host ('  {0,-5}' -f $r.Status) -ForegroundColor $color[$r.Status] -NoNewline
        $line = " $($r.Check)"
        if ($r.Detail) { $line += "：$($r.Detail)" }
        Write-Host $line
        if ($r.Fix -and ($r.Status -eq 'NG' -or $r.Status -eq 'WARN')) { Write-Host "         → $($r.Fix)" -ForegroundColor DarkYellow }
    }
    $ng   = @($script:Results | Where-Object Status -eq 'NG').Count
    $warn = @($script:Results | Where-Object Status -eq 'WARN').Count
    Write-Host ''
    if ($ng + $warn -eq 0) { Write-Host '結果：すべて OK' -ForegroundColor Green }
    elseif ($ng -gt 0) { Write-Host "結果：NG $ng 件、WARN $warn 件" -ForegroundColor Red }
    else { Write-Host "結果：WARN $warn 件" -ForegroundColor Yellow }
}

function Show-CheckJson {
    $text = [pscustomobject]@{
        tool         = 'kanmon-setup -CheckOnly'
        generated_at = (Get-Date).ToString('o')
        results      = $script:Results
    } | ConvertTo-Json -Depth 5
    # 報告用：ユーザー名・ホスト名・ホームのパスを伏せる。JSON 内では \ が \\ になるので両方を置き換える
    $pairs = @(@($env:USERPROFILE, '%USERPROFILE%'), @($env:COMPUTERNAME, '<host>'), @($env:USERNAME, '<user>'))
    foreach ($pr in $pairs) {
        if (-not $pr[0]) { continue }
        foreach ($v in @($pr[0], $pr[0].Replace('\', '\\'))) {
            $pat = '(?<![A-Za-z0-9_])' + [regex]::Escape($v) + '(?![A-Za-z0-9_])'
            $text = [regex]::Replace($text, $pat, $pr[1], 'IgnoreCase')
        }
    }
    Write-Output $text
}

# ================================================================== Sysmon の用意
# winget で入れた Sysmon の実行ファイルを探す（アーキテクチャに合うもの）
function Find-WingetSysmonExe {
    $names = @('Sysmon64.exe', 'Sysmon.exe')
    if ((Get-Arch) -eq 'ARM64') { $names = @('Sysmon64a.exe') }
    $roots = @(
        (Join-Path $env:ProgramFiles 'WinGet\Packages'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages')
    )
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        $dirs = @(Get-ChildItem -LiteralPath $r -Directory -Filter "$SysmonWingetId*" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        foreach ($d in $dirs) {
            foreach ($n in $names) {
                $p = Join-Path $d.FullName $n
                if (Test-Path -LiteralPath $p) { return $p }
            }
        }
    }
    # 【要検証】winget の Links に置かれる別名から辿る
    Update-SessionPath
    foreach ($n in $names) {
        $c = Get-Command ($n -replace '\.exe$', '') -ErrorAction SilentlyContinue
        if ($c -and $c.Source) {
            $item = Get-Item -LiteralPath $c.Source
            if ($item.LinkType -and $item.Target) { return [string]@($item.Target)[0] }
            return $c.Source
        }
    }
    return $null
}

function Find-BuiltinSysmonExe {
    $p = Join-Path $env:SystemRoot 'System32\Sysmon.exe'
    if (Test-Path -LiteralPath $p) { return $p }
    Update-SessionPath
    $c = Get-Command sysmon -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return $null
}

function Invoke-Sysmon {
    param([string]$Exe, [string[]]$Arguments)
    # 5.1 では EAP=Stop のままネイティブの stderr を 2>&1 で受けると止まるので、この関数の中だけ Continue
    $ErrorActionPreference = 'Continue'
    if (-not (Test-MicrosoftSigned $Exe)) { Stop-Setup "Sysmon の実行ファイルに Microsoft の署名が確かめられない：$Exe" }
    Write-Info "実行：$Exe $($Arguments -join ' ')"
    $out = & $Exe @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Code = $code; Output = $out }
}

# 戻り値：$true = 続けてよい、$false = 再起動が必要
function Install-SysmonIfNeeded {
    param([string]$ConfigPath)
    $svcs = @(Get-SysmonServices)
    $feature = Get-SysmonFeatureState

    if ($svcs.Count -gt 1) { Stop-Setup 'Sysmon のサービスが複数ある。どちらか一方を sysmon -u で外してから実行し直す' }

    if ($svcs.Count -eq 1) {
        Write-Done "Sysmon は入っている（$($svcs[0].Name)）"
        if ($svcs[0].Status -ne 'Running') { Start-Service $svcs[0].Name; Write-Done 'Sysmon を開始した' }
        $exe = Get-ServiceExePath $svcs[0].Name
        $seen = Get-SysmonIdCounts 60
        $missing = @($NeededIds | Where-Object { -not $seen.ContainsKey($_) })
        $replace = $ReplaceSysmonConfig.IsPresent
        if (-not $replace -and $missing.Count -gt 0) {
            Write-Warn2 ("直近 1 時間に Event ID " + ($missing -join '・') + ' が出ていない。今の Sysmon の設定では kanmon が働かない可能性がある')
            $replace = Confirm-Step 'Sysmon の設定を kanmon 用に差し替えるか（今の設定は控えを残す）'
        }
        if ($replace) {
            $bk = Join-Path $KanmonData ("backup\sysmon-config-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            New-Item -ItemType Directory -Force -Path (Split-Path $bk) | Out-Null
            $cur = Invoke-Sysmon $exe @('-c')
            Set-Content -LiteralPath $bk -Value $cur.Output -Encoding UTF8
            Write-Done "今の設定の控え：$bk"
            $r = Invoke-Sysmon $exe @('-c', $ConfigPath)
            if ($r.Code -ne 0) { Write-Host $r.Output; Stop-Setup "Sysmon の設定を当てられない（終了コード $($r.Code)）" }
            Write-Done 'Sysmon に kanmon 用の設定を当てた'
        } elseif ($missing.Count -eq 0) {
            Write-Done '今の Sysmon の設定で Event ID 1・3・22 が取れているので、そのまま使う'
        } else {
            Write-Warn2 'Sysmon の設定は変えなかった。最後の確認で WARN が出る'
        }
        return $true
    }

    # ---- 入っていない：入れる
    $method = $SysmonMethod
    if ($method -eq 'Auto') {
        if ($feature -ne 'Absent') { $method = 'Builtin' } else { $method = 'Winget' }
    }

    $exe = $null
    if ($method -eq 'Builtin') {
        if ($feature -eq 'Absent') { Stop-Setup 'この Windows には組み込みの Sysmon が無い。-SysmonMethod Winget で実行し直す' }
        if ($feature -eq 'EnablePending') { Write-Warn2 '組み込み Sysmon の有効化が再起動待ち。再起動してからこのスクリプトを実行し直す'; return $false }
        if ($feature -ne 'Enabled') {
            Write-Info '組み込み Sysmon（Windows の機能）を有効にする'
            $r = Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -NoRestart -All
            if ($r.RestartNeeded) { Write-Warn2 '再起動が必要。再起動してからこのスクリプトを実行し直す（続きから進む）'; return $false }
            Write-Done '組み込み Sysmon を有効にした'
        }
        $exe = Find-BuiltinSysmonExe
        if (-not $exe) { Stop-Setup '組み込み Sysmon の実行ファイルが見つからない（Sysmon.exe）。動作報告に書いてほしい' }
    } else {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Stop-Setup 'winget が無い。Microsoft Store で「アプリ インストーラー」を入れてから実行し直す'
        }
        Write-Info "winget で $SysmonWingetId を入れる"
        $common = @('install', '--id', $SysmonWingetId, '--exact', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
        & winget @common '--scope' 'machine'
        if ($LASTEXITCODE -ne 0) {
            Write-Warn2 "--scope machine で入らなかった（終了コード $LASTEXITCODE）。scope を指定せずにもう一度試す"
            & winget @common
            if ($LASTEXITCODE -ne 0) { Stop-Setup "winget で Sysmon を入れられない（終了コード $LASTEXITCODE）" }
        }
        $exe = Find-WingetSysmonExe
        if (-not $exe) { Stop-Setup 'winget で入れた Sysmon の実行ファイルが見つからない。動作報告に書いてほしい' }
        Write-Done "Sysmon を入れた：$exe"
    }

    $r = Invoke-Sysmon $exe @('-accepteula', '-i', $ConfigPath)
    if ($r.Code -ne 0) { Write-Host $r.Output; Stop-Setup "Sysmon を開始できない（終了コード $($r.Code)）" }
    $svcs = @(Get-SysmonServices)
    if ($svcs.Count -eq 0) { Write-Host $r.Output; Stop-Setup 'sysmon -i の後もサービスが見つからない' }
    Write-Done "Sysmon を kanmon 用の設定で開始した（$($svcs[0].Name)）"
    return $true
}

function Set-SysmonLogSize {
    try {
        $log = Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop
        if ($log.MaximumSizeInBytes -lt 256MB) {
            & wevtutil.exe sl $SysmonLog '/ms:268435456'
            if ($LASTEXITCODE -eq 0) { Write-Done 'Sysmon のログの上限を 256 MB にした' }
        }
    } catch { Write-Warn2 'Sysmon のログの上限を変えられなかった' }
}

# 当てる Sysmon 設定：前回置いたもの（利用者が直したかもしれない）→ 配布物 → 埋め込みの順
function Resolve-SysmonConfig {
    $dst = Join-Path $KanmonData $SysmonCfgName
    if (Test-Path -LiteralPath $dst) { return $dst }
    New-Item -ItemType Directory -Force -Path $KanmonData | Out-Null
    $src = Join-Path $Source $SysmonCfgName
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $dst }
    else { Set-Content -LiteralPath $dst -Value $EmbeddedSysmonConfig -Encoding UTF8 }
    Set-SecureAcl $KanmonData
    return $dst
}

# ================================================================== kanmon の導入
function Test-SourceFiles {
    $need = @('kanmond.exe', 'kanmonctl.exe', 'kanmon-tray.exe', $SysmonCfgName, 'kanmon.toml.example', 'detections')
    $miss = @($need | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Source $_)) })
    if ($miss.Count -gt 0) { Stop-Setup ("配布物に無いもの：" + ($miss -join ', ') + "（-Source で zip を展開したフォルダを指定する）") }

    # 配布物の SHA256SUMS があれば各ファイルを照合する（zip 自体の照合は手順書 §1）
    $sums = Join-Path $Source 'SHA256SUMS'
    if (Test-Path -LiteralPath $sums) {
        $bad = @()
        foreach ($line in Get-Content -LiteralPath $sums) {
            if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') { continue }
            $want = $Matches[1].ToLower(); $rel = $Matches[2].Trim()
            $p = Join-Path $Source $rel
            if (-not (Test-Path -LiteralPath $p)) { continue }   # zip 自体などは無い
            $got = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()
            if ($got -ne $want) { $bad += $rel }
        }
        if ($bad.Count -gt 0) { Stop-Setup ("ハッシュが合わない：" + ($bad -join ', ') + "。配布物を取り直す") }
        Write-Done 'SHA256SUMS と照合した'
    } else {
        Write-Warn2 'SHA256SUMS が無いので照合しない'
    }
    # zip から展開したファイルの「インターネットから来た」印を外す（照合のあとで）
    Get-ChildItem -LiteralPath $Source -Recurse -File | Unblock-File
}

# Administrators と SYSTEM はフル、Users は読み取りと実行だけ。継承を切る
function Set-SecureAcl {
    param([string]$Path)
    # フォルダ自身：継承を切り、明示の ACE を付け直す
    & icacls.exe $Path '/inheritance:r' '/grant:r' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' '/Q' | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Setup "権限を設定できない：$Path（icacls 終了コード $LASTEXITCODE）" }
    # 残っている Authenticated Users・Everyone の ACE を消す
    & icacls.exe $Path '/remove:g' '*S-1-5-11' '*S-1-1-0' '/Q' | Out-Null
    # 中身：明示の ACE を捨て、フォルダの ACE を継承させる
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
        & icacls.exe (Join-Path $Path '*') '/reset' '/T' '/C' '/Q' | Out-Null
    }
}

function Install-Kanmon {
    $existing = Get-Service -Name $KanmonSvc -ErrorAction SilentlyContinue
    if ($existing -and $existing.Status -ne 'Stopped') {
        Stop-Service -Name $KanmonSvc -Force
        Write-Done 'kanmond を止めた（更新のため）'
    }

    # 動いているトレイを止める（実行ファイルを置き換えるため）
    Get-Process -Name 'kanmon-tray' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    # 実行ファイル
    New-Item -ItemType Directory -Force -Path $KanmonBin | Out-Null
    foreach ($f in @('kanmond.exe', 'kanmonctl.exe', 'kanmon-tray.exe')) {
        Copy-Item -LiteralPath (Join-Path $Source $f) -Destination (Join-Path $KanmonBin $f) -Force
    }
    # 後で -CheckOnly・-Uninstall に使えるように、このスクリプトも置く
    if ($PSCommandPath -and ((Split-Path $PSCommandPath -Parent) -ne $KanmonBin)) {
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $KanmonBin 'kanmon-setup.ps1') -Force
    }
    Set-SecureAcl $KanmonBin
    Write-Done "実行ファイルを置いた：$KanmonBin"

    # 設定とルール。kanmon.toml は利用者が直すので、あれば上書きしない
    New-Item -ItemType Directory -Force -Path $KanmonData | Out-Null
    if (-not (Test-Path -LiteralPath $KanmonToml)) {
        Copy-Item -LiteralPath (Join-Path $Source 'kanmon.toml.example') -Destination $KanmonToml
        Write-Done "設定の雛形を置いた：$KanmonToml"
    } else {
        Copy-Item -LiteralPath (Join-Path $Source 'kanmon.toml.example') -Destination (Join-Path $KanmonData 'kanmon.toml.example') -Force
        Write-Done "設定はそのまま（新しい雛形は kanmon.toml.example に置いた）"
    }
    if (Test-Path -LiteralPath $KanmonDet) { Remove-Item -LiteralPath $KanmonDet -Recurse -Force }
    Copy-Item -LiteralPath (Join-Path $Source 'detections') -Destination $KanmonDet -Recurse
    # Sysmon の設定も利用者が直す（除外を足す）ので、あれば上書きしない
    $cfgDst = Join-Path $KanmonData $SysmonCfgName
    if (-not (Test-Path -LiteralPath $cfgDst)) { Copy-Item -LiteralPath (Join-Path $Source $SysmonCfgName) -Destination $cfgDst }
    else { Copy-Item -LiteralPath (Join-Path $Source $SysmonCfgName) -Destination "$cfgDst.example" -Force }
    Set-SecureAcl $KanmonData
    Write-Done "設定とルールを置いた：$KanmonData（Administrators と SYSTEM だけが書ける）"

    # イベントログの書き込み元
    try {
        if (-not [Diagnostics.EventLog]::SourceExists('kanmon')) { New-EventLog -LogName Application -Source kanmon }
    } catch { Write-Warn2 'イベントログの書き込み元 kanmon を作れなかった' }

    # サービス
    $bin = "`"$(Join-Path $KanmonBin 'kanmond.exe')`" $KanmondArgs"
    if (-not $existing) {
        New-Service -Name $KanmonSvc -BinaryPathName $bin -DisplayName 'kanmon monitor' `
            -Description 'kanmon：プロセスごとの通信を監視して通知する（beta）' -StartupType Automatic | Out-Null
        Write-Done 'サービス kanmond を登録した'
    } else {
        # sc.exe config binPath= に引用符入りの値を渡すと 5.1 で崩れるので、レジストリを直接直す
        Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$KanmonSvc" -Name ImagePath -Value $bin
        Set-Service -Name $KanmonSvc -StartupType Automatic
        Write-Done 'サービス kanmond の設定を更新した'
    }
    # 落ちたら 1 分後に起こし直す（1 日で数え直す）
    & sc.exe failure $KanmonSvc reset= 86400 actions= restart/60000/restart/60000// | Out-Null

    # PATH
    $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (-not (($mp -split ';') -contains $KanmonBin)) {
        [Environment]::SetEnvironmentVariable('Path', ($mp.TrimEnd(';') + ';' + $KanmonBin), 'Machine')
        Write-Done 'PATH に足した（新しく開いた PowerShell から kanmonctl が使える）'
    }

    Start-Service -Name $KanmonSvc
    Start-Sleep -Seconds 2
    $s = Get-Service -Name $KanmonSvc
    if ($s.Status -ne 'Running') { Write-Warn2 "kanmond が開始しない（$($s.Status)）。$KanmondLog を見る" }
    else { Write-Done 'kanmond を開始した' }

    # トレイ：全員のログオン時に起動（HKLM の Run。kanmond の居座りの走査は、Program Files\kanmon を指す自分の登録を除く）
    $trayExe = Join-Path $KanmonBin 'kanmon-tray.exe'
    Set-ItemProperty -LiteralPath $TrayRunKey -Name $TrayRunName -Value "`"$trayExe`""
    Write-Done 'トレイをログオン時に起動するよう登録した'
    # 今の利用者の画面にも出す。このスクリプトは管理者で動いているので、explorer 経由で通常の権限で起動する
    try { Start-Process -FilePath "$env:SystemRoot\explorer.exe" -ArgumentList "`"$trayExe`"" | Out-Null; Write-Done 'トレイを起動した（通知領域の ^ の中にあることがある）' }
    catch { Write-Warn2 'トレイを起動できなかった。次のログオンで起動する' }
}

# ================================================================== アンインストール
function Uninstall-Kanmon {
    $ErrorActionPreference = 'Continue'   # winget の stderr で止まらないように
    Write-Step 'kanmon を外す'
    Get-Process -Name 'kanmon-tray' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -LiteralPath $TrayRunKey -Name $TrayRunName -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'HKCU:\Software\Classes\AppUserModelId\Kanmon.Tray' -Recurse -ErrorAction SilentlyContinue
    Write-Done 'トレイを止め、自動起動の登録を消した'
    $s = Get-Service -Name $KanmonSvc -ErrorAction SilentlyContinue
    if ($s) {
        if ($s.Status -ne 'Stopped') { Stop-Service -Name $KanmonSvc -Force }
        & sc.exe delete $KanmonSvc | Out-Null
        Write-Done 'サービス kanmond を消した'
    }
    $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($mp -split ';' | Where-Object { $_ -and $_ -ne $KanmonBin })
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'Machine')
    if (Test-Path -LiteralPath $KanmonBin) {
        # 実行中のこのスクリプトが中にある場合でも、PowerShell は読み込み済みなので消せる
        Remove-Item -LiteralPath $KanmonBin -Recurse -Force
        Write-Done "$KanmonBin を消した"
    }
    if ($Purge -and (Test-Path -LiteralPath $KanmonData)) {
        Remove-Item -LiteralPath $KanmonData -Recurse -Force
        Write-Done "$KanmonData を消した"
    } elseif (Test-Path -LiteralPath $KanmonData) {
        Write-Info "$KanmonData は残した（設定・ログ。消すなら -Purge）"
    }

    if ($RemoveSysmon) {
        Write-Step 'Sysmon を外す'
        $svcs = @(Get-SysmonServices)
        foreach ($sv in $svcs) {
            $exe = Get-ServiceExePath $sv.Name
            if ($exe) {
                $r = Invoke-Sysmon $exe @('-u')
                if ($r.Code -eq 0) { Write-Done "$($sv.Name) を外した" } else { Write-Warn2 "$($sv.Name) を外せない（終了コード $($r.Code)）" }
            }
        }
        if ((Get-SysmonFeatureState) -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName Sysmon -NoRestart | Out-Null
            Write-Done '組み込み Sysmon（Windows の機能）を無効にした（再起動で反映）'
        }
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $out = & winget list --id $SysmonWingetId --exact --accept-source-agreements 2>$null | Out-String
            if ($out -match [regex]::Escape($SysmonWingetId)) {
                & winget uninstall --id $SysmonWingetId --exact --disable-interactivity | Out-Null
                Write-Done 'winget の Sysmon を外した'
            }
        }
    }
}

# ================================================================== 本体
# 管理者でなければ、同じ引数で管理者として起動し直す
if (-not (Test-IsAdmin)) {
    if (-not $PSCommandPath) { Stop-Setup '管理者の PowerShell で実行する' }
    Write-Host '管理者として起動し直す（ユーザー アカウント制御の確認が出る）'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $argList += "-$k" } }
        else { $argList += "-$k"; $argList += "`"$v`"" }
    }
    if (-not $PSBoundParameters.ContainsKey('Source')) { $argList += '-Source'; $argList += "`"$Source`"" }
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList | Out-Null }
    catch { Stop-Setup '管理者として起動できなかった（確認が拒否された）' }
    exit $EXIT_OK
}

if ($CheckOnly) {
    Invoke-Check -Probe:(-not $NoProbe) -SysmonOnlyCheck:$SysmonOnly
    if ($Json) { Show-CheckJson } else { Show-Check }
    exit (Get-CheckExitCode)
}

if ($Uninstall) {
    $what = 'kanmon（サービス・トレイ・実行ファイル・PATH）'
    if ($Purge) { $what += '、設定とログ' }
    if ($RemoveSysmon) { $what += '、Sysmon' }
    if (-not (Confirm-Step "$what を外す。よいか")) { Stop-Setup '取りやめた' }
    Uninstall-Kanmon
    Write-Host ''
    Write-Host '完了' -ForegroundColor Green
    exit $EXIT_OK
}

# ---- セットアップ
$logDir = Join-Path $KanmonData 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$transcript = Join-Path $logDir ("setup-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
try { Start-Transcript -LiteralPath $transcript | Out-Null } catch { }

Write-Step '1/4 今の状態'
Invoke-Check -SysmonOnlyCheck:$SysmonOnly
Show-Check

Write-Step '2/4 これから行うこと'
$plan = @()
$svcs = @(Get-SysmonServices)
if ($SkipSysmon) { $plan += 'Sysmon：触らない（-SkipSysmon）' }
elseif ($svcs.Count -eq 0) {
    $m = $SysmonMethod
    if ($m -eq 'Auto') { if ((Get-SysmonFeatureState) -ne 'Absent') { $m = 'Builtin' } else { $m = 'Winget' } }
    if ($m -eq 'Builtin') { $plan += 'Sysmon：Windows 11 の組み込み Sysmon を有効にし、kanmon 用の設定で開始する（再起動を求められることがある）' }
    else { $plan += "Sysmon：winget で $SysmonWingetId を入れ、kanmon 用の設定で開始する" }
} elseif ($ReplaceSysmonConfig) { $plan += 'Sysmon：今の設定の控えを残し、kanmon 用の設定に差し替える' }
else { $plan += 'Sysmon：入っている。Event ID 1・3・22 が取れていなければ、設定を差し替えるか確認する' }
if (-not $SkipSysmon) { $plan += 'Sysmon のログの上限を 256 MB にする（小さい場合）' }
if ($SysmonOnly) { $plan += 'kanmon：入れない（-SysmonOnly）' }
else { $plan += "kanmon：$KanmonBin と $KanmonData に置き、サービス kanmond を登録・開始し、PATH に足す。トレイをログオン時に起動する（入っていれば更新）" }
foreach ($p in $plan) { Write-Info "・$p" }
Write-Info "記録：$transcript"
if (-not (Confirm-Step '進めるか')) { Stop-Setup '取りやめた' }

Write-Step '3/4 Sysmon'
if (-not $SysmonOnly) { Test-SourceFiles }
$cfg = Resolve-SysmonConfig
Write-Info "Sysmon の設定：$cfg"
if ($SkipSysmon) {
    Write-Info '触らない（-SkipSysmon）'
} else {
    $ok = Install-SysmonIfNeeded -ConfigPath $cfg
    if (-not $ok) {
        try { Stop-Transcript | Out-Null } catch { }
        Write-Host ''
        Write-Host '再起動してから、同じコマンドをもう一度実行する（済んだ手順は飛ばす）' -ForegroundColor Yellow
        exit $EXIT_REBOOT
    }
    Set-SysmonLogSize
}

Write-Step '4/4 kanmon'
if ($SysmonOnly) { Write-Info '入れない（-SysmonOnly）' } else { Install-Kanmon }

Write-Step '確認'
Invoke-Check -Probe:(-not $NoProbe) -SysmonOnlyCheck:$SysmonOnly
Show-Check
$code = Get-CheckExitCode
try { Stop-Transcript | Out-Null } catch { }
Write-Host ''
Write-Host "記録：$transcript"
Write-Host "あとで確かめる：powershell -ExecutionPolicy Bypass -File `"$KanmonBin\kanmon-setup.ps1`" -CheckOnly"
exit $code
