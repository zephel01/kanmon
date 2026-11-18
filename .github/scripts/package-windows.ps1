# Windows の配布物（zip）を作る（release.yml・ci.yml から呼ぶ）。
#   引数：-Version 0.4.0-beta.1 -BinDir target\release -OutDir dist
# 中身：kanmond.exe・kanmonctl.exe・kanmon-tray.exe・kanmon-setup.ps1・kanmon-sysmon.xml・kanmon.toml.example・
#       detections\*.yaml・SHA256SUMS（中身のハッシュ。kanmon-setup.ps1 が照合する）
# zip の外に kanmon-<版>-windows-x64.zip.sha256 も作る
param(
    [Parameter(Mandatory)] [string]$Version,
    [string]$BinDir = 'target\release',
    [string]$OutDir = 'dist'
)
$ErrorActionPreference = 'Stop'
$name = "kanmon-$Version-windows-x64"
$stage = Join-Path $OutDir $name
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'detections') | Out-Null
foreach ($f in 'kanmond.exe', 'kanmonctl.exe', 'kanmon-tray.exe') { Copy-Item (Join-Path $BinDir $f) $stage }
foreach ($f in 'kanmon-setup.ps1', 'kanmon-sysmon.xml', 'kanmon.toml.example') { Copy-Item (Join-Path 'packaging\windows' $f) $stage }
Copy-Item 'detections\*.yaml' (Join-Path $stage 'detections')
Copy-Item 'LICENSE' $stage

# 中身のハッシュ（sha256sum と同じ形：「ハッシュ  相対パス」、区切りは /）
$lines = Get-ChildItem $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring((Resolve-Path $stage).Path.Length + 1).Replace('\', '/')
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
}
[IO.File]::WriteAllLines((Join-Path $stage 'SHA256SUMS'), $lines)

$zip = Join-Path $OutDir "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip
$h = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText("$zip.sha256", "$h  $name.zip`n")
Write-Host "$zip"
Write-Host "sha256: $h"
