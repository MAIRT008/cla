<#
构建机上使用已入库的三份 Cargo.lock 生成、验证 Rust 依赖许可汇总 build\inputs\THIRD-PARTY-RUST.txt（Windows PowerShell 5.1）。

  generate-rust-licenses.ps1

- 锁是版本控制输入（2026-09-27 第四次 pin 裁决）：本脚本不生成、不更新、不删除也不恢复任何 Cargo.lock。
- 三个 manifest 按固定顺序处理：先核对同目录的 Cargo.lock 存在且等于 tools\release\release-inputs.json 固定的 SHA-256，再用 about.toml 与 about.hbs 以 --locked 扫描生成片段。
- 每个 manifest 独立记锁检查与许可扫描的结果：锁缺失、未固定或不符则该项不扫描、记“未执行”；扫描失败保留完整输出，锁需要更新而被 --locked 拒绝的单独标出；都继续处理其余 manifest。
- 锁检查通过只说明输入等于批准基线；清单与锁是否相容由实际的 --locked 扫描判定。全部扫描后再核一次锁，扫描期间被改写也算失败。
- 结束时集中列出失败项、未扫描项与锁问题。全部成功才按原顺序合并、改名成正式文件；否则非零退出，不生成正式汇总，清掉本次片段与半成品。
- 正式文件已存在就拒绝，不覆盖上一轮结果；cargo-about 不是 0.8.4 时拒绝，文件头写的版本必须是真的。
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$AboutVersion = '0.8.4'
$TargetTriple = 'x86_64-pc-windows-msvc'
$Repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Manifests = @(
  'services/control-rs/Cargo.toml',
  'apps/desktop-host/vendor/service-ipc/Cargo.toml',
  'apps/desktop-host/src-tauri/Cargo.toml'
)
$Config = Join-Path $PSScriptRoot 'about.toml'
$InputsFile = Join-Path $PSScriptRoot 'release-inputs.json'
$Template = Join-Path $PSScriptRoot 'about.hbs'
$InputsDir = Join-Path $Repo 'build\inputs'
$Target = Join-Path $InputsDir 'THIRD-PARTY-RUST.txt'
$Work = Join-Path $InputsDir "third-party-rust.partial-$PID"
$Partial = "$Target.partial-$PID"

# Windows PowerShell 5.1 在 Stop 下会把原生命令写到 stderr 的第一行当成终止错误，cargo 的进度全在 stderr；
# 这里临时切到 Continue，只按退出码判断成败。命令起不来时按 -1 返回，不沿用上一条命令的退出码。
function Invoke-Native([string]$file, [string[]]$arguments) {
  Write-Host "run: $file $($arguments -join ' ')"
  $previous = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $global:LASTEXITCODE = -1
  try {
    $lines = @(& $file @arguments 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
  } catch {
    $lines = @("start failed: $($_.Exception.Message)")
    $code = -1
  } finally {
    $ErrorActionPreference = $previous
  }
  $lines | ForEach-Object { Write-Host $_ }
  return [pscustomobject]@{ code = $code; lines = $lines }
}

function Get-Sha256([string]$file) {
  $digest = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($file))
  return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

if (Test-Path -LiteralPath $Target) {
  Write-Host "refuse: build\inputs\THIRD-PARTY-RUST.txt already exists; this script never overwrites"
  exit 2
}
foreach ($manifest in $Manifests) {
  if (-not (Test-Path -LiteralPath (Join-Path $Repo $manifest))) { Write-Host "refuse: missing $manifest"; exit 2 }
}
foreach ($file in @($Config, $Template, $InputsFile)) {
  if (-not (Test-Path -LiteralPath $file)) { Write-Host "refuse: missing $file"; exit 2 }
}

$releaseInputs = [System.IO.File]::ReadAllText($InputsFile, $Utf8) | ConvertFrom-Json

[void](New-Item -ItemType Directory -Force -Path $InputsDir)
[void](New-Item -ItemType Directory -Path $Work)
$ok = $false
$results = @()
try {
  $version = Invoke-Native 'cargo' @('about', '--version')
  if ($version.code -ne 0) { throw "cargo about --version exited $($version.code)" }
  if (($version.lines -join ' ') -notmatch "\b$([regex]::Escape($AboutVersion))\b") { throw "cargo-about version is '$($version.lines -join ' ')', expected $AboutVersion" }

  $index = 0
  foreach ($manifest in $Manifests) {
    $index += 1
    $path = Join-Path $Repo $manifest
    $lockSource = $manifest -replace '/Cargo\.toml$', '/Cargo.lock'
    $lockFile = Join-Path $Repo $lockSource
    $expected = @($releaseInputs.items | Where-Object { $_.source -eq $lockSource } | ForEach-Object { $_.sha256 }) | Select-Object -First 1
    $fragment = Join-Path $Work "$index.txt"
    $result = [ordered]@{ manifest = $manifest; lockFile = $lockFile; expected = $expected; fragment = $fragment; lock = 'ok'; scan = 'ok' }
    if (-not $expected) {
      $result.lock = 'unpinned'
    } elseif (-not (Test-Path -LiteralPath $lockFile)) {
      $result.lock = 'missing'
    } else {
      $actual = Get-Sha256 $lockFile
      if ($actual -ne $expected) { $result.lock = "mismatch(expected=$expected,actual=$actual)" }
    }
    if ($result.lock -ne 'ok') {
      $result.scan = 'not_run'
    } else {
      $scan = Invoke-Native 'cargo' @('about', 'generate', '--manifest-path', $path, '--config', $Config, '--all-features', '--locked', '--fail', '--output-file', $fragment, $Template)
      if ($scan.code -ne 0) {
        $scanText = $scan.lines -join "`n"
        $kind = if ($scanText -match 'failed to satisfy license requirements') { 'license_requirements_not_satisfied' } elseif ($scanText -match 'needs to be updated but --locked was passed') { 'lock_update_required' } else { 'other_error' }
        $result.scan = "failed(exit=$($scan.code),$kind)"
      } elseif (-not (Test-Path -LiteralPath $fragment)) {
        $result.scan = 'failed(no_output)'
      }
    }
    $results += , $result
  }

  foreach ($result in @($results | Where-Object { $_.lock -eq 'ok' })) {
    $now = if (Test-Path -LiteralPath $result.lockFile) { Get-Sha256 $result.lockFile } else { 'missing' }
    if ($now -ne $result.expected) { $result.lock = "changed_during_run(expected=$($result.expected),now=$now)" }
  }

  foreach ($result in $results) {
    Write-Host "licenses.summary $($result.manifest) lock=$($result.lock) scan=$($result.scan)"
  }
  $failed = @($results | Where-Object { $_.scan -like 'failed*' } | ForEach-Object { $_.manifest })
  $notRun = @($results | Where-Object { $_.scan -eq 'not_run' } | ForEach-Object { $_.manifest })
  $lockProblems = @($results | Where-Object { $_.lock -ne 'ok' } | ForEach-Object { $_.manifest })
  if ($failed.Count -or $notRun.Count -or $lockProblems.Count) {
    throw "not every manifest was scanned successfully against its committed lock; failed=[$($failed -join ', ')] not_run=[$($notRun -join ', ')] lock=[$($lockProblems -join ', ')]"
  }

  $text = New-Object System.Text.StringBuilder
  [void]$text.Append("Third-party Rust dependency licenses for AI Environmental Steward`n")
  [void]$text.Append("Generated by: cargo-about $AboutVersion`n")
  [void]$text.Append("Target: $TargetTriple`n")
  [void]$text.Append("Manifests (each scanned with --all-features --locked against its committed Cargo.lock):`n")
  foreach ($result in $results) { [void]$text.Append("  $($result.manifest)  Cargo.lock sha256=$($result.expected)`n") }
  foreach ($result in $results) {
    [void]$text.Append("`n################################################################################`n")
    [void]$text.Append("Manifest: $($result.manifest)`n")
    [void]$text.Append("################################################################################`n")
    [void]$text.Append([System.IO.File]::ReadAllText($result.fragment, $Utf8))
  }
  [System.IO.File]::WriteAllText($Partial, $text.ToString(), $Utf8)
  Move-Item -LiteralPath $Partial -Destination $Target
  $ok = $true
} catch {
  Write-Host "failed: $($_.Exception.Message)"
} finally {
  Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath $Partial) { Remove-Item -LiteralPath $Partial -Force }
}

if (-not $ok) { exit 1 }
Write-Host "wrote build\inputs\THIRD-PARTY-RUST.txt sha256=$(Get-Sha256 $Target)"
exit 0
