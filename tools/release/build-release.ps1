<#
构建机上的发布候选构建入口（Windows PowerShell 5.1）。当前开发机不运行完整构建。

  build-release.ps1 -PlanOnly     只查工具与发布输入，写日志后按 READY/NOT_READY 退出（0 / 2）
  build-release.ps1               依次：编控制端 → 编网络服务 → 检查发布输入 → 装配 → tauri build

- 第一步就建日志目录 <LogRoot>\<UTC 时间>-<进程号>\，每一步的命令、退出码与输出都写进去，失败也留着；不覆盖上一轮。
- 连日志目录都建不了时，按提示用 Start-Transcript 保存控制台输出。
- 缺工具或发布输入时停在装配之前，不生成任何安装包、占位文件或假哈希。
#>
[CmdletBinding()]
param(
  [switch]$PlanOnly,
  [string]$LogRoot = ''
)

$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $LogRoot) { $LogRoot = Join-Path $Repo 'build\logs' }
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Run = "$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ'))-$PID"
$LogDir = Join-Path $LogRoot $Run
try {
  [void](New-Item -ItemType Directory -Force -Path $LogDir)
} catch {
  Write-Output "无法创建构建日志目录 $LogDir：$($_.Exception.Message)"
  Write-Output '请先运行 Start-Transcript -Path <可写路径>\build-console.log，再重跑本脚本，把控制台输出一并交回。'
  exit 3
}
$Log = Join-Path $LogDir 'build.log'

function Log([string]$line) {
  $stamped = "$((Get-Date).ToUniversalTime().ToString('o')) $line"
  [System.IO.File]::AppendAllText($Log, "$stamped`r`n", $Utf8)
  Write-Host $stamped
}

function Step([string]$name, [string]$file, [string[]]$arguments, [string]$workdir = $Repo) {
  $output = Join-Path $LogDir "$name.log"
  Log "step.begin $name :: $file $($arguments -join ' ')"
  Push-Location $workdir
  # Windows PowerShell 5.1 在 Stop 下会把重定向进来的原生命令 stderr 当终止错误，cargo 的进度都写 stderr：调用期间切到 Continue，只按退出码判断。
  # 退出码先置 -1，命令起不来时把原因记进步骤日志并按失败返回，不沿用上一步的 0；步骤日志写不进去则照旧终止整个构建。
  $previous = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $global:LASTEXITCODE = -1
  $logFailed = $false
  try {
    & $file @arguments *>&1 | ForEach-Object {
      try { [System.IO.File]::AppendAllText($output, "$_`r`n", $Utf8) } catch { $logFailed = $true; throw }
    }
    $code = $LASTEXITCODE
  } catch {
    $ErrorActionPreference = $previous
    if ($logFailed) { throw }
    [System.IO.File]::AppendAllText($output, "step.start_failed $($_.Exception.Message)`r`n", $Utf8)
    $code = -1
  } finally {
    $ErrorActionPreference = $previous
    Pop-Location
  }
  Log "step.end $name exit=$code log=$name.log"
  return $code
}

Log "build.begin plan_only=$([bool]$PlanOnly) log_dir=$LogDir"
$missing = @()
foreach ($tool in @('rustc', 'cargo', 'node')) {
  $command = Get-Command $tool -ErrorAction SilentlyContinue
  if ($command) { Log "tool.$tool PRESENT $($command.Source)" } else { Log "tool.$tool TOOL_MISSING"; $missing += $tool }
}

function Check-Inputs {
  if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Log 'release.check SKIPPED node is missing'; return 'NOT_READY' }
  $code = Step 'release-check' 'node' @('tools/release/release.mjs', 'check')
  Copy-Item -LiteralPath (Join-Path $LogDir 'release-check.log') -Destination (Join-Path $LogDir 'check.json')
  $status = if ($code -eq 0) { 'READY' } else { 'NOT_READY' }
  Log "release.check $status"
  return $status
}

if ($PlanOnly -or $missing.Count -gt 0) {
  $status = Check-Inputs
  if ($missing.Count -gt 0) { Log "build.stop NOT_READY missing_tools=$($missing -join ',')"; exit 2 }
  Log "build.plan $status"
  if ($status -eq 'READY') { exit 0 } else { exit 2 }
}

if ((Step 'cargo-control' 'cargo' @('build', '--release', '--manifest-path', 'services/control-rs/Cargo.toml')) -ne 0) { Log 'build.failed cargo-control'; exit 1 }
if ((Step 'cargo-service' 'cargo' @('build', '--release', '--features', 'service', '--manifest-path', 'apps/desktop-host/vendor/service-ipc/Cargo.toml')) -ne 0) { Log 'build.failed cargo-service'; exit 1 }
if ((Check-Inputs) -ne 'READY') { Log 'build.stop NOT_READY see check.json'; exit 2 }
if ((Step 'assemble' 'node' @('tools/release/release.mjs', 'assemble')) -ne 0) { Log 'build.failed assemble'; exit 1 }
if ((Step 'tauri-build' 'cargo' @('tauri', 'build', '--features', 'tauri') (Join-Path $Repo 'apps\desktop-host\src-tauri')) -ne 0) { Log 'build.failed tauri-build'; exit 1 }
Log 'build.done installer produced by tauri build; record its file list and hashes for E54'
exit 0
