<#
统一日志收集（Windows PowerShell 5.1 可直接运行，不需要 Node、Rust 或 Python；界面起不来时也能用）。

  collect-logs.cmd -Preview                              列出会收集的日志、大小、是否含访问明细，以及缺哪类日志
  collect-logs.cmd -Export -CaseId E57 [-OperationId x]  导出到新目录 <Out>\<CaseId>\<UTC 时间>-<进程号>\

- 只读固定白名单：宿主与应用日志、控制端日志、产品网络服务日志、内核日志、安装器与安装助手日志、构建日志。
  不读授权保险库、链接密钥、内核配置、网络草稿、浏览器数据或任何其他文件。
- 内核日志含访问明细，默认不导出；要导出须显式加 -IncludeAccessHistory。
- 每个文件按与应用内诊断包相同的规则脱敏后写入；manifest.json 最后写。任何一步失败都删掉本次目录并提示「日志包未生成」。
- 每次导出都是新目录，失败与复测的记录各自保留，不覆盖旧包。不上传。
- -FailAfterFiles 只供离线用例模拟中途写失败。
#>
[CmdletBinding()]
param(
  [switch]$Preview,
  [switch]$Export,
  [string]$CaseId = 'manual',
  [string]$OperationId = '',
  [string]$Out = '',
  [switch]$IncludeAccessHistory,
  [string]$DataRoot = '',
  [string]$ServiceRoot = '',
  [string]$BuildLogRoot = '',
  [int]$FailAfterFiles = 0
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$MaxBytes = 64MB

if (-not $DataRoot) { $DataRoot = Join-Path $env:LOCALAPPDATA 'local.ai-environmental-steward.desktop' }
if (-not $ServiceRoot) { $ServiceRoot = Join-Path $env:ProgramData 'ai-environmental-steward-service' }
if (-not $BuildLogRoot) { $BuildLogRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build\logs' }
if (-not $Out) { $Out = Join-Path $DataRoot 'logs\collected' }

# 与 src/core/audit/redact.mjs 的 RULES 逐条对应、顺序相同；ECMAScript 选项让 \b、\s 与 JavaScript 同义。
$Rules = @(
  @{ name = 'pem_private_key'; pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'; ignoreCase = $false; replace = '[redacted private key]' },
  @{ name = 'url_userinfo'; pattern = '\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@"'']+@'; ignoreCase = $true; replace = '$1[redacted]@' },
  @{ name = 'bearer'; pattern = '\b(bearer\s+)[A-Za-z0-9._~+/=-]+'; ignoreCase = $true; replace = '$1[redacted]' },
  @{ name = 'json_secret_field'; pattern = '("[A-Za-z0-9_-]*(?:authorization|cookie|token|password|passwd|secret|api[_-]?key|credential|private[_-]?key)[A-Za-z0-9_-]*"\s*:\s*)"(?:[^"\\]|\\.)*"'; ignoreCase = $true; replace = '$1"[redacted]"' },
  @{ name = 'keyed_value'; pattern = '\b((?:proxy-authorization|authorization|set-cookie|cookie|access[_-]?token|refresh[_-]?token|token|api[_-]?key|password|passwd|secret|private[_ -]?key)\s*[:=]\s*)("[^"]*"|[^\s,;&"]+)'; ignoreCase = $true; replace = '$1[redacted]' },
  @{ name = 'query_secret'; pattern = '([?&](?:access_token|token|key|secret|sig|signature|password|auth)=)[^&\s"'']+'; ignoreCase = $true; replace = '$1[redacted]' },
  @{ name = 'api_key'; pattern = '\bsk-[A-Za-z0-9_-]{8,}'; ignoreCase = $false; replace = '[redacted]' }
)

function Redact([string]$text) {
  $count = 0
  foreach ($rule in $Rules) {
    $options = [System.Text.RegularExpressions.RegexOptions]::ECMAScript
    if ($rule.ignoreCase) { $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    $regex = New-Object System.Text.RegularExpressions.Regex($rule.pattern, $options)
    $count += $regex.Matches($text).Count
    $text = $regex.Replace($text, $rule.replace)
  }
  return @{ text = $text; count = $count }
}

function Sha256([byte[]]$bytes) {
  $hasher = [System.Security.Cryptography.SHA256]::Create()
  try { return ([System.BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $hasher.Dispose() }
}

function Plain-Files([string]$dir, [string]$pattern) {
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return @() }
  return @(Get-ChildItem -LiteralPath $dir -File -Force | Where-Object {
    $_.Name -match $pattern -and -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
  })
}

$Categories = @(
  @{ category = 'host'; dir = (Join-Path $DataRoot 'logs'); pattern = '^(app|host-control)-[A-Za-z0-9._-]+\.log$'; access = $false },
  @{ category = 'control'; dir = (Join-Path $DataRoot 'control\logs'); pattern = '^control-[A-Za-z0-9._-]+\.log$'; access = $false },
  @{ category = 'network_service'; dir = (Join-Path $ServiceRoot 'logs'); pattern = '^service(\.1)?\.log$'; access = $false },
  @{ category = 'network_core'; dir = (Join-Path $ServiceRoot 'logs'); pattern = '^core(\.1)?\.log$'; access = $true },
  @{ category = 'installer'; dir = (Join-Path $ServiceRoot 'logs'); pattern = '^(install|installer)-[A-Za-z0-9._-]+\.log$'; access = $false }
)

$sources = New-Object System.Collections.ArrayList
$gaps = New-Object System.Collections.ArrayList
foreach ($entry in $Categories) {
  $found = Plain-Files $entry.dir $entry.pattern
  if ($found.Count -eq 0) {
    [void]$gaps.Add([ordered]@{ category = $entry.category; reason = $(if (Test-Path -LiteralPath $entry.dir) { 'NO_FILES' } else { 'DIR_MISSING' }) })
  }
  foreach ($file in $found) {
    [void]$sources.Add([ordered]@{
      source_ref = "$($entry.category)/$($file.Name)"; category = $entry.category; path = $file.FullName; bytes = $file.Length
      modified_at = $file.LastWriteTimeUtc.ToString('o'); contains_access_history = $entry.access
      selected = (-not $entry.access) -or [bool]$IncludeAccessHistory
    })
  }
}
$buildFiles = 0
if (Test-Path -LiteralPath $BuildLogRoot -PathType Container) {
  foreach ($run in @(Get-ChildItem -LiteralPath $BuildLogRoot -Directory -Force | Where-Object { $_.Name -match '^[0-9A-Za-z-]+$' -and -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) })) {
    foreach ($file in (Plain-Files $run.FullName '^[A-Za-z0-9._-]+\.(log|json)$')) {
      $buildFiles += 1
      [void]$sources.Add([ordered]@{
        source_ref = "build/$($run.Name)__$($file.Name)"; category = 'build'; path = $file.FullName; bytes = $file.Length
        modified_at = $file.LastWriteTimeUtc.ToString('o'); contains_access_history = $false; selected = $true
      })
    }
  }
}
if ($buildFiles -eq 0) { [void]$gaps.Add([ordered]@{ category = 'build'; reason = $(if (Test-Path -LiteralPath $BuildLogRoot) { 'NO_FILES' } else { 'DIR_MISSING' }) }) }

function Public-Source($item) {
  return [ordered]@{ source_ref = $item.source_ref; category = $item.category; bytes = $item.bytes; modified_at = $item.modified_at; contains_access_history = $item.contains_access_history; selected = $item.selected }
}

if ($Preview) {
  $view = [ordered]@{ preview = $true; case_id = $CaseId; sources = @($sources | ForEach-Object { Public-Source $_ }); gaps = @($gaps); out = $Out }
  Write-Output ($view | ConvertTo-Json -Depth 6)
  exit 0
}
if (-not $Export) {
  [Console]::Error.WriteLine('usage: collect-logs.cmd -Preview | -Export -CaseId <编号> [-OperationId <编号>] [-IncludeAccessHistory] [-Out <目录>]')
  exit 64
}
if ($CaseId -notmatch '^[A-Za-z0-9._-]{1,64}$' -or ($OperationId -and $OperationId -notmatch '^[A-Za-z0-9._:-]{1,128}$')) {
  [Console]::Error.WriteLine('日志包未生成：CaseId / OperationId 只能用字母、数字与 ._-:')
  exit 2
}

$run = "$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ'))-$PID"
$bundle = Join-Path (Join-Path $Out $CaseId) $run
try {
  if (Test-Path -LiteralPath $bundle) { throw "bundle directory $bundle already exists" }
  [void](New-Item -ItemType Directory -Path $bundle)
  $files = New-Object System.Collections.ArrayList
  $excluded = New-Object System.Collections.ArrayList
  $written = 0
  foreach ($item in $sources) {
    if (-not $item.selected) { [void]$excluded.Add([ordered]@{ source_ref = $item.source_ref; reason = 'ACCESS_HISTORY_NOT_SELECTED' }); continue }
    if ($item.bytes -gt $MaxBytes) { [void]$excluded.Add([ordered]@{ source_ref = $item.source_ref; reason = 'TOO_LARGE' }); continue }
    $raw = [System.IO.File]::ReadAllBytes($item.path)
    $redacted = Redact ($Utf8.GetString($raw).TrimStart([char]0xFEFF))
    $name = ($item.source_ref -replace '/', '__')
    $bytes = $Utf8.GetBytes($redacted.text)
    [System.IO.File]::WriteAllBytes((Join-Path $bundle $name), $bytes)
    $written += 1
    if ($FailAfterFiles -gt 0 -and $written -ge $FailAfterFiles) { throw 'simulated write failure after the requested number of files' }
    [void]$files.Add([ordered]@{
      source_ref = $item.source_ref; name = $name; bytes = $bytes.Length; sha256 = (Sha256 $bytes); source_sha256 = (Sha256 $raw)
      derived = $(if ($redacted.count -gt 0) { 'REDACTED' } else { 'VERBATIM' }); redactions = $redacted.count
    })
  }
  $manifest = [ordered]@{
    schema = 'steward-log-bundle-1'; case_id = $CaseId; operation_id = $(if ($OperationId) { $OperationId } else { $null })
    collected_at = (Get-Date).ToUniversalTime().ToString('o'); uploaded = $false
    redaction_rules = @($Rules | ForEach-Object { $_.name }); files = @($files); excluded = @($excluded); gaps = @($gaps)
  }
  [System.IO.File]::WriteAllText((Join-Path $bundle 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6), $Utf8)
  Write-Output ([ordered]@{ ok = $true; bundle = "$CaseId/$run"; path = $bundle; files = $files.Count; gaps = @($gaps) } | ConvertTo-Json -Depth 4)
  exit 0
} catch {
  if (Test-Path -LiteralPath $bundle) { Remove-Item -LiteralPath $bundle -Recurse -Force -ErrorAction SilentlyContinue }
  [Console]::Error.WriteLine("日志包未生成：$($_.Exception.Message)")
  exit 1
}
