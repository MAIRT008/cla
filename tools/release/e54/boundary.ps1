<#
E54 镜像边界与秘密检查（Windows PowerShell 5.1；不装工具、不联网、不改文件）。

  boundary.ps1 [-Tracked] [-LogFile <路径>]

- 不带 -Tracked：遍历镜像目录（跳过 .git），在初始化 Git 之前用。
- 带 -Tracked：只看 git ls-files 的已跟踪文件，CI checkout 之后、安装任何工具或下载依赖之前用。
- 查五类问题：白名单外路径、禁止目录、符号链接/重解析点/子模块、私钥与凭据类文件名、高置信秘密模式。
- 秘密模式只报文件名与模式名，从不输出命中正文；命中文件必须在 SOURCE-MIRROR.json 的人工复核清单里、模式与哈希都一致才放行。
- 有任何问题退出 1，全部通过退出 0。
#>
[CmdletBinding()]
param(
  [switch]$Tracked,
  [string]$LogFile = ''
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)

$ForbiddenSegments = @('fixtures', 'experiments', 'dist', 'build', 'node_modules', 'target')
$SecretFileName = '(?i)(\.(pfx|p12|pem|key)$|^\.env$|^\.env\.|^auth\.json$|^credentials\.json$)'
$SecretPatterns = [ordered]@{
  'pem-private-key'      = '-----BEGIN ([A-Z]+ )*PRIVATE KEY-----'
  'github-pat'           = 'github_pat_[A-Za-z0-9_]{20,}'
  'github-classic-token' = '\bghp_[A-Za-z0-9]{20,}'
  'aws-access-key-id'    = '\bAKIA[0-9A-Z]{16}\b'
  'sk-key'               = '\bsk-[A-Za-z0-9_-]{20,}'
}

$problems = New-Object System.Collections.Generic.List[string]
function Report([string]$code, [string]$path, [string]$detail = '') {
  $line = "boundary.$code $path"
  if ($detail) { $line = "$line $detail" }
  $problems.Add($line)
}
function Write-Log([string]$line) {
  Write-Host $line
  if ($LogFile) { [System.IO.File]::AppendAllText($LogFile, "$line`r`n", $Utf8) }
}

if ($LogFile) {
  $LogFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Get-Location).ProviderPath, $LogFile))
  [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogFile))
}

$mirrorFile = Join-Path $Root 'SOURCE-MIRROR.json'
if (-not (Test-Path -LiteralPath $mirrorFile)) {
  Write-Log 'boundary.MISSING_SOURCE_MIRROR SOURCE-MIRROR.json'
  Write-Log 'boundary.result FAIL'
  exit 1
}
$mirror = [System.IO.File]::ReadAllText($mirrorFile, $Utf8) | ConvertFrom-Json
$allowedFiles = @($mirror.whitelist.files) + @($mirror.whitelist.mirror_additions | Where-Object { -not $_.EndsWith('/') })
$allowedPrefixes = @($mirror.whitelist.directories | ForEach-Object { "$_/" }) + @($mirror.whitelist.mirror_additions | Where-Object { $_.EndsWith('/') })
$allowedDist = @($mirror.whitelist.allowed_dist_directories)
$reviewed = @($mirror.secret_scan.reviewed_synthetic)

# 收集待查文件：相对路径统一用正斜杠。
$files = New-Object System.Collections.Generic.List[string]
if ($Tracked) {
  $previousEncoding = [Console]::OutputEncoding
  [Console]::OutputEncoding = $Utf8
  try {
    $raw = (& git -C $Root -c core.quotepath=false ls-files -s -z) -join "`n"
    $gitCode = $LASTEXITCODE
  } finally {
    [Console]::OutputEncoding = $previousEncoding
  }
  if ($gitCode -ne 0) { Write-Log "boundary.GIT_FAILED ls-files exit=$gitCode"; Write-Log 'boundary.result FAIL'; exit 1 }
  foreach ($entry in ($raw -split "`0")) {
    if (-not $entry) { continue }
    $tab = $entry.IndexOf("`t")
    $mode = $entry.Substring(0, 6)
    $path = $entry.Substring($tab + 1)
    if ($mode -eq '120000') { Report 'SYMLINK' $path }
    elseif ($mode -eq '160000') { Report 'SUBMODULE' $path }
    $files.Add($path)
  }
} else {
  $pending = New-Object System.Collections.Generic.Stack[string]
  $pending.Push($Root)
  while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    foreach ($item in [System.IO.Directory]::GetFileSystemEntries($directory)) {
      $relative = $item.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/')
      if ($relative -eq '.git') { continue }
      $attributes = [System.IO.File]::GetAttributes($item)
      if ($attributes -band [System.IO.FileAttributes]::ReparsePoint) { Report 'REPARSE_POINT' $relative; continue }
      if ($attributes -band [System.IO.FileAttributes]::Directory) { $pending.Push($item) } else { $files.Add($relative) }
    }
  }
}

$reviewedHits = 0
foreach ($path in $files) {
  $allowed = ($allowedFiles -contains $path) -or [bool]($allowedPrefixes | Where-Object { $path.StartsWith($_) })
  if (-not $allowed) { Report 'OUTSIDE_WHITELIST' $path }

  $segments = $path.Split('/')
  for ($i = 0; $i -lt $segments.Length - 1; $i++) {
    $prefix = ($segments[0..$i] -join '/')
    if (($ForbiddenSegments -contains $segments[$i].ToLowerInvariant()) -and -not ($allowedDist -contains $prefix)) { Report 'FORBIDDEN_DIRECTORY' $path; break }
  }
  if ($path.StartsWith('services/control/')) { Report 'FORBIDDEN_DIRECTORY' $path }
  if ($segments[-1] -match $SecretFileName) { Report 'SECRET_FILE_NAME' $path }

  $absolute = Join-Path $Root ($path.Replace('/', '\'))
  if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { Report 'NOT_ON_DISK' $path; continue }
  if ([System.IO.File]::GetAttributes($absolute) -band [System.IO.FileAttributes]::ReparsePoint) { Report 'REPARSE_POINT' $path; continue }

  $bytes = [System.IO.File]::ReadAllBytes($absolute)
  $text = $Latin1.GetString($bytes)
  foreach ($name in $SecretPatterns.Keys) {
    if (-not [regex]::IsMatch($text, $SecretPatterns[$name])) { continue }
    $digest = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    $match = $reviewed | Where-Object { $_.path -eq $path -and $_.pattern -eq $name -and $_.sha256 -eq $digest }
    if ($match) { $reviewedHits += 1 } else { Report 'SECRET_PATTERN' $path $name }
  }
}

$problems | ForEach-Object { Write-Log $_ }
$status = if ($problems.Count -eq 0) { 'PASS' } else { 'FAIL' }
Write-Log "boundary.result $status mode=$(if ($Tracked) { 'tracked' } else { 'filesystem' }) files=$($files.Count) problems=$($problems.Count) reviewed_synthetic_hits=$reviewedHits"
if ($problems.Count -eq 0) { exit 0 } else { exit 1 }
