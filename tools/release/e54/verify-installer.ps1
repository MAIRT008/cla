<#
E54 安装包内容核对（Windows PowerShell 5.1；构建完成后在 GitHub runner 上跑，只读构建产物）。

  verify-installer.ps1 [-SevenZip <7z.exe>] [-Root <仓库根>]

- 用 7-Zip 解开 NSIS 安装包，列出实际文件、逐个算 SHA-256。
- 以 build\release-staging\release-manifest.json 为准：每个带目标路径的项都要在包里、哈希一致；包里的 release-manifest.json 与装配目录那份逐字节一致。
- 包里的每个文件都要归类：清单项、主程序（恰好一个）、NSIS 内部文件（$PLUGINSDIR 等变量目录、[NSIS] 条目、uninstall.exe）；其余一律算清单外文件。
- 路径不得落进 services/control、fixtures、experiments、dist、tests、evidence、node_modules；
  文本文件与本项目编译的程序不得含高置信秘密模式或非 runner 账号的用户目录绝对路径（第三方程序只核哈希，不扫内容）。
- 三份 Cargo.lock 必须仍是生成时的哈希（对 build\logs\generated-inputs.json 与 manifest 的 build_inputs）。
- 结果写 build\logs\e54-installer-contents.json 与 build\logs\e54-hashes.json；有任何问题退出 1。
#>
[CmdletBinding()]
param(
  [string]$SevenZip = 'C:\Program Files\7-Zip\7z.exe',
  [string]$Root = ''
)

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) }
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)
$Logs = Join-Path $Root 'build\logs'
$InstallerDir = Join-Path $Root 'apps\desktop-host\src-tauri\target\release\bundle\nsis'
$StagingManifest = Join-Path $Root 'build\release-staging\release-manifest.json'
$Extract = Join-Path $Root 'build\e54-installer-extract'
$ForbiddenSegments = @('services/control', 'fixtures', 'experiments', 'dist', 'tests', 'evidence', 'node_modules')
$TextExtensions = @('.json', '.md', '.txt', '.ps1', '.cmd', '.bat', '.nsi', '.nsh', '.html', '.js', '.mjs', '.css', '.yaml', '.yml', '.toml', '.xml', '.ini', '.log')
$OwnPrograms = @('control/ai-steward-control.exe', 'service/ai-environmental-steward-service.exe', 'service/ai-environmental-steward-service-install.exe', 'service/ai-environmental-steward-service-uninstall.exe')
$SecretPatterns = [ordered]@{
  'pem-private-key'      = '-----BEGIN ([A-Z]+ )*PRIVATE KEY-----'
  'github-pat'           = 'github_pat_[A-Za-z0-9_]{20,}'
  'github-classic-token' = '\bghp_[A-Za-z0-9]{20,}'
  'aws-access-key-id'    = '\bAKIA[0-9A-Z]{16}\b'
  'sk-key'               = '\bsk-[A-Za-z0-9_-]{20,}'
}
$UserProfilePath = '(?i)\b[A-Z]:[\\/]+Users[\\/]+([^\\/\x00-\x1f"''<>|*?]+)[\\/]'
$RunnerAccounts = @('runneradmin', 'default', 'public', 'all users')

$problems = New-Object System.Collections.Generic.List[object]
function Problem([string]$code, [string]$path, [string]$detail = '') {
  $problems.Add([ordered]@{ code = $code; path = $path; detail = $detail })
  Write-Host "installer.$code $path $detail"
}
# 不用 Get-FileHash：它在 5.1 里定义在脚本模块中，从 pwsh 7 启动时 PSModulePath 先指到 7 的模块，会找不到。
function Get-Sha256([string]$path) {
  $stream = [System.IO.File]::OpenRead($path)
  try { $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($stream) } finally { $stream.Dispose() }
  return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
}
function Get-Relative([string]$base, [string]$path) { return $path.Substring($base.Length).TrimStart('\', '/').Replace('\', '/') }
function Save-Json([string]$name, $value) { [System.IO.File]::WriteAllText((Join-Path $Logs $name), ($value | ConvertTo-Json -Depth 8), $Utf8) }

[void](New-Item -ItemType Directory -Force -Path $Logs)
$installers = @(Get-ChildItem -LiteralPath $InstallerDir -Filter '*.exe' -File -ErrorAction SilentlyContinue)
if ($installers.Count -ne 1) { Write-Host "installer.INSTALLER_COUNT expected exactly one NSIS installer, found $($installers.Count)"; exit 1 }
if (-not (Test-Path -LiteralPath $StagingManifest)) { Write-Host 'installer.MANIFEST_MISSING build/release-staging/release-manifest.json'; exit 1 }
if (Test-Path -LiteralPath $Extract) { Write-Host 'installer.EXTRACT_EXISTS build/e54-installer-extract already exists'; exit 1 }
if (-not (Test-Path -LiteralPath $SevenZip)) { Write-Host "installer.EXTRACTOR_MISSING $SevenZip"; exit 1 }
$installer = $installers[0]
$manifest = [System.IO.File]::ReadAllText($StagingManifest, $Utf8) | ConvertFrom-Json

# 7-Zip 的进度与提示写 stderr；Windows PowerShell 5.1 在 Stop 下重定向 stderr 会抛错，这里只按退出码判断。
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
  $extractorVersion = (& $SevenZip 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match '7-Zip' } | Select-Object -First 1)
  $output = & $SevenZip x -y "-o$Extract" $installer.FullName 2>&1 | ForEach-Object { "$_" }
  $extractCode = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $previous
}
[System.IO.File]::WriteAllLines((Join-Path $Logs 'e54-7z-extract.log'), [string[]]@($output), $Utf8)
if ($extractCode -ne 0) { Write-Host "installer.EXTRACT_FAILED exit=$extractCode"; exit 1 }

$expected = [ordered]@{}
foreach ($item in @($manifest.items)) { if ($item.target) { $expected[$item.target] = [ordered]@{ id = $item.id; sha256 = $item.sha256; found = $false } } }
$expected['release-manifest.json'] = [ordered]@{ id = 'release-manifest'; sha256 = (Get-Sha256 $StagingManifest); found = $false }

$files = @()
$mainCandidates = @()
foreach ($file in @(Get-ChildItem -LiteralPath $Extract -Recurse -File -Force)) {
  $path = Get-Relative $Extract $file.FullName
  $normalized = $path -replace '^(?i)\$INSTDIR/', ''
  $digest = Get-Sha256 $file.FullName
  $class = 'unexpected'
  if ($expected.Contains($normalized)) {
    $class = 'manifest'
    $expected[$normalized].found = $true
    if ($expected[$normalized].sha256 -ne $digest) { Problem 'HASH_MISMATCH' $normalized "installer=$digest manifest=$($expected[$normalized].sha256)" }
  } elseif ($normalized.StartsWith('$') -or $normalized.StartsWith('[NSIS]')) {
    $class = 'nsis-internal'
  } elseif ($normalized -notmatch '/' -and $normalized -match '(?i)^uninstall\.exe$') {
    $class = 'nsis-internal'
  } elseif ($normalized -notmatch '/' -and $normalized -match '(?i)\.exe$') {
    $class = 'main-program'
    $mainCandidates += $normalized
  } else {
    Problem 'UNEXPECTED_FILE' $normalized
  }
  foreach ($segment in $ForbiddenSegments) {
    if ("/$($normalized.ToLowerInvariant())".Contains("/$segment/")) { Problem 'FORBIDDEN_PATH' $normalized $segment }
  }
  $files += [ordered]@{ path = $path; normalized = $normalized; bytes = $file.Length; sha256 = $digest; class = $class }
}
foreach ($target in $expected.Keys) { if (-not $expected[$target].found) { Problem 'MISSING_IN_INSTALLER' $target $expected[$target].id } }
if ($mainCandidates.Count -ne 1) { Problem 'MAIN_PROGRAM_COUNT' '' "found $($mainCandidates.Count): $($mainCandidates -join ',')" }

$scanned = @()
foreach ($entry in $files) {
  $extension = [System.IO.Path]::GetExtension($entry.normalized).ToLowerInvariant()
  $own = ($OwnPrograms -contains $entry.normalized) -or ($entry.class -eq 'main-program')
  if (-not $own -and -not ($TextExtensions -contains $extension)) { continue }
  $absolute = Join-Path $Extract ($entry.path.Replace('/', '\'))
  $text = $Latin1.GetString([System.IO.File]::ReadAllBytes($absolute))
  foreach ($name in $SecretPatterns.Keys) { if ([regex]::IsMatch($text, $SecretPatterns[$name])) { Problem 'SECRET_PATTERN' $entry.normalized $name } }
  foreach ($match in [regex]::Matches($text, $UserProfilePath)) {
    if (-not ($RunnerAccounts -contains $match.Groups[1].Value.ToLowerInvariant())) { Problem 'LOCAL_USER_PATH' $entry.normalized 'user-profile path of a non-runner account'; break }
  }
  $scanned += $entry.normalized
}

$main = $null
if ($mainCandidates.Count -eq 1) {
  $mainEntry = $files | Where-Object { $_.normalized -eq $mainCandidates[0] }
  $built = Join-Path $Root "apps\desktop-host\src-tauri\target\release\$($mainCandidates[0])"
  $main = [ordered]@{ name = $mainCandidates[0]; sha256 = $mainEntry.sha256; target_release_sha256 = $(if (Test-Path -LiteralPath $built) { Get-Sha256 $built } else { $null }) }
}

$generatedFile = Join-Path $Logs 'generated-inputs.json'
$generated = if (Test-Path -LiteralPath $generatedFile) { [System.IO.File]::ReadAllText($generatedFile, $Utf8) | ConvertFrom-Json } else { $null }
$locks = @()
foreach ($lockInput in @($manifest.build_inputs)) {
  $current = Join-Path $Root ($lockInput.source.Replace('/', '\'))
  $now = if (Test-Path -LiteralPath $current) { Get-Sha256 $current } else { $null }
  $atGeneration = if ($generated) { (@($generated.files) | Where-Object { $_.path -eq $lockInput.source } | Select-Object -First 1).sha256 } else { $null }
  if ($now -ne $lockInput.sha256 -or $atGeneration -ne $lockInput.sha256) { Problem 'LOCK_CHANGED' $lockInput.source "generated=$atGeneration manifest=$($lockInput.sha256) now=$now" }
  $locks += [ordered]@{ id = $lockInput.id; path = $lockInput.source; sha256 = $lockInput.sha256 }
}

$status = if ($problems.Count -eq 0) { 'PASS' } else { 'FAIL' }
$counts = [ordered]@{}
foreach ($entry in $files) { $counts[$entry.class] = 1 + [int]$counts[$entry.class] }
Save-Json 'e54-installer-contents.json' ([ordered]@{
  schema = 'steward-e54-installer-contents-1'
  status = $status
  installer = [ordered]@{ name = $installer.Name; bytes = $installer.Length; sha256 = (Get-Sha256 $installer.FullName) }
  extractor = [ordered]@{ path = $SevenZip; version = $extractorVersion }
  frontend_note = 'Tauri embeds frontendDist into the main program; page files are not separate installer entries. Their hashes are in release-manifest.json.'
  class_counts = $counts
  expected = $expected
  main_program = $main
  scanned_for_secrets_and_paths = $scanned
  files = $files
  problems = $problems
})

$third = Join-Path $Root 'build\inputs\THIRD-PARTY-RUST.txt'
$hostBuilt = Join-Path $Root 'apps\desktop-host\src-tauri\target\release\ai-steward-desktop-host.exe'
$icons = @(Get-ChildItem -LiteralPath (Join-Path $Root 'apps\desktop-host\src-tauri\icons') -File | ForEach-Object { [ordered]@{ path = "apps/desktop-host/src-tauri/icons/$($_.Name)"; sha256 = (Get-Sha256 $_.FullName) } })
Save-Json 'e54-hashes.json' ([ordered]@{
  schema = 'steward-e54-hashes-1'
  status = $status
  installer = [ordered]@{ name = $installer.Name; bytes = $installer.Length; sha256 = (Get-Sha256 $installer.FullName) }
  main_program = $main
  host_build_output = [ordered]@{ path = 'apps/desktop-host/src-tauri/target/release/ai-steward-desktop-host.exe'; sha256 = $(if (Test-Path -LiteralPath $hostBuilt) { Get-Sha256 $hostBuilt } else { $null }) }
  packaged = @($manifest.items | Where-Object { $_.target } | ForEach-Object { [ordered]@{ id = $_.id; target = $_.target; sha256 = $_.sha256 } })
  release_manifest = [ordered]@{ path = 'build/release-staging/release-manifest.json'; sha256 = (Get-Sha256 $StagingManifest) }
  cargo_locks = $locks
  third_party_rust = [ordered]@{ path = 'build/inputs/THIRD-PARTY-RUST.txt'; sha256 = $(if (Test-Path -LiteralPath $third) { Get-Sha256 $third } else { $null }) }
  icons = $icons
})

Write-Host "installer.result $status files=$($files.Count) problems=$($problems.Count) installer=$($installer.Name)"
if ($problems.Count -eq 0) { exit 0 } else { exit 1 }
