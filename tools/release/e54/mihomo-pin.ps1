<#
从 MetaCubeX 官方 release metadata 取得并核对 Mihomo v1.19.30 Windows AMD64（Windows PowerShell 5.1，只在 GitHub runner 上跑）。

  mihomo-pin.ps1 -Mode pin     取得、核对、写 build\logs\mihomo-pin.json，再生成把 EXE 哈希写进 release-inputs.json 的补丁（不提交）
  mihomo-pin.ps1 -Mode build   同样取得与核对，再要求 release-inputs.json 已固定的哈希与本次 EXE 一致

- 只接受资产名 mihomo-windows-amd64-v1.19.30.zip；tag 必须指向固定提交；资产必须带 GitHub 返回的 sha256 digest。
- 先核归档大小与 digest，再解压；归档里必须恰好一个预期名字的 EXE，且 PE 头是 AMD64。
- EXE 放到 build\inputs\mihomo-windows-amd64-v1.19.30.exe；目标已存在就拒绝，不覆盖。
- GITHUB_TOKEN 只用于 api.github.com 的只读请求，从不写进日志；下载资产不带认证头。
#>
[CmdletBinding()]
param(
  [ValidateSet('pin', 'build')]
  [string]$Mode = 'pin'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Tag = 'v1.19.30'
$AssetName = 'mihomo-windows-amd64-v1.19.30.zip'
$ExpectedCommit = 'ac017cdd246ce8bd547653d927e7bf77d7ee73d5'
$ExeEntryPattern = '^mihomo-windows-amd64(-v1\.19\.30)?\.exe$'
$InputsRelative = 'tools/release/release-inputs.json'
$PinLine = '"sha256": null, "pin": "PIN_REQUIRED"'

# 不用 Get-FileHash：它在 5.1 里定义在脚本模块中，从 pwsh 7 启动时 PSModulePath 先指到 7 的模块，会找不到。
function Get-Sha256([string]$path) {
  $stream = [System.IO.File]::OpenRead($path)
  try { $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($stream) } finally { $stream.Dispose() }
  return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
}

function Get-GitHubJson([string]$uri) {
  $headers = @{ 'X-GitHub-Api-Version' = '2022-11-28' }
  if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
  return Invoke-RestMethod -Uri $uri -Headers $headers -UserAgent 'steward-e54-mihomo-pin' -UseBasicParsing
}

# 返回 PE 头里的机器类型（十六进制）；不是 PE 文件就抛错。
function Get-PeMachine([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw 'not an MZ executable' }
  $offset = [System.BitConverter]::ToInt32($bytes, 0x3C)
  if ($offset -lt 0 -or $offset + 6 -gt $bytes.Length) { throw 'PE header offset out of range' }
  if ($bytes[$offset] -ne 0x50 -or $bytes[$offset + 1] -ne 0x45 -or $bytes[$offset + 2] -ne 0 -or $bytes[$offset + 3] -ne 0) { throw 'PE signature missing' }
  return ('0x{0:x4}' -f [System.BitConverter]::ToUInt16($bytes, $offset + 4))
}

# 把 mihomo 那一行的「未固定」换成 EXE 哈希，用 git 生成补丁后原样还原工作区文件。
function Save-PinPatch([string]$repo, [string]$digest, [string]$patchPath) {
  $file = Join-Path $repo ($InputsRelative.Replace('/', '\'))
  $original = [System.IO.File]::ReadAllText($file, $Utf8)
  $originalHash = Get-Sha256 $file
  $lines = $original.Split("`n")
  $mihomo = @($lines | Where-Object { $_.Contains('"id": "mihomo"') })
  if ($mihomo.Count -ne 1) { throw "expected exactly one mihomo line in $InputsRelative, found $($mihomo.Count)" }
  if (([regex]::Matches($original, [regex]::Escape($PinLine))).Count -ne 1 -or -not $mihomo[0].Contains($PinLine)) { throw "the mihomo line does not carry the unpinned marker exactly once" }
  $pinned = $original.Replace($PinLine, "`"sha256`": `"$digest`"")
  try {
    [System.IO.File]::WriteAllText($file, $pinned, $Utf8)
    & git -C $repo diff --no-color "--output=$patchPath" -- $InputsRelative
    if ($LASTEXITCODE -ne 0) { throw "git diff exited $LASTEXITCODE" }
  } finally {
    & git -C $repo checkout -q -- $InputsRelative
  }
  if ((Get-Sha256 $file) -ne $originalHash) { throw "$InputsRelative was not restored byte for byte" }
  if (-not (Test-Path -LiteralPath $patchPath) -or (Get-Item -LiteralPath $patchPath).Length -eq 0) { throw 'git diff produced no patch' }
}

function Invoke-Main {
  $logs = Join-Path $Repo 'build\logs'
  $inputs = Join-Path $Repo 'build\inputs'
  $exeTarget = Join-Path $inputs 'mihomo-windows-amd64-v1.19.30.exe'
  $pinJson = Join-Path $logs 'mihomo-pin.json'
  [void](New-Item -ItemType Directory -Force -Path $logs, $inputs)
  if (Test-Path -LiteralPath $exeTarget) { throw 'build\inputs\mihomo-windows-amd64-v1.19.30.exe already exists; refusing to overwrite' }
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $release = Get-GitHubJson "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/$Tag"
  if ($release.tag_name -ne $Tag) { throw "release tag is '$($release.tag_name)', expected $Tag" }
  $assets = @($release.assets | Where-Object { $_.name -eq $AssetName })
  if ($assets.Count -ne 1) { throw "expected exactly one asset named $AssetName, found $($assets.Count)" }
  $asset = $assets[0]
  if ("$($asset.digest)" -notmatch '^sha256:[0-9a-f]{64}$') { throw "asset digest is missing or not sha256: '$($asset.digest)'" }
  $archiveDigest = "$($asset.digest)".Substring(7)
  $commit = Get-GitHubJson "https://api.github.com/repos/MetaCubeX/mihomo/commits/$Tag"
  if ($commit.sha -ne $ExpectedCommit) { throw "tag $Tag points to $($commit.sha), expected $ExpectedCommit" }
  Write-Host "mihomo.release id=$($release.id) published=$($release.published_at) asset=$AssetName size=$($asset.size) digest=sha256:$archiveDigest commit=$($commit.sha)"

  $work = Join-Path $inputs "mihomo-download.partial-$PID"
  [void](New-Item -ItemType Directory -Path $work)
  try {
    $zip = Join-Path $work $AssetName
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UserAgent 'steward-e54-mihomo-pin' -UseBasicParsing
    $zipSize = (Get-Item -LiteralPath $zip).Length
    $zipDigest = Get-Sha256 $zip
    if ($zipSize -ne [long]$asset.size) { throw "archive size $zipSize differs from release metadata $($asset.size)" }
    if ($zipDigest -ne $archiveDigest) { throw "archive sha256 $zipDigest differs from release digest $archiveDigest" }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
    try {
      $entries = @($archive.Entries | Where-Object { -not $_.FullName.EndsWith('/') })
      $listing = @($entries | ForEach-Object { [ordered]@{ name = $_.FullName; size = $_.Length } })
      $exes = @($entries | Where-Object { $_.FullName -like '*.exe' })
      if ($exes.Count -ne 1) { throw "expected exactly one .exe in the archive, found $($exes.Count)" }
      $exe = $exes[0]
      if ($exe.FullName -notmatch $ExeEntryPattern) { throw "archive exe is named '$($exe.FullName)', expected $ExeEntryPattern" }
      $exeEntry = $exe.FullName
      [System.IO.Compression.ZipFileExtensions]::ExtractToFile($exe, $exeTarget)
    } finally {
      $archive.Dispose()
    }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }

  $machine = Get-PeMachine $exeTarget
  if ($machine -ne '0x8664') { throw "archive exe PE machine is $machine, expected 0x8664 (AMD64)" }
  $exeDigest = Get-Sha256 $exeTarget
  $pin = [ordered]@{
    schema = 'steward-e54-mihomo-pin-1'
    mode = $Mode
    retrieved_utc = (Get-Date).ToUniversalTime().ToString('o')
    repository = 'MetaCubeX/mihomo'
    tag = $Tag
    commit = $commit.sha
    release_id = $release.id
    published_at = $release.published_at
    asset = [ordered]@{ name = $AssetName; url = $asset.browser_download_url; size = [long]$asset.size; digest = "sha256:$archiveDigest" }
    archive_entries = $listing
    exe = [ordered]@{ entry = $exeEntry; path = 'build/inputs/mihomo-windows-amd64-v1.19.30.exe'; size = (Get-Item -LiteralPath $exeTarget).Length; sha256 = $exeDigest; pe_machine = $machine }
  }

  [System.IO.File]::WriteAllText($pinJson, ($pin | ConvertTo-Json -Depth 6), $Utf8)
  if ($Mode -eq 'pin') {
    $patch = Join-Path $logs 'mihomo-pin.patch'
    Save-PinPatch $Repo $exeDigest $patch
    $pin['patch'] = [ordered]@{ path = 'build/logs/mihomo-pin.patch'; sha256 = (Get-Sha256 $patch); applies_to = $InputsRelative }
    [System.IO.File]::WriteAllText($pinJson, ($pin | ConvertTo-Json -Depth 6), $Utf8)
  }
  Write-Host "mihomo.exe entry=$exeEntry sha256=$exeDigest pe_machine=$machine"

  if ($Mode -eq 'build') {
    $declared = @(([System.IO.File]::ReadAllText((Join-Path $Repo $InputsRelative), $Utf8) | ConvertFrom-Json).items | Where-Object { $_.id -eq 'mihomo' })
    if ($declared.Count -ne 1) { throw 'release-inputs.json must declare exactly one mihomo item' }
    if ($declared[0].pin -eq 'PIN_REQUIRED' -or "$($declared[0].sha256)" -ne $exeDigest) { throw "PIN_MISMATCH: release-inputs.json mihomo sha256 is '$($declared[0].sha256)', downloaded exe is $exeDigest" }
    Write-Host 'mihomo.pin MATCH release-inputs.json'
  }
}

if ($MyInvocation.InvocationName -ne '.') {
  try {
    Invoke-Main
    exit 0
  } catch {
    Write-Host "mihomo.failed $($_.Exception.Message)"
    exit 1
  }
}
