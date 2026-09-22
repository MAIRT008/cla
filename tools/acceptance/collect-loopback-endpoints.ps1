<#
.SYNOPSIS
  只读采集受保护程序发起的本机回环连接，供候选 loopback_endpoints 清单使用（T10 E40）。

.DESCRIPTION
  在 Owner 指定的隔离 Windows 验收机上，由 Owner 或其指定的测试人员执行；不在开发工作机上运行。
  只调用 Get-NetTCPConnection、Get-NetUDPEndpoint、Get-Process、Get-FileHash 读取状态，
  不改网络、防火墙、代理或服务，不发起任何连接。

  每轮输出一个 JSON：发起程序路径与 SHA-256、协议、远端回环地址、远端端口、监听进程路径与 SHA-256、
  首次与最后一次看到的时间、采样命中次数，以及本轮阶段与 CVR（本机代理）是否存在。
  用途不由脚本猜，由执行人在 -Purpose 里写本阶段在做什么，整理候选清单时再逐项确认。

  已知盲区：UDP 没有连接表，发起方到远端回环端口的 UDP 流量看不到；脚本只记录绑定在回环地址上的 UDP 端点
  （监听方）。受保护程序若依赖 UDP 回环，需要另行确认，不能凭本脚本写入模板。
  采样间隔之间建立又关闭的短连接可能漏记，所以每个阶段要重复多轮。

.EXAMPLE
  .\collect-loopback-endpoints.ps1 -ProtectedPaths 'C:\Program Files\Claude\claude.exe' -Phase login_oauth -Round 1 -CvrState absent -Purpose '首次登录 OAuth 回调'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $ProtectedPaths,

    [Parameter(Mandatory = $true)]
    [ValidateSet('cold_start', 'restart', 'login_oauth', 'managed_browser', 'local_service', 'other')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 1000)]
    [int] $Round,

    [Parameter(Mandatory = $true)]
    [ValidateSet('present', 'absent')]
    [string] $CvrState,

    [Parameter(Mandatory = $true)]
    [string] $Purpose,

    [ValidateRange(10, 3600)]
    [int] $DurationSeconds = 120,

    [ValidateRange(100, 10000)]
    [int] $IntervalMilliseconds = 250,

    [string] $OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'loopback-evidence')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$toolVersion = 'loopback-collector-1'
$protected = @($ProtectedPaths | ForEach-Object { $_.ToLowerInvariant() })
$pathCache = @{}
$hashCache = @{}

function Test-LoopbackAddress([string] $address) {
    return ($address -eq '::1') -or ($address -match '^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
}

function Get-ProcessPath([int] $processId) {
    if ($pathCache.ContainsKey($processId)) { return $pathCache[$processId] }
    $path = $null
    try { $path = (Get-Process -Id $processId -ErrorAction Stop).Path } catch { $path = $null }
    $pathCache[$processId] = $path
    return $path
}

function Get-Sha256([string] $path) {
    if (-not $path) { return $null }
    if ($hashCache.ContainsKey($path)) { return $hashCache[$path] }
    $hash = $null
    try { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { $hash = $null }
    $hashCache[$path] = $hash
    return $hash
}

$observations = @{}
$udpListeners = @{}
$samples = 0
$started = Get-Date
$deadline = $started.AddSeconds($DurationSeconds)

while ((Get-Date) -lt $deadline) {
    $samples += 1
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $listeners = @{}
    foreach ($row in $tcp) {
        if ($row.State -eq 'Listen') { $listeners["$($row.LocalAddress)|$($row.LocalPort)"] = [int] $row.OwningProcess }
    }
    foreach ($row in $tcp) {
        if ($row.State -eq 'Listen' -or -not (Test-LoopbackAddress ([string] $row.RemoteAddress))) { continue }
        $initiatorPath = Get-ProcessPath ([int] $row.OwningProcess)
        if (-not $initiatorPath -or ($protected -notcontains $initiatorPath.ToLowerInvariant())) { continue }
        $listenerPid = $listeners["$($row.RemoteAddress)|$($row.RemotePort)"]
        if ($null -eq $listenerPid) {
            $wildcard = if ($row.RemoteAddress -eq '::1') { '::' } else { '0.0.0.0' }
            $listenerPid = $listeners["$wildcard|$($row.RemotePort)"]
        }
        $listenerPath = if ($null -ne $listenerPid) { Get-ProcessPath $listenerPid } else { $null }
        $key = "$($initiatorPath.ToLowerInvariant())|tcp|$($row.RemoteAddress)|$($row.RemotePort)|$listenerPath"
        if (-not $observations.ContainsKey($key)) {
            $observations[$key] = [ordered]@{
                source_process_path   = $initiatorPath
                source_sha256         = Get-Sha256 $initiatorPath
                transport             = 'tcp'
                address               = [string] $row.RemoteAddress
                port                  = [int] $row.RemotePort
                listener_process_path = $listenerPath
                listener_sha256       = Get-Sha256 $listenerPath
                listener_is_protected = [bool] ($listenerPath -and ($protected -contains $listenerPath.ToLowerInvariant()))
                states                = @()
                first_seen            = $now
                last_seen             = $now
                hits                  = 0
            }
        }
        $entry = $observations[$key]
        $entry.last_seen = $now
        $entry.hits += 1
        if ($entry.states -notcontains [string] $row.State) { $entry.states += [string] $row.State }
    }
    foreach ($row in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        if (-not (Test-LoopbackAddress ([string] $row.LocalAddress))) { continue }
        $ownerPath = Get-ProcessPath ([int] $row.OwningProcess)
        $key = "$($row.LocalAddress)|$($row.LocalPort)|$ownerPath"
        if (-not $udpListeners.ContainsKey($key)) {
            $udpListeners[$key] = [ordered]@{
                address            = [string] $row.LocalAddress
                port               = [int] $row.LocalPort
                owner_process_path = $ownerPath
                owner_sha256       = Get-Sha256 $ownerPath
                owner_is_protected = [bool] ($ownerPath -and ($protected -contains $ownerPath.ToLowerInvariant()))
                first_seen         = $now
            }
        }
    }
    Start-Sleep -Milliseconds $IntervalMilliseconds
}

$report = [ordered]@{
    tool             = $toolVersion
    computer         = $env:COMPUTERNAME
    os_version       = [System.Environment]::OSVersion.VersionString
    started_at       = $started.ToUniversalTime().ToString('o')
    finished_at      = (Get-Date).ToUniversalTime().ToString('o')
    phase            = $Phase
    round            = $Round
    cvr_state        = $CvrState
    purpose          = $Purpose
    duration_seconds = $DurationSeconds
    interval_ms      = $IntervalMilliseconds
    samples          = $samples
    protected_paths  = @($ProtectedPaths | ForEach-Object { [ordered]@{ path = $_; sha256 = Get-Sha256 $_ } })
    tcp_observations = @($observations.Values)
    udp_loopback_endpoints = @($udpListeners.Values)
    limitations      = @(
        'UDP 发起方到远端回环端口的流量不在连接表里，这里只列绑定在回环地址上的 UDP 端点',
        '采样间隔内建立并关闭的短连接可能漏记，每个阶段要重复多轮',
        '用途由执行人填写，不由脚本推断'
    )
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$file = Join-Path -Path (Resolve-Path -LiteralPath $OutputDirectory).Path -ChildPath "loopback-$Phase-cvr_$CvrState-r$Round-$stamp.json"
[System.IO.File]::WriteAllText($file, ($report | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding $false))
Write-Output "已写入 $file（TCP 观测 $($observations.Count) 条，回环 UDP 端点 $($udpListeners.Count) 个，采样 $samples 次）"
