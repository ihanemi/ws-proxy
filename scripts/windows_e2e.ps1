param(
    [Parameter(Mandatory = $true)][string]$Relay,
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$ClientPath = ".\WsVpn.exe",
    [string]$TunName = "wsvpn",
    [int]$StartupTimeoutSeconds = 30,
    [switch]$TestIpv6Internet
)

$ErrorActionPreference = "Stop"
$statePath = Join-Path $env:ProgramData "WsVpn\state.json"
$process = $null
$session = $null
$clientWasStarted = $false
$cleanupSucceeded = $false
$bypassRouteCreated = $false

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SessionState {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $null }
    return Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
}

function Assert-SessionJournal {
    param([Parameter(Mandatory = $true)]$State)
    if ($State.version -ne 2 -or -not $State.session_id) {
        throw "Recovery journal is missing its version 2 session identity."
    }
    if ($State.tun_name -ne $TunName -or -not $State.tun2socks_pid) {
        throw "Recovery journal does not identify the active TUN process."
    }
    if (-not $State.firewall_names -or -not $State.routes) {
        throw "Recovery journal is missing firewall or route ownership records."
    }
    foreach ($name in $State.firewall_names) {
        $rule = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction SilentlyContinue)
        if ($rule.Count -ne 1 -or $rule[0].Enabled -ne "True" -or $rule[0].Action -ne "Block") {
            throw "Journaled firewall rule is absent or ineffective: $name"
        }
    }
    foreach ($route in @($State.routes | Where-Object created -eq $true)) {
        $actual = @(Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex $route.interface_index `
            -DestinationPrefix $route.prefix -ErrorAction SilentlyContinue | Where-Object {
                $_.NextHop -eq $route.next_hop -and $_.RouteMetric -eq $route.metric -and $_.Protocol -eq "NetMgmt"
            })
        if ($actual.Count -ne 1) { throw "Journaled route is absent or ambiguous: $($route.prefix)" }
    }
}

function Invoke-ParallelHttps {
    $jobs = @()
    try {
        foreach ($number in 1..6) {
            $jobs += Start-Job -ScriptBlock {
                & curl.exe --fail --silent --show-error --connect-timeout 8 --max-time 20 `
                    -4 "https://example.com/?wsvpn-e2e=$using:number" -o NUL
                return $LASTEXITCODE
            }
        }
        $finished = @(Wait-Job -Job $jobs -Timeout 25)
        if ($finished.Count -ne $jobs.Count) {
            throw "Concurrent HTTPS streams did not finish before the timeout."
        }
        foreach ($job in $jobs) {
            $exitCode = Receive-Job -Job $job
            if ($job.State -ne "Completed" -or $exitCode -ne 0) {
                throw "A concurrent HTTPS stream failed (state=$($job.State), exit=$exitCode)."
            }
        }
    }
    finally {
        $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell (Run as Administrator)."
}
if (Test-Path -LiteralPath $statePath) {
    throw "A recovery journal already exists. Inspect it and run the client --cleanup before this test."
}
$orphanRules = @(Get-NetFirewallRule -Name "WSVPN-KillSwitch-*" -ErrorAction SilentlyContinue)
if ($orphanRules) {
    throw "Unjournaled WS VPN firewall rules already exist; refusing to mix them with the test session."
}

$resolvedClient = (Resolve-Path $ClientPath).Path
$previousToken = $env:WS_VPN_TOKEN
$env:WS_VPN_TOKEN = $Token

try {
    Write-Host "[1/8] Starting WS VPN and waiting for its ownership journal..."
    $process = Start-Process -FilePath $resolvedClient -ArgumentList @(
        "--relay", $Relay, "--tun", "--tun-name", $TunName
    ) -PassThru -NoNewWindow
    $clientWasStarted = $true
    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    do {
        if ($process.HasExited) { throw "WsVpn exited during startup with code $($process.ExitCode)." }
        $adapter = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
        $session = Get-SessionState
        $ipv4Route = Get-NetRoute -InterfaceAlias $TunName -DestinationPrefix "0.0.0.0/0" `
            -ErrorAction SilentlyContinue
        $ipv6Route = Get-NetRoute -InterfaceAlias $TunName -DestinationPrefix "::/0" `
            -ErrorAction SilentlyContinue
        if ($adapter -and $session -and $ipv4Route -and $ipv6Route) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    if (-not $adapter -or -not $session -or -not $ipv4Route -or -not $ipv6Route) {
        throw "TUN adapter, IPv4/IPv6 routes, and journal did not become ready within $StartupTimeoutSeconds seconds."
    }

    Write-Host "[2/8] Verifying exact journaled routes and firewall rules..."
    Assert-SessionJournal -State $session

    Write-Host "[3/8] Testing multiple UDP DNS destinations through the tunnel..."
    foreach ($server in @("1.1.1.1", "8.8.8.8")) {
        $udp = Resolve-DnsName example.com -Server $server -DnsOnly -QuickTimeout -ErrorAction Stop
        $tcp = Resolve-DnsName example.com -Server $server -DnsOnly -TcpOnly -QuickTimeout -ErrorAction Stop
        if (-not $udp -or -not $tcp) { throw "DNS through $server returned no records." }
    }

    Write-Host "[4/8] Testing concurrent TCP streams through the tunnel..."
    Invoke-ParallelHttps
    if ($TestIpv6Internet) {
        & curl.exe --fail --silent --show-error --connect-timeout 8 --max-time 20 `
            -6 https://example.com/ -o NUL
        if ($LASTEXITCODE -ne 0) { throw "IPv6 HTTPS test failed with curl exit code $LASTEXITCODE." }
    }

    Write-Host "[5/8] Verifying a physical-interface Internet bypass is blocked..."
    $existingBypass = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix "1.1.1.1/32" -ErrorAction SilentlyContinue)
    if ($existingBypass) {
        throw "Cannot run the bypass probe because a 1.1.1.1/32 route already exists."
    }
    New-NetRoute -DestinationPrefix "1.1.1.1/32" -InterfaceIndex $session.primary_interface_index -NextHop $session.primary_gateway -RouteMetric 2 -PolicyStore ActiveStore | Out-Null
    $bypassRouteCreated = $true
    $bypass = Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($bypass) {
        throw "Public TCP escaped through the physical interface while the kill switch was active."
    }
    Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix "1.1.1.1/32" -InterfaceIndex $session.primary_interface_index |
        Where-Object { $_.NextHop -eq $session.primary_gateway -and $_.RouteMetric -eq 2 -and $_.Protocol -eq "NetMgmt" } |
        Remove-NetRoute -Confirm:$false
    $bypassRouteCreated = $false

    Write-Host "[6/8] Force-killing tun2socks and checking fail-closed behavior..."
    Stop-Process -Id $session.tun2socks_pid -Force -ErrorAction Stop
    if (-not $process.WaitForExit(15000)) {
        throw "The client did not notice the tun2socks failure within 15 seconds."
    }
    if ($process.ExitCode -eq 0) {
        throw "Unexpected tun2socks death was reported as a successful client exit."
    }
    foreach ($name in $session.firewall_names) {
        if (-not (Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction SilentlyContinue)) {
            throw "Kill-switch rule disappeared after tun2socks failure: $name"
        }
    }

    Write-Host "[7/8] Running ownership-aware crash recovery..."
    & $resolvedClient --cleanup
    if ($LASTEXITCODE -ne 0) { throw "Automatic --cleanup failed with exit code $LASTEXITCODE." }
    $cleanupSucceeded = $true

    Write-Host "[8/8] Verifying only the journaled resources were removed..."
    if (Test-Path -LiteralPath $statePath) { throw "Recovery journal still exists after successful cleanup." }
    foreach ($name in $session.firewall_names) {
        if (Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue) {
            throw "Journaled firewall rule survived cleanup: $name"
        }
    }
    foreach ($route in @($session.routes | Where-Object created -eq $true)) {
        $remaining = @(Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex $route.interface_index `
            -DestinationPrefix $route.prefix -ErrorAction SilentlyContinue | Where-Object {
                $_.NextHop -eq $route.next_hop -and $_.RouteMetric -eq $route.metric -and $_.Protocol -eq "NetMgmt"
            })
        if ($remaining) { throw "Journaled route survived cleanup: $($route.prefix)" }
    }
    Write-Host "PASS: exact ownership, concurrent TCP, multi-target UDP/TCP DNS, bypass blocking, crash persistence, and recovery validated."
}
finally {
    if ($bypassRouteCreated -and $session) {
        Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix "1.1.1.1/32" -InterfaceIndex $session.primary_interface_index -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $session.primary_gateway -and $_.RouteMetric -eq 2 -and $_.Protocol -eq "NetMgmt" } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    if ($clientWasStarted -and -not $cleanupSucceeded) {
        Write-Host "Recovering the test session..."
        & $resolvedClient --cleanup
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Recovery failed with exit code $LASTEXITCODE. Keep the machine offline and inspect $statePath."
        }
    }
    if ($null -eq $previousToken) {
        Remove-Item Env:WS_VPN_TOKEN -ErrorAction SilentlyContinue
    }
    else {
        $env:WS_VPN_TOKEN = $previousToken
    }
}
