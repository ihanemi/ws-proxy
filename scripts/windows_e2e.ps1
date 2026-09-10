param(
    [Parameter(Mandatory = $true)]
    [string]$Relay,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$ClientPath = ".\WsVpn.exe",
    [string]$TunName = "wsvpn",
    [int]$StartupTimeoutSeconds = 20,
    [switch]$TestIpv6Internet
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell (Run as Administrator)."
}

$resolvedClient = (Resolve-Path $ClientPath).Path
$previousToken = $env:WS_VPN_TOKEN
$env:WS_VPN_TOKEN = $Token
$process = $null

try {
    Write-Host "[1/6] Starting WS VPN..."
    $process = Start-Process \
        -FilePath $resolvedClient \
        -ArgumentList @("--relay", $Relay, "--tun", "--tun-name", $TunName) \
        -PassThru \
        -NoNewWindow

    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    do {
        if ($process.HasExited) {
            throw "WsVpn exited during startup with code $($process.ExitCode)."
        }
        $adapter = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
        $ipv4Route = Get-NetRoute -InterfaceAlias $TunName -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($adapter -and $ipv4Route) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if (-not $adapter -or -not $ipv4Route) {
        throw "TUN adapter/default IPv4 route did not become ready within $StartupTimeoutSeconds seconds."
    }

    Write-Host "[2/6] Checking TUN routes..."
    $ipv6Route = Get-NetRoute -InterfaceAlias $TunName -DestinationPrefix "::/0" -ErrorAction SilentlyContinue
    if (-not $ipv6Route) {
        throw "IPv6 default route on $TunName is missing."
    }

    Write-Host "[3/6] Checking persistent kill-switch rules..."
    $firewallRules = Get-NetFirewallRule -Name "WSVPN-KillSwitch-*" -ErrorAction SilentlyContinue
    if (-not $firewallRules) {
        throw "Kill-switch firewall rules were not created."
    }

    Write-Host "[4/6] Testing UDP DNS through the tunnel..."
    $dns = Resolve-DnsName example.com -Server 1.1.1.1 -DnsOnly -QuickTimeout -ErrorAction Stop
    if (-not $dns) {
        throw "DNS test returned no records."
    }

    Write-Host "[5/6] Testing HTTPS/TCP through the tunnel..."
    & curl.exe --fail --silent --show-error --connect-timeout 8 --max-time 15 -4 https://example.com/ -o NUL
    if ($LASTEXITCODE -ne 0) {
        throw "IPv4 HTTPS test failed with curl exit code $LASTEXITCODE."
    }

    if ($TestIpv6Internet) {
        & curl.exe --fail --silent --show-error --connect-timeout 8 --max-time 15 -6 https://example.com/ -o NUL
        if ($LASTEXITCODE -ne 0) {
            throw "IPv6 HTTPS test failed with curl exit code $LASTEXITCODE."
        }
    }

    Write-Host "[6/6] Simulating a hard client crash..."
    Stop-Process -Id $process.Id -Force -ErrorAction Stop
    $process.WaitForExit()
    Start-Sleep -Milliseconds 500

    $firewallAfterCrash = Get-NetFirewallRule -Name "WSVPN-KillSwitch-*" -ErrorAction SilentlyContinue
    if (-not $firewallAfterCrash) {
        throw "Kill switch disappeared after a hard crash; expected fail-closed persistence."
    }

    Write-Host "PASS: TCP, UDP DNS, IPv4/IPv6 TUN routes, and crash-persistent kill switch validated."
}
finally {
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Recovering WS VPN state..."
    & $resolvedClient --cleanup
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Automatic --cleanup failed with exit code $LASTEXITCODE. Run '$resolvedClient --cleanup' as Administrator."
    }

    if ($null -eq $previousToken) {
        Remove-Item Env:WS_VPN_TOKEN -ErrorAction SilentlyContinue
    }
    else {
        $env:WS_VPN_TOKEN = $previousToken
    }
}
