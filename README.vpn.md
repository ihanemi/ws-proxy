# WS VPN

Experimental system-wide Windows VPN tunnel over authenticated WebSockets.

## Architecture

```text
Windows apps (IPv4 + IPv6)
  -> Wintun
  -> tun2socks
  -> local SOCKS5 TCP/UDP (127.0.0.1:1080)
  -> WSS over a pinned IPv4 relay connection
  -> ws-vpn-relay
  -> destination TCP or UDP server (IPv4 or IPv6)
```

The VPN client and relay authenticate with a shared bearer token. The relay refuses loopback/private/reserved destinations and port 25.

TCP uses one WebSocket stream per SOCKS5 CONNECT request. UDP uses SOCKS5 UDP ASSOCIATE and one WebSocket association carrying framed datagrams with their destination address and port. UDP responses carry the original source address back to the client.

## Status

- TCP CONNECT tunnel: implemented
- SOCKS5 UDP ASSOCIATE: implemented
- UDP datagram framing over WSS: implemented
- Authenticated WSS transport: implemented
- Windows Wintun/tun2socks orchestration: implemented
- IPv4 and IPv6 default routing through the TUN: implemented
- IPv4 DNS configuration on the TUN adapter: implemented
- Relay-route loop protection: implemented
- Persistent Windows firewall kill switch: implemented
- Crash-state persistence and `--cleanup` recovery: implemented
- tun2socks child-process monitoring: implemented
- GUI Connect/Disconnect controller: implemented
- System tray Show/Connect/Disconnect/Quit: implemented
- Persistent GUI settings: implemented
- DPAPI-protected remembered token: implemented
- Standalone TCP/UDP WSS relay: implemented
- Protocol/unit CI: implemented
- Self-contained Windows AMD64 GUI build: implemented
- Inno Setup Windows installer: implemented
- Windows end-to-end/crash-recovery probe: implemented
- Cloudflare Worker relay: experimental TCP fallback only; Cloudflare restrictions prevent it from being a complete Internet tunnel

The relay transport itself is deliberately IPv4-pinned on the client. This keeps the control/data WebSocket connection outside the `::/0` TUN route while IPv6 application traffic is carried inside the VPN. Therefore the relay hostname needs an IPv4 A record for Windows system-wide mode.

## GUI and tray

Launching `WsVpn.exe` without command-line arguments opens the Windows GUI. Enter the WSS relay URL and shared token, then press **Connect**. The GUI also exposes DNS, TUN name, IPv6, kill-switch, secure-token-memory, and start-minimized settings.

Closing the window hides it to the system tray instead of stopping the VPN. The tray menu exposes Show, Connect/Disconnect, and Quit. Quit performs a graceful VPN disconnect before the application exits.

GUI settings are stored under `%APPDATA%\WsVpn\config.json`. When **Remember token securely** is enabled, the token is encrypted with Windows DPAPI for the current Windows user before it is written to disk; the plaintext token is not stored in the JSON configuration. Runtime logs are written to `%APPDATA%\WsVpn\ws-vpn.log`.

## Kill switch and crash recovery

System-wide Windows mode enables a firewall kill switch by default. It creates persistent outbound block rules on the physical interface for public IPv4/IPv6 destinations while excluding the resolved IPv4 relay endpoints. Loopback, RFC1918/CGNAT/link-local LAN ranges, and multicast scopes remain reachable.

The rules are persistent on purpose. If `WsVpn.exe`, Python, or `tun2socks` dies unexpectedly, public traffic on the physical interface remains blocked instead of silently falling back outside the VPN. A normal graceful shutdown removes the rules.

Session recovery metadata is stored in `%ProgramData%\WsVpn\state.json`. It records the TUN name, primary interface/gateway, relay host-route IPs, and the tun2socks PID/path so recovery only targets state created by WS VPN.

The GUI has a **Recover** button. The CLI equivalent is:

```powershell
.\WsVpn.exe --cleanup
```

When running from source, use `ws-vpn --cleanup` instead.

`--no-kill-switch` disables the firewall guard and is intended only for debugging. `--no-ipv6` disables IPv6 TUN routing; when the kill switch remains enabled, public native IPv6 is still blocked rather than allowed to bypass the VPN.

## Windows build and installer

The `VPN Windows Build` GitHub Actions workflow builds the `WsVpn-windows-amd64` artifact. It contains:

- `WsVpn.exe`
- `WsVpn.exe.sha256`
- `WsVpn-Setup-x64.exe`
- `WsVpn-Setup-x64.exe.sha256`
- `THIRD_PARTY_NOTICES.md`
- `scripts/windows_e2e.ps1`

`WsVpn.exe` is a windowed, administrator-elevated AMD64 build. It bundles the verified tun2socks runtime and signed Wintun DLL, so neither component needs to be installed separately. `WsVpn-Setup-x64.exe` installs the client under Program Files and creates a Start Menu shortcut; an optional desktop shortcut can be selected during setup. Uninstall runs WS VPN recovery first so stale routes/firewall state are removed.

The build currently pins:

- tun2socks `v2.7.0`
- Wintun `0.14.1`
- PyInstaller `6.22.2`
- Inno Setup `7.1.0`

The workflow verifies the downloaded tun2socks and Wintun archives against pinned SHA-256 digests, validates the official Inno Setup Authenticode signature, performs a real Windows DPAPI round-trip test, unit-tests the VPN/kill-switch/settings logic, builds `WsVpn.exe`, smoke-tests its CLI path, compiles the installer, generates SHA-256 files, and uploads the final artifact.

## Install from source

For the command-line client and relay:

```powershell
python -m pip install -e .
```

For the Windows GUI/tray dependencies too:

```powershell
python -m pip install -e ".[gui]"
```

When running from source in system-wide Windows mode, place `tun2socks.exe` and `wintun.dll` together in a directory and pass the executable path with `--tun2socks`. The client must be run as Administrator when `--tun` is enabled.

## Run the relay

Install the project on a public server:

```bash
python -m pip install -e .
export WS_VPN_TOKEN='replace-with-a-long-random-token'
ws-vpn-relay --host 0.0.0.0 --port 8765
```

For production, put the relay behind a TLS reverse proxy such as Nginx/Caddy and expose both `/tunnel` and `/udp` as WebSocket paths, or pass `--cert` and `--key` to terminate TLS directly in the relay.

## Run the client as a SOCKS5 TCP/UDP tunnel

```powershell
$env:WS_VPN_TOKEN='replace-with-the-same-token'
ws-vpn --relay wss://vpn.example.com/tunnel
```

Applications can use SOCKS5 at `127.0.0.1:1080`. The server supports CONNECT and UDP ASSOCIATE.

## Run the standalone Windows EXE from CLI

Launching `WsVpn.exe` with no arguments opens the GUI. Command-line arguments keep the CLI behavior available:

```powershell
$env:WS_VPN_TOKEN='replace-with-the-same-token'
.\WsVpn.exe `
  --relay wss://vpn.example.com/tunnel `
  --tun `
  --dns 1.1.1.1 `
  --udp-timeout 2m
```

IPv6 routing and the kill switch are enabled by default.

## Run system-wide mode from source

Run an elevated PowerShell:

```powershell
$env:WS_VPN_TOKEN='replace-with-the-same-token'
ws-vpn `
  --relay wss://vpn.example.com/tunnel `
  --tun `
  --tun2socks C:\path\to\tun2socks.exe `
  --dns 1.1.1.1 `
  --udp-timeout 2m
```

The client detects the primary IPv4 route, resolves the relay before installing the TUN routes, adds IPv4 host-route exceptions for the relay, enables the fail-closed firewall guard, configures IPv4 and IPv6 on the Wintun adapter, installs `0.0.0.0/0` and `::/0` TUN routes, configures DNS, monitors tun2socks, and removes its state on graceful shutdown.

## Windows end-to-end test

After deploying a real WSS relay and downloading the Windows artifact, run this from an elevated PowerShell:

```powershell
.\scripts\windows_e2e.ps1 `
  -Relay 'wss://vpn.example.com/tunnel' `
  -Token 'replace-with-the-same-token' `
  -ClientPath '.\WsVpn.exe'
```

The probe validates the IPv4 and IPv6 TUN routes, persistent firewall rules, UDP DNS, and IPv4 HTTPS. It then deliberately force-kills the client, confirms that the kill switch survived the crash, and runs `--cleanup` in a `finally` block. Use `-TestIpv6Internet` to additionally require a successful IPv6 HTTPS request through a relay host that has working IPv6 egress.

This E2E script intentionally modifies routes and Windows Firewall state while it runs. Use it only from an elevated shell on a test machine or when temporary connectivity interruption is acceptable.

## UDP security behavior

The local SOCKS UDP relay accepts datagrams only from the IP associated with its SOCKS TCP control connection and locks each association to the first UDP source endpoint it sees.

The remote relay resolves destinations itself, refuses private/loopback/link-local/reserved/multicast/unspecified IPs, and only accepts UDP responses from destination IP:port pairs that the association previously contacted.

## Experimental Cloudflare Worker backend

`worker/` contains an optional Worker implementation using WebSocket + `cloudflare:sockets`. It is useful for TCP testing but isn't the primary backend because Workers cannot open raw TCP connections to Cloudflare IP ranges and this Worker path doesn't implement the UDP relay protocol.
