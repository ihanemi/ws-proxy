# WS VPN

Experimental system-wide Windows VPN tunnel over authenticated WebSockets.

Current version: `0.1.0-alpha.1`. No public release is approved yet. The
client executable and installer produced by CI are unsigned test artifacts.

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

The VPN client and relay use the versioned `WSVPN/1` subprotocol and authenticate with a shared bearer token before the WebSocket upgrade. The relay refuses loopback/private/reserved destinations and port 25.

TCP uses one WebSocket stream per SOCKS5 CONNECT request. UDP uses SOCKS5 UDP ASSOCIATE and one WebSocket association carrying framed datagrams with their destination address and port. UDP responses carry the original source address back to the client.

## Status

- TCP CONNECT tunnel: implemented
- SOCKS5 UDP ASSOCIATE: implemented
- UDP datagram framing over WSS: implemented
- Authenticated WSS transport: implemented
- Authenticated startup readiness probe: implemented
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
- Windows end-to-end/crash-recovery probe: implemented, pending execution on a dedicated Windows test machine
- Cloudflare Worker relay: experimental TCP fallback only; Cloudflare restrictions prevent it from being a complete Internet tunnel

The relay transport itself is deliberately IPv4-pinned on the client. This keeps the control/data WebSocket connection outside the `::/0` TUN route while IPv6 application traffic is carried inside the VPN. Therefore the relay hostname needs an IPv4 A record for Windows system-wide mode.

## GUI and tray

Launching `WsVpn.exe` without command-line arguments opens the Windows GUI. Enter the WSS relay URL and shared token, then press **Connect**. The GUI also exposes DNS, TUN name, IPv6, kill-switch, secure-token-memory, and start-minimized settings.

Closing the window hides it to the system tray instead of stopping the VPN. The tray menu exposes Show, Connect/Disconnect, and Quit. Quit performs a graceful VPN disconnect before the application exits.

GUI settings are stored under `%APPDATA%\WsVpn\config.json`. When **Remember token securely** is enabled, the token is encrypted with Windows DPAPI for the current Windows user before it is written to disk; the plaintext token is not stored in the JSON configuration. Rotating runtime logs are written to `%LOCALAPPDATA%\WsVpn\logs\ws-vpn.log` (5 MiB per file, three backups).

## Kill switch and crash recovery

System-wide Windows mode enables a firewall kill switch by default. It creates persistent outbound block rules on the physical interface for public IPv4/IPv6 destinations while excluding the resolved IPv4 relay endpoints. Loopback, RFC1918/CGNAT/link-local LAN ranges, and multicast scopes remain reachable.

The rules are persistent on purpose. If `WsVpn.exe`, Python, or `tun2socks` dies unexpectedly, public traffic on the physical interface remains blocked instead of silently falling back outside the VPN. A normal graceful shutdown removes the rules.

Session recovery metadata is stored in `%ProgramData%\WsVpn\state.json` under an Administrators/SYSTEM-only ACL. It journals a random session ID, exact route and firewall identities, adapter GUID/index, and the tun2socks PID/path/process creation time. Recovery validates all of that data and never sweeps resources by a wildcard.

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

`WsVpn.exe` is a windowed, administrator-elevated AMD64 build. It bundles the checksum-verified tun2socks runtime and the upstream-signed Wintun DLL, so neither component needs to be installed separately. These properties do not sign the WS VPN outputs themselves. `WsVpn-Setup-x64.exe` installs the client under Program Files and creates a Start Menu shortcut; an optional desktop shortcut can be selected during setup. Uninstall runs ownership-aware WS VPN recovery and aborts if cleanup fails, preserving the recovery tool and journal for inspection.

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

For a bounded systemd, Docker, Caddy, or Nginx deployment, follow [`deploy/README.md`](deploy/README.md). The relay exposes `/healthz`; WebSocket traffic uses `/tunnel`, `/udp`, and the authenticated `/probe`. TLS can terminate at the relay with `--cert` and `--key`, or at a reviewed reverse proxy.

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

The probe refuses to touch a pre-existing recovery journal or unjournaled WS VPN firewall rules. It validates exact journaled routes/rules, multiple UDP and TCP DNS targets, concurrent IPv4 HTTPS streams, and a forced physical-interface route that must remain blocked. It then kills tun2socks, requires the client to fail while the guard persists, runs `--cleanup`, and verifies every journaled route/rule is gone. Use `-TestIpv6Internet` to additionally require a successful IPv6 HTTPS request through a relay host that has working IPv6 egress.

This E2E script intentionally modifies routes and Windows Firewall state while it runs. Use it only from an elevated shell on a test machine or when temporary connectivity interruption is acceptable.

## Known system-wide limitations

- The firewall inventory is captured at connection start. A network adapter attached later is not protected until a new session; do not treat the current guard as a zero-window hot-plug design.
- Wi-Fi/Ethernet switching, sleep/resume, reboot recovery, installer upgrade/uninstall, Defender behavior, and sustained throughput still require physical Windows validation.
- The GUI reports readiness only after the local stack is established and an authenticated TLS/WebSocket probe receives `WSVPN/1` READY. The probe does not prove relay egress, and controlled reconnects are not implemented yet.
- The Cloudflare Worker remains TCP-only and is not protocol-compatible with full VPN mode.

## UDP security behavior

The local SOCKS UDP relay accepts datagrams only from the IP associated with its SOCKS TCP control connection and locks each association to the first UDP source endpoint it sees.

The remote relay resolves destinations itself, refuses private/loopback/link-local/reserved/multicast/unspecified IPs, and only accepts UDP responses from destination IP:port pairs that the association previously contacted.

## Experimental Cloudflare Worker backend

`worker/` contains an optional Worker implementation using WebSocket + `cloudflare:sockets`. It is useful for TCP testing but isn't the primary backend because Workers cannot open raw TCP connections to Cloudflare IP ranges and this Worker path doesn't implement the UDP relay protocol.
