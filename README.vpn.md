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
- IPv4 default routing through the TUN: implemented
- IPv6 default routing through the TUN: implemented
- IPv6 TUN address (`fd42:4242:4242::1/64`): implemented
- IPv4 DNS configuration on the TUN adapter: implemented
- Relay-route loop protection: implemented
- Relay WSS transport pinned to IPv4: implemented
- Standalone TCP/UDP WSS relay: implemented
- Protocol/unit CI: implemented
- Self-contained Windows AMD64 build: implemented
- Cloudflare Worker relay: experimental TCP fallback only; Cloudflare restrictions prevent it from being a complete Internet tunnel

The relay transport itself is deliberately IPv4-pinned on the client. This keeps the control/data WebSocket connection outside the `::/0` TUN route while IPv6 application traffic is carried inside the VPN. Therefore the relay hostname needs an IPv4 A record for Windows system-wide mode.

This project still doesn't implement a firewall-based kill switch. If the VPN process or TUN fails unexpectedly, Windows may fall back to another available route. Treat this branch as alpha until it has been exercised end-to-end on real Windows hosts and a kill switch is added.

## Windows standalone build

The `VPN Windows Build` GitHub Actions workflow builds the `WsVpn-windows-amd64` artifact. It contains:

- `WsVpn.exe`
- `WsVpn.exe.sha256`
- `THIRD_PARTY_NOTICES.md`

The EXE bundles the verified Windows AMD64 tun2socks runtime and signed Wintun DLL, so they don't need to be installed separately when using this build.

The build currently pins:

- tun2socks `v2.7.0`
- Wintun `0.14.1`
- PyInstaller `6.22.2`

The workflow verifies the downloaded tun2socks and Wintun archives against pinned SHA-256 digests before packaging and smoke-tests `WsVpn.exe --help` before uploading the artifact.

## Install from source

```powershell
python -m pip install -e .
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

## Run the standalone Windows EXE

Open an elevated PowerShell and run:

```powershell
$env:WS_VPN_TOKEN='replace-with-the-same-token'
.\WsVpn.exe `
  --relay wss://vpn.example.com/tunnel `
  --tun `
  --dns 1.1.1.1 `
  --udp-timeout 2m
```

IPv6 routing is enabled by default. `--no-ipv6` disables the IPv6 TUN route for troubleshooting, but doing so can allow native IPv6 traffic to bypass the VPN on hosts that have IPv6 connectivity.

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

The client detects the primary IPv4 route, resolves the relay before installing the TUN routes, adds IPv4 host-route exceptions for the relay, configures IPv4 and IPv6 on the Wintun adapter, installs `0.0.0.0/0` and `::/0` TUN routes, configures DNS, and removes the routes it added on graceful shutdown.

## UDP security behavior

The local SOCKS UDP relay accepts datagrams only from the IP associated with its SOCKS TCP control connection and locks each association to the first UDP source endpoint it sees.

The remote relay resolves destinations itself, refuses private/loopback/link-local/reserved/multicast/unspecified IPs, and only accepts UDP responses from destination IP:port pairs that the association previously contacted.

## Experimental Cloudflare Worker backend

`worker/` contains an optional Worker implementation using WebSocket + `cloudflare:sockets`. It is useful for TCP testing but isn't the primary backend because Workers cannot open raw TCP connections to Cloudflare IP ranges and this Worker path doesn't implement the UDP relay protocol.
