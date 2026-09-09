# WS VPN

Experimental system-wide Windows VPN tunnel over WebSockets.

## Architecture

```text
Windows apps
  -> Wintun
  -> tun2socks
  -> local SOCKS5 (127.0.0.1:1080)
  -> WSS
  -> ws-vpn-relay
  -> destination TCP server
```

The VPN client and relay authenticate with a shared bearer token. The relay refuses loopback/private/reserved destinations and port 25.

## Status

- TCP CONNECT tunnel: implemented
- Authenticated WSS transport: implemented
- Windows Wintun/tun2socks orchestration: implemented
- Relay-route loop protection: implemented
- Standalone WSS relay: implemented
- Cloudflare Worker relay: experimental fallback only; Cloudflare blocks raw TCP connections to Cloudflare-owned IP ranges, so it cannot provide a complete Internet tunnel
- UDP / SOCKS5 UDP ASSOCIATE: not implemented yet

Because UDP isn't implemented yet, this is an alpha TCP VPN. DNS and QUIC behavior will be completed with the UDP transport.

## Install client

```powershell
python -m pip install -e .
```

For system-wide Windows mode, place `tun2socks.exe` and `wintun.dll` together in a directory. The client must be run as Administrator.

## Run the relay

Install the project on a public server:

```bash
python -m pip install -e .
export WS_VPN_TOKEN='replace-with-a-long-random-token'
ws-vpn-relay --host 0.0.0.0 --port 8765
```

For production, put the relay behind a TLS reverse proxy such as Nginx/Caddy and expose `/tunnel` as WebSocket, or pass `--cert` and `--key` to terminate TLS directly in the relay.

## Run the client as a SOCKS5 tunnel

```powershell
$env:WS_VPN_TOKEN='replace-with-the-same-token'
ws-vpn --relay wss://vpn.example.com/tunnel
```

Test with an application configured for SOCKS5 at `127.0.0.1:1080`.

## Run system-wide Windows TUN mode

Run an elevated PowerShell:

```powershell
$env:WS_VPN_TOKEN='replace-with-the-same-token'
ws-vpn `
  --relay wss://vpn.example.com/tunnel `
  --tun `
  --tun2socks C:\path\to\tun2socks.exe
```

The client detects the primary IPv4 route, resolves the relay before installing the TUN default route, adds host-route exceptions for the relay, starts the Wintun adapter, and removes the routes on shutdown.

## Experimental Cloudflare Worker backend

`worker/` contains an optional Worker implementation using WebSocket + `cloudflare:sockets`. It is useful for testing but isn't the primary backend because Workers cannot open raw TCP connections to Cloudflare IP ranges.
