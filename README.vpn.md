# WS VPN

Experimental system-wide Windows VPN tunnel over WebSockets.

## Architecture

```text
Windows apps
  -> Wintun
  -> tun2socks
  -> local SOCKS5 TCP/UDP (127.0.0.1:1080)
  -> WSS
  -> ws-vpn-relay
  -> destination TCP or UDP server
```

The VPN client and relay authenticate with a shared bearer token. The relay refuses loopback/private/reserved destinations and port 25.

TCP uses one WebSocket stream per SOCKS5 CONNECT request. UDP uses SOCKS5 UDP ASSOCIATE and one WebSocket association carrying framed datagrams with their destination address and port. UDP responses carry the original source address back to the client.

## Status

- TCP CONNECT tunnel: implemented
- SOCKS5 UDP ASSOCIATE: implemented
- UDP datagram framing over WSS: implemented
- Authenticated WSS transport: implemented
- Windows Wintun/tun2socks orchestration: implemented
- DNS configuration on the TUN adapter: implemented
- Relay-route loop protection: implemented
- Standalone TCP/UDP WSS relay: implemented
- Protocol/unit CI: implemented
- Cloudflare Worker relay: experimental TCP fallback only; Cloudflare blocks raw TCP connections to Cloudflare-owned IP ranges, so it cannot provide a complete Internet tunnel
- Native IPv6 system-wide routing: not implemented yet

The current TUN path is IPv4 system-wide. TCP and UDP, including tunneled IPv4 DNS, are supported. Native IPv6 routing still needs its own TUN route and relay bypass handling before this should be treated as a leak-resistant production VPN.

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

For production, put the relay behind a TLS reverse proxy such as Nginx/Caddy and expose both `/tunnel` and `/udp` as WebSocket paths, or pass `--cert` and `--key` to terminate TLS directly in the relay.

## Run the client as a SOCKS5 TCP/UDP tunnel

```powershell
$env:WS_VPN_TOKEN='replace-with-the-same-token'
ws-vpn --relay wss://vpn.example.com/tunnel
```

Applications can use SOCKS5 at `127.0.0.1:1080`. The server supports CONNECT and UDP ASSOCIATE.

## Run system-wide Windows TUN mode

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

The client detects the primary IPv4 route, resolves the relay before installing the TUN default route, adds host-route exceptions for the relay, starts the Wintun adapter, configures its DNS server, and removes the added routes on shutdown.

`tun2socks` must support SOCKS5 UDP. Current xjasonlyu/tun2socks releases support UDP through SOCKS5; keep `wintun.dll` next to the executable on Windows.

## UDP security behavior

The local SOCKS UDP relay accepts datagrams only from the IP associated with its SOCKS TCP control connection and locks each association to the first UDP source endpoint it sees.

The remote relay resolves destinations itself, refuses private/loopback/link-local/reserved/multicast/unspecified IPs, and only accepts UDP responses from destination IP:port pairs that the association previously contacted.

## Experimental Cloudflare Worker backend

`worker/` contains an optional Worker implementation using WebSocket + `cloudflare:sockets`. It is useful for TCP testing but isn't the primary backend because Workers cannot open raw TCP connections to Cloudflare IP ranges and this Worker path doesn't implement the UDP relay protocol.
