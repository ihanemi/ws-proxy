# Relay deployment

Use a dedicated public Linux host. The recommended layout is Caddy or Nginx
terminating TLS on port 443 and `ws-vpn-relay` bound to `127.0.0.1:8765`.
The relay refuses a non-loopback plaintext bind; direct public binding requires
`--cert` and `--key`. Both `/tunnel` and `/udp` must preserve WebSocket Upgrade,
`Authorization`, and the two TCP destination headers.

## systemd and Caddy

```bash
sudo useradd --system --home /opt/ws-vpn --shell /usr/sbin/nologin ws-vpn
sudo install -d -o ws-vpn -g ws-vpn /opt/ws-vpn
sudo -u ws-vpn python3 -m venv /opt/ws-vpn/.venv
sudo -u ws-vpn /opt/ws-vpn/.venv/bin/pip install /path/to/ws-proxy
sudo install -m 600 -o root -g root deploy/ws-vpn-relay.env.example /etc/ws-vpn-relay.env
sudo install -m 644 deploy/systemd/ws-vpn-relay.service /etc/systemd/system/
sudo install -m 644 deploy/caddy/Caddyfile.example /etc/caddy/Caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now ws-vpn-relay caddy
curl --fail https://vpn.example.com/healthz
```

Replace the hostname and token placeholder first. Keep `/etc/ws-vpn-relay.env`
out of backups or repositories that aren't authorized for the shared secret.
Rotate the token by changing the environment file and restarting the relay;
clients using the old token will be rejected with HTTP 401.

The systemd unit permits only IPv4/IPv6 sockets and makes the filesystem
read-only to the service. The relay needs ordinary outbound TCP/UDP and DNS.
Put host firewall/egress policy and bandwidth/accounting controls around it;
the application blocks nonpublic destinations, port 25, oversized frames,
excess destinations and per-session UDP bursts, but it isn't a billing or
multi-tenant authorization system.

## Nginx

Install `deploy/nginx/ws-vpn.conf.example` after replacing the hostname and
certificate paths. The example log format doesn't include credentials or
destination headers. Do not add `$http_authorization` to access/error logs.

## Container

The container defaults to direct TLS and expects read-only secrets at
`/run/secrets/tls.crt` and `/run/secrets/tls.key`. When a reverse proxy is in a
separate container, override the command to bind the container network and
secure that network from untrusted tenants; the relay intentionally rejects a
plaintext non-loopback bind in the host-oriented CLI configuration.

## Operations

`GET /healthz` proves the process can accept HTTP. It doesn't perform egress or
validate the token. Monitor connection count, CPU, memory, bandwidth, file
descriptors and restarts at the service/proxy layer. Graceful SIGTERM stops
accepting new connections and gives active handlers the server close timeout.
Never pass the token on the command line because process listings may expose it.
