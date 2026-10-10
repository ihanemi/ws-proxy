# WS VPN

A standalone Windows VPN client using authenticated WebSockets, with two
independent backends. Development continues on **`feature/vpn-mode`**, preserving
the existing Python core, Wintun, tun2socks, GUI/tray and Windows packaging.
This repository is a fork of Flowseal/tg-ws-proxy; the current product objective
is system-wide VPN traffic rather than a Telegram-only proxy.

**Alpha software (`0.1.0-alpha.1`).** Automated protocol tests and Windows builds
are available. Live Cloudflare egress and physical Windows routing, crash and
leak tests still require validation. CI artifacts are unsigned test builds,
not an approved stable release.

## Choose a backend

| Capability | `cloudflare` | `selfhosted` (default) |
| --- | --- | --- |
| Hosting | Cloudflare Worker; no VPS required | Your own public relay with TLS |
| TCP | WSVPN/1, with bounded download flow control | WSVPN/1 |
| System DNS | UDP and TCP at the configured marker, translated to authenticated Worker DoH | TCP/UDP DNS through the relay |
| Generic UDP, QUIC, gaming | Unsupported | UDP supported; actual application/egress compatibility requires testing |
| IPv4/IPv6 destination traffic | Public TCP as allowed by Workers | TCP/UDP as supported by the relay host |
| Cloudflare-hosted TCP destinations | May be blocked by Workers' raw TCP restrictions | As supported by the relay host |

Both profiles use TLS verification, pre-upgrade token authentication and the
`wsvpn.v1` subprotocol. There is **no direct Internet fallback** when a backend
fails. A successful WebSocket probe does not prove Internet egress.

Worker DNS uses the fixed HTTPS resolver, not an arbitrary UDP destination.
The default DNS address `1.1.1.1` is a routing marker in this profile. Other
resolvers are rejected, and compressed DNS questions or messages larger than
4096 bytes are unsupported. Free-plan quotas still apply; zero cost and
unrestricted connectivity are not guaranteed.

## Test on Windows

1. Open [VPN Windows Build](https://github.com/ihanemi/ws-proxy/actions/workflows/vpn-windows-build.yml),
   choose a successful run for the development branch and its exact commit,
   and download `WsVpn-windows-amd64`. It includes the EXE, installer, SHA-256
   files, runtime licenses and E2E script.
2. For Worker mode, follow [Cloudflare setup](docs/CLOUDFLARE_BACKEND.md) to test
   and deploy the existing Worker with a **fresh** `TUNNEL_TOKEN`. Keep Cloudflare
   API credentials separate from this VPN secret. No Worker has been deployed
   by this implementation work.
3. Run `WsVpn.exe` elevated. Choose `cloudflare`, enter
   `wss://ws-vpn-relay.<your-subdomain>.workers.dev/tunnel` and the fresh token,
   keep DNS `1.1.1.1` and the kill switch enabled, then Connect.
4. For a full relay, follow [self-hosted deployment](deploy/README.md), choose
   `selfhosted`, and enter that relay's WSS URL and token.

The bundled Wintun and tun2socks downloads are verified by the build workflow.
Remembered GUI tokens use Windows DPAPI. Closing the window keeps the tray
running; Quit disconnects. After a crash, inspect the session and use the
Recover button or `WsVpn.exe --cleanup` to remove exactly the owned resources.

The current firewall guard leaves a material exception: **other applications
can reach the exact relay IP/TCP port**, including shared Cloudflare edge IPs.
Adapters attached after startup are another remaining gate. Do not treat this
alpha as a verified no-leak VPN. See [security limits and physical test steps](docs/CLOUDFLARE_BACKEND.md#actual-limitations-and-security-gates).

## Develop and validate

```bash
git clone --branch feature/vpn-mode https://github.com/ihanemi/ws-proxy.git
cd ws-proxy
python -m pip install '.[dev]' certifi
python -m ruff check vpn relay tests/test_vpn_*.py
python -m compileall -q vpn relay
python -m unittest discover -s tests -q
cd worker
npm ci --ignore-scripts
npm test
npm run check
```

`certifi` is needed by preserved upstream tests, not the VPN core. `npm run
check` bundles the Worker without deploying it. VPN CI tests Python and Worker
behavior; Windows CI additionally verifies native token storage, builds the
EXE/installer and checks the E2E script syntax. These checks do not replace
packet captures, live relay traffic or tests on a physical Windows machine.

The latest local checks ran 129 Python tests (4 Windows-only skips) and passed
all 17 Worker tests, lint and the Worker dry-run build. Worker runtime DNS tests
mock the outbound HTTPS resolver; TCP lifecycle tests inject sockets. TCP DNS
also has a real localhost SOCKS test with fragmented/pipelined requests.

Android is planned around native `VpnService` and the same WSVPN/1 contract.
Implementation follows shared transport and physical Windows validation;
there is no Android APK yet.

## Documentation

- [Complete Windows client manual](README.vpn.md)
- [Cloudflare deployment, architecture decisions and validation gates](docs/CLOUDFLARE_BACKEND.md)
- [WSVPN/1 protocol and compatible extensions](docs/VPN_PROTOCOL.md)
- [Security audit](docs/VPN_SECURITY_AUDIT.md)
- [Windows recovery](docs/WINDOWS_RECOVERY.md)
- [Dependency licenses and provenance](THIRD_PARTY_NOTICES.md)
- [Preserved upstream Telegram proxy documentation](docs/EN/README.md)

Licensed under [MIT](LICENSE); bundled dependencies retain their own licenses.
