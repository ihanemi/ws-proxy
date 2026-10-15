# Cloudflare backend: setup and validation

## Delivered implementation

Baseline: `feature/vpn-mode` at `b4150ed04bd012fdf110bc9330b5fb66614cf164`.
The implementation from `feature/cloudflare-backend` was merged through
[PR #1](https://github.com/ihanemi/ws-proxy/pull/1) into `feature/vpn-mode`
at `9583b21`. Continue from that development branch. No changes are merged into
`main` and no stable release is published. A private free-plan test Worker has
since been deployed; see [actual laptop results](VALIDATION_2026-10-15.md),
including intermittent failures and the outstanding Windows gates.

The draft [session-path update](TRANSPORT_TIMEOUT_FIX.md) requires deploying
the updated Worker **before** using its matching Cloudflare client. The Worker
keeps compatibility with previous clients, while the new client requires the
explicit `echo-v1` negotiation. Its live validation is pending approval; do not
interpret passing local tests as resolution of the recorded Cloudflare failures.

| Phase | Result | Remaining gate |
| --- | --- | --- |
| 0 | Original Python implementation retained; baseline tests recorded | None |
| 1 | Worker WSVPN/1 TCP, probe, half-close, validation and bounded flow control | Live Cloudflare outbound TCP and network performance |
| 2 | Fixed-upstream Worker DoH, UDP and TCP DNS translation, startup/health probes | Real Windows system DNS and packet-capture leak checks |
| 3 | Explicit backend in CLI, GUI and persisted settings; mandatory guard in Cloudflare TUN | Physical Windows GUI/TUN execution |
| 4 | Automated tests, Windows build workflow and profile-aware E2E script | Hardware, crash, adapter switching, sleep/resume and leak tests |
| 5 | Self-hosted relay unchanged; regression/integration tests retained | Operational real-host load/IPv4/IPv6/UDP checks |
| 6 | Android platform boundary specified below | Windows validation first; no Android APK implemented |
| 7 | Worker test/build CI, preserved Windows packaging, deployment instructions | See current GitHub Actions results and remaining physical gates |

## Architecture decisions

- ADR-001: Python, Wintun, tun2socks, GUI and the existing relay remain in place.
- ADR-002: Keep WSVPN/1. `/dns` is a DNS-only sibling endpoint. Optional `ack-v1`
  negotiation adds bounded Worker downloads without changing base framing.
- ADR-003: `selfhosted` is the default. `cloudflare` supports TCP and secure DNS,
  exposes limited connectivity and refuses generic UDP. There is no direct fallback.
- ADR-004: System UDP and TCP DNS are encapsulated in authenticated WSS and translated to
  fixed-upstream HTTPS DNS by the Worker; no client-side plaintext DNS fallback.
- ADR-005: Resolve hostnames through DoH, check every A/AAAA answer, reject mixed
  public/private answers and connect to a pinned numeric public address. Bound
  connection attempts, queues, ACKs, idle time and DoH response bodies.
- ADR-006: Android must use Kotlin `VpnService` to own TUN/lifecycle and protect
  the backend transport sockets with `VpnService.protect()` before routing.
  A separate transport implements WSVPN/1 and the same capability profiles;
  Python GUI/Windows automation is not packaged into Android. Native tun2socks
  integration, ABI/provenance/licensing and actual device traffic tests are
  prerequisites before choosing a library or shipping an APK. This work does
  not add an untested placeholder Android app before the Windows gate is met.

## Deploy the Worker yourself

Use a **new** VPN secret; never reuse any credential pasted into a conversation.
Cloudflare API credentials and the VPN secret serve different purposes.

```bash
git fetch origin
git switch feature/vpn-mode
git pull --ff-only origin feature/vpn-mode
cd worker
npm ci --ignore-scripts
npm test
npm run check
npx wrangler login
npx wrangler secret put TUNNEL_TOKEN
npm run deploy
```

`wrangler secret put` prompts for the fresh VPN secret. Do not put it into
`wrangler.jsonc`, URLs, Git or shell history. If the Worker doesn't yet exist,
create a blank Worker named `ws-vpn-relay` in the Cloudflare dashboard first,
then set its secret and deploy the code above. Keep the account on its existing
free plan; this implementation has no paid bindings or automatic plan upgrades.
Use your own endpoint and fresh VPN secret; the private validation deployment
is not a shared VPN service.

Copy the deployed `https://ws-vpn-relay.<your-subdomain>.workers.dev` URL.
`/health` reports capabilities without claiming working Internet egress.

## Connect Windows

Use the Windows artifact from the **new branch's** successful Actions run,
not the old baseline artifact. In its elevated GUI choose **cloudflare**, set
`wss://ws-vpn-relay.<your-subdomain>.workers.dev/tunnel`, enter the fresh VPN
secret, keep DNS `1.1.1.1` and the kill switch enabled, then Connect.

CLI equivalent in elevated PowerShell:

```powershell
$secret = Read-Host 'Fresh VPN secret' -AsSecureString
$env:WS_VPN_TOKEN = [System.Net.NetworkCredential]::new('', $secret).Password
try {
  .\WsVpn.exe --backend cloudflare `
    --relay 'wss://ws-vpn-relay.<your-subdomain>.workers.dev/tunnel' --tun --dns 1.1.1.1
} finally {
  Remove-Item Env:WS_VPN_TOKEN -ErrorAction SilentlyContinue
}
```

The DNS address is a routing marker; the actual resolver is the Worker's fixed
Cloudflare DoH endpoint. QUIC/UDP drops may make some apps fail or use their own
TCP fallback **inside** the tunnel. A successful probe proves control transport
and DoH; destination TCP readiness is checked separately for each flow and does
not guarantee reachability of every Internet service.

To use the original full relay, select **selfhosted** or pass
`--backend selfhosted` with its original WSS URL/token. Existing `/udp` stays intact.

## Physical Windows test

On a machine where temporary loss of Internet is acceptable, run the bundled
E2E script elevated with `-Backend cloudflare`, the fresh token, and
`-HttpsUrl https://<your-known-non-Cloudflare-TCP-test-host>/`. The default
example.com target is not a guaranteed valid Worker TCP destination. Use the
original default profile for self-hosted multi-target UDP/TCP DNS checks.

```powershell
.\scripts\windows_e2e.ps1 -Backend cloudflare `
  -Relay 'wss://ws-vpn-relay.<your-subdomain>.workers.dev/tunnel' `
  -Token $env:WS_VPN_TOKEN -ClientPath '.\WsVpn.exe' `
  -HttpsUrl 'https://<your-non-Cloudflare-test-host>/'
```

The script tests owned resources, profile DNS, concurrent TCP, physical bypass
blocking, tun2socks termination and recovery. It is **not** a comprehensive
packet-capture DNS/IPv6 leak test and does not test all adapter/sleep conditions.
Capture traffic separately on every physical adapter while testing DNS,
unsupported UDP, reconnection and intentional failure. Inspect shared-edge
bypass and hot-plug behavior described below before trusting leak protection.
An unexpected failure retains the guard; inspect then run `WsVpn.exe --cleanup`.
Do not disconnect merely to work around a failed DNS/UDP flow while claiming
that it remains tunneled.

## Actual limitations and security gates

- Workers raw TCP cannot connect to Cloudflare IP ranges, private addresses or
  port 25. Raw `/tunnel` connections to port 53 are also blocked; DNS TCP to the
  configured marker uses `/dns` and fixed-upstream DoH instead.
  Some Cloudflare-hosted HTTPS destinations therefore fail. HTTPS fetch cannot
  transparently replace a TLS byte stream; no misleading fallback is provided.
- No generic UDP/QUIC/VoIP/gaming. DNS-only association is not a general UDP
  relay. TCP DNS works only at the configured IPv4 marker (default 1.1.1.1),
  using the same secure path as UDP DNS. Compressed DNS questions and
  >4096-byte DNS queries/replies fail;
  there is no plaintext fallback. Legacy TCP clients lacking ACK are capped at
  8 MiB downstream; current Cloudflare-profile clients negotiate ACK.
- New guard rules block UDP/ICMP and TCP ports other than the configured relay
  port at bypass IPs. **TCP to the exact relay IP/port remains reachable by other
  applications**, because the existing firewall design excludes that endpoint
  and cannot distinguish its shared-hosting TLS name. Do not claim complete
  no-leak protection on shared Cloudflare edge IPs. A tested process-scoped WFP
  design or separate controlled relay remains a gate for stronger guarantees.
- Interface inventory is taken at startup. New/hot-plug adapters require a
  restart and physical validation; there is no proven zero-window adapter switch.
  LAN/multicast exceptions and local discovery remain part of existing policy.
- The relay hostname is resolved on the physical connection **before** the
  firewall/TUN setup, then the same IPv4 snapshot is pinned for routing and TLS
  dials. This bootstrap resolution is not hidden or a post-connect DNS fallback.
- Limits are per isolate, not globally authoritative. Oversized messages are
  checked after runtime reassembly. Authentication tokens must be high entropy;
  this is a private alpha endpoint, not a hardened public multi-user service.
- Free-plan quotas, CPU and connection limits still apply; zero cost, sustained
  throughput and access from a restricted network are not guaranteed.
- Local `workerd` tests use a mocked HTTPS resolver, and TCP lifecycle tests
  inject sockets. They prove protocol/runtime behavior, not Cloudflare Internet
  egress. Windows native/build CI is not a physical Windows leak test.

## Reproduce available checks

```bash
python -m pip install '.[dev]' certifi cryptography
python -m ruff check vpn relay tests/test_vpn_*.py
python -m compileall -q vpn relay
python -m unittest discover -s tests -q
cd worker
npm ci --ignore-scripts
npm test
npm run check
```

`certifi` and `cryptography` are required by preserved legacy Telegram tests,
not the VPN core.
The Worker lockfile pins runtime/build dependencies and integrity hashes. Local
runtime tests use Miniflare's version matching the pinned Wrangler runtime;
Miniflare is a development dependency, not shipped in the Worker.

## Official runtime references

- https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
- https://developers.cloudflare.com/workers/runtime-apis/websockets/
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/

Constraints verified on 2026-10-10. One WebSocket per TCP flow is retained.
