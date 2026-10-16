# WS VPN

A standalone Windows VPN client using authenticated WebSockets, with two
independent backends. Development continues on **`feature/vpn-mode`**, preserving
the existing Python core, Wintun, tun2socks, GUI/tray and Windows packaging.
This repository is a fork of Flowseal/tg-ws-proxy; the current product objective
is system-wide VPN traffic rather than a Telegram-only proxy.

**Alpha software (`0.1.0-alpha.1`).** Automated protocol tests and Windows builds
are available. The [approved PR #2 test deployment](docs/PR2_LIVE_VALIDATION_2026-10-15.md)
passed live UDP/TCP DNS and verified TLS 1.3 handshakes with the matching Windows
EXE, but single and concurrent HTTPS responses still stalled. **Live acceptance
failed and the previous test Worker version was restored. PR #2 is not merged.**
Physical Windows routing, crash and leak tests remain open. Artifacts are
unsigned test builds, not an approved stable release.

The draft [session-path change](docs/TRANSPORT_TIMEOUT_FIX.md) adds a negotiated
nonce check before application traffic. It did **not** resolve the live stall.
A [follow-up diagnosis](docs/TRANSPORT_DIAGNOSIS_2026-10-15.md) reproduced HTTPS
failure with the restored Worker and original EXE, while fresh legacy source
sessions sometimes returned response bytes. DNS recovered in the new baseline,
but sustained application health and the internal cause remain unresolved.
The Worker and its configuration were unchanged during that investigation.

Keep the new `WsVpn-path-check` test EXE separate: it requires the updated
`echo-v1` Worker and is incompatible with the restored previous Worker. The
previous client was retained. Self-hosted functionality is preserved; no direct
fallback, production deployment or stable release was introduced.

A separate [diagnostic experiment](docs/DIAGNOSTIC_EXPERIMENT.md) is prepared on
`diagnostic/cloudflare-session-counters`, based on PR #2 at `458e877`. It adds
opt-in correlated counters, a synthetic HTTPS origin and local success/stall
tests. It is **not deployed or a production fix**. The restored legacy Worker
and PR #2 remain unchanged; live use requires separate approval and an approved
public origin. Default Worker builds do not include the instrumentation.
The [authorized Vercel origin-only trial](docs/VERCEL_ORIGIN_VALIDATION_2026-10-15.md)
ran seven independent HTTPS requests from Windows. The public non-Cloudflare
addresses and TLS certificates were verified, but all seven requests returned
HTTP 400 before accepted-session counters. **The origin is not accepted.** Its
temporary project was protected after the failed run. The exact rejection cause
of those seven hosted replies and hosted streaming controls remain unresolved.
A [bounded local follow-up](docs/VERCEL_ORIGIN_REJECTION_DIAGNOSIS_2026-10-16.md)
confirmed and corrected a routing compatibility defect: the adapter rejected
Vercel CLI's original pathname plus matching rewrite query. It now accepts that
form and exposes capped, predefined rejection codes without logging raw requests.
All 38 Node tests and 4 verifier tests passed on both Linux and Windows, including
full 180,000-byte local HTTPS responses and intentional 10-second stalls through
the rewrite. These are local results; the correction has **not been deployed**.
The initial public canary was [stopped at its cleanup gate](docs/VERCEL_CANARY_GATE_2026-10-16.md).
A separately authorized [protected-preview canary](docs/VERCEL_PROTECTED_CANARY_2026-10-16.md)
then passed: exactly one Windows HTTPS request returned HTTP 200, the matching ID
and all 180,000 verified bytes in 1.665 seconds, with six correlated origin events.
Vercel Authentication stayed `all`; the dedicated automation bypass was revoked
and fresh independent API reads verified zero remaining bypasses, the unchanged
Hobby plan and original production deployment/aliases. Only four origin files
were deployed to an immutable preview. No origin retry or unauthenticated probe ran.
This single success does not qualify hosted stalls/concurrency or Worker raw-TCP
reachability. The seven-request matrix remains unauthorized; no Worker operation
or live Worker tail occurred.
PR #2 stays Draft and unmerged.

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
   API credentials separate from this VPN secret. The private validation
   deployment is not a shared VPN service.
3. Run `WsVpn.exe` elevated. Choose `cloudflare`, enter
   `wss://ws-vpn-relay.<your-subdomain>.workers.dev/tunnel` and the fresh token,
   keep DNS `1.1.1.1` and the kill switch enabled, then Connect.
4. For a full relay, follow [self-hosted deployment](deploy/README.md), choose
   `selfhosted`, and enter that relay's WSS URL and token.

The bundled Wintun and tun2socks downloads are verified by the build workflow.
Remembered GUI tokens use Windows DPAPI. Closing the window keeps the tray
running; Quit disconnects. After a crash, inspect the session and use the
Recover button or `WsVpn.exe --cleanup` to remove exactly the owned resources.

Windowed EXE CLI runs now retain diagnostics in
`%LOCALAPPDATA%\WsVpn\logs\ws-vpn.log`. An open SOCKS port is created before
startup checks complete; validate authenticated transport, secure DNS and
tunneled Internet traffic before proceeding with TUN tests.

The current firewall guard leaves a material exception: **other applications
can reach the exact relay IP/TCP port**, including shared Cloudflare edge IPs.
Adapters attached after startup are another remaining gate. Do not treat this
alpha as a verified no-leak VPN. See [security limits and physical test steps](docs/CLOUDFLARE_BACKEND.md#actual-limitations-and-security-gates).

## Develop and validate

```bash
git clone --branch feature/vpn-mode https://github.com/ihanemi/ws-proxy.git
cd ws-proxy
python -m pip install '.[dev]' certifi cryptography
python -m ruff check vpn relay vpn_windows.py tests/test_vpn_*.py
python -m compileall -q vpn relay vpn_windows.py
python -m unittest discover -s tests -q
cd worker
npm ci --ignore-scripts
npm test
npm run check
```

`certifi` and `cryptography` are needed by preserved upstream tests, not the VPN core. `npm run
check` bundles the Worker without deploying it. VPN CI tests Python and Worker
behavior; Windows CI additionally verifies native token storage, builds the
EXE/installer and checks the E2E script syntax. These checks do not replace
packet captures, live relay traffic or tests on a physical Windows machine.

The latest focused checks ran 89 VPN Python tests on Linux (4 Windows-only
skips) and physical Windows (no skips), with no failures. All 28 Worker tests
passed on both. New tests run the production Worker inside workerd with real
TCP and verified HTTPS, delivering a complete 180,000-byte response in all
four path-check/ACK combinations. Two integration tests also cover the actual
Python SOCKS/WSS client and an origin that receives a request but withholds its
response. CI runs this coverage explicitly. See the
[diagnosis and reproduction commands](docs/TRANSPORT_DIAGNOSIS_2026-10-15.md).
These local passes do not resolve failed live acceptance or verify leak protection.

Android is planned around native `VpnService` and the same WSVPN/1 contract.
Implementation follows shared transport and physical Windows validation;
there is no Android APK yet.

## Documentation

- [Successful single protected Vercel canary and verified credential cleanup](docs/VERCEL_PROTECTED_CANARY_2026-10-16.md)
- [Vercel rejection diagnosis, local correction and proposed single-request canary](docs/VERCEL_ORIGIN_REJECTION_DIAGNOSIS_2026-10-16.md)
- [Latest bounded transport diagnosis and real TCP/HTTPS tests](docs/TRANSPORT_DIAGNOSIS_2026-10-15.md)
- [Approved PR #2 deployment, failed live tests and verified version rollback](docs/PR2_LIVE_VALIDATION_2026-10-15.md)
- [Complete Windows client manual](README.vpn.md)
- [Cloudflare deployment, architecture decisions and validation gates](docs/CLOUDFLARE_BACKEND.md)
- [WSVPN/1 protocol and compatible extensions](docs/VPN_PROTOCOL.md)
- [Security audit](docs/VPN_SECURITY_AUDIT.md)
- [Windows recovery](docs/WINDOWS_RECOVERY.md)
- [Dependency licenses and provenance](THIRD_PARTY_NOTICES.md)
- [Preserved upstream Telegram proxy documentation](docs/EN/README.md)

Licensed under [MIT](LICENSE); bundled dependencies retain their own licenses.
