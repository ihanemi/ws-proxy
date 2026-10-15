# Laptop validation — 2026-10-15

Development continues on `feature/vpn-mode`, based on merge `9583b21`.
Existing transport, Windows integration and self-hosted TCP/UDP are retained.
No stable release or merge to `main` is approved by these results.

## Completed changes

- `e91f6f1`: real localhost HTTP upgrade and masked WebSocket tests against
  workerd, including fragmented DNS messages and repeated probe admission cleanup.
  The test client `ws` is an exact development dependency, reusing the already
  locked version; no production transport dependency was added.
- `65d6945`: windowed Windows EXE CLI sessions now use the existing rotating
  file logger. Startup transport/DNS stages and safe failure types are recorded.
  A regression test verifies operation without stderr and keeps a test secret
  out of the log. CI now also watches, lints and compiles the Windows entry point.

## Actual checks

| Environment/check | Result |
| --- | --- |
| Linux Python 3.12, websockets 15.0.1 | 130 tests, 4 Windows-only skips, no failures; Ruff and compile pass |
| Physical Windows 11, Python 3.13, Administrator | 128 tests, 1 skip, no failures; Ruff and compile pass |
| Worker Node 24, Linux and physical Windows | 19 tests pass, including real localhost masked frames; Windows Wrangler dry-run passes |
| Windows local PyInstaller build | Updated unsigned EXE built successfully from implementation `65d6945` |
| Updated EXE logging smoke | Log created, no VPN token present; correctly recorded startup transport timeout |
| Live authenticated Worker probe and secure DoH | Successful individual source-client checks; intermittent failures also observed |
| Live SOCKS TCP DNS | Real Worker-mediated DNS response obtained from source and the original CI EXE |
| Live SOCKS UDP DNS | Comprehensive run timed out; a separate instrumented run received a real answer and dropped generic UDP |
| Live raw TCP | Google HTTP returned `204` through WSVPN/1 |
| Live source SOCKS HTTPS | Google returned `200`; six concurrent streams also returned `200` with certificate verification |
| Original CI EXE egress run | TCP DNS passed, HTTPS/concurrency failed; not a successful full client validation |
| Updated EXE startup | Transport probe timed out; egress tests were skipped rather than treating its open SOCKS listener as readiness |
| TUN, routes, firewall, leak/crash/hot-plug/sleep tests | Not performed in this session |
| Live self-hosted relay load, UDP, IPv6 | No suitable relay available; automated regression tests retained |

The local runtime DNS tests still mock outbound HTTPS. Real localhost sockets
extend framing coverage; they do not reproduce Cloudflare's network or prove
Internet egress. Tests that deliberately reject bad handshakes can emit expected
server tracebacks while the suite succeeds.

## Deployment and remaining gates

A private test Worker was deployed on the existing free account with a fresh
VPN secret stored using Windows DPAPI. Cloudflare OAuth credentials remain
separate. No paid plan was enabled. Endpoint/account details, tokens and local
deployment files are deliberately outside Git. The Worker production source
was not changed during this continuation and needs no redeployment for these
test/logging changes.

Live results establish that TCP and secure DNS can pass through the deployed
Worker. They **do not establish reliable connectivity**: no comprehensive run
passed every test, and the rebuilt EXE failed an authenticated startup probe.
The cause of intermittent timeouts remains unresolved; no TLS downgrade,
timing workaround or direct destination fallback was introduced as a supposed
fix. Do not proceed to a stable release or claim a functioning system-wide VPN.

Before TUN testing, obtain reproducible success for authenticated probes,
secure TCP/UDP DNS and concurrent verified HTTPS using the packaged client.
Use a known Worker-compatible destination; failures to Cloudflare-hosted raw
TCP destinations remain an architectural limitation. Then run
`scripts/windows_e2e.ps1` elevated and perform the separately documented
packet-capture, recovery, adapter and sleep/resume checks. Android remains gated
on shared transport and Windows validation.

For windowed CLI runs, inspect `%LOCALAPPDATA%\WsVpn\logs\ws-vpn.log`.
An open loopback SOCKS listener alone is not startup readiness: it is created
before authenticated transport and secure DNS checks. Observe the connected
state and independently validate tunneled Internet traffic. Local private
diagnostic reports retain failed runs as well as successful individual checks.
