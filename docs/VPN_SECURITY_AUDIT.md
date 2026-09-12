# WS VPN engineering audit

Baseline: `feature/vpn-mode` at `7a9d05e058dfd39297ae854be8858a4e4d7b62b7`,
reviewed 2026-09-10. This is an experimental client, not an approved alpha.

## Evidence and architecture

Reviewed `vpn/`, `relay/`, VPN tests, Windows entrypoints, settings/DPAPI,
PowerShell E2E script, packaging and workflow definitions, and the legacy
entrypoint/import/build paths. No repository AGENTS.md was present.

The VPN packages do not import the Telegram packages. TCP uses one WSS per
SOCKS CONNECT; UDP uses one WSS per UDP association and one egress socket per
address family. tun2socks runs as a child of the elevated client. The GUI
controls the core in a thread but marks the connection ready on route creation.

The baseline has **13 VPN unit tests**, all passing locally. GitHub run
[34459310107](https://github.com/ihanemi/ws-proxy/actions/runs/34459310107)
passed Linux tests. Windows run
[34459147669](https://github.com/ihanemi/ws-proxy/actions/runs/34459147669)
at `fb06c17` passed packaging, a DPAPI round trip, PowerShell parsing, and
`--help`. None proves that real traffic crossed Wintun or that traffic was
blocked after a crash. PowerShell multi-command steps can also mask earlier
native-command failures if their exit codes are not checked individually.

## Baseline findings

| Priority | Finding | Consequence |
| --- | --- | --- |
| Critical | Recovery trusts loosely parsed machine-wide JSON; process termination checks only PID/path, then terminates by PID | Malformed state can reach PowerShell; PID reuse or a race can terminate an unrelated process |
| High | Cleanup removes all default routes on an adapter selected by its name, and deletes relay routes whether creation succeeded or not | Unrelated routes/adapters can be affected |
| High | No machine-wide session lock; startup automatically removes a prior guard | A second instance or reconnect can dismantle an active kill switch |
| High | Firewall applies to one interface; restart deletes rules before replacement | Secondary interfaces and network changes can leak |
| High | TUN DNS configuration leaves other interface DNS reachable, including private routers | Windows multihomed DNS can leak queries |
| High | PowerShell nonterminating errors and cleanup failures are suppressed | A failed firewall install/cleanup can be reported as successful |
| High | Client frames and relay messages have no size limit; UDP creates unbounded send tasks and destination caches | Memory/socket/task exhaustion |
| High | Authentication happens after HTTP 101; SOCKS success precedes destination connect | Unauthorized/failed tunnels can appear successful |
| High | Client WebSocket close frame marks closed without closing the socket; cancellation does not always join bridge tasks | Transport and task leaks |
| High | Per-request relay DNS resolution is independent from bypass route resolution | DNS rotation can select an unbypassed address and recurse through TUN |
| High | State is written after route/firewall changes; no protected directory ACL is established | Crash gaps and local state tampering |
| High | No relay connect/idle/session limits; `is_public_ip` admits CGNAT | Relay abuse and nonpublic egress |
| Medium | SOCKS handshake lacks timeout; reserved byte/endpoint handling is incomplete | Stalled clients and malformed protocol handling |
| Medium | Uninstall ignores cleanup failure and doesn't coordinate with a live client | Networking state can outlive the installed recovery tool |
| Medium | GUI readiness uses route creation, not traffic; no health check/reconnect | False connected status and no recovery from relay outage |
| Medium | One-file elevated packaging and runtime lookup from cwd/PATH require additional review | Privileged runtime provenance/extraction risk |
| Medium | Third-party notices refer to licenses without shipping all required texts | Redistribution review needed |
| Medium | Logs don't rotate; enabling library DEBUG could expose WSS headers | Unbounded files / credential disclosure |

DPAPI input buffers and pointer signatures were fixed in recent commits and
are present in the inspected code; encryption is user-scoped. That does not
authenticate routing state or make arbitrary configuration input safe.

## Release blockers and sequencing

Fix ownership, parsing, transport and resource bounds first, then provide a
deployable relay and stronger E2E tooling. Keep `main` unchanged. Do not change
third-party binary pins without checking official upstream releases.

The baseline Worker backend has hostname-only filtering and no UDP; it is
not a compatible production relay. The root Dockerfile, legacy UI, updater,
and manually triggered Build & Release workflow still target Telegram.
The old workflow even rewrites PE metadata. Do not use it for WS VPN releases.
Legacy removal/restructuring remains gated on proving the VPN path.

**A firewall rule existing is not evidence of fail-closed traffic behavior.**
Hot-plugged interfaces, simultaneous Ethernet/Wi-Fi, private DNS fallback,
sleep/resume, route preference, IPv6, boot recovery, and installer lifecycle
require real Windows measurements. Snapshot-based interface rules cannot
promise a zero-window guarantee for newly attached adapters. Full protection
needs a separately validated persistent filtering design; do not label this
implementation production-ready while that remains open.

No real Windows/relay E2E, performance benchmark, production validation,
Defender test or Authenticode signing was performed by this review.
The WS VPN EXE and installer are unsigned; a signed upstream compiler or
Wintun DLL does not sign our outputs.

## Reference contracts

- [websockets 15 client API](https://websockets.readthedocs.io/en/15.0.1/reference/asyncio/client.html)
- [websockets 15 server API](https://websockets.readthedocs.io/en/15.0.1/reference/asyncio/server.html)
- [Windows Firewall rule precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)
- [Inno Setup lifecycle hooks](https://jrsoftware.org/ishelp/topic_scriptevents.htm)

See subsequent commits and the remediation record below for verified fixes;
the table above intentionally records the original baseline.

## Remediation record

| Area | Current evidence | Remaining gate |
| --- | --- | --- |
| Transport | `WSVPN/1`, pre-upgrade auth, bounded frames/queues/tasks, TCP half-close and TLS integration tests | Sustained throughput and lossy-network measurements |
| Relay | Public-address validation, connection/peer/time limits, bounded UDP state, `/healthz`, systemd/container/reverse-proxy examples | Deploy to a real host and run operational/load checks |
| Windows ownership | Versioned private journal, exact route/rule identity, adapter GUID/index, PID/path/birth-time validation, machine-wide mutex | Physical reboot, upgrade/uninstall and adversarial recovery tests |
| Leak prevention | All startup adapters guarded; physical DNS/DoT blocked; E2E contains a forced physical-route bypass probe | Hot-plug adapter design plus Wi-Fi/Ethernet, sleep/resume and native IPv6 measurements |
| Packaging | Versioned PyInstaller/Inno outputs, pinned dependency hashes and fail-fast CI | Authenticode-sign the WS VPN EXE/installer and test Defender reputation |
| Product lifecycle | Explicit disconnect path, crash-preserved guard, rotating logs | Traffic-based readiness, bounded reconnect state machine and physical Windows E2E |

Automated Linux transport tests and Windows native/build tests are CI evidence,
not a substitute for the physical tests above. No alpha tag or release should be
created until the dedicated Windows E2E run is recorded and its cleanup is
manually inspected.
