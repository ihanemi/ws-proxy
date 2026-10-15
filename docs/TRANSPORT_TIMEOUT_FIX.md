# Session path verification — live validation failed

Branch: `fix/cloudflare-transport-timeouts`, based on `feature/vpn-mode`
at `722a26a`. This is an alpha compatibility update, not a stable release.

## Evidence and scope

On the physical Windows laptop, a fixed matrix with the same source client,
verified TLS, hostname, token and pinned relay addresses received READY on both
Cloudflare addresses. One address failed all three application probes, DNS and
HTTP checks; the other initially passed all five. A read-only Cloudflare tail
correlated two failed requests with `loadShed` and internal errors. That does
not identify Cloudflare's internal cause or establish a permanent bad IP.

Later runs showed intermittent failures even on the initially working address.
Selecting a successful `/probe` address alone did not fix newly opened sessions.
Standard WebSocket Ping/Pong caught some failures, but subsequent application
DNS/TCP could still stall. Those intermediate attempts did **not** pass full
live validation and must not be reported as a successful fix.

The proposed change checks Worker message processing on each exact data session
with the negotiated `echo-v1` nonce exchange described in
[WSVPN/1](VPN_PROTOCOL.md#per-session-path-check-echo-v1). It retries only control
handshakes, before any application payload. It does not claim to repair
Cloudflare infrastructure, guarantee Internet reachability or replay TCP bytes.

The source commits add session-local relay preference, deadline-bound path
checks, forced cleanup of timed-out handshakes and an optional Worker challenge
gate. Existing self-hosted TCP/UDP and legacy Worker clients remain supported.
The new Cloudflare client requires the updated Worker; there is no silent
fallback to the older handshake. Windows builds now run on PRs into
`feature/vpn-mode`, allowing artifacts to be checked before merge.

## Actual validation

- Linux: 144 Python tests, 4 Windows-only skips, no failures; Ruff/compile pass.
- Physical Windows 11 as Administrator, Python 3.13: 144 Python tests, no skips
  or failures, including verified local TLS failover and native safety tests.
  Git's OpenSSL directory was added to the test process PATH, not system PATH.
- Worker: all 24 tests pass on Linux and physical Windows; Wrangler dry-run
  bundles approximately 47.6 KiB without deployment.
- Real localhost workerd tests cover extension negotiation, fragmented masked
  challenges and DNS mediation. DNS upstream is mocked in those runtime tests.
- Negative tests cover early data, duplicate/malformed/absent challenge,
  timeout cleanup, absent negotiation, protocol failure, cancellation and
  prevention of application-payload replay. Server-first TCP banners are kept.
- The matching unsigned Windows EXE was built locally from `024b3db` with
  PyInstaller 6.22.2. SHA-256:
  `3f686ff085ed50465f46bf5c86bb1a55a7bf0f103ac24be7282b635aacd668ed`.
- With explicit approval, the final extension was deployed to the existing test
  Worker on 2026-10-15. Live physical Windows EXE checks passed startup and
  Worker-mediated DNS over both local SOCKS UDP and TCP.
- HTTPS **failed**. Schannel curl obtained no successful HTTP response in the
  single or six-stream tests. A follow-up using Python's verified TLS through
  the same EXE completed TLS 1.3 with a valid Google certificate on all seven
  streams, but every HTTP response timed out. This isolates the observed stall
  after the TLS handshake; it does not identify the internal cause.
- Incomplete local SOCKS negotiation closed after 10.01 seconds in both runs.
  This is a client input timeout test, not an upstream blackhole timeout test.
- Reconnection and rollback results are recorded in
  [the approved deployment report](PR2_LIVE_VALIDATION_2026-10-15.md).
- No TUN/routes/firewall changes or physical leak, crash, sleep or adapter-switch
  tests were performed. Android remains gated. These results do not establish
  a working system-wide VPN.

## Deployment and rollback

The user explicitly approved deployment to the existing **test Worker only**.
The exact account, Worker name, previous immutable version, one existing
`TUNNEL_TOKEN` secret binding and local DPAPI profile were verified first.
No previous pasted credentials were reused, no tokens were rotated, and no
production Worker or unrelated resource was touched.

The pinned Wrangler 4.149.0 uploaded only the existing Worker source with
`versions upload --keep-vars --strict`, then activated the uploaded immutable
version at 100% traffic. No routes/triggers deployment, billing upgrade, new
bindings, or diagnostic logging was applied. Before/after API reads compared
settings, bindings, subdomain and schedules. Version tag/message annotations
were recorded separately: these descriptive fields change on version upload
and are not runtime configuration. The initial exact comparison stopped before
activation on those annotations; activation resumed only after verifying that
all remaining fields were identical.

Rollback uses the preserved **immutable version**, not a rebuild of an old
commit. Its version-only activation command was dry-run before deployment and
its actual result is in the deployment report. After rollback, use the matching
older client: the new Cloudflare client intentionally rejects a Worker without
`echo-v1`. Keep the new EXE separate from the previous client.

The final extension **did not pass live validation**. Do not merge PR #2,
release a stable build, or describe the timeout as resolved. A nonce echo proves
only the session at that instant; it cannot guarantee subsequent traffic.
The next focused fix needs evidence of where post-TLS data stops, with a
repeatable comparison against the preserved Worker/client pair. No speculative
code change or additional deployment is justified by these results alone.

## Subsequent bounded diagnosis

[The follow-up investigation](TRANSPORT_DIAGNOSIS_2026-10-15.md) tested the
restored Worker with the original EXE, traced encrypted byte counts on legacy
sessions and added real workerd/TCP/HTTPS integration coverage. It found both
working response fragments and stalls on the legacy path, but no confirmed
internal root cause. No further Worker deployment or production fix occurred.
