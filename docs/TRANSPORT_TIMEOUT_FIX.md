# Session path verification — pending live deployment

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
- The updated unsigned Windows EXE was built locally with PyInstaller 6.22.2;
  its final live Cloudflare test awaits the matching Worker deployment.
- Live validation of **the final extension** is pending. The existing private
  Worker has not been updated. Earlier successful and failed live observations
  refer to the deployed old contract or intermediate client-only changes.
- No TUN/routes/firewall changes or physical leak, crash, sleep or adapter-switch
  tests were performed during this continuation. Android remains gated.

## Review, deployment and rollback

Automatic approval review rejected an attempted diagnostic replacement of the
existing live Worker because the exact endpoint replacement and added logging
were not explicitly approved. That diagnostic deploy did not run. The final
change adds **no diagnostic Worker logs**. It is prepared as a draft PR;
deployment of the final functional Worker change still awaits user approval.
No merge or stable-release claim is appropriate before live validation.

After approval, use the existing private deployment config and encrypted
Cloudflare OAuth session to deploy this branch's `worker/src/index.js` to the
same test Worker. Keep the current fresh VPN secret unchanged and separate from
Cloudflare credentials. Do not enable paid bindings, account upgrades or a
public shared service. Then use the matching client build and repeat secure
UDP/TCP DNS, verified HTTPS and concurrency checks, including failed-path
selection, before running any TUN tests.

The previous development revision `722a26a` supplies the rollback Worker source
and matching old Windows build. Reverting the Worker requires also using the
old client for Cloudflare mode; the new client intentionally rejects the old
Worker. Preserve encrypted settings and exact resource ownership throughout.
