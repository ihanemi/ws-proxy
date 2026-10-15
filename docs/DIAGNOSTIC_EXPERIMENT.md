# Prepared diagnostic experiment — approval required, NOT deployed

Base: PR #2 at `458e877`. Separate branch/worktree:
`diagnostic/cloudflare-session-counters`. PR #2 remains Draft at the same head.
The restored live Worker `6a903b04-b90d-43f6-a9a6-4f6e129bbc4c` was not changed.
No live tail, public origin, paid resource, routing/firewall change or Android
work was started. This is instrumentation, not a proposed production fix.

## Review boundary and artifact

`worker/diagnostic/index.js` is a separate entry. The normal `src/index.js`,
all production forwarding/security/DNS sources, Python core, dependency locks
and Wrangler configuration are unchanged. Normal Worker builds contain no
`wsvpn-diag/1` code. Default build/deployment commands do not select this entry.

The diagnostic builder applies exactly three guarded edits to an **in-memory
copy** of `handler.js`:

1. Rename its captured `runtime` parameter to `baseRuntime`.
2. Bind `runtime = baseRuntime.forRequest(request, env)` inside each request.
3. Call `runtime.diagnosticDone?.()` after the original `active--` in release.

The handler is still instantiated once, retaining its shared eight-session
admission cap. The final hook runs after the original cleanup completes. Build
anchors must match exactly; a source change stops the build for review.

Wrappers observe existing `read()`/`write()` promises and WebSocket callbacks.
They add no pump, read-ahead, payload copy/replay, ACK, retry or fallback.
Writes, backpressure, authentication, TLS, READY, protocol negotiation and
half-close behavior remain in the existing code. Instrumentation adds logging
and promise-observation overhead; identical timing is not claimed.

Build with the existing pinned dependencies:

```bash
cd worker
node diagnostic/build.mjs
```

Outputs are ignored by Git: `diagnostic/build/worker.js` and `manifest.json`.
The validated bundle SHA-256 is:

`5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`

Windows and Linux produced identical bundles. The manifest also records the
normalized production-source hashes; no credentials or environment secrets are
build inputs. Upload only this reviewed bundle, not the raw diagnostic entry
or local fixture. The fixture's loopback mapping/statistics endpoint is absent
from the deployable bundle.

## Correlation, counters and privacy

Each synthetic session has a fresh random 128-bit ID, exactly 32 lowercase hex
characters. The client sends it in `X-WSVPN-Diagnostic-ID` on the outer WSS
upgrade and inside the encrypted synthetic HTTPS request. The authenticated
diagnostic Worker echoes it in the upgrade response. No-ID/invalid-ID requests
retain ordinary forwarding and are not instrumented. Failed authentication
cannot enable diagnostic logs.

Worker records use schema `wsvpn-diag/1`, ID, per-session sequence, relative
elapsed time, fixed event names and non-sensitive counts:

- WebSocket DATA reception and accepted send bytes/frames.
- TCP connect start/completion/error; write start/completion/error.
- TCP read start/completion/error/EOF and byte counts.
- ACK receipt, outstanding ACK count and wait/progress boundaries.
- Half-close, read/write cancellation and an allowlisted close reason.
- A final `session.summary` after cleanup, including totals and suppressed-event
  count. At most 128 normal events plus close and summary: 130 records/session.

No payload, decrypted HTTP content, token, Authorization header, TLS key,
exception message/stack, target hostname, peer IP or user-selected reason is
recorded. Untrusted reason text becomes `other`. Clocks are not assumed to be
synchronized; join by ID and compare per-side sequence/counters, not global
timestamp ordering. Successful WebSocket send/write callbacks indicate local
acceptance/completion, not proof of peer receipt.

`scripts/collect_worker_diagnostics.py` filters raw Wrangler tail envelopes in
memory. It writes only allowlisted fields/events for 1–16 preselected IDs and
sanitized runtime outcomes. Raw request headers, logs, exceptions and payloads
never reach its output file. It has bounded buffering, 2,000-row/240-second
limits, records drops/truncation, uses the exact test account/config and pinned
Wrangler 4.149.0, and terminates its own direct CLI process. It requires the
explicit `--authorized-live-tail` switch. **It has not been run live.** A zero,
truncated or interrupted capture cannot establish an edge failure.

`scripts/diagnostic_https.py` sends exactly one synthetic request with ACK
enabled, strict WSS/origin TLS and no direct fallback. Contract selection is
explicit (`legacy` or `echo-v1`); it never downgrades automatically. It verifies
the origin's echoed ID, HTTP status, length and entire fixed body without
logging contents. The overall request deadline is at most 20 seconds, followed
by at most 0.5 seconds for graceful close and forced cleanup. Evidence files
use exclusive creation and cannot overwrite prior runs. VPN authentication is
supplied only in the child process environment from the existing DPAPI profile.

## Controlled origin and remaining prerequisite

`worker/diagnostic/origin.mjs` is a standalone Node 24 HTTPS service. It defaults
to loopback; public binding requires an explicit flag and separate authorization.
It requires explicit certificate/key files, accepts only bodyless synthetic GET
requests with a valid ID, and emits ID/counter/event records without contents.
It has four-connection, 24-request and five-minute lifetime limits. There are
three fixed routes:

| Mode | Origin behavior |
| --- | --- |
| `ok` | Send a fixed 180,000-byte synthetic body; record request receipt and response callback counts. |
| `stall-response` | Receive the request, send no response, close after at most 10 seconds. |
| `stall-body` | Send headers and 1,024 synthetic body bytes, then hold/close within 10 seconds. |

The public experiment requires an **already authorized public host** and valid
certificate on a dedicated, already permitted port (443 or 8443). The origin
must use public non-Cloudflare egress addresses: Workers raw TCP blocks
Cloudflare IP ranges and private/loopback destinations, per the
[official TCP documentation](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/#considerations).
A second Worker or a Cloudflare-proxied origin is unsuitable for this raw-TCP
experiment. No VPS purchase, new account, DNS/firewall change or exposure of the
laptop is included in the proposed authorization.

**No public origin hostname/server has been supplied or provisioned.** Public
reachability and certificate validation remain preconditions, not passing live
tests. If no suitable host already exists, stop rather than substitute a paid
resource, a public laptop listener or a third-party endpoint without consent.

Future origin command, only on that approved host:

```bash
node worker/diagnostic/origin.mjs --key /approved/tls/key.pem --cert /approved/tls/cert.pem --host 0.0.0.0 --port 8443 --duration 240 --allow-public-bind
```

TLS files stay on the origin host. Origin logs contain synthetic counters only.
No system trust store or production HTTPS service is modified.

## Local validation actually performed

| Environment/check | Result |
| --- | --- |
| Linux VPN Python, real runtime enabled | 94 tests; 4 Windows-only skips; no failures |
| Physical Windows Python 3.13, real runtime enabled | 94 tests; no skips or failures |
| Worker tests on both systems | 31/31 passed on each |
| Ruff and diagnostic bundle build | Passed on both |
| Ordinary Worker build | Generated; diagnostic marker absent |

The new real-socket tests correlate all three sides for full responses under
both contracts, intentional no-response and 1,024-byte stalls, and two concurrent
sessions with distinct IDs. ACK remains enabled. They verify TCP/WS progress,
origin request/response counts and post-cleanup cancellation summaries. Unit
tests check original byte references/method results/error identity, EOF calls,
auth opt-in, log-injection resistance, event caps, and the original shared
admission/auth/protocol behavior. Collector tests seed fake credentials/private
content in raw envelopes and prove that they are excluded.

Earlier local harness failures are retained/reported: IPC line limits,
overlapping test CA patches, and cleanup assertions after the event cap. These
were corrected in diagnostic/test code; they were not production defect fixes.
No live root cause is claimed from local passes. The local fixture alone maps
an artificial validated address to loopback and trusts an ephemeral test CA;
that mapping/CA is neither in the deployable Worker nor used by public runs.

[Machine-readable preparation results and manifest](test-results/diagnostic-experiment-preparation-2026-10-15.json).
Reproduce with Python dependencies, Node 24, existing Worker dependencies and
OpenSSL on the test process PATH:

```bash
WSVPN_WORKER_RUNTIME_TESTS=1 python -m unittest tests.test_vpn_diagnostic -v
cd worker
node --test test/diagnostic.test.js
node diagnostic/build.mjs
```

## Proposed bounded live matrix — not executed

Freeze at most two Worker IPv4 addresses before the run. Generate 14 fresh IDs
in advance for client/origin/tail correlation; never reuse an application request.
Keep the existing VPN secret separate from infrastructure OAuth. Start sanitized
tail capture before tests, using only the existing encrypted OAuth session.

| Cases | Count | Required observation |
| --- | ---: | --- |
| Two pinned IPs × legacy/echo-v1 × `ok` | 4 | Exact ID; verified TLS; request at origin; full 180,000 bytes across all boundaries. |
| Two IPs × both contracts × `stall-response` | 4 | Origin request count one, response count zero; expected bounded timeout/cleanup. |
| Two IPs × both contracts × `stall-body` | 4 | Origin/client 1,024 bytes; expected bounded timeout/cleanup. |
| Two concurrent `ok` requests on a previously verified address | 2 | Distinct IDs; full independent responses; original admission/backpressure retained. Skip if no address passed. |

Use 12-second request deadlines, no more than two concurrent sessions, a
180-second matrix deadline, and a 240-second total diagnostic activation budget.
Start rollback no later than 210 seconds even if tests are incomplete. Stop
early on unexpected failures, telemetry loss or inability to verify resources.
Intentional origin stalls are expected controls, not regression passes. The origin
closes within 10 seconds, so a deliberate EOF/close may precede the 12-second
client timeout; record that distinction rather than requiring TimeoutError.

Interpretation is conditional on complete capture and a successful control:

- Client reports write, Worker DATA absent: client/edge/Worker-ingress span;
  absence alone does **not** prove a Cloudflare edge fault.
- Worker DATA present but corresponding TCP write incomplete/error: Worker
  forwarding/socket boundary.
- TCP write completes but origin request absent after verified TLS: outbound
  transport/origin-read span; local acceptance is not proof of origin delivery.
- Origin receives request but emits no response: origin behavior; intentional
  controls must produce exactly this signature.
- Origin emits bytes, Worker read absent: origin-to-Worker transport/read span.
- Worker reads bytes but sends no DATA while ACK is pending: investigate the
  recorded ACK boundary; do not disable backpressure.
- Worker sends DATA but client receives none: return edge/network/client span.
  If client receives DATA but no body progress, investigate TLS/client parsing.

## Exact deployment and rollback requirements — future authorized step only

Only existing test Worker `ws-vpn-laptop-9583b21`, account
`f97e1b7fd6a5f23a1ffb8c4f0450c58e`, may be targeted. The private configuration is
`C:\Users\user\AppData\Local\WsVpn\setup\wrangler.laptop.json`.
It retains compatibility date `2026-09-09`, existing `TUNNEL_TOKEN` secret,
bindings, plan, settings, subdomain, schedules and disabled persistent
observability. Do not use the repository default Worker name/config.

Before activation: require separate approval and an approved origin; confirm
the current version is still the preserved rollback ID; verify settings/profile
hashes, fresh encrypted OAuth and rollback access. Rebuild and check the exact
SHA above. Any target, version, config, binding or artifact mismatch stops work.
The existing private `approved_deploy.py verify` can read back invariants;
its old `deploy`/`preflight` modes target an earlier source and must not be used.

The reviewed CLI sequence, using the pinned direct CLI and isolated existing
OAuth environment, is:

```text
node <pinned-wrangler-dist/cli.js> versions view 6a903b04-b90d-43f6-a9a6-4f6e129bbc4c --config <exact-private-config> --json
node <pinned-wrangler-dist/cli.js> versions deploy 6a903b04-b90d-43f6-a9a6-4f6e129bbc4c@100 --config <exact-private-config> --yes --dry-run
node <pinned-wrangler-dist/cli.js> versions upload <reviewed-diagnostic-build/worker.js> --no-bundle --config <exact-private-config> --keep-vars --strict
```

Upload creates an inactive immutable version. Verify its runtime/binding
metadata and all unchanged settings before activating only that candidate:

```text
node <pinned-wrangler-dist/cli.js> versions deploy <verified-new-version>@100 --config <exact-private-config> --yes
```

No secret file, variable upload, compatibility flag, observability setting,
route/trigger deployment, paid binding or production resource is authorized.
Do not run a plain `wrangler deploy`. Record the candidate version and manifest.

**Unconditional rollback after the bounded run, including on error:**

```text
node <pinned-wrangler-dist/cli.js> versions deploy 6a903b04-b90d-43f6-a9a6-4f6e129bbc4c@100 --config <exact-private-config> --yes
```

Use the existing immutable version, not rebuilt source. The private
`approved_deploy.py rollback` already performs that operation and invariant
checks. Verify old version at 100%, settings/bindings/profile unchanged, stop
the owned tail process and origin, and preserve sanitized evidence. If rollback
fails, stop testing and report the actual active version/error; never claim
service restoration from version metadata. The known legacy health issue may
remain after rollback. Retain both Worker versions and matching old client.

**Authorization requested, not granted:** a temporary diagnostic deployment and
bounded sanitized tail/matrix on this exact test Worker, conditional on approval
of the controlled public origin, followed by mandatory rollback. No action is
taken until that separate authorization and origin prerequisite are satisfied.
