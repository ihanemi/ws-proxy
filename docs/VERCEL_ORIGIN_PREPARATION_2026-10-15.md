# Vercel origin preparation — local validation, authentication required

**Historical preparation record:** owner login subsequently completed. The
[authorized hosted trial](VERCEL_ORIGIN_VALIDATION_2026-10-15.md) verified public
DNS/ownership/TLS but failed all seven controls with HTTP 400. The temporary
project is protected again; no diagnostic Worker use is authorized.

The owner authorized **only** a temporary user-owned Vercel Hobby origin and
independent tests. Account registration/authentication must be completed securely
by the owner. No Cloudflare upload, deployment, activation, modification or live
Worker tail is authorized. PR #2 remains Draft at `458e877`.

## Implementation

Source commit: `afef41e`, on the existing separate
`diagnostic/cloudflare-session-counters` branch.

- `worker/diagnostic/vercel/api/origin.mjs`: dependency-free Node 24 Function
  adapter with the existing three fixed synthetic modes and ID header.
- `worker/diagnostic/vercel/vercel.json`: one function, 15-second invocation
  limit, explicit experiment-file inclusion and fixed diagnostic-path rewrite.
- `worker/diagnostic/stage-vercel.mjs`: copy **only four allowlisted files** to
  a separate empty upload directory. It generates exactly seven fresh IDs and
  an absolute 20-minute validity window. Its hash manifest stays outside that
  directory. No repository root, `.git`, Worker, VPN credentials, Cloudflare
  config, environment file or dependency tree is copied.
- `worker/test/vercel-origin.test.js`: real-socket HTTPS and lifecycle/negative/
  privacy/staging checks, automatically included in the existing Node test glob.

The adapter accepts only bodyless GET requests, valid allowlisted IDs and fixed
modes. Expired/unlisted IDs fail closed. Duplicate IDs are rejected within an
instance; this is explicitly **not a global serverless rate limit**. All responses
disable caching; synthetic bodies request identity encoding. Runtime/request/
response events contain only IDs, allowlisted names, sequences, elapsed times
and byte counts. Raw request content, arbitrary errors and headers are not logged.

The original standalone HTTPS origin, production Worker/client/relay sources and
diagnostic Worker bundle are unchanged. Bundle SHA-256 remains
`5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`.
The preserved immutable Worker rollback ID remains
`6a903b04-b90d-43f6-a9a6-4f6e129bbc4c`; no Cloudflare state was accessed or changed.

## What the evidence means

`origin.request.received` is emitted when the function accepts the synthetic
request. `origin.response.queued` records the proposed body size;
`origin.response.write_complete` records bytes accepted by Node's response
callback. `origin.response.finish` and close/deadline events record the response
lifecycle. The handler awaits that lifecycle instead of returning while its
stall timer is still pending.

**A write callback is not evidence of Vercel edge TCP transmission.** Vercel
terminates public TLS outside this function. Independent client byte counts,
timing and correlated function logs must be compared. If a later Worker test
stalls, a function callback alone cannot distinguish Vercel edge buffering from
the Vercel-to-Worker network span. This limitation must remain explicit.

`stall-response` sends no headers/body and destroys the response after 10 seconds.
`stall-body` flushes headers and writes 1,024 body bytes before the same deadline.
If Vercel substitutes an error page, buffers those partial bytes until the deadline,
changes/caches the response or omits necessary correlated logs, reject the origin
rather than replacing the control with a successful-looking response.

## Actual local validation

On Linux/Node 24.19.0:

```text
cd worker
node --test test/vercel-origin.test.js
4 passed, 0 failed

node --test --test-concurrency=1 --test-reporter=tap test/*.test.js
35 passed, 0 failed, 0 skipped (23.953 seconds)
```

The seven local HTTPS requests were three sequential `ok`, `stall-response`,
`stall-body`, and two concurrent `ok`. TLS used an ephemeral local test certificate
with explicit trust and hostname verification; no trust store was changed.
All five healthy requests validated every byte of the 180,000-byte fixed body
and the echoed ID. The empty stall returned no HTTP response; the partial stall
returned exactly 1,024 bytes before close. Both used the actual 10-second timer
(asserted 9.8–12 seconds), and the partial bytes arrived at least five seconds
before close. Request receipt, callback byte counts, distinct concurrent IDs,
ordered events and close reasons were checked. No public listener was opened.

Negative tests cover bad methods/IDs/modes/query parameters, unlisted/expired/
duplicate sessions, already-consumed request streams, rewrite routing and a
nonempty staging destination. Tests verify the exact deployment-file allowlist
and that malformed requests do not enter the structured log.

An initial default-concurrency full-suite invocation exited with an incomplete
10-test log and no completion footer. It is retained as incomplete evidence, not
a full pass. The explicitly serial TAP run above completed with all 35 tests.
No forwarding change was made in response to that harness result. Existing
Python tests were not rerun for this isolated Node adapter; their earlier results
remain historical results, not new validation.

On the Windows laptop/Node 24.19.0, the focused adapter suite also completed:
**4 passed, 0 failed, 0 skipped (20.414 seconds)**, including all seven local HTTPS
controls. The full Windows Worker suite was not rerun. Results are recorded in the accompanying
[structured preparation record](test-results/vercel-origin-preparation-2026-10-15.json).
These tests exercise local Node HTTPS, **not the hosted Vercel runtime**, a
physical VPN route or a public origin.

## Current public prerequisite status

| Item | Actual state |
| --- | --- |
| Vercel authentication | No CLI or auth configuration found in the checked standard Windows locations; no account login/registration attempted. |
| Target account/project and Hobby plan | Not yet verified; no project created or existing project linked. |
| Public hostname / A / AAAA / network owner | Not assigned/verified. |
| External port | Authorized proposal TCP 443; no laptop listener/firewall change. |
| Public certificate and TLS | Not available for testing yet. |
| Seven independent public synthetic requests | **0 run; blocked on user authentication and origin creation.** |
| Hosted buffering/caching/cold-start/proxy behavior | Unverified. Local results cannot establish it. |
| Workers raw-TCP address eligibility | Pending actual public DNS and network ownership checks. |
| Actual reachability from a Worker | Unverified; no Worker-origin session was attempted. |

Account login is the immediate blocker. The account must be the owner's and its
plan confirmed as free Hobby before creating a dedicated temporary project. Do
not reuse or alter an existing website/project, enable paid features, connect the
whole Git repository or transfer infrastructure credentials to the origin.

The official npm registry reported Vercel CLI `64.2.0` with integrity
`sha512-4Aqk7Wn0z3IhC+sGuMF6CUUnh8Fy7IO/F8lg9khdTbIgVFpnJKEYTrajiZ+8MaJnqASIJy470MQfdeAhjCJBMg==`.
No global CLI install or system setting was changed. The owner can start its
official browser/device login from PowerShell on the laptop:

```powershell
& 'D:\Apps\Data\nodejs\npx.cmd' --yes --ignore-scripts vercel@64.2.0 login
```

Complete authentication only on the official Vercel page opened by the CLI;
verify the request context. If registration is needed, the owner completes it
and selects Hobby. Never paste a password, token, recovery code or auth file into
chat. A simple confirmation that login completed is sufficient to resume.

## Resume after secure login

1. Read back authenticated owner, scope and free Hobby plan. Stop on mismatch,
   a paid commitment or inability to verify ownership/plan. Create only a new
   dedicated temporary origin project in that scope.
2. Immediately before origin deployment, generate fresh IDs in a new private
   staging directory outside Git, verify its four-file hash manifest, and upload
   only that directory. No secrets/environment-variable upload or Git integration.
   Ensure this new origin is publicly accessible without an authentication wall;
   no other project's protection settings may be changed.
3. Record the actual assigned hostname, A/AAAA results and actual public network
   ownership. Reject Cloudflare-owned/nonpublic addresses and unresolved ownership.
   Check Cloudflare's published ranges and official raw-TCP restrictions. Verify
   the real certificate's chain, SAN, expiry, peer address and negotiated TLS with
   strict SNI/hostname validation on port 443; no redirects or certificate bypass.
4. Start a bounded, sanitized **Vercel-origin-only** log capture and run the
   seven direct synthetic cases in the original prerequisite plan, with exactly
   those fresh IDs and 12-second client deadlines. Record cold first response
   separately; do not warm it up with hidden extra requests. Verify all five full
   responses, the zero/1,024-byte stalls, concurrency, IDs, cache/encoding/status
   metadata and correlated receipt/response counters. No payload logging or retry.
5. Report exact infrastructure/cost and actual outcomes; reject proxy interference
   or unreliable evidence. The seven-ID origin expires automatically. Preserve
   logs/manifest and do not silently extend/reactivate it for a later experiment.
   No ongoing paid resource or automatic redeploy is required.
6. Stop before using **any** Worker to reach this origin. Public-IP/port eligibility
   and independent HTTPS success do not prove actual Workers raw-TCP reachability.
   That proof requires a separately authorized Worker-origin session. Request
   separate authorization only after independent origin results are presented;
   preserve the existing 14-session/four-minute/mandatory-rollback constraints.

Official runtime references: [Node request/response APIs](https://vercel.com/docs/functions/runtimes/node-js),
[streaming](https://vercel.com/docs/functions/streaming-functions),
[runtime logs](https://vercel.com/docs/logs/runtime),
[device login](https://vercel.com/changelog/new-vercel-cli-login-flow),
[Hobby limits](https://vercel.com/docs/plans/hobby), and
[Workers TCP restrictions](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/#considerations).
