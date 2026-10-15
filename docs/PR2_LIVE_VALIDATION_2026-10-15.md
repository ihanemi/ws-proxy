# PR #2 — approved test deployment and failed live validation

**Outcome: not accepted; previous Worker version restored; PR remains draft.**
This report covers the explicitly approved test deployment on 2026-10-15.
It supersedes the pending-deployment status in earlier reports, without
reclassifying previous failures as passes.

## Exact scope and preserved resources

- Existing test Worker: `ws-vpn-laptop-9583b21`. Its exact Cloudflare account
  name and account ID were confirmed before deployment in the private preflight
  record and user-facing update. No other Worker was targeted.
- Tested PR source: `024b3dbaf6d2e266ba96b6bfdc256007dc73759a`, branch
  `fix/cloudflare-transport-timeouts`, PR #2 into `feature/vpn-mode`.
- Only Worker production source differences were `src/handler.js` and
  `src/session.js`, implementing the negotiated `echo-v1` gate.
- Previous immutable Worker version:
  `6a903b04-b90d-43f6-a9a6-4f6e129bbc4c`.
- Uploaded and activated test version:
  `6d21fd85-5796-4e05-8869-8776cb0a9770`.
- Matching physical Windows EXE SHA-256:
  `3f686ff085ed50465f46bf5c86bb1a55a7bf0f103ac24be7282b635aacd668ed`.

The existing `TUNNEL_TOKEN` secret binding was retained. No secret upload,
rotation, new binding, route/trigger deployment, plan/billing change or added
Worker logging occurred. Existing encrypted OAuth and DPAPI credentials were
used only locally; credentials are absent from this report and Git.

Pinned Wrangler 4.149.0 uploaded an inactive version with `--keep-vars --strict`,
then activated only that version at 100% on the exact test Worker. Before/after
reads verified settings, bindings, runtime, subdomain and schedules. The local
deployment configuration and DPAPI profile hashes also remained unchanged.
The first comparison stopped before activation because upload added version
tag/message annotations. Those exact descriptive changes were reviewed and
recorded; all runtime configuration still matched before activation resumed.

## Live physical Windows results

Windows 11, Administrator, exact matching windowed EXE; isolated local SOCKS
listener and log directory. No TUN, routes or firewall configuration changed.
Destination requests used SOCKS, strict certificate/hostname verification and
no direct fallback. DNS queries targeted only the configured marker, through
the EXE and authenticated Worker DoH.

| Test | Actual result |
| --- | --- |
| EXE startup | Passed twice: `Connected` observed after transport and DNS checks, not inferred from an open port. |
| TCP DNS | Passed twice; transaction, question, flags, RCODE and nonempty answers validated. 1.13 s / 0.85 s. |
| UDP DNS | Passed twice with the same response checks. 4.69 s / 3.70 s. This does not establish generic UDP support. |
| Single HTTPS, Schannel curl | Failed: HTTP `000`, curl 28 after 25.04 s, no response bytes. |
| Six concurrent HTTPS, Schannel curl | Failed 6/6: one curl 28 timeout, five curl 56 abrupt TLS closes. |
| Single HTTPS, independent Python TLS through the same EXE | TLS 1.3 and Google certificate verification passed; HTTP response timed out after 16.17 s total. |
| Six concurrent HTTPS, Python TLS through the same EXE | TLS 1.3 and certificate checks passed 6/6; HTTP responses timed out 6/6, 16.21–18.65 s total. |
| Incomplete SOCKS handshake timeout | Passed twice: EXE closed the incomplete local handshake in 10.01 s. No upstream blackhole timeout is claimed. |
| Automatic reconnect | First harness failed before fault injection due to a TCP-table decoding bug. Corrected test closed only exact test-process Worker TCP connections after rechecking process identity. `Reconnecting` and health recovery were observed; post-recovery DNS passed, but HTTPS still timed out. Overall failed. |
| EXE process and redaction | EXE remained alive; collected logs contained no VPN token. Exact test processes were then cleaned up. |

During the second run, the log recorded reconnect at 17:26:58 UTC and health
recovery at 17:27:03 UTC. That health recovery did not establish Internet
application recovery. The first run also recovered spontaneously from a failed
health probe. A bounded read-only Worker tail collected no events during its
window; it provides no current server-side cause. Earlier `loadShed` evidence
must not be attributed to these new failures.

[Structured results, including both failed runs](test-results/pr2-live-2026-10-15.json)
retain the tested source/build/version identifiers and actual failures. Original
scripts, logs, preflight snapshots and rollback records remain on the laptop
outside Git. The fault-injection harness bug was corrected locally; no
speculative production code fix was deployed.

## Rollback and final state

Before deployment, the existing immutable version was viewed and its 100%
version-only activation command passed dry-run. After failed validation, the
same operation restored it. The active version was read back and runtime,
bindings, settings, subdomain, schedules and local profile invariants were
verified. Both immutable versions remain available.

The pinned CLI's exact operation, using the existing private deployment config,
was equivalent to:

```powershell
node <pinned-wrangler-cli> versions deploy 6a903b04-b90d-43f6-a9a6-4f6e129bbc4c@100 --config <existing-test-config> --yes
```

The private helper `approved_deploy.py rollback` performs that operation and
post-checks; `approved_deploy.py verify` reads back the state. The config binds
the exact account and test Worker. Do not use the repository's default Worker
name or a different account. Do not re-upload secrets or apply routes/triggers.

An additional Windows **source-client legacy-contract** DNS smoke after
rollback timed out on both pinned Worker IPv4 addresses (8 s per attempt).
This was not an EXE acceptance test. The previous version is verifiably restored,
but functional recovery is **not** claimed. Intermittent failures existed before
this deployment, so these tests do not establish that the new Worker caused a
new regression. Restoring it was the conservative response to failed validation.

Keep the new `WsVpn-path-check` EXE separate: it requires `echo-v1` and is now
incompatible with the restored old Worker. The previous client and its settings
were retained; desktop shortcuts/default configuration were not replaced.
No user action or new deployment is required to complete this rollback.

## Remaining gate

`echo-v1` negotiated and allowed real DNS and TLS handshakes, but did not solve
post-handshake application stalls. The precise internal cause remains unknown.
The next code change must be driven by a reproducible, bounded comparison of
post-TLS traffic with the preserved client/Worker pair, rather than more nonce
checks or speculative retries. Never replay application payload or add direct
fallback to hide the failure.

PR #2 is not merged. TUN routing, IPv6, leak protection, adapter switching,
sleep/resume and crash recovery were not physically validated in this run;
the existing relay-IP firewall exception remains a separate critical gate.
Generic UDP/QUIC is still unsupported in Worker mode. Automated CI passes
remain useful but do not override this failed live acceptance.
