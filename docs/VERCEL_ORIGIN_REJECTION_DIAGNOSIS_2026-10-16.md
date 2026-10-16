# Vercel HTTP 400: confirmed local rewrite defect; hosted cause still bounded

Continued from evidence commit `dc81589`, without reactivating the project,
deploying anything, querying live origin logs or sending any public request.
Implementation commit: `5b7823b`, on `diagnostic/cloudflare-session-counters`.
The [seven failed hosted controls](VERCEL_ORIGIN_VALIDATION_2026-10-15.md) and
their original evidence remain unchanged.

## Exact reproduced rejection

The cached official Vercel CLI **64.2.0** on the Windows laptop contains this
rewrite operation in its bundled `dist/commands/dev/index.js`:

```js
let rewriteUrlParsed=url3.parse(beforeRewriteUrl);rewriteUrlParsed.search=url3.parse(rewritePath).search,req.url=url3.format(rewriteUrlParsed)
```

It keeps the original pathname and replaces its query with the rewrite target's
query. With the unchanged `vercel.json`, this produces:

| Original request | Rewrite destination | Delivered `req.url` |
| --- | --- | --- |
| `/_wsvpn_diag/ok` | `/api/origin?mode=ok` | `/_wsvpn_diag/ok?mode=ok` |
| `/_wsvpn_diag/stall-response` | `/api/origin?mode=stall-response` | `/_wsvpn_diag/stall-response?mode=stall-response` |
| `/_wsvpn_diag/stall-body` | `/api/origin?mode=stall-body` | `/_wsvpn_diag/stall-body?mode=stall-body` |

At `dc81589`, `modeFor()` accepted the original pathname **without a query**, or
the internal `/api/origin` destination with a single valid `mode` query. It
rejected all three hybrid forms above.

An offline replay extracted that exact block from the cached CLI, evaluated it
with Node's URL implementation, and sent the resulting requests to the baseline
adapter over loopback sockets. All three returned **400 with zero accepted
events**. All other 400 predicates passed individually:

| Predicate | Baseline replay value | Result |
| --- | --- | --- |
| Method | `GET` | Accepted |
| Diagnostic ID | Fresh local, valid and admitted | Accepted |
| URL/mode | Original pathname plus matching rewrite query | **Rejected: `modeFor()` returns null** |
| Content-Length | Absent | Accepted |
| Transfer-Encoding | Absent | Accepted |

The [preserved replay record](test-results/vercel-rewrite-baseline-replay-2026-10-16.json)
contains the CLI file hash, extracted-block hash and individual case results.
No expired hosted ID was reused. These displayed URLs are fixed synthetic test
vectors, not captured user URLs.

**Limit:** this is a confirmed adapter compatibility bug against the pinned CLI
runtime's rewrite representation. It is not a capture of the hosted production
bridge. The seven historical requests' delivered URLs and incoming framing were
not recorded. Their exclusive cause, and whether each 400 came from application
validation or a Vercel upstream layer, cannot be established retrospectively.
CDN mapping, no-store responses and missing accepted events are consistent with
the defect, but do not prove that historical attribution.

## Minimal correction and rejection evidence

Only origin-specific code, its independent verifier and tests changed:

- `modeFor()` additionally accepts the original diagnostic path with exactly one
  `mode` query matching its path mode. Existing direct/internal forms remain
  valid. Unknown, mismatched, extra and duplicate query parameters still fail.
  `vercel.json` and the rewrite itself are unchanged.
- Each validation predicate contributes a predefined reason code: `method`,
  `diagnostic_id`, `mode_url`, `transfer_encoding`, `content_length`. Admission
  failures use `inactive`, `unlisted_id`, `duplicate_id`. Statuses remain
  400/403/409. Configuration failure remains 503 with `configuration`.
- Application responses carry fixed `X-WSVPN-Origin-Source: wsvpn-origin/2`.
  Rejections also carry `X-WSVPN-Origin-Rejection` with the first fixed reason.
  The separate `wsvpn-origin-rejection/1` log contains only `schema`, `reasons`
  and `id`. The ID is null unless valid, admitted and currently active. All failed
  predicates are included, with at most five reason codes per record and **24
  rejection records per warm instance**, not a global serverless quota.
- Rejection logs never contain raw methods, headers, arbitrary URLs, bodies,
  exceptions or credentials. Logger failure does not change rejection behavior.
  Accepted-session `wsvpn-diag/1` event semantics/schema are unchanged.
- The verifier records only allowlisted rejection codes and an exact marker
  match. It separates `body_wire_bytes` from `body_bytes`; the latter is null for
  unsupported transfer encoding. The old chunked 400 records are preserved,
  not retroactively counted as decoded payload.
- Optional `--canary` staging and verifier modes prepare one fresh admitted ID
  and send exactly one `ok` request without retries. Defaults remain seven
  controls. No new deployment directory or live IDs have been staged this turn.

A matching application marker and correlated function event can establish
application handling in a new test. Marker absence alone cannot prove an upstream
rejection: a proxy could strip it or logs could be incomplete. The fixed marker
is diagnostic evidence, not cryptographic attestation.

ID validity/admission, absolute expiry, instance-local duplicate protection,
bodyless GET restrictions, response bytes, cache controls, 10-second stall timers
and request/response lifecycle handling are preserved. No ACK, backpressure,
payload replay or production transport change was made.

## Actual local tests

| Environment | Check | Result |
| --- | --- | --- |
| Linux, Node 24.19.0 | Focused adapter suite | 7 passed, 0 failed, 0 skipped |
| Linux, Node 24.19.0 | Full serial Node suite | 38 passed, 0 failed, 0 skipped; exit 0 |
| Linux, Python 3.12 | Independent verifier suite | 4 passed, 0 failed |
| Linux | Ruff for changed Python files; `git diff --check` | Passed |
| Windows laptop, Node 24.19.0 | Full serial Node suite | 38 passed, 0 failed, 0 skipped; exit 0 |
| Windows laptop | Independent verifier suite | 4 passed, 0 failed; exit 0 |

```text
cd worker
node --test --test-concurrency=1 --test-reporter=tap test/*.test.js
cd ..
python -m unittest discover -s tests -p test_vpn_vercel_origin.py -v
python -m ruff check scripts/verify_vercel_origin.py tests/test_vpn_vercel_origin.py
```

The seven HTTPS controls now traverse a local routing shim reproducing the
pinned CLI rewrite before reaching the adapter. Five healthy responses each
contain exactly **180,000 verified synthetic bytes** and the matching ID,
including two concurrent sessions. `stall-response` returns no HTTP bytes;
`stall-body` returns exactly 1,024 bytes and remains incomplete. Both close after
9.8–12 seconds, with partial bytes arriving at least five seconds before close.
Node write-callback byte totals, accepted-event ordering and close reasons are
checked. TLS uses an ephemeral explicitly trusted local certificate; no system
trust configuration is changed.

Additional tests isolate all five 400 predicates, cover real-socket framing
rejections, reject incompatible query forms, verify logging limits/redaction,
retain the internal function path and already-consumed Node request handling,
and check the four-file staging allowlist. Python tests cover marker/reason
sanitization, chunk framing counts, a one-request canary invocation and real TLS
with a wrong-host certificate failure. These are local socket tests, not hosted
Vercel, public Worker reachability, VPN routing or physical leak validation.

The first Windows wrapper lost the Node process's exit-code property despite a
complete 38-pass TAP footer and incorrectly raised a wrapper error. That output
is retained. A final synchronous process invocation is used to verify the exit
code and completed successfully; no application change was made for the wrapper
issue. [Structured local results and log hashes](test-results/vercel-origin-rejection-local-2026-10-16.json)
record both operating systems. Existing CI globs already include the changed
tests; no hosted CI run or Windows VPN build is claimed for this isolated change.

## Proposed next step — separate approval required

**No reactivation or public request is currently authorized.** The smallest next
experiment is one origin-only canary, not another seven-case batch:

1. Reconfirm the owner's `hanemi` scope, free Hobby plan and exact existing
   project `ws-vpn-diag-origin-afef41e` / `prj_5zg0OaiYqUemEvmM62FR1YVGXqqM`.
   Record the current deployment, alias and all-deployment protection before
   making any change. Stop on mismatch, unexpected configuration or cost.
2. Prepare a new empty private staging directory with
   `node worker/diagnostic/stage-vercel.mjs <new-private-directory> --canary`.
   Verify its four-file manifest and fresh single ID. Upload only those files
   to that temporary project while protection stays enabled. Preserve the old
   immutable deployment `dpl_8cuGnWLoCfQbvjUBCoMpANgGx2VM` and all old evidence.
3. Review hostname `ws-vpn-diag-origin-afef41e.vercel.app:443`, current resolved
   public addresses, ownership and Cloudflare ranges again. Reject private or
   Cloudflare-owned destinations. Previously verified IPs were `64.29.17.67`
   and `216.198.79.67`; they are historical values, not freshly verified today.
   Pin one approved IP; verify TLS inside the single synthetic request, without
   warm-up, redirects or alternate-IP retries.
4. Prepare a two-minute cleanup deadline before temporarily allowing public
   access. Send **one** fresh-ID `ok` request using the verifier's `--canary`
   mode, with its existing **12-second total deadline**. Preserve sanitized
   marker/reason/status/timing/byte evidence and filtered deployment-scoped
   `wsvpn-origin-rejection/1` or `wsvpn-diag/1` events. Never save raw Vercel logs
   or request fields. Public activation is bounded to **two minutes maximum**;
   if cleanup cannot be prepared reliably, do not expose the origin.
5. In cleanup regardless of outcome, restore protection to
   `ssoProtection.deploymentType = all`, restore the previous deployment/alias
   if it was changed, and verify actual target/configuration through fresh API
   reads. Preserve the new immutable deployment and evidence; no extra public
   request to test protection. Report any cleanup failure immediately.
6. Stop after that one request. A 200/full-body/correlated-log result establishes
   only this canary's success, not reliable hosted stalls, cold-start behavior
   or origin suitability for Workers. Those still need separately approved
   full independent controls. A rejection is reported with its fixed code and
   remaining boundary; no automatic retry or second correction/deploy loop.

For example, after the separate approval and reviewed network preflight:

```text
python scripts/verify_vercel_origin.py --host ws-vpn-diag-origin-afef41e.vercel.app --ip <reviewed-IP> --experiment <fresh-stage>/experiment.json --cloudflare-ranges <reviewed-ranges.json> --output <new-private-evidence.json> --canary
```

This proposal authorizes nothing by itself. No new account, paid feature, DNS,
laptop exposure, environment upload, VPN secret or unrelated project change is
needed. The project's last verified protection was `all` at 2026-10-15
20:48:17 UTC; this turn has not queried or changed it.

Cloudflare resources were not accessed. The original standalone origin and
diagnostic Worker bundle remain unchanged (bundle SHA-256
`5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`).
Immutable Worker rollback `6a903b04-b90d-43f6-a9a6-4f6e129bbc4c` is retained.
PR #2 remains Draft/unmerged at `458e877`; its head is not changed by this branch.
No Windows firewall/routing, production VPN, relay or Android changes were made.
