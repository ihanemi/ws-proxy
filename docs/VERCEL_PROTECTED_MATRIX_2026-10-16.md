# Protected seven-request qualification — 5 passed, 2 failed; origin not qualified

Continued from successful canary `aa8e84e` under separate authorization for one
seven-request matrix. Exactly seven fresh-ID requests ran from Windows on
2026-10-16 **11:25:26–11:25:53 UTC** (14:55:26–14:55:53 Asia/Tehran). All five
healthy controls passed, including both concurrent requests. Both intentional
stall controls failed. **This Vercel origin is not sufficiently reliable for the
complete future Worker diagnostic experiment.** No Worker operation follows.

## Individual client results

IDs below are abbreviated only for readability; the
[structured evidence](test-results/vercel-protected-matrix-2026-10-16.json)
contains all seven complete correlation IDs, TLS details, read timestamps,
byte counts, origin events and final API snapshots.

| Case | ID prefix | Mode | HTTP | Body bytes received | Elapsed ms | Result |
| --- | --- | --- | ---: | ---: | ---: | --- |
| 1 | `14c51cfe` | Sequential `ok` | 200 | 180000 | 1084.731 | Pass |
| 2 | `d8282041` | Sequential `ok` | 200 | 180000 | 1206.044 | Pass |
| 3 | `090b1c57` | Sequential `ok` | 200 | 180000 | 1139.958 | Pass |
| 4 | `167d5580` | `stall-response` | 500 | 96, error response | 10805.709 | **Fail: substituted response** |
| 5 | `268ae4a3` | `stall-body` | 200 | 0 | 12003.361 | **Fail: partial body missing, timeout** |
| 6 | `38f888ab` | Concurrent `ok` A | 200 | 180000 | 1273.452 | Pass |
| 7 | `810f1477` | Concurrent `ok` B | 200 | 180000 | 1218.502 | Pass |

Every request verified TLS 1.3, the exact immutable preview hostname and the same
pinned public peer. Every healthy response matched its ID and source marker,
verified all 180,000 synthetic bytes, retained identity encoding and declared
length, had no Transfer-Encoding, and reported cache MISS/no-store/zero-or-absent
Age. Total verified healthy payload was **900,000 bytes**. These are full-body
successes, not TLS-handshake-only passes.

Measured request intervals show the first five were sequential. The last two
overlapped, with maximum observed concurrency **2**. They began at matrix offsets
26244.230 and 26244.482 ms and finished at 27518.610 and 27464.078 ms. There were
no warm-ups, redirects, alternate-address attempts, retries or added batches.

The I/O deadline was configured as 12 seconds for every request. The partial
stall's recorded wall time was **12003.361 ms**, 3.361 ms beyond that value,
including timeout handling, socket closure and measurement overhead. This
overrun is preserved, not rounded into a strict sub-12-second result. No deadline
extension was configured; that control remains failed.

## What the stalled controls actually establish

The adapter and expectations are unchanged from the accepted source:
`stall-response` must send no HTTP bytes; `stall-body` must deliver 1,024 early
synthetic bytes, then remain incomplete. Both destroy the response after about
10 seconds. A replacement error page, missing/late partial bytes or incomplete
correlation is not accepted as a pass.

For **`stall-response`**, the origin recorded request receipt/completion and its
deadline at **10001 ms**, with zero response bytes accepted. It subsequently
recorded `origin.request.error` at 10003 ms. The client instead received HTTP 500
and a 96-byte non-synthetic error response after 10.806 seconds; source/ID markers
and no-store were absent. The adapter's stall branch does not generate that
status/body. This is response substitution outside the intended origin behavior,
not a successful empty stall. Its contents were not saved.

For **`stall-body`**, the origin queued 1,024 bytes at 0 ms and its write callback
accepted them at **1 ms**. Its deadline occurred at **10000 ms**, followed by
`origin.request.error` at 10001 ms. The client saw only 543 HTTP header bytes at
**10956.421 ms** from connection start, including the correct ID/source marker,
HTTP 200 and declared length 180000. It received **zero body bytes** before its
timeout. There was no early partial response to validate, so this is a failure.

That observed boundary is **runtime callback accepted 1,024 bytes → no client
body before the deadline**, with delayed header visibility. It is consistent
with buffering/abort/forwarding interference in the hosted path, but a Node
write callback cannot prove edge TCP transmission. The exact internal queue,
drop point or buffering mechanism is unresolved. No unsupported attribution to
the original Cloudflare transport failure is made.

## Actual sanitized origin evidence

The one deployment-scoped, filtered runtime query returned 40 records, no
pagination and no excluded interval. The sanitizer retained 40 permitted events
for the seven admitted IDs and no rejection records. Every ID has exactly one
receipt. The five healthy sessions each have sequences 1–6, 180,000 write-callback
bytes, response finish and complete close.

| Session group | Receipts | Runtime write-callback bytes | Deadlines | Complete closes |
| --- | ---: | ---: | ---: | ---: |
| Five healthy IDs | 5 | 900000 | 0 | 5 |
| Empty stall | 1 | 0 | 1 | 0 observed |
| Partial stall | 1 | 1024 | 1 | 0 observed |

The empty-stall records contain sequences **1,2,3,6**; the partial-stall records
contain **1,2,3,4,5,8**. Sequences 4–5 and 6–7 respectively are missing from the
retained records, and no deadline-close event was observed for either stall.
No complete lifecycle is inferred from the query's pagination summary. The
reason for those gaps was not investigated with another batch or raw logging.
The actual records are preserved newest-first; analysis uses sequence numbers.

## Exact deployment, address eligibility and credential cleanup

| Item | Verified value |
| --- | --- |
| Account | `ihanemi`, OWNER/creator of `hanemi`, `team_rGnSqY0IkqM6gracJSAOzW50` |
| Plan/project | Hobby; existing `ws-vpn-diag-origin-afef41e`, `prj_5zg0OaiYqUemEvmM62FR1YVGXqqM` |
| New immutable preview | `dpl_HhdK7ikrNGkD5RfBgysN3GTggtLm`; READY, non-production, no aliases |
| Hostname/port | `ws-vpn-diag-origin-afef41e-mtxd9rmt9-hanemi.vercel.app:443` |
| Sole pinned HTTPS peer | `216.198.79.3`; VERCEL-05, `216.198.79.0/24`, AS16509 Amazon.com |
| Other DNS address, not probed | `64.29.17.3`; VERCEL-12, `64.29.17.0/24`, AS16509 Amazon.com |
| Protection | `ssoProtection.deploymentType = all` throughout; no protection-setting writes |
| Original production deployment | `dpl_8cuGnWLoCfQbvjUBCoMpANgGx2VM`, retained READY |
| Original aliases, unchanged | `ws-vpn-diag-origin-afef41e.vercel.app`, `ws-vpn-diag-origin-afef41e-hanemi.vercel.app` |
| Independent final API read | 2026-10-16 **11:27:22 UTC**; matches predeployment state, zero bypasses |

Fresh DNS, ARIN RDAP, RIPEstat network/AS ownership and Cloudflare published-range
reads verified both addresses as public/non-Cloudflare before the matrix. Only
the pinned peer was used for HTTPS, with the preview hostname as SNI/Host and
strict certificate verification. No proxy or direct VPN fallback was involved.
TLS issuer was Google Trust Services WR1, SAN `*.vercel.app`, valid 2026-08-29
through 2026-11-27, leaf SHA-256
`8f46c4a0a289bfde4060d06986f2af761ee62d668dde972e6bef4687ee4f6093`.
This does not test reachability from Workers.

Exactly four files were staged, hashed and confirmed by CLI dry-run:
`api/origin.mjs`, `package.json`, `vercel.json`, `experiment.json`. Seven random
unique IDs were checked against retained earlier experiments and used only once.
The origin's three source/config files remain byte-identical to `78d5f46`.

The preview was built before generating its dedicated project-scoped automation
bypass. The supported API generated the secret; it was used only in process
memory/environment, API stdin and the encrypted HTTPS bypass header, never argv,
URLs, logs, Git or deployment inputs. No build occurred while it existed. The
provider's default future-build environment selection was not mistaken for a
secret in the already immutable preview; the preview environment entry was absent.

Revocation completed with regeneration disabled. Its fresh readback and a
separate final process verified zero remaining bypasses, unchanged `all`
protection, original target/aliases, selected configuration and Hobby ownership.
There were zero project/shared environment entries and no Git integration.
Authentication was checked through configuration, not an extra unauthenticated
probe. No production alias or protection rollback was needed because neither
was changed. Both new and previous immutable deployments and reports are retained.

[Automation Bypass is included on Hobby](https://vercel.com/docs/deployment-protection/usage-and-pricing);
no paid feature, billing upgrade, new project or unrelated resource was enabled.
No invoice audit is claimed. No credential remains for manual revocation.

## Local changes, checks and stop point

The independent diagnostic verifier now accepts its environment-only bypass in
the fixed seven-case matrix, retains failed controls without retries and records
request start/finish offsets. No origin behavior, acceptance criteria, production
VPN/Worker/relay code or system networking was changed. The runner change is
`ebae4a7`; `af487db` makes test pairing lengths explicit for lint.

Six focused verifier tests passed on Linux and Windows, including exact request
count/order, a barrier-verified concurrency ceiling of two, bypass privacy, real
TLS and malformed/proxy response rejection. Windows Ruff passed after correcting
two `zip` strictness findings; Ruff was unavailable in the current Linux runtime.
JSON parsing and `git diff --check` passed. No new full VPN suite, hosted CI run,
Windows build or physical VPN/leak validation is claimed. The live matrix process
exited **1** because controls failed; the PowerShell wrapper printed that code
and itself exited 0. The matrix is not reported as successful from wrapper status.

**Qualification verdict: rejected for the complete diagnostic experiment.** Five
healthy streams/concurrency worked, but empty/partial stall behavior and their
complete lifecycle evidence were not faithfully preserved. Those are required
controls for distinguishing Worker failure from origin/platform interference.
No speculative origin fix, changed expectation, retry or extra probe follows.
Future Worker work requires separate authorization and an independently qualified
origin/experiment; the current seven-request budget is exhausted.

PR #2 remains Draft/unmerged at `458e877`; no Worker deployment, activation,
modification or tail occurred. Preserved Worker rollback is
`6a903b04-b90d-43f6-a9a6-4f6e129bbc4c`; diagnostic bundle SHA-256 remains
`5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`.
