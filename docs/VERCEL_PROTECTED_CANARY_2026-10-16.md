# Protected Vercel origin canary — one request passed, secrets revoked

**The single authorized synthetic request passed.** At 2026-10-16 08:45:45–46 UTC
(12:15:45–46 Asia/Tehran), the Windows laptop received HTTP 200, its matching ID
and all **180,000 verified synthetic bytes** in **1,664.909 ms**, within the
12-second deadline. Six matching origin events corroborate receipt and response
completion. No origin retry, unauthenticated probe or seven-case matrix ran.

The corrected adapter/configuration/staging source is unchanged from approved
commit `78d5f46`. Only the independent verifier gained environment/header-only
bypass support, with regression tests, in `17a5b0f`. The production VPN,
standalone origin, Worker and relay sources are unchanged.

## Exact protected infrastructure

| Item | Actual verified value |
| --- | --- |
| Owner/scope | `ihanemi` / `hanemi`; OWNER and account creator |
| Account ID | `team_rGnSqY0IkqM6gracJSAOzW50` |
| Project | `ws-vpn-diag-origin-afef41e`; `prj_5zg0OaiYqUemEvmM62FR1YVGXqqM` |
| Plan | Hobby; no upgrade, paid add-on or new project |
| New immutable preview | `dpl_QvuNXCnbwQkK4Kj4mj1VkWhf2JpA`; READY, non-production target; no aliases |
| Requested hostname/port | `ws-vpn-diag-origin-afef41e-d43yq57cx-hanemi.vercel.app:443` |
| Authentication | `ssoProtection.deploymentType = all` before deployment, before request, after cleanup and in a separate final reader |
| Existing production deployment | `dpl_8cuGnWLoCfQbvjUBCoMpANgGx2VM`; retained READY throughout |
| Existing aliases, unchanged | `ws-vpn-diag-origin-afef41e.vercel.app` and `ws-vpn-diag-origin-afef41e-hanemi.vercel.app` |
| Upload | Exactly four allowlisted input files, 7,256 bytes; CLI dry-run and SHA-256 manifest checked |
| Runtime | Node 24.x; `iad1`; existing resource configuration preserved |

The upload contained only `api/origin.mjs`, `package.json`, `vercel.json` and
generated `experiment.json`, with one new random admitted ID. No repository root,
VPN/Cloudflare credential, environment file or dependency directory was uploaded.
No production alias was assigned or moved. The preview and previous immutable
deployments are retained for review; they were not deleted.

The [official pricing table](https://vercel.com/docs/deployment-protection/usage-and-pricing)
lists Automation Bypass as included on Hobby without a separate protection
charge. Fresh API reads confirmed the actual account's Hobby plan. No invoice
audit is claimed.

Protection was verified through control-plane configuration and the preview's
exact project membership, not by a second unauthenticated HTTP request. The
experiment made **zero protection-setting writes** and never disabled or relaxed
Authentication. No empirical 401/redirect probe was added to the one-request budget.

## Direct network, TLS and response evidence

Fresh DNS, ARIN RDAP, RIPEstat AS ownership and Cloudflare published-range checks
verified these two addresses before the request:

| Address | Registered network | Announced owner | HTTPS used |
| --- | --- | --- | --- |
| `216.198.79.195` | VERCEL-05, `216.198.79.0/24` | AS16509, Amazon.com | **Yes; sole pinned peer** |
| `64.29.17.195` | VERCEL-12, `64.29.17.0/24` | AS16509, Amazon.com | No |

Both were public and outside Cloudflare's ranges, with no Cloudflare ownership
observed. The verifier connected directly to the first reviewed IP, sent the
immutable preview hostname as SNI/Host and strictly verified the TLS certificate.
No proxy, redirect, alternate-address retry, trust-store change or TLS-key logging
was used. This direct connection was the explicitly authorized origin diagnostic,
not a VPN fallback.

- TLS 1.3; peer `216.198.79.195`; SAN `*.vercel.app`.
- Google Trust Services / WR1; validity 2026-08-29 19:48:09 through
  2026-11-27 19:48:08 UTC.
- Certificate SHA-256:
  `8f46c4a0a289bfde4060d06986f2af761ee62d668dde972e6bef4687ee4f6093`.
- Correlation ID: `ef1e5477ba3a8fad564d17eaa3db9b88`; fixed `ok` path only.
- HTTP 200; matching echoed ID and `wsvpn-origin/2` source marker; no rejection code.
- `Content-Length: 180000`, identity encoding, no Transfer-Encoding;
  **180,000 body bytes**, each matching the fixed synthetic pattern.
- 180,543 total HTTP bytes; cache MISS, no-store, zero/absent Age.
- Total connection/request/response time 1,664.909 ms; full body received before
  closing locally. No request timeout occurred.

The filtered runtime query returned six records, no pagination and no excluded
interval. The CLI returns newest first; reconstructing by the origin's sequence:

| Sequence | Elapsed ms | Permitted event | Bytes / accumulated response bytes |
| --- | ---: | --- | --- |
| 1 | 0 | `origin.request.received` | 0 / 0 |
| 2 | 1 | `origin.request.complete` | 0 / 0 |
| 3 | 5 | `origin.response.queued` | 180000 / 0 |
| 4 | 8 | `origin.response.write_complete` | 180000 / 180000 |
| 5 | 9 | `origin.response.finish` | 0 / 180000 |
| 6 | 10 | `origin.close.complete` | 0 / 180000 |

All six match the single ID; there is one receipt and no rejection event.
The callback alone proves runtime acceptance; the independently verified client
body establishes that the full response also crossed the edge/network span in
this request. No raw platform logs, headers, payload contents or TLS secrets
were persisted.

## Dedicated bypass lifecycle and final verification

The supported mechanism was the project's
[`protection-bypass` API](https://vercel.com/docs/rest-api/projects/update-protection-bypass-for-automation)
and the recommended `x-vercel-protection-bypass` header. No query parameter,
bypass cookie or browser login was used. The bypass is project-scoped, not
preview-scoped; it was used only on the authorized immutable preview.

The preview was built **before** generating its bypass. Vercel generated the
secret, which stayed in the trial process's memory/environment and the encrypted
HTTPS header. API bodies containing it used process stdin, never command-line
arguments or files. CLI/API output was captured in memory and reduced to safe
metadata. No secret was printed, committed or uploaded in deployment inputs.

Vercel selected the temporary secret for its automatic system environment
variable on future builds. An optional attempt to deselect it was rejected;
no provider defect or precise reason is claimed. No build/redeploy occurred
while a secret existed, and API checks found no automation-secret environment
entry in the already immutable preview. The normal default mechanism was used
without claiming that the provider's selection flag was false.

After the request, revocation completed with regeneration disabled. A fresh
project read verified **zero bypass secrets**, matching the original empty set.
A separate process performed fresh user/team/project/production-alias/original-
deployment/preview reads at **08:47:03 UTC**. It confirmed:

- Hobby ownership, project protection `all` and selected configuration unchanged.
- Original production target and both old aliases retained; preview has no aliases.
- Zero project/shared environment entries, no Git integration and zero bypasses.
- Protected immutable preview retained and no runtime automation-secret entry.

No remaining credential requires manual revocation. If a later operation leaves
a credential, the owner can open this project's **Settings → Deployment
Protection → Protection Bypass for Automation**, revoke the entry labelled
`WSVPN protected origin canary 20261016 source 78d5f46`, and confirm absence in
a fresh project read. No additional public probe is necessary.

Preparation errors are preserved, rather than counted as application failures:
`--skip-domain` was rejected for a preview before deployment creation. Two custom
64-character secret generation attempts were rejected before credential creation;
the official schema requires 32 alphanumeric characters and says OAuth clients
should omit the custom value. Provider-generated credentials resolved that input
issue. One generated credential was revoked before any origin request after the
optional environment-selection operation failed; the separate credential used
for the actual canary was also revoked. Each cleanup read confirmed zero bypasses.
These control-plane preparation attempts did not send an origin request or retry
the canary. Original scripts/results are retained privately; Git contains only
sanitized evidence, never the generated secret values.

## Tests, limits and stop point

The verifier's five focused tests passed on Linux and Windows, including a real
local TLS request with the bypass header, wrong-host TLS failure, header-injection
rejection before socket creation, environment-only CLI intake, one-request
accounting and secret-free reports. Ruff and `git diff --check` passed. No new
full VPN suite, hosted CI run, Windows build or physical VPN/leak test is claimed.

[Structured results, six origin events, manifests and independent final state](test-results/vercel-protected-canary-2026-10-16.json)
are committed. Previous seven-400 evidence and the earlier cleanup-gated attempt
remain unchanged.

This establishes **one successful protected hosted request through the corrected
adapter**. It does not establish the exclusive cause of the seven historical
400s, controlled hosted stalls, concurrency, sustained/cold-start reliability,
Workers raw-TCP reachability or a fix for the original Cloudflare post-TLS stall.
The full origin qualification remains incomplete.

**Stop after this canary.** No seven-request matrix or Worker operation follows.
PR #2 remains Draft/unmerged at `458e877`. Immutable Worker rollback
`6a903b04-b90d-43f6-a9a6-4f6e129bbc4c` and diagnostic bundle SHA-256
`5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`
are preserved; no Cloudflare control-plane operation or Worker tail occurred.
