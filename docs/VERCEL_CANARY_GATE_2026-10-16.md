# Authorized canary: stopped before deployment at the cleanup gate

The owner authorized one fresh-ID `ok` request against the existing temporary
Vercel origin, from immutable source `78d5f46`, with a 12-second request deadline
and at most 120 seconds of public exposure. The authorization explicitly says:

> Prepare a reliable, independently enforceable cleanup mechanism before enabling public access. If cleanup cannot be assured, do not expose the project.

**Outcome: not run.** Independent cleanup was not verified with the available
execution contexts. No deployment, public reactivation or origin request occurred.
The corrected adapter's hosted acceptance remains unverified. This is a failed
precondition, not a new HTTP failure or a successful canary.

## Actual completed checks

The Windows diagnostic worktree was clean at
`78d5f46f100d8430abbb625f88763f5255e69099`. Existing source, evidence and rollback
artifacts were preserved. Two separate sets of authenticated API GETs checked
the user, team, project, alias and previous immutable deployment:

| Item | Freshly verified value |
| --- | --- |
| User | `ihanemi`; `LBDE7wqDFWomctJb4Yi6P9pY` |
| Scope | `hanemi`; `team_rGnSqY0IkqM6gracJSAOzW50`; OWNER and account creator |
| Plan | `hobby` |
| Project | `ws-vpn-diag-origin-afef41e`; `prj_5zg0OaiYqUemEvmM62FR1YVGXqqM` |
| Authentication | `ssoProtection.deploymentType = all` |
| Production target | `dpl_8cuGnWLoCfQbvjUBCoMpANgGx2VM`, READY |
| Primary alias | `ws-vpn-diag-origin-afef41e.vercel.app`, pointing to the previous deployment |
| Other retained alias | `ws-vpn-diag-origin-afef41e-hanemi.vercel.app` in that deployment's alias list |
| Runtime/settings | Node `24.x`, region `iad1`, existing resource/build settings preserved |
| Environment/Git link | Zero project/shared environment entries; no Git integration |
| Initial snapshot | 2026-10-16 08:21:54 UTC |
| Separate final snapshot | 2026-10-16 08:23:52 UTC |

Compared user/team/project settings/alias/deployment values are identical in
both snapshots. These are fresh control-plane reads, not public HTTP tests or a
claim that edge propagation was observed. No cleanup mutation was necessary:
the protected original state was never changed.

The canary staging command ran locally from the approved commit, producing only
`api/origin.mjs`, `package.json`, `vercel.json` and generated `experiment.json`.
A separate check verified the exact recursive four-file allowlist and every
SHA-256 against the outside-directory manifest. The experiment contains exactly
one valid random ID, different from the seven previous hosted IDs. It was never
uploaded or transmitted. Its expiry and hashes are preserved privately and in
the [sanitized evidence](test-results/vercel-canary-gated-2026-10-16.json).
The three source files are unchanged from the approved commit. No credential,
environment file, Worker source or unrelated repository file was staged.

## Why the cleanup gate did not pass

Desktop Commander reported one online device, the Windows laptop. The only
verified authenticated Vercel execution context is on that laptop. A detached
process or scheduled local task can survive interruption of the controller, but
shares the laptop's power and network failure domain. It cannot issue the
required protection/alias restoration API requests while that laptop is offline.
No independently authenticated external cleanup executor has been verified or
authorized for this experiment.

The reviewed [Vercel Authentication API documentation](https://vercel.com/docs/deployment-protection/methods-to-protect-deployments/vercel-authentication#how-to-manage-vercel-authentication-with-the-api)
and [project update schema](https://vercel.com/docs/rest-api/projects/update-an-existing-project)
describe changing `ssoProtection.deploymentType`; they did not provide a verified
120-second automatic re-protection mechanism for this run. This is a bounded
capability finding, not a claim that no other Vercel facility can exist.

The adapter's absolute experiment expiry is not a substitute: expiry rejects
requests inside the function; it does not restore Vercel Authentication or an
alias. The unchanged staging code's validity window is 20 minutes, also not a
120-second public-exposure bound. Merely shortening it would not restore the
control-plane state either. No speculative timer or untested watchdog was
presented as satisfying the owner's mandatory safeguard.

To proceed, first verify an approved cleanup executor independent of the laptop,
including secure Vercel authorization, bounded restoration and a no-exposure
rehearsal against the protected original state. No credentials were copied to an
external host, GitHub secret or deployed function to construct such an executor.
That additional setup is outside the currently verified scope. Alternatively,
the owner could separately approve a revised test which keeps Authentication
enabled throughout; that would differ from the current unauthenticated canary
and has not been substituted automatically. The existing canary authorization
does not need to be requested again unchanged.

## Actual results and preserved boundaries

- Origin deployments/uploads/configuration writes: **0**.
- Public origin requests: **0**; public exposure: **0 seconds**; no retries.
- TLS certificate, fresh DNS/IP ownership and functional 180,000-byte canary:
  **not tested in this attempt**, because the cleanup gate stopped execution.
- Origin runtime logs/tails: **not collected**; no request occurred.
- API GETs: **10**, across the two independent snapshots above.
- Local staging/allowlist/hash/fresh-ID checks: **passed**. Existing regression
  results remain those recorded at `78d5f46`; they were not relabelled as new tests.
- PR #2 freshly read as Draft/unmerged, head
  `458e87726fb63766cfb9c33ee80b6c1d306519fb`.
- No Cloudflare operation or tail. Immutable Worker rollback
  `6a903b04-b90d-43f6-a9a6-4f6e129bbc4c` and diagnostic bundle SHA-256
  `5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`
  remain preserved.
- No production VPN source, secrets, laptop networking, firewall, routing,
  billing, unrelated project or Android change.

The single-request budget was not consumed. No seven-request validation or
Worker experiment follows this report.
