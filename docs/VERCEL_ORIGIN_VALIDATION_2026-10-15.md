# Vercel origin-only trial — rejected; no Worker connection authorized

Seven independent requests ran on **2026-10-15 at 20:43:50–20:43:55 UTC**
(2026-10-16 at 00:13:50–00:13:55 Asia/Tehran). All seven verified TLS and then
received HTTP 400. **Zero functional controls passed.** The origin is not
accepted for the diagnostic Worker experiment. No eighth synthetic request,
payload replay, warm-up, Worker session, Worker upload/activation or Worker tail
was performed. The initial hosted source was not changed to hide the failures.

## Exact infrastructure and ownership

| Item | Verified value |
| --- | --- |
| Authenticated user | `ihanemi` |
| Account/scope | Hanemi / `hanemi`; `team_rGnSqY0IkqM6gracJSAOzW50`; user is OWNER and account creator |
| Plan/cost | Free Hobby, $0/month plan; unchanged after the trial. No paid upgrade/add-on, billing change or extra infrastructure. No invoice audit was performed. |
| New project only | `ws-vpn-diag-origin-afef41e`; `prj_5zg0OaiYqUemEvmM62FR1YVGXqqM` |
| Tested hostname/port | `ws-vpn-diag-origin-afef41e.vercel.app:443` |
| Immutable deployment | `dpl_8cuGnWLoCfQbvjUBCoMpANgGx2VM`; `ws-vpn-diag-origin-afef41e-aws4eny6b-hanemi.vercel.app` |
| Deployment/runtime | READY; Node `24.x`; function region `iad1` (Washington, D.C.). CLI target `production` refers only to this newly created temporary Vercel project, not any existing website or Cloudflare Worker. |
| Source | Original adapter `afef41e`; independent verifier `6b3077a` |
| Upload | Exactly four files, confirmed by the Vercel deployment log and private SHA-256 manifest: `api/origin.mjs`, `package.json`, `vercel.json`, generated `experiment.json`. |
| Secrets/integrations | No VPN/Cloudflare credentials, environment files, repository root or Git integration uploaded. Final metadata shows zero project/shared environment variables and no Git link. |

Fresh authenticated CLI/API reads verified the owner and free plan before work.
Only the new temporary project was configured for public access during the
trial. Existing Vercel projects and Cloudflare resources were not changed.

DNS resolved two public IPv4 addresses:

| Address | ARIN registered network | Announced prefix / operator |
| --- | --- | --- |
| `64.29.17.67` | `VERCEL-12`, `64.29.17.0–64.29.17.255` | `64.29.17.0/24`, AS16509, AMAZON-02 — Amazon.com, Inc. |
| `216.198.79.67` | `VERCEL-05`, `216.198.79.0–216.198.79.255` | `216.198.79.0/24`, AS16509, AMAZON-02 — Amazon.com, Inc. |

ARIN RDAP, RIPEstat routing/AS-holder data and Cloudflare's current published IP
ranges were checked independently. Both addresses are public and non-Cloudflare;
DNS was checked again before the matrix. No IPv6 address was returned by the
Windows lookup. Requests pinned **only `64.29.17.67`** with the hostname as SNI
and Host; no alternate-address retry or proxy/direct-fallback substitution.
The second address was checked for DNS/ownership eligibility, not HTTPS traffic.

This satisfies the public-address/port portion of Workers raw-TCP eligibility,
**not actual reachability from Workers**. No Worker-origin session was authorized
or attempted. Relevant primary records are linked in the structured evidence:
[ARIN](https://rdap.arin.net/registry/ip/64.29.17.67),
[RIPEstat](https://stat.ripe.net/data/network-info/data.json?resource=64.29.17.67),
[Cloudflare ranges](https://api.cloudflare.com/client/v4/ips) and
[Workers restrictions](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/#considerations).

## TLS and actual seven-request results

All seven used strict Python TLS verification on the Windows laptop, without
modifying its trust store, firewall, routing or system proxy settings:

- TLS 1.3; peer `64.29.17.67`; SAN `*.vercel.app`.
- Issuer Google Trust Services / WR1.
- Certificate valid 2026-08-29 19:48:09 UTC through 2026-11-27 19:48:08 UTC.
- Leaf SHA-256 `8f46c4a0a289bfde4060d06986f2af761ee62d668dde972e6bef4687ee4f6093`.

| Case | HTTP | Elapsed seconds | Result |
| --- | ---: | ---: | --- |
| First `ok`, without warm-up | 400 | 0.923 | Failed; no 180,000-byte response or echoed ID. |
| Second `ok` | 400 | 1.271 | Failed. |
| Third `ok` | 400 | 0.700 | Failed. |
| `stall-response` | 400 | 0.692 | Failed; immediate error response, not the 10-second empty-response control. |
| `stall-body` | 400 | 1.018 | Failed; no 1,024-byte synthetic partial response/control. |
| Concurrent `ok` A | 400 | 0.755 | Failed. |
| Concurrent `ok` B | 400 | 0.738 | Failed. |

Each received 374 HTTP wire bytes. The replies used chunked transfer encoding;
the verifier's original `body_bytes: 5` field is a **raw post-header wire count**,
not five decoded payload bytes or verified synthetic data. Do not count it as
application-body delivery. No response content was logged. Verified synthetic
payload delivery is zero. Cache metadata was MISS, no-store, identity encoding
and zero/absent Age for every reply; there is no observed cache HIT. The original
verifier records are preserved without rewriting the failed outcomes.

## Failure boundary and limits of the diagnosis

The bounded, deployment-scoped Vercel CDN metadata query contains the seven
diagnostic GETs, mapped to `/api/origin`, each with HTTP 400 and cache MISS.
A filtered runtime query returned zero `wsvpn-diag/1` events, no pagination and
no excluded interval reported. The source emits its first accepted-session
marker **after request validation**, so marker absence cannot prove the function
was never invoked. The observed boundary is **verified TLS → Vercel function
route → HTTP 400 before any accepted-session evidence**, not the original
Cloudflare post-TLS response stall.

The adapter's request-shape validation/integration is a suspect, supported by
the route and no-store error responses. **The specific failed predicate is not
established.** Do not claim a rewrite/header/body-framing root cause or weaken
validation without evidence. No forwarding fix was made. This trial also does
not establish that Vercel inherently cannot stream these controls.

The CDN query additionally returned five earlier, nondiagnostic HTTP 404 records
during the deployment window. These are retained as separate counts, not added
to the seven-request matrix or attributed to an actor without evidence. No
extra client warm-up/probe request was sent by the verifier.

Because all controls were rejected, hosted response buffering, healthy cold-start
behavior, correlation-ID echo and receipt-versus-response-byte instrumentation
remain **unverified**. Function write callbacks would in any case prove runtime
acceptance rather than Vercel edge transmission. The current origin does not
provide sufficiently reliable evidence for the Worker experiment.

## Cleanup, preserved state and remaining gate

After collecting evidence, the new project's Vercel Authentication was set to
protect **all** deployments. A separate API read at **20:48:17 UTC** verified
`ssoProtection.deploymentType = all`, the same project/account, free Hobby,
Node 24, no environment variables/shared variables and no Git link. No eighth
HTTP request was sent to check the protection externally; this is verified
configuration state, not a new functional HTTP test. The seven-ID configuration
also has an absolute expiry of **21:02:31 UTC**. No reactivation is authorized.
The project/deployment and evidence were retained for review, not deleted.

The original standalone origin and diagnostic Worker bundle are unchanged:
`5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`.
The preserved Worker rollback remains `6a903b04-b90d-43f6-a9a6-4f6e129bbc4c`;
no Worker control plane, deployment or live tail was used. PR #2 is still Draft
at `458e877` and is not merged. Existing laptop worktrees/untracked vendor and
license files were preserved. No physical VPN/leak validation is claimed.

The new independent verifier and interference/certificate tests passed **2/2 on
Linux and 2/2 on Windows**; Linux Ruff passed. Existing Node adapter/full-suite
passes are the previous preparation results, not a new hosted-Vercel pass.
Three preparation issues were recorded separately: the create API rejected an
unsupported `nodeVersion` field before creating a project; `npx.cmd` mishandled
an ampersand in a lookup argument; and PowerShell treated test stderr as an error.
The supported minimal create body and pinned Node CLI entry point/process
redirection resolved those harness issues. They do not explain away the seven
real HTTP 400 failures.

[Structured results, sanitized counters/metadata, certificates and artifact hashes](test-results/vercel-origin-live-2026-10-15.json)
are committed; original local evidence, failed preparation requests and logs
remain in the private laptop setup directory. No credentials or payloads are in Git.

**Stop here.** First identify the adapter's exact rejection condition using a
bounded, reviewed origin-only diagnostic change. Any reactivation/new public
request batch needs separate bounded approval; the original seven-request budget
is exhausted. Do not connect or request deployment of the diagnostic Worker
against this failed origin. A later Worker experiment still requires a suitable
independently validated origin and separate authorization, with the existing
14-session/four-minute/unconditional-rollback limits preserved.
