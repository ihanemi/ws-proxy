# Public diagnostic origin prerequisite — blocked, no deployment authorized

**Latest outcome:** the [separately authorized Vercel origin trial](VERCEL_ORIGIN_VALIDATION_2026-10-15.md)
established the public hostname/IP/TLS/ownership, but all seven requests returned
HTTP 400. The origin remains unsuitable and is protected pending review. No
Worker deployment or connection is authorized. The assessment below is historical.

**Follow-up:** the owner subsequently authorized preparation and independent
testing of a temporary user-owned Vercel Hobby origin only. The
[adapter implementation and current authentication blocker](VERCEL_ORIGIN_PREPARATION_2026-10-15.md)
supersede this assessment's origin-setup authorization status. No Cloudflare
Worker operation is authorized; exact public origin identity remains pending.

Assessment date: 2026-10-15. This supplements
[the prepared experiment](DIAGNOSTIC_EXPERIMENT.md); it does not authorize it.
PR #2 remains Draft at `458e877`. No public origin or Worker was deployed,
and no account, firewall, DNS, billing or routing setting was changed.

## Existing-host assessment

No suitable **existing authorized server was identified** in this project's
deployment examples, reports, prior project context or the two Windows VPN
profiles. The examples contain placeholders, not an operational relay.
Both profiles select the Cloudflare backend and the existing test Worker's
hostname. This finding does not establish that the owner has no other servers;
no unrelated hosts, SSH credentials or personal domains were inventoried/probed.

The diagnostic worktree was clean at `4157201` before this documentation-only
update. The original laptop worktree remains on
`fix/cloudflare-transport-timeouts` with its existing untracked `vendor/` and
Wintun license preserved. The Linux and Windows diagnostic bundles still have
SHA-256 `5095703c896769faab7cd3b90151dbbd217b86b1723086659b83bb6ed3901960`.
Existing test results and credentials were not modified. The preserved rollback
target remains `6a903b04-b90d-43f6-a9a6-4f6e129bbc4c`; no live Cloudflare state
was queried or changed in this prerequisite assessment.

## Proposed alternative if no existing host is supplied

The simplest candidate is a **temporary Vercel Hobby project owned by the user**,
using its assigned `*.vercel.app` hostname and managed HTTPS on **TCP 443**.
No custom domain, DNS change, laptop listener or purchased VM is proposed.
This is a candidate, not an approved/verified origin.

| Approval detail | Current state |
| --- | --- |
| Exact hostname | Not assigned; no project has been created. A suggested project name is not a reserved hostname. |
| Public IP / network owner | Unknown until the assigned hostname is resolved and its actual network ownership checked. Must be public and non-Cloudflare. Do not substitute the example IP in provider documentation. |
| Port | Proposed external TCP 443; not approved yet. No laptop/firewall port opening. |
| TLS | Proposed provider-managed certificate, strict hostname/chain/expiry verification; exact certificate and negotiated TLS version pending. TLS terminates at the provider edge. |
| Resource ownership | Must be the user's confirmed Vercel account/project; none has been identified or accessed. |
| Cost | Hobby is advertised at $0/month, for personal non-commercial use within quotas. No Pro/trial/add-ons/payment-method changes are proposed. Stop if registration requires a paid commitment. |
| Registration | A Vercel account is required; user registration or explicit authorization for account creation is required if none exists. Do not request a password/token in chat. |
| Current verification | **NOT RUN: no controlled public endpoint exists.** Provider documentation/homepage responses are not synthetic-origin validation. |

Vercel Functions support streaming and the current Hobby function-duration limit
is 300 seconds, longer than our 10-second stall controls. However, this platform
adds a TLS/HTTP proxy and function lifecycle. App write completion proves only
acceptance by that runtime, not delivery from its edge to the Worker. Buffering,
cold starts, cache/security challenges and platform error responses can invalidate
the controls. One-hour Hobby runtime-log retention requires prompt sanitized
capture. A small isolated function adapter would be needed: the existing
standalone `https.createServer` origin is **not** a drop-in Vercel Function.
The adapter has not been implemented or validated for this unselected platform.
Preserve the existing direct-TLS origin and Worker bundle unchanged.

Render was considered and rejected: its official documentation states that web
services use Cloudflare DDoS protection, conflicting with this experiment's
non-Cloudflare destination requirement. Cloud Run is a possible managed-HTTPS
fallback, but requires a Google Cloud billing account even for its free allowance;
it is not an unconditional zero-cost alternative. No such resources were created.

Official references checked on the assessment date:

- [Vercel pricing](https://vercel.com/pricing) and [Hobby limits/eligibility/log retention](https://vercel.com/docs/plans/hobby).
- [Vercel account setup](https://vercel.com/docs/getting-started-with-vercel), [SSL](https://vercel.com/docs/domains/working-with-ssl), [streaming](https://vercel.com/docs/functions/streaming-functions) and [actual project DNS values versus examples](https://vercel.com/docs/domains).
- [Render protection](https://render.com/docs/ddos-protection).
- [Google free-tier billing prerequisite](https://docs.cloud.google.com/free/docs/free-cloud-features) and [Cloud Run pricing](https://cloud.google.com/run/pricing).
- [Workers raw TCP destination restrictions](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/#considerations).

## Staged execution and approval gates

1. **Host/setup decision, pending:** the owner supplies an existing authorized
   public server and its permitted TLS port, or explicitly authorizes a temporary
   origin-only project in a specified user-owned Vercel Hobby account (and account
   registration separately if needed). That permission would not authorize any
   Worker upload, activation or tail. No deployment is authorized now.
2. **Prepare only the selected origin:** for an existing host, reuse the original
   bounded direct-TLS service without altering its production HTTPS listener.
   For Vercel, locally validate an isolated adapter with the same synthetic routes,
   ID-only counters, 180,000-byte body and 10-second controls before its separately
   authorized origin deployment. Keep VPN secrets out of the origin. Restrict
   accepted IDs to the experiment's fresh IDs and use an absolute expiry; do not
   claim process-local quotas are global serverless limits. Do not enable paid
   features or import/deploy the entire VPN repository automatically.
3. **Independent verification, before origin approval:** record the actual
   hostname, every current A/AAAA result, UTC timestamp, provider/network
   ownership, owner/account confirmation, plan and expected cost. Check public
   address eligibility and Cloudflare's published ranges plus routing/ownership
   evidence; unresolved ownership fails the prerequisite. Freeze the selected
   address(es) and use a normal direct HTTPS socket with that IP, the exact
   hostname as SNI/Host, normal certificate verification and a 12-second deadline.
   No VPN token, test Worker, system proxy/routing change or fallback is involved.
4. Use at most **seven independent synthetic requests** with fresh IDs: three
   consecutive complete `ok` responses, one `stall-response`, one `stall-body`,
   and two concurrent `ok` responses. Verify HTTP/1.1 status, echoed ID, declared
   length and all 180,000 fixed body bytes for success. Verify no response for the
   first stall and exactly 1,024 body bytes for the partial stall, then bounded
   close/timeout. Match origin receipt/write/close counters to each ID. Record
   actual peer IP, certificate issuer/SAN/validity, TLS version, byte counts,
   relative event times and outcome, without payloads/credentials/raw headers.
   Reject redirects, authentication walls, caching, proxy-generated responses,
   missing logs, unexpected buffering or cold-start failures. Do not silently
   widen the request budget; report failures. An independent successful request
   proves that path only, not Worker reachability.
5. **Origin approval, pending:** present the now-exact hostname/IP/443/TLS,
   ownership, costs, adapter revision (if any), independent results and limitations
   to the user. Wait for their separate approval of that exact origin. Re-resolve
   and revalidate if its address/certificate changes; no silent target substitution.
6. **Final Worker authorization, not requested yet:** only after step 5, request
   the bounded experiment below. Any missing prerequisite stops here.

## Final Worker plan, conditional on both later approvals

Only `ws-vpn-laptop-9583b21` in account
`f97e1b7fd6a5f23a1ffb8c4f0450c58e`, using the exact private configuration,
reviewed bundle and unchanged credentials/bindings/plan/routes. Confirm current
active immutable version and configuration against the preserved baseline before
uploading anything. An unexpected version/configuration stops the experiment.

Use the existing 12 sequential sessions (two pinned Worker IPv4 addresses × two
contracts × three origin modes), then at most two concurrent successful controls:
**14 sessions maximum**, ACK enabled, fresh correlation IDs, no payload replay.
If no healthy address passes, omit concurrency. Request deadlines are 12 seconds;
matrix deadline is 180 seconds. Capture only sanitized, ID-filtered diagnostic
events with the prepared bounded collector. No raw tail or ordinary user traffic.

Activation lasts **at most four minutes**, including rollback. Start rollback no
later than 210 seconds, earlier on any unexpected failure, telemetry loss or
deadline. Use the preserved immutable version regardless of test outcome:

```text
versions deploy 6a903b04-b90d-43f6-a9a6-4f6e129bbc4c@100 --config <exact-private-config> --yes
```

The pinned CLI, upload/activation commands and invariant checks are in
[the original runbook](DIAGNOSTIC_EXPERIMENT.md#exact-deployment-and-rollback-requirements--future-authorized-step-only).
Require a functioning rollback control channel; never claim an absolute time
guarantee if the provider API fails. Independently read back the actual active
version at 100% and all preserved settings/bindings after rollback; stop owned
collectors/origin as approved and retain sanitized evidence. Distinguish verified
configuration restoration from functional legacy health. A failed rollback or
verification is a reported failure, not a pass. Retain prior versions, client,
logs and bundles. PR #2 stays Draft and unmerged.

**Current result:** host discovery completed within project scope; a conditional
free candidate and execution gates are documented. Public origin identity,
non-Cloudflare IP ownership, TLS and synthetic functionality remain blocked on
the owner's existing-host details or explicit origin-setup authorization. No
Worker deployment approval is being requested at this stage.
