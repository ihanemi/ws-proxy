# Post-TLS transport diagnosis — bounded, unresolved

Continuation of [PR #2 live validation](PR2_LIVE_VALIDATION_2026-10-15.md),
starting at `7231be7`. No Worker upload, activation, rollback, configuration
write, routing/firewall change or Android work occurred during this investigation.
The restored Worker is still `6a903b04-b90d-43f6-a9a6-4f6e129bbc4c`.

## Baseline with the original client

The physical Windows laptop ran the preserved original CI EXE from `9583b21`:
SHA-256 `609187360943cb8dc159d42b6f2e23e2dbfe2f88d43eb205c134581e15645700`.
It used the existing DPAPI-backed token and an isolated loopback SOCKS listener.
No default configuration or shortcut was replaced. The listener alone was not
treated as readiness; actual DNS and tunneled HTTPS were tested.

Three sequential DNS queries succeeded (0.75, 0.64 and 0.57 seconds). All three
HTTPS attempts verified Google's TLS 1.3 certificate, then ended with no HTTP
response bytes after 10.62, 13.07 and 10.58 seconds. These were empty-response
assertions, not all timeout exceptions. The original EXE remained alive and
its exact test processes were subsequently stopped.

This reproduces application failure with the original Worker/client pair.
It rules out a failure unique to `echo-v1`; it does not prove that PR #2 has
no additional regressions, or that the old service has recovered.

## Last observed progress on the live path

The original Python core was exported from Git revision `9583b21` to a separate
private test directory. No checkout/reset or tracked source replacement was
used. Windows Python 3.13 drove verified TLS with `SSLObject`/`MemoryBIO` over
that original transport. This source trace is distinct from the original
packaged EXE baseline above.

Only event order, elapsed time, encrypted byte counts, control-frame counts and
response byte counts were retained. No token, credential, TLS key material,
HTTP content or decrypted response was logged. Each session sent one synthetic
request; application payload was never retried on another session.

One reproducible failure sequence on pinned address `172.67.198.140` was:

1. READY arrived and TLS 1.3 certificate verification completed.
2. TLS Finished generated 80 encrypted bytes, sent in an 81-byte DATA frame.
3. The synthetic 59-byte HTTP request generated 81 encrypted bytes, sent in an
   82-byte DATA frame. The WebSocket send coroutine completed.
4. No later WebSocket DATA or TCP EOF arrived within the six-second receive
   deadline. A separate Microsoft-target trace also stalled after verified TLS
   and an 85-byte outgoing DATA frame.

**Send completion means the client accepted/flushed its write; it does not
prove that the live Worker received it or that the destination read it.**
The unobserved span remains client network/edge, Worker message reception,
Worker TCP write, origin handling, Worker TCP read and Worker WebSocket send.
Those live server boundaries cannot be distinguished by client counters alone.

There were also failures before the TLS response and successful response
fragments on fresh legacy sessions. In an alternating six-session matrix on
the same pinned address, ACK-enabled sessions returned application bytes 1/3
times; legacy no-ACK sessions did so 2/3 times. Both modes failed at least once.
These small samples implicate neither ACK nor a permanently bad address as a
confirmed root cause. They do not justify disabling backpressure. A later
trace using the PR's current Python core with the explicit legacy contract and
ACK received a verified HTTP response fragment in 1.23 seconds.

Thus the service is intermittent within this bounded observation window, while
the original EXE's three samples all failed. Successful first fragments do not
establish a complete download, sustained reliability or system-wide VPN health.

[Structured baseline and event sequences](test-results/pr2-transport-diagnosis-2026-10-15.json)
retain every sampled failure and success; original private laptop logs remain
unchanged. Earlier Cloudflare `loadShed` observations are not evidence of the
cause of these particular failures.

## Local reproduction and code inspection

`worker/test/tcp-runtime.test.js` now exercises the production handler/session
inside actual workerd, real network WebSocket frames, `cloudflare:sockets`, a
real TCP connection and a local HTTPS origin with an ephemeral trusted CA.
Only the test entry point maps the validated destination to the local origin;
production destination validation is unchanged. All four combinations of
legacy/`echo-v1` and no-ACK/ACK deliver a complete verified 180,000-byte response.
This crosses multiple downstream frames and ACK cycles.

`tests/test_vpn_worker_runtime.py` additionally exercises the actual Python
SOCKS handler and WSS transport through workerd to that real HTTPS origin. The
positive test verifies the entire response and origin-side request/response
counters. A negative control has the origin receive the request but withhold
its response: TLS passes, HTTP times out, the origin request count is one and
the response count is zero. This validates diagnostic discrimination; it is
an intentional stall, not reproduction of the unknown live defect.

Inspection confirmed that Python's paired bridge retains the other direction
after normal EOF, and Worker writes remain serialized with bounded input
queues. The Worker read pump awaits each negotiated ACK before the next DATA
frame; EOF and cancellation paths retain their existing semantics. The PR's
Worker source difference is the negotiation/challenge gate, not a replacement
of these forwarding paths. These observations and passing local tests do not
exclude a timing-dependent or Cloudflare-only failure.

Actual checks after adding coverage:

| Environment | Result |
| --- | --- |
| Linux Python VPN tests, runtime integration enabled | 89 run, 4 Windows-only skips, no failures |
| Physical Windows Python 3.13, runtime integration enabled | 89 run, no skips or failures |
| Worker tests on Linux and physical Windows | 28/28 passed on each |
| Ruff, including the new trace tool | Passed |
| Trace tool against a real silent local WSS endpoint | Overall 0.2 s deadline enforced in 0.201 s |

VPN CI now runs the Python/workerd integration explicitly in addition to the
Node tests. [Hosted VPN CI](https://github.com/ihanemi/ws-proxy/actions/runs/38780924809)
passed for the coverage commit `7fe09b0`. Opt-in setup requires Python 3.11+, Node 24, `npm ci --ignore-scripts` in
`worker/`, and
OpenSSL on the test process PATH:

```bash
WSVPN_WORKER_RUNTIME_TESTS=1 python -m unittest tests.test_vpn_worker_runtime -v
```

The reusable `scripts/trace_vpn_https.py` performs one synthetic request with an
overall deadline of at most 30 seconds. It requires explicit contract and flow
control selections, a pinned Worker IPv4 address, a token supplied securely in
the process environment and a new output filename. It never overwrites evidence.
Example with the existing restored Worker and already loaded secret:

```bash
python scripts/trace_vpn_https.py --relay "$TEST_RELAY" --ip 172.67.198.140 --contract legacy --flow-control ack-v1 --timeout 8 --output new-trace.json
```

Do not place the VPN secret in command arguments or shell history. The tool
checks only the first HTTP response fragment, not full transfer or health.
Selecting the legacy contract is an explicit diagnostic experiment, not a
fallback in the application. The new EXE still requires `echo-v1`.

## Root cause and fix status

**The internal root cause is not established.** No confirmed production-code
defect was reproduced locally. No change to TCP forwarding, ACK behavior,
protocol negotiation, retries or security policy is justified by this evidence.
Only diagnostic tooling, real integration coverage and CI were implemented.

Before another live deployment is requested, prepare and locally validate a
separate, reviewable diagnostic build with per-session counters for Worker
message reception, TCP write completion, TCP read completion, WebSocket send,
ACK and close reason. It must record only counts/sequences, use a synthetic
controlled origin where request receipt can be verified, and preserve the
current immutable version, secret and configuration. This investigation neither
deploys that instrumentation nor requests authorization for it yet.

PR #2 remains draft and unmerged. No stable release, full VPN health or leak
protection is claimed. Physical routing/firewall security gates remain open.
