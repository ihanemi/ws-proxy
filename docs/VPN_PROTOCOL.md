# WSVPN/1

Client and relay must be upgraded together. Pre-audit clients, relays and the
experimental Worker are incompatible. There is no insecure legacy fallback.

TLS certificate/hostname verification is mandatory. HTTP Upgrade requests use
`Authorization: Bearer ...` and `Sec-WebSocket-Protocol: wsvpn.v1`. The relay
checks authentication, path and version before upgrading; wrong credentials
return 401, an unsupported version returns 426, invalid destinations return
400. `/tunnel` takes exactly one `X-Tunnel-Host` and `X-Tunnel-Port`; `/udp`
uses destinations inside each datagram. An authenticated `/probe` upgrade sends
READY, echoes one 32-byte DATA challenge, and closes without opening an egress
socket. Reverse proxies must strip any path prefix before forwarding. Do not put
credentials in URLs or access logs.

After upgrading, the server sends binary `03` only when the outbound TCP
connection is open, or UDP sockets are available. The client must receive it
before replying successfully to SOCKS. Failure closes the WebSocket; it never
sends an application-ready indication. This proves a per-flow relay socket is
ready, not that the complete Windows VPN is healthy.

TCP binary messages start with `01`, followed by 0..262144 payload bytes.
A binary message consisting of `02` signals TCP write EOF. The opposite
stream stays open until it also reaches EOF. Unknown types and text messages
are errors. Connection loss before EOF is an error, not successful completion.

UDP messages keep the version-1 datagram encoding: version (1 byte), SOCKS
address type (1 byte), address (4 or 16 bytes, or 1-byte length and ASCII/IDNA
hostname), big-endian port (2 bytes), payload (at most 65507 bytes). Destinations
are at most 253 characters; scopes, control characters and invalid DNS labels
are rejected. Fragmented SOCKS UDP datagrams are rejected.

Both endpoints disable compression, cap each reassembled WebSocket message
at 262145 bytes, and bound receive queues. The mature WebSocket implementation
validates masking, RSV bits, opcodes and fragmentation. The local UDP send
queue holds at most 16 packets and drops overflow. Relay associations cap
cached targets and allowed response endpoints at 256, expire them after 60
seconds and rate-limit each direction to 1000 packets / 1 MiB per second.
Authenticated transport sessions, including incomplete HTTP handshakes, are
limited to 256 globally and 128 per socket peer. A reverse proxy's clients
share its peer limit; forwarded address headers are not trusted.

DNS resolution and outbound connect have a combined 10-second deadline.
TCP idle timeout is 300 seconds (activity in either direction); UDP idle
is 120 seconds. Cleanup joins child tasks and closes sockets. A relay only
connects to validated numeric public addresses; mixed private/public DNS
answers and transition IPv6 destinations are rejected. Port 25 is blocked.
TLS SNI and the HTTP Host retain the configured relay hostname while the
client can connect to a fixed IPv4 endpoint. Automatic system proxy detection
is disabled so the transport cannot silently take another path.

## Cloudflare profile extensions

`/tunnel` and `/probe` retain the base wire contract above. Worker sockets use
`allowHalfOpen`; downstream EOF sends `02` and retains the writable half until
upstream EOF. Authentication and subprotocol validation precede any DNS/connect.

For bounded downloads, a client may offer `X-WSVPN-Flow-Control: ack-v1` on
`/tunnel`. The Worker echoes this header only when it enables this extension.
The Cloudflare profile requires the echo; absence closes the transport without
fallback. An extension-enabled client replies to every valid downstream DATA
message with the one-byte binary ACK `04`. The Worker sends at most one DATA
message (payload <= 65536 bytes) awaiting ACK, with a 30-second deadline. EOF
and READY are never acknowledged. Unsolicited ACKs and DATA after upstream EOF
are protocol errors. The self-hosted profile neither requests nor sends ACKs.
Clients without the extension can use Worker base TCP framing, with an 8 MiB
per-flow downstream quota to bound runtime WebSocket buffering.

`/dns` authenticates and negotiates `wsvpn.v1`, sends READY, then carries the
existing version-1 **datagram encoding without a TCP DATA prefix**. Only public
numeric IP markers and port 53 are accepted. The marker is echoed to preserve
SOCKS addressing; it does not select the upstream resolver. The fixed resolver
is `https://cloudflare-dns.com/dns-query` using POST wire-format DoH, without
following redirects. Client associations only accept the configured IPv4 DNS
marker (default 1.1.1.1); other UDP traffic is dropped, never sent directly.

DNS queries have one uncompressed ASCII/IDNA IN question, are <=4096 bytes, and
must be standard queries. Replies are <=4096 bytes and must echo transaction ID,
question name/type/class and response opcode. DoH error, mismatch or timeout
closes the association; reconnect requires a new secure association. Compressed
questions and larger replies are unsupported, with no insecure fallback.
Worker `/udp` is not exposed. Relay `/udp` is unchanged.

### Per-session path check (`echo-v1`)

The Cloudflare client offers `X-WSVPN-Path-Check: echo-v1` on `/tunnel` and
`/dns` and requires the same response header. Missing negotiation fails closed
with a Worker-update error. Deploy the updated Worker before using this client;
the Worker still accepts existing clients that do not offer the extension.
The self-hosted profile does not request it. The subprotocol stays `wsvpn.v1`.

After READY, the client sends a **raw binary message** consisting of byte `05`
and a fresh 32-byte nonce. The Worker must echo exactly those 33 bytes before
either side sends application traffic. This is not a TCP DATA or UDP datagram
and never reaches an egress socket or DoH. TCP server-first bytes are held
behind the echo. Early application messages, malformed or duplicate challenges
close the session; the Worker allows 10 seconds for the initial challenge.

The client also checks standard WebSocket Ping/Pong (at most 2 seconds for a
pong) before the application-level challenge. Ping/Pong alone does not prove
Worker message processing, DNS resolution or Internet egress. Address dial,
TLS, upgrade, READY and both checks share one configured connection deadline.
At most two pre-application handshakes are attempted per supplied address;
each receives a share of the remaining budget. Failed paths are aborted
without an additional close-handshake delay. Once application bytes have been
sent, the client does not replay them on another connection.

Cloudflare startup snapshots relay IPv4 addresses before routing. Authenticated
`/probe` challenges can promote another address within that same snapshot;
normal TCP/DNS dials use the selected address, and the health monitor can change
the selection for subsequent flows. The full bypass/firewall address snapshot
is unchanged, no post-connect resolver fallback is added, and no new address
is admitted during reconnect. Certificate, authentication and protocol failures
remain fatal rather than triggering downgrade or destination-direct access.

The Cloudflare client also accepts SOCKS CONNECT to its configured IPv4 DNS
marker on port 53. It translates the standard two-byte big-endian DNS TCP
length prefix to one `/dns` datagram per query, and restores the length prefix
on the matching response. Pipelined queries are processed sequentially with a
4096-byte limit per query/reply, a 120-second idle header deadline and the
configured client timeout for query completion/DoH response/output drain.
Partial or invalid lengths, response mismatch, close and timeout fail the TCP
stream. No raw port-53 socket or client resolver is used, and no new Worker
wire version is needed. Other TCP DNS markers are rejected. The self-hosted
profile continues to forward TCP DNS normally over `/tunnel`.

Worker application limits: 8 active sessions per isolate including pending
connects, 10-second combined resolution/connect and individual DoH deadlines,
16 pending messages / 1 MiB queued bytes, 300-second TCP idle, 120-second DNS/probe
idle, and 8 MiB DNS response quota per association. These are not account-wide
limits. Worker WebSocket events arrive after runtime reassembly: application
size checks cannot prevent the runtime allocation of an oversized hostile
message. No compression extension is negotiated by this Worker response.
