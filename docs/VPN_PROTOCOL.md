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
