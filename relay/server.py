from __future__ import annotations

import argparse
import asyncio
import hmac
import ipaddress
import logging
import os
import signal
import socket
import ssl
import time
from collections import Counter
from dataclasses import dataclass
from http import HTTPStatus

from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from vpn.async_utils import cancel_and_join, close_writer, run_pair
from vpn.protocol import (
    DATA, MAX_MESSAGE, MAX_PAYLOAD, MAX_QUEUE, READY, SUBPROTOCOL, TCP_EOF,
    decode_tcp, validate_host, validate_token,
)
from vpn.udp_protocol import MAX_DATAGRAM, decode_datagram, encode_datagram

log = logging.getLogger("ws-vpn-relay")
WIRE_LOG = logging.getLogger("ws-vpn-relay.wire")
WIRE_LOG.setLevel(logging.WARNING)  # DEBUG would disclose Authorization headers.


@dataclass(frozen=True)
class RelayLimits:
    connections: int = 256
    per_peer: int = 128
    connect_timeout: float = 10
    tcp_idle: float = 300
    udp_idle: float = 120
    udp_targets: int = 256
    udp_target_ttl: float = 60
    udp_packets_per_second: int = 1000
    udp_bytes_per_second: int = 1024 * 1024

    def __post_init__(self):
        if any(value <= 0 for value in vars(self).values()):
            raise ValueError("All relay limits must be positive")


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    # is_global also excludes CGNAT; reject transition mechanisms to avoid
    # embedding a different IPv4 destination inside an apparently global IPv6 IP.
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None:
            return False
        if ip in ipaddress.ip_network("64:ff9b::/96") or ip in ipaddress.ip_network("64:ff9b:1::/48"):
            return False
    return True


async def _resolve_public(host: str, port: int, socktype: int) -> tuple[str, int]:
    host = validate_host(host)
    if not 1 <= port <= 65535 or port == 25:
        raise ValueError("Invalid destination port")
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socktype)
    candidates = [(addr[0], family) for family, _, _, _, addr in infos
                  if family in (socket.AF_INET, socket.AF_INET6)]
    # Reject mixed public/private answers instead of letting resolver order
    # choose a bypass. Connect/send only to the validated numeric address.
    if not candidates or any(not _is_public_ip(ip) for ip, _ in candidates):
        raise ValueError("Destination must resolve exclusively to public addresses")
    return candidates[0]


class Activity:
    def __init__(self):
        self.last = time.monotonic()

    def touch(self):
        self.last = time.monotonic()

    async def watchdog(self, timeout: float):
        while True:
            remaining = timeout - (time.monotonic() - self.last)
            if remaining <= 0:
                raise TimeoutError("Relay session idle timeout")
            await asyncio.sleep(remaining)


class Budget:
    """Per-association packet and byte token bucket, in each direction."""
    def __init__(self, limits: RelayLimits):
        self.limits = limits
        self.packets = float(limits.udp_packets_per_second)
        self.bytes = float(limits.udp_bytes_per_second)
        self.updated = time.monotonic()

    def take(self, size: int) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated
        self.updated = now
        self.packets = min(self.limits.udp_packets_per_second,
                           self.packets + elapsed * self.limits.udp_packets_per_second)
        self.bytes = min(self.limits.udp_bytes_per_second,
                         self.bytes + elapsed * self.limits.udp_bytes_per_second)
        if self.packets < 1 or self.bytes < size:
            return False
        self.packets -= 1
        self.bytes -= size
        return True


class Relay:
    def __init__(self, token: str, limits: RelayLimits | None = None):
        validate_token(token)
        self.token = token
        self.limits = limits or RelayLimits()
        self.total = 0
        self.peers: Counter = Counter()

    def connection_factory(self, *args, **kwargs):
        relay = self

        class LimitedConnection(ServerConnection):
            admitted = False

            def connection_made(self, transport):
                peer = transport.get_extra_info("peername")
                self.peer_key = peer[0] if peer else "unknown"
                super().connection_made(transport)
                if relay.total >= relay.limits.connections or relay.peers[self.peer_key] >= relay.limits.per_peer:
                    transport.close()
                    return
                self.admitted = True
                relay.total += 1
                relay.peers[self.peer_key] += 1

            def connection_lost(self, exc):
                if self.admitted:
                    self.admitted = False
                    relay.total -= 1
                    relay.peers[self.peer_key] -= 1
                    if not relay.peers[self.peer_key]:
                        del relay.peers[self.peer_key]
                super().connection_lost(exc)

        return LimitedConnection(*args, **kwargs)

    def process_request(self, connection, request):
        if request.path == "/healthz":
            return connection.respond(HTTPStatus.OK, "ok\n")
        auth = request.headers.get_all("Authorization")
        expected = f"Bearer {self.token}".encode("ascii")
        if len(auth) != 1 or not hmac.compare_digest(auth[0].encode("utf-8"), expected):
            return connection.respond(HTTPStatus.UNAUTHORIZED, "Unauthorized\n")
        if request.path not in ("/tunnel", "/udp", "/probe"):
            return connection.respond(HTTPStatus.NOT_FOUND, "Unknown tunnel path\n")
        protocols = ",".join(request.headers.get_all("Sec-WebSocket-Protocol")).split(",")
        if SUBPROTOCOL not in [s.strip() for s in protocols]:
            return connection.respond(HTTPStatus.UPGRADE_REQUIRED, "WSVPN/1 required\n")
        if request.path == "/tunnel":
            try:
                hosts = request.headers.get_all("X-Tunnel-Host")
                ports = request.headers.get_all("X-Tunnel-Port")
                if len(hosts) != 1 or len(ports) != 1:
                    raise ValueError("Invalid destination headers")
                validate_host(hosts[0])
                if not ports[0].isascii() or not ports[0].isdigit():
                    raise ValueError("Invalid port")
                port = int(ports[0])
                if not 1 <= port <= 65535 or port == 25:
                    raise ValueError("Invalid port")
            except ValueError:
                return connection.respond(HTTPStatus.BAD_REQUEST, "Invalid destination\n")
        return None

    async def handle(self, ws):
        try:
            if ws.request.path == "/tunnel":
                await self.tcp(ws)
            elif ws.request.path == "/udp":
                await self.udp(ws)
            else:
                await self.probe(ws)
        except (ValueError, TimeoutError, OSError, ConnectionClosed) as exc:
            # Never log a request, headers, or exception text provided by a peer.
            log.info("session_closed reason=%s", type(exc).__name__)
            await ws.close(code=1008 if isinstance(exc, ValueError) else 1011,
                           reason="tunnel failed")

    async def probe(self, ws):
        await ws.send(READY)
        message = await asyncio.wait_for(ws.recv(), self.limits.connect_timeout)
        payload = decode_tcp(message)
        if payload is None or len(payload) != 32:
            raise ValueError("Invalid health challenge")
        await ws.send(DATA + payload)
        await ws.close()

    async def tcp(self, ws):
        headers = ws.request.headers
        host, port = headers["X-Tunnel-Host"], int(headers["X-Tunnel-Port"])

        async def open_target():
            ip, family = await _resolve_public(host, port, socket.SOCK_STREAM)
            return await asyncio.open_connection(ip, port, family=family)

        reader, writer = await asyncio.wait_for(open_target(), self.limits.connect_timeout)
        activity = Activity()

        async def upstream():
            while True:
                data = decode_tcp(await ws.recv())
                activity.touch()
                if data is None:
                    writer.write_eof()
                    await writer.drain()
                    return
                writer.write(data)
                await writer.drain()

        async def downstream():
            while True:
                data = await reader.read(MAX_PAYLOAD)
                activity.touch()
                if not data:
                    await ws.send(TCP_EOF)
                    return
                await ws.send(DATA + data)

        try:
            await ws.send(READY)
            await run_pair(run_pair(upstream(), downstream(), half_close=True),
                           activity.watchdog(self.limits.tcp_idle))
        finally:
            await close_writer(writer)

    async def udp(self, ws):
        sockets = {}
        tasks = []
        # Both maps have a hard cap and expiry. Answers must come from a
        # currently contacted numeric endpoint, never arbitrary UDP senders.
        cache = {}
        allowed = {}
        outgoing = Budget(self.limits)
        incoming = Budget(self.limits)
        activity = Activity()
        loop = asyncio.get_running_loop()

        async def receive(sock):
            while True:
                payload, source = await loop.sock_recvfrom(sock, MAX_DATAGRAM + 1)
                if len(payload) > MAX_DATAGRAM or not incoming.take(len(payload)):
                    continue
                if allowed.get((source[0], source[1]), 0) <= time.monotonic():
                    continue
                activity.touch()
                await ws.send(encode_datagram(source[0], source[1], payload))

        async def send():
            async for message in ws:
                if not isinstance(message, bytes):
                    raise ValueError("UDP requires binary messages")
                host, port, payload = decode_datagram(message)
                activity.touch()
                if port == 25 or not outgoing.take(len(payload)):
                    continue
                now = time.monotonic()
                for key in [key for key, value in cache.items() if value[2] <= now]:
                    del cache[key]
                for key in [key for key, expires in allowed.items() if expires <= now]:
                    del allowed[key]
                key = (host, port)
                if key not in cache:
                    if len(cache) >= self.limits.udp_targets:
                        continue
                    try:
                        ip, family = await asyncio.wait_for(
                            _resolve_public(host, port, socket.SOCK_DGRAM), self.limits.connect_timeout,
                        )
                    except (OSError, ValueError, TimeoutError):
                        continue
                    cache[key] = (ip, family, now + self.limits.udp_target_ttl)
                ip, family, _ = cache[key]
                if family not in sockets:
                    continue
                endpoint = (ip, port)
                if endpoint not in allowed and len(allowed) >= self.limits.udp_targets:
                    continue
                # Install before send so a fast reply cannot beat the check.
                allowed[endpoint] = now + self.limits.udp_target_ttl
                try:
                    await loop.sock_sendto(sockets[family], payload,
                                           endpoint if family == socket.AF_INET else (*endpoint, 0, 0))
                except OSError:
                    allowed.pop(endpoint, None)

        try:
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    sock = _create_udp_socket(family)
                except OSError:
                    continue
                sockets[family] = sock
                tasks.append(asyncio.create_task(receive(sock)))
            if not sockets:
                raise OSError("UDP egress unavailable")
            await ws.send(READY)
            tasks.extend((asyncio.create_task(send()),
                          asyncio.create_task(activity.watchdog(self.limits.udp_idle))))
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            await cancel_and_join(*tasks)
            for sock in sockets.values():
                sock.close()


def _create_udp_socket(family):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("0.0.0.0", 0) if family == socket.AF_INET else ("::", 0))
        return sock
    except BaseException:
        sock.close()
        raise


def _ssl_context(cert, key):
    if not cert and not key:
        return None
    if not cert or not key:
        raise ValueError("Both --cert and --key are required for TLS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def build_parser():
    parser = argparse.ArgumentParser(description="WS VPN remote relay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default=os.getenv("WS_VPN_TOKEN"))
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--max-connections", type=int, default=256)
    parser.add_argument("--max-per-peer", type=int, default=128)
    parser.add_argument("--connect-timeout", type=float, default=10)
    parser.add_argument("--tcp-idle", type=float, default=300)
    parser.add_argument("--udp-idle", type=float, default=120)
    parser.add_argument("--udp-targets", type=int, default=256)
    parser.add_argument("--verbose", action="store_true")
    return parser


async def run_server(args):
    if not args.token:
        raise ValueError("Set WS_VPN_TOKEN to a long random token")
    context = _ssl_context(args.cert, args.key)
    if context is None and not ipaddress.ip_address(args.host).is_loopback:
        raise ValueError("Plaintext relay must bind to loopback behind a TLS reverse proxy")
    relay = Relay(args.token, RelayLimits(
        connections=args.max_connections, per_peer=args.max_per_peer,
        connect_timeout=args.connect_timeout, tcp_idle=args.tcp_idle,
        udp_idle=args.udp_idle, udp_targets=args.udp_targets,
    ))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
            installed.append(sig)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        async with serve(
            relay.handle, args.host, args.port, ssl=context,
            process_request=relay.process_request, create_connection=relay.connection_factory,
            subprotocols=[SUBPROTOCOL], compression=None, max_size=MAX_MESSAGE,
            max_queue=MAX_QUEUE, open_timeout=10, close_timeout=3,
            ping_interval=20, ping_timeout=20, logger=WIRE_LOG,
        ):
            log.info("relay_listening host=%s port=%d tls=%s", args.host, args.port, bool(context))
            await stop.wait()
    finally:
        for sig in installed:
            loop.remove_signal_handler(sig)


def main():
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        asyncio.run(run_server(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
