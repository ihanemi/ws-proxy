from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import socket
import ssl
from dataclasses import replace
from typing import Mapping, Sequence

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake

from .endpoints import RelayEndpoints

from .protocol import (
    DATA, MAX_MESSAGE, MAX_PAYLOAD, MAX_QUEUE, READY, SUBPROTOCOL, TCP_EOF,
    decode_tcp, validate_host,
)

# The library's DEBUG logs include HTTP headers, including Authorization.
WIRE_LOG = logging.getLogger("ws-vpn.wire")
WIRE_LOG.setLevel(logging.WARNING)


class WebSocketError(ConnectionError):
    pass


class RelayAddressError(WebSocketError):
    """A network dial failed; authentication/protocol/TLS errors stay fatal."""


class WebSocketTunnel:
    def __init__(self, connection: ClientConnection, *, udp: bool = False, flow_control: bool = False):
        self.connection = connection
        self.udp = udp
        self.flow_control = flow_control
        self.closed = False

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        path: str,
        headers: Mapping[str, str] | None = None,
        timeout: float = 10.0,
        *,
        force_ipv4: bool = True,
        resolved_ips: Sequence[str] = (),
        flow_control: bool = False,
        check_path: bool = False,
        path_challenge: bool = False,
    ) -> WebSocketTunnel:
        validate_host(host)
        if not path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in path):
            raise ValueError("Invalid relay path")
        if any(any(ord(c) <= 31 or ord(c) >= 127 for c in k + v) for k, v in (headers or {}).items()):
            raise ValueError("Invalid tunnel header")
        authority = f"[{host}]" if ":" in host else host
        uri = f"wss://{authority}:{port}{path}"
        ssl_context = ssl.create_default_context()
        udp = path.split("?", 1)[0].endswith(("/udp", "/dns"))
        headers = dict(headers or {})
        if flow_control:
            headers["X-WSVPN-Flow-Control"] = "ack-v1"
        if path_challenge:
            headers["X-WSVPN-Path-Check"] = "echo-v1"

        async def establish() -> WebSocketTunnel:
            targets = list(resolved_ips)
            if targets:
                for value in targets:
                    ipaddress.IPv4Address(value)
            elif force_ipv4:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    host, port, family=socket.AF_INET, type=socket.SOCK_STREAM,
                )
                targets = list(dict.fromkeys(info[4][0] for info in infos))
                if not targets:
                    raise WebSocketError("Relay requires an IPv4 A record")
            else:
                targets = [host]
            if check_path:
                # A fresh connection can recover a transient edge failure.
                # At most two handshakes per address, all within one deadline.
                targets = [target for target in targets for _ in range(2)]
            deadline = asyncio.get_running_loop().time() + timeout
            for index, target in enumerate(targets):
                connection = None
                remaining = deadline - asyncio.get_running_loop().time()
                budget = remaining / (len(targets) - index) if check_path else remaining
                if budget <= 0:
                    raise TimeoutError("Relay connection timed out")
                try:
                    async def handshake(target=target, budget=budget):
                        nonlocal connection
                        connection = await connect(
                            uri, host=target, port=port, ssl=ssl_context,
                            # Keep hostname verification/SNI when routing to a snapshot IP.
                            server_hostname=host, proxy=None,
                            additional_headers=headers, subprotocols=[SUBPROTOCOL],
                            compression=None, max_size=MAX_MESSAGE, max_queue=MAX_QUEUE,
                            open_timeout=budget, close_timeout=3,
                            ping_interval=20, ping_timeout=20, logger=WIRE_LOG,
                        )
                        if connection.subprotocol != SUBPROTOCOL:
                            raise WebSocketError("Relay doesn't support WSVPN/1")
                        if flow_control and connection.response.headers.get("X-WSVPN-Flow-Control") != "ack-v1":
                            raise WebSocketError("Worker didn't negotiate required flow control")
                        if path_challenge and connection.response.headers.get("X-WSVPN-Path-Check") != "echo-v1":
                            raise WebSocketError("Worker requires an update for the session path check")
                        if await connection.recv() != READY:
                            raise WebSocketError("Relay didn't acknowledge tunnel readiness")
                        if check_path:
                            # READY can arrive on a path whose subsequent frames
                            # are blackholed. Verify this exact socket before any
                            # application payload; no new WSVPN frame is needed.
                            pong = await connection.ping(secrets.token_bytes(16))
                            await asyncio.wait_for(pong, min(2.0, budget))
                        if path_challenge:
                            challenge = b"\x05" + secrets.token_bytes(32)
                            await connection.send(challenge)
                            if await connection.recv() != challenge:
                                raise WebSocketError("Worker session path check failed")
                        return cls(connection, udp=udp, flow_control=flow_control)
                    return await asyncio.wait_for(handshake(), budget)
                except BaseException as exc:
                    if connection is not None:
                        if isinstance(exc, (asyncio.CancelledError, TimeoutError)):
                            # A cancelled readiness deadline must not spend a
                            # further close-handshake timeout on a dead path.
                            connection.transport.abort()
                        else:
                            await connection.close()
                    if isinstance(exc, asyncio.CancelledError):
                        raise
                    if isinstance(exc, TimeoutError):
                        if check_path and index + 1 < len(targets):
                            continue
                        raise
                    if isinstance(exc, WebSocketError):
                        raise
                    if isinstance(exc, OSError) and not isinstance(exc, ssl.SSLError):
                        if index + 1 < len(targets):
                            continue
                        raise RelayAddressError("Relay address connection failed") from None
                    if isinstance(exc, (ConnectionClosed, InvalidHandshake, OSError)):
                        raise WebSocketError("Relay authentication, TLS, or destination connection failed") from None
                    raise
            raise WebSocketError("No relay address is available")

        return await asyncio.wait_for(establish(), timeout=timeout)

    async def send(self, payload: bytes) -> None:
        if self.closed or len(payload) > MAX_PAYLOAD:
            raise WebSocketError("Tunnel is closed or message is too large")
        await self.connection.send(payload if self.udp else DATA + payload)

    async def send_eof(self) -> None:
        if self.udp:
            raise WebSocketError("UDP doesn't support half-close")
        await self.connection.send(TCP_EOF)

    async def recv(self) -> bytes | None:
        try:
            message = await self.connection.recv()
        except ConnectionClosed as exc:
            # A TCP connection must finish with EOF, not an ambiguous WS close.
            if self.udp and exc.code == 1000:
                return None
            raise WebSocketError("Relay connection closed") from None
        if not isinstance(message, bytes):
            raise WebSocketError("Text messages aren't supported")
        if self.udp:
            return message
        try:
            payload = decode_tcp(message)
            if self.flow_control and payload is not None:
                await self.connection.send(b"\x04")
            return payload
        except ValueError as exc:
            raise WebSocketError(str(exc)) from None

    async def close(self) -> None:
        self.closed = True
        # Always close the underlying transport, including after a received close.
        await self.connection.close()

    def abort(self) -> None:
        """Discard a failed control probe without waiting for its peer."""
        self.closed = True
        self.connection.transport.abort()


async def prepare_relay(config):
    """Bootstrap Cloudflare once, before routing, retaining every bypass IP."""
    if config.backend != "cloudflare" or config.endpoints is not None:
        return config
    addresses = config.relay_ips
    if not addresses:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            config.relay_host, config.relay_port, family=socket.AF_INET, type=socket.SOCK_STREAM,
        ), config.connect_timeout)
        addresses = tuple(dict.fromkeys(info[4][0] for info in infos))
    return replace(config, relay_ips=addresses, endpoints=RelayEndpoints(addresses))


async def probe_relay(config) -> None:
    """Prove TLS, authentication, negotiation, and bidirectional framing."""
    if config.endpoints is None:
        await _probe_once(config, config.relay_ips, config.connect_timeout)
        return
    addresses = config.endpoints.ordered()
    deadline = asyncio.get_running_loop().time() + config.connect_timeout
    for index, address in enumerate(addresses):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("Relay data-path probe timed out")
        budget = remaining / (len(addresses) - index)
        try:
            await asyncio.wait_for(_probe_once(config, (address,), budget), budget)
        except (TimeoutError, RelayAddressError):
            # Retry only the authenticated control probe. Never replay user
            # traffic or dial outside the unchanged firewall/route snapshot.
            if index + 1 == len(addresses):
                raise
            logging.getLogger("ws-vpn").warning("Relay data-path unavailable; probing next pinned address")
            continue
        config.endpoints.verified(address)
        return


async def _probe_once(config, addresses, timeout) -> None:
    tunnel = await WebSocketTunnel.connect(
        config.relay_host,
        config.relay_port,
        config.relay_probe_path,
        headers={"Authorization": "Bearer " + config.token},
        timeout=timeout,
        resolved_ips=addresses,
        check_path=config.backend == "cloudflare",
    )
    verified = False
    try:
        challenge = secrets.token_bytes(32)
        await asyncio.wait_for(tunnel.send(challenge), timeout)
        response = await asyncio.wait_for(tunnel.recv(), timeout)
        if response != challenge:
            raise WebSocketError("Relay health challenge failed")
        verified = True
    finally:
        if verified:
            await tunnel.close()
        else:
            tunnel.abort()
