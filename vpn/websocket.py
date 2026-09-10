from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import ssl
from typing import Mapping, Sequence

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake

from .protocol import (
    DATA, MAX_MESSAGE, MAX_PAYLOAD, MAX_QUEUE, READY, SUBPROTOCOL, TCP_EOF,
    decode_tcp, validate_host,
)

# The library's DEBUG logs include HTTP headers, including Authorization.
WIRE_LOG = logging.getLogger("ws-vpn.wire")
WIRE_LOG.setLevel(logging.WARNING)


class WebSocketError(ConnectionError):
    pass


class WebSocketTunnel:
    def __init__(self, connection: ClientConnection, *, udp: bool = False):
        self.connection = connection
        self.udp = udp
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
    ) -> WebSocketTunnel:
        validate_host(host)
        if not path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in path):
            raise ValueError("Invalid relay path")
        if any(any(ord(c) <= 31 or ord(c) >= 127 for c in k + v) for k, v in (headers or {}).items()):
            raise ValueError("Invalid tunnel header")
        authority = f"[{host}]" if ":" in host else host
        uri = f"wss://{authority}:{port}{path}"
        ssl_context = ssl.create_default_context()
        udp = path.split("?", 1)[0].endswith("/udp")

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
            for index, target in enumerate(targets):
                connection = None
                try:
                    connection = await connect(
                        uri, host=target, port=port, ssl=ssl_context,
                        # Preserve TLS hostname verification and SNI while pinning routing.
                        server_hostname=host, proxy=None,
                        additional_headers=headers, subprotocols=[SUBPROTOCOL],
                        compression=None, max_size=MAX_MESSAGE, max_queue=MAX_QUEUE,
                        open_timeout=timeout, close_timeout=3,
                        ping_interval=20, ping_timeout=20, logger=WIRE_LOG,
                    )
                    if connection.subprotocol != SUBPROTOCOL:
                        raise WebSocketError("Relay doesn't support WSVPN/1")
                    # HTTP 101 alone doesn't prove authentication or destination connect.
                    if await connection.recv() != READY:
                        raise WebSocketError("Relay didn't acknowledge tunnel readiness")
                    return cls(connection, udp=udp)
                except BaseException as exc:
                    if connection is not None:
                        await connection.close()
                    if isinstance(exc, asyncio.CancelledError):
                        raise
                    if isinstance(exc, OSError) and index + 1 < len(targets):
                        continue
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
            return decode_tcp(message)
        except ValueError as exc:
            raise WebSocketError(str(exc)) from None

    async def close(self) -> None:
        self.closed = True
        # Always close the underlying transport, including after a received close.
        await self.connection.close()
