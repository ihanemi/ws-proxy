"""Worker-mediated DNS for readiness and TCP fallback; no local resolver."""
from __future__ import annotations

import asyncio
import secrets
import struct

from .udp_protocol import decode_datagram, encode_datagram
from .websocket import WebSocketError, WebSocketTunnel

MAX_DNS = 4096


async def _exchange(tunnel, marker: str, query: bytes) -> bytes:
    await tunnel.send(encode_datagram(marker, 53, query))
    frame = await tunnel.recv()
    if frame is None:
        raise WebSocketError("Worker DNS closed without a response")
    try:
        host, port, packet = decode_datagram(frame)
    except ValueError as exc:
        raise WebSocketError("Invalid Worker DNS datagram") from exc
    if (host != marker or port != 53 or not 12 <= len(packet) <= MAX_DNS
            or packet[:2] != query[:2] or packet[2] & 0x80 == 0
            or packet[2] & 0x78 or packet[4:6] != b"\x00\x01"):
        raise WebSocketError("Invalid Worker DNS response")
    return packet


async def forward_tcp_dns(reader, writer, tunnel, config) -> None:
    """Convert length-prefixed DNS TCP messages to the existing /dns contract.

    Read one bounded query at a time, including pipelined requests. The Worker
    validates questions and answers and uses its fixed HTTPS resolver. Neither
    the DNS marker nor a TCP fallback opens a direct port-53 connection.
    """
    while True:
        try:
            header = await asyncio.wait_for(reader.readexactly(2), 120)
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                return
            raise WebSocketError("Truncated TCP DNS length") from exc
        size = struct.unpack(">H", header)[0]
        if not 17 <= size <= MAX_DNS:
            raise WebSocketError("TCP DNS query exceeds supported size")
        query = await asyncio.wait_for(reader.readexactly(size), config.connect_timeout)
        packet = await asyncio.wait_for(
            _exchange(tunnel, config.dns_server, query), config.connect_timeout,
        )
        writer.write(struct.pack(">H", len(packet)) + packet)
        await asyncio.wait_for(writer.drain(), config.connect_timeout)


async def probe_dns(config) -> None:
    transaction = secrets.token_bytes(2)
    query = transaction + struct.pack(">5H", 0x0100, 1, 0, 0, 0)
    query += b"\x07example\x03com\x00\x00\x01\x00\x01"
    tunnel = await WebSocketTunnel.connect(
        config.relay_host, config.relay_port, config.relay_udp_path,
        headers={"Authorization": "Bearer " + config.token},
        timeout=config.connect_timeout, resolved_ips=config.relay_ips,
    )
    try:
        packet = await asyncio.wait_for(
            _exchange(tunnel, config.dns_server, query), config.connect_timeout,
        )
        if (len(packet) < len(query)
                or packet[2] & 0x02 or packet[6:8] == b"\x00\x00"
                or packet[3] & 0x0f
                or packet[12:len(query)] != query[12:]):
            raise WebSocketError("Worker DNS probe failed")
    finally:
        await tunnel.close()
