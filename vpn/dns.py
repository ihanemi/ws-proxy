"""Authenticated Worker DNS readiness; never consult the local DNS resolver."""
from __future__ import annotations

import asyncio
import secrets
import struct

from .udp_protocol import decode_datagram, encode_datagram
from .websocket import WebSocketError, WebSocketTunnel


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
        await asyncio.wait_for(
            tunnel.send(encode_datagram(config.dns_server, 53, query)), config.connect_timeout,
        )
        frame = await asyncio.wait_for(tunnel.recv(), config.connect_timeout)
        if frame is None:
            raise WebSocketError("Worker DNS probe closed without a response")
        host, port, packet = decode_datagram(frame)
        if (host != config.dns_server or port != 53 or len(packet) < len(query)
                or packet[:2] != transaction or packet[2] & 0x80 == 0
                or packet[2] & 0x02 or packet[6:8] == b"\x00\x00"
                or packet[3] & 0x0f or packet[4:6] != b"\x00\x01"
                or packet[12:len(query)] != query[12:]):
            raise WebSocketError("Worker DNS probe failed")
    finally:
        await tunnel.close()
