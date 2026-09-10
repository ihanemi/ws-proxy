from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
from typing import Tuple

from .async_utils import cancel_and_join, close_writer, run_pair
from .config import VpnConfig
from .protocol import validate_host
from .udp_protocol import MAX_DATAGRAM, UdpFrameError
from .udp_protocol import decode_datagram, encode_datagram
from .websocket import WebSocketTunnel


log = logging.getLogger("ws-vpn")

SOCKS_VERSION = 5
CMD_CONNECT = 1
CMD_UDP_ASSOCIATE = 3
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4


class SocksProtocolError(Exception):
    pass


async def _read_address(reader: asyncio.StreamReader, atyp: int) -> str:
    if atyp == ATYP_IPV4:
        return str(ipaddress.IPv4Address(await reader.readexactly(4)))
    if atyp == ATYP_IPV6:
        return str(ipaddress.IPv6Address(await reader.readexactly(16)))
    if atyp == ATYP_DOMAIN:
        size = (await reader.readexactly(1))[0]
        if size == 0:
            raise SocksProtocolError("Empty domain name")
        return (await reader.readexactly(size)).decode("idna")
    raise SocksProtocolError("Unsupported address type")


async def _read_request(reader: asyncio.StreamReader) -> Tuple[int, str, int]:
    header = await reader.readexactly(4)
    ver, cmd, rsv, atyp = header
    if rsv != 0:
        raise SocksProtocolError("Invalid reserved byte")
    if ver != SOCKS_VERSION:
        raise SocksProtocolError("Unsupported SOCKS version")
    host = await _read_address(reader, atyp)
    port = struct.unpack(">H", await reader.readexactly(2))[0]
    validate_host(host)
    if cmd == CMD_CONNECT and port == 0:
        raise SocksProtocolError("Invalid destination port")
    return cmd, host, port


async def _negotiate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    ver, nmethods = await reader.readexactly(2)
    if ver != SOCKS_VERSION:
        raise SocksProtocolError("Unsupported SOCKS version")
    methods = await reader.readexactly(nmethods)
    if 0 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        raise SocksProtocolError("Client does not support no-auth SOCKS5")
    writer.write(b"\x05\x00")
    await writer.drain()


def _encode_address(host: str) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if not encoded or len(encoded) > 255:
            raise SocksProtocolError("Invalid domain") from None
        return bytes((ATYP_DOMAIN, len(encoded))) + encoded

    if isinstance(ip, ipaddress.IPv4Address):
        return bytes((ATYP_IPV4,)) + ip.packed
    return bytes((ATYP_IPV6,)) + ip.packed


def _reply(
    writer: asyncio.StreamWriter,
    code: int,
    bind_host: str = "0.0.0.0",
    bind_port: int = 0,
) -> None:
    writer.write(
        bytes((SOCKS_VERSION, code, 0))
        + _encode_address(bind_host)
        + struct.pack(">H", bind_port)
    )


def _parse_udp_request(data: bytes) -> Tuple[str, int, bytes]:
    if len(data) < 4 or data[:2] != b"\x00\x00":
        raise SocksProtocolError("Invalid SOCKS UDP datagram")
    if data[2] != 0:
        raise SocksProtocolError("SOCKS UDP fragmentation is not supported")

    atyp = data[3]
    offset = 4
    if atyp == ATYP_IPV4:
        if len(data) < offset + 4 + 2:
            raise SocksProtocolError("Truncated IPv4 UDP datagram")
        host = str(ipaddress.IPv4Address(data[offset:offset + 4]))
        offset += 4
    elif atyp == ATYP_IPV6:
        if len(data) < offset + 16 + 2:
            raise SocksProtocolError("Truncated IPv6 UDP datagram")
        host = str(ipaddress.IPv6Address(data[offset:offset + 16]))
        offset += 16
    elif atyp == ATYP_DOMAIN:
        if len(data) < offset + 1:
            raise SocksProtocolError("Truncated domain UDP datagram")
        size = data[offset]
        offset += 1
        if size == 0 or len(data) < offset + size + 2:
            raise SocksProtocolError("Invalid domain UDP datagram")
        host = data[offset:offset + size].decode("idna")
        offset += size
    else:
        raise SocksProtocolError("Unsupported UDP address type")

    port = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    if port == 0:
        raise SocksProtocolError("Invalid UDP destination port")
    return host, port, data[offset:]


def _build_udp_response(host: str, port: int, payload: bytes) -> bytes:
    return b"\x00\x00\x00" + _encode_address(host) + struct.pack(">H", port) + payload


async def _client_to_ws(
    reader: asyncio.StreamReader,
    ws: WebSocketTunnel,
    chunk_size: int,
) -> None:
    while True:
        data = await reader.read(chunk_size)
        if not data:
            await ws.send_eof()
            return
        await ws.send(data)


async def _ws_to_client(
    ws: WebSocketTunnel,
    writer: asyncio.StreamWriter,
) -> None:
    while True:
        data = await ws.recv()
        if data is None:
            writer.write_eof()
            await writer.drain()
            return
        writer.write(data)
        await writer.drain()


async def _bridge(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ws: WebSocketTunnel,
    chunk_size: int,
) -> None:
    await run_pair(_client_to_ws(reader, ws, chunk_size),
                   _ws_to_client(ws, writer), half_close=True)


class _UdpAssociateProtocol(asyncio.DatagramProtocol):
    def __init__(self, ws: WebSocketTunnel, allowed_ip: str, allowed_port: int = 0):
        self.ws = ws
        self.allowed_ip = allowed_ip
        self.allowed_port = allowed_port
        self.transport = None
        self.client_addr = None
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=16)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        endpoint = (addr[0], addr[1])
        if addr[0] != self.allowed_ip or (self.allowed_port and addr[1] != self.allowed_port):
            return
        if self.client_addr is not None and endpoint != self.client_addr:
            return
        try:
            host, port, payload = _parse_udp_request(data)
            validate_host(host)
            if len(payload) > MAX_DATAGRAM:
                return
            frame = encode_datagram(host, port, payload)
        except (SocksProtocolError, UnicodeError, UdpFrameError, ValueError):
            return
        # Malformed packets cannot claim the association's source port.
        if self.client_addr is None:
            self.client_addr = endpoint
        try:
            self.queue.put_nowait(frame)
        except asyncio.QueueFull:
            pass  # UDP drops are preferable to unbounded allocations/tasks.

    async def sender(self):
        while True:
            await self.ws.send(await self.queue.get())

    async def close(self):
        if self.transport:
            self.transport.close()

    def error_received(self, exc):
        log.debug("Local UDP socket error: %s", type(exc).__name__)


async def _udp_ws_to_client(
    ws: WebSocketTunnel,
    protocol: _UdpAssociateProtocol,
) -> None:
    while True:
        frame = await ws.recv()
        if frame is None:
            return
        host, port, payload = decode_datagram(frame)
        if protocol.transport and protocol.client_addr:
            protocol.transport.sendto(
                _build_udp_response(host, port, payload),
                protocol.client_addr,
            )


async def _handle_udp_associate(reader, writer, config, peer, host, port, mark_ready):
    if host not in ("0.0.0.0", "::", peer[0]):
        raise SocksProtocolError("UDP source must match the TCP control peer")
    ws = await WebSocketTunnel.connect(
        host=config.relay_host, port=config.relay_port, path=config.relay_udp_path,
        timeout=config.connect_timeout, resolved_ips=config.relay_ips,
        headers={"Authorization": f"Bearer {config.token}"},
    )
    protocol = _UdpAssociateProtocol(ws, peer[0], port)
    tasks = []
    try:
        family = socket.AF_INET6 if ":" in config.listen_host else socket.AF_INET
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: protocol, local_addr=(config.listen_host, 0), family=family,
        )
        sockname = transport.get_extra_info("sockname")
        _reply(writer, 0, sockname[0], sockname[1])
        mark_ready()
        await writer.drain()
        # A SOCKS UDP control channel is a lifetime signal, not a data buffer.
        tasks = [asyncio.create_task(reader.read(1)),
                 asyncio.create_task(_udp_ws_to_client(ws, protocol)),
                 asyncio.create_task(protocol.sender())]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        await cancel_and_join(*tasks)
        await protocol.close()
        await ws.close()


async def _handle_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: VpnConfig,
    peer,
    host: str,
    port: int,
    mark_ready,
) -> None:
    ws = await WebSocketTunnel.connect(
        host=config.relay_host,
        port=config.relay_port,
        path=config.relay_path,
        timeout=config.connect_timeout,
        resolved_ips=config.relay_ips,
        headers={
            "Authorization": f"Bearer {config.token}",
            "X-Tunnel-Host": host,
            "X-Tunnel-Port": str(port),
        },
    )
    try:
        _reply(writer, 0)
        mark_ready()
        await writer.drain()
        log.info("%s -> TCP %s:%d", peer, host, port)
        await _bridge(reader, writer, ws, config.buffer_size)
    finally:
        await ws.close()


async def handle_client(reader, writer, config):
    peer = writer.get_extra_info("peername")
    negotiated = False
    established = False

    def mark_ready():
        nonlocal established
        established = True

    try:
        await asyncio.wait_for(_negotiate(reader, writer), config.connect_timeout)
        negotiated = True
        cmd, host, port = await asyncio.wait_for(_read_request(reader), config.connect_timeout)
        if cmd == CMD_CONNECT:
            await _handle_connect(reader, writer, config, peer, host, port, mark_ready)
        elif cmd == CMD_UDP_ASSOCIATE:
            await _handle_udp_associate(reader, writer, config, peer, host, port, mark_ready)
        else:
            _reply(writer, 7)
            await writer.drain()
    except asyncio.IncompleteReadError:
        pass
    except (OSError, ValueError, SocksProtocolError, TimeoutError) as exc:
        log.debug("SOCKS session failed: %s", type(exc).__name__)
        # Never append SOCKS reply bytes to an already-established TCP stream.
        if negotiated and not established:
            _reply(writer, 1)
            try:
                await writer.drain()
            except OSError:
                pass
    finally:
        await close_writer(writer)


async def serve(config: VpnConfig, *, ready: asyncio.Event | None = None):
    clients = set()

    def accept(reader, writer):
        if len(clients) >= config.max_clients:
            writer.close()
            return
        task = asyncio.create_task(handle_client(reader, writer, config))
        clients.add(task)

        def finished(task):
            clients.discard(task)
            if not task.cancelled() and task.exception():
                log.error("SOCKS handler stopped: %s", type(task.exception()).__name__)
        task.add_done_callback(finished)

    server = await asyncio.start_server(accept, config.listen_host, config.listen_port)
    try:
        async with server:
            if ready is not None:
                ready.set()
            await server.serve_forever()
    finally:
        await cancel_and_join(*clients)
