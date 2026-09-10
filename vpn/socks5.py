from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
from typing import Optional, Tuple

from .config import VpnConfig
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
    ver, cmd, _rsv, atyp = header
    if ver != SOCKS_VERSION:
        raise SocksProtocolError("Unsupported SOCKS version")
    host = await _read_address(reader, atyp)
    port = struct.unpack(">H", await reader.readexactly(2))[0]
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
            raise SocksProtocolError("Invalid domain")
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
            return
        await ws.send(data)


async def _ws_to_client(
    ws: WebSocketTunnel,
    writer: asyncio.StreamWriter,
) -> None:
    while True:
        data = await ws.recv()
        if data is None:
            return
        writer.write(data)
        await writer.drain()


async def _bridge(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ws: WebSocketTunnel,
    chunk_size: int,
) -> None:
    upstream = asyncio.create_task(_client_to_ws(reader, ws, chunk_size))
    downstream = asyncio.create_task(_ws_to_client(ws, writer))
    done, pending = await asyncio.wait(
        (upstream, downstream), return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        if task.cancelled():
            continue
        exc = task.exception()
        if exc:
            raise exc


class _UdpAssociateProtocol(asyncio.DatagramProtocol):
    def __init__(self, ws: WebSocketTunnel, allowed_ip: Optional[str]):
        self.ws = ws
        self.allowed_ip = allowed_ip
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.tasks: set[asyncio.Task] = set()

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if self.allowed_ip and addr[0] != self.allowed_ip:
            return
        if self.client_addr is None:
            self.client_addr = (addr[0], addr[1])
        elif addr != self.client_addr:
            return

        try:
            host, port, payload = _parse_udp_request(data)
        except (SocksProtocolError, UnicodeError) as exc:
            log.debug("Dropping malformed SOCKS UDP datagram from %s: %s", addr, exc)
            return

        task = asyncio.create_task(self.ws.send(encode_datagram(host, port, payload)))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def error_received(self, exc: Exception) -> None:
        log.debug("Local UDP relay error: %s", exc)

    async def close(self) -> None:
        if self.transport:
            self.transport.close()
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)


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


async def _handle_udp_associate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: VpnConfig,
    peer,
) -> None:
    ws = await WebSocketTunnel.connect(
        host=config.relay_host,
        port=config.relay_port,
        path=config.relay_udp_path,
        timeout=config.connect_timeout,
        headers={"Authorization": f"Bearer {config.token}"},
    )

    loop = asyncio.get_running_loop()
    allowed_ip = peer[0] if peer else None
    protocol = _UdpAssociateProtocol(ws, allowed_ip)
    bind_host = config.listen_host
    try:
        ip = ipaddress.ip_address(bind_host)
        if not isinstance(ip, ipaddress.IPv4Address) or ip.is_unspecified:
            bind_host = "127.0.0.1"
    except ValueError:
        bind_host = "127.0.0.1"

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        local_addr=(bind_host, 0),
        family=socket.AF_INET,
    )
    sockname = transport.get_extra_info("sockname")
    _reply(writer, 0, sockname[0], sockname[1])
    await writer.drain()
    log.info("%s -> UDP ASSOCIATE %s:%d", peer, sockname[0], sockname[1])

    control = asyncio.create_task(reader.read(), name="socks-udp-control")
    receiver = asyncio.create_task(
        _udp_ws_to_client(ws, protocol), name="socks-udp-downstream"
    )
    try:
        done, pending = await asyncio.wait(
            (control, receiver), return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            if task.cancelled():
                continue
            exc = task.exception()
            if exc:
                raise exc
    finally:
        await protocol.close()
        await ws.close()


async def _handle_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: VpnConfig,
    peer,
    host: str,
    port: int,
) -> None:
    ws = await WebSocketTunnel.connect(
        host=config.relay_host,
        port=config.relay_port,
        path=config.relay_path,
        timeout=config.connect_timeout,
        headers={
            "Authorization": f"Bearer {config.token}",
            "X-Tunnel-Host": host,
            "X-Tunnel-Port": str(port),
        },
    )
    try:
        _reply(writer, 0)
        await writer.drain()
        log.info("%s -> TCP %s:%d", peer, host, port)
        await _bridge(reader, writer, ws, config.buffer_size)
    finally:
        await ws.close()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: VpnConfig,
) -> None:
    peer = writer.get_extra_info("peername")
    request: Optional[Tuple[int, str, int]] = None
    try:
        await _negotiate(reader, writer)
        request = await _read_request(reader)
        cmd, host, port = request
        if cmd == CMD_CONNECT:
            await _handle_connect(reader, writer, config, peer, host, port)
        elif cmd == CMD_UDP_ASSOCIATE:
            await _handle_udp_associate(reader, writer, config, peer)
        else:
            _reply(writer, 7)
            await writer.drain()
    except SocksProtocolError as exc:
        log.debug("SOCKS error from %s: %s", peer, exc)
        try:
            _reply(writer, 7)
            await writer.drain()
        except Exception:
            pass
    except asyncio.IncompleteReadError:
        pass
    except Exception as exc:
        log.warning("Tunnel failed %s -> %s: %s", peer, request, exc)
        try:
            _reply(writer, 1)
            await writer.drain()
        except Exception:
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve(config: VpnConfig) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, config),
        config.listen_host,
        config.listen_port,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    log.info("SOCKS5 TCP/UDP listening on %s", sockets)
    async with server:
        await server.serve_forever()
