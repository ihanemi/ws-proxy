from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
from typing import Optional, Tuple

from .config import VpnConfig
from .websocket import WebSocketTunnel


log = logging.getLogger("ws-vpn")

SOCKS_VERSION = 5
CMD_CONNECT = 1
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4


class SocksProtocolError(Exception):
    pass


async def _read_target(reader: asyncio.StreamReader) -> Tuple[str, int]:
    header = await reader.readexactly(4)
    ver, cmd, _rsv, atyp = header
    if ver != SOCKS_VERSION:
        raise SocksProtocolError("Unsupported SOCKS version")
    if cmd != CMD_CONNECT:
        raise SocksProtocolError("Only CONNECT is supported")

    if atyp == ATYP_IPV4:
        host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif atyp == ATYP_IPV6:
        host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    elif atyp == ATYP_DOMAIN:
        size = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(size)).decode("idna")
    else:
        raise SocksProtocolError("Unsupported address type")

    port = struct.unpack(">H", await reader.readexactly(2))[0]
    return host, port


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


def _reply(writer: asyncio.StreamWriter, code: int) -> None:
    writer.write(bytes((5, code, 0, 1)) + b"\x00\x00\x00\x00\x00\x00")


async def _client_to_ws(reader: asyncio.StreamReader, ws: WebSocketTunnel, chunk_size: int) -> None:
    while True:
        data = await reader.read(chunk_size)
        if not data:
            return
        await ws.send(data)


async def _ws_to_client(ws: WebSocketTunnel, writer: asyncio.StreamWriter) -> None:
    while True:
        data = await ws.recv()
        if data is None:
            return
        writer.write(data)
        await writer.drain()


async def _bridge(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ws: WebSocketTunnel, chunk_size: int) -> None:
    upstream = asyncio.create_task(_client_to_ws(reader, ws, chunk_size))
    downstream = asyncio.create_task(_ws_to_client(ws, writer))
    done, pending = await asyncio.wait(
        (upstream, downstream), return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        exc = task.exception()
        if exc:
            raise exc


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: VpnConfig,
) -> None:
    peer = writer.get_extra_info("peername")
    target: Optional[Tuple[str, int]] = None
    ws: Optional[WebSocketTunnel] = None
    try:
        await _negotiate(reader, writer)
        target = await _read_target(reader)
        host, port = target
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
        _reply(writer, 0)
        await writer.drain()
        log.info("%s -> %s:%d", peer, host, port)
        await _bridge(reader, writer, ws, config.buffer_size)
    except SocksProtocolError as exc:
        log.debug("SOCKS error from %s: %s", peer, exc)
        try:
            _reply(writer, 7)
            await writer.drain()
        except Exception:
            pass
    except Exception as exc:
        log.warning("Tunnel failed %s -> %s: %s", peer, target, exc)
        try:
            _reply(writer, 1)
            await writer.drain()
        except Exception:
            pass
    finally:
        if ws:
            await ws.close()
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
    log.info("SOCKS5 listening on %s", sockets)
    async with server:
        await server.serve_forever()
