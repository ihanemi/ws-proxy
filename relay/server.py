from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import socket
import ssl
from typing import Dict, Optional, Set, Tuple

from websockets.asyncio.server import ServerConnection, serve

from vpn.udp_protocol import UdpFrameError, decode_datagram, encode_datagram


log = logging.getLogger("ws-vpn-relay")


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def _resolve_public(
    host: str,
    port: int,
    socktype: int,
) -> Tuple[str, int]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socktype)
    seen = set()
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        try:
            if _is_public_ip(ip):
                return ip, family
        except ValueError:
            continue
    raise ValueError("Destination didn't resolve to a public IP")


async def _pipe_ws_to_tcp(ws: ServerConnection, writer: asyncio.StreamWriter) -> None:
    async for message in ws:
        if isinstance(message, str):
            raise ValueError("Text frames aren't supported")
        writer.write(message)
        await writer.drain()


async def _pipe_tcp_to_ws(reader: asyncio.StreamReader, ws: ServerConnection) -> None:
    while True:
        chunk = await reader.read(256 * 1024)
        if not chunk:
            return
        await ws.send(chunk)


async def _handle_tcp(ws: ServerConnection) -> None:
    request = ws.request
    assert request is not None
    headers = request.headers
    host = (headers.get("X-Tunnel-Host") or "").strip()
    try:
        port = int(headers.get("X-Tunnel-Port") or "0")
    except ValueError:
        port = 0

    if not host or port < 1 or port > 65535 or port == 25:
        await ws.close(code=1008, reason="invalid destination")
        return

    try:
        ip, family = await _resolve_public(host, port, socket.SOCK_STREAM)
        reader, writer = await asyncio.open_connection(ip, port, family=family)
    except Exception as exc:
        log.warning("TCP connect failed %s:%d: %s", host, port, exc)
        await ws.close(code=1011, reason="connect failed")
        return

    peer = ws.remote_address
    log.info("%s -> TCP %s:%d (%s)", peer, host, port, ip)

    upstream = asyncio.create_task(_pipe_ws_to_tcp(ws, writer))
    downstream = asyncio.create_task(_pipe_tcp_to_ws(reader, ws))
    try:
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
    except Exception as exc:
        log.debug("TCP relay closed %s:%d: %s", host, port, exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _create_udp_socket(family: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    if family == socket.AF_INET:
        sock.bind(("0.0.0.0", 0))
    elif family == socket.AF_INET6:
        sock.bind(("::", 0))
    else:
        sock.close()
        raise ValueError("Unsupported UDP family")
    return sock


async def _udp_ws_to_network(
    ws: ServerConnection,
    sockets: Dict[int, socket.socket],
    allowed_sources: Set[Tuple[str, int]],
) -> None:
    loop = asyncio.get_running_loop()
    cache: Dict[Tuple[str, int], Tuple[str, int]] = {}

    async for message in ws:
        if isinstance(message, str):
            raise ValueError("Text frames aren't supported")
        try:
            host, port, payload = decode_datagram(message)
        except UdpFrameError as exc:
            log.debug("Dropping invalid UDP tunnel frame: %s", exc)
            continue
        if port == 25:
            continue

        key = (host, port)
        resolved = cache.get(key)
        if resolved is None:
            try:
                resolved = await _resolve_public(host, port, socket.SOCK_DGRAM)
            except Exception as exc:
                log.debug("UDP resolve rejected %s:%d: %s", host, port, exc)
                continue
            cache[key] = resolved

        ip, family = resolved
        sock = sockets.get(family)
        if sock is None:
            try:
                sock = _create_udp_socket(family)
            except OSError as exc:
                log.debug("UDP family %s unavailable: %s", family, exc)
                continue
            sockets[family] = sock

        allowed_sources.add((ip, port))
        target = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
        try:
            await loop.sock_sendto(sock, payload, target)
        except OSError as exc:
            log.debug("UDP send failed %s:%d: %s", ip, port, exc)


async def _udp_network_to_ws(
    ws: ServerConnection,
    sock: socket.socket,
    allowed_sources: Set[Tuple[str, int]],
) -> None:
    loop = asyncio.get_running_loop()
    while True:
        payload, source = await loop.sock_recvfrom(sock, 65535)
        host, port = source[0], source[1]
        if (host, port) not in allowed_sources:
            continue
        await ws.send(encode_datagram(host, port, payload))


async def _handle_udp(ws: ServerConnection) -> None:
    sockets: Dict[int, socket.socket] = {}
    allowed_sources: Set[Tuple[str, int]] = set()
    peer = ws.remote_address
    log.info("%s -> UDP association", peer)

    upstream = asyncio.create_task(
        _udp_ws_to_network(ws, sockets, allowed_sources),
        name="relay-udp-upstream",
    )
    receivers: Dict[int, asyncio.Task] = {}

    async def monitor_sockets() -> None:
        try:
            while True:
                for family, sock in list(sockets.items()):
                    if family not in receivers:
                        receivers[family] = asyncio.create_task(
                            _udp_network_to_ws(ws, sock, allowed_sources),
                            name=f"relay-udp-downstream-{family}",
                        )
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            raise

    monitor = asyncio.create_task(monitor_sockets(), name="relay-udp-monitor")
    try:
        await upstream
    except Exception as exc:
        log.debug("UDP relay closed for %s: %s", peer, exc)
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        for task in receivers.values():
            task.cancel()
        if receivers:
            await asyncio.gather(*receivers.values(), return_exceptions=True)
        for sock in sockets.values():
            sock.close()


async def _handle_connection(ws: ServerConnection, token: str) -> None:
    request = ws.request
    if request is None:
        await ws.close(code=1008, reason="missing request")
        return

    if request.headers.get("Authorization") != f"Bearer {token}":
        await ws.close(code=1008, reason="unauthorized")
        return

    path = request.path.split("?", 1)[0]
    if path == "/tunnel":
        await _handle_tcp(ws)
    elif path == "/udp":
        await _handle_udp(ws)
    else:
        await ws.close(code=1008, reason="invalid path")


def _ssl_context(cert: Optional[str], key: Optional[str]) -> Optional[ssl.SSLContext]:
    if not cert and not key:
        return None
    if not cert or not key:
        raise ValueError("Both --cert and --key are required for TLS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WS VPN remote relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default=os.getenv("WS_VPN_TOKEN"))
    parser.add_argument("--cert", help="TLS certificate path; omit when behind a TLS reverse proxy")
    parser.add_argument("--key", help="TLS private key path")
    parser.add_argument("--verbose", action="store_true")
    return parser


async def run_server(args: argparse.Namespace) -> None:
    if not args.token:
        raise RuntimeError("Missing token: pass --token or set WS_VPN_TOKEN")
    ssl_context = _ssl_context(args.cert, args.key)
    async with serve(
        lambda ws: _handle_connection(ws, args.token),
        args.host,
        args.port,
        ssl=ssl_context,
        compression=None,
        max_size=None,
        ping_interval=20,
        ping_timeout=20,
    ) as server:
        scheme = "wss" if ssl_context else "ws"
        log.info("relay listening on %s://%s:%d (TCP /tunnel, UDP /udp)", scheme, args.host, args.port)
        await server.serve_forever()


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run_server(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
