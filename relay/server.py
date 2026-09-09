from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import ssl
from typing import Iterable, Optional, Tuple

from websockets.asyncio.server import ServerConnection, serve


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


async def _resolve_public(host: str, port: int) -> Tuple[str, int]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=0)
    seen = set()
    for family, socktype, proto, canonname, sockaddr in infos:
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


async def _handle_connection(ws: ServerConnection, token: str) -> None:
    request = ws.request
    if request is None or request.path.split("?", 1)[0] != "/tunnel":
        await ws.close(code=1008, reason="invalid path")
        return

    headers = request.headers
    if headers.get("Authorization") != f"Bearer {token}":
        await ws.close(code=1008, reason="unauthorized")
        return

    host = (headers.get("X-Tunnel-Host") or "").strip()
    try:
        port = int(headers.get("X-Tunnel-Port") or "0")
    except ValueError:
        port = 0

    if not host or port < 1 or port > 65535 or port == 25:
        await ws.close(code=1008, reason="invalid destination")
        return

    try:
        ip, family = await _resolve_public(host, port)
        reader, writer = await asyncio.open_connection(ip, port, family=family)
    except Exception as exc:
        log.warning("connect failed %s:%d: %s", host, port, exc)
        await ws.close(code=1011, reason="connect failed")
        return

    peer = ws.remote_address
    log.info("%s -> %s:%d (%s)", peer, host, port, ip)

    a = asyncio.create_task(_pipe_ws_to_tcp(ws, writer))
    b = asyncio.create_task(_pipe_tcp_to_ws(reader, ws))
    try:
        done, pending = await asyncio.wait((a, b), return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            exc = task.exception()
            if exc:
                raise exc
    except Exception as exc:
        log.debug("relay closed %s:%d: %s", host, port, exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


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
        log.info("relay listening on %s://%s:%d/tunnel", scheme, args.host, args.port)
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
