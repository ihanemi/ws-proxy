from __future__ import annotations

import argparse
import asyncio
import logging
import os

from .config import VpnConfig
from .socks5 import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WSS-backed VPN tunnel client")
    parser.add_argument("--worker", required=True, help="Worker URL, e.g. wss://name.workers.dev/tunnel")
    parser.add_argument("--token", default=os.getenv("WS_VPN_TOKEN"), help="Tunnel token (or WS_VPN_TOKEN)")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=1080)
    parser.add_argument("--tun", action="store_true", help="Enable system-wide Windows TUN mode")
    parser.add_argument("--tun2socks", default="tun2socks.exe", help="Path to tun2socks executable")
    parser.add_argument("--tun-name", default="wsvpn", help="Wintun adapter name")
    parser.add_argument("--verbose", action="store_true")
    return parser


async def run(config: VpnConfig, args: argparse.Namespace) -> None:
    socks_task = asyncio.create_task(serve(config), name="socks5-server")
    tun = None
    try:
        await asyncio.sleep(0.1)
        if socks_task.done():
            await socks_task

        if args.tun:
            if os.name != "nt":
                raise RuntimeError("--tun currently supports Windows only")
            from .windows_tun import WindowsTun

            tun = WindowsTun(config, args.tun2socks, args.tun_name)
            await tun.start()
            logging.getLogger("ws-vpn").info("System-wide VPN mode enabled")

        await socks_task
    finally:
        if tun:
            await tun.stop()
        if not socks_task.done():
            socks_task.cancel()
            await asyncio.gather(socks_task, return_exceptions=True)


def main() -> None:
    args = build_parser().parse_args()
    if not args.token:
        raise SystemExit("Missing token: pass --token or set WS_VPN_TOKEN")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = VpnConfig(
        worker_url=args.worker,
        token=args.token,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
    )
    try:
        asyncio.run(run(config, args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
