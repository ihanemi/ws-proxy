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
    parser.add_argument("--verbose", action="store_true")
    return parser


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
        asyncio.run(serve(config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
