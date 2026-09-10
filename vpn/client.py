from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import sys
from pathlib import Path

from .config import VpnConfig
from .socks5 import serve


def _bundled_tun2socks() -> str:
    candidates = []
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        candidates.append(Path(bundle_root) / "tun2socks.exe")
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / "tun2socks.exe")
    candidates.append(Path.cwd() / "tun2socks.exe")

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    found = shutil.which("tun2socks.exe")
    return found or "tun2socks.exe"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WSS-backed VPN tunnel client")
    parser.add_argument("--relay", help="Relay URL, e.g. wss://vpn.example.com/tunnel")
    parser.add_argument("--token", default=os.getenv("WS_VPN_TOKEN"), help="Tunnel token (or WS_VPN_TOKEN)")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=1080)
    parser.add_argument("--tun", action="store_true", help="Enable system-wide Windows TUN mode")
    parser.add_argument(
        "--tun2socks",
        default=None,
        help="Path to tun2socks executable; bundled Windows builds auto-detect it",
    )
    parser.add_argument("--tun-name", default="wsvpn", help="Wintun adapter name")
    parser.add_argument("--dns", default="1.1.1.1", help="IPv4 DNS server used by the TUN adapter")
    parser.add_argument("--udp-timeout", default="2m", help="tun2socks UDP session timeout")
    parser.add_argument(
        "--no-ipv6",
        action="store_true",
        help="Disable IPv6 TUN routing; public IPv6 remains blocked when the kill switch is enabled",
    )
    parser.add_argument(
        "--no-kill-switch",
        action="store_true",
        help="Disable the Windows fail-closed firewall guard (not recommended)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove stale WS VPN routes/firewall state from a previous crash and exit",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


async def run(config: VpnConfig, args: argparse.Namespace) -> None:
    socks_task = asyncio.create_task(serve(config), name="socks5-server")
    tun = None
    tun_task: asyncio.Task[int] | None = None
    preserve_kill_switch = False
    try:
        await asyncio.sleep(0.1)
        if socks_task.done():
            await socks_task

        if args.tun:
            if os.name != "nt":
                raise RuntimeError("--tun currently supports Windows only")
            from .windows_tun import WindowsTun

            tun2socks_path = args.tun2socks or _bundled_tun2socks()
            tun = WindowsTun(
                config,
                tun2socks_path,
                args.tun_name,
                dns_server=args.dns,
                udp_timeout=args.udp_timeout,
                ipv6=not args.no_ipv6,
                kill_switch=not args.no_kill_switch,
            )
            await tun.start()
            logging.getLogger("ws-vpn").info(
                "System-wide VPN enabled (TCP + UDP, DNS %s, IPv6 %s, kill switch %s)",
                args.dns,
                "on" if not args.no_ipv6 else "off",
                "on" if not args.no_kill_switch else "off",
            )

            tun_task = asyncio.create_task(tun.wait(), name="tun2socks-process")
            done, _pending = await asyncio.wait(
                (socks_task, tun_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if tun_task in done:
                return_code = tun_task.result()
                preserve_kill_switch = not args.no_kill_switch
                raise RuntimeError(
                    f"tun2socks exited unexpectedly with code {return_code}; "
                    "the kill switch remains active. Restart the VPN or run --cleanup as Administrator."
                )
            await socks_task
        else:
            await socks_task
    finally:
        if tun_task and not tun_task.done():
            tun_task.cancel()
            await asyncio.gather(tun_task, return_exceptions=True)
        if tun:
            await tun.stop(preserve_kill_switch=preserve_kill_switch)
        if not socks_task.done():
            socks_task.cancel()
            await asyncio.gather(socks_task, return_exceptions=True)


def _cleanup_windows_state() -> None:
    if os.name != "nt":
        raise SystemExit("--cleanup is only supported on Windows")
    from .windows_guard import cleanup_stale_state
    from .windows_tun import is_admin

    if not is_admin():
        raise SystemExit("--cleanup must be run as Administrator")
    recovered = cleanup_stale_state()
    if recovered:
        print("Recovered stale WS VPN state and removed the kill switch.")
    else:
        print("No recorded WS VPN session was found; stale WS VPN firewall rules were removed if present.")


def main() -> None:
    args = build_parser().parse_args()

    if args.cleanup:
        _cleanup_windows_state()
        return

    if not args.relay:
        raise SystemExit("Missing relay: pass --relay wss://host/tunnel")
    if not args.token:
        raise SystemExit("Missing token: pass --token or set WS_VPN_TOKEN")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = VpnConfig(
        relay_url=args.relay,
        token=args.token,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
    )
    try:
        asyncio.run(run(config, args))
    except KeyboardInterrupt:
        pass
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
