from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Callable

from .config import VpnConfig
from .async_utils import cancel_and_join
from .socks5 import serve
from .version import __version__


def _bundled_tun2socks() -> str:
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        candidate = Path(bundle_root) / "tun2socks.exe"
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError("Bundled runtime unavailable; from source, pass an explicit --tun2socks path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WSS-backed VPN tunnel client")
    parser.add_argument("--version", action="version", version=f"WS VPN {__version__}")
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


async def run(
    config: VpnConfig,
    args: argparse.Namespace,
    *,
    stop_event: asyncio.Event | None = None,
    on_ready: Callable[[], None] | None = None,
) -> None:
    if args.tun:
        if os.name != "nt":
            raise RuntimeError("--tun currently supports Windows only")
        from .windows_native import session_lock
        with session_lock():
            await _run_session(config, args, stop_event=stop_event, on_ready=on_ready)
    else:
        await _run_session(config, args, stop_event=stop_event, on_ready=on_ready)


async def _run_session(config, args, *, stop_event=None, on_ready=None):
    tun = None
    tasks = []
    clean_shutdown = False
    try:
        if args.tun:
            from .windows_tun import WindowsTun
            tun = WindowsTun(
                config, args.tun2socks or _bundled_tun2socks(), args.tun_name,
                dns_server=args.dns, udp_timeout=args.udp_timeout,
                ipv6=not args.no_ipv6, kill_switch=not args.no_kill_switch,
            )
            config = await tun.prepare()
        ready = asyncio.Event()
        socks_task = asyncio.create_task(serve(config, ready=ready), name="socks5-server")
        ready_task = asyncio.create_task(ready.wait())
        tasks.extend((socks_task, ready_task))
        done, _ = await asyncio.wait((socks_task, ready_task), return_when=asyncio.FIRST_COMPLETED)
        if socks_task in done:
            await socks_task
            raise RuntimeError("SOCKS listener stopped during startup")
        if tun:
            await tun.start()
            tasks.append(asyncio.create_task(tun.wait(), name="tun2socks-process"))
        if on_ready:
            on_ready()
        stop_task = None
        if stop_event is not None:
            stop_task = asyncio.create_task(stop_event.wait(), name="vpn-stop-request")
            tasks.append(stop_task)
        waiters = [task for task in tasks if task is not ready_task]
        done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        if stop_task is not None and stop_task in done:
            clean_shutdown = True
            return
        for task in done:
            task.result()
        raise RuntimeError("VPN core stopped unexpectedly; kill switch retained. Run --cleanup after inspection.")
    finally:
        await cancel_and_join(*tasks)
        if tun:
            # All unexpected errors (including startup and SOCKS failure) retain
            # the guard. Only an explicit disconnect releases its ownership.
            await tun.stop(preserve_kill_switch=not clean_shutdown and not args.no_kill_switch)


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
        print("No recorded WS VPN session was found; no network resources were changed.")


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
        asyncio.run(_run_until_signal(config, args))
    except (RuntimeError, ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc


async def _run_until_signal(config: VpnConfig, args: argparse.Namespace) -> None:
    """Translate console signals into the same explicit disconnect as the GUI."""
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    previous: dict[int, object] = {}

    def request_stop(_signum=None, _frame=None) -> None:
        loop.call_soon_threadsafe(stop_event.set)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[sig] = signal.signal(sig, request_stop)
        except (ValueError, OSError):
            pass
    try:
        await run(config, args, stop_event=stop_event)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    main()
