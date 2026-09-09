from __future__ import annotations

import asyncio
import ctypes
import json
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .config import VpnConfig


TUN_NAME = "wsvpn"
TUN_IP = "192.168.123.1"
TUN_MASK = "255.255.255.0"


@dataclass(frozen=True)
class PrimaryRoute:
    interface_alias: str
    interface_index: int
    gateway: str


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _powershell_json(script: str):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        check=True,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    text = result.stdout.strip()
    return json.loads(text) if text else None


def get_primary_route() -> PrimaryRoute:
    data = _powershell_json(
        "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "| Where-Object {$_.NextHop -ne '0.0.0.0'} "
        "| Sort-Object RouteMetric | Select-Object -First 1; "
        "$a = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex; "
        "[pscustomobject]@{alias=$a.Name; index=$r.InterfaceIndex; gateway=$r.NextHop} "
        "| ConvertTo-Json -Compress"
    )
    if not data:
        raise RuntimeError("Could not determine the primary IPv4 route")
    return PrimaryRoute(
        interface_alias=str(data["alias"]),
        interface_index=int(data["index"]),
        gateway=str(data["gateway"]),
    )


def resolve_relay_ipv4(host: str, port: int) -> List[str]:
    addresses = []
    for info in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        ip = info[4][0]
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise RuntimeError(f"Could not resolve relay host: {host}")
    return addresses


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args),
        check=check,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


class WindowsTun:
    def __init__(self, config: VpnConfig, tun2socks_path: str, tun_name: str = TUN_NAME):
        if os.name != "nt":
            raise RuntimeError("WindowsTun can only run on Windows")
        self.config = config
        self.tun_name = tun_name
        self.tun2socks_path = shutil.which(tun2socks_path) or tun2socks_path
        self.primary: Optional[PrimaryRoute] = None
        self.relay_ips: List[str] = []
        self.process: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> None:
        if not is_admin():
            raise PermissionError("VPN mode must be run as Administrator")
        if not os.path.exists(self.tun2socks_path) and not shutil.which(self.tun2socks_path):
            raise FileNotFoundError(f"tun2socks not found: {self.tun2socks_path}")

        self.primary = get_primary_route()
        self.relay_ips = resolve_relay_ipv4(self.config.relay_host, self.config.relay_port)

        self.process = await asyncio.create_subprocess_exec(
            self.tun2socks_path,
            "--device", f"tun://{self.tun_name}",
            "--proxy", f"socks5://{self.config.listen_host}:{self.config.listen_port}",
            "--interface", self.primary.interface_alias,
            "--loglevel", "info",
        )

        await self._wait_for_adapter()
        _run(
            "netsh", "interface", "ipv4", "set", "address",
            f"name={self.tun_name}", "source=static",
            f"address={TUN_IP}", f"mask={TUN_MASK}", "gateway=none",
        )

        for ip in self.relay_ips:
            _run(
                "route", "add", ip, "mask", "255.255.255.255",
                self.primary.gateway, "if", str(self.primary.interface_index),
                "metric", "1",
            )

        _run(
            "netsh", "interface", "ipv4", "add", "route",
            "0.0.0.0/0", self.tun_name, TUN_IP, "metric=1",
        )

    async def _wait_for_adapter(self) -> None:
        for _ in range(50):
            result = _run(
                "powershell", "-NoProfile", "-Command",
                f"if (Get-NetAdapter -Name '{self.tun_name}' -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
                check=False,
            )
            if result.returncode == 0:
                return
            if self.process and self.process.returncode is not None:
                raise RuntimeError(f"tun2socks exited with code {self.process.returncode}")
            await asyncio.sleep(0.1)
        raise RuntimeError(f"TUN adapter '{self.tun_name}' did not appear")

    async def stop(self) -> None:
        _run(
            "netsh", "interface", "ipv4", "delete", "route",
            "0.0.0.0/0", self.tun_name, check=False,
        )
        if self.primary:
            for ip in self.relay_ips:
                _run("route", "delete", ip, check=False)

        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
