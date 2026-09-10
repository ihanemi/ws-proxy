from __future__ import annotations

import asyncio
import ctypes
import ipaddress
import json
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .config import VpnConfig
from .windows_guard import (
    GuardState,
    cleanup_stale_state,
    clear_state,
    install_kill_switch,
    remove_kill_switch,
    save_state,
)


TUN_NAME = "wsvpn"
TUN_IPV4 = "192.168.123.1"
TUN_IPV4_MASK = "255.255.255.0"
TUN_IPV6 = "fd42:4242:4242::1"
TUN_IPV6_PREFIX = 64


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


def _powershell(script: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=check,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _powershell_json(script: str):
    result = _powershell(script)
    text = result.stdout.strip()
    return json.loads(text) if text else None


def _ps_quote(value: str) -> str:
    return value.replace("'", "''")


def get_primary_route() -> PrimaryRoute:
    data = _powershell_json(
        "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "| Where-Object {$_.NextHop -ne '0.0.0.0'} "
        "| Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; "
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
    addresses: List[str] = []
    for info in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        ip = info[4][0]
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise RuntimeError(
            f"Relay host {host!r} has no IPv4 address; Windows TUN mode requires an A record"
        )
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
    def __init__(
        self,
        config: VpnConfig,
        tun2socks_path: str,
        tun_name: str = TUN_NAME,
        *,
        dns_server: str = "1.1.1.1",
        udp_timeout: str = "2m",
        ipv6: bool = True,
        kill_switch: bool = True,
    ):
        if os.name != "nt":
            raise RuntimeError("WindowsTun can only run on Windows")
        try:
            dns = ipaddress.ip_address(dns_server)
        except ValueError as exc:
            raise ValueError("--dns must be an IP address") from exc
        if not isinstance(dns, ipaddress.IPv4Address):
            raise ValueError("--dns currently supports IPv4 only")

        self.config = config
        self.tun_name = tun_name
        self.dns_server = str(dns)
        self.udp_timeout = udp_timeout
        self.ipv6 = ipv6
        self.kill_switch = kill_switch
        self.tun2socks_path = shutil.which(tun2socks_path) or tun2socks_path
        self.primary: Optional[PrimaryRoute] = None
        self.relay_ips: List[str] = []
        self.process: Optional[asyncio.subprocess.Process] = None
        self._state: Optional[GuardState] = None

    async def start(self) -> None:
        if not is_admin():
            raise PermissionError("VPN mode must be run as Administrator")
        if not os.path.exists(self.tun2socks_path) and not shutil.which(self.tun2socks_path):
            raise FileNotFoundError(f"tun2socks not found: {self.tun2socks_path}")

        wintun_path = os.path.join(os.path.dirname(os.path.abspath(self.tun2socks_path)), "wintun.dll")
        if not os.path.exists(wintun_path):
            raise FileNotFoundError(
                f"wintun.dll must be next to tun2socks: {wintun_path}"
            )

        # A previous hard crash intentionally leaves the kill switch behind.
        # On a new explicit start, recover that recorded session before building
        # a fresh fail-closed state.
        cleanup_stale_state()

        self.primary = get_primary_route()
        self.relay_ips = resolve_relay_ipv4(self.config.relay_host, self.config.relay_port)

        # Pin the relay outside the future default TUN route first. The firewall
        # rules exclude these exact IPv4 endpoints so the WSS control channel
        # remains reachable while other public traffic is fail-closed.
        for ip in self.relay_ips:
            _run(
                "route", "add", ip, "mask", "255.255.255.255",
                self.primary.gateway, "if", str(self.primary.interface_index),
                "metric", "1",
            )

        if self.kill_switch:
            install_kill_switch(self.primary.interface_alias, self.relay_ips)

        self._state = GuardState(
            version=1,
            tun_name=self.tun_name,
            primary_interface_alias=self.primary.interface_alias,
            primary_interface_index=self.primary.interface_index,
            primary_gateway=self.primary.gateway,
            relay_ips=list(self.relay_ips),
            ipv6=self.ipv6,
            kill_switch=self.kill_switch,
            tun2socks_path=os.path.abspath(self.tun2socks_path),
        )
        save_state(self._state)

        self.process = await asyncio.create_subprocess_exec(
            self.tun2socks_path,
            "--device", f"tun://{self.tun_name}",
            "--proxy", f"socks5://{self.config.listen_host}:{self.config.listen_port}",
            "--interface", self.primary.interface_alias,
            "--udp-timeout", self.udp_timeout,
            "--loglevel", "info",
            cwd=os.path.dirname(os.path.abspath(self.tun2socks_path)) or None,
        )
        self._state.tun2socks_pid = self.process.pid
        save_state(self._state)

        await self._wait_for_adapter()
        self._configure_ipv4()

        _run(
            "netsh", "interface", "ipv4", "add", "route",
            "0.0.0.0/0", self.tun_name, TUN_IPV4, "metric=1",
        )

        if self.ipv6:
            self._configure_ipv6()

    def _configure_ipv4(self) -> None:
        _run(
            "netsh", "interface", "ipv4", "set", "address",
            f"name={self.tun_name}", "source=static",
            f"address={TUN_IPV4}", f"mask={TUN_IPV4_MASK}", "gateway=none",
        )
        _run(
            "netsh", "interface", "ipv4", "set", "dnsservers",
            f"name={self.tun_name}", "source=static",
            f"address={self.dns_server}", "register=none", "validate=no",
        )

    def _configure_ipv6(self) -> None:
        alias = _ps_quote(self.tun_name)
        script = (
            f"$a = Get-NetAdapter -Name '{alias}' -ErrorAction Stop; "
            "$idx = $a.ifIndex; "
            f"Get-NetRoute -InterfaceIndex $idx -AddressFamily IPv6 -DestinationPrefix '::/0' "
            "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; "
            f"Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv6 -IPAddress '{TUN_IPV6}' "
            "-ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
            f"New-NetIPAddress -InterfaceIndex $idx -IPAddress '{TUN_IPV6}' "
            f"-PrefixLength {TUN_IPV6_PREFIX} -AddressFamily IPv6 -PolicyStore ActiveStore | Out-Null; "
            "New-NetRoute -DestinationPrefix '::/0' -InterfaceIndex $idx -NextHop '::' "
            "-RouteMetric 1 -PolicyStore ActiveStore | Out-Null"
        )
        _powershell(script)

    async def _wait_for_adapter(self) -> None:
        alias = _ps_quote(self.tun_name)
        for _ in range(80):
            result = _powershell(
                f"if (Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue) "
                "{ exit 0 } else { exit 1 }",
                check=False,
            )
            if result.returncode == 0:
                return
            if self.process and self.process.returncode is not None:
                raise RuntimeError(f"tun2socks exited with code {self.process.returncode}")
            await asyncio.sleep(0.1)
        raise RuntimeError(f"TUN adapter '{self.tun_name}' did not appear")

    async def wait(self) -> int:
        if self.process is None:
            raise RuntimeError("tun2socks has not been started")
        return await self.process.wait()

    async def stop(self, *, preserve_kill_switch: bool = False) -> None:
        if preserve_kill_switch:
            # On unexpected tun2socks death, leave the persistent firewall/state
            # untouched. A later VPN start or `WsVpn.exe --cleanup` recovers it.
            return

        _run(
            "netsh", "interface", "ipv4", "delete", "route",
            "0.0.0.0/0", self.tun_name, check=False,
        )

        if self.ipv6:
            alias = _ps_quote(self.tun_name)
            _powershell(
                f"$a = Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue; "
                "if ($a) { "
                "$idx = $a.ifIndex; "
                "Get-NetRoute -InterfaceIndex $idx -AddressFamily IPv6 -DestinationPrefix '::/0' "
                "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; "
                f"Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv6 -IPAddress '{TUN_IPV6}' "
                "-ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue "
                "}",
                check=False,
            )

        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()

        if self.primary:
            for ip in self.relay_ips:
                destination = f"{ip}/32"
                _powershell(
                    f"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{destination}' "
                    f"-InterfaceIndex {self.primary.interface_index} "
                    f"-NextHop '{_ps_quote(self.primary.gateway)}' -ErrorAction SilentlyContinue "
                    "| Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
                    check=False,
                )

        if self.kill_switch:
            remove_kill_switch()
        clear_state()
