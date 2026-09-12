from __future__ import annotations

import asyncio
import ctypes
import ipaddress
import os
import re
import socket
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from .config import VpnConfig
from .windows_guard import (
    STATE_VERSION, GuardState, _powershell, _powershell_json, add_route,
    cleanup_recorded_state, install_kill_switch, load_state, save_state, validate_tun_name,
)
from .windows_native import process_identity

TUN_NAME = "wsvpn"
TUN_IPV4 = "192.168.123.1"
TUN_IPV6 = "fd42:4242:4242::1"
TUN_IPV6_PREFIX = 64


@dataclass(frozen=True)
class PrimaryRoute:
    interface_alias: str
    interface_index: int
    gateway: str
    interface_guid: str


def is_admin() -> bool:
    if os.name != "nt":
        return False
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.IsUserAnAdmin.argtypes = []
    shell.IsUserAnAdmin.restype = ctypes.c_int
    return bool(shell.IsUserAnAdmin())


def get_adapters() -> list[dict]:
    data = _powershell_json(
        "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden | ForEach-Object { "
        "[pscustomobject]@{alias=$_.Name; index=$_.ifIndex; guid=$_.InterfaceGuid.ToString().Trim('{}')} })"
    )
    return data or []


def get_primary_route() -> PrimaryRoute:
    data = _powershell_json(
        "$interfaces=@(Get-NetIPInterface -AddressFamily IPv4 | Where-Object ConnectionState -eq 'Connected'); "
        "$routes=@(Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "| Where-Object NextHop -ne '0.0.0.0' | ForEach-Object { "
        "$r=$_; $i=$interfaces | Where-Object InterfaceIndex -eq $r.InterfaceIndex | Select-Object -First 1; "
        "if ($i) { [pscustomobject]@{index=$r.InterfaceIndex; gateway=$r.NextHop; "
        "metric=([int]$r.RouteMetric+[int]$i.InterfaceMetric)} } }); "
        "$r=$routes | Sort-Object metric,index | Select-Object -First 1; "
        "if (-not $r) { throw 'No connected IPv4 default route' }; "
        "$a=Get-NetAdapter -IncludeHidden | Where-Object ifIndex -eq $r.index | Select-Object -First 1; "
        "if (-not $a) { throw 'Default route adapter unavailable' }; "
        "[pscustomobject]@{alias=$a.Name; index=$r.index; gateway=$r.gateway; guid=$a.InterfaceGuid.ToString().Trim('{}')} "
        "| ConvertTo-Json -Compress"
    )
    return PrimaryRoute(data["alias"], int(data["index"]), data["gateway"], data["guid"])


def resolve_relay_ipv4(host: str, port: int) -> list[str]:
    addresses = list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(
        host, port, socket.AF_INET, socket.SOCK_STREAM,
    )))
    if not addresses or len(addresses) > 32:
        raise RuntimeError("Windows TUN mode requires 1 to 32 relay IPv4 A records")
    return addresses


class WindowsTun:
    def __init__(self, config: VpnConfig, tun2socks_path: str, tun_name=TUN_NAME, *,
                 dns_server="1.1.1.1", udp_timeout="2m", ipv6=True, kill_switch=True):
        if os.name != "nt":
            raise RuntimeError("WindowsTun requires Windows")
        validate_tun_name(tun_name)
        dns = ipaddress.ip_address(dns_server)
        if not isinstance(dns, ipaddress.IPv4Address) or not dns.is_global:
            raise ValueError("DNS must be a public IPv4 address reachable through the relay")
        if not re.fullmatch(r"[1-9][0-9]{0,3}(ms|s|m)", udp_timeout):
            raise ValueError("UDP timeout must be a positive duration such as 30s or 2m")
        self.config = config
        self.tun_name = tun_name
        self.dns_server = str(dns)
        self.udp_timeout = udp_timeout
        self.ipv6 = ipv6
        self.kill_switch = kill_switch
        self.tun2socks_path = str(Path(tun2socks_path).resolve(strict=True))
        self.primary = None
        self.relay_ips = []
        self.process = None
        self._state = None
        self.adapter = None
        self.adapters = []

    async def prepare(self) -> VpnConfig:
        if not is_admin():
            raise PermissionError("VPN mode must be run as Administrator")
        if not Path(self.tun2socks_path).is_file() or not Path(self.tun2socks_path).with_name("wintun.dll").is_file():
            raise FileNotFoundError("tun2socks.exe and wintun.dll must exist in the selected runtime directory")
        if load_state() is not None:
            raise RuntimeError("A recorded WS VPN session requires explicit --cleanup before a new connection")
        self.adapters = get_adapters()
        if any(a["alias"].casefold() == self.tun_name.casefold() for a in self.adapters):
            raise RuntimeError("The requested adapter name already exists; WS VPN will not modify it")
        self.primary = get_primary_route()
        self.relay_ips = await asyncio.wait_for(asyncio.to_thread(
            resolve_relay_ipv4, self.config.relay_host, self.config.relay_port,
        ), self.config.connect_timeout)
        # The exact same snapshot is used by route creation and every WSS dial.
        self.config = replace(self.config, relay_ips=tuple(self.relay_ips))
        return self.config

    async def start(self) -> None:
        if self.primary is None:
            raise RuntimeError("Prepare the Windows session before starting it")
        self._state = GuardState(
            version=STATE_VERSION, session_id=uuid.uuid4().hex,
            tun_name=self.tun_name, primary_interface_alias=self.primary.interface_alias,
            primary_interface_index=self.primary.interface_index, primary_gateway=self.primary.gateway,
            relay_ips=list(self.relay_ips), ipv6=self.ipv6, kill_switch=self.kill_switch,
        )
        save_state(self._state)
        if self.kill_switch:
            install_kill_switch(self._state, self.adapters)
        primary_adapter = {"index": self.primary.interface_index, "guid": self.primary.interface_guid}
        for ip in self.relay_ips:
            add_route(self._state, prefix=ip + "/32", next_hop=self.primary.gateway, adapter=primary_adapter)

        self.process = await asyncio.create_subprocess_exec(
            self.tun2socks_path, "--device", f"tun://{self.tun_name}",
            "--proxy", f"socks5://{self.config.listen_host}:{self.config.listen_port}",
            "--udp-timeout", self.udp_timeout, "--loglevel", "warning",
            # Only Python's WSS transport needs a physical bypass. Binding the
            # loopback SOCKS dial to a physical interface is unnecessary.
            cwd=str(Path(self.tun2socks_path).parent),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        identity = process_identity(self.process.pid)
        if identity is None:
            raise RuntimeError("tun2socks exited during startup; kill switch retained")
        self._state.tun2socks_pid = identity.pid
        self._state.tun2socks_created = identity.created
        self._state.tun2socks_path = identity.path
        save_state(self._state)
        await self._wait_for_adapter()
        index = int(self.adapter["index"])
        _powershell(
            f"Set-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv4 -Dhcp Disabled "
            "-AutomaticMetric Disabled -InterfaceMetric 1; "
            f"New-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 -IPAddress '{TUN_IPV4}' "
            "-PrefixLength 24 -PolicyStore ActiveStore | Out-Null; "
            f"Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses '{self.dns_server}'"
        )
        add_route(self._state, prefix="0.0.0.0/0", next_hop="0.0.0.0", adapter=self.adapter)
        if self.ipv6:
            _powershell(
                f"Set-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv6 "
                "-AutomaticMetric Disabled -InterfaceMetric 1; "
                f"New-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv6 -IPAddress '{TUN_IPV6}' "
                f"-PrefixLength {TUN_IPV6_PREFIX} -PolicyStore ActiveStore | Out-Null"
            )
            add_route(self._state, prefix="::/0", next_hop="::", adapter=self.adapter)

    async def _wait_for_adapter(self) -> None:
        for _ in range(80):
            if self.process.returncode is not None:
                raise RuntimeError("tun2socks exited before the adapter became available")
            adapters = get_adapters()
            matches = [a for a in adapters if a["alias"].casefold() == self.tun_name.casefold()]
            if len(matches) == 1:
                # New adapter must not reuse an adapter present in the snapshot.
                if matches[0]["guid"] in {a["guid"] for a in self.adapters}:
                    raise RuntimeError("Adapter identity conflict; existing adapter was left unchanged")
                self.adapter = matches[0]
                return
            await asyncio.sleep(.1)
        raise RuntimeError("Wintun adapter did not appear; recovery is required")

    async def wait(self):
        if self.process is None:
            raise RuntimeError("tun2socks hasn't started")
        return await self.process.wait()

    async def stop(self, *, preserve_kill_switch=False):
        # The owning caller holds the machine-wide lock until cleanup finishes.
        if self._state is None:
            return
        if preserve_kill_switch:
            # An unexpected core failure must not leave an unmonitored child
            # accepting packets. Keep the exact recovery journal and firewall
            # guard, but stop the process through the handle we created.
            if self.process is not None and self.process.returncode is None:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), 5)
            return
        cleanup_recorded_state(self._state)
        if self.process is not None:
            await asyncio.wait_for(self.process.wait(), 5)
        self._state = None
