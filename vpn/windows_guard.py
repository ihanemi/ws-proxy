from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


FIREWALL_GROUP = "WS VPN Kill Switch"
FIREWALL_PREFIX = "WSVPN-KillSwitch"
STATE_VERSION = 1

# These destinations stay reachable on the physical interface. The kill switch
# targets public Internet traffic; loopback/LAN/link-local traffic is left alone.
_IPV4_LOCAL_EXEMPT = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
)

_IPV6_LOCAL_EXEMPT = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


@dataclass
class GuardState:
    version: int
    tun_name: str
    primary_interface_alias: str
    primary_interface_index: int
    primary_gateway: str
    relay_ips: List[str]
    ipv6: bool
    kill_switch: bool
    tun2socks_pid: int | None = None
    tun2socks_path: str | None = None


def _state_path() -> Path:
    override = os.getenv("WS_VPN_STATE_PATH")
    if override:
        return Path(override)
    root = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    return root / "WsVpn" / "state.json"


def _powershell(script: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=check,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _ps_quote(value: str) -> str:
    return value.replace("'", "''")


def _subtract_networks(
    base: ipaddress.IPv4Network | ipaddress.IPv6Network,
    exclusions: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    remaining: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [base]
    for exclusion in exclusions:
        updated: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for network in remaining:
            if network.version != exclusion.version or not network.overlaps(exclusion):
                updated.append(network)
            elif network.subnet_of(exclusion):
                continue
            elif exclusion.subnet_of(network):
                updated.extend(network.address_exclude(exclusion))
        remaining = updated
    return list(ipaddress.collapse_addresses(remaining))


def ipv4_kill_switch_networks(relay_ips: Sequence[str]) -> List[str]:
    exclusions: List[ipaddress.IPv4Network] = list(_IPV4_LOCAL_EXEMPT)
    for value in relay_ips:
        address = ipaddress.ip_address(value)
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError(f"Relay address is not IPv4: {value}")
        exclusions.append(ipaddress.ip_network(f"{address}/32"))
    networks = _subtract_networks(ipaddress.ip_network("0.0.0.0/0"), exclusions)
    return [str(network) for network in networks]


def ipv6_kill_switch_networks() -> List[str]:
    networks = _subtract_networks(ipaddress.ip_network("::/0"), _IPV6_LOCAL_EXEMPT)
    return [str(network) for network in networks]


def _chunks(values: Sequence[str], size: int = 48) -> Iterable[Sequence[str]]:
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def remove_kill_switch() -> None:
    _powershell(
        f"Get-NetFirewallRule -Name '{FIREWALL_PREFIX}-*' -ErrorAction SilentlyContinue "
        "| Remove-NetFirewallRule -ErrorAction SilentlyContinue",
        check=False,
    )


def _create_block_rules(interface_alias: str, family: str, networks: Sequence[str]) -> List[str]:
    alias = _ps_quote(interface_alias)
    names: List[str] = []
    for index, chunk in enumerate(_chunks(networks), start=1):
        name = f"{FIREWALL_PREFIX}-{family}-{index}"
        display_name = f"WS VPN Kill Switch {family.upper()} #{index}"
        values = ",".join(f"'{_ps_quote(value)}'" for value in chunk)
        script = (
            f"$remote = @({values}); "
            f"New-NetFirewallRule -Name '{name}' -DisplayName '{display_name}' "
            f"-Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block "
            f"-Enabled True -Profile Any -InterfaceAlias '{alias}' "
            "-RemoteAddress $remote | Out-Null"
        )
        _powershell(script)
        names.append(name)
    return names


def install_kill_switch(interface_alias: str, relay_ips: Sequence[str]) -> List[str]:
    # Remove only our own stale rule names. New rules are persistent by design,
    # so a hard process crash leaves the machine fail-closed.
    remove_kill_switch()
    names: List[str] = []
    try:
        names.extend(
            _create_block_rules(
                interface_alias,
                "ipv4",
                ipv4_kill_switch_networks(relay_ips),
            )
        )
        # IPv6 is blocked on the physical interface even when IPv6 TUN routing
        # is disabled. That turns --no-ipv6 into "no public IPv6" rather than a leak.
        names.extend(
            _create_block_rules(
                interface_alias,
                "ipv6",
                ipv6_kill_switch_networks(),
            )
        )
    except Exception:
        remove_kill_switch()
        raise
    return names


def save_state(state: GuardState) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
    os.replace(temporary, path)


def load_state() -> GuardState | None:
    path = _state_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if int(data.get("version", 0)) != STATE_VERSION:
            return None
        return GuardState(**data)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def clear_state() -> None:
    try:
        _state_path().unlink(missing_ok=True)
    except OSError:
        pass


def _remove_recorded_routes(state: GuardState) -> None:
    alias = _ps_quote(state.tun_name)
    _powershell(
        f"$a = Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue; "
        "if ($a) { "
        "$idx = $a.ifIndex; "
        "Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; "
        "Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '::/0' "
        "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue "
        "}",
        check=False,
    )

    gateway = _ps_quote(state.primary_gateway)
    for relay_ip in state.relay_ips:
        destination = _ps_quote(f"{relay_ip}/32")
        _powershell(
            f"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{destination}' "
            f"-InterfaceIndex {state.primary_interface_index} -NextHop '{gateway}' "
            "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
            check=False,
        )


def _stop_recorded_tun2socks(state: GuardState) -> None:
    if not state.tun2socks_pid or not state.tun2socks_path:
        return
    expected = _ps_quote(str(Path(state.tun2socks_path).resolve()))
    script = (
        f"$p = Get-CimInstance Win32_Process -Filter \"ProcessId = {state.tun2socks_pid}\" "
        "-ErrorAction SilentlyContinue; "
        f"if ($p -and $p.ExecutablePath -and ($p.ExecutablePath -ieq '{expected}')) {{ "
        f"Stop-Process -Id {state.tun2socks_pid} -Force -ErrorAction SilentlyContinue }}"
    )
    _powershell(script, check=False)


def cleanup_stale_state() -> bool:
    state = load_state()
    if state is not None:
        _stop_recorded_tun2socks(state)
        _remove_recorded_routes(state)
    remove_kill_switch()
    clear_state()
    return state is not None
