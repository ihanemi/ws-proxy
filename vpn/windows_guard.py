from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import stat
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Iterable, List, Sequence

from .windows_native import (
    ProcessIdentity, create_private_directory, session_lock,
    stop_recorded_process, system_executable, write_private_state,
)

FIREWALL_GROUP = "WS VPN Kill Switch"
FIREWALL_PREFIX = "WSVPN-KillSwitch"
STATE_VERSION = 2


@dataclass
class GuardState:
    version: int
    session_id: str
    tun_name: str
    primary_interface_alias: str
    primary_interface_index: int
    primary_gateway: str
    relay_ips: list[str]
    ipv6: bool
    kill_switch: bool
    tun2socks_pid: int | None = None
    tun2socks_path: str | None = None
    tun2socks_created: int | None = None
    routes: list[dict] = field(default_factory=list)
    firewall_names: list[str] = field(default_factory=list)


def validate_tun_name(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value):
        raise ValueError("TUN name must contain 1 to 32 letters, numbers, underscores or hyphens")


def _state_path() -> Path:
    if os.name == "nt":
        # Do not use environment-supplied paths for elevated recovery input.
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        fn = shell.SHGetFolderPathW
        fn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint, ctypes.c_wchar_p]
        fn.restype = ctypes.c_long
        if fn(None, 0x23, None, 0, buffer) != 0:  # CSIDL_COMMON_APPDATA
            raise OSError("Cannot locate ProgramData")
        return Path(buffer.value) / "WsVpn" / "state.json"
    return Path(os.environ.get("WS_VPN_STATE_PATH", "state.json"))


def _ps_quote(value: str) -> str:
    return value.replace("'", "''")


def _powershell(script: str, *, check: bool = True) -> subprocess.CompletedProcess:
    executable = system_executable(r"WindowsPowerShell\v1.0\powershell.exe") if os.name == "nt" else "powershell"
    environment = os.environ.copy()
    if os.name == "nt":
        # A PowerShell 7 parent (including GitHub Actions' pwsh shell) exports a
        # PSModulePath containing Core-only modules.  Windows PowerShell 5.1 may
        # select those incompatible modules before its inbox networking and ACL
        # modules, making Get-Acl/Get-NetRoute fail to import.  Let 5.1 rebuild
        # its own trusted default module path instead.
        environment.pop("PSModulePath", None)
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command",
         "$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())); "
         "& ([ScriptBlock]::Create($s))"],
        input=base64.b64encode(("$ErrorActionPreference='Stop'; try { " + script
                               + " } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }").encode("utf-16-le")).decode("ascii"),
        capture_output=True, text=True, timeout=60,
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if check and result.returncode:
        raise RuntimeError("Windows networking command failed; recovery state retained. " + result.stderr.strip()[-2000:])
    return result


def _powershell_json(script: str):
    output = _powershell(script).stdout.strip()
    return json.loads(output) if output else None


def _secure_directory(path: Path, *, create: bool) -> None:
    directory = path.parent
    if not directory.exists():
        if not create:
            return
        if os.name == "nt":
            create_private_directory(str(directory))
        else:
            directory.mkdir(mode=0o700, parents=True)
    for candidate in (directory, path):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("Refusing reparse point in WS VPN recovery storage")
        if candidate == path and not stat.S_ISREG(info.st_mode):
            raise RuntimeError("Recovery state is not a regular file")
        if candidate == path and info.st_nlink != 1:
            raise RuntimeError("Refusing hard-linked recovery state")
    if os.name == "nt":
        # Never tighten an old, user-writable directory and then trust its data.
        # It must already have been securely created by this implementation.
        paths = [directory] + ([path] if path.exists() else [])
        values = ",".join(f"'{_ps_quote(str(value))}'" for value in paths)
        _powershell(
            f"foreach($path in @({values})) {{ $acl=Get-Acl -LiteralPath $path; "
            "$owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; "
            "if ($owner -notin @('S-1-5-18','S-1-5-32-544') -or -not $acl.AreAccessRulesProtected) "
            "{ throw 'Untrusted legacy state directory; inspect and migrate it before using this client' }; "
            "$rules=$acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]); "
            "foreach($r in $rules) { if ($r.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') "
            "-or $r.AccessControlType -ne 'Allow') { throw 'Untrusted recovery ACL' } } }"
        )


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _validate_state(state: GuardState) -> None:
    if state.version != STATE_VERSION or type(state.version) is not int:
        raise ValueError("Legacy or unsupported recovery state; automatic migration is unsafe")
    if not isinstance(state.session_id, str) or not re.fullmatch(r"[0-9a-f]{32}", state.session_id):
        raise ValueError("Invalid recovery session identifier")
    validate_tun_name(state.tun_name)
    if not isinstance(state.primary_interface_alias, str) or not state.primary_interface_alias or any(
        ord(c) < 32 for c in state.primary_interface_alias
    ):
        raise ValueError("Invalid physical interface")
    if not _integer(state.primary_interface_index, 1, 2**32 - 1):
        raise ValueError("Invalid interface index")
    ipaddress.IPv4Address(state.primary_gateway)
    if type(state.ipv6) is not bool or type(state.kill_switch) is not bool:
        raise ValueError("Invalid recovery flags")
    if type(state.relay_ips) is not list or not 1 <= len(state.relay_ips) <= 32:
        raise ValueError("Invalid recorded relay addresses")
    for value in state.relay_ips:
        if not isinstance(value, str):
            raise ValueError("Invalid relay address")
        ipaddress.IPv4Address(value)
    if state.tun2socks_pid is not None and not _integer(state.tun2socks_pid, 1, 2**32 - 1):
        raise ValueError("Invalid recorded process ID")
    if state.tun2socks_created is not None and not _integer(state.tun2socks_created, 1, 2**64 - 1):
        raise ValueError("Invalid process creation time")
    if state.tun2socks_pid is not None and (not state.tun2socks_created or not state.tun2socks_path):
        raise ValueError("Process recovery requires PID, path and creation time")
    if state.tun2socks_path is not None and (
        not isinstance(state.tun2socks_path, str) or not PureWindowsPath(state.tun2socks_path).is_absolute()
        or any(ord(c) < 32 for c in state.tun2socks_path)
    ):
        raise ValueError("Invalid process path")
    if type(state.firewall_names) is not list or len(state.firewall_names) > 4096:
        raise ValueError("Invalid firewall journal")
    pattern = re.compile(rf"{FIREWALL_PREFIX}-{state.session_id}-[A-Za-z0-9-]+")
    for name in state.firewall_names:
        if not isinstance(name, str) or not pattern.fullmatch(name):
            raise ValueError("Foreign firewall name in recovery state")
    if type(state.routes) is not list or len(state.routes) > 34:
        raise ValueError("Invalid route journal")
    for route in state.routes:
        if type(route) is not dict or set(route) != {"prefix", "next_hop", "interface_index", "interface_guid", "metric", "created"}:
            raise ValueError("Invalid route record")
        prefix = ipaddress.ip_network(route["prefix"], strict=True)
        hop = ipaddress.ip_address(route["next_hop"])
        if prefix.version != hop.version or not _integer(route["interface_index"], 1, 2**32 - 1):
            raise ValueError("Invalid route identity")
        if not isinstance(route["interface_guid"], str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", route["interface_guid"]):
            raise ValueError("Invalid adapter identity")
        if not _integer(route["metric"], 1, 65535) or type(route["created"]) is not bool:
            raise ValueError("Invalid route ownership marker")
        if str(prefix) not in ("0.0.0.0/0", "::/0", *(ip + "/32" for ip in state.relay_ips)):
            raise ValueError("Unrelated route in recovery state")


def save_state(state: GuardState) -> None:
    _validate_state(state)
    path = _state_path()
    _secure_directory(path, create=True)
    if os.name == "nt":
        write_private_state(str(path), json.dumps(asdict(state), indent=2).encode("utf-8"))
        return
    temporary = path.with_suffix(".tmp")
    # Private parent prevents races/reparse replacement by unelevated users.
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(asdict(state), stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def load_state() -> GuardState | None:
    path = _state_path()
    _secure_directory(path, create=False)
    if not path.exists():
        return None
    if path.stat().st_size > 256 * 1024:
        raise RuntimeError("Recovery state exceeds size limit; no resources were changed")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if type(data) is not dict:
            raise ValueError("Recovery state must be an object")
        state = GuardState(**data)
        _validate_state(state)
        return state
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError("Recovery state is invalid or legacy; no resources were changed") from exc


def clear_state() -> None:
    _state_path().unlink(missing_ok=True)


def add_route(state: GuardState, *, prefix, next_hop, adapter, metric=1) -> None:
    record = {"prefix": prefix, "next_hop": next_hop, "interface_index": int(adapter["index"]),
              "interface_guid": str(adapter["guid"]).strip("{}"), "metric": metric, "created": False}
    existing = _powershell_json(
        f"@(Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex {record['interface_index']} "
        f"-ErrorAction Stop | Where-Object DestinationPrefix -eq '{_ps_quote(prefix)}') | ConvertTo-Json -Compress"
    )
    if existing:
        raise RuntimeError("A route with this prefix already exists on the selected interface; it was left untouched")
    state.routes.append(record)
    save_state(state)  # Journal intent BEFORE mutation; uncertain ownership is never guessed.
    _powershell(
        f"New-NetRoute -DestinationPrefix '{_ps_quote(prefix)}' -InterfaceIndex {record['interface_index']} "
        f"-NextHop '{_ps_quote(next_hop)}' -RouteMetric {metric} -PolicyStore ActiveStore | Out-Null"
    )
    record["created"] = True
    save_state(state)


def _remove_recorded_routes(state: GuardState) -> None:
    for route in reversed(state.routes):
        script = (
            f"$a=@(Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid.ToString().Trim('{{}}') "
            f"-eq '{route['interface_guid']}' }}); "
            "if ($a.Count -gt 1) { throw 'Ambiguous adapter identity' }; "
            "if ($a.Count -eq 1) { "
            f"if ($a[0].ifIndex -ne {route['interface_index']}) {{ throw 'Adapter index changed; inspect recovery state' }}; "
            "$routes=@(Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex $a[0].ifIndex "
            f"| Where-Object {{ $_.DestinationPrefix -eq '{route['prefix']}' -and "
            f"$_.NextHop -eq '{route['next_hop']}' -and $_.RouteMetric -eq {route['metric']} "
            "-and $_.Protocol -eq 'NetMgmt' }); "
        )
        if route["created"]:
            script += "$routes | Remove-NetRoute -Confirm:$false; }"
        else:
            script += "if ($routes.Count) { throw 'Route creation was interrupted; ownership requires inspection' }; }"
        _powershell(script)


def install_kill_switch(state: GuardState, adapters: list[dict]) -> None:
    if not adapters or len(adapters) > 64:
        raise RuntimeError("Unsupported interface inventory; refusing to claim kill-switch protection")
    _powershell("if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled -or $_.AllowLocalFirewallRules -eq 'False' }).Count) "
                "{ throw 'Firewall must be enabled and accept local rules on all profiles' }")
    rules = []
    for adapter in adapters:
        alias = _ps_quote(adapter["alias"])
        index = int(adapter["index"])
        for family, networks in (("v4", ipv4_kill_switch_networks(state.relay_ips)), ("v6", ipv6_kill_switch_networks())):
            for chunk_index, chunk in enumerate(_chunks(networks)):
                name = f"{FIREWALL_PREFIX}-{state.session_id}-{index}-{family}-{chunk_index}"
                addresses = ",".join(f"'{value}'" for value in chunk)
                rules.append((name, f"-InterfaceAlias '{alias}' -RemoteAddress @({addresses})"))
        # Unicast DNS/DoT to private gateways must not bypass the tunnel either.
        for protocol in ("UDP", "TCP"):
            name = f"{FIREWALL_PREFIX}-{state.session_id}-{index}-dns-{protocol}"
            rules.append((name, f"-InterfaceAlias '{alias}' -Protocol {protocol} -RemotePort 53,853"))
    names = ",".join(f"'{name}'" for name, _ in rules)
    _powershell(f"$names=@({names}); if (@(Get-NetFirewallRule -PolicyStore PersistentStore "
                "| Where-Object Name -in $names).Count) { throw 'Firewall name collision' }")
    state.firewall_names.extend(name for name, _ in rules)
    save_state(state)
    # One PowerShell invocation avoids a process launch for each individual rule.
    # A partial failure leaves its journal and any installed guards intact.
    script = ""
    for name, arguments in rules:
        script += (
            f"New-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -DisplayName '{name}' "
            f"-Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any "
            + arguments + " | Out-Null; "
        )
    script += (f"$names=@({names}); $effective=@(Get-NetFirewallRule -PolicyStore ActiveStore "
               "| Where-Object { $_.Name -in $names -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }); "
               "if ($effective.Count -ne $names.Count) { throw 'Firewall rules are not effective' }")
    _powershell(script)


def remove_kill_switch(state: GuardState) -> None:
    for name in state.firewall_names:
        _powershell(
            f"$rules=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -eq '{name}'); "
            f"if (@($rules | Where-Object Group -ne '{FIREWALL_GROUP}').Count) {{ throw 'Firewall ownership mismatch' }}; "
            "$rules | Remove-NetFirewallRule"
        )


def cleanup_recorded_state(state: GuardState) -> None:
    _validate_state(state)
    if state.tun2socks_pid is not None:
        stop_recorded_process(ProcessIdentity(state.tun2socks_pid, state.tun2socks_created, state.tun2socks_path))
    _remove_recorded_routes(state)
    remove_kill_switch(state)  # Only after route/process cleanup succeeds.
    clear_state()


def cleanup_stale_state() -> bool:
    with session_lock():
        state = load_state()
        if state is None:
            return False  # Never sweep by prefix or guess ownership without a journal.
        cleanup_recorded_state(state)
        return True
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
