# Windows ownership and recovery

The network session is serialized by a machine-wide named mutex. Recovery
and uninstall must obtain the same lock; a live client must be disconnected
first. A second client cannot silently clean up the first client's session.

Version-2 state uses a random session ID, exact firewall names, route tuples
(prefix, gateway, metric, interface index and adapter GUID), and the child
process's PID, full executable path and creation FILETIME. Process validation
and termination use the same Win32 handle, so PID reuse cannot target a later
process. State and its directory are owned by Administrators with protected
ACLs permitting Administrators and SYSTEM only; malformed, linked, oversized,
legacy or untrusted state is rejected before any network action.

A new connection refuses any existing adapter with the requested name or any
existing same-prefix route on the selected interface. Route creation is
journaled before mutation. If a crash occurs between creation and confirmation,
cleanup refuses to guess ownership and retains the guard for inspection.
Cleanup selects adapters by GUID and exact routes, never all default routes by
adapter name. Firewall cleanup uses only journaled names in the WS VPN group;
without a valid journal, it does nothing. Errors preserve the journal.

All existing adapters (including disconnected and virtual adapters) are
included in the guard snapshot. Unicast DNS and DoT (TCP/UDP 53 and 853) on
these interfaces are blocked even to private gateways. This intentionally
prevents router DNS fallback. mDNS/LLMNR and ordinary LAN access remain
available. Relay IPs are resolved once before route installation and the same
snapshot is used by every WSS connection; automatic proxy discovery is off.

**This does not yet guarantee protection for newly attached adapters or a
reboot with changed interface identities.** Network switching, sleep/resume,
and effective filtering need physical Windows E2E validation. Do not publish
an alpha on the strength of rule-existence checks.

## Recover a version-2 session

Close other WS VPN instances, then run an elevated PowerShell:

```powershell
$p = Start-Process -FilePath .\WsVpn.exe -ArgumentList '--cleanup' -PassThru -Wait
if ($p.ExitCode -ne 0) { throw 'Recovery failed; keep the executable and inspect the logs/state.' }
```

Windowed PyInstaller programs must be started with `-Wait -PassThru` when
checking exit codes. A nonzero exit code is not a successful cleanup.

## Existing pre-audit sessions

Version-1 state cannot prove route or process ownership. The new client
intentionally does not migrate it, remove wildcard firewall rules, or kill
its recorded PID. Do not delete the journal or manually loosen its ACL to
make the new client accept it.

Before updating an old installation, disconnect it normally using that
installation. If it previously crashed, retain the old executable and collect
its state and matching resource inventory for review. Run these **read-only**
commands in an elevated shell (do not include the GUI token/config file):

```powershell
Get-Content "$env:ProgramData\WsVpn\state.json" -ErrorAction SilentlyContinue
Get-NetAdapter -IncludeHidden | Select-Object Name,ifIndex,InterfaceGuid,InterfaceDescription
Get-NetRoute -PolicyStore ActiveStore | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,Protocol
Get-NetFirewallRule -Name 'WSVPN-KillSwitch-*' -ErrorAction SilentlyContinue |
    Select-Object Name,Group,Enabled,Direction,Action
```

An inherited/untrusted old `WsVpn` directory must also be inspected before
migration, even if its old state file has already been removed. There is no
blanket "delete everything" migration command. Preserve user configuration in
`%APPDATA%\WsVpn`.

## Remaining ownership gaps

A hard crash at the exact boundary between creating tun2socks and recording
its birth time can leave an unrecorded child. Recovery deliberately will not
kill a process it cannot identify. Creating/joining the child in a validated
Win32 job and adapter ownership through Wintun handles need further work.
An administrator concurrently changing adapters/routes is outside the mutex;
route conflicts and ambiguous creation are treated conservatively.
