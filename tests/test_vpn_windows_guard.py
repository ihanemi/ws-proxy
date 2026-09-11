from __future__ import annotations

import base64
import ipaddress
import json
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

from vpn.windows_guard import (
    GuardState,
    add_route,
    cleanup_stale_state,
    cleanup_recorded_state,
    install_kill_switch,
    clear_state,
    ipv4_kill_switch_networks,
    ipv6_kill_switch_networks,
    load_state,
    save_state,
)


def _contains(networks: list[str], address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip in ipaddress.ip_network(network) for network in networks)


class KillSwitchNetworkTests(unittest.TestCase):
    def test_ipv4_blocks_public_but_excludes_relay_and_lan(self) -> None:
        networks = ipv4_kill_switch_networks(["203.0.113.10"])

        self.assertTrue(_contains(networks, "8.8.8.8"))
        self.assertTrue(_contains(networks, "1.1.1.1"))
        self.assertFalse(_contains(networks, "203.0.113.10"))
        self.assertFalse(_contains(networks, "192.168.1.1"))
        self.assertFalse(_contains(networks, "10.0.0.1"))
        self.assertFalse(_contains(networks, "172.16.0.1"))
        self.assertFalse(_contains(networks, "169.254.1.1"))

    def test_ipv6_blocks_public_but_excludes_local_scopes(self) -> None:
        networks = ipv6_kill_switch_networks()

        self.assertTrue(_contains(networks, "2606:4700:4700::1111"))
        self.assertTrue(_contains(networks, "2001:4860:4860::8888"))
        self.assertFalse(_contains(networks, "fd00::1"))
        self.assertFalse(_contains(networks, "fe80::1"))
        self.assertFalse(_contains(networks, "ff02::1"))
        self.assertFalse(_contains(networks, "::1"))


class GuardStateTests(unittest.TestCase):
    def test_state_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path = os.path.join(directory, "state.json")
            with mock.patch("vpn.windows_guard._state_path", return_value=Path(state_path)), mock.patch("vpn.windows_guard._secure_directory"):
                state = GuardState(
                    version=2,
                    session_id="a" * 32,
                    tun_name="wsvpn",
                    primary_interface_alias="Ethernet",
                    primary_interface_index=7,
                    primary_gateway="192.168.1.1",
                    relay_ips=["203.0.113.10"],
                    ipv6=True,
                    kill_switch=True,
                    tun2socks_pid=1234,
                    tun2socks_created=123456,
                    tun2socks_path=r"C:\\Tools\\tun2socks.exe",
                )
                save_state(state)
                self.assertEqual(load_state(), state)
                clear_state()
                self.assertIsNone(load_state())


if __name__ == "__main__":
    unittest.main()


def state_fixture():
    return GuardState(version=2, session_id="a" * 32, tun_name="wsvpn",
                      primary_interface_alias="Ethernet", primary_interface_index=7,
                      primary_gateway="192.168.1.1", relay_ips=["8.8.8.8"], ipv6=True, kill_switch=True)


class RecoverySafetyTests(unittest.TestCase):
    def test_corrupt_or_legacy_state_is_preserved_and_never_used(self):
        payloads = [[], {"version": 1}, {**asdict(state_fixture()), "primary_interface_index": "7; bad"},
                    {**asdict(state_fixture()), "primary_interface_index": True},
                    {**asdict(state_fixture()), "tun2socks_pid": 123},
                    {**asdict(state_fixture()), "firewall_names": ["SomeOtherApplication"]}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            with mock.patch("vpn.windows_guard._state_path", return_value=path), mock.patch("vpn.windows_guard._secure_directory"):
                for payload in payloads:
                    path.write_text(json.dumps(payload))
                    with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                        load_state()
                    self.assertTrue(path.exists())

    def test_cleanup_without_journal_changes_nothing(self):
        with mock.patch("vpn.windows_guard.session_lock", return_value=nullcontext()), mock.patch(
            "vpn.windows_guard.load_state", return_value=None
        ), mock.patch("vpn.windows_guard._powershell") as powershell:
            self.assertFalse(cleanup_stale_state())
            powershell.assert_not_called()

    def test_route_conflict_never_deletes_or_claims_existing_route(self):
        state = state_fixture()
        with mock.patch("vpn.windows_guard._powershell_json", return_value={"existing": True}), mock.patch(
            "vpn.windows_guard._powershell"
        ) as powershell, mock.patch("vpn.windows_guard.save_state") as save:
            with self.assertRaises(RuntimeError):
                add_route(state, prefix="8.8.8.8/32", next_hop="192.168.1.1",
                          adapter={"index": 7, "guid": "a" * 36})
            self.assertEqual(state.routes, [])
            powershell.assert_not_called()
            save.assert_not_called()

    def test_failed_route_cleanup_keeps_firewall_and_state(self):
        with mock.patch("vpn.windows_guard._remove_recorded_routes", side_effect=RuntimeError("denied")), mock.patch(
            "vpn.windows_guard.remove_kill_switch"
        ) as remove, mock.patch("vpn.windows_guard.clear_state") as clear:
            with self.assertRaises(RuntimeError):
                cleanup_recorded_state(state_fixture())
            remove.assert_not_called()
            clear.assert_not_called()

    def test_firewall_failure_keeps_exact_journal_and_never_sweeps_old_rules(self):
        state = state_fixture()
        scripts = []
        def powershell(script):
            scripts.append(script)
            if "New-NetFirewallRule" in script:
                raise RuntimeError("simulated partial failure")
        with mock.patch("vpn.windows_guard._powershell", side_effect=powershell), mock.patch("vpn.windows_guard.save_state") as save:
            with self.assertRaises(RuntimeError):
                install_kill_switch(state, [{"alias": "Ethernet", "index": 7}, {"alias": "Wi-Fi", "index": 8}])
            save.assert_called_once()
            self.assertTrue(state.firewall_names)
            self.assertTrue(any("-8-" in name for name in state.firewall_names))
            self.assertFalse(any("Remove-NetFirewallRule" in script for script in scripts))
            self.assertIn("-RemotePort 53,853", scripts[-1])

    def test_powershell_nonterminating_errors_are_promoted(self):
        from vpn.windows_guard import _powershell
        failed = mock.Mock(returncode=1, stderr="denied")
        with mock.patch("vpn.windows_guard.subprocess.run", return_value=failed) as run, mock.patch(
            "vpn.windows_guard.system_executable", return_value="powershell.exe"
        ):
            with self.assertRaises(RuntimeError):
                _powershell("New-NetRoute")
            self.assertIn("$ErrorActionPreference='Stop'", base64.b64decode(run.call_args.kwargs["input"]).decode("utf-16-le"))
