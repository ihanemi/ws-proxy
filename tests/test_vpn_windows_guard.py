from __future__ import annotations

import ipaddress
import os
import tempfile
import unittest
from unittest import mock

from vpn.windows_guard import (
    GuardState,
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
            with mock.patch.dict(os.environ, {"WS_VPN_STATE_PATH": state_path}):
                state = GuardState(
                    version=1,
                    tun_name="wsvpn",
                    primary_interface_alias="Ethernet",
                    primary_interface_index=7,
                    primary_gateway="192.168.1.1",
                    relay_ips=["203.0.113.10"],
                    ipv6=True,
                    kill_switch=True,
                    tun2socks_pid=1234,
                    tun2socks_path=r"C:\\Tools\\tun2socks.exe",
                )
                save_state(state)
                self.assertEqual(load_state(), state)
                clear_state()
                self.assertIsNone(load_state())


if __name__ == "__main__":
    unittest.main()
