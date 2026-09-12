import argparse
import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from vpn.client import _run_session, _run_until_signal
from vpn.config import VpnConfig


class LifecycleSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_error_and_explicit_disconnect_have_different_cleanup(self):
        config = VpnConfig("wss://relay.example/tunnel", "test-only-token")
        args = argparse.Namespace(tun=True, tun2socks="runtime.exe", tun_name="wsvpn", dns="1.1.1.1",
                                  udp_timeout="2m", no_ipv6=False, no_kill_switch=False)
        async def blocked():
            await asyncio.Event().wait()
        async def socks(_config, *, ready):
            ready.set()
            await blocked()
        for startup_error in (False, True):
            tun = AsyncMock()
            tun.prepare.return_value = config
            tun.wait.side_effect = blocked
            if startup_error:
                tun.start.side_effect = RuntimeError("partial firewall installation")
            stop = asyncio.Event()
            stop.set()
            with patch("vpn.windows_tun.WindowsTun", return_value=tun), patch(
                "vpn.client.serve", side_effect=socks
            ), patch("vpn.websocket.probe_relay", new=AsyncMock()):
                if startup_error:
                    with self.assertRaises(RuntimeError):
                        await _run_session(config, args, stop_event=stop)
                else:
                    await _run_session(config, args, stop_event=stop)
            tun.stop.assert_awaited_once_with(preserve_kill_switch=startup_error)

    async def test_failed_authenticated_probe_never_reports_ready(self):
        config = VpnConfig("wss://relay.example/tunnel", "test-only-token")
        args = argparse.Namespace(tun=True, tun2socks="runtime.exe", tun_name="wsvpn", dns="1.1.1.1",
                                  udp_timeout="2m", no_ipv6=False, no_kill_switch=False)
        tun = AsyncMock()
        tun.prepare.return_value = config

        async def blocked():
            await asyncio.Event().wait()

        async def socks(_config, *, ready):
            ready.set()
            await blocked()

        tun.wait.side_effect = blocked
        ready_callback = Mock()
        with patch("vpn.windows_tun.WindowsTun", return_value=tun), patch(
            "vpn.client.serve", side_effect=socks
        ), patch("vpn.websocket.probe_relay", side_effect=ConnectionError("relay rejected probe")):
            with self.assertRaises(ConnectionError):
                await _run_session(config, args, on_ready=ready_callback)
        ready_callback.assert_not_called()
        tun.stop.assert_awaited_once_with(preserve_kill_switch=True)

    async def test_console_signal_path_supplies_explicit_stop_event(self):
        config = VpnConfig("wss://relay.example/tunnel", "test-only-token")
        args = argparse.Namespace(tun=False)

        async def fake_run(_config, _args, *, stop_event):
            self.assertIsInstance(stop_event, asyncio.Event)
            stop_event.set()

        with patch("vpn.client.run", side_effect=fake_run), patch(
            "vpn.client.signal.signal", return_value=lambda *_: None
        ) as install:
            await _run_until_signal(config, args)
        self.assertGreaterEqual(install.call_count, 2)
