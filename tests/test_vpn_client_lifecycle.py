import argparse
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from vpn.client import _run_session
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
            with patch("vpn.windows_tun.WindowsTun", return_value=tun), patch("vpn.client.serve", side_effect=socks):
                if startup_error:
                    with self.assertRaises(RuntimeError):
                        await _run_session(config, args, stop_event=stop)
                else:
                    await _run_session(config, args, stop_event=stop)
            tun.stop.assert_awaited_once_with(preserve_kill_switch=startup_error)
