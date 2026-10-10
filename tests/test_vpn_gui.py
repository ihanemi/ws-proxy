from __future__ import annotations

import asyncio
import queue
import unittest
from unittest.mock import AsyncMock, patch

try:
    from vpn.gui import VpnGui
except ModuleNotFoundError as exc:
    if exc.name not in ("tkinter", "_tkinter"):
        raise
    VpnGui = None

from vpn.config import VpnConfig
from vpn.settings import AppSettings


@unittest.skipIf(VpnGui is None, "Tkinter is unavailable")
class GuiStartupTests(unittest.TestCase):
    def test_missing_runtime_reports_error_and_closes_event_loop(self):
        gui = object.__new__(VpnGui)
        gui.events = queue.Queue()
        error = FileNotFoundError("tun2socks executable is missing")
        loop = asyncio.new_event_loop()
        with patch("vpn.gui.asyncio.new_event_loop", return_value=loop):
            with patch("vpn.gui._bundled_tun2socks", side_effect=error):
                with patch("vpn.gui.run", new_callable=AsyncMock) as run:
                    gui._core_worker(AppSettings(), VpnConfig("wss://relay.example/tunnel", "test-token"))
                    run.assert_not_called()
        self.assertEqual(gui.events.get_nowait(), ("error", error))
        self.assertIsNone(gui.core_loop)
        self.assertIsNone(gui.stop_event)
        self.assertTrue(loop.is_closed())
        asyncio.set_event_loop(None)
