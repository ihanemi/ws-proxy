import logging
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from vpn.client import build_parser
from vpn.logging_setup import configure_file_logging
from vpn.version import __version__
import vpn_windows


class VersionAndLoggingTests(unittest.TestCase):
    def test_windowed_cli_keeps_diagnostics_without_console_or_token_leak(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"LOCALAPPDATA": tmp}):
            with mock.patch("sys.argv", ["WsVpn.exe", "--relay", "wss://relay.example/tunnel",
                                         "--token", "test-secret-do-not-log", "--verbose"]), mock.patch(
                "sys.frozen", True, create=True
            ), mock.patch("sys.stderr", None), mock.patch(
                "vpn.client.asyncio.run", side_effect=OSError("test-secret-do-not-log")
            ) as run:
                try:
                    with self.assertRaises(SystemExit):
                        vpn_windows.main()
                    # asyncio.run was replaced; close the coroutine it received.
                    run.call_args.args[0].close()
                    handlers = logging.getLogger().handlers[:]
                    for handler in handlers:
                        handler.flush()
                    text = (Path(tmp) / "WsVpn" / "logs" / "ws-vpn.log").read_text()
                    self.assertIn("VPN stopped: OSError", text)
                    self.assertNotIn("test-secret-do-not-log", text)
                    self.assertFalse(logging.getLogger("ws-vpn.wire").isEnabledFor(logging.DEBUG))
                finally:
                    for handler in logging.getLogger().handlers[:]:
                        handler.close()
                        logging.getLogger().removeHandler(handler)

    def test_cli_and_package_use_alpha_version(self):
        output = StringIO()
        with self.assertRaises(SystemExit) as stopped, redirect_stdout(output):
            build_parser().parse_args(["--version"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn(__version__, output.getvalue())
        pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text()
        self.assertIn('version = "0.1.0a1"', pyproject)

    def test_file_logging_rotates_and_suppresses_wire_debug(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"LOCALAPPDATA": tmp}):
            path = configure_file_logging(verbose=True)
            try:
                root = logging.getLogger()
                self.assertIsInstance(root.handlers[0], logging.handlers.RotatingFileHandler)
                self.assertEqual(root.handlers[0].backupCount, 3)
                self.assertFalse(logging.getLogger("websockets").isEnabledFor(logging.DEBUG))
                logging.getLogger("component").info("safe event")
                root.handlers[0].flush()
                self.assertIn("safe event", path.read_text())
            finally:
                for handler in logging.getLogger().handlers[:]:
                    handler.close()
                    logging.getLogger().removeHandler(handler)
