from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from vpn.settings import AppSettings, load_settings, save_settings


class SettingsTests(unittest.TestCase):
    def test_round_trip_uses_protected_token_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            previous = os.environ.get("WS_VPN_CONFIG_PATH")
            os.environ["WS_VPN_CONFIG_PATH"] = str(path)
            try:
                settings = AppSettings(
                    relay="wss://vpn.example.com/tunnel",
                    dns="9.9.9.9",
                    tun_name="testtun",
                    ipv6=False,
                    kill_switch=True,
                    remember_token=True,
                    start_minimized=True,
                )
                save_settings(settings, "secret-token", protector=lambda value: f"ENC:{value[::-1]}")

                raw = path.read_text(encoding="utf-8")
                self.assertNotIn("secret-token", raw)
                payload = json.loads(raw)
                self.assertEqual(payload["protected_token"], "ENC:nekot-terces")

                loaded, token = load_settings(
                    unprotector=lambda value: value.removeprefix("ENC:")[::-1]
                )
                self.assertEqual(loaded.relay, settings.relay)
                self.assertEqual(loaded.dns, "9.9.9.9")
                self.assertEqual(loaded.tun_name, "testtun")
                self.assertFalse(loaded.ipv6)
                self.assertTrue(loaded.kill_switch)
                self.assertTrue(loaded.start_minimized)
                self.assertEqual(token, "secret-token")
            finally:
                if previous is None:
                    os.environ.pop("WS_VPN_CONFIG_PATH", None)
                else:
                    os.environ["WS_VPN_CONFIG_PATH"] = previous

    def test_token_is_not_persisted_when_remember_is_off(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            previous = os.environ.get("WS_VPN_CONFIG_PATH")
            os.environ["WS_VPN_CONFIG_PATH"] = str(path)
            try:
                settings = AppSettings(remember_token=False)
                save_settings(settings, "do-not-save", protector=lambda _value: "SHOULD-NOT-RUN")
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(payload["protected_token"], "")
            finally:
                if previous is None:
                    os.environ.pop("WS_VPN_CONFIG_PATH", None)
                else:
                    os.environ["WS_VPN_CONFIG_PATH"] = previous


if __name__ == "__main__":
    unittest.main()
