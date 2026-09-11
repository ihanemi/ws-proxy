import os
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from vpn.windows_native import process_identity, session_lock, stop_recorded_process


@unittest.skipUnless(os.name == "nt", "Win32 handle tests require a Windows runner")
class NativeOwnershipTests(unittest.TestCase):
    def test_same_executable_with_different_birth_time_is_never_killed(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            identity = process_identity(process.pid)
            self.assertIsNotNone(identity)
            self.assertFalse(stop_recorded_process(replace(identity, created=identity.created + 1)))
            self.assertIsNone(process.poll())
            self.assertTrue(stop_recorded_process(identity))
            self.assertIsNotNone(process.wait(timeout=5))
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait()

    def test_network_operations_are_serialized_across_threads(self):
        def another_operation():
            with session_lock():
                pass
        with session_lock(), ThreadPoolExecutor(max_workers=1) as pool:
            with self.assertRaises(RuntimeError):
                pool.submit(another_operation).result(timeout=3)
        with session_lock():
            pass

    def test_state_directory_and_file_are_protected_before_use(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from vpn.windows_guard import load_state, save_state
        from tests.test_vpn_windows_guard import state_fixture
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private" / "state.json"
            with patch("vpn.windows_guard._state_path", return_value=path):
                save_state(state_fixture())
                self.assertEqual(load_state(), state_fixture())
            with patch("vpn.windows_guard._state_path", return_value=Path(tmp) / "state.json"):
                with self.assertRaises(RuntimeError):
                    save_state(state_fixture())

    def test_generated_network_commands_parse_without_executing_them(self):
        import base64
        from unittest.mock import patch
        from vpn.windows_guard import (
            _powershell, _remove_recorded_routes, install_kill_switch, remove_kill_switch,
        )
        from tests.test_vpn_windows_guard import state_fixture
        scripts = []
        state = state_fixture()
        state.routes = [{"prefix": "8.8.8.8/32", "next_hop": "192.168.1.1", "interface_index": 7,
                         "interface_guid": "12345678-1234-1234-1234-123456789abc", "metric": 1, "created": True}]
        with patch("vpn.windows_guard._powershell", side_effect=scripts.append), patch("vpn.windows_guard.save_state"):
            install_kill_switch(state, [{"alias": "Wi-Fi", "index": 7}, {"alias": "Ethernet", "index": 8}])
            _remove_recorded_routes(state)
            remove_kill_switch(state)
        for script in scripts:
            encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            _powershell(f"$text=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')); "
                        "$errors=$null; [System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$null,[ref]$errors) "
                        "| Out-Null; if ($errors.Count) { throw ($errors | Out-String) }")
