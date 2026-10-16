from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import shutil
import subprocess
import tempfile
import time
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_vercel_origin", ROOT / "scripts/verify_vercel_origin.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
IDENTIFIER = "a" * 32


def response(body, extra=b""):
    return (b"HTTP/1.1 200 OK\r\nContent-Length: 180000\r\nCache-Control: no-store\r\n"
            b"X-WSVPN-Diagnostic-ID: " + IDENTIFIER.encode() + b"\r\n" + extra + b"\r\n" + body)


class IndependentOriginTests(unittest.TestCase):
    def test_matrix_sends_exactly_seven_with_bypass_and_maximum_two_concurrent(self):
        ids = [f"{i:032x}" for i in range(1, 8)]
        active = peak = 0
        calls = []
        lock, barrier = threading.Lock(), threading.Barrier(2)
        secret = "local_synthetic_bypass_" + "a" * 32

        def case(host, ip, identifier, mode, **options):
            nonlocal active, peak
            self.assertEqual(options, {"bypass_secret": secret})
            with lock:
                calls.append((identifier, mode))
                active += 1
                peak = max(peak, active)
            if identifier in ids[5:]:
                barrier.wait(timeout=2)
            with lock:
                active -= 1
            # Failure is retained; the runner must not retry or add a request.
            return {"id": identifier, "mode": mode, "passed": mode == "ok"}

        with patch.object(VERIFY, "run_case", side_effect=case) as run:
            rows = VERIFY.run_matrix("test.vercel.app", "64.29.17.67", ids, bypass_secret=secret)
        self.assertEqual(run.call_count, 7)
        self.assertEqual(peak, 2)
        self.assertEqual(calls[:5], list(zip(ids[:5], ["ok", "ok", "ok", "stall-response", "stall-body"], strict=True)))
        self.assertEqual(set(calls[5:]), {(identifier, "ok") for identifier in ids[5:]})
        self.assertEqual([row["id"] for row in rows], ids)
        self.assertEqual(sum(row["passed"] for row in rows), 5)
        self.assertNotIn(secret, json.dumps(rows))
        for previous, current in zip(rows[:4], rows[1:5], strict=True):
            self.assertLessEqual(previous["matrix_finished_ms"], current["matrix_started_ms"])
        self.assertLessEqual(max(rows[5]["matrix_started_ms"], rows[6]["matrix_started_ms"]),
                             min(rows[5]["matrix_finished_ms"], rows[6]["matrix_finished_ms"]))
        with patch.object(VERIFY, "run_case") as run:
            for invalid in (ids[:6], [ids[0]] * 7, ["invalid"] + ids[1:]):
                with self.assertRaises(ValueError):
                    VERIFY.run_matrix("test.vercel.app", "64.29.17.67", invalid, bypass_secret=secret)
            run.assert_not_called()

    def test_canary_cli_sends_exactly_one_request_without_retries(self):
        with tempfile.TemporaryDirectory(prefix="wsvpn-canary-cli-") as directory:
            root = Path(directory)
            config, ranges, output = root / "experiment.json", root / "ranges.json", root / "result.json"
            now = int(time.time() * 1000)
            config.write_text(json.dumps({"ids": [IDENTIFIER], "not_before_ms": now - 1000,
                                          "expires_ms": now + 120000}), encoding="utf-8")
            ranges.write_text(json.dumps({"result": {"ipv4_cidrs": ["104.16.0.0/13"],
                                                     "ipv6_cidrs": ["2606:4700::/32"]}}), encoding="utf-8")
            argv = ["verify_vercel_origin.py", "--host", "test.vercel.app", "--ip", "64.29.17.67",
                    "--experiment", str(config), "--cloudflare-ranges", str(ranges),
                    "--output", str(output), "--canary"]
            with patch("sys.argv", argv), patch.object(VERIFY, "run_case", return_value={"passed": True}) as run:
                with patch("builtins.print"):
                    self.assertEqual(VERIFY.main(), 0)
                run.assert_called_once_with("test.vercel.app", "64.29.17.67", IDENTIFIER, "ok")
            self.assertEqual(len(json.loads(output.read_text(encoding="utf-8"))["requests"]), 1)
            output.unlink()
            secret = "local_synthetic_bypass_" + "a" * 32
            with patch("sys.argv", argv + ["--automation-bypass"]), \
                    patch.dict(os.environ, {"WSVPN_VERCEL_AUTOMATION_BYPASS": secret}), \
                    patch.object(VERIFY, "run_case", return_value={"passed": True}) as run:
                with patch("builtins.print"):
                    self.assertEqual(VERIFY.main(), 0)
                run.assert_called_once_with("test.vercel.app", "64.29.17.67", IDENTIFIER, "ok", bypass_secret=secret)
                self.assertNotIn("WSVPN_VERCEL_AUTOMATION_BYPASS", os.environ)
            self.assertNotIn(secret, output.read_text(encoding="utf-8"))

    def test_rejection_diagnostics_are_allowlisted_and_wire_bytes_are_not_payload(self):
        wire = (b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n"
                b"X-WSVPN-Origin-Source: wsvpn-origin/2\r\n"
                b"X-WSVPN-Origin-Rejection: mode_url\r\n\r\n0\r\n\r\n")
        report = {"mode": "ok", "tls_verified": True, "elapsed_ms": 10, "reads": []}
        self.assertFalse(VERIFY.evaluate(report, wire, IDENTIFIER))
        self.assertEqual(report["body_wire_bytes"], 5)
        self.assertIsNone(report["body_bytes"])
        self.assertTrue(report["origin_source_marker"])
        self.assertEqual(report["origin_rejection"], "mode_url")
        untrusted = wire.replace(b"mode_url", b"PRIVATE-secret").replace(b"wsvpn-origin/2", b"PRIVATE")
        report = {"mode": "ok", "tls_verified": True, "elapsed_ms": 10, "reads": []}
        self.assertFalse(VERIFY.evaluate(report, untrusted, IDENTIFIER))
        self.assertIsNone(report["origin_rejection"])
        self.assertFalse(report["origin_source_marker"])
        self.assertNotIn("PRIVATE", str(report))

    def test_invalid_bypass_cannot_inject_headers_or_open_a_socket(self):
        for secret in ("bad\r\nInjected: value", "x" * 257, "short", b"not-text"):
            with patch.object(VERIFY.socket, "create_connection") as connect:
                with self.assertRaisesRegex(ValueError, "Invalid automation bypass format"):
                    VERIFY.run_case("localhost", "127.0.0.1", IDENTIFIER, "ok", bypass_secret=secret)
                connect.assert_not_called()

    def test_controls_and_proxy_interference(self):
        def check(mode, wire, first=10):
            report = {"mode": mode, "tls_verified": True, "elapsed_ms": 10010,
                      "request_sent_ms": 10, "reads": [{"bytes": len(wire), "elapsed_ms": first}]}
            return VERIFY.evaluate(report, wire, IDENTIFIER)
        self.assertTrue(check("ok", response(b"A" * 180000)))
        self.assertTrue(check("stall-response", b""))
        self.assertTrue(check("stall-body", response(b"A" * 1024)))
        self.assertFalse(check("stall-body", response(b"A" * 1024), first=10000))
        self.assertFalse(check("ok", response(b"A" * 180000, b"X-Vercel-Cache: HIT\r\n")))
        self.assertFalse(check("ok", response(b"A" * 180000, b"Content-Encoding: gzip\r\n")))
        self.assertFalse(check("ok", response(b"A" * 180000, b"Transfer-Encoding: chunked\r\n")))
        self.assertFalse(check("ok", response(b"B" * 180000)))
        self.assertFalse(check("stall-response", b"HTTP/1.1 502 Bad Gateway\r\n\r\n"))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for the local TLS fixture")
    def test_real_direct_tls_and_certificate_failure(self):
        with tempfile.TemporaryDirectory(prefix="wsvpn-origin-verifier-") as directory:
            key, cert = Path(directory) / "key.pem", Path(directory) / "cert.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext",
                            "subjectAltName=DNS:localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            seen = []

            class Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, *_args):
                    pass

                def do_GET(self):
                    seen.append(self.headers.get(VERIFY.ID_HEADER))
                    self.send_response(200)
                    self.send_header("Content-Length", "180000")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header(VERIFY.ID_HEADER, IDENTIFIER)
                    self.end_headers()
                    self.wfile.write(b"A" * 180000)

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cert)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(server.serve_forever)
                try:
                    report = VERIFY.run_case("localhost", "127.0.0.1", IDENTIFIER, "ok",
                                             context=context, port=server.server_port)
                    self.assertTrue(report["passed"], report)
                    self.assertEqual(report["body_bytes"], 180000)
                    self.assertEqual(report["end"], "complete_body")
                    secret = "local_synthetic_bypass_" + "a" * 32
                    # Inspect only a boolean in the fixture, never retain/log header contents.
                    original = Handler.do_GET
                    received = []

                    def with_bypass(handler):
                        received.append(handler.headers.get("x-vercel-protection-bypass") == secret)
                        self.assertEqual(handler.path, "/_wsvpn_diag/ok")
                        return original(handler)

                    with patch.object(Handler, "do_GET", with_bypass):
                        bypassed = VERIFY.run_case("localhost", "127.0.0.1", IDENTIFIER, "ok",
                                                   context=context, port=server.server_port, bypass_secret=secret)
                    self.assertEqual(received, [True])
                    self.assertTrue(bypassed["passed"])
                    self.assertNotIn(secret, json.dumps(bypassed))
                    wrong = VERIFY.run_case("wrong-host", "127.0.0.1", IDENTIFIER, "ok",
                                            context=context, port=server.server_port)
                    self.assertFalse(wrong["passed"])
                    self.assertFalse(wrong["tls_verified"])
                    self.assertEqual(wrong["end"], "SSLCertVerificationError")
                    self.assertEqual(seen, [IDENTIFIER, IDENTIFIER])
                finally:
                    server.shutdown()
                    server.server_close()
                    future.result(timeout=5)


if __name__ == "__main__":
    unittest.main()
