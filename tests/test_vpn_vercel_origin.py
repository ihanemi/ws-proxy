from concurrent.futures import ThreadPoolExecutor
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_vercel_origin", ROOT / "scripts/verify_vercel_origin.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
IDENTIFIER = "a" * 32


def response(body, extra=b""):
    return (b"HTTP/1.1 200 OK\r\nContent-Length: 180000\r\nCache-Control: no-store\r\n"
            b"X-WSVPN-Diagnostic-ID: " + IDENTIFIER.encode() + b"\r\n" + extra + b"\r\n" + body)


class IndependentOriginTests(unittest.TestCase):
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
                    wrong = VERIFY.run_case("wrong-host", "127.0.0.1", IDENTIFIER, "ok",
                                            context=context, port=server.server_port)
                    self.assertFalse(wrong["passed"])
                    self.assertFalse(wrong["tls_verified"])
                    self.assertEqual(wrong["end"], "SSLCertVerificationError")
                    self.assertEqual(seen, [IDENTIFIER])
                finally:
                    server.shutdown()
                    server.server_close()
                    future.result(timeout=5)


if __name__ == "__main__":
    unittest.main()
