from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve as ws_serve
from websockets.exceptions import ConnectionClosed, InvalidStatus

from relay.server import Relay, RelayLimits, _is_public_ip, _resolve_public
from vpn.async_utils import run_pair
from vpn.config import VpnConfig
from vpn.protocol import DATA, MAX_MESSAGE, READY, SUBPROTOCOL, TCP_EOF, decode_tcp
from vpn.socks5 import _UdpAssociateProtocol, _build_udp_response, handle_client
from vpn.udp_protocol import decode_datagram, encode_datagram
from vpn.websocket import WebSocketError, WebSocketTunnel

TOKEN = "test-only-" + "x" * 32


class ValidationTests(unittest.TestCase):
    def test_nonpublic_and_transition_addresses(self):
        for value in ("127.0.0.1", "10.1.2.3", "100.64.1.1", "224.0.0.1", "0.0.0.0",
                      "::1", "fd00::1", "fe80::1", "ff02::1", "::ffff:8.8.8.8",
                      "2002:7f00:1::", "64:ff9b::7f00:1", "192.0.2.1"):
            with self.subTest(value=value):
                self.assertFalse(_is_public_ip(value))
        self.assertTrue(_is_public_ip("8.8.8.8"))
        self.assertTrue(_is_public_ip("2606:4700:4700::1111"))

    def test_config_cannot_inject_headers_or_expose_socks(self):
        for args in ({"token": "token\r\nInjected: yes"}, {"relay_url": "ws://host/tunnel"},
                     {"relay_url": "wss://user:password@host/tunnel"},
                     {"relay_url": "wss://host:0/tunnel"}, {"relay_url": "wss://host/other"},
                     {"relay_url": "wss://host/tunnel#token"}, {"listen_host": "0.0.0.0"}):
            values = {"relay_url": "wss://relay.example/tunnel", "token": TOKEN}
            values.update(args)
            with self.subTest(args=list(args)):
                with self.assertRaises(ValueError):
                    VpnConfig(**values)
        self.assertNotIn(TOKEN, repr(VpnConfig("wss://relay.example/tunnel", TOKEN)))

    def test_tcp_frame_types(self):
        for frame in ("text", b"", READY, b"\x02extra", DATA + bytes(MAX_MESSAGE)):
            with self.assertRaises(ValueError):
                decode_tcp(frame)
        self.assertIsNone(decode_tcp(TCP_EOF))
        self.assertEqual(decode_tcp(DATA + b"hello"), b"hello")

    def test_library_debug_headers_disabled(self):
        for name in ("ws-vpn.wire", "ws-vpn-relay.wire"):
            self.assertFalse(logging.getLogger(name).isEnabledFor(logging.DEBUG))


class AsyncSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_mixed_dns_answer_rejected(self):
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))
                    for ip in ("8.8.8.8", "127.0.0.1")]
        with patch.object(asyncio.get_running_loop(), "getaddrinfo", resolve):
            with self.assertRaises(ValueError):
                await _resolve_public("example.com", 80, socket.SOCK_STREAM)

    async def test_bridge_cancellation_joins_both_children(self):
        stopped = []
        async def child(n):
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append(n)
        task = asyncio.create_task(run_pair(child(1), child(2)))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertCountEqual(stopped, [1, 2])

    async def test_udp_queue_bound_and_invalid_packet_cannot_claim_source(self):
        protocol = _UdpAssociateProtocol(None, "127.0.0.1")
        protocol.datagram_received(b"bad", ("127.0.0.1", 1111))
        self.assertIsNone(protocol.client_addr)
        packet = _build_udp_response("1.1.1.1", 53, b"dns")
        for _ in range(1000):
            protocol.datagram_received(packet, ("127.0.0.1", 2222))
        self.assertEqual(protocol.client_addr, ("127.0.0.1", 2222))
        self.assertEqual(protocol.queue.qsize(), 16)
        protocol.datagram_received(packet, ("127.0.0.1", 1111))
        self.assertEqual(protocol.queue.qsize(), 16)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = Relay(TOKEN, RelayLimits(connect_timeout=.3, tcp_idle=2, udp_idle=2))
        self.server = await ws_serve(
            self.relay.handle, "127.0.0.1", 0,
            process_request=self.relay.process_request,
            create_connection=self.relay.connection_factory,
            subprotocols=[SUBPROTOCOL], compression=None, max_size=MAX_MESSAGE,
            close_timeout=.2, logger=logging.getLogger("ws-vpn-relay.wire"),
        )
        self.url = "ws://127.0.0.1:" + str(self.server.sockets[0].getsockname()[1])
        self.targets = []

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        for target in self.targets:
            target.close()
            if hasattr(target, "wait_closed"):
                await target.wait_closed()
        self.assertEqual(self.relay.total, 0)
        self.assertEqual(self.relay.peers, {})

    def dial(self, path="/udp", headers=None, protocols=(SUBPROTOCOL,)):
        if headers is None:
            headers = {"Authorization": "Bearer " + TOKEN}
        return connect(self.url + path, additional_headers=headers,
                       subprotocols=protocols, proxy=None, compression=None, close_timeout=.2)

    async def test_unauthorized_is_http_401_before_upgrade(self):
        with patch("relay.server._resolve_public") as resolve:
            with self.assertRaises(InvalidStatus) as caught:
                await self.dial(headers={"Authorization": "Bearer wrong"})
            self.assertEqual(caught.exception.response.status_code, 401)
            resolve.assert_not_called()

    async def test_duplicate_auth_rejected(self):
        with self.assertRaises(InvalidStatus) as caught:
            await self.dial(headers=[("Authorization", "Bearer " + TOKEN)] * 2)
        self.assertEqual(caught.exception.response.status_code, 401)

    async def test_unsupported_protocol_rejected(self):
        with self.assertRaises(InvalidStatus) as caught:
            await self.dial(protocols=())
        self.assertEqual(caught.exception.response.status_code, 426)

    async def test_invalid_destination_rejected_before_upgrade(self):
        with self.assertRaises(InvalidStatus) as caught:
            await self.dial("/tunnel", {"Authorization": "Bearer " + TOKEN,
                                       "X-Tunnel-Host": "example.com", "X-Tunnel-Port": "25"})
        self.assertEqual(caught.exception.response.status_code, 400)

    async def test_connect_failure_never_sends_ready(self):
        with patch("relay.server._resolve_public", side_effect=ValueError("blocked")):
            async with self.dial("/tunnel", {"Authorization": "Bearer " + TOKEN,
                                           "X-Tunnel-Host": "example.com", "X-Tunnel-Port": "80"}) as ws:
                with self.assertRaises(ConnectionClosed):
                    await ws.recv()

    async def test_tcp_half_close_preserves_response(self):
        async def echo_after_eof(reader, writer):
            data = await reader.read()
            writer.write(b"reply:" + data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        target = await asyncio.start_server(echo_after_eof, "127.0.0.1", 0)
        self.targets.append(target)
        port = target.sockets[0].getsockname()[1]
        with patch("relay.server._resolve_public", return_value=("127.0.0.1", socket.AF_INET)):
            async with self.dial("/tunnel", {"Authorization": "Bearer " + TOKEN,
                                           "X-Tunnel-Host": "example.com", "X-Tunnel-Port": str(port)}) as ws:
                self.assertEqual(await ws.recv(), READY)
                await ws.send(DATA + b"payload")
                await ws.send(TCP_EOF)
                self.assertEqual(await ws.recv(), DATA + b"reply:payload")
                self.assertEqual(await ws.recv(), TCP_EOF)

    async def test_oversized_message_closes_association(self):
        async with self.dial() as ws:
            self.assertEqual(await ws.recv(), READY)
            await ws.send(bytes(MAX_MESSAGE + 1))
            with self.assertRaises(ConnectionClosed) as caught:
                await ws.recv()
            self.assertEqual(caught.exception.rcvd.code, 1009)

    async def test_udp_two_destinations(self):
        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, addr):
                self.transport.sendto(b"reply:" + data, addr)
        loop = asyncio.get_running_loop()
        endpoints = []
        for _ in range(2):
            transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
            self.targets.append(transport)
            endpoints.append(transport.get_extra_info("sockname")[1])
        with patch("relay.server._resolve_public", return_value=("127.0.0.1", socket.AF_INET)):
            async with self.dial() as ws:
                self.assertEqual(await ws.recv(), READY)
                for port in endpoints:
                    await ws.send(encode_datagram("example.com", port, b"udp"))
                    self.assertEqual(decode_datagram(await asyncio.wait_for(ws.recv(), 1)),
                                     ("127.0.0.1", port, b"reply:udp"))

    async def test_idle_association_is_closed(self):
        self.relay.limits = RelayLimits(udp_idle=.03)
        async with self.dial() as ws:
            self.assertEqual(await ws.recv(), READY)
            with self.assertRaises(ConnectionClosed):
                await asyncio.wait_for(ws.recv(), 1)

    async def test_slow_handshakes_count_toward_limits(self):
        self.relay.limits = RelayLimits(connections=1, per_peer=1)
        port = self.server.sockets[0].getsockname()[1]
        reader1, writer1 = await asyncio.open_connection("127.0.0.1", port)
        reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
        try:
            self.assertEqual(await asyncio.wait_for(reader2.read(), 1), b"")
            self.assertEqual(self.relay.total, 1)
        finally:
            writer1.close()
            writer2.close()
            await writer1.wait_closed()
            await writer2.wait_closed()


class TlsSocksIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which("openssl")
        if not openssl:
            candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/usr/bin/openssl.exe"
            openssl = str(candidate) if candidate.exists() else None
        if not openssl:
            raise unittest.SkipTest("OpenSSL is required for ephemeral test certificates")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = str(Path(cls.tmp.name) / "cert.pem")
        cls.key = str(Path(cls.tmp.name) / "key.pem")
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", cls.key, "-out", cls.cert, "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    async def test_socks_tcp_over_verified_tls_and_pinned_address(self):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.cert, self.key)
        client_context = ssl.create_default_context(cafile=self.cert)
        relay = Relay(TOKEN)
        async def echo(reader, writer):
            data = await reader.read()
            writer.write(b"echo:" + data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        async with await asyncio.start_server(echo, "127.0.0.1", 0) as target:
            target_port = target.sockets[0].getsockname()[1]
            async with ws_serve(relay.handle, "127.0.0.1", 0, ssl=server_context,
                                process_request=relay.process_request, subprotocols=[SUBPROTOCOL]) as server:
                port = server.sockets[0].getsockname()[1]
                cfg = VpnConfig(f"wss://localhost:{port}/tunnel", TOKEN, relay_ips=("127.0.0.1",))
                with patch("vpn.websocket.ssl.create_default_context", return_value=client_context), patch(
                    "relay.server._resolve_public", return_value=("127.0.0.1", socket.AF_INET)
                ):
                    async with await asyncio.start_server(lambda r, w: handle_client(r, w, cfg), "127.0.0.1", 0) as socks:
                        reader, writer = await asyncio.open_connection("127.0.0.1", socks.sockets[0].getsockname()[1])
                        try:
                            writer.write(b"\x05\x01\x00")
                            self.assertEqual(await reader.readexactly(2), b"\x05\x00")
                            writer.write(b"\x05\x01\x00\x01\x08\x08\x08\x08" + target_port.to_bytes(2, "big"))
                            reply = await asyncio.wait_for(reader.readexactly(10), 2)
                            self.assertEqual(reply[1], 0)
                            writer.write(b"through SOCKS and TLS")
                            writer.write_eof()
                            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"echo:through SOCKS and TLS")
                        finally:
                            writer.close()
                            await writer.wait_closed()

    async def test_untrusted_certificate_is_rejected(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        relay = Relay(TOKEN)
        async with ws_serve(relay.handle, "127.0.0.1", 0, ssl=context) as server:
            with self.assertRaises(WebSocketError):
                await WebSocketTunnel.connect("localhost", server.sockets[0].getsockname()[1],
                                              "/udp", headers={"Authorization": "Bearer " + TOKEN}, timeout=1)
