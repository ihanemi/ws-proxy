from __future__ import annotations

import asyncio
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from vpn.client import run
from vpn.config import VpnConfig
from vpn.dns import probe_dns
from vpn.socks5 import (
    SocksProtocolError, _UdpAssociateProtocol, _build_udp_response, _handle_connect, handle_client,
)
from vpn.udp_protocol import decode_datagram, encode_datagram
from vpn.websocket import WebSocketError, WebSocketTunnel


class CloudflareProfileTests(unittest.TestCase):
    def test_backend_paths_and_capabilities(self):
        old = VpnConfig("wss://relay.example/prefix/tunnel", "test-token")
        cf = VpnConfig("wss://worker.example/prefix/tunnel", "test-token", backend="cloudflare")
        self.assertTrue(old.supports_udp)
        self.assertEqual(old.relay_udp_path, "/prefix/udp")
        self.assertFalse(cf.supports_udp)
        self.assertEqual(cf.relay_udp_path, "/prefix/dns")
        self.assertIn("UDP unavailable", cf.connection_label)
        with self.assertRaises(ValueError):
            VpnConfig("wss://relay.example", "test-token", backend="typo")

    def test_cloudflare_udp_filter_drops_quic_and_other_resolvers(self):
        p = _UdpAssociateProtocol(None, "127.0.0.1", dns_server="1.1.1.1")
        for host, port in [("8.8.8.8", 53), ("1.1.1.1", 443), ("example.com", 53)]:
            p.datagram_received(_build_udp_response(host, port, b"payload"), ("127.0.0.1", 2000))
        self.assertEqual(p.queue.qsize(), 0)
        self.assertIsNone(p.client_addr)
        p.datagram_received(_build_udp_response("1.1.1.1", 53, b"dns"), ("127.0.0.1", 2000))
        self.assertEqual(decode_datagram(p.queue.get_nowait()), ("1.1.1.1", 53, b"dns"))

    def test_selfhosted_udp_filter_preserves_non_dns_traffic(self):
        p = _UdpAssociateProtocol(None, "127.0.0.1")
        p.datagram_received(_build_udp_response("8.8.8.8", 443, b"quic"), ("127.0.0.1", 2000))
        self.assertEqual(decode_datagram(p.queue.get_nowait()), ("8.8.8.8", 443, b"quic"))


class CloudflareSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_cloudflare_tun_cannot_disable_guard(self):
        cfg = VpnConfig("wss://worker.example/tunnel", "test-token", backend="cloudflare")
        with patch("vpn.client._run_session", new_callable=AsyncMock) as session:
            with self.assertRaises(ValueError):
                await run(cfg, SimpleNamespace(tun=True, no_kill_switch=True))
            session.assert_not_called()

    async def test_other_tcp_dns_marker_is_rejected_without_dial(self):
        cfg = VpnConfig("wss://worker.example/tunnel", "test-token", backend="cloudflare")
        with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock) as dial:
            with self.assertRaises(SocksProtocolError):
                await _handle_connect(None, None, cfg, None, "8.8.8.8", 53, lambda: None)
            dial.assert_not_called()

    async def test_flow_control_ack_is_only_sent_after_valid_data(self):
        conn = SimpleNamespace(recv=AsyncMock(return_value=b"\x01hello"), send=AsyncMock())
        tunnel = WebSocketTunnel(conn, flow_control=True)
        self.assertEqual(await tunnel.recv(), b"hello")
        conn.send.assert_awaited_once_with(b"\x04")
        conn.send.reset_mock()
        conn.recv.return_value = b"\x02"
        self.assertIsNone(await tunnel.recv())
        conn.send.assert_not_called()
        conn.recv.return_value = b"\x04"
        with self.assertRaises(WebSocketError):
            await tunnel.recv()
        conn.send.assert_not_called()

    async def test_dns_probe_roundtrip_uses_authenticated_tunnel_only(self):
        cfg = VpnConfig("wss://worker.example/tunnel", "test-token", backend="cloudflare")
        tunnel = SimpleNamespace(send=AsyncMock(), recv=AsyncMock(), close=AsyncMock())

        async def reply():
            host, port, query = decode_datagram(tunnel.send.call_args.args[0])
            answer = bytearray(query)
            answer[2:4] = struct.pack(">H", 0x8180)
            answer[6:8] = b"\x00\x01"
            answer.extend(bytes.fromhex("c00c000100010000003c000408080808"))
            return encode_datagram(host, port, bytes(answer))

        tunnel.recv.side_effect = reply
        with patch("vpn.dns.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=tunnel) as dial:
            with patch.object(asyncio.get_running_loop(), "getaddrinfo") as resolve:
                await probe_dns(cfg)
                resolve.assert_not_called()
            self.assertEqual(dial.call_args.args[2], "/dns")
            self.assertEqual(dial.call_args.kwargs["headers"], {"Authorization": "Bearer test-token"})
            tunnel.close.assert_awaited_once()

    async def test_dns_failure_closes_and_never_falls_back(self):
        cfg = VpnConfig("wss://worker.example/tunnel", "test-token", backend="cloudflare")
        for response in (None, b"bad", encode_datagram("8.8.8.8", 53, b"bad")):
            tunnel = SimpleNamespace(send=AsyncMock(), recv=AsyncMock(return_value=response), close=AsyncMock())
            with patch("vpn.dns.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=tunnel):
                with self.assertRaises(WebSocketError):
                    await probe_dns(cfg)
                tunnel.close.assert_awaited_once()


class CloudflareTcpDNSTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config = VpnConfig("wss://worker.example/tunnel", "test-token", backend="cloudflare",
                                relay_ips=("8.8.8.8",), connect_timeout=0.05)
        self.query = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
        answer = bytearray(self.query)
        answer[2:4] = b"\x81\x80"
        answer[6:8] = b"\x00\x01"
        answer.extend(bytes.fromhex("c00c000100010000003c000408080808"))
        self.answer = bytes(answer)
        self.ws = SimpleNamespace(send=AsyncMock(), recv=AsyncMock(), close=AsyncMock())
        self.ws.recv.return_value = encode_datagram("1.1.1.1", 53, self.answer)
        self.writer = SimpleNamespace(write=Mock(), drain=AsyncMock())

    async def test_real_socks_tcp_dns_handles_fragmented_and_pipelined_queries(self):
        finished = asyncio.Event()
        second_query = b"\x56\x78" + self.query[2:]

        async def echo_sent_query():
            _, _, query = decode_datagram(self.ws.send.call_args.args[0])
            return encode_datagram("1.1.1.1", 53, query[:2] + self.answer[2:])

        self.ws.recv.side_effect = echo_sent_query

        async def accept(reader, writer):
            try:
                await handle_client(reader, writer, self.config)
            finally:
                finished.set()

        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        try:
            with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock,
                       return_value=self.ws) as dial:
                reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
                try:
                    writer.write(b"\x05\x01\x00")
                    await writer.drain()
                    self.assertEqual(await reader.readexactly(2), b"\x05\x00")
                    writer.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x35")
                    await writer.drain()
                    self.assertEqual((await reader.readexactly(10))[:2], b"\x05\x00")
                    length = struct.pack(">H", len(self.query))
                    writer.write(length[:1])
                    await writer.drain()
                    await asyncio.sleep(0)
                    writer.write(length[1:] + self.query + length + second_query)
                    await writer.drain()
                    writer.write_eof()
                    expected = struct.pack(">H", len(self.answer)) + self.answer
                    expected += struct.pack(">H", len(self.answer)) + second_query[:2] + self.answer[2:]
                    self.assertEqual(await asyncio.wait_for(reader.read(), 2), expected)
                    await asyncio.wait_for(finished.wait(), 2)
                finally:
                    writer.close()
                    await writer.wait_closed()
                self.assertEqual(dial.call_args.kwargs["path"], "/dns")
                self.assertEqual(dial.call_args.kwargs["resolved_ips"], ("8.8.8.8",))
                self.assertEqual(dial.call_args.kwargs["headers"], {"Authorization": "Bearer test-token"})
                self.assertNotIn("flow_control", dial.call_args.kwargs)
                self.assertEqual(self.ws.send.await_count, 2)
                self.ws.send.assert_awaited_with(encode_datagram("1.1.1.1", 53, second_query))
                self.ws.close.assert_awaited_once()
        finally:
            server.close()
            await server.wait_closed()

    async def test_invalid_or_truncated_lengths_close_secure_transport(self):
        for payload in (b"\x00", b"\x00\x00", b"\x10\x01", b"\x00\x20short"):
            reader = asyncio.StreamReader()
            reader.feed_data(payload)
            reader.feed_eof()
            self.ws.close.reset_mock()
            with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=self.ws):
                with self.assertRaises((WebSocketError, asyncio.IncompleteReadError)):
                    await _handle_connect(reader, self.writer, self.config, None, "1.1.1.1", 53, lambda: None)
            self.ws.close.assert_awaited_once()
        self.ws.send.assert_not_called()

    async def test_malformed_and_mismatched_responses_fail_closed(self):
        answers = [b"bad", encode_datagram("8.8.8.8", 53, self.answer),
                   encode_datagram("1.1.1.1", 53, b"\x99\x99" + self.answer[2:]),
                   encode_datagram("1.1.1.1", 53, self.query),
                   encode_datagram("1.1.1.1", 53, self.answer + bytes(4096))]
        for response in answers:
            reader = asyncio.StreamReader()
            reader.feed_data(struct.pack(">H", len(self.query)) + self.query)
            reader.feed_eof()
            self.ws.recv.return_value = response
            self.ws.close.reset_mock()
            self.writer.write.reset_mock()
            with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=self.ws):
                with self.assertRaises(WebSocketError):
                    await _handle_connect(reader, self.writer, self.config, None, "1.1.1.1", 53, lambda: None)
            self.ws.close.assert_awaited_once()
            self.assertEqual(self.writer.write.call_count, 1)  # SOCKS success; no DNS payload.

    async def test_timeout_has_no_resolver_or_direct_retry(self):
        async def stalled():
            await asyncio.Future()
        self.ws.recv.side_effect = stalled
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack(">H", len(self.query)) + self.query)
        with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=self.ws) as dial:
            with patch.object(asyncio.get_running_loop(), "getaddrinfo") as resolve:
                with self.assertRaises(TimeoutError):
                    await _handle_connect(reader, self.writer, self.config, None, "1.1.1.1", 53, lambda: None)
                resolve.assert_not_called()
            self.assertEqual(dial.await_count, 1)
        self.ws.close.assert_awaited_once()

    async def test_selfhosted_tcp_dns_still_uses_original_tcp_tunnel(self):
        config = VpnConfig("wss://relay.example/tunnel", "test-token")
        with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=self.ws) as dial:
            with patch("vpn.socks5._bridge", new_callable=AsyncMock) as bridge:
                await _handle_connect(None, self.writer, config, None, "8.8.8.8", 53, lambda: None)
                bridge.assert_awaited_once()
            self.assertEqual(dial.call_args.kwargs["path"], "/tunnel")
            self.assertEqual(dial.call_args.kwargs["headers"]["X-Tunnel-Port"], "53")
            self.assertFalse(dial.call_args.kwargs["flow_control"])

    async def test_resolver_servfail_is_forwarded_without_retry(self):
        answer = self.query[:2] + b"\x81\x82" + self.query[4:]
        self.ws.recv.return_value = encode_datagram("1.1.1.1", 53, answer)
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack(">H", len(self.query)) + self.query)
        reader.feed_eof()
        with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=self.ws) as dial:
            await _handle_connect(reader, self.writer, self.config, None, "1.1.1.1", 53, lambda: None)
            self.assertEqual(dial.await_count, 1)
        self.writer.write.assert_called_with(struct.pack(">H", len(answer)) + answer)
        self.ws.close.assert_awaited_once()

    async def test_cancellation_closes_secure_dns_transport(self):
        receiving = asyncio.Event()

        async def stalled():
            receiving.set()
            await asyncio.Future()
        self.ws.recv.side_effect = stalled
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack(">H", len(self.query)) + self.query)
        with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=self.ws):
            task = asyncio.create_task(
                _handle_connect(reader, self.writer, self.config, None, "1.1.1.1", 53, lambda: None),
            )
            await receiving.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.ws.close.assert_awaited_once()


class FlowControlNegotiationTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_worker_ack_negotiation_is_rejected_without_downgrade(self):
        conn = SimpleNamespace(subprotocol="wsvpn.v1", response=SimpleNamespace(headers={}),
                               recv=AsyncMock(return_value=b"\x03"), close=AsyncMock())
        with patch("vpn.websocket.connect", new_callable=AsyncMock, return_value=conn) as dial:
            with self.assertRaises(WebSocketError):
                await WebSocketTunnel.connect("worker.example", 443, "/tunnel",
                                              resolved_ips=("8.8.8.8",), flow_control=True)
            self.assertIsNone(dial.call_args.kwargs["proxy"])
            self.assertEqual(dial.call_args.kwargs["additional_headers"]["X-WSVPN-Flow-Control"], "ack-v1")
            conn.close.assert_awaited_once()
            conn.recv.assert_not_called()
