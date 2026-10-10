from __future__ import annotations

import asyncio
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from vpn.client import run
from vpn.config import VpnConfig
from vpn.dns import probe_dns
from vpn.socks5 import SocksProtocolError, _UdpAssociateProtocol, _build_udp_response, _handle_connect
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

    async def test_tcp_dns_is_rejected_without_dial(self):
        cfg = VpnConfig("wss://worker.example/tunnel", "test-token", backend="cloudflare")
        with patch("vpn.socks5.WebSocketTunnel.connect", new_callable=AsyncMock) as dial:
            with self.assertRaises(SocksProtocolError):
                await _handle_connect(None, None, cfg, None, "1.1.1.1", 53, lambda: None)
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
        for response in (None, encode_datagram("8.8.8.8", 53, b"bad")):
            tunnel = SimpleNamespace(send=AsyncMock(), recv=AsyncMock(return_value=response), close=AsyncMock())
            with patch("vpn.dns.WebSocketTunnel.connect", new_callable=AsyncMock, return_value=tunnel):
                with self.assertRaises(WebSocketError):
                    await probe_dns(cfg)
                tunnel.close.assert_awaited_once()


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
