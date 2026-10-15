import asyncio
import ssl
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from vpn.config import VpnConfig
from vpn.endpoints import RelayEndpoints
from vpn.websocket import RelayAddressError, WebSocketError, WebSocketTunnel, prepare_relay, probe_relay


class EndpointTests(unittest.IsolatedAsyncioTestCase):
    def config(self):
        ips = ("192.0.2.1", "192.0.2.2")
        return VpnConfig("wss://relay.example/tunnel", "test-token", backend="cloudflare",
                         relay_ips=ips, endpoints=RelayEndpoints(ips), connect_timeout=.08)

    def tunnel(self):
        tunnel = SimpleNamespace(send=AsyncMock(), recv=AsyncMock(), close=AsyncMock(), abort=Mock())
        tunnel.recv.side_effect = lambda: tunnel.send.call_args.args[0]
        return tunnel

    async def test_timeout_after_ready_selects_next_address_and_preserves_snapshot(self):
        cfg = self.config()
        stalled, good = self.tunnel(), self.tunnel()
        async def stalled_recv():
            await asyncio.Event().wait()

        stalled.recv.side_effect = stalled_recv
        with patch("vpn.websocket.WebSocketTunnel.connect", side_effect=[stalled, good]) as dial:
            await probe_relay(cfg)
        self.assertEqual([call.kwargs["resolved_ips"] for call in dial.call_args_list],
                         [("192.0.2.1",), ("192.0.2.2",)])
        stalled.abort.assert_called_once()
        stalled.close.assert_not_called()
        self.assertEqual(cfg.relay_ips, ("192.0.2.1", "192.0.2.2"))
        self.assertEqual(cfg.relay_dial_ips, ("192.0.2.2",))

    async def test_network_dial_error_can_fail_over(self):
        cfg = self.config()
        with patch("vpn.websocket.WebSocketTunnel.connect",
                   side_effect=[RelayAddressError("unreachable"), self.tunnel()]) as dial:
            await probe_relay(cfg)
        self.assertEqual(dial.await_count, 2)
        self.assertEqual(cfg.relay_dial_ips[0], "192.0.2.2")

    async def test_protocol_and_tls_failures_do_not_select_another_address(self):
        for error in (WebSocketError("unsupported protocol"), ssl.SSLCertVerificationError("untrusted")):
            cfg = self.config()
            with patch("vpn.websocket.WebSocketTunnel.connect", side_effect=error) as dial:
                with self.assertRaises(type(error)):
                    await probe_relay(cfg)
            self.assertEqual(dial.await_count, 1)
            self.assertEqual(cfg.relay_dial_ips, cfg.relay_ips)

    async def test_invalid_challenge_aborts_without_promotion(self):
        cfg, tunnel = self.config(), self.tunnel()
        tunnel.recv.side_effect = None
        tunnel.recv.return_value = b"wrong"
        with patch("vpn.websocket.WebSocketTunnel.connect", return_value=tunnel) as dial:
            with self.assertRaises(WebSocketError):
                await probe_relay(cfg)
        self.assertEqual(dial.await_count, 1)
        tunnel.abort.assert_called_once()
        self.assertEqual(cfg.relay_dial_ips, cfg.relay_ips)

    async def test_all_timeouts_share_one_deadline_and_do_not_promote(self):
        cfg = self.config()
        async def stalled(*args, **kwargs):
            await asyncio.Event().wait()
        started = asyncio.get_running_loop().time()
        with patch("vpn.websocket.WebSocketTunnel.connect", side_effect=stalled) as dial:
            with self.assertRaises(TimeoutError):
                await probe_relay(cfg)
        self.assertEqual(dial.await_count, 2)
        self.assertLess(asyncio.get_running_loop().time() - started, .3)
        self.assertEqual(cfg.relay_dial_ips, cfg.relay_ips)

    async def test_cancelled_probe_aborts_and_does_not_try_next_address(self):
        cfg, tunnel = self.config(), self.tunnel()
        waiting = asyncio.Event()
        async def stalled():
            waiting.set()
            await asyncio.Event().wait()
        tunnel.recv.side_effect = stalled
        with patch("vpn.websocket.WebSocketTunnel.connect", return_value=tunnel) as dial:
            task = asyncio.create_task(probe_relay(cfg))
            await waiting.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        tunnel.abort.assert_called_once()
        self.assertEqual(dial.await_count, 1)

    async def test_cloudflare_bootstrap_is_once_and_selfhosted_is_unchanged(self):
        cfg = VpnConfig("wss://relay.example/tunnel", "test-token", backend="cloudflare")
        info = [(2, 1, 6, "", (ip, 443)) for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.1")]
        with patch.object(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=info)) as resolve:
            prepared = await prepare_relay(cfg)
            self.assertIs(await prepare_relay(prepared), prepared)
            resolve.assert_awaited_once()
        self.assertEqual(prepared.relay_ips, ("192.0.2.1", "192.0.2.2"))
        old = replace(cfg, backend="selfhosted")
        with patch.object(asyncio.get_running_loop(), "getaddrinfo") as resolve:
            self.assertIs(await prepare_relay(old), old)
            resolve.assert_not_called()

    def test_preference_cannot_escape_snapshot_or_other_sessions(self):
        cfg, other = self.config(), self.config()
        cfg.endpoints.verified("192.0.2.2")
        self.assertEqual(other.relay_dial_ips, other.relay_ips)
        with self.assertRaises(ValueError):
            cfg.endpoints.verified("192.0.2.3")
        with self.assertRaises(ValueError):
            replace(cfg, relay_ips=("192.0.2.3",))

    async def test_same_address_ping_timeout_retries_without_replaying_payload(self):
        loop = asyncio.get_running_loop()
        missing, pong = loop.create_future(), loop.create_future()
        pong.set_result(None)
        def connection(pong):
            return SimpleNamespace(subprotocol="wsvpn.v1", recv=AsyncMock(return_value=b"\x03"),
                ping=AsyncMock(return_value=pong), send=AsyncMock(), close=AsyncMock(),
                transport=Mock())
        first, second = connection(missing), connection(pong)
        with patch("vpn.websocket.connect", new_callable=AsyncMock, side_effect=[first, second]) as dial:
            tunnel = await WebSocketTunnel.connect("relay.example", 443, "/dns",
                resolved_ips=("192.0.2.1",), timeout=.1, check_path=True)
            await tunnel.send(b"query")
            await tunnel.close()
        self.assertEqual([call.kwargs["host"] for call in dial.call_args_list], ["192.0.2.1"] * 2)
        first.transport.abort.assert_called_once()
        first.close.assert_not_called()
        first.send.assert_not_called()
        second.send.assert_awaited_once_with(b"query")

    async def test_path_check_does_not_retry_failed_protocol_negotiation(self):
        conn = SimpleNamespace(subprotocol="legacy", close=AsyncMock(), ping=AsyncMock())
        with patch("vpn.websocket.connect", new_callable=AsyncMock, return_value=conn) as dial:
            with self.assertRaises(WebSocketError):
                await WebSocketTunnel.connect("relay.example", 443, "/dns",
                    resolved_ips=("192.0.2.1", "192.0.2.2"), timeout=.1, check_path=True)
        dial.assert_awaited_once()
        conn.ping.assert_not_called()

    async def test_required_session_extension_cannot_silently_downgrade(self):
        conn = SimpleNamespace(subprotocol="wsvpn.v1", response=SimpleNamespace(headers={}),
                               recv=AsyncMock(), close=AsyncMock())
        with patch("vpn.websocket.connect", new_callable=AsyncMock, return_value=conn) as dial:
            with self.assertRaisesRegex(WebSocketError, "requires an update"):
                await WebSocketTunnel.connect("relay.example", 443, "/dns", timeout=.1,
                    resolved_ips=("192.0.2.1",), check_path=True, path_challenge=True)
        self.assertEqual(dial.await_count, 1)
        conn.recv.assert_not_called()
        conn.close.assert_awaited_once()

    async def test_session_echo_timeout_retries_only_control_frames(self):
        def connection(stall):
            pong = asyncio.get_running_loop().create_future()
            pong.set_result(None)
            conn = SimpleNamespace(subprotocol="wsvpn.v1", transport=Mock(),
                response=SimpleNamespace(headers={"X-WSVPN-Path-Check": "echo-v1"}),
                send=AsyncMock(), close=AsyncMock(), ping=AsyncMock(return_value=pong))
            count = 0
            async def recv():
                nonlocal count
                count += 1
                if count == 1:
                    return b"\x03"
                if stall:
                    await asyncio.Event().wait()
                return conn.send.call_args.args[0]
            conn.recv = AsyncMock(side_effect=recv)
            return conn
        first, second = connection(True), connection(False)
        with patch("vpn.websocket.connect", new_callable=AsyncMock, side_effect=[first, second]):
            tunnel = await WebSocketTunnel.connect("relay.example", 443, "/dns", timeout=.1,
                resolved_ips=("192.0.2.1",), check_path=True, path_challenge=True)
            await tunnel.send(b"actual DNS query")
            await tunnel.close()
        first.transport.abort.assert_called_once()
        first.send.assert_awaited_once()
        self.assertEqual(first.send.call_args.args[0][:1], b"\x05")
        self.assertEqual(len(first.send.call_args.args[0]), 33)
        self.assertEqual([call.args[0] for call in second.send.call_args_list][1:], [b"actual DNS query"])
