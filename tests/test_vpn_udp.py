import struct
import unittest

from vpn.config import VpnConfig
from vpn.socks5 import _build_udp_response, _parse_udp_request
from vpn.udp_protocol import UdpFrameError, decode_datagram, encode_datagram


class UdpTunnelFrameTests(unittest.TestCase):
    def test_ipv4_roundtrip(self):
        frame = encode_datagram("1.1.1.1", 53, b"dns")
        self.assertEqual(decode_datagram(frame), ("1.1.1.1", 53, b"dns"))

    def test_ipv6_roundtrip(self):
        frame = encode_datagram("2606:4700:4700::1111", 53, b"dns6")
        self.assertEqual(
            decode_datagram(frame),
            ("2606:4700:4700::1111", 53, b"dns6"),
        )

    def test_domain_roundtrip(self):
        frame = encode_datagram("example.com", 443, b"quic")
        self.assertEqual(decode_datagram(frame), ("example.com", 443, b"quic"))

    def test_rejects_bad_version(self):
        with self.assertRaises(UdpFrameError):
            decode_datagram(b"\x02\x01\x01\x01\x01\x01\x00\x35")


class SocksUdpFrameTests(unittest.TestCase):
    def test_parse_ipv4_request(self):
        packet = (
            b"\x00\x00\x00\x01"
            + b"\x08\x08\x08\x08"
            + struct.pack(">H", 53)
            + b"hello"
        )
        self.assertEqual(_parse_udp_request(packet), ("8.8.8.8", 53, b"hello"))

    def test_build_response_roundtrip(self):
        packet = _build_udp_response("9.9.9.9", 53, b"reply")
        self.assertEqual(_parse_udp_request(packet), ("9.9.9.9", 53, b"reply"))


class VpnConfigTests(unittest.TestCase):
    def test_udp_path_is_sibling_of_tunnel(self):
        cfg = VpnConfig("wss://vpn.example.com/tunnel", "secret")
        self.assertEqual(cfg.relay_udp_path, "/udp")

    def test_relay_query_is_rejected(self):
        with self.assertRaises(ValueError):
            VpnConfig("wss://vpn.example.com/ws/tunnel?edge=1", "secret")


if __name__ == "__main__":
    unittest.main()
