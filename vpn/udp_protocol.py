from __future__ import annotations

import ipaddress
import struct
from typing import Tuple

from .protocol import validate_host


VERSION = 1
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4
MAX_DATAGRAM = 65507


class UdpFrameError(ValueError):
    pass


def encode_datagram(host: str, port: int, payload: bytes) -> bytes:
    host = validate_host(host)
    if port < 1 or port > 65535:
        raise UdpFrameError("invalid UDP port")
    if len(payload) > MAX_DATAGRAM:
        raise UdpFrameError("UDP payload too large")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if not encoded or len(encoded) > 255:
            raise UdpFrameError("invalid domain name") from None
        address = bytes((ATYP_DOMAIN, len(encoded))) + encoded
    else:
        if isinstance(ip, ipaddress.IPv4Address):
            address = bytes((ATYP_IPV4,)) + ip.packed
        else:
            address = bytes((ATYP_IPV6,)) + ip.packed

    return bytes((VERSION,)) + address + struct.pack(">H", port) + payload


def decode_datagram(frame: bytes) -> Tuple[str, int, bytes]:
    if len(frame) > MAX_DATAGRAM + 260:
        raise UdpFrameError("UDP frame too large")
    if len(frame) < 1 + 1 + 2:
        raise UdpFrameError("truncated UDP frame")
    if frame[0] != VERSION:
        raise UdpFrameError("unsupported UDP frame version")

    offset = 1
    atyp = frame[offset]
    offset += 1

    if atyp == ATYP_IPV4:
        if len(frame) < offset + 4 + 2:
            raise UdpFrameError("truncated IPv4 UDP frame")
        host = str(ipaddress.IPv4Address(frame[offset:offset + 4]))
        offset += 4
    elif atyp == ATYP_IPV6:
        if len(frame) < offset + 16 + 2:
            raise UdpFrameError("truncated IPv6 UDP frame")
        host = str(ipaddress.IPv6Address(frame[offset:offset + 16]))
        offset += 16
    elif atyp == ATYP_DOMAIN:
        if len(frame) < offset + 1:
            raise UdpFrameError("truncated domain UDP frame")
        size = frame[offset]
        offset += 1
        if size == 0 or len(frame) < offset + size + 2:
            raise UdpFrameError("invalid domain UDP frame")
        try:
            host = frame[offset:offset + size].decode("idna")
        except UnicodeError as exc:
            raise UdpFrameError("invalid domain encoding") from exc
        offset += size
    else:
        raise UdpFrameError("unsupported UDP address type")

    try:
        validate_host(host)
    except ValueError as exc:
        raise UdpFrameError("invalid UDP destination") from exc
    port = struct.unpack(">H", frame[offset:offset + 2])[0]
    offset += 2
    if port == 0:
        raise UdpFrameError("invalid UDP port")
    payload = frame[offset:]
    if len(payload) > MAX_DATAGRAM:
        raise UdpFrameError("UDP payload too large")
    return host, port, payload
