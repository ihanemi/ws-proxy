"""Shared, bounded WSVPN/1 wire contract (independent of Windows)."""
from __future__ import annotations

import ipaddress
import re

SUBPROTOCOL = "wsvpn.v1"
MAX_PAYLOAD = 256 * 1024
MAX_MESSAGE = MAX_PAYLOAD + 1
MAX_QUEUE = 4
READY = b"\x03"
TCP_EOF = b"\x02"
DATA = b"\x01"


def validate_host(host: str) -> str:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("Invalid destination hostname length")
    # Scoped literals and header/control injection must never reach DNS or HTTP.
    if any(ord(c) <= 32 or ord(c) >= 127 for c in host) or "%" in host:
        raise ValueError("Hostname must be an ASCII hostname or unscoped IP literal")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        labels = host.rstrip(".").split(".")
        if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", s) for s in labels):
            raise ValueError("Invalid destination hostname") from None
        return host


def validate_token(token: str) -> None:
    if not isinstance(token, str) or not token or len(token) > 4096:
        raise ValueError("Token must contain 1 to 4096 ASCII characters")
    if any(ord(c) <= 32 or ord(c) >= 127 for c in token):
        raise ValueError("Token must not contain spaces, controls, or non-ASCII characters")


def decode_tcp(message: bytes | str) -> bytes | None:
    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE:
        raise ValueError("Invalid TCP message type or size")
    if message == TCP_EOF:
        return None
    if not message.startswith(DATA):
        raise ValueError("Invalid TCP frame type")
    return message[1:]
