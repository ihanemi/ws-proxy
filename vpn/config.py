from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .protocol import MAX_PAYLOAD, validate_host, validate_token


@dataclass(frozen=True)
class VpnConfig:
    relay_url: str
    token: str = field(repr=False)
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    connect_timeout: float = 10.0
    buffer_size: int = 256 * 1024
    relay_ips: tuple[str, ...] = ()
    max_clients: int = 256

    def __post_init__(self) -> None:
        validate_token(self.token)
        parsed = self._parsed_relay()
        validate_host(parsed.hostname or "")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("Relay URL must not contain credentials or a fragment")
        if parsed.path and not parsed.path.endswith("/tunnel"):
            raise ValueError("Relay URL path must end in /tunnel")
        if any(ord(c) <= 32 or ord(c) >= 127 for c in self.relay_url):
            raise ValueError("Relay URL must be ASCII and contain no whitespace")
        if not 1 <= self.relay_port <= 65535:
            raise ValueError("Relay port must be between 1 and 65535")
        if not ipaddress.ip_address(self.listen_host).is_loopback:
            raise ValueError("Unauthenticated local SOCKS must bind to a loopback IP")
        if not 1 <= self.listen_port <= 65535:
            raise ValueError("SOCKS port must be between 1 and 65535")
        if not 0 < self.connect_timeout <= 120:
            raise ValueError("Connect timeout must be between 0 and 120 seconds")
        if not 1 <= self.buffer_size <= MAX_PAYLOAD:
            raise ValueError("Buffer size exceeds the protocol limit")
        if not 1 <= self.max_clients <= 1024:
            raise ValueError("SOCKS client limit must be between 1 and 1024")
        for value in self.relay_ips:
            ipaddress.IPv4Address(value)

    def _parsed_relay(self):
        parsed = urlparse(self.relay_url)
        if parsed.scheme not in ("wss", "https"):
            raise ValueError("relay_url must use wss:// or https://")
        if not parsed.hostname:
            raise ValueError("relay_url must include a hostname")
        return parsed

    @property
    def relay_host(self) -> str:
        return self._parsed_relay().hostname or ""

    @property
    def relay_path(self) -> str:
        parsed = self._parsed_relay()
        path = parsed.path or "/tunnel"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    @property
    def relay_udp_path(self) -> str:
        parsed = self._parsed_relay()
        path = parsed.path or "/tunnel"
        if path.endswith("/tunnel"):
            path = path[:-len("/tunnel")] + "/udp"
        else:
            path = path.rstrip("/") + "/udp"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    @property
    def relay_port(self) -> int:
        parsed = self._parsed_relay()
        return 443 if parsed.port is None else parsed.port
