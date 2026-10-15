from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .protocol import MAX_PAYLOAD, validate_host, validate_token
from .endpoints import RelayEndpoints


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
    health_interval: float = 20.0
    backend: str = "selfhosted"
    dns_server: str = "1.1.1.1"
    endpoints: RelayEndpoints | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.backend not in ("selfhosted", "cloudflare"):
            raise ValueError("Unknown backend profile")
        dns = ipaddress.ip_address(self.dns_server)
        if not isinstance(dns, ipaddress.IPv4Address) or not dns.is_global or dns.is_multicast:
            raise ValueError("DNS marker must be a public IPv4 address")
        validate_token(self.token)
        parsed = self._parsed_relay()
        validate_host(parsed.hostname or "")
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("Relay URL must not contain credentials, a query, or a fragment")
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
        if not 5 <= self.health_interval <= 300:
            raise ValueError("Health interval must be between 5 and 300 seconds")
        for value in self.relay_ips:
            ipaddress.IPv4Address(value)
        if self.endpoints is not None and self.endpoints.addresses != self.relay_ips:
            raise ValueError("Relay preference must match the session address snapshot")

    @property
    def relay_dial_ips(self) -> tuple[str, ...]:
        return self.endpoints.selected() if self.endpoints else self.relay_ips

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
        return path

    @property
    def relay_udp_path(self) -> str:
        parsed = self._parsed_relay()
        path = parsed.path or "/tunnel"
        if path.endswith("/tunnel"):
            path = path[:-len("/tunnel")] + ("/dns" if self.backend == "cloudflare" else "/udp")
        else:
            path = path.rstrip("/") + "/udp"
        return path

    @property
    def supports_udp(self) -> bool:
        return self.backend == "selfhosted"

    @property
    def connection_label(self) -> str:
        if self.backend == "cloudflare":
            return "Connected â€” TCP + DoH only; UDP unavailable"
        return "Connected â€” self-hosted TCP/UDP"

    @property
    def relay_probe_path(self) -> str:
        return self.relay_path[:-len("/tunnel")] + "/probe"

    @property
    def relay_port(self) -> int:
        parsed = self._parsed_relay()
        return 443 if parsed.port is None else parsed.port
