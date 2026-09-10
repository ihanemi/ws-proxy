from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class VpnConfig:
    relay_url: str
    token: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    connect_timeout: float = 10.0
    buffer_size: int = 256 * 1024

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
        return parsed.port or 443
