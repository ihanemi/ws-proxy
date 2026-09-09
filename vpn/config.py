from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class VpnConfig:
    worker_url: str
    token: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    connect_timeout: float = 10.0
    buffer_size: int = 256 * 1024

    @property
    def worker_host(self) -> str:
        parsed = urlparse(self.worker_url)
        if parsed.scheme not in ("wss", "https"):
            raise ValueError("worker_url must use wss:// or https://")
        if not parsed.hostname:
            raise ValueError("worker_url must include a hostname")
        return parsed.hostname

    @property
    def worker_path(self) -> str:
        parsed = urlparse(self.worker_url)
        path = parsed.path or "/tunnel"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    @property
    def worker_port(self) -> int:
        parsed = urlparse(self.worker_url)
        return parsed.port or 443
