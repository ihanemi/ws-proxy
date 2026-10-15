"""Session-local preference within the journaled relay address snapshot."""
from __future__ import annotations

import ipaddress


class RelayEndpoints:
    def __init__(self, addresses: tuple[str, ...]):
        if not 1 <= len(addresses) <= 32 or len(set(addresses)) != len(addresses):
            raise ValueError("Expected 1 to 32 distinct relay IPv4 addresses")
        for address in addresses:
            ipaddress.IPv4Address(address)
        self._addresses = tuple(addresses)
        self._preferred: str | None = None

    @property
    def addresses(self) -> tuple[str, ...]:
        return self._addresses

    def ordered(self) -> tuple[str, ...]:
        if self._preferred is None:
            return self._addresses
        return (self._preferred,) + tuple(ip for ip in self._addresses if ip != self._preferred)

    def selected(self) -> tuple[str, ...]:
        # Application dials must not fall through to an unverified edge. The
        # health monitor can select another member using a fresh full probe.
        return (self._preferred,) if self._preferred else self._addresses

    def verified(self, address: str) -> None:
        if address not in self._addresses:
            raise ValueError("Relay address is outside the session snapshot")
        self._preferred = address
