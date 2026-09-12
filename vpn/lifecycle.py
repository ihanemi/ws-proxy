from __future__ import annotations

import asyncio
import logging
import random
from enum import Enum
from typing import Callable, Iterator

from .websocket import probe_relay

log = logging.getLogger("ws-vpn.lifecycle")


class ConnectionState(str, Enum):
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    RECONNECTING = "Reconnecting"
    DISCONNECTING = "Disconnecting"
    FAILED = "Failed"


_TRANSITIONS = {
    ConnectionState.DISCONNECTED: {ConnectionState.CONNECTING},
    ConnectionState.CONNECTING: {
        ConnectionState.CONNECTED,
        ConnectionState.DISCONNECTING,
        ConnectionState.FAILED,
    },
    ConnectionState.CONNECTED: {
        ConnectionState.RECONNECTING,
        ConnectionState.DISCONNECTING,
        ConnectionState.FAILED,
    },
    ConnectionState.RECONNECTING: {
        ConnectionState.CONNECTED,
        ConnectionState.DISCONNECTING,
        ConnectionState.FAILED,
    },
    ConnectionState.DISCONNECTING: {
        ConnectionState.DISCONNECTED,
        ConnectionState.FAILED,
    },
    ConnectionState.FAILED: set(),
}


class ConnectionStateMachine:
    def __init__(self, callback: Callable[[ConnectionState], None] | None = None):
        self.state = ConnectionState.DISCONNECTED
        self.callback = callback

    def transition(self, state: ConnectionState) -> None:
        if state == self.state:
            return
        if state not in _TRANSITIONS[self.state]:
            raise RuntimeError(f"Invalid VPN state transition: {self.state.value} -> {state.value}")
        self.state = state
        if self.callback:
            try:
                self.callback(state)
            except Exception:
                log.exception("connection state callback failed")

    def fail(self) -> None:
        if self.state not in (ConnectionState.FAILED, ConnectionState.DISCONNECTED):
            self.transition(ConnectionState.FAILED)


def reconnect_delays(rng: random.Random | None = None) -> Iterator[float]:
    """Bounded exponential delays with ±20% jitter, then a 30s ceiling."""
    source = rng or random.SystemRandom()
    schedule = (1, 2, 4, 8, 15, 30)
    index = 0
    while True:
        delay = schedule[min(index, len(schedule) - 1)]
        index += 1
        yield delay * source.uniform(0.8, 1.2)


async def wait_or_stop(stop_event: asyncio.Event, timeout: float) -> bool:
    try:
        await asyncio.wait_for(stop_event.wait(), timeout)
        return True
    except TimeoutError:
        return False


async def monitor_relay(config, stop_event: asyncio.Event, machine: ConnectionStateMachine) -> None:
    """Keep probing the authenticated data path without relaxing the guard."""
    while not await wait_or_stop(stop_event, config.health_interval):
        try:
            await probe_relay(config)
            continue
        except (ConnectionError, OSError, TimeoutError):
            machine.transition(ConnectionState.RECONNECTING)
            log.warning("relay health probe failed; entering bounded reconnect")

        for delay in reconnect_delays():
            if await wait_or_stop(stop_event, delay):
                return
            try:
                await probe_relay(config)
            except (ConnectionError, OSError, TimeoutError):
                log.warning("relay reconnect probe failed; retrying in bounded backoff")
                continue
            machine.transition(ConnectionState.CONNECTED)
            log.info("relay health recovered")
            break
