import asyncio
import random
import unittest
from unittest.mock import AsyncMock, patch

from vpn.config import VpnConfig
from vpn.lifecycle import (
    ConnectionState,
    ConnectionStateMachine,
    monitor_relay,
    reconnect_delays,
)


class StateMachineTests(unittest.IsolatedAsyncioTestCase):
    def test_transitions_are_explicit(self):
        seen = []
        machine = ConnectionStateMachine(seen.append)
        for state in (
            ConnectionState.CONNECTING,
            ConnectionState.CONNECTED,
            ConnectionState.RECONNECTING,
            ConnectionState.CONNECTED,
            ConnectionState.DISCONNECTING,
            ConnectionState.DISCONNECTED,
        ):
            machine.transition(state)
        self.assertEqual(seen[-1], ConnectionState.DISCONNECTED)
        with self.assertRaises(RuntimeError):
            machine.transition(ConnectionState.RECONNECTING)

    def test_backoff_is_bounded_and_jittered(self):
        delays = reconnect_delays(random.Random(7))
        values = [next(delays) for _ in range(20)]
        self.assertTrue(all(0.8 <= value <= 36 for value in values))
        self.assertTrue(all(24 <= value <= 36 for value in values[6:]))

    async def test_health_failure_recovers_without_stopping_tunnel(self):
        config = VpnConfig(
            "wss://relay.example/tunnel",
            "test-only-token",
            health_interval=5,
        )
        states = []
        machine = ConnectionStateMachine(states.append)
        machine.transition(ConnectionState.CONNECTING)
        machine.transition(ConnectionState.CONNECTED)
        stop = asyncio.Event()

        async def wait_immediately(_event, _delay):
            await asyncio.sleep(0)
            return False

        probe = AsyncMock(side_effect=[ConnectionError("offline"), None])
        with patch("vpn.lifecycle.wait_or_stop", side_effect=wait_immediately), patch(
            "vpn.lifecycle.probe_relay", probe
        ):
            task = asyncio.create_task(monitor_relay(config, stop, machine))
            for _ in range(20):
                if machine.state == ConnectionState.CONNECTED and probe.await_count == 2:
                    break
                await asyncio.sleep(0)
            stop.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        self.assertIn(ConnectionState.RECONNECTING, states)
        self.assertEqual(machine.state, ConnectionState.CONNECTED)
        self.assertEqual(probe.await_count, 2)


if __name__ == "__main__":
    unittest.main()
