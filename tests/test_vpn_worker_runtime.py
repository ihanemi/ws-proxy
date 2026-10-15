"""Opt-in real Python SOCKS -> WSS workerd -> TCP HTTPS integration."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import ssl
import unittest
from unittest.mock import patch

from vpn.config import VpnConfig
from vpn.socks5 import handle_client

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('WSVPN_WORKER_RUNTIME_TESTS') == '1',
                     'Set WSVPN_WORKER_RUNTIME_TESTS=1 with worker npm dependencies and OpenSSL')
class WorkerHttpsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.process = await asyncio.create_subprocess_exec(
            shutil.which('node') or 'node', 'test/helpers/python-tcp-runtime.mjs',
            cwd=ROOT / 'worker', stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        self.addAsyncCleanup(self.stop_fixture)
        line = await asyncio.wait_for(self.process.stdout.readline(), 12)
        if not line:
            error = await self.process.stderr.read()
            self.fail('Local workerd fixture failed: ' + error.decode(errors='replace')[-1500:])
        info = json.loads(line)
        self.context = ssl.create_default_context(cadata=info['ca'])
        self.url = info['url'].replace('https://127.0.0.1:', 'wss://localhost:') + 'tunnel'

    async def stop_fixture(self):
        if self.process.returncode is None:
            self.process.stdin.write(b'stop\n')
            await self.process.stdin.drain()
            try:
                await asyncio.wait_for(self.process.wait(), 5)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()

    async def test_real_python_socks_wss_worker_tcp_https(self):
        await self.exchange('/')

    async def test_tls_success_is_not_http_success_when_origin_stalls(self):
        await self.exchange('/stall', stalled=True)

    async def exchange(self, path, *, stalled=False):
        cfg = VpnConfig(self.url, 'test-only-token', backend='cloudflare',
                        relay_ips=('127.0.0.1',), connect_timeout=4)
        tasks = set()

        def accept(reader, writer):
            task = asyncio.create_task(handle_client(reader, writer, cfg))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        server = await asyncio.start_server(accept, '127.0.0.1', 0)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        port = server.sockets[0].getsockname()[1]
        try:
            # Trust only this test's ephemeral CA for the outer WSS connection.
            # The tunneled HTTPS connection independently validates the same CA.
            with patch('vpn.websocket.ssl.create_default_context', return_value=self.context):
                reader, writer = await asyncio.open_connection('127.0.0.1', port)
                try:
                    writer.write(b'\x05\x01\x00')
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 5), b'\x05\x00')
                    writer.write(b'\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb')
                    await writer.drain()
                    self.assertEqual((await asyncio.wait_for(reader.readexactly(10), 6))[:2], b'\x05\x00')
                    await asyncio.wait_for(writer.start_tls(self.context, server_hostname='localhost'), 5)
                    self.assertTrue(writer.get_extra_info('ssl_object').getpeercert())
                    writer.write(f'GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
                    await writer.drain()
                    if stalled:
                        with self.assertRaises(TimeoutError):
                            await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), .4)
                    else:
                        headers = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
                        self.assertTrue(headers.startswith(b'HTTP/1.1 200'))
                        body = await asyncio.wait_for(reader.readexactly(180000), 5)
                        self.assertEqual(body, b'A' * 180000)
                finally:
                    writer.close()
                    await writer.wait_closed()
            self.process.stdin.write(b'stats\n')
            await self.process.stdin.drain()
            stats = json.loads(await asyncio.wait_for(self.process.stdout.readline(), 3))
            self.assertEqual(sum(x['type'] == 'origin.request' for x in stats['events']), 1)
            if stalled:
                self.assertFalse(any(x['type'] == 'origin.response' for x in stats['events']))
            else:
                self.assertIn({'type': 'origin.response', 'bytes': 180000}, stats['events'])
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
