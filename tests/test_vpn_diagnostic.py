"""Correlated diagnostic experiment: localhost only, real WSS/TCP/TLS."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import secrets
import ssl
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.diagnostic_https import experiment

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('WSVPN_WORKER_RUNTIME_TESTS') == '1', 'Opt-in Node/workerd runtime tests')
class DiagnosticExperimentTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.child = await asyncio.create_subprocess_exec(
            'node', 'diagnostic/local-fixture.mjs', cwd=ROOT / 'worker',
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            limit=2 * 1024 * 1024)
        self.addAsyncCleanup(self.stop)
        line = await asyncio.wait_for(self.child.stdout.readline(), 12)
        if not line:
            self.fail((await self.child.stderr.read()).decode(errors='replace')[-2000:])
        self.info = json.loads(line)
        self.context = ssl.create_default_context(cafile=self.info['ca_file'])
        patcher = patch('vpn.websocket.ssl.create_default_context', return_value=self.context)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def stop(self):
        if self.child.returncode is None:
            self.child.stdin.write(b'stop\n')
            await self.child.stdin.drain()
            try:
                await asyncio.wait_for(self.child.wait(), 5)
            except TimeoutError:
                self.child.kill()
                await self.child.wait()

    async def stats(self):
        self.child.stdin.write(b'stats\n')
        await self.child.stdin.drain()
        return json.loads(await asyncio.wait_for(self.child.stdout.readline(), 3))

    async def run_case(self, mode='ok', contract='echo-v1', timeout=2):
        args = SimpleNamespace(id=secrets.token_hex(16), relay=self.info['relay'],
                               origin=self.info['origin'], ip='127.0.0.1', timeout=timeout,
                               contract=contract, mode=mode, origin_ca=self.info['ca_file'])
        return await experiment(args, 'test-only-token')

    async def assert_correlated(self, result, expected_bytes):
        stats = await self.stats()
        for _ in range(20):
            if any(x['id'] == result['id'] and x['event'] == 'session.summary' for x in stats['worker']):
                break
            await asyncio.sleep(.02)
            stats = await self.stats()
        worker = [x for x in stats['worker'] if x['id'] == result['id']]
        origin = [x for x in stats['origin'] if x['id'] == result['id']]
        self.assertTrue(any(x['event'] == 'tcp.connect.complete' for x in worker))
        self.assertTrue(any(x['event'] == 'tcp.write.complete' for x in worker))
        self.assertTrue(any(x['event'] == 'tcp.read.complete' for x in worker))
        self.assertTrue(any(x['event'] == 'ws.data.received' for x in worker))
        self.assertTrue(any(x['event'] == 'ws.data.sent' for x in worker))
        self.assertTrue(any(x['event'] == 'ws.ack.received' for x in worker))
        self.assertTrue(any(x['event'] == 'flow.ack.wait' for x in worker))
        summaries = [x for x in worker if x['event'] == 'session.summary']
        self.assertEqual(len(summaries), 1)
        self.assertGreaterEqual(summaries[0]['read_cancels'], 1)
        self.assertGreaterEqual(summaries[0]['write_cancels'], 1)
        self.assertTrue(any(x['event'] == 'ws.close.request' for x in worker))
        self.assertEqual(sum(x['event'] == 'origin.request.received' for x in origin), 1)
        self.assertEqual(max(x['response_bytes'] for x in origin), expected_bytes)
        self.assertEqual(result['response_bytes'], expected_bytes)
        self.assertNotIn('test-only-token', json.dumps(stats))
        for rows in (worker, origin):
            self.assertEqual([r['seq'] for r in rows], sorted(r['seq'] for r in rows))
        return worker, origin

    async def test_success_legacy_and_echo_keep_ack_and_full_body(self):
        for contract in ('legacy', 'echo-v1'):
            result = await self.run_case(contract=contract)
            self.assertTrue(result['passed'], result)
            self.assertTrue(result['certificate_verified'])
            worker, _ = await self.assert_correlated(result, 180000)
            self.assertGreaterEqual(max(x['tcp_read_bytes'] for x in worker), 180000)
            self.assertEqual(max(x['tcp_write_bytes'] for x in worker), max(x['ws_rx_bytes'] for x in worker))

    async def test_origin_request_received_but_no_response(self):
        result = await self.run_case(mode='stall-response', timeout=1)
        self.assertFalse(result['passed'])
        self.assertEqual(result['error'], 'TimeoutError', result)
        self.assertTrue(result['certificate_verified'])
        await self.assert_correlated(result, 0)

    async def test_partial_origin_response_then_stall(self):
        result = await self.run_case(mode='stall-body', timeout=1)
        self.assertFalse(result['passed'])
        self.assertEqual(result['error'], 'TimeoutError', result)
        await self.assert_correlated(result, 1024)

    async def test_concurrent_sessions_do_not_mix_correlation(self):
        first, second = await asyncio.gather(self.run_case(), self.run_case())
        for result in (first, second):
            self.assertTrue(result['passed'], result)
            await self.assert_correlated(result, 180000)
        self.assertNotEqual(first['id'], second['id'])


class TailPrivacyTests(unittest.TestCase):
    def test_raw_headers_exceptions_and_extra_payload_are_never_retained(self):
        from scripts.collect_worker_diagnostics import sanitize
        identity = 'a' * 32
        private = 'NEVER-STORE-TOKEN-OR-CONTENT'
        envelope = {'event': {'request': {'headers': {'Authorization': private,
                    'X-WSVPN-Diagnostic-ID': identity}}}, 'exceptions': [{'message': private}],
                    'outcome': 'ok', 'logs': [{'message': [json.dumps({'schema': 'wsvpn-diag/1',
                    'side': 'worker', 'id': identity, 'event': 'tcp.write.complete', 'bytes': 81,
                    'payload': private, 'reason': private})]}]}
        result = sanitize(envelope, {identity})
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['bytes'], 81)
        self.assertNotIn(private, json.dumps(result))
        self.assertEqual(sanitize(envelope, {'b' * 32}), [])
