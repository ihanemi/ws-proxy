"""Bounded opt-in tail collector. Raw Cloudflare envelopes never reach disk/stdout."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time

ID = re.compile(r'^[0-9a-f]{32}$')
EVENTS = set('request.accepted tcp.connect.begin tcp.connect.complete tcp.connect.error tcp.closed '
             'tcp.closed.error tcp.read.begin tcp.read.complete tcp.read.error tcp.read.cancel tcp.eof '
             'tcp.write.begin tcp.write.complete tcp.write.error tcp.write.eof.begin tcp.write.eof.complete '
             'tcp.write.cancel tcp.close.request ws.data.received ws.data.sent ws.ack.received flow.ack.wait '
             'ws.eof.received ws.eof.sent ws.path_check.received ws.control.received ws.control.sent '
             'ws.close.received ws.close.request ws.error ws.upgrade session.summary'.split())
NUMBERS = set('seq elapsed_ms bytes ws_rx_bytes ws_rx_frames tcp_write_bytes tcp_writes tcp_read_bytes '
              'tcp_reads ws_tx_bytes ws_tx_frames ack_rx ack_pending read_cancels write_cancels tcp_eof ws_eof_rx ws_eof_tx close_requests events_suppressed'.split())
REASONS = set('closed|idle timeout|websocket error|invalid frame|unexpected ACK|queue limit|session failed|'
              'tcp read failed|tcp socket failed|upgrade failed|path check timeout|other'.split('|'))
OUTCOMES = set('ok exception exceededCpu exceededMemory canceled unknown loadShed responseStreamDisconnected scriptNotFound'.split())


def sanitize(envelope, ids):
    result = []
    for entry in envelope.get('logs', []):
        for value in entry.get('message', []):
            try:
                row = json.loads(value) if isinstance(value, str) else value
            except (ValueError, TypeError):
                continue
            if (not isinstance(row, dict) or row.get('schema') != 'wsvpn-diag/1' or
                    row.get('side') != 'worker' or not isinstance(row.get('id'), str) or
                    not isinstance(row.get('event'), str) or row.get('id') not in ids or row.get('event') not in EVENTS):
                continue
            clean = {k: row[k] for k in ('schema', 'side', 'id', 'event')}
            for key in NUMBERS:
                value = row.get(key)
                if type(value) is int and 0 <= value <= 2**53:
                    clean[key] = value
            if isinstance(row.get('reason'), str) and row['reason'] in REASONS:
                clean['reason'] = row['reason']
            result.append(clean)
    request = (envelope.get('event') or {}).get('request') or {}
    headers = {k.lower(): v for k, v in request.get('headers', {}).items()}
    correlation = headers.get('x-wsvpn-diagnostic-id')
    if isinstance(correlation, str) and correlation in ids and 'outcome' in envelope:
        outcome = envelope['outcome']
        result.append({'schema': 'wsvpn-diag/1', 'side': 'runtime', 'id': correlation,
                       'event': 'request.outcome', 'outcome': outcome if isinstance(outcome, str) and outcome in OUTCOMES else 'other'})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorized-live-tail', action='store_true')
    parser.add_argument('--node', default='node')
    parser.add_argument('--wrangler-root', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--ids-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=180)
    args = parser.parse_args()
    if not args.authorized_live_tail:
        parser.error('Live tail requires separate explicit authorization; preparation/tests do not start it')
    ids = set(json.loads(args.ids_file.read_text(encoding='utf-8')))
    if not 1 <= len(ids) <= 16 or not all(isinstance(x, str) and ID.fullmatch(x) for x in ids):
        parser.error('Expected 1..16 fresh synthetic correlation IDs')
    if not 1 <= args.seconds <= 240:
        parser.error('Tail duration must be 1..240 seconds')
    config = json.loads(args.config.read_text(encoding='utf-8'))
    if config.get('name') != 'ws-vpn-laptop-9583b21' or config.get('account_id') != 'f97e1b7fd6a5f23a1ffb8c4f0450c58e':
        parser.error('Only the exact approved test Worker/account can be tailed')
    package = json.loads((args.wrangler_root / 'package.json').read_text(encoding='utf-8'))
    if package['version'] != '4.149.0':
        parser.error('Review required: pinned Wrangler version changed')
    env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID='f97e1b7fd6a5f23a1ffb8c4f0450c58e', WRANGLER_SEND_METRICS='false', CLOUDFLARE_AUTH_USE_KEYRING='true', NO_COLOR='1')
    for name in ('CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_API_KEY', 'CLOUDFLARE_EMAIL'):
        env.pop(name, None)
    with args.output.open('x', encoding='utf-8') as output:
        # Direct pinned CLI avoids the launcher's extra child process.
        process = subprocess.Popen([args.node, '--no-warnings', str(args.wrangler_root / 'wrangler-dist/cli.js'),
                                    'tail', '--config', str(args.config), '--format', 'json'],
                                   env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
        lines = queue.Queue(maxsize=16)
        lost = {'queue_drops': 0, 'oversized': 0}

        def read():
            for line in iter(lambda: process.stdout.readline(1024 * 1024 + 1), ''):
                try:
                    lines.put(line, timeout=.2)
                except queue.Full:
                    lost['queue_drops'] += 1  # Never hide incomplete telemetry.

        threading.Thread(target=read, daemon=True).start()
        deadline, buffer, count = time.monotonic() + args.seconds, '', 0
        try:
            while time.monotonic() < deadline and count < 2000:
                try:
                    line = lines.get(timeout=.2)
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                if len(line) > 1024 * 1024 or len(buffer) + len(line) > 1024 * 1024:
                    lost['oversized'] += 1
                    buffer = ''
                    continue
                if not buffer and not line.lstrip().startswith('{'):
                    continue
                buffer += line
                try:
                    envelope = json.loads(buffer)
                except ValueError:
                    continue
                buffer = ''
                for row in sanitize(envelope, ids):
                    output.write(json.dumps(row) + '\n')
                    output.flush()
                    count += 1
                    if count >= 2000:
                        break
        finally:
            stop_reason = 'row_limit' if count >= 2000 else 'deadline' if time.monotonic() >= deadline else 'process_exit'
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    print(json.dumps({'side': 'collector', 'event': 'stopped', 'sanitized_rows': count, 'stop_reason': stop_reason, **lost}))
    return 0 if stop_reason == 'deadline' and count and not any(lost.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
