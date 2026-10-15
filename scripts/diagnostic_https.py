"""One correlated synthetic request; no payload/key/credential logging or retry."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import time
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vpn.config import VpnConfig  # noqa: E402
from vpn.websocket import WebSocketTunnel  # noqa: E402

ID_HEADER = 'X-WSVPN-Diagnostic-ID'
VALID_ID = re.compile(r'^[0-9a-f]{32}$')
BODY_BYTES = 180000


async def experiment(args, token):
    if not VALID_ID.fullmatch(args.id):
        raise ValueError('Invalid correlation ID')
    origin = urlparse(args.origin)
    if (origin.scheme != 'https' or not origin.hostname or origin.username or origin.password
            or origin.query or origin.fragment or origin.path not in ('', '/')):
        raise ValueError('Origin must be a plain HTTPS origin URL')
    cfg = VpnConfig(args.relay, token, backend='cloudflare')
    report = {'schema': 'wsvpn-diag/1', 'side': 'client', 'id': args.id, 'mode': args.mode,
              'contract': args.contract, 'passed': False, 'response_bytes': 0, 'events': []}
    start = time.monotonic()
    phase = 'connect'
    tunnel = None

    def event(name, n=0):
        if len(report['events']) < 128:
            report['events'].append({'seq': len(report['events']) + 1, 'elapsed_ms':
                                     round((time.monotonic() - start) * 1000),
                                     'event': name, 'phase': phase, 'bytes': n})

    async def run():
        nonlocal tunnel, phase
        origin_ca = ssl.create_default_context(cafile=getattr(args, 'origin_ca', None))
        tunnel = await WebSocketTunnel.connect(
            cfg.relay_host, cfg.relay_port, cfg.relay_path, timeout=args.timeout,
            resolved_ips=(args.ip,), flow_control=True, check_path=args.contract == 'echo-v1',
            path_challenge=args.contract == 'echo-v1', headers={
                'Authorization': 'Bearer ' + token, 'X-Tunnel-Host': origin.hostname,
                'X-Tunnel-Port': str(origin.port or 443), ID_HEADER: args.id},
        )
        if tunnel.connection.response.headers.get(ID_HEADER) != args.id:
            raise ConnectionError('Diagnostic build did not echo correlation ID')
        event('ws.ready')
        send, recv = tunnel.connection.send, tunnel.connection.recv

        async def counted_send(frame, *a, **kw):
            event('ws.ack.sent' if frame == b'\x04' else 'ws.data.send', len(frame))
            await send(frame, *a, **kw)
            event('ws.send.complete', len(frame))

        async def counted_recv(*a, **kw):
            frame = await recv(*a, **kw)
            event('ws.control.received' if len(frame) == 1 else 'ws.data.received', len(frame))
            return frame

        tunnel.connection.send, tunnel.connection.recv = counted_send, counted_recv
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = origin_ca.wrap_bio(incoming, outgoing, server_side=False, server_hostname=origin.hostname)

        async def flush():
            while outgoing.pending:
                data = outgoing.read()
                event('tls.encrypted.output', len(data))
                await tunnel.send(data)

        async def feed():
            data = await tunnel.recv()
            if data is None:
                incoming.write_eof()
                event('tcp.eof')
            else:
                event('tls.encrypted.input', len(data))
                incoming.write(data)

        phase = 'tls'
        while True:
            try:
                tls.do_handshake()
                await flush()
                break
            except ssl.SSLWantReadError:
                await flush()
                await feed()
        report['certificate_verified'] = True
        event('tls.verified')
        phase = 'request'
        request = (f'GET /_wsvpn_diag/{args.mode} HTTP/1.1\r\nHost: {origin.hostname}\r\n'
                   f'{ID_HEADER}: {args.id}\r\nConnection: close\r\n\r\n').encode('ascii')
        event('synthetic.request.accepted', tls.write(request))
        await flush()
        phase = 'response'
        header = b''
        headers_done = False
        while report['response_bytes'] < BODY_BYTES:
            try:
                chunk = tls.read(32768)
            except ssl.SSLWantReadError:
                await flush()
                await feed()
                continue
            if not chunk:
                raise EOFError('Synthetic response incomplete')
            if not headers_done:
                header += chunk
                split = header.find(b'\r\n\r\n')
                if split < 0:
                    if len(header) > 8192:
                        raise ValueError('Origin header limit')
                    continue
                if split > 8192:
                    raise ValueError('Origin header limit')
                lines = header[:split].decode('ascii').split('\r\n')
                fields = dict(line.split(':', 1) for line in lines[1:])
                fields = {k.lower(): v.strip() for k, v in fields.items()}
                if (not lines[0].startswith('HTTP/1.1 200 ') or
                        fields.get(ID_HEADER.lower()) != args.id or
                        fields.get('content-length') != str(BODY_BYTES)):
                    raise ValueError('Synthetic origin response mismatch')
                chunk, header, headers_done = header[split + 4:], b'', True
                event('origin.headers.validated')
            if any(byte != 65 for byte in chunk):
                raise ValueError('Synthetic response content mismatch')
            report['response_bytes'] += len(chunk)
            event('synthetic.response.bytes', len(chunk))
            if report['response_bytes'] > BODY_BYTES:
                raise ValueError('Synthetic response size limit')
        report['passed'] = True

    try:
        await asyncio.wait_for(run(), args.timeout)
    except Exception as error:
        report.update(error=type(error).__name__, failed_phase=phase)
        event('client.cancel' if isinstance(error, (TimeoutError, asyncio.TimeoutError)) else 'client.failed')
    finally:
        if tunnel:
            try:
                await asyncio.wait_for(tunnel.close(), .5)
            except (OSError, TimeoutError, asyncio.TimeoutError):
                pass
            finally:
                tunnel.abort()
            event('client.close')
        report['elapsed_ms'] = round((time.monotonic() - start) * 1000)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--relay', required=True)
    parser.add_argument('--ip', required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--contract', choices=['legacy', 'echo-v1'], required=True)
    parser.add_argument('--mode', choices=['ok', 'stall-response', 'stall-body'], default='ok')
    parser.add_argument('--id', default=secrets.token_hex(16))
    parser.add_argument('--timeout', type=float, default=12)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 0 < args.timeout <= 20:
        parser.error('Overall timeout must be between 0 and 20 seconds')
    token = os.environ.get('WS_VPN_TOKEN', '')
    if not token:
        parser.error('Load WS_VPN_TOKEN securely into this process environment')
    with args.output.open('x', encoding='utf-8') as output:
        report = asyncio.run(experiment(args, token))
        json.dump(report, output, indent=2)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
