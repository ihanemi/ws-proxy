"""One bounded synthetic HTTPS trace; never records payload or credentials.

Uses WS_VPN_TOKEN from the environment. Contract and flow control are explicit;
there is no destination fallback, automatic retry, or replay of application data.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import ssl
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vpn.config import VpnConfig  # noqa: E402
from vpn.websocket import WebSocketTunnel  # noqa: E402


async def trace(args, token):
    config = VpnConfig(args.relay, token, backend='cloudflare')
    events = []
    result = {'contract': args.contract, 'flow_control': args.flow_control,
              'target': args.target, 'address': args.ip, 'events': events, 'passed': False,
              'scope': 'first HTTP response fragment only; not full transfer or service health'}
    start = time.monotonic()
    phase = 'connect'
    tunnel = None

    def event(name, size=0):
        events.append({'sequence': len(events) + 1, 'seconds': round(time.monotonic() - start, 3),
                       'phase': phase, 'event': name, 'bytes': size})

    async def exchange():
        nonlocal tunnel, phase
        tunnel = await WebSocketTunnel.connect(
            config.relay_host, config.relay_port, config.relay_path,
            headers={'Authorization': 'Bearer ' + token,
                     'X-Tunnel-Host': args.target, 'X-Tunnel-Port': '443'},
            resolved_ips=(args.ip,), timeout=args.timeout,
            flow_control=args.flow_control == 'ack-v1',
            check_path=args.contract == 'echo-v1', path_challenge=args.contract == 'echo-v1',
        )
        event('ready')
        send, recv = tunnel.connection.send, tunnel.connection.recv

        async def counted_send(frame, *a, **kw):
            event('ws.send.ack' if frame == b'\x04' else 'ws.send.data', len(frame))
            await send(frame, *a, **kw)
            event('ws.send.completed', len(frame))

        async def counted_recv(*a, **kw):
            frame = await recv(*a, **kw)
            event('ws.recv.control' if len(frame) == 1 else 'ws.recv.data', len(frame))
            return frame

        tunnel.connection.send, tunnel.connection.recv = counted_send, counted_recv
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(
            incoming, outgoing, server_side=False, server_hostname=args.target)

        async def flush():
            while outgoing.pending:
                data = outgoing.read()
                event('tls.encrypted.output', len(data))
                await tunnel.send(data)

        async def feed():
            data = await tunnel.recv()
            if data is None:
                event('tcp.eof')
                incoming.write_eof()
            else:
                event('tls.encrypted.input', len(data))
                incoming.write(data)

        phase = 'tls_handshake'
        while True:
            try:
                tls.do_handshake()
                await flush()
                break
            except ssl.SSLWantReadError:
                await flush()
                await feed()
        result.update(certificate_verified=True, tls=tls.version())
        event('tls.verified')
        phase = 'http_request'
        request = f'GET / HTTP/1.1\r\nHost: {args.target}\r\nConnection: close\r\n\r\n'.encode()
        event('synthetic.request.accepted', tls.write(request))
        await flush()
        phase = 'http_response'
        while True:
            try:
                data = tls.read(32768)
                event('synthetic.response.bytes', len(data))
                # Count only; never persist or print the decrypted response.
                result.update(passed=data.startswith(b'HTTP/1.'), response_bytes=len(data))
                break
            except ssl.SSLWantReadError:
                await flush()
                await feed()

    try:
        await asyncio.wait_for(exchange(), args.timeout)
    except Exception as exc:
        result.update(error=type(exc).__name__, failed_phase=phase)
    finally:
        if tunnel:
            tunnel.abort()
        result['seconds'] = round(time.monotonic() - start, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--relay', required=True)
    parser.add_argument('--ip', required=True, help='Explicit pinned Worker IPv4 address')
    parser.add_argument('--contract', required=True, choices=['legacy', 'echo-v1'])
    parser.add_argument('--flow-control', required=True, choices=['legacy', 'ack-v1'])
    parser.add_argument('--target', choices=['www.google.com', 'www.microsoft.com'], default='www.google.com')
    parser.add_argument('--timeout', type=float, default=8)
    parser.add_argument('--output', type=Path, required=True, help='New evidence file; never overwrite')
    args = parser.parse_args()
    if not 0 < args.timeout <= 30:
        parser.error('Timeout must be between 0 and 30 seconds')
    token = os.environ.get('WS_VPN_TOKEN', '')
    if not token:
        parser.error('Set WS_VPN_TOKEN securely in this process environment')
    # Reserve the evidence file before sending traffic, preserving previous runs.
    with args.output.open('x', encoding='utf-8') as output:
        result = asyncio.run(trace(args, token))
        json.dump(result, output, indent=2)
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
