from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import struct
from typing import Dict, Optional


_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocketError(ConnectionError):
    pass


class WebSocketTunnel:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.closed = False
        self._fragment = bytearray()
        self._send_lock = asyncio.Lock()

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
    ) -> "WebSocketTunnel":
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host),
            timeout=timeout,
        )

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request_headers = {
            "Host": host,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
        }
        if headers:
            request_headers.update(headers)

        request = f"GET {path} HTTP/1.1\r\n" + "".join(
            f"{name}: {value}\r\n" for name, value in request_headers.items()
        ) + "\r\n"
        writer.write(request.encode("ascii"))
        await writer.drain()

        status = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not status.startswith(b"HTTP/1.1 101"):
            body = status.decode("utf-8", errors="replace").strip()
            writer.close()
            await writer.wait_closed()
            raise WebSocketError(f"WebSocket upgrade failed: {body}")

        response_headers: Dict[str, str] = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line in (b"\r\n", b"\n", b""):
                break
            name, sep, value = line.decode("latin1").partition(":")
            if sep:
                response_headers[name.strip().lower()] = value.strip()

        expected = base64.b64encode(
            hashlib.sha1((key + _GUID).encode("ascii")).digest()
        ).decode("ascii")
        if response_headers.get("sec-websocket-accept") != expected:
            writer.close()
            await writer.wait_closed()
            raise WebSocketError("Invalid Sec-WebSocket-Accept header")

        return cls(reader, writer)

    async def send(self, payload: bytes) -> None:
        if self.closed:
            raise WebSocketError("WebSocket is closed")
        frame = self._build_frame(0x2, payload, mask=True)
        async with self._send_lock:
            if self.closed:
                raise WebSocketError("WebSocket is closed")
            self.writer.write(frame)
            await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self.closed:
            opcode, payload, fin = await self._read_frame()
            if opcode == 0x8:
                self.closed = True
                return None
            if opcode == 0x9:
                async with self._send_lock:
                    self.writer.write(self._build_frame(0xA, payload, mask=True))
                    await self.writer.drain()
                continue
            if opcode == 0xA:
                continue
            if opcode not in (0x0, 0x1, 0x2):
                raise WebSocketError(f"Unsupported opcode: {opcode}")

            if fin and not self._fragment:
                return payload
            self._fragment.extend(payload)
            if fin:
                message = bytes(self._fragment)
                self._fragment.clear()
                return message
        return None

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            async with self._send_lock:
                self.writer.write(self._build_frame(0x8, b"", mask=True))
                await self.writer.drain()
        except Exception:
            pass
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass

    async def _read_frame(self):
        header = await self.reader.readexactly(2)
        b1, b2 = header
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F

        if length == 126:
            length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", await self.reader.readexactly(8))[0]

        mask = await self.reader.readexactly(4) if masked else None
        payload = await self.reader.readexactly(length)
        if mask:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        return opcode, payload, fin

    @staticmethod
    def _build_frame(opcode: int, payload: bytes, mask: bool) -> bytes:
        first = 0x80 | opcode
        length = len(payload)
        mask_bit = 0x80 if mask else 0
        if length < 126:
            header = bytes((first, mask_bit | length))
        elif length < 65536:
            header = bytes((first, mask_bit | 126)) + struct.pack(">H", length)
        else:
            header = bytes((first, mask_bit | 127)) + struct.pack(">Q", length)

        if not mask:
            return header + payload

        key = os.urandom(4)
        masked = bytes(byte ^ key[i % 4] for i, byte in enumerate(payload))
        return header + key + masked
