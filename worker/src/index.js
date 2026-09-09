import { connect } from "cloudflare:sockets";

const textEncoder = new TextEncoder();

function unauthorized() {
  return new Response("Unauthorized", { status: 401 });
}

function badRequest(message) {
  return new Response(message, { status: 400 });
}

function isValidPort(value) {
  return Number.isInteger(value) && value >= 1 && value <= 65535 && value !== 25;
}

function isBlockedHost(host) {
  const normalized = host.trim().toLowerCase();
  if (!normalized) return true;
  if (normalized === "localhost" || normalized.endsWith(".localhost")) return true;
  if (normalized === "0.0.0.0" || normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("127.")) return true;
  if (normalized.startsWith("10.")) return true;
  if (normalized.startsWith("192.168.")) return true;
  const parts = normalized.split(".");
  if (parts.length === 4) {
    const a = Number(parts[0]);
    const b = Number(parts[1]);
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
  }
  return false;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ ok: true });
    }

    if (url.pathname !== "/tunnel") {
      return new Response("Not found", { status: 404 });
    }

    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket upgrade", { status: 426 });
    }

    const expectedToken = env.TUNNEL_TOKEN;
    const authorization = request.headers.get("Authorization") || "";
    if (!expectedToken || authorization !== `Bearer ${expectedToken}`) {
      return unauthorized();
    }

    const host = request.headers.get("X-Tunnel-Host") || "";
    const port = Number.parseInt(request.headers.get("X-Tunnel-Port") || "", 10);
    if (isBlockedHost(host)) {
      return badRequest("Blocked destination");
    }
    if (!isValidPort(port)) {
      return badRequest("Invalid destination port");
    }

    let tcp;
    try {
      tcp = connect({ hostname: host, port }, { allowHalfOpen: true });
      await tcp.opened;
    } catch (error) {
      return new Response(`TCP connect failed: ${String(error)}`, { status: 502 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept({ allowHalfOpen: true });

    const tcpWriter = tcp.writable.getWriter();
    let closed = false;

    const closeAll = async (code = 1000, reason = "closed") => {
      if (closed) return;
      closed = true;
      try { await tcpWriter.close(); } catch {}
      try { tcp.close(); } catch {}
      try { server.close(code, reason); } catch {}
    };

    server.addEventListener("message", (event) => {
      const data = event.data;
      let chunk;
      if (data instanceof ArrayBuffer) {
        chunk = new Uint8Array(data);
      } else if (ArrayBuffer.isView(data)) {
        chunk = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      } else if (typeof data === "string") {
        chunk = textEncoder.encode(data);
      } else {
        closeAll(1003, "unsupported frame");
        return;
      }
      ctx.waitUntil(
        tcpWriter.write(chunk).catch(() => closeAll(1011, "tcp write failed"))
      );
    });

    server.addEventListener("close", () => {
      ctx.waitUntil(closeAll());
    });

    server.addEventListener("error", () => {
      ctx.waitUntil(closeAll(1011, "websocket error"));
    });

    const pumpTcpToWs = async () => {
      const reader = tcp.readable.getReader();
      try {
        while (!closed) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.byteLength) {
            server.send(value);
          }
        }
        await closeAll();
      } catch {
        await closeAll(1011, "tcp read failed");
      } finally {
        try { reader.releaseLock(); } catch {}
      }
    };

    ctx.waitUntil(pumpTcpToWs());

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  },
};
