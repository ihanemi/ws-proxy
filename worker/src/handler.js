import { resolvePublic, validHost, validPort } from "./security.js";
import { dnsResponse } from "./dns.js";
import { startSession } from "./session.js";

const SUBPROTOCOL = "wsvpn.v1";
// Isolate-local admission control, not a global/account-wide security limit.
const MAX_SESSIONS = 8;

export function createHandler(runtime) {
  let active = 0;
  return async (request, env, ctx) => {
    const path = new URL(request.url).pathname;
    if (path === "/health" || path === "/healthz") return Response.json({ ok: true, backend: "cloudflare", tcp: true, dns: true, udp: false });
    if (!["/tunnel", "/probe", "/dns"].includes(path)) return new Response("Not found", { status: 404 });
    if (request.method !== "GET") return new Response("Method not allowed", { status: 405 });
    const token = env.TUNNEL_TOKEN;
    if (!token || token.length > 4096 || /[^\x21-\x7e]/.test(token) ||
        request.headers.get("Authorization") !== `Bearer ${token}`) return new Response("Unauthorized", { status: 401 });
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket" ||
        !request.headers.get("Sec-WebSocket-Protocol")?.split(",").map(x => x.trim()).includes(SUBPROTOCOL)) {
      return new Response("WSVPN/1 required", { status: 426 });
    }
    let port;
    if (path === "/tunnel") {
      try {
        port = validPort(request.headers.get("X-Tunnel-Port"));
        validHost(request.headers.get("X-Tunnel-Host"));
      } catch { return new Response("Invalid destination", { status: 400 }); }
    }
    if (active >= MAX_SESSIONS) return new Response("Session limit", { status: 503 });
    active++;
    let released = false;
    const release = () => { if (!released) { released = true; active--; } };
    let tcp;
    let session;
    try {
      if (path === "/tunnel") {
        const controller = new AbortController();
        const timer = setTimeout(() => { controller.abort(); tcp?.close().catch(() => {}); }, 10000);
        try {
          // Promise deadline also covers a runtime connect() that doesn't settle.
          let timeout;
          const deadline = new Promise((_, reject) => {
            timeout = () => reject(new Error("Connect timeout"));
            controller.signal.addEventListener("abort", timeout, { once: true });
          });
          try {
            await Promise.race([deadline, (async () => {
              const host = await resolvePublic(request.headers.get("X-Tunnel-Host"), runtime.fetcher, controller.signal);
              if (controller.signal.aborted) throw new Error("Connect timeout");
              tcp = runtime.connect({ hostname: host, port }, { allowHalfOpen: true });
              tcp.closed.catch(() => {});
              await tcp.opened;
            })()]);
          } finally { controller.signal.removeEventListener("abort", timeout); }
        } finally { clearTimeout(timer); }
      }
      const [client, server] = runtime.pair();
      const flowControl = path === "/tunnel" && request.headers.get("X-WSVPN-Flow-Control") === "ack-v1";
      const pathCheck = path !== "/probe" && request.headers.get("X-WSVPN-Path-Check") === "echo-v1";
      session = startSession(server, tcp, path === "/tunnel" ? "tcp" : path.slice(1), {
        ...runtime, dnsResponse, waitUntil: task => ctx.waitUntil(task),
      }, release, flowControl, pathCheck);
      return runtime.upgrade(client, {
        "Sec-WebSocket-Protocol": SUBPROTOCOL,
        ...(flowControl ? { "X-WSVPN-Flow-Control": "ack-v1" } : {}),
        ...(pathCheck ? { "X-WSVPN-Path-Check": "echo-v1" } : {}),
      });
    } catch {
      if (session) session.close(1011, "upgrade failed");
      else { await tcp?.close().catch(() => {}); release(); }
      // Don't disclose resolver/socket errors, IPs or credentials in HTTP/logs.
      return new Response("Destination or transport unavailable", { status: 502 });
    }
  };
}
