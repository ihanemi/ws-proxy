import test from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

async function runtime(t, fetcher) {
  const bundle = await build({ entryPoints: ["src/index.js"], bundle: true, write: false,
    format: "esm", external: ["cloudflare:sockets"] });
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text,
    compatibilityDate: "2026-09-09", bindings: { TUNNEL_TOKEN: "test-only-token" },
    outboundService: fetcher || (() => new Response("Unexpected egress", { status: 502 })),
  }));
  t.after(() => mf.dispose());
  return mf;
}
const headers = { Authorization: "Bearer test-only-token", Upgrade: "websocket", "Sec-WebSocket-Protocol": "wsvpn.v1" };
function inbox(ws) {
  const messages = [], waiters = [];
  let closed;
  ws.addEventListener("close", e => {
    closed = new Error(`WS closed: ${e.code} ${e.reason}`);
    for (const waiter of waiters.splice(0)) waiter.reject(closed);
  });
  ws.addEventListener("message", event => {
    const value = new Uint8Array(event.data);
    const waiter = waiters.shift();
    if (waiter) waiter.resolve(value); else messages.push(value);
  });
  ws.accept();
  return () => messages.length ? Promise.resolve(messages.shift()) : new Promise((resolve, reject) => closed ? reject(closed) : waiters.push({ resolve, reject }));
}

test("actual workerd runtime negotiates WSVPN/1 and probe framing", { timeout: 15000 }, async t => {
  const mf = await runtime(t);
  const denied = await mf.dispatchFetch("https://worker.test/probe", { headers: { ...headers, Authorization: "Bearer wrong" } });
  assert.equal(denied.status, 401);
  const response = await mf.dispatchFetch("https://worker.test/probe", { headers });
  assert.equal(response.status, 101);
  assert.equal(response.headers.get("Sec-WebSocket-Protocol"), "wsvpn.v1");
  const ws = response.webSocket;
  const recv = inbox(ws);
  assert.deepEqual([...await recv()], [3]);
  const frame = new Uint8Array([1, ...new Uint8Array(32).fill(77)]);
  ws.send(frame);
  assert.deepEqual(await recv(), frame);
  ws.close();
});

test("actual workerd runtime handles DNS binary type and HTTPS mediation", { timeout: 15000 }, async t => {
  let calls = 0;
  const mf = await runtime(t, async req => {
    calls++;
    assert.equal(req.url, "https://cloudflare-dns.com/dns-query");
    assert.equal(req.method, "POST");
    const answer = new Uint8Array(await req.arrayBuffer());
    answer[2] = 0x81; answer[3] = 0x80;
    return new Response(answer, { headers: { "Content-Type": "application/dns-message" } });
  });
  const response = await mf.dispatchFetch("https://worker.test/dns", { headers });
  assert.equal(response.status, 101);
  const ws = response.webSocket;
  const recv = inbox(ws);
  assert.deepEqual([...await recv()], [3]);
  const query = new Uint8Array([1, 1, 1, 1, 1, 1, 0, 53,
    0, 42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, ...new TextEncoder().encode("example"),
    3, ...new TextEncoder().encode("com"), 0, 0, 1, 0, 1]);
  ws.send(query);
  const answer = await recv();
  assert.equal(answer[8], 0); assert.equal(answer[9], 42); assert.equal(answer[10], 0x81);
  assert.equal(calls, 1);
  ws.close();
});
