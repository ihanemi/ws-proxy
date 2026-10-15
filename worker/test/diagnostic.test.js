import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { buildDiagnostic, scopeHandler } from "../diagnostic/build.mjs";
import { createTrace, scopedRuntime, ID_HEADER, MAX_EVENTS } from "../diagnostic/runtime.js";

const id = "a".repeat(32), secret = "private-user-content-and-token";
function request(extra = {}) {
  return new Request("https://worker.test/tunnel", { headers: {
    Authorization: `Bearer ${secret}`, [ID_HEADER]: id, "X-WSVPN-Flow-Control": "ack-v1", ...extra,
  } });
}

test("diagnostic wrappers preserve bytes, failures, EOF and cancellation", async () => {
  const rows = [], writes = [], calls = [], listeners = {}, sent = [];
  const payload = new TextEncoder().encode(secret), failure = new Error(secret);
  let fail = false;
  const socket = { opened: Promise.resolve(), closed: new Promise(() => {}),
    readable: { getReader: () => ({ read: () => Promise.resolve({ value: payload, done: false }),
      cancel: () => { calls.push("read-cancel"); return Promise.resolve(); } }) },
    writable: { getWriter: () => ({ write: value => { writes.push(value); return fail ? Promise.reject(failure) : Promise.resolve(42); },
      close: () => { calls.push("write-eof"); return Promise.resolve(); },
      abort: () => { calls.push("write-cancel"); return Promise.resolve(); } }) }, close: () => Promise.resolve() };
  const ws = { addEventListener: (type, fn) => { listeners[type] = fn; },
    send: value => { sent.push(value); return 37; }, close: () => 19, accept() {} };
  const native = { connect: () => socket, pair: () => [{}, ws], upgrade: (_client, headers) => headers };
  const runtime = scopedRuntime(native, request(), { TUNNEL_TOKEN: secret }, row => rows.push(row));
  const wrapped = runtime.connect({ hostname: "8.8.8.8", port: 443 }, { allowHalfOpen: true });
  await wrapped.opened;
  const w = wrapped.writable.getWriter(), r = wrapped.readable.getReader();
  assert.equal(await w.write(payload), 42); assert.equal(writes[0], payload);
  assert.equal((await r.read()).value, payload);
  await w.close(); await r.cancel(secret); await w.abort(secret);
  assert.deepEqual(calls, ["write-eof", "read-cancel", "write-cancel"]);
  fail = true; await assert.rejects(w.write(payload), error => error === failure);
  const [, server] = runtime.pair();
  server.addEventListener("message", () => {});
  listeners.message({ data: new Uint8Array([1, ...payload]).buffer });
  const frame = new Uint8Array([1, ...payload]);
  assert.equal(server.send(frame), 37); assert.equal(sent[0], frame);
  listeners.message({ data: new Uint8Array([4]).buffer });
  listeners.message({ data: new Uint8Array([2]).buffer });
  server.send(new Uint8Array([2]));
  assert.equal(server.close(1000, secret), 19);
  assert.ok(rows.some(x => x.event === "ws.ack.received" && x.ack_pending === 0));
  for (const event of ["tcp.write.error", "tcp.write.eof.complete", "tcp.read.cancel", "ws.eof.received", "ws.eof.sent"]) {
    assert.ok(rows.some(x => x.event === event), event);
  }
  assert.equal(runtime.upgrade({}, {})[ID_HEADER], id);
  assert.ok(!JSON.stringify(rows).includes(secret));
  assert.ok(rows.every(x => x.schema === "wsvpn-diag/1" && x.id === id));
});

test("diagnostics are authenticated, opt-in, bounded and log-injection safe", () => {
  const native = {}, rows = [];
  for (const headers of [{ [ID_HEADER]: secret }, { [ID_HEADER]: "" }, { Authorization: "Bearer wrong" }]) {
    assert.equal(scopedRuntime(native, request(headers), { TUNNEL_TOKEN: secret }, x => rows.push(x)), native);
  }
  assert.equal(rows.length, 0);
  const trace = createTrace(id, x => rows.push(x));
  for (let i = 0; i < 1000; i++) trace.event("tcp.read.begin");
  trace.event("ws.close.request", 0, secret, true);
  assert.equal(rows.length, MAX_EVENTS + 1);
  assert.equal(rows.at(-1).reason, "other");
  assert.ok(!JSON.stringify(rows).includes(secret));
  assert.doesNotThrow(() => createTrace(id, () => { throw new Error(secret); }).event("tcp.read.begin"));
});

test("diagnostic build keeps shared admission, auth, protocol and source unchanged", { timeout: 15000 }, async t => {
  const before = await readFile("src/handler.js", "utf8");
  assert.throws(() => scopeHandler(before.replace("createHandler(runtime)", "changed(runtime)")), /review required/);
  const bundle = await buildDiagnostic();
  assert.ok(!bundle.includes("__local_stats"));
  assert.ok(!bundle.includes("origin.response.complete"));
  assert.equal(await readFile("src/handler.js", "utf8"), before);
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle,
    compatibilityDate: "2026-09-09", bindings: { TUNNEL_TOKEN: "test-only-token" } }));
  t.after(() => mf.dispose());
  const headers = { Authorization: "Bearer test-only-token", Upgrade: "websocket", "Sec-WebSocket-Protocol": "wsvpn.v1" };
  assert.equal((await mf.dispatchFetch("http://worker.test/probe", { headers: { ...headers, Authorization: "wrong" } })).status, 401);
  assert.equal((await mf.dispatchFetch("http://worker.test/probe", { headers: { ...headers, "Sec-WebSocket-Protocol": "wrong" } })).status, 426);
  const peers = [];
  for (let i = 0; i < 8; i++) {
    const response = await mf.dispatchFetch("http://worker.test/probe", { headers });
    assert.equal(response.status, 101); response.webSocket.accept(); peers.push(response.webSocket);
  }
  assert.equal((await mf.dispatchFetch("http://worker.test/probe", { headers })).status, 503);
  for (const peer of peers) peer.close();
});
