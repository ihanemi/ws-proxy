import test from "node:test";
import assert from "node:assert/strict";
import { createHandler } from "../src/handler.js";
import { publicIP, resolvePublic } from "../src/security.js";
import { decodeDNSDatagram, dnsResponse, validateQuery } from "../src/dns.js";

const tick = () => new Promise(resolve => setTimeout(resolve, 5));
class Socket {
  sent = []; listeners = {}; closeCalls = [];
  accept() { this.accepted = true; }
  send(frame) { this.sent.push([...frame]); }
  close(code, reason) { this.closeCalls.push([code, reason]); }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  message(frame) { this.listeners.message({ data: typeof frame === "string" ? frame : new Uint8Array(frame).buffer }); }
}
function setup(overrides = {}) {
  const ws = new Socket(), client = {};
  let controller;
  const writes = [];
  let eof = false, socketClosed = 0;
  const tcp = {
    opened: Promise.resolve(), closed: new Promise(() => {}),
    readable: new ReadableStream({ start(c) { controller = c; } }),
    writable: new WritableStream({ write(x) { writes.push([...x]); }, close() { eof = true; } }),
    close: async () => { socketClosed++; },
  };
  const connects = [];
  const tasks = [];
  const runtime = {
    pair: () => [client, ws],
    connect: (address, options) => { connects.push({ address, options }); return tcp; },
    fetcher: () => { throw new Error("unexpected DNS"); },
    upgrade: (socket, headers) => ({ status: 101, socket, headers }),
    ...overrides,
  };
  const handler = createHandler(runtime);
  const ctx = { waitUntil(task) { tasks.push(task); } };
  const request = (path = "/tunnel", headers = {}) => new Request("https://worker.test" + path, {
    headers: { Authorization: "Bearer test-only-token", Upgrade: "websocket", "Sec-WebSocket-Protocol": "wsvpn.v1",
      "X-Tunnel-Host": "8.8.8.8", "X-Tunnel-Port": "443", ...headers },
  });
  return { ws, request, writes, connects, tcp, ctx, tasks, controller: () => controller,
    eof: () => eof, closed: () => socketClosed,
    run: req => handler(req, { TUNNEL_TOKEN: "test-only-token" }, ctx),
    finish: async () => { ws.listeners.close?.({}); await Promise.allSettled(tasks); },
  };
}
const query = new Uint8Array([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
  7, ...new TextEncoder().encode("example"), 3, ...new TextEncoder().encode("com"), 0, 0, 1, 0, 1]);
const dnsFrame = (payload = query) => new Uint8Array([1, 1, 1, 1, 1, 1, 0, 53, ...payload]);
const answer = () => { const bytes = query.slice(); bytes[2] = 0x81; bytes[3] = 0x80; return bytes; };

test("auth/version/path validation precedes egress", async () => {
  const s = setup();
  for (const [path, headers, status] of [
    ["/tunnel", { Authorization: "Bearer wrong" }, 401],
    ["/tunnel", { "Sec-WebSocket-Protocol": "legacy" }, 426],
    ["/udp", {}, 404],
    ["/tunnel", { "X-Tunnel-Port": "443junk" }, 400],
    ["/tunnel", { "X-Tunnel-Port": "25" }, 400],
    ["/tunnel", { "X-Tunnel-Port": "53" }, 400],
    ["/tunnel", { "X-Tunnel-Host": "127.0.0.1" }, 400],
    ["/tunnel", { "X-Tunnel-Host": "8.8.8.8, 127.0.0.1" }, 400],
  ]) assert.equal((await s.run(s.request(path, headers))).status, status);
  assert.equal(s.connects.length, 0);
});

test("probe sends READY and echoes exactly one 32-byte challenge without TCP", async () => {
  const s = setup();
  const r = await s.run(s.request("/probe"));
  assert.equal(r.headers["Sec-WebSocket-Protocol"], "wsvpn.v1");
  assert.deepEqual(s.ws.sent, [[3]]);
  s.ws.message([1, ...new Uint8Array(32).fill(42)]);
  await tick();
  assert.deepEqual(s.ws.sent[1], [1, ...new Uint8Array(32).fill(42)]);
  assert.equal(s.connects.length, 0);
  await s.finish();
});

test("TCP framing, delayed READY, input EOF retains downstream until EOF", async () => {
  let open;
  const s = setup();
  s.tcp.opened = new Promise(resolve => { open = resolve; });
  const upgrade = s.run(s.request());
  await tick(); assert.deepEqual(s.ws.sent, []);
  open(); assert.equal((await upgrade).status, 101);
  s.ws.message([1, 10, 11]); s.ws.message([2]);
  await tick();
  assert.deepEqual(s.writes, [[10, 11]]); assert.equal(s.eof(), true);
  assert.equal(s.closed(), 0);
  s.controller().enqueue(new Uint8Array([20, 21])); s.controller().close();
  await tick();
  assert.deepEqual(s.ws.sent, [[3], [1, 20, 21], [2]]);
  assert.equal(s.ws.closeCalls[0][0], 1000);
  await s.finish(); assert.equal(s.closed(), 1);
});

test("remote EOF retains writable half", async () => {
  const s = setup(); await s.run(s.request());
  s.controller().close(); await tick();
  assert.deepEqual(s.ws.sent, [[3], [2]]); assert.equal(s.closed(), 0);
  s.ws.message([1, 5]); await tick(); assert.deepEqual(s.writes, [[5]]);
  s.ws.message([2]); await tick(); await s.finish();
});

test("ACK negotiation bounds downstream to one DATA frame", async () => {
  const s = setup();
  const r = await s.run(s.request("/tunnel", { "X-WSVPN-Flow-Control": "ack-v1" }));
  assert.equal(r.headers["X-WSVPN-Flow-Control"], "ack-v1");
  s.controller().enqueue(new Uint8Array(65537).fill(7));
  await tick(); assert.equal(s.ws.sent.length, 2); assert.equal(s.ws.sent[1].length, 65537);
  s.ws.message([4]); await tick(); assert.equal(s.ws.sent.length, 3);
  s.ws.message([4]); await tick(); await s.finish();
});

test("invalid text/type/oversize and duplicate EOF fail closed", async () => {
  for (const frame of ["text", [], [3], [2, 1], new Uint8Array(262146)]) {
    const s = setup(); await s.run(s.request()); s.ws.message(frame);
    await tick(); assert.equal(s.ws.closeCalls[0][0], 1002); await s.finish();
  }
  const s = setup(); await s.run(s.request()); s.ws.message([2]); s.ws.message([1, 10]);
  await tick(); assert.equal(s.ws.closeCalls[0][0], 1002); await s.finish();
});

test("queue overflow is bounded and releases sockets", async () => {
  const s = setup(); await s.run(s.request());
  for (let i = 0; i < 17; i++) s.ws.message([1, 1]);
  await tick(); assert.equal(s.ws.closeCalls[0][0], 1008); await s.finish(); assert.equal(s.closed(), 1);
});

test("connect failure is redacted, no READY/upgrade", async () => {
  const s = setup({ connect() { throw new Error("secret ip internal failure"); } });
  const r = await s.run(s.request());
  assert.equal(r.status, 502); assert.deepEqual(s.ws.sent, []);
  assert.doesNotMatch(await r.text(), /secret|internal/);
});

test("public address validation rejects private/reserved/transition/ambiguous forms", () => {
  for (const ip of ["0.0.0.0", "127.0.0.1", "10.1.1.1", "172.16.0.1", "192.168.1.1", "100.64.0.1",
    "169.254.1.1", "192.0.2.1", "224.0.0.1", "240.0.0.1", "::1", "fd00::1", "fe80::1", "ff02::1",
    "::ffff:8.8.8.8", "2002:0808:0808::", "2001::1", "2001:db8::1", "64:ff9b::808:808", "3fff::1",
    "0177.0.0.1", "127.1", "0x08080808", "8.8.8.8%eth0"]) assert.throws(() => publicIP(ip), ip);
  assert.equal(publicIP("8.8.8.8"), "8.8.8.8");
  assert.equal(publicIP("2606:4700:4700::1111"), "2606:4700:4700::1111");
});

test("DNS resolution validates all answers then pins numeric destination", async () => {
  for (const mixed of [false, true]) {
    let calls = 0;
    const fetcher = async (url, options) => {
      calls++; assert.equal(options.redirect, "manual");
      const type = new URL(url).searchParams.get("type") === "A" ? 1 : 28;
      return Response.json({ Status: 0, Question: [{ name: "example.com.", type }],
        Answer: type === 1 ? [{ type: 1, data: "8.8.8.8" }] : [{ type: 28, data: mixed ? "::1" : "2606:4700:4700::1111" }] });
    };
    if (mixed) await assert.rejects(resolvePublic("example.com", fetcher), /Blocked/);
    else assert.equal(await resolvePublic("example.com", fetcher), "8.8.8.8");
    assert.equal(calls, 2);
  }
});

test("DNS datagrams preserve markers and IDs and use fixed HTTPS POST", async () => {
  const s = setup({ fetcher: async (url, options) => {
    assert.equal(url, "https://cloudflare-dns.com/dns-query"); assert.equal(options.method, "POST");
    assert.equal(options.redirect, "manual"); assert.deepEqual(options.body, query);
    return new Response(answer(), { headers: { "Content-Type": "application/dns-message" } });
  } });
  await s.run(s.request("/dns")); s.ws.message(dnsFrame());
  await tick(); assert.deepEqual(s.ws.sent, [[3], [...dnsFrame(answer())]]);
  assert.equal(s.connects.length, 0); await s.finish();
});

test("generic UDP, malformed DNS, mismatch, oversized responses and DoH errors are rejected", async () => {
  const wrongPort = dnsFrame(); wrongPort[7] = 443 & 255;
  assert.throws(() => decodeDNSDatagram(wrongPort));
  for (const packet of [new Uint8Array(11), new Uint8Array(4097), query.slice(0, -1)]) assert.throws(() => validateQuery(packet));
  const response = answer(); response[0]++;
  for (const result of [
    new Response(response, { headers: { "Content-Type": "application/dns-message" } }),
    new Response(new Uint8Array(4097), { headers: { "Content-Type": "application/dns-message" } }),
    new Response("error", { status: 504 }),
  ]) await assert.rejects(dnsResponse(dnsFrame(), async () => result));
  const s = setup({ fetcher: async () => { throw new Error("DoH unreachable"); } });
  await s.run(s.request("/dns")); s.ws.message(dnsFrame()); await tick();
  assert.equal(s.ws.closeCalls[0][0], 1002); assert.deepEqual(s.ws.sent, [[3]]); await s.finish();
});

test("connect deadline closes a stalled socket and sends no READY", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const s = setup();
  s.tcp.opened = new Promise(() => {});
  const pending = s.run(s.request());
  for (let i = 0; i < 10; i++) await Promise.resolve();
  t.mock.timers.tick(10001);
  const response = await pending;
  assert.equal(response.status, 502); assert.deepEqual(s.ws.sent, []);
  assert.ok(s.closed() >= 1);
});

test("DNS timeout aborts HTTPS and closes without fallback", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let aborts = 0;
  const s = setup({ fetcher: (_url, { signal }) => new Promise((_, reject) => {
    signal.addEventListener("abort", () => { aborts++; reject(new Error("aborted")); });
  }) });
  await s.run(s.request("/dns")); s.ws.message(dnsFrame());
  for (let i = 0; i < 10; i++) await Promise.resolve();
  t.mock.timers.tick(10001);
  for (let i = 0; i < 10; i++) await Promise.resolve();
  assert.equal(aborts, 1); assert.equal(s.ws.closeCalls[0][0], 1002);
  assert.deepEqual(s.ws.sent, [[3]]); assert.equal(s.connects.length, 0);
  await s.finish();
});

test("missing ACK times out and closes downstream rather than buffering", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const s = setup();
  await s.run(s.request("/tunnel", { "X-WSVPN-Flow-Control": "ack-v1" }));
  s.controller().enqueue(new Uint8Array(131072));
  for (let i = 0; i < 10; i++) await Promise.resolve();
  assert.equal(s.ws.sent.length, 2);
  t.mock.timers.tick(30001);
  for (let i = 0; i < 10; i++) await Promise.resolve();
  assert.equal(s.ws.closeCalls[0][0], 1011); assert.equal(s.ws.sent.length, 2);
  await s.finish();
});

test("negotiated path echo precedes server-first TCP bytes and application writes", async () => {
  const s = setup();
  const response = await s.run(s.request("/tunnel", { "X-WSVPN-Path-Check": "echo-v1" }));
  assert.equal(response.headers["X-WSVPN-Path-Check"], "echo-v1");
  s.controller().enqueue(new Uint8Array([7, 8]));
  await tick(); assert.deepEqual(s.ws.sent, [[3]]);
  const challenge = [5, ...new Uint8Array(32).fill(42)];
  s.ws.message(challenge);
  await tick(); assert.deepEqual(s.ws.sent, [[3], challenge, [1, 7, 8]]);
  assert.deepEqual(s.writes, []);
  s.ws.message([1, 9]); await tick(); assert.deepEqual(s.writes, [[9]]);
  await s.finish(); assert.equal(s.closed(), 1);
});

test("negotiated DNS path echo has no upstream side effect", async () => {
  let calls = 0;
  const s = setup({ fetcher: async () => {
    calls++;
    return new Response(answer(), { headers: { "Content-Type": "application/dns-message" } });
  } });
  const response = await s.run(s.request("/dns", { "X-WSVPN-Path-Check": "echo-v1" }));
  assert.equal(response.headers["X-WSVPN-Path-Check"], "echo-v1");
  const challenge = [5, ...new Uint8Array(32).fill(13)];
  s.ws.message(challenge); await tick();
  assert.equal(calls, 0); assert.deepEqual(s.ws.sent, [[3], challenge]);
  s.ws.message(dnsFrame()); await tick();
  assert.equal(calls, 1); assert.deepEqual(s.ws.sent[2], [...dnsFrame(answer())]);
  await s.finish();
});

test("early application data, malformed and duplicate path challenges fail closed", async () => {
  const challenge = [5, ...new Uint8Array(32).fill(13)];
  for (const path of ["/tunnel", "/dns"]) {
    for (const early of [[1, 8], [5], [5, ...new Uint8Array(33)], [2]]) {
      const s = setup(); await s.run(s.request(path, { "X-WSVPN-Path-Check": "echo-v1" }));
      s.ws.message(early); await tick();
      assert.equal(s.ws.closeCalls[0][0], 1002); assert.deepEqual(s.writes, []);
      assert.deepEqual(s.ws.sent, [[3]]); await s.finish();
    }
    const s = setup(); await s.run(s.request(path, { "X-WSVPN-Path-Check": "echo-v1" }));
    s.ws.message(challenge); await tick(); s.ws.message(challenge); await tick();
    assert.equal(s.ws.closeCalls[0][0], 1002); await s.finish();
  }
});

test("path check timeout releases a TCP pump waiting behind the gate", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const s = setup(); await s.run(s.request("/tunnel", { "X-WSVPN-Path-Check": "echo-v1" }));
  s.controller().enqueue(new Uint8Array([10]));
  t.mock.timers.tick(10001);
  await s.finish();
  assert.equal(s.ws.closeCalls[0][0], 1008);
  assert.deepEqual(s.ws.sent, [[3]]); assert.deepEqual(s.writes, []);
  assert.equal(s.closed(), 1);
});
