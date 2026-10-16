import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse, format } from "node:url";
import { EventEmitter } from "node:events";
import { createOrigin, validateExperiment, ID_HEADER, BODY_BYTES, SOURCE_HEADER, SOURCE_MARKER,
  REJECTION_HEADER, REJECTION_LOG_LIMIT } from "../diagnostic/vercel/api/origin.mjs";
import { stageOrigin } from "../diagnostic/stage-vercel.mjs";

const ids = Array.from({ length: 7 }, (_, i) => (i + 1).toString(16).padStart(32, "0"));
const config = () => ({ ids, not_before_ms: Date.now() - 100, expires_ms: Date.now() + 120000 });
// Same URL transformation as pinned Vercel CLI 64.2.0 dev/server, replayed offline.
function rewrite(url) {
  const mode = /^\/_wsvpn_diag\/(ok|stall-response|stall-body)$/.exec(parse(url).pathname)?.[1];
  if (!mode) return url;
  const parsed = parse(url);
  parsed.search = parse(`/api/origin?mode=${mode}`).search;
  return format(parsed);
}
async function fixture(t, options = {}, secure = false, rewritten = false) {
  const events = [], sockets = new Set();
  const handler = createOrigin(config(), { emit: row => events.push(row), ...options });
  let tls;
  if (secure) {
    const dir = await mkdtemp(join(tmpdir(), "wsvpn-vercel-tls-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "key.pem"),
      "-out", join(dir, "cert.pem"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], { stdio: "ignore" });
    tls = { key: await readFile(join(dir, "key.pem")), cert: await readFile(join(dir, "cert.pem")) };
  }
  const dispatch = (req, res) => { if (rewritten) req.url = rewrite(req.url); return handler(req, res); };
  const server = tls ? https.createServer(tls, dispatch) : http.createServer(dispatch);
  server.on("connection", s => { sockets.add(s); s.once("close", () => sockets.delete(s)); });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { for (const s of sockets) s.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { port: server.address().port, events, ca: tls?.cert };
}
function request(port, id, mode, extra = {}) {
  const start = performance.now();
  return new Promise((resolve, reject) => {
    const result = { status: null, bytes: 0, first_ms: null, elapsed_ms: null, complete: false };
    const finish = () => { result.elapsed_ms = performance.now() - start; resolve(result); };
    const req = (extra.ca ? https : http).request({ host: "127.0.0.1", port, servername: "localhost", method: "GET",
      path: `/_wsvpn_diag/${mode}`, agent: false, headers: { [ID_HEADER]: id }, ...extra }, res => {
      result.status = res.statusCode; result.id = res.headers[ID_HEADER.toLowerCase()];
      result.headers = res.headers;
      res.on("data", data => {
        result.first_ms ??= performance.now() - start;
        assert.ok(data.every(byte => byte === 65)); result.bytes += data.length;
      });
      res.once("end", () => { result.complete = true; finish(); });
      res.once("error", finish);
    });
    req.once("error", finish);
    req.setTimeout(12500, () => { req.destroy(); reject(new Error("Local origin test deadline")); });
    req.end();
  });
}

test("seven real HTTPS controls through Vercel rewrite retain IDs, bytes and 10-second stalls", { timeout: 30000 }, async t => {
  assert.equal(rewrite("/_wsvpn_diag/ok"), "/_wsvpn_diag/ok?mode=ok");
  const { port, events, ca } = await fixture(t, {}, true, true);
  const modes = ["ok", "ok", "ok", "stall-response", "stall-body", "ok", "ok"];
  const results = [];
  for (let i = 0; i < 5; i++) results.push(await request(port, ids[i], modes[i], { ca }));
  results.push(...await Promise.all([request(port, ids[5], "ok", { ca }), request(port, ids[6], "ok", { ca })]));
  for (const i of [0, 1, 2, 5, 6]) {
    assert.equal(results[i].status, 200); assert.equal(results[i].id, ids[i]);
    assert.equal(results[i].bytes, BODY_BYTES); assert.equal(results[i].complete, true);
    assert.equal(results[i].headers["cache-control"], "no-store, no-transform, max-age=0");
    assert.equal(results[i].headers[SOURCE_HEADER.toLowerCase()], SOURCE_MARKER);
    assert.equal(events.filter(e => e.id === ids[i] && e.event === "origin.response.write_complete")
      .reduce((sum, e) => sum + e.bytes, 0), BODY_BYTES);
  }
  assert.equal(results[3].status, null); assert.equal(results[3].bytes, 0);
  assert.equal(results[4].status, 200); assert.equal(results[4].bytes, 1024);
  assert.equal(results[4].complete, false); assert.ok(results[4].first_ms < results[4].elapsed_ms - 5000);
  for (const i of [3, 4]) assert.ok(results[i].elapsed_ms >= 9800 && results[i].elapsed_ms < 12000);
  await new Promise(resolve => setImmediate(resolve));
  for (const id of ids) {
    const rows = events.filter(e => e.id === id);
    assert.equal(rows.filter(e => e.event === "origin.request.received").length, 1);
    assert.ok(rows.some(e => e.event.startsWith("origin.close.")));
    assert.deepEqual(rows.map(e => e.seq), rows.map((_, i) => i + 1));
    for (const row of rows) assert.deepEqual(Object.keys(row).sort(),
      ["schema", "side", "id", "seq", "elapsed_ms", "event", "bytes", "mode", "response_bytes"].sort());
  }
});

test("origin rejects malformed, expired, unlisted and duplicate sessions without raw logging", async t => {
  const { port, events } = await fixture(t);
  assert.equal((await request(port, ids[0], "ok")).status, 200);
  assert.equal((await request(port, ids[0], "ok")).status, 409);
  assert.equal((await request(port, "f".repeat(32), "ok")).status, 403);
  assert.equal((await request(port, "bad-id", "ok")).status, 400);
  assert.equal((await request(port, ids[1], "unknown")).status, 400);
  assert.equal((await request(port, ids[1], "ok", { method: "POST" })).status, 400);
  assert.equal((await request(port, ids[1], "ok", { path: "/api/origin?mode=ok&extra=private" })).status, 400);
  assert.ok(!JSON.stringify(events).includes("private"));
  const expired = await fixture(t, { now: () => Date.now() + 300000 });
  assert.equal((await request(expired.port, ids[0], "ok")).status, 403);
  assert.deepEqual(expired.events, [{ schema: "wsvpn-origin-rejection/1", reasons: ["inactive"], id: null }]);
});

test("rewritten function path and already-consumed Node request are supported", async t => {
  const { port } = await fixture(t);
  assert.equal((await request(port, ids[0], "ok", { path: "/api/origin?mode=ok" })).bytes, BODY_BYTES);
  const handler = createOrigin(config(), { emit() {} });
  // No network listener: validate this Vercel-specific lifecycle state explicitly.
  const req = Object.assign(new EventEmitter(), { readableEnded: true, method: "GET",
    url: "/_wsvpn_diag/ok", headers: { [ID_HEADER.toLowerCase()]: ids[1] } });
  const res = Object.assign(new EventEmitter(), { setHeader() {}, writeHead() {},
    end(body, callback) { assert.equal(body.length, BODY_BYTES); callback(); this.emit("finish"); }, destroy() {} });
  await handler(req, res);
});

test("hybrid rewrite accepts only a single matching mode query and retains bodyless GET admission", async t => {
  const { port, events } = await fixture(t);
  for (const path of ["/_wsvpn_diag/ok?mode=stall-body", "/_wsvpn_diag/ok?mode=unknown",
    "/_wsvpn_diag/ok?mode=ok&mode=ok", "/_wsvpn_diag/ok?mode=ok&extra=private",
    "/_wsvpn_diag/ok?extra=private", "/elsewhere?mode=ok", "/api/origin?mode=ok&mode=ok"]) {
    const result = await request(port, ids[0], "ok", { path });
    assert.equal(result.status, 400);
    assert.equal(result.headers[REJECTION_HEADER.toLowerCase()], "mode_url");
    assert.equal(result.headers[SOURCE_HEADER.toLowerCase()], SOURCE_MARKER);
  }
  assert.equal((await request(port, ids[0], "ok", { path: rewrite("/_wsvpn_diag/ok"),
    headers: { [ID_HEADER]: ids[0], "Content-Length": "0" } })).bytes, BODY_BYTES);
  assert.equal(events.filter(e => e.event === "origin.request.received").length, 1);
  assert.ok(!JSON.stringify(events).includes("private"));
});

test("each rejection predicate is isolated, allowlisted, capped and does not consume an ID", async () => {
  const rows = [], handler = createOrigin(config(), { emit: row => rows.push(row) });
  const invoke = async changes => {
    const req = Object.assign(new EventEmitter(), { method: "GET", url: "/_wsvpn_diag/ok",
      headers: { [ID_HEADER.toLowerCase()]: ids[0] } }, changes);
    const headers = {};
    const res = { setHeader(k, v) { headers[k] = v; }, writeHead(status) { this.status = status; }, end() {} };
    await handler(req, res);
    return { status: res.status, headers };
  };
  const bad = "PRIVATE-never-log";
  const cases = [
    [{ method: bad }, "method"],
    [{ headers: { [ID_HEADER.toLowerCase()]: bad } }, "diagnostic_id"],
    [{ url: `/private?token=${bad}` }, "mode_url"],
    [{ headers: { [ID_HEADER.toLowerCase()]: ids[0], "transfer-encoding": bad } }, "transfer_encoding"],
    [{ headers: { [ID_HEADER.toLowerCase()]: ids[0], "content-length": "1" } }, "content_length"],
  ];
  for (const [change, code] of cases) {
    const result = await invoke(change);
    assert.equal(result.status, 400); assert.equal(result.headers[REJECTION_HEADER], code);
    assert.deepEqual(rows.at(-1).reasons, [code]);
  }
  await invoke({ method: bad, url: bad, headers: { [ID_HEADER.toLowerCase()]: [bad],
    "transfer-encoding": bad, "content-length": bad } });
  assert.deepEqual(rows.at(-1).reasons, cases.map(c => c[1]));
  for (let i = 0; i < 30; i++) assert.equal((await invoke({ url: bad })).status, 400);
  assert.equal(rows.length, REJECTION_LOG_LIMIT);
  assert.ok(!JSON.stringify(rows).includes(bad));
  for (const row of rows) assert.deepEqual(Object.keys(row).sort(), ["schema", "reasons", "id"].sort());
  assert.equal(rows[1].id, null);
  assert.equal(rows[0].id, ids[0]);
  // Rejected attempts must not consume the accepted-session ID.
  const req = Object.assign(new EventEmitter(), { method: "GET", url: rewrite("/_wsvpn_diag/ok"),
    readableEnded: true, headers: { [ID_HEADER.toLowerCase()]: ids[0] } });
  const res = Object.assign(new EventEmitter(), { setHeader() {}, writeHead(s) { assert.equal(s, 200); },
    end(body, cb) { assert.equal(body.length, BODY_BYTES); cb(); this.emit("finish"); }, destroy() {} });
  await handler(req, res);
});

test("framing rejections are observable over real HTTP sockets", async t => {
  const { port } = await fixture(t);
  for (const [name, value, code] of [["Content-Length", "1", "content_length"],
    ["Transfer-Encoding", "chunked", "transfer_encoding"]]) {
    const result = await request(port, ids[0], "ok", { headers: { [ID_HEADER]: ids[0], [name]: value } });
    assert.equal(result.status, 400);
    assert.equal(result.headers[REJECTION_HEADER.toLowerCase()], code);
  }
});

test("staging allowlist excludes Worker, repository, credentials and refuses nonempty targets", async t => {
  const target = await mkdtemp(join(tmpdir(), "wsvpn-vercel-stage-"));
  t.after(() => rm(target, { recursive: true, force: true }));
  const manifest = await stageOrigin(target);
  assert.deepEqual((await readdir(target)).sort(), ["api", "experiment.json", "package.json", "vercel.json"]);
  assert.deepEqual(await readdir(join(target, "api")), ["origin.mjs"]);
  const experiment = JSON.parse(await readFile(join(target, "experiment.json")));
  assert.equal(validateExperiment(experiment).ids.size, 7);
  assert.equal(Object.keys(manifest.files).length, 4);
  assert.deepEqual(JSON.parse(await readFile(join(target, "package.json"))).dependencies, undefined);
  await assert.rejects(stageOrigin(target), /empty/);
  await writeFile(join(target, "experiment.json"), "{}");
  assert.throws(() => validateExperiment({ ...experiment, ids: ["not-an-id"] }));
  assert.throws(() => validateExperiment({ ...experiment, expires_ms: experiment.not_before_ms + 1200001 }));
  const canary = join(target, "local-canary");
  const single = await stageOrigin(canary, { requests: 1 });
  assert.equal(single.requests, 1);
  assert.equal(validateExperiment(JSON.parse(await readFile(join(canary, "experiment.json")))).ids.size, 1);
  await assert.rejects(stageOrigin(join(target, "invalid-count"), { requests: 2 }), /one canary/);
});
