import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createOrigin, validateExperiment, ID_HEADER, BODY_BYTES } from "../diagnostic/vercel/api/origin.mjs";
import { stageOrigin } from "../diagnostic/stage-vercel.mjs";

const ids = Array.from({ length: 7 }, (_, i) => (i + 1).toString(16).padStart(32, "0"));
const config = () => ({ ids, not_before_ms: Date.now() - 100, expires_ms: Date.now() + 120000 });
async function fixture(t, options = {}, secure = false) {
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
  const server = tls ? https.createServer(tls, (req, res) => handler(req, res)) :
    http.createServer((req, res) => handler(req, res));
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

test("seven real HTTPS controls retain IDs, bytes and production 10-second stalls", { timeout: 30000 }, async t => {
  const { port, events, ca } = await fixture(t, {}, true);
  const modes = ["ok", "ok", "ok", "stall-response", "stall-body", "ok", "ok"];
  const results = [];
  for (let i = 0; i < 5; i++) results.push(await request(port, ids[i], modes[i], { ca }));
  results.push(...await Promise.all([request(port, ids[5], "ok", { ca }), request(port, ids[6], "ok", { ca })]));
  for (const i of [0, 1, 2, 5, 6]) {
    assert.equal(results[i].status, 200); assert.equal(results[i].id, ids[i]);
    assert.equal(results[i].bytes, BODY_BYTES); assert.equal(results[i].complete, true);
    assert.equal(results[i].headers["cache-control"], "no-store, no-transform, max-age=0");
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
  assert.equal(expired.events.length, 0);
});

test("rewritten function path and already-consumed Node request are supported", async t => {
  const { port } = await fixture(t);
  assert.equal((await request(port, ids[0], "ok", { path: "/api/origin?mode=ok" })).bytes, BODY_BYTES);
  const handler = createOrigin(config(), { emit() {} });
  // No network listener: validate this Vercel-specific lifecycle state explicitly.
  const { EventEmitter } = await import("node:events");
  const req = Object.assign(new EventEmitter(), { readableEnded: true, method: "GET",
    url: "/_wsvpn_diag/ok", headers: { [ID_HEADER.toLowerCase()]: ids[1] } });
  const res = Object.assign(new EventEmitter(), { setHeader() {}, writeHead() {},
    end(body, callback) { assert.equal(body.length, BODY_BYTES); callback(); this.emit("finish"); }, destroy() {} });
  await handler(req, res);
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
});
