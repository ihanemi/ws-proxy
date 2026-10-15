import https from "node:https";
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ID_HEADER, VALID_ID } from "./runtime.js";

export const BODY_BYTES = 180000;
export async function startOrigin({ key, cert, emit, host = "127.0.0.1", port = 0,
  allowPublic = false, stallMs = 10000, durationMs = 180000 }) {
  if (!["127.0.0.1", "::1"].includes(host) && !allowPublic) throw new Error("Public binding requires explicit authorization/--allow-public-bind");
  if (!(stallMs > 0 && stallMs <= 10000 && durationMs > 0 && durationMs <= 300000)) throw new Error("Invalid bounded origin lifetime");
  const sockets = new Set(), timers = new Set();
  let accepted = 0;
  const body = Buffer.alloc(BODY_BYTES, 65);
  const server = https.createServer({ key, cert, handshakeTimeout: 5000 }, (req, res) => {
    const id = req.headers[ID_HEADER.toLowerCase()];
    const mode = { "/_wsvpn_diag/ok": "ok", "/_wsvpn_diag/stall-response": "stall-response",
      "/_wsvpn_diag/stall-body": "stall-body" }[req.url];
    if (req.method !== "GET" || !VALID_ID.test(id || "") || !mode || req.headers["transfer-encoding"] ||
        (req.headers["content-length"] && req.headers["content-length"] !== "0")) {
      res.writeHead(400, { Connection: "close" }); res.end(); return;
    }
    if (accepted++ >= 24) { res.writeHead(429, { Connection: "close" }); res.end(); return; }
    let seq = 0, responseBytes = 0, completed = false, intentional = false;
    const start = Date.now();
    function event(kind, bytes = 0) {
      try { emit({ schema: "wsvpn-diag/1", side: "origin", id, seq: ++seq,
        elapsed_ms: Date.now() - start, event: kind, bytes, mode, response_bytes: responseBytes }); } catch {}
    }
    event("origin.request.received");
    res.on("error", () => event("origin.response.error"));
    req.once("aborted", () => event("origin.request.cancelled"));
    const timer = setTimeout(() => { intentional = true; event("origin.deadline"); req.socket.destroy(); }, stallMs);
    timers.add(timer);
    req.socket.once("close", () => {
      clearTimeout(timer); timers.delete(timer);
      event(intentional ? "origin.close.deadline" : completed ? "origin.close.complete" : "origin.close.peer");
    });
    req.once("end", () => {
      event("origin.request.complete");
      if (mode === "stall-response") return;
      res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": BODY_BYTES,
        "Cache-Control": "no-store", Connection: "close", [ID_HEADER]: id });
      if (mode === "stall-body") {
        res.write(body.subarray(0, 1024), error => { if (error) { event("origin.response.error"); return; } responseBytes += 1024; event("origin.response.write", 1024); });
      } else {
        res.end(body, error => {
          if (error) { event("origin.response.error"); return; }
          completed = true; responseBytes += BODY_BYTES;
          event("origin.response.complete", BODY_BYTES); clearTimeout(timer); timers.delete(timer);
        });
      }
    });
    req.resume(); // Only an explicitly bodyless synthetic request is accepted.
  });
  server.maxConnections = 4;
  server.headersTimeout = 5000; server.requestTimeout = 5000; server.keepAliveTimeout = 1000;
  server.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.on("clientError", (_error, socket) => socket.destroy()); // Never log raw HTTP parser errors.
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, resolve); });
  let stopping;
  const stop = () => stopping ||= (async () => {
    clearTimeout(lifetime);
    for (const timer of timers) clearTimeout(timer);
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  })();
  const lifetime = setTimeout(stop, durationMs);
  return { server, port: server.address().port, stop };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: {
    key: { type: "string" }, cert: { type: "string" }, host: { type: "string", default: "127.0.0.1" },
    port: { type: "string", default: "0" }, duration: { type: "string", default: "180" },
    "allow-public-bind": { type: "boolean", default: false },
  } });
  if (!values.key || !values.cert) throw new Error("Explicit TLS key/certificate file paths are required");
  const origin = await startOrigin({ key: await readFile(values.key), cert: await readFile(values.cert),
    host: values.host, port: Number(values.port), durationMs: Number(values.duration) * 1000,
    allowPublic: values["allow-public-bind"], emit: row => console.log(JSON.stringify(row)) });
  console.error("Diagnostic origin listening; bounded lifetime active; no application logging");
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, origin.stop);
}
