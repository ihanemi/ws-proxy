import { readFile } from "node:fs/promises";

// Intentionally self-contained: deploy only the staged origin, never the VPN repo.
export const ID_HEADER = "X-WSVPN-Diagnostic-ID";
export const BODY_BYTES = 180000;
const VALID_ID = /^[0-9a-f]{32}$/;
const MODES = new Set(["ok", "stall-response", "stall-body"]);
const BODY = Buffer.alloc(BODY_BYTES, 65);

export function validateExperiment(value) {
  if (!value || !Array.isArray(value.ids) || !value.ids.length || value.ids.length > 24 ||
      value.ids.some(id => typeof id !== "string" || !VALID_ID.test(id)) ||
      new Set(value.ids).size !== value.ids.length || !Number.isSafeInteger(value.not_before_ms) ||
      !Number.isSafeInteger(value.expires_ms) || value.expires_ms <= value.not_before_ms ||
      value.expires_ms - value.not_before_ms > 20 * 60 * 1000) throw new Error("Invalid experiment limits");
  return { ids: new Set(value.ids), notBefore: value.not_before_ms, expires: value.expires_ms };
}

function modeFor(url) {
  try {
    const parsed = new URL(url, "https://diagnostic.invalid");
    const direct = /^\/_wsvpn_diag\/(ok|stall-response|stall-body)$/.exec(parsed.pathname);
    if (direct && !parsed.search) return direct[1];
    // Vercel's static rewrite adds only this fixed mode parameter.
    const entries = [...parsed.searchParams];
    if (parsed.pathname === "/api/origin" && entries.length === 1 && entries[0][0] === "mode" &&
        MODES.has(entries[0][1])) return entries[0][1];
  } catch {}
  return null;
}

export function createOrigin(experiment, { emit = row => console.log(JSON.stringify(row)),
  now = Date.now, stallMs = 10000 } = {}) {
  const limits = validateExperiment(experiment);
  if (!(stallMs > 0 && stallMs <= 10000)) throw new Error("Invalid stall limit");
  // Not a global serverless quota: admission uses fixed IDs and an absolute expiry.
  const seen = new Set();
  return async function origin(req, res) {
    res.setHeader("Cache-Control", "no-store, no-transform, max-age=0");
    res.setHeader("CDN-Cache-Control", "no-store");
    res.setHeader("Vercel-CDN-Cache-Control", "no-store");
    const id = req.headers[ID_HEADER.toLowerCase()], mode = modeFor(req.url);
    const time = now();
    if (req.method !== "GET" || typeof id !== "string" || !VALID_ID.test(id) || !mode ||
        req.headers["transfer-encoding"] || (req.headers["content-length"] && req.headers["content-length"] !== "0")) {
      res.writeHead(400); res.end(); return;
    }
    if (time < limits.notBefore || time >= limits.expires || !limits.ids.has(id)) {
      res.writeHead(403); res.end(); return;
    }
    if (seen.has(id)) { res.writeHead(409); res.end(); return; }
    seen.add(id);
    let seq = 0, acceptedBytes = 0, finished = false, intentional = false;
    const started = now();
    const event = (kind, bytes = 0) => {
      try { emit({ schema: "wsvpn-diag/1", side: "origin", id, seq: ++seq,
        elapsed_ms: Math.max(0, now() - started), event: kind, bytes, mode,
        response_bytes: acceptedBytes }); } catch {}
    };
    event("origin.request.received");
    // Await the response lifecycle so Vercel does not freeze unfinished work.
    await new Promise(resolve => {
      const timer = setTimeout(() => {
        intentional = true;
        event("origin.deadline");
        res.destroy(); // Preserve the stall. A platform-generated response invalidates it.
      }, Math.min(stallMs, limits.expires - time));
      const done = () => { clearTimeout(timer); resolve(); };
      req.once("error", () => { event("origin.request.error"); res.destroy(); });
      req.once("aborted", () => { event("origin.request.cancelled"); res.destroy(); });
      res.once("error", () => { event("origin.response.error"); res.destroy(); done(); });
      res.once("finish", () => { finished = true; event("origin.response.finish"); done(); });
      res.once("close", () => {
        event(intentional ? "origin.close.deadline" : finished ? "origin.close.complete" : "origin.close.peer");
        done();
      });
      const respond = () => {
        if (res.destroyed) return;
        event("origin.request.complete");
        if (mode === "stall-response") return;
        res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": BODY_BYTES,
          "Content-Encoding": "identity", [ID_HEADER]: id });
        const bytes = mode === "ok" ? BODY_BYTES : 1024;
        event("origin.response.queued", bytes);
        const accepted = error => {
          if (error) { event("origin.response.error"); return; }
          acceptedBytes += bytes;
          // This callback is runtime acceptance, NOT proof of edge transmission.
          event("origin.response.write_complete", bytes);
        };
        if (mode === "ok") res.end(BODY, accepted);
        else { res.flushHeaders(); res.write(BODY.subarray(0, 1024), accepted); }
      };
      if (req.readableEnded) respond();
      else { req.once("end", respond); req.resume(); }
    });
  };
}

let handler;
export default async function origin(req, res) {
  let run;
  try {
    handler ||= readFile(new URL("../experiment.json", import.meta.url), "utf8")
      .then(text => createOrigin(JSON.parse(text)));
    run = await handler;
  } catch {
    res.setHeader("Cache-Control", "no-store"); res.writeHead(503); res.end(); return;
  }
  await run(req, res);
}
