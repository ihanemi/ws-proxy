import { readFile } from "node:fs/promises";

// Intentionally self-contained: deploy only the staged origin, never the VPN repo.
export const ID_HEADER = "X-WSVPN-Diagnostic-ID";
export const BODY_BYTES = 180000;
export const SOURCE_HEADER = "X-WSVPN-Origin-Source";
export const SOURCE_MARKER = "wsvpn-origin/2";
export const REJECTION_HEADER = "X-WSVPN-Origin-Rejection";
export const REJECTION_LOG_LIMIT = 24; // Per warm instance, not a global serverless quota.
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
    // Vercel CLI preserves the original pathname and adds the rewrite query.
    // Also retain the internal destination form used by other runtime bridges.
    const entries = [...parsed.searchParams];
    if (entries.length === 1 && entries[0][0] === "mode" && MODES.has(entries[0][1]) &&
        (parsed.pathname === "/api/origin" || direct?.[1] === entries[0][1])) return entries[0][1];
  } catch {}
  return null;
}

export function createOrigin(experiment, { emit = row => console.log(JSON.stringify(row)),
  now = Date.now, stallMs = 10000 } = {}) {
  const limits = validateExperiment(experiment);
  if (!(stallMs > 0 && stallMs <= 10000)) throw new Error("Invalid stall limit");
  // Not a global serverless quota: admission uses fixed IDs and an absolute expiry.
  const seen = new Set();
  let rejectionLogs = 0;
  return async function origin(req, res) {
    res.setHeader(SOURCE_HEADER, SOURCE_MARKER);
    res.setHeader("Cache-Control", "no-store, no-transform, max-age=0");
    res.setHeader("CDN-Cache-Control", "no-store");
    res.setHeader("Vercel-CDN-Cache-Control", "no-store");
    const id = req.headers[ID_HEADER.toLowerCase()], mode = modeFor(req.url);
    const time = now();
    const validId = typeof id === "string" && VALID_ID.test(id);
    const active = time >= limits.notBefore && time < limits.expires;
    const reject = (status, reasons) => {
      res.setHeader(REJECTION_HEADER, reasons[0]);
      if (rejectionLogs < REJECTION_LOG_LIMIT) {
        rejectionLogs++;
        try { emit({ schema: "wsvpn-origin-rejection/1", reasons,
          id: validId && active && limits.ids.has(id) ? id : null }); } catch {}
      }
      res.writeHead(status); res.end();
    };
    // Values are fixed reason codes only. Never include raw request fields.
    const reasons = [];
    if (req.method !== "GET") reasons.push("method");
    if (!validId) reasons.push("diagnostic_id");
    if (!mode) reasons.push("mode_url");
    if (req.headers["transfer-encoding"]) reasons.push("transfer_encoding");
    if (req.headers["content-length"] && req.headers["content-length"] !== "0") reasons.push("content_length");
    if (reasons.length) { reject(400, reasons); return; }
    if (time < limits.notBefore || time >= limits.expires || !limits.ids.has(id)) {
      reject(403, [!active ? "inactive" : "unlisted_id"]); return;
    }
    if (seen.has(id)) { reject(409, ["duplicate_id"]); return; }
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
    res.setHeader(SOURCE_HEADER, SOURCE_MARKER);
    res.setHeader(REJECTION_HEADER, "configuration");
    res.setHeader("Cache-Control", "no-store"); res.writeHead(503); res.end(); return;
  }
  await run(req, res);
}
