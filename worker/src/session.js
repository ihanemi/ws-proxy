// Application flow control bounds TCP -> WS buffering; standard WSVPN/1 clients
// remain compatible, but are capped at 8 MiB/flow without the negotiated ACK.
export const MAX_FRAME = 262145;
const MAX_QUEUED_BYTES = 1024 * 1024;
const MAX_QUEUED_FRAMES = 16;
const LEGACY_OUTPUT_LIMIT = 8 * 1024 * 1024;

export function startSession(ws, tcp, mode, runtime, release, flowControl = false) {
  const { fetcher } = runtime;
  const writer = tcp?.writable.getWriter();
  const reader = tcp?.readable.getReader();
  const abort = new AbortController();
  let closed = false, inputEOF = false, outputEOF = false;
  let frames = 0, bytes = 0, sent = 0, ack = null;
  let chain = Promise.resolve();
  let idle;
  const pending = new Set();

  function touch() {
    clearTimeout(idle);
    idle = setTimeout(() => close(1008, "idle timeout"), mode === "tcp" ? 300000 : 120000);
  }
  function close(code = 1000, reason = "closed") {
    if (closed) return;
    closed = true;
    clearTimeout(idle);
    abort.abort();
    ack?.reject(new Error("closed")); ack = null;
    try { ws.close(code, reason); } catch {}
    // Close forcibly unblocks pending reads/writes. Release locks only after
    // tasks settle; never use writer.close() during error cleanup (half-close).
    const cleanup = Promise.allSettled([
      tcp?.close(), reader?.cancel(), writer?.abort(), ...pending,
    ]).finally(() => {
      try { reader?.releaseLock(); } catch {}
      try { writer?.releaseLock(); } catch {}
      release();
    });
    runtime.waitUntil(cleanup);
  }
  function track(task) {
    pending.add(task);
    task.then(() => pending.delete(task), () => pending.delete(task));
    runtime.waitUntil(task);
  }
  async function send(chunk) {
    if (closed) throw new Error("closed");
    sent += chunk.length;
    if (!flowControl && mode === "tcp" && sent > LEGACY_OUTPUT_LIMIT) throw new Error("legacy output limit");
    if (!flowControl) { ws.send(chunk); return; }
    let timer;
    try {
      await new Promise((resolve, reject) => {
        timer = setTimeout(() => { ack = null; reject(new Error("ACK timeout")); }, 30000);
        ack = { resolve, reject };
        ws.send(chunk);
      });
    } finally { clearTimeout(timer); ack = null; }
  }
  function finished() {
    if (inputEOF && outputEOF) close();
  }

  ws.binaryType = "arraybuffer";
  ws.accept({ allowHalfOpen: true });
  ws.addEventListener("close", () => close());
  ws.addEventListener("error", () => close(1011, "websocket error"));
  ws.addEventListener("message", event => {
    if (closed) return;
    const message = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : null;
    if (!message || !message.length || message.length > MAX_FRAME) { close(1002, "invalid frame"); return; }
    touch();
    if (mode === "tcp" && flowControl && message.length === 1 && message[0] === 4) {
      if (!ack) { close(1002, "unexpected ACK"); return; }
      const current = ack; ack = null; current.resolve(); return;
    }
    if (++frames > MAX_QUEUED_FRAMES || (bytes += message.length) > MAX_QUEUED_BYTES) {
      close(1008, "queue limit"); return;
    }
    chain = chain.then(async () => {
      if (closed) return;
      if (mode === "probe") {
        if (message.length !== 33 || message[0] !== 1) throw new Error("invalid probe");
        ws.send(message); close(); return;
      }
      if (mode === "dns") {
        // Serial bounded DoH, no arbitrary UDP socket or user-selected URL.
        const controller = new AbortController();
        const cancel = () => controller.abort();
        abort.signal.addEventListener("abort", cancel, { once: true });
        const timer = setTimeout(cancel, 10000);
        try {
          const response = await runtime.dnsResponse(message, fetcher, controller.signal);
          sent += response.length;
          if (sent > LEGACY_OUTPUT_LIMIT) throw new Error("DNS output limit");
          if (!closed) ws.send(response);
        } finally { clearTimeout(timer); abort.signal.removeEventListener("abort", cancel); }
        return;
      }
      if (inputEOF) throw new Error("data after EOF");
      if (message.length === 1 && message[0] === 2) {
        inputEOF = true;
        await writer.close();
        finished();
      } else if (message[0] === 1) {
        await writer.write(message.subarray(1));
      } else throw new Error("invalid TCP frame");
    }).catch(() => close(1002, "session failed"))
      .finally(() => { frames--; bytes -= message.length; });
    track(chain);
  });
  ws.send(new Uint8Array([3]));
  touch();
  if (tcp) {
    track((async () => {
      try {
        while (!closed) {
          const { value, done } = await reader.read();
          if (closed) return;
          if (done) {
            outputEOF = true;
            ws.send(new Uint8Array([2]));
            finished(); return;
          }
          touch();
          for (let offset = 0; offset < value.length; offset += 65536) {
            const payload = value.subarray(offset, offset + 65536);
            const frame = new Uint8Array(1 + payload.length);
            frame[0] = 1; frame.set(payload, 1);
            await send(frame);
          }
        }
      } catch { close(1011, "tcp read failed"); }
    })());
    tcp.closed.catch(() => close(1011, "tcp socket failed"));
  }
  return { close };
}
