// Diagnostic-only wrappers. No extra pumps, reads, writes, ACKs, or retries.
export const ID_HEADER = "X-WSVPN-Diagnostic-ID";
export const VALID_ID = /^[0-9a-f]{32}$/;
const REASONS = new Set(["closed", "idle timeout", "websocket error", "invalid frame", "unexpected ACK",
  "queue limit", "session failed", "tcp read failed", "tcp socket failed", "upgrade failed", "path check timeout"]);
export const MAX_EVENTS = 128;

export function createTrace(id, emit, now = () => Date.now()) {
  const start = now();
  let sequence = 0, emitted = 0;
  const counters = { ws_rx_bytes: 0, ws_rx_frames: 0, tcp_write_bytes: 0, tcp_writes: 0,
    tcp_read_bytes: 0, tcp_reads: 0, ws_tx_bytes: 0, ws_tx_frames: 0, ack_rx: 0, ack_pending: 0, read_cancels: 0, write_cancels: 0, tcp_eof: 0,
    ws_eof_rx: 0, ws_eof_tx: 0, close_requests: 0, events_suppressed: 0 };
  function event(kind, bytes = 0, reason = undefined, final = false) {
    sequence++;
    if (emitted >= MAX_EVENTS && !final) { counters.events_suppressed++; return; }
    emitted++;
    // Only caller-controlled constants/numbers and validated random ID enter logs.
    const row = { schema: "wsvpn-diag/1", side: "worker", id, seq: sequence,
      elapsed_ms: Math.max(0, now() - start), event: kind, bytes, ...counters };
    if (reason !== undefined) row.reason = REASONS.has(reason) ? reason : "other";
    try { emit(row); } catch { /* Instrumentation must not interrupt forwarding. */ }
  }
  return { counters, event };
}

function frameBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return null;
}
function wrapReader(reader, trace) {
  return new Proxy(reader, { get(target, key) {
    if (key === "read") return (...args) => {
      trace.event("tcp.read.begin");
      return target.read(...args).then(result => {
        const n = result.value?.byteLength || 0;
        trace.counters.tcp_reads++; trace.counters.tcp_read_bytes += n;
        if (result.done) trace.counters.tcp_eof++;
        trace.event(result.done ? "tcp.eof" : "tcp.read.complete", n);
        return result;
      }, error => { trace.event("tcp.read.error"); throw error; });
    };
    if (key === "cancel") return (...args) => { trace.counters.read_cancels++; trace.event("tcp.read.cancel"); return target.cancel(...args); };
    const value = Reflect.get(target, key, target);
    return typeof value === "function" ? value.bind(target) : value;
  } });
}
function wrapWriter(writer, trace) {
  return new Proxy(writer, { get(target, key) {
    if (key === "write") return (...args) => {
      const n = args[0]?.byteLength || 0;
      trace.event("tcp.write.begin", n);
      return target.write(...args).then(result => {
        trace.counters.tcp_writes++; trace.counters.tcp_write_bytes += n;
        trace.event("tcp.write.complete", n); return result;
      }, error => { trace.event("tcp.write.error"); throw error; });
    };
    if (key === "close") return (...args) => {
      trace.event("tcp.write.eof.begin");
      return target.close(...args).then(value => { trace.event("tcp.write.eof.complete"); return value; });
    };
    if (key === "abort") return (...args) => { trace.counters.write_cancels++; trace.event("tcp.write.cancel"); return target.abort(...args); };
    const value = Reflect.get(target, key, target);
    return typeof value === "function" ? value.bind(target) : value;
  } });
}
function wrapSocket(socket, trace) {
  const opened = socket.opened.then(value => { trace.event("tcp.connect.complete"); return value; },
    error => { trace.event("tcp.connect.error"); throw error; });
  const closed = socket.closed.then(value => { trace.event("tcp.closed"); return value; },
    error => { trace.event("tcp.closed.error"); throw error; });
  // Both rejections are observed by the unchanged handler immediately after connect.
  return { opened, closed,
    readable: { getReader: (...args) => wrapReader(socket.readable.getReader(...args), trace) },
    writable: { getWriter: (...args) => wrapWriter(socket.writable.getWriter(...args), trace) },
    close: (...args) => { trace.event("tcp.close.request"); return socket.close(...args); },
  };
}
function wrapWebSocket(ws, trace, flowControl) {
  let final = false;
  return new Proxy(ws, { get(target, key) {
    if (key === "addEventListener") return (type, listener, ...rest) => target.addEventListener(type, event => {
      if (type === "message") {
        const frame = frameBytes(event.data);
        if (frame?.[0] === 1) {
          trace.counters.ws_rx_frames++; trace.counters.ws_rx_bytes += Math.max(0, frame.length - 1);
          trace.event("ws.data.received", frame.length - 1);
        } else if (frame?.length === 1 && frame[0] === 4) {
          trace.counters.ack_rx++; trace.counters.ack_pending = Math.max(0, trace.counters.ack_pending - 1);
          trace.event("ws.ack.received");
        } else if (frame?.length === 1 && frame[0] === 2) { trace.counters.ws_eof_rx++; trace.event("ws.eof.received"); }
        else if (frame?.[0] === 5) trace.event("ws.path_check.received");
        else trace.event("ws.control.received");
      } else if (type === "close") trace.event("ws.close.received");
      else if (type === "error") trace.event("ws.error");
      return listener.call(target, event);
    }, ...rest);
    if (key === "send") return (...args) => {
      const frame = frameBytes(args[0]);
      const result = target.send(...args); // Observe acceptance, never send twice.
      if (frame?.[0] === 1) {
        trace.counters.ws_tx_frames++; trace.counters.ws_tx_bytes += Math.max(0, frame.length - 1);
        if (flowControl) trace.counters.ack_pending++;
        trace.event("ws.data.sent", frame.length - 1);
        if (flowControl) trace.event("flow.ack.wait");
      } else if (frame?.length === 1 && frame[0] === 2) { trace.counters.ws_eof_tx++; trace.event("ws.eof.sent"); }
      else trace.event("ws.control.sent");
      return result;
    };
    if (key === "close") return (code, reason, ...rest) => {
      if (!final) { final = true; trace.counters.close_requests++; trace.event("ws.close.request", 0, reason, true); }
      return target.close(code, reason, ...rest);
    };
    const value = Reflect.get(target, key, target);
    return typeof value === "function" ? value.bind(target) : value;
  }, set(target, key, value) { return Reflect.set(target, key, value, target); } });
}

export function scopedRuntime(native, request, env, emit) {
  const id = request.headers.get(ID_HEADER);
  if (new URL(request.url).pathname !== "/tunnel" || !VALID_ID.test(id || "") ||
      !env.TUNNEL_TOKEN || request.headers.get("Authorization") !== `Bearer ${env.TUNNEL_TOKEN}`) return native;
  const trace = createTrace(id, emit);
  trace.event("request.accepted");
  const flow = request.headers.get("X-WSVPN-Flow-Control") === "ack-v1";
  return { ...native,
    diagnosticDone: () => trace.event("session.summary", 0, undefined, true),
    connect: (...args) => {
      trace.event("tcp.connect.begin");
      try { return wrapSocket(native.connect(...args), trace); }
      catch (error) { trace.event("tcp.connect.error"); throw error; }
    },
    pair: () => { const [client, server] = native.pair(); return [client, wrapWebSocket(server, trace, flow)]; },
    upgrade: (client, headers) => {
      const response = native.upgrade(client, { ...headers, [ID_HEADER]: id });
      trace.event("ws.upgrade"); return response;
    },
  };
}
