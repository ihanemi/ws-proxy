import { boundedBody, DOH_URL, publicIP } from "./security.js";

export const MAX_DNS = 4096;

function validateRecords(packet, q) {
  const count = q.view.getUint16(6) + q.view.getUint16(8) + q.view.getUint16(10);
  if (count > 128) throw new Error("DNS record limit");
  let offset = q.end;
  for (let record = 0; record < count; record++) {
    let nameBytes = 0;
    while (true) {
      if (offset >= packet.length || ++nameBytes > 255) throw new Error("Truncated DNS name");
      const size = packet[offset++];
      if (!size) break;
      if ((size & 0xc0) === 0xc0) {
        if (offset >= packet.length || (((size & 63) << 8) | packet[offset]) >= offset - 1) {
          throw new Error("Invalid DNS pointer");
        }
        offset++; break;
      }
      if (size > 63 || offset + size >= packet.length) throw new Error("Invalid DNS label");
      nameBytes += size; offset += size;
    }
    if (offset + 10 > packet.length) throw new Error("Truncated DNS record");
    const length = q.view.getUint16(offset + 8);
    offset += 10 + length;
    if (offset > packet.length) throw new Error("Truncated DNS data");
  }
  if (offset !== packet.length) throw new Error("Trailing DNS data");
}

function question(packet) {
  if (packet.length < 17 || packet.length > MAX_DNS) throw new Error("Invalid DNS size");
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  if (view.getUint16(4) !== 1) throw new Error("Expected one DNS question");
  let offset = 12;
  const labels = [];
  // Queries must contain an uncompressed, valid ASCII/IDNA question.
  while (true) {
    const size = packet[offset++];
    if (size === 0) break;
    if (!size || size > 63 || offset + size >= packet.length) throw new Error("Invalid DNS name");
    const label = new TextDecoder("ascii", { fatal: true }).decode(packet.subarray(offset, offset + size));
    if (!/^[a-z0-9_-]+$/i.test(label)) throw new Error("Invalid DNS label");
    labels.push(label.toLowerCase());
    offset += size;
    if (offset > 267) throw new Error("DNS name too long");
  }
  if (offset + 4 > packet.length || view.getUint16(offset + 2) !== 1) throw new Error("Invalid DNS class");
  return { name: labels.join("."), type: view.getUint16(offset), end: offset + 4, view };
}

export function validateQuery(packet) {
  const q = question(packet);
  const flags = q.view.getUint16(2);
  if (flags & 0xf800 || q.view.getUint16(6) || q.view.getUint16(8)) throw new Error("Invalid DNS query");
  validateRecords(packet, q);
  return q;
}

export function decodeDNSDatagram(frame) {
  if (frame[0] !== 1) throw new Error("Invalid datagram version");
  let end, host;
  if (frame[1] === 1 && frame.length >= 8) {
    host = [...frame.subarray(2, 6)].join("."); end = 6;
  } else if (frame[1] === 4 && frame.length >= 20) {
    const words = [];
    for (let i = 2; i < 18; i += 2) words.push(((frame[i] << 8) | frame[i + 1]).toString(16));
    host = words.join(":"); end = 18;
  } else throw new Error("DNS requires an IP marker");
  publicIP(host);
  if (frame[end] !== 0 || frame[end + 1] !== 53) throw new Error("Generic UDP unsupported");
  const payload = frame.subarray(end + 2);
  validateQuery(payload);
  return { prefix: frame.slice(0, end + 2), payload };
}

export async function dnsResponse(frame, fetcher, signal) {
  const { prefix, payload } = decodeDNSDatagram(frame);
  const q = validateQuery(payload);
  const response = await fetcher(DOH_URL, {
    method: "POST", headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
    body: payload, signal, redirect: "manual",
  });
  if (!response.ok || response.headers.get("Content-Type")?.split(";")[0] !== "application/dns-message") {
    await response.body?.cancel(); throw new Error("DoH failed");
  }
  const packet = await boundedBody(response, MAX_DNS);
  const answer = question(packet);
  validateRecords(packet, answer);
  if (!(answer.view.getUint16(2) & 0x8000) || (answer.view.getUint16(2) & 0x7800) ||
      packet[0] !== payload[0] || packet[1] !== payload[1] || answer.name !== q.name || answer.type !== q.type) {
    throw new Error("Mismatched DNS response");
  }
  const result = new Uint8Array(prefix.length + packet.length);
  result.set(prefix); result.set(packet, prefix.length);
  return result;
}
