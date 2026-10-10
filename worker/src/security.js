import ipaddr from "ipaddr.js";

export function publicIP(host) {
  // Reject legacy octal/hex/short IPv4 spellings, scoped and transition IPv6.
  if (typeof host !== "string" || host.includes("%")) throw new Error("Invalid address");
  if (!host.includes(":") && !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(host)) {
    throw new Error("Invalid IPv4");
  }
  const ip = ipaddr.parse(host);
  if (ip.range() !== "unicast") throw new Error("Blocked address");
  if (ip.kind() === "ipv6") {
    // Conservative global-unicast subset; reject documentation/transition ranges.
    if (!ip.match(ipaddr.parse("2000::"), 3) ||
        ip.match(ipaddr.parse("2001::"), 23) ||
        ip.match(ipaddr.parse("2001:db8::"), 32) ||
        ip.match(ipaddr.parse("2002::"), 16) ||
        ip.match(ipaddr.parse("3fff::"), 20)) throw new Error("Blocked IPv6");
  }
  return ip.toString();
}

export function validHost(host) {
  if (typeof host !== "string" || !host || host.length > 253 || /[^\x21-\x7e]/.test(host) || host.includes("%")) {
    throw new Error("Invalid host");
  }
  if (host.includes(":") || /^[0-9.]+$/.test(host) || /^(0x|0[0-9])/i.test(host)) return publicIP(host);
  const name = host.toLowerCase().replace(/\.$/, "");
  if (!name.includes(".") || name === "localhost" || name.endsWith(".localhost") ||
      name.endsWith(".local") || name.split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error("Invalid DNS host");
  }
  return name;
}

export function validPort(value) {
  if (!/^[0-9]{1,5}$/.test(value || "")) throw new Error("Invalid port");
  const port = Number(value);
  if (!port || port > 65535 || port === 25 || port === 53) throw new Error("Blocked port");
  return port;
}

export async function boundedBody(response, limit) {
  if (!response.body) throw new Error("Empty response");
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new Error("Response limit");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
  return result;
}

export const DOH_URL = "https://cloudflare-dns.com/dns-query";

export async function resolvePublic(host, fetcher, signal) {
  host = validHost(host);
  if (ipaddr.isValid(host)) return host;
  const addresses = [];
  for (const type of ["A", "AAAA"]) {
    const url = new URL(DOH_URL);
    url.searchParams.set("name", host);
    url.searchParams.set("type", type);
    const response = await fetcher(url.toString(), {
      headers: { Accept: "application/dns-json" }, redirect: "manual", signal,
    });
    if (!response.ok) { await response.body?.cancel(); throw new Error("Resolution failed"); }
    const data = JSON.parse(new TextDecoder().decode(await boundedBody(response, 16384)));
    if (data.Status !== 0 || data.TC || !Array.isArray(data.Question) ||
        data.Question.length !== 1 || data.Question[0].name.toLowerCase().replace(/\.$/, "") !== host ||
        data.Question[0].type !== (type === "A" ? 1 : 28)) throw new Error("Resolution failed");
    for (const answer of data.Answer || []) {
      if (answer.type === 1 || answer.type === 28) addresses.push(publicIP(answer.data));
    }
  }
  if (!addresses.length) throw new Error("No public addresses");
  // Check every A/AAAA answer above, then pin the numeric address in connect().
  return addresses[0];
}
