import { connect } from "cloudflare:sockets";
import { createDiagnosticHandler } from "./factory.js";

// This entry MUST use build.mjs, which applies the three-line request-scoping
// adapter to a copy of handler.js. Production source stays byte-for-byte intact.
if (typeof WSVPN_DIAGNOSTIC_BUILD === "undefined") throw new Error("Use diagnostic/build.mjs");
const native = {
  connect, fetcher: (...args) => fetch(...args),
  pair: () => Object.values(new WebSocketPair()),
  upgrade: (webSocket, headers) => new Response(null, { status: 101, webSocket, headers }),
};
export default { fetch: createDiagnosticHandler(native, row => console.log(JSON.stringify(row))) };
