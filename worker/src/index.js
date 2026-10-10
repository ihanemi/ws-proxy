import { connect } from "cloudflare:sockets";
import { createHandler } from "./handler.js";

export default {
  fetch: createHandler({
    connect,
    fetcher: (...args) => fetch(...args),
    pair: () => Object.values(new WebSocketPair()),
    upgrade: (client, headers) => new Response(null, { status: 101, webSocket: client, headers }),
  }),
};
