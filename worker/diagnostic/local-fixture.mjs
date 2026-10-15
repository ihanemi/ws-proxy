// Local-only test harness. The statistics endpoint and loopback dial mapping
// are NOT part of diagnostic/index.js or its deployable bundle.
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { startOrigin } from "./origin.mjs";
import { root, scopePlugin } from "./build.mjs";

const dir = await mkdtemp(join(tmpdir(), "wsvpn-diagnostic-"));
let origin, mf;
try {
  const keyPath = join(dir, "key.pem"), certPath = join(dir, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
    "-out", certPath, "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:8.8.8.8"], { stdio: "ignore" });
  const key = await readFile(keyPath), cert = await readFile(certPath);
  const originEvents = [];
  origin = await startOrigin({ key, cert, emit: row => originEvents.push(row) });
  const entry = `import {connect} from 'cloudflare:sockets';
    import {createDiagnosticHandler} from './diagnostic/factory.js';
    const events=[];
    const handler=createDiagnosticHandler({
      connect:(address,options)=>connect({hostname:'127.0.0.1',port:${origin.port}},options),
      fetcher:()=>{throw new Error('Unexpected DNS')},
      pair:()=>Object.values(new WebSocketPair()),
      upgrade:(webSocket,headers)=>new Response(null,{status:101,webSocket,headers})
    },row=>{if(events.length<2048)events.push(row)});
    export default {fetch:(request,env,ctx)=>new URL(request.url).pathname==='/__local_stats'
      ?Response.json(events):handler(request,env,ctx)};`;
  const bundle = await build({ stdin: { contents: entry, resolveDir: root }, bundle: true,
    write: false, format: "esm", external: ["cloudflare:sockets"], plugins: [scopePlugin()] });
  mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text,
    compatibilityDate: "2026-09-09", https: true, httpsKey: key.toString(), httpsCert: cert.toString(),
    bindings: { TUNNEL_TOKEN: "test-only-token" } }));
  console.log(JSON.stringify({ relay: String(await mf.ready).replace("https://127.0.0.1:", "wss://localhost:") + "tunnel",
    ca_file: certPath, origin: "https://8.8.8.8" }));
  process.stdin.setEncoding("utf8");
  let pending = "", chain = Promise.resolve();
  process.stdin.on("data", chunk => {
    pending += chunk;
    while (pending.includes("\n")) {
      const i = pending.indexOf("\n"), command = pending.slice(0, i); pending = pending.slice(i + 1);
      chain = chain.then(async () => {
        if (command === "stats") {
          const response = await mf.dispatchFetch("https://worker.test/__local_stats");
          console.log(JSON.stringify({ worker: await response.json(), origin: originEvents }));
        }
        if (command === "stop") process.stdin.destroy();
      });
    }
  });
  await new Promise(resolve => process.stdin.once("close", resolve));
  await chain;
} finally {
  await mf?.dispose(); await origin?.stop(); await rm(dir, { recursive: true, force: true });
}
