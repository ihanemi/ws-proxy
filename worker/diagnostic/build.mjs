import { build } from "esbuild";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

export const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export function scopeHandler(source) {
  const a = "export function createHandler(runtime) {";
  const b = "return async (request, env, ctx) => {";
  const c = "released = true; active--;";
  if (source.split(a).length !== 2 || source.split(b).length !== 2 || source.split(c).length !== 2) throw new Error("Handler scoping anchors changed; review required");
  return source.replace(a, "export function createHandler(baseRuntime) {")
    .replace(b, b + "\n    const runtime = baseRuntime.forRequest(request, env);")
    .replace(c, c + " runtime.diagnosticDone?.();");
}
export function scopePlugin() {
  return { name: "diagnostic-request-scope", setup(builder) {
    builder.onLoad({ filter: /[\\/]src[\\/]handler\.js$/ }, async args => ({
      contents: scopeHandler(await readFile(args.path, "utf8")), loader: "js",
    }));
  } };
}
export async function buildDiagnostic() {
  const result = await build({ absWorkingDir: root, entryPoints: ["diagnostic/index.js"],
    bundle: true, write: false, format: "esm", external: ["cloudflare:sockets"],
    define: { WSVPN_DIAGNOSTIC_BUILD: "true" }, plugins: [scopePlugin()], metafile: true,
  });
  return result.outputFiles[0].text;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const bundle = await buildDiagnostic();
  const sha256 = data => createHash("sha256").update(data).digest("hex");
  const files = ["src/index.js", "src/handler.js", "src/session.js", "src/security.js", "src/dns.js"];
  const hashes = Object.fromEntries(await Promise.all(files.map(async name => [name, sha256((await readFile(resolve(root, name), "utf8")).replace(/\r\n/g, "\n"))])));
  const manifest = { kind: "diagnostic-only-no-deployment", base: "458e877", schema: "wsvpn-diag/1",
    compatibility_date: "2026-09-09", production_source_hashes_lf: hashes, bundle_sha256: sha256(bundle),
    runtime_config_changes: [], credentials_in_bundle: false, log_event_limit_per_session: 130 };
  await mkdir(resolve(root, "diagnostic/build"), { recursive: true });
  await writeFile(resolve(root, "diagnostic/build/worker.js"), bundle);
  await writeFile(resolve(root, "diagnostic/build/manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  console.log(JSON.stringify(manifest));
}
