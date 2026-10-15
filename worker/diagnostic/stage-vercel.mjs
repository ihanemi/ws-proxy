import { mkdir, readFile, writeFile, copyFile, readdir } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export async function stageOrigin(destination, { now = Date.now() } = {}) {
  const source = fileURLToPath(new URL("./vercel/", import.meta.url));
  const target = resolve(destination);
  if (target === resolve(source)) throw new Error("Use a separate empty staging directory");
  await mkdir(target, { recursive: true });
  if ((await readdir(target)).length) throw new Error("Staging directory must be empty");
  const files = ["api/origin.mjs", "package.json", "vercel.json"];
  await mkdir(join(target, "api"));
  for (const name of files) await copyFile(join(source, name), join(target, name));
  const config = { not_before_ms: now, expires_ms: now + 20 * 60 * 1000,
    ids: Array.from({ length: 7 }, () => randomBytes(16).toString("hex")) };
  await writeFile(join(target, "experiment.json"), JSON.stringify(config, null, 2) + "\n", { flag: "wx" });
  const hashes = {};
  for (const name of [...files, "experiment.json"]) hashes[name] = createHash("sha256")
    .update(await readFile(join(target, name))).digest("hex");
  return { kind: "origin-only-no-worker", destination: target, files: hashes,
    requests: 7, expires_ms: config.expires_ms };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error("Usage: node stage-vercel.mjs <empty-private-directory>");
  const manifest = await stageOrigin(process.argv[2]);
  // Manifest stays OUTSIDE the deployment upload root.
  const path = join(dirname(manifest.destination), `${manifest.destination.split(/[\\/]/).pop()}.manifest.json`);
  await writeFile(path, JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
  console.log(JSON.stringify(manifest));
}
