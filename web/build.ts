// Build the Drop web client. Run from the repo root: bun run web/build.ts
// Two flat bundles in web/dist/: app.js (main thread) and worker.js (off-thread
// streaming crypto for files >= 64 MB). Built separately so each lands at its
// basename (dist/app.js, dist/worker.js) — the worker is loaded at runtime via
// `new URL("./worker.js", import.meta.url)` relative to app.js.
import { rmSync } from "node:fs";

rmSync("web/dist", { recursive: true, force: true });

for (const entry of ["web/src/app.ts", "web/fk/worker.ts"]) {
  const result = await Bun.build({
    entrypoints: [entry],
    outdir: "web/dist",
    target: "browser",
    minify: true,
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    throw new Error(`web build failed: ${entry}`);
  }
  console.log(`built ${result.outputs.map((o) => o.path).join(", ")}`);
}
