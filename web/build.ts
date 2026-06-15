// Build the Drop web client. Run from the repo root: bun run web/build.ts
// One flat bundle in web/dist/app.js. All crypto streams on the main thread
// (crypto.subtle runs AES off-thread internally), so there is no separate worker bundle.
import { rmSync } from "node:fs";

rmSync("web/dist", { recursive: true, force: true });

const result = await Bun.build({
  entrypoints: ["web/src/app.ts"],
  outdir: "web/dist",
  target: "browser",
  minify: true,
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  throw new Error("web build failed: web/src/app.ts");
}
console.log(`built ${result.outputs.map((o) => o.path).join(", ")}`);
