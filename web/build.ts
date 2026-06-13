// Build the Drop web client. Run from the repo root: bun run web/build.ts
// Bundles web/src/app.ts (which pulls in the vendored core + shared/) to web/dist/app.js.
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
  throw new Error("web build failed");
}
console.log(`built ${result.outputs.map((o) => o.path).join(", ")}`);
