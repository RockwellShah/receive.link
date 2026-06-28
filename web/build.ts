// Build the Drop web client. Run from the repo root: bun run web/build.ts
// One flat bundle in web/dist/app.js. All crypto streams on the main thread
// (crypto.subtle runs AES off-thread internally), so there is no separate worker bundle.
import { rmSync } from "node:fs";

rmSync("web/dist", { recursive: true, force: true });

// Stamp the menu footer with the package version at build time (define replaces __APP_VERSION__).
const { version } = (await Bun.file("package.json").json()) as { version: string };

const result = await Bun.build({
  entrypoints: ["web/src/app.ts", "web/src/home-create.ts", "web/src/home-result.ts", "web/src/home-send.ts", "web/src/home-receive.ts"],
  outdir: "web/dist",
  target: "browser",
  minify: true,
  define: { __APP_VERSION__: JSON.stringify(version) },
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  throw new Error("web build failed: web/src/app.ts");
}
console.log(`built ${result.outputs.map((o) => o.path).join(", ")}`);
