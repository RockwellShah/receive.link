// Build the Drop web client. Run from the repo root: bun run web/build.ts
// One flat bundle in web/dist/app.js. All crypto streams on the main thread
// (crypto.subtle runs AES off-thread internally), so there is no separate worker bundle.
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

rmSync("web/dist", { recursive: true, force: true });

// Stamp the menu footer with the package version at build time (define replaces __APP_VERSION__).
const { version } = (await Bun.file("package.json").json()) as { version: string };

const result = await Bun.build({
  entrypoints: ["web/src/app.ts", "web/src/home-create.ts", "web/src/home-result.ts", "web/src/home-send.ts", "web/src/home-receive.ts", "web/src/home-account.ts"],
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

// Cache-bust: Cloudflare Pages FORCES a 4h cache on /dist/* bundles and ignores a _headers Cache-Control
// override (see web/_headers), so stamp a content-hash ?v= onto each page's bundle reference (the <script
// src> and the homepage's dynamic import). The hash changes only when the bundle content changes, so a
// deploy busts the cache exactly when needed and there's no spurious HTML churn otherwise.
const PAGE_BUNDLES: { html: string; bundle: string }[] = [
  { html: "web/app.html", bundle: "app.js" },
  { html: "web/home/index.html", bundle: "home-create.js" },
  { html: "web/send/index.html", bundle: "home-send.js" },
  { html: "web/result/index.html", bundle: "home-result.js" },
  { html: "web/receive/index.html", bundle: "home-receive.js" },
  { html: "web/credit/index.html", bundle: "home-account.js" },
];
for (const { html, bundle } of PAGE_BUNDLES) {
  const hash = createHash("sha256").update(readFileSync(`web/dist/${bundle}`)).digest("hex").slice(0, 10);
  const before = readFileSync(html, "utf8");
  // Match /dist/<bundle> with an optional existing ?v=, not part of a longer name (so app.js != app.json).
  const re = new RegExp(`/dist/${bundle.replace(/\./g, "\\.")}(\\?v=[0-9a-f]+)?(?![\\w.])`, "g");
  const after = before.replace(re, `/dist/${bundle}?v=${hash}`);
  if (after !== before) { writeFileSync(html, after); console.log(`stamped ${html} -> ?v=${hash}`); }
}
