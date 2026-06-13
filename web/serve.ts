// Dev server for the Drop web client. Run (after a build): bun run web/serve.ts
// Serves web/ statically with an SPA fallback so /, /#<link>, /confirm, and /d/<id>
// all load the app. It does NOT proxy /api yet — the live server round-trip needs a
// running Worker (wrangler dev or staging); this is for building + visual checks.
import { file } from "bun";

const ROOT = `${import.meta.dir}/`; // .../web/ (decoded; handles spaces in the path)
const port = 8080;

Bun.serve({
  port,
  async fetch(req) {
    const path = decodeURIComponent(new URL(req.url).pathname);
    if (path !== "/" && !path.endsWith("/")) {
      const f = file(ROOT + path.replace(/^\//, ""));
      if (await f.exists()) return new Response(f);
    }
    return new Response(file(ROOT + "index.html"), { headers: { "content-type": "text/html; charset=utf-8" } });
  },
});

console.log(`Drop dev server: http://localhost:${port}`);
