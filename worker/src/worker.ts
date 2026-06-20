// FileKey Drop — Worker (Cloudflare). Stateless happy path: it verifies a signed
// Drop link, relays ciphertext through R2, and emails the receiver a link. It
// NEVER decrypts files and stores no email↔key mapping; the receiver's address
// lives sealed inside their own link and is unsealed only in memory at send time.
//
// Endpoints (always-relay: every share goes through R2, the email carries a link):
//   GET  /healthz          liveness
//   POST /register         unseal email, send confirm mail, 202
//   POST /confirm          consume one-time nonce, return the signed link + revoke token
//   POST /revoke           turn a link off using the receiver's revoke token
//   POST /upload-init      verify + limit; presigned single PUT (small) or multipart (large)
//   POST /upload-parts     re-presign a batch of multipart UploadPart URLs (browser uploads direct)
//   POST /upload-complete  assemble (multipart), verify it's real FileKey ciphertext, email the receiver
//   POST /upload-abort     cancel an in-progress multipart upload
//   GET  /fetch/:id        presigned R2 GET for the receiver's decrypt page

import { confirm, fetchObject, register, revoke, uploadAbort, uploadComplete, uploadInit, uploadParts } from "./handlers";
import { corsOrigin, cors, isForbiddenCrossOrigin, json } from "./http";
import type { Env } from "./types";

// The Durable Object class must be exported from the entry module so the runtime can construct it.
export { CompletionGuard } from "./completion";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const origin = corsOrigin(env, req);

    if (req.method === "OPTIONS") return new Response(null, { headers: { ...cors(origin), "cache-control": "no-store" } });

    // CORS only hides the response, so reject a cross-site POST (present-but-disallowed Origin)
    // before any handler side effect runs. No-Origin callers and allow-listed origins pass.
    if (isForbiddenCrossOrigin(env, req)) return json({ error: "forbidden origin" }, 403, "");

    const route = `${req.method} ${url.pathname}`;
    switch (route) {
      case "GET /healthz":
        return json({ ok: true, service: "filekey-drop" }, 200, origin);
      case "POST /register":
        return register(req, env);
      case "POST /confirm":
        return confirm(req, env);
      case "POST /revoke":
        return revoke(req, env);
      case "POST /upload-init":
        return uploadInit(req, env);
      case "POST /upload-parts":
        return uploadParts(req, env);
      case "POST /upload-complete":
        return uploadComplete(req, env);
      case "POST /upload-abort":
        return uploadAbort(req, env);
      default: {
        const fetchId = req.method === "GET" && url.pathname.startsWith("/fetch/")
          ? url.pathname.slice("/fetch/".length)
          : null;
        if (fetchId !== null) return fetchObject(req, env, fetchId);
        return json({ error: "not found" }, 404, origin);
      }
    }
  },
} satisfies ExportedHandler<Env>;
