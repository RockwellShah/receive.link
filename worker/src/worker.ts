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
//   POST /upload-init      verify + limit, presigned R2 PUT (browser uploads direct)
//   POST /upload-complete  verify the object is real FileKey ciphertext, email the receiver
//   GET  /fetch/:id        presigned R2 GET for the receiver's decrypt page

import { confirm, fetchObject, register, revoke, uploadComplete, uploadInit } from "./handlers";
import { cors, json } from "./http";
import type { Env } from "./types";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const origin = env.ALLOWED_ORIGIN || "*";

    if (req.method === "OPTIONS") return new Response(null, { headers: cors(origin) });

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
      case "POST /upload-complete":
        return uploadComplete(req, env);
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
