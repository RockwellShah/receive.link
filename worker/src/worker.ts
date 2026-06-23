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
//   POST /fetch/challenge  download gate: seal a nonce to the receiver's key (passkey-proof)
//   POST /fetch/preview    verify the proof, serve the head+metadata bytes (free; filename + size)
//   POST /fetch/download   verify the proof, charge the per-file price, return a short-lived presigned GET
//   GET  /billing/packs    the prepaid credit tiers at the current price (for the top-up picker)
//   POST /billing/checkout passkey-proof -> a Stripe Checkout URL to add prepaid credit
//   POST /billing/webhook  Stripe -> us: verify the signature, credit the account on a paid session

import { billingCheckout, billingPacks, billingWebhook, confirm, fetchChallenge, fetchDownload, fetchPreview, register, revoke, uploadAbort, uploadComplete, uploadInit, uploadParts } from "./handlers";
import { corsOrigin, cors, isForbiddenCrossOrigin, json } from "./http";
import type { Env } from "./types";

// Durable Object classes must be exported from the entry module so the runtime can construct them.
export { CompletionGuard } from "./completion";
export { ReceiverAccount } from "./receiver";

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
      case "POST /fetch/challenge":
        return fetchChallenge(req, env);
      case "POST /fetch/preview":
        return fetchPreview(req, env);
      case "POST /fetch/download":
        return fetchDownload(req, env);
      case "GET /billing/packs":
        return billingPacks(req, env);
      case "POST /billing/checkout":
        return billingCheckout(req, env);
      case "POST /billing/webhook":
        return billingWebhook(req, env);
      default:
        return json({ error: "not found" }, 404, origin);
    }
  },
} satisfies ExportedHandler<Env>;
