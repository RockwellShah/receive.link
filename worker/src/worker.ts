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
//   POST /discard          receiver removes a delivered object after saving it
//   POST /fetch/challenge  download gate: seal a nonce to the receiver's key (passkey-proof)
//   POST /fetch/preview    verify the proof, serve the head+metadata bytes (free; filename + size)
//   POST /fetch/download   verify the proof, charge the per-file price, return a short-lived presigned GET
//   GET  /billing/packs    the prepaid credit tiers at the current price (for the top-up picker)
//   POST /billing/checkout passkey-proof -> a Stripe Checkout URL to add prepaid credit
//   POST /billing/webhook  Stripe -> us: verify the signature, credit the account on a paid session
//   POST /account/login    email magic-link sign-in: sealed email -> emailed sign-in link, uniform 202
//   POST /account/session  redeem a magic token -> a 30-min Bearer session + opening balance
//   POST /account/summary  (Bearer) -> the account's tier + balance
//   POST /account/checkout (Bearer) -> a Stripe Checkout URL to add prepaid credit (no file needed)

import { accountCheckout, accountLogin, accountSession, accountSummary } from "./account";
import { billingCheckout, billingPacks, billingWebhook, confirm, discardObject, fetchChallenge, fetchDownload, fetchPreview, register, revoke, uploadAbort, uploadComplete, uploadInit, uploadParts } from "./handlers";
import { corsOrigin, cors, isForbiddenCrossOrigin, json, logEvent } from "./http";
import type { Env } from "./types";

// Durable Object classes must be exported from the entry module so the runtime can construct them.
export { CompletionGuard } from "./completion";
export { ReceiverAccount } from "./receiver";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    // www.receive.link exists only as a custom domain on the prod Worker (that's what
    // creates its DNS record) and always bounces to the apex. Handled before any
    // config checks so the redirect works even if the API is misconfigured. Link
    // payloads ride in URL fragments, which browsers re-attach after a redirect.
    if (url.hostname === "www.receive.link") {
      url.hostname = "receive.link";
      return Response.redirect(url.toString(), 301);
    }

    const origin = corsOrigin(env, req);

    if (req.method === "OPTIONS") return new Response(null, { headers: { ...cors(origin), "cache-control": "no-store" } });

    // Fail fast on a missing rate-limit hash key: nearly every endpoint HMACs abuse-limit keys with it
    // (hmacHex throws on an empty key), so an unset secret would otherwise surface as opaque 500s deep in
    // random handlers. One loud, obvious config error instead — same policy as RECEIVER_ID_SECRET.
    if (!env.HASH_SECRET) {
      logEvent("config_error", { what: "HASH_SECRET" });
      return json({ error: "service misconfigured" }, 503, origin);
    }

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
      case "POST /discard":
        return discardObject(req, env);
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
      case "POST /account/login":
        return accountLogin(req, env);
      case "POST /account/session":
        return accountSession(req, env);
      case "POST /account/summary":
        return accountSummary(req, env);
      case "POST /account/checkout":
        return accountCheckout(req, env);
      default:
        return json({ error: "not found" }, 404, origin);
    }
  },
} satisfies ExportedHandler<Env>;
