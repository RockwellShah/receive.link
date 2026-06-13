// FileKey Drop — Worker (Cloudflare). Stateless happy path: it verifies a signed
// Drop link, relays ciphertext through R2, and emails the receiver a link. It
// NEVER decrypts files and stores no email↔key mapping; the receiver's address
// lives sealed inside their own link and is unsealed only in memory at send time.
//
// Endpoints (always-relay design — every share goes through R2, email carries a link):
//   GET  /healthz          liveness
//   POST /register         { payloadB64 } -> unseal email, send confirm mail, 202
//   POST /confirm          { token }      -> verify one-time token, return server_sig
//   POST /upload-init      { payloadB64, size } -> verify+limit, presigned R2 PUT + object id
//   POST /upload-complete  { payloadB64, objectId } -> verify object, unseal email, send link
//   GET  /fetch/:id        presigned R2 GET (capability = unguessable id; payload is E2E)
//
// Status: routing + parse/verify are wired to the real codec + crypto. The four
// handlers are stubbed (501) pending Phase 1. See HANDOFF in the FileKey v1 repo.

import { decodeDropLink, splitSignature, base64urlDecode, type DropLink } from "./codec";
import { importSignPublicKey, verifyRegion } from "./crypto";
import type { Env } from "./types";

function cors(origin: string): Record<string, string> {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
  };
}

function json(data: unknown, status: number, origin: string): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors(origin), "content-type": "application/json" },
  });
}

/**
 * Decode a Drop link from its base64url payload and verify the server signature
 * against the signing PUBLIC key. Returns the parsed link, or throws. This is
 * the gate every upload endpoint runs before trusting a link.
 */
export async function parseAndVerify(payloadB64: string, env: Env): Promise<DropLink> {
  const bytes = base64urlDecode(payloadB64);
  const { signable, signature } = splitSignature(bytes);
  const pub = await importSignPublicKey(JSON.parse(env.SERVER_SIGN_PUBLIC_JWK) as JsonWebKey);
  if (!(await verifyRegion(pub, signable, signature))) {
    throw new Error("bad server signature");
  }
  return decodeDropLink(bytes);
}

const notImplemented = (origin: string) =>
  json({ error: "not implemented", phase: 1 }, 501, origin);

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const origin = env.ALLOWED_ORIGIN || "*";

    if (req.method === "OPTIONS") return new Response(null, { headers: cors(origin) });

    const route = `${req.method} ${url.pathname}`;
    switch (route) {
      case "GET /healthz":
        return json({ ok: true, service: "filekey-drop" }, 200, origin);

      // TODO Phase 1: rate-limit (IP + hash(email)); parseAndVerify; unseal email;
      // mint one-time confirm token (HMAC, single-use via DROP_KV, 1h TTL); EMAIL.send
      // a confirmation link; always return 202 (no email-existence oracle).
      case "POST /register":
        return notImplemented(origin);

      // TODO Phase 1: verify+consume the one-time token; sign the canonical link
      // region with SERVER_SIGN_PRIVATE_JWK; return the 64-byte server_sig.
      case "POST /confirm":
        return notImplemented(origin);

      // TODO Phase 1: parseAndVerify; check DROP_KV denylist(link_id); rate-limit
      // (per link_id + per IP); enforce max size; mint presigned R2 PUT (random
      // 128-bit object id, bucket lifecycle 7d); return { uploadUrl, objectId }.
      case "POST /upload-init":
        return notImplemented(origin);

      // TODO Phase 1: parseAndVerify; confirm the R2 object exists + size matches;
      // unseal the email in memory; EMAIL.send the /d/<id> link; store nothing.
      case "POST /upload-complete":
        return notImplemented(origin);

      default:
        // TODO Phase 1: GET /fetch/<id> -> presigned R2 GET (or proxy).
        if (req.method === "GET" && url.pathname.startsWith("/fetch/")) return notImplemented(origin);
        return json({ error: "not found" }, 404, origin);
    }
  },
} satisfies ExportedHandler<Env>;
