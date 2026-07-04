// HTTP helpers: CORS + JSON responses + safe body parsing.
import type { Env } from "./types";

/**
 * ALLOWED_ORIGIN is a comma-separated allowlist of cross-origin callers. The FIRST
 * entry is canonical: the Worker builds confirm/drop/download links + emails from it,
 * so links always point at one host (e.g. the iOS Universal Links on receive.link).
 * Any other entries are additional origins accepted for CORS (e.g. a staging subdomain
 * served by the same Worker).
 */
function originAllowList(env: Env): string[] {
  return (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
}

/** Canonical origin used to build links + emails: the first allow-listed origin. */
export function linkOrigin(env: Env): string {
  return originAllowList(env)[0] || "";
}

/**
 * The CORS origin to echo back: the request's Origin iff it is allow-listed, else ""
 * (an origin no browser matches). FAIL-CLOSED: never "*", so a disallowed or
 * misconfigured origin is denied rather than opening the API to any site.
 */
export function corsOrigin(env: Env, req: Request): string {
  const o = req.headers.get("origin") || "";
  return originAllowList(env).includes(o) ? o : "";
}

/**
 * True when a mutating (POST) request carries a present-but-disallowed Origin, so it must be
 * rejected before any handler runs. CORS only hides the response; a cross-site page can still
 * fire a no-preflight POST and trigger blind side effects (e.g. a /register email). No-Origin
 * callers (native apps, server-to-server) and allow-listed browser origins are NOT blocked.
 */
export function isForbiddenCrossOrigin(env: Env, req: Request): boolean {
  return req.method === "POST" && !!req.headers.get("origin") && corsOrigin(env, req) === "";
}

export function cors(origin: string): Record<string, string> {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    // `authorization` carries the account-page session token (Bearer) on /account/summary + /account/checkout.
    "access-control-allow-headers": "content-type, authorization",
    // Custom response headers the browser may read cross-origin: the /fetch/preview credit headers
    // (X-RL-Credit, X-RL-Tier) for the balance chip, and X-RL-Expires (when the file self-deletes) for
    // the saved screen's auto-delete note. (R2's own ETag is exposed by the bucket CORS config in
    // deploy/r2-cors.*.json, not here, since those PUT/GETs go direct to R2.)
    "access-control-expose-headers": "X-RL-Credit, X-RL-Tier, X-RL-Expires",
    "access-control-max-age": "86400",
    vary: "origin",
  };
}

/**
 * Structured log line for Cloudflare Workers logs (`wrangler tail` / Logpush). PRIVACY: object ids,
 * link-id hashes, sizes, and error tags only — NEVER emails, plaintext, ciphertext, or tokens.
 */
export function logEvent(event: string, fields: Record<string, unknown> = {}): void {
  try {
    console.log(JSON.stringify({ event, ...fields }));
  } catch {
    /* logging must never throw into a handler */
  }
}

export function json(data: unknown, status: number, origin: string): Response {
  return new Response(JSON.stringify(data), {
    status,
    // no-store: these bodies carry presigned R2 URLs, one-time nonces, and revoke
    // tokens — never let a cache (browser, CDN, proxy) keep them.
    headers: { ...cors(origin), "content-type": "application/json", "cache-control": "no-store" },
  });
}

// Most Drop JSON bodies are tiny (a link payload + a couple of base64 fields); the
// file bytes go direct to R2, never through these endpoints. Cap the body so an
// attacker can't force a huge allocation before the codec's length checks run.
// EXCEPTION: /upload-complete's `parts` array scales with the part count (up to
// ~10k parts x ~60 B each, ~600 KB for a multi-TB multipart), so that one route
// passes a larger explicit cap — the 5.5 GB live experiment caught a 1,050-part
// completion bouncing off this 64 KB default as a bogus "missing fields" 400.
const MAX_JSON_BYTES = 64 * 1024;

export async function readJson<T = Record<string, unknown>>(req: Request, maxBytes: number = MAX_JSON_BYTES): Promise<T | null> {
  // Reject before buffering when the client declares an oversized body. The
  // post-read check is a backstop for chunked / Content-Length-absent requests
  // (those are additionally bounded by Cloudflare's platform body limit).
  const declared = parseInt(req.headers.get("content-length") || "0", 10);
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  try {
    const text = await req.text();
    if (text.length > maxBytes) return null;
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

/** Best-effort client IP for rate-limiting (Cloudflare sets cf-connecting-ip). */
export function clientIp(req: Request): string {
  return req.headers.get("cf-connecting-ip") || "0.0.0.0";
}
