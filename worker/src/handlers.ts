// FileKey Drop — request handlers. The Worker is a thin, mostly-stateless relay:
// it verifies signed Drop links, dampens abuse, moves ciphertext through R2, and
// emails the receiver a link. It never decrypts and keeps no email↔key store.
//
// Flow:
//   register  -> unseal email, stash the unsigned link in KV (1h), email a confirm link
//   confirm   -> consume the nonce, sign the link region, return the finished link
//   upload-init     -> verify the link, presign an R2 PUT (browser uploads direct)
//   upload-complete -> verify the object is real FileKey ciphertext, email the receiver
//   fetch     -> presign an R2 GET for the receiver's decrypt page

import {
  DROP_PAYLOAD_VERSION,
  KEY_ID_LEN,
  LINK_ID_LEN,
  base64urlDecode,
  base64urlEncode,
  decodeDropLink,
  signableBytes,
  splitSignature,
  type DropLink,
} from "../../shared/codec";
import { FETCH_CHALLENGE_INFO, fetchProofHex, hpkeSealTo, importKemPrivateKey, importKemPublicKey, importSignPrivateKey, importSignPublicKey, signRegion, unsealEmail, verifyRegion } from "../../shared/crypto";
import { recipientPkFromShareKeyBytes } from "../../shared/sharekey";
import { sendConfirmEmail, sendDownloadEmail, sendDropLinkEmail } from "./email";
import { cors, clientIp, corsOrigin, json, linkOrigin, logEvent, readJson } from "./http";
import { DAY, HOUR, MINUTE, rateLimit, rateLimitBytes } from "./kv";
import { abortMultipart, completeMultipart, copyObject, createMultipart, deleteObject, fileKeyMetadataPrefixLen, objectInfo, presignGet, presignPut, presignUploadPart, validateFileKeyHeader } from "./r2";
import { createCheckoutSession, isPackId, parseCreditFromEvent, stripeConfigured, verifyStripeSignature } from "./stripe";
import type { Env } from "./types";
import { hex, hmacSha256hex, isEmail, isHex, randomBytes, sha256hex } from "../../shared/util";

// Abuse limits (soft, KV fixed-window). Tune from real traffic. Exported so tests
// assert against the source of truth.
export const REG_IP_PER_DAY = 20; // confirmation emails one IP can trigger
export const REG_EMAIL_PER_DAY = 5; // confirmation emails one address can receive (anti-bombing)
export const UPLOAD_LINK_PER_DAY = 25; // files one Drop link accepts (anti-flood of the inbox)
export const UPLOAD_IP_PER_DAY = 100; // files one IP can push across all links
export const FETCH_IP_PER_DAY = 1000; // download-gate challenge + prove calls one IP can make per day
export const REVOKE_IP_PER_DAY = 60; // revoke calls one IP can make (tokens are unguessable; this just caps probing)
const UPLOAD_BYTES_LINK_FACTOR = 5; // per-link daily byte budget defaults to 5x the per-file cap
const UPLOAD_BYTES_IP_FACTOR = 10; // per-IP daily byte budget defaults to 10x the per-file cap
const DEFAULT_SIGN_KEY_ID = 1; // key id stamped into links when SERVER_SIGN_KEY_ID is unset
const CONFIRM_TTL_SEC = HOUR; // pending registration lifetime
const PRESIGN_TTL_SEC = HOUR; // presigned upload PUT lifetime
// Download gate (passkey-proof at /fetch). The download URL is short-lived + distinct from the 1h upload
// presign; the binding outlives the 7-day R2 object lifecycle; the challenge is single-use within its window.
const FETCH_URL_TTL_SEC = 5 * MINUTE; // post-proof presigned GET
const FETCHBIND_TTL_SEC = 8 * DAY; // finalId -> { receiver pubkey, size, rid }
const CHALLENGE_TTL_SEC = 5 * MINUTE; // sealed-nonce challenge
const FETCH_NONCE_BYTES = 32;
const CHALLENGE_ID_BYTES = 16;
const FETCH_PREVIEW_BYTES = 1_200_000; // bytes the FREE preview serves: head + metadata (cap ~1 MiB); never the payload
const DEFAULT_MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
const OBJECT_ID_BYTES = 16;
const REVOKE_TOKEN_BYTES = 16; // receiver-only secret that maps to a link_id for revocation

// ---- Multipart sizing (large uploads). The cap is policy (MAX_UPLOAD_BYTES, up to
// R2's ~5 TiB object ceiling); these shape how a big ciphertext splits into <=10k
// parts and keep client RAM bounded (part size grows with file size). ----
const MULTIPART_THRESHOLD = 100 * 1024 * 1024; // ciphertext above this uses multipart; below, single PUT
const MIN_PART_SIZE = 16 * 1024 * 1024; // R2 needs >=5 MiB for non-last parts; 16 MiB is a comfortable floor
const MAX_PART_SIZE = 1024 * 1024 * 1024; // 1 GiB ceiling per part (keeps one in-flight part's RAM sane)
const TARGET_PARTS = 9000; // aim under R2's 10k-part hard limit, with headroom
const MAX_PARTS = 10000; // R2 hard limit
const PART_PRESIGN_BATCH = 100; // presign part URLs in batches, on demand (not all 10k up front)
const MULTIPART_TTL_SEC = DAY; // the upload binding must outlive a multi-hour upload

// Both knobs are env-overridable (tunable without a code edit; tests set them low
// so multipart exercises with tiny payloads).
function multipartThreshold(env: Env): number {
  const n = env.MULTIPART_THRESHOLD ? parseInt(env.MULTIPART_THRESHOLD, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : MULTIPART_THRESHOLD;
}
function minPartSize(env: Env): number {
  const n = env.MULTIPART_MIN_PART ? parseInt(env.MULTIPART_MIN_PART, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : MIN_PART_SIZE;
}

/** part_size = clamp(ceil(size / TARGET_PARTS), MIN, MAX) — keeps partCount <= ~TARGET_PARTS. */
function computePartSize(size: number, env: Env): number {
  return Math.min(MAX_PART_SIZE, Math.max(minPartSize(env), Math.ceil(size / TARGET_PARTS)));
}

/** Presign UploadPart URLs for part numbers [from, from+count), clamped to 1..partCount. */
async function presignParts(env: Env, objectId: string, uploadId: string, from: number, count: number, partCount: number): Promise<{ partNumber: number; url: string }[]> {
  const out: { partNumber: number; url: string }[] = [];
  const end = Math.min(from + count, partCount + 1); // part numbers are 1-based, 1..partCount
  for (let n = Math.max(1, from); n < end; n++) {
    out.push({ partNumber: n, url: await presignUploadPart(env, objectId, uploadId, n, PRESIGN_TTL_SEC) });
  }
  return out;
}

/** Strict Complete validation: exactly partCount parts, each numbered 1..partCount once, non-empty etag. */
function validateParts(parts: unknown, partCount: number): { partNumber: number; etag: string }[] | null {
  if (!Array.isArray(parts) || parts.length !== partCount) return null;
  const seen = new Set<number>();
  const out: { partNumber: number; etag: string }[] = [];
  for (const p of parts) {
    const n = (p as { partNumber?: unknown }).partNumber;
    const etag = (p as { etag?: unknown }).etag;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > partCount || seen.has(n)) return null;
    if (typeof etag !== "string" || !etag) return null;
    seen.add(n);
    out.push({ partNumber: n, etag });
  }
  return out;
}

// The KV upload-binding: which link minted this object, and (for multipart) the
// in-progress upload's id + sizing. JSON so single + multipart share one key.
type UploadBinding = { link: string; mp?: { uploadId: string; size: number; partSize: number; partCount: number } };

function maxUploadBytes(env: Env): number {
  const n = env.MAX_UPLOAD_BYTES ? parseInt(env.MAX_UPLOAD_BYTES, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_UPLOAD_BYTES;
}

// Per-day abuse caps are overridable per environment: staging runs them high so
// testing isn't throttled; prod omits the vars and gets the strict defaults above.
function envInt(v: string | undefined, dflt: number): number {
  const n = v ? parseInt(v, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : dflt;
}

// Daily BYTE budgets (alongside the file-count caps): default to a multiple of the per-file cap so a
// single max-size upload always fits, but a link/IP can't move unbounded bytes per day.
function bytesPerLinkDay(env: Env): number {
  return envInt(env.UPLOAD_BYTES_PER_LINK_DAY, maxUploadBytes(env) * UPLOAD_BYTES_LINK_FACTOR);
}
function bytesPerIpDay(env: Env): number {
  return envInt(env.UPLOAD_BYTES_PER_IP_DAY, maxUploadBytes(env) * UPLOAD_BYTES_IP_FACTOR);
}

/** Stable per-recipient account id, derived from the receiver's CONFIRMED email via a keyed digest.
 *  The email is the one identity a sender can't forge — you can only confirm an address you control —
 *  whereas the share key inside a link is public, so keying on it would let anyone who sees a victim's
 *  link mint their own link for the victim's account and burn its capacity. HMAC (not a bare hash)
 *  keeps the id from being reversed back to the address. */
export function receiverId(env: Env, email: string): Promise<string> {
  return hmacSha256hex(env.RECEIVER_ID_SECRET, canonEmail(email));
}

/** Per-recipient cumulative inbound ceiling in bytes (the free-tier cap). Unset/<=0 => uncapped, so
 *  the Worker meters every recipient but rejects nothing until the cap is dialed in (see uploadComplete). */
function receiverInboundCap(env: Env): number {
  return envInt(env.RECEIVER_INBOUND_CAP_BYTES, 0);
}

// ---- Phase 2 billing config (download charge). Ships INERT: billingEnabled() is false unless the env
// var is set, so /fetch/download issues a free URL exactly like Phase 1 until Stripe (2b) is live. ----
const DEFAULT_FREE_GRANT_BYTES = 1024 * 1024 * 1024; // 1 GiB of free download credit per new account

/** Paid-tier at-rest (un-downloaded) ceiling in bytes (the 100 GB safety cap). Unset/<=0 => uncapped. */
function paidAtRestCap(env: Env): number {
  return envInt(env.PAID_ATREST_CAP_BYTES, 0);
}
/** Free credit seeded into a new account when billing is on (default 1 GiB). Unlike envInt, an explicit
 *  "0" is honored (a deliberate no-free-grant config), not coerced to the default. */
function freeGrantBytes(env: Env): number {
  if (env.FREE_GRANT_BYTES === undefined) return DEFAULT_FREE_GRANT_BYTES;
  const n = parseInt(env.FREE_GRANT_BYTES, 10);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_FREE_GRANT_BYTES;
}
/** Whether the per-file download charge is live. Off (default) = downloads are free (Phase 1 behavior). */
function billingEnabled(env: Env): boolean {
  const v = env.BILLING_ENABLED?.toLowerCase();
  return v === "1" || v === "true";
}

/** The signing key id stamped into newly minted links, so the verifier can pick the right key later. */
function currentSignKeyId(env: Env): number {
  return envInt(env.SERVER_SIGN_KEY_ID, DEFAULT_SIGN_KEY_ID);
}

/** Public keys a link signature may verify against, by key id: the current key + an optional previous
 *  key kept across a rotation so already-minted (permanent) links keep verifying. */
function signingKeys(env: Env): Map<number, JsonWebKey> {
  const keys = new Map<number, JsonWebKey>();
  keys.set(currentSignKeyId(env), JSON.parse(env.SERVER_SIGN_PUBLIC_JWK) as JsonWebKey);
  if (env.SERVER_SIGN_PUBLIC_JWK_PREV && env.SERVER_SIGN_KEY_ID_PREV) {
    keys.set(envInt(env.SERVER_SIGN_KEY_ID_PREV, 0), JSON.parse(env.SERVER_SIGN_PUBLIC_JWK_PREV) as JsonWebKey);
  }
  return keys;
}

// Strip CR/LF + C0/DEL controls so a sender-chosen label can't inject email
// headers or smuggle control bytes. Applied before signing, so the signed label
// is already clean everywhere it's later shown.
const stripControl = (s: string) => s.replace(/[\x00-\x1f\x7f]/g, "");

// Canonicalize for abuse-limit keys only (we still deliver to the exact unsealed
// address): trim + lowercase so "User@x.com " and "user@x.com" share a quota.
const canonEmail = (s: string) => s.trim().toLowerCase();

/**
 * Decode a Drop link and verify the server signature against the signing PUBLIC
 * key. Verifies over the raw signed region (not a re-encode), then parses. The
 * gate every upload endpoint runs before trusting a link. Throws on any failure.
 */
export async function parseAndVerify(payloadB64: string, env: Env): Promise<DropLink> {
  const bytes = base64urlDecode(payloadB64);
  const { signable, signature } = splitSignature(bytes);
  // key_id sits right after the version byte, inside the signed region — read it BEFORE verifying so
  // we pick the public key that signed this (permanent) link, which lets the signing key rotate.
  if (signable.length < 1 + KEY_ID_LEN) throw new Error("malformed link");
  const jwk = signingKeys(env).get(signable[1]!);
  if (!jwk) throw new Error("unknown signing key id");
  const pub = await importSignPublicKey(jwk);
  if (!(await verifyRegion(pub, signable, signature))) throw new Error("bad server signature");
  return decodeDropLink(bytes);
}

// POST /register { sealedEmail, shareKey, label } (all base64url except label)
export async function register(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ sealedEmail: string; shareKey: string; label: string }>(req);
  if (!body || typeof body.sealedEmail !== "string" || typeof body.shareKey !== "string" || typeof body.label !== "string") {
    return json({ error: "missing fields" }, 400, origin);
  }

  // Hash the IP so KV only ever holds a digest, never a raw address (it's only a rate-limit key).
  const ipHash = await sha256hex(clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `reg:ip:${ipHash}`, envInt(env.REG_IP_PER_DAY, REG_IP_PER_DAY), DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }

  // Build the unsigned signable region (validates field lengths) and unseal the
  // email it commits to. A server-chosen random link_id guarantees uniqueness.
  // Sanitize the label BEFORE signing so the signed bytes are clean everywhere.
  const label = stripControl(body.label);
  let region: Uint8Array;
  let sealedEmailBytes: Uint8Array;
  try {
    sealedEmailBytes = base64urlDecode(body.sealedEmail);
    region = signableBytes({
      version: DROP_PAYLOAD_VERSION,
      keyId: currentSignKeyId(env),
      linkId: randomBytes(LINK_ID_LEN),
      shareKey: base64urlDecode(body.shareKey),
      label,
      sealedEmail: sealedEmailBytes,
    });
  } catch {
    return json({ error: "invalid payload" }, 400, origin);
  }

  let email: string;
  try {
    const kemPriv = await importKemPrivateKey(JSON.parse(env.SERVER_KEM_PRIVATE_JWK) as JsonWebKey);
    email = await unsealEmail(kemPriv, sealedEmailBytes);
  } catch {
    return json({ error: "invalid sealed email" }, 400, origin);
  }
  if (!isEmail(email)) return json({ error: "invalid email" }, 400, origin);

  // Anti-bombing: silently succeed once an address is over its daily quota, so
  // register can't be used to probe or flood a victim. No existence oracle.
  const emailHash = await sha256hex(canonEmail(email));
  if (!(await rateLimit(env.DROP_KV, `reg:em:${emailHash}`, envInt(env.REG_EMAIL_PER_DAY, REG_EMAIL_PER_DAY), DAY))) {
    return json({ ok: true }, 202, origin);
  }

  const nonce = base64urlEncode(randomBytes(16));
  await env.DROP_KV.put(`pending:${nonce}`, base64urlEncode(region), { expirationTtl: CONFIRM_TTL_SEC });
  await sendConfirmEmail(env, email, `${linkOrigin(env)}/confirm#${nonce}`, label);
  return json({ ok: true }, 202, origin);
}

// POST /confirm { nonce } -> { link }
export async function confirm(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ nonce: string }>(req);
  if (!body || typeof body.nonce !== "string") return json({ error: "missing nonce" }, 400, origin);

  const stored = await env.DROP_KV.get(`pending:${body.nonce}`);
  if (!stored) return json({ error: "invalid or expired" }, 404, origin);
  await env.DROP_KV.delete(`pending:${body.nonce}`); // single use

  const region = base64urlDecode(stored);
  const signPriv = await importSignPrivateKey(JSON.parse(env.SERVER_SIGN_PRIVATE_JWK) as JsonWebKey);
  const sig = await signRegion(signPriv, region);
  const full = new Uint8Array(region.length + sig.length);
  full.set(region, 0);
  full.set(sig, region.length);
  const linkB64 = base64urlEncode(full);

  // Mint a receiver-only revoke token so they can turn this link off later. It maps
  // to the link_id both ways: revtok->id powers POST /revoke; id->revtok lets each
  // delivery email carry the manage link. Neither entry ever touches the email address.
  const linkIdHex = hex(region.slice(1 + KEY_ID_LEN, 1 + KEY_ID_LEN + LINK_ID_LEN)); // skip version(1) + key_id(1)
  const revokeToken = hex(randomBytes(REVOKE_TOKEN_BYTES));
  await env.DROP_KV.put(`revtok:${revokeToken}`, linkIdHex);
  await env.DROP_KV.put(`linkrev:${linkIdHex}`, revokeToken);

  // Best-effort: email the receiver a durable copy of their Drop link + manage link.
  // The page reveals both immediately; this just survives a closed tab. A failure
  // here must not fail the confirm (the nonce is already spent and the page has them).
  try {
    const decoded = decodeDropLink(full);
    const kemPriv = await importKemPrivateKey(JSON.parse(env.SERVER_KEM_PRIVATE_JWK) as JsonWebKey);
    const email = await unsealEmail(kemPriv, decoded.sealedEmail);
    await sendDropLinkEmail(env, email, `${linkOrigin(env)}/#${linkB64}`, `${linkOrigin(env)}/revoke#${revokeToken}`, decoded.label);
  } catch {
    /* page already showed both links */
  }

  return json({ link: linkB64, revokeToken }, 200, origin);
}

// POST /revoke { token } -> { ok } — the receiver turns their own Drop link off.
// The token is the secret minted at confirm; it resolves to the link_id we flag.
export async function revoke(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ token: string }>(req);
  if (!body || typeof body.token !== "string") return json({ error: "missing token" }, 400, origin);
  if (!isHex(body.token, REVOKE_TOKEN_BYTES)) return json({ error: "bad token" }, 400, origin);

  const ipHash = await sha256hex(clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `rev:ip:${ipHash}`, REVOKE_IP_PER_DAY, DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }

  const linkIdHex = await env.DROP_KV.get(`revtok:${body.token}`);
  if (!linkIdHex) return json({ error: "invalid token" }, 404, origin);
  // Permanent flag (links are permanent); enforced at upload-init + upload-complete.
  await env.DROP_KV.put(`revoked:${linkIdHex}`, "1");
  return json({ ok: true }, 200, origin);
}

// POST /upload-init { payload, size } -> single-PUT or multipart upload descriptor.
//   small (size <= MULTIPART_THRESHOLD): { mode:"single", objectId, uploadUrl }
//   large: { mode:"multipart", objectId, uploadId, partSize, partCount, partUrls, batchSize }
export async function uploadInit(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ payload: string; size: number }>(req);
  if (!body || typeof body.payload !== "string" || typeof body.size !== "number") {
    return json({ error: "missing fields" }, 400, origin);
  }
  const cap = maxUploadBytes(env);
  if (!Number.isInteger(body.size) || body.size <= 0 || body.size > cap) {
    return json({ error: "file too large", maxBytes: cap }, 413, origin);
  }

  let link: DropLink;
  try {
    link = await parseAndVerify(body.payload, env);
  } catch {
    return json({ error: "invalid link" }, 400, origin);
  }

  const linkIdHex = hex(link.linkId);
  if (await env.DROP_KV.get(`revoked:${linkIdHex}`)) return json({ error: "link revoked" }, 410, origin);
  if (!(await rateLimit(env.DROP_KV, `up:link:${linkIdHex}`, UPLOAD_LINK_PER_DAY, DAY))) {
    return json({ error: "link is over its daily limit" }, 429, origin);
  }
  const ipHash = await sha256hex(clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `up:ip:${ipHash}`, UPLOAD_IP_PER_DAY, DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }
  // Byte budgets + the AUTHORITATIVE recipient-capacity charge are applied at upload-COMPLETE on the
  // actual object size, not here — the declared `size` is client-controlled and no presigned PUT enforces
  // it (see uploadComplete). This is only a FAIL-FAST pre-check on the declared size: bounce an obviously
  // over-cap upload before the transfer so the sender sees "inbox full" up front. Best-effort + advisory
  // (complete re-checks on the real size), and skipped entirely while both caps are unset (the default),
  // so it costs nothing — not even the email unseal — until monetization is switched on.
  const freeCap = receiverInboundCap(env);
  const paidCap = paidAtRestCap(env);
  if (freeCap > 0 || paidCap > 0) {
    try {
      const kemPriv = await importKemPrivateKey(JSON.parse(env.SERVER_KEM_PRIVATE_JWK) as JsonWebKey);
      const email = await unsealEmail(kemPriv, link.sealedEmail);
      const acct = env.RECEIVER.get(env.RECEIVER.idFromName(await receiverId(env, email)));
      const s = await acct.summary(freeGrantBytes(env));
      const cap = s.tier === "paid" ? paidCap : freeCap;
      const basis = s.tier === "paid" ? s.pending : s.total;
      if (cap > 0 && basis + s.reserved + body.size > cap) {
        return json({ error: "recipient inbox is full", overCapacity: true }, 507, origin);
      }
    } catch {
      /* pre-check is best-effort: on any failure, fall through to the authoritative gate at complete */
    }
  }

  // Bind the object to the link that minted it, so completion can't pair another
  // (e.g. a victim's) link with this object.
  const objectId = hex(randomBytes(OBJECT_ID_BYTES));

  // Small files: one presigned PUT (unchanged path; fields kept for the old client).
  if (body.size <= multipartThreshold(env)) {
    const bind: UploadBinding = { link: linkIdHex };
    await env.DROP_KV.put(`upload:${objectId}`, JSON.stringify(bind), { expirationTtl: PRESIGN_TTL_SEC });
    const uploadUrl = await presignPut(env, objectId, PRESIGN_TTL_SEC);
    return json({ mode: "single", objectId, uploadUrl, expiresInSec: PRESIGN_TTL_SEC }, 200, origin);
  }

  // Large files: S3 multipart. Part size scales so partCount stays under ~10k; the
  // browser PUTs each part directly via presigned UploadPart URLs (bytes never transit
  // the Worker). The presign-gated cap = MAX_PARTS * MAX_PART_SIZE bounds total size,
  // and `partCount` (stored in the binding) caps how many part URLs we will ever sign.
  const partSize = computePartSize(body.size, env);
  const partCount = Math.ceil(body.size / partSize);
  if (partCount > MAX_PARTS) return json({ error: "file too large", maxBytes: cap }, 413, origin);

  const uploadId = await createMultipart(env, objectId);
  const bind: UploadBinding = { link: linkIdHex, mp: { uploadId, size: body.size, partSize, partCount } };
  await env.DROP_KV.put(`upload:${objectId}`, JSON.stringify(bind), { expirationTtl: MULTIPART_TTL_SEC });
  const partUrls = await presignParts(env, objectId, uploadId, 1, PART_PRESIGN_BATCH, partCount);
  return json(
    { mode: "multipart", objectId, uploadId, partSize, partCount, partUrls, batchSize: PART_PRESIGN_BATCH, expiresInSec: PRESIGN_TTL_SEC },
    200,
    origin,
  );
}

// POST /upload-parts { payload, objectId, from, count } -> { partUrls }
// Re-presign a batch of UploadPart URLs on demand, so long uploads get fresh
// signatures and we never sign all 10k up front.
export async function uploadParts(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ payload: string; objectId: string; from: number; count: number }>(req);
  if (!body || typeof body.payload !== "string" || typeof body.objectId !== "string" || typeof body.from !== "number" || typeof body.count !== "number") {
    return json({ error: "missing fields" }, 400, origin);
  }
  if (!isHex(body.objectId, OBJECT_ID_BYTES)) return json({ error: "bad object id" }, 400, origin);
  let link: DropLink;
  try {
    link = await parseAndVerify(body.payload, env);
  } catch {
    return json({ error: "invalid link" }, 400, origin);
  }
  const linkIdHex = hex(link.linkId);
  const bindRaw = await env.DROP_KV.get(`upload:${body.objectId}`);
  if (!bindRaw) return json({ error: "upload not found" }, 404, origin);
  let bind: UploadBinding;
  try {
    bind = JSON.parse(bindRaw) as UploadBinding;
  } catch {
    return json({ error: "object/link mismatch" }, 400, origin);
  }
  if (bind.link !== linkIdHex || !bind.mp) return json({ error: "object/link mismatch" }, 400, origin);
  if (await env.DROP_KV.get(`revoked:${linkIdHex}`)) return json({ error: "link revoked" }, 410, origin);

  const from = Math.max(1, Math.floor(body.from));
  const count = Math.max(1, Math.min(PART_PRESIGN_BATCH, Math.floor(body.count)));
  const partUrls = from > bind.mp.partCount ? [] : await presignParts(env, body.objectId, bind.mp.uploadId, from, count, bind.mp.partCount);
  return json({ partUrls }, 200, origin);
}

// POST /upload-abort { payload, objectId } -> { ok } (cancel cleanup)
export async function uploadAbort(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ payload: string; objectId: string }>(req);
  if (!body || typeof body.payload !== "string" || typeof body.objectId !== "string") {
    return json({ error: "missing fields" }, 400, origin);
  }
  if (!isHex(body.objectId, OBJECT_ID_BYTES)) return json({ error: "bad object id" }, 400, origin);
  let link: DropLink;
  try {
    link = await parseAndVerify(body.payload, env);
  } catch {
    return json({ error: "invalid link" }, 400, origin);
  }
  const linkIdHex = hex(link.linkId);
  const bindRaw = await env.DROP_KV.get(`upload:${body.objectId}`);
  if (bindRaw) {
    try {
      const bind = JSON.parse(bindRaw) as UploadBinding;
      if (bind.link === linkIdHex && bind.mp) await abortMultipart(env, body.objectId, bind.mp.uploadId);
    } catch {
      /* unparseable binding — nothing to abort */
    }
    await env.DROP_KV.delete(`upload:${body.objectId}`);
  }
  return json({ ok: true }, 200, origin);
}

// POST /upload-complete { payload, objectId, parts? } -> { ok }
// `parts` ({partNumber, etag} per part) is required for multipart; omitted for single PUT.
export async function uploadComplete(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ payload: string; objectId: string; parts?: unknown }>(req);
  if (!body || typeof body.payload !== "string" || typeof body.objectId !== "string") {
    return json({ error: "missing fields" }, 400, origin);
  }
  if (!isHex(body.objectId, OBJECT_ID_BYTES)) return json({ error: "bad object id" }, 400, origin);
  // Fail fast on a missing account-id secret BEFORE any side effect (copy, byte-budget increments): the
  // recipient charge derives rid from it, and we don't want a misconfigured deploy to do work + orphan
  // R2 objects before throwing late.
  if (!env.RECEIVER_ID_SECRET) {
    logEvent("config_error", { what: "RECEIVER_ID_SECRET" });
    return json({ error: "service misconfigured" }, 503, origin);
  }

  let link: DropLink;
  try {
    link = await parseAndVerify(body.payload, env);
  } catch {
    return json({ error: "invalid link" }, 400, origin);
  }
  const linkIdHex = hex(link.linkId);

  // Atomic completion guard (a per-object Durable Object) for exactly-once delivery. peek() is
  // read-only, so the early idempotency check spawns NO persistent DO state for a bogus object id;
  // claim() (which writes state + an alarm) runs only after the object is proven bound to this link.
  const guard = env.COMPLETION.get(env.COMPLETION.idFromName(body.objectId));
  if ((await guard.peek()) === "done") return json({ ok: true, already: true }, 200, origin);

  // The object must have been minted for THIS link (bound at upload-init). Stops an attacker pairing a
  // victim's link with an object uploaded under their own link to bypass the victim's caps.
  const bindRaw = await env.DROP_KV.get(`upload:${body.objectId}`);
  if (!bindRaw) return json({ error: "object/link mismatch" }, 400, origin);
  let bind: UploadBinding;
  try {
    bind = JSON.parse(bindRaw) as UploadBinding;
  } catch {
    return json({ error: "object/link mismatch" }, 400, origin);
  }
  if (bind.link !== linkIdHex) return json({ error: "object/link mismatch" }, 400, origin);

  // Revocation on the DELIVERY link (the email goes out here).
  if (await env.DROP_KV.get(`revoked:${linkIdHex}`)) return json({ error: "link revoked" }, 410, origin);

  // Take the completion lock (writes DO state only now, for a real bound object). The fencing token
  // guards finish()/release() so a stale, reclaimed attempt can't clobber a newer owner's lock.
  const claim = await guard.claim();
  if (!claim.ok) {
    return claim.reason === "done"
      ? json({ ok: true, already: true }, 200, origin)
      : json({ error: "completion already in progress, try again" }, 409, origin);
  }
  let finished = false;
  // The recipient-capacity reservation taken before the delivery email (below). Committed iff this
  // attempt wins the exactly-once delivery race; released on every other path. Held here so the finally
  // can release it on an abort. A crash before either frees the hold via the DO's reservation TTL.
  let reservation: { acct: ReturnType<Env["RECEIVER"]["get"]>; token: string } | null = null;
  try {
    // Multipart: validate the part set strictly, then assemble — but only if a prior attempt hasn't
    // already completed the MPU (CompleteMultipartUpload consumes the uploadId; if an earlier attempt
    // completed but failed downstream, the assembled object already exists — skip straight to delivery).
    if (bind.mp && !(await objectInfo(env, body.objectId))) {
      const parts = validateParts(body.parts, bind.mp.partCount);
      if (!parts) {
        // Terminal: the part set is wrong/incomplete. Discard the upload.
        await abortMultipart(env, body.objectId, bind.mp.uploadId);
        await env.DROP_KV.delete(`upload:${body.objectId}`);
        return json({ error: "bad or incomplete parts" }, 400, origin);
      }
      if (!(await completeMultipart(env, body.objectId, bind.mp.uploadId, parts))) {
        // Possibly transient — keep the multipart + binding so the client can retry.
        logEvent("assemble_failed", { objectId: body.objectId, parts: parts.length });
        return json({ error: "could not assemble upload, try again" }, 502, origin);
      }
    }

    // The object (single-PUT or multipart-assembled) must exist + be within the cap.
    const staged = await objectInfo(env, body.objectId);
    if (!staged) return json({ error: "object not found" }, 404, origin);
    if (staged.size > maxUploadBytes(env)) {
      await deleteObject(env, body.objectId);
      return json({ error: "file too large" }, 413, origin);
    }

    // Per-link flood cap on the delivery link (gates the expensive copy below).
    if (!(await rateLimit(env.DROP_KV, `deliver:link:${linkIdHex}`, UPLOAD_LINK_PER_DAY, DAY))) {
      return json({ error: "link is over its daily limit" }, 429, origin);
    }

    // Promote to an immutable, sender-unknown final key, then validate THAT copy. The sender holds no
    // PUT URL for the final key, so it can't be swapped after the check (closes the mutable-PUT TOCTOU).
    const finalId = hex(randomBytes(OBJECT_ID_BYTES));
    if (!(await copyObject(env, body.objectId, finalId))) return json({ error: "object not found" }, 404, origin);
    const finalInfo = await objectInfo(env, finalId);
    if (!finalInfo || finalInfo.size > maxUploadBytes(env) || !(await validateFileKeyHeader(env, finalId, finalInfo.size))) {
      logEvent("invalid_ciphertext", { link: linkIdHex, size: finalInfo?.size ?? null });
      await deleteObject(env, finalId);
      return json({ error: "not a FileKey file" }, 422, origin);
    }

    let email: string;
    try {
      const kemPriv = await importKemPrivateKey(JSON.parse(env.SERVER_KEM_PRIVATE_JWK) as JsonWebKey);
      email = await unsealEmail(kemPriv, link.sealedEmail);
    } catch {
      await deleteObject(env, finalId);
      return json({ error: "invalid link" }, 400, origin);
    }

    // If a stalled attempt was reclaimed while we worked, the reclaimer now owns delivery — abort
    // before the email rather than send a duplicate (fences the side effect, not just the state). The
    // reclaimer mints its own final key, so drop ours instead of leaking it until TTL.
    if (!(await guard.heldBy(claim.token))) {
      await deleteObject(env, finalId);
      return json({ error: "completion was retried elsewhere, try again" }, 409, origin);
    }

    // Recipient capacity FIRST among the post-fence gates, on the ACTUAL final-object size: RESERVE the
    // bytes against the cap (atomic in the DO, so two concurrent uploads to one recipient can't both
    // slip a tight cap). The hold is committed only if THIS attempt wins delivery (below) and released
    // on every other path (byte-budget reject, failed email, abort, or a duplicate that lost the
    // exactly-once race), so the charge is exactly-once; a crash frees the hold via the DO's reservation
    // TTL. An over-cap upload rejects here WITHOUT burning the byte budget. We reserve the actual
    // final-object size on every (re)try, so overwriting mutable staging to deliver more is caught here.
    // Uncapped deployments still meter (commit accrues `total`) for accurate history.
    const rid = await receiverId(env, email);
    const acct = env.RECEIVER.get(env.RECEIVER.idFromName(rid));
    const hold = await acct.reserve(finalInfo.size, receiverInboundCap(env), paidAtRestCap(env));
    if (!hold.ok) {
      logEvent("recipient_over_capacity", { link: linkIdHex, size: finalInfo.size });
      await deleteObject(env, finalId);
      await deleteObject(env, body.objectId);
      return json({ error: "recipient inbox is full", overCapacity: true }, 507, origin);
    }
    reservation = { acct, token: hold.token };

    // Decode the receiver's share key to a raw pubkey for the download gate, BEFORE the byte budgets — a
    // malformed key (the only structural way this fails) then rejects without burning daily budget. The
    // Worker only holds the signed link during completion, so this is the one place to do it. The
    // fetchbind WRITE itself happens just before the email (below).
    let recipientPk: Uint8Array;
    try {
      recipientPk = recipientPkFromShareKeyBytes(link.shareKey);
    } catch {
      await deleteObject(env, finalId);
      return json({ error: "invalid link" }, 400, origin);
    }

    // Byte budgets on the ACTUAL object size, after the recipient reservation (released by the finally
    // if a budget rejects here). Per-link + per-IP daily caps keep a multi-TB per-file cap from
    // becoming petabytes/day.
    const ipHash = await sha256hex(clientIp(req));
    if (!(await rateLimitBytes(env.DROP_KV, `up:bytes:link:${linkIdHex}`, finalInfo.size, bytesPerLinkDay(env), DAY))) {
      logEvent("byte_budget_exceeded", { scope: "link", link: linkIdHex, size: finalInfo.size });
      await deleteObject(env, finalId);
      await deleteObject(env, body.objectId);
      return json({ error: "link is over its daily transfer limit" }, 429, origin);
    }
    if (!(await rateLimitBytes(env.DROP_KV, `up:bytes:ip:${ipHash}`, finalInfo.size, bytesPerIpDay(env), DAY))) {
      logEvent("byte_budget_exceeded", { scope: "ip", link: linkIdHex, size: finalInfo.size });
      await deleteObject(env, finalId);
      await deleteObject(env, body.objectId);
      return json({ error: "rate limited" }, 429, origin);
    }

    // Bind the delivered object to the receiver's (already-decoded) key so the download gate can prove
    // possession later: store the raw pubkey + size + owning account (rid) keyed by finalId. The rid lets
    // a download charge the right account without re-unsealing the email; it's an opaque HMAC (already the
    // DO name), so it carries no PII. FAIL-CLOSED: if the write fails, do NOT deliver, or the receiver
    // gets a link the gate can't authenticate. No linkId/email stored alongside (correlation hygiene).
    try {
      await env.DROP_KV.put(
        `fetchbind:${finalId}`,
        JSON.stringify({ pk: base64urlEncode(recipientPk), size: finalInfo.size, rid }),
        { expirationTtl: FETCHBIND_TTL_SEC },
      );
    } catch {
      logEvent("fetchbind_failed", { link: linkIdHex });
      await deleteObject(env, finalId);
      return json({ error: "delivery failed, try again" }, 502, origin);
    }

    // Carry the receiver's manage/revoke link in the delivery email (best-effort): a KV blip fetching the
    // token must NOT fail an otherwise-deliverable upload, so fall back to no manage link rather than
    // throwing into the finally (which would orphan the object + fetchbind and 500 a deliverable send).
    const revokeToken = await env.DROP_KV.get(`linkrev:${linkIdHex}`).catch(() => null);
    const manageUrl = revokeToken ? `${linkOrigin(env)}/revoke#${revokeToken}` : undefined;
    try {
      await sendDownloadEmail(env, email, `${linkOrigin(env)}/d/${finalId}`, link.label, manageUrl);
    } catch {
      logEvent("delivery_failed", { link: linkIdHex });
      // Best-effort cleanup, each guarded independently so a throw in one can't skip the other (and
      // neither masks the 502 the client retries on): drop the gate binding AND the final object. A
      // residual of either is harmless and TTL-bounded (fetchbind ~8d; the object via the 7-day lifecycle).
      await env.DROP_KV.delete(`fetchbind:${finalId}`).catch(() => {});
      await deleteObject(env, finalId).catch(() => {});
      return json({ error: "delivery failed, try again" }, 502, origin);
    }
    // The email is OUT — from here we must never release the completion lock (that would let a retry
    // send a duplicate). Commit the recipient charge IFF we WON the exactly-once delivery transition; if
    // a stalled+reclaimed sibling already delivered (a duplicate email, the completion guard's accepted
    // residual), finish() is "already"/"lost" and we RELEASE the hold instead, so the receiver is
    // charged exactly once. Then best-effort cleanup; a cleanup failure must NOT 500 after a successful
    // delivery (the client doesn't retry 500, so it would report a false failure).
    finished = true;
    const outcome = await guard.finish(claim.token);
    // Accrue total always; track per-file pending only when the at-rest cap is BOTH configured AND billing
    // is on — i.e. only when downloads actually run through charge() to clear it. (Setting the cap without
    // billing would otherwise let pending drift up with no downloads to decrement it.)
    if (outcome === "won") await acct.commit(hold.token, finalId, billingEnabled(env) && paidAtRestCap(env) > 0);
    else { logEvent("delivery_duplicate", { link: linkIdHex }); await acct.release(hold.token); }
    logEvent("delivered", { link: linkIdHex, size: finalInfo.size });
    try {
      await deleteObject(env, body.objectId);
      await env.DROP_KV.delete(`upload:${body.objectId}`);
    } catch {
      /* orphaned staging object — the 7-day lifecycle reaps it */
    }
    return json({ ok: true }, 200, origin);
  } finally {
    if (!finished) {
      // Abort path (before delivery): release the capacity hold so it doesn't sit against the cap until
      // its TTL, then free the completion claim for a retry. Best-effort: a release failure must not mask
      // the real result (the DO's reservation alarm reclaims the hold either way).
      if (reservation) await reservation.acct.release(reservation.token).catch(() => logEvent("receiver_release_failed", { link: linkIdHex }));
      await guard.release(claim.token);
    }
  }
}

// ---- Download gate (passkey-proof at /fetch) ---------------------------------------------------------
// The relay never sees plaintext, so it can't tell WHO is downloading — which it must know to charge the
// right account. So a download is gated by an HPKE challenge-response that proves the requester holds the
// receiver's passkey, without revealing anything: the Worker seals a random nonce to the receiver's bound
// share key (only their passkey unseals it) and acts only once they prove they recovered it. The proof is
// the gate for two outcomes, each needing its own single-use challenge:
//   /fetch/challenge -> /fetch/preview  : FREE. The Worker serves only the head+metadata bytes (so the
//                                         receiver sees the filename + size), never a URL to the payload.
//   /fetch/challenge -> /fetch/download : CHARGED (when billing is on). Debits the per-file price from the
//                                         account balance (free re-downloads), then issues a short-lived
//                                         presigned GET; 402 when out of funds. Free (Phase-1 behavior)
//                                         when billing is off, so 2a ships inert.

/** Constant-time equality for two equal-length hex strings (used to compare proofs). */
function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// rid is optional for backward compatibility: bindings written before Phase 2 carry only { pk, size }.
// A challenge needs just the pubkey, so those still authenticate; a charged download with no rid can't
// resolve an account and falls back to free (safe — billing is only switched on long after every live
// binding has a rid, since they expire in 8 days).
type Fetchbind = { pk: string; size: number; rid?: string };

/** Load + parse the delivery binding for a finalId (the receiver pubkey + size + owning account). */
async function loadFetchbind(env: Env, objectId: string): Promise<Fetchbind | null> {
  const raw = await env.DROP_KV.get(`fetchbind:${objectId}`);
  if (!raw) return null;
  try {
    const b = JSON.parse(raw) as Partial<Fetchbind>;
    if (typeof b.pk !== "string" || typeof b.size !== "number" || !Number.isFinite(b.size) || b.size < 0) return null;
    return { pk: b.pk, size: b.size, rid: typeof b.rid === "string" ? b.rid : undefined };
  } catch {
    return null;
  }
}

/** Verify a single-use challenge proof (shared by preview + download): validate + rate-limit, then
 *  consume the challenge (delete-before-compare, so a wrong guess can't be retried) and constant-time
 *  compare. Returns the bound objectId on success, else the error Response to return as-is. */
async function verifyFetchProof(req: Request, env: Env, origin: string, body: { challengeId?: unknown; proof?: unknown } | null): Promise<{ ok: true; objectId: string } | { ok: false; resp: Response }> {
  if (!body || typeof body.challengeId !== "string" || typeof body.proof !== "string") {
    return { ok: false, resp: json({ error: "missing fields" }, 400, origin) };
  }
  const { challengeId, proof } = body;
  if (!isHex(challengeId, CHALLENGE_ID_BYTES) || !isHex(proof, 32)) return { ok: false, resp: json({ error: "bad proof" }, 400, origin) };
  const ipHash = await sha256hex(clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `prove:ip:${ipHash}`, envInt(env.FETCH_IP_PER_DAY, FETCH_IP_PER_DAY), DAY))) {
    return { ok: false, resp: json({ error: "rate limited" }, 429, origin) };
  }
  const stored = await env.DROP_KV.get(`challenge:${challengeId}`);
  if (!stored) return { ok: false, resp: json({ error: "challenge expired" }, 404, origin) };
  await env.DROP_KV.delete(`challenge:${challengeId}`); // best-effort single-use (KV get+delete isn't atomic)
  let ch: { objectId: string; proof: string };
  try {
    ch = JSON.parse(stored) as { objectId: string; proof: string };
  } catch {
    return { ok: false, resp: json({ error: "challenge expired" }, 404, origin) };
  }
  if (!constantTimeEqualHex(proof, ch.proof)) return { ok: false, resp: json({ error: "proof failed" }, 403, origin) };
  return { ok: true, objectId: ch.objectId };
}

// POST /fetch/challenge { objectId } -> { challengeId, sealed }
export async function fetchChallenge(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const body = await readJson<{ objectId: string }>(req);
  if (!body || typeof body.objectId !== "string") return json({ error: "missing fields" }, 400, origin);
  if (!isHex(body.objectId, OBJECT_ID_BYTES)) return json({ error: "bad object id" }, 400, origin);
  const ipHash = await sha256hex(clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `fetch:ip:${ipHash}`, envInt(env.FETCH_IP_PER_DAY, FETCH_IP_PER_DAY), DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }
  // Hard cutover: only a delivered object has a binding; anything else is unauthenticated -> 404.
  const bind = await loadFetchbind(env, body.objectId);
  if (!bind) return json({ error: "expired or not found" }, 404, origin);

  // Seal a fresh nonce to the receiver's pubkey (base mode); only the passkey holder can unseal it.
  const recipientPk = await importKemPublicKey(base64urlDecode(bind.pk));
  const nonce = randomBytes(FETCH_NONCE_BYTES);
  const sealed = await hpkeSealTo(recipientPk, nonce, FETCH_CHALLENGE_INFO);
  const challengeId = hex(randomBytes(CHALLENGE_ID_BYTES));
  const expectedProof = await fetchProofHex(challengeId, body.objectId, nonce);
  await env.DROP_KV.put(
    `challenge:${challengeId}`,
    JSON.stringify({ objectId: body.objectId, proof: expectedProof }),
    { expirationTtl: CHALLENGE_TTL_SEC },
  );
  return json({ challengeId, sealed: base64urlEncode(sealed) }, 200, origin);
}

// POST /fetch/preview { challengeId, proof } -> binary body: the head + metadata bytes only (FREE).
// The Worker serves the bytes itself rather than a presigned URL because a URL is all-or-nothing — handing
// one out for "preview" would be a free full download. Bounded to the metadata prefix, so the payload is
// never exposed for free. (R2 egress is free, so the only cost here is anti-abuse, which the prove:ip cap
// and the size bound cover.)
export async function fetchPreview(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const v = await verifyFetchProof(req, env, origin, await readJson(req));
  if (!v.ok) return v.resp;
  const info = await objectInfo(env, v.objectId);
  if (!info) return json({ error: "expired or not found" }, 404, origin);
  // Read a bounded prefix, then trim to EXACTLY head + metadata-ciphertext so the payload is never served
  // for free (a fixed prefix would leak the start of the payload on files with small metadata).
  const obj = await env.DROP_BUCKET.get(v.objectId, { range: { offset: 0, length: Math.min(FETCH_PREVIEW_BYTES, info.size) } });
  if (!obj) return json({ error: "expired or not found" }, 404, origin);
  const buf = new Uint8Array(await obj.arrayBuffer());
  const metaLen = fileKeyMetadataPrefixLen(buf);
  // Fail CLOSED: if the header won't parse we can't tell metadata from payload, so serve nothing rather
  // than risk leaking payload bytes for free. (A delivered object always has a valid header.)
  if (metaLen === null || metaLen > buf.length) return json({ error: "expired or not found" }, 404, origin);
  return new Response(buf.subarray(0, metaLen), { status: 200, headers: { ...cors(origin), "content-type": "application/octet-stream", "cache-control": "no-store" } });
}

// POST /fetch/download { challengeId, proof } -> { url, expiresInSec } | 402 { needBytes, balanceBytes }.
// Charges the per-file price to the owning account once (free re-downloads), then issues a short-lived
// presigned GET. When billing is off (default) it skips the charge and behaves exactly like Phase 1.
export async function fetchDownload(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  const v = await verifyFetchProof(req, env, origin, await readJson(req));
  if (!v.ok) return v.resp;
  // Confirm the object still exists BEFORE charging, so we never debit for a file that's already gone.
  if (!(await objectInfo(env, v.objectId))) return json({ error: "expired or not found" }, 404, origin);
  if (billingEnabled(env)) {
    const bind = await loadFetchbind(env, v.objectId);
    // A challenge only mints for a bound object, so a missing bind here is anomalous (not a free pass) -> 404.
    if (!bind) return json({ error: "expired or not found" }, 404, origin);
    if (bind.rid) {
      const acct = env.RECEIVER.get(env.RECEIVER.idFromName(bind.rid));
      // charge() is exactly-once per finalId: a re-download (or a double-clicked/retried Save) sees the
      // file already paid and returns free, so a crash between charge and URL issue can't double-charge —
      // the retry re-proves, charge() says alreadyPaid, and the URL is re-issued.
      const result = await acct.charge(v.objectId, bind.size, freeGrantBytes(env));
      if (!result.ok) return json({ error: "needs funds", needBytes: result.need, balanceBytes: result.balance }, 402, origin);
    } else {
      logEvent("billing_skipped_no_rid"); // ONLY a legacy pre-Phase-2 binding (has pk+size, no rid) -> free
    }
  }
  const url = await presignGet(env, v.objectId, FETCH_URL_TTL_SEC);
  return json({ url, expiresInSec: FETCH_URL_TTL_SEC }, 200, origin);
}

// ---- Billing (Stripe top-up) -------------------------------------------------------------------------
// A receiver tops up prepaid credit through Stripe-hosted Checkout. The account to credit is the one that
// owns the file being unlocked: the client proves passkey possession (same gate as a download), which
// resolves the rid from the binding. The credit itself lands via the webhook, not the redirect, so it's
// robust to the user closing the tab. Both endpoints 503 until Stripe is configured, so 2b ships inert.

// POST /billing/checkout { challengeId, proof, pack } -> { url } (a Stripe-hosted Checkout URL)
export async function billingCheckout(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  if (!stripeConfigured(env)) return json({ error: "billing unavailable" }, 503, origin);
  const body = await readJson<{ challengeId: string; proof: string; pack: string }>(req);
  if (!body || typeof body.pack !== "string" || !isPackId(body.pack)) return json({ error: "unknown pack" }, 400, origin);
  // Prove passkey possession on the file being unlocked -> the owning account (rid) to credit.
  const v = await verifyFetchProof(req, env, origin, body);
  if (!v.ok) return v.resp;
  const bind = await loadFetchbind(env, v.objectId);
  if (!bind?.rid) return json({ error: "expired or not found" }, 404, origin);
  const base = linkOrigin(env);
  try {
    const url = await createCheckoutSession(env, {
      rid: bind.rid,
      pack: body.pack,
      successUrl: `${base}/d/${v.objectId}?paid=1`, // back to the file; the client retries the download
      cancelUrl: `${base}/d/${v.objectId}`,
    });
    return json({ url }, 200, origin);
  } catch {
    logEvent("stripe_checkout_failed");
    return json({ error: "could not start checkout, try again" }, 502, origin);
  }
}

// POST /billing/webhook (Stripe -> us; server-to-server, raw body, signature-verified) -> 200/400
export async function billingWebhook(req: Request, env: Env): Promise<Response> {
  if (!env.STRIPE_WEBHOOK_SECRET) {
    logEvent("config_error", { what: "STRIPE_WEBHOOK_SECRET" });
    return new Response("unconfigured", { status: 503 });
  }
  const sig = req.headers.get("stripe-signature") ?? "";
  const raw = await req.text(); // RAW body: re-serialized JSON would break the signature
  if (!(await verifyStripeSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET, Math.floor(Date.now() / 1000)))) {
    return new Response("bad signature", { status: 400 });
  }
  let event: unknown;
  try {
    event = JSON.parse(raw);
  } catch {
    return new Response("bad payload", { status: 400 });
  }
  const credit = parseCreditFromEvent(event);
  if (credit) {
    // credit() is idempotent on the Stripe event id, so a webhook retry can't double-credit.
    const acct = env.RECEIVER.get(env.RECEIVER.idFromName(credit.rid));
    await acct.credit(credit.bytes, freeGrantBytes(env), credit.eventId);
    logEvent("billing_credited", { bytes: credit.bytes }); // bytes only — never the rid/email
  }
  return new Response("ok", { status: 200 }); // 200 even for ignored event types, so Stripe stops retrying
}
