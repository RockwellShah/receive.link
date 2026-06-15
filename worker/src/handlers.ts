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
  LINK_ID_LEN,
  base64urlDecode,
  base64urlEncode,
  decodeDropLink,
  signableBytes,
  splitSignature,
  type DropLink,
} from "../../shared/codec";
import { importKemPrivateKey, importSignPrivateKey, importSignPublicKey, signRegion, unsealEmail, verifyRegion } from "../../shared/crypto";
import { sendConfirmEmail, sendDownloadEmail, sendDropLinkEmail } from "./email";
import { clientIp, json, readJson } from "./http";
import { DAY, HOUR, rateLimit } from "./kv";
import { abortMultipart, completeMultipart, copyObject, createMultipart, deleteObject, hasFileKeyMagic, objectInfo, presignGet, presignPut, presignUploadPart } from "./r2";
import type { Env } from "./types";
import { hex, isEmail, isHex, randomBytes, sha256hex } from "../../shared/util";

// Abuse limits (soft, KV fixed-window). Tune from real traffic. Exported so tests
// assert against the source of truth.
export const REG_IP_PER_DAY = 20; // confirmation emails one IP can trigger
export const REG_EMAIL_PER_DAY = 5; // confirmation emails one address can receive (anti-bombing)
export const UPLOAD_LINK_PER_DAY = 25; // files one Drop link accepts (anti-flood of the inbox)
export const UPLOAD_IP_PER_DAY = 100; // files one IP can push across all links
export const REVOKE_IP_PER_DAY = 60; // revoke calls one IP can make (tokens are unguessable; this just caps probing)
const CONFIRM_TTL_SEC = HOUR; // pending registration lifetime
const PRESIGN_TTL_SEC = HOUR; // presigned PUT/GET lifetime
const OBJECT_TTL_SEC = 7 * DAY; // matches the R2 bucket lifecycle rule
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
  const pub = await importSignPublicKey(JSON.parse(env.SERVER_SIGN_PUBLIC_JWK) as JsonWebKey);
  if (!(await verifyRegion(pub, signable, signature))) throw new Error("bad server signature");
  return decodeDropLink(bytes);
}

// POST /register { sealedEmail, shareKey, label } (all base64url except label)
export async function register(req: Request, env: Env): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN || "*";
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
  await sendConfirmEmail(env, email, `${origin}/confirm#${nonce}`, label);
  return json({ ok: true }, 202, origin);
}

// POST /confirm { nonce } -> { link }
export async function confirm(req: Request, env: Env): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN || "*";
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
  const linkIdHex = hex(region.slice(1, 1 + LINK_ID_LEN));
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
    await sendDropLinkEmail(env, email, `${origin}/#${linkB64}`, `${origin}/revoke#${revokeToken}`, decoded.label);
  } catch {
    /* page already showed both links */
  }

  return json({ link: linkB64, revokeToken }, 200, origin);
}

// POST /revoke { token } -> { ok } — the receiver turns their own Drop link off.
// The token is the secret minted at confirm; it resolves to the link_id we flag.
export async function revoke(req: Request, env: Env): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN || "*";
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
  const origin = env.ALLOWED_ORIGIN || "*";
  const body = await readJson<{ payload: string; size: number }>(req);
  if (!body || typeof body.payload !== "string" || typeof body.size !== "number") {
    return json({ error: "missing fields" }, 400, origin);
  }
  const cap = maxUploadBytes(env);
  if (body.size <= 0 || body.size > cap) {
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
  const origin = env.ALLOWED_ORIGIN || "*";
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
  const origin = env.ALLOWED_ORIGIN || "*";
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
  const origin = env.ALLOWED_ORIGIN || "*";
  const body = await readJson<{ payload: string; objectId: string; parts?: unknown }>(req);
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

  // Idempotent: a re-issued complete for an already-delivered object is a no-op,
  // so a client can't amplify one upload into many emails.
  const doneKey = `done:${body.objectId}`;
  if (await env.DROP_KV.get(doneKey)) return json({ ok: true, already: true }, 200, origin);

  // The object must have been minted for THIS link (bound at upload-init). Stops
  // an attacker pairing a victim's link with an object uploaded under their own
  // link to bypass the victim link's flood cap + revocation.
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

  // Best-effort concurrency guard (the done flag is the permanent one): blocks a
  // second concurrent complete while this one runs. Held only during the work; the
  // finally frees it so a failed attempt can be retried.
  const completingKey = `completing:${body.objectId}`;
  if (await env.DROP_KV.get(completingKey)) return json({ ok: true, already: true }, 200, origin);
  await env.DROP_KV.put(completingKey, "1", { expirationTtl: 120 });
  try {
    // Multipart: validate the part set strictly, then assemble. After this the
    // object exists at objectId exactly like a single PUT did.
    if (bind.mp) {
      const parts = validateParts(body.parts, bind.mp.partCount);
      if (!parts) {
        // Terminal: the part set is wrong/incomplete. Discard the upload.
        await abortMultipart(env, body.objectId, bind.mp.uploadId);
        await env.DROP_KV.delete(`upload:${body.objectId}`);
        return json({ error: "bad or incomplete parts" }, 400, origin);
      }
      if (!(await completeMultipart(env, body.objectId, bind.mp.uploadId, parts))) {
        // Possibly transient — keep the multipart + binding so the client can retry.
        return json({ error: "could not assemble upload, try again" }, 502, origin);
      }
    }

    // The object (single-PUT or multipart-assembled) must exist + be within the cap.
    // Checked BEFORE spending the link's delivery quota.
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

    // Promote to an immutable, sender-unknown final key, then validate THAT copy.
    // The sender holds no PUT URL for the final key, so it can't be swapped after
    // the check (closes the mutable-PUT TOCTOU). Size + magic are checked on the
    // final object, which is authoritative.
    const finalId = hex(randomBytes(OBJECT_ID_BYTES));
    if (!(await copyObject(env, body.objectId, finalId))) return json({ error: "object not found" }, 404, origin);
    const finalInfo = await objectInfo(env, finalId);
    if (!finalInfo || finalInfo.size > maxUploadBytes(env) || !(await hasFileKeyMagic(env, finalId))) {
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

    // Carry the receiver's manage/revoke link in the delivery email (best-effort:
    // links minted before revoke existed simply won't have one).
    const revokeToken = await env.DROP_KV.get(`linkrev:${linkIdHex}`);
    const manageUrl = revokeToken ? `${origin}/revoke#${revokeToken}` : undefined;
    try {
      await sendDownloadEmail(env, email, `${origin}/d/${finalId}`, link.label, manageUrl);
    } catch {
      await deleteObject(env, finalId); // no orphaned final; the client can retry
      return json({ error: "delivery failed, try again" }, 502, origin);
    }
    // Mark done only AFTER the email sends, so a failed send stays retryable.
    await env.DROP_KV.put(doneKey, finalId, { expirationTtl: OBJECT_TTL_SEC });
    await deleteObject(env, body.objectId); // drop the staging/assembled object (best-effort)
    await env.DROP_KV.delete(`upload:${body.objectId}`);
    return json({ ok: true }, 200, origin);
  } finally {
    await env.DROP_KV.delete(completingKey);
  }
}

// GET /fetch/:id -> { url } (presigned R2 GET for the receiver's decrypt page)
export async function fetchObject(_req: Request, env: Env, objectId: string): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN || "*";
  if (!isHex(objectId, OBJECT_ID_BYTES)) return json({ error: "bad object id" }, 400, origin);
  if (!(await objectInfo(env, objectId))) return json({ error: "expired or not found" }, 404, origin);
  const url = await presignGet(env, objectId, PRESIGN_TTL_SEC);
  return json({ url, expiresInSec: PRESIGN_TTL_SEC }, 200, origin);
}
