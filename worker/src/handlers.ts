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
import { sendConfirmEmail, sendDownloadEmail } from "./email";
import { clientIp, json, readJson } from "./http";
import { DAY, HOUR, rateLimit } from "./kv";
import { copyObject, deleteObject, hasFileKeyMagic, objectInfo, presignGet, presignPut } from "./r2";
import type { Env } from "./types";
import { hex, isEmail, isHex, randomBytes, sha256hex } from "../../shared/util";

// Abuse limits (soft, KV fixed-window). Tune from real traffic. Exported so tests
// assert against the source of truth.
export const REG_IP_PER_DAY = 20; // confirmation emails one IP can trigger
export const REG_EMAIL_PER_DAY = 5; // confirmation emails one address can receive (anti-bombing)
export const UPLOAD_LINK_PER_DAY = 25; // files one Drop link accepts (anti-flood of the inbox)
export const UPLOAD_IP_PER_DAY = 100; // files one IP can push across all links
const CONFIRM_TTL_SEC = HOUR; // pending registration lifetime
const PRESIGN_TTL_SEC = HOUR; // presigned PUT/GET lifetime
const OBJECT_TTL_SEC = 7 * DAY; // matches the R2 bucket lifecycle rule
const DEFAULT_MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
const OBJECT_ID_BYTES = 16;

function maxUploadBytes(env: Env): number {
  const n = env.MAX_UPLOAD_BYTES ? parseInt(env.MAX_UPLOAD_BYTES, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_UPLOAD_BYTES;
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

  if (!(await rateLimit(env.DROP_KV, `reg:ip:${clientIp(req)}`, REG_IP_PER_DAY, DAY))) {
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
  if (!(await rateLimit(env.DROP_KV, `reg:em:${emailHash}`, REG_EMAIL_PER_DAY, DAY))) {
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
  return json({ link: base64urlEncode(full) }, 200, origin);
}

// POST /upload-init { payload, size } -> { objectId, uploadUrl, expiresInSec }
export async function uploadInit(req: Request, env: Env): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN || "*";
  const body = await readJson<{ payload: string; size: number }>(req);
  if (!body || typeof body.payload !== "string" || typeof body.size !== "number") {
    return json({ error: "missing fields" }, 400, origin);
  }
  if (body.size <= 0 || body.size > maxUploadBytes(env)) {
    return json({ error: "file too large", maxBytes: maxUploadBytes(env) }, 413, origin);
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
  if (!(await rateLimit(env.DROP_KV, `up:ip:${clientIp(req)}`, UPLOAD_IP_PER_DAY, DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }

  // Bind the object to the link that minted it, so completion can't pair another
  // (e.g. a victim's) link with this object. Expires with the presign window.
  const objectId = hex(randomBytes(OBJECT_ID_BYTES));
  await env.DROP_KV.put(`upload:${objectId}`, linkIdHex, { expirationTtl: PRESIGN_TTL_SEC });
  const uploadUrl = await presignPut(env, objectId, PRESIGN_TTL_SEC);
  return json({ objectId, uploadUrl, expiresInSec: PRESIGN_TTL_SEC }, 200, origin);
}

// POST /upload-complete { payload, objectId } -> { ok }
export async function uploadComplete(req: Request, env: Env): Promise<Response> {
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

  // Idempotent: a re-issued complete for an already-delivered object is a no-op,
  // so a client can't amplify one upload into many emails.
  const doneKey = `done:${body.objectId}`;
  if (await env.DROP_KV.get(doneKey)) return json({ ok: true, already: true }, 200, origin);

  // The object must have been minted for THIS link (bound at upload-init). Stops
  // an attacker pairing a victim's link with an object uploaded under their own
  // link to bypass the victim link's flood cap + revocation.
  if ((await env.DROP_KV.get(`upload:${body.objectId}`)) !== linkIdHex) {
    return json({ error: "object/link mismatch" }, 400, origin);
  }

  // Revocation + per-link flood cap on the DELIVERY link — the email goes out
  // here, so this is where the receiver link's controls must actually apply.
  if (await env.DROP_KV.get(`revoked:${linkIdHex}`)) return json({ error: "link revoked" }, 410, origin);
  if (!(await rateLimit(env.DROP_KV, `deliver:link:${linkIdHex}`, UPLOAD_LINK_PER_DAY, DAY))) {
    return json({ error: "link is over its daily limit" }, 429, origin);
  }

  const staged = await objectInfo(env, body.objectId);
  if (!staged) return json({ error: "object not found" }, 404, origin);
  if (staged.size > maxUploadBytes(env)) {
    await deleteObject(env, body.objectId);
    return json({ error: "file too large" }, 413, origin);
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

  await sendDownloadEmail(env, email, `${origin}/d/${finalId}`, link.label);
  // Mark done only AFTER the email is sent, so a failed send stays retryable.
  await env.DROP_KV.put(doneKey, finalId, { expirationTtl: OBJECT_TTL_SEC });
  await deleteObject(env, body.objectId); // drop the staging object (best-effort)
  return json({ ok: true }, 200, origin);
}

// GET /fetch/:id -> { url } (presigned R2 GET for the receiver's decrypt page)
export async function fetchObject(_req: Request, env: Env, objectId: string): Promise<Response> {
  const origin = env.ALLOWED_ORIGIN || "*";
  if (!isHex(objectId, OBJECT_ID_BYTES)) return json({ error: "bad object id" }, 400, origin);
  if (!(await objectInfo(env, objectId))) return json({ error: "expired or not found" }, 404, origin);
  const url = await presignGet(env, objectId, PRESIGN_TTL_SEC);
  return json({ url, expiresInSec: PRESIGN_TTL_SEC }, 200, origin);
}
