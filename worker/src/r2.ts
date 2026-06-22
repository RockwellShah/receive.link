// R2 relay access. Uploads and downloads go BROWSER-DIRECT to R2 via presigned
// S3 URLs (bytes never transit the Worker — no 100 MB body limit, no Worker CPU
// on the payload). The Worker signs the URLs (SigV4 via aws4fetch) and uses the
// R2 *binding* for server-side checks (object size, magic-byte sniff).
//
// Requires R2 S3 API credentials (Dashboard > R2 > Manage API tokens) as
// secrets, plus the bucket's CORS allowing PUT/GET from the Drop web origin.
// The browser-direct PUT/GET + CORS is the one thing to verify on live R2.

import { AwsClient } from "aws4fetch";
import type { Env } from "./types";

/** FileKey container magic: "FKEY" at offset 0 (src/constants.ts). */
export const FILEKEY_MAGIC = new Uint8Array([0x46, 0x4b, 0x45, 0x59]);

function client(env: Env): AwsClient {
  return new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    region: "auto",
    service: "s3",
  });
}

function objectUrl(env: Env, objectId: string): string {
  return `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${env.R2_BUCKET}/${objectId}`;
}

async function presign(env: Env, objectId: string, method: "PUT" | "GET", expiresSec: number): Promise<string> {
  const url = `${objectUrl(env, objectId)}?X-Amz-Expires=${expiresSec}`;
  const signed = await client(env).sign(url, { method, aws: { signQuery: true } });
  return signed.url;
}

export function presignPut(env: Env, objectId: string, expiresSec = 3600): Promise<string> {
  return presign(env, objectId, "PUT", expiresSec);
}

export function presignGet(env: Env, objectId: string, expiresSec = 3600): Promise<string> {
  return presign(env, objectId, "GET", expiresSec);
}

/** Server-side existence + size check via the binding. Null if missing. */
export async function objectInfo(env: Env, objectId: string): Promise<{ size: number } | null> {
  const head = await env.DROP_BUCKET.head(objectId);
  return head ? { size: head.size } : null;
}

/**
 * Copy an object to a new key. Uses S3 CopyObject (server-side; bytes never
 * transit the Worker, so it's O(1) Worker work for any size). In-memory test
 * doubles expose a `copy` method on the binding, which we prefer when present.
 * Returns false if the source is missing. This is how a validated upload is
 * promoted to an immutable, sender-unknown delivery key (closes the mutable-PUT
 * TOCTOU: the sender has no PUT URL for the final key).
 */
export async function copyObject(env: Env, srcKey: string, dstKey: string): Promise<boolean> {
  const bucket = env.DROP_BUCKET as unknown as { copy?: (s: string, d: string) => Promise<boolean> };
  if (typeof bucket.copy === "function") return bucket.copy(srcKey, dstKey);
  const res = await client(env).fetch(objectUrl(env, dstKey), {
    method: "PUT",
    headers: { "x-amz-copy-source": `/${env.R2_BUCKET}/${srcKey}` },
  });
  return res.ok;
}

/** Delete an object via the binding (best-effort cleanup of staging objects). */
export async function deleteObject(env: Env, objectId: string): Promise<void> {
  await env.DROP_BUCKET.delete(objectId);
}

// FileKey container header layout — mirrors web/core/src/constants.ts (§3, §5). Keep in sync.
const FK_VERSION = 0x01; // FORMAT_VERSION
const FK_SUITE = 0x01; // SUITE_ID
const FK_META_LEN_OFFSET = 12 + 65 + 65; // HEADER_LEN(12) + PK_LEN(65) + ENC_LEN(65) = 142; u32be metadata length follows
const FK_META_CT_MIN = 17; // 1-byte metadata version + 16-byte tag
const FK_META_CT_MAX = 1_048_592; // 1 MiB + 16-byte tag
const FK_GCM_TAG = 16; // a payload chunk's GCM tag — even a 0-byte file has one chunk
const FK_MIN_PREFIX = FK_META_LEN_OFFSET + 4; // 146: smallest prefix we read + validate

/**
 * Length of the head + metadata-ciphertext prefix (FK_META_LEN_OFFSET + 4 + metaLen) of a FileKey
 * container, parsed from its first bytes (must be >= FK_MIN_PREFIX). Validates magic + format version +
 * suite id + a sane metadata-length field; returns null if any check fails. The download preview uses
 * this to serve EXACTLY the metadata and never any payload (a fixed prefix would leak the start of the
 * payload for files with small metadata).
 */
export function fileKeyMetadataPrefixLen(head: Uint8Array): number | null {
  if (head.length < FK_MIN_PREFIX) return null; // too small to be a real FileKey ciphertext
  if (!FILEKEY_MAGIC.every((b, i) => head[i] === b)) return null;
  if (head[4] !== FK_VERSION || head[5] !== FK_SUITE) return null;
  const metaLen = ((head[FK_META_LEN_OFFSET]! << 24) | (head[FK_META_LEN_OFFSET + 1]! << 16) | (head[FK_META_LEN_OFFSET + 2]! << 8) | head[FK_META_LEN_OFFSET + 3]!) >>> 0;
  if (metaLen < FK_META_CT_MIN || metaLen > FK_META_CT_MAX) return null;
  return FK_META_LEN_OFFSET + 4 + metaLen;
}

/**
 * Validate the FileKey container's fixed (unencrypted) header via a ranged GET of the first ~146
 * bytes — not just the 4-byte magic: magic + format version + suite id + a sane metadata-length
 * field, and (using the known object size) that the object is actually large enough to contain that
 * metadata plus a payload tag. This is the server's only structural gate (it can't authenticate the
 * E2E ciphertext), so it stays strict on what it CAN check; it's what stops Drop being an open mailer.
 */
export async function validateFileKeyHeader(env: Env, objectId: string, totalSize: number): Promise<boolean> {
  const obj = await env.DROP_BUCKET.get(objectId, { range: { offset: 0, length: FK_MIN_PREFIX } });
  if (!obj) return false;
  const prefixLen = fileKeyMetadataPrefixLen(new Uint8Array(await obj.arrayBuffer()));
  if (prefixLen === null) return false;
  // The object must actually hold the declared metadata + at least one payload chunk tag — rejects
  // header-shaped-but-truncated junk that passes the field checks.
  return totalSize >= prefixLen + FK_GCM_TAG;
}

// ---- Multipart (large uploads) -----------------------------------------------
// Parts upload browser->R2 via presigned UploadPart URLs (bytes never transit the
// Worker). The Worker only starts, completes, and aborts the upload. Create/
// complete/abort go through the R2 *binding* so the in-memory dev/test double can
// model them; only the per-part PUT is presigned. NOTE: pairing a binding-created
// uploadId with S3-presigned UploadPart + binding complete() relies on R2's
// binding<->S3 multipart interop — verified by scripts/smoke-multipart against
// real R2 before we depend on it. If that ever breaks, swap these three to the S3
// XML API; callers (handlers.ts) don't change.

/** Start a multipart upload; returns the R2 uploadId. */
export async function createMultipart(env: Env, objectId: string): Promise<string> {
  const mpu = await env.DROP_BUCKET.createMultipartUpload(objectId);
  return mpu.uploadId;
}

/** Presign one UploadPart URL (the browser PUTs the part body straight to R2). */
export async function presignUploadPart(env: Env, objectId: string, uploadId: string, partNumber: number, expiresSec: number): Promise<string> {
  const url = `${objectUrl(env, objectId)}?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}&X-Amz-Expires=${expiresSec}`;
  const signed = await client(env).sign(url, { method: "PUT", aws: { signQuery: true } });
  return signed.url;
}

/** Assemble the object from its parts. Returns false if R2 rejects the set. */
export async function completeMultipart(
  env: Env,
  objectId: string,
  uploadId: string,
  parts: { partNumber: number; etag: string }[],
): Promise<boolean> {
  try {
    const mpu = env.DROP_BUCKET.resumeMultipartUpload(objectId, uploadId);
    await mpu.complete(parts.map((p) => ({ partNumber: p.partNumber, etag: normalizeEtag(p.etag) })));
    return true;
  } catch {
    return false;
  }
}

/** Discard an in-progress multipart upload (cancel / cleanup). Best-effort. */
export async function abortMultipart(env: Env, objectId: string, uploadId: string): Promise<void> {
  try {
    await env.DROP_BUCKET.resumeMultipartUpload(objectId, uploadId).abort();
  } catch {
    /* already gone / never existed */
  }
}

// R2's S3 UploadPart returns a quoted ETag (e.g. `"<md5>"`); the binding's
// complete() wants the raw value. Strip surrounding quotes defensively.
const normalizeEtag = (e: string): string => e.trim().replace(/^"+|"+$/g, "");
