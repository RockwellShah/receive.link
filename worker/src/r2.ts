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
 * Read just the first bytes via a ranged GET and confirm the FileKey magic.
 * This is what stops Drop being used as an open mailer for arbitrary bytes,
 * even though the upload itself went straight to R2.
 */
export async function hasFileKeyMagic(env: Env, objectId: string): Promise<boolean> {
  const obj = await env.DROP_BUCKET.get(objectId, { range: { offset: 0, length: FILEKEY_MAGIC.length } });
  if (!obj) return false;
  const head = new Uint8Array(await obj.arrayBuffer());
  return head.length >= FILEKEY_MAGIC.length && FILEKEY_MAGIC.every((b, i) => head[i] === b);
}
