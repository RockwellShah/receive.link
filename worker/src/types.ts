// Worker environment bindings. R2Bucket / KVNamespace / ExportedHandler come
// from @cloudflare/workers-types.
import type { CompletionGuard } from "./completion";

/** Minimal shape of the Cloudflare `send_email` Worker binding. */
export interface SendEmailBinding {
  send(message: {
    to: string;
    from: string;
    subject: string;
    text?: string;
    html?: string;
  }): Promise<{ messageId: string }>;
}

export interface Env {
  // Bindings
  EMAIL: SendEmailBinding; // [[send_email]] name = "EMAIL"
  DROP_BUCKET: R2Bucket; // ciphertext relay (lifecycle TTL ~7 days)
  DROP_KV: KVNamespace; // confirm-nonce store + rate-limit counters
  COMPLETION: DurableObjectNamespace<CompletionGuard>; // atomic per-object completion guard (exactly-once delivery)

  // Secrets (wrangler secret put) — never in wrangler.toml
  SERVER_KEM_PRIVATE_JWK: string; // unseal recipient emails (HPKE)
  SERVER_SIGN_PRIVATE_JWK: string; // sign Drop links at /confirm (ECDSA)
  R2_ACCESS_KEY_ID: string; // R2 S3 API token — presign uploads/downloads
  R2_SECRET_ACCESS_KEY: string;
  HASH_SECRET: string; // HMAC key for rate-limit digests of email/IP (so low-entropy inputs can't be brute-forced)

  // Vars (public, in wrangler.toml)
  SERVER_SIGN_PUBLIC_JWK: string; // verify Drop links on upload (public half)
  SERVER_SIGN_KEY_ID?: string; // id (0..255) of the current signing key, stamped into minted links (default 1)
  SERVER_SIGN_PUBLIC_JWK_PREV?: string; // optional previous signing key, kept to verify links minted before a rotation
  SERVER_SIGN_KEY_ID_PREV?: string; // id of the previous signing key (pairs with _PREV)
  ALLOWED_ORIGIN: string; // comma-separated CORS allowlist; first entry is the canonical link/email base
  MAIL_FROM: string; // e.g. "files@send.filekey.app"
  R2_ACCOUNT_ID: string; // <id>.r2.cloudflarestorage.com
  R2_BUCKET: string; // bucket name for S3 presigning
  MAX_UPLOAD_BYTES?: string; // optional cap override (default 2 GiB)
  MULTIPART_THRESHOLD?: string; // optional: ciphertext bytes above which multipart kicks in
  MULTIPART_MIN_PART?: string; // optional: minimum part size (R2 needs >=5 MiB for non-last parts)
  REG_IP_PER_DAY?: string; // optional per-day abuse-cap overrides (staging runs these high)
  REG_EMAIL_PER_DAY?: string;
  UPLOAD_BYTES_PER_LINK_DAY?: string; // optional daily byte budget per link (default 5x the per-file cap)
  UPLOAD_BYTES_PER_IP_DAY?: string; // optional daily byte budget per IP (default 10x the per-file cap)
}
