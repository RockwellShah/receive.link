// Worker environment bindings. R2Bucket / KVNamespace / ExportedHandler come
// from @cloudflare/workers-types.

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
  DROP_KV: KVNamespace; // confirm-nonce store + rate-limit counters + idempotency flags

  // Secrets (wrangler secret put) — never in wrangler.toml
  SERVER_KEM_PRIVATE_JWK: string; // unseal recipient emails (HPKE)
  SERVER_SIGN_PRIVATE_JWK: string; // sign Drop links at /confirm (ECDSA)
  R2_ACCESS_KEY_ID: string; // R2 S3 API token — presign uploads/downloads
  R2_SECRET_ACCESS_KEY: string;

  // Vars (public, in wrangler.toml)
  SERVER_SIGN_PUBLIC_JWK: string; // verify Drop links on upload (public half)
  ALLOWED_ORIGIN: string; // the Drop web client origin (CORS + link/email base)
  MAIL_FROM: string; // e.g. "files@send.filekey.app"
  R2_ACCOUNT_ID: string; // <id>.r2.cloudflarestorage.com
  R2_BUCKET: string; // bucket name for S3 presigning
  MAX_UPLOAD_BYTES?: string; // optional cap override (default 2 GiB)
  REG_IP_PER_DAY?: string; // optional per-day abuse-cap overrides (staging runs these high)
  REG_EMAIL_PER_DAY?: string;
}
