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
  DROP_KV: KVNamespace; // single-use confirm-token nonces + rate-limit counters

  // Secrets (wrangler secret put) — never in wrangler.toml
  SERVER_KEM_PRIVATE_JWK: string; // unseal recipient emails
  SERVER_SIGN_PRIVATE_JWK: string; // sign Drop links at /confirm
  CONFIRM_HMAC_KEY: string; // base64; mints/verifies one-time email-confirm tokens

  // Vars (public, in wrangler.toml)
  SERVER_SIGN_PUBLIC_JWK: string; // verify Drop links on upload (public half)
  ALLOWED_ORIGIN: string; // CORS allowlist for the Drop web client
  MAIL_FROM: string; // e.g. "files@send.filekey.app"
}
