// Worker environment bindings. R2Bucket / KVNamespace / ExportedHandler come
// from @cloudflare/workers-types.
import type { CompletionGuard } from "./completion";
import type { ReceiverAccount } from "./receiver";

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
  RECEIVER: DurableObjectNamespace<ReceiverAccount>; // persistent per-recipient account (inbound metering + capacity cap)

  // Secrets (wrangler secret put) — never in wrangler.toml
  SERVER_KEM_PRIVATE_JWK: string; // unseal recipient emails (HPKE)
  SERVER_SIGN_PRIVATE_JWK: string; // sign Drop links at /confirm (ECDSA)
  R2_ACCESS_KEY_ID: string; // R2 S3 API token — presign uploads/downloads
  R2_SECRET_ACCESS_KEY: string;
  HASH_SECRET: string; // HMAC key for rate-limit digests of email/IP (so low-entropy inputs can't be brute-forced)
  RECEIVER_ID_SECRET: string; // HMAC key deriving a recipient's account id (rid) from their confirmed email — stable + long-lived (rotating it re-keys every account)
  STRIPE_SECRET_KEY?: string; // Stripe API secret (sk_test_… / sk_live_…); unset = billing/checkout 503s (ships inert)
  STRIPE_WEBHOOK_SECRET?: string; // Stripe endpoint signing secret (whsec_…) for verifying webhook signatures
  POSTMARK_SERVER_TOKEN?: string; // Postmark Server API token; required when EMAIL_PROVIDER = "postmark"

  // Vars (public, in wrangler.toml)
  SERVER_SIGN_PUBLIC_JWK: string; // verify Drop links on upload (public half)
  SERVER_SIGN_KEY_ID?: string; // id (0..255) of the current signing key, stamped into minted links (default 1)
  SERVER_SIGN_PUBLIC_JWK_PREV?: string; // optional previous signing key, kept to verify links minted before a rotation
  SERVER_SIGN_KEY_ID_PREV?: string; // id of the previous signing key (pairs with _PREV)
  ALLOWED_ORIGIN: string; // comma-separated CORS allowlist; first entry is the canonical link/email base
  MAIL_FROM: string; // e.g. "files@send.filekey.app"
  EMAIL_PROVIDER?: string; // outbound mail provider: "postmark" routes via the Postmark REST API (needs POSTMARK_SERVER_TOKEN); unset/anything else = the Cloudflare send_email binding. Escape hatch for corporate (M365) deliverability, where Cloudflare's young shared IPs get silently filtered despite perfect SPF/DKIM/DMARC
  R2_ACCOUNT_ID: string; // <id>.r2.cloudflarestorage.com
  R2_BUCKET: string; // bucket name for S3 presigning
  MAX_UPLOAD_BYTES?: string; // optional per-file cap override (default 2 GiB)
  // (No inbound/at-rest cap vars: when billing is on, a receiver's CAPACITY IS their credit balance —
  // un-downloaded bytes at rest can never exceed what they could pay to download. See ReceiverAccount.)
  // Phase 2 billing (download charge). Ships INERT: with BILLING_ENABLED unset, /fetch/download issues a
  // free URL exactly like Phase 1 ("prove then download"), so deploying 2a changes nothing until Stripe
  // (2b) is live and this is flipped on.
  BILLING_ENABLED?: string; // "1"/"true" turns on the per-file download charge; unset/false = downloads free
  FREE_GRANT_BYTES?: string; // free credit seeded into a new account when billing is on (default 1 GB)
  PRICE_CENTS_PER_GB?: string; // price knob: cents per GB of download (default 1 = 1¢/GB, $10 = 1 TB). Tune in the dashboard to walk the price with no code change; fixed $10/$25/$50/$100 tiers derive their GB from it
  MULTIPART_THRESHOLD?: string; // optional: ciphertext bytes above which multipart kicks in
  MULTIPART_MIN_PART?: string; // optional: minimum part size (R2 needs >=5 MiB for non-last parts)
  REG_IP_PER_DAY?: string; // optional per-day abuse-cap overrides (staging runs these high)
  REG_EMAIL_PER_DAY?: string;
  FETCH_IP_PER_DAY?: string; // optional per-day cap on download-gate challenge + prove calls per IP
  UPLOAD_BYTES_PER_LINK_DAY?: string; // optional daily byte budget per link (default 5x the per-file cap)
  UPLOAD_BYTES_PER_IP_DAY?: string; // optional daily byte budget per IP (default 10x the per-file cap)
}
