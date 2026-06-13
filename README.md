# FileKey Drop

Give anyone a link. Whatever they drop arrives end-to-end encrypted to your passkey, in your email inbox. *Email attachments, but the server can't read them.*

Part of the FileKey family: **Vault** (the local/offline app), **Drop** (this — inbound file requests), **Send** (outbound links, later). One identity, one crypto core.

> Status: **Phase 1 complete** — the register → confirm → upload → email protocol is implemented and tested (33 tests). The web client (Phase 2) is next. Local-only repo, no remote, until built and security-reviewed. This is a different product from FileKey with a server component, so it lives in its own repo.

## How it works (always-relay)

1. **Receiver** (passkey holder) does one-time setup: confirms an email, gets a permanent Drop link.
2. **Sender** (anyone, no account) opens the link, drops a file. Their browser encrypts it to the receiver's public key and uploads the **ciphertext** to R2.
3. **Worker** verifies the link's signature, unseals the receiver's email *in memory*, and emails them a download link. Stores no email↔key mapping.
4. **Receiver** clicks the link, fetches the ciphertext, decrypts with their passkey.

The Worker never decrypts and holds no database. The receiver's address lives **sealed inside their own link** (HPKE-sealed to the server key) and is read only for the moment it takes to send the email. The link can't exist for an inbox nobody proved they control (the server signs it only after an email-confirm click).

Full design + threat model + cost/pricing research: `../FileKey v1/HANDOFF-cloud-storage.md` (internal).

## Layout

```
worker/src/codec.ts    Drop-link payload codec (zero-dep; shared with the web client)
worker/src/crypto.ts   ECDSA link signatures + HPKE email sealing (@hpke/core)
worker/src/handlers.ts register / confirm / upload-init / upload-complete / fetch
worker/src/r2.ts       presigned R2 PUT/GET (browser-direct) + FileKey-magic sniff
worker/src/kv.ts       soft rate limiting + nonce/idempotency state
worker/src/email.ts    Cloudflare Email Service wrappers (confirm + delivery mail)
worker/src/worker.ts   request router
worker/src/types.ts    Worker env bindings (EMAIL, R2, KV, secrets)
worker/src/testing.ts  in-memory binding fakes for tests
scripts/gen-keys.ts    generate per-env server keys (KEM + signing)
wrangler.toml          send_email + R2 + KV bindings (fill REPLACE_ME at deploy)
```

## Develop

```sh
bun install
bun test          # codec + crypto + full handler protocol (33 tests)
bun run typecheck
```

## Stack

- **Email:** Cloudflare Email Service via the `send_email` Worker binding (`env.EMAIL.send`). One vendor for R2 + Worker + Email + DNS. Beta as of 2026-05; kept behind a single swappable call.
- **Relay:** Cloudflare R2 (zero egress), 7-day object lifecycle.
- **Crypto:** WebCrypto ECDSA P-256 (link signatures) + `@hpke/core` HPKE base mode, DHKEM-P256 + HKDF-SHA-256 + AES-256-GCM (email sealing). Same suite as FileKey's core.

## Deploy (when ready)

1. `bun run gen:keys` once per environment → set `SERVER_SIGN_PRIVATE_JWK` + `SERVER_KEM_PRIVATE_JWK` with `wrangler secret put`, paste the 2 public values into `wrangler.toml` / the client. Staging and prod use different keys.
2. Create an R2 S3 API token (R2 > Manage API tokens) → set `R2_ACCESS_KEY_ID` + `R2_SECRET_ACCESS_KEY` secrets; fill `R2_ACCOUNT_ID` / `R2_BUCKET` vars.
3. Onboard + DKIM-verify the `MAIL_FROM` sender domain (`send.filekey.app`) in the Cloudflare dashboard.
4. Create the R2 bucket + a ~7-day lifecycle rule, the KV namespace (fill the `REPLACE_ME` ids), and a bucket **CORS** rule allowing PUT/GET from the Drop web origin (browser-direct upload/download).
5. `wrangler deploy` (staging) → smoke-test → `wrangler deploy --env production`.

Secrets never go in git or `wrangler.toml`; they live in Wrangler secrets / `.dev.vars` (gitignored). Four secrets total: two server keys (from gen-keys) + two R2 S3 credentials.

## Roadmap

- **Phase 1 (done)** — the four handlers: register → confirm (one-time nonce) → upload-init (presigned R2 PUT) → upload-complete (FileKey-magic check + unseal + email), plus `/fetch/:id`. Soft abuse limits + idempotency. 33 tests.
- **Phase 2** — Drop web client: setup flow + upload page (vendors a read-only copy of FileKey's DOM-free core; extract a shared `@filekey/core` package before any public push) + `/d/<id>` fetch+decrypt page.
- **Phase 3** — tune abuse limits, logging policy, threat-model docs page, then the Fable-5 + Codex security review and a staging dogfood before going public. Verify browser-direct R2 PUT/GET + CORS on live R2.
