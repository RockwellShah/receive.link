# FileKey Drop

Give anyone a link. Whatever they drop arrives end-to-end encrypted to your passkey, in your email inbox. *Email attachments, but the server can't read them.*

Part of the FileKey family: **Vault** (the local/offline app), **Drop** (this — inbound file requests), **Send** (outbound links, later). One identity, one crypto core.

> Status: **scaffold (Phase 0)**. Local-only repo, no remote, until built and security-reviewed. This is a different product from FileKey with a server component, so it lives in its own repo.

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
worker/src/worker.ts   request router; parse+verify wired, handlers stubbed (Phase 1)
worker/src/types.ts    Worker env bindings (EMAIL, R2, KV, secrets)
scripts/gen-keys.ts    generate per-env server keys (KEM + signing + confirm HMAC)
wrangler.toml          send_email + R2 + KV bindings (fill REPLACE_ME at deploy)
```

## Develop

```sh
bun install
bun test          # codec + crypto round-trips (20 tests)
bun run typecheck
```

## Stack

- **Email:** Cloudflare Email Service via the `send_email` Worker binding (`env.EMAIL.send`). One vendor for R2 + Worker + Email + DNS. Beta as of 2026-05; kept behind a single swappable call.
- **Relay:** Cloudflare R2 (zero egress), 7-day object lifecycle.
- **Crypto:** WebCrypto ECDSA P-256 (link signatures) + `@hpke/core` HPKE base mode, DHKEM-P256 + HKDF-SHA-256 + AES-256-GCM (email sealing). Same suite as FileKey's core.

## Deploy (when ready)

1. `bun run gen:keys` once per environment → set the 3 secrets with `wrangler secret put`, paste the 2 public values into `wrangler.toml` / the client. Staging and prod use different keys.
2. Onboard + DKIM-verify the `MAIL_FROM` sender domain (`send.filekey.app`) in the Cloudflare dashboard.
3. Create the R2 bucket + a ~7-day lifecycle rule, and the KV namespace; fill the `REPLACE_ME` ids.
4. `wrangler deploy` (staging) → smoke-test → `wrangler deploy --env production`.

Secrets never go in git or `wrangler.toml`; they live in Wrangler secrets / `.dev.vars` (gitignored).

## Roadmap

- **Phase 1** — implement the four handlers: register → confirm (one-time token) → upload-init (presigned R2 PUT) → upload-complete (unseal + email). Worker unit tests.
- **Phase 2** — Drop web client: setup flow + upload page (vendors a read-only copy of FileKey's DOM-free core; extract a shared `@filekey/core` package before any public push) + `/d/<id>` fetch+decrypt page.
- **Phase 3** — abuse limits (per-link + per-IP), logging policy, threat-model docs page, then the Fable-5 + Codex security review and a staging dogfood before going public.
