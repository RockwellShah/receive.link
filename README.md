# receive.link

> **receive.link** is the name, brand, and domain. Some internal code identifiers
> (e.g. `DropLink`, `DropApi`) and the vendored `web/core` still carry the older `FileKey` name.

Give anyone a link. Whatever files they drop through it arrive **end-to-end encrypted to your passkey**, with a download link in your email. Think "email attachments, but the relay can't read them."

Files are encrypted in the sender's browser and uploaded straight to object storage. A small Cloudflare Worker only coordinates: it verifies a signed link, hands out short-lived upload/download URLs, and sends the email. **It never sees your files and never holds a key.**

- **How it works** (architecture, what the server can and cannot see, the tradeoff): [HOW-IT-WORKS.md](HOW-IT-WORKS.md)
- **Set it up, run it, tests, conventions:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Status

Working end-to-end on **staging** (`drop-staging.filekey.app`): register, confirm, upload (single PUT and S3 multipart, up to ~5 TB), email delivery, receive, decrypt. Hardened across three rounds of adversarial review. **Not in production yet** (the prod config is still placeholders). 47 tests; typecheck clean on both the worker and the browser client.

## Quick start (local, no secrets needed)

```sh
bun install
bun run dev:mock      # mock server at http://localhost:8080
bun test              # codec + crypto + the full worker protocol + multipart + streaming
bun run typecheck     # worker/shared AND the browser client
```

`dev:mock` (`web/devserver.ts`) runs the **real** Worker handlers over in-memory R2/KV/email fakes and generates throwaway keys, so you can drive the whole flow with no Cloudflare account. Captured emails (the confirm + download links) show up at `http://localhost:8080/__mail`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full dev guide.

## Layout

| Path | What |
|------|------|
| `web/src/` | the browser app: `app.ts` (flows + routing), `api.ts` (Worker client), `webauthn.ts` (passkey/PRF), `config.ts` |
| `web/fk/` | DOM + crypto glue: `ui.ts` (chat UI + save-to-disk), `stream.ts` (streaming encrypt/decrypt), `pool.ts` (concurrent multipart upload), `bundle.ts` |
| `web/core/` | **vendored, read-only** copy of FileKey's crypto core. Do not edit (see `web/fk/README.md`) |
| `shared/` | `codec.ts` (Drop-link wire format, used by both sides), `crypto.ts` (link signatures + email sealing), `util.ts` |
| `worker/src/` | the Cloudflare Worker: `handlers.ts` (endpoints), `completion.ts` (Durable Object), `r2.ts`, `kv.ts`, `email.ts`, `http.ts`, `worker.ts` (router), `testing.ts` (in-memory fakes) |
| `scripts/` | `gen-keys.ts` plus live smoke tests (these need staging keys) |
| `wrangler.toml` | Worker config + bindings. Secrets live in Wrangler, never here |

## Stack

- **Web:** static client on Cloudflare Pages. All crypto runs in the browser.
- **Worker:** Cloudflare Workers + one Durable Object (`CompletionGuard`, for atomic exactly-once delivery).
- **Storage:** R2 (browser-direct via presigned URLs, ~7-day object lifecycle) + KV (one-time nonces, rate-limit counters).
- **Email:** Cloudflare Email Service via the `send_email` binding.
- **Crypto:** WebAuthn PRF derives a passkey-bound identity; HPKE (DHKEM-P256 / HKDF-SHA-256 / AES-256-GCM) seals files and the recipient's email; ECDSA-P256 signs links. Tooling: Bun + TypeScript + esbuild + Wrangler.

## Deploy (owner only)

Deploys need the Cloudflare secrets, which are not in the repo, so contributors develop against the mock server instead. For the owner:

1. `bun run gen:keys` per environment, then `wrangler secret put` every secret in the `wrangler.toml` checklist: the two private keys (`SERVER_SIGN_PRIVATE_JWK`, `SERVER_KEM_PRIVATE_JWK`), the two R2 S3 credentials (`R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`), `HASH_SECRET`, and `RECEIVER_ID_SECRET` (plus the Stripe pair when billing goes live); paste the public values into `wrangler.toml` / the client config.
2. Create the R2 bucket with lifecycle rules (7-day object expiry + abort-incomplete-multipart) and a CORS rule allowing browser-direct PUT/GET; create the KV namespace; DKIM-verify the `MAIL_FROM` sender domain.
3. `bun run deploy` (Worker), then build + publish the client from a CURATED directory. Never `wrangler pages deploy web` directly: Cloudflare Pages ignores `.assetsignore`, so the raw form publishes all TypeScript source to the CDN (with a ~7-day edge cache).

   ```sh
   bun run build:web
   rm -rf /tmp/web-publish && cp -R web /tmp/web-publish
   rm -rf /tmp/web-publish/src /tmp/web-publish/fk /tmp/web-publish/core \
          /tmp/web-publish/*.ts /tmp/web-publish/tsconfig.json \
          /tmp/web-publish/og-card*.html /tmp/web-publish/.assetsignore
   wrangler pages deploy /tmp/web-publish --project-name <pages-project> --branch main
   ```

   Smoke-test staging, then the `--env production` Worker deploy.

Secrets never go in git or `wrangler.toml`. `keys/`, `.dev.vars`, and `.env` are gitignored.
