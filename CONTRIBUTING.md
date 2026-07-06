# Contributing to receive.link

Welcome. This gets you from a clone to a running app and a green test suite, and covers the conventions worth knowing before you change anything.

> Naming: this is **receive.link** (the name, brand, and domain). Some internal identifiers
> (`DropLink`, `DropApi`, the codec) and the vendored `web/core` still use the older `FileKey` name.

## Prerequisites

- **[Bun](https://bun.sh)** is the runtime, test runner, and bundler: `curl -fsSL https://bun.sh/install | bash`.
- That is all you need for local development. A Cloudflare account is only needed to *deploy*, which only the owner does (the deploy secrets are not in the repo).

## Run it locally

```sh
bun install
bun run dev:mock      # http://localhost:8080
```

`dev:mock` (`web/devserver.ts`) is the way to develop. It mounts the **real** Worker request handlers over in-memory fakes for R2, KV, and email, and generates throwaway server keys at startup. So you get the entire flow (register, confirm, upload single and multi-part, receive, decrypt) with no Cloudflare account and no secrets.

- The app is at `http://localhost:8080`.
- Outgoing email is captured, not sent: open **`http://localhost:8080/__mail`** to click the confirmation and download links.
- Passkeys (WebAuthn) work on `localhost` and on `receive.link`, but not on arbitrary hosts (see Gotchas).

Other run targets:
- `bun run dev` runs the real Worker via `wrangler dev` (needs Cloudflare auth + secrets; usually not needed).
- `bun run dev:web` serves the static client only.

## Test, typecheck, build

```sh
bun test              # codec, crypto, the full worker protocol, multipart, streaming
bun run typecheck     # tsc for BOTH the worker/shared (server) and the browser client
bun run build:web     # bundle the client into web/dist/
```

Run `bun test` and `bun run typecheck` before opening a PR. The client and the server are typechecked separately (`web/tsconfig.json` is the browser config, with the DOM lib); `bun run typecheck` runs both.

## Things to know before you change things

- **The end-to-end boundary is the whole point.** File bytes go browser-to-R2 directly through presigned URLs; the Worker never sees plaintext or ciphertext and never holds a decryption key. Any change that routes file bytes through the Worker, or gives it a key, breaks the core guarantee.
- **`web/core/` is vendored and read-only.** It is a copy of FileKey's crypto core; changes belong upstream and get re-vendored. Do not edit it here (see `web/fk/README.md`).
- **`shared/codec.ts` is the wire format.** It encodes the signed Drop link (version 2, carrying a `key_id` for signing-key rotation). The Worker and the client depend on byte-for-byte agreement, so editing it is a breaking change for existing links: bump the version and handle both.
- **The Worker is mostly stateless.** State lives in KV (one-time confirm nonces + soft rate-limit counters) and one Durable Object, `CompletionGuard` (`worker/src/completion.ts`), which makes "deliver the email exactly once" atomic under retries and concurrency.
- **Two upload paths.** Small files take a single presigned PUT; large files use S3 multipart, stream-encrypted into parts and uploaded with bounded concurrency (`web/fk/pool.ts`). Receiving streams ciphertext straight to disk. Nothing buffers a whole file in memory.
- **Tests use in-memory fakes.** `worker/src/testing.ts` provides `MemoryKV` / `MemoryR2` / `CapturingEmail` / `MemoryCompletion`, so handler tests exercise the real logic without Cloudflare.

## Conventions

- **No em dashes** in user-facing copy or docs (house style). Use hyphens or rephrase.
- **Never commit secrets.** Server keys and R2 credentials live in Wrangler secrets; `keys/`, `.dev.vars`, and `.env` are gitignored. The repo contains no secrets; keep it that way.
- **Typecheck both halves.** `bun run typecheck` covers the worker/shared and the browser client; the client is not in the default server tsconfig.

## Workflow

Branch off `main`, push your branch, open a PR, and keep `main` deployable. The owner handles staging and production deploys (they hold the secrets).

## Gotchas (these have cost real time)

- **Passkeys need a registrable domain.** WebAuthn's RP ID is the last two labels of the host, and browsers reject a public-suffix RP ID. Passkeys therefore work on `localhost` and on `receive.link`, but not on a bare `*.pages.dev` or a random host. Develop on `localhost` (the mock server).
- **Drop links are v2.** A link minted by an older v1 build no longer verifies against the current code; re-register to get a fresh one.

## Deploy (owner only, for reference)

Contributors do not need any of this; the mock server covers local development. Deploys need the Cloudflare and Stripe secrets, which are never in the repo.

1. **Secrets.** `bun run gen:keys` per environment, then `wrangler secret put` every name in the `wrangler.toml` checklist: `SERVER_SIGN_PRIVATE_JWK`, `SERVER_KEM_PRIVATE_JWK`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `HASH_SECRET`, `RECEIVER_ID_SECRET`, and (billing) `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET`. Paste the public keys into `wrangler.toml` and the client config. When pasting a secret, the NAME stays literal; only the value goes at wrangler's "Enter a secret value:" prompt. After setting a key secret, verify it semantically (mint a real session and check what comes back), not just by name.

2. **Resources.** Create the R2 bucket with two lifecycle rules (7-day object expiry, and abort-incomplete-multipart at 8 days, which must stay at or above the worker's `MULTIPART_TTL_SEC`) and a CORS rule allowing browser-direct PUT/GET from the site origin. Create the KV namespace. DKIM-verify the `MAIL_FROM` sender domain. Register the Stripe webhook (event `checkout.session.completed`, payload style Snapshot) at the WORKER url `/billing/webhook`, never the Pages domain.

3. **Worker.** `bun run deploy` (staging) or `bun run deploy --env production`. If the config declares any `routes`, keep `workers_dev = true` or the deploy silently drops the workers.dev trigger the web client calls.

4. **Web.** Build, then publish a CURATED directory. Never `wrangler pages deploy web` directly: Pages ignores `.assetsignore`, so the raw form publishes all TypeScript source to the CDN with a ~7-day edge cache.

   ```sh
   bun run build:web
   rm -rf /tmp/web-publish && cp -R web /tmp/web-publish
   rm -rf /tmp/web-publish/src /tmp/web-publish/fk /tmp/web-publish/core \
          /tmp/web-publish/*.ts /tmp/web-publish/tsconfig.json \
          /tmp/web-publish/og-card*.html /tmp/web-publish/.assetsignore \
          /tmp/web-publish/app.html /tmp/web-publish/dist/app.js
   wrangler pages deploy /tmp/web-publish --project-name <pages-project> --branch main
   ```

5. **Verify.** Smoke-test staging (`scripts/` has live smoke tests; `e2e/run.mjs` drives the real site with a virtual passkey), then repeat for production.
