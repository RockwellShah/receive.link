# 📥 receive.link

**Receive files only you can open**. Share one link, and everything sent through it arrives end-to-end encrypted to your passkey. No accounts, no subscriptions, no tracking.

> 🛡️ **receive.link is free to try, open-source, and privacy-first.** Live at [receive.link](https://receive.link).

---

### 🚀 Features

- ✅ **One link sharing.** Receive files easily with one link. No app, no accounts.
- ✅ **Only you can open.** Each file is end-to-end encrypted, locked to your passkey in the sender's browser before it uploads.
- ✅ **Supports huge files.** Supports up to 5 terabytes per file.
- ✅ **No Subscriptions.** First 1GB of downloads is free, then a penny per GB after that.
- ✅ **Privacy focused.** We never store your email, IP address, or track you.
- ✅ **Open source.** Licensed under GPLv3.

---

### 👨‍💻 How it works

1. **Create your link**<br>
   Unlock with your passkey, confirm your email once, and you get a permanent link like `receive.link/u#...` to share anywhere: an email signature, a bio, a QR code.

2. **Anyone sends**<br>
   They drop a file through your link. It locks in their browser to your passkey before it uploads. No account, no app.

3. **Only you can open it**<br>
   We email you a secure download link to the file which only your passkey can unlock. No one in between can read it.

---

### 💰 Pricing

Receiving a file costs nothing until you download it. Then it's pay-as-you-go:

| Step | Cost |
|---|---|
| **First 1 GB** | free for every account |
| **After that** | $0.01 per GB you download, prepaid |
| **Re-downloads** | free |
| **Sending** | always free |

Credit never expires, and belongs to you rather than to any one link. Ignored files you don't download expire in 7 days and you're never charged for them.

---

### 💾 Supported systems

Only the **receiver** needs a passkey, and it must come from a provider that supports the WebAuthn **PRF extension**: Apple Passwords, Google Password Manager, 1Password, a YubiKey 5, and similar. Senders just need a modern browser.

| Platform | Passkey providers | Notes |
|----------|-------------------|-------|
| **macOS** | Apple Passwords, 1Password, YubiKey | Safari ≥ 17 or Chrome ≥ 112 |
| **iOS / iPadOS** | Apple Passwords, 1Password | Safari ≥ 17 or Chrome ≥ 112 |
| **Windows** | 1Password, YubiKey | Windows 11 with Edge or Chrome ≥ 112 |
| **Android** | Google Password Manager, 1Password, YubiKey | Chrome ≥ 112 |
| **Linux** | YubiKey (via browser) | Recent Chromium browsers |

Synced passkeys (iCloud Keychain, Google Password Manager) follow you across devices, so the same identity works on your phone and your laptop.

---

### 🛠️ How the encryption works

Your identity is derived, not stored. Authenticating runs your passkey's PRF extension over a fixed input, producing a secret that never leaves your device; HKDF-SHA-256 turns it into a long-term P-256 key pair bound to the `receive.link` namespace. The same passkey always reproduces the same identity, so there is no account record anywhere.

Files are sealed with HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): DHKEM-P256 + HKDF-SHA-256 + AES-256-GCM) in a streaming, chunked construction, so a 5TB file encrypts and decrypts without ever being held in memory. The sender's browser uploads the ciphertext directly to object storage through short-lived presigned URLs; the coordination server never proxies file bytes.

Three independent layers stand between your files and anyone else:

1. **Downloads are proof-gated.** The server seals a one-time challenge to your public key; only your passkey-derived private key can answer it. No proof, no download URL.
2. **Storage is private.** Objects live in a non-public bucket under unguessable ids, reachable only through 5-minute presigned URLs issued after a valid proof.
3. **The content is ciphertext anyway.** Even a leaked object is sealed to your key. The most the server ever learns is a file's size and when it moved.

Your link itself is signed (ECDSA P-256), so a tampered or forged link fails closed. The deeper walkthrough lives at [receive.link/technical](https://receive.link/technical) and in [HOW-IT-WORKS.md](HOW-IT-WORKS.md).

---

### ⚡ Quick start (local, no secrets needed)

The whole stack runs locally against in-memory fakes, no Cloudflare account required:

```sh
bun install
bun run dev:mock      # real Worker handlers over mock R2/KV/email at http://localhost:8080
bun test              # codec + crypto + the full worker protocol + billing + multipart
bun run typecheck     # worker/shared AND the browser client
```

Captured emails (confirm + download links) appear at `http://localhost:8080/__mail`, so you can drive the entire create → send → receive flow on your machine. The full dev guide, test map, and conventions are in [CONTRIBUTING.md](CONTRIBUTING.md).

> Some internal identifiers (`DropLink`, `DropApi`, the vendored `web/core`) predate the receive.link name and carry an older working title. The brand is receive.link; the code is catching up.

---

### 🧱 Under the hood

- **Web:** a static client on Cloudflare Pages. All crypto runs in the browser.
- **Worker:** Cloudflare Workers plus two Durable Objects: `CompletionGuard` (atomic exactly-once delivery) and `ReceiverAccount` (prepaid balance, per-file download charge, capacity).
- **Storage:** R2, browser-direct via presigned URLs (single PUT for small files, S3 multipart delivered in place for large ones), 7-day object lifecycle. KV holds one-time nonces and rate-limit counters.
- **Email:** Cloudflare Email Service via the `send_email` binding.
- **Payments:** Stripe-hosted Checkout. The worker stores no cards and never sends your email to Stripe; payments tie to an account by an opaque id.
- **Testing:** unit tests across the worker protocol and billing engine, plus a browser end-to-end suite that drives the real staging site with a virtual passkey authenticator (`e2e/run.mjs`).

| Path | What |
|------|------|
| `web/src/` | the browser pages: create, send, receive, result, wallet |
| `web/fk/` | crypto + transfer glue: streaming encrypt/decrypt, multipart upload pool, the receive gate |
| `web/core/` | vendored, read-only crypto core (do not edit) |
| `shared/` | the link wire format, signatures, email sealing (used by both sides) |
| `worker/src/` | the Worker: endpoints, Durable Objects, R2/KV/email/Stripe adapters |
| `e2e/` | the browser end-to-end suite + the mail-capture worker it uses |
| `scripts/` | key generation + live smoke tests |

---

### 🚢 Deploy (owner only)

Deploys need Cloudflare and Stripe secrets that are not in the repo, so contributors develop against the mock server. The full runbook (secrets checklist, R2 lifecycle + CORS, the curated-directory Pages publish) is in [CONTRIBUTING.md](CONTRIBUTING.md). The one rule worth repeating: never `wrangler pages deploy web` directly, because Pages ignores `.assetsignore` and would publish TypeScript source; always deploy the curated directory.

---

### 🔗 Links

> 📥 **[receive.link](https://receive.link)**: the app
>
> 🔬 **[receive.link/technical](https://receive.link/technical)**: the cryptography, in detail

---

### 📜 License

[GPL-3.0-or-later](LICENSE). The GPL covers the software; the receive.link name and branding are not licensed for reuse.
