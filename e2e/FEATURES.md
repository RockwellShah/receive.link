# receive.link — Feature & Test Catalog

Single source of truth for **every** feature: its user story, expected behaviour (pinned to code),
and test status. Built from a full code audit (2026-06-24). **Update the Status column as tests land.**

## Legend

**Test type** — how a feature is verified:
- `unit` — Bun test, no browser (`bun test` from repo root). Crypto, codec, wire.
- `worker` — Worker API / integration test (`worker/src/*.test.ts`).
- `e2e` — Playwright browser cell: CDP virtual authenticator + the B1 inbox, against `staging.receive.link` (`e2e/run.mjs`).
- `manual` — visual/design or platform behaviour not worth automating; checked by eye / `/design-review`.

**Status** — `✅ passing` · `🟡 exists, re-verify` · `🚧 todo` · `👁 manual-only` · `⛔ blocked`

## How to run

- Unit + worker: `bun test` (repo root)
- E2E: `cd e2e && npm install && npm test` (needs `e2e/inbox/.token`; drives `staging.receive.link`)

**Baseline (2026-06-24):** `bun test` = **50 pass / 0 fail** across 9 files (crypto, codec, core, worker). E2E round-trip (create→confirm→upload→download→fail-closed) **passes** on staging.

## 🐞 Bugs found by this suite

- **✅ FIXED 2026-06-24 — `/qr` + `/revoke` were prod-blocking.** The suite found it; the other thread fixed
  it by targeting `/result/` (trailing slash) in `_redirects`, so the `200` rewrite no longer 308s. Now
  `curl -sI /qr` → `200` and **the suite is 7/7 green**. History: all three result routes had 308-redirected to
  `/result/` (the rewrite to the `/result` *directory* became a trailing-slash 308), so `home-result.ts`'s
  `location.pathname` dispatch always fell through to `confirmFlow` — `/confirm` worked by luck, `/qr` + `/revoke`
  ran `confirmFlow` on the payload/token → "expired" error. The route discriminator was lost in the redirect.

## Codex review follow-ups (2026-06-24)

Codex reviewed the suite for "false green" risks. **Fixed:** fail-closed now requires the Worker's `410`
(not just any error text — `run.mjs` captures the `/upload-init` status); the inbox worker drops mail not
from the `receive.link` sender so it can't be poisoned (`inbox.ts`). **Deferred:**
- A **wrong-passkey download cell** (S9): a *different* passkey must FAIL to decrypt — proves real E2E
  confidentiality, not just the round-trip. Also assert the uploaded R2 object starts with `FKEY` (≠ plaintext).
- Correlate inbox mail to the run (tag-in-subject / link-id), not just `?since` — for parallel-run isolation.
- Inbox link extraction: decode `=3D`/HTML entities + validate URL shape (today it only un-folds QP soft breaks).
- `pollInbox` KV `list` pagination; the virtual authenticator is **synthetic-path** coverage — real-device
  passkey behaviour (PRF availability, resident persistence, sync) still needs a manual pass.

## Dashboard

| Area | Features | Test type | Status summary |
|------|---------:|-----------|----------------|
| 1. Crypto core | 18 | unit | ✅ baseline green (`crypto`+`codec`+`core` tests in the 50/50 `bun test` run); C12-C18 lack dedicated tests |
| 2. Worker API | 14 | worker + e2e | ✅ baseline green (`handlers`+`http`+`r2`+`web/e2e` tests in the 50/50 run); browser round-trip 🚧 |
| 3. SPA flows | 11 | e2e | 🟢 round-trip 7/7 green (create→confirm→upload→download→qr→revoke→fail-closed); negatives 🚧 |
| 4. Homepage + modal | 12 | e2e + manual | 🚧 todo |
| 5. Result pages | 9 | e2e | 🚧 todo |
| 6. Cross-cutting | 6 | e2e + unit | 🚧 todo |

The **happy-path spine** (build order): `create → confirm → upload → download → revoke → qr`, then the
negative/fail-closed cases. The create→confirm loop is already proven by hand (B1 smoke test).

---

## 1. Crypto core — `web/core/src`, `shared/crypto.ts`, `shared/codec.ts`

All `unit` (deterministic, no browser). Existing: `shared/crypto.test.ts` (7), `shared/codec.test.ts` (18),
`web/core.test.ts` (1 smoke). Goal: confirm they pass and fill the gaps below.

| # | Feature | User story | Expected behaviour (from code) | Status |
|---|---------|-----------|--------------------------------|--------|
| C1 | PRF → identity | As a receiver, my identity comes only from my passkey | `master_prk=HKDF-Extract(prf_secret)`, identity KEM keypair via RFC 9180 DeriveKeyPair; same prf+rpId ⇒ byte-identical `static_pk`. Wrong length ⇒ `FileKeyError`. `identity.ts:24,97` | 🟡 |
| C2 | Namespace tag | As the system, bind identity to one realm | `tag=SHA-256(canonical_rp_id)[0:4]`; in header bytes 8-11, share key, HPKE info. `namespace.ts:47` | 🟡 |
| C3 | Share-key encode/decode | As a sender, paste `fkey1…` to target a receiver | Bech32m(`ver‖tag‖compressed_pk`)=38B; 10 strict decode checks (bech32m-only, version, namespace match, point on-curve/non-identity, length). `sharekey.ts:36,55` | 🟡 |
| C4 | Email seal/unseal | As a receiver, my email is sealed to the server key only | HPKE base (DHKEM-P256/HKDF-SHA256/AES-256-GCM), info `FILEKEY-DROP/email-seal/v1`; `enc(65)‖ct`; unseal throws on tamper/wrong-key/bad-UTF8. `crypto.ts:59` | 🟡 |
| C5 | File encrypt to share key | As a sender, encrypt so only the receiver opens it | HPKE **auth** mode (sender-signed); header `FKEY`+ver+suite; 64 KiB chunks, per-chunk `AES-256-GCM`, counter nonce; AAD binds header+pks+enc. `cipher.ts:88` | 🟡 |
| C6 | File decrypt + auth | As a receiver, only my passkey opens it, and tamper fails closed | HPKE auth SetupR proves sender; per-chunk auth; release only after **all** chunks pass; `decryptedBytes==originalSize` or throw (truncation). `cipher.ts:248,373` | 🟡 |
| C7 | Link signature | As the server, sign links; anyone can verify, tamper rejected | ECDSA P-256 raw `r‖s` (64B); `verifyRegion` over exact bytes; key-id byte enables rotation (current+prev). `crypto.ts:35` | 🟡 |
| C8 | Drop-link codec | As the system, one canonical link framing | `ver‖keyId‖linkId(8)‖shareKey‖label(≤64B UTF8)‖sealedEmail(≤1024)‖sig(64)`; strict bounds, reject trailing bytes / bad version / truncation. `codec.ts:26` | 🟡 |
| C9 | Namespace validation + collision | As the system, reject bad RP-IDs and tag collisions | RP-ID 1-253B `[a-z0-9.-]`, label rules; `NamespaceSet` throws on same-tag/different-rpId. `namespace.ts:18` | 🟡 |
| C10 | File header fail-closed | As the system, unknown formats never run | magic `FKEY`, version `0x01`, suite `0x01`, flags/reserved **must be 0x00** (reject, not ignore). `wire.ts:14` | 🟡 |
| C11 | Metadata encode/validate | As a receiver, malicious metadata can't hurt me | 8 rules: ≤1 MiB, version, filename (no `/ \ .. .`, no control/edge-space), MIME, sizes ≤ MAX_SAFE_INT, ≤256 unique extras, no trailing. `metadata.ts:37` | 🟡 |
| C12 | Chunk nonce uniqueness | As the system, never reuse an AES-GCM nonce | `I2OSP(index,11)‖(0x00|0x01 last)`; deterministic; `index≥2^32`⇒`chunk_overflow`. `wire.ts:60` | 🚧 |
| C13 | PRF input salt | As a receiver, my passkey always derives the same secret | `PRF_INPUT_SALT=SHA-256("FILEKEY-v1/prf-input/identity")`, constant. `identity.ts:20` | 🚧 |
| C14 | Identity fingerprint | As a receiver, verify keys out-of-band | 6 BIP39 words + 4-byte hex from `SHA-256("…/fingerprint"‖pk)`; deterministic. `identity.ts:134` | 🚧 |
| C15 | Recovery codes | As a receiver, back up my identity | BIP39-24 (master_prk) + Bech32m `fkeyrec1…` (ver‖tag‖prk); namespace-bound; strict decode. `recovery.ts:14` | 🚧 |
| C16 | Constant-time compare | As the system, no timing leak on key compare | `equalCT` OR-accumulates XOR; length early-exit only. `bytes.ts:50` | 🚧 |
| C17 | Non-extractable private key | As the browser, JS can't exfiltrate the key | private key imported `extractable:false`; `exportKey` throws; HPKE still works. `identity.ts:77` | 🚧 |
| C18 | Private-scalar scrubbing | As the browser, wipe key material after use | `fill(0)` on ikm/dkpPrk/scalar (best-effort, documented). `identity.ts:84` | 🚧 |

---

## 2. Worker API — `worker/src` (`handlers.ts`, `http.ts`, `email.ts`, `completion.ts`)

`worker` = direct API test; `e2e` = exercised by the browser round-trip. Existing: `handlers.test.ts`,
`http.test.ts`, `r2.test.ts`.

| # | Endpoint / guard | User story | Expected behaviour (from code) | Status |
|---|------------------|-----------|--------------------------------|--------|
| W1 | `POST /register` | As a receiver, create a link from my sealed email | unseal→validate email; sanitize label; mint linkId; `pending:<nonce>` (1h TTL); send confirm email; **202** (even on rate-limit, no email — anti-enumeration). `handlers.ts:169` | 🟡 |
| W2 | `POST /confirm` | As a receiver, exchange the nonce for my signed link | single-use nonce (delete on read); ECDSA-sign region; mint revoke token (2 KV maps); best-effort durable email; **200** `{link,revokeToken}`; replay⇒404. `handlers.ts:225` | 🟡 |
| W3 | `POST /upload-init` (single) | As a sender, start a small upload | size≤threshold ⇒ one presigned PUT; `upload:<id>`(1h). `handlers.ts:288` | 🟡 |
| W4 | `POST /upload-init` (multipart) | As a sender, start a large upload | size>threshold ⇒ MPU, partSize clamp 16 MiB–1 GiB, ≤10k parts, presign first 100; `upload:<id>`(7d). 413/410/429 gates. `handlers.ts:328` | 🟡 |
| W5 | `POST /upload-parts` | As a sender, refresh presigned part URLs mid-upload | verify link+binding+mp, clamp ≤100, `from>partCount`⇒`[]`; mismatch⇒400, revoked⇒410. `handlers.ts:352` | 🚧 |
| W6 | `POST /upload-abort` | As a sender, cancel and free R2 | abort MPU + delete binding; idempotent (always 200). `handlers.ts:384` | 🚧 |
| W7 | `POST /upload-complete` | As a sender, finalize so the receiver is emailed | guard peek/claim (exactly-once); assemble MPU; copy to immutable final; **FileKey header validate** (422); byte budgets; delivery email; finish. Idempotent (`already:true`); concurrent⇒409. `handlers.ts:413` | 🟡 |
| W8 | `GET /fetch/:id` | As a receiver, get a presigned download URL | hex id; object exists; presigned GET (1h); 404 expired/gone. `handlers.ts:561` | 🚧 |
| W9 | `POST /revoke` | As a receiver, turn the link off | hex token; `revtok:`→linkId; set `revoked:<link>`; idempotent 200; bad/unknown⇒400/404; 60/day/IP. `handlers.ts:267` | 🟡 |
| W10 | `GET /healthz` | As an operator, check liveness | `200 {ok,service}`. `workers.ts:37` | 🚧 |
| W11 | CORS preflight + forbidden cross-origin | As an operator, block blind cross-site POSTs | OPTIONS⇒204 echo-if-allowed; POST with present, non-allowlisted Origin⇒**403**; no-Origin allowed. `workers.ts:31` | 🟡 |
| W12 | Rate limits (IP/email/link/bytes) | As an operator, dampen abuse | KV fixed-window; IPs hashed; emails canonicalized; REG 20/IP 5/email, UPLOAD 25/link 100/IP, REVOKE 60/IP; byte budgets at complete. `kv.ts:18` | 🚧 |
| W13 | KV TTLs + R2 lifecycle | As an operator, state self-expires | nonce 1h, single-PUT 1h, MPU 7d, rl windows 2×; revoke maps permanent; R2 ~7d. `handlers.ts:219` | 🚧 |
| W14 | Completion Guard (DO) | As a receiver, exactly one delivery email | fresh/running/done; fencing token; `heldBy` re-check before email; stale reclaim >5min; alarm cleanup 7d. `completion.ts` | 🚧 |

---

## 3. SPA flows — `web/src/app.ts` (+ `webauthn.ts`, `api.ts`, `config.ts`). All `e2e`.

| # | Mode / flow | User story | Expected behaviour (from code) | Status |
|---|-------------|-----------|--------------------------------|--------|
| S1 | Setup: enroll (first) | As a new receiver, create a passkey + link | email regex; `enrollPasskey` (resident+UV+PRF required); pin `rl_passkey`/`rl_cred`; seal+register; "Check your email". `app.ts:82` | 🚧 |
| S2 | Setup: assert (returning) | As a returning receiver, reuse my passkey | `rl_cred`⇒no-picker assertion; PRF→identity; zero PRF in `finally`. `app.ts:125` | 🚧 |
| S3 | Setup: deleted-passkey recovery | As a receiver who lost a passkey, recover | get() fails ⇒ recovery panel "Try again / Create new"; new ⇒ `forceEnroll` clears pins, fresh identity. `app.ts:138` | 🚧 |
| S4 | Confirm reveal | As a receiver, get my shareable link | `api.confirm(nonce)`⇒link+revokeToken; `linkReveal` (copy/share/QR); revoke link shown. `app.ts:167` | 🚧 |
| S5 | Upload: link verify | As a sender, only a valid link accepts files | `splitSignature`+`verifyRegion`; tampered⇒"isn't valid"; label extracted. `app.ts:187` | 🚧 |
| S6 | Upload: single | As a sender, send a small file | throwaway identity; `encryptFileToShareKey`→R2 PUT→complete; "Sent!". `app.ts:229` | 🚧 |
| S7 | Upload: multipart + cancel | As a sender, send a large file, cancel if needed | part pool (RAM-budgeted), retry+backoff, progress, AbortController, abort frees R2. `app.ts:283` | 🚧 |
| S8 | Receive: gate + decrypt | As a receiver, download only with my passkey | HTTPS+WebAuthn+PRF gate; metadata Range (1.2 MiB); stream-decrypt to disk; **bytes match** original. `app.ts:405` | 🚧 |
| S9 | Receive: wrong passkey fail-closed | As a receiver, the wrong key can't open it | re-enrolled/other identity ⇒ `openCiphertext` `auth_failed/wrong_namespace`⇒"encrypted for a different passkey". `app.ts:44` | 🚧 |
| S10 | Revoke | As a receiver, stop new uploads | `/revoke#token` confirm panel; `api.revoke`; revoked link upload⇒410. `app.ts:455` | 🚧 |
| S11 | QR | As a receiver, show my link as a QR | verify payload; `encodeQR` SVG; fallback to link on failure. `app.ts:484` | 🚧 |

---

## 4. Homepage + create modal — `web/home/index.html`, `web/src/home-create.ts`

`e2e` for behaviour; `manual` for pure visual. (Visual/animation/a11y/responsive details — sticky nav,
shadows, Spectral/Nunito self-hosted fonts, modal/spinner animation, ARIA dialog, mobile breakpoints —
tracked as one `👁 manual` line; verify via `/design-review`, not automated.)

| # | Feature | User story | Expected behaviour (from code) | Status |
|---|---------|-----------|--------------------------------|--------|
| H1 | CTA opens modal | As a visitor, click "Create your link" | every `[data-create]` opens `#cmodal`, focuses email, `loadRl()` preloads bundle, body scroll-lock. `index.html:438` | 🚧 |
| H2 | Modal lifecycle / close | As a visitor, dismiss the modal | X / backdrop / Escape ⇒ close, reset form, re-enable button. `index.html:438` | 🚧 |
| H3 | Form validation | As a visitor, bad email is caught client-side | regex `^[^@\s]+@[^@\s]+\.[^@\s]+$`; invalid ⇒ red border, no submit; label optional (maxlength 60). `index.html:465` | 🚧 |
| H4 | Email privacy hint + passkey badge | As a visitor, understand the model before committing | "We'll email you… Senders never see your address…"; "Face ID or a fingerprint. No password…". `index.html:387,391` | 🚧 |
| H5 | Working state | As a visitor, see progress during passkey | `data-state=working` spinner + "Confirm with your passkey". `home-create.ts cb.working` | 🚧 |
| H6 | Sent state | As a visitor, know the email was sent | `data-state=sent`, interpolates my address, "Check your email" + spam note. `cb.sent` | 🚧 |
| H7 | Error state + Try again | As a visitor, recover from a failure | humanized message (rate-limit/passkey/config); `data-retry`⇒back to form, button re-enabled. `home-create.ts:35` | 🚧 |
| H8 | Recovery state (deleted passkey) | As a returning visitor, recover a lost passkey | `cb.recovery()` only when `!firstPasskey && isPasskeyError`; "Try again" vs "Create a new passkey" (`forceEnroll`). `home-create.ts:108` | 🚧 |
| H9 | Lazy-load crypto bundle | As a visitor, a light homepage | `home-create.js` (~620 KB) dynamic-imported on CTA, not on load; failure⇒"Couldn't load the secure module". `index.html:456` | 🚧 |
| H10 | rlCreate stub fallback | As a visitor, no silent dead-modal if the bundle 404s | inline stub vs real `window.rlCreate`; the catch-all-redirect bug (now fixed) is exactly this hazard. | 🚧 |
| H11 | `*.pages.dev` guard | As a tester on a preview, get a clear message | `hostname.endsWith(".pages.dev")`⇒`cb.error("Passkeys need a real domain…")`. `home-create.ts:74` | 🚧 |
| H12 | Nav: menu, Contact, sticky / SEO | As a visitor, navigate and share | 3-dot menu (How/Pricing/FAQ/Contact mailto), Escape/outside-close; OG/Twitter/canonical; `noindex` (drop at prod cutover). + 👁 visual | 🚧 / 👁 |

---

## 5. Result pages — `web/src/home-result.ts`, `web/result/index.html` (serves `/confirm`,`/revoke`,`/qr`). All `e2e`.

| # | Feature | User story | Expected behaviour (from code) | Status |
|---|---------|-----------|--------------------------------|--------|
| R1 | Pathname routing | As a receiver, one bundle backs 3 routes | `_redirects` 200-rewrites `/confirm`,`/revoke`,`/qr`→`/result`; `home-result.ts` dispatches on `location.pathname`. `home-result.ts:150` | 🚧 |
| R2 | Confirm reveal | As a receiver, see my link after the email click | `api.confirm`→render `origin/#link`; "Your link is ready"; revoke link shown. `home-result.ts:92` | 🚧 |
| R3 | Copy link | As a receiver, copy my link | `clipboard.writeText`; "Copied!" 2s; silent-fail if blocked. `home-result.ts:57` | 🚧 |
| R4 | Native share | As a receiver on mobile, share via OS sheet | `navigator.share` if present, else hide button. `home-result.ts:65` | 🚧 |
| R5 | QR generate + toggle | As a receiver, show a scannable QR | `encodeQR(svg, ecc:medium, border:2)`; Show/Hide; hidden on `/confirm`, open on `/qr`; failure⇒hide, copy still works. `home-result.ts:71` | 🚧 |
| R6 | Revoke confirm → loading → done | As a receiver, turn off my link safely | confirm panel; "Keep it"→`/`; "Turn it off"→`api.revoke`→done; double-click guard; error⇒back to confirm. `home-result.ts:130` | 🚧 |
| R7 | QR signature verify | As a receiver, a forged `/qr` is rejected | `splitSignature`+`verifyRegion`; invalid⇒"This link isn't valid". `home-result.ts:110` | 🚧 |
| R8 | QR reveal (read-only) | As a receiver via QR, no revoke control | reveal without revokeUrl; "Your link"; QR open by default. `home-result.ts:122` | 🚧 |
| R9 | Error + humanError + loading | As a receiver, friendly failures | `showError` panel + "Back to receive.link"; messages mirror `app.ts` (revoked/expired/rate-limit/bad-sig); loading spinner per flow. `home-result.ts:24,39` | 🚧 |

---

## 6. Cross-cutting

| # | Concern | User story | Expected behaviour (from code) | Test | Status |
|---|---------|-----------|--------------------------------|------|--------|
| X1 | Error taxonomy (`humanError`) | As a user, errors are legible not cryptic | maps DropApiError/DOMException → friendly copy; same intent in `app.ts` + `home-result.ts`. | unit/e2e | 🚧 |
| X2 | Passkey pinning (`rl_passkey`/`rl_cred`) | As a returning user, no passkey picker | pin on enroll; targeted assert; self-heal on open prompt; private-mode safe (try/catch). | e2e | 🚧 |
| X3 | Identity continuity / break | As a receiver, same passkey ⇒ same identity; new passkey ⇒ new | deterministic PRF→identity; deleted+re-enrolled ⇒ old files won't open (by design). | e2e | 🚧 |
| X4 | Config loading | As the app, load keys per host | `dropConfig` by hostname (prod/staging/localhost); `isConfigured`; dev fetches `/api/__config`. | e2e | 🚧 |
| X5 | Storage / private mode | As a user, private browsing doesn't crash | every `localStorage` access try/caught; degrades to re-enroll/open-prompt. | e2e | 🚧 |
| X6 | Fail-closed invariants (whole pipeline) | As a user, anything wrong fails safe (no plaintext leak) | unknown header/flags reject; truncation detected; wrong key ⇒ no output card; revoked ⇒ upload blocked. | unit+e2e | 🚧 |

---

## E2E cell build order (run.mjs)

1. ✅ **`create`** (S1/H1-H6) — virtual authenticator enroll + register → "Check your email". *(automated + passing)*
2. ✅ **`confirm`** (S4/R2) — poll inbox → open `/confirm#` → share link revealed. *(automated + passing)*
3. ✅ **`upload`** (S5/S6) — sender drops a file → encrypt → R2 → "Sent!". *(passing)*
4. ✅ **`download`** (S8) — `/d/<id>` → assertion → decrypt → **bytes match** the sent file. *(passing)*
5. ✅ **`revoke: re-upload fails closed`** (S10) — revoke via Worker API → re-upload rejected. *(passing — security)*
6. ✅ **`qr` + `revoke` UI** (R5-R8) — the `/result` routing bug was fixed (trailing-slash `/result/` target); both pass.
7. 🚧 **negatives** — S3/S9/H8 (recovery, wrong passkey), W11 (cross-origin), C-series fail-closed.

Gate (`EXPECTED_CRITICAL`): every critical cell must **run and pass** — a missing cell counts as fail.
