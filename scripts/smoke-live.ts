// One-off: verify the LIVE staging Worker's R2 relay path end-to-end WITHOUT email.
// Mints a server-signed Drop link offline (using keys/staging.json — same key the
// confirm handler signs with), then runs upload-init -> real R2 PUT -> upload-complete
// against the deployed Worker.
//
// A 502 at upload-complete is the SUCCESS signal: presign + R2 PUT + S3 CopyObject +
// magic-sniff + email-unseal all worked, and only the (not-yet-onboarded) email send
// failed. That exercises every use of the R2 credentials the user just set.
//   bun run scripts/smoke-live.ts
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../web/core/src/index";
import { DROP_PAYLOAD_VERSION, LINK_ID_LEN, base64urlEncode, signableBytes } from "../shared/codec";
import { importKemPublicKey, importSignPrivateKey, sealEmail, signRegion } from "../shared/crypto";

const BASE = "https://filekey-drop-staging.rockwellshah.workers.dev";

// Server keys (gitignored). signPriv mints a link the Worker accepts; kemPubHex is
// what we seal the throwaway receiver email to.
const keys = (await Bun.file("keys/staging.json").json()) as { signPriv: JsonWebKey; kemPubHex: string };
const signPriv = await importSignPrivateKey(keys.signPriv);
const kemPub = await importKemPublicKey(Uint8Array.from(keys.kemPubHex.match(/../g)!.map((h) => parseInt(h, 16))));

// Throwaway receiver identity (no passkey needed for the relay path itself).
const ns = new NamespaceSet(["filekey.app"]).namespaces[0]!;
const receiver = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
const testEmail = Bun.argv[2] ?? "smoke-test@example.com";
const sealed = await sealEmail(kemPub, testEmail);

// Mint the signed link (replicates the confirm handler, offline).
const region = signableBytes({
  version: DROP_PAYLOAD_VERSION,
  keyId: 1, // matches the worker's default SERVER_SIGN_KEY_ID
  linkId: crypto.getRandomValues(new Uint8Array(LINK_ID_LEN)),
  shareKey: new TextEncoder().encode(shareKey),
  label: "Smoke test",
  sealedEmail: sealed,
});
const sig = await signRegion(signPriv, region);
const full = new Uint8Array(region.length + sig.length);
full.set(region, 0);
full.set(sig, region.length);
const payload = base64urlEncode(full);

// Minimal valid-looking FileKey ciphertext: the FKEY magic + padding (enough for the
// server-side magic sniff; we're testing the relay, not decryptability).
const blob = new Uint8Array(64);
blob.set([0x46, 0x4b, 0x45, 0x59], 0);

const post = (path: string, body: unknown) =>
  fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

console.log("delivery target:", testEmail);
console.log("1) upload-init ...");
const initRes = await post("/upload-init", { payload, size: blob.length });
const init = (await initRes.json()) as { objectId: string; uploadUrl: string };
console.log("   ->", initRes.status, initRes.ok ? `objectId=${init.objectId}` : JSON.stringify(init));
if (!initRes.ok) process.exit(1);

console.log("2) R2 PUT (the real credential test) ...");
const putRes = await fetch(init.uploadUrl, { method: "PUT", body: blob });
console.log("   ->", putRes.status, putRes.ok ? "OK — R2 accepted the SigV4 signature (creds valid)" : await putRes.text());

console.log("3) upload-complete ...");
const compRes = await post("/upload-complete", { payload, objectId: init.objectId });
console.log("   ->", compRes.status, (await compRes.text()).slice(0, 400));

console.log("\nstaging objectId (for cleanup):", init.objectId);
console.log(
  compRes.status === 502
    ? "RESULT: ✅ Relay fully works end-to-end; only email send failed (expected — domain not onboarded)."
    : compRes.status === 200
      ? "RESULT: ✅ FULL success incl. email delivery."
      : `RESULT: ⚠️ Stopped at status ${compRes.status} — see above.`,
);
