// Generate the FileKey Drop server keys. Run once per environment (staging, prod):
//   bun run scripts/gen-keys.ts
//
// Prints THREE secrets (set via `wrangler secret put`) and TWO public values
// (paste into wrangler.toml [vars] / pin in the web client). Staging and prod
// MUST use different keys, so a staging link never validates against prod.
//
// SECURITY: this prints private keys to your terminal. Don't paste them into
// chat, commit them, or leave them in scrollback. The repo .gitignore excludes
// keys/ and *.private.jwk, but this script writes nothing to disk by design.

import { base64urlDecode } from "../worker/src/codec";

function rawFromEcJwk(jwk: JsonWebKey): Uint8Array {
  const raw = new Uint8Array(65);
  raw[0] = 0x04; // SEC1 uncompressed
  raw.set(base64urlDecode(jwk.x!), 1);
  raw.set(base64urlDecode(jwk.y!), 33);
  return raw;
}

const hex = (u: Uint8Array) => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

const sign = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const signPriv = await crypto.subtle.exportKey("jwk", sign.privateKey);
const signPub = await crypto.subtle.exportKey("jwk", sign.publicKey);

const kem = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
const kemPriv = await crypto.subtle.exportKey("jwk", kem.privateKey);
const kemPubRaw = rawFromEcJwk(await crypto.subtle.exportKey("jwk", kem.publicKey));

const line = "─".repeat(72);
console.log(`\n${line}\nFileKey Drop server keys — handle the SECRETS carefully\n${line}`);

console.log(`\n# SECRET 1 — wrangler secret put SERVER_SIGN_PRIVATE_JWK`);
console.log(JSON.stringify(signPriv));

console.log(`\n# SECRET 2 — wrangler secret put SERVER_KEM_PRIVATE_JWK`);
console.log(JSON.stringify(kemPriv));

console.log(`\n# The other two secrets are R2 S3 credentials from the Cloudflare`);
console.log(`# dashboard (R2 > Manage API tokens), NOT generated here:`);
console.log(`#   wrangler secret put R2_ACCESS_KEY_ID`);
console.log(`#   wrangler secret put R2_SECRET_ACCESS_KEY`);

console.log(`\n${line}\n# PUBLIC — paste into wrangler.toml [vars]`);
console.log(`SERVER_SIGN_PUBLIC_JWK = ${JSON.stringify(JSON.stringify(signPub))}`);

console.log(`\n# PUBLIC — pin in the Drop web client (KEM public key, 65-byte SEC1 hex)`);
console.log(`SERVER_KEM_PUBLIC_HEX = "${hex(kemPubRaw)}"`);
console.log(`${line}\n`);
