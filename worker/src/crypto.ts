// FileKey Drop — server-side crypto primitives.
//
// Two protocol-critical operations, both built on the same primitives FileKey
// already uses (WebCrypto + @hpke/core), so the Worker and browser agree byte
// for byte:
//
//  1. Link signature (ECDSA P-256, raw r||s): the Worker signs a Drop link's
//     signable region at /confirm (after the email is verified); the sender's
//     browser AND the Worker verify it before trusting the link.
//  2. Email sealing (HPKE base mode, DHKEM-P256 + HKDF-SHA-256 + AES-256-GCM):
//     the receiver's browser seals their email TO the server's KEM public key
//     once at setup; the Worker unseals it in memory at send time and never
//     stores it.
//
// NOTE: needs the Fable-5 + Codex security review before production — this is
// the same two-model loop run on the FileKey v1.1 core.

import { Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

/** DHKEM(P-256) encapsulated key length: a SEC1 uncompressed point. */
export const HPKE_ENC_LEN = 65;

function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(u.length);
  new Uint8Array(ab).set(u);
  return ab;
}

// ---- ECDSA P-256 link signature ----

export function importSignPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

export function importSignPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

export async function signRegion(privateKey: CryptoKey, region: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, toArrayBuffer(region));
  return new Uint8Array(sig); // 64 bytes raw r||s for P-256
}

export function verifyRegion(publicKey: CryptoKey, region: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    toArrayBuffer(signature),
    toArrayBuffer(region),
  );
}

// ---- HPKE base-mode email sealing ----

/** Import the server KEM public key from a 65-byte SEC1 uncompressed point. */
export function importKemPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  return suite.kem.importKey("raw", toArrayBuffer(raw), true);
}

export function importKemPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return suite.kem.importKey("jwk", jwk as JsonWebKey, false);
}

/**
 * Seal `email` to the server KEM public key. Returns enc(65) || ct, where ct is
 * AES-256-GCM ciphertext + tag. Randomized: call once at setup, then the sealed
 * bytes are immutable inside the signed link (never re-seal a signed payload).
 */
export async function sealEmail(serverKemPublicKey: CryptoKey, email: string): Promise<Uint8Array> {
  const sender = await suite.createSenderContext({ recipientPublicKey: serverKemPublicKey });
  const ct = new Uint8Array(await sender.seal(new TextEncoder().encode(email)));
  const enc = new Uint8Array(sender.enc);
  if (enc.length !== HPKE_ENC_LEN) throw new Error(`unexpected enc length ${enc.length}`);
  const out = new Uint8Array(enc.length + ct.length);
  out.set(enc, 0);
  out.set(ct, enc.length);
  return out;
}

/** Unseal enc(65) || ct produced by {@link sealEmail}. Throws on tamper/wrong key. */
export async function unsealEmail(serverKemPrivateKey: CryptoKey, sealed: Uint8Array): Promise<string> {
  if (sealed.length <= HPKE_ENC_LEN) throw new Error("sealed_email too short");
  const enc = sealed.subarray(0, HPKE_ENC_LEN);
  const ct = sealed.subarray(HPKE_ENC_LEN);
  const recipient = await suite.createRecipientContext({
    recipientKey: serverKemPrivateKey,
    enc: toArrayBuffer(enc),
  });
  const pt = new Uint8Array(await recipient.open(toArrayBuffer(ct)));
  return new TextDecoder("utf-8", { fatal: true }).decode(pt);
}

/** Generate a fresh server KEM key pair (used by scripts/gen-keys.ts). */
export function generateKemKeyPair(): Promise<CryptoKeyPair> {
  return suite.kem.generateKeyPair();
}

/** Serialize a KEM public key to its 65-byte SEC1 uncompressed form. */
export async function serializeKemPublicKey(publicKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await suite.kem.serializePublicKey(publicKey));
}
