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
import { hex } from "./util";

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

// HPKE `info` for domain separation: binds a sealed ciphertext to THIS purpose, so it can never be
// replayed against another HPKE context that happens to use the same key. Must match on seal + unseal.
const EMAIL_SEAL_INFO = new TextEncoder().encode("FILEKEY-DROP/email-seal/v1");
/** Domain label for the download-gate challenge (a nonce sealed base-mode to the receiver's share key). */
export const FETCH_CHALLENGE_INFO = new TextEncoder().encode("FILEKEY-DROP/fetch-challenge/v1");
const FETCH_PROOF_LABEL = new TextEncoder().encode("FILEKEY-DROP/fetch-proof/v1");

/**
 * Download-gate proof = SHA-256(label || challengeId-hex || objectId-hex || nonce), as hex. The Worker
 * computes the expected value when it mints the challenge; the client computes the response after
 * unsealing the nonce. Both derive it identically; the hex ids are fixed-length, so the transcript is
 * unambiguous. The proof is bound to one object so it can't be replayed against another.
 */
export async function fetchProofHex(challengeIdHex: string, objectIdHex: string, nonce: Uint8Array): Promise<string> {
  const cid = new TextEncoder().encode(challengeIdHex);
  const oid = new TextEncoder().encode(objectIdHex);
  const buf = new Uint8Array(FETCH_PROOF_LABEL.length + cid.length + oid.length + nonce.length);
  let o = 0;
  buf.set(FETCH_PROOF_LABEL, o); o += FETCH_PROOF_LABEL.length;
  buf.set(cid, o); o += cid.length;
  buf.set(oid, o); o += oid.length;
  buf.set(nonce, o);
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", buf)));
}

/**
 * Base-mode HPKE: seal `data` to `recipientPublicKey` under domain-separating `info`. Returns
 * enc(65) || ct (AES-256-GCM ciphertext + tag), randomized per call. Recover it with {@link hpkeUnseal}
 * and the same info.
 */
export async function hpkeSealTo(recipientPublicKey: CryptoKey, data: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ct = new Uint8Array(await sender.seal(toArrayBuffer(data)));
  const enc = new Uint8Array(sender.enc);
  if (enc.length !== HPKE_ENC_LEN) throw new Error(`unexpected enc length ${enc.length}`);
  const out = new Uint8Array(enc.length + ct.length);
  out.set(enc, 0);
  out.set(ct, enc.length);
  return out;
}

/**
 * Base-mode HPKE: unseal enc(65) || ct from {@link hpkeSealTo}. `recipientKey` may be a bare private key
 * or a full key pair — a non-extractable identity keyPair works (@hpke uses the provided public key
 * directly; see web/core/src/identity.ts). Throws on tamper / wrong key. Same `info` as the seal.
 */
export async function hpkeUnseal(recipientKey: CryptoKey | CryptoKeyPair, sealed: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  if (sealed.length <= HPKE_ENC_LEN) throw new Error("sealed payload too short");
  const enc = sealed.subarray(0, HPKE_ENC_LEN);
  const ct = sealed.subarray(HPKE_ENC_LEN);
  const recipient = await suite.createRecipientContext({ recipientKey, enc: toArrayBuffer(enc), info });
  return new Uint8Array(await recipient.open(toArrayBuffer(ct)));
}

/**
 * Seal `email` to the server KEM public key (thin base-mode wrapper). Returns enc(65) || ct. Randomized:
 * call once at setup; the sealed bytes are then immutable inside the signed link.
 */
export function sealEmail(serverKemPublicKey: CryptoKey, email: string): Promise<Uint8Array> {
  return hpkeSealTo(serverKemPublicKey, new TextEncoder().encode(email), EMAIL_SEAL_INFO);
}

/** Unseal enc(65) || ct produced by {@link sealEmail}. Throws on tamper/wrong key. */
export async function unsealEmail(serverKemPrivateKey: CryptoKey, sealed: Uint8Array): Promise<string> {
  const pt = await hpkeUnseal(serverKemPrivateKey, sealed, EMAIL_SEAL_INFO);
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
