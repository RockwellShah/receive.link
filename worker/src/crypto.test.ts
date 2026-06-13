// Real round-trip + tamper tests for the server crypto. Needs @hpke/core (bun install).
import { expect, test } from "bun:test";
import {
  generateKemKeyPair,
  importKemPrivateKey,
  importKemPublicKey,
  sealEmail,
  serializeKemPublicKey,
  signRegion,
  unsealEmail,
  verifyRegion,
} from "./crypto";
import { base64urlDecode } from "./codec";

test("HPKE seal/unseal round-trips an email address", async () => {
  const kp = await generateKemKeyPair();
  const sealed = await sealEmail(kp.publicKey, "alice@example.com");
  expect(await unsealEmail(kp.privateKey, sealed)).toBe("alice@example.com");
});

test("a KEM public key survives serialize → import (the client-pinned form)", async () => {
  const kp = await generateKemKeyPair();
  const raw = await serializeKemPublicKey(kp.publicKey);
  expect(raw.length).toBe(65);
  const reimported = await importKemPublicKey(raw);
  const sealed = await sealEmail(reimported, "bob@example.com");
  expect(await unsealEmail(kp.privateKey, sealed)).toBe("bob@example.com");
});

test("HPKE unseal rejects a tampered ciphertext", async () => {
  const kp = await generateKemKeyPair();
  const sealed = await sealEmail(kp.publicKey, "carol@example.com");
  sealed[sealed.length - 1] = sealed[sealed.length - 1]! ^ 0x01;
  await expect(unsealEmail(kp.privateKey, sealed)).rejects.toBeDefined();
});

test("HPKE unseal rejects the wrong key", async () => {
  const a = await generateKemKeyPair();
  const b = await generateKemKeyPair();
  const sealed = await sealEmail(a.publicKey, "dave@example.com");
  await expect(unsealEmail(b.privateKey, sealed)).rejects.toBeDefined();
});

test("gen-keys key path interoperates: client seals to pinned raw pubkey, Worker unseals from JWK", async () => {
  // Mirror scripts/gen-keys.ts: generate the KEM keypair with crypto.subtle (ECDH
  // P-256), export the private as JWK (the Worker secret) and derive the 65-byte
  // raw public (the client pin). The two must interoperate with seal/unseal.
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(base64urlDecode(pubJwk.x!), 1);
  raw.set(base64urlDecode(pubJwk.y!), 33);

  const clientPub = await importKemPublicKey(raw); // client side
  const workerPriv = await importKemPrivateKey(privJwk); // Worker side
  const sealed = await sealEmail(clientPub, "erin@example.com");
  expect(await unsealEmail(workerPriv, sealed)).toBe("erin@example.com");
});

test("ECDSA sign/verify over the signable region; tamper fails", async () => {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const region = new TextEncoder().encode("the signable region bytes");
  const sig = await signRegion(kp.privateKey, region);
  expect(sig.length).toBe(64);
  expect(await verifyRegion(kp.publicKey, region, sig)).toBe(true);
  region[0] = region[0]! ^ 0x01;
  expect(await verifyRegion(kp.publicKey, region, sig)).toBe(false);
});
