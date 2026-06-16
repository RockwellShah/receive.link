// The load-bearing multipart invariant: stream-encrypting a file into parts and
// concatenating them yields EXACTLY the ciphertext (predicted size), and it decrypts
// back to the original. (Codex review: don't compare to a re-encryption — fresh HPKE
// makes that differ; compare assembly of the SAME run + round-trip.)
import { expect, test } from "bun:test";
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "./core/src/index.js";
import { ciphertextLength, encryptFileToParts, openCiphertext, openCiphertextSource, streamSource } from "./fk/stream";

test("encryptFileToParts: parts concatenate to a ciphertext of the predicted size that decrypts to the original", async () => {
  const NS = new NamespaceSet(["filekey.app"]);
  const ns = NS.namespaces[0]!;
  const receiver = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
  const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
  const sender = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);

  const plaintext = crypto.getRandomValues(new Uint8Array(300_000)); // spans several 64 KiB chunks
  const file = new File([plaintext], "blob.bin", { type: "application/octet-stream" });

  const partSize = 64 * 1024; // small parts → multiple parts, last one a remainder
  const parts: Uint8Array[] = [];
  for await (const p of encryptFileToParts(file, shareKey, NS, sender, partSize)) parts.push(p);

  expect(parts.length).toBeGreaterThan(1);
  for (let i = 0; i < parts.length - 1; i++) expect(parts[i]!.length).toBe(partSize); // all but last exact
  expect(parts[parts.length - 1]!.length).toBeLessThanOrEqual(partSize);

  const total = parts.reduce((n, p) => n + p.length, 0);
  expect(total).toBe(ciphertextLength(file)); // up-front size estimate is exact

  // Concatenate the parts (what R2 does) and decrypt — must recover the original bytes.
  const ct = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    ct.set(p, off);
    off += p.length;
  }
  const { chunks } = await openCiphertext(new Blob([ct]), receiver, NS);
  const out: Uint8Array[] = [];
  for await (const chunk of chunks) out.push(chunk);
  const dec = new Uint8Array(out.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of out) {
    dec.set(c, o);
    o += c.length;
  }
  expect(dec.length).toBe(plaintext.length);
  expect([...dec.slice(0, 64)]).toEqual([...plaintext.slice(0, 64)]);
  expect([...dec.slice(-64)]).toEqual([...plaintext.slice(-64)]);
});

test("streamSource: decrypts a ciphertext fed through a forward-only ReadableStream (1x-disk receive)", async () => {
  const NS = new NamespaceSet(["filekey.app"]);
  const ns = NS.namespaces[0]!;
  const receiver = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
  const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
  const sender = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);

  const plaintext = crypto.getRandomValues(new Uint8Array(300_000));
  const file = new File([plaintext], "blob.bin", { type: "application/octet-stream" });

  // Build the full ciphertext.
  const parts: Uint8Array[] = [];
  for await (const p of encryptFileToParts(file, shareKey, NS, sender, 64 * 1024)) parts.push(p);
  const ct = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    ct.set(p, o);
    o += p.length;
  }

  // Feed it through a forward-only ReadableStream in IRREGULAR chunk sizes (so stream boundaries cut
  // across the slice boundaries decryptStream asks for) — what a real fetch body does.
  let i = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (i >= ct.length) return c.close();
      const n = 1 + ((i * 7919) % 9000);
      c.enqueue(ct.subarray(i, Math.min(i + n, ct.length)));
      i += n;
    },
  });

  const { chunks } = await openCiphertextSource(streamSource(stream, ct.length), receiver, NS);
  const out: Uint8Array[] = [];
  for await (const chunk of chunks) out.push(chunk);
  const dec = new Uint8Array(out.reduce((n, c) => n + c.length, 0));
  let d = 0;
  for (const c of out) {
    dec.set(c, d);
    d += c.length;
  }
  expect(dec.length).toBe(plaintext.length);
  expect([...dec]).toEqual([...plaintext]); // full byte-for-byte match
});
