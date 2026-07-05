// Smoke test for the vendored FileKey core: proves the copy under web/core/ works
// in this repo, and that its ciphertext carries the "FKEY" magic the Drop Worker
// checks in upload-complete. Run by `bun test`; not part of the tsc program (the
// vendored core has its own provenance + 71 tests upstream).
import { expect, test } from "bun:test";
import { NamespaceSet, decrypt, deriveIdentityFromPrf, encodeShareKey, encryptToShareKey } from "./core/src/index";

const NS = new NamespaceSet(["receive.link"]);
const ns = NS.namespaces[0]!;
const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

test("vendored core: encrypt-to-share-key round-trips and emits FKEY magic", async () => {
  // Receiver identity (in the real flow: derived from their passkey at setup).
  const receiver = await deriveIdentityFromPrf(rnd32(), ns);
  const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
  expect(shareKey.startsWith("fkey1")).toBe(true);

  // Sender side (the Drop upload page): a throwaway identity, no passkey needed.
  const sender = await deriveIdentityFromPrf(rnd32(), ns);
  const plaintext = new TextEncoder().encode("hello from a FileKey Drop link");
  const ct = await encryptToShareKey({
    senderIdentity: sender,
    recipientShareKey: shareKey,
    namespaces: NS,
    plaintext,
    metadata: { filename: "note.txt", mimeType: "text/plain", createdAtUnixMs: 0, extras: new Map() },
  });

  // The exact gate the Worker enforces on the relayed object.
  expect(Array.from(ct.subarray(0, 4))).toEqual([0x46, 0x4b, 0x45, 0x59]); // "FKEY"

  // Receiver decrypts with their identity (in the real flow: from their passkey).
  const res = await decrypt({ file: ct, namespaces: NS, resolveIdentity: async () => receiver });
  expect(new TextDecoder().decode(res.plaintext)).toBe("hello from a FileKey Drop link");
  expect(res.metadata.filename).toBe("note.txt");
  expect(res.selfEncrypted).toBe(false);
});
