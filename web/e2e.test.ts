// End-to-end: the whole Drop protocol through the REAL Worker handlers AND the real
// client crypto (the vendored core + shared codec/crypto). No passkey needed — the
// core derives identities from a 32-byte secret directly; WebAuthn is only the
// browser wrapper. Run by `bun test`.
import { expect, test } from "bun:test";
import { NamespaceSet, decrypt, deriveIdentityFromPrf, encodeShareKey, encryptToShareKey } from "./core/src/index";
import { base64urlDecode, base64urlEncode, decodeDropLink } from "../shared/codec";
import { importKemPublicKey, sealEmail } from "../shared/crypto";
import { confirm, register, uploadComplete, uploadInit } from "../worker/src/handlers";
import { makeTestEnv } from "../worker/src/testing";

const NS = new NamespaceSet(["filekey.app"]);
const ns = NS.namespaces[0]!;
const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

function post(path: string, body: unknown, ip = "2.2.2.2"): Request {
  return new Request(`https://api.drop.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": ip },
    body: JSON.stringify(body),
  });
}
function nonceFrom(text: string): string {
  const m = text.match(/\/confirm#([A-Za-z0-9_-]+)/);
  if (!m) throw new Error("no nonce in confirm email");
  return m[1]!;
}

test("receiver sets up -> sender encrypts + uploads -> receiver decrypts the real file", async () => {
  const h = await makeTestEnv();

  // --- Receiver setup (the client crypto path, minus the WebAuthn wrapper) ---
  const receiver = await deriveIdentityFromPrf(rnd32(), ns);
  const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
  const kemPub = await importKemPublicKey(h.kemPublicRaw);
  const sealedEmail = base64urlEncode(await sealEmail(kemPub, "receiver@example.com"));

  await register(post("/register", { sealedEmail, shareKey: base64urlEncode(new TextEncoder().encode(shareKey)), label: "Tax inbox" }), h.env);
  const nonce = nonceFrom(h.email.sent.at(-1)!.text!);
  const link = ((await (await confirm(post("/confirm", { nonce }), h.env)).json()) as { link: string }).link;

  // --- Sender (anonymous, no passkey): encrypt a real file to the link's share key ---
  const linkShareKey = new TextDecoder().decode(decodeDropLink(base64urlDecode(link)).shareKey);
  const sender = await deriveIdentityFromPrf(rnd32(), ns); // throwaway
  const plaintext = new TextEncoder().encode("the secret quarterly numbers");
  const ciphertext = await encryptToShareKey({
    senderIdentity: sender,
    recipientShareKey: linkShareKey,
    namespaces: NS,
    plaintext,
    metadata: { filename: "q3.txt", mimeType: "text/plain", createdAtUnixMs: 0, extras: new Map() },
  });

  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: ciphertext.length }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, ciphertext); // the browser's direct-to-R2 PUT
  const done = await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  expect(done.status).toBe(200);

  // --- Delivery email reached the receiver's real (unsealed) address ---
  const delivery = h.email.sent.at(-1)!;
  expect(delivery.to).toBe("receiver@example.com");
  expect(delivery.text).toContain("/d/");
  // The email links to the immutable final key (a copy of the staged upload).
  const finalId = delivery.text!.match(/\/d\/([0-9a-f]{32})/)![1]!;

  // --- Receiver fetches the ciphertext + decrypts with their identity ---
  const stored = (await h.r2.get(finalId))!;
  const fetched = new Uint8Array(await stored.arrayBuffer());
  const res = await decrypt({ file: fetched, namespaces: NS, resolveIdentity: async () => receiver });
  expect(new TextDecoder().decode(res.plaintext)).toBe("the secret quarterly numbers");
  expect(res.metadata.filename).toBe("q3.txt");
  expect(res.selfEncrypted).toBe(false);
});
