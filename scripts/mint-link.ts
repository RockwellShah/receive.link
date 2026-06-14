// Dev helper: mint a Drop link against the running mock dev server and print it,
// so you can open the upload (/#<link>) and revoke (/revoke#<token>) pages by hand.
// Start the server first:  bun run web/devserver.ts
// Then run:               bun run scripts/mint-link.ts
import { base64urlEncode } from "../shared/codec";
import { importKemPublicKey, sealEmail } from "../shared/crypto";
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../web/core/src/index.js";

const BASE = process.env.DROP_BASE || "http://localhost:8080/api";
const ORIGIN = BASE.replace(/\/api$/, "");
const hexToBytes = (s: string) => new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
const post = (p: string, b: unknown) =>
  fetch(`${BASE}${p}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });

const cfg = (await (await fetch(`${BASE}/__config`)).json()) as { kemPublicHex: string };
const kemPub = await importKemPublicKey(hexToBytes(cfg.kemPublicHex));
const sealedEmail = base64urlEncode(await sealEmail(kemPub, "demo@example.com"));
// A real, decodable share key (random throwaway identity) so the sender's browser
// can actually encrypt to it. Decrypt won't work (private key is discarded), but
// that's fine for exercising the send/upload flow in dev.
const ns = new NamespaceSet(["filekey.app"]).namespaces[0]!;
const identity = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
const shareKey = base64urlEncode(new TextEncoder().encode(encodeShareKey(identity.staticPkRaw, identity.namespace)));

await post("/register", { sealedEmail, shareKey, label: "Demo Drop" });
const mail = (await (await fetch(`${BASE}/__lastmail`)).json()) as { text: string };
const nonce = mail.text.match(/confirm#([A-Za-z0-9_-]+)/)![1]!;
const conf = (await (await post("/confirm", { nonce })).json()) as { link: string; revokeToken: string };

console.log("UPLOAD " + `${ORIGIN}/#${conf.link}`);
console.log("REVOKE " + `${ORIGIN}/revoke#${conf.revokeToken}`);
