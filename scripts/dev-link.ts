// Generate a usable Drop upload link against the running mock dev server
// (bun run web/devserver.ts must be running). Derives a throwaway "receiver" with
// no passkey, registers + confirms, and prints the upload URL to open in a browser.
//   bun run scripts/dev-link.ts
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../web/core/src/index";
import { base64urlEncode } from "../shared/codec";
import { importKemPublicKey, sealEmail } from "../shared/crypto";

const BASE = "http://localhost:8080/api";
const NS = new NamespaceSet(["receive.link"]);
const ns = NS.namespaces[0]!;
const json = (path: string, body: unknown) =>
  fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json());

const cfg = (await (await fetch(`${BASE}/__config`)).json()) as { kemPublicHex: string };
const receiver = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
const kemPub = await importKemPublicKey(Uint8Array.from(cfg.kemPublicHex.match(/../g)!.map((h) => parseInt(h, 16))));
const sealed = await sealEmail(kemPub, "dev-receiver@example.com");

await json("/register", { sealedEmail: base64urlEncode(sealed), shareKey: base64urlEncode(new TextEncoder().encode(shareKey)), label: "Dev inbox" });
const last = (await (await fetch(`${BASE}/__lastmail`)).json()) as { text: string };
const nonce = last.text.match(/\/confirm#([A-Za-z0-9_-]+)/)![1];
const { link } = (await json("/confirm", { nonce })) as { link: string };

console.log(`http://localhost:8080/#${link}`);
