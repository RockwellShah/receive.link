// Offline smoke test for the revoke loop against the mock dev server.
// Start the server first:  bun run web/devserver.ts
// Then run:               bun run scripts/smoke-revoke.ts
//
// Walks the real handlers: register -> confirm (mints a revoke token) ->
// upload-init OK -> revoke -> upload-init now 410 -> bad token 404.
import { base64urlEncode } from "../shared/codec";
import { importKemPublicKey, sealEmail } from "../shared/crypto";

const BASE = process.env.DROP_BASE || "http://localhost:8080/api";
const hexToBytes = (s: string) => new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
const post = (path: string, body: unknown) =>
  fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

const cfg = (await (await fetch(`${BASE}/__config`)).json()) as { kemPublicHex: string };
const kemPub = await importKemPublicKey(hexToBytes(cfg.kemPublicHex));
const sealedEmail = base64urlEncode(await sealEmail(kemPub, "smoke@example.com"));
const shareKey = base64urlEncode(new TextEncoder().encode("smoke-share-key-0123456789"));

const reg = await post("/register", { sealedEmail, shareKey, label: "Smoke" });
console.log("register:", reg.status, "(expect 202)");

const mail = (await (await fetch(`${BASE}/__lastmail`)).json()) as { text: string };
const nonce = mail.text.match(/confirm#([A-Za-z0-9_-]+)/)![1]!;

const conf = (await (await post("/confirm", { nonce })).json()) as { link?: string; revokeToken?: string };
console.log("confirm -> link:", !!conf.link, "revokeToken:", !!conf.revokeToken, "(expect true true)");

const init1 = await post("/upload-init", { payload: conf.link, size: 1000 });
console.log("upload-init before revoke:", init1.status, "(expect 200)");

const rev = await post("/revoke", { token: conf.revokeToken });
console.log("revoke:", rev.status, "(expect 200)");

const init2 = await post("/upload-init", { payload: conf.link, size: 1000 });
console.log("upload-init after revoke:", init2.status, ((await init2.json()) as { error?: string }).error, "(expect 410 link revoked)");

const revBad = await post("/revoke", { token: "00000000000000000000000000000000" });
console.log("revoke bad token:", revBad.status, "(expect 404)");

const pass =
  reg.status === 202 && !!conf.link && !!conf.revokeToken &&
  init1.status === 200 && rev.status === 200 && init2.status === 410 && revBad.status === 404;
console.log(pass ? "\n✅ revoke loop OK" : "\n❌ revoke loop FAILED");
process.exit(pass ? 0 : 1);
