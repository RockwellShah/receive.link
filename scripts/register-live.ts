// One-off smoke: hit the LIVE worker's /register to confirm email sending still
// works after a From-header change. A 202 means the send binding accepted the
// `from` (incl. any display name); a 5xx means it rejected it. Recipient defaults
// to an example.com address (queued + bounced, no real inbox touched).
//   bun run scripts/register-live.ts
import { base64urlEncode } from "../shared/codec";
import { importKemPublicKey, sealEmail } from "../shared/crypto";

const API = process.env.DROP_API || "https://filekey-drop-staging.rockwellshah.workers.dev";
const KEM_HEX =
  process.env.DROP_KEM_HEX ||
  "043b235d0c8594a8dda07e5db3ce127f697a65037aa606135c4ba80316b850833a524f6f78b35f98959887323342bdb93f6b7cc92e2ae92b556ffc5807c116b2b2";
const TO = process.env.DROP_TO || "from-header-test@example.com";
const hexToBytes = (s: string) => new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));

const kemPub = await importKemPublicKey(hexToBytes(KEM_HEX));
const sealedEmail = base64urlEncode(await sealEmail(kemPub, TO));
const shareKey = base64urlEncode(new TextEncoder().encode("from-test-share-key-0123456789"));
const res = await fetch(`${API}/register`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ sealedEmail, shareKey, label: "From test" }),
});
console.log("register ->", res.status, await res.text());
console.log(res.status === 202 ? "✅ send binding accepted the From header" : "❌ binding rejected it — revert the From change");
