// One-off launch-gate experiment: does the delivery COPY PROMOTION work past the S3 dialect's 5 GiB
// single-CopyObject limit on real R2? uploadComplete promotes every delivery via one CopyObject
// (r2.ts copyObject); if R2 enforces the S3 cap, every file > 5 GiB uploads fully and then fails.
// This uploads a 5.5 GB (> 5 GiB = 5,368,709,120) FKEY-prefixed zero-blob to the MON worker through
// the REAL multipart flow, then completes and interprets the outcome:
//   200                          -> copy > 5 GiB WORKS (full delivery)
//   502 "delivery failed"        -> copy WORKED (the email after it failed; worker cleaned up the final)
//   404 "object not found" here  -> copy FAILED at promotion = the 5 GiB limit is real
// Mints the link offline (keys/staging.json, same keys as mon). Run: bun run scripts/smoke-copy-5gb.ts
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../web/core/src/index";
import { DROP_PAYLOAD_VERSION, LINK_ID_LEN, base64urlDecode, base64urlEncode, signableBytes } from "../shared/codec";
import { FETCH_CHALLENGE_INFO, fetchProofHex, hpkeUnseal, importKemPublicKey, importSignPrivateKey, sealEmail, signRegion } from "../shared/crypto";

const BASE = process.env.SMOKE_BASE ?? "https://receive-link-monetization.rockwellshah.workers.dev"; // any env's WORKER url
const SIZE = Number(process.env.SMOKE_SIZE ?? 5_500_000_000); // default 5.5 GB decimal, safely over 5 GiB
const CONCURRENCY = 6;

const keys = (await Bun.file(process.env.SMOKE_KEYS ?? "keys/staging.json").json()) as { signPriv: JsonWebKey; kemPubHex: string };
const signPriv = await importSignPrivateKey(keys.signPriv);
const kemPub = await importKemPublicKey(Uint8Array.from(keys.kemPubHex.match(/../g)!.map((h) => parseInt(h, 16))));

const ns = new NamespaceSet(["filekey.app"]).namespaces[0]!;
const receiver = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
const sealed = await sealEmail(kemPub, "smoke-copy-5gb@example.com"); // throwaway; a failed send still proves the copy

const region = signableBytes({
  version: DROP_PAYLOAD_VERSION,
  keyId: 1,
  linkId: crypto.getRandomValues(new Uint8Array(LINK_ID_LEN)),
  shareKey: new TextEncoder().encode(shareKey),
  label: "Copy-limit smoke",
  sealedEmail: sealed,
});
const sig = await signRegion(signPriv, region);
const full = new Uint8Array(region.length + sig.length);
full.set(region, 0);
full.set(sig, region.length);
const payload = base64urlEncode(full);

const post = (path: string, body: unknown) =>
  fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

console.log(`1) upload-init size=${SIZE} ...`);
const initRes = await post("/upload-init", { payload, size: SIZE });
const init = (await initRes.json()) as {
  mode?: string;
  objectId: string;
  partSize: number;
  partCount: number;
  partUrls: { partNumber: number; url: string }[];
  batchSize: number;
};
console.log("   ->", initRes.status, JSON.stringify({ mode: init.mode, partSize: init.partSize, partCount: init.partCount }));
if (!initRes.ok || init.mode !== "multipart") { console.log("ABORT: expected multipart"); process.exit(1); }

// Part body: zeros, with the FKEY header overlaid on part 1 (magic + version + suite + metaLen=17 @142).
function partBody(partNumber: number): Uint8Array {
  const start = (partNumber - 1) * init.partSize;
  const len = Math.min(init.partSize, SIZE - start);
  const buf = new Uint8Array(len);
  if (partNumber === 1) {
    buf.set([0x46, 0x4b, 0x45, 0x59], 0);
    buf[4] = 0x01;
    buf[5] = 0x01;
    buf[145] = 17; // u32be metadata length @142 -> 17
  }
  return buf;
}

async function putPart(partNumber: number, url: string): Promise<{ partNumber: number; etag: string }> {
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await fetch(url, { method: "PUT", body: partBody(partNumber) });
      const etag = r.headers.get("etag") ?? "";
      if (r.ok && etag) return { partNumber, etag };
      if (attempt >= 2) throw new Error(`part ${partNumber}: HTTP ${r.status}, etag=${etag || "none"}`);
    } catch (e) {
      if (attempt >= 2) throw e;
    }
    await new Promise((res) => setTimeout(res, 1500 * (attempt + 1)));
  }
}

const t0 = Date.now();
const parts: { partNumber: number; etag: string }[] = [];
let urls = init.partUrls;
let done = 0;
while (parts.length < init.partCount) {
  // Upload this batch with bounded concurrency.
  const queue = [...urls];
  const workers = Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
    for (;;) {
      const item = queue.shift();
      if (!item) return;
      parts.push(await putPart(item.partNumber, item.url));
      done++;
    }
  });
  await Promise.all(workers);
  const bytes = Math.min(done * init.partSize, SIZE);
  const secs = (Date.now() - t0) / 1000;
  const mbps = (bytes / 1e6 / secs) * 8;
  console.log(`   parts ${done}/${init.partCount}  ${(bytes / 1e9).toFixed(2)} GB  ${mbps.toFixed(0)} Mbps  ETA ${Math.max(0, Math.round((SIZE - bytes) / (bytes / secs)))}s`);
  if (parts.length >= init.partCount) break;
  const from = done + 1;
  const more = await post("/upload-parts", { payload, objectId: init.objectId, from, count: init.batchSize });
  if (!more.ok) { console.log(`ABORT: upload-parts ${more.status}`); process.exit(1); }
  urls = ((await more.json()) as { partUrls: { partNumber: number; url: string }[] }).partUrls;
}
parts.sort((a, b) => a.partNumber - b.partNumber);
console.log(`2) all ${parts.length} parts uploaded in ${((Date.now() - t0) / 1000 / 60).toFixed(1)} min`);

console.log("3) upload-complete (assemble + COPY PROMOTION, the moment under test) ...");
const tC = Date.now();
const compRes = await post("/upload-complete", { payload, objectId: init.objectId, parts });
const compText = (await compRes.text()).slice(0, 300);
console.log(`   -> ${compRes.status} in ${((Date.now() - tC) / 1000).toFixed(1)}s: ${compText}`);

let verdict: string;
if (compRes.status === 200) verdict = "✅ DELIVERED end-to-end (in-place: no copy, no size wall)";
else if (compRes.status === 502 && /delivery/i.test(compText)) verdict = "✅ DELIVERY MECHANICS WORK (assembled + promoted/bound; only the throwaway-address email failed)";
else if (compRes.status === 404 && /object not found/i.test(compText)) verdict = "❌ FAILED AT PROMOTION — the copy wall is still in the path (in-place not active?).";
else if (compRes.status === 502 && /assemble/i.test(compText)) verdict = "⚠️ Failed at multipart assembly — investigate separately.";
else verdict = `⚠️ Unexpected outcome ${compRes.status} — see body above.`;
console.log("\nRESULT:", verdict);

// Immutability probe: a spent part URL must be DEAD after completion (the uploadId was consumed) — this
// is the property that makes in-place delivery safe against post-validation swaps.
try {
  const spent = init.partUrls[0]!;
  const replay = await fetch(spent.url, { method: "PUT", body: partBody(spent.partNumber) });
  console.log(`immutability: replaying part ${spent.partNumber}'s spent URL -> HTTP ${replay.status} ${replay.ok ? "❌ STILL WRITABLE (BAD)" : "✅ dead (uploadId consumed)"}`);
} catch (e) {
  console.log(`immutability: spent part URL replay threw (${(e as Error).message}) ✅ dead`);
}

// Cleanup via the PROOF-GATED discard (the receiver identity lives in this script): frees the object now
// instead of waiting out the 7-day lifecycle. If the email failed (502), the worker already dropped the
// fetchbind, so the challenge 404s — the object then just expires via the lifecycle.
try {
  const ch = await post("/fetch/challenge", { objectId: init.objectId });
  if (!ch.ok) {
    console.log(`cleanup: challenge ${ch.status} (fetchbind gone) — the lifecycle reaps the object`);
  } else {
    const { challengeId, sealed: sealedNonce } = (await ch.json()) as { challengeId: string; sealed: string };
    const nonce = await hpkeUnseal(receiver.keyPair, base64urlDecode(sealedNonce), FETCH_CHALLENGE_INFO);
    const proof = await fetchProofHex(challengeId, init.objectId, nonce);
    const disc = await post("/discard", { challengeId, proof });
    console.log(`cleanup: proof-gated discard of ${init.objectId} -> ${disc.status}`);
  }
} catch (e) {
  console.log(`cleanup: skipped (${(e as Error).message}) — the lifecycle reaps the object`);
}
