// One-off: verify the LIVE staging Worker's MULTIPART path end-to-end against real R2.
// This is the one prod-only unknown the spec flagged: does a binding-created uploadId
// accept an S3-presigned UploadPart, and does binding complete() then assemble it?
// Mints a link offline (keys/staging.json), uploads a ~6 MiB FKEY-prefixed blob as two
// real parts, and completes. Requires staging MULTIPART_THRESHOLD set low (wrangler.toml).
//   bun run scripts/smoke-multipart.ts
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../web/core/src/index";
import { DROP_PAYLOAD_VERSION, LINK_ID_LEN, base64urlEncode, signableBytes } from "../shared/codec";
import { importKemPublicKey, importSignPrivateKey, sealEmail, signRegion } from "../shared/crypto";

const BASE = "https://filekey-drop-staging.rockwellshah.workers.dev";
const keys = (await Bun.file("keys/staging.json").json()) as { signPriv: JsonWebKey; kemPubHex: string };
const signPriv = await importSignPrivateKey(keys.signPriv);
const kemPub = await importKemPublicKey(Uint8Array.from(keys.kemPubHex.match(/../g)!.map((h) => parseInt(h, 16))));

const ns = new NamespaceSet(["filekey.app"]).namespaces[0]!;
const receiver = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
const sealed = await sealEmail(kemPub, Bun.argv[2] ?? "smoke-multipart@example.com");

const region = signableBytes({
  version: DROP_PAYLOAD_VERSION,
  keyId: 1, // matches the worker's default SERVER_SIGN_KEY_ID
  linkId: crypto.getRandomValues(new Uint8Array(LINK_ID_LEN)),
  shareKey: new TextEncoder().encode(shareKey),
  label: "Multipart smoke",
  sealedEmail: sealed,
});
const sig = await signRegion(signPriv, region);
const full = new Uint8Array(region.length + sig.length);
full.set(region, 0);
full.set(sig, region.length);
const payload = base64urlEncode(full);

const post = (path: string, body: unknown) =>
  fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

// ~6 MiB so it splits into 2 parts at a 5 MiB min part size (part 2 < 5 MiB is fine — it's last).
const SIZE = 6 * 1024 * 1024;
const blob = new Uint8Array(SIZE);
blob.set([0x46, 0x4b, 0x45, 0x59], 0); // FKEY magic for the server-side header check
blob[4] = 0x01; // FORMAT_VERSION
blob[5] = 0x01; // SUITE_ID
blob[145] = 17; // u32be metadata length @142 == 17 (passes validateFileKeyHeader)

console.log("1) upload-init ...");
const initRes = await post("/upload-init", { payload, size: SIZE });
const init = (await initRes.json()) as {
  mode?: string;
  objectId: string;
  uploadId: string;
  partSize: number;
  partCount: number;
  partUrls: { partNumber: number; url: string }[];
};
console.log("   ->", initRes.status, JSON.stringify({ mode: init.mode, partSize: init.partSize, partCount: init.partCount, urls: init.partUrls?.length }));
if (!initRes.ok || init.mode !== "multipart") {
  console.log("   EXPECTED multipart mode — is staging MULTIPART_THRESHOLD set low and the new worker deployed?");
  process.exit(1);
}

console.log(`2) PUT ${init.partCount} parts straight to R2 (presigned UploadPart) ...`);
const parts: { partNumber: number; etag: string }[] = [];
for (const { partNumber, url } of init.partUrls) {
  const start = (partNumber - 1) * init.partSize;
  const body = blob.subarray(start, Math.min(start + init.partSize, SIZE));
  const r = await fetch(url, { method: "PUT", body });
  const etag = r.headers.get("etag") ?? "";
  console.log(`   part ${partNumber}: ${r.status} ${body.length}B etag=${etag || "(none)"}`);
  if (!r.ok || !etag) {
    console.log("   ❌ R2 rejected the presigned UploadPart or returned no ETag — presign/CORS-free interop issue.");
    process.exit(1);
  }
  parts.push({ partNumber, etag });
}

console.log("3) upload-complete (binding complete assembles the parts) ...");
const compRes = await post("/upload-complete", { payload, objectId: init.objectId, parts });
const compText = (await compRes.text()).slice(0, 400);
console.log("   ->", compRes.status, compText);

console.log("\nstaging objectId:", init.objectId);
const interopWorked = compRes.status === 200 || (compRes.status === 502 && /delivery/i.test(compText));
console.log(
  interopWorked
    ? "RESULT: ✅ MULTIPART INTEROP WORKS — binding create + S3 presigned UploadPart + binding complete assembled the object on real R2."
    : /assemble/i.test(compText)
      ? "RESULT: ❌ INTEROP BROKEN at complete — switch r2.ts create/complete/abort to the all-S3 XML API (callers unchanged)."
      : `RESULT: ⚠️ Stopped at ${compRes.status} — see above.`,
);
