// Verify the LIVE staging Worker binds Content-Length into its presigned upload URLs so R2 rejects an
// oversized body (the "declare small, PUT big, never complete" abuse). Mints a signed link offline
// (keys/staging.json), then for BOTH the single-PUT and multipart-part paths asserts:
//   - PUT of EXACTLY the declared size  -> 2xx (a legitimate upload still works — no hero-path regression)
//   - PUT of declared size + 1 byte     -> 4xx (R2 enforces the signed Content-Length)
//   bun run scripts/smoke-contentlength.ts
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../web/core/src/index";
import { DROP_PAYLOAD_VERSION, LINK_ID_LEN, base64urlEncode, signableBytes } from "../shared/codec";
import { importKemPublicKey, importSignPrivateKey, sealEmail, signRegion } from "../shared/crypto";

const BASE = process.env.SMOKE_BASE ?? "https://filekey-drop-staging.rockwellshah.workers.dev";
const keys = (await Bun.file("keys/staging.json").json()) as { signPriv: JsonWebKey; kemPubHex: string };
const signPriv = await importSignPrivateKey(keys.signPriv);
const kemPub = await importKemPublicKey(Uint8Array.from(keys.kemPubHex.match(/../g)!.map((h) => parseInt(h, 16))));

async function mintLink(): Promise<string> {
  const ns = new NamespaceSet(["receive.link"]).namespaces[0]!;
  const receiver = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns);
  const shareKey = encodeShareKey(receiver.staticPkRaw, receiver.namespace);
  const sealed = await sealEmail(kemPub, "smoke-cl@example.com");
  const region = signableBytes({
    version: DROP_PAYLOAD_VERSION,
    keyId: 1,
    linkId: crypto.getRandomValues(new Uint8Array(LINK_ID_LEN)),
    shareKey: new TextEncoder().encode(shareKey),
    label: "CL smoke",
    sealedEmail: sealed,
  });
  const sig = await signRegion(signPriv, region);
  const full = new Uint8Array(region.length + sig.length);
  full.set(region, 0);
  full.set(sig, region.length);
  return base64urlEncode(full);
}

const post = (path: string, body: unknown) => fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const fkeyBlob = (n: number) => {
  const b = new Uint8Array(n);
  b.set([0x46, 0x4b, 0x45, 0x59], 0); // FKEY magic (cosmetic here; we test the PUT, not completion)
  return b;
};

let pass = 0;
let fail = 0;
const check = (name: string, ok: boolean, detail: string) => {
  console.log(`  ${ok ? "✅" : "❌"} ${name} — ${detail}`);
  ok ? pass++ : fail++;
};

// ---- Single PUT: declared size N, signed Content-Length = N ----
console.log("SINGLE PUT (declared 64 bytes):");
{
  const payload = await mintLink();
  const N = 64;
  const init = (await (await post("/upload-init", { payload, size: N })).json()) as { mode: string; uploadUrl: string };
  const exact = await fetch(init.uploadUrl, { method: "PUT", body: fkeyBlob(N) });
  check("exact-size PUT accepted", exact.ok, `${exact.status} (want 2xx)`);
  const over = await fetch(init.uploadUrl, { method: "PUT", body: fkeyBlob(N + 1) });
  check("oversized PUT rejected", over.status >= 400, `${over.status} (want 4xx)`);
}

// ---- Multipart part: declared 2 MiB -> one 5 MiB-min part sized to the remainder (2 MiB) ----
console.log("MULTIPART PART (declared 2 MiB):");
{
  const payload = await mintLink();
  const N = 2 * 1024 * 1024;
  const init = (await (await post("/upload-init", { payload, size: N })).json()) as { mode: string; uploadId: string; objectId: string; partUrls: { partNumber: number; url: string }[] };
  if (init.mode !== "multipart" || !init.partUrls?.length) {
    check("multipart plan returned", false, `mode=${init.mode}`);
  } else {
    const url = init.partUrls[0]!.url;
    const exact = await fetch(url, { method: "PUT", body: fkeyBlob(N) });
    check("exact-size part accepted", exact.ok, `${exact.status} (want 2xx)`);
    const over = await fetch(url, { method: "PUT", body: fkeyBlob(N + 1) });
    check("oversized part rejected", over.status >= 400, `${over.status} (want 4xx)`);
    await post("/upload-abort", { payload, objectId: init.objectId }); // clean up the multipart
  }
}

console.log(`\n${fail === 0 ? "✅ PASS" : "❌ FAIL"}: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
