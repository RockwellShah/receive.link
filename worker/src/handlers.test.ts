// End-to-end handler tests: the full register -> confirm -> upload protocol run
// through the real codec + crypto against in-memory bindings.
import { expect, test } from "bun:test";
import { base64urlDecode, base64urlEncode } from "../../shared/codec";
import { importKemPublicKey, sealEmail } from "../../shared/crypto";
import { hex } from "../../shared/util";
import {
  REG_EMAIL_PER_DAY,
  confirm,
  fetchObject,
  parseAndVerify,
  register,
  uploadComplete,
  uploadInit,
  uploadParts,
} from "./handlers";
import { CapturingEmail, makeTestEnv, type TestHarness } from "./testing";

function post(path: string, body: unknown, ip = "1.2.3.4"): Request {
  return new Request(`https://api.drop.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": ip },
    body: JSON.stringify(body),
  });
}

function nonceFrom(text: string): string {
  const m = text.match(/\/confirm#([A-Za-z0-9_-]+)/);
  if (!m) throw new Error(`no nonce in confirm email: ${text}`);
  return m[1]!;
}

async function sealed(h: TestHarness, email: string): Promise<string> {
  return base64urlEncode(await sealEmail(await importKemPublicKey(h.kemPublicRaw), email));
}

const SHARE_KEY = base64urlEncode(new Uint8Array(38).fill(9));

/** Run register + confirm, returning the finished signed Drop link. */
async function setupLink(h: TestHarness, email = "receiver@example.com", label = "Tax inbox"): Promise<string> {
  await register(post("/register", { sealedEmail: await sealed(h, email), shareKey: SHARE_KEY, label }), h.env);
  const nonce = nonceFrom(h.email.sent.at(-1)!.text!);
  const conf = await confirm(post("/confirm", { nonce }), h.env);
  return ((await conf.json()) as { link: string }).link;
}

// A minimally-valid FileKey container: magic + format version + suite + a sane metadata-length field
// (u32be at offset 142), zero-padded. Padded up to 146 (a full header) so the worker's header check
// accepts it; mirrors web/core/src/constants.ts.
function fkeyCiphertext(size: number): Uint8Array {
  const ct = new Uint8Array(Math.max(size, 200)); // >= 142+4+metaLen(17)+tag(16)=179, so the size check passes
  ct.set([0x46, 0x4b, 0x45, 0x59], 0); // "FKEY"
  ct[4] = 0x01; // FORMAT_VERSION
  ct[5] = 0x01; // SUITE_ID
  ct[145] = 17; // u32be metadata length at offset 142 == 17 (METADATA_CT_MIN)
  return ct;
}

test("full flow: register -> confirm -> upload-init -> upload-complete emails the receiver", async () => {
  const h = await makeTestEnv();

  const reg = await register(
    post("/register", { sealedEmail: await sealed(h, "receiver@example.com"), shareKey: SHARE_KEY, label: "Tax inbox" }),
    h.env,
  );
  expect(reg.status).toBe(202);
  expect(h.email.sent.length).toBe(1);
  expect(h.email.sent[0]!.to).toBe("receiver@example.com");
  expect(h.email.sent[0]!.from).toBe("FileKey Drop <files@send.test>");

  const conf = await confirm(post("/confirm", { nonce: nonceFrom(h.email.sent[0]!.text!) }), h.env);
  expect(conf.status).toBe(200);
  const link = ((await conf.json()) as { link: string }).link;
  expect((await parseAndVerify(link, h.env)).label).toBe("Tax inbox");

  const init = await uploadInit(post("/upload-init", { payload: link, size: 100 }), h.env);
  expect(init.status).toBe(200);
  const { objectId, uploadUrl } = (await init.json()) as { objectId: string; uploadUrl: string };
  expect(uploadUrl).toContain("X-Amz-Signature=");

  h.r2.putRaw(objectId, fkeyCiphertext(100)); // simulate the browser's direct PUT

  const comp = await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  expect(comp.status).toBe(200);
  expect(h.email.sent.length).toBe(3); // register (confirm) + confirm (drop-link) + this delivery
  const delivery = h.email.sent.at(-1)!;
  expect(delivery.to).toBe("receiver@example.com"); // unseal worked end-to-end
  expect(delivery.text).toContain("/d/");
  // Delivered under a fresh, sender-unknown final key (not the staging objectId),
  // and the staging object is cleaned up.
  const finalId = delivery.text!.match(/\/d\/([0-9a-f]{32})/)![1]!;
  expect(finalId).not.toBe(objectId);
  expect(await h.r2.head(finalId)).not.toBeNull();
  expect(await h.r2.head(objectId)).toBeNull();
});

test("upload-complete rejects bytes that aren't FileKey ciphertext (no open mailer)", async () => {
  const h = await makeTestEnv();
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 50 }), h.env)).json()) as {
    objectId: string;
  };
  h.r2.putRaw(objectId, new Uint8Array([1, 2, 3, 4, 5, 6])); // no FKEY magic
  const comp = await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  expect(comp.status).toBe(422);
  expect(h.email.sent.length).toBe(2); // only the two setup emails (confirm + drop link); no delivery
});

test("upload-complete is idempotent: one upload, one delivery email", async () => {
  const h = await makeTestEnv();
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 50 }), h.env)).json()) as {
    objectId: string;
  };
  h.r2.putRaw(objectId, fkeyCiphertext(50));
  await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  expect(h.email.sent.length).toBe(3); // 2 setup emails + 1 delivery (idempotent: not 2 deliveries)
});

test("byte budget is charged on the ACTUAL object size at complete, not the declared size", async () => {
  // 300-byte/day link budget; each upload is a real 200-byte object regardless of declared size.
  const h = await makeTestEnv({ UPLOAD_BYTES_PER_LINK_DAY: "300" });
  const link = await setupLink(h);
  const send = async (declared: number) => {
    const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: declared }), h.env)).json()) as { objectId: string };
    h.r2.putRaw(objectId, fkeyCiphertext(200)); // 200 actual bytes, whatever was declared
    return (await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status;
  };
  // First 200-byte upload fits the 300-byte budget. A spoofed-low declared size doesn't help: the
  // SECOND upload is charged its real 200 bytes (total 400 > 300) and is rejected at complete.
  expect(await send(200)).toBe(200);
  expect(await send(1)).toBe(429);
});

// MULTIPART_THRESHOLD/MIN_PART are forced tiny so a 200-byte file exercises the real multipart
// path (20 parts of 10 bytes) without moving 100+ MiB through the test. 200 bytes is also a full
// FileKey header, so the assembled object passes the worker's header validation.
test("multipart: a large upload splits into parts, assembles, and delivers", async () => {
  const h = await makeTestEnv({ MULTIPART_THRESHOLD: "10", MULTIPART_MIN_PART: "10" });
  const link = await setupLink(h);
  const init = await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env);
  expect(init.status).toBe(200);
  const mp = (await init.json()) as {
    mode: string;
    objectId: string;
    uploadId: string;
    partSize: number;
    partCount: number;
    partUrls: { partNumber: number; url: string }[];
  };
  expect(mp.mode).toBe("multipart");
  expect(mp.partSize).toBe(10);
  expect(mp.partCount).toBe(20);
  expect(mp.partUrls.length).toBe(20);
  expect(mp.partUrls[0]!.url).toContain("partNumber=1");
  expect(mp.partUrls[0]!.url).toContain("X-Amz-Signature=");

  // Simulate the browser's direct UploadPart PUTs: split one valid ciphertext into partSize chunks.
  const full = fkeyCiphertext(200);
  const parts: { partNumber: number; etag: string }[] = [];
  for (let n = 1; n <= mp.partCount; n++) {
    const chunk = full.subarray((n - 1) * mp.partSize, n * mp.partSize);
    parts.push({ partNumber: n, etag: h.r2.putPartRaw(mp.uploadId, n, chunk) });
  }

  const comp = await uploadComplete(post("/upload-complete", { payload: link, objectId: mp.objectId, parts }), h.env);
  expect(comp.status).toBe(200);
  const delivery = h.email.sent.at(-1)!;
  expect(delivery.text).toContain("/d/");
  // The assembled final object is the full 200 bytes (parts concatenated in order).
  const finalId = delivery.text!.match(/\/d\/([0-9a-f]{32})/)![1]!;
  expect((await h.r2.head(finalId))!.size).toBe(200);
});

// A delivery email that throws the first time it is called, then succeeds. Installed AFTER setup so
// register/confirm go through the harness's default email and only the first delivery fails.
class FailOnce extends CapturingEmail {
  failed = false;
  async send(message: Parameters<CapturingEmail["send"]>[0]): Promise<{ messageId: string }> {
    if (!this.failed) {
      this.failed = true;
      throw new Error("smtp down");
    }
    return super.send(message);
  }
}

test("multipart: delivery failure after assembly is retry-safe (retry skips the consumed uploadId)", async () => {
  const h = await makeTestEnv({ MULTIPART_THRESHOLD: "10", MULTIPART_MIN_PART: "10" });
  const link = await setupLink(h);
  const init = await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env);
  const mp = (await init.json()) as { objectId: string; uploadId: string; partSize: number; partCount: number };
  const full = fkeyCiphertext(200);
  const parts: { partNumber: number; etag: string }[] = [];
  for (let n = 1; n <= mp.partCount; n++) {
    const chunk = full.subarray((n - 1) * mp.partSize, n * mp.partSize);
    parts.push({ partNumber: n, etag: h.r2.putPartRaw(mp.uploadId, n, chunk) });
  }

  // Swap in a one-shot-failing email for the delivery (setup already used the default one).
  const failEmail = new FailOnce();
  h.env.EMAIL = failEmail;

  // First complete: the MPU assembles, but the delivery email throws -> retryable 502, staging kept.
  const first = await uploadComplete(post("/upload-complete", { payload: link, objectId: mp.objectId, parts }), h.env);
  expect(first.status).toBe(502);
  expect((await h.r2.head(mp.objectId))!.size).toBe(200); // assembled object survived for the retry
  expect(failEmail.sent.length).toBe(0); // delivery threw; nothing recorded

  // Retry: the uploadId is already consumed (CompleteMultipartUpload is one-shot). The fix must detect
  // the assembled object and skip re-completing — otherwise this 502s (or 500s) forever.
  const second = await uploadComplete(post("/upload-complete", { payload: link, objectId: mp.objectId, parts }), h.env);
  expect(second.status).toBe(200);
  expect(failEmail.sent.at(-1)!.text).toContain("/d/"); // delivered on the retry
});

test("multipart: a wrong part count is rejected (no partial assembly, no email)", async () => {
  const h = await makeTestEnv({ MULTIPART_THRESHOLD: "10", MULTIPART_MIN_PART: "10" });
  const link = await setupLink(h);
  const init = await uploadInit(post("/upload-init", { payload: link, size: 50 }), h.env);
  const mp = (await init.json()) as { objectId: string; uploadId: string };
  // Upload + claim only 3 of the required 5 parts.
  const parts: { partNumber: number; etag: string }[] = [];
  for (let n = 1; n <= 3; n++) parts.push({ partNumber: n, etag: h.r2.putPartRaw(mp.uploadId, n, n === 1 ? fkeyCiphertext(10) : new Uint8Array(10)) });
  const before = h.email.sent.length;
  const comp = await uploadComplete(post("/upload-complete", { payload: link, objectId: mp.objectId, parts }), h.env);
  expect(comp.status).toBe(400);
  expect(h.email.sent.length).toBe(before); // no delivery
});

test("upload-parts re-presigns the next batch on demand", async () => {
  const h = await makeTestEnv({ MULTIPART_THRESHOLD: "10", MULTIPART_MIN_PART: "10" });
  const link = await setupLink(h);
  const init = await uploadInit(post("/upload-init", { payload: link, size: 50 }), h.env);
  const mp = (await init.json()) as { objectId: string };
  const res = await uploadParts(post("/upload-parts", { payload: link, objectId: mp.objectId, from: 3, count: 2 }), h.env);
  expect(res.status).toBe(200);
  const { partUrls } = (await res.json()) as { partUrls: { partNumber: number; url: string }[] };
  expect(partUrls.map((p) => p.partNumber)).toEqual([3, 4]);
  expect(partUrls[0]!.url).toContain("partNumber=3");
});

test("upload-complete rejects an object paired with a different link than minted it", async () => {
  const h = await makeTestEnv();
  const linkA = await setupLink(h, "alice@example.com", "Alice");
  const linkB = await setupLink(h, "victim@example.com", "Victim");
  // Mint + upload an object under link A.
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: linkA, size: 50 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(50));
  // Completing it against the victim's link B must be rejected (no email to victim).
  const before = h.email.sent.length;
  const comp = await uploadComplete(post("/upload-complete", { payload: linkB, objectId }), h.env);
  expect(comp.status).toBe(400);
  expect(h.email.sent.length).toBe(before);
});

test("upload-complete honors a revocation set after init (on the delivery link)", async () => {
  const h = await makeTestEnv();
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 50 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(50));
  const linkId = (await parseAndVerify(link, h.env)).linkId;
  await h.kv.put(`revoked:${hex(linkId)}`, "1"); // receiver revokes between init and complete
  const comp = await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  expect(comp.status).toBe(410);
});

test("upload-init rejects a tampered link", async () => {
  const h = await makeTestEnv();
  const link = await setupLink(h);
  const bytes = base64urlDecode(link);
  bytes[20] = bytes[20]! ^ 0x01; // flip a byte inside the signed region
  const res = await uploadInit(post("/upload-init", { payload: base64urlEncode(bytes), size: 10 }), h.env);
  expect(res.status).toBe(400);
});

test("upload-init rejects an oversize file", async () => {
  const h = await makeTestEnv({ MAX_UPLOAD_BYTES: "1000" });
  const link = await setupLink(h);
  const res = await uploadInit(post("/upload-init", { payload: link, size: 1001 }), h.env);
  expect(res.status).toBe(413);
});

test("confirm rejects an unknown nonce", async () => {
  const h = await makeTestEnv();
  expect((await confirm(post("/confirm", { nonce: "nope" }), h.env)).status).toBe(404);
});

test("confirm consumes the nonce (single use)", async () => {
  const h = await makeTestEnv();
  await setupLink(h); // consumes the nonce
  const reused = await confirm(post("/confirm", { nonce: nonceFrom(h.email.sent[0]!.text!) }), h.env);
  expect(reused.status).toBe(404);
});

test("register stops emailing an address over its daily quota (anti-bombing)", async () => {
  const h = await makeTestEnv();
  const sealedEmail = await sealed(h, "victim@example.com");
  for (let i = 0; i < REG_EMAIL_PER_DAY; i++) {
    // vary IP so the per-IP limit doesn't trip before the per-address one
    const r = await register(post("/register", { sealedEmail, shareKey: SHARE_KEY, label: "x" }, `9.9.9.${i}`), h.env);
    expect(r.status).toBe(202);
  }
  expect(h.email.sent.length).toBe(REG_EMAIL_PER_DAY);
  const extra = await register(post("/register", { sealedEmail, shareKey: SHARE_KEY, label: "x" }, "9.9.9.250"), h.env);
  expect(extra.status).toBe(202); // silent
  expect(h.email.sent.length).toBe(REG_EMAIL_PER_DAY); // but no new email
});

test("register rejects a sealed value that isn't an email", async () => {
  const h = await makeTestEnv();
  const res = await register(
    post("/register", { sealedEmail: await sealed(h, "not-an-email"), shareKey: SHARE_KEY, label: "x" }),
    h.env,
  );
  expect(res.status).toBe(400);
});

test("fetch returns a presigned GET url for an existing object", async () => {
  const h = await makeTestEnv();
  const objectId = "00112233445566778899aabbccddeeff";
  h.r2.putRaw(objectId, fkeyCiphertext(64));
  const res = await fetchObject(new Request(`https://api.drop.test/fetch/${objectId}`), h.env, objectId);
  expect(res.status).toBe(200);
  const { url } = (await res.json()) as { url: string };
  expect(url).toContain(objectId);
  expect(url).toContain("X-Amz-Signature=");
});

test("fetch 404s a missing object and 400s a malformed id", async () => {
  const h = await makeTestEnv();
  const missing = "ab".repeat(16);
  expect((await fetchObject(new Request(`https://api/fetch/${missing}`), h.env, missing)).status).toBe(404);
  expect((await fetchObject(new Request("https://api/fetch/xyz"), h.env, "xyz")).status).toBe(400);
});
