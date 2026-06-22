// End-to-end handler tests: the full register -> confirm -> upload protocol run
// through the real codec + crypto against in-memory bindings.
import { expect, test } from "bun:test";
import { base64urlDecode, base64urlEncode } from "../../shared/codec";
import { FETCH_CHALLENGE_INFO, fetchProofHex, generateKemKeyPair, hpkeUnseal, importKemPublicKey, sealEmail, serializeKemPublicKey } from "../../shared/crypto";
import { hex } from "../../shared/util";
import { p256 } from "@noble/curves/nist.js";
import { bech32m } from "@scure/base";
import {
  REG_EMAIL_PER_DAY,
  confirm,
  fetchChallenge,
  fetchDownload,
  fetchPreview,
  parseAndVerify,
  receiverId,
  register,
  uploadComplete,
  uploadInit,
  uploadParts,
} from "./handlers";
import { CapturingEmail, MemoryCompletion, MemoryReceiver, makeTestEnv, type SentMail, type TestHarness } from "./testing";

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

// A real receiver KEM keypair whose public key we encode as a valid Bech32m "fkey" share key, so the
// Worker can decode it + seal a download-gate challenge to it; RECEIVER unseals those challenges below.
// (The namespace tag is irrelevant to the gate decode — it only extracts the public point — so a
// placeholder 4-zero tag is fine.)
const RECEIVER = await generateKemKeyPair();
function shareKeyFor(pkRaw: Uint8Array): string {
  const payload = new Uint8Array([0x01, 0, 0, 0, 0, ...p256.Point.fromBytes(pkRaw).toBytes(true)]); // version || nsTag(4) || compressed(33)
  return base64urlEncode(new TextEncoder().encode(bech32m.encode("fkey", bech32m.toWords(payload), 1023)));
}
const SHARE_KEY = shareKeyFor(await serializeKemPublicKey(RECEIVER.publicKey));

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
  expect(h.email.sent[0]!.from).toBe("receive.link <files@send.test>");

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

test("recipient capacity is per-recipient (shared across a receiver's links) and charged on the actual size", async () => {
  // 300-byte ceiling. Two SEPARATE links confirmed to the SAME email resolve to one account (rid is a
  // keyed hash of the confirmed email), so they draw down ONE shared budget — per-recipient, not per-link.
  const h = await makeTestEnv({ RECEIVER_INBOUND_CAP_BYTES: "300" });
  const linkA = await setupLink(h, "shared@example.com", "A");
  const linkB = await setupLink(h, "shared@example.com", "B");
  const before = h.email.sent.length;
  const send = async (link: string, declared: number) => {
    const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: declared }), h.env)).json()) as { objectId: string };
    h.r2.putRaw(objectId, fkeyCiphertext(200)); // 200 real bytes, whatever was declared
    return (await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status;
  };
  expect(await send(linkA, 200)).toBe(200); // 200 <= 300
  // The tiny declared size (1) slips the init pre-check; the actual 200 bytes are charged at complete on
  // the OTHER link: 200 + 200 = 400 > 300, rejected there, the recipient never emailed.
  expect(await send(linkB, 1)).toBe(507);
  expect(h.email.sent.length).toBe(before + 1); // only the first upload delivered
});

test("recipient links keyed to DIFFERENT confirmed emails have independent capacity", async () => {
  // Same 300-byte ceiling, but two different recipients each get their own budget.
  const h = await makeTestEnv({ RECEIVER_INBOUND_CAP_BYTES: "300" });
  const send = async (link: string) => {
    const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
    h.r2.putRaw(objectId, fkeyCiphertext(200));
    return (await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status;
  };
  // Two 200-byte uploads, one to each recipient, both succeed — neither eats the other's quota.
  expect(await send(await setupLink(h, "alice@example.com", "A"))).toBe(200);
  expect(await send(await setupLink(h, "bob@example.com", "B"))).toBe(200);
});

test("recipient capacity: a retried completion after a delivery failure counts the bytes once", async () => {
  // 450-byte ceiling. One 200-byte upload whose first delivery email throws, then succeeds when the
  // SAME completion retries. The failed attempt's reservation is released in the finally, so the retry
  // re-reserves to a clean total (counted once), not double-counted.
  const h = await makeTestEnv({ RECEIVER_INBOUND_CAP_BYTES: "450" });
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(200));
  h.env.EMAIL = new FailOnce();
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(502); // charged, then email throws -> refunded
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(200); // retry re-charges + delivers

  // A second, distinct 200-byte upload brings the total to 400 (<= 450) and is accepted. Had the failed
  // attempt's hold NOT been released, the total would already be 400 and this would be 600 > 450 and
  // rejected, so its success proves the first upload was counted exactly once.
  const { objectId: o2 } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(o2, fkeyCiphertext(200));
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId: o2 }), h.env)).status).toBe(200);
});

test("recipient capacity: a retry can't overwrite mutable staging to deliver more than was charged", async () => {
  // 300-byte ceiling. First completion reserves the real 200 bytes, then the delivery email fails (502)
  // and the hold is released. The sender overwrites the still-mutable staging object to 400 bytes (the
  // presigned PUT stays valid) and retries: the retry must re-reserve the CURRENT 400 bytes (400 > 300)
  // and reject, not deliver 400 while having counted only 200.
  const h = await makeTestEnv({ RECEIVER_INBOUND_CAP_BYTES: "300" });
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(200));
  const fail = new FailOnce();
  h.env.EMAIL = fail;
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(502); // charged 200, email throws -> refunded
  h.r2.putRaw(objectId, fkeyCiphertext(400)); // attacker overwrites staging via the still-valid presigned PUT
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(507); // 400 > 300 -> rejected
  expect(fail.sent.length).toBe(0); // never delivered the oversized object
});

test("upload-complete fails fast (503, no side effects) when RECEIVER_ID_SECRET is unset", async () => {
  // A misconfigured deploy must not do work (copy, byte-budget charges) then throw late deriving rid.
  const h = await makeTestEnv({ RECEIVER_ID_SECRET: "" });
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(200));
  const before = h.email.sent.length;
  const comp = await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  expect(comp.status).toBe(503);
  expect(h.email.sent.length).toBe(before); // no delivery
  expect(await h.r2.head(objectId)).not.toBeNull(); // staging untouched (guard fired before the copy)
});

test("an over-capacity rejection does not burn the daily byte budget", async () => {
  // The recipient charge at COMPLETE runs BEFORE the byte budgets and on the ACTUAL object size, so a
  // spoofed-low declared size slips the init pre-check yet the 507 at complete still leaves no byte-budget
  // counters — a rejected upload can't eat the link/IP transfer quota that real deliveries need.
  const h = await makeTestEnv({ RECEIVER_INBOUND_CAP_BYTES: "100" });
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 1 }), h.env)).json()) as { objectId: string }; // declared 1 slips the pre-check
  h.r2.putRaw(objectId, fkeyCiphertext(200)); // actual 200 > 100 cap -> charged + rejected at complete
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(507);
  expect([...h.kv.store.keys()].some((k) => k.startsWith("rlb:up:bytes:"))).toBe(false);
});

test("reclaim race: a duplicate delivery that lost the exactly-once race releases its hold (charges once)", async () => {
  // Simulate a stalled+reclaimed sibling finishing during our email send: the completion flips to "done"
  // mid-send, so our finish() returns "already" and we must RELEASE the capacity reservation, not commit
  // it. Without commit-on-won this is the double-charge Codex flagged.
  const h = await makeTestEnv({ RECEIVER_INBOUND_CAP_BYTES: "1000" });
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(200));
  const completion = h.env.COMPLETION as unknown as MemoryCompletion;
  h.env.EMAIL = new (class extends CapturingEmail {
    async send(m: SentMail): Promise<{ messageId: string }> {
      completion.forceDone(objectId); // another attempt wins the race just before our send lands
      return super.send(m);
    }
  })();
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(200); // still delivered (a duplicate)

  // The 200 bytes were RELEASED, not committed: a fresh 1000-byte upload to the same recipient fits the
  // 1000 cap. Had we wrongly committed, total would be 200 and this would be 1200 > 1000 -> 507.
  h.env.EMAIL = new CapturingEmail();
  const { objectId: o2 } = (await (await uploadInit(post("/upload-init", { payload: link, size: 1000 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(o2, fkeyCiphertext(1000));
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId: o2 }), h.env)).status).toBe(200);
});

test("recipient capacity: a live reservation holds against the cap so concurrent uploads can't both slip", async () => {
  // The handler path is linear per request, so exercise the hold directly on the account: a still-open
  // reservation must count against the cap, and releasing it must free the space again.
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-concurrency"));
  const first = await acct.reserve(200, 300, 0); // free tier (default) -> the freeCap (300) applies
  expect(first.ok).toBe(true);
  expect((await acct.reserve(200, 300, 0)).ok).toBe(false); // 0 + 200(held) + 200 = 400 > 300
  if (first.ok) await acct.release(first.token);
  expect((await acct.reserve(200, 300, 0)).ok).toBe(true); // hold freed -> fits again
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

// ---- Download gate (passkey-proof at /fetch) ----

/** Deliver a file to the default RECEIVER via `link`; return the /d/<finalId> object id for gate tests. */
async function deliver(h: TestHarness, link: string, size = 200): Promise<string> {
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(size));
  await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env);
  return h.email.sent.at(-1)!.text!.match(/\/d\/([0-9a-f]{32})/)![1]!;
}

/** Client half of the gate: challenge for `finalId`, unseal the nonce with `identity`, derive the proof
 *  (over `objectIdForProof`, default the real one). */
async function challengeAndProof(h: TestHarness, finalId: string, identity: typeof RECEIVER, objectIdForProof = finalId): Promise<{ challengeId: string; proof: string }> {
  const { challengeId, sealed } = (await (await fetchChallenge(post("/fetch/challenge", { objectId: finalId }), h.env)).json()) as { challengeId: string; sealed: string };
  const nonce = await hpkeUnseal(identity, base64urlDecode(sealed), FETCH_CHALLENGE_INFO);
  return { challengeId, proof: await fetchProofHex(challengeId, objectIdForProof, nonce) };
}

test("download gate: the receiver proves possession and gets a short-lived URL (real HPKE round-trip)", async () => {
  const h = await makeTestEnv();
  const finalId = await deliver(h, await setupLink(h));
  const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
  const res = await fetchDownload(post("/fetch/download", { challengeId, proof }), h.env);
  expect(res.status).toBe(200);
  const { url, expiresInSec } = (await res.json()) as { url: string; expiresInSec: number };
  expect(url).toContain(finalId);
  expect(url).toContain("X-Amz-Signature=");
  expect(expiresInSec).toBeLessThanOrEqual(600); // short, not the 1h upload presign
});

test("download gate: a proof is single-use (replay after success is 404)", async () => {
  const h = await makeTestEnv();
  const finalId = await deliver(h, await setupLink(h));
  const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
  expect((await fetchDownload(post("/fetch/download", { challengeId, proof }), h.env)).status).toBe(200);
  expect((await fetchDownload(post("/fetch/download", { challengeId, proof }), h.env)).status).toBe(404); // consumed
});

test("download gate: a different passkey identity cannot unseal the challenge", async () => {
  const h = await makeTestEnv();
  const finalId = await deliver(h, await setupLink(h));
  const wrong = await generateKemKeyPair();
  const { sealed } = (await (await fetchChallenge(post("/fetch/challenge", { objectId: finalId }), h.env)).json()) as { sealed: string };
  await expect(hpkeUnseal(wrong, base64urlDecode(sealed), FETCH_CHALLENGE_INFO)).rejects.toThrow();
});

test("download gate: a wrong proof is rejected (403) and consumes the challenge", async () => {
  const h = await makeTestEnv();
  const finalId = await deliver(h, await setupLink(h));
  const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
  expect((await fetchDownload(post("/fetch/download", { challengeId, proof: "00".repeat(32) }), h.env)).status).toBe(403);
  expect((await fetchDownload(post("/fetch/download", { challengeId, proof }), h.env)).status).toBe(404); // even the real proof now: consumed
});

test("download gate: a proof bound to a different object is rejected (403)", async () => {
  const h = await makeTestEnv();
  const link = await setupLink(h);
  const finalA = await deliver(h, link);
  const finalB = await deliver(h, link);
  // Challenge for A but compute the proof over B's id -> won't match A's stored expected proof.
  const { challengeId, proof } = await challengeAndProof(h, finalA, RECEIVER, finalB);
  expect((await fetchDownload(post("/fetch/download", { challengeId, proof }), h.env)).status).toBe(403);
});

test("download gate: a challenge for an unbound object id is 404 (hard cutover, no open fetch)", async () => {
  const h = await makeTestEnv();
  expect((await fetchChallenge(post("/fetch/challenge", { objectId: "ab".repeat(16) }), h.env)).status).toBe(404);
});

test("upload-complete fails closed (no delivery) when the share key can't be decoded for the gate", async () => {
  const h = await makeTestEnv();
  const badShareKey = base64urlEncode(new Uint8Array(38).fill(9)); // not a valid Bech32m "fkey" string
  await register(post("/register", { sealedEmail: await sealed(h, "r@example.com"), shareKey: badShareKey, label: "x" }), h.env);
  const link = ((await (await confirm(post("/confirm", { nonce: nonceFrom(h.email.sent.at(-1)!.text!) }), h.env)).json()) as { link: string }).link;
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(200));
  const before = h.email.sent.length;
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(400); // decode failed -> no delivery
  expect(h.email.sent.length).toBe(before); // no delivery email
  expect([...h.kv.store.keys()].some((k) => k.startsWith("rlb:up:bytes:"))).toBe(false); // decode (now pre-budget) didn't burn budget
});

// ---- Phase 2: billing (download charge + free preview + caps) ----

/** The account DO for the default setupLink receiver (to assert balances/pending directly). */
function defaultAccount(h: TestHarness, email = "receiver@example.com") {
  return receiverId(h.env, email).then((rid) => h.env.RECEIVER.get(h.env.RECEIVER.idFromName(rid)));
}
/** Run the charged-download gate for finalId and return the Response. */
async function download(h: TestHarness, finalId: string): Promise<Response> {
  const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
  return fetchDownload(post("/fetch/download", { challengeId, proof }), h.env);
}

test("billing: a download charges the file size once; a re-download does not double-charge", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "1000" });
  const finalId = await deliver(h, await setupLink(h), 200);
  const acct = await defaultAccount(h);
  expect((await acct.summary(1000)).pending).toBe(200); // delivered, not yet downloaded
  expect((await download(h, finalId)).status).toBe(200);
  expect((await acct.summary(1000)).balance).toBe(800); // charged 200 once (1000 grant -> 800)
  expect((await acct.summary(1000)).pending).toBe(0); // downloaded -> no longer pending
  expect((await download(h, finalId)).status).toBe(200); // re-download is free...
  expect((await acct.summary(1000)).balance).toBe(800); // ...balance unchanged (not charged again)
});

test("billing: a download beyond remaining credit returns 402 and isn't charged", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "300" });
  const link = await setupLink(h);
  const a = await deliver(h, link, 200);
  const b = await deliver(h, link, 200);
  const acct = await defaultAccount(h);
  expect((await download(h, a)).status).toBe(200); // 300 -> 100
  expect((await download(h, b)).status).toBe(402); // needs 200, only 100 left
  expect((await acct.summary(300)).balance).toBe(100); // the 402 left the balance untouched
});

test("billing: the default 1 GB free grant covers a normal small download", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1" }); // default grant = 1 GiB
  const finalId = await deliver(h, await setupLink(h), 200);
  expect((await download(h, finalId)).status).toBe(200);
});

test("billing OFF (default): a download is free with no balance (Phase-1 behavior, inert)", async () => {
  const h = await makeTestEnv(); // BILLING_ENABLED unset
  const finalId = await deliver(h, await setupLink(h), 200);
  const acct = await defaultAccount(h);
  expect((await download(h, finalId)).status).toBe(200);
  expect((await acct.summary(0)).balance).toBe(0); // never seeded/charged: the charge path was skipped
});

test("download gate: preview serves only the head+metadata, never the payload (free, even at zero balance)", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "0" }); // broke account: preview still free
  const finalId = await deliver(h, await setupLink(h), 5000); // 5000-byte object, 17-byte metadata
  const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
  const res = await fetchPreview(post("/fetch/preview", { challengeId, proof }), h.env);
  expect(res.status).toBe(200);
  const bytes = new Uint8Array(await res.arrayBuffer());
  expect(bytes.length).toBeGreaterThanOrEqual(146); // the full fixed header is present...
  expect(bytes.length).toBeLessThan(5000); // ...but the payload is NOT served for free
});

test("download gate: preview still requires a valid proof (a wrong proof is 403)", async () => {
  const h = await makeTestEnv();
  const finalId = await deliver(h, await setupLink(h), 200);
  const { challengeId } = await challengeAndProof(h, finalId, RECEIVER);
  expect((await fetchPreview(post("/fetch/preview", { challengeId, proof: "00".repeat(32) }), h.env)).status).toBe(403);
});

test("upload-init pre-check: a free account at its inbound cap bounces (507) before the transfer", async () => {
  const h = await makeTestEnv({ RECEIVER_INBOUND_CAP_BYTES: "300" });
  const link = await setupLink(h);
  await deliver(h, link, 200); // committed total -> 200
  // A further 200 would push total to 400 > 300, so the pre-check bounces at init (no upload URL issued).
  expect((await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).status).toBe(507);
});

test("upload-init pre-check: stays inert (no bounce) while caps are unset", async () => {
  const h = await makeTestEnv(); // both caps unset
  const link = await setupLink(h);
  await deliver(h, link, 200);
  // A 1 GB upload (well past the 1 GB+ a free cap would impose) is still admitted, because no cap is set.
  expect((await uploadInit(post("/upload-init", { payload: link, size: 1_000_000_000 }), h.env)).status).toBe(200);
});

test("receiver DO: caps are tier-aware (free gates on total, paid gates on at-rest pending)", async () => {
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-tier"));
  const h1 = await acct.reserve(200, 300, 1000); // free tier: freeCap=300, paidCap=1000
  expect(h1.ok).toBe(true);
  if (h1.ok) await acct.commit(h1.token); // total=200, pending=200
  expect((await acct.reserve(200, 300, 1000)).ok).toBe(false); // free: total 200 + 200 > 300
  await acct.credit(500, 0); // flip to paid (and add credit)
  const h2 = await acct.reserve(200, 300, 1000); // paid now gates on pending (200) vs 1000, not total vs 300
  expect(h2.ok).toBe(true);
});

test("receiver DO: pending rises on delivery and falls once on the first paid download", async () => {
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-pending"));
  const h1 = await acct.reserve(500, 0, 0); // uncapped
  expect(h1.ok).toBe(true);
  if (h1.ok) await acct.commit(h1.token);
  expect((await acct.summary(1000)).pending).toBe(500);
  const r = await acct.charge("file-1", 500, 1000);
  expect(r.ok && !r.alreadyPaid).toBe(true);
  expect((await acct.summary(1000)).balance).toBe(500); // 1000 grant - 500
  expect((await acct.summary(1000)).pending).toBe(0); // decremented on download
  const r2 = await acct.charge("file-1", 500, 1000); // re-download
  expect(r2.ok && r2.alreadyPaid).toBe(true);
  expect((await acct.summary(1000)).balance).toBe(500); // not charged again
  expect((await acct.summary(1000)).pending).toBe(0); // not decremented again
});

test("receiver DO: credit is idempotent on the Stripe event id", async () => {
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-credit"));
  await acct.credit(1000, 0, "evt_1");
  await acct.credit(1000, 0, "evt_1"); // webhook retry: must not double-credit
  expect((await acct.summary(0)).balance).toBe(1000);
  await acct.credit(1000, 0, "evt_2"); // a new event does credit
  expect((await acct.summary(0)).balance).toBe(2000);
});
