// End-to-end handler tests: the full register -> confirm -> upload protocol run
// through the real codec + crypto against in-memory bindings.
import { expect, test } from "bun:test";
import { DROP_PAYLOAD_VERSION, LINK_ID_LEN, base64urlDecode, base64urlEncode, signableBytes } from "../../shared/codec";
import { FETCH_CHALLENGE_INFO, fetchProofHex, generateKemKeyPair, hpkeUnseal, importKemPublicKey, importSignPrivateKey, sealEmail, serializeKemPublicKey, signRegion } from "../../shared/crypto";
import { RECEIVE_LINK_NS_TAG } from "../../shared/sharekey";
import { hex, hmacSha256hex, isEmail, randomBytes } from "../../shared/util";
import { p256 } from "@noble/curves/nist.js";
import { bech32m } from "@scure/base";
import {
  BILLING_CHECKOUT_RID_PER_DAY,
  REG_EMAIL_PER_DAY,
  billingCheckout,
  billingPacks,
  billingWebhook,
  canonEmail,
  confirm,
  discardObject,
  fetchChallenge,
  fetchDownload,
  fetchPreview,
  parseAndVerify,
  receiverId,
  register,
  uploadAbort,
  uploadComplete,
  uploadInit,
  uploadParts,
} from "./handlers";
import { checkoutSessionParams, createCheckoutSession, customPriceParams, packList, parseCreditFromEvent, priceCentsPerGb, verifyStripeSignature } from "./stripe";
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
// The namespace tag must be the receive.link tag: the decode now ENFORCES it (links minted under the old
// "filekey.app" namespace fail closed by design).
const RECEIVER = await generateKemKeyPair();
function shareKeyFor(pkRaw: Uint8Array): string {
  const payload = new Uint8Array([0x01, ...RECEIVE_LINK_NS_TAG, ...p256.Point.fromBytes(pkRaw).toBytes(true)]); // version || nsTag(4) || compressed(33)
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

test("canonEmail collapses +tag and Gmail-dot sub-addressing (one mailbox = one identity/quota)", () => {
  // +tag stripped for any domain (universal sub-addressing convention).
  expect(canonEmail("me+filekey@gmail.com")).toBe("me@gmail.com");
  expect(canonEmail("me+1@outlook.com")).toBe("me@outlook.com");
  expect(canonEmail(" Me+Tag@Fastmail.com ")).toBe("me@fastmail.com"); // trim + lowercase too
  // Gmail (and its googlemail alias) ignore dots in the local part; other providers do NOT.
  expect(canonEmail("rock.well.shah@gmail.com")).toBe("rockwellshah@gmail.com");
  expect(canonEmail("rock.well+x@googlemail.com")).toBe("rockwell@gmail.com"); // alias folds to gmail.com
  expect(canonEmail("first.last@outlook.com")).toBe("first.last@outlook.com"); // dots kept for non-Gmail
  // Plain addresses are untouched — so this change is a no-op for every normal account.
  expect(canonEmail("receiver@example.com")).toBe("receiver@example.com");
  // A leading '+' has no base local part, so it is NOT stripped (avoids an empty-local "@domain" key).
  expect(canonEmail("+x@example.com")).toBe("+x@example.com");
});

test("isEmail rejects display-name/angle-addr and trailing-dot forms that would poison the identity", () => {
  // The farming bypass Codex caught: a lenient provider may deliver "x<victim@gmail.com>" to
  // victim@gmail.com while canonEmail would hash the whole string as a distinct rid. Reject it up front.
  expect(isEmail("x<victim@gmail.com>")).toBe(false);
  expect(isEmail("victim <victim@gmail.com>")).toBe(false); // classic display-name form (space + angle)
  expect(isEmail("vic.tim+1@gmail.com.")).toBe(false); // trailing-dot domain
  expect(isEmail("a@b@gmail.com")).toBe(false); // two addr-specs / injection
  expect(isEmail("a,b@gmail.com")).toBe(false); // comma (header injection shape)
  expect(isEmail("a@gmail..com")).toBe(false); // duplicate domain dots
  expect(isEmail("a b@gmail.com")).toBe(false); // whitespace
  // Legit addresses still pass (no regression for real users).
  for (const ok of ["victim@gmail.com", "me+tag@gmail.com", "first.last@sub.example.co.uk", "o'brien@corp.com", "a@b.co"]) {
    expect(isEmail(ok)).toBe(true);
  }
});

test("canonEmail: +tag and dot variants of one Gmail resolve to the SAME receiver account (no free-grant farming)", async () => {
  const h = await makeTestEnv();
  const base = await receiverId(h.env, "victim@gmail.com");
  expect(await receiverId(h.env, "victim+1@gmail.com")).toBe(base); // +tag can't mint a fresh account
  expect(await receiverId(h.env, "vic.tim@gmail.com")).toBe(base); // Gmail dots can't either
  expect(await receiverId(h.env, "victim+anything@googlemail.com")).toBe(base);
  // A genuinely different mailbox is still a different account.
  expect(await receiverId(h.env, "someone-else@gmail.com")).not.toBe(base);
});

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
  // Capacity = the 300-byte balance. Two SEPARATE links confirmed to the SAME email resolve to one
  // account (rid is a keyed hash of the confirmed email), so they draw down ONE shared capacity.
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "300" });
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
  // Same 300-byte balance, but two different recipients each get their own.
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "300" });
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
  // 450-byte capacity. One 200-byte upload whose first delivery email throws, then succeeds when the
  // SAME completion retries. The failed attempt's reservation is released in the finally, so the retry
  // re-reserves to a clean basis (counted once), not double-counted.
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "450" });
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
  // 300-byte capacity. First completion reserves the real 200 bytes, then the delivery email fails (502)
  // and the hold is released. The sender overwrites the still-mutable staging object to 400 bytes (the
  // presigned PUT stays valid) and retries: the retry must re-reserve the CURRENT 400 bytes (400 > 300)
  // and reject, not deliver 400 while having counted only 200.
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "300" });
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
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "100" });
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
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "1000" });
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

  // The duplicate's gate binding + object are torn down, so opening its /d/<finalId> email can't trigger a
  // SECOND download charge (billing is keyed by finalId; the winner's own finalId is distinct).
  const dupFinalId = (h.env.EMAIL as CapturingEmail).sent.at(-1)!.text!.match(/\/d\/([0-9a-f]+)/)![1]!;
  expect(await h.env.DROP_KV.get(`fetchbind:${dupFinalId}`)).toBeNull();
  expect(await h.env.DROP_BUCKET.get(dupFinalId)).toBeNull();

  // The 200 bytes were RELEASED, not committed: a fresh 1000-byte upload to the same recipient fits the
  // 1000 cap. Had we wrongly committed, total would be 200 and this would be 1200 > 1000 -> 507.
  h.env.EMAIL = new CapturingEmail();
  const { objectId: o2 } = (await (await uploadInit(post("/upload-init", { payload: link, size: 1000 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(o2, fkeyCiphertext(1000));
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId: o2 }), h.env)).status).toBe(200);
});

/** Drive a full multipart upload through init + part PUTs, returning what complete needs. */
async function multipartUpload(h: TestHarness, link: string, size: number): Promise<{ objectId: string; parts: { partNumber: number; etag: string }[] }> {
  const init = (await (await uploadInit(post("/upload-init", { payload: link, size }), h.env)).json()) as {
    mode: string; objectId: string; uploadId: string; partSize: number; partCount: number;
  };
  expect(init.mode).toBe("multipart");
  const blob = fkeyCiphertext(size);
  const parts: { partNumber: number; etag: string }[] = [];
  for (let n = 1; n <= init.partCount; n++) {
    const start = (n - 1) * init.partSize;
    parts.push({ partNumber: n, etag: h.r2.putPartRaw(init.uploadId, n, blob.subarray(start, Math.min(start + init.partSize, blob.length))) });
  }
  return { objectId: init.objectId, parts };
}

test("in-place delivery: a multipart upload delivers under its OWN id (no copy), object survives", async () => {
  const h = await makeTestEnv({ MULTIPART_THRESHOLD: "10", MULTIPART_MIN_PART: "50" });
  const link = await setupLink(h);
  const { objectId, parts } = await multipartUpload(h, link, 200);
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId, parts }), h.env)).status).toBe(200);
  const emailedId = h.email.sent.at(-1)!.text!.match(/\/d\/([0-9a-f]+)/)![1]!;
  expect(emailedId).toBe(objectId); // delivered IN PLACE: the emailed id IS the staging id
  expect(await h.env.DROP_BUCKET.get(objectId)).not.toBeNull(); // the object survives at that key
  expect(await h.env.DROP_KV.get(`fetchbind:${objectId}`)).not.toBeNull(); // gate bound to the same id
  expect(h.kv.store.has(`upload:${objectId}`)).toBe(false); // upload binding spent
});

test("cutover: a LEGACY multipart binding (no inplace flag) still promotes via the copy path", async () => {
  const h = await makeTestEnv({ MULTIPART_THRESHOLD: "10", MULTIPART_MIN_PART: "50" });
  const link = await setupLink(h);
  const { objectId, parts } = await multipartUpload(h, link, 200);
  // Simulate a binding minted by the PREVIOUS worker build: strip the inplace flag (SPEC-large-files A2).
  const bind = JSON.parse((await h.env.DROP_KV.get(`upload:${objectId}`))!) as { inplace?: boolean };
  delete bind.inplace;
  await h.kv.put(`upload:${objectId}`, JSON.stringify(bind));
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId, parts }), h.env)).status).toBe(200);
  const emailedId = h.email.sent.at(-1)!.text!.match(/\/d\/([0-9a-f]+)/)![1]!;
  expect(emailedId).not.toBe(objectId); // legacy semantics: promoted to a fresh sender-unknown id
  expect(await h.env.DROP_BUCKET.get(emailedId)).not.toBeNull();
  expect(await h.env.DROP_BUCKET.get(objectId)).toBeNull(); // staging cleaned up as before
});

test("reclaim race (in-place): the duplicate keeps the SHARED object and inbound counts once", async () => {
  const h = await makeTestEnv({ MULTIPART_THRESHOLD: "10", MULTIPART_MIN_PART: "50", BILLING_ENABLED: "1", FREE_GRANT_BYTES: "1000" });
  const link = await setupLink(h);
  const { objectId, parts } = await multipartUpload(h, link, 200);
  const completion = h.env.COMPLETION as unknown as MemoryCompletion;
  h.env.EMAIL = new (class extends CapturingEmail {
    async send(m: SentMail): Promise<{ messageId: string }> {
      completion.forceDone(objectId); // a reclaimed sibling wins the race just before our send lands
      return super.send(m);
    }
  })();
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId, parts }), h.env)).status).toBe(200);
  // IN-PLACE: the sibling delivered the SAME id, so the duplicate must delete NOTHING (the object and
  // gate binding are the winner's delivery), and the meter counts the file once (idempotent by id).
  expect(await h.env.DROP_BUCKET.get(objectId)).not.toBeNull();
  expect(await h.env.DROP_KV.get(`fetchbind:${objectId}`)).not.toBeNull();
  const acct = await defaultAccount(h);
  expect((await acct.summary(0)).total).toBe(200); // once, not twice
  expect((await acct.summary(0)).reserved).toBe(0); // the hold was released
});

test("byte budgets burn once per object across a 502 email-failure retry", async () => {
  const h = await makeTestEnv();
  const link = await setupLink(h);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(200));
  let failOnce = true;
  h.env.EMAIL = new (class extends CapturingEmail {
    async send(m: SentMail): Promise<{ messageId: string }> {
      if (failOnce) { failOnce = false; throw new Error("smtp down"); }
      return super.send(m);
    }
  })();
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(502);
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(200); // retry delivers
  // The daily byte budget was consumed ONCE for this object (the retry saw the bb: marker), so a big
  // file's transient failure can't eat the link's whole daily budget.
  const linkBudget = [...h.kv.store.entries()].find(([k]) => k.startsWith("rlb:up:bytes:link:"));
  expect(linkBudget).toBeDefined();
  expect(Number(linkBudget![1])).toBe(200); // once, not 400
});

test("recipient capacity: a live reservation holds against the balance so concurrent uploads can't both slip", async () => {
  // The handler path is linear per request, so exercise the hold directly on the account: a still-open
  // reservation must count against the capacity (= balance), and releasing it must free the space again.
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-concurrency"));
  const first = await acct.reserve(200, 300, true); // fresh account: capacity = the 300 grant
  expect(first.ok).toBe(true);
  expect((await acct.reserve(200, 300, true)).ok).toBe(false); // 0 at rest + 200(held) + 200 = 400 > 300
  if (first.ok) await acct.release(first.token);
  expect((await acct.reserve(200, 300, true)).ok).toBe(true); // hold freed -> fits again
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
  // register now REJECTS an undecodable share key at mint time, so forge a signed link directly — the
  // shape of a LEGACY link minted before that validation. The completion-time decode is the
  // defense-in-depth gate and must still fail closed for such a link.
  const region = signableBytes({
    version: DROP_PAYLOAD_VERSION,
    keyId: 1,
    linkId: randomBytes(LINK_ID_LEN),
    shareKey: new Uint8Array(38).fill(9), // not a valid Bech32m "fkey" string
    label: "x",
    sealedEmail: base64urlDecode(await sealed(h, "r@example.com")),
  });
  const signPriv = await importSignPrivateKey(JSON.parse(h.env.SERVER_SIGN_PRIVATE_JWK) as JsonWebKey);
  const sig = await signRegion(signPriv, region);
  const full = new Uint8Array(region.length + sig.length);
  full.set(region, 0);
  full.set(sig, region.length);
  const link = base64urlEncode(full);
  const { objectId } = (await (await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).json()) as { objectId: string };
  h.r2.putRaw(objectId, fkeyCiphertext(200));
  const before = h.email.sent.length;
  expect((await uploadComplete(post("/upload-complete", { payload: link, objectId }), h.env)).status).toBe(400); // decode failed -> no delivery
  expect(h.email.sent.length).toBe(before); // no delivery email
  expect([...h.kv.store.keys()].some((k) => k.startsWith("rlb:up:bytes:"))).toBe(false); // decode (now pre-budget) didn't burn budget
});

test("discard is proof-gated: bare object ids are rejected; a valid proof deletes object + binding", async () => {
  const h = await makeTestEnv();
  const finalId = await deliver(h, await setupLink(h));
  // The legacy bare-id form is GONE (under in-place delivery the SENDER knows the id).
  expect((await discardObject(post("/discard", { objectId: finalId }), h.env)).status).toBe(400);
  // A wrong proof burns its (single-use) challenge and is rejected.
  const c1 = await challengeAndProof(h, finalId, RECEIVER);
  expect((await discardObject(post("/discard", { challengeId: c1.challengeId, proof: "0".repeat(64) }), h.env)).status).toBe(403);
  expect(await h.env.DROP_BUCKET.get(finalId)).not.toBeNull(); // still there
  // A valid proof deletes the object AND its gate binding.
  const c2 = await challengeAndProof(h, finalId, RECEIVER);
  expect((await discardObject(post("/discard", { challengeId: c2.challengeId, proof: c2.proof }), h.env)).status).toBe(200);
  expect(await h.env.DROP_BUCKET.get(finalId)).toBeNull();
  expect(await h.env.DROP_KV.get(`fetchbind:${finalId}`)).toBeNull();
});

test("discard returns the at-rest capacity hold immediately, spending nothing", async () => {
  // Capacity = balance: a delivered-but-unwanted file occupies the inbox until its TTL — UNLESS the
  // receiver discards it, which must free the capacity right away (for a 1 GB free inbox this is the
  // receiver's only lever against junk). Discarding is not a download, so the balance is untouched.
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "300" });
  const link = await setupLink(h);
  const finalId = await deliver(h, link, 200); // 200 of the 300 balance at rest
  expect((await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).status).toBe(507); // full
  const c = await challengeAndProof(h, finalId, RECEIVER);
  expect((await discardObject(post("/discard", { challengeId: c.challengeId, proof: c.proof }), h.env)).status).toBe(200);
  const acct = await defaultAccount(h);
  expect((await acct.summary(300)).pending).toBe(0); // hold released
  expect((await acct.summary(300)).balance).toBe(300); // discard is free
  expect((await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).status).toBe(200); // fits again
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
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "1000" }); // billing on -> pending tracked
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
  // Capacity = balance makes an unaffordable delivery impossible going FORWARD (reserve rejects it), so
  // the 402 guards the TRANSITION cohort: files delivered while billing was off, whose receiver's grant
  // can't cover them once it flips on. Deliver two 200s billing-off, flip, then download both.
  const h = await makeTestEnv({ FREE_GRANT_BYTES: "300" }); // billing OFF at delivery time
  const link = await setupLink(h);
  const a = await deliver(h, link, 200);
  const b = await deliver(h, link, 200);
  h.env.BILLING_ENABLED = "1"; // pre-enforcement files are now charged at download
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
  // A zero-balance account can't RECEIVE anymore (capacity = balance), so make the broke-account state
  // the transition way: deliver billing-off, then flip billing on with a zero grant. Preview stays free.
  const h = await makeTestEnv({ FREE_GRANT_BYTES: "0" });
  const finalId = await deliver(h, await setupLink(h), 5000); // 5000-byte object, 17-byte metadata
  h.env.BILLING_ENABLED = "1"; // broke account: preview still free
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

// ---- Phase 1 credit UX: preview balance headers + delivery-email status line ----

test("credit UX: preview stamps X-RL-Credit + X-RL-Tier when billing is on (rid present)", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "1000" });
  const finalId = await deliver(h, await setupLink(h), 200); // delivered, not yet downloaded -> balance still the full grant
  const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
  const res = await fetchPreview(post("/fetch/preview", { challengeId, proof }), h.env);
  expect(res.status).toBe(200);
  expect(res.headers.get("X-RL-Credit")).toBe("1000"); // the new account's seeded free grant, in bytes
  expect(res.headers.get("X-RL-Tier")).toBe("free");
  // The CORS layer must expose the custom headers so the cross-origin page can read them.
  expect((res.headers.get("access-control-expose-headers") ?? "")).toContain("X-RL-Credit");
});

test("credit UX: preview omits BOTH credit headers when billing is off", async () => {
  const h = await makeTestEnv(); // BILLING_ENABLED unset
  const finalId = await deliver(h, await setupLink(h), 200);
  const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
  const res = await fetchPreview(post("/fetch/preview", { challengeId, proof }), h.env);
  expect(res.status).toBe(200);
  expect(res.headers.get("X-RL-Credit")).toBeNull();
  expect(res.headers.get("X-RL-Tier")).toBeNull();
  // The auto-delete header is billing-INDEPENDENT: present even with billing off, carrying the object's
  // lifecycle expiry (creation + 7 days, epoch seconds) for the saved screen's "deletes itself" note.
  const exp = Number(res.headers.get("X-RL-Expires"));
  const want = Math.floor(Date.now() / 1000) + 7 * 86400;
  expect(Math.abs(exp - want) < 120).toBe(true); // within 2 min of created+7d
});

test("credit UX: the delivery email carries the credit status line when billing is on", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "1000000000" }); // 1 GB grant
  await deliver(h, await setupLink(h), 200);
  const delivery = h.email.sent.at(-1)!;
  expect(delivery.text).toContain("download credit left."); // the credit line is now its own fenced block...
  expect(delivery.text).toContain("Add credit:"); // ...with "Add credit:" on its own line (not crowded inline)
  expect(delivery.text).toContain("free plan"); // a brand-new account is on the free tier
  expect(delivery.text).toContain("/credit#"); // the proactive add-credit link is a credit-page magic-link (Phase 2a)
  expect(delivery.html).toContain("download credit left."); // HTML part carries it too
});

test("credit UX: the delivery email has NO credit status line when billing is off (unchanged email)", async () => {
  const h = await makeTestEnv(); // BILLING_ENABLED unset
  await deliver(h, await setupLink(h), 200);
  const delivery = h.email.sent.at(-1)!;
  expect(delivery.text).not.toContain("download credit");
  expect(delivery.text).not.toContain("/credit#");
});

test("credit UX: the /confirm response carries billingEnabled (gates the result page messaging)", async () => {
  const on = await makeTestEnv({ BILLING_ENABLED: "1" });
  await register(post("/register", { sealedEmail: await sealed(on, "r@example.com"), shareKey: SHARE_KEY, label: "x" }), on.env);
  const conf = await confirm(post("/confirm", { nonce: nonceFrom(on.email.sent.at(-1)!.text!) }), on.env);
  expect(((await conf.json()) as { billingEnabled: boolean }).billingEnabled).toBe(true);

  const off = await makeTestEnv(); // billing unset
  await register(post("/register", { sealedEmail: await sealed(off, "r@example.com"), shareKey: SHARE_KEY, label: "x" }), off.env);
  const conf2 = await confirm(post("/confirm", { nonce: nonceFrom(off.email.sent.at(-1)!.text!) }), off.env);
  expect(((await conf2.json()) as { billingEnabled: boolean }).billingEnabled).toBe(false);
});

test("upload-init pre-check: an account at capacity bounces (507) before the transfer", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", FREE_GRANT_BYTES: "300" });
  const link = await setupLink(h);
  await deliver(h, link, 200); // at rest (pending) -> 200 of the 300 balance
  // A further 200 would put 400 at rest against a 300 balance, so the pre-check bounces at init.
  expect((await uploadInit(post("/upload-init", { payload: link, size: 200 }), h.env)).status).toBe(507);
});

test("upload-init pre-check: stays inert (no bounce) while billing is off", async () => {
  const h = await makeTestEnv(); // billing off -> no capacity enforcement
  const link = await setupLink(h);
  await deliver(h, link, 200);
  // A 1 GB upload (well past any grant) is still admitted, because capacity only binds with billing on.
  expect((await uploadInit(post("/upload-init", { payload: link, size: 1_000_000_000 }), h.env)).status).toBe(200);
});

test("receiver DO: capacity = balance (at-rest + holds vs credit), and a top-up raises it", async () => {
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-tier"));
  const h1 = await acct.reserve(200, 300, true); // fresh account: capacity = the 300 grant
  expect(h1.ok).toBe(true);
  if (h1.ok) await acct.release(h1.token); // the hold is a capacity check; the meters accrue via commitDelivered
  await acct.commitDelivered("file-tier", 200, true); // at rest: pending=200
  expect((await acct.reserve(200, 300, true)).ok).toBe(false); // 200 at rest + 200 = 400 > 300
  await acct.credit(500, 300); // top-up: balance 300 + 500 = 800 -> capacity rises with it
  expect((await acct.reserve(200, 300, true)).ok).toBe(true); // 200 at rest + 200 = 400 <= 800
});

test("receiver DO: pending rises on delivery and falls once on the first paid download", async () => {
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-pending"));
  const h1 = await acct.reserve(500, 0, false); // billing off: unenforced hold
  expect(h1.ok).toBe(true);
  if (h1.ok) await acct.release(h1.token);
  await acct.commitDelivered("file-1", 500, true); // deliver file-1 (pending 500)
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

test("receiver DO: a delayed commit does not resurrect a paid file's pending hold", async () => {
  // Crash-then-retry racing a fast receiver: the file is downloaded (charged, pending cleared — here it
  // was never tracked at all) BEFORE the retried completion's commitDelivered lands. The late commit
  // must not re-add the paid file to pending, or the receiver loses that capacity until the TTL.
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-late-commit"));
  const r = await acct.charge("file-raced", 200, 1000); // downloaded first (balance 1000 -> 800)
  expect(r.ok).toBe(true);
  await acct.commitDelivered("file-raced", 200, true); // the delayed commit arrives after
  expect((await acct.summary(1000)).pending).toBe(0); // not resurrected
  expect((await acct.summary(1000)).total).toBe(200); // the lifetime meter still counts it
});

test("receiver DO: commitDelivered counts a delivery id exactly once (crash-retry / duplicate safe)", async () => {
  const recv = new MemoryReceiver();
  const acct = recv.get(recv.idFromName("rid-idem"));
  await acct.commitDelivered("f1", 300, false);
  await acct.commitDelivered("f1", 300, false); // a retry / duplicate sibling of the SAME delivery
  await acct.commitDelivered("f2", 100, false);
  expect((await acct.summary(0)).total).toBe(400); // f1 once + f2 once
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

test("billing: FREE_GRANT_BYTES=0 is honored (no free credit) -> the first download is 402", async () => {
  // With capacity = balance a zero-grant account can't receive at all, so the explicit-0 semantics are
  // only observable on transition files (delivered billing-off): the download must 402, not draw on a
  // wrongly-defaulted 1 GB.
  const h = await makeTestEnv({ FREE_GRANT_BYTES: "0" });
  const finalId = await deliver(h, await setupLink(h), 200);
  h.env.BILLING_ENABLED = "1";
  expect((await download(h, finalId)).status).toBe(402); // balance seeded to 0, can't cover 200
});

test("billing: a legacy binding with no rid downloads free (backward compat)", async () => {
  const h = await makeTestEnv({ FREE_GRANT_BYTES: "0" });
  const finalId = await deliver(h, await setupLink(h), 200);
  h.env.BILLING_ENABLED = "1"; // flipped on after delivery (a legacy binding predates billing by definition)
  // Rewrite the binding to the pre-Phase-2 shape (pk + size, no rid): can't resolve an account to charge.
  const b = JSON.parse((await h.kv.get(`fetchbind:${finalId}`))!) as { pk: string; size: number };
  await h.kv.put(`fetchbind:${finalId}`, JSON.stringify({ pk: b.pk, size: b.size }));
  expect((await download(h, finalId)).status).toBe(200); // no rid -> free, even at zero balance
});

// ---- Phase 2b: Stripe (checkout + webhook) ----

/** Build a valid `Stripe-Signature` header for a raw body at timestamp t. */
async function stripeSig(secret: string, body: string, t: number): Promise<string> {
  return `t=${t},v1=${await hmacSha256hex(secret, `${t}.${body}`)}`;
}

test("stripe: a valid webhook signature verifies; wrong secret / tampered body / stale timestamp fail", async () => {
  const secret = "whsec_test";
  const body = JSON.stringify({ hello: "world" });
  const now = 1_700_000_000;
  const sig = await stripeSig(secret, body, now);
  expect(await verifyStripeSignature(body, sig, secret, now)).toBe(true);
  expect(await verifyStripeSignature(body, sig, "whsec_wrong", now)).toBe(false);
  expect(await verifyStripeSignature(`${body} `, sig, secret, now)).toBe(false); // tampered body
  expect(await verifyStripeSignature(body, sig, secret, now + 1000)).toBe(false); // outside the 300s window
  expect(await verifyStripeSignature(body, "v1=abc", secret, now)).toBe(false); // no timestamp
});

test("stripe: signature verify accepts any v1 during a secret rotation", async () => {
  const body = "{}";
  const now = 1_700_000_000;
  const good = (await stripeSig("whsec_new", body, now)).split("v1=")[1]!;
  expect(await verifyStripeSignature(body, `t=${now},v1=deadbeef,v1=${good}`, "whsec_new", now)).toBe(true);
});

test("stripe: parseCreditFromEvent credits only a PAID session with a known pack, bytes from the LOCKED price", async () => {
  const ev = (obj: object) => ({ id: "evt_1", type: "checkout.session.completed", data: { object: { payment_status: "paid", amount_total: 1000, currency: "usd", metadata: { rid: "rid_x", pack: "p10", price: "1" }, ...obj } } });
  expect(parseCreditFromEvent(ev({}))).toEqual({ rid: "rid_x", bytes: 1_000_000_000_000, eventId: "evt_1" }); // $10 @ 1c/GB = 1 TB
  // The bytes follow the price LOCKED in the session, not the live knob: same $10 pack stamped at 10c/GB -> 100 GB.
  expect(parseCreditFromEvent(ev({ metadata: { rid: "rid_x", pack: "p10", price: "10" } }))).toEqual({ rid: "rid_x", bytes: 100_000_000_000, eventId: "evt_1" });
  expect(parseCreditFromEvent(ev({ payment_status: "unpaid" }))).toBeNull(); // not paid
  expect(parseCreditFromEvent(ev({ amount_total: 100 }))).toBeNull(); // underpaid for p10 ($1 < $10)
  expect(parseCreditFromEvent(ev({ currency: "eur" }))).toBeNull(); // wrong currency
  expect(parseCreditFromEvent(ev({ metadata: { rid: "rid_x", pack: "p10" } }))).toBeNull(); // no locked price -> reject (not max-bytes)
  expect(parseCreditFromEvent(ev({ metadata: { rid: "rid_x", price: "1" } }))).toBeNull(); // no pack
  expect(parseCreditFromEvent(ev({ metadata: { rid: "rid_x", pack: "nope", price: "1" } }))).toBeNull(); // unknown pack
  expect(parseCreditFromEvent(ev({ metadata: { pack: "p10", price: "1" } }))).toBeNull(); // no rid
  expect(parseCreditFromEvent({ id: "x", type: "payment_intent.succeeded", data: { object: {} } })).toBeNull(); // wrong type
});

test("stripe: checkoutSessionParams encodes a one-time payment and LOCKS the current price", async () => {
  const { env } = await makeTestEnv({ PRICE_CENTS_PER_GB: "1" });
  const p = checkoutSessionParams(env, { rid: "rid_y", pack: "p10", successUrl: "https://x/s", cancelUrl: "https://x/c" });
  expect(p.get("mode")).toBe("payment");
  expect(p.get("client_reference_id")).toBe("rid_y");
  expect(p.get("metadata[rid]")).toBe("rid_y");
  expect(p.get("metadata[pack]")).toBe("p10");
  expect(p.get("metadata[price]")).toBe("1"); // locked for the webhook
  expect(p.get("line_items[0][price_data][unit_amount]")).toBe("1000"); // $10
});

test("stripe: 'Other amount' = a custom PRICE object + a session referencing it (price_data rejects custom_unit_amount)", async () => {
  const { env } = await makeTestEnv({ PRICE_CENTS_PER_GB: "1" });
  // The price object carries the pay-what-you-want config...
  const price = customPriceParams();
  expect(price.get("custom_unit_amount[enabled]")).toBe("true");
  expect(price.get("custom_unit_amount[minimum]")).toBe("1000"); // $10 floor
  expect(price.get("custom_unit_amount[maximum]")).toBe("1000000"); // $10,000 ceiling
  // ...and the session just points at it: NO inline price_data (Stripe 400s parameter_unknown on it).
  const p = checkoutSessionParams(env, { rid: "rid_z", pack: "custom", successUrl: "https://x/s", cancelUrl: "https://x/c", customPriceId: "price_test_1" });
  expect(p.get("metadata[pack]")).toBe("custom");
  expect(p.get("line_items[0][price]")).toBe("price_test_1");
  expect([...p.keys()].some((k) => k.includes("price_data"))).toBe(false);
});

test("stripe: createCheckoutSession for 'custom' is the two-call flow (price, then session)", async () => {
  const { env } = await makeTestEnv({ BILLING_ENABLED: "1", STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec_x" });
  const calls: { url: string; body: string }[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url: String(url), body: String(init.body) });
    if (String(url).endsWith("/v1/prices")) return new Response(JSON.stringify({ id: "price_live_9" }), { status: 200 });
    return new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/pay/cs_test_9" }), { status: 200 });
  }) as unknown as typeof fetch;
  try {
    const url = await createCheckoutSession(env, { rid: "rid_q", pack: "custom", successUrl: "https://x/s", cancelUrl: "https://x/c" });
    expect(url).toContain("checkout.stripe.com");
    expect(calls.length).toBe(2);
    expect(calls[0]!.url).toContain("/v1/prices");
    expect(calls[0]!.body).toContain("custom_unit_amount%5Benabled%5D=true");
    expect(calls[1]!.url).toContain("/v1/checkout/sessions");
    expect(calls[1]!.body).toContain("line_items%5B0%5D%5Bprice%5D=price_live_9");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("stripe: parseCreditFromEvent credits an 'Other amount' from the VERIFIED amount_total, bounded", async () => {
  const ev = (obj: object) => ({ id: "evt_c", type: "checkout.session.completed", data: { object: { payment_status: "paid", currency: "usd", metadata: { rid: "rid_x", pack: "custom", price: "1" }, ...obj } } });
  // $30 custom @ 1c/GB = 3,000 GB, derived from the actual amount paid (no fixed tier to re-derive from).
  expect(parseCreditFromEvent(ev({ amount_total: 3000 }))).toEqual({ rid: "rid_x", bytes: 3_000_000_000_000, eventId: "evt_c" });
  expect(parseCreditFromEvent(ev({ amount_total: 999 }))).toBeNull(); // below the $10 floor
  expect(parseCreditFromEvent(ev({ amount_total: 1_000_001 }))).toBeNull(); // above the $10,000 ceiling
  // The locked price still sets the rate: $30 @ 10c/GB = 300 GB.
  expect(parseCreditFromEvent(ev({ amount_total: 3000, metadata: { rid: "rid_x", pack: "custom", price: "10" } }))).toEqual({ rid: "rid_x", bytes: 300_000_000_000, eventId: "evt_c" });
});

test("billing: the price is one env knob; packs + labels derive from it", async () => {
  const cheap = await makeTestEnv({ BILLING_ENABLED: "1" }); // default 1¢/GB; billing on so /billing/packs serves
  expect(priceCentsPerGb(cheap.env)).toBe(1);
  const p10cheap = packList(cheap.env).find((p) => p.id === "p10")!;
  expect(p10cheap.bytes).toBe(1_000_000_000_000); // $10 = 1 TB of bytes, shown as 1,000 GB (always-GB labels)
  expect(p10cheap.label).toContain("1,000 GB");
  const dear = await makeTestEnv({ PRICE_CENTS_PER_GB: "10" }); // walk it to 10¢/GB
  const p10dear = packList(dear.env).find((p) => p.id === "p10")!;
  expect(p10dear.bytes).toBe(100_000_000_000); // same $10 now buys 100 GB
  expect(p10dear.label).toContain("100 GB");
  // /billing/packs serves the current tiers for the client picker.
  const out = (await billingPacks(new Request("http://x/billing/packs"), cheap.env).json()) as { packs: { id: string; label: string }[]; priceCentsPerGb: number };
  expect(out.priceCentsPerGb).toBe(1);
  expect(out.packs.map((x) => x.id)).toEqual(["p10", "p25", "p50", "p100", "custom"]); // fixed tiers + "Other amount"
  expect(out.packs.at(-1)!.label).toBe("Other amount");
});

test("upload-abort: only the owning link can clear an in-flight upload binding", async () => {
  const h = await makeTestEnv();
  const linkA = await setupLink(h, "a@example.com", "A");
  const linkB = await setupLink(h, "b@example.com", "B");
  const init = (await (await uploadInit(post("/upload-init", { payload: linkA, size: 100 }), h.env)).json()) as { objectId: string };
  expect(h.kv.store.has(`upload:${init.objectId}`)).toBe(true);
  // A stranger's otherwise-valid link can't kill the upload (200 by design: abort is idempotent and must
  // not leak whether the object exists, but the binding survives).
  expect((await uploadAbort(post("/upload-abort", { payload: linkB, objectId: init.objectId }), h.env)).status).toBe(200);
  expect(h.kv.store.has(`upload:${init.objectId}`)).toBe(true);
  // The owner can.
  expect((await uploadAbort(post("/upload-abort", { payload: linkA, objectId: init.objectId }), h.env)).status).toBe(200);
  expect(h.kv.store.has(`upload:${init.objectId}`)).toBe(false);
});

test("config fail-fast: confirm 503s on a garbled signing key WITHOUT burning the one-time nonce", async () => {
  const h = await makeTestEnv();
  await register(post("/register", { sealedEmail: await sealed(h, "r@example.com"), shareKey: SHARE_KEY, label: "x" }), h.env);
  const nonce = nonceFrom(h.email.sent.at(-1)!.text!);
  const good = h.env.SERVER_SIGN_PRIVATE_JWK;
  h.env.SERVER_SIGN_PRIVATE_JWK = "not json";
  expect((await confirm(post("/confirm", { nonce }), h.env)).status).toBe(503);
  // The nonce survived the misconfig: fixing the secret lets the same confirm succeed.
  h.env.SERVER_SIGN_PRIVATE_JWK = good;
  expect((await confirm(post("/confirm", { nonce }), h.env)).status).toBe(200);
});

test("config fail-fast: register 503s (server misconfig) on a garbled KEM private key, not a client 400", async () => {
  const h = await makeTestEnv();
  h.env.SERVER_KEM_PRIVATE_JWK = "not json";
  const res = await register(post("/register", { sealedEmail: await sealed(h, "r@example.com"), shareKey: SHARE_KEY, label: "x" }), h.env);
  expect(res.status).toBe(503);
});

test("register rejects an undecodable share key (would otherwise mint a permanent trap link)", async () => {
  const h = await makeTestEnv();
  const bad = base64urlEncode(new TextEncoder().encode("not-a-fkey-sharekey"));
  const res = await register(post("/register", { sealedEmail: await sealed(h, "r@example.com"), shareKey: bad, label: "x" }), h.env);
  expect(res.status).toBe(400);
});

test("billing: the file-proof checkout trips the per-account cap", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec_x" });
  const finalId = await deliver(h, await setupLink(h), 200);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/x" }), { status: 200 })) as unknown as typeof fetch;
  try {
    let last = 200;
    // Distinct IP per call so the per-IP cap never trips: this isolates the per-ACCOUNT (rid) cap.
    for (let i = 0; i <= BILLING_CHECKOUT_RID_PER_DAY; i++) {
      const { challengeId, proof } = await challengeAndProof(h, finalId, RECEIVER);
      last = (await billingCheckout(post("/billing/checkout", { challengeId, proof, pack: "p10" }, `7.7.${Math.floor(i / 250)}.${i % 250}`), h.env)).status;
    }
    expect(last).toBe(429);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("billing: checkout + packs are 503 when BILLING_ENABLED is off, even with Stripe configured", async () => {
  // Stripe keys present but BILLING_ENABLED off: a direct caller still cannot buy credit that downloads
  // (free while billing is off) would never spend. The gate is billingEnabled, not just stripeConfigured.
  const h = await makeTestEnv({ STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec_x" });
  expect(billingPacks(new Request("http://x/billing/packs"), h.env).status).toBe(503);
  expect((await billingCheckout(post("/billing/checkout", { challengeId: "x", proof: "y", pack: "p10" }), h.env)).status).toBe(503);
});

test("credit UX: the setup (drop-link) email carries the free-credit line only when billing is on", async () => {
  const on = await makeTestEnv({ BILLING_ENABLED: "1" });
  await register(post("/register", { sealedEmail: await sealed(on, "receiver@example.com"), shareKey: SHARE_KEY, label: "x" }), on.env);
  await confirm(post("/confirm", { nonce: nonceFrom(on.email.sent[0]!.text!) }), on.env);
  const drop = on.email.sent.at(-1)!; // confirm sends the drop-link email after the register confirm email
  expect(drop.text).toContain("download credit");
  expect(drop.html).toContain("download credit");

  const off = await makeTestEnv(); // billing off (default)
  await register(post("/register", { sealedEmail: await sealed(off, "r2@example.com"), shareKey: SHARE_KEY, label: "x" }), off.env);
  await confirm(post("/confirm", { nonce: nonceFrom(off.email.sent[0]!.text!) }), off.env);
  expect(off.email.sent.at(-1)!.text).not.toContain("download credit");
});

test("billing checkout: 503 unless BOTH Stripe secrets are set; 400 on an unknown pack", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1" }); // billing on; neither Stripe secret -> the Stripe gate 503s
  const finalId = await deliver(h, await setupLink(h), 200);
  const cp = await challengeAndProof(h, finalId, RECEIVER);
  expect((await billingCheckout(post("/billing/checkout", { ...cp, pack: "p10" }), h.env)).status).toBe(503);
  // API key set but webhook secret missing -> still 503, so a user can never pay before we can credit them.
  const hk = await makeTestEnv({ BILLING_ENABLED: "1", STRIPE_SECRET_KEY: "sk_test_x" });
  const fk = await deliver(hk, await setupLink(hk), 200);
  const cpk = await challengeAndProof(hk, fk, RECEIVER);
  expect((await billingCheckout(post("/billing/checkout", { ...cpk, pack: "p10" }), hk.env)).status).toBe(503);
  const h2 = await makeTestEnv({ BILLING_ENABLED: "1", STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec_x" });
  const f2 = await deliver(h2, await setupLink(h2), 200);
  const cp2 = await challengeAndProof(h2, f2, RECEIVER);
  expect((await billingCheckout(post("/billing/checkout", { ...cp2, pack: "nope" }), h2.env)).status).toBe(400);
});

test("billing checkout: a proven request returns a Stripe Checkout URL", async () => {
  const h = await makeTestEnv({ BILLING_ENABLED: "1", STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec_x" });
  const finalId = await deliver(h, await setupLink(h), 200);
  const cp = await challengeAndProof(h, finalId, RECEIVER);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/pay/cs_test_123" }), { status: 200 })) as unknown as typeof fetch;
  try {
    const res = await billingCheckout(post("/billing/checkout", { ...cp, pack: "p10" }), h.env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { url: string }).url).toContain("checkout.stripe.com");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("billing webhook: a signed paid session credits the account, idempotent on the event id", async () => {
  const secret = "whsec_test";
  const h = await makeTestEnv({ STRIPE_WEBHOOK_SECRET: secret, FREE_GRANT_BYTES: "0" });
  const rid = await receiverId(h.env, "receiver@example.com");
  const body = JSON.stringify({ id: "evt_42", type: "checkout.session.completed", data: { object: { payment_status: "paid", amount_total: 1000, currency: "usd", metadata: { rid, pack: "p10", price: "1" } } } });
  const now = Math.floor(Date.now() / 1000);
  const hook = async () => billingWebhook(new Request("http://x/billing/webhook", { method: "POST", headers: { "stripe-signature": await stripeSig(secret, body, now) }, body }), h.env);
  const acct = h.env.RECEIVER.get(h.env.RECEIVER.idFromName(rid));
  expect((await hook()).status).toBe(200);
  expect((await acct.summary(0)).balance).toBe(1_000_000_000_000); // p10 @ 1c/GB = 1 TB (grant 0)
  expect((await hook()).status).toBe(200); // webhook retry, same event id
  expect((await acct.summary(0)).balance).toBe(1_000_000_000_000); // not double-credited
});

test("billing webhook: a bad signature is rejected (400) and credits nothing", async () => {
  const h = await makeTestEnv({ STRIPE_WEBHOOK_SECRET: "whsec_test", FREE_GRANT_BYTES: "0" });
  const rid = await receiverId(h.env, "receiver@example.com");
  const body = JSON.stringify({ id: "evt_9", type: "checkout.session.completed", data: { object: { payment_status: "paid", metadata: { rid, bytes: "100" } } } });
  const req = new Request("http://x/billing/webhook", { method: "POST", headers: { "stripe-signature": "t=1,v1=bad" }, body });
  expect((await billingWebhook(req, h.env)).status).toBe(400);
  expect((await h.env.RECEIVER.get(h.env.RECEIVER.idFromName(rid)).summary(0)).balance).toBe(0);
});

test("billing webhook: an oversized body is rejected (413) before the signature check", async () => {
  const h = await makeTestEnv({ STRIPE_WEBHOOK_SECRET: "whsec_test" });
  const body = "x".repeat(300 * 1024); // > the 256 KB cap
  const req = new Request("http://x/billing/webhook", { method: "POST", headers: { "stripe-signature": "t=1,v1=bad" }, body });
  expect((await billingWebhook(req, h.env)).status).toBe(413); // capped before buffering + HMAC
});

test("confirm: a malformed (oversized) nonce is a clean 404, not a 500", async () => {
  const h = await makeTestEnv();
  // A 2000-char nonce would blow KV's key-size limit if it reached the lookup; the shape check bounces it.
  expect((await confirm(post("/confirm", { nonce: "z".repeat(2000) }), h.env)).status).toBe(404);
  // A well-shaped but unknown nonce (22 base64url chars) is also a clean 404 (KV miss).
  expect((await confirm(post("/confirm", { nonce: "A".repeat(22) }), h.env)).status).toBe(404);
});

test("upload-init: a per-IP request flood is capped (429) before the ECDSA verify", async () => {
  const h = await makeTestEnv({ UPLOAD_REQ_IP_PER_DAY: "2" });
  const link = await setupLink(h);
  // Same IP (post() default), so the up:req:ip counter is shared: 2 through, the 3rd is rate limited.
  expect((await uploadInit(post("/upload-init", { payload: link, size: 100 }), h.env)).status).toBe(200);
  expect((await uploadInit(post("/upload-init", { payload: link, size: 100 }), h.env)).status).toBe(200);
  expect((await uploadInit(post("/upload-init", { payload: link, size: 100 }), h.env)).status).toBe(429);
});

test("upload-init: no per-link cap, so a public link can't be locked by no-op init calls", async () => {
  // The per-link daily limit lives at COMPLETE (deliver:link), not init. Many inits to one link from
  // DIFFERENT IPs (to dodge the per-IP cap) must all pass — previously the 26th 429'd on up:link, which
  // let anyone disable a public link for a day with 25 no-upload init calls.
  const h = await makeTestEnv();
  const link = await setupLink(h);
  for (let i = 0; i < 30; i++) {
    const status = (await uploadInit(post("/upload-init", { payload: link, size: 100 }, `9.9.${i}.1`), h.env)).status;
    expect(status).toBe(200); // never 429 on a per-link basis
  }
});
