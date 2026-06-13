// End-to-end handler tests: the full register -> confirm -> upload protocol run
// through the real codec + crypto against in-memory bindings.
import { expect, test } from "bun:test";
import { base64urlDecode, base64urlEncode } from "../../shared/codec";
import { importKemPublicKey, sealEmail } from "../../shared/crypto";
import {
  REG_EMAIL_PER_DAY,
  confirm,
  fetchObject,
  parseAndVerify,
  register,
  uploadComplete,
  uploadInit,
} from "./handlers";
import { makeTestEnv, type TestHarness } from "./testing";

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

function fkeyCiphertext(size: number): Uint8Array {
  const ct = new Uint8Array(size);
  ct.set([0x46, 0x4b, 0x45, 0x59], 0); // "FKEY"
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
  expect(h.email.sent[0]!.from).toBe("files@send.test");

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
  expect(h.email.sent.length).toBe(2);
  expect(h.email.sent[1]!.to).toBe("receiver@example.com"); // unseal worked end-to-end
  expect(h.email.sent[1]!.text).toContain(objectId);
  expect(h.email.sent[1]!.text).toContain("/d/");
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
  expect(h.email.sent.length).toBe(1); // only the confirm email
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
  expect(h.email.sent.length).toBe(2); // 1 confirm + 1 delivery
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
