// Phase 2a account-wallet tests: magic-link login (uniform, anti-enumeration, anti-bombing), session redeem
// (single-use vs reusable, malformed/unknown rejection), Bearer summary, and account-authenticated checkout
// (gating + the right rid/return-URL + per-account cap). Mirrors handlers.test.ts's request/seal helpers.
import { expect, test } from "bun:test";
import { base64urlEncode } from "../../shared/codec";
import { importKemPublicKey, sealEmail } from "../../shared/crypto";
import { ACCT_LOGIN_EMAIL_PER_DAY, accountCheckout, accountLogin, accountSession, accountSummary } from "./account";
import { freeGrantBytes, receiverId } from "./handlers";
import { mintMagicToken } from "./magic";
import { makeTestEnv, type TestHarness } from "./testing";

function post(path: string, body: unknown, ip = "1.2.3.4", auth?: string): Request {
  const headers: Record<string, string> = { "content-type": "application/json", "cf-connecting-ip": ip };
  if (auth) headers.authorization = auth;
  return new Request(`https://api.drop.test${path}`, { method: "POST", headers, body: JSON.stringify(body) });
}
async function sealed(h: TestHarness, email: string): Promise<string> {
  return base64urlEncode(await sealEmail(await importKemPublicKey(h.kemPublicRaw), email));
}
function magicFrom(text: string): string {
  const m = text.match(/\/credit#([A-Za-z0-9_-]+)/);
  if (!m) throw new Error(`no magic token in: ${text}`);
  return m[1]!;
}
const BILLING = { BILLING_ENABLED: "1" } as const;
const STRIPE = { BILLING_ENABLED: "1", STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec_x" } as const;
async function sessionFor(h: TestHarness, email: string): Promise<{ rid: string; token: string }> {
  const rid = await receiverId(h.env, email);
  const mt = await mintMagicToken(h.env, rid, true);
  const body = (await (await accountSession(post("/account/session", { magicToken: mt }), h.env)).json()) as { token: string };
  return { rid, token: body.token };
}

test("every account endpoint 503s when billing is off (ships inert)", async () => {
  const h = await makeTestEnv(); // billing off
  const tok = "Bearer " + "a".repeat(43);
  expect((await accountLogin(post("/account/login", { sealedEmail: await sealed(h, "a@b.com") }), h.env)).status).toBe(503);
  expect((await accountSession(post("/account/session", { magicToken: "a".repeat(43) }), h.env)).status).toBe(503);
  expect((await accountSummary(post("/account/summary", {}, "1.2.3.4", tok), h.env)).status).toBe(503);
  expect((await accountCheckout(post("/account/checkout", { pack: "p10" }, "1.2.3.4", tok), h.env)).status).toBe(503);
});

test("login emails a single-use sign-in link and returns 202", async () => {
  const h = await makeTestEnv(BILLING);
  const res = await accountLogin(post("/account/login", { sealedEmail: await sealed(h, "rcv@example.com") }), h.env);
  expect(res.status).toBe(202);
  const mail = h.email.sent.at(-1)!;
  expect(mail.to).toBe("rcv@example.com");
  expect(mail.subject.toLowerCase()).toContain("credit");
  expect(mail.text).toContain("/credit#");
});

test("login is a uniform 202 for valid, garbage, and non-email inputs (no enumeration oracle)", async () => {
  const h = await makeTestEnv(BILLING);
  const valid = await accountLogin(post("/account/login", { sealedEmail: await sealed(h, "real@example.com") }, "9.9.9.1"), h.env);
  const garbage = await accountLogin(post("/account/login", { sealedEmail: "!!!not-base64!!!" }, "9.9.9.2"), h.env);
  const notEmail = await accountLogin(post("/account/login", { sealedEmail: await sealed(h, "not-an-email") }, "9.9.9.3"), h.env);
  for (const r of [valid, garbage, notEmail]) {
    expect(r.status).toBe(202);
    expect((await r.json()) as { ok: boolean }).toEqual({ ok: true });
  }
});

test("login rejects a missing body (400) and trips the per-IP cap (429)", async () => {
  const h = await makeTestEnv(BILLING);
  expect((await accountLogin(post("/account/login", {}), h.env)).status).toBe(400);
  let last = 202;
  for (let i = 0; i < 40; i++) {
    last = (await accountLogin(post("/account/login", { sealedEmail: await sealed(h, `u${i}@x.com`) }, "5.5.5.5"), h.env)).status;
  }
  expect(last).toBe(429); // ACCT_LOGIN_IP_PER_DAY = 30
});

test("login silently stops emailing an address over its daily quota (anti-bombing, still uniform 202)", async () => {
  const h = await makeTestEnv(BILLING);
  const sealedEmail = await sealed(h, "victim@example.com");
  for (let i = 0; i < ACCT_LOGIN_EMAIL_PER_DAY; i++) {
    expect((await accountLogin(post("/account/login", { sealedEmail }, `1.1.1.${i}`), h.env)).status).toBe(202);
  }
  const before = h.email.sent.length;
  const res = await accountLogin(post("/account/login", { sealedEmail }, "1.1.1.250"), h.env);
  expect(res.status).toBe(202); // uniform: looks identical to a sent one
  expect(h.email.sent.length).toBe(before); // but no new email actually went out
});

test("session redeems a single-use magic token once, returns the opening balance, then it's dead", async () => {
  const h = await makeTestEnv(BILLING);
  await accountLogin(post("/account/login", { sealedEmail: await sealed(h, "rcv@example.com") }), h.env);
  const mt = magicFrom(h.email.sent.at(-1)!.text!);
  const r1 = await accountSession(post("/account/session", { magicToken: mt }), h.env);
  expect(r1.status).toBe(200);
  const body = (await r1.json()) as { token: string; tier: string; balanceBytes: number };
  expect(body.token.length).toBe(43);
  expect(body.tier).toBe("free");
  expect(body.balanceBytes).toBe(freeGrantBytes(h.env));
  expect((await accountSession(post("/account/session", { magicToken: mt }), h.env)).status).toBe(401); // single-use spent
});

test("session rejects a malformed token before any KV work, and counts a well-formed unknown token", async () => {
  const h = await makeTestEnv(BILLING);
  expect((await accountSession(post("/account/session", { magicToken: "short" }), h.env)).status).toBe(401);
  // Rejected before any HMAC/KV work: no rate-limit counter key was written for the malformed token.
  expect([...h.kv.store.keys()].some((k) => k.startsWith("rl:acct:session"))).toBe(false);
  // A well-formed but unknown token IS the real amplification vector: it's counted against the IP cap, then 401s.
  expect((await accountSession(post("/account/session", { magicToken: "a".repeat(43) }), h.env)).status).toBe(401);
  expect([...h.kv.store.keys()].some((k) => k.startsWith("rl:acct:session"))).toBe(true);
});

test("a reusable (email-embedded) magic token survives repeated redemption", async () => {
  const h = await makeTestEnv(BILLING);
  const rid = await receiverId(h.env, "rcv@example.com");
  const mt = await mintMagicToken(h.env, rid, true);
  expect((await accountSession(post("/account/session", { magicToken: mt }), h.env)).status).toBe(200);
  expect((await accountSession(post("/account/session", { magicToken: mt }), h.env)).status).toBe(200);
});

test("summary returns the live balance/tier for a valid Bearer session, 401 otherwise", async () => {
  const h = await makeTestEnv(BILLING);
  const { rid, token } = await sessionFor(h, "rcv@example.com");
  await h.env.RECEIVER.get(h.env.RECEIVER.idFromName(rid)).credit(2_000_000_000, freeGrantBytes(h.env), "evt_1");
  const r = await accountSummary(post("/account/summary", {}, "1.2.3.4", `Bearer ${token}`), h.env);
  expect(r.status).toBe(200);
  const s = (await r.json()) as { tier: string; balanceBytes: number };
  expect(s.tier).toBe("paid");
  expect(s.balanceBytes).toBe(freeGrantBytes(h.env) + 2_000_000_000);
  expect((await accountSummary(post("/account/summary", {}), h.env)).status).toBe(401); // no token
  expect((await accountSummary(post("/account/summary", {}, "1.2.3.4", "Bearer " + "z".repeat(43)), h.env)).status).toBe(401); // unknown token
});

test("checkout needs a session + known pack, and builds a /credit-return Stripe session for the right rid", async () => {
  const h = await makeTestEnv(STRIPE);
  const { rid, token } = await sessionFor(h, "rcv@example.com");
  const auth = `Bearer ${token}`;
  expect((await accountCheckout(post("/account/checkout", { pack: "p10" }), h.env)).status).toBe(401); // no session
  expect((await accountCheckout(post("/account/checkout", { pack: "nope" }, "1.2.3.4", auth), h.env)).status).toBe(400); // bad pack

  const realFetch = globalThis.fetch;
  let captured = "";
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    captured = String(init.body);
    if (String(url).endsWith("/v1/prices")) return new Response(JSON.stringify({ id: "price_test_7" }), { status: 200 });
    return new Response(JSON.stringify({ url: "https://checkout.stripe.com/c/pay/cs_test_1" }), { status: 200 });
  }) as unknown as typeof fetch;
  try {
    const res = await accountCheckout(post("/account/checkout", { pack: "p10" }, "1.2.3.4", auth), h.env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { url: string }).url).toContain("checkout.stripe.com");
    expect(captured).toContain(`client_reference_id=${rid}`); // credits the session's account
    expect(decodeURIComponent(captured)).toContain("/credit?paid=1"); // returns to the credit page, not a file
    // "Other amount" is accepted too: the two-call flow ends in a session referencing the minted price.
    const resCustom = await accountCheckout(post("/account/checkout", { pack: "custom" }, "1.2.3.4", auth), h.env);
    expect(resCustom.status).toBe(200);
    expect(decodeURIComponent(captured)).toContain("line_items[0][price]=price_test_7");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("checkout trips the per-account cap", async () => {
  const h = await makeTestEnv(STRIPE);
  const { token } = await sessionFor(h, "rcv@example.com");
  const auth = `Bearer ${token}`;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ url: "https://checkout.stripe.com/x" }), { status: 200 })) as unknown as typeof fetch;
  try {
    let last = 200;
    // Distinct IP each call so the per-IP cap never trips: this isolates the per-ACCOUNT (rid) cap.
    for (let i = 0; i < 31; i++) last = (await accountCheckout(post("/account/checkout", { pack: "p10" }, `8.8.8.${i}`, auth), h.env)).status;
    expect(last).toBe(429); // ACCT_CHECKOUT_RID_PER_DAY = 30, same session/rid every call
  } finally {
    globalThis.fetch = realFetch;
  }
});

// (The old paidTierDowngrades misconfig test is gone with the tier caps themselves: capacity = credit
// balance now, so a top-up raising the balance mathematically cannot shrink capacity — the no-downgrade
// invariant is structural, not a config rule to police.)
