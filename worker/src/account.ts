// Phase 2a - the account WALLET surface: an email magic-link sign-in that lets a receiver see their prepaid
// balance and add credit WITHOUT a delivered file in hand (the file-proof /billing/checkout stays for the
// in-context 402 wall). The account is identified by the email-derived rid (handlers.receiverId); the passkey
// is a per-file decryption key and is deliberately NOT involved here (there is no durable account<->passkey
// binding by design), so a file-free surface is necessarily email-authenticated. The wallet is inert to an
// attacker: a leaked session can view the balance and add credit (with their own card) but cannot decrypt or
// download a file, spend the balance (spend = a passkey download), or withdraw.
//
// Auth: POST /account/login (sealed email -> emailed magic link) -> POST /account/session (magic -> 30-min
// Bearer session) -> POST /account/summary | /account/checkout (Bearer). All 503 when billing is off. The
// token helpers live in the neutral magic.ts (no account<->handlers import cycle).
import { base64urlDecode } from "../../shared/codec";
import { importKemPrivateKey, unsealEmail } from "../../shared/crypto";
import { hmacHex, isEmail } from "../../shared/util";
import { billingEnabled, canonEmail, freeGrantBytes, receiverId } from "./handlers";
import { clientIp, corsOrigin, json, linkOrigin, logEvent, readJson } from "./http";
import { DAY, rateLimit } from "./kv";
import { isWellFormedToken, mintMagicToken, mintSession, redeemMagicToken, resolveSession } from "./magic";
import { sendAccountLoginEmail } from "./email";
import { createCheckoutSession, isCheckoutPack, stripeConfigured } from "./stripe";
import type { Env } from "./types";

// Soft KV caps (exported so tests assert the source of truth). The login form is low-friction, so cap both the
// IP (pre-unseal, the only key we have then) and the address (post-unseal, anti-bombing). Session-redeem and
// checkout get their own per-IP caps (random-token spam / unbounded Stripe sessions); checkout also per-rid.
export const ACCT_LOGIN_IP_PER_DAY = 30; // sign-in emails one IP can trigger
export const ACCT_LOGIN_EMAIL_PER_DAY = 5; // sign-in emails one address can receive (anti-bombing)
export const ACCT_SESSION_IP_PER_DAY = 120; // magic-token redemptions one IP can attempt
export const ACCT_CHECKOUT_IP_PER_DAY = 30; // checkout sessions one IP can start
export const ACCT_CHECKOUT_RID_PER_DAY = 30; // checkout sessions one account can start

// POST /account/login { sealedEmail } -> 202 { ok: true } (uniform: never reveals whether an account exists).
export async function accountLogin(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  if (!billingEnabled(env)) return json({ error: "unavailable" }, 503, origin);
  const body = await readJson<{ sealedEmail?: unknown }>(req);
  if (!body || typeof body.sealedEmail !== "string") return json({ error: "missing fields" }, 400, origin);

  // IP cap BEFORE unseal - the email hash can't be computed until we've unsealed (the email is sealed). Hash
  // the IP so KV only holds a digest. This is the one non-202 email-independent outcome (no existence signal).
  const ipHash = await hmacHex(env.HASH_SECRET, clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `acct:login:ip:${ipHash}`, ACCT_LOGIN_IP_PER_DAY, DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }

  // From here EVERY outcome returns the identical 202 (invalid/garbled sealed email, non-email, over-quota,
  // success) so the endpoint is not an account-existence oracle. The DO is never touched on login.
  let email: string;
  try {
    const kemPriv = await importKemPrivateKey(JSON.parse(env.SERVER_KEM_PRIVATE_JWK) as JsonWebKey);
    email = await unsealEmail(kemPriv, base64urlDecode(body.sealedEmail));
  } catch {
    return json({ ok: true }, 202, origin);
  }
  if (!isEmail(email)) return json({ ok: true }, 202, origin);

  // Anti-bombing: silently succeed once an address is over its daily quota (mirrors register). Then mint a
  // single-use, short-lived sign-in token and email it. rid is derived, never stored.
  const emailHash = await hmacHex(env.HASH_SECRET, canonEmail(email));
  if (!(await rateLimit(env.DROP_KV, `acct:login:em:${emailHash}`, ACCT_LOGIN_EMAIL_PER_DAY, DAY))) {
    return json({ ok: true }, 202, origin);
  }
  const rid = await receiverId(env, email);
  const mt = await mintMagicToken(env, rid, false); // self-service: single-use, 15 min
  try {
    await sendAccountLoginEmail(env, email, `${linkOrigin(env)}/credit#${mt}`);
    logEvent("account_login_sent");
  } catch {
    logEvent("account_login_email_failed"); // still 202 (uniform); the user can retry
  }
  return json({ ok: true }, 202, origin);
}

// POST /account/session { magicToken } -> 200 { token, tier, balanceBytes } | 401. Redeems an emailed magic
// token for a 30-min Bearer session and returns the opening balance so the page renders without a 2nd call.
export async function accountSession(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  if (!billingEnabled(env)) return json({ error: "unavailable" }, 503, origin);
  const body = await readJson<{ magicToken?: unknown }>(req);
  // Validate token shape BEFORE any HMAC/KV work (including the rate-limit counter) so malformed-token spam
  // is rejected for free and can't burn a shared-IP/NAT quota. Well-formed-but-unknown tokens still hit the
  // IP cap below (that is the real amplification vector).
  if (!isWellFormedToken(body?.magicToken)) return json({ error: "invalid or expired" }, 401, origin);
  const ipHash = await hmacHex(env.HASH_SECRET, clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `acct:session:ip:${ipHash}`, ACCT_SESSION_IP_PER_DAY, DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }
  const rid = await redeemMagicToken(env, body.magicToken);
  if (!rid) return json({ error: "invalid or expired" }, 401, origin);
  const st = await mintSession(env, rid);
  const acct = env.RECEIVER.get(env.RECEIVER.idFromName(rid));
  const s = await acct.summary(freeGrantBytes(env));
  logEvent("account_session_ok");
  return json({ token: st, tier: s.tier, balanceBytes: s.balance }, 200, origin);
}

// POST /account/summary  (Authorization: Bearer <st>) -> 200 { tier, balanceBytes } | 401.
export async function accountSummary(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  if (!billingEnabled(env)) return json({ error: "unavailable" }, 503, origin);
  const rid = await resolveSession(env, req.headers.get("authorization"));
  if (!rid) return json({ error: "unauthorized" }, 401, origin);
  const acct = env.RECEIVER.get(env.RECEIVER.idFromName(rid));
  const s = await acct.summary(freeGrantBytes(env));
  return json({ tier: s.tier, balanceBytes: s.balance }, 200, origin);
}

// POST /account/checkout { pack }  (Authorization: Bearer <st>) -> 200 { url } | 400 | 401 | 503 | 502.
// The account-page analog of /billing/checkout: the session resolves the rid (instead of a file-proof). The
// webhook credit path is unchanged (rid in metadata, idempotent, bytes re-derived from the fixed pack).
export async function accountCheckout(req: Request, env: Env): Promise<Response> {
  const origin = corsOrigin(env, req);
  if (!billingEnabled(env) || !stripeConfigured(env)) return json({ error: "billing unavailable" }, 503, origin);
  const rid = await resolveSession(env, req.headers.get("authorization"));
  if (!rid) return json({ error: "unauthorized" }, 401, origin);
  const body = await readJson<{ pack?: unknown }>(req);
  if (!body || typeof body.pack !== "string" || !isCheckoutPack(body.pack)) return json({ error: "unknown pack" }, 400, origin);
  // A valid session must not mint unlimited Stripe sessions: cap per-IP AND per-account.
  const ipHash = await hmacHex(env.HASH_SECRET, clientIp(req));
  if (!(await rateLimit(env.DROP_KV, `acct:checkout:ip:${ipHash}`, ACCT_CHECKOUT_IP_PER_DAY, DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }
  if (!(await rateLimit(env.DROP_KV, `acct:checkout:rid:${rid}`, ACCT_CHECKOUT_RID_PER_DAY, DAY))) {
    return json({ error: "rate limited" }, 429, origin);
  }
  const base = linkOrigin(env);
  try {
    const url = await createCheckoutSession(env, {
      rid,
      pack: body.pack,
      successUrl: `${base}/credit?paid=1`, // back to the credit page; it polls summary until the balance rises
      cancelUrl: `${base}/credit`,
    });
    logEvent("checkout_minted", { kind: body.pack });
    return json({ url }, 200, origin);
  } catch {
    logEvent("stripe_checkout_failed");
    return json({ error: "could not start checkout, try again" }, 502, origin);
  }
}
