// Account magic-link + session tokens (Phase 2a wallet). A NEUTRAL module: it imports only kv/util/codec/
// types, never handlers.ts or account.ts, so both can use it without an import cycle (handlers.ts mints magic
// tokens for the setup/delivery emails; account.ts redeems them + mints sessions).
//
// Two opaque bearer tokens, both 32 random bytes rendered base64url (43 chars), both stored HASHED at rest
// (hmac over HASH_SECRET) so a KV read leak can't be replayed, and neither ever encodes the rid (so a token
// leak can't expose the account handle):
//   magic:<hash(mt)>    -> { rid, reusable }   the emailed sign-in token. reusable (7d, email-embedded) or
//                                              single-use (15m, self-service "email me a link").
//   acctsess:<hash(st)> -> rid                 the 30-min session minted on redemption; carried as a Bearer.
// The wallet these unlock is inert to an attacker (view balance + add credit with their OWN card; no file
// access, no spend, no withdrawal), which is what lets the email-embedded token be a reusable 7-day bearer.
import { base64urlEncode } from "../../shared/codec";
import { hmacHex, isHex, randomBytes } from "../../shared/util";
import { DAY, MINUTE } from "./kv";
import type { Env } from "./types";

const TOKEN_BYTES = 32;
export const TOKEN_B64_LEN = 43; // 32 bytes base64url, unpadded
const MAGIC_TTL_REUSABLE_SEC = 7 * DAY; // email-embedded "Add credit" links: reusable until this lapses
const MAGIC_TTL_ONCE_SEC = 15 * MINUTE; // self-service "email me a sign-in link": single-use, short
const SESSION_TTL_SEC = 30 * MINUTE; // account session

type MagicValue = { rid: string; reusable: boolean };

/** A syntactically valid opaque token: exactly 43 base64url chars. Checked BEFORE any HMAC/KV work so random
 *  spam is cheap to reject (no KV read amplification). */
export function isWellFormedToken(s: unknown): s is string {
  return typeof s === "string" && s.length === TOKEN_B64_LEN && /^[A-Za-z0-9_-]+$/.test(s);
}

/** rid is an HMAC-SHA256 hex digest (32 bytes -> 64 hex). Validate anything loaded from KV before it reaches
 *  the DO / Stripe, so a corrupted value can never address an unintended account. */
function isRid(s: unknown): s is string {
  return typeof s === "string" && isHex(s, 32);
}

const newToken = (): string => base64urlEncode(randomBytes(TOKEN_BYTES));
const magicKey = async (env: Env, mt: string): Promise<string> => `magic:${await hmacHex(env.HASH_SECRET, mt)}`;
const sessionKey = async (env: Env, st: string): Promise<string> => `acctsess:${await hmacHex(env.HASH_SECRET, st)}`;

/** Mint an emailed magic token bound to `rid`. reusable=true => 7-day bearer (setup/delivery "Add credit");
 *  reusable=false => single-use 15-min (self-service login). Returns the raw token for the URL fragment. */
export async function mintMagicToken(env: Env, rid: string, reusable: boolean): Promise<string> {
  const mt = newToken();
  const value: MagicValue = { rid, reusable };
  await env.DROP_KV.put(await magicKey(env, mt), JSON.stringify(value), {
    expirationTtl: reusable ? MAGIC_TTL_REUSABLE_SEC : MAGIC_TTL_ONCE_SEC,
  });
  return mt;
}

/** Redeem a magic token -> rid, or null if malformed / unknown / expired. A single-use token is DELETED here
 *  (best-effort: KV get+delete is non-atomic, so a raced single-use token could mint a couple of extra 30-min
 *  sessions — still wallet-only, still inert); a reusable token is left to expire on its TTL. */
export async function redeemMagicToken(env: Env, mt: unknown): Promise<string | null> {
  if (!isWellFormedToken(mt)) return null;
  const key = await magicKey(env, mt);
  const raw = await env.DROP_KV.get(key);
  if (!raw) return null;
  let v: MagicValue;
  try {
    v = JSON.parse(raw) as MagicValue;
  } catch {
    return null;
  }
  if (!isRid(v.rid)) return null;
  if (!v.reusable) await env.DROP_KV.delete(key);
  return v.rid;
}

/** Mint a 30-minute opaque session for `rid`; returns the raw token to carry as `Authorization: Bearer`. */
export async function mintSession(env: Env, rid: string): Promise<string> {
  const st = newToken();
  await env.DROP_KV.put(await sessionKey(env, st), rid, { expirationTtl: SESSION_TTL_SEC });
  return st;
}

/** Resolve an `Authorization: Bearer <st>` header -> rid, or null. Validates the header shape + token charset
 *  BEFORE any HMAC/KV work, and validates the loaded rid as 64-hex before it can reach the DO / Stripe. */
export async function resolveSession(env: Env, authHeader: string | null): Promise<string | null> {
  if (!authHeader) return null;
  const m = /^Bearer ([A-Za-z0-9_-]+)$/.exec(authHeader);
  if (!m || !isWellFormedToken(m[1])) return null;
  const rid = await env.DROP_KV.get(await sessionKey(env, m[1]!));
  return isRid(rid) ? rid : null;
}
