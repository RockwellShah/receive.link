// KV-backed rate limiting + small state helpers (confirm nonces, revocation,
// idempotency flags). All state here is short-lived and self-expiring — there is
// no persistent email↔key store anywhere in FileKey Drop.

import { logEvent } from "./http";

export const MINUTE = 60;
export const HOUR = 3600;
export const DAY = 86400;

/**
 * Fixed-window counter. Returns true if the action is allowed (and records it),
 * false if the limit for the current window is already reached.
 *
 * NOTE: KV is eventually consistent and caps ~1 write/s per key, so this is a
 * SOFT limit — fine for abuse dampening at low volume, racy under a burst. If
 * abuse shows up, move the hot paths to the Workers Rate Limiting binding or a
 * Durable Object. `nowMs` is injectable for deterministic tests.
 */
export async function rateLimit(
  kv: KVNamespace,
  key: string,
  limit: number,
  windowSec: number,
  nowMs: number = Date.now(),
): Promise<boolean> {
  const window = Math.floor(nowMs / 1000 / windowSec);
  const k = `rl:${key}:${window}`;
  const current = parseInt((await kv.get(k)) || "0", 10);
  if (current >= limit) {
    // The limiter KIND only (key minus its trailing hash/id segment): "reg:ip", "up:bytes:link",
    // "billing:checkout:rid"... — the abuse dashboard's main dimension, never the subject.
    logEvent("rate_limited", { kind: key.split(":").slice(0, -1).join(":") });
    return false;
  }
  await kv.put(k, String(current + 1), { expirationTtl: windowSec * 2 });
  return true;
}

/**
 * Fixed-window counter that counts a given `onceKey` (e.g. an objectId) AT MOST ONCE per window. A repeat
 * call for the same onceKey returns true WITHOUT touching the counter (an idempotent retry), and an
 * over-limit call does NOT set the marker — so the caller invokes this only for a work item that passed
 * its validation, and neither an invalid/failed attempt nor a 502-retry of the same item can burn the
 * quota more than once. Used for the per-link delivery cap, which must count real deliveries, not
 * completion attempts. Same SOFT-limit caveat as {@link rateLimit}.
 */
export async function rateLimitOnce(
  kv: KVNamespace,
  key: string,
  limit: number,
  windowSec: number,
  onceKey: string,
  nowMs: number = Date.now(),
): Promise<boolean> {
  const marker = `rl1:${key}:${onceKey}`;
  if (await kv.get(marker)) return true; // this item was already counted -> a retry, allow for free
  const window = Math.floor(nowMs / 1000 / windowSec);
  const k = `rl:${key}:${window}`;
  const current = parseInt((await kv.get(k)) || "0", 10);
  if (current >= limit) {
    logEvent("rate_limited", { kind: key.split(":").slice(0, -1).join(":") }); // see rateLimit
    return false; // over the cap; do NOT mark (this item was not counted/delivered)
  }
  await kv.put(k, String(current + 1), { expirationTtl: windowSec * 2 });
  await kv.put(marker, "1", { expirationTtl: windowSec * 2 });
  return true;
}

/**
 * Byte-budget variant of {@link rateLimit}: accumulates `addBytes` into a fixed window and returns
 * false once the window total would exceed `limitBytes`. Same SOFT-limit caveat (KV is eventually
 * consistent, ~1 write/s/key) — an abuse dampener, not a hard quota. Pairs with the count limit so a
 * 5 TB per-file cap can't be turned into petabytes/day via many uploads.
 */
export async function rateLimitBytes(
  kv: KVNamespace,
  key: string,
  addBytes: number,
  limitBytes: number,
  windowSec: number,
  nowMs: number = Date.now(),
): Promise<boolean> {
  const window = Math.floor(nowMs / 1000 / windowSec);
  const k = `rlb:${key}:${window}`;
  const current = parseInt((await kv.get(k)) || "0", 10);
  if (current + addBytes > limitBytes) return false;
  await kv.put(k, String(current + addBytes), { expirationTtl: windowSec * 2 });
  return true;
}
