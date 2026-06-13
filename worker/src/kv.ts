// KV-backed rate limiting + small state helpers (confirm nonces, revocation,
// idempotency flags). All state here is short-lived and self-expiring — there is
// no persistent email↔key store anywhere in FileKey Drop.

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
  if (current >= limit) return false;
  await kv.put(k, String(current + 1), { expirationTtl: windowSec * 2 });
  return true;
}
