// Per-object completion guard (Durable Object): the atomic, single-threaded replacement for the soft
// KV `done:`/`completing:` flags. A DO instance is single-threaded, so claim() is a true atomic
// check-and-set — KV's get-then-put is not, and could race two concurrent upload-complete calls into
// two delivery emails. One instance per objectId (idFromName(objectId)).
//
// Exactly-once-delivery design (see the Codex review):
// - Fencing token: claim() returns a random owner token; finish()/release() only act for that token,
//   so a stale attempt can never clobber a newer attempt's lock.
// - RUNNING_TTL is longer than any completion can run, so a still-alive attempt is NEVER reclaimed
//   (the only way two runners could both email). Only a genuinely crashed attempt is reclaimed.
// - peek() is read-only (no storage write), so the early idempotency check spawns no DO state/alarm
//   for arbitrary object ids.
import { DurableObject } from "cloudflare:workers";

const RUNNING_TTL_MS = 5 * 60_000; // > any completion (assemble+copy+email); a live attempt is never reclaimed
const STATE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // keep the done record ~ the object lifecycle, then self-clean

type Stored = { phase: "running" | "done"; owner?: string; runAt?: number };
export type ClaimResult = { ok: true; token: string } | { ok: false; reason: "running" | "done" };

export class CompletionGuard extends DurableObject {
  /** Read-only: already delivered / in progress / free? Writes nothing, so calling it for an arbitrary
   *  (even bogus) object id spawns no persistent storage or alarm. */
  async peek(): Promise<"fresh" | "running" | "done"> {
    const s = await this.ctx.storage.get<Stored>("s");
    if (s?.phase === "done") return "done";
    if (s?.phase === "running" && s.runAt !== undefined && Date.now() - s.runAt < RUNNING_TTL_MS) return "running";
    return "fresh";
  }

  /** Atomically take the completion lock, returning an owner token. Fails if already done, or a fresh
   *  attempt is still running. A stale running lock (a crashed attempt) is reclaimable. */
  async claim(): Promise<ClaimResult> {
    const s = await this.ctx.storage.get<Stored>("s");
    if (s?.phase === "done") return { ok: false, reason: "done" };
    if (s?.phase === "running" && s.runAt !== undefined && Date.now() - s.runAt < RUNNING_TTL_MS) return { ok: false, reason: "running" };
    const token = crypto.randomUUID();
    await this.ctx.storage.put("s", { phase: "running", owner: token, runAt: Date.now() } satisfies Stored);
    await this.ctx.storage.setAlarm(Date.now() + STATE_TTL_MS);
    return { ok: true, token };
  }

  /** True only if THIS token still owns a NON-STALE running lock. Checked right before the irreversible
   *  email so a stalled, about-to-be-reclaimed attempt aborts instead of sending a duplicate — fences the
   *  side effect, not just the state. (Residual: a stall landing exactly on the TTL boundary with a slow
   *  email is still possible, but that's a duplicate email, not data loss.) */
  async heldBy(token: string): Promise<boolean> {
    const s = await this.ctx.storage.get<Stored>("s");
    return s?.phase === "running" && s.owner === token && s.runAt !== undefined && Date.now() - s.runAt < RUNNING_TTL_MS;
  }

  /** Mark delivered — only the current owner may. Returns false if the lock was reclaimed by someone
   *  else (already-done counts as success/idempotent). */
  async finish(token: string): Promise<boolean> {
    const s = await this.ctx.storage.get<Stored>("s");
    if (s?.phase === "done") return true;
    if (s?.phase === "running" && s.owner === token) {
      await this.ctx.storage.put("s", { phase: "done" } satisfies Stored);
      return true;
    }
    return false;
  }

  /** Release the lock after a retryable failure — only the current owner may, so a reclaimed attempt
   *  can't wipe a newer owner's lock. */
  async release(token: string): Promise<void> {
    const s = await this.ctx.storage.get<Stored>("s");
    if (s?.phase === "running" && s.owner === token) await this.ctx.storage.delete("s");
  }

  /** TTL cleanup: the object has expired anyway, so drop the record. */
  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
