// Per-object completion guard (Durable Object): the atomic, single-threaded replacement for the soft
// KV `done:`/`completing:` flags. A DO instance is single-threaded, so claim() is a true atomic
// check-and-set — KV's get-then-put is not, and could race two concurrent upload-complete calls into
// two delivery emails. One instance per objectId (idFromName(objectId)).
import { DurableObject } from "cloudflare:workers";

const RUNNING_TTL_MS = 120_000; // a crashed completion's lock becomes reclaimable after this
const STATE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // keep the done record ~ the object lifecycle, then self-clean

type Stored = { state: "running" | "done"; runAt?: number };
export type Claim = "claimed" | "running" | "done";

export class CompletionGuard extends DurableObject {
  /** Atomically claim the right to complete this object, or learn it's already done / in progress. */
  async claim(): Promise<Claim> {
    const s = await this.ctx.storage.get<Stored>("s");
    if (s?.state === "done") return "done";
    if (s?.state === "running" && s.runAt !== undefined && Date.now() - s.runAt < RUNNING_TTL_MS) return "running";
    await this.ctx.storage.put("s", { state: "running", runAt: Date.now() } satisfies Stored);
    await this.ctx.storage.setAlarm(Date.now() + STATE_TTL_MS);
    return "claimed";
  }

  /** Record successful delivery; every later claim() returns "done" (idempotent) until cleanup. */
  async finish(): Promise<void> {
    await this.ctx.storage.put("s", { state: "done" } satisfies Stored);
  }

  /** Release the running lock after a retryable failure, so a retry can re-claim. */
  async release(): Promise<void> {
    const s = await this.ctx.storage.get<Stored>("s");
    if (s?.state === "running") await this.ctx.storage.delete("s");
  }

  /** TTL cleanup: the object has expired anyway, so drop the record. */
  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
