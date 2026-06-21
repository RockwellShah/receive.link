// Per-receiver account (Durable Object): the persistent per-recipient state behind inbound metering
// and the capacity cap. One instance per receiver id (rid = HMAC over the receiver's CONFIRMED email,
// see handlers.receiverId), so every link AND every upload for one recipient shares a single counter.
// Single-threaded, so reserve() is a true atomic check-and-hold — KV's get-then-put is not.
//
// TRANSACTIONAL charge (Phase 1): upload-complete RESERVES the actual object size against the cap
// before the delivery email, then COMMITS it iff this attempt won the exactly-once delivery race
// (CompletionGuard.finish() === "won"), else RELEASES it. Because finish() makes the running->done
// transition exactly once, at most one attempt ever commits — so a completion-guard reclaim can't
// double-charge. Reservations carry a TTL and an alarm prunes them, so an attempt that crashes between
// reserve and commit/release frees its hold instead of stranding cap space forever. Together that makes
// the charge exactly-once + crash-durable: the prerequisite for safely enabling RECEIVER_INBOUND_CAP_BYTES.
// (Replaces the Phase-0 provisional charge/refund, which double-counted on a crash or a reclaim.)
//
// `total` = committed cumulative inbound bytes (the meter; always accrues, even uncapped). Prepaid
// balance / pending-at-rest / paid-file flags arrive with Stripe (Phase 2); DO storage is schemaless.
import { DurableObject } from "cloudflare:workers";

// A reservation must outlive any LEGITIMATE completion (CompletionGuard RUNNING_TTL is 5 min, and a
// real completion commits in seconds) but clean up a crashed one. 10 min frees a crashed hold well
// after any live attempt would have committed.
const RESERVATION_TTL_MS = 10 * 60_000;
const ALARM_GRACE_MS = 1000; // fire the alarm just after a reservation is provably expired

const clampBytes = (n: number): number => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);

type Reservation = { bytes: number; expiresAt: number };
type Reservations = Record<string, Reservation>;

export class ReceiverAccount extends DurableObject {
  private async committed(): Promise<number> {
    return (await this.ctx.storage.get<number>("total")) ?? 0;
  }
  private async holds(): Promise<Reservations> {
    return (await this.ctx.storage.get<Reservations>("res")) ?? {};
  }

  /** Sum of still-live reservations (expired holds don't count against the cap). */
  private liveReserved(res: Reservations, now: number): number {
    let sum = 0;
    for (const k in res) if (res[k]!.expiresAt > now) sum += res[k]!.bytes;
    return sum;
  }

  /** Drop expired holds in place (a crashed attempt's reservation that was never committed/released). */
  private prune(res: Reservations, now: number): void {
    for (const k in res) if (res[k]!.expiresAt <= now) delete res[k];
  }

  /** Set the alarm to the earliest remaining expiry, or clear it when no holds remain. */
  private async rescheduleAlarm(res: Reservations): Promise<void> {
    let next = Infinity;
    for (const k in res) next = Math.min(next, res[k]!.expiresAt);
    if (next === Infinity) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(next + ALARM_GRACE_MS);
  }

  /**
   * Atomically HOLD `bytes` against `cap` (cap <= 0 = uncapped). The check counts committed `total`
   * PLUS other live reservations, so two concurrent uploads to one recipient can't both slip a tight
   * cap. Returns a token for commit()/release(); rejects (holding nothing) when it would exceed a
   * positive cap.
   */
  async reserve(bytes: number, cap: number): Promise<{ ok: true; token: string } | { ok: false }> {
    const add = clampBytes(bytes);
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    if (cap > 0 && (await this.committed()) + this.liveReserved(res, now) + add > cap) {
      await this.ctx.storage.put("res", res); // persist the prune
      await this.rescheduleAlarm(res);
      return { ok: false };
    }
    const token = crypto.randomUUID();
    res[token] = { bytes: add, expiresAt: now + RESERVATION_TTL_MS };
    await this.ctx.storage.put("res", res);
    await this.rescheduleAlarm(res);
    return { ok: true, token };
  }

  /** Commit a held reservation into the permanent total — only the exactly-once delivery winner calls
   *  this. Idempotent: a token already committed/released, or expired (pathological >TTL stall, dropped
   *  without charging — a safe under-count, never over), is a no-op. */
  async commit(token: string): Promise<void> {
    const now = Date.now();
    const res = await this.holds();
    const r = res[token];
    if (!r) return; // already committed/released, or pruned by the alarm
    delete res[token];
    if (r.expiresAt > now) await this.ctx.storage.put("total", (await this.committed()) + r.bytes);
    await this.ctx.storage.put("res", res);
    await this.rescheduleAlarm(res);
  }

  /** Release a held reservation: an aborted attempt, or a duplicate delivery that LOST the exactly-once
   *  race (so the winner's commit is the one true charge). Idempotent. */
  async release(token: string): Promise<void> {
    const res = await this.holds();
    if (!res[token]) return;
    delete res[token];
    await this.ctx.storage.put("res", res);
    await this.rescheduleAlarm(res);
  }

  /** Alarm: prune reservations from crashed attempts (never committed/released), then reschedule. */
  async alarm(): Promise<void> {
    const res = await this.holds();
    this.prune(res, Date.now());
    await this.ctx.storage.put("res", res);
    await this.rescheduleAlarm(res);
  }
}
