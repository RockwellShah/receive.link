// Per-receiver account (Durable Object): the persistent per-recipient state behind inbound metering,
// the capacity cap, and (Phase 2) the prepaid balance + per-file download charge. One instance per
// receiver id (rid = HMAC over the receiver's CONFIRMED email, see handlers.receiverId), so every link,
// every upload, AND every download for one recipient shares a single counter. Single-threaded, so
// reserve() and charge() are true atomic check-and-acts — KV's get-then-put is not.
//
// TRANSACTIONAL upload charge (Phase 1): upload-complete RESERVES the actual object size against the cap
// before the delivery email, then COMMITS it iff this attempt won the exactly-once delivery race
// (CompletionGuard.finish() === "won"), else RELEASES it. Because finish() makes the running->done
// transition exactly once, at most one attempt ever commits — so a completion-guard reclaim can't
// double-charge. Reservations carry a TTL and an alarm prunes them, so an attempt that crashes between
// reserve and commit/release frees its hold instead of stranding cap space forever. Together that makes
// the charge exactly-once + crash-durable.
//
// PER-FILE download charge (Phase 2): charge() atomically debits `balance` once per finalId and records
// it in `paidFiles`, so re-downloads are free and a double-clicked/retried download can't double-charge
// (the single-threaded DO serializes; the second call sees the paid flag). No reserve/commit dance is
// needed on the download side because marking the file paid IS the idempotency key.
//
// State (schemaless DO storage; every field lazy-defaults, so old accounts cost no migration):
//   total    — committed cumulative inbound bytes (the lifetime meter; always accrues, even uncapped)
//   res      — in-flight upload reservations (token -> {bytes, expiresAt})
//   balance  — prepaid credit in bytes; lazy-seeded to the free grant on first touch (Phase 2)
//   pending  — un-downloaded bytes at rest (the paid 100 GB cap): += on commit, -= on first download
//   tier     — "free" | "paid"; flips to "paid" on the first credit() (a Stripe top-up)
//   paid     — finalId -> expiresAt for files already charged (free re-downloads); pruned past expiry
//   events   — Stripe event ids already credited (webhook idempotency; Phase 2b)
import { DurableObject } from "cloudflare:workers";

// A reservation must outlive any LEGITIMATE completion (CompletionGuard RUNNING_TTL is 5 min, and a
// real completion commits in seconds) but clean up a crashed one. 10 min frees a crashed hold well
// after any live attempt would have committed.
const RESERVATION_TTL_MS = 10 * 60_000;
const ALARM_GRACE_MS = 1000; // fire the alarm just after a reservation is provably expired

// A paid-file flag must outlive the OBJECT it frees re-downloads for (fetchbind TTL is 8 days, the R2
// lifecycle reaps at 7), so 10 days covers the object's whole life with margin; after that the object is
// gone and the flag is dead weight, so it's pruned lazily (on charge) and opportunistically (in alarm).
const DAY_MS = 86_400_000;
const PAID_TTL_MS = 10 * DAY_MS;

const clampBytes = (n: number): number => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);

type Reservation = { bytes: number; expiresAt: number };
type Reservations = Record<string, Reservation>;
type PaidFiles = Record<string, number>; // finalId -> expiresAt

export type Tier = "free" | "paid";
export type ChargeResult = { ok: true; alreadyPaid: boolean; balance: number } | { ok: false; balance: number; need: number };
export type AccountSummary = { tier: Tier; total: number; pending: number; balance: number; reserved: number };

export class ReceiverAccount extends DurableObject {
  private async committed(): Promise<number> {
    return (await this.ctx.storage.get<number>("total")) ?? 0;
  }
  private async pending(): Promise<number> {
    return (await this.ctx.storage.get<number>("pending")) ?? 0;
  }
  /** Credit balance in bytes; lazy-seeded to the free grant the first time it's read for an account that
   *  has never been credited or charged (so a brand-new receiver starts with the free 1 GB). */
  private async balance(grant: number): Promise<number> {
    return (await this.ctx.storage.get<number>("balance")) ?? clampBytes(grant);
  }
  private async tier(): Promise<Tier> {
    return (await this.ctx.storage.get<Tier>("tier")) ?? "free";
  }
  private async holds(): Promise<Reservations> {
    return (await this.ctx.storage.get<Reservations>("res")) ?? {};
  }
  private async paidFiles(): Promise<PaidFiles> {
    return (await this.ctx.storage.get<PaidFiles>("paid")) ?? {};
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

  /** Drop paid-file flags whose object has expired. Returns true if anything was removed. */
  private prunePaid(paid: PaidFiles, now: number): boolean {
    let changed = false;
    for (const k in paid)
      if (paid[k]! <= now) {
        delete paid[k];
        changed = true;
      }
    return changed;
  }

  /** Set the alarm to the earliest remaining reservation expiry, or clear it when no holds remain.
   *  (Paid-file flags are pruned lazily, not alarm-driven, so an idle paid account isn't kept awake.) */
  private async rescheduleAlarm(res: Reservations): Promise<void> {
    let next = Infinity;
    for (const k in res) next = Math.min(next, res[k]!.expiresAt);
    if (next === Infinity) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(next + ALARM_GRACE_MS);
  }

  /**
   * Atomically HOLD `bytes` for an in-flight upload against the receiver's tier cap (cap <= 0 = uncapped).
   * Free accounts are capped on lifetime `total`; paid accounts on at-rest `pending`. The check counts the
   * committed basis PLUS other live reservations, so two concurrent uploads to one recipient can't both
   * slip a tight cap. Returns a token for commit()/release(); rejects (holding nothing) when it would
   * exceed a positive cap.
   */
  async reserve(bytes: number, freeCap: number, paidCap: number): Promise<{ ok: true; token: string } | { ok: false }> {
    const add = clampBytes(bytes);
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    const paid = (await this.tier()) === "paid";
    const cap = paid ? paidCap : freeCap;
    const basis = paid ? await this.pending() : await this.committed();
    if (cap > 0 && basis + this.liveReserved(res, now) + add > cap) {
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

  /** Commit a held reservation into the permanent meters — only the exactly-once delivery winner calls
   *  this. Accrues both `total` (lifetime) and `pending` (at-rest, decremented later on download).
   *  Idempotent: a token already committed/released, or expired (pathological >TTL stall, dropped without
   *  charging — a safe under-count, never over), is a no-op. */
  async commit(token: string): Promise<void> {
    const now = Date.now();
    const res = await this.holds();
    const r = res[token];
    if (!r) return; // already committed/released, or pruned by the alarm
    delete res[token];
    if (r.expiresAt > now) {
      await this.ctx.storage.put("total", (await this.committed()) + r.bytes);
      await this.ctx.storage.put("pending", (await this.pending()) + r.bytes);
    }
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

  /**
   * Atomically charge a per-file download. Exactly-once per finalId: an already-paid file (a re-download,
   * or a double-clicked/retried Save) is free and touches nothing; otherwise the file size is debited from
   * `balance` (the free 1 GB grant is just the seeded starting balance), the file is flagged paid so every
   * later fetch is free, and `pending` is decremented (the bytes are no longer un-downloaded). Returns
   * ok:false (no state change) when the balance can't cover it, which the caller turns into a 402.
   * Single-threaded execution + the paid flag make a crash-then-retry safe: the retry sees the flag and
   * returns free, so the user is charged once and still gets the file.
   */
  async charge(finalId: string, size: number, grant: number): Promise<ChargeResult> {
    const need = clampBytes(size);
    const now = Date.now();
    const paid = await this.paidFiles();
    const prunedPaid = this.prunePaid(paid, now);
    const balance = await this.balance(grant);

    if (paid[finalId] && paid[finalId]! > now) {
      if (prunedPaid) await this.ctx.storage.put("paid", paid);
      return { ok: true, alreadyPaid: true, balance };
    }
    if (balance < need) {
      if (prunedPaid) await this.ctx.storage.put("paid", paid);
      return { ok: false, balance, need };
    }
    paid[finalId] = now + PAID_TTL_MS;
    const newBalance = balance - need;
    const newPending = Math.max(0, (await this.pending()) - need); // clamp: pre-Phase-2 files were never counted in
    await this.ctx.storage.put("balance", newBalance);
    await this.ctx.storage.put("paid", paid);
    await this.ctx.storage.put("pending", newPending);
    return { ok: true, alreadyPaid: false, balance: newBalance };
  }

  /** Add prepaid credit (a Stripe top-up) and mark the account paid. Idempotent on the Stripe event id so
   *  a webhook retry can't double-credit. (Phase 2b.) */
  async credit(packBytes: number, grant: number, eventId?: string): Promise<{ balance: number }> {
    if (eventId) {
      const seen = (await this.ctx.storage.get<Record<string, true>>("events")) ?? {};
      if (seen[eventId]) return { balance: await this.balance(grant) }; // already applied this event
      seen[eventId] = true;
      await this.ctx.storage.put("events", seen);
    }
    const newBalance = (await this.balance(grant)) + clampBytes(packBytes);
    await this.ctx.storage.put("balance", newBalance);
    await this.ctx.storage.put("tier", "paid" satisfies Tier);
    return { balance: newBalance };
  }

  /** Read-only snapshot for the upload-init fail-fast pre-check (and support/debug). Prunes expired
   *  reservations in memory for an accurate live count, but doesn't mutate stored meters. */
  async summary(grant: number): Promise<AccountSummary> {
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    return {
      tier: await this.tier(),
      total: await this.committed(),
      pending: await this.pending(),
      balance: await this.balance(grant),
      reserved: this.liveReserved(res, now),
    };
  }

  /** Alarm: prune reservations from crashed attempts, and opportunistically prune dead paid-file flags
   *  while we're awake, then reschedule for the next reservation expiry. */
  async alarm(): Promise<void> {
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    await this.ctx.storage.put("res", res);
    const paid = await this.paidFiles();
    if (this.prunePaid(paid, now)) await this.ctx.storage.put("paid", paid);
    await this.rescheduleAlarm(res);
  }
}
