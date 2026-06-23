// Per-receiver account (Durable Object): the persistent per-recipient state behind inbound metering,
// the capacity cap, and (Phase 2) the prepaid balance + per-file download charge. One instance per
// receiver id (rid = HMAC over the receiver's CONFIRMED email, see handlers.receiverId), so every link,
// every upload, AND every download for one recipient shares a single counter. Single-threaded, so
// reserve() and charge() are true atomic check-and-acts — KV's get-then-put is not.
//
// CRASH ATOMICITY: every method that mutates more than one key writes them in a SINGLE storage.put({...})
// (a multi-key put commits atomically), so a crash can never leave a half-applied charge/credit/commit
// (e.g. balance debited but the paid flag missing, or a Stripe event marked seen but the credit lost).
//
// TRANSACTIONAL upload charge (Phase 1): upload-complete RESERVES the actual object size against the cap
// before the delivery email, then COMMITS it iff this attempt won the exactly-once delivery race
// (CompletionGuard.finish() === "won"), else RELEASES it. Because finish() makes the running->done
// transition exactly once, at most one attempt ever commits — so a completion-guard reclaim can't
// double-charge. Reservations carry a TTL and an alarm prunes them, so an attempt that crashes between
// reserve and commit/release frees its hold instead of stranding cap space forever.
//
// PER-FILE download charge (Phase 2): charge() atomically debits `balance` once per finalId and records
// it in `paidFiles`, so re-downloads are free and a double-clicked/retried download can't double-charge
// (the single-threaded DO serializes; the second call sees the paid flag). Marking the file paid IS the
// idempotency key, so no reserve/commit dance is needed on the download side.
//
// State (schemaless DO storage; every field lazy-defaults, so old accounts cost no migration):
//   total    — committed cumulative inbound bytes (the lifetime meter; always accrues, even uncapped)
//   res      — in-flight upload reservations (token -> {bytes, expiresAt})
//   pendingf — un-downloaded files at rest (finalId -> {bytes, expiresAt}); summed for the paid 100 GB
//              cap. Self-correcting: an entry is removed on its first download and otherwise drops out at
//              its expiry (object lifetime), so neither expired nor downloaded files inflate the cap.
//   balance  — prepaid credit in bytes; lazy-seeded to the free grant on first touch (Phase 2)
//   tier     — "free" | "paid"; flips to "paid" on the first credit() (a Stripe top-up)
//   paid     — finalId -> expiresAt for files already charged (free re-downloads); pruned past expiry
//   evt:<id> — one key per credited Stripe event (webhook idempotency; per-key, not a growing map; 2b)
import { DurableObject } from "cloudflare:workers";

// A reservation must outlive any LEGITIMATE completion (CompletionGuard RUNNING_TTL is 5 min, and a
// real completion commits in seconds) but clean up a crashed one. 10 min frees a crashed hold well
// after any live attempt would have committed.
const RESERVATION_TTL_MS = 10 * 60_000;
const ALARM_GRACE_MS = 1000; // fire the alarm just after a reservation is provably expired

// A paid-file flag and a pending-file entry must outlive the OBJECT they track (fetchbind TTL is 8 days,
// the R2 lifecycle reaps at 7), so 10 days covers the object's whole life with margin; after that the
// object is gone and the entry is dead weight, dropped lazily (on touch) and opportunistically (in alarm).
const DAY_MS = 86_400_000;
const FILE_TTL_MS = 10 * DAY_MS;

const clampBytes = (n: number): number => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);

type Reservation = { bytes: number; expiresAt: number };
type Reservations = Record<string, Reservation>;
type PendingFile = { bytes: number; expiresAt: number };
type PendingFiles = Record<string, PendingFile>; // finalId -> {bytes, expiresAt}
type PaidFiles = Record<string, number>; // finalId -> expiresAt

export type Tier = "free" | "paid";
export type ChargeResult = { ok: true; alreadyPaid: boolean; balance: number } | { ok: false; balance: number; need: number };
export type AccountSummary = { tier: Tier; total: number; pending: number; balance: number; reserved: number };

export class ReceiverAccount extends DurableObject {
  private async committed(): Promise<number> {
    return (await this.ctx.storage.get<number>("total")) ?? 0;
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
  private async pendingFiles(): Promise<PendingFiles> {
    return (await this.ctx.storage.get<PendingFiles>("pendingf")) ?? {};
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
  /** Sum of still-live pending (un-downloaded, un-expired) files — the paid at-rest cap basis. Expired
   *  entries are excluded here (accurate cap even before they're pruned from storage). */
  private livePending(pf: PendingFiles, now: number): number {
    let sum = 0;
    for (const k in pf) if (pf[k]!.expiresAt > now) sum += pf[k]!.bytes;
    return sum;
  }

  /** Drop expired holds in place (a crashed attempt's reservation that was never committed/released). */
  private prune(res: Reservations, now: number): void {
    for (const k in res) if (res[k]!.expiresAt <= now) delete res[k];
  }
  /** Drop pending-file entries whose object has expired. Returns true if anything was removed. */
  private prunePending(pf: PendingFiles, now: number): boolean {
    let changed = false;
    for (const k in pf)
      if (pf[k]!.expiresAt <= now) {
        delete pf[k];
        changed = true;
      }
    return changed;
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
   *  (Paid/pending file entries are pruned lazily, not alarm-driven, so an idle account isn't kept awake.) */
  private async rescheduleAlarm(res: Reservations): Promise<void> {
    let next = Infinity;
    for (const k in res) next = Math.min(next, res[k]!.expiresAt);
    if (next === Infinity) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(next + ALARM_GRACE_MS);
  }

  /**
   * Atomically HOLD `bytes` for an in-flight upload against the receiver's tier cap (cap <= 0 = uncapped).
   * Free accounts are capped on lifetime `total`; paid accounts on at-rest pending. The check counts the
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
    const basis = paid ? this.livePending(await this.pendingFiles(), now) : await this.committed();
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
   *  this. Always accrues lifetime `total`. Records the delivered file in `pendingf` (at-rest, removed on
   *  its first download or dropped at expiry) ONLY when `accruePending` is set — i.e. when the paid at-rest
   *  cap is active. While that cap is off (Phase 2a's default), `pendingf` isn't touched, so the delivery
   *  hot path stays as cheap and bounded as Phase 1 (no growing-map write that could hit the 128 KB DO
   *  value limit). NOTE for 2b: before enabling the paid cap at scale, move `pendingf`/`paid` from a single
   *  JSON value to per-file DO keys (storage.list) — a 100 GB cap implies far more entries than one value
   *  holds. All mutated keys are written in one atomic put. Idempotent: a token already committed/released,
   *  or expired (pathological >TTL stall, dropped without charging — a safe under-count), is a no-op. */
  async commit(token: string, finalId: string, accruePending: boolean): Promise<void> {
    const now = Date.now();
    const res = await this.holds();
    const r = res[token];
    if (!r) return; // already committed/released, or pruned by the alarm
    delete res[token];
    if (r.expiresAt > now) {
      const writes: Record<string, unknown> = { total: (await this.committed()) + r.bytes, res };
      if (accruePending) {
        const pf = await this.pendingFiles();
        this.prunePending(pf, now);
        pf[finalId] = { bytes: r.bytes, expiresAt: now + FILE_TTL_MS };
        writes.pendingf = pf;
      }
      await this.ctx.storage.put(writes);
    } else {
      await this.ctx.storage.put("res", res);
    }
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
   * later fetch is free, and its pending entry is cleared (it's no longer un-downloaded). Returns ok:false
   * (no state change) when the balance can't cover it, which the caller turns into a 402. Single-threaded
   * execution + the paid flag make a crash-then-retry safe: the retry sees the flag and returns free, so
   * the user is charged once and still gets the file. balance/paid/pending are written in one atomic put.
   */
  async charge(finalId: string, size: number, grant: number): Promise<ChargeResult> {
    const need = clampBytes(size);
    const now = Date.now();
    const paid = await this.paidFiles();
    const prunedPaid = this.prunePaid(paid, now);
    const balance = await this.balance(grant);

    if (paid[finalId] && paid[finalId]! > now) {
      if (prunedPaid) await this.ctx.storage.put({ paid });
      return { ok: true, alreadyPaid: true, balance };
    }
    if (balance < need) {
      if (prunedPaid) await this.ctx.storage.put({ paid });
      return { ok: false, balance, need };
    }
    paid[finalId] = now + FILE_TTL_MS;
    const pf = await this.pendingFiles();
    delete pf[finalId]; // downloaded -> no longer pending (idempotent: a no-op if already gone/expired)
    await this.ctx.storage.put({ balance: balance - need, paid, pendingf: pf });
    return { ok: true, alreadyPaid: false, balance: balance - need };
  }

  /** Add prepaid credit (a Stripe top-up) and mark the account paid. Idempotent on the Stripe event id so a
   *  webhook retry can't double-credit: each credited event is its OWN `evt:<id>` storage key (not a single
   *  growing map — that would hit the 128 KB value limit for a high-volume account), and the seen-marker +
   *  balance + tier are written in one atomic put so a crash can't mark the event credited while losing the
   *  credit. (Phase 2b.) */
  async credit(packBytes: number, grant: number, eventId?: string): Promise<{ balance: number }> {
    if (eventId && (await this.ctx.storage.get(`evt:${eventId}`))) return { balance: await this.balance(grant) }; // already applied
    const newBalance = (await this.balance(grant)) + clampBytes(packBytes);
    const writes: Record<string, unknown> = { balance: newBalance, tier: "paid" satisfies Tier };
    if (eventId) writes[`evt:${eventId}`] = true;
    await this.ctx.storage.put(writes);
    return { balance: newBalance };
  }

  /** Read-only snapshot for the upload-init fail-fast pre-check (and support/debug). Prunes nothing;
   *  live* sums exclude expired entries, so the counts are accurate without mutating storage. */
  async summary(grant: number): Promise<AccountSummary> {
    const now = Date.now();
    const res = await this.holds();
    return {
      tier: await this.tier(),
      total: await this.committed(),
      pending: this.livePending(await this.pendingFiles(), now),
      balance: await this.balance(grant),
      reserved: this.liveReserved(res, now),
    };
  }

  /** Alarm: prune reservations from crashed attempts, and opportunistically prune dead paid/pending file
   *  entries while we're awake, then reschedule for the next reservation expiry. */
  async alarm(): Promise<void> {
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    const writes: Record<string, unknown> = { res };
    const pf = await this.pendingFiles();
    if (this.prunePending(pf, now)) writes.pendingf = pf;
    const paid = await this.paidFiles();
    if (this.prunePaid(paid, now)) writes.paid = paid;
    await this.ctx.storage.put(writes);
    await this.rescheduleAlarm(res);
  }
}
