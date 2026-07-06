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
//   pendingf — un-downloaded files at rest (finalId -> {bytes, expiresAt}); summed as the CAPACITY basis
//              (capacity = credit balance). Self-correcting: an entry is removed on its first download
//              (charge) or discard (releasePending) and otherwise drops out at its expiry (object
//              lifetime), so neither expired nor downloaded files inflate the basis.
//   balance  — prepaid credit in bytes; lazy-seeded to the free grant on first touch (Phase 2)
//   tier     — "free" | "paid"; flips to "paid" on the first credit() (a Stripe top-up)
//   paid     — finalId -> expiresAt for files already charged (free re-downloads); pruned past expiry
//   cmt      — finalId -> expiresAt for deliveries already counted into `total` (commitDelivered's
//              idempotency ledger, so a crashed-then-retried or duplicate completion can never double- or
//              under-count the inbound meter); pruned past expiry like `paid`
//   evt:<id> — one key per credited Stripe event (webhook idempotency; per-key, not a growing map; 2b)
import { DurableObject } from "cloudflare:workers";

// A reservation must outlive any LEGITIMATE completion (CompletionGuard's RUNNING_TTL treats an attempt
// as live for 15 min) but clean up a crashed one. 20 min > the guard window, so a stalled-but-live
// completion can never have its hold pruned out from under it (another upload reserving that freed
// space, then both committing, would put pending over the balance).
const RESERVATION_TTL_MS = 20 * 60_000;
const ALARM_GRACE_MS = 1000; // fire the alarm just after a reservation is provably expired

// A paid-file flag and a pending-file entry must outlive the OBJECT they track (fetchbind TTL is 8 days,
// the R2 lifecycle reaps at 7), so 10 days covers the object's whole life with margin; after that the
// object is gone and the entry is dead weight, dropped lazily (on touch) and opportunistically (in alarm).
const DAY_MS = 86_400_000;
const FILE_TTL_MS = 10 * DAY_MS;
// Pending (at-rest) entries are the CAPACITY basis, so they get a tighter TTL: the object is reaped at
// 7 days, and every phantom day past that is capacity the receiver can't use. 8 days = the object's whole
// life + a day of clock slack, and matches the fetchbind TTL (past it the file can't be fetched anyway).
const PENDING_TTL_MS = 8 * DAY_MS;

const clampBytes = (n: number): number => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);

type Reservation = { bytes: number; expiresAt: number };
type Reservations = Record<string, Reservation>;
type PendingFile = { bytes: number; expiresAt: number };
type PendingFiles = Record<string, PendingFile>; // finalId -> {bytes, expiresAt}
type PaidFiles = Record<string, number>; // finalId -> expiresAt
type CommittedFiles = Record<string, number>; // finalId -> expiresAt (deliveries already counted into total)

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
  private async committedFiles(): Promise<CommittedFiles> {
    return (await this.ctx.storage.get<CommittedFiles>("cmt")) ?? {};
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
  /** Drop commit markers whose object has expired (same shape as prunePaid). */
  private pruneCmt(cmt: CommittedFiles, now: number): boolean {
    let changed = false;
    for (const k in cmt)
      if (cmt[k]! <= now) {
        delete cmt[k];
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
   * Atomically HOLD `bytes` for an in-flight upload against the receiver's CAPACITY, which IS the credit
   * balance: un-downloaded bytes at rest (pending) + other live holds + this upload may never exceed what
   * the receiver could pay to download. So no delivery can strand a file its receiver can't afford, total
   * at-rest storage per account is bounded by prepaid credit, and a fresh account's capacity is simply its
   * seeded grant — free accounts need no special-casing, and capacity returns as files are downloaded
   * (charge() spends balance but clears pending), discarded (releasePending) or expire (the pending TTL).
   * `enforce=false` (billing off) holds without checking, preserving the free Phase-1 behavior. Returns a
   * token for release(); rejects (holding nothing) when the capacity check fails.
   */
  async reserve(bytes: number, grant: number, enforce: boolean): Promise<{ ok: true; token: string } | { ok: false }> {
    const add = clampBytes(bytes);
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    if (enforce) {
      const capacity = await this.balance(grant);
      const atRest = this.livePending(await this.pendingFiles(), now);
      if (atRest + this.liveReserved(res, now) + add > capacity) {
        await this.ctx.storage.put("res", res); // persist the prune
        await this.rescheduleAlarm(res);
        return { ok: false };
      }
    }
    const token = crypto.randomUUID();
    res[token] = { bytes: add, expiresAt: now + RESERVATION_TTL_MS };
    await this.ctx.storage.put("res", res);
    await this.rescheduleAlarm(res);
    return { ok: true, token };
  }

  /** Count a DELIVERED file into the permanent meters, idempotent per finalId: the `cmt` marker makes a
   *  crashed-then-retried completion, or a duplicate/reclaimed sibling delivering the SAME finalId, count
   *  exactly once — and lets the in-place path commit BEFORE the exactly-once finish() (a crash after
   *  finish can no longer under-count; see SPEC-large-files A1). Does NOT touch the reservation: the
   *  caller always release()s its hold separately (the finally). Always accrues lifetime `total`; records
   *  the file in `pendingf` (at-rest) ONLY when `accruePending` is set — i.e. when billing is on, since
   *  pending is the capacity (= balance) basis — so the delivery hot path stays cheap while billing is
   *  off. NOTE for 2b: at scale, move `pendingf`/`paid`/`cmt` from single JSON values to per-file DO keys
   *  (the 128 KB value limit). All mutated keys are written in one atomic put. */
  async commitDelivered(finalId: string, bytes: number, accruePending: boolean): Promise<void> {
    const now = Date.now();
    const cmt = await this.committedFiles();
    const pruned = this.pruneCmt(cmt, now);
    if (cmt[finalId] && cmt[finalId]! > now) {
      if (pruned) await this.ctx.storage.put({ cmt }); // persist the prune; the delivery is already counted
      return;
    }
    cmt[finalId] = now + FILE_TTL_MS;
    const writes: Record<string, unknown> = { total: (await this.committed()) + clampBytes(bytes), cmt };
    if (accruePending) {
      // An already-downloaded file is NOT pending: a delayed commit (crash-then-retry racing a fast
      // receiver) must not resurrect a paid file's capacity hold.
      const paid = await this.paidFiles();
      if (!(paid[finalId] && paid[finalId]! > now)) {
        const pf = await this.pendingFiles();
        this.prunePending(pf, now);
        pf[finalId] = { bytes: clampBytes(bytes), expiresAt: now + PENDING_TTL_MS };
        writes.pendingf = pf;
      }
    }
    await this.ctx.storage.put(writes);
  }

  /** Free the at-rest hold for a DISCARDED (deleted-without-download) file, so its capacity returns
   *  immediately instead of at the pending TTL. Downloaded files were already cleared by charge();
   *  idempotent, and purely an accelerator — the entry self-expires either way. */
  async releasePending(finalId: string): Promise<void> {
    const pf = await this.pendingFiles();
    if (!(finalId in pf)) return;
    delete pf[finalId];
    await this.ctx.storage.put("pendingf", pf);
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

  /** Alarm: prune reservations from crashed attempts, and opportunistically prune dead paid/pending/cmt
   *  file entries while we're awake, then reschedule for the next reservation expiry. */
  async alarm(): Promise<void> {
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    const writes: Record<string, unknown> = { res };
    const pf = await this.pendingFiles();
    if (this.prunePending(pf, now)) writes.pendingf = pf;
    const paid = await this.paidFiles();
    if (this.prunePaid(paid, now)) writes.paid = paid;
    const cmt = await this.committedFiles();
    if (this.pruneCmt(cmt, now)) writes.cmt = cmt;
    await this.ctx.storage.put(writes);
    await this.rescheduleAlarm(res);
  }
}
