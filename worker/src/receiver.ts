// Per-receiver account (Durable Object): the persistent per-recipient state behind inbound metering,
// the capacity cap, and (Phase 2) the prepaid balance + per-file download charge. One instance per
// receiver id (rid = HMAC over the receiver's CONFIRMED email, see handlers.receiverId), so every link,
// every upload, AND every download for one recipient shares one DO. Single-threaded, so reserve() and
// charge() are true atomic check-and-acts — KV's get-then-put is not.
//
// CRASH ATOMICITY (money): the money-critical fields are written TOGETHER in one storage.put({...}) (a
// multi-key put commits atomically), so a crash can never leave a half-applied charge/credit (balance
// debited but the paid marker missing, or a Stripe event marked seen but the credit lost). Where a method
// also does a separate delete (charge clears the pending marker), the delete is ordered AFTER the atomic
// money put and is BENIGN if a crash skips it: a lingering pending marker only over-counts at-rest bytes
// (capacity is reduced, never expanded — fail-closed), and it self-heals (expiry / a later reconcile).
//
// PER-FILE KEYS (the 2b scale fix): the three per-file ledgers are stored as INDIVIDUAL keys, never as one
// growing JSON map, so a high-file-count receiver can't blow the per-VALUE size limit (2 MB on the prod
// SQLite-backed DO, ~28k files; 128 KiB on a KV-backed DO, ~1.7k), which would throw mid-commit and, on
// the in-place path, drop the accounting record + risk a duplicate delivery. A single put({...}) is capped
// at 128 key-value pairs regardless of backend, so batch writes stay <=128. Expiry is carried IN each
// value (expiresAt); every READ filters on it, so correctness never depends on TTL timing, and the alarm
// prunes dead keys only as storage hygiene.
//
// State (schemaless DO storage; every field lazy-defaults):
//   total        — committed cumulative inbound bytes (lifetime meter; always accrues, even billing-off)
//   balance      — prepaid credit in bytes; lazy-seeded to the free grant on first read
//   tier         — "free" | "paid"; flips to "paid" on the first credit() (a Stripe top-up)
//   res          — in-flight upload reservations (token -> {bytes, expiresAt}); small, bounded by
//                  concurrent uploads, so it stays a single map (never per-file-scale)
//   pf:<finalId> — {bytes, expiresAt}: an un-downloaded file at rest. SUMMED (live only) as the capacity
//                  basis (capacity = balance). Cleared on download (charge) or discard (releasePending);
//                  otherwise filtered out once expired and pruned by the alarm.
//   pd:<finalId> — expiresAt: a file already charged (free re-downloads + charge idempotency)
//   cm:<finalId> — expiresAt: a delivery already counted into `total` (commitDelivered idempotency, so a
//                  crashed-then-retried or duplicate completion can't double- or under-count the meter)
//   evt:<id>     — one key per credited Stripe event (webhook idempotency)
//   mig2         — set once the account has migrated the old single-map ledgers to per-file keys
import { DurableObject } from "cloudflare:workers";

// A reservation must outlive any LEGITIMATE completion (CompletionGuard's RUNNING_TTL treats an attempt
// as live for 15 min) but clean up a crashed one. 20 min > the guard window, so a stalled-but-live
// completion can never have its hold pruned out from under it (another upload reserving that freed
// space, then both committing, would put pending over the balance).
const RESERVATION_TTL_MS = 20 * 60_000;
const ALARM_GRACE_MS = 1000; // fire the alarm just after a reservation is provably expired

// A paid/committed marker must outlive the OBJECT it tracks (fetchbind TTL 8d, R2 lifecycle 7d), so 10
// days covers the object's whole life with margin; after that the object is gone and the marker is dead
// weight, filtered out by reads and pruned by the alarm.
const DAY_MS = 86_400_000;
const FILE_TTL_MS = 10 * DAY_MS;
// Pending (at-rest) entries are the CAPACITY basis, so they get a tighter TTL: the object is reaped at
// 7 days, and every phantom day past that is capacity the receiver can't use. 8 days = the object's whole
// life + a day of clock slack, and matches the fetchbind TTL (past it the file can't be fetched anyway).
const PENDING_TTL_MS = 8 * DAY_MS;

const PF = "pf:"; // per-file key prefixes
const PD = "pd:";
const CM = "cm:";
const PUT_BATCH = 128; // DO storage.put({...}) accepts at most 128 key-value pairs
const LIST_PAGE = 1000; // paginate list() so a sum/prune is correct at any key count

const clampBytes = (n: number): number => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);

type Reservation = { bytes: number; expiresAt: number };
type Reservations = Record<string, Reservation>;
type PendingFile = { bytes: number; expiresAt: number };
// Legacy (pre-migration) single-map shapes, read once by migrate().
type LegacyPending = Record<string, PendingFile>;
type LegacyExpiry = Record<string, number>;

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

  /** One-time migration of a pre-per-file account: convert the old `pendingf`/`paid`/`cmt` single maps to
   *  per-file keys, then drop the maps. Idempotent + crash-safe: per-file keys are written first (a retry
   *  re-writes the same keys), and only the final step sets `mig2` + deletes the maps, so a crash just
   *  re-runs migrate on the next call. A brand-new account has no maps and only sets `mig2`. Called at the
   *  top of every method; after the first run it costs a single `get("mig2")`. */
  private async migrate(): Promise<void> {
    if (await this.ctx.storage.get("mig2")) return;
    const oldPending = (await this.ctx.storage.get<LegacyPending>("pendingf")) ?? {};
    const oldPaid = (await this.ctx.storage.get<LegacyExpiry>("paid")) ?? {};
    const oldCmt = (await this.ctx.storage.get<LegacyExpiry>("cmt")) ?? {};
    const entries: [string, unknown][] = [];
    for (const [id, v] of Object.entries(oldPending)) entries.push([PF + id, v]);
    for (const [id, exp] of Object.entries(oldPaid)) entries.push([PD + id, exp]);
    for (const [id, exp] of Object.entries(oldCmt)) entries.push([CM + id, exp]);
    for (let i = 0; i < entries.length; i += PUT_BATCH) {
      await this.ctx.storage.put(Object.fromEntries(entries.slice(i, i + PUT_BATCH)));
    }
    // Drop the old maps BEFORE marking migrated: a crash here re-runs migrate (mig2 still unset) and the
    // per-file writes above are idempotent, so we never strand the old maps (mig2 would block re-cleanup).
    await this.ctx.storage.delete(["pendingf", "paid", "cmt"]);
    await this.ctx.storage.put({ mig2: true });
  }

  /** Live (unexpired) expiry for a per-file marker key, or 0 if absent/expired. */
  private async liveMarker(key: string, now: number): Promise<number> {
    const exp = await this.ctx.storage.get<number>(key);
    return exp && exp > now ? exp : 0;
  }

  /** Sum of still-live pending bytes — the capacity basis. Paginates the pf: keys and filters expired
   *  entries in the value, so it is correct at any file count and never depends on prune timing. */
  private async sumPending(now: number): Promise<number> {
    let sum = 0;
    let startAfter: string | undefined;
    for (;;) {
      const page: Map<string, PendingFile> = await this.ctx.storage.list<PendingFile>({ prefix: PF, startAfter, limit: LIST_PAGE });
      if (page.size === 0) break;
      let last = "";
      for (const [k, v] of page) {
        if (v && v.expiresAt > now) sum += clampBytes(v.bytes);
        last = k;
      }
      if (page.size < LIST_PAGE) break;
      startAfter = last;
    }
    return sum;
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

  /** Set the alarm to the earliest remaining reservation expiry, or clear it when no holds remain.
   *  (Per-file markers are pruned opportunistically when the alarm fires, not scheduled for, so an idle
   *  account isn't kept awake; reads filter expired entries either way.) */
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
    await this.migrate();
    const add = clampBytes(bytes);
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    if (enforce) {
      const capacity = await this.balance(grant);
      const atRest = await this.sumPending(now);
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

  /** Count a DELIVERED file into the permanent meters, idempotent per finalId: the `cm:` marker makes a
   *  crashed-then-retried completion, or a duplicate/reclaimed sibling delivering the SAME finalId, count
   *  exactly once — and lets the in-place path commit BEFORE the exactly-once finish() (a crash after
   *  finish can no longer under-count; see SPEC-large-files A1). Does NOT touch the reservation: the caller
   *  always release()s its hold separately (the finally). Always accrues lifetime `total`; records the file
   *  in `pf:` (at-rest) ONLY when `accruePending` is set — i.e. when billing is on, since pending is the
   *  capacity (= balance) basis — so the delivery hot path stays cheap while billing is off. total + the
   *  cm:/pf: markers are written in ONE atomic put; per-file keys mean this can never overflow a value. */
  async commitDelivered(finalId: string, bytes: number, accruePending: boolean): Promise<void> {
    await this.migrate();
    const now = Date.now();
    if (await this.liveMarker(CM + finalId, now)) return; // already counted (idempotent per delivery id)
    const writes: Record<string, unknown> = { total: (await this.committed()) + clampBytes(bytes), [CM + finalId]: now + FILE_TTL_MS };
    if (accruePending) {
      // An already-downloaded file is NOT pending: a delayed commit (crash-then-retry racing a fast
      // receiver) must not resurrect a paid file's capacity hold.
      if (!(await this.liveMarker(PD + finalId, now))) {
        writes[PF + finalId] = { bytes: clampBytes(bytes), expiresAt: now + PENDING_TTL_MS } satisfies PendingFile;
      }
    }
    await this.ctx.storage.put(writes);
  }

  /** Free the at-rest hold for a DISCARDED (deleted-without-download) file, so its capacity returns
   *  immediately instead of at the pending TTL. Downloaded files were already cleared by charge();
   *  idempotent, and purely an accelerator — the entry self-expires either way. */
  async releasePending(finalId: string): Promise<void> {
    await this.migrate();
    await this.ctx.storage.delete(PF + finalId);
  }

  /** Release a held reservation: an aborted attempt, or a duplicate delivery that LOST the exactly-once
   *  race (so the winner's commit is the one true charge). Idempotent. */
  async release(token: string): Promise<void> {
    await this.migrate();
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
   * (no state change) when the balance can't cover it, which the caller turns into a 402. The MONEY write
   * (balance + the pd: marker) is ONE atomic put, so a crash can't debit without marking paid; the pf:
   * delete is ordered after and is benign if skipped (a lingering pending marker only over-counts at-rest,
   * which is fail-closed and self-heals). Single-threaded + the paid marker make a crash-retry safe.
   */
  async charge(finalId: string, size: number, grant: number): Promise<ChargeResult> {
    await this.migrate();
    const need = clampBytes(size);
    const now = Date.now();
    const balance = await this.balance(grant);

    if (await this.liveMarker(PD + finalId, now)) return { ok: true, alreadyPaid: true, balance };
    if (balance < need) return { ok: false, balance, need };
    await this.ctx.storage.put({ balance: balance - need, [PD + finalId]: now + FILE_TTL_MS }); // atomic money write
    await this.ctx.storage.delete(PF + finalId); // downloaded -> no longer pending (benign if a crash skips it)
    return { ok: true, alreadyPaid: false, balance: balance - need };
  }

  /** Add prepaid credit (a Stripe top-up) and mark the account paid. Idempotent across a SET of dedupe
   *  keys: if ANY is already recorded, this is a duplicate and does nothing; otherwise ALL are recorded so
   *  a later duplicate keyed on any of them dedupes. The webhook passes both the Checkout SESSION id (the
   *  primary key — Stripe can emit multiple Event objects for one session) AND the Event id (so a
   *  pre-migration credit, recorded only under the old evt-id key, still dedupes a same-event retry after
   *  deploy). Each key is its own `evt:<key>` marker; markers + balance + tier are one atomic put, so a
   *  crash can't mark it credited while losing the credit. (Phase 2b.) */
  async credit(packBytes: number, grant: number, dedupeKeys: string[] = []): Promise<{ balance: number }> {
    await this.migrate();
    for (const key of dedupeKeys) {
      if (await this.ctx.storage.get(`evt:${key}`)) return { balance: await this.balance(grant) }; // already applied
    }
    const newBalance = (await this.balance(grant)) + clampBytes(packBytes);
    const writes: Record<string, unknown> = { balance: newBalance, tier: "paid" satisfies Tier };
    for (const key of dedupeKeys) writes[`evt:${key}`] = true;
    await this.ctx.storage.put(writes);
    return { balance: newBalance };
  }

  /** Read-only snapshot for the upload-init fail-fast pre-check (and support/debug). Mutates nothing;
   *  live sums exclude expired entries, so the counts are accurate without pruning. */
  async summary(grant: number): Promise<AccountSummary> {
    await this.migrate();
    const now = Date.now();
    const res = await this.holds();
    return {
      tier: await this.tier(),
      total: await this.committed(),
      pending: await this.sumPending(now),
      balance: await this.balance(grant),
      reserved: this.liveReserved(res, now),
    };
  }

  /** Alarm: prune reservations from crashed attempts, and prune dead per-file markers (pf:/pd:/cm:) as
   *  storage hygiene while we're awake, then reschedule for the next reservation expiry. Reads already
   *  filter expired entries, so this pruning is not correctness-critical, only keeps storage tidy. */
  async alarm(): Promise<void> {
    await this.migrate();
    const now = Date.now();
    const res = await this.holds();
    this.prune(res, now);
    await this.ctx.storage.put({ res });
    await this.pruneExpiredMarkers(now);
    await this.rescheduleAlarm(res);
  }

  /** Delete expired per-file marker keys across all three prefixes (paginated + batch-deleted). Hygiene
   *  only: reads filter on expiresAt, so a not-yet-pruned dead key never affects a sum or an existence check. */
  private async pruneExpiredMarkers(now: number): Promise<void> {
    for (const prefix of [PF, PD, CM]) {
      const expired: string[] = [];
      let startAfter: string | undefined;
      for (;;) {
        const page: Map<string, PendingFile | number> = await this.ctx.storage.list<PendingFile | number>({ prefix, startAfter, limit: LIST_PAGE });
        if (page.size === 0) break;
        let last = "";
        for (const [k, v] of page) {
          const exp = typeof v === "number" ? v : v?.expiresAt;
          if (!exp || exp <= now) expired.push(k);
          last = k;
        }
        if (page.size < LIST_PAGE) break;
        startAfter = last;
      }
      for (let i = 0; i < expired.length; i += PUT_BATCH) await this.ctx.storage.delete(expired.slice(i, i + PUT_BATCH));
    }
  }
}
