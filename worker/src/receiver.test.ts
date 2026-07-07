// Direct unit tests of the REAL ReceiverAccount Durable Object (not the MemoryReceiver double), against a
// Map-backed fake storage (see bunfig.toml -> do-stub.preload.ts for the cloudflare:workers stub). Covers
// the per-file-key model + the one-time migration of legacy single-map accounts — the money-critical
// paths that the handler tests (which use the double) don't exercise.
import { expect, test } from "bun:test";
import { FakeDOStorage } from "./fake-do-storage";
import { ReceiverAccount } from "./receiver";

function acct(): { a: ReceiverAccount; s: FakeDOStorage } {
  const s = new FakeDOStorage();
  const a = new ReceiverAccount({ storage: s } as unknown as DurableObjectState, {} as unknown as never);
  return { a, s };
}
const now = () => Date.now();
const FUTURE = 3_000_000_000_000; // far past any real expiresAt used here
const keys = (s: FakeDOStorage, prefix: string) => [...s.map.keys()].filter((k) => k.startsWith(prefix));

test("commitDelivered: accrues total + cm:, adds pf: when billing on, idempotent per finalId", async () => {
  const { a, s } = acct();
  await a.commitDelivered("f1", 200, true);
  expect(s.map.get("total")).toBe(200);
  expect(s.map.has("cm:f1")).toBe(true);
  expect((s.map.get("pf:f1") as { bytes: number }).bytes).toBe(200);
  await a.commitDelivered("f1", 200, true); // duplicate/retry -> no double count
  expect(s.map.get("total")).toBe(200);
});

test("commitDelivered: billing off accrues total only (no pf:)", async () => {
  const { a, s } = acct();
  await a.commitDelivered("f1", 500, false);
  expect(s.map.get("total")).toBe(500);
  expect(keys(s, "pf:")).toEqual([]);
});

test("charge: debits balance once, marks paid, clears pending; re-download is free", async () => {
  const { a } = acct();
  await a.commitDelivered("f1", 200, true); // pending 200
  const r1 = await a.charge("f1", 200, 1000);
  expect(r1).toEqual({ ok: true, alreadyPaid: false, balance: 800 });
  expect((await a.summary(1000)).pending).toBe(0); // cleared
  const r2 = await a.charge("f1", 200, 1000); // re-download
  expect(r2).toEqual({ ok: true, alreadyPaid: true, balance: 800 }); // not charged again
});

test("charge: insufficient balance returns 402 and changes nothing", async () => {
  const { a } = acct();
  await a.commitDelivered("big", 500, true);
  const r = await a.charge("big", 500, 300); // grant 300 < 500
  expect(r.ok).toBe(false);
  expect((await a.summary(300)).balance).toBe(300); // untouched
});

test("commitDelivered: a delayed commit does not resurrect a paid file's pending hold", async () => {
  const { a } = acct();
  const r = await a.charge("raced", 200, 1000); // downloaded first (no prior pending)
  expect(r.ok).toBe(true);
  await a.commitDelivered("raced", 200, true); // late commit
  expect((await a.summary(1000)).pending).toBe(0); // not resurrected
  expect((await a.summary(1000)).total).toBe(200); // meter still counts it
});

test("reserve: capacity = balance (pending + holds + add), enforce off skips the check", async () => {
  const { a } = acct();
  await a.commitDelivered("f1", 200, true); // 200 at rest
  const h = await a.reserve(200, 300, true); // 200 + 200 = 400 > 300 -> reject
  expect(h.ok).toBe(false);
  const ok = await a.reserve(100, 300, true); // 200 + 100 = 300 <= 300 -> ok
  expect(ok.ok).toBe(true);
  const unenf = await a.reserve(9_999_999, 300, false); // billing off: no check
  expect(unenf.ok).toBe(true);
});

test("releasePending: frees a discarded file's capacity immediately", async () => {
  const { a } = acct();
  await a.commitDelivered("junk", 200, true);
  expect((await a.summary(300)).pending).toBe(200);
  await a.releasePending("junk");
  expect((await a.summary(300)).pending).toBe(0);
});

test("credit: adds balance, flips to paid, idempotent on the Stripe event id", async () => {
  const { a } = acct();
  const r1 = await a.credit(1000, 0, ["s:cs_1", "evt_1"]);
  expect(r1.balance).toBe(1000);
  expect((await a.summary(0)).tier).toBe("paid");
  const r2 = await a.credit(1000, 0, ["s:cs_1", "evt_9"]); // different event, same session
  expect(r2.balance).toBe(1000); // not double-credited
});

test("expired pending is filtered from the capacity sum even before pruning", async () => {
  const { a, s } = acct();
  s.map.set("pf:old", { bytes: 500, expiresAt: now() - 1000 }); // already expired
  s.map.set("pf:live", { bytes: 100, expiresAt: FUTURE });
  s.map.set("mig2", true);
  expect((await a.summary(1000)).pending).toBe(100); // only the live one
});

// ---- Migration of a legacy single-map account (the prod-account-critical path) ----

test("migrate: converts old pendingf/paid/cmt maps to per-file keys, preserving all state", async () => {
  const { a, s } = acct();
  // Seed a pre-migration account: balance, a pending file, a paid file, a committed marker.
  s.map.set("balance", 5000);
  s.map.set("tier", "paid");
  s.map.set("total", 900);
  s.map.set("pendingf", { pA: { bytes: 300, expiresAt: FUTURE } });
  s.map.set("paid", { pB: FUTURE });
  s.map.set("cmt", { pA: FUTURE, pB: FUTURE });

  const sum = await a.summary(1000); // any method triggers migrate()
  expect(sum.balance).toBe(5000); // preserved
  expect(sum.tier).toBe("paid");
  expect(sum.total).toBe(900);
  expect(sum.pending).toBe(300); // old pending carried over

  // Old maps gone, per-file keys present, migration flag set.
  expect(s.map.has("pendingf")).toBe(false);
  expect(s.map.has("paid")).toBe(false);
  expect(s.map.has("cmt")).toBe(false);
  expect(s.map.get("mig2")).toBe(true);
  expect((s.map.get("pf:pA") as { bytes: number }).bytes).toBe(300);
  expect(s.map.get("pd:pB")).toBe(FUTURE);

  // Semantics preserved: the already-paid file re-downloads free; the already-committed file is idempotent.
  const reDl = await a.charge("pB", 100, 1000);
  expect(reDl.ok && reDl.alreadyPaid).toBe(true); // was in the old `paid` map -> still free, not re-charged
  await a.commitDelivered("pA", 300, true);
  expect((await a.summary(1000)).total).toBe(900); // cm:pA carried over -> not re-counted
});

test("migrate: a fresh account just sets mig2 (no old maps to convert)", async () => {
  const { a, s } = acct();
  await a.summary(1000);
  expect(s.map.get("mig2")).toBe(true);
  expect(keys(s, "pf:")).toEqual([]);
});

test("scale: 2,000 pending files sum correctly (per-file keys, paginated) with no value-size limit", async () => {
  const { a, s } = acct();
  s.map.set("mig2", true);
  for (let i = 0; i < 2000; i++) s.map.set(`pf:f${i}`, { bytes: 1000, expiresAt: FUTURE });
  // The old single-map model would have thrown at ~1,750 entries; per-file keys don't, and the paginated
  // sum is exact across >1 list page.
  expect((await a.summary(999_999_999)).pending).toBe(2_000_000);
});

test("scale: migrating a 300-entry legacy map batches puts under the 128-key limit", async () => {
  const { a, s } = acct();
  const bigPending: Record<string, { bytes: number; expiresAt: number }> = {};
  for (let i = 0; i < 300; i++) bigPending[`f${i}`] = { bytes: 10, expiresAt: FUTURE };
  s.map.set("pendingf", bigPending); // 300 > 128: migrate must batch or the fake put() throws
  await a.summary(1000); // triggers migrate; would throw if it tried one 300-key put
  expect(keys(s, "pf:").length).toBe(300);
  expect((await a.summary(1000)).pending).toBe(3000);
});

test("alarm: prunes expired per-file markers, keeps live ones", async () => {
  const { a, s } = acct();
  s.map.set("mig2", true);
  s.map.set("pf:dead", { bytes: 100, expiresAt: now() - 1000 });
  s.map.set("pf:live", { bytes: 100, expiresAt: FUTURE });
  s.map.set("pd:dead", now() - 1000);
  s.map.set("cm:live", FUTURE);
  await a.alarm();
  expect(s.map.has("pf:dead")).toBe(false);
  expect(s.map.has("pd:dead")).toBe(false);
  expect(s.map.has("pf:live")).toBe(true);
  expect(s.map.has("cm:live")).toBe(true);
});
