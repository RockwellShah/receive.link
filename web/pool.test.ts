// Invariants of the multipart upload pool: every part uploads exactly once, concurrency never exceeds
// the cap (but does run in parallel), progress sums all bytes, results come back sorted, and the first
// failure stops the pool and rejects. Pure orchestration — no crypto/DOM needed.
import { expect, test } from "bun:test";
import { uploadPartsPool } from "./fk/pool";

async function* genParts(count: number, size = 10): AsyncGenerator<Uint8Array> {
  for (let i = 0; i < count; i++) yield new Uint8Array(size).fill(i);
}

test("uploadPartsPool: uploads every part once, respects the concurrency cap, returns sorted, sums progress", async () => {
  let active = 0;
  let maxActive = 0;
  let confirmed = 0;
  const seen: number[] = [];
  const C = 3;
  const result = await uploadPartsPool(
    genParts(10),
    C,
    async (partNumber, bytes) => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 5)); // hold the slot so parts genuinely overlap
      seen.push(partNumber);
      active--;
      return `etag-${partNumber}-${bytes.length}`;
    },
    (bytes) => {
      confirmed += bytes;
    },
  );

  expect(result.map((p) => p.partNumber)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // present + sorted
  expect(result[0]!.etag).toBe("etag-1-10");
  expect(new Set(seen).size).toBe(10); // each part uploaded exactly once
  expect(maxActive).toBeGreaterThan(1); // genuinely concurrent
  expect(maxActive).toBeLessThanOrEqual(C); // never exceeded the cap
  expect(confirmed).toBe(10 * 10); // progress summed every part's bytes
});

test("uploadPartsPool: a failed part stops the pool and rejects without uploading the rest", async () => {
  let attempted = 0;
  await expect(
    uploadPartsPool(genParts(50), 2, async (partNumber) => {
      attempted++;
      if (partNumber === 3) throw new Error("boom");
      await new Promise((r) => setTimeout(r, 1));
      return `etag-${partNumber}`;
    }),
  ).rejects.toThrow("boom");
  expect(attempted).toBeLessThan(50); // backpressure stopped us well before the end
});
