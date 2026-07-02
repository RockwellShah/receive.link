import { test, expect } from "bun:test";
import { corsOrigin, isForbiddenCrossOrigin, linkOrigin, readJson } from "./http";
import type { Env } from "./types";

const envWith = (allowed: string) => ({ ALLOWED_ORIGIN: allowed }) as Env;
const reqWith = (origin?: string) =>
  new Request("https://worker.example/x", origin ? { headers: { origin } } : undefined);

test("linkOrigin is the first allow-listed origin", () => {
  expect(linkOrigin(envWith("https://a.test,https://b.test"))).toBe("https://a.test");
  expect(linkOrigin(envWith("https://a.test"))).toBe("https://a.test");
  expect(linkOrigin(envWith(""))).toBe("");
});

test("corsOrigin echoes an allow-listed request origin, else '' (fail-closed)", () => {
  const env = envWith("https://a.test, https://b.test"); // note the space — entries are trimmed
  expect(corsOrigin(env, reqWith("https://a.test"))).toBe("https://a.test");
  expect(corsOrigin(env, reqWith("https://b.test"))).toBe("https://b.test"); // a non-first entry is allowed too
  expect(corsOrigin(env, reqWith("https://evil.test"))).toBe(""); // not allow-listed
  expect(corsOrigin(env, reqWith(undefined))).toBe(""); // no Origin header
  expect(corsOrigin(envWith(""), reqWith("https://a.test"))).toBe(""); // empty allowlist never matches
});

test("isForbiddenCrossOrigin blocks only a present-but-disallowed Origin on POST", () => {
  const env = envWith("https://a.test,https://b.test");
  const post = (origin?: string) =>
    new Request("https://worker.example/register", origin ? { method: "POST", headers: { origin } } : { method: "POST" });
  expect(isForbiddenCrossOrigin(env, post("https://evil.test"))).toBe(true); // cross-site POST -> blocked
  expect(isForbiddenCrossOrigin(env, post("https://b.test"))).toBe(false); // allow-listed (non-first) origin
  expect(isForbiddenCrossOrigin(env, post(undefined))).toBe(false); // no Origin: native app / server-side
  const getEvil = new Request("https://worker.example/fetch/x", { method: "GET", headers: { origin: "https://evil.test" } });
  expect(isForbiddenCrossOrigin(env, getEvil)).toBe(false); // GET is safe; the response is already hidden
});

test("readJson: the default 64 KB cap rejects a large multipart parts body; an explicit cap admits it", async () => {
  // A realistic big-multipart completion body: ~2,000 parts x ~55 B (about 110 KB, over the 64 KB
  // default). Exactly the shape that capped real uploads at ~1k parts (~17 GB at prod's 16 MiB part
  // floor) until upload-complete got its own 1 MiB cap — found by the 5.5 GB live experiment.
  const parts = Array.from({ length: 2000 }, (_, i) => ({ partNumber: i + 1, etag: `"etag-${i + 1}-0123456789abcdef"` }));
  const body = JSON.stringify({ payload: "x".repeat(400), objectId: "ab".repeat(16), parts });
  expect(body.length).toBeGreaterThan(64 * 1024);
  const req = () => new Request("https://worker.example/upload-complete", { method: "POST", body });
  expect(await readJson(req())).toBeNull(); // default cap: parsed as null -> was surfacing as a bogus "missing fields" 400
  const parsed = await readJson<{ parts: unknown[] }>(req(), 1024 * 1024); // the upload-complete cap
  expect(Array.isArray(parsed?.parts)).toBe(true);
  expect(parsed!.parts.length).toBe(2000);
});
