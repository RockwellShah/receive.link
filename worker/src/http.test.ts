import { test, expect } from "bun:test";
import { corsOrigin, isForbiddenCrossOrigin, linkOrigin } from "./http";
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
