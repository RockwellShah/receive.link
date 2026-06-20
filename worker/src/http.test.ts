import { test, expect } from "bun:test";
import { corsOrigin, linkOrigin } from "./http";
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
