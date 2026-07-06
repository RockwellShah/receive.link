// Structural tests for R2 presigning. Asserts the SigV4 query shape offline (no
// live R2); the browser-direct PUT/GET + bucket CORS still needs an empirical
// check on real R2 before launch.
import { expect, test } from "bun:test";
import { presignGet, presignPut, presignUploadPart } from "./r2";
import type { Env } from "./types";

const env = {
  R2_ACCOUNT_ID: "acct123",
  R2_BUCKET: "bucket",
  R2_ACCESS_KEY_ID: "AKIAEXAMPLE",
  R2_SECRET_ACCESS_KEY: "secretexample",
} as unknown as Env;

test("presignPut signs an S3 PUT url for the object", async () => {
  const url = await presignPut(env, "deadbeefdeadbeefdeadbeefdeadbeef");
  expect(url).toContain("acct123.r2.cloudflarestorage.com");
  expect(url).toContain("/bucket/deadbeefdeadbeefdeadbeefdeadbeef");
  expect(url).toContain("X-Amz-Algorithm=AWS4-HMAC-SHA256");
  expect(url).toContain("X-Amz-Credential=");
  expect(url).toContain("X-Amz-Signature=");
  expect(url).toContain("X-Amz-Expires=3600");
});

test("presignGet signs an S3 GET url with a custom expiry", async () => {
  const url = await presignGet(env, "cafebabecafebabecafebabecafebabe", 60);
  expect(url).toContain("/bucket/cafebabecafebabecafebabecafebabe");
  expect(url).toContain("X-Amz-Expires=60");
  expect(url).toContain("X-Amz-Signature=");
});

test("presignPut without a contentLength signs only host (legacy, unbounded)", async () => {
  const url = await presignPut(env, "deadbeefdeadbeefdeadbeefdeadbeef");
  // No content-length bound: SignedHeaders is just host, so R2 doesn't cap the body.
  expect(decodeURIComponent(new URL(url).searchParams.get("X-Amz-SignedHeaders")!)).toBe("host");
});

test("presignPut with a contentLength binds it into SignedHeaders (R2 caps the body size)", async () => {
  const url = await presignPut(env, "deadbeefdeadbeefdeadbeefdeadbeef", 3600, 12345);
  // content-length is in the signed set, so an upload whose body size != 12345 fails the R2 signature.
  const signed = decodeURIComponent(new URL(url).searchParams.get("X-Amz-SignedHeaders")!);
  expect(signed.split(";").sort()).toEqual(["content-length", "host"]);
  expect(url).toContain("X-Amz-Signature=");
});

test("presignUploadPart binds the part's contentLength into SignedHeaders", async () => {
  const url = await presignUploadPart(env, "deadbeefdeadbeefdeadbeefdeadbeef", "up-id-1", 2, 60, 5242880);
  const u = new URL(url);
  expect(u.searchParams.get("partNumber")).toBe("2");
  expect(decodeURIComponent(u.searchParams.get("X-Amz-SignedHeaders")!).split(";").sort()).toEqual(["content-length", "host"]);
});
