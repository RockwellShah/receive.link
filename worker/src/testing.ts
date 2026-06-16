// In-memory fakes for the Cloudflare bindings, so handlers can be exercised
// end-to-end under `bun test` with no account. Test-only.
import { base64urlDecode } from "../../shared/codec";
import type { Env, SendEmailBinding } from "./types";

export class MemoryKV {
  store = new Map<string, string>();
  async get(key: string): Promise<string | null> {
    return this.store.has(key) ? this.store.get(key)! : null;
  }
  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

export class MemoryR2 {
  store = new Map<string, Uint8Array>();
  /** Simulate the browser's direct-to-R2 PUT. */
  putRaw(key: string, value: Uint8Array): void {
    this.store.set(key, value);
  }
  async head(key: string): Promise<{ size: number } | null> {
    const v = this.store.get(key);
    return v ? { size: v.length } : null;
  }
  async get(
    key: string,
    opts?: { range?: { offset: number; length: number } },
  ): Promise<{ arrayBuffer(): Promise<ArrayBuffer> } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    const slice = opts?.range
      ? v.subarray(opts.range.offset, opts.range.offset + opts.range.length)
      : v;
    const copy = slice.slice();
    return { arrayBuffer: async () => copy.buffer as ArrayBuffer };
  }
  /** Stand-in for S3 CopyObject (the binding seam used by r2.copyObject in tests). */
  async copy(src: string, dst: string): Promise<boolean> {
    const v = this.store.get(src);
    if (!v) return false;
    this.store.set(dst, v.slice());
    return true;
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  // ---- multipart: mirrors the R2 binding surface r2.ts uses (create/resume +
  // the handle's uploadPart/complete/abort), plus putPartRaw to stand in for the
  // browser's presigned UploadPart PUT (the dev server calls it). ----
  multipart = new Map<string, { key: string; parts: Map<number, Uint8Array> }>();
  mpuSeq = 0;
  private mpuHandle(key: string, uploadId: string) {
    const r2 = this;
    return {
      key,
      uploadId,
      async uploadPart(partNumber: number, value: Uint8Array): Promise<{ partNumber: number; etag: string }> {
        return { partNumber, etag: r2.putPartRaw(uploadId, partNumber, value) };
      },
      async complete(parts: { partNumber: number; etag: string }[]): Promise<{ size: number }> {
        const mpu = r2.multipart.get(uploadId);
        if (!mpu) throw new Error("no such multipart upload");
        const ordered = [...parts].sort((a, b) => a.partNumber - b.partNumber);
        const pieces: Uint8Array[] = [];
        for (const p of ordered) {
          const b = mpu.parts.get(p.partNumber);
          if (!b) throw new Error(`missing part ${p.partNumber}`);
          pieces.push(b);
        }
        const size = pieces.reduce((n, c) => n + c.length, 0);
        const out = new Uint8Array(size);
        let o = 0;
        for (const c of pieces) {
          out.set(c, o);
          o += c.length;
        }
        r2.store.set(mpu.key, out);
        r2.multipart.delete(uploadId);
        return { size };
      },
      async abort(): Promise<void> {
        r2.multipart.delete(uploadId);
      },
    };
  }
  async createMultipartUpload(key: string) {
    const uploadId = `mpu-${++this.mpuSeq}`;
    this.multipart.set(uploadId, { key, parts: new Map() });
    return this.mpuHandle(key, uploadId);
  }
  resumeMultipartUpload(key: string, uploadId: string) {
    return this.mpuHandle(key, uploadId);
  }
  /** Stand in for the browser's presigned UploadPart PUT; returns a quoted ETag like S3. */
  putPartRaw(uploadId: string, partNumber: number, value: Uint8Array): string {
    const mpu = this.multipart.get(uploadId);
    if (!mpu) throw new Error("no such multipart upload");
    mpu.parts.set(partNumber, value.slice());
    return `"etag-${partNumber}-${value.length}"`;
  }
}

export interface SentMail {
  to: string;
  from: string;
  subject: string;
  text?: string;
  html?: string;
}

export class CapturingEmail implements SendEmailBinding {
  sent: SentMail[] = [];
  async send(message: SentMail): Promise<{ messageId: string }> {
    this.sent.push(message);
    return { messageId: `test-${this.sent.length}` };
  }
}

// In-memory stand-in for the CompletionGuard Durable Object namespace. Bun tests are single-threaded,
// so the atomic claim()/finish()/release() semantics hold without modeling the running-TTL or alarm.
export class MemoryCompletion {
  private state = new Map<string, { phase: "running" | "done"; owner?: string }>();
  idFromName(name: string): DurableObjectId {
    return { toString: () => name } as unknown as DurableObjectId;
  }
  get(id: DurableObjectId) {
    const name = id.toString();
    const state = this.state;
    return {
      async peek(): Promise<"fresh" | "running" | "done"> {
        const s = state.get(name);
        return s?.phase === "done" ? "done" : s?.phase === "running" ? "running" : "fresh";
      },
      async claim(): Promise<{ ok: true; token: string } | { ok: false; reason: "running" | "done" }> {
        const s = state.get(name);
        if (s?.phase === "done") return { ok: false, reason: "done" };
        if (s?.phase === "running") return { ok: false, reason: "running" };
        const token = crypto.randomUUID();
        state.set(name, { phase: "running", owner: token });
        return { ok: true, token };
      },
      async finish(token: string): Promise<boolean> {
        const s = state.get(name);
        if (s?.phase === "done") return true;
        if (s?.phase === "running" && s.owner === token) {
          state.set(name, { phase: "done" });
          return true;
        }
        return false;
      },
      async release(token: string): Promise<void> {
        const s = state.get(name);
        if (s?.phase === "running" && s.owner === token) state.delete(name);
      },
    };
  }
}

function rawFromEcJwk(jwk: JsonWebKey): Uint8Array {
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(base64urlDecode(jwk.x!), 1);
  raw.set(base64urlDecode(jwk.y!), 33);
  return raw;
}

export interface TestHarness {
  env: Env;
  kv: MemoryKV;
  r2: MemoryR2;
  email: CapturingEmail;
  kemPublicRaw: Uint8Array; // seal test emails to this
}

/** Build an Env backed by in-memory fakes + freshly generated server keys. */
export async function makeTestEnv(overrides: Partial<Env> = {}): Promise<TestHarness> {
  const sign = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const kem = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);

  const kv = new MemoryKV();
  const r2 = new MemoryR2();
  const email = new CapturingEmail();
  const completion = new MemoryCompletion();

  const env: Env = {
    EMAIL: email,
    DROP_BUCKET: r2 as unknown as R2Bucket,
    DROP_KV: kv as unknown as KVNamespace,
    COMPLETION: completion as unknown as Env["COMPLETION"],
    SERVER_SIGN_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", sign.privateKey)),
    SERVER_SIGN_PUBLIC_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", sign.publicKey)),
    SERVER_KEM_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", kem.privateKey)),
    ALLOWED_ORIGIN: "https://drop.test",
    MAIL_FROM: "files@send.test",
    R2_ACCOUNT_ID: "testacct",
    R2_BUCKET: "filekey-drop-test",
    R2_ACCESS_KEY_ID: "TESTKEYID",
    R2_SECRET_ACCESS_KEY: "testsecret",
    ...overrides,
  };

  return { env, kv, r2, email, kemPublicRaw: rawFromEcJwk(await crypto.subtle.exportKey("jwk", kem.publicKey)) };
}
