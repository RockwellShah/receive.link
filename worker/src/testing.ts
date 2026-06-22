// In-memory fakes for the Cloudflare bindings, so handlers can be exercised
// end-to-end under `bun test` with no account. Test-only.
import { base64urlDecode } from "../../shared/codec";
import type { AccountSummary, ChargeResult, Tier } from "./receiver";
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
  /** Test hook: simulate another attempt winning the exactly-once race for `name`, so the in-flight
   *  owner's finish() returns "already" (its delivery becomes a duplicate). */
  forceDone(name: string): void {
    this.state.set(name, { phase: "done" });
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
      async heldBy(token: string): Promise<boolean> {
        const s = state.get(name);
        return s?.phase === "running" && s.owner === token;
      },
      async finish(token: string): Promise<"won" | "already" | "lost"> {
        const s = state.get(name);
        if (s?.phase === "done") return "already";
        if (s?.phase === "running" && s.owner === token) {
          state.set(name, { phase: "done" });
          return "won";
        }
        return "lost";
      },
      async release(token: string): Promise<void> {
        const s = state.get(name);
        if (s?.phase === "running" && s.owner === token) state.delete(name);
      },
    };
  }
}

// In-memory stand-in for the ReceiverAccount DO namespace. Single-threaded bun tests, so the atomic
// reserve()/commit()/release()/charge() hold trivially. Mirrors worker/src/receiver.ts's accounting —
// minus the time-based expiry of reservations and paid-file flags (the DO's crash-cleanup alarm, which is
// exercised against the live DO), so tests never advance 10 days and paid flags need no expiry here.
export class MemoryReceiver {
  private totals = new Map<string, number>();
  private pendingFiles = new Map<string, Map<string, number>>(); // rid -> finalId -> bytes (un-downloaded)
  private balances = new Map<string, number>(); // present once seeded/changed; absent = lazy-default to grant
  private tiers = new Map<string, Tier>();
  private paid = new Map<string, Set<string>>(); // rid -> finalIds already charged
  private holds = new Map<string, Map<string, number>>(); // rid -> token -> reserved bytes
  private events = new Map<string, Set<string>>(); // rid -> stripe event ids already credited
  idFromName(name: string): DurableObjectId {
    return { toString: () => name } as unknown as DurableObjectId;
  }
  get(id: DurableObjectId) {
    const name = id.toString();
    const { totals, pendingFiles, balances, tiers, paid, holds, events } = this;
    const clamp = (n: number) => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);
    const held = () => holds.get(name) ?? holds.set(name, new Map<string, number>()).get(name)!;
    const pend = () => pendingFiles.get(name) ?? pendingFiles.set(name, new Map<string, number>()).get(name)!;
    const paidSet = () => paid.get(name) ?? paid.set(name, new Set<string>()).get(name)!;
    const tierOf = (): Tier => tiers.get(name) ?? "free";
    const bal = (grant: number) => balances.get(name) ?? clamp(grant);
    const sum = (m: Map<string, number>) => {
      let s = 0;
      for (const b of m.values()) s += b;
      return s;
    };
    return {
      async reserve(bytes: number, freeCap: number, paidCap: number): Promise<{ ok: true; token: string } | { ok: false }> {
        const add = clamp(bytes);
        const isPaid = tierOf() === "paid";
        const cap = isPaid ? paidCap : freeCap;
        const basis = isPaid ? sum(pend()) : (totals.get(name) ?? 0);
        if (cap > 0 && basis + sum(held()) + add > cap) return { ok: false };
        const token = crypto.randomUUID();
        held().set(token, add);
        return { ok: true, token };
      },
      async commit(token: string, finalId: string, accruePending: boolean): Promise<void> {
        const b = held().get(token);
        if (b === undefined) return;
        held().delete(token);
        totals.set(name, (totals.get(name) ?? 0) + b);
        if (accruePending) pend().set(finalId, b); // delivered, un-downloaded (only tracked when the cap is on)
      },
      async release(token: string): Promise<void> {
        held().delete(token);
      },
      async charge(finalId: string, size: number, grant: number): Promise<ChargeResult> {
        const need = clamp(size);
        const balance = bal(grant);
        if (paidSet().has(finalId)) return { ok: true, alreadyPaid: true, balance };
        if (balance < need) return { ok: false, balance, need };
        paidSet().add(finalId);
        const newBalance = balance - need;
        balances.set(name, newBalance);
        pend().delete(finalId); // downloaded -> no longer pending
        return { ok: true, alreadyPaid: false, balance: newBalance };
      },
      async credit(packBytes: number, grant: number, eventId?: string): Promise<{ balance: number }> {
        if (eventId) {
          const ev = events.get(name) ?? events.set(name, new Set<string>()).get(name)!;
          if (ev.has(eventId)) return { balance: bal(grant) };
          ev.add(eventId);
        }
        const newBalance = bal(grant) + clamp(packBytes);
        balances.set(name, newBalance);
        tiers.set(name, "paid");
        return { balance: newBalance };
      },
      async summary(grant: number): Promise<AccountSummary> {
        return {
          tier: tierOf(),
          total: totals.get(name) ?? 0,
          pending: sum(pend()),
          balance: bal(grant),
          reserved: sum(held()),
        };
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
  const receiver = new MemoryReceiver();

  const env: Env = {
    EMAIL: email,
    DROP_BUCKET: r2 as unknown as R2Bucket,
    DROP_KV: kv as unknown as KVNamespace,
    COMPLETION: completion as unknown as Env["COMPLETION"],
    RECEIVER: receiver as unknown as Env["RECEIVER"],
    SERVER_SIGN_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", sign.privateKey)),
    SERVER_SIGN_PUBLIC_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", sign.publicKey)),
    SERVER_KEM_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", kem.privateKey)),
    ALLOWED_ORIGIN: "https://drop.test",
    MAIL_FROM: "files@send.test",
    R2_ACCOUNT_ID: "testacct",
    R2_BUCKET: "filekey-drop-test",
    R2_ACCESS_KEY_ID: "TESTKEYID",
    R2_SECRET_ACCESS_KEY: "testsecret",
    RECEIVER_ID_SECRET: "test-receiver-id-secret",
    ...overrides,
  };

  return { env, kv, r2, email, kemPublicRaw: rawFromEcJwk(await crypto.subtle.exportKey("jwk", kem.publicKey)) };
}
