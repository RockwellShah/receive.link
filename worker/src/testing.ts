// In-memory fakes for the Cloudflare bindings, so handlers can be exercised
// end-to-end under `bun test` with no account. Test-only.
import { base64urlDecode } from "./codec";
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

  const env: Env = {
    EMAIL: email,
    DROP_BUCKET: r2 as unknown as R2Bucket,
    DROP_KV: kv as unknown as KVNamespace,
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
