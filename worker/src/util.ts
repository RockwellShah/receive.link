// Small shared helpers (runtime-agnostic: Worker + bun).

export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function hex(u: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u.length; i++) s += u[i]!.toString(16).padStart(2, "0");
  return s;
}

export async function sha256hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return hex(new Uint8Array(digest));
}

// Deliberately permissive: we only guard against obviously-malformed input before
// handing an address to the mail provider. Real validity is proven by delivery.
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
export function isEmail(s: string): boolean {
  return s.length <= 254 && EMAIL_RE.test(s);
}

/** Lowercase hex of exactly `len` bytes, e.g. an object id. */
export function isHex(s: string, len: number): boolean {
  return s.length === len * 2 && /^[0-9a-f]+$/.test(s);
}
