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

// Keyed one-way digest (HMAC-SHA-256), hex output. For rate-limit keys derived from LOW-ENTROPY
// inputs (email addresses, IPs): a plain SHA-256 of those is brute-forceable back to the input, but
// without the server-held secret an HMAC is not. `secret` is required — a missing key must fail loud,
// never silently fall back to an unkeyed (guessable) digest.
export async function hmacHex(secret: string, message: string): Promise<string> {
  if (!secret) throw new Error("hmacHex: missing HASH_SECRET");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return hex(new Uint8Array(sig));
}

/** Keyed digest: HMAC-SHA-256(keyUtf8, msg) as hex. Used to derive a stable, non-reversible account id
 *  from a confirmed email — the secret stops anyone who sees the id from dictionary-recovering the address. */
export async function hmacSha256hex(keyUtf8: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(keyUtf8), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return hex(new Uint8Array(sig));
}

// Strict single addr-spec: a dot-atom local part @ dotted domain labels. This is a SECURITY gate, not
// just UX — canonEmail derives the account IDENTITY (rid) from this exact string, so a permissive match
// let a display-name / angle-addr form like "x<victim@gmail.com>" (which a lenient mail provider may
// still deliver to victim@gmail.com) mint a DISTINCT rid = a farmable fresh 1 GB grant. We therefore
// reject the RFC "specials" (<>()[]:;@\," and whitespace) and trailing/duplicate domain dots, so the
// address that seeds the identity is the same one the provider will deliver to. Real deliverability is
// still proven by the confirm email; this only bounds the shape.
const EMAIL_RE = /^[a-z0-9!#$%&'*+\/=?^_`{|}~.-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
export function isEmail(s: string): boolean {
  return s.length <= 254 && EMAIL_RE.test(s);
}

/** Lowercase hex of exactly `len` bytes, e.g. an object id. */
export function isHex(s: string, len: number): boolean {
  return s.length === len * 2 && /^[0-9a-f]+$/.test(s);
}
