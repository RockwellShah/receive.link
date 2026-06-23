// Stripe top-up: prepaid credit packs bought through Stripe-HOSTED Checkout. We call the Stripe REST API
// directly (one authed fetch to create a session) and verify webhooks with WebCrypto HMAC, so the Worker
// bundle stays dependency-free and the card form never touches our origin (no PCI scope). We store no card
// and never send the receive.link email to Stripe: a payment ties to the account by `rid` alone
// (client_reference_id + metadata), credited by the webhook into the ReceiverAccount DO.
import { hmacSha256hex } from "../../shared/util";
import type { Env } from "./types";

const GIB = 1024 * 1024 * 1024;

// Prepaid packs (SPEC-monetization §5): 10c/GB, clean round multiples; $1 = 10 GB. amountCents is what
// Stripe charges, bytes is the credit granted. The $10 entry pack clears Stripe's 2.9% + $0.30 floor
// comfortably (~$0.59 on $10). The bytes are authoritative server-side (set into session metadata), never
// trusted from the client.
export const PACKS = {
  p10: { amountCents: 1_000, bytes: 100 * GIB, label: "$10 — 100 GB" },
  p25: { amountCents: 2_500, bytes: 250 * GIB, label: "$25 — 250 GB" },
  p50: { amountCents: 5_000, bytes: 500 * GIB, label: "$50 — 500 GB" },
  p100: { amountCents: 10_000, bytes: 1024 * GIB, label: "$100 — 1 TB" },
} as const;
export type PackId = keyof typeof PACKS;
export function isPackId(s: string): s is PackId {
  return Object.prototype.hasOwnProperty.call(PACKS, s);
}

/** True only when BOTH the API secret and the webhook secret are set — checkout 503s until then. We need
 *  the webhook secret too, because without it a paid session's credit could never land (the webhook would
 *  503 forever), so a user must never be able to pay before we can credit them. Ships inert until both. */
export function stripeConfigured(env: Env): boolean {
  return !!env.STRIPE_SECRET_KEY && !!env.STRIPE_WEBHOOK_SECRET;
}

/** Form-encode the Checkout session params (pure; testable). One-time payment for prepaid credit. The rid
 *  is carried in BOTH client_reference_id and metadata so the webhook can credit the right account, and
 *  the granted bytes ride in metadata (server-set) so we never trust a client-supplied amount. We pass no
 *  customer email — Checkout collects whatever billing email the buyer types, in Stripe's scope, not ours. */
export function checkoutSessionParams(opts: { rid: string; pack: PackId; successUrl: string; cancelUrl: string }): URLSearchParams {
  const pack = PACKS[opts.pack];
  const p = new URLSearchParams();
  p.set("mode", "payment");
  p.set("success_url", opts.successUrl);
  p.set("cancel_url", opts.cancelUrl);
  p.set("client_reference_id", opts.rid);
  p.set("metadata[rid]", opts.rid);
  p.set("metadata[pack]", opts.pack);
  p.set("metadata[bytes]", String(pack.bytes));
  p.set("line_items[0][quantity]", "1");
  p.set("line_items[0][price_data][currency]", "usd");
  p.set("line_items[0][price_data][unit_amount]", String(pack.amountCents));
  p.set("line_items[0][price_data][product_data][name]", `receive.link credit — ${pack.label}`);
  return p;
}

/** Create a Checkout session via the Stripe REST API; returns the hosted Checkout URL to redirect to. */
export async function createCheckoutSession(env: Env, opts: { rid: string; pack: PackId; successUrl: string; cancelUrl: string }): Promise<string> {
  const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "content-type": "application/x-www-form-urlencoded" },
    body: checkoutSessionParams(opts).toString(),
  });
  if (!res.ok) throw new Error(`stripe checkout failed (${res.status})`);
  const body = (await res.json()) as { url?: string };
  if (!body.url) throw new Error("stripe checkout: no url in response");
  return body.url;
}

/** Constant-time hex compare (signatures are equal-length lowercase hex). */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Verify a Stripe webhook signature (the `Stripe-Signature` header scheme): HMAC-SHA256 over
 *  `${t}.${rawBody}` with the endpoint secret, compared constant-time to a v1 signature, within a
 *  timestamp tolerance (replay + clock-skew guard). Multiple v1s can appear during a secret rotation, so
 *  any match passes. Returns true iff valid. The RAW request body must be passed (re-serializing JSON
 *  would change bytes and break the MAC). */
export async function verifyStripeSignature(rawBody: string, sigHeader: string, secret: string, nowSec: number, toleranceSec = 300): Promise<boolean> {
  let t = "";
  const v1: string[] = [];
  for (const part of sigHeader.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (k === "t") t = val;
    else if (k === "v1") v1.push(val);
  }
  const ts = parseInt(t, 10);
  if (!t || v1.length === 0 || !Number.isFinite(ts) || Math.abs(nowSec - ts) > toleranceSec) return false;
  const expected = await hmacSha256hex(secret, `${t}.${rawBody}`);
  return v1.some((sig) => timingSafeEqualHex(sig, expected));
}

/** Pull the credit instruction out of a verified `checkout.session.completed` event, or null for any other
 *  event type / an unpaid or malformed session. The granted bytes are derived from the pack id in the
 *  metadata WE set (looked up in PACKS, the single source of truth) — never from a client- or event-supplied
 *  amount — so even an unexpected session in our Stripe account can only ever credit a known pack size. The
 *  event id makes the credit idempotent on a webhook retry. */
export function parseCreditFromEvent(event: unknown): { rid: string; bytes: number; eventId: string } | null {
  const e = event as {
    id?: unknown;
    type?: unknown;
    data?: { object?: { payment_status?: unknown; metadata?: { rid?: unknown; pack?: unknown } } };
  };
  if (typeof e?.id !== "string" || e.type !== "checkout.session.completed") return null;
  const o = e.data?.object;
  if (!o || o.payment_status !== "paid") return null; // only credit a fully-paid session
  const rid = typeof o.metadata?.rid === "string" ? o.metadata.rid : "";
  const pack = typeof o.metadata?.pack === "string" ? o.metadata.pack : "";
  if (!rid || !isPackId(pack)) return null;
  return { rid, bytes: PACKS[pack].bytes, eventId: e.id };
}
