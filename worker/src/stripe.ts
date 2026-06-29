// Stripe top-up: prepaid credit packs bought through Stripe-HOSTED Checkout. We call the Stripe REST API
// directly (one authed fetch to create a session) and verify webhooks with WebCrypto HMAC, so the Worker
// bundle stays dependency-free and the card form never touches our origin (no PCI scope). We store no card
// and never send the receive.link email to Stripe: a payment ties to the account by `rid` alone
// (client_reference_id + metadata), credited by the webhook into the ReceiverAccount DO.
import { hmacSha256hex } from "../../shared/util";
import type { Env } from "./types";

const GB = 1_000_000_000; // decimal GB — the pricing/marketing unit (so $10 = 1 TB is clean, not 0.93 TiB)

// PRICE IS ONE KNOB. The prepaid DOLLAR tiers are fixed (set by Stripe's 2.9% + $0.30 floor — $10 is the
// sensible minimum), but the GB each grants is DERIVED from PRICE_CENTS_PER_GB, so walking the price is a
// single env change, not a table edit. Default 1¢/GB → $10 = 1 TB. The charge engine is byte-based, so
// price only affects how many bytes a top-up grants; the per-download debit never changes.
const PACK_CENTS = { p10: 1_000, p25: 2_500, p50: 5_000, p100: 10_000 } as const;
export type PackId = keyof typeof PACK_CENTS;
export function isPackId(s: string): s is PackId {
  return Object.prototype.hasOwnProperty.call(PACK_CENTS, s);
}

const DEFAULT_PRICE_CENTS_PER_GB = 1; // 1¢/GB
const MAX_PRICE_CENTS_PER_GB = 1000; // $10/GB — a sanity clamp bounding the webhook's byte derivation

// Floor to >= 1 so the divisor in bytesForCents can never be 0 (a fractional like 0.5 floors to 0, hence
// the >= 1 guard, not > 0). Out-of-range / non-numeric -> the default.
const clampPrice = (n: number): number => (Number.isFinite(n) && n >= 1 ? Math.min(Math.floor(n), MAX_PRICE_CENTS_PER_GB) : DEFAULT_PRICE_CENTS_PER_GB);

/** Price in cents per GB, from PRICE_CENTS_PER_GB (clamped to a sane range; default 1¢/GB). Change it in
 *  the Cloudflare dashboard to walk the price with no code change. */
export function priceCentsPerGb(env: Env): number {
  return clampPrice(env.PRICE_CENTS_PER_GB ? parseInt(env.PRICE_CENTS_PER_GB, 10) : NaN);
}

/** Bytes a dollar tier grants at a given price: tier_cents / price_cents_per_gb GB. */
function bytesForCents(amountCents: number, priceCentsPerGb: number): number {
  return Math.floor((amountCents / priceCentsPerGb) * GB);
}

/** Human pack/credit size for labels. ALWAYS GB (never rolls up to TB), with thousands separators, so a
 *  1 TB pack reads "1,000 GB" (big numbers feel more generous than "1 TB"). Exported so the credit-UX
 *  surfaces (delivery email status line, the /fetch/preview balance headers consumer) and the pack picker
 *  all render credit in the same unit. Decimal GB (1 GB = 1e9). No em dash per house style. */
export function humanSize(bytes: number): string {
  const gb = bytes / GB;
  const s = Number.isInteger(gb) ? String(gb) : gb.toFixed(1);
  const [intPart, frac] = s.split(".");
  const withCommas = intPart!.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return frac ? `${withCommas}.${frac} GB` : `${withCommas} GB`;
}

/** The prepaid packs at the CURRENT price, for the client's top-up picker. Derived, so changing the price
 *  knob updates these (and the labels) with no client redeploy. */
export function packList(env: Env): { id: PackId; amountCents: number; bytes: number; label: string }[] {
  const price = priceCentsPerGb(env);
  return (Object.keys(PACK_CENTS) as PackId[]).map((id) => {
    const amountCents = PACK_CENTS[id];
    const bytes = bytesForCents(amountCents, price);
    return { id, amountCents, bytes, label: `$${amountCents / 100} · ${humanSize(bytes)}` };
  });
}

/** True only when BOTH the API secret and the webhook secret are set — checkout 503s until then. We need
 *  the webhook secret too, because without it a paid session's credit could never land (the webhook would
 *  503 forever), so a user must never be able to pay before we can credit them. Ships inert until both. */
export function stripeConfigured(env: Env): boolean {
  return !!env.STRIPE_SECRET_KEY && !!env.STRIPE_WEBHOOK_SECRET;
}

/** Form-encode the Checkout session params (testable). One-time payment for prepaid credit. The rid rides
 *  in BOTH client_reference_id and metadata so the webhook can credit the right account, and the PRICE used
 *  is LOCKED into metadata so the webhook credits at the price the buyer was quoted even if the global price
 *  knob moves mid-payment (the credited bytes are re-derived from pack + locked price, never a raw client
 *  amount). We pass no customer email — Checkout collects whatever billing email the buyer types, in
 *  Stripe's scope, not ours. */
export function checkoutSessionParams(env: Env, opts: { rid: string; pack: PackId; successUrl: string; cancelUrl: string }): URLSearchParams {
  const price = priceCentsPerGb(env);
  const amountCents = PACK_CENTS[opts.pack];
  const p = new URLSearchParams();
  p.set("mode", "payment");
  p.set("success_url", opts.successUrl);
  p.set("cancel_url", opts.cancelUrl);
  p.set("client_reference_id", opts.rid);
  p.set("metadata[rid]", opts.rid);
  p.set("metadata[pack]", opts.pack);
  p.set("metadata[price]", String(price)); // lock the price for the webhook credit
  p.set("line_items[0][quantity]", "1");
  p.set("line_items[0][price_data][currency]", "usd");
  p.set("line_items[0][price_data][unit_amount]", String(amountCents));
  p.set("line_items[0][price_data][product_data][name]", `receive.link credit · ${humanSize(bytesForCents(amountCents, price))}`);
  return p;
}

/** Create a Checkout session via the Stripe REST API; returns the hosted Checkout URL to redirect to. */
export async function createCheckoutSession(env: Env, opts: { rid: string; pack: PackId; successUrl: string; cancelUrl: string }): Promise<string> {
  const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "content-type": "application/x-www-form-urlencoded" },
    body: checkoutSessionParams(env, opts).toString(),
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
 *  event type / an unpaid or malformed session. The granted bytes are RE-DERIVED from the pack id (a known
 *  fixed dollar tier) and the price LOCKED into metadata at checkout — never a raw client/event byte amount,
 *  and bounded by the price clamp — so even an unexpected session in our Stripe account can only ever credit
 *  a known tier at a sane price. The event id makes the credit idempotent on a webhook retry. */
export function parseCreditFromEvent(event: unknown): { rid: string; bytes: number; eventId: string } | null {
  const e = event as {
    id?: unknown;
    type?: unknown;
    data?: { object?: { payment_status?: unknown; amount_total?: unknown; currency?: unknown; metadata?: { rid?: unknown; pack?: unknown; price?: unknown } } };
  };
  if (typeof e?.id !== "string" || e.type !== "checkout.session.completed") return null;
  const o = e.data?.object;
  if (!o || o.payment_status !== "paid") return null; // only credit a fully-paid session
  const rid = typeof o.metadata?.rid === "string" ? o.metadata.rid : "";
  const pack = typeof o.metadata?.pack === "string" ? o.metadata.pack : "";
  if (!rid || !isPackId(pack)) return null;
  // REQUIRE a valid locked price (do NOT default — a price-less/garbled session is anomalous, and
  // defaulting to the floor price would credit the MOST bytes; reject it instead).
  const price = typeof o.metadata?.price === "string" ? parseInt(o.metadata.price, 10) : NaN;
  if (!Number.isInteger(price) || price < 1 || price > MAX_PRICE_CENTS_PER_GB) return null;
  // Credit only if they actually paid (at least) this tier's price in USD — guards a forged same-account
  // session that underpays but stamps a bigger pack. (We don't enable Stripe tax, so amount_total == tier.)
  if (o.currency !== "usd" || typeof o.amount_total !== "number" || o.amount_total < PACK_CENTS[pack]) return null;
  return { rid, bytes: bytesForCents(PACK_CENTS[pack], price), eventId: e.id };
}
