// Stripe top-up: prepaid credit packs bought through Stripe-HOSTED Checkout. We call the Stripe REST API
// directly (one authed fetch to create a session) and verify webhooks with WebCrypto HMAC, so the Worker
// bundle stays dependency-free and the card form never touches our origin (no PCI scope). We store no card
// and never send the receive.link email to Stripe: a payment ties to the account by `rid` alone
// (client_reference_id + metadata), credited by the webhook into the ReceiverAccount DO.
import { hmacSha256hex } from "../../shared/util";
import { logEvent } from "./http";
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

// "Other amount": a custom top-up where Stripe collects the dollar amount on its OWN hosted Checkout page
// (custom_unit_amount), bounded to a sane range. There is no fixed tier, so the webhook credits from the
// Stripe-VERIFIED amount_total (signed in the event), never an unsigned client value.
export const CUSTOM_PACK = "custom";
const CUSTOM_MIN_CENTS = 1_000; // $10 floor (matches the smallest preset; keeps the 2.9% + $0.30 fee efficient)
const CUSTOM_MAX_CENTS = 1_000_000; // $10,000 ceiling (bounds a fat-finger + the webhook's byte derivation)
export type CheckoutPack = PackId | typeof CUSTOM_PACK;
/** A valid checkout selection: a fixed dollar tier OR the custom "Other amount". */
export function isCheckoutPack(s: string): s is CheckoutPack {
  return isPackId(s) || s === CUSTOM_PACK;
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
  const gb = Math.round((bytes / GB) * 10) / 10; // round to 0.1 GB so float noise can't render a spurious ".0"
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
export function checkoutSessionParams(env: Env, opts: { rid: string; pack: CheckoutPack; successUrl: string; cancelUrl: string; customPriceId?: string }): URLSearchParams {
  const price = priceCentsPerGb(env);
  const p = new URLSearchParams();
  p.set("mode", "payment");
  p.set("success_url", opts.successUrl);
  p.set("cancel_url", opts.cancelUrl);
  p.set("client_reference_id", opts.rid);
  p.set("metadata[rid]", opts.rid);
  p.set("metadata[pack]", opts.pack);
  p.set("metadata[price]", String(price)); // lock the price for the webhook credit
  p.set("line_items[0][quantity]", "1");
  if (opts.pack === CUSTOM_PACK) {
    // "Other amount" references a PRICE OBJECT created just before the session (customPriceParams below):
    // Checkout's inline price_data does NOT accept custom_unit_amount — Stripe 400s with parameter_unknown
    // (found live on mon). Only the Prices API carries the pay-what-you-want config, so the session simply
    // points at that price. The webhook still credits from the VERIFIED amount_total, bounded to min/max.
    p.set("line_items[0][price]", opts.customPriceId ?? "");
  } else {
    const amountCents = PACK_CENTS[opts.pack];
    p.set("line_items[0][price_data][currency]", "usd");
    p.set("line_items[0][price_data][unit_amount]", String(amountCents));
    p.set("line_items[0][price_data][product_data][name]", `receive.link credit · ${humanSize(bytesForCents(amountCents, price))}`);
  }
  return p;
}

/** Params for the one-off "Other amount" PRICE object (POST /v1/prices): the customer types the amount on
 *  Stripe's page, bounded $10..$10,000, preset $10. A fresh price per checkout keeps this stateless (no
 *  cross-env KV cache — mon and staging share a KV namespace but hold DIFFERENT Stripe keys, so a cached
 *  price id could leak across accounts); the custom path is rare, so the extra API call is negligible. */
export function customPriceParams(): URLSearchParams {
  const p = new URLSearchParams();
  p.set("currency", "usd");
  p.set("custom_unit_amount[enabled]", "true");
  p.set("custom_unit_amount[minimum]", String(CUSTOM_MIN_CENTS));
  p.set("custom_unit_amount[maximum]", String(CUSTOM_MAX_CENTS));
  p.set("custom_unit_amount[preset]", String(CUSTOM_MIN_CENTS));
  p.set("product_data[name]", "receive.link credit");
  return p;
}

/** One authed form-POST to the Stripe REST API. On failure, logs Stripe's own diagnostic (code/param/
 *  message only — our requests carry no card data and no PII) so a bad param never again surfaces as an
 *  opaque 502 with nothing to debug from (the "Other amount" incident). */
async function stripePost<T>(env: Env, path: string, params: URLSearchParams, what: string): Promise<T> {
  const res = await fetch(`https://api.stripe.com${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "content-type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!res.ok) {
    let detail = "";
    try {
      const err = (await res.json()) as { error?: { code?: string; param?: string; message?: string } };
      detail = [err.error?.code, err.error?.param, err.error?.message].filter(Boolean).join(" | ").slice(0, 300);
    } catch {
      /* non-JSON error body */
    }
    logEvent("stripe_checkout_error", { status: res.status, what, detail });
    throw new Error(`stripe ${what} failed (${res.status})`);
  }
  return (await res.json()) as T;
}

/** Create a Checkout session via the Stripe REST API; returns the hosted Checkout URL to redirect to.
 *  "Other amount" is a two-call flow: mint the pay-what-you-want PRICE first (Checkout's inline price_data
 *  rejects custom_unit_amount), then the session referencing it. Fixed tiers stay a single call. */
export async function createCheckoutSession(env: Env, opts: { rid: string; pack: CheckoutPack; successUrl: string; cancelUrl: string }): Promise<string> {
  let customPriceId: string | undefined;
  if (opts.pack === CUSTOM_PACK) {
    const price = await stripePost<{ id?: string }>(env, "/v1/prices", customPriceParams(), "custom price");
    if (!price.id) throw new Error("stripe custom price: no id in response");
    customPriceId = price.id;
  }
  const body = await stripePost<{ url?: string }>(env, "/v1/checkout/sessions", checkoutSessionParams(env, { ...opts, customPriceId }), "checkout");
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
 *  a known tier at a sane price. Idempotency keys on the CHECKOUT SESSION id (`data.object.id`), NOT the
 *  Event id: Stripe can emit more than one Event object for the same session (Stripe's documented duplicate
 *  class), so keying on the event id alone would credit one payment twice — the session id is stable. */
export function parseCreditFromEvent(event: unknown): { rid: string; bytes: number; dedupeKeys: string[] } | null {
  const e = event as {
    id?: unknown;
    type?: unknown;
    data?: { object?: { id?: unknown; payment_status?: unknown; amount_total?: unknown; currency?: unknown; metadata?: { rid?: unknown; pack?: unknown; price?: unknown } } };
  };
  if (typeof e?.id !== "string" || e.type !== "checkout.session.completed") return null;
  const o = e.data?.object;
  if (!o || o.payment_status !== "paid") return null; // only credit a fully-paid session
  const sessionId = typeof o.id === "string" ? o.id : "";
  if (!sessionId) return null; // a real Checkout Session always has an id; refuse an anomalous one
  const rid = typeof o.metadata?.rid === "string" ? o.metadata.rid : "";
  const pack = typeof o.metadata?.pack === "string" ? o.metadata.pack : "";
  if (!rid || !isCheckoutPack(pack)) return null;
  // REQUIRE a valid locked price (do NOT default — a price-less/garbled session is anomalous, and
  // defaulting to the floor price would credit the MOST bytes; reject it instead).
  const price = typeof o.metadata?.price === "string" ? parseInt(o.metadata.price, 10) : NaN;
  if (!Number.isInteger(price) || price < 1 || price > MAX_PRICE_CENTS_PER_GB) return null;
  if (o.currency !== "usd" || typeof o.amount_total !== "number") return null;
  // The cents to credit for. A FIXED tier re-derives from its KNOWN pack price (amount_total is only
  // floor-checked, so a forged same-account session can't underpay yet stamp a bigger tier). "Other amount"
  // has no fixed tier, so it credits from the Stripe-VERIFIED amount_total (this event is signature-checked
  // upstream), bounded to the custom min/max so a malformed-but-signed session can't credit absurd bytes.
  let chargedCents: number;
  if (pack === CUSTOM_PACK) {
    if (o.amount_total < CUSTOM_MIN_CENTS || o.amount_total > CUSTOM_MAX_CENTS) return null;
    chargedCents = o.amount_total;
  } else {
    if (o.amount_total < PACK_CENTS[pack]) return null;
    chargedCents = PACK_CENTS[pack];
  }
  // Primary key = the session id (dedupes distinct Event objects for one session); the Event id is
  // included so a pre-migration credit (recorded only under evt:<eventId>) still dedupes a retry.
  return { rid, bytes: bytesForCents(chargedCents, price), dedupeKeys: [`s:${sessionId}`, e.id] };
}
