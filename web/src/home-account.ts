// The ACCOUNT WALLET page (Phase 2a): an email magic-link sign-in -> see prepaid balance + add credit, with
// no delivered file needed. Renders into web/account/index.html's [data-state] panels and calls /account/* on
// the Worker. Served at /account via _redirects -> /account/. One flat bundle: web/dist/home-account.js.
//
// Entry: arriving with `#<magicToken>` redeems it (the token is scrubbed from history immediately) for a
// 30-min session; otherwise a session in sessionStorage is restored; otherwise the enter-email form shows.
// After a Stripe top-up the page returns with ?paid=1 and polls the balance against a pre-checkout baseline
// (a webhook can lag the redirect), only claiming "Credit added" once the balance actually rises.
import { base64urlEncode } from "../../shared/codec";
import { importKemPublicKey, sealEmail } from "../../shared/crypto";
import { DropApi, DropApiError } from "./api";
import { ensureConfig, isConfigured } from "./config";

const SESSION_KEY = "rl_acct"; // the 30-min Bearer session token (tab-scoped)
const BASELINE_KEY = "rl_acct_base"; // balance captured just before a checkout redirect, to detect the credit

function el(id: string): HTMLElement {
  const e = document.getElementById(id);
  if (!e) throw new Error("missing #" + id);
  return e;
}
function show(state: string): void {
  document.querySelectorAll<HTMLElement>(".st").forEach((s) => {
    s.hidden = s.getAttribute("data-state") !== state;
  });
}
function hexToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
// Capacity in GB with thousands separators, rounded to 0.1 so float noise can't render a spurious ".0"
// (mirrors the worker's humanSize + the receive page's creditSize, so credit reads the same everywhere).
function creditSize(bytes: number): string {
  const gb = Math.round((bytes / 1_000_000_000) * 10) / 10;
  const s = Number.isInteger(gb) ? String(gb) : gb.toFixed(1);
  const [intPart, frac] = s.split(".");
  const withCommas = intPart!.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return frac ? `${withCommas}.${frac} GB` : `${withCommas} GB`;
}
function humanError(e: unknown): string {
  if (e instanceof DropApiError) {
    if (e.status === 401) return "That sign-in link expired or was already used. Sign in again.";
    if (e.status === 503) return "Accounts aren't available here yet. Try again shortly.";
    if (/rate limited|too many/i.test(e.message)) return "Too many requests right now. Please try again in a bit.";
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function getSession(): string | null { try { return sessionStorage.getItem(SESSION_KEY); } catch { return null; } }
function setSession(t: string): void { try { sessionStorage.setItem(SESSION_KEY, t); } catch { /* private mode */ } }
function clearSession(): void { try { sessionStorage.removeItem(SESSION_KEY); } catch { /* ignore */ } }

let api: DropApi;
let cfg: Awaited<ReturnType<typeof ensureConfig>>;
let paidReturn = false; // arrived via ?paid=1 (a Stripe return)

function showError(msg: string): void { el("errmsg").textContent = msg; show("error"); }

// The enter-email form: seal the typed address to the server KEM key and ask for a magic link. The response
// is a uniform 202 (it never says whether an account exists), so we always advance to "check your email".
function showEmail(note?: string): void {
  if (note) el("emailsub").textContent = note;
  show("email");
  const input = el("email") as HTMLInputElement;
  const send = el("send") as HTMLButtonElement;
  const submit = async () => {
    const email = input.value.trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { input.focus(); return; }
    send.disabled = true; send.textContent = "Sending…";
    try {
      if (!isConfigured(cfg)) { showError("This site isn't wired up for accounts yet. Try again shortly."); return; }
      const kemPub = await importKemPublicKey(hexToBytes(cfg.serverKemPublicHex));
      await api.accountLogin(base64urlEncode(await sealEmail(kemPub, email)));
      show("sent");
    } catch (e) {
      send.disabled = false; send.textContent = "Email me a sign-in link";
      showError(humanError(e));
    }
  };
  send.onclick = () => void submit();
  input.onkeydown = (ev) => { if (ev.key === "Enter") void submit(); };
}

function renderBalance(tier: "free" | "paid", balanceBytes: number): void {
  el("balance").textContent = `${creditSize(balanceBytes)} left`;
  el("acctsub").textContent = tier === "free"
    ? "You're on the free plan. Credit is spent only when you download a file, and never expires."
    : "Credit is spent only when you download a file, and never expires.";
}

// The account view: balance chip + an "Add credit" button that reveals the prepaid pack picker. A pack tap
// stores the current balance as a baseline (so the ?paid return can detect the credit) and redirects to
// Stripe-hosted Checkout.
function renderAccount(token: string, tier: "free" | "paid", balanceBytes: number): void {
  renderBalance(tier, balanceBytes);
  show("account");
  const add = el("add") as HTMLButtonElement;
  const packsBox = el("packs");
  const back = el("packsback") as HTMLButtonElement;
  const closePacks = () => { packsBox.hidden = true; packsBox.replaceChildren(); back.hidden = true; add.hidden = false; add.disabled = false; };
  back.onclick = closePacks;
  add.onclick = async () => {
    add.disabled = true;
    try {
      const { packs } = await api.billingPacks();
      packsBox.replaceChildren();
      for (const p of packs) {
        const b = document.createElement("button");
        b.className = "pack"; b.type = "button"; b.textContent = p.label;
        b.onclick = async () => {
          packsBox.querySelectorAll("button").forEach((x) => ((x as HTMLButtonElement).disabled = true));
          try {
            // Capture a FRESH baseline right before checkout (not the stale render-time balance) so the ?paid
            // return reliably detects this top-up even if the balance moved since the page loaded.
            const fresh = await api.accountSummary(token);
            try { sessionStorage.setItem(BASELINE_KEY, String(fresh.balanceBytes)); } catch { /* private mode: the poll just won't fire */ }
            const { url } = await api.accountCheckout(token, p.id);
            window.location.href = url;
          } catch (e) {
            packsBox.querySelectorAll("button").forEach((x) => ((x as HTMLButtonElement).disabled = false));
            if (e instanceof DropApiError && e.status === 401) { clearSession(); showEmail("Your session expired. Sign in again to add credit."); return; }
            showError(humanError(e));
          }
        };
        packsBox.appendChild(b);
      }
      add.hidden = true; packsBox.hidden = false; back.hidden = false;
    } catch (e) {
      add.disabled = false;
      showError(humanError(e));
    }
  };
}

// After a Stripe return (?paid=1), the webhook that actually credits the account can lag the redirect, so we
// poll the balance against the pre-checkout baseline and only claim success once it actually rises.
async function settleAfterPayment(token: string, tier: "free" | "paid", balanceBytes: number): Promise<void> {
  let baseline = NaN;
  try { const b = sessionStorage.getItem(BASELINE_KEY); if (b !== null) baseline = Number(b); } catch { /* ignore */ }
  try { sessionStorage.removeItem(BASELINE_KEY); } catch { /* ignore */ }
  renderAccount(token, tier, balanceBytes);
  if (!Number.isFinite(baseline)) return; // no baseline (e.g. private mode) -> just show the current balance
  const paidNote = el("paidnote");
  paidNote.textContent = "Payment processing…"; paidNote.hidden = false;
  for (let i = 0; i < 10; i++) { // ~20s: webhook credit usually lands in a second or two
    if (balanceBytes > baseline) { paidNote.textContent = `Credit added. You now have ${creditSize(balanceBytes)} of download credit.`; return; }
    await sleep(2000);
    try {
      const s = await api.accountSummary(token);
      balanceBytes = s.balanceBytes;
      renderBalance(s.tier, s.balanceBytes);
    } catch (e) {
      if (e instanceof DropApiError && e.status === 401) { clearSession(); showEmail("Your session expired. Sign in again to see your updated balance."); return; }
      break;
    }
  }
  paidNote.textContent = balanceBytes > baseline
    ? `Credit added. You now have ${creditSize(balanceBytes)} of download credit.`
    : "Still processing your payment. Check back in a moment.";
}

async function main(): Promise<void> {
  paidReturn = new URLSearchParams(location.search).get("paid") === "1";
  // Read the magic token from the fragment, then scrub it from the URL + history immediately (it's a bearer).
  const mt = location.hash.replace(/^#/, "");
  if (mt) history.replaceState(null, "", location.pathname + location.search);
  if (paidReturn) history.replaceState(null, "", location.pathname); // drop ?paid so a refresh doesn't re-poll

  try {
    cfg = await ensureConfig();
    api = new DropApi(cfg.apiBase);
  } catch (e) { showError(humanError(e)); return; }

  // 1) A magic link click: redeem it for a session.
  if (mt) {
    el("loadh").textContent = "Signing you in"; show("loading");
    try {
      const s = await api.accountSession(mt);
      setSession(s.token);
      if (paidReturn) { await settleAfterPayment(s.token, s.tier, s.balanceBytes); return; }
      renderAccount(s.token, s.tier, s.balanceBytes);
    } catch (e) {
      if (e instanceof DropApiError && e.status === 401) { showEmail("That sign-in link expired or was already used. Sign in again."); return; }
      showError(humanError(e));
    }
    return;
  }

  // 2) An existing tab session: restore it.
  const token = getSession();
  if (token) {
    show("loading");
    try {
      const s = await api.accountSummary(token);
      if (paidReturn) { await settleAfterPayment(token, s.tier, s.balanceBytes); return; }
      renderAccount(token, s.tier, s.balanceBytes);
      return;
    } catch (e) {
      if (!(e instanceof DropApiError && e.status === 401)) { showError(humanError(e)); return; }
      clearSession(); // 401 -> session lapsed; fall through to sign-in
    }
  }

  // 3) No token. If this is a Stripe return, the payment likely went through but the session was lost
  // (slow/new-tab return) - tell the user to sign in to see the updated balance rather than a dead end.
  showEmail(paidReturn ? "Sign in to see your updated balance." : undefined);
}

el("retry").onclick = () => showEmail();
void main();
