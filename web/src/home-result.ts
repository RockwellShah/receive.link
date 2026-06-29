// Back-half receiver pages in the new design: /confirm (reveal the permanent link), /revoke, /qr.
// Reuses app.ts's exact logic (api.confirm/revoke, the @paulmillr/qr QR, the /qr link-signature check)
// but renders into web/result/index.html's [data-state] panels instead of the chat-feed UI. The page
// is served at /confirm, /revoke, /qr via _redirects -> /result, so location.pathname is the route.
// One flat bundle: web/dist/home-result.js.
import { base64urlDecode, decodeDropLink, splitSignature } from "../../shared/codec";
import { importSignPublicKey, verifyRegion } from "../../shared/crypto";
import { DropApi, DropApiError } from "./api";
import { ensureConfig, isConfigured } from "./config";
import encodeQR from "@paulmillr/qr";

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

// Clipboard fallback for insecure origins / older browsers where navigator.clipboard is absent.
function legacyCopy(text: string): boolean {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:-1000px;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch { return false; }
}

// Last resort: select the visible link so the user can copy it by hand.
function selectUrl(): void {
  const u = document.getElementById("url");
  if (!u) return;
  const range = document.createRange();
  range.selectNodeContents(u);
  const sel = window.getSelection();
  sel?.removeAllRanges();
  sel?.addRange(range);
}

// Humanize the back-half errors (mirrors the relevant branches of app.ts humanError).
function humanError(e: unknown): string {
  if (e instanceof DropApiError) {
    const m = e.message;
    if (/revoked/i.test(m)) return "This link has already been turned off.";
    if (/invalid or expired/i.test(m)) return "This confirmation link expired or was already used. Set up a new link.";
    if (/invalid token|bad token|missing token/i.test(m)) return "This manage link isn't valid. Use the most recent one from a delivery email or your confirmation page.";
    if (/rate limited|daily limit|over its daily/i.test(m)) return "Too many requests right now. Please try again in a bit.";
    return m;
  }
  const m = e instanceof Error ? e.message : String(e);
  if (/invalid link|bad signature|not a/i.test(m)) return "This link isn't valid. Ask the recipient for a fresh one.";
  return m;
}

function showError(msg: string): void {
  el("errmsg").textContent = msg;
  show("error");
}

// The link's name (the label chosen at setup), parsed from the signed payload. "" if absent/unparsable.
function linkLabel(payload: string): string {
  try { return decodeDropLink(base64urlDecode(payload)).label || ""; } catch { return ""; }
}

// Reveal the link: the URL, copy + share, and the QR toggle.
function renderReveal(shareUrl: string, opts: { heading: string; sub: string; note?: string; qrOpen: boolean; name?: string; billingEnabled?: boolean }): void {
  el("revh").textContent = opts.heading;
  el("revsub").innerHTML = opts.sub; // sub is a trusted constant; may contain <br>
  const nameEl = el("revname");
  if (opts.name) { el("revnametext").textContent = opts.name; nameEl.hidden = false; } else { nameEl.hidden = true; }
  el("url").textContent = shareUrl;

  const note = el("note");
  if (opts.note) { note.textContent = opts.note; note.hidden = false; } else { note.hidden = true; }

  const copy = el("copy");
  const flashCopy = (msg: string) => { copy.textContent = msg; setTimeout(() => { copy.textContent = "Copy link"; }, 1800); };
  copy.onclick = () => {
    const done = (ok: boolean) => {
      if (ok) flashCopy("Copied!");
      else if (legacyCopy(shareUrl)) flashCopy("Copied!");
      else { selectUrl(); flashCopy("Copy the selected link"); }
    };
    // navigator.clipboard is undefined on insecure origins / older browsers and would throw
    // synchronously, so guard it before calling and route every failure through the fallback.
    const clip = navigator.clipboard;
    if (clip && typeof clip.writeText === "function") clip.writeText(shareUrl).then(() => done(true)).catch(() => done(false));
    else done(false);
  };

  const share = el("share");
  if (typeof navigator.share === "function") {
    share.hidden = false;
    share.onclick = () => { void navigator.share({ url: shareUrl }).catch(() => {}); };
  }

  // QR as a raster PNG <img> (drawn from the raw module matrix onto a canvas) so mobile long-press
  // offers Save / Copy / Share. PNG keeps the 2-color image tiny (a few KB) vs the library's
  // uncompressed GIF; the white .qr padding doubles as the scanner quiet zone.
  const qrEl = el("qr");
  const qrToggle = el("qrtoggle");
  const qrLabel = el("qrlabel");
  let qrOk = false;
  try {
    const matrix = encodeQR(shareUrl, "raw", { ecc: "medium", border: 2 });
    const n = matrix.length;
    const px = 6;
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = n * px;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.fillStyle = "#fff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#000";
      for (let y = 0; y < n; y++) {
        const row = matrix[y];
        if (!row) continue;
        for (let x = 0; x < n; x++) if (row[x]) ctx.fillRect(x * px, y * px, px, px);
      }
      qrEl.innerHTML = `<img alt="QR code linking to your receive.link" src="${canvas.toDataURL("image/png")}">`;
      qrOk = true;
    }
  } catch { /* QR failed */ }
  if (qrOk) {
    qrToggle.hidden = false;
    const setQr = (open: boolean) => { qrEl.hidden = !open; qrLabel.textContent = open ? "Hide QR" : "Show QR"; qrToggle.setAttribute("aria-expanded", open ? "true" : "false"); };
    setQr(opts.qrOpen);
    qrToggle.onclick = () => setQr(qrEl.hidden);
  } else {
    qrToggle.hidden = true;
  }

  show("reveal");
}

async function confirmFlow(nonce: string): Promise<void> {
  el("loadh").textContent = "Finishing setup";
  show("loading");
  try {
    const cfg = await ensureConfig();
    if (!isConfigured(cfg)) { showError("This site isn't configured for sign-up yet. Try again shortly."); return; }
    const api = new DropApi(cfg.apiBase);
    const { link, billingEnabled } = await api.confirm(nonce);
    renderReveal(`${location.origin}/#${link}`, {
      heading: "Your link is ready",
      sub: "Share it with anyone.<br>Only you can open what they send.",
      note: "Also, we emailed you this info.",
      qrOpen: false,
      name: linkLabel(link),
      billingEnabled,
    });
  } catch (e) { showError(humanError(e)); }
}

async function qrFlow(payload: string): Promise<void> {
  el("loadh").textContent = "Loading your link";
  show("loading");
  try {
    if (!payload) { showError("This link isn't valid. Ask the recipient for a fresh one."); return; }
    const cfg = await ensureConfig();
    if (!isConfigured(cfg)) { showError("This site isn't configured yet. Try again shortly."); return; }
    // Verify the link's server signature before showing it (mirrors app.ts qrMode).
    const bytes = base64urlDecode(payload);
    const { signable, signature } = splitSignature(bytes);
    const pub = await importSignPublicKey(cfg.serverSignPublicJwk as JsonWebKey);
    if (!(await verifyRegion(pub, signable, signature))) throw new Error("bad signature");
    renderReveal(`${location.origin}/#${payload}`, {
      heading: "Your link",
      sub: "Share it, or have them scan the QR.<br>Only you can open what they send.",
      qrOpen: true,
      name: linkLabel(payload),
    });
  } catch (e) { showError(humanError(e)); }
}

function revokeFlow(token: string): void {
  if (!token) { showError("This manage link isn't valid. Use the most recent one from a delivery email or your confirmation page."); return; }
  show("revoke-confirm");
  let revoking = false;
  el("revyes").onclick = () => {
    if (revoking) return;
    revoking = true;
    el("loadh").textContent = "Turning off your link";
    show("loading");
    void (async () => {
      try {
        const cfg = await ensureConfig();
        const api = new DropApi(cfg.apiBase);
        await api.revoke(token);
        show("revoke-done");
      } catch (e) { revoking = false; showError(humanError(e)); }
    })();
  };
}

const path = location.pathname;
const hash = location.hash.replace(/^#/, "");
if (path === "/revoke") revokeFlow(hash);
else if (path === "/qr") void qrFlow(hash);
else void confirmFlow(hash); // /confirm (and a bare /result fallback)
