// RECEIVE/download page driver (served at /d/<id> -> /receive/). Gates browser support, loads the
// delivery (passkey + metadata) via fk/receive.ts, and renders save progress into the [data-state]
// panels of web/receive/index.html. One flat bundle: web/dist/home-receive.js.
import { ensureConfig } from "./config";
import { DropApi, DropApiError } from "./api";
import { type Delivery, type ReceiveUI, loadDelivery, receiveSupportError } from "../fk/receive";

function el(id: string): HTMLElement {
  const e = document.getElementById(id);
  if (!e) throw new Error("missing #" + id);
  return e;
}
function show(state: string): void {
  document.querySelectorAll<HTMLElement>(".st").forEach((s) => { s.hidden = s.getAttribute("data-state") !== state; });
}
function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1, v = n;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}
function humanError(e: unknown): string {
  if (e instanceof DropApiError) {
    const m = e.message;
    if (/expired|removed|not found|410|404/i.test(m)) return "This file has expired or was already removed. Ask the sender for a fresh one.";
    if (/rate limited|429/i.test(m)) return "Too many requests right now. Please try again in a bit.";
    return m;
  }
  const m = e instanceof Error ? e.message : String(e);
  if (/expired|removed/i.test(m)) return "This file has expired or was already removed. Ask the sender for a fresh one.";
  if (/not allowed|timed out|NotAllowed|AbortError|cancel/i.test(m)) return "The passkey prompt was dismissed or timed out.";
  if (/no PRF|passkey|assertion/i.test(m)) return "Couldn't use that passkey on this device.";
  if (/auth_failed|wrong_namespace|AEAD|decrypt/i.test(m)) return "This file was encrypted for a different passkey. Try the passkey for the link it was sent to.";
  if (/file size/i.test(m)) return "Couldn't read the file. Ask the sender for a fresh link.";
  return m || "Something went wrong. Please try again.";
}

let delivery: Delivery | null = null;
let saving = false;
let opening = false;
let deleting = false;
let api: DropApi | null = null;
let objectId = "";
// Returning from a top-up (Stripe -> ?paid=1): the crediting webhook can lag the redirect a second or two.
const justPaid = new URLSearchParams(location.search).has("paid");
// Proactive add-credit from the delivery email (?buy=1): after unlock, auto-open the top-up picker.
const wantBuy = new URLSearchParams(location.search).has("buy");
// Low-balance nudge floor: if this file is affordable but leaves under 200 MB, show a soft note (mirrors
// the worker's projected-remaining nudge logic). Affordable-only; an unaffordable file hits the wall instead.
const LOW_CREDIT_FLOOR = 200 * 1024 * 1024;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// The saved screen's auto-delete note ("deletes itself in about N days"), from the file's ACTUAL
// remaining lifetime. Nobody should think we hold their file indefinitely; this is the moment they
// wonder. "About" hedges the lifecycle clock; null (expired-or-unknown) keeps the note hidden.
function expiresPhrase(expiresAt: number | undefined): string | null {
  if (!expiresAt) return null;
  const left = expiresAt - Date.now();
  if (left <= 0) return null;
  const days = Math.round(left / 86_400_000);
  if (days >= 2) return `in ${days} days`;
  const hours = Math.round(left / 3_600_000);
  if (hours >= 2) return `in ${hours} hours`;
  return "within the hour";
}
function renderSaved(): void {
  const note = el("expnote");
  const when = expiresPhrase(delivery?.expiresAt);
  if (when) { note.textContent = `File auto-deletes ${when}.`; note.hidden = false; }
  else note.hidden = true;
  show("saved");
}

// Offer the "try a different passkey" recovery only for failures a different passkey can fix (passkey
// dismissed / not on this device, or a wrong-identity decrypt) — not for expired/network errors.
function canRetryWithDifferentPasskey(e: unknown): boolean {
  if (e instanceof DropApiError) return false; // expired / not-found / rate-limited: a passkey won't help
  const m = e instanceof Error ? e.message : String(e);
  if (/expired|removed/i.test(m)) return false;
  return /not allowed|timed out|NotAllowed|AbortError|cancel|no PRF|passkey|assertion|auth_failed|wrong_namespace|AEAD|decrypt/i.test(m);
}
function showError(msg: string, offerDifferentPasskey = false): void {
  el("errmsg").textContent = msg;
  (el("reopen") as HTMLButtonElement).hidden = !offerDifferentPasskey;
  // Back stays the primary green CTA unless the passkey-retry button takes that slot above it.
  el("errback").className = offerDifferentPasskey ? "btn ghost full" : "btn full";
  show("error");
}

// Strip the common top-level folder shared by every path ("Signal/foo.jpg" -> "foo.jpg"), so the list
// shows clean relative names instead of repeating the folder on every row. Keeps any subfolders.
function stripTopFolder(names: string[]): string[] {
  if (names.length < 2) return names;
  const slash = names[0]!.indexOf("/");
  if (slash < 0) return names;
  const prefix = names[0]!.slice(0, slash + 1);
  return names.every((n) => n.startsWith(prefix)) ? names.map((n) => n.slice(prefix.length) || n) : names;
}

// Per-extension preview icons (Tabler-style), so the list shows photo/video/audio/zip/doc/sheet/code
// instead of one generic file icon. The paths are static (the filename only picks a category), so
// embedding them via innerHTML carries no user data.
const ICONS = {
  image: '<path d="M15 8h.01"/><path d="M3 6a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v12a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3v-12z"/><path d="M3 16l5 -5c.928 -.893 2.072 -.893 3 0l5 5"/><path d="M14 14l1 -1c.928 -.893 2.072 -.893 3 0l3 3"/>',
  video: '<path d="M15 10l4.553 -2.276a1 1 0 0 1 1.447 .894v6.764a1 1 0 0 1 -1.447 .894l-4.553 -2.276v-4z"/><path d="M3 6m0 2a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2z"/>',
  audio: '<path d="M3 17a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"/><path d="M13 17a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"/><path d="M9 17v-13h10v13"/><path d="M9 8h10"/>',
  archive: '<path d="M3 4m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v1a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z"/><path d="M5 9v8a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-8"/><path d="M10 13l4 0"/>',
  doc: '<path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"/><path d="M9 9l1 0"/><path d="M9 13l6 0"/><path d="M9 17l6 0"/>',
  sheet: '<path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"/><path d="M8 11h8v7h-8z"/><path d="M8 15h8"/><path d="M11 11v7"/>',
  code: '<path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"/><path d="M10 13l-1 2l1 2"/><path d="M14 13l1 2l-1 2"/>',
  file: '<path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"/>',
} as const;
const EXT_CATEGORY: Record<string, keyof typeof ICONS> = {
  jpg: "image", jpeg: "image", png: "image", gif: "image", webp: "image", svg: "image", heic: "image", heif: "image", bmp: "image", tiff: "image", tif: "image", avif: "image", ico: "image",
  mp4: "video", mov: "video", avi: "video", mkv: "video", webm: "video", m4v: "video", wmv: "video", mpg: "video", mpeg: "video",
  mp3: "audio", wav: "audio", flac: "audio", aac: "audio", ogg: "audio", m4a: "audio", wma: "audio", aiff: "audio",
  zip: "archive", rar: "archive", "7z": "archive", tar: "archive", gz: "archive", bz2: "archive", xz: "archive",
  pdf: "doc", doc: "doc", docx: "doc", txt: "doc", rtf: "doc", md: "doc", odt: "doc", pages: "doc",
  xls: "sheet", xlsx: "sheet", csv: "sheet", numbers: "sheet", ods: "sheet",
  js: "code", ts: "code", jsx: "code", tsx: "code", json: "code", html: "code", css: "code", py: "code", java: "code", c: "code", cpp: "code", rb: "code", go: "code", rs: "code", php: "code", sh: "code", xml: "code", yml: "code", yaml: "code", swift: "code", kt: "code",
};
function iconFor(name: string): string {
  const dot = name.lastIndexOf(".");
  const ext = dot >= 0 ? name.slice(dot + 1).toLowerCase() : "";
  const cat = EXT_CATEGORY[ext] ?? "file";
  return `<svg class="frowicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[cat]}</svg>`;
}

function showReady(): void {
  if (!delivery) return;
  el("rfname").textContent = delivery.filename;
  const entries = delivery.entries;
  const list = el("rfiles");      // the inner scroll element we fill with rows
  const box = el("rfilesbox");    // the outer rounded box we show/hide
  if (entries) {
    el("rfsize").textContent = `${fmtBytes(delivery.originalSize)} · ${entries.total} ${entries.total === 1 ? "file" : "files"}`;
    list.replaceChildren();
    for (const name of stripTopFolder(entries.names)) {
      const row = document.createElement("div");
      row.className = "filerow";
      row.innerHTML = iconFor(name); // static per-type SVG; the filename only selects a category (no user data)
      const span = document.createElement("span");
      span.className = "frowname";
      span.textContent = name; // textContent escapes any HTML in the filename
      row.appendChild(span);
      list.appendChild(row);
    }
    if (entries.names.length < entries.total) {
      const more = document.createElement("div");
      more.className = "filemore";
      more.textContent = `and ${entries.total - entries.names.length} more`;
      list.appendChild(more);
    }
    box.hidden = false;
  } else {
    el("rfsize").textContent = fmtBytes(delivery.originalSize);
    box.hidden = true;
  }
  renderCredit();
  show("ready");
}

// Credit UI on the ready panel, ALL gated on delivery.credit (billing on). No-ops cleanly when it's
// undefined (billing off): every element stays hidden and the add-credit link is inert. Reuses the page's
// Credit in GB ALWAYS (never rolls up to TB), with thousands separators, matching the worker's humanSize,
// the email, and the pack labels: a 1 TB balance reads "1,000 GB credit" (big numbers feel generous).
// Decimal GB (1 GB = 1e9), never a dollar price. (Binary fmtBytes stays for raw file sizes.)
function creditSize(bytes: number): string {
  const gb = Math.round((bytes / 1_000_000_000) * 10) / 10; // round to 0.1 GB so float noise can't render a spurious ".0"
  const s = Number.isInteger(gb) ? String(gb) : gb.toFixed(1);
  const [intPart, frac] = s.split(".");
  const withCommas = intPart!.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return frac ? `${withCommas}.${frac} GB` : `${withCommas} GB`;
}
function renderCredit(): void {
  const chipRow = el("rcreditrow");
  const chip = el("rcredit");
  const low = el("rlownote");
  const paidNote = el("rpaidnote");
  const addLink = el("raddcredit") as HTMLButtonElement;
  const credit = delivery?.credit;
  if (!credit) {
    // Billing off: hide the whole credit cluster.
    chipRow.hidden = true;
    low.hidden = true;
    paidNote.hidden = true;
    addLink.hidden = true;
    return;
  }
  chip.textContent = `${creditSize(credit.balanceBytes)} left`;
  chipRow.hidden = false;
  addLink.hidden = false;
  // After a top-up (?paid=1) the chip already reflects the refreshed balance (a fresh loadDelivery re-read
  // the header on unlock); confirm it with a brief "Credit added" note.
  if (justPaid) paidNote.textContent = `Credit added. You now have ${creditSize(credit.balanceBytes)} of download credit.`;
  paidNote.hidden = !justPaid;
  // Low-balance nudge: affordable file (projected remaining >= 0) but it leaves under the floor. An
  // unaffordable file is the existing wall, not this soft note.
  const projected = credit.balanceBytes - (delivery?.originalSize ?? 0);
  low.hidden = !(projected >= 0 && projected < LOW_CREDIT_FLOOR);
}

function makeUI(): ReceiveUI {
  const phaseEl = el("phase"), bytesEl = el("bytes"), fill = el("barfill"), bar = fill.parentElement!;
  const cancelBtn = el("cancel") as HTMLButtonElement;
  let onCancelFn: (() => void) | null = null;
  cancelBtn.onclick = () => { cancelBtn.disabled = true; cancelBtn.textContent = "Cancelling…"; onCancelFn?.(); };
  return {
    onCancel(fn) { onCancelFn = fn; },
    phase(label) { phaseEl.textContent = label; bytesEl.textContent = ""; bar.classList.add("indet"); },
    progress(done, total) {
      bar.classList.remove("indet");
      fill.style.width = `${total > 0 ? Math.min(100, (done / total) * 100) : 0}%`;
      bytesEl.textContent = total > 0 ? `${fmtBytes(done)} of ${fmtBytes(total)}` : "";
    },
  };
}

async function doSave(): Promise<void> {
  if (!delivery || saving) return;
  saving = true;
  el("sfname").textContent = delivery.filename;
  el("sfsize").textContent = fmtBytes(delivery.originalSize);
  const cancelBtn = el("cancel") as HTMLButtonElement;
  cancelBtn.disabled = false; cancelBtn.textContent = "Cancel";
  el("phase").textContent = "Saving"; el("bytes").textContent = "";
  el("barfill").style.width = "0%"; el("barfill").parentElement!.classList.add("indet");
  show("saving");
  try {
    const result = await delivery.save(makeUI());
    if (result === "stopped") { showReady(); return; } // cancelled or dismissed the save dialog
    if (typeof result !== "string") {
      // Out of credit. If the user JUST paid (?paid return), the crediting webhook may simply lag the
      // redirect — do NOT re-enter save() from a timer (the OS save dialog needs a live user gesture;
      // Chrome's activation expires ~5s, so a late retry throws SecurityError right after a successful
      // payment), and NEVER bounce them back to the wall they just paid at (that invites a double
      // purchase). Instead poll the FREE credit read (no charge, no dialog, no passkey prompt) until the
      // balance covers this file, then hand back a fresh Save click.
      if (justPaid) {
        el("phase").textContent = "Confirming payment"; el("bytes").textContent = "";
        el("barfill").parentElement!.classList.add("indet");
        const before = result.balanceBytes;
        let balance = before;
        for (let i = 0; i < 8 && balance < result.needBytes; i++) {
          await sleep(1500);
          if (cancelBtn.disabled) { showReady(); return; } // user hit Cancel during the wait (the button disables on click)
          const fresh = await delivery.refreshCredit().catch(() => null);
          if (fresh) { balance = fresh.balanceBytes; delivery.credit = fresh; }
        }
        if (balance < result.needBytes && balance > before) { await showTopUp(); return; } // payment landed but under-bought -> the wall, with the new balance
        showReady(); // covers it (tap Save again) or still processing -- either way, never the wall
        const note = el("rpaidnote");
        note.textContent = balance >= result.needBytes
          ? "Payment received. Tap Save to download."
          : "Your payment is still processing. Give it a moment, then tap Save again.";
        note.hidden = false;
        return;
      }
      await showTopUp(); // out of credit, no recent payment -> the only money moment
      return;
    }
    renderSaved();
  } catch (e) {
    showError(humanError(e));
  } finally {
    saving = false;
  }
}

// The out-of-funds wall (the only place money surfaces): pull the prepaid tiers from the server (labels
// reflect the live price), render them, and on a tap prove possession + redirect to Stripe Checkout.
async function showTopUp(): Promise<void> {
  if (!delivery) return;
  const list = el("packs");
  list.replaceChildren();
  show("topup");
  try {
    const packs = await delivery.packs();
    for (const p of packs) {
      const b = document.createElement("button");
      b.className = "pack";
      b.type = "button";
      b.textContent = p.label;
      b.onclick = () => {
        list.querySelectorAll("button").forEach((x) => ((x as HTMLButtonElement).disabled = true));
        void delivery!.checkout(p.id).catch((e) => {
          list.querySelectorAll("button").forEach((x) => ((x as HTMLButtonElement).disabled = false));
          showError(humanError(e));
        });
      };
      list.appendChild(b);
    }
  } catch (e) {
    showError(humanError(e));
  }
}

// Remove the delivered ciphertext from the server: frees our storage (and the receiver's inbox
// capacity, immediately) and clears the only server copy for peace of mind. Proof-gated via the
// delivery's in-memory identity (no passkey prompt): under in-place delivery the SENDER knows the
// object id, so only a possession proof may delete. Offered from the "saved" state (file already on
// disk) AND from "ready" as "Delete without saving" — the receiver's lever against junk, which is
// never charged (discarding is not a download).
async function doDelete(btnId: "delfile" | "rdiscard"): Promise<void> {
  if (deleting || !delivery) return;
  deleting = true;
  const btn = el(btnId) as HTMLButtonElement;
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Removing…";
  try {
    await delivery.discard();
    // The deleted screen's default sub assumes a saved copy exists; the unsaved path has none.
    if (btnId === "rdiscard") el("delsub").textContent = "This file is gone from our servers. Nothing was saved and nothing was charged.";
    show("deleted");
  } catch (e) {
    showError(humanError(e));
  } finally {
    deleting = false;
    btn.disabled = false;
    btn.textContent = label;
  }
}

// "Delete without saving" is destructive for a file that exists nowhere else yet, so it takes two taps:
// the first arms the control (label turns explicit + red), the second within 5s deletes. The timer
// disarms it again so a stray tap can't linger as a loaded gun.
let discardArm = 0;
function confirmDiscard(): void {
  const b = el("rdiscard") as HTMLButtonElement;
  if (b.classList.contains("armed")) {
    clearTimeout(discardArm);
    b.classList.remove("armed");
    b.textContent = "Delete without saving";
    void doDelete("rdiscard");
    return;
  }
  b.classList.add("armed");
  b.textContent = "This destroys the file. Tap again to delete.";
  clearTimeout(discardArm);
  discardArm = window.setTimeout(() => {
    b.classList.remove("armed");
    b.textContent = "Delete without saving";
  }, 5000);
}

// Unlock runs the passkey + metadata decrypt ON THE CLICK (a user gesture). Safari rejects a WebAuthn
// call made on page load ("the document is not focused"), so we wait for this gesture; loadDelivery
// keeps the passkey first (before any network await) so it stays inside the click's activation.
function doOpen(forceOpen = false): void {
  if (opening || !api) return;
  const a = api; // capture after the null-guard so TS keeps the narrowed type across the calls below
  opening = true;
  show("loading");
  loadDelivery(a, objectId, forceOpen)
    .then((d) => {
      delivery = d;
      showReady();
      // Proactive add-credit from the email's ?buy=1 link: open the top-up picker once the file is unlocked
      // (only if billing is on, so an off deployment ignores a stray ?buy). showTopUp swaps to the topup panel.
      if (wantBuy && d.credit) void showTopUp();
    })
    .catch((e) => showError(humanError(e), canRetryWithDifferentPasskey(e)))
    .finally(() => { opening = false; });
}

async function main(): Promise<void> {
  const path = location.pathname;
  objectId = path.startsWith("/d/") ? path.slice("/d/".length).replace(/\/+$/, "") : "";
  if (!objectId) { showError("This download link is incomplete. Use the link from your delivery email."); return; }
  // Scrub ?paid from the URL once captured, so a refresh/bookmark doesn't replay the "Credit added" note
  // forever. (justPaid was already read at module load; this page-view keeps its behavior.)
  if (justPaid) {
    const u = new URL(location.href);
    u.searchParams.delete("paid");
    history.replaceState(null, "", u.pathname + u.search + u.hash);
  }
  const gateErr = await receiveSupportError();
  if (gateErr) { showError(gateErr); return; }
  try {
    const cfg = await ensureConfig();
    // Receive only needs apiBase; decryption uses the passkey-derived identity, not the server keys.
    api = new DropApi(cfg.apiBase);
  } catch (e) {
    showError(humanError(e));
    return;
  }
  if (wantBuy) {
    // Arrived via the email's "Add credit" link (?buy=1): reframe the unlock screen for adding credit, so it
    // doesn't read as "open a file". The passkey identifies the account; after unlock the picker auto-opens.
    el("lockh1").textContent = "Add credit";
    el("locksub").textContent = "Unlock with your passkey to add credit to your account.";
  }
  show("locked"); // wait for the Unlock click before touching the passkey (Safari needs the user gesture)
}

el("open").onclick = () => doOpen();
el("reopen").onclick = () => doOpen(true); // explicit "try a different passkey" (open prompt, ignores the pin)
el("save").onclick = () => void doSave();
el("saveagain").onclick = () => void doSave();
el("delfile").onclick = () => void doDelete("delfile");
el("rdiscard").onclick = confirmDiscard;
el("raddcredit").onclick = () => void showTopUp(); // proactive add-credit (billing on; the element is hidden otherwise)
el("topupback").onclick = () => showReady();
void main();
