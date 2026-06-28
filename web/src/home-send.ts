// SEND page driver (served at /u -> /send/). Verifies the share link, arms the drop zone + pickers,
// runs the UI-agnostic fk/send.ts orchestration, and renders its phases/progress into the [data-state]
// panels of web/send/index.html. One flat bundle: web/dist/home-send.js.
import { ensureConfig, isConfigured } from "./config";
import { DropApi, DropApiError } from "./api";
import { type BundleItem, collectFromDrop, collectFromInput } from "../fk/bundle";
import { type SendUI, sendBundle, verifyLink } from "../fk/send";

function el(id: string): HTMLElement {
  const e = document.getElementById(id);
  if (!e) throw new Error("missing #" + id);
  return e;
}
function show(state: string): void {
  document.querySelectorAll<HTMLElement>(".st").forEach((s) => { s.hidden = s.getAttribute("data-state") !== state; });
}
function isReady(): boolean {
  const r = document.querySelector('.st[data-state="ready"]') as HTMLElement | null;
  return !!r && !r.hidden;
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
    if (/too large|maxBytes|413/i.test(m)) return "That's over the upload size limit for this link.";
    if (/rate limited|daily limit|over its daily|429/i.test(m)) return "This link has hit its limit for now. Please try again later.";
    if (/revoked|expired|not found|410|404/i.test(m)) return "This link is no longer active. Ask the recipient for a fresh one.";
    return m;
  }
  const m = e instanceof Error ? e.message : String(e);
  if (/aborted|cancel/i.test(m)) return "Upload cancelled.";
  return m || "Something went wrong. Please try again.";
}

let api: DropApi;
let payload = "";
let recipientLabel = "";
let sending = false; // serialize sends: ignore new drops/picks while one is in flight

function quoted(): string {
  return recipientLabel ? `“${recipientLabel}”` : "the recipient";
}

function showReady(): void {
  el("sendh").textContent = recipientLabel ? `Send files to ${quoted()}` : "Send files";
  el("sendsub").textContent = `They're encrypted in your browser, so only ${quoted()} can open them.`;
  show("ready");
}

function showError(msg: string, fatal = false): void {
  el("errmsg").textContent = msg;
  const btn = el("errbtn") as HTMLButtonElement;
  if (fatal) { btn.textContent = "Back to receive.link"; btn.onclick = () => { location.href = "/"; }; }
  else { btn.textContent = "Try again"; btn.onclick = () => showReady(); }
  show("error");
}

// Map fk/send.ts phases/progress onto the working panel. Phases without byte progress (Preparing,
// Finishing) show an indeterminate sliding bar; progress() switches it to a determinate fill.
function makeUI(): SendUI {
  const phaseEl = el("phase"), bytesEl = el("bytes"), fill = el("barfill"), bar = fill.parentElement!;
  const cancelBtn = el("cancel") as HTMLButtonElement;
  let onCancelFn: (() => void) | null = null;
  cancelBtn.onclick = () => { cancelBtn.disabled = true; cancelBtn.textContent = "Cancelling…"; onCancelFn?.(); };
  return {
    onCancel(fn) { onCancelFn = fn; },
    // Show Cancel for cancelable phases (Encrypting/Uploading, any size); hide it for the rest
    // (Bundling/Preparing/Finishing) so it's never clickable during the non-abortable steps.
    phase(label, cancelable = false) {
      phaseEl.textContent = label; bytesEl.textContent = ""; bar.classList.add("indet");
      cancelBtn.hidden = !cancelable;
    },
    progress(done, total) {
      bar.classList.remove("indet");
      fill.style.width = `${total > 0 ? Math.min(100, (done / total) * 100) : 0}%`;
      bytesEl.textContent = total > 0 ? `${fmtBytes(done)} of ${fmtBytes(total)}` : "";
    },
  };
}

async function startSend(items: BundleItem[]): Promise<void> {
  if (sending || !items.length) return;
  sending = true;
  const single = items.length === 1 && !items[0]!.fromFolder;
  const totalSize = items.reduce((n, it) => n + it.file.size, 0);
  el("fname").textContent = single ? items[0]!.file.name : `${items.length} files`;
  el("fsize").textContent = fmtBytes(totalSize);
  const cancelBtn = el("cancel") as HTMLButtonElement;
  cancelBtn.hidden = true; cancelBtn.disabled = false; cancelBtn.textContent = "Cancel";
  el("phase").textContent = "Preparing"; el("bytes").textContent = "";
  el("barfill").style.width = "0%"; el("barfill").parentElement!.classList.add("indet");
  show("working");
  try {
    const result = await sendBundle(api, payload, items, makeUI());
    if (result === "cancelled") { showReady(); return; }
    el("sentsub").textContent = recipientLabel
      ? `We emailed ${quoted()} a secure download link.`
      : "We emailed them a secure download link.";
    show("sent");
  } catch (e) {
    showError(humanError(e));
  } finally {
    sending = false;
  }
}

function armDropZone(): void {
  const drop = el("drop");
  const fileInput = el("fileinput") as HTMLInputElement;
  const folderInput = el("folderinput") as HTMLInputElement;
  el("browse").onclick = () => fileInput.click();
  el("folderbtn").onclick = () => folderInput.click();
  // Click anywhere in the box except on a picker button opens the file picker.
  drop.onclick = (e) => { if (!(e.target as HTMLElement).closest(".dc_btn")) fileInput.click(); };
  fileInput.onchange = () => { if (fileInput.files?.length) void startSend(collectFromInput(fileInput.files)); fileInput.value = ""; };
  folderInput.onchange = () => { if (folderInput.files?.length) void startSend(collectFromInput(folderInput.files)); folderInput.value = ""; };
  // Accept a drop anywhere on the page; highlight the zone while dragging.
  const stop = (e: Event) => { e.preventDefault(); e.stopPropagation(); };
  ["dragenter", "dragover"].forEach((ev) => window.addEventListener(ev, (e) => { stop(e); if (isReady()) drop.classList.add("drag"); }));
  // Clear the highlight only when the drag truly leaves the window (relatedTarget null), not on
  // child-boundary leaves — otherwise it flickers as the pointer crosses page elements.
  window.addEventListener("dragleave", (e) => { stop(e); if ((e as DragEvent).relatedTarget === null) drop.classList.remove("drag"); });
  window.addEventListener("drop", (e) => {
    stop(e);
    drop.classList.remove("drag");
    const dt = (e as DragEvent).dataTransfer;
    if (dt && isReady()) void collectFromDrop(dt).then((items) => { if (items.length) void startSend(items); });
  });
}

async function main(): Promise<void> {
  payload = location.hash.replace(/^#/, "");
  if (!payload) { showError("This link is incomplete. Ask the recipient for a fresh one.", true); return; }
  try {
    const cfg = await ensureConfig();
    if (!isConfigured(cfg)) { showError("This site isn't configured yet. Try again shortly.", true); return; }
    api = new DropApi(cfg.apiBase);
    const { label } = await verifyLink(payload, cfg.serverSignPublicJwk as JsonWebKey);
    recipientLabel = label;
    showReady();
  } catch {
    showError("This link isn't valid. It may be incomplete or tampered with. Ask the recipient for a fresh one.", true);
  }
}

el("sendmore").onclick = () => showReady();
armDropZone();
void main();
