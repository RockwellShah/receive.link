// UI-agnostic receive/download orchestration, lifted from app.ts (the gate + receiveMode + the save).
// Gate browser support, derive the identity from the passkey (PRF), fetch + decrypt the metadata prefix
// for the filename, then stream the full ciphertext to disk on save (1x disk, never buffering the whole
// file). The page provides a ReceiveUI for save progress/cancel. Crypto/stream/api/webauthn reused.
import { type Identity, NamespaceSet, deriveIdentityFromPrf } from "../core/src/index.js";
import { base64urlDecode, base64urlEncode } from "../../shared/codec";
import type { DropApi } from "../src/api";
import { checkSupport, getPrfSecret, prfBrowserSupport } from "../src/webauthn";
import { openCiphertext, openCiphertextSource, streamSource } from "./stream";

// Same namespace as the app (interop with filekey.app).
const NS = new NamespaceSet(["filekey.app"]);
const ns = NS.namespaces[0]!;

// Enough of the ciphertext to cover the fixed head + metadata (<= ~1 MiB), fetched as a Range request so
// the filename shows without downloading the whole file.
const METADATA_PREFIX = 1_200_000;

// The page implements this to render save progress + wire the Cancel button.
export interface ReceiveUI {
  phase(label: string): void;
  progress(done: number, total: number): void;
  onCancel(fn: () => void): void;
}

export interface Delivery {
  filename: string;
  mimeType: string;
  originalSize: number;
  // For a multi-file bundle, the file list the sender packed into the encrypted metadata (undefined for
  // a single file or a link without it). `total` is the true count; `names` may be truncated for huge bundles.
  entries?: { total: number; names: string[] };
  // Stream the full file to disk. "saved" on success; "stopped" if the user cancels or dismisses the
  // OS save dialog (the page returns to ready); throws on a real failure.
  save(ui: ReceiveUI): Promise<"saved" | "stopped">;
}

// Read the bundle file list a Drop sender packed into metadata.extras ("rl.files"). undefined if absent
// or malformed (single files, old links, and main-app bundles just won't have it).
function parseBundleEntries(extras: Map<string, Uint8Array>): { total: number; names: string[] } | undefined {
  const raw = extras.get("rl.files");
  if (!raw) return undefined;
  try {
    const obj = JSON.parse(new TextDecoder().decode(raw)) as { n?: unknown; f?: unknown };
    if (!Array.isArray(obj.f)) return undefined;
    const names = obj.f.filter((x): x is string => typeof x === "string");
    if (!names.length) return undefined;
    const total = typeof obj.n === "number" && Number.isSafeInteger(obj.n) && obj.n >= names.length ? obj.n : names.length;
    return { total, names };
  } catch {
    return undefined;
  }
}

// The gate: an error message if this browser can't open a delivery, else null.
export async function receiveSupportError(): Promise<string | null> {
  const s = checkSupport();
  if (!s.secureContext || !s.webauthn) return "This browser can't open receive.link. It needs passkeys (WebAuthn) over HTTPS. Try a recent Chrome, Edge, or Safari.";
  if ((await prfBrowserSupport()) === false) return "This browser is missing a passkey feature receive.link needs (PRF). Try the latest Chrome, Edge, or Safari.";
  return null;
}

// Persist / drop the passkey pin (rl_cred). We pin ONLY after a passkey is proven to own the file
// (loadDelivery, post-decrypt) and forget it the moment a decrypt fails, so a wrong passkey never sticks.
function rememberPasskey(credentialId: Uint8Array): void {
  try { localStorage.setItem("rl_cred", base64urlEncode(credentialId)); } catch { /* storage blocked / private mode */ }
}
function forgetPasskey(): void {
  try { localStorage.removeItem("rl_cred"); } catch { /* private mode */ }
}

// PRF secret + the credential it came from. Targets the pinned passkey (rl_cred) so the authenticator
// uses it directly; forceOpen ignores the pin and shows an OPEN prompt (any receive.link passkey on this
// device) — that's the explicit "try a different passkey" recovery. This does NOT persist anything:
// loadDelivery pins only after the decrypt proves the identity, so a cancel or a wrong pick can't
// silently re-pin to the wrong credential. Mirrors app.ts prfSecret().
async function prfSecret(forceOpen: boolean): Promise<{ secret: Uint8Array; credentialId: Uint8Array }> {
  let id: Uint8Array | undefined;
  if (!forceOpen) {
    try {
      const stored = localStorage.getItem("rl_cred");
      if (stored) id = base64urlDecode(stored);
    } catch { /* storage blocked / private mode: open prompt */ }
  }
  return await getPrfSecret(id);
}

// Read at most `max` bytes from a response body, then cancel the rest (so reading just the metadata never
// downloads the whole file even if the server ignored our Range request). Ported from app.ts.
async function readPrefix(resp: Response, max: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!resp.body) return new Uint8Array(await resp.arrayBuffer()).subarray(0, max);
  const reader = resp.body.getReader();
  const parts: Uint8Array[] = [];
  let len = 0;
  try {
    while (len < max) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value && value.length) { parts.push(value); len += value.length; }
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(len, max));
  let off = 0;
  for (const p of parts) {
    if (off >= out.length) break;
    const take = p.subarray(0, out.length - off);
    out.set(take, off);
    off += take.length;
  }
  return out;
}

// Strip bidi-override/isolate + LRM/RLM chars (filename spoofing — "Trojan Source") and control chars,
// map path separators to "_", cap length. Code-point comparisons so no invisible chars live in source.
function sanitizeName(name: string): string {
  let out = "";
  for (const ch of name) {
    const c = ch.codePointAt(0) ?? 0;
    if ((c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c === 0x200e || c === 0x200f) continue; // bidi
    if (c < 0x20) continue; // control chars
    out += ch === "/" || ch === "\\" ? "_" : ch;
  }
  return (out.trim() || "filekey-output").slice(0, 200);
}

// Fetch the full ciphertext + open it for streaming decryption (never buffers the whole file).
async function openStream(url: string, identity: Identity, signal: AbortSignal): Promise<AsyncGenerator<Uint8Array>> {
  const resp = await fetch(url, { signal });
  if (!resp.ok || !resp.body) throw new Error("the file has expired or was already removed");
  const size = Number(resp.headers.get("content-length"));
  if (!Number.isFinite(size) || size <= 0) throw new Error("couldn't read the file size");
  const { chunks } = await openCiphertextSource(streamSource(resp.body, size), identity, NS);
  return chunks;
}

// Stream the full ciphertext to disk: a fresh fetch per call (naturally restartable), decrypt, write.
async function saveToDisk(url: string, identity: Identity, filename: string, mimeType: string, totalSize: number, ui: ReceiveUI): Promise<"saved" | "stopped"> {
  const name = sanitizeName(filename);
  const ctrl = new AbortController();
  let cancelled = false;
  ui.onCancel(() => { cancelled = true; ctrl.abort(); });
  const w = window as unknown as {
    showSaveFilePicker?: (o: unknown) => Promise<{ createWritable: () => Promise<{ write: (b: Uint8Array) => Promise<void>; close: () => Promise<void>; abort?: () => Promise<void> }> }>;
  };
  try {
    // Fetch + open the stream FIRST so a stale/expired link fails fast, before prompting for a save
    // location (matches the original receive flow). 1x disk: never buffers the whole ciphertext.
    const chunks = await openStream(url, identity, ctrl.signal);
    if (w.showSaveFilePicker) {
      // Chrome/Edge: pick a destination, then stream chunks straight to it.
      let ws: { write: (b: Uint8Array) => Promise<void>; close: () => Promise<void>; abort?: () => Promise<void> } | null = null;
      try {
        const handle = await w.showSaveFilePicker({ suggestedName: name });
        ws = await handle.createWritable();
        ui.phase("Saving");
        let written = 0;
        for await (const chunk of chunks) { await ws.write(chunk); written += chunk.length; ui.progress(written, totalSize); }
        await ws.close();
        return "saved";
      } catch (e) {
        await ws?.abort?.().catch(() => {});
        if (cancelled) return "stopped"; // our Cancel
        if ((e as Error).name === "AbortError") return "stopped"; // the user dismissed the save dialog
        throw e;
      }
    }
    // Fallback (Safari, no File System Access API): assemble a disk-backed Blob, then download via an object URL.
    ui.phase("Decrypting");
    const parts: Blob[] = [];
    let written = 0;
    for await (const chunk of chunks) { parts.push(new Blob([chunk as unknown as BlobPart])); written += chunk.length; ui.progress(written, totalSize); }
    const blob = new Blob(parts, { type: mimeType || "application/octet-stream" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), Math.min(600_000, Math.max(60_000, Math.ceil(blob.size / (1024 * 1024)) * 1000)));
    return "saved";
  } catch (e) {
    if (cancelled) return "stopped";
    throw e;
  }
}

// Load the delivery: passkey -> identity -> fetch + decrypt the metadata prefix -> filename + a save()
// closure. Throws on expired/removed, a passkey failure, or a wrong-key (different passkey) decrypt.
// forceOpen drives the "try a different passkey" recovery (an open prompt instead of the pinned passkey).
export async function loadDelivery(api: DropApi, objectId: string, forceOpen = false): Promise<Delivery> {
  // Passkey FIRST, before any network await. Safari requires the WebAuthn call to run inside the user
  // activation from the Unlock click; an await before it (e.g. fetchUrl) loses that activation and the
  // assertion throws "the document is not focused". Chrome is lenient, Safari is not.
  const { secret, credentialId } = await prfSecret(forceOpen);
  // Zero the PRF secret whether derivation succeeds or throws, so it isn't left live on the error path.
  const identity = await deriveIdentityFromPrf(secret, ns).finally(() => secret.fill(0));
  const { url } = await api.fetchUrl(objectId);
  const headResp = await fetch(url, { headers: { Range: `bytes=0-${METADATA_PREFIX - 1}` } });
  if (!headResp.ok) throw new Error("the file has expired or was already removed"); // 200 or 206 are ok
  const prefix = await readPrefix(headResp, METADATA_PREFIX);
  const { metadata } = await openCiphertext(new Blob([prefix]), identity, NS).catch((e) => {
    // This passkey didn't decrypt the file (wrong identity). Drop any stale pin so the next open
    // re-prompts cleanly instead of silently reusing the wrong passkey, then surface the failure.
    forgetPasskey();
    throw e;
  });
  // The passkey is proven to own this file. NOW pin it so future opens target it directly (no picker).
  rememberPasskey(credentialId);
  const filename = metadata.filename || "file";
  return {
    filename,
    mimeType: metadata.mimeType,
    originalSize: metadata.originalSize,
    entries: parseBundleEntries(metadata.extras),
    save: (ui) => saveToDisk(url, identity, filename, metadata.mimeType, metadata.originalSize, ui),
  };
}
