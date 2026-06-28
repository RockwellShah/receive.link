// UI-agnostic send orchestration, lifted from app.ts (uploadMode/sendFiles/uploadMultipart/uploadPart).
// bundle -> encrypt -> upload (single PUT or concurrent multipart) -> complete. The page provides a
// SendUI to render phases/progress/cancel; the crypto, pool, bundling, and network layers are reused
// untouched. Throws on error (the page humanizes it); returns "cancelled" if the user aborts.
import { type Identity, NamespaceSet, deriveIdentityFromPrf } from "../core/src/index.js";
import { base64urlDecode, decodeDropLink, splitSignature } from "../../shared/codec";
import { importSignPublicKey, verifyRegion } from "../../shared/crypto";
import type { DropApi, UploadInit } from "../src/api";
import { ciphertextLength, encryptFileToParts, encryptFileToShareKey } from "./stream";
import { type BundleItem, bundleName, zipBundleToBlob } from "./bundle";
import { type UploadedPart, uploadPartsPool } from "./pool";

// Same namespace as the app (interop with filekey.app). Tag = SHA-256("filekey.app")[0:4].
const NS = new NamespaceSet(["filekey.app"]);
const ns = NS.namespaces[0]!;

// The page implements this to drive its own UI. phase(label, cancelable) starts a labeled step and
// shows/hides the Cancel button; progress() updates byte progress within it; onCancel() registers the
// cancel handler once (fired when the user hits Cancel during a cancelable phase).
export interface SendUI {
  phase(label: string, cancelable?: boolean): void;
  progress(done: number, total: number): void;
  onCancel(fn: () => void): void;
}

// Verify the share link's server signature and return its label (for "Send files to X"). Throws on a
// bad / tampered / incomplete link.
export async function verifyLink(payload: string, serverSignPublicJwk: JsonWebKey): Promise<{ label: string }> {
  const bytes = base64urlDecode(payload);
  const { signable, signature } = splitSignature(bytes);
  const pub = await importSignPublicKey(serverSignPublicJwk);
  if (!(await verifyRegion(pub, signable, signature))) throw new Error("bad signature");
  return { label: decodeDropLink(bytes).label };
}

// Pack a bundle's file list into a metadata extra ("rl.files") so the receiver can preview the names
// without downloading the whole zip. JSON { n: total count, f: names } with f capped to stay under the
// 64KB extras-value limit; the receiver shows "and (n - f.length) more" when the list was truncated.
function buildBundleExtras(items: BundleItem[]): Map<string, Uint8Array> {
  const enc = new TextEncoder();
  // Truncate any pathological long path so a SINGLE name can't blow the 64KB extras-value limit.
  const names = items.map((i) => (i.path.length > 200 ? i.path.slice(0, 199) + "…" : i.path));
  let f = names.slice(0, 500); // initial cap; the loop halves further if the JSON is still too big
  let json = JSON.stringify({ n: names.length, f });
  while (enc.encode(json).length > 60000 && f.length > 0) {
    f = f.slice(0, Math.floor(f.length / 2)); // halve toward 0 so even one huge entry can't exceed the limit
    json = JSON.stringify({ n: names.length, f });
  }
  return new Map([["rl.files", enc.encode(json)]]);
}

// Largest part-buffer RAM held across all in-flight uploads; concurrency scales down for very large
// parts so peak memory stays ~ C x partSize.
const UPLOAD_RAM_BUDGET = 1024 * 1024 * 1024; // 1 GiB
function uploadConcurrency(partSize: number): number {
  return Math.max(1, Math.min(4, Math.floor(UPLOAD_RAM_BUDGET / partSize)));
}

// A setTimeout that also resolves the instant `signal` aborts, so a cancel during retry backoff doesn't
// wait out the delay.
function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal?.aborted) { resolve(); return; }
    let t: ReturnType<typeof setTimeout>;
    const onAbort = () => { clearTimeout(t); resolve(); };
    t = setTimeout(() => { signal?.removeEventListener("abort", onAbort); resolve(); }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function uploadPart(
  api: DropApi,
  payload: string,
  init: Extract<UploadInit, { mode: "multipart" }>,
  partNumber: number,
  bytes: Uint8Array,
  urls: Map<number, string>,
  opts?: { onProgress?: (sent: number) => void; signal?: AbortSignal },
): Promise<string> {
  let delay = 500;
  for (let attempt = 0; attempt < 5; attempt++) {
    if (opts?.signal?.aborted) throw new Error("aborted"); // cancelled (incl. during backoff)
    let url = urls.get(partNumber);
    if (!url) {
      const batch = await api.uploadParts(payload, init.objectId, partNumber, init.batchSize, opts?.signal);
      for (const p of batch.partUrls) urls.set(p.partNumber, p.url);
      url = urls.get(partNumber);
    }
    if (!url) throw new Error(`no upload URL for part ${partNumber}`);
    opts?.onProgress?.(0); // reset this part's reported progress so a retry doesn't double-count
    try {
      return await api.putPart(url, bytes, opts);
    } catch (e) {
      if (opts?.signal?.aborted) throw e; // user cancelled — don't retry
      urls.delete(partNumber); // force a fresh presign on retry (covers an expired URL)
      if (attempt === 4) throw e;
      await abortableSleep(delay, opts?.signal);
      delay *= 2;
    }
  }
  throw new Error("unreachable");
}

// Stream-encrypt + multipart-upload with up to C parts in flight (C = RAM budget / partSize, max 4).
// The first failure aborts the multipart so R2 keeps no orphaned parts.
async function uploadMultipart(
  api: DropApi,
  payload: string,
  file: File,
  shareKey: string,
  sender: Identity,
  init: Extract<UploadInit, { mode: "multipart" }>,
  ctLen: number,
  ui: SendUI,
  signal: AbortSignal,
  extras?: Map<string, Uint8Array>,
): Promise<UploadedPart[]> {
  const urls = new Map<number, string>(init.partUrls.map((p) => [p.partNumber, p.url] as const));
  let confirmed = 0;
  const live = new Map<number, number>(); // partNumber -> bytes sent so far, for parts still uploading
  const report = () => {
    let sum = confirmed;
    for (const v of live.values()) sum += v;
    ui.progress(Math.min(sum, ctLen), ctLen);
  };
  try {
    return await uploadPartsPool(
      encryptFileToParts(file, shareKey, NS, sender, init.partSize, undefined, extras),
      uploadConcurrency(init.partSize),
      (n, bytes) =>
        uploadPart(api, payload, init, n, bytes, urls, {
          signal,
          onProgress: (sent) => { live.set(n, sent); report(); },
        }).then((etag) => { live.delete(n); confirmed += bytes.length; report(); return etag; }),
    );
  } catch (e) {
    await api.uploadAbort(payload, init.objectId).catch(() => {});
    throw e;
  }
}

// Send the selected items to the link. Returns "sent" or "cancelled"; throws on error.
export async function sendBundle(api: DropApi, payload: string, items: BundleItem[], ui: SendUI): Promise<"sent" | "cancelled"> {
  if (!items.length) return "cancelled";
  const single = items.length === 1 && !items[0]!.fromFolder;
  // For a bundle, embed the file list in the encrypted metadata so the receiver can preview the names
  // without downloading the whole zip (single files don't need it — the filename IS the file).
  const extras = single ? undefined : buildBundleExtras(items);
  // One AbortController + cancel flag for the whole send; phases mark themselves cancelable so the
  // Cancel button shows during Encrypting/Uploading at ANY size, but not the non-abortable steps.
  let cancelled = false;
  const ctrl = new AbortController();
  ui.onCancel(() => { cancelled = true; ctrl.abort(); });
  let file: File;
  if (single) {
    file = items[0]!.file;
  } else {
    // Multiple files / a folder: stream them into one zip (disk-backed), then encrypt that archive as a
    // single .filekey. Decrypt yields the .zip (matches the main app 1:1).
    const total = items.reduce((n, it) => n + it.file.size, 0);
    ui.phase("Bundling");
    const zipBlob = await zipBundleToBlob(items, (b) => ui.progress(b, total));
    file = new File([zipBlob], `${bundleName(items)}.zip`, { type: "application/zip" });
  }
  ui.phase("Preparing");
  const link = decodeDropLink(base64urlDecode(payload));
  const shareKey = new TextDecoder().decode(link.shareKey);
  const sender = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns); // throwaway
  const ctLen = ciphertextLength(file, extras); // MUST pass the same extras we encrypt with, or multipart presizing breaks
  const init = await api.uploadInit(payload, ctLen);
  try {
    if (init.mode === "single") {
      // Small file: encrypt to a (disk-backed) ciphertext Blob, then one PUT. Both are cancelable.
      ui.phase("Encrypting", true);
      const ciphertext = await encryptFileToShareKey(file, shareKey, NS, sender, { onProgress: (d, t) => ui.progress(d, t) }, extras);
      if (ctrl.signal.aborted) return "cancelled"; // cancelled during encrypt — bail before uploading
      ui.phase("Uploading", true);
      await api.putToR2(init.uploadUrl, ciphertext, { signal: ctrl.signal });
      ui.phase("Finishing");
      await api.uploadComplete(payload, init.objectId);
    } else {
      // Large file: stream-encrypt straight into parts and upload them (constant memory).
      ui.phase("Uploading", true);
      const parts = await uploadMultipart(api, payload, file, shareKey, sender, init, ctLen, ui, ctrl.signal, extras);
      ui.phase("Finishing");
      await api.uploadComplete(payload, init.objectId, parts);
    }
    return "sent";
  } catch (e) {
    if (cancelled) return "cancelled";
    throw e;
  }
}
