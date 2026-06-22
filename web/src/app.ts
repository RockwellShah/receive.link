// receive.link web client. Routes four surfaces by path + hash, each played out
// as a FileKey chat conversation using FileKey's own UI machinery (web/fk/ui.ts,
// vendored verbatim):
//   /                  -> Setup (receiver creates a link)
//   /#<linkPayload>    -> Upload (anyone drops a file for the receiver)
//   /confirm#<nonce>   -> Confirm (finish setup, reveal the permanent link)
//   /d/<objectId>      -> Receive (receiver fetches + decrypts a delivered file)
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../core/src/index.js";
import { base64urlDecode, base64urlEncode, decodeDropLink, splitSignature } from "../../shared/codec";
import { importKemPublicKey, importSignPublicKey, sealEmail, verifyRegion } from "../../shared/crypto";
import { ERR, SVG, StatusMsg, actionRow, appMsg, hideDropBar, initChrome, inputPrompt, linkReveal, saveCardWith, saveDecryptedStream, showDropBar, uploadCard } from "../fk/ui";
import { ciphertextLength, encryptFileToParts, encryptFileToShareKey, openCiphertext, openCiphertextSource, streamSource } from "../fk/stream";
import { uploadPartsPool } from "../fk/pool";
import { bundleName, zipBundleToBlob, type BundleItem } from "../fk/bundle";
import { DropApi, DropApiError, type UploadInit } from "./api";
import { dropConfig, ensureConfig, isConfigured } from "./config";
import { checkSupport, enrollPasskey, getPrfSecret, prfBrowserSupport } from "./webauthn";

const NS = new NamespaceSet(["filekey.app"]);
const ns = NS.namespaces[0]!;
let cfg = dropConfig();
let api = new DropApi(cfg.apiBase);

function hexToBytes(s: string): Uint8Array {
  const u = new Uint8Array(s.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return u;
}

function humanError(e: unknown): string {
  if (e instanceof DropApiError) {
    const m = e.message;
    if (/revoked/i.test(m)) return "This link has been turned off. Ask the recipient for a new one.";
    if (/invalid or expired/i.test(m)) return "This confirmation link expired or was already used. Set up again.";
    if (/too large|maxBytes/i.test(m)) return "That file is over the upload limit.";
    if (/rate limited|daily limit|over its daily/i.test(m)) return "Too many requests right now. Please try again later.";
    if (/invalid link|bad signature|not a FileKey/i.test(m)) return "This link isn't valid. Ask the recipient for a fresh one.";
    if (/invalid token|bad token|missing token/i.test(m)) return "This manage link isn't valid. Use the most recent one from a delivery email or your confirmation page.";
    return m;
  }
  const m = e instanceof Error ? e.message : String(e);
  if (/not allowed|timed out|NotAllowed|AbortError|cancel/i.test(m)) return "The passkey prompt was dismissed or timed out. Reload and try again.";
  if (/no PRF|passkey|assertion/i.test(m)) return "Couldn't use your passkey. Make sure you have a receive.link passkey on this device, then reload.";
  if (/auth_failed|wrong_namespace|AEAD/i.test(m)) return "This file was encrypted for a different passkey, so yours can't open it. Make sure you're using the passkey for the link it was sent to.";
  return m;
}

async function requireConfig(): Promise<boolean> {
  if (isConfigured(cfg)) return true;
  await appMsg([{ t: "This build isn't configured yet.", b: true }, " Run gen-keys and fill web/src/config.ts with the server's public keys."], ERR);
  return false;
}

// Derive the PRF secret, pinned to the passkey this browser enrolled (rl_cred) so the authenticator
// uses THAT one instead of offering every receive.link passkey to pick from. When nothing is pinned
// (e.g. a different device opening a download link) it's an open prompt. NO fallback to an open prompt
// on a pinned failure: a different passkey is a DIFFERENT identity, so it can't recover a lost one — it
// would only make a wrong link on setup or fail to decrypt on receive. Surface the error and let the
// user retry instead.
async function prfSecret(): Promise<Uint8Array> {
  let id: Uint8Array | undefined;
  try {
    const stored = localStorage.getItem("rl_cred"); // can throw in storage-blocked / private contexts
    if (stored) id = base64urlDecode(stored);
  } catch { /* no usable pin — fall through to an open prompt */ }
  const { secret, credentialId } = await getPrfSecret(id);
  // Self-heal: if nothing was pinned (an existing browser from before pinning, or a cleared cred),
  // remember whichever passkey the user just used so the next assertion targets it directly — no picker.
  if (!id) { try { localStorage.setItem("rl_cred", base64urlEncode(credentialId)); } catch { /* private mode */ } }
  return secret;
}

// ---- Setup ----
async function setupMode(): Promise<void> {
  await appMsg([
    { t: "Receive files privately.", b: true },
    " Share a link. Anyone can send you files. Only you can open them.",
  ], { speed: 12 });
  await appMsg([
    { t: "Where should we send notifications?", b: true },
    " We'll email you when files arrive. Senders never see your address, and we never store it.",
  ]);
  const { email, label } = await inputPrompt(
    [
      { key: "email", placeholder: "Email", type: "email" },
      { key: "label", placeholder: "Link name (optional)" },
    ],
    (v) => (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email) ? null : "Enter an email address like you@example.com."),
  );
  if (!(await requireConfig())) return;
  // New visitors have no passkey to "use" yet, so create one on this browser's first setup,
  // then derive the identity from it; after that we reuse it. (Opening a download link always
  // uses the existing passkey and never enrolls, so received files stay tied to one key.)
  const firstPasskey = !localStorage.getItem("rl_passkey");
  if (firstPasskey) {
    await appMsg(["Now create your passkey. It's the key that unlocks your files, kept on this device (Face ID, a fingerprint, or a security key). No password, no account."]);
  }
  const st = new StatusMsg("Setting up");
  try {
    if (firstPasskey) {
      const credId = await enrollPasskey(email);
      try {
        localStorage.setItem("rl_passkey", "1");
        localStorage.setItem("rl_cred", base64urlEncode(credId)); // pin future gets to THIS passkey
      } catch { /* private mode: just enroll again next time */ }
    }
    const prf = await prfSecret();
    const identity = await deriveIdentityFromPrf(prf, ns);
    prf.fill(0);
    const shareKey = encodeShareKey(identity.staticPkRaw, identity.namespace);
    const kemPub = await importKemPublicKey(hexToBytes(cfg.serverKemPublicHex));
    const sealed = await sealEmail(kemPub, email);
    await api.register({
      sealedEmail: base64urlEncode(sealed),
      shareKey: base64urlEncode(new TextEncoder().encode(shareKey)),
      label,
    });
    st.fail();
    await appMsg([{ t: "Check your email.", b: true }, ` We sent a confirmation link to ${email}. Click it to finish and get your link. You can close this tab.`]);
  } catch (e) {
    st.fail();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- Confirm ----
async function confirmMode(nonce: string): Promise<void> {
  const st = new StatusMsg("Finishing setup");
  try {
    const { link } = await api.confirm(nonce);
    st.fail();
    await linkReveal(
      [
        { t: "Your private file link is ready.", b: true },
        " Share it with anyone. When someone sends you a file, we'll email you a secure download link. Only you can open the file.",
      ],
      `${location.origin}/#${link}`,
    );
    await appMsg(["We just emailed you this link, plus a private one to turn it off later."]);
  } catch (e) {
    st.fail();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- Upload (the link target) ----
async function uploadMode(payload: string): Promise<void> {
  if (!(await requireConfig())) return;
  let label = "";
  try {
    const bytes = base64urlDecode(payload);
    const { signable, signature } = splitSignature(bytes);
    const pub = await importSignPublicKey(cfg.serverSignPublicJwk!);
    if (!(await verifyRegion(pub, signable, signature))) throw new Error("bad signature");
    label = decodeDropLink(bytes).label;
  } catch {
    await appMsg([{ t: "This link isn't valid.", b: true }, " It may be incomplete or tampered with. Ask the recipient for a fresh link."], ERR);
    return;
  }
  const who = label ? `"${label}"` : "this person";
  await appMsg([`Send files to ${who}.`, " The contents are encrypted so only they can open them."]);
  showDropBar("Drop files to send", (items) => void sendFiles(payload, items));
}

async function sendFiles(payload: string, items: BundleItem[]): Promise<void> {
  if (!items.length) return;
  hideDropBar();
  try {
    const single = items.length === 1 && !items[0]!.fromFolder;
    let file: File;
    if (single) {
      file = items[0]!.file;
    } else {
      // Multiple files / a folder: stream them into one zip (disk-backed, never whole in RAM), then
      // encrypt that archive as a single .filekey. Decrypt yields the .zip (matches the main app 1:1).
      const total = items.reduce((n, it) => n + it.file.size, 0);
      const zip = new StatusMsg("Bundling");
      try {
        const zipBlob = await zipBundleToBlob(items, (b) => zip.progress(b, total));
        file = new File([zipBlob], `${bundleName(items)}.zip`, { type: "application/zip" });
      } catch (e) {
        zip.fail();
        await appMsg([humanError(e)], ERR);
        return;
      }
      zip.done();
    }
    // `active` tracks the live phase so a failure (or cancel) acts on the right status row.
    let active: StatusMsg | undefined;
    try {
      // Show the file + a status the instant the picker closes. Deriving the throwaway sender identity
      // and presigning (uploadInit) take a beat; without this the page sat blank until "Encrypting".
      uploadCard(file.name, single ? "File" : "Bundle");
      active = new StatusMsg("Preparing");
      const link = decodeDropLink(base64urlDecode(payload));
      const shareKey = new TextDecoder().decode(link.shareKey);
      const sender = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns); // throwaway
      const ctLen = ciphertextLength(file);
      const init = await api.uploadInit(payload, ctLen);
      active.done();
      if (init.mode === "single") {
        // Small file: encrypt to a (disk-backed) ciphertext Blob, then one PUT.
        active = new StatusMsg("Encrypting");
        const ciphertext = await encryptFileToShareKey(file, shareKey, NS, sender, {
          onProgress: (d, t) => active!.progress(d, t),
        });
        active.done();
        active = new StatusMsg("Uploading");
        await api.putToR2(init.uploadUrl, ciphertext);
        await api.uploadComplete(payload, init.objectId);
        active.done();
      } else {
        // Large file: stream-encrypt straight into parts and upload them (constant memory).
        active = new StatusMsg("Uploading");
        const parts = await uploadMultipart(payload, file, shareKey, sender, init, ctLen, active);
        active.done();
        // Assembling the parts (R2 CompleteMultipartUpload) + verify + email takes a beat; show it instead
        // of a dead gap between "Uploading... Done!" and "Sent!".
        active = new StatusMsg("Finishing");
        await api.uploadComplete(payload, init.objectId, parts);
        active.done();
      }
      await appMsg([{ t: "Sent!", b: true }, " We emailed them a secure download link. If you're done, you can close this tab now."]);
    } catch (e) {
      if (active?.cancelled) { await appMsg(["Upload cancelled."]); return; }
      active?.fail();
      await appMsg([humanError(e)], ERR);
    }
  } finally {
    // Re-show the drop bar so they can keep sending without reloading — the link
    // stays valid (capped per day by the Worker). Runs on success, error, and cancel.
    showDropBar("Drop files to send", (next) => void sendFiles(payload, next));
  }
}

// Largest amount of part-buffer RAM we hold across all in-flight uploads. Concurrency scales down
// for very large parts (multi-TB files reach ~582 MiB parts) so peak memory stays ~ C x partSize.
const UPLOAD_RAM_BUDGET = 1024 * 1024 * 1024; // 1 GiB
function uploadConcurrency(partSize: number): number {
  return Math.max(1, Math.min(4, Math.floor(UPLOAD_RAM_BUDGET / partSize)));
}

// Stream-encrypt + multipart-upload with up to C parts in flight (C = RAM budget / partSize, max 4).
// Encryption is sequential (the stream is forward-only) but uploads overlap, so the network isn't idle
// while we encrypt and the CPU isn't idle while we upload. The pool (web/fk/pool.ts) holds each part's
// buffer until its ETag (uploadPart retries + re-presigns an expired URL) and caps buffered parts at C
// (memory ~ C x partSize). The first failure aborts the multipart so R2 keeps no orphaned parts.
async function uploadMultipart(
  payload: string,
  file: File,
  shareKey: string,
  sender: Awaited<ReturnType<typeof deriveIdentityFromPrf>>,
  init: Extract<UploadInit, { mode: "multipart" }>,
  ctLen: number,
  status: StatusMsg,
): Promise<{ partNumber: number; etag: string }[]> {
  const urls = new Map<number, string>(init.partUrls.map((p) => [p.partNumber, p.url] as const));
  // Byte-level progress: confirmed (completed parts) + bytes in flight across the concurrent parts, so the
  // readout moves ~every MB instead of jumping a whole part (5 MiB+) at a time. The Cancel button aborts
  // every in-flight part PUT through the shared AbortController.
  const controller = new AbortController();
  status.enableCancel(() => controller.abort());
  let confirmed = 0;
  const live = new Map<number, number>(); // partNumber -> bytes sent so far, for parts still uploading
  const report = () => {
    let sum = confirmed;
    for (const v of live.values()) sum += v;
    status.progress(Math.min(sum, ctLen), ctLen);
  };
  try {
    return await uploadPartsPool(
      encryptFileToParts(file, shareKey, NS, sender, init.partSize),
      uploadConcurrency(init.partSize),
      (n, bytes) =>
        uploadPart(payload, init, n, bytes, urls, {
          signal: controller.signal,
          onProgress: (sent) => { live.set(n, sent); report(); },
        }).then((etag) => { live.delete(n); confirmed += bytes.length; report(); return etag; }),
    );
  } catch (e) {
    await api.uploadAbort(payload, init.objectId).catch(() => {});
    throw e;
  }
}

// A setTimeout that also resolves the instant `signal` aborts, so a cancel during retry backoff doesn't
// have to wait out the delay.
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
  payload: string,
  init: Extract<UploadInit, { mode: "multipart" }>,
  partNumber: number,
  bytes: Uint8Array,
  urls: Map<number, string>,
  opts?: { onProgress?: (sent: number) => void; signal?: AbortSignal },
): Promise<string> {
  let delay = 500;
  for (let attempt = 0; attempt < 5; attempt++) {
    if (opts?.signal?.aborted) throw new Error("aborted"); // cancelled (incl. during backoff) — stop before re-presigning
    let url = urls.get(partNumber);
    if (!url) {
      const batch = await api.uploadParts(payload, init.objectId, partNumber, init.batchSize, opts?.signal);
      for (const p of batch.partUrls) urls.set(p.partNumber, p.url);
      url = urls.get(partNumber);
    }
    if (!url) throw new Error(`no upload URL for part ${partNumber}`);
    opts?.onProgress?.(0); // reset this part's reported progress so a retry doesn't leave stale bytes counted
    try {
      return await api.putPart(url, bytes, opts);
    } catch (e) {
      if (opts?.signal?.aborted) throw e; // user cancelled — don't retry
      urls.delete(partNumber); // force a fresh presign on retry (covers an expired URL)
      if (attempt === 4) throw e;
      await abortableSleep(delay, opts?.signal); // wake immediately if cancelled mid-backoff
      delay *= 2;
    }
  }
  throw new Error("unreachable");
}

// ---- Receive (/d/<id>) ----
// Enough of the ciphertext to cover the fixed head + the metadata (<= ~1 MiB), fetched as a Range
// request so we can show the filename without downloading the whole file.
const METADATA_PREFIX = 1_200_000;

// Read at most `max` bytes from a response body, then cancel the rest — so opening a link to read just
// the metadata never downloads the whole file, even if the server ignored our Range request (200).
async function readPrefix(resp: Response, max: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!resp.body) return new Uint8Array(await resp.arrayBuffer()).subarray(0, max);
  const reader = resp.body.getReader();
  const parts: Uint8Array[] = [];
  let len = 0;
  try {
    while (len < max) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value && value.length) {
        parts.push(value);
        len += value.length;
      }
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

async function receiveMode(objectId: string): Promise<void> {
  const st = new StatusMsg("Opening your file");
  try {
    const { url } = await api.fetchUrl(objectId);
    const prf = await prfSecret();
    const identity = await deriveIdentityFromPrf(prf, ns);
    prf.fill(0);
    // Metadata only: fetch just the head + metadata prefix (a Range request) and decrypt it for the
    // filename. The full payload streams to disk on Save (below), so the whole ciphertext is never
    // buffered — true 1x disk, which is what makes receiving a multi-TB file feasible.
    const headResp = await fetch(url, { headers: { Range: `bytes=0-${METADATA_PREFIX - 1}` } });
    if (!headResp.ok) throw new Error("the file has expired or was already removed"); // 200 or 206 are ok
    // Read only the prefix + cancel: even if the server ignored Range (200), we never download the
    // whole ciphertext just to read the filename.
    const { metadata } = await openCiphertext(new Blob([await readPrefix(headResp, METADATA_PREFIX)]), identity, NS);
    st.done();
    await appMsg([{ t: "Ready to save.", b: true }, " It's encrypted to you, and the file itself only decrypts on your device when you save it."]);
    if (!(window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker && metadata.originalSize > 2 * 1024 * 1024 * 1024) {
      await appMsg(["For a file this large, Chrome or Edge can save it more reliably than this browser."]);
    }
    const filename = metadata.filename || "file";
    let saving = false;
    saveCardWith(filename, "Decrypted file", async () => {
      if (saving) return; // one save at a time; ignore double-clicks
      saving = true;
      const controller = new AbortController(); // the Save's Cancel button aborts this download
      try {
        // Stream the full ciphertext straight to disk (1x disk): fetch -> ReadableStream -> decrypt ->
        // write, never buffering the whole file. A fresh fetch per click is naturally re-startable, so a
        // failed/cancelled/double-clicked save just starts clean.
        const resp = await fetch(url, { signal: controller.signal });
        if (!resp.ok || !resp.body) throw new Error("the file has expired or was already removed");
        const size = Number(resp.headers.get("content-length"));
        if (!Number.isFinite(size) || size <= 0) throw new Error("couldn't read the file size");
        const { chunks } = await openCiphertextSource(streamSource(resp.body, size), identity, NS);
        await saveDecryptedStream(filename, metadata.mimeType, metadata.originalSize, chunks, () => controller.abort());
      } catch (e) {
        if (controller.signal.aborted) return; // user cancelled the download — already handled
        await appMsg([humanError(e)], ERR);
      } finally {
        saving = false;
      }
    });
  } catch (e) {
    st.fail();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- Revoke (/revoke#<token>) ----
async function revokeMode(token: string): Promise<void> {
  if (!token) {
    await appMsg([{ t: "This manage link isn't valid.", b: true }, " Use the link from your confirmation page or a delivery email."], ERR);
    return;
  }
  let revoking = false;
  const host = await appMsg([
    { t: "Turn off this link?", b: true },
    " People with the old link won't be able to send you files anymore. Download links already emailed to you still work until they expire.",
  ]);
  actionRow(host, [
    { label: "Turn off this link", icon: SVG.trash.replace("<svg", '<svg class="act_icon"'), onClick: () => { if (revoking) return; revoking = true; void doRevoke(token); } },
    { label: "Keep it", muted: true, icon: SVG.close.replace("<svg", '<svg class="act_icon"'), onClick: () => void (location.href = "/") },
  ]);
}

async function doRevoke(token: string): Promise<void> {
  const st = new StatusMsg("Turning off your link");
  try {
    await api.revoke(token);
    st.fail();
    const host = await appMsg([{ t: "This link is off.", b: true }, " People can no longer send files to it. You can create a new one anytime."]);
    actionRow(host, [{ label: "Create a new link", icon: SVG.plus.replace("<svg", '<svg class="act_icon act_fill"'), onClick: () => void (location.href = "/") }]);
  } catch (e) {
    st.fail();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- QR (/qr#<link>): a public page that shows this link as a scannable QR (linked from the email) ----
async function qrMode(payload: string): Promise<void> {
  if (!payload) {
    await appMsg([{ t: "Nothing to show.", b: true }, " This QR link is incomplete. Use the one from your email."], ERR);
    return;
  }
  if (!(await requireConfig())) return;
  // Validate the link (same decode + signature check as the upload page) before showing it as a QR, so a
  // tampered or truncated link is caught here, not only when a sender scans it.
  try {
    const bytes = base64urlDecode(payload);
    const { signable, signature } = splitSignature(bytes);
    const pub = await importSignPublicKey(cfg.serverSignPublicJwk!);
    if (!(await verifyRegion(pub, signable, signature))) throw new Error("bad signature");
  } catch {
    await appMsg([{ t: "This link isn't valid.", b: true }, " It may be incomplete or tampered with. Use the most recent one from your email."], ERR);
    return;
  }
  const qrShown = await linkReveal(
    [
      { t: "Your link.", b: true },
      " Share it with anyone, or have them scan the QR. Only you can open what they send.",
    ],
    `${location.origin}/#${payload}`,
    { qrOpen: true },
  );
  if (!qrShown) {
    await appMsg([{ t: "Couldn't show the QR.", b: true }, " Your link is above — copy it or use Share instead."], ERR);
  }
}

// Build-time app version (Bun.build define, sourced from package.json), stamped into the menu footer.
declare const __APP_VERSION__: string;

// ---- route ----
void (async () => {
  initChrome();
  const verEl = document.querySelector(".menu_version");
  if (verEl) verEl.textContent = `v${__APP_VERSION__}`;
  cfg = await ensureConfig(); // in dev, fetches the mock server's keys so they match
  api = new DropApi(cfg.apiBase);

  // Only the receiver's flows need a passkey (WebAuthn PRF): creating a link (setup) and
  // decrypting a delivered file (receive). SENDERS use a throwaway identity, and confirm/revoke are
  // nonce/token based — so we gate ONLY those two flows, and fail loudly there instead of cryptically.
  // (Gating everything would wrongly block senders on browsers that can encrypt but lack PRF.)
  const gated = async (fn: () => void): Promise<void> => {
    const s = checkSupport();
    if (!s.secureContext || !s.webauthn) {
      await appMsg([{ t: "This browser can't open receive.link.", b: true }, " It needs passkeys (WebAuthn) over HTTPS - try a recent Chrome, Edge, or Safari."], ERR);
      return;
    }
    if ((await prfBrowserSupport()) === false) {
      await appMsg([{ t: "This browser is missing a passkey feature receive.link needs (PRF).", b: true }, " Try the latest Chrome, Edge, or Safari."], ERR);
      return;
    }
    fn();
  };

  const path = location.pathname;
  const hash = location.hash.replace(/^#/, "");
  if (path === "/confirm") void confirmMode(hash); // nonce exchange — no passkey
  else if (path === "/revoke") void revokeMode(hash); // token — no passkey
  else if (path === "/qr") void qrMode(hash); // show this link as a QR (no passkey)
  else if (path.startsWith("/d/")) void gated(() => void receiveMode(path.slice("/d/".length))); // decrypt — needs PRF
  else if (hash.length > 0) void uploadMode(hash); // sender — throwaway identity, no passkey
  else void gated(() => void setupMode()); // create a link — needs PRF
})();
