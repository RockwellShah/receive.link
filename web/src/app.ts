// receive.link web client. Routes four surfaces by path + hash, each played out
// as a FileKey chat conversation using FileKey's own UI machinery (web/fk/ui.ts,
// vendored verbatim):
//   /                  -> Setup (receiver creates a link)
//   /#<linkPayload>    -> Upload (anyone drops a file for the receiver)
//   /confirm#<nonce>   -> Confirm (finish setup, reveal the permanent link)
//   /d/<objectId>      -> Receive (receiver fetches + decrypts a delivered file)
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../core/src/index.js";
import { base64urlDecode, base64urlEncode, decodeDropLink, splitSignature } from "../../shared/codec";
import { FETCH_CHALLENGE_INFO, fetchProofHex, hpkeUnseal, importKemPublicKey, importSignPublicKey, sealEmail, verifyRegion } from "../../shared/crypto";
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
    if (/inbox is full|over capacity/i.test(m)) return "This inbox is full right now. The recipient has been notified.";
    if (/rate limited|daily limit|over its daily/i.test(m)) return "Too many requests right now. Please try again later.";
    if (/invalid link|bad signature|not a FileKey/i.test(m)) return "This link isn't valid. Ask the recipient for a fresh one.";
    if (/invalid token|bad token|missing token/i.test(m)) return "This manage link isn't valid. Use the most recent one from a delivery email or your confirmation page.";
    return m;
  }
  const m = e instanceof Error ? e.message : String(e);
  if (/not allowed|timed out|NotAllowed|AbortError|cancel/i.test(m)) return "The passkey prompt was dismissed or timed out. Reload and try again.";
  if (/no PRF|passkey|assertion/i.test(m)) return "Couldn't use your passkey. Make sure you have a receive.link passkey on this device, then reload.";
  if (/auth_failed|wrong_namespace/i.test(m)) return "This file couldn't be decrypted. It may be corrupted, or not encrypted for you.";
  return m;
}

async function requireConfig(): Promise<boolean> {
  if (isConfigured(cfg)) return true;
  await appMsg([{ t: "This build isn't configured yet.", b: true }, " Run gen-keys and fill web/src/config.ts with the server's public keys."], ERR);
  return false;
}

// ---- Setup ----
async function setupMode(): Promise<void> {
  await appMsg([
    { t: "Receive files privately.", b: true },
    " Share a link. Anyone can send you files. Only you can open them.",
  ], { speed: 12 });
  await appMsg([
    { t: "Where should we send notifications?", b: true },
    " We email you a secure link when files arrive. Your email address is never stored.",
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
      await enrollPasskey(email);
      try { localStorage.setItem("rl_passkey", "1"); } catch { /* private mode: just enroll again next time */ }
    }
    const prf = await getPrfSecret();
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
      const link = decodeDropLink(base64urlDecode(payload));
      const shareKey = new TextDecoder().decode(link.shareKey);
      const sender = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns); // throwaway
      const ctLen = ciphertextLength(file);
      const init = await api.uploadInit(payload, ctLen);
      uploadCard(file.name, single ? "File" : "Bundle");
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
        await api.uploadComplete(payload, init.objectId, parts);
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
  let confirmed = 0;
  try {
    return await uploadPartsPool(
      encryptFileToParts(file, shareKey, NS, sender, init.partSize),
      uploadConcurrency(init.partSize),
      (n, bytes) => uploadPart(payload, init, n, bytes, urls),
      (bytes) => {
        confirmed += bytes;
        status.progress(confirmed, ctLen);
      },
    );
  } catch (e) {
    await api.uploadAbort(payload, init.objectId).catch(() => {});
    throw e;
  }
}

async function uploadPart(
  payload: string,
  init: Extract<UploadInit, { mode: "multipart" }>,
  partNumber: number,
  bytes: Uint8Array,
  urls: Map<number, string>,
): Promise<string> {
  let delay = 500;
  for (let attempt = 0; attempt < 5; attempt++) {
    let url = urls.get(partNumber);
    if (!url) {
      const batch = await api.uploadParts(payload, init.objectId, partNumber, init.batchSize);
      for (const p of batch.partUrls) urls.set(p.partNumber, p.url);
      url = urls.get(partNumber);
    }
    if (!url) throw new Error(`no upload URL for part ${partNumber}`);
    try {
      return await api.putPart(url, bytes);
    } catch (e) {
      urls.delete(partNumber); // force a fresh presign on retry (covers an expired URL)
      if (attempt === 4) throw e;
      await new Promise((r) => setTimeout(r, delay));
      delay *= 2;
    }
  }
  throw new Error("unreachable");
}

// ---- Receive (/d/<id>) ----
// Download gate: prove the passkey holder is the one downloading. Request a challenge (a nonce the Worker
// sealed to the receiver's share key), unseal it with the identity, and derive the proof. Each outcome
// (free preview, charged download) consumes its own single-use challenge; both reuse the in-memory
// identity, so neither the preview nor a re-proven Save triggers a second passkey prompt.
type Identity = Awaited<ReturnType<typeof deriveIdentityFromPrf>>;
async function proveFetch(objectId: string, identity: Identity): Promise<{ challengeId: string; proof: string }> {
  const { challengeId, sealed } = await api.fetchChallenge(objectId);
  const nonce = await hpkeUnseal(identity.keyPair, base64urlDecode(sealed), FETCH_CHALLENGE_INFO);
  const proof = await fetchProofHex(challengeId, objectId, nonce);
  return { challengeId, proof };
}
/** Free preview: the head + metadata bytes (the Worker serves them directly; no payload, no charge). */
async function fetchMetaPrefix(objectId: string, identity: Identity): Promise<Uint8Array<ArrayBuffer>> {
  const { challengeId, proof } = await proveFetch(objectId, identity);
  return api.fetchPreview(challengeId, proof);
}
/** Charged download: a short-lived URL for the full ciphertext, or a needs-funds signal. */
async function fetchDownloadUrl(objectId: string, identity: Identity) {
  const { challengeId, proof } = await proveFetch(objectId, identity);
  return api.fetchDownload(challengeId, proof);
}

async function receiveMode(objectId: string): Promise<void> {
  const st = new StatusMsg("Opening your file");
  try {
    // Derive the identity FIRST (one passkey prompt), then prove possession to the gate — only the passkey
    // holder can unseal the gate's challenge, so a stranger with the link can't even see the filename.
    const prf = await getPrfSecret();
    const identity = await deriveIdentityFromPrf(prf, ns);
    prf.fill(0);
    // Free preview: the Worker serves just the head + metadata (never the payload, no charge), so we can
    // show the filename before the receiver commits to (and pays for) the download. The full payload
    // streams to disk on Save (below), so the whole ciphertext is never buffered — true 1x disk.
    const { metadata } = await openCiphertext(new Blob([await fetchMetaPrefix(objectId, identity)]), identity, NS);
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
      try {
        // Re-prove on Save (reuses the in-memory identity, so no second passkey prompt) and request the
        // charged download. Out of credit -> prompt to top up (re-clickable once funded; Stripe wires in
        // Phase 2b). Otherwise stream the full ciphertext straight to disk (1x disk): fetch -> decrypt ->
        // write, never buffering the whole file. A fresh prove+fetch per click is naturally re-startable.
        const got = await fetchDownloadUrl(objectId, identity);
        if ("needsFunds" in got) {
          await appMsg([{ t: "Add credit to unlock this download.", b: true }, " You're out of download credit for this file."], ERR);
          return;
        }
        const resp = await fetch(got.url);
        if (!resp.ok || !resp.body) throw new Error("the file has expired or was already removed");
        const size = Number(resp.headers.get("content-length"));
        if (!Number.isFinite(size) || size <= 0) throw new Error("couldn't read the file size");
        const { chunks } = await openCiphertextSource(streamSource(resp.body, size), identity, NS);
        await saveDecryptedStream(filename, metadata.mimeType, metadata.originalSize, chunks);
      } catch (e) {
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

// ---- route ----
void (async () => {
  initChrome();
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
  else if (path.startsWith("/d/")) void gated(() => void receiveMode(path.slice("/d/".length))); // decrypt — needs PRF
  else if (hash.length > 0) void uploadMode(hash); // sender — throwaway identity, no passkey
  else void gated(() => void setupMode()); // create a link — needs PRF
})();
