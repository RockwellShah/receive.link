// FileKey Drop — web client. Routes four surfaces by path + hash, each played out
// as a FileKey chat conversation using FileKey's own UI machinery (web/fk/ui.ts,
// vendored verbatim):
//   /                  -> Setup (receiver creates a Drop link)
//   /#<linkPayload>    -> Upload (anyone drops a file for the receiver)
//   /confirm#<nonce>   -> Confirm (finish setup, reveal the permanent link)
//   /d/<objectId>      -> Receive (receiver fetches + decrypts a delivered file)
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../core/src/index.js";
import { base64urlDecode, base64urlEncode, decodeDropLink, splitSignature } from "../../shared/codec";
import { importKemPublicKey, importSignPublicKey, sealEmail, verifyRegion } from "../../shared/crypto";
import { ERR, OK, SVG, StatusMsg, actionRow, appMsg, hideDropBar, initChrome, inputPrompt, linkReveal, saveCardWith, saveDecryptedStream, showDropBar, uploadCard } from "../fk/ui";
import { ciphertextLength, encryptFileToParts, encryptFileToShareKey, openCiphertext } from "../fk/stream";
import { bundleName, zipBundleToBlob, type BundleItem } from "../fk/bundle";
import { DropApi, DropApiError, type UploadInit } from "./api";
import { dropConfig, ensureConfig, isConfigured } from "./config";
import { getPrfSecret } from "./webauthn";

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
    if (/revoked/i.test(m)) return "This Drop link has been turned off. Ask the recipient for a new one.";
    if (/invalid or expired/i.test(m)) return "This confirmation link expired or was already used. Set up again.";
    if (/too large|maxBytes/i.test(m)) return "That file is over the upload limit.";
    if (/rate limited|daily limit|over its daily/i.test(m)) return "Too many requests right now. Please try again later.";
    if (/invalid link|bad signature|not a FileKey/i.test(m)) return "This link isn't valid. Ask the recipient for a fresh one.";
    if (/invalid token|bad token|missing token/i.test(m)) return "This manage link isn't valid. Use the most recent one from a delivery email or your confirmation page.";
    return m;
  }
  const m = e instanceof Error ? e.message : String(e);
  if (/no PRF|passkey|assertion/i.test(m)) return "Couldn't use your passkey. Make sure you have a FileKey passkey on this device, then reload.";
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
    { t: "Create a link people can use to send you files.", b: true },
    " Only your passkey can open them, and we never see your files or store your email address.",
  ], { speed: 12 });
  await appMsg(["First, what email should we send your file links to? We email a link to each file, never the file itself."]);
  const { email, label } = await inputPrompt(
    [
      { key: "email", placeholder: "you@example.com", type: "email" },
      { key: "label", placeholder: "A label senders will see (optional)" },
    ],
    (v) => (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email) ? null : "Enter an email address like you@example.com."),
  );
  if (!(await requireConfig())) return;
  const st = new StatusMsg("Setting up");
  try {
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
    await appMsg([{ t: "Check your email.", b: true }, ` We sent a confirmation link to ${email}. Click it to finish and get your Drop link.`]);
    await appMsg(["You can close this tab. After you confirm, your Drop link can be shared from any device."]);
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
      "Your Drop link is ready. Share it with anyone, and we'll email you a download link whenever someone sends a file. The file stays encrypted until you open it with your passkey:",
      `${location.origin}/#${link}`,
    );
    await appMsg(["Save it somewhere. If you lose it, just set up again."]);
  } catch (e) {
    st.fail();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- Upload (the Drop link target) ----
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
  const who = label ? `"${label}"` : "this FileKey user";
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
          onCancel: (cancel) => active!.enableCancel(cancel),
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
      await appMsg([{ t: "Sent!", b: true }, " We emailed them a download link. If you're done, you can close this tab now."], OK);
    } catch (e) {
      if (active?.cancelled) { await appMsg(["Upload cancelled."]); return; }
      active?.fail();
      await appMsg([humanError(e)], ERR);
    }
  } finally {
    // Re-show the drop bar so they can keep sending without reloading — the Drop link
    // stays valid (capped per day by the Worker). Runs on success, error, and cancel.
    showDropBar("Drop files to send", (next) => void sendFiles(payload, next));
  }
}

// Stream-encrypt + multipart-upload a file one part at a time (constant memory). Per-part retry
// re-presigns the URL (covers a part URL expiring mid long upload); a failure aborts the multipart
// so R2 keeps no orphaned parts.
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
  const parts: { partNumber: number; etag: string }[] = [];
  let uploaded = 0;
  let partNumber = 1;
  try {
    for await (const partBytes of encryptFileToParts(file, shareKey, NS, sender, init.partSize)) {
      parts.push({ partNumber, etag: await uploadPart(payload, init, partNumber, partBytes, urls) });
      uploaded += partBytes.length;
      status.progress(uploaded, ctLen);
      partNumber++;
    }
    return parts;
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
async function receiveMode(objectId: string): Promise<void> {
  const st = new StatusMsg("Opening your file");
  try {
    const { url } = await api.fetchUrl(objectId);
    const resp = await fetch(url);
    if (!resp.ok) throw new Error("the file has expired or was already removed");
    const ciphertext = await resp.blob(); // disk-backed; not held whole in RAM
    const prf = await getPrfSecret();
    const identity = await deriveIdentityFromPrf(prf, ns);
    prf.fill(0);
    // Reads the head + metadata (small, authenticated); the payload stays lazy until Save, so it
    // streams straight to disk instead of staging the whole plaintext (1x disk for huge files).
    const { metadata, chunks } = await openCiphertext(ciphertext, identity, NS);
    st.done();
    await appMsg([{ t: "Ready to save.", b: true }, " It's encrypted to you and decrypts on your device as you save it."], OK);
    if (!(window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker && metadata.originalSize > 2 * 1024 * 1024 * 1024) {
      await appMsg(["For a file this large, Chrome or Edge can save it more reliably than this browser."]);
    }
    saveCardWith(metadata.filename || "file", "Decrypted file", () =>
      void saveDecryptedStream(metadata.filename || "file", metadata.mimeType, metadata.originalSize, chunks),
    );
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
    { t: "Turn off this Drop link?", b: true },
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
    const host = await appMsg([{ t: "This Drop link is off.", b: true }, " People can no longer send files to it. You can create a new one anytime."], OK);
    actionRow(host, [{ label: "Create a new Drop link", icon: SVG.plus.replace("<svg", '<svg class="act_icon act_fill"'), onClick: () => void (location.href = "/") }]);
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
  const path = location.pathname;
  const hash = location.hash.replace(/^#/, "");
  if (path === "/confirm") void confirmMode(hash);
  else if (path === "/revoke") void revokeMode(hash);
  else if (path.startsWith("/d/")) void receiveMode(path.slice("/d/".length));
  else if (hash.length > 0) void uploadMode(hash);
  else void setupMode();
})();
