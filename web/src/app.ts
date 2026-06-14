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
import { ERR, OK, StatusMsg, actionRow, appMsg, hideDropBar, initChrome, inputPrompt, linkReveal, saveCard, showDropBar, uploadCard } from "../fk/ui";
import { decryptCiphertextBlob, encryptFileToShareKey } from "../fk/stream";
import { bundleName, zipBundleToBlob, type BundleItem } from "../fk/bundle";
import { DropApi, DropApiError } from "./api";
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
    uploadCard(file.name, single ? "File" : "Bundle");
    // One status row at a time; `active` always points at the live phase, so a failure
    // (or cancel) acts on the right row instead of leaving a stale "Uploading…" spinner.
    let active = new StatusMsg("Encrypting");
    try {
      const link = decodeDropLink(base64urlDecode(payload));
      const shareKey = new TextDecoder().decode(link.shareKey);
      const sender = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns); // throwaway
      // Streams: read in slices, ciphertext is a Blob-of-Blobs, never fully in RAM (>=64MB off-thread).
      const ciphertext = await encryptFileToShareKey(file, shareKey, NS, sender, {
        onProgress: (d, t) => active.progress(d, t),
        onCancel: (cancel) => active.enableCancel(cancel),
      });
      active.done();
      active = new StatusMsg("Uploading");
      const { objectId, uploadUrl } = await api.uploadInit(payload, ciphertext.size);
      await api.putToR2(uploadUrl, ciphertext);
      await api.uploadComplete(payload, objectId);
      active.done();
      await appMsg([{ t: "Sent!", b: true }, " We emailed them a download link. If you're done, you can close this tab now."], OK);
    } catch (e) {
      if (active.cancelled) { await appMsg(["Upload cancelled."]); return; }
      active.fail();
      await appMsg([humanError(e)], ERR);
    }
  } finally {
    // Re-show the drop bar so they can keep sending without reloading — the Drop link
    // stays valid (capped per day by the Worker). Runs on success, error, and cancel.
    showDropBar("Drop files to send", (next) => void sendFiles(payload, next));
  }
}

// ---- Receive (/d/<id>) ----
async function receiveMode(objectId: string): Promise<void> {
  const st = new StatusMsg("Decrypting your file");
  try {
    const { url } = await api.fetchUrl(objectId);
    const resp = await fetch(url);
    if (!resp.ok) throw new Error("the file has expired or was already removed");
    const ciphertext = await resp.blob(); // disk-backed; not held whole in RAM
    const prf = await getPrfSecret();
    const identity = await deriveIdentityFromPrf(prf, ns);
    prf.fill(0);
    const { blob, metadata } = await decryptCiphertextBlob(ciphertext, identity, NS, { onProgress: (d, t) => st.progress(d, t) });
    st.done();
    await appMsg([{ t: "Decrypted.", b: true }, " Save it wherever you like."], OK);
    saveCard(metadata.filename || "file", "Decrypted file", blob);
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
    { label: "Turn off this link", onClick: () => { if (revoking) return; revoking = true; void doRevoke(token); } },
    { label: "Keep it", muted: true, onClick: () => void (location.href = "/") },
  ]);
}

async function doRevoke(token: string): Promise<void> {
  const st = new StatusMsg("Turning off your link");
  try {
    await api.revoke(token);
    st.fail();
    const host = await appMsg([{ t: "This Drop link is off.", b: true }, " People can no longer send files to it. You can create a new one anytime."], OK);
    actionRow(host, [{ label: "Create a new Drop link", onClick: () => void (location.href = "/") }]);
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
