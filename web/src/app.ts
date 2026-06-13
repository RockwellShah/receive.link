// FileKey Drop — web client. One bundle routes four surfaces by path + hash, each
// played out as a FileKey-style chat conversation (typed messages with the lock
// avatar, inline links, the bottom drop bar):
//   /                  -> Setup (receiver creates a Drop link)
//   /#<linkPayload>    -> Upload (anyone drops a file for the receiver)
//   /confirm#<nonce>   -> Confirm (finish setup, reveal the permanent link)
//   /d/<objectId>      -> Receive (receiver fetches + decrypts a delivered file)
import { NamespaceSet, decrypt, deriveIdentityFromPrf, encodeShareKey, encryptToShareKey } from "../core/src/index.js";
import { base64urlDecode, base64urlEncode, decodeDropLink, splitSignature } from "../../shared/codec";
import { importKemPublicKey, importSignPublicKey, sealEmail, verifyRegion } from "../../shared/crypto";
import { DropApi, DropApiError } from "./api";
import { appMsg, hideDropBar, initChrome, inputPrompt, linkReveal, showDropBar, statusMsg } from "./chat";
import { dropConfig, isConfigured } from "./config";
import { getPrfSecret } from "./webauthn";

const NS = new NamespaceSet(["filekey.app"]);
const ns = NS.namespaces[0]!;
const cfg = dropConfig();
const api = new DropApi(cfg.apiBase);

const ERR = { speed: 4, dp: "failed_dp", icon: "failed_filekey_icon" };
const OK = { dp: "ok_dp", icon: "ok_filekey_icon" };

function hexToBytes(s: string): Uint8Array {
  const u = new Uint8Array(s.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return u;
}

function humanError(e: unknown): string {
  if (e instanceof DropApiError) return e.message;
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
    { t: "Get files, end-to-end encrypted.", b: true },
    " Create a link people can use to send you files. Only your passkey can open them, and we never see your files or store your address.",
  ]);
  await appMsg(["First, what email should we deliver your files to?"]);
  const { email, label } = await inputPrompt([
    { key: "email", placeholder: "you@example.com", type: "email" },
    { key: "label", placeholder: "A label senders will see (optional)" },
  ]);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    await appMsg(["That email doesn't look right. Reload the page to try again."], ERR);
    return;
  }
  if (!(await requireConfig())) return;
  const st = statusMsg("Setting up");
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
    st.remove();
    await appMsg([{ t: "Check your email.", b: true }, ` We sent a confirmation link to ${email}. Click it to finish and get your Drop link.`]);
    await appMsg(["You can close this tab. The link works on any device."]);
  } catch (e) {
    st.remove();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- Confirm ----
async function confirmMode(nonce: string): Promise<void> {
  const st = statusMsg("Finishing setup");
  try {
    const { link } = await api.confirm(nonce);
    st.remove();
    await appMsg([{ t: "Your Drop link is ready.", b: true }, " Share it with anyone. Whatever they drop arrives encrypted to your passkey, in your inbox."]);
    linkReveal(`${location.origin}/#${link}`);
    await appMsg(["Save it somewhere. If you lose it, just set up again."]);
  } catch (e) {
    st.remove();
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
  await appMsg([`Send a file to ${who}.`, " It's encrypted to their key in your browser before it leaves. Only they can open it."]);
  showDropBar("Drop a file to send", (f) => void sendFile(payload, f));
}

async function sendFile(payload: string, file: File): Promise<void> {
  hideDropBar();
  const st = statusMsg(`Encrypting ${file.name}`);
  try {
    const link = decodeDropLink(base64urlDecode(payload));
    const shareKey = new TextDecoder().decode(link.shareKey);
    const sender = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), ns); // throwaway
    const plaintext = new Uint8Array(await file.arrayBuffer());
    const ciphertext = await encryptToShareKey({
      senderIdentity: sender,
      recipientShareKey: shareKey,
      namespaces: NS,
      plaintext,
      metadata: { filename: file.name, mimeType: file.type || "application/octet-stream", createdAtUnixMs: 0, extras: new Map() },
    });
    st.done(`Uploading ${file.name}…`);
    const { objectId, uploadUrl } = await api.uploadInit(payload, ciphertext.length);
    await api.putToR2(uploadUrl, ciphertext);
    await api.uploadComplete(payload, objectId);
    st.remove();
    await appMsg([{ t: "Sent.", b: true }, " They'll get an email with a link to open it. Thanks!"], OK);
  } catch (e) {
    st.remove();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- Receive (/d/<id>) ----
async function receiveMode(objectId: string): Promise<void> {
  const st = statusMsg("Opening your file");
  try {
    const { url } = await api.fetchUrl(objectId);
    const resp = await fetch(url);
    if (!resp.ok) throw new Error("the file has expired or was already removed");
    const ciphertext = new Uint8Array(await resp.arrayBuffer());
    st.done("Waiting for your passkey…");
    const prf = await getPrfSecret();
    const identity = await deriveIdentityFromPrf(prf, ns);
    prf.fill(0);
    const res = await decrypt({ file: ciphertext, namespaces: NS, resolveIdentity: async () => identity });
    st.remove();
    const blob = new Blob([res.plaintext as BufferSource], { type: res.metadata.mimeType || "application/octet-stream" });
    const msg = await appMsg([{ t: "Decrypted.", b: true }, ` ${res.metadata.filename} is ready, decrypted on your device. `]);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = res.metadata.filename || "file";
    a.className = "msg_clickable no_select";
    a.textContent = "Save file";
    msg.appendChild(a);
  } catch (e) {
    st.remove();
    await appMsg([humanError(e)], ERR);
  }
}

// ---- route ----
initChrome();
const path = location.pathname;
const hash = location.hash.replace(/^#/, "");
if (path === "/confirm") void confirmMode(hash);
else if (path.startsWith("/d/")) void receiveMode(path.slice("/d/".length));
else if (hash.length > 0) void uploadMode(hash);
else void setupMode();
