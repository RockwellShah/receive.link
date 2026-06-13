// FileKey Drop — web client. One bundle routes four surfaces by path + hash:
//   /                  -> Setup (receiver creates a Drop link)
//   /#<linkPayload>    -> Upload (anyone drops a file for the receiver)
//   /confirm#<nonce>   -> Confirm (finish setup, reveal the permanent link)
//   /d/<objectId>      -> Receive (receiver fetches + decrypts a delivered file)
//
// Crypto is the vendored FileKey core (file encryption) + shared/ (link + email).
// The sender needs no passkey; the receiver uses theirs only at setup + receive.
import { NamespaceSet, decrypt, deriveIdentityFromPrf, encodeShareKey, encryptToShareKey } from "../core/src/index.js";
import { base64urlDecode, base64urlEncode, decodeDropLink, splitSignature } from "../../shared/codec";
import { importKemPublicKey, importSignPublicKey, sealEmail, verifyRegion } from "../../shared/crypto";
import { DropApi, DropApiError } from "./api";
import { dropConfig, isConfigured, type DropConfig } from "./config";
import { card, clear, el, field, ghostButton, h, monoBox, note, p, primaryButton, spinner, textInput } from "./ui";
import { getPrfSecret } from "./webauthn";

const NS = new NamespaceSet(["filekey.app"]);
const ns = NS.namespaces[0]!;
const cfg = dropConfig();
const api = new DropApi(cfg.apiBase);
const root = () => document.getElementById("app")!;

function hexToBytes(s: string): Uint8Array {
  const u = new Uint8Array(s.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return u;
}

function show(...children: (Node | string)[]): void {
  const r = root();
  clear(r);
  r.append(card(children));
}

function configGuard(): boolean {
  if (isConfigured(cfg)) return true;
  show(h("Not configured yet"), note("This build has no server keys pinned. Run gen-keys and fill web/src/config.ts.", "error"));
  return false;
}

// ---- Setup ----------------------------------------------------------------

function setupMode(): void {
  const email = textInput({ type: "email", placeholder: "you@example.com", autocomplete: "email" });
  const label = textInput({ type: "text", placeholder: "Tax inbox (optional)", maxlength: "64" });
  const msg = el("div");
  const submit = primaryButton("Create my Drop link", () => void doSetup());

  async function doSetup(): Promise<void> {
    const addr = email.value.trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr)) {
      clear(msg);
      msg.append(note("Enter a valid email address.", "error"));
      return;
    }
    if (!configGuard()) return;
    clear(msg);
    msg.append(spinner("Waiting for your passkey…"));
    try {
      const prf = await getPrfSecret();
      const identity = await deriveIdentityFromPrf(prf, ns);
      prf.fill(0);
      const shareKey = encodeShareKey(identity.staticPkRaw, identity.namespace); // fkey1…
      const kemPub = await importKemPublicKey(hexToBytes(cfg.serverKemPublicHex));
      const sealed = await sealEmail(kemPub, addr);
      clear(msg);
      msg.append(spinner("Sending you a confirmation email…"));
      await api.register({
        sealedEmail: base64urlEncode(sealed),
        shareKey: base64urlEncode(new TextEncoder().encode(shareKey)),
        label: label.value.trim(),
      });
      show(
        h("Check your email"),
        p(`We sent a confirmation link to ${addr}. Click it to finish and get your permanent Drop link.`),
        p("You can close this tab. The link works on any device.", "muted small"),
      );
    } catch (e) {
      clear(msg);
      msg.append(note(humanError(e), "error"));
      msg.append(el("div", { class: "row" }, [submit]));
    }
  }

  show(
    h("Get files, end-to-end encrypted"),
    p("Create a link people can use to send you files. Only your passkey can open them. We never see your files, and we don't store your address."),
    field("Your email", email),
    field("Label senders will see", label),
    el("div", { class: "row" }, [submit]),
    msg,
  );
}

// ---- Confirm --------------------------------------------------------------

async function confirmMode(nonce: string): Promise<void> {
  show(h("Finishing setup"), spinner("Confirming…"));
  try {
    const { link } = await api.confirm(nonce);
    const url = `${location.origin}/#${link}`;
    const copy = primaryButton("Copy link", () => void navigator.clipboard?.writeText(url));
    show(
      h("Your Drop link is ready"),
      p("Share this link with anyone. Whatever they drop arrives encrypted to your passkey, in your inbox."),
      monoBox(url),
      el("div", { class: "row" }, [copy]),
      p("Save it somewhere. If you lose it, just set up again.", "muted small"),
    );
  } catch (e) {
    show(h("That link didn't work"), note(humanError(e), "error"), p("Confirmation links expire after an hour. Set up again to get a new one.", "muted small"));
  }
}

// ---- Upload (the Drop link target) ----------------------------------------

async function uploadMode(payload: string): Promise<void> {
  if (!configGuard()) return;
  let label = "";
  try {
    const bytes = base64urlDecode(payload);
    const { signable, signature } = splitSignature(bytes);
    const signPub = await importSignPublicKey(cfg.serverSignPublicJwk!);
    if (!(await verifyRegion(signPub, signable, signature))) throw new Error("bad signature");
    label = decodeDropLink(bytes).label;
  } catch {
    show(h("This link isn't valid"), note("It may be incomplete or tampered with. Ask the recipient for a fresh link.", "error"));
    return;
  }

  const who = label ? `"${label}"` : "this FileKey user";
  const picker = el("input", { type: "file" }) as HTMLInputElement;
  picker.style.display = "none";
  picker.addEventListener("change", () => {
    const f = picker.files?.[0];
    if (f) void sendFile(payload, f);
  });
  const choose = primaryButton("Choose a file", () => picker.click());

  show(
    h(`Send a file to ${who}`),
    p("Your file is encrypted in this browser, to their key, before it leaves. They open it with their passkey."),
    el("div", { class: "row" }, [choose, picker]),
    p(`${label ? `"${label}" is just the label on this link.` : ""} Nobody but the recipient can read what you send.`, "muted small"),
  );
}

async function sendFile(payload: string, file: File): Promise<void> {
  show(h("Encrypting…"), spinner(`Encrypting ${file.name}…`));
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
    show(h("Uploading…"), spinner("Uploading the encrypted file…"));
    const { objectId, uploadUrl } = await api.uploadInit(payload, ciphertext.length);
    await api.putToR2(uploadUrl, ciphertext);
    await api.uploadComplete(payload, objectId);
    show(h("Sent"), p("They'll get an email with a link to open it. Thanks!"), note("The file is encrypted end-to-end. We can't read it.", "ok"));
  } catch (e) {
    show(h("Couldn't send that"), note(humanError(e), "error"));
  }
}

// ---- Receive (/d/<id>) ----------------------------------------------------

async function receiveMode(objectId: string): Promise<void> {
  show(h("Opening your file"), spinner("Fetching…"));
  try {
    const { url } = await api.fetchUrl(objectId);
    const resp = await fetch(url);
    if (!resp.ok) throw new Error("the file has expired or was already removed");
    const ciphertext = new Uint8Array(await resp.arrayBuffer());
    show(h("Opening your file"), spinner("Waiting for your passkey…"));
    const prf = await getPrfSecret();
    const identity = await deriveIdentityFromPrf(prf, ns);
    prf.fill(0);
    const res = await decrypt({ file: ciphertext, namespaces: NS, resolveIdentity: async () => identity });
    const blob = new Blob([res.plaintext as BufferSource], { type: res.metadata.mimeType || "application/octet-stream" });
    const dl = el("a", { href: URL.createObjectURL(blob), download: res.metadata.filename || "file", class: "btn btn-primary" }, ["Save file"]);
    show(h("Decrypted"), p(`${res.metadata.filename} is ready, decrypted on your device.`), el("div", { class: "row" }, [dl]));
  } catch (e) {
    show(h("Couldn't open this"), note(humanError(e), "error"));
  }
}

// ---- routing + helpers ----------------------------------------------------

function humanError(e: unknown): string {
  if (e instanceof DropApiError) return e.message;
  const m = e instanceof Error ? e.message : String(e);
  if (/no PRF|passkey|assertion/i.test(m)) return "Couldn't use your passkey. Make sure you have a FileKey passkey on this device.";
  if (/auth_failed|wrong_namespace/i.test(m)) return "This file couldn't be decrypted. It may be corrupted or not encrypted for you.";
  return m;
}

function route(): void {
  const path = location.pathname;
  const hash = location.hash.replace(/^#/, "");
  if (path === "/confirm") return void confirmMode(hash);
  if (path.startsWith("/d/")) return void receiveMode(path.slice("/d/".length));
  if (hash.length > 0) return void uploadMode(hash);
  return setupMode();
}

// Light/Dark toggle (the header button); persists like the rest of FileKey.
document.getElementById("themeBtn")?.addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme");
  const isDark = cur === "dark" || (cur === null && matchMedia("(prefers-color-scheme: dark)").matches);
  const next = isDark ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("filekey-theme", next);
  } catch {
    /* private mode */
  }
});

route();
