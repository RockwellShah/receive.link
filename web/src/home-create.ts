// Real "Create your link" flow for the marketing-homepage modal (web/home/index.html).
// Mirrors app.ts setup: enroll/assert a passkey -> derive the identity -> seal the email ->
// register the link. It's driven by the modal's callback object (cb) instead of the chat-feed
// UI, and exposed as window.rlCreate so the modal's inline JS calls it (the modal falls back to
// a visual stub when this bundle is absent). One flat bundle: web/dist/home-create.js.
import { NamespaceSet, deriveIdentityFromPrf, encodeShareKey } from "../core/src/index.js";
import { base64urlDecode, base64urlEncode } from "../../shared/codec";
import { importKemPublicKey, sealEmail } from "../../shared/crypto";
import { DropApi, DropApiError } from "./api";
import { ensureConfig, isConfigured } from "./config";
import { enrollPasskey, getPrfSecret } from "./webauthn";

// Same namespace as the app (interop with filekey.app). Tag = SHA-256("filekey.app")[0:4].
const NS = new NamespaceSet(["filekey.app"]);
const ns = NS.namespaces[0]!;

// The modal's panel switcher (web/home/index.html) hands us these. recovery() is the
// deleted-passkey self-heal panel (Try again / Create a new passkey).
interface CreateCallbacks {
  working(): void;
  sent(): void;
  error(message: string): void;
  recovery(): void;
}

function hexToBytes(s: string): Uint8Array {
  const u = new Uint8Array(s.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return u;
}

// Humanize the errors this flow can hit. Register failures arrive as DropApiError; passkey
// failures as a DOMException / Error. (The recovery panel handles the deleted-passkey case, so
// these messages just steer the user to retry.)
function humanError(e: unknown): string {
  if (e instanceof DropApiError) {
    const m = e.message;
    if (/rate limited|daily limit|over its daily/i.test(m)) return "Too many sign-ups right now. Please try again later.";
    return m;
  }
  const m = e instanceof Error ? e.message : String(e);
  if (/not allowed|timed out|NotAllowed|AbortError|cancel/i.test(m)) return "The passkey prompt was dismissed or timed out. Try again.";
  if (/no PRF|passkey|assertion/i.test(m)) return "Couldn't use your passkey on this device. Try again.";
  return m;
}

// A passkey assertion failed because no usable passkey was found (deleted / cancelled / none here).
// Mirrors app.ts isPasskeyError.
function isPasskeyError(e: unknown): boolean {
  if ((e as { name?: string } | null)?.name === "NotAllowedError") return true;
  const m = e instanceof Error ? e.message : String(e);
  return /not allowed|timed out|NotAllowed|AbortError|cancel|no PRF|passkey|assertion/i.test(m);
}

// PRF secret, pinned to the passkey this browser enrolled (rl_cred) so the authenticator targets
// THAT one (no picker). Self-heals the pin when missing. Mirrors app.ts prfSecret().
async function prfSecret(): Promise<Uint8Array> {
  let id: Uint8Array | undefined;
  try {
    const stored = localStorage.getItem("rl_cred");
    if (stored) id = base64urlDecode(stored);
  } catch { /* storage blocked / private mode: open prompt */ }
  const { secret, credentialId } = await getPrfSecret(id);
  if (!id) { try { localStorage.setItem("rl_cred", base64urlEncode(credentialId)); } catch { /* private mode */ } }
  return secret;
}

// The create flow. forceEnroll=true is the modal's "Create a new passkey" path: forget the stale
// pin and enroll a fresh passkey (a new identity), mirroring app.ts runSetup's recovery branch.
async function rlCreate(email: string, label: string, cb: CreateCallbacks, forceEnroll = false): Promise<void> {
  // *.pages.dev previews can't run WebAuthn: deploymentRpId() resolves to the public-suffix
  // "pages.dev", which browsers refuse for credential creation. Steer testers to a real domain
  // (staging.receive.link or localhost) rather than surfacing a cryptic browser error.
  if (location.hostname.endsWith(".pages.dev")) {
    cb.error("Passkeys need a real domain. Test the create flow on staging.receive.link, not this preview URL.");
    return;
  }
  cb.working();
  if (forceEnroll) {
    try { localStorage.removeItem("rl_passkey"); localStorage.removeItem("rl_cred"); } catch { /* private mode */ }
  }
  const firstPasskey = forceEnroll || !localStorage.getItem("rl_passkey");
  try {
    const cfg = await ensureConfig();
    if (!isConfigured(cfg)) { cb.error("This site isn't wired up for sign-up yet. Try again shortly."); return; }
    const api = new DropApi(cfg.apiBase);
    if (firstPasskey) {
      const credId = await enrollPasskey(email);
      try { localStorage.setItem("rl_passkey", "1"); localStorage.setItem("rl_cred", base64urlEncode(credId)); } catch { /* private mode */ }
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
    cb.sent();
  } catch (e) {
    // We were USING an existing passkey and it failed -> likely deleted from this device. Offer the
    // recovery panel rather than a dead-end error (a get() can't become a create()).
    if (!firstPasskey && isPasskeyError(e)) { cb.recovery(); return; }
    cb.error(humanError(e));
  }
}

(window as unknown as { rlCreate: typeof rlCreate }).rlCreate = rlCreate;
