// WebAuthn PRF provider (browser-only). Vendored from FileKey web/webauthn.ts — the
// ONLY change is the import path (FileKey core lives at ../core/src here). The RP-ID is
// normalized to the registrable domain, so a passkey enrolled on filekey.app (Vault)
// works unchanged on drop.filekey.app: one identity across the family.
import { PRF_INPUT_SALT, bs } from "../core/src/index.js";

export interface PrfSupport {
  webauthn: boolean;
  secureContext: boolean;
}

export function checkSupport(): PrfSupport {
  return {
    webauthn: typeof PublicKeyCredential !== "undefined" && !!navigator.credentials,
    secureContext: window.isSecureContext,
  };
}

export async function prfBrowserSupport(): Promise<boolean | undefined> {
  const PKC = typeof PublicKeyCredential !== "undefined"
    ? (PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> })
    : undefined;
  if (!PKC?.getClientCapabilities) return undefined;
  try {
    const v = (await PKC.getClientCapabilities())["extension:prf"];
    return v === true ? true : v === false ? false : undefined;
  } catch {
    return undefined;
  }
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * RP-ID normalized to the registrable domain (apex), so the identity survives being
 * served from any subdomain (filekey.app, drop.filekey.app, …) and both products agree
 * on rp.id and share the passkey. localhost and bare (<=2-label) hostnames pass through.
 */
export function deploymentRpId(): string {
  const host = location.hostname;
  if (host === "localhost") return host;
  const parts = host.split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : host;
}

/** Enroll a new passkey with the PRF extension enabled. Throws if PRF is unsupported. */
export async function enrollPasskey(displayName: string): Promise<Uint8Array> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: deploymentRpId(), name: "receive.link" },
      user: { id: bs(randomBytes(16)), name: displayName || "receive.link", displayName: displayName || "receive.link" },
      challenge: bs(randomBytes(32)),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      // userVerification MUST be "required": the CTAP2 hmac-secret returns a DIFFERENT
      // secret for UV vs non-UV assertions, so "preferred" could silently derive a
      // different identity. "required" also means a stolen authenticator can't decrypt
      // without its PIN/biometric. (residentKey:"required" already mandates a PIN.)
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      timeout: 60_000,
      extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!cred) throw new Error("passkey creation returned null");
  const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean } };
  if (!ext.prf?.enabled) throw new Error("this authenticator/browser does not support the PRF extension");
  return new Uint8Array(cred.rawId); // credential id, so the caller can pin getPrfSecret to THIS passkey
}

/** Perform a PRF assertion and return the 32-byte prf_secret. */
export async function getPrfSecret(credentialId?: Uint8Array): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      rpId: deploymentRpId(),
      challenge: bs(randomBytes(32)),
      userVerification: "required", // MUST match enrollment (PRF differs without UV)
      timeout: 60_000,
      // Pin to a specific passkey when the caller knows which one set up this browser, so the
      // browser uses it directly instead of offering every receive.link passkey to choose from.
      allowCredentials: credentialId ? [{ type: "public-key", id: bs(credentialId) }] : undefined,
      extensions: { prf: { eval: { first: bs(PRF_INPUT_SALT) } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("assertion returned null");
  const ext = assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  const first = ext.prf?.results?.first;
  if (!first) throw new Error("no PRF output (authenticator may not support PRF, or no passkey enrolled here)");
  const out = new Uint8Array(first);
  if (out.length !== 32) throw new Error(`PRF output is ${out.length} bytes, expected 32`);
  return out;
}
