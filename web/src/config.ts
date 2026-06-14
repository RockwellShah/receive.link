// Per-environment config: which Worker to talk to + the pinned server PUBLIC keys.
// The KEM public key is what the browser seals the receiver's email TO; the signing
// public key is what it verifies Drop links against. Both are public (safe to ship).
// Fill the keys per env from `bun run gen:keys` output. Same trust model as the app
// bundle itself: we already trust the code we serve, and pin the matching keys with it.

export interface DropConfig {
  /** Worker API base, no trailing slash. */
  apiBase: string;
  /** 65-byte SEC1 uncompressed P-256, hex. From gen-keys SERVER_KEM_PUBLIC_HEX. */
  serverKemPublicHex: string;
  /** ECDSA P-256 public JWK. From gen-keys SERVER_SIGN_PUBLIC_JWK. */
  serverSignPublicJwk: JsonWebKey | null;
}

const PLACEHOLDER = "REPLACE_AFTER_GEN_KEYS";

const ENVS: Record<string, DropConfig> = {
  "drop.filekey.app": {
    apiBase: "https://api.drop.filekey.app",
    serverKemPublicHex: PLACEHOLDER,
    serverSignPublicJwk: null,
  },
  "drop-staging.filekey.app": {
    apiBase: "https://filekey-drop-staging.rockwellshah.workers.dev",
    serverKemPublicHex:
      "043b235d0c8594a8dda07e5db3ce127f697a65037aa606135c4ba80316b850833a524f6f78b35f98959887323342bdb93f6b7cc92e2ae92b556ffc5807c116b2b2",
    serverSignPublicJwk: { crv: "P-256", ext: true, key_ops: ["verify"], kty: "EC", x: "wQspI1R3MyBRr0hPRba5LEbKH643Gbl0-EdqKbAVH1E", y: "3twD-Dp7LZXQkJQQ_M8X9dN_LtaC2kUZ-Il6CR5gEcE" },
  },
  // Staging on Cloudflare Pages → the workers.dev Worker. Keys pinned from
  // keys/staging.json (gen-keys output); the matching privates are Wrangler secrets.
  "filekey-drop-staging.pages.dev": {
    apiBase: "https://filekey-drop-staging.rockwellshah.workers.dev",
    serverKemPublicHex:
      "043b235d0c8594a8dda07e5db3ce127f697a65037aa606135c4ba80316b850833a524f6f78b35f98959887323342bdb93f6b7cc92e2ae92b556ffc5807c116b2b2",
    serverSignPublicJwk: { crv: "P-256", ext: true, key_ops: ["verify"], kty: "EC", x: "wQspI1R3MyBRr0hPRba5LEbKH643Gbl0-EdqKbAVH1E", y: "3twD-Dp7LZXQkJQQ_M8X9dN_LtaC2kUZ-Il6CR5gEcE" },
  },
  // Local dev: the serve.ts dev server proxies /api to a local Worker (wrangler dev
  // or the mock). Keys get filled from a local gen-keys run.
  localhost: {
    apiBase: "/api",
    serverKemPublicHex: PLACEHOLDER,
    serverSignPublicJwk: null,
  },
};

export function dropConfig(): DropConfig {
  return ENVS[location.hostname] ?? ENVS["localhost"]!;
}

export function isConfigured(c: DropConfig): boolean {
  return c.serverKemPublicHex !== PLACEHOLDER && !!c.serverSignPublicJwk;
}

/**
 * Resolve the active config. In local dev the mock server (web/devserver.ts) holds
 * the keys and serves them at /api/__config, so the client always matches whatever
 * key the server generated this run. In prod the keys are pinned in ENVS above.
 */
export async function ensureConfig(): Promise<DropConfig> {
  const c = dropConfig();
  if (isConfigured(c)) return c;
  if (location.hostname === "localhost" || location.hostname === "127.0.0.1") {
    try {
      const r = await fetch(`${c.apiBase}/__config`);
      if (r.ok) {
        const j = (await r.json()) as { kemPublicHex: string; signPublicJwk: JsonWebKey };
        c.serverKemPublicHex = j.kemPublicHex;
        c.serverSignPublicJwk = j.signPublicJwk;
      }
    } catch {
      /* dev server not running — stays unconfigured, flows show the hint */
    }
  }
  return c;
}
