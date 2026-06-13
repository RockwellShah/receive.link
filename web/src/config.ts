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
  "staging.drop.filekey.app": {
    apiBase: "https://api-staging.drop.filekey.app",
    serverKemPublicHex: PLACEHOLDER,
    serverSignPublicJwk: null,
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
