// HTTP helpers: CORS + JSON responses + safe body parsing.

export function cors(origin: string): Record<string, string> {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
    vary: "origin",
  };
}

export function json(data: unknown, status: number, origin: string): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors(origin), "content-type": "application/json" },
  });
}

// All Drop JSON bodies are tiny (a link payload + a couple of base64 fields); the
// file bytes go direct to R2, never through these endpoints. Cap the body so an
// attacker can't force a huge allocation before the codec's length checks run.
const MAX_JSON_BYTES = 64 * 1024;

export async function readJson<T = Record<string, unknown>>(req: Request): Promise<T | null> {
  try {
    const text = await req.text();
    if (text.length > MAX_JSON_BYTES) return null;
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

/** Best-effort client IP for rate-limiting (Cloudflare sets cf-connecting-ip). */
export function clientIp(req: Request): string {
  return req.headers.get("cf-connecting-ip") || "0.0.0.0";
}
