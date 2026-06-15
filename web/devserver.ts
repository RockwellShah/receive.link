// Local mock dev server: drive the whole Drop flow in a browser with NO Cloudflare.
// It mounts the REAL Worker handlers over in-memory bindings (testing.ts), generates
// a dev keypair at startup (served to the client at /api/__config so the pinned keys
// always match), stands in for R2 at /__r2/<id>, and exposes the captured outbound
// mail at /__mail so you can click the confirm + download links. Run: bun run web/devserver.ts
import { file } from "bun";
import { base64urlDecode } from "../shared/codec";
import { confirm, fetchObject, register, revoke, uploadAbort, uploadComplete, uploadInit, uploadParts } from "../worker/src/handlers";
import { CapturingEmail, MemoryKV, MemoryR2 } from "../worker/src/testing";
import type { Env } from "../worker/src/types";

const ROOT = `${import.meta.dir}/`;
const PORT = 8080;
const ORIGIN = `http://localhost:${PORT}`;

// --- dev keys (throwaway, regenerated each run) ---
const sign = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const kem = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
const signPubJwk = await crypto.subtle.exportKey("jwk", sign.publicKey);
const kemPubJwk = await crypto.subtle.exportKey("jwk", kem.publicKey);
const kemPubRaw = new Uint8Array(65);
kemPubRaw[0] = 0x04;
kemPubRaw.set(base64urlDecode(kemPubJwk.x!), 1);
kemPubRaw.set(base64urlDecode(kemPubJwk.y!), 33);
const kemPubHex = [...kemPubRaw].map((b) => b.toString(16).padStart(2, "0")).join("");

const kv = new MemoryKV();
const r2 = new MemoryR2();
const mail = new CapturingEmail();
const env: Env = {
  EMAIL: mail,
  DROP_BUCKET: r2 as unknown as R2Bucket,
  DROP_KV: kv as unknown as KVNamespace,
  SERVER_KEM_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", kem.privateKey)),
  SERVER_SIGN_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey("jwk", sign.privateKey)),
  SERVER_SIGN_PUBLIC_JWK: JSON.stringify(signPubJwk),
  ALLOWED_ORIGIN: ORIGIN,
  MAIL_FROM: "files@drop.localhost",
  R2_ACCOUNT_ID: "dev",
  R2_BUCKET: "dev",
  R2_ACCESS_KEY_ID: "dev",
  R2_SECRET_ACCESS_KEY: "dev",
  MAX_UPLOAD_BYTES: String(2 * 1024 * 1024 * 1024),
  // Low so the browser exercises multipart on small dev files. The in-memory R2 double
  // doesn't enforce R2's real 5 MiB minimum, so tiny parts are fine here.
  MULTIPART_THRESHOLD: String(256 * 1024),
  MULTIPART_MIN_PART: String(256 * 1024),
};

// Rewrite a handler's presigned-R2 URL to the local /__r2 stand-in.
async function localizeUrl(res: Response, field: "uploadUrl" | "url", objectId: string): Promise<Response> {
  const body = (await res.json()) as Record<string, unknown>;
  if (body[field]) body[field] = `${ORIGIN}/__r2/${objectId}`;
  return Response.json(body, { status: res.status });
}

// Rewrite presigned multipart UploadPart URLs to the local /__r2 stand-in (carrying
// partNumber + uploadId so the mock can route the part to the right upload).
function localizeParts(partUrls: { partNumber: number }[], objectId: string, uploadId: string): { partNumber: number; url: string }[] {
  return partUrls.map((p) => ({ partNumber: p.partNumber, url: `${ORIGIN}/__r2/${objectId}?partNumber=${p.partNumber}&uploadId=${encodeURIComponent(uploadId)}` }));
}

async function handleApi(req: Request, sub: string): Promise<Response> {
  if (req.method === "GET" && sub === "/__config") return Response.json({ kemPublicHex: kemPubHex, signPublicJwk: signPubJwk });
  if (req.method === "GET" && sub === "/__lastmail") return Response.json(mail.sent.at(-1) ?? null);
  if (req.method === "POST" && sub === "/register") return register(req, env);
  if (req.method === "POST" && sub === "/confirm") return confirm(req, env);
  if (req.method === "POST" && sub === "/revoke") return revoke(req, env);
  if (req.method === "POST" && sub === "/upload-init") {
    const res = await uploadInit(req, env);
    const body = (await res.json()) as Record<string, unknown>;
    if (body.mode === "single" && body.uploadUrl) body.uploadUrl = `${ORIGIN}/__r2/${body.objectId as string}`;
    else if (body.mode === "multipart" && Array.isArray(body.partUrls)) {
      body.partUrls = localizeParts(body.partUrls as { partNumber: number }[], body.objectId as string, body.uploadId as string);
    }
    return Response.json(body, { status: res.status });
  }
  if (req.method === "POST" && sub === "/upload-parts") {
    const rc = req.clone();
    const res = await uploadParts(req, env);
    const body = (await res.json()) as Record<string, unknown>;
    if (Array.isArray(body.partUrls)) {
      const { objectId } = (await rc.json()) as { objectId: string };
      const bindRaw = await kv.get(`upload:${objectId}`);
      const uploadId = bindRaw ? ((JSON.parse(bindRaw) as { mp?: { uploadId?: string } }).mp?.uploadId ?? "") : "";
      body.partUrls = localizeParts(body.partUrls as { partNumber: number }[], objectId, uploadId);
    }
    return Response.json(body, { status: res.status });
  }
  if (req.method === "POST" && sub === "/upload-complete") return uploadComplete(req, env);
  if (req.method === "POST" && sub === "/upload-abort") return uploadAbort(req, env);
  if (req.method === "GET" && sub.startsWith("/fetch/")) {
    const id = sub.slice("/fetch/".length);
    return localizeUrl(await fetchObject(req, env, id), "url", id);
  }
  return new Response("not found", { status: 404 });
}

function mailbox(): Response {
  const rows = mail.sent
    .map((m) => {
      const text = m.text!.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1">$1</a>');
      return `<div style="border:1px solid #ddd;border-radius:8px;padding:14px;margin:12px 0;font-family:system-ui"><b>To:</b> ${m.to}<br><b>Subject:</b> ${m.subject}<pre style="white-space:pre-wrap;font:13px ui-monospace">${text}</pre></div>`;
    })
    .reverse()
    .join("");
  return new Response(`<!doctype html><meta charset=utf-8><title>Drop dev mailbox</title><body style="max-width:680px;margin:40px auto;font-family:system-ui"><h2>Drop dev mailbox (${mail.sent.length})</h2>${rows || "<p>No mail yet.</p>"}`, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

Bun.serve({
  port: PORT,
  async fetch(req) {
    const path = decodeURIComponent(new URL(req.url).pathname);
    if (path.startsWith("/api/")) return handleApi(req, path.slice("/api".length));
    if (path === "/__mail") return mailbox();
    if (path.startsWith("/__r2/")) {
      const id = path.slice("/__r2/".length);
      if (req.method === "PUT") {
        const q = new URL(req.url).searchParams;
        const partNumber = q.get("partNumber");
        const uploadId = q.get("uploadId");
        const bytes = new Uint8Array(await req.arrayBuffer());
        if (partNumber && uploadId) {
          const etag = r2.putPartRaw(uploadId, Number(partNumber), bytes);
          return new Response(null, { status: 200, headers: { ETag: etag } });
        }
        r2.putRaw(id, bytes);
        return new Response(null, { status: 200 });
      }
      const obj = await r2.get(id);
      return obj ? new Response(await obj.arrayBuffer()) : new Response("not found", { status: 404 });
    }
    if (path !== "/" && !path.endsWith("/")) {
      const f = file(ROOT + path.replace(/^\//, ""));
      if (await f.exists()) return new Response(f);
    }
    return new Response(file(ROOT + "index.html"), { headers: { "content-type": "text/html; charset=utf-8" } });
  },
});

console.log(`Drop MOCK dev server: ${ORIGIN}  (mailbox at ${ORIGIN}/__mail)`);
