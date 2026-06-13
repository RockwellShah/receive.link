// FileKey Drop — link-payload codec (shared by the Worker and the web client).
//
// A Drop link rides in the URL fragment of the receiver's permanent upload page:
//   https://drop.filekey.app/#<base64url(payload)>
// It binds, under a server signature, everything a sender's browser needs to
// encrypt a file to the receiver and hand it back through the relay:
//
//   version(1) | link_id(8) | share_key | label | sealed_email | server_sig(64)
//
// - share_key   : the receiver's public identity, exactly as the FileKey app
//                 encodes it for the `#to=` flow (opaque bytes here).
// - sealed_email: HPKE base-mode seal of the receiver's email TO the server's
//                 KEM key — only the Worker can read it (opaque bytes here).
// - server_sig  : ECDSA P-256 over every byte before it. The server mints this
//                 only after the receiver confirms their email, so a link can't
//                 exist for an inbox nobody proved they control, and the label /
//                 key / link_id can't be tampered with after the fact.
//
// This module has ZERO dependencies so it produces byte-identical output in the
// Worker (no DOM) and the browser. Crypto lives in crypto.ts; framing lives here.

export const DROP_PAYLOAD_VERSION = 1;
export const LINK_ID_LEN = 8;
export const SERVER_SIG_LEN = 64; // ECDSA P-256, raw r||s
export const MAX_LABEL_BYTES = 64; // UTF-8 length cap for the receiver-chosen label
export const MAX_SHARE_KEY_LEN = 255;
export const MAX_SEALED_EMAIL_LEN = 1024;

export interface DropLink {
  version: number;
  linkId: Uint8Array; // 8 bytes; rate-limit + revocation handle
  shareKey: Uint8Array; // opaque recipient public-identity bytes (as the app encodes them)
  label: string; // UTF-8, <= MAX_LABEL_BYTES bytes; shown to senders
  sealedEmail: Uint8Array; // HPKE seal of the email to the server KEM key
  serverSig: Uint8Array; // 64 bytes; ECDSA over signableBytes()
}

export class DropCodecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DropCodecError";
  }
}

const utf8 = new TextEncoder();
// fatal:true so a corrupted label is rejected, not silently replaced — this is a
// security product; malformed input should fail loudly.
const utf8Decode = new TextDecoder("utf-8", { fatal: true });

/**
 * The exact byte range the server signs and the client verifies: the whole
 * payload EXCEPT the trailing 64-byte signature. Built from the struct on the
 * mint side; on the verify side use {@link splitSignature} against raw bytes so
 * verification never depends on re-encoding (no canonicalization gaps).
 */
export function signableBytes(link: Omit<DropLink, "serverSig">): Uint8Array {
  const label = utf8.encode(link.label);
  if (link.linkId.length !== LINK_ID_LEN) {
    throw new DropCodecError(`link_id must be ${LINK_ID_LEN} bytes, got ${link.linkId.length}`);
  }
  if (link.shareKey.length < 1 || link.shareKey.length > MAX_SHARE_KEY_LEN) {
    throw new DropCodecError(`share_key length out of range: ${link.shareKey.length}`);
  }
  if (label.length > MAX_LABEL_BYTES) {
    throw new DropCodecError(`label exceeds ${MAX_LABEL_BYTES} bytes: ${label.length}`);
  }
  if (link.sealedEmail.length < 1 || link.sealedEmail.length > MAX_SEALED_EMAIL_LEN) {
    throw new DropCodecError(`sealed_email length out of range: ${link.sealedEmail.length}`);
  }
  const size = 1 + LINK_ID_LEN + 1 + link.shareKey.length + 1 + label.length + 2 + link.sealedEmail.length;
  const out = new Uint8Array(size);
  let o = 0;
  out[o++] = link.version & 0xff;
  out.set(link.linkId, o);
  o += LINK_ID_LEN;
  out[o++] = link.shareKey.length & 0xff;
  out.set(link.shareKey, o);
  o += link.shareKey.length;
  out[o++] = label.length & 0xff;
  out.set(label, o);
  o += label.length;
  out[o++] = (link.sealedEmail.length >> 8) & 0xff;
  out[o++] = link.sealedEmail.length & 0xff;
  out.set(link.sealedEmail, o);
  return out;
}

/** Full payload = signableBytes || server_sig. */
export function encodeDropLink(link: DropLink): Uint8Array {
  if (link.serverSig.length !== SERVER_SIG_LEN) {
    throw new DropCodecError(`server_sig must be ${SERVER_SIG_LEN} bytes, got ${link.serverSig.length}`);
  }
  const body = signableBytes(link);
  const out = new Uint8Array(body.length + SERVER_SIG_LEN);
  out.set(body, 0);
  out.set(link.serverSig, body.length);
  return out;
}

/**
 * Split raw payload bytes into the signed region and the signature, for
 * verification. Does NOT parse fields — verify the signature first, THEN
 * {@link decodeDropLink}.
 */
export function splitSignature(bytes: Uint8Array): { signable: Uint8Array; signature: Uint8Array } {
  if (bytes.length <= SERVER_SIG_LEN) throw new DropCodecError("payload too short to contain a signature");
  return {
    signable: bytes.subarray(0, bytes.length - SERVER_SIG_LEN),
    signature: bytes.subarray(bytes.length - SERVER_SIG_LEN),
  };
}

/** Strict parse. Throws DropCodecError on any malformation. */
export function decodeDropLink(bytes: Uint8Array): DropLink {
  let o = 0;
  const need = (n: number) => {
    if (o + n > bytes.length) throw new DropCodecError("truncated payload");
  };
  need(1);
  const version = bytes[o++]!;
  if (version !== DROP_PAYLOAD_VERSION) throw new DropCodecError(`unsupported version ${version}`);
  need(LINK_ID_LEN);
  const linkId = bytes.slice(o, o + LINK_ID_LEN);
  o += LINK_ID_LEN;
  need(1);
  const skLen = bytes[o++]!;
  if (skLen < 1) throw new DropCodecError("empty share_key");
  need(skLen);
  const shareKey = bytes.slice(o, o + skLen);
  o += skLen;
  need(1);
  const labelLen = bytes[o++]!;
  if (labelLen > MAX_LABEL_BYTES) throw new DropCodecError(`label too large: ${labelLen}`);
  need(labelLen);
  const label = utf8Decode.decode(bytes.slice(o, o + labelLen));
  o += labelLen;
  need(2);
  const seLen = (bytes[o++]! << 8) | bytes[o++]!;
  if (seLen < 1 || seLen > MAX_SEALED_EMAIL_LEN) throw new DropCodecError(`sealed_email length out of range: ${seLen}`);
  need(seLen);
  const sealedEmail = bytes.slice(o, o + seLen);
  o += seLen;
  need(SERVER_SIG_LEN);
  const serverSig = bytes.slice(o, o + SERVER_SIG_LEN);
  o += SERVER_SIG_LEN;
  if (o !== bytes.length) throw new DropCodecError("trailing bytes after payload");
  return { version, linkId, shareKey, label, sealedEmail, serverSig };
}

export function encodeDropLinkToFragment(link: DropLink): string {
  return base64urlEncode(encodeDropLink(link));
}

export function decodeDropLinkFromFragment(fragment: string): DropLink {
  return decodeDropLink(base64urlDecode(fragment));
}

// ---- zero-dep base64url (btoa/atob exist in Workers, bun, and browsers) ----

export function base64urlEncode(u: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new DropCodecError("invalid base64url");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
