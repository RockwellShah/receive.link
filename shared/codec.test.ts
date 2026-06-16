// Codec round-trip, framing, and strict-rejection tests. Zero-dep; runs under `bun test`.
import { expect, test } from "bun:test";
import {
  DROP_PAYLOAD_VERSION,
  DropCodecError,
  MAX_LABEL_BYTES,
  SERVER_SIG_LEN,
  base64urlDecode,
  base64urlEncode,
  decodeDropLink,
  decodeDropLinkFromFragment,
  encodeDropLink,
  encodeDropLinkToFragment,
  signableBytes,
  splitSignature,
  type DropLink,
} from "./codec";

function sample(over: Partial<DropLink> = {}): DropLink {
  return {
    version: DROP_PAYLOAD_VERSION,
    keyId: 1,
    linkId: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    shareKey: new Uint8Array(38).fill(0xab),
    label: "Rockwell's tax inbox",
    sealedEmail: new Uint8Array(121).fill(0xcd),
    serverSig: new Uint8Array(SERVER_SIG_LEN).fill(0xee),
    ...over,
  };
}

test("encode → decode round-trips every field", () => {
  const link = sample();
  const decoded = decodeDropLink(encodeDropLink(link));
  expect(decoded.version).toBe(link.version);
  expect(decoded.keyId).toBe(link.keyId);
  expect(decoded.linkId).toEqual(link.linkId);
  expect(decoded.shareKey).toEqual(link.shareKey);
  expect(decoded.label).toBe(link.label);
  expect(decoded.sealedEmail).toEqual(link.sealedEmail);
  expect(decoded.serverSig).toEqual(link.serverSig);
});

test("base64url fragment round-trips", () => {
  const link = sample();
  const decoded = decodeDropLinkFromFragment(encodeDropLinkToFragment(link));
  expect(decoded.label).toBe(link.label);
  expect(decoded.sealedEmail).toEqual(link.sealedEmail);
});

test("signableBytes equals the full payload minus the trailing signature", () => {
  const link = sample();
  const full = encodeDropLink(link);
  const { signable, signature } = splitSignature(full);
  expect(signable).toEqual(signableBytes(link));
  expect(signature).toEqual(link.serverSig);
});

test("a UTF-8 label round-trips by byte length, not char count", () => {
  // 16 emoji = 64 UTF-8 bytes = exactly MAX_LABEL_BYTES.
  const label = "🔑".repeat(16);
  expect(new TextEncoder().encode(label).length).toBe(MAX_LABEL_BYTES);
  const decoded = decodeDropLink(encodeDropLink(sample({ label })));
  expect(decoded.label).toBe(label);
});

test("rejects an over-long label at encode", () => {
  expect(() => signableBytes(sample({ label: "x".repeat(MAX_LABEL_BYTES + 1) }))).toThrow(DropCodecError);
});

test("rejects a wrong-length link_id at encode", () => {
  expect(() => signableBytes(sample({ linkId: new Uint8Array(7) }))).toThrow(DropCodecError);
});

test("rejects a wrong-length signature at encode", () => {
  expect(() => encodeDropLink(sample({ serverSig: new Uint8Array(63) }))).toThrow(DropCodecError);
});

test("rejects an unknown version at decode", () => {
  const bytes = encodeDropLink(sample());
  bytes[0] = 0x09; // not DROP_PAYLOAD_VERSION
  expect(() => decodeDropLink(bytes)).toThrow(/unsupported version/);
});

test("round-trips key_id and rejects an out-of-range one at encode", () => {
  expect(decodeDropLink(encodeDropLink(sample({ keyId: 200 }))).keyId).toBe(200);
  expect(() => signableBytes(sample({ keyId: 256 }))).toThrow(DropCodecError);
});

test("rejects a truncated payload", () => {
  const bytes = encodeDropLink(sample());
  expect(() => decodeDropLink(bytes.subarray(0, bytes.length - 1))).toThrow(DropCodecError);
});

test("rejects trailing bytes after the payload", () => {
  const bytes = encodeDropLink(sample());
  const padded = new Uint8Array(bytes.length + 1);
  padded.set(bytes, 0);
  expect(() => decodeDropLink(padded)).toThrow(/trailing bytes/);
});

test("rejects too-short input in splitSignature", () => {
  expect(() => splitSignature(new Uint8Array(SERVER_SIG_LEN))).toThrow(DropCodecError);
});

test("base64url rejects non-alphabet characters", () => {
  expect(() => base64urlDecode("abc$def")).toThrow(DropCodecError);
});

test("base64url encode/decode is identity on random-ish bytes", () => {
  const u = new Uint8Array(200);
  for (let i = 0; i < u.length; i++) u[i] = (i * 37 + 11) & 0xff;
  expect(base64urlDecode(base64urlEncode(u))).toEqual(u);
});

test("a flipped byte in the signed region changes signableBytes (sig would fail)", () => {
  const link = sample();
  const a = splitSignature(encodeDropLink(link)).signable;
  const tampered = sample({ label: "Rockwell's tax inb0x" }); // one char different
  const b = splitSignature(encodeDropLink(tampered)).signable;
  expect(a).not.toEqual(b);
});
