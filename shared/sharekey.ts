// Share-key decode for the WORKER (the download gate seals a challenge to the receiver's public key).
//
// A share key is a Bech32m "fkey1…" string over: sk_version(1) || namespace_tag(4) || compressed_pk(33)
// = 38 bytes (web/core/src/sharekey.ts §4.4). In a signed Drop link it rides as the UTF-8 bytes of that
// string. This module turns those bytes into a 65-byte SEC1 uncompressed P-256 point, ready for HPKE.
//
// We don't pull in web/core's full NamespaceSet validation: the link is already server-signed, so the
// share key is trusted; we only need the public point, and we still validate structure + that the point
// is on-curve. Keep the constants in sync with web/core/src/constants.ts.
import { p256 } from "@noble/curves/nist.js";
import { bech32m } from "@scure/base";

const SHARE_KEY_HRP = "fkey";
const SK_VERSION = 0x01;
const NS_TAG_LEN = 4;
const COMPRESSED_PK_LEN = 33;
const PAYLOAD_LEN = 1 + NS_TAG_LEN + COMPRESSED_PK_LEN; // 38
const BECH32_LIMIT = 1023;

/** The ONLY namespace this relay serves: tag = SHA-256("receive.link")[0:4] (core namespaceTag, section 4.4).
 *  receive.link identities were re-namespaced from "filekey.app" on 2026-07-06 (a deliberate one-time
 *  break: browser-decrypted downloads mean cross-app ciphertext compatibility bought nothing). Enforcing
 *  the tag here makes links minted under the OLD namespace fail LOUDLY at init/complete instead of
 *  delivering files their receiver's re-derived identity can no longer open. Exported for tests. */
export const RECEIVE_LINK_NS_TAG = Uint8Array.from([0x02, 0xf2, 0xad, 0x28]);

/**
 * Decode a receiver share key (the UTF-8 bytes of the Bech32m "fkey…" string from a signed link) to a
 * 65-byte SEC1 uncompressed P-256 public key. Throws on any malformation (invalid UTF-8, bad Bech32m,
 * wrong HRP/version/length, or an off-curve / identity point) — callers treat a throw as fail-closed.
 */
export function recipientPkFromShareKeyBytes(shareKeyBytes: Uint8Array): Uint8Array {
  const str = new TextDecoder("utf-8", { fatal: true }).decode(shareKeyBytes); // rejects invalid UTF-8
  const { prefix, words } = bech32m.decode(str as `${string}1${string}`, BECH32_LIMIT); // rejects bad checksum
  if (prefix !== SHARE_KEY_HRP) throw new Error(`share-key HRP "${prefix}" != "${SHARE_KEY_HRP}"`);
  const payload = bech32m.fromWords(words);
  if (payload.length !== PAYLOAD_LEN) throw new Error(`share-key payload length ${payload.length} != ${PAYLOAD_LEN}`);
  if (payload[0] !== SK_VERSION) throw new Error(`unsupported sk_version 0x${payload[0]!.toString(16)}`);
  const tag = payload.subarray(1, 1 + NS_TAG_LEN);
  if (!RECEIVE_LINK_NS_TAG.every((b, i) => tag[i] === b)) throw new Error("share-key namespace tag mismatch (a link from a previous namespace)");
  const compressed = payload.subarray(1 + NS_TAG_LEN); // 33-byte compressed point
  if (compressed.length !== COMPRESSED_PK_LEN || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new Error("expected 33-byte compressed SEC1 point (0x02/0x03 prefix)");
  }
  const point = p256.Point.fromBytes(compressed);
  point.assertValidity(); // explicit on-curve + non-identity check
  return point.toBytes(false); // 65-byte SEC1 uncompressed
}
