// Streaming encrypt/decrypt glue — VENDORED from FileKey web/app.ts (blobSource +
// encryptStream/decryptStream) plus thin Drop wrappers. Everything streams: the input
// is read in slices and the output is a Blob-of-Blobs (or part-sized chunks), so a
// multi-GB file never sits whole in memory. All crypto runs on the MAIN THREAD —
// crypto.subtle does the AES off-thread internally and each chunk awaits, so the UI
// stays responsive without a dedicated Web Worker (Drop drops FileKey's worker path:
// large files stream through encryptFileToParts/openCiphertext, never one giant blob).
import {
  CHUNK_SIZE,
  ENC_LEN,
  GCM_TAG_LEN,
  HEADER_LEN,
  PK_LEN,
  type Identity,
  type Metadata,
  type NamespaceSet,
  decodeShareKey,
  encodeMetadata,
  encryptStream,
  decryptStream,
  type ByteSource,
} from "../core/src/index.js";

export function blobSource(blob: Blob, onRead?: (highWater: number) => void): ByteSource {
  return {
    size: blob.size,
    async slice(start: number, end: number): Promise<Uint8Array> {
      const stop = Math.min(end, blob.size);
      const u = new Uint8Array(await blob.slice(start, stop).arrayBuffer());
      onRead?.(stop);
      return u;
    },
  };
}

type JobProgress = (done: number, total: number) => void;

export interface StreamHandle {
  onProgress?: JobProgress;
}

/** Encrypt a File to a recipient's share key. Streams on the main thread; returns a ciphertext Blob. */
export async function encryptFileToShareKey(
  file: File,
  shareKey: string,
  namespaces: NamespaceSet,
  sender: Identity,
  h: StreamHandle = {},
): Promise<Blob> {
  const { recipientPkRaw, namespace } = decodeShareKey(shareKey, namespaces);
  const metadata = metaFor(file);
  const parts: Blob[] = [];
  const plaintext = blobSource(file, (read) => h.onProgress?.(read, file.size));
  for await (const piece of encryptStream({ senderIdentity: sender, recipientPkRaw, namespace, plaintext, metadata })) {
    parts.push(new Blob([piece as unknown as BlobPart]));
  }
  return new Blob(parts, { type: "application/octet-stream" });
}

/** Metadata FileKey commits for a File. Shared so the size estimate matches the actual encryption. */
function metaFor(file: File): Omit<Metadata, "originalSize"> {
  return { filename: file.name, mimeType: file.type || "application/octet-stream", createdAtUnixMs: 0, extras: new Map() };
}

/** Exact .filekey ciphertext length for a File — computed up front so upload-init can size multipart. */
export function ciphertextLength(file: File): number {
  const metaCtLen = encodeMetadata({ ...metaFor(file), originalSize: file.size }).length + GCM_TAG_LEN;
  const headLen = HEADER_LEN + PK_LEN + ENC_LEN + 4 + metaCtLen;
  const numChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
  return headLen + file.size + numChunks * GCM_TAG_LEN;
}

/**
 * Stream-encrypt a File and yield the ciphertext as parts of exactly `partSize` bytes (last is the
 * remainder), for multipart upload. Constant memory: never holds more than ~one part + one chunk, and
 * the source is read in slices. Byte-identical to the single-shot ciphertext for the same run.
 */
export async function* encryptFileToParts(
  file: File,
  shareKey: string,
  namespaces: NamespaceSet,
  sender: Identity,
  partSize: number,
  onRead?: (bytes: number) => void,
): AsyncGenerator<Uint8Array> {
  const { recipientPkRaw, namespace } = decodeShareKey(shareKey, namespaces);
  const pending: Uint8Array[] = [];
  let pendingLen = 0;
  for await (const piece of encryptStream({ senderIdentity: sender, recipientPkRaw, namespace, plaintext: blobSource(file, onRead), metadata: metaFor(file) })) {
    pending.push(piece);
    pendingLen += piece.length;
    while (pendingLen >= partSize) {
      yield takeBytes(pending, partSize);
      pendingLen -= partSize;
    }
  }
  if (pendingLen > 0) yield concatBytes(pending);
}

/** Pull exactly n bytes off the front of a chunk queue, leaving the remainder in place. */
function takeBytes(pending: Uint8Array[], n: number): Uint8Array {
  const out = new Uint8Array(n);
  let off = 0;
  while (off < n) {
    const head = pending[0]!;
    const need = n - off;
    if (head.length <= need) {
      out.set(head, off);
      off += head.length;
      pending.shift();
    } else {
      out.set(head.subarray(0, need), off);
      off += need;
      pending[0] = head.subarray(need);
    }
  }
  return out;
}

function concatBytes(pending: Uint8Array[]): Uint8Array {
  const total = pending.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of pending) {
    out.set(p, off);
    off += p.length;
  }
  pending.length = 0;
  return out;
}

/**
 * Open a ciphertext for streaming decryption: reads the head + metadata (small, authenticated; this
 * is where the identity is resolved) and returns a generator of authenticated plaintext chunks. The
 * caller writes chunks straight to disk (constant memory). Policy B: a truncated/corrupt file can
 * surface an authenticated prefix before the generator throws at the end.
 */
export async function openCiphertext(
  ciphertext: Blob,
  identity: Identity,
  namespaces: NamespaceSet,
): Promise<{ metadata: Metadata; chunks: AsyncGenerator<Uint8Array> }> {
  const res = await decryptStream({ file: blobSource(ciphertext), namespaces, resolveIdentity: async () => identity });
  return { metadata: res.metadata, chunks: res.chunks };
}
