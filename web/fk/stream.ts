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
 * Open a ciphertext (any ByteSource) for streaming decryption: reads the head + metadata (small,
 * authenticated; this is where the identity is resolved) and returns a generator of authenticated
 * plaintext chunks. The caller writes chunks straight to disk (constant memory). Policy B: a
 * truncated/corrupt file can surface an authenticated prefix before the generator throws at the end.
 */
export async function openCiphertextSource(
  source: ByteSource,
  identity: Identity,
  namespaces: NamespaceSet,
): Promise<{ metadata: Metadata; chunks: AsyncGenerator<Uint8Array> }> {
  const res = await decryptStream({ file: source, namespaces, resolveIdentity: async () => identity });
  return { metadata: res.metadata, chunks: res.chunks };
}

/** Open a ciphertext Blob (random-access). Convenience wrapper over {@link openCiphertextSource}. */
export function openCiphertext(
  ciphertext: Blob,
  identity: Identity,
  namespaces: NamespaceSet,
): Promise<{ metadata: Metadata; chunks: AsyncGenerator<Uint8Array> }> {
  return openCiphertextSource(blobSource(ciphertext), identity, namespaces);
}

/**
 * A ByteSource backed by a forward-only ReadableStream (a fetch response body), so the receive path
 * decrypts straight from the network to disk WITHOUT buffering the whole ciphertext (true 1x disk).
 * decryptStream reads strictly forward and contiguously, so slice() only ever advances the cursor; a
 * backward read is a bug and throws. `size` is the total ciphertext length (the GET's Content-Length).
 */
export function streamSource(stream: ReadableStream<Uint8Array>, size: number): ByteSource {
  const reader = stream.getReader();
  const pending: Uint8Array[] = [];
  let pendingLen = 0;
  let cursor = 0;
  let eof = false;
  const fill = async (n: number): Promise<void> => {
    while (pendingLen < n && !eof) {
      const { value, done } = await reader.read();
      if (done) eof = true;
      else if (value && value.length) {
        pending.push(value);
        pendingLen += value.length;
      }
    }
  };
  const take = async (n: number): Promise<Uint8Array> => {
    await fill(n);
    const len = Math.min(n, pendingLen);
    const out = new Uint8Array(len);
    let off = 0;
    while (off < len) {
      const head = pending[0]!;
      const need = len - off;
      if (head.length <= need) {
        out.set(head, off);
        off += head.length;
        pending.shift();
        pendingLen -= head.length;
      } else {
        out.set(head.subarray(0, need), off);
        pending[0] = head.subarray(need);
        pendingLen -= need;
        off += need;
      }
    }
    cursor += len;
    return out;
  };
  return {
    size,
    async slice(start: number, end: number): Promise<Uint8Array> {
      if (start < cursor) throw new Error("streamSource: only forward reads are supported");
      if (start > cursor) await take(start - cursor); // skip a gap (decryptStream reads contiguously)
      return take(Math.max(0, Math.min(end, size) - cursor));
    },
  };
}
