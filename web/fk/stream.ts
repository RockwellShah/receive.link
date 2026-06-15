// Streaming encrypt/decrypt glue — VENDORED from FileKey web/app.ts (blobSource +
// runCryptoJob) plus thin Drop wrappers. Files >= 64 MB run in the off-thread
// worker (web/fk/worker.ts); smaller ones stream on the main thread. Either way
// the input is read in slices and the output is a Blob-of-Blobs, so a multi-GB
// file never sits whole in memory.
import {
  CHUNK_SIZE,
  ENC_LEN,
  FileKeyError,
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

export const STREAM_THRESHOLD = 64 * 1024 * 1024; // 64 MB

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
type JobOutcome = { blob: Blob; metadata?: Metadata } | { cancelled: true };

// One Worker per job, terminated on completion or cancel (cancel = terminate).
export function runCryptoJob(job: Record<string, unknown>, onProgress?: JobProgress): { result: Promise<JobOutcome>; cancel: () => void } {
  const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  let settled = false;
  let resolveOutcome!: (o: JobOutcome) => void;
  const end = (fn: () => void) => {
    if (settled) return;
    settled = true;
    worker.terminate();
    fn();
  };
  const result = new Promise<JobOutcome>((resolve, reject) => {
    resolveOutcome = resolve;
    worker.onmessage = (e: MessageEvent) => {
      const m = e.data as { kind: string; done?: number; total?: number; blob?: Blob; metadata?: Metadata; code?: string; message?: string };
      if (m.kind === "progress") onProgress?.(m.done ?? 0, m.total ?? 0);
      else if (m.kind === "done") end(() => resolve({ blob: m.blob!, metadata: m.metadata }));
      else if (m.kind === "error") end(() => reject(m.code ? new FileKeyError(m.message ?? "", m.code) : new Error(m.message ?? "worker error")));
    };
    worker.onerror = (ev) => end(() => reject(new Error((ev as ErrorEvent).message || "crypto worker failed to start")));
    worker.postMessage(job);
  });
  return { result, cancel: () => end(() => resolveOutcome({ cancelled: true })) };
}

export interface StreamHandle {
  onProgress?: JobProgress;
  onCancel?: (cancel: () => void) => void;
}

/** Encrypt a File to a recipient's share key. Streams; returns a ciphertext Blob. */
export async function encryptFileToShareKey(
  file: File,
  shareKey: string,
  namespaces: NamespaceSet,
  sender: Identity,
  h: StreamHandle = {},
): Promise<Blob> {
  const { recipientPkRaw, namespace } = decodeShareKey(shareKey, namespaces);
  const metadata = metaFor(file);
  if (file.size >= STREAM_THRESHOLD) {
    const job = runCryptoJob(
      { kind: "encrypt", rpId: namespace.canonicalRpId, senderKeyPair: sender.keyPair, senderPk: sender.staticPkRaw, recipientPk: recipientPkRaw, blob: file, metadata },
      h.onProgress,
    );
    h.onCancel?.(job.cancel);
    const r = await job.result;
    if ("cancelled" in r) throw new Error("cancelled");
    return r.blob;
  }
  const parts: Blob[] = [];
  for await (const piece of encryptStream({ senderIdentity: sender, recipientPkRaw, namespace, plaintext: blobSource(file), metadata })) {
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

/** Decrypt a ciphertext Blob with the receiver's identity. Streams; returns a plaintext Blob + metadata. */
export async function decryptCiphertextBlob(
  ciphertext: Blob,
  identity: Identity,
  namespaces: NamespaceSet,
  h: StreamHandle = {},
): Promise<{ blob: Blob; metadata: Metadata }> {
  const rpId = identity.namespace.canonicalRpId;
  if (ciphertext.size >= STREAM_THRESHOLD) {
    const job = runCryptoJob(
      { kind: "decrypt", rpId, rpIds: [rpId], keyPair: identity.keyPair, staticPk: identity.staticPkRaw, file: ciphertext },
      h.onProgress,
    );
    h.onCancel?.(job.cancel);
    const r = await job.result;
    if ("cancelled" in r) throw new Error("cancelled");
    return { blob: r.blob, metadata: r.metadata! };
  }
  const res = await decryptStream({ file: blobSource(ciphertext), namespaces, resolveIdentity: async () => identity });
  const parts: Blob[] = [];
  for await (const pt of res.chunks) parts.push(new Blob([pt as unknown as BlobPart]));
  return { blob: new Blob(parts, { type: res.metadata.mimeType || "application/octet-stream" }), metadata: res.metadata };
}
