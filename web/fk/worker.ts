// Off-main-thread streaming encrypt/decrypt — VENDORED from FileKey web/worker.ts.
// Trimmed to the single-file paths Drop needs (no folder zip). Keeps large files
// off the main thread AND out of RAM: it reads the input Blob in slices and emits
// a Blob-of-Blobs (disk-backed), so neither the plaintext nor the ciphertext is
// ever fully resident. WebAuthn stays on the main thread; this worker receives the
// already-derived key material (a structured-cloned CryptoKeyPair) and rebuilds
// the Identity/Namespace here.
import {
  FileKeyError,
  Namespace,
  NamespaceSet,
  decryptStream,
  encryptStream,
  type ByteSource,
  type Identity,
  type Metadata,
} from "../core/src/index.js";

type EncryptJob = {
  kind: "encrypt";
  rpId: string;
  senderKeyPair: CryptoKeyPair;
  senderPk: Uint8Array;
  recipientPk: Uint8Array;
  blob: Blob;
  metadata: Omit<Metadata, "originalSize">;
};
type DecryptJob = { kind: "decrypt"; rpId: string; rpIds: string[]; keyPair: CryptoKeyPair; staticPk: Uint8Array; file: Blob };
type Job = EncryptJob | DecryptJob;

const ctx = self as unknown as { onmessage: ((e: MessageEvent) => void) | null; postMessage: (m: unknown) => void };
const post = (m: unknown) => ctx.postMessage(m);
const progress = (done: number, total: number) => post({ kind: "progress", done, total });

function blobSource(blob: Blob, onRead?: (highWater: number) => void): ByteSource {
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

async function runEncrypt(job: EncryptJob): Promise<{ blob: Blob }> {
  const ns = new Namespace(job.rpId);
  const senderIdentity: Identity = { namespace: ns, keyPair: job.senderKeyPair, staticPkRaw: job.senderPk };
  const plaintext = blobSource(job.blob, (hw) => progress(hw, job.blob.size));
  const parts: Blob[] = [];
  for await (const piece of encryptStream({ senderIdentity, recipientPkRaw: job.recipientPk, namespace: ns, plaintext, metadata: job.metadata })) {
    parts.push(new Blob([piece as unknown as BlobPart]));
  }
  return { blob: new Blob(parts, { type: "application/octet-stream" }) };
}

async function runDecrypt(job: DecryptJob): Promise<{ blob: Blob; metadata: Metadata }> {
  const identity: Identity = { namespace: new Namespace(job.rpId), keyPair: job.keyPair, staticPkRaw: job.staticPk };
  const res = await decryptStream({ file: blobSource(job.file), namespaces: new NamespaceSet(job.rpIds), resolveIdentity: async () => identity });
  const total = res.metadata.originalSize;
  const parts: Blob[] = [];
  let done = 0;
  for await (const pt of res.chunks) {
    parts.push(new Blob([pt as unknown as BlobPart])); // only assembled + returned after full authentication
    done += pt.length;
    progress(done, total);
  }
  return { blob: new Blob(parts, { type: res.metadata.mimeType || "application/octet-stream" }), metadata: res.metadata };
}

ctx.onmessage = (e: MessageEvent) => {
  const job = e.data as Job;
  void (async () => {
    try {
      if (job.kind === "decrypt") {
        const { blob, metadata } = await runDecrypt(job);
        post({ kind: "done", blob, metadata });
      } else {
        const { blob } = await runEncrypt(job);
        post({ kind: "done", blob });
      }
    } catch (err) {
      const code = err instanceof FileKeyError ? err.code : "";
      post({ kind: "error", code, message: (err as Error)?.message ?? "worker error" });
    }
  })();
};
