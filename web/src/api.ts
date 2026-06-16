// Typed client for the Drop Worker. Thin wrappers + uniform error handling.

export class DropApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "DropApiError";
  }
}

async function asError(res: Response): Promise<DropApiError> {
  let msg = `request failed (${res.status})`;
  try {
    const body = (await res.json()) as { error?: string };
    if (body?.error) msg = body.error;
  } catch {
    /* non-JSON body */
  }
  return new DropApiError(msg, res.status);
}

export interface PartUrl {
  partNumber: number;
  url: string;
}
/** upload-init response: small files get one PUT URL; large files get a multipart plan. */
export type UploadInit =
  | { mode: "single"; objectId: string; uploadUrl: string; expiresInSec: number }
  | {
      mode: "multipart";
      objectId: string;
      uploadId: string;
      partSize: number;
      partCount: number;
      partUrls: PartUrl[];
      batchSize: number;
      expiresInSec: number;
    };

export class DropApi {
  constructor(private readonly base: string) {}

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await asError(res);
    return (await res.json()) as T;
  }

  /** Setup: ask the Worker to email a confirmation link. Always resolves (202). */
  register(body: { sealedEmail: string; shareKey: string; label: string }): Promise<{ ok: true }> {
    return this.postJson("/register", body);
  }

  /** Confirm: exchange the one-time nonce for the finished signed Drop link. */
  confirm(nonce: string): Promise<{ link: string; revokeToken: string }> {
    return this.postJson("/confirm", { nonce });
  }

  /** Turn off a Drop link using the receiver's private revoke token. */
  revoke(token: string): Promise<{ ok: true }> {
    return this.postJson("/revoke", { token });
  }

  /** Upload step 1: verify the link + get an upload descriptor (single PUT or multipart). */
  uploadInit(payload: string, size: number): Promise<UploadInit> {
    return this.postJson("/upload-init", { payload, size });
  }

  /** Multipart: presign the next batch of UploadPart URLs on demand. */
  uploadParts(payload: string, objectId: string, from: number, count: number): Promise<{ partUrls: PartUrl[] }> {
    return this.postJson("/upload-parts", { payload, objectId, from, count });
  }

  /** Upload step 2 (single): PUT the ciphertext straight to R2 (bytes never touch the Worker). */
  async putToR2(uploadUrl: string, body: Blob | Uint8Array): Promise<void> {
    const res = await fetch(uploadUrl, { method: "PUT", body: body as BodyInit });
    if (!res.ok) throw new DropApiError(`upload to storage failed (${res.status})`, res.status);
  }

  /** Upload step 2 (multipart): PUT one part to R2; returns its ETag (needed to complete). */
  async putPart(url: string, body: Blob | Uint8Array): Promise<string> {
    const res = await fetch(url, { method: "PUT", body: body as BodyInit });
    if (!res.ok) throw new DropApiError(`part upload failed (${res.status})`, res.status);
    const etag = res.headers.get("ETag") ?? res.headers.get("etag");
    if (!etag) throw new DropApiError("storage returned no ETag (CORS must expose ETag)", res.status);
    return etag;
  }

  /**
   * Upload step 3: confirm the object + trigger the delivery email. `parts` for multipart. Retries on
   * transient 409 (another complete in progress) and 502 (assembly/email blip): the Worker makes these
   * safe to repeat (completion is idempotent + retry-safe), so a recoverable race resolves itself
   * instead of failing the send. Terminal errors (400/410/413/422) are not retried.
   */
  async uploadComplete(payload: string, objectId: string, parts?: { partNumber: number; etag: string }[]): Promise<{ ok: true }> {
    const body = parts ? { payload, objectId, parts } : { payload, objectId };
    let delay = 1000;
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.postJson<{ ok: true }>("/upload-complete", body);
      } catch (e) {
        const retryable = e instanceof DropApiError && (e.status === 409 || e.status === 502);
        if (!retryable || attempt >= 4) throw e;
        await new Promise((r) => setTimeout(r, delay));
        delay *= 2;
      }
    }
  }

  /** Cancel an in-progress multipart upload (frees the staged parts on R2). */
  uploadAbort(payload: string, objectId: string): Promise<{ ok: true }> {
    return this.postJson("/upload-abort", { payload, objectId });
  }

  /** Receive: get a presigned R2 GET URL for an object id. */
  async fetchUrl(objectId: string): Promise<{ url: string }> {
    const res = await fetch(`${this.base}/fetch/${objectId}`);
    if (!res.ok) throw await asError(res);
    return (await res.json()) as { url: string };
  }
}
