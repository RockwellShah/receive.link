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
  confirm(nonce: string): Promise<{ link: string }> {
    return this.postJson("/confirm", { nonce });
  }

  /** Upload step 1: verify the link + get a presigned R2 PUT URL. */
  uploadInit(payload: string, size: number): Promise<{ objectId: string; uploadUrl: string; expiresInSec: number }> {
    return this.postJson("/upload-init", { payload, size });
  }

  /** Upload step 2: PUT the ciphertext straight to R2 (bytes never touch the Worker). */
  async putToR2(uploadUrl: string, body: Blob | Uint8Array): Promise<void> {
    const res = await fetch(uploadUrl, { method: "PUT", body });
    if (!res.ok) throw new DropApiError(`upload to storage failed (${res.status})`, res.status);
  }

  /** Upload step 3: confirm the object + trigger the delivery email. */
  uploadComplete(payload: string, objectId: string): Promise<{ ok: true }> {
    return this.postJson("/upload-complete", { payload, objectId });
  }

  /** Receive: get a presigned R2 GET URL for an object id. */
  async fetchUrl(objectId: string): Promise<{ url: string }> {
    const res = await fetch(`${this.base}/fetch/${objectId}`);
    if (!res.ok) throw await asError(res);
    return (await res.json()) as { url: string };
  }
}
