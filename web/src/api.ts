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

  private async postJson<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
    const res = await fetch(`${this.base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
    if (!res.ok) throw await asError(res);
    return (await res.json()) as T;
  }

  /** Setup: ask the Worker to email a confirmation link. Always resolves (202). */
  register(body: { sealedEmail: string; shareKey: string; label: string }): Promise<{ ok: true }> {
    return this.postJson("/register", body);
  }

  /** Confirm: exchange the one-time nonce for the finished signed Drop link. `billingEnabled` gates the
   *  result page's free-credit messaging (the worker is the source of truth). */
  confirm(nonce: string): Promise<{ link: string; revokeToken: string; billingEnabled?: boolean }> {
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
  uploadParts(payload: string, objectId: string, from: number, count: number, signal?: AbortSignal): Promise<{ partUrls: PartUrl[] }> {
    return this.postJson("/upload-parts", { payload, objectId, from, count }, signal);
  }

  /** Upload step 2 (single): PUT the ciphertext straight to R2 (bytes never touch the Worker). */
  async putToR2(uploadUrl: string, body: Blob | Uint8Array, opts?: { signal?: AbortSignal }): Promise<void> {
    const res = await fetch(uploadUrl, { method: "PUT", body: body as BodyInit, signal: opts?.signal });
    if (!res.ok) throw new DropApiError(`upload to storage failed (${res.status})`, res.status);
  }

  /** Upload step 2 (multipart): PUT one part to R2; returns its ETag (needed to complete). Uses XHR (not
   *  fetch) so we get byte-level upload progress and a real mid-flight abort — both of which fetch lacks. */
  async putPart(url: string, body: Blob | Uint8Array, opts?: { onProgress?: (sent: number) => void; signal?: AbortSignal }): Promise<string> {
    return await new Promise<string>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", url);
      if (opts?.onProgress) xhr.upload.onprogress = (e) => opts.onProgress!(e.loaded);
      const signal = opts?.signal;
      const onAbort = () => xhr.abort();
      // Remove the abort listener once this PUT settles. {once:true} only fires on abort, so on success
      // it would otherwise stay on the shared signal forever, retaining this XHR — thousands leak per
      // large upload.
      const cleanup = () => { if (signal) signal.removeEventListener("abort", onAbort); };
      xhr.onload = () => {
        cleanup();
        if (xhr.status < 200 || xhr.status >= 300) { reject(new DropApiError(`part upload failed (${xhr.status})`, xhr.status)); return; }
        const etag = xhr.getResponseHeader("ETag") ?? xhr.getResponseHeader("etag");
        if (!etag) { reject(new DropApiError("storage returned no ETag (CORS must expose ETag)", xhr.status)); return; }
        resolve(etag);
      };
      xhr.onerror = () => { cleanup(); reject(new DropApiError("part upload network error", 0)); };
      xhr.onabort = () => { cleanup(); reject(new DropApiError("part upload aborted", 0)); };
      if (signal) {
        if (signal.aborted) { reject(new DropApiError("part upload aborted", 0)); return; }
        signal.addEventListener("abort", onAbort);
      }
      xhr.send(body as XMLHttpRequestBodyInit);
    });
  }

  /**
   * Upload step 3: confirm the object + trigger the delivery email. `parts` for multipart. Retries on
   * transient 409 (another complete in progress) and 502 (assembly/email blip): the Worker makes these
   * safe to repeat (completion is idempotent + retry-safe), so a recoverable race resolves itself
   * instead of failing the send. Terminal errors (400/410/413/422/507) are not retried.
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

  /** Download gate step 1: request a sealed-nonce challenge for a delivered object. The returned `sealed`
   *  (base64url enc||ct) only the receiver's passkey identity can open. */
  fetchChallenge(objectId: string): Promise<{ challengeId: string; sealed: string }> {
    return this.postJson("/fetch/challenge", { objectId });
  }

  /** Download gate (free preview): submit the proof -> the head+metadata bytes. The Worker serves them
   *  directly (a presigned URL would be all-or-nothing, i.e. a free full download), so this returns raw
   *  ciphertext prefix bytes for the client to decrypt into the filename + size. When billing is on the
   *  Worker also stamps the receiver's balance + tier into response headers (X-RL-Credit / X-RL-Tier);
   *  `credit` is undefined when those headers are absent (billing off, or a legacy binding with no rid). */
  async fetchPreview(challengeId: string, proof: string): Promise<{ prefix: Uint8Array<ArrayBuffer>; credit?: { balanceBytes: number; tier: "free" | "paid" } }> {
    const res = await fetch(`${this.base}/fetch/preview`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ challengeId, proof }),
    });
    if (!res.ok) throw await asError(res);
    const prefix = new Uint8Array(await res.arrayBuffer());
    const rawCredit = res.headers.get("X-RL-Credit");
    const rawTier = res.headers.get("X-RL-Tier");
    // Only surface credit when BOTH headers are present and parse cleanly (billing on); any gap = billing
    // off, so the page renders no credit UI.
    const balanceBytes = rawCredit !== null && /^\d+$/.test(rawCredit) ? Number(rawCredit) : NaN; // non-negative integer only; reject "", whitespace, negative, fractional
    const tier: "free" | "paid" | undefined = rawTier === "free" || rawTier === "paid" ? rawTier : undefined;
    const credit: { balanceBytes: number; tier: "free" | "paid" } | undefined =
      Number.isFinite(balanceBytes) && tier ? { balanceBytes, tier } : undefined;
    return { prefix, credit };
  }

  /** Download gate (charged download): submit the proof -> a short-lived presigned GET URL, or a
   *  needs-funds signal (HTTP 402) the caller turns into the "add credit to unlock" prompt. */
  async fetchDownload(challengeId: string, proof: string): Promise<{ url: string; expiresInSec: number } | { needsFunds: true; needBytes: number; balanceBytes: number }> {
    const res = await fetch(`${this.base}/fetch/download`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ challengeId, proof }),
    });
    if (res.status === 402) {
      const b = (await res.json().catch(() => ({}))) as { needBytes?: number; balanceBytes?: number };
      return { needsFunds: true, needBytes: b.needBytes ?? 0, balanceBytes: b.balanceBytes ?? 0 };
    }
    if (!res.ok) throw await asError(res);
    return (await res.json()) as { url: string; expiresInSec: number };
  }

  /** The prepaid credit tiers at the current price (for the top-up picker; labels track the price knob). */
  async billingPacks(): Promise<{ packs: { id: string; label: string }[] }> {
    const res = await fetch(`${this.base}/billing/packs`);
    if (!res.ok) throw await asError(res);
    return (await res.json()) as { packs: { id: string; label: string }[] };
  }

  /** Start a top-up: prove possession of the file being unlocked (so the server credits the owning
   *  account) and get a Stripe-hosted Checkout URL to redirect to. */
  billingCheckout(challengeId: string, proof: string, pack: string): Promise<{ url: string }> {
    return this.postJson("/billing/checkout", { challengeId, proof, pack });
  }

  /** Receive: remove a delivered object from storage after saving it (frees R2 + clears the server copy). */
  discard(objectId: string): Promise<{ ok: true }> {
    return this.postJson("/discard", { objectId });
  }

  // ---- Account wallet (Phase 2a): magic-link sign-in -> session -> balance + add credit (no file needed) ----

  /** Ask the Worker to email a magic sign-in link. Always resolves (uniform 202; never an account oracle). */
  accountLogin(sealedEmail: string): Promise<{ ok: true }> {
    return this.postJson("/account/login", { sealedEmail });
  }

  /** Redeem an emailed magic token for a 30-min session token + the opening balance (so the page renders
   *  without a second round trip). Throws DropApiError(401) if the link expired / was already used. */
  accountSession(magicToken: string): Promise<{ token: string; tier: "free" | "paid"; balanceBytes: number }> {
    return this.postJson("/account/session", { magicToken });
  }

  private async postAuthed<T>(path: string, token: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await asError(res);
    return (await res.json()) as T;
  }

  /** Current balance + tier for a session (Authorization: Bearer). 401 once the 30-min session lapses. */
  accountSummary(token: string): Promise<{ tier: "free" | "paid"; balanceBytes: number }> {
    return this.postAuthed("/account/summary", token, {});
  }

  /** Start a top-up from the account page (Authorization: Bearer) -> a Stripe-hosted Checkout URL. */
  accountCheckout(token: string, pack: string): Promise<{ url: string }> {
    return this.postAuthed("/account/checkout", token, { pack });
  }
}
