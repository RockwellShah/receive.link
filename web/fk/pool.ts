// Bounded-concurrency upload pool for multipart uploads. Pure orchestration — no DOM, no crypto, no
// network client — so it unit-tests in isolation. Drive an async generator of already-encrypted parts
// through up to `concurrency` concurrent uploads. The generator (encryption) stays sequential and is
// paced by backpressure, so at most `concurrency` part buffers are alive at once (memory ~ concurrency
// x partSize). The first upload or encryption error stops the pool and rejects; the caller aborts the
// multipart. Parts come back sorted ascending by part number (what CompleteMultipartUpload wants).

export interface UploadedPart {
  partNumber: number;
  etag: string;
}

export async function uploadPartsPool(
  parts: AsyncGenerator<Uint8Array>,
  concurrency: number,
  upload: (partNumber: number, bytes: Uint8Array) => Promise<string>,
  onConfirmed?: (bytes: number) => void,
): Promise<UploadedPart[]> {
  const done: UploadedPart[] = [];
  const inFlight = new Set<Promise<void>>();
  let partNumber = 1;
  let failure: unknown = null;
  const launch = (n: number, bytes: Uint8Array) => {
    const task = upload(n, bytes)
      .then((etag) => {
        done.push({ partNumber: n, etag });
        onConfirmed?.(bytes.length);
      })
      .catch((e) => {
        failure ??= e; // capture the first error; keeps the rejection handled
      })
      .finally(() => inFlight.delete(task));
    inFlight.add(task);
  };
  // Drive the generator manually so we check `failure` BEFORE pulling (encrypting) the next part — a
  // for-await would encrypt one extra part past a failure before the loop could break.
  const iter = parts[Symbol.asyncIterator]();
  try {
    while (!failure) {
      const next = await iter.next();
      if (next.done) break;
      launch(partNumber++, next.value);
      // Backpressure: don't pull (encrypt) the next part until a slot frees.
      while (inFlight.size >= concurrency && !failure) await Promise.race(inFlight);
    }
  } catch (e) {
    failure ??= e; // the generator (encryption) threw
  } finally {
    await iter.return?.(undefined).catch(() => {}); // stop encryption promptly on failure/abort
  }
  await Promise.allSettled(inFlight); // let every in-flight upload settle (each captures its own error)
  if (failure) throw failure;
  done.sort((a, b) => a.partNumber - b.partNumber);
  return done;
}
