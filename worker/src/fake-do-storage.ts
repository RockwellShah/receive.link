// A Map-backed fake of the Durable Object storage API, enough to unit-test ReceiverAccount's real code
// (get/put single+batch, delete single+batch, prefix list with pagination, alarm). NOT production code —
// imported only by receiver.test.ts. Mirrors the DO semantics the DO relies on: single-threaded, and a
// multi-key put({...}) commits its keys together.
export class FakeDOStorage {
  readonly map = new Map<string, unknown>();
  private alarm: number | null = null;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.map.has(key) ? (structuredClone(this.map.get(key)) as T) : undefined;
  }

  async put(keyOrEntries: string | Record<string, unknown>, value?: unknown): Promise<void> {
    if (typeof keyOrEntries === "string") {
      this.map.set(keyOrEntries, structuredClone(value));
      return;
    }
    const keys = Object.keys(keyOrEntries);
    if (keys.length > 128) throw new Error(`put() accepts at most 128 keys, got ${keys.length}`); // mirror the DO limit
    for (const k of keys) this.map.set(k, structuredClone(keyOrEntries[k]));
  }

  async delete(keyOrKeys: string | string[]): Promise<void> {
    const keys = Array.isArray(keyOrKeys) ? keyOrKeys : [keyOrKeys];
    for (const k of keys) this.map.delete(k);
  }

  async list<T = unknown>(opts: { prefix?: string; startAfter?: string; limit?: number } = {}): Promise<Map<string, T>> {
    const { prefix, startAfter, limit } = opts;
    let keys = [...this.map.keys()].sort();
    if (prefix) keys = keys.filter((k) => k.startsWith(prefix));
    if (startAfter !== undefined) keys = keys.filter((k) => k > startAfter);
    if (limit !== undefined) keys = keys.slice(0, limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, structuredClone(this.map.get(k)) as T);
    return out;
  }

  async getAlarm(): Promise<number | null> {
    return this.alarm;
  }
  async setAlarm(t: number): Promise<void> {
    this.alarm = t;
  }
  async deleteAlarm(): Promise<void> {
    this.alarm = null;
  }
}
