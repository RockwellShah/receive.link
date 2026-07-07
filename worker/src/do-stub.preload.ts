// bun test preload (see bunfig.toml): make `import { DurableObject } from "cloudflare:workers"` resolve
// to a no-op base class so the real Durable Objects (receiver.ts) can be unit-tested against a fake
// storage. Only activates for that one module; every other test is unaffected.
import { plugin } from "bun";

plugin({
  name: "cloudflare-workers-stub",
  setup(build) {
    build.module("cloudflare:workers", () => ({
      loader: "object",
      exports: {
        DurableObject: class DurableObject {
          ctx: unknown;
          env: unknown;
          constructor(ctx: unknown, env: unknown) {
            this.ctx = ctx;
            this.env = env;
          }
        },
      },
    }));
  },
});
