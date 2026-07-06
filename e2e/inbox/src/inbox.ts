// E2E test inbox — a Cloudflare Email Worker. It receives mail routed to e2e[+tag]@receive.link,
// extracts the receive.link links (confirm / d/ / revoke / qr) from the raw MIME, stashes them in KV,
// and serves them back to the E2E suite over a token-gated GET /inbox?to=<addr>[&since=<ms>].
// TEST-ONLY: it only handles e2e* addresses and never touches real user mail. The Email Routing rule
// on the receive.link zone is what actually sends matching inbound mail here.

export interface Env {
  E2E_KV: KVNamespace;
  E2E_TOKEN: string;
}

interface StoredMail {
  to: string;
  from: string;
  subject: string;
  links: string[];
  ts: number;
}

// Receiver-facing links the worker emails: /confirm#<nonce>, /revoke#<token>, /qr#<payload> (hash),
// /credit#<magic-token> (the wallet sign-in), and /d/<id> (path). Pull them straight out of the raw
// MIME so we don't need a full MIME parser.
const LINK_RE =
  /https?:\/\/[^\s"'<>]*receive\.link\/(?:confirm|revoke|qr|credit)#[^\s"'<>]+|https?:\/\/[^\s"'<>]*receive\.link\/d\/[^\s"'<>]+/gi;

const isTestAddr = (to: string) => /^e2e(\+[^@]*)?@receive\.link$/.test(to);

export default {
  // Inbound mail. Only e2e* addresses should ever be routed here; we re-check as a backstop and ignore
  // anything else (so a misrouted real email is dropped, never stored).
  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    const to = (message.to || "").toLowerCase();
    if (!isTestAddr(to)) return;
    // Only accept mail from the app's own sender domain (receive.link / cf-bounce.receive.link). Drops
    // stray or injected inbound so a third party who mails e2e@receive.link can't poison the test inbox.
    const from = (message.from || "").toLowerCase();
    if (!/@([a-z0-9-]+\.)*receive\.link$/.test(from)) return;
    let raw = "";
    try {
      raw = await new Response(message.raw).text();
    } catch {
      /* unreadable body — store with no links so the test still sees the email arrived */
    }
    // Un-fold quoted-printable soft line breaks (`=\r\n`) before matching: the HTML part wraps long lines
    // mid-URL, which otherwise truncates the link (`...0KKO9=` instead of the full `...0KKO9stC3-w` nonce).
    const body = raw.replace(/=\r?\n/g, "");
    const links = [...new Set([...body.matchAll(LINK_RE)].map((m) => m[0]))];
    const rec: StoredMail = {
      to,
      from: message.from || "",
      subject: message.headers.get("subject") || "",
      links,
      ts: Date.now(),
    };
    // 1h TTL: a test inbox should self-clean, never accumulate.
    await env.E2E_KV.put(`mail:${to}:${rec.ts}`, JSON.stringify(rec), { expirationTtl: 3600 });
  },

  // The E2E suite reads captured mail here. Bearer-token gated. ?since=<ms> filters to mail newer than a
  // timestamp the test records right before it triggers the email (so it never reads a stale message).
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname !== "/inbox") return new Response("e2e inbox", { status: 200 });
    if (req.headers.get("authorization") !== `Bearer ${env.E2E_TOKEN}`) {
      return new Response("unauthorized", { status: 401 });
    }
    const to = (url.searchParams.get("to") || "").toLowerCase();
    if (!to || !isTestAddr(to)) return new Response("bad or missing ?to (must be an e2e address)", { status: 400 });
    const since = Number(url.searchParams.get("since") || "0");
    const { keys } = await env.E2E_KV.list({ prefix: `mail:${to}:` });
    const mails = (
      await Promise.all(
        keys.map((k) => env.E2E_KV.get(k.name).then((v) => (v ? (JSON.parse(v) as StoredMail) : null))),
      )
    )
      .filter((m): m is StoredMail => !!m && m.ts >= since)
      .sort((a, b) => b.ts - a.ts);
    return Response.json(mails, { headers: { "cache-control": "no-store" } });
  },
};
