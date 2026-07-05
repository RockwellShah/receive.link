// Provider routing tests for outbound mail (email.ts sendMail): default = the Cloudflare send_email
// binding; EMAIL_PROVIDER="postmark" = the Postmark REST API (corporate-deliverability escape hatch).
// Exercised through a public sender (sendConfirmEmail) since sendMail is internal.
import { expect, test } from "bun:test";
import { sendConfirmEmail } from "./email";
import { makeTestEnv } from "./testing";

test("default provider: mail goes out via the Cloudflare binding (no Postmark call)", async () => {
  const h = await makeTestEnv();
  let fetched = false;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => { fetched = true; return new Response("{}", { status: 200 }); }) as unknown as typeof fetch;
  try {
    await sendConfirmEmail(h.env, "rcv@example.com", "https://x/confirm#n", "label");
  } finally {
    globalThis.fetch = realFetch;
  }
  expect(fetched).toBe(false);
  expect(h.email.sent.length).toBe(1);
  expect(h.email.sent[0]!.to).toBe("rcv@example.com");
  expect(h.email.sent[0]!.from).toContain(h.env.MAIL_FROM);
});

test("postmark provider: routes to the Postmark API with the token, maps fields, skips the binding", async () => {
  const h = await makeTestEnv({ EMAIL_PROVIDER: "postmark", POSTMARK_SERVER_TOKEN: "pm-test-token" });
  let url = "";
  let init: RequestInit | undefined;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (u: string, i: RequestInit) => { url = String(u); init = i; return new Response(JSON.stringify({ MessageID: "x" }), { status: 200 }); }) as unknown as typeof fetch;
  try {
    await sendConfirmEmail(h.env, "corp@bigco.com", "https://x/confirm#n", "Tax inbox");
  } finally {
    globalThis.fetch = realFetch;
  }
  expect(url).toBe("https://api.postmarkapp.com/email");
  const headers = init!.headers as Record<string, string>;
  expect(headers["x-postmark-server-token"]).toBe("pm-test-token");
  const body = JSON.parse(String(init!.body)) as { From: string; To: string; Subject: string; TextBody: string; HtmlBody: string; MessageStream: string };
  expect(body.To).toBe("corp@bigco.com");
  expect(body.From).toContain(h.env.MAIL_FROM);
  expect(body.Subject).toContain("Confirmation link");
  expect(body.TextBody).toContain("/confirm#n");
  expect(body.HtmlBody).toContain("/confirm#n");
  expect(body.MessageStream).toBe("outbound");
  expect(h.email.sent.length).toBe(0); // the binding was NOT used
});

test("postmark provider without a token fails loud (no silent fallback to the binding)", async () => {
  const h = await makeTestEnv({ EMAIL_PROVIDER: "postmark" }); // token missing
  await expect(sendConfirmEmail(h.env, "rcv@example.com", "https://x/c#n", "l")).rejects.toThrow("misconfigured");
  expect(h.email.sent.length).toBe(0);
});

test("postmark API error surfaces as a throw (callers treat it as email-failed)", async () => {
  const h = await makeTestEnv({ EMAIL_PROVIDER: "postmark", POSTMARK_SERVER_TOKEN: "pm-test-token" });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ ErrorCode: 300 }), { status: 422 })) as unknown as typeof fetch;
  try {
    await expect(sendConfirmEmail(h.env, "rcv@example.com", "https://x/c#n", "l")).rejects.toThrow("postmark send failed (422)");
  } finally {
    globalThis.fetch = realFetch;
  }
});
