// E2E harness for receive.link. Playwright + a CDP virtual authenticator (fakes the passkey + the PRF
// extension, so the create/unlock flows run fully headless with no human) + a poller for the B1 test
// inbox (e2e/inbox/). Node, ESM. The cells live in run.mjs; this file is the reusable plumbing.
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Target. Override with RL_E2E_BASE to point at localhost or a preview. Default = the real staging.
export const STAGING = process.env.RL_E2E_BASE || "https://staging.receive.link";

// The B1 email-capture worker (e2e/inbox/). Reads the gitignored token that the worker also holds as a
// secret (E2E_TOKEN). The suite polls this for the confirm + delivery links that arrive by email.
const INBOX_URL = process.env.RL_E2E_INBOX || "https://receive-link-e2e-inbox.rockwellshah.workers.dev";
const INBOX_TOKEN = readFileSync(new URL("./inbox/.token", import.meta.url), "utf8").trim();

// Virtual authenticator: CTAP 2.1 + PRF, internal transport, auto user-verification. Mirrors the config
// FileKey's suite uses so navigator.credentials.create()/get() and the PRF extension resolve headless.
export const VAUTH = {
  protocol: "ctap2",
  ctap2Version: "ctap2_1",
  transport: "internal",
  hasResidentKey: true,
  hasUserVerification: true,
  hasPrf: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
};

// A fresh browser context wired to its own virtual authenticator. Returns the page, the CDP client, and
// the authenticatorId (so a cell can later remove the credential to simulate a deleted passkey).
export async function newSession(browser, onLog = () => {}) {
  const context = await browser.newContext({ acceptDownloads: true, reducedMotion: "reduce" });
  const page = await context.newPage();
  // Force the capturable download path: with showSaveFilePicker present, saveDecryptedStream uses the
  // File System Access API (a native dialog Playwright can't drive). Undefining it falls back to an
  // <a download> blob, which Playwright captures via the 'download' event. (Mirrors FileKey's harness.)
  await page.addInitScript(() => {
    try { Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true }); } catch {}
  });
  page.on("pageerror", (e) => onLog("PAGEERROR: " + e.message));
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", { options: VAUTH });
  return { context, page, client, authenticatorId };
}

// Poll the test inbox until a mail to `to` (newer than `since` ms) has a link matching `match`. Returns
// { link, mail }. Throws on timeout. Used for the email-gated steps (confirm link, delivery /d/ link).
export async function pollInbox(to, { since = 0, match = /./, timeoutMs = 90000, intervalMs = 5000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = "no mail yet";
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${INBOX_URL}/inbox?to=${encodeURIComponent(to)}&since=${since}`, {
        headers: { authorization: `Bearer ${INBOX_TOKEN}` },
      });
      if (res.ok) {
        const mails = await res.json();
        for (const m of mails) {
          const link = (m.links || []).find((l) => match.test(l));
          if (link) return { link, mail: m };
        }
        lastErr = `${mails.length} mail(s) to ${to}, none matching ${match}`;
      } else {
        lastErr = `inbox responded ${res.status}`;
      }
    } catch (e) {
      lastErr = String((e && e.message) || e);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`pollInbox(${to}, ${match}): ${lastErr} after ${timeoutMs}ms`);
}

// The test recipient. The receive.link Email Routing rule targets this EXACT address, so the suite uses
// it (not a +tag) and disambiguates runs with pollInbox's ?since filter. Per-run +tag isolation (for
// parallel runs) would need the receive.link catch-all pointed at the inbox worker.
export const INBOX_ADDR = "e2e@receive.link";

// The staging Worker (the app's apiBase for staging.receive.link). Used to drive endpoints directly,
// e.g. revoke for the fail-closed security check independent of the result-page UI. node fetch sends no
// Origin, so the Worker's cross-origin POST guard allows it.
export const API_BASE = "https://filekey-drop-staging.rockwellshah.workers.dev";

// A known random file for the upload→download bytes-match test. Returns { path, bytes, name }.
export function makeTestFile(name = "e2e-payload.bin", size = 5000) {
  const bytes = randomBytes(size);
  const path = join(mkdtempSync(join(tmpdir(), "rl-e2e-")), name);
  writeFileSync(path, bytes);
  return { path, bytes, name };
}

// Remove the virtual authenticator's credential(s) to simulate "passkey deleted on this device" — the
// recovery path. After this a get() assertion fails (NotAllowedError) like a real deleted passkey.
export async function deleteCredentials(client, authenticatorId) {
  const { credentials } = await client.send("WebAuthn.getCredentials", { authenticatorId });
  for (const c of credentials) {
    await client.send("WebAuthn.removeCredential", { authenticatorId, credentialId: c.credentialId });
  }
  return credentials.length;
}
