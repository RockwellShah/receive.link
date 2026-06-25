// E2E suite for receive.link. Each feature is a "cell" — a named pass/fail check. The gate
// (EXPECTED_CRITICAL) fails unless every critical cell RAN and PASSED; a missing cell (harness threw
// before it ran) counts as a fail, never a silent green. Run: npm test.
//
// It drives the REAL staging.receive.link with a CDP virtual authenticator (fakes the passkey + PRF, so
// the flows run headless) and the B1 inbox worker (e2e/inbox) for the email-gated steps. See FEATURES.md.
//
// Shape: one receiver session (rx) keeps its passkey/authenticator across create→confirm→download→qr→
// revoke; each sender (tx) is a fresh anonymous session (no passkey — the upload identity is throwaway).
import { chromium } from "playwright";
import { readFileSync } from "node:fs";
import { STAGING, newSession, pollInbox, INBOX_ADDR, API_BASE, makeTestFile } from "./lib.mjs";

// Don't let an orphaned promise (e.g. a download that never fires after an error) crash the run before
// the result matrix prints.
process.on("unhandledRejection", (e) => console.log("  unhandledRejection:", String((e && e.message) || e).slice(0, 80)));

const results = [];
let harnessError = null;
const record = (name, critical, pass, detail = "") => {
  results.push({ name, critical, pass });
  console.log(`  [${pass ? "PASS" : "FAIL"}] ${name}${detail ? " — " + detail : ""}`);
};

const EXPECTED_CRITICAL = [
  "create: passkey enroll + register → sent",
  "confirm: nonce → share link revealed",
  "upload: sender encrypts + uploads → Sent!",
  "download: receiver decrypts → bytes match",
  "qr: /qr verifies + renders",
  "revoke: /revoke page turns off the link",
  "revoke: re-upload fails closed",
];

// Drop a known file on a share link as a fresh anonymous sender. Returns the visible outcome text.
// `expectSent` true ⇒ wait for "Sent!"; false ⇒ wait for the "turned off"/error path (fail-closed check).
async function sendAs(browser, shareUrl, file, expectSent) {
  const tx = await newSession(browser, (...a) => console.log("     [tx]", ...a));
  // Capture the Worker's /upload-init status so the fail-closed cell can require the revocation-specific
  // 410 — not just any error text. ("isn't valid" comes from bad signatures, not revocation; codex P1.)
  let initStatus = 0;
  tx.page.on("response", (r) => { if (r.request().method() === "POST" && r.url().includes("/upload-init")) initStatus = r.status(); });
  try {
    await tx.page.goto(shareUrl, { waitUntil: "domcontentloaded", timeout: 60_000 }); // /#code bounces to /u#code
    await tx.page.locator("#file_input").waitFor({ state: "attached", timeout: 30_000 });
    await tx.page.locator("#main_inner").getByText(/Send files to/i).waitFor({ timeout: 30_000 });
    await tx.page.setInputFiles("#file_input", file.path);
    if (expectSent) {
      await tx.page.locator("#main_inner").getByText(/Sent!/).waitFor({ timeout: 120_000 });
      return { sent: true, initStatus };
    }
    // fail-closed: a revoked link ⇒ /upload-init 410 ⇒ the "turned off" message (revocation-specific only).
    const blocked = await tx.page
      .locator("#main_inner")
      .getByText(/turned off/i)
      .waitFor({ timeout: 90_000 })
      .then(() => true)
      .catch(() => false);
    const sent = await tx.page.locator("#main_inner").getByText(/Sent!/).count();
    return { blocked, sent: sent > 0, initStatus };
  } finally {
    await tx.context.close();
  }
}

async function roundTrip(browser) {
  const tag = "c" + Date.now().toString(36);
  const email = INBOX_ADDR;
  const t0 = Date.now() - 5_000;
  const file = makeTestFile();
  const rx = await newSession(browser, (...a) => console.log("     [rx]", ...a));
  try {
    // 1. create (S1/H1-H6)
    await rx.page.goto(STAGING + "/", { waitUntil: "domcontentloaded", timeout: 60_000 });
    await rx.page.locator("[data-create]").first().click();
    await rx.page.locator("#cmodal").waitFor({ state: "visible", timeout: 15_000 });
    await rx.page.fill("#cmodal input[name=email]", email);
    await rx.page.fill("#cmodal input[name=label]", "e2e " + tag);
    await rx.page.locator('#cmodal [data-state="form"] .cmbtn').click();
    await rx.page.locator('#cmodal [data-state="sent"]').waitFor({ state: "visible", timeout: 60_000 });
    record("create: passkey enroll + register → sent", true, true, email);

    // 2. confirm (S4/R2)
    const { link: confirmLink } = await pollInbox(email, { since: t0, match: /\/confirm#/, timeoutMs: 90_000 });
    await rx.page.goto(confirmLink, { waitUntil: "domcontentloaded", timeout: 60_000 });
    await rx.page.locator('.st[data-state="reveal"]').waitFor({ state: "visible", timeout: 45_000 });
    const shareUrl = (await rx.page.locator("#url").innerText()).trim();
    record("confirm: nonce → share link revealed", true, /\/#[A-Za-z0-9_-]+$/.test(shareUrl), shareUrl.slice(0, 56));

    // 3. upload (S5/S6) — fresh sender
    const tUpload = Date.now() - 5_000;
    const up = await sendAs(browser, shareUrl, file, true);
    record("upload: sender encrypts + uploads → Sent!", true, up.sent === true, file.name);

    // 4. download (S8) — receiver, same passkey, bytes must match. Save is a <span class="save_act">.
    const { link: dlLink, mail: delivery } = await pollInbox(email, { since: tUpload, match: /\/d\//, timeoutMs: 120_000 });
    await rx.page.goto(dlLink, { waitUntil: "domcontentloaded", timeout: 60_000 });
    let dlMatch = false, dlDetail = "";
    try {
      await rx.page.locator("#main_inner").getByText(/Ready to save/i).waitFor({ timeout: 90_000 });
      const dlPromise = rx.page.waitForEvent("download", { timeout: 90_000 }).catch(() => null);
      await rx.page.locator("#main_inner .save_act").first().click();
      const dl = await dlPromise;
      if (dl) {
        const saved = readFileSync(await dl.path());
        dlMatch = Buffer.compare(saved, file.bytes) === 0;
        dlDetail = `${saved.length}B vs ${file.bytes.length}B`;
      } else dlDetail = "no download event";
    } catch (e) { dlDetail = "err: " + String((e && e.message) || e).slice(0, 50); }
    record("download: receiver decrypts → bytes match", true, dlMatch, dlDetail);

    // diagnostic: what state did a result-page route actually reach?
    const pageState = (page) => page.evaluate(() => ({
      p: location.pathname, h: location.hash.length,
      vis: [...document.querySelectorAll(".st:not([hidden])")].map((e) => e.getAttribute("data-state")),
      err: document.getElementById("errmsg")?.textContent || "",
      qr: document.querySelectorAll("#qr img, #qr svg").length,
    }));

    // 5. qr (S11/R8). /qr verifies the signed payload then reveals (QR is a raster <img>). Critical: a
    // broken /qr ships a dead feature. (Currently failing — the /result routing bug; see step 6 note.)
    const qrUrl = shareUrl.replace("/#", "/qr#");
    let qrOk = false;
    try {
      await rx.page.goto(qrUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
      await rx.page.waitForTimeout(2500);
      const s = await pageState(rx.page);
      console.log("     [qr] " + JSON.stringify(s));
      qrOk = s.vis.includes("reveal") && s.qr > 0;
    } catch (e) { console.log("     [qr] " + String((e && e.message) || e).slice(0, 60)); }
    record("qr: /qr verifies + renders", true, qrOk, qrOk ? "" : "BUG: /qr 308→/result/ ⇒ confirmFlow");

    // 6. revoke UI (S10/R6) — the /revoke page turns the link off. BUG: /confirm, /revoke, /qr all 308 to
    // /result/, so home-result.ts's pathname dispatch always runs confirmFlow → /revoke + /qr are broken.
    const revokeLink = (delivery.links || []).find((l) => /\/revoke#/.test(l));
    let offOk = false;
    if (revokeLink) {
      try {
        await rx.page.goto(revokeLink, { waitUntil: "domcontentloaded", timeout: 60_000 });
        await rx.page.waitForTimeout(1500);
        const s = await pageState(rx.page);
        console.log("     [revoke-ui] " + JSON.stringify(s));
        if (s.vis.includes("revoke-confirm")) {
          await rx.page.locator("#revyes").click();
          offOk = await rx.page.locator('.st[data-state="revoke-done"]').waitFor({ state: "visible", timeout: 30_000 }).then(() => true).catch(() => false);
        }
      } catch (e) { console.log("     [revoke-ui] " + String((e && e.message) || e).slice(0, 60)); }
    }
    record("revoke: /revoke page turns off the link", true, offOk, offOk ? "" : "BUG: /revoke 308→/result/ ⇒ confirmFlow");

    // 7. fail-closed SECURITY check, independent of the broken UI: revoke via the Worker API, then a
    // re-upload MUST be rejected. Proves the worker enforces revocation even while the page is broken.
    let failClosed = false, fcDetail = "no revoke token in delivery email";
    const token = revokeLink ? revokeLink.split("#")[1] : "";
    if (token) {
      const res = await fetch(API_BASE + "/revoke", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
      const re = await sendAs(browser, shareUrl, file, false);
      failClosed = res.ok && re.initStatus === 410 && re.blocked === true && re.sent === false;
      fcDetail = `api revoke ${res.status}, upload-init ${re.initStatus}, re-upload ${re.blocked ? "blocked" : re.sent ? "SENT (LEAK!)" : "?"}`;
    }
    record("revoke: re-upload fails closed", true, failClosed, fcDetail);
  } finally {
    await rx.context.close();
  }
}

async function main() {
  const exe = process.env.RL_E2E_CHROME;
  const browser = await chromium.launch({ headless: true, ...(exe ? { executablePath: exe } : {}) });
  try {
    await roundTrip(browser);
  } catch (e) {
    harnessError = String((e && e.stack) || e);
    console.log("  HARNESS ERROR: " + harnessError.split("\n")[0]);
  } finally {
    await browser.close();
  }

  const ran = new Set(results.map((r) => r.name));
  const missing = EXPECTED_CRITICAL.filter((n) => !ran.has(n));
  console.log("\n================ RESULT MATRIX ================");
  for (const r of results) console.log(`  ${r.pass ? "✅" : "❌"} ${r.critical ? "[critical] " : "[extra]    "}${r.name}`);
  for (const n of missing) console.log(`  ❌ [critical] ${n} (NEVER RAN — counted as FAIL)`);
  const critFail = results.filter((r) => r.critical && !r.pass);
  console.log("==============================================");
  if (harnessError) console.log("HARNESS ERROR: " + harnessError.split("\n")[0]);
  const ok = !harnessError && missing.length === 0 && critFail.length === 0;
  console.log(`critical: ${results.filter((r) => r.critical && r.pass).length}/${EXPECTED_CRITICAL.length} pass`);
  console.log(`extra:    ${results.filter((r) => !r.critical && r.pass).length}/${results.filter((r) => !r.critical).length} pass`);
  console.log("SUITE: " + (ok ? "PASS" : "FAIL"));
  process.exitCode = ok ? 0 : 1;
}

main();
