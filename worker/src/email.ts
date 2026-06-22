// Outbound mail via the Cloudflare Email Service `send_email` Worker binding.
// One swappable surface: if the Beta send product ever disappoints, only this file
// changes (e.g. to Amazon SES). Each mail carries an HTML part (clean, single column,
// inline-styled for broad client support) AND a plain-text fallback with the same copy.
// Mail never carries the file or the real filename; the only variable echoed is the
// receiver's own link label, which is HTML-escaped before it touches the markup.

import type { Env } from "./types";

const BRAND = "#23A267"; // receive.link green

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
// Inline-styled fragments — email clients strip <style>/classes, so every rule is inline.
const wrap = (inner: string): string =>
  `<div style="max-width:480px;margin:0 auto;padding:12px 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#1a1a1a;">${inner}</div>`;
const intro = (html: string): string => `<div style="margin:0 0 6px;">${html}</div>`;
const head = (t: string): string => `<div style="font-size:18px;font-weight:700;color:#0e0e16;margin:28px 0 10px;">${t}</div>`;
const para = (html: string): string => `<div style="margin:0 0 14px;color:#3a3a3a;">${html}</div>`;
const rule = `<div style="border-top:1px solid #e6e6e6;margin:26px 0;"></div>`;
const button = (url: string, label: string): string =>
  `<div style="margin:8px 0 14px;"><a href="${url}" style="display:inline-block;background:${BRAND};color:#ffffff !important;text-decoration:none;font-weight:600;font-size:15px;padding:11px 22px;border-radius:8px;">${label}</a></div>`;
// Secondary action: a quiet text link, not a filled button (e.g. the "disable" link
// next to a primary "open the file" button).
const quietLink = (url: string, label: string): string =>
  `<div style="margin:10px 0 4px;"><a href="${url}" style="color:#1f9d57;text-decoration:underline;font-size:14px;">${label}</a></div>`;
// Fine print (expiry notices, "didn't request this" disclaimers): muted + smaller.
const note = (html: string): string =>
  `<div style="margin:0;color:#8a8a8a;font-size:13px;line-height:1.5;">${html}</div>`;
const urlBox = (url: string): string =>
  `<div style="background:#f4f4f5;border-radius:8px;padding:12px 14px;margin:6px 0 2px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:1.5;word-break:break-all;"><a href="${url}" style="color:#1f9d57;text-decoration:none;">${url}</a></div>`;

/** Setup-time email: the receiver clicks this once to confirm their address. */
export async function sendConfirmEmail(env: Env, to: string, confirmUrl: string, label: string): Promise<void> {
  const subject = "Confirmation link";
  const lbl = label ? ` "${label}"` : "";
  const text =
    `You're setting up a file link${lbl} on receive.link.\n\n` +
    `ONE MORE STEP\n` +
    `Click below to finish and get your share link. Then anyone with your link can send you files, and only you can open them:\n\n` +
    `${confirmUrl}\n\n` +
    `- - - - - -\n\n` +
    `This link expires in 1 hour. If you didn't request it, you can ignore this email.\n`;
  const html = wrap(
    intro(`You're setting up a file link${label ? ` <strong>"${esc(label)}"</strong>` : ""} on receive.link.`) +
      head("One more step") +
      para("Click below to finish and get your share link. Then anyone with your link can send you files, and only you can open them.") +
      button(confirmUrl, "Confirm your address") +
      rule +
      note("This link expires in 1 hour. If you didn't request it, you can ignore this email."),
  );
  await env.EMAIL.send({ to, from: `receive.link <${env.MAIL_FROM}>`, subject, text, html });
}

/** Post-confirm email: a durable copy of the receiver's link (to share) and their
 *  private manage/revoke link, so neither is lost if they close the tab. */
export async function sendDropLinkEmail(env: Env, to: string, dropUrl: string, manageUrl: string, label: string): Promise<void> {
  const subject = `Your share link is ready${label ? ` · ${label}` : ""}`;
  const lbl = label ? ` "${label}"` : "";
  const text =
    `Your share link${lbl} is ready.\n\n` +
    `SHARE THIS LINK\n` +
    `Give this link to anyone who should be able to send you files. Anything they send ` +
    `is encrypted so that only you can open it:\n\n` +
    `${dropUrl}\n\n` +
    `Show this link as a QR code:\n${dropUrl.replace("/#", "/qr#")}\n\n` +
    `- - - - - -\n\n` +
    `DISABLE THIS LINK\n` +
    `Keep this link private. If you ever want to stop receiving files through this ` +
    `receiver, use the link below:\n\n` +
    `${manageUrl}\n\n` +
    `- - - - - -\n\n` +
    `Only you can open the files. We can't see them, and we don't store your email address.\n`;
  const html = wrap(
    intro(`Your share link${label ? ` <strong>"${esc(label)}"</strong>` : ""} is ready.`) +
      head("Share this link") +
      para("Give this link to anyone who should be able to send you files.") +
      para(`Anything they send is encrypted so that <strong>only you can open it.</strong>`) +
      urlBox(dropUrl) +
      quietLink(dropUrl.replace("/#", "/qr#"), "Show as a QR code") +
      rule +
      head("Disable this link") +
      para("Keep this link private.") +
      para("If you ever want to stop receiving files through this receiver, use the link below.") +
      urlBox(manageUrl) +
      rule +
      para("Only you can open the files. We can't see them, and we don't store your email address."),
  );
  await env.EMAIL.send({ to, from: `receive.link <${env.MAIL_FROM}>`, subject, text, html });
}

/** Delivery email: someone sent a file; here is the link to open it. */
export async function sendDownloadEmail(env: Env, to: string, downloadUrl: string, label: string, manageUrl?: string): Promise<void> {
  // Append a short code from the download id so every delivery has a unique subject;
  // otherwise mail clients thread same-subject messages into one conversation. The
  // code is the start of the /d/<id> link, so it lines up with the download URL below.
  const ref = downloadUrl.split("/").pop()?.slice(0, 6) ?? "";
  const subject = `A file was sent to you${label ? ` · ${label}` : ""}${ref ? ` · #${ref}` : ""}`;
  const lbl = label ? ` "${label}"` : "";
  const text =
    `A file was sent to your link${lbl}.\n\n` +
    `OPEN THE FILE\n` +
    `This file is encrypted and can only be opened with your passkey:\n\n` +
    `${downloadUrl}\n\n` +
    `Link expires in 7 days.\n\n` +
    `- - - - - -\n\n` +
    `Only you can open this file.\n` +
    (manageUrl ? `\nNeed to stop receiving files through ${label ? `"${label}"` : "this link"}?\n${manageUrl}\n` : "");
  const html = wrap(
    intro(`A file was sent to your link${label ? ` <strong>"${esc(label)}"</strong>` : ""}.`) +
      head("Open the file") +
      para("This file is encrypted and can only be opened with your passkey.") +
      button(downloadUrl, "Open File") +
      para("Link expires in 7 days.") +
      rule +
      para("Only you can open this file.") +
      (manageUrl
        ? para(`Need to stop receiving files through ${label ? `<strong>${esc(label)}</strong>` : "this link"}?`) +
          quietLink(manageUrl, "Disable this link")
        : ""),
  );
  await env.EMAIL.send({ to, from: `receive.link <${env.MAIL_FROM}>`, subject, text, html });
}
