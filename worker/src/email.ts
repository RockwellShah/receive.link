// Outbound mail via the Cloudflare Email Service `send_email` Worker binding.
// One swappable surface: if the Beta send product ever disappoints, only this
// file changes (e.g. to Amazon SES). Copy is deliberately plain, asks for
// nothing, and never carries the file or the real filename.

import type { Env } from "./types";

/** Setup-time email: the receiver clicks this once to confirm their address. */
export async function sendConfirmEmail(env: Env, to: string, confirmUrl: string, label: string): Promise<void> {
  const subject = "Confirm your FileKey Drop link";
  const text =
    `You're setting up a FileKey Drop link${label ? ` ("${label}")` : ""} so people can send you ` +
    `end-to-end encrypted files.\n\n` +
    `Confirm this address to finish:\n${confirmUrl}\n\n` +
    `If you didn't request this, ignore this email. This confirmation link expires in 1 hour.\n`;
  await env.EMAIL.send({ to, from: `FileKey Drop <${env.MAIL_FROM}>`, subject, text });
}

/** Post-confirm email: a durable copy of the receiver's Drop link (to share) and
 *  their private manage/revoke link, so neither is lost if they close the tab. */
export async function sendDropLinkEmail(env: Env, to: string, dropUrl: string, manageUrl: string, label: string): Promise<void> {
  const subject = `Your FileKey Drop link${label ? ` · ${label}` : ""}`;
  const text =
    `Your FileKey Drop link${label ? ` ("${label}")` : ""} is ready.\n\n` +
    `Share this link so anyone can send you files. Whatever they drop is end-to-end encrypted to your passkey:\n${dropUrl}\n\n` +
    `Keep this private link to turn your Drop link off later. Don't share it:\n${manageUrl}\n\n` +
    `We never see your files or store your email address.\n`;
  await env.EMAIL.send({ to, from: `FileKey Drop <${env.MAIL_FROM}>`, subject, text });
}

/** Delivery email: someone dropped a file; here is the link to open it. */
export async function sendDownloadEmail(env: Env, to: string, downloadUrl: string, label: string, manageUrl?: string): Promise<void> {
  // Append a short code from the download id so every delivery has a unique subject;
  // otherwise mail clients thread same-subject messages into one conversation. The
  // code is the start of the /d/<id> link, so it lines up with the download URL below.
  const ref = downloadUrl.split("/").pop()?.slice(0, 6) ?? "";
  const subject = `A file was sent to your FileKey Drop${label ? ` · ${label}` : ""}${ref ? ` · #${ref}` : ""}`;
  const text =
    `Someone dropped a file or folder for you${label ? ` ("${label}")` : ""}.\n\n` +
    `Open it in FileKey (you'll need your passkey):\n${downloadUrl}\n\n` +
    `This download link expires in 7 days. We can't read your files, and we don't store your email address.\n` +
    (manageUrl ? `\nWant to stop future drops to this link? Turn it off here:\n${manageUrl}\n` : "");
  await env.EMAIL.send({ to, from: `FileKey Drop <${env.MAIL_FROM}>`, subject, text });
}
