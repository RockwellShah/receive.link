// Native delivery notifications. The Worker does not need APNs-specific code in
// tests/dev: a PUSH binding can capture messages. Production can either provide
// that binding through an adapter or configure an APNS_WEBHOOK_URL relay.

import { logEvent } from "./http";
import type { Env } from "./types";

export interface NativeDevice {
  installId: string;
  token: string;
  platform: "ios";
  environment: "development" | "production";
}

export async function sendNativeDownloadNotification(
  env: Env,
  device: NativeDevice,
  message: { downloadUrl: string; objectId: string; linkId: string; label: string },
): Promise<boolean> {
  const title = "A file was sent to your Envoy Drop";
  const body = message.label ? `Ready in ${message.label}.` : "Open Envoy to save it.";
  if (env.PUSH) {
    await env.PUSH.send({
      token: device.token,
      environment: device.environment,
      title,
      body,
      url: message.downloadUrl,
      objectId: message.objectId,
      linkId: message.linkId,
      label: message.label || undefined,
    });
    return true;
  }
  if (env.APNS_WEBHOOK_URL && env.APNS_AUTH_TOKEN) {
    const res = await fetch(env.APNS_WEBHOOK_URL, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.APNS_AUTH_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        token: device.token,
        environment: device.environment,
        title,
        body,
        url: message.downloadUrl,
        objectId: message.objectId,
        linkId: message.linkId,
        label: message.label,
      }),
    });
    if (!res.ok) throw new Error(`push relay failed ${res.status}`);
    return true;
  }
  logEvent("native_push_unconfigured", { link: message.linkId, objectId: message.objectId });
  return false;
}
