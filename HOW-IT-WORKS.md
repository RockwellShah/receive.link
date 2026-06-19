# How FileKey Drop works

FileKey Drop lets anyone send you files through a link, and the files arrive end-to-end encrypted to your passkey. The short version: there is barely a backend, and that is deliberate. Files are encrypted in your browser and sent straight to plain storage. The server is only a coordinator. It checks a signed link, hands out a temporary upload or download URL, and sends the email. It never sees your files and never holds a key.

## The pieces

- **Cloudflare Worker:** the only real backend. It is the coordinator. It verifies links, issues short-lived storage URLs, sends emails, and enforces rate limits. It is small and mostly stateless.
- **R2:** Cloudflare's object storage, used as a plain relay. It holds the encrypted blob for about 7 days, then it expires. It has no idea what is inside.
- **KV:** a small key-value store for one-time email-confirmation codes and rate-limit counters.
- **Email (Cloudflare Email Service):** sends the confirmation link and the "you have a file" link.
- **Pages:** serves the static web app. All encryption and decryption runs in the visitor's browser.

## The flow

```
                ciphertext, uploaded and downloaded directly
      Browser  <-------------------------------------------->  R2
     (encrypts                                              (encrypted
      and                                                    blobs,
      decrypts)                                              ~7 days)
          |                                                     ^
          |  "give me a temporary URL"                          |
          v                                                     |
      Cloudflare Worker  -------- signs that URL ---------------'
        (coordinator)
          |          |
          v          v
        Email        KV
     (delivers    (confirm codes,
      the link)    rate limits)

      Files never pass through the Worker.
```

**Setup, once, by you (the receiver).** You enter your email, and your browser derives a keypair from your passkey. You confirm through a one-time emailed link, and the Worker returns a signed Drop link you can post anywhere. The link carries your public key and your email, with the email sealed so only the server can read it. There is no secret in the link itself.

**Someone sends you files.** They open your link and drop files. Their browser encrypts everything to your public key, asks the Worker for a temporary upload URL, and uploads the ciphertext straight to R2. The bytes never pass through the Worker. The Worker then emails you a download link.

**You receive.** You click the email link. Your browser asks the Worker for a temporary download URL, pulls the ciphertext straight from R2, and decrypts it locally with your passkey.

## What the server can and cannot see

- It **cannot** read your files. R2 only ever holds ciphertext, and the decryption key is derived from the recipient's passkey. The key never leaves the recipient's device, and the server never has it.
- It is **never** in the path of your file bytes. Uploads and downloads go directly between the browser and R2 through temporary, signed URLs.
- It **does** handle the metadata it needs to do its job: a sealed (unreadable) copy of the recipient's email, the signed link, file sizes, and timing.

## Why have a server at all

Three jobs cannot happen purely in the browser:

1. **Abuse control:** rate limits and size caps, so the relay does not become a free file host for spam or huge dumps.
2. **Privacy of the recipient's email:** the email is sealed inside the link, so a leaked link does not expose it. Only the server can unseal it, and only in memory at the moment it sends mail.
3. **Trust in the link:** the server signs each link, and only after the recipient confirms their email once. That makes links unforgeable and stops someone from registering an address they do not control.

## The tradeoff

This is true end-to-end encryption. There is no server-side copy of your files and no key escrow. If the recipient loses their passkey, files encrypted to it cannot be recovered. That is the deliberate cost of the server never being able to read anything.
