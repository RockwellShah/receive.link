# Vendored: FileKey web UI machinery

`ui.ts` is FileKey's chat-feed UI machinery **copied verbatim** from the FileKey
reference app (`web/app.ts`): the typewriter messages with the lock-avatar "dp",
`StatusMsg` (cycling dots, byte progress, Cancel), the upload/download cards,
`saveBlob` (native save picker + "Saving → Saved" + object-URL fallback), the
hamburger menu + Light/Dark/Auto appearance toggle, and the marching-ants drop
bar. This is what gives Drop the exact FileKey look/feel/experience.

**Do not edit here.** Fix upstream in FileKey and re-vendor. The only deltas vs
`app.ts` are mechanical: the functions are parameterized instead of reaching
Vault-only globals (`identity`, contacts, the encrypt/decrypt routing), and the
download card is Save-only (Drop has no re-share step).

Before Drop goes public, extract this into a shared `@filekey/ui` package that
both FileKey (Vault) and Drop depend on — one source of truth, no drift.

Provenance: FileKey reference `web/app.ts` (+ the `<style>` block now in
`web/style.css`).
