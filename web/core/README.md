# Vendored: FileKey crypto core

A **read-only** copy of FileKey's DOM-free crypto core (`reference/src/*.ts` from
the FileKey repo). Do NOT edit these files here — fix upstream in FileKey and
re-vendor, so Drop's encryption stays byte-identical to FileKey/Vault.

- License: GPL-3.0-or-later (same as FileKey).
- Provenance: copied verbatim from the FileKey reference implementation's `src/`.
- Verified in this repo by `web/core.test.ts` (encrypt → decrypt round-trip + the
  `FKEY` magic the Drop Worker enforces).

Before any **public** release of FileKey Drop, extract this into a shared
`@filekey/core` package that both FileKey (Vault) and Drop depend on — one
audited core, no drift. Until then, this copy is Drop's source of truth for
client-side file encryption.
