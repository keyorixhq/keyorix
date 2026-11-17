# internal/securefiles invariants

Read this before changing anything in `internal/securefiles` — the symlink-safe, durable
file-write primitives (`SecureWriteFileSync`, `SecureOpenBeneath`'s per-path-component
`O_NOFOLLOW` walk, `SyncDir`, `SecureCreateFile*`, `SecureDeleteFile`) the key-set manifest,
the DEK/KEK files and every other key-material writer sit on. See the function doc comments
in `securefiles.go` for the TOCTOU/symlink trust model.

Format: `INV-SECUREFILES-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-SECUREFILES-<kebab-slug>.md` (one per file), not
appended here — see `docs/invariants-fragments.md`.
