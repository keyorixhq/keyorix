# internal/identity invariants

Read this before changing anything in `internal/identity` (constructor-enforced Unicode
normalization for identity-bearing strings; see `doc.go`/`identity.go`). A raw string
becomes a `FoldedName`/`AddressName` only through the constructors, so every INSERT and
WHERE goes through the same normalization.

Format: `INV-IDENTITY-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Cross-library normalization agreement

Keyorix's folding is checked against the RFC 8265 PRECIS reference by
`INV-IDENTITY-fold-vs-precis` (`INVARIANTS.d/INV-IDENTITY-fold-vs-precis.md`).

New invariants go in `INVARIANTS.d/INV-IDENTITY-<kebab-slug>.md`, one per file.
